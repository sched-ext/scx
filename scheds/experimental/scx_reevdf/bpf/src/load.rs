// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.

//! The signals placement and balance decide on: how much of a CPU a task
//! uses, how busy a CID has been, and the averaged runnable weight that
//! stands for its load.
//!
//! A task's running average records whether it runs. Its utilization is the
//! larger of that and what it used over its last activation, task_util_est(),
//! since a task that runs in bursts is idle at exactly the moment it wakes to
//! ask for a whole CPU again. A CID's running average records whether it
//! runs one of ours, and drives cpufreq. A CID's load averages its pack's
//! weight, the queued tasks and the running one: what cfs_rq->avg.load_avg
//! is and what wake_affine_weight() compares. It is sampled from the CID's
//! own tick and when the CID goes idle, so a remote join or leave reaches it
//! within a tick.
//!
//! Counterpart in scx_eevdf: load.bpf.h.

use crate::{
    accounting::{UTIL_HALF_LIFE_NS, runnable_update, task_load as weighed, util_est_update},
    cid_table, pack,
    ravg::{FRAC_BITS, Ravg, accumulate, read, read_fast},
    taskctx::Context,
};
use scx_rustsched::sched::Cid;
use scx_rustsched::task::Task;

/// From a running average of 0 or 1 to utilization in 0..=1024.
const UTIL_SHIFT: u32 = FRAC_BITS - 10;
scx_rustsched::arena_struct! {
    /// What is tracked per CID: 256 bytes, four cache lines of its own.
    pub struct Load {
        run_avg: [u64; 4],
        load_avg: [u64; 4],
        wake_load: u64,
        /// When the CID last went idle.
        idle_stamp: u64,
        /// When a fork was last placed on the core this CID is the first
        /// of, and on this CID.
        fork_core_at: u64,
        fork_cid_at: u64,
        /// pressure.rs's: whether sched_ext has work there, when the
        /// window started, the time lost to displacement and its value
        /// then, the gap between the two clocks then, when the task
        /// running was displaced, the smoothed available fraction and
        /// whether it has been measured, when demand last went away, the
        /// balance capacity, and the pacing and failures of displaced-task
        /// moves.
        pressure_demand: u64,
        pressure_at: u64,
        pressure_lost: u64,
        pressure_lost_at: u64,
        unused: u64,
        pressure_clock_off_at: u64,
        pressure_blocked_at: u64,
        pressure_avail: u64,
        pressure_valid: u64,
        pressure_idle_at: u64,
        pressure_cap: u64,
        pressure_migrate_next: u64,
        pressure_migrate_failed: u64,
        /// The PELT period cpufreq was last told in, plus one.
        perf_period: u64,
        pad: [u64; 6],
    }
}

scx_rustsched::cid_slot!(Load, LOADS in ".data.loads");

/// The entry of `cid`, which the caller knows is a CID, see valid().
#[inline(always)]
pub(crate) fn load(cid: Cid) -> Load {
    cid_table::entry(cid)
}

pub fn init(_count: u32) -> i32 {
    cid_table::init_slots::<Load>()
}

#[inline(always)]
fn ravg_of([val, val_at, old, cur]: [u64; 4]) -> Ravg {
    Ravg {
        val,
        val_at,
        old,
        cur,
    }
}

#[inline(always)]
fn words_of(average: &Ravg) -> [u64; 4] {
    [average.val, average.val_at, average.old, average.cur]
}

#[inline(always)]
pub(crate) fn valid(cid: Cid) -> bool {
    cid_table::valid::<Load>(cid)
}

/// The task started or stopped running at `now`.
#[inline(always)]
pub fn task_running(state: &Context, running: bool, now: u64) {
    let mut average = state.run_avg();
    accumulate(&mut average, u64::from(running), now, UTIL_HALF_LIFE_NS);
    state.set_run_avg(&average);
}

/// The task stops being runnable at `now`, after a sleep if `sleep`: fold
/// what it used into its estimate and, for a sleep, the runnable fraction of
/// the cycle that ends.
#[inline(always)]
pub fn task_quiesce(state: &Context, sleep: bool, now: u64) {
    let [util_est, mut runnable_est, mut last_sleep_at, runnable_at] = state.load_state();
    let dequeued = read(&state.run_avg(), now, UTIL_HALF_LIFE_NS) >> UTIL_SHIFT;
    let util_est = util_est_update(util_est, dequeued);
    if sleep {
        if last_sleep_at != 0 && runnable_at != 0 {
            runnable_est = runnable_update(runnable_est, now - last_sleep_at, now - runnable_at);
        }
        last_sleep_at = now;
    }
    state.set_load_state([util_est, runnable_est, last_sleep_at, runnable_at]);
}

/// The task woke up at `now`.
#[inline(always)]
pub fn task_woke(state: &Context, now: u64) {
    state.runnable_at().set(now);
}

/// What the task uses, in 0..=1024: the larger of what it uses now and
/// what it used over its last activation, task_util().
#[allow(dead_code, reason = "read by wakeup placement")]
#[inline(always)]
pub fn task_util(state: &Context, now: u64) -> u64 {
    let util = read(&state.run_avg(), now, UTIL_HALF_LIFE_NS) >> UTIL_SHIFT;
    util.max(state.util_est().get())
}

/// The task's load at `weight`, see accounting::task_load().
#[allow(dead_code, reason = "read by wakeup placement")]
#[inline(always)]
pub fn task_load(task: &Task, state: &Context, weight: u64, now: u64) -> u64 {
    let [util_est, runnable_est, last_sleep_at, _] = state.load_state();
    let asleep = if !task.running() && now > last_sleep_at {
        now - last_sleep_at
    } else {
        0
    };
    weighed(weight, util_est, runnable_est, asleep)
}

/// `cid` started or stopped running a task of ours at `now`.
#[inline(always)]
pub fn cid_running(cid: Cid, running: bool, now: u64) {
    if !valid(cid) {
        return;
    }
    let mut average = ravg_of(load(cid).run_avg().get());
    accumulate(&mut average, u64::from(running), now, UTIL_HALF_LIFE_NS);
    load(cid).run_avg().set(words_of(&average));
}

/// How busy `cid` has been, in 0..=1024, the cpufreq scale.
///
/// A global function, verified once on its own with scalar arguments:
/// placement reads it for every CID of a domain, and as a static one the
/// verifier walked the average's branches again in every caller state.
#[scx_rustsched::global]
pub fn cid_util(cid: Cid, now: u64) -> u64 {
    if !valid(cid) {
        return 0;
    }
    read_fast(&ravg_of(load(cid).run_avg().get()), now, UTIL_HALF_LIFE_NS) >> UTIL_SHIFT
}

/// Fold `cid`'s pack weight into its load average, from its own tick or as
/// it goes idle, and cache the result for wakeups.
#[inline(always)]
pub fn cid_load_accumulate(cid: Cid, now: u64) {
    if !valid(cid) {
        return;
    }
    let mut average = ravg_of(load(cid).load_avg().get());
    accumulate(&mut average, pack::weight(cid), now, UTIL_HALF_LIFE_NS);
    load(cid).load_avg().set(words_of(&average));
    load(cid)
        .wake_load()
        .set(read_fast(&average, now, UTIL_HALF_LIFE_NS) >> FRAC_BITS);
}

/// `cid`'s load as of `now`, cpu_load(), a global function as
/// cid_util() is.
#[scx_rustsched::global]
pub fn cid_load(cid: Cid, now: u64) -> u64 {
    if !valid(cid) {
        return 0;
    }
    read_fast(&ravg_of(load(cid).load_avg().get()), now, UTIL_HALF_LIFE_NS) >> FRAC_BITS
}

/// `cid`'s load as of its last sample, for wakeups that read many CIDs.
#[allow(dead_code, reason = "read by wakeup placement")]
#[inline(always)]
pub fn cid_wake_load(cid: Cid) -> u64 {
    if !valid(cid) {
        return 0;
    }
    load(cid).wake_load().get()
}

/// `cid` went idle at `now`.
#[inline(always)]
pub fn set_idle_stamp(cid: Cid, now: u64) {
    if valid(cid) {
        load(cid).idle_stamp().set(now);
    }
}

/// When `cid` last went idle.
#[inline(always)]
pub fn idle_stamp(cid: Cid) -> u64 {
    if valid(cid) {
        load(cid).idle_stamp().get()
    } else {
        0
    }
}

/// When a fork was last placed on the core `core_base` begins, or on `cid`.
#[inline(always)]
pub fn fork_placed_at(cid: Cid, core: bool) -> u64 {
    if !valid(cid) {
        return 0;
    }
    if core {
        load(cid).fork_core_at().get()
    } else {
        load(cid).fork_cid_at().get()
    }
}

/// A fork was placed on `cid`, whose core begins at `core_base`, at `now`.
#[inline(always)]
pub fn fork_placed(cid: Cid, core_base: Cid, now: u64) {
    if valid(cid) && valid(core_base) {
        load(core_base).fork_core_at().set(now);
        load(cid).fork_cid_at().set(now);
    }
}

/// PELT's period, 1024 us.
const PELT_PERIOD_SHIFT: u32 = 20;

/// Tell the cpufreq governor how busy `cid` is, with nothing added:
/// schedutil does the shaping itself, as for the fair class. Called as a
/// task starts and from every tick, so a task that keeps the CPU does not
/// leave the request it started with in force.
///
/// fair.c tells the governor when the runqueue's load average decays, at
/// most once a PELT period, and when a task attaches to it, the
/// cfs_rq_util_change() calls of update_load_avg(). So does this: `attach`
/// is a task that has just joined `cid`'s pack.
#[inline(always)]
pub fn update_cpufreq(cid: Cid, now: u64, attach: bool) {
    if !valid(cid) {
        return;
    }
    let period = (now >> PELT_PERIOD_SHIFT) + 1;
    if !attach && load(cid).perf_period().get() == period {
        return;
    }
    load(cid).perf_period().set(period);
    cid.set_perf(cid_util(cid, now) as u32);
}
