// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Piotr Gorski <lucjan.lucjanov@gmail.com>
//
// Ported from scx_lavd, Copyright (c) 2023-2025 Valve Corporation.
// Author of scx_lavd: Changwoo Min <changwoo@igalia.com>

//! System-wide statistics, collected every 10 ms by a timer: utilization,
//! the average and maximum latency criticality, the average service time,
//! how many tasks wait. The policy reads them back for the deadline, the
//! time slice, preemption and load balancing.
//!
//! The statistics are a structure of their own in `.data.sys_stat`, which
//! the loader reads for --stats.
//!
//! lavd separates IRQ and steal time from the time RT and DL tasks take
//! with the PELT clock, which the runtime does not read. Here a CPU's
//! utilization is what was not idle, as lavd's cur_util_wall is, and its
//! invariant utilization scales by capacity what the scheduler's tasks did
//! not run.
//!
//! Counterpart in scx_lavd: sys_stat.bpf.c.

use scx_rustsched::sched::Cid;
use scx_rustsched::time;
use scx_rustsched::timer::{Timer, TimerMap};
use scx_rustsched::var::Var;

use crate::cpdom::{self, Cpdom};
use crate::cpuctx;
use crate::lavd::*;
use crate::util::{calc_asym_avg, calc_avg, time_delta, wall_to_invr};
use crate::{PREEMPT_SHIFT, SLICE_MAX_NS, SLICE_MIN_NS, balance, power, preempt};

/// When the CPU utilization is almost full, 90%, the actual demand is
/// likely higher still.
const LAVD_CC_UTIL_SPIKE: u64 = p2s(90);

/// lavd's struct sys_stat, a word per field, in its order.
#[repr(C)]
pub struct SysStat {
    pub last_update_clk: Var<u64>,
    /// The CPU utilization, wall clock and invariant.
    pub avg_util_wall: Var<u64>,
    pub avg_util_invr: Var<u64>,
    /// The average service time per task, weighted invariant time.
    pub avg_svc_time_iwgt: Var<u64>,
    pub nr_queued_task: Var<u64>,
    /// The base time slice.
    pub slice_wall: Var<u64>,
    /// Latency criticality: the average, the maximum and the threshold
    /// for kicking.
    pub avg_lat_cri: Var<u64>,
    pub max_lat_cri: Var<u64>,
    pub thr_lat_cri: Var<u64>,
    /// Performance criticality: the minimum, the average, the maximum and
    /// the threshold for a big core.
    pub min_perf_cri: Var<u64>,
    pub avg_perf_cri: Var<u64>,
    pub max_perf_cri: Var<u64>,
    pub thr_perf_cri: Var<u64>,
    /// Domains to steal from, active CPUs and active domains.
    pub nr_stealee: Var<u64>,
    pub nr_active: Var<u64>,
    pub nr_active_cpdoms: Var<u64>,
    /// Counters, halved every LAVD_SYS_STAT_DECAY_TIMES intervals.
    pub nr_sched: Var<u64>,
    pub nr_preempt: Var<u64>,
    pub nr_perf_cri: Var<u64>,
    pub nr_lat_cri: Var<u64>,
    pub nr_x_migration: Var<u64>,
    pub nr_big: Var<u64>,
    pub nr_pc_on_big: Var<u64>,
    pub nr_lc_on_big: Var<u64>,
}

scx_rustsched::shared! {
    pub static SYS_STAT in ".data.sys_stat": SysStat = SysStat {
        last_update_clk: Var::new(0),
        avg_util_wall: Var::new(0),
        avg_util_invr: Var::new(0),
        avg_svc_time_iwgt: Var::new(0),
        nr_queued_task: Var::new(0),
        slice_wall: Var::new(0),
        avg_lat_cri: Var::new(0),
        max_lat_cri: Var::new(0),
        thr_lat_cri: Var::new(0),
        min_perf_cri: Var::new(0),
        avg_perf_cri: Var::new(0),
        max_perf_cri: Var::new(0),
        thr_perf_cri: Var::new(0),
        nr_stealee: Var::new(0),
        nr_active: Var::new(0),
        nr_active_cpdoms: Var::new(0),
        nr_sched: Var::new(0),
        nr_preempt: Var::new(0),
        nr_perf_cri: Var::new(0),
        nr_lat_cri: Var::new(0),
        nr_x_migration: Var::new(0),
        nr_big: Var::new(0),
        nr_pc_on_big: Var::new(0),
        nr_lc_on_big: Var::new(0),
    };
}

/// The logical clock, which runs ahead with the deadlines of the tasks
/// that run, see main.rs's advance_cur_logical_clk().
pub static CUR_LOGICAL_CLK: Var<u64> = Var::new(LAVD_DL_COMPETE_WINDOW);

/// The largest service time a task has had.
pub static CUR_SVC_TIME_IWGT: Var<u64> = Var::new(0);

/// Intervals since the counters were last halved.
static DECAY_COUNT: Var<u64> = Var::new(0);

scx_rustsched::timer_map!(pub sys_stat_timer: SysStatTimer, entries: 1, callback: fire);

/// What one collection sums over the CPUs, struct sys_stat_ctx.
/// A global function takes it by its address, see collect_cid().
#[repr(C)]
#[derive(Default)]
pub struct Ctx {
    now: u64,
    duration_wall: u64,
    idle_total_wall: u64,
    compute_total_invr: u64,
    tsct_spike_invr: u64,
    tot_task_time_iwgt: u64,
    nr_queued_task: u64,
    nr_sched: u64,
    nr_preempt: u64,
    nr_perf_cri: u64,
    nr_lat_cri: u64,
    nr_x_migration: u64,
    nr_big: u64,
    nr_pc_on_big: u64,
    nr_lc_on_big: u64,
    sum_lat_cri: u64,
    max_lat_cri: u64,
    sum_perf_cri: u64,
    min_perf_cri: u64,
    max_perf_cri: u64,
}

/// Collect domain `id`'s queue and reset its sums.
#[inline(always)]
fn collect_cpdom(dom: Cpdom, id: u64) -> u64 {
    dom.cur_util_wall_sum().set(0);
    dom.avg_util_wall_sum().set(0);
    dom.avg_util_invr_sum().set(0);
    let queued = u64::from(scx_rustsched::dsq::nr_queued(cpdom::queue(id)));
    dom.nr_queued_task().set(queued);
    queued
}

/// Collect `cid`'s interval into `c`, collect_sys_stat() for one CPU. A
/// global function, verified once rather than inlined into the loop over
/// the CIDs.
#[scx_rustsched::global]
fn collect_cid(c: Option<&mut Ctx>, cid: Cid) -> u32 {
    let Some(c) = c else {
        return 0;
    };
    let Some(cpuc) = cpuctx::get(cid) else {
        return 0;
    };
    // The local DSQ and the CID's own queue count as queued in its domain.
    let queued = u64::from(scx_rustsched::dsq::nr_queued(
        scx_rustsched::dsq::Dsq::LocalOn(cid),
    )) + cid.nr_queued();
    c.nr_queued_task += queued;
    let Some(dom) = cpdom::get(cpuc.cpdom_id().get()) else {
        return 0;
    };
    dom.nr_queued_task().update(|nr| nr + queued);

    // Slices boosted while they should not be any more are cut back.
    preempt::shrink_boosted_slice_if_needed(cid, cpuc, c.now);

    c.tot_task_time_iwgt += cpuc.tot_task_time_iwgt().get();
    cpuc.tot_task_time_iwgt().set(0);

    // An idle period still running is counted up to now, and goes on
    // from here.
    for _ in scx_rustsched::loops::range(0, LAVD_MAX_RETRY) {
        let old = cpuc.idle_start_clk().get();
        if old == 0 || time::before(c.now, old) {
            break;
        }
        if cpuc.idle_start_clk().compare_exchange(old, c.now) == old {
            cpuc.idle_total_wall().add(time_delta(c.now, old));
            break;
        }
    }
    let idle_wall = cpuc.idle_total_wall().get().min(c.duration_wall);
    let compute_wall = time_delta(c.duration_wall, idle_wall);
    let task_wall = cpuc.tot_task_time_wall().get().min(compute_wall);
    cpuc.tot_task_time_wall().set(0);
    let task_invr = cpuc.tot_task_time_invr().get();
    cpuc.tot_task_time_invr().set(0);

    // What the CPU did besides the scheduler's tasks, IRQs and the
    // classes above, at the CPU's capacity.
    let steal_invr = wall_to_invr(compute_wall - task_wall, cid);
    let compute_invr = (task_invr + steal_invr).min(compute_wall);

    let duration = c.duration_wall;
    cpuc.cur_util_wall().set(
        (compute_wall << LAVD_SHIFT)
            .checked_div(duration)
            .unwrap_or(0),
    );
    cpuc.avg_util_wall()
        .update(|avg| calc_asym_avg(avg, cpuc.cur_util_wall().get()));
    cpuc.cur_util_invr().set(
        (compute_invr << LAVD_SHIFT)
            .checked_div(duration)
            .unwrap_or(0),
    );
    cpuc.avg_util_invr()
        .update(|avg| calc_asym_avg(avg, cpuc.cur_util_invr().get()));

    power::calc_cpuperf_target(cid, cpuc);
    power::decay_idle_cpuperf_target(cid, cpuc);

    dom.cur_util_wall_sum()
        .update(|sum| sum + cpuc.cur_util_wall().get());
    dom.avg_util_wall_sum()
        .update(|sum| sum + cpuc.avg_util_wall().get());
    dom.avg_util_invr_sum()
        .update(|sum| sum + cpuc.avg_util_invr().get());

    c.compute_total_invr += compute_invr;
    if cpuc.cur_util_wall().get() > LAVD_CC_UTIL_SPIKE {
        c.tsct_spike_invr += compute_invr;
    }

    // The per-schedule counters.
    let nr_sched = cpuc.nr_sched().get();
    if cpuc.big_core().get() {
        c.nr_big += nr_sched;
        c.nr_pc_on_big += cpuc.nr_perf_cri().get();
        c.nr_lc_on_big += cpuc.nr_lat_cri().get();
    }
    c.nr_perf_cri += cpuc.nr_perf_cri().get();
    cpuc.nr_perf_cri().set(0);
    c.nr_lat_cri += cpuc.nr_lat_cri().get();
    cpuc.nr_lat_cri().set(0);
    c.nr_x_migration += cpuc.nr_x_migration().get();
    cpuc.nr_x_migration().set(0);
    c.sum_lat_cri += cpuc.sum_lat_cri().get();
    cpuc.sum_lat_cri().set(0);
    c.nr_sched += nr_sched;
    cpuc.nr_sched().set(0);
    c.nr_preempt += cpuc.nr_preempt().get();
    cpuc.nr_preempt().set(0);
    c.max_lat_cri = c.max_lat_cri.max(cpuc.max_lat_cri().get());
    cpuc.max_lat_cri().set(0);
    if cpdom::have_little_core() {
        c.min_perf_cri = c.min_perf_cri.min(cpuc.min_perf_cri().get());
        cpuc.min_perf_cri().set(LAVD_SCALE);
        c.max_perf_cri = c.max_perf_cri.max(cpuc.max_perf_cri().get());
        cpuc.max_perf_cri().set(0);
        c.sum_perf_cri += cpuc.sum_perf_cri().get();
        cpuc.sum_perf_cri().set(0);
    }

    c.idle_total_wall += idle_wall;
    cpuc.idle_total_wall().set(0);
    0
}

/// calc_sys_stat(): fold the interval into the averages.
#[inline(always)]
fn calc_sys_stat(c: &Ctx) {
    let s = &SYS_STAT;
    let nr_cpus = u64::from(Cid::count());
    let duration_total_wall = (c.duration_wall * nr_cpus).max(1);
    let compute_total_wall = time_delta(duration_total_wall, c.idle_total_wall);
    let cur_util_wall = (compute_total_wall << LAVD_SHIFT)
        .checked_div(duration_total_wall)
        .unwrap_or(0);

    let mut cur_util_invr = (c.compute_total_invr << LAVD_SHIFT)
        .checked_div(duration_total_wall)
        .unwrap_or(0);
    if cur_util_invr > cur_util_wall {
        cur_util_invr = s.avg_util_invr.get().min(cur_util_wall);
    }
    // A CPU that is almost fully used likely has more demand than it
    // shows: give that time a 50% premium, which buys breathing room.
    let spike_invr = (c.tsct_spike_invr << (LAVD_SHIFT - 1))
        .checked_div(duration_total_wall)
        .unwrap_or(0);
    let cur_util_invr = (cur_util_invr + spike_invr).min(LAVD_SCALE);

    let (avg_lat_cri, max_lat_cri, avg_perf_cri, min_perf_cri, max_perf_cri) =
        if c.nr_sched == 0 || compute_total_wall == 0 {
            // A completely idle interval: nothing new.
            (
                s.avg_lat_cri.get(),
                s.max_lat_cri.get(),
                s.avg_perf_cri.get(),
                s.min_perf_cri.get(),
                s.max_perf_cri.get(),
            )
        } else {
            (
                c.sum_lat_cri.checked_div(c.nr_sched).unwrap_or(0),
                c.max_lat_cri,
                c.sum_perf_cri.checked_div(c.nr_sched).unwrap_or(0),
                c.min_perf_cri,
                c.max_perf_cri,
            )
        };

    s.avg_util_wall
        .update(|avg| calc_asym_avg(avg, cur_util_wall));
    s.avg_util_invr
        .update(|avg| calc_asym_avg(avg, cur_util_invr));
    s.max_lat_cri.update(|max| calc_avg(max, max_lat_cri));
    s.avg_lat_cri.update(|avg| calc_avg(avg, avg_lat_cri));
    let max = s.max_lat_cri.get();
    let avg = s.avg_lat_cri.get();
    s.thr_lat_cri
        .set(crate::math::thr_lat_cri(max, avg, PREEMPT_SHIFT.get()));

    if cpdom::have_little_core() {
        s.min_perf_cri.update(|min| calc_avg(min, min_perf_cri));
        s.avg_perf_cri.update(|avg| calc_avg(avg, avg_perf_cri));
        s.max_perf_cri.update(|max| calc_avg(max, max_perf_cri));
    }

    let avg_svc_time_iwgt = c.tot_task_time_iwgt.checked_div(c.nr_sched).unwrap_or(0);
    s.avg_svc_time_iwgt
        .update(|avg| calc_avg(avg, avg_svc_time_iwgt));
    s.nr_queued_task
        .update(|avg| calc_avg(avg, c.nr_queued_task));

    // Halve the counters every two seconds, so they hold a few seconds.
    if DECAY_COUNT.get() == LAVD_SYS_STAT_DECAY_TIMES {
        DECAY_COUNT.set(0);
        s.nr_sched.update(|n| n >> 1);
        s.nr_preempt.update(|n| n >> 1);
        s.nr_perf_cri.update(|n| n >> 1);
        s.nr_lat_cri.update(|n| n >> 1);
        s.nr_x_migration.update(|n| n >> 1);
        s.nr_big.update(|n| n >> 1);
        s.nr_pc_on_big.update(|n| n >> 1);
        s.nr_lc_on_big.update(|n| n >> 1);
    } else {
        DECAY_COUNT.update(|n| n + 1);
    }
    s.nr_sched.update(|n| n + c.nr_sched);
    s.nr_preempt.update(|n| n + c.nr_preempt);
    s.nr_perf_cri.update(|n| n + c.nr_perf_cri);
    s.nr_lat_cri.update(|n| n + c.nr_lat_cri);
    s.nr_x_migration.update(|n| n + c.nr_x_migration);
    s.nr_big.update(|n| n + c.nr_big);
    s.nr_pc_on_big.update(|n| n + c.nr_pc_on_big);
    s.nr_lc_on_big.update(|n| n + c.nr_lc_on_big);
}

/// calc_sys_time_slice(): a slice short enough to run every runnable task
/// once within the targeted latency on the active CPUs.
#[inline(always)]
fn calc_sys_time_slice() {
    let slice_wall = crate::math::sys_time_slice(
        SYS_STAT.nr_queued_task.get(),
        SYS_STAT.nr_active.get(),
        SLICE_MIN_NS.get(),
        SLICE_MAX_NS.get(),
    );
    SYS_STAT.slice_wall.update(|avg| calc_avg(avg, slice_wall));
}

/// update_sys_stat(): one interval. A global function, verified once
/// rather than in the timer's callback.
#[scx_rustsched::global]
fn update_sys_stat(now: u64) -> u32 {
    let mut c = Ctx {
        now,
        duration_wall: time_delta(now, SYS_STAT.last_update_clk.get()).max(1),
        min_perf_cri: LAVD_SCALE,
        ..Default::default()
    };
    SYS_STAT.last_update_clk.set(now);

    for id in scx_rustsched::loops::range(0, cpdom::nr_cpdoms() as u32) {
        if let Some(dom) = cpdom::get(u64::from(id)) {
            c.nr_queued_task += collect_cpdom(dom, u64::from(id));
        }
    }
    for cid in Cid::all() {
        collect_cid(Some(&mut c), cid);
    }
    calc_sys_stat(&c);
    calc_sys_time_slice();
    power::update_thr_perf_cri();
    if cpdom::nr_cpdoms() > 1 {
        balance::plan_x_cpdom_migration();
    }
    0
}

/// The timer fired: collect, and arm it for the next interval.
fn fire(_key: u32, timer: &Timer) {
    scx_rustsched::pool::touch();
    update_sys_stat(time::now());
    timer.start(LAVD_SYS_STAT_INTERVAL_NS);
}

/// init_sys_stat(): the starting point, and the timer, from ops.init().
pub fn init(now: u64) -> i32 {
    SYS_STAT.last_update_clk.set(now);
    SYS_STAT.nr_active.set(u64::from(Cid::count()));
    SYS_STAT.nr_active_cpdoms.set(cpdom::nr_cpdoms());
    SYS_STAT.slice_wall.set(SLICE_MAX_NS.get());
    SYS_STAT.min_perf_cri.set(LAVD_SCALE);
    let result = SysStatTimer::init(0);
    if result != 0 {
        return result;
    }
    if !SysStatTimer::start(0, LAVD_SYS_STAT_INTERVAL_NS) {
        return -3; // ESRCH
    }
    0
}
