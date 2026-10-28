// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Piotr Gorski <lucjan.lucjanov@gmail.com>
//
// Ported from scx_lavd, Copyright (c) 2023-2025 Valve Corporation.
// Author of scx_lavd: Changwoo Min <changwoo@igalia.com>

//! Preemption: an urgent task that found no idle CPU takes one from a less
//! urgent task, and slices that grew longer than the system can afford
//! are cut back.
//!
//! Kick-based preemption picks a victim with the power of two random
//! choices: two CPUs of the task's domain whose running tasks are less
//! latency-critical and expected to run longer than it, and of the two
//! the one that would wait longer. The victim is asked to yield at once,
//! its slice set to the minimum, rather than sent a preempting IPI.
//!
//! Counterpart in scx_lavd: preempt.bpf.c.

use scx_rustsched::sched::{Cid, KickFlags};
use scx_rustsched::task::Task;
use scx_rustsched::time;

use crate::cpdom;
use crate::cpuctx::{self, CpuCtx};
use crate::lavd::*;
use crate::sys_stat::SYS_STAT;
use crate::taskctx::TaskCtx;
use crate::util::{can_boost_slice, is_affinitized, is_rt_or_dl_task_running, time_delta};
use crate::{NO_SLICE_BOOST, PINNED_SLICE_NS};

/// What a preemption decision compares, struct preemption_info.
#[derive(Clone, Copy)]
struct Info {
    est_stopping_clk: u64,
    lat_cri: u64,
    cid: i32,
}

/// When `taskc` would stop if it started now, get_est_stopping_clk().
#[inline(always)]
pub fn get_est_stopping_clk(taskc: TaskCtx, now: u64) -> u64 {
    now + taskc.avg_runtime_wall().get().min(taskc.slice_wall().get())
}

/// Can `x` kick `y`? Only if it is more latency-critical and would finish
/// sooner.
#[inline(always)]
fn can_x_kick_y(x: Info, y: Info) -> bool {
    x.lat_cri > y.lat_cri && x.est_stopping_clk < y.est_stopping_clk
}

/// What runs on `cid`, if a task of `x` may kick it: neither an RT or DL
/// task nor one of ours that is not expected to stop.
#[inline(always)]
fn can_x_kick_cpu(x: Info, cid: Cid, cpuc: CpuCtx) -> Option<Info> {
    if is_rt_or_dl_task_running(cid) {
        return None;
    }
    let y = Info {
        est_stopping_clk: cpuc.est_stopping_clk().get(),
        lat_cri: cpuc.lat_cri().get(),
        cid: cid.raw(),
    };
    can_x_kick_y(x, y).then_some(y)
}

#[inline(always)]
fn info_of(taskc: TaskCtx, now: u64) -> Info {
    Info {
        est_stopping_clk: get_est_stopping_clk(taskc, now),
        lat_cri: taskc.lat_cri().get(),
        cid: -1,
    }
}

/// Is the task urgent enough to kick another, is_worth_kick_other_task()?
#[inline(always)]
fn is_worth_kick_other_task(taskc: TaskCtx) -> bool {
    taskc.lat_cri().get() >= SYS_STAT.thr_lat_cri.get()
}

/// find_victim_cpu(): `preferred` first, then CIDs of `dom` at random,
/// until two candidates are found. A global function: its loop is
/// verified once.
#[scx_rustsched::global]
fn find_victim_cpu(task: &Task, taskc: TaskCtx, preferred: i32, dom: u64, now: u64) -> i32 {
    let x = info_of(taskc, now);
    // No candidate is a cid of -1: an Option merged across the paths of
    // the loop is the kind of copy the verifier has refused.
    let none = Info {
        est_stopping_clk: 0,
        lat_cri: 0,
        cid: -1,
    };
    let mut first = none;
    let mut second = none;

    let preferred = Cid(preferred);
    if let Some(cpuc) = cpuctx::get(preferred)
        && let Some(y) = can_x_kick_cpu(x, preferred, cpuc)
    {
        first = y;
    }

    let Some(cpdomc) = cpdom::get(dom) else {
        return -1;
    };
    let nr = cpdomc.nr_cpus().get().max(1) as u32;
    let (llc_nr, llc_base) = Cid(cpdomc.first_cid().get() as i32).llc_span();
    for _ in scx_rustsched::loops::range(0, nr) {
        if second.cid >= 0 {
            break;
        }
        // A CID of the domain, by a random draw from its LLC.
        let offset = scx_rustsched::helpers::get_prandom_u32()
            .checked_rem(llc_nr)
            .unwrap_or(0);
        let cid = Cid((llc_base + offset) as i32);
        if cid == preferred || !task.allowed_on(cid) {
            continue;
        }
        let Some(cpuc) = cpuctx::get(cid) else {
            continue;
        };
        if cpuc.cpdom_id().get() != dom {
            continue;
        }
        let Some(y) = can_x_kick_cpu(x, cid, cpuc) else {
            continue;
        };
        if first.cid < 0 {
            first = y;
        } else {
            second = y;
        }
    }

    if first.cid < 0 || second.cid < 0 {
        return first.cid;
    }
    // Of two, the victim is the one the other could kick.
    if can_x_kick_y(first, second) {
        first.cid
    } else {
        second.cid
    }
}

/// Ask the task running on `cid` to yield after `new_slice` ns, or at
/// once for 0, ask_cpu_yield_after(). A slice that is already shorter
/// stays.
#[inline(always)]
fn ask_cpu_yield_after(cid: Cid, cpuc: CpuCtx, new_slice: u64) {
    let curr = scx_rustsched::kfuncs::scx_bpf_cid_curr(cid.raw());
    if curr.is_null() {
        return;
    }
    // SAFETY: the task running on the CID, valid under the RCU read lock
    // every callback runs in.
    let victim = unsafe { Task::from_ptr(curr) };
    let new_slice = new_slice.max(1);
    if new_slice == 1 {
        // Kick it only once, however many tasks pick it as their victim.
        let old = cpuc.est_stopping_clk().get();
        if old == 0 || cpuc.est_stopping_clk().compare_exchange(old, 0) != old {
            return;
        }
        victim.set_slice(new_slice);
    } else if victim.slice() > new_slice {
        victim.set_slice(new_slice);
    }
}

/// Cut `cid`'s boosted slice to what is left of the system's, from the
/// timer: kick it if nothing is, shrink_boosted_slice_remote().
#[inline(always)]
pub fn shrink_boosted_slice_remote(cid: Cid, cpuc: CpuCtx, now: u64) {
    cpuc.reset_flag(LAVD_FLAG_SLICE_BOOST);
    let pinned = PINNED_SLICE_NS.get();
    let target = if pinned != 0 && cpuc.nr_pinned_tasks().get() != 0 {
        pinned
    } else {
        SYS_STAT.slice_wall.get()
    };
    let duration = time_delta(now, cpuc.running_clk().get());
    let new_slice = time_delta(target, duration);
    if new_slice == 0 {
        cid.kick(KickFlags::PREEMPT);
    } else {
        // lavd sets the running task's slice from here, with
        // bpf_rcu_read_lock() around scx_bpf_cpu_curr(). The timer runs
        // as the sleepable ops.init() that armed it, where that kfunc
        // needs the lock, which the runtime does not declare: the CPU's
        // own tick applies the cut instead, see apply_shrink().
        cpuc.shrink_at().set(now + new_slice);
    }
    cpuc.nr_preempt().update(|n| n + 1);
}

/// From ops.tick() on the CPU: end the running task's slice when the
/// timer asked, shrink_boosted_slice_remote(). A slice already shorter
/// stays.
#[inline(always)]
pub fn apply_shrink(task: &Task, cpuc: CpuCtx, now: u64) {
    let at = cpuc.shrink_at().get();
    if at == 0 {
        return;
    }
    cpuc.shrink_at().set(0);
    let left = time_delta(at, now);
    if task.slice() > left {
        task.set_slice(left);
    }
}

/// From the timer, for each CID: a boosted slice is cut when a pinned
/// task waits for the CPU, when the system can no longer afford boosts,
/// or when a task waits on the local DSQ.
#[inline(always)]
pub fn shrink_boosted_slice_if_needed(cid: Cid, cpuc: CpuCtx, now: u64) {
    if !cpuc.test_flag(LAVD_FLAG_SLICE_BOOST) {
        return;
    }
    if cpuc.nr_pinned_tasks().get() != 0
        || !can_boost_slice()
        || scx_rustsched::dsq::nr_queued(scx_rustsched::dsq::Dsq::LocalOn(cid)) != 0
    {
        shrink_boosted_slice_remote(cid, cpuc, now);
    }
}

/// shrink_slice_at_tick(): with a pinned task waiting, the running task
/// gets no more than the system's slice, or the pinned slice.
#[inline(always)]
pub fn shrink_slice_at_tick(task: &Task, cpuc: CpuCtx, now: u64) {
    let pinned = PINNED_SLICE_NS.get();
    let ub = if pinned != 0 {
        pinned.min(SYS_STAT.slice_wall.get())
    } else {
        SYS_STAT.slice_wall.get()
    };
    let duration = time_delta(now, cpuc.running_clk().get());
    task.set_slice(time_delta(ub, duration));
    cpuc.reset_flag(LAVD_FLAG_SLICE_BOOST);
    cpuc.nr_preempt().update(|n| n + 1);
}

/// try_find_and_kick_victim_cpu(): `task` found no idle CPU at
/// ops.enqueue(). If it is urgent, take a CPU from a less urgent task:
/// `preferred`'s if it runs a boosted slice past the system's, or a
/// victim found in domain `dom`.
#[inline(always)]
pub fn try_find_and_kick_victim_cpu(task: &Task, taskc: TaskCtx, preferred: Cid, dom: u64) {
    if taskc.test_flag(LAVD_FLAG_IS_GREEDY) || !is_worth_kick_other_task(taskc) {
        return;
    }
    let now = time::now();
    if !NO_SLICE_BOOST.get()
        && let Some(cpuc) = cpuctx::get(preferred)
        && cpuc.test_flag(LAVD_FLAG_SLICE_BOOST)
    {
        // A boosted slice past the system's is fair game, and a task that
        // cannot go elsewhere waits only for the rest of a regular slice.
        let duration = time_delta(now, cpuc.running_clk().get());
        if duration >= SYS_STAT.slice_wall.get()
            && can_x_kick_cpu(info_of(taskc, now), preferred, cpuc).is_some()
        {
            cpuc.reset_flag(LAVD_FLAG_SLICE_BOOST);
            return kick(preferred, cpuc, 0);
        }
        if is_affinitized(task) {
            cpuc.reset_flag(LAVD_FLAG_SLICE_BOOST);
            return kick(
                preferred,
                cpuc,
                time_delta(SYS_STAT.slice_wall.get(), duration),
            );
        }
    }
    let victim = Cid(find_victim_cpu(task, taskc, preferred.raw(), dom, now));
    if let Some(cpuc) = cpuctx::get(victim) {
        kick(victim, cpuc, 0);
    }
}

#[inline(always)]
fn kick(victim: Cid, cpuc: CpuCtx, new_slice: u64) {
    ask_cpu_yield_after(victim, cpuc, new_slice);
    if let Some(here) = cpuctx::get(Cid::current()) {
        here.nr_preempt().update(|n| n + 1);
    }
}
