// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Piotr Gorski <lucjan.lucjanov@gmail.com>
//
// Ported from scx_lavd, Copyright (c) 2023-2025 Valve Corporation.
// Author of scx_lavd: Changwoo Min <changwoo@igalia.com>

//! Performance criticality and CPU frequency.
//!
//! On a machine of big and little cores, a task whose performance
//! criticality is above a threshold goes to a big core. The threshold
//! splits the tasks in the proportion of the big cores' capacity to the
//! whole machine's: with big cores worth 60% of it, the 60% most
//! performance-critical tasks are big.
//!
//! A CPU's performance target follows its utilization, with headroom: at
//! 85% or more it gets the full frequency. It goes up at once when a task
//! that needs more starts running, and down at the next collection.
//!
//! Counterpart in scx_lavd: power.bpf.c. Core compaction, which runs a
//! lightly loaded system on fewer CPUs, the power profiles and autopilot
//! are not ported: every CPU is active, and the threshold for big cores
//! is the balanced one. Nor is schedutil's rate limit: the target is sent
//! when it changes.

use scx_rustsched::sched::Cid;
use scx_rustsched::var::Var;

use crate::NO_FREQ_SCALING;
use crate::cpdom;
use crate::cpuctx::CpuCtx;
use crate::lavd::*;
use crate::sys_stat::SYS_STAT;
use crate::taskctx::TaskCtx;

/// Raise the target in steps of a 64th of the capacity, and lower it only
/// past a 32nd.
const LAVD_CPUPERF_UP_SHIFT: u32 = 6;
const LAVD_CPUPERF_DOWN_SHIFT: u32 = 5;

/// The big cores' share of the machine's capacity, of 1024.
pub static BIG_CORE_SCALE: Var<u64> = Var::new(LAVD_SCALE);

scx_rustsched::arena_struct! {
    /// A CID's performance target: what its utilization asks for, set by
    /// the timer, and the demand of the task running there, which raises it.
    pub struct Perf {
        target: u64,
        floor: u64,
    }
}

scx_rustsched::cid_slot!(Perf, PERF in ".data.perf");

/// Allocate the targets and compute the big cores' share, from ops.init().
pub fn init() -> i32 {
    let result = scx_rustsched::cid_table::init_slots::<Perf>();
    if result != 0 {
        return result;
    }
    let (mut big, mut sum) = (0, 0);
    for id in scx_rustsched::loops::range(0, cpdom::nr_cpdoms() as u32) {
        if let Some(dom) = cpdom::get(u64::from(id)) {
            sum += dom.cap_sum().get();
            if dom.is_big().get() {
                big += dom.cap_sum().get();
            }
        }
    }
    BIG_CORE_SCALE.set((big << LAVD_SHIFT).checked_div(sum).unwrap_or(LAVD_SCALE));
    0
}

/// Does the task want a big core, is_perf_cri()? Every task does on a
/// machine of one core type.
#[inline(always)]
pub fn is_perf_cri(taskc: TaskCtx) -> bool {
    if !cpdom::have_little_core() {
        return true;
    }
    taskc.perf_cri().get() > SYS_STAT.thr_perf_cri.get()
}

/// update_thr_perf_cri(): the threshold that puts the big cores' share of
/// the tasks on big cores.
#[inline(always)]
pub fn update_thr_perf_cri() {
    let s = &SYS_STAT;
    s.thr_perf_cri.set(crate::math::thr_perf_cri(
        BIG_CORE_SCALE.get(),
        s.min_perf_cri.get(),
        s.avg_perf_cri.get(),
        s.max_perf_cri.get(),
    ));
}

#[inline(always)]
fn round_up(value: u64, step: u64) -> u64 {
    match (value + step)
        .checked_sub(1)
        .and_then(|v| v.checked_div(step))
    {
        Some(steps) => steps * step,
        None => value,
    }
}

/// calc_cpuperf_target(): the target `cid`'s utilization asks for, from the
/// timer. A small decrease is ignored, to keep the frequency steady.
#[inline(always)]
pub fn calc_cpuperf_target(cid: Cid, cpuc: CpuCtx) {
    let Some(perf) = cid.slot::<Perf>() else {
        return;
    };
    let cap = cid.capacity();
    let target = if NO_FREQ_SCALING.get() {
        cap
    } else {
        let util_wall = cpuc.avg_util_wall().get().max(cpuc.cur_util_wall().get());
        if util_wall >= LAVD_CPU_UTIL_MAX_FOR_CPUPERF {
            cap
        } else {
            let util_invr = cpuc.avg_util_invr().get().max(cpuc.cur_util_invr().get());
            util_invr.min(cap)
        }
    };
    let target = round_up(target, cap >> LAVD_CPUPERF_UP_SHIFT).min(cap);
    let cur = perf.target().get();
    if target < cur && cur - target < (cap >> LAVD_CPUPERF_DOWN_SHIFT) {
        return;
    }
    perf.target().set(target);
}

/// Send `cid`'s target if it changed: the utilization's, or the demand of
/// the task running there if that is higher. From a callback that holds
/// `cid`'s runqueue.
#[inline(always)]
pub fn commit(cid: Cid, cpuc: CpuCtx) {
    let Some(perf) = cid.slot::<Perf>() else {
        return;
    };
    let target = perf.target().get().max(perf.floor().get()).max(1);
    if target != cpuc.cpuperf_cur().get() {
        cid.set_perf(target as u32);
        cpuc.cpuperf_cur().set(target);
    }
}

/// update_cpuperf_target(): the task starting on `cid` needs `demand` of
/// it, its duty cycle. The CPU's utilization takes time to follow a task's
/// demand, so the target goes up at once.
#[inline(always)]
pub fn update_cpuperf_target(cid: Cid, cpuc: CpuCtx, demand: u64) {
    let Some(perf) = cid.slot::<Perf>() else {
        return;
    };
    let step = LAVD_SCALE >> LAVD_CPUPERF_UP_SHIFT;
    perf.floor().set(round_up(demand, step).min(LAVD_SCALE));
    commit(cid, cpuc);
}

/// The task left `cid`: its demand no longer holds the target up.
#[inline(always)]
pub fn clear_floor(cid: Cid) {
    if let Some(perf) = cid.slot::<Perf>() {
        perf.floor().set(0);
    }
}

/// decay_idle_cpuperf_target(), from the timer: an idle CID sends the lower
/// target its utilization now asks for. Nothing runs there to commit it,
/// and a high request left behind holds up every CPU of its cpufreq
/// policy.
#[inline(always)]
pub fn decay_idle_cpuperf_target(cid: Cid, cpuc: CpuCtx) {
    if cpuc.idle_start_clk().get() == 0 {
        return;
    }
    let Some(perf) = cid.slot::<Perf>() else {
        return;
    };
    perf.floor().set(0);
    let target = perf.target().get().max(1);
    if target < cpuc.cpuperf_cur().get() {
        cid.set_perf(target as u32);
        cpuc.cpuperf_cur().set(target);
    }
}
