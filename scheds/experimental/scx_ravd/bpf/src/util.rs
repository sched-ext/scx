// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Piotr Gorski <lucjan.lucjanov@gmail.com>
//
// Ported from scx_lavd, Copyright (c) 2023-2025 Valve Corporation.
// Author of scx_lavd: Changwoo Min <changwoo@igalia.com>

//! Arithmetic and the questions the policy asks of a task or a CPU.
//!
//! Counterpart in scx_lavd: util.bpf.c, and the helpers of common.bpf.h
//! it uses.

use scx_rustsched::dsq::{self, Dsq};
use scx_rustsched::helpers;
use scx_rustsched::sched::Cid;
use scx_rustsched::task::Task;

use crate::cpdom;
use crate::cpuctx::CpuCtx;
use crate::lavd::*;
use crate::sys_stat::SYS_STAT;
use crate::taskctx::TaskCtx;

pub use crate::math::{calc_asym_avg, calc_avg, calc_avg_freq, time_delta};

/// One, as an unknown scalar to the verifier: always 1, but kept in a
/// writable global, as the runtime's LOOP_ONE is for the loop step.
static ONE: scx_rustsched::var::Var<u64> = scx_rustsched::var::Var::new(1);

/// What a counter carried across a loop adds per step. A counter the
/// verifier tracks as a precise constant, because something later compares
/// it, is a new state in every iteration: the loop never converges, and the
/// verifier gives up on "the sequence of 8193 jumps is too complex".
#[inline(always)]
pub fn one() -> u64 {
    ONE.get()
}

/// The task's weight as sched_ext gives it, p->scx.weight: 100 at nice 0,
/// within [1, 10000]. lavd's arithmetic is calibrated to it.
#[inline(always)]
pub fn scx_weight(task: &Task) -> u64 {
    crate::math::scx_weight_of(task.weight())
}

/// scale_by_task_weight_inverse().
#[inline(always)]
pub fn scale_by_task_weight_inverse(task: &Task, value: u64) -> u64 {
    (value * 100).checked_div(scx_weight(task)).unwrap_or(value)
}

/// Wall clock time spent on `cid`, as capacity-invariant time.
///
/// lavd measures invariant time with the PELT clock, which is scaled by
/// both capacity and frequency. The port scales by capacity only, which
/// leaves out frequency: a task on a slowed-down CPU is credited with the
/// work its full frequency would have done.
#[inline(always)]
pub fn wall_to_invr(wall: u64, cid: Cid) -> u64 {
    (wall * cid.capacity()) >> LAVD_SHIFT
}

/// Is the task more latency-critical than average, is_lat_cri()?
#[inline(always)]
pub fn is_lat_cri(taskc: TaskCtx) -> bool {
    taskc.lat_cri().get() >= SYS_STAT.avg_lat_cri.get()
}

/// is_kernel_task().
#[inline(always)]
pub fn is_kernel_task(task: &Task) -> bool {
    task.is_kthread()
}

/// is_kernel_worker().
#[inline(always)]
pub fn is_kernel_worker(task: &Task) -> bool {
    task.is_kworker()
}

/// is_affinitized(): the task may not run on every CPU. lavd also counts
/// a task whose cpus_ptr is not its own mask, which only a task that
/// disabled migration has, and that is counted here.
#[inline(always)]
pub fn is_affinitized(task: &Task) -> bool {
    task.nr_cpus_allowed() != Cid::nr_cpus() || task.pinned()
}

/// The task is bound to one CPU, by its affinity or because it disabled
/// migration: is_effectively_pinned() or is_migration_disabled().
#[inline(always)]
pub fn is_pinned(task: &Task) -> bool {
    task.pinned()
}

/// Can the time slice be boosted, can_boost_slice()? Not at 95%
/// utilization or more, nor with more tasks queued than CPUs active.
#[inline(always)]
pub fn can_boost_slice() -> bool {
    SYS_STAT.avg_util_wall.get() <= LAVD_SLICE_BOOST_UTIL_WALL
        && SYS_STAT.nr_queued_task.get() <= SYS_STAT.nr_active.get()
}

/// prob_x_out_of_y(): true with a probability of x/y.
#[inline(always)]
pub fn prob_x_out_of_y(x: u64, y: u64) -> bool {
    if x >= y {
        return true;
    }
    let r = u64::from(helpers::get_prandom_u32())
        .checked_rem(y)
        .unwrap_or(0);
    r < x
}

/// normalize_lat_cri(): the latency criticality on [0, 1024], against the
/// system's maximum.
#[inline(always)]
pub fn normalize_lat_cri(lat_cri: u64) -> u64 {
    let max = SYS_STAT.max_lat_cri.get();
    if max == 0 {
        return 0;
    }
    if lat_cri >= max {
        return LAVD_SCALE;
    }
    (lat_cri << LAVD_SHIFT).checked_div(max).unwrap_or(0) & 0xffff
}

/// Does `cid` have something waiting, queued_on_cpu(): on its local DSQ,
/// its own queue or its domain's?
#[inline(always)]
pub fn queued_on_cpu(cid: Cid, cpuc: CpuCtx) -> bool {
    dsq::nr_queued(Dsq::LocalOn(cid)) != 0
        || cid.has_queued()
        || dsq::nr_queued(cpdom::queue(cpuc.cpdom_id().get())) != 0
}

/// Is `cid` congested, is_cpu_congested(): a task waiting across its
/// queues?
#[inline(always)]
pub fn is_cpu_congested(cid: Cid, cpuc: CpuCtx) -> bool {
    let mut nr = u64::from(dsq::nr_queued(Dsq::LocalOn(cid)));
    if nr >= LAVD_CPU_CONGESTED_THRES {
        return true;
    }
    nr += u64::from(dsq::nr_queued(cpdom::queue(cpuc.cpdom_id().get())));
    if nr >= LAVD_CPU_CONGESTED_THRES {
        return true;
    }
    nr + cid.nr_queued() >= LAVD_CPU_CONGESTED_THRES
}

/// Is a realtime or deadline task running on `cid`,
/// is_rt_or_dl_task_running()?
#[inline(always)]
pub fn is_rt_or_dl_task_running(cid: Cid) -> bool {
    let curr = scx_rustsched::kfuncs::scx_bpf_cid_curr(cid.raw());
    if curr.is_null() {
        return false;
    }
    // SAFETY: the kernel returned the task running on the CID, which
    // stays valid under the RCU read lock every callback runs in, and it
    // is only read.
    unsafe { Task::from_ptr(curr) }.rt_or_dl()
}

/// Is `cid` running its idle task, is_cpu_idle_now()? Only from a callback,
/// which holds the RCU read lock the kfunc needs.
#[inline(always)]
pub fn is_cpu_idle_now(cid: Cid) -> bool {
    let curr = scx_rustsched::kfuncs::scx_bpf_cid_curr(cid.raw());
    if curr.is_null() {
        return false;
    }
    // SAFETY: as in is_rt_or_dl_task_running().
    unsafe { Task::from_ptr(curr) }.pid() == 0
}

/// The first CID `task` may run on, for a task whose CPU is not one of
/// them, bpf_cpumask_first(p->cpus_ptr). A global function: it loops.
#[scx_rustsched::global]
fn first_allowed_cid(task: &Task) -> i32 {
    for cid in Cid::all() {
        if task.allowed_on(cid) {
            return cid.raw();
        }
    }
    -1
}

/// `cid` if `task` may run there, or the first CID it may run on. The
/// task's own CID is the last resort, which the kernel always lets it
/// stay on.
#[inline(always)]
pub fn allowed_cid(task: &Task, cid: Cid) -> Cid {
    if task.allowed_on(cid) {
        return cid;
    }
    let first = first_allowed_cid(task);
    if first >= 0 { Cid(first) } else { task.cid() }
}
