// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Piotr Gorski <lucjan.lucjanov@gmail.com>
//
// Ported from scx_lavd, Copyright (c) 2023-2025 Valve Corporation.
// Author of scx_lavd: Changwoo Min <changwoo@igalia.com>

//! scx_ravd: LAVD, the Latency-criticality Aware Virtual Deadline
//! scheduler, with its BPF program written in Rust.
//!
//! LAVD measures how latency-critical each task is from how it behaves:
//! a task that wakes others often, waits often and runs briefly is in the
//! middle of a task chain, and its delay delays the chain. That criticality
//! sets the task's virtual deadline, the tighter the more critical, and
//! the task with the earliest deadline runs next, for a time slice the
//! system's load sizes. A task that has had more than its share is
//! penalized in its deadline, and an urgent task that finds no idle CPU
//! takes one from a less urgent one.
//!
//! The callbacks are here, and the policy in the modules, named as lavd's
//! files are:
//!
//! ```text
//! select_cid    where a waking task goes                  idle.rs
//! enqueue       its deadline, then a CPU or a queue;     lat_cri.rs
//!               preempt for it if it is urgent           preempt.rs
//! dispatch      the earliest deadline of the CPU's own    balance.rs
//!               queue and its domain's, or a steal
//! runnable      waker and wakee hand their criticality
//! running       the slice, the logical clock, statistics
//! tick          runtime, and the slice with pinned tasks preempt.rs
//! stopping      runtime averages
//! quiescent     the waiting frequency
//! init          compute domains, the statistics timer   cpdom.rs
//!                                                         sys_stat.rs
//! ```
//!
//! Counterpart in scx_lavd: main.bpf.c.

#![no_std]
#![no_main]

use scx_rustsched::prelude::{
    Cid, DeqFlags, Dsq, DumpCtx, EnqFlags, Error, InitTaskArgs, KickFlags, Task, WakeFlags, dsq,
};
use scx_rustsched::ravg;
use scx_rustsched::time;

mod balance;
mod cpdom;
mod cpuctx;
mod idle;
mod lat_cri;
mod lavd;
mod math;
mod power;
mod preempt;
mod sys_stat;
mod taskctx;
mod util;

use cpuctx::CpuCtx;
use lavd::*;
use sys_stat::{CUR_LOGICAL_CLK, CUR_SVC_TIME_IWGT, SYS_STAT};
use taskctx::TaskCtx;
use util::{calc_avg, calc_avg_freq, time_delta, wall_to_invr};

// The tunables: one for each option of `Opts` in the loader,
// ../src/main.rs, named as the option in upper case, a time in
// microseconds as _NS.
scx_rustsched::opts!();

/// advance_cur_logical_clk(): the logical clock moves toward the deadline
/// of the task that starts running, slower the more tasks wait, so that
/// others can still get ahead of it.
#[inline(always)]
fn advance_cur_logical_clk(taskc: TaskCtx) {
    let vlc = taskc.deadline().get();
    let mut clc = CUR_LOGICAL_CLK.get();
    for _ in scx_rustsched::loops::range(0, LAVD_MAX_RETRY) {
        let new_clk = math::advance_clock(clc, vlc, SYS_STAT.nr_queued_task.get());
        if new_clk == clc {
            return;
        }
        let observed = CUR_LOGICAL_CLK.compare_exchange(clc, new_clk);
        if observed == clc {
            return;
        }
        clc = observed;
    }
}

/// calc_time_slice(): the slice of `taskc` on the CPU of `cpuc`.
#[inline(always)]
fn calc_time_slice(taskc: TaskCtx, cpuc: CpuCtx) -> u64 {
    let slice_wall = SYS_STAT.slice_wall.get();
    // Pinned tasks waiting here get the CPU promptly.
    let pinned = PINNED_SLICE_NS.get();
    if pinned != 0 && cpuc.nr_pinned_tasks().get() != 0 {
        let slice = pinned.min(slice_wall);
        taskc.slice_wall().set(slice);
        taskc.reset_flag(LAVD_FLAG_SLICE_BOOST);
        return slice;
    }
    // A task that runs longer than the slice would be switched out
    // before it is done: boost its slice, all the way while the system
    // can afford it, and in proportion to its latency criticality, up to
    // twice the slice, while it cannot.
    let avg_runtime = taskc.avg_runtime_wall().get();
    if !NO_SLICE_BOOST.get() && cpuc.nr_pinned_tasks().get() == 0 && avg_runtime >= slice_wall {
        if util::can_boost_slice() {
            // max().min() rather than clamp(), whose check of its bounds,
            // a tunable here, is a panic path.
            let slice = (avg_runtime + LAVD_SLICE_BOOST_BONUS)
                .max(SLICE_MIN_NS.get())
                .min(LAVD_SLICE_BOOST_MAX);
            taskc.slice_wall().set(slice);
            taskc.set_flag(LAVD_FLAG_SLICE_BOOST);
            return slice;
        }
        let lat_cri = taskc.lat_cri().get();
        let avg_lat_cri = SYS_STAT.avg_lat_cri.get();
        if lat_cri > avg_lat_cri {
            let boost = (slice_wall * lat_cri)
                .checked_div(avg_lat_cri + 1)
                .unwrap_or(0);
            let upper = avg_runtime.min(slice_wall * 2).max(SLICE_MIN_NS.get());
            let slice = (slice_wall + boost).max(SLICE_MIN_NS.get()).min(upper);
            taskc.slice_wall().set(slice);
            taskc.set_flag(LAVD_FLAG_SLICE_BOOST);
            return slice;
        }
    }
    taskc.slice_wall().set(slice_wall);
    taskc.reset_flag(LAVD_FLAG_SLICE_BOOST);
    slice_wall
}

/// The running average `field` of a context, accumulated with `value`.
#[inline(always)]
fn ravg_update<const OFFSET: u64>(
    field: scx_rustsched::arena::Field<ravg::Ravg, OFFSET>,
    value: u64,
    now: u64,
) -> u64 {
    let mut average = field.get();
    ravg::accumulate(&mut average, value, now, LAVD_RAVG_HALFLIFE_NS);
    field.set(average);
    ravg::read(&average, now, LAVD_RAVG_HALFLIFE_NS) >> ravg::FRAC_BITS
}

/// update_stat_for_running().
#[inline(always)]
fn update_stat_for_running(task: &Task, taskc: TaskCtx, cid: Cid, cpuc: CpuCtx, now: u64) {
    taskc
        .util_est()
        .set(ravg_update(taskc.avg_util(), LAVD_SCALE, now));

    // The scheduling frequency, over its runtime and the wait before it.
    if taskc.have_scheduled() {
        let wait_period = time_delta(now, taskc.last_quiescent_clk().get());
        let interval = taskc.avg_runtime_invr().get() + wait_period;
        if interval > 0 {
            taskc
                .run_freq()
                .update(|freq| calc_avg_freq(freq, interval));
        }
    }

    let prev = taskc.cid().get();
    taskc.prev_cid().set(prev);
    taskc.cid().set(i64::from(cid.raw()));
    taskc.reset_flag(LAVD_FLAG_IS_WAKEUP | LAVD_FLAG_IS_SYNC_WAKEUP);
    taskc.last_running_clk().set(now);
    taskc.last_measured_wall_clk().set(now);
    taskc.last_measured_exec().set(task.sum_exec_runtime());

    cpuc.util_est()
        .set(ravg_update(cpuc.avg_util(), LAVD_SCALE, now));

    let lat_cri = taskc.lat_cri().get();
    cpuc.max_lat_cri().update(|max| max.max(lat_cri));
    cpuc.sum_lat_cri().update(|sum| sum + lat_cri);
    cpuc.nr_sched().update(|n| n + 1);
    if cpdom::have_little_core() {
        let perf_cri = taskc.perf_cri().get();
        cpuc.max_perf_cri().update(|max| max.max(perf_cri));
        cpuc.min_perf_cri().update(|min| min.min(perf_cri));
        cpuc.sum_perf_cri().update(|sum| sum + perf_cri);
    }

    // What remote CPUs read for preemption, and no cut the timer asked
    // of the run before.
    cpuc.shrink_at().set(0);
    cpuc.flags().set(taskc.flags().get());
    cpuc.lat_cri().set(lat_cri);
    cpuc.running_clk().set(now);
    cpuc.est_stopping_clk()
        .set(preempt::get_est_stopping_clk(taskc, now));

    if util::is_lat_cri(taskc) {
        cpuc.nr_lat_cri().update(|n| n + 1);
    }
    if power::is_perf_cri(taskc) {
        cpuc.nr_perf_cri().update(|n| n + 1);
    }
    if let Some(prev_cpuc) = cpuctx::get(Cid(prev as i32))
        && prev_cpuc.cpdom_id().get() != cpuc.cpdom_id().get()
    {
        cpuc.nr_x_migration().update(|n| n + 1);
    }
}

/// account_task_runtime(): what the task ran since it was last measured,
/// as the kernel accounted it, se.sum_exec_runtime. lavd reads the task
/// clock and bounds it by the same.
#[inline(always)]
fn account_task_runtime(task: &Task, taskc: TaskCtx, cid: Cid, cpuc: CpuCtx, now: u64) {
    let exec_now = task.sum_exec_runtime();
    let last = taskc.last_measured_exec().get();
    let task_time_wall = if last == 0 {
        0
    } else {
        time_delta(exec_now, last)
    };
    let task_time_invr = wall_to_invr(task_time_wall, cid);
    let task_time_iwgt = task_time_invr
        .checked_div(util::scx_weight(task))
        .unwrap_or(0);

    cpuc.tot_task_time_wall().add(task_time_wall);
    cpuc.tot_task_time_invr().add(task_time_invr);
    cpuc.tot_task_time_iwgt().add(task_time_iwgt);

    taskc.acc_runtime_wall().update(|acc| acc + task_time_wall);
    taskc.acc_runtime_invr().update(|acc| acc + task_time_invr);
    taskc.svc_time_iwgt().update(|svc| svc + task_time_iwgt);
    taskc.last_measured_wall_clk().set(now);
    taskc.last_measured_exec().set(exec_now);
}

/// update_stat_for_stopping().
#[inline(always)]
fn update_stat_for_stopping(task: &Task, taskc: TaskCtx, cid: Cid, cpuc: CpuCtx) {
    let now = time::now();
    account_task_runtime(task, taskc, cid, cpuc, now);
    taskc
        .avg_runtime_wall()
        .update(|avg| calc_avg(avg, taskc.acc_runtime_wall().get()));
    taskc
        .avg_runtime_invr()
        .update(|avg| calc_avg(avg, taskc.acc_runtime_invr().get()));
    cpuc.util_est().set(ravg_update(cpuc.avg_util(), 0, now));
    taskc
        .last_slice_used_wall()
        .set(time_delta(now, taskc.last_running_clk().get()));
    let svc = taskc.svc_time_iwgt().get();
    if CUR_SVC_TIME_IWGT.get() < svc {
        CUR_SVC_TIME_IWGT.set(svc);
    }
}

/// update_stat_for_refill(): the task keeps the CPU and gets a new slice,
/// which its average runtime sizes.
#[inline(always)]
fn update_stat_for_refill(task: &Task, taskc: TaskCtx, cid: Cid, cpuc: CpuCtx) {
    account_task_runtime(task, taskc, cid, cpuc, time::now());
    taskc
        .avg_runtime_wall()
        .update(|avg| calc_avg(avg, taskc.acc_runtime_wall().get()));
    taskc
        .avg_runtime_invr()
        .update(|avg| calc_avg(avg, taskc.acc_runtime_invr().get()));
}

/// can_direct_dispatch(): straight to the local DSQ of a CPU found idle
/// with nothing waiting, or, under low utilization, of one that is not
/// congested and runs no task of a higher class.
#[inline(always)]
fn can_direct_dispatch(task: &Task, cid: Cid, cpuc: CpuCtx, is_idle: bool) -> bool {
    if !task.allowed_on(cid) {
        return false;
    }
    // The claim is a hint, which can be stale: bypass mode skips
    // ops.update_idle(). Check that the CPU really runs its idle task.
    if is_idle && !util::queued_on_cpu(cid, cpuc) && util::is_cpu_idle_now(cid) {
        return true;
    }
    let low_util = p2s(LB_LOCAL_DSQ_UTIL_PCT.get());
    low_util > 0
        && cpuc.avg_util_wall().get() < low_util
        && !util::is_cpu_congested(cid, cpuc)
        && !util::is_rt_or_dl_task_running(cid)
}

/// The queue a task waits in, get_target_dsq_id(): the CPU's own for a
/// pinned task, when pinned tasks get a slice of their own or every task
/// waits per CPU, and its domain's otherwise.
#[inline(always)]
fn insert_queued(task: &Task, taskc: TaskCtx, cid: Cid, dom: u64, flags: EnqFlags) {
    let slice = task.slice();
    let deadline = taskc.deadline().get();
    if PER_CPU_DSQ.get() || (PINNED_SLICE_NS.get() != 0 && util::is_pinned(task)) {
        dsq::insert_vtime(task, dsq::Edq::Cid(cid), slice, deadline, flags);
    } else {
        dsq::insert_vtime(task, cpdom::queue(dom), slice, deadline, flags);
    }
}

/// ops.select_cid(): pick_idle_cpu(), and a task found an idle CPU with
/// nothing waiting goes straight to it.
#[inline(always)]
fn select_cid(task: &Task, prev: Cid, wake_flags: WakeFlags) -> Cid {
    let Some(taskc) = taskctx::lookup(task) else {
        return prev;
    };
    // A synchronous wakeup boosts the latency criticality later.
    taskc.assign_flag(
        LAVD_FLAG_IS_SYNC_WAKEUP,
        wake_flags.contains(WakeFlags::SYNC),
    );
    let pick = idle::pick_idle_cpu(task, taskc, prev, true);
    taskc.suggested_cid().set(i64::from(pick.cid.raw()));
    if !pick.idle {
        taskc.reset_flag(LAVD_FLAG_IDLE_CPU_PICKED);
        return pick.cid;
    }
    taskc.set_flag(LAVD_FLAG_IDLE_CPU_PICKED);
    let Some(cpuc) = cpuctx::get(pick.cid) else {
        return pick.cid;
    };
    if can_direct_dispatch(task, pick.cid, cpuc, true) {
        taskc.deadline().set(lat_cri::calc_when_to_run(task, taskc));
        dsq::insert(task, Dsq::Local, LAVD_SLICE_MAX_NS_DFL, EnqFlags::NONE);
    }
    pick.cid
}

/// ops.enqueue(): the task's deadline, then a CPU for it and a queue; a
/// CPU it found idle is kicked, and otherwise a less urgent task may be
/// preempted for it.
#[inline(always)]
fn enqueue(task: &Task, flags: EnqFlags) {
    let Some(taskc) = taskctx::lookup(task) else {
        dsq::insert(task, Dsq::Global, LAVD_SLICE_MIN_NS_DFL, flags);
        return;
    };
    let reenq = config_flag(scx_rustsched::config::ENQ_REENQ, flags);

    // A task the kernel handed back, its CPU taken by a higher class, has
    // not run since: it keeps its CPU choice and goes in that queue again,
    // with its deadline taken from the clock as it is now.
    if reenq {
        // The affinity may have changed since the CPU was chosen.
        let cid = util::allowed_cid(task, Cid(taskc.suggested_cid().get() as i32));
        taskc.suggested_cid().set(i64::from(cid.raw()));
        let Some(cpuc) = cpuctx::get(cid) else {
            dsq::insert(task, Dsq::Global, task.slice(), flags);
            return;
        };
        taskc.deadline().set(lat_cri::calc_when_to_run(task, taskc));
        insert_queued(task, taskc, cid, cpuc.cpdom_id().get(), flags);
        kick_or_preempt(task, taskc, cid, cpuc, false);
        return;
    }

    taskc.assign_flag(LAVD_FLAG_IS_WAKEUP, flags.contains(EnqFlags::WAKEUP));
    taskc.deadline().set(lat_cri::calc_when_to_run(task, taskc));
    task.set_slice(LAVD_SLICE_MIN_NS_DFL);

    let (cid, is_idle) = if flags.cid_selected() {
        let picked = taskc.test_flag(LAVD_FLAG_IDLE_CPU_PICKED);
        taskc.reset_flag(LAVD_FLAG_IDLE_CPU_PICKED);
        (task.cid(), picked)
    } else {
        // Without ops.select_cid(), the task's CPU can lag a change of
        // its affinity: set_cpus_allowed() enqueues it again before it
        // moves it.
        let prev = util::allowed_cid(task, task.cid());
        let pick = idle::pick_idle_cpu(task, taskc, prev, false);
        (pick.cid, pick.idle)
    };
    let Some(cpuc) = cpuctx::get(cid) else {
        dsq::insert(task, Dsq::Global, task.slice(), flags);
        return;
    };
    let dom = cpuc.cpdom_id().get();
    taskc.suggested_cid().set(i64::from(cid.raw()));
    taskc.cpdom_id().set(dom);

    // A pinned task counts on its CPU, which shortens the slices there,
    // until it stops being runnable.
    if util::is_pinned(task) && taskc.pinned_cid().get() == NO_CID {
        taskc.pinned_cid().set(i64::from(cid.raw()));
        cpuc.nr_pinned_tasks().add(1);
    }

    if can_direct_dispatch(task, cid, cpuc, is_idle) {
        dsq::insert(task, Dsq::LocalOn(cid), task.slice(), flags);
    } else {
        insert_queued(task, taskc, cid, dom, flags);
    }
    kick_or_preempt(task, taskc, cid, cpuc, is_idle);
}

/// Is the kernel's flag at config word `index`, 0 where it has none, set in
/// `flags`?
#[inline(always)]
fn config_flag(index: usize, flags: EnqFlags) -> bool {
    let flag = scx_rustsched::config::get(index);
    flag != 0 && flags.raw() & flag != 0
}

/// Wake `cid` if it was found or is marked idle; otherwise look for a CPU
/// to take from a less urgent task.
#[inline(always)]
fn kick_or_preempt(task: &Task, taskc: TaskCtx, cid: Cid, cpuc: CpuCtx, is_idle: bool) {
    if is_idle || cid.is_idle() {
        cid.kick(KickFlags::IDLE);
        return;
    }
    if !NO_PREEMPTION.get() {
        preempt::try_find_and_kick_victim_cpu(task, taskc, cid, cpuc.cpdom_id().get());
    }
}

/// consume_prev(): with nothing else to run, the task that was running
/// goes on, with a new slice.
#[inline(always)]
fn consume_prev(prev: &Task, cid: Cid, cpuc: CpuCtx) {
    if !prev.queued() {
        return;
    }
    let Some(taskc) = taskctx::lookup(prev) else {
        return;
    };
    update_stat_for_refill(prev, taskc, cid, cpuc);
    prev.set_slice(calc_time_slice(taskc, cpuc));
    // The slice boost flag may have changed.
    cpuc.flags().set(taskc.flags().get());
}

/// ops.dispatch(): the earliest deadline of this CPU's queues, a task
/// stolen from another domain, or the task that was running.
#[inline(always)]
fn dispatch(cid: Cid, prev: Option<&Task>) {
    let Some(cpuc) = cpuctx::get(cid) else {
        return;
    };
    if balance::consume_task(cid, cpuc.cpdom_id().get()) {
        return;
    }
    if let Some(prev) = prev {
        consume_prev(prev, cid, cpuc);
    }
}

/// ops.runnable(): the task's runtime since it woke starts from zero, and
/// a wakeup by a related task hands latency criticality over both ways.
#[inline(always)]
fn runnable(task: &Task, flags: EnqFlags) {
    let Some(taskc) = taskctx::lookup(task) else {
        return;
    };
    taskc.acc_runtime_wall().set(0);
    taskc.acc_runtime_invr().set(0);

    if !flags.contains(EnqFlags::WAKEUP)
        || flags.contains(EnqFlags::PREEMPT)
        || flags.last()
        || config_flag(scx_rustsched::config::ENQ_REENQ, flags)
    {
        return;
    }
    // The waker is the task running here. Only tasks of one parent are
    // taken as related, kernel tasks with kernel tasks.
    // An interrupt that woke the task from the idle task leaves nothing to
    // credit. lavd also skips every wakeup from interrupt context, which
    // the runtime cannot tell.
    let Some(waker) = Task::current() else {
        return;
    };
    if waker.pid() == 0 {
        return;
    }
    if task.parent_id() != waker.parent_id() || task.is_kthread() != waker.is_kthread() {
        return;
    }
    // The criticality of an RT or DL waker is not tracked: the wakee gets
    // a fixed boost instead.
    taskc.assign_flag(LAVD_FLAG_WOKEN_BY_RT_DL, waker.rt_or_dl());
    let Some(waker_taskc) = taskctx::lookup_optional(waker) else {
        return;
    };

    // How often the waker wakes others.
    let now = time::now();
    let interval = time_delta(now, waker_taskc.last_runnable_clk().get());
    if interval >= LAVD_LC_WAKE_INTERVAL_MIN {
        waker_taskc
            .wake_freq()
            .update(|freq| calc_avg_freq(freq, interval));
        waker_taskc.last_runnable_clk().set(now);
    }

    // Forward to the wakee, and backward to the waker.
    taskc.lat_cri_waker().set(waker_taskc.lat_cri().get());
    let lat_cri = taskc.lat_cri().get();
    waker_taskc
        .lat_cri_wakee()
        .update(|wakee| wakee.max(lat_cri));
}

/// ops.running(): the slice, the logical clock and the statistics.
#[inline(always)]
fn running(task: &Task) {
    let Some(taskc) = taskctx::lookup(task) else {
        return;
    };
    let cid = task.cid();
    let Some(cpuc) = cpuctx::get(cid) else {
        return;
    };
    let now = time::now();
    // A task the kernel dispatched itself, as it does in bypass mode,
    // skipped our deadline: it runs at the logical clock.
    if task.slice() == dsq::SLICE_DFL {
        taskc.deadline().set(CUR_LOGICAL_CLK.get());
    }
    task.set_slice(calc_time_slice(taskc, cpuc));
    advance_cur_logical_clk(taskc);
    update_stat_for_running(task, taskc, cid, cpuc, now);
    power::update_cpuperf_target(cid, cpuc, taskc.util_est().get().min(LAVD_SCALE));
}

/// ops.tick(): account the runtime, refresh the performance target, and
/// keep the slice short with a pinned task waiting.
#[inline(always)]
fn tick(task: &Task) {
    let Some(taskc) = taskctx::lookup(task) else {
        return;
    };
    let cid = task.cid();
    let Some(cpuc) = cpuctx::get(cid) else {
        return;
    };
    let now = time::now();
    power::commit(cid, cpuc);
    account_task_runtime(task, taskc, cid, cpuc, now);
    preempt::apply_shrink(task, cpuc, now);
    if cpuc.nr_pinned_tasks().get() != 0 {
        preempt::shrink_slice_at_tick(task, cpuc, now);
    }
}

/// ops.stopping(): fold the run into the averages.
#[inline(always)]
fn stopping(task: &Task, _runnable: bool) {
    let Some(taskc) = taskctx::lookup(task) else {
        return;
    };
    let cid = task.cid();
    let Some(cpuc) = cpuctx::get(cid) else {
        return;
    };
    update_stat_for_stopping(task, taskc, cid, cpuc);
    power::clear_floor(cid);
}

/// ops.quiescent(): the task stops being runnable. Its pinned count goes,
/// and a sleep updates its duty cycle and how often it waits.
#[inline(always)]
fn quiescent(task: &Task, flags: DeqFlags) {
    let Some(taskc) = taskctx::lookup(task) else {
        return;
    };
    if let Some(cpuc) = cpuctx::get(task.cid()) {
        cpuc.flags().set(0);
    }
    let pinned = taskc.pinned_cid().get();
    if pinned != NO_CID {
        if let Some(cpuc) = cpuctx::get(Cid(pinned as i32)) {
            cpuctx::dec_pinned(cpuc);
        }
        taskc.pinned_cid().set(NO_CID);
    }
    if !flags.contains(DeqFlags::SLEEP) {
        return;
    }
    let now = time::now();
    taskc.util_est().set(ravg_update(taskc.avg_util(), 0, now));
    let interval = time_delta(now, taskc.last_quiescent_clk().get());
    if interval > 0 {
        taskc
            .wait_freq()
            .update(|freq| calc_avg_freq(freq, interval));
        taskc.last_quiescent_clk().set(now);
    }
}

/// ops.update_idle(): the idle time a CPU's utilization is computed from,
/// and what it runs for preemption: nothing.
#[inline(always)]
fn update_idle(cid: Cid, idle: bool) {
    let Some(cpuc) = cpuctx::get(cid) else {
        return;
    };
    let now = time::now();
    if idle {
        cpuc.idle_start_clk().set(now);
        cpuc.reset_preemption_info();
        if util::queued_on_cpu(cid, cpuc) {
            cid.kick(KickFlags::IDLE);
        }
        return;
    }
    for _ in scx_rustsched::loops::range(0, LAVD_MAX_RETRY) {
        let old = cpuc.idle_start_clk().get();
        if old == 0 {
            break;
        }
        if cpuc.idle_start_clk().compare_exchange(old, 0) == old {
            if !time::before(now, old) {
                cpuc.idle_total_wall().add(now - old);
            }
            break;
        }
    }
}

/// ops.enable(): a task starts with the largest service time any task
/// has had, so it does not get ahead of the others.
#[inline(always)]
fn enable(task: &Task) {
    if let Some(taskc) = taskctx::lookup(task) {
        taskc.svc_time_iwgt().set(CUR_SVC_TIME_IWGT.get());
    }
}

/// ops.init_task(): a forked task starts from its parent's behavior, which
/// is the task running the fork, and any other from the system's.
#[inline(always)]
fn init_task(task: &Task, args: &InitTaskArgs) {
    let Some(taskc) = taskctx::lookup(task) else {
        return;
    };
    let now = time::now();
    let parent = if args.fork() {
        Task::current().and_then(taskctx::lookup_optional)
    } else {
        None
    };
    if let Some(parent) = parent {
        taskc.lat_cri().set(parent.lat_cri().get());
        taskc.perf_cri().set(parent.perf_cri().get());
        taskc.run_freq().set(parent.run_freq().get());
        taskc.wait_freq().set(parent.wait_freq().get());
        taskc.wake_freq().set(parent.wake_freq().get());
        taskc
            .avg_runtime_wall()
            .set(parent.avg_runtime_wall().get());
        taskc
            .avg_runtime_invr()
            .set(parent.avg_runtime_invr().get());
        taskc.svc_time_iwgt().set(parent.svc_time_iwgt().get());
        taskc.avg_util().set(parent.avg_util().get());
        taskc.util_est().set(parent.util_est().get());
        taskc
            .last_runnable_clk()
            .set(parent.last_runnable_clk().get());
        taskc
            .last_running_clk()
            .set(parent.last_running_clk().get());
        taskc
            .last_quiescent_clk()
            .set(parent.last_quiescent_clk().get());
    } else {
        taskc.last_runnable_clk().set(now);
        taskc.last_running_clk().set(now);
        taskc.last_quiescent_clk().set(now);
        taskc.avg_runtime_wall().set(SYS_STAT.slice_wall.get());
        taskc.avg_runtime_invr().set(SYS_STAT.slice_wall.get());
        taskc.svc_time_iwgt().set(SYS_STAT.avg_svc_time_iwgt.get());
    }
    taskc.suggested_cid().set(i64::from(task.cid().raw()));
    taskc.pinned_cid().set(NO_CID);
}

/// ops.exit_task(): a pinned count still held goes with the task.
#[inline(always)]
fn exit_task(task: &Task) {
    if let Some(taskc) = taskctx::lookup(task) {
        let pinned = taskc.pinned_cid().get();
        if pinned != NO_CID
            && let Some(cpuc) = cpuctx::get(Cid(pinned as i32))
        {
            cpuctx::dec_pinned(cpuc);
        }
        taskc.pinned_cid().set(NO_CID);
    }
}

/// ops.init(): the compute domains, the CPU contexts and the timer.
#[inline(always)]
fn init() -> i32 {
    let result = cpdom::init();
    if result != 0 {
        return result;
    }
    let result = power::init();
    if result != 0 {
        return result;
    }
    for cid in Cid::all() {
        if let Some(cpuc) = cpuctx::get(cid) {
            cpuc.reset_preemption_info();
            cpuc.min_perf_cri().set(LAVD_SCALE);
        }
    }
    sys_stat::init(time::now())
}

#[scx_rustsched::scheduler(
    name = "ravd",
    flags = TID_TO_TASK | ENQ_LAST | ENQ_EXITING | ENQ_MIGRATION_DISABLED,
    timeout_ms = 30000,
    task_slot = taskctx::TaskCtx,
    cid_slot = cpuctx::CpuCtx
)]
impl Ravd {
    #[inline(always)]
    fn init() -> Result<(), Error> {
        Error::check(init())
    }

    #[inline(always)]
    fn init_task(task: &Task, args: &InitTaskArgs) {
        init_task(task, args)
    }

    #[inline(always)]
    fn exit_task(task: &Task) {
        exit_task(task)
    }

    #[inline(always)]
    fn enable(task: &Task) {
        enable(task)
    }

    #[inline(always)]
    fn select_cid(task: &Task, prev: Cid, flags: WakeFlags) -> Cid {
        select_cid(task, prev, flags)
    }

    #[inline(always)]
    fn enqueue(task: &Task, flags: EnqFlags) {
        enqueue(task, flags)
    }

    #[inline(always)]
    fn dispatch(cid: Cid, prev: Option<&Task>) {
        dispatch(cid, prev)
    }

    #[inline(always)]
    fn runnable(task: &Task, flags: EnqFlags) {
        runnable(task, flags)
    }

    #[inline(always)]
    fn running(task: &Task) {
        running(task)
    }

    #[inline(always)]
    fn tick(task: &Task) {
        tick(task)
    }

    #[inline(always)]
    fn stopping(task: &Task, runnable: bool) {
        stopping(task, runnable)
    }

    #[inline(always)]
    fn quiescent(task: &Task, flags: DeqFlags) {
        quiescent(task, flags)
    }

    #[inline(always)]
    fn update_idle(cid: Cid, idle: bool) {
        update_idle(cid, idle)
    }

    #[inline(always)]
    fn dump(_dump: &DumpCtx) {
        scx_rustsched::dump!(
            "ravd clock=%llu slice=%llu avg_lat_cri=%llu thr_lat_cri=%llu",
            CUR_LOGICAL_CLK.get(),
            SYS_STAT.slice_wall.get(),
            SYS_STAT.avg_lat_cri.get(),
            SYS_STAT.thr_lat_cri.get()
        );
    }

    #[inline(always)]
    fn dump_task(_dump: &DumpCtx, task: &Task) {
        if let Some(taskc) = taskctx::lookup(task) {
            scx_rustsched::dump!(
                "ravd lat_cri=%llu perf_cri=%llu deadline=%llu slice=%llu",
                taskc.lat_cri().get(),
                taskc.perf_cri().get(),
                taskc.deadline().get(),
                taskc.slice_wall().get()
            );
        }
    }
}
