// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Piotr Gorski <lucjan.lucjanov@gmail.com>
//
// Ported from scx_lavd, Copyright (c) 2023-2025 Valve Corporation.
// Author of scx_lavd: Changwoo Min <changwoo@igalia.com>

//! Latency criticality and the virtual deadline it sets.
//!
//! A task is more latency-critical the more often it waits (it consumes
//! events), the more often it wakes others (it produces them), and the
//! shorter it runs each time. In a chain A -> B -> C, the delay of B delays
//! everything behind it. The criticality then sets the task's virtual
//! deadline: the more critical, the tighter, so the task is picked sooner.
//!
//! Counterpart in scx_lavd: lat_cri.bpf.c. The factors, their weights and
//! the deadline are lavd's. Two inputs are missing: the port cannot tell a
//! wakeup from an interrupt handler, so no task is boosted for being woken
//! by a hardirq or a softirq, nor recognize ksoftirqd by its name; and
//! there is no futex tracking, so no lock holder is boosted.

use scx_rustsched::task::Task;

use crate::cpdom;
use crate::lavd::*;
use crate::math::{
    compete_window, deadline_delta, greedy_penalty, lat_cri_of, log2x, reverse_runtime_factor,
};
use crate::sys_stat::{CUR_LOGICAL_CLK, SYS_STAT};
use crate::taskctx::TaskCtx;
use crate::util::{
    is_affinitized, is_kernel_task, is_kernel_worker, is_pinned, normalize_lat_cri,
    scale_by_task_weight_inverse, scx_weight,
};

/// The weight of the task, boosted by the context it runs in: a wakeup, a
/// synchronous one, a waker of a realtime class, a kernel task or worker,
/// or one restricted in where it can run.
#[inline(always)]
fn calc_weight_factor(task: &Task, taskc: TaskCtx) -> u64 {
    let mut weight_boost = 1;

    // A wakeup is a clear sign of an immediate consumer, and a
    // synchronous one twice so.
    if taskc.test_flag(LAVD_FLAG_IS_WAKEUP) {
        weight_boost += LAVD_LC_WEIGHT_BOOST_REGULAR;
    }
    if taskc.test_flag(LAVD_FLAG_IS_SYNC_WAKEUP) {
        weight_boost += LAVD_LC_WEIGHT_BOOST_REGULAR;
    }
    // A task woken by an RT or DL task, whose criticality is not
    // tracked, gets a fixed boost instead of inheriting it.
    if taskc.test_flag(LAVD_FLAG_WOKEN_BY_RT_DL) {
        taskc.reset_flag(LAVD_FLAG_WOKEN_BY_RT_DL);
        weight_boost += LAVD_LC_WEIGHT_BOOST_HIGH;
    }
    // Many kernel tasks serve latency-critical work, kworkers more so.
    if is_kernel_task(task) {
        weight_boost += LAVD_LC_WEIGHT_BOOST_MEDIUM;
    }
    if is_kernel_worker(task) {
        weight_boost += LAVD_LC_WEIGHT_BOOST_REGULAR;
    }
    // A task restricted in its placement tends to be delayed, and one
    // pinned to a CPU more so.
    if is_affinitized(task) {
        weight_boost += LAVD_LC_WEIGHT_BOOST_REGULAR;
    }
    if is_pinned(task) {
        weight_boost += LAVD_LC_WEIGHT_BOOST_MEDIUM;
    }

    // Respect the nice priority.
    scx_weight(task) * weight_boost + 1
}

#[inline(always)]
fn calc_wait_factor(taskc: TaskCtx) -> u64 {
    taskc.wait_freq().get().min(LAVD_LC_FREQ_MAX) + 1
}

#[inline(always)]
fn calc_wake_factor(taskc: TaskCtx) -> u64 {
    taskc.wake_freq().get().min(LAVD_LC_FREQ_MAX) + 1
}

/// The task's compute demand per second, run_freq * runtime, which makes it
/// performance-critical rather than latency-critical.
#[inline(always)]
fn calc_sum_runtime_factor(task: &Task, taskc: TaskCtx) -> u64 {
    let runtime = taskc
        .avg_runtime_invr()
        .get()
        .max(taskc.acc_runtime_invr().get());
    let sum = taskc.run_freq().get().max(1) * runtime.max(1);
    (sum >> LAVD_SHIFT) * scx_weight(task)
}

/// calc_lat_cri(): the task's latency criticality, and its performance
/// criticality on a machine of big and little cores.
#[inline(always)]
pub fn calc_lat_cri(task: &Task, taskc: TaskCtx) {
    let wait_ft = calc_wait_factor(taskc);
    let wake_ft = calc_wake_factor(taskc);
    let runtime_ft = reverse_runtime_factor(taskc.avg_runtime_invr().get());
    let weight_ft = calc_weight_factor(task, taskc);
    let giver = taskc.lat_cri_waker().get() + taskc.lat_cri_wakee().get();
    let (lat_cri, log_wwf) = lat_cri_of(wait_ft, wake_ft, runtime_ft, weight_ft, giver);
    taskc.lat_cri().set(lat_cri);
    taskc.lat_cri_waker().set(0);
    taskc.lat_cri_wakee().set(0);
    taskc.normalized_lat_cri().set(normalize_lat_cri(lat_cri));

    // A task is performance-critical, worth a big core and a high
    // frequency, in the middle of a task chain, with long and frequent
    // runs and a high priority.
    let mut perf_cri = LAVD_SCALE;
    if cpdom::have_little_core() {
        let sum_runtime_ft = calc_sum_runtime_factor(task, taskc);
        perf_cri = log_wwf + log2x(sum_runtime_ft);
    }
    taskc.perf_cri().set(perf_cri & 0xffff);
}

/// The task's lag against the system's average service, as a penalty of
/// [100%, 200%] for a greedy task, which has had more than its share.
#[inline(always)]
fn calc_greedy_penalty(task: &Task, taskc: TaskCtx) -> u64 {
    let lag_max = scale_by_task_weight_inverse(task, LAVD_TASK_LAG_MAX);
    let greedy = greedy_penalty(
        SYS_STAT.avg_svc_time_iwgt.get(),
        taskc.svc_time_iwgt().get(),
        lag_max,
    );
    taskc.assign_flag(LAVD_FLAG_IS_GREEDY, greedy.greedy);
    taskc.svc_time_iwgt().set(greedy.svc_time_iwgt);
    greedy.penalty
}

#[inline(always)]
fn calc_virtual_deadline_delta(task: &Task, taskc: TaskCtx) -> u64 {
    calc_lat_cri(task, taskc);
    let penalty = calc_greedy_penalty(task, taskc);
    deadline_delta(
        taskc.acc_runtime_invr().get(),
        penalty,
        taskc.lat_cri().get(),
    )
}

/// calc_when_to_run(): the task's virtual deadline, ahead of the logical
/// clock less the compete window, which boosts bursty tasks: they benefit
/// from the enqueue boost more often.
#[inline(always)]
pub fn calc_when_to_run(task: &Task, taskc: TaskCtx) -> u64 {
    let dl_delta = calc_virtual_deadline_delta(task, taskc);
    let window = compete_window(
        SYS_STAT.nr_queued_task.get(),
        u64::from(scx_rustsched::sched::Cid::count()),
    );
    CUR_LOGICAL_CLK
        .get()
        .wrapping_sub(window)
        .wrapping_add(dl_delta)
}
