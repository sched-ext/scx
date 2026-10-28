// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Piotr Gorski <lucjan.lucjanov@gmail.com>
//
// Ported from scx_lavd, Copyright (c) 2023-2025 Valve Corporation.
// Author of scx_lavd: Changwoo Min <changwoo@igalia.com>

//! The task context, lavd's struct task_ctx: what the scheduler keeps per
//! task in its arena slot.
//!
//! lavd keeps its task_ctx in the arena too, found through task storage.
//! Here the runtime hands every task a slot in ops.init_task() and finds it
//! with one load, see scx_rustsched's slots.
//!
//! What lavd keeps in p->scx.dsq_vtime, the task's virtual deadline, is
//! `deadline` here: the runtime keeps the slot's address in that field.
//!
//! Counterpart in scx_lavd: struct task_ctx in lavd.bpf.h.

use scx_rustsched::ravg::Ravg;
use scx_rustsched::task::Task;

use crate::lavd::NO_CID;

scx_rustsched::arena_struct! {
    /// A task's context: a handle to its slot in the arena.
    pub struct TaskCtx {
        /// LAVD_FLAG_*.
        flags: u64,
        /// The time slice, wall clock time.
        slice_wall: u64,
        /// When the runtime was last measured, and se.sum_exec_runtime
        /// then.
        last_measured_wall_clk: u64,
        last_measured_exec: u64,
        /// The runtime from runnable to quiescent.
        acc_runtime_wall: u64,
        acc_runtime_invr: u64,
        /// The invariant time the task consumed, scaled by its weight.
        svc_time_iwgt: u64,
        /// The context-aware latency criticality, normalized to
        /// [0, 1024] by the system's maximum, and what the waker and the
        /// wakees handed over at the last wakeup.
        lat_cri: u64,
        normalized_lat_cri: u64,
        lat_cri_waker: u64,
        lat_cri_wakee: u64,
        /// The performance criticality.
        perf_cri: u64,
        /// The compute domain chosen at ops.enqueue().
        cpdom_id: u64,
        /// The CID chosen at ops.select_cid() or ops.enqueue().
        suggested_cid: i64,
        /// The CID whose nr_pinned_tasks counts the task, or NO_CID.
        pinned_cid: i64,
        last_running_clk: u64,
        /// Scheduling, waiting and waking frequencies, per second.
        run_freq: u64,
        wait_freq: u64,
        wake_freq: u64,
        /// The average runtime per schedule.
        avg_runtime_invr: u64,
        avg_runtime_wall: u64,
        last_runnable_clk: u64,
        last_quiescent_clk: u64,
        /// Where the task runs, and where it ran before.
        cid: i64,
        prev_cid: i64,
        /// The time used in the last scheduling interval.
        last_slice_used_wall: u64,
        /// The virtual deadline, p->scx.dsq_vtime in lavd.
        deadline: u64,
        /// The task's duty cycle, and its estimate in [0, 1024].
        avg_util: Ravg,
        util_est: u64,
    }
}

impl scx_rustsched::slots::TaskSlot for TaskCtx {
    /// What a reader may see before the first write to it.
    #[inline(always)]
    fn reset(&self) {
        self.pinned_cid().set(NO_CID);
        self.suggested_cid().set(NO_CID);
        self.cid().set(NO_CID);
        self.prev_cid().set(NO_CID);
    }
}

/// The context of a task the scheduler was given.
#[inline(always)]
pub fn lookup(task: &Task) -> Option<TaskCtx> {
    task.slot()
}

/// The context of a task that may not be the scheduler's, such as the
/// waker: the idle task, or one of a higher class.
#[inline(always)]
pub fn lookup_optional(task: &Task) -> Option<TaskCtx> {
    task.slot_optional()
}

impl TaskCtx {
    #[inline(always)]
    pub fn test_flag(&self, flag: u64) -> bool {
        self.flags().get() & flag == flag
    }

    #[inline(always)]
    pub fn set_flag(&self, flag: u64) {
        self.flags().update(|flags| flags | flag);
    }

    #[inline(always)]
    pub fn reset_flag(&self, flag: u64) {
        self.flags().update(|flags| flags & !flag);
    }

    /// set_flag() or reset_flag(), by `on`.
    #[inline(always)]
    pub fn assign_flag(&self, flag: u64, on: bool) {
        if on {
            self.set_flag(flag)
        } else {
            self.reset_flag(flag)
        }
    }

    /// Has the task run under this scheduler, have_scheduled()? Its slice
    /// is set the first time it does.
    #[inline(always)]
    pub fn have_scheduled(&self) -> bool {
        self.slice_wall().get() != 0
    }
}
