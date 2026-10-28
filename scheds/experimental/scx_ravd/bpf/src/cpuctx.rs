// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Piotr Gorski <lucjan.lucjanov@gmail.com>
//
// Ported from scx_lavd, Copyright (c) 2023-2025 Valve Corporation.
// Author of scx_lavd: Changwoo Min <changwoo@igalia.com>

//! The CPU context, lavd's struct cpu_ctx: what the scheduler keeps per
//! CID, in a table in the arena that `#[scheduler(cid_slot = CpuCtx)]`
//! declares and every CPU can read.
//!
//! lavd keeps cpu_ctx in a per-CPU map and reaches another CPU's with
//! bpf_map_lookup_percpu_elem(). In the arena, an entry is one load away
//! from any CPU.
//!
//! Counterpart in scx_lavd: struct cpu_ctx in lavd.bpf.h.

use scx_rustsched::ravg::Ravg;
use scx_rustsched::sched::Cid;

scx_rustsched::arena_struct! {
    /// A CID's context.
    pub struct CpuCtx {
        /// What remote CPUs read for a preemption decision: a copy of the
        /// running task's flags, when it is expected to stop, when it
        /// started and its latency criticality.
        flags: u64,
        est_stopping_clk: u64,
        running_clk: u64,
        lat_cri: u64,
        /// Per-interval sums of what ran here, for sys_stat.rs.
        sum_lat_cri: u64,
        max_lat_cri: u64,
        nr_sched: u64,
        sum_perf_cri: u64,
        min_perf_cri: u64,
        max_perf_cri: u64,
        /// Pinned tasks waiting to run here.
        nr_pinned_tasks: u64,
        /// When the running task's slice is to end, as the timer asked,
        /// see preempt.rs, or 0.
        shrink_at: u64,
        /// The compute domain, and whether this is a big core.
        cpdom_id: u64,
        big_core: bool,
        /// Time the scheduler's tasks spent here, wall clock, invariant
        /// and weighted invariant, since sys_stat.rs last collected it.
        tot_task_time_wall: u64,
        tot_task_time_invr: u64,
        tot_task_time_iwgt: u64,
        /// Idle time since the last collection, and when the CPU went idle,
        /// 0 while it is busy.
        idle_total_wall: u64,
        idle_start_clk: u64,
        /// Utilization in [0, 1024]: the last interval's and its average,
        /// wall clock and invariant.
        cur_util_wall: u64,
        avg_util_wall: u64,
        cur_util_invr: u64,
        avg_util_invr: u64,
        /// The duty cycle of the CPU, and its estimate in [0, 1024].
        avg_util: Ravg,
        util_est: u64,
        /// Counters since the last collection.
        nr_preempt: u64,
        nr_lat_cri: u64,
        nr_perf_cri: u64,
        nr_x_migration: u64,
        /// The performance target sent last, see power.rs.
        cpuperf_cur: u64,
    }
}

/// The context of `cid`, None for a number that is not a CID.
#[inline(always)]
pub fn get(cid: Cid) -> Option<CpuCtx> {
    cid.slot()
}

impl CpuCtx {
    #[inline(always)]
    pub fn test_flag(&self, flag: u64) -> bool {
        self.flags().get() & flag == flag
    }

    #[inline(always)]
    pub fn reset_flag(&self, flag: u64) {
        self.flags().update(|flags| flags & !flag);
    }

    /// Forget what was running, reset_cpu_preemption_info().
    #[inline(always)]
    pub fn reset_preemption_info(&self) {
        self.flags().set(0);
        self.lat_cri().set(0);
        self.est_stopping_clk().set(crate::lavd::SCX_SLICE_INF);
    }
}

/// One pinned task fewer waits on `cpuc`'s CPU. Two CPUs can do this at
/// once, for the CPU the count was taken on, so it is a compare and
/// exchange, which never goes below zero.
#[inline(always)]
pub fn dec_pinned(cpuc: CpuCtx) {
    for _ in scx_rustsched::loops::range(0, crate::lavd::LAVD_MAX_RETRY) {
        let old = cpuc.nr_pinned_tasks().get();
        if old == 0 || cpuc.nr_pinned_tasks().compare_exchange(old, old - 1) == old {
            return;
        }
    }
}
