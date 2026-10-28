// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Piotr Gorski <lucjan.lucjanov@gmail.com>
//
// Ported from scx_lavd, Copyright (c) 2023-2025 Valve Corporation.
// Author of scx_lavd: Changwoo Min <changwoo@igalia.com>

//! LAVD's constants and flags, under the names lavd.bpf.h gives them, so
//! that the policy modules read as the C they follow.
//!
//! Suffixes on time-related names, as lavd has them:
//!
//! - `_wall`: wall clock time
//! - `_invr`: capacity-invariant time, see `util::wall_to_invr()`
//! - `_iwgt`: invariant time scaled by the task's weight
//!
//! Counterpart in scx_lavd: lavd.bpf.h.

pub const LAVD_SHIFT: u32 = 10;
pub const LAVD_SCALE: u64 = 1 << LAVD_SHIFT;

/// A percentage in LAVD's fixed point, p2s().
pub const fn p2s(percent: u64) -> u64 {
    (percent << LAVD_SHIFT) / 100
}

pub const NSEC_PER_USEC: u64 = 1_000;
pub const NSEC_PER_MSEC: u64 = 1_000 * NSEC_PER_USEC;
pub const LAVD_TIME_ONE_SEC: u64 = 1_000 * NSEC_PER_MSEC;
pub const LAVD_MAX_RETRY: u32 = 3;

pub const LAVD_TARGETED_LATENCY_NS: u64 = 10 * NSEC_PER_MSEC;
pub const LAVD_SLICE_MIN_NS_DFL: u64 = 500 * NSEC_PER_USEC;
pub const LAVD_SLICE_MAX_NS_DFL: u64 = 5 * NSEC_PER_MSEC;
pub const LAVD_SLICE_BOOST_BONUS: u64 = LAVD_SLICE_MIN_NS_DFL;
pub const LAVD_SLICE_BOOST_MAX: u64 = 500 * NSEC_PER_MSEC;
/// Below 95% utilization a task's slice may be boosted.
pub const LAVD_SLICE_BOOST_UTIL_WALL: u64 = p2s(95);
pub const LAVD_ACC_RUNTIME_MAX: u64 = LAVD_SLICE_MAX_NS_DFL;
pub const LAVD_TASK_LAG_MAX: u64 = 500 * NSEC_PER_MSEC;
/// The compete window, assuming a latency criticality around 1000.
pub const LAVD_DL_COMPETE_WINDOW: u64 = (300 * NSEC_PER_MSEC) >> 16;

/// The shortest interval a frequency is counted at: 10 us.
pub const LAVD_LC_FREQ_MAX: u64 = 100_000;
pub const LAVD_LC_RUNTIME_MAX: u64 = LAVD_TIME_ONE_SEC;
pub const LAVD_LC_WEIGHT_BOOST_REGULAR: u64 = 128;
pub const LAVD_LC_WEIGHT_BOOST_MEDIUM: u64 = 2 * LAVD_LC_WEIGHT_BOOST_REGULAR;
pub const LAVD_LC_WEIGHT_BOOST_HIGH: u64 = 2 * LAVD_LC_WEIGHT_BOOST_MEDIUM;
/// The greedy penalty is at most 50%.
pub const LAVD_LC_GREEDY_SHIFT: u32 = 1;
pub const LAVD_LC_WAKE_INTERVAL_MIN: u64 = LAVD_SLICE_MIN_NS_DFL;
/// A receiver inherits at most 25% of its own latency criticality, and
/// takes 12.5% of what its givers have beyond twice its own.
pub const LAVD_LC_INH_RECEIVER_SHIFT: u32 = 2;
pub const LAVD_LC_INH_GIVER_SHIFT: u32 = 3;

pub const LAVD_RAVG_HALFLIFE_NS: u32 = (128 * NSEC_PER_MSEC) as u32;

pub const LAVD_SYS_STAT_INTERVAL_NS: u64 = 10 * NSEC_PER_MSEC;
/// Intervals between two halvings of the long-running counters: 2 s.
pub const LAVD_SYS_STAT_DECAY_TIMES: u64 = (2 * LAVD_TIME_ONE_SEC) / LAVD_SYS_STAT_INTERVAL_NS;

/// The CPU utilization a performance target is computed against: 85%.
pub const LAVD_CPU_UTIL_MAX_FOR_CPUPERF: u64 = p2s(85);

/// Load balancing: the margin around a domain's fair share, by how
/// loaded the system is.
pub const LAVD_CPDOM_MIG_SHIFT_UL: u32 = 2;
pub const LAVD_CPDOM_MIG_SHIFT: u32 = 3;
pub const LAVD_CPDOM_MIG_SHIFT_OL: u32 = 4;
/// Roughly twice per interval.
pub const LAVD_CPDOM_MIG_PROB_FT: u64 = LAVD_SYS_STAT_INTERVAL_NS / LAVD_SLICE_MAX_NS_DFL;
/// The neighbor distances: the same LLC, the same node, another node.
pub const LAVD_CPDOM_MAX_DIST: u32 = 3;
/// A CPU is congested with this many tasks waiting across its queues.
pub const LAVD_CPU_CONGESTED_THRES: u64 = 1;

/// What est_stopping_clk holds for a CPU that runs nothing of ours.
pub const SCX_SLICE_INF: u64 = u64::MAX;

/// The task flags, LAVD_FLAG_*, the ones the port uses with lavd's values.
pub const LAVD_FLAG_IS_GREEDY: u64 = 1 << 2;
pub const LAVD_FLAG_IS_WAKEUP: u64 = 1 << 4;
pub const LAVD_FLAG_IS_SYNC_WAKEUP: u64 = 1 << 5;
pub const LAVD_FLAG_SLICE_BOOST: u64 = 1 << 8;
pub const LAVD_FLAG_IDLE_CPU_PICKED: u64 = 1 << 9;
pub const LAVD_FLAG_WOKEN_BY_RT_DL: u64 = 1 << 11;

/// What pinned_cid holds for a task that holds no count on a CPU's
/// nr_pinned_tasks.
pub const NO_CID: i64 = -1;
