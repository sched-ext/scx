/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 *
 * This software may be used and distributed according to the terms of the GNU
 * General Public License version 2.
 */
#ifndef __INTF_H
#define __INTF_H

/*
 * Shared BPF constants for scx_flow.
 */
enum consts {
	NSEC_PER_USEC = 1000ULL,
	NSEC_PER_MSEC = (1000ULL * NSEC_PER_USEC),

	FLOW_SLICE_MIN_NS = (50ULL * NSEC_PER_USEC),
	FLOW_SLICE_RESERVED_MAX_NS = (250ULL * NSEC_PER_USEC),
	FLOW_SLICE_RESERVED_TUNE_MAX_NS = (350ULL * NSEC_PER_USEC),
	FLOW_SLICE_SHARED_NS = (1ULL * NSEC_PER_MSEC),
	FLOW_SLICE_SHARED_MIN_NS = (750ULL * NSEC_PER_USEC),
	FLOW_SLICE_SHARED_MAX_NS = (1500ULL * NSEC_PER_USEC),
	FLOW_SLICE_CONTAINED_MIN_NS = (1200ULL * NSEC_PER_USEC),
	FLOW_BUDGET_MAX_NS = (2ULL * NSEC_PER_MSEC),
	FLOW_BUDGET_MIN_NS = (500ULL * NSEC_PER_USEC),
	FLOW_SLEEP_MAX_NS = (250ULL * NSEC_PER_MSEC),
	FLOW_INTERACTIVE_SLEEP_MIN_NS = (750ULL * NSEC_PER_USEC),
	FLOW_INTERACTIVE_FLOOR_NS = (100ULL * NSEC_PER_USEC),
	FLOW_INTERACTIVE_FLOOR_MIN_NS = (80ULL * NSEC_PER_USEC),
	FLOW_INTERACTIVE_FLOOR_MAX_NS = (200ULL * NSEC_PER_USEC),
	FLOW_PREEMPT_BUDGET_MIN_NS = (150ULL * NSEC_PER_USEC),
	FLOW_PREEMPT_BUDGET_MAX_NS = (350ULL * NSEC_PER_USEC),
	FLOW_PREEMPT_REFILL_MIN_NS = (200ULL * NSEC_PER_USEC),
	FLOW_PREEMPT_REFILL_MAX_NS = (350ULL * NSEC_PER_USEC),
	FLOW_RT_WAKE_SLICE_NS = (50ULL * NSEC_PER_USEC),
	FLOW_LATENCY_LANE_REFILL_MIN_NS = (60ULL * NSEC_PER_USEC),
	FLOW_LATENCY_LANE_BUDGET_MIN_NS = (80ULL * NSEC_PER_USEC),
	FLOW_LATENCY_CREDIT_GRANT_MIN = 1ULL,
	FLOW_LATENCY_CREDIT_GRANT_MAX = 4ULL,
	FLOW_LATENCY_CREDIT_MAX = 4ULL,
	FLOW_LATENCY_CREDIT_GRANT = 2ULL,
	FLOW_LATENCY_CREDIT_DECAY_MIN = 1ULL,
	FLOW_LATENCY_CREDIT_DECAY_MAX = 4ULL,
	FLOW_LATENCY_CREDIT_DECAY = 1ULL,
	FLOW_LATENCY_CREDIT_DECAY_SHIFT = 1ULL,
	FLOW_LATENCY_DEBT_MAX = 4ULL,
	FLOW_LATENCY_DEBT_URGENT_MIN_MIN = 1ULL,
	FLOW_LATENCY_DEBT_URGENT_MIN_MAX = 3ULL,
	FLOW_LATENCY_DEBT_URGENT_MIN = 1ULL,
	FLOW_LATENCY_DEBT_RAISE_STEP = 1ULL,
	FLOW_LATENCY_DEBT_DECAY_STEP = 1ULL,
	FLOW_LATENCY_DEBT_DECAY_SHIFT = 1ULL,
	FLOW_URGENT_LATENCY_BURST_MIN = 1ULL,
	FLOW_URGENT_LATENCY_BURST_MAX_TUNE = 4ULL,
	FLOW_URGENT_LATENCY_BURST_MAX = 2ULL,
	FLOW_RESERVED_QUOTA_BURST_MIN = 2ULL,
	FLOW_RESERVED_QUOTA_BURST_MAX_TUNE = 8ULL,
	FLOW_RESERVED_QUOTA_BURST_MAX = 4ULL,
	FLOW_RESERVED_LANE_BURST_MIN = 2ULL,
	FLOW_RESERVED_LANE_BURST_MAX_TUNE = 10ULL,
	FLOW_RESERVED_LANE_BURST_MAX = 5ULL,
	FLOW_DIRECT_LOCAL_SCORE_MAX = 8ULL,
	FLOW_DIRECT_LOCAL_SCORE_MIN = 3ULL,
	FLOW_DIRECT_LOCAL_SCORE_GAIN = 1ULL,
	FLOW_DIRECT_LOCAL_SCORE_DECAY = 2ULL,
	FLOW_DIRECT_LOCAL_SCORE_DECAY_SHIFT = 1ULL,
	FLOW_DIRECT_LOCAL_MISMATCH_DECAY = 1ULL,
	FLOW_DIRECT_LOCAL_SLICE_NS = (150ULL * NSEC_PER_USEC),
	FLOW_IPC_SCORE_MAX = 16ULL,
	FLOW_IPC_SCORE_ACTIVATE = 4ULL,
	FLOW_IPC_SCORE_GAIN = 4ULL,
	FLOW_IPC_SCORE_DECAY_SHIFT = 1ULL,
	FLOW_IPC_CPUS_MAX = 2ULL,
	FLOW_IPC_SLEEP_MAX_NS = (2ULL * NSEC_PER_MSEC),
	FLOW_IPC_RUNTIME_MAX_NS = (120ULL * NSEC_PER_USEC),
	FLOW_IPC_REFILL_MIN_NS = (80ULL * NSEC_PER_USEC),
	FLOW_IPC_SLICE_NS = (120ULL * NSEC_PER_USEC),
	FLOW_LOCAL_FAST_NR_RUNNING_MIN = 1ULL,
	FLOW_LOCAL_FAST_NR_RUNNING_MAX_TUNE = 6ULL,
	FLOW_LOCAL_FAST_NR_RUNNING_MAX = 4ULL,
	FLOW_LOCAL_RESERVED_BURST_MIN = 2ULL,
	FLOW_LOCAL_RESERVED_BURST_MAX_TUNE = 8ULL,
	FLOW_LOCAL_RESERVED_BURST_MAX = 5ULL,
	FLOW_CONTAINED_STARVATION_MIN = 3ULL,
	FLOW_CONTAINED_STARVATION_MAX_TUNE = 12ULL,
	FLOW_CONTAINED_STARVATION_MAX = 6ULL,
	FLOW_SHARED_STARVATION_MIN = 6ULL,
	FLOW_SHARED_STARVATION_MAX_TUNE = 20ULL,
	FLOW_SHARED_STARVATION_MAX = 12ULL,
	FLOW_HOG_SCORE_MAX = 8ULL,
	FLOW_HOG_SCORE_CONTAIN = 3ULL,
	FLOW_HOG_SCORE_EXHAUST_STEP = 2ULL,
	FLOW_HOG_SCORE_DECAY_STEP = 1ULL,
	FLOW_HOG_SCORE_DECAY_SHIFT = 1ULL,
	FLOW_HOG_RECOVERY_MARGIN_NS = (50ULL * NSEC_PER_USEC),
	FLOW_REFILL_DIV = 100ULL,
};

#ifndef __VMLINUX_H__
typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long u64;

typedef signed char s8;
typedef signed short s16;
typedef signed int s32;
typedef signed long s64;

typedef int pid_t;
#endif /* __VMLINUX_H__ */

struct flow_cpu_state {
	u64 urgent_latency_burst_rounds;
	u64 high_priority_burst_rounds;
	u64 local_reserved_burst_rounds;
	u64 local_reserved_fast_grants;
	u64 local_reserved_burst_continuations;
	u64 reserved_lane_burst_rounds;
	u64 contained_starvation_rounds;
	u64 shared_starvation_rounds;
	u64 budget_refill_events;
	u64 budget_exhaustions;
	u64 runnable_wakeups;
	u64 urgent_latency_dispatches;
	u64 urgent_latency_burst_grants;
	u64 urgent_latency_burst_continuations;
	u64 urgent_latency_enqueues;
	u64 urgent_latency_misses;
	u64 latency_dispatches;
	u64 latency_debt_raises;
	u64 latency_debt_decays;
	u64 latency_debt_urgent_enqueues;
	u64 reserved_dispatches;
	u64 shared_dispatches;
	u64 contained_dispatches;
	u64 contained_rescue_dispatches;
	u64 shared_rescue_dispatches;
	u64 local_fast_dispatches;
	u64 wake_preempt_dispatches;
	u64 cpu_stability_biases;
	u64 last_cpu_matches;
	u64 latency_lane_candidates;
	u64 latency_lane_enqueues;
	u64 latency_candidate_local_enqueues;
	u64 latency_candidate_hog_blocks;
	u64 positive_budget_wakeups;
	u64 rt_sensitive_wakeups;
	u64 reserved_local_enqueues;
	u64 reserved_global_enqueues;
	u64 reserved_quota_skips;
	u64 quota_shared_forces;
	u64 quota_contained_forces;
	u64 reserved_lane_grants;
	u64 reserved_lane_burst_continuations;
	u64 reserved_lane_skips;
	u64 reserved_lane_shared_forces;
	u64 reserved_lane_contained_forces;
	u64 reserved_lane_shared_misses;
	u64 reserved_lane_contained_misses;
	u64 shared_wakeup_enqueues;
	u64 shared_starved_head_enqueues;
	u64 local_quota_skips;
	u64 rt_sensitive_local_enqueues;
	u64 rt_sensitive_preempts;
	u64 direct_local_candidates;
	u64 direct_local_enqueues;
	u64 direct_local_rejections;
	u64 direct_local_mismatches;
	u64 ipc_wake_candidates;
	u64 ipc_local_enqueues;
	u64 ipc_score_raises;
	u64 ipc_boosts;
	u64 contained_enqueues;
	u64 contained_starved_head_enqueues;
	u64 hog_containment_enqueues;
	u64 hog_recoveries;
	u64 cpu_migrations;
};

#endif /* __INTF_H */
