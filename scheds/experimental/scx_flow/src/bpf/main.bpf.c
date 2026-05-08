/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */

#include <scx/common.bpf.h>
#include <scx/compat.bpf.h>
#include <scx/user_exit_info.bpf.h>
#include "intf.h"

char _license[] SEC("license") = "GPL";

UEI_DEFINE(uei);

struct task_ctx {
	s64 budget_ns;
	s64 last_refill_ns;
	u64 last_run_at;
	u64 last_sleep_ns;
	u64 sleep_started_at;
	u32 latency_allowance;
	u32 latency_pressure;
	u32 containment_score;
	u32 locality_score;
	u32 ipc_confidence;
	u32 wake_profile;
	s32 last_cpu;
	s32 wake_cpu;
	bool wake_cpu_idle;
	bool wake_cpu_valid;
};

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct task_ctx);
} task_ctx_stor SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct flow_cpu_state);
} cpu_state SEC(".maps");

volatile u64 nr_running;
volatile u64 total_runtime;
volatile u64 reserved_dispatches;
volatile u64 urgent_latency_dispatches;
volatile u64 urgent_latency_burst_grants;
volatile u64 urgent_latency_burst_continuations;
volatile u64 latency_dispatches;
volatile u64 shared_dispatches;
volatile u64 contained_dispatches;
volatile u64 local_fast_dispatches;
volatile u64 wake_preempt_dispatches;
volatile u64 budget_refill_events;
volatile u64 budget_exhaustions;
volatile u64 positive_budget_wakeups;
volatile u64 urgent_latency_enqueues;
volatile u64 latency_lane_enqueues;
volatile u64 latency_lane_candidates;
volatile u64 latency_candidate_local_enqueues;
volatile u64 latency_candidate_hog_blocks;
volatile u64 latency_debt_raises;
volatile u64 latency_debt_decays;
volatile u64 latency_debt_urgent_enqueues;
volatile u64 urgent_latency_misses;
volatile u64 reserved_local_enqueues;
volatile u64 reserved_global_enqueues;
volatile u64 shared_wakeup_enqueues;
volatile u64 runnable_wakeups;
volatile u64 cpu_release_reenqueues;
volatile u64 local_reserved_fast_grants;
volatile u64 local_reserved_burst_continuations;
volatile u64 local_quota_skips;
volatile u64 reserved_quota_skips;
volatile u64 quota_shared_forces;
volatile u64 quota_contained_forces;
volatile u64 init_task_events;
volatile u64 enable_events;
volatile u64 exit_task_events;
volatile u64 cpu_stability_biases;
volatile u64 last_cpu_matches;
volatile u64 cpu_migrations;
volatile u64 rt_sensitive_wakeups;
volatile u64 rt_sensitive_local_enqueues;
volatile u64 rt_sensitive_preempts;
volatile u64 reserved_lane_grants;
volatile u64 reserved_lane_burst_continuations;
volatile u64 reserved_lane_skips;
volatile u64 reserved_lane_shared_forces;
volatile u64 reserved_lane_contained_forces;
volatile u64 reserved_lane_shared_misses;
volatile u64 reserved_lane_contained_misses;
volatile u64 contained_starved_head_enqueues;
volatile u64 shared_starved_head_enqueues;
volatile u64 direct_local_candidates;
volatile u64 direct_local_enqueues;
volatile u64 direct_local_rejections;
volatile u64 direct_local_mismatches;
volatile u64 ipc_wake_candidates;
volatile u64 ipc_local_enqueues;
volatile u64 ipc_score_raises;
volatile u64 ipc_boosts;
volatile u64 contained_enqueues;
volatile u64 hog_containment_enqueues;
volatile u64 hog_recoveries;
volatile u64 contained_rescue_dispatches;
volatile u64 shared_rescue_dispatches;
volatile u64 tune_reserved_max_ns = FLOW_SLICE_RESERVED_MAX_NS;
volatile u64 tune_shared_slice_ns = FLOW_SLICE_SHARED_NS;
volatile u64 tune_interactive_floor_ns = FLOW_INTERACTIVE_FLOOR_NS;
volatile u64 tune_preempt_budget_min_ns = FLOW_PREEMPT_BUDGET_MIN_NS;
volatile u64 tune_preempt_refill_min_ns = FLOW_PREEMPT_REFILL_MIN_NS;
volatile u64 tune_latency_credit_grant = FLOW_LATENCY_CREDIT_GRANT;
volatile u64 tune_latency_credit_decay = FLOW_LATENCY_CREDIT_DECAY;
volatile u64 tune_latency_debt_urgent_min = FLOW_LATENCY_DEBT_URGENT_MIN;
volatile u64 tune_urgent_latency_burst_max = FLOW_URGENT_LATENCY_BURST_MAX;
volatile u64 tune_reserved_quota_burst_max = FLOW_RESERVED_QUOTA_BURST_MAX;
volatile u64 tune_reserved_lane_burst_max = FLOW_RESERVED_LANE_BURST_MAX;
volatile u64 tune_contained_starvation_max = FLOW_CONTAINED_STARVATION_MAX;
volatile u64 tune_shared_starvation_max = FLOW_SHARED_STARVATION_MAX;
volatile u64 tune_local_fast_nr_running_max = FLOW_LOCAL_FAST_NR_RUNNING_MAX;
volatile u64 tune_local_reserved_burst_max = FLOW_LOCAL_RESERVED_BURST_MAX;
volatile u64 autotune_generation;
volatile u64 autotune_mode;

static u64 nr_cpu_ids;

#define URGENT_LATENCY_DSQ 1022
#define LATENCY_DSQ 1023
#define RESERVED_DSQ 1024
#define CONTAINED_DSQ 1025
#define SHARED_DSQ 1026
#define RESERVED_CPU_DSQ_BASE 0x40000000ULL
#define SHARED_CPU_DSQ_BASE 0x50000000ULL

enum wake_profile_bits {
	WAKE_PROFILE_POSITIVE_BUDGET = 1U << 0,
	WAKE_PROFILE_CONTAINMENT_ACTIVE = 1U << 1,
	WAKE_PROFILE_LATENCY_ALLOWANCE = 1U << 2,
	WAKE_PROFILE_LATENCY_PRESSURE = 1U << 3,
	WAKE_PROFILE_LATENCY_LANE = 1U << 4,
	WAKE_PROFILE_URGENT_LATENCY = 1U << 5,
	WAKE_PROFILE_RT_SENSITIVE = 1U << 6,
	WAKE_PROFILE_LOCALITY = 1U << 7,
	WAKE_PROFILE_LOCALITY_FAST = 1U << 8,
	WAKE_PROFILE_IPC = 1U << 9,
	WAKE_PROFILE_IPC_STRONG = 1U << 10,
	WAKE_PROFILE_PREEMPT_READY = 1U << 11,
	WAKE_PROFILE_RESERVED_HEAD = 1U << 12,
};

static inline struct task_ctx *lookup_task_ctx(const struct task_struct *p)
{
	return bpf_task_storage_get(&task_ctx_stor,
				    (struct task_struct *)p, 0, 0);
}

static inline struct task_ctx *alloc_task_ctx(struct task_struct *p)
{
	return bpf_task_storage_get(&task_ctx_stor,
				    (struct task_struct *)p, 0,
				    BPF_LOCAL_STORAGE_GET_F_CREATE);
}

static __always_inline struct flow_cpu_state *lookup_cpu_state(void)
{
	u32 key = 0;

	return bpf_map_lookup_elem(&cpu_state, &key);
}

#define FLOW_CPUSTAT_INC(_cstate, _field)					\
	do {									\
		typeof(_cstate) __cstate = (_cstate);				\
		if (__cstate)							\
			__cstate->_field++;					\
		else								\
			__sync_fetch_and_add(&_field, 1);			\
	} while (0)

static __always_inline bool is_kthread(const struct task_struct *p)
{
	return p->flags & PF_KTHREAD;
}

static __always_inline bool is_pinned_kthread(const struct task_struct *p)
{
	return is_kthread(p) && p->nr_cpus_allowed == 1;
}

static __always_inline bool is_non_migratable(const struct task_struct *p)
{
	return p->nr_cpus_allowed == 1 || is_migration_disabled(p);
}

static __always_inline s64 clamp_budget(s64 budget_ns)
{
	if (budget_ns > (s64)FLOW_BUDGET_MAX_NS)
		return FLOW_BUDGET_MAX_NS;
	if (budget_ns < -(s64)FLOW_BUDGET_MIN_NS)
		return -(s64)FLOW_BUDGET_MIN_NS;
	return budget_ns;
}

static __always_inline u64 task_slice_ns(const struct task_ctx *tctx)
{
	if (tctx && tctx->budget_ns > 0) {
		u64 budget_ns = (u64)tctx->budget_ns;
		u64 reserved_max_ns = tune_reserved_max_ns;

		if (reserved_max_ns < FLOW_SLICE_MIN_NS)
			reserved_max_ns = FLOW_SLICE_MIN_NS;
		else if (reserved_max_ns > FLOW_SLICE_RESERVED_TUNE_MAX_NS)
			reserved_max_ns = FLOW_SLICE_RESERVED_TUNE_MAX_NS;

		if (budget_ns < FLOW_SLICE_MIN_NS)
			return FLOW_SLICE_MIN_NS;
		if (budget_ns > reserved_max_ns)
			return reserved_max_ns;
		return budget_ns;
	}

	if (tune_shared_slice_ns < FLOW_SLICE_SHARED_MIN_NS)
		return FLOW_SLICE_SHARED_MIN_NS;
	if (tune_shared_slice_ns > FLOW_SLICE_SHARED_MAX_NS)
		return FLOW_SLICE_SHARED_MAX_NS;
	return tune_shared_slice_ns;
}

static __always_inline u64 contained_slice_ns(void)
{
	u64 slice_ns = tune_shared_slice_ns;

	if (slice_ns < FLOW_SLICE_CONTAINED_MIN_NS)
		slice_ns = FLOW_SLICE_CONTAINED_MIN_NS;
	if (slice_ns > FLOW_SLICE_SHARED_MAX_NS)
		slice_ns = FLOW_SLICE_SHARED_MAX_NS;
	return slice_ns;
}

static __always_inline bool valid_sched_cpu(s32 cpu)
{
	return cpu >= 0 && (u64)cpu < nr_cpu_ids;
}

static __always_inline u64 reserved_cpu_dsq_id(s32 cpu)
{
	return RESERVED_CPU_DSQ_BASE | (u32)cpu;
}

static __always_inline u64 shared_cpu_dsq_id(s32 cpu)
{
	return SHARED_CPU_DSQ_BASE | (u32)cpu;
}

static __always_inline bool move_reserved_lane_to_local(s32 cpu)
{
	if (valid_sched_cpu(cpu) &&
	    scx_bpf_dsq_move_to_local(reserved_cpu_dsq_id(cpu), 0))
		return true;

	return scx_bpf_dsq_move_to_local(RESERVED_DSQ, 0);
}

static __always_inline bool move_shared_lane_to_local(s32 cpu)
{
	if (valid_sched_cpu(cpu) &&
	    scx_bpf_dsq_move_to_local(shared_cpu_dsq_id(cpu), 0))
		return true;

	return scx_bpf_dsq_move_to_local(SHARED_DSQ, 0);
}

static __always_inline void clear_wake_target(struct task_ctx *tctx)
{
	if (!tctx)
		return;

	tctx->wake_cpu = -1;
	tctx->wake_cpu_idle = false;
	tctx->wake_cpu_valid = false;
}

static __always_inline void reset_task_ctx(struct task_ctx *tctx, u64 now, bool sleeping)
{
	if (!tctx)
		return;

	tctx->budget_ns = 0;
	tctx->last_refill_ns = 0;
	tctx->last_run_at = 0;
	tctx->last_sleep_ns = 0;
	tctx->sleep_started_at = sleeping ? now : 0;
	tctx->latency_allowance = 0;
	tctx->latency_pressure = 0;
	tctx->containment_score = 0;
	tctx->locality_score = 0;
	tctx->ipc_confidence = 0;
	tctx->wake_profile = 0;
	tctx->last_cpu = -1;
	clear_wake_target(tctx);
}

static __always_inline s64 calc_budget_refill(const struct task_struct *p, u64 sleep_ns)
{
	s64 refill_ns;
	u64 refill_base;

	if (!sleep_ns)
		return 0;

	if (sleep_ns > FLOW_SLEEP_MAX_NS)
		sleep_ns = FLOW_SLEEP_MAX_NS;

	refill_base = sleep_ns / FLOW_REFILL_DIV;
	if (!refill_base)
		return 0;

	refill_ns = (s64)scale_by_task_weight((struct task_struct *)p, refill_base);
	if (sleep_ns >= FLOW_INTERACTIVE_SLEEP_MIN_NS) {
		u64 interactive_floor_ns = tune_interactive_floor_ns;

		if (interactive_floor_ns < FLOW_INTERACTIVE_FLOOR_MIN_NS)
			interactive_floor_ns = FLOW_INTERACTIVE_FLOOR_MIN_NS;
		else if (interactive_floor_ns > FLOW_INTERACTIVE_FLOOR_MAX_NS)
			interactive_floor_ns = FLOW_INTERACTIVE_FLOOR_MAX_NS;

		if (refill_ns < (s64)interactive_floor_ns)
			refill_ns = (s64)interactive_floor_ns;
	}

	return refill_ns;
}

/*
 * Keep small scheduler signals bounded and decayed consistently so policy
 * gates can stay simple while the evidence underneath remains recency-aware.
 */
static __always_inline u32 clamp_bounded_signal(u32 signal, u32 signal_max)
{
	if (signal > signal_max)
		return signal_max;
	return signal;
}

static __always_inline u32 raise_bounded_signal(u32 signal, u32 delta,
						       u32 signal_max)
{
	if (!delta)
		return signal;
	return clamp_bounded_signal(signal + delta, signal_max);
}

static __always_inline u32 decay_bounded_signal(u32 signal, u32 delta)
{
	if (!delta || !signal)
		return signal;
	if (signal <= delta)
		return 0;
	return signal - delta;
}

static __always_inline u32 decay_geometric_signal(u32 signal, u32 shift)
{
	u32 delta;

	if (!signal)
		return 0;

	delta = shift ? signal >> shift : signal;
	if (!delta)
		delta = 1;

	return decay_bounded_signal(signal, delta);
}

static __always_inline u32 decay_confidence_signal(u32 signal, u32 delta,
						   u32 shift)
{
	u32 decayed_signal;

	if (!signal)
		return 0;

	decayed_signal = decay_geometric_signal(signal, shift);
	if (delta > 1)
		decayed_signal = decay_bounded_signal(decayed_signal, delta - 1);

	return decayed_signal;
}

static __always_inline bool is_containment_active(const struct task_ctx *tctx)
{
	return tctx && tctx->containment_score >= FLOW_HOG_SCORE_CONTAIN;
}

static __always_inline u32 tuned_latency_credit_grant(void)
{
	u64 grant = tune_latency_credit_grant;

	if (grant < FLOW_LATENCY_CREDIT_GRANT_MIN)
		grant = FLOW_LATENCY_CREDIT_GRANT_MIN;
	else if (grant > FLOW_LATENCY_CREDIT_GRANT_MAX)
		grant = FLOW_LATENCY_CREDIT_GRANT_MAX;

	return grant;
}

static __always_inline u32 tuned_latency_credit_decay(void)
{
	u64 decay = tune_latency_credit_decay;

	if (decay < FLOW_LATENCY_CREDIT_DECAY_MIN)
		decay = FLOW_LATENCY_CREDIT_DECAY_MIN;
	else if (decay > FLOW_LATENCY_CREDIT_DECAY_MAX)
		decay = FLOW_LATENCY_CREDIT_DECAY_MAX;

	return decay;
}

static __always_inline u32 tuned_latency_debt_urgent_min(void)
{
	u64 urgent_min = tune_latency_debt_urgent_min;

	if (urgent_min < FLOW_LATENCY_DEBT_URGENT_MIN_MIN)
		urgent_min = FLOW_LATENCY_DEBT_URGENT_MIN_MIN;
	else if (urgent_min > FLOW_LATENCY_DEBT_URGENT_MIN_MAX)
		urgent_min = FLOW_LATENCY_DEBT_URGENT_MIN_MAX;

	return urgent_min;
}

static __always_inline u32 tuned_urgent_latency_burst_max(void)
{
	u64 burst_max = tune_urgent_latency_burst_max;

	if (burst_max < FLOW_URGENT_LATENCY_BURST_MIN)
		burst_max = FLOW_URGENT_LATENCY_BURST_MIN;
	else if (burst_max > FLOW_URGENT_LATENCY_BURST_MAX_TUNE)
		burst_max = FLOW_URGENT_LATENCY_BURST_MAX_TUNE;

	return burst_max;
}

static __always_inline u32 tuned_reserved_quota_burst_max(void)
{
	u64 burst_max = tune_reserved_quota_burst_max;

	if (burst_max < FLOW_RESERVED_QUOTA_BURST_MIN)
		burst_max = FLOW_RESERVED_QUOTA_BURST_MIN;
	else if (burst_max > FLOW_RESERVED_QUOTA_BURST_MAX_TUNE)
		burst_max = FLOW_RESERVED_QUOTA_BURST_MAX_TUNE;

	return burst_max;
}

static __always_inline u32 tuned_reserved_lane_burst_max(void)
{
	u64 burst_max = tune_reserved_lane_burst_max;

	if (burst_max < FLOW_RESERVED_LANE_BURST_MIN)
		burst_max = FLOW_RESERVED_LANE_BURST_MIN;
	else if (burst_max > FLOW_RESERVED_LANE_BURST_MAX_TUNE)
		burst_max = FLOW_RESERVED_LANE_BURST_MAX_TUNE;

	return burst_max;
}

static __always_inline u32 tuned_local_reserved_burst_max(void)
{
	u64 burst_max = tune_local_reserved_burst_max;

	if (burst_max < FLOW_LOCAL_RESERVED_BURST_MIN)
		burst_max = FLOW_LOCAL_RESERVED_BURST_MIN;
	else if (burst_max > FLOW_LOCAL_RESERVED_BURST_MAX_TUNE)
		burst_max = FLOW_LOCAL_RESERVED_BURST_MAX_TUNE;

	return burst_max;
}

static __always_inline void raise_latency_allowance(struct task_ctx *tctx, u32 delta)
{
	if (!tctx || !delta)
		return;

	tctx->latency_allowance = raise_bounded_signal(tctx->latency_allowance, delta,
							FLOW_LATENCY_CREDIT_MAX);
}

static __always_inline void decay_latency_allowance(struct task_ctx *tctx, u32 delta)
{
	if (!tctx || !delta)
		return;

	tctx->latency_allowance =
		decay_confidence_signal(tctx->latency_allowance, delta,
					FLOW_LATENCY_CREDIT_DECAY_SHIFT);
}

static __always_inline bool has_urgent_latency_pressure(const struct task_ctx *tctx)
{
	return tctx && tctx->latency_pressure >= tuned_latency_debt_urgent_min();
}

static __always_inline bool is_latency_allowance_candidate(const struct task_ctx *tctx)
{
	if (!tctx || tctx->budget_ns <= 0 || !tctx->latency_allowance)
		return false;
	return tctx->budget_ns >= (s64)FLOW_LATENCY_LANE_BUDGET_MIN_NS;
}

static __always_inline bool raise_latency_pressure(struct task_ctx *tctx, u32 delta)
{
	u32 old_pressure;
	u32 new_pressure;

	if (!tctx || !delta)
		return false;

	old_pressure = tctx->latency_pressure;
	new_pressure = raise_bounded_signal(old_pressure, delta, FLOW_LATENCY_DEBT_MAX);
	if (new_pressure == old_pressure)
		return false;

	tctx->latency_pressure = new_pressure;
	return true;
}

static __always_inline bool decay_latency_pressure(struct task_ctx *tctx, u32 delta)
{
	u32 old_pressure;

	if (!tctx || !delta)
		return false;

	old_pressure = tctx->latency_pressure;
	if (!old_pressure)
		return false;

	tctx->latency_pressure =
		decay_confidence_signal(old_pressure, delta,
					FLOW_LATENCY_DEBT_DECAY_SHIFT);

	return tctx->latency_pressure != old_pressure;
}

static __always_inline bool has_locality_confidence(const struct task_ctx *tctx, u32 min_score)
{
	return tctx && tctx->locality_score >= min_score;
}

static __always_inline bool locality_hits_last_cpu(const struct task_ctx *tctx,
						   s32 target_cpu)
{
	return tctx && target_cpu >= 0 && tctx->last_cpu >= 0 &&
		target_cpu == tctx->last_cpu;
}

static __always_inline void raise_locality_score(struct task_ctx *tctx, u32 delta)
{
	if (!tctx || !delta)
		return;

	tctx->locality_score =
		raise_bounded_signal(tctx->locality_score, delta,
				   FLOW_DIRECT_LOCAL_SCORE_MAX);
}

static __always_inline void decay_locality_score(struct task_ctx *tctx, u32 delta)
{
	if (!tctx || !delta)
		return;

	tctx->locality_score =
		decay_confidence_signal(tctx->locality_score, delta,
					FLOW_DIRECT_LOCAL_SCORE_DECAY_SHIFT);
}

static __always_inline bool has_ipc_confidence(const struct task_ctx *tctx, u32 min_score)
{
	return tctx && tctx->ipc_confidence >= min_score;
}

static __always_inline bool has_ipc_continuity_confidence(const struct task_ctx *tctx,
							  u32 ipc_min_score,
							  u32 locality_min_score)
{
	return has_ipc_confidence(tctx, ipc_min_score) &&
		has_locality_confidence(tctx, locality_min_score);
}

static __always_inline bool has_wake_profile(const struct task_ctx *tctx, u32 bit)
{
	return tctx && (tctx->wake_profile & bit);
}

static __always_inline void decay_ipc_confidence(struct task_ctx *tctx)
{
	if (!tctx || !tctx->ipc_confidence)
		return;

	tctx->ipc_confidence =
		decay_geometric_signal(tctx->ipc_confidence, FLOW_IPC_SCORE_DECAY_SHIFT);
}

static __always_inline void raise_ipc_confidence(struct task_ctx *tctx)
{
	struct flow_cpu_state *cstate = lookup_cpu_state();

	if (!tctx)
		return;

	decay_ipc_confidence(tctx);
	tctx->ipc_confidence = raise_bounded_signal(tctx->ipc_confidence,
						      FLOW_IPC_SCORE_GAIN,
						      FLOW_IPC_SCORE_MAX);
	FLOW_CPUSTAT_INC(cstate, ipc_score_raises);
}

static __always_inline void decay_containment_score(struct task_ctx *tctx, u32 delta)
{
	struct flow_cpu_state *cstate = lookup_cpu_state();
	u32 old_score;

	if (!tctx || !delta)
		return;

	old_score = tctx->containment_score;
	tctx->containment_score =
		decay_confidence_signal(old_score, delta,
					FLOW_HOG_SCORE_DECAY_SHIFT);

	if (old_score >= FLOW_HOG_SCORE_CONTAIN &&
	    tctx->containment_score < FLOW_HOG_SCORE_CONTAIN)
		FLOW_CPUSTAT_INC(cstate, hog_recoveries);
}

static __always_inline void raise_containment_score(struct task_ctx *tctx, u32 delta)
{
	if (!tctx || !delta)
		return;

	tctx->containment_score =
		raise_bounded_signal(tctx->containment_score, delta,
				   FLOW_HOG_SCORE_MAX);
}

static __always_inline void recompute_wake_profile(const struct task_struct *p,
						   struct task_ctx *tctx)
{
	u32 wake_profile = 0;
	bool allowance_ready = false;
	bool pressure_ready = false;
	bool latency_lane_ready = false;
	bool rt_sensitive_ready = false;
	bool preempt_ready = false;
	bool containment_active;
	bool positive_budget;
	u64 preempt_refill_min_ns = tune_preempt_refill_min_ns;
	u64 preempt_budget_min_ns = tune_preempt_budget_min_ns;

	if (!tctx)
		return;

	containment_active = is_containment_active(tctx);
	positive_budget = tctx->budget_ns > 0;

	if (positive_budget)
		wake_profile |= WAKE_PROFILE_POSITIVE_BUDGET;
	if (containment_active)
		wake_profile |= WAKE_PROFILE_CONTAINMENT_ACTIVE;

	if (!positive_budget) {
		tctx->wake_profile = wake_profile;
		return;
	}

	if (preempt_refill_min_ns < FLOW_PREEMPT_REFILL_MIN_NS)
		preempt_refill_min_ns = FLOW_PREEMPT_REFILL_MIN_NS;
	else if (preempt_refill_min_ns > FLOW_PREEMPT_REFILL_MAX_NS)
		preempt_refill_min_ns = FLOW_PREEMPT_REFILL_MAX_NS;

	if (preempt_budget_min_ns < FLOW_PREEMPT_BUDGET_MIN_NS)
		preempt_budget_min_ns = FLOW_PREEMPT_BUDGET_MIN_NS;
	else if (preempt_budget_min_ns > FLOW_PREEMPT_BUDGET_MAX_NS)
		preempt_budget_min_ns = FLOW_PREEMPT_BUDGET_MAX_NS;

	allowance_ready = !containment_active &&
		is_latency_allowance_candidate(tctx);
	pressure_ready = !containment_active &&
		has_urgent_latency_pressure(tctx);
	rt_sensitive_ready = !containment_active &&
		p->nr_cpus_allowed == 1 &&
		tctx->last_refill_ns > 0 &&
		tctx->last_refill_ns >= (s64)FLOW_INTERACTIVE_FLOOR_MIN_NS;
	preempt_ready = !containment_active &&
		(p->nr_cpus_allowed == 1 ||
		 tctx->budget_ns >= (s64)preempt_budget_min_ns);
	latency_lane_ready = (allowance_ready || pressure_ready) &&
		!rt_sensitive_ready;

	if (allowance_ready)
		wake_profile |= WAKE_PROFILE_LATENCY_ALLOWANCE;
	if (pressure_ready)
		wake_profile |= WAKE_PROFILE_LATENCY_PRESSURE;
	if (latency_lane_ready)
		wake_profile |= WAKE_PROFILE_LATENCY_LANE;
	if (pressure_ready && latency_lane_ready)
		wake_profile |= WAKE_PROFILE_URGENT_LATENCY;
	if (rt_sensitive_ready)
		wake_profile |= WAKE_PROFILE_RT_SENSITIVE;
	if (preempt_ready)
		wake_profile |= WAKE_PROFILE_PREEMPT_READY;

	if (!containment_active &&
	    has_locality_confidence(tctx, FLOW_DIRECT_LOCAL_SCORE_MIN))
		wake_profile |= WAKE_PROFILE_LOCALITY;

	if (!containment_active &&
	    !rt_sensitive_ready &&
	    !latency_lane_ready &&
	    has_locality_confidence(tctx, FLOW_DIRECT_LOCAL_SCORE_MIN))
		wake_profile |= WAKE_PROFILE_LOCALITY_FAST;

	if (!containment_active &&
	    p->nr_cpus_allowed <= FLOW_IPC_CPUS_MAX &&
	    tctx->last_sleep_ns > 0 &&
	    tctx->last_sleep_ns <= FLOW_IPC_SLEEP_MAX_NS &&
	    tctx->budget_ns >= (s64)FLOW_IPC_REFILL_MIN_NS &&
	    tctx->last_refill_ns >= (s64)FLOW_IPC_REFILL_MIN_NS &&
	    has_ipc_continuity_confidence(tctx, FLOW_IPC_SCORE_ACTIVATE,
					      FLOW_DIRECT_LOCAL_SCORE_GAIN))
		wake_profile |= WAKE_PROFILE_IPC;

	if (!containment_active &&
	    p->nr_cpus_allowed == FLOW_IPC_CPUS_MAX &&
	    tctx->last_sleep_ns > 0 &&
	    tctx->last_sleep_ns <= FLOW_IPC_SLEEP_MAX_NS &&
	    tctx->budget_ns >= (s64)FLOW_IPC_REFILL_MIN_NS &&
	    tctx->last_refill_ns >= (s64)FLOW_IPC_REFILL_MIN_NS &&
	    has_ipc_continuity_confidence(tctx,
					      FLOW_IPC_SCORE_ACTIVATE + FLOW_IPC_SCORE_GAIN,
					      FLOW_DIRECT_LOCAL_SCORE_MIN))
		wake_profile |= WAKE_PROFILE_IPC_STRONG;

	if (!containment_active &&
	    !latency_lane_ready &&
	    (rt_sensitive_ready ||
	     (wake_profile & WAKE_PROFILE_LOCALITY_FAST) ||
	     (wake_profile & WAKE_PROFILE_IPC)))
		wake_profile |= WAKE_PROFILE_RESERVED_HEAD;

	tctx->wake_profile = wake_profile;
}

static __always_inline void update_budget_on_wakeup(const struct task_struct *p,
						    struct task_ctx *tctx,
						    u64 now)
{
	s64 refill_ns;
	u64 sleep_ns;
	u64 interactive_floor_ns = tune_interactive_floor_ns;
	u64 recovery_refill_min_ns;

	if (!tctx)
		return;

	tctx->last_refill_ns = 0;

	if (!tctx->sleep_started_at || now <= tctx->sleep_started_at) {
		tctx->last_sleep_ns = 0;
		return;
	}

	sleep_ns = now - tctx->sleep_started_at;
	refill_ns = calc_budget_refill(p, sleep_ns);
	tctx->budget_ns = clamp_budget(tctx->budget_ns + refill_ns);
	tctx->last_refill_ns = refill_ns;
	tctx->last_sleep_ns = sleep_ns;
	tctx->sleep_started_at = 0;

	if (refill_ns > 0) {
		if (interactive_floor_ns < FLOW_INTERACTIVE_FLOOR_MIN_NS)
			interactive_floor_ns = FLOW_INTERACTIVE_FLOOR_MIN_NS;
		else if (interactive_floor_ns > FLOW_INTERACTIVE_FLOOR_MAX_NS)
			interactive_floor_ns = FLOW_INTERACTIVE_FLOOR_MAX_NS;

		recovery_refill_min_ns = interactive_floor_ns + FLOW_HOG_RECOVERY_MARGIN_NS;
		if (refill_ns >= (s64)recovery_refill_min_ns)
			decay_containment_score(tctx, FLOW_HOG_SCORE_DECAY_STEP);
		if (refill_ns >= (s64)FLOW_LATENCY_LANE_REFILL_MIN_NS &&
		    tctx->budget_ns >= (s64)FLOW_LATENCY_LANE_BUDGET_MIN_NS)
			raise_latency_allowance(tctx, tuned_latency_credit_grant());
		/* Count every positive budget refill event, not only lane grants. */
		FLOW_CPUSTAT_INC(lookup_cpu_state(), budget_refill_events);
	}

	if (p->nr_cpus_allowed > FLOW_IPC_CPUS_MAX ||
	    !tctx->last_sleep_ns ||
	    tctx->last_sleep_ns > FLOW_IPC_SLEEP_MAX_NS ||
	    refill_ns < (s64)FLOW_IPC_REFILL_MIN_NS)
		decay_ipc_confidence(tctx);

	recompute_wake_profile(p, tctx);
}

static __always_inline bool is_ipc_confidence_candidate(const struct task_struct *p,
							const struct task_ctx *tctx,
							s32 target_cpu,
							bool wake_cpu_idle,
							bool is_wakeup,
							bool latency_lane_wakeup,
							bool containment_active)
{
	s32 task_cpu;

	if (!tctx || !is_wakeup)
		return false;
	if (containment_active || latency_lane_wakeup)
		return false;
	if (!has_wake_profile(tctx, WAKE_PROFILE_IPC))
		return false;
	if (target_cpu < 0 || tctx->last_cpu < 0)
		return false;

	if (locality_hits_last_cpu(tctx, target_cpu))
		return true;

	if (!has_wake_profile(tctx, WAKE_PROFILE_IPC_STRONG))
		return false;

	task_cpu = scx_bpf_task_cpu(p);
	if (task_cpu >= 0 && target_cpu == task_cpu)
		return true;

	return wake_cpu_idle;
}

static __always_inline bool is_locality_candidate(const struct task_ctx *tctx,
						  s32 target_cpu,
						  bool wake_cpu_idle,
						  bool is_wakeup,
						  bool rt_sensitive_wakeup,
						  bool latency_lane_wakeup,
						  bool containment_active)
{
	if (!tctx || !is_wakeup)
		return false;
	if (target_cpu < 0)
		return false;
	if (containment_active || rt_sensitive_wakeup || latency_lane_wakeup)
		return false;
	if (!has_wake_profile(tctx, WAKE_PROFILE_LOCALITY_FAST))
		return false;

	if (locality_hits_last_cpu(tctx, target_cpu))
		return true;

	return wake_cpu_idle;
}

static __always_inline bool should_prioritize_reserved_enqueue(
	const struct task_ctx *tctx, bool is_wakeup, bool containment_active,
	bool latency_lane_wakeup, bool rt_sensitive_wakeup,
	bool direct_local_wakeup, bool ipc_confidence_wakeup)
{
	if (!tctx || !is_wakeup)
		return false;
	if (containment_active || latency_lane_wakeup)
		return false;
	if (!has_wake_profile(tctx, WAKE_PROFILE_RESERVED_HEAD))
		return false;
	if (rt_sensitive_wakeup || direct_local_wakeup || ipc_confidence_wakeup)
		return true;

	return has_wake_profile(tctx, WAKE_PROFILE_LOCALITY_FAST);
}

static __always_inline bool allow_direct_local_fast_path(void)
{
	u64 max_running = tune_local_fast_nr_running_max;

	if (max_running < FLOW_LOCAL_FAST_NR_RUNNING_MIN)
		max_running = FLOW_LOCAL_FAST_NR_RUNNING_MIN;
	else if (max_running > FLOW_LOCAL_FAST_NR_RUNNING_MAX_TUNE)
		max_running = FLOW_LOCAL_FAST_NR_RUNNING_MAX_TUNE;

	if (nr_running > max_running)
		return false;
	return true;
}

static __always_inline u64 direct_local_slice_ns(u64 slice_ns)
{
	if (slice_ns < FLOW_SLICE_MIN_NS)
		return FLOW_SLICE_MIN_NS;
	if (slice_ns > FLOW_DIRECT_LOCAL_SLICE_NS)
		return FLOW_DIRECT_LOCAL_SLICE_NS;
	return slice_ns;
}

static __always_inline void bump_starvation_round(u64 *counter, u64 max_rounds)
{
	if (counter && *counter < max_rounds)
		*counter += 1;
}

static __always_inline void backoff_starvation_round(u64 *counter, u64 max_rounds)
{
	if (!counter || !max_rounds)
		return;

	if (*counter >= max_rounds)
		*counter = max_rounds - 1;
}

static __always_inline void note_high_priority_dispatch(struct flow_cpu_state *cstate)
{
	u64 contained_max = tune_contained_starvation_max;
	u64 shared_max = tune_shared_starvation_max;
	u64 quota_max = tuned_reserved_quota_burst_max();

	if (contained_max < FLOW_CONTAINED_STARVATION_MIN)
		contained_max = FLOW_CONTAINED_STARVATION_MIN;
	else if (contained_max > FLOW_CONTAINED_STARVATION_MAX_TUNE)
		contained_max = FLOW_CONTAINED_STARVATION_MAX_TUNE;

	if (shared_max < FLOW_SHARED_STARVATION_MIN)
		shared_max = FLOW_SHARED_STARVATION_MIN;
	else if (shared_max > FLOW_SHARED_STARVATION_MAX_TUNE)
		shared_max = FLOW_SHARED_STARVATION_MAX_TUNE;

	bump_starvation_round(cstate ? &cstate->contained_starvation_rounds : NULL,
			      contained_max);
	bump_starvation_round(cstate ? &cstate->shared_starvation_rounds : NULL,
			      shared_max);
	if (cstate && cstate->high_priority_burst_rounds < quota_max)
		cstate->high_priority_burst_rounds++;
}

static __always_inline void reset_urgent_latency_burst(struct flow_cpu_state *cstate)
{
	if (cstate)
		cstate->urgent_latency_burst_rounds = 0;
}

static __always_inline void reset_reserved_lane_burst(struct flow_cpu_state *cstate)
{
	if (cstate)
		cstate->reserved_lane_burst_rounds = 0;
}

static __always_inline void reset_local_reserved_burst(struct flow_cpu_state *cstate)
{
	if (cstate)
		cstate->local_reserved_burst_rounds = 0;
}

static __always_inline void note_local_reserved_fast(struct flow_cpu_state *cstate)
{
	u64 burst_max = tuned_local_reserved_burst_max();

	FLOW_CPUSTAT_INC(cstate, local_reserved_fast_grants);
	if (cstate && cstate->local_reserved_burst_rounds > 0)
		FLOW_CPUSTAT_INC(cstate, local_reserved_burst_continuations);
	if (cstate && cstate->local_reserved_burst_rounds < burst_max)
		cstate->local_reserved_burst_rounds++;
}

static __always_inline void note_urgent_latency_dispatch(struct flow_cpu_state *cstate)
{
	if (cstate && cstate->urgent_latency_burst_rounds > 0)
		FLOW_CPUSTAT_INC(cstate, urgent_latency_burst_continuations);
	if (cstate &&
	    cstate->urgent_latency_burst_rounds < tuned_urgent_latency_burst_max())
		cstate->urgent_latency_burst_rounds++;
	FLOW_CPUSTAT_INC(cstate, urgent_latency_dispatches);
	FLOW_CPUSTAT_INC(cstate, urgent_latency_burst_grants);
	reset_reserved_lane_burst(cstate);
	note_high_priority_dispatch(cstate);
}

static __always_inline void note_reserved_dispatch(struct flow_cpu_state *cstate)
{
	u64 burst_max = tuned_reserved_lane_burst_max();

	FLOW_CPUSTAT_INC(cstate, reserved_dispatches);
	FLOW_CPUSTAT_INC(cstate, reserved_lane_grants);
	if (cstate && cstate->reserved_lane_burst_rounds > 0)
		FLOW_CPUSTAT_INC(cstate, reserved_lane_burst_continuations);
	if (cstate && cstate->reserved_lane_burst_rounds < burst_max)
		cstate->reserved_lane_burst_rounds++;
	reset_urgent_latency_burst(cstate);
	reset_local_reserved_burst(cstate);
	note_high_priority_dispatch(cstate);
}

static __always_inline void note_contained_dispatch(struct flow_cpu_state *cstate,
						    bool rescued)
{
	u64 shared_max = tune_shared_starvation_max;

	if (shared_max < FLOW_SHARED_STARVATION_MIN)
		shared_max = FLOW_SHARED_STARVATION_MIN;
	else if (shared_max > FLOW_SHARED_STARVATION_MAX_TUNE)
		shared_max = FLOW_SHARED_STARVATION_MAX_TUNE;

	if (cstate) {
		cstate->contained_starvation_rounds = 0;
		cstate->high_priority_burst_rounds = 0;
	}
	bump_starvation_round(cstate ? &cstate->shared_starvation_rounds : NULL,
			      shared_max);
	reset_urgent_latency_burst(cstate);
	reset_reserved_lane_burst(cstate);
	reset_local_reserved_burst(cstate);
	if (rescued)
		FLOW_CPUSTAT_INC(cstate, contained_rescue_dispatches);
}

static __always_inline void note_shared_dispatch(struct flow_cpu_state *cstate,
						 bool rescued)
{
	u64 contained_max = tune_contained_starvation_max;

	if (contained_max < FLOW_CONTAINED_STARVATION_MIN)
		contained_max = FLOW_CONTAINED_STARVATION_MIN;
	else if (contained_max > FLOW_CONTAINED_STARVATION_MAX_TUNE)
		contained_max = FLOW_CONTAINED_STARVATION_MAX_TUNE;

	if (cstate) {
		cstate->shared_starvation_rounds = 0;
		cstate->high_priority_burst_rounds = 0;
	}
	bump_starvation_round(cstate ? &cstate->contained_starvation_rounds : NULL,
			      contained_max);
	reset_urgent_latency_burst(cstate);
	reset_reserved_lane_burst(cstate);
	reset_local_reserved_burst(cstate);
	if (rescued)
		FLOW_CPUSTAT_INC(cstate, shared_rescue_dispatches);
}

static __always_inline bool local_reserved_quota_active(struct flow_cpu_state *cstate)
{
	u64 max_running = tune_local_fast_nr_running_max;

	if (max_running < FLOW_LOCAL_FAST_NR_RUNNING_MIN)
		max_running = FLOW_LOCAL_FAST_NR_RUNNING_MIN;
	else if (max_running > FLOW_LOCAL_FAST_NR_RUNNING_MAX_TUNE)
		max_running = FLOW_LOCAL_FAST_NR_RUNNING_MAX_TUNE;

	return nr_running > max_running ||
		(cstate && cstate->contained_starvation_rounds > 0) ||
		(cstate && cstate->shared_starvation_rounds > 0);
}

static __always_inline void note_locality_mismatch(const struct task_struct *p,
						   struct task_ctx *tctx)
{
	struct flow_cpu_state *cstate = lookup_cpu_state();

	if (!tctx)
		return;

	FLOW_CPUSTAT_INC(cstate, direct_local_mismatches);
	decay_locality_score(tctx, FLOW_DIRECT_LOCAL_MISMATCH_DECAY);
	recompute_wake_profile(p, tctx);
}

static __always_inline void note_locality_rejection(const struct task_struct *p,
						    struct task_ctx *tctx)
{
	struct flow_cpu_state *cstate = lookup_cpu_state();

	if (!tctx)
		return;

	FLOW_CPUSTAT_INC(cstate, direct_local_rejections);
	decay_locality_score(tctx, FLOW_DIRECT_LOCAL_MISMATCH_DECAY);
	recompute_wake_profile(p, tctx);
}

static __always_inline bool should_promote_shared_enqueue(struct flow_cpu_state *cstate)
{
	u64 shared_max = tune_shared_starvation_max;

	if (shared_max < FLOW_SHARED_STARVATION_MIN)
		shared_max = FLOW_SHARED_STARVATION_MIN;
	else if (shared_max > FLOW_SHARED_STARVATION_MAX_TUNE)
		shared_max = FLOW_SHARED_STARVATION_MAX_TUNE;

	return cstate && cstate->shared_starvation_rounds * 2 >= shared_max;
}

static __always_inline bool should_promote_contained_enqueue(struct flow_cpu_state *cstate)
{
	u64 contained_max = tune_contained_starvation_max;

	if (contained_max < FLOW_CONTAINED_STARVATION_MIN)
		contained_max = FLOW_CONTAINED_STARVATION_MIN;
	else if (contained_max > FLOW_CONTAINED_STARVATION_MAX_TUNE)
		contained_max = FLOW_CONTAINED_STARVATION_MAX_TUNE;

	return cstate && cstate->contained_starvation_rounds * 2 >= contained_max;
}

s32 BPF_STRUCT_OPS_SLEEPABLE(flow_init)
{
	s32 cpu;
	s32 ret;

	ret = scx_lib_init();
	if (ret)
		return ret;

	nr_cpu_ids = scx_bpf_nr_cpu_ids();

	bpf_for(cpu, 0, nr_cpu_ids) {
		ret = scx_bpf_create_dsq(reserved_cpu_dsq_id(cpu), -1);
		if (ret < 0 && ret != -EEXIST) {
			scx_bpf_error("failed to create reserved cpu DSQ %d: %d",
				      cpu, ret);
			return ret;
		}

		ret = scx_bpf_create_dsq(shared_cpu_dsq_id(cpu), -1);
		if (ret < 0 && ret != -EEXIST) {
			scx_bpf_error("failed to create shared cpu DSQ %d: %d",
				      cpu, ret);
			return ret;
		}
	}

	ret = scx_bpf_create_dsq(LATENCY_DSQ, -1);
	if (ret < 0 && ret != -EEXIST) {
		scx_bpf_error("failed to create latency DSQ %d: %d", LATENCY_DSQ, ret);
		return ret;
	}

	ret = scx_bpf_create_dsq(URGENT_LATENCY_DSQ, -1);
	if (ret < 0 && ret != -EEXIST) {
		scx_bpf_error("failed to create urgent latency DSQ %d: %d",
			     URGENT_LATENCY_DSQ, ret);
		return ret;
	}

	ret = scx_bpf_create_dsq(RESERVED_DSQ, -1);
	if (ret < 0 && ret != -EEXIST) {
		scx_bpf_error("failed to create reserved DSQ %d: %d", RESERVED_DSQ, ret);
		return ret;
	}

	ret = scx_bpf_create_dsq(CONTAINED_DSQ, -1);
	if (ret < 0 && ret != -EEXIST) {
		scx_bpf_error("failed to create contained DSQ %d: %d", CONTAINED_DSQ, ret);
		return ret;
	}

	ret = scx_bpf_create_dsq(SHARED_DSQ, -1);
	if (ret < 0 && ret != -EEXIST) {
		scx_bpf_error("failed to create shared DSQ %d: %d", SHARED_DSQ, ret);
		return ret;
	}

	return 0;
}

s32 BPF_STRUCT_OPS_SLEEPABLE(flow_init_task, struct task_struct *p,
			     struct scx_init_task_args *args)
{
	struct task_ctx *tctx;
	u64 now;

	tctx = alloc_task_ctx(p);
	if (!tctx)
		return -ENOMEM;

	now = bpf_ktime_get_ns();
	reset_task_ctx(tctx, now, true);
	__sync_fetch_and_add(&init_task_events, 1);

	return 0;
}

void BPF_STRUCT_OPS(flow_enable, struct task_struct *p)
{
	struct task_ctx *tctx;
	bool sleeping;

	tctx = lookup_task_ctx(p);
	if (!tctx)
		return;

	sleeping = !scx_bpf_task_running(p);
	reset_task_ctx(tctx, bpf_ktime_get_ns(), sleeping);
	__sync_fetch_and_add(&enable_events, 1);
}

s32 BPF_STRUCT_OPS(flow_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
	struct task_ctx *tctx;
	bool is_idle = false;
	s32 cpu;
	s32 preferred_cpu;
	s32 this_cpu = bpf_get_smp_processor_id();
	bool non_migratable = is_non_migratable(p);
	bool is_this_cpu_allowed = bpf_cpumask_test_cpu(this_cpu, p->cpus_ptr);

	tctx = lookup_task_ctx(p);
	if (tctx) {
		if (tctx->sleep_started_at)
			update_budget_on_wakeup(p, tctx, bpf_ktime_get_ns());
		clear_wake_target(tctx);
	}

	if (!bpf_cpumask_test_cpu(prev_cpu, p->cpus_ptr))
		prev_cpu = is_this_cpu_allowed ? this_cpu : bpf_cpumask_first(p->cpus_ptr);

	preferred_cpu = prev_cpu;
	if (!non_migratable && tctx && tctx->last_cpu >= 0 &&
	    bpf_cpumask_test_cpu(tctx->last_cpu, p->cpus_ptr)) {
		preferred_cpu = tctx->last_cpu;
		FLOW_CPUSTAT_INC(lookup_cpu_state(), cpu_stability_biases);
	}

	if (non_migratable) {
		cpu = preferred_cpu;
		is_idle = scx_bpf_test_and_clear_cpu_idle(preferred_cpu);
	} else {
		cpu = scx_bpf_select_cpu_dfl(p, preferred_cpu, wake_flags, &is_idle);
	}

	if (tctx) {
		tctx->wake_cpu = cpu >= 0 ? cpu : preferred_cpu;
		tctx->wake_cpu_idle = is_idle;
		tctx->wake_cpu_valid =
			tctx->wake_cpu >= 0 &&
			bpf_cpumask_test_cpu(tctx->wake_cpu, p->cpus_ptr);
		if (tctx->last_cpu >= 0 && tctx->wake_cpu == tctx->last_cpu)
			FLOW_CPUSTAT_INC(lookup_cpu_state(), last_cpu_matches);
		else if (tctx->last_cpu >= 0)
			note_locality_mismatch(p, tctx);
	}

	return cpu >= 0 ? cpu : preferred_cpu;
}

void BPF_STRUCT_OPS(flow_runnable, struct task_struct *p, u64 enq_flags)
{
	struct task_ctx *tctx;
	u64 now;

	tctx = lookup_task_ctx(p);
	if (!tctx)
		return;

	now = bpf_ktime_get_ns();
	if (tctx->sleep_started_at && now > tctx->sleep_started_at)
		FLOW_CPUSTAT_INC(lookup_cpu_state(), runnable_wakeups);
	update_budget_on_wakeup(p, tctx, now);
}

void BPF_STRUCT_OPS(flow_enqueue, struct task_struct *p, u64 enq_flags)
{
	struct task_ctx *tctx;
	struct flow_cpu_state *cstate;
	s32 target_cpu = -1;
	s32 task_cpu;
	u64 slice_ns;
	bool is_wakeup;
	bool has_wake_target = false;
	bool non_migratable = is_non_migratable(p);
	bool rt_sensitive_wakeup = false;
	bool allowance_latency_wakeup = false;
	bool pressure_latency_wakeup = false;
	bool latency_lane_wakeup = false;
	bool urgent_latency_wakeup = false;
	bool direct_local_wakeup = false;
	bool ipc_confidence_wakeup = false;
	bool containment_active = false;
	bool reserved_priority_wakeup = false;
	bool use_local_reserved = false;
	bool ordinary_local_reserved = false;

	tctx = lookup_task_ctx(p);
	cstate = lookup_cpu_state();
	slice_ns = task_slice_ns(tctx);
	is_wakeup = enq_flags & SCX_ENQ_WAKEUP;

	if (tctx && tctx->wake_cpu_valid) {
		target_cpu = tctx->wake_cpu;
		has_wake_target = true;
	} else {
		target_cpu = scx_bpf_task_cpu(p);
	}

	task_cpu = scx_bpf_task_cpu(p);
	if (non_migratable && task_cpu >= 0 &&
	    bpf_cpumask_test_cpu(task_cpu, p->cpus_ptr)) {
		if (!has_wake_target || target_cpu != task_cpu) {
			target_cpu = task_cpu;
			has_wake_target = true;
			if (tctx) {
				tctx->wake_cpu = task_cpu;
				tctx->wake_cpu_idle = false;
				tctx->wake_cpu_valid = true;
			}
		}
	}

	if (is_pinned_kthread(p)) {
		clear_wake_target(tctx);
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, task_slice_ns(NULL), enq_flags);
		FLOW_CPUSTAT_INC(cstate, local_fast_dispatches);
		return;
	}

	if (tctx && tctx->budget_ns > 0) {
		containment_active = has_wake_profile(tctx, WAKE_PROFILE_CONTAINMENT_ACTIVE);
		pressure_latency_wakeup =
			is_wakeup && has_wake_profile(tctx, WAKE_PROFILE_LATENCY_PRESSURE);
		allowance_latency_wakeup =
			is_wakeup && has_wake_profile(tctx, WAKE_PROFILE_LATENCY_ALLOWANCE);
		if (allowance_latency_wakeup || pressure_latency_wakeup)
			FLOW_CPUSTAT_INC(cstate, latency_lane_candidates);
		if (is_wakeup && containment_active && tctx->latency_allowance > 0)
			FLOW_CPUSTAT_INC(cstate, latency_candidate_hog_blocks);
		if (is_wakeup)
			FLOW_CPUSTAT_INC(cstate, positive_budget_wakeups);

		rt_sensitive_wakeup =
			is_wakeup && has_wake_profile(tctx, WAKE_PROFILE_RT_SENSITIVE);
		if (rt_sensitive_wakeup)
			FLOW_CPUSTAT_INC(cstate, rt_sensitive_wakeups);

		latency_lane_wakeup =
			is_wakeup && has_wake_profile(tctx, WAKE_PROFILE_LATENCY_LANE);
		urgent_latency_wakeup =
			is_wakeup && has_wake_profile(tctx, WAKE_PROFILE_URGENT_LATENCY);
		ipc_confidence_wakeup = is_ipc_confidence_candidate(
			p, tctx, target_cpu, tctx->wake_cpu_idle, is_wakeup,
			latency_lane_wakeup, containment_active);
		if (ipc_confidence_wakeup)
			FLOW_CPUSTAT_INC(cstate, ipc_wake_candidates);

		direct_local_wakeup = is_locality_candidate(
			tctx, target_cpu, tctx->wake_cpu_idle, is_wakeup,
			rt_sensitive_wakeup, latency_lane_wakeup, containment_active);
		if (direct_local_wakeup && !allow_direct_local_fast_path()) {
			direct_local_wakeup = false;
			note_locality_rejection(p, tctx);
		}
		if (direct_local_wakeup)
			FLOW_CPUSTAT_INC(cstate, direct_local_candidates);

		if (is_wakeup && !containment_active)
			enq_flags |= SCX_ENQ_HEAD;

		/*
		 * Short-sleep fast path: tasks that have been sleeping for less
		 * than FLOW_INTERACTIVE_SLEEP_MIN_NS are extremely high-frequency
		 * wakeups (e.g. cyclictest, timer-driven periodic work).  They
		 * should bypass all lane analysis and be dispatched directly to
		 * the target CPU's local DSQ with a minimal slice.
		 *
		 * A positive accumulated budget is sufficient evidence of
		 * responsiveness — the refill and lane gates only add per-wakeup
		 * BPF overhead without changing the outcome for such tasks.
		 */
		if (is_wakeup && tctx && tctx->budget_ns > 0 &&
		    !containment_active &&
		    tctx->last_sleep_ns > 0 &&
		    tctx->last_sleep_ns <= FLOW_INTERACTIVE_SLEEP_MIN_NS &&
		    (has_wake_target ||
		     (target_cpu >= 0 && bpf_cpumask_test_cpu(target_cpu, p->cpus_ptr)))) {
			scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | target_cpu,
					   FLOW_SLICE_MIN_NS,
					   enq_flags | SCX_ENQ_HEAD);
			FLOW_CPUSTAT_INC(cstate, local_fast_dispatches);
			clear_wake_target(tctx);
			return;
		}

		if (has_wake_target ||
		    (target_cpu >= 0 && bpf_cpumask_test_cpu(target_cpu, p->cpus_ptr))) {
			bool should_preempt;

			should_preempt = rt_sensitive_wakeup || ipc_confidence_wakeup ||
				(is_wakeup && !containment_active && !tctx->wake_cpu_idle &&
				 has_wake_profile(tctx, WAKE_PROFILE_PREEMPT_READY));

			use_local_reserved = should_preempt || direct_local_wakeup ||
				ipc_confidence_wakeup ||
				(tctx->wake_cpu_idle && is_wakeup);
			ordinary_local_reserved = use_local_reserved && !should_preempt;

			if (ordinary_local_reserved &&
			    local_reserved_quota_active(cstate) &&
			    cstate &&
			    cstate->local_reserved_burst_rounds >=
				    tuned_local_reserved_burst_max()) {
				use_local_reserved = false;
				ordinary_local_reserved = false;
				FLOW_CPUSTAT_INC(cstate, local_quota_skips);
			}

			if (should_preempt) {
				enq_flags |= SCX_ENQ_PREEMPT;
				scx_bpf_kick_cpu(target_cpu, SCX_KICK_PREEMPT);
				FLOW_CPUSTAT_INC(cstate, wake_preempt_dispatches);
				if (rt_sensitive_wakeup)
					FLOW_CPUSTAT_INC(cstate, rt_sensitive_preempts);
			} else if (tctx->wake_cpu_idle &&
				   (is_wakeup || !scx_bpf_task_running(p))) {
				scx_bpf_kick_cpu(target_cpu, SCX_KICK_IDLE);
			}

			if (use_local_reserved) {
				u64 local_slice_ns;

				if (ipc_confidence_wakeup) {
					local_slice_ns = FLOW_IPC_SLICE_NS;
					FLOW_CPUSTAT_INC(cstate, ipc_boosts);
				} else if (rt_sensitive_wakeup) {
					local_slice_ns = FLOW_RT_WAKE_SLICE_NS;
				} else {
					local_slice_ns = direct_local_slice_ns(slice_ns);
				}

				if (urgent_latency_wakeup)
					FLOW_CPUSTAT_INC(cstate, urgent_latency_misses);
				scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | target_cpu,
						   local_slice_ns, enq_flags);
				if (latency_lane_wakeup)
					FLOW_CPUSTAT_INC(cstate, latency_candidate_local_enqueues);
				FLOW_CPUSTAT_INC(cstate, reserved_local_enqueues);
				if (rt_sensitive_wakeup)
					FLOW_CPUSTAT_INC(cstate, rt_sensitive_local_enqueues);
				if (direct_local_wakeup)
					FLOW_CPUSTAT_INC(cstate, direct_local_enqueues);
				if (ipc_confidence_wakeup)
					FLOW_CPUSTAT_INC(cstate, ipc_local_enqueues);
				if (tctx->wake_cpu_idle)
					FLOW_CPUSTAT_INC(cstate, local_fast_dispatches);
				if (ordinary_local_reserved)
					note_local_reserved_fast(cstate);
				clear_wake_target(tctx);
				return;
			}
		}

		if (direct_local_wakeup)
			note_locality_rejection(p, tctx);

		if (containment_active) {
			if (should_promote_contained_enqueue(cstate)) {
				enq_flags |= SCX_ENQ_HEAD;
				FLOW_CPUSTAT_INC(cstate, contained_starved_head_enqueues);
			}
			scx_bpf_dsq_insert(p, CONTAINED_DSQ, contained_slice_ns(), enq_flags);
			reset_local_reserved_burst(cstate);
			FLOW_CPUSTAT_INC(cstate, contained_enqueues);
			FLOW_CPUSTAT_INC(cstate, hog_containment_enqueues);
			clear_wake_target(tctx);
			return;
		}

		if (latency_lane_wakeup) {
			u64 latency_dsq = urgent_latency_wakeup ?
				URGENT_LATENCY_DSQ : LATENCY_DSQ;

			scx_bpf_dsq_insert(p, latency_dsq, slice_ns, enq_flags);
			reset_local_reserved_burst(cstate);
			decay_latency_allowance(tctx, tuned_latency_credit_decay());
			if (urgent_latency_wakeup)
				FLOW_CPUSTAT_INC(cstate, urgent_latency_enqueues);
			if (has_urgent_latency_pressure(tctx))
				FLOW_CPUSTAT_INC(cstate, latency_debt_urgent_enqueues);
			if (decay_latency_pressure(tctx, FLOW_LATENCY_DEBT_DECAY_STEP))
				FLOW_CPUSTAT_INC(cstate, latency_debt_decays);
			FLOW_CPUSTAT_INC(cstate, latency_lane_enqueues);
			if (has_wake_target && (is_wakeup || !scx_bpf_task_running(p)))
				scx_bpf_kick_cpu(target_cpu, SCX_KICK_IDLE);
			clear_wake_target(tctx);
			return;
		}

		reserved_priority_wakeup = should_prioritize_reserved_enqueue(
			tctx, is_wakeup, containment_active, latency_lane_wakeup,
			rt_sensitive_wakeup, direct_local_wakeup, ipc_confidence_wakeup);
		if (reserved_priority_wakeup)
			enq_flags |= SCX_ENQ_HEAD;

		if (has_wake_target && is_wakeup && valid_sched_cpu(target_cpu)) {
			scx_bpf_dsq_insert(p, reserved_cpu_dsq_id(target_cpu), slice_ns, enq_flags);
			reset_local_reserved_burst(cstate);
			FLOW_CPUSTAT_INC(cstate, reserved_global_enqueues);
			if (tctx->wake_cpu_idle)
				scx_bpf_kick_cpu(target_cpu, SCX_KICK_IDLE);
			clear_wake_target(tctx);
			return;
		}

		scx_bpf_dsq_insert(p, RESERVED_DSQ, slice_ns, enq_flags);
		reset_local_reserved_burst(cstate);
		FLOW_CPUSTAT_INC(cstate, reserved_global_enqueues);
		if (has_wake_target && (is_wakeup || !scx_bpf_task_running(p)))
			scx_bpf_kick_cpu(target_cpu, SCX_KICK_IDLE);
		clear_wake_target(tctx);
		return;
	}

	if (tctx && is_containment_active(tctx)) {
		if (should_promote_contained_enqueue(cstate)) {
			enq_flags |= SCX_ENQ_HEAD;
			FLOW_CPUSTAT_INC(cstate, contained_starved_head_enqueues);
		}
		scx_bpf_dsq_insert(p, CONTAINED_DSQ, contained_slice_ns(), enq_flags);
		reset_local_reserved_burst(cstate);
		FLOW_CPUSTAT_INC(cstate, contained_enqueues);
		FLOW_CPUSTAT_INC(cstate, hog_containment_enqueues);
		clear_wake_target(tctx);
		return;
	}

	if (is_wakeup)
		FLOW_CPUSTAT_INC(cstate, shared_wakeup_enqueues);

	if (should_promote_shared_enqueue(cstate)) {
		enq_flags |= SCX_ENQ_HEAD;
		FLOW_CPUSTAT_INC(cstate, shared_starved_head_enqueues);
	}

	if (is_wakeup && has_wake_target && valid_sched_cpu(target_cpu)) {
		scx_bpf_dsq_insert(p, shared_cpu_dsq_id(target_cpu), slice_ns, enq_flags);
		reset_local_reserved_burst(cstate);
		if (tctx && tctx->wake_cpu_idle)
			scx_bpf_kick_cpu(target_cpu, SCX_KICK_IDLE);
		clear_wake_target(tctx);
		return;
	}

	scx_bpf_dsq_insert(p, SHARED_DSQ, slice_ns, enq_flags);
	reset_local_reserved_burst(cstate);
	clear_wake_target(tctx);
}

void BPF_STRUCT_OPS(flow_dispatch, s32 cpu, struct task_struct *prev)
{
	struct task_ctx *tctx;
	struct flow_cpu_state *cstate;
	u64 shared_max = tune_shared_starvation_max;
	u64 contained_max = tune_contained_starvation_max;
	u64 reserved_lane_max = tuned_reserved_lane_burst_max();
	bool force_shared;
	bool force_contained;
	u64 quota_max = tuned_reserved_quota_burst_max();
	bool quota_force_shared;
	bool quota_force_contained;
	bool shared_more_starved;
	u64 shared_rounds;
	u64 contained_rounds;
	u64 high_priority_rounds;
	u64 urgent_burst_rounds;
	u64 reserved_lane_rounds;

	if (shared_max < FLOW_SHARED_STARVATION_MIN)
		shared_max = FLOW_SHARED_STARVATION_MIN;
	else if (shared_max > FLOW_SHARED_STARVATION_MAX_TUNE)
		shared_max = FLOW_SHARED_STARVATION_MAX_TUNE;

	if (contained_max < FLOW_CONTAINED_STARVATION_MIN)
		contained_max = FLOW_CONTAINED_STARVATION_MIN;
	else if (contained_max > FLOW_CONTAINED_STARVATION_MAX_TUNE)
		contained_max = FLOW_CONTAINED_STARVATION_MAX_TUNE;

	cstate = lookup_cpu_state();
	shared_rounds = cstate ? cstate->shared_starvation_rounds : 0;
	contained_rounds = cstate ? cstate->contained_starvation_rounds : 0;
	high_priority_rounds = cstate ? cstate->high_priority_burst_rounds : 0;
	urgent_burst_rounds = cstate ? cstate->urgent_latency_burst_rounds : 0;
	reserved_lane_rounds = cstate ? cstate->reserved_lane_burst_rounds : 0;

	force_shared = shared_rounds >= shared_max;
	force_contained = contained_rounds >= contained_max;
	quota_force_shared = !force_shared &&
		high_priority_rounds >= quota_max &&
		shared_rounds > 0;
	quota_force_contained = !force_contained &&
		high_priority_rounds >= quota_max &&
		contained_rounds > 0;
	shared_more_starved =
		shared_rounds * contained_max >=
		contained_rounds * shared_max;

	if (quota_force_shared || quota_force_contained)
		FLOW_CPUSTAT_INC(cstate, reserved_quota_skips);

	if (quota_force_shared &&
	    (!quota_force_contained || shared_more_starved)) {
		if (move_shared_lane_to_local(cpu)) {
			FLOW_CPUSTAT_INC(cstate, shared_dispatches);
			FLOW_CPUSTAT_INC(cstate, quota_shared_forces);
			note_shared_dispatch(cstate, true);
			return;
		}
	}

	if (quota_force_contained &&
	    (!quota_force_shared || !shared_more_starved)) {
		if (scx_bpf_dsq_move_to_local(CONTAINED_DSQ, 0)) {
			FLOW_CPUSTAT_INC(cstate, contained_dispatches);
			FLOW_CPUSTAT_INC(cstate, quota_contained_forces);
			note_contained_dispatch(cstate, true);
			return;
		}
	}

	if (force_shared) {
		if (move_shared_lane_to_local(cpu)) {
			FLOW_CPUSTAT_INC(cstate, shared_dispatches);
			note_shared_dispatch(cstate, true);
			return;
		}
		backoff_starvation_round(cstate ? &cstate->shared_starvation_rounds : NULL,
					 shared_max);
	}

	if (force_contained) {
		if (scx_bpf_dsq_move_to_local(CONTAINED_DSQ, 0)) {
			FLOW_CPUSTAT_INC(cstate, contained_dispatches);
			note_contained_dispatch(cstate, true);
			return;
		}
		backoff_starvation_round(cstate ? &cstate->contained_starvation_rounds : NULL,
					 contained_max);
	}

	if (urgent_burst_rounds < tuned_urgent_latency_burst_max() &&
	    scx_bpf_dsq_move_to_local(URGENT_LATENCY_DSQ, 0)) {
		reset_local_reserved_burst(cstate);
		note_urgent_latency_dispatch(cstate);
		return;
	}

	if (scx_bpf_dsq_move_to_local(LATENCY_DSQ, 0)) {
		reset_urgent_latency_burst(cstate);
		reset_reserved_lane_burst(cstate);
		reset_local_reserved_burst(cstate);
		FLOW_CPUSTAT_INC(cstate, latency_dispatches);
		note_high_priority_dispatch(cstate);
		return;
	}

	if (reserved_lane_rounds >= reserved_lane_max) {
		FLOW_CPUSTAT_INC(cstate, reserved_lane_skips);
		if (shared_more_starved) {
			if (move_shared_lane_to_local(cpu)) {
				FLOW_CPUSTAT_INC(cstate, shared_dispatches);
				FLOW_CPUSTAT_INC(cstate, reserved_lane_shared_forces);
				note_shared_dispatch(cstate, true);
				return;
			}
			FLOW_CPUSTAT_INC(cstate, reserved_lane_shared_misses);
			if (scx_bpf_dsq_move_to_local(CONTAINED_DSQ, 0)) {
				FLOW_CPUSTAT_INC(cstate, contained_dispatches);
				FLOW_CPUSTAT_INC(cstate, reserved_lane_contained_forces);
				note_contained_dispatch(cstate, true);
				return;
			}
			FLOW_CPUSTAT_INC(cstate, reserved_lane_contained_misses);
		} else {
			if (scx_bpf_dsq_move_to_local(CONTAINED_DSQ, 0)) {
				FLOW_CPUSTAT_INC(cstate, contained_dispatches);
				FLOW_CPUSTAT_INC(cstate, reserved_lane_contained_forces);
				note_contained_dispatch(cstate, true);
				return;
			}
			FLOW_CPUSTAT_INC(cstate, reserved_lane_contained_misses);
			if (move_shared_lane_to_local(cpu)) {
				FLOW_CPUSTAT_INC(cstate, shared_dispatches);
				FLOW_CPUSTAT_INC(cstate, reserved_lane_shared_forces);
				note_shared_dispatch(cstate, true);
				return;
			}
			FLOW_CPUSTAT_INC(cstate, reserved_lane_shared_misses);
		}
	}

	if (move_reserved_lane_to_local(cpu)) {
		note_reserved_dispatch(cstate);
		return;
	}

	if (scx_bpf_dsq_move_to_local(CONTAINED_DSQ, 0)) {
		FLOW_CPUSTAT_INC(cstate, contained_dispatches);
		note_contained_dispatch(cstate, false);
		return;
	}

	if (move_shared_lane_to_local(cpu)) {
		FLOW_CPUSTAT_INC(cstate, shared_dispatches);
		note_shared_dispatch(cstate, false);
		return;
	}

	if (!prev || !(prev->scx.flags & SCX_TASK_QUEUED))
		return;

	tctx = lookup_task_ctx(prev);
	prev->scx.slice = task_slice_ns(tctx);
}

void BPF_STRUCT_OPS(flow_running, struct task_struct *p)
{
	struct task_ctx *tctx;
	s32 current_cpu;
	u64 now;

	tctx = lookup_task_ctx(p);
	current_cpu = bpf_get_smp_processor_id();
	now = bpf_ktime_get_ns();
	if (tctx) {
		if (tctx->last_cpu >= 0 && tctx->last_cpu != current_cpu) {
			FLOW_CPUSTAT_INC(lookup_cpu_state(), cpu_migrations);
			decay_locality_score(tctx, FLOW_DIRECT_LOCAL_SCORE_DECAY);
			decay_ipc_confidence(tctx);
		}
		tctx->last_cpu = current_cpu;
		tctx->last_run_at = now;
		recompute_wake_profile(p, tctx);
	}

	__sync_fetch_and_add(&nr_running, 1);
}

void BPF_STRUCT_OPS(flow_stopping, struct task_struct *p, bool runnable)
{
	struct task_ctx *tctx;
	u64 now;
	u64 runtime_ns = 0;
	bool exhausted_budget = false;

	tctx = lookup_task_ctx(p);
	now = bpf_ktime_get_ns();

	if (tctx) {
		if (tctx->last_run_at && now > tctx->last_run_at)
			runtime_ns = now - tctx->last_run_at;

		exhausted_budget = tctx->budget_ns > 0 &&
			tctx->budget_ns - (s64)runtime_ns <= 0;

		if (exhausted_budget)
			FLOW_CPUSTAT_INC(lookup_cpu_state(), budget_exhaustions);
		if (exhausted_budget)
			raise_containment_score(tctx, FLOW_HOG_SCORE_EXHAUST_STEP);
		if (exhausted_budget)
			decay_latency_allowance(tctx, tuned_latency_credit_decay());
		if (exhausted_budget)
			decay_locality_score(tctx, FLOW_DIRECT_LOCAL_SCORE_DECAY);
		if (exhausted_budget)
			decay_ipc_confidence(tctx);
		if (exhausted_budget && runnable &&
		    !is_containment_active(tctx) &&
		    (tctx->last_refill_ns >= (s64)FLOW_LATENCY_LANE_REFILL_MIN_NS ||
		     tctx->latency_allowance > 0) &&
		    raise_latency_pressure(tctx, FLOW_LATENCY_DEBT_RAISE_STEP))
			FLOW_CPUSTAT_INC(lookup_cpu_state(), latency_debt_raises);

		tctx->budget_ns = clamp_budget(tctx->budget_ns - (s64)runtime_ns);
		if (!runnable && !exhausted_budget &&
		    !is_containment_active(tctx) &&
		    runtime_ns > 0 && runtime_ns <= FLOW_DIRECT_LOCAL_SLICE_NS &&
		    tctx->last_cpu >= 0)
			raise_locality_score(tctx, FLOW_DIRECT_LOCAL_SCORE_GAIN);
		if (!runnable && !exhausted_budget &&
		    !is_containment_active(tctx) &&
		    p->nr_cpus_allowed <= FLOW_IPC_CPUS_MAX &&
		    runtime_ns > 0 &&
		    runtime_ns <= FLOW_IPC_RUNTIME_MAX_NS &&
		    tctx->budget_ns > (s64)FLOW_IPC_REFILL_MIN_NS)
			raise_ipc_confidence(tctx);
		else if (runtime_ns > FLOW_IPC_RUNTIME_MAX_NS ||
			 p->nr_cpus_allowed > FLOW_IPC_CPUS_MAX)
			decay_ipc_confidence(tctx);
		tctx->last_run_at = 0;
		tctx->sleep_started_at = runnable ? 0 : now;
		if (!runnable)
			clear_wake_target(tctx);
		recompute_wake_profile(p, tctx);
	}

	__sync_fetch_and_add(&total_runtime, runtime_ns);
	__sync_fetch_and_sub(&nr_running, 1);
}

bool BPF_STRUCT_OPS(flow_yield, struct task_struct *from, struct task_struct *to)
{
	from->scx.slice = FLOW_SLICE_MIN_NS;
	return false;
}

void BPF_STRUCT_OPS(flow_cpu_release, s32 cpu, struct scx_cpu_release_args *args)
{
	scx_bpf_reenqueue_local();
	__sync_fetch_and_add(&cpu_release_reenqueues, 1);
}

void BPF_STRUCT_OPS(flow_exit_task, struct task_struct *p,
		    struct scx_exit_task_args *args)
{
	struct task_ctx *tctx;

	tctx = lookup_task_ctx(p);
	if (!tctx)
		return;

	reset_task_ctx(tctx, 0, false);
	__sync_fetch_and_add(&exit_task_events, 1);
}

void BPF_STRUCT_OPS(flow_exit, struct scx_exit_info *info)
{
	UEI_RECORD(uei, info);
}

SCX_OPS_DEFINE(flow_ops,
	       .select_cpu		= (void *)flow_select_cpu,
	       .enqueue			= (void *)flow_enqueue,
	       .dispatch		= (void *)flow_dispatch,
	       .cpu_release		= (void *)flow_cpu_release,
	       .runnable		= (void *)flow_runnable,
	       .enable			= (void *)flow_enable,
	       .running			= (void *)flow_running,
	       .stopping		= (void *)flow_stopping,
	       .init_task		= (void *)flow_init_task,
	       .exit_task		= (void *)flow_exit_task,
	       .init			= (void *)flow_init,
	       .yield			= (void *)flow_yield,
	       .exit			= (void *)flow_exit,
	       .timeout_ms		= 5000,
	       .name			= "scx_flow");
