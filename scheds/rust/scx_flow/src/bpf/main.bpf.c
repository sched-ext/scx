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

bool scx_bpf_dsq_move_to_local___v2(u64 dsq_id, u64 enq_flags) __ksym __weak;
bool scx_bpf_dsq_move_to_local___v1(u64 dsq_id) __ksym __weak;
bool scx_bpf_dsq_move_to_local___new(u64 dsq_id) __ksym __weak;
bool scx_bpf_consume___old(u64 dsq_id) __ksym __weak;

struct task_ctx {
	s64 budget_ns;
	s64 last_refill_ns;
	u64 last_run_at;
	u64 sleep_started_at;
	u32 latency_credit;
	u32 latency_debt;
	u32 hog_score;
	u32 stable_score;
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
volatile u64 urgent_latency_burst_rounds;
volatile u64 high_priority_burst_rounds;
volatile u64 local_reserved_burst_rounds;
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
volatile u64 reserved_lane_burst_rounds;
volatile u64 reserved_lane_grants;
volatile u64 reserved_lane_burst_continuations;
volatile u64 reserved_lane_skips;
volatile u64 reserved_lane_shared_forces;
volatile u64 reserved_lane_contained_forces;
volatile u64 reserved_lane_shared_misses;
volatile u64 reserved_lane_contained_misses;
volatile u64 contained_starved_head_enqueues;
volatile u64 shared_starved_head_enqueues;
volatile u64 stable_local_candidates;
volatile u64 stable_local_enqueues;
volatile u64 stable_local_rejections;
volatile u64 stable_local_mismatches;
volatile u64 contained_enqueues;
volatile u64 hog_containment_enqueues;
volatile u64 hog_recoveries;
volatile u64 contained_starvation_rounds;
volatile u64 shared_starvation_rounds;
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

#define URGENT_LATENCY_DSQ 1022
#define LATENCY_DSQ 1023
#define RESERVED_DSQ 1024
#define CONTAINED_DSQ 1025
#define SHARED_DSQ 1026

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

static __always_inline bool is_kthread(const struct task_struct *p)
{
	return p->flags & PF_KTHREAD;
}

static __always_inline bool is_pinned_kthread(const struct task_struct *p)
{
	return is_kthread(p) && p->nr_cpus_allowed == 1;
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
	tctx->sleep_started_at = sleeping ? now : 0;
	tctx->latency_credit = 0;
	tctx->latency_debt = 0;
	tctx->hog_score = 0;
	tctx->stable_score = 0;
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

static __always_inline u32 clamp_hog_score(u32 hog_score)
{
	if (hog_score > FLOW_HOG_SCORE_MAX)
		return FLOW_HOG_SCORE_MAX;
	return hog_score;
}

static __always_inline bool is_contained_hog(const struct task_ctx *tctx)
{
	return tctx && tctx->hog_score >= FLOW_HOG_SCORE_CONTAIN;
}

static __always_inline u32 clamp_latency_credit(u32 latency_credit)
{
	if (latency_credit > FLOW_LATENCY_CREDIT_MAX)
		return FLOW_LATENCY_CREDIT_MAX;
	return latency_credit;
}

static __always_inline u32 clamp_latency_debt(u32 latency_debt)
{
	if (latency_debt > FLOW_LATENCY_DEBT_MAX)
		return FLOW_LATENCY_DEBT_MAX;
	return latency_debt;
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

static __always_inline void raise_latency_credit(struct task_ctx *tctx, u32 delta)
{
	if (!tctx || !delta)
		return;

	tctx->latency_credit = clamp_latency_credit(tctx->latency_credit + delta);
}

static __always_inline void decay_latency_credit(struct task_ctx *tctx, u32 delta)
{
	if (!tctx || !delta)
		return;

	if (tctx->latency_credit <= delta)
		tctx->latency_credit = 0;
	else
		tctx->latency_credit -= delta;
}

static __always_inline bool has_urgent_latency_debt(const struct task_ctx *tctx)
{
	return tctx && tctx->latency_debt >= tuned_latency_debt_urgent_min();
}

static __always_inline bool raise_latency_debt(struct task_ctx *tctx, u32 delta)
{
	u32 old_debt;
	u32 new_debt;

	if (!tctx || !delta)
		return false;

	old_debt = tctx->latency_debt;
	new_debt = clamp_latency_debt(old_debt + delta);
	if (new_debt == old_debt)
		return false;

	tctx->latency_debt = new_debt;
	return true;
}

static __always_inline bool decay_latency_debt(struct task_ctx *tctx, u32 delta)
{
	u32 old_debt;

	if (!tctx || !delta)
		return false;

	old_debt = tctx->latency_debt;
	if (!old_debt)
		return false;

	if (old_debt <= delta)
		tctx->latency_debt = 0;
	else
		tctx->latency_debt = old_debt - delta;

	return tctx->latency_debt != old_debt;
}

static __always_inline u32 clamp_stable_score(u32 stable_score)
{
	if (stable_score > FLOW_STABLE_SCORE_MAX)
		return FLOW_STABLE_SCORE_MAX;
	return stable_score;
}

static __always_inline void raise_stable_score(struct task_ctx *tctx, u32 delta)
{
	if (!tctx || !delta)
		return;

	tctx->stable_score = clamp_stable_score(tctx->stable_score + delta);
}

static __always_inline void decay_stable_score(struct task_ctx *tctx, u32 delta)
{
	if (!tctx || !delta)
		return;

	if (tctx->stable_score <= delta)
		tctx->stable_score = 0;
	else
		tctx->stable_score -= delta;
}

static __always_inline void decay_hog_score(struct task_ctx *tctx, u32 delta)
{
	u32 old_score;

	if (!tctx || !delta)
		return;

	old_score = tctx->hog_score;
	if (old_score <= delta)
		tctx->hog_score = 0;
	else
		tctx->hog_score = old_score - delta;

	if (old_score >= FLOW_HOG_SCORE_CONTAIN &&
	    tctx->hog_score < FLOW_HOG_SCORE_CONTAIN)
		__sync_fetch_and_add(&hog_recoveries, 1);
}

static __always_inline void raise_hog_score(struct task_ctx *tctx, u32 delta)
{
	if (!tctx || !delta)
		return;

	tctx->hog_score = clamp_hog_score(tctx->hog_score + delta);
}

static __always_inline void update_budget_on_wakeup(const struct task_struct *p,
						    struct task_ctx *tctx,
						    u64 now)
{
	s64 refill_ns;
	u64 interactive_floor_ns = tune_interactive_floor_ns;
	u64 recovery_refill_min_ns;

	if (!tctx)
		return;

	tctx->last_refill_ns = 0;

	if (!tctx->sleep_started_at || now <= tctx->sleep_started_at)
		return;

	refill_ns = calc_budget_refill(p, now - tctx->sleep_started_at);
	tctx->budget_ns = clamp_budget(tctx->budget_ns + refill_ns);
	tctx->last_refill_ns = refill_ns;
	tctx->sleep_started_at = 0;

	if (refill_ns > 0) {
		if (interactive_floor_ns < FLOW_INTERACTIVE_FLOOR_MIN_NS)
			interactive_floor_ns = FLOW_INTERACTIVE_FLOOR_MIN_NS;
		else if (interactive_floor_ns > FLOW_INTERACTIVE_FLOOR_MAX_NS)
			interactive_floor_ns = FLOW_INTERACTIVE_FLOOR_MAX_NS;

		recovery_refill_min_ns = interactive_floor_ns + FLOW_HOG_RECOVERY_MARGIN_NS;
		if (refill_ns >= (s64)recovery_refill_min_ns)
			decay_hog_score(tctx, FLOW_HOG_SCORE_DECAY_STEP);
		if (refill_ns >= (s64)FLOW_LATENCY_LANE_REFILL_MIN_NS &&
		    tctx->budget_ns >= (s64)FLOW_LATENCY_LANE_BUDGET_MIN_NS)
			raise_latency_credit(tctx, tuned_latency_credit_grant());
		__sync_fetch_and_add(&budget_refill_events, 1);
	}
}

static __always_inline bool is_rt_sensitive_wakeup(const struct task_struct *p,
						    const struct task_ctx *tctx,
						    bool is_wakeup)
{
	if (!tctx || !is_wakeup)
		return false;
	if (p->nr_cpus_allowed != 1)
		return false;
	if (is_contained_hog(tctx))
		return false;
	if (tctx->budget_ns <= 0)
		return false;
	if (tctx->last_refill_ns <= 0)
		return false;

	return tctx->last_refill_ns >= (s64)FLOW_INTERACTIVE_FLOOR_MIN_NS;
}

static __always_inline bool is_soft_latency_candidate(const struct task_ctx *tctx)
{
	if (!tctx || tctx->budget_ns <= 0 || !tctx->latency_credit)
		return false;
	return tctx->budget_ns >= (s64)FLOW_LATENCY_LANE_BUDGET_MIN_NS;
}

static __always_inline bool is_stable_local_candidate(const struct task_ctx *tctx,
						      s32 target_cpu,
						      bool is_wakeup,
						      bool rt_sensitive_wakeup,
						      bool latency_lane_wakeup,
						      bool contained_hog)
{
	if (!tctx || !is_wakeup)
		return false;
	if (contained_hog || rt_sensitive_wakeup || latency_lane_wakeup)
		return false;
	if (tctx->budget_ns <= 0)
		return false;
	if (tctx->last_cpu < 0 || target_cpu < 0 || target_cpu != tctx->last_cpu)
		return false;

	return tctx->stable_score >= FLOW_STABLE_LOCAL_SCORE_MIN;
}

static __always_inline bool allow_idle_local_fast_path(void)
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

static __always_inline bool allow_stable_local_fast_path(void)
{
	if (nr_running > FLOW_STABLE_LOCAL_NR_RUNNING_MAX)
		return false;
	return true;
}

static __always_inline void bump_starvation_round(volatile u64 *counter, u64 max_rounds)
{
	if (*counter < max_rounds)
		__sync_fetch_and_add(counter, 1);
}

static __always_inline void backoff_starvation_round(volatile u64 *counter, u64 max_rounds)
{
	if (!max_rounds)
		return;

	if (*counter >= max_rounds)
		*counter = max_rounds - 1;
}

static __always_inline void note_high_priority_dispatch(void)
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

	bump_starvation_round(&contained_starvation_rounds,
			      contained_max);
	bump_starvation_round(&shared_starvation_rounds,
			      shared_max);
	if (high_priority_burst_rounds < quota_max)
		high_priority_burst_rounds++;
}

static __always_inline void reset_urgent_latency_burst(void)
{
	urgent_latency_burst_rounds = 0;
}

static __always_inline void reset_reserved_lane_burst(void)
{
	reserved_lane_burst_rounds = 0;
}

static __always_inline void reset_local_reserved_burst(void)
{
	local_reserved_burst_rounds = 0;
}

static __always_inline void note_local_reserved_fast(void)
{
	u64 burst_max = tuned_local_reserved_burst_max();

	__sync_fetch_and_add(&local_reserved_fast_grants, 1);
	if (local_reserved_burst_rounds > 0)
		__sync_fetch_and_add(&local_reserved_burst_continuations, 1);
	if (local_reserved_burst_rounds < burst_max)
		local_reserved_burst_rounds++;
}

static __always_inline void note_urgent_latency_dispatch(void)
{
	if (urgent_latency_burst_rounds > 0)
		__sync_fetch_and_add(&urgent_latency_burst_continuations, 1);
	if (urgent_latency_burst_rounds < tuned_urgent_latency_burst_max())
		urgent_latency_burst_rounds++;
	__sync_fetch_and_add(&urgent_latency_dispatches, 1);
	__sync_fetch_and_add(&urgent_latency_burst_grants, 1);
	reset_reserved_lane_burst();
	note_high_priority_dispatch();
}

static __always_inline void note_reserved_dispatch(void)
{
	u64 burst_max = tuned_reserved_lane_burst_max();

	__sync_fetch_and_add(&reserved_dispatches, 1);
	__sync_fetch_and_add(&reserved_lane_grants, 1);
	if (reserved_lane_burst_rounds > 0)
		__sync_fetch_and_add(&reserved_lane_burst_continuations, 1);
	if (reserved_lane_burst_rounds < burst_max)
		reserved_lane_burst_rounds++;
	reset_urgent_latency_burst();
	reset_local_reserved_burst();
	note_high_priority_dispatch();
}

static __always_inline void note_contained_dispatch(bool rescued)
{
	u64 shared_max = tune_shared_starvation_max;

	if (shared_max < FLOW_SHARED_STARVATION_MIN)
		shared_max = FLOW_SHARED_STARVATION_MIN;
	else if (shared_max > FLOW_SHARED_STARVATION_MAX_TUNE)
		shared_max = FLOW_SHARED_STARVATION_MAX_TUNE;

	contained_starvation_rounds = 0;
	high_priority_burst_rounds = 0;
	bump_starvation_round(&shared_starvation_rounds, shared_max);
	reset_urgent_latency_burst();
	reset_reserved_lane_burst();
	reset_local_reserved_burst();
	if (rescued)
		__sync_fetch_and_add(&contained_rescue_dispatches, 1);
}

static __always_inline void note_shared_dispatch(bool rescued)
{
	u64 contained_max = tune_contained_starvation_max;

	if (contained_max < FLOW_CONTAINED_STARVATION_MIN)
		contained_max = FLOW_CONTAINED_STARVATION_MIN;
	else if (contained_max > FLOW_CONTAINED_STARVATION_MAX_TUNE)
		contained_max = FLOW_CONTAINED_STARVATION_MAX_TUNE;

	shared_starvation_rounds = 0;
	high_priority_burst_rounds = 0;
	bump_starvation_round(&contained_starvation_rounds, contained_max);
	reset_urgent_latency_burst();
	reset_reserved_lane_burst();
	reset_local_reserved_burst();
	if (rescued)
		__sync_fetch_and_add(&shared_rescue_dispatches, 1);
}

static __always_inline bool local_reserved_quota_active(void)
{
	u64 max_running = tune_local_fast_nr_running_max;

	if (max_running < FLOW_LOCAL_FAST_NR_RUNNING_MIN)
		max_running = FLOW_LOCAL_FAST_NR_RUNNING_MIN;
	else if (max_running > FLOW_LOCAL_FAST_NR_RUNNING_MAX_TUNE)
		max_running = FLOW_LOCAL_FAST_NR_RUNNING_MAX_TUNE;

	return nr_running > max_running ||
		contained_starvation_rounds > 0 ||
		shared_starvation_rounds > 0;
}

static __always_inline void note_stable_mismatch(struct task_ctx *tctx)
{
	if (!tctx)
		return;

	__sync_fetch_and_add(&stable_local_mismatches, 1);
	decay_stable_score(tctx, FLOW_STABLE_MISMATCH_DECAY);
}

static __always_inline void note_stable_rejection(struct task_ctx *tctx)
{
	if (!tctx)
		return;

	__sync_fetch_and_add(&stable_local_rejections, 1);
	decay_stable_score(tctx, FLOW_STABLE_MISMATCH_DECAY);
}

static __always_inline bool should_promote_shared_enqueue(void)
{
	u64 shared_max = tune_shared_starvation_max;

	if (shared_max < FLOW_SHARED_STARVATION_MIN)
		shared_max = FLOW_SHARED_STARVATION_MIN;
	else if (shared_max > FLOW_SHARED_STARVATION_MAX_TUNE)
		shared_max = FLOW_SHARED_STARVATION_MAX_TUNE;

	return shared_starvation_rounds * 2 >= shared_max;
}

static __always_inline bool should_promote_contained_enqueue(void)
{
	u64 contained_max = tune_contained_starvation_max;

	if (contained_max < FLOW_CONTAINED_STARVATION_MIN)
		contained_max = FLOW_CONTAINED_STARVATION_MIN;
	else if (contained_max > FLOW_CONTAINED_STARVATION_MAX_TUNE)
		contained_max = FLOW_CONTAINED_STARVATION_MAX_TUNE;

	return contained_starvation_rounds * 2 >= contained_max;
}

static __always_inline bool move_to_local_compat(u64 dsq_id)
{
	if (bpf_ksym_exists(scx_bpf_dsq_move_to_local___v2))
		return scx_bpf_dsq_move_to_local___v2(dsq_id, 0);
	if (bpf_ksym_exists(scx_bpf_dsq_move_to_local___v1))
		return scx_bpf_dsq_move_to_local___v1(dsq_id);
	if (bpf_ksym_exists(scx_bpf_dsq_move_to_local___new))
		return scx_bpf_dsq_move_to_local___new(dsq_id);
	return scx_bpf_consume___old(dsq_id);
}

s32 BPF_STRUCT_OPS_SLEEPABLE(flow_init)
{
	s32 ret;

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
	bool is_this_cpu_allowed = bpf_cpumask_test_cpu(this_cpu, p->cpus_ptr);

	tctx = lookup_task_ctx(p);
	if (tctx) {
		update_budget_on_wakeup(p, tctx, bpf_ktime_get_ns());
		clear_wake_target(tctx);
	}

	if (!bpf_cpumask_test_cpu(prev_cpu, p->cpus_ptr))
		prev_cpu = is_this_cpu_allowed ? this_cpu : bpf_cpumask_first(p->cpus_ptr);

	preferred_cpu = prev_cpu;
	if (tctx && tctx->last_cpu >= 0 &&
	    bpf_cpumask_test_cpu(tctx->last_cpu, p->cpus_ptr)) {
		preferred_cpu = tctx->last_cpu;
		__sync_fetch_and_add(&cpu_stability_biases, 1);
	}

	cpu = scx_bpf_select_cpu_dfl(p, preferred_cpu, wake_flags, &is_idle);
	if (tctx) {
		tctx->wake_cpu = cpu >= 0 ? cpu : preferred_cpu;
		tctx->wake_cpu_idle = is_idle;
		tctx->wake_cpu_valid =
			tctx->wake_cpu >= 0 &&
			bpf_cpumask_test_cpu(tctx->wake_cpu, p->cpus_ptr);
		if (tctx->last_cpu >= 0 && tctx->wake_cpu == tctx->last_cpu)
			__sync_fetch_and_add(&last_cpu_matches, 1);
		else if (tctx->last_cpu >= 0)
			note_stable_mismatch(tctx);
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
		__sync_fetch_and_add(&runnable_wakeups, 1);
	update_budget_on_wakeup(p, tctx, now);
}

void BPF_STRUCT_OPS(flow_enqueue, struct task_struct *p, u64 enq_flags)
{
	struct task_ctx *tctx;
	s32 target_cpu = -1;
	u64 slice_ns;
	bool is_wakeup;
	bool has_wake_target = false;
	bool rt_sensitive_wakeup = false;
	bool soft_latency_wakeup = false;
	bool debt_latency_wakeup = false;
	bool latency_lane_wakeup = false;
	bool urgent_latency_wakeup = false;
	bool stable_local_wakeup = false;
	bool contained_hog = false;
	bool use_local_reserved = false;
	bool ordinary_local_reserved = false;

	tctx = lookup_task_ctx(p);
	slice_ns = task_slice_ns(tctx);
	is_wakeup = enq_flags & SCX_ENQ_WAKEUP;

	if (tctx && tctx->wake_cpu_valid) {
		target_cpu = tctx->wake_cpu;
		has_wake_target = true;
	} else {
		target_cpu = scx_bpf_task_cpu(p);
	}

	if (is_pinned_kthread(p)) {
		clear_wake_target(tctx);
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, task_slice_ns(NULL), enq_flags);
		__sync_fetch_and_add(&local_fast_dispatches, 1);
		return;
	}

	if (tctx) {
		if (tctx->budget_ns > 0) {
			contained_hog = is_contained_hog(tctx);
			debt_latency_wakeup = is_wakeup &&
				!contained_hog &&
				has_urgent_latency_debt(tctx);
			soft_latency_wakeup = is_wakeup &&
				!contained_hog &&
				is_soft_latency_candidate(tctx);
			if (soft_latency_wakeup || debt_latency_wakeup) {
				__sync_fetch_and_add(&latency_lane_candidates, 1);
			}
			if (contained_hog && is_soft_latency_candidate(tctx))
				__sync_fetch_and_add(&latency_candidate_hog_blocks, 1);
			if (is_wakeup)
				__sync_fetch_and_add(&positive_budget_wakeups, 1);
			rt_sensitive_wakeup = is_rt_sensitive_wakeup(p, tctx, is_wakeup);
			if (rt_sensitive_wakeup)
				__sync_fetch_and_add(&rt_sensitive_wakeups, 1);
			latency_lane_wakeup =
				(soft_latency_wakeup || debt_latency_wakeup) &&
				!rt_sensitive_wakeup;
			urgent_latency_wakeup = debt_latency_wakeup &&
				!rt_sensitive_wakeup;
			stable_local_wakeup = is_stable_local_candidate(tctx, target_cpu,
									       is_wakeup,
									       rt_sensitive_wakeup,
									       latency_lane_wakeup,
									       contained_hog);
			if (stable_local_wakeup && !allow_stable_local_fast_path()) {
				stable_local_wakeup = false;
				note_stable_rejection(tctx);
			}
			if (stable_local_wakeup)
				__sync_fetch_and_add(&stable_local_candidates, 1);

			if (is_wakeup && !contained_hog)
				enq_flags |= SCX_ENQ_HEAD;

			if (has_wake_target ||
			    bpf_cpumask_test_cpu(target_cpu, p->cpus_ptr)) {
				u64 preempt_refill_min_ns = tune_preempt_refill_min_ns;
				u64 preempt_budget_min_ns = tune_preempt_budget_min_ns;
				bool single_cpu_task = p->nr_cpus_allowed == 1;
				bool should_preempt;

				if (preempt_refill_min_ns < FLOW_PREEMPT_REFILL_MIN_NS)
					preempt_refill_min_ns = FLOW_PREEMPT_REFILL_MIN_NS;
				else if (preempt_refill_min_ns > FLOW_PREEMPT_REFILL_MAX_NS)
					preempt_refill_min_ns = FLOW_PREEMPT_REFILL_MAX_NS;

				if (preempt_budget_min_ns < FLOW_PREEMPT_BUDGET_MIN_NS)
					preempt_budget_min_ns = FLOW_PREEMPT_BUDGET_MIN_NS;
				else if (preempt_budget_min_ns > FLOW_PREEMPT_BUDGET_MAX_NS)
					preempt_budget_min_ns = FLOW_PREEMPT_BUDGET_MAX_NS;

				should_preempt = rt_sensitive_wakeup ||
					(is_wakeup &&
					 !contained_hog &&
					 !tctx->wake_cpu_idle &&
					 (single_cpu_task ||
					  (tctx->last_refill_ns >= (s64)preempt_refill_min_ns &&
					   tctx->budget_ns >= (s64)preempt_budget_min_ns)));

				use_local_reserved = should_preempt ||
					(!latency_lane_wakeup &&
					 !contained_hog &&
					 tctx->wake_cpu_idle && is_wakeup &&
					 allow_idle_local_fast_path()) ||
					stable_local_wakeup;
				ordinary_local_reserved = use_local_reserved &&
					!should_preempt;

				if (ordinary_local_reserved &&
				    local_reserved_quota_active() &&
				    local_reserved_burst_rounds >=
					    tuned_local_reserved_burst_max()) {
					use_local_reserved = false;
					ordinary_local_reserved = false;
					__sync_fetch_and_add(&local_quota_skips, 1);
				}

				if (should_preempt) {
					enq_flags |= SCX_ENQ_PREEMPT;
					scx_bpf_kick_cpu(target_cpu, SCX_KICK_PREEMPT);
					__sync_fetch_and_add(&wake_preempt_dispatches, 1);
					if (rt_sensitive_wakeup)
						__sync_fetch_and_add(&rt_sensitive_preempts, 1);
				} else if (tctx->wake_cpu_idle &&
					   (is_wakeup || !scx_bpf_task_running(p))) {
					scx_bpf_kick_cpu(target_cpu, SCX_KICK_IDLE);
				}

				if (use_local_reserved) {
					u64 local_slice_ns = rt_sensitive_wakeup ?
						FLOW_RT_WAKE_SLICE_NS : slice_ns;

					if (urgent_latency_wakeup)
						__sync_fetch_and_add(&urgent_latency_misses, 1);
					scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | target_cpu,
							   local_slice_ns, enq_flags);
					if (latency_lane_wakeup)
						__sync_fetch_and_add(&latency_candidate_local_enqueues, 1);
					__sync_fetch_and_add(&reserved_local_enqueues, 1);
					if (rt_sensitive_wakeup)
						__sync_fetch_and_add(&rt_sensitive_local_enqueues, 1);
					if (stable_local_wakeup)
						__sync_fetch_and_add(&stable_local_enqueues, 1);
					if (tctx->wake_cpu_idle)
						__sync_fetch_and_add(&local_fast_dispatches, 1);
					if (ordinary_local_reserved)
						note_local_reserved_fast();
					clear_wake_target(tctx);
					return;
				}
			}

			if (stable_local_wakeup)
				note_stable_rejection(tctx);

			if (contained_hog) {
				if (should_promote_contained_enqueue()) {
					enq_flags |= SCX_ENQ_HEAD;
					__sync_fetch_and_add(&contained_starved_head_enqueues, 1);
				}
				scx_bpf_dsq_insert(p, CONTAINED_DSQ, contained_slice_ns(),
						   enq_flags);
				reset_local_reserved_burst();
				__sync_fetch_and_add(&contained_enqueues, 1);
				__sync_fetch_and_add(&hog_containment_enqueues, 1);
				clear_wake_target(tctx);
				return;
			}

			if (latency_lane_wakeup) {
				u64 latency_dsq = urgent_latency_wakeup ?
					URGENT_LATENCY_DSQ : LATENCY_DSQ;

				scx_bpf_dsq_insert(p, latency_dsq, slice_ns, enq_flags);
				reset_local_reserved_burst();
				decay_latency_credit(tctx, tuned_latency_credit_decay());
				if (urgent_latency_wakeup)
					__sync_fetch_and_add(&urgent_latency_enqueues, 1);
				if (has_urgent_latency_debt(tctx))
					__sync_fetch_and_add(&latency_debt_urgent_enqueues, 1);
				if (decay_latency_debt(tctx, FLOW_LATENCY_DEBT_DECAY_STEP))
					__sync_fetch_and_add(&latency_debt_decays, 1);
				__sync_fetch_and_add(&latency_lane_enqueues, 1);
				if (has_wake_target && (is_wakeup || !scx_bpf_task_running(p)))
					scx_bpf_kick_cpu(target_cpu, SCX_KICK_IDLE);
				clear_wake_target(tctx);
				return;
			}

			scx_bpf_dsq_insert(p, RESERVED_DSQ, slice_ns, enq_flags);
			reset_local_reserved_burst();
			__sync_fetch_and_add(&reserved_global_enqueues, 1);
			if (has_wake_target && (is_wakeup || !scx_bpf_task_running(p)))
				scx_bpf_kick_cpu(target_cpu, SCX_KICK_IDLE);
			clear_wake_target(tctx);
			return;
		}
	}

	if (tctx && is_contained_hog(tctx)) {
		if (should_promote_contained_enqueue()) {
			enq_flags |= SCX_ENQ_HEAD;
			__sync_fetch_and_add(&contained_starved_head_enqueues, 1);
		}
		scx_bpf_dsq_insert(p, CONTAINED_DSQ, contained_slice_ns(), enq_flags);
		reset_local_reserved_burst();
		__sync_fetch_and_add(&contained_enqueues, 1);
		__sync_fetch_and_add(&hog_containment_enqueues, 1);
		clear_wake_target(tctx);
		return;
	}

	if (is_wakeup)
		__sync_fetch_and_add(&shared_wakeup_enqueues, 1);

	if (should_promote_shared_enqueue()) {
		enq_flags |= SCX_ENQ_HEAD;
		__sync_fetch_and_add(&shared_starved_head_enqueues, 1);
	}
	scx_bpf_dsq_insert(p, SHARED_DSQ, slice_ns, enq_flags);
	reset_local_reserved_burst();
	clear_wake_target(tctx);
}

void BPF_STRUCT_OPS(flow_dispatch, s32 cpu, struct task_struct *prev)
{
	struct task_ctx *tctx;
	u64 shared_max = tune_shared_starvation_max;
	u64 contained_max = tune_contained_starvation_max;
	u64 reserved_lane_max = tuned_reserved_lane_burst_max();
	bool force_shared;
	bool force_contained;
	u64 quota_max = tuned_reserved_quota_burst_max();
	bool quota_force_shared;
	bool quota_force_contained;
	bool shared_more_starved;

	if (shared_max < FLOW_SHARED_STARVATION_MIN)
		shared_max = FLOW_SHARED_STARVATION_MIN;
	else if (shared_max > FLOW_SHARED_STARVATION_MAX_TUNE)
		shared_max = FLOW_SHARED_STARVATION_MAX_TUNE;

	if (contained_max < FLOW_CONTAINED_STARVATION_MIN)
		contained_max = FLOW_CONTAINED_STARVATION_MIN;
	else if (contained_max > FLOW_CONTAINED_STARVATION_MAX_TUNE)
		contained_max = FLOW_CONTAINED_STARVATION_MAX_TUNE;

	force_shared = shared_starvation_rounds >= shared_max;
	force_contained = contained_starvation_rounds >= contained_max;
	quota_force_shared = !force_shared &&
		high_priority_burst_rounds >= quota_max &&
		shared_starvation_rounds > 0;
	quota_force_contained = !force_contained &&
		high_priority_burst_rounds >= quota_max &&
		contained_starvation_rounds > 0;
	shared_more_starved =
		shared_starvation_rounds * contained_max >=
		contained_starvation_rounds * shared_max;

	if (quota_force_shared || quota_force_contained)
		__sync_fetch_and_add(&reserved_quota_skips, 1);

	if (quota_force_shared &&
	    (!quota_force_contained || shared_more_starved)) {
		if (move_to_local_compat(SHARED_DSQ)) {
			__sync_fetch_and_add(&shared_dispatches, 1);
			__sync_fetch_and_add(&quota_shared_forces, 1);
			note_shared_dispatch(true);
			return;
		}
	}

	if (quota_force_contained &&
	    (!quota_force_shared || !shared_more_starved)) {
		if (move_to_local_compat(CONTAINED_DSQ)) {
			__sync_fetch_and_add(&contained_dispatches, 1);
			__sync_fetch_and_add(&quota_contained_forces, 1);
			note_contained_dispatch(true);
			return;
		}
	}

	if (force_shared) {
		if (move_to_local_compat(SHARED_DSQ)) {
			__sync_fetch_and_add(&shared_dispatches, 1);
			note_shared_dispatch(true);
			return;
		}
		backoff_starvation_round(&shared_starvation_rounds, shared_max);
	}

	if (force_contained) {
		if (move_to_local_compat(CONTAINED_DSQ)) {
			__sync_fetch_and_add(&contained_dispatches, 1);
			note_contained_dispatch(true);
			return;
		}
		backoff_starvation_round(&contained_starvation_rounds, contained_max);
	}

	if (urgent_latency_burst_rounds < tuned_urgent_latency_burst_max() &&
	    move_to_local_compat(URGENT_LATENCY_DSQ)) {
		reset_local_reserved_burst();
		note_urgent_latency_dispatch();
		return;
	}

	if (move_to_local_compat(LATENCY_DSQ)) {
		reset_urgent_latency_burst();
		reset_reserved_lane_burst();
		reset_local_reserved_burst();
		__sync_fetch_and_add(&latency_dispatches, 1);
		note_high_priority_dispatch();
		return;
	}

	if (reserved_lane_burst_rounds >= reserved_lane_max) {
		__sync_fetch_and_add(&reserved_lane_skips, 1);
		if (shared_more_starved) {
			if (move_to_local_compat(SHARED_DSQ)) {
				__sync_fetch_and_add(&shared_dispatches, 1);
				__sync_fetch_and_add(&reserved_lane_shared_forces, 1);
				note_shared_dispatch(true);
				return;
			}
			__sync_fetch_and_add(&reserved_lane_shared_misses, 1);
			if (move_to_local_compat(CONTAINED_DSQ)) {
				__sync_fetch_and_add(&contained_dispatches, 1);
				__sync_fetch_and_add(&reserved_lane_contained_forces, 1);
				note_contained_dispatch(true);
				return;
			}
			__sync_fetch_and_add(&reserved_lane_contained_misses, 1);
		} else {
			if (move_to_local_compat(CONTAINED_DSQ)) {
				__sync_fetch_and_add(&contained_dispatches, 1);
				__sync_fetch_and_add(&reserved_lane_contained_forces, 1);
				note_contained_dispatch(true);
				return;
			}
			__sync_fetch_and_add(&reserved_lane_contained_misses, 1);
			if (move_to_local_compat(SHARED_DSQ)) {
				__sync_fetch_and_add(&shared_dispatches, 1);
				__sync_fetch_and_add(&reserved_lane_shared_forces, 1);
				note_shared_dispatch(true);
				return;
			}
			__sync_fetch_and_add(&reserved_lane_shared_misses, 1);
		}
	}

	if (move_to_local_compat(RESERVED_DSQ)) {
		note_reserved_dispatch();
		return;
	}

	if (move_to_local_compat(CONTAINED_DSQ)) {
		__sync_fetch_and_add(&contained_dispatches, 1);
		note_contained_dispatch(false);
		return;
	}

	if (move_to_local_compat(SHARED_DSQ)) {
		__sync_fetch_and_add(&shared_dispatches, 1);
		note_shared_dispatch(false);
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
			__sync_fetch_and_add(&cpu_migrations, 1);
			decay_stable_score(tctx, FLOW_STABLE_SCORE_DECAY);
		} else {
			raise_stable_score(tctx, FLOW_STABLE_SCORE_GAIN);
		}
		tctx->last_cpu = current_cpu;
		tctx->last_run_at = now;
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
			__sync_fetch_and_add(&budget_exhaustions, 1);
		if (exhausted_budget)
			raise_hog_score(tctx, FLOW_HOG_SCORE_EXHAUST_STEP);
		if (exhausted_budget)
			decay_latency_credit(tctx, tuned_latency_credit_decay());
		if (exhausted_budget && runnable &&
		    !is_contained_hog(tctx) &&
		    (tctx->last_refill_ns >= (s64)FLOW_LATENCY_LANE_REFILL_MIN_NS ||
		     tctx->latency_credit > 0) &&
		    raise_latency_debt(tctx, FLOW_LATENCY_DEBT_RAISE_STEP))
			__sync_fetch_and_add(&latency_debt_raises, 1);

		tctx->budget_ns = clamp_budget(tctx->budget_ns - (s64)runtime_ns);
		tctx->last_run_at = 0;
		tctx->sleep_started_at = runnable ? 0 : now;
		if (!runnable)
			clear_wake_target(tctx);
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
