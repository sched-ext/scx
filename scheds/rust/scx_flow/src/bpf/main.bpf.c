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
	u32 hog_score;
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
volatile u64 latency_dispatches;
volatile u64 shared_dispatches;
volatile u64 local_fast_dispatches;
volatile u64 wake_preempt_dispatches;
volatile u64 budget_refill_events;
volatile u64 budget_exhaustions;
volatile u64 positive_budget_wakeups;
volatile u64 latency_lane_enqueues;
volatile u64 reserved_local_enqueues;
volatile u64 reserved_global_enqueues;
volatile u64 shared_wakeup_enqueues;
volatile u64 runnable_wakeups;
volatile u64 cpu_release_reenqueues;
volatile u64 init_task_events;
volatile u64 enable_events;
volatile u64 exit_task_events;
volatile u64 cpu_stability_biases;
volatile u64 last_cpu_matches;
volatile u64 cpu_migrations;
volatile u64 rt_sensitive_wakeups;
volatile u64 rt_sensitive_local_enqueues;
volatile u64 rt_sensitive_preempts;
volatile u64 hog_containment_enqueues;
volatile u64 hog_recoveries;
volatile u64 tune_reserved_max_ns = FLOW_SLICE_RESERVED_MAX_NS;
volatile u64 tune_shared_slice_ns = FLOW_SLICE_SHARED_NS;
volatile u64 tune_interactive_floor_ns = FLOW_INTERACTIVE_FLOOR_NS;
volatile u64 tune_preempt_budget_min_ns = FLOW_PREEMPT_BUDGET_MIN_NS;
volatile u64 tune_preempt_refill_min_ns = FLOW_PREEMPT_REFILL_MIN_NS;
volatile u64 autotune_generation;
volatile u64 autotune_mode;

#define LATENCY_DSQ 1023
#define RESERVED_DSQ 1024
#define SHARED_DSQ 1025

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
	tctx->hog_score = 0;
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
	u32 hog_decay = FLOW_HOG_SCORE_DECAY_STEP;

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
		if (refill_ns >= (s64)FLOW_INTERACTIVE_FLOOR_MIN_NS)
			hog_decay = FLOW_HOG_SCORE_INTERACTIVE_DECAY_STEP;
		decay_hog_score(tctx, hog_decay);
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

static __always_inline bool is_latency_lane_wakeup(const struct task_ctx *tctx,
						   bool is_wakeup)
{
	u64 interactive_floor_ns = tune_interactive_floor_ns;

	if (!tctx || !is_wakeup || tctx->budget_ns <= 0 || tctx->last_refill_ns <= 0)
		return false;
	if (is_contained_hog(tctx))
		return false;

	if (interactive_floor_ns < FLOW_INTERACTIVE_FLOOR_MIN_NS)
		interactive_floor_ns = FLOW_INTERACTIVE_FLOOR_MIN_NS;
	else if (interactive_floor_ns > FLOW_INTERACTIVE_FLOOR_MAX_NS)
		interactive_floor_ns = FLOW_INTERACTIVE_FLOOR_MAX_NS;

	return tctx->last_refill_ns >= (s64)interactive_floor_ns;
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

	ret = scx_bpf_create_dsq(RESERVED_DSQ, -1);
	if (ret < 0 && ret != -EEXIST) {
		scx_bpf_error("failed to create reserved DSQ %d: %d", RESERVED_DSQ, ret);
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
	bool latency_lane_wakeup = false;
	bool contained_hog = false;
	bool use_local_reserved = false;

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
			if (is_wakeup)
				__sync_fetch_and_add(&positive_budget_wakeups, 1);
			rt_sensitive_wakeup = is_rt_sensitive_wakeup(p, tctx, is_wakeup);
			if (rt_sensitive_wakeup)
				__sync_fetch_and_add(&rt_sensitive_wakeups, 1);
			latency_lane_wakeup = is_latency_lane_wakeup(tctx, is_wakeup);

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
					(tctx->wake_cpu_idle && is_wakeup);

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

					scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | target_cpu,
							   local_slice_ns, enq_flags);
					__sync_fetch_and_add(&reserved_local_enqueues, 1);
					if (rt_sensitive_wakeup)
						__sync_fetch_and_add(&rt_sensitive_local_enqueues, 1);
					if (tctx->wake_cpu_idle)
						__sync_fetch_and_add(&local_fast_dispatches, 1);
					clear_wake_target(tctx);
					return;
				}
			}

			if (contained_hog)
				__sync_fetch_and_add(&hog_containment_enqueues, 1);

			if (latency_lane_wakeup) {
				scx_bpf_dsq_insert(p, LATENCY_DSQ, slice_ns, enq_flags);
				__sync_fetch_and_add(&latency_lane_enqueues, 1);
				if (has_wake_target && (is_wakeup || !scx_bpf_task_running(p)))
					scx_bpf_kick_cpu(target_cpu, SCX_KICK_IDLE);
				clear_wake_target(tctx);
				return;
			}

			scx_bpf_dsq_insert(p, RESERVED_DSQ, slice_ns, enq_flags);
			__sync_fetch_and_add(&reserved_global_enqueues, 1);
			if (has_wake_target && (is_wakeup || !scx_bpf_task_running(p)))
				scx_bpf_kick_cpu(target_cpu, SCX_KICK_IDLE);
			clear_wake_target(tctx);
			return;
		}
	}

	if (tctx && is_contained_hog(tctx))
		__sync_fetch_and_add(&hog_containment_enqueues, 1);

	if (is_wakeup)
		__sync_fetch_and_add(&shared_wakeup_enqueues, 1);

	scx_bpf_dsq_insert(p, SHARED_DSQ, slice_ns, enq_flags);
	clear_wake_target(tctx);
}

void BPF_STRUCT_OPS(flow_dispatch, s32 cpu, struct task_struct *prev)
{
	struct task_ctx *tctx;

	if (move_to_local_compat(LATENCY_DSQ)) {
		__sync_fetch_and_add(&latency_dispatches, 1);
		return;
	}

	if (move_to_local_compat(RESERVED_DSQ)) {
		__sync_fetch_and_add(&reserved_dispatches, 1);
		return;
	}

	if (move_to_local_compat(SHARED_DSQ)) {
		__sync_fetch_and_add(&shared_dispatches, 1);
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
		if (tctx->last_cpu >= 0 && tctx->last_cpu != current_cpu)
			__sync_fetch_and_add(&cpu_migrations, 1);
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
			raise_hog_score(tctx, 1);

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
