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
	s32 last_cpu;
	s32 wake_cpu;
	bool wake_cpu_idle;
	bool wake_cpu_valid;
	bool first_run;
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
volatile u64 prio_dispatches;
volatile u64 normal_dispatches;
volatile u64 budget_refill_events;
volatile u64 budget_exhaustions;
volatile u64 runnable_wakeups;
volatile u64 cpu_release_reenqueues;
volatile u64 init_task_events;
volatile u64 enable_events;
volatile u64 exit_task_events;
volatile u64 cpu_migrations;
volatile u64 tune_reserved_max_ns = FLOW_SLICE_RESERVED_MAX_NS;
volatile u64 tune_shared_slice_ns = FLOW_SLICE_SHARED_NS;
volatile u64 tune_interactive_floor_ns = FLOW_INTERACTIVE_FLOOR_NS;
volatile u64 autotune_generation;
volatile u64 autotune_mode;

static u64 nr_cpu_ids;

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

		/* Floor at tune_shared_slice_ns for tiny budgets.  The wakeup
		 * path overrides to FLOW_SLICE_MIN_NS independently of this
		 * function, so this only affects re-enqueues in the normal
		 * DSQ, where a 50 us slice would cause excessive context
		 * switching on workloads such as hackbench. */
		if (budget_ns < FLOW_SLICE_MIN_NS)
			return tune_shared_slice_ns;
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

static __always_inline bool valid_sched_cpu(s32 cpu)
{
	return cpu >= 0 && (u64)cpu < nr_cpu_ids;
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

	tctx->budget_ns = FLOW_BUDGET_TIER_NS;
	tctx->last_refill_ns = 0;
	tctx->last_run_at = 0;
	tctx->last_sleep_ns = 0;
	tctx->sleep_started_at = sleeping ? now : 0;
	tctx->last_cpu = -1;
	tctx->first_run = true;
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

static __always_inline void update_budget_on_wakeup(const struct task_struct *p,
						    struct task_ctx *tctx,
						    u64 now)
{
	s64 refill_ns;
	u64 sleep_ns;

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

	if (refill_ns > 0)
		__sync_fetch_and_add(&budget_refill_events, 1);
}

s32 BPF_STRUCT_OPS_SLEEPABLE(flow_init)
{
	s32 ret;

	nr_cpu_ids = scx_bpf_nr_cpu_ids();

	/* High-priority vtime DSQ for tasks with budget > FLOW_BUDGET_TIER_NS.
	 * Low-priority vtime DSQ for tasks with budget <= FLOW_BUDGET_TIER_NS.
	 * The tier boundary at 50 us separates interactive tasks (longer
	 * sleep, higher budget) from bulk workers (brief sleep, low budget),
	 * giving the former priority at dispatch time without requiring
	 * heuristic classification.  Wakeup tasks bypass both and use the
	 * built-in FLOW_DSQ_LOCAL_ON mechanism. */
	ret = scx_bpf_create_dsq(FLOW_NORMAL_HIGH_DSQ, -1);
	if (ret < 0 && ret != -EEXIST) {
		scx_bpf_error("failed to create High DSQ: %d", ret);
		return ret;
	}

	ret = scx_bpf_create_dsq(FLOW_NORMAL_LOW_DSQ, -1);
	if (ret < 0 && ret != -EEXIST) {
		scx_bpf_error("failed to create Low DSQ: %d", ret);
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
	    bpf_cpumask_test_cpu(tctx->last_cpu, p->cpus_ptr))
		preferred_cpu = tctx->last_cpu;

	if (non_migratable) {
		cpu = preferred_cpu;
		is_idle = scx_bpf_test_and_clear_cpu_idle(preferred_cpu);
	} else if (tctx && tctx->first_run) {
		/* First-run task: prefer idle core, then any idle CPU, then default. */
		cpu = scx_bpf_pick_idle_cpu(p->cpus_ptr, FLOW_PICK_IDLE_CORE);
		if (cpu < 0)
			cpu = scx_bpf_pick_idle_cpu(p->cpus_ptr, 0);
		if (cpu >= 0)
			is_idle = true;
		else
			cpu = scx_bpf_select_cpu_dfl(p, preferred_cpu, wake_flags, &is_idle);
	} else {
		cpu = scx_bpf_select_cpu_dfl(p, preferred_cpu, wake_flags, &is_idle);
	}

	if (tctx) {
		tctx->wake_cpu = cpu >= 0 ? cpu : preferred_cpu;
		tctx->wake_cpu_idle = is_idle;
		tctx->wake_cpu_valid =
			tctx->wake_cpu >= 0 &&
			bpf_cpumask_test_cpu(tctx->wake_cpu, p->cpus_ptr);
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
	s32 target_cpu = -1;
	s32 task_cpu;
	u64 slice_ns;
	bool is_wakeup;
	bool has_wake_target = false;

	tctx = lookup_task_ctx(p);
	slice_ns = task_slice_ns(tctx);
	is_wakeup = enq_flags & FLOW_ENQ_WAKEUP;

	if (tctx && tctx->wake_cpu_valid) {
		target_cpu = tctx->wake_cpu;
		has_wake_target = true;
	}

	task_cpu = scx_bpf_task_cpu(p);
	if (is_non_migratable(p) && task_cpu >= 0 &&
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
		scx_bpf_dsq_insert(p, FLOW_DSQ_LOCAL, task_slice_ns(NULL), enq_flags);
		return;
	}

	/*
	 * Two-lane dispatch:
	 *   Priority lane (per-CPU FIFO, SCX_ENQ_HEAD): wakeup tasks
	 *   Normal lane (global vtime): all other tasks
	 *
	 * Wakeup tasks are inserted to their target CPU's priority DSQ
	 * with SCX_ENQ_HEAD (front of queue).  Only wakeups with sufficient
	 * budget (≥ FLOW_BUDGET_TIER_NS) set SCX_ENQ_PREEMPT, requesting
	 * the kernel to preempt the currently running task on the target
	 * CPU.  This gives interactive tasks (cyclictest, audio) immediate
	 * dispatch while preventing bulk workers (hackbench) from causing
	 * unnecessary preemption spikes on the target CPU.
	 *
	 * The cpufreq hint (scx_bpf_cpuperf_set) is set on the target CPU
	 * to request an immediate frequency ramp — the kernel's PELT signal
	 * takes ~32ms to respond, so an explicit hint on each latency-
	 * sensitive scheduling event eliminates frequency-ramp tail latency.
	 */
	if (is_wakeup && has_wake_target && valid_sched_cpu(target_cpu)) {
		u64 wake_enq_flags;
		/* Fixed 50 µs slice for all wakeup tasks.  Keeping the slice
		 * at the minimum bounds worst-case latency: a wakeup task
		 * holds the CPU for at most 50 µs before yielding, which
		 * limits how long other wakeups for the same CPU must wait.
		 * Larger budget-derived slices were tested but regressed
		 * max latency (505 µs → 653 µs) and spikes >100 µs (15 → 44)
		 * because a longer-running wakeup delays subsequent arrivals. */
		slice_ns = FLOW_SLICE_MIN_NS;

		/* All wakeups go to the target CPU local DSQ with head-of-
		 * queue priority (FIFO within the local DSQ).  Only wakeups
		 * with budget ≥ FLOW_BUDGET_TIER_NS (50 us) send an IPI to
		 * preempt the currently running task — this matches the
		 * classification that v2.3.0 achieved via its urgent-latency
		 * lane, using the budget signal directly. */
		wake_enq_flags = enq_flags | FLOW_ENQ_HEAD;
		if (tctx && (tctx->first_run ||
			     tctx->budget_ns >= (s64)FLOW_BUDGET_TIER_NS))
			wake_enq_flags |= FLOW_ENQ_PREEMPT;

		scx_bpf_cpuperf_set(target_cpu, SCX_CPUPERF_ONE);
		scx_bpf_dsq_insert(p, FLOW_DSQ_LOCAL_ON | (u32)target_cpu,
				   slice_ns, wake_enq_flags);
		__sync_fetch_and_add(&prio_dispatches, 1);
		clear_wake_target(tctx);
		return;
	}

	/*
	 * Budget-based vtime with budget-tiered DSQs.  Tasks with remaining
	 * budget at or above FLOW_BUDGET_TIER_NS go to the high-priority
	 * DSQ (checked first at dispatch), below it to the low-priority DSQ.
	 * This separates interactive tasks (longer sleep, higher budget)
	 * from bulk workers (brief sleep, low budget) without heuristic
	 * classification — the budget signal itself determines the tier.
	 *
	 * Within each tier, tasks are ordered by vtime so that a task with
	 * more budget is dispatched sooner within its tier.
	 */
	if (tctx) {
		s64 effective_budget = tctx->budget_ns > 0 ? tctx->budget_ns : 0;
		u64 vtime = FLOW_BUDGET_MAX_NS - (u64)effective_budget;
		u64 dsq_id = (u64)effective_budget >= FLOW_BUDGET_TIER_NS
			   ? FLOW_NORMAL_HIGH_DSQ
			   : FLOW_NORMAL_LOW_DSQ;

		scx_bpf_dsq_insert_vtime(p, dsq_id, slice_ns,
					  vtime, enq_flags);
	} else {
		scx_bpf_dsq_insert(p, FLOW_NORMAL_LOW_DSQ, slice_ns, enq_flags);
	}
	clear_wake_target(tctx);
}

void BPF_STRUCT_OPS(flow_dispatch, s32 cpu, struct task_struct *prev)
{
	struct flow_cpu_state *cstate;

	cstate = lookup_cpu_state();
	if (!cstate)
		return;

	/*
	 * Wakeup tasks use FLOW_DSQ_LOCAL_ON which inserts directly to
	 * the target CPU's local DSQ with immediate reschedule.  The
	 * kernel picks them from the local DSQ before calling dispatch.
	 *
	 * This dispatch function handles the Normal lane split into two
	 * budget tiers: high-priority (budget > FLOW_BUDGET_TIER_NS) and
	 * low-priority (budget <= FLOW_BUDGET_TIER_NS).  The high tier is
	 * checked first so interactive tasks (longer sleep, higher budget)
	 * are dispatched before bulk workers.
	 */
	if (scx_bpf_dsq_move_to_local(FLOW_NORMAL_HIGH_DSQ, 0)) {
		FLOW_CPUSTAT_INC(cstate, normal_dispatches);
		return;
	}

	if (scx_bpf_dsq_move_to_local(FLOW_NORMAL_LOW_DSQ, 0)) {
		FLOW_CPUSTAT_INC(cstate, normal_dispatches);
		return;
	}

	/*
	 * Nothing to dispatch.  Re-run @prev if it's still queued.
	 */
	if (!prev || !(prev->scx.flags & SCX_TASK_QUEUED))
		return;

	prev->scx.slice = task_slice_ns(lookup_task_ctx(prev));
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
			FLOW_CPUSTAT_INC(lookup_cpu_state(), cpu_migrations);
		tctx->last_cpu = current_cpu;
		tctx->last_run_at = now;
		tctx->first_run = false;
	}

	__sync_fetch_and_add(&nr_running, 1);
}

void BPF_STRUCT_OPS(flow_stopping, struct task_struct *p, bool runnable)
{
	struct task_ctx *tctx;
	u64 now;
	u64 runtime_ns = 0;

	tctx = lookup_task_ctx(p);
	now = bpf_ktime_get_ns();

	if (tctx) {
		if (tctx->last_run_at && now > tctx->last_run_at)
			runtime_ns = now - tctx->last_run_at;

		if (tctx->budget_ns > 0 &&
		    tctx->budget_ns - (s64)runtime_ns <= 0)
			FLOW_CPUSTAT_INC(lookup_cpu_state(), budget_exhaustions);

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
