/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2025 Andrea Righi <arighi@nvidia.com>
 */
#include <scx/common.bpf.h>
#include "intf.h"

/*
 * Maximum amount of CPUs supported by the scheduler when flat or preferred
 * idle CPU scan is enabled.
 */
#define MAX_CPUS	1024

/*
 * Shared DSQ used to schedule tasks in deadline mode when the system is
 * saturated.
 *
 * When system is not saturated tasks will be dispatched to the local DSQ
 * in round-robin mode.
 */
#define SHARED_DSQ		0

/*
 * Thresholds for applying hysteresis to CPU performance scaling:
 *  - CPUFREQ_LOW_THRESH: below this level, reduce performance to minimum
 *  - CPUFREQ_HIGH_THRESH: above this level, raise performance to maximum
 *
 * Values between the two thresholds retain the current smoothed performance level.
 */
#define CPUFREQ_LOW_THRESH	(SCX_CPUPERF_ONE / 4)
#define CPUFREQ_HIGH_THRESH	(SCX_CPUPERF_ONE - SCX_CPUPERF_ONE / 4)

/*
 * Subset of CPUs to prioritize.
 */
private(COSMOS) struct bpf_cpumask __kptr *primary_cpumask;

/*
 * Set to true when @primary_cpumask is empty (primary domain includes all
 * the CPU).
 */
const volatile bool primary_all = true;

/*
 * Enable flat iteration to find idle CPUs (fast but inaccurate).
 */
const volatile bool flat_idle_scan = false;

/*
 * CPUs in the system have SMT is enabled.
 */
const volatile bool smt_enabled = true;

/*
 * Enable preferred cores prioritization.
 */
const volatile bool preferred_idle_scan = false;

/*
 * CPUs sorted by their capacity in descendent order.
 */
const volatile u64 preferred_cpus[MAX_CPUS];

/*
 * Enable cpufreq integration.
 */
const volatile bool cpufreq_enabled = true;

/*
 * Enable NUMA optimizatons.
 */
const volatile bool numa_enabled;

/*
 * Aggressively try to avoid SMT contention.
 *
 * Default to true here, so veristat takes the more complicated path.
 */
const volatile bool avoid_smt = true;

/*
 * Enable address space affinity.
 */
const volatile bool mm_affinity;

/*
 * Enable deferred wakeup.
 */
const volatile bool deferred_wakeups = true;

/*
 * Ignore synchronous wakeup events.
 */
const volatile bool no_wake_sync;

/*
 * Default time slice.
 */
const volatile u64 slice_ns = 10000ULL;

/*
 * Maximum runtime that can be charged to a task.
 */
const volatile u64 slice_lag = 20000000ULL;

/*
 * User CPU utilization threshold to determine when the system is busy.
 */
const volatile u64 busy_threshold;

/*
 * Current global CPU utilization percentage in the range [0 .. 1024].
 */
volatile u64 cpu_util;

char _license[] SEC("license") = "GPL";

/*
 * Scheduler's exit status.
 */
UEI_DEFINE(uei);

/*
 * Maximum amount of CPUs supported by the system.
 */
static u64 nr_cpu_ids;

/*
 * Current system vruntime.
 */
static u64 vtime_now;

/*
 * Per-task context.
 */
struct task_ctx {
	u64 last_run_at;
	u64 exec_runtime;
	u64 wakeup_freq;
	u64 last_woke_at;
};

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct task_ctx);
} task_ctx_stor SEC(".maps");

/*
 * Return a local task context from a generic task.
 */
struct task_ctx *try_lookup_task_ctx(const struct task_struct *p)
{
	return bpf_task_storage_get(&task_ctx_stor,
					(struct task_struct *)p, 0, 0);
}

/*
 * Per-CPU context.
 */
struct cpu_ctx {
	u64 last_update;
	u64 perf_lvl;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, u32);
	__type(value, struct cpu_ctx);
	__uint(max_entries, 1);
} cpu_ctx_stor SEC(".maps");

/*
 * Return a CPU context.
 */
struct cpu_ctx *try_lookup_cpu_ctx(s32 cpu)
{
	const u32 idx = 0;
	return bpf_map_lookup_percpu_elem(&cpu_ctx_stor, &idx, cpu);
}

/*
 * Exponential weighted moving average (EWMA).
 *
 * Copied from scx_lavd. Returns the new average as:
 *
 *	new_avg := (old_avg * .75) + (new_val * .25);
 */
static u64 calc_avg(u64 old_val, u64 new_val)
{
	return (old_val - (old_val >> 2)) + (new_val >> 2);
}

/*
 * Update the average frequency of an event.
 *
 * The frequency is computed from the given interval since the last event
 * and combined with the previous frequency using an exponential weighted
 * moving average.
 */
static u64 update_freq(u64 freq, u64 interval)
{
        u64 new_freq;

        new_freq = (100 * NSEC_PER_MSEC) / interval;
        return calc_avg(freq, new_freq);
}

/*
 * Update CPU load and scale target performance level accordingly.
 */
static void update_cpu_load(struct task_struct *p, u64 slice)
{
	u64 now = scx_bpf_now();
	s32 cpu = scx_bpf_task_cpu(p);
	u64 perf_lvl, delta_t;
	struct cpu_ctx *cctx;

	if (!cpufreq_enabled)
		return;

	cctx = try_lookup_cpu_ctx(cpu);
	if (!cctx)
		return;

	/*
	 * Evaluate dynamic cpuperf scaling factor using the average CPU
	 * utilization, normalized in the range [0 .. SCX_CPUPERF_ONE].
	 */
	delta_t = now - cctx->last_update;
	if (!delta_t)
		return;

	/*
	 * Refresh target performance level.
	 */
	perf_lvl = MIN(slice * SCX_CPUPERF_ONE / delta_t, SCX_CPUPERF_ONE);
	cctx->perf_lvl = calc_avg(cctx->perf_lvl, perf_lvl);
	cctx->last_update = now;
}

/*
 * Apply target cpufreq performance level to @cpu.
 */
static void update_cpufreq(s32 cpu)
{
	struct cpu_ctx *cctx;
	u64 perf_lvl;

	if (!cpufreq_enabled)
		return;

	cctx = try_lookup_cpu_ctx(cpu);
	if (!cctx)
		return;

	/*
	 * Apply target performance level to the cpufreq governor.
	 */
	if (cctx->perf_lvl >= CPUFREQ_HIGH_THRESH)
		perf_lvl = SCX_CPUPERF_ONE;
	else if (cctx->perf_lvl <= CPUFREQ_LOW_THRESH)
		perf_lvl = SCX_CPUPERF_ONE / 2;
	else
		perf_lvl = cctx->perf_lvl;

	scx_bpf_cpuperf_set(cpu, perf_lvl);
}

/*
 * Timer used to defer idle CPU wakeups.
 *
 * Instead of triggering wake-up events directly from hot paths, such as
 * ops.enqueue(), idle CPUs are kicked using the wake-up timer.
 */
struct wakeup_timer {
	struct bpf_timer timer;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct wakeup_timer);
} wakeup_timer SEC(".maps");

/*
 * Return the global system shared DSQ.
 */
static inline u64 shared_dsq(s32 cpu)
{
	return numa_enabled ? __COMPAT_scx_bpf_cpu_node(cpu) : SHARED_DSQ;
}

/*
 * Return true if @p can only run on a single CPU, false otherwise.
 */
static inline bool is_pcpu_task(const struct task_struct *p)
{
	return p->nr_cpus_allowed == 1 || is_migration_disabled(p);
}

/*
 * Return true if the system is busy, false otherwise.
 *
 * This function determines when the scheduler needs to switch to
 * deadline-mode (using a shared DSQ) vs round-robin mode (using per-CPU
 * local DSQs).
 */
static inline bool is_system_busy(void)
{
	return cpu_util >= busy_threshold;
}

/*
 * Return the cpumask of fully idle SMT cores within the NUMA node that
 * contains @cpu.
 *
 * If NUMA support is disabled, @cpu is ignored.
 */
static inline const struct cpumask *get_idle_smtmask(s32 cpu)
{
	if (!numa_enabled)
		return scx_bpf_get_idle_smtmask();

	return __COMPAT_scx_bpf_get_idle_smtmask_node(__COMPAT_scx_bpf_cpu_node(cpu));
}

/*
 * Return true if the CPU is running the idle thread, false otherwise.
 */
static inline bool is_cpu_idle(s32 cpu)
{
	struct rq *rq = scx_bpf_cpu_rq(cpu);

	if (!rq) {
		scx_bpf_error("Failed to access rq %d", cpu);
		return false;
	}
	return rq->curr->flags & PF_IDLE;
}

/*
 * Try to pick the best idle CPU based on the @preferred_cpus ranking.
 * Return a full-idle SMT core if @do_idle_smt is true, or any idle CPU if
 * @do_idle_smt is false.
 */
static s32 pick_idle_cpu_pref_smt(struct task_struct *p, s32 prev_cpu, bool is_prev_allowed,
				  const struct cpumask *primary, const struct cpumask *smt)
{
	static u32 last_cpu;
	u64 max_cpus = MIN(nr_cpu_ids, MAX_CPUS);
	int i, start;

	if (is_prev_allowed &&
	    (!primary || bpf_cpumask_test_cpu(prev_cpu, primary)) &&
	    (!smt || bpf_cpumask_test_cpu(prev_cpu, smt)) &&
	    scx_bpf_test_and_clear_cpu_idle(prev_cpu))
		return prev_cpu;

	start = last_cpu;
	bpf_for(i, 0, max_cpus) {
		/*
		 * If @preferred_idle_scan is true, always scan the CPUs in
		 * the preferred order, otherwise rotate the CPUs to
		 * distribute the load more evenly.
		 */
		s32 cpu = preferred_idle_scan ?
				preferred_cpus[i] : (start + i) % max_cpus;

		if ((cpu == prev_cpu) || !bpf_cpumask_test_cpu(cpu, p->cpus_ptr))
			continue;

		if ((!primary || bpf_cpumask_test_cpu(cpu, primary)) &&
		    (!smt || bpf_cpumask_test_cpu(cpu, smt)) &&
		    scx_bpf_test_and_clear_cpu_idle(cpu)) {
			if (!preferred_idle_scan)
				last_cpu = cpu + 1;
			return cpu;
		}
	}

	return -EBUSY;
}

/*
 * Return the optimal idle CPU for task @p or -EBUSY if no idle CPU is
 * found.
 */
static s32 pick_idle_cpu_flat(struct task_struct *p, s32 prev_cpu)
{
	const struct cpumask *smt, *primary;
	bool is_prev_allowed = bpf_cpumask_test_cpu(prev_cpu, p->cpus_ptr);
	s32 cpu;

	primary = !primary_all ? cast_mask(primary_cpumask) : NULL;
	smt = smt_enabled ? get_idle_smtmask(prev_cpu) : NULL;

	/*
	 * If the task can't migrate, there's no point looking for other
	 * CPUs.
	 */
	if (p->nr_cpus_allowed == 1 || is_migration_disabled(p)) {
		if (scx_bpf_test_and_clear_cpu_idle(prev_cpu)) {
			cpu = prev_cpu;
			goto out;
		}
	}

	if (!primary_all) {
		if (smt_enabled) {
			/*
			 * Try to pick a full-idle core in the primary
			 * domain.
			 */
			cpu = pick_idle_cpu_pref_smt(p, prev_cpu, is_prev_allowed, primary, smt);
			if (cpu >= 0)
				goto out;
		}

		/*
		 * Try to pick any idle CPU in the primary domain.
		 */
		cpu = pick_idle_cpu_pref_smt(p, prev_cpu, is_prev_allowed, primary, NULL);
		if (cpu >= 0)
			goto out;
	}

	if (smt_enabled) {
		/*
		 * Try to pick any full-idle core in the system.
		 */
		cpu = pick_idle_cpu_pref_smt(p, prev_cpu, is_prev_allowed, NULL, smt);
		if (cpu >= 0)
			goto out;
	}

	/*
	 * Try to pick any idle CPU in the system.
	 */
	cpu = pick_idle_cpu_pref_smt(p, prev_cpu, is_prev_allowed, NULL, NULL);

out:
	if (smt)
		scx_bpf_put_cpumask(smt);

	return cpu;
}

/*
 * Pick an optimal idle CPU for task @p (as close as possible to
 * @prev_cpu).
 *
 * Return the CPU id or a negative value if an idle CPU can't be found.
 */
static s32 pick_idle_cpu(struct task_struct *p, s32 prev_cpu, u64 wake_flags, bool from_enqueue)
{
	const struct cpumask *mask = cast_mask(primary_cpumask);
	s32 cpu;

	/*
	 * Use lightweight idle CPU scanning when flat or preferred idle
	 * scan is enabled, unless the system is busy, in which case the
	 * cpumask-based scanning is more efficient.
	 */
	if ((flat_idle_scan || preferred_idle_scan) && !is_system_busy())
		return pick_idle_cpu_flat(p, prev_cpu);

	/*
	 * Clear the wake sync bit if synchronous wakeups are disabled.
	 */
	if (no_wake_sync)
		wake_flags &= ~SCX_WAKE_SYNC;

	/*
	 * Fallback to the old API if the kernel doesn't support
	 * scx_bpf_select_cpu_and().
	 *
	 * This is required to support kernels <= 6.16.
	 */
	if (!bpf_ksym_exists(scx_bpf_select_cpu_and)) {
		bool is_idle = false;

		if (from_enqueue)
			return -EBUSY;

		cpu = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle);

		return is_idle ? cpu : -EBUSY;
	}

	/*
	 * If a primary domain is defined, try to pick an idle CPU from
	 * there first.
	 */
	if (!primary_all && mask) {
		cpu = scx_bpf_select_cpu_and(p, prev_cpu, wake_flags, mask,
					     avoid_smt ? SCX_PICK_IDLE_CORE : 0);
		if (cpu >= 0)
			return cpu;
	}

	/*
	 * Pick any idle CPU usable by the task.
	 */
	return scx_bpf_select_cpu_and(p, prev_cpu, wake_flags, p->cpus_ptr, 0);
}

/*
 * Return a time slice scaled by the task's weight.
 */
static u64 task_slice(const struct task_struct *p)
{
	return scale_by_task_weight(p, slice_ns);
}

/*
 * Calculate and return the virtual deadline for the given task.
 *
 *  The deadline is defined as:
 *
 *    deadline = vruntime + exec_vruntime
 *
 * Here, `vruntime` represents the task's total accumulated runtime,
 * inversely scaled by its weight, while `exec_vruntime` accounts the
 * runtime accumulated since the last sleep event, also inversely scaled by
 * the task's weight.
 *
 * Fairness is driven by `vruntime`, while `exec_vruntime` helps prioritize
 * tasks that sleep frequently and use the CPU in short bursts (resulting
 * in a small `exec_vruntime` value), which are typically latency critical.
 *
 * Additionally, to prevent over-prioritizing tasks that sleep for long
 * periods of time, the vruntime credit they can accumulate while sleeping
 * is limited by @slice_lag, which is also scaled based on the task's
 * weight.
 *
 * To prioritize tasks that sleep frequently over those with long sleep
 * intervals, @slice_lag is also adjusted in function of the task's wakeup
 * frequency: tasks that sleep often have a bigger slice lag, allowing them
 * to accumulate more time-slice credit than tasks with infrequent, long
 * sleeps.
 */
static u64 task_dl(struct task_struct *p, struct task_ctx *tctx)
{
	u64 lag_scale = MAX(tctx->wakeup_freq, 1);
	u64 vsleep_max = scale_by_task_weight(p, slice_lag * lag_scale);
	u64 vtime_min = vtime_now - vsleep_max;

	if (time_before(p->scx.dsq_vtime, vtime_min))
		p->scx.dsq_vtime = vtime_min;

	return p->scx.dsq_vtime + scale_by_task_weight_inverse(p, tctx->exec_runtime);
}

/*
 * Initialize a new cpumask, return 0 in case of success or a negative
 * value otherwise.
 */
static int init_cpumask(struct bpf_cpumask **p_cpumask)
{
	struct bpf_cpumask *mask;

	mask = *p_cpumask;
	if (mask)
		return 0;

	mask = bpf_cpumask_create();
	if (!mask)
		return -ENOMEM;

	mask = bpf_kptr_xchg(p_cpumask, mask);
	if (mask)
		bpf_cpumask_release(mask);

	return *p_cpumask ? 0 : -ENOMEM;
}

/*
 * Called from user-space to add CPUs to the the primary domain.
 */
SEC("syscall")
int enable_primary_cpu(struct cpu_arg *input)
{
	struct bpf_cpumask *mask;
	int err = 0;

	err = init_cpumask(&primary_cpumask);
	if (err)
		return err;

	bpf_rcu_read_lock();
	mask = primary_cpumask;
	if (mask)
		bpf_cpumask_set_cpu(input->cpu_id, mask);
	bpf_rcu_read_unlock();

	return err;
}

/*
 * Kick idle CPUs with pending tasks.
 *
 * Instead of waking up CPU when tasks are enqueued, we defer the wakeup
 * using this timer handler, in order to have a faster enqueue hot path.
 */
static int wakeup_timerfn(void *map, int *key, struct bpf_timer *timer)
{
	s32 cpu;
	int err;

	/*
	 * Iterate over all CPUs and wake up those that have pending tasks
	 * in their local DSQ.
	 *
	 * Note that tasks are only enqueued in ops.enqueue(), but we never
	 * wake-up the CPUs from there to reduce overhead in the hot path.
         */
	bpf_for(cpu, 0, nr_cpu_ids)
		if (scx_bpf_dsq_nr_queued(SCX_DSQ_LOCAL_ON | cpu) && is_cpu_idle(cpu))
			scx_bpf_kick_cpu(cpu, SCX_KICK_IDLE);

	/*
	 * Re-arm the wakeup timer.
	 */
	err = bpf_timer_start(timer, slice_ns, 0);
	if (err)
		scx_bpf_error("Failed to re-arm wakeup timer");

	return 0;
}

/*
 * Return true if the CPU is part of a fully busy SMT core, false
 * otherwise.
 *
 * If SMT is disabled or SMT contention avoidance is disabled, always
 * return false (since there's no SMT contention or it's ignored).
 */
static bool is_smt_contended(s32 cpu)
{
	const struct cpumask *smt;
	bool is_contended;

	if (!smt_enabled || !avoid_smt)
		return false;

	smt = get_idle_smtmask(cpu);
	is_contended = bpf_cpumask_empty(smt);
	scx_bpf_put_cpumask(smt);

	return is_contended;
}

/*
 * Return true if we should attempt a task migration to an idle CPU, false
 * otherwise.
 */
static bool need_migrate(const struct task_struct *p, s32 prev_cpu, u64 enq_flags)
{
	/*
	 * Per-CPU tasks are not allowed to migrate.
	 */
	if (is_pcpu_task(p))
		return false;

	/*
	 * Always attempt to migrate if we're contending an SMT core.
	 */
	if (is_smt_contended(prev_cpu))
		return true;

	/*
	 * Attempt a migration on wakeup (if ops.select_cpu() was skipped)
	 * or if the task was re-enqueued due to a higher scheduling class
	 * stealing the CPU it was queued on.
	 */
	return (!__COMPAT_is_enq_cpu_selected(enq_flags) && !scx_bpf_task_running(p)) ||
	       (enq_flags & SCX_ENQ_REENQ);
}

/*
 * Return true if a task is waking up another task that share the same
 * address space, false otherwise.
 */
static inline bool
is_wake_affine(const struct task_struct *waker, const struct task_struct *wakee)
{
	return mm_affinity &&
		!(waker->flags & PF_EXITING) && wakee->mm && (wakee->mm == waker->mm);
}

s32 BPF_STRUCT_OPS(cosmos_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
	const struct task_struct *current = (void *)bpf_get_current_task_btf();
	bool is_busy = is_system_busy();
	s32 cpu;

	/*
	 * When the waker and wakee share the same address space and were previously
	 * running on the same CPU, there's a high chance of finding hot cache data
	 * on that CPU. In such cases, prefer keeping the wakee on the same CPU.
	 *
	 * This optimization is applied only when the system is not saturated,
	 * to avoid introducing too much unfairness.
	 */
	if (is_wake_affine(current, p) && !is_busy) {
		cpu = bpf_get_smp_processor_id();
		if (cpu == prev_cpu) {
			scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, task_slice(p), 0);
			return cpu;
		}
	}

	/*
	 * Try to find an idle CPU and dispatch the task directly to the
	 * target CPU.
	 *
	 * Since we only use local DSQs, there's no reason to bounce the
	 * task to ops.enqueue(). Dispatching directly from here, even if
	 * we can't find an idle CPU, allows to save some locking overhead.
	 */
	cpu = pick_idle_cpu(p, prev_cpu, wake_flags, false);
	if (cpu >= 0 || !is_busy)
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, task_slice(p), 0);

	return cpu >= 0 ? cpu : prev_cpu;
}

/*
 * Wake-up @cpu if it's idle.
 */
static inline void wakeup_cpu(s32 cpu)
{
	/*
	 * If deferred wakeups are enabled all the wakeup events are
	 * performed asynchronously by wakeup_timerfn().
	 */
	if (deferred_wakeups)
		return;
	scx_bpf_kick_cpu(cpu, SCX_KICK_IDLE);
}

void BPF_STRUCT_OPS(cosmos_enqueue, struct task_struct *p, u64 enq_flags)
{
	s32 prev_cpu = scx_bpf_task_cpu(p), cpu;
	struct task_ctx *tctx;

	/*
	 * Attempt to dispatch directly to an idle CPU if the task can
	 * migrate.
	 */
	if (need_migrate(p, prev_cpu, enq_flags)) {
		cpu = pick_idle_cpu(p, prev_cpu, 0, true);
		if (cpu >= 0) {
			scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | cpu, task_slice(p), enq_flags);
			wakeup_cpu(cpu);
			return;
		}
	}

	/*
	 * Keep using the same CPU if the system is not busy, otherwise
	 * fallback to the shared DSQ.
	 */
	if (!is_system_busy()) {
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, task_slice(p), enq_flags);
		wakeup_cpu(prev_cpu);
		return;
	}

	/*
	 * Dispatch the task to the shared DSQ, using the deadline-based
	 * scheduling.
	 */
	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return;
	scx_bpf_dsq_insert_vtime(p, shared_dsq(prev_cpu),
				 task_slice(p), task_dl(p, tctx), enq_flags);
	wakeup_cpu(prev_cpu);
}

void BPF_STRUCT_OPS(cosmos_dispatch, s32 cpu, struct task_struct *prev)
{
	/*
	 * Check if the there's any task waiting in the shared DSQ and
	 * dispatch.
	 */
	if (scx_bpf_dsq_move_to_local(shared_dsq(cpu)))
		return;

	/*
	 * If the previous task expired its time slice, but no other task
	 * wants to run on this SMT core, allow the previous task to run
	 * for another time slot.
	 */
	if (prev && (prev->scx.flags & SCX_TASK_QUEUED) && !is_smt_contended(cpu))
		prev->scx.slice = task_slice(prev);
}

void BPF_STRUCT_OPS(cosmos_cpu_release, s32 cpu, struct scx_cpu_release_args *args)
{
	/*
	 * A higher scheduler class stole the CPU, re-enqueue all the tasks
	 * that are waiting on this CPU and give them a chance to pick
	 * another idle CPU.
	 */
	scx_bpf_reenqueue_local();
}

void BPF_STRUCT_OPS(cosmos_runnable, struct task_struct *p, u64 enq_flags)
{
	u64 now = scx_bpf_now(), delta_t;
	struct task_ctx *tctx;

	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return;

	/*
	 * Reset exec runtime (accumulated execution time since last
	 * sleep).
	 */
	tctx->exec_runtime = 0;

	/*
	 * Update the task's wakeup frequency based on the time since
	 * the last wakeup, then cap the result at 1024 to avoid large
	 * spikes.
	 */
	delta_t = now - tctx->last_woke_at;
	tctx->wakeup_freq = update_freq(tctx->wakeup_freq, delta_t);
	tctx->wakeup_freq = MIN(tctx->wakeup_freq, 1024);
	tctx->last_woke_at = now;
}

void BPF_STRUCT_OPS(cosmos_running, struct task_struct *p)
{
	struct task_ctx *tctx;

	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return;

	/*
	 * Save a timestamp when the task begins to run (used to evaluate
	 * the used time slice).
	 */
	tctx->last_run_at = scx_bpf_now();

	/*
	 * Update current system's vruntime.
	 */
	if (time_before(vtime_now, p->scx.dsq_vtime))
		vtime_now = p->scx.dsq_vtime;

	/*
	 * Refresh cpufreq performance level.
	 */
	update_cpufreq(scx_bpf_task_cpu(p));
}

void BPF_STRUCT_OPS(cosmos_stopping, struct task_struct *p, bool runnable)
{
	struct task_ctx *tctx;
	u64 slice;

	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return;

	/*
	 * Evaluate the used time slice.
	 */
	slice = MIN(scx_bpf_now() - tctx->last_run_at, slice_ns);

	/*
	 * Update the vruntime and the total accumulated runtime since last
	 * sleep.
	 *
	 * Cap the maximum accumulated time since last sleep to @slice_lag,
	 * to prevent starving CPU-intensive tasks.
	 */
	p->scx.dsq_vtime += scale_by_task_weight_inverse(p, slice);
	tctx->exec_runtime = MIN(tctx->exec_runtime + slice, slice_lag);

	/*
	 * Update per-CPU statistics.
	 */
	update_cpu_load(p, slice);
}

void BPF_STRUCT_OPS(cosmos_enable, struct task_struct *p)
{
	p->scx.dsq_vtime = vtime_now;
}

s32 BPF_STRUCT_OPS(cosmos_init_task, struct task_struct *p,
		   struct scx_init_task_args *args)
{
	struct task_ctx *tctx;

	tctx = bpf_task_storage_get(&task_ctx_stor, p, 0,
				    BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!tctx)
		return -ENOMEM;

	return 0;
}

s32 BPF_STRUCT_OPS_SLEEPABLE(cosmos_init)
{
	struct bpf_timer *timer;
	u32 key = 0;
	int err;

	nr_cpu_ids = scx_bpf_nr_cpu_ids();

	/*
	 * Create separate per-node DSQs if NUMA optimization is enabled,
	 * otherwise use a single shared DSQ.
	 */
	if (numa_enabled) {
		int node;

		bpf_for(node, 0, __COMPAT_scx_bpf_nr_node_ids()) {
			err = scx_bpf_create_dsq(node, node);
			if (err) {
				scx_bpf_error("failed to create node DSQ %d: %d", node, err);
				return err;
			}
		}
	} else {
		err = scx_bpf_create_dsq(SHARED_DSQ, -1);
		if (err) {
			scx_bpf_error("failed to create shared DSQ: %d", err);
			return err;
		}
	}

	if (deferred_wakeups) {
		timer = bpf_map_lookup_elem(&wakeup_timer, &key);
		if (!timer) {
			scx_bpf_error("Failed to lookup wakeup timer");
			return -ESRCH;
		}

		bpf_timer_init(timer, &wakeup_timer, CLOCK_MONOTONIC);
		bpf_timer_set_callback(timer, wakeup_timerfn);

		err = bpf_timer_start(timer, slice_ns, 0);
		if (err) {
			scx_bpf_error("Failed to arm wakeup timer");
			return err;
		}
	}

	return 0;
}

void BPF_STRUCT_OPS(cosmos_exit, struct scx_exit_info *ei)
{
	UEI_RECORD(uei, ei);
}

SCX_OPS_DEFINE(cosmos_ops,
	       .select_cpu		= (void *)cosmos_select_cpu,
	       .enqueue			= (void *)cosmos_enqueue,
	       .dispatch		= (void *)cosmos_dispatch,
	       .runnable		= (void *)cosmos_runnable,
	       .running			= (void *)cosmos_running,
	       .stopping		= (void *)cosmos_stopping,
	       .cpu_release		= (void *)cosmos_cpu_release,
	       .enable			= (void *)cosmos_enable,
	       .init_task		= (void *)cosmos_init_task,
	       .init			= (void *)cosmos_init,
	       .exit			= (void *)cosmos_exit,
	       .timeout_ms		= 5000,
	       .name			= "cosmos");
