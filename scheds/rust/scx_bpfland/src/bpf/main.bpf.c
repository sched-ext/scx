/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2024 Andrea Righi <andrea.righi@linux.dev>
 */
#include <scx/common.bpf.h>
#include <scx/percpu.bpf.h>
#include "intf.h"

/*
 * Maximum time a task can wait in the scheduler's queue before triggering
 * a stall.
 */
#define STARVATION_MS	5000ULL

/*
 * Maximum amount of CPUs supported by the scheduler when flat or preferred
 * idle CPU scan is enabled.
 */
#define MAX_CPUS	1024

/*
 * Maximum rate of task wakeups/sec (tasks with a higher rate are capped to
 * this value).
 *
 * Note that the wakeup rate is evaluate over a period of 100ms, so this
 * number must be multiplied by 10 to determine the actual limit in
 * wakeups/sec.
 */
#define MAX_WAKEUP_FREQ		64ULL

char _license[] SEC("license") = "GPL";

/* Allow to use bpf_printk() only when @debug is set */
#define dbg_msg(_fmt, ...) do {				\
	if (debug)					\
		bpf_printk(_fmt, ##__VA_ARGS__);	\
} while(0)

 /* Report additional debugging information */
const volatile bool debug;

/*
 * Default task time slice.
 */
const volatile u64 slice_max = 1ULL * NSEC_PER_MSEC;

/*
 * Maximum time slice lag.
 *
 * Increasing this value can help to increase the responsiveness of interactive
 * tasks at the cost of making regular and newly created tasks less responsive
 * (0 = disabled).
 */
const volatile u64 slice_lag = 40ULL * NSEC_PER_MSEC;

/*
 * Ignore synchronous wakeup events.
 */
const volatile bool no_wake_sync;

/*
 * Force tasks with a high rate of enqueues/sec to stay on the same CPU
 * to reduce contention on the node DSQs.
 */
const volatile bool sticky_tasks = true;

/*
 * When enabled always dispatch per-CPU kthreads directly.
 *
 * This allows to prioritize critical kernel threads that may potentially slow
 * down the entire system if they are blocked for too long, but it may also
 * introduce interactivity issues or unfairness in scenarios with high kthread
 * activity, such as heavy I/O or network traffic.
 */
const volatile bool local_kthreads = true;

/*
 * Prioritize per-CPU tasks (tasks that can only run on a single CPU).
 *
 * This allows to prioritize per-CPU tasks that usually tend to be
 * de-prioritized (since they can't be migrated when their only usable CPU
 * is busy). Enabling this option can introduce unfairness and potentially
 * trigger stalls, but it can improve performance of server-type workloads
 * (such as large parallel builds).
 */
const volatile bool local_pcpu = true;

/*
 * The CPU frequency performance level: a negative value will not affect the
 * performance level and will be ignored.
 */
volatile s64 cpufreq_perf_lvl;

/*
 * Enable preferred cores prioritization.
 */
const volatile bool preferred_idle_scan;

/*
 * CPUs sorted by their capacity in descendent order.
 */
const volatile u64 preferred_cpus[MAX_CPUS];

/*
 * Cache CPU capacity values.
 */
const volatile u64 cpu_capacity[MAX_CPUS];

/*
 * Scheduling statistics.
 */
volatile u64 nr_kthread_dispatches, nr_direct_dispatches, nr_shared_dispatches;

/*
 * Amount of currently running tasks.
 */
volatile u64 nr_running;

/*
 * Amount of online CPUs.
 */
volatile u64 nr_online_cpus;

/*
 * Maximum possible CPU number.
 */
static u64 nr_cpu_ids;

/*
 * Runtime throttling.
 *
 * Throttle the CPUs by injecting @throttle_ns idle time every @slice_max.
 */
const volatile u64 throttle_ns;
static volatile bool cpus_throttled;

static inline bool is_throttled(void)
{
	return READ_ONCE(cpus_throttled);
}

static inline void set_throttled(bool state)
{
	WRITE_ONCE(cpus_throttled, state);
}

/*
 * Exit information.
 */
UEI_DEFINE(uei);

/*
 * Mask of CPUs that the scheduler can use until the system becomes saturated,
 * at which point tasks may overflow to other available CPUs.
 */
private(BPFLAND) struct bpf_cpumask __kptr *primary_cpumask;

/* Primary domain includes all CPU */
const volatile bool primary_all = true;

/*
 * CPUs in the system have SMT is enabled.
 */
const volatile bool smt_enabled = true;

/*
 * Disable NUMA rebalancing.
 */
const volatile bool numa_enabled = true;

/*
 * Current global vruntime.
 */
static u64 vtime_now;

/*
 * Timer used to inject idle cycles when CPU throttling is enabled.
 */
struct throttle_timer {
	struct bpf_timer timer;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct throttle_timer);
} throttle_timer SEC(".maps");

/*
 * Per-CPU context.
 */
struct cpu_ctx {
	u64 tot_runtime;
	u64 prev_runtime;
	u64 last_running;
	u64 perf_lvl;
	struct bpf_cpumask __kptr *smt;
	struct bpf_cpumask __kptr *l2_cpumask;
	struct bpf_cpumask __kptr *l3_cpumask;
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
 * Per-task local storage.
 *
 * This contain all the per-task information used internally by the BPF code.
 */
struct task_ctx {
	u64 awake_vtime;
	u64 last_run_at;
	u64 wakeup_freq;
	u64 last_woke_at;
	u64 avg_runtime;
};

/* Map that contains task-local storage. */
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
 * Return the DSQ id of the corresponding @cpu.
 */
static inline u64 cpu_dsq(s32 cpu)
{
	return cpu;
}

/*
 * Return the DSQ id of the corresponding @cpu.
 */
static inline u64 node_dsq(s32 cpu)
{
	int node = __COMPAT_scx_bpf_cpu_node(cpu);

	return nr_cpu_ids + node;
}

/*
 * Return true if the target task @p is a kernel thread.
 */
static inline bool is_kthread(const struct task_struct *p)
{
	return p->flags & PF_KTHREAD;
}

/*
 * Return true if @p still wants to run, false otherwise.
 */
static bool is_task_queued(const struct task_struct *p)
{
	return p->scx.flags & SCX_TASK_QUEUED;
}

/*
 * Return true if @p can only run on a single CPU, false otherwise.
 */
static inline bool is_pcpu_task(const struct task_struct *p)
{
	return p->nr_cpus_allowed == 1 || is_migration_disabled(p);
}

/*
 * Return true if @p1's deadline is less than @p2's deadline, false
 * otherwise.
 */
static inline bool
is_deadline_min(const struct task_struct *p1, const struct task_struct *p2)
{
	if (!p1)
		return false;
	if (!p2)
		return true;

	return p1->scx.dsq_vtime < p2->scx.dsq_vtime;
}

/*
 * Return the cpumask of idle CPUs within the NUMA node that contains @cpu.
 *
 * If NUMA support is disabled, @cpu is ignored.
 */
static inline const struct cpumask *get_idle_cpumask(s32 cpu)
{
	if (!numa_enabled)
		return scx_bpf_get_idle_cpumask();

	return __COMPAT_scx_bpf_get_idle_cpumask_node(__COMPAT_scx_bpf_cpu_node(cpu));
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
 * Return true if @cpu is valid, otherwise trigger an error and return
 * false.
 */
static inline bool is_cpu_valid(s32 cpu)
{
	if (cpu < 0 || cpu >= MAX_CPUS) {
		scx_bpf_error("invalid CPU id: %d", cpu);
		return false;
	}
	return true;
}

/*
 * Return true if @this_cpu and @that_cpu are in the same LLC, false
 * otherwise.
 */
static inline bool cpus_share_cache(s32 this_cpu, s32 that_cpu)
{
        if (this_cpu == that_cpu)
                return true;

	if (!is_cpu_valid(this_cpu) || !is_cpu_valid(that_cpu))
		return false;

	return cpu_llc_id(this_cpu) == cpu_llc_id(that_cpu);
}

/*
 * Return true if @this_cpu is faster than @that_cpu, false otherwise.
 */
static inline bool is_cpu_faster(s32 this_cpu, s32 that_cpu)
{
        if (this_cpu == that_cpu)
                return false;

	if (!is_cpu_valid(this_cpu) || !is_cpu_valid(that_cpu))
		return false;

	return cpu_capacity[this_cpu] > cpu_capacity[that_cpu];
}

/*
 * Return the SMT sibling CPU of a @cpu.
 */
static s32 smt_sibling(s32 cpu)
{
	const struct cpumask *smt;
	struct cpu_ctx *cctx;

	cctx = try_lookup_cpu_ctx(cpu);
	if (!cctx)
		return cpu;

	smt = cast_mask(cctx->smt);
	if (!smt)
		return cpu;

	return bpf_cpumask_first(smt);
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
	const struct cpumask *idle_mask;
	bool is_contended;

	if (!smt_enabled)
		return false;

	/*
	 * If the sibling SMT CPU is not idle and there are other full-idle
	 * SMT cores available, consider the current CPU as contended.
	 */
	idle_mask = get_idle_cpumask(cpu);
	is_contended = !bpf_cpumask_test_cpu(smt_sibling(cpu), idle_mask) &&
		       !bpf_cpumask_empty(idle_mask);
	scx_bpf_put_cpumask(idle_mask);

	return is_contended;
}

/*
 * Return true in case of a task wakeup, false otherwise.
 */
static inline bool is_wakeup(u64 wake_flags)
{
	return wake_flags & SCX_WAKE_TTWU;
}

/*
 * Try to pick the best idle CPU based on the @preferred_cpus ranking.
 * Return a full-idle SMT core if @do_idle_smt is true, or any idle CPU if
 * @do_idle_smt is false.
 */
static s32 pick_idle_cpu_pref_smt(struct task_struct *p, s32 prev_cpu, bool is_prev_allowed,
				  const struct cpumask *primary, const struct cpumask *smt)
{
	u64 max_cpus = MIN(nr_cpu_ids, MAX_CPUS);
	int i;

	if (is_prev_allowed &&
	    (!primary || bpf_cpumask_test_cpu(prev_cpu, primary)) &&
	    (!smt || bpf_cpumask_test_cpu(prev_cpu, smt)) &&
	    scx_bpf_test_and_clear_cpu_idle(prev_cpu))
		return prev_cpu;

	bpf_for(i, 0, max_cpus) {
		s32 cpu = preferred_cpus[i];

		if ((cpu == prev_cpu) || !bpf_cpumask_test_cpu(cpu, p->cpus_ptr))
			continue;

		if ((!primary || bpf_cpumask_test_cpu(cpu, primary)) &&
		    (!smt || bpf_cpumask_test_cpu(cpu, smt)) &&
		    scx_bpf_test_and_clear_cpu_idle(cpu))
			return cpu;
	}

	return -EBUSY;
}

/*
 * Return the optimal idle CPU for task @p or -EBUSY if no idle CPU is
 * found.
 */
static s32 pick_idle_cpu_scan(struct task_struct *p, s32 prev_cpu)
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
static s32 pick_idle_cpu(struct task_struct *p, s32 prev_cpu, s32 this_cpu,
			 u64 wake_flags, bool from_enqueue)
{
	const struct cpumask *primary = cast_mask(primary_cpumask);
	s32 cpu;

	/*
	 * Use lightweight idle CPU scanning when flat or preferred idle
	 * scan is enabled, unless the system is busy, in which case the
	 * cpumask-based scanning is more efficient.
	 */
	if (preferred_idle_scan)
		return pick_idle_cpu_scan(p, prev_cpu);

	/*
	 * Clear the wake sync bit if synchronous wakeups are disabled.
	 */
	if (no_wake_sync)
		wake_flags &= ~SCX_WAKE_SYNC;

	/*
	 * On wakeup if the waker's CPU is faster than the wakee's CPU, try
	 * to move the wakee closer to the waker.
	 *
	 * In presence of hybrid cores this helps to naturally migrate
	 * tasks over to the faster cores.
	 */
	if (primary_all && is_wakeup(wake_flags) && this_cpu >= 0 &&
	    is_cpu_faster(this_cpu, prev_cpu)) {
		/*
		 * If both the waker's CPU and the wakee's CPU are in the
		 * same LLC and the wakee's CPU is a fully idle SMT core,
		 * don't migrate.
		 */
		if (cpus_share_cache(this_cpu, prev_cpu) &&
		    !is_smt_contended(prev_cpu) &&
		    scx_bpf_test_and_clear_cpu_idle(prev_cpu))
			return prev_cpu;

		prev_cpu = this_cpu;
	}

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
	if (!primary_all && primary) {
		cpu = scx_bpf_select_cpu_and(p, prev_cpu, wake_flags, primary, 0);
		if (cpu >= 0)
			return cpu;
	}

	/*
	 * Pick any idle CPU usable by the task.
	 */
	return scx_bpf_select_cpu_and(p, prev_cpu, wake_flags, p->cpus_ptr, 0);
}

/*
 * Allocate/re-allocate a new cpumask.
 */
static int calloc_cpumask(struct bpf_cpumask **p_cpumask)
{
	struct bpf_cpumask *cpumask;

	cpumask = bpf_cpumask_create();
	if (!cpumask)
		return -ENOMEM;

	cpumask = bpf_kptr_xchg(p_cpumask, cpumask);
	if (cpumask)
		bpf_cpumask_release(cpumask);

	return 0;
}

/*
 * Calculate and return the virtual deadline for the given task.
 *
 *  The deadline is defined as:
 *
 *    deadline = vruntime + awake_vtime
 *
 * Here, `vruntime` represents the task's total accumulated runtime,
 * inversely scaled by its weight, while `awake_vtime` accounts the runtime
 * accumulated since the last sleep event, also inversely scaled by the
 * task's weight.
 *
 * Fairness is driven by `vruntime`, while `awake_vtime` helps prioritize
 * tasks that sleep frequently and use the CPU in short bursts (resulting
 * in a small `awake_vtime` value), which are typically latency critical.
 *
 * Additionally, to prevent over-prioritizing tasks that sleep for long
 * periods of time, the maximum vruntime they can accumulate while sleeping
 * is limited to @slice_lag, which is also scaled based on the task's
 * weight.
 *
 * To prioritize tasks that sleep frequently over those with long sleep
 * intervals, @slice_lag is also adjusted in function of the task's wakeup
 * frequency: tasks that sleep often have a bigger slice lag, allowing them
 * to accumulate more time-slice credit than tasks with infrequent, long
 * sleeps.
 */
static u64 task_dl(struct task_struct *p, s32 cpu, struct task_ctx *tctx)
{
	/*
	 * Reference queue depth: how many tasks would take 1/10 the SLA to
	 * drain at average slice usage.
	 */
	const u64 STARVATION_THRESH = STARVATION_MS * NSEC_PER_MSEC / 10;
	const u64 q_thresh = MAX(STARVATION_THRESH / slice_max, 1);

	u64 nr_queued = scx_bpf_dsq_nr_queued(cpu_dsq(cpu)) +
			scx_bpf_dsq_nr_queued(node_dsq(cpu));
	u64 lag_scale = MAX(tctx->wakeup_freq, 1);
	u64 awake_max = scale_by_task_weight_inverse(p, slice_lag);
	u64 vtime_min;

	/*
	 * Queue pressure factor = q_thresh / (q_thresh + nr_queued), applied to
	 * @lag_scale.
	 *
	 * Emergency clamp: if queued work (q * slice_max) already spans
	 * the starvation window, stop boosting vruntime credit.
	 */
	if (nr_queued * slice_max >= STARVATION_THRESH)
		lag_scale = 1;
	else
		lag_scale = MAX(lag_scale * q_thresh / (q_thresh + nr_queued), 1);

	/*
	 * Cap the partial accumulated vruntime since last sleep in
	 * function of @slice_lag and @lag_scale.
	 */
	vtime_min = vtime_now - scale_by_task_weight(p, slice_lag * lag_scale);
	if (time_before(p->scx.dsq_vtime, vtime_min))
		p->scx.dsq_vtime = vtime_min;

	/*
	 * Cap the partial accumulated vruntime since last sleep to
	 * @slice_lag.
	 */
	if (time_after(tctx->awake_vtime, awake_max))
		tctx->awake_vtime = awake_max;

	/*
	 * Evaluate task's deadline as the accumulated vruntime +
	 * accumulated vruntime since last sleep.
	 *
	 * Note that, since the wakeup frequency is only updated in
	 * ops.runnable(), a task that runs continuously without sleeping
	 * will retain a high wakeup frequency. However, this is balanced
	 * by its high total and awake vruntimes, resulting in a higher
	 * deadline, as intended.
	 */
	return p->scx.dsq_vtime + tctx->awake_vtime;
}

/*
 * Return a time slice scaled by the task's weight.
 */
static u64 task_slice(const struct task_struct *p, s32 cpu)
{
	u64 nr_wait = scx_bpf_dsq_nr_queued(cpu_dsq(cpu)) +
		      scx_bpf_dsq_nr_queued(node_dsq(cpu));

	/*
	 * Adjust time slice in function of the task's priority and the
	 * amount of tasks waiting to be dispatched.
	 */
	return scale_by_task_weight(p, slice_max) / MAX(nr_wait, 1);
}

/*
 * Pick a target CPU for a task which is being woken up.
 *
 * If a task is dispatched here, ops.enqueue() will be skipped: task will be
 * dispatched directly to the CPU returned by this callback.
 */
s32 BPF_STRUCT_OPS(bpfland_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
	s32 cpu, this_cpu = bpf_get_smp_processor_id();
	bool is_this_cpu_allowed = bpf_cpumask_test_cpu(this_cpu, p->cpus_ptr);

	/*
	 * Make sure @prev_cpu is usable, otherwise try to move close to
	 * the waker's CPU. If the waker's CPU is also not usable, then
	 * pick the first usable CPU.
	 */
	if (!bpf_cpumask_test_cpu(prev_cpu, p->cpus_ptr))
		prev_cpu = is_this_cpu_allowed ? this_cpu : bpf_cpumask_first(p->cpus_ptr);

	/*
	 * Try to find an idle CPU and dispatch the task directly to the
	 * target CPU.
	 */
	cpu = pick_idle_cpu(p, prev_cpu, is_this_cpu_allowed ? this_cpu : -1,
			    wake_flags, false);
	if (cpu >= 0) {
		struct task_ctx *tctx;

		tctx = try_lookup_task_ctx(p);
		if (tctx) {
			scx_bpf_dsq_insert_vtime(p, cpu_dsq(cpu),
						 task_slice(p, cpu), task_dl(p, cpu, tctx), 0);
			__sync_fetch_and_add(&nr_direct_dispatches, 1);
		}
		return cpu;
	}

	return prev_cpu;
}

/*
 * Return true if the task should be forced to stay on the same CPU, false
 * otherwise.
 */
static bool is_task_sticky(const struct task_ctx *tctx)
{
	return sticky_tasks && tctx->avg_runtime < 10 * NSEC_PER_USEC;
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
 * Return true if the task should attempt a migration, false otherwise.
 */
static bool task_should_migrate(struct task_struct *p, u64 enq_flags)
{
	/*
	 * If @sticky_tasks is enabled, attempt a migration only on wakeup
	 * (task was not running) and only if ops.select_cpu() has not been
	 * called. Otherwise, always attempt a migration unless
	 * ops.select_cpu() already handled it.
	 */
	return !__COMPAT_is_enq_cpu_selected(enq_flags) &&
	       (!sticky_tasks || !scx_bpf_task_running(p));
}

/*
 * Dispatch all the other tasks that were not dispatched directly in
 * select_cpu().
 */
void BPF_STRUCT_OPS(bpfland_enqueue, struct task_struct *p, u64 enq_flags)
{
	s32 prev_cpu = scx_bpf_task_cpu(p);
	struct task_ctx *tctx;

	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return;

	/*
	 * If the task is marked as sticky due to excessive rescheduling
	 * activity, dispatch it directly to the same CPU to reduce the
	 * locking pressure on the per-CPU and per-node DSQs.
	 */
	if (is_task_sticky(tctx)) {
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, task_slice(p, prev_cpu), enq_flags);
		__sync_fetch_and_add(&nr_direct_dispatches, 1);
		return;
	}

	/*
	 * If @local_kthread is specified dispatch per-CPU kthreads
	 * directly on their assigned CPU bypassing the per-CPU and
	 * per-node DSQs.
	 */
	if (local_kthreads && is_kthread(p) && p->nr_cpus_allowed == 1) {
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, task_slice(p, prev_cpu), enq_flags);
		__sync_fetch_and_add(&nr_kthread_dispatches, 1);
		return;
	}

	/*
	 * If the task can only run on the current CPU, dispatch it to the
	 * corresponding per-CPU DSQ.
	 *
	 * This does not cause starvation for tasks in per-node DSQs, since
	 * ops.dispatch() always picks the task with the earliest deadline
	 * between per-node and per-CPU DSQs.
	 *
	 * However, if @local_pcpu is enabled, per-CPU tasks are dispatched
	 * directly to SCX_DSQ_LOCAL, which can lead to starvation, but it
	 * also grants them higher priority, which can improve performance
	 * for certain workloads.
	 */
	if (is_pcpu_task(p)) {
		if (local_pcpu)
			scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, task_slice(p, prev_cpu), enq_flags);
		else
			scx_bpf_dsq_insert_vtime(p, cpu_dsq(prev_cpu),
						 task_slice(p, prev_cpu), task_dl(p, prev_cpu, tctx), enq_flags);
		__sync_fetch_and_add(&nr_direct_dispatches, 1);
		return;
	}

	/*
	 * Attempt to dispatch directly to an idle CPU if ops.select_cpu() was
	 * skipped.
	 */
	if (task_should_migrate(p, enq_flags)) {
		s32 cpu;

		if (is_pcpu_task(p))
			cpu = scx_bpf_test_and_clear_cpu_idle(prev_cpu) ? prev_cpu : -EBUSY;
		else
			cpu = pick_idle_cpu(p, prev_cpu, -1, 0, true);

		if (cpu >= 0) {
			scx_bpf_dsq_insert_vtime(p, cpu_dsq(cpu),
						 task_slice(p, cpu), task_dl(p, cpu, tctx), enq_flags);
			__sync_fetch_and_add(&nr_direct_dispatches, 1);

			if (prev_cpu != cpu || !scx_bpf_task_running(p))
				scx_bpf_kick_cpu(cpu, SCX_KICK_IDLE);
			return;
		}
	}

	/*
	 * Dispatch the task to the node DSQ, using the deadline-based
	 * scheduling.
	 */
	scx_bpf_dsq_insert_vtime(p, node_dsq(prev_cpu),
				 task_slice(p, prev_cpu), task_dl(p, prev_cpu, tctx), enq_flags);
	__sync_fetch_and_add(&nr_shared_dispatches, 1);

	/*
	 * No need to kick the CPU if ops.select_cpu() has been called.
	 */
	if (task_should_migrate(p, enq_flags))
		scx_bpf_kick_cpu(prev_cpu, SCX_KICK_IDLE);
}

/*
 * Return true if the task can keep running on its current CPU from
 * ops.dispatch(), false if the task should migrate.
 */
static bool keep_running(const struct task_struct *p, s32 cpu)
{
	/* Do not keep running if the task doesn't need to run */
	if (!is_task_queued(p))
		return false;

	/*
	 * If the task can only run on this CPU, keep it running.
	 */
	if (is_pcpu_task(p))
		return true;

	/*
	 * If the task is not running in a full-idle SMT core and there are
	 * full-idle SMT cores available in the system, give it a chance to
	 * migrate elsewhere.
	 */
	if (is_smt_contended(cpu))
		return false;

	return true;
}

/*
 * Consume and dispatch the first task from @dsq_id. If the first task can't be
 * dispatched on the corresponding DSQ, redirect the task to a proper CPU.
 */
static bool consume_first_task(u64 dsq_id, struct task_struct *p)
{
	if (!p)
		return false;

	return scx_bpf_dsq_move_to_local(dsq_id);
}

void BPF_STRUCT_OPS(bpfland_dispatch, s32 cpu, struct task_struct *prev)
{
	struct task_struct *p = __COMPAT_scx_bpf_dsq_peek(cpu_dsq(cpu));
	struct task_struct *q = __COMPAT_scx_bpf_dsq_peek(node_dsq(cpu));

	/*
	 * Let the CPU go idle if the system is throttled.
	 */
	if (is_throttled())
		return;

	/*
	 * Try to consume the first task either from the per-CPU DSQ or the
	 * per-node DSQ, picking the one with the minimum deadline that can
	 * run on @cpu.
	 */
	if (!is_deadline_min(q, p)) {
		if (consume_first_task(cpu_dsq(cpu), p) || consume_first_task(node_dsq(cpu), q))
			return;
	} else {
		if (consume_first_task(node_dsq(cpu), q) || consume_first_task(cpu_dsq(cpu), p))
			return;
	}

	/*
	 * If the current task expired its time slice and no other task wants
	 * to run, simply replenish its time slice and let it run for another
	 * round on the same CPU.
	 */
	if (prev && keep_running(prev, cpu))
		prev->scx.slice = task_slice(prev, cpu);
}

/*
 * Update CPU load and scale target performance level accordingly.
 */
static void update_cpu_load(struct task_struct *p, struct task_ctx *tctx)
{
	u64 now = bpf_ktime_get_ns();
	s32 cpu = scx_bpf_task_cpu(p);
	u64 perf_lvl, delta_runtime, delta_t;
	struct cpu_ctx *cctx;

	/*
	 * For non-interactive tasks determine their cpufreq scaling factor as
	 * a function of their CPU utilization.
	 */
	cctx = try_lookup_cpu_ctx(cpu);
	if (!cctx)
		return;

	/*
	 * Evaluate dynamic cpuperf scaling factor using the average CPU
	 * utilization, normalized in the range [0 .. SCX_CPUPERF_ONE].
	 */
	delta_t = now > cctx->last_running ? now - cctx->last_running : 1;

	/*
	 * Refresh target performance level, if utilization is above 75%
	 * bump up the performance level to the max.
	 */
	delta_runtime = cctx->tot_runtime - cctx->prev_runtime;
	perf_lvl = MIN(delta_runtime * SCX_CPUPERF_ONE / delta_t, SCX_CPUPERF_ONE);
	if (perf_lvl >= SCX_CPUPERF_ONE - SCX_CPUPERF_ONE / 4)
		perf_lvl = SCX_CPUPERF_ONE;
	cctx->perf_lvl = perf_lvl;

	/*
	 * Refresh the dynamic cpuperf scaling factor if needed.
	 */
	if (cpufreq_perf_lvl < 0)
		scx_bpf_cpuperf_set(cpu, cctx->perf_lvl);

	cctx->last_running = now;
	cctx->prev_runtime = cctx->tot_runtime;
}

void BPF_STRUCT_OPS(bpfland_running, struct task_struct *p)
{
	struct task_ctx *tctx;

	__sync_fetch_and_add(&nr_running, 1);

	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return;

	/*
	 * Save a timestamp when the task begins to run (used to evaluate
	 * the used time slice).
	 */
	tctx->last_run_at = bpf_ktime_get_ns();

	/*
	 * Adjust target CPU frequency before the task starts to run.
	 */
	update_cpu_load(p, tctx);

	/*
	 * Update current system's vruntime.
	 */
	if (time_before(vtime_now, p->scx.dsq_vtime))
		vtime_now = p->scx.dsq_vtime;
}

/*
 * Update task statistics when the task is releasing the CPU (either
 * voluntarily or because it expires its assigned time slice).
 */
void BPF_STRUCT_OPS(bpfland_stopping, struct task_struct *p, bool runnable)
{
	u64 now = bpf_ktime_get_ns(), slice, delta_vtime, delta_runtime;
	s32 cpu = scx_bpf_task_cpu(p);
	struct task_ctx *tctx;
	struct cpu_ctx *cctx;

	__sync_fetch_and_sub(&nr_running, 1);

	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return;

	/*
	 * Evaluate the used time slice and actual runtime.
	 */
	slice = now - tctx->last_run_at;

	/*
	 * Update average runtime per scheduling cycle for sticky task detection.
	 */
	tctx->avg_runtime = calc_avg(tctx->avg_runtime, slice);

	/*
	 * Update the vruntime and the total accumulated runtime since last
	 * sleep.
	 */
	delta_vtime = scale_by_task_weight_inverse(p, slice);
	p->scx.dsq_vtime += delta_vtime;
	tctx->awake_vtime += delta_vtime;

	/*
	 * Update CPU runtime.
	 */
	cctx = try_lookup_cpu_ctx(cpu);
	if (!cctx)
		return;
	delta_runtime = now - cctx->last_running;
	cctx->tot_runtime += delta_runtime;
}

void BPF_STRUCT_OPS(bpfland_runnable, struct task_struct *p, u64 enq_flags)
{
	u64 now = bpf_ktime_get_ns(), delta_t;
	struct task_ctx *tctx;

	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return;

	tctx->awake_vtime = 0;

	/*
	 * Update the task's wakeup frequency based on the time since the
	 * last wakeup, then cap the result to avoid large spikes.
	 */
	delta_t = now > tctx->last_woke_at ? now - tctx->last_woke_at : 1;
	tctx->wakeup_freq = update_freq(tctx->wakeup_freq, delta_t);
	tctx->wakeup_freq = MIN(tctx->wakeup_freq, MAX_WAKEUP_FREQ);
	tctx->last_woke_at = now;
}

void BPF_STRUCT_OPS(bpfland_enable, struct task_struct *p)
{
	/*
	 * Initialize the task vruntime to the current global vruntime.
	 */
	p->scx.dsq_vtime = vtime_now;
}

s32 BPF_STRUCT_OPS(bpfland_init_task, struct task_struct *p,
		   struct scx_init_task_args *args)
{
	struct task_ctx *tctx;

	tctx = bpf_task_storage_get(&task_ctx_stor, p, 0,
				    BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!tctx)
		return -ENOMEM;

	return 0;
}

/*
 * Evaluate the amount of online CPUs.
 */
static s32 get_nr_online_cpus(void)
{
	const struct cpumask *online_cpumask;
	int cpus;

	online_cpumask = scx_bpf_get_online_cpumask();
	cpus = bpf_cpumask_weight(online_cpumask);
	scx_bpf_put_cpumask(online_cpumask);

	return cpus;
}

static int init_cpumask(struct bpf_cpumask **cpumask)
{
	struct bpf_cpumask *mask;
	int err = 0;

	/*
	 * Do nothing if the mask is already initialized.
	 */
	mask = *cpumask;
	if (mask)
		return 0;
	/*
	 * Create the CPU mask.
	 */
	err = calloc_cpumask(cpumask);
	if (!err)
		mask = *cpumask;
	if (!mask)
		err = -ENOMEM;

	return err;
}

SEC("syscall")
int enable_sibling_cpu(struct domain_arg *input)
{
	struct cpu_ctx *cctx;
	struct bpf_cpumask *mask, **pmask;
	int err = 0;

	cctx = try_lookup_cpu_ctx(input->cpu_id);
	if (!cctx)
		return -ENOENT;

	pmask = &cctx->smt;
	err = init_cpumask(pmask);
	if (err)
		return err;

	bpf_rcu_read_lock();
	mask = *pmask;
	if (mask)
		bpf_cpumask_set_cpu(input->sibling_cpu_id, mask);
	bpf_rcu_read_unlock();

	return err;
}

SEC("syscall")
int enable_primary_cpu(struct cpu_arg *input)
{
	struct bpf_cpumask *mask;
	int err = 0;

	/* Make sure the primary CPU mask is initialized */
	err = init_cpumask(&primary_cpumask);
	if (err)
		return err;
	/*
	 * Enable the target CPU in the primary scheduling domain. If the
	 * target CPU is a negative value, clear the whole mask (this can be
	 * used to reset the primary domain).
	 */
	bpf_rcu_read_lock();
	mask = primary_cpumask;
	if (mask) {
		s32 cpu = input->cpu_id;

		if (cpu < 0)
			bpf_cpumask_clear(mask);
		else
			bpf_cpumask_set_cpu(cpu, mask);
	}
	bpf_rcu_read_unlock();

	return err;
}

/*
 * Initialize cpufreq performance level on all the online CPUs.
 */
static void init_cpuperf_target(void)
{
	const struct cpumask *online_cpumask;
	u64 perf_lvl;
	s32 cpu;

	online_cpumask = scx_bpf_get_online_cpumask();
	bpf_for(cpu, 0, nr_cpu_ids) {
		if (!bpf_cpumask_test_cpu(cpu, online_cpumask))
			continue;

		/* Set the initial cpufreq performance level  */
		if (cpufreq_perf_lvl < 0)
			perf_lvl = SCX_CPUPERF_ONE;
		else
			perf_lvl = MIN(cpufreq_perf_lvl, SCX_CPUPERF_ONE);
		scx_bpf_cpuperf_set(cpu, perf_lvl);
	}
	scx_bpf_put_cpumask(online_cpumask);
}

/*
 * Throttle timer used to inject idle time across all the CPUs.
 */
static int throttle_timerfn(void *map, int *key, struct bpf_timer *timer)
{
	bool throttled = is_throttled();
	u64 flags, duration;
	s32 cpu;
	int err;

	/*
	 * Stop the CPUs sending a preemption IPI (SCX_KICK_PREEMPT) if we
	 * need to interrupt the running tasks and inject the idle sleep.
	 *
	 * Otherwise, send a wakeup IPI to resume from the injected idle
	 * sleep.
	 */
	if (throttled) {
		flags = SCX_KICK_IDLE;
		duration = slice_max;
	} else {
		flags = SCX_KICK_PREEMPT;
		duration = throttle_ns;
	}

	/*
	 * Flip the throttled state.
	 */
	set_throttled(!throttled);

	bpf_for(cpu, 0, nr_cpu_ids)
		scx_bpf_kick_cpu(cpu, flags);

	/*
	 * Re-arm the duty-cycle timer setting the runtime or the idle time
	 * duration.
	 */
	err = bpf_timer_start(timer, duration, 0);
	if (err)
		scx_bpf_error("Failed to re-arm duty cycle timer");

	return 0;
}

s32 BPF_STRUCT_OPS_SLEEPABLE(bpfland_init)
{
	struct bpf_timer *timer;
	int err, i;
	u32 key = 0;

	/* Initialize amount of online and possible CPUs */
	nr_online_cpus = get_nr_online_cpus();
	nr_cpu_ids = scx_bpf_nr_cpu_ids();

	/* Initialize CPUs and NUMA properties */
	init_cpuperf_target();

	/*
	 * Create the per-CPU DSQs.
	 */
	bpf_for(i, 0, nr_cpu_ids) {
		int node = __COMPAT_scx_bpf_cpu_node(i);
		u64 dsq_id = i;

		err = scx_bpf_create_dsq(dsq_id, node);
		if (err) {
			scx_bpf_error("failed to create DSQ %llu: %d", dsq_id, err);
			return err;
		}
	}

	/*
	 * Create the per-node DSQs.
	 */
	bpf_for(i, 0, __COMPAT_scx_bpf_nr_node_ids()) {
		u64 dsq_id = nr_cpu_ids + i;

		err = scx_bpf_create_dsq(dsq_id, i);
		if (err) {
			scx_bpf_error("failed to create DSQ %llu: %d", dsq_id, err);
			return err;
		}
	}

	/* Initialize the primary scheduling domain */
	err = init_cpumask(&primary_cpumask);
	if (err)
		return err;

	timer = bpf_map_lookup_elem(&throttle_timer, &key);
	if (!timer) {
		scx_bpf_error("Failed to lookup throttle timer");
		return -ESRCH;
	}

	/*
	 * Fire the throttle timer if CPU throttling is enabled.
	 */
	if (throttle_ns) {
		bpf_timer_init(timer, &throttle_timer, CLOCK_BOOTTIME);
		bpf_timer_set_callback(timer, throttle_timerfn);
		err = bpf_timer_start(timer, slice_max, 0);
		if (err) {
			scx_bpf_error("Failed to arm throttle timer");
			return err;
		}
	}

	return 0;
}

void BPF_STRUCT_OPS(bpfland_exit, struct scx_exit_info *ei)
{
	UEI_RECORD(uei, ei);
}

SCX_OPS_DEFINE(bpfland_ops,
	       .select_cpu		= (void *)bpfland_select_cpu,
	       .enqueue			= (void *)bpfland_enqueue,
	       .dispatch		= (void *)bpfland_dispatch,
	       .running			= (void *)bpfland_running,
	       .stopping		= (void *)bpfland_stopping,
	       .runnable		= (void *)bpfland_runnable,
	       .enable			= (void *)bpfland_enable,
	       .init_task		= (void *)bpfland_init_task,
	       .init			= (void *)bpfland_init,
	       .exit			= (void *)bpfland_exit,
	       .timeout_ms		= STARVATION_MS,
	       .name			= "bpfland");
