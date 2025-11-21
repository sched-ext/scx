/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2025 Andrea Righi <arighi@nvidia.com>
 */
#include <scx/common.bpf.h>
#include <scx/percpu.bpf.h>
#include <lib/pmu.h>
#include "intf.h"

char _license[] SEC("license") = "GPL";

/*
 * Maximum amount of CPUs supported by the scheduler when flat or preferred
 * idle CPU scan is enabled.
 */
#define MAX_CPUS	1024

/*
 * Maximum amount of NUMA nodes supported by the scheduler.
 */
#define MAX_NODES	1024

/*
 * Maximum amount of GPUs supported by the scheduler.
 */
#define MAX_GPUS	32

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
 * Cache CPU capacity values.
 */
const volatile u64 cpu_capacity[MAX_CPUS];

/*
 * Enable cpufreq integration.
 */
const volatile bool cpufreq_enabled = true;

/*
 * Enable NUMA optimizations.
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
 * ID of perf-event being tracked. 0 for "no event".
 */
const volatile u64 perf_config;

/*
 * Performance counter threshold to classify a task as event heavy.
 */
volatile u64 perf_threshold;

/*
 * Enable deferred wakeup.
 */
const volatile bool deferred_wakeups = true;

/*
 * Sticky perf event (0x0 = disabled). When task's count for this event
 * exceeds perf_sticky_threshold, keep it on the same CPU.
 */
const volatile u64 perf_sticky;

/*
 * Threshold for sticky event; task is kept on same CPU when exceeded.
 */
volatile u64 perf_sticky_threshold;

/*
 * Enable tick-based preemption enforcement.
 */
const volatile bool tick_preempt = true;

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

/*
 * Scheduler statistics.
 */
volatile u64 nr_event_dispatches;
volatile u64 nr_ev_sticky_dispatches;

/*
 * Scheduler's exit status.
 */
UEI_DEFINE(uei);

/*
 * Maximum amount of CPUs supported by the system.
 */
static u64 nr_cpu_ids;

/*
 * Maximum possible NUMA node number.
 */
const volatile u32 nr_node_ids;

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
	u64 perf_events;
	u64 perf_sticky_events;
};

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct task_ctx);
} task_ctx_stor SEC(".maps");

/*
 * NUMA node context.
 */
struct node_ctx {
        struct bpf_cpumask __kptr *cpumask;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, struct node_ctx);
	__uint(max_entries, MAX_NODES);
} node_ctx_stor SEC(".maps");

struct node_ctx *try_lookup_node_ctx(int node)
{
	return bpf_map_lookup_elem(&node_ctx_stor, &node);
}

/*
 * CPU -> NUMA node mapping.
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_CPUS);
	__type(key, u32);	/* cpu_id */
	__type(value, u32);	/* node_id */
} cpu_node_map SEC(".maps");

static int cpu_node(s32 cpu)
{
	u32 *id;

	if (!numa_enabled)
		return 0;

	id = bpf_map_lookup_elem(&cpu_node_map, &cpu);
	if (!id)
		return -ENOENT;

	return *id;
}

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
	u64 perf_events;
	struct bpf_cpumask __kptr *smt;
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

static void update_counters(struct task_struct *p, struct task_ctx *tctx, s32 cpu)
{
	struct cpu_ctx *cctx;
	u64 delta = 0;
	u64 sticky_delta = 0;

	cctx = try_lookup_cpu_ctx(cpu);
	if (cctx)
		cctx->perf_events += delta;

	if (perf_config) {
		scx_pmu_read(p, perf_config, &delta, true);
		tctx->perf_events = delta;
	}

	if (perf_sticky) {
		scx_pmu_read(p, perf_sticky, &sticky_delta, true);
		tctx->perf_sticky_events = sticky_delta;
	}
}

/*
 * Return true if the task is triggering too many PMU events (migration event).
 */
static inline bool is_event_heavy(const struct task_ctx *tctx)
{
	return perf_config && tctx->perf_events > perf_threshold;
}

/*
 * Return true if the task exceeds the sticky event threshold and should
 * stay on the same CPU.
 */
static inline bool is_sticky_event_heavy(const struct task_ctx *tctx)
{
	return perf_sticky && tctx->perf_sticky_events > perf_sticky_threshold;
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
	return numa_enabled ? cpu_node(cpu) : SHARED_DSQ;
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
 * Return true if the CPU is running the idle thread, false otherwise.
 */
static inline bool is_cpu_idle(s32 cpu)
{
	struct task_struct *p;
	bool idle;

	bpf_rcu_read_lock();
	p = __COMPAT_scx_bpf_cpu_curr(cpu);

	if (!p) {
		bpf_rcu_read_unlock();
		scx_bpf_error("Failed to access rq->curr %d", cpu);
		return false;
	}
	idle = p->flags & PF_IDLE;
	bpf_rcu_read_unlock();
	return idle;
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
	idle_mask = scx_bpf_get_idle_cpumask();
	is_contended = !bpf_cpumask_test_cpu(smt_sibling(cpu), idle_mask) &&
		       !bpf_cpumask_empty(idle_mask);
	scx_bpf_put_cpumask(idle_mask);

	return is_contended;
}

/*
 * Return true if @cpu is valid, otherwise trigger an error and return
 * false.
 */
static inline bool is_cpu_valid(s32 cpu)
{
	u64 max_cpu = MIN(nr_cpu_ids, MAX_CPUS);

	if (cpu < 0 || cpu >= max_cpu) {
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
	smt = smt_enabled ? scx_bpf_get_idle_smtmask() : NULL;

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
 * Return true in case of a task wakeup, false otherwise.
 */
static inline bool is_wakeup(u64 wake_flags)
{
	return wake_flags & SCX_WAKE_TTWU;
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
 * Return true if the task should attempt a migration, false otherwise.
 */
static bool task_should_migrate(struct task_struct *p, u64 enq_flags)
{
	/*
	 * Attempt a migration on wakeup (task was not running) and only if
	 * ops.select_cpu() has not been called already.
	 */
	return !__COMPAT_is_enq_cpu_selected(enq_flags) && !scx_bpf_task_running(p);
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

/*
 * Look for the least busy cpu based on perf_event count. Look within the
 * same node as prev_cpu, otherwise this optimization becomes expensive on
 * large CPU numa systems
 */
static int pick_least_busy_event_cpu(const struct task_struct *p, s32 prev_cpu,
				     const struct task_ctx *tctx)
{
	struct cpu_ctx *cctx;
	u64 min = ~0UL;
	int cpu, ret_cpu = -EBUSY;

	bpf_for(cpu, 0, nr_cpu_ids) {
		if (cpu_node(cpu) != cpu_node(prev_cpu) ||
		    !is_cpu_idle(cpu) ||
		    !bpf_cpumask_test_cpu(cpu, p->cpus_ptr))
			continue;

		cctx = try_lookup_cpu_ctx(cpu);
		if (!cctx)
			continue;

		if (cctx->perf_events < min) {
			min = cctx->perf_events;
			ret_cpu = cpu;
		}
	}

	return ret_cpu;
}

s32 BPF_STRUCT_OPS(cosmos_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
	const struct task_struct *current = (void *)bpf_get_current_task_btf();
	bool is_busy = is_system_busy();
	s32 cpu, this_cpu = bpf_get_smp_processor_id();
	bool is_this_cpu_allowed = bpf_cpumask_test_cpu(this_cpu, p->cpus_ptr);
	int new_cpu;

	/*
	 * Make sure @prev_cpu is usable, otherwise try to move close to
	 * the waker's CPU. If the waker's CPU is also not usable, then
	 * pick the first usable CPU.
	 */
	if (!bpf_cpumask_test_cpu(prev_cpu, p->cpus_ptr))
		prev_cpu = is_this_cpu_allowed ? this_cpu : bpf_cpumask_first(p->cpus_ptr);

	/*
	 * When the waker and wakee share the same address space and were previously
	 * running on the same CPU, there's a high chance of finding hot cache data
	 * on that CPU. In such cases, prefer keeping the wakee on the same CPU.
	 *
	 * This optimization is applied only when the system is not saturated,
	 * to avoid introducing too much unfairness.
	 */
	if (is_wake_affine(current, p) && !is_busy) {
		if (this_cpu == prev_cpu) {
			scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, task_slice(p), 0);
			return this_cpu;
		}
	}

	/*
	 * Pick an event free CPU: if task exceeds sticky threshold, keep
	 * on same CPU, if it exceeds migration threshold, move to least
	 * event-busy CPU.
	 */
	if (perf_config || perf_sticky) {
		struct task_ctx *tctx;

		tctx = try_lookup_task_ctx(p);
		if (!tctx)
			return prev_cpu;

		if (is_sticky_event_heavy(tctx)) {
			__sync_fetch_and_add(&nr_ev_sticky_dispatches, 1);
			scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, task_slice(p), 0);
			return prev_cpu;
		}

		if (is_event_heavy(tctx)) {
			__sync_fetch_and_add(&nr_event_dispatches, 1);
			new_cpu = pick_least_busy_event_cpu(p, prev_cpu, tctx);
			if (new_cpu >= 0) {
				scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, task_slice(p), 0);
				return new_cpu;
			}
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
	cpu = pick_idle_cpu(p, prev_cpu, is_this_cpu_allowed ? this_cpu : -1,
			    wake_flags, false);
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

void BPF_STRUCT_OPS(cosmos_tick, struct task_struct *p)
{
	struct task_ctx *tctx;

	if (!tick_preempt)
		return;

	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return;

	/*
	 * Force preemption if the task has exceeded its time slice and
	 * either:
	 * - SMT contention has changed since we started running
	 *   (sibling went busy or idle), triggering rescheduling so
	 *   select_cpu can make a better placement decision, or
	 * - the system is busy and there are tasks waiting in the
	 *   local or shared DSQ.
	 */
	if (time_delta(scx_bpf_now(), tctx->last_run_at) > task_slice(p)) {
		s32 cpu = scx_bpf_task_cpu(p);
		bool smt_contention = avoid_smt && is_smt_contended(cpu);
		bool cpu_busy = scx_bpf_dsq_nr_queued(SCX_DSQ_LOCAL_ON | cpu) ||
				scx_bpf_dsq_nr_queued(shared_dsq(cpu));

		if (smt_contention || (is_system_busy() && cpu_busy))
			p->scx.slice = 0;
	}
}

void BPF_STRUCT_OPS(cosmos_enqueue, struct task_struct *p, u64 enq_flags)
{
	s32 prev_cpu = scx_bpf_task_cpu(p), cpu;
	struct task_ctx *tctx;
	int new_cpu;

	/*
	 * Dispatch the task to the shared DSQ, using the deadline-based
	 * scheduling.
	 */
	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return;

	/*
	 * Immediately dispatch sticky event-heavy tasks to the same CPU.
	 */
	if (is_sticky_event_heavy(tctx)) {
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, task_slice(p), enq_flags);
		__sync_fetch_and_add(&nr_ev_sticky_dispatches, 1);

		if (!scx_bpf_task_running(p))
			scx_bpf_kick_cpu(prev_cpu, SCX_KICK_IDLE);
		return;
	}

	/*
	 * Immediately dispatch migration event-heavy tasks to a new CPU
	 * (if the task is allowed to migrate).
	 */
	if (!is_migration_disabled(p) && is_event_heavy(tctx)) {
		new_cpu = pick_least_busy_event_cpu(p, prev_cpu, tctx);
		if (new_cpu >= 0) {
			scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | new_cpu,
					   task_slice(p), enq_flags);
			__sync_fetch_and_add(&nr_event_dispatches, 1);

			if (new_cpu != prev_cpu || !scx_bpf_task_running(p))
				scx_bpf_kick_cpu(new_cpu, SCX_KICK_IDLE);
			return;
		}
	}

	/*
	 * Attempt to dispatch directly to an idle CPU if the task can
	 * migrate.
	 */
	if (task_should_migrate(p, enq_flags)) {
		if (is_pcpu_task(p))
			cpu = scx_bpf_test_and_clear_cpu_idle(prev_cpu) ? prev_cpu : -EBUSY;
		else
			cpu = pick_idle_cpu(p, prev_cpu, -1, 0, true);
		if (cpu >= 0) {
			scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | cpu, task_slice(p), enq_flags);
			if (cpu != prev_cpu || !scx_bpf_task_running(p))
				wakeup_cpu(cpu);
			return;
		}
	}

	/*
	 * Keep using the same CPU if the system is not busy.
	 */
	if (!is_system_busy()) {
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, task_slice(p), enq_flags);
		if (task_should_migrate(p, enq_flags))
			wakeup_cpu(prev_cpu);
		return;
	}

	/*
	 * Dispatch the task to the shared DSQ.
	 */
	scx_bpf_dsq_insert_vtime(p, shared_dsq(prev_cpu),
				 task_slice(p), task_dl(p, tctx), enq_flags);

	if (task_should_migrate(p, enq_flags))
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
	if (prev && (prev->scx.flags & SCX_TASK_QUEUED))
		prev->scx.slice = task_slice(prev);
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

	/*
	 * Capture performance counter baseline when task starts running.
	 */
	if (perf_config || perf_sticky)
		scx_pmu_event_start(p, false);
}

void BPF_STRUCT_OPS(cosmos_stopping, struct task_struct *p, bool runnable)
{
	s32 cpu = scx_bpf_task_cpu(p);
	struct task_ctx *tctx;
	u64 slice;

	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return;

	/* Update task's performance counters */
	if (perf_config || perf_sticky) {
		scx_pmu_event_stop(p);
		update_counters(p, tctx, cpu);
	}

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
	int ret;

	tctx = bpf_task_storage_get(&task_ctx_stor, p, 0,
				    BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!tctx)
		return -ENOMEM;

	if ((ret = scx_pmu_task_init(p)))
		return ret;

	return 0;
}

void BPF_STRUCT_OPS(cosmos_exit_task, struct task_struct *p,
		   struct scx_exit_task_args *args)
{
	scx_pmu_task_fini(p);
}

/*
 * Initialize a NUMA node context.
 */
static int init_node(int node)
{
	struct bpf_cpumask *cpumask;
	struct node_ctx *nctx;
	u32 cpu;
	int ret;

	nctx = try_lookup_node_ctx(node);
	if (!nctx)
		return -ENOENT;

	ret = init_cpumask(&nctx->cpumask);
	if (ret)
		return ret;

	bpf_rcu_read_lock();
	cpumask = nctx->cpumask;
	if (!cpumask) {
		ret = -EINVAL;
		goto out_unlock;
	}
	bpf_for(cpu, 0, nr_cpu_ids)
		if (cpu_node(cpu) == node)
			bpf_cpumask_set_cpu(cpu, cpumask);
out_unlock:
	bpf_rcu_read_unlock();

	return ret;
}

s32 BPF_STRUCT_OPS_SLEEPABLE(cosmos_init)
{
	struct bpf_timer *timer;
	u32 key = 0;
	int err;
	int cpu;
	struct cpu_ctx *cctx;

	nr_cpu_ids = scx_bpf_nr_cpu_ids();

	/*
	 * Create separate per-node DSQs if NUMA optimization is enabled,
	 * otherwise use a single shared DSQ.
	 */
	if (numa_enabled) {
		int node;

		bpf_for(node, 0, nr_node_ids) {
			err = scx_bpf_create_dsq(node, node);
			if (err) {
				scx_bpf_error("failed to create node DSQ %d: %d", node, err);
				return err;
			}
			err = init_node(node);
			if (err) {
				scx_bpf_error("failed to initialize NUMA node %d: %d", node, err);
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

	bpf_for(cpu, 0, nr_cpu_ids) {
		cctx = try_lookup_cpu_ctx(cpu);
		if (!cctx)
			continue;
		cctx->perf_events = 0;
	}

	if (perf_config) {
		err = scx_pmu_install(perf_config);
		if (err)
			return err;
	}

	if (perf_sticky) {
		err = scx_pmu_install(perf_sticky);
		if (err)
			return err;
	}

	return 0;
}

void BPF_STRUCT_OPS(cosmos_exit, struct scx_exit_info *ei)
{
	if (perf_config)
		scx_pmu_uninstall(perf_config);

	if (perf_sticky)
		scx_pmu_uninstall(perf_sticky);

	UEI_RECORD(uei, ei);
}

SCX_OPS_DEFINE(cosmos_ops,
	       .select_cpu		= (void *)cosmos_select_cpu,
	       .enqueue			= (void *)cosmos_enqueue,
	       .dispatch		= (void *)cosmos_dispatch,
	       .tick                    = (void *)cosmos_tick,
	       .runnable		= (void *)cosmos_runnable,
	       .running			= (void *)cosmos_running,
	       .stopping		= (void *)cosmos_stopping,
	       .enable			= (void *)cosmos_enable,
	       .init_task		= (void *)cosmos_init_task,
	       .exit_task		= (void *)cosmos_exit_task,
	       .init			= (void *)cosmos_init,
	       .exit			= (void *)cosmos_exit,
	       .timeout_ms		= 5000,
	       .name			= "cosmos");
