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
#define STARVATION_MS 5000ULL

/*
 * Maximum amount of CPUs supported by the scheduler when flat or preferred
 * idle CPU scan is enabled.
 */
#define MAX_CPUS 1024

/*
 * Maximum rate of task wakeups/sec (tasks with a higher rate are capped to
 * this value).
 *
 * Note that the wakeup rate is evaluate over a period of 100ms, so this
 * number must be multiplied by 10 to determine the actual limit in
 * wakeups/sec.
 */
#define MAX_WAKEUP_FREQ 64ULL

/*
 * Enable TIMELY mode: when true, the scheduler uses TIMELY's delay-driven
 * feedback for adaptive time slices and pressure-aware load balancing.
 */
const volatile bool timely_enabled;

/*
 * TIMELY-specific constants for v2 locality and pressure-aware load balancing.
 */
#define V2_LOCALITY_NONE 0U
#define V2_LOCALITY_BASE 1U
#define V2_LOCALITY_CONGESTED 2U

char _license[] SEC("license") = "GPL";

/* Allow to use bpf_printk() only when @debug is set */
#define dbg_msg(_fmt, ...)                               \
	do {                                             \
		if (debug)                               \
			bpf_printk(_fmt, ##__VA_ARGS__); \
	} while (0)

/* Report additional debugging information */
const volatile bool debug;

/*
 * Default task time slice.
 */
const volatile u64 slice_max = 1ULL * NSEC_PER_MSEC;

/*
 * Default minimum time slice.
 */
const volatile u64 slice_min;

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
volatile u64 nr_kthread_dispatches, nr_direct_dispatches, nr_shared_dispatches,
	nr_delay_recovery_dispatches, nr_delay_middle_add_dispatches,
	nr_delay_fast_recovery_dispatches, nr_delay_rate_limited_dispatches,
	nr_gain_floor_dispatches, nr_gain_ceiling_dispatches,
	nr_delay_low_region_samples, nr_delay_mid_region_samples,
	nr_delay_high_region_samples, nr_gain_floor_resident_samples,
	nr_gain_mid_resident_samples, nr_gain_ceiling_resident_samples,
	nr_idle_select_path_picks, nr_idle_enqueue_path_picks,
	nr_idle_prev_cpu_picks, nr_idle_primary_picks, nr_idle_spill_picks,
	nr_idle_pick_failures, nr_idle_primary_domain_misses,
	nr_idle_global_misses, nr_waker_cpu_biases, nr_keep_running_reuses,
	nr_keep_running_queue_empty, nr_keep_running_smt_blocked,
	nr_keep_running_queued_work, nr_dispatch_cpu_dsq_consumes,
	nr_dispatch_node_dsq_consumes, nr_v2_locality_cpu_dispatches,
	nr_v2_congested_locality_cpu_dispatches,
	nr_v2_delay_locality_cpu_dispatches, nr_v2_local_head_biases,
	nr_v2_pressure_mode_entries, nr_v2_pressure_mode_exits,
	nr_v2_pressure_shared_dispatches, nr_v2_expand_mode_dispatches,
	nr_v2_contract_mode_dispatches, nr_cpu_release_reenqueue;

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
 * TIMELY tunables.
 */
const volatile u64 timely_tlow_ns	      = 5000ULL * NSEC_PER_USEC;
const volatile u64 timely_thigh_ns	      = 50000ULL * NSEC_PER_USEC;
const volatile u32 timely_gain_min_fp	      = 128U;
const volatile u32 timely_gain_max_fp	      = 1024U;
const volatile u32 timely_gain_step_fp	      = 32U;
const volatile u32 timely_hai_thresh_fp	      = 768U;
const volatile u32 timely_hai_multiplier      = 2U;
const volatile u32 timely_backoff_low_fp      = 768U;
const volatile u32 timely_backoff_high_fp     = 960U;
const volatile u32 timely_backoff_gradient_fp = 992U;
const volatile u64 timely_gradient_margin_ns  = 125ULL * NSEC_PER_USEC;
const volatile u64 timely_control_interval_ns = 500ULL * NSEC_PER_USEC;

/*
 * TIMELY v2 locality fallback tunables.
 */
const volatile bool v2_locality_fallback;
const volatile u64  v2_locality_wakeup_freq = 8ULL;
const volatile u64  v2_locality_max_cpuq    = 0ULL;
const volatile u64  v2_locality_congested_nodeq;
const volatile u64  v2_locality_congested_max_cpuq;
const volatile bool v2_local_head_bias;
const volatile u64  v2_local_head_bias_slack_ns;
const volatile u32  v2_pressure_enter_streak;
const volatile u32  v2_pressure_exit_streak;

/*
 * v2 pressure-aware load-balancing thresholds.
 *
 * The scheduler operates in two modes:
 * - CONTRACT (locality-first): Favor staying on the current/favored CPU set
 * - EXPAND (balance-first): More aggressively spread work to reduce delay
 */
const volatile u32 v2ExpandThreshold   = 75;
const volatile u32 v2ContractThreshold = 50;

/*
 * v2 global pressure state for load-balancing decisions.
 */
volatile u32 v2_global_pressure;
volatile u32 v2_expand_mode;
volatile u32 v2_primary_domain_busy;
volatile u64 v2_expand_mode_entries;
volatile u64 v2_expand_mode_exits;

/*
 * Runtime throttling.
 *
 * Throttle the CPUs by injecting @throttle_ns idle time every @slice_max.
 */
const volatile u64   throttle_ns;
static volatile bool cpus_throttled;

static inline bool   is_throttled(void)
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
	u64			   tot_runtime;
	u64			   prev_runtime;
	u64			   last_running;
	u64			   perf_lvl;
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
	/* TIMELY-specific fields (valid when timely_enabled=true) */
	u64 timely_last_enqueued_at;
	u32 timely_gain_fp;
	u64 timely_last_gain_update_at;
	u64 timely_last_delay_sample_at;
	u64 timely_avg_queue_delay;
	s64 timely_avg_queue_gradient;
	u32 timely_hai_streak;
	u32 v2_pressure_streak;
	u32 v2_recovery_streak;
	u32 v2_pressure_mode;
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
	return bpf_task_storage_get(&task_ctx_stor, (struct task_struct *)p, 0,
				    0);
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
static inline bool is_deadline_min(const struct task_struct *p1,
				   const struct task_struct *p2)
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

	return __COMPAT_scx_bpf_get_idle_cpumask_node(
		__COMPAT_scx_bpf_cpu_node(cpu));
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

	return __COMPAT_scx_bpf_get_idle_smtmask_node(
		__COMPAT_scx_bpf_cpu_node(cpu));
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
 * Return the SMT sibling CPU of a @cpu.
 */
static s32 smt_sibling(s32 cpu)
{
	const struct cpumask *smt;
	struct cpu_ctx	     *cctx;

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
	bool		      is_contended;

	if (!smt_enabled)
		return false;

	/*
	 * If the sibling SMT CPU is not idle and there are other full-idle
	 * SMT cores available, consider the current CPU as contended.
	 */
	idle_mask    = get_idle_cpumask(cpu);
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
static s32 pick_idle_cpu_pref_smt(struct task_struct *p, s32 prev_cpu,
				  bool			is_prev_allowed,
				  const struct cpumask *primary,
				  const struct cpumask *smt)
{
	u64 max_cpus = MIN(nr_cpu_ids, MAX_CPUS);
	int i;

	if (is_prev_allowed &&
	    (!primary || bpf_cpumask_test_cpu(prev_cpu, primary)) &&
	    (!smt || bpf_cpumask_test_cpu(prev_cpu, smt)) &&
	    scx_bpf_test_and_clear_cpu_idle(prev_cpu))
		return prev_cpu;

	bpf_for(i, 0, max_cpus)
	{
		s32 cpu = preferred_cpus[i];

		if ((cpu == prev_cpu) ||
		    !bpf_cpumask_test_cpu(cpu, p->cpus_ptr))
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
	s32  cpu;

	primary = !primary_all ? cast_mask(primary_cpumask) : NULL;
	smt	= smt_enabled ? get_idle_smtmask(prev_cpu) : NULL;

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
			cpu = pick_idle_cpu_pref_smt(
				p, prev_cpu, is_prev_allowed, primary, smt);
			if (cpu >= 0)
				goto out;
		}

		/*
		 * Try to pick any idle CPU in the primary domain.
		 */
		cpu = pick_idle_cpu_pref_smt(p, prev_cpu, is_prev_allowed,
					     primary, NULL);
		if (cpu >= 0)
			goto out;
	}

	if (smt_enabled) {
		/*
		 * Try to pick any full-idle core in the system.
		 */
		cpu = pick_idle_cpu_pref_smt(p, prev_cpu, is_prev_allowed, NULL,
					     smt);
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
	s32		      cpu;

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
	if (!__COMPAT_HAS_scx_bpf_select_cpu_and) {
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
		cpu = scx_bpf_select_cpu_and(p, prev_cpu, wake_flags, primary,
					     0);
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
	const u64 q_thresh	    = MAX(STARVATION_THRESH / slice_max, 1);

	u64	  nr_queued	    = scx_bpf_dsq_nr_queued(cpu_dsq(cpu)) +
				      scx_bpf_dsq_nr_queued(node_dsq(cpu));
	u64	  lag_scale	    = MAX(tctx->wakeup_freq, 1);
	u64	  awake_max = scale_by_task_weight_inverse(p, slice_lag);
	u64	  vtime_min;

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
		lag_scale =
			MAX(lag_scale * q_thresh / (q_thresh + nr_queued), 1);

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
	u64 slice;

	/*
	 * Adjust time slice in function of the task's priority and the
	 * amount of tasks waiting to be dispatched, but never assign a
	 * time slice smaller than @slice_min.
	 */
	slice = scale_by_task_weight(p, slice_max) / MAX(nr_wait, 1);

	return MAX(slice, slice_min);
}

/*
 * TIMELY helpers (used only when timely_enabled=true)
 */

static void record_idle_pick_result(s32 cpu, s32 prev_cpu, bool from_enqueue)
{
	const struct cpumask *primary =
		!primary_all ? cast_mask(primary_cpumask) : NULL;

	if (cpu < 0) {
		__sync_fetch_and_add(&nr_idle_pick_failures, 1);
		return;
	}

	if (from_enqueue)
		__sync_fetch_and_add(&nr_idle_enqueue_path_picks, 1);
	else
		__sync_fetch_and_add(&nr_idle_select_path_picks, 1);

	if (cpu == prev_cpu)
		__sync_fetch_and_add(&nr_idle_prev_cpu_picks, 1);

	if (primary_all || !primary || bpf_cpumask_test_cpu(cpu, primary))
		__sync_fetch_and_add(&nr_idle_primary_picks, 1);
	else
		__sync_fetch_and_add(&nr_idle_spill_picks, 1);
}

static bool is_delay_pressured(const struct task_ctx *tctx)
{
	const u32 TIMELY_GAIN_ONE = 1024U;
	u64	  low_target, high_target;
	u32	  gain;
	s64	  gradient_margin;

	if (!tctx || !tctx->timely_avg_queue_delay)
		return false;

	low_target	= MAX(timely_tlow_ns, 1);
	high_target	= MAX(timely_thigh_ns, low_target + 1);
	gain		= tctx->timely_gain_fp ?: TIMELY_GAIN_ONE;
	gradient_margin = (s64)MAX(timely_gradient_margin_ns, 1);

	if (tctx->timely_avg_queue_delay > high_target)
		return true;

	if (tctx->timely_avg_queue_delay > low_target &&
	    (gain < TIMELY_GAIN_ONE ||
	     tctx->timely_avg_queue_gradient > gradient_margin))
		return true;

	return false;
}

static inline bool is_pressure_mode_active(const struct task_ctx *tctx)
{
	return tctx && tctx->v2_pressure_mode;
}

static void update_pressure_mode(struct task_ctx *tctx)
{
	if (!tctx || !v2_pressure_enter_streak || !v2_pressure_exit_streak)
		return;

	if (is_delay_pressured(tctx)) {
		if (tctx->v2_pressure_streak < v2_pressure_enter_streak)
			tctx->v2_pressure_streak++;
		tctx->v2_recovery_streak = 0;

		if (!tctx->v2_pressure_mode &&
		    tctx->v2_pressure_streak >= v2_pressure_enter_streak) {
			tctx->v2_pressure_mode = 1;
			__sync_fetch_and_add(&nr_v2_pressure_mode_entries, 1);
		}
		return;
	}

	tctx->v2_pressure_streak = 0;

	if (!tctx->v2_pressure_mode) {
		tctx->v2_recovery_streak = 0;
		return;
	}

	if (tctx->v2_recovery_streak < v2_pressure_exit_streak) {
		tctx->v2_recovery_streak++;
		return;
	}
	tctx->v2_pressure_mode	 = 0;
	tctx->v2_recovery_streak = 0;
	__sync_fetch_and_add(&nr_v2_pressure_mode_exits, 1);
}

static void update_global_pressure(const struct task_ctx *tctx)
{
	u32 expand_threshold, contract_threshold;
	u32 new_pressure, old_pressure;
	u32 primary_busy_pct;

	if (!v2_pressure_enter_streak || !v2_pressure_exit_streak)
		return;

	primary_busy_pct = 0;
	u32 online_cpus	 = READ_ONCE(nr_online_cpus);
	if (online_cpus > 0) {
		u64 running	 = READ_ONCE(nr_running);
		u64 product	 = running * 100ULL;
		primary_busy_pct = (u32)(product / online_cpus);
		primary_busy_pct = MIN(primary_busy_pct, 100U);
		__sync_val_compare_and_swap(&v2_primary_domain_busy,
					    v2_primary_domain_busy,
					    primary_busy_pct);
	}

	old_pressure = READ_ONCE(v2_global_pressure);
	new_pressure = old_pressure;

	if (tctx && is_delay_pressured(tctx)) {
		new_pressure = old_pressure - (old_pressure >> 2) + 25;
	} else {
		new_pressure = old_pressure - (old_pressure >> 3);
	}
	new_pressure = MIN(new_pressure, 100U);

	__sync_val_compare_and_swap(&v2_global_pressure, old_pressure,
				    new_pressure);

	u32 expand_th	= READ_ONCE(v2ExpandThreshold);
	u32 contract_th = READ_ONCE(v2ContractThreshold);

	if (expand_th == 0)
		expand_th = 1;
	if (contract_th >= expand_th)
		contract_th = expand_th - 1;

	expand_threshold   = expand_th;
	contract_threshold = contract_th;

	if (!v2_expand_mode) {
		if (new_pressure >= expand_threshold ||
		    primary_busy_pct >= expand_threshold) {
			if (__sync_val_compare_and_swap(&v2_expand_mode, 0,
							1) == 0) {
				__sync_fetch_and_add(&v2_expand_mode_entries,
						     1);
			}
		}
	} else {
		if (new_pressure < contract_threshold &&
		    primary_busy_pct < contract_threshold) {
			if (__sync_val_compare_and_swap(&v2_expand_mode, 1,
							0) == 1) {
				__sync_fetch_and_add(&v2_expand_mode_exits, 1);
			}
		}
	}
}

static inline bool is_expand_mode_active(void)
{
	return READ_ONCE(v2_expand_mode);
}

static bool should_expand_skip_locality(const struct task_ctx *tctx)
{
	if (is_expand_mode_active()) {
		if (!tctx)
			return true;
		bool wake_heavy = tctx->wakeup_freq >=
				  MAX(v2_locality_wakeup_freq, 1);
		if (wake_heavy)
			return false;
		return true;
	}

	if (tctx && tctx->v2_pressure_mode) {
		u32 primary_busy = READ_ONCE(v2_primary_domain_busy);
		if (primary_busy >= v2ExpandThreshold / 2)
			return true;
	}

	return false;
}

static u32 locality_fallback_kind(const struct task_struct *p,
				  const struct task_ctx *tctx, s32 prev_cpu,
				  bool *from_delay_pressure)
{
	u64  cpuq, nodeq;
	bool wake_heavy, delay_pressured;

	if (from_delay_pressure)
		*from_delay_pressure = false;

	if (!v2_locality_fallback || !tctx || is_pcpu_task(p))
		return V2_LOCALITY_NONE;

	wake_heavy	= tctx->wakeup_freq >= MAX(v2_locality_wakeup_freq, 1);
	delay_pressured = is_delay_pressured(tctx);
	if (!wake_heavy && !delay_pressured)
		return V2_LOCALITY_NONE;

	cpuq  = scx_bpf_dsq_nr_queued(cpu_dsq(prev_cpu));
	nodeq = scx_bpf_dsq_nr_queued(node_dsq(prev_cpu));

	if (cpuq <= v2_locality_max_cpuq && cpuq < nodeq)
		goto use_local;

	if (v2_locality_congested_nodeq &&
	    nodeq >= v2_locality_congested_nodeq &&
	    cpuq <= v2_locality_congested_max_cpuq)
		goto use_congested;

	return V2_LOCALITY_NONE;

use_local:
	if (from_delay_pressure)
		*from_delay_pressure = delay_pressured && !wake_heavy;
	return V2_LOCALITY_BASE;

use_congested:
	if (from_delay_pressure)
		*from_delay_pressure = delay_pressured && !wake_heavy;
	return V2_LOCALITY_CONGESTED;
}

static bool should_bias_local_head(const struct task_struct *p,
				   const struct task_struct *q,
				   bool *from_delay_pressure)
{
	struct task_ctx *tctx;
	bool		 wake_heavy, delay_pressured;
	u64		 slack, diff;

	if (from_delay_pressure)
		*from_delay_pressure = false;

	if (!v2_local_head_bias || !p || !q)
		return false;

	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return false;
	wake_heavy	= tctx->wakeup_freq >= MAX(v2_locality_wakeup_freq, 1);
	delay_pressured = is_delay_pressured(tctx);
	if (!wake_heavy && !delay_pressured)
		return false;
	if (p->scx.dsq_vtime <= q->scx.dsq_vtime)
		return false;

	slack = v2_local_head_bias_slack_ns;
	if (!slack)
		return false;

	diff = p->scx.dsq_vtime - q->scx.dsq_vtime;
	if (from_delay_pressure)
		*from_delay_pressure = delay_pressured && !wake_heavy;
	return diff <= slack;
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
 * Signed EWMA for delay gradient (can go negative).
 */
static s64 calc_avg_s64(s64 old_val, s64 new_val)
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
 * Return true if the task should be forced to stay on the same CPU, false
 * otherwise.
 */
static bool is_task_sticky(const struct task_ctx *tctx)
{
	return sticky_tasks && tctx->avg_runtime < 10 * NSEC_PER_USEC;
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
 * Consume and dispatch the first task from @dsq_id. If the first task can't be
 * dispatched on the corresponding DSQ, redirect the task to a proper CPU.
 */
static bool consume_first_task(u64 dsq_id, struct task_struct *p)
{
	if (!p)
		return false;

	return scx_bpf_dsq_move_to_local(dsq_id, 0);
}

/*
 * Pick a target CPU for a task which is being woken up.
 *
 * If a task is dispatched here, ops.enqueue() will be skipped: task will be
 * dispatched directly to the CPU returned by this callback.
 */
static s32 do_bpfland_select_cpu(struct task_struct *p, s32 prev_cpu,
				 u64 wake_flags)
{
	s32  cpu, this_cpu = bpf_get_smp_processor_id();
	bool is_this_cpu_allowed = bpf_cpumask_test_cpu(this_cpu, p->cpus_ptr);

	/*
	 * Make sure @prev_cpu is usable, otherwise try to move close to
	 * the waker's CPU. If the waker's CPU is also not usable, then
	 * pick the first usable CPU.
	 */
	if (!bpf_cpumask_test_cpu(prev_cpu, p->cpus_ptr))
		prev_cpu = is_this_cpu_allowed ? this_cpu :
						 bpf_cpumask_first(p->cpus_ptr);

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
						 task_slice(p, cpu),
						 task_dl(p, cpu, tctx), 0);
			__sync_fetch_and_add(&nr_direct_dispatches, 1);
		}
		return cpu;
	}

	return prev_cpu;
}

/*
 * Dispatch all the other tasks that were not dispatched directly in
 * select_cpu().
 */
static void do_bpfland_enqueue(struct task_struct *p, u64 enq_flags)
{
	s32		 prev_cpu = scx_bpf_task_cpu(p);
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
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, task_slice(p, prev_cpu),
				   enq_flags);
		__sync_fetch_and_add(&nr_direct_dispatches, 1);
		return;
	}

	/*
	 * If @local_kthread is specified dispatch per-CPU kthreads
	 * directly on their assigned CPU bypassing the per-CPU and
	 * per-node DSQs.
	 */
	if (local_kthreads && is_kthread(p) && p->nr_cpus_allowed == 1) {
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, task_slice(p, prev_cpu),
				   enq_flags);
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
			scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL,
					   task_slice(p, prev_cpu), enq_flags);
		else
			scx_bpf_dsq_insert_vtime(p, cpu_dsq(prev_cpu),
						 task_slice(p, prev_cpu),
						 task_dl(p, prev_cpu, tctx),
						 enq_flags);
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
			cpu = scx_bpf_test_and_clear_cpu_idle(prev_cpu) ?
				      prev_cpu :
				      -EBUSY;
		else
			cpu = pick_idle_cpu(p, prev_cpu, -1, 0, true);

		if (cpu >= 0) {
			scx_bpf_dsq_insert_vtime(p, cpu_dsq(cpu),
						 task_slice(p, cpu),
						 task_dl(p, cpu, tctx),
						 enq_flags);
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
	scx_bpf_dsq_insert_vtime(p, node_dsq(prev_cpu), task_slice(p, prev_cpu),
				 task_dl(p, prev_cpu, tctx), enq_flags);
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

static void do_bpfland_dispatch(s32 cpu, struct task_struct *prev)
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
		if (consume_first_task(cpu_dsq(cpu), p) ||
		    consume_first_task(node_dsq(cpu), q))
			return;
	} else {
		if (consume_first_task(node_dsq(cpu), q) ||
		    consume_first_task(cpu_dsq(cpu), p))
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
	u64		now = bpf_ktime_get_ns();
	s32		cpu = scx_bpf_task_cpu(p);
	u64		perf_lvl, delta_runtime, delta_t;
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
	perf_lvl =
		MIN(delta_runtime * SCX_CPUPERF_ONE / delta_t, SCX_CPUPERF_ONE);
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

static void do_bpfland_running(struct task_struct *p)
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
static void do_bpfland_stopping(struct task_struct *p, bool runnable)
{
	u64 now = bpf_ktime_get_ns(), slice, delta_vtime, delta_runtime;
	s32 cpu = scx_bpf_task_cpu(p);
	struct task_ctx *tctx;
	struct cpu_ctx	*cctx;

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

static void do_bpfland_runnable(struct task_struct *p, u64 enq_flags)
{
	u64		 now = bpf_ktime_get_ns(), delta_t;
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
	tctx->wakeup_freq  = update_freq(tctx->wakeup_freq, delta_t);
	tctx->wakeup_freq  = MIN(tctx->wakeup_freq, MAX_WAKEUP_FREQ);
	tctx->last_woke_at = now;
}

static void do_bpfland_enable(struct task_struct *p)
{
	/*
	 * Initialize the task vruntime to the current global vruntime.
	 */
	p->scx.dsq_vtime = vtime_now;
}

static s32 do_bpfland_init_task(struct task_struct	  *p,
				struct scx_init_task_args *args)
{
	struct task_ctx *tctx;

	tctx = bpf_task_storage_get(&task_ctx_stor, p, 0,
				    BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!tctx)
		return -ENOMEM;

	return 0;
}

static void do_bpfland_exit(struct scx_exit_info *ei)
{
	UEI_RECORD(uei, ei);
}

/*
 * Evaluate the amount of online CPUs.
 */
static s32 get_nr_online_cpus(void)
{
	const struct cpumask *online_cpumask;
	int		      cpus;

	online_cpumask = scx_bpf_get_online_cpumask();
	cpus	       = bpf_cpumask_weight(online_cpumask);
	scx_bpf_put_cpumask(online_cpumask);

	return cpus;
}

static int init_cpumask(struct bpf_cpumask **cpumask)
{
	struct bpf_cpumask *mask;
	int		    err = 0;

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
	struct cpu_ctx	   *cctx;
	struct bpf_cpumask *mask, **pmask;
	int		    err = 0;

	cctx			= try_lookup_cpu_ctx(input->cpu_id);
	if (!cctx)
		return -ENOENT;

	pmask = &cctx->smt;
	err   = init_cpumask(pmask);
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
	int		    err = 0;

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
	u64		      perf_lvl;
	s32		      cpu;

	online_cpumask = scx_bpf_get_online_cpumask();
	bpf_for(cpu, 0, nr_cpu_ids)
	{
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
	u64  flags, duration;
	s32  cpu;
	int  err;

	/*
	 * Stop the CPUs sending a preemption IPI (SCX_KICK_PREEMPT) if we
	 * need to interrupt the running tasks and inject the idle sleep.
	 *
	 * Otherwise, send a wakeup IPI to resume from the injected idle
	 * sleep.
	 */
	if (throttled) {
		flags	 = SCX_KICK_IDLE;
		duration = slice_max;
	} else {
		flags	 = SCX_KICK_PREEMPT;
		duration = throttle_ns;
	}

	/*
	 * Flip the throttled state.
	 */
	set_throttled(!throttled);

	bpf_for(cpu, 0, nr_cpu_ids) scx_bpf_kick_cpu(cpu, flags);

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
	int		  err, i;
	u32		  key = 0;

	/* Initialize amount of online and possible CPUs */
	nr_online_cpus = get_nr_online_cpus();
	nr_cpu_ids     = scx_bpf_nr_cpu_ids();

	/* Initialize CPUs and NUMA properties */
	init_cpuperf_target();

	/*
	 * Create the per-CPU DSQs.
	 */
	bpf_for(i, 0, nr_cpu_ids)
	{
		int node   = __COMPAT_scx_bpf_cpu_node(i);
		u64 dsq_id = i;

		err	   = scx_bpf_create_dsq(dsq_id, node);
		if (err) {
			scx_bpf_error("failed to create DSQ %llu: %d", dsq_id,
				      err);
			return err;
		}
	}

	/*
	 * Create the per-node DSQs.
	 */
	bpf_for(i, 0, __COMPAT_scx_bpf_nr_node_ids())
	{
		u64 dsq_id = nr_cpu_ids + i;

		err	   = scx_bpf_create_dsq(dsq_id, i);
		if (err) {
			scx_bpf_error("failed to create DSQ %llu: %d", dsq_id,
				      err);
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

/*
 * TIMELY op implementations (used when timely_enabled=true)
 */

static s32 do_timely_select_cpu(struct task_struct *p, s32 prev_cpu,
				u64 wake_flags)
{
	s32  cpu, this_cpu = bpf_get_smp_processor_id();
	bool is_this_cpu_allowed = bpf_cpumask_test_cpu(this_cpu, p->cpus_ptr);

	if (!bpf_cpumask_test_cpu(prev_cpu, p->cpus_ptr))
		prev_cpu = is_this_cpu_allowed ? this_cpu :
						 bpf_cpumask_first(p->cpus_ptr);

	cpu = pick_idle_cpu(p, prev_cpu, is_this_cpu_allowed ? this_cpu : -1,
			    wake_flags, false);
	record_idle_pick_result(cpu, prev_cpu, false);
	if (cpu >= 0) {
		struct task_ctx *tctx;

		tctx = try_lookup_task_ctx(p);
		if (!tctx)
			return cpu;
		scx_bpf_dsq_insert_vtime(p, cpu_dsq(cpu),
					 task_slice(p, cpu),
					 task_dl(p, cpu, tctx), 0);
		__sync_fetch_and_add(&nr_direct_dispatches, 1);
		return cpu;
	}

	return prev_cpu;
}

static void do_timely_enqueue(struct task_struct *p, u64 enq_flags)
{
	s32		 prev_cpu		      = scx_bpf_task_cpu(p);
	bool		 locality_from_delay_pressure = false;
	bool		 pressure_mode_active;
	u32		 fallback_kind = V2_LOCALITY_NONE;
	struct task_ctx *tctx;

	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return;
	pressure_mode_active	      = is_pressure_mode_active(tctx);
	tctx->timely_last_enqueued_at = bpf_ktime_get_ns();

	if (is_task_sticky(tctx)) {
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, task_slice(p, prev_cpu),
				   enq_flags);
		__sync_fetch_and_add(&nr_direct_dispatches, 1);
		return;
	}

	if (local_kthreads && is_kthread(p) && p->nr_cpus_allowed == 1) {
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, task_slice(p, prev_cpu),
				   enq_flags);
		__sync_fetch_and_add(&nr_kthread_dispatches, 1);
		return;
	}

	if (is_pcpu_task(p)) {
		if (local_pcpu)
			scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL,
					   task_slice(p, prev_cpu), enq_flags);
		else
			scx_bpf_dsq_insert_vtime(p, cpu_dsq(prev_cpu),
						 task_slice(p, prev_cpu),
						 task_dl(p, prev_cpu, tctx),
						 enq_flags);
		__sync_fetch_and_add(&nr_direct_dispatches, 1);
		return;
	}

	if (task_should_migrate(p, enq_flags)) {
		s32 cpu;

		if (is_pcpu_task(p))
			cpu = scx_bpf_test_and_clear_cpu_idle(prev_cpu) ?
				      prev_cpu :
				      -EBUSY;
		else
			cpu = pick_idle_cpu(p, prev_cpu, -1, 0, true);
		record_idle_pick_result(cpu, prev_cpu, true);

		if (cpu >= 0) {
			scx_bpf_dsq_insert_vtime(p, cpu_dsq(cpu),
						 task_slice(p, cpu),
						 task_dl(p, cpu, tctx),
						 enq_flags);
			__sync_fetch_and_add(&nr_direct_dispatches, 1);

			if (prev_cpu != cpu || !scx_bpf_task_running(p))
				scx_bpf_kick_cpu(cpu, SCX_KICK_IDLE);
			return;
		}

		if (!should_expand_skip_locality(tctx))
			fallback_kind = locality_fallback_kind(
				p, tctx, prev_cpu,
				&locality_from_delay_pressure);
	}

	if (fallback_kind != V2_LOCALITY_NONE) {
		scx_bpf_dsq_insert_vtime(p, cpu_dsq(prev_cpu),
					 task_slice(p, prev_cpu),
					 task_dl(p, prev_cpu, tctx), enq_flags);
		__sync_fetch_and_add(&nr_direct_dispatches, 1);
		__sync_fetch_and_add(&nr_v2_locality_cpu_dispatches, 1);
		if (fallback_kind == V2_LOCALITY_CONGESTED)
			__sync_fetch_and_add(
				&nr_v2_congested_locality_cpu_dispatches, 1);
		if (locality_from_delay_pressure)
			__sync_fetch_and_add(
				&nr_v2_delay_locality_cpu_dispatches, 1);
		scx_bpf_kick_cpu(prev_cpu, SCX_KICK_IDLE);
		return;
	}

	scx_bpf_dsq_insert_vtime(p, node_dsq(prev_cpu), task_slice(p, prev_cpu),
				 task_dl(p, prev_cpu, tctx), enq_flags);
	__sync_fetch_and_add(&nr_shared_dispatches, 1);
	if (is_expand_mode_active()) {
		__sync_fetch_and_add(&nr_v2_expand_mode_dispatches, 1);
	} else {
		__sync_fetch_and_add(&nr_v2_contract_mode_dispatches, 1);
	}
	if (pressure_mode_active)
		__sync_fetch_and_add(&nr_v2_pressure_shared_dispatches, 1);

	if (task_should_migrate(p, enq_flags))
		scx_bpf_kick_cpu(prev_cpu, SCX_KICK_IDLE);
}

static bool timely_keep_running(const struct task_struct *p, s32 cpu)
{
	if (!is_task_queued(p)) {
		__sync_fetch_and_add(&nr_keep_running_queue_empty, 1);
		return false;
	}

	if (is_pcpu_task(p))
		return true;

	if (is_smt_contended(cpu)) {
		__sync_fetch_and_add(&nr_keep_running_smt_blocked, 1);
		return false;
	}

	return true;
}

static void do_timely_cpu_release(s32 cpu, struct scx_cpu_release_args *args)
{
	scx_bpf_reenqueue_local();
	__sync_fetch_and_add(&nr_cpu_release_reenqueue, 1);
}

static void do_timely_dispatch(s32 cpu, struct task_struct *prev)
{
	struct task_struct *p = __COMPAT_scx_bpf_dsq_peek(cpu_dsq(cpu));
	struct task_struct *q = __COMPAT_scx_bpf_dsq_peek(node_dsq(cpu));
	bool		    had_queued_work = (p || q);
	bool		    consumed	    = false;
	bool local_head_bias = should_bias_local_head(p, q, NULL);

	if (is_throttled())
		return;

	if (local_head_bias || !is_deadline_min(q, p)) {
		if (consume_first_task(cpu_dsq(cpu), p)) {
			__sync_fetch_and_add(&nr_dispatch_cpu_dsq_consumes, 1);
			if (local_head_bias)
				__sync_fetch_and_add(&nr_v2_local_head_biases,
						     1);
			consumed = true;
			return;
		}
		if (consume_first_task(node_dsq(cpu), q)) {
			__sync_fetch_and_add(&nr_dispatch_node_dsq_consumes, 1);
			consumed = true;
			return;
		}
	} else {
		if (consume_first_task(node_dsq(cpu), q)) {
			__sync_fetch_and_add(&nr_dispatch_node_dsq_consumes, 1);
			consumed = true;
			return;
		}
		if (consume_first_task(cpu_dsq(cpu), p)) {
			__sync_fetch_and_add(&nr_dispatch_cpu_dsq_consumes, 1);
			consumed = true;
			return;
		}
	}

	if (prev && !consumed && !had_queued_work &&
	    timely_keep_running(prev, cpu)) {
		__sync_fetch_and_add(&nr_keep_running_reuses, 1);
		prev->scx.slice = task_slice(prev, cpu);
	} else if (prev && !consumed && had_queued_work) {
		__sync_fetch_and_add(&nr_keep_running_queued_work, 1);
	}
}

static void do_timely_running(struct task_struct *p)
{
	u64		 now = bpf_ktime_get_ns();
	struct task_ctx *tctx;

	__sync_fetch_and_add(&nr_running, 1);

	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return;

	tctx->last_run_at = now;

	update_cpu_load(p, tctx);

	if (time_before(vtime_now, p->scx.dsq_vtime))
		vtime_now = p->scx.dsq_vtime;

	/*
	 * TIMELY delay tracking: evaluate queue delay and update gain.
	 */
	if (tctx->timely_last_enqueued_at > 0) {
		u64  delay	      = now - tctx->timely_last_enqueued_at;
		u64  low_target	      = MAX(timely_tlow_ns, 1);
		u64  high_target      = MAX(timely_thigh_ns, low_target + 1);
		u64  control_interval = timely_control_interval_ns;
		u32  old_gain	      = tctx->timely_gain_fp ?: 1024U;
		bool gain_changed     = false;

		if (old_gain <= timely_gain_min_fp) {
			__sync_fetch_and_add(&nr_gain_floor_resident_samples,
					     1);
		} else if (old_gain >= 1024U) {
			__sync_fetch_and_add(&nr_gain_ceiling_resident_samples,
					     1);
		} else {
			__sync_fetch_and_add(&nr_gain_mid_resident_samples, 1);
		}

		if (tctx->timely_avg_queue_delay > high_target) {
			__sync_fetch_and_add(&nr_delay_high_region_samples, 1);
		} else if (tctx->timely_avg_queue_delay <= low_target) {
			__sync_fetch_and_add(&nr_delay_low_region_samples, 1);
		} else {
			__sync_fetch_and_add(&nr_delay_mid_region_samples, 1);
		}

		if (tctx->timely_last_gain_update_at &&
		    tctx->timely_last_delay_sample_at -
				    tctx->timely_last_gain_update_at <
			    control_interval) {
			__sync_fetch_and_add(&nr_delay_rate_limited_dispatches,
					     1);
		} else {
			s64 gradient =
				(s64)delay - (s64)tctx->timely_avg_queue_delay;
			u32 action   = 0;
			u32 new_gain = old_gain;

			if (delay > high_target) {
				if (old_gain < timely_gain_max_fp) {
					new_gain = MIN(
						old_gain + timely_gain_step_fp,
						timely_gain_max_fp);
					action = 1;
					if (new_gain >= timely_gain_max_fp)
						__sync_fetch_and_add(
							&nr_gain_ceiling_dispatches,
							1);
				} else {
					__sync_fetch_and_add(
						&nr_gain_ceiling_dispatches, 1);
				}
			} else if (delay < low_target) {
				if (old_gain > timely_gain_min_fp) {
					if (gradient < 0 &&
					    old_gain >=
						    timely_gain_step_fp +
							    timely_gain_min_fp) {
						new_gain = old_gain -
							   timely_gain_step_fp;
						action	 = 2;
					} else if (gradient >= 0) {
						new_gain = old_gain -
							   (old_gain >> 3);
						action	 = 3;
					}
				}
				if (action == 0 || action == 3)
					__sync_fetch_and_add(
						&nr_delay_rate_limited_dispatches,
						1);
			} else {
				u32 hai_th = timely_hai_thresh_fp;
				if (gradient > 0 && old_gain < hai_th) {
					new_gain = MIN(
						old_gain *
							timely_hai_multiplier,
						timely_gain_max_fp);
					action = 4;
					__sync_fetch_and_add(
						&nr_delay_rate_limited_dispatches,
						1);
				} else if (gradient < 0 && old_gain < hai_th) {
					new_gain =
						old_gain + timely_gain_step_fp;
					action = 5;
				} else if (old_gain < 1024U) {
					new_gain = old_gain +
						   (1024U - old_gain) / 8;
					action	 = 6;
				}
			}

			if (new_gain != old_gain) {
				tctx->timely_gain_fp		 = new_gain;
				tctx->timely_last_gain_update_at = now;
				gain_changed			 = true;
			}

			tctx->timely_avg_queue_delay =
				calc_avg(tctx->timely_avg_queue_delay, delay);
			tctx->timely_avg_queue_gradient = calc_avg_s64(
				tctx->timely_avg_queue_gradient, gradient);

			if (gain_changed) {
				if (action == 1 || action == 5 || action == 6)
					__sync_fetch_and_add(
						&nr_delay_recovery_dispatches,
						1);
				else if (action == 2 || action == 4)
					__sync_fetch_and_add(
						&nr_delay_fast_recovery_dispatches,
						1);
				else if (action == 3)
					__sync_fetch_and_add(
						&nr_delay_middle_add_dispatches,
						1);
			}

			if (new_gain <= timely_gain_min_fp)
				__sync_fetch_and_add(&nr_gain_floor_dispatches,
						     1);
			if (new_gain >= timely_gain_max_fp)
				__sync_fetch_and_add(
					&nr_gain_ceiling_dispatches, 1);
		}

		tctx->timely_last_delay_sample_at = now;
		tctx->timely_last_enqueued_at	  = 0;
		update_pressure_mode(tctx);
		update_global_pressure(tctx);
	}
}

static void do_timely_stopping(struct task_struct *p, bool runnable)
{
	u64 now = bpf_ktime_get_ns(), slice, delta_vtime, delta_runtime;
	s32 cpu = scx_bpf_task_cpu(p);
	struct task_ctx *tctx;
	struct cpu_ctx	*cctx;

	__sync_fetch_and_sub(&nr_running, 1);

	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return;

	slice		  = now - tctx->last_run_at;

	tctx->avg_runtime = calc_avg(tctx->avg_runtime, slice);

	delta_vtime	  = scale_by_task_weight_inverse(p, slice);
	p->scx.dsq_vtime += delta_vtime;
	tctx->awake_vtime += delta_vtime;

	cctx = try_lookup_cpu_ctx(cpu);
	if (!cctx)
		return;
	delta_runtime = now - cctx->last_running;
	cctx->tot_runtime += delta_runtime;
}

static void do_timely_runnable(struct task_struct *p, u64 enq_flags)
{
	u64		 now = bpf_ktime_get_ns(), delta_t;
	struct task_ctx *tctx;

	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return;

	tctx->awake_vtime = 0;

	delta_t = now > tctx->last_woke_at ? now - tctx->last_woke_at : 1;
	tctx->wakeup_freq  = update_freq(tctx->wakeup_freq, delta_t);
	tctx->wakeup_freq  = MIN(tctx->wakeup_freq, MAX_WAKEUP_FREQ);
	tctx->last_woke_at = now;
}

static void do_timely_exit(struct scx_exit_info *ei)
{
	UEI_RECORD(uei, ei);
}

/*
 * Dispatch wrappers that call either bpfland or timely implementation
 * based on the timely_enabled flag.
 */
s32 BPF_STRUCT_OPS(dispatch_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
	if (timely_enabled)
		return do_timely_select_cpu(p, prev_cpu, wake_flags);
	return do_bpfland_select_cpu(p, prev_cpu, wake_flags);
}

void BPF_STRUCT_OPS(dispatch_enqueue, struct task_struct *p, u64 enq_flags)
{
	if (timely_enabled)
		do_timely_enqueue(p, enq_flags);
	else
		do_bpfland_enqueue(p, enq_flags);
}

void BPF_STRUCT_OPS(dispatch_dispatch, s32 cpu, struct task_struct *prev)
{
	if (timely_enabled)
		do_timely_dispatch(cpu, prev);
	else
		do_bpfland_dispatch(cpu, prev);
}

void BPF_STRUCT_OPS(dispatch_running, struct task_struct *p)
{
	if (timely_enabled)
		do_timely_running(p);
	else
		do_bpfland_running(p);
}

void BPF_STRUCT_OPS(dispatch_stopping, struct task_struct *p, bool runnable)
{
	if (timely_enabled)
		do_timely_stopping(p, runnable);
	else
		do_bpfland_stopping(p, runnable);
}

void BPF_STRUCT_OPS(dispatch_runnable, struct task_struct *p, u64 enq_flags)
{
	if (timely_enabled)
		do_timely_runnable(p, enq_flags);
	else
		do_bpfland_runnable(p, enq_flags);
}

void BPF_STRUCT_OPS(dispatch_enable, struct task_struct *p)
{
	do_bpfland_enable(p);
}

s32 BPF_STRUCT_OPS(dispatch_init_task, struct task_struct *p, struct scx_init_task_args *args)
{
	return do_bpfland_init_task(p, args);
}

void BPF_STRUCT_OPS(dispatch_cpu_release, s32 cpu, struct scx_cpu_release_args *args)
{
	if (timely_enabled)
		do_timely_cpu_release(cpu, args);
}

void BPF_STRUCT_OPS(dispatch_exit, struct scx_exit_info *ei)
{
	if (timely_enabled)
		do_timely_exit(ei);
	else
		do_bpfland_exit(ei);
}

SCX_OPS_DEFINE(bpfland_ops, .select_cpu = (void *)dispatch_select_cpu,
	       .enqueue	  = (void *)dispatch_enqueue,
	       .dispatch  = (void *)dispatch_dispatch,
	       .cpu_release = (void *)dispatch_cpu_release,
	       .running	  = (void *)dispatch_running,
	       .stopping  = (void *)dispatch_stopping,
	       .runnable  = (void *)dispatch_runnable,
	       .enable	  = (void *)dispatch_enable,
	       .init_task = (void *)dispatch_init_task,
	       .init = (void *)bpfland_init, .exit = (void *)dispatch_exit,
	       .timeout_ms = STARVATION_MS, .name = "bpfland");
