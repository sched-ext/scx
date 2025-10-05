/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2024 Andrea Righi <andrea.righi@linux.dev>
 */
#include <scx/common.bpf.h>
#include "intf.h"

#define MAX_VTIME	(~0ULL)

#define DSQ_FLAG_NODE	(1LLU << 32)

extern unsigned CONFIG_HZ __kconfig;

/*
 * Return the time interval between two ticks in ns.
 */
static inline u64 tick_interval_ns(void)
{
	return NSEC_PER_SEC / CONFIG_HZ;
}

/*
 * Thresholds for applying hysteresis to CPU performance scaling:
 *  - CPUFREQ_LOW_THRESH: below this level, reduce performance to minimum
 *  - CPUFREQ_HIGH_THRESH: above this level, raise performance to maximum
 *
 * Values between the two thresholds retain the current smoothed performance level.
 */
#define CPUFREQ_LOW_THRESH	(SCX_CPUPERF_ONE / 4)
#define CPUFREQ_HIGH_THRESH	(SCX_CPUPERF_ONE - SCX_CPUPERF_ONE / 4)

const volatile u64 __COMPAT_SCX_PICK_IDLE_IN_NODE;

char _license[] SEC("license") = "GPL";

/* Allow to use bpf_printk() only when @debug is set */
#define dbg_msg(_fmt, ...) do {				\
	if (debug)					\
		bpf_printk(_fmt, ##__VA_ARGS__);	\
} while(0)

 /* Report additional debugging information */
const volatile bool debug;

/* Enable round-robin mode */
const volatile bool rr_sched;

/* Primary domain includes all CPU */
const volatile bool primary_all = true;

/*
 * Default task time slice.
 */
const volatile u64 slice_max = 4096ULL * NSEC_PER_USEC;

/*
 * Time slice used when system is over commissioned.
 */
const volatile u64 slice_min = 128ULL * NSEC_PER_USEC;

/*
 * Maximum runtime budget that a task can accumulate while sleeping (used
 * to determine the task's minimum vruntime).
 */
const volatile u64 slice_lag = 4096ULL * NSEC_PER_USEC;

/*
 * Adjust the maximum sleep budget in function of the average CPU
 * utilization.
 */
const volatile bool slice_lag_scaling;

/*
 * Maximum runtime penalty that a task can accumulate while running (used
 * to determine the task's maximum exec_vruntime: accumulated vruntime
 * since last sleep).
 */
const volatile u64 run_lag = 32768ULL * NSEC_PER_USEC;

/*
 * Maximum amount of voluntary context switches (this limit allows to prevent
 * spikes or abuse of the nvcsw dynamic).
 */
const volatile u64 max_avg_nvcsw = 128ULL;

/*
 * CPU utilization threshold to consider the CPU as busy.
 */
const volatile s64 cpu_busy_thresh = -1LL;

/*
 * Current CPU user utilization (evaluated from user-space).
 */
volatile u64 cpu_util;

/*
 * Ignore synchronous wakeup events.
 */
const volatile bool no_wake_sync;

/*
 * When enabled always dispatch per-CPU kthreads directly.
 *
 * This allows to prioritize critical kernel threads that may potentially slow
 * down the entire system if they are blocked for too long, but it may also
 * introduce interactivity issues or unfairness in scenarios with high kthread
 * activity, such as heavy I/O or network traffic.
 */
const volatile bool local_kthreads;

/*
 * If set, keep reusing the same CPU even if it's not in the primary
 * scheduling domain.
 */
const volatile bool sticky_cpu;

/*
 * Prioritize per-CPU tasks (tasks that can only run on a single CPU).
 *
 * Enabling this option allows to prioritize per-CPU tasks that usually
 * tend to be de-prioritized, since they can't be migrated when their only
 * usable CPU is busy.
 *
 * This is implemented by disabling direct dispatch when there are tasks
 * queued to the per-CPU DSQ or the per-node DSQ. In this way, per-CPU
 * tasks waiting in those queues are scheduled based solely on their
 * deadline, avoiding further delays caused by direct dispatches.
 */
const volatile bool local_pcpu;

/*
 * Always directly dispatch a task if an idle CPU is found.
 */
const volatile bool direct_dispatch;

/*
 * Enable built-in idle CPU selection policy.
 */
const volatile bool builtin_idle;

/*
 * Native tasks priorities.
 *
 * By default, the scheduler normalizes task priorities to avoid large gaps
 * that could lead to stalls or starvation. This option disables
 * normalization and uses the default Linux priority range instead.
 */
const volatile bool native_priority;

/*
 * Enable tickless mode.
 */
const volatile bool tickless_sched;

/*
 * The CPU frequency performance level: a negative value will not affect the
 * performance level and will be ignored.
 */
volatile s64 cpufreq_perf_lvl;

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
private(FLASH) struct bpf_cpumask __kptr *primary_cpumask;

/*
 * CPUs in the system have SMT is enabled.
 */
const volatile bool smt_enabled = true;

/*
 * Disable NUMA rebalancing.
 */
const volatile bool numa_disabled = false;

/*
 * Current global vruntime.
 */
static u64 vtime_now;

/*
 * Timer used to update NUMA statistics.
 */
struct numa_timer {
	struct bpf_timer timer;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct numa_timer);
} numa_timer SEC(".maps");

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
 * Timer used to preempt CPUs in tickless mode.
 */
struct tickless_timer {
	struct bpf_timer timer;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct tickless_timer);
} tickless_timer SEC(".maps");

/*
 * Per-node context.
 */
struct node_ctx {
	u64 tot_perf_lvl;
	u64 nr_cpus;
	u64 perf_lvl;
	bool need_rebalance;
};

/* CONFIG_NODES_SHIFT should be always <= 10 */
#define MAX_NUMA_NODES	1024

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, int);
	__type(value, struct node_ctx);
	__uint(max_entries, MAX_NUMA_NODES);
	__uint(map_flags, 0);
} node_ctx_stor SEC(".maps");

/*
 * Return a node context.
 */
struct node_ctx *try_lookup_node_ctx(int node)
{
	return bpf_map_lookup_elem(&node_ctx_stor, &node);
}

/*
 * Return true if @node needs a rebalance, false otherwise.
 */
static bool node_rebalance(int node)
{
	const struct node_ctx *nctx;

	if (numa_disabled)
		return false;

	nctx = try_lookup_node_ctx(node);
	if (!nctx)
		return false;

	return nctx->need_rebalance;
}

/*
 * Per-CPU context.
 */
struct cpu_ctx {
	u64 tot_runtime;
	u64 prev_runtime;
	u64 last_running;
	u64 perf_lvl;
	struct bpf_cpumask __kptr *smt_cpumask;
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
	/*
	 * Temporary cpumask for calculating scheduling domains.
	 */
	struct bpf_cpumask __kptr *cpumask;
	struct bpf_cpumask __kptr *l2_cpumask;
	struct bpf_cpumask __kptr *l3_cpumask;

	/*
	 * Task's average used time slice.
	 */
	u64 exec_runtime;
	u64 last_run_at;

	/*
	 * Voluntary context switches metrics.
	 */
	u64 avg_nvcsw;
	u64 last_sleep_at;

	/*
	 * Task's recently used CPU: used to determine whether we need to
	 * refresh the task's cpumasks.
	 */
	s32 recent_used_cpu;

	/*
	 * Keep track of the last waker.
	 */
	u32 waker_pid;
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
 * Return true if the target task @p is a kernel thread.
 */
static inline bool is_kthread(const struct task_struct *p)
{
	return p->flags & PF_KTHREAD;
}

/*
 * Return true if @p can only run on a single CPU, false otherwise.
 */
static bool is_pcpu_task(const struct task_struct *p)
{
	return p->nr_cpus_allowed == 1 || is_migration_disabled(p);
}

/*
 * Return true if @p still wants to run, false otherwise.
 */
static bool is_queued(const struct task_struct *p)
{
	return p->scx.flags & SCX_TASK_QUEUED;
}

/*
 * Return the cpumask of full-idle SMT CPUs associated to @node.
 *
 * If NUMA support is disabled, @node is ignored.
 */
static const struct cpumask *get_idle_smtmask_node(int node)
{
	return numa_disabled ? scx_bpf_get_idle_smtmask() :
			       __COMPAT_scx_bpf_get_idle_smtmask_node(node);
}

/*
 * Return the cpumask of idle CPUs associated to @node.
 *
 * If NUMA support is disabled, @node is ignored.
 */
static const struct cpumask *get_idle_cpumask_node(int node)
{
	return numa_disabled ? scx_bpf_get_idle_cpumask() :
			       __COMPAT_scx_bpf_get_idle_cpumask_node(node);
}

/*
 * Return an idle CPU within the @cpus_allowed mask and @node.
 *
 * If NUMA support is disabled, @node is ignored.
 */
static s32 pick_idle_cpu_node(const struct cpumask *cpus_allowed, int node, u64 flags)
{
	return numa_disabled ?
		scx_bpf_pick_idle_cpu(cpus_allowed, flags) :
	       __COMPAT_scx_bpf_pick_idle_cpu_node(cpus_allowed, node, flags);
}

/*
 * Return true if @cpu is in a full-idle physical core,
 * false otherwise.
 */
static bool is_fully_idle(s32 cpu)
{
	const struct cpumask *idle_smtmask;
	int node = __COMPAT_scx_bpf_cpu_node(cpu);
	bool is_idle;

	idle_smtmask = get_idle_smtmask_node(node);
	is_idle = bpf_cpumask_test_cpu(cpu, idle_smtmask);
	scx_bpf_put_cpumask(idle_smtmask);

	return is_idle;
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
 * Return the DSQ associated to @cpu.
 */
static inline u64 cpu_to_dsq(s32 cpu)
{
	return (u64)cpu;
}

/*
 * Return the DSQ associated to @node.
 */
static inline u64 node_to_dsq(int node)
{
	return DSQ_FLAG_NODE | node;
}

/*
 * Return the total amount of tasks that are currently waiting to be scheduled.
 */
static inline u64 nr_tasks_waiting(s32 cpu)
{
	int node = __COMPAT_scx_bpf_cpu_node(cpu);

	return scx_bpf_dsq_nr_queued(SCX_DSQ_LOCAL_ON | cpu) +
	       scx_bpf_dsq_nr_queued(cpu_to_dsq(cpu)) +
	       scx_bpf_dsq_nr_queued(node_to_dsq(node));
}

/*
 * Return the time slice that can be assigned to a task queued to @dsq_id
 * DSQ.
 */
static inline u64 task_slice(const struct task_struct *p, s32 cpu)
{
	u64 nr_wait = nr_tasks_waiting(cpu);

	/*
	 * Scale by task weight only when -n / native_priority is set.
	 * Since we don't have preemption, if there's a big gap between
	 * priorities certain tasks may get a really long time slice and
	 * this can hurt interactivity.
	 */
	u64 smax = native_priority ? scale_by_task_weight(p, slice_max) : slice_max;

	if (!nr_wait)
		return tickless_sched ? SCX_SLICE_INF : smax;

	return MAX(smax / nr_wait, slice_min);
}

/*
 * Return the task's weight, normalized into a smaller domain.
 *
 * Original weight range:   [1, 10000], default = 100
 * Normalized weight range: [1, 128], default = 64
 *
 * This normalization reduces the impact of extreme weight differences,
 * preventing highly prioritized tasks from starving lower-priority ones.
 *
 * The goal is to ensure a more balanced scheduling that is influenced more
 * by the task's behavior rather than its priority difference and prevent
 * potential stalls due to large priority gaps.
 */
static inline u64 task_weight(const struct task_struct *p)
{
	/*
	 * Return the non-normalized task weight if @native_priority is
	 * enabled.
	 */
	if (native_priority)
		return p->scx.weight;

	return 1 + (127 * log2_u64(p->scx.weight) / log2_u64(10000));
}

/*
 * Return the default task weight.
 */
static inline u64 task_base_weight(void)
{
	return native_priority ? 100 : 64;
}

/*
 * Scale a value proportional to the task's normalized weight.
 */
static inline u64 scale_by_task_normalized_weight(const struct task_struct *p, u64 value)
{
	return value * task_weight(p) / task_base_weight();
}

/*
 * Scale a value inversely proportional to the task's normalized weight.
 */
static inline u64 scale_by_task_normalized_weight_inverse(const struct task_struct *p, u64 value)
{
	return value * task_base_weight() / task_weight(p);
}

/*
 * Update the task deadline.
 */
static void update_task_deadline(struct task_struct *p, struct task_ctx *tctx)
{
	u64 vtime_min, max_sleep, lag_scale;

	if (rr_sched)
		return;

	/*
	 * Evaluate the scaling factor for the maximum time budget that a
	 * task can accumulate while sleeping proportionally to the
	 * voluntary context switch rate.
	 *
	 * A task that is doing few long sleeps will get a smaller time
	 * budget, a task that is sleeping frequently will get a bigger
	 * time budget.
	 */
	lag_scale = max_avg_nvcsw ? log2_u64(MAX(tctx->avg_nvcsw, 2)) : 1;

	/*
	 * Adjust the budget in function of the average user CPU
	 * utilization: increase the allowed spread when CPUs are more
	 * utilized and reduce it when they are more idle.
	 *
	 * This enables dynamic fairness: when user CPU utilization is low,
	 * the impact of vruntime is reduced, favoring bursty workloads
	 * that use short execution slots (i.e., message-passing tasks like
	 * hackbench or similar).
	 *
	 * As utilization increases, sleeping tasks regain vruntime credit
	 * more quickly, restoring fairness and maintaining system
	 * responsiveness under load.
         *
         * This ensures that isolated bursty workloads are prioritized for
         * performance, while mixed workloads remain responsive and balanced.
	 */
	if (slice_lag_scaling)
		lag_scale = lag_scale * cpu_util / SCX_CPUPERF_ONE;

	/*
	 * Cap the vruntime budget that an idle task can accumulate to
	 * the scaled @slice_lag, preventing sleeping tasks from gaining
	 * excessive priority.
	 *
	 * A larger @slice_lag favors tasks that sleep longer by allowing
	 * them to accumulate more credit, leading to shorter deadlines and
	 * earlier execution. A smaller @slice_lag reduces the advantage of
	 * long sleeps, treating short and long sleeps equally once they
	 * exceed the threshold.
	 */
	max_sleep = scale_by_task_normalized_weight(p, slice_lag * lag_scale);
	vtime_min = vtime_now > max_sleep ? vtime_now - max_sleep : 0;
	if (time_before(p->scx.dsq_vtime, vtime_min))
		p->scx.dsq_vtime = vtime_min;

	/*
	 * Add the execution vruntime to the deadline.
	 */
	p->scx.dsq_vtime += scale_by_task_normalized_weight_inverse(p, tctx->exec_runtime);
}

static void task_update_domain(struct task_struct *p, struct task_ctx *tctx,
			       s32 cpu, const struct cpumask *cpumask)
{
	struct bpf_cpumask *primary, *l2_domain, *l3_domain;
	struct bpf_cpumask *mask, *l2_mask, *l3_mask;
	const struct cpumask *p_mask;
	struct cpu_ctx *cctx;

	/*
	 * Refresh task's recently used CPU every time the task's domain
	 * is updated.
	 */
	tctx->recent_used_cpu = cpu;

	cctx = try_lookup_cpu_ctx(cpu);
	if (!cctx)
		return;

	primary = primary_cpumask;
	if (!primary)
		return;

	l2_domain = cctx->l2_cpumask;
	l3_domain = cctx->l3_cpumask;

	mask = tctx->cpumask;
	if (!mask) {
		scx_bpf_error("cpumask not initialized");
		return;
	}

	l2_mask = tctx->l2_cpumask;
	if (!l2_mask) {
		scx_bpf_error("l2 cpumask not initialized");
		return;
	}

	l3_mask = tctx->l3_cpumask;
	if (!l3_mask) {
		scx_bpf_error("l3 cpumask not initialized");
		return;
	}

	/*
	 * Determine the task's scheduling domain.
	 * idle CPU, re-try again with the primary scheduling domain.
	 */
	if (primary_all) {
		p_mask = cpumask;
	} else {
		if (!bpf_cpumask_and(mask, cpumask, cast_mask(primary)))
			bpf_cpumask_copy(mask, cpumask);
		p_mask = cast_mask(mask);
	}

	/*
	 * Determine the L2 cache domain as the intersection of the task's
	 * primary cpumask and the L2 cache domain mask of the previously used
	 * CPU.
	 */
	if (l2_domain)
		bpf_cpumask_and(l2_mask, p_mask, cast_mask(l2_domain));

	/*
	 * Determine the L3 cache domain as the intersection of the task's
	 * primary cpumask and the L3 cache domain mask of the previously used
	 * CPU.
	 */
	if (l3_domain)
		bpf_cpumask_and(l3_mask, p_mask, cast_mask(l3_domain));
}

/*
 * Return true if all the CPUs in the LLC of @cpu are busy, false
 * otherwise.
 */
static bool is_llc_busy(s32 cpu)
{
	const struct cpumask *primary, *l3_mask, *idle_cpumask;
	struct cpu_ctx *cctx;
	int node;
	bool ret;

	primary = cast_mask(primary_cpumask);
	if (!primary)
		return false;

	cctx = try_lookup_cpu_ctx(cpu);
	if (!cctx)
		return false;

	l3_mask = cast_mask(cctx->l3_cpumask);
	if (!l3_mask)
		l3_mask = primary;

	node = __COMPAT_scx_bpf_cpu_node(cpu);
	idle_cpumask = get_idle_cpumask_node(node);

	ret = !bpf_cpumask_intersects(l3_mask, idle_cpumask);

	scx_bpf_put_cpumask(idle_cpumask);

	return ret;
}

/*
 * Return true if the waker commits to release the CPU after waking up @p,
 * false otherwise.
 */
static bool is_wake_sync(const struct task_struct *current,
			 s32 prev_cpu, s32 this_cpu, u64 wake_flags)
{
	if (no_wake_sync)
		return false;

	return (wake_flags & SCX_WAKE_SYNC) && !(current->flags & PF_EXITING);
}

/*
 * Return true if @this_cpu and @that_cpu shares the same LLC, false
 * otherwise.
 */
static bool cpus_share_llc(s32 this_cpu, s32 that_cpu)
{
	const struct cpumask *llc_mask;
	struct cpu_ctx *cctx;

	if (this_cpu == that_cpu)
		return true;

	cctx = try_lookup_cpu_ctx(that_cpu);
	if (!cctx)
		return false;

	/*
	 * If the L3 cpumask isn't defined, it means that either all CPUs
	 * share the same L3 cache or the scheduler is running with
	 * --disable-l3.
	 *
	 * In both cases, treat the CPUs as if they share the same LLC (the
	 * --disable-l3 option, in this case, is interpreted as merging all
	 *  L3 caches into a single virtual LLC).
	 */
	llc_mask = cast_mask(cctx->l3_cpumask);
	if (!llc_mask)
		return true;

	return bpf_cpumask_test_cpu(this_cpu, llc_mask);
}

/*
 * Compatibility helper to transparently use the built-in idle CPU
 * selection policy (if scx_bpf_select_cpu_and() is available) or fallback
 * to the custom idle selection policy.
 */
static s32 pick_idle_cpu_builtin(struct task_struct *p, s32 prev_cpu, u64 wake_flags, bool *is_idle)
{
	const struct cpumask *primary;
	s32 cpu;

	if (!builtin_idle || !bpf_ksym_exists(scx_bpf_select_cpu_and))
		return -ENOENT;

	primary = cast_mask(primary_cpumask);
	if (!primary)
		return -EINVAL;

	if (no_wake_sync)
		wake_flags &= ~SCX_WAKE_SYNC;

	cpu = primary_all ? -ENOENT :
			scx_bpf_select_cpu_and(p, prev_cpu, wake_flags, primary, 0);
	if (cpu < 0) {
		cpu = scx_bpf_select_cpu_and(p, prev_cpu, wake_flags, p->cpus_ptr, 0);
		if (cpu < 0)
			return prev_cpu;
	}
	*is_idle = true;

	return cpu;
}

/*
 * Find an idle CPU in the system.
 *
 * NOTE: the idle CPU selection doesn't need to be formally perfect, it is
 * totally fine to accept racy conditions and potentially make mistakes, by
 * picking CPUs that are not idle or even offline, the logic has been designed
 * to handle these mistakes in favor of a more efficient response and a reduced
 * scheduling overhead.
 */
static s32 pick_idle_cpu(struct task_struct *p, struct task_ctx *tctx,
			 s32 prev_cpu, u64 wake_flags, bool *is_idle)
{
	const struct task_struct *current = (void *)bpf_get_current_task_btf();
	const struct cpumask *idle_smtmask, *idle_cpumask;
	const struct cpumask *primary, *p_mask, *l2_mask, *l3_mask;
	int node;
	s32 this_cpu = bpf_get_smp_processor_id(), cpu;
	bool is_prev_allowed;

	primary = cast_mask(primary_cpumask);
	if (!primary)
		return -EINVAL;

	/*
	 * Use the built-in idle CPU selection policy, if enabled.
	 */
	cpu = pick_idle_cpu_builtin(p, prev_cpu, wake_flags, is_idle);
	if (cpu >= 0)
		return cpu;

	/*
	 * Use the custom idle CPU selection policy if the built-in policy
	 * is disabled.
	 */
	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return -ENOENT;

	/*
	 * Get the task's primary scheduling domain.
	 */
	p_mask = primary_all ? p->cpus_ptr : cast_mask(tctx->cpumask);

	/*
	 * Decide whether the task can continue running on the same CPU:
	 *  - if the CPU is outside the primary domain, force a migration;
	 *  - otherwise, allow it if the CPU is within the primary domain
	 *    or if CPU stickiness is enabled.
	 */
	is_prev_allowed = (primary_all || sticky_cpu) ? true :
				p_mask && bpf_cpumask_test_cpu(prev_cpu, p_mask);

	/*
	 * Acquire the CPU masks to determine the idle CPUs in the system.
	 */
	node = __COMPAT_scx_bpf_cpu_node(prev_cpu);
	idle_smtmask = get_idle_smtmask_node(node);
	idle_cpumask = get_idle_cpumask_node(node);

	/*
	 * In case of a sync wakeup, attempt to run the wakee on the
	 * waker's CPU if possible, as it's going to release the CPU right
	 * after the wakeup, so it can be considered as idle and, possibly,
	 * cache hot.
	 */
	if (is_wake_sync(current, prev_cpu, this_cpu, wake_flags)) {
		bool share_llc = cpus_share_llc(prev_cpu, this_cpu);

		/*
		 * If waker and wakee are on the same LLC and @prev_cpu is
		 * idle, keep using it, since there is no guarantee that
		 * the cache hot data from the waker's CPU is more
		 * important than cache hot data in the wakee's CPU.
		 *
		 * @prev_cpu is considered idle under the following
		 * conditions:
		 *  - if SMT is enabled, check if it's a full-idle core;
		 *  - if SMT is disabled, check if the CPU is idle.
		 */
		if (is_prev_allowed && share_llc &&
		    (!smt_enabled || bpf_cpumask_test_cpu(prev_cpu, idle_smtmask)) &&
		    scx_bpf_test_and_clear_cpu_idle(prev_cpu)) {
			cpu = prev_cpu;
			*is_idle = true;
			goto out_put_cpumask;
		}

		/*
		 * Migrate the wakee to the waker's CPU, but only if the
		 * waker's LLC is not completely saturated, to prevent
		 * wakers/wakees abusing this mechanism and potentially
		 * starving other tasks.
		 *
		 * Moreover, allow cross-LLC migrations only if the waker
		 * performed the most recent wakeup of the wakee (meaning
		 * that the two tasks are probably part of the same
		 * pipeline).
		 */
		if ((share_llc || current->pid == tctx->waker_pid) &&
		    p_mask && bpf_cpumask_test_cpu(this_cpu, p_mask) &&
		    !scx_bpf_dsq_nr_queued(SCX_DSQ_LOCAL_ON | this_cpu) &&
		    !scx_bpf_dsq_nr_queued(cpu_to_dsq(this_cpu)) &&
		    !is_llc_busy(this_cpu)) {
			cpu = this_cpu;
			*is_idle = true;
			goto out_put_cpumask;
		}
	}

	/*
	 * Refresh task domain based on the previously used cpu. If we keep
	 * selecting the same CPU, the task's domain doesn't need to be
	 * updated and we can save some cpumask ops.
	 */
	if (tctx->recent_used_cpu != prev_cpu)
		task_update_domain(p, tctx, prev_cpu, p->cpus_ptr);

	l2_mask = cast_mask(tctx->l2_cpumask);
	l3_mask = cast_mask(tctx->l3_cpumask);

	/*
	 * Find the best idle CPU, prioritizing full idle cores in SMT systems.
	 */
	if (smt_enabled) {
		/*
		 * If the task can still run on the previously used CPU and
		 * it's a full-idle core, keep using it.
		 */
		if (is_prev_allowed &&
		    bpf_cpumask_test_cpu(prev_cpu, idle_smtmask) &&
		    scx_bpf_test_and_clear_cpu_idle(prev_cpu)) {
			cpu = prev_cpu;
			*is_idle = true;
			goto out_put_cpumask;
		}

		/*
		 * Search for any full-idle CPU in the primary domain that
		 * shares the same L2 cache.
		 */
		if (l2_mask) {
			cpu = pick_idle_cpu_node(l2_mask, node, SCX_PICK_IDLE_CORE | __COMPAT_SCX_PICK_IDLE_IN_NODE);
			if (cpu >= 0) {
				*is_idle = true;
				goto out_put_cpumask;
			}
		}

		/*
		 * Search for any full-idle CPU in the primary domain that
		 * shares the same L3 cache.
		 */
		if (l3_mask) {
			cpu = pick_idle_cpu_node(l3_mask, node, SCX_PICK_IDLE_CORE | __COMPAT_SCX_PICK_IDLE_IN_NODE);
			if (cpu >= 0) {
				*is_idle = true;
				goto out_put_cpumask;
			}
		}

		/*
		 * Search for any full-idle CPU in the primary domain.
		 *
		 * If the current node needs a rebalance, look for any
		 * full-idle CPU also on different nodes.
		 */
		if (p_mask) {
			u64 flags = SCX_PICK_IDLE_CORE;

			if (!node_rebalance(node))
				flags |= __COMPAT_SCX_PICK_IDLE_IN_NODE;

			cpu = pick_idle_cpu_node(p_mask, node, flags);
			if (cpu >= 0) {
				*is_idle = true;
				goto out_put_cpumask;
			}
		}

		/*
		 * Search for any full-idle CPU usable by the task.
		 */
		if (p_mask != p->cpus_ptr) {
			cpu = pick_idle_cpu_node(p->cpus_ptr, node,
						SCX_PICK_IDLE_CORE);
			if (cpu >= 0) {
				*is_idle = true;
				goto out_put_cpumask;
			}
		}
	}

	/*
	 * If a full-idle core can't be found (or if this is not an SMT system)
	 * try to re-use the same CPU, even if it's not in a full-idle core.
	 */
	if (is_prev_allowed &&
	    scx_bpf_test_and_clear_cpu_idle(prev_cpu)) {
		cpu = prev_cpu;
		*is_idle = true;
		goto out_put_cpumask;
	}

	/*
	 * Search for any idle CPU in the primary domain that shares the same
	 * L2 cache.
	 */
	if (l2_mask && !node_rebalance(node)) {
		cpu = pick_idle_cpu_node(l2_mask, node, __COMPAT_SCX_PICK_IDLE_IN_NODE);
		if (cpu >= 0) {
			*is_idle = true;
			goto out_put_cpumask;
		}
	}

	/*
	 * Search for any idle CPU in the primary domain that shares the same
	 * L3 cache.
	 */
	if (l3_mask && !node_rebalance(node)) {
		cpu = pick_idle_cpu_node(l3_mask, node, __COMPAT_SCX_PICK_IDLE_IN_NODE);
		if (cpu >= 0) {
			*is_idle = true;
			goto out_put_cpumask;
		}
	}

	/*
	 * Search for any idle CPU in the scheduling domain.
	 */
	if (p_mask) {
		cpu = pick_idle_cpu_node(p_mask, node, 0);
		if (cpu >= 0) {
			*is_idle = true;
			goto out_put_cpumask;
		}
	}

	/*
	 * Search for any idle CPU usable by the task.
	 */
	if (p_mask != p->cpus_ptr) {
		cpu = pick_idle_cpu_node(p->cpus_ptr, node, 0);
		if (cpu >= 0) {
			*is_idle = true;
			goto out_put_cpumask;
		}
	}

out_put_cpumask:
	scx_bpf_put_cpumask(idle_cpumask);
	scx_bpf_put_cpumask(idle_smtmask);

	/*
	 * If we couldn't find any CPU, or in case of error, return the
	 * previously used CPU.
	 */
	if (cpu < 0)
		cpu = prev_cpu;

	return cpu;
}

/*
 * Return true if we can perform a direct dispatch on @cpu, false
 * otherwise.
 */
static inline bool can_direct_dispatch(s32 cpu)
{
	/*
	 * If @direct_dispatch is enabled always allow direct dispatch,
	 * otherwise allow it only if there are no other tasks queued to
	 * the DSQs.
	 */
	return direct_dispatch ?: !nr_tasks_waiting(cpu);
}

/*
 * Pick a target CPU for a task which is being woken up.
 *
 * If a task is dispatched here, ops.enqueue() will be skipped: task will be
 * dispatched directly to the CPU returned by this callback.
 */
s32 BPF_STRUCT_OPS(flash_select_cpu, struct task_struct *p,
			s32 prev_cpu, u64 wake_flags)
{
	struct task_ctx *tctx;
	bool is_idle = false;
	s32 cpu;

	if (is_throttled())
		return prev_cpu;

	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return -ENOENT;

	cpu = pick_idle_cpu(p, tctx, prev_cpu, wake_flags, &is_idle);
	if (rr_sched || (is_idle && can_direct_dispatch(cpu))) {
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, task_slice(p, cpu), 0);
		__sync_fetch_and_add(&nr_direct_dispatches, 1);
	}

	return cpu;
}

/*
 * Try to wake up an idle CPU that can immediately process the task.
 *
 * Return true if a CPU has been kicked, false otherwise.
 */
static bool kick_idle_cpu(const struct task_struct *p, const struct task_ctx *tctx,
			  s32 prev_cpu, bool idle_smt)
{
	const struct cpumask *mask;
	u64 flags = idle_smt ? SCX_PICK_IDLE_CORE : 0;
	s32 cpu = scx_bpf_task_cpu(p);
	int node = __COMPAT_scx_bpf_cpu_node(cpu);

	if (is_throttled())
		return false;

	/*
	 * No need to look for full-idle SMT cores if SMT is disabled.
	 */
	if (idle_smt && !smt_enabled)
		return false;

	/*
	 * Try to reuse the same CPU if idle.
	 */
	if (!idle_smt || is_fully_idle(prev_cpu)) {
		if (scx_bpf_test_and_clear_cpu_idle(prev_cpu)) {
			scx_bpf_kick_cpu(prev_cpu, SCX_KICK_IDLE);
			return true;
		}
	}

	/*
	 * Look for any idle CPU usable by the task that can immediately
	 * execute the task, prioritizing SMT isolation and cache locality.
	 */
	mask = cast_mask(tctx->l2_cpumask);
	if (mask) {
		cpu = pick_idle_cpu_node(mask, node, flags | __COMPAT_SCX_PICK_IDLE_IN_NODE);
		if (cpu >= 0) {
			scx_bpf_kick_cpu(cpu, SCX_KICK_IDLE);
			return true;
		}
	}
	mask = cast_mask(tctx->l3_cpumask);
	if (mask) {
		cpu = pick_idle_cpu_node(mask, node, flags | __COMPAT_SCX_PICK_IDLE_IN_NODE);
		if (cpu >= 0) {
			scx_bpf_kick_cpu(cpu, SCX_KICK_IDLE);
			return true;
		}
	}

	return false;
}

/*
 * Return true if a CPU is busy (based on its utilization), false
 * otherwise.
 */
static bool is_cpu_busy(s32 cpu)
{
	const struct cpu_ctx *cctx;

	/*
	 * If no other tasks are contending for this CPU, consider the CPU
	 * as non-busy.
	 */
	if (!nr_tasks_waiting(cpu))
		return false;

	/*
	 * Determine whether a CPU is considered busy using the following logic:
	 *  - if a fixed threshold is provided (@cpu_busy_thresh), use it
	 *    directly;
	 *  - otherwise, compute a dynamic threshold as:
	 *        100% - global CPU user time %
	 *
	 * The dynamic threshold adapts to system load: when user time is
	 * high, the threshold decreases, making the scheduler more
	 * aggressive in migrating tasks to improve responsiveness. When
	 * user time is low, the threshold increases, encouraging task
	 * stickiness to improve cache locality while still preserving work
	 * conservation, since the system isn't overloaded.
	 */
	u64 cpu_thresh = cpu_busy_thresh >= 0 ? cpu_busy_thresh :
						(SCX_CPUPERF_ONE - cpu_util);

	/*
	 * If the target threshold is greater than 100% assume the CPU is
	 * never busy,
	 */
	if (cpu_thresh > SCX_CPUPERF_ONE)
		return false;

	cctx = try_lookup_cpu_ctx(cpu);
	if (!cctx)
		return false;

	/*
	 * Normalize the utilization in range [0 .. SCX_CPUPERF_ONE] and
	 * check if the current utilization exceeds the target threshold.
	 */
	return cctx->perf_lvl >= cpu_thresh;
}

/*
 * Attempt to dispatch a task directly to its assigned CPU.
 *
 * Return true if the task is dispatched, false otherwise.
 */
static bool try_direct_dispatch(struct task_struct *p, struct task_ctx *tctx,
				s32 prev_cpu, u64 enq_flags)
{
	bool is_idle = false, dispatched = false;
	s32 cpu = prev_cpu;

	/*
	 * Dispatch per-CPU kthreads directly on their assigned CPU if
	 * @local_kthreads is enabled.
	 *
	 * This allows to prioritize critical kernel threads that may
	 * potentially stall the entire system if they are blocked (i.e.,
	 * ksoftirqd/N, rcuop/N, etc.).
	 */
	if (local_kthreads && is_kthread(p) && p->nr_cpus_allowed == 1) {
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | prev_cpu, slice_max, enq_flags);
		__sync_fetch_and_add(&nr_kthread_dispatches, 1);
		dispatched = true;

		goto out_kick;
	}

	/*
	 * Skip direct dispatch if the CPUs are forced to stay idle.
	 */
	if (is_throttled())
		return false;

	/*
	 * Skip direct dispatch if ops.select_cpu() was already called, as
	 * the task has already had an opportunity for direct dispatch
	 * there.
	 */
	if (__COMPAT_is_enq_cpu_selected(enq_flags))
		return false;

	/*
	 * Skip direct dispatch if the task was already running, since we
	 * only want to consider migrations on task wakeup.
	 *
	 * While this is typically handled in ops.select_cpu(), remote
	 * wakeups (ttwu_queue) skip that callback, so we need to handle
	 * migration here.
	 *
	 * However, if the task was re-enqueued due to a higher scheduling
	 * class stealing the CPU it was previously queued on, give it a
	 * chance to migrate to a different CPU.
	 */
	if (!(enq_flags & SCX_ENQ_REENQ) && scx_bpf_task_running(p))
		return false;

	/*
	 * If the CPU is not busy dispatch tasks in a round-robin fashion.
	 */
	if (direct_dispatch && !is_cpu_busy(cpu)) {
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | cpu, task_slice(p, cpu), enq_flags);
		__sync_fetch_and_add(&nr_direct_dispatches, 1);
		dispatched = true;

		goto out_kick;
	}

	/*
	 * If the task can only run on a single CPU and that CPU is idle,
	 * perform a direct dispatch.
	 */
	if (is_pcpu_task(p)) {
		if (can_direct_dispatch(cpu) && scx_bpf_test_and_clear_cpu_idle(cpu)) {
			scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, task_slice(p, cpu), enq_flags);
			__sync_fetch_and_add(&nr_direct_dispatches, 1);
			dispatched = true;

			goto out_kick;
		}

		/*
		 * No need to check for other CPUs if the task can only run
		 * on a single one.
		 */
		return false;
	}

	/*
	 * Try to pick an idle CPU close to the one the task is using.
	 */
	cpu = pick_idle_cpu(p, tctx, prev_cpu, 0, &is_idle);
	if (!is_idle)
		return false;

	if (can_direct_dispatch(cpu)) {
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | cpu, task_slice(p, cpu), 0);
		__sync_fetch_and_add(&nr_direct_dispatches, 1);
		dispatched = true;
	}

out_kick:
	/*
	 * Kick the CPU even if we didn't directly dispatch, so it can be
	 * clear its idle state (transitioning from idle->awake->idle) or
	 * consume another task from the CPU DSQ.
	 */
	scx_bpf_kick_cpu(cpu, SCX_KICK_IDLE);

	return dispatched;
}

/*
 * Return true if the @p can be enqueued to the @cpu DSQ, false otherwise.
 */
static bool can_enqueue_to_cpu(const struct task_struct *p, s32 cpu)
{
	if (local_pcpu && is_pcpu_task(p))
		return true;

	return !is_cpu_busy(cpu);
}

/*
 * Enqueue a task when running in round-robin mode.
 */
static void rr_enqueue(struct task_struct *p, struct task_ctx *tctx,
		       s32 prev_cpu, u64 enq_flags)
{
	bool is_idle;
	s32 cpu;

	/*
	 * Attempt to migrate on another CPU on wakeup or if the task has
	 * been re-enqueued due to a higher priority class stealing the
	 * CPU, otherwise always prefer running on the same CPU.
	 */
	if (!scx_bpf_task_running(p) || (enq_flags & SCX_ENQ_REENQ)) {
		if (is_pcpu_task(p)) {
			if (scx_bpf_test_and_clear_cpu_idle(prev_cpu))
				scx_bpf_kick_cpu(prev_cpu, SCX_KICK_IDLE);
		} else {
			cpu = pick_idle_cpu(p, tctx, prev_cpu, 0, &is_idle);
			if (is_idle) {
				scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | cpu,
						   task_slice(p, cpu), enq_flags);
				scx_bpf_kick_cpu(cpu, SCX_KICK_IDLE);
				return;
			}
		}
	}
	scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, task_slice(p, prev_cpu), enq_flags);
}

/*
 * Dispatch all the other tasks that were not dispatched directly in
 * select_cpu().
 */
void BPF_STRUCT_OPS(flash_enqueue, struct task_struct *p, u64 enq_flags)
{
	const struct cpumask *idle_cpumask;
	struct task_ctx *tctx;
	s32 prev_cpu = scx_bpf_task_cpu(p);
	int node = __COMPAT_scx_bpf_cpu_node(prev_cpu);

	/*
	 * Dispatch regular tasks to the shared DSQ.
	 */
	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return;

	/*
	 * Keep reusing the same CPU in round-robin mode.
	 */
	if (rr_sched) {
		rr_enqueue(p, tctx, prev_cpu, enq_flags);
		return;
	}

	/*
	 * No need to update the task's deadline if it was re-enqueued due
	 * a higher scheduling class stealing the CPU (as the task didn't
	 * actually run).
	 */
	if (!(enq_flags & SCX_ENQ_REENQ))
		update_task_deadline(p, tctx);

	/*
	 * Try to dispatch the task directly, if possible.
	 */
	if (try_direct_dispatch(p, tctx, prev_cpu, enq_flags))
		return;

	/*
	 * Try to keep awakened tasks on the same CPU using the per-CPU DSQ
	 * and use the per-node DSQ if the CPU is getting saturated, so
	 * that tasks can attempt to migrate somewhere else.
	 */
	if (!scx_bpf_task_running(p) && can_enqueue_to_cpu(p, prev_cpu)) {
		scx_bpf_dsq_insert_vtime(p, cpu_to_dsq(prev_cpu),
					 task_slice(p, prev_cpu), p->scx.dsq_vtime, enq_flags);
		__sync_fetch_and_add(&nr_shared_dispatches, 1);
		scx_bpf_kick_cpu(prev_cpu, SCX_KICK_IDLE);

		return;
	}
	scx_bpf_dsq_insert_vtime(p, node_to_dsq(node),
				 task_slice(p, prev_cpu), p->scx.dsq_vtime, enq_flags);
	__sync_fetch_and_add(&nr_shared_dispatches, 1);

	/*
	 * Refresh the task domain if it was migrated to a different CPU,
	 * without going through ops.select_cpu().
	 *
	 * This ensures the proactive wakeup (see below) will target a CPU
	 * near the one the task was most recently running on.
	 */
	if (tctx->recent_used_cpu != prev_cpu)
		task_update_domain(p, tctx, prev_cpu, p->cpus_ptr);

	/*
	 * If there are idle CPUs in the system try to proactively wake up
	 * one, so that it can immediately execute the task in case its
	 * current CPU is busy (always prioritizing full-idle SMT cores
	 * first, if present).
	 */
	idle_cpumask = get_idle_cpumask_node(node);
	if (!bpf_cpumask_empty(idle_cpumask))
		if (!kick_idle_cpu(p, tctx, prev_cpu, true))
			kick_idle_cpu(p, tctx, prev_cpu, false);
	scx_bpf_put_cpumask(idle_cpumask);
}

/*
 * Return true if the task can keep running on its current CPU, false if
 * the task should migrate.
 */
static bool keep_running(const struct task_struct *p, s32 cpu)
{
	int node = __COMPAT_scx_bpf_cpu_node(cpu);
	const struct cpumask *primary = cast_mask(primary_cpumask), *smt;
	const struct cpumask *idle_smtmask, *idle_cpumask;
	struct cpu_ctx *cctx;
	bool ret;

	/* Do not keep running if the task doesn't need to run */
	if (!is_queued(p))
		return false;


	/*
	 * Do not keep running if the CPU is not in the primary domain and
	 * the task can use the primary domain.
	 */
	if (primary && bpf_cpumask_intersects(primary, p->cpus_ptr) &&
	    !bpf_cpumask_test_cpu(cpu, primary))
		return false;

	/*
	 * Keep running only if the task is on a full-idle SMT core (or SMT
	 * is disabled).
	 */
	if (!smt_enabled)
		return true;

	/*
	 * Keep running on the same CPU if round-robin mode is enabled.
	 */
	if (rr_sched)
		return true;

	/*
	 * If the task can only run on this CPU, keep it running.
	 */
	if (p->nr_cpus_allowed == 1)
		return true;

	cctx = try_lookup_cpu_ctx(cpu);
	if (!cctx)
		return false;

	smt = cast_mask(cctx->smt_cpumask);
	if (!smt)
		return false;

	idle_smtmask = get_idle_smtmask_node(node);
	idle_cpumask = get_idle_cpumask_node(node);

	/*
	 * If the task is running in a full-idle SMT core or if all the SMT
	 * cores in the system are busy (they all have at least one busy
	 * sibling), keep the task running on its current CPU.
	 */
	ret = bpf_cpumask_subset(smt, idle_cpumask) || bpf_cpumask_empty(idle_smtmask);

	scx_bpf_put_cpumask(idle_cpumask);
	scx_bpf_put_cpumask(idle_smtmask);

	return ret;
}

void BPF_STRUCT_OPS(flash_dispatch, s32 cpu, struct task_struct *prev)
{
	int node = __COMPAT_scx_bpf_cpu_node(cpu);

	/*
	 * Let the CPU go idle if the system is throttled.
	 */
	if (is_throttled())
		return;

	/*
	 * Try to consume a task from the per-CPU DSQ.
	 */
	if (scx_bpf_dsq_move_to_local(cpu_to_dsq(cpu)))
		return;

	/*
	 * Try to consume a task from the per-node DSQ.
	 */
	if (scx_bpf_dsq_move_to_local(node_to_dsq(node)))
		return;

	/*
	 * If the current task expired its time slice and no other task wants
	 * to run, simply replenish its time slice and let it run for another
	 * round on the same CPU.
	 */
	if (prev && keep_running(prev, cpu))
		prev->scx.slice = task_slice(prev, cpu);
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
 * Evaluate the EWMA limited to the range [low ... high]
 */
static u64 calc_avg_clamp(u64 old_val, u64 new_val, u64 low, u64 high)
{
	return CLAMP(calc_avg(old_val, new_val), low, high);
}

/*
 * Update CPU load and scale target performance level accordingly.
 */
static void update_cpu_load(struct task_struct *p, struct task_ctx *tctx)
{
	u64 now = scx_bpf_now();
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
	delta_t = now - cctx->last_running;
	if (!delta_t)
		return;

	/*
	 * Refresh target performance level.
	 */
	delta_runtime = cctx->tot_runtime - cctx->prev_runtime;
	perf_lvl = MIN(delta_runtime * SCX_CPUPERF_ONE / delta_t, SCX_CPUPERF_ONE);

	/*
	 * Use a moving average to evalute the target performance level,
	 * giving more priority to the current average, so that we can
	 * react faster at CPU load variations and at the same time smooth
	 * the short spikes.
	 */
	cctx->perf_lvl = calc_avg(perf_lvl, cctx->perf_lvl);

	/*
	 * Refresh the dynamic cpuperf scaling factor if needed.
	 *
	 * Apply hysteresis to the scaling factor:
	 *  - if utilization is above the high threshold, bump to max;
	 *  - if it's below the low threshold, scale down to half capacity;
	 *  - otherwise, maintain the smoothed perf level.
	 */
	if (cpufreq_perf_lvl < 0) {
		if (cctx->perf_lvl >= CPUFREQ_HIGH_THRESH)
			perf_lvl = SCX_CPUPERF_ONE;
		else if (cctx->perf_lvl <= CPUFREQ_LOW_THRESH)
			perf_lvl = SCX_CPUPERF_ONE / 2;
		else
			perf_lvl = cctx->perf_lvl;
		scx_bpf_cpuperf_set(cpu, perf_lvl);
	}

	cctx->last_running = now;
	cctx->prev_runtime = cctx->tot_runtime;
}

void BPF_STRUCT_OPS(flash_running, struct task_struct *p)
{
	struct task_ctx *tctx;

	__sync_fetch_and_add(&nr_running, 1);

	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return;
	tctx->last_run_at = scx_bpf_now();

	/*
	 * Adjust target CPU frequency before the task starts to run.
	 */
	update_cpu_load(p, tctx);

	/*
	 * Update the global vruntime as a new task is starting to use a
	 * CPU.
	 */
	if (!rr_sched && time_before(vtime_now, p->scx.dsq_vtime))
		vtime_now = p->scx.dsq_vtime;
}

/*
 * Update task statistics when the task is releasing the CPU (either
 * voluntarily or because it expires its assigned time slice).
 */
void BPF_STRUCT_OPS(flash_stopping, struct task_struct *p, bool runnable)
{
	u64 now = scx_bpf_now(), slice;
	s32 cpu = scx_bpf_task_cpu(p);
	struct cpu_ctx *cctx;
	struct task_ctx *tctx;

	__sync_fetch_and_sub(&nr_running, 1);

	if (!rr_sched) {
		tctx = try_lookup_task_ctx(p);
		if (!tctx)
			return;

		/*
		 * Evaluate the time slice used by the task.
		 */
		slice = MIN(now - tctx->last_run_at, slice_max);

		/*
		 * Update task's execution time (exec_runtime), but never
		 * account more than @run_lag to prevent excessive
		 * de-prioritization of CPU-intensive tasks (which could
		 * lead to starvation).
		 */
		tctx->exec_runtime = MIN(tctx->exec_runtime + slice, run_lag);

		/*
		 * Update task's vruntime.
		 */
		p->scx.dsq_vtime += scale_by_task_normalized_weight_inverse(p, slice);
	}

	/*
	 * Update CPU runtime.
	 */
	cctx = try_lookup_cpu_ctx(cpu);
	if (cctx)
		cctx->tot_runtime += now - cctx->last_running;
}

void BPF_STRUCT_OPS(flash_runnable, struct task_struct *p, u64 enq_flags)
{
	const struct task_struct *current = (void *)bpf_get_current_task_btf();
	struct task_ctx *tctx;

	if (rr_sched)
		return;

	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return;

	tctx->exec_runtime = 0;
	tctx->waker_pid = current->pid;
}

void BPF_STRUCT_OPS(flash_quiescent, struct task_struct *p, u64 deq_flags)
{
	u64 now = scx_bpf_now();
	s64 delta_t;
	struct task_ctx *tctx;

	if (rr_sched || !max_avg_nvcsw)
		return;

	/*
	 * Update voluntary context switch rate only on task sleep events.
	 */
	if (!(deq_flags & SCX_DEQ_SLEEP))
		return;

	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return;

	/*
	 * Refresh the average rate of voluntary context switches.
	 */
	delta_t = time_delta(now, tctx->last_sleep_at);
	if (delta_t > 0) {
	    u64 nvcsw = slice_max / delta_t;

	    tctx->avg_nvcsw = calc_avg_clamp(tctx->avg_nvcsw, nvcsw, 0, max_avg_nvcsw);
	    tctx->last_sleep_at = now;
	}
}

void BPF_STRUCT_OPS(flash_cpu_release, s32 cpu, struct scx_cpu_release_args *args)
{
	/*
	 * When a CPU is taken by a higher priority scheduler class,
	 * re-enqueue all the tasks that are waiting in the local DSQ, so
	 * that we can give them a chance to run on another CPU.
	 */
	scx_bpf_reenqueue_local();
}

void BPF_STRUCT_OPS(flash_set_cpumask, struct task_struct *p,
		    const struct cpumask *cpumask)
{
	s32 cpu = bpf_get_smp_processor_id();
	struct task_ctx *tctx;

	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return;

	task_update_domain(p, tctx, cpu, cpumask);
}

void BPF_STRUCT_OPS(flash_enable, struct task_struct *p)
{
	/*
	 * Initialize the task vruntime to the current global vruntime.
	 */
	if (!rr_sched)
		p->scx.dsq_vtime = vtime_now;
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

s32 BPF_STRUCT_OPS(flash_init_task, struct task_struct *p,
		   struct scx_init_task_args *args)
{
	s32 cpu = bpf_get_smp_processor_id();
	struct task_ctx *tctx;
	int err;

	tctx = bpf_task_storage_get(&task_ctx_stor, p, 0,
				    BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!tctx)
		return -ENOMEM;

	/*
	 * Create task's primary cpumask.
	 */
	err = init_cpumask(&tctx->cpumask);
	if (err)
		return err;
	/*
	 * Create task's L2 cache cpumask.
	 */
	err = init_cpumask(&tctx->l2_cpumask);
	if (err)
		return err;
	/*
	 * Create task's L3 cache cpumask.
	 */
	err = init_cpumask(&tctx->l3_cpumask);
	if (err)
		return err;

	task_update_domain(p, tctx, cpu, p->cpus_ptr);

	return 0;
}

/*
 * Evaluate the amount of online CPUs.
 */
s32 get_nr_online_cpus(void)
{
	const struct cpumask *online_cpumask;
	int cpus;

	online_cpumask = scx_bpf_get_online_cpumask();
	cpus = bpf_cpumask_weight(online_cpumask);
	scx_bpf_put_cpumask(online_cpumask);

	return cpus;
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

	/* Make sure the target CPU mask is initialized */
	switch (input->lvl_id) {
	case 0:
		pmask = &cctx->smt_cpumask;
		break;
	case 2:
		pmask = &cctx->l2_cpumask;
		break;
	case 3:
		pmask = &cctx->l3_cpumask;
		break;
	default:
		return -EINVAL;
	}
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
	struct node_ctx *nctx;
	u64 perf_lvl;
	int node;
	s32 cpu;

	online_cpumask = scx_bpf_get_online_cpumask();
	bpf_for (cpu, 0, nr_cpu_ids) {
		if (!bpf_cpumask_test_cpu(cpu, online_cpumask))
			continue;

		/* Set the initial cpufreq performance level  */
		if (cpufreq_perf_lvl < 0)
			perf_lvl = SCX_CPUPERF_ONE;
		else
			perf_lvl = MIN(cpufreq_perf_lvl, SCX_CPUPERF_ONE);
		scx_bpf_cpuperf_set(cpu, perf_lvl);

		/* Evaluate the amount of online CPUs for each node */
		node = __COMPAT_scx_bpf_cpu_node(cpu);
		nctx = try_lookup_node_ctx(node);
		if (nctx)
			nctx->nr_cpus++;
	}
	scx_bpf_put_cpumask(online_cpumask);
}

/*
 * Tickless timer used to preempt CPUs.
 */
static int tickless_timerfn(void *map, int *key, struct bpf_timer *timer)
{
	s32 cpu;
	int err;

	/*
	 * Check if we need to preempt the running tasks.
	 */
	bpf_rcu_read_lock();
	bpf_for(cpu, 0, nr_cpu_ids) {
		struct task_struct *p;
		struct rq *rq = scx_bpf_cpu_rq(cpu);

		if (!rq)
			continue;
		/*
		 * Ignore CPU if idle task is running.
		 */
		p = rq->curr;
		if (p->flags & PF_IDLE)
			continue;

		/*
		 * Ignore CPUs without any task waiting.
		 */
		if (!nr_tasks_waiting(cpu))
			continue;

		/*
		 * Set a finite time slice to the running task, so that it
		 * can be preempted.
		 */
		if (p->scx.slice == SCX_SLICE_INF)
			p->scx.slice = slice_min;
	}
	bpf_rcu_read_unlock();

	err = bpf_timer_start(timer, tick_interval_ns(), 0);
	if (err)
		scx_bpf_error("Failed to re-arm tickless timer");

	return 0;
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

/*
 * Refresh NUMA statistics.
 */
static int numa_timerfn(void *map, int *key, struct bpf_timer *timer)
{
	const struct cpumask *online_cpumask;
	struct node_ctx *nctx;
	int node, err;
	bool has_idle_nodes = false;
	s32 cpu;

	/*
	 * Update node statistics.
	 */
	online_cpumask = scx_bpf_get_online_cpumask();
	bpf_for (cpu, 0, nr_cpu_ids) {
		struct cpu_ctx *cctx;

		if (!bpf_cpumask_test_cpu(cpu, online_cpumask))
			continue;

		cctx = try_lookup_cpu_ctx(cpu);
		if (!cctx)
			continue;

		node = __COMPAT_scx_bpf_cpu_node(cpu);
		nctx = try_lookup_node_ctx(node);
		if (!nctx)
			continue;

		nctx->tot_perf_lvl += cctx->perf_lvl;
	}
	scx_bpf_put_cpumask(online_cpumask);

	/*
	 * Update node utilization.
	 */
	bpf_for(node, 0, __COMPAT_scx_bpf_nr_node_ids()) {
		nctx = try_lookup_node_ctx(node);
		if (!nctx || !nctx->nr_cpus)
			continue;

		/*
		 * Evaluate node utilization as the average perf_lvl among
		 * its CPUs.
		 */
		nctx->perf_lvl = nctx->tot_perf_lvl / nctx->nr_cpus;

		/*
		 * System has at least one idle node if its current
		 * utilization is 25% or below.
		 */
		if (nctx->perf_lvl <= SCX_CPUPERF_ONE / 4)
			has_idle_nodes = true;

		/*
		 * Reset partial performance level.
		 */
		nctx->tot_perf_lvl = 0;
	}

	/*
	 * Determine nodes that need a rebalance.
	 */
	bpf_for(node, 0, __COMPAT_scx_bpf_nr_node_ids()) {
		nctx = try_lookup_node_ctx(node);
		if (!nctx)
			continue;

		/*
		 * If the current node utilization is 50% or more and there
		 * is at least an idle node in the system, trigger a
		 * rebalance.
		 */
		nctx->need_rebalance = has_idle_nodes && nctx->perf_lvl >= SCX_CPUPERF_ONE / 2;

		dbg_msg("node %d util %llu rebalance %d",
			   node, nctx->perf_lvl, nctx->need_rebalance);
	}

	err = bpf_timer_start(timer, NSEC_PER_SEC, 0);
	if (err)
		scx_bpf_error("Failed to start NUMA timer");

	return 0;
}

s32 BPF_STRUCT_OPS_SLEEPABLE(flash_init)
{
	struct bpf_timer *timer;
	int err, node;
	s32 cpu;
	u32 key = 0;

	/* Initialize amount of online and possible CPUs */
	nr_online_cpus = get_nr_online_cpus();
	nr_cpu_ids = scx_bpf_nr_cpu_ids();

	/* Initialize CPUs and NUMA properties */
	init_cpuperf_target();

	/* Create per-CPU DSQs */
	bpf_for(cpu, 0, nr_cpu_ids) {
		err = scx_bpf_create_dsq(cpu, __COMPAT_scx_bpf_cpu_node(cpu));
		if (err) {
			scx_bpf_error("failed to create DSQ %d: %d", cpu, err);
			return err;
		}
	}

	/* Create per-node DSQs */
	bpf_for(node, 0, __COMPAT_scx_bpf_nr_node_ids()) {
		err = scx_bpf_create_dsq(node_to_dsq(node), node);
		if (err) {
			scx_bpf_error("failed to create DSQ %d: %d", node, err);
			return err;
		}
	}

	/* Initialize the primary scheduling domain */
	err = init_cpumask(&primary_cpumask);
	if (err)
		return err;

	timer = bpf_map_lookup_elem(&tickless_timer, &key);
	if (!timer) {
		scx_bpf_error("Failed to lookup tickless timer");
		return -ESRCH;
	}

	/*
	 * Fire the tickless timer if tickless mode is enabled.
	 */
	if (tickless_sched) {
		bpf_timer_init(timer, &tickless_timer, CLOCK_MONOTONIC);
		bpf_timer_set_callback(timer, tickless_timerfn);
		err = bpf_timer_start(timer, tick_interval_ns(), 0);
		if (err) {
			scx_bpf_error("Failed to arm tickless timer");
			return err;
		}
	}

	timer = bpf_map_lookup_elem(&throttle_timer, &key);
	if (!timer) {
		scx_bpf_error("Failed to lookup throttle timer");
		return -ESRCH;
	}

	/*
	 * Fire the throttle timer if CPU throttling is enabled.
	 */
	if (throttle_ns) {
		bpf_timer_init(timer, &throttle_timer, CLOCK_MONOTONIC);
		bpf_timer_set_callback(timer, throttle_timerfn);
		err = bpf_timer_start(timer, slice_max, 0);
		if (err) {
			scx_bpf_error("Failed to arm throttle timer");
			return err;
		}
	}

	/* Do not update NUMA statistics if there's only one node */
	if (numa_disabled || __COMPAT_scx_bpf_nr_node_ids() <= 1)
		return 0;

	timer = bpf_map_lookup_elem(&numa_timer, &key);
	if (!timer) {
		scx_bpf_error("Failed to lookup NUMA timer");
		return -ESRCH;
	}

	bpf_timer_init(timer, &numa_timer, CLOCK_MONOTONIC);
	bpf_timer_set_callback(timer, numa_timerfn);
	err = bpf_timer_start(timer, NSEC_PER_SEC, 0);
	if (err) {
		scx_bpf_error("Failed to start NUMA timer");
		return err;
	}

	return 0;
}

void BPF_STRUCT_OPS(flash_exit, struct scx_exit_info *ei)
{
	UEI_RECORD(uei, ei);
}

SCX_OPS_DEFINE(flash_ops,
	       .select_cpu		= (void *)flash_select_cpu,
	       .enqueue			= (void *)flash_enqueue,
	       .dispatch		= (void *)flash_dispatch,
	       .running			= (void *)flash_running,
	       .stopping		= (void *)flash_stopping,
	       .runnable		= (void *)flash_runnable,
	       .quiescent		= (void *)flash_quiescent,
	       .cpu_release		= (void *)flash_cpu_release,
	       .set_cpumask		= (void *)flash_set_cpumask,
	       .enable			= (void *)flash_enable,
	       .init_task		= (void *)flash_init_task,
	       .init			= (void *)flash_init,
	       .exit			= (void *)flash_exit,
	       .timeout_ms		= 5000,
	       .name			= "flash");
