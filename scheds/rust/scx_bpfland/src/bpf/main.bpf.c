/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2024 Andrea Righi <andrea.righi@linux.dev>
 */
#include <scx/common.bpf.h>
#include "intf.h"

const volatile u64 __COMPAT_SCX_PICK_IDLE_IN_NODE;

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
const volatile u64 slice_max = 20ULL * NSEC_PER_MSEC;

/*
 * Time slice used when system is over commissioned.
 */
const volatile u64 slice_min = 1ULL * NSEC_PER_MSEC;

/*
 * Maximum time slice lag.
 *
 * Increasing this value can help to increase the responsiveness of interactive
 * tasks at the cost of making regular and newly created tasks less responsive
 * (0 = disabled).
 */
const volatile s64 slice_lag = 20ULL * NSEC_PER_MSEC;

/*
 * If enabled, never allow tasks to be directly dispatched.
 */
const volatile bool no_preempt;

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
 * Prioritize per-CPU tasks (tasks that can only run on a single CPU).
 *
 * This allows to prioritize per-CPU tasks that usually tend to be
 * de-prioritized (since they can't be migrated when their only usable CPU
 * is busy). Enabling this option can introduce unfairness and potentially
 * trigger stalls, but it can improve performance of server-type workloads
 * (such as large parallel builds).
 */
const volatile bool local_pcpu;

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
 * Exit information.
 */
UEI_DEFINE(uei);

/*
 * Mask of CPUs that the scheduler can use until the system becomes saturated,
 * at which point tasks may overflow to other available CPUs.
 */
private(BPFLAND) struct bpf_cpumask __kptr *primary_cpumask;

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
	 * Task's deadline, defined as:
	 *
	 *   deadline = vruntime + exec_vruntime
	 *
	 * Here, vruntime represents the task's total runtime, scaled inversely by
	 * its weight, while exec_vruntime accounts for the vruntime accumulated
	 * from the moment the task becomes runnable until it voluntarily releases
	 * the CPU.
	 *
	 * Fairness is ensured through vruntime, whereas exec_vruntime helps in
	 * prioritizing latency-sensitive tasks: tasks that are frequently blocked
	 * waiting for an event (typically latency sensitive) will accumulate a
	 * smaller exec_vruntime, compared to tasks that continuously consume CPU
	 * without interruption.
	 *
	 * As a result, tasks with a smaller exec_vruntime will have a shorter
	 * deadline and will be dispatched earlier, ensuring better responsiveness
	 * for latency-sensitive tasks.
	 */
	u64 deadline;

	/*
	 * Task's recently used CPU: used to determine whether we need to
	 * refresh the task's cpumasks.
	 */
	s32 recent_used_cpu;
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
 * Return true if @p still wants to run, false otherwise.
 */
static bool is_queued(const struct task_struct *p)
{
	return p->scx.flags & SCX_TASK_QUEUED;
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

	idle_smtmask = __COMPAT_scx_bpf_get_idle_smtmask_node(node);
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
 * Return the total amount of tasks that are currently waiting to be scheduled.
 */
static u64 nr_tasks_waiting(int node)
{
	return scx_bpf_dsq_nr_queued(node) + 1;
}

/*
 * Scale a value inversely proportional to the task's normalized weight.
 */
static inline u64 scale_by_task_normalized_weight_inverse(const struct task_struct *p, u64 value)
{
	/*
	 * Original weight range:   [1, 10000], default = 100
	 * Normalized weight range: [1, 128], default = 64
	 *
	 * This normalization reduces the impact of extreme weight differences,
	 * preventing highly prioritized tasks from starving lower-priority ones.
	 *
	 * The goal is to ensure a more balanced scheduling that is
	 * influenced more by the task's behavior rather than its priority
	 * difference and prevent potential stalls due to large priority
	 * gaps.
	*/
	u64 weight = 1 + (127 * log2_u64(p->scx.weight) / log2_u64(10000));

	return value * 64 / weight;
}

/*
 * Update and return the task's deadline.
 */
static u64 task_deadline(const struct task_struct *p, struct task_ctx *tctx)
{
	u64 vtime_min;

	/*
	 * Cap the vruntime budget that an idle task can accumulate to
	 * slice_lag, preventing sleeping tasks from gaining excessive
	 * priority.
	 *
	 * A larger slice_lag favors tasks that sleep longer by allowing
	 * them to accumulate more credit, leading to shorter deadlines and
	 * earlier execution. A smaller slice_lag reduces the advantage of
	 * long sleeps, treating short and long sleeps equally once they
	 * exceed the threshold.
	 *
	 * If slice_lag is negative, it can be used to de-emphasize the
	 * deadline-based scheduling altogether by charging all tasks a
	 * fixed vruntime penalty (equal to the absolute value of
	 * slice_lag), effectively approximating FIFO behavior as the
	 * penalty increases.
	 */
	vtime_min = vtime_now - slice_lag;
	if (time_before(tctx->deadline, vtime_min))
		tctx->deadline = vtime_min;

	/*
	 * Add the execution vruntime to the deadline.
	 */
	tctx->deadline += scale_by_task_normalized_weight_inverse(p, tctx->exec_runtime);

	return tctx->deadline;
}

static void task_update_domain(struct task_struct *p, struct task_ctx *tctx,
			       s32 cpu, const struct cpumask *cpumask)
{
	struct bpf_cpumask *primary, *l2_domain, *l3_domain;
	struct bpf_cpumask *p_mask, *l2_mask, *l3_mask;
	struct cpu_ctx *cctx;

	/*
	 * Refresh task's recently used CPU every time the task's domain
	 * is updated..
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

	p_mask = tctx->cpumask;
	if (!p_mask) {
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
	bpf_cpumask_and(p_mask, cpumask, cast_mask(primary));

	/*
	 * Determine the L2 cache domain as the intersection of the task's
	 * primary cpumask and the L2 cache domain mask of the previously used
	 * CPU.
	 */
	if (l2_domain)
		bpf_cpumask_and(l2_mask, cast_mask(p_mask), cast_mask(l2_domain));

	/*
	 * Determine the L3 cache domain as the intersection of the task's
	 * primary cpumask and the L3 cache domain mask of the previously used
	 * CPU.
	 */
	if (l3_domain)
		bpf_cpumask_and(l3_mask, cast_mask(p_mask), cast_mask(l3_domain));
}

/*
 * Return true if all the CPUs in the LLC of @cpu are busy, false
 * otherwise.
 */
static bool is_llc_busy(const struct cpumask *idle_cpumask, s32 cpu)
{
	const struct cpumask *primary, *l3_mask;
	struct cpu_ctx *cctx;

	primary = cast_mask(primary_cpumask);
	if (!primary)
		return false;

	cctx = try_lookup_cpu_ctx(cpu);
	if (!cctx)
		return false;

	l3_mask = cast_mask(cctx->l3_cpumask);
	if (!l3_mask)
		l3_mask = primary;

	return !bpf_cpumask_intersects(l3_mask, idle_cpumask);
}

/*
 * Return true if the waker commits to release the CPU after waking up @p,
 * false otherwise.
 */
static bool is_wake_sync(s32 prev_cpu, s32 this_cpu, u64 wake_flags)
{
	const struct task_struct *current = (void *)bpf_get_current_task_btf();

	if (no_wake_sync)
		return false;

	if ((wake_flags & SCX_WAKE_SYNC) && !(current->flags & PF_EXITING))
		return true;

	/*
	 * If the current task is a per-CPU kthread running on the wakee's
	 * previous CPU, treat it as a synchronous wakeup.
	 *
	 * The assumption is that the wakee had queued work for the per-CPU
	 * kthread, which has now finished, making the wakeup effectively
	 * synchronous. An example of this behavior is seen in IO
	 * completions.
	 */
	if (is_kthread(current) && (current->nr_cpus_allowed == 1) &&
	    (prev_cpu == this_cpu))
		return true;

	return false;
}

/*
 * Return the target CPU for @p in case of a sync wakeup.
 *
 * During a sync wakeup, the waker commits to releasing the CPU immediately
 * after the wakeup event, so we should consider a sync wakeup almost like
 * a direct function call between a waker and a wakee.
 */
static s32 try_sync_wakeup(const struct task_struct *p, s32 prev_cpu, s32 this_cpu)
{
	/*
	 * If @prev_cpu is idle, keep using it, since there is no guarantee
	 * that the cache hot data from the waker's CPU is more important
	 * than cache hot data in the wakee's CPU.
	 */
	if ((this_cpu != prev_cpu) && scx_bpf_test_and_clear_cpu_idle(prev_cpu))
		return prev_cpu;

	/*
	 * If waker and wakee are on the same CPU and no other tasks are
	 * queued, consider the waker's CPU as idle.
	 */
	if (!scx_bpf_dsq_nr_queued(SCX_DSQ_LOCAL_ON | this_cpu))
		return this_cpu;

	return -EBUSY;
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
static s32 pick_idle_cpu(struct task_struct *p, s32 prev_cpu, u64 wake_flags, bool *is_idle)
{
	const struct cpumask *idle_smtmask, *idle_cpumask;
	const struct cpumask *primary, *p_mask, *l2_mask, *l3_mask;
	struct task_ctx *tctx;
	int node;
	s32 this_cpu = bpf_get_smp_processor_id(), cpu;
	bool share_llc;

	primary = cast_mask(primary_cpumask);
	if (!primary)
		return -EINVAL;

	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return -ENOENT;

	/*
	 * If prev_cpu is not in the primary domain, pick an arbitrary CPU
	 * in the primary domain.
	 */
	if (!bpf_cpumask_test_cpu(prev_cpu, primary)) {
		cpu = bpf_cpumask_any_and_distribute(p->cpus_ptr, primary);
		if (cpu >= nr_cpu_ids)
			return prev_cpu;
		prev_cpu = cpu;
	}

	/*
	 * Refresh task domain based on the previously used cpu. If we keep
	 * selecting the same CPU, the task's domain doesn't need to be
	 * updated and we can save some cpumask ops.
	 */
	if (tctx->recent_used_cpu != prev_cpu)
		task_update_domain(p, tctx, prev_cpu, p->cpus_ptr);

	p_mask = cast_mask(tctx->cpumask);
	if (p_mask && bpf_cpumask_empty(p_mask))
		p_mask = NULL;
	l2_mask = cast_mask(tctx->l2_cpumask);
	if (l2_mask && bpf_cpumask_empty(l2_mask))
		l2_mask = NULL;
	l3_mask = cast_mask(tctx->l3_cpumask);
	if (l3_mask && bpf_cpumask_empty(l3_mask))
		l3_mask = NULL;

	/*
	 * Acquire the CPU masks to determine the idle CPUs in the system.
	 */
	node = __COMPAT_scx_bpf_cpu_node(prev_cpu);
	idle_smtmask = __COMPAT_scx_bpf_get_idle_smtmask_node(node);
	idle_cpumask = __COMPAT_scx_bpf_get_idle_cpumask_node(node);

	/*
	 * In case of a sync wakeup, attempt to run the wakee on the
	 * waker's CPU if possible, as it's going to release the CPU right
	 * after the wakeup, so it can be considered as idle and, possibly,
	 * cache hot.
	 *
	 * However, ignore this optimization if the LLC is completely
	 * saturated, since it's just more efficient to dispatch the task
	 * on the first CPU available.
	 */
	share_llc = l3_mask && bpf_cpumask_test_cpu(this_cpu, l3_mask);
	if (is_wake_sync(prev_cpu, this_cpu, wake_flags) &&
	    share_llc && !is_llc_busy(idle_cpumask, this_cpu)) {
		cpu = try_sync_wakeup(p, prev_cpu, this_cpu);
		if (cpu >= 0) {
			*is_idle = true;
			goto out_put_cpumask;
		}
	}

	/*
	 * Find the best idle CPU, prioritizing full idle cores in SMT systems.
	 */
	if (smt_enabled) {
		/*
		 * If the task can still run on the previously used CPU and
		 * it's a full-idle core, keep using it.
		 */
		if (bpf_cpumask_test_cpu(prev_cpu, idle_smtmask) &&
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
			cpu = __COMPAT_scx_bpf_pick_idle_cpu_node(l2_mask, node,
						SCX_PICK_IDLE_CORE | __COMPAT_SCX_PICK_IDLE_IN_NODE);
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
			cpu = __COMPAT_scx_bpf_pick_idle_cpu_node(l3_mask, node,
						SCX_PICK_IDLE_CORE | __COMPAT_SCX_PICK_IDLE_IN_NODE);
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

			cpu = __COMPAT_scx_bpf_pick_idle_cpu_node(p_mask, node, flags);
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
	if (scx_bpf_test_and_clear_cpu_idle(prev_cpu)) {
		cpu = prev_cpu;
		*is_idle = true;
		goto out_put_cpumask;
	}

	/*
	 * Search for any idle CPU in the primary domain that shares the same
	 * L2 cache.
	 */
	if (l2_mask && !node_rebalance(node)) {
		cpu = __COMPAT_scx_bpf_pick_idle_cpu_node(l2_mask, node,
						__COMPAT_SCX_PICK_IDLE_IN_NODE);
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
		cpu = __COMPAT_scx_bpf_pick_idle_cpu_node(l3_mask, node,
						__COMPAT_SCX_PICK_IDLE_IN_NODE);
		if (cpu >= 0) {
			*is_idle = true;
			goto out_put_cpumask;
		}
	}

	/*
	 * Search for any idle CPU in the scheduling domain.
	 */
	if (p_mask) {
		cpu = __COMPAT_scx_bpf_pick_idle_cpu_node(p_mask, node, 0);
		if (cpu >= 0) {
			*is_idle = true;
			goto out_put_cpumask;
		}
	}

	/*
	 * Search for any idle CPU usable by the task.
	 */
	cpu = __COMPAT_scx_bpf_pick_idle_cpu_node(p->cpus_ptr, node, 0);
	if (cpu >= 0) {
		*is_idle = true;
		goto out_put_cpumask;
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
 * Return true if we can perform a direct dispatch on @node, false
 * otherwise.
 */
static bool can_direct_dispatch(int node)
{
	/*
	 * Never allow direct dispatch if preemption is disabled.
	 */
	if (no_preempt)
		return false;

	/*
	 * Allow direct dispatch when @local_pcpu is enabled, or when there
	 * are no tasks queued in the node DSQ.
	 */
	return local_pcpu || !scx_bpf_dsq_nr_queued(node);
}

/*
 * Pick a target CPU for a task which is being woken up.
 *
 * If a task is dispatched here, ops.enqueue() will be skipped: task will be
 * dispatched directly to the CPU returned by this callback.
 */
s32 BPF_STRUCT_OPS(bpfland_select_cpu, struct task_struct *p,
			s32 prev_cpu, u64 wake_flags)
{
	bool is_idle = false;
	s32 cpu;

	cpu = pick_idle_cpu(p, prev_cpu, wake_flags, &is_idle);
	if (is_idle) {
		int node = __COMPAT_scx_bpf_cpu_node(cpu);

		if (can_direct_dispatch(node)) {
			scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, slice_max, 0);
			__sync_fetch_and_add(&nr_direct_dispatches, 1);
		}
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

	/*
	 * No need to look for full-idle SMT cores if SMT is disabled.
	 */
	if (idle_smt && !smt_enabled)
		return false;

	/*
	 * Try to reuse the same CPU if idle.
	 */
	if (!idle_smt || (idle_smt && is_fully_idle(prev_cpu))) {
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
		cpu = __COMPAT_scx_bpf_pick_idle_cpu_node(mask, node,
					flags | __COMPAT_SCX_PICK_IDLE_IN_NODE);
		if (cpu >= 0) {
			scx_bpf_kick_cpu(cpu, SCX_KICK_IDLE);
			return true;
		}
	}
	mask = cast_mask(tctx->l3_cpumask);
	if (mask) {
		cpu = __COMPAT_scx_bpf_pick_idle_cpu_node(mask, node,
					flags | __COMPAT_SCX_PICK_IDLE_IN_NODE);
		if (cpu >= 0) {
			scx_bpf_kick_cpu(cpu, SCX_KICK_IDLE);
			return true;
		}
	}

	return false;
}

/*
 * Attempt to dispatch a task directly to its assigned CPU.
 *
 * Return true if the task is dispatched, false otherwise.
 */
static bool try_direct_dispatch(struct task_struct *p, struct task_ctx *tctx,
				s32 prev_cpu, u64 slice, u64 enq_flags)
{
	/*
	 * If a task has been re-enqueued because its assigned CPU has been
	 * taken by a higher priority scheduling class, force it to follow
	 * the regular scheduling path and give it a chance to run on a
	 * different CPU.
	 */
	if (enq_flags & SCX_ENQ_REENQ)
		return false;

	/*
	 * If local_kthread is specified dispatch per-CPU kthreads
	 * directly on their assigned CPU.
	 */
	if (local_kthreads && is_kthread(p) && p->nr_cpus_allowed == 1) {
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, slice_max, enq_flags);
		__sync_fetch_and_add(&nr_kthread_dispatches, 1);

		return true;
	}

	/*
	 * If ops.select_cpu() has been skipped, try direct dispatch.
	 */
	if (!__COMPAT_is_enq_cpu_selected(enq_flags)) {
		int node = __COMPAT_scx_bpf_cpu_node(prev_cpu);

		/*
		 * Stop here if direct dispatch is not allowed in the
		 * target node.
		 */
		if (!can_direct_dispatch(node))
			return false;

		/*
		 * If local_pcpu is enabled always dispatch tasks that can
		 * only run on one CPU directly.
		 *
		 * This can help to improve I/O workloads (like large
		 * parallel builds).
		 */
		if (local_pcpu && p->nr_cpus_allowed == 1) {
			scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, slice, enq_flags);
			__sync_fetch_and_add(&nr_direct_dispatches, 1);

			return true;
		}

		/*
		 * If the task can only run on a single CPU and that CPU is
		 * idle, perform a direct dispatch.
		 */
		if (p->nr_cpus_allowed == 1 || is_migration_disabled(p)) {
			if (scx_bpf_test_and_clear_cpu_idle(prev_cpu)) {
				scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL,
						   slice_max, enq_flags);
				__sync_fetch_and_add(&nr_direct_dispatches, 1);

				return true;
			}

			/*
			 * No need to check for other CPUs if the task can
			 * only run on a single one.
			 */
			return false;
		}

		/*
		 * For tasks that are not limited to run on a single CPU,
		 * check if their previously used CPU is a full-idle SMT
		 * core and in that case perform a direct dispatch.
		 */
		if (is_fully_idle(prev_cpu)) {
			scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | prev_cpu,
					   slice_max, enq_flags);
			__sync_fetch_and_add(&nr_direct_dispatches, 1);

			return true;
		}

		/*
		 * In case of a remote wakeup (ttwu_queue), attempt a task
		 * migration.
		 */
		if (!scx_bpf_task_running(p)) {
			bool is_idle = false;
			s32 cpu;

			cpu = pick_idle_cpu(p, prev_cpu, 0, &is_idle);
			if (is_idle) {
				scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | cpu, slice_max, 0);
				__sync_fetch_and_add(&nr_direct_dispatches, 1);

				return true;
			}
		}
	}

	/*
	 * Direct dispatch not possible, follow the regular scheduling
	 * path.
	 */
	return false;
}

/*
 * Dispatch all the other tasks that were not dispatched directly in
 * select_cpu().
 */
void BPF_STRUCT_OPS(bpfland_enqueue, struct task_struct *p, u64 enq_flags)
{
	const struct cpumask *idle_cpumask;
	struct task_ctx *tctx;
	u64 slice, deadline;
	s32 prev_cpu = scx_bpf_task_cpu(p);
	int node = __COMPAT_scx_bpf_cpu_node(prev_cpu);

	/*
	 * Dispatch regular tasks to the shared DSQ.
	 */
	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return;
	deadline = task_deadline(p, tctx);
	slice = CLAMP(slice_max / nr_tasks_waiting(node), slice_min, slice_max);

	/*
	 * Try to dispatch the task directly, if possible.
	 */
	if (try_direct_dispatch(p, tctx, prev_cpu, slice, enq_flags))
		return;

	scx_bpf_dsq_insert_vtime(p, node, slice, deadline, enq_flags);
	__sync_fetch_and_add(&nr_shared_dispatches, 1);

	/*
	 * If there are idle CPUs in the system try to proactively wake up
	 * one, so that it can immediately execute the task in case its
	 * current CPU is busy (always prioritizing full-idle SMT cores
	 * first, if present).
	 */
	idle_cpumask = __COMPAT_scx_bpf_get_idle_cpumask_node(node);
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

	/* Do not keep running if the CPU is not in the primary domain */
	if (!primary || !bpf_cpumask_test_cpu(cpu, primary))
		return false;

	/*
	 * Keep running only if the task is on a full-idle SMT core (or SMT
	 * is disabled).
	 */
	if (!smt_enabled)
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

	idle_smtmask = __COMPAT_scx_bpf_get_idle_smtmask_node(node);
	idle_cpumask = __COMPAT_scx_bpf_get_idle_cpumask_node(node);

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

void BPF_STRUCT_OPS(bpfland_dispatch, s32 cpu, struct task_struct *prev)
{
	int node = __COMPAT_scx_bpf_cpu_node(cpu);

	/*
	 * Consume regular tasks from the shared DSQ, transferring them to the
	 * local CPU DSQ.
	 */
	if (scx_bpf_dsq_move_to_local(node))
		return;

	/*
	 * If the current task expired its time slice and no other task wants
	 * to run, simply replenish its time slice and let it run for another
	 * round on the same CPU.
	 */
	if (prev && keep_running(prev, cpu))
		prev->scx.slice = slice_max;
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
	tctx->last_run_at = scx_bpf_now();

	/*
	 * Adjust target CPU frequency before the task starts to run.
	 */
	update_cpu_load(p, tctx);

	/*
	 * Update the global vruntime as a new task is starting to use a
	 * CPU.
	 */
	if (time_before(vtime_now, tctx->deadline))
		vtime_now = tctx->deadline;
}

/*
 * Update task statistics when the task is releasing the CPU (either
 * voluntarily or because it expires its assigned time slice).
 */
void BPF_STRUCT_OPS(bpfland_stopping, struct task_struct *p, bool runnable)
{
	u64 now = scx_bpf_now(), slice, delta_runtime;
	s32 cpu = scx_bpf_task_cpu(p);
	struct cpu_ctx *cctx;
	struct task_ctx *tctx;

	__sync_fetch_and_sub(&nr_running, 1);

	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return;

	/*
	 * Evaluate the time slice used by the task.
	 */
	slice = scx_bpf_now() - tctx->last_run_at;

	/*
	 * Update task's execution time (exec_runtime), but never account
	 * more than 10 slices of runtime to prevent excessive
	 * de-prioritization of CPU-intensive tasks (which could lead to
	 * starvation).
	 */
	if (tctx->exec_runtime < 10 * slice_max)
		tctx->exec_runtime += slice;

	/*
	 * Update task's vruntime.
	 */
	tctx->deadline += scale_by_task_normalized_weight_inverse(p, slice);

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
	struct task_ctx *tctx;

	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return;

	tctx->exec_runtime = 0;
}

void BPF_STRUCT_OPS(bpfland_cpu_release, s32 cpu, struct scx_cpu_release_args *args)
{
	/*
	 * When a CPU is taken by a higher priority scheduler class,
	 * re-enqueue all the tasks that are waiting in the local DSQ, so
	 * that we can give them a chance to run on another CPU.
	 */
	scx_bpf_reenqueue_local();
}

void BPF_STRUCT_OPS(bpfland_set_cpumask, struct task_struct *p,
		    const struct cpumask *cpumask)
{
	s32 cpu = bpf_get_smp_processor_id();
	struct task_ctx *tctx;

	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return;

	task_update_domain(p, tctx, cpu, cpumask);
}

void BPF_STRUCT_OPS(bpfland_enable, struct task_struct *p)
{
	struct task_ctx *tctx;

	/* Initialize voluntary context switch timestamp */
	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return;

	/*
	 * Initialize the task vruntime to the current global vruntime.
	 */
	tctx->deadline = vtime_now;
}

s32 BPF_STRUCT_OPS(bpfland_init_task, struct task_struct *p,
		   struct scx_init_task_args *args)
{
	s32 cpu = bpf_get_smp_processor_id();
	struct task_ctx *tctx;
	struct bpf_cpumask *cpumask;

	tctx = bpf_task_storage_get(&task_ctx_stor, p, 0,
				    BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!tctx)
		return -ENOMEM;
	/*
	 * Create task's primary cpumask.
	 */
	cpumask = bpf_cpumask_create();
	if (!cpumask)
		return -ENOMEM;
	cpumask = bpf_kptr_xchg(&tctx->cpumask, cpumask);
	if (cpumask)
		bpf_cpumask_release(cpumask);
	/*
	 * Create task's L2 cache cpumask.
	 */
	cpumask = bpf_cpumask_create();
	if (!cpumask)
		return -ENOMEM;
	cpumask = bpf_kptr_xchg(&tctx->l2_cpumask, cpumask);
	if (cpumask)
		bpf_cpumask_release(cpumask);
	/*
	 * Create task's L3 cache cpumask.
	 */
	cpumask = bpf_cpumask_create();
	if (!cpumask)
		return -ENOMEM;
	cpumask = bpf_kptr_xchg(&tctx->l3_cpumask, cpumask);
	if (cpumask)
		bpf_cpumask_release(cpumask);

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

s32 BPF_STRUCT_OPS_SLEEPABLE(bpfland_init)
{
	struct bpf_timer *timer;
	int err, node;
	u32 key = 0;

	/* Initialize amount of online and possible CPUs */
	nr_online_cpus = get_nr_online_cpus();
	nr_cpu_ids = scx_bpf_nr_cpu_ids();

	/* Initialize CPUs and NUMA properties */
	init_cpuperf_target();

	/*
	 * Create the global shared DSQ.
	 */
	bpf_for(node, 0, __COMPAT_scx_bpf_nr_node_ids()) {
		err = scx_bpf_create_dsq(node, node);
		if (err) {
			scx_bpf_error("failed to create DSQ %d: %d", node, err);
			return err;
		}
	}

	/* Initialize the primary scheduling domain */
	err = init_cpumask(&primary_cpumask);
	if (err)
		return err;

	/* Do not update NUMA statistics if there's only one node */
	if (numa_disabled || __COMPAT_scx_bpf_nr_node_ids() <= 1)
		return 0;

	timer = bpf_map_lookup_elem(&numa_timer, &key);
	if (!timer) {
		scx_bpf_error("Failed to lookup central timer");
		return -ESRCH;
	}

	bpf_timer_init(timer, &numa_timer, CLOCK_BOOTTIME);
	bpf_timer_set_callback(timer, numa_timerfn);
	err = bpf_timer_start(timer, NSEC_PER_SEC, 0);
	if (err)
		scx_bpf_error("Failed to start NUMA timer");

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
	       .cpu_release		= (void *)bpfland_cpu_release,
	       .set_cpumask		= (void *)bpfland_set_cpumask,
	       .enable			= (void *)bpfland_enable,
	       .init_task		= (void *)bpfland_init_task,
	       .init			= (void *)bpfland_init,
	       .exit			= (void *)bpfland_exit,
	       .timeout_ms		= 5000,
	       .name			= "bpfland");
