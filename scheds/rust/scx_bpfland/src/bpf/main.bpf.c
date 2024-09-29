/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2024 Andrea Righi <andrea.righi@linux.dev>
 */
#include <scx/common.bpf.h>
#include "intf.h"

char _license[] SEC("license") = "GPL";

/* Allow to use bpf_printk() only when @debug is set */
#define dbg_msg(_fmt, ...) do {				\
	if (debug)					\
		bpf_printk(_fmt, ##__VA_ARGS__);	\
} while(0)

 /* Report additional debugging information */
const volatile bool debug;

/*
 * Priority DSQ used to dispatch interactive tasks.
 */
static s32 prio_dsq_id;

/*
 * DSQ used to dispatch regular tasks.
 */
static s32 shared_dsq_id;

/*
 * Default task time slice.
 */
const volatile u64 slice_ns = 5ULL * NSEC_PER_MSEC;

/*
 * Time slice used when system is over commissioned.
 */
const volatile u64 slice_ns_min = 500ULL * NSEC_PER_USEC;

/*
 * Maximum time slice lag.
 *
 * Increasing this value can help to increase the responsiveness of interactive
 * tasks at the cost of making regular and newly created tasks less responsive
 * (0 = disabled).
 */
const volatile s64 slice_ns_lag;

/*
 * When enabled always dispatch per-CPU kthreads directly on their CPU DSQ.
 *
 * This allows to prioritize critical kernel threads that may potentially slow
 * down the entire system if they are blocked for too long (i.e., ksoftirqd/N,
 * rcuop/N, etc.).
 *
 * NOTE: this could cause interactivity problems or unfairness if there are too
 * many softirqs being scheduled (e.g., in presence of high RX network RX
 * traffic).
 */
const volatile bool local_kthreads;

/*
 * Boost interactive tasks, by shortening their deadline as a function of their
 * average amount of voluntary context switches.
 *
 * Tasks are already classified as interactive if their average amount of
 * context switches exceeds nvcsw_avg_thresh, which grants them higher
 * priority.
 *
 * When this option is enabled, tasks will receive a deadline boost in addition
 * to their interactive vs. regular classification, with the boost being
 * proportional to their average number of context switches.
 *
 * This ensures that within the main scheduling classes (interactive and
 * regular), tasks that more frequently voluntarily yield the CPU receive an
 * even higher priority.
 *
 * This option is particularly useful in soft real-time scenarios, such as
 * audio processing, multimedia, etc.
 */
const volatile bool lowlatency;

/*
 * Maximum threshold of voluntary context switches.
 *
 * This limits the range of nvcsw_avg_thresh (see below).
 */
const volatile u64 nvcsw_max_thresh = 10ULL;

/*
 * Global average of voluntary context switches used to classify interactive
 * tasks: tasks with an average amount of voluntary context switches (nvcsw)
 * greater than this value will be classified as interactive.
 */
volatile u64 nvcsw_avg_thresh;

/*
 * The CPU frequency performance level: a negative value will not affect the
 * performance level and will be ignored.
 */
volatile s64 cpufreq_perf_lvl;

/*
 * Time threshold to prevent task starvation.
 *
 * The scheduler processes tasks from various DSQs in the following order:
 *
 *  per-CPU DSQs => priority DSQ => shared DSQ
 *
 *  Tasks in the shared DSQ may be starved by those in the priority DSQ, which
 *  in turn may be starved by tasks in any per-CPU DSQ.
 *
 *  To mitigate this, store the timestamp of the last task consumption from
 *  both the priority DSQ and the shared DSQ. If the starvation_thresh_ns
 *  threshold is exceeded without consuming a task, the scheduler will be
 *  forced to consume a task from the corresponding DSQ.
 */
const volatile u64 starvation_thresh_ns = 5ULL * NSEC_PER_MSEC;
static u64 starvation_shared_ts;
static u64 starvation_prio_ts;

/*
 * Scheduling statistics.
 */
volatile u64 nr_direct_dispatches, nr_shared_dispatches, nr_prio_dispatches;

/*
 * Amount of currently running tasks.
 */
volatile u64 nr_running, nr_waiting, nr_interactive, nr_online_cpus;

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
 * Mask of offline CPUs, used to properly support CPU hotplugging.
 */
private(BPFLAND) struct bpf_cpumask __kptr *offline_cpumask;

/*
 * Determine when we need to drain tasks dispatched to CPUs that went offline.
 */
static int offline_needed;

/*
 * CPU hotplugging generation counter (used to notify the user-space
 * counterpart when a CPU hotplug event happened, allowing it to refresh the
 * topology information).
 */
volatile u64 cpu_hotplug_cnt;

/*
 * Notify the scheduler that we need to drain and re-enqueue the tasks
 * dispatched to the offline CPU DSQs.
 */
static void set_offline_needed(void)
{
	__sync_fetch_and_or(&offline_needed, 1);
}

/*
 * Check and clear the state of the offline CPUs re-enqueuing.
 */
static bool test_and_clear_offline_needed(void)
{
	return __sync_fetch_and_and(&offline_needed, 0) == 1;
}

/*
 * CPUs in the system have SMT is enabled.
 */
const volatile bool smt_enabled = true;

/*
 * Current global vruntime.
 */
static u64 vtime_now;

/*
 * Per-CPU context.
 */
struct cpu_ctx {
	u64 tot_runtime;
	u64 prev_runtime;
	u64 last_running;
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
	 * Total execution time of the task.
	 */
	u64 sum_exec_runtime;

	/*
	 * Voluntary context switches metrics.
	 */
	u64 nvcsw;
	u64 nvcsw_ts;
	u64 avg_nvcsw;

	/*
	 * Set to true if the task is classified as interactive.
	 */
	bool is_interactive;

	/*
	 * Determine if ops.select_cpu() has been called.
	 */
	bool select_cpu_done;
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
 * Return true if interactive tasks classification via voluntary context
 * switches is enabled, false otherwise.
 */
static bool is_nvcsw_enabled(void)
{
	return !!nvcsw_max_thresh;
}

/*
 * Return true if the task is interactive, false otherwise.
 */
static bool is_task_interactive(struct task_struct *p)
{
	struct task_ctx *tctx;

	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return false;
	return tctx->is_interactive;
}

/*
 * Return true if the target task @p is a kernel thread.
 */
static inline bool is_kthread(const struct task_struct *p)
{
	return p->flags & PF_KTHREAD;
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
 * Set the state of a CPU in a cpumask.
 */
static bool set_cpu_state(struct bpf_cpumask *cpumask, s32 cpu, bool state)
{
	if (!cpumask)
		return false;
	if (state)
		return bpf_cpumask_test_and_set_cpu(cpu, cpumask);
	else
		return bpf_cpumask_test_and_clear_cpu(cpu, cpumask);
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
 * Compare two vruntime values, returns true if the first value is less than
 * the second one.
 *
 * Copied from scx_simple.
 */
static inline bool vtime_before(u64 a, u64 b)
{
	return (s64)(a - b) < 0;
}

/*
 * Return task's average amount of context switches per second.
 */
static bool task_avg_nvcsw(struct task_struct *p)
{
	struct task_ctx *tctx;

	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return 0;
	return tctx->avg_nvcsw;
}

/*
 * Return task's evaluated deadline.
 */
static inline u64 task_deadline(struct task_struct *p)
{
	u64 dl_boost = lowlatency ? task_avg_nvcsw(p) * slice_ns : 0;

	/*
	 * Limit the vruntime to (vtime_now - slice_ns_lag) to avoid
	 * excessively penalizing tasks.
	 *
	 * A positive slice_ns_lag can enhance vruntime scheduling
	 * effectiveness, but it may lead to more "spikey" performance as tasks
	 * could remain in the queue for too long.
	 *
	 * Instead, a negative slice_ns_lag can result in more consistent
	 * performance (less spikey), smoothing the reordering of the vruntime
	 * scheduling and making the scheduler closer to a FIFO.
	 */
	if (vtime_before(p->scx.dsq_vtime, vtime_now - slice_ns_lag))
		p->scx.dsq_vtime = vtime_now - slice_ns_lag;

	/*
	 * Return the task's deadline as its vruntime, with a bonus that is
	 * proportional to the task's average number of voluntary context
	 * switches.
	 *
	 * Also make sure the bonus is limited to the starvation threshold (to
	 * prevent starvation).
	 */
	return p->scx.dsq_vtime - MIN(dl_boost, starvation_thresh_ns);
}

/*
 * Return the amount of tasks waiting to be dispatched.
 */
static u64 nr_tasks_waiting(void)
{
	return scx_bpf_dsq_nr_queued(prio_dsq_id) +
	       scx_bpf_dsq_nr_queued(shared_dsq_id);
}

/*
 * Return the task's unused portion of its previously assigned time slice in
 * the range a [slice_ns_min .. slice_ns].
 */
static inline u64 task_slice(struct task_struct *p)
{
	/*
	 * Refresh the amount of waiting tasks to get a more accurate scaling
	 * factor for the time slice.
	 */
	nr_waiting = (nr_waiting + nr_tasks_waiting()) / 2;

	/*
	 * Scale the time slice based on the average number of waiting tasks
	 * (more waiting tasks result in a shorter time slice).
	 */
	return MAX(slice_ns / (nr_waiting + 1), slice_ns_min);
}

/*
 * Return the DSQ ID associated to a CPU, or shared_dsq_id if the CPU is not
 * valid.
 */
static u64 cpu_to_dsq(s32 cpu)
{
	u64 nr_cpu_ids = scx_bpf_nr_cpu_ids();

	if (cpu < 0 || cpu >= nr_cpu_ids) {
		scx_bpf_error("Invalid cpu: %d", cpu);
		return shared_dsq_id;
	}
	return (u64)cpu;
}

/*
 * Dispatch a task directly to the assigned CPU DSQ (used when an idle CPU is
 * found).
 */
static int dispatch_direct_cpu(struct task_struct *p, s32 cpu, u64 enq_flags)
{
	struct bpf_cpumask *offline;
	u64 deadline = task_deadline(p);
	u64 dsq_id = cpu_to_dsq(cpu);

	/*
	 * Make sure we can dispatch the task to the target CPU according to
	 * its cpumask.
	 */
	if (!bpf_cpumask_test_cpu(cpu, p->cpus_ptr)) {
		scx_bpf_error("%d %s can't be dispatched to CPU %d",
			      p->pid, p->comm, cpu);
		return -EINVAL;
	}

	scx_bpf_dispatch_vtime(p, dsq_id, SCX_SLICE_DFL, deadline, enq_flags);

	/*
	 * If the CPU has gone offline notify that the task needs to be
	 * consumed from another CPU.
	 */
	offline = offline_cpumask;
	if (!offline)
		return 0;
	if (bpf_cpumask_test_cpu(cpu, cast_mask(offline))) {
		set_offline_needed();
		return 0;
	}

	/*
	 * Wake-up the target CPU to make sure that the task is consumed as
	 * soon as possible.
	 *
	 * Note that the target CPU must be activated, because the task has
	 * been dispatched to a DSQ that only the target CPU can consume. If we
	 * do not kick the CPU, and the CPU is idle, the task can stall in the
	 * DSQ indefinitely.
	 */
	scx_bpf_kick_cpu(cpu, SCX_KICK_IDLE);

	return 0;
}

/*
 * Return true if priority DSQ is congested, false otherwise.
 */
static bool is_prio_congested(void)
{
	return scx_bpf_dsq_nr_queued(prio_dsq_id) > nr_online_cpus * 4;
}

/*
 * Handle synchronous wake-up event for a task.
 */
static void handle_sync_wakeup(struct task_struct *p)
{
	struct task_ctx *tctx;

	/*
	 * If we are waking up a task immediately promote it as interactive, so
	 * that it can be dispatched as soon as possible on the first CPU
	 * available.
	 *
	 * However, if the priority queue is congested, we don't want to
	 * promote additional interactive tasks, instead we give priority to
	 * the tasks that are already classified as interactive.
	 */
	tctx = try_lookup_task_ctx(p);
	if (tctx && is_nvcsw_enabled() && !is_prio_congested())
		tctx->is_interactive = true;
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
static s32 pick_idle_cpu(struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
	const struct cpumask *online_cpumask, *idle_smtmask, *idle_cpumask;
	struct bpf_cpumask *primary, *l2_domain, *l3_domain;
	struct bpf_cpumask *p_mask, *l2_mask, *l3_mask;
	struct task_ctx *tctx;
	struct cpu_ctx *cctx;
	s32 cpu;

	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return -ENOENT;
	cctx = try_lookup_cpu_ctx(prev_cpu);
	if (!cctx)
		return -ENOENT;

	primary = primary_cpumask;
	if (!primary)
		return -ENOENT;

	/*
	 * If the task isn't allowed to use its previously used CPU it means
	 * that it's rapidly changing affinity. In this case it's pointless to
	 * find an optimal idle CPU, just return and let the task being
	 * dispatched to a global DSQ.
	 */
	if (!bpf_cpumask_test_cpu(prev_cpu, p->cpus_ptr))
		return -ENOENT;

	/*
	 * For tasks that can run only on a single CPU, we can simply verify if
	 * their only allowed CPU is still idle.
	 */
	if (p->nr_cpus_allowed == 1) {
		if (scx_bpf_test_and_clear_cpu_idle(prev_cpu))
			return prev_cpu;
		/*
		 * If local_kthreads is enabled, always dispatch per-CPU
		 * kthreads directly, even if their allowed CPU is not idle.
		 */
		if (local_kthreads && is_kthread(p))
			return prev_cpu;
		return -ENOENT;
	}

	/*
	 * Acquire the CPU masks to determine the online and idle CPUs in the
	 * system.
	 */
	online_cpumask = scx_bpf_get_online_cpumask();
	idle_smtmask = scx_bpf_get_idle_smtmask();
	idle_cpumask = scx_bpf_get_idle_cpumask();

	/*
	 * Scheduling domains of the previously used CPU.
	 */
	l2_domain = cctx->l2_cpumask;
	if (!l2_domain)
		l2_domain = primary;
	l3_domain = cctx->l3_cpumask;
	if (!l3_domain)
		l3_domain = primary;

	/*
	 * Task's scheduling domains.
	 */
	p_mask = tctx->cpumask;
	if (!p_mask) {
		scx_bpf_error("cpumask not initialized");
		cpu = prev_cpu;
		goto out_put_cpumask;
	}
	l2_mask = tctx->l2_cpumask;
	if (!l2_mask) {
		scx_bpf_error("l2 cpumask not initialized");
		cpu = prev_cpu;
		goto out_put_cpumask;
	}
	l3_mask = tctx->l3_cpumask;
	if (!l3_mask) {
		scx_bpf_error("l3 cpumask not initialized");
		cpu = prev_cpu;
		goto out_put_cpumask;
	}

	/*
	 * Determine the task's scheduling domain.
	 * idle CPU, re-try again with the primary scheduling domain.
	 */
	bpf_cpumask_and(p_mask, p->cpus_ptr, cast_mask(primary));

	/*
	 * Determine the L2 cache domain as the intersection of the task's
	 * primary cpumask and the L2 cache domain mask of the previously used
	 * CPU (ignore if this cpumask completely overlaps with the task's
	 * cpumask).
	 */
	bpf_cpumask_and(l2_mask, cast_mask(p_mask), cast_mask(l2_domain));
	if (bpf_cpumask_empty(cast_mask(l2_mask)))
		l2_mask = NULL;

	/*
	 * Determine the L3 cache domain as the intersection of the task's
	 * primary cpumask and the L3 cache domain mask of the previously used
	 * CPU (ignore if this cpumask completely overlaps with the task's
	 * cpumask).
	 */
	bpf_cpumask_and(l3_mask, cast_mask(p_mask), cast_mask(l3_domain));
	if (bpf_cpumask_empty(cast_mask(l3_mask)))
		l3_mask = NULL;

	if (wake_flags & SCX_WAKE_SYNC) {
		struct task_struct *current = (void *)bpf_get_current_task_btf();
		bool share_llc, has_idle;

		/*
		 * Prioritize newly awakened tasks by immediately promoting
		 * them as interactive.
		 */
		handle_sync_wakeup(p);

		/*
		 * Determine waker CPU scheduling domain.
		 */
		cpu = bpf_get_smp_processor_id();

		cctx = try_lookup_cpu_ctx(cpu);
		if (!cctx) {
			cpu = -ENOENT;
			goto out_put_cpumask;
		}

		l3_domain = cctx->l3_cpumask;
		if (!l3_domain) {
			scx_bpf_error("CPU L3 cpumask not initialized");
			cpu = -ENOENT;
			goto out_put_cpumask;
		}

		/*
		 * If both the waker and wakee share the same L3 cache keep
		 * using the same CPU if possible.
		 */
		share_llc = bpf_cpumask_test_cpu(prev_cpu, cast_mask(l3_domain));
		if (share_llc && scx_bpf_test_and_clear_cpu_idle(prev_cpu)) {
			cpu = prev_cpu;
			goto out_put_cpumask;
		}

		/*
		 * If the waker's L3 domain is not saturated attempt to migrate
		 * the wakee on the same CPU as the waker.
		 */
		has_idle = bpf_cpumask_intersects(cast_mask(l3_domain), idle_cpumask);
		if (has_idle &&
		    bpf_cpumask_test_cpu(cpu, p->cpus_ptr) &&
		    !(current->flags & PF_EXITING) &&
		    scx_bpf_dsq_nr_queued(cpu_to_dsq(cpu)) == 0)
			goto out_put_cpumask;
	}

	/*
	 * Find the best idle CPU, prioritizing full idle cores in SMT systems.
	 */
	if (smt_enabled) {
		/*
		 * If the task can still run on the previously used CPU and
		 * it's a full-idle core, keep using it.
		 */
		if (bpf_cpumask_test_cpu(prev_cpu, cast_mask(p_mask)) &&
		    bpf_cpumask_test_cpu(prev_cpu, idle_smtmask) &&
		    scx_bpf_test_and_clear_cpu_idle(prev_cpu)) {
			cpu = prev_cpu;
			goto out_put_cpumask;
		}

		/*
		 * Search for any full-idle CPU in the primary domain that
		 * shares the same L2 cache.
		 */
		if (l2_mask) {
			cpu = bpf_cpumask_any_and_distribute(cast_mask(l2_mask), idle_smtmask);
			if (bpf_cpumask_test_cpu(cpu, online_cpumask) &&
			    scx_bpf_test_and_clear_cpu_idle(cpu))
				goto out_put_cpumask;
		}

		/*
		 * Search for any full-idle CPU in the primary domain that
		 * shares the same L3 cache.
		 */
		if (l3_mask) {
			cpu = bpf_cpumask_any_and_distribute(cast_mask(l3_mask), idle_smtmask);
			if (bpf_cpumask_test_cpu(cpu, online_cpumask) &&
			    scx_bpf_test_and_clear_cpu_idle(cpu))
				goto out_put_cpumask;
		}

		/*
		 * Search for any other full-idle core in the primary domain.
		 */
		cpu = bpf_cpumask_any_and_distribute(cast_mask(p_mask), idle_smtmask);
		if (bpf_cpumask_test_cpu(cpu, online_cpumask) &&
		    scx_bpf_test_and_clear_cpu_idle(cpu))
			goto out_put_cpumask;
	}

	/*
	 * If a full-idle core can't be found (or if this is not an SMT system)
	 * try to re-use the same CPU, even if it's not in a full-idle core.
	 */
	if (bpf_cpumask_test_cpu(prev_cpu, cast_mask(p_mask)) &&
	    scx_bpf_test_and_clear_cpu_idle(prev_cpu)) {
		cpu = prev_cpu;
		goto out_put_cpumask;
	}

	/*
	 * Search for any idle CPU in the primary domain that shares the same
	 * L2 cache.
	 */
	if (l2_mask) {
		cpu = bpf_cpumask_any_and_distribute(cast_mask(l2_mask), idle_cpumask);
		if (bpf_cpumask_test_cpu(cpu, online_cpumask) &&
		    scx_bpf_test_and_clear_cpu_idle(cpu))
			goto out_put_cpumask;
	}

	/*
	 * Search for any idle CPU in the primary domain that shares the same
	 * L3 cache.
	 */
	if (l3_mask) {
		cpu = bpf_cpumask_any_and_distribute(cast_mask(l3_mask), idle_cpumask);
		if (bpf_cpumask_test_cpu(cpu, online_cpumask) &&
		    scx_bpf_test_and_clear_cpu_idle(cpu))
			goto out_put_cpumask;
	}

	/*
	 * Search for any idle CPU in the scheduling domain.
	 */
	cpu = bpf_cpumask_any_and_distribute(cast_mask(p_mask), idle_cpumask);
	if (bpf_cpumask_test_cpu(cpu, online_cpumask) &&
	    scx_bpf_test_and_clear_cpu_idle(cpu))
		goto out_put_cpumask;

	/*
	 * We couldn't find any idle CPU, so simply dispatch the task to the
	 * first CPU that will become available.
	 */
	cpu = -ENOENT;

out_put_cpumask:
	scx_bpf_put_cpumask(idle_cpumask);
	scx_bpf_put_cpumask(idle_smtmask);
	scx_bpf_put_cpumask(online_cpumask);

	return cpu;
}

s32 BPF_STRUCT_OPS(bpfland_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
	struct task_ctx *tctx;
	s32 cpu;

	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return prev_cpu;

	cpu = pick_idle_cpu(p, prev_cpu, wake_flags);
	if (cpu >= 0 && !dispatch_direct_cpu(p, cpu, 0))
		__sync_fetch_and_add(&nr_direct_dispatches, 1);
	else
		cpu = prev_cpu;

	tctx->select_cpu_done = true;

	return cpu;
}

/*
 * Dispatch all the other tasks that were not dispatched directly in
 * select_cpu().
 */
void BPF_STRUCT_OPS(bpfland_enqueue, struct task_struct *p, u64 enq_flags)
{
	struct bpf_cpumask *primary;
	struct task_ctx *tctx;
	u64 deadline = task_deadline(p);
	s32 cpu = scx_bpf_task_cpu(p);

	/*
	 * During ttwu, the kernel may decide to skip ->select_task_rq() (e.g.,
	 * when only one CPU is allowed or migration is disabled). This causes
	 * to call ops.enqueue() directly without having a chance to call
	 * ops.select_cpu().
	 *
	 * Therefore, rely on the flag tctx->select_cpu_done to determine if
	 * ops.select_cpu() was called, if not check for idle CPU directly here
	 * from ops.enqueue(), giving the task a chance to be dispatched
	 * directly on an idle CPU, without going to the shared DSQ.
	 */
	tctx = try_lookup_task_ctx(p);
	if (tctx && !tctx->select_cpu_done) {
		cpu = pick_idle_cpu(p, cpu, 0);
		if (cpu >= 0 && !dispatch_direct_cpu(p, cpu, 0)) {
			__sync_fetch_and_add(&nr_direct_dispatches, 1);
			return;
		}
	}

	/*
	 * Dispatch interactive tasks to the priority DSQ and regular tasks to
	 * the shared DSQ.
	 *
	 * However, avoid queuing too many tasks to the priority DSQ: if we
	 * have a storm of interactive tasks (more than 4x the amount of CPUs
	 * that can consume them) we can just dispatch them to the shared DSQ
	 * and simply rely on the vruntime logic.
	 */
	if (is_task_interactive(p)) {
		scx_bpf_dispatch_vtime(p, prio_dsq_id, SCX_SLICE_DFL,
				       deadline, enq_flags);
		__sync_fetch_and_add(&nr_prio_dispatches, 1);
	} else {
		scx_bpf_dispatch_vtime(p, shared_dsq_id, SCX_SLICE_DFL,
				       deadline, enq_flags);
		__sync_fetch_and_add(&nr_shared_dispatches, 1);
	}

	/*
	 * If there are idle CPUs that are usable by the task, wake them up to
	 * see whether they'd be able to steal the just queued task.
	 */
	cpu = scx_bpf_pick_idle_cpu(p->cpus_ptr, 0);
	if (cpu >= 0)
		scx_bpf_kick_cpu(cpu, 0);
}

/*
 * Consume tasks dispatched to CPUs that have gone offline.
 *
 * These tasks will be consumed on other active CPUs to prevent indefinite
 * stalling.
 *
 * Return true if one task is consumed, false otherwise.
 */
static bool consume_offline_cpus(s32 cpu)
{
	u64 nr_cpu_ids = scx_bpf_nr_cpu_ids();
	struct bpf_cpumask *offline;
	bool ret = false;

	if (!test_and_clear_offline_needed())
		return false;

	offline = offline_cpumask;
	if (!offline)
		return false;

	/*
	 * Cycle through all the CPUs and evenly consume tasks from the DSQs of
	 * those that are offline.
	 */
	bpf_repeat(nr_cpu_ids - 1) {
		s32 dsq_id;

		cpu = (cpu + 1) % nr_cpu_ids;
		dsq_id = cpu_to_dsq(cpu);

		if (!bpf_cpumask_test_cpu(cpu, cast_mask(offline)))
			continue;
		if (!scx_bpf_dsq_nr_queued(dsq_id))
			continue;
		set_offline_needed();

		/*
		 * This CPU is offline, if a task has been dispatched there
		 * consume it immediately on the current CPU.
		 */
		if (scx_bpf_consume(dsq_id)) {
			ret = true;
			break;
		}
	}

	return ret;
}

/*
 * Consume a task from the priority DSQ, transferring it to the local CPU DSQ.
 *
 * Return true if a task is consumed, false otherwise.
 */
static bool consume_prio_task(u64 now)
{
	bool ret;

	ret = scx_bpf_consume(prio_dsq_id);
	if (ret)
		starvation_prio_ts = now;

	return ret;
}

/*
 * Consume a task from the shared DSQ, transferring it to the local CPU DSQ.
 *
 * Return true if a task is consumed, false otherwise.
 */
static bool consume_regular_task(u64 now)
{
	bool ret;

	ret = scx_bpf_consume(shared_dsq_id);
	if (ret)
		starvation_shared_ts = now;

	return ret;
}

/*
 * Consume tasks that are potentially starving.
 *
 * In order to limit potential starvation conditions the scheduler uses a
 * time-based threshold to ensure that at least one task from the
 * lower-priority DSQs is periodically consumed.
 */
static bool consume_starving_tasks(u64 now)
{
	if (!starvation_thresh_ns)
		return false;

	if (vtime_before(starvation_shared_ts + starvation_thresh_ns, now))
		if (consume_regular_task(now))
			return true;

	if (vtime_before(starvation_prio_ts + starvation_thresh_ns, now))
		if (consume_prio_task(now))
			return true;

	return false;
}

void BPF_STRUCT_OPS(bpfland_dispatch, s32 cpu, struct task_struct *prev)
{
	u64 now = bpf_ktime_get_ns();

	/*
	 * Try also to steal tasks directly dispatched to CPUs that have gone
	 * offline (this allows to prevent indefinite task stalls).
	 */
	if (consume_offline_cpus(cpu))
		return;

	/*
	 * Make sure we are not staving tasks from the lower priority DSQs.
	 */
	if (consume_starving_tasks(now))
		return;

	/*
	 * Consume directly dispatched tasks, so that they can immediately use
	 * the CPU assigned in select_cpu().
	 */
	if (scx_bpf_consume(cpu_to_dsq(cpu)))
		return;

	/*
	 * Then always consume interactive tasks before regular tasks.
	 */
	if (consume_prio_task(now))
		return;

	/*
	 * Lastly, consume regular tasks from the shared DSQ.
	 */
	if (consume_regular_task(now))
		return;

	/*
	 * If the current task expired its time slice, but no other task wants
	 * to run, simply replenish its time slice and let it run for another
	 * round on the same CPU.
	 *
	 * Note that bpfland_stopping() won't be called if we replenish the
	 * time slice here. As a result, the nvcsw statistics won't be updated,
	 * but this isn't an issue, because these statistics are only relevant
	 * when the system is overloaded, which isn't the case when there are
	 * no other tasks to run.
	 */
	if (prev && (prev->scx.flags & SCX_TASK_QUEUED))
		prev->scx.slice = task_slice(prev);
}

/*
 * Scale target CPU frequency based on the performance level selected
 * from user-space and the CPU utilization.
 */
static void update_cpuperf_target(struct task_struct *p)
{
	u64 now = bpf_ktime_get_ns();
	s32 cpu = scx_bpf_task_cpu(p);
	u64 perf_lvl, delta_runtime, delta_t;
	struct cpu_ctx *cctx;

	if (cpufreq_perf_lvl >= 0) {
		/*
		 * Apply fixed cpuperf scaling factor determined by user-space.
		 */
		perf_lvl = MIN(cpufreq_perf_lvl, SCX_CPUPERF_ONE);
		scx_bpf_cpuperf_set(cpu, perf_lvl);
		return;
	}

	/*
	 * Auto mode: always tset max performance for interactive tasks.
	 */
	if (is_task_interactive(p)) {
		scx_bpf_cpuperf_set(cpu, SCX_CPUPERF_ONE);
		return;
	}

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
	delta_runtime = cctx->tot_runtime - cctx->prev_runtime;
	perf_lvl = MIN(delta_runtime * SCX_CPUPERF_ONE / delta_t, SCX_CPUPERF_ONE);

	/*
	 * Apply the dynamic cpuperf scaling factor.
	 */
	scx_bpf_cpuperf_set(cpu, perf_lvl);

	cctx->last_running = bpf_ktime_get_ns();
	cctx->prev_runtime = cctx->tot_runtime;
}

void BPF_STRUCT_OPS(bpfland_running, struct task_struct *p)
{
	/*
	 * Refresh task's time slice immediately before it starts to run on its
	 * assigned CPU.
	 */
	p->scx.slice = task_slice(p);

	/*
	 * Adjust target CPU frequency before the task starts to run.
	 */
	update_cpuperf_target(p);

	/*
	 * Update CPU interactive state.
	 */
	if (is_task_interactive(p))
		__sync_fetch_and_add(&nr_interactive, 1);

	__sync_fetch_and_add(&nr_running, 1);
}

static void update_task_interactive(struct task_ctx *tctx)
{
	/*
	 * Classify the task based on the average of voluntary context
	 * switches.
	 *
	 * If the task has an average greater than the global average
	 * (nvcsw_avg_thresh) it is classified as interactive, otherwise the
	 * task is classified as regular.
	 */
	if (is_nvcsw_enabled())
		tctx->is_interactive = tctx->avg_nvcsw >= nvcsw_avg_thresh;
}

/*
 * Update task statistics when the task is releasing the CPU (either
 * voluntarily or because it expires its assigned time slice).
 */
void BPF_STRUCT_OPS(bpfland_stopping, struct task_struct *p, bool runnable)
{
	u64 now = bpf_ktime_get_ns(), task_slice;
	s32 cpu = scx_bpf_task_cpu(p);
	s64 delta_t;
	struct cpu_ctx *cctx;
	struct task_ctx *tctx;

	cctx = try_lookup_cpu_ctx(cpu);
	if (cctx)
		cctx->tot_runtime += now - cctx->last_running;

	__sync_fetch_and_sub(&nr_running, 1);

	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return;

	if (tctx->is_interactive)
		__sync_fetch_and_sub(&nr_interactive, 1);

	tctx->select_cpu_done = false;

	/*
	 * Update task vruntime, charging the weighted used time slice.
	 */
	task_slice = p->se.sum_exec_runtime - tctx->sum_exec_runtime;
	p->scx.dsq_vtime += task_slice * 100 / p->scx.weight;
	tctx->sum_exec_runtime = p->se.sum_exec_runtime;

	/*
	 * Update global vruntime.
	 */
	vtime_now += task_slice * 100 / p->scx.weight;

	/*
	 * Refresh voluntary context switch metrics.
	 *
	 * Evaluate the average number of voluntary context switches per second
	 * using an exponentially weighted moving average, see calc_avg().
	 */
	if (!lowlatency && !is_nvcsw_enabled())
		return;
	delta_t = (s64)(now - tctx->nvcsw_ts);
	if (delta_t > NSEC_PER_SEC) {
		u64 delta_nvcsw = p->nvcsw - tctx->nvcsw;
		u64 avg_nvcsw = delta_nvcsw * NSEC_PER_SEC / delta_t;

		/*
		 * Evaluate the average nvcsw for the task, limited to the
		 * range [0 .. 1000] to prevent excessive spikes.
		 */
		tctx->avg_nvcsw = calc_avg_clamp(tctx->avg_nvcsw, avg_nvcsw,
						 0, MAX(nvcsw_max_thresh, 1000));
		tctx->nvcsw = p->nvcsw;
		tctx->nvcsw_ts = now;

		/*
		 * Update the global voluntary context switches average using
		 * an exponentially weighted moving average (EWMA) with the
		 * formula:
		 *
		 *   avg(t) = avg(t - 1) * 0.75 - task_avg(t) * 0.25
		 *
		 * This approach is more efficient than iterating through all
		 * tasks and it helps to prevent rapid fluctuations that may be
		 * caused by bursts of voluntary context switch events.
		 *
		 * Additionally, restrict the global nvcsw_avg_thresh average
		 * to the range [1 .. nvcsw_max_thresh] to always allow the
		 * classification of some tasks as interactive.
		 */
		nvcsw_avg_thresh = calc_avg_clamp(nvcsw_avg_thresh, avg_nvcsw,
						  1, nvcsw_max_thresh);
		/*
		 * Reresh task status: interactive or regular.
		 */
		update_task_interactive(tctx);
	}
}

void BPF_STRUCT_OPS(bpfland_enable, struct task_struct *p)
{
	struct task_ctx *tctx;

	/* Initialize task's vruntime */
	p->scx.dsq_vtime = vtime_now;

	/* Initialize voluntary context switch timestamp */
	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return;
	tctx->sum_exec_runtime = p->se.sum_exec_runtime;
	tctx->nvcsw = p->nvcsw;
	tctx->nvcsw_ts = bpf_ktime_get_ns();
	tctx->avg_nvcsw = p->nvcsw * NSEC_PER_SEC / tctx->nvcsw_ts;

	update_task_interactive(tctx);
}

void BPF_STRUCT_OPS(bpfland_cpu_online, s32 cpu)
{
	/* Set the CPU state to online */
	set_cpu_state(offline_cpumask, cpu, false);

	__sync_fetch_and_add(&nr_online_cpus, 1);
	__sync_fetch_and_add(&cpu_hotplug_cnt, 1);
}

void BPF_STRUCT_OPS(bpfland_cpu_offline, s32 cpu)
{
	/* Set the CPU state to offline */
	set_cpu_state(offline_cpumask, cpu, true);

	__sync_fetch_and_sub(&nr_online_cpus, 1);
	__sync_fetch_and_add(&cpu_hotplug_cnt, 1);

	set_offline_needed();
}

s32 BPF_STRUCT_OPS(bpfland_init_task, struct task_struct *p,
		   struct scx_init_task_args *args)
{
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

	return 0;
}

/*
 * Evaluate the amount of online CPUs.
 */
s32 get_nr_online_cpus(void)
{
	const struct cpumask *online_cpumask;
	u64 nr_cpu_ids = scx_bpf_nr_cpu_ids();
	int i, cpus = 0;

	online_cpumask = scx_bpf_get_online_cpumask();

	bpf_for(i, 0, nr_cpu_ids) {
		if (!bpf_cpumask_test_cpu(i, online_cpumask))
			continue;
		cpus++;
	}

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

s32 BPF_STRUCT_OPS_SLEEPABLE(bpfland_init)
{
	struct bpf_cpumask *mask;
	u64 nr_cpu_ids = scx_bpf_nr_cpu_ids();
	int err;
	s32 cpu;

	/* Initialize amount of online CPUs */
	nr_online_cpus = get_nr_online_cpus();

	/* Create per-CPU DSQs (used to dispatch tasks directly on a CPU) */
	bpf_for(cpu, 0, nr_cpu_ids) {
		err = scx_bpf_create_dsq(cpu_to_dsq(cpu), -1);
		if (err) {
			scx_bpf_error("failed to create pcpu DSQ %d: %d",
				      cpu, err);
			return err;
		}
	}

	/*
	 * Create the global priority DSQ (for interactive tasks).
	 *
	 * Allocate a new DSQ id that does not clash with any valid CPU id.
	 */
	prio_dsq_id = nr_cpu_ids++;
	err = scx_bpf_create_dsq(prio_dsq_id, -1);
	if (err) {
		scx_bpf_error("failed to create priority DSQ: %d", err);
		return err;
	}

	/*
	 * Create the global shared DSQ (for regular tasks).
	 *
	 * Allocate a new DSQ id that does not clash with any valid CPU id..
	 */
	shared_dsq_id = nr_cpu_ids++;
	err = scx_bpf_create_dsq(shared_dsq_id, -1);
	if (err) {
		scx_bpf_error("failed to create shared DSQ: %d", err);
		return err;
	}

	/* Initialize the offline CPU mask */
	err = calloc_cpumask(&offline_cpumask);
	mask = offline_cpumask;
	if (!mask)
		err = -ENOMEM;
	if (err)
		return err;

	/* Initialize the primary scheduling domain */
	err = init_cpumask(&primary_cpumask);
	if (err)
		return err;

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
	       .enable			= (void *)bpfland_enable,
	       .cpu_online		= (void *)bpfland_cpu_online,
	       .cpu_offline		= (void *)bpfland_cpu_offline,
	       .init_task		= (void *)bpfland_init_task,
	       .init			= (void *)bpfland_init,
	       .exit			= (void *)bpfland_exit,
	       .timeout_ms		= 5000,
	       .name			= "bpfland");
