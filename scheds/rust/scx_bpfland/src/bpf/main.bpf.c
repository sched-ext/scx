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
#define PRIO_DSQ	0

/*
 * DSQ used to dispatch regular tasks.
 */
#define SHARED_DSQ	1

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
 * When enabled always dispatch all kthreads directly.
 *
 * This allows to prioritize critical kernel threads that may potentially slow
 * down the entire system if they are blocked for too long, but it may also
 * introduce interactivity issues or unfairness in scenarios with high kthread
 * activity, such as heavy I/O or network traffic.
 */
const volatile bool local_kthreads;

/*
 * With lowlatency enabled, instead of classifying tasks as interactive or
 * non-interactive, they all get a dynamic priority, which is adjusted in
 * function of their average rate of voluntary context switches.
 *
 * This option guarantess less spikey behavior and it can be particularly
 * useful in soft real-time scenarios, such as audio processing, multimedia,
 * etc.
 */
const volatile bool lowlatency;

/*
 * Maximum threshold of voluntary context switches.
 */
const volatile u64 nvcsw_max_thresh = 10ULL;

/*
 * The CPU frequency performance level: a negative value will not affect the
 * performance level and will be ignored.
 */
volatile s64 cpufreq_perf_lvl;

/*
 * Time threshold to prevent task starvation.
 *
 * Tasks dispatched to the priority DSQ are always consumed before those
 * dispatched to the shared DSQ, so tasks in shared DSQ may be starved by those
 * in the priority DSQ.
 *
 *  To mitigate this, store the timestamp of the last task consumption from
 *  the shared DSQ. If the starvation_thresh_ns threshold is exceeded without
 *  consuming a task, the scheduler will be forced to consume a task from the
 *  corresponding DSQ.
 */
const volatile u64 starvation_thresh_ns = 1000ULL * NSEC_PER_MSEC;
static u64 starvation_shared_ts;

/*
 * Scheduling statistics.
 */
volatile u64 nr_kthread_dispatches, nr_direct_dispatches,
	     nr_prio_dispatches, nr_shared_dispatches;

/*
 * Amount of currently running tasks.
 */
volatile u64 nr_running, nr_interactive, nr_shared_waiting, nr_prio_waiting;

/*
 * Amount of online CPUs.
 */
volatile u64 nr_online_cpus;

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

	/*
	 * Task's latency priority.
	 */
	u64 lat_weight;

	/*
	 * Task's average used time slice.
	 */
	u64 avg_runtime;

	/*
	 * Task's deadline.
	 */
	u64 deadline;

	/*
	 * Set to true if the task is classified as interactive.
	 */
	bool is_interactive;
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
 * Return the dynamic priority multiplier (only applied in lowlatency mode).
 *
 * The multiplier is evaluated in function of the task's average rate of
 * voluntary context switches per second.
 */
static u64 task_dyn_prio(struct task_struct *p)
{
	struct task_ctx *tctx;

	if (!lowlatency)
		return 1;
	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return 1;
	return MAX(tctx->lat_weight, 1);
}

/*
 * Return task's dynamic priority.
 */
static u64 task_prio(struct task_struct *p)
{
	return p->scx.weight * task_dyn_prio(p);
}

/*
 * Return the task's allowed lag: used to determine how early its vruntime can
 * be.
 */
static u64 task_lag(struct task_struct *p)
{
	return slice_lag * task_prio(p) / 100;
}

/*
 * Return a value inversely proportional to the task's weight.
 */
static u64 scale_inverse_fair(struct task_struct *p, u64 value)
{
	return value * 100 / task_prio(p);
}

/*
 * Compute the deadline component of a task (this value will be added to the
 * task's vruntime to determine the actual deadline).
 */
static s64 task_compute_dl(struct task_struct *p ,struct task_ctx *tctx)
{
	/*
	 * Return the deadline as a function of the average runtime and the
	 * evaluated task's dynamic priority.
	 */
	return scale_inverse_fair(p, tctx->avg_runtime);
}

/*
 * Return task's evaluated vruntime.
 */
static inline u64 task_deadline(struct task_struct *p)
{
	u64 min_vruntime = vtime_now - task_lag(p);
	struct task_ctx *tctx;

	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return min_vruntime;

	/*
	 * Limit the vruntime to to avoid excessively penalizing tasks.
	 */
	if (vtime_before(p->scx.dsq_vtime, min_vruntime)) {
		p->scx.dsq_vtime = min_vruntime;
		tctx->deadline = p->scx.dsq_vtime + task_compute_dl(p, tctx);
	}

	return tctx->deadline;
}

/*
 * Evaluate task's time slice in function of the total amount of tasks that are
 * waiting to be dispatched and the task's weight.
 */
static inline void task_refill_slice(struct task_struct *p)
{
	u64 curr_prio_waiting = scx_bpf_dsq_nr_queued(PRIO_DSQ);
	u64 curr_shared_waiting = scx_bpf_dsq_nr_queued(SHARED_DSQ);
	u64 scale_factor;

	/*
	 * Refresh the amount of waiting tasks to get a more accurate scaling
	 * factor for the time slice.
	 */
	nr_prio_waiting = calc_avg(nr_prio_waiting, curr_prio_waiting);
	nr_shared_waiting = calc_avg(nr_shared_waiting, curr_shared_waiting);

	/*
	 * Scale the time slice of an inversely proportional factor of the
	 * total amount of tasks that are waiting (use a more immediate metric
	 * in lowlatency mode and an average in normal mode).
	 */
	if (lowlatency)
		scale_factor = curr_shared_waiting + 1;
	else
		scale_factor = nr_prio_waiting + nr_shared_waiting + 1;

	p->scx.slice = CLAMP(slice_max / scale_factor, slice_min, slice_max);
}

static bool is_prio_congested(void)
{
	return scx_bpf_dsq_nr_queued(PRIO_DSQ) > nr_online_cpus * 4;
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
	if (tctx && !is_prio_congested())
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

	/*
	 * If the task isn't allowed to use its previously used CPU it means
	 * that it's changing affinity. In this case try to pick any random
	 * idle CPU in its new allowed CPU domain.
	 */
	if (!bpf_cpumask_test_cpu(prev_cpu, p->cpus_ptr))
		return scx_bpf_pick_idle_cpu(p->cpus_ptr, 0);

	/*
	 * For tasks that can run only on a single CPU, we can simply verify if
	 * their only allowed CPU is still idle.
	 */
	if (p->nr_cpus_allowed == 1 || p->migration_disabled) {
		if (scx_bpf_test_and_clear_cpu_idle(prev_cpu))
			return prev_cpu;
		return -EBUSY;
	}

	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return -ENOENT;

	cctx = try_lookup_cpu_ctx(prev_cpu);
	if (!cctx)
		return -EINVAL;

	primary = primary_cpumask;
	if (!primary)
		return -EINVAL;

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
		cpu = -EINVAL;
		goto out_put_cpumask;
	}

	l2_mask = tctx->l2_cpumask;
	if (!l2_mask) {
		scx_bpf_error("l2 cpumask not initialized");
		cpu = -EINVAL;
		goto out_put_cpumask;
	}

	l3_mask = tctx->l3_cpumask;
	if (!l3_mask) {
		scx_bpf_error("l3 cpumask not initialized");
		cpu = -EINVAL;
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
	 * CPU.
	 */
	bpf_cpumask_and(l2_mask, cast_mask(p_mask), cast_mask(l2_domain));

	/*
	 * Determine the L3 cache domain as the intersection of the task's
	 * primary cpumask and the L3 cache domain mask of the previously used
	 * CPU.
	 */
	bpf_cpumask_and(l3_mask, cast_mask(p_mask), cast_mask(l3_domain));

	/*
	 * If the current task is waking up another task and releasing the CPU
	 * (WAKE_SYNC), attempt to migrate the wakee on the same CPU as the
	 * waker.
	 */
	if (wake_flags & SCX_WAKE_SYNC) {
		struct task_struct *current = (void *)bpf_get_current_task_btf();
		struct bpf_cpumask *curr_l3_domain;
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
			cpu = -EINVAL;
			goto out_put_cpumask;
		}

		curr_l3_domain = cctx->l3_cpumask;
		if (!curr_l3_domain)
			curr_l3_domain = primary;

		/*
		 * If both the waker and wakee share the same L3 cache keep
		 * using the same CPU if possible.
		 */
		share_llc = bpf_cpumask_test_cpu(prev_cpu, cast_mask(curr_l3_domain));
		if (share_llc && scx_bpf_test_and_clear_cpu_idle(prev_cpu)) {
			cpu = prev_cpu;
			goto out_put_cpumask;
		}

		/*
		 * If the waker's L3 domain is not saturated attempt to migrate
		 * the wakee on the same CPU as the waker (since it's going to
		 * block and release the current CPU).
		 */
		has_idle = bpf_cpumask_intersects(cast_mask(curr_l3_domain), idle_cpumask);
		if (has_idle &&
		    bpf_cpumask_test_cpu(cpu, p->cpus_ptr) &&
		    !(current->flags & PF_EXITING) &&
		    scx_bpf_dsq_nr_queued(SCX_DSQ_LOCAL_ON | cpu) == 0)
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
		cpu = bpf_cpumask_any_and_distribute(cast_mask(l2_mask), idle_smtmask);
		if (bpf_cpumask_test_cpu(cpu, online_cpumask) &&
		    scx_bpf_test_and_clear_cpu_idle(cpu))
			goto out_put_cpumask;

		/*
		 * Search for any full-idle CPU in the primary domain that
		 * shares the same L3 cache.
		 */
		cpu = bpf_cpumask_any_and_distribute(cast_mask(l3_mask), idle_smtmask);
		if (bpf_cpumask_test_cpu(cpu, online_cpumask) &&
		    scx_bpf_test_and_clear_cpu_idle(cpu))
			goto out_put_cpumask;

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
	cpu = bpf_cpumask_any_and_distribute(cast_mask(l2_mask), idle_cpumask);
	if (bpf_cpumask_test_cpu(cpu, online_cpumask) &&
	    scx_bpf_test_and_clear_cpu_idle(cpu))
		goto out_put_cpumask;

	/*
	 * Search for any idle CPU in the primary domain that shares the same
	 * L3 cache.
	 */
	cpu = bpf_cpumask_any_and_distribute(cast_mask(l3_mask), idle_cpumask);
	if (bpf_cpumask_test_cpu(cpu, online_cpumask) &&
	    scx_bpf_test_and_clear_cpu_idle(cpu))
		goto out_put_cpumask;

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

/*
 * Pick a target CPU for a task which is being woken up.
 *
 * If a task is dispatched here, ops.enqueue() will be skipped: task will be
 * dispatched directly to the CPU returned by this callback.
 */
s32 BPF_STRUCT_OPS(bpfland_select_cpu, struct task_struct *p,
			s32 prev_cpu, u64 wake_flags)
{
	s32 cpu;

	cpu = pick_idle_cpu(p, prev_cpu, wake_flags);
	if (cpu >= 0) {
		scx_bpf_dispatch(p, SCX_DSQ_LOCAL, SCX_SLICE_DFL, 0);
		__sync_fetch_and_add(&nr_direct_dispatches, 1);
		return cpu;
	}

	return prev_cpu;
}

/*
 * Wake up an idle CPU for task @p.
 */
static void kick_task_cpu(struct task_struct *p)
{
	s32 cpu = scx_bpf_task_cpu(p);

	cpu = pick_idle_cpu(p, cpu, 0);
	if (cpu >= 0)
		scx_bpf_kick_cpu(cpu, 0);
}

/*
 * Dispatch all the other tasks that were not dispatched directly in
 * select_cpu().
 */
void BPF_STRUCT_OPS(bpfland_enqueue, struct task_struct *p, u64 enq_flags)
{
	struct task_ctx *tctx;
	s32 dsq_id;

	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return;

	/*
	 * Per-CPU kthreads are critical for system responsiveness so make sure
	 * they are dispatched before any other task.
	 *
	 * If local_kthread is specified dispatch all kthreads directly.
	 */
	if (is_kthread(p) && (local_kthreads || p->nr_cpus_allowed == 1)) {
		scx_bpf_dispatch(p, SCX_DSQ_LOCAL, SCX_SLICE_DFL,
				 enq_flags | SCX_ENQ_PREEMPT);
		__sync_fetch_and_add(&nr_kthread_dispatches, 1);
		return;
	}

	/*
	 * Dispatch interactive tasks to the priority DSQ and regular tasks to
	 * the shared DSQ.
	 *
	 * When lowlatency is enabled, the separate priority DSQ is disabled,
	 * so in this case always dispatch to the shared DSQ.
	 */
	if (!lowlatency && tctx->is_interactive) {
		dsq_id = PRIO_DSQ;
		__sync_fetch_and_add(&nr_prio_dispatches, 1);
	} else {
		dsq_id = SHARED_DSQ;
		__sync_fetch_and_add(&nr_shared_dispatches, 1);
	}
	scx_bpf_dispatch_vtime(p, dsq_id, SCX_SLICE_DFL,
			       task_deadline(p), enq_flags);

	/*
	 * If there is an idle CPU available for the task, wake it up so it can
	 * consume the task immediately.
	 */
	kick_task_cpu(p);
}

/*
 * Consume a task from the priority DSQ, transferring it to the local CPU DSQ.
 *
 * Return true if a task is consumed, false otherwise.
 */
static bool consume_prio_task(u64 now)
{
	return scx_bpf_consume(PRIO_DSQ);
}

/*
 * Consume a task from the shared DSQ, transferring it to the local CPU DSQ.
 *
 * Return true if a task is consumed, false otherwise.
 */
static bool consume_regular_task(u64 now)
{
	bool ret;

	ret = scx_bpf_consume(SHARED_DSQ);
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

	return false;
}

/*
 * Consume regular tasks from the per-CPU DSQ or a shared DSQ, transferring
 * them to the local CPU DSQ.
 *
 * Return true if at least a task is consumed, false otherwise.
 */
static bool consume_shared_tasks(s32 cpu, u64 now)
{
	/*
	 * The priority DSQ can starve the shared DSQ, so to mitigate this
	 * starvation we have the starvation_thresh_ns, see also
	 * consume_starving_tasks().
	 */
	if (consume_prio_task(now) || consume_regular_task(now))
		return true;
	return false;
}

void BPF_STRUCT_OPS(bpfland_dispatch, s32 cpu, struct task_struct *prev)
{
	u64 now = bpf_ktime_get_ns();

	if (consume_starving_tasks(now))
		return;
	if (consume_shared_tasks(cpu, now))
		return;
	/*
	 * If the current task expired its time slice and no other task wants
	 * to run, simply replenish its time slice and let it run for another
	 * round on the same CPU.
	 */
	if (prev && (prev->scx.flags & SCX_TASK_QUEUED))
		task_refill_slice(prev);
}

/*
 * Scale target CPU frequency based on the performance level selected
 * from user-space and the CPU utilization.
 */
static void update_cpuperf_target(struct task_struct *p, struct task_ctx *tctx)
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
	if (tctx->is_interactive) {
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
	struct task_ctx *tctx;

	__sync_fetch_and_add(&nr_running, 1);

	/*
	 * Refresh task's time slice immediately before it starts to run on its
	 * assigned CPU.
	 */
	task_refill_slice(p);

	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return;

	/*
	 * Adjust target CPU frequency before the task starts to run.
	 */
	update_cpuperf_target(p, tctx);

	/*
	 * Update CPU interactive state.
	 */
	if (tctx->is_interactive)
		__sync_fetch_and_add(&nr_interactive, 1);
}

/*
 * Update task statistics when the task is releasing the CPU (either
 * voluntarily or because it expires its assigned time slice).
 */
void BPF_STRUCT_OPS(bpfland_stopping, struct task_struct *p, bool runnable)
{
	u64 now = bpf_ktime_get_ns(), slice;
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

	/*
	 * If the time slice is not fully depleted, it means that the task
	 * voluntarily relased the CPU, therefore update the voluntary context
	 * switch counter.
	 *
	 * NOTE: the sched_ext core implements sched_yield() by setting the
	 * time slice to 0, so we won't boost the priority of tasks that are
	 * explicitly calling sched_yield().
	 *
	 * This is actually a good thing, because we want to prioritize tasks
	 * that are releasing the CPU, because they're doing I/O, waiting for
	 * input or sending output to other tasks.
	 *
	 * Tasks that are using sched_yield() don't really need the priority
	 * boost and when they get the chance to run again they will be
	 * naturally prioritized by the vruntime-based scheduling policy.
	 */
	if (p->scx.slice > 0)
		tctx->nvcsw++;

	/*
	 * Update task's average runtime.
	 */
	slice = p->se.sum_exec_runtime - tctx->sum_exec_runtime;
	if (lowlatency)
		slice = CLAMP(slice, slice_min, slice_max);
	tctx->sum_exec_runtime = p->se.sum_exec_runtime;
	tctx->avg_runtime = calc_avg(tctx->avg_runtime, slice);

	/*
	 * Update task vruntime charging the weighted used time slice.
	 */
	slice = scale_inverse_fair(p, slice);
	p->scx.dsq_vtime += slice;
	tctx->deadline = p->scx.dsq_vtime + task_compute_dl(p, tctx);

	/*
	 * Update global vruntime.
	 */
	vtime_now += slice;

	/*
	 * Refresh voluntary context switch metrics.
	 *
	 * Evaluate the average number of voluntary context switches per second
	 * using an exponentially weighted moving average, see calc_avg().
	 */
	delta_t = (s64)(now - tctx->nvcsw_ts);
	if (delta_t > NSEC_PER_SEC) {
		u64 avg_nvcsw = tctx->nvcsw * NSEC_PER_SEC / delta_t;
		u64 max_lat_weight = nvcsw_max_thresh * 100;

		tctx->nvcsw = 0;
		tctx->nvcsw_ts = now;

		/*
		 * Evaluate the latency weight of the task as its average rate
		 * of voluntary context switches (limited to to prevent
		 * excessive spikes).
		 */
		tctx->lat_weight = calc_avg_clamp(tctx->lat_weight, avg_nvcsw,
						  0, max_lat_weight);

		/*
		 * Classify the task based on the average of voluntary context
		 * switches.
		 *
		 * If the task has an average greater than the global average
		 * it is classified as interactive, otherwise the task is
		 * classified as regular.
		 */
		tctx->is_interactive = tctx->lat_weight >= nvcsw_max_thresh;
	}
}

void BPF_STRUCT_OPS(bpfland_enable, struct task_struct *p)
{
	u64 now = bpf_ktime_get_ns();
	struct task_ctx *tctx;

	/* Initialize task's vruntime */
	p->scx.dsq_vtime = vtime_now;

	/* Initialize voluntary context switch timestamp */
	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return;
	tctx->sum_exec_runtime = p->se.sum_exec_runtime;
	tctx->nvcsw_ts = now;
	tctx->avg_runtime = slice_max;
	tctx->deadline = vtime_now;
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
	int err;

	/* Initialize amount of online CPUs */
	nr_online_cpus = get_nr_online_cpus();

	/*
	 * Create the global priority and shared DSQs.
	 *
	 * Allocate a new DSQ id that does not clash with any valid CPU id.
	 */
	err = scx_bpf_create_dsq(PRIO_DSQ, -1);
	if (err) {
		scx_bpf_error("failed to create priority DSQ: %d", err);
		return err;
	}

	err = scx_bpf_create_dsq(SHARED_DSQ, -1);
	if (err) {
		scx_bpf_error("failed to create shared DSQ: %d", err);
		return err;
	}

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
	       .init_task		= (void *)bpfland_init_task,
	       .init			= (void *)bpfland_init,
	       .exit			= (void *)bpfland_exit,
	       .timeout_ms		= 5000,
	       .name			= "bpfland");
