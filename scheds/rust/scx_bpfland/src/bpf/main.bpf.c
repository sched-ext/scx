/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2024 Andrea Righi <righi.andrea@gmail.com>
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
 * Mask of offline CPUs, used to properly support CPU hotplugging.
 */
private(BPFLAND) struct bpf_cpumask __kptr *offline_cpumask;

/*
 * Determine when we need to drain tasks dispatched to CPUs that went offline.
 */
static int offline_needed;

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
 * Per-task local storage.
 *
 * This contain all the per-task information used internally by the BPF code.
 */
struct task_ctx {
	/*
	 * Set to true if the task is classified as interactive.
	 */
	bool is_interactive;

	/*
	 * Voluntary context switches metrics.
	 */
	u64 nvcsw;
	u64 nvcsw_ts;
	u64 avg_nvcsw;
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
 * Return a local task context from a generic task, failing if it doesn't
 * exist.
 */
struct task_ctx *lookup_task_ctx(const struct task_struct *p)
{
	struct task_ctx *tctx;

	tctx = try_lookup_task_ctx(p);
	if (!tctx) {
		scx_bpf_error("Failed to lookup task ctx for %d (%s)",
			      p->pid, p->comm);
		return NULL;
	}
	return tctx;
}

/*
 * Return true if the target task @p is a kernel thread.
 */
static inline bool is_kthread(const struct task_struct *p)
{
	return !!(p->flags & PF_KTHREAD);
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
 * Access a cpumask in read-only mode (typically to check bits).
 */
static const struct cpumask *cast_mask(struct bpf_cpumask *mask)
{
	return (const struct cpumask *)mask;
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
 * Return task's evaluated vruntime.
 */
static inline u64 task_vtime(struct task_struct *p)
{
	u64 vtime = p->scx.dsq_vtime;

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
	 * scheduling and making the scheduler closer to a FIFO.  ￼ ￼ ￼
	 */
	if (vtime_before(vtime, vtime_now - slice_ns_lag))
		vtime = vtime_now - slice_ns_lag;

	return vtime;
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
	u64 slice = task_slice(p);
	u64 vtime = task_vtime(p);
	u64 dsq_id = cpu_to_dsq(cpu);

	/*
	 * Make sure we can dispatch the task to the target CPU according to
	 * its cpumask.
	 */
	if (!bpf_cpumask_test_cpu(cpu, p->cpus_ptr))
		return -EINVAL;

	scx_bpf_dispatch_vtime(p, dsq_id, slice, vtime, enq_flags);

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
	s32 cpu;

	/*
	 * For tasks that can run only on a single CPU, we can simply verify if
	 * their only allowed CPU is idle.
	 */
	if (p->nr_cpus_allowed == 1) {
		cpu = bpf_cpumask_first(p->cpus_ptr);

		if (scx_bpf_test_and_clear_cpu_idle(cpu))
			return cpu;

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
	 * Find the best idle CPU, prioritizing full idle cores in SMT systems.
	 */
	if (smt_enabled) {
		/*
		 * If the task can still run on the previously used CPU and
		 * it's a full-idle core, keep using it.
		 */
		if (bpf_cpumask_test_cpu(prev_cpu, p->cpus_ptr) &&
		    bpf_cpumask_test_cpu(prev_cpu, idle_smtmask) &&
		    scx_bpf_test_and_clear_cpu_idle(prev_cpu)) {
			cpu = prev_cpu;
			goto out_put_cpumask;
		}

		/*
		 * Otherwise, search for another usable full-idle core.
		 */
		cpu = bpf_cpumask_any_and_distribute(p->cpus_ptr, idle_smtmask);
		if (bpf_cpumask_test_cpu(cpu, online_cpumask) &&
		    scx_bpf_test_and_clear_cpu_idle(cpu))
			goto out_put_cpumask;
	}

	/*
	 * If a full-idle core can't be found (or if this is not an SMT system)
	 * try to re-use the same CPU, even if it's not in a full-idle core.
	 */
	if (bpf_cpumask_test_cpu(prev_cpu, p->cpus_ptr) &&
	    scx_bpf_test_and_clear_cpu_idle(prev_cpu)) {
		cpu = prev_cpu;
		goto out_put_cpumask;
	}

	/*
	 * If all the previous attempts have failed, try to use any idle CPU in
	 * the system.
	 */
	cpu = bpf_cpumask_any_and_distribute(p->cpus_ptr, idle_cpumask);
	if (bpf_cpumask_test_cpu(cpu, online_cpumask) &&
	    scx_bpf_test_and_clear_cpu_idle(cpu))
		goto out_put_cpumask;

	/*
	 * If all the previous attempts have failed, dispatch the task to the
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
	tctx = lookup_task_ctx(p);
	if (!tctx)
		return;
	if (!tctx->is_interactive && !is_prio_congested())
		tctx->is_interactive = true;
}

s32 BPF_STRUCT_OPS(bpfland_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
	s32 cpu;

	/*
	 * Try to prioritize newly awakened tasks.
	 */
	if (wake_flags & SCX_WAKE_SYNC)
		handle_sync_wakeup(p);

	cpu = pick_idle_cpu(p, prev_cpu, wake_flags);
	if (cpu >= 0 && !dispatch_direct_cpu(p, cpu, 0)) {
		__sync_fetch_and_add(&nr_direct_dispatches, 1);
		return cpu;
	}

	return prev_cpu;
}

/*
 * Dispatch all the other tasks that were not dispatched directly in
 * select_cpu().
 */
void BPF_STRUCT_OPS(bpfland_enqueue, struct task_struct *p, u64 enq_flags)
{
	u64 vtime = task_vtime(p);
	u64 slice = task_slice(p);
	struct task_ctx *tctx;

	/*
	 * Always dispatch per-CPU kthreads directly on their target CPU if
	 * local_kthreads is enabled.
	 */
	if (local_kthreads && is_kthread(p) && p->nr_cpus_allowed == 1) {
		s32 cpu = scx_bpf_task_cpu(p);
		if (!dispatch_direct_cpu(p, cpu, enq_flags)) {
			__sync_fetch_and_add(&nr_direct_dispatches, 1);
			return;
		}
	}

	tctx = lookup_task_ctx(p);
	if (!tctx)
		return;

	/*
	 * Dispatch interactive tasks to the priority DSQ and regular tasks to
	 * the shared DSQ.
	 *
	 * However, avoid queuing too many tasks to the priority DSQ: if we
	 * have a storm of interactive tasks (more than 4x the amount of CPUs
	 * that can consume them) we can just dispatch them to the shared DSQ
	 * and simply rely on the vruntime logic.
	 */
	if (tctx->is_interactive) {
		scx_bpf_dispatch_vtime(p, prio_dsq_id, slice, vtime, enq_flags);
		__sync_fetch_and_add(&nr_prio_dispatches, 1);
	} else {
		scx_bpf_dispatch_vtime(p, shared_dsq_id, slice, vtime, enq_flags);
		__sync_fetch_and_add(&nr_shared_dispatches, 1);
	}
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
		cpu = (cpu + 1) % nr_cpu_ids;

		if (!bpf_cpumask_test_cpu(cpu, cast_mask(offline)))
			continue;
		/*
		 * This CPU is offline, if a task has been dispatched there
		 * consume it immediately on the current CPU.
		 */
		if (scx_bpf_consume(cpu_to_dsq(cpu))) {
			set_offline_needed();
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
	consume_regular_task(now);
}

void BPF_STRUCT_OPS(bpfland_running, struct task_struct *p)
{
	struct task_ctx *tctx;

	tctx = lookup_task_ctx(p);
	if (!tctx)
		return;

	/* Update global vruntime */
	if (vtime_before(vtime_now, p->scx.dsq_vtime))
		vtime_now = p->scx.dsq_vtime;

	/*
	 * Ensure time slice never exceeds slice_ns when a task is started on a
	 * CPU.
	 */
	if (p->scx.slice > slice_ns)
		p->scx.slice = slice_ns;

	/* Update CPU interactive state */
	if (tctx->is_interactive)
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
	tctx->is_interactive = tctx->avg_nvcsw >= nvcsw_avg_thresh;
}

/*
 * Update task statistics when the task is releasing the CPU (either
 * voluntarily or because it expires its assigned time slice).
 */
void BPF_STRUCT_OPS(bpfland_stopping, struct task_struct *p, bool runnable)
{
	u64 now = bpf_ktime_get_ns();
	s64 delta_t;
	struct task_ctx *tctx;

	__sync_fetch_and_sub(&nr_running, 1);

	tctx = lookup_task_ctx(p);
	if (!tctx)
		return;

	if (tctx->is_interactive)
		__sync_fetch_and_sub(&nr_interactive, 1);

	/*
	 * Update task vruntime, charging the weighted used time slice.
	 *
	 * Note that using p->scx.slice here can excessively penalize tasks
	 * that call sched_yield(), because in sched_ext, yielding is
	 * implemented by setting p->scx.slice to 0, that is considered as if
	 * the task has used up its entire budgeted time slice.
	 *
	 * However, this is balanced by the fact that yielding increases the
	 * number of voluntary context switches (nvcsw), giving the task more
	 * opportunities to be classified as interactive and dispatched to the
	 * high priority DSQ (prio_dsq_id).
	 */
	if (slice_ns > p->scx.slice)
		p->scx.dsq_vtime += (slice_ns - p->scx.slice) * 100 / p->scx.weight;

	/*
	 * Refresh voluntary context switch metrics.
	 *
	 * Evaluate the average number of voluntary context switches per second
	 * using an exponentially weighted moving average, see calc_avg().
	 */
	delta_t = (s64)(now - tctx->nvcsw_ts);
	if (is_nvcsw_enabled() && delta_t > NSEC_PER_SEC) {
		u64 delta_nvcsw = p->nvcsw - tctx->nvcsw;
		u64 avg_nvcsw = delta_nvcsw * NSEC_PER_SEC / delta_t;

		/*
		 * Evaluate the average nvcsw for the task, limited to the
		 * range [0 .. nvcsw_max_thresh * 8] to prevent excessive
		 * spikes.
		 */
		tctx->avg_nvcsw = calc_avg_clamp(tctx->avg_nvcsw, avg_nvcsw,
						 0, nvcsw_max_thresh << 3);
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

		dbg_msg("%d (%s) avg_nvcsw = %llu [%s]",
			p->pid, p->comm, tctx->avg_nvcsw,
			tctx->avg_nvcsw < nvcsw_avg_thresh ? "regular" : "interactive");
	}
}

void BPF_STRUCT_OPS(bpfland_enable, struct task_struct *p)
{
	struct task_ctx *tctx;

	/* Initialize task's vruntime */
	p->scx.dsq_vtime = vtime_now;

	/* Initialize voluntary context switch timestamp */
	tctx = lookup_task_ctx(p);
	if (!tctx)
		return;
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
}

void BPF_STRUCT_OPS(bpfland_cpu_offline, s32 cpu)
{
	/* Set the CPU state to offline */
	set_cpu_state(offline_cpumask, cpu, true);

	__sync_fetch_and_sub(&nr_online_cpus, 1);
	set_offline_needed();
}

s32 BPF_STRUCT_OPS(bpfland_init_task, struct task_struct *p,
		   struct scx_init_task_args *args)
{
	if (bpf_task_storage_get(&task_ctx_stor, p, 0,
				 BPF_LOCAL_STORAGE_GET_F_CREATE))
		return 0;
	else
		return -ENOMEM;
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

	return err;
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
