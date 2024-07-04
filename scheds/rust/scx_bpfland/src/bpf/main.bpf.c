/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2024 Andrea Righi <righi.andrea@gmail.com>
 */
#include <scx/common.bpf.h>
#include "intf.h"

/*
 * Maximum amount of CPUs supported by the scheduler.
 */
#define MAX_CPUS	1024

/*
 * DSQ used to dispatch regular tasks.
 */
#define SHARED_DSQ	MAX_CPUS

/*
 * Priority DSQ used to dispatch interactive tasks.
 */
#define PRIO_DSQ	(MAX_CPUS + 1)

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
const volatile u64 slice_ns = SCX_SLICE_DFL;

/*
 * Time slice used when system is over commissioned.
 */
const volatile u64 slice_ns_min = 500000;

/*
 * Maximum time slice lag.
 *
 * Increasing this value can help to increase the responsiveness of interactive
 * tasks at the cost of making regular and newly created tasks less responsive
 * (0 = disabled).
 */
const volatile u64 slice_ns_lag;

/*
 * Enable built-in idle selection logic.
 */
const volatile bool builtin_idle;

/*
 * Threshold of voluntary context switches used to classify a task as
 * interactive.
 */
const volatile u64 nvcsw_thresh = 10;

/*
 * Scheduling statistics.
 */
volatile u64 nr_direct_dispatches, nr_kthread_dispatches,
	     nr_shared_dispatches, nr_prio_dispatches;

/*
 * Amount of currently running tasks.
 */
volatile u64 nr_running;

/*
 * Exit information.
 */
UEI_DEFINE(uei);

/*
 * Mask of offline CPUs, used to properly support CPU hotplugging.
 */
private(BPFLAND) struct bpf_cpumask __kptr *offline_cpumask;

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

/* Return a local task context from a generic task */
struct task_ctx *lookup_task_ctx(const struct task_struct *p)
{
	struct task_ctx *tctx;

	tctx = bpf_task_storage_get(&task_ctx_stor, (struct task_struct *)p, 0, 0);
	if (!tctx) {
		scx_bpf_error("Failed to lookup task ctx for %s", p->comm);
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
	 * Limit the vruntime to (vtime_now - slice_ns_lag) to avoid penalizing
	 * tasks too much (this helps to speed up new fork'ed tasks).
	 */
	if (vtime_before(vtime, vtime_now - slice_ns_lag))
		vtime = vtime_now - slice_ns_lag;

	return vtime;
}

/*
 * Return the task's unused portion of its previously assigned time slice (with
 * a minimum of slice_ns_min).
 */
static inline u64 task_slice(struct task_struct *p)
{
	u64 slice = p->scx.slice;

	return MAX(slice, slice_ns_min);
}

/*
 * Return the DSQ ID associated to a CPU, or SHARED_DSQ if the CPU is not
 * valid.
 */
static u64 cpu_to_dsq(s32 cpu)
{
	if (cpu < 0 || cpu >= MAX_CPUS) {
		scx_bpf_error("Invalid cpu: %d", cpu);
		return SHARED_DSQ;
	}
	return (u64)cpu;
}

/*
 * Dispatch a per-CPU kthread directly to the local CPU DSQ.
 */
static void dispatch_kthread(struct task_struct *p, u64 enq_flags)
{
	u64 slice = task_slice(p);

	/*
	 * Use the local CPU DSQ directly for per-CPU kthreads, to give them
	 * maximum priority.
	 */
	scx_bpf_dispatch(p, SCX_DSQ_LOCAL, slice, enq_flags);

	__sync_fetch_and_add(&nr_kthread_dispatches, 1);
}

/*
 * Dispatch a task directly to the assigned CPU DSQ (used when an idle CPU is
 * found).
 */
static int dispatch_direct_cpu(struct task_struct *p, s32 cpu)
{
	u64 slice = task_slice(p);
	u64 dsq_id = cpu_to_dsq(cpu);

	/*
	 * Make sure we can dispatch the task to the target CPU according to
	 * its cpumask.
	 */
	if (!bpf_cpumask_test_cpu(cpu, p->cpus_ptr))
		return -EINVAL;

	/*
	 * We don't need to use vtime here, because we basically dispatch one
	 * task at a time when the corresponding CPU is idle.
	 *
	 * We could also use SCX_DSQ_LOCAL, but we want to distinguish regular
	 * tasks from per-CPU kthreads to give more priority to the latter.
	 */
	scx_bpf_dispatch(p, dsq_id, slice, 0);
	__sync_fetch_and_add(&nr_direct_dispatches, 1);

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
 * Dispatch a regular task.
 */
static void dispatch_task(struct task_struct *p, u64 enq_flags)
{
	u64 vtime = task_vtime(p);
	u64 slice = task_slice(p);
	struct task_ctx *tctx;

	tctx = lookup_task_ctx(p);
	if (!tctx)
		return;
	/*
	 * Always dispatch interactive tasks to the priority DSQ and regular
	 * tasks to the shared DSQ.
	 */
	if (tctx->is_interactive) {
		scx_bpf_dispatch_vtime(p, PRIO_DSQ, slice, vtime, enq_flags);
		__sync_fetch_and_add(&nr_prio_dispatches, 1);
	} else {
		scx_bpf_dispatch_vtime(p, SHARED_DSQ, slice, vtime, enq_flags);
		__sync_fetch_and_add(&nr_shared_dispatches, 1);
	}
}

/*
 * Find an idle CPU in the system.
 */
static s32 pick_idle_cpu(struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
	const struct cpumask *online_cpumask, *idle_smtmask, *idle_cpumask;
	bool prev_in_cand;
	s32 cpu;

	if (builtin_idle) {
		bool is_idle = false;

		/*
		 * Find an idle CPU using the sched_ext built-in idle selection
		 * logic.
		 */
		cpu = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle);
		if (is_idle)
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

	prev_in_cand = bpf_cpumask_test_cpu(prev_cpu, p->cpus_ptr);

	if (smt_enabled) {
		/*
		 * If the task can still run on the previously used CPU and
		 * it's a full-idle core, keep using it.
		 */
		if (prev_in_cand &&
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
	 * If a full-idle core can't be found (or if it's not an SMT system)
	 * try to re-use the same CPU, even if it's not in a full-idle core.
	 */
	if (prev_in_cand && scx_bpf_test_and_clear_cpu_idle(prev_cpu)) {
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
	 * Try to prioritize newly awakened tasks.
	 */
	if (wake_flags & SCX_WAKE_SYNC) {
		struct task_ctx *tctx;

		/*
		 * If we are waking up a task and we couldn't find any idle CPU
		 * to use, at least set the task as interactive, so that it can
		 * be dispatched as soon as possible on the first CPU
		 * available.
		 */
		tctx = lookup_task_ctx(p);
		if (tctx)
			tctx->is_interactive = true;
	}

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

s32 BPF_STRUCT_OPS(bpfland_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
	s32 cpu;

	cpu = pick_idle_cpu(p, prev_cpu, wake_flags);
	if (cpu >= 0 && !dispatch_direct_cpu(p, cpu))
		return cpu;

	return prev_cpu;
}

void BPF_STRUCT_OPS(bpfland_enqueue, struct task_struct *p, u64 enq_flags)
{
	/*
	 * Always dispatch per-CPU kthreads immediately.
	 *
	 * This allows to prioritize critical kernel threads that may
	 * potentially slow down the entire system if they are blocked for too
	 * long (i.e., ksoftirqd/N, rcuop/N, etc.).
	 *
	 * NOTE: this could cause interactivity problems or unfairness if there
	 * are too many softirqs being scheduled (e.g., in presence of high RX
	 * network RX traffic). However, considering that the main target of
	 * this scheduler is desktop usage, this shouldn't be a problem.
	 */
	if (is_kthread(p) && p->nr_cpus_allowed == 1) {
		dispatch_kthread(p, enq_flags);
		return;
	}

	/*
	 * Dispatch all the other tasks that were not dispatched directly in
	 * select_cpu().
	 */
	dispatch_task(p, enq_flags);
}

/*
 * Consume tasks dispatched to CPUs that have gone offline.
 *
 * These tasks will be consumed on other active CPUs to prevent indefinite
 * stalling.
 */
static int dispatch_offline_cpus(s32 cpu)
{
	u64 cpu_max = scx_bpf_nr_cpu_ids();
	struct bpf_cpumask *offline;
	int ret = -ENOENT;

	bpf_rcu_read_lock();

	offline = offline_cpumask;
	if (!offline)
		goto out_rcu;

	/*
	 * Cycle through all the CPUs and evenly consume tasks from the DSQs of
	 * those that are offline.
	 */
	bpf_repeat(cpu_max - 1) {
		cpu = (cpu + 1) % cpu_max;

		if (!bpf_cpumask_test_cpu(cpu, cast_mask(offline)))
			continue;
		/*
		 * This CPU is offline, if a task has been dispatched there
		 * consume it immediately on the current CPU.
		 */
		if (scx_bpf_consume(cpu_to_dsq(cpu))) {
			ret = 0;
			goto out_rcu;
		}
	}
out_rcu:
	bpf_rcu_read_unlock();

	return ret;
}

void BPF_STRUCT_OPS(bpfland_dispatch, s32 cpu, struct task_struct *prev)
{
	/*
	 * First consume directly dispatched tasks, so that they can
	 * immediately use the CPU assigned in select_cpu().
	 */
	if (scx_bpf_consume(cpu_to_dsq(cpu)))
		return;

	/*
	 * Try also to steal tasks directly dispatched to CPUs that have gone
	 * offline (this allows to prevent indefinite task stalls).
	 */
	if (!dispatch_offline_cpus(cpu))
		return;

	/*
	 * Then always consume interactive tasks before regular tasks.
	 *
	 * This is fine and we shouldn't have starvation, because interactive
	 * tasks are classified by their amount of voluntary context switches,
	 * so they should naturally release the CPU quickly and give a chance
	 * to the regular tasks to run.
	 *
	 * TODO: Add a tunable setting to limit the number of priority tasks
	 * dispatched. Once this limit is reached, at least one regular task
	 * must be dispatched.
	 */
	if (scx_bpf_consume(PRIO_DSQ))
		return;

	/*
	 * Lastly, consume regular tasks from the shared DSQ.
	 */
	scx_bpf_consume(SHARED_DSQ);
}

void BPF_STRUCT_OPS(bpfland_running, struct task_struct *p)
{
	/* Update global vruntime */
	if (vtime_before(vtime_now, p->scx.dsq_vtime))
		vtime_now = p->scx.dsq_vtime;

	__sync_fetch_and_add(&nr_running, 1);
}

/*
 * Update task statistics when the task is releasing the CPU (either
 * voluntarily or because it expires its assigned time slice).
 */
void BPF_STRUCT_OPS(bpfland_stopping, struct task_struct *p, bool runnable)
{
	u64 now = bpf_ktime_get_ns();
	struct task_ctx *tctx;

	__sync_fetch_and_sub(&nr_running, 1);

	tctx = lookup_task_ctx(p);
	if (!tctx)
		return;

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
	 * high priority DSQ (PRIO_DSQ).
	 */
	p->scx.dsq_vtime += (slice_ns - p->scx.slice) * 100 / p->scx.weight;

	/*
	 * Refresh voluntary context switch metrics.
	 *
	 * Evaluate the average number of voluntary context switches per second
	 * using an exponentially weighted moving average, see calc_avg().
	 */
	if (now - tctx->nvcsw_ts > NSEC_PER_SEC) {
		u64 delta_nvcsw = p->nvcsw - tctx->nvcsw;
		u64 delta_t = MAX(now - tctx->nvcsw_ts, 1);
		u64 avg_nvcsw = delta_nvcsw * NSEC_PER_SEC / delta_t;

		tctx->avg_nvcsw = calc_avg(tctx->avg_nvcsw, avg_nvcsw);
		tctx->nvcsw = p->nvcsw;
		tctx->nvcsw_ts = now;

		dbg_msg("%s: pid=%d (%s) delta_nvcsw=%llu delta_t=%llu "
			"curr_avg_nvcsw=%llu avg_nvcsw=%llu",
			__func__, p->pid, p->comm, delta_nvcsw, delta_t,
			avg_nvcsw, tctx->avg_nvcsw);
	}

	/*
	 * Classify interactive tasks based on the average amount of their
	 * voluntary context switches.
	 */
	if (nvcsw_thresh && tctx->avg_nvcsw >= nvcsw_thresh)
		tctx->is_interactive = true;
}

void BPF_STRUCT_OPS(bpfland_enable, struct task_struct *p)
{
	/* Initialize task's vruntime */
	p->scx.dsq_vtime = vtime_now;
}

/*
 * Set the offline state of a CPU, updating the global offline cpumask.
 */
static void set_cpu_offline(s32 cpu, bool state)
{
	struct bpf_cpumask *offline;

	bpf_rcu_read_lock();

	offline = offline_cpumask;
	if (!offline)
		goto out_rcu;
	if (state)
		bpf_cpumask_set_cpu(cpu, offline);
	else
		bpf_cpumask_clear_cpu(cpu, offline);

out_rcu:
	bpf_rcu_read_unlock();
}

void BPF_STRUCT_OPS(bpfland_cpu_online, s32 cpu)
{
	/* Set the CPU state to offline */
	set_cpu_offline(cpu, false);
}

void BPF_STRUCT_OPS(bpfland_cpu_offline, s32 cpu)
{
	/* Set the CPU state to online */
	set_cpu_offline(cpu, true);
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

s32 BPF_STRUCT_OPS_SLEEPABLE(bpfland_init)
{
	struct bpf_cpumask *offline;
	int err;
	s32 cpu;

	/* Create per-CPU DSQs (used to dispatch tasks directly on a CPU) */
	bpf_for(cpu, 0, MAX_CPUS) {
		err = scx_bpf_create_dsq(cpu_to_dsq(cpu), -1);
		if (err) {
			scx_bpf_error("failed to create pcpu DSQ %d: %d",
				      cpu, err);
			return err;
		}
	}

	/* Create the global priority DSQ (for interactive tasks) */
	err = scx_bpf_create_dsq(PRIO_DSQ, -1);
	if (err) {
		scx_bpf_error("failed to create priority DSQ: %d", err);
		return err;
	}

	/* Create the global shared DSQ (for regular tasks) */
	err = scx_bpf_create_dsq(SHARED_DSQ, -1);
	if (err) {
		scx_bpf_error("failed to create shared DSQ: %d", err);
		return err;
	}

	/* Initialize the offline CPU mask */
	bpf_rcu_read_lock();
	err = calloc_cpumask(&offline_cpumask);
	offline = offline_cpumask;
	if (err || !offline)
		err = -ENOMEM;
	bpf_rcu_read_unlock();

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
