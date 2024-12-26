/* SPDX-License-Identifier: GPL-2.0 */
/*
 * scx_vder: Virtual Deadline with Execution Runtime.
 *
 * Copyright (c) 2025 Andrea Righi <arighi@nvidia.com>
 */
#include <scx/common.bpf.h>

char _license[] SEC("license") = "GPL";

/*
 * Define struct user_exit_info which is shared between BPF and userspace
 * to communicate the exit status.
 */
UEI_DEFINE(uei);

/*
 * Custom global DSQ.
 */
#define SHARED_DSQ 0

/*
 * Default task time slice (task's time budget).
 */
const volatile u64 slice_ns;

/*
 * Keep track of the current global vruntime.
 *
 * The vuntime is defined as the task's runtime inversely scaled using the
 * task's weight (priority).
 */
static u64 vtime_now;

/*
 * Per-task context.
 */
struct task_ctx {
	/*
	 * Timestamp (in ns) when the task ran last time.
	 */
	u64 last_run_at;

	/*
	 * Sum of the task's runtime from when it becomes runnable (ready
	 * to run on a CPU) to when the task voluntarily releases the CPU
	 * (either by completing its execution or waiting for an event).
	 */
	u64 exec_runtime;

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
};

/*
 * BPF map to store the context of each task.
 */
struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct task_ctx);
} task_ctx_stor SEC(".maps");

/*
 * Return the context of @p, or NULL if the task doesn't exist.
 */
struct task_ctx *try_lookup_task_ctx(const struct task_struct *p)
{
	return bpf_task_storage_get(&task_ctx_stor,
				    (struct task_struct *)p, 0, 0);
}

/*
 * Return true if @p still wants to run, false otherwise.
 */
static bool is_queued(const struct task_struct *p)
{
	return p->scx.flags & SCX_TASK_QUEUED;
}

/*
 * Return true if vtime @a is before vtime @b, false otherwise.
 */
static inline bool vtime_before(u64 a, u64 b)
{
	return (s64)(a - b) < 0;
}

/*
 * Scale value inversely proportional to the weight of @p.
 */
static u64 scale_inverse_fair(const struct task_struct *p, u64 value)
{
	return value * 100 / p->scx.weight;
}

/*
 * Find the optimal CPU to run @p, if an idle CPU is found dispatch @p
 * directly, otherwise try to keep @p on the same CPU.
 */
s32 BPF_STRUCT_OPS(vder_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
	bool is_idle = false;
	s32 cpu;

	/*
	 * Completely rely on the in-kernel built-in idle selection policy
	 * and dispatch directly if an idle CPU is found.
	 *
	 * Note that we should avoid direct dispatch if there are tasks
	 * waiting in the shared DSQ, as tasks that frequently receive
	 * wakeup events may continue to be directly dispatched on the same
	 * local DSQ from here, monopolizing a CPU.
	 *
	 * This could lead to starvation of tasks that are waiting in the
	 * shared DSQ, in particular those that can only run on a single
	 * CPU (per-CPU tasks).
	 */
	cpu = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle);
	if (is_idle && !scx_bpf_dsq_nr_queued(SHARED_DSQ))
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, slice_ns, 0);

	return cpu;
}

/*
 * Try to wake up an idle CPU that can immediately process the task.
 */
static void kick_idle_cpu(const struct task_struct *p,
			  const struct task_ctx *tctx)
{
	const struct cpumask *idle_cpumask;
	s32 cpu;

	/*
	 * Look for an idle CPU that can immediately execute the task.
	 *
	 * Note that we do not want to mark the CPU as busy, since we don't
	 * know at this stage if we'll actually dispatch any task on it.
	 */
	idle_cpumask = scx_bpf_get_idle_cpumask();
	cpu = bpf_cpumask_any_and_distribute(p->cpus_ptr, idle_cpumask);
	scx_bpf_put_cpumask(idle_cpumask);

	/*
	 * Try to wake up the idle CPU, if we have found one.
	 */
	if (cpu < scx_bpf_nr_cpu_ids())
		scx_bpf_kick_cpu(cpu, SCX_KICK_IDLE);
}

/*
 * Attempt to dispatch a task directly to its assigned CPU.
 *
 * Return true if the task is dispatched, false otherwise.
 */
static bool try_direct_dispatch(struct task_struct *p, u64 enq_flags)
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
	 * If ops.select_cpu() has been skipped, try direct dispatch.
	 */
	if (!(enq_flags & SCX_ENQ_CPU_SELECTED)) {
		s32 prev_cpu = scx_bpf_task_cpu(p);

		/*
		 * If both the local and shared DSQs are empty and the
		 * previous CPU can still be used by the task, perform the
		 * direct dispatch.
		 */
		if (!scx_bpf_dsq_nr_queued(SCX_DSQ_LOCAL_ON | prev_cpu) &&
		    !scx_bpf_dsq_nr_queued(SHARED_DSQ) &&
		    bpf_cpumask_test_cpu(prev_cpu, p->cpus_ptr)) {
			scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | prev_cpu,
					   slice_ns, enq_flags);
			return true;
		}
	}

	/*
	 * Direct dispatch not possible, follow the regular scheduling
	 * path.
	 */
	return false;
}

/*
 * Update and return the task's deadline.
 */
static u64 task_deadline(const struct task_struct *p, struct task_ctx *tctx)
{
	u64 vtime_min;

	/*
	 * Limit the amount of vtime budget that an idling task can
	 * accumulate to prevent excessive prioritization of sleeping
	 * tasks.
	 *
	 * Tasks with a higher weight get a bigger "bucket" for their
	 * allowed accumulated time budget.
	 */
	vtime_min = vtime_now - slice_ns;
	if (vtime_before(tctx->deadline, vtime_min))
		tctx->deadline = vtime_min;

	/*
	 * Add the execution vruntime to the deadline.
	 */
	tctx->deadline += scale_inverse_fair(p, tctx->exec_runtime);

	return tctx->deadline;
}

/*
 * Evaluate and return the task's time slice.
 */
static u64 task_slice(const struct task_struct *p, struct task_ctx *tctx)
{
	u64 nr_waiting;

	/*
	 * Assign a time slice that is inversely proportional to the number
	 * of tasks waiting in the shared DSQ.
         *
	 * This can help to improve system responsiveness, reducing average
	 * runqueue latency, when the system is overcommitted.
         */
	nr_waiting = scx_bpf_dsq_nr_queued(SHARED_DSQ) + 1;

	return slice_ns / nr_waiting;
}

/*
 * Task @p has been queued to the scheduler.
 */
void BPF_STRUCT_OPS(vder_enqueue, struct task_struct *p, u64 enq_flags)
{
	struct task_ctx *tctx;
	u64 deadline, slice;

	/*
	 * Attempt to dispatch the task directly on its assigned CPU.
	 */
	if (try_direct_dispatch(p, enq_flags))
		return;

	/*
	 * Get the task context, if a context doesn't exist it is safe to
	 * ignore the spurious enqueue event.
	 */
	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return;

	deadline = task_deadline(p, tctx);
	slice = task_slice(p, tctx);

	/*
	 * Queue the task to the shared DSQ.
	 *
	 * Tasks are ordered by their deadline, the task with the earliest
	 * deadline will be consumed first in ops.dispatch().
	 */
	scx_bpf_dsq_insert_vtime(p, SHARED_DSQ, slice, deadline, enq_flags);

	/*
	 * Try to proactively wake up an idle CPU, so that it can
	 * immediately execute the task in case its current CPU is busy.
	 */
	kick_idle_cpu(p, tctx);
}

/*
 * A CPU is ready to execute a task.
 */
void BPF_STRUCT_OPS(vder_dispatch, s32 cpu, struct task_struct *prev)
{
	/*
	 * Consume the first task from SHARED_DSQ.
	 */
	if (scx_bpf_dsq_move_to_local(SHARED_DSQ))
		return;

	/*
	 * If the current task expired its time slice and no other task wants
	 * to run on the CPU, simply replenish its time slice and let it
	 * run for another round on the same CPU.
	 */
	if (prev && is_queued(prev))
		prev->scx.slice = slice_ns;
}

/*
 * Task @p is ready to run.
 */
void BPF_STRUCT_OPS(vder_runnable, struct task_struct *p, u64 enq_flags)
{
	struct task_ctx *tctx;

	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return;

	/*
	 * Reset the execution runtime, as we are starting the task either
	 * from the beginning of its lifetime or after it has been blocked.
	 */
	tctx->exec_runtime = 0;
}

/*
 * Task @p is about to start running on a CPU.
 */
void BPF_STRUCT_OPS(vder_running, struct task_struct *p)
{
	struct task_ctx *tctx;

	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return;

	/*
	 * Update the run timestamp (used to evaluate the used time slice).
	 */
	tctx->last_run_at = bpf_ktime_get_ns();

	/*
	 * Update the global vruntime as a new task is starting to use a
	 * CPU.
	 */
	if (vtime_before(vtime_now, tctx->deadline))
		vtime_now = tctx->deadline;
}

/*
 * Task @p is about to release the CPU.
 */
void BPF_STRUCT_OPS(vder_stopping, struct task_struct *p, bool runnable)
{
	struct task_ctx *tctx;
	u64 slice;

	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return;

	/*
	 * Evaluate the time slice used by the task.
	 */
	slice = bpf_ktime_get_ns() - tctx->last_run_at;

	/*
	 * Update task's execution time (exec_runtime), but never account
	 * more than 10 slices of runtime to prevent excessive
	 * de-prioritization of CPU-intensive tasks (which could lead to
	 * starvation).
	 */
	if (tctx->exec_runtime < 10 * slice_ns)
		tctx->exec_runtime += slice;

	/*
	 * Update task's vruntime.
	 */
	tctx->deadline += scale_inverse_fair(p, slice);
}

/*
 * Task @p is becoming non-runnable, because it's sleeping, moved to
 * another CPU or temporarily taken off the queue for attribute change).
 */
void BPF_STRUCT_OPS(vder_quiescent, struct task_struct *p, u64 deq_flags)
{
	/* Do nothing */
}

/*
 * Task @p is entering the BPF scheduler.
 */
void BPF_STRUCT_OPS(vder_enable, struct task_struct *p)
{
	struct task_ctx *tctx;

	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return;

	/*
	 * Initialize the task vruntime to the current global vruntime.
	 */
	tctx->deadline = vtime_now;
}

/*
 * Task @p is created.
 */
s32 BPF_STRUCT_OPS(vder_init_task, struct task_struct *p,
		   struct scx_init_task_args *args)
{
	struct task_ctx *tctx;

	tctx = bpf_task_storage_get(&task_ctx_stor, p, 0,
				    BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!tctx)
		return -ENOMEM;

	return 0;
}

void BPF_STRUCT_OPS(vder_cpu_release, s32 cpu, struct scx_cpu_release_args *args)
{
	/*
	 * When a CPU is taken by a higher priority scheduler class,
	 * re-enqueue all the tasks that are waiting in the local DSQ, so
	 * that we can give them a chance to run on another CPU.
	 */
	scx_bpf_reenqueue_local();
}

s32 BPF_STRUCT_OPS_SLEEPABLE(vder_init)
{
	return scx_bpf_create_dsq(SHARED_DSQ, -1);
}

void BPF_STRUCT_OPS(vder_exit, struct scx_exit_info *ei)
{
	UEI_RECORD(uei, ei);
}

SCX_OPS_DEFINE(vder_ops,
	       .select_cpu		= (void *)vder_select_cpu,
	       .enqueue			= (void *)vder_enqueue,
	       .dispatch		= (void *)vder_dispatch,
	       .runnable		= (void *)vder_runnable,
	       .running			= (void *)vder_running,
	       .stopping		= (void *)vder_stopping,
	       .quiescent		= (void *)vder_quiescent,
	       .enable			= (void *)vder_enable,
	       .init_task		= (void *)vder_init_task,
	       .cpu_release		= (void *)vder_cpu_release,
	       .init			= (void *)vder_init,
	       .exit			= (void *)vder_exit,
	       .timeout_ms		= 5000,
	       .name			= "vder");
