/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2024 Andrea Righi <arighi@nvidia.com>
 */
#include <scx/common.bpf.h>
#include "intf.h"

char _license[] SEC("license") = "GPL";

/*
 * Maximum amount of voluntary context switches (this limit allows to prevent
 * spikes or abuse of the nvcsw dynamic).
 */
#define MAX_AVG_NVCSW		128

/*
 * Task time slice range.
 */
const volatile u64 slice_max = 20ULL * NSEC_PER_MSEC;
const volatile u64 slice_lag = 20ULL * NSEC_PER_MSEC;

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
 * Scheduling statistics.
 */
volatile u64 nr_kthread_dispatches, nr_direct_dispatches, nr_shared_dispatches;

/*
 * Exit information.
 */
UEI_DEFINE(uei);

/*
 * CPUs in the system have SMT is enabled.
 */
const volatile bool smt_enabled = true;

/*
 * Current global vruntime.
 */
static u64 vtime_now;

/*
 * Maximum possible CPU number.
 */
static u64 nr_cpu_ids;

/*
 * Per-task local storage.
 *
 * This contain all the per-task information used internally by the BPF code.
 */
struct task_ctx {
	/*
	 * Voluntary context switches metrics.
	 */
	u64 nvcsw;
	u64 nvcsw_ts;
	u64 avg_nvcsw;

	/*
	 * Task's average used time slice.
	 */
	u64 exec_runtime;
	u64 last_run_at;

	/*
	 * Task's deadline.
	 */
	u64 deadline;
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
 * Prevent excessive prioritization of tasks performing massive fsync()
 * operations on the filesystem. These tasks can degrade system responsiveness
 * by not being inherently latency-sensitive.
 */
SEC("?kprobe/vfs_fsync_range")
int kprobe_vfs_fsync_range(struct file *file, u64 start, u64 end, int datasync)
{
	struct task_struct *p = (void *)bpf_get_current_task_btf();
	struct task_ctx *tctx;

	tctx = try_lookup_task_ctx(p);
	if (tctx)
		tctx->avg_nvcsw = 0;
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
 * Return true if the target task @p is a kernel thread, false instead.
 */
static inline bool is_kthread(const struct task_struct *p)
{
	return p->flags & PF_KTHREAD;
}

/*
 * Return the amount of tasks that are waiting to run.
 */
static inline u64 nr_tasks_waiting(int node)
{
	return scx_bpf_dsq_nr_queued(node) + 1;
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
	 * Tasks with a higher nvcsw rate get a bigger "bucket" for their
	 * allowed accumulated time budget.
	 */
	vtime_min = vtime_now - slice_lag * tctx->avg_nvcsw;
	if (time_before(tctx->deadline, vtime_min))
		tctx->deadline = vtime_min;

	/*
	 * Add the execution vruntime to the deadline.
	 */
	return tctx->deadline + scale_by_task_weight_inverse(p, tctx->exec_runtime);
}

/*
 * Evaluate task's time slice in function of the total amount of tasks that
 * are waiting to be dispatched and the task's weight.
 */
static u64 task_slice(const struct task_struct *p,
		      const struct task_ctx *tctx, int node)
{
	/*
	 * Assign a time slice proportional to the task weight and inversely
	 * proportional to the total amount of tasks that are waiting to be
	 * scheduled.
	 */
	return scale_by_task_weight(p, slice_max / nr_tasks_waiting(node));
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
	int node = __COMPAT_scx_bpf_cpu_node(prev_cpu);
	bool is_idle = false;
	s32 cpu;

	cpu = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle);
	if (is_idle && !scx_bpf_dsq_nr_queued(node)) {
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, SCX_SLICE_DFL, 0);
		__sync_fetch_and_add(&nr_direct_dispatches, 1);
	}

	return cpu;
}

/*
 * Dispatch all the other tasks that were not dispatched directly in
 * select_cpu().
 */
void BPF_STRUCT_OPS(flash_enqueue, struct task_struct *p, u64 enq_flags)
{
	s32 cpu = scx_bpf_task_cpu(p);
	int node = __COMPAT_scx_bpf_cpu_node(cpu);
	struct task_ctx *tctx;

	/*
	 * Per-CPU kthreads can be critical for system responsiveness, when
	 * local_kthreads is specified they are always dispatched directly
	 * before any other task.
	 */
	if (local_kthreads && is_kthread(p) && (p->nr_cpus_allowed == 1)) {
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, SCX_SLICE_DFL,
				   enq_flags | SCX_ENQ_PREEMPT);
		__sync_fetch_and_add(&nr_kthread_dispatches, 1);
		return;
	}

	/*
	 * Enqueue the task to the global DSQ. The task will be dispatched on
	 * the first CPU that becomes available.
	 */
	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return;

	scx_bpf_dsq_insert_vtime(p, node, task_slice(p, tctx, node),
				 task_deadline(p, tctx), enq_flags);
	__sync_fetch_and_add(&nr_shared_dispatches, 1);

	/*
	 * Ensure the CPU currently used by the task is awake.
	 *
	 * We don't want to be overly proactive at waking idle CPUs here to
	 * increase the likelihood that CPU-intensive tasks remain on the
	 * same CPU if the system is not fully saturated (which should
	 * benefit cache-sensitive workloads), since they are re-enqueued
	 * directly via ops.enqueue() on slice exhaustion.
	 *
	 * While this may reduce work conservation for CPU-intensive tasks,
	 * it should also ensures that interactive tasks have more
	 * opportunities to find an idle CPU via ops.select_cpu(),
	 * improving their responsiveness.
	 */
	if (scx_bpf_test_and_clear_cpu_idle(cpu))
		scx_bpf_kick_cpu(cpu, SCX_KICK_IDLE);
}

void BPF_STRUCT_OPS(flash_dispatch, s32 cpu, struct task_struct *prev)
{
	int node = __COMPAT_scx_bpf_cpu_node(cpu);

	/*
	 * Select a new task to run.
	 */
	if (scx_bpf_dsq_move_to_local(node))
		return;

	/*
	 * If the current task expired its time slice and no other task wants
	 * to run, simply replenish its time slice and let it run for another
	 * round on the same CPU.
	 */
	if (prev && (prev->scx.flags & SCX_TASK_QUEUED))
		prev->scx.slice = SCX_SLICE_DFL;
}

void BPF_STRUCT_OPS(flash_runnable, struct task_struct *p, u64 enq_flags)
{
	struct task_ctx *tctx;

	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return;

	tctx->exec_runtime = 0;
}

void BPF_STRUCT_OPS(flash_running, struct task_struct *p)
{
	struct task_ctx *tctx;

	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return;
	tctx->last_run_at = scx_bpf_now();

	/*
	 * Update global vruntime.
	 */
	if (time_before(vtime_now, tctx->deadline))
		vtime_now = tctx->deadline;
}

void BPF_STRUCT_OPS(flash_stopping, struct task_struct *p, bool runnable)
{
	struct task_ctx *tctx;
	u64 slice;

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
	tctx->deadline += scale_by_task_weight_inverse(p, slice);
}

void BPF_STRUCT_OPS(flash_quiescent, struct task_struct *p, u64 deq_flags)
{
	u64 now = scx_bpf_now();
	s64 delta_t;
	struct task_ctx *tctx;

	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return;

	/*
	 * Increase the counter of voluntary context switches.
	 */
	tctx->nvcsw++;

	/*
	 * Refresh voluntary context switch metrics.
	 *
	 * Evaluate the average number of voluntary context switches per second
	 * using an exponentially weighted moving average, see calc_avg().
	 */
	delta_t = (s64)(now - tctx->nvcsw_ts);
	if (delta_t > NSEC_PER_SEC) {
		u64 avg_nvcsw = tctx->nvcsw * NSEC_PER_SEC / delta_t;

		tctx->nvcsw = 0;
		tctx->nvcsw_ts = now;

		/*
		 * Evaluate the latency weight of the task as its average rate
		 * of voluntary context switches (limited to to prevent
		 * excessive spikes).
		 */
		tctx->avg_nvcsw = calc_avg_clamp(tctx->avg_nvcsw, avg_nvcsw,
						 0, MAX_AVG_NVCSW);
	}
}

void BPF_STRUCT_OPS(flash_enable, struct task_struct *p)
{
	struct task_ctx *tctx;

	tctx = try_lookup_task_ctx(p);
	if (!tctx) {
		scx_bpf_error("incorrectly initialized task: %d (%s)",
			      p->pid, p->comm);
		return;
	}
	tctx->deadline = vtime_now;

	/*
	 * Assume new tasks will use the minimum allowed time slice.
	 */
	tctx->nvcsw_ts = scx_bpf_now();
}

s32 BPF_STRUCT_OPS(flash_init_task, struct task_struct *p,
		   struct scx_init_task_args *args)
{
	struct task_ctx *tctx;

	tctx = bpf_task_storage_get(&task_ctx_stor, p, 0,
				    BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!tctx)
		return -ENOMEM;

	return 0;
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

s32 BPF_STRUCT_OPS_SLEEPABLE(flash_init)
{
	int err, node;

	/* Initialize the amount of possible CPUs */
	nr_cpu_ids = scx_bpf_nr_cpu_ids();

	/*
	 * Create a separate DSQ for each NUMA node.
	 */
	bpf_for(node, 0, __COMPAT_scx_bpf_nr_node_ids()) {
		err = scx_bpf_create_dsq(node, node);
		if (err) {
			scx_bpf_error("failed to create DSQ %d: %d", node, err);
			return err;
		}
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
	       .runnable		= (void *)flash_runnable,
	       .running			= (void *)flash_running,
	       .stopping		= (void *)flash_stopping,
	       .quiescent		= (void *)flash_quiescent,
	       .enable			= (void *)flash_enable,
	       .init_task		= (void *)flash_init_task,
	       .cpu_release		= (void *)flash_cpu_release,
	       .init			= (void *)flash_init,
	       .exit			= (void *)flash_exit,
	       .timeout_ms		= 5000U,
	       .name			= "flash");
