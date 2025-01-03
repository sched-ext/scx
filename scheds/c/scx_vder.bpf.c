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
 * Time constants.
 */
enum consts {
	NSEC_PER_USEC = 1000ULL,
	NSEC_PER_MSEC = (1000ULL * NSEC_PER_USEC),
	NSEC_PER_SEC = (1000ULL * NSEC_PER_MSEC),
};

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
	 * The task's deadline (vruntime).
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
	 * Completely rely on the in-kernel built-in idle selection policy.
	 */
	cpu = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle);
	if (is_idle)
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, slice_ns, 0);

	return cpu;
}

/*
 * Task @p has been queued to the scheduler.
 */
void BPF_STRUCT_OPS(vder_enqueue, struct task_struct *p, u64 enq_flags)
{
	struct task_ctx *tctx;
	u64 vtime_min;

	/*
	 * Get the task context, if a context doesn't exist we can ignore
	 * the spurious enqueue event.
	 */
	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return;

	/*
	 * Limit the amount of vtime budget that an idling task can
	 * accumulate to prevent excessive prioritization of sleeping
	 * tasks.
	 *
	 * Tasks with a higher weight get a bigger "bucket" for their
	 * allowed accumulated time budget.
	 */
	vtime_min = vtime_now - slice_ns;
	if (vtime_before(p->scx.dsq_vtime, vtime_min))
		tctx->deadline = vtime_min;

	/*
	 * Queue the task to the global shared DSQ.
	 *
	 * Tasks are ordered by their deadline, the task with the earliest
	 * deadline will be consumed first in ops.dispatch().
	 */
	scx_bpf_dsq_insert_vtime(p, SHARED_DSQ, slice_ns, tctx->deadline, enq_flags);
}

/*
 * A CPU is ready to execute a task.
 */
void BPF_STRUCT_OPS(vder_dispatch, s32 cpu, struct task_struct *prev)
{
	/*
	 * Consume the first task from SHARED_DSQ.
	 */
	scx_bpf_dsq_move_to_local(SHARED_DSQ);
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
	slice = slice_ns - p->scx.slice;
	if (slice > slice_ns)
		slice = slice_ns;

	/*
	 * Update task's vruntime.
	 */
	tctx->deadline += scale_inverse_fair(p, slice);
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
	       .running			= (void *)vder_running,
	       .stopping		= (void *)vder_stopping,
	       .enable			= (void *)vder_enable,
	       .init_task		= (void *)vder_init_task,
	       .init			= (void *)vder_init,
	       .exit			= (void *)vder_exit,
	       .flags			= SCX_OPS_ENQ_EXITING,
	       .timeout_ms		= 5000,
	       .name			= "vder");
