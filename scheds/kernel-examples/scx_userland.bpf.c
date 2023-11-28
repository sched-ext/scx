/* SPDX-License-Identifier: GPL-2.0 */
/*
 * A minimal userland scheduler.
 *
 * In terms of scheduling, this provides two different types of behaviors:
 * 1. A global FIFO scheduling order for _any_ tasks that have CPU affinity.
 *    All such tasks are direct-dispatched from the kernel, and are never
 *    enqueued in user space.
 * 2. A primitive vruntime scheduler that is implemented in user space, for all
 *    other tasks.
 *
 * Some parts of this example user space scheduler could be implemented more
 * efficiently using more complex and sophisticated data structures. For
 * example, rather than using BPF_MAP_TYPE_QUEUE's,
 * BPF_MAP_TYPE_{USER_}RINGBUF's could be used for exchanging messages between
 * user space and kernel space. Similarly, we use a simple vruntime-sorted list
 * in user space, but an rbtree could be used instead.
 *
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 * Copyright (c) 2022 Tejun Heo <tj@kernel.org>
 * Copyright (c) 2022 David Vernet <dvernet@meta.com>
 */
#include <string.h>
#include "scx_common.bpf.h"
#include "scx_userland.h"

char _license[] SEC("license") = "GPL";

const volatile bool switch_partial;
const volatile s32 usersched_pid;

/* !0 for veristat, set during init */
const volatile u32 num_possible_cpus = 64;

/* Stats that are printed by user space. */
u64 nr_failed_enqueues, nr_kernel_enqueues, nr_user_enqueues;

struct user_exit_info uei;

/*
 * Whether the user space scheduler needs to be scheduled due to a task being
 * enqueued in user space.
 */
static bool usersched_needed;

/*
 * The map containing tasks that are enqueued in user space from the kernel.
 *
 * This map is drained by the user space scheduler.
 */
struct {
	__uint(type, BPF_MAP_TYPE_QUEUE);
	__uint(max_entries, USERLAND_MAX_TASKS);
	__type(value, struct scx_userland_enqueued_task);
} enqueued SEC(".maps");

/*
 * The map containing tasks that are dispatched to the kernel from user space.
 *
 * Drained by the kernel in userland_dispatch().
 */
struct {
	__uint(type, BPF_MAP_TYPE_QUEUE);
	__uint(max_entries, USERLAND_MAX_TASKS);
	__type(value, s32);
} dispatched SEC(".maps");

/* Per-task scheduling context */
struct task_ctx {
	bool force_local; /* Dispatch directly to local DSQ */
};

/* Map that contains task-local storage. */
struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct task_ctx);
} task_ctx_stor SEC(".maps");

static bool is_usersched_task(const struct task_struct *p)
{
	return p->pid == usersched_pid;
}

static bool keep_in_kernel(const struct task_struct *p)
{
	return p->nr_cpus_allowed < num_possible_cpus;
}

static struct task_struct *usersched_task(void)
{
	struct task_struct *p;

	p = bpf_task_from_pid(usersched_pid);
	/*
	 * Should never happen -- the usersched task should always be managed
	 * by sched_ext.
	 */
	if (!p)
		scx_bpf_error("Failed to find usersched task %d", usersched_pid);

	return p;
}

s32 BPF_STRUCT_OPS(userland_select_cpu, struct task_struct *p,
		   s32 prev_cpu, u64 wake_flags)
{
	if (keep_in_kernel(p)) {
		s32 cpu;
		struct task_ctx *tctx;

		tctx = bpf_task_storage_get(&task_ctx_stor, p, 0, 0);
		if (!tctx) {
			scx_bpf_error("Failed to look up task-local storage for %s", p->comm);
			return -ESRCH;
		}

		if (p->nr_cpus_allowed == 1 ||
		    scx_bpf_test_and_clear_cpu_idle(prev_cpu)) {
			tctx->force_local = true;
			return prev_cpu;
		}

		cpu = scx_bpf_pick_idle_cpu(p->cpus_ptr, 0);
		if (cpu >= 0) {
			tctx->force_local = true;
			return cpu;
		}
	}

	return prev_cpu;
}

static void dispatch_user_scheduler(void)
{
	struct task_struct *p;

	usersched_needed = false;
	p = usersched_task();
	if (p) {
		scx_bpf_dispatch(p, SCX_DSQ_GLOBAL, SCX_SLICE_DFL, 0);
		bpf_task_release(p);
	}
}

static void enqueue_task_in_user_space(struct task_struct *p, u64 enq_flags)
{
	struct scx_userland_enqueued_task task;

	memset(&task, 0, sizeof(task));
	task.pid = p->pid;
	task.sum_exec_runtime = p->se.sum_exec_runtime;
	task.weight = p->scx.weight;

	if (bpf_map_push_elem(&enqueued, &task, 0)) {
		/*
		 * If we fail to enqueue the task in user space, put it
		 * directly on the global DSQ.
		 */
		__sync_fetch_and_add(&nr_failed_enqueues, 1);
		scx_bpf_dispatch(p, SCX_DSQ_GLOBAL, SCX_SLICE_DFL, enq_flags);
	} else {
		__sync_fetch_and_add(&nr_user_enqueues, 1);
		usersched_needed = true;
	}
}

void BPF_STRUCT_OPS(userland_enqueue, struct task_struct *p, u64 enq_flags)
{
	if (keep_in_kernel(p)) {
		u64 dsq_id = SCX_DSQ_GLOBAL;
		struct task_ctx *tctx;

		tctx = bpf_task_storage_get(&task_ctx_stor, p, 0, 0);
		if (!tctx) {
			scx_bpf_error("Failed to lookup task ctx for %s", p->comm);
			return;
		}

		if (tctx->force_local)
			dsq_id = SCX_DSQ_LOCAL;
		tctx->force_local = false;
		scx_bpf_dispatch(p, dsq_id, SCX_SLICE_DFL, enq_flags);
		__sync_fetch_and_add(&nr_kernel_enqueues, 1);
		return;
	} else if (!is_usersched_task(p)) {
		enqueue_task_in_user_space(p, enq_flags);
	}
}

void BPF_STRUCT_OPS(userland_dispatch, s32 cpu, struct task_struct *prev)
{
	if (usersched_needed)
		dispatch_user_scheduler();

	bpf_repeat(4096) {
		s32 pid;
		struct task_struct *p;

		if (bpf_map_pop_elem(&dispatched, &pid))
			break;

		/*
		 * The task could have exited by the time we get around to
		 * dispatching it. Treat this as a normal occurrence, and simply
		 * move onto the next iteration.
		 */
		p = bpf_task_from_pid(pid);
		if (!p)
			continue;

		scx_bpf_dispatch(p, SCX_DSQ_GLOBAL, SCX_SLICE_DFL, 0);
		bpf_task_release(p);
	}
}

s32 BPF_STRUCT_OPS(userland_prep_enable, struct task_struct *p,
		   struct scx_enable_args *args)
{
	if (bpf_task_storage_get(&task_ctx_stor, p, 0,
				 BPF_LOCAL_STORAGE_GET_F_CREATE))
		return 0;
	else
		return -ENOMEM;
}

s32 BPF_STRUCT_OPS(userland_init)
{
	if (num_possible_cpus == 0) {
		scx_bpf_error("User scheduler # CPUs uninitialized (%d)",
			      num_possible_cpus);
		return -EINVAL;
	}

	if (usersched_pid <= 0) {
		scx_bpf_error("User scheduler pid uninitialized (%d)",
			      usersched_pid);
		return -EINVAL;
	}

	if (!switch_partial)
		scx_bpf_switch_all();
	return 0;
}

void BPF_STRUCT_OPS(userland_exit, struct scx_exit_info *ei)
{
	uei_record(&uei, ei);
}

SEC(".struct_ops.link")
struct sched_ext_ops userland_ops = {
	.select_cpu		= (void *)userland_select_cpu,
	.enqueue		= (void *)userland_enqueue,
	.dispatch		= (void *)userland_dispatch,
	.prep_enable		= (void *)userland_prep_enable,
	.init			= (void *)userland_init,
	.exit			= (void *)userland_exit,
	.timeout_ms		= 3000,
	.name			= "userland",
};
