/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2024 Meta Platforms, Inc. and affiliates.
 * Copyright (c) 2024 Tejun Heo <tj@kernel.org>
 * Copyright (c) 2024 Emil Tsalapatis <etsal@meta.com>
 */

#include <libarena/common.h>
#include <scx/common.bpf.h>
#include <lib/arena.h>
#include <lib/sdt_task.h>
#include <lib/urcu.h>

static size_t task_ctx_size;

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, u64);
} scx_task_map SEC(".maps");

__hidden
void __arena *scx_task_alloc(struct task_struct *p)
{
	void __arena *data;
	u64 *mval;

	mval = bpf_task_storage_get(&scx_task_map, p, 0,
				    BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!mval) {
		scx_bpf_error("bpf_task_storage_get failed");
		return NULL;
	}

	data = arena_calloc(1, task_ctx_size);
	if (unlikely(!data)) {
		scx_bpf_error("arena_calloc failed");
		return NULL;
	}

	*mval = (u64)data;

	return data;
}

__hidden
int scx_task_init(__u64 data_size, __u64 align)
{
	/*
	 * @align is satisfied implicitly: libarena's buddy allocator rounds a
	 * request up to a power of two and returns blocks aligned to their own
	 * size, so an allocation of @data_size bytes is at least @align aligned
	 * for any @align no larger than it.
	 */
	task_ctx_size = data_size;
	return 0;
}

__hidden
void __arena *__scx_task_data(struct task_struct *p)
{
	u64 *mval;

	arena_subprog_init();

	mval = bpf_task_storage_get(&scx_task_map, p, 0, 0);
	if (unlikely(!mval || !*mval))
		return NULL;

	return (void __arena *)*mval;
}

__hidden
void __arena *scx_task_data(struct task_struct *p)
{
	void __arena *data = __scx_task_data(p);

	if (unlikely(!data))
		scx_err_loc("no task data");

	return data;
}

/*
 * Repeated and concurrent frees are no-ops: whoever claims the pointer frees
 * the allocation. The task_storage entry is left for the kernel to reclaim
 * when the task itself is freed, which takes the immediate free path and keeps
 * task exit off RCU-tasks-trace deferral.
 */
__hidden
void scx_task_free(struct task_struct *p)
{
	u64 *mval;
	void __arena *data;

	arena_subprog_init();

	mval = bpf_task_storage_get(&scx_task_map, p, 0, 0);
	if (unlikely(!mval))
		return;

	data = (void __arena *)__sync_lock_test_and_set(mval, 0);
	if (unlikely(!data))
		return;

	arena_free(data);
}

static struct scx_urcu scx_task_urcu;

/*
 * The deferred counterpart of scx_task_free(): queue @p's allocation, if any,
 * for freeing after a grace period, currently provided by the scx_urcu
 * machinery in lib/urcu.bpf.c. For free path hooks: absence is not an error
 * and repeated calls are no-ops, the first caller claims the allocation.
 */
__hidden
void scx_task_free_rcu(struct task_struct *p)
{
	void __arena *data;
	u64 *mval;

	arena_subprog_init();

	mval = bpf_task_storage_get(&scx_task_map, p, 0, 0);
	if (unlikely(!mval))
		return;

	data = (void __arena *)__sync_lock_test_and_set(mval, 0);
	if (unlikely(!data))
		return;

	scx_urcu_free(&scx_task_urcu, data);
}

/* scx_urcu driver programs, discovered by name and run by the userspace side */
SEC("syscall")
int scx_urcu_task_pending(void *ctx)
{
	return scx_urcu_pending(&scx_task_urcu);
}

SEC("syscall")
int scx_urcu_task_reclaim(void *ctx)
{
	return scx_urcu_reclaim(&scx_task_urcu);
}
