/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2024 Meta Platforms, Inc. and affiliates.
 * Copyright (c) 2024 Tejun Heo <tj@kernel.org>
 * Copyright (c) 2024 Emil Tsalapatis <etsal@meta.com>
 */

#include <scx/common.bpf.h>
#include <lib/alloc/bpf_helpers_local.h>
#include <lib/sdt_task.h>

/*
 * Task BPF map entry recording the task's assigned ID and pointing to the data
 * area allocated in arena.
 */
struct scx_task_map_val {
	union sdt_id		tid;
	__u64			tptr;
	void __arena		*data;
};

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct scx_task_map_val);
} scx_task_map SEC(".maps");

struct scx_allocator scx_task_allocator;

__hidden
void __arena *scx_task_alloc(struct task_struct *p)
{
	struct scx_task_map_val *mval;
	void __arena *data;

	mval = bpf_task_storage_get(&scx_task_map, p, 0,
				    BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!mval) {
		scx_bpf_error("bpf_task_storage_get failed");
		return NULL;
	}

	data = scx_alloc(&scx_task_allocator);
	if (unlikely(!data)) {
		scx_bpf_error("scx_alloc failed");
		return NULL;
	}

	mval->tid = sdt_tailer(&scx_task_allocator, data)->tid;
	mval->tptr = (__u64) p;
	mval->data = data;

	return data;
}

__hidden
int scx_task_init(__u64 data_size)
{
	return scx_alloc_init(&scx_task_allocator, data_size);
}

__hidden
void __arena *__scx_task_data(struct task_struct *p)
{
	struct scx_task_map_val *mval;

	scx_arena_subprog_init();

	mval = bpf_task_storage_get(&scx_task_map, p, 0, 0);
	if (unlikely(!mval || !mval->data))
		return NULL;

	return mval->data;
}

__hidden
void __arena *scx_task_data(struct task_struct *p)
{
	void __arena *data = __scx_task_data(p);

	if (unlikely(!data))
		scx_err_loc("no task data");

	return data;
}

__hidden
void scx_task_free(struct task_struct *p)
{
	struct scx_task_map_val *mval;

	scx_arena_subprog_init();

	mval = bpf_task_storage_get(&scx_task_map, p, 0, 0);
	if (!mval) {
		scx_err_loc("bpf_task_storage_get failed");
		return;
	}

	scx_alloc_free_idx(&scx_task_allocator, mval->tid.idx);
	bpf_task_storage_delete(&scx_task_map, p);
}

static struct scx_urcu scx_task_urcu;

/*
 * The deferred counterpart of scx_task_free(): queue @p's allocation, if any,
 * for freeing after a grace period, currently provided by the scx_urcu
 * machinery in lib/sdt_alloc.bpf.c. For free path hooks: absence is not an
 * error and repeated calls are no-ops, the first caller claims the allocation.
 */
__hidden
void scx_task_free_rcu(struct task_struct *p)
{
	struct scx_task_map_val *mval;
	void __arena *data;

	scx_arena_subprog_init();

	mval = bpf_task_storage_get(&scx_task_map, p, 0, 0);
	if (unlikely(!mval))
		return;

	data = (void __arena *)__sync_lock_test_and_set((__u64 *)&mval->data, 0);
	if (unlikely(!data))
		return;

	scx_urcu_free(&scx_task_urcu, &scx_task_allocator, data);
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
	return scx_urcu_reclaim(&scx_task_urcu, &scx_task_allocator);
}
