/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2024 Meta Platforms, Inc. and affiliates.
 * Copyright (c) 2024 Tejun Heo <tj@kernel.org>
 * Copyright (c) 2024 Emil Tsalapatis <etsal@meta.com>
 */

#include "scxtest/scx_test.h"
#include <scx/common.bpf.h>
#include <lib/sdt_task.h>

/*
 * Task BPF map entry recording the task's assigned ID and pointing to the data
 * area allocated in arena.
 */
struct scx_task_map_val {
	union sdt_id		tid;
	__u64			tptr;
	struct sdt_data __arena	*data;
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
	struct sdt_data __arena *data = NULL;
	struct scx_task_map_val *mval;

	mval = bpf_task_storage_get(&scx_task_map, p, 0,
				    BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!mval) {
		bpf_printk("%s:%d bpf_task_storage_get failed", __func__, __LINE__);
		return NULL;
	}

	data = scx_alloc(&scx_task_allocator);
	if (unlikely(!data)) {
		bpf_printk("%s:%d scx_alloc failed", __func__, __LINE__);
		return NULL;
	}

	mval->tid = data->tid;
	mval->tptr = (__u64) p;
	mval->data = data;

	return (void __arena *)data->payload;
}

__hidden
int scx_task_init(__u64 data_size)
{
	return scx_alloc_init(&scx_task_allocator, data_size);
}

__hidden
void __arena *scx_task_data(struct task_struct *p)
{
	struct sdt_data __arena *data;
	struct scx_task_map_val *mval;

	scx_arena_subprog_init();

	mval = bpf_task_storage_get(&scx_task_map, p, 0, 0);
	if (!mval)
		return NULL;

	data = mval->data;

	return (void __arena *)data->payload;
}

__hidden
void scx_task_free(struct task_struct *p)
{
	struct scx_task_map_val *mval;

	scx_arena_subprog_init();

	mval = bpf_task_storage_get(&scx_task_map, p, 0, 0);
	if (!mval)
		return;

	scx_alloc_free_idx(&scx_task_allocator, mval->tid.idx);
	bpf_task_storage_delete(&scx_task_map, p);
}
