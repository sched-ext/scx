/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2024 Meta Platforms, Inc. and affiliates.
 * Copyright (c) 2024 Tejun Heo <tj@kernel.org>
 * Copyright (c) 2024 Emil Tsalapatis <etsal@meta.com>
 */

#include <scx/common.bpf.h>

#include "sdt_task.h"

/*
 * Task BPF map entry recording the task's assigned ID and pointing to the data
 * area allocated in arena.
 */
struct sdt_task_map_val {
	union sdt_id		tid;
	__u64			tptr;
	struct sdt_data __arena	*data;
};

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct sdt_task_map_val);
} sdt_task_map SEC(".maps");

struct sdt_allocator sdt_task_allocator;

__hidden
void __arena *sdt_task_alloc(struct task_struct *p)
{
	struct sdt_data __arena *data = NULL;
	struct sdt_task_map_val *mval;

	mval = bpf_task_storage_get(&sdt_task_map, p, 0,
				    BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!mval)
		return NULL;

	data = sdt_alloc(&sdt_task_allocator);
	if (unlikely(!data))
		return NULL;

	cast_kern(data);

	mval->tid = data->tid;
	mval->tptr = (__u64) p;
	mval->data = data;

	return (void __arena *)data->payload;
}

__hidden
int sdt_task_init(__u64 data_size)
{
	return sdt_alloc_init(&sdt_task_allocator, data_size);
}

__hidden
void __arena *sdt_task_data(struct task_struct *p)
{
	struct sdt_data __arena *data;
	struct sdt_task_map_val *mval;

	sdt_subprog_init_arena();

	mval = bpf_task_storage_get(&sdt_task_map, p, 0, 0);
	if (!mval)
		return NULL;

	data = mval->data;

	return (void __arena *)data->payload;
}

__hidden
void sdt_task_free(struct task_struct *p)
{
	struct sdt_task_map_val *mval;

	sdt_subprog_init_arena();

	mval = bpf_task_storage_get(&sdt_task_map, p, 0, 0);
	if (!mval)
		return;

	sdt_free_idx(&sdt_task_allocator, mval->tid.idx);
	bpf_task_storage_delete(&sdt_task_map, p);
}
