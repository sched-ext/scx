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
		scx_err_loc("bpf_task_storage_get failed");
		return NULL;
	}

	data = arena_malloc(task_ctx_size);
	if (unlikely(!data)) {
		scx_err_loc("scx_alloc failed");
		return NULL;
	}

	*mval = (u64)data;

	return data;
}

__hidden
int scx_task_init(__u64 data_size)
{
	task_ctx_size = data_size;
	return 0;
}

__hidden
void __arena *scx_task_data(struct task_struct *p)
{
	u64 *mval;

	arena_subprog_init();

	mval = bpf_task_storage_get(&scx_task_map, p, 0, 0);
	if (!mval) {
		scx_err_loc("bpf_task_storage_get failed");
		return NULL;
	}

	return (void __arena *)*mval;
}

__hidden
void scx_task_free(struct task_struct *p)
{
	u64 *mval;

	arena_subprog_init();

	mval = bpf_task_storage_get(&scx_task_map, p, 0, 0);
	if (!mval) {
		scx_err_loc("bpf_task_storage_get failed");
		return;
	}

	arena_free((void __arena *)*mval);
	bpf_task_storage_delete(&scx_task_map, p);
}
