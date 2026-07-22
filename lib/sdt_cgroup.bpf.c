/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2026 Meta Platforms, Inc. and affiliates.
 * Copyright (c) 2026 Tejun Heo <tj@kernel.org>
 *
 * Arena-backed per-cgroup data, mirroring the per-task machinery in
 * sdt_task.bpf.c: the allocation lives in the arena and BPF cgroup local
 * storage holds the reference, so lookups go through the cgroup pointer with no
 * separate index.
 *
 * While task data is expected to match every task's lifetime, cgroup data is
 * allowed to be managed on demand, so both alloc and free are safe against
 * repeated and concurrent calls.
 *
 * With frees deferred to a hook on the kernel's cgroup storage teardown, an
 * fentry on bpf_cgrp_storage_free() which is after the cgroup is unreferencable
 * and before the storage entry is destroyed, the data stays valid for as long
 * as the cgroup data pointer that leads to it.
 */

#include <libarena/common.h>
#include <scx/common.bpf.h>
#include <lib/sdt_cgroup.h>
#include <lib/urcu.h>

/*
 * Cgroup BPF map entry pointing to the data area allocated in arena. The
 * pointer is the single word that alloc and free race on, and is all the
 * allocator needs to hand the allocation back.
 */
struct scx_cgrp_map_val {
	__u64			cptr;
	void __arena		*data;
};

struct {
	__uint(type, BPF_MAP_TYPE_CGRP_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct scx_cgrp_map_val);
} scx_cgrp_map SEC(".maps");

static size_t cgrp_ctx_size;

__hidden
int scx_cgrp_init(__u64 data_size, __u64 align)
{
	/*
	 * @align is satisfied implicitly: libarena's buddy allocator rounds a
	 * request up to a power of two and returns blocks aligned to their own
	 * size, so an allocation of @data_size bytes is at least @align aligned
	 * for any @align no larger than it.
	 */
	cgrp_ctx_size = data_size;
	return 0;
}

__hidden
void __arena *scx_cgrp_alloc(struct cgroup *cgrp)
{
	struct scx_cgrp_map_val *mval;
	void __arena *data;
	__u64 old;

	mval = bpf_cgrp_storage_get(&scx_cgrp_map, cgrp, 0, BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!mval) {
		scx_bpf_error("bpf_cgrp_storage_get failed");
		return NULL;
	}

	data = (void __arena *)READ_ONCE(*(__u64 *)&mval->data);
	if (unlikely(data))
		return data;

	data = arena_calloc(1, cgrp_ctx_size);
	if (unlikely(!data)) {
		scx_bpf_error("arena_calloc failed");
		return NULL;
	}

	/* racing allocs publish with cmpxchg, the loser uses the winner's */
	old = __sync_val_compare_and_swap((__u64 *)&mval->data, 0, (__u64)data);
	if (unlikely(old)) {
		arena_free(data);
		data = (void __arena *)old;
	} else {
		mval->cptr = (__u64)cgrp;
	}

	return data;
}

/*
 * Returns NULL without complaint when @cgrp has no allocation: unlike tasks,
 * schedulers routinely probe cgroups they never initialized, cgroups that
 * predate the scheduler for example. Callers decide whether NULL is an error.
 */
__hidden
void __arena *scx_cgrp_data(struct cgroup *cgrp)
{
	struct scx_cgrp_map_val *mval;

	arena_subprog_init();

	mval = bpf_cgrp_storage_get(&scx_cgrp_map, cgrp, 0, 0);
	if (unlikely(!mval))
		return NULL;

	return (void __arena *)READ_ONCE(*(__u64 *)&mval->data);
}

/*
 * Repeated and concurrent frees are no-ops: whoever claims the pointer frees
 * the allocation. Safe on cgroups that never had one, so free path hooks can
 * call this for every cgroup in the system.
 */
__hidden
void scx_cgrp_free(struct cgroup *cgrp)
{
	struct scx_cgrp_map_val *mval;
	void __arena *data;

	arena_subprog_init();

	mval = bpf_cgrp_storage_get(&scx_cgrp_map, cgrp, 0, 0);
	if (unlikely(!mval))
		return;

	data = (void __arena *)__sync_lock_test_and_set((__u64 *)&mval->data, 0);
	if (unlikely(!data))
		return;

	arena_free(data);
}

static struct scx_urcu scx_cgrp_urcu;

/*
 * The deferred counterpart of scx_cgrp_free(): queue @cgrp's allocation, if
 * any, for freeing after a grace period, currently provided by the scx_urcu
 * machinery in lib/urcu.bpf.c. Same repetition rules as scx_cgrp_free().
 */
__hidden
void scx_cgrp_free_rcu(struct cgroup *cgrp)
{
	struct scx_cgrp_map_val *mval;
	void __arena *data;

	arena_subprog_init();

	mval = bpf_cgrp_storage_get(&scx_cgrp_map, cgrp, 0, 0);
	if (unlikely(!mval))
		return;

	data = (void __arena *)__sync_lock_test_and_set((__u64 *)&mval->data, 0);
	if (unlikely(!data))
		return;

	scx_urcu_free(&scx_cgrp_urcu, data);
}

/* scx_urcu driver programs, discovered by name and run by the userspace side */
SEC("syscall")
int scx_urcu_cgrp_pending(void *ctx)
{
	return scx_urcu_pending(&scx_cgrp_urcu);
}

SEC("syscall")
int scx_urcu_cgrp_reclaim(void *ctx)
{
	return scx_urcu_reclaim(&scx_cgrp_urcu);
}
