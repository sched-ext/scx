/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2025 Meta Platforms, Inc. and affiliates.
 */
#include <scx/common.bpf.h>
#include <lib/arena_map.h>
#include <lib/sdt_task.h>

#include <lib/arena.h>
#include <lib/cpumask.h>
#include <lib/topology.h>
#include <lib/rbtree.h>
#include <lib/atq.h>

/*
 * "System-call" based API for arenas.
 */

struct task_ctx;

/*
 * A NULL arena pointer aliases the arena's first page at access time and a
 * stray NULL dereference would silently read or corrupt live data. Keep the
 * front of the arena unallocated so such accesses fault and get reported on the
 * program's BPF stderr stream instead. The guard must exceed the largest single
 * arena object so that indexing into one from NULL stays inside it. Negative
 * offsets off NULL wrap to the top of the window, which cannot be guarded the
 * same way as libbpf places the __arena globals there.
 */
enum {
	NULL_GUARD_PAGES	= 8192,	/* 32MB with 4k pages */
};

/*
 * bpf_arena_reserve_pages() fails with -EBUSY both when it can't take the arena
 * lock and when part of the range is already allocated. Retry once for the
 * former. If that fails too, reserve the pages one at a time and report how
 * many were busy, which tells the two apart. The scheduler fails to start
 * either way.
 */
/* the busy page tally, global so that the verifier doesn't track it per page */
static u32 null_guard_nr_busy, null_guard_first_busy, null_guard_last_busy;

static __always_inline int null_guard_reserve(void)
{
	int ret;
	u32 i;

	ret = bpf_arena_reserve_pages(&arena, NULL, NULL_GUARD_PAGES);
	if (!ret)
		return 0;

	ret = bpf_arena_reserve_pages(&arena, NULL, NULL_GUARD_PAGES);
	if (!ret) {
		bpf_printk("NULL guard: reserving pages [0, %u) succeeded on retry",
			   NULL_GUARD_PAGES);
		return 0;
	}

	bpf_for(i, 0, NULL_GUARD_PAGES) {
		void __arena *page = (void __arena *)((u64)i * PAGE_SIZE);

		if (!bpf_arena_reserve_pages(&arena, page, 1))
			continue;
		if (!null_guard_nr_busy)
			null_guard_first_busy = i;
		null_guard_last_busy = i;
		null_guard_nr_busy++;
	}

	bpf_printk("NULL guard: reserving pages [0, %u) failed with %d, %u busy in [%u, %u]",
		   NULL_GUARD_PAGES, ret, null_guard_nr_busy, null_guard_first_busy,
		   null_guard_last_busy);
	return ret;
}

SEC("syscall")
int arena_init(struct arena_init_args *args)
{
	int ret;

	args->failed_step = ARENA_INIT_DONE;

	/*
	 * On kernels without full-range LDIMM64 offset support, libbpf places
	 * the __arena globals at the bottom of the arena instead of the top and
	 * the guard region is occupied from the get-go. The guard cannot work
	 * there, skip it. qnodes is in the __arena globals, test its placement.
	 */
	if (bpf_ksym_exists(bpf_arena_reserve_pages) &&
	    (u32)(u64)qnodes >= NULL_GUARD_PAGES * PAGE_SIZE) {
		ret = null_guard_reserve();
		if (ret) {
			args->failed_step = ARENA_INIT_NULL_GUARD;
			return ret;
		}
	}

	ret = scx_static_init(args->static_pages);
	if (ret) {
		args->failed_step = ARENA_INIT_STATIC;
		return ret;
	}

	if (nr_cpu_ids == NR_CPU_IDS_UNINIT) {
		bpf_printk("uninitialized nr_cpu_ids variable");
		args->failed_step = ARENA_INIT_NR_CPU_IDS;
		return -ENODEV;
	}

	/* How many types to store all CPU IDs? */
	ret = scx_bitmap_init(div_round_up(nr_cpu_ids, 8));
	if (ret) {
		bpf_printk("scx_bitmap_init failed with %d", ret);
		args->failed_step = ARENA_INIT_BITMAP;
		return ret;
	}

	ret = cmask_distribute_init(&arena);
	if (ret) {
		bpf_printk("cmask_distribute_init failed with %d", ret);
		args->failed_step = ARENA_INIT_CMASK;
		return ret;
	}

	ret = scx_task_init(args->task_ctx_size, args->task_ctx_align);
	if (ret) {
		bpf_printk("scx_task_init failed with %d", ret);
		args->failed_step = ARENA_INIT_TASK;
		return ret;
	}

	ret = scx_rb_init();
	if (ret) {
		bpf_printk("scx_rb_init failed with %d", ret);
		args->failed_step = ARENA_INIT_RB;
		return ret;
	}

	ret = scx_atq_init();
	if (ret) {
		bpf_printk("scx_atq_init failed with %d", ret);
		args->failed_step = ARENA_INIT_ATQ;
		return ret;
	}

	return 0;
}

SEC("syscall")
int arena_alloc_mask(struct arena_alloc_mask_args *args)
{
	scx_bitmap_t bitmap;

	bitmap = scx_bitmap_alloc();
	if (!bitmap)
		return -ENOMEM;

	args->bitmap = (u64)&bitmap->bits;

	return 0;
}

SEC("syscall")
int arena_topology_init(struct arena_topology_init_args *args)
{
	/*
	 * Variable-offset access into a SEC("syscall") context pointer is
	 * disallowed by the BPF verifier. Access each element with a constant
	 * index to avoid the restriction.
	 */
	_Static_assert(TOPO_MAX_LEVEL == 5, "unroll below must match TOPO_MAX_LEVEL");
	topo_max_children[0] = args->max_children[0];
	topo_max_children[1] = args->max_children[1];
	topo_max_children[2] = args->max_children[2];
	topo_max_children[3] = args->max_children[3];
	topo_max_children[4] = args->max_children[4];

	return 0;
}

SEC("syscall")
int arena_topology_node_init(struct arena_topology_node_init_args *args)
{
	scx_bitmap_t bitmap = (scx_bitmap_t)container_of(args->bitmap, struct scx_bitmap, bits);
	int ret;

	ret = topo_init(bitmap, args->data_size, args->id);
	if (ret)
		return ret;

	return 0;
}

SEC("syscall")
int arena_topology_print(void)
{
	scx_arena_subprog_init();

	topo_print();

	return 0;
}
