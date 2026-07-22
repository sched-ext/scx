/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2025 Meta Platforms, Inc. and affiliates.
 */
#include <libarena/common.h>
#include <scx/common.bpf.h>
#include <lib/sdt_task.h>

#include <lib/arena.h>
#include <lib/percpu.h>
#include <lib/cpumask.h>
#include <lib/topology.h>

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

SEC("syscall")
int arena_init(struct arena_init_args *args)
{
	int ret;

	/*
	 * On kernels without full-range LDIMM64 offset support, libbpf places
	 * the __arena globals at the bottom of the arena instead of the top and
	 * the guard region is occupied from the get-go. The guard cannot work
	 * there, skip it. qnodes is in the __arena globals, test its placement.
	 */
	if (bpf_ksym_exists(bpf_arena_reserve_pages) &&
	    (u32)(u64)qnodes >= NULL_GUARD_PAGES * PAGE_SIZE) {
		ret = bpf_arena_reserve_pages(&arena, NULL, NULL_GUARD_PAGES);
		if (ret) {
			bpf_printk("NULL guard: reserving pages [0, %u) failed with %d, "
				   "the arena front was allocated before arena_init()",
				   NULL_GUARD_PAGES, ret);
			return ret;
		}
	}

	if (nr_cpu_ids == NR_CPU_IDS_UNINIT) {
		bpf_printk("uninitialized nr_cpu_ids variable");
		return -ENODEV;
	}

	ret = scx_percpu_storage_init();
	if (ret) {
		bpf_printk("scx_percpu_storage_init failed with %d", ret);
		return ret;
	}

	ret = scx_task_init(args->task_ctx_size, args->task_ctx_align);
	if (ret) {
		bpf_printk("scx_task_init failed with %d", ret);
		return ret;
	}

	return 0;
}

SEC("syscall")
int arena_alloc_mask(struct arena_alloc_mask_args *args)
{
	struct arena_bitmap __arena *bitmap;

	bitmap = bmp_alloc(SCX_BITMAP_NR_BITS);
	if (!bitmap)
		return -ENOMEM;

	args->bitmap = (u64)bitmap;

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
	struct arena_bitmap __arena *bitmap = (struct arena_bitmap __arena *)args->bitmap;
	int ret;

	ret = topo_init(bitmap, args->data_size, args->id);
	if (ret)
		return ret;

	return 0;
}

SEC("syscall")
int arena_topology_print(void)
{
	arena_subprog_init();

	topo_print();

	return 0;
}
