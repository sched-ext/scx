/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2025 Meta Platforms, Inc. and affiliates.
 */
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

SEC("syscall")
int arena_init(struct arena_init_args *args)
{
	int ret;

	ret = scx_static_init(args->static_pages);
	if (ret)
		return ret;

	/* How many types to store all CPU IDs? */
	ret = scx_bitmap_init(div_round_up(nr_cpu_ids, 8));
	if (ret)
		return ret;

	ret = scx_percpu_storage_init();
	if (ret)
		return ret;

	ret = scx_task_init(args->task_ctx_size);
	if (ret)
		return ret;

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
int arena_topology_node_init(struct arena_topology_node_init_args *args)
{
	scx_bitmap_t bitmap = (scx_bitmap_t)container_of(args->bitmap, struct scx_bitmap, bits);
	int ret;

	ret = topo_init(bitmap, args->data_size);
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

