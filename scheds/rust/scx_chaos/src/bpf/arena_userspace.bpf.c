/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2025 Meta Platforms, Inc. and affiliates.
 *
 * Userspace-driven arena page allocation. scx_chaos hands these two programs
 * to scx_userspace_arena::alloc, which runs its heap allocator in userspace
 * over arena pages grabbed through them. Nothing else in the tree uses them,
 * so they live here rather than in lib/.
 */

#include <libarena/common.h>
#include <scx/common.bpf.h>
#include <scx/arena_userspace_interrop.bpf.h>

/**
 * scx_userspace_arena_alloc_pages - BPF program to enable allocating arena pages
 * explicitly from userspace.
 *
 * @ctx->sz: Size to allocate. Any positive number is a valid request.
 * @ctx->ret: Address of the allocated pages. NULL if unable to allocate.
 */
SEC("syscall")
int scx_userspace_arena_alloc_pages(struct scx_userspace_arena_alloc_pages_args *ctx)
{
	u32 pages = (ctx->sz + PAGE_SIZE - 1) / PAGE_SIZE;
	ctx->sz = pages * PAGE_SIZE;

	ctx->ret = bpf_arena_alloc_pages(&arena, NULL, pages, NUMA_NO_NODE, 0);
	return 0;
}

/**
 * scx_userspace_arena_free_pages - BPF program to enable freeing arena pages
 * explicitly from userspace.
 *
 * @ctx->addr: Address of the allocated pages. Should have been allocated by
 *	`scx_userspace_arena_alloc_pages`.
 * @ctx->sz: Size to free. Should be the same number passed to
 *	`scx_userspace_arena_alloc_pages`.
 */
SEC("syscall")
int scx_userspace_arena_free_pages(struct scx_userspace_arena_free_pages_args *ctx)
{
	u32 pages = (ctx->sz + PAGE_SIZE - 1) / PAGE_SIZE;

	bpf_arena_free_pages(&arena, ctx->addr, pages);
	return 0;
}
