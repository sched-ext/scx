/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2025 Meta Platforms, Inc. and affiliates.
 */
#include <scx/common.bpf.h>
#include <bpf/bpf_helpers.h>

#include <lib/arena_map.h>

#include <alloc/asan.h>
#include <alloc/common.h>

/* How many pages do we reserve at the beginning of the arena segment? */
#define RESERVE_ALLOC (8)

SEC("syscall")
int arena_base(struct arena_base_args *args)
{
	args->arena_base = (void __arena *)((struct bpf_arena *)(&arena))->user_vm_start;

	return 0;
}

SEC("syscall")
int arena_alloc_reserve(void)
{
	return bpf_arena_reserve_pages(&arena, NULL, RESERVE_ALLOC);
}

__weak
int scx_fls(__u64 word)
{
	unsigned int num = 0;

	if (word & 0xffffffff00000000ULL) {
		num += 32;
		word >>= 32;
	}

	if (word & 0xffff0000) {
		num += 16;
		word >>= 16;
	}

	if (word & 0xff00) {
		num += 8;
		word >>= 8;
	}

	if (word & 0xf0) {
		num += 4;
		word >>= 4;
	}

	if (word & 0xc) {
		num += 2;
		word >>= 2;
	}

	if (word & 0x2) {
		num += 1;
	}

	return num;
}
