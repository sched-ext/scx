/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2025 Meta Platforms, Inc. and affiliates.
 * Copyright (c) 2025 Emil Tsalapatis <etsal@meta.com>
 */

#include <alloc/common.h>

#include <alloc/asan.h>
#include <alloc/buddy.h>

#include "selftest.h"

private(ST_BUDDY) struct buddy st_buddy;
static u64 __arena st_buddy_lock;

struct segarr_entry {
	u8 __arena *block;
	size_t sz;
	u8 poison;
};

typedef struct segarr_entry __arena segarr_entry_t;

#define SEGARRLEN (512)
static struct segarr_entry __arena segarr[SEGARRLEN];
size_t __arena sizes[] = { 3, 17, 1025, 129, 16350, 333, 9, 517, 2099 };

static int buddy_selftest_create()
{
	const int iters = 10;
	int ret, i;

	for (i = 0; i < iters && can_loop; i++) {
		ret = buddy_init(
			&st_buddy, (arena_spinlock_t __arena *)&st_buddy_lock);
		if (ret)
			return ret;

		ret = buddy_destroy(&st_buddy);
		if (ret)
			return ret;
	}

	return 0;
}

static int buddy_selftest_alloc()
{
	void __arena *mem;
	int ret, i;

	for (i = 0; i < 8 && can_loop; i++) {
		ret = buddy_init(
			&st_buddy, (arena_spinlock_t __arena *)&st_buddy_lock);
		if (ret)
			return ret;

		mem = buddy_alloc(&st_buddy, sizes[i]);
		if (!mem) {
			buddy_destroy(&st_buddy);
			return -ENOMEM;
		}

		buddy_destroy(&st_buddy);
	}

	return 0;
}

static int buddy_selftest_alloc_free()
{
	size_t sizes[] = { 3, 17, 64, 129, 256, 333, 512, 517 };
	const int iters = 800;
	void __arena *mem;
	int ret, i;

	ret = buddy_init(&st_buddy,
			     (arena_spinlock_t __arena *)&st_buddy_lock);
	if (ret)
		return ret;

	bpf_for(i, 0, iters) {
		mem = buddy_alloc(&st_buddy, sizes[(i * 5) % 8]);
		if (!mem) {
			buddy_destroy(&st_buddy);
			return -ENOMEM;
		}

		buddy_free(&st_buddy, mem);
	}

	buddy_destroy(&st_buddy);

	return 0;
}

static int buddy_selftest_alloc_multiple()
{
	int ret, j;
	u32 i, idx;
	u8 __arena *mem;
	size_t sz;
	u8 poison;

	ret = buddy_init(&st_buddy,
			     (arena_spinlock_t __arena *)&st_buddy_lock);
	if (ret)
		return ret;

	/*
	 * Cycle through each size, allocating an entry in the
	 * segarr. Continue for SEGARRLEN iterations. For every
	 * allocation write down the size, use the current index
	 * as a poison value, and log it with the pointer in the
	 * segarr entry. Use the poison value to poison the entire
	 * allocated memory according to the size given.
	 */
	idx = 0;
	bpf_for(i, 0, SEGARRLEN) {
		sz = sizes[idx % 9];
		poison = (u8)i;

		mem = buddy_alloc(&st_buddy, sz);
		if (!mem) {
			buddy_destroy(&st_buddy);
			bpf_printk("%s:%d", __func__, __LINE__);
			return -ENOMEM;
		}

		segarr[i].block = mem;
		segarr[i].sz = sz;
		segarr[i].poison = poison;

		bpf_for(j, 0, sz) {
			mem[j] = poison;
			if (mem[j] != poison) {
				buddy_destroy(&st_buddy);
				return -EINVAL;
			}
		}
	}

	/*
	 * For SEGARRLEN iterations, go to (i * 17) % SEGARRLEN, and free
	 * the block pointed to. Before freeing, check all bytes have the
	 * poisoned value corresponding to the element. If any values
	 * are unexpected, return an error.
	 */
	bpf_for(i, 10, SEGARRLEN) {
		idx = (i * 17) % SEGARRLEN;

		mem = segarr[idx].block;
		sz = segarr[idx].sz;
		poison = segarr[idx].poison;

		bpf_for(j, 0, sz) {
			if (mem[j] != poison) {
				buddy_destroy(&st_buddy);
				bpf_printk("%s:%d %lx %u vs %u", __func__,
					   __LINE__, &mem[j], mem[j], poison);
				return -EINVAL;
			}
		}

		buddy_free(&st_buddy, mem);
	}

	buddy_destroy(&st_buddy);

	return 0;
}

static int buddy_selftest_alignment()
{
	size_t sizes[] = { 1, 3, 7, 8, 9, 15, 16, 17, 31,
			   32, 64, 100, 128, 255, 256, 512, 1000 };
	void __arena *ptrs[17];
	int ret, i;

	ret = buddy_init(&st_buddy,
			     (arena_spinlock_t __arena *)&st_buddy_lock);
	if (ret)
		return ret;

	/* Allocate various sizes and check alignment */
	bpf_for(i, 0, 17) {
		ptrs[i] = buddy_alloc(&st_buddy, sizes[i]);
		if (!ptrs[i]) {
			bpf_printk("alignment test: alloc failed for size %lu",
				   sizes[i]);
			buddy_destroy(&st_buddy);
			return -ENOMEM;
		}

		/* Check 8-byte alignment */
		if ((u64)ptrs[i] & 0x7) {
			bpf_printk(
				"alignment test: ptr %llx not 8-byte aligned (size %lu)",
				(u64)ptrs[i], sizes[i]);
			buddy_destroy(&st_buddy);
			return -EINVAL;
		}
	}

	/* Free all allocations */
	bpf_for(i, 0, 17) {
		buddy_free(&st_buddy, ptrs[i]);
	}

	buddy_destroy(&st_buddy);

	return 0;
}

#define BUDDY_ALLOC_SELFTEST(suffix) ALLOC_SELFTEST(buddy_selftest_##suffix)

__weak int buddy_selftest(void)
{
	BUDDY_ALLOC_SELFTEST(create);
	BUDDY_ALLOC_SELFTEST(alloc);
	BUDDY_ALLOC_SELFTEST(alloc_free);
	BUDDY_ALLOC_SELFTEST(alloc_multiple);
	BUDDY_ALLOC_SELFTEST(alignment);

	return 0;
}
