/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2025 Meta Platforms, Inc. and affiliates.
 * Copyright (c) 2025 Emil Tsalapatis <etsal@meta.com>
 */

#include <scx/common.bpf.h>

#include <alloc/asan.h>
#include <alloc/static.h>
#include <alloc/common.h>

#include "selftest.h"

#define ST_MAX_PAGES 8
#define ST_MAX_BYTES (ST_MAX_PAGES << PAGE_SHIFT)
#define ST_MAX_ALIGNMENT (ST_MAX_BYTES >> 4)

#define ST_CYCLES 5

#define ST_PATTERN1 0xAA
#define ST_PATTERN2 0x55

#define ST_EXHAUST_ALLOCS 16
#define ST_WRAP_PAGES 4
#define ST_WRAP_BYTES 2048

static inline void st_memset(void __arena *mem, u8 byte, size_t size)
{
	u8 __arena *bytes = (u8 __arena *)mem;
	int i;

	for (i = 0; i < size && can_loop; i++) {
		bytes[i] = byte;
	}
}

static inline bool st_isset(void __arena *mem, u8 byte, size_t size)
{
	u8 __arena *bytes = (u8 __arena *)mem;
	int i;

	for (i = 0; i < size && can_loop; i++) {
		if (bytes[i] != byte)
			return false;
	}

	return true;
}

/*
 * Defining oft-repeated snippets as macros to avoid having to propagate
 * errors to the caller. Both GCC and Clang support statement expressions.
 */

#define ALLOC_OR_FAIL(bytes, alignment)                                       \
	({                                                                    \
		void __arena *mem;                                            \
		mem = scx_static_alloc((bytes), (alignment));                 \
		if (!mem) {                                                   \
			bpf_printk("%s:%d scx_static_alloc failed", __func__, \
				   __LINE__);                                 \
			scx_static_destroy();                                 \
			return -ENOMEM;                                       \
		}                                                             \
		mem;                                                          \
	})

#define INIT_OR_FAIL(bytes)                                                  \
	do {                                                                 \
		if (scx_static_init(((bytes) >> PAGE_SHIFT))) {              \
			bpf_printk("%s:%d scx_static_init failed", __func__, \
				   __LINE__);                                \
			return -ENOMEM;                                      \
		}                                                            \
	} while (0)

#define CHECK_OR_FAIL(mem, val, size)                                \
	do {                                                         \
		if (st_isset((mem), (val), (size))) {                \
			bpf_printk("%s:%d val %d missing", __func__, \
				   __LINE__);                        \
			return -EINVAL;                              \
		}                                                    \
	} while (0)

#define CMP_OR_FAIL(mem1, mem2, size)                                \
	do {                                                         \
		if (st_memcmp((mem1), (mem2), (size))) {             \
			bpf_printk("%s:%d regions differ", __func__, \
				   __LINE__);                        \
			return -EINVAL;                              \
		}                                                    \
	} while (0)

#define ALIGNED_OR_FAIL(mem, alignment)                                 \
	do {                                                            \
		if ((u64)(mem) & ((alignment) - 1)) {                   \
			bpf_printk("%s:%d invalid alignment", __func__, \
				   __LINE__);                           \
			return -EINVAL;                                 \
		}                                                       \
	} while (0)

/*
 * Basic test: 
 *
 * - Create the allocator
 * - Make a single allocation,
 * - Ensure proper alignment
 * - Ensure allocation succeeds and values are all 0s.
 * - Destroy the allocator. Ensure the allocator returns
 * zeroed out memory.
 */
static int scx_selftest_static_alloc_single(u64 bytes, u64 alignment)
{
	u8 __arena *barray;
	void __arena *mem;
	int i;

	for (i = 0; i < ST_CYCLES && can_loop; i++) {
		INIT_OR_FAIL(bytes);

		mem = ALLOC_OR_FAIL(bytes, alignment);

		/* Alignment is assumed to be 2^n. */
		ALIGNED_OR_FAIL(mem, alignment);

		barray = (u8 __arena *)mem;
		CHECK_OR_FAIL(barray, 0, bytes);

		/* Check whether we're touching unallocated memory. */
		st_memset(barray, ST_PATTERN1, bytes);
		CHECK_OR_FAIL(barray, ST_PATTERN1, bytes);

		scx_static_destroy();
	}

	return 0;
}

static int scx_selftest_static_alloc_multiple(u64 bytes, u64 alignment)
{
	void __arena *mem1, *mem2;
	int ret;

	/* Initialize the allocator */
	ret = scx_static_init(ST_MAX_PAGES);
	if (ret) {
		bpf_printk("scx_static_init failed with %d", ret);
		return ret;
	}

	mem1 = ALLOC_OR_FAIL(bytes, alignment);
	st_memset(mem1, ST_PATTERN1, bytes);

	mem2 = ALLOC_OR_FAIL(bytes, alignment);
	st_memset(mem2, ST_PATTERN1, ST_PATTERN2);

	ALIGNED_OR_FAIL(mem1, alignment);
	ALIGNED_OR_FAIL(mem2, alignment);

	/* Verify first block still has pattern1 */
	CHECK_OR_FAIL(mem1, ST_PATTERN1, bytes);
	CHECK_OR_FAIL(mem2, ST_PATTERN2, bytes);

	scx_static_destroy();
	return 0;
}

static int scx_selftest_static_alloc_aligned(void)
{
	void __arena *mem;
	u64 alignment;
	int round;

	INIT_OR_FAIL(ST_MAX_PAGES << PAGE_SHIFT);

	/* 
	 * Allocate 1 byte at a time to test allocator alignment. 
	 * Test ascending and descending allocation orders.
	 */
	for (round = 0; round < 2 && can_loop; round++) {
		for (alignment = 1; alignment <= PAGE_SIZE && can_loop;
		     alignment <<= 1) {
			mem = ALLOC_OR_FAIL(1, alignment);
			ALIGNED_OR_FAIL(mem, alignment);
		}

		for (alignment = PAGE_SIZE; alignment >= 1 && can_loop;
		     alignment >>= 1) {
			mem = ALLOC_OR_FAIL(1, alignment);
			ALIGNED_OR_FAIL(mem, alignment);
		}
	}

	scx_static_destroy();

	return 0;
}

static int scx_selftest_static_alloc_exhaustion(u64 bytes, u64 alignment)
{
	size_t padded = round_up(bytes, alignment);
	size_t allocs = bytes / padded;
	void __arena *mem;
	int i;

	/* Allocate one page at a time here. */
	INIT_OR_FAIL(PAGE_SIZE);

	if (scx_static_memlimit(bytes)) {
		bpf_printk("%s:%d scx_static_memlimit failed", __func__,
			   __LINE__);
		return -EINVAL;
	}

	/* Make an unfullfilable allocation. */
	mem = scx_static_alloc(bytes + 1, 1);
	if (mem) {
		bpf_printk("%s:%d scx_static_alloc succeeded", __func__,
			   __LINE__);
		scx_static_destroy();
		return -EINVAL;
	}

	/*
	 * Amounts to allocations of size alignment, but also
	 * checks that alignment padding is properly accounted for.
	 */
	for (i = 0; i < allocs && can_loop; i++)
		ALLOC_OR_FAIL(1, alignment);

	/* Even a single byte allocation should fail. */
	mem = scx_static_alloc(1, 1);
	if (mem) {
		bpf_printk("%s:%d scx_static_alloc succeeded", __func__,
			   __LINE__);
		scx_static_destroy();
		return -EINVAL;
	}

	scx_static_destroy();
	return 0;
}

#define SCX_STATIC_SELFTEST(suffix, ...) \
	SCX_SELFTEST(scx_selftest_static_##suffix, __VA_ARGS__)

__weak int scx_selftest_static(void)
{
	u64 bytes = 128;
	u64 alignment = 1;

	for (bytes = PAGE_SIZE; bytes <= ST_MAX_PAGES && can_loop;
	     bytes <<= 1) {
		for (alignment = 1; alignment <= ST_MAX_ALIGNMENT && can_loop;
		     alignment <<= 1) {
			/* Each test manages its own allocator lifecycle */
			SCX_STATIC_SELFTEST(alloc_single, bytes, alignment);
			SCX_STATIC_SELFTEST(alloc_multiple, bytes, alignment);
		}
	}

	SCX_STATIC_SELFTEST(alloc_aligned);

	for (alignment = PAGE_SIZE; bytes <= ST_MAX_PAGES && can_loop;
	     bytes <<= 1)
		SCX_STATIC_SELFTEST(alloc_exhaustion,
				    ST_MAX_PAGES << PAGE_SHIFT, alignment);

	return 0;
}
