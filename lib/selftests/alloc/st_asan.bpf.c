/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2025 Meta Platforms, Inc. and affiliates.
 * Copyright (c) 2025 Emil Tsalapatis <etsal@meta.com>
 */

#include <scx/common.bpf.h>

#include <alloc/asan.h>
#include <alloc/buddy.h>
#include <alloc/stack.h>
#include <alloc/static.h>
#include <alloc/common.h>

#include "selftest.h"

#define ST_PAGES 64

#define ASAN_MAP_STATE(addr)                                                 \
	do {                                                                 \
		bpf_printk("%s:%d ASAN %lx -> (val: %x gran: %x set: [%s])", \
			   __func__, __LINE__, addr,                         \
			   asan_shadow_value((addr)), ASAN_GRANULE(addr),    \
			   asan_shadow_set((addr)) ? "yes" : "no");          \
	} while (0)

/*
 * Emit an error and force the current function to exit if the ASAN
 * violation state is unexpected. Reset the violation state after.
 */
#define ASAN_VALIDATE_ADDR(cond, addr)                                       \
	do {                                                                 \
		asm volatile("" ::: "memory");                               \
		if ((asan_violated != 0) != (cond)) {                        \
			bpf_printk("%s:%d ASAN asan_violated %lx", __func__, \
				   __LINE__, (u64)asan_violated);            \
			ASAN_MAP_STATE((addr));                              \
			return -EINVAL;                                      \
		}                                                            \
		asan_violated = 0;                                           \
	} while (0)

#define ASAN_VALIDATE()                                                 \
	do {                                                            \
		if ((asan_violated)) {                                  \
			bpf_printk("%s:%d Found ASAN violation at %lx", \
				   __func__, __LINE__, asan_violated);  \
			return -EINVAL;                                 \
		}                                                       \
	} while (0)

struct blob {
	volatile u8 mem[59];
	u8 oob;
};

int asan_test_static_blob_one(void)
{
	volatile struct blob __arena *blob;
	const size_t alignment = 1;

	blob = scx_static_alloc(sizeof(blob) - 1, alignment);
	if (!blob)
		return -ENOMEM;

	blob->mem[0] = 0xba;
	ASAN_VALIDATE_ADDR(false, &blob->mem[0]);

	blob->oob = 0;
	ASAN_VALIDATE_ADDR(true, &blob->oob);

	blob = (volatile struct blob __arena *)&blob->oob;
	blob->mem[0] = 0xba;
	ASAN_VALIDATE_ADDR(true, &blob->mem[0]);

	blob->oob = 4;
	ASAN_VALIDATE_ADDR(true, &blob->oob);

	/*
	 * Go even further, cast the OOB variable into
	 * another struct blob and access its own oob.
	 */
	blob = (volatile struct blob __arena *)&blob->oob;
	blob->oob = 5;
	ASAN_VALIDATE_ADDR(true, &blob->oob);

	return 0;
}

int asan_test_static_blob(void)
{
	const int iters = 20;
	int ret, i;

	ret = scx_static_init(ST_PAGES);
	if (ret) {
		bpf_printk("scx_static_init failed with %d", ret);
		return ret;
	}

	for (i = 0; i < iters && can_loop; i++) {
		ret = asan_test_static_blob_one();
		if (ret) {
			bpf_printk("%s:%d Failed on iteration %d", __func__,
				   __LINE__, i);
			return ret;
		}
	}

	scx_static_destroy();

	ASAN_VALIDATE();

	return 0;
}

int asan_test_static_array_one(void)
{
	size_t bytes = 37;
	size_t overrun = 13;
	size_t alignment = 1;
	char __arena *mem;
	int i;

	mem = scx_static_alloc(sizeof(*mem) * bytes, alignment);
	if (!mem)
		return -ENOMEM;

	for (i = 0; i < bytes + overrun && can_loop; i++) {
		mem[i] = 0xba;
		ASAN_VALIDATE_ADDR(i >= bytes, &mem[i]);
	}

	ASAN_VALIDATE();

	return 0;
}

int asan_test_static_array(void)
{
	const size_t iters = 20;
	int ret, i;

	ret = scx_static_init(ST_PAGES);
	if (ret) {
		bpf_printk("scx_static_init failed with %d", ret);
		return ret;
	}

	for (i = 0; i < iters && can_loop; i++) {
		ret = asan_test_static_array_one();
		if (ret) {
			bpf_printk("%s:%d Failed on iteration %d", __func__,
				   __LINE__, i);
			return ret;
		}
	}

	scx_static_destroy();

	return 0;
}

int asan_test_static_all(void)
{
	const int iters = 50;
	int ret, i;

	ret = scx_static_init(ST_PAGES);
	if (ret) {
		bpf_printk("scx_static_init failed with %d", ret);
		return ret;
	}

	for (i = 0; i < iters && can_loop; i++) {
		ret = asan_test_static_array_one();
		if (ret) {
			bpf_printk("%s:%d Failed on iteration %d", __func__,
				   __LINE__, i);
			return ret;
		}

		ret = asan_test_static_blob_one();
		if (ret) {
			bpf_printk("%s:%d Failed on iteration %d", __func__,
				   __LINE__, i);
			return ret;
		}
	}

	scx_static_destroy();

	return 0;
}

#define STACK_PAGES_PER_ALLOC (4)
#define STACK_ALLOCS (4)

/* 
 * Keep this test-related array in BSS to avoid
 * overly burdening the function stack.
 */
u64 __arena stk_blks[STACK_ALLOCS];

/*
 * Spinlock used by the stack allocator.
 */
private(ST_STACK) struct scx_stk st_stack;
u64 __arena st_asan_lock;

static __maybe_unused void stk_blks_dump(void)
{
	int i;

	for (i = 0; i < STACK_ALLOCS && can_loop; i++)
		bpf_printk("[%d] 0x%lx", i, stk_blks[i]);
}

struct qsort_limits {
	int lo;
	int hi;
};

__always_inline void swap(unsigned int i, unsigned int j)
{
	u64 tmp;

	tmp = stk_blks[i];
	stk_blks[i] = stk_blks[j];
	stk_blks[j] = tmp;
}

__weak int qsort_partition(unsigned int lo, unsigned hi)
{
	unsigned int i;
	u64 pivotval;
	int pivot;

	if (lo >= STACK_ALLOCS || hi >= STACK_ALLOCS) {
		bpf_printk("%s:%d invalid lo/hi indices %d/%d", __func__,
			   __LINE__, lo, hi);
		return 0;
	}

	pivotval = stk_blks[hi];
	pivot = lo;

	for (i = lo; i < hi && can_loop; i++) {
		if (stk_blks[i] > pivotval)
			continue;

		swap(i, pivot);
		pivot += 1;
	}

	swap(pivot, hi);

	return pivot;
}

__weak int qsort_stack_blocks(void)
{
	struct qsort_limits stack[STACK_ALLOCS];
	struct qsort_limits limits;
	int stackind = 0;
	int pivot;

	limits = (struct qsort_limits){ 0, STACK_ALLOCS - 1 };
	stack[stackind++] = limits;

	while (stackind > 0 && can_loop) {
		if (stackind <= 0 || stackind > STACK_ALLOCS) {
			bpf_printk("%s:%d invalid stack index %d", __func__,
				   __LINE__, stackind);
			return 0;
		}

		limits = stack[--stackind];
		if (limits.lo >= limits.hi)
			continue;

		pivot = qsort_partition(limits.lo, limits.hi);
		stack[stackind++] = (struct qsort_limits){
			.lo = limits.lo,
			.hi = pivot - 1,
		};

		if (stackind <= 0 || stackind >= STACK_ALLOCS) {
			bpf_printk("%s:%d invalid stack index", __func__,
				   __LINE__);
			return 0;
		}

		stack[stackind++] = (struct qsort_limits){
			.lo = pivot + 1,
			.hi = limits.hi,
		};
	}

	return 0;
}

int asan_test_stack_uaf_oob_single(u8 __arena __arg_arena *alloced,
				   u8 __arena __arg_arena *freed)
{
	const size_t overshoot = 5;
	int i;

	/* Use after free check. */
	scx_stk_free(&st_stack, freed);

	bpf_for(i, 0, PAGE_SIZE) {
		freed[i] = 0xba;
		ASAN_VALIDATE_ADDR(true, &freed[i]);
	}

	/* 
	 * Out of bounds check. Assuming the blocks before were
	 * allocated consecutively, past the end of the block
	 * the memory is guaranteed to be freed.
	 */
	bpf_for(i, 0, PAGE_SIZE + overshoot) {
		alloced[i] = 0xba;
		ASAN_VALIDATE_ADDR(i >= PAGE_SIZE, &alloced[i]);
	}

	return 0;
}

static int asan_sort_stack_blocks()
{
	int i;

	qsort_stack_blocks();

	if (!stk_blks[0]) {
		bpf_printk("NULL stack block pointer");
		return -EINVAL;
	}

	for (i = 1; i < STACK_ALLOCS; i++) {
		if (!stk_blks[i]) {
			bpf_printk("missing block");
			return -EINVAL;
		}

		if (stk_blks[i] != stk_blks[i - 1] + PAGE_SIZE) {
			bpf_printk("allocations not consecutive");
			return -EINVAL;
		}
	}

	return 0;
}

__weak int asan_test_stack_uaf_oob(void)
{
	u64 base = (u64)(-1);
	const u64 alloc_size = 4096;
	u64 block;
	int ret, i;

	/* Set the stack to support 4KiB allocations. */
	ret = scx_stk_init(&st_stack, (arena_spinlock_t __arena *)&st_asan_lock,
			   alloc_size, STACK_PAGES_PER_ALLOC);
	if (ret) {
		bpf_printk("scx_stk_init failed with %d", ret);
		return ret;
	}

	bpf_for(i, 0, STACK_ALLOCS) {
		block = (u64)scx_stk_alloc(&st_stack);
		if (!block) {
			bpf_printk("allocation %d failed", i);
			return -ENOMEM;
		}

		stk_blks[i] = block;
		base = block < base ? block : base;
	}

	ret = asan_sort_stack_blocks();
	if (ret)
		return ret;

	for (i = 0; i < STACK_ALLOCS && can_loop; i += 2) {
		if (i + 1 >= STACK_ALLOCS)
			break;

		if (stk_blks[i] + alloc_size != stk_blks[i + 1]) {
			bpf_printk("Stack allocations not consecutive");
			return -EINVAL;
		}

		ret = asan_test_stack_uaf_oob_single(
			(u8 __arena *)stk_blks[i],
			(u8 __arena *)stk_blks[i + 1]);
		if (ret)
			return ret;
	}

	scx_stk_destroy(&st_stack);

	return 0;
}

int asan_test_stack(void)
{
	int ret;

	ret = asan_test_stack_uaf_oob();
	if (ret) {
		bpf_printk("%s:%d test failed", __func__, __LINE__);
		return ret;
	}

	return 0;
}

int asan_test_static(void)
{
	int ret;

	ret = asan_test_static_blob();
	if (ret) {
		bpf_printk("%s:%d test failed", __func__, __LINE__);
		return ret;
	}

	ret = asan_test_static_array();
	if (ret) {
		bpf_printk("%s:%d test failed", __func__, __LINE__);
		return ret;
	}

	ret = asan_test_static_all();
	if (ret) {
		bpf_printk("%s:%d test failed", __func__, __LINE__);
		return ret;
	}

	return 0;
}

private(ST_BUDDY) struct scx_buddy st_buddy_asan;

__weak int asan_test_buddy_oob_single(size_t alloc_size)
{
	u8 __arena *mem;
	int i;

	ASAN_VALIDATE();

	mem = scx_buddy_alloc(&st_buddy_asan, alloc_size);
	if (!mem) {
		bpf_printk("scx_buddy_alloc failed for size %lu", alloc_size);
		return -ENOMEM;
	}

	ASAN_VALIDATE();

	bpf_for(i, 0, alloc_size) {
		mem[i] = 0xba;
		ASAN_VALIDATE_ADDR(false, &mem[i]);
	}

	mem[alloc_size] = 0xba;
	ASAN_VALIDATE_ADDR(true, &mem[alloc_size]);

	scx_buddy_free(&st_buddy_asan, mem);

	return 0;
}

__weak int asan_test_buddy_uaf_single(size_t alloc_size)
{
	u8 __arena *mem;
	int i;

	mem = scx_buddy_alloc(&st_buddy_asan, alloc_size);
	if (!mem) {
		bpf_printk("scx_buddy_alloc failed for size %lu", alloc_size);
		return -ENOMEM;
	}

	ASAN_VALIDATE();

	bpf_for(i, 0, alloc_size) {
		mem[i] = 0xba;
		ASAN_VALIDATE_ADDR(false, &mem[i]);
	}

	ASAN_VALIDATE();

	scx_buddy_free(&st_buddy_asan, mem);

	bpf_for(i, 0, alloc_size) {
		/* The header doesn't get poisoned. */
		if (SCX_BUDDY_HEADER_OFF <= i &&
		    i < SCX_BUDDY_HEADER_OFF + sizeof(struct scx_buddy_header))
			continue;

		mem[i] = 0xba;
		ASAN_VALIDATE_ADDR(true, &mem[i]);
	}

	return 0;
}

struct buddy_blob {
	volatile u8 mem[48];
	u8 oob;
};

__weak int asan_test_buddy_blob_single(void)
{
	volatile struct buddy_blob __arena *blob;
	const size_t alloc_size = sizeof(struct buddy_blob) - 1;

	blob = scx_buddy_alloc(&st_buddy_asan, alloc_size);
	if (!blob)
		return -ENOMEM;

	blob->mem[0] = 0xba;
	ASAN_VALIDATE_ADDR(false, &blob->mem[0]);

	blob->mem[47] = 0xba;
	ASAN_VALIDATE_ADDR(false, &blob->mem[47]);

	blob->oob = 0;
	ASAN_VALIDATE_ADDR(true, &blob->oob);

	scx_buddy_free(&st_buddy_asan, (void __arena *)blob);

	return 0;
}

__weak int asan_test_buddy_oob(void)
{
	size_t sizes[] = {
		7, 8, 17, 18, 64, 256, 317, 512, 1024,
	};
	int ret, i;

	ret = scx_buddy_init(&st_buddy_asan,
			     (arena_spinlock_t __arena *)&st_asan_lock);
	if (ret) {
		bpf_printk("scx_buddy_init failed with %d", ret);
		return ret;
	}

	bpf_for(i, 0, 7) {
		ret = asan_test_buddy_oob_single(sizes[i]);
		if (ret) {
			bpf_printk("%s:%d Failed for size %lu", __func__,
				   __LINE__, sizes[i]);
			scx_buddy_destroy(&st_buddy_asan);
			return ret;
		}
	}

	scx_buddy_destroy(&st_buddy_asan);

	ASAN_VALIDATE();

	return 0;
}

__weak int asan_test_buddy_uaf(void)
{
	size_t sizes[] = { 16, 32, 64, 128, 256, 512, 128, 1024, 16384 };
	int ret, i;

	ret = scx_buddy_init(&st_buddy_asan,
			     (arena_spinlock_t __arena *)&st_asan_lock);
	if (ret) {
		bpf_printk("scx_buddy_init failed with %d", ret);
		return ret;
	}

	bpf_for(i, 0, 7) {
		ret = asan_test_buddy_uaf_single(sizes[i]);
		if (ret) {
			bpf_printk("%s:%d Failed for size %lu", __func__,
				   __LINE__, sizes[i]);
			scx_buddy_destroy(&st_buddy_asan);
			return ret;
		}
	}

	scx_buddy_destroy(&st_buddy_asan);

	ASAN_VALIDATE();

	return 0;
}

__weak int asan_test_buddy_blob(void)
{
	const int iters = 10;
	int ret, i;

	ret = scx_buddy_init(&st_buddy_asan,
			     (arena_spinlock_t __arena *)&st_asan_lock);
	if (ret) {
		bpf_printk("scx_buddy_init failed with %d", ret);
		return ret;
	}

	for (i = 0; i < iters && can_loop; i++) {
		ret = asan_test_buddy_blob_single();
		if (ret) {
			bpf_printk("%s:%d Failed on iteration %d", __func__,
				   __LINE__, i);
			scx_buddy_destroy(&st_buddy_asan);
			return ret;
		}
	}

	scx_buddy_destroy(&st_buddy_asan);

	ASAN_VALIDATE();

	return 0;
}

int asan_test_buddy(void)
{
	int ret;

	ret = asan_test_buddy_oob();
	if (ret) {
		bpf_printk("%s:%d OOB test failed", __func__, __LINE__);
		return ret;
	}

	ret = asan_test_buddy_uaf();
	if (ret) {
		bpf_printk("%s:%d UAF test failed", __func__, __LINE__);
		return ret;
	}

	ret = asan_test_buddy_blob();
	if (ret) {
		bpf_printk("%s:%d blob test failed", __func__, __LINE__);
		return ret;
	}

	return 0;
}

SEC("syscall")
int asan_test(void)
{
	int ret;

	bpf_printk("ASAN tests starting...");

	ret = asan_test_static();
	if (ret)
		return ret;

	bpf_printk("STATIC test passed...");

	ret = asan_test_stack();
	if (ret)
		return ret;

	bpf_printk("STACK test passed...");

	ret = asan_test_buddy();
	if (ret)
		return ret;

	bpf_printk("BUDDY test passed...");

	bpf_printk("ASAN tests successful.");

	return 0;
}
