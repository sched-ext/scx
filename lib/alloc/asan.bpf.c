/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2024-2025 Meta Platforms, Inc. and affiliates.
 * Copyright (c) 2024-2025 Emil Tsalapatis <etsal@meta.com>
 */
#include <scx/common.bpf.h>
#include <scx/bpf_arena_common.bpf.h>

#include <lib/arena_map.h>
#include <alloc/asan.h>
#include <alloc/common.h>

#pragma clang attribute push(__attribute__((no_sanitize("address"))), \
			     apply_to = function)

#define SHADOW_ALL_ZEROES ((u64)-1)

/*
 * Implementation based on mm/kasan/generic.c.
 */

/*
 * Canary variable for ASAN violations.
 */
volatile u64 asan_violated = 0;

/*
 * XXX Shadow map occupancy map (see comment in arena_init.c and the 
 * item in the README).
 */
u64 __asan_shadow_memory_dynamic_address;

static bool reported = false;
static bool inited = false;

static bool asan_enabled = true;

/*
 * BPF does not currently support the memset/memcpy/memcmp intrinsics.
 */
__always_inline int asan_memset(s8a __arg_arena *dst, s8 val, size_t size)
{
	int i;

	/*
	 * XXX Switching this to a may_goto confuses the verifier and
	 * prevents verification on bpf-next as of late December 2025.
	 */
	bpf_for(i, 0, size) {
		dst[i] = val;
	}

	return 0;
}

/* Validate a 1-byte access, always within a single byte. */
static __always_inline bool memory_is_poisoned_1(s8a *addr)
{
	s8 shadow_value = asan_shadow_value(addr);

	/* Byte is 0, access is valid. */
	if (likely(!shadow_value))
		return false;

	/* 
	 * Byte is non-zero. Access is valid if granule offset in [0, shadow_value),
	 * so the memory is poisoned if shadow_value is negative or smaller than
	 * the granule's value.
	 */

	return ASAN_GRANULE(addr) >= shadow_value;
}

/* Validate a 2- 4-, 8-byte access, spans up to 2 bytes. */
static __always_inline bool memory_is_poisoned_2_4_8(s8a *addr, u64 size)
{
	u64 end = (u64)addr + size - 1;

	/*
	 * Region fully within a single byte (addition didn't
	 * overflow above ASAN_GRANULE).
	 */
	if (likely(ASAN_GRANULE(end) >= size - 1))
		return memory_is_poisoned_1((s8a *)end);

	/*
	 * Otherwise first byte must be fully unpoisoned, and second byte
	 * must be unpoisoned up to the end of the accessed region.
	 */

	return asan_shadow_value(addr) || memory_is_poisoned_1((s8a *)end);
}

__weak bool asan_shadow_set(void __arena __arg_arena *addr)
{
	return memory_is_poisoned_1(addr);
}

static __always_inline u64 first_nonzero_byte(u64 addr, size_t size)
{
	while (size && can_loop) {
		if (unlikely(*(s8a *)addr))
			return addr;
		addr += 1;
		size -= 1;
	}

	return SHADOW_ALL_ZEROES;
}

static __always_inline bool memory_is_poisoned_n(s8a *addr, u64 size)
{
	u64 ret;
	u64 start;
	u64 end;

	/* Size of [start, end] is end - start + 1. */
	start = (u64)mem_to_shadow(addr);
	end = (u64)mem_to_shadow(addr + size - 1);

	ret = first_nonzero_byte(start, (end - start) + 1);
	if (likely(ret == SHADOW_ALL_ZEROES))
		return false;

	return __builtin_expect(ret != end || ASAN_GRANULE(addr + size - 1) >=
						      *(s8a *)end, false);
}

static __always_inline int asan_report(s8a __arg_arena *addr, size_t sz,
				       bool write)
{
#if 0
	/* Only report the first ASAN violation. */
	if (likely(!reported)) {
		//bpf_printk("[ARENA ASAN] Poisoned %s at address [%p, %p)", "[TODO]", NULL, NULL);
		reported = true;
	}
#endif
	reported = true;

	asan_violated = (u64)addr;
	//	if ((u64)addr)
	//		asan_violated = (u64)addr;
	//	else
	//		asan_violated = (u64)-1;

	/* XXX Flesh out. */

	return 0;
}

static __always_inline bool check_asan_args(s8a *addr, size_t size,
					    bool *result)
{
	bool valid = true;

	if (unlikely(!asan_enabled))
		goto confirmed_valid;

	/* Size 0 accesses are valid even if the address is invalid. */
	if (unlikely(size == 0))
		goto confirmed_valid;

	/*
	 * Wraparound is possible for extremely high size. Possible if the size
	 * is a misinterpreted negative number.
	 */
	if (unlikely(addr + size < addr))
		goto confirmed_invalid;

	return false;

confirmed_invalid:
	valid = false;

	/* FALLTHROUGH */
confirmed_valid:
	*result = valid;

	return true;
}

/*
 * XXX The "explicit" call to be used from outside without worrying
 * about size. 
 */

static __always_inline bool check_region_inline(void *ptr, size_t size,
						bool write)
{
	s8a *addr = (s8a *)(u64)ptr;
	bool is_poisoned, is_valid;

	if (check_asan_args(addr, size, &is_valid)) {
		if (!is_valid)
			asan_report(addr, size, write);
		return is_valid;
	}

	switch (size) {
	case 1:
		is_poisoned = memory_is_poisoned_1(addr);
		break;
	case 2:
	case 4:
	case 8:
		is_poisoned = memory_is_poisoned_2_4_8(addr, size);
		break;
	default:
		is_poisoned = memory_is_poisoned_n(addr, size);
	}

	if (is_poisoned) {
		asan_report(addr, size, write);
		return false;
	}

	return true;
}

/*
 * __alias is not supported for BPF so define *__noabort() variants as wrappers.
 */
#define DEFINE_ASAN_LOAD_STORE(size)                                           \
	__hidden void __asan_store##size(void *addr)                           \
	{                                                                      \
		check_region_inline(addr, size, true);                         \
	}                                                                      \
	__hidden void __always_inline __asan_store##size##_noabort(void *addr) \
	{                                                                      \
		check_region_inline(addr, size, true);                         \
	}                                                                      \
	__hidden void __asan_load##size(void *addr)                            \
	{                                                                      \
		check_region_inline(addr, size, false);                        \
	}                                                                      \
	__hidden void __asan_load##size##_noabort(void *addr)                  \
	{                                                                      \
		check_region_inline(addr, size, false);                        \
	}                                                                      \
	__hidden void __asan_report_store##size(void *addr)                    \
	{                                                                      \
		asan_report((s8a *)addr, size, true);                          \
	}                                                                      \
	__hidden void __asan_report_store##size##_noabort(void *addr)          \
	{                                                                      \
		asan_report((s8a *)addr, size, true);                          \
	}                                                                      \
	__hidden void __asan_report_load##size(void *addr)                     \
	{                                                                      \
		asan_report((s8a *)addr, size, false);                         \
	}                                                                      \
	__hidden void __asan_report_load##size##_noabort(void *addr)           \
	{                                                                      \
		asan_report((s8a *)addr, size, false);                         \
	}

DEFINE_ASAN_LOAD_STORE(1);
DEFINE_ASAN_LOAD_STORE(2);
DEFINE_ASAN_LOAD_STORE(4);
DEFINE_ASAN_LOAD_STORE(8);

void __asan_storeN(void *addr, ssize_t size)
{
	check_region_inline(addr, size, true);
}

void __asan_loadN(void *addr, ssize_t size)
{
	check_region_inline(addr, size, false);
}

void __asan_register_globals(void *globals, size_t n)
{
	/* XXX What is the format in which we are passing the globals? */
	/* XXX Build the poisoning function. Should use asan_poisoning.cpp as a guide. */
	bpf_printk("Emitted %s", __func__);
}

void __asan_unregister_globals(void *globals, size_t n)
{
	bpf_printk("Emitted %s", __func__);
}

// Functions concerning block memory destinations
void *__asan_memcpy(void *d, const void *s, size_t n)
{
	bpf_printk("Emitted %s", __func__);
	return NULL;
}

void *__asan_memmove(void *d, const void *s, size_t n)
{
	bpf_printk("Emitted %s", __func__);
	return NULL;
}

void *__asan_memset(void *p, int c, size_t n)
{
	bpf_printk("Emitted %s", __func__);
	return NULL;
}

/*
 * Poisoning code, used when we add more freed memory to the allocator by:
 * 	a) pulling memory from the arena segment using bpf_arena_alloc_pages()
 * 	b) freeing memory from application code
 */
__hidden __noasan int asan_poison(void __arena *addr, s8 val, size_t size)
{
	s8a *shadow;
	size_t len;

	/*
	 * Poisoning from a non-granule address makes no sense: We can only allocate
	 * memory to the application that with a granule-aligned starting address,
	 * and bpf_arena_alloc_pages returns page-aligned memory. A non-aligned
	 * addr then implies we're freeing a different address than the one we
	 * allocated.
	 */
	if (unlikely((u64)addr & ASAN_GRANULE_MASK))
		return -EINVAL;

	/*
	 * We cannot free an unaligned region because it's possible that we
	 * cannot describe the resulting poisoning state of the granule in 
	 * the ASAN encoding.
	 *
	 * Every granule represents a region of memory that looks like the
	 * following (P for poisoned bytes, C for clear):
	 *
	 * <Clear>  <Poisoned>
	 * [ C C C ... P P ]
	 *
	 * The value of the granule's shadow map is the number of clear bytes in
	 * it. We cannot represent granules with the following state:
	 *
	 * [ P P ... C C ... P P ]
	 *
	 * That would be possible if we could free unaligned regions, so prevent that.
	 * 
	 */
	if (unlikely(size & ASAN_GRANULE_MASK))
		return -EINVAL;

	shadow = mem_to_shadow(addr);
	len = size >> ASAN_SHADOW_SHIFT;

	asan_memset(shadow, val, len);

	return 0;
}

/*
 * Unpoisoning code for marking memory as valid during allocation calls.
 *
 * Very similar to asan_poison, except we need to round up instead of
 * down, the partially poison the last granule if necessary.
 *
 * Partial poisoning is useful for keeping the padding poisoned. Allocations
 * are granule-aligned, so we we're reserving granule-aligned sizes for the
 * allocation. However, we want to still treat accesses to the padding as 
 * invalid. Partial poisoning takes care of that. Freeing and poisoning the
 * memory is still done in granule-aligned sizes and repoisons the already
 * poisoned padding.
 */
__hidden __noasan int asan_unpoison(void __arena *addr, size_t size)
{
	size_t partial = size & ASAN_GRANULE_MASK;
	s8a *shadow;
	size_t len;

	/*
	 * We cannot allocate in the middle of the granule. The ASAN shadow
	 * map encoding only describes regions of memory where every granule
	 * follows this format (P for poisoned, C for clear):
	 *
	 * <Clear>  <Poisoned>
	 * [ C C C ... P P ]
	 *
	 * This is so we can use a single number in [0, ASAN_SHADOW_SCALE)
	 * to represent the poison state of the granule.
	 */
	if (unlikely((u64)addr & ASAN_GRANULE_MASK))
		return -EINVAL;

	shadow = mem_to_shadow(addr);
	len = size >> ASAN_SHADOW_SHIFT;

	asan_memset(shadow, 0, len);

	/* 
	 * If we are allocating a non-granule aligned region, we need to adjust
	 * the last byte of the shadow map to list how many bytes in the granule
	 * are unpoisoned. If the region is aligned, then the memset call above
	 * was enough.
	 */
	if (partial)
		shadow[len] = partial;

	return 0;
}

/*
 * Initialize ASAN state when necessary. Triggered from userspace before
 * allocator startup.
 */
SEC("syscall")
__hidden __noasan int asan_init(struct asan_init_args *args)
{
	u64 globals_pages = args->arena_globals_pages;
	u64 all_pages = args->arena_all_pages;
	u64 shadowmap, shadow_pgoff;
	u64 shadow_pages;

	if (inited)
		return 0;

	/* 
	 * Retrieve how many pages in the arena are already mapped in.
	 * This is equal to or higher than the size of the arena globals.
	 * We use this to place the mapping right before the globals.
	 */
	shadow_pages = all_pages >> ASAN_SHADOW_SHIFT;

	/*
	 * Make sure the numbers provided by userspace are sane.
	 */
	if (all_pages > (1ULL << 32) >> PAGE_SHIFT) {
		bpf_printk("error: arena size %lx too large", all_pages);
		return -EINVAL;
	}

	if (globals_pages > all_pages) {
		bpf_printk("error: globals %lx do not fit in arena %lx", globals_pages, all_pages);
		return -EINVAL;
	}

	if (globals_pages + shadow_pages > all_pages) {
		bpf_printk("error: globals %lx do not leave room for shadow map %lx (arena pages %lx)",
			globals_pages, shadow_pages, all_pages);
		return -EINVAL;
	}

	shadow_pgoff = all_pages - shadow_pages - globals_pages;
	__asan_shadow_memory_dynamic_address = shadow_pgoff * PAGE_SIZE;

	/*
	 * XXX Fail for arenas that are < 32KiB, or are not 32KiB aligned. 
	 * Handling them would require extra edge case handling that would
	 * complicate things, and there is no good reason to support them.
	 */

	/* 
	 * Allocate the last (1/ASAN_GRANULE_SIZE)th of an arena's pages for the map
	 * We find the offset and size from the arena map.
	 *
	 * The allocated map pages are zeroed out, meaning all memory is marked as valid
	 * even if it's not allocated already. This is expected: Since the actual memory
	 * pages are not allocated, accesses to it will trigger page faults and will be
	 * reported through BPF streams. Any pages allocated through bpf_arena_alloc_pages
	 * should be poisoned by the allocator right after the call succeeds.
	 *
	 * XXX Do this lazily as denoted in the README item. Scale this with the arena
	 * size - right now we assume both in the offset and the size are for a 4GiB
	 * arena. Even for a 4GiB arena, the space overhead for lazy shadow map 
	 * allocation is 4KiB.
	 */
	shadowmap = (u64)bpf_arena_alloc_pages(
		&arena, (void __arena *)__asan_shadow_memory_dynamic_address,
		shadow_pages, NUMA_NO_NODE, 0);
	if (!shadowmap) {
		arena_stderr("Could not allocate shadow map\n");
		return -ENOMEM;
	}

	inited = true;

	return 0;
}

#pragma clang attribute pop
