/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2024-2025 Meta Platforms, Inc. and affiliates.
 * Copyright (c) 2024-2025 Tejun Heo <tj@kernel.org>
 * Copyright (c) 2024-2025 Emil Tsalapatis <etsal@meta.com>
 */

/*
 * Static allocation module used to allocate arena memory for
 * whose lifetime is that of the BPF program. Data is rarely
 * allocated, mostly at program init, and never freed. The
 * memory returned by this code is typeless so it avoids us
 * having to define an allocator for each type.
 */

#include <scx/common.bpf.h>
#include <lib/arena_map.h>

#include <alloc/common.h>
#include <alloc/asan.h>
#include <alloc/static.h>

/* Maximum memory that can be allocated by the arena. */
#define ARENA_MAX_MEMORY (1ULL << 20)

private(STATIC_ALLOC_LOCK) struct bpf_spin_lock static_lock;

private(STATIC_ALLOC) struct scx_static scx_static;

const s8 STATIC_POISON_UNINIT = 0xff;

extern volatile u64 asan_violated;

struct scx_ll;
struct scx_ll {
	struct scx_ll __arena *next;
};
typedef struct scx_ll __arena scx_ll_t;

__weak u64 scx_static_alloc_internal(size_t bytes, size_t alignment)
{
	void __arena *memory, *old;
	scx_ll_t     *oldll, *newll;
	size_t	      alloc_bytes;
	size_t	      alloc_pages;
	void __arena *ptr;
	size_t	      padding;
	u64	      addr;

	/* 
	 * Allocated addresses must be aligned to the nearest granule,
	 * and since we're stack allocating this implies that allocations
	 * sizes are also aligned.
	 */
	alignment = round_up(alignment, 1 << ASAN_SHADOW_SHIFT);

	bpf_spin_lock(&static_lock);

	/* Round up the current offset. */
	addr	    = (__u64)scx_static.memory + scx_static.off;

	padding	    = round_up(addr, alignment) - addr;
	alloc_bytes = bytes + padding;

	if (alloc_bytes > scx_static.max_contig_bytes) {
		bpf_spin_unlock(&static_lock);
		bpf_printk("invalid request %ld, max is %ld\n", alloc_bytes,
			   scx_static.max_contig_bytes);
		return (u64)NULL;
	}

	/*
	 * The code assumes that the maximum static allocation
	 * size is significantly larger than the typical allocation
	 * size, so it does not attempt to alleviate memory
	 * fragmentation.
	 */
	if (scx_static.off + alloc_bytes > scx_static.max_contig_bytes) {
		if (scx_static.cur_memusage + scx_static.max_contig_bytes >
		    scx_static.lim_memusage) {
			bpf_spin_unlock(&static_lock);
			bpf_printk("allocator memory limit exceeded");
			return (u64)NULL;
		}

		old = scx_static.memory;

		bpf_spin_unlock(&static_lock);

		/*
		 * No free operation so just forget about the previous
		 * allocation memory.
		 */

		alloc_pages = scx_static.max_contig_bytes / PAGE_SIZE;

		memory	    = bpf_arena_alloc_pages(&arena, NULL, alloc_pages,
						    NUMA_NO_NODE, 0);
		if (!memory)
			return (u64)NULL;

		asan_poison(memory, STATIC_POISON_UNINIT,
			    scx_static.max_contig_bytes);

		bpf_spin_lock(&static_lock);

		/* Error out if we raced with another allocation. */
		if (scx_static.memory != old) {
			bpf_spin_unlock(&static_lock);
			asan_unpoison(memory, scx_static.max_contig_bytes);
			bpf_arena_free_pages(&arena, memory, alloc_pages);

			bpf_printk(
				"concurrent static memory allocations unsupported");
			return (u64)NULL;
		}

		/* Keep a list of allocated blocks to free on allocator destruction. */
		oldll = (scx_ll_t *)old;
		newll = (scx_ll_t *)memory;
		asan_unpoison(newll, sizeof(*newll));
		newll->next = oldll;

		/*
		 * Switch to new memory block, reset offset,
		 * and recalculate base address.
		 */
		scx_static.memory = memory;
		scx_static.off	  = sizeof(*newll);
		addr		  = (__u64)scx_static.memory + scx_static.off;

		/*
		 * We changed the base address. Recompute the padding.
		 */
		padding	    = round_up(addr, alignment) - addr;
		alloc_bytes = bytes + padding;

		scx_static.cur_memusage += scx_static.max_contig_bytes;
	}

	ptr = (void __arena *)(addr + padding);
	asan_unpoison(ptr, bytes);

	scx_static.off += alloc_bytes;

	bpf_spin_unlock(&static_lock);

	return (u64)ptr;
}

__weak int scx_static_destroy(void)
{
	size_t	  alloc_pages = scx_static.max_contig_bytes / PAGE_SIZE;
	scx_ll_t *ll, *llnext;

	for (ll = scx_static.memory; ll && can_loop; ll = llnext) {
		llnext = ll->next;
		asan_unpoison(ll, scx_static.max_contig_bytes);
		bpf_arena_free_pages(&arena, ll, alloc_pages);
	}

	for (int i = 0; i < sizeof(scx_static) && can_loop; i++) {
		((u8 *)&scx_static)[i] = 0;
	}

	return 0;
}

__weak int scx_static_init(size_t alloc_pages)
{
	size_t	      max_bytes = alloc_pages * PAGE_SIZE;
	void __arena *memory;
	scx_ll_t     *ll;
	int	      ret;

	memory = bpf_arena_alloc_pages(&arena, NULL, alloc_pages, NUMA_NO_NODE,
				       0);
	if (!memory) {
		bpf_printk("Failed to allocate %d pages", alloc_pages);
		return -ENOMEM;
	}

	ret = asan_poison(memory, STATIC_POISON_UNINIT, max_bytes);
	if (ret)
		bpf_printk("Error %d: by poisoning", ret);

	ret = asan_unpoison(memory, sizeof(*ll));
	if (ret)
		bpf_printk("Error %d: by poisoning", ret);

	ll	 = (scx_ll_t *)memory;
	ll->next = NULL;

	bpf_spin_lock(&static_lock);

	/* We reserve sizeof(*ll) for the embedded linked list. */
	scx_static = (struct scx_static){
		.max_contig_bytes = max_bytes,
		.off		  = sizeof(*ll),
		.memory		  = memory,
		.lim_memusage	  = ARENA_MAX_MEMORY,
		.cur_memusage	  = max_bytes,
	};
	bpf_spin_unlock(&static_lock);

	return 0;
}

__weak int scx_static_memlimit(u64 lim_memusage)
{
	bpf_spin_lock(&static_lock);

	if (lim_memusage > ARENA_MAX_MEMORY)
		goto error;

	/* We always allocate at a page granularity. */
	if (lim_memusage % PAGE_SIZE)
		goto error;

	/* Have we already overshot the limit? */
	if (lim_memusage < scx_static.cur_memusage)
		goto error;

	scx_static.lim_memusage = lim_memusage;

	bpf_spin_unlock(&static_lock);

	return 0;

error:
	bpf_spin_unlock(&static_lock);

	return -EINVAL;
}
