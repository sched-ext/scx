/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2024-2025 Meta Platforms, Inc. and affiliates.
 * Copyright (c) 2024-2025 Emil Tsalapatis <etsal@meta.com>
 */

#include <scx/common.bpf.h>
#include <lib/arena_map.h>
#include <alloc/common.h>
#include <alloc/buddy.h>
#include <alloc/asan.h>

volatile int zero = 0;

enum {
	BUDDY_POISONED = (s8)0xef,
};

static inline int scx_buddy_lock(struct scx_buddy *buddy)
{
	return arena_spin_lock(buddy->lock);
}

static inline void scx_buddy_unlock(struct scx_buddy *buddy)
{
	arena_spin_unlock(buddy->lock);
}

/*
 * Reserve part of the arena address space for the allocator. We use
 * this to get aligned addresses for the chunks.
 */
static int scx_reserve_arena_vaddr(struct scx_buddy *buddy)
{
	buddy->vaddr = 0;

	return bpf_arena_reserve_pages(&arena,
				       (void __arena *)SCX_BUDDY_VADDR_OFFSET,
				       SCX_BUDDY_VADDR_SIZE / PAGE_SIZE);
}

/*
 * Free up any unused address space. Used only during teardown.
 */
static void scx_unreserve_arena_vaddr(struct scx_buddy *buddy)
{
	bpf_arena_free_pages(
		&arena, (void __arena *)(SCX_BUDDY_VADDR_OFFSET + buddy->vaddr),
		(SCX_BUDDY_VADDR_SIZE - buddy->vaddr) / PAGE_SIZE);

	buddy->vaddr = 0;
}

/* Carve out part of the reserved address space and allocate it to the */
static int scx_alloc_arena_vaddr(struct scx_buddy *buddy, u64 *vaddrp)
{
	u64 vaddr, old, new;

	do {
		vaddr = buddy->vaddr;
		new   = vaddr + SCX_BUDDY_CHUNK_BYTES;

		if (new > SCX_BUDDY_VADDR_SIZE)
			return -EINVAL;

		old = __sync_val_compare_and_swap(&buddy->vaddr, vaddr, new);
	} while (old != vaddr && can_loop);

	if (old != vaddr)
		return -EINVAL;

	*vaddrp = SCX_BUDDY_VADDR_OFFSET + vaddr;

	return 0;
}

static u64 scx_next_pow2(__u64 n)
{
	n--;
	n |= n >> 1;
	n |= n >> 2;
	n |= n >> 4;
	n |= n >> 8;
	n |= n >> 16;
	n |= n >> 32;
	n++;

	return n;
}

__weak
int idx_set_allocated(scx_buddy_chunk_t __arg_arena *chunk, u64 idx, bool allocated)
{
	if (unlikely(idx >= SCX_BUDDY_CHUNK_ITEMS)) {
		arena_stderr("setting order of invalid idx (%d, max %d)\n", idx,
			     SCX_BUDDY_CHUNK_ITEMS);
		return -EINVAL;
	}

	if (allocated)
		chunk->allocated[idx / 8] |= 1 << (idx % 8);
	else
		chunk->allocated[idx / 8] &= ~(1 << (idx % 8));

	return 0;
}

static int idx_is_allocated(scx_buddy_chunk_t *chunk, u64 idx, bool *allocated)
{
	if (unlikely(idx >= SCX_BUDDY_CHUNK_ITEMS)) {
		arena_stderr("setting order of invalid idx (%d, max %d)\n", idx,
			     SCX_BUDDY_CHUNK_ITEMS);
		return -EINVAL;
	}

	*allocated = chunk->allocated[idx / 8] & (1 << (idx % 8));
	return 0;
}

__weak
int idx_set_order(scx_buddy_chunk_t __arg_arena *chunk, u64 idx, u8 order)
{
	u8 prev_order;

	if (unlikely(order >= SCX_BUDDY_CHUNK_NUM_ORDERS)) {
		arena_stderr("setting invalid order %u\n", order);
		return -EINVAL;
	}

	if (unlikely(idx >= SCX_BUDDY_CHUNK_ITEMS)) {
		arena_stderr("setting order of invalid idx (%d, max %d)\n", idx,
			     SCX_BUDDY_CHUNK_ITEMS);
		return -EINVAL;
	}

	/* 
	 * We store two order instances per byte, one per nibble.
	 * Retain the existing nibble.
	 */
	prev_order = chunk->orders[idx / 2];
	if (idx & 0x1) {
		order &= 0xf;
		order |= (prev_order & 0xf0);
	} else {
		order <<= 4;
		order |= (prev_order & 0xf);
	}

	chunk->orders[idx / 2] = order;

	return 0;
}

static u8 idx_get_order(scx_buddy_chunk_t *chunk, u64 idx)
{
	u8 result;

	_Static_assert(SCX_BUDDY_CHUNK_NUM_ORDERS <= 16,
		       "order must fit in 4 bits");

	if (unlikely(idx >= SCX_BUDDY_CHUNK_ITEMS)) {
		arena_stderr("setting order of invalid idx\n");
		return SCX_BUDDY_CHUNK_NUM_ORDERS;
	}

	result = chunk->orders[idx / 2];

	return (idx & 0x1) ? (result & 0xf) : (result >> 4);
}

static void __arena *idx_to_addr(scx_buddy_chunk_t *chunk, size_t idx)
{
	u64 address;

	if (unlikely(idx >= SCX_BUDDY_CHUNK_ITEMS)) {
		arena_stderr("setting order of invalid idx\n");
		return NULL;
	}

	/*
	 * The data blocks start in the chunk after the metadata block.
	 * We find the actual address by indexing into the region at an
	 * SCX_BUDDY_MIN_ALLOC_BYTES granularity, the minimum allowed.
	 * The index number already accounts for the fact that the first
	 * blocks in the chunk are occupied by the metadata, so we do
	 * not need to offset it.
	 */

	if ((u64)chunk % SCX_BUDDY_CHUNK_BYTES)
		DIAG();

	address = (u64)chunk + (idx * SCX_BUDDY_MIN_ALLOC_BYTES);

	return (void __arena *)address;
}

static scx_buddy_header_t *idx_to_header(scx_buddy_chunk_t *chunk, size_t idx)
{
	bool allocated;
	u64 address;

	if (unlikely(idx_is_allocated(chunk, idx, &allocated))) {
		arena_stderr("accessing invalid idx 0x%lx\n", idx);
		return NULL;
	}

	if (unlikely(allocated)) {
		arena_stderr("accessing allocated idx 0x%lx as header\n", idx);
		return NULL;
	}

	address = (u64)idx_to_addr(chunk, idx);

	/* 
	 * Offset the header within the block. This avoids accidental overwrites
	 * to the header because of off-by-one errors when using adjacent blocks.
	 *
	 * The offset has been chosen as a compromise between ASAN effectiveness
	 * and allocator granularity:
	 * 1) ASAN dictates valid data runs are 8-byte aligned.
	 * 2) We want to keep a low minimum allocation size (currently 16).
	 * 
	 * As a result, we have only two possible positions for the header: Bytes
	 * 0 and 8. Keeping the header in byte 0 means off-by-ones from the previous
	 * block touch the header, and, since the header must be accessible, ASAN
	 * will not trigger. Keeping the header on byte 8 means off-by-one errors from
	 * the previous block are caught by ASAN. Negative offsets are rarer, so 
	 * while accesses into the block from the next block are possible, they are
	 * less probable.
	 */

	return (scx_buddy_header_t *)(address + SCX_BUDDY_HEADER_OFF);
}

static void header_add_freelist(scx_buddy_chunk_t  *chunk,
				scx_buddy_header_t *header, u64 idx, u8 order)
{
	scx_buddy_header_t *tmp_header;

	idx_set_order(chunk, idx, order);

	header->next_index = chunk->freelists[order];
	header->prev_index = SCX_BUDDY_CHUNK_ITEMS;

	if (header->next_index != SCX_BUDDY_CHUNK_ITEMS) {
		tmp_header = idx_to_header(chunk, header->next_index);
		tmp_header->prev_index = idx;
	}

	chunk->freelists[order] = idx;
}

static void header_remove_freelist(scx_buddy_chunk_t  *chunk,
				   scx_buddy_header_t *header, u8 order)
{
	scx_buddy_header_t *tmp_header;

	if (header->prev_index != SCX_BUDDY_CHUNK_ITEMS) {
		tmp_header = idx_to_header(chunk, header->prev_index);
		tmp_header->next_index = header->next_index;
	}

	if (header->next_index != SCX_BUDDY_CHUNK_ITEMS) {
		tmp_header = idx_to_header(chunk, header->next_index);
		tmp_header->prev_index = header->prev_index;
	}

	/* Pop off the list head if necessary. */
	if (idx_to_header(chunk, chunk->freelists[order]) == header)
		chunk->freelists[order] = header->next_index;

	header->prev_index = SCX_BUDDY_CHUNK_ITEMS;
	header->next_index = SCX_BUDDY_CHUNK_ITEMS;
}

static u64 size_to_order(size_t size)
{
	u64 order;

	if (unlikely(!size)) {
		arena_stderr("size 0 has no order\n");
		return 64;
	}

	/*
	 * To find the order of the allocation we find the first power of two
	 * >= the requested size, take the log2, then adjust it for the minimum
	 * allocation size by removing the minimum shift from it. Requests
	 * smaller than the minimum allocation size are rounded up.
	 */
	order = scx_fls(scx_next_pow2(size));
	if (order < SCX_BUDDY_MIN_ALLOC_SHIFT)
		return 0;

	return order - SCX_BUDDY_MIN_ALLOC_SHIFT;
}

__weak
int add_leftovers_to_freelist(scx_buddy_chunk_t __arg_arena *chunk, u32 cur_idx,
		u64 min_order, u64 max_order)
{
	scx_buddy_header_t *header;
	u64 ord;
	u32 idx;

	bpf_for(ord, min_order, max_order) {
		/* Mark the buddy as free and add it to the freelists. */
		idx = cur_idx + (1 << ord);

		header = idx_to_header(chunk, idx);
		if (unlikely(!header))
			return -EINVAL;

		asan_unpoison(header, sizeof(*header));

		idx_set_allocated(chunk, idx, false);
		header_add_freelist(chunk, header, idx, ord);
	}

	return 0;
}

static scx_buddy_chunk_t *scx_buddy_chunk_get(struct scx_buddy *buddy)
{
	u64 order, ord, min_order, max_order;
	scx_buddy_chunk_t  *chunk;
	size_t left;
	int power2;
	u64 vaddr;
	u32 idx;
	int ret;

	scx_buddy_unlock(buddy);

	ret = scx_alloc_arena_vaddr(buddy, &vaddr);
	if (ret) {
		DIAG();
		return NULL;
	}

	/* Addresses must be aligned to the chunk boundary. */
	if (vaddr % SCX_BUDDY_CHUNK_BYTES) {
		DIAG();
		return NULL;
	}

	/* Unreserve the address space. */
	bpf_arena_free_pages(&arena, (void __arena *)vaddr,
			     SCX_BUDDY_CHUNK_PAGES);

	chunk = bpf_arena_alloc_pages(&arena, (void __arena *)vaddr,
				      SCX_BUDDY_CHUNK_PAGES, NUMA_NO_NODE, 0);
	if (!chunk) {
		arena_stderr("[ALLOC FAILED]");
		return NULL;
	}

	if ((ret = scx_buddy_lock(buddy))) {
		bpf_arena_free_pages(&arena, chunk, SCX_BUDDY_CHUNK_PAGES);
		return NULL;
	}

	asan_poison(chunk, BUDDY_POISONED, SCX_BUDDY_CHUNK_PAGES * PAGE_SIZE);

	/* Unpoison the chunk itself. */
	asan_unpoison(chunk, sizeof(*chunk));

	/* Mark all freelists as empty. */
	for (ord = zero; ord < SCX_BUDDY_CHUNK_NUM_ORDERS && can_loop; ord++)
		chunk->freelists[ord] = SCX_BUDDY_CHUNK_ITEMS;

	/*
	 * Initialize the chunk by carving out the first page to hold the metadata struct above,
	 * then dumping the rest of the pages into the allocator.
	 */

	_Static_assert(SCX_BUDDY_CHUNK_PAGES * PAGE_SIZE >=
			       SCX_BUDDY_MIN_ALLOC_BYTES *
				       SCX_BUDDY_CHUNK_ITEMS,
		       "chunk must fit within the allocation");

	/*
	 * Step 2: Reserve a chunk for the chunk metadata, then breaks
	 * the rest of the full allocation into the different buckets.
	 * We allocating the memory by grabbing blocks of progressively
	 * smaller sizes from the allocator, which are guaranteed to be
	 * continuous.
	 *
	 * This operation also populates the allocator.
	 *
	 * Algorithm:
	 *
	 * - max_order: The last order allocation we made
	 * - left: How many bytes are left to allocate
	 * - cur_index: Current index into the top-level block we are 
	 * allocating from.
	 * 
	 * Step:
	 * - Find the largest power-of-2 allocation still smaller than left (infimum)
	 * - Reserve a chunk of that size, along with its buddy
	 * - For every order from [infimum + 1, last order), carve out a block 
	 *   and put it into the allocator.
	 *
	 *  Example: Chunk size 0b1010000 (80 bytes)
	 *
	 *  Step 1:
	 *
	 *   idx  infimum			   1 << max_order
	 *   0 	      64	128		      1 << 20	
	 *   |________|_________|______________________|
	 *
	 *   Blocks set aside:
	 *   	[0, 64)		- Completely allocated
	 *   	[64, 128)	- Will be further split in the next iteration
	 *   
	 *   Blocks added to the allocator:
	 *   	[128, 256)
	 *   	[256, 512)
	 *   	...
	 *   	[1 << 18, 1 << 19)
	 *   	[1 << 19, 1 << 20)
	 *
	 *  Step 2:
	 *
	 *   idx  infimum			   idx + 1 << max_order
	 *   64	      80	96		   	64 + 1 << 6 = 128
	 *   |________|_________|______________________|
	 *
	 *   Blocks set aside:
	 *   	[64, 80)	- Completely allocated
	 *   
	 *   Blocks added to the allocator:
	 *      [80, 96) - left == 0 so the buddy is unused and marked as freed
	 *   	[96, 128)
	 */
	max_order = SCX_BUDDY_CHUNK_NUM_ORDERS;
	left = sizeof(*chunk);
	idx = 0;
	while (left && can_loop) {
		power2 = scx_fls(left);
		if (unlikely(power2 >= SCX_BUDDY_CHUNK_NUM_ORDERS)) {
			arena_stderr(
				"buddy chunk metadata require allocation of order %d\n",
				power2);
			arena_stderr(
				"chunk has size of 0x%lx bytes (left %lx bytes)\n",
				sizeof(*chunk), left);

			scx_buddy_unlock(buddy);
			return NULL;
		}

		/* Round up allocations that are too small. */

		left -= (power2 >= SCX_BUDDY_MIN_ALLOC_SHIFT) ? 1 << power2 : left;
		order = (power2 >= SCX_BUDDY_MIN_ALLOC_SHIFT) ? power2 - SCX_BUDDY_MIN_ALLOC_SHIFT : 0;

		idx_set_allocated(chunk, idx, true);

		/* 
		 * Starting an order above the one we allocated, populate
		 * the allocator with free blocks. If this is the last
		 * allocation (left == 0), also mark the buddy as free.
		 */
		min_order = left ? order + 1 : order;
		if (add_leftovers_to_freelist(chunk, idx, min_order, max_order)) {
			scx_buddy_unlock(buddy);
			return NULL;
		}

		/* Adjust the index. */
		idx += 1 << order;
		max_order = order;
	}

	return chunk;
}

__hidden int scx_buddy_init(struct scx_buddy			 *buddy,
			    arena_spinlock_t __arg_arena __arena *lock)
{
	scx_buddy_chunk_t *chunk;
	int ret;

	buddy->lock = lock;

	/* 
	 * Reserve enough address space to ensure allocations are aligned.
	 */
	if ((ret = scx_reserve_arena_vaddr(buddy))) {
		DIAG();
		return ret;
	}

	_Static_assert(SCX_BUDDY_CHUNK_PAGES > 0,
		       "chunk must use one or more pages");

	/* Chunk is already properly unpoisoned if allocated. */
	if (scx_buddy_lock(buddy)) {
		DIAG();
		return -EINVAL;
	}

	chunk = scx_buddy_chunk_get(buddy);
	if (!chunk) {
		buddy->first_chunk = NULL;
		return -ENOMEM;
	}

	/* Put the chunk at the beginning of the list. */
	chunk->next = buddy->first_chunk;
	chunk->prev = NULL;
	buddy->first_chunk = chunk;

	scx_buddy_unlock(buddy);

	return 0;
}

/*
 * Destroy the allocator. This does not check whether there are any allocations
 * currently in use, so any pages being accessed will start taking arena faults.
 * We do not take a lock because we are freeing arena pages, and nobody should
 * be using the allocator at that point in the execution.
 */
__weak int scx_buddy_destroy(struct scx_buddy *buddy)
{
	scx_buddy_chunk_t *chunk, *next;

	if (!buddy)
		return -EINVAL;

	/*
	 * Traverse all buddy chunks and free them back to the arena
	 * with the same granularity they were allocated with.
	 */
	for (chunk = buddy->first_chunk; chunk && can_loop; chunk = next) {
		next = chunk->next;

		/* Wholesale poison the entire block. */
		asan_poison(chunk, BUDDY_POISONED,
			    SCX_BUDDY_CHUNK_PAGES * PAGE_SIZE);
		bpf_arena_free_pages(&arena, chunk, SCX_BUDDY_CHUNK_PAGES);
	}

	/* Free up any part of the address space that did not get used. */
	scx_unreserve_arena_vaddr(buddy);

	/* Clear all fields. */
	buddy->first_chunk = NULL;

	return 0;
}

__weak u64 scx_buddy_chunk_alloc(scx_buddy_chunk_t __arg_arena *chunk,
				 int				order_req)
{
	scx_buddy_header_t *header, *tmp_header, *next_header;
	u32 idx, tmpidx, retidx;
	u64 address;
	u64 order = 0;
	u64 i;

	bpf_for(order, order_req, SCX_BUDDY_CHUNK_NUM_ORDERS) {
		if (chunk->freelists[order] != SCX_BUDDY_CHUNK_ITEMS)
			break;
	}

	if (order >= SCX_BUDDY_CHUNK_NUM_ORDERS)
		return (u64)NULL;

	retidx = chunk->freelists[order];
	header = idx_to_header(chunk, retidx);
	chunk->freelists[order] = header->next_index;

	if (header->next_index != SCX_BUDDY_CHUNK_ITEMS) {
		next_header = idx_to_header(chunk, header->next_index);
		next_header->prev_index = SCX_BUDDY_CHUNK_ITEMS;
	}

	header->prev_index = SCX_BUDDY_CHUNK_ITEMS;
	header->next_index = SCX_BUDDY_CHUNK_ITEMS;
	if (idx_set_order(chunk, retidx, order_req))
		return (u64)NULL;

	if (idx_set_allocated(chunk, retidx, true))
		return (u64)NULL;

	/* 
	 * Do not unpoison the address yet, will be done by the caller
	 * because the caller has the exact allocation size requested.
	 */
	address = (u64)idx_to_addr(chunk, retidx);

	/* If we allocated from a larger-order chunk, split the buddies. */
	bpf_for(i, order_req, order) {
		/*
		 * Flip the bit for the current order (the bit is guaranteed
		 * to be 0, so just add 1 << i). 
		 */
		idx = retidx + (1 << i);

		/* Add the buddy of the allocation to the free list. */
		header = idx_to_header(chunk, idx);
		/* Unpoison the buddy header */
		asan_unpoison(header, sizeof(*header));
		if (idx_set_allocated(chunk, idx, false))
			return (u64)NULL;

		if (idx_set_order(chunk, idx, i))
			return (u64)NULL;

		/* Push the header to the beginning of the freelists list. */
		tmpidx = chunk->freelists[i];

		header->prev_index = SCX_BUDDY_CHUNK_ITEMS;
		header->next_index = tmpidx;

		if (tmpidx != SCX_BUDDY_CHUNK_ITEMS) {
			tmp_header = idx_to_header(chunk, tmpidx);
			tmp_header->prev_index = idx;
		}

		chunk->freelists[i] = idx;
	}

	return address;
}

__weak u64 scx_buddy_alloc_internal(struct scx_buddy *buddy, size_t size)
{
	scx_buddy_chunk_t *chunk;
	u64 address;
	int order;

	if (!buddy)
		return (u64)NULL;

	order = size_to_order(size);
	if (order >= SCX_BUDDY_CHUNK_NUM_ORDERS || order < 0) {
		arena_stderr("invalid order %d (sz %lu)\n", order, size);
		return (u64)NULL;
	}

	if (scx_buddy_lock(buddy))
		return (u64)NULL;

	for (chunk = buddy->first_chunk; chunk != NULL && can_loop;
	     chunk = chunk->next) {
		address = scx_buddy_chunk_alloc(chunk, order);
		if (address)
			goto done;
	}

	/* Get a new chunk. */
	chunk = scx_buddy_chunk_get(buddy);
	if (!chunk)
		return (u64)NULL;

	/* Add the chunk into the allocator and retry. */
	chunk->next = buddy->first_chunk;
	chunk->prev = NULL;
	buddy->first_chunk = chunk;

	address = scx_buddy_chunk_alloc(buddy->first_chunk, order);

done:

	if (!address) {
		scx_buddy_unlock(buddy);
		return (u64)NULL;
	}

	/* 
	 * Unpoison exactly the amount of bytes requested. If the
	 * data is smaller than the header, we must poison any
	 * unused bytes that were part of the header.
	 */
	if (size < SCX_BUDDY_HEADER_OFF + sizeof(scx_buddy_header_t))
		asan_poison((u8 __arena *)address + SCX_BUDDY_HEADER_OFF,
			    BUDDY_POISONED, sizeof(scx_buddy_header_t));

	asan_unpoison((u8 __arena *)address, size);

	scx_buddy_unlock(buddy);

	return address;
}

static __always_inline int scx_buddy_free_unlocked(struct scx_buddy *buddy, u64 addr)
{
	scx_buddy_header_t *header, *buddy_header;
	u64 idx, buddy_idx, tmp_idx;
	scx_buddy_chunk_t *chunk;
	bool allocated;
	u8 order;

	if (!buddy)
		return -EINVAL;

	if (addr & (SCX_BUDDY_MIN_ALLOC_BYTES - 1)) {
		arena_stderr("Freeing unaligned address %llx\n", addr);
		return 0;
	}

	/* Get (chunk, idx) out of the address. */
	chunk = (void __arena *)(addr & ~SCX_BUDDY_CHUNK_OFFSET_MASK);
	idx = (addr & SCX_BUDDY_CHUNK_OFFSET_MASK) / SCX_BUDDY_MIN_ALLOC_BYTES;

	/* Mark the block as unallocated so we can access the header. */
	idx_set_allocated(chunk, idx, false);

	order  = idx_get_order(chunk, idx);
	header = idx_to_header(chunk, idx);

	/* The header is in the block itself, keep it unpoisoned. */
	asan_poison((u8 __arena *)addr, BUDDY_POISONED,
		    SCX_BUDDY_MIN_ALLOC_BYTES << order);
	asan_unpoison(header, sizeof(*header));

	/* 
	 * Coalescing loop. Merge with free buddies of equal order.
	 * For every coalescing step, keep the left buddy and 
	 * drop the right buddy's header.
	 */
	bpf_for(order, order, SCX_BUDDY_CHUNK_NUM_ORDERS) {
		buddy_idx = idx ^ (1 << order);

		/* Check if the buddy is actually free. */
		idx_is_allocated(chunk, buddy_idx, &allocated);
		if (allocated)
			break;

		/* 
		 * If buddy is not the same order as the chunk
		 * being freed, then we're done coalescing.
		 */
		if (idx_get_order(chunk, buddy_idx) != order)
			break;

		buddy_header = idx_to_header(chunk, buddy_idx);
		header_remove_freelist(chunk, buddy_header, order);

		/* Keep the left header out of the two buddies, drop the other one. */
		if (buddy_idx < idx) {
			tmp_idx = idx;
			idx = buddy_idx;
			buddy_idx = tmp_idx;
		}

		/* Remove the buddy from the freelists so that we can merge it. */
		idx_set_order(chunk, buddy_idx, order);

		buddy_header = idx_to_header(chunk, buddy_idx);
		asan_poison(buddy_header, BUDDY_POISONED,
			    sizeof(*buddy_header));
	}

	/* Header properly freed but not in any freelists yet .*/
	idx_set_order(chunk, idx, order);

	header = idx_to_header(chunk, idx);
	header_add_freelist(chunk, header, idx, order);

	return 0;
}

__weak int scx_buddy_free_internal(struct scx_buddy *buddy, u64 addr)
{
	int ret;

	if (!buddy)
		return -EINVAL;

	if ((ret = scx_buddy_lock(buddy)))
		return ret;

	scx_buddy_free_unlocked(buddy, addr);

	scx_buddy_unlock(buddy);

	return 0;
}
