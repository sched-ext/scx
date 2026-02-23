#pragma once

#include <lib/alloc/common.h>

enum buddy_consts {
	BUDDY_MIN_ALLOC_SHIFT	= 4,
	BUDDY_MIN_ALLOC_BYTES	= 1 << BUDDY_MIN_ALLOC_SHIFT,
	BUDDY_CHUNK_NUM_ORDERS	= 1 << 4,	/* 4 bits per order */
	BUDDY_CHUNK_BYTES	= BUDDY_MIN_ALLOC_BYTES << BUDDY_CHUNK_NUM_ORDERS,
	BUDDY_HEADER_OFF	= 8, /* header byte offset, see buddy.bpf.c for details */
	BUDDY_CHUNK_PAGES	= BUDDY_CHUNK_BYTES / PAGE_SIZE,
	BUDDY_CHUNK_ITEMS	= 1 << BUDDY_CHUNK_NUM_ORDERS,
	BUDDY_CHUNK_OFFSET_MASK	= BUDDY_CHUNK_BYTES - 1,
	BUDDY_VADDR_OFFSET	= BUDDY_CHUNK_BYTES,
	BUDDY_VADDR_SIZE	= ((ARENA_MAX_PAGES >> 2) * PAGE_SIZE), /* 1/4 of the arena size */
	BUDDY_VADDR_MAX_SLOTS	= ARENA_MAX_PAGES / (BUDDY_VADDR_SIZE / PAGE_SIZE),
};

struct buddy_header {
	u32 prev_index;	/* "Pointer" to the previous available allocation of the same size. */
	u32 next_index; /* Same for the next allocation. */
};

/*
 * We bring memory into the allocator 1MiB at a time.
 */
struct buddy_chunk {
	/* The order of the current allocation for a item. 4 bits per order. */
	u8		orders[BUDDY_CHUNK_ITEMS / 2];
	/* 
	 * Bit to denote whether chunk is allocated. Size of the allocated/free
	 * chunk found from the orders array.
	 */
	u8		allocated[BUDDY_CHUNK_ITEMS / 8];
	/* Freelists for O(1) allocation. */
	u64		freelists[BUDDY_CHUNK_NUM_ORDERS];
	buddy_chunk_t	*prev;
	buddy_chunk_t	*next;
};
