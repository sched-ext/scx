#pragma once

#ifdef __BPF__
#include <scx/bpf_arena_common.bpf.h>
#include <scx/bpf_arena_spin_lock.h>
#else  /* __BPF__ */
#include <scx/bpf_arena_common.h>
#endif /* __BPF__ */

#include <alloc/stack.h>

/* Buddy allocator-related structs. */

struct scx_buddy_chunk;
typedef struct scx_buddy_chunk __arena scx_buddy_chunk_t;

struct scx_buddy_header;
typedef struct scx_buddy_header __arena scx_buddy_header_t;

enum scx_buddy_consts {
	SCX_BUDDY_MIN_ALLOC_SHIFT	= 4,
	SCX_BUDDY_MIN_ALLOC_BYTES	= 1 << SCX_BUDDY_MIN_ALLOC_SHIFT,
	SCX_BUDDY_CHUNK_NUM_ORDERS	= 1 << 4,	/* 4 bits per order */
	SCX_BUDDY_CHUNK_BYTES		= SCX_BUDDY_MIN_ALLOC_BYTES << SCX_BUDDY_CHUNK_NUM_ORDERS,
	SCX_BUDDY_HEADER_OFF		= 8, /* header byte offset, see buddy.bpf.c for details */
	SCX_BUDDY_CHUNK_PAGES		= SCX_BUDDY_CHUNK_BYTES / PAGE_SIZE,
	SCX_BUDDY_CHUNK_ITEMS		= 1 << SCX_BUDDY_CHUNK_NUM_ORDERS,
	SCX_BUDDY_CHUNK_OFFSET_MASK	= SCX_BUDDY_CHUNK_BYTES - 1,
	SCX_BUDDY_VADDR_OFFSET		= SCX_BUDDY_CHUNK_BYTES,	/* Start aligning at chunk */
	SCX_BUDDY_VADDR_SIZE		= SCX_BUDDY_CHUNK_BYTES << 10 /* 1024 chunks maximum */
};

struct scx_buddy_header {
	u32 prev_index;	/* "Pointer" to the previous available allocation of the same size. */
	u32 next_index; /* Same for the next allocation. */
};

/*
 * We bring memory into the allocator 1MiB at a time.
 */
struct scx_buddy_chunk {
	/* The order of the current allocation for a item. 4 bits per order. */
	u8			orders[SCX_BUDDY_CHUNK_ITEMS / 2];
	/* 
	 * Bit to denote whether chunk is allocated. Size of the allocated/free
	 * chunk found from the orders array.
	 */
	u8			allocated[SCX_BUDDY_CHUNK_ITEMS / 8];
	/* Freelists for O(1) allocation. */
	u64			freelists[SCX_BUDDY_CHUNK_NUM_ORDERS];
	scx_buddy_chunk_t	*prev;
	scx_buddy_chunk_t	*next;
};

struct scx_buddy {
	scx_buddy_chunk_t *first_chunk;		/* Pointer to the chunk linked list. */
	arena_spinlock_t __arena *lock;		/* Allocator lock */
	u64 vaddr;				/* Allocation into reserved vaddr */
};

#ifdef __BPF__

int scx_buddy_init(struct scx_buddy *buddy, arena_spinlock_t __arena *lock);
int scx_buddy_destroy(struct scx_buddy *buddy);
int scx_buddy_free_internal(struct scx_buddy *buddy, u64 free);
#define scx_buddy_free(buddy, ptr) do { scx_buddy_free_internal((buddy), (u64)(ptr)); } while (0)
u64 scx_buddy_alloc_internal(struct scx_buddy *buddy, size_t size);
#define scx_buddy_alloc(alloc, size) ((void __arena *)scx_buddy_alloc_internal((alloc), (size)))


#endif /* __BPF__  */
