#pragma once

/* Buddy allocator-related structs. */

struct buddy_chunk;
typedef struct buddy_chunk __arena buddy_chunk_t;

struct buddy_header;
typedef struct buddy_header __arena buddy_header_t;

enum buddy_consts {
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

struct buddy_header {
	u32 prev_index;	/* "Pointer" to the previous available allocation of the same size. */
	u32 next_index; /* Same for the next allocation. */
};

/*
 * We bring memory into the allocator 1MiB at a time.
 */
struct buddy_chunk {
	/* The order of the current allocation for a item. 4 bits per order. */
	u8			orders[SCX_BUDDY_CHUNK_ITEMS / 2];
	/* 
	 * Bit to denote whether chunk is allocated. Size of the allocated/free
	 * chunk found from the orders array.
	 */
	u8			allocated[SCX_BUDDY_CHUNK_ITEMS / 8];
	/* Freelists for O(1) allocation. */
	u64			freelists[SCX_BUDDY_CHUNK_NUM_ORDERS];
	buddy_chunk_t	*prev;
	buddy_chunk_t	*next;
};

struct buddy {
	buddy_chunk_t *first_chunk;		/* Pointer to the chunk linked list. */
	arena_spinlock_t __arena *lock;		/* Allocator lock */
	u64 vaddr;				/* Allocation into reserved vaddr */
};

#ifdef __BPF__

int buddy_init(struct buddy *buddy, arena_spinlock_t __arena *lock);
int buddy_destroy(struct buddy *buddy);
int buddy_free_internal(struct buddy *buddy, u64 free);
#define buddy_free(buddy, ptr) do { buddy_free_internal((buddy), (u64)(ptr)); } while (0)
u64 buddy_alloc_internal(struct buddy *buddy, size_t size);
#define buddy_alloc(alloc, size) ((void __arena *)buddy_alloc_internal((alloc), (size)))


#endif /* __BPF__  */
