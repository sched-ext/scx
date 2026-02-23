#pragma once

/* Buddy allocator-related structs. */

struct buddy_chunk;
typedef struct buddy_chunk __arena buddy_chunk_t;

struct buddy_header;
typedef struct buddy_header __arena buddy_header_t;

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
