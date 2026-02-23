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
	u64 arena_pages_used;			/* # of arena pages in use */
};

#ifdef __BPF__

int buddy_init(struct buddy *buddy, arena_spinlock_t __arena *lock);
int buddy_destroy(struct buddy *buddy);
int buddy_free_internal(struct buddy *buddy, u64 free);
#define buddy_free(buddy, ptr) do { buddy_free_internal((buddy), (u64)(ptr)); } while (0)

u64 buddy_alloc_internal(struct buddy *buddy, size_t size);
#define buddy_alloc(alloc, size) ((void __arena *)buddy_alloc_internal((alloc), (size)))

static __always_inline
u64 buddy_zalloc_internal(struct buddy *buddy, size_t size)
{
	u64 p = buddy_alloc_internal(buddy, size);

	if (p) {
		/* Poor man's memset to zero. */
		char __arena *pc = (char __arena *)p;
		for (int i = 0; i < size && can_loop; i++)
			pc[i] = 0;
	}

	return p;
}
#define buddy_zalloc(alloc, size) ((void __arena *)buddy_zalloc_internal((alloc), (size)))

int sys_buddy_init(void);

void sys_buddy_alloc_out(size_t size, void __arena **out);
#define sys_buddy_alloc(size) ({						\
	void __arena *out;							\
	sys_buddy_alloc_out((size), &out);					\
	out;									\
})

void sys_buddy_zalloc_out(size_t size, void __arena **out);
#define sys_buddy_zalloc(size) ({						\
	void __arena *out;							\
	sys_buddy_zalloc_out((size), &out);					\
	out;									\
})

void sys_buddy_free(void __arena *ptr);
u64 sys_buddy_get_arena_pages_used(void);
#endif /* __BPF__  */
