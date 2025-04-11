/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2025 Meta Platforms, Inc. and affiliates.
 * Copyright (c) 2025 Tejun Heo <tj@kernel.org>
 * Copyright (c) 2025 Emil Tsalapatis <etsal@meta.com>
 */
#pragma once
#include <scx/bpf_arena_common.h>

#ifndef div_round_up
#define div_round_up(a, b) (((a) + (b) - 1) / (b))
#endif

typedef struct sdt_desc __arena sdt_desc_t;

enum sdt_consts {
	SDT_TASK_ENTS_PER_PAGE_SHIFT	= 9,
	SDT_TASK_LEVELS			= 3,
	SDT_TASK_ENTS_PER_CHUNK		= 1 << SDT_TASK_ENTS_PER_PAGE_SHIFT,
	SDT_TASK_CHUNK_BITMAP_U64S	= div_round_up(SDT_TASK_ENTS_PER_CHUNK, 64),
	SDT_TASK_ALLOC_STACK_MIN	= 2 * SDT_TASK_LEVELS,
	SDT_TASK_ALLOC_STACK_MAX	= SDT_TASK_ALLOC_STACK_MIN * 5,
	SDT_TASK_MIN_ELEM_PER_ALLOC = 8,
	SDT_TASK_ALLOC_ATTEMPTS		= 32,
};

union sdt_id {
	__s64				val;
	struct {
		__s32			idx;	/* index in the radix tree */
		__s32			gen;	/* ++'d on recycle so that it forms unique'ish 64bit ID */
	};
};

struct sdt_chunk;

/*
 * Each index page is described by the following descriptor which carries the
 * bitmap. This way the actual index can host power-of-two numbers of entries
 * which makes indexing cheaper.
 */
struct sdt_desc {
	__u64				allocated[SDT_TASK_CHUNK_BITMAP_U64S];
	__u64				nr_free;
	struct sdt_chunk __arena	*chunk;
};

/*
 * Leaf node containing per-task data.
 */
struct sdt_data {
	union sdt_id			tid;
	__u64				payload[];
};

/*
 * Intermediate node pointing to another intermediate node or leaf node.
 */
struct sdt_chunk {
	union {
		sdt_desc_t * descs[SDT_TASK_ENTS_PER_CHUNK];
		struct sdt_data __arena *data[SDT_TASK_ENTS_PER_CHUNK];
	};
};

/*
 * Stack structure to avoid chunk allocations/frees while under lock. The
 * allocator preallocates enough arena pages before any operation to satisfy
 * the maximum amount of chunk allocations:(2 * SDT_TASK_LEVELS + 1), two
 * allocations per tree level, and one for the data itself. Preallocating
 * ensures that the stack can satisfy these allocations, so we do not need
 * to drop the lock to allocate pages from the arena in the middle of the
 * top-level alloc. This in turn prevents races and simplifies the code.
 */
struct scx_alloc_stack {
	__u64 idx;
	void __arena	*stack[SDT_TASK_ALLOC_STACK_MAX];
};

struct sdt_pool {
	void __arena	*slab;
	__u64		elem_size;
	__u64		max_elems;
	__u64		idx;
};

struct scx_alloc_stats {
	__u64		chunk_allocs;
	__u64		data_allocs;
	__u64		alloc_ops;
	__u64		free_ops;
	__u64		active_allocs;
	__u64		arena_pages_used;
};

struct scx_allocator {
	struct sdt_pool	pool;
	sdt_desc_t	*root;
};

struct scx_static {
	size_t max_alloc_bytes;
	void __arena *memory;
	size_t off;
};

#ifdef __BPF__

#include <scx/bpf_arena_spin_lock.h>

struct scx_ring;
typedef struct scx_ring __arena scx_ring_t;

#define SCX_RING_MAX (SDT_TASK_ENTS_PER_CHUNK - 2)

struct scx_ring {
	void __arena	*elems[SCX_RING_MAX];
	scx_ring_t	*prev;
	scx_ring_t	*next;
};

/*
 * Extensible stack struct.
 */
struct scx_stk {
	arena_spinlock_t __arena *lock;

	scx_ring_t *first;	/* First ring. */
	scx_ring_t *last;

	scx_ring_t *current;	/* Current ring. */
	__u64 cind;

	__u64 capacity;		/* Free slots in the ring buffer. */
	__u64 available;	/* Available items in the ring buffer. */
	__u64 data_size;
	__u64 nr_pages_per_alloc;

	scx_ring_t *reserve;
};

void __arena *scx_task_data(struct task_struct *p);
int scx_task_init(__u64 data_size);
void __arena *scx_task_alloc(struct task_struct *p);
void scx_task_free(struct task_struct *p);
void scx_arena_subprog_init(void);

int scx_alloc_init(struct scx_allocator *alloc, __u64 data_size);
u64 scx_alloc_internal(struct scx_allocator *alloc);
int scx_alloc_free_idx(struct scx_allocator *alloc, __u64 idx);

#define scx_alloc(alloc) ((struct sdt_data __arena *)scx_alloc_internal((alloc)))

void __arena *scx_static_alloc(size_t bytes);
int scx_static_init(size_t max_alloc_pages);

u64 scx_stk_alloc(struct scx_stk *stack);
int scx_stk_init(struct scx_stk *stackp, __u64 data_size, __u64 nr_pages_per_alloc);
int scx_stk_free_internal(struct scx_stk *stack, __u64 elem);

#define scx_stk_free(stack, elem) scx_stk_free_internal(stack, (__u64)elem)

/* Buddy allocator-related structs. */

/* 
 * XXX Initially we do page-sized allocations, there are certain intricacies in using
 * a buddy allocator with smaller sizes - mainly the metadata and worst-case allocations
 * cause high space overhead in the average and worst case.
 */
enum scx_buddy_consts {
	SCX_BUDDY_CHUNK_PAGES		= 256,
	SCX_BUDDY_CHUNK_ORDERS		= 8,
	SCX_BUDDY_MIN_ALLOC_BYTES	= 4096,
	SCX_BUDDY_CHUNK_ITEMS		= SCX_BUDDY_CHUNK_PAGES * PAGE_SIZE / SCX_BUDDY_MIN_ALLOC_BYTES,
};

struct scx_buddy_chunk;
typedef struct scx_buddy_chunk __arena scx_buddy_chunk_t;

struct scx_buddy_header;
typedef struct scx_buddy_header __arena scx_buddy_header_t;

/* 
 * XXXETSAL: Right now this is 16 bytes because of the pointer and alignment. 
 * We can make this 8 bytes if we use a 32-bit pointer, since arena pointers
 * are 32-bit anyway, then turn it into 2 bytes if we replace the pointer 
 * with an offset into the chunk array and mark the struct as packed (assuming
 * BPF permits it).
 */
struct scx_buddy_header {
	u16 prev_index;	/* "Pointer" to the previous available allocation of the same size. */
	u16 next_index; /* Same for the next allocation. */
	u16 order;	/* Allocation order, starting from the base allocation of the allocator. */
};

/*
 * We bring memory into the allocator 1MiB at a time.
 */
struct scx_buddy_chunk {
	struct scx_buddy_header	headers[SCX_BUDDY_CHUNK_ITEMS];
	u64			order_indices[SCX_BUDDY_CHUNK_ORDERS];
	scx_buddy_chunk_t	*prev;
	scx_buddy_chunk_t	*next;
};

struct scx_buddy {
	scx_buddy_chunk_t *first_chunk;		/* Pointer to the chunk linked list. */
	size_t min_alloc_bytes;			/* Minimum allocation in bytes */
	struct scx_stk stack;			/* Underlying stack page allocator. */
	struct bpf_spin_lock lock;

	/* XXXETSAL: Track used pages, used to drain the underlying page stack. */
};

int scx_buddy_init(struct scx_buddy *buddy, size_t size);
void scx_buddy_free(struct scx_buddy *buddy, size_t free);
u64 scx_buddy_alloc_internal(struct scx_buddy *buddy, size_t size);
#define scx_buddy_alloc(alloc) ((void __arena *)scx_buddy_alloc_internal((buddy, size)))

#endif /* __BPF__ */
