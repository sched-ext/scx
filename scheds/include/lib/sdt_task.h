/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2025 Meta Platforms, Inc. and affiliates.
 * Copyright (c) 2025 Tejun Heo <tj@kernel.org>
 * Copyright (c) 2025 Emil Tsalapatis <etsal@meta.com>
 */
#pragma once

#include <scx/bpf_arena_common.bpf.h>
#include <scx/bpf_arena_spin_lock.h>
#include "sdt_task_defs.h"

struct scx_stk_seg;
typedef struct scx_stk_seg __arena scx_stk_seg_t;

#define SCX_STK_SEG_MAX (SDT_TASK_ENTS_PER_CHUNK - 2)

struct scx_stk_seg {
	void __arena	*elems[SCX_STK_SEG_MAX];
	scx_stk_seg_t	*prev;
	scx_stk_seg_t	*next;
};

/*
 * Extensible stack struct.
 */
struct scx_stk {
	arena_spinlock_t __arena *lock;

	scx_stk_seg_t *first;	/* First stack segment. */
	scx_stk_seg_t *last;

	scx_stk_seg_t *current;	/* Current stack segment. */
	__u64 cind;

	__u64 capacity;		/* Free slots in the stack. */
	__u64 available;	/* Available items in the stack. */
	__u64 data_size;
	__u64 nr_pages_per_alloc;

	scx_stk_seg_t *reserve;
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

void __arena *scx_static_alloc(size_t bytes, size_t alignment);
int scx_static_init(size_t max_alloc_pages);

u64 scx_stk_alloc(struct scx_stk *stack);
int scx_stk_init(struct scx_stk *stackp, __u64 data_size, __u64 nr_pages_per_alloc);
int scx_stk_free_internal(struct scx_stk *stack, __u64 elem);

#define scx_stk_free(stack, elem) scx_stk_free_internal(stack, (__u64)elem)

/* Buddy allocator-related structs. */

struct scx_buddy_chunk;
typedef struct scx_buddy_chunk __arena scx_buddy_chunk_t;

struct scx_buddy_header;
typedef struct scx_buddy_header __arena scx_buddy_header_t;

enum scx_buddy_consts {
	SCX_BUDDY_MIN_ALLOC_SHIFT	= 4,
	SCX_BUDDY_MIN_ALLOC_BYTES	= 1 << SCX_BUDDY_MIN_ALLOC_SHIFT,
	SCX_BUDDY_CHUNK_MAX_ORDER	= 16,
	SCX_BUDDY_CHUNK_PAGES		= (SCX_BUDDY_MIN_ALLOC_BYTES << SCX_BUDDY_CHUNK_MAX_ORDER) / PAGE_SIZE,
	SCX_BUDDY_CHUNK_ITEMS		= SCX_BUDDY_CHUNK_PAGES * PAGE_SIZE / SCX_BUDDY_MIN_ALLOC_BYTES,
	SCX_BUDDY_CHUNK_OFFSET_MASK	= (SCX_BUDDY_CHUNK_PAGES * PAGE_SIZE) - 1,
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
	u64			order_indices[SCX_BUDDY_CHUNK_MAX_ORDER];
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
void scx_buddy_free_internal(struct scx_buddy *buddy, u64 free);
#define scx_buddy_free(buddy, ptr) do { scx_buddy_free_internal((buddy), (u64)(ptr)); } while (0)
u64 scx_buddy_alloc_internal(struct scx_buddy *buddy, size_t size);
#define scx_buddy_alloc(alloc, size) ((void __arena *)scx_buddy_alloc_internal((alloc), (size)))

static inline
int scx_ffs(__u64 word)
{
	unsigned int num = 0;

	if ((word & 0xffffffff) == 0) {
		num += 32;
		word >>= 32;
	}

	if ((word & 0xffff) == 0) {
		num += 16;
		word >>= 16;
	}

	if ((word & 0xff) == 0) {
		num += 8;
		word >>= 8;
	}

	if ((word & 0xf) == 0) {
		num += 4;
		word >>= 4;
	}

	if ((word & 0x3) == 0) {
		num += 2;
		word >>= 2;
	}

	if ((word & 0x1) == 0) {
		num += 1;
		word >>= 1;
	}

	return num;
}
