/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2025 Meta Platforms, Inc. and affiliates.
 * Copyright (c) 2025 Tejun Heo <tj@kernel.org>
 * Copyright (c) 2025 Emil Tsalapatis <etsal@meta.com>
 */
#pragma once

#ifdef __BPF__

#include <bpf_arena_common.bpf.h>
#include <bpf_arena_spin_lock.h>

#else /* __BPF__ */

/* For userspace programs, __arena is a no-op. */
#ifndef __arena
#define __arena
#endif

/* Userspace only carries pointers to arena spinlocks. */
struct __qspinlock;
#define arena_spinlock_t struct __qspinlock

#endif /* __BPF__ */

#include "sdt_task_defs.h"
#include "const-defs.h"

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

/*
 * RCU for sdt allocations. Freed nodes accumulate on the active side while the
 * draining side sits out a grace period before its nodes return to the
 * allocator.
 *
 * With bpf_call_rcu() the grace period comes from RCU and the callbacks drain,
 * using head[0] and @draining with @active left at 0. Without it userspace
 * provides the grace period, see rust/scx_arena, and drives scx_urcu_reclaim()
 * over the two sides named by @active.
 */
struct scx_urcu {
	__u64		head[2];	/* struct sdt_data ptrs linked via urcu_link */
	__u32		active;
	__u64		draining;	/* bpf_call_rcu(): frozen set, callbacks only */
};

#ifdef __BPF__

void scx_arena_subprog_init(void);

int scx_alloc_init(struct scx_allocator *alloc, __u64 data_size, __u64 align);
u64 scx_alloc_internal(struct scx_allocator *alloc);
int scx_alloc_free_idx(struct scx_allocator *alloc, __u64 idx);

#define scx_alloc(alloc) ((void __arena *)scx_alloc_internal((alloc)))

/*
 * The metadata of the allocation holding @payload. It trails the payload inside
 * the element so that the payload starts at the element's alignment boundary.
 */
static inline struct sdt_data __arena *sdt_tailer(struct scx_allocator *alloc,
						  void __arena *payload)
{
	return (struct sdt_data __arena *)
		((__u64)payload + alloc->pool.elem_size - sizeof(struct sdt_data));
}

/* free by payload pointer, the tailer carries the index */
static inline int scx_free(struct scx_allocator *alloc, void __arena *payload)
{
	return scx_alloc_free_idx(alloc, sdt_tailer(alloc, payload)->tid.idx);
}

/*
 * Not a ___local copy: the kernel matches the field by type name, so the map
 * value has to carry this one. Drop it once the bundled vmlinux.h has the type.
 */
#ifndef SCX_VMLINUX_HAS_BPF_RCU_HEAD
struct bpf_rcu_head {
	__u64 __opaque[6];
};

typedef int (*bpf_rcu_callback_t)(struct bpf_map *map, void *key, void *value);
#endif

extern int bpf_call_rcu(struct bpf_rcu_head *rh, void *map__const_map,
			bpf_rcu_callback_t callback) __ksym __weak;

int scx_urcu_pending(struct scx_urcu *urcu);

/*
 * Returns nonzero when the active side went empty to non-empty. With
 * bpf_call_rcu() the caller then kicks the instance's timer, otherwise
 * userspace has been woken.
 */
int scx_urcu_free(struct scx_urcu *urcu, struct scx_allocator *alloc,
		  void __arena *payload);
int scx_urcu_reclaim(struct scx_urcu *urcu, struct scx_allocator *alloc);
/* per-call reclaim cap to bound the verifier walk */
#define SCX_URCU_RECLAIM_BATCH	4096

/*
 * Imprecise, so may_goto can converge the drain loop. Initialising the counter
 * from a constant makes it precise and defeats that, see the note on zero in
 * lib/sdt_alloc.bpf.c.
 */
static __u64 scx_urcu_zero;

/* What an instance should do after scx_urcu_progress(). */
enum scx_urcu_next {
	SCX_URCU_DONE = 0,	/* nothing left */
	SCX_URCU_SOON,		/* leftovers, already past a grace period */
	SCX_URCU_GP,		/* freshly frozen, needs a grace period */
};

/*
 * Free a batch of the set frozen by an earlier call, then, once it is empty,
 * freeze the current accumulation for the next one. Two stages are needed
 * because bpf_call_rcu() only promises a grace period since the arm: nodes
 * pushed after it was armed have not had one.
 *
 * Leftovers past the batch cap have already sat out their grace period, so
 * they come back through the timer rather than through RCU.
 *
 * @draining is reached only from the callbacks, of which one runs at a time
 * per instance, so it needs no atomics.
 */
static __always_inline
int scx_urcu_progress(struct scx_urcu *urcu, struct scx_allocator *alloc)
{
	__u64 i;

	for (i = scx_urcu_zero; i < SCX_URCU_RECLAIM_BATCH && can_loop; i++) {
		struct sdt_data __arena *data = (struct sdt_data __arena *)urcu->draining;

		if (!data)
			break;
		urcu->draining = data->urcu_link;
		scx_alloc_free_idx(alloc, data->tid.idx);
	}

	if (urcu->draining)
		return SCX_URCU_SOON;

	urcu->draining = __sync_lock_test_and_set(&urcu->head[0], 0);

	return urcu->draining ? SCX_URCU_GP : SCX_URCU_DONE;
}

/* The value of the one-entry array map an instance drives itself through. */
struct scx_urcu_state {
	struct bpf_timer	timer;
	struct bpf_rcu_head	rh;
	__u32			gp_pending;	/* draining is inside a grace period */
};

/*
 * Define the reclaim machinery for one scx_urcu instance. @urcu and @alloc are
 * file scope, which is why this is a macro: the callbacks only get the map,
 * the key and the value.
 *
 * Reclaim is driven from a bpf_timer rather than armed straight from the free
 * path. bpf_timer_set_callback() is understood on every kernel, so the timer
 * callback is always an async callback and check_max_stack_depth() does not
 * charge its subtree to whoever starts the timer. A kernel without
 * bpf_call_rcu() cannot tell the RCU callback is async, so that one's subtree
 * lands on the timer callback, which is a stack depth root of its own. The
 * free path only calls bpf_timer_start(), which names no subprog at all.
 */
#define SCX_URCU_DEFINE(name, urcu, alloc)					\
struct {									\
	__uint(type, BPF_MAP_TYPE_ARRAY);					\
	__uint(max_entries, 1);							\
	__type(key, u32);							\
	__type(value, struct scx_urcu_state);					\
} name##_state SEC(".maps");							\
										\
/*										\
 * Only reports that a grace period has passed. Doing the work here would	\
 * name this callback from inside itself, and a kernel which cannot tell it	\
 * is async walks that as a cycle when computing stack depth.			\
 */										\
static int name##_rcu_cb(struct bpf_map *map, void *key, void *value)		\
{										\
	struct scx_urcu_state *v = value;					\
										\
	WRITE_ONCE(v->gp_pending, 0);						\
	bpf_timer_start(&v->timer, 0, 0);					\
	return 0;								\
}										\
										\
static int name##_timer_cb(void *map, int *key, struct scx_urcu_state *v)	\
{										\
	/*									\
	 * A free can kick the timer while the frozen set is still inside the	\
	 * grace period armed for it. Draining it now would free too early;	\
	 * the kicked nodes wait on the accepting side until the next freeze.	\
	 */									\
	if (READ_ONCE(v->gp_pending))						\
		return 0;							\
										\
	switch (scx_urcu_progress(&(urcu), &(alloc))) {				\
	case SCX_URCU_SOON:							\
		bpf_timer_start(&v->timer, 0, 0);				\
		break;								\
	case SCX_URCU_GP:							\
		WRITE_ONCE(v->gp_pending, 1);					\
		bpf_call_rcu(&v->rh, &name##_state, name##_rcu_cb);		\
		break;								\
	}									\
										\
	return 0;								\
}										\
										\
/* Call once, before any free can reach scx_urcu_free(). */			\
static __always_inline							\
int name##_urcu_init(void)							\
{										\
	struct scx_urcu_state *v;						\
	u32 zero = 0;								\
										\
	if (!bpf_ksym_exists(bpf_call_rcu))					\
		return 0;							\
										\
	v = bpf_map_lookup_elem(&name##_state, &zero);				\
	if (!v)									\
		return -ENOENT;							\
										\
	bpf_timer_init(&v->timer, &name##_state, CLOCK_MONOTONIC);		\
	return bpf_timer_set_callback(&v->timer, name##_timer_cb);		\
}										\
										\
/* Kick reclaim after a free made the accepting list non-empty. */		\
static __always_inline							\
void name##_urcu_kick(void)							\
{										\
	struct scx_urcu_state *v;						\
	u32 zero = 0;								\
										\
	if (!bpf_ksym_exists(bpf_call_rcu))					\
		return;								\
										\
	v = bpf_map_lookup_elem(&name##_state, &zero);				\
	if (v)									\
		bpf_timer_start(&v->timer, 0, 0);				\
}										\
struct __scx_urcu_semicolon_##name

u64 scx_static_alloc_internal(size_t bytes, size_t alignment);
#define scx_static_alloc(bytes, alignment) ((void __arena *)scx_static_alloc_internal((bytes), (alignment)))
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

#endif /* __BPF__ */
