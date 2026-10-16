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
#include <lib/spinlock.h>

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
 * RCU for sdt allocations. Freed nodes accumulate on the accepting side while the
 * draining side sits out a grace period before its nodes return to the
 * allocator.
 *
 * With bpf_call_rcu() the grace period comes from RCU and the timer callback
 * drains, using head[0] and @draining with @active left at 0. Without it
 * userspace
 * provides the grace period, see rust/scx_arena, and drives scx_urcu_reclaim()
 * over the two sides named by @active.
 */
struct scx_urcu {
	__u64		head[2];	/* struct sdt_data ptrs linked via urcu_link */
	__u32		active;
	__u64		draining;	/* bpf_call_rcu(): draining side, callbacks only */
	__u32		kick_lost;	/* a free path failed to start the timer */
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

extern int bpf_call_rcu(struct bpf_rcu_head *rh, void *map__const_map,
			bpf_rcu_callback_t callback) __ksym __weak;

int scx_urcu_pending(struct scx_urcu *urcu);

/*
 * Returns nonzero when the caller should kick the instance's timer: the
 * accepting side went empty to non-empty, or an earlier kick failed to start
 * it. Without bpf_call_rcu() there is no timer and userspace has been woken.
 */
int scx_urcu_free(struct scx_urcu *urcu, struct scx_allocator *alloc,
		  void __arena *payload);
int scx_urcu_reclaim(struct scx_urcu *urcu, struct scx_allocator *alloc);

/* per-call reclaim cap to bound the verifier walk */
#define SCX_URCU_RECLAIM_BATCH	4096
/* the timer drain runs in softirq, so it frees far fewer per run */
#define SCX_URCU_DRAIN_BATCH	512
/* a failed arm is retried off the timer rather than spun on */
#define SCX_URCU_ARM_RETRY_NS	(1 * 1000 * 1000)

/* what an instance should do after scx_urcu_progress() */
enum scx_urcu_next {
	SCX_URCU_DONE = 0,	/* nothing left */
	SCX_URCU_SOON,		/* leftovers, already past a grace period */
	SCX_URCU_GP,		/* freshly frozen, needs a grace period */
};

/*
 * Free a batch of the set frozen by an earlier call, then, once it is empty,
 * freeze the accepting side for the next one. Two stages are needed because
 * bpf_call_rcu() only promises a grace period since the arm: nodes pushed
 * after it was armed have not had one.
 *
 * Leftovers past the batch cap have already sat out their grace period, so
 * they come back through the timer rather than through RCU.
 *
 * @draining is reached only from the timer callback, which the hrtimer core
 * runs one at a time per timer, so it needs no atomics.
 */
static __always_inline
enum scx_urcu_next scx_urcu_progress(struct scx_urcu *urcu, struct scx_allocator *alloc)
{
	__u64 i;

	for (i = 0; i < SCX_URCU_DRAIN_BATCH && can_loop; i++) {
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

/* the value of the one-entry array map an instance drives itself through */
struct scx_urcu_state {
	struct bpf_timer	timer;
	struct bpf_rcu_head	rh;
	__u32			gp_pending;	/* draining is inside a grace period */
	__u32			arm_failed;	/* and bpf_call_rcu() has not taken */
};

/*
 * Define the reclaim machinery for one scx_urcu instance. @urcu and @alloc are
 * file scope, which is why this is a macro: the callbacks only get the map,
 * the key and the value.
 *
 * Reclaim is driven from a bpf_timer so that the free path only ever calls
 * bpf_timer_start(), which names no subprog: see the commit message for the
 * stack depth argument that rests on it.
 */
#define SCX_URCU_DEFINE(name, urcu, alloc)					\
struct {									\
	__uint(type, BPF_MAP_TYPE_ARRAY);					\
	__uint(max_entries, 1);							\
	__type(key, u32);							\
	__type(value, struct scx_urcu_state);					\
} scx_urcu_##name##_state SEC(".maps");						\
										\
/* A start that fails leaves nothing to drive reclaim, so let a free retry. */	\
static __always_inline								\
void name##_urcu_restart(struct scx_urcu_state *v, __u64 ns)			\
{										\
	if (bpf_timer_start(&v->timer, ns, 0))					\
		WRITE_ONCE((urcu).kick_lost, 1);				\
}										\
										\
/* reports the grace period; doing the work here would name this callback */	\
static int name##_rcu_cb(struct bpf_map *map, void *key, void *value)		\
{										\
	struct scx_urcu_state *v = value;					\
										\
	WRITE_ONCE(v->gp_pending, 0);						\
	name##_urcu_restart(v, 0);						\
	return 0;								\
}										\
										\
/*										\
 * An arm can fail, and the draining side must not be freed until one takes,	\
 * so retry off the timer rather than letting the next drain run early.		\
 */										\
static __always_inline void name##_urcu_arm(struct scx_urcu_state *v)		\
{										\
	if (bpf_call_rcu(&v->rh, &scx_urcu_##name##_state, name##_rcu_cb)) {	\
		WRITE_ONCE(v->arm_failed, 1);					\
		name##_urcu_restart(v, SCX_URCU_ARM_RETRY_NS);			\
	} else {								\
		WRITE_ONCE(v->arm_failed, 0);					\
	}									\
}										\
										\
static int name##_timer_cb(void *map, int *key, struct scx_urcu_state *v)	\
{										\
	if (!bpf_ksym_exists(bpf_call_rcu))					\
		return 0;							\
										\
	WRITE_ONCE((urcu).kick_lost, 0);					\
										\
	/*									\
	 * A free can kick while the draining side is still inside the grace	\
	 * period armed for it. Draining it now would free too early; the	\
	 * kicked nodes wait on the accepting side until the next freeze.	\
	 */									\
	if (READ_ONCE(v->gp_pending)) {						\
		if (READ_ONCE(v->arm_failed))					\
			name##_urcu_arm(v);					\
		return 0;							\
	}									\
										\
	switch (scx_urcu_progress(&(urcu), &(alloc))) {				\
	case SCX_URCU_SOON:							\
		name##_urcu_restart(v, 0);					\
		break;								\
	case SCX_URCU_GP:							\
		WRITE_ONCE(v->gp_pending, 1);					\
		name##_urcu_arm(v);						\
		break;								\
	case SCX_URCU_DONE:							\
		break;								\
	}									\
										\
	return 0;								\
}										\
										\
/*										\
 * Call once, before any free can reach scx_urcu_free(). The callback is set	\
 * unconditionally so the verifier marks it async on every kernel, but without	\
 * the kfunc the timer is never started and a failure there does not matter.	\
 */										\
static __always_inline								\
int name##_urcu_init(void)							\
{										\
	struct scx_urcu_state *v;						\
	u32 zero = 0;								\
	int ret;								\
										\
	v = bpf_map_lookup_elem(&scx_urcu_##name##_state, &zero);		\
	if (!v)									\
		return -ENOENT;							\
										\
	bpf_timer_init(&v->timer, &scx_urcu_##name##_state, CLOCK_MONOTONIC);	\
	ret = bpf_timer_set_callback(&v->timer, name##_timer_cb);		\
										\
	return bpf_ksym_exists(bpf_call_rcu) ? ret : 0;				\
}										\
										\
/*										\
 * Kick reclaim after scx_urcu_free() asked for it. A free path can run with	\
 * irqs off, where the start takes the deferred path and can fail; remember	\
 * that so later frees retry, since they no longer kick on their own.		\
 */										\
static __always_inline								\
void name##_urcu_kick(void)							\
{										\
	struct scx_urcu_state *v;						\
	u32 zero = 0;								\
										\
	if (!bpf_ksym_exists(bpf_call_rcu))					\
		return;								\
										\
	v = bpf_map_lookup_elem(&scx_urcu_##name##_state, &zero);		\
	if (!v)									\
		return;								\
										\
	if (bpf_timer_start(&v->timer, 0, 0))					\
		WRITE_ONCE((urcu).kick_lost, 1);				\
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
