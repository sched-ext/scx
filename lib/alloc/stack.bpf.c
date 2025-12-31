/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2024-2025 Meta Platforms, Inc. and affiliates.
 * Copyright (c) 2024-2025 Emil Tsalapatis <etsal@meta.com>
 */

#include <scx/common.bpf.h>
#include <lib/arena_map.h>
#include <alloc/stack.h>
#include <alloc/asan.h>

/*
 * Necessary for cond_break/can_loop's semantics. According to kernel commit
 * 011832b, the loop counter variable must be seen as imprecise and bounded
 * by the verifier. Initializing it from a constant (e.g., i = 0;), then,
 * makes it precise and prevents may_goto from helping with converging the
 * loop. For these loops we must initialize the loop counter from a variable
 * whose value the verifier cannot reason about when checking the program, so
 * that the loop counter's value is imprecise.
 */
static __u64 zero = 0;

enum {
	STACK_POISONED = (s8)0xef,
};

__hidden int scx_stk_init(struct scx_stk		       *stack,
			  arena_spinlock_t __arg_arena __arena *lock,
			  __u64 data_size, __u64 nr_pages_per_alloc)
{
	if (!stack)
		return -EINVAL;

	stack->data_size = data_size;
	stack->nr_pages_per_alloc = nr_pages_per_alloc;
	stack->lock = lock;

	return 0;
}

__hidden void scx_stk_destroy(struct scx_stk *stack)
{
	scx_stk_seg_t *seg, *next;
	__u64 nr_pages;

	/* Operation happens unlocked since we are called last. */

	if (!stack)
		return;

	nr_pages = stack->nr_pages_per_alloc;

	/*
	 * While we have allocated in batches of either 1
	 * or 2, and broken the allocation into multiple
	 * segments, the arena kfunc API lets us free
	 * each segment separately.
	 */
	for (seg = stack->reserve; seg && can_loop; seg = next) {
		next = seg->next;
		asan_unpoison(seg, sizeof(*seg));
		bpf_arena_free_pages(&arena, seg, nr_pages);
	}

	for (seg = stack->first; seg && can_loop; seg = next) {
		next = seg->next;
		asan_unpoison(seg, sizeof(*seg));
		bpf_arena_free_pages(&arena, seg, nr_pages);
	}

	stack->first = NULL;
	stack->last = NULL;

	stack->current = NULL;
	stack->cind = 0;

	stack->capacity = 0;
	stack->available = 0;
	stack->data_size = 0;
	stack->nr_pages_per_alloc = 0;

	stack->reserve = NULL;
}

static int scx_stk_push(struct scx_stk *stack, void __arena *elem)
{
	scx_stk_seg_t *stk_seg = stack->current;
	int ridx = stack->cind;

	stack->current->elems[stack->cind] = elem;

	ridx += 1;

	/* Possibly loop into the next segment. */
	if (ridx == SCX_STK_SEG_MAX) {
		ridx = 0;
		stk_seg = stk_seg->next;
		if (!stk_seg)
			return -ENOSPC;
	}

	stack->current = stk_seg;
	stack->cind = ridx;

	stack->capacity -= 1;
	stack->available += 1;

	return 0;
}

static void __arena *scx_stk_pop(struct scx_stk *stack)
{
	scx_stk_seg_t *stk_seg = stack->current;
	void __arena *elem;
	int ridx = stack->cind;

	/* Possibly loop into previous segment. */
	if (ridx == 0) {
		ridx = SCX_STK_SEG_MAX;
		stk_seg = stack->current->prev;
		/* Possibly loop back into the last segment. */
		if (!stk_seg)
			return NULL;
	}

	ridx -= 1;

	stack->current = stk_seg;
	stack->cind = ridx;

	elem = stack->current->elems[stack->cind];

	stack->capacity += 1;
	stack->available -= 1;

	return elem;
}

static int scx_stk_seg_to_data(struct scx_stk *stack, size_t nelems)
{
	int ret, i;
	u64 data;

	/* Do we have enough empty segments for the conversion? */
	if (!stack->first || stack->first == stack->last)
		return -ENOMEM;

	data = (u64)stack->last;

	stack->last->prev->next = NULL;
	stack->last = stack->last->prev;

	/* We removed a segment. */
	stack->capacity -= SCX_STK_SEG_MAX;

	for (i = zero; i < nelems && can_loop; i++) {
		asan_poison((void __arena *)data, STACK_POISONED,
			    sizeof(struct scx_stk_seg));

		ret = scx_stk_push(stack, (void __arena *)data);
		if (ret)
			return ret;
		data += stack->data_size;
	}

	return 0;
}

static void scx_stk_extend(struct scx_stk *stack, scx_stk_seg_t *stk_seg)
{
	if (stack->last)
		stack->last->next = stk_seg;

	stk_seg->prev = stack->last;
	stk_seg->next = NULL;

	stack->last = stk_seg;
	stack->capacity += SCX_STK_SEG_MAX;

	if (!stack->first)
		stack->current = stack->first = stk_seg;

	/*
	 * Do not adjust the current segment/idx because we did not add
	 * any elements. The new segment will be pushed into during the next
	 * allocation.
	 */
}

static int scx_stk_free_unlocked(struct scx_stk *stack, void __arena *elem)
{
	if (!stack)
		return -EINVAL;

	asan_poison(elem, STACK_POISONED, stack->data_size);

	/* If no more room, repurpose the allocation into a segment. */
	if (stack->capacity == 0) {
		asan_unpoison(elem, sizeof(struct scx_stk_seg));

		scx_stk_extend(stack, (scx_stk_seg_t *)elem);
		return 0;
	}

	return scx_stk_push(stack, elem);
}

__weak int scx_stk_free_internal(struct scx_stk *stack, __u64 elem)
{
	int ret;

	if (!stack)
		return -EINVAL;

	ret = arena_spin_lock(stack->lock);
	if (ret)
		return ret;

	ret = scx_stk_free_unlocked(stack, (void __arena *)elem);

	arena_spin_unlock(stack->lock);

	return ret;
}

static int scx_stk_get_arena_memory(struct scx_stk *stack, __u64 nr_pages,
				    __u64 nstk_segs)
{
	scx_stk_seg_t *stk_seg;
	int ret, i;
	u64 mem;

	/*
	 * The code allocates new memory only as segments. The allocation and
	 * free code freely typecasts the segment buffer into data that can be
	 * allocated, and vice versa to avoid either ending up with too many
	 * empty segments under memory pressure, or having no space in the segment
	 * buffer for a buffer currently being freed.
	 */

	/*
	 * On error, we return with the segment buffer unlocked.
	 */
	if (!stack)
		return -EINVAL;

	arena_spin_unlock(stack->lock);

	mem = (__u64)bpf_arena_alloc_pages(&arena, NULL, nstk_segs * nr_pages,
					   NUMA_NO_NODE, 0);
	if (!mem)
		return -ENOMEM;

	ret = arena_spin_lock(stack->lock);
	if (ret)
		return ret;

	asan_poison((void __arena *)mem, STACK_POISONED,
		    nstk_segs * nr_pages * PAGE_SIZE);

	_Static_assert(sizeof(struct scx_stk_seg) <= PAGE_SIZE,
		       "segment must fit into a page");

	/* Attach the segments to the reserve linked list. */
	for (i = zero; i < nstk_segs && can_loop; i++) {
		/* Keep the memory that hosts metadata unpoisoned.*/
		stk_seg = (scx_stk_seg_t *)mem;
		asan_unpoison(stk_seg, sizeof(*stk_seg));

		stk_seg->next  = stack->reserve;
		stack->reserve = stk_seg;

		mem += nr_pages * PAGE_SIZE;
	}

	return 0;
}

static int scx_stk_fill_new_elems(struct scx_stk *stack)
{
	size_t nelems, nstk_segs;
	scx_stk_seg_t *stk_seg;
	__u64 nr_pages;
	int ret, i;
	u64 mem;

	nr_pages = stack->nr_pages_per_alloc;
	nelems = (nr_pages * PAGE_SIZE) / stack->data_size;
	if (nelems > SCX_STK_SEG_MAX) {
		ret = -EINVAL;
		goto error;
	}

	/* How many segments should we allocate? */
	nstk_segs = stack->capacity ? 1 : 2;

	/*
	 * If we have more than two empty segments available,
	 * repurpose one of them into an allocation.
	 */
	ret = scx_stk_seg_to_data(stack, nelems);
	if (!ret)
		return 0;

	/* If we haven't set aside enough memory from before, allocate. */
	if (!stack->reserve || !stack->reserve->next) {
		/* This call drops and retakes the lock. */
		ret = scx_stk_get_arena_memory(stack, nr_pages, nstk_segs);
		if (ret) {
			/* No need to unlock, we dropped the lock in the call. */
			return ret;
		}
	}

	/*
	 * If somebody replenished the stack while we were asleep, no need
	 * to do anything. Keep the allocated memory in the reserve linked
	 * list for subsequent allocations.
	 */
	if (stack->available > 0)
		return 0;

	/* Otherwise add elements and possibly capacity to the stack. */
	if (!stack->capacity) {
		stk_seg = stack->reserve;
		stack->reserve = stack->reserve->next;

		scx_stk_extend(stack, stk_seg);
	}

	/* Pop out the reserve and attach to the stack. */
	stk_seg = stack->reserve;
	stack->reserve = stk_seg->next;

	mem = (u64)stk_seg;
	for (i = zero; i < nelems && can_loop; i++) {
		ret = scx_stk_push(stack, (void __arena *)mem);
		if (ret)
			goto error;
		mem += stack->data_size;
	}

	return 0;

	/* 
	 * Drop the arena lock on error. On error we cannot
	 * guarantee we can return with the lock held, so
	 * make sure the lock is not taken for all error
	 * paths.
	 */
error:
	arena_spin_unlock(stack->lock);
	return ret;
}

static inline __u64 scx_stk_alloc_unlocked(struct scx_stk *stack)
{
	void __arena *elem;
	int ret;

	/* If segment buffer is empty, we have to populate it. */
	if (stack->available == 0) {
		/* The call drops the lock on error. */
		ret = scx_stk_fill_new_elems(stack);
		if (ret)
			return 0ULL;
	}

	/* An elem value of 0 implies error, drop the lock. */
	elem = scx_stk_pop(stack);
	if (elem)
		asan_unpoison(elem, stack->data_size);
	else
		arena_spin_unlock(stack->lock);

	return (__u64)elem;
}

__weak __u64 scx_stk_alloc(struct scx_stk *stack)
{
	u64 elem;

	if (!stack) {
		bpf_printk("using uninitialized stack allocator");
		return 0ULL;
	}

	if (arena_spin_lock(stack->lock))
		return 0ULL;

	elem = scx_stk_alloc_unlocked(stack);

	if (elem)
		arena_spin_unlock(stack->lock);

	return (u64)elem;
}
