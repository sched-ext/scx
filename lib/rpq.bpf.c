/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2025 Meta Platforms, Inc. and affiliates.
 */

/*
 * Relaxed Priority Queue (RPQ) - BPF arena implementation.
 *
 * A scalable concurrent priority queue based on the MultiQueue design
 * (Rihani, Sanders, Dementiev - SPAA 2015; extended ESA 2021).
 *
 * Design overview:
 *   - nr_queues independent binary min-heaps stored as flat arrays
 *     in BPF arena memory.
 *   - Each heap protected by its own arena qspinlock, minimizing
 *     contention (with c*p queues and p CPUs, collision probability
 *     per operation is ~1/(c*p)).
 *   - Insert: random queue selection + lock + heap sift-up.
 *   - Pop: "power of two choices" -- peek two random heaps without
 *     locking, lock the one with the smaller minimum, extract.
 *   - All loops bounded by log2(per_queue_capacity) for BPF verifier.
 *   - No dynamic allocation in the fast path; all heaps pre-allocated
 *     at creation time via scx_static_alloc.
 *
 * Relaxation guarantee:
 *   Pop returns an element within the top O(nr_queues) elements
 *   of the global ordering, with high probability.
 */

#include <scx/common.bpf.h>

#include <lib/sdt_task.h>
#include <lib/rpq.h>

/*
 * Maximum number of retries for insert/pop when encountering
 * lock contention or full/empty queues.
 */
#define RPQ_MAX_RETRIES 8

/*
 * Swap two rpq_elem values in arena memory.
 */
static __always_inline void
rpq_swap_elems(struct rpq_elem __arena *a __arg_arena,
	       struct rpq_elem __arena *b __arg_arena)
{
	u64 tmp_elem = a->elem;
	u64 tmp_key = a->key;

	a->elem = b->elem;
	a->key = b->key;

	b->elem = tmp_elem;
	b->key = tmp_key;
}

/*
 * Sift the last element up to restore min-heap property.
 * Follows the scx_minheap_balance_bottom_up pattern.
 */
static inline void
rpq_sift_up(rpq_heap_t __arg_arena *heap)
{
	int parent;
	int ind;

	for (ind = heap->size - 1; ind > 0 && can_loop; ind = parent) {
		parent = (ind - 1) >> 1;

		if (heap->elems[parent].key <= heap->elems[ind].key)
			break;

		rpq_swap_elems(&heap->elems[parent], &heap->elems[ind]);
	}
}

/*
 * Sift the root element down to restore min-heap property.
 * Follows the scx_minheap_balance_top_down pattern.
 */
static inline void
rpq_sift_down(rpq_heap_t __arg_arena *heap)
{
	int child, next;
	int off, ind;

	for (ind = 0; ind < heap->size && can_loop; ind = next) {
		next = ind;

		for (off = 1; off < 3 && can_loop; off++) {
			/*
			 * Correspondence between parent and children is:
			 * y = 2x + 1, y = 2x + 2
			 */
			child = 2 * ind + off;

			if (child >= heap->size)
				continue;

			if (heap->elems[next].key <= heap->elems[child].key)
				continue;

			next = child;
		}

		if (next == ind)
			break;

		rpq_swap_elems(&heap->elems[next], &heap->elems[ind]);
	}
}

/*
 * Insert an element into a specific heap.
 * Caller must hold heap->lock.
 */
static inline int
rpq_heap_insert(rpq_heap_t __arg_arena *heap, u64 elem, u64 key)
{
	u64 pos;

	if (heap->size >= heap->capacity)
		return -ENOSPC;

	pos = heap->size;
	heap->elems[pos].elem = elem;
	heap->elems[pos].key = key;
	heap->size++;

	rpq_sift_up(heap);

	/*
	 * Update min_key for lockless peek. After sift-up the
	 * minimum is always at elems[0].
	 */
	WRITE_ONCE(heap->min_key, heap->elems[0].key);

	return 0;
}

/*
 * Extract the minimum element from a specific heap.
 * Caller must hold heap->lock.
 */
static inline int
rpq_heap_pop(rpq_heap_t __arg_arena *heap, u64 *elem, u64 *key)
{
	if (heap->size == 0)
		return -ENOENT;

	*elem = heap->elems[0].elem;
	*key = heap->elems[0].key;

	heap->size--;

	if (heap->size > 0) {
		heap->elems[0].elem = heap->elems[heap->size].elem;
		heap->elems[0].key = heap->elems[heap->size].key;
		rpq_sift_down(heap);

		WRITE_ONCE(heap->min_key, heap->elems[0].key);
	} else {
		WRITE_ONCE(heap->min_key, (u64)-1);
	}

	return 0;
}

/*
 * Maximum pick-d value for the pop heuristic. Clamped to avoid
 * excessive cache-line reads per pop.
 */
#define RPQ_MAX_D 8

/*
 * Create a relaxed priority queue.
 *
 * @nr_queues: Number of internal heaps. For best results, use
 *             c * nr_cpus where c >= 2.
 * @per_queue_capacity: Maximum elements per internal heap.
 * @d: Number of queues to sample during pop (pick-d heuristic).
 *     Use 2 for the standard MultiQueue design.
 *
 * Returns a u64-encoded arena pointer, or 0 on failure.
 */
__weak
u64 rpq_create_internal(u32 nr_queues, u64 per_queue_capacity, u32 d)
{
	/*
	 * Marked as volatile because otherwise the array reference
	 * in the initialization loop gets demoted to scalar and the
	 * program fails verification.
	 */
	volatile rpq_t *pq;
	volatile rpq_heap_t *queues;
	int i;

	if (!nr_queues || !per_queue_capacity)
		return (u64)NULL;

	pq = scx_static_alloc(sizeof(*pq), 1);
	if (!pq)
		return (u64)NULL;

	queues = scx_static_alloc(nr_queues * sizeof(*queues), 1);
	if (!queues)
		return (u64)NULL;

	pq->nr_queues = nr_queues;
	pq->d = (d >= 1 && d <= RPQ_MAX_D) ? d : 2;
	pq->queues = (rpq_heap_t *)queues;

	for (i = 0; i < nr_queues && can_loop; i++) {
		struct rpq_elem __arena *elems;

		elems = scx_static_alloc(
			per_queue_capacity * sizeof(*elems), 1);
		if (!elems)
			return (u64)NULL;

		queues[i].size = 0;
		queues[i].capacity = per_queue_capacity;
		queues[i].min_key = (u64)-1;
		queues[i].elems = elems;
		/*
		 * Lock is zero-initialized by arena allocation,
		 * which is the unlocked state for qspinlock.
		 */
	}

	return (u64)pq;
}

/*
 * Try to insert into a specific heap. Lock, insert, unlock.
 * Returns 0 on success, -ENOSPC if full, other negative on error.
 * Returns 1 if the lock could not be acquired (caller should retry).
 */
static inline int
rpq_try_insert(rpq_heap_t __arg_arena *heap, u64 elem, u64 key)
{
	int ret;

	ret = arena_spin_lock(&heap->lock);
	if (ret)
		return 1; /* lock failed, retry */

	ret = rpq_heap_insert(heap, elem, key);
	arena_spin_unlock(&heap->lock);

	return ret;
}

/*
 * Insert retry loop over random queues.
 */
static inline int
rpq_insert_random(rpq_t __arg_arena *pq, u32 nq, u64 elem, u64 key)
{
	int ret, i;

	for (i = 0; i < RPQ_MAX_RETRIES && can_loop; i++) {
		u32 qi = bpf_get_prandom_u32() % nq;

		ret = rpq_try_insert(&pq->queues[qi], elem, key);
		if (ret == 0)
			return 0;
		if (ret == 1 || ret == -ENOSPC)
			continue;
		return ret;
	}

	return -ENOSPC;
}

/*
 * Insert an element into the relaxed priority queue.
 *
 * Picks a random internal heap, locks it, and inserts. If the
 * selected heap is full or the lock fails, retries with a
 * different random heap (up to RPQ_MAX_RETRIES attempts).
 *
 * @pq: Pointer to the relaxed priority queue.
 * @elem: Payload value to insert.
 * @key: Priority key (lower = higher priority).
 *
 * Returns 0 on success, -ENOSPC if all attempted queues are full,
 * or another negative errno on failure.
 */
__weak
int rpq_insert(rpq_t __arg_arena *pq, u64 elem, u64 key)
{
	u32 nq;

	if (unlikely(!pq))
		return -EINVAL;

	nq = pq->nr_queues;
	if (unlikely(!nq))
		return -EINVAL;

	return rpq_insert_random(pq, nq, elem, key);
}

/*
 * Insert an element into the caller's home queue.
 *
 * Unlike rpq_insert which picks a random queue, this always targets
 * the queue at index (home % nr_queues) first. Falls back to random
 * queues on ENOSPC or lock failure. This gives each CPU a preferred
 * queue, improving cache locality on insert.
 *
 * @pq: Pointer to the relaxed priority queue.
 * @elem: Payload value to insert.
 * @key: Priority key (lower = higher priority).
 * @home: Home queue index (typically CPU ID).
 *
 * Returns 0 on success, -ENOSPC if all attempted queues are full,
 * or another negative errno on failure.
 */
__weak
int rpq_insert_home(rpq_t __arg_arena *pq, u64 elem, u64 key, u32 home)
{
	u32 nq;
	int ret;

	if (unlikely(!pq))
		return -EINVAL;

	nq = pq->nr_queues;
	if (unlikely(!nq))
		return -EINVAL;

	/* Try home queue first */
	ret = rpq_try_insert(&pq->queues[home % nq], elem, key);
	if (ret == 0)
		return 0;

	/* Fall back to random */
	return rpq_insert_random(pq, nq, elem, key);
}

/*
 * Pop retry body: given the best queue from sampling, lock and extract.
 * Returns 0 on success, -ENOENT if empty (caller retries), or
 * 1 if lock failed (caller retries).
 */
static inline int
rpq_try_pop(rpq_heap_t __arg_arena *heap, u64 *elem, u64 *key)
{
	int ret;

	ret = arena_spin_lock(&heap->lock);
	if (ret)
		return 1; /* lock failed */

	ret = rpq_heap_pop(heap, elem, key);
	arena_spin_unlock(&heap->lock);

	return ret;
}

/*
 * Pop the approximate minimum element from the relaxed priority queue.
 *
 * Uses the pick-d heuristic: peeks at d random heaps via cached
 * min_key (without locking), selects the one with the smallest
 * minimum, locks it, and extracts.
 *
 * @pq: Pointer to the relaxed priority queue.
 * @elem: Output parameter for the payload.
 * @key: Output parameter for the priority key.
 *
 * Returns 0 on success, -ENOENT if all queues are empty.
 */
__weak
int rpq_pop(rpq_t __arg_arena *pq, u64 *elem, u64 *key)
{
	u32 nq;
	int ret, i;

	if (unlikely(!pq || !elem || !key))
		return -EINVAL;

	nq = pq->nr_queues;
	if (unlikely(!nq))
		return -EINVAL;

	for (i = 0; i < RPQ_MAX_RETRIES && can_loop; i++) {
		u64 best_key = (u64)-1;
		u32 best_q = 0;
		int j;

		bpf_for(j, 0, pq->d) {
			u32 q = bpf_get_prandom_u32() % nq;
			u64 k = READ_ONCE(pq->queues[q].min_key);

			if (k < best_key) {
				best_key = k;
				best_q = q;
			}
		}

		if (best_key == (u64)-1)
			continue;

		ret = rpq_try_pop(&pq->queues[best_q], elem, key);
		if (ret == 0)
			return 0;
	}

	return -ENOENT;
}

/*
 * Pop with home queue bias.
 *
 * Like rpq_pop, but the home queue is always included as one of
 * the d sampled queues. The remaining d-1 samples are random.
 * This biases pops toward the caller's local queue, improving
 * cache locality when paired with rpq_insert_home.
 *
 * @pq: Pointer to the relaxed priority queue.
 * @elem: Output parameter for the payload.
 * @key: Output parameter for the priority key.
 * @home: Home queue index (typically CPU ID).
 *
 * Returns 0 on success, -ENOENT if all queues are empty.
 */
__weak
int rpq_pop_home(rpq_t __arg_arena *pq, u64 *elem, u64 *key, u32 home)
{
	u32 nq, home_q;
	int ret, i;

	if (unlikely(!pq || !elem || !key))
		return -EINVAL;

	nq = pq->nr_queues;
	if (unlikely(!nq))
		return -EINVAL;

	home_q = home % nq;

	for (i = 0; i < RPQ_MAX_RETRIES && can_loop; i++) {
		u64 best_key = (u64)-1;
		u32 best_q = 0;
		int j;

		/* Home queue is always the first sample */
		best_key = READ_ONCE(pq->queues[home_q].min_key);
		best_q = home_q;

		/* Then d-1 random samples */
		bpf_for(j, 1, pq->d) {
			u32 q = bpf_get_prandom_u32() % nq;
			u64 k = READ_ONCE(pq->queues[q].min_key);

			if (k < best_key) {
				best_key = k;
				best_q = q;
			}
		}

		if (best_key == (u64)-1)
			continue;

		ret = rpq_try_pop(&pq->queues[best_q], elem, key);
		if (ret == 0)
			return 0;
	}

	return -ENOENT;
}

/*
 * Peek at the approximate minimum without removing it.
 *
 * Samples several random heaps without locking and returns the
 * smallest minimum seen. The result may be stale by the time
 * the caller acts on it.
 *
 * @pq: Pointer to the relaxed priority queue.
 * @elem: Output parameter for the payload.
 * @key: Output parameter for the priority key.
 *
 * Returns 0 on success, -ENOENT if all sampled queues are empty.
 */
__weak
int rpq_peek(rpq_t __arg_arena *pq, u64 *elem, u64 *key)
{
	u64 best_key = (u64)-1;
	u64 cur_key;
	u32 nq, qi;
	int i;

	if (unlikely(!pq || !elem || !key))
		return -EINVAL;

	nq = pq->nr_queues;
	if (unlikely(!nq))
		return -EINVAL;

	/*
	 * Sample d random queues (matching pop's pick-d heuristic)
	 * and return the best minimum seen.
	 */
	for (i = 0; i < pq->d && can_loop; i++) {
		qi = bpf_get_prandom_u32() % nq;

		cur_key = READ_ONCE(pq->queues[qi].min_key);
		if (cur_key < best_key) {
			best_key = cur_key;
			/*
			 * Read elem under the assumption min_key is
			 * current. May be stale but that's acceptable
			 * for a lockless peek.
			 */
			*elem = READ_ONCE(pq->queues[qi].elems[0].elem);
			*key = cur_key;
		}
	}

	return (best_key == (u64)-1) ? -ENOENT : 0;
}

/*
 * Return the approximate total number of elements across all heaps.
 *
 * This is a lockless scan; the result may be slightly inaccurate
 * under concurrent modifications but is useful for diagnostics.
 *
 * @pq: Pointer to the relaxed priority queue.
 *
 * Returns the total element count (>= 0), or negative errno on error.
 */
__weak
int rpq_size(rpq_t __arg_arena *pq)
{
	u32 nq;
	int total = 0;
	int i;

	if (unlikely(!pq))
		return -EINVAL;

	nq = pq->nr_queues;

	for (i = 0; i < nq && can_loop; i++)
		total += READ_ONCE(pq->queues[i].size);

	return total;
}

__weak
int rpq_destroy(rpq_t __arg_arena *pq)
{
	if (unlikely(!pq))
		return -EINVAL;

	/* XXX Free when migrating from the static allocator. */
	return -EOPNOTSUPP;
}
