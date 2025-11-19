#include <scx/common.bpf.h>
#include <lib/sdt_task.h>

#include <lib/dhq.h>

/*
 * Double Helix Queue (DHQ) implementation.
 *
 * Inspired by DNA's double helix structure, this queue maintains two
 * parallel strands that can be accessed independently or in coordinated
 * fashion. Supports multiple dequeue strategies: alternating between
 * strands, priority-based selection, or balanced distribution.
 *
 * Fixed-size implementation: Uses minheap with pre-allocated capacity
 * to avoid sleepable allocations in fast path (enqueue/dequeue). This
 * makes DHQ usable in non-sleepable contexts like BPF enqueue callbacks.
 */

__weak
u64 scx_dhq_create_internal(bool fifo, size_t capacity, u64 mode, u64 max_imbalance)
{
	scx_dhq_t *dhq;
	u64 heap_capacity;

	dhq = scx_static_alloc(sizeof(*dhq), 1);
	if (!dhq)
		return (u64)NULL;

	/* Split capacity evenly between the two strands */
	heap_capacity = capacity / 2;

	dhq->strand_a = scx_minheap_alloc(heap_capacity);
	if (!dhq->strand_a)
		return (u64)NULL;

	dhq->strand_b = scx_minheap_alloc(heap_capacity);
	if (!dhq->strand_b)
		return (u64)NULL;

	dhq->fifo = fifo;
	dhq->capacity = capacity;
	dhq->mode = mode;
	dhq->max_imbalance = max_imbalance;
	dhq->last_strand = SCX_DHQ_STRAND_B;

	/* Note: BPF arena memory is zero-initialized, so size_a, size_b, seq_a, seq_b, dequeue_count_* are already 0 */

	return (u64)dhq;
}

static inline
int __scx_dhq_insert_strand(scx_dhq_t *dhq, u64 taskc_ptr, u64 strand, u64 key)
{
	scx_minheap_t *heap;
	u64 my_size, other_size;
	int ret;

	heap = (strand == SCX_DHQ_STRAND_A) ? dhq->strand_a : dhq->strand_b;

	ret = arena_spin_lock(&dhq->lock);
	if (ret)
		return ret;

	/* Check total capacity */
	if (unlikely(dhq->size_a + dhq->size_b == dhq->capacity)) {
		ret = -ENOSPC;
		goto error;
	}

	/* Check strand intertwining constraint for enqueue:
	 * Prevent one strand from having too many more items than the other.
	 * This keeps the double helix "complete" - strands must stay paired.
	 */
	if (dhq->max_imbalance > 0) {
		if (strand == SCX_DHQ_STRAND_A) {
			my_size = dhq->size_a;
			other_size = dhq->size_b;
		} else {
			my_size = dhq->size_b;
			other_size = dhq->size_a;
		}

		/* If enqueueing to this strand would create too large a size imbalance, fail */
		if (my_size >= other_size + dhq->max_imbalance) {
			ret = -EAGAIN;  /* Try again later when strands are more balanced */
			goto error;
		}
	}

	ret = scx_minheap_insert(heap, taskc_ptr, key);
	if (ret)
		goto error;

	if (strand == SCX_DHQ_STRAND_A)
		dhq->size_a += 1;
	else
		dhq->size_b += 1;

	arena_spin_unlock(&dhq->lock);

	return 0;

error:
	arena_spin_unlock(&dhq->lock);

	return ret;
}

__hidden
int scx_dhq_insert(scx_dhq_t *dhq, u64 taskc_ptr, u64 strand)
{
	u64 key, selected_strand;

	if (!dhq->fifo)
		return -EINVAL;

	/* Auto-select strand based on balance mode */
	if (strand == SCX_DHQ_STRAND_AUTO) {
		/* Choose less full strand */
		selected_strand = (dhq->size_a <= dhq->size_b) ?
				  SCX_DHQ_STRAND_A : SCX_DHQ_STRAND_B;
	} else {
		selected_strand = strand;
	}

	/* Get sequence number for selected strand */
	if (selected_strand == SCX_DHQ_STRAND_A) {
		key = dhq->seq_a++;
	} else {
		key = dhq->seq_b++;
	}

	return __scx_dhq_insert_strand(dhq, taskc_ptr, selected_strand, key);
}

__hidden
int scx_dhq_insert_vtime(scx_dhq_t *dhq, u64 taskc_ptr, u64 vtime, u64 strand)
{
	u64 selected_strand;

	if (dhq->fifo)
		return -EINVAL;

	/* Auto-select strand based on balance mode */
	if (strand == SCX_DHQ_STRAND_AUTO) {
		/* Choose less full strand */
		selected_strand = (dhq->size_a <= dhq->size_b) ?
				  SCX_DHQ_STRAND_A : SCX_DHQ_STRAND_B;
	} else {
		selected_strand = strand;
	}

	return __scx_dhq_insert_strand(dhq, taskc_ptr, selected_strand, vtime);
}

static inline
u64 __scx_dhq_pop_strand_nolock(scx_dhq_t *dhq, u64 strand)
{
	scx_minheap_t *heap;
	struct scx_minheap_elem helem;
	int ret;

	heap = (strand == SCX_DHQ_STRAND_A) ? dhq->strand_a : dhq->strand_b;

	/* Check if strand is empty */
	if ((strand == SCX_DHQ_STRAND_A && dhq->size_a == 0) ||
	    (strand == SCX_DHQ_STRAND_B && dhq->size_b == 0))
		return (u64)NULL;

	/* NOTE: No dequeue_count imbalance constraint for cross-LLC migration.
	 * We only enforce size balance on enqueue to prevent one LLC from
	 * flooding the DHQ. On dequeue, we allow asymmetric consumption so
	 * idle LLCs can steal work from busy LLCs without being blocked.
	 */

	ret = scx_minheap_pop(heap, &helem);
	if (!ret) {
		if (strand == SCX_DHQ_STRAND_A) {
			dhq->size_a -= 1;
			dhq->dequeue_count_a += 1;
		} else {
			dhq->size_b -= 1;
			dhq->dequeue_count_b += 1;
		}
		return helem.elem;
	}

	return (u64)NULL;
}

__hidden
u64 scx_dhq_pop_strand(scx_dhq_t *dhq, u64 strand)
{
	u64 taskc_ptr;
	int ret;

	ret = arena_spin_lock(&dhq->lock);
	if (ret)
		return (u64)NULL;

	taskc_ptr = __scx_dhq_pop_strand_nolock(dhq, strand);

	arena_spin_unlock(&dhq->lock);

	return taskc_ptr;
}

__hidden
u64 scx_dhq_pop(scx_dhq_t *dhq)
{
	u64 taskc_ptr;
	u64 vtime_a, vtime_b;
	u64 strand;
	int ret;

	ret = arena_spin_lock(&dhq->lock);
	if (ret)
		return (u64)NULL;

	/* If empty, return NULL */
	if (scx_dhq_nr_queued(dhq) == 0) {
		arena_spin_unlock(&dhq->lock);
		return (u64)NULL;
	}

	switch (dhq->mode) {
	case SCX_DHQ_MODE_ALTERNATING:
		/*
		 * Alternate between strands. If selected strand is empty,
		 * try the other strand.
		 */
		strand = (dhq->last_strand == SCX_DHQ_STRAND_A) ?
			 SCX_DHQ_STRAND_B : SCX_DHQ_STRAND_A;

		taskc_ptr = __scx_dhq_pop_strand_nolock(dhq, strand);
		if (!taskc_ptr) {
			/* Try other strand */
			strand = (strand == SCX_DHQ_STRAND_A) ?
				 SCX_DHQ_STRAND_B : SCX_DHQ_STRAND_A;
			taskc_ptr = __scx_dhq_pop_strand_nolock(dhq, strand);
		}

		if (taskc_ptr)
			dhq->last_strand = strand;
		break;

	case SCX_DHQ_MODE_PRIORITY:
		/*
		 * Select task with lowest vtime from either strand.
		 * Peek at both strands and compare.
		 * If the preferred strand is blocked (imbalance), try the other.
		 */
		if (dhq->strand_a->size > 0) {
			vtime_a = dhq->strand_a->helems[0].weight;
		} else {
			vtime_a = (u64)-1; /* Max value if strand A empty */
		}

		if (dhq->strand_b->size > 0) {
			vtime_b = dhq->strand_b->helems[0].weight;
		} else {
			vtime_b = (u64)-1; /* Max value if strand B empty */
		}

		if (vtime_a <= vtime_b) {
			taskc_ptr = __scx_dhq_pop_strand_nolock(dhq, SCX_DHQ_STRAND_A);
			if (!taskc_ptr) {
				/* Strand A blocked by imbalance or empty, try B */
				taskc_ptr = __scx_dhq_pop_strand_nolock(dhq, SCX_DHQ_STRAND_B);
				if (taskc_ptr)
					dhq->last_strand = SCX_DHQ_STRAND_B;
			} else {
				dhq->last_strand = SCX_DHQ_STRAND_A;
			}
		} else {
			taskc_ptr = __scx_dhq_pop_strand_nolock(dhq, SCX_DHQ_STRAND_B);
			if (!taskc_ptr) {
				/* Strand B blocked by imbalance or empty, try A */
				taskc_ptr = __scx_dhq_pop_strand_nolock(dhq, SCX_DHQ_STRAND_A);
				if (taskc_ptr)
					dhq->last_strand = SCX_DHQ_STRAND_A;
			} else {
				dhq->last_strand = SCX_DHQ_STRAND_B;
			}
		}
		break;

	case SCX_DHQ_MODE_BALANCED:
		/*
		 * Maintain balance: prefer strand with more tasks.
		 * This helps keep the strands roughly equal in size.
		 */
		if (dhq->size_a >= dhq->size_b) {
			taskc_ptr = __scx_dhq_pop_strand_nolock(dhq, SCX_DHQ_STRAND_A);
			if (!taskc_ptr)
				taskc_ptr = __scx_dhq_pop_strand_nolock(dhq, SCX_DHQ_STRAND_B);
			else
				dhq->last_strand = SCX_DHQ_STRAND_A;
		} else {
			taskc_ptr = __scx_dhq_pop_strand_nolock(dhq, SCX_DHQ_STRAND_B);
			if (!taskc_ptr)
				taskc_ptr = __scx_dhq_pop_strand_nolock(dhq, SCX_DHQ_STRAND_A);
			else
				dhq->last_strand = SCX_DHQ_STRAND_B;
		}
		break;

	default:
		taskc_ptr = (u64)NULL;
		break;
	}

	arena_spin_unlock(&dhq->lock);

	return taskc_ptr;
}

static inline
u64 __scx_dhq_peek_strand_nolock(scx_dhq_t *dhq, u64 strand)
{
	scx_minheap_t *heap;

	heap = (strand == SCX_DHQ_STRAND_A) ? dhq->strand_a : dhq->strand_b;

	if (heap->size == 0)
		return (u64)NULL;

	return heap->helems[0].elem;
}

__hidden
u64 scx_dhq_peek_strand(scx_dhq_t *dhq, u64 strand)
{
	u64 taskc_ptr;
	int ret;

	ret = arena_spin_lock(&dhq->lock);
	if (ret)
		return (u64)NULL;

	taskc_ptr = __scx_dhq_peek_strand_nolock(dhq, strand);

	arena_spin_unlock(&dhq->lock);

	return taskc_ptr;
}

__hidden
u64 scx_dhq_peek(scx_dhq_t *dhq)
{
	u64 taskc_ptr;
	u64 vtime_a, vtime_b;
	u64 strand;
	int ret;

	ret = arena_spin_lock(&dhq->lock);
	if (ret)
		return (u64)NULL;

	if (scx_dhq_nr_queued(dhq) == 0) {
		arena_spin_unlock(&dhq->lock);
		return (u64)NULL;
	}

	switch (dhq->mode) {
	case SCX_DHQ_MODE_ALTERNATING:
		/* Peek at next strand in alternation */
		strand = (dhq->last_strand == SCX_DHQ_STRAND_A) ?
			 SCX_DHQ_STRAND_B : SCX_DHQ_STRAND_A;

		taskc_ptr = __scx_dhq_peek_strand_nolock(dhq, strand);
		if (!taskc_ptr) {
			/* Try other strand */
			strand = (strand == SCX_DHQ_STRAND_A) ?
				 SCX_DHQ_STRAND_B : SCX_DHQ_STRAND_A;
			taskc_ptr = __scx_dhq_peek_strand_nolock(dhq, strand);
		}
		break;

	case SCX_DHQ_MODE_PRIORITY:
		/* Peek at task with lowest vtime */
		if (dhq->strand_a->size > 0) {
			vtime_a = dhq->strand_a->helems[0].weight;
		} else {
			vtime_a = (u64)-1;
		}

		if (dhq->strand_b->size > 0) {
			vtime_b = dhq->strand_b->helems[0].weight;
		} else {
			vtime_b = (u64)-1;
		}

		if (vtime_a <= vtime_b)
			taskc_ptr = __scx_dhq_peek_strand_nolock(dhq, SCX_DHQ_STRAND_A);
		else
			taskc_ptr = __scx_dhq_peek_strand_nolock(dhq, SCX_DHQ_STRAND_B);
		break;

	case SCX_DHQ_MODE_BALANCED:
		/* Peek at strand with more tasks */
		if (dhq->size_a >= dhq->size_b) {
			taskc_ptr = __scx_dhq_peek_strand_nolock(dhq, SCX_DHQ_STRAND_A);
			if (!taskc_ptr)
				taskc_ptr = __scx_dhq_peek_strand_nolock(dhq, SCX_DHQ_STRAND_B);
		} else {
			taskc_ptr = __scx_dhq_peek_strand_nolock(dhq, SCX_DHQ_STRAND_B);
			if (!taskc_ptr)
				taskc_ptr = __scx_dhq_peek_strand_nolock(dhq, SCX_DHQ_STRAND_A);
		}
		break;

	default:
		taskc_ptr = (u64)NULL;
		break;
	}

	arena_spin_unlock(&dhq->lock);

	return taskc_ptr;
}

__hidden
int scx_dhq_nr_queued(scx_dhq_t *dhq)
{
	return dhq->size_a + dhq->size_b;
}

__hidden
int scx_dhq_nr_queued_strand(scx_dhq_t *dhq, u64 strand)
{
	return (strand == SCX_DHQ_STRAND_A) ? dhq->size_a : dhq->size_b;
}
