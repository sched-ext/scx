#include "scxtest/scx_test.h"
#include <scx/common.bpf.h>
#include <lib/sdt_task.h>

#include <lib/atq.h>

/*
 * Arena task queue implementation.
 */

__weak
u64 scx_atq_create_internal(bool fifo, size_t capacity)
{
	scx_atq_t *atq;

	atq = scx_static_alloc(sizeof(*atq), 1);
	if (!atq)
		return (u64)NULL;

	atq->heap = scx_minheap_alloc(capacity);
	if (!atq->heap)
		return (u64)NULL;

	atq->fifo = fifo;

	return (u64)atq;
}

__hidden
int scx_atq_insert(scx_atq_t *atq, u64 taskc_ptr)
{
	int ret;

	if (!atq->fifo)
		return -EINVAL;

	ret = arena_spin_lock(&atq->lock);
	if (ret)
		return ret;

	ret = scx_minheap_insert(atq->heap, taskc_ptr, atq->seq++);

	arena_spin_unlock(&atq->lock);

	return ret;
}

__hidden
int scx_atq_insert_vtime(scx_atq_t *atq, u64 taskc_ptr, u64 vtime)
{
	int ret;

	if (atq->fifo)
		return -EINVAL;

	ret = arena_spin_lock(&atq->lock);
	if (ret)
		return ret;

	ret = scx_minheap_insert(atq->heap, taskc_ptr, vtime);

	arena_spin_unlock(&atq->lock);

	return ret;
}

__hidden
u64 scx_atq_pop(scx_atq_t *atq)
{
	struct scx_minheap_elem helem;
	int ret;

	ret = arena_spin_lock(&atq->lock);
	if (ret)
		return (u64)NULL;

	if (!scx_atq_nr_queued(atq)) {
		arena_spin_unlock(&atq->lock);
		return (u64)NULL;
	}

	ret = scx_minheap_pop(atq->heap, &helem);

	arena_spin_unlock(&atq->lock);

	if (ret)
		return (u64)NULL;

	return helem.elem;
}

__hidden
u64 scx_atq_peek(scx_atq_t *atq)
{
	u64 elem;
	int ret;

	ret = arena_spin_lock(&atq->lock);
	if (ret)
		return (u64)NULL;

	if (!scx_atq_nr_queued(atq)) {
		arena_spin_unlock(&atq->lock);
		return (u64)NULL;
	}

	elem = atq->heap->helems[0].elem;

	arena_spin_unlock(&atq->lock);

	return elem;
}

__hidden
int scx_atq_nr_queued(scx_atq_t *atq)
{
	return atq->heap->size;
}
