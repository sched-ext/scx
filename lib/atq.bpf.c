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

	atq->tree = rb_create(RB_ALLOC);
	if (!atq->tree)
		return (u64)NULL;

	atq->fifo = fifo;
	atq->capacity = capacity;
	atq->size = 0;

	return (u64)atq;
}

/* 
 * XXXETSAL: We are using the __hidden antipattern for API functions because some
 * older kernels do not allow function calls with preemption disabled. We will replace
 * these annotations with the proper ones (__weak) at some point in the future.
 */

__hidden
int scx_atq_insert_node(scx_atq_t __arg_arena *atq, rbnode_t __arg_arena *node, u64 key)
{
	int ret;

	ret = arena_spin_lock(&atq->lock);
	if (ret)
		return ret;

	if (unlikely(atq->size == atq->capacity)) {
		ret = -ENOSPC;
		goto done;
	}

	if ((key == SCX_ATQ_FIFO) != atq->fifo) {
		ret = -EINVAL;
		goto done;
	}

	/*
	 * For FIFO, "Leak" the seq on error. We only want
	 * sequence numbers to be monotonic, not
	 * consecutive.
	 */
	node->key = (key == SCX_ATQ_FIFO) ? atq->seq++ : key;

	ret = rb_insert_node(atq->tree, node, RB_DUPLICATE);
	if (ret)
		goto done;

	atq->size += 1;

done:
	arena_spin_unlock(&atq->lock);

	return ret;
}

__hidden
int scx_atq_insert_vtime(scx_atq_t *atq, u64 taskc_ptr, u64 vtime)
{
	rbnode_t *node;
	int ret;

	/*
	 * Use dummy sequence number because we're
	 * outside of the critical section.
	 */
	node = rb_node_alloc(atq->tree, 0, taskc_ptr);
	if (!node)
		return -ENOMEM;

	ret = scx_atq_insert_node(atq, node, vtime);
	if (ret) {
		rb_node_free(atq->tree, node);
		return ret;
	}

	return 0;
}

__hidden
int scx_atq_insert(scx_atq_t *atq, u64 taskc_ptr)
{
	return scx_atq_insert_vtime(atq, taskc_ptr, SCX_ATQ_FIFO);
}

__hidden
u64 scx_atq_pop(scx_atq_t *atq)
{
	u64 vtime, taskc_ptr;
	int ret;

	ret = arena_spin_lock(&atq->lock);
	if (ret)
		return (u64)NULL;

	if (!scx_atq_nr_queued(atq)) {
		arena_spin_unlock(&atq->lock);
		return (u64)NULL;
	}

	ret = rb_pop(atq->tree, &vtime, &taskc_ptr);
	if (!ret)
		atq->size -= 1;

	arena_spin_unlock(&atq->lock);

	if (ret) {
		if (ret != -ENOENT)
			bpf_printk("%s: error %d", __func__, ret);
		return (u64)NULL;
	}

	return taskc_ptr;
}

__hidden
u64 scx_atq_peek(scx_atq_t *atq)
{
	u64 vtime, taskc_ptr;
	int ret;

	ret = arena_spin_lock(&atq->lock);
	if (ret)
		return (u64)NULL;

	if (!scx_atq_nr_queued(atq)) {
		arena_spin_unlock(&atq->lock);
		return (u64)NULL;
	}

	ret = rb_least(atq->tree, &vtime, &taskc_ptr);

	arena_spin_unlock(&atq->lock);

	return taskc_ptr;
}

__hidden
int scx_atq_nr_queued(scx_atq_t *atq)
{
	return atq->size;
}
