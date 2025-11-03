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

	atq->tree = rb_create(RB_NOALLOC, RB_DUPLICATE);
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
int scx_atq_insert_vtime(scx_atq_t __arg_arena *atq, scx_task_common __arg_arena *taskc, u64 vtime)
{
	rbnode_t *node = &taskc->node;
	int ret;

	ret = arena_spin_lock(&atq->lock);
	if (ret)
		return ret;

	if (unlikely(atq->size == atq->capacity)) {
		ret = -ENOSPC;
		goto done;
	}

	if ((vtime == SCX_ATQ_FIFO) != atq->fifo) {
		ret = -EINVAL;
		goto done;
	}

	/*
	 * For FIFO, "Leak" the seq on error. We only want
	 * sequence numbers to be monotonic, not
	 * consecutive.
	 */
	node->key = (vtime == SCX_ATQ_FIFO) ? atq->seq++ : vtime;
	node->value = (u64)taskc;

	ret = rb_insert_node(atq->tree, node);
	if (ret)
		goto done;

	taskc->atq = atq;
	atq->size += 1;

done:
	arena_spin_unlock(&atq->lock);

	return ret;
}

__hidden
int scx_atq_insert(scx_atq_t *atq, scx_task_common __arg_arena *taskc)
{
	return scx_atq_insert_vtime(atq, taskc, SCX_ATQ_FIFO);
}

__hidden
int scx_atq_remove(scx_atq_t *atq, scx_task_common __arg_arena *taskc)
{
       int ret;

       ret = arena_spin_lock(&atq->lock);
       if (ret)
               return ret;

       /* Are we in this ATQ in the first place? */
       if (taskc->atq != atq) {
	       arena_spin_unlock(&atq->lock);
	       return -EINVAL;
       }

       ret = rb_remove_node(atq->tree, &taskc->node);
       taskc->atq = NULL;

       arena_spin_unlock(&atq->lock);

       return ret;
}

__hidden
u64 scx_atq_pop(scx_atq_t *atq)
{
	scx_task_common *taskc;
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

	taskc = (scx_task_common *)taskc_ptr;
	taskc->atq = NULL;

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
