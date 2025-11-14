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

__hidden __inline
int scx_atq_insert_vtime_unlocked(scx_atq_t __arg_arena *atq, scx_task_common __arg_arena *taskc, u64 vtime)
{
	rbnode_t *node = &taskc->node;
	int ret;

	if (unlikely(atq->size == atq->capacity))
		return -ENOSPC;

	if ((vtime == SCX_ATQ_FIFO) != atq->fifo)
		return -EINVAL;

	/*
	 * For FIFO, "Leak" the seq on error. We only want
	 * sequence numbers to be monotonic, not
	 * consecutive.
	 */
	node->key = (vtime == SCX_ATQ_FIFO) ? atq->seq++ : vtime;
	node->value = (u64)taskc;

	ret = rb_insert_node(atq->tree, node);
	if (ret)
		return ret;

	taskc->atq = atq;
	atq->size += 1;

	return 0;
}

/* 
 * XXXETSAL: We are using the __hidden antipattern for API functions because some
 * older kernels do not allow function calls with preemption disabled. We will replace
 * these annotations with the proper ones (__weak) at some point in the future.
 */

__hidden
int scx_atq_insert_vtime(scx_atq_t __arg_arena *atq, scx_task_common __arg_arena *taskc, u64 vtime)
{
	int ret;

	ret = arena_spin_lock(&atq->lock);
	if (ret)
		return ret;

	ret = scx_atq_insert_vtime_unlocked(atq, taskc, vtime);

	arena_spin_unlock(&atq->lock);

	return ret;
}

__hidden
int scx_atq_insert_unlocked(scx_atq_t *atq, scx_task_common __arg_arena *taskc)
{
	return scx_atq_insert_vtime_unlocked(atq, taskc, SCX_ATQ_FIFO);
}

__hidden
int scx_atq_insert(scx_atq_t *atq, scx_task_common __arg_arena *taskc)
{
	return scx_atq_insert_vtime(atq, taskc, SCX_ATQ_FIFO);
}

__hidden
int scx_atq_remove_unlocked(scx_atq_t *atq, scx_task_common __arg_arena *taskc)
{
	int ret;

       /* Are we in this ATQ in the first place? */
       if (taskc->atq != atq)
	       return -EINVAL;

       ret = rb_remove_node(atq->tree, &taskc->node);
       taskc->atq = NULL;

       return ret;
}

__hidden
int scx_atq_remove(scx_atq_t *atq, scx_task_common __arg_arena *taskc)
{
       int ret;

       ret = arena_spin_lock(&atq->lock);
       if (ret)
               return ret;

       ret = scx_atq_remove_unlocked(atq, taskc);

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

/*
 * Cancel ATQ membership for the task. Find any ATQs it is
 * in and pop it out.
 */
__weak
int scx_atq_cancel(scx_task_common __arg_arena *taskc)
{
	scx_atq_t *atq;
	int ret;

	/*
	 * Copy the ATQ pointer over to the stack and use it to avoid
	 * a racing scx_atq_pop() from overwriting it. Check the
	 * pointer is valid, as expected by the caller.
	 */
	atq = taskc->atq;
	if (!atq)
		return 0;

	if ((ret = scx_atq_lock(atq))) {
		bpf_printk("Failed to lock ATQ for task");
		return ret;
	}

	/* We lost the race, assume whoever popped the task will handle it. */
	if (taskc->atq != atq) {
		scx_atq_unlock(atq);
		return 0;
	}

	/* Protected from races by the lock. */
	if ((ret = scx_atq_remove_unlocked(taskc->atq, taskc))) {
		/* There is an unavoidable race with scx_atq_pop. */
		bpf_printk("Failed to remove node from task");
	}

	scx_atq_unlock(atq);
	return ret;
}

