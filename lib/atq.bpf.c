#include <scx/common.bpf.h>
#include <lib/sdt_task.h>

#include <lib/atq.h>

/*
 * Arena task queue implementation.
 */

static struct scx_allocator scx_atq_allocator;

__weak
int scx_atq_init(void)
{
	return scx_alloc_init(&scx_atq_allocator, sizeof(scx_atq_t));
}

__weak
u64 scx_atq_create_internal(bool fifo, size_t capacity)
{
	struct sdt_data __arena *data = NULL;
	scx_atq_t *atq;

	/* Note that scx_alloc() returns a zero-initialized memory. */
	data = scx_alloc(&scx_atq_allocator);
	if (unlikely(!data))
		return (u64)NULL;

	atq = (scx_atq_t *)data->payload;
	atq->tid = data->tid;

	atq->tree = rb_create(RB_NOALLOC, RB_DUPLICATE);
	if (!atq->tree) {
		scx_alloc_free_idx(&scx_atq_allocator, atq->tid.idx);
		return (u64)NULL;
	}

	atq->fifo = fifo;
	atq->capacity = capacity;

	return (u64)atq;
}

__weak
int scx_atq_destroy(scx_atq_t __arg_arena *atq)
{
	scx_arena_subprog_init();

	while (scx_atq_pop(atq, false) && can_loop) {
		/* Do nothing. Just drain all the queued tasks. */
	}
	rb_destroy(atq->tree);

	scx_alloc_free_idx(&scx_atq_allocator, atq->tid.idx);
	return 0;
}

__hidden __inline
int scx_atq_insert_vtime_unlocked(scx_atq_t __arg_arena *atq, scx_task_common __arg_arena *taskc, u64 vtime)
{
	rbnode_t *node = &taskc->node;
	scx_atq_t *old_atq;
	int ret;

	if (unlikely(atq->size == atq->capacity))
		return -ENOSPC;

	if ((vtime == SCX_ATQ_FIFO) != atq->fifo)
		return -EINVAL;

	/*
	 * Claim the task with a single atomic election on ->atq. The field is
	 * not protected by the ATQ lock because a task may be inserted into
	 * different ATQs concurrently; cmpxchg picks one winner. The claim only
	 * succeeds from NULL, so a task already queued (a real BTQ pointer) or
	 * dying (SCX_ATQ_DEAD) is rejected.
	 */
	old_atq = cmpxchg(&taskc->atq, 0, atq);
	if (old_atq)
		return old_atq == (scx_atq_t *)SCX_ATQ_DEAD ? -ECANCELED : -EALREADY;

	/*
	 * For FIFO, "Leak" the seq on error. We only want
	 * sequence numbers to be monotonic, not
	 * consecutive.
	 */
	node->key = (vtime == SCX_ATQ_FIFO) ? atq->seq++ : vtime;
	node->value = (u64)taskc;

	ret = rb_insert_node(atq->tree, node);
	if (ret) {
		taskc->atq = NULL;
		return ret;
	}

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

	ret = scx_atq_lock(atq);
	if (ret)
		return ret;

	ret = scx_atq_insert_vtime_unlocked(atq, taskc, vtime);

	scx_atq_unlock(atq);

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

static __always_inline
int scx_atq_remove_internal(scx_atq_t *atq, scx_task_common __arg_arena *taskc,
			    bool dead)
{
	int ret;

	/*
	 * Are we in this ATQ in the first place?
	 *
	 * Note: Unlike in the insert path, the ATQ
	 * lock is valid enough protection here.
	 */
	if (taskc->atq != atq)
		return -EINVAL;

	ret = rb_remove_node(atq->tree, &taskc->node);
	if (ret)
		return ret;

	taskc->atq = dead ? (scx_atq_t *)SCX_ATQ_DEAD : NULL;

	atq->size -= 1;

	return 0;
}

__hidden
int scx_atq_remove_unlocked(scx_atq_t *atq, scx_task_common __arg_arena *taskc)
{
	return scx_atq_remove_internal(atq, taskc, false);
}

__hidden
int scx_atq_remove(scx_atq_t *atq, scx_task_common __arg_arena *taskc)
{
	int ret;

	ret = scx_atq_lock(atq);
	if (ret)
		return ret;

	ret = scx_atq_remove_internal(atq, taskc, false);

	scx_atq_unlock(atq);

	return ret;
}

__hidden
u64 scx_atq_pop(scx_atq_t *atq, bool hold)
{
	scx_task_common *taskc;
	u64 vtime, taskc_ptr;
	int ret;

	ret = scx_atq_lock(atq);
	if (ret)
		return (u64)NULL;

	if (!scx_atq_nr_queued(atq)) {
		scx_atq_unlock(atq);
		return (u64)NULL;
	}

	ret = rb_pop(atq->tree, &vtime, &taskc_ptr);
	if (ret) {
		scx_atq_unlock(atq);

		if (ret != -ENOENT)
			bpf_printk("%s: error %d", __func__, ret);
		return (u64)NULL;
	}

	atq->size -= 1;

	taskc = (scx_task_common *)taskc_ptr;
	if (hold)
		scx_atq_task_hold(taskc);

	taskc->atq = NULL;

	scx_atq_unlock(atq);

	return taskc_ptr;
}

__hidden
u64 scx_atq_peek(scx_atq_t *atq)
{
	u64 vtime, taskc_ptr;
	int ret;

	ret = scx_atq_lock(atq);
	if (ret)
		return (u64)NULL;

	if (!scx_atq_nr_queued(atq)) {
		scx_atq_unlock(atq);
		return (u64)NULL;
	}

	ret = rb_least(atq->tree, &vtime, &taskc_ptr);

	scx_atq_unlock(atq);

	return taskc_ptr;
}

__hidden
int scx_atq_nr_queued(scx_atq_t *atq)
{
	return atq->size;
}

/*
 * Detach a dying task from the ATQ subsystem so its context can be freed.
 *
 * Unlink it from whatever BTQ it currently sits in and latch SCX_ATQ_DEAD so
 * it can never be queued again. Then wait for any in-flight operation still
 * pinning the task to drop its hold, so the caller can safely free the task.
 */
__weak
int scx_atq_task_detach(scx_task_common __arg_arena *taskc)
{
	volatile int holdcnt;
	scx_atq_t *atq;
	int ret;

	while (can_loop) {
		atq = taskc->atq;
		if (atq == (scx_atq_t *)SCX_ATQ_DEAD)
			break;

		if (!atq) {
			if (!cmpxchg(&taskc->atq, 0, (scx_atq_t *)SCX_ATQ_DEAD))
				break;
			continue;
		}

		if ((ret = scx_atq_lock(atq))) {
			bpf_printk("Failed to lock ATQ for task");
			return ret;
		}

		if (taskc->atq != atq) {
			scx_atq_unlock(atq);
			continue;
		}

		ret = scx_atq_remove_internal(atq, taskc, true);
		scx_atq_unlock(atq);
		if (ret)
			return ret;
		break;
	}

	while ((holdcnt = taskc->holdcnt) > 0 && can_loop)
		;

	return 0;
}

/*
 * Cancel ATQ membership from the task itself, keeping it reusable. Returns 1
 * if this caller removed the task, 0 if it was not queued (or dying), or
 * -errno on failure.
 */
__weak
int scx_atq_task_fini(scx_task_common __arg_arena *taskc)
{
	scx_atq_t *atq;
	int ret;

	while (can_loop) {
		atq = taskc->atq;
		if (!atq || atq == (scx_atq_t *)SCX_ATQ_DEAD)
			return 0;

		if ((ret = scx_atq_lock(atq))) {
			bpf_printk("Failed to lock ATQ for task");
			return ret;
		}

		if (taskc->atq != atq) {
			scx_atq_unlock(atq);
			continue;
		}

		ret = scx_atq_remove_unlocked(taskc->atq, taskc);
		scx_atq_unlock(atq);
		return ret ? ret : 1;
	}

	return 0;
}
