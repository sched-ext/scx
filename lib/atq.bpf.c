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

	while (scx_atq_pop(atq) && can_loop) {
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
	int ret;

	if (unlikely(atq->size == atq->capacity))
		return -ENOSPC;

	if ((vtime == SCX_ATQ_FIFO) != atq->fifo)
		return -EINVAL;

	/*
	 * The ->atq field is not protected by the ATQ
	 * lock, since multiple callers may be trying to
	 * add the same task to differnt ATQs. Use atomic
	 * cmpxchg so that races have a single winner.
	 */
	if (cmpxchg(&taskc->atq, 0, atq))
		return -EALREADY;

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

__hidden
int scx_atq_remove_unlocked(scx_atq_t *atq, scx_task_common __arg_arena *taskc)
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

       taskc->atq = NULL;

       atq->size -= 1;

       return 0;
}

__hidden
int scx_atq_remove(scx_atq_t *atq, scx_task_common __arg_arena *taskc)
{
       int ret;

       ret = scx_atq_lock(atq);
       if (ret)
               return ret;

       ret = scx_atq_remove_unlocked(atq, taskc);

       scx_atq_unlock(atq);

       return ret;
}

__hidden
u64 scx_atq_pop(scx_atq_t *atq)
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
	taskc->atq = NULL;

	scx_atq_unlock(atq);

	return taskc_ptr;
}

/*
 * Lock two distinct ATQs, lowest address first, to avoid ABBA deadlock with
 * a concurrent move in the opposite direction. @a and @b must differ;
 * scx_atq_move_vtime() rejects @src == @dst before calling this. Keeping the
 * lock count unconditional (always two) also keeps the verifier's
 * preempt-disable/enable balance provable.
 */
static __always_inline
int scx_atq_lock2(scx_atq_t *a, scx_atq_t *b)
{
	scx_atq_t *first, *second;
	int ret;

	if ((u64)a < (u64)b) {
		first = a;
		second = b;
	} else {
		first = b;
		second = a;
	}

	if ((ret = scx_atq_lock(first)))
		return ret;
	if ((ret = scx_atq_lock(second))) {
		scx_atq_unlock(first);
		return ret;
	}

	return 0;
}

static __always_inline
void scx_atq_unlock2(scx_atq_t *a, scx_atq_t *b)
{
	scx_atq_t *first, *second;

	if ((u64)a < (u64)b) {
		first = a;
		second = b;
	} else {
		first = b;
		second = a;
	}

	scx_atq_unlock(second);
	scx_atq_unlock(first);
}

/*
 * Atomically move the front (min-key) task of @src into @dst, re-keyed by
 * @vtime. Both ATQ locks are held across the move and the task's ->atq is
 * updated directly from @src to @dst, so a lockless reader of ->atq never
 * observes the transient NULL that a separate scx_atq_pop()+insert() would
 * expose. Locks are taken lowest-address-first (see scx_atq_lock2()).
 *
 * On insertion failure the task is left in @src; it is never lost.
 *
 * Return the moved task (scx_task_common *) as u64, or (u64)NULL if @src is
 * empty or the move failed.
 */
__hidden
u64 scx_atq_move_vtime(scx_atq_t *src, scx_atq_t *dst, u64 vtime)
{
	scx_task_common *taskc;
	rbnode_t *node;
	u64 src_key, taskc_ptr;
	int ret;

	/*
	 * Relocation is between distinct ATQs; @src == @dst would self-deadlock
	 * in scx_atq_lock2(). Reject it before locking.
	 */
	if (src == dst)
		return (u64)NULL;

	ret = scx_atq_lock2(src, dst);
	if (ret)
		return (u64)NULL;

	/* Same FIFO/vtime discipline as scx_atq_insert_vtime_unlocked(). */
	if ((vtime == SCX_ATQ_FIFO) != dst->fifo)
		goto out_unlock;

	/* Need room in @dst before removing from @src. */
	if (dst->size == dst->capacity)
		goto out_unlock;

	if (!scx_atq_nr_queued(src))
		goto out_unlock;

	ret = rb_pop(src->tree, &src_key, &taskc_ptr);
	if (ret) {
		if (ret != -ENOENT)
			bpf_printk("%s: src error %d", __func__, ret);
		goto out_unlock;
	}
	src->size -= 1;

	taskc = (scx_task_common *)taskc_ptr;
	node = &taskc->node;

	/* The node still carries value == taskc from @src; only re-key it. */
	node->key = (vtime == SCX_ATQ_FIFO) ? dst->seq++ : vtime;

	ret = rb_insert_node(dst->tree, node);
	if (ret) {
		/*
		 * Couldn't insert into @dst after popping from @src. Restore
		 * the task to @src so it is never lost. The capacity check
		 * above makes this unreachable in practice.
		 */
		node->key = src_key;
		if (!rb_insert_node(src->tree, node))
			src->size += 1;
		else
			bpf_printk("%s: failed to restore task to src", __func__);
		goto out_unlock;
	}

	dst->size += 1;

	/*
	 * Publish the new owner. Both ATQ locks are held, so no concurrent
	 * pop/cancel/insert can run on @src or @dst; ->atq transitions
	 * directly from @src to @dst and is never observed as NULL.
	 */
	taskc->atq = dst;

	scx_atq_unlock2(src, dst);
	return taskc_ptr;

out_unlock:
	scx_atq_unlock2(src, dst);
	return (u64)NULL;
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
 * Cancel ATQ membership for the task. Find any ATQs it is
 * in and pop it out.
 */
__weak
int scx_atq_cancel(scx_task_common __arg_arena *taskc)
{
	scx_atq_t *atq;
	int ret;

	/*
	 * scx_atq_move_vtime() acquires both ATQ locks up front and only drops
	 * them after publishing the new owner (taskc->atq = dst), so a task's
	 * ATQ membership changes atomically: ->atq is safe to read locklessly --
	 * never NULL, never torn. But that does not pin the value across the gap
	 * between our lockless read and our lock acquisition, so a move can slip
	 * in between them:
	 *
	 *   1. we snapshot atq = taskc->atq, holding no lock yet;
	 *   2. a move relocates the task out of atq into another ATQ and
	 *      completes -- it acquired atq's lock before we did;
	 *   3. we finally acquire atq's lock and observe taskc->atq != atq.
	 *
	 * At step 3 we are holding the wrong ATQ's lock and must not touch the
	 * node, so we re-snapshot ->atq and retry against the ATQ the task now
	 * lives in. can_loop bounds the retries; in the common, race-free case
	 * the loop body runs exactly once.
	 */
	while (can_loop) {
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

		/* Relocated after our snapshot; retry against the new ATQ. */
		if (taskc->atq != atq) {
			scx_atq_unlock(atq);
			continue;
		}

		/* Protected from races by the lock. */
		if ((ret = scx_atq_remove_unlocked(taskc->atq, taskc))) {
			/* There is an unavoidable race with scx_atq_pop. */
			bpf_printk("Failed to remove node from task");
		}

		scx_atq_unlock(atq);
		return ret;
	}

	return 0;
}

