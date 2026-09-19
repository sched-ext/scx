/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.
 *
 * The per-cid runnable queue: the EDQ node a task carries, the state that
 * says whose it is, and the inserts and pops the callbacks make of it. The
 * bitmap of the cids that have something queued is kept here too, next to
 * what changes it.
 */
#pragma once

#include "eevdf.bpf.h"

static cid_edq_task_t *cid_edq_task(task_ctx_t *tctx)
{
	return tctx ? &tctx->se.edq : NULL;
}

/*
 * Queue inspection is advisory. Never join a contended lock wait from a
 * preemption decision or a remote steal scan; the queue owner will make
 * progress and a later dispatch can try again.
 */
static int cid_edq_try_peek_next(s32 cid, scx_edq_cursor_t *cursor,
				 cid_edq_task_t **atp)
{
	u64 task;
	int ret;

	*atp = NULL;
	ret = scx_edq_try_peek_next_hold(&cid_pack(cid)->edq, cursor, &task);
	if (ret) {
		if (ret != -EBUSY)
			scx_bpf_error("EDQ cursor peek failed for cid %d: %d",
				      cid, ret);
		return ret;
	}
	*atp = (cid_edq_task_t *)task;
	return 0;
}

static void cid_edq_mark_dispatched(task_ctx_t *tctx)
{
	cid_edq_task_t *at;

	at = cid_edq_task(tctx);
	if (at)
		WRITE_ONCE(at->state, CID_EDQ_DISPATCHED);
}

static u32 cid_queue_nr(s32 cid)
{
	return scx_edq_nr_queued(&cid_pack(cid)->edq);
}

/*
 * Return the sched_ext tid at the EDQ head, or 0. For the cid's own ops
 * only: they hold the rq lock, so the only other holder of the lock is a
 * remote trylocker in a short peek or remove, and waiting for it is
 * cheaper than skipping the decision. peek_hold keeps the arena object
 * alive across the unlocked tid load; the caller resolves it under RCU.
 */
static u64 cid_edq_peek_tid_owned(s32 cid)
{
	cid_edq_task_t *at;
	u64 tid = 0;

	at = (cid_edq_task_t *)scx_edq_peek_hold(&cid_pack(cid)->edq);
	if (at) {
		tid = at->tid;
		scx_edq_task_drop(&at->common);
	}
	return tid;
}

/*
 * scx_bpf_tid_to_task() returns an RCU-protected pointer. Every lookup below
 * runs from a non-sleepable struct_ops callback, which BPF treats as an
 * implicit RCU read-side critical section. Keep lookups out of sleepable ops.
 */
static __noinline bool cid_edq_dispatch_popped(cid_edq_task_t *at,
					       struct task_struct *p, s32 dst_cid)
{
	if (__sync_val_compare_and_swap(&at->state, CID_EDQ_ENQUEUED,
					CID_EDQ_DISPATCHING) != CID_EDQ_ENQUEUED) {
		scx_edq_task_drop(&at->common);
		return false;
	}
	if (!p)
		p = scx_bpf_tid_to_task(at->tid);
	if (!p) {
		/*
		 * The sched_ext tid remains resolvable through task exit. Failure here
		 * means the queue entry outlived the task or was otherwise corrupted;
		 * fail into scheduler rescue rather than silently losing its only
		 * runnable-queue entry.
		 */
		scx_bpf_error("EDQ cannot resolve queued tid %llu", at->tid);
		scx_edq_task_drop(&at->common);
		return false;
	}
	if (!is_task_queued(p)) {
		scx_edq_task_drop(&at->common);
		return false;
	}
	if (READ_ONCE(at->state) != CID_EDQ_DISPATCHING) {
		scx_edq_task_drop(&at->common);
		return false;
	}
	/*
	 * The task's affinity can change after EDQ selected it. Unlike a DSQ
	 * move, a direct LOCAL insertion with a now-invalid destination is a
	 * scheduler error. A changed affinity belongs to a scheduler-property
	 * workflow: drop this old pop and let the core's matching enqueue place the
	 * task again, as fair's sched_change dequeue/enqueue pair does.
	 */
	if (is_restricted(p) && !cid_allowed(p, dst_cid)) {
		scx_edq_task_drop(&at->common);
		return false;
	}

	scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, at->slice, at->enq_flags);
	scx_edq_task_drop(&at->common);
	return true;
}

enum cid_edq_move_result {
	CID_EDQ_MOVE_MISS,
	CID_EDQ_MOVE_MOVED,
	CID_EDQ_MOVE_BUSY,
};

static __noinline enum cid_edq_move_result
cid_edq_remove_held_to_local(s32 src_cid, s32 dst_cid, cid_edq_task_t *at,
				    struct task_struct *p)
{
	int ret;

	ret = scx_edq_try_remove(&cid_pack(src_cid)->edq, &at->common);
	if (ret) {
		if (ret != -EINVAL && ret != -EBUSY)
			scx_bpf_error("EDQ exact remove failed for tid %llu: %d",
				      at->tid, ret);
		scx_edq_task_drop(&at->common);
		return ret == -EBUSY ? CID_EDQ_MOVE_BUSY : CID_EDQ_MOVE_MISS;
	}

	return cid_edq_dispatch_popped(at, p, dst_cid) ? CID_EDQ_MOVE_MOVED :
							 CID_EDQ_MOVE_MISS;
}

/*
 * A pop that fails to dispatch has still removed its node: the task it
 * chose is in the hands of a concurrent dequeue, and the core enqueues it
 * again. The rest of the queue is not, so pop again rather than end the
 * round and leave the CPU idle over tasks that are ready to run. Every
 * iteration removes a node, so the queue depth bounds the loop.
 */
static __noinline bool cid_queue_move_head_to_local(s32 cid)
{
	struct scx_edq __arena *edq = &cid_pack(cid)->edq;
	cid_edq_task_t *at;

	while (can_loop) {
		at = (cid_edq_task_t *)scx_edq_pop(edq, true);
		if (!at)
			return false;
		if (cid_edq_dispatch_popped(at, NULL, cid))
			return true;
	}
	return false;
}

/*
 * Atomically remove the earliest-deadline task whose vruntime is eligible.
 * If a lockless V snapshot finds none, retain the existing head fallback so
 * a transiently all-ineligible queue cannot be stranded, unless @strict: the
 * caller has a runnable task to keep instead. Pops again after a failed
 * dispatch, see cid_queue_move_head_to_local().
 */
static __noinline bool cid_edq_move_first_eligible_to_local(s32 cid, u64 vref,
							    bool strict)
{
	struct scx_edq __arena *edq = &cid_pack(cid)->edq;
	cid_edq_task_t *at;

	while (can_loop) {
		at = (cid_edq_task_t *)(strict ?
			scx_edq_pop_first_eligible(edq, vref, true) :
			scx_edq_pop_first_eligible_or_first(edq, vref, true));
		if (!at)
			return false;
		if (cid_edq_dispatch_popped(at, NULL, cid))
			return true;
	}
	return false;
}

static __always_inline bool cid_queue_insert(struct task_struct *p, task_ctx_t *tctx,
			     s32 cid, u64 slice,
			     u64 deadline, u64 vruntime, u64 enq_flags)
{
	cid_edq_task_t *at;
	int ret;

	at = cid_edq_task(tctx);
	if (!at) {
		scx_bpf_error("missing EDQ task for pid %d", p->pid);
		return false;
	}
	/*
	 * A held node was popped by an older enqueue workflow. A property-change
	 * dequeue can end that workflow and re-enqueue the task before the old
	 * dispatcher drops its hold. Do not let the one intrusive node represent
	 * both workflows: direct-dispatch the new one and make the stale pop fail
	 * its state check.
	 */
	if (READ_ONCE(at->common.holdcnt)) {
		WRITE_ONCE(at->state, CID_EDQ_DISPATCHED);
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | cid, slice, enq_flags);
		return false;
	}
	if (READ_ONCE(at->state) == CID_EDQ_ENQUEUED)
		scx_bpf_error("EDQ double enqueue for pid %d", p->pid);
	at->slice = slice;
	at->enq_flags = enq_flags;
	at->cid = cid;
	/* Publish custody before the node becomes visible to another CPU's pop. */
	WRITE_ONCE(at->state, CID_EDQ_ENQUEUED);
	ret = scx_edq_insert(&cid_pack(cid)->edq, &at->common, deadline,
			      vruntime, tctx->se.request);
	if (ret) {
		__sync_val_compare_and_swap(&at->state, CID_EDQ_ENQUEUED,
					CID_EDQ_NONE);
		scx_bpf_error("EDQ insert failed for pid %d: %d", p->pid, ret);
		return false;
	}
	return true;
}

/*
 * Queued cid tracking.
 *
 * One bit per cid whose EDQ holds at least one task, kept next to the
 * idle bitmap and scanned the same way, so that a cid looking for work
 * to pull walks a word of it instead of peeking at every EDQ of the node.
 *
 * The bit is set after a task is queued and cleared by whoever finds the
 * EDQ empty, with a second look after the clear in case a task was queued
 * in between. It is a hint: the kernel can dequeue a task behind the
 * scheduler's back, and a bit left set is cleared by the first cid that
 * peeks and finds nothing.
 */
static bool cid_queued_test(s32 cid)
{
	return cid_valid(cid) && __cmask_test(cid, queued_cids);
}

static void cid_queued_set(s32 cid)
{
	if (cid_valid(cid))
		cmask_set(cid, queued_cids);
}

/*
 * Clear the queued bit of @cid if its EDQ is empty, looking again after
 * the clear for a task queued in the meantime.
 */
static void cid_queued_check(s32 cid)
{
	if (!cid_valid(cid) || cid_queue_nr(cid))
		return;
	/*
	 * The queue is empty because ops.dispatch() has just taken its head
	 * while the task that was running is still runnable: that task is
	 * enqueued back here as soon as ops.dispatch() returns,
	 * put_prev_task_scx(). Clearing the bit now and setting it again
	 * then is two atomic writes per switch to a word every CPU shares,
	 * and the cacheline bouncing between CPUs each switching between
	 * two of their own tasks ran a pinned pair of yielders per CPU five
	 * times slower than fair.c. Leave the bit alone: the enqueue finds
	 * it set and writes nothing, and clears the flag.
	 */
	if (READ_ONCE(cid_ctx(cid)->requeue_pending))
		return;
	cmask_clear(cid, queued_cids);
	if (cid_queue_nr(cid))
		cmask_set(cid, queued_cids);
}
