/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.
 *
 * The per-cid runnable queue: what a sched_ext scheduler has to build for
 * itself in place of the rbtree fair.c picks from.
 *
 *
 * The queue
 * ---------
 *
 * Every cid owns one EDQ (lib/edq.h): an AVL tree ordered by virtual
 * deadline and augmented, in every subtree, with the least eligible
 * vruntime and the shortest request under it. That augmentation is what
 * makes the EEVDF pick one descent instead of a walk:
 *
 *                 [ deadline 40 ]        pick = leftmost deadline among
 *                  min_v 10, min_r 700   the entities with v <= V
 *                 /              \
 *      [ dl 20 ]                  [ dl 90 ]
 *       min_v 30                   min_v 10
 *         |                          |
 *     v > V, pruned              contains the answer
 *
 * so scx_edq_pop_first_eligible(V) descends past whole subtrees whose
 * least eligible vruntime is still ahead of the reference, exactly as
 * pick_eevdf() prunes on min_vruntime. The shortest request is there for
 * set_protect_slice(), which bounds a task's protection by the smallest
 * competitor rather than by its own deadline.
 *
 * A task carries its node inside its own arena context, so a pop hands
 * back the address of the context itself: no lookup, no map, and the
 * scheduler never has to resolve a pid to find what it just picked.
 *
 *
 * Who owns a task, and when
 * -------------------------
 *
 * The kernel can dequeue a task behind the scheduler's back, and another
 * cid can be halfway through stealing it, so the node carries a state and
 * only the side that holds it may move it on:
 *
 *                 enqueue            pop             insert on the
 *      NONE ----------------> ENQUEUED ----> DISPATCHING ----> DISPATCHED
 *        ^                        |               |   local DSQ      |
 *        |                        |               v                  |
 *        |                        |        lost the race: the task   |
 *        +------------------------+------- belongs to somebody else -+
 *        |        ops.dequeue(), or a property change ending
 *        |        this enqueue workflow
 *        |
 *      PARKED   its cgroup ran out of cpu.max, see cgroup.bpf.c
 *
 * A pop that loses the compare-and-swap drops the task and tries the next
 * one rather than ending the round, since the rest of the queue is still
 * runnable and the alternative is an idle CPU. A dequeue that arrives
 * first publishes NONE before unlinking, so the pop in flight fails its
 * state check instead of dispatching a task the kernel has taken back.
 * Nodes are held across the unlocked parts of that (scx_edq_task_drop()
 * releases), which is what keeps an arena object alive while a remote cid
 * is looking at it.
 *
 * Beside the queues is one bit per cid that has something in one, so a cid
 * looking for work reads a word of a bitmap instead of peeking into every
 * EDQ of the node. The bit is a hint: whoever finds a queue empty clears
 * it, and looks again after clearing in case something was queued in
 * between. It is deliberately left set across a dispatch that is about to
 * re-enqueue the task it took, because clearing and setting it again is
 * two writes to a line every CPU shares - that alone ran a pinned pair of
 * yielding tasks five times slower than fair.c.
 *
 *
 * What is here
 * ------------
 *
 * Only the two operations that are not inline: the eligible pick a
 * dispatch takes from its own queue, which needs the pack's reference and
 * so cannot live beside the queue itself in queue.bpf.h, and
 * ops.dequeue(), which ends whatever workflow the node was in and is where
 * a task leaves BPF custody for good.
 */
#include "eevdf.bpf.h"
#include "cgroup.bpf.h"
#include "queue.bpf.h"
#include "task.bpf.h"

/*
 * Move the earliest-deadline eligible task from @cid to this CPU. EDQ selects
 * and removes under its lock. If every observed queued task is ineligible,
 * fall back to the head rather than strand a runnable queue. This can happen
 * when the current task is the pack's sole eligible member but active balance
 * is moving it elsewhere, or when the lockless reference and queue snapshots
 * race. Callers enter here only when eligible scanning and eligibility
 * enforcement are both enabled.
 */
static __noinline bool move_first_eligible_to_local(s32 cid, u64 tnow,
						   bool strict)
{
	TOUCH_ARENA();
	return cid_edq_move_first_eligible_to_local(
		cid, pack_vref_place(cid_pack(cid), tnow), strict);
}

void BPF_STRUCT_OPS(eevdf_dequeue, struct task_struct *p, u64 deq_flags)
{
	cid_edq_task_t *at;
	task_ctx_t *tctx;
	u32 state;
	s32 cid;
	int ret;

	TOUCH_ARENA();
	tctx = try_lookup_task_ctx(p);
	at = cid_edq_task(tctx);
	if (!at)
		return;
	cid = at->cid;
	state = READ_ONCE(at->state);
	if (deq_flags & SCX_DEQ_SCHED_CHANGE) {
		/*
		 * A property change ends this enqueue workflow. Publish NONE before
		 * unlinking so a concurrent pop cannot dispatch the old workflow.
		 * Its held intrusive node prevents a later enqueue from reusing the
		 * queue entry until that pop drops its reference.
		 */
		WRITE_ONCE(at->state, CID_EDQ_NONE);
	} else if (state == CID_EDQ_ENQUEUED ||
		   state == CID_EDQ_DISPATCHING) {
		/* The task is leaving BPF custody for a terminal DSQ or execution. */
		WRITE_ONCE(at->state, CID_EDQ_DISPATCHED);
	}
	ret = scx_edq_task_fini(&at->common);
	if (ret < 0) {
		scx_bpf_error("EDQ dequeue failed for pid %d: %d", p->pid, ret);
		return;
	}
	if (ret > 0) {
		/*
		 * A task that leaves custody from a cgroup's backlog was taken
		 * out of it here, so it is this side that stops counting it,
		 * see bw_unpark_one() for the other.
		 */
		if (state == CID_EDQ_PARKED)
			task_bw_unparked(tctx);
		else
			cid_queued_check(cid);
	}
}
