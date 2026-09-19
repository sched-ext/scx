/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.
 *
 * The two queue operations that are not inline: the eligible pick a
 * dispatch takes from a cid's own EDQ, and ops.dequeue(), which ends
 * whatever an enqueue workflow had started.
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
