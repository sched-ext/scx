/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 *
 * EEVDF virtual-time substrate, included by main.bpf.c via #include.
 *
 * The pure math (calc_delta_fair_bpf, the virtual-clock advance, and
 * place_entity) lives in intf.h so the native unit-test harness compiles
 * it directly. This module wires that math to the per-queue virtual
 * clock. The lock-free placement entry point used by enqueue(), the
 * monotone clock advance that follows the service given to a queue, and
 * the vruntime charging used by the lifecycle path.
 */

static __always_inline struct queue_ctx *mlfq_lookup_queue(u32 qid)
{
	return bpf_map_lookup_elem(&queue_ctx_stor, &qid);
}

/*
 * Place @tctx into queue @qid against the queue's virtual clock. No lock
 * is taken: the clock is updated only through the monotone advance, and
 * the placement clamp bounds any error a momentarily stale
 * clock can introduce, so the bounded-lag safety properties hold without
 * mutual exclusion.
 *
 * Return: the placement deadline, or 0 on lookup failure.
 */
static __always_inline u64 mlfq_place_task(u32 qid, struct task_ctx *tctx,
					   s32 pid)
{
	struct queue_ctx *q = mlfq_lookup_queue(qid);
	u64 deadline;

	if (!q) {
		scx_bpf_error("pid %d queue %u lookup failed", pid, qid);
		return 0;
	}

	deadline = mlfq_place_entity(q, tctx);
#if MLFQ_CHECK
	if (!mlfq_check_queued_vlag(tctx->vlag))
		scx_bpf_error("pid %d queue %u vlag %lld < 0", pid, qid,
			      tctx->vlag);
#endif
	return deadline;
}

/**
 * mlfq_update_vruntime - Advance a task's virtual runtime for a run segment.
 * @tctx: The task.
 * @delta_ns: Physical run time in nsecs.
 *
 * vruntime += calc_delta_fair(delta, weight) (fair.c:317-323).
 */
static __always_inline void mlfq_update_vruntime(struct task_ctx *tctx,
						 u64 delta_ns)
{
	tctx->vruntime += calc_delta_fair_bpf(delta_ns, tctx->weight);
}
