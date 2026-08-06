/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 *
 * EEVDF virtual-time substrate, included by main.bpf.c via #include.
 *
 * The pure math (calc_delta_fair_bpf, avg_vruntime, entity_lag_clamp,
 * place_entity) lives in intf.h so the native unit-test harness compiles
 * it directly. This module wires that math to the per-queue aggregates:
 * account_add/account_del under the per-queue spinlock, the local-curr
 * fold, the zero_vruntime advancement and the placement entry points used
 * by enqueue().
 */

/*
 * Fair schedulers conserve lag:
 *
 *   \Sum lag_i = 0,   lag_i = S - s_i = w_i * (V - v_i)
 *
 * which gives the weighted average virtual time:
 *
 *   V = \Sum(v_i * w_i) / \Sum w_i
 *
 * Placing a task with lag vl_i moves V to V' = V - w_i*vl_i/(W + w_i),
 * strictly reducing the placed lag. To preserve lag across dequeue we
 * must inflate it before placement:
 *
 *   vl_i = (W + w_i) * vl'_i / W
 *
 * (See kernel/sched/fair.c place_entity().) In BPF we evaluate this
 * against a per-queue zero_vruntime base so all key*weight products stay
 * within s64 -- see the magnitude note in avg_vruntime().
 */

/*
 * EEVDF never selects an ineligible entity (vruntime > V); the kernel
 * finds the best eligible entity in O(log n) using an augmented tree.
 * BPF DSQs have no augmentation, so we enforce eligibility at placement
 * instead: a task whose stored lag would be negative is placed at V
 * (lag := 0). This matches fair.c's DELAY_ZERO and is conservative --
 * a task can never run before its fair-share point. Selection is then
 * min-virtual-deadline, which the kernel's DSQ rbtree provides natively.
 */

static __always_inline struct queue_ctx *mlfq_lookup_queue(u32 qid)
{
	return bpf_map_lookup_elem(&queue_ctx_stor, &qid);
}

static __always_inline struct bpf_spin_lock *mlfq_lookup_queue_lock(u32 qid)
{
	struct mlfq_queue_lock *lockw;

	lockw = bpf_map_lookup_elem(&queue_locks, &qid);
	if (!lockw)
		return NULL;
	return &lockw->lock;
}

/*
 * Add @tctx to queue @q's aggregate (key = vruntime - zero_vruntime, which
 * place_entity keeps within a few lag bounds). Idempotent under the
 * MLFQ_TF_ACCOUNTED flag so the fast-path and migration-disabled tasks --
 * which never enter a queue DSQ -- are never double-counted. Caller holds
 * the queue lock.
 */
static __always_inline void mlfq_queue_account_add(struct queue_ctx *q,
						   struct task_ctx *tctx)
{
	s64 key = (s64)(tctx->vruntime - q->zero_vruntime);

	if (tctx->flags & MLFQ_TF_ACCOUNTED)
		return;
	tctx->flags |= MLFQ_TF_ACCOUNTED;
	q->sum_w_vruntime += key * (s64)tctx->weight;
	q->sum_weight += tctx->weight;
	q->nr_queued++;
}

/*
 * Remove @tctx from queue @q's aggregate. Idempotent under the
 * MLFQ_TF_ACCOUNTED flag; matches mlfq_queue_account_add(). Caller holds
 * the queue lock.
 */
static __always_inline void mlfq_queue_account_del(struct queue_ctx *q,
						   struct task_ctx *tctx)
{
	s64 key = (s64)(tctx->vruntime - q->zero_vruntime);

	if (!(tctx->flags & MLFQ_TF_ACCOUNTED))
		return;
	tctx->flags &= ~MLFQ_TF_ACCOUNTED;
	q->sum_w_vruntime -= key * (s64)tctx->weight;
	q->sum_weight -= tctx->weight;
	q->nr_queued--;
}

/*
 * The running task is out of its queue's DSQ and out of the
 * aggregate; fold in the local CPU's running task (the CPU that the enqueue
 * runs on, i.e. the rq the task is being enqueued to) when it belongs to
 * @qid so V_q does not lag by that task's running-time contribution -- the
 * same "fold the enqueueing rq's curr" semantics as fair.c place_entity().
 * Other CPUs' running tasks are not folded; the lag clamp absorbs the
 * staleness at re-enqueue.
 */
static __always_inline bool mlfq_queue_fold_local(struct queue_ctx *q, u32 qid,
						  const struct mlfq_cpu_state *cpu)
{
	if (!cpu || cpu->running_queue != (s32)qid || !cpu->running_weight)
		return false;

	q->sum_w_vruntime += (s64)(cpu->running_vruntime - q->zero_vruntime) *
			     (s64)cpu->running_weight;
	q->sum_weight += cpu->running_weight;
	return true;
}

static __always_inline void mlfq_queue_unfold_local(struct queue_ctx *q,
						    const struct mlfq_cpu_state *cpu)
{
	if (!cpu || !cpu->running_weight)
		return;
	q->sum_w_vruntime -= (s64)(cpu->running_vruntime - q->zero_vruntime) *
			     (s64)cpu->running_weight;
	q->sum_weight -= cpu->running_weight;
}

/*
 * Advance zero_vruntime so the weighted average stays within one
 * worst-case lag limit (weight 1) of the base. The rebase shifts every
 * key by the same delta -- sum_w_vruntime -= delta * sum_weight -- which
 * preserves the average exactly while keeping all key*weight products
 * within s64.
 */
static __always_inline void mlfq_queue_advance_zero(struct queue_ctx *q)
{
	u64 vq, limit_max, delta;

	if (q->sum_weight == 0)
		return;

	vq = mlfq_avg_vruntime(q);
	if (!mlfq_time_before(q->zero_vruntime, vq))
		return;

	delta = vq - q->zero_vruntime;
	limit_max = calc_delta_fair_bpf(q->max_slice_ns + MLFQ_TICK_NS, 1);
	if (delta <= limit_max)
		return;

	delta -= limit_max;
	q->sum_w_vruntime -= (s64)delta * (s64)q->sum_weight;
	q->zero_vruntime += delta;
}

/*
 * Place @tctx into queue @qid. Computes the EEVDF deadline under the
 * per-queue spinlock (with the local-curr fold), updates the task state
 * and -- when @account -- adds the task to the aggregate. The caller
 * inserts the task into the chosen DSQ with the returned deadline.
 *
 * Return: the placement deadline, or 0 on lookup failure.
 */
static __always_inline u64 mlfq_place_task(u32 qid, struct task_ctx *tctx,
					   bool inflate,
					   struct mlfq_cpu_state *cpu, s32 pid,
					   bool account)
{
	struct queue_ctx *q = mlfq_lookup_queue(qid);
	struct bpf_spin_lock *lock = mlfq_lookup_queue_lock(qid);
	bool folded;
	u64 deadline;

	if (!q || !lock) {
		scx_bpf_error("pid %d queue %u lookup failed", pid, qid);
		return 0;
	}

	bpf_spin_lock(lock);
	folded = mlfq_queue_fold_local(q, qid, cpu);
	deadline = mlfq_place_entity(q, tctx, inflate);
	if (account)
		mlfq_queue_account_add(q, tctx);
	/*
	 * Unfold before advancing zero_vruntime: the fold's key is relative
	 * to the pre-rebase base, and the rebase shifts every key by the
	 * same delta. Unfolding first keeps the aggregate exact.
	 */
	if (folded)
		mlfq_queue_unfold_local(q, cpu);
	if (account)
		mlfq_queue_advance_zero(q);
#if MLFQ_CHECK
	if (!mlfq_check_queue_ctx(q) || !mlfq_check_aggregate_bounds(q))
		scx_bpf_error("pid %d q%u aggregate inconsistent s=%lld W=%llu n=%llu",
			      pid, qid, q->sum_w_vruntime, q->sum_weight,
			      q->nr_queued);
	if (!mlfq_check_queued_vlag(tctx->vlag))
		scx_bpf_error("pid %d queue %u vlag %lld < 0", pid, qid,
			      tctx->vlag);
#endif
	bpf_spin_unlock(lock);

	return deadline;
}

/*
 * Remove @tctx from queue @q's aggregate (ops.running()/exit_task()).
 * Caller looks up @q by tctx->queue.
 */
static __always_inline void mlfq_queue_del_task(u32 qid, struct queue_ctx *q,
						struct task_ctx *tctx)
{
	struct bpf_spin_lock *lock = mlfq_lookup_queue_lock(qid);

	if (!lock)
		return;

	bpf_spin_lock(lock);
	mlfq_queue_account_del(q, tctx);
	mlfq_queue_advance_zero(q);
#if MLFQ_CHECK
	if (!mlfq_check_queue_ctx(q) || !mlfq_check_aggregate_bounds(q))
		scx_bpf_error("q%u aggregate inconsistent s=%lld W=%llu n=%llu",
			      qid, q->sum_w_vruntime, q->sum_weight,
			      q->nr_queued);
#endif
	bpf_spin_unlock(lock);
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
