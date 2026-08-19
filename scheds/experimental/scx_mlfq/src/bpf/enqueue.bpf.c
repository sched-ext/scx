/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 *
 * Enqueue routing, included by main.bpf.c via #include.
 *
 * The MLFQ enqueue path:
 *   WAKEUP -> EMA decay + classification, then placement
 *   RUN-OUT (enq_flags == 0) -> demotion, then placement
 *   other (fork / SCX_ENQ_LAST / class switch) -> counter reset, placement
 *   wall-clock aging check for Q2/Q3 stays, then placement
 *
 * The wakeup preemption decision runs before the regular placement: a
 * wakeup outranks the task running on the CPU it was last running on when
 * it belongs to a higher queue, and is dispatched to that CPU's local DSQ
 * with SCX_ENQ_PREEMPT. The local-DSQ insert is FIFO, so no deadline is
 * needed and no shared state is touched. Same-queue wakeups never preempt:
 * they join the queue DSQ and are served by virtual-time order at
 * dispatch, so a running task is not displaced mid-slice by a task of its
 * own priority. A wakeup whose affinity no longer includes the CPU it was
 * last running on falls through to the regular path.
 *
 * The demotion path keys on the flags == 0 run-out re-enqueue. flags == 0
 * arrives from put_prev_task_scx() for a runnable task whose slice grant
 * was consumed: slice exhaustion and SCX_ENQ_PREEMPT preemptions both zero
 * the running task's slice, so both produce the same flag-less re-enqueue.
 * SCX_ENQ_LAST is passed when the task is about to enter a lower sched
 * class and remains the only runnable ext task on the CPU. SCX_ENQ_REENQ
 * arrives only from scx_bpf_reenqueue_local(), which ops.cpu_release()
 * calls to fold the local DSQ back into the queue DSQs. Preemptions by a
 * higher sched class keep the task at the local-DSQ head without calling
 * ops.enqueue() at all.
 *
 * Every placement calls mlfq_place_task(), which can only fail when the
 * queue map lookup fails. The queue maps are static and in-range, so a
 * failed placement is unreachable for valid inputs; the error call on
 * each failure path turns a future regression into a scheduler exit into
 * bypass instead of a silently stranded task. The two FIFO local-DSQ
 * paths (pinned-idle and the idle-CPU fast path) skip placement entirely:
 * the insert does not consume a deadline, so placement is deferred to the
 * next real placement, which re-anchors the task under the lag clamp.
 */

static __always_inline bool mlfq_task_is_migration_disabled(const struct task_struct *p)
{
	return p->nr_cpus_allowed == 1 || is_migration_disabled(p);
}

static __always_inline u64 mlfq_queue_slice(u8 qid)
{
	if (qid == 1)
		return mlfq_q1_slice_ns;
	if (qid == 2)
		return mlfq_q2_slice_ns;
	return mlfq_q3_slice_ns;
}

static __always_inline void mlfq_stat_placement(u8 qid)
{
	if (qid == 1)
		__sync_fetch_and_add(&mlfq_stats.q1_placements, 1);
	else if (qid == 2)
		__sync_fetch_and_add(&mlfq_stats.q2_placements, 1);
	else
		__sync_fetch_and_add(&mlfq_stats.q3_placements, 1);
}

/*
 * A placement into another CPU's queue needs that CPU to run one more
 * scheduling cycle so a queued task is not stranded on a nohz-idle CPU;
 * the idle kick is a cheap flag that is consumed when the CPU next goes
 * idle. The enqueueing CPU needs no kick: its own dispatch drains the
 * queue in the same scheduling cycle.
 */
static __always_inline void mlfq_idle_kick(u64 cpu)
{
	if (cpu != bpf_get_smp_processor_id())
		scx_bpf_kick_cpu(cpu, SCX_KICK_IDLE);
}

void BPF_STRUCT_OPS(mlfq_enqueue, struct task_struct *p, u64 enq_flags)
{
	struct task_ctx *tctx;
	u64 now, deadline, slice;
	u32 weight, qid;
	u8 old_queue;
	bool wakeup, runout, local_fast_path, migration_disabled;
	bool sched_idle;
	s32 prev_cpu = scx_bpf_task_cpu(p);
	s32 target_cpu;

	tctx = mlfq_lookup_task_ctx(p);
	if (!tctx) {
		/*
		 * init_task() normally pre-allocates the task storage, but a
		 * task can reach enqueue() without it (for example a task
		 * that was runnable when this scheduler attached). Allocate
		 * on demand instead of dropping the task from scheduling: a
		 * runnable task without state would otherwise stay stranded
		 * until its next enqueue. If the allocation still fails (out
		 * of memory), the error path exits the scheduler and the
		 * kernel's bypass mode then guarantees every runnable task
		 * makes progress, so a task is never silently stranded.
		 */
		tctx = mlfq_alloc_task_ctx(p);
		if (!tctx) {
			__sync_fetch_and_add(&mlfq_stats.enq_no_tctx, 1);
			scx_bpf_error("pid %d task state allocation failed in enqueue",
				      p->pid);
			return;
		}
		mlfq_reset_task_ctx(tctx, p, scx_bpf_now());
	}

	/* Refresh the weight cache; the kernel clamps p->scx.weight to [1, 10000]. */
	weight = p->scx.weight;
	if (weight < 1) {
		__sync_fetch_and_add(&mlfq_stats.enq_bad_weight, 1);
		scx_bpf_error("pid %d has invalid weight %u", p->pid, weight);
		return;
	}
	tctx->weight = weight;

	now = scx_bpf_now();
	wakeup = enq_flags & SCX_ENQ_WAKEUP;
	/* See the file header for the flags == 0 call-site table. */
	runout = enq_flags == 0;
	old_queue = tctx->queue;

	if (wakeup) {
		mlfq_wakeup_classify(p, tctx, now);
	} else if (runout) {
		/*
		 * Slice-exhaustion re-enqueue from put_prev_task_scx().
		 * The consecutive-exhaustion demotion state machine runs
		 * here and only here.
		 */
		mlfq_runout_classify(p, tctx);
	} else {
		/* fork, SCX_ENQ_LAST or class switch: reset the counters. */
		tctx->wake_cnt = 0;
		tctx->reenq_cnt = 0;
	}

	/*
	 * SCHED_IDLE is always Q3 and never ages.
	 */
	sched_idle = mlfq_apply_sched_idle(p, tctx);

	/*
	 * Stay bookkeeping: a wakeup ends the previous stay (sleeping resets
	 * it), a queue change starts a fresh one, and a run-out ends the
	 * previous stay because the task just ran a full slice. A queue
	 * change also clears the consecutive slice-exhaustion counter (band
	 * semantics). Only Q2/Q3 stays carry a non-zero queued_at.
	 */
	if (tctx->queue != old_queue) {
		tctx->queued_at = tctx->queue >= 2 ? now : 0;
		tctx->reenq_cnt = 0;
	} else if (wakeup || runout) {
		tctx->queued_at = tctx->queue >= 2 ? now : 0;
	}

	/*
	 * Aging: a stay of >= MLFQ_AGING_PERIOD_NS of continuous Q2/Q3
	 * wall-clock time is elevated to a Q1 placement. queued_at re-arms
	 * at every wakeup, queue change and run-out, so a continuously
	 * running task never accumulates aging wall-clock time; only a task
	 * that genuinely waits behind others in the queue keeps a stale stay
	 * and ages. A task that sleeps resets its stay at the wakeup, so
	 * wall-clock time spent asleep never counts toward aging.
	 */
	if (tctx->queue >= 2 && !sched_idle &&
	    tctx->queued_at &&
	    !mlfq_time_before(now, tctx->queued_at + mlfq_aging_period_ns)) {
		tctx->queue = 1;
		tctx->reenq_cnt = 0;
		__sync_fetch_and_add(&mlfq_stats.aging_boosts, 1);
	}

	qid = tctx->queue;
	slice = mlfq_queue_slice(qid);

#if MLFQ_CHECK
	if (!mlfq_check_queue(tctx->queue) || !mlfq_check_weight(tctx->weight))
		scx_bpf_error("pid %d invalid queue %u weight %u", p->pid,
			      tctx->queue, tctx->weight);
#endif

	migration_disabled = mlfq_task_is_migration_disabled(p);
	if (migration_disabled) {
		if (prev_cpu < 0) {
			scx_bpf_error("pid %d pinned task without a CPU", p->pid);
			return;
		}

		/*
		 * The allowed CPU set may have changed since the last
		 * placement; the pinned CPU is prev_cpu only when the task
		 * may still run there. A task whose affinity no longer
		 * includes prev_cpu is parked on the global DSQ, which the
		 * kernel drains on every dispatch cycle without this
		 * scheduler's involvement.
		 */
		if (!bpf_cpumask_test_cpu((u32)prev_cpu, p->cpus_ptr)) {
			__sync_fetch_and_add(&mlfq_stats.enq_pinned_global, 1);
			scx_bpf_dsq_insert(p, SCX_DSQ_GLOBAL,
					   slice, enq_flags);
			tctx->wake_cpu_state = 0;
			goto done;
		}

		if (scx_bpf_test_and_clear_cpu_idle(prev_cpu)) {
			/*
			 * The pinned CPU is idle, so the local DSQ is
			 * empty. The task runs on the next scheduling
			 * cycle and the local DSQ drains immediately after,
			 * which keeps balance_one() from skipping
			 * ops.dispatch() for the tasks queued behind it.
			 * The FIFO local-DSQ insert does not consume a
			 * deadline, so placement is deferred to the next
			 * real placement, which re-anchors the task under
			 * the lag clamp.
			 */
			__sync_fetch_and_add(&mlfq_stats.enq_pinned_idle, 1);
			scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | (u64)prev_cpu,
					   slice, enq_flags);
			mlfq_stat_placement(qid);
			tctx->wake_cpu_state = 0;
			goto done;
		}

		/*
		 * The pinned CPU is busy. The task is placed into the
		 * CPU's queue DSQ and shares the CPU by virtual time
		 * order; the owning CPU drains the queue at every slice
		 * boundary, so the task is served without ever parking in
		 * the local DSQ, which would shadow every other runnable
		 * task on the CPU until the stall watchdog fires.
		 */
		deadline = mlfq_place_task(qid, tctx, p->pid);
		if (!deadline) {
			/* Unreachable for valid inputs; see the header note. */
			__sync_fetch_and_add(&mlfq_stats.enq_no_deadline, 1);
			scx_bpf_error("pid %d pinned-busy placement failed",
				      p->pid);
			return;
		}
		__sync_fetch_and_add(&mlfq_stats.enq_pinned_busy, 1);
		scx_bpf_dsq_insert_vtime(p, mlfq_dsq_id(qid, prev_cpu),
					 slice, deadline,
					 enq_flags);
		mlfq_stat_placement(qid);
		tctx->wake_cpu_state = 0;
		mlfq_idle_kick(prev_cpu);
		goto done;
	}

	/*
	 * Idle-CPU fast path: select_cpu() found an idle CPU and returned it,
	 * so the wakeup can be served on that CPU's local DSQ immediately.
	 * Correct because the CPU is idle -- no runnable task is displaced.
	 */
	local_fast_path = __COMPAT_is_enq_cpu_selected(enq_flags) &&
			  (tctx->wake_cpu_state & MLFQ_WAKE_CPU_VALID) &&
			  (tctx->wake_cpu_state & MLFQ_WAKE_CPU_IDLE);
	if (local_fast_path) {
		/*
		 * The FIFO local-DSQ insert does not consume a deadline,
		 * so placement is deferred to the next real placement,
		 * which re-anchors the task under the lag clamp.
		 */
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, slice,
				   enq_flags);
		__sync_fetch_and_add(&mlfq_stats.enq_fastpath, 1);
		mlfq_stat_placement(qid);
		tctx->wake_cpu_state = 0;
		goto done;
	}

	/*
	 * The queue DSQ a task is placed in is owned by the CPU it is
	 * enqueued to: a wakeup lands on prev_cpu, the CPU the task was
	 * last running on, while run-out re-enqueues and fork/class-switch
	 * placements run on the rq the task is being enqueued to, which is
	 * the enqueueing CPU. Each CPU drains only its own three queue
	 * DSQs (see dispatch.bpf.c), so the insert must target the owning
	 * CPU's queue.
	 */
	if (wakeup)
		target_cpu = prev_cpu;
	else
		target_cpu = bpf_get_smp_processor_id();
	/* A concurrent affinity change may have dropped target_cpu; use the enqueueing CPU. */
	if (!bpf_cpumask_test_cpu((u32)target_cpu, p->cpus_ptr))
		target_cpu = bpf_get_smp_processor_id();

	/*
	 * Wakeup preemption: a wakeup outranks the task running on the CPU
	 * it was last running on when it belongs to a higher queue. This is
	 * the check_preempt_wakeup semantics of the fair scheduler, where
	 * the higher-priority arrival preempts: the wakee is dispatched to
	 * that CPU's local DSQ with SCX_ENQ_PREEMPT, which the kernel
	 * resolves into a preemption on the next scheduling event. The
	 * local-DSQ insert is FIFO, so no placement and no shared state
	 * needs to be touched. Same-queue wakeups do not preempt: they join the queue
	 * DSQ and are served by virtual-time order at dispatch, so a
	 * running task is never displaced mid-slice by a task of its own
	 * priority. A concurrent affinity change between CPU selection and
	 * enqueue must not target a CPU outside the allowed set; the
	 * local-DSQ insert is a same-rq operation, so the failure is a
	 * placement violation rather than a fatal error, and the queue
	 * placement is the correct fallback.
	 */
	if (wakeup && !migration_disabled) {
		struct mlfq_cpu_state *prev_state = mlfq_lookup_cpu_state(prev_cpu);

		if (prev_state && prev_state->running_pid &&
		    prev_state->running_pid != p->pid &&
		    prev_state->running_queue > 0 &&
		    (s32)qid < prev_state->running_queue &&
		    bpf_cpumask_test_cpu((u32)prev_cpu, p->cpus_ptr)) {
			scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | (u64)prev_cpu,
					   slice, enq_flags | SCX_ENQ_PREEMPT);
			__sync_fetch_and_add(&mlfq_stats.preemption_kicks, 1);
			tctx->wake_cpu_state = 0;
			goto done;
		}
	}

	/* Regular path: into the owning CPU's queue vtime DSQ. */
	deadline = mlfq_place_task(qid, tctx, p->pid);
	if (!deadline) {
		/* Unreachable for valid inputs; see the header note. */
		__sync_fetch_and_add(&mlfq_stats.enq_no_deadline, 1);
		scx_bpf_error("pid %d regular placement failed",
			      p->pid);
		return;
	}

	__sync_fetch_and_add(&mlfq_stats.enq_regular, 1);
	scx_bpf_dsq_insert_vtime(p, mlfq_dsq_id(qid, target_cpu),
				 slice, deadline, enq_flags);
	mlfq_stat_placement(qid);

	/* Keep the fast-path state from leaking into the next enqueue. */
	tctx->wake_cpu_state = 0;

	mlfq_idle_kick(target_cpu);

done:
	;
}
