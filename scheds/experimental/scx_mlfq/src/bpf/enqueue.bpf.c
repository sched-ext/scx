/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 *
 * Enqueue routing, included by main.bpf.c via #include.
 *
 * The MLFQ enqueue path has four cases.
 *   WAKEUP -> EMA decay + classification, then placement
 *   RUN-OUT (enq_flags == 0) -> demotion, then placement
 *   other (fork / SCX_ENQ_LAST / class switch) -> counter reset, placement
 *   wall-clock aging check for Q2/Q3 stays, then placement
 *
 * The wakeup preemption decision runs before the regular placement. A
 * wakeup outranks the task running on the CPU it was last running on when
 * it belongs to a higher queue, or when it belongs to the same queue and
 * the same-queue rule is met. The interactive same-queue rule (Q1 onto
 * Q1) preempts on a minimum residency alone. The non-interactive rule
 * additionally requires the wakeup's freshly computed deadline to be
 * earlier than the resident's. The wakeup is dispatched to that CPU's
 * local DSQ with SCX_ENQ_PREEMPT. The local-DSQ insert is FIFO. The
 * wakee's deadline is computed only for the non-interactive preemption
 * test and is not committed, so no shared state is touched and the next
 * real placement re-anchors the task under the lag clamp. Same-queue
 * wakeups that do not meet their rule join the queue DSQ and are served
 * by virtual-time order at dispatch. A wakeup whose affinity no longer
 * includes the CPU it was last running on proceeds to the regular
 * path.
 *
 * The demotion path keys on the flags == 0 run-out re-enqueue. flags == 0
 * arrives from put_prev_task_scx() for a runnable task whose slice grant
 * was consumed. Slice exhaustion and SCX_ENQ_PREEMPT preemptions both zero
 * the running task's slice, so both produce the same flag-less re-enqueue.
 * SCX_ENQ_LAST is passed when the task is about to enter a lower sched
 * class and remains the only runnable ext task on the CPU. SCX_ENQ_REENQ
 * arrives from the kernel's reenqueue paths (do_enqueue_task() with
 * SCX_ENQ_REENQ in ext.c). ops.cpu_release() folds the local DSQ back
 * into the queue DSQs through scx_bpf_reenqueue_local(), and the
 * realtime-takeover drain in rtdl.bpf.c re-enqueues the local DSQ and
 * the queue DSQs through the same flag. Preemptions by a higher sched
 * class keep the task at the local-DSQ head without calling
 * ops.enqueue() at all.
 *
 * Every placement calls mlfq_place_task(), which can only fail when the
 * queue map lookup fails. The queue maps are static and in-range, so a
 * failed placement is unreachable for valid inputs. The error call on
 * each failure path turns a future regression into a scheduler exit into
 * bypass instead of a silently stranded task. The two FIFO local-DSQ
 * paths (pinned-idle and the idle-CPU fast path) skip placement entirely.
 * The insert does not consume a deadline, so placement is deferred to the
 * next real placement, which re-anchors the task under the lag clamp.
 *
 * Runnable accounting: every insert below calls
 * mlfq_runnable_enter() with the owning CPU's LLC and the final queue,
 * so the per-LLC/per-queue runnable gauges track each tracked task's
 * ownership from its first enqueue (wakeup, fork, class-switch-in) to
 * its leave-runnable release in ops.quiescent. Continuation re-enqueues
 * (run-out, preemption of the displaced resident, REENQ, ENQ_LAST) do
 * not re-count: the helper only moves the ownership when the LLC or the
 * queue changed. The pinned-global path is the one release here. A task
 * parked on the kernel-owned global DSQ leaves LLC ownership, and
 * ops.running() re-acquires it when the kernel hands it a CPU.
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
 * mlfq_stamp_enq_at - Start an enqueue-to-run measurement episode.
 * @tctx: The task being inserted.
 * @now: Current time (scx_bpf_now()).
 * @wakeup: True for a wakeup insert (SCX_ENQ_WAKEUP set).
 *
 * Every DSQ insert this scheduler controls stamps the episode start.
 * The wait since it is measured at the first ops.running() of the
 * episode. The global park is the one exception (no stamp, because the
 * parked wait is kernel-side and never attributed to this scheduler). The
 * wakeup flag marks wakeup episodes, so the measured wait feeds the
 * wakeup-latency features and gauges. A non-wakeup re-enqueue (for
 * example a takeover drain) clears it, so only the queue wait is
 * measured there.
 */
static __always_inline void mlfq_stamp_enq_at(struct task_ctx *tctx, u64 now,
					      bool wakeup)
{
	tctx->enq_at = now;
	if (wakeup)
		tctx->flags |= MLFQ_TF_ENQ_WAKEUP;
	else
		tctx->flags &= ~MLFQ_TF_ENQ_WAKEUP;
}

/*
 * A placement into another CPU's queue needs that CPU to run one more
 * scheduling cycle so a queued task is not stranded on a nohz-idle CPU.
 * The idle kick is a cheap flag that is consumed when the CPU next goes
 * idle. The enqueueing CPU needs no kick. Its own dispatch drains the
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
	u64 op_lat_start = scx_bpf_now();
	u32 weight, qid;
	u8 old_queue;
	bool wakeup, runout, local_fast_path, migration_disabled;
	bool sched_idle;
	bool skip_preempt = false;
	s32 prev_cpu = scx_bpf_task_cpu(p);
	s32 target_cpu;

	tctx = mlfq_lookup_task_ctx(p);
	if (!tctx) {
		/*
		 * init_task() normally pre-allocates the task storage, but a
		 * task can reach enqueue() without it (for example a task
		 * that was runnable when this scheduler attached). Allocate
		 * on demand instead of dropping the task from scheduling. A
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
			mlfq_op_lat_charge(MLFQ_OP_LAT_ENQUEUE, op_lat_start);
			return;
		}
		mlfq_reset_task_ctx(tctx, p, scx_bpf_now());
	}

	/* Refresh the weight cache. The kernel clamps p->scx.weight to [1, 10000]. */
	weight = p->scx.weight;
	if (weight < 1) {
		__sync_fetch_and_add(&mlfq_stats.enq_bad_weight, 1);
		scx_bpf_error("pid %d has invalid weight %u", p->pid, weight);
		mlfq_op_lat_charge(MLFQ_OP_LAT_ENQUEUE, op_lat_start);
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
		/*
		 * Count the wakeup arrival for the system wakeup-rate
		 * gauge. The counters are per-CPU map slots (each CPU owns
		 * its own slot), so the wakeup path needs no locked
		 * operation on a shared line. Both counters are bumped
		 * with atomic adds, tear-free for the stats reader and
		 * race-free against the adaptation fold. total is the
		 * lifetime sum the stats read adds up, and window is
		 * consumed and zeroed by the fold with an atomic exchange,
		 * so every arrival is counted exactly once. A failed map
		 * lookup drops the count.
		 */
		struct mlfq_wakeup_counters *wc;
		u32 wakeup_key = 0;

		wc = bpf_map_lookup_elem(&mlfq_wakeup_stats, &wakeup_key);
		if (wc) {
			__atomic_fetch_add(&wc->total, 1, __ATOMIC_RELAXED);
			__atomic_fetch_add(&wc->window, 1, __ATOMIC_RELAXED);
		}
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
		/*
		 * The SCX_ENQ_REENQ evacuation re-enqueues land here (the
		 * neutral else branch). Count them as the realtime-takeover
		 * reenqueue traffic diagnostic. A reenqueue is never a
		 * wakeup, so the flag is exclusive with WAKEUP.
		 */
		if (enq_flags & SCX_ENQ_REENQ)
			__sync_fetch_and_add(&mlfq_stats.rt_reenqs, 1);
	}

	/*
	 * SCHED_IDLE is always Q3 and never ages.
	 */
	sched_idle = mlfq_apply_sched_idle(p, tctx);

	/*
	 * Stay bookkeeping. A wakeup ends the previous stay (sleeping resets
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
	 * running task never accumulates aging wall-clock time. Only a task
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
			mlfq_op_lat_charge(MLFQ_OP_LAT_ENQUEUE, op_lat_start);
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
			/*
			 * The task leaves LLC ownership. The global DSQ is
			 * kernel-owned and drained invisibly to this BPF
			 * program (consume_global_dsq), so no LLC may be
			 * charged for the parked wait. A task that was
			 * counted by a previous placement is released now;
			 * ops.running() re-acquires its ownership when the
			 * kernel hands it a CPU. A task never counted
			 * (first global park of a fresh task) is a no-op.
			 */
			mlfq_runnable_exit(tctx);
			/*
			 * The global park also ends the enqueue-to-run
			 * measurement episode. No stamp is written here (the
			 * parked wait is kernel-side), and any stamp from an
			 * earlier enqueue is cleared so the kernel's drain
			 * cannot measure the park as a schedulable wait.
			 */
			tctx->enq_at = 0;
			tctx->flags &= ~MLFQ_TF_ENQ_WAKEUP;
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
			mlfq_runnable_enter(tctx, (u8)qid,
					    mlfq_llc_of_cpu((u32)prev_cpu));
			mlfq_stamp_enq_at(tctx, now, wakeup);
			scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | (u64)prev_cpu,
					   slice, enq_flags);
			mlfq_stat_placement(qid);
			tctx->wake_cpu_state = 0;
			goto done;
		}

		/*
		 * The pinned CPU is busy. The task is placed into the
		 * CPU's queue DSQ and shares the CPU by virtual time
		 * order. The owning CPU drains the queue at every slice
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
			mlfq_op_lat_charge(MLFQ_OP_LAT_ENQUEUE, op_lat_start);
			return;
		}
		__sync_fetch_and_add(&mlfq_stats.enq_pinned_busy, 1);
		mlfq_runnable_enter(tctx, (u8)qid,
				    mlfq_llc_of_cpu((u32)prev_cpu));
		mlfq_stamp_enq_at(tctx, now, wakeup);
		scx_bpf_dsq_insert_vtime(p, mlfq_dsq_id(qid, prev_cpu),
					 slice, deadline,
					 enq_flags);
		mlfq_stat_placement(qid);
		tctx->wake_cpu_state = 0;
		mlfq_idle_kick(prev_cpu);
		goto done;
	}

	/*
	 * The idle-CPU fast path. select_cpu() found an idle CPU and returned it,
	 * so the wakeup can be served on that CPU's local DSQ immediately.
	 * It is correct because the CPU is idle, so no runnable task is displaced.
	 */
	local_fast_path = __COMPAT_is_enq_cpu_selected(enq_flags) &&
			  (tctx->wake_cpu_state & MLFQ_WAKE_CPU_VALID) &&
			  (tctx->wake_cpu_state & MLFQ_WAKE_CPU_IDLE) &&
			  !mlfq_cpu_occupied(bpf_get_smp_processor_id());
	if (local_fast_path) {
		/*
		 * The FIFO local-DSQ insert does not consume a deadline,
		 * so placement is deferred to the next real placement,
		 * which re-anchors the task under the lag clamp. The
		 * occupied guard closes the window between the idle claim
		 * and this insert: a realtime task taking the CPU over in
		 * between would otherwise strand the wakeup in its local
		 * DSQ until the takeover drain.
		 */
		mlfq_runnable_enter(tctx, (u8)qid,
				    mlfq_llc_of_cpu((u32)bpf_get_smp_processor_id()));
		mlfq_stamp_enq_at(tctx, now, wakeup);
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, slice,
				   enq_flags);
		__sync_fetch_and_add(&mlfq_stats.enq_fastpath, 1);
		mlfq_stat_placement(qid);
		tctx->wake_cpu_state = 0;
		goto done;
	}

	/*
	 * The queue DSQ a task is placed in is owned by the CPU it is
	 * enqueued to. A wakeup lands on prev_cpu, the CPU the task was
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
	/* A concurrent affinity change may have dropped target_cpu. Use the enqueueing CPU. */
	if (!bpf_cpumask_test_cpu((u32)target_cpu, p->cpus_ptr))
		target_cpu = bpf_get_smp_processor_id();

	/*
	 * A placement targeted at a CPU a realtime task is occupying is
	 * redirected to a non-occupied CPU, and a wakeup's preemption is
	 * skipped. Preempting into an occupied CPU's local DSQ would
	 * strand the wakeup behind the realtime task, so it proceeds
	 * to the regular vtime placement into the owning queue
	 * DSQ instead. The redirect covers wakeups and the reenqueues of
	 * the takeover drain alike. A reenqueued task's target is the
	 * enqueueing CPU, which is the taken-over one, so without the
	 * redirect the evacuation would only re-anchor the task in
	 * place. The regular placement kicks the fallback CPU, so the
	 * redirected task runs there. Classification and the lag clamp
	 * are untouched. Only the owning queue DSQ changes, and the
	 * queue DSQs of different CPUs share the per-queue virtual
	 * clock, so the placement is identical wherever it lands. Run-out
	 * re-enqueues and pinned tasks get no redirect. A run-out can be
	 * enqueued by the kernel while the CPU is being taken over,
	 * before the hook marks it, and lands in the owning queue DSQ
	 * where the takeover drain or the steal scans serve it. A pinned
	 * task cannot legally run elsewhere.
	 */
	if ((wakeup || (enq_flags & SCX_ENQ_REENQ)) &&
	    mlfq_cpu_occupied(target_cpu)) {
		s32 fallback = mlfq_pick_unoccupied_cpu(p, bpf_get_smp_processor_id());

		skip_preempt = true;
		if (fallback >= 0) {
			target_cpu = fallback;
			__sync_fetch_and_add(&mlfq_stats.rt_redirects, 1);
		}
	}

	/*
	 * Wakeup preemption: a wakeup outranks the task running on the CPU
	 * it was last running on when it belongs to a higher queue (the
	 * check_preempt_wakeup semantics of the fair scheduler, where the
	 * higher-priority arrival preempts), or when it belongs to the
	 * same queue and the same-queue rule is met. An interactive wakeup
	 * onto an interactive resident preempts on the residency guard
	 * alone. Interactive wakeups need immediate service, and the
	 * virtual-time order still governs the queue DSQ, while the
	 * preemption is the wakeup-latency mechanism. The guard protects
	 * the waker's own run and prevents preemption thrash. A Q2/Q3
	 * wakeup preempts only when its fresh deadline is earlier than the
	 * resident's, the conservative EEVDF rule. The wakee is dispatched
	 * to that CPU's local DSQ with SCX_ENQ_PREEMPT, which the kernel
	 * resolves into a preemption on the next scheduling event. The
	 * ENQ_PREEMPT path puts the task at the local-DSQ head, zeroes the
	 * resident's slice and rescheds. The preempting wakeup is granted
	 * only a capped slice (MLFQ_PREEMPT_SLICE_NS), so it yields back to
	 * the displaced task at the next scheduling event instead of holding
	 * the CPU for a full policy slice. The local-DSQ insert is FIFO, so
	 * the wakee's deadline is computed only for the non-interactive
	 * comparison and is not committed. Placement is deferred to the
	 * next real placement, which re-anchors the task under the lag
	 * clamp. A concurrent affinity change between CPU selection and
	 * enqueue must not target a CPU outside the allowed set; the
	 * local-DSQ insert is a same-rq operation, so the failure is a
	 * placement violation rather than a fatal error, and the queue
	 * placement is the correct fallback. The redirect above sets
	 * skip_preempt when the target CPU is occupied, so this block never
	 * inserts into an occupied CPU's local DSQ.
	 */
	if (wakeup && !migration_disabled && !skip_preempt) {
		struct mlfq_cpu_state *prev_state = mlfq_lookup_cpu_state(prev_cpu);
		bool owed = false;

		if (prev_state && prev_state->running_pid &&
		    prev_state->running_pid != p->pid &&
		    prev_state->running_queue > 0 &&
		    bpf_cpumask_test_cpu((u32)prev_cpu, p->cpus_ptr)) {
			if ((s32)qid < prev_state->running_queue) {
				owed = true;
			} else if (qid == prev_state->running_queue) {
				u64 wakee_deadline = 0;

				/*
				 * Same queue. The Q1 rule needs no
				 * deadline, so the fresh placement is
				 * computed (without committing it, see
				 * above) only for the non-interactive
				 * rule.
				 */
				if (qid > 1) {
					struct queue_ctx *q = mlfq_lookup_queue(qid);

					if (q)
						wakee_deadline =
							mlfq_place_entity_deadline(q, tctx);
				}

				owed = mlfq_sameq_preempt_owed(
					qid, (u8)prev_state->running_queue,
					wakee_deadline,
					prev_state->running_deadline,
					prev_state->run_start_at,
					now, mlfq_adapt_state.guard_eff_ns);
			}
		}

		if (owed) {
			u64 preempt_slice = slice;

			/*
			 * Cap the grant: a preempting wakeup displaces a
			 * running task, so it runs a bounded burst
			 * (MLFQ_PREEMPT_SLICE_NS) and then yields, so the
			 * displaced task (typically the waker, whose early
			 * deadline puts it first in the virtual-time order)
			 * resumes at the next scheduling event. The policy
			 * slice still governs the regular path and the
			 * continuation after the run-out re-enqueue.
			 */
			if (mlfq_preempt_slice_ns < preempt_slice)
				preempt_slice = mlfq_preempt_slice_ns;
			mlfq_runnable_enter(tctx, (u8)qid,
					    mlfq_llc_of_cpu((u32)prev_cpu));
			mlfq_stamp_enq_at(tctx, now, wakeup);
			scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | (u64)prev_cpu,
					   preempt_slice, enq_flags | SCX_ENQ_PREEMPT);
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
		mlfq_op_lat_charge(MLFQ_OP_LAT_ENQUEUE, op_lat_start);
		return;
	}

	__sync_fetch_and_add(&mlfq_stats.enq_regular, 1);
	mlfq_runnable_enter(tctx, (u8)qid,
			    mlfq_llc_of_cpu((u32)target_cpu));
	mlfq_stamp_enq_at(tctx, now, wakeup);
	scx_bpf_dsq_insert_vtime(p, mlfq_dsq_id(qid, target_cpu),
				 slice, deadline, enq_flags);
	mlfq_stat_placement(qid);

	/* Keep the fast-path state from leaking into the next enqueue. */
	tctx->wake_cpu_state = 0;

	mlfq_idle_kick(target_cpu);

done:
	mlfq_op_lat_charge(MLFQ_OP_LAT_ENQUEUE, op_lat_start);
	;
}
