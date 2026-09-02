/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 *
 * Classification, tree inference, EMA gauge, queue mapping and hysteresis.
 *
 * The tree predicts the next burst from the captured features and maps
 * the prediction to the queues. The EMA gauge remains a feature and the
 * untrained fallback. The gauge is a continuous interactivity measure
 * mapped onto the three queues. It climbs per run segment in stopping()
 * and decays per sleep at wakeup. See mlfq_ema_climb()/mlfq_ema_decay()
 * in intf.h. Queue changes are asymmetric. The wakeup path is
 * promotion-only (the tree raises the queue, and the short-sleep and
 * band hysteresis promote), while demotions flow through the run-out
 * gate in enqueue.bpf.c, whose consecutive-exhaustion counters
 * (mlfq_demote_on_reenq in intf.h) implement the demotion hysteresis.
 */

#include <bpf/bpf_core_read.h>

/*
 * in_iowait guard. task_struct::in_iowait is a 1-bit bitfield read with
 * BPF_CORE_READ_BITFIELD. Define MLFQ_HAVE_IN_IOWAIT to 0 when the
 * kernel type header does not expose the field.
 */
#ifndef MLFQ_HAVE_IN_IOWAIT
#define MLFQ_HAVE_IN_IOWAIT 1
#endif

/*
 * uclamp_min guard. task_struct::uclamp_req only exists with
 * CONFIG_UCLAMP_TASK; the kernel type header used for this build does
 * not expose it, so the guard is compiled out. Define
 * MLFQ_HAVE_TASK_UCLAMP_MIN to 1 when the kernel type header provides
 * the field.
 */
#ifndef MLFQ_HAVE_TASK_UCLAMP_MIN
#define MLFQ_HAVE_TASK_UCLAMP_MIN 0
#endif

static __always_inline bool mlfq_demotion_blocked(const struct task_struct *p)
{
#if MLFQ_HAVE_TASK_UCLAMP_MIN
	/* UCLAMP_MIN > 0 marks a latency-sensitive task. Keep its queue. */
	return BPF_CORE_READ(p, uclamp_req[0].value) > 0;
#else
	(void)p;
	return false;
#endif
}

/*
 * The task is waking from I/O when task_struct::in_iowait is set. The
 * bitfield is read with the CO-RE bitfield macro (direct memory read is
 * fine for the trusted task pointer ops.enqueue receives). The parameter
 * is intentionally not named p, because BPF_CORE_READ_BITFIELD() declares
 * its own local named p and would shadow it.
 *
 * Return: true if @task is an I/O waiter.
 */
static __always_inline bool mlfq_task_io_wait(const struct task_struct *task)
{
#if MLFQ_HAVE_IN_IOWAIT
	return BPF_CORE_READ_BITFIELD(task, in_iowait);
#else
	(void)task;
	return false;
#endif
}

/*
 * SCHED_IDLE tasks always run in Q3.
 *
 * Return: true if @p is SCHED_IDLE.
 */
static __always_inline bool mlfq_apply_sched_idle(const struct task_struct *p,
						  struct task_ctx *tctx)
{
	if (p->policy == MLFQ_SCHED_IDLE) {
		tctx->queue = 3;
		return true;
	}
	return false;
}

/*
 * Climb the gauge for a run segment (stopping path). The
 * delta is clamped by mlfq_ema_climb(), so a CPU-bound task saturates the
 * gauge and the classification thresholds keep it out of Q1.
 */
static __always_inline void mlfq_ema_climb_task(struct task_ctx *tctx,
						u64 delta_ns)
{
	tctx->ema = mlfq_ema_climb(tctx->ema, delta_ns, mlfq_budget_max_ns,
				   mlfq_alpha);
#if MLFQ_CHECK
	if (!mlfq_check_ema_bounds(tctx->ema, mlfq_budget_max_ns))
		scx_bpf_error("ema %llu exceeds budget max after climb",
			      tctx->ema);
#endif
}

/*
 * mlfq_wakeup_classify - Wakeup classification.
 * @p: The task.
 * @tctx: The task context.
 * @now: Current time (scx_bpf_now()).
 *
 * Applies, in order, the EMA decay over the sleep, the tree inference on
 * the captured features, the rate-limited short-sleep IPC boost, the
 * band-hysteresis promotion and, on the untrained fallback only, the
 * long-sleep base-mapping boost. It updates the promotion, boost and tree
 * stats.
 *
 * The tree mapping is promotion-only (mlfq_tree_map_queue). The tree is
 * authoritative for raising the queue at the wakeup, and demotions are
 * the run-out gate's job, so a single wakeup prediction can never demote
 * a task and bypass the exhaustion hysteresis. The tree inference is a
 * pure conditional at the top of the mapping. While untrained (pred ==
 * 0) the classification below runs on the EMA gauge alone, and the boost
 * and the hysteresis are unconditional in both paths, so the tree can
 * never take away the latency guarantees.
 */
static __always_inline void mlfq_wakeup_classify(const struct task_struct *p,
						 struct task_ctx *tctx, u64 now)
{
	u64 sleep_ns = 0, base_q, pred = 0;
	bool io_wait = mlfq_task_io_wait(p);

	if (tctx->last_sleep_at && mlfq_time_before(tctx->last_sleep_at, now)) {
		sleep_ns = now - tctx->last_sleep_at;
		tctx->ema = mlfq_ema_decay(tctx->ema, sleep_ns,
					   mlfq_ema_half_life_ns);
#if MLFQ_CHECK
		if (!mlfq_check_ema_bounds(tctx->ema, mlfq_budget_max_ns))
			scx_bpf_error("pid %d ema %llu out of bounds after decay",
				      p->pid, tctx->ema);
#endif
	}
	tctx->last_sleep_at = 0;
	tctx->reenq_cnt = 0;

	/*
	 * Capture the pending sample features once, after the decay, and
	 * run the tree inference on that same vector: the captured
	 * features feed both the pending sample (completed with the run
	 * segment in ops.stopping()) and the live queue mapping, so the
	 * sample and the classification are consistent with each other.
	 * The queue is snapshotted at the same instant, so the emitted
	 * sample's queue field is the capture-time queue, not the queue
	 * later placement decisions (aging, a subsequent classification)
	 * leave behind. The prediction also doubles as the trained gate.
	 * The walk returns 0 while untrained, so the fallback is a pure
	 * conditional on it.
	 *
	 * SCHED_IDLE tasks are policy-pinned to Q3 and the tree never
	 * classifies them, so their samples would only pollute the
	 * training. The capture is skipped, any pending sample is dropped
	 * and pred stays 0, which is the untrained mapping below. The
	 * skip is policy service, not fallback service. A SCHED_IDLE
	 * classification is never counted against tree_fallback, even
	 * while the tree is untrained.
	 */
	if (p->policy == MLFQ_SCHED_IDLE) {
		tctx->pending_valid = 0;
		pred = 0;
	} else {
		tctx->pending_feats.prev_burst_ns = tctx->prev_burst_ns;
		tctx->pending_feats.sleep_ns = sleep_ns;
		tctx->pending_feats.ema = tctx->ema;
		tctx->pending_feats.io_wait = io_wait;
		tctx->pending_feats.wake_cnt = tctx->wake_cnt;
		/*
		 * The service features are the measured values of the
		 * previous episode (the last wakeup latency, the last
		 * queue wait and the service-quality EMA), captured as
		 * emitted data.
		 */
		tctx->pending_feats.wake_lat_us =
			tctx->last_wake_lat_ns / NSEC_PER_USEC;
		tctx->pending_feats.queue_wait_us =
			tctx->last_q_wait_ns / NSEC_PER_USEC;
		tctx->pending_feats.sq_ema = tctx->sq_ema;
		tctx->pending_feats.sleep_var_ratio = tctx->sleep_var_ratio;
		tctx->pending_feats.pad = 0;
		tctx->pending_feats.gpu_submit = tctx->gpu_submit;
		tctx->pending_feats.pad2 = 0;
		tctx->pending_queue = tctx->queue;
		tctx->pending_valid = 1;

		pred = mlfq_tree_predict(&tctx->pending_feats);
	}

	/*
	 * Q3 clamp: gpu_submit is Q1-only, not Q3-defining. A leaf that
	 * splits on gpu_submit>0 must not push the Q3 threshold up for
	 * throughput tasks that never submit GPU work. A prediction that
	 * would map to Q3 is therefore demoted to Q2 when the task
	 * recently submitted GPU work, unless the sleep or the previous
	 * burst also indicates Q3.
	 *
	 * Paired with the Q3 seed below in mlfq_wakeup_classify() and the
	 * mirrored seed in mlfq_runout_classify(): the seeds keep Q3
	 * labels alive for gpu_submit == 0 throughput tasks, while this
	 * clamp keeps gpu_submit from becoming a Q3-defining feature.
	 * Together they implement gpu_submit as Q1-only. Keep both; the
	 * clamp without the seed still starves Q3, and the seed without
	 * the clamp still pollutes Q3.
	 */
	if (pred >= mlfq_adapt_state.t_bnd_eff_ns && tctx->gpu_submit > 0 &&
	    !(sleep_ns > mlfq_short_sleep_ns ||
	      tctx->prev_burst_ns > mlfq_adapt_state.t_h_eff_ns))
		pred = mlfq_adapt_state.t_bnd_eff_ns - 1;

	if (pred) {
		/*
		 * The mapping is promotion-only. The tree is authoritative
		 * for promotions at the wakeup, and demotions flow through
		 * the run-out gate (mlfq_demote_on_reenq) with its
		 * consecutive-exhaustion hysteresis, so a single wakeup
		 * prediction can never demote a task. This is the
		 * classic MLFQ asymmetry. tree_disagree compares the
		 * mapping result against the EMA base band.
		 */
		tctx->queue = mlfq_tree_map_queue(pred, tctx->queue,
						  mlfq_adapt_state.t_int_eff_ns,
						  mlfq_adapt_state.t_bnd_eff_ns);
		__sync_fetch_and_add(&mlfq_stats.tree_inference, 1);
		base_q = mlfq_queue_from_ema(tctx->ema,
					     mlfq_adapt_state.t_l_eff_ns,
					     mlfq_adapt_state.t_h_eff_ns);
		if (tctx->queue != base_q)
			__sync_fetch_and_add(&mlfq_stats.tree_disagree, 1);
	} else if (p->policy != MLFQ_SCHED_IDLE) {
		/*
		 * Untrained fallback (the walk returns 0 until the first
		 * model is published). SCHED_IDLE is excluded above: its
		 * classification is policy-pinned, not fallback-served.
		 */
		__sync_fetch_and_add(&mlfq_stats.tree_fallback, 1);
	}

	/*
	 * The IPC boost. A wakeup from I/O or a short sleep is treated as
	 * interactive and placed in Q1, rate-limited per task (the
	 * stand-in for the kernel's futex/IPC wakeup fast paths). The
	 * rate limit is part of mlfq_ss_boost_pending(), which the CPU
	 * selection also consults so the two paths agree on whether the
	 * wakeup will be treated as interactive. The boost is
	 * unconditional. It runs after the tree mapping in both paths,
	 * so the tree can never take the latency guarantee away.
	 *
	 * SCHED_IDLE tasks are forced to Q3 by mlfq_apply_sched_idle, so
	 * a boost would burn the rate-limit budget and push the counter
	 * up to no effect. It is gated on the task policy.
	 */
	if (p->policy != MLFQ_SCHED_IDLE &&
	    mlfq_ss_boost_pending(tctx, sleep_ns, io_wait, now,
				  mlfq_short_sleep_ns, mlfq_short_sleep_rate_limit_ns)) {
		tctx->queue = 1;
		tctx->last_ss_boost_at = now;
		__sync_fetch_and_add(&mlfq_stats.short_sleep_boosts, 1);
	}

	if (mlfq_promote_on_wakeup(tctx, sleep_ns,
				   mlfq_adapt_state.t_l_eff_ns,
				   mlfq_adapt_state.t_h_eff_ns,
				   mlfq_hysteresis_sleep_ns))
		__sync_fetch_and_add(&mlfq_stats.promotions, 1);

	/*
	 * A long sleep collapses the gauge. Re-adopt the base mapping so
	 * an interactive task cannot be stuck in Q3. This is the
	 * untrained fallback. A trained tree already saw the long sleep
	 * in its sleep_ns feature, so the remap would be redundant and
	 * would fight the tree mapping.
	 */
	if (!pred && sleep_ns > mlfq_long_sleep_ns) {
		base_q = mlfq_queue_from_ema(tctx->ema,
					     mlfq_adapt_state.t_l_eff_ns,
					     mlfq_adapt_state.t_h_eff_ns);
		if (base_q < tctx->queue) {
			tctx->queue = base_q;
			__sync_fetch_and_add(&mlfq_stats.promotions, 1);
		}
	}

	/*
	 * Q3 seed for throughput tasks that never submit GPU work.
	 * Throughput tasks with gpu_submit == 0 would otherwise never
	 * emit Q3 labels once the tree learns a gpu_submit > 0 split
	 * for Q1 and pushes the Q3 threshold up. Seed one Q3 placement
	 * when the previous burst exceeds T_H and the sleep exceeds
	 * MLFQ_SHORT_SLEEP_NS, so the sample completed in stopping()
	 * carries a Q3 label into the next training window.
	 *
	 * Paired with the Q3 clamp above: the clamp demotes Q3
	 * predictions for gpu_submit > 0 tasks to Q2, while this seed
	 * preserves Q3 labels for gpu_submit == 0 tasks. Together they
	 * implement gpu_submit as Q1-only, not Q3-defining. Keep both;
	 * removing either reintroduces Q3 starvation or Q3 pollution.
	 *
	 * Invariant: I/O latency is strictly dominant. The seed is
	 * gated on !io_wait and ordered after the I/O/short-sleep boost
	 * (mlfq_ss_boost_pending() / mlfq_boost_eligible()), so a task
	 * waking from I/O stays in Q1 for this episode even when its
	 * burst and sleep would otherwise match Q3. This avoids a
	 * one-episode latency inversion for gpu_submit == 0, long-sleep,
	 * large-burst I/O tasks. See also mlfq_runout_classify() which
	 * seeds on the run-out path with no sleep guard (sleep == 0,
	 * io_wait == 0 there) and is left unchanged.
	 *
	 * One branch, no loop. Preserves per-queue EEVDF bounded lag and
	 * the 64/84/240 V4 NR9 ABI (task_ctx 240 with dedup timestamp);
	 * verifier stays within 1M insn / 512B stack.
	 */
	if (!io_wait && tctx->gpu_submit == 0 &&
	    tctx->prev_burst_ns > mlfq_adapt_state.t_h_eff_ns &&
	    sleep_ns > mlfq_short_sleep_ns && tctx->queue != 3)
		tctx->queue = 3;
}

/*
 * mlfq_runout_classify - Slice-exhaustion demotion.
 * @p: The task.
 * @tctx: The task context.
 *
 * The run-out re-enqueue arrives through ops.enqueue() with flags == 0,
 * delivered by put_prev_task_scx()'s do_enqueue_task(rq, p, 0, -1), and is
 * the scx equivalent of the tick/demotion path. It is the only enqueue
 * without flag bits, which identifies it at the routing in enqueue(). The
 * consecutive-exhaustion counter gates the band crossing, the tree
 * prediction gates the CPU-bound test once trained, and uclamp_min tasks
 * keep their queue.
 */
static __always_inline void mlfq_runout_classify(const struct task_struct *p,
						 struct task_ctx *tctx)
{
	u64 pred;

	/*
	 * Capture the pending sample features before the wake_cnt reset
	 * below and run the tree inference on the same vector, which
	 * gates the demotion. A run-out re-enqueue is not a wakeup, so
	 * the sleep length is zero and the task is not in iowait.
	 *
	 * The run-out capture (sleep=0, io=0) intentionally re-arms the
	 * pending sample with the run-out state. That state is the
	 * correct feature vector for the run-out inference point. The
	 * wakeup-armed samples survive for tasks that block within a
	 * slice. A task that sleeps mid-slice keeps the wakeup capture
	 * for its emission, and only a run-out re-enqueue overwrites the
	 * pending block. The queue is snapshotted with the features, as
	 * on the wakeup path.
	 *
	 * SCHED_IDLE tasks are pinned to Q3 and never demoted, so their
	 * captures are skipped like the wakeup path's, and the skip is
	 * policy service, not fallback service. It is not counted
	 * against tree_fallback either.
	 */
	if (p->policy == MLFQ_SCHED_IDLE) {
		tctx->pending_valid = 0;
		pred = 0;
	} else {
		tctx->pending_feats.prev_burst_ns = tctx->prev_burst_ns;
		tctx->pending_feats.sleep_ns = 0;
		tctx->pending_feats.ema = tctx->ema;
		tctx->pending_feats.io_wait = 0;
		tctx->pending_feats.wake_cnt = tctx->wake_cnt;
		tctx->pending_feats.wake_lat_us =
			tctx->last_wake_lat_ns / NSEC_PER_USEC;
		tctx->pending_feats.queue_wait_us =
			tctx->last_q_wait_ns / NSEC_PER_USEC;
		tctx->pending_feats.sq_ema = tctx->sq_ema;
		tctx->pending_feats.sleep_var_ratio = tctx->sleep_var_ratio;
		tctx->pending_feats.pad = 0;
		tctx->pending_feats.gpu_submit = tctx->gpu_submit;
		tctx->pending_feats.pad2 = 0;
		tctx->pending_queue = tctx->queue;
		tctx->pending_valid = 1;

		pred = mlfq_tree_predict(&tctx->pending_feats);
		if (pred)
			__sync_fetch_and_add(&mlfq_stats.tree_inference, 1);
		else
			__sync_fetch_and_add(&mlfq_stats.tree_fallback, 1);
	}

	tctx->wake_cnt = 0;

	/*
	 * Q3 seed for the run-out path, mirroring the wakeup seed except
	 * for the sleep / I/O gate. A throughput task with gpu_submit == 0
	 * and a large previous burst (> T_H) would otherwise never emit
	 * Q3 labels once the tree splits on gpu_submit. Force one Q3
	 * placement so the next window regains Q3 labels. No sleep check
	 * here: a run-out re-enqueue has sleep == 0 and io_wait == 0 by
	 * construction (see the capture above), so the I/O-dominance
	 * invariant and the MLFQ_SHORT_SLEEP_NS guard only apply to the
	 * wakeup seed in mlfq_wakeup_classify(). One branch, no loop.
	 */
	if (tctx->gpu_submit == 0 &&
	    tctx->prev_burst_ns > mlfq_adapt_state.t_h_eff_ns &&
	    tctx->queue != 3)
		tctx->queue = 3;

	if (mlfq_demotion_blocked(p))
		return;
	if (mlfq_demote_on_reenq(tctx, mlfq_adapt_state.t_h_eff_ns,
				 mlfq_adapt_state.t_bnd_eff_ns, pred))
		__sync_fetch_and_add(&mlfq_stats.demotions, 1);
}
