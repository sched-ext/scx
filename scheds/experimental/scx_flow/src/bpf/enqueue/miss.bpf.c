// SPDX-License-Identifier: GPL-2.0
/*
 * Enqueue miss rejoin for the flow scheduler.
 *
 * Holds the self-contained miss path with the fresh deadline plus the
 * held slice plus the strict fair time plus the shared RED admit plus
 * the tier rejoin. A miss on the last deadline counts before the new
 * deadline, so the miss count tracks wall completion past deadline with
 * skip aging. The miss holds the stored slice else floors it to 10us
 * with no dynamic recompute, then rejoins via the same tier escalation
 * re-derived with the fresh deadline, so urgency returns at once with
 * no starvation. RED uses the same O(1) newcomer check through the
 * shared outlined helper, so a reject needs cost past the fixed 256us Emax plus cost past the exceed with no critical. Tolerance aids only
 * the guarantee without shaping the key. A full O(n) least value scan
 * stays a noted alternative, so the verifier keeps one pass. Critical
 * follows the unified latency, so RED and slice agree. Like fair.c,
 * the earliest key wins, unlike rt.c, no fixed priority holds. Runs
 * under the caller with one kick at most.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
/**
 * flow_enqueue_miss - rejoin one missed task in tier order.
 * @p: task to rejoin, passed to the tier plus reject inserts.
 * @t: miss tail with state plus target plus hint plus time plus flags.
 *
 * Counts one miss before the fresh deadline, holds the stored slice
 * else floors it to 10us, then rejoins via the same tier escalation
 * re-derived with the fresh deadline plus skip aging. RED on the rejoin
 * uses the shared outlined helper with cost past Emax plus cost past
 * exceed and never critical. A reject joins the value ordered queue
 * with one idle kick, else the tier queue with one admit plus one idle
 * kick. Queue order uses the strict fair time capped at now plus one
 * period, so far keys never starve past the bound while placement tests
 * the deadline. Returns true when the miss took with no further work
 * for the caller, else false when no miss holds.
 *
 * Outlined with noinline to keep verifier headroom and the miss plus
 * open paths share no inline growth with the same order plus the same
 * counts.
 */
static __noinline bool flow_enqueue_miss(struct task_struct *p,
	const struct flow_miss_tail *t)
{
	struct flow_task_ctx *tctx;
	s32 cpu;
	s32 sel;
	u64 now;
	u64 enq_flags;
	u32 hint;
	u32 hint_w;
	u64 avg;
	u64 dev;
	u64 m_sleep;
	u64 ndl;
	u64 nvt;
	u32 msl;
	bool mcrit;
	if (!p || !t)
		return false;
	tctx = t->tctx;
	if (!tctx)
		return false;
	cpu = t->cpu;
	sel = t->sel;
	now = t->now;
	enq_flags = t->enq_flags;
	hint = t->hint;
	hint_w = t->hint_w;
	avg = t->avg;
	dev = t->dev;
	/* No miss without a stored deadline past now, so fresh work falls */
	/* through to the open compute with no count and no deadline move. */
	if (!READ_ONCE(tctx->deadline))
		return false;
	if (!flow_missed(READ_ONCE(tctx->deadline), now))
		return false;
	/* A miss holds the stored slice else floors it to 10us with no */
	/* dynamic recompute via the shared miss helper, then rejoins via */
	/* the same tier escalation re-derived with the fresh deadline plus */
	/* skip aging in the miss count, so urgency returns at once with no */
	/* starvation. */
	flow_count_miss(tctx);
	m_sleep = flow_take_sleep(tctx, now, avg);
	ndl = flow_pred_deadline(now, avg, dev, hint);
	__sync_lock_test_and_set(&tctx->deadline, ndl);
	__sync_lock_test_and_set(&tctx->slice_ns,
	    flow_slice_miss_hold(READ_ONCE(tctx->slice_ns)));
	nvt = flow_make_fair(tctx, ndl, hint_w);
	/* In-tier keys cap at now plus one period through the shared */
	/* helper, so far keys never starve past the bound. */
	nvt = flow_enqueue_cap_key(nvt, now);
	/* RED on the miss rejoin with the same O(1) newcomer check through */
	/* the shared outlined helper, so a reject needs cost past the */
	/* fixed 256us Emax plus cost past the exceed with no critical. */
	/* Tolerance aids only the guarantee without shaping the key. */
	/* A full O(n) least value scan stays a noted alternative, so */
	/* the verifier keeps one pass. Critical follows the unified */
	/* latency through the shared test, so RED and slice agree. */
	msl = READ_ONCE(tctx->slice_ns);
	mcrit = flow_enqueue_is_lat(avg, dev, hint, m_sleep,
	    flow_task_effective_weight(READ_ONCE(tctx->weight), hint_w));
	{
		struct flow_reject_tail rej = {
			.tctx = tctx,
			.deadline = ndl,
			.now = now,
			.avg = avg,
			.slice = msl,
			.is_lat = mcrit,
			.hint_w = hint_w,
			.enq_flags = enq_flags,
			.sel = sel,
		};
		if (flow_enqueue_reject(p, &rej))
			return true;
	}
	flow_tier_insert(p, cpu, nvt, now);
	flow_count_admit();
	flow_kick_idle_allowed(p, sel);
	return true;
}
