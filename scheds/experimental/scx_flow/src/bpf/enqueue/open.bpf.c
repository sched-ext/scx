// SPDX-License-Identifier: GPL-2.0
/*
 * Enqueue open compute for the flow scheduler.
 *
 * Holds the fresh plus requeue fair time with the dynamic slice plus
 * the latency clamp plus the strict key. Fresh waits earn the dynamic
 * remaining clamp to 10us plus 1ms with the tier cap plus the 100us
 * latency clamp, while requeues hold the stored charge else inherit the
 * quantum with no recompute. The slice holds the dynamic remaining
 * clamp on fresh waits else the held charge on requeues, so near
 * deadlines earn near virtual times without a band jump. Sleep isolates
 * the true gap as now minus wait minus burst, so queue plus run never
 * look like sleep. In-tier keys cap at now plus one period, so far keys
 * never starve past the bound. Like fair.c, the cap paces service,
 * unlike rt.c, no fixed priority holds. Runs under the caller with the
 * shared RED plus place plus kick left to the dispatcher.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
/**
 * flow_enqueue_open - compute one open fair time with out fields.
 * @t: open tail with state plus deadline plus hint plus time plus flags.
 * @out: out fields with fair time plus RED cost plus kick sleep.
 *
 * A fresh wait clamps the slice to 100us plus caps the key to now plus
 * max 4ms else slice plus 100us via the strict key, while RED stays on
 * the original deadline. A preempted head resumes without a slice
 * rewrite here, so the stored leftover stays with one charge in
 * stopping. A requeue holds the stored charge else inherits the quantum
 * on zero, so the virtual deadline tracks the same charge the key
 * sorts. The effective share stacks task times hint over 128, so
 * cgroup plus task weights shape fairness together. Latency recomputes
 * per enqueue without a stored bit, so 72B holds. Fills the fair time
 * plus the pre-clamp slice plus the sleep plus the latency plus the
 * fresh flag, so the dispatcher keeps one shared RED admit plus one
 * eligibility plus one place plus kick with no second compute.
 *
 * Outlined with noinline to keep verifier headroom and the fresh plus
 * requeue paths share one divide copy with the same order.
 */
static __noinline void flow_enqueue_open(const struct flow_open_tail *t,
	struct flow_open_out *out)
{
	struct flow_task_ctx *tctx;
	u64 deadline;
	u64 now;
	u64 enq_flags;
	u32 hint;
	u32 hint_w;
	u64 avg;
	u64 dev;
	bool is_reenq;
	if (!t || !out)
		return;
	tctx = t->tctx;
	if (!tctx) {
		out->vtime = 0;
		out->pre_slice = 0;
		out->sleep_ns = 0;
		out->is_lat = false;
		out->is_fresh = !t->is_reenq;
		return;
	}
	deadline = t->deadline;
	now = t->now;
	enq_flags = t->enq_flags;
	hint = t->hint;
	hint_w = t->hint_w;
	avg = t->avg;
	dev = t->dev;
	is_reenq = t->is_reenq;
	out->vtime = 0;
	out->pre_slice = 0;
	out->sleep_ns = 0;
	out->is_lat = false;
	out->is_fresh = !is_reenq;
	/* Latency recompute per enqueue without a stored bit, so 72B holds. */
	/* A fresh wait clamps the slice to 100us plus caps the key to now */
	/* plus max 4ms else slice plus 100us via the strict key, while RED */
	/* stays on the original deadline. Like fair.c, the cap paces */
	/* service, unlike rt.c, no fixed priority holds. A preempted head */
	/* resumes via lifecycle only without a slice rewrite here, so the */
	/* stored leftover stays with one charge in stopping. Sleep isolates */
	/* the true gap as now minus wait minus burst, so queue plus run */
	/* never look like sleep. In-tier keys cap at now plus one period, */
	/* so far keys never starve past the bound. */
	if (!is_reenq) {
		u64 lat_sleep = flow_take_sleep(tctx, now, avg);
		bool is_lat;
		u32 pre_slice;
		u32 lat_slice;
		u64 lat_vt;
		u64 vtime;
		/* No stable uclamp field in this task view, so fail open to */
		/* zero without an extra map, and the ext helper keeps the veto */
		/* for callers that thread a real clamp. Probation holds through */
		/* both helpers, so newcomers stay batch. Latency shares one */
		/* copy with miss plus pinned, so the open path keeps headroom. */
		is_lat = flow_enqueue_is_lat(avg, dev, hint, lat_sleep,
		    flow_task_effective_weight(READ_ONCE(tctx->weight),
		    hint_w));
		pre_slice = flow_slice_for(deadline, now);
		pre_slice = flow_slice_tier_cap(pre_slice, avg, dev, is_lat);
		lat_slice = flow_slice_lat_clamp(pre_slice, is_lat);
		out->is_lat = is_lat;
		out->pre_slice = pre_slice;
		out->sleep_ns = lat_sleep;
		out->is_fresh = true;
		if (enq_flags & SCX_ENQ_PREEMPT) {
			vtime = flow_make_fair(tctx, deadline, hint_w);
		} else {
			u64 lat_dl;
			__sync_lock_test_and_set(&tctx->slice_ns, lat_slice);
			lat_vt = flow_make_fair(tctx, deadline, hint_w);
			if (is_lat) {
				lat_dl = flow_lat_deadline(now, lat_slice);
				vtime = flow_edf_key(lat_vt, lat_dl);
			} else {
				vtime = lat_vt;
			}
		}
		vtime = flow_enqueue_cap_key(vtime, now);
		out->vtime = vtime;
	} else {
		u64 re_sleep = flow_take_sleep(tctx, now, avg);
		u64 vtime;
		/* Strict slice before the key without stale reuse. A slice */
		/* rotation holds the stored charge else inherits the quantum */
		/* on zero, so the virtual deadline tracks the same charge the */
		/* key sorts. The remaining time feeds the slice plus slack only */
		/* with the sort staying the earlier of deadline plus virtual */
		/* time. */
		out->sleep_ns = re_sleep;
		out->is_fresh = false;
		out->pre_slice = 0;
		/* RED latency for the requeue uses the same unified test on */
		/* the same gap through the shared helper, so RED and slice */
		/* agree with no second wait read at the caller. */
		out->is_lat = flow_enqueue_is_lat(avg, dev, hint, re_sleep,
		    flow_task_effective_weight(READ_ONCE(tctx->weight),
		    hint_w));
		__sync_lock_test_and_set(&tctx->slice_ns,
		    flow_slice_inherit(READ_ONCE(tctx->slice_ns)));
		/* Strict EDF key from the virtual deadline plus the EDF */
		/* deadline. Heavy tasks earn a near virtual time while light */
		/* tasks earn a far one with one divide, so the earlier of the */
		/* two paces order with latency still capped by the deadline. */
		/* The effective share stacks task times hint over 128, so */
		/* cgroup plus task weights shape fairness together. In-tier */
		/* keys cap at now plus one period through the shared helper, */
		/* so far keys never starve past the bound. */
		vtime = flow_make_fair(tctx, deadline, hint_w);
		vtime = flow_enqueue_cap_key(vtime, now);
		out->vtime = vtime;
	}
}
