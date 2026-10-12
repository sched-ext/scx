// SPDX-License-Identifier: GPL-2.0
/*
 * Enqueue tier inserts plus fair time for the flow scheduler.
 *
 * Holds the local plus node plus machine plus overflow inserts with
 * the hoisted combined drain escalation plus the shared fair time
 * plus the lag clamp plus the pinned wait path. Queue order uses the
 * earlier of the deadline plus the virtual deadline, so urgent tasks
 * still win while hogs fall behind with lag bounds. Tasks join direct
 * when the target can drain before the shared home, so no task waits
 * for a busy CPU while shared room stays open. Strict PRIQ holds with
 * no batch bias plus no new map plus no new queue plus no knob,
 * reusing the tier escalation plus the slowest sufficient pick.
 * Every tier join counts one admit with no reject, so the counters
 * track joins with no bound. Runs under the caller with no lock.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
/* Insert one task into the local tier of one CPU with fair order. */
static __always_inline void flow_local_insert(struct task_struct *p, s32 cpu, u64 vtime)
{
	scx_bpf_dsq_insert_vtime(p, flow_local_dsq((u32)cpu), (u64)FLOW_QUANTUM_NS, vtime, 0);
}
/* Insert one task into the shared tier of one node with fair order. */
static __always_inline void flow_node_insert(struct task_struct *p, u32 node, u64 vtime)
{
	scx_bpf_dsq_insert_vtime(p, flow_node_dsq(node), (u64)FLOW_QUANTUM_NS, vtime, 0);
}
/* Insert one task into the machine tier with fair order. */
static __always_inline void flow_machine_insert(struct task_struct *p, u64 vtime)
{
	scx_bpf_dsq_insert_vtime(p, flow_machine_dsq(), (u64)FLOW_QUANTUM_NS, vtime, 0);
}
/* Insert one task into the reject queue value ordered with no FIFO. */
/* Orders by decreasing value through the kernel priority queue, so the */
/* greatest value drains first on reclaim with no extra map. Value */
/* picks the order with no vruntime shaping. Runs */
/* outside dispatch with reclaim only, so dispatch tiers stay strict. */
static __always_inline void flow_overflow_insert(struct task_struct *p, u64 enq_flags, u32 value)
{
	u64 key = flow_reject_key(value);
	scx_bpf_dsq_insert_vtime(p, flow_overflow_dsq(), (u64)FLOW_QUANTUM_NS, key, enq_flags);
}
/**
 * flow_tier_insert_hint - tier join from hoisted combined drain.
 * @p: task to join, null is ignored by the insert helpers.
 * @cpu: target CPU for the drain gate.
 * @vtime: fair time used for order plus the drain gate.
 * @now: current time in nanos.
 * @local_q: hoisted own local depth, non-positive means empty.
 * @node_q: hoisted node depth, non-positive means empty.
 *
 * Takes the local tier when the hoisted combined drain finishes before
 * the fair time, else the node tier when live, else the machine tier, so
 * a busy node holds local with no wait and no second poll. Escalation
 * follows the combined drain with mask wins on dispatch drain. Strict
 * PRIQ holds with no batch push, so the earliest key wins in every
 * tier with no load swap. Like fair.c, the earliest key wins, unlike
 * rt.c, no fixed priority holds.
 */
static __always_inline void flow_tier_insert_hint(struct task_struct *p,
	s32 cpu, u64 vtime, u64 now, s32 local_q, s32 node_q)
{
	u32 node;
	bool drain_ok = false;
	if (cpu >= 0)
		drain_ok = flow_cpu_meets_fair_hint(local_q, node_q, vtime,
		    now);
	if (cpu >= 0 && drain_ok) {
		flow_local_insert(p, cpu, vtime);
		return;
	}
	if (cpu >= 0) {
		node = flow_cpu_node((u32)cpu);
		if (node < (u32)FLOW_MAX_NODES && (u64)node < nr_node_ids) {
			flow_node_insert(p, node, vtime);
			return;
		}
	}
	flow_machine_insert(p, vtime);
}
/* Join one task to the tier its target drains first with fair order. */
/* Polls local plus node once here, so callers without hoisted depths */
/* pay the same reads with no double poll. The local queue takes the */
/* task when the target drains local plus node before the fair key, */
/* else the node queue when live, else the machine queue, so no task */
/* waits for a busy CPU while shared room stays open. */
static __always_inline void flow_tier_insert(struct task_struct *p, s32 cpu, u64 vtime, u64 now)
{
	s32 local_q = 0;
	s32 node_q = 0;
	if (cpu >= 0) {
		u32 node;
		local_q = scx_bpf_dsq_nr_queued(flow_local_dsq((u32)cpu));
		node = flow_cpu_node((u32)cpu);
		if (node < (u32)FLOW_MAX_NODES && (u64)node < nr_node_ids)
			node_q = scx_bpf_dsq_nr_queued(flow_node_dsq(node));
	}
	flow_tier_insert_hint(p, cpu, vtime, now, local_q, node_q);
}
/**
 * flow_make_fair - strict EDF key from task state plus deadline plus hint.
 * @tctx: task state with vruntime plus weight plus slice.
 * @deadline: absolute EDF deadline in nanos.
 * @hint_w: hint share with base for neutral.
 *
 * Reads vruntime plus weight plus slice once and stacks the effective
 * share of task times hint over 128, so pinned plus miss plus open
 * paths share one divide copy with the same order. The slice holds
 * the dynamic remaining clamp on fresh waits else the held charge on
 * misses, so near deadlines earn near virtual times with no band jump.
 *
 * Returns: strict key as the earlier of deadline plus virtual deadline.
 *
 * Outlined with noinline to keep verifier headroom and pinned plus miss
 * plus open paths share one divide copy with no inline growth.
 */
static __noinline u64 flow_make_fair(struct flow_task_ctx *tctx,
	u64 deadline, u32 hint_w)
{
	u64 vr = READ_ONCE(tctx->vruntime);
	u32 sl = READ_ONCE(tctx->slice_ns);
	u32 task_w = READ_ONCE(tctx->weight);
	u32 eff;
	u64 vd;
	if (task_w == 0)
		task_w = (u32)FLOW_WEIGHT_BASE;
	eff = flow_task_effective_weight(task_w, hint_w);
	if (sl == 0)
		sl = (u32)FLOW_QUANTUM_NS;
	vd = flow_virt_deadline(vr, (u64)sl, eff);
	return flow_edf_key(deadline, vd);
}
/**
 * flow_clamp_to_min - clamp vruntime within the lag bound of a CPU.
 * @tctx: task state with vruntime to fold forward.
 * @cpu: target CPU whose minimum bounds the boost.
 *
 * Folds a vruntime more than 2ms behind the minimum forward to minimum
 * minus 2ms with saturation at zero, so long sleepers wake only slightly
 * early with no huge boost. Uses a compare and swap, so a concurrent
 * charge win keeps the winner with no regression.
 *
 * Outlined with noinline to keep verifier headroom and pinned plus open
 * paths share one clamp copy with no inline growth.
 */
static __noinline void flow_clamp_to_min(struct flow_task_ctx *tctx,
	u32 cpu)
{
	u64 min = flow_cpu_min(cpu);
	u64 cur = READ_ONCE(tctx->vruntime);
	u64 bound = (u64)FLOW_VLAG_MAX_NS;
	u64 floor = 0;
	if (min > bound)
		floor = min - bound;
	if (min > bound && cur < floor)
		__sync_val_compare_and_swap(&tctx->vruntime, cur, floor);
}
/**
 * struct flow_pinned_tail - pinned args for the outlined pinned path.
 * @tctx: task state with vruntime plus deadline plus predictor.
 * @sel: selected CPU hint, negative falls back to first allowed.
 * @is_reenq: true reuses the stored hint plus weight with no lookup.
 * @now: current time in nanos.
 * @enq_flags: enqueue flags threaded to the reject insert with no loss.
 *
 * Bundles the pinned state plus hint plus time plus flags, so the outlined
 * pinned path takes one pointer with no stack args like the scan plus
 * enqueue tails.
 */
struct flow_pinned_tail {
	struct flow_task_ctx *tctx;
	s32 sel;
	bool is_reenq;
	u64 now;
	u64 enq_flags;
};
/**
 * flow_enqueue_pinned - enqueue one pinned task in tier order.
 * @p: task to enqueue, pinned to one CPU with no scan.
 * @t: pinned tail with state plus hint plus time plus flags, hoisted once
 * by the caller with no second read.
 *
 * Pinned tasks wait in a tier queue with wait set and one idle kick.
 * Homeless pins with no live CPU wait in the value ordered reject queue
 * like open tasks with the stored share plus value order, so no pin
 * parks in the machine tier without a live CPU. Queue order uses the fair
 * the effective share of task times hint over 128. Vruntime clamps to
 * the target minimum minus 2ms like open tasks, and a past deadline
 * counts one miss before the fresh deadline, so pins track lag plus
 * overload with no stale reuse. The tier keeps mask wins on drain, so
 * a pinned task still meets only its allowed CPU.
 *
 * Outlined with noinline to keep verifier headroom and the cold pinned
 * path leaves the open path with no inline growth and the same order.
 */
static __noinline void flow_enqueue_pinned(struct task_struct *p,
	const struct flow_pinned_tail *t)
{
	struct flow_task_ctx *tctx = t->tctx;
	s32 sel = t->sel;
	bool is_reenq = t->is_reenq;
	u64 now = t->now;
	u64 enq_flags = t->enq_flags;
	s32 pc = flow_pick_target(p, sel);
	u32 ph;
	u32 phint_w = (u32)FLOW_WEIGHT_BASE;
	u64 pavg;
	u64 pdev;
	u64 pdl;
	u64 pvt;
	bool pmiss = false;
	bool pin_is_lat = false;
	u32 pin_pre = 0;
	bool have_pin = false;
	if (is_reenq) {
		ph = READ_ONCE(tctx->hint_us);
		phint_w = READ_ONCE(tctx->hint_w);
	} else {
		/* One cache plus one row read for both values, so */
		/* the fresh pinned path pays no double lookup. */
		/* The task base stays stored, only the hint reads. */
		flow_task_hint_weight(p, &ph, &phint_w);
	}
	tctx->hint_us = ph;
	tctx->hint_w = phint_w;
	/* Clamp vruntime within the lag bound of the pinned target */
	/* through the shared helper with no order change. */
	if (pc >= 0 && flow_cpu_ok(p, pc))
		flow_clamp_to_min(tctx, (u32)pc);
	/* A past deadline counts one miss before the fresh deadline, */
	/* so pinned overload tracks like open tasks with no loss. The */
	/* miss holds the stored slice else floors it to 10us via the */
	/* shared miss helper, and a fresh wait earns the dynamic */
	/* remaining clamp, so the key stays strict with skip aging in */
	/* the miss count. */
	if (READ_ONCE(tctx->deadline) &&
	    flow_missed(READ_ONCE(tctx->deadline), now)) {
		flow_count_miss(tctx);
		pmiss = true;
	}
	/* Pinned tasks recompute the deadline from the predictor */
	/* plus hint with no stale reuse, so a pinned requeue tracks */
	/* recent bursts like open tasks with no order break. A zero */
	/* average means no history, so the hint period applies. */
	pavg = (u64)READ_ONCE(tctx->avg_ns);
	pdev = (u64)READ_ONCE(tctx->dev_ns);
	pdl = flow_pred_deadline(now, pavg, pdev, ph);
	__sync_lock_test_and_set(&tctx->deadline, pdl);
	/* Latency recompute per enqueue with no stored bit, so 72B holds. */
	/* A fresh pinned wait clamps the slice to 100us plus caps the key */
	/* to now plus max 4ms else slice plus 100us via the strict key, */
	/* while RED stays on the original deadline with no order change. */
	/* Like fair.c, the cap paces service, unlike rt.c, no fixed */
	/* priority holds. A preempted pinned head resumes via lifecycle */
	/* only with no slice rewrite here, so the stored leftover stays. */
	/* Sleep isolates the true gap as now minus wait minus burst, and */
	/* in-tier keys cap at now plus one period for the starvation bound. */
	if (pmiss) {
		tctx->wait_at = now;
		__sync_lock_test_and_set(&tctx->slice_ns,
		    flow_slice_miss_hold(READ_ONCE(tctx->slice_ns)));
		pvt = flow_make_fair(tctx, pdl, phint_w);
		{
			u64 pbound0 = flow_sat_add(now, (u64)FLOW_PERIOD_NS);
			if (pvt != 0 && pbound0 != (u64)~0ULL &&
			    !flow_time_before(pvt, pbound0) && pvt != pbound0)
				pvt = pbound0;
		}
	} else if (!is_reenq) {
		u64 p_old_wait = READ_ONCE(tctx->wait_at);
		u64 p_sleep = flow_sleep_ns(p_old_wait, now, pavg);
		u32 p_task_w = READ_ONCE(tctx->weight);
		u32 p_eff = 0;
		bool p_is_lat;
		u32 p_pre;
		u32 p_slice;
		u64 p_vt;
		/* No stable uclamp field in this task view, so fail open to */
		/* zero with no map plus no knob, and probation holds through */
		/* both helpers, so newcomers stay batch. */
		if (p_task_w == 0)
			p_task_w = (u32)FLOW_WEIGHT_BASE;
		p_eff = flow_task_effective_weight(p_task_w, phint_w);
		p_is_lat = flow_is_lat(pavg, pdev, ph, p_sleep, 0, p_eff);
		p_pre = flow_slice_for(pdl, now);
		p_slice = flow_slice_lat_clamp(p_pre, p_is_lat);
		pin_is_lat = p_is_lat;
		pin_pre = p_pre;
		have_pin = true;
		if (enq_flags & SCX_ENQ_PREEMPT) {
			tctx->wait_at = now;
			pvt = flow_make_fair(tctx, pdl, phint_w);
		} else {
			u64 p_dl;
			tctx->wait_at = now;
			__sync_lock_test_and_set(&tctx->slice_ns, p_slice);
			p_vt = flow_make_fair(tctx, pdl, phint_w);
			if (p_is_lat) {
				p_dl = flow_lat_deadline(now, p_slice);
				pvt = flow_edf_key(p_vt, p_dl);
			} else {
				pvt = p_vt;
			}
		}
		{
			u64 pbound = flow_sat_add(now, (u64)FLOW_PERIOD_NS);
			if (pvt != 0 && pbound != (u64)~0ULL &&
			    !flow_time_before(pvt, pbound) && pvt != pbound)
				pvt = pbound;
		}
	} else {
		tctx->wait_at = now;
		__sync_lock_test_and_set(&tctx->slice_ns,
		    flow_slice_inherit(READ_ONCE(tctx->slice_ns)));
		pvt = flow_make_fair(tctx, pdl, phint_w);
		{
			u64 pbound2 = flow_sat_add(now, (u64)FLOW_PERIOD_NS);
			if (pvt != 0 && pbound2 != (u64)~0ULL &&
			    !flow_time_before(pvt, pbound2) && pvt != pbound2)
				pvt = pbound2;
		}
	}
	/* RED on the pinned join with the same bounded O(1) newcomer check. */
	/* A zero exceed plus a critical exceed plus a newcomer that fails */
	/* the victim test admits to the tier, else the newcomer rejects to */
	/* the value ordered queue with no tier wait. Tolerance aids only */
	/* the guarantee with no key shaping. Critical follows the unified */
	/* latency and cost uses the pre-clamp slice for fresh waits. */
	{
		u32 psl = READ_ONCE(tctx->slice_ns);
		bool pcrit;
		u32 pcost_sl;
		u64 pex;
		if (have_pin) {
			pcrit = pin_is_lat;
			if (!(enq_flags & SCX_ENQ_PREEMPT))
				pcost_sl = pin_pre;
			else
				pcost_sl = psl;
		} else if (pmiss) {
			u32 ptw0 = READ_ONCE(tctx->weight);
			u32 peff0;
			if (ptw0 == 0)
				ptw0 = (u32)FLOW_WEIGHT_BASE;
			peff0 = flow_task_effective_weight(ptw0, phint_w);
			pcrit = flow_is_lat(pavg, pdev, ph, 0, 0, peff0);
			pcost_sl = psl;
		} else {
			u32 ptw0 = READ_ONCE(tctx->weight);
			u32 peff0;
			if (ptw0 == 0)
				ptw0 = (u32)FLOW_WEIGHT_BASE;
			peff0 = flow_task_effective_weight(ptw0, phint_w);
			pcrit = flow_is_lat(pavg, pdev, ph, 0, 0, peff0);
			pcost_sl = psl;
		}
		pex = flow_red_newcomer_exceed(pdl, now, pavg, pcost_sl,
		    pcrit);
		if (pex && !pcrit) {
			u32 ptw = READ_ONCE(tctx->weight);
			u32 peff = flow_task_effective_weight(ptw, phint_w);
			u64 pcost = flow_red_cost(pavg, pcost_sl);
			if (!flow_red_victim_ok(pdl, pdl, pcost, pex,
			    pcrit)) {
				if (flow_cpu_ok(p, pc)) {
					flow_tier_insert(p, pc, pvt, now);
					flow_count_admit();
					flow_kick_idle_allowed(p, sel);
					return;
				}
				flow_gate_reject();
				tctx->wait_at = now;
				flow_overflow_insert(p, enq_flags,
				    flow_red_value(peff, pcrit));
				flow_kick_idle_allowed(p, sel);
				return;
			}
			flow_count_red_reject();
			flow_overflow_insert(p, enq_flags,
			    flow_red_value(peff, pcrit));
			flow_kick_idle_allowed(p, sel);
			return;
		}
	}
	if (flow_cpu_ok(p, pc)) {
		flow_tier_insert(p, pc, pvt, now);
		flow_count_admit();
		flow_kick_idle_allowed(p, sel);
		return;
	}
	{
		u32 ptw = READ_ONCE(tctx->weight);
		u32 peff;
		bool pcrit;
		if (ptw == 0)
			ptw = (u32)FLOW_WEIGHT_BASE;
		peff = flow_task_effective_weight(ptw, phint_w);
		pcrit = flow_is_lat(pavg, pdev, ph, 0, 0, peff);
		flow_gate_reject();
		tctx->wait_at = now;
		flow_overflow_insert(p, enq_flags,
		    flow_red_value(peff, pcrit));
		flow_kick_idle_allowed(p, sel);
	}
}
