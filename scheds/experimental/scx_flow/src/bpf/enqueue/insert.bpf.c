// SPDX-License-Identifier: GPL-2.0
/*
 * Enqueue tier inserts plus fair time for the flow scheduler.
 *
 * Holds the local plus node plus machine plus overflow inserts with
 * the shared drain escalation plus the shared fair time plus the lag
 * clamp plus the pinned wait path. Queue order uses the earlier of the
 * deadline plus the virtual deadline, so urgent tasks still win while
 * hogs fall behind with lag bounds. Tasks join direct when the target
 * can drain before the shared home, so no task waits for a busy CPU
 * while shared room stays open. Strict PRIQ holds without favoring batch,
 * reusing the tier escalation plus the slowest sufficient pick. Every
 * tier join counts one admit, so the counters track joins. Runs under
 * the caller.
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
/* Insert one task into the reject queue value ordered without FIFO. */
/* Orders by decreasing value through the kernel priority queue, so the */
/* greatest value drains first on reclaim. Value picks the order without */
/* shaping vruntime. Runs outside dispatch with reclaim only, so dispatch */
/* tiers stay strict. */
static __always_inline void flow_overflow_insert(struct task_struct *p, u64 enq_flags, u32 value)
{
	u64 key = flow_reject_key(value);
	scx_bpf_dsq_insert_vtime(p, flow_overflow_dsq(), (u64)FLOW_QUANTUM_NS, key, enq_flags);
}
/**
 * flow_take_sleep - true sleep plus wait stamp in one shared copy.
 * @tctx: task state with wait stamp to read plus overwrite.
 * @now: current time in nanos.
 * @avg: burst average in nanos for the gap minus burst.
 *
 * Isolates the true gap as now minus wait minus burst with wrap safety,
 * then stamps wait to now, so queue plus run never look like sleep and
 * later reads see one snapshot. Shares one sleep plus store copy, so
 * miss plus open plus pinned keep no inline growth and the same gap.
 *
 * Outlined with noinline to keep verifier headroom on the enqueue path.
 *
 * Returns: sleep time in nanos, zero when unknown.
 */
static __noinline u64 flow_take_sleep(struct flow_task_ctx *tctx, u64 now,
	u64 avg)
{
	u64 sleep;
	if (!tctx)
		return 0;
	sleep = flow_sleep_ns(READ_ONCE(tctx->wait_at), now, avg);
	tctx->wait_at = now;
	return sleep;
}
/**
 * flow_tier_insert_hint - tier join from saved combined drain.
 * @p: task to join, null is ignored by the insert helpers.
 * @cpu: target CPU for the drain gate.
 * @vtime: fair time used for order plus the drain gate.
 * @now: current time in nanos.
 * @local_q: saved own local depth, non-positive means empty.
 * @node_q: saved node depth, non-positive means empty.
 *
 * Takes the local tier when the saved combined drain finishes before
 * the fair time, else the node tier when live, else the machine tier, so
 * a busy node keeps the task local. Escalation follows the combined drain
 * with mask wins on dispatch drain. Strict PRIQ holds without favoring
 * batch, so the earliest key wins in every tier. Like fair.c, the
 * earliest key wins, unlike rt.c, no fixed priority holds.
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
/* Reads local plus node once here, so callers without saved depths pay */
/* the same reads. The local queue takes the task when the target drains */
/* local plus node before the fair key, else the node queue when live, */
/* else the machine queue, so no task waits for a busy CPU while shared */
/* room stays open. */
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
 * share of task times hint over 128, so pinned, miss, and open paths
 * share one divide copy with the same order. The slice holds the dynamic
 * remaining clamp on fresh waits else the held charge on misses, so near
 * deadlines earn near virtual times without a band jump. RED cost stays
 * on the pre-clamp slice, so admit plus order agree. The strict key
 * drives tier plus kick while placement tests the deadline.
 *
 * Returns: strict key as the earlier of deadline plus virtual deadline.
 *
 * Outlined with noinline to keep verifier headroom and pinned plus miss
 * plus open paths share one divide copy.
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
 * early. Uses a compare and swap, so a concurrent charge win keeps the
 * winner.
 *
 * Outlined with noinline to keep verifier headroom and pinned plus open
 * paths share one clamp copy.
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
 * flow_enqueue_cap_key - cap one fair key at now plus one period.
 * @vtime: strict fair time from the EDF key, zero keeps zero.
 * @now: current time in nanos.
 *
 * Caps far keys at now plus one period with saturation, so far keys
 * never starve past the bound while placement tests the deadline.
 * Like fair.c, the cap paces service, unlike rt.c, no fixed priority
 * holds.
 *
 * Outlined with noinline to keep verifier headroom with one shared
 * copy, so miss plus open plus pinned share the same bound with no
 * inline growth.
 *
 * Returns: capped key in nanos.
 */
static __noinline u64 flow_enqueue_cap_key(u64 vtime, u64 now)
{
	u64 bound = flow_sat_add(now, (u64)FLOW_PERIOD_NS);
	if (vtime != 0 && bound != (u64)~0ULL &&
	    !flow_time_before(vtime, bound) && vtime != bound)
		vtime = bound;
	return vtime;
}
/**
 * flow_enqueue_is_lat - unified latency for one wait from stored fields.
 * @avg: burst average in nanos, zero for no history.
 * @dev: burst deviation in nanos.
 * @hint: flat period hint in micros, zero for no hint.
 * @sleep_ns: true sleep gap from the caller wrap-safe helper.
 * @eff: effective share from task times hint over 128.
 *
 * Runs the unified base plus ext test with probation, so newcomers
 * stay batch with no stored bit and RED plus slice agree on the same
 * gap. The caller stacks task times hint over 128, so the shared
 * test stays at five args with no stack spill. Like fair.c, the test
 * paces service, unlike rt.c, no fixed priority holds.
 *
 * Outlined with noinline to keep verifier headroom with one shared
 * copy, so miss plus open plus pinned share the same test with no
 * inline growth.
 *
 * Returns: true when latency holds, else false for batch.
 */
static __noinline bool flow_enqueue_is_lat(u64 avg, u64 dev, u32 hint,
	u64 sleep_ns, u32 eff)
{
	return flow_is_lat(avg, dev, hint, sleep_ns, 0, eff);
}
/**
 * struct flow_reject_tail - RED reject args for the shared reject path.
 * @tctx: task state with weight for the value order.
 * @deadline: newcomer absolute deadline in nanos.
 * @now: current time in nanos.
 * @avg: burst average in nanos, zero for no history.
 * @slice: cost slice in nanos for the RED check.
 * @is_lat: unified latency for the RED check.
 * @hint_w: hint share with base for neutral.
 * @enq_flags: enqueue flags threaded to the reject insert.
 * @sel: selected CPU hint for the idle kick.
 *
 * Bundles the RED state plus time plus flags, so the shared reject
 * takes one pointer like the miss plus open tails with no stack args
 * and the same order.
 */
struct flow_reject_tail {
	struct flow_task_ctx *tctx;
	u64 deadline;
	u64 now;
	u64 avg;
	u32 slice;
	bool is_lat;
	u32 hint_w;
	u64 enq_flags;
	s32 sel;
};
/**
 * flow_enqueue_reject - RED reject one newcomer to the value queue.
 * @p: task to reject, passed to the reject insert.
 * @t: reject tail with state plus deadline plus time plus flags.
 *
 * Runs the shared O(1) newcomer check through the outlined helper, so
 * a reject needs cost past the fixed 256us Emax plus cost past the
 * exceed with no critical. A reject joins the value ordered queue with
 * one idle kick, else admits with no insert. Queue order uses value
 * without shaping vruntime. Like fair.c, the earliest key wins,
 * unlike rt.c, no fixed priority holds.
 *
 * Outlined with noinline to keep verifier headroom with one shared
 * copy, so miss plus open plus pinned share the same reject with no
 * inline growth and the same counts.
 *
 * Returns: true when rejected with insert plus kick, else false.
 */
static __noinline bool flow_enqueue_reject(struct task_struct *p,
	const struct flow_reject_tail *t)
{
	struct flow_task_ctx *tctx;
	u64 deadline;
	u64 now;
	u64 avg;
	u32 slice;
	bool is_lat;
	u32 hint_w;
	if (!p || !t)
		return false;
	tctx = t->tctx;
	if (!tctx)
		return false;
	deadline = t->deadline;
	now = t->now;
	avg = t->avg;
	slice = t->slice;
	is_lat = t->is_lat;
	hint_w = t->hint_w;
	if (!flow_red_should_reject(deadline, now, avg, slice, is_lat))
		return false;
	{
		u32 tw = READ_ONCE(tctx->weight);
		u32 eff = flow_task_effective_weight(tw, hint_w);
		flow_count_red_reject();
		flow_overflow_insert(p, t->enq_flags,
		    flow_red_value(eff, is_lat));
		flow_kick_idle_allowed(p, t->sel);
	}
	return true;
}
/**
 * flow_enqueue_pinned - enqueue one pinned task in tier order.
 * @p: task to enqueue, pinned to one CPU without a scan.
 * @tctx: task state with vruntime plus deadline plus predictor.
 * @sel: selected CPU hint, negative falls back to first allowed.
 * @now: current time in nanos.
 * @enq_flags: enqueue flags threaded to the reject insert plus requeue
 * pace derived from REENQ plus LAST with no extra arg.
 *
 * Pinned tasks wait in a tier queue with wait set and one idle kick.
 * Homeless pins without a live CPU wait in the value ordered reject queue
 * like open tasks with the stored share plus value order, so no pin
 * parks in the machine tier without a live CPU. Queue order uses the
 * effective share of task times hint over 128. Vruntime clamps to the
 * target minimum minus 2ms like open tasks, and a past deadline counts
 * one miss before the fresh deadline, so pins track lag plus overload
 * without stale reuse. The tier keeps mask wins on drain, so a pinned
 * task still meets only its allowed CPU. Takes scalars with no tail
 * struct, so the verifier tracks registers with no stack spill.
 *
 * Outlined with noinline to keep verifier headroom and the cold pinned
 * path leaves the open path with the same order.
 */
static __noinline void flow_enqueue_pinned(struct task_struct *p,
	struct flow_task_ctx *tctx, s32 sel, u64 now, u64 enq_flags)
{
	bool is_reenq = !!(enq_flags & (SCX_ENQ_REENQ | SCX_ENQ_LAST));
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
	u64 pin_sleep_hold = 0;
	if (is_reenq) {
		ph = READ_ONCE(tctx->hint_us);
		phint_w = READ_ONCE(tctx->hint_w);
	} else {
		/* One cache plus one row read for both values, so the fresh */
		/* pinned path skips a double lookup. The task base stays stored, */
		/* only the hint reads. */
		flow_task_hint_weight(p, &ph, &phint_w);
	}
	tctx->hint_us = ph;
	tctx->hint_w = phint_w;
	/* Clamp vruntime within the lag bound of the pinned target through */
	/* the shared helper. */
	if (pc >= 0 && flow_cpu_ok(p, pc))
		flow_clamp_to_min(tctx, (u32)pc);
	/* A past deadline counts one miss before the fresh deadline, so */
	/* pinned overload tracks like open tasks. The miss holds the stored */
	/* slice else floors it to 10us via the shared miss helper, and a */
	/* fresh wait earns the dynamic remaining clamp, so the key stays */
	/* strict with skip aging in the miss count. */
	if (READ_ONCE(tctx->deadline) &&
	    flow_missed(READ_ONCE(tctx->deadline), now)) {
		flow_count_miss(tctx);
		pmiss = true;
	}
	/* Pinned tasks recompute the deadline from the predictor plus hint */
	/* without stale reuse, so a pinned requeue tracks recent bursts like */
	/* open tasks. A zero average means no history, so the hint period */
	/* applies. */
	pavg = (u64)READ_ONCE(tctx->avg_ns);
	pdev = (u64)READ_ONCE(tctx->dev_ns);
	pdl = flow_pred_deadline(now, pavg, pdev, ph);
	__sync_lock_test_and_set(&tctx->deadline, pdl);
	/* Latency recompute per enqueue without a stored bit, so 72B holds. */
	/* A fresh pinned wait clamps the slice to 100us plus caps the key */
	/* to now plus max 4ms else slice plus 100us via the strict key, */
	/* while RED stays on the original deadline. Like fair.c, the cap */
	/* paces service, unlike rt.c, no fixed priority holds. A preempted */
	/* pinned head resumes via lifecycle only without a slice rewrite */
	/* here, so the stored leftover stays. Sleep isolates the true gap as */
	/* now minus wait minus burst, and in-tier keys cap at now plus one */
	/* period for the starvation bound. */
	if (pmiss) {
		u64 pm_sleep = flow_take_sleep(tctx, now, pavg);
		pin_sleep_hold = pm_sleep;
		__sync_lock_test_and_set(&tctx->slice_ns,
		    flow_slice_miss_hold(READ_ONCE(tctx->slice_ns)));
		pvt = flow_make_fair(tctx, pdl, phint_w);
		pvt = flow_enqueue_cap_key(pvt, now);
	} else if (!is_reenq) {
		u64 p_sleep = flow_take_sleep(tctx, now, pavg);
		bool p_is_lat;
		u32 p_pre;
		u32 p_slice;
		u64 p_vt;
		u32 p_eff;
		/* No stable uclamp field in this task view, so fail open to */
		/* zero without an extra map, and probation holds through both */
		/* helpers, so newcomers stay batch. Shares the latency copy */
		/* with miss plus open. */
		p_eff = flow_task_effective_weight(READ_ONCE(tctx->weight),
		    phint_w);
		p_is_lat = flow_enqueue_is_lat(pavg, pdev, ph, p_sleep,
		    p_eff);
		p_pre = flow_slice_for(pdl, now);
		p_pre = flow_slice_tier_cap(p_pre, pavg, pdev, p_is_lat);
		p_slice = flow_slice_lat_clamp(p_pre, p_is_lat);
		pin_is_lat = p_is_lat;
		pin_pre = p_pre;
		have_pin = true;
		pin_sleep_hold = p_sleep;
		if (enq_flags & SCX_ENQ_PREEMPT) {
			pvt = flow_make_fair(tctx, pdl, phint_w);
		} else {
			u64 p_dl;
			__sync_lock_test_and_set(&tctx->slice_ns, p_slice);
			p_vt = flow_make_fair(tctx, pdl, phint_w);
			if (p_is_lat) {
				p_dl = flow_lat_deadline(now, p_slice);
				pvt = flow_edf_key(p_vt, p_dl);
			} else {
				pvt = p_vt;
			}
		}
		pvt = flow_enqueue_cap_key(pvt, now);
	} else {
		u64 pr_sleep = flow_take_sleep(tctx, now, pavg);
		pin_sleep_hold = pr_sleep;
		__sync_lock_test_and_set(&tctx->slice_ns,
		    flow_slice_inherit(READ_ONCE(tctx->slice_ns)));
		pvt = flow_make_fair(tctx, pdl, phint_w);
		pvt = flow_enqueue_cap_key(pvt, now);
	}
	/* RED on the pinned join through the shared outlined helper, so a */
	/* reject needs cost past the fixed 256us Emax plus cost past the */
	/* exceed with no critical. Tolerance aids only the guarantee */
	/* without shaping the key. Critical follows the unified latency */
	/* through the shared test and cost uses the pre-clamp slice for */
	/* fresh waits. */
	{
		u32 psl = READ_ONCE(tctx->slice_ns);
		bool pcrit;
		u32 pcost_sl;
		struct flow_reject_tail rej;
		if (have_pin) {
			pcrit = pin_is_lat;
			if (!(enq_flags & SCX_ENQ_PREEMPT))
				pcost_sl = pin_pre;
			else
				pcost_sl = psl;
		} else {
			u32 p_eff = flow_task_effective_weight(
			    READ_ONCE(tctx->weight), phint_w);
			pcrit = flow_enqueue_is_lat(pavg, pdev, ph,
			    pin_sleep_hold, p_eff);
			pcost_sl = psl;
		}
		rej.tctx = tctx;
		rej.deadline = pdl;
		rej.now = now;
		rej.avg = pavg;
		rej.slice = pcost_sl;
		rej.is_lat = pcrit;
		rej.hint_w = phint_w;
		rej.enq_flags = enq_flags;
		rej.sel = sel;
		if (flow_enqueue_reject(p, &rej))
			return;
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
		pcrit = flow_enqueue_is_lat(pavg, pdev, ph, pin_sleep_hold,
		    peff);
		flow_gate_reject();
		tctx->wait_at = now;
		flow_overflow_insert(p, enq_flags,
		    flow_red_value(peff, pcrit));
		flow_kick_idle_allowed(p, sel);
	}
}
