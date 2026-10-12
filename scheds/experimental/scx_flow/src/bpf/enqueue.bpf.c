// SPDX-License-Identifier: GPL-2.0
/*
 * Enqueue op with RED admission plus strict PRIQ.
 *
 * Every wakeup earns one EDF deadline from the burst predictor else
 * the hint period plus one virtual deadline from vruntime plus slice
 * over weight, then passes the RED check with residual plus exceed
 * plus tolerance used only for the guarantee. The deadline bounds the
 * check with no vruntime shaping. A zero exceed admits at once, a
 * critical exceed admits with no swap, else the newcomer itself is
 * tested as the bounded O(1) victim with cost past 128us plus cost
 * past the exceed plus never critical, else the newcomer admits and a
 * full least value scan stays a noted alternative. Queue order uses the strict EDF key of the earlier of the two times in
 * three PRIQ tiers with insert vtime, so urgent tasks still win while
 * hogs fall behind with lag bounds. Fresh waits earn a dynamic slice
 * from the saturated remaining time clamped to 10us plus 1ms, while
 * misses hold else floor only and rejoin via the same tier escalation
 * re-derived with a fresh deadline plus skip aging. Tasks join direct
 * only when all tiers incl the reject hold no work or the target still
 * drains before the key with an empty machine plus an empty reject, so
 * no earlier key waits behind this arrival. Missed tasks rejoin a tier queue with a fresh
 * deadline plus a miss count and one idle kick and no wait, else the
 * reject queue on overload. Pinned tasks wait in a tier queue with
 * wait set and one idle kick, else the reject queue on overload.
 * Exiting tasks run at once on the task CPU with no queue wait and no
 * gate. The gate runs first for all other arrivals, so a stale CPU
 * plus a moved task fails closed with one counter. The predictor
 * average plus deviation shape later deadlines with shift updates from
 * stopping, so short bursts earn tight deadlines with no table walk.
 * Vruntime advances by scaled service with one divide, and the CPU
 * minimum folds forward on every charge, so fairness tracks service
 * with no table. Every tier join counts one admit plus every RED
 * overload counts one RED reject with no gate double count plus no
 * global queue use. The exiting plus bypass plus tier idle plus preempt
 * paths form the kick points, so every wait meets at most one kick with
 * no storm. A direct preempt needs unified latency with probation plus
 * an eligible lat arrival against a batch owner plus a 100us margin
 * lead with more than 100us still left on the owner, so near ties plus
 * nearly done owners never bounce while one kick per wait stays. The
 * owner paces on start plus inherit cur with no fresh quantum, so the
 * tail tracks the stored slice. A preempted
 * head resumes via lifecycle only with start plus cur clamped to 10us
 * plus 100us for latency else 1ms with inherit on bad start plus tail
 * plus history, so the same head resumes with its leftover.
 * Latency-critical slice carryover keeps the unused quantum, so short
 * bursts earn nearer keys. Strict slice writes run here before the key.
 * Fresh waits earn the dynamic remaining clamp, misses hold else floor
 * only, and rotations inherit zero. Slice expiry paces the rest with
 * no stamp run here. Local plus node depths hoist once, so the drain
 * gated bypass plus the combined drain tier escalation share one read
 * with no second poll. See intf.h for the deadline plus fairness
 * helpers and dispatch.bpf.c for the tier scans.
 *
 * The op holds the target plus insert plus kick helpers in enqueue/
 * with the fair plus clamp noinline on scalar input plus the pinned
 * plus place plus kick noinline on tail pointers, so the verifier
 * stays small.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
#include "enqueue/target.bpf.c"
#include "enqueue/insert.bpf.c"
#include "enqueue/kick.bpf.c"

void BPF_STRUCT_OPS(flow_enqueue, struct task_struct *p,
	u64 enq_flags)
{
	struct flow_task_ctx *tctx;
	s32 sel;
	s32 cpu = -1;
	bool pinned = false;
	u64 now;
	u64 deadline;
	u64 vtime;
	u32 hint;
	u32 hint_w = (u32)FLOW_WEIGHT_BASE;
	u64 avg = 0;
	u64 dev = 0;
	bool is_reenq = false;
	u64 hoist_vr = 0;
	s32 hoist_lag = 0;
	u64 hoist_min = 0;
	bool hoist_elig = false;
	bool open_is_lat = false;
	u32 open_pre = 0;
	bool have_open = false;
	/* Requeue plus last slice expiry bypass the cgroup hint read plus */
	/* the occupant preempt lookup, so slice rotation stays cheap. The */
	/* stored hint plus hint weight in the task state carry the period */
	/* plus the share, and the owner paces at slice expiry with no */
	/* extra kick. The requeue case is rare beside fresh wakeups, so */
	/* it stays unlikely. */
	if (unlikely(enq_flags & (SCX_ENQ_REENQ | SCX_ENQ_LAST)))
		is_reenq = true;
	/* Exiting tasks run at once on the task CPU with no queue wait. */
	/* The gate never runs here, so exiting work stays exempt. Exiting */
	/* is rare, so it stays unlikely. */
	if (unlikely(p->flags & PF_EXITING)) {
		s32 tgt = scx_bpf_task_cpu(p);
		if (flow_cpu_ok(p, tgt)) {
			struct flow_cpu_state *tst;
			scx_bpf_dsq_insert(p,
			    (u64)SCX_DSQ_LOCAL_ON | (u64)tgt,
			    (u64)FLOW_QUANTUM_NS, enq_flags);
			tst = flow_cpu((u32)tgt);
			if (tst &&
			    READ_ONCE(tst->running_pid) == 0) {
				scx_bpf_kick_cpu(tgt,
				    SCX_KICK_IDLE);
				flow_count_kick();
			}
			return;
		}
	}
	tctx = NULL;
	sel = p->scx.selected_cpu;
	pinned = flow_task_pinned(p);
	now = flow_now();
	/* The gate runs first with no state create, so stale CPUs plus */
	/* moved tasks fail closed with no alloc cost. The lookup stays */
	/* read only here, and the create follows only on pass. Rejects are */
	/* rare, so they stay unlikely. Gate misses join the value ordered */
	/* reject queue with no deadline wait, so no path needs a tail */
	/* queue and no insert touches the kernel global queue. */
	if (unlikely(!flow_entry_ok(sel, p, 0) && !flow_entry_ok(
	    scx_bpf_task_cpu(p), p, 0))) {
		struct flow_task_ctx *lctx = flow_lookup(p);
		u32 gval;
		flow_gate_reject();
		if (lctx)
			lctx->wait_at = now;
		/* Gate misses thread the stored share plus unified latency when */
		/* state holds, else batch value when absent with probation. */
		if (lctx) {
			u32 gw = READ_ONCE(lctx->weight);
			u32 ghw = READ_ONCE(lctx->hint_w);
			u64 gavg = (u64)READ_ONCE(lctx->avg_ns);
			u64 gdev = (u64)READ_ONCE(lctx->dev_ns);
			u32 ghint = READ_ONCE(lctx->hint_us);
			u32 geff = flow_task_effective_weight(gw, ghw);
			bool gcrit = flow_is_lat(gavg, gdev, ghint, 0, 0,
			    geff);
			gval = flow_red_value(geff, gcrit);
		} else {
			gval = flow_red_value((u32)FLOW_WEIGHT_BASE, false);
		}
		flow_overflow_insert(p, enq_flags, gval);
		flow_kick_idle_allowed(p, sel);
		return;
	}
	tctx = flow_get(p);
	/* Tasks without state join a tier queue with a fallback deadline */
	/* as the fair time plus an idle kick. The kick targets one idle */
	/* allowed CPU with no preempt, so a waiting task wakes without a */
	/* storm. The gate already passed, so this path holds no gate count */
	/* with no double count. Missing state is rare, so it stays unlikely. */
	if (unlikely(!tctx)) {
		s32 mc = flow_pick_target(p, sel);
		u32 mh = 0;
		u32 mhw = (u32)FLOW_WEIGHT_BASE;
		u64 mdl;
		/* No state holds no predictor, so the hint weight threads */
		/* with BASE-only task share and batch value when state */
		/* is absent with probation and no extra map. */
		flow_task_hint_weight(p, &mh, &mhw);
		mdl = flow_fallback_deadline(now, mh);
		if (flow_cpu_ok(p, mc)) {
			flow_tier_insert(p, mc, mdl, now);
			flow_count_admit();
		} else {
			u32 meff = flow_task_effective_weight(
			    (u32)FLOW_WEIGHT_BASE, mhw);
			flow_gate_reject();
			flow_overflow_insert(p, enq_flags,
			    flow_red_value(meff, false));
		}
		flow_kick_idle_allowed(p, sel);
		return;
	}
	/* Ensure the fairness fields hold sane defaults with no divide. */
	/* A zero weight means no history, so the neutral share applies. */
	/* A zero slice means no history, so the fixed quantum applies. */
	{
		u32 w = READ_ONCE(tctx->weight);
		u32 s = READ_ONCE(tctx->slice_ns);
		if (w == 0)
			__sync_lock_test_and_set(&tctx->weight,
			    (u32)FLOW_WEIGHT_BASE);
		if (s == 0)
			__sync_lock_test_and_set(&tctx->slice_ns,
			    (u32)FLOW_QUANTUM_NS);
	}
	/* Pinned tasks wait in a tier queue with wait set and one idle kick. */
	/* Pinning is rare, so it stays unlikely. The tier keeps mask wins */
	/* on drain, so a pinned task still meets only its allowed CPU. */
	/* The pinned wait runs Outlined with no order change, so the open */
	/* path keeps verifier headroom with the same fair time plus miss */
	/* plus clamp plus kick. */
	if (unlikely(pinned)) {
		struct flow_pinned_tail tail = {
			.tctx = tctx,
			.sel = sel,
			.is_reenq = is_reenq,
			.now = now,
			.enq_flags = enq_flags,
		};
		flow_enqueue_pinned(p, &tail);
		return;
	}
	cpu = flow_pick_target(p, sel);
	/* No live CPU waits in the value ordered reject queue with an idle */
	/* kick. Homeless work waits there with the stored share plus value */
	/* order and enq flags kept, so no insert touches the kernel global */
	/* queue. */
	if (!flow_cpu_ok(p, cpu)) {
		u32 hw = READ_ONCE(tctx->weight);
		u32 hw_hint = READ_ONCE(tctx->hint_w);
		u32 hhint = READ_ONCE(tctx->hint_us);
		u32 heff = flow_task_effective_weight(hw, hw_hint);
		bool hcrit = flow_is_lat((u64)READ_ONCE(tctx->avg_ns),
		    (u64)READ_ONCE(tctx->dev_ns), hhint, 0, 0, heff);
		flow_gate_reject();
		tctx->wait_at = now;
		flow_overflow_insert(p, enq_flags, flow_red_value(heff, hcrit));
		flow_kick_idle_allowed(p, sel);
		return;
	}
	if (READ_ONCE(tctx->deadline) == 0 && READ_ONCE(tctx->wait_at) == 0)
		flow_count_insert();
	/* One predictor period plus one EDF deadline plus one fair time. */
	/* A zero average means no history, so the fresh hint period */
	/* applies with the default when the hint is zero. Later wakeups */
	/* add average plus deviation with saturation, so short bursts earn */
	/* tight deadlines with no table walk. The hint stores with no lag, */
	/* while the predictor shapes only the deadline once history exists. */
	/* A miss on the last deadline counts before the new deadline, so */
	/* the miss count tracks wall completion past deadline. Requeues */
	/* reuse the stored hint plus hint weight with no lookup and no */
	/* cgroup acquire, so slice rotation keeps the heavy share with no */
	/* neutral cliff. The reuse may stay stale across one slice when */
	/* the share changed, so the new values show on the next fresh */
	/* wakeup with no order break. A cgroup move shows the same way */
	/* on the next fresh wakeup with no order break. Vruntime clamps within the lag bound of the target */
	/* minimum with a compare and swap, so sleepers gain no more than */
	/* one boost with no storm. The effective share stacks task times */
	/* hint over 128 on the stack, so every task earns a clamped share */
	/* with no special case and the hint weight stored alongside. */
	if (is_reenq) {
		hint = READ_ONCE(tctx->hint_us);
		hint_w = READ_ONCE(tctx->hint_w);
	} else {
		/* One cache plus one row read for both values, so the fresh */
		/* path pays no double lookup with no behavior change. The */
		/* task base stays stored, only the hint reads here. */
		flow_task_hint_weight(p, &hint, &hint_w);
	}
	avg = (u64)READ_ONCE(tctx->avg_ns);
	dev = (u64)READ_ONCE(tctx->dev_ns);
	tctx->hint_us = hint;
	tctx->hint_w = hint_w;
	/* Clamp vruntime within the lag bound of the target minimum */
	/* through the shared helper with no order change. */
	flow_clamp_to_min(tctx, (u32)cpu);
	if (READ_ONCE(tctx->deadline) &&
	    flow_missed(READ_ONCE(tctx->deadline), now)) {
		u64 ndl;
		u64 nvt;
		u32 msl;
		bool mcrit;
		u64 mex;
		flow_count_miss(tctx);
		tctx->wait_at = now;
		ndl = flow_pred_deadline(now, avg, dev, hint);
		__sync_lock_test_and_set(&tctx->deadline, ndl);
		/* A miss holds the stored slice else floors it to 10us */
		/* with no dynamic recompute via the shared miss helper, then */
		/* rejoins via the same tier escalation re-derived with the */
		/* fresh deadline plus skip aging in the miss count, so */
		/* urgency returns at once with no starvation. */
		__sync_lock_test_and_set(&tctx->slice_ns,
		    flow_slice_miss_hold(READ_ONCE(tctx->slice_ns)));
		nvt = flow_make_fair(tctx, ndl, hint_w);
		{
			u64 mbound = flow_sat_add(now, (u64)FLOW_PERIOD_NS);
			if (nvt != 0 && mbound != (u64)~0ULL &&
			    !flow_time_before(nvt, mbound) && nvt != mbound)
				nvt = mbound;
		}
		/* RED on the miss rejoin with the same bounded O(1) newcomer */
		/* check. A zero exceed plus a critical exceed plus a newcomer */
		/* that fails the victim test admits at once, else the */
		/* newcomer rejects to the value ordered queue. Tolerance aids */
		/* only the guarantee with no key shaping. A full O(n) least */
		/* value scan stays a noted alternative with no knob here, so */
		/* the verifier keeps one pass with no walk. Critical follows */
		/* the unified latency, so RED and slice agree. */
		msl = READ_ONCE(tctx->slice_ns);
		{
			u32 mtw0 = READ_ONCE(tctx->weight);
			u32 meff0;
			if (mtw0 == 0)
				mtw0 = (u32)FLOW_WEIGHT_BASE;
			meff0 = flow_task_effective_weight(mtw0, hint_w);
			mcrit = flow_is_lat(avg, dev, hint, 0, 0, meff0);
		}
		mex = flow_red_newcomer_exceed(ndl, now, avg, msl, mcrit);
		if (mex && !mcrit) {
			u32 mtw = READ_ONCE(tctx->weight);
			u32 meff = flow_task_effective_weight(mtw, hint_w);
			u64 mcost = flow_red_cost(avg, msl);
			if (!flow_red_victim_ok(ndl, ndl, mcost, mex,
			    mcrit)) {
				flow_tier_insert(p, cpu, nvt, now);
				flow_count_admit();
				flow_kick_idle_allowed(p, sel);
				return;
			}
			flow_count_red_reject();
			flow_overflow_insert(p, enq_flags,
			    flow_red_value(meff, mcrit));
			flow_kick_idle_allowed(p, sel);
			return;
		}
		flow_tier_insert(p, cpu, nvt, now);
		flow_count_admit();
		flow_kick_idle_allowed(p, sel);
		return;
	}
	deadline = flow_pred_deadline(now, avg, dev, hint);
	__sync_lock_test_and_set(&tctx->deadline, deadline);
	/* Latency recompute per enqueue with no stored bit, so 72B holds. */
	/* A fresh wait clamps the slice to 100us plus caps the key to now */
	/* plus max 4ms else slice plus 100us via the strict key, while RED */
	/* stays on the original deadline with no order change. Like fair.c, */
	/* the cap paces service, unlike rt.c, no fixed priority holds. A */
	/* preempted head resumes via lifecycle only with no slice rewrite */
	/* here, so the stored leftover stays with one charge in stopping. */
	/* Sleep isolates the true gap as now minus wait minus burst, so */
	/* queue plus run never masquerade as sleep. Intentional: in-tier */
	/* keys cap at now plus one period, so far keys never starve past */
	/* the bound with no extra queue. */
	if (!is_reenq) {
		u64 old_wait = READ_ONCE(tctx->wait_at);
		u64 lat_sleep = flow_sleep_ns(old_wait, now, avg);
		u32 lat_task_w = READ_ONCE(tctx->weight);
		u32 lat_eff = 0;
		bool is_lat;
		u32 pre_slice;
		u32 lat_slice;
		u64 lat_vt;
		/* No stable uclamp field in this task view, so fail open to */
		/* zero with no map plus no knob, and the ext helper keeps the */
		/* veto for callers that thread a real clamp. Probation holds */
		/* through both helpers, so newcomers stay batch. */
		if (lat_task_w == 0)
			lat_task_w = (u32)FLOW_WEIGHT_BASE;
		lat_eff = flow_task_effective_weight(lat_task_w, hint_w);
		is_lat = flow_is_lat(avg, dev, hint, lat_sleep, 0, lat_eff);
		pre_slice = flow_slice_for(deadline, now);
		lat_slice = flow_slice_lat_clamp(pre_slice, is_lat);
		open_is_lat = is_lat;
		open_pre = pre_slice;
		have_open = true;
		if (enq_flags & SCX_ENQ_PREEMPT) {
			tctx->wait_at = now;
			vtime = flow_make_fair(tctx, deadline, hint_w);
		} else {
			u64 lat_dl;
			tctx->wait_at = now;
			__sync_lock_test_and_set(&tctx->slice_ns, lat_slice);
			lat_vt = flow_make_fair(tctx, deadline, hint_w);
			if (is_lat) {
				lat_dl = flow_lat_deadline(now, lat_slice);
				vtime = flow_edf_key(lat_vt, lat_dl);
			} else {
				vtime = lat_vt;
			}
		}
		{
			u64 bound = flow_sat_add(now, (u64)FLOW_PERIOD_NS);
			if (vtime != 0 && bound != (u64)~0ULL &&
			    !flow_time_before(vtime, bound) && vtime != bound)
				vtime = bound;
		}
	} else {
		tctx->wait_at = now;
		/* Strict slice before the key with no stale reuse. A slice */
		/* rotation holds the stored charge else inherits the quantum */
		/* on zero, so the virtual deadline tracks the same charge the */
		/* key sorts. The remaining time feeds the slice plus slack only */
		/* with the sort staying the earlier of deadline plus virtual */
		/* time. */
		__sync_lock_test_and_set(&tctx->slice_ns,
		    flow_slice_inherit(READ_ONCE(tctx->slice_ns)));
		/* Strict EDF key from the virtual deadline plus the EDF */
		/* deadline. Heavy tasks earn a near virtual time while light */
		/* tasks earn a far one with one divide, so the earlier of the */
		/* two paces order with latency still capped by the deadline. */
		/* The effective share stacks task times hint over 128, so */
		/* cgroup plus task weights shape fairness together. In-tier */
		/* keys cap at now plus one period, so far keys never starve */
		/* past the bound. */
		vtime = flow_make_fair(tctx, deadline, hint_w);
		{
			u64 bound = flow_sat_add(now, (u64)FLOW_PERIOD_NS);
			if (vtime != 0 && bound != (u64)~0ULL &&
			    !flow_time_before(vtime, bound) && vtime != bound)
				vtime = bound;
		}
	}
	/* RED admission with residual plus exceed plus tolerance used only */
	/* here. A zero exceed plus a critical exceed plus a newcomer that */
	/* fails the victim test admits at once, else the newcomer rejects */
	/* to the value ordered queue outside dispatch. The deadline bounds */
	/* the check with no vruntime shaping. Critical follows the unified */
	/* latency and cost uses the pre-clamp slice for fresh waits, so */
	/* RED and slice agree with no post-clamp underestimate. A full O(n) */
	/* least value scan stays a noted alternative with no knob here, so */
	/* the verifier keeps one pass with no walk. */
	{
		u32 csl = READ_ONCE(tctx->slice_ns);
		bool ccrit;
		u32 cost_sl;
		u64 cex;
		if (have_open) {
			ccrit = open_is_lat;
			if (!(enq_flags & SCX_ENQ_PREEMPT))
				cost_sl = open_pre;
			else
				cost_sl = csl;
		} else {
			u32 ctw0 = READ_ONCE(tctx->weight);
			u32 ceff0;
			if (ctw0 == 0)
				ctw0 = (u32)FLOW_WEIGHT_BASE;
			ceff0 = flow_task_effective_weight(ctw0, hint_w);
			ccrit = flow_is_lat(avg, dev, hint, 0, 0, ceff0);
			cost_sl = csl;
		}
		cex = flow_red_newcomer_exceed(deadline, now, avg, cost_sl,
		    ccrit);
		if (cex && !ccrit) {
			u32 ctw = READ_ONCE(tctx->weight);
			u32 ceff = flow_task_effective_weight(ctw, hint_w);
			u64 ccost = flow_red_cost(avg, cost_sl);
			if (flow_red_victim_ok(deadline, deadline, ccost,
			    cex, ccrit)) {
				flow_count_red_reject();
				flow_overflow_insert(p, enq_flags,
				    flow_red_value(ceff, ccrit));
				flow_kick_idle_allowed(p, sel);
				return;
			}
		}
	}
	/* Every tier plus bypass join counts one admit with no bound and no */
	/* double count, so the counters track joins while tier queues hold */
	/* misses plus pins. */
	flow_count_admit();
	/* Eligibility hoist reads vruntime plus lag plus minimum once per */
	/* wait with no second minimum poll. The bypass plus the kick share */
	/* this one gate, so hogs pace with one minimum read and no storm. */
	/* Dropped polls keep the same order with no behavior change. */
	hoist_vr = READ_ONCE(tctx->vruntime);
	hoist_lag = READ_ONCE(tctx->vlag);
	hoist_min = flow_cpu_min((u32)cpu);
	hoist_elig = flow_eligible(hoist_vr, hoist_min, hoist_lag);
	/* Idle direct bypass plus tier join run Outlined with no order */
	/* change, so the drain gate plus the tier escalation share one */
	/* hoist with no second poll. A direct bypass returns at once with */
	/* one kick, else the tier join falls into the single kick tail. */
	/* The deadline plus admit already hold, so order plus counters stay */
	/* correct with no extra wait. Strict fair order gates the bypass */
	/* with eligibility plus drain, so hogs pace through tiers with no */
	/* direct jump and one kick per wait stays. The TOCTOU between the */
	/* empty hints and the direct insert only races a concurrent tier */
	/* join with no loss, since dispatch still drains in fair order with */
	/* mask wins on the next pass. */
	{
		struct flow_enqueue_tail tail = {
			.cpu = cpu,
			.vtime = vtime,
			.now = now,
			.enq_flags = enq_flags,
			.is_reenq = is_reenq,
			.hoist_elig = hoist_elig,
		};
		if (flow_enqueue_place(p, &tail))
			return;
		flow_enqueue_kick(p, &tail);
	}
}
