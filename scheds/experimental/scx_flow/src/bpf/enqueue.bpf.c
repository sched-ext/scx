// SPDX-License-Identifier: GPL-2.0
/*
 * Enqueue op with RED admission plus strict PRIQ.
 *
 * Every wakeup earns one EDF deadline from the burst predictor else
 * the hint period plus one virtual deadline from vruntime plus slice
 * over weight, then passes the RED check with residual plus exceed
 * plus tolerance used only for the guarantee. The deadline bounds the
 * check without shaping vruntime. A zero exceed admits at once, a
 * critical exceed admits without a swap, else the newcomer itself is
 * tested as the O(1) victim with cost past the fixed 256us Emax plus
 * cost past the exceed plus never critical, else the newcomer admits and a full least
 * value scan stays a noted alternative. Queue order uses the strict EDF
 * key of the earlier of the two times in three PRIQ tiers (local plus
 * node plus machine) plus value ordered reject plus steal for five total
 * with insert vtime, so urgent tasks still win while hogs fall behind
 * with lag bounds. Fresh waits earn a dynamic slice from the saturated
 * remaining time clamped to 10us plus 1ms, while misses hold else floor
 * only and rejoin via the same tier escalation re-derived with a fresh
 * deadline plus skip aging. Tasks join direct only when all tiers
 * including the reject hold no work or the target still drains before
 * the key with an empty machine and an empty reject, so no earlier key
 * waits behind this arrival. Missed tasks rejoin a tier queue with a
 * fresh deadline plus a miss count and one idle kick without waiting,
 * else the reject queue on overload. Pinned tasks wait in a tier queue
 * with wait set and one idle kick, else the reject queue on overload.
 * Exiting tasks run at once on the task CPU without queueing. The gate
 * runs first for all other arrivals, so a stale CPU or a moved task fails
 * closed with one counter. The predictor average rises fast with shift 3
 * plus falls slow with shift 4 and the deviation widens fast with shift 2
 * plus narrows slow with shift 3 plus half deviation margin from stopping,
 * so short bursts earn tight deadlines without a table walk. Vruntime advances by scaled
 * service with one divide, and the CPU minimum folds forward on every
 * charge, so fairness tracks service without a table. Every tier join
 * counts one admit and every RED overload counts one RED reject without
 * double counting the gate. The exiting, bypass, tier idle, and preempt
 * paths form the kick points, so every wait meets at most one kick. A
 * direct preempt needs unified latency with probation plus an eligible lat
 * arrival against a batch owner plus a 100us margin lead with more than
 * 100us still left on the owner, so near ties and nearly done owners
 * never bounce while one kick per wait stays. The owner paces on start
 * plus inherit cur without a fresh quantum, so the tail tracks the stored
 * slice. A preempted head resumes via lifecycle only with start plus cur
 * clamped to 10us plus 100us for latency else 1ms with inherit on bad
 * start plus tail plus history, so the same head resumes with its
 * leftover. Latency-critical slice carryover keeps the unused quantum, so
 * short bursts earn nearer keys. Strict slice writes run here before the
 * key. Fresh waits earn the dynamic remaining clamp, misses hold else
 * floor only, and rotations inherit zero. Slice expiry paces the rest
 * without stamping here. Local plus node depths read once, so the drain
 * gated bypass and the combined drain tier escalation share one read. See
 * intf.h for the deadline plus fairness helpers and dispatch.bpf.c for
 * the tier scans.
 *
 * The op holds the target plus insert plus miss plus open plus kick
 * helpers in enqueue/ with the fair plus clamp noinline on scalar input
 * plus the pinned plus miss plus open plus place plus kick noinline on
 * tail pointers, so the verifier stays small.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
#include "enqueue/target.bpf.c"
#include "enqueue/insert.bpf.c"
#include "enqueue/miss.bpf.c"
#include "enqueue/open.bpf.c"
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
	struct flow_open_out open_out = { 0 };
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
	/* The gate runs first without creating state, so stale CPUs or */
	/* moved tasks fail closed. The lookup stays read only here, and the */
	/* create follows only on pass. Rejects are rare, so they stay */
	/* unlikely. Gate misses join the value ordered reject queue without */
	/* waiting, so no path needs a tail queue and no insert touches the */
	/* kernel global queue. */
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
	/* allowed CPU without preempting, so a waiting task wakes cleanly. */
	/* The gate already passed, so this path adds no gate count. Missing */
	/* state is rare, so it stays unlikely. */
	if (unlikely(!tctx)) {
		s32 mc = flow_pick_target(p, sel);
		u32 mh = 0;
		u32 mhw = (u32)FLOW_WEIGHT_BASE;
		u64 mdl;
		/* No state means no predictor, so the hint weight threads */
		/* with BASE-only task share and batch value with probation. */
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
	/* Ensure the fairness fields hold sane defaults without a divide. */
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
	/* The pinned wait runs Outlined on scalars with no tail struct, so */
	/* the open path keeps verifier headroom with the same fair time */
	/* plus miss plus clamp plus kick and no stack spill. */
	if (unlikely(pinned)) {
		flow_enqueue_pinned(p, tctx, sel, now, enq_flags);
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
		u64 h_avg = (u64)READ_ONCE(tctx->avg_ns);
		u64 h_dev = (u64)READ_ONCE(tctx->dev_ns);
		u64 h_sleep = flow_sleep_ns(READ_ONCE(tctx->wait_at), now,
		    h_avg);
		u32 heff = flow_task_effective_weight(hw, hw_hint);
		bool hcrit = flow_is_lat(h_avg, h_dev, hhint, h_sleep, 0,
		    heff);
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
	/* Miss rejoins self-contained through the outlined helper with the */
	/* same fresh deadline plus held slice plus RED plus tier plus kick, */
	/* so the open path below handles only fresh plus requeue compute */
	/* with no inline growth and the same counts. */
	{
		struct flow_miss_tail miss = {
			.tctx = tctx,
			.cpu = cpu,
			.sel = sel,
			.now = now,
			.enq_flags = enq_flags,
			.hint = hint,
			.hint_w = hint_w,
			.avg = avg,
			.dev = dev,
		};
		if (flow_enqueue_miss(p, &miss))
			return;
	}
	deadline = flow_pred_deadline(now, avg, dev, hint);
	__sync_lock_test_and_set(&tctx->deadline, deadline);
	/* Open fair time runs outlined with out fields for RED plus place */
	/* plus kick, so fresh plus requeue share one divide copy with no */
	/* inline growth and the same order. */
	{
		struct flow_open_tail open = {
			.tctx = tctx,
			.deadline = deadline,
			.now = now,
			.enq_flags = enq_flags,
			.hint = hint,
			.hint_w = hint_w,
			.avg = avg,
			.dev = dev,
			.is_reenq = is_reenq,
		};
		flow_enqueue_open(&open, &open_out);
		vtime = open_out.vtime;
	}
	/* RED admission through the shared outlined helper. A reject needs */
	/* cost past the fixed 256us Emax plus cost past the exceed with no */
	/* critical, else the newcomer admits to the tier path. The deadline */
	/* bounds the check without shaping vruntime. Critical follows the */
	/* unified latency and cost uses the pre-clamp slice for fresh */
	/* waits, so RED and slice agree. A full O(n) least value scan stays */
	/* a noted alternative, so the verifier keeps one pass. Shares one */
	/* copy with miss plus pinned, so the dispatcher stays thin. */
	{
		u32 csl = READ_ONCE(tctx->slice_ns);
		bool ccrit = open_out.is_lat;
		u32 cost_sl = csl;
		struct flow_reject_tail rej;
		if (open_out.is_fresh && !(enq_flags & SCX_ENQ_PREEMPT))
			cost_sl = open_out.pre_slice;
		rej.tctx = tctx;
		rej.deadline = deadline;
		rej.now = now;
		rej.avg = avg;
		rej.slice = cost_sl;
		rej.is_lat = ccrit;
		rej.hint_w = hint_w;
		rej.enq_flags = enq_flags;
		rej.sel = sel;
		if (flow_enqueue_reject(p, &rej))
			return;
	}
	/* Every tier plus bypass join counts one admit without double */
	/* counting, so the counters track joins while tier queues hold */
	/* misses plus pins. */
	flow_count_admit();
	/* Eligibility read takes vruntime plus lag plus minimum once per */
	/* wait. The bypass and the kick share this one gate, so hogs pace */
	/* with one minimum read. Dropped reads keep the same order. */
	hoist_vr = READ_ONCE(tctx->vruntime);
	hoist_lag = READ_ONCE(tctx->vlag);
	hoist_min = flow_cpu_min((u32)cpu);
	hoist_elig = flow_eligible(hoist_vr, hoist_min, hoist_lag);
	/* Idle direct bypass plus tier join run outlined without changing */
	/* order, so the drain gate and the tier escalation share one read. */
	/* A direct bypass returns at once with one kick, else the tier join */
	/* falls into the single kick tail. The deadline plus admit already */
	/* hold, so order plus counters stay correct without extra waiting. */
	/* Strict fair order gates the bypass with eligibility plus drain, so */
	/* hogs pace through tiers without a direct jump and one kick per wait */
	/* stays. A stale hint only races a concurrent tier join, since */
	/* dispatch still drains in fair order with mask wins on the next pass. */
	/* Arrival sleep threads the pre-overwrite gap, so kick agrees with */
	/* RED plus slice on the same latency with no second wait read. */
	{
		struct flow_enqueue_tail tail;
		tail.cpu = cpu;
		tail.vtime = vtime;
		tail.now = now;
		tail.enq_flags = enq_flags;
		tail.arr_sleep = open_out.sleep_ns;
		tail.is_reenq = is_reenq;
		tail.hoist_elig = hoist_elig;
		if (flow_enqueue_place(p, &tail))
			return;
		flow_enqueue_kick(p, &tail);
	}
}
