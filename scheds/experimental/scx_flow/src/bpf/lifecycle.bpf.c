// SPDX-License-Identifier: GPL-2.0
/*
 * Task lifecycle ops with adaptive slice plus reclaim.
 *
 * Running claims the segment start from zero with an unconditional
 * pid store. Only stopping charges. A stall past 5s clamps the
 * stopping delta to zero, so suspend plus resume never poisons the
 * predictor plus the minimum plus the credit. The snapshot counts
 * live pids for the on CPU gauge. Stopping claims the start once,
 * charges the raw segment to total runtime, advances vruntime by the
 * scaled delta, folds
 * the CPU minimum forward, then feeds the burst predictor average plus
 * deviation from the same delta with up plus down shifts plus half
 * deviation margin, then resumes a preempt-like head with start plus cur
 * minus now clamped to 10us plus 100us for latency else 1ms with inherit
 * on bad start plus end else carries the latency-critical slice up to one
 * quantum clamped to 10us plus 1ms else adapts proportionally by exceed
 * SHIFT capped 1ms plus half then halved shrink on late else slack SHIFT
 * capped 1ms plus half then halved grow on early with deadband hold plus
 * clamp to 10us plus 1ms and latency grow to 100us without changing
 * virtual time, then counts one requeue per runnable stop else one
 * completion. Like fair.c, vruntime paces order, unlike rt.c, no fixed
 * priority holds. C holds burst else slice else quantum, and V holds
 * weight with zero mapped to 128, so the slice adapts while virtual time
 * stays untouched. A global saved credit at or past the fixed 256us Emax
 * reclaims one value ordered reject with positive laxity plus same
 * key or strictly after with a single move. A runnable preempt-like yield
 * with history plus tail left and no wall miss keeps start plus cur minus
 * now, else a yield before one quantum keeps the unused remainder only
 * when wall time still meets the deadline plus unified latency holds, else
 * the proportional step runs on the same expiring deadline. A wall
 * completion past the deadline counts one miss without a kick, since the
 * task already left the CPU. Miss plus Term where Term equals completions
 * stay counters only, so misses plus completions record history. Frozen
 * rejects plus on CPU plus overflow hold wire compat without a BPF writer,
 * whitelisted with readers using gate plus RED plus live pids.
 * Enable clears vruntime plus deadline plus stamps plus predictor plus lag
 * plus weight plus slice plus hint plus hint weight plus misses plus adapt
 * miss plus sat plus delta, and Disable plus exit clear without charging,
 * so each segment meets exactly one charge in stopping without double
 * counting. Disable clears the cached hierarchy id like move plus enable
 * plus exit, so a reused pid never reads stale. A closed gate still counts
 * one reject without charging. Release clears a stale running view without
 * charging. The gate runs first in every op except the exiting paths, so a
 * stale CPU fails closed with one counter. See intf.h for the shared
 * helpers and enqueue.bpf.c for the fair time choice.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
void BPF_STRUCT_OPS(flow_running, struct task_struct *p)
{
	struct flow_task_ctx *tctx;
	struct flow_cpu_state *st;
	s32 cpu;
	u64 now;
	u64 stamp;
	cpu = scx_bpf_task_cpu(p);
	/* The gate runs first with fail closed and no count on pass. */
	/* Exiting tasks never reach here through the running path. */
	if (unlikely(!flow_entry_ok(cpu, p, 0))) {
		flow_gate_reject();
		return;
	}
	tctx = flow_lookup(p);
	now = flow_now();
	/* Fold a bad clock, so a zero or saturated read never stamps zero */
	/* or max into the segment start. */
	if (now == 0 || now == (u64)~0ULL)
		now = 1;
	if (likely(tctx)) {
		/* The stamp never reads zero or max after the fold above, */
		/* so the claim swaps from zero only while a second running */
		/* without a stop keeps the first start with no second use. */
		/* The on CPU gauge lives in the snapshot with no BPF count, */
		/* so this path holds no gauge add. */
		stamp = now;
		__sync_val_compare_and_swap(&tctx->run_at,
		    0, stamp);
	}
	if (unlikely(cpu < 0))
		return;
	if (unlikely(!flow_cpu_live((u32)cpu)))
		return;
	st = flow_cpu((u32)cpu);
	if (likely(st)) {
		/* Claim the pid with an unconditional store, so a concurrent */
		/* clear plus run keeps the running task with no lost update. */
		/* The clear only clears when it still owns the pid, so the */
		/* store always wins over a stale clear with no torn write. A */
		/* compare and swap from the observed owner loses here, when */
		/* the clear wins the race to zero first, the swap fails and */
		/* leaves zero while this task still runs. The next running */
		/* would fold again, but the live view stays wrong until then. */
		__sync_lock_test_and_set(&st->running_pid,
		    (u32)p->pid);
	}
}
void BPF_STRUCT_OPS(flow_dequeue, struct task_struct *p,
	u64 deq_flags)
{
	(void)p;
	(void)deq_flags;
}
/**
 * struct flow_stop_tail - stopping commit args for the outlined commit.
 * @tctx: task state with slice plus adapt miss plus sat plus delta.
 * @slice: new slice in nanos to store.
 * @miss: true counts one adapt miss else clears the streak.
 * @sat_hi: saturation ceiling with 100us for latency else 1ms.
 * @cost_avg: burst average for the RED cost, zero for no history.
 * @cost_slice: stored slice for the RED cost.
 * @delta: raw service in nanos of the stopping segment.
 *
 * Bundles the adapt plus carry commit, so the four stopping paths share
 * one store with no inline growth and the same order.
 */
struct flow_stop_tail {
	struct flow_task_ctx *tctx;
	u32 slice;
	bool miss;
	u32 sat_hi;
	u64 cost_avg;
	u32 cost_slice;
	u64 delta;
};
/**
 * flow_stop_commit - commit one stopping slice plus adapt plus delta.
 * @t: stop tail with state plus slice plus miss plus ceiling plus cost
 * plus delta, read once by the caller.
 *
 * Stores the slice, folds the adapt miss streak with saturation at
 * 0xffff, folds the clamp streak at the floor plus ceiling, then saves
 * the unused cost minus delta for the global credit with no wrap. Like
 * fair.c, the step paces service, unlike rt.c, no fixed priority
 * holds. Virtual time stays untouched.
 *
 * Outlined with noinline to keep verifier headroom with one shared
 * copy, so resume plus carry plus adapt share the same commit with no
 * inline growth.
 */
static __noinline void flow_stop_commit(const struct flow_stop_tail *t)
{
	struct flow_task_ctx *tctx;
	u32 slice;
	bool miss;
	u32 sat_hi;
	u64 ccost;
	u64 csaved;
	u32 cs;
	if (!t)
		return;
	tctx = t->tctx;
	if (!tctx)
		return;
	slice = t->slice;
	miss = t->miss;
	sat_hi = t->sat_hi;
	__sync_lock_test_and_set(&tctx->slice_ns, slice);
	if (miss) {
		u16 mm = READ_ONCE(tctx->adapt_miss);
		if (mm < 0xffffU)
			tctx->adapt_miss = mm + 1;
	} else {
		tctx->adapt_miss = 0;
	}
	{
		u16 sat = READ_ONCE(tctx->adapt_sat);
		if (slice == (u32)FLOW_SLICE_MIN_NS || slice == sat_hi) {
			if (sat < 0xffffU)
				tctx->adapt_sat = sat + 1;
		} else {
			tctx->adapt_sat = 0;
		}
	}
	ccost = flow_red_cost(t->cost_avg, t->cost_slice);
	csaved = ccost > t->delta ? ccost - t->delta : 0;
	cs = csaved > 0xffffffffULL ? 0xffffffffU : (u32)csaved;
	tctx->adapt_delta = cs;
}
void BPF_STRUCT_OPS(flow_stopping, struct task_struct *p,
	bool runnable)
{
	struct flow_task_ctx *tctx;
	s32 cpu;
	u64 now;
	u64 delta;
	u64 start;
	u64 n_avg_keep = 0;
	u64 n_dev_keep = 0;
	bool have_pred = false;
	bool stop_is_lat = false;
	cpu = scx_bpf_task_cpu(p);
	if (!flow_entry_ok(cpu, p, 0)) {
		flow_gate_reject();
		return;
	}
	tctx = flow_lookup(p);
	now = flow_now();
	/* Tasks without state hold no claim, so they hold no count. */
	/* The pid view still clears when owned. */
	if (!tctx) {
		flow_clear_running_if_owner(cpu, (u32)p->pid);
		return;
	}
	/* The start claims with an exchange, so only stopping charges. */
	/* A zero claim means no counted start, */
	/* so this pass drops with no charge. The on CPU gauge lives in */
	/* the snapshot with no BPF drop, so every pass ends here with no */
	/* gauge use. */
	start = __sync_lock_test_and_set(&tctx->run_at, 0);
	if (start == 0) {
		flow_clear_running_if_owner(cpu, (u32)p->pid);
		return;
	}
	/* Clamp the segment delta with a fold on bad stamps, then clamp an */
	/* s2idle stall past 5s to zero, so a stale start never pollutes */
	/* the predictor plus the minimum plus the credit below. S3 pauses */
	/* monotonic with no BPF gap, so the boot gap reseeds instead. */
	/* The zero delta skips the predictor plus the minimum fold through */
	/* the gated charge, and the credit through its own delta gate. */
	delta = flow_delta_clamp(now, start);
	if (flow_gap_is_resume(delta))
		delta = 0;
	/* Every segment counts raw time while vruntime counts scaled time. */
	/* The predictor average rises fast with shift 3 plus falls slow */
	/* with shift 4, and the deviation widens fast with shift 2 plus */
	/* narrows slow with shift 3, plus a first deviation floor at */
	/* average quarter, so later deadlines track recent bursts with no */
	/* extra walk. A zero delta keeps the predictor, so a backward clock */
	/* never pulls the average to 1ns. The vruntime advance uses the */
	/* effective share of task times stored hint over 128 with no divide */
	/* and no lookup, so heavy tasks move slowly while light tasks move */
	/* quickly with no neutral cliff. The CPU minimum folds forward best */
	/* effort with no regression past a concurrent win. */
	flow_count_runtime(delta);
	if (delta) {
		u64 avg = (u64)READ_ONCE(tctx->avg_ns);
		u64 dev = (u64)READ_ONCE(tctx->dev_ns);
		u32 task_w = READ_ONCE(tctx->weight);
		u32 hint_w = READ_ONCE(tctx->hint_w);
		u32 eff_w;
		u64 n_avg = flow_pred_avg(avg, delta);
		/* Deviation updates from the observed delta with the new average, */
		/* so a fresh mean shapes the margin at once with no lagging bound. */
		u64 n_dev = flow_pred_dev(dev, n_avg, delta);
		u64 vrun = READ_ONCE(tctx->vruntime);
		u64 n_vrun;
		if (task_w == 0)
			task_w = (u32)FLOW_WEIGHT_BASE;
		eff_w = flow_task_effective_weight(task_w, hint_w);
		n_vrun = flow_ledger_advance(vrun, delta, eff_w);
		__sync_lock_test_and_set(&tctx->avg_ns, (u32)n_avg);
		__sync_lock_test_and_set(&tctx->dev_ns, (u32)n_dev);
		__sync_lock_test_and_set(&tctx->vruntime, n_vrun);
		flow_min_advance(cpu, n_vrun);
		n_avg_keep = n_avg;
		n_dev_keep = n_dev;
		have_pred = true;
	}
	/* Latency-critical slice carryover from the fixed quantum with no knob. */
	/* A runnable task that yields before one quantum keeps quantum */
	/* minus delta as the next slice when wall time still meets the */
	/* deadline plus predictor slack still holds critical, so short */
	/* bursts earn a nearer virtual deadline without an extra slice. All */
	/* other stops adapt proportionally with exceed right 3 capped 1ms */
	/* plus half of base then halved grow on late else slack right 3 */
	/* capped 1ms plus half of base then halved grow on early with */
	/* deadband hold plus clamp to 10us plus 1ms without changing virtual */
	/* time, so the slice tracks recent runs with shifts only. The same */
	/* expiring deadline feeds exceed plus slack, and the carry gate runs */
	/* first. */
	/* Like fair.c, the step paces service, unlike rt.c, no fixed priority holds. */
	/* C holds burst else slice else quantum, and V holds weight with */
	/* zero mapped to 128. Exiting plus completion paths skip the carry */
	/* with adapt only, so only runnable waits carry with one kick per */
	/* wait at enqueue. Misses count lifetime with saturation, adapt */
	/* miss counts the consecutive wall miss streak with saturation, so */
	/* promotion latches on lifetime while adapt tracks the window. */
	/* Latency recompute per stop without a stored bit, so 72B holds. */
	/* Sleep stays unknown with fail open, while hint plus effective */
	/* share veto toward batch with quantum-relative bounds and */
	/* probation, so newcomers stay batch. Like fair.c, the test paces */
	/* service, unlike rt.c, no fixed priority holds. Carry caps at */
	/* 100us plus adapt re-clamps at 100us past the 1ms step with */
	/* slack grow allowed to the cap, so urgent bursts rotate each tenth quantum. */
	stop_is_lat = false;
	{
		u64 s_avg = have_pred ? n_avg_keep :
		    (u64)READ_ONCE(tctx->avg_ns);
		u64 s_dev = have_pred ? n_dev_keep :
		    (u64)READ_ONCE(tctx->dev_ns);
		u32 s_hint = READ_ONCE(tctx->hint_us);
		u32 s_task_w = READ_ONCE(tctx->weight);
		u32 s_hint_w = READ_ONCE(tctx->hint_w);
		u32 s_eff;
		if (s_task_w == 0)
			s_task_w = (u32)FLOW_WEIGHT_BASE;
		s_eff = flow_task_effective_weight(s_task_w, s_hint_w);
		/* No stable uclamp field in this task view, so fail open to */
		/* zero without an extra map, and probation holds through both */
		/* helpers. */
		stop_is_lat = flow_is_lat(s_avg, s_dev, s_hint, 0, 0, s_eff);
	}
	if (runnable) {
		u64 exp_dl = READ_ONCE(tctx->deadline);
		bool wmiss = !flow_deadline_ok(exp_dl, now);
		u32 pre_cur = READ_ONCE(tctx->slice_ns);
		/* Preempt-like resume keeps the start plus cur leftover when */
		/* runnable yields early with history plus tail left and no wall */
		/* miss, so only preempt heads with more than 100us left resume */
		/* with occ start plus cur clamped to 10us plus 100us for latency */
		/* else 1ms with inherit on bad start plus end. The tail check is */
		/* delta plus 100us below cur here, so the helper keeps no tail */
		/* check. Equality fails closed and floors, so a latency head at */
		/* the 100us cap never resumes: cap equals tail, so delta plus */
		/* tail never falls below cap with delta past zero. This path */
		/* never runs and keeps latency rotating via carry plus adapt */
		/* without changing virtual time. Voluntary short yields fall */
		/* through to carry plus adapt, so resume never shadows. */
		if (!wmiss && have_pred && delta > 0 &&
		    flow_sat_add(delta, (u64)FLOW_PREEMPT_TAIL_NS) <
		    (u64)pre_cur) {
			u32 rem = flow_slice_resume(start, now, stop_is_lat,
			    pre_cur);
			u32 rem_cap = stop_is_lat ?
			    (u32)FLOW_SLICE_LAT_NS : (u32)FLOW_QUANTUM_NS;
			/* Resume plus carry plus adapt commit through the */
			/* shared helper, so the four stores share one copy */
			/* with no behavior change. */
			struct flow_stop_tail commit = {
				.tctx = tctx,
				.slice = rem,
				.miss = false,
				.sat_hi = rem_cap,
				.cost_avg = have_pred ? n_avg_keep : 0,
				.cost_slice = pre_cur,
				.delta = delta,
			};
			flow_stop_commit(&commit);
		} else if (!wmiss && have_pred && delta > 0 &&
		    delta < (u64)FLOW_QUANTUM_NS && stop_is_lat) {
			u32 carry = flow_carry_for(delta);
			u32 lat_cap = stop_is_lat ?
			    (u32)FLOW_SLICE_LAT_NS : (u32)FLOW_QUANTUM_NS;
			struct flow_stop_tail commit;
			carry = flow_slice_lat_clamp(carry, stop_is_lat);
			commit.tctx = tctx;
			commit.slice = carry;
			commit.miss = false;
			commit.sat_hi = lat_cap;
			commit.cost_avg = n_avg_keep;
			commit.cost_slice = pre_cur;
			commit.delta = delta;
			flow_stop_commit(&commit);
		} else {
			u32 cur = READ_ONCE(tctx->slice_ns);
			u64 exceed = 0;
			u64 slack = 0;
			u32 nxt;
			bool m = wmiss;
			u32 sat_hi;
			struct flow_stop_tail commit;
			if (exp_dl != 0) {
				if (m)
					exceed = now - exp_dl;
				else if (now != exp_dl)
					slack = exp_dl - now;
			}
			nxt = flow_adapt_prop(cur, exceed, slack);
			if (stop_is_lat)
				nxt = flow_slice_lat_clamp(nxt, true);
			sat_hi = stop_is_lat ?
			    (u32)FLOW_SLICE_LAT_NS : (u32)FLOW_QUANTUM_NS;
			commit.tctx = tctx;
			commit.slice = nxt;
			commit.miss = m;
			commit.sat_hi = sat_hi;
			commit.cost_avg = have_pred ? n_avg_keep : 0;
			commit.cost_slice = cur;
			commit.delta = delta;
			flow_stop_commit(&commit);
		}
	} else {
		/* Completion adapt without carry and without a kick. An exceed */
		/* shrinks by exceed right 3 capped 1ms plus half of base, a slack */
		/* grows by slack right 3 capped 1ms plus half of base, both clamped */
		/* without changing virtual time. The */
		/* global credit funds reclaim below. */
		u64 exp_dl = READ_ONCE(tctx->deadline);
		u32 cur = READ_ONCE(tctx->slice_ns);
		bool cmiss = !flow_deadline_ok(exp_dl, now);
		u64 exceed = 0;
		u64 slack = 0;
		u32 nxt;
		if (exp_dl != 0) {
			if (cmiss)
				exceed = now - exp_dl;
			else if (now != exp_dl)
				slack = exp_dl - now;
		}
		nxt = flow_adapt_prop(cur, exceed, slack);
		if (stop_is_lat)
			nxt = flow_slice_lat_clamp(nxt, true);
		{
			u32 sat_hi = stop_is_lat ?
			    (u32)FLOW_SLICE_LAT_NS : (u32)FLOW_QUANTUM_NS;
			struct flow_stop_tail commit = {
				.tctx = tctx,
				.slice = nxt,
				.miss = cmiss,
				.sat_hi = sat_hi,
				.cost_avg = have_pred ? n_avg_keep : 0,
				.cost_slice = cur,
				.delta = delta,
			};
			flow_stop_commit(&commit);
			/* Reclaim runs in dispatch from the global credit at or past */
			/* the fixed 256us Emax with tiers-empty fallback plus aged */
			/* cover past one period, so this path records only without */
			/* walking. The global credit funds the retry without shaping */
			/* shares. Dispatch scans at most eight value ordered rejects */
			/* with positive laxity plus same key or strictly after plus */
			/* mask wins, so strict order holds with a single move. Zero */
			/* service completions fund nothing, so only a real delta with */
			/* a fresh predictor adds credit. Credit reuses the committed */
			/* delta, so funding agrees with the stored value with no */
			/* second cost pass. */
			if (delta > 0 && have_pred)
				flow_credit_add((u64)READ_ONCE(tctx->adapt_delta));
		}
	}
	/* The pid view clears when owned. The snapshot counts live pids for */
	/* the on CPU gauge. */
	flow_clear_running_if_owner(cpu, (u32)p->pid);
	/* A wall completion past the deadline counts one miss without a kick, */
	/* since the task already left the CPU. The miss count stays lifetime */
	/* without a reset here, so stopping records only. The miss count */
	/* tracks the proportional shrink. */
	if (!runnable && !flow_deadline_ok(READ_ONCE(tctx->deadline), now))
		flow_count_miss(tctx);
	if (runnable) {
		flow_count_requeue(true);
		return;
	}
	flow_count_requeue(false);
}
void BPF_STRUCT_OPS(flow_enable, struct task_struct *p)
{
	struct flow_task_ctx *tctx;
	s32 cpu = scx_bpf_task_cpu(p);
	if (!flow_entry_ok(cpu, p, 0)) {
		flow_gate_reject();
		return;
	}
	tctx = flow_get(p);
	if (!tctx)
		return;
	/* Fresh tasks hold no vruntime, no deadline, no stamps, no */
	/* predictor, no lag, neutral weight, fixed slice, no hint, neutral */
	/* hint weight, no misses, no adapt miss, no adapt sat, and no adapt */
	/* delta. The first enqueue clamps vruntime to the CPU minimum */
	/* minus the lag bound with a fallback deadline plus a virtual */
	/* deadline, so sleepers gain no more than one boost. The cached */
	/* hierarchy id clears too, so a reused pid never reads a stale */
	/* hierarchy. */
	flow_cgrp_cache_invalidate((u32)p->pid);
	tctx->vruntime = 0;
	tctx->deadline = 0;
	tctx->wait_at = 0;
	tctx->run_at = 0;
	tctx->hint_w = (u32)FLOW_WEIGHT_BASE;
	tctx->avg_ns = 0;
	tctx->dev_ns = 0;
	tctx->vlag = 0;
	tctx->weight = (u32)FLOW_WEIGHT_BASE;
	tctx->slice_ns = (u32)FLOW_QUANTUM_NS;
	tctx->hint_us = 0;
	tctx->misses = 0;
	tctx->adapt_miss = 0;
	tctx->adapt_sat = 0;
	tctx->adapt_delta = 0;
}
void BPF_STRUCT_OPS(flow_disable, struct task_struct *p)
{
	s32 cpu = scx_bpf_task_cpu(p);
	if (!flow_entry_ok(cpu, p, 0)) {
		flow_gate_reject();
		return;
	}
	/* Clear the cached hierarchy id for ABA safety, so a later pid */
	/* reuse never reads a stale hierarchy like move plus enable plus */
	/* exit. A zero pid needs no clear with the zero sentinel. */
	flow_cgrp_cache_invalidate((u32)p->pid);
	/* Charge lives only in stopping with no leftover, so disable */
	/* clears the pid view with no advance and no minimum fold. */
	flow_clear_running_if_owner(cpu, (u32)p->pid);
}
void BPF_STRUCT_OPS(flow_exit_task, struct task_struct *p,
	struct scx_exit_task_args *args)
{
	s32 cpu = scx_bpf_task_cpu(p);
	(void)args;
	/* Exiting tasks stay exempt from the gate with no count. The */
	/* cached hierarchy id clears too, so a later pid reuse never */
	/* reads a stale hierarchy. */
	flow_cgrp_cache_invalidate((u32)p->pid);
	/* Charge lives only in stopping with no leftover, so exit clears */
	/* the pid view with no advance and no minimum fold. */
	flow_clear_running_if_owner(cpu, (u32)p->pid);
}
void BPF_STRUCT_OPS(flow_cpu_release, s32 cpu,
	struct scx_cpu_release_args *args)
{
	(void)args;
	/* The gate runs with no task here, so only the CPU checks. */
	/* A stale CPU counts one reject with no clear. */
	if (cpu >= 0 && !flow_cpu_live((u32)cpu)) {
		flow_gate_reject();
		return;
	}
	/* Clear the stale running view with no charge. */
	/* The segment still ends through stopping or disable. */
	flow_clear_running(cpu);
}
