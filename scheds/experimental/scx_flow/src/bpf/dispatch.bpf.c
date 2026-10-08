// SPDX-License-Identifier: GPL-2.0
/*
 * Dispatch with strict PRIQ plus bounded steal plus fail open.
 *
 * Each pass drains local plus node plus machine plus steal in order
 * with at most one hint threaded move per tier bounded by remaining
 * slots and visits capped at eight per pass shared across tiers. Four
 * depths hoist once, so tiers plus steal plus perf share the same
 * reads with no second poll. Three PRIQ tiers hold strict order
 * through the kernel priority queue with insert vtime, so the
 * earliest key always wins with no load swap. The reject queue stays
 * value ordered outside dispatch with no tier move here, so overload
 * never inverts the PRIQ order. The reject queue holds overload with
 * no drop and reclaims at most one per pass with tiers-empty fallback
 * plus aged cover past one period, so PRIQ tiers never starve behind
 * rejects and zero credit never idles queued work. A reject rejoins a PRIQ tier only on
 * reclaim with the same key or a strictly after key, so an earlier key
 * never waits behind a rejoin. The steal tier scans four to eight
 * peers sticky with node-local first plus idle affinity plus backoff
 * on gate plus miss pressure, with per peer hints threaded into one
 * hint move plus a saturated early out when tiers still hold work. A
 * Q1 only fast path drains the single queue pass skips two empty moves
 * plus the steal polls. The shared cursor advances by two on a
 * successful steal to match select, so the next pass starts past the
 * drained peer with no hotspot and no extra scan. Fail open moves
 * through the shared mask gate, so one foreign head never stalls its
 * tier. The TOCTOU between hoisted hints and moves only repeats or
 * skips a pass with no loss. The level follows after all moves through
 * the fused hint probe with no kfunc and stays transition only. The
 * fused scope is per CPU own local plus local on plus node plus
 * running only with no machine plus reject plus steal, so a busy
 * shared tier never forces max on an idle CPU. Local on stays
 * terminal only at three sites with no global queue use.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
/* Depth probe with hoisted hints plus running and no kfunc. */
/* Takes the dispatch hoisted depths for own local plus local on plus */
/* node, so the perf pass reuses the same five reads with no second poll. */
/* Fused early out keeps one compare on the busy path and the first queued */
/* hint or running pid returns busy at once. The TOCTOU with dispatch */
/* moves only shifts the perf level by one pass with no order effect, */
/* since the next pass re-probes with no latch. Signed hints keep empty */
/* at zero or below with no unsigned wrap. */
/**
 * flow_perf_busy_hint - test busy from hoisted queue hints.
 * @cpu: CPU to test, negative fails closed.
 * @local_q: hoisted own local depth, non-positive means empty.
 * @local_on_q: hoisted local on depth, non-positive means empty.
 * @node_q: hoisted node depth, non-positive means empty.
 *
 * Scope is per CPU own local plus local on plus node plus running only
 * with no machine plus overflow plus steal, and the caller gates on live
 * with the same check inside, so an idle CPU with only shared backlog
 * still rests at half with no order effect.
 *
 * Returns: true when busy, else false with no kfunc.
 */
static __noinline bool flow_perf_busy_hint(s32 cpu, s32 local_q,
	s32 local_on_q, s32 node_q)
{
	struct flow_cpu_state *st;
	if (cpu < 0)
		return false;
	if (!flow_cpu_live((u32)cpu))
		return false;
	if (local_q > 0)
		return true;
	if (local_on_q > 0)
		return true;
	if (node_q > 0)
		return true;
	st = flow_cpu((u32)cpu);
	if (st && READ_ONCE(st->running_pid) != 0)
		return true;
	return false;
}
/* Core perf set with transition only store. */
static __noinline void flow_perf_set(s32 cpu, u32 want)
{
	u32 cap;
	u32 key;
	u32 *last;
	if (!bpf_ksym_exists(scx_bpf_cpuperf_set))
		return;
	if (cpu < 0)
		return;
	if (!flow_cpu_live((u32)cpu))
		return;
	if ((u64)cpu >= (u64)FLOW_MAX_CPUS)
		return;
	if (want != (u32)FLOW_CPU_PERF_HALF &&
	    want != (u32)FLOW_CPU_PERF_MAX)
		return;
	if (bpf_ksym_exists(scx_bpf_cpuperf_cap)) {
		cap = scx_bpf_cpuperf_cap(cpu);
		if (cap == 0)
			return;
		if (want > cap)
			want = cap;
	}
	key = (u32)cpu;
	last = bpf_map_lookup_elem(&cpu_perf_last, &key);
	if (!last)
		return;
	if (READ_ONCE(*last) == want)
		return;
	__sync_lock_test_and_set(last, want);
	scx_bpf_cpuperf_set(cpu, want);
}
/* Fused perf update with hoisted hints and no kfunc on the probe. */
static __always_inline void flow_perf_update_hint(s32 cpu, s32 local_q,
	s32 local_on_q, s32 node_q)
{
	if (flow_perf_busy_hint(cpu, local_q, local_on_q, node_q))
		flow_perf_set(cpu, (u32)FLOW_CPU_PERF_MAX);
	else
		flow_perf_set(cpu, (u32)FLOW_CPU_PERF_HALF);
}
/**
 * struct flow_reclaim_tail - reclaim args for the outlined candidate check.
 * @rctx: reject task state with deadline plus predictor plus vruntime.
 * @q: reject task for the mask gate.
 * @cpu: target CPU for the mask gate.
 * @now: current time in nanos.
 * @credit: hoisted global reclaim credit with no second poll.
 * @tiers_empty: true when local plus node plus machine hold no work.
 *
 * Bundles the candidate state plus time plus credit plus gate, so the
 * outlined check takes one pointer with no stack args like the scan
 * plus enqueue tails and the dispatch loop stays small.
 */
struct flow_reclaim_tail {
	struct flow_task_ctx *rctx;
	struct task_struct *q;
	s32 cpu;
	u64 now;
	u64 credit;
	bool tiers_empty;
};
/**
 * flow_reclaim_candidate_ok - test one reject for reclaim plus reserve.
 * @t: reclaim tail with state plus task plus target plus time plus credit
 * plus gate, hoisted once by the caller with no second read.
 *
 * Checks laxity plus tiers-empty plus aged cover plus key freshness plus
 * mask plus credit with reserve, so the loop keeps one call with no
 * inline growth. Tiers-empty heads with positive laxity fall back without
 * reserve while funded heads reserve before the move, so zero credit never
 * idles queued work. Aged heads past one period pass even when tiers hold
 * work. A stale key plus a foreign mask plus a lost reserve fails closed
 * to the next candidate with no head block.
 *
 * Returns: true when the caller may move the candidate.
 *
 * Outlined with noinline to keep verifier headroom on the dispatch path
 * with no order change.
 */
static __noinline bool flow_reclaim_candidate_ok(const struct flow_reclaim_tail *t)
{
	struct flow_task_ctx *rctx = t->rctx;
	struct task_struct *q = t->q;
	s32 cpu = t->cpu;
	u64 now = t->now;
	u64 credit = t->credit;
	bool tiers_empty = t->tiers_empty;
	u64 rdl;
	u64 ravg;
	u64 rdev;
	u64 rcost;
	u64 rtol;
	s64 rres;
	u64 rexc;
	u64 rlax;
	u64 rvtime;
	u64 rwait;
	bool rcrit;
	bool is_aged = false;
	bool funded;
	if (!rctx || !q)
		return false;
	rdl = READ_ONCE(rctx->deadline);
	ravg = (u64)READ_ONCE(rctx->avg_ns);
	rdev = (u64)READ_ONCE(rctx->dev_ns);
	rcrit = flow_lat_crit(ravg, rdev);
	rcost = flow_red_cost(ravg, READ_ONCE(rctx->slice_ns));
	rtol = flow_red_tol(rcrit);
	rres = flow_red_residual(rdl, now, rcost);
	rexc = flow_red_exceed(rres, rtol);
	rlax = flow_red_laxity(rdl, now, rcost);
	if (rlax == 0)
		return false;
	rwait = READ_ONCE(rctx->wait_at);
	if (rwait != 0 && rwait != now &&
	    !flow_time_before(now, rwait)) {
		u64 age = now - rwait;
		if (age > (u64)FLOW_PERIOD_NS)
			is_aged = true;
	}
	if (!tiers_empty && !is_aged)
		return false;
	rvtime = flow_edf_key(rdl,
	    flow_virt_deadline(READ_ONCE(rctx->vruntime),
	    (u64)READ_ONCE(rctx->slice_ns),
	    flow_task_effective_weight(READ_ONCE(rctx->weight),
	    READ_ONCE(rctx->hint_w))));
	if (rvtime != now && flow_time_before(rvtime, now))
		return false;
	if (!flow_mask_ok(cpu, q))
		return false;
	funded = flow_red_reclaim_ok(credit, rexc, rlax);
	if (funded) {
		if (!flow_credit_consume(rexc))
			return false;
	}
	return true;
}
/**
 * flow_reject_reclaim_one - reclaim one value ordered reject.
 * @cpu: target CPU for the mask gate.
 * @visits: per pass visit count shared across tiers.
 * @now: current time in nanos.
 * @queued: hoisted reject depth, non-positive skips with no walk.
 * @tiers_empty: true when local plus node plus machine hold no work.
 *
 * Scans at most eight value ordered rejects with one RCU walk and no
 * unbounded loop, so the check stays cheap. Funded heads reserve credit
 * before the move with a recheck to the next candidate on a lost race,
 * while tiers-empty heads with positive laxity fall back without reserve
 * so zero credit never idles queued work. Aged heads past one period
 * reclaim even when tiers hold work, so continuous tier load never parks
 * rejects without bound and the bypass veto never deadlocks. Non
 * reclaimable plus stale plus foreign entries skip to the next candidate
 * with no head block, so one bad head never stalls the queue. The credit
 * funds the retry with no head state use. The greatest value still wins
 * among reclaimable entries with no extra sort. Tiers-empty gating plus
 * one move per pass plus the one period age bound keep starvation bounded
 * and PRIQ tiers never wait behind rejects past the age bound.
 *
 * Returns: one on move else zero with no state.
 *
 * Outlined with noinline to keep verifier headroom on the dispatch
 * path with no order change.
 */
static __noinline u32 flow_reject_reclaim_one(s32 cpu, u32 *visits, u64 now,
	s32 queued, bool tiers_empty)
{
	u64 credit;
	struct task_struct *q;
	u32 moved = 0;
	if (unlikely(cpu < 0))
		return 0;
	if (unlikely(!visits))
		return 0;
	if (unlikely(!flow_cpu_live((u32)cpu)))
		return 0;
	if (unlikely(*visits >= (u32)FLOW_DISPATCH_MAX_VISIT))
		return 0;
	if (likely(queued <= 0))
		return 0;
	credit = flow_credit_peek();
	bpf_rcu_read_lock();
	bpf_for_each(scx_dsq, q, flow_overflow_dsq(), 0) {
		struct flow_task_ctx *rctx;
		struct flow_reclaim_tail tail;
		u32 cur;
		if (unlikely(*visits >= (u32)FLOW_DISPATCH_MAX_VISIT))
			break;
		if (unlikely(moved))
			break;
		(*visits)++;
		rctx = flow_lookup(q);
		if (!rctx)
			continue;
		tail.rctx = rctx;
		tail.q = q;
		tail.cpu = cpu;
		tail.now = now;
		tail.credit = credit;
		tail.tiers_empty = tiers_empty;
		if (!flow_reclaim_candidate_ok(&tail))
			continue;
		cur = flow_move_candidate(BPF_FOR_EACH_ITER, cpu, q);
		if (cur)
			moved = cur;
		break;
	}
	bpf_rcu_read_unlock();
	return moved;
}
void BPF_STRUCT_OPS(flow_dispatch, s32 cpu,
	struct task_struct *prev)
{
	u32 budget;
	u32 left = 0;
	u32 visits = 0;
	u32 local_moved = 0;
	u32 node_moved = 0;
	u32 machine_moved = 0;
	u32 reclaim_moved = 0;
	u64 own_local;
	u32 node;
	u64 node_dsq;
	u64 machine_dsq;
	(void)prev;
	if (unlikely(cpu < 0))
		return;
	if (unlikely(!flow_cpu_live((u32)cpu))) {
		flow_gate_reject();
		return;
	}
	budget = scx_bpf_dispatch_nr_slots();
	own_local = flow_local_dsq((u32)cpu);
	node = flow_cpu_node((u32)cpu);
	if (node >= (u32)FLOW_MAX_NODES ||
	    (u64)node >= nr_node_ids)
		node = 0;
	node_dsq = flow_node_dsq(node);
	machine_dsq = flow_machine_dsq();
	/* Hoist four depths once before the budget gate, so the fused perf */
	/* probe at out reuses the same reads with no second poll even when */
	/* slots run out. Signed hints keep empty at zero or below. The */
	/* reject queue stays outside here with no hoist, so the pass pays */
	/* four reads total with no duplicate. */
	{
		s32 lq0 = scx_bpf_dsq_nr_queued(own_local);
		s32 lo0 = scx_bpf_dsq_nr_queued((u64)SCX_DSQ_LOCAL_ON |
		    (u64)(u32)cpu);
		s32 nq0 = scx_bpf_dsq_nr_queued(node_dsq);
		s32 mq0 = scx_bpf_dsq_nr_queued(machine_dsq);
		if (unlikely(budget == 0))
			goto out_hint;
		left = budget;
	/* Queue runnable hints hoist four depths once. Each tier move threads */
	/* its hint through the shared hint move with no second poll, so empty */
	/* tiers skip the RCU scan with no visit cost. The same hints feed the */
	/* steal early out plus the fused perf probe with no second poll, so */
	/* the pass pays four queue reads total with no duplicate. The TOCTOU */
	/* between a hint and its move only repeats or skips a pass with no */
	/* loss, since the shared hint move rechecks under RCU with the same */
	/* visit cap. Signed hints keep empty at zero or below. */
	{
		bool q1_only = lq0 > 0 && nq0 <= 0 && mq0 <= 0;
		/* Q1 only fast path drains the local tier alone. The common */
		/* single queue pass skips two empty moves plus the steal */
		/* backlog with the same order plus the same counts. Threads */
		/* the hoisted hint with no second poll. */
		if (q1_only && likely(left) &&
		    likely(visits < (u32)FLOW_DISPATCH_MAX_VISIT)) {
			local_moved = flow_move_one_hint(own_local, cpu, &visits,
			    lq0);
			if (local_moved > left)
				local_moved = left;
			left -= local_moved;
			goto account;
		}
		if (likely(left) && likely(visits < (u32)FLOW_DISPATCH_MAX_VISIT)) {
			if (lq0 > 0) {
				local_moved = flow_move_one_hint(own_local, cpu,
				    &visits, lq0);
				if (local_moved > left)
					local_moved = left;
				left -= local_moved;
			}
		}
		if (likely(left) && likely(visits < (u32)FLOW_DISPATCH_MAX_VISIT)) {
			if (nq0 > 0) {
				node_moved = flow_move_one_hint(node_dsq, cpu,
				    &visits, nq0);
				if (node_moved > left)
					node_moved = left;
				left -= node_moved;
			}
		}
		if (likely(left) && likely(visits < (u32)FLOW_DISPATCH_MAX_VISIT)) {
			if (mq0 > 0) {
				machine_moved = flow_move_one_hint(machine_dsq, cpu,
				    &visits, mq0);
				if (machine_moved > left)
					machine_moved = left;
				left -= machine_moved;
			}
		}
		/* Reject queue stays outside dispatch with no tier move here. */
		/* A reject rejoins a PRIQ tier only on reclaim with the same */
		/* key or a strictly after key, so strict order holds with no */
		/* inversion. Like fair.c, the earliest key wins, unlike */
		/* rt.c, no fixed priority holds. */
		/* Reclaim one value ordered reject with tiers-empty plus aged cover. */
		/* Tiers-empty heads fall back without reserve so zero credit */
		/* never idles queued work, while aged heads past one period */
		/* reclaim even when tiers hold work so the reject never grows */
		/* without bound. The clock reads only here with no hot path */
		/* cost, and the TOCTOU between the hoisted hint and the reclaim */
		/* move only repeats or skips a pass with no loss. */
		if (likely(left) && likely(visits < (u32)FLOW_DISPATCH_MAX_VISIT)) {
			bool tiers_empty = (lq0 <= 0 && nq0 <= 0 && mq0 <= 0);
			s32 oq = scx_bpf_dsq_nr_queued(flow_overflow_dsq());
			if (oq > 0) {
				u64 now = flow_now();
				u32 rec = flow_reject_reclaim_one(cpu, &visits,
				    now, oq, tiers_empty);
				if (rec > left)
					rec = left;
				left -= rec;
				local_moved += rec;
				reclaim_moved += rec;
			}
		}
		/* Steal tier last with a bounded 4 to 8 peer window with saturation. */
		/* Only steals when tiers drained, so busy passes skip cheap with */
		/* the hoisted hints and no second poll. Starvation stays bounded */
		/* here. The window caps each pass while miss counts pace every */
		/* tier, so the lowest tier still turns. */
		/* Backlog sums the three */
		/* queued tiers with saturation, so a huge depth clamps instead */
		/* of wrapping to idle. Narrow means */
		/* empty peers skip with no RCU through the per peer hint in the */
		/* shared steal, so the effective scan stays small. */
		if (likely(left) && likely(visits < (u32)FLOW_DISPATCH_MAX_VISIT)) {
			u32 steal_moved = 0;
			struct flow_cpu_state *cst;
			u32 cursor;
			u64 backlog = 0;
			if (lq0 > 0)
				backlog = flow_sat_add(backlog, (u64)lq0);
			if (nq0 > 0)
				backlog = flow_sat_add(backlog, (u64)nq0);
			if (mq0 > 0)
				backlog = flow_sat_add(backlog, (u64)mq0);
			if (backlog == 0) {
				u64 nr = nr_cpu_ids;
				cst = flow_cpu((u32)cpu);
				cursor = cst ? READ_ONCE(cst->cursor) : (u32)cpu;
				steal_moved = flow_steal_one(cpu, &visits, cursor);
				if (steal_moved > left)
					steal_moved = left;
				left -= steal_moved;
				local_moved += steal_moved;
				/* Shared cursor advances by two on success to match */
				/* select, so the next steal starts fresh with no */
				/* hotspot and no extra scan. Best effort races */
				/* keep no atomic order beyond the single store. */
				if (steal_moved && cst && nr > 1 &&
				    nr <= (u64)FLOW_MAX_CPUS) {
					u32 n = (u32)nr;
					u32 next = flow_wrap_idx((u64)cursor + 2ULL, n);
					__sync_lock_test_and_set(&cst->cursor, next);
				}
			}
		}
	}
account:
	flow_account_local(local_moved);
	flow_account_node(node_moved);
	flow_account_machine(machine_moved);
	flow_count_red_reclaim(reclaim_moved);
out_hint:
	/* Fused perf probe reuses the hoisted local plus local on plus node */
	/* hints with no kfunc, so the pass pays no second poll on the busy */
	/* path. The TOCTOU only shifts the level by one pass with no order. */
	flow_perf_update_hint(cpu, lq0, lo0, nq0);
	}
	return;
}
