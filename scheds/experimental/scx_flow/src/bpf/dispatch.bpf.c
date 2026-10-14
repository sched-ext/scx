// SPDX-License-Identifier: GPL-2.0
/*
 * Dispatch with strict PRIQ plus capped steal plus fail open.
 *
 * Each pass drains local plus node plus machine plus steal in order
 * with at most one hint threaded move per tier capped by remaining
 * slots and visits capped at eight per pass shared across tiers. Four
 * depths read once, so tiers plus steal plus perf share the same
 * reads. Three PRIQ tiers (local plus node plus machine) hold strict
 * order through the kernel priority queue with insert vtime plus value
 * ordered reject plus steal for five total, so the earliest key always
 * wins. In-tier keys cap at now plus one period at enqueue, so far keys
 * never starve past one period and eight visits per pass cap each tier
 * with resume next pass. The reject queue stays value ordered outside
 * dispatch, so overload never inverts the PRIQ order. The reject queue
 * holds overload and reclaims at most one per pass with tiers-empty
 * fallback plus aged cover past one period, so PRIQ tiers never starve
 * behind rejects and zero credit never idles queued work. A reject
 * rejoins a PRIQ tier only on reclaim with the same key or a strictly
 * after key, so an earlier key never waits behind a rejoin. The steal
 * tier scans four to eight peers sticky with node-local first plus idle
 * affinity plus backoff on gate plus miss pressure, with per peer hints
 * threaded into one hint move plus a saturated early out when tiers
 * still hold work. A Q1 only fast path drains the single queue pass and
 * skips two empty moves plus the steal checks. The shared cursor advances
 * by two on a successful steal to match select, so the next pass starts
 * past the drained peer without a hotspot. Fail open moves through the
 * shared mask gate, so one foreign head never stalls its tier. A stale
 * hint only repeats or skips a pass. The level follows after all moves
 * through the shared hint check without a kfunc and stays transition
 * only. The check covers per CPU local, local on, node, and running, and
 * skips machine, reject, and steal, so a busy shared tier never forces
 * max on an idle CPU. Local on stays terminal FIFO at three sites
 * outside PRIQ order with no tier rank, so tiers stay PRIQ-only.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
/* Depth check with saved hints plus running without a kfunc. */
/* Takes the dispatch depths for own local plus local on plus node, */
/* so the perf pass reuses the same reads. Shared early exit keeps one */
/* compare on the busy path and the first queued hint or running pid */
/* returns busy at once. A stale read with dispatch moves only shifts the */
/* perf level by one pass without changing order, since the next pass */
/* reads again. Signed hints keep empty at zero or below, so empty never */
/* wraps. */
/**
 * flow_perf_busy_hint - test busy from saved queue hints.
 * @cpu: CPU to test, negative fails closed.
 * @local_q: saved own local depth, non-positive means empty.
 * @local_on_q: saved local on depth, non-positive means empty.
 * @node_q: saved node depth, non-positive means empty.
 *
 * Scope covers per CPU local, local on, node, and running, and skips
 * machine, overflow, and steal. The caller also gates on live, so an
 * idle CPU with only shared backlog still rests at half without changing
 * order.
 *
 * Returns: true when busy, else false without a kfunc.
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
/* Shared perf update with saved hints without a kfunc on the check. */
 /* Scope covers per CPU local, local on, node, and running, and skips */
 /* machine, overflow, and steal, so a busy shared tier never forces max */
 /* on an idle CPU. Transition-only store keeps one level per change */
 /* without flapping, and a stale read only shifts the level by one pass. */
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
 * @credit: saved global reclaim credit, read once by the caller.
 * @tiers_empty: true when local plus node plus machine hold no work.
 *
 * Bundles the candidate state plus time plus credit plus gate, so the
 * outlined check takes one pointer like the scan plus enqueue tails and
 * the dispatch loop stays small.
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
 * flow_reclaim_is_aged - test one reject wait past one period.
 * @wait_at: last wait stamp in nanos, zero means unknown.
 * @now: current time in nanos.
 *
 * Ages past one period with wrap safety, so continuous tier load still
 * needs credit past the age bound with no bypass. A zero stamp, a stamp
 * at now, or a future stamp never counts as aged with no stall.
 * Like fair.c, the bound paces reclaim, unlike rt.c, no fixed priority
 * holds.
 *
 * Outlined with noinline to keep verifier headroom with one shared
 * copy, so the reclaim check keeps one age with no inline growth.
 *
 * Returns: true when aged past one period, else false.
 */
static __noinline bool flow_reclaim_is_aged(u64 wait_at, u64 now)
{
	u64 age;
	if (wait_at == 0 || wait_at == now)
		return false;
	if (flow_time_before(now, wait_at))
		return false;
	age = now - wait_at;
	return age > (u64)FLOW_PERIOD_NS;
}
/**
 * flow_reclaim_key_ok - test one reject key still fresh.
 * @rctx: reject task state with vruntime plus slice plus weight.
 * @rdl: reject absolute deadline in nanos.
 * @now: current time in nanos.
 *
 * Rebuilds the strict key as the earlier of deadline plus virtual
 * deadline with the effective share, so a stale key fails closed to
 * the next candidate with no move. A key at now stays fresh with no
 * stall. Like fair.c, the earliest key wins, unlike rt.c, no fixed
 * priority holds.
 *
 * Outlined with noinline to keep verifier headroom with one shared
 * copy, so the reclaim check keeps one key with no inline growth.
 *
 * Returns: true when fresh, else false on stale state.
 */
static __noinline bool flow_reclaim_key_ok(struct flow_task_ctx *rctx,
	u64 rdl, u64 now)
{
	u64 rvtime;
	u64 vr;
	u64 sl;
	u32 tw;
	u32 hw;
	u32 eff;
	u64 vd;
	if (!rctx)
		return false;
	vr = READ_ONCE(rctx->vruntime);
	sl = (u64)READ_ONCE(rctx->slice_ns);
	tw = READ_ONCE(rctx->weight);
	hw = READ_ONCE(rctx->hint_w);
	eff = flow_task_effective_weight(tw, hw);
	vd = flow_virt_deadline(vr, sl, eff);
	rvtime = flow_edf_key(rdl, vd);
	if (rvtime != now && flow_time_before(rvtime, now))
		return false;
	return true;
}
/**
 * flow_reclaim_early_skip - test whether the reclaim walk skips early.
 * @credit: saved global reclaim credit, read once by the caller.
 * @tiers_empty: true when local plus node plus machine hold no work.
 *
 * Skips the walk when tiers hold work plus credit stays short of the
 * fixed 256us Emax, since aged heads still need funding with no
 * fallback. Tiers-empty keeps the walk with no reserve, so zero credit
 * never idles work.
 *
 * Outlined with noinline to keep verifier headroom with one shared
 * copy, so the dispatch pass keeps one fixed read with no inline
 * growth.
 *
 * Returns: true when the caller skips the walk, else false.
 */
static __noinline bool flow_reclaim_early_skip(u64 credit, bool tiers_empty)
{
	if (!tiers_empty && credit < (u64)FLOW_RED_EMAX_NS)
		return true;
	return false;
}
/**
 * flow_reclaim_candidate_ok - test one reject for reclaim plus reserve.
 * @t: reclaim tail with state plus task plus target plus time plus credit
 * plus gate, read once by the caller.
 *
 * Checks laxity with the fixed 64us tolerance plus tiers-empty plus
 * aged cover plus key freshness plus mask plus credit with reserve,
 * so the loop keeps one call. Hard takes 64us while latency-critical
 * keeps zero, so reclaim agrees with admit. Tiers-empty heads with
 * positive laxity fall back without reserve while funded heads reserve
 * before the move, so zero credit never idles queued work. Aged heads
 * past one period pass even when tiers hold work. A stale key, a
 * foreign mask, or a lost reserve fails closed to the next candidate.
 *
 * Returns: true when the caller may move the candidate.
 *
 * Outlined with noinline to keep verifier headroom on the dispatch path.
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
	bool rcrit;
	bool funded;
	if (!rctx || !q)
		return false;
	rdl = READ_ONCE(rctx->deadline);
	ravg = (u64)READ_ONCE(rctx->avg_ns);
	rdev = (u64)READ_ONCE(rctx->dev_ns);
	{
		u32 rhint = READ_ONCE(rctx->hint_us);
		u32 rtw = READ_ONCE(rctx->weight);
		u32 rhw = READ_ONCE(rctx->hint_w);
		u32 reff;
		if (rtw == 0)
			rtw = (u32)FLOW_WEIGHT_BASE;
		reff = flow_task_effective_weight(rtw, rhw);
		/* Queue wait is not sleep, so the reclaim check passes zero */
		/* sleep with probation, while enqueue checks pass the true */
		/* gap read before the wait overwrite. */
		rcrit = flow_is_lat(ravg, rdev, rhint, 0, 0, reff);
	}
	rcost = flow_red_cost(ravg, READ_ONCE(rctx->slice_ns));
	/* Reclaim shares the fixed 64us tolerance with admit, so hard */
	/* takes 64us while latency-critical keeps zero. */
	rtol = flow_red_tol(rcrit);
	rres = flow_red_residual(rdl, now, rcost);
	rexc = flow_red_exceed(rres, rtol);
	rlax = flow_red_laxity(rdl, now, rcost);
	if (rlax == 0)
		return false;
	/* Aged cover past one period through the shared helper, so PRIQ */
	/* tiers never wait behind rejects past the age bound. */
	if (!tiers_empty &&
	    !flow_reclaim_is_aged(READ_ONCE(rctx->wait_at), now))
		return false;
	/* Key freshness through the shared helper, so an earlier key never */
	/* waits behind a rejoin with a stale key failing closed. */
	if (!flow_reclaim_key_ok(rctx, rdl, now))
		return false;
	if (!flow_mask_ok(cpu, q))
		return false;
	/* Aged heads still need funding, so continuous tier load never */
	/* drains rejects without credit with no overload bypass. */
	/* Tiers-empty heads with positive laxity fall back without reserve, */
	/* so zero credit never idles queued work. */
	funded = flow_red_reclaim_ok(credit, rexc, rlax);
	if (!tiers_empty && !funded)
		return false;
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
 * @queued: saved reject depth, non-positive skips without a walk.
 * @tiers_empty: true when local plus node plus machine hold no work.
 *
 * Scans at most eight value ordered rejects with one RCU walk, so the
 * check stays cheap with no overload stall. Funded heads reserve credit
 * before the move with a recheck to the next candidate on a lost race,
 * while tiers-empty heads with positive laxity fall back without reserve
 * so zero credit never idles queued work. Aged heads past one period
 * reclaim when funded even while tiers hold work, so continuous tier
 * load still needs credit with no bypass. Non reclaimable, stale, and
 * foreign entries skip to the next candidate, so one bad head never
 * stalls the queue. The credit funds the retry without using head
 * state. The greatest value still wins among reclaimable entries.
 * Tiers-empty gating plus one move per pass plus the one period age
 * bound keep starvation capped and PRIQ tiers never wait behind
 * rejects past the age bound.
 *
 * Returns: one on move else zero.
 *
 * Outlined with noinline to keep verifier headroom on the dispatch path.
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
	/* Skip the walk when tiers hold work plus credit stays short of the */
	/* fixed 256us Emax through the shared helper, since aged heads */
	/* still need funding with no fallback. Tiers-empty keeps the walk */
	/* with no reserve, so zero credit never idles work. */
	if (flow_reclaim_early_skip(credit, tiers_empty))
		return 0;
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
	/* Read four depths once before the budget gate, so the perf check */
	/* at out reuses the same reads even when slots run out. Signed hints */
	/* keep empty at zero or below. The reject queue stays outside here, */
	/* so the pass pays four reads total. */
	{
		s32 lq0 = scx_bpf_dsq_nr_queued(own_local);
		s32 lo0 = scx_bpf_dsq_nr_queued((u64)SCX_DSQ_LOCAL_ON |
		    (u64)(u32)cpu);
		s32 nq0 = scx_bpf_dsq_nr_queued(node_dsq);
		s32 mq0 = scx_bpf_dsq_nr_queued(machine_dsq);
		if (unlikely(budget == 0))
			goto out_hint;
		left = budget;
	/* Queue depths read once. Each tier move threads its hint through */
	/* the shared hint move, so empty tiers skip the RCU scan without a */
	/* visit cost. The same hints feed the steal early exit and the perf */
	/* check, so the pass pays four queue reads total. A stale hint only */
	/* repeats or skips a pass, since the shared hint move rechecks under */
	/* RCU with the same visit cap. Signed hints keep empty at zero or */
	/* below. */
	{
		bool q1_only = lq0 > 0 && nq0 <= 0 && mq0 <= 0;
		/* Q1 only fast path drains the local tier alone. The common */
		/* single queue pass skips two empty moves plus the steal */
		/* backlog with the same order plus the same counts. Uses */
		/* the saved hint without polling again. */
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
		/* Reject queue stays outside dispatch. A reject rejoins a PRIQ */
		/* tier only on reclaim with the same key or a strictly after */
		/* key, so strict order holds. Like fair.c, the earliest key */
		/* wins, unlike rt.c, no fixed priority holds. */
		/* Reclaim one value ordered reject with tiers-empty plus aged cover. */
		/* Tiers-empty heads fall back without reserve so zero credit */
		/* never idles queued work, while aged heads past one period */
		/* reclaim even when tiers hold work so the reject queue keeps */
		/* draining. The clock reads only here, and a stale hint only */
		/* repeats or skips a pass. */
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
		/* Steal tier last with a capped 4 to 8 peer window with saturation. */
		/* Only steals when tiers drained, so busy passes skip cheap with */
		/* the saved hints. The window caps each pass while miss counts */
		/* pace every tier, so the lowest tier still turns. */
		/* Backlog sums the three queued PRIQ tiers (local plus node */
		/* plus machine) with saturation, so a huge depth clamps instead */
		/* of wrapping to idle. Narrow means empty peers skip without */
		/* RCU through the per peer hint in the shared steal, so the */
		/* effective scan stays small. */
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
				/* select, so the next steal starts fresh without a */
				/* hotspot. Races keep no atomic order beyond the */
				/* single store. */
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
	/* Perf check reuses the saved local plus local on plus node hints */
	/* without a kfunc, so the pass skips a second check on the busy */
	/* path. A stale read only shifts the level by one pass without */
	/* changing order. */
	flow_perf_update_hint(cpu, lq0, lo0, nq0);
	}
	return;
}
