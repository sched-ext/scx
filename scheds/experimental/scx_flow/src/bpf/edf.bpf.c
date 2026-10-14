// SPDX-License-Identifier: GPL-2.0
/*
 * EDF deadline plus eligibility plus drain for the core.
 *
 * Holds the burst predictor, the absolute deadline, the fair
 * key, and the eligibility gate. Every task earns a deadline from the
 * predictor else the hint period, and queue order uses the earlier of
 * deadline plus virtual deadline with a 2ms lag bound. Eligibility
 * gates every kick, so hogs pace while lagging tasks wake. Drain sums
 * local plus node with saturation, so a busy node keeps the local tier
 * without waiting. Depths read once feed the same drain, so enqueue
 * bypass and tier escalation share one read. Runs under the caller.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
/* True when one task still meets its deadline from the given time. */
/* A zero deadline means no order yet, so the check passes with no */
/* miss. A time past the deadline fails, so the caller rejoins a tier. */
static __always_inline bool flow_deadline_ok(u64 deadline,
	u64 now)
{
	if (deadline == 0)
		return true;
	if (flow_time_before(now, deadline))
		return true;
	if (now == deadline)
		return true;
	return false;
}
/* Drain depth of one CPU as queued slices times the quantum. */
/* Saturates on wrap, so a huge depth clamps instead of wrapping to */
/* an idle view. A bad read drops to zero with no boost. */
static __always_inline u64 flow_drain_ns(u64 dsq)
{
	s32 n = scx_bpf_dsq_nr_queued(dsq);
	u64 depth;
	if (n <= 0)
		return 0;
	depth = (u64)n;
	if (depth > (u64)~0ULL / (u64)FLOW_QUANTUM_NS)
		return (u64)~0ULL;
	return depth * (u64)FLOW_QUANTUM_NS;
}
/* Drain nanos from a saved queued hint without a kfunc. */
/* Non-positive hints read zero with no boost. Saturates on wrap, so a */
/* huge depth clamps instead of wrapping to an idle view. */
static __always_inline u64 flow_drain_from_q(s32 n)
{
	u64 depth;
	if (n <= 0)
		return 0;
	depth = (u64)n;
	if (depth > (u64)~0ULL / (u64)FLOW_QUANTUM_NS)
		return (u64)~0ULL;
	return depth * (u64)FLOW_QUANTUM_NS;
}
/**
 * flow_cpu_drain_hint - combined drain from saved local plus node.
 * @local_q: saved own local depth, non-positive means empty.
 * @node_q: saved node depth, non-positive means empty.
 *
 * Sums both drains with saturation and no kfunc, so a busy node holds
 * the local tier with no wait on the same reads as the bypass gate.
 *
 * Returns: combined drain in nanos.
 */
static __always_inline u64 flow_cpu_drain_hint(s32 local_q, s32 node_q)
{
	return flow_sat_add(flow_drain_from_q(local_q),
	    flow_drain_from_q(node_q));
}
/**
 * flow_cpu_drain - combined drain of one CPU as local plus node.
 * @cpu: CPU id below the 1024 bound.
 *
 * Sums both depths with saturation, so a busy node holds the local
 * tier with no wait. A missing node reads zero with no boost, and
 * sparse nodes fold to zero.
 *
 * Outlined with noinline to keep verifier headroom and callers in meets
 * plus fair plus BSF share one copy with no inline growth.
 *
 * Returns: combined drain in nanos.
 */
static __noinline u64 flow_cpu_drain(u32 cpu)
{
	u64 local = flow_drain_ns(flow_local_dsq(cpu));
	u32 node = flow_cpu_node((u32)cpu);
	u64 shared = 0;
	if (node < (u32)FLOW_MAX_NODES &&
	    (u64)node < nr_node_ids)
		shared = flow_drain_ns(flow_node_dsq(node));
	return flow_sat_add(local, shared);
}
/**
 * flow_ready_before - test ready time against deadline with wrap safety.
 * @ready: ready time in nanos, max fails closed.
 * @deadline: absolute deadline in nanos.
 *
 * Fails closed on saturated ready, else wrap safe before plus equal,
 * so a huge drain never reads as early with no wrap to the front.
 *
 * Outlined with noinline to share one compare copy across drain plus
 * deadline checks with no inline growth and no order change.
 *
 * Returns: true when @ready falls before or on @deadline.
 */
static __noinline bool flow_ready_before(u64 ready, u64 deadline)
{
	if (ready == (u64)~0ULL)
		return false;
	if (flow_time_before(ready, deadline))
		return true;
	if (ready == deadline)
		return true;
	return false;
}
/**
 * flow_cpu_meets - test deadline against one CPU drain.
 * @cpu: CPU id below the 1024 bound.
 * @deadline: absolute deadline, zero meets all.
 * @now: current time in nanos.
 *
 * Adds now plus the combined local plus node drain with saturation,
 * so a huge drain fails closed with no wrap to an early view. The
 * drain poll plus the compare split across two noinline calls, so the
 * SSF plus BSF loops share one copy each with no inline growth.
 *
 * Outlined with noinline to keep verifier headroom on the select path
 * with no order change.
 *
 * Returns: true when the drain finishes before @deadline.
 */
static __noinline bool flow_cpu_meets(u32 cpu,
	u64 deadline, u64 now)
{
	u64 drain;
	u64 ready;
	if (deadline == 0)
		return true;
	drain = flow_cpu_drain(cpu);
	ready = flow_sat_add(now, drain);
	return flow_ready_before(ready, deadline);
}
/**
 * flow_cpu_meets_fair_hint - test fair time against saved drain.
 * @local_q: saved own local depth, non-positive means empty.
 * @node_q: saved node depth, non-positive means empty.
 * @vtime: fair time, zero meets all.
 * @now: current time in nanos.
 *
 * Mirrors the drain check for the fair key without a kfunc, so the bypass
 * plus the tier choice share one read with the same order. A zero fair
 * time means no fair order yet, so the check passes.
 *
 * Returns: true when the drain finishes before @vtime.
 */
static __always_inline bool flow_cpu_meets_fair_hint(s32 local_q,
	s32 node_q, u64 vtime, u64 now)
{
	u64 drain;
	u64 ready;
	if (vtime == 0)
		return true;
	drain = flow_cpu_drain_hint(local_q, node_q);
	ready = flow_sat_add(now, drain);
	return flow_ready_before(ready, vtime);
}
/*
 * RED guarantee core for the flow scheduler.
 *
 * Holds the residual and exceeding time with fixed tolerance used
 * only for the guarantee. The deadline bounds the check without
 * shaping vruntime. A newcomer with zero exceed passes at once, else
 * the newcomer itself is tested as the O(1) victim with cost past the
 * fixed 256us Emax plus cost past the exceed plus never critical, else
 * the newcomer admits. A full least value scan stays a noted
 * alternative, so the verifier keeps one pass. Newcomer-pays trades
 * exact victim choice for a single check with tiers-empty reclaim
 * covering starvation below. The reject queue stays value ordered
 * outside dispatch, and a global saved credit at or past the fixed
 * 256us Emax reclaims one head with positive laxity. Runs under the
 * caller without a lock here, so the verifier stays small.
 */
/**
 * flow_red_gate - shared victim gate for one newcomer cost.
 * @cost: remaining worst cost in nanos from burst else slice.
 * @exceed: newcomer exceeding time in nanos, zero admits at once.
 * @emax: fixed Emax in nanos at 256us.
 * @is_crit: true marks latency-critical that never rejects.
 * @deadline: newcomer absolute deadline, zero admits at once.
 *
 * Checks cost past Emax plus cost past exceed with no critical, so the
 * newcomer itself covers the overload as the O(1) victim. A full least
 * value scan stays a noted alternative with no verifier growth.
 *
 * Returns: true when the newcomer should reject, else false.
 */
static __always_inline bool flow_red_gate(u64 cost, u64 exceed, u64 emax,
	bool is_crit, u64 deadline)
{
	if (exceed == 0)
		return false;
	if (is_crit)
		return false;
	if (deadline == 0)
		return false;
	if (cost <= emax)
		return false;
	if (cost <= exceed)
		return false;
	return true;
}
/**
 * flow_red_should_reject - test one newcomer for RED reject.
 * @deadline: newcomer absolute deadline in nanos.
 * @now: current time in nanos.
 * @avg: burst average in nanos, zero for no history.
 * @slice: stored slice in nanos, zero for no history.
 * @is_crit: true marks latency-critical via the unified latency test
 * with zero tolerance, false for hard batch.
 *
 * Costs burst else slice else quantum once, tolerates the fixed 64us
 * for hard batch only, then shares the gate below. Latency-critical
 * keeps zero with no slack. Like fair.c, the bound paces order, unlike
 * rt.c, no fixed priority holds.
 *
 * Outlined with noinline to keep verifier headroom with one shared
 * copy, so miss plus open plus pinned share one read with no inline
 * growth.
 *
 * Returns: true when the newcomer should reject to the value ordered
 * queue, else false for admit.
 */
static __noinline bool flow_red_should_reject(u64 deadline, u64 now,
	u64 avg, u32 slice, bool is_crit)
{
	u64 cost = flow_red_cost(avg, slice);
	u64 tol = flow_red_tol(is_crit);
	u64 emax = (u64)FLOW_RED_EMAX_NS;
	s64 resid = flow_red_residual(deadline, now, cost);
	u64 exceed = flow_red_exceed(resid, tol);
	/* Newcomer tests itself, so the deadline order holds with no */
	/* before check past equality. Shares the gate with reclaim, so */
	/* both agree with one copy. */
	return flow_red_gate(cost, exceed, emax, is_crit, deadline);
}
/**
 * flow_red_reclaim_ok - test reclaim from one global credit.
 * @saved: global completer credit in nanos from completions.
 * @exceed: head exceeding time in nanos.
 * @laxity: head laxity in nanos, zero means no room.
 *
 * Reclaims when the global credit passes the fixed 256us Emax and
 * covers the head exceed with positive laxity. The global credit funds
 * the retry without shaping shares.
 *
 * Returns: true when the head may rejoin.
 */
static __always_inline bool flow_red_reclaim_ok(u64 saved, u64 exceed,
	u64 laxity)
{
	u64 emax = (u64)FLOW_RED_EMAX_NS;
	if (saved < emax)
		return false;
	if (laxity == 0)
		return false;
	if (saved < exceed)
		return false;
	return true;
}
/* Global reclaim credit from completer saved deltas. */
/* Stopping adds the unused cost minus delta on completions with */
/* saturation at 1s, so one completion funds a later retry without */
/* keeping a task pointer. Dispatch peeks this credit for the head check */
/* and reserves the exceed else the fixed 256us Emax before a move, so the */
/* completer delta funds the retry without using head state. Compare and */
/* swap retries stop at four, so a lost race only delays one pass. */
/* Add one saved delta to the global reclaim credit with saturation. */
static __always_inline void flow_credit_add(u64 delta)
{
	u32 key = 0;
	u64 *slot;
	s32 i;
	if (delta == 0)
		return;
	slot = bpf_map_lookup_elem(&reclaim_credit_stor, &key);
	if (!slot)
		return;
	bpf_for(i, 0, 4) {
		u64 cur = READ_ONCE(*slot);
		u64 nxt = flow_sat_add(cur, delta);
		u64 old;
		if (nxt > (u64)FLOW_PRED_MAX_NS)
			nxt = (u64)FLOW_PRED_MAX_NS;
		old = __sync_val_compare_and_swap(slot, cur, nxt);
		if (old == cur)
			break;
	}
}
/* Peek the global reclaim credit with zero on miss. */
static __always_inline u64 flow_credit_peek(void)
{
	u32 key = 0;
	u64 *slot = bpf_map_lookup_elem(&reclaim_credit_stor, &key);
	if (!slot)
		return 0;
	return READ_ONCE(*slot);
}
/* Consume one reclaim funding with floor at zero. */
/* Takes the exceed when past zero else the fixed 256us Emax, so a zero */
/* exceed still spends the bound. Fails closed when short without */
/* spending, so a lost compare and swap race retries up to four times */
/* then delays one pass. The reclaim caller reserves before the move and */
/* falls back without reserve when tiers hold no work, so the consume */
/* stays strict while the reclaim keeps one move per pass. */
static __always_inline bool flow_credit_consume(u64 exceed)
{
	u32 key = 0;
	u64 *slot = bpf_map_lookup_elem(&reclaim_credit_stor, &key);
	s32 i;
	u64 emax = (u64)FLOW_RED_EMAX_NS;
	if (!slot)
		return false;
	bpf_for(i, 0, 4) {
		u64 cur = READ_ONCE(*slot);
		u64 need = exceed ? exceed : emax;
		u64 nxt;
		u64 old;
		if (cur < need)
			return false;
		if (cur < emax)
			return false;
		nxt = cur - need;
		old = __sync_val_compare_and_swap(slot, cur, nxt);
		if (old == cur)
			return true;
	}
	return false;
}
