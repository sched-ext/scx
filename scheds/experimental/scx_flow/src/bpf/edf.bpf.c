// SPDX-License-Identifier: GPL-2.0
/*
 * EDF deadline plus eligibility plus hoisted drain for the core.
 *
 * Holds the burst predictor plus the absolute deadline plus the fair
 * key plus the eligibility gate. Every task earns a deadline from the
 * predictor else the hint period, and queue order uses the earlier of
 * deadline plus virtual deadline with a 2ms lag bound. Eligibility
 * gates every kick, so hogs pace while lagging tasks wake. Drain sums
 * local plus node with saturation, so a busy node holds the local tier
 * with no wait. Hoisted depths feed the same drain with no second poll,
 * so enqueue bypass plus tier escalation share one read. Runs under the
 * caller with no lock.
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
/* Drain nanos from a hoisted queued hint with no kfunc. */
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
 * flow_cpu_drain_hint - combined drain from hoisted local plus node.
 * @local_q: hoisted own local depth, non-positive means empty.
 * @node_q: hoisted node depth, non-positive means empty.
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
 * flow_cpu_meets_hint - test deadline against hoisted combined drain.
 * @local_q: hoisted own local depth, non-positive means empty.
 * @node_q: hoisted node depth, non-positive means empty.
 * @deadline: absolute deadline, zero meets all.
 * @now: current time in nanos.
 *
 * Adds now plus the hoisted combined drain with saturation and no
 * kfunc, so placement checks share the enqueue reads with no wrap to
 * an early view.
 *
 * Returns: true when the drain finishes before @deadline.
 */
static __always_inline bool flow_cpu_meets_hint(s32 local_q, s32 node_q,
	u64 deadline, u64 now)
{
	u64 drain;
	u64 ready;
	if (deadline == 0)
		return true;
	drain = flow_cpu_drain_hint(local_q, node_q);
	ready = flow_sat_add(now, drain);
	return flow_ready_before(ready, deadline);
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
 * flow_cpu_meets_fair_hint - test fair time against hoisted drain.
 * @local_q: hoisted own local depth, non-positive means empty.
 * @node_q: hoisted node depth, non-positive means empty.
 * @vtime: fair time, zero meets all.
 * @now: current time in nanos.
 *
 * Mirrors the drain check for the fair key with no kfunc, so the bypass
 * plus the tier choice share one hoist with the same order. A zero fair
 * time means no fair order yet, so the check passes with no gate.
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
 * Holds the residual plus exceeding time with tolerance used
 * only for the guarantee. The deadline bounds the check with no
 * vruntime shaping. A newcomer with zero exceed
 * passes at once, else the newcomer itself is tested as the bounded
 * O(1) victim with cost past the exceed plus deadline at or before
 * itself plus never critical, else the newcomer admits. A full least
 * value scan stays a noted alternative with no knob here, so the
 * verifier keeps one pass with no walk. Newcomer-pays trades exact
 * victim choice for bounded admission with starvation bounded by the
 * tiers-empty reclaim below. The reject queue stays value
 * ordered outside dispatch, and a global saved credit at or past 128us
 * reclaims one head with positive laxity. Runs under the caller with
 * no lock and no RCU walk here, so the verifier stays small.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
/**
 * flow_red_newcomer_exceed - exceeding time of one newcomer.
 * @deadline: newcomer absolute deadline in nanos.
 * @now: current time in nanos.
 * @avg: burst average in nanos, zero for no history.
 * @slice: stored slice in nanos, zero for no history.
 * @is_crit: true marks critical with zero tolerance.
 *
 * Costs burst else slice else quantum, tolerates 64us for hard only,
 * then residuals deadline minus now minus cost with wrap safety.
 * Tolerance aids only the guarantee with no order shaping.
 *
 * Returns: exceeding time in nanos, zero when guaranteed.
 */
static __always_inline u64 flow_red_newcomer_exceed(u64 deadline,
	u64 now, u64 avg, u32 slice, bool is_crit)
{
	u64 cost = flow_red_cost(avg, slice);
	u64 tol = flow_red_tol(is_crit);
	s64 resid = flow_red_residual(deadline, now, cost);
	return flow_red_exceed(resid, tol);
}
/**
 * flow_red_victim_ok - test one victim for one exceed.
 * @v_deadline: victim deadline in nanos, zero fails closed.
 * @n_deadline: newcomer deadline in nanos, zero fails closed.
 * @v_cost: victim remaining cost in nanos.
 * @exceed: newcomer exceeding time in nanos, zero fails closed.
 * @v_crit: true marks a critical victim that never rejects.
 *
 * Victim needs cost past 128us plus cost past the exceed plus deadline
 * at or before the newcomer, so only work ahead of the overload pays.
 * Callers test the newcomer itself as the bounded O(1) victim with no
 * scan, so a full least value scan stays a noted alternative with no
 * knob here. A critical victim never passes with no swap.
 *
 * Returns: true when the victim may cover the exceed.
 */
static __always_inline bool flow_red_victim_ok(u64 v_deadline,
	u64 n_deadline, u64 v_cost, u64 exceed, bool v_crit)
{
	if (exceed == 0)
		return false;
	if (v_crit)
		return false;
	if (v_deadline == 0 || n_deadline == 0)
		return false;
	if (v_cost <= (u64)FLOW_RED_EMAX_NS)
		return false;
	if (v_cost <= exceed)
		return false;
	if (flow_time_before(n_deadline, v_deadline))
		return false;
	return true;
}
/**
 * flow_red_reclaim_ok - test reclaim from one global credit.
 * @saved: global completer credit in nanos from completions.
 * @exceed: head exceeding time in nanos.
 * @laxity: head laxity in nanos, zero means no room.
 *
 * Reclaims when the global credit reaches past 128us plus covers the
 * head exceed with positive laxity with no scan here. The global credit
 * funds the retry with no share shaping.
 *
 * Returns: true when the head may rejoin.
 */
static __always_inline bool flow_red_reclaim_ok(u64 saved, u64 exceed,
	u64 laxity)
{
	if (saved < (u64)FLOW_RED_EMAX_NS)
		return false;
	if (laxity == 0)
		return false;
	if (saved < exceed)
		return false;
	return true;
}
/* Global reclaim credit from completer saved deltas with no knob. */
/* Stopping adds the unused cost minus delta on completions with */
/* saturation at 1s, so one completion funds a later retry with no */
/* task pointer. Dispatch peeks this credit for the head check and */
/* reserves the exceed else 128us before a move, so the completer delta */
/* funds the retry with no head state use. Compare and swap retries */
/* bound at four keep best effort races to a one pass delay with no loss. */
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
/* Takes the exceed when past zero else 128us, so a zero exceed still */
/* spends the bound with no free retry. Fails closed when short with no */
/* spend, so a lost compare and swap race retries up to four times then */
/* delays one pass. The reclaim caller reserves before the move and */
/* falls back without reserve when tiers hold no work, so the consume */
/* stays strict while the reclaim stays bounded at one move per pass. */
static __always_inline bool flow_credit_consume(u64 exceed)
{
	u32 key = 0;
	u64 *slot = bpf_map_lookup_elem(&reclaim_credit_stor, &key);
	s32 i;
	if (!slot)
		return false;
	bpf_for(i, 0, 4) {
		u64 cur = READ_ONCE(*slot);
		u64 need = exceed ? exceed : (u64)FLOW_RED_EMAX_NS;
		u64 nxt;
		u64 old;
		if (cur < need)
			return false;
		if (cur < (u64)FLOW_RED_EMAX_NS)
			return false;
		nxt = cur - need;
		old = __sync_val_compare_and_swap(slot, cur, nxt);
		if (old == cur)
			return true;
	}
	return false;
}
