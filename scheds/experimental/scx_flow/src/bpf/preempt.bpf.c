// SPDX-License-Identifier: GPL-2.0
/*
 * Preempt plus idle kick for the enqueue pass.
 *
 * Holds the strict one kick per wait rule with unified latency plus
 * lead plus tail plus eligibility. Only a latency arrival against a
 * batch occupant leads by the margin with more than the tail left on
 * the owner, so near ties plus nearly done owners never bounce while
 * one kick per wait stays with no storm. Lat to lat plus batch to
 * batch plus batch to lat fail closed with one skipped count.
 * Every hold counts in preempt skipped with no missing fill. The exiting
 * plus bypass plus tier idle plus preempt paths share this gate with no
 * extra sender. Runs under the
 * caller with no lock.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
/* True when one arrival strictly preempts with margin plus tail plus latency. */
/* The arrival key must lead the occupant key strictly with the margin also */
/* strictly before, so near ties never bounce. The owner must hold more */
/* than the tail past now from start plus inherit cur, so nearly done */
/* owners finish instead of taking a kick. Equality fails closed and */
/* floors, so a head with exactly the tail left never kicks. Only a latency arrival */
/* against a batch occupant preempts, so lat to batch wins while lat */
/* to lat plus batch to batch plus batch to lat fail closed with one */
/* skipped count and no kick. The enqueue busy path calls */
/* this helper after the eligibility gate, so eligibility stays outside */
/* here with one minimum read per wait. Equal arrivals pace with no */
/* extra kick by design, so no tie assert runs with no verifier cost. */
/* Mirrored in config.rs preempt_ok for host tests, so the kernel plus */
/* the host agree with no drift. */
static __always_inline bool flow_preempt_ok(u64 arr_key,
	u64 occ_key, u64 now, u64 occ_run_at, u32 occ_cur, bool arr_lat,
	bool occ_lat)
{
	u64 margin;
	u64 occ_end;
	u64 tail;
	u64 base;
	if (!arr_lat || occ_lat)
		return false;
	if (arr_key == 0 || arr_key == (u64)~0ULL)
		return false;
	if (occ_key == 0 || occ_key == (u64)~0ULL)
		return false;
	if (!flow_time_before(arr_key, occ_key))
		return false;
	margin = flow_sat_add(arr_key, (u64)FLOW_PREEMPT_MARGIN_NS);
	if (margin == (u64)~0ULL)
		return false;
	if (!flow_time_before(margin, occ_key))
		return false;
	if (occ_run_at == 0 || occ_run_at == (u64)~0ULL)
		return false;
	base = (u64)flow_slice_inherit(occ_cur);
	occ_end = flow_sat_add(occ_run_at, base);
	if (occ_end == (u64)~0ULL)
		return false;
	tail = flow_sat_add(now, (u64)FLOW_PREEMPT_TAIL_NS);
	if (tail == (u64)~0ULL)
		return false;
	if (!flow_time_before(tail, occ_end))
		return false;
	return true;
}
/* Kick one idle allowed CPU for tier waits with strict one kick at most. */
/* Tries the selected CPU first, then the kernel idle pick, then the */
/* first allowed live CPU. Kicks only when the target runs nothing, with */
/* the idle flag cleared first so the kick sticks. Never sends a preempt */
/* kick, so tier waits stay idle only. */
/* Factored per target probe keeps one copy with no triple growth. */
/**
 * flow_kick_one_if_idle - kick one CPU when idle plus eligible.
 * @p: task waiting for the kick.
 * @cpu: candidate CPU, negative fails closed.
 * @vr: arrival vruntime for the eligibility gate.
 * @lag: arrival lag bound for the eligibility gate.
 * @has_ctx: true when @vr plus @lag hold valid state.
 *
 * Outlined with noinline to keep verifier headroom and the three probes
 * share one eligibility plus kick copy with no inline growth.
 *
 * Returns: true when the kick took or an ineligible hold counted, so
 * the caller stops, else false to try the next candidate.
 */
static __noinline bool flow_kick_one_if_idle(
	const struct task_struct *p, s32 cpu, u64 vr, s32 lag, bool has_ctx)
{
	struct flow_cpu_state *st;
	if (!flow_cpu_ok(p, cpu))
		return false;
	st = flow_cpu((u32)cpu);
	if (!st || READ_ONCE(st->running_pid) != 0)
		return false;
	if (has_ctx &&
	    !flow_eligible(vr, READ_ONCE(st->min_vruntime), lag)) {
		flow_count_preempt_skip();
		return true;
	}
	scx_bpf_test_and_clear_cpu_idle(cpu);
	scx_bpf_kick_cpu(cpu, SCX_KICK_IDLE);
	flow_count_kick();
	return true;
}
static __noinline void flow_kick_idle_allowed(
	const struct task_struct *p, s32 sel)
{
	s32 idle;
	s32 first;
	struct flow_task_ctx *tctx;
	u64 vr = 0;
	s32 lag = 0;
	bool has_ctx = false;
	tctx = flow_lookup((struct task_struct *)p);
	if (tctx) {
		vr = READ_ONCE(tctx->vruntime);
		lag = READ_ONCE(tctx->vlag);
		has_ctx = true;
	}
	if (flow_kick_one_if_idle(p, sel, vr, lag, has_ctx))
		return;
	idle = scx_bpf_pick_idle_cpu(p->cpus_ptr, 0);
	if (flow_kick_one_if_idle(p, idle, vr, lag, has_ctx))
		return;
	first = (s32)bpf_cpumask_first(p->cpus_ptr);
	flow_kick_one_if_idle(p, first, vr, lag, has_ctx);
}
