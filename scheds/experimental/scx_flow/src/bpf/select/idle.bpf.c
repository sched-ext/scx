// SPDX-License-Identifier: GPL-2.0
/*
 * Select idle plus pinned probes for the flow scheduler.
 *
 * Holds the pinned pick plus the idle-first probe for the select pass.
 * Pinned tasks stay where the mask allows with no scan, and every
 * other arrival tries the waker when idle else the kernel idle pick
 * with no state cost. An empty mask falls through to the machine tier
 * at the caller. Runs under the caller with no lock.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
/**
 * flow_select_pinned_cpu - pick one CPU for a pinned task.
 * @p: pinned task, stays where the mask allows with no scan.
 * @prev_cpu: previous CPU for the fallback when live plus allowed.
 *
 * Takes the task CPU when live plus allowed, else the previous CPU
 * when live plus allowed, else the first allowed CPU when live, else
 * counts one gate reject and falls back to the previous CPU. Covers
 * both migration disabled plus single allowed with the same order.
 *
 * Returns: picked CPU or @prev_cpu on fallback with gate count.
 *
 * Outlined with noinline to keep verifier headroom on the select path
 * with no order change.
 */
static __noinline s32 flow_select_pinned_cpu(struct task_struct *p,
	s32 prev_cpu)
{
	s32 here = scx_bpf_task_cpu(p);
	s32 first;
	if (flow_cpu_ok(p, here))
		return here;
	if (flow_cpu_ok(p, prev_cpu))
		return prev_cpu;
	first = (s32)bpf_cpumask_first(p->cpus_ptr);
	if (flow_cpu_ok(p, first))
		return first;
	flow_gate_reject();
	return prev_cpu;
}
/**
 * flow_select_idle_probe - probe the idle-first CPUs for one task.
 * @p: task to place.
 * @this_cpu: waker CPU tried first when idle plus allowed.
 *
 * Takes the waker when live plus allowed plus idle with no state cost,
 * else the kernel idle pick when live plus allowed, else negative with
 * no scan, so the caller falls through to the deadline plus scan pass.
 *
 * Returns: picked CPU or negative when no idle CPU meets.
 *
 * Outlined with noinline to keep verifier headroom on the select path
 * with no order change.
 */
static __noinline s32 flow_select_idle_probe(struct task_struct *p,
	s32 this_cpu)
{
	struct flow_cpu_state *wst;
	s32 picked;
	if (likely(flow_cpu_ok(p, this_cpu))) {
		wst = flow_cpu((u32)this_cpu);
		if (wst && READ_ONCE(wst->running_pid) == 0)
			return this_cpu;
	}
	picked = scx_bpf_pick_idle_cpu(p->cpus_ptr, 0);
	if (picked >= 0 && flow_cpu_ok(p, picked))
		return picked;
	return -1;
}
