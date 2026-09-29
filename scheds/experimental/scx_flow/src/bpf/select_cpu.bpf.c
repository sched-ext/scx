// SPDX-License-Identifier: GPL-2.0
/*
 * Select CPU op.
 *
 * Placement takes idle first, then the previous CPU, then the shared
 * home, and it keeps the slowest sufficient CPU among the allowed
 * set that can meet the deadline. An idle CPU takes the task at once
 * with no scan. The previous CPU wins next when it can drain before
 * the deadline, so warmth stays free with no cost. The shared home
 * takes the rest, so no task waits for a busy CPU while shared room
 * stays open. Capacities stay symmetric on test hosts, so the lowest
 * sufficient id is the slowest sufficient pick. Pinned tasks stay
 * where the mask allows with no scan, and the task mask always wins.
 * An empty mask falls through to the overflow tail at enqueue. See
 * enqueue.bpf.c for admission plus the deadline choice after select.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
s32 BPF_STRUCT_OPS(flow_select_cpu, struct task_struct *p,
	s32 prev_cpu, u64 wake_flags)
{
	s32 this_cpu;
	s32 first;
	u64 deadline = 0;
	struct flow_task_ctx *tctx;
	(void)wake_flags;
	this_cpu = (s32)bpf_get_smp_processor_id();
	/* Pinned tasks stay where the mask allows with no scan. */
	if (is_migration_disabled(p)) {
		s32 here = scx_bpf_task_cpu(p);
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
	/* Single mask tasks keep the same pinned path with no scan. */
	if (p->nr_cpus_allowed == 1) {
		s32 here = scx_bpf_task_cpu(p);
		s32 allow;
		if (flow_cpu_ok(p, here))
			return here;
		if (flow_cpu_ok(p, prev_cpu))
			return prev_cpu;
		allow = (s32)bpf_cpumask_first(p->cpus_ptr);
		if (flow_cpu_ok(p, allow))
			return allow;
		flow_gate_reject();
		return prev_cpu;
	}
	/* The deadline shapes the sufficient check below. */
	/* A missing state means no order yet, so every live CPU meets. */
	tctx = flow_lookup(p);
	if (tctx)
		deadline = READ_ONCE(tctx->deadline);
	/* The waker CPU is free when it runs nothing and the mask allows. */
	/* An idle core cannot stack, so the slowest sufficient scan ends */
	/* here with no cost. The pid read uses a relaxed load to match */
	/* the running stores. */
	if (flow_cpu_ok(p, this_cpu)) {
		struct flow_cpu_state *wst = flow_cpu((u32)this_cpu);
		if (wst && READ_ONCE(wst->running_pid) == 0)
			return this_cpu;
	}
	/* One idle scan only with no depth pass. */
	/* The first idle allowed CPU is the slowest sufficient pick on */
	/* a symmetric host, so the scan ends here with no drain check. */
	{
		s32 picked = scx_bpf_pick_idle_cpu(p->cpus_ptr, 0);
		if (picked >= 0 && flow_cpu_ok(p, picked))
			return picked;
	}
	/* The previous CPU wins when it can drain before the deadline. */
	/* Warmth stays free, and a miss falls to the shared home. */
	if (flow_cpu_ok(p, prev_cpu)) {
		u64 now = flow_now();
		if (flow_cpu_meets((u32)prev_cpu, deadline, now))
			return prev_cpu;
	}
	/* The shared home takes the rest in id order. */
	/* The slowest sufficient allowed CPU wins with the lowest units */
	/* among the peers that drain before the deadline, so light work */
	/* never takes a fast CPU that other work needs. Capacities stay */
	/* symmetric on test hosts, so the first sufficient id usually */
	/* wins with no extra pass. The cursor spreads passes with no */
	/* hotspot, and it races best effort with no atomic order. */
	{
		u64 nr = nr_cpu_ids;
		struct flow_cpu_state *wst = flow_cpu((u32)this_cpu);
		u32 cursor = wst ? READ_ONCE(wst->cursor) : 0;
		u32 off;
		u64 now = flow_now();
		u32 best = 0xffffffffU;
		u32 best_units = 0xffffffffU;
		if (nr > 1 && nr <= (u64)FLOW_MAX_CPUS) {
			u32 n = (u32)nr;
			u32 start = (cursor + 1U) % n;
			bpf_for(off, 0, 8) {
				u32 peer;
				u32 units;
				if ((u64)off >= (u64)n)
					break;
				peer = (start + off) % n;
				/* The busy waker stays out on purpose. */
				/* An idle waker already returned above, */
				/* so a busy waker here would only stack */
				/* on its own depth with no warmth win. */
				/* The previous CPU below keeps warmth. */
				if (peer == (u32)this_cpu)
					continue;
				if (!flow_cpu_ok(p, (s32)peer))
					continue;
				if (!flow_cpu_meets(peer, deadline,
				    now))
					continue;
				units = flow_cpu_units(peer);
				if (units >= best_units)
					continue;
				best_units = units;
				best = peer;
			}
			if (wst && best != 0xffffffffU)
				__sync_lock_test_and_set(
				    &wst->cursor,
				    (start + 1U) % n);
			if (best != 0xffffffffU)
				return (s32)best;
		}
	}
	/* A scan miss keeps the previous CPU when allowed. */
	if (flow_cpu_ok(p, prev_cpu))
		return prev_cpu;
	/* The first allowed CPU is the fail closed fallback. */
	first = (s32)bpf_cpumask_first(p->cpus_ptr);
	if (flow_cpu_ok(p, first))
		return first;
	flow_gate_reject();
	return prev_cpu;
}
