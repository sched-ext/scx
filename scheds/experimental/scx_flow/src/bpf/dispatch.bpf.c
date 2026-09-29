// SPDX-License-Identifier: GPL-2.0
/*
 * Dispatch op.
 *
 * Each pass moves one task per tier to local in fixed order across
 * local plus node plus machine plus overflow. One move per tier moves
 * four tasks at most with no shared math and no pre scan, and an
 * empty tier moves nothing with no scan. The overflow tail holds
 * homeless parks plus missed parks plus rejected parks plus pinned
 * tasks, and every park arrives with a direct kick and no wait, so no
 * timer wakes the pass. Per tier moves count once with no lock.
 * Level follows with the same CPU only. See intf.h for the batch and
 * enqueue.bpf.c for admission plus the deadline choice.
 *
 * The pass splits the tier moves into dispatch/drain plus perf with
 * no lock here. Each move stays noinline with a scalar input, so
 * the verifier stays small. Level follows with no call on steady.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
#include "dispatch/drain.bpf.c"
#include "dispatch/perf.bpf.c"

void BPF_STRUCT_OPS(flow_dispatch, s32 cpu,
	struct task_struct *prev)
{
	/* One move per tier moves four tasks at most with no stall. */
	/* Tiers take scalars only and verify once with no cross inline. */
	u32 local_moved = 0;
	u32 node_moved = 0;
	u32 machine_moved = 0;
	u32 over_moved = 0;
	u64 own_local;
	u32 node;

	(void)prev;
	/* A negative CPU is a core idle call with no queue work, so it */
	/* returns with no gate count. A stale live CPU fails closed with */
	/* one count below, so only real rejects count. */
	if (cpu < 0)
		return;
	if (!flow_cpu_live((u32)cpu)) {
		flow_gate_reject();
		return;
	}
	own_local = flow_local_dsq((u32)cpu);
	node = flow_cpu_node((u32)cpu);
	/* Fold past the derived count to zero like enqueue, so the node */
	/* turn always names a created queue with no stale id. */
	if (node >= (u32)FLOW_MAX_NODES ||
	    (u64)node >= nr_node_ids)
		node = 0;
	/* Local tier first with one move and no scan on empty. */
	local_moved = flow_move_one(own_local);
	/* Node tier next with one move and no scan on empty. */
	node_moved = flow_move_one(flow_node_dsq(node));
	/* Machine tier next with one move and no scan on empty. */
	machine_moved = flow_move_one(flow_machine_dsq());
	/* Overflow tail last with one move and no scan on empty. */
	/* Homeless parks move here with all other parks, so the kernel */
	/* global queue stays out of the pass. */
	over_moved = flow_move_one(flow_overflow_dsq());
	/* Level follows with the same CPU only. */
	flow_perf_update(cpu);
	if (local_moved != 0)
		__sync_fetch_and_add(&flow_stats.local_moves,
		    (u64)local_moved);
	if (node_moved != 0)
		__sync_fetch_and_add(&flow_stats.node_moves,
		    (u64)node_moved);
	if (machine_moved != 0)
		__sync_fetch_and_add(&flow_stats.machine_moves,
		    (u64)machine_moved);
	if (over_moved != 0)
		__sync_fetch_and_add(&flow_stats.over_moves,
		    (u64)over_moved);
}
