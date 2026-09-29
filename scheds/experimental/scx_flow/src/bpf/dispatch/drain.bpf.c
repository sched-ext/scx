// SPDX-License-Identifier: GPL-2.0
/*
 * Tier moves for the dispatch pass.
 *
 * Moves one queued task to local with no iterator and no per task
 * lookup. Each tier calls once in fixed order, and an empty queue
 * moves nothing with no scan. The kernel picks the queue head, so
 * deadline order holds on the ordered queues and arrival order holds
 * on the overflow tail. Homeless parks rest in overflow with all
 * other parks, so no trip touches the kernel global queue. Fresh
 * parks join the same order at once with no hold. Runs under the
 * caller with no lock.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
/* Move one queued task to local with no gate. */
/* Takes a queue id scalar with no struct pass, so every tier verifies */
/* through this one call. The live check in the caller covers the CPU, */
/* and the kernel holds queue order, so an empty queue returns zero */
/* with no scan and no miss count. */
static __noinline u32 flow_move_one(u64 dsq)
{
	if (scx_bpf_dsq_move_to_local(dsq, 0))
		return 1;
	return 0;
}
