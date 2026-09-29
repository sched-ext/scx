// SPDX-License-Identifier: GPL-2.0
/*
 * Charge and miss helpers for the core.
 *
 * Holds the leftover charge plus the miss count. Parks wake by direct
 * kick on insert with no timer wait, so no timer lives here. Each
 * helper stays noinline with scalar inputs, so the verifier stays
 * small.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
/* Charge one leftover run segment at most once with no scaling. */
/* Stopping owns the normal charge and clears the run start. */
/* Disable and exit funnel here only for a running task that */
/* stopping never saw. The start claims with a compare and swap, so */
/* stopping versus disable or exit charges once, and a failed claim */
/* means stopping won, so this pass drops with no double charge. */
/* The gauge drop follows the claim with no owner gate, the owner */
/* check gates the pid clear in the caller only, so a migrated stop */
/* still pairs. A backward clock charges zero time but still pairs */
/* the gauge. Runtime advances by scaled time with the task weight */
/* beside the raw charge. Outlined to keep disable and exit small. */
static __noinline void flow_charge_leftover(struct task_struct *p,
	struct flow_task_ctx *tctx, s32 cpu)
{
	u64 start;
	u64 now;
	u64 delta;
	u64 got;
	if (!tctx)
		return;
	(void)p;
	start = READ_ONCE(tctx->run_at);
	if (start == 0)
		return;
	now = flow_now();
	if (flow_time_before(now, start))
		delta = 0;
	else
		delta = now - start;
	got = __sync_val_compare_and_swap(&tctx->run_at,
	    start, 0);
	if (got != start)
		return;
	__sync_fetch_and_add(&flow_stats.total_runtime, delta);
	{
		u32 w = flow_weight_clamp(p->scx.weight);
		tctx->vruntime = flow_vruntime_advance(tctx->vruntime,
		    delta, w);
	}
	flow_on_cpu_dec();
}
/* Count one deadline miss with saturation plus one park. */
/* Misses clamp, so a huge miss count never wraps to zero. Parks */
/* count the same hits, so the wire shows misses plus parks together. */
static __noinline void flow_count_miss(
	struct flow_task_ctx *tctx)
{
	u32 m;
	if (!tctx)
		return;
	m = READ_ONCE(tctx->misses);
	if (m != 0xffffffffU)
		__sync_fetch_and_add(&tctx->misses, 1);
	__sync_fetch_and_add(&flow_stats.misses, 1);
	__sync_fetch_and_add(&flow_stats.parks, 1);
}
