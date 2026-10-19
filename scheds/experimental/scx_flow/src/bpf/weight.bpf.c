// SPDX-License-Identifier: GPL-2.0
/*
 * Task weight for the core.
 *
 * Holds the per task base share plus the nice table plus the fair
 * delta scaler. The nice table maps nice minus 20 to 19 into weights
 * centred at 128 for nice zero with powers near two, so light nices
 * earn small shares while heavy nices earn large shares with no walk.
 * The fair delta scales service inversely with weight through one
 * divide, so heavy tasks advance slowly while light tasks advance
 * quickly with no band jump. A zero input maps to the lightest share
 * while missing state stays neutral via the effective helper.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
/* Nice weight table for nice minus 20 to 19. Index 20 holds nice zero */
/* at 128 with kernel ratios scaled by eight, so the full span covers */
/* 1 to 11095 within the 1 to 16384 bound with no divide at lookup. */
static const u32 flow_nice_weight[40] = {
	11095U, 8969U, 7060U, 5784U, 4536U, 3644U, 2906U, 2338U,
	1868U, 1489U, 1193U, 952U, 762U, 613U, 488U, 390U,
	312U, 248U, 198U, 159U, 128U, 102U, 81U, 65U,
	52U, 41U, 34U, 26U, 21U, 17U, 13U, 10U,
	8U, 7U, 5U, 4U, 3U, 2U, 2U, 1U
};
/**
 * flow_nice_to_weight - weight for one nice value.
 * @nice: nice from minus 20 to 19, clamped into range.
 *
 * Returns: weight from the table with no divide.
 */
static __always_inline u32 flow_nice_to_weight(s32 nice)
{
	u32 idx;
	if (nice < -20)
		nice = -20;
	if (nice > 19)
		nice = 19;
	idx = (u32)(nice + 20);
	if (idx >= 40U)
		idx = 20U;
	return flow_nice_weight[idx];
}
/**
 * flow_calc_delta_fair - scaled service for one delta at one weight.
 * @delta: raw service in nanos.
 * @weight: scheduling share, clamped to range.
 *
 * Scales inversely with weight through one divide, so the neutral
 * weight of 128 keeps the delta unchanged while lighter tasks grow
 * and heavier tasks shrink with no band jump. A zero weight maps to
 * the floor, so an explicit zero earns the lightest share. A zero
 * delta stays zero with no floor, so idle charges nothing. A nonzero
 * delta that scales to zero rises to one, so every service step moves
 * the ledger forward with no stall. A huge product saturates instead
 * of wrapping to a short charge.
 *
 * Returns: scaled service in nanos.
 */
static __always_inline u64 flow_calc_delta_fair(u64 delta, u32 weight)
{
	return flow_scaled_delta(delta, weight);
}
/**
 * flow_set_weight - store one task base share with clamp.
 * @p: task to reweight, null fails closed.
 * @weight: raw share, clamped to range with zero mapping to 1.
 *
 * Stores the clamped base in task state with no hint use, so later
 * enqueues stack the effective share with the stored flat hint. A
 * zero input stores 1 for the lightest share with no neutral. A
 * missing task state fails closed with no create and no stall.
 */
void BPF_STRUCT_OPS(flow_set_weight, struct task_struct *p,
	u32 weight)
{
	struct flow_task_ctx *tctx;
	u32 w;
	if (!p)
		return;
	tctx = flow_lookup(p);
	if (!tctx)
		return;
	w = flow_weight_clamp(weight);
	__sync_lock_test_and_set(&tctx->weight, w);
}
