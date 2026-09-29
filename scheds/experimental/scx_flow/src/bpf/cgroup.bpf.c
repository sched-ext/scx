// SPDX-License-Identifier: GPL-2.0
/*
 * Flat hierarchy ops.
 *
 * The flat view holds one period hint per id only, and no group or
 * pool shapes order. The table holds 4096 rows with no eviction, so
 * a full table misses to the default period with no stall. Init runs
 * sleepable with map create, the rest run without sleep with lookup
 * only. Moves carry the release plus the period plus the deadline
 * plus the runtime with no hint carry, so the next enqueue reads the
 * new hint. Weight sets the hint from a fixed table with no share
 * use. See intf.h for the hint helpers and enqueue.bpf.c for the
 * hint use.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
/* Init one flat hint row with zero period and no hint. */
/* Sleepable only, so map create runs here. A full table keeps the */
/* miss to the default period with no fail, so the update stays */
/* unchecked and init returns zero on purpose with no eviction. */
s32 BPF_STRUCT_OPS_SLEEPABLE(flow_cgroup_init, struct cgroup *cgrp,
	struct scx_cgroup_init_args *args)
{
	u64 id;
	struct flow_hint h = {};
	(void)args;
	if (!cgrp)
		return -EINVAL;
	id = flow_cgrp_id(cgrp);
	if (!id)
		return -EINVAL;
	bpf_map_update_elem(&hint_stor, &id, &h, BPF_ANY);
	return 0;
}
/* Exit one flat hint row. */
/* Deletes the row, so later lookups miss to the default period. */
void BPF_STRUCT_OPS(flow_cgroup_exit, struct cgroup *cgrp)
{
	u64 id;
	if (!cgrp)
		return;
	id = flow_cgrp_id(cgrp);
	if (!id)
		return;
	bpf_map_delete_elem(&hint_stor, &id);
}
/* Prepare one flat move with no alloc and no fail. */
/* Always passes, so the move pairs one to one. */
s32 BPF_STRUCT_OPS(flow_cgroup_prep_move, struct task_struct *p,
	struct cgroup *from, struct cgroup *to)
{
	(void)p;
	(void)from;
	(void)to;
	return 0;
}
/* Commit one flat move with release plus deadline plus runtime carry. */
/* The release plus the period plus the deadline plus the runtime */
/* stay, so order survives the move. The hint stays per id with no */
/* carry, so the next enqueue reads the new hint with no id read here. */
void BPF_STRUCT_OPS(flow_cgroup_move, struct task_struct *p,
	struct cgroup *from, struct cgroup *to)
{
	(void)from;
	(void)p;
	if (!to)
		return;
}
/* Cancel one flat move with no state change. */
/* Preparation holds no state, so cancel stays empty. */
void BPF_STRUCT_OPS(flow_cgroup_cancel_move, struct task_struct *p,
	struct cgroup *from, struct cgroup *to)
{
	(void)p;
	(void)from;
	(void)to;
}
/* Update one flat hint from the share with a fixed table. */
/* Light shares map to long periods and heavy shares map to short */
/* periods, so the hint tunes admission with no share use. Creates */
/* the row on miss, so later reads see the new hint at once. A full */
/* table keeps the miss to the default period with no eviction. */
void BPF_STRUCT_OPS(flow_cgroup_set_weight, struct cgroup *cgrp,
	u32 weight)
{
	u64 id;
	u32 w;
	struct flow_hint h = {};
	if (!cgrp)
		return;
	id = flow_cgrp_id(cgrp);
	if (!id)
		return;
	w = flow_weight_clamp(weight);
	if (w < 64)
		h.period_us = 32000;
	else if (w < 128)
		h.period_us = 16000;
	else if (w < 512)
		h.period_us = 8000;
	else
		h.period_us = 4000;
	if (bpf_map_update_elem(&hint_stor, &id, &h, BPF_ANY) < 0)
		return;
}
