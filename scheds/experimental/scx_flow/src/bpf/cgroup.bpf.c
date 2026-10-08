// SPDX-License-Identifier: GPL-2.0
/*
 * Admission gate plus flat hierarchy for the core.
 *
 * The gate runs first in every op, so stale CPUs plus moved tasks plus
 * stale queues fail closed with one counter and no charge. The flat
 * view holds one period plus weight hint per id with single weighting
 * through one shared band helper, and no group or pool shapes order.
 * The table holds 8192 rows with no eviction, so a full table misses
 * to defaults with no stall. Id zero scopes to defaults with no row.
 * A zero cached id is the stale sentinel with miss to the acquire path.
 * Moves carry vruntime plus deadline with no hint carry, so the next
 * enqueue reads the new hint after the move invalidate clears the id.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
/* True when the id is a live CPU below nr and the bound. */
static __always_inline bool flow_cpu_live(u32 cpu)
{
	if (unlikely((u64)cpu >= nr_cpu_ids))
		return false;
	if (unlikely((u64)cpu >= (u64)FLOW_MAX_CPUS))
		return false;
	return true;
}
/* True when the CPU is live and inside the task mask. */
static __always_inline bool flow_cpu_ok(
	const struct task_struct *p, s32 cpu)
{
	if (unlikely(cpu < 0))
		return false;
	if (unlikely((u64)cpu >= nr_cpu_ids))
		return false;
	if (unlikely((u64)cpu >= (u64)FLOW_MAX_CPUS))
		return false;
	return bpf_cpumask_test_cpu((u32)cpu, p->cpus_ptr);
}
/* True when one task may enter an op on the given CPU. */
static __always_inline bool flow_entry_ok(s32 cpu,
	const struct task_struct *p, u64 dsq)
{
	if (unlikely(!p))
		return false;
	if (unlikely(cpu >= 0 && !flow_cpu_live((u32)cpu)))
		return false;
	if (unlikely(cpu >= 0 && !bpf_cpumask_test_cpu((u32)cpu,
	    p->cpus_ptr)))
		return false;
	if (unlikely(dsq && !flow_dsq_valid(dsq)))
		return false;
	return true;
}
/* Id of one hierarchy with root at one on missing. */
static __always_inline u64 flow_cgrp_id(struct cgroup *cgrp)
{
	struct kernfs_node *kn;
	u64 id;
	if (!cgrp)
		return 1;
	kn = BPF_CORE_READ(cgrp, kn);
	if (!kn)
		return 1;
	id = BPF_CORE_READ(kn, id);
	if (!id)
		return 1;
	return id;
}
/* Clear one cached hierarchy id for a pid with no fail. */
static __always_inline void flow_cgrp_cache_invalidate(u32 pid)
{
	if (!pid)
		return;
	bpf_map_delete_elem(&cgrp_cache_stor, &pid);
}
/* Acquired hierarchy of one task with paired release. */
static __always_inline struct cgroup *flow_task_cgrp(
	struct task_struct *p)
{
	return scx_bpf_task_cgroup(p);
}
/* Release one acquired hierarchy with null tolerance. */
static __always_inline void flow_cgrp_put(struct cgroup *cgrp)
{
	if (cgrp)
		bpf_cgroup_release(cgrp);
}
/* Flat period hint in micros for one id with zero for no hint. */
static __always_inline u32 flow_hint_us(u64 cgid)
{
	struct flow_hint *h;
	if (!cgid)
		return 0;
	h = bpf_map_lookup_elem(&hint_stor, &cgid);
	if (!h)
		return 0;
	return READ_ONCE(h->period_us);
}
/* Hint plus weight of one task with one cache plus one row read. */
static __always_inline void flow_task_hint_weight(
	struct task_struct *p, u32 *hint_us, u32 *weight)
{
	u32 pid = (u32)p->pid;
	u64 *cached;
	u64 id;
	struct flow_hint *h;
	if (hint_us)
		*hint_us = 0;
	if (weight)
		*weight = (u32)FLOW_WEIGHT_BASE;
	if (!p)
		return;
	if (pid) {
		cached = bpf_map_lookup_elem(&cgrp_cache_stor, &pid);
		if (cached && *cached) {
			id = *cached;
			h = bpf_map_lookup_elem(&hint_stor, &id);
			if (!h)
				return;
			if (hint_us)
				*hint_us = READ_ONCE(h->period_us);
			if (weight) {
				u32 w = READ_ONCE(h->weight);
				*weight = w ? flow_weight_clamp(w) :
				    (u32)FLOW_WEIGHT_BASE;
			}
			return;
		}
	}
	{
		struct cgroup *cgrp = flow_task_cgrp(p);
		if (!cgrp)
			return;
		id = flow_cgrp_id(cgrp);
		flow_cgrp_put(cgrp);
		if (pid)
			bpf_map_update_elem(&cgrp_cache_stor,
			    &pid, &id, BPF_ANY);
		h = bpf_map_lookup_elem(&hint_stor, &id);
		if (!h)
			return;
		if (hint_us)
			*hint_us = READ_ONCE(h->period_us);
		if (weight) {
			u32 w = READ_ONCE(h->weight);
			*weight = w ? flow_weight_clamp(w) :
			    (u32)FLOW_WEIGHT_BASE;
		}
	}
}
/* Init one flat hint row with zero period plus neutral weight. */
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
	h.weight = (u32)FLOW_WEIGHT_BASE;
	bpf_map_update_elem(&hint_stor, &id, &h, BPF_ANY);
	return 0;
}
/* Exit one flat hint row. */
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
s32 BPF_STRUCT_OPS(flow_cgroup_prep_move, struct task_struct *p,
	struct cgroup *from, struct cgroup *to)
{
	(void)p;
	(void)from;
	(void)to;
	return 0;
}
/* Commit one flat move with vruntime plus deadline carry. */
void BPF_STRUCT_OPS(flow_cgroup_move, struct task_struct *p,
	struct cgroup *from, struct cgroup *to)
{
	(void)from;
	if (!p)
		return;
	if (!to)
		return;
	flow_cgrp_cache_invalidate((u32)p->pid);
}
/* Cancel one flat move with no state change. */
void BPF_STRUCT_OPS(flow_cgroup_cancel_move, struct task_struct *p,
	struct cgroup *from, struct cgroup *to)
{
	(void)p;
	(void)from;
	(void)to;
}
/* Shared single share band for cgroup plus task paths. */
static __always_inline void flow_share_band(u32 w, u32 *period_us,
	u32 *weight)
{
	u32 p = 8000;
	u32 b = 256;
	u32 c = flow_weight_clamp(w);
	if (c < 64) {
		p = 32000;
		b = 32;
	} else if (c < 128) {
		p = 16000;
		b = 64;
	} else if (c < 512) {
		p = 8000;
		b = 256;
	} else {
		p = 4000;
		b = 1024;
	}
	if (period_us)
		*period_us = p;
	if (weight)
		*weight = b;
}
/* Update one flat hint from the share with fixed bands. */
void BPF_STRUCT_OPS(flow_cgroup_set_weight, struct cgroup *cgrp,
	u32 weight)
{
	u64 id;
	struct flow_hint h = {};
	if (!cgrp)
		return;
	id = flow_cgrp_id(cgrp);
	if (!id)
		return;
	flow_share_band(weight, &h.period_us, &h.weight);
	if (bpf_map_update_elem(&hint_stor, &id, &h, BPF_ANY) < 0)
		return;
}
