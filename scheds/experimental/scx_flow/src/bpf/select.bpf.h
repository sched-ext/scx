// SPDX-License-Identifier: GPL-2.0
/*
 * Placement for the flow scheduler.
 *
 * The pick first tries the previous CPU when it is allowed and
 * online. Otherwise it scans once and prefers the same LLC, then
 * the same node, then a distant CPU. Cache and node identity come
 * from the upstream topology tree with cluster hints from the seed
 * view. Ties keep the first CPU in fixed order. Within the same LLC
 * the scan favors the same cluster, with the tie favor kept even
 * when threads share cores and only the fast pick gated on single
 * threads. No sibling probe runs and each CPU stands single with
 * fail closed choice. Every check returns minus one on failure.
 * Masks are tested again before each wake, so a task is never kicked
 * toward a CPU outside its current mask. Frequency follows core
 * busyness and never steers placement.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
#ifndef __FLOW_SELECT_BPF_H
#define __FLOW_SELECT_BPF_H
#include "intf.h"
#include "maps.bpf.h"
#include "stats.bpf.h"
#include <lib/sdt_alloc.h>
static __always_inline bool flow_is_pinned(struct task_struct *p)
{
	if (!p)
		return false;
	if (p->nr_cpus_allowed == 1)
		return true;
	return is_migration_disabled(p);
}
static __always_inline bool flow_cpu_allowed(s32 cpu, struct task_struct *p)
{
	u32 c;
	if (!p || !p->cpus_ptr)
		return false;
	if (cpu < 0)
		return false;
	c = (u32)cpu;
	if (!flow_cpu_ok(c))
		return false;
	return bpf_cpumask_test_cpu(c, p->cpus_ptr);
}
static __always_inline bool flow_cpu_live(u32 cpu)
{
	if (!flow_cpu_ok(cpu))
		return false;
	if (!topo_all)
		return false;
	return topo_contains(topo_all, cpu) ? true : false;
}
static __always_inline s32 flow_first_allowed(struct task_struct *p)
{
	u32 first;
	if (!p || !p->cpus_ptr)
		return -1;
	first = bpf_cpumask_first(p->cpus_ptr);
	if (!flow_cpu_live(first))
		return -1;
	if (!flow_cpu_allowed((s32)first, p))
		return -1;
	return (s32)first;
}
static __always_inline s32 flow_constrained_target(s32 hint, struct task_struct *p)
{
	if (!p || !p->cpus_ptr)
		return -1;
	if (hint >= 0 && flow_cpu_allowed(hint, p) && flow_cpu_live((u32)hint))
		return hint;
	return flow_first_allowed(p);
}
static __always_inline bool flow_is_primary(u32 node)
{
	return node == 0;
}
static __always_inline int flow_hint_llc(s32 hint)
{
	int v;
	if (hint < 0 || !flow_cpu_ok((u32)hint))
		return -1;
	if (!topo_all)
		return -1;
	v = topo_cpu_to_llc_id((u32)hint);
	if (v < 0 || !flow_llc_ok((u32)v))
		return -1;
	return v;
}
static __always_inline u32 flow_cpu_ccx(u32 cpu)
{
	u32 key = cpu;
	struct flow_cpu_ctx *cc;
	if (!flow_cpu_ok(cpu))
		return 0;
	cc = bpf_map_lookup_elem(&cpu_ctx_stor, &key);
	if (!cc)
		return 0;
	return READ_ONCE(cc->ccx_id);
}
s32 BPF_STRUCT_OPS(flow_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
	s32 hint = prev_cpu;
	s32 tgt;
	int hint_llc = -1;
	u32 hint_ccx = 0;
	bool have_hint_topo = false;
	s32 best = -1;
	int best_score = 99;
	bool best_same = false;
	bool use_ccx;
	bool smt_on;
	u32 c;
	struct topo_iter hint_iter;
	topo_ptr hint_node = 0;
	topo_ptr walk = 0;
	(void)wake_flags;
	if (!p)
		return hint;
	scx_arena_subprog_init();
	use_ccx = READ_ONCE(flow_ccx_prefer) ? true : false;
	smt_on = READ_ONCE(flow_smt_enabled) ? true : false;
	tgt = flow_constrained_target(hint, p);
	if (tgt >= 0)
		return tgt;
	if (hint >= 0 && flow_cpu_ok((u32)hint) && topo_all &&
	    topo_contains(topo_all, (u32)hint)) {
		hint_llc = flow_hint_llc(hint);
		hint_ccx = flow_cpu_ccx((u32)hint);
		TOPO_FOR_EACH_NODE(&hint_iter, walk) {
			if (topo_contains(walk, (u32)hint)) {
				hint_node = walk;
				break;
			}
		}
		if (hint_llc >= 0 || hint_node)
			have_hint_topo = true;
	}
	bpf_for(c, 0, FLOW_MAX_CPUS) {
		u32 l;
		u32 cx;
		int score;
		int vllc;
		bool same_node = false;
		if (!flow_cpu_live(c))
			continue;
		if (!flow_cpu_allowed((s32)c, p))
			continue;
		vllc = topo_cpu_to_llc_id(c);
		if (vllc < 0 || !flow_llc_ok((u32)vllc))
			continue;
		l = (u32)vllc;
		cx = flow_cpu_ccx(c);
		if (hint_node && topo_contains(hint_node, c))
			same_node = true;
		score = 3;
		if (have_hint_topo) {
			if (hint_llc >= 0 && l == (u32)hint_llc)
				score = 0;
			else if (same_node)
				score = 1;
			else
				score = 2;
			if (!smt_on && use_ccx && hint_llc >= 0 &&
			    l == (u32)hint_llc && cx == hint_ccx)
				score = -1;
		} else if (flow_is_primary(0)) {
			score = 2;
		}
		if (score < best_score) {
			best_score = score;
			best = (s32)c;
			best_same = have_hint_topo && use_ccx && cx == hint_ccx;
			if (score == -1)
				break;
			if (score == 0 && (!use_ccx || best_same))
				break;
		} else if (score == best_score) {
			/* Tie favor stays even with threads on; only the fast pick is gated. */
			bool cur_same = have_hint_topo && use_ccx && cx == hint_ccx;
			if (cur_same && !best_same) {
				best = (s32)c;
				best_same = true;
				if (score == 0)
					break;
			}
		}
	}
	/* The mask can change while scanning, check the pick again. */
	if (best >= 0 && flow_cpu_allowed(best, p))
		return best;
	return flow_first_allowed(p);
}
#endif
