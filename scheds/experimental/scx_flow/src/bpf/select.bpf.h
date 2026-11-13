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
 * threads. Tiers stay L1 greater than L2 greater than L3, so the same
 * cluster wins inside the same LLC before the wider LLC and node fall
 * back in fixed order. Short form is L1>L2>L3. No sibling probe runs
 * and each CPU stands single with fail closed choice. Inside the same
 * cache tiers ties prefer larger buckets first within tier with known
 * priority matching the drain, else fixed order covers unknown sizes.
 * Group tier reads l2 and LLC tier reads l3 after one seed lookup.
 * Every check returns minus one on failure.
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
/* Owner tree lookup plus empty probe shared with enqueue and dispatch.
 * Lives here so select can reuse the same helper with no duplicate. */
static __always_inline struct flow_rb_root __arena *flow_rb_for_cpu(s32 tgt)
{
	if (tgt < 0 || !flow_cpu_ok((u32)tgt))
		return 0;
	if ((u64)(u32)tgt >= scx_bpf_nr_cpu_ids())
		return 0;
	/* No live gate here so offline roots still reap. Enqueue callers gate
	 * live explicitly and fall back to FIFO for offline targets. No new
	 * insert lands offline. */
	if (!flow_rb_roots)
		return 0;
	return &flow_rb_roots[(u32)tgt];
}
static __always_inline bool flow_rb_empty(struct flow_rb_root __arena *r)
{
	if (!r)
		return true;
	return READ_ONCE(r->root) == 0;
}
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
/* Unknown cluster reads as all ones, so group zero stays a valid match.
 * The value never collides with a seeded group id, which stays small. */
#define FLOW_CCX_UNKNOWN 0xFFFFFFFFU
static __noinline s32 flow_first_allowed(struct task_struct *p)
{
	u32 first;
	u32 c;
	if (!p || !p->cpus_ptr)
		return -1;
	first = bpf_cpumask_first(p->cpus_ptr);
	if (flow_cpu_ok(first) && flow_cpu_live(first) && flow_cpu_allowed((s32)first, p))
		return (s32)first;
	/* The first mask bit can be offline while a later bit stays usable.
	 * Scan the mask in fixed order for the first allowed live CPU, so
	 * only tasks with no usable CPU fall back to minus one. Bounded scan
	 * within the CPU bound with mask plus live checks only and no widening. */
	bpf_for(c, 0, FLOW_MAX_CPUS) {
		if (!flow_cpu_live(c))
			continue;
		if (!flow_cpu_allowed((s32)c, p))
			continue;
		return (s32)c;
	}
	return -1;
}
static __noinline s32 flow_constrained_target(s32 hint, struct task_struct *p)
{
	if (!p || !p->cpus_ptr)
		return -1;
	if (hint >= 0 && flow_cpu_allowed(hint, p) && flow_cpu_live((u32)hint))
		return hint;
	return flow_first_allowed(p);
}
/* A busy core runs at max and an idle core runs at half. The call
 * stays on one live core and never sends zero. Shared here so enqueue
 * and dispatch use one helper with no duplicate max path. The gate
 * also bounds the id by the live ids and skips a remote target while
 * a queue lock is held, so the set never trips the invalid target
 * exit. Kick stays allowed for a valid target while the set skips.
 * Caller must hold the target runqueue lock for a remote set, else the call skips. */
static __always_inline void flow_cpuperf_mark(u32 cpu, bool idle)
{
	u32 perf;
	if (!flow_cpu_ok(cpu) || !flow_cpu_live(cpu))
		return;
	if ((u64)cpu >= scx_bpf_nr_cpu_ids())
		return;
	if (!bpf_ksym_exists(scx_bpf_cpuperf_set))
		return;
	if (bpf_ksym_exists(scx_bpf_cpu_rq)) {
		struct rq *locked = scx_bpf_locked_rq();
		if (locked) {
			struct rq *target = scx_bpf_cpu_rq((s32)cpu);
			if (!target || target != locked)
				return;
		}
	} else {
		struct rq *locked = scx_bpf_locked_rq();
		if (locked && cpu != bpf_get_smp_processor_id())
			return;
	}
	perf = (u32)SCX_CPUPERF_ONE;
	if (idle)
		perf = (u32)(SCX_CPUPERF_ONE / 2);
	if (!perf)
		return;
	scx_bpf_cpuperf_set((s32)cpu, perf);
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
		return (u32)FLOW_CCX_UNKNOWN;
	cc = bpf_map_lookup_elem(&cpu_ctx_stor, &key);
	if (!cc)
		return (u32)FLOW_CCX_UNKNOWN;
	return READ_ONCE(cc->ccx_id);
}
/* Same cluster match on the seed view with the seed flag gate. Both group
 * ids must be known, so unknown reads as all ones never match and fixed
 * order covers them. The seed flag stays always on with init one and no
 * userspace seed as an interim, so the gate stays for a later seed without
 * changing the match. */
/* Size buckets read as u8 with zero meaning unknown. A miss reads
 * unknown, so unknown sizes keep fixed order with no match. */
static __always_inline u8 flow_cpu_l2bkt(u32 cpu)
{
	u32 key = cpu;
	struct flow_cpu_ctx *cc;
	if (!flow_cpu_ok(cpu))
		return 0;
	cc = bpf_map_lookup_elem(&cpu_ctx_stor, &key);
	if (!cc)
		return 0;
	return READ_ONCE(cc->l2_bkt);
}
static __always_inline u8 flow_cpu_l3bkt(u32 cpu)
{
	u32 key = cpu;
	struct flow_cpu_ctx *cc;
	if (!flow_cpu_ok(cpu))
		return 0;
	cc = bpf_map_lookup_elem(&cpu_ctx_stor, &key);
	if (!cc)
		return 0;
	return READ_ONCE(cc->l3_bkt);
}
/* Larger check with the both known gate. Unknown sizes never match,
 * so fixed order covers them. Compares promote to int per C rules with
 * identical result and no extra budget. */
static __always_inline bool flow_cache_larger(u8 a, u8 b)
{
	if (!a || !b)
		return false;
	return a > b;
}
/* Coalesced seed view with one map lookup for cluster plus both buckets.
 * Group tier picks l2 and LLC tier picks l3 after the score, so one lookup
 * covers both with no extra loop. A miss reads unknown with no match. */
struct flow_cpu_view {
	u32 ccx;
	u8 l2;
	u8 l3;
};
static __always_inline struct flow_cpu_view flow_cpu_view(u32 cpu)
{
	struct flow_cpu_view v = { (u32)FLOW_CCX_UNKNOWN, 0, 0 };
	u32 key = cpu;
	struct flow_cpu_ctx *cc;
	if (!flow_cpu_ok(cpu))
		return v;
	cc = bpf_map_lookup_elem(&cpu_ctx_stor, &key);
	if (!cc)
		return v;
	v.ccx = READ_ONCE(cc->ccx_id);
	v.l2 = READ_ONCE(cc->l2_bkt);
	v.l3 = READ_ONCE(cc->l3_bkt);
	return v;
}
static __always_inline bool flow_ccx_match(bool use, u32 cx, u32 hint)
{
	if (!use)
		return false;
	if (cx == (u32)FLOW_CCX_UNKNOWN || hint == (u32)FLOW_CCX_UNKNOWN)
		return false;
	return cx == hint;
}
s32 BPF_STRUCT_OPS(flow_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
	const struct cpumask *idle_mask;
	s32 hint = prev_cpu;
	int hint_llc = -1;
	u32 hint_ccx = (u32)FLOW_CCX_UNKNOWN;
	bool have_hint_topo = false;
	s32 best = -1;
	int best_score = 99;
	bool best_same = false;
	u8 best_bkt = 0;
	bool have_best_bkt = false;
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
	if (flow_is_pinned(p))
		return flow_constrained_target(hint, p);
	idle_mask = scx_bpf_get_idle_cpumask();
	if (!idle_mask)
		return flow_constrained_target(hint, p);
	/* Read-only idle check: keeps the idle bit intact for flow_enqueue to kick */
	if (hint >= 0 && flow_cpu_allowed(hint, p) && flow_cpu_live((u32)hint) &&
	    bpf_cpumask_test_cpu((u32)hint, idle_mask) &&
	    flow_rb_empty(flow_rb_for_cpu(hint))) {
		scx_bpf_put_cpumask(idle_mask);
		return hint;
	}
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
		u8 cb = 0;
		int score;
		int pre;
		int vllc;
		bool same_node = false;
		struct flow_cpu_view vw;
		if (!flow_cpu_live(c))
			continue;
		if (!flow_cpu_allowed((s32)c, p))
			continue;
		if (!bpf_cpumask_test_cpu(c, idle_mask))
			continue;
		if (!flow_rb_empty(flow_rb_for_cpu((s32)c)))
			continue;
		vllc = topo_cpu_to_llc_id(c);
		if (vllc < 0 || !flow_llc_ok((u32)vllc))
			continue;
		l = (u32)vllc;
		if (hint_node && topo_contains(hint_node, c))
			same_node = true;
		pre = 3;
		if (have_hint_topo) {
			if (hint_llc >= 0 && l == (u32)hint_llc)
				pre = 0;
			else if (same_node)
				pre = 1;
			else
				pre = 2;
		} else if (flow_is_primary(0)) {
			/* Intentional: no hint topo falls back to the node tier.
			 * The zero arg is the single node default with no widening.
			 * No core walk runs here by design; each CPU stands single. */
			pre = 2;
		}
		if (pre > best_score)
			continue;
		vw = flow_cpu_view(c);
		cx = vw.ccx;
		score = pre;
		if (have_hint_topo && !smt_on && hint_llc >= 0 &&
		    l == (u32)hint_llc && flow_ccx_match(use_ccx, cx, hint_ccx))
			score = -1;
		if (score == -1)
			cb = vw.l2;
		else if (score == 0)
			cb = vw.l3;
		if (score < best_score) {
			best_score = score;
			best = (s32)c;
			best_same = have_hint_topo && flow_ccx_match(use_ccx, cx, hint_ccx);
			best_bkt = cb;
			have_best_bkt = cb ? true : false;
		} else if (score == best_score) {
			/* Tie favor stays even with threads on; only the fast pick is gated.
			 * Inside the cache tiers the tie then prefers larger buckets first
			 * within tier with known priority matching the drain, else fixed
			 * order keeps unknown sizes. A known bucket replaces an unknown
			 * best and larger replaces smaller with equal keeping fixed order.
			 * The full scan stays bounded with no early break
			 * so the largest known bucket wins. */
			bool cur_same = have_hint_topo && flow_ccx_match(use_ccx, cx, hint_ccx);
			if (cur_same && !best_same) {
				best = (s32)c;
				best_same = true;
				best_bkt = cb;
				have_best_bkt = cb ? true : false;
			} else if (cur_same == best_same && score <= 0 && have_hint_topo &&
				   cb && (!have_best_bkt || flow_cache_larger(cb, best_bkt))) {
				best = (s32)c;
				best_bkt = cb;
				have_best_bkt = true;
			}
		}
	}
	scx_bpf_put_cpumask(idle_mask);
	/* The mask can change while scanning, check the pick again. */
	if (best >= 0 && flow_cpu_allowed(best, p))
		return best;
	return flow_constrained_target(hint, p);
}
#endif
