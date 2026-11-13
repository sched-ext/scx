// SPDX-License-Identifier: GPL-2.0
/*
 * Dispatch and lifecycle for the flow scheduler.
 *
 * Each CPU drains its own queue first, then the same cache group, then
 * the rest of the same LLC, then the same node, then distant queues,
 * then fallback. Tiers stay L1 greater than L2 greater than L3. Closer
 * caches drain first with larger buckets first within tier when both
 * buckets are known. Fixed order covers the rest. Short form is
 * L1>L2>L3. Empty queues skip before any group lookup. Both known group
 * ids gate the group match. Unknown groups fall through to fixed order.
 * Each tree drains in deadline order with leftmost wins and ties right
 * in RB_DUPLICATE-compatible order. The tree is an unbalanced BST with
 * depth bound at RB_MAX_DEPTH. A head that cannot run here sends one
 * wake to its owner and stays queued. Forward slots hash by victim mask
 * with sixty four slots plus the fallback on the last slot. Sixteen
 * victims share one slot with dedup key of pid plus vtime plus owner.
 * A dead head is dropped with its count and the next queue is tried.
 * The fallback drops its count from the task and wakes the owner when
 * the move fails. A dispatch that moved nothing but saw such a head
 * wakes the fallback head again without the dedup check. Remote moves
 * count on the thief and drop the gauge on the source. Running records
 * the task snapshot and mirrors the due time beside it for gap checks.
 * Stopping charges burnt time into the stored time and mirrors the
 * stored time beside it. It tracks the run length for the next due time.
 * A runnable yield with no burnt time still moves the stored time
 * forward by one. The tick charges the burnt delta and moves the due
 * time. Stopping charges only the tail past the last tick. A busy core
 * runs at max and an idle core runs at half. The set call never sends
 * zero and never steers placement. A mask change on a queued task keeps
 * the queue and wakes the new owner. It counts the wake when the owner
 * is usable. A task with no usable CPU waits in the fallback queue until
 * the mask widens. Stopping plus tick keep the burst and run state with
 * guarded preempt and no reclaim. Init creates one tree per CPU with depth bound at
 * RB_MAX_DEPTH plus slab for entries and the fallback queue. Trees hold
 * without bound on live task count with per tree depth bound. Trees use
 * a plain unbalanced BST with always eligible tasks. Liveness comes from
 * the upstream tree. CPUs that arrive late need a restart to be seen.
 * Each entry carries its pid for lookup with the biased key for order.
 * Offline roots stay reaped through the same drain. No slab entry
 * strands offline.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
#ifndef __FLOW_DISPATCH_BPF_H
#define __FLOW_DISPATCH_BPF_H
#include "intf.h"
#include "maps.bpf.h"
#include "stats.bpf.h"
#include "select.bpf.h"
#include "enqueue.bpf.h"
#include "fair.bpf.h"
#include <lib/topology.h>
#include <lib/sdt_alloc.h>
#include <lib/sdt_task.h>
/* A busy core runs at max and an idle core runs at half. Shared mark
 * lives in select.bpf.h so enqueue and dispatch use one helper. The call
 * never sends zero with no steering. */
/* Empty trees skip before any group lookup, so idle victims cost one
 * counter read with no topology walk. */
static __always_inline bool flow_rb_is_empty(struct flow_rb_root __arena *rb)
{
	if (!rb)
		return true;
	return flow_rb_empty(rb);
}
static __noinline void flow_forward_from_peeked(struct task_struct *ph, u32 llc, u32 slot)
{
	s32 owner;
	s64 hv;
	u64 pid;
	if (!ph)
		return;
	if (slot > (u32)FLOW_MAX_LLCS)
		return;
	pid = (u64)ph->pid;
	hv = (s64)ph->scx.dsq_vtime;
	owner = flow_first_allowed(ph);
	{
		u64 last_p = READ_ONCE(flow_fwd_pid[slot]);
		s64 last_v = READ_ONCE(flow_fwd_vtime[slot]);
		s32 last_o = READ_ONCE(flow_fwd_owner[slot]);
		if (last_p == pid && last_v == hv && last_o == owner)
			return;
		flow_fwd_pid[slot] = pid;
		flow_fwd_vtime[slot] = hv;
		flow_fwd_owner[slot] = owner;
	}
	if (owner < 0) {
		flow_kick_idle_only(owner, ph, llc);
		return;
	}
	flow_stat_inc(llc, 12);
	flow_kick_idle_only(owner, ph, llc);
}
/* A dispatch that moved nothing but saw an unrunnable head wakes the
 * fallback head again without the dedup check, so an owner that
 * turned idle is not missed. The kick stays idle only with no pad check. */
static __noinline void flow_rekick_unrunnable(struct task_struct *ph, u32 llc)
{
	s32 owner;
	if (!ph)
		return;
	owner = flow_first_allowed(ph);
	flow_kick_idle_only(owner, ph, llc);
}
/* Steal-back path outlined so the victim insert verifies once as a
 * subprogram instead of inline in every drain. */
static __noinline bool flow_try_stealback(struct flow_rb_root __arena *rb,
					  struct flow_rb_entry __arena *got,
					  struct task_struct *p, int steal)
{
	if (!steal || !rb || !got || !p)
		return false;
	if (!flow_cpu_allowed((s32)READ_ONCE(got->owner), p))
		return false;
	if (!flow_rb_insert(rb, got))
		return false;
	bpf_task_release(p);
	return true;
}
/* Move request packs the drain inputs into one struct plus the saw flag
 * with no logic change. Caller builds the struct on stack then passes
 * a pointer with no extra alloc and no new loop. */
struct flow_move_req {
	struct flow_rb_root __arena *rb;
	u32 cpu;
	u32 llc;
	u32 vllc;
	u32 slot;
	int steal;
};
static __noinline int flow_try_move_rb(const struct flow_move_req *req, bool *saw)
{
	struct task_struct *p;
	struct flow_task_ctx *lt;
	u64 slice;
	struct flow_rb_entry __arena *got;
	s32 got_pid;
	u32 cpu;
	u32 llc;
	u32 vllc;
	struct flow_rb_root __arena *rb;
	u32 slot;
	int steal;
	if (!req || !req->rb)
		return 0;
	if (req->slot > (u32)FLOW_MAX_LLCS)
		return 0;
	cpu = req->cpu;
	llc = req->llc;
	vllc = req->vllc;
	rb = req->rb;
	slot = req->slot;
	steal = req->steal;
	/* Pop-first then validate. This avoids the peek then pop race. A
	 * peeked dead head plus a raced pop could free the wrong entry. The
	 * lossy peek-dead path is removed. The pop owns the head atomically
	 * under the try lock. The pid below is always the popped entry. */
	got = flow_rb_pop(rb);
	if (!got)
		return 0;
	got_pid = READ_ONCE(got->node.pid);
	p = bpf_task_from_pid(got_pid);
	if (!p) {
		/* Dead entry. Free with no gauge move. Exit or dequeue owns
		 * the single dec through the queued bit. */
		scx_free(&flow_rb_alloc, got);
		return 0;
	}
	if (!flow_cpu_allowed((s32)cpu, p)) {
		if (saw)
			*saw = true;
		flow_forward_from_peeked(p, llc, slot);
		/* If stealing from a remote or peer CPU that IS allowed for p,
		 * try to put the entry right back into the victim BST first
		 * so p does not lose its deadline order. Outlined above. */
		if (flow_try_stealback(rb, got, p, steal))
			return 0;
		/* Fallback if local unrunnable or re-insert contended or full. */
		lt = bpf_task_storage_get(&task_ctx_stor, p, 0, 0);
		slice = (u64)FLOW_SLICE_MIN_NS;
		if (lt) {
			u64 s = READ_ONCE(lt->slice_rem);
			if (s)
				slice = s;
			__sync_fetch_and_and(&lt->flags, (u32)~(u32)FLOW_FLAG_IN_RB);
		}
		scx_bpf_dsq_insert(p, (u64)FLOW_FALLBACK_DSQ, slice, 0);
		flow_stat_inc(llc, 2);
		bpf_task_release(p);
		scx_free(&flow_rb_alloc, got);
		return 0;
	}
	lt = bpf_task_storage_get(&task_ctx_stor, p, 0, 0);
	slice = (u64)FLOW_SLICE_MIN_NS;
	if (lt) {
		u64 s = READ_ONCE(lt->slice_rem);
		if (s)
			slice = s;
	}
	scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, slice, 0);
	flow_cpuperf_mark(cpu, false);
	flow_stat_inc(llc, 1);
	if (lt) {
		u32 old = __sync_fetch_and_and(&lt->flags,
					      (u32)~((u32)FLOW_FLAG_QUEUED | (u32)FLOW_FLAG_IN_RB));
		if (old & (u32)FLOW_FLAG_QUEUED)
			flow_queued_dec(vllc);
	}
	bpf_task_release(p);
	scx_free(&flow_rb_alloc, got);
	if (steal) {
		flow_stat_inc(llc, 3);
		flow_stat_inc(llc, 5);
	}
	return 1;
}
static __noinline int flow_drain_cpu(u32 cpu, u32 llc, u32 victim, int steal, bool *saw)
{
	struct flow_rb_root __arena *rb;
	int vllc;
	u32 vuse;
	u32 slot;
	if (!flow_cpu_ok(victim))
		return 0;
	/* No live gate here so offline roots still reap with no new loop.
	 * Enqueue never inserts offline, so any offline entry here is a
	 * stranded orphan that drains to local or fallback below. */
	/* Bound the index by the live table size with no new table. */
	if ((u64)victim >= scx_bpf_nr_cpu_ids())
		return 0;
	rb = flow_rb_for_cpu((s32)victim);
	/* Empty trees skip before the LLC lookup below. */
	if (flow_rb_is_empty(rb))
		return 0;
	vllc = topo_cpu_to_llc_id(victim);
	if (vllc < 0 || !flow_llc_ok((u32)vllc))
		return 0;
	vuse = (u32)vllc;
	/* The bound is a power of two, so a mask keeps the slot in
	 * range with no division. The fallback keeps the last slot. */
	slot = victim & ((u32)FLOW_MAX_LLCS - 1U);
	/* Deadline order drain with insertion ties from the tree. */
	{
		struct flow_move_req mreq;
		mreq.cpu = cpu;
		mreq.llc = llc;
		mreq.vllc = vuse;
		mreq.rb = rb;
		mreq.slot = slot;
		mreq.steal = steal;
		if (flow_try_move_rb(&mreq, saw))
			return 1;
	}
	return 0;
}
void BPF_STRUCT_OPS(flow_dispatch, s32 cpu, struct task_struct *prev)
{
	u32 c;
	u32 llc = 0;
	u32 victim;
	int v;
	bool saw_unrunnable = false;
	bool use_ccx;
	u32 my_ccx;
	u32 best_victim;
	u32 best2_victim;
	u32 first_victim;
	u8 best_bkt;
	u8 best2_bkt;
	bool have_best;
	bool have_best2;
	bool have_first;
	struct topo_iter hint_iter;
	topo_ptr hint_node = 0;
	topo_ptr walk = 0;
	(void)prev;
	scx_arena_subprog_init();
	if (cpu < 0)
		return;
	c = (u32)cpu;
	if (!flow_cpu_ok(c) || !flow_cpu_live(c))
		return;
	v = topo_cpu_to_llc_id(c);
	if (v < 0 || !flow_llc_ok((u32)v))
		return;
	llc = (u32)v;
	if (topo_all && topo_contains(topo_all, c)) {
		TOPO_FOR_EACH_NODE(&hint_iter, walk) {
			if (topo_contains(walk, c)) {
				hint_node = walk;
				break;
			}
		}
	}
	if (flow_drain_cpu(c, llc, c, 0, &saw_unrunnable))
		return;
	/* Same cache group victims drain first inside the same LLC, so
	 * tasks stay near warm cache. Larger buckets first within tier
	 * orders the group victims with known priority, else the
	 * first fixed victim covers unknown sizes. The pass tracks the best
	 * plus second best known larger victims plus the first fixed victim
	 * in one scan with no new loop, then drains best plus first plus
	 * second best with at most three tries. The group
	 * match needs the seed flag with both group ids known, so unknown
	 * reads as all ones match nothing and the fixed victim covers them.
	 * Sentinel never matches by design with fail closed fallthrough.
	 * Empty queues skip before the group lookup, so idle victims cost
	 * one counter read with no topology walk. The empty check can race
	 * a new enqueue, which stays safe since the next dispatch covers
	 * the new head. One seed lookup returns cluster plus buckets. */
	use_ccx = READ_ONCE(flow_ccx_prefer) ? true : false;
	my_ccx = flow_cpu_ccx(c);
	best_victim = (u32)FLOW_MAX_CPUS;
	best2_victim = (u32)FLOW_MAX_CPUS;
	first_victim = (u32)FLOW_MAX_CPUS;
	best_bkt = 0;
	best2_bkt = 0;
	have_best = false;
	have_best2 = false;
	have_first = false;
	bpf_for(victim, 0, FLOW_MAX_CPUS) {
		int vl;
		u32 vccx;
		u8 vb;
		struct flow_cpu_view vw;
		if (victim == c)
			continue;
		/* No live gate so offline roots still reap with no new loop. */
		if ((u64)victim >= scx_bpf_nr_cpu_ids())
			continue;
		if (flow_rb_is_empty(flow_rb_for_cpu((s32)victim)))
			continue;
		vl = topo_cpu_to_llc_id(victim);
		if (vl < 0 || (u32)vl != llc)
			continue;
		vw = flow_cpu_view(victim);
		vccx = vw.ccx;
		if (!flow_ccx_match(use_ccx, vccx, my_ccx))
			continue;
		vb = vw.l2;
		if (!have_first) {
			first_victim = victim;
			have_first = true;
		}
		if (vb && (!have_best || flow_cache_larger(vb, best_bkt))) {
			if (have_best && best_victim != victim) {
				best2_victim = best_victim;
				best2_bkt = best_bkt;
				have_best2 = true;
			}
			best_victim = victim;
			best_bkt = vb;
			have_best = true;
		} else if (vb && victim != best_victim &&
			   (!have_best2 || flow_cache_larger(vb, best2_bkt))) {
			best2_victim = victim;
			best2_bkt = vb;
			have_best2 = true;
		}
	}
	if (have_best && flow_drain_cpu(c, llc, best_victim, 1, &saw_unrunnable))
		return;
	if (have_first && (!have_best || first_victim != best_victim) &&
	    flow_drain_cpu(c, llc, first_victim, 1, &saw_unrunnable))
		return;
	if (have_best2 && (!have_best || best2_victim != best_victim) &&
	    (!have_first || best2_victim != first_victim) &&
	    flow_drain_cpu(c, llc, best2_victim, 1, &saw_unrunnable))
		return;
	/* Same LLC victims drain next with larger buckets first within tier
	 * with known priority and fixed order else, with already tried group
	 * victims skipped, so each queue probes once per dispatch. The pass
	 * tracks the best plus second best known larger victims plus the first
	 * fixed victim in one scan with no new loop, then drains best plus
	 * first plus second best with at most three tries.
	 * Empty queues skip before the dedup lookup. The empty check
	 * can race a new enqueue, which stays safe since the next dispatch
	 * covers the new head. One seed lookup returns cluster plus buckets. */
	best_victim = (u32)FLOW_MAX_CPUS;
	best2_victim = (u32)FLOW_MAX_CPUS;
	first_victim = (u32)FLOW_MAX_CPUS;
	best_bkt = 0;
	best2_bkt = 0;
	have_best = false;
	have_best2 = false;
	have_first = false;
	bpf_for(victim, 0, FLOW_MAX_CPUS) {
		int vl;
		u8 vb;
		struct flow_cpu_view vw;
		if (victim == c)
			continue;
		/* No live gate so offline roots still reap with no new loop. */
		if ((u64)victim >= scx_bpf_nr_cpu_ids())
			continue;
		if (flow_rb_is_empty(flow_rb_for_cpu((s32)victim)))
			continue;
		vl = topo_cpu_to_llc_id(victim);
		if (vl < 0 || (u32)vl != llc)
			continue;
		vw = flow_cpu_view(victim);
		if (flow_ccx_match(use_ccx, vw.ccx, my_ccx))
			continue;
		vb = vw.l3;
		if (!have_first) {
			first_victim = victim;
			have_first = true;
		}
		if (vb && (!have_best || flow_cache_larger(vb, best_bkt))) {
			if (have_best && best_victim != victim) {
				best2_victim = best_victim;
				best2_bkt = best_bkt;
				have_best2 = true;
			}
			best_victim = victim;
			best_bkt = vb;
			have_best = true;
		} else if (vb && victim != best_victim &&
			   (!have_best2 || flow_cache_larger(vb, best2_bkt))) {
			best2_victim = victim;
			best2_bkt = vb;
			have_best2 = true;
		}
	}
	if (have_best && flow_drain_cpu(c, llc, best_victim, 1, &saw_unrunnable))
		return;
	if (have_first && (!have_best || first_victim != best_victim) &&
	    flow_drain_cpu(c, llc, first_victim, 1, &saw_unrunnable))
		return;
	if (have_best2 && (!have_best || best2_victim != best_victim) &&
	    (!have_first || best2_victim != first_victim) &&
	    flow_drain_cpu(c, llc, best2_victim, 1, &saw_unrunnable))
		return;
	bpf_for(victim, 0, FLOW_MAX_CPUS) {
		int vl;
		if (victim == c)
			continue;
		/* No live gate so offline roots still reap with no new loop. */
		vl = topo_cpu_to_llc_id(victim);
		if (vl < 0 || !flow_llc_ok((u32)vl) || (u32)vl == llc)
			continue;
		/* Node identity comes from the tree with no per-CPU walk here. */
		if (!hint_node || !topo_contains(hint_node, victim))
			continue;
		if (flow_drain_cpu(c, llc, victim, 1, &saw_unrunnable))
			return;
	}
	bpf_for(victim, 0, FLOW_MAX_CPUS) {
		int vl;
		if (victim == c)
			continue;
		/* No live gate so offline roots still reap with no new loop. */
		vl = topo_cpu_to_llc_id(victim);
		if (vl < 0 || !flow_llc_ok((u32)vl) || (u32)vl == llc)
			continue;
		if (hint_node && topo_contains(hint_node, victim))
			continue;
		if (flow_drain_cpu(c, llc, victim, 1, &saw_unrunnable))
			return;
	}
	/* Distant aggregate stays repointed with no remote size compare. The
	 * folded share feeds the seed only. Unknown stays zero with fixed
	 * order covering unknown sizes. The distant pass above keeps fixed
	 * order with no size lookup. The fallback peek below covers the
	 * stripped share. The fallback probe counter fires only when the
	 * fallback peek finds a head. It stays BSS only. */
	/* The compat peek returns a borrowed reference with no release. The
	 * task stays valid for the check below. The borrowed head is checked
	 * for mask plus liveness before any move. A raced exit stays safe. */
	{
		struct task_struct *ph = __COMPAT_scx_bpf_dsq_peek((u64)FLOW_FALLBACK_DSQ);
		if (ph) {
			__sync_fetch_and_add(&m_estrip_probe, 1ULL);
			if (!flow_cpu_allowed((s32)c, ph)) {
				flow_forward_from_peeked(ph, llc, (u32)FLOW_MAX_LLCS);
				saw_unrunnable = true;
			} else {
				struct flow_task_ctx *pt;
				u32 vllc = llc;
				pt = bpf_task_storage_get(&task_ctx_stor, ph, 0, 0);
				if (pt) {
					u32 q = READ_ONCE(pt->llc_id);
					if (flow_llc_ok(q))
						vllc = q;
				}
				if (scx_bpf_dsq_move_to_local((u64)FLOW_FALLBACK_DSQ, 0)) {
					flow_stat_inc(llc, 1);
					flow_cpuperf_mark(c, false);
					if (pt) {
						u32 old = __sync_fetch_and_and(&pt->flags,
								      (u32)~((u32)FLOW_FLAG_QUEUED | (u32)FLOW_FLAG_IN_RB));
						if (old & (u32)FLOW_FLAG_QUEUED)
							flow_queued_dec(vllc);
					}
					return;
				}
				/* The head can run here but the move failed.
				 * Wake the owner so the task is not left idle. */
				flow_forward_from_peeked(ph, llc, (u32)FLOW_MAX_LLCS);
				saw_unrunnable = true;
			}
		}
	}
	if (saw_unrunnable) {
		/* Borrowed reference as above with no release. The rekick stays
		 * safe. */
		struct task_struct *rh = __COMPAT_scx_bpf_dsq_peek((u64)FLOW_FALLBACK_DSQ);
		if (rh)
			flow_rekick_unrunnable(rh, llc);
	}
	/* No task moved, so the core stays idle at half. */
	flow_cpuperf_mark(c, true);
}
void BPF_STRUCT_OPS(flow_running, struct task_struct *p)
{
	s32 task_cpu = scx_bpf_task_cpu(p);
	u32 cpu;
	struct flow_task_ctx *t;
	u32 llc = 0;
	struct flow_running_state *rs;
	u64 sl;
	u64 ng;
	int v;
	if (task_cpu < 0)
		return;
	cpu = (u32)task_cpu;
	if (!flow_cpu_ok(cpu))
		return;
	scx_arena_subprog_init();
	t = bpf_task_storage_get(&task_ctx_stor, p, 0, 0);
	if (!t)
		return;
	v = topo_cpu_to_llc_id(cpu);
	if (v >= 0 && flow_llc_ok((u32)v))
		llc = (u32)v;
	else if (flow_llc_ok(t->llc_id))
		llc = t->llc_id;
	sl = p->scx.slice;
	if (!sl)
		sl = (u64)FLOW_SLICE_MIN_NS;
	else if (sl > (u64)FLOW_SLICE_MIN_NS)
		sl = (u64)FLOW_SLICE_MIN_NS;
	rs = &flow_running_state[cpu];
	ng = rs->gen + 1;
	if (ng == 0)
		ng = 1;
	rs->vtime = READ_ONCE(t->vtime);
	rs->slice_rem = sl;
	rs->gen = ng;
	rs->llc_id = llc;
	rs->vd = READ_ONCE(t->vd);
	/* The start stamp uses a plain store on an aligned eight byte
	 * word with a tear free read in the kick path. A torn read yields
	 * zero ran with a fail closed skip and the generation recheck
	 * covers recycle with no extra fence. */
	rs->start_ts = bpf_ktime_get_ns();
	t->gen = ng;
	t->slice_rem = sl;
	t->llc_id = llc;
	/* Running keeps the stored time and mirrors the due time beside it for gap checks. */
	scx_bpf_task_set_dsq_vtime(p, READ_ONCE(t->vd));
	/* The gauge was already dropped when the task moved to the local
	 * queue. Local inserts were never counted. Running only clears
	 * ownership with no gauge move. The core is busy now, so it runs
	 * at max. */
	__sync_fetch_and_and(&t->flags,
			      (u32)~((u32)FLOW_FLAG_QUEUED | (u32)FLOW_FLAG_IN_RB));
	flow_cpuperf_mark(cpu, false);
}
void BPF_STRUCT_OPS(flow_stopping, struct task_struct *p, bool runnable)
{
	s32 task_cpu = scx_bpf_task_cpu(p);
	u32 cpu;
	struct flow_task_ctx *t;
	struct flow_running_state *rs;
	u64 cur;
	u64 have;
	u64 used;
	u64 total_used;
	if (task_cpu < 0)
		return;
	cpu = (u32)task_cpu;
	if (!flow_cpu_ok(cpu))
		return;
	scx_arena_subprog_init();
	t = bpf_task_storage_get(&task_ctx_stor, p, 0, 0);
	if (!t)
		return;
	rs = &flow_running_state[cpu];
	cur = p->scx.slice;
	have = READ_ONCE(t->slice_rem);
	if (!have)
		have = (u64)FLOW_SLICE_MIN_NS;
	if (cur > have)
		cur = have;
	if (cur >= have)
		used = 0;
	else
		used = have - cur;
	/* Accumulate the tail burnt past the last tick first, so run_total
	 * holds the exact runtime burnt across this activation even when
	 * the initial slice was custom-sized below FLOW_SLICE_MIN_NS. */
	flow_run_add(t, used);
	total_used = READ_ONCE(t->run_total);
	if (!total_used && used)
		total_used = used;
	t->burst_ns = flow_burst_update(READ_ONCE(t->burst_ns), total_used, cur, runnable);
	{
		u64 now = bpf_ktime_get_ns();
		if (now) {
			flow_run_prune(t, now);
			if (!runnable)
				flow_run_close(t, now);
		}
	}
	/* Burnt time pays here into the stored time, scaled by the effective
	 * weight with saturation and mirrored as the stored time beside it. The
	 * tick already moved the left slice forward, so this charges only
	 * the tail past the last tick. A runnable yield with no burnt time
	 * still moves the stored time forward by one, so repeated yields
	 * cannot hold the queue head. */
	if (used) {
		s64 nv = flow_fair_charge(READ_ONCE(t->vtime), used,
					  flow_eff_w(flow_nice_weight(p),
						    flow_share_live(p)));
		t->vtime = nv;
		scx_bpf_task_set_dsq_vtime(p, nv);
		if (!cur)
			flow_stat_inc(rs->llc_id, 9);
	} else if (runnable) {
		s64 nv = flow_fair_cap_add(READ_ONCE(t->vtime), 1);
		t->vtime = nv;
		scx_bpf_task_set_dsq_vtime(p, nv);
	}
	rs->slice_rem = cur;
	t->slice_rem = cur;
	/* Intentional cpufreq policy: keep core at 100% if it still has a
	 * task waiting in its local tree. Only drop to 50% when empty. */
	if (runnable)
		flow_stat_inc(rs->llc_id, 10);
	else if (flow_rb_is_empty(flow_rb_for_cpu((s32)cpu)))
		flow_cpuperf_mark(cpu, true);
}
void BPF_STRUCT_OPS(flow_tick, struct task_struct *p)
{
	s32 task_cpu = scx_bpf_task_cpu(p);
	u32 cpu;
	struct flow_task_ctx *t;
	struct flow_running_state *rs;
	u64 cur;
	u64 have;
	if (task_cpu < 0)
		return;
	cpu = (u32)task_cpu;
	if (!flow_cpu_ok(cpu))
		return;
	scx_arena_subprog_init();
	rs = &flow_running_state[cpu];
	cur = p->scx.slice;
	t = bpf_task_storage_get(&task_ctx_stor, p, 0, 0);
	if (!t) {
		rs->slice_rem = cur;
		return;
	}
	/* Charge the burnt delta, then move the due time with the burst
	 * left while inside it and the left slice past it in both the
	 * stored and running views, so the running horizon keeps the
	 * burst bound. Stopping later charges only the tail past this tick.
	 * The run sum grows by the delta here and freezes prune on a zero
	 * or backward clock. The exhausted branch adds nothing here since
	 * stopping charges that tail. */
	have = READ_ONCE(t->slice_rem);
	{
		u64 now = bpf_ktime_get_ns();
		if (now)
			flow_run_prune(t, now);
	}
	if (cur && cur < have) {
		u64 delta = have - cur;
		u32 w = flow_eff_w(flow_nice_weight(p), flow_share_live(p));
		s64 nv = flow_fair_charge(READ_ONCE(t->vtime), delta, w);
		s64 nvd = flow_vd_for(nv, cur, w);
		flow_run_add(t, delta);
		t->vtime = nv;
		t->vd = nvd;
		t->slice_rem = cur;
		rs->vtime = nv;
		rs->vd = nvd;
		scx_bpf_task_set_dsq_vtime(p, nvd);
	} else if (!cur && have) {
		/* The slice ran out at the tick. Keep the stored slice so
		 * stopping still charges the tail, but move the running horizon
		 * out by one slice so a wake can land at once with the two
		 * views diverged until stopping. Seed the burst to one slice
		 * for the next run. */
		u32 w = flow_eff_w(flow_nice_weight(p), flow_share_live(p));
		s64 nv = flow_fair_charge(READ_ONCE(t->vtime), have, w);
		s64 nvd = flow_vd_for(nv, (u64)FLOW_SLICE_MIN_NS, w);
		rs->vtime = nv;
		rs->vd = nvd;
		rs->slice_rem = 0;
		t->burst_ns = (u64)FLOW_SLICE_MIN_NS;
	}
}
void BPF_STRUCT_OPS(flow_set_cpumask, struct task_struct *p, const struct cpumask *mask)
{
	struct flow_task_ctx *t;
	(void)mask;
	if (!p)
		return;
	scx_arena_subprog_init();
	t = bpf_task_storage_get(&task_ctx_stor, p, 0, 0);
	if (!t)
		return;
	if (READ_ONCE(t->flags) & (u32)FLOW_FLAG_QUEUED) {
		s32 owner = flow_first_allowed(p);
		u32 qllc = READ_ONCE(t->llc_id);
		if (!flow_llc_ok(qllc))
			qllc = 0;
		if (owner < 0) {
			/* No usable CPU. The task waits in fallback
			 * until the mask widens, so count the skip. */
			flow_stat_inc(qllc, 8);
			return;
		}
		if (!flow_cpu_allowed(owner, p) || !flow_cpu_live((u32)owner)) {
			flow_stat_inc(qllc, 8);
			return;
		}
		flow_kick_idle_only(owner, p, qllc);
		flow_stat_inc(qllc, 11);
		return;
	}
	if (p->flags & PF_EXITING)
		t->slice_rem = (u64)FLOW_EXIT_SLICE_NS;
	{
		s32 tgt = flow_first_allowed(p);
		int v;
		if (tgt < 0)
			return;
		if (!flow_cpu_live((u32)tgt))
			return;
		v = topo_cpu_to_llc_id((u32)tgt);
		if (v < 0 || !flow_llc_ok((u32)v))
			return;
		t->llc_id = (u32)v;
	}
}
void BPF_STRUCT_OPS(flow_enable, struct task_struct *p)
{
	struct flow_task_ctx *t;
	s64 v;
	if (!p)
		return;
	t = bpf_task_storage_get(&task_ctx_stor, p, 0, BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!t)
		return;
	v = (s64)p->scx.dsq_vtime;
	t->vtime = v;
	t->vd = v;
	t->slice_rem = (u64)FLOW_SLICE_MIN_NS;
	t->burst_ns = (u64)FLOW_SLICE_MIN_NS;
	t->gen = 0;
	t->llc_id = 0;
	t->flags = 0;
	flow_run_reset(t);
}
s32 BPF_STRUCT_OPS_SLEEPABLE(flow_init_task, struct task_struct *p, struct scx_init_task_args *args)
{
	struct flow_task_ctx *t;
	void __arena *mem;
	struct flow_arena_task __arena *at;
	(void)args;
	if (!p)
		return 0;
	t = bpf_task_storage_get(&task_ctx_stor, p, 0, BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (t) {
		t->vtime = 0;
		t->vd = 0;
		t->slice_rem = (u64)FLOW_SLICE_MIN_NS;
		t->burst_ns = (u64)FLOW_SLICE_MIN_NS;
		t->gen = 0;
		t->llc_id = 0;
		t->flags = 0;
		flow_run_reset(t);
		scx_bpf_task_set_dsq_vtime(p, 0);
	}
	/* One reserved arena slot per task. The slot sits at offset zero.
	 * The slot stays at one hundred thirty six bytes. Tree entries live
	 * in slab memory, not in this slot. The slab holds at most one forty
	 * eight byte entry per queued task through the queued bit. The worst
	 * stays at four hundred within five hundred twelve. Init keeps the
	 * slot with no tree link. Slab entries are freed on pop plus dequeue
	 * plus exit. Dead heads are reaped lazily by the next pop. Exit or
	 * dequeue owns the gauge dec. */
	mem = __scx_task_data(p);
	if (mem) {
		at = mem;
		WRITE_ONCE(at->pid, p->pid);
		WRITE_ONCE(at->pad, 0);
		WRITE_ONCE(at->storage[0], 0ULL);
		return 0;
	}
	mem = scx_task_alloc(p);
	if (!mem)
		return 0;
	at = mem;
	WRITE_ONCE(at->pid, p->pid);
	WRITE_ONCE(at->pad, 0);
	WRITE_ONCE(at->storage[0], 0ULL);
	return 0;
}
void BPF_STRUCT_OPS(flow_exit_task, struct task_struct *p, struct scx_exit_task_args *args)
{
	struct flow_task_ctx *t;
	void __arena *mem;
	(void)args;
	if (!p)
		return;
	scx_arena_subprog_init();
	t = bpf_task_storage_get(&task_ctx_stor, p, 0, 0);
	mem = __scx_task_data(p);
	if (!mem) {
		if (t) {
			u32 old = __sync_fetch_and_and(&t->flags,
						      (u32)~((u32)FLOW_FLAG_QUEUED | (u32)FLOW_FLAG_IN_RB));
			if (old & (u32)FLOW_FLAG_QUEUED) {
				u32 dllc = READ_ONCE(t->llc_id);
				if (!flow_llc_ok(dllc))
					dllc = 0;
				flow_queued_dec(dllc);
			}
		}
		return;
	}
	{
		u32 was_queued = 0;
		u32 was_tree = 0;
		u32 dllc = 0;
		u32 owner = 0;
		u64 key = 0;
		bool have_key = false;
		if (t) {
			u32 old;
			dllc = READ_ONCE(t->llc_id);
			if (!flow_llc_ok(dllc))
				dllc = 0;
			owner = READ_ONCE(t->run_pad);
			old = __sync_fetch_and_and(&t->flags,
						  (u32)~((u32)FLOW_FLAG_QUEUED | (u32)FLOW_FLAG_IN_RB));
			was_queued = old & (u32)FLOW_FLAG_QUEUED;
			was_tree = old & (u32)FLOW_FLAG_IN_RB;
			if (was_tree && mem) {
				struct flow_arena_task __arena *at = mem;
				u64 sk = READ_ONCE(at->storage[0]);
				if (sk) {
					key = sk;
					have_key = true;
				}
			}
		}
		/* Drop the reserved slot when still present. Dequeue already
		 * dropped the gauge when it ran. Drop here only when the flag
		 * shows dequeue had not run yet. Exit owns the single dec.
		 * Then unlink the tree entry when the tree bit shows it is
		 * still linked. Removal frees with no gauge move. Contention
		 * leaves the entry for the next pop. Stored key keeps remove
		 * stable past later due time moves. */
		if (was_queued) {
			flow_queued_dec(dllc);
			if (was_tree && have_key && flow_cpu_ok(owner)) {
				struct flow_rb_root __arena *rb = flow_rb_for_cpu((s32)owner);
				flow_rb_remove(rb, key, p->pid, owner);
			}
		}
		scx_task_free(p);
	}
}
s32 BPF_STRUCT_OPS_SLEEPABLE(flow_init)
{
	u64 n;
	n = scx_bpf_nr_cpu_ids();
	scx_arena_subprog_init();
	if (n == 0) {
		scx_bpf_error("no CPUs found");
		return -EINVAL;
	}
	if (n > (u64)FLOW_MAX_CPUS) {
		scx_bpf_error("CPU count over bound");
		return -E2BIG;
	}
	/* The arena library must be ready before any queue is built.
	 * Userspace sets up the arena and the topology tree before load,
	 * so a missing tree fails closed here with no partial queues. */
	if (!topo_all) {
		scx_bpf_error("topology tree missing");
		return -ENODEV;
	}
	/* Thread shape keeps the userspace seed with the source default on miss. */
	flow_ccx_prefer = 1;
	/* Intentional: static cap is one thousand twenty four while the
	 * operational queue table caps at five hundred twelve. The first
	 * check guards the static area and the second guards the BST
	 * table, so both stay fail closed with no silent truncation. */
	if (n > 512ULL) {
		scx_bpf_error("CPU count over bound");
		return -E2BIG;
	}
	/* One tree per live CPU in deadline order with depth bound at
	 * RB_MAX_DEPTH. Leftmost wins with ties right. Roots live in arena
	 * memory through static alloc. Fresh pages start zeroed, which is the
	 * empty tree state. Slab entries live in arena memory. The fallback
	 * queue stays as the only DSQ. Slab init runs before roots alloc.
	 * Roots alloc failure leaves the slab live with no entries. Exit
	 * stays safe. Lifetime starts here and ends in flow exit. Roots are
	 * cleared on exit. Slab entries are freed by pop plus remove. */
	if (scx_alloc_init(&flow_rb_alloc, sizeof(struct flow_rb_entry),
			   __alignof__(struct flow_rb_entry))) {
		scx_bpf_error("rb alloc init failed");
		return -ENOMEM;
	}
	/* Roots live in arena memory with one entry per CPU id below the
	 * observed count, so every live id stays in range. Fresh pages start
	 * zeroed, which is the empty tree state with no static sizing of
	 * queue nodes. */
	flow_rb_roots = scx_static_alloc(sizeof(struct flow_rb_root) * (size_t)n,
					 __alignof__(struct flow_rb_root));
	if (!flow_rb_roots) {
		scx_bpf_error("rb roots alloc failed");
		return -ENOMEM;
	}
	{
		s32 ret = scx_bpf_create_dsq((u64)FLOW_FALLBACK_DSQ, -1);
		if (ret < 0 && ret != -EEXIST) {
			scx_bpf_error("fallback dsq create failed");
			return ret;
		}
	}
	return 0;
}
void BPF_STRUCT_OPS(flow_exit, struct scx_exit_info *info)
{
	UEI_RECORD(uei, info);
	/* Lifetime ends here. Roots are cleared. The slab store is torn down
	 * with the arena. No entry strands after this point. */
	flow_rb_roots = 0;
	scx_bpf_destroy_dsq((u64)FLOW_FALLBACK_DSQ);
}
#endif
