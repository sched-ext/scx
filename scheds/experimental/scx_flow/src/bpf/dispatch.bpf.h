// SPDX-License-Identifier: GPL-2.0
/*
 * Dispatch and lifecycle for the flow scheduler.
 *
 * Each CPU drains its own queue first, then queues on the same LLC,
 * then the same node, then distant queues, then fallback. Each queue
 * drains in deadline order. A head that cannot run here
 * sends one wake to its owner and stays queued. Each victim keeps
 * its own forward slot with the fallback on the last slot, so one
 * victim does not hide another. A dead head is dropped with its count
 * and the next queue is tried. The fallback drops its count from the
 * task and wakes the owner when the move fails. A dispatch that moved
 * nothing but saw such a head wakes the fallback head again without
 * the dedup check. Remote moves count on the thief and drop the gauge
 * on the source. Running records the task snapshot and mirrors the
 * due time beside it for gap checks. Stopping charges burnt time into the
 * stored time and mirrors the stored time beside it, and tracks the
 * run length for the next due time. A runnable yield with no burnt
 * time still moves the stored time forward by one. The tick charges
 * the burnt delta and moves the due time with the burst left while
 * inside it and the left slice past it and mirrors the due time beside
 * it, so stopping charges only the tail past the last tick. When the
 * slice is exhausted at the tick, the stored slice stays while the
 * running horizon moves out by one slice, so the two views diverge
 * until stopping charges the tail. A busy core runs at max and an idle
 * core runs at half. The set call never sends zero and never steers
 * placement. A mask change on a queued task keeps the queue and wakes
 * the new owner, counting the wake when the owner is usable. A task
 * with no usable CPU waits in the fallback queue until the mask widens.
 * Stopping plus tick reclaim at most one saved delta from burst past
 * burnt with room plus live plus allowed and idle only kick, so overload
 * drains with no new op. Init creates one embedded queue per CPU bounded at 64 total
 * and the fallback queue. Queues
 * use the upstream deadline library with always eligible tasks. Liveness comes from
 * the upstream tree, so CPUs that arrive late need a restart to be seen.
 * Each task carries one arena queue node with its pid for lookup.
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
#include <lib/edq.h>
#include <lib/topology.h>
#include <lib/sdt_alloc.h>
#include <lib/sdt_task.h>
/* A busy core runs at max and an idle core runs at half. The call
 * stays on one live core and never sends zero. */
static __always_inline void flow_cpuperf_mark(u32 cpu, bool idle)
{
	u32 perf;
	if (!flow_cpu_ok(cpu) || !flow_cpu_live(cpu))
		return;
	if (!bpf_ksym_exists(scx_bpf_cpuperf_set))
		return;
	perf = (u32)SCX_CPUPERF_ONE;
	if (idle)
		perf = (u32)(SCX_CPUPERF_ONE / 2);
	if (!perf)
		return;
	scx_bpf_cpuperf_set((s32)cpu, perf);
}
static __always_inline void flow_forward_from_peeked(struct task_struct *ph, u32 llc, u32 slot)
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
static __always_inline void flow_rekick_unrunnable(struct task_struct *ph, u32 llc)
{
	s32 owner;
	if (!ph)
		return;
	owner = flow_first_allowed(ph);
	flow_kick_idle_only(owner, ph, llc);
}
/* Reclaim one fallback head with saved burst. Peeks the fallback queue
 * once and kicks the idle owner once when the target holds room with
 * live plus allowed, so overload drains with no extra probe and no new
 * op. Saved zero skips with no kick. Compare only with no divide. */
static __always_inline void flow_reclaim_kick(u64 saved, u32 llc)
{
	struct task_struct *ph;
	s32 owner;
	struct scx_edq __arena *edq;
	if (!saved)
		return;
	if (!flow_llc_ok(llc))
		return;
	ph = __COMPAT_scx_bpf_dsq_peek((u64)FLOW_FALLBACK_DSQ);
	if (!ph)
		return;
	owner = flow_first_allowed(ph);
	if (owner < 0)
		return;
	edq = flow_edq_for_cpu(owner);
	if (!edq)
		return;
	if (scx_edq_nr_queued(edq) >= (u64)FLOW_QUEUE_CAP)
		return;
	flow_kick_idle_only(owner, ph, llc);
}
static __always_inline int flow_try_move_edq(u32 cpu, u32 llc, u32 vllc,
					     struct scx_edq __arena *edq,
					     u32 slot, int steal, bool *saw)
{
	u64 peeked_raw;
	struct flow_arena_task __arena *peeked_at;
	s32 peek_pid;
	struct task_struct *ph;
	struct task_struct *p;
	struct flow_task_ctx *lt;
	u64 slice;
	u64 popped_raw;
	struct flow_arena_task __arena *popped_at;
	s32 popped_pid;
	if (!edq)
		return 0;
	if (slot > (u32)FLOW_MAX_LLCS)
		return 0;
	/* Peek with a hold so the node stays alive across the owner check. */
	peeked_raw = scx_edq_peek_hold(edq);
	if (!peeked_raw)
		return 0;
	/* The pop address is also the wrapper address with the node at
	 * offset zero. This cast follows the queue API and does not
	 * launder task storage. */
	peeked_at = (struct flow_arena_task __arena *)peeked_raw;
	peek_pid = READ_ONCE(peeked_at->pid);
	ph = bpf_task_from_pid(peek_pid);
	if (!ph) {
		/* Dead head. Remove the exact node with no extra pop so a
		 * raced pop elsewhere does not lose its count. */
		int r = scx_edq_try_remove(edq, (scx_edq_task_t *)peeked_at);
		scx_edq_task_drop((scx_edq_task_t *)peeked_at);
		if (!r)
			flow_queued_dec(vllc);
		return 0;
	}
	if (!flow_cpu_allowed((s32)cpu, ph)) {
		if (saw)
			*saw = true;
		flow_forward_from_peeked(ph, llc, slot);
		bpf_task_release(ph);
		scx_edq_task_drop((scx_edq_task_t *)peeked_at);
		return 0;
	}
	bpf_task_release(ph);
	scx_edq_task_drop((scx_edq_task_t *)peeked_at);
	/* Claim the head with a hold. A raced pop may hand the next task,
	 * which is checked again below. */
	popped_raw = scx_edq_pop(edq, true);
	if (!popped_raw)
		return 0;
	popped_at = (struct flow_arena_task __arena *)popped_raw;
	popped_pid = READ_ONCE(popped_at->pid);
	p = bpf_task_from_pid(popped_pid);
	if (!p) {
		scx_edq_task_drop((scx_edq_task_t *)popped_at);
		flow_queued_dec(vllc);
		return 0;
	}
	if (!flow_cpu_allowed((s32)cpu, p)) {
		if (saw)
			*saw = true;
		flow_forward_from_peeked(p, llc, slot);
		/* Keep the task alive through the fallback queue. */
		lt = bpf_task_storage_get(&task_ctx_stor, p, 0, 0);
		slice = (u64)FLOW_SLICE_MIN_NS;
		if (lt) {
			u64 s = READ_ONCE(lt->slice_rem);
			if (s)
				slice = s;
		}
		scx_bpf_dsq_insert(p, (u64)FLOW_FALLBACK_DSQ, slice, 0);
		flow_stat_inc(llc, 2);
		bpf_task_release(p);
		scx_edq_task_drop((scx_edq_task_t *)popped_at);
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
	flow_queued_dec(vllc);
	bpf_task_release(p);
	scx_edq_task_drop((scx_edq_task_t *)popped_at);
	if (steal) {
		flow_stat_inc(llc, 3);
		flow_stat_inc(llc, 5);
	}
	return 1;
}
static __always_inline int flow_drain_cpu(u32 cpu, u32 llc, u32 victim, int steal, bool *saw)
{
	struct scx_edq __arena *edq;
	int vllc;
	u32 vuse;
	u32 slot;
	if (!flow_cpu_ok(victim) || !flow_cpu_live(victim))
		return 0;
	if (!flow_edqs)
		return 0;
	edq = &flow_edqs[victim];
	vllc = topo_cpu_to_llc_id(victim);
	if (vllc < 0 || !flow_llc_ok((u32)vllc))
		return 0;
	vuse = (u32)vllc;
	/* The bound is a power of two, so a mask keeps the slot in
	 * range with no division. The fallback keeps the last slot. */
	slot = victim & ((u32)FLOW_MAX_LLCS - 1U);
	/* Deadline order drain with insertion ties from the queue. */
	if (flow_try_move_edq(cpu, llc, vuse, edq, slot, steal, saw))
		return 1;
	return 0;
}
void BPF_STRUCT_OPS(flow_dispatch, s32 cpu, struct task_struct *prev)
{
	u32 c;
	u32 llc = 0;
	u32 victim;
	int v;
	bool saw_unrunnable = false;
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
	bpf_for(victim, 0, FLOW_MAX_CPUS) {
		int vl;
		if (victim == c)
			continue;
		if (!flow_cpu_live(victim))
			continue;
		vl = topo_cpu_to_llc_id(victim);
		if (vl < 0 || (u32)vl != llc)
			continue;
		if (flow_drain_cpu(c, llc, victim, 1, &saw_unrunnable))
			return;
	}
	bpf_for(victim, 0, FLOW_MAX_CPUS) {
		int vl;
		if (victim == c)
			continue;
		if (!flow_cpu_live(victim))
			continue;
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
		if (!flow_cpu_live(victim))
			continue;
		vl = topo_cpu_to_llc_id(victim);
		if (vl < 0 || !flow_llc_ok((u32)vl) || (u32)vl == llc)
			continue;
		if (hint_node && topo_contains(hint_node, victim))
			continue;
		if (flow_drain_cpu(c, llc, victim, 1, &saw_unrunnable))
			return;
	}
	{
		struct task_struct *ph = __COMPAT_scx_bpf_dsq_peek((u64)FLOW_FALLBACK_DSQ);
		if (ph) {
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
					flow_queued_dec(vllc);
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
	t->gen = ng;
	t->slice_rem = sl;
	t->llc_id = llc;
	/* Running keeps the stored time and mirrors the due time beside it for gap checks. */
	scx_bpf_task_set_dsq_vtime(p, READ_ONCE(t->vd));
	/* The gauge was already dropped when the task moved to the local
	 * queue. Local inserts were never counted. Running only clears
	 * ownership. The core is busy now, so it runs at max. */
	__sync_fetch_and_and(&t->flags, (u32)~(u32)FLOW_FLAG_QUEUED);
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
	u64 old_b;
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
	/* Track the run length before the tail charge, so the next due
	 * time prices what this run actually burnt. */
	if (cur < (u64)FLOW_SLICE_MIN_NS)
		total_used = (u64)FLOW_SLICE_MIN_NS - cur;
	else
		total_used = 0;
	old_b = flow_burst_clamp(READ_ONCE(t->burst_ns));
	t->burst_ns = flow_burst_update(READ_ONCE(t->burst_ns), total_used, cur, runnable);
	/* Burnt time pays here into the stored time, scaled by the nice
	 * weight with saturation and mirrored as the stored time beside it. The
	 * tick already moved the left slice forward, so this charges only
	 * the tail past the last tick. A runnable yield with no burnt time
	 * still moves the stored time forward by one, so repeated yields
	 * cannot hold the queue head. */
	if (used) {
		s64 nv = flow_fair_charge(READ_ONCE(t->vtime), used,
					  flow_nice_weight(p));
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
	/* A sleeping task leaves the core idle at half. A runnable task
	 * keeps its count with no frequency change. Reclaim at most one
	 * saved delta from burst past burnt with room plus live plus
	 * allowed and idle only kick. */
	if (runnable)
		flow_stat_inc(rs->llc_id, 10);
	else
		flow_cpuperf_mark(cpu, true);
	{
		u64 saved = (old_b > total_used) ? (old_b - total_used) : 0;
		flow_reclaim_kick(saved, READ_ONCE(rs->llc_id));
	}
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
	 * burst bound. Stopping later charges only the tail past this tick. */
	have = READ_ONCE(t->slice_rem);
	if (cur && cur < have) {
		u64 delta = have - cur;
		u64 burnt = (cur < (u64)FLOW_SLICE_MIN_NS) ?
			    ((u64)FLOW_SLICE_MIN_NS - cur) : (u64)FLOW_SLICE_MIN_NS;
		u64 b = flow_burst_clamp(READ_ONCE(t->burst_ns));
		u64 rem = (burnt < b) ? (b - burnt) : cur;
		u32 w = flow_nice_weight(p);
		s64 nv = flow_fair_charge(READ_ONCE(t->vtime), delta, w);
		s64 nvd = flow_vd_for(nv, rem, w);
		u64 saved = (b > burnt) ? (b - burnt) : 0;
		u32 rllc = READ_ONCE(t->llc_id);
		t->vtime = nv;
		t->vd = nvd;
		t->slice_rem = cur;
		rs->vtime = nv;
		rs->vd = nvd;
		scx_bpf_task_set_dsq_vtime(p, nvd);
		/* Reclaim at most one saved delta with room plus live plus
		 * allowed and idle only kick. */
		if (!flow_llc_ok(rllc))
			rllc = 0;
		flow_reclaim_kick(saved, rllc);
	} else if (!cur && have) {
		/* The slice ran out at the tick. Keep the stored slice so
		 * stopping still charges the tail, but move the running horizon
		 * out by one slice so a wake can preempt at once with the two
		 * views diverged until stopping. Seed the burst to one slice
		 * for the next run. */
		u32 w = flow_nice_weight(p);
		s64 nv = flow_fair_charge(READ_ONCE(t->vtime), have, w);
		s64 nvd = flow_vd_for(nv, (u64)FLOW_SLICE_MIN_NS, w);
		rs->vtime = nv;
		rs->vd = nvd;
		t->burst_ns = (u64)FLOW_SLICE_MIN_NS;
	}
	rs->slice_rem = cur;
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
		scx_bpf_task_set_dsq_vtime(p, 0);
	}
	/* One arena node per task for the queue. The node sits at offset
	 * zero of the wrapper, so the queue address is also the wrapper
	 * address with no storage laundering. */
	mem = __scx_task_data(p);
	if (mem) {
		at = mem;
		scx_edq_task_init((scx_edq_task_t *)at);
		WRITE_ONCE(at->pid, p->pid);
		WRITE_ONCE(at->pad, 0);
		return 0;
	}
	mem = scx_task_alloc(p);
	if (!mem)
		return 0;
	at = mem;
	scx_edq_task_init((scx_edq_task_t *)at);
	WRITE_ONCE(at->pid, p->pid);
	WRITE_ONCE(at->pad, 0);
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
			u32 old = __sync_fetch_and_and(&t->flags, (u32)~(u32)FLOW_FLAG_QUEUED);
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
		struct flow_arena_task __arena *at = mem;
		u32 was_queued = 0;
		u32 dllc = 0;
		if (t) {
			dllc = READ_ONCE(t->llc_id);
			if (!flow_llc_ok(dllc))
				dllc = 0;
			was_queued = __sync_fetch_and_and(&t->flags,
							  (u32)~(u32)FLOW_FLAG_QUEUED) &
				     (u32)FLOW_FLAG_QUEUED;
		}
		/* Drop the queue link when still present. Dequeue already
		 * dropped the gauge when it ran, so drop here only when
		 * the flag shows dequeue had not run yet. Detach then
		 * waits for holds before the free below. */
		scx_edq_task_fini((scx_edq_task_t *)at);
		if (was_queued)
			flow_queued_dec(dllc);
		scx_edq_task_detach((scx_edq_task_t *)at);
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
	if (n > 512ULL) {
		scx_bpf_error("CPU count over bound");
		return -E2BIG;
	}
	/* One embedded queue per live CPU in deadline order bounded at
	 * 64 total. The table holds one entry per CPU id below the
	 * observed count, so every live id stays in range while the
	 * request stays within the static area cap. The array lives in
	 * arena memory for the queue address space. Fresh pages start
	 * zeroed, which is the empty queue state. */
	flow_edqs = scx_static_alloc(sizeof(struct scx_edq) * (size_t)n,
				     __alignof__(struct scx_edq));
	if (!flow_edqs) {
		scx_bpf_error("queue alloc failed");
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
	flow_edqs = 0;
	scx_bpf_destroy_dsq((u64)FLOW_FALLBACK_DSQ);
}
#endif
