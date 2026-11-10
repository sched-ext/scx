// SPDX-License-Identifier: GPL-2.0
/*
 * Queueing for the flow scheduler.
 *
 * Shared tasks join the queue of the constrained target in deadline order.
 * The upstream queue keeps insertion order for equal deadlines, so the code
 * adds no extra tie handling. Pinned tasks join the local queue in order
 * with a single slice. Exiting tasks use the local queue when allowed and
 * the owner queue otherwise with a short slice. Tasks that have no usable
 * CPU join the fallback queue in FIFO order. The queue key is the floored
 * virtual deadline saturated to unsigned with negatives at zero. Shared
 * inserts move past the per LLC floor and add the burst scaled nice
 * step to the floored time through the shared charge path. Tasks with
 * no usable CPU skip the floor and stay FIFO. The charge scales with
 * the nice weight. Each shared enqueue checks the idle flag first, then the
 * running deadline on the target for an earlier deadline win. Idle targets take
 * an idle wake and never preempt. Each running instance kicks at most once.
 * A deadline win kicks for preempt on a win, else it counts a skip with no wake. A wake goes only to an idle target, else it counts a
 * skip with no wake. The kernel idle flag decides the idle wake.
 * Preempts stay in the same LLC with an allowed live target. Local
 * inserts are not counted in the shared gauge. Shared and fallback
 * inserts count the gauge, and fallback inserts also count fallback.
 * Dequeue drops the gauge on cancel. Masks
 * are checked again before each wake, so a task is never kicked toward
 * a CPU outside its current mask. The queue node lives in arena memory
 * beside the task with the pid for owner lookup. Rejects fall back to
 * the FIFO queue with no extra probe. Overload admits with live plus
 * tolerance plus bound plus room plus cap and evicts at most one ready
 * task with the latest deadline in the lowest band through a bounded
 * scan of at most eight. Queues hold
 * bounded at 64 total with eligibility always eligible.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
#ifndef __FLOW_ENQUEUE_BPF_H
#define __FLOW_ENQUEUE_BPF_H
#include "intf.h"
#include "maps.bpf.h"
#include "stats.bpf.h"
#include "fair.bpf.h"
#include "select.bpf.h"
#include <lib/edq.h>
#include <lib/sdt_task.h>
#include <lib/sdt_alloc.h>
static __always_inline struct scx_edq __arena *flow_edq_for_cpu(s32 tgt)
{
	if (tgt < 0 || !flow_cpu_ok((u32)tgt))
		return 0;
	if (!flow_cpu_live((u32)tgt))
		return 0;
	if (!flow_edqs)
		return 0;
	return &flow_edqs[(u32)tgt];
}
static __always_inline u64 flow_edq_deadline(s64 vd)
{
	if (vd < 0)
		return 0;
	return (u64)vd;
}
static __always_inline int flow_llc_for_cpu(s32 tgt, u32 *out)
{
	int v;
	if (tgt < 0 || !flow_cpu_ok((u32)tgt))
		return -1;
	v = topo_cpu_to_llc_id((u32)tgt);
	if (v < 0 || !flow_llc_ok((u32)v))
		return -1;
	*out = (u32)v;
	return 0;
}
static __always_inline void flow_kick_idle_only(s32 tgt, struct task_struct *p, u32 llc)
{
	if (tgt < 0) {
		flow_stat_inc(llc, 8);
		return;
	}
	if (!flow_cpu_allowed(tgt, p)) {
		flow_stat_inc(llc, 8);
		return;
	}
	if (!flow_cpu_live((u32)tgt)) {
		flow_stat_inc(llc, 8);
		return;
	}
	if (!scx_bpf_test_and_clear_cpu_idle(tgt)) {
		flow_stat_inc(llc, 8);
		return;
	}
	scx_bpf_kick_cpu(tgt, SCX_KICK_IDLE);
	flow_stat_inc(llc, 7);
}
static __always_inline void flow_kick_vd(s32 tgt, struct task_struct *p, u32 llc, s64 new_vd)
{
	struct flow_running_state *rs;
	u64 rgen;
	u32 rllc;
	u32 last;
	s64 run_vd;
	u32 c;
	if (tgt < 0 || !p || !flow_cpu_ok((u32)tgt) || !flow_cpu_allowed(tgt, p) ||
	    !flow_cpu_live((u32)tgt)) {
		flow_stat_inc(llc, 8);
		return;
	}
	if (scx_bpf_test_and_clear_cpu_idle(tgt)) {
		scx_bpf_kick_cpu(tgt, SCX_KICK_IDLE);
		flow_stat_inc(llc, 7);
		return;
	}
	/* Reassert the bound on the index used below so the verifier
	 * keeps the range across the calls above. The barrier keeps the
	 * compiler from folding the check away with the earlier one. */
	c = (u32)tgt;
	asm volatile ("" : "+r" (c));
	if (c >= (u32)FLOW_MAX_CPUS)
		return;
	rs = &flow_running_state[c];
	rgen = READ_ONCE(rs->gen);
	rllc = READ_ONCE(rs->llc_id);
	if (!rgen || !flow_llc_ok(rllc) || rllc != llc) {
		flow_stat_inc(llc, 8);
		return;
	}
	last = READ_ONCE(rs->pad);
	if ((u32)rgen == last) {
		flow_stat_inc(llc, 8);
		return;
	}
	run_vd = READ_ONCE(rs->vd);
	if (!(new_vd < run_vd)) {
		flow_stat_inc(llc, 8);
		return;
	}
	if (__sync_val_compare_and_swap(&rs->pad, last, (u32)rgen) != last) {
		flow_stat_inc(llc, 8);
		return;
	}
	scx_bpf_kick_cpu(tgt, SCX_KICK_PREEMPT);
	flow_stat_inc(llc, 6);
}
/* Bounded evict one for overload. Scans at most eight ready tasks on the
 * target queue and keeps the latest deadline in the lowest implicit band.
 * The victim moves to the fallback queue in FIFO order and the caller
 * admits the newcomer. Ready means still queued. Compare only with no
 * divide and a single remove, so one pass never holds across the host. */
static __always_inline bool flow_try_evict_one(struct scx_edq __arena *edq,
					       s64 new_vd, u32 new_band, u32 llc)
{
	u64 best_raw = 0;
	s32 best_pid = -1;
	u32 best_band = 4U;
	s64 best_vd = 0;
	bool have_best = false;
	int i;
	if (!edq)
		return false;
	for (i = 0; i < 8; i++) {
		u64 raw = 0;
		struct flow_arena_task __arena *at;
		s32 pid;
		struct task_struct *ph;
		struct flow_task_ctx *vt;
		u32 vb;
		s64 vvd;
		int r = scx_edq_try_peek_nth_hold(edq, (u32)i, &raw);
		if (r || !raw)
			break;
		at = (struct flow_arena_task __arena *)raw;
		pid = READ_ONCE(at->pid);
		ph = bpf_task_from_pid(pid);
		if (!ph) {
			scx_edq_task_drop((scx_edq_task_t *)at);
			continue;
		}
		vt = bpf_task_storage_get(&task_ctx_stor, ph, 0, 0);
		if (!vt) {
			bpf_task_release(ph);
			scx_edq_task_drop((scx_edq_task_t *)at);
			continue;
		}
		if (!(READ_ONCE(vt->flags) & (u32)FLOW_FLAG_QUEUED)) {
			bpf_task_release(ph);
			scx_edq_task_drop((scx_edq_task_t *)at);
			continue;
		}
		vb = flow_band_for_weight(flow_nice_weight(ph));
		vvd = READ_ONCE(vt->vd);
		bpf_task_release(ph);
		if (!have_best || vb < best_band ||
		    (vb == best_band && vvd > best_vd)) {
			if (have_best && best_raw)
				scx_edq_task_drop((scx_edq_task_t *)best_raw);
			best_raw = raw;
			best_pid = pid;
			best_band = vb;
			best_vd = vvd;
			have_best = true;
		} else {
			scx_edq_task_drop((scx_edq_task_t *)at);
		}
	}
	if (!have_best || !best_raw || best_pid < 0)
		return false;
	if (best_band > new_band) {
		scx_edq_task_drop((scx_edq_task_t *)best_raw);
		return false;
	}
	if (best_band == new_band && best_vd < new_vd) {
		scx_edq_task_drop((scx_edq_task_t *)best_raw);
		return false;
	}
	{
		struct flow_arena_task __arena *best_at =
			(struct flow_arena_task __arena *)best_raw;
		int r = scx_edq_try_remove(edq, (scx_edq_task_t *)best_at);
		scx_edq_task_drop((scx_edq_task_t *)best_at);
		if (r)
			return false;
	}
	{
		struct task_struct *vp = bpf_task_from_pid(best_pid);
		struct flow_task_ctx *lt;
		u64 slice = (u64)FLOW_SLICE_MIN_NS;
		if (!vp) {
			flow_queued_dec(llc);
			return true;
		}
		lt = bpf_task_storage_get(&task_ctx_stor, vp, 0, 0);
		if (lt) {
			u64 s = READ_ONCE(lt->slice_rem);
			if (s)
				slice = s;
		}
		scx_bpf_dsq_insert(vp, (u64)FLOW_FALLBACK_DSQ, slice, 0);
		flow_stat_inc(llc, 2);
		bpf_task_release(vp);
		return true;
	}
}
void BPF_STRUCT_OPS(flow_enqueue, struct task_struct *p, u64 enq_flags)
{
	s32 task_cpu;
	s32 tgt;
	u32 llc = 0;
	u32 cpu_ok = 0;
	s64 raw_v;
	bool pinned = false;
	struct flow_task_ctx *t;
	u32 old_flags;
	bool no_cpu;
	if (!p)
		return;
	scx_arena_subprog_init();
	task_cpu = scx_bpf_task_cpu(p);
	if (task_cpu < 0)
		task_cpu = (s32)bpf_get_smp_processor_id();
	tgt = flow_constrained_target(task_cpu, p);
	if (tgt >= 0 && flow_cpu_live((u32)tgt)) {
		u32 tmp = 0;
		if (!flow_llc_for_cpu(tgt, &tmp))
			llc = tmp;
		cpu_ok = 1;
	}
	/* The bound is a power of two, so a mask keeps the index in
	 * range with no division. */
	llc &= ((u32)FLOW_MAX_LLCS - 1U);
	no_cpu = !cpu_ok || tgt < 0;
	raw_v = (s64)p->scx.dsq_vtime;
	pinned = flow_is_pinned(p);
	t = bpf_task_storage_get(&task_ctx_stor, p, 0, BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!t) {
		if (p->flags & PF_EXITING) {
			if (tgt >= 0 && flow_cpu_allowed(tgt, p)) {
				u64 ldsq = (u64)SCX_DSQ_LOCAL_ON | (u64)(u32)tgt;
				scx_bpf_dsq_insert(p, ldsq, (u64)FLOW_EXIT_SLICE_NS, enq_flags);
				flow_kick_idle_only(tgt, p, llc);
				return;
			}
			{
				struct scx_edq __arena *edq = no_cpu ? 0 : flow_edq_for_cpu(tgt);
				bool fell = true;
				if (edq) {
					void __arena *mem = __scx_task_data(p);
					if (mem) {
						struct flow_arena_task __arena *at = mem;
						u64 dl = flow_edq_deadline(raw_v);
						WRITE_ONCE(at->pid, p->pid);
						if (scx_edq_nr_queued(edq) < (u64)FLOW_QUEUE_CAP) {
							int ret = scx_edq_insert(edq,
										 (scx_edq_task_t *)at,
										 dl, 0,
										 (u64)FLOW_EXIT_SLICE_NS);
							if (!ret)
								fell = false;
						}
					}
				}
				if (fell)
					scx_bpf_dsq_insert(p, (u64)FLOW_FALLBACK_DSQ,
							   (u64)FLOW_EXIT_SLICE_NS, enq_flags);
				flow_stat_inc(llc, 0);
				if (fell)
					flow_stat_inc(llc, 2);
				flow_kick_idle_only(tgt, p, llc);
				return;
			}
		}
		goto insert_only;
	}
	/* Local placements run before ownership is taken. A task on a
	 * local queue is not counted in the shared gauge, so it leaves
	 * without the queued bit. Shared and fallback inserts take the
	 * bit below and count the gauge together. */
	if (p->flags & PF_EXITING) {
		if (tgt >= 0 && flow_cpu_allowed(tgt, p)) {
			u64 ldsq = (u64)SCX_DSQ_LOCAL_ON | (u64)(u32)tgt;
			scx_bpf_dsq_insert(p, ldsq, (u64)FLOW_EXIT_SLICE_NS, enq_flags);
			flow_kick_idle_only(tgt, p, llc);
			return;
		}
	}
	if (pinned) {
		s32 first = flow_first_allowed(p);
		if (first < 0)
			first = tgt;
		if (first >= 0 && flow_cpu_allowed(first, p)) {
			u32 pllc = llc;
			u32 tmp = 0;
			if (!flow_llc_for_cpu(first, &tmp))
				pllc = tmp;
			{
				u64 ldsq = (u64)SCX_DSQ_LOCAL_ON | (u64)(u32)first;
				scx_bpf_dsq_insert(p, ldsq, (u64)FLOW_SLICE_MIN_NS, enq_flags);
				flow_kick_idle_only(first, p, pllc);
				return;
			}
		}
	}
	old_flags = __sync_fetch_and_or(&t->flags, (u32)FLOW_FLAG_QUEUED);
	if (old_flags & (u32)FLOW_FLAG_QUEUED) {
		flow_fb_inc(llc, 4);
		return;
	}
	if (p->flags & PF_EXITING) {
		struct scx_edq __arena *edq = no_cpu ? 0 : flow_edq_for_cpu(tgt);
		bool fell = true;
		t->llc_id = llc;
		if (edq) {
			void __arena *mem = __scx_task_data(p);
			if (mem) {
				struct flow_arena_task __arena *at = mem;
				u64 dl = flow_edq_deadline(raw_v);
				WRITE_ONCE(at->pid, p->pid);
				if (scx_edq_nr_queued(edq) < (u64)FLOW_QUEUE_CAP) {
					int ret = scx_edq_insert(edq,
								 (scx_edq_task_t *)at,
								 dl, 0,
								 (u64)FLOW_EXIT_SLICE_NS);
					if (!ret)
						fell = false;
				}
			}
		}
		if (fell)
			scx_bpf_dsq_insert(p, (u64)FLOW_FALLBACK_DSQ,
					   (u64)FLOW_EXIT_SLICE_NS, enq_flags);
		flow_stat_inc(llc, 0);
		if (fell)
			flow_stat_inc(llc, 2);
		flow_kick_idle_only(tgt, p, llc);
		return;
	}
	if (pinned) {
		t->llc_id = llc;
		scx_bpf_dsq_insert(p, (u64)FLOW_FALLBACK_DSQ, (u64)FLOW_SLICE_MIN_NS, enq_flags);
		flow_stat_inc(llc, 0);
		flow_stat_inc(llc, 2);
		/* No owner queue took the task. Kick self when idle so the
		 * fallback head is peeked again soon. */
		flow_kick_idle_only((s32)bpf_get_smp_processor_id(), p, llc);
		return;
	}
	{
		/* Shared inserts join the order past the floor. Tasks with no
		 * usable CPU skip the floor, and fallback inserts stay FIFO.
		 * Queues hold bounded at 64 total with pure deadline order
		 * and a single kick. Overload admits with live plus tolerance
		 * plus bound plus room plus cap and evicts at most one ready
		 * task with the latest deadline in the lowest band through a
		 * bounded scan of at most eight. Rejects fall back to FIFO. */
		s64 base = READ_ONCE(t->vtime);
		u32 w = flow_nice_weight(p);
		s64 floored = no_cpu ? base : flow_seq_floor(llc, base);
		s64 vd = flow_vd_for(floored, READ_ONCE(t->burst_ns), w);
		u64 slice_len = (u64)FLOW_SLICE_MIN_NS;
		struct scx_edq __arena *edq = no_cpu ? 0 : flow_edq_for_cpu(tgt);
		bool fell = true;
		bool can_queue = false;
		void __arena *mem = 0;
		if (edq) {
			u64 cost = flow_red_cost(READ_ONCE(t->burst_ns));
			u64 exceed = flow_red_exceed(cost);
			u64 nr = scx_edq_nr_queued(edq);
			bool over = flow_red_gate(cost, exceed, nr);
			mem = __scx_task_data(p);
			if (mem && !over && nr < (u64)FLOW_QUEUE_CAP)
				can_queue = true;
			else if (mem && (over || nr >= (u64)FLOW_QUEUE_CAP)) {
				u32 nb = flow_band_for_weight(w);
				if (flow_try_evict_one(edq, vd, nb, llc)) {
					if (scx_edq_nr_queued(edq) <
					    (u64)FLOW_QUEUE_CAP)
						can_queue = true;
				}
			}
		}
		t->vtime = floored;
		t->vd = vd;
		t->slice_rem = slice_len;
		t->llc_id = llc;
		/* Mirror the due time beside the stored time so later reads see the same due time for order checks. */
		scx_bpf_task_set_dsq_vtime(p, vd);
		/* Rejects fall back to FIFO with no extra probe. */
		if (can_queue) {
			struct flow_arena_task __arena *at = mem;
			u64 dl = flow_edq_deadline(vd);
			WRITE_ONCE(at->pid, p->pid);
			{
				int ret = scx_edq_insert(edq,
							 (scx_edq_task_t *)at,
							 dl, 0, slice_len);
				if (!ret)
					fell = false;
			}
		}
		if (fell)
			scx_bpf_dsq_insert(p, (u64)FLOW_FALLBACK_DSQ, slice_len, enq_flags);
		flow_stat_inc(llc, 0);
		if (fell)
			flow_stat_inc(llc, 2);
		if (no_cpu) {
			/* No usable CPU. Kick self when idle so the
			 * fallback head is peeked again soon. */
			flow_kick_idle_only((s32)bpf_get_smp_processor_id(), p, llc);
			return;
		}
		flow_kick_vd(tgt, p, llc, vd);
		return;
	}
insert_only:
	{
		u64 sl = (u64)FLOW_SLICE_MIN_NS;
		scx_bpf_dsq_insert(p, (u64)FLOW_FALLBACK_DSQ, sl, enq_flags);
		flow_stat_inc(llc, 0);
		flow_stat_inc(llc, 2);
		flow_kick_idle_only(tgt, p, llc);
		return;
	}
}
void BPF_STRUCT_OPS(flow_dequeue, struct task_struct *p, u64 deq_flags)
{
	struct flow_task_ctx *t;
	u32 old;
	(void)deq_flags;
	if (!p)
		return;
	t = bpf_task_storage_get(&task_ctx_stor, p, 0, 0);
	if (!t)
		return;
	old = __sync_fetch_and_and(&t->flags, (u32)~(u32)FLOW_FLAG_QUEUED);
	if (old & (u32)FLOW_FLAG_QUEUED) {
		u32 dllc = READ_ONCE(t->llc_id);
		if (!flow_llc_ok(dllc))
			dllc = 0;
		flow_queued_dec(dllc);
	}
}
#endif
