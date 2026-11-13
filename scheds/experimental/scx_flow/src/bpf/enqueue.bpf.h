// SPDX-License-Identifier: GPL-2.0
/*
 * Queueing for the flow scheduler.
 *
 * Shared tasks join the tree of the constrained target in deadline
 * order. The tree is an unbalanced BST. Ties chain right in
 * RB_DUPLICATE-compatible order with insertion order for equal
 * deadlines. Depth stays bound at RB_MAX_DEPTH with FIFO spill on
 * overflow. Contention plus depth
 * overflow plus alloc miss fall back to FIFO. Pinned tasks join the
 * local queue when allowed else the fallback queue in order with a single slice. Exiting tasks use the local
 * queue when allowed and the owner tree otherwise with a short slice.
 * Tasks that have no usable CPU join the fallback queue in FIFO order.
 * The tree key is the biased deadline from the floored virtual deadline.
 * Shared inserts move past the per LLC floor. They add the burst scaled
 * step to the floored time. Tasks with no usable CPU skip the floor and
 * stay FIFO. The charge scales with the effective weight. Each shared
 * enqueue checks the idle flag first, then the running deadline on the
 * target. Idle targets take an idle wake. Running targets keep running
 * unless the guarded win fires. Each running instance kicks at most once.
 * A deadline win preempts on a guarded win, else it counts a skip. A wake goes only to an idle target, else it counts a skip. The
 * kernel idle flag decides the idle wake. Wakes stay in the same LLC
 * with an allowed live target. Local inserts are not counted in the
 * shared gauge. Shared and fallback inserts count the gauge. Fallback
 * inserts also count fallback. Dequeue drops the gauge on cancel with
 * a single dec shared with the pop path. Every non duplicate ends in a
 * queue insert with the gauge paired by a saturating floor for telemetry only.
 * Masks are checked again before each wake. A task is never kicked toward a CPU outside its current
 * mask. Tree entries live in slab arena with the pid for owner lookup
 * and the biased key for order. Each entry holds forty eight bytes with
 * at most one per queued task through the queued bit plus the tree bit.
 * Three hundred
 * fifty two plus forty eight stays at four hundred within five hundred
 * twelve. An insert miss keeps the newcomer in the FIFO queue. Trees
 * hold without bound with eligibility always eligible. Fallback is best
 * effort. Each fallback cause has its own BSS counter with a pinned
 * cause split from no CPU. The wire fallback counter sums them.
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
#include <lib/sdt_task.h>
#include <lib/sdt_alloc.h>
/* Tree lookup plus empty probe live in select.bpf.h so placement reuses
 * the same helper with no duplicate. */
static __always_inline bool flow_rb_trylock(struct flow_rb_root __arena *r)
{
	if (!r)
		return false;
	return __sync_val_compare_and_swap(&r->lock, 0U, 1U) == 0U;
}
static __always_inline void flow_rb_unlock(struct flow_rb_root __arena *r)
{
	if (!r)
		return;
	/* Exchange clears the lock with BPF backend support. */
	(void)__sync_lock_test_and_set(&r->lock, 0);
}
/* Insert one entry into the owner tree with BST order and ties chained
 * right for RB_DUPLICATE-compatible order with no full RB balancing.
 * The tree is an unbalanced BST. Depth stays bound at RB_MAX_DEPTH with
 * FIFO spill on overflow. Contention plus depth overflow fall back to
 * FIFO. The insert return is the admit test as the sole test. Depth
 * sample plus max depth plus duplicate count stay BSS only with updates
 * outside the tree lock. The lock is a short try with no wait. Each walk
 * caps at thirty two steps independent of the insert bound. Lock hold
 * stays bound at depth steps. Outlined as a subprogram so enqueue plus
 * dispatch verify the walk once with the same bound. */
static __noinline bool flow_rb_insert(struct flow_rb_root __arena *r, struct flow_rb_entry __arena *e)
{
	u64 key;
	u64 cur;
	u64 parent = 0;
	u32 depth = 1;
	bool saw_dup = false;
	u32 done_depth = 0;
	bool done_dup = false;
	if (!r || !e)
		return false;
	key = READ_ONCE(e->key);
	if (!flow_rb_trylock(r)) {
		__sync_fetch_and_add(&m_fb_contention, 1ULL);
		return false;
	}
	cur = READ_ONCE(r->root);
	if (!cur) {
		WRITE_ONCE(e->node.__rb_parent_color, 0);
		WRITE_ONCE(e->node.rb_left, 0);
		WRITE_ONCE(e->node.rb_right, 0);
		WRITE_ONCE(r->root, (u64)e);
		r->cnt++;
		done_depth = 1;
		flow_rb_unlock(r);
		WRITE_ONCE(m_rb_depth, 1ULL);
		if (READ_ONCE(m_rb_depth_max) < 1ULL)
			WRITE_ONCE(m_rb_depth_max, 1ULL);
		return true;
	}
	while (cur) {
		struct flow_rb_entry __arena *c = (void __arena *)(u64)cur;
		u64 ck;
		u64 left;
		u64 right;
		if (depth > (u32)FLOW_RB_MAX_DEPTH)
			break;
		ck = READ_ONCE(c->key);
		parent = cur;
		depth++;
		if (ck == key)
			saw_dup = true;
		if (key < ck) {
			left = READ_ONCE(c->node.rb_left);
			if (!left) {
				if (depth > (u32)FLOW_RB_MAX_DEPTH) {
					flow_rb_unlock(r);
					__sync_fetch_and_add(&m_fb_depth, 1ULL);
					return false;
				}
				e->node.__rb_parent_color = parent;
				WRITE_ONCE(e->node.rb_left, 0);
				WRITE_ONCE(e->node.rb_right, 0);
				WRITE_ONCE(c->node.rb_left, (u64)e);
				r->cnt++;
				done_depth = depth;
				done_dup = saw_dup;
				flow_rb_unlock(r);
				WRITE_ONCE(m_rb_depth, (u64)done_depth);
				if ((u64)done_depth > READ_ONCE(m_rb_depth_max))
					WRITE_ONCE(m_rb_depth_max, (u64)done_depth);
				if (done_dup)
					__sync_fetch_and_add(&m_dup_chain, 1ULL);
				return true;
			}
			cur = left;
		} else {
			right = READ_ONCE(c->node.rb_right);
			if (!right) {
				if (depth > (u32)FLOW_RB_MAX_DEPTH) {
					flow_rb_unlock(r);
					__sync_fetch_and_add(&m_fb_depth, 1ULL);
					return false;
				}
				e->node.__rb_parent_color = parent;
				WRITE_ONCE(e->node.rb_left, 0);
				WRITE_ONCE(e->node.rb_right, 0);
				WRITE_ONCE(c->node.rb_right, (u64)e);
				r->cnt++;
				done_depth = depth;
				done_dup = saw_dup;
				flow_rb_unlock(r);
				WRITE_ONCE(m_rb_depth, (u64)done_depth);
				if ((u64)done_depth > READ_ONCE(m_rb_depth_max))
					WRITE_ONCE(m_rb_depth_max, (u64)done_depth);
				if (done_dup)
					__sync_fetch_and_add(&m_dup_chain, 1ULL);
				return true;
			}
			cur = right;
		}
	}
	flow_rb_unlock(r);
	__sync_fetch_and_add(&m_fb_depth, 1ULL);
	return false;
}
/* Remove one entry by key plus pid plus owner. The caller clears the
 * queued bit plus the tree bit first and owns the single dec, so no gauge
 * move happens here. Removal frees the unlinked entry with no gauge move.
 * Try lock keeps no wait. Contention leaves the entry for the next pop.
 * Each walk caps at thirty two steps independent of the insert bound.
 * Owner is checked with key plus pid. Pad2 stays reserved. Two child
 * removal uses successor splice with no orphan and no leak and a single
 * count drop. Returns true when an entry was unlinked and freed. */
static __always_inline bool flow_rb_remove(struct flow_rb_root __arena *r, u64 key, s32 pid, u32 owner)
{
	u64 cur;
	u64 parent = 0;
	bool is_left = false;
	u32 steps = 0;
	if (!r)
		return false;
	if (!flow_rb_trylock(r))
		return false;
	cur = READ_ONCE(r->root);
	while (cur && can_loop) {
		struct flow_rb_entry __arena *c = (void __arena *)(u64)cur;
		u64 ck = READ_ONCE(c->key);
		s32 cp = READ_ONCE(c->node.pid);
		u32 co = READ_ONCE(c->owner);
		if (steps >= 32U)
			break;
		steps++;
		if (ck == key && cp == pid && co == owner) {
			u64 left = READ_ONCE(c->node.rb_left);
			u64 right = READ_ONCE(c->node.rb_right);
			u64 rep = 0;
			if (left && !right) {
				rep = left;
			} else if (!left && right) {
				rep = right;
			} else if (!left && !right) {
				rep = 0;
			} else {
				u64 succ = right;
				u64 succ_parent = cur;
				u32 ssteps = 0;
				while (can_loop) {
					struct flow_rb_entry __arena *sc = (void __arena *)(u64)succ;
					u64 sleft = READ_ONCE(sc->node.rb_left);
					if (!sleft)
						break;
					if (ssteps >= 32U)
						break;
					ssteps++;
					succ_parent = succ;
					succ = sleft;
				}
				/* Bounded walk hit the step cap with a live left
				 * child still linked. Splicing now would orphan the
				 * deep successor chain, so drop the lock and fail
				 * closed with no gauge move. */
				{
					struct flow_rb_entry __arena *chk =
						(void __arena *)(u64)succ;
					if (READ_ONCE(chk->node.rb_left)) {
						flow_rb_unlock(r);
						return false;
					}
				}
				if (succ == right) {
					struct flow_rb_entry __arena *s = (void __arena *)(u64)succ;
					s->node.rb_left = left;
					if (left) {
						struct flow_rb_entry __arena *lc = (void __arena *)(u64)left;
						lc->node.__rb_parent_color = succ;
					}
					rep = succ;
				} else {
					struct flow_rb_entry __arena *s = (void __arena *)(u64)succ;
					struct flow_rb_entry __arena *sp = (void __arena *)(u64)succ_parent;
					u64 sright = READ_ONCE(s->node.rb_right);
					WRITE_ONCE(sp->node.rb_left, sright);
					if (sright) {
						struct flow_rb_entry __arena *src = (void __arena *)(u64)sright;
						src->node.__rb_parent_color = succ_parent;
					}
					s->node.rb_left = left;
					if (left) {
						struct flow_rb_entry __arena *lc = (void __arena *)(u64)left;
						lc->node.__rb_parent_color = succ;
					}
					s->node.rb_right = right;
					if (right) {
						struct flow_rb_entry __arena *rc = (void __arena *)(u64)right;
						rc->node.__rb_parent_color = succ;
					}
					rep = succ;
				}
			}
			if (!parent) {
				WRITE_ONCE(r->root, rep);
				if (rep) {
					struct flow_rb_entry __arena *rc = (void __arena *)(u64)rep;
					rc->node.__rb_parent_color = 0;
				}
			} else {
				struct flow_rb_entry __arena *par = (void __arena *)(u64)parent;
				if (is_left)
					WRITE_ONCE(par->node.rb_left, rep);
				else
					WRITE_ONCE(par->node.rb_right, rep);
				if (rep) {
					struct flow_rb_entry __arena *rc = (void __arena *)(u64)rep;
					rc->node.__rb_parent_color = parent;
				}
			}
			if (r->cnt)
				r->cnt--;
			flow_rb_unlock(r);
			scx_free(&flow_rb_alloc, c);
			return true;
		}
		parent = cur;
		if (key < ck) {
			u64 left = READ_ONCE(c->node.rb_left);
			if (!left)
				break;
			is_left = true;
			cur = left;
		} else if (key > ck) {
			u64 right = READ_ONCE(c->node.rb_right);
			if (!right)
				break;
			is_left = false;
			cur = right;
		} else {
			u64 right = READ_ONCE(c->node.rb_right);
			if (!right)
				break;
			is_left = false;
			cur = right;
		}
	}
	flow_rb_unlock(r);
	return false;
}
/* Pop the leftmost entry. The caller clears the queued bit plus the tree
 * bit first and owns the single dec on live moves only. Dead reaps free
 * with no gauge move. Counts the leftmost hit in BSS outside the lock.
 * Returns the unlinked entry. The caller owns it. Returns zero on empty
 * or contention. The walk caps at thirty two steps independent of the
 * insert bound. */
static __always_inline struct flow_rb_entry __arena *flow_rb_pop(struct flow_rb_root __arena *r)
{
	u64 cur;
	u64 parent = 0;
	struct flow_rb_entry __arena *least;
	u64 right;
	u32 steps = 0;
	if (!r)
		return 0;
	if (!flow_rb_trylock(r))
		return 0;
	cur = READ_ONCE(r->root);
	if (!cur) {
		flow_rb_unlock(r);
		return 0;
	}
	while (can_loop) {
		struct flow_rb_entry __arena *c = (void __arena *)(u64)cur;
		u64 left = READ_ONCE(c->node.rb_left);
		if (!left)
			break;
		if (steps >= 32U)
			break;
		steps++;
		parent = cur;
		cur = left;
	}
	least = (void __arena *)(u64)cur;
	right = READ_ONCE(least->node.rb_right);
	if (!parent) {
		WRITE_ONCE(r->root, right);
		if (right) {
			struct flow_rb_entry __arena *rc = (void __arena *)(u64)right;
			rc->node.__rb_parent_color = 0;
		}
	} else {
		struct flow_rb_entry __arena *p = (void __arena *)(u64)parent;
		WRITE_ONCE(p->node.rb_left, right);
		if (right) {
			struct flow_rb_entry __arena *rc = (void __arena *)(u64)right;
			rc->node.__rb_parent_color = parent;
		}
	}
	if (r->cnt)
		r->cnt--;
	flow_rb_unlock(r);
	__sync_fetch_and_add(&m_leftmost_hit, 1ULL);
	return least;
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
/* Idle wakes go only to an idle target. Each miss counts a skip
 * with no wake. Misses split by cause with no new counter. A bad
 * target skips. A masked target skips. An offline target skips.
 * A busy target skips. An idle wake ramps the target to max frequency
 * at once so the P-state ramp overlaps the IPI. Max path reuses the
 * shared mark helper with no duplicate set logic. The target is
 * checked again after the idle claim, so a stale claim skips with
 * no kick and no perf set. */
static __noinline void flow_kick_idle_only(s32 tgt, struct task_struct *p, u32 llc)
{
	u32 c;
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
	c = (u32)tgt;
	if (!flow_cpu_ok(c) || !flow_cpu_live(c)) {
		flow_stat_inc(llc, 8);
		return;
	}
	if ((u64)c >= scx_bpf_nr_cpu_ids()) {
		flow_stat_inc(llc, 8);
		return;
	}
	flow_cpuperf_mark(c, false);
	scx_bpf_kick_cpu(tgt, SCX_KICK_IDLE);
	flow_stat_inc(llc, 7);
}
/* Guarded deadline wins preempt with one kick per run. Seven steps run
 * target then idle then run then token then gap then wall then win. Each
 * miss counts a skip with no wake. Misses split by cause with no new
 * counter. A bad or masked or offline target skips. An idle target takes
 * an idle wake at max frequency. A stale run skips. An already kicked run
 * skips. A late due time past the gap skips. A fresh run under granularity
 * skips. A short tail skips unless the slice already expired at the tick.
 * A lost race skips. A changed run after the win skips, so a
 * stale kick never wakes a fresh run. The token keeps the low thirty two
 * bits of the run count, so a repeat needs four billion runs on one CPU.
 * Gates run gap then granularity then tail with no reorder. Each run kicks
 * at most once to prevent storms, so a later even earlier Virtual deadline
 * in the same run misses with no second kick. The post win tail recheck
 * keeps the same tail bound with the token already spent. An abort after
 * winning the token on the same generation restores the token, so a
 * later Virtual deadline can still preempt. */
/* Tail gate outlined so both pre-win and post-win checks verify once.
 * Returns true when the tail passes. Expired slice with zero raw passes
 * so an overrun at the tick still preempts. Integer only. */
static __noinline bool flow_kick_tail_ok(u64 raw_rem, u64 ran)
{
	u64 rem = (raw_rem > ran) ? (raw_rem - ran) : 0;
	if (raw_rem > 0 && rem < (u64)FLOW_KICK_TAIL_NS)
		return false;
	return true;
}
static __noinline void flow_kick_vd(s32 tgt, struct task_struct *p, u32 llc, s64 new_vd)
{
	const s64 vmax = (s64)0x7fffffffffffffffLL;
	struct flow_running_state *rs;
	u64 rgen;
	u32 rllc;
	u32 last;
	s64 run_vd;
	s64 win;
	u64 start;
	u64 now;
	u64 ran;
	u64 raw_rem;
	u32 c;
	u64 fresh_gen;
	s64 fresh_vd;
	u64 fresh_raw_rem;
	/* Step one of seven keeps the target gate. A bad or masked or
	 * offline target skips with no wake. */
	if (tgt < 0 || !p || !flow_cpu_ok((u32)tgt) || !flow_cpu_allowed(tgt, p) ||
	    !flow_cpu_live((u32)tgt)) {
		flow_stat_inc(llc, 8);
		return;
	}
	/* Step two of seven keeps the idle fast path. An idle target takes
	 * an idle wake at max frequency with no preempt. The target is
	 * checked again after the idle claim, so a stale claim skips with
	 * no kick and no perf set. */
	if (scx_bpf_test_and_clear_cpu_idle(tgt)) {
		c = (u32)tgt;
		if (!flow_cpu_ok(c) || !flow_cpu_live(c)) {
			flow_stat_inc(llc, 8);
			return;
		}
		if ((u64)c >= scx_bpf_nr_cpu_ids()) {
			flow_stat_inc(llc, 8);
			return;
		}
		flow_cpuperf_mark(c, false);
		scx_bpf_kick_cpu(tgt, SCX_KICK_IDLE);
		flow_stat_inc(llc, 7);
		return;
	}
	/* Reassert the bound on the index used below so the verifier
	 * keeps the range across the calls above. The barrier keeps the
	 * compiler from folding the check away with the earlier one. */
	c = (u32)tgt;
	asm volatile ("" : "+r" (c));
	if (c >= (u32)FLOW_MAX_CPUS) {
		flow_stat_inc(llc, 8);
		return;
	}
	rs = &flow_running_state[c];
	rgen = READ_ONCE(rs->gen);
	rllc = READ_ONCE(rs->llc_id);
	/* Step three of seven keeps the run gate. A stale run skips. */
	if (!rgen || !flow_llc_ok(rllc) || rllc != llc) {
		flow_stat_inc(llc, 8);
		return;
	}
	last = READ_ONCE(rs->pad);
	/* Step four of seven keeps the token gate. An already kicked run
	 * skips. */
	if ((u32)rgen == last) {
		flow_stat_inc(llc, 8);
		return;
	}
	run_vd = READ_ONCE(rs->vd);
	/* Step five of seven keeps the gap gate. The win needs the new due
	 * time plus the gap below the running due time with signed
	 * saturation, else a late due time skips. */
	win = new_vd;
	if (win >= vmax - (s64)FLOW_KICK_GAP_NS)
		win = vmax;
	else
		win += (s64)FLOW_KICK_GAP_NS;
	if (!(win < run_vd)) {
		flow_stat_inc(llc, 8);
		return;
	}
	/* Step six of seven keeps the wall gates. A fresh run under
	 * granularity skips on a tear free heuristic read, then a short
	 * tail skips on a tear free heuristic read unless the slice already
	 * expired at the tick. A heuristic skip can miss a preempt with
	 * dispatch still correct. Wraparound reads zero. */
	start = READ_ONCE(rs->start_ts);
	now = bpf_ktime_get_ns();
	ran = flow_lag_clamp(now > start ? now - start : 0);
	if (ran < (u64)FLOW_KICK_GRAN_NS) {
		flow_stat_inc(llc, 8);
		return;
	}
	raw_rem = READ_ONCE(rs->slice_rem);
	/* Only skip when raw_rem > 0 (not already expired at tick) and
	 * the tail is short. When raw_rem == 0 the task already overran
	 * its slice at the tick, so bypass the tail gate. Outlined. */
	if (!flow_kick_tail_ok(raw_rem, ran)) {
		flow_stat_inc(llc, 8);
		return;
	}
	/* Step seven of seven wins the token then rechecks the run. A lost
	 * race skips with the token spent, so each run still kicks at most
	 * once. */
	if (__sync_val_compare_and_swap(&rs->pad, last, (u32)rgen) != last) {
		flow_stat_inc(llc, 8);
		return;
	}
	/* Freshness check after the win. The run may have ended and
	 * the mask may have moved while winning the token. A changed
	 * run skips with the token spent, so each run still kicks at
	 * most once. A short tail after the win skips with the token
	 * restored on the same generation to avoid a wasted preempt on
	 * a tail below the bound. */
	if (!flow_cpu_allowed(tgt, p) || !flow_cpu_live((u32)tgt) ||
	    (u64)c >= scx_bpf_nr_cpu_ids()) {
		(void)__sync_val_compare_and_swap(&rs->pad, (u32)rgen, last);
		flow_stat_inc(llc, 8);
		return;
	}
	fresh_gen = READ_ONCE(rs->gen);
	if (fresh_gen != rgen) {
		flow_stat_inc(llc, 8);
		return;
	}
	fresh_vd = READ_ONCE(rs->vd);
	if (!(win < fresh_vd)) {
		(void)__sync_val_compare_and_swap(&rs->pad, (u32)rgen, last);
		flow_stat_inc(llc, 8);
		return;
	}
	fresh_raw_rem = READ_ONCE(rs->slice_rem);
	if (!flow_kick_tail_ok(fresh_raw_rem, ran)) {
		(void)__sync_val_compare_and_swap(&rs->pad, (u32)rgen, last);
		flow_stat_inc(llc, 8);
		return;
	}
	/* The running CPU keeps its LLC for the whole run, so this recheck
	 * always holds and only states the bound in the open. */
	rllc = READ_ONCE(rs->llc_id);
	if (!flow_llc_ok(rllc) || rllc != llc) {
		flow_stat_inc(llc, 8);
		return;
	}
	scx_bpf_kick_cpu(tgt, SCX_KICK_PREEMPT);
	flow_stat_inc(llc, 6);
}
/* Request structs keep subprograms within five args with no logic change.
 * Each struct packs scalars only with integer fields and no new loop. */
struct flow_insert_req {
	u64 dl;
	u64 slice;
	u64 enq_flags;
	s32 tgt;
	u32 llc;
	bool no_cpu;
	bool count_queued;
};
struct flow_noctx_req {
	s64 raw_v;
	u64 enq_flags;
	bool no_cpu;
};
struct flow_post_req {
	s64 raw_v;
	u64 enq_flags;
	s32 tgt;
	u32 llc;
	bool no_cpu;
	bool pinned;
};
/* Shared insert folds three copies of trylock plus alloc plus init plus
 * insert plus fallback with no semantic change. The caller passes the
 * biased key plus the owner plus the fallback slice plus the enqueue flags
 * plus the queue index plus whether the shared gauge counts. A null task
 * context skips the arena slot plus the tree bit plus the gauge. The
 * insert return stays as the sole test with depth bound kept short. The
 * gauge stays balanced with paired counts for telemetry only. */
static __noinline bool flow_enqueue_insert_shared(struct task_struct *p, struct flow_task_ctx *t,
						  const struct flow_insert_req *req)
{
	struct flow_rb_root __arena *rb;
	bool fell = true;
	s32 tgt;
	bool no_cpu;
	u64 dl;
	u64 slice;
	u64 enq_flags;
	u32 llc;
	bool count_queued;
	if (!p || !req)
		return false;
	tgt = req->tgt;
	no_cpu = req->no_cpu;
	dl = req->dl;
	slice = req->slice;
	enq_flags = req->enq_flags;
	llc = req->llc;
	count_queued = req->count_queued;
	if (t) {
		t->llc_id = llc;
		t->run_pad = (u32)(tgt < 0 ? 0 : tgt);
	}
	rb = (no_cpu || tgt < 0 || !flow_cpu_live((u32)tgt)) ? 0 : flow_rb_for_cpu(tgt);
	if (!rb) {
		__sync_fetch_and_add(&m_fb_nocpu, 1ULL);
	} else if (!flow_rb_trylock(rb)) {
		__sync_fetch_and_add(&m_fb_contention, 1ULL);
	} else {
		flow_rb_unlock(rb);
		{
			struct flow_rb_entry __arena *e = scx_alloc(&flow_rb_alloc);
			if (!e) {
				__sync_fetch_and_add(&m_fb_alloc, 1ULL);
			} else {
				bool have_mem = true;
				void __arena *mem = 0;
				if (t) {
					mem = __scx_task_data(p);
					if (!mem) {
						have_mem = false;
					} else {
						struct flow_arena_task __arena *at = mem;
						WRITE_ONCE(at->storage[0], dl);
					}
				}
				if (!have_mem) {
					scx_free(&flow_rb_alloc, e);
				} else {
					WRITE_ONCE(e->node.__rb_parent_color, 0);
					WRITE_ONCE(e->node.rb_left, 0);
					WRITE_ONCE(e->node.rb_right, 0);
					WRITE_ONCE(e->node.pid, p->pid);
					WRITE_ONCE(e->node.pad, 0U);
					WRITE_ONCE(e->key, dl);
					WRITE_ONCE(e->owner, (u32)tgt);
					WRITE_ONCE(e->pad2, 0U);
					/* Depth bound keeps the walk short. The insert
					 * return stays as the sole test. */
					if (flow_rb_insert(rb, e)) {
						fell = false;
						if (t)
							__sync_fetch_and_or(&t->flags, (u32)FLOW_FLAG_IN_RB);
					} else {
						scx_free(&flow_rb_alloc, e);
					}
				}
			}
		}
	}
	if (fell)
		scx_bpf_dsq_insert(p, (u64)FLOW_FALLBACK_DSQ, slice, enq_flags);
	if (count_queued)
		flow_stat_inc(llc, 0);
	if (fell)
		flow_stat_inc(llc, 2);
	return !fell;
}
/* Cold exiting plus pinned paths run outside the hot shared path with no
 * semantic change. The no context helper covers a missing task context
 * with a local queue for an allowed exiting target else the shared insert
 * else the fallback for an alloc miss. The pre helper covers the local
 * queues before the queued bit with no gauge move. The post helper covers
 * the fallback inserts after the queued bit with the gauge paired. Each
 * helper keeps the same order of exiting before pinned with the same
 * slices and the same kicks. */
static __noinline void flow_enqueue_cold_noctx(struct task_struct *p, s32 tgt, u32 llc,
					       const struct flow_noctx_req *req)
{
	bool no_cpu;
	s64 raw_v;
	u64 enq_flags;
	if (!req)
		return;
	no_cpu = req->no_cpu;
	raw_v = req->raw_v;
	enq_flags = req->enq_flags;
	if ((p->flags & PF_EXITING) && tgt >= 0 && flow_cpu_allowed(tgt, p)) {
		u64 ldsq = (u64)SCX_DSQ_LOCAL_ON | (u64)(u32)tgt;
		scx_bpf_dsq_insert(p, ldsq, (u64)FLOW_EXIT_SLICE_NS, enq_flags);
		flow_kick_idle_only(tgt, p, llc);
		return;
	}
	if (p->flags & PF_EXITING) {
		u64 dl = flow_rb_deadline(raw_v);
		struct flow_insert_req ireq;
		ireq.tgt = tgt;
		ireq.no_cpu = no_cpu;
		ireq.dl = dl;
		ireq.slice = (u64)FLOW_EXIT_SLICE_NS;
		ireq.enq_flags = enq_flags;
		ireq.llc = llc;
		ireq.count_queued = false;
		(void)flow_enqueue_insert_shared(p, 0, &ireq);
		flow_kick_idle_only(tgt, p, llc);
		return;
	}
	{
		u64 sl = (u64)FLOW_SLICE_MIN_NS;
		__sync_fetch_and_add(&m_fb_alloc, 1ULL);
		scx_bpf_dsq_insert(p, (u64)FLOW_FALLBACK_DSQ, sl, enq_flags);
		flow_stat_inc(llc, 2);
		flow_kick_idle_only(tgt, p, llc);
		return;
	}
}
static __noinline bool flow_enqueue_cold_pre(struct task_struct *p, s32 tgt, u32 llc, u64 enq_flags, bool pinned)
{
	if (p->flags & PF_EXITING) {
		if (tgt >= 0 && flow_cpu_allowed(tgt, p)) {
			u64 ldsq = (u64)SCX_DSQ_LOCAL_ON | (u64)(u32)tgt;
			scx_bpf_dsq_insert(p, ldsq, (u64)FLOW_EXIT_SLICE_NS, enq_flags);
			flow_kick_idle_only(tgt, p, llc);
			return true;
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
				return true;
			}
		}
	}
	return false;
}
static __noinline bool flow_enqueue_cold_post(struct task_struct *p, struct flow_task_ctx *t,
					      const struct flow_post_req *req)
{
	s32 tgt;
	u32 llc;
	bool no_cpu;
	s64 raw_v;
	u64 enq_flags;
	bool pinned;
	if (!req)
		return false;
	tgt = req->tgt;
	llc = req->llc;
	no_cpu = req->no_cpu;
	raw_v = req->raw_v;
	enq_flags = req->enq_flags;
	pinned = req->pinned;
	if (p->flags & PF_EXITING) {
		u64 dl = flow_rb_deadline(raw_v);
		struct flow_insert_req ireq;
		ireq.tgt = tgt;
		ireq.no_cpu = no_cpu;
		ireq.dl = dl;
		ireq.slice = (u64)FLOW_EXIT_SLICE_NS;
		ireq.enq_flags = enq_flags;
		ireq.llc = llc;
		ireq.count_queued = true;
		(void)flow_enqueue_insert_shared(p, t, &ireq);
		flow_kick_idle_only(tgt, p, llc);
		return true;
	}
	if (pinned) {
		t->llc_id = llc;
		t->run_pad = (u32)(tgt < 0 ? 0 : tgt);
		__sync_fetch_and_add(&m_fb_pinned, 1ULL);
		scx_bpf_dsq_insert(p, (u64)FLOW_FALLBACK_DSQ, (u64)FLOW_SLICE_MIN_NS, enq_flags);
		flow_stat_inc(llc, 0);
		flow_stat_inc(llc, 2);
		/* No owner tree took the task. Kick self when idle so the
		 * fallback head is peeked again soon. */
		flow_kick_idle_only((s32)bpf_get_smp_processor_id(), p, llc);
		return true;
	}
	return false;
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
		struct flow_noctx_req nreq;
		nreq.no_cpu = no_cpu;
		nreq.raw_v = raw_v;
		nreq.enq_flags = enq_flags;
		flow_enqueue_cold_noctx(p, tgt, llc, &nreq);
		return;
	}
	/* Local placements run before ownership is taken. A task on a
	 * local queue is not counted in the shared gauge, so it leaves
	 * without the queued bit. Shared and fallback inserts take the
	 * bit below and count the gauge together. Outlined cold pre keeps
	 * the same order with no gauge move. */
	if (flow_enqueue_cold_pre(p, tgt, llc, enq_flags, pinned))
		return;
	old_flags = __sync_fetch_and_or(&t->flags, (u32)FLOW_FLAG_QUEUED);
	if (old_flags & (u32)FLOW_FLAG_QUEUED) {
		/* Single slot per task through the queued bit. A duplicate
		 * requeue drops with the duplicate count only and no gauge
		 * move and no fallback move and no extra probe, so the
		 * backlog stays within the live task count with FIFO order
		 * kept and no new counter. */
		flow_stat_inc(llc, 4);
		return;
	}
	/* Cold post keeps exiting before pinned with the same slices and
	 * the same kicks as the open code. */
	{
		struct flow_post_req preq;
		preq.tgt = tgt;
		preq.llc = llc;
		preq.no_cpu = no_cpu;
		preq.raw_v = raw_v;
		preq.enq_flags = enq_flags;
		preq.pinned = pinned;
		if (flow_enqueue_cold_post(p, t, &preq))
			return;
	}
	{
		/* Shared inserts join the order past the floor. Tasks with no
		 * usable CPU skip the floor, and fallback inserts stay FIFO.
		 * Trees hold without bound with pure deadline order
		 * and a single kick. An insert miss keeps the newcomer in
		 * FIFO with no evict. Unknown tasks price by the true EEVDF
		 * quantum minus bounded virtual lag credit, while steady
		 * tasks price by the smoothed kept max with a complementary
		 * response due time. Enqueue reads the smoothed reference from
		 * the cached flag with no clock and no scan. Wait comes
		 * from the floor advance with no new clock and no scan.
		 * The fallback prices the due time with the shared charge
		 * path first. The gated response replaces both the due time
		 * and the slice only when every input proves usable. */
		s64 base = READ_ONCE(t->vtime);
		u32 w = flow_eff_w(flow_nice_weight(p), flow_share_live(p));
		s64 floored = no_cpu ? base : flow_seq_floor(llc, base);
		u64 W = (base > 0 && floored > base) ? (u64)(floored - base) : (u64)0;
		s64 vd;
		u64 slice_len;
		u64 sref;
		if (W > (u64)FLOW_RUN_WIN_NS)
			W = (u64)FLOW_RUN_WIN_NS;
		sref = flow_smoothed_ref(t);
		/* Single Virtual deadline branch with no overwrite. Unpredicted
		 * tasks run pure EEVDF with 1ms quantum and lag credit. Predicted
		 * tasks run custom-quantum EEVDF complemented by HRRN when the
		 * gate holds, else the smoothed run value. One charge per path. */
		if (!sref) {
			vd = flow_eevdf_vd(floored, W, w);
			slice_len = (u64)FLOW_SLICE_MIN_NS;
		} else {
			u64 eff = flow_smoothed_eff(sref, READ_ONCE(t->burst_ns));
			slice_len = flow_run_slice(sref);
			if (hrrn_ready(t, sref, eff, W, eff, w, no_cpu))
				vd = vd_HRRN(floored, W, eff, w);
			else
				vd = flow_run_vd(floored, eff, w);
		}
		t->vtime = floored;
		t->vd = vd;
		t->slice_rem = slice_len;
		/* Mirror the due time beside the stored time. Later reads see
		 * the same due time for order checks. The shared insert sets
		 * the queue index plus the owner pad plus the stored key plus
		 * the tree bit with the same values as the open code. */
		scx_bpf_task_set_dsq_vtime(p, vd);
		/* An insert miss keeps the newcomer in FIFO. Contention is
		 * probed before the alloc with no wasted slab on busy. Stored
		 * key keeps remove stable past later due time moves. Tree bit
		 * marks tree members for a direct remove with no wasted walk
		 * on fallback members. Shared helper holds the sole test. */
		{
			u64 dl = flow_rb_deadline(vd);
			struct flow_insert_req ireq;
			ireq.tgt = tgt;
			ireq.no_cpu = no_cpu;
			ireq.dl = dl;
			ireq.slice = slice_len;
			ireq.enq_flags = enq_flags;
			ireq.llc = llc;
			ireq.count_queued = true;
			(void)flow_enqueue_insert_shared(p, t, &ireq);
		}
		if (no_cpu) {
			/* No usable CPU. Kick self when idle so the
			 * fallback head is peeked again soon. */
			flow_kick_idle_only((s32)bpf_get_smp_processor_id(), p, llc);
			return;
		}
		flow_kick_vd(tgt, p, llc, vd);
		return;
	}
}
void BPF_STRUCT_OPS(flow_dequeue, struct task_struct *p, u64 deq_flags)
{
	struct flow_task_ctx *t;
	u32 old;
	u32 owner = 0;
	u64 key = 0;
	bool have_key = false;
	void __arena *mem;
	(void)deq_flags;
	if (!p)
		return;
	t = bpf_task_storage_get(&task_ctx_stor, p, 0, 0);
	if (!t)
		return;
	mem = __scx_task_data(p);
	owner = READ_ONCE(t->run_pad);
	if (mem) {
		struct flow_arena_task __arena *at = mem;
		u64 sk = READ_ONCE(at->storage[0]);
		if (sk) {
			key = sk;
			have_key = true;
		}
	}
	old = __sync_fetch_and_and(&t->flags,
				      (u32)~((u32)FLOW_FLAG_QUEUED | (u32)FLOW_FLAG_IN_RB));
	if (old & (u32)FLOW_FLAG_QUEUED) {
		u32 dllc = READ_ONCE(t->llc_id);
		if (!flow_llc_ok(dllc))
			dllc = 0;
		flow_queued_dec(dllc);
		/* Drop the tree entry when the tree bit shows it is still
		 * linked. The gauge was just dropped. Removal frees with no
		 * gauge move. Contention leaves the entry for the next pop.
		 * Stored key keeps remove stable past later due time moves.
		 * Fallback tasks skip the walk with no wasted search. */
		if ((old & (u32)FLOW_FLAG_IN_RB) && have_key && flow_cpu_ok(owner)) {
			struct flow_rb_root __arena *rb = flow_rb_for_cpu((s32)owner);
			flow_rb_remove(rb, key, p->pid, owner);
		}
	}
}
#endif
