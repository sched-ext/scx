// SPDX-License-Identifier: GPL-2.0
/*
 * Fair charging for the flow scheduler.
 *
 * The base charge scales with the effective weight. Values saturate at
 * the top. The task nice weight comes from a small table over minus
 * twenty to nineteen with zero as one hundred, read from the task
 * static priority minus one hundred twenty. Out of range tasks keep
 * the default. The live share reads as the default with clamp to one
 * through ten thousand and no map. The hierarchy walk stays out of
 * budget, so misses keep nice only. The effective weight keeps the
 * smaller of the two clamped weights with no divide, so the tighter
 * bound governs.
 * Fresh times move past the per LLC floor through a short
 * compare and swap loop, so stored times stay best effort unique with
 * the winner publishing its value at once. When the loop loses
 * too often, the last observed value plus one is stored directly
 * with no further retry. A rare duplicate keeps insertion order with
 * no extra promise. An invalid LLC skips the floor and keeps
 * the input time directly. The floor rises over time and never
 * moves backward for a given LLC. When the time runs ahead of the
 * floor, the floor moves up by at most one floor step per enqueue,
 * so one far time cannot pull the floor with it. The fallback stores
 * nothing when the time runs ahead, so uniqueness stays best effort.
 * The base constant stays kept unused reserved with no reader. Virtual deadline adds the burst scaled effective step
 * to the floored time through the shared charge path, so a larger
 * effective weight or a shorter run gives an earlier due time with no extra
 * divide. Two level vruntime keeps vtime as charged service plus due time
 * as the floored time plus the burst scaled step with lag clamped at
 * LAG_MAX with integer only. Lag caps at eight milliseconds
 * with saturation at zero on skew and at LAG_MAX on excess and no wrap.
 * Burst holds the last run length between the floor and
 * one slice with shift only moves. Run keeps
 * eight recent run lengths with close stamps plus the kept range plus
 * a stable flag plus the current sum, so steady tasks price by the
 * kept max with short tasks keeping the burst path with a floor slice
 * and long tasks in one slice quanta.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
#ifndef __FLOW_FAIR_BPF_H
#define __FLOW_FAIR_BPF_H
#include "intf.h"
#include "maps.bpf.h"
#include <lib/sdt_alloc.h>
/* Slab for BST entries with one entry per queued task at most through
 * the queued bit, so the backlog stays within the live task count. */
static struct scx_allocator flow_rb_alloc;
/* Nice weight on the weight scale from minus twenty to nineteen.
 * Strictly falls from ten thousand to one with one hundred at zero.
 * Fits in read only data with direct indexing and no loop. */
static const u32 flow_nice_table[40] = {
	10000, 7943, 6310, 5012, 3981, 3162, 2512, 1995,
	1585, 1259, 1000, 794, 631, 501, 398, 316,
	251, 200, 158, 126, 100, 78, 62, 48,
	38, 30, 23, 18, 14, 11, 10, 9,
	8, 7, 6, 5, 4, 3, 2, 1,
};
static __always_inline u32 flow_nice_weight(const struct task_struct *p)
{
	s32 prio;
	u32 idx;
	if (!p)
		return (u32)FLOW_CGROUP_WEIGHT_DFLT;
	prio = p->static_prio - 120;
	if (prio < -20 || prio > 19)
		return (u32)FLOW_CGROUP_WEIGHT_DFLT;
	idx = (u32)(prio + 20);
	if (idx >= 40U)
		return (u32)FLOW_CGROUP_WEIGHT_DFLT;
	return flow_nice_table[idx];
}
/* Live share with miss default and clamp and no map. The hierarchy walk
 * stays out of budget, so this keeps the default with nice only and no
 * extra table and no new op by design. */
static __always_inline u32 flow_share_live(const struct task_struct *p)
{
	(void)p;
	return (u32)FLOW_CGROUP_WEIGHT_DFLT;
}
/* Effective weight from nice plus share with clamp only and no divide.
 * Each side clamps to one through ten thousand with miss default one
 * hundred. A default side keeps the other side, else the smaller wins,
 * so the tighter bound governs with integer only and bounded cost. */
static __always_inline u32 flow_eff_w(u32 nw, u32 sw)
{
	u32 n = nw;
	u32 s = sw;
	if (n == (u32)FLOW_CGROUP_WEIGHT_INVALID || n < (u32)FLOW_CGROUP_WEIGHT_MIN)
		n = (u32)FLOW_CGROUP_WEIGHT_DFLT;
	else if (n > (u32)FLOW_CGROUP_WEIGHT_MAX)
		n = (u32)FLOW_CGROUP_WEIGHT_MAX;
	if (s == (u32)FLOW_CGROUP_WEIGHT_INVALID || s < (u32)FLOW_CGROUP_WEIGHT_MIN)
		s = (u32)FLOW_CGROUP_WEIGHT_DFLT;
	else if (s > (u32)FLOW_CGROUP_WEIGHT_MAX)
		s = (u32)FLOW_CGROUP_WEIGHT_MAX;
	if (s == (u32)FLOW_CGROUP_WEIGHT_DFLT)
		return n;
	if (n == (u32)FLOW_CGROUP_WEIGHT_DFLT)
		return s;
	return n < s ? n : s;
}
/* Effective step from one slice over weight. The base step equals one
 * slice times the default weight divided by the clamped weight, so the
 * step spans ten thousand at weight ten thousand through one million at
 * weight one hundred to one hundred million at weight one. The table
 * below gives weight against step and the scaled floor at sixty two
 * thousand five hundred. Weight one hundred steps one million with a
 * scaled floor of sixty two thousand five hundred. Weight ten thousand
 * steps ten thousand with a scaled floor of six hundred twenty five.
 * Weight one steps one hundred million with a scaled floor of six
 * million two hundred fifty thousand. Integer divide only with no
 * rounding beyond the divide. */
static __always_inline u64 flow_fair_step(u32 w)
{
	u32 cw = w;
	if (cw == (u32)FLOW_CGROUP_WEIGHT_INVALID || cw < (u32)FLOW_CGROUP_WEIGHT_MIN)
		cw = (u32)FLOW_CGROUP_WEIGHT_DFLT;
	if (cw > (u32)FLOW_CGROUP_WEIGHT_MAX)
		cw = (u32)FLOW_CGROUP_WEIGHT_MAX;
	if (!cw)
		return (u64)FLOW_SLICE_MIN_NS;
	return (u64)FLOW_SLICE_MIN_NS * (u64)FLOW_CGROUP_WEIGHT_DFLT / (u64)cw;
}
static __always_inline s64 flow_fair_cap_add(s64 base, u64 add)
{
	const s64 vmax = (s64)0x7fffffffffffffffLL;
	if (add > (u64)vmax)
		return vmax;
	if (base >= vmax - (s64)add)
		return vmax;
	return base + (s64)add;
}
/* Lag clamp at eight milliseconds with integer only. Lag is now minus
 * start. Skew saturates at zero. Excess saturates at LAG_MAX. The clamp
 * counts the lag sample in BSS. Kick path only with no pricing use.
 * Pricing stays vruntime only. */
static __always_inline u64 flow_lag_clamp(u64 lag)
{
	if (lag > (u64)FLOW_LAG_MAX_NS) {
		__sync_fetch_and_add(&m_lag_clamp, 1ULL);
		return (u64)FLOW_LAG_MAX_NS;
	}
	return lag;
}
/* Tree order is plain BST. Leftmost wins. Ties chain right. Order
 * matches RB_DUPLICATE-compatible order with no full RB balancing.
 * The tree is an unbalanced BST. Depth stays bound at RB_MAX_DEPTH.
 * Contention plus depth overflow plus alloc miss fall back to FIFO.
 * Order is pure deadline with bias. Dl equals vd plus 0x8000000000000000.
 * Unsigned compare matches signed order. Nodes live in slab memory.
 * The node holds thirty two bytes plus key plus owner. Task slots stay
 * reserved at one hundred thirty six. The per queued worst stays at four
 * hundred within five hundred twelve. Roots use try locks. Contention
 * falls back with no wait. Leftmost walks use the bounded hold. The loop
 * budget stays at six. Depth is a last sample plus a max sample. Duplicate
 * counts equal keys. Leftmost counts pops. All stay BSS only.
 * No rotations run. Order stays straight line. */
static __always_inline u64 flow_rb_deadline(s64 vd)
{
	return (u64)vd + 0x8000000000000000ULL;
}
/* Overflow bound with the burst clamp. The due time path feeds at most
 * one slice, so hi stays at most one with lo below one slice and the
 * scaled sum stays at most twice the step with two hundred million as
 * the top at weight one. The general path keeps the hi guard plus the
 * saturating add with no wrap. */
static __always_inline s64 flow_fair_charge(s64 base, u64 used, u32 w)
{
	const s64 vmax = (s64)0x7fffffffffffffffLL;
	u64 st = flow_fair_step(w);
	u64 slice = (u64)FLOW_SLICE_MIN_NS;
	u64 hi;
	u64 lo;
	u64 scaled;
	if (!st)
		st = (u64)FLOW_SLICE_MIN_NS;
	if (!slice)
		slice = (u64)FLOW_SLICE_MIN_NS;
	hi = used / slice;
	lo = used % slice;
	if (hi > (u64)vmax / st)
		return vmax;
	scaled = hi * st + lo * st / slice;
	if (scaled > (u64)vmax)
		return vmax;
	return flow_fair_cap_add(base, scaled);
}
/* Burst stays between the floor and one slice. A zero or past slice
 * value snaps to one slice and a short value snaps to the floor.
 * Shift moves keep the update without divide. */
static __always_inline u64 flow_burst_clamp(u64 burst_ns)
{
	if (!burst_ns || burst_ns > (u64)FLOW_SLICE_MIN_NS)
		return (u64)FLOW_SLICE_MIN_NS;
	if (burst_ns < (u64)FLOW_SLICE_FLOOR_NS)
		return (u64)FLOW_SLICE_FLOOR_NS;
	return burst_ns;
}
static __always_inline s64 flow_vd_for(s64 floored, u64 burst_ns, u32 w)
{
	u64 b = flow_burst_clamp(burst_ns);
	s64 vd = flow_fair_charge(floored, b, w);
	if (vd <= floored)
		return flow_fair_cap_add(floored, 1);
	return vd;
}
/* Track the last run length. An overrun snaps to one slice. A run
 * that ends early while still runnable only moves up past the old
 * value by a quarter of the gap and holds otherwise, since the stop cut the
 * run short. A sleep moves by a quarter toward the run length. */
static __always_inline u64 flow_burst_update(u64 old_burst, u64 total_used,
					     u64 cur, bool runnable)
{
	u64 b = flow_burst_clamp(old_burst);
	u64 u = total_used;
	if (u > (u64)FLOW_SLICE_MIN_NS)
		u = (u64)FLOW_SLICE_MIN_NS;
	if (!cur)
		return (u64)FLOW_SLICE_MIN_NS;
	if (runnable) {
		if (u > b)
			b = b - (b >> 2) + (u >> 2);
		return flow_burst_clamp(b);
	}
	b = b - (b >> 2) + (u >> 2);
	return flow_burst_clamp(b);
}
/* Smoothed pricing folds five run observables with one shared shift gain.
 * Burst length plus ring durations plus ring stamps plus run sum plus kept
 * range feed one effective duration with shift only and saturation. The gain
 * stays at one quarter for all five criteria with no per criterion tuning.
 * New value equals old minus the quarter of old plus the quarter of sample.
 * A zero sample freezes with no move. A zero old takes the sample as init.
 * Saturation uses the shared cap helper with slice caps where bounded. A
 * backward clock freezes prune and close with no ring move. The smoothed
 * reference derives from the kept max in the ring with zero new bytes. The
 * effective value keeps the larger of reference and burst with a slice cap.
 * Order holds since a larger effective value never yields an earlier virtual
 * deadline. The global fold counts recalc passes in BSS only with no wire
 * bytes. Read the counters with a BSS dump. Enqueue prices stable tasks by
 * the smoothed reference through the shared charge path with unknown tasks
 * keeping the burst path. Lag clamp stays on the kick path with no pricing
 * use there. */
u64 m_ewma_fold;
u64 m_ewma_sat;
u64 m_ewma_freeze;
static __always_inline u64 flow_ewma_next(u64 old, u64 sample)
{
	if (!sample)
		return old;
	if (!old)
		return sample;
	return old - (old >> 2) + (sample >> 2);
}
/* Smoothed reference for the enqueue known path with a BSS fold count.
 * Unknown tasks return zero with a freeze count, so the caller keeps
 * the burst path. Stable tasks price by this value with no clock and
 * no scan. */
static __always_inline u64 flow_smoothed_ref(struct flow_task_ctx *t)
{
	u64 ref;
	if (!t)
		return 0;
	if (!READ_ONCE(t->run_known))
		return 0;
	ref = READ_ONCE(t->run_max);
	__sync_fetch_and_add(&m_ewma_fold, 1ULL);
	if (!ref)
		__sync_fetch_and_add(&m_ewma_freeze, 1ULL);
	return ref;
}
/* Smoothed effective duration for the enqueue known path from reference
 * plus burst with max and slice cap. Larger input never yields an earlier
 * virtual deadline. Saturation at the slice cap counts in BSS. Enqueue
 * feeds this value to the shared charge path. */
static __always_inline u64 flow_smoothed_eff(u64 ref, u64 burst_ns)
{
	u64 b = flow_burst_clamp(burst_ns);
	u64 e = ref > b ? ref : b;
	if (e > (u64)FLOW_SLICE_MIN_NS) {
		__sync_fetch_and_add(&m_ewma_sat, 1ULL);
		e = (u64)FLOW_SLICE_MIN_NS;
	}
	return e;
}
static __always_inline s64 flow_seq_floor(u32 llc, s64 v)
{
	const s64 vmax = (s64)0x7fffffffffffffffLL;
	int i;
	if (!flow_llc_ok(llc))
		return v;
	for (i = 0; i < 4; i++) {
		s64 last = READ_ONCE(flow_llc_seq[llc]);
		s64 want = v;
		s64 next;
		if (want <= last) {
			if (last == vmax)
				want = last;
			else
				want = last + 1;
			next = want;
		} else {
			s64 cap = flow_fair_cap_add(last, (u64)FLOW_SEQ_FLOOR_STEP_NS);
			if (want < cap)
				next = want;
			else
				next = cap;
		}
		if (__sync_val_compare_and_swap(&flow_llc_seq[llc], last, next) == last)
			return want;
	}
	{
		s64 last = READ_ONCE(flow_llc_seq[llc]);
		s64 want = v;
		if (want <= last) {
			if (last == vmax)
				want = last;
			else
				want = last + 1;
			flow_llc_seq[llc] = want;
		}
		return want;
	}
}
 /* Recent run lengths with close stamps. The ring holds eight pairs
  * with the next slot masked by seven. Total holds the current run
  * sum capped at thirty seconds. Prune drops stamps past the window
  * and freezes on a zero or backward clock. Close pushes the sum on
  * sleep only, so tasks that never sleep stay unknown. The stable
  * flag needs four kept plus a four second span plus a tight range
  * with short tasks stable under the floor. Enqueue reads the cached
  * flag with no clock and no scan. Integer only with bounded scans. */
static __always_inline void flow_run_reset(struct flow_task_ctx *t)
{
	int i;
	if (!t)
		return;
	for (i = 0; i < 8; i++) {
		t->run_dur[i] = 0;
		t->run_stamp[i] = 0;
	}
	t->run_min = 0;
	t->run_max = 0;
	t->run_total = 0;
	t->run_head = 0;
	t->run_pruned = 0;
	t->run_known = 0;
	t->run_pad = 0;
}
static __always_inline void flow_run_add(struct flow_task_ctx *t, u64 delta)
{
	u64 cur;
	u64 win;
	if (!t || !delta)
		return;
	win = (u64)FLOW_RUN_WIN_NS;
	if (delta > win)
		delta = win;
	cur = READ_ONCE(t->run_total);
	if (cur >= win)
		return;
	if (delta >= win - cur)
		t->run_total = win;
	else
		t->run_total = cur + delta;
}
static __always_inline void flow_run_recalc(struct flow_task_ctx *t)
{
	u64 min_d = 0;
	u64 max_d = 0;
	u64 min_s = 0;
	u64 max_s = 0;
	u64 kept = 0;
	bool have = false;
	int i;
	if (!t)
		return;
	__sync_fetch_and_add(&m_ewma_fold, 1ULL);
	for (i = 0; i < 8; i++) {
		u64 d = READ_ONCE(t->run_dur[i]);
		u64 s = READ_ONCE(t->run_stamp[i]);
		if (!d || !s)
			continue;
		if (!have) {
			min_d = d;
			max_d = d;
			min_s = s;
			max_s = s;
			have = true;
		} else {
			if (d < min_d)
				min_d = d;
			if (d > max_d)
				max_d = d;
			if (s < min_s)
				min_s = s;
			if (s > max_s)
				max_s = s;
		}
		kept++;
	}
	if (!have) {
		t->run_min = 0;
		t->run_max = 0;
		t->run_known = 0;
		__sync_fetch_and_add(&m_ewma_freeze, 1ULL);
		return;
	}
	t->run_min = min_d;
	t->run_max = max_d;
	if (max_d < (u64)FLOW_SLICE_FLOOR_NS) {
		t->run_known = 1;
		__sync_fetch_and_add(&m_ewma_sat, 1ULL);
		return;
	}
	if (kept < (u64)FLOW_RUN_NEED) {
		t->run_known = 0;
		__sync_fetch_and_add(&m_ewma_freeze, 1ULL);
		return;
	}
	if (max_s < min_s || max_s - min_s < (u64)FLOW_RUN_SPAN_NS) {
		t->run_known = 0;
		__sync_fetch_and_add(&m_ewma_freeze, 1ULL);
		return;
	}
	if (max_d < min_d || max_d - min_d > (min_d >> 3)) {
		t->run_known = 0;
		__sync_fetch_and_add(&m_ewma_freeze, 1ULL);
		return;
	}
	t->run_known = 1;
	__sync_fetch_and_add(&m_ewma_sat, 1ULL);
}
static __always_inline void flow_run_prune(struct flow_task_ctx *t, u64 now)
{
	u64 win;
	int i;
	if (!t || !now)
		return;
	win = (u64)FLOW_RUN_WIN_NS;
	for (i = 0; i < 8; i++) {
		u64 s = READ_ONCE(t->run_stamp[i]);
		if (s && s > now)
			return;
	}
	for (i = 0; i < 8; i++) {
		u64 s = READ_ONCE(t->run_stamp[i]);
		u64 d = READ_ONCE(t->run_dur[i]);
		if (!s || !d)
			continue;
		if (now - s > win) {
			t->run_dur[i] = 0;
			t->run_stamp[i] = 0;
			t->run_pruned++;
		}
	}
	flow_run_recalc(t);
}
static __always_inline void flow_run_close(struct flow_task_ctx *t, u64 now)
{
	u64 tot;
	u64 win;
	u32 idx;
	int i;
	if (!t || !now)
		return;
	tot = READ_ONCE(t->run_total);
	if (!tot)
		return;
	win = (u64)FLOW_RUN_WIN_NS;
	if (tot > win)
		tot = win;
	for (i = 0; i < 8; i++) {
		u64 s = READ_ONCE(t->run_stamp[i]);
		if (s && s > now)
			return;
	}
	idx = READ_ONCE(t->run_head) & 7U;
	if (idx >= 8U)
		return;
	t->run_dur[idx] = tot;
	t->run_stamp[idx] = now;
	t->run_head++;
	t->run_total = 0;
	flow_run_recalc(t);
}
/* Guard kept helper with no caller in tree. Reads the kept max when
 * stable else zero for later use. */
static __always_inline u64 flow_run_ref(struct flow_task_ctx *t)
{
	if (!t)
		return 0;
	if (!READ_ONCE(t->run_known))
		return 0;
	return READ_ONCE(t->run_max);
}
static __always_inline u64 flow_run_eff(u64 ref, u64 burst_ns)
{
	u64 b = flow_burst_clamp(burst_ns);
	u64 e = ref > b ? ref : b;
	if (e > (u64)FLOW_SLICE_MIN_NS)
		e = (u64)FLOW_SLICE_MIN_NS;
	return e;
}
static __always_inline s64 flow_run_vd(s64 floored, u64 eff, u32 w)
{
	s64 vd = flow_fair_charge(floored, eff, w);
	if (vd <= floored)
		return flow_fair_cap_add(floored, 1);
	return vd;
}
/* Readiness gate for the single response path. Every input stays
 * usable before the response runs. A null task plus no CPU plus an
 * unknown reference plus a zero effective value plus a service
 * mismatch plus a service outside the floor through slice range plus
 * a zero wait plus a wait past the run window plus a zero weight
 * plus an invalid weight each keep the fallback path. The checks
 * hold compares only with no divide and no clock and no scan and
 * no shared state read. */
static __always_inline bool hrrn_ready(struct flow_task_ctx *t, u64 sref, u64 eff, u64 W, u64 S, u32 w, bool no_cpu)
{
	return t != 0 && !no_cpu && sref != 0 && eff != 0 && S == eff &&
	       S >= (u64)FLOW_SLICE_FLOOR_NS && S <= (u64)FLOW_SLICE_MIN_NS &&
	       W != 0 && W <= (u64)FLOW_RUN_WIN_NS && w != 0 &&
	       w != (u32)FLOW_CGROUP_WEIGHT_INVALID;
}
/* Single response due time with wait over service. The step comes from
 * the weight only with no tuning. Service stays in the floor through
 * slice range with clamp only. Wait stays capped at the run window
 * with min only and no clock and no scan. The response is step times
 * service over wait plus service with zero plus denominator guards.
 * Zero wait keeps max boost with full step. Max wait keeps min boost
 * with a small scaled term. The sum stays bounded at twice the step
 * with saturation through the shared cap helper and no wrap. The
 * caller passes service plus wait from existing locals with no new
 * storage and no ring walk. This keeps pure arithmetic with integer
 * only and no extra state. */
static __always_inline s64 vd_HRRN(s64 floored, u64 W, u64 S, u32 w)
{
	u64 step = flow_fair_step(w);
	u64 s = S;
	u64 win = W;
	u64 denom;
	u64 resp;
	if (!step)
		step = (u64)FLOW_SLICE_MIN_NS;
	if (!s)
		return flow_fair_cap_add(floored, 1);
	if (s < (u64)FLOW_SLICE_FLOOR_NS)
		s = (u64)FLOW_SLICE_FLOOR_NS;
	if (s > (u64)FLOW_SLICE_MIN_NS)
		s = (u64)FLOW_SLICE_MIN_NS;
	if (win > (u64)FLOW_RUN_WIN_NS)
		win = (u64)FLOW_RUN_WIN_NS;
	denom = win + s;
	if (!denom)
		return flow_fair_cap_add(floored, 1);
	resp = step * s / denom;
	if (resp > step)
		resp = step;
	if (!resp)
		resp = 1;
	return flow_fair_cap_add(floored, resp);
}
static __always_inline u64 flow_run_slice(u64 ref)
{
	if (!ref)
		return (u64)FLOW_SLICE_MIN_NS;
	if (ref < (u64)FLOW_SLICE_FLOOR_NS)
		return (u64)FLOW_SLICE_FLOOR_NS;
	if (ref > (u64)FLOW_SLICE_MIN_NS)
		return (u64)FLOW_SLICE_MIN_NS;
	return ref;
}
#endif
