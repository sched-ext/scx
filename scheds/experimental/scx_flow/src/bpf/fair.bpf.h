// SPDX-License-Identifier: GPL-2.0
/*
 * Fair charging for the flow scheduler.
 *
 * The base charge scales with the nice weight. Values saturate at
 * the top. The task nice weight comes from a small table over minus
 * twenty to nineteen with zero as one hundred, read from the task
 * static priority minus one hundred twenty. Out of range tasks keep
 * the default.
 * Fresh times move past the per LLC floor through a short
 * compare and swap loop, so each stored time stays unique with
 * the winner publishing its value at once. When the loop loses
 * too often, the last observed value plus one is stored directly
 * with no further retry. An invalid LLC skips the floor and keeps
 * the input time directly. The floor rises over time and never
 * moves backward for a given LLC. When the time runs ahead of the
 * floor, the floor moves up by at most one base step per enqueue,
 * so one far time cannot pull the floor with it. Virtual deadline adds the burst scaled nice step
 * to the floored time through the shared charge path, so a larger
 * weight or a shorter run gives an earlier due time with no extra
 * divide. Burst holds the last run length between the floor and
 * one slice with shift only moves. Overload cost holds the run length
 * between the floor and one slice. Exceed holds the cost past tolerance
 * else zero. The gate admits with live plus tolerance plus bound plus
 * room plus cap and rejects large costs on a full target. Bands map the
 * nice weight between one and sixteen thousand three hundred eighty four
 * with base one hundred twenty eight through shift only moves with no
 * new field, so the lowest band holds the lightest share.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
#ifndef __FLOW_FAIR_BPF_H
#define __FLOW_FAIR_BPF_H
#include "intf.h"
#include "maps.bpf.h"
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
static __always_inline u64 flow_fair_step(u32 w)
{
	u32 cw = w;
	if (cw == (u32)FLOW_CGROUP_WEIGHT_INVALID || cw < (u32)FLOW_CGROUP_WEIGHT_MIN)
		cw = (u32)FLOW_CGROUP_WEIGHT_DFLT;
	if (cw > (u32)FLOW_CGROUP_WEIGHT_MAX)
		cw = (u32)FLOW_CGROUP_WEIGHT_MAX;
	if (!cw)
		return (u64)FLOW_FAIR_BASE_NS;
	return (u64)FLOW_FAIR_BASE_NS * (u64)FLOW_CGROUP_WEIGHT_DFLT / (u64)cw;
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
static __always_inline s64 flow_fair_charge(s64 base, u64 used, u32 w)
{
	const s64 vmax = (s64)0x7fffffffffffffffLL;
	u64 st = flow_fair_step(w);
	u64 slice = (u64)FLOW_SLICE_MIN_NS;
	u64 hi;
	u64 lo;
	u64 scaled;
	if (!st)
		st = (u64)FLOW_FAIR_BASE_NS;
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
 * value by half the gap and holds otherwise, since the stop cut the
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
			b = b - (b >> 1) + (u >> 1);
		return flow_burst_clamp(b);
	}
	b = b - (b >> 2) + (u >> 2);
	return flow_burst_clamp(b);
}
/* Overload cost for one burst. Holds the run length between the floor
 * and one slice, so a larger burst pays more with saturating clamp only. */
static __always_inline u64 flow_red_cost(u64 burst_ns)
{
	return flow_burst_clamp(burst_ns);
}
/* Overload exceed past tolerance. Holds zero when the cost sits within
 * tolerance else the cost past tolerance, so small costs admit at once
 * with saturating math only. */
static __always_inline u64 flow_red_exceed(u64 cost)
{
	u64 tol = (u64)FLOW_RED_TOL_NS;
	if (cost <= tol)
		return 0;
	return cost - tol;
}
/* Overload gate for one newcomer cost with target room. Rejects when the
 * cost sits past the bound and the target holds no room under the cap,
 * so small costs plus room admit and overload drains to fallback with
 * the caps kept. Compare only with no divide. */
static __always_inline bool flow_red_gate(u64 cost, u64 exceed, u64 queued)
{
	u64 emax = (u64)FLOW_RED_EMAX_NS;
	if (!exceed)
		return false;
	if (cost <= emax)
		return false;
	if (queued < (u64)FLOW_QUEUE_CAP)
		return false;
	return true;
}
/* Implicit band for one nice weight. Maps between one and sixteen
 * thousand three hundred eighty four with base one hundred twenty eight
 * through shift only moves, so the lightest share sits in the lowest
 * band with no new field and no divide. */
static __always_inline u32 flow_band_for_weight(u32 w)
{
	u32 cw = w;
	if (!cw || cw < 1U)
		cw = 1U;
	if (cw > 16384U)
		cw = 16384U;
	if (cw >= (128U << 3))
		return 3U;
	if (cw >= 128U)
		return 2U;
	if (cw >= (128U >> 3))
		return 1U;
	return 0U;
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
			s64 cap = flow_fair_cap_add(last, (u64)FLOW_FAIR_BASE_NS);
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
#endif
