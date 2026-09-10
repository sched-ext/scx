/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2026 Galih Tama <galpt@v.recipes> */
#ifndef __FLOW_INTF_H
#define __FLOW_INTF_H
#ifndef __VMLINUX_H__
typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long u64;
typedef signed char s8;
typedef signed short s16;
typedef signed int s32;
typedef signed long s64;
typedef int pid_t;
#endif
#include <stdbool.h>
#ifndef __always_inline
#define __always_inline inline __attribute__((__always_inline__))
#endif
/* Fixed slice at 1ms, two groups, ordered queues. */
enum flow_consts {
	FLOW_EST_MIN_NS = 1ULL,
	FLOW_EST_MAX_NS = (1ULL * 1000ULL * 1000ULL * 1000ULL),
	FLOW_SLICE_NS = (1ULL * 1000ULL * 1000ULL),
	FLOW_MAX_CPUS = 1024ULL,
	FLOW_DSQ_BASE = 0x4000ULL,
	FLOW_DSQ_PARK = 0x5000ULL,
	FLOW_DSQ_PARK_HOG = 0x5001ULL,
	FLOW_NGROUPS = 2ULL,
	FLOW_GROUP_LIGHT = 0ULL,
	FLOW_GROUP_HOG = 1ULL,
	FLOW_WIN_NS = (32ULL * 1000ULL * 1000ULL),
	FLOW_DEMOTE_BURN_NS = (16ULL * 1000ULL * 1000ULL),
	FLOW_DEMOTE_BURST_NS = (4ULL * 1000ULL * 1000ULL),
	FLOW_DEMOTE_BURST_MID_NS = (2ULL * 1000ULL * 1000ULL),
	FLOW_DEMOTE_BURST_FLOOR_NS = (1ULL * 1000ULL * 1000ULL),
	FLOW_PROMOTE_BURN_NS = (4ULL * 1000ULL * 1000ULL),
	FLOW_PROMOTE_WINS = 64ULL,
	FLOW_PROMOTE_WAKE_HITS = 8ULL,
	FLOW_WAKE_SHORT_NS = (1ULL * 1000ULL * 1000ULL),
	FLOW_HETERO_SPREAD_PCT = 10ULL,
	FLOW_PINNED_INFLATE_NS = (8ULL * 1000ULL * 1000ULL),
	FLOW_PERF_LIGHT = 1024ULL,
	FLOW_PERF_HOG = 1024ULL,
	FLOW_DISPATCH_MAX_BATCH = 32ULL,
	FLOW_STEAL_BOUND = 8ULL,
	FLOW_OPS_TIMEOUT_MS = 30000ULL,
	FLOW_WEIGHT = 1024ULL,
	FLOW_STEAL_MIN_DEPTH = 2ULL,
	FLOW_DELAY_UNIT_NS = 32000ULL,
	FLOW_DELAY_MAX = 250ULL,
	FLOW_DELAY_ARM = 16ULL,
	FLOW_DELAY_STAND = 8ULL,
	FLOW_DELAY_WIN_LEN = 8ULL,
	FLOW_GRANULE_FLOOR_NS = 64000ULL,
	FLOW_CURSOR_RATE_BIT = 0x80000000ULL,
	FLOW_CURSOR_STAND_BIT = 0x400ULL,
	FLOW_CURSOR_MASK = 0x7ffffbffULL,
	FLOW_KICK_COALESCE_NS = 50000ULL,
};
/* Weight fits u16 for the running repack. */
/* Nice minus 20 to 19 fits s16 for repack. */
_Static_assert((FLOW_WEIGHT) <= 65535,
    "weight fits u16");
_Static_assert(20 <= 32767,
    "nice fits s16");
/* Per task state at 48B with group plus window plus wake. */
struct flow_task_ctx {
	u64 est_ns;
	u64 run_at;
	u64 vruntime;
	u64 deadline;
	u64 win_start;
	u32 burn;
	u8 group;
	u8 low_runs;
	u16 wake_hits;
};
/* Per CPU state at 32B with delay plus rate. */
struct flow_cpu_state {
	u64 frontier;
	u64 running_est;
	u32 running_pid;
	u32 cursor;
	s16 running_nice;
	u16 running_weight;
	u8 delay_win;
	u8 delay_cur;
	u16 delay_cnt;
};
/* Counters at 160B with group plus coalesce. */
/* Skipped lumps all fail-closed busy no-kicks. */
/* Coalesced counts q2 idle skips in 50us. */
struct flow_sched_stats {
	u64 on_cpu;
	u64 total_runtime;
	u64 inserts;
	u64 requeues;
	u64 completions;
	u64 park_moves;
	u64 steal_moves;
	u64 kicks;
	u64 enq_no_tctx;
	u64 edf_enqueued;
	u64 edf_clamped;
	u64 edf_ordered;
	u64 group_demote;
	u64 group_promote;
	u64 pinned_hog_inflated;
	u64 group_steal_skipped;
	u64 group_wake_promote;
	u64 preempt_kicks;
	u64 preempt_skipped;
	u64 kick_coalesced;
};
/* Clamp estimate to the estimate range. */
static __always_inline u64 flow_clamp_est(u64 v)
{
	if (v < (u64)FLOW_EST_MIN_NS)
		return (u64)FLOW_EST_MIN_NS;
	if (v > (u64)FLOW_EST_MAX_NS)
		return (u64)FLOW_EST_MAX_NS;
	return v;
}
/* Queue id of one CPU with range check by caller. */
static __always_inline u64 flow_dsq_for_cpu(u32 cpu)
{
	return (u64)FLOW_DSQ_BASE + (u64)cpu;
}
/* Group of one CPU by id halves with extra to hog. */
/* Halves is the fallback when the group table is not ready. */
static __always_inline u8 flow_group_of_cpu(u32 cpu,
	u64 nr)
{
	if (nr <= 1)
		return (u8)FLOW_GROUP_LIGHT;
	if ((u64)cpu < nr / 2)
		return (u8)FLOW_GROUP_LIGHT;
	return (u8)FLOW_GROUP_HOG;
}
/* Park id of one group with light as default. */
static __always_inline u64 flow_park_for_group(u8 group)
{
	if (group == (u8)FLOW_GROUP_HOG)
		return (u64)FLOW_DSQ_PARK_HOG;
	return (u64)FLOW_DSQ_PARK;
}
/* Perf hint of one group with single policy at max. */
static __always_inline u32 flow_perf_for_group(u8 group)
{
	if (group == (u8)FLOW_GROUP_HOG)
		return (u32)FLOW_PERF_HOG;
	return (u32)FLOW_PERF_LIGHT;
}
/* True when one window of 32ms has passed. */
static __always_inline bool flow_win_ready(u64 now,
	u64 win_start)
{
	if (win_start == 0)
		return false;
	return now - win_start >= (u64)FLOW_WIN_NS;
}
/* True when window burn reaches 16ms for demote. */
static __always_inline bool flow_burn_hot(u32 burn)
{
	return (u64)burn >= (u64)FLOW_DEMOTE_BURN_NS;
}
/* True when one burst reaches 4ms for demote. */
/* Quiet case of the adaptive check with depth 0. */
static __always_inline bool flow_burst_hot(u64 delta)
{
	return delta >= (u64)FLOW_DEMOTE_BURST_NS;
}
/* Burst allowance from light depth with flood backpressure. */
/* Depth sums queued tasks in light per CPU queues capped at */
/* 4. Table is depth 0 to 1 to 4ms, depth 2 to 3 to 2ms, */
/* depth 4 plus to 1ms. Quiet keeps 4ms so lone bursts move */
/* fast with no pressure. Mild halves to 2ms so flood bursts */
/* move earlier but still above one slice with no flap on */
/* single slices. Deep floors at 1ms, so per task worst case */
/* is the floor during flood. Halves keeps the view matched */
/* to dispatch isolation with no BSS cost in stopping. */
/* Strict iff ready is zero, best effort iff ready is one. */
static __always_inline u64 flow_burst_allowance(u64 depth)
{
	if (depth >= 4)
		return (u64)FLOW_DEMOTE_BURST_FLOOR_NS;
	if (depth >= 2)
		return (u64)FLOW_DEMOTE_BURST_MID_NS;
	return (u64)FLOW_DEMOTE_BURST_NS;
}
/* True when one burst reaches the allowance for demote. */
static __always_inline bool flow_burst_hot_at(u64 delta,
	u64 allow)
{
	return delta >= allow;
}
/* True when window burn stays below 4ms for promote. */
static __always_inline bool flow_burn_low(u32 burn)
{
	return (u64)burn < (u64)FLOW_PROMOTE_BURN_NS;
}
/* True when one block is short below 1ms for wake. */
static __always_inline bool flow_wake_short(u64 delta)
{
	return delta < (u64)FLOW_WAKE_SHORT_NS;
}
/* True when wake hits reach 8 for fast promote. */
static __always_inline bool flow_wake_ready(u16 hits)
{
	return (u64)hits >= (u64)FLOW_PROMOTE_WAKE_HITS;
}
/* Deadline with pinned hog extra of 8ms. */
static __always_inline u64 flow_inflate_deadline(u64 dl)
{
	return dl + (u64)FLOW_PINNED_INFLATE_NS;
}
/* Scale estimate by weight with fixed identity. */
static __always_inline u64 flow_scale_by_weight(u64 est,
	u32 weight)
{
	if (weight == 0)
		return est;
	if (weight == (u32)FLOW_WEIGHT)
		return est;
	return (est * 1024ULL) / (u64)weight;
}
/* True when first time is before second with wrap. */
static __always_inline bool flow_time_before(u64 a,
	u64 b)
{
	return (s64)(a - b) < 0;
}
/* Clamp virtual time to one slice behind frontier. */
static __always_inline u64 flow_clamp_vruntime(u64 v,
	u64 frontier, u64 slice)
{
	u64 floor = frontier - slice;
	if (flow_time_before(v, floor))
		return floor;
	return v;
}
/* Weight table for 40 nice levels from minus 20 to 19. */
/* Index is nice plus 20 with center 1024 at nice 0. */
/* Ends are 2048 at minus 20 and 256 at 19, */
/* so total spread K is 8 with boost 2x and penalty 4x. */
/* Made as 1024 times 2 to minus nice over 20 below 1, */
/* else 1024 times 4 to minus nice over 19, rounded. */
/* The maker is docs only, the table is rodata. */
static const u16 flow_weight_table[40] = {
	2048, 1978, 1911, 1846, 1783, 1722, 1663, 1607,
	1552, 1499, 1448, 1399, 1351, 1305, 1261, 1218,
	1176, 1136, 1097, 1060, 1024, 952, 885, 823,
	765, 711, 661, 614, 571, 531, 494, 459,
	427, 397, 369, 343, 319, 296, 275, 256,
};
/* Weight of one nice level from the table. */
/* Out of range maps to 1024 with no trap. */
/* Nice 0 skips the table with no load. */
static __always_inline u32 flow_weight_of(s32 nice)
{
	s32 idx;
	if (nice == 0)
		return 1024;
	if (nice < -20)
		return 1024;
	if (nice > 19)
		return 1024;
	idx = nice + 20;
	return (u32)flow_weight_table[(u32)idx];
}
/* Cap of one weight in nanos with K bounds. */
/* Base is slice times 1024 over weight, held in slice */
/* over 8 to slice times 8, so extremes stay bounded. */
static __always_inline u64 flow_cap_for_weight(u32 weight,
	u64 slice)
{
	u64 cap;
	u64 lo;
	u64 hi;
	if (weight == 0)
		return slice;
	if (weight == 1024)
		return slice;
	if (slice == 0)
		return 0;
	cap = (slice * 1024ULL) / (u64)weight;
	lo = slice / 8ULL;
	hi = slice * 8ULL;
	if (cap < lo)
		return lo;
	if (cap > hi)
		return hi;
	return cap;
}
/* Clamp virtual time with a weight scaled cap. */
/* Floor is frontier minus cap with wrap, same as the */
/* fixed clamp with slice at 1024. */
static __always_inline u64 flow_clamp_vruntime_w(u64 v,
	u64 frontier, u64 slice, u32 weight)
{
	u64 cap = flow_cap_for_weight(weight, slice);
	u64 floor = frontier - cap;
	if (flow_time_before(v, floor))
		return floor;
	return v;
}
/* Deadline from clamped time plus scaled estimate. */
static __always_inline u64 flow_deadline(u64 clamped_v,
	u64 scaled)
{
	return clamped_v + scaled;
}
/* Advance virtual time by scaled runtime with wrap. */
static __always_inline u64 flow_vruntime_add(u64 v,
	u64 delta)
{
	return v + delta;
}
/* Max of two virtual times with wrap safety. */
static __always_inline u64 flow_frontier_max(u64 old,
	u64 next)
{
	if (flow_time_before(old, next))
		return next;
	return old;
}
/* Frontier for idle CPU from waking time with no zero. */
/* The caller keeps the old frontier when waking is zero, */
/* so zero never disorders the frontier. */
static __always_inline u64 flow_frontier_idle(u64 waking_v)
{
	return waking_v;
}
/* Next peer for steal scan with rotating cursor. */
/* Masks rate plus stand, so one kick per slice keeps */
/* the scan order with no extra state. */
static __always_inline u32 flow_steal_next(u32 cursor,
	u32 nr_cpus)
{
	u32 cur;
	if (nr_cpus == 0)
		return 0;
	cur = cursor & (u32)FLOW_CURSOR_MASK;
	return (cur + 1) % nr_cpus;
}
/* Cursor peer without rate plus stand. */
static __always_inline u32 flow_cursor_val(u32 cursor)
{
	return cursor & (u32)FLOW_CURSOR_MASK;
}
/* True when the stand latch is held in bit10. */
/* Bits 0 to 9 hold peer, bit10 holds stand, top */
/* holds rate, so rotation masks both flags. */
static __always_inline bool flow_stand_held(u32 cursor)
{
	return (cursor &
	    (u32)FLOW_CURSOR_STAND_BIT) != 0;
}
/* Store peer plus keep rate plus stand. */
/* Dispatch CAS keeps fresh flags, model */
/* is sequential form, timing only. */
static __always_inline u32 flow_cursor_store(u32 peer,
	u32 old)
{
	return (peer & (u32)FLOW_CURSOR_MASK) |
	    (old & ((u32)FLOW_CURSOR_RATE_BIT |
	    (u32)FLOW_CURSOR_STAND_BIT));
}
/* Set the stand latch plus keep peer plus rate. */
static __always_inline u32 flow_stand_set(u32 cursor)
{
	return cursor | (u32)FLOW_CURSOR_STAND_BIT;
}
/* Clear the stand latch plus keep peer plus rate. */
static __always_inline u32 flow_stand_clear(u32 cursor)
{
	return cursor & ~(u32)FLOW_CURSOR_STAND_BIT;
}
/* True when the rate bit is clear for one kick. */
/* Read only, so claim below does the atomic set. */
static __always_inline bool flow_rate_clear(u32 cursor)
{
	return (cursor &
	    (u32)FLOW_CURSOR_RATE_BIT) == 0;
}
/* Atomically set rate and report prior clear. */
/* One winner per slice with no check then set. */
static __always_inline bool flow_rate_claim(u32 *cursor)
{
	u32 old;
	old = __sync_fetch_and_or(cursor,
	    (u32)FLOW_CURSOR_RATE_BIT);
	return flow_rate_clear(old);
}
/* Delay sample in 32us units from queued count. */
/* One queued is 31 units, half slice arms at 16. */
/* Cap is 250 at 8ms with integer math only. */
static __always_inline u8 flow_delay_from_queued(
	u64 queued)
{
	u64 v;
	if (queued >= 8)
		return 250;
	v = (queued * 125ULL) / 4ULL;
	if (v > 250ULL)
		return 250;
	return (u8)v;
}
/* Decay one step by 1/8 with integer math only. */
/* Holds peaks across windows for hysteresis. */
static __always_inline u8 flow_delay_decay(u8 old)
{
	u32 o = (u32)old;
	u32 d = o - o / 8U;
	return (u8)d;
}
/* True when the delay window is armed at 16. */
/* 16 is 512us in 32us units near half slice. */
static __always_inline bool flow_delay_armed(u8 win)
{
	return (u32)win >= (u32)FLOW_DELAY_ARM;
}
/* True when delay is armed with hysteresis. */
/* Arms at 16, then holds while win stays at or */
/* past stand at 8 with the latched flag. */
/* Persists across idle with no decay sans traffic. */
/* Delay shows stale when idle, see dashboard. */
/* Next running decays at 1/8 per window. */
static __always_inline bool flow_delay_armed_latched(
	u8 win, bool held)
{
	if ((u32)win >= (u32)FLOW_DELAY_ARM)
		return true;
	if (held && (u32)win >= (u32)FLOW_DELAY_STAND)
		return true;
	return false;
}
/* Max of two delay samples with cap at 250. */
/* Win plus cur are dual writer max, count is */
/* running only. Lost race drops at most one */
/* sample with no count skew, decay intact. */
static __always_inline u8 flow_delay_max(u8 a,
	u8 b)
{
	u8 m = a > b ? a : b;
	if ((u32)m > (u32)FLOW_DELAY_MAX)
		return (u8)FLOW_DELAY_MAX;
	return m;
}
/* Close one window of 8 with decay plus max. */
/* Decays the old max by 1/8 then keeps the max */
/* with the current window max with cap at 250. */
static __always_inline u8 flow_delay_close(u8 win,
	u8 cur)
{
	u8 d = flow_delay_decay(win);
	u8 m = flow_delay_max(d, cur);
	return m;
}
/* Granule in nanos quarter slice with 64us floor. */
/* Base is slice times 1024 over weight quartered */
/* with floor at 64us, so heavy keeps short and */
/* light keeps long with no trap on zero input. */
/* Short heavy is stricter, tempering deadline */
/* lead. Net easiness is deadline math, not gran. */
/* Quarter bounds theft near 25% of a slice. */
/* Floor covers IPI plus switch cost, no thrash. */
/* Uses woken weight only, see deserved. */
static __always_inline u64 flow_granule_for_weight(
	u32 weight, u64 slice)
{
	u64 base;
	u64 gran;
	if (weight == 0) {
		gran = slice / 4ULL;
		if (gran < (u64)FLOW_GRANULE_FLOOR_NS)
			return (u64)FLOW_GRANULE_FLOOR_NS;
		return gran;
	}
	if (slice == 0)
		return (u64)FLOW_GRANULE_FLOOR_NS;
	base = (slice * 1024ULL) / (u64)weight;
	gran = base / 4ULL;
	if (gran < (u64)FLOW_GRANULE_FLOOR_NS)
		return (u64)FLOW_GRANULE_FLOOR_NS;
	return gran;
}
/* True when woken deadline beats frontier plus gran. */
/* Frontier is the service floor, so beating it by */
/* granule proves earliness with no occupant state. */
/* Granule uses woken weight only, occupant weight */
/* stays out after the frontier compare fix. */
static __always_inline bool flow_deserved(u64 woken_dl,
	u64 frontier, u64 granule)
{
	return flow_time_before(woken_dl,
	    frontier + granule);
}
/* True when all five preempt gates pass. */
/* Armed plus deserved plus rate clear plus same */
/* group plus mask with fail closed on any clear. */
/* One skipped count covers all fail-closed no-kicks. */
/* Disarmed plus rate plus isolation share one count. */
static __always_inline bool flow_preempt_ok(bool armed,
	bool deserved, bool rate_clear, bool same_group,
	bool mask_ok)
{
	return armed && deserved && rate_clear &&
	    same_group && mask_ok;
}
/* True when one idle kick is recent in 50us. */
/* Zero last never counts as recent with wrap. */
/* Diff wraps, so order holds across the wrap. */
static __always_inline bool flow_kick_recent(u64 now,
	u64 last)
{
	if (last == 0)
		return false;
	return now - last <
	    (u64)FLOW_KICK_COALESCE_NS;
}
#endif
