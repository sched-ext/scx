// SPDX-License-Identifier: GPL-2.0
/*
 * Shared flow header
 *
 * Defines the shared constants, structs, helpers with a fixed 1ms slice, two
 * groups, and per CPU bounded LIFO slot queues. Mirrored by userspace so
 * behavior stays the same on both sides of the boundary.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
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
#ifndef __noinline
#define __noinline __attribute__((noinline))
#endif
/* Fixed slice at 1ms, two groups, per CPU bounded LIFO slots. */
enum flow_consts {
	FLOW_EST_MIN_NS = 1ULL,
	FLOW_EST_MAX_NS = (1ULL * 1000ULL * 1000ULL * 1000ULL),
	FLOW_SLICE_NS = (1ULL * 1000ULL * 1000ULL),
	FLOW_MAX_CPUS = 1024ULL,
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
	FLOW_CPUPERF_LEVEL = 1024ULL,
	FLOW_CPUPERF_IDLE = 0ULL,
	FLOW_CPUPERF_BUDGET_NS = (1ULL * 1000ULL * 1000ULL),
	FLOW_CPUPERF_HALF_LIFE_NS = (24ULL * 1000ULL * 1000ULL),
	FLOW_CPUPERF_ALPHA = 3072ULL,
	FLOW_CPUPERF_FP_SHIFT = 8ULL,
	FLOW_CPUPERF_FP_ONE = 256ULL,
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
	FLOW_DESERVED_SLACK_NS = 32000ULL,
	FLOW_CURSOR_STAND_BIT = 0x400ULL,
	FLOW_CURSOR_MASK = 0x7ffffbffULL,
	FLOW_KICK_COALESCE_NS = 50000ULL,
	FLOW_WHEEL_SLOT_NS = (64ULL * 1000ULL),
	FLOW_WHEEL_DIM = 256ULL,
	FLOW_WHEEL_TOTAL = 65536ULL,
	FLOW_WHEEL_HORIZON_NS = (64ULL * 1000ULL * 65536ULL),
	FLOW_WHEEL_QUANT_LO = 0xFFFFULL,
	FLOW_TOKEN_MAX = 255ULL,
	FLOW_SLOT_BASE = 0x6000ULL,
	FLOW_SLOT_OVERFLOW_BASE = 0x6800ULL,
	FLOW_SLOT_OVERFLOW_N = 2ULL,
	FLOW_SLOT_PER_CPU = 2ULL,
	FLOW_SLOT_MAX_DSQS = 2050ULL,
	FLOW_SLOT_D = 4ULL,
	FLOW_SLOT_BUDGET = 32ULL,
	FLOW_SLOT_SWEEP_MAX = 256ULL,
	FLOW_LIFO_K = 8ULL,
	FLOW_LIFO_PERIOD = 9ULL,
};
/* Weight fits u16 for the running repack. */
/* Nice minus 20 to 19 fits s16 for repack. */
_Static_assert((FLOW_WEIGHT) <= 65535,
    "weight fits u16");
_Static_assert(20 <= 32767,
    "nice fits s16");
/* Per task state at 48B with group, window, and wake. */
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
/* Per CPU state at 64B with delay, rate, EMA, active, and occupant. */
/* Frontier, running, cursor, delay, and cpuperf EMA at 32B base. */
/* The base carries 16B EMA tail with 8B active tail plus 8B occupant tail. */
/* EMA holds the proportional budget in nanos capped at 1ms, at */
/* holds the last EMA update time in nanos. Active holds */
/* lifetime active nanos charged once per run segment. Occupant holds */
/* the group of the running task with LIGHT fallback, written in */
/* running and cleared with pid, read post-empty in enqueue. */
/* BSS zero covers the cold start and explicit zero kept as */
/* verify for the 48B to 56B growth and the 56B to 64B growth */
/* with no trap. */
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
	u64 cpuperf_ema;
	u64 cpuperf_ema_at;
	u64 active_ns;
	u8 occupant_group;
};
/* Counters at 272B with group, coalesce, overflow, token, slot. Total keeps */
/* the sum for compat. Busy uses the bound gate with empty first plus */
/* deserved or hog plus same plus mask plus rate, so busy kicks count */
/* under kicks and busy no kicks count under total plus deserved plus */
/* group plus mask plus rate with armed retired frozen for compat and empty */
/* plus pinned total only with no other reason write. Mask stays defensive, */
/* expect near zero with outer check. Coalesced counts q2 idle skips in */
/* 50us. Overflow counts tail pins past the horizon, boosts counts token */
/* spends, and cas fails counts lost token races. Armed stays frozen for */
/* compat, so tail offsets shift once with no new writes. Slot moves counts */
/* all slot tasks moved via slot drains, park moves counts the overflow */
/* subset, steal moves counts all peer moves, steal x moves counts the cross */
/* subset with post hoc LSB compare and unconditional adds, slot kicks */
/* counts safety net kicks, slot defer counts capped drains with work left, */
/* LIFO heads counts head inserts at K 8, bound hits counts tail, all append */
/* only at the tail with BSS zero. */
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
	u64 preempt_skipped_armed;
	u64 preempt_skipped_deserved;
	u64 preempt_skipped_group;
	u64 preempt_skipped_mask;
	u64 preempt_skipped_rate;
	u64 wheel_overflow;
	u64 token_boosts;
	u64 slot_kicks;
	u64 token_cas_fails;
	u64 slot_moves;
	u64 slot_defer;
	u64 steal_xmoves;
	u64 lifo_heads;
	u64 lifo_bound_hits;
};
/* Soft preempt shortens the occupant slice out of band to zero at the kick */
/* win, so the kick sticks on the waker with no remainder race. Stuck */
/* shortens match preempt_kicks one for one, kicks sent exceed it by */
/* declined plus null or self. A declined shorten keeps kick only with */
/* total plus rate, null or self sends kick only with no count, and no */
/* counter is added. */
/* Bounded LIFO takes head for K 8 with one tail in period 9 plus forced tail */
/* at MAX, so per queue order stays fresh with no starve or preempt use. */
/* Head uses the build gate with zero fallback to tail, so builds without */
/* HEAD keep tail with no trap and old kernels keep FIFO fallback with no */
/* preempt use. Total 2050 matches slot max with per CPU plus overflow. */

/* Clamp estimate to the estimate range. */
static __always_inline u64 flow_clamp_est(u64 v)
{
	if (v < (u64)FLOW_EST_MIN_NS)
		return (u64)FLOW_EST_MIN_NS;
	if (v > (u64)FLOW_EST_MAX_NS)
		return (u64)FLOW_EST_MAX_NS;
	return v;
}
/* Group of one CPU by id halves with extra to hog. */
/* Halves is the fallback when the group table is not ready. */
/* Userspace seeds by online rank with write by id, offline */
/* stays light inert, skewed forces ready one, dense full */
/* keeps halves exactly. Snapshot covers online only. */
static __always_inline u8 flow_group_of_cpu(u32 cpu,
	u64 nr)
{
	if (nr <= 1)
		return (u8)FLOW_GROUP_LIGHT;
	if ((u64)cpu < nr / 2)
		return (u8)FLOW_GROUP_LIGHT;
	return (u8)FLOW_GROUP_HOG;
}
/* True when a stopping task should restore the idle hint. Bang-bang edge at */
/* M1 with no EMA or state growth. M2 keeps the predicate but maps the */
/* value through the EMA with from_ema, so long idle still decays to zero. */
/* Needs blocked, per CPU queue empty, and local empty, so runnable never */
/* restores with any queued work held high. */
static __always_inline bool flow_should_restore_hint(
	bool runnable, u64 dsq_nr, u64 local_nr)
{
	return !runnable && dsq_nr == 0 && local_nr == 0;
}
/* Climb the EMA toward the 1ms budget with a gap step. */
/* Pure-EMA proportional at M2 with uniform both groups. */
/* Delta clamps to the budget first with u64 order, so a */
/* long burst never overshoots in one step. Step is gap */
/* times delta times alpha over budget times FP_ONE at */
/* 12x in FP8, so a full slice saturates at once with a */
/* fast attack. Adds min step gap, so max stays capped. */
/* Names use FLOW_CPUPERF prefix to guard FP clashes. */
static __always_inline u64 flow_ema_climb(u64 ema,
	u64 delta)
{
	u64 budget = (u64)FLOW_CPUPERF_BUDGET_NS;
	u64 alpha = (u64)FLOW_CPUPERF_ALPHA;
	u64 one = (u64)FLOW_CPUPERF_FP_ONE;
	u64 d;
	u64 gap;
	u64 step;
	u64 denom;
	if (ema >= budget)
		return budget;
	gap = budget - ema;
	d = delta > budget ? budget : delta;
	if (d == 0 || gap == 0)
		return ema;
	denom = budget * one;
	if (denom == 0)
		return ema;
	step = gap * d * alpha / denom;
	if (step > gap)
		step = gap;
	return ema + step;
}
/* Decay the EMA by sleep with half-life halves and Taylor. Shifts whole */
/* half-lives then scales the residual below one half with a 2nd-order Taylor */
/* of 0.5 to the r power at r is rem over half. Fixed point at FP_ONE 256 */
/* holds ln2 times 256 at 177 + quad times 256 at 61, so t is rem times 256 */
/* over half in 0 to 255 with dec1 + inc2 in u64 order with no float or */
/* loop. Zero sleep keeps identity. Zero half keeps identity with no divide. */
/* At or past 64 periods returns zero, so long idle still maps to zero. */
static __always_inline u64 flow_ema_decay(u64 ema,
	u64 sleep, u64 half)
{
	u64 periods;
	u64 rem;
	u64 one;
	u64 t;
	u64 dec1;
	u64 inc2;
	u64 out;
	if (ema == 0)
		return 0;
	if (sleep == 0)
		return ema;
	if (half == 0)
		return ema;
	periods = sleep / half;
	rem = sleep % half;
	if (periods >= 64)
		return 0;
	if (periods > 0) {
		ema = ema >> periods;
		if (ema == 0)
			return 0;
	}
	if (rem == 0)
		return ema;
	one = (u64)FLOW_CPUPERF_FP_ONE;
	t = rem * one / half;
	dec1 = ema * 177ULL * t / (one * one);
	inc2 = ema * 61ULL * t * t /
	    (one * one * one);
	out = ema + inc2;
	if (out < dec1)
		return 0;
	out = out - dec1;
	if (out > ema)
		out = ema;
	return out;
}
/* Map the EMA budget to a 0 to 1024 cpuperf hint. */
/* Zero maps to zero, budget maps to 1024, over maps to */
/* 1024 with clamp, so uniform both groups with no tier. */
static __always_inline u32 flow_cpuperf_from_ema(u64 ema)
{
	u64 budget = (u64)FLOW_CPUPERF_BUDGET_NS;
	u64 v;
	if (ema == 0)
		return 0;
	if (ema >= budget)
		return 1024;
	if (budget == 0)
		return 1024;
	v = ema * 1024ULL / budget;
	if (v > 1024ULL)
		return 1024;
	return (u32)v;
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
/* Burst allowance from light depth with flood backpressure. Depth sums */
/* queued tasks in light per CPU queues capped at 4. Table is depth 0 to 1 to */
/* 4ms, depth 2 to 3 to 2ms, depth 4 and above to 1ms. Quiet keeps 4ms so */
/* lone bursts move fast with no pressure. Mild halves to 2ms so flood */
/* bursts move earlier but still above one slice with no flap on single */
/* slices. Deep floors at 1ms, so per task worst case is the floor during */
/* flood. Halves keeps the view matched to dispatch isolation with no BSS */
/* cost in stopping. Strict iff ready is zero, best effort iff ready is one. */
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
/* Weight table for 40 nice levels from minus 20 to 19. Index is nice + 20 */
/* with center 1024 at nice 0. Ends are 2048 at minus 20 and 256 at 19, so */
/* total spread K is 8 with boost 2x and penalty 4x. Made as 1024 times 2 to */
/* minus nice over 20 below 1, else 1024 times 4 to minus nice over 19, */
/* rounded. The maker is docs only, the table is rodata. */
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
/* Deadline from clamped time and scaled estimate. */
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
/* Cursor peer without stand, top stays masked. */
static __always_inline u32 flow_cursor_val(u32 cursor)
{
	return cursor & (u32)FLOW_CURSOR_MASK;
}
/* True when the stand latch is held in bit10. */
/* Bits 0 to 9 hold peer, bit10 holds stand, so */
/* peer reads mask the flag. */
static __always_inline bool flow_stand_held(u32 cursor)
{
	return (cursor &
	    (u32)FLOW_CURSOR_STAND_BIT) != 0;
}
/* Delay sample in 32us units from queued count. */
/* One queued is 31 units, 512us arms at 16. */
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
/* Max of two delay samples with cap at 250. Win and cur are dual writer max, */
/* count is running only. Lost race drops at most one sample with no count */
/* skew, decay intact. */
static __always_inline u8 flow_delay_max(u8 a,
	u8 b)
{
	u8 m = a > b ? a : b;
	if ((u32)m > (u32)FLOW_DELAY_MAX)
		return (u8)FLOW_DELAY_MAX;
	return m;
}
/* Close one window of 8 with decay and max. Decays the old max by 1/8 then */
/* keeps the max with the current window max with cap at 250. */
static __always_inline u8 flow_delay_close(u8 win,
	u8 cur)
{
	u8 d = flow_delay_decay(win);
	u8 m = flow_delay_max(d, cur);
	return m;
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
/* True when perf mode is on for S0 plus S1. */
/* BSS flag holds zero for strict plus one for perf. */
/* S0 keeps tier order with wider any allowed set, */
/* S1 bypasses the kick group gate with no recount. */
/* Mask always wins in both modes with no new knob. */
/* Extern lives in the function body, so bindgen keeps */
/* no host copy with BSS only in main. */
static __always_inline bool flow_perf_enabled(void)
{
	extern volatile u8 flow_perf_mode;
	return flow_perf_mode != 0;
}
/* Deadline with the low 16 bits cleared near 64us down. Clearing moves early */
/* only, so order never moves late with at most 65535ns of earliness. */
static __always_inline u64 flow_qdl_round_down(u64 dl)
{
	return dl & ~0xFFFFULL;
}
/* Probe of one deadline into quantised deadline, slot, error, and overflow. */
/* Base is the enqueue frontier in vruntime, never ktime. Overdue keeps the */
/* rounded deadline with slot zero and no overflow. Inside keeps the rounded */
/* deadline with the slot from the rounded distance shifted by 16. Outside */
/* pins to the tail at frontier plus horizon minus one with the last slot */
/* and overflow set. Error holds deadline minus rounded deadline */
/* in 0 to 65535. One pass keeps a single horizon test with no double read. */
static __always_inline u64 flow_wheel_probe(u64 dl,
	u64 frontier, u64 *slot, u64 *err, bool *over)
{
	u64 e;
	bool overdue;
	bool inside;
	bool is_over;
	u64 qdl;
	u64 s;
	e = dl & (u64)FLOW_WHEEL_QUANT_LO;
	*err = e;
	overdue = flow_time_before(dl, frontier);
	inside = overdue ||
	    ((dl - frontier) < (u64)FLOW_WHEEL_HORIZON_NS);
	is_over = !inside;
	*over = is_over;
	if (is_over) {
		u64 tail = frontier +
		    (u64)FLOW_WHEEL_HORIZON_NS - 1ULL;
		qdl = flow_qdl_round_down(tail);
		*slot = (u64)FLOW_WHEEL_TOTAL - 1ULL;
		return qdl;
	}
	qdl = flow_qdl_round_down(dl);
	if (flow_time_before(qdl, frontier)) {
		*slot = 0;
		return qdl;
	}
	s = (qdl - frontier) >> 16ULL;
	if (s >= (u64)FLOW_WHEEL_TOTAL)
		s = (u64)FLOW_WHEEL_TOTAL - 1ULL;
	*slot = s;
	return qdl;
}
/* Slot id of one group overflow with light as default. Holds overflow base */
/* plus group, so two tails keep queue order per group with no share. Bad */
/* group falls to light with no trap. Slot only, never vtime, so per DSQ one */
/* flavor holds with mask wins on drain. */
static __always_inline u64 flow_slot_overflow_dsq(u8 group)
{
	if (group == (u8)FLOW_GROUP_HOG)
		return (u64)FLOW_SLOT_OVERFLOW_BASE + 1ULL;
	return (u64)FLOW_SLOT_OVERFLOW_BASE;
}
/* Slot id of one CPU group with light as default. Holds base plus CPU */
/* times 2 plus group, so two per CPU keep light and hog apart with no */
/* share. Bad group falls to light with no trap. Slot only, never vtime, */
/* so per DSQ one flavor holds with mask wins on drain. */
/* DSQ low bit is group, so base plus stride stay even. */
/* Base even keeps light even, stride 2 keeps hog odd. */
_Static_assert((FLOW_SLOT_BASE & 1) == 0,
    "slot base even keeps DSQ low bit group");
_Static_assert((FLOW_SLOT_PER_CPU & 1) == 0,
    "slot stride even keeps DSQ low bit group");
static __always_inline u64 flow_slot_cpu_dsq(u32 cpu,
	u8 group)
{
	u64 g = group == (u8)FLOW_GROUP_HOG ? 1ULL : 0ULL;
	return (u64)FLOW_SLOT_BASE + (u64)cpu * 2ULL + g;
}
/* True when one insert takes head with bounded LIFO at K 8. */
/* Takes head for 8 of 9 with one tail plus one forced tail at MAX, so */
/* fresh work wins fast with no starve or preempt use. Forced tails */
/* at period plus MAX keep max gap 9 with 8 heads everywhere with wrap, */
/* so the bound stays exact with one compare and no new state. Pure with */
/* no BSS use, so tests mirror the period with no drift. */
static __always_inline bool flow_lifo_take_head(u32 seq)
{
	if (seq == 0xffffffffU)
		return false;
	return (seq % (u32)FLOW_LIFO_PERIOD) !=
	    (u32)FLOW_LIFO_K;
}
/* Index of one LIFO sequence with per CPU plus overflow at 2050. */
/* Per CPU holds CPU times 2 plus group, overflow holds 2048 plus group, */
/* so total 2050 matches slot max with no share. Bad group falls to light */
/* with no trap. Pure with no state. */
static __always_inline u32 flow_lifo_idx(bool over,
	u32 cpu, u8 group)
{
	u32 g = group == (u8)FLOW_GROUP_HOG ? 1U : 0U;
	if (over)
		return 2048U + g;
	return cpu * 2U + g;
}
/* Least donor depth for one steal with idle empty fast path. Holds 1 when */
/* idle empty, else 2, so idle owners collect the last task with no strand. */
static __always_inline u64 flow_steal_need(bool idle_empty)
{
	if (idle_empty)
		return 1ULL;
	return (u64)FLOW_STEAL_MIN_DEPTH;
}
/* Cap of one trip at D under the dispatch budget. Returns the min of budget */
/* and 4, so one per CPU queue or overflow moves at most 4 with the shared */
/* loop and no K loop. Mirrors the drain cap with the same test. */
static __always_inline u32 flow_slot_cap(u32 budget)
{
	if (budget > (u32)FLOW_SLOT_D)
		return (u32)FLOW_SLOT_D;
	return budget;
}
/* Own cap of one dispatch at budget minus one. Holds 31 with budget 32, so */
/* one slot stays for overflow, other CPU, and other overflow plus steal */
/* with no strand on saturated own. Zero stays zero with no wrap. Mirrors */
/* the BPF reserve. */
static __always_inline u32 flow_slot_own_cap(u32 budget)
{
	if (budget == 0)
		return 0;
	return budget - 1U;
}
/* Granule in nanos quarter slice with 64us floor. Base is slice times 1024 */
/* over weight quartered with floor at 64us, so heavy keeps short and light */
/* keeps long with no trap on zero input. Short heavy is stricter, tempering */
/* deadline lead. Net easiness is deadline math, not gran. Quarter bounds */
/* theft near 25% of a slice. Floor covers IPI and switch cost, no thrash. */
/* Uses woken weight only, see deserved. Minimal with no wrap and no branch. */
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
/* True when woken deadline beats frontier plus gran plus slack. Frontier is */
/* the service floor, so beating it by granule proves earliness with no */
/* occupant state. Slack is 32us bounded at half the 64us floor, so near */
/* misses ease with no storm. Wrap safe via time before on the summed bound */
/* with no branch. Granule uses woken weight only, occupant weight stays out */
/* after the frontier compare fix. Minimal with no new constant. */
static __always_inline bool flow_deserved(u64 woken_dl,
	u64 frontier, u64 granule)
{
	return flow_time_before(woken_dl,
	    frontier + granule + (u64)FLOW_DESERVED_SLACK_NS);
}
/* True when one queue holds at most one task for empty first. */
/* Holds when queued is zero or one, else false, so deep */
/* queues stay quiet with no storm and no time use. Minimal */
/* compare with no wrap and no new constant. */
static __always_inline bool flow_empty_ok(u64 q)
{
	return q <= 1ULL;
}
/* True when one wake earns the CPU by earliness or hog. */
/* Holds when deserved holds or occupant holds hog regardless */
/* of waker class, so hog occupants preempt with no time cap */
/* past empty first, still bounded by empty plus same plus mask */
/* plus rate. Minimal OR with no wrap and no new branch. */
static __always_inline bool flow_deserved_or_hog(bool deserved,
	bool occupant_hog)
{
	return deserved || occupant_hog;
}
#endif
