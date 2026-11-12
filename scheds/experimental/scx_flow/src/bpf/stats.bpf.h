// SPDX-License-Identifier: GPL-2.0
/*
 * Counters for the flow scheduler.
 *
 * Each helper updates the counters of one LLC. The queued gauge
 * never drops below zero. It uses a short compare and swap loop.
 * When the loop loses, a saturating atomic step keeps the floor
 * with no plain store, so a decrement is not lost under contention.
 * An unknown offset does nothing. Shared plus fallback inserts count
 * the gauge with fallback inserts also counting fallback. Dequeue
 * drops the gauge on cancel. Exit drops the gauge only when the queued
 * bit shows pending. Running clears ownership with no gauge move.
 * A duplicate requeue counts the duplicate counter only with no gauge
 * move. The thirteen counters keep their order for the userspace
 * reader with no new counter.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
#ifndef __FLOW_STATS_BPF_H
#define __FLOW_STATS_BPF_H
#include "intf.h"
#include "maps.bpf.h"
static __always_inline struct flow_llc_stats *flow_stats_for(u32 llc)
{
	return bpf_map_lookup_elem(&llc_stats_stor, &llc);
}
static __always_inline void flow_stat_inc(u32 llc, u64 off)
{
	struct flow_llc_stats *st = flow_stats_for(llc);
	u64 *cell;
	if (!st)
		return;
	if (off == 0)
		cell = &st->queued;
	else if (off == 1)
		cell = &st->dispatched;
	else if (off == 2)
		cell = &st->fallback;
	else if (off == 3)
		cell = &st->steal;
	else if (off == 4)
		cell = &st->fb_duplicate;
	else if (off == 5)
		cell = &st->steal_llc;
	else if (off == 6)
		cell = &st->kick_preempt;
	else if (off == 7)
		cell = &st->kick_idle;
	else if (off == 8)
		cell = &st->kick_skip;
	else if (off == 9)
		cell = &st->overrun;
	else if (off == 10)
		cell = &st->blocked;
	else if (off == 11)
		cell = &st->orphan_kick;
	else if (off == 12)
		cell = &st->hol_forward;
	else
		return;
	__sync_fetch_and_add(cell, 1ULL);
}
/* Guard kept helper with no caller in tree. Counts fallback plus
 * the given tail with no new counter. */
static __always_inline void flow_fb_inc(u32 llc, u64 tail_off)
{
	flow_stat_inc(llc, 2);
	flow_stat_inc(llc, tail_off);
}
static __always_inline void flow_queued_dec(u32 llc)
{
	struct flow_llc_stats *st = flow_stats_for(llc);
	int i;
	if (!st)
		return;
	for (i = 0; i < 4; i++) {
		u64 old = READ_ONCE(st->queued);
		u64 next;
		if (old == 0)
			return;
		next = old - 1;
		if (__sync_val_compare_and_swap(&st->queued, old, next) == old)
			return;
	}
	{
		u64 old = __sync_fetch_and_sub(&st->queued, 1ULL);
		if (!old)
			__sync_fetch_and_add(&st->queued, 1ULL);
	}
}
#endif
