/* Copyright (c) Meta Platforms, Inc. and affiliates. */
/*
 * This software may be used and distributed according to the terms of the
 * GNU General Public License version 2.
 *
 * Slice shrinking: when a CPU-pinned task is waiting in a per-CPU DSQ,
 * shrink the running task's remaining slice so the waiter runs sooner.
 * The shrink limit scales with the waiter's EWMA runtime.
 *
 * ── Problem ──────────────────────────────────────────────────────
 *
 * Mitosis slices are long (20ms). A CPU-pinned task must wait behind
 * whatever is running, which hurts two cases:
 *
 *   1. System tasks (kworkers, softirqd) that need microseconds and
 *      may wake other threads.
 *   2. Workload threads pinned to a CPU subset — long waits increase
 *      runnable time and can reduce throughput.
 *
 * ── How slice shrinking works ────────────────────────────────────
 *
 * When a pinned waiter is detected, the running task's slice is
 * shrunk to avg_runtime * K (the waiter's EWMA runtime times a
 * multiplier), clamped to [min, max]. Any task type can be shrunk.
 *
 * Two event-driven checks (no polling):
 *   enqueue()  — pinned waiter arrives while another task is running
 *   running()  — task starts and pinned waiters are already queued
 *
 * Idempotent: if (slice > limit) slice = limit. Repeated shrinking
 * is a no-op.
 *
 * ── Shrink limit ─────────────────────────────────────────────────
 *
 * The limit is computed from the waiter's EWMA runtime:
 *
 *   limit = clamp(avg_runtime * K, min, max)
 *
 * With defaults K=2, min=500us, max=4ms:
 *
 * K controls how much of its slice the running task keeps:
 *
 *   K   500us waiter   2ms waiter    Tradeoff
 *   ──  ────────────   ──────────    ──────────────────
 *   1   500us (min)    2ms           Aggressive shrinking
 *   2   1ms            4ms (max)     Balanced (default)
 *   4   2ms            4ms (max)     Conservative
 *
 * ── Possible limitations ────────────────────────────────
 *
 * 1. A pinned task with high vtime may sit in the CPU DSQ without
 *    being dispatched (dispatch picks lowest vtime across DSQs).
 *    This causes repeated shrinking without the waiter ever running.
 *    This doesn't "rob" the runner or "boost" the pinned task,
 *    vtime is still respected. It just introduces more context switches.
 *    Possible fix: check if waiter's vtime is competitive before shrinking.
 *
 * 2. Some tasks, like softirqd workers, may benefit from batching
 *    rather than running immediately on every wakeup.
 *    Possible fix: track running frequency and suppress shrinking
 *    above some threshold.
 */
#pragma once

#include "mitosis.bpf.h"
#include "dsq.bpf.h"

/* ── Config (populated by userspace rodata) ────────────────────────── */

/* Defaults are in main.rs; userspace always overwrites via rodata */
const volatile bool enable_slice_shrinking;
const volatile u64 slice_shrink_min_ns;
const volatile u64 slice_shrink_max_ns;
const volatile u32 slice_shrink_multiplier;

/* ── Helpers ───────────────────────────────────────────────────────── */

enum slice_shrink_result {
	SHRINK_NONE = 0, /* no shrinking occurred */
	SHRINK_MIN, /* min used (prop was below min) */
	SHRINK_PROPORTIONAL, /* proportional shrink between min and max */
	SHRINK_MAX, /* max used (prop >= max) */
};

/*
 * Compute the effective shrink limit given a waiter's EWMA runtime.
 * Sets *result to indicate which category was used.
 */
static inline u64 slice_shrink_limit(u64 avg_runtime_ns, enum slice_shrink_result *result)
{
	/* Max shrunken slice */
	u64 limit = slice_shrink_max_ns;
	*result = SHRINK_MAX;

	u64 prop = avg_runtime_ns * slice_shrink_multiplier;
	if (prop < slice_shrink_min_ns) {
		/* Very short task — clamp to min */
		limit = slice_shrink_min_ns;
		*result = SHRINK_MIN;
	} else if (prop < limit) {
		/* Within proportional range */
		limit = prop;
		*result = SHRINK_PROPORTIONAL;
	}

	return limit;
}

/* Shrink p's slice to limit and bump the appropriate stat counter. */
static inline void slice_shrink_apply(struct task_struct *p, u64 limit,
				      enum slice_shrink_result result, u32 cell,
				      struct cpu_ctx *cctx)
{
	if (p->scx.slice > limit) {
		p->scx.slice = limit;
		if (result == SHRINK_MAX)
			cstat_inc(CSTAT_SLICE_SHRINK_MAX, cell, cctx);
		else if (result == SHRINK_PROPORTIONAL)
			cstat_inc(CSTAT_SLICE_SHRINK_PROPORTIONAL, cell, cctx);
		else if (result == SHRINK_MIN)
			cstat_inc(CSTAT_SLICE_SHRINK_MIN, cell, cctx);
	}
}

/*
 * Called from enqueue() when a pinned waiter arrives.
 * Shrinks the currently running task's slice based on the waiter's
 * EWMA runtime. Caller must check enable_slice_shrinking and curr.
 */
static inline void slice_shrink_on_enqueue(struct task_struct *curr,
					   struct task_ctx *pinned_waiter_tctx, u32 cell,
					   struct cpu_ctx *cctx)
{
	enum slice_shrink_result result;
	u64 limit = slice_shrink_limit(pinned_waiter_tctx->avg_runtime_ns, &result);
	slice_shrink_apply(curr, limit, result, cell, cctx);
}

/*
 * Called from running() to shrink our slice when waiters are queued
 * on our CPU DSQ. Peeks the head waiter for EWMA data.
 * Caller must check enable_slice_shrinking.
 */
static inline int slice_shrink_on_running(struct task_struct *p, u32 cell, struct cpu_ctx *cctx)
{
	dsq_id_t cpu_dsq = get_cpu_dsq_id(scx_bpf_task_cpu(p));
	if (dsq_is_invalid(cpu_dsq))
		return -1;

	s32 nr_queued = scx_bpf_dsq_nr_queued(cpu_dsq.raw);
	if (nr_queued < 0) {
		scx_bpf_error("scx_bpf_dsq_nr_queued failed: %d", nr_queued);
		return -1;
	}
	/* Nothing to shrink for */
	if (nr_queued == 0)
		return 0;

	/*
	 * Possible limitation: deeper queued task has lower avg runtime than head.
	 */
	struct task_struct *waiter = dsq_peek(cpu_dsq.raw);
	/* Raced with num queued above. Do nothing. */
	if (!waiter)
		return 0;

	struct task_ctx *wtctx = lookup_task_ctx(waiter);
	if (!wtctx)
		return -ENOENT;

	enum slice_shrink_result result;
	u64 limit = slice_shrink_limit(wtctx->avg_runtime_ns, &result);

	slice_shrink_apply(p, limit, result, cell, cctx);
	return 0;
}
