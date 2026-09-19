/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.
 *
 * The capacity a cid actually delivers, and the load balance normalizes
 * against.
 *
 *
 * Why it has to be measured
 * -------------------------
 *
 * fair.c scales a runqueue's capacity by what RT, deadline, IRQ and steal
 * time take from that CPU, each tracked by a PELT signal of its own, so
 * that balance compares CPUs by what they can still give to fair tasks. A
 * sched_ext scheduler is told none of that: it sees its own callbacks and
 * nothing else. Without it, work displaced by a higher class stays where
 * it is, because the balancer reads that cid's load as normal and its
 * capacity as full.
 *
 * So it is inferred from the events the scheduler does see:
 *
 *   demand    |<---------------- 32 ms window ---------------->|
 *   ours       ====      =========        ====   ===========
 *   displaced      xxxxxx         xxxxxxxx    xxx
 *                  ^     ^
 *                  |     ops.running(): one of ours runs again, the
 *                  |     interval ends
 *                  ops.stopping() with slice left: the task did not yield,
 *                  something above us took the CPU
 *
 *   available = 1024 - lost / elapsed        (smoothed, 3:1, over windows)
 *   busy_balance_cap = capacity * available / 1024
 *
 * Two things keep that honest. The window only runs while sched_ext has
 * runnable work on the cid, so a CPU that is merely idle cannot look
 * constrained, and an estimate is invalidated when demand disappears -
 * there is no clock here while nothing of ours wants the CPU, unlike
 * fair.c's RT PELT which decays on its own. And the interval is measured
 * between scheduling events in the task clock, so ordinary dispatch and
 * context-switch overhead is not counted as pressure; IRQ and steal time
 * come from the drift between the rq clock and the task clock over the
 * same window.
 *
 *
 * What reads it
 * -------------
 *
 * Periodic balance divides each cid's load by busy_balance_cap instead of
 * by its nominal capacity, so a cid that only gets half of itself counts
 * as twice as loaded. cid_capacity_reduced() is fair.c's
 * check_cpu_capacity(), with the same 117% threshold, and a task displaced
 * on such a cid gets a paced search for a better one in balance.bpf.c.
 *
 * The signals a wakeup or a switch reads - what a task uses, how busy a
 * cid has been, and the averaged runnable weight that stands for its load
 * in wake_affine_weight() - are inline in load.bpf.h, where they cost a
 * few instructions on the hot path.
 */
#include "eevdf.bpf.h"
#include "load.bpf.h"

#define PRESSURE_EVAL_NS	(32ULL * NSEC_PER_MSEC)

static void update_balance_cap(s32 cid, u64 now)
{
	struct cid_ctx __arena *cctx = cid_ctx(cid);
	u64 cap = cid_topo(cid)->cap;
	u64 elapsed, lost, off, available;

	if (!capacity_pressure)
		return;
	if (!cctx->pressure_demand)
		return;
	elapsed = now - cctx->pressure_at;
	if (elapsed < PRESSURE_EVAL_NS)
		return;
	/* Refresh rq_clock - rq_clock_task; its delta is IRQ plus steal time. */
	cid_clock_task_owned(cid, now);
	off = cctx->clock_off;
	lost = cctx->pressure_lost - cctx->pressure_lost_at;
	if (off > cctx->pressure_clock_off_at)
		lost += off - cctx->pressure_clock_off_at;
	available = 1024 - MIN(lost * 1024 / elapsed, 1024ULL);
	if (cctx->pressure_valid)
		cctx->pressure_avail = (3 * cctx->pressure_avail + available) / 4;
	else
		cctx->pressure_avail = available;
	cctx->pressure_at = now;
	cctx->pressure_lost_at = cctx->pressure_lost;
	cctx->pressure_clock_off_at = off;
	cctx->pressure_valid = 1;
	WRITE_ONCE(cctx->busy_balance_cap,
		   MAX(cap * cctx->pressure_avail / 1024, 1ULL));
}

/* fair.c's check_cpu_capacity(), using the domain's imbalance threshold. */
static bool cid_capacity_reduced(s32 cid)
{
	u64 cap;

	if (!capacity_pressure || !cid_valid(cid) ||
	    !READ_ONCE(cid_ctx(cid)->pressure_demand) ||
	    !READ_ONCE(cid_ctx(cid)->pressure_valid))
		return false;
	cap = READ_ONCE(cid_ctx(cid)->busy_balance_cap);
	return cap && cap * BUSY_BALANCE_IMBALANCE_PCT <
		cid_topo(cid)->cap * 100;
}
