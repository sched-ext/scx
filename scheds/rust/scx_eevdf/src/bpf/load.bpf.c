/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.
 *
 * The capacity a cid actually delivers: what a higher scheduling class,
 * interrupts and steal time take from it, measured over a demand window and
 * published for periodic balance to normalize load against.
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
