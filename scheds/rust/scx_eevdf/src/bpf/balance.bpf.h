/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.
 *
 * What both balancers and the idle pull need of each other: whether a task
 * is still cache hot where it is, the cursor a bounded scan of a remote
 * queue walks, and what an active balance came to.
 */
#pragma once

#include "eevdf.bpf.h"
#include "queue.bpf.h"

/*
 * Is the task of @tctx, queued on @src_cid, still cache hot there as far as
 * @dst_cid is concerned?
 *
 * Two threads of one core share every cache there is, so a task is never
 * hot between them: moving it costs nothing and leaving one of them idle
 * costs a thread. task_hot() says the same of a domain with
 * SD_SHARE_CPUCAPACITY.
 */
static bool task_hot(const task_ctx_t *tctx, s32 src_cid, s32 dst_cid,
		     u64 now)
{
	if (smt_enabled &&
	    cid_topo(src_cid)->core_base == cid_topo(dst_cid)->core_base)
		return false;

	return time_before(now, tctx->last_stop_at + migration_cost_ns);
}

#define BALANCE_TASK_SCAN	8U

static __always_inline void
edq_scan_reset(scx_edq_cursor_t *cursor)
{
	scx_edq_cursor_reset(cursor);
}

/*
 * Fetch the next task in deadline order and advance @cursor past it. A queue
 * mutation cannot invalidate the cursor because it contains the ordering key,
 * not a node pointer. Reaching the end resets the scan so its next bounded
 * pass wraps to the head and tasks inserted before the cursor are eventually
 * considered too.
 */
static __always_inline int
edq_scan_next(s32 src_cid, scx_edq_cursor_t *cursor,
	      cid_edq_task_t **atp)
{
	return cid_edq_try_peek_next(src_cid, cursor, atp);
}

enum active_balance_outcome {
	ACTIVE_BALANCE_MISS,
	ACTIVE_BALANCE_MOVED,
	ACTIVE_BALANCE_PINNED,
};
