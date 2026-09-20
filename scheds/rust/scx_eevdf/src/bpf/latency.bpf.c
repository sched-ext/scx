/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.
 *
 * Virtual-time borrowing for latency-sensitive wakees. Admission follows
 * user-space CPU pressure, and placement floors a wakee's carried lag at a
 * fixed virtual-time credit.
 */
#include "latency.bpf.h"
#include "task.bpf.h"

#define USER_EVAL_NS		10000000ULL
#define USER_STALE_EVALS	5
#define USER_STALE_NS		(USER_EVAL_NS * USER_STALE_EVALS)

static volatile u64 user_util_sum __hot_written;
static volatile u64 user_util_snapshot_at __hot_written;

/*
 * Refresh the system-wide user-utilization snapshot from the per-cid EWMAs.
 * Only one caller does the bounded scan in each evaluation period, keeping
 * the scan out of the wakeup path. The result is a bounded-age snapshot, not
 * a simultaneous observation. Stale cids contribute zero.
 */
static void update_user_util_snapshot(u64 now)
{
	u64 last = user_util_snapshot_at;
	u64 sum = 0;
	u32 i;

	if (now - last < USER_EVAL_NS)
		return;
	if (__sync_val_compare_and_swap(&user_util_snapshot_at, last, now) != last)
		return;

	bpf_arena_for(i, 0, nr_cids) {
		struct cid_ctx __arena *cctx = cid_ctx(i);

		if (now - cctx->user_eval_at <= USER_STALE_NS)
			sum += cctx->user_util_ewma;
	}
	user_util_sum = sum;
}

/*
 * Charge p->utime deltas from the tick and when the task stops, then fold
 * them every 10ms into an EWMA of the fraction of wall time spent in user
 * space. System time is excluded so syscall-heavy sleep workloads do not
 * enable the credit.
 */
static void update_cid_user(struct task_struct *p, s32 cid,
			    task_ctx_t *tctx, u64 now)
{
	struct cid_ctx __arena *cctx;
	u64 delta, util;

	if (!latency_credit || !latency_credit_user_thresh || !cid_valid(cid))
		return;
	cctx = cid_ctx(cid);

	/*
	 * ops.running() resets last_utime, and tick/stopping charge the delta
	 * to the cid on which that run occurred. A migration crosses a
	 * stopping/running pair, so task-global utime does not leak between
	 * cids while a task is queued.
	 */
	cctx->user_acc += p->utime - tctx->last_utime;
	tctx->last_utime = p->utime;

	delta = now - cctx->user_eval_at;
	if (delta < USER_EVAL_NS)
		return;

	util = MIN(cctx->user_acc * 1024 / delta, 1024);
	cctx->user_util_ewma = (cctx->user_util_ewma -
				  (cctx->user_util_ewma >> 2)) + (util >> 2);
	cctx->user_acc = 0;
	cctx->user_eval_at = now;

	if (!cctx->user_busy &&
	    cctx->user_util_ewma >= latency_credit_user_thresh)
		cctx->user_busy = true;
	else if (cctx->user_busy &&
		 cctx->user_util_ewma < latency_credit_user_thresh -
					 latency_credit_user_thresh / 4)
		cctx->user_busy = false;

	/* The aggregate can only change when one of its samples changes. */
	update_user_util_snapshot(now);
}

static bool cid_user_busy(s32 cid, u64 now)
{
	struct cid_ctx __arena *cctx;
	u64 local = 0, peers;

	if (!latency_credit_user_thresh)
		return true;
	cctx = cid_ctx(cid);
	if (now - cctx->user_eval_at <= USER_STALE_NS) {
		local = cctx->user_util_ewma;
		if (cctx->user_busy)
			return true;
	}

	if (nr_cids <= 1 || now - user_util_snapshot_at > USER_STALE_NS)
		return false;

	/*
	 * The target's utilization can fall when latency-sensitive work
	 * displaces its sole CPU hog. Use the continuous mean utilization of the
	 * other cids as independent evidence that this is a placement hole in
	 * an otherwise user-saturated system. user_util_sum is a periodic
	 * snapshot, while local is the target's latest EWMA, so this is an
	 * intentionally approximate leave-one-out value.
	 */
	peers = user_util_sum;
	if (peers >= local)
		peers -= local;
	else
		peers = 0;

	if (peers >= latency_credit_user_thresh * (nr_cids - 1))
		return true;

	return false;
}

static __always_inline bool task_credit_admitted(s32 cid, u64 now)
{
	return latency_credit && cid_user_busy(cid, now);
}

/*
 * Return the offset from the destination reference used to place @p: the lag
 * carried out of its old pack, with a minimum of the configured virtual-time
 * credit when latency-credit admission succeeds.
 *
 * The credit is a fixed placement scale rather than a computed minimum needed
 * to cross the current deadline frontier. It is scaled by the task's deadline
 * weight and granted only on a cid with sustained user-space utilization. A
 * CPU busy in the kernel keeps the lag the task earned instead.
 */
static s64 task_place_offset(s32 cid, const struct task_struct *p,
			     task_ctx_t *tctx, u64 now)
{
	s64 credit;

	if (!task_credit_admitted(cid, now))
		return tctx->se.vlag;

	credit = (s64)scale_by_dl_weight(p, tctx, latency_credit_ns);

	return MAX(tctx->se.vlag, credit);
}
