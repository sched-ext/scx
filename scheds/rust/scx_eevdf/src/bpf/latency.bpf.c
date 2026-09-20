/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.
 *
 * Virtual-time borrowing for latency-sensitive wakees. Admission follows
 * user-space CPU pressure, placement floors a wakee's carried lag at a fixed
 * virtual-time credit, and optional packing sends admitted work to a higher
 * asymmetric-packing tier when no CPU is idle.
 */
#include "latency.bpf.h"
#include "task.bpf.h"

#define USER_EVAL_NS		10000000ULL
#define USER_STALE_EVALS	5
#define USER_STALE_NS		(USER_EVAL_NS * USER_STALE_EVALS)

static volatile u64 user_util_sum __hot_written;
static volatile u64 user_util_snapshot_at __hot_written;
static u64 credit_pack_cursor;

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

/*
 * Return whether @tctx may borrow on @cid. The sleep window is always met by
 * a wakeup; it also defines the current tasks that packing leaves alone.
 */
static __always_inline bool task_credit_admitted(s32 cid,
						 const task_ctx_t *tctx, u64 now)
{
	return latency_credit && cid_user_busy(cid, now) &&
	       now - tctx->last_sleep_at < latency_credit_sleep_ns;
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

	if (!task_credit_admitted(cid, tctx, now))
		return tctx->se.vlag;

	credit = (s64)scale_by_dl_weight(p, tctx, latency_credit_ns);

	return MAX(tctx->se.vlag, credit);
}

/*
 * Return the cid an admitted wakee is queued on when the idle scan found
 * nothing: @target, unless a cid of a higher asymmetric-packing priority
 * is running a task that never sleeps.
 *
 * SD_ASYM_PACKING fills the preferred CPUs first, and fair.c's asymmetric
 * active balance pulls a running task up to a preferred CPU only when that
 * CPU is idle. With a hog on every CPU nothing is ever idle, and a task
 * stays wherever its wakeups keep finding it. The WebGL aquarium's render
 * thread sat on an E-core at 2.2 GHz for as long as the hogs ran, at 19
 * fps, while the same thread pinned to a P-core beside its hog made 37 to
 * 46. The credit already lets the wakee win the CPU from a hog wherever it
 * lands, so let it land where the CPU is fastest: the hog there loses its
 * turn, and the balancer finds it a lower-priority CPU in due course. A
 * cid whose current task slept recently is left alone, it is running work
 * of the same kind, and a cursor spreads successive wakees over the tier.
 * A task pinned to one CPU, or one whose target is already in the top
 * tier, is not moved.
 */
static s32 credit_pack_cid(const struct task_struct *p, task_ctx_t *tctx,
			   s32 target, u64 now)
{
	u32 tier, t, i, start;
	bool restricted;

	if (!latency_credit || no_latency_credit_pack || !asym_packing ||
	    nr_place_tiers < 2 || !cid_valid(target) || is_pcpu_task(p))
		return target;
	tier = cid_topo(target)->place_tier;
	if (!tier || !task_credit_admitted(target, tctx, now))
		return target;

	restricted = is_restricted(p);
	start = __sync_fetch_and_add(&credit_pack_cursor, 1);
	bpf_arena_for(t, 0, tier) {
		bpf_arena_for(i, 0, nr_cids) {
			s32 cid = (start + i) % nr_cids;

			if (cid_topo(cid)->place_tier != t)
				continue;
			if (READ_ONCE(cid_ctx(cid)->curr_sleeper))
				continue;
			if (restricted && !cid_allowed(p, cid))
				continue;
			return cid;
		}
	}

	return target;
}
