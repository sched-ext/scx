/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.
 *
 * Group scheduling: what the cgroup of a task does to the weight it is
 * queued at, and to whether it may run at all. What a context switch pays
 * for is here; the registry, the sweep, the bandwidth pool, the backlog and
 * the cgroup callbacks are in cgroup.bpf.c.
 */
#pragma once

#include "eevdf.bpf.h"

/*
 * Group scheduling, fair.c's with a single runqueue: a cgroup's task on a cid
 * is queued, placed and picked in the cid's own pack beside every other task,
 * at an effective weight that is its share of the hierarchy, and the cgroup
 * hierarchy itself only keeps the weights that share is computed from, see
 * commit 85570f10a4c6 ("sched/eevdf: Move to a single runqueue").
 *
 * One struct grp_q per cgroup per cid, the load of fair.c's cfs_rq of the
 * group: @load is the weight of the group's members on the cid, its tasks at
 * their nice weights and its child groups at their shares, and @contrib is
 * what the group adds to its parent's @load there, its shares while it has
 * any member and nothing otherwise. A task's effective weight is its nice
 * weight scaled by shares / load at every level up to the cid's own,
 * __calc_prop_weight() in enqueue_hierarchy(), see grp_h_weight().
 *
 * A cgroup at the root has no queues, its tasks weigh their nice weights. A
 * cgroup nested deeper than GRP_MAX_DEPTH shares its ancestor's at that depth.
 */
#define GRP_MAX_DEPTH	8

struct grp_hdr {
	u64 weight;		/* cpu.weight as a load weight, tg->shares */
	u64 pages;		/* arena pages of this block */
	u64 idle;		/* cpu.idle, see eevdf_cpuctl_set_idle() */
	u64 slot;		/* its index in @grp_hdrs */
	u64 next_free;		/* next block to free, see grp_free_defer() */

	/* cpu.max, see eevdf_cpuctl_set_bandwidth() */
	u64 quota;		/* what the group may run for in a period, 0 for no limit */
	u64 period;		/* the period, cfs_bandwidth->period */
	u64 burst;		/* what it may carry into one, cfs_bandwidth->burst */
	u64 period_start;	/* when the period it is in began */
	u64 pool;		/* what is left of its bandwidth in it, cfs_b->runtime */
	u64 throttled;		/* whether it has run out, cfs_rq->throttled */
	u64 throttled_at;	/* when it did */
	u64 throttled_ns;	/* how long it has spent out of bandwidth */
	u64 nr_throttled;	/* how often it has run out */
	u64 bw_gen;		/* bumped when cpu.max changes, see grp_bw_charge() */
	u64 bw_slot;		/* its index in @bw_hdrs, BW_MAX_LIMITED for none */
	u64 nr_parked;		/* tasks waiting in @bq */
	struct scx_edq bq;	/* them, see cid_park() */

	/*
	 * Moved by every cid as its queue's averages drift, see
	 * grp_update_shares() and grp_live_update(). On a line of their own:
	 * ops.running() reads @idle and the wakeup path reads the cpu.max
	 * state on every switch, and a line that is also written from every
	 * CPU is one those reads miss.
	 */
	u64 load_avg __attribute__((aligned(64)));	/* sum of the queues' averaged loads, tg->load_avg */
	u64 nr_avg;		/* sum of their averaged task counts, tg->runnable_avg */
};

struct grp_q {
	u64 load;
	u64 contrib;
	u64 shares;		/* the group's weight in its parent on this cid */
	u64 nr;			/* tasks queued in the group or below it on this cid */
	struct grp_q __arena *parent;	/* NULL for a child of the root */
	struct grp_hdr __arena *hdr;
	struct ravg_data load_avg;	/* @load averaged, cfs_rq->avg.load_avg */
	struct ravg_data nr_avg;	/* @nr averaged, cfs_rq->avg.runnable_avg */
	u64 load_avg_contrib;	/* what @hdr->load_avg holds of this queue */
	u64 nr_avg_contrib;	/* what @hdr->nr_avg holds of this queue */
	u64 shares_at;		/* when @shares was last computed */
	s64 runtime_remaining;	/* what the cid holds of the group's bandwidth */
	u64 bw_gen;		/* the cpu.max @runtime_remaining was taken under */
	u32 cid;
	u32 avg_lock;		/* serializes the averages, see grp_avg_trylock() */
};

typedef struct grp_q __arena grp_q_t;

/*
 * cpu.max, the bandwidth the cpu controller gives a cgroup: the group may run
 * for @quota nanoseconds in every @period, plus what it carried over into the
 * period, up to @burst. A group is held to the limits of every group above it
 * as well as its own, so what binds a task is the tightest of them.
 *
 * Most machines set no limit anywhere. @bw_nr_limited counts the cgroups that
 * carry one, so that everything the accounting adds costs a single load until
 * somebody writes a cpu.max. Written by the cgroup ops, which the kernel
 * serializes; read from everywhere.
 */
#define BW_QUOTA_INF		((u64)~0ULL)	/* cpu.max "max", RUNTIME_INF */

static u64 bw_nr_limited;

/*
 * The cgroups that carry a limit, so that a cid looking for tasks to let run
 * again has a handful of blocks to look at rather than every cgroup on the
 * machine. @bw_parked says which of them have tasks waiting, and is what the
 * search reads; @bw_nr_parked keeps it out of the way entirely while nothing
 * is waiting anywhere.
 *
 * The array is written by the cgroup ops, which the kernel serializes, and a
 * cgroup that finds no free slot is accounted but never throttles: enforcing
 * it would need a slot for its backlog to be found again from.
 *
 * @bw_nr_parked keeps the search out of the way entirely while nothing is
 * waiting anywhere, which is every machine that sets no cpu.max and every
 * moment a group is inside its limit.
 */
#define BW_MAX_LIMITED		1024
#define BW_SLOT_NONE		BW_MAX_LIMITED

static u64 bw_hdrs[BW_MAX_LIMITED];		/* struct grp_hdr __arena * */
static u32 bw_hdrs_nr;				/* slots ever used */
static u64 bw_nr_parked;

/*
 * Bring what @gq and each group above it add to their parents in line with
 * their loads and shares, the sums of enqueue_hierarchy() and
 * dequeue_hierarchy().
 *
 * The loads are changed from whichever cid a task joins or leaves a pack
 * from, without a lock, so a group's @contrib is moved by compare and swap to
 * what its load says it should be, its delta is applied to the parent, and
 * the group is looked at again before going up: whoever changes a load last
 * also leaves the contributions above it matching.
 */
static void grp_contrib_sync(grp_q_t *gq)
{
	bool moved = false;
	int i;

	for (i = 0; i < 4 * GRP_MAX_DEPTH && gq && gq->parent; i++) {
		grp_q_t *parent = gq->parent;
		u64 load = READ_ONCE(gq->load);
		u64 target = load ? READ_ONCE(gq->shares) : 0;
		u64 cur = READ_ONCE(gq->contrib);

		if (cur != target) {
			if (__sync_val_compare_and_swap(&gq->contrib, cur, target) == cur) {
				__sync_fetch_and_add(&parent->load, target - cur);
				moved = true;
			}
			continue;
		}
		if (!moved)
			break;
		gq = parent;
		moved = false;
	}
}

/*
 * Add @delta to the load of @gq and take the change up the hierarchy.
 */
static void grp_load_add(grp_q_t *gq, s64 delta)
{
	__sync_fetch_and_add(&gq->load, delta);
	grp_contrib_sync(gq);
}

/*
 * Fractional bits the effective weight is carried with down the hierarchy,
 * the precision scale_load() gives fair.c's weights on 64-bit.
 */
#define GRP_WEIGHT_SHIFT	10

/*
 * The effective weight of a member of @gq that weighs @w in it: @w scaled by
 * shares / load at every level, __calc_prop_weight(). With @joining, the
 * weight it will have once it has joined, its own weight and those of the
 * groups that join with it counted in.
 *
 * The product is carried in fixed point and rounded once at the end: truncated
 * at every level, a light task in a large or deep hierarchy loses a unit per
 * level off a weight of a few units. Packs keep whole weights, which are
 * multiplied by vruntime distances, so the result still has a floor of 1
 * where fair.c's has MIN_SHARES of a scaled weight.
 */
static u64 grp_h_weight(grp_q_t *gq, u64 w, bool joining)
{
	u64 add = joining ? w : 0, wf = w << GRP_WEIGHT_SHIFT;
	int i;

	for (i = 0; gq && i < GRP_MAX_DEPTH; i++) {
		u64 shares = READ_ONCE(gq->shares);
		u64 load = READ_ONCE(gq->load) + add;

		add = joining && !READ_ONCE(gq->contrib) ? shares : 0;
		wf = wf * shares / MAX(load, 1ULL);
		gq = gq->parent;
	}

	w = (wf + (1ULL << (GRP_WEIGHT_SHIFT - 1))) >> GRP_WEIGHT_SHIFT;
	return MAX(w, 1ULL);
}

/*
 * Count a task in or out of @gq and every group above it on the cid,
 * cfs_rq->h_nr_runnable.
 */
static void grp_nr_add(grp_q_t *gq, s64 delta)
{
	int i;

	for (i = 0; gq && i < GRP_MAX_DEPTH; i++) {
		__sync_fetch_and_add(&gq->nr, delta);
		gq = gq->parent;
	}
}

/*
 * Whether the cgroup of @hdr carries a cpu.max of its own. A cgroup without
 * one still runs under the limits of the groups above it.
 */
static __always_inline bool grp_bw_limited(struct grp_hdr __arena *hdr)
{
	return READ_ONCE(hdr->quota) != 0;
}

/*
 * Whether a cgroup that runs out of bandwidth can be held to it at all:
 * without a slot among the limited cgroups its backlog could not be found
 * again, and the tasks put in it would wait there for good.
 */
static __always_inline bool grp_bw_enforced(struct grp_hdr __arena *hdr)
{
	return hdr->bw_slot < BW_MAX_LIMITED;
}

static __always_inline bool bw_enabled(void)
{
	return cpu_max_enabled && READ_ONCE(bw_nr_limited);
}

/*
 * What a cid takes from its group's bandwidth at a time, and what it keeps in
 * hand once the group is spent: sysctl_sched_cfs_bandwidth_slice, and the
 * millisecond assign_cfs_rq_runtime() leaves a throttled cfs_rq so that the
 * task on its way out is not charged against the next period.
 */
#define BW_SLICE_NS		(5 * NSEC_PER_MSEC)

/*
 * The group has run out of bandwidth for this period. Its tasks keep running
 * until somebody looks at this, see grp_bw_throttled().
 */
static void grp_bw_throttle(struct grp_hdr __arena *hdr, u64 now)
{
	if (!grp_bw_enforced(hdr) || READ_ONCE(hdr->throttled) ||
	    __sync_val_compare_and_swap(&hdr->throttled, 0, 1) != 0)
		return;

	WRITE_ONCE(hdr->throttled_at, now);
	hdr->nr_throttled++;
}

/*
 * The group has bandwidth again, whether because its period turned over or
 * because somebody widened its cpu.max.
 */
static void grp_bw_unthrottle(struct grp_hdr __arena *hdr, u64 now)
{
	if (!READ_ONCE(hdr->throttled))
		return;

	hdr->throttled_ns += now - READ_ONCE(hdr->throttled_at);
	WRITE_ONCE(hdr->throttled, 0);
}

/*
 * Start @hdr's next period if the one it is in has run out,
 * __refill_cfs_bandwidth_runtime(): the group gets its quota back, and keeps
 * what it left unused as long as its burst covers it.
 *
 * Whoever moves @period_start refills; everybody else goes on with what is
 * there. Periods are not aligned to anything, so a group that stops running
 * takes its next one from wherever it starts again, as fair.c's period timer
 * does once it has been let stop.
 */
static void grp_bw_refill(struct grp_hdr __arena *hdr, u64 now)
{
	u64 period = READ_ONCE(hdr->period);
	u64 start = READ_ONCE(hdr->period_start);
	u64 quota, burst, pool;

	if (!period || now - start < period)
		return;
	if (__sync_val_compare_and_swap(&hdr->period_start, start, now) != start)
		return;

	quota = READ_ONCE(hdr->quota);
	burst = READ_ONCE(hdr->burst);
	while (can_loop) {
		pool = READ_ONCE(hdr->pool);
		if (__sync_val_compare_and_swap(&hdr->pool, pool,
						MIN(pool + quota, quota + burst)) == pool)
			break;
	}

	grp_bw_unthrottle(hdr, now);
}

/*
 * Hand a cid that has run out @want of the group's bandwidth, and a slice
 * ahead of it so that it does not come back for every charge,
 * assign_cfs_rq_runtime(). Returns what there was to give.
 */
static u64 grp_bw_assign(struct grp_hdr __arena *hdr, u64 want)
{
	u64 pool, take;

	while (can_loop) {
		pool = READ_ONCE(hdr->pool);
		if (!pool)
			return 0;
		take = MIN(pool, want + BW_SLICE_NS);
		if (__sync_val_compare_and_swap(&hdr->pool, pool, pool - take) == pool)
			return take;
	}

	return 0;
}

/*
 * Charge @delta of runtime to the group of @gq and to every group above it,
 * account_cfs_rq_runtime() at each level of update_curr(): the time a cgroup
 * spends is spent by all of its ancestors too. A level that runs through what
 * its cid was given asks the group's pool for more, and one whose pool is
 * empty throttles itself and everything under it.
 *
 * The cid keeps what it is given across periods, as fair.c has done since it
 * stopped expiring local slices: what a cid holds and does not use is given
 * back when its queue goes quiet, see grp_bw_return().
 *
 * It does not keep it across a change of cpu.max. tg_set_cfs_bandwidth() resets
 * every cfs_rq of the group when the limit moves, and without that a cid could
 * go on spending a slice taken under the old quota: on a machine with hundreds
 * of them, a group that had touched many could overrun a lowered limit by a
 * slice apiece. The generation says which limit a slice was taken under.
 */
static void grp_bw_charge(grp_q_t *gq, u64 delta, u64 now)
{
	int i;

	for (i = 0; gq && i < GRP_MAX_DEPTH; i++, gq = gq->parent) {
		struct grp_hdr __arena *hdr = gq->hdr;
		u64 gen;
		s64 rem;

		if (!hdr || !grp_bw_limited(hdr))
			continue;

		grp_bw_refill(hdr, now);

		gen = READ_ONCE(hdr->bw_gen);
		if (READ_ONCE(gq->bw_gen) != gen) {
			WRITE_ONCE(gq->runtime_remaining, 0);
			WRITE_ONCE(gq->bw_gen, gen);
		}

		rem = READ_ONCE(gq->runtime_remaining) - (s64)delta;
		if (rem < 0)
			rem += grp_bw_assign(hdr, -rem);
		WRITE_ONCE(gq->runtime_remaining, rem);
		if (rem < 0)
			grp_bw_throttle(hdr, now);
	}
}

/*
 * A task is no longer waiting on the cgroup it was put aside for, because the
 * drain took it out of the backlog or because it left BPF custody from there.
 * Whoever took the node out of the queue does this, exactly once.
 */
static void task_bw_unparked(task_ctx_t *tctx)
{
	struct grp_hdr __arena *hdr = tctx->bw_hdr;

	if (!hdr)
		return;

	tctx->bw_hdr = NULL;
	__sync_fetch_and_sub(&hdr->nr_parked, 1);
	__sync_fetch_and_sub(&bw_nr_parked, 1);
}

/*
 * Return true if the task of @tctx is in an idle cgroup or under one,
 * cfs_rq_is_idle() on the way up enqueue_hierarchy(). A group has the same
 * ancestors on every cid, so the chain of the first one stands for all.
 */
static bool task_in_idle_cgroup(const task_ctx_t *tctx)
{
	grp_q_t *gq = tctx->grp;
	int i;

	for (i = 0; gq && i < GRP_MAX_DEPTH; i++) {
		if (READ_ONCE(gq->hdr->idle))
			return true;
		gq = gq->parent;
	}

	return false;
}

/*
 * Charge @delta to the cgroup of @tctx for the time it ran on @cid.
 *
 * @delta is the cid's task clock, what fair.c charges from rq_clock_task, and
 * the period it counts against is wall time: a group is held to its quota of
 * the time it is given, not of the time the CPU spends elsewhere.
 */
static void task_bw_charge(task_ctx_t *tctx, s32 cid, u64 delta)
{
	if (!bw_enabled() || !tctx->grp || !cid_valid(cid) || !delta)
		return;

	grp_bw_charge(&tctx->grp[cid], delta, scx_bpf_now());
}

/*
 * The nearest group at or above the one @tctx is in on @cid that has run out
 * of bandwidth, NULL when none has: a group that is out of bandwidth takes
 * everything under it with it, as a throttled cfs_rq does.
 *
 * Periods turn over here as well as on the charge, so that a group whose tasks
 * are all waiting, and which therefore charges nothing, is found runnable
 * again by the first of them to ask.
 */
static struct grp_hdr __arena *task_bw_throttled(task_ctx_t *tctx, s32 cid, u64 now)
{
	grp_q_t *gq;
	int i;

	if (!bw_enabled() || !tctx->grp || !cid_valid(cid))
		return NULL;

	gq = &tctx->grp[cid];
	for (i = 0; gq && i < GRP_MAX_DEPTH; i++, gq = gq->parent) {
		struct grp_hdr __arena *hdr = gq->hdr;

		if (!hdr || !grp_bw_limited(hdr))
			continue;
		grp_bw_refill(hdr, now);
		if (READ_ONCE(hdr->throttled))
			return hdr;
	}

	return NULL;
}
