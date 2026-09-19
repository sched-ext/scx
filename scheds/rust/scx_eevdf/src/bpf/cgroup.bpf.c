/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.
 *
 * Group scheduling - cpu.weight, cpu.idle and cpu.max: what the cgroup of
 * a task does to the weight it is queued at, and to whether it may run at
 * all.
 *
 *
 * One runqueue, not a hierarchy of them
 * -------------------------------------
 *
 * fair.c gives every cgroup a cfs_rq per CPU and picks down the nesting,
 * one level at a time. This scheduler has a single runqueue per cid, the
 * way commit 85570f10a4c6 ("sched/eevdf: Move to a single runqueue")
 * takes fair.c, so a cgroup's tasks sit in the cid's own EDQ beside
 * everything else, at an effective weight that stands for their place in
 * the hierarchy. What a cgroup keeps per cid is only what that weight is
 * computed from. One arena block per cgroup holds all of it:
 *
 *   +----------+----------+----------+-----+----------+-------------+
 *   | grp_hdr  | grp_q[0] | grp_q[1] | ... | grp_q[n] | live bitmap |
 *   +----------+----------+----------+-----+----------+-------------+
 *    cpu.weight            per cid: the weight of its members there,
 *    cpu.idle              the shares it has there, how many tasks,
 *    cpu.max and its pool  and the averages of the two
 *    the sums over cids
 *    the backlog
 *
 * The weight a task is queued with is its nice weight scaled by
 * shares / load at every level up to the cid's own, which is
 * __calc_prop_weight() in enqueue_hierarchy():
 *
 *   nice weight -> x shares(/A/B on cid 3)/load(/A/B on cid 3)
 *               -> x shares(/A   on cid 3)/load(/A   on cid 3)
 *               -> the weight the pack sees
 *
 * and the shares of a queue are update_cfs_group() with fair.c's default
 * "concur" mode: the group's cpu.weight, scaled by how many CPUs' worth of
 * tasks it is running, distributed over its cids by their load. Without
 * that scaling a group spread over N cids would weigh 1/N of its
 * cpu.weight on each of them, and a nested group 1/N per level, which a
 * single runqueue cannot afford.
 *
 * cpu.idle is the same machinery at a different weight: a group that has
 * it set carries WEIGHT_IDLEPRIO in place of its cpu.weight, and a task
 * under one is queued as SCHED_IDLE would queue it, cfs_rq_is_idle() at
 * every level on the way up.
 *
 *
 * Kept without locks
 * ------------------
 *
 * A task joins and leaves a group's load from whichever cid it happens to
 * be on, so the loads are moved with atomics and a group's contribution to
 * its parent is moved by compare and swap to whatever its own load says it
 * should be, walking up until nothing more changes: whoever writes a load
 * last also leaves the levels above it consistent, see grp_contrib_sync().
 *
 * The averages are different: they are a running average per queue, which
 * only their own cid can advance, so each is updated from that cid's tick
 * under a trylock, and what they add to the per-cgroup sums is written at
 * most once a millisecond and only when it has moved by more than a 64th.
 * A group that stops running on a cid would otherwise hold that cid's last
 * contribution for ever, inflating the total its shares are divided by, so
 * grp_sweep() walks the queues that still count, a few per millisecond
 * from whichever cid runs it, and decays the quiet ones. That is
 * update_blocked_averages() for an idle CPU, which has no idle balancer
 * here to run it.
 *
 *
 * cpu.max
 * -------
 *
 * Each limited cgroup has a pool refilled once a period. A cid takes a
 * 5 ms slice of it at a time rather than a charge per switch, and gives
 * back what it does not use when its queue for that group goes quiet. A
 * group that runs out throttles, and then its tasks may not run:
 *
 *   ops.stopping()   charge the service to every level -> pool empty
 *                    -> the group throttles
 *   ops.enqueue()    throttled? -> cid_park(): the task leaves its pack
 *                    and its group's load and waits in the cgroup's own
 *                    backlog, ordered by vruntime so the least served
 *                    comes back first
 *   period ends      grp_bw_refill() -> bw_unpark() from the next
 *                    ops.dispatch(), a few tasks at a time; and from one
 *                    bpf_timer for the case where every cid is asleep and
 *                    nobody would ever look
 *
 * The backlog is a queue of its own because the pick descends an AVL tree
 * by deadline and prunes on eligibility: it has no way to step over a task
 * that may not run, so a task that may not run has to be somewhere else.
 *
 * The registry at the top (grp_hdrs[], bw_hdrs[]) is what makes the sweep
 * and the unthrottle possible at all: a BPF program cannot walk the cgroup
 * tree, so every block is registered in a slot when the cgroup is created
 * and the walks go over those slots.
 *
 * What a context switch pays for - the hierarchy weight of the running
 * task, and charging its cgroup - is inline in cgroup.bpf.h.
 */
#include "eevdf.bpf.h"
#include "cgroup.bpf.h"
#include "queue.bpf.h"
#include "task.bpf.h"

/*
 * A cgroup's block: the header, its queues, one per cid, and a bitmap of the
 * cids whose queue still adds to the per-cgroup sums, see grp_sweep().
 */
static __always_inline grp_q_t *grp_ents(struct grp_hdr __arena *hdr)
{
	return (grp_q_t *)((char __arena *)hdr + sizeof(struct grp_hdr));
}

static __always_inline u64 __arena *grp_live(struct grp_hdr __arena *hdr, u32 nr)
{
	return (u64 __arena *)((char __arena *)grp_ents(hdr) +
			       (u64)nr * sizeof(struct grp_q));
}

/*
 * Per-cgroup context: where the cgroup's queues are. @hdr is NULL when
 * @ents is not the cgroup's own.
 */
struct cgrp_ctx {
	grp_q_t *ents;
	struct grp_hdr __arena *hdr;
	u32 depth;
};

struct {
	__uint(type, BPF_MAP_TYPE_CGRP_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct cgrp_ctx);
} cgrp_ctx_stor SEC(".maps");

/*
 * The one timer cpu.max needs. A cid with nothing to run never reaches
 * ops.dispatch(), so a group whose tasks are all waiting on a period would
 * wait past the end of it with every CPU asleep and nobody to notice. Armed
 * only while something is waiting, for the first period that ends.
 */
struct bw_timer {
	struct bpf_timer timer;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, struct bw_timer);
	__uint(max_entries, 1);
} bw_timers SEC(".maps");

/*
 * The smallest weight a group can have on a cid, MIN_SHARES.
 */
#define GRP_MIN_SHARES		2

/*
 * How long the per-cgroup sums are left alone after an update, and by how
 * much a queue's average has to move to update them, update_tg_load_avg().
 */
#define GRP_SUM_NS		1000000ULL

/*
 * The averages of a group queue, what they add to the per-cgroup sums, and its
 * bit in the live bitmap are updated by the cid that owns the queue, from its
 * tick, and by grp_sweep() from whichever cid runs it once the queue has gone
 * quiet. fair.c does both under the runqueue's lock; here the two take the
 * queue's own lock and give way to each other rather than wait: the owner's
 * next tick, or the next sweep, does what one skipped.
 */
static bool grp_avg_trylock(grp_q_t *gq)
{
	return !READ_ONCE(gq->avg_lock) &&
	       __sync_val_compare_and_swap(&gq->avg_lock, 0, 1) == 0;
}

static void grp_avg_unlock(grp_q_t *gq)
{
	__sync_val_compare_and_swap(&gq->avg_lock, 1, 0);
}

/*
 * Every cgroup block, indexed by struct grp_hdr's @slot, for grp_sweep() to
 * walk. Allocated by ops.init(), written by the cgroup ops, which the kernel
 * serializes.
 */
#define GRP_MAX_CGROUPS		16384

static u64 __arena *grp_hdrs;
static u32 grp_hdrs_nr;		/* slots ever used */

static u64 grp_sweep_at __hot_written;
static u32 grp_sweep_lock __hot_written;
static u64 grp_sweep_pos;	/* where grp_sweep() goes on from */
static u64 grp_free_head;	/* blocks waiting to be freed, see grp_free_defer() */

/*
 * How often, and over how many queues at most, grp_sweep() runs.
 */
#define GRP_SWEEP_NS		NSEC_PER_MSEC
#define GRP_SWEEP_BUDGET	64

/*
 * Nothing of the group is left on the cid of @gq: give back what the cid holds
 * of the group's bandwidth, less the millisecond __return_cfs_rq_runtime()
 * keeps behind for whoever runs there next. Without this the time a cid was
 * handed and did not use would sit there for good, and a group that moves
 * around would be held to a fraction of its quota.
 */
static void grp_bw_return(grp_q_t *gq)
{
	struct grp_hdr __arena *hdr = gq->hdr;
	s64 rem = READ_ONCE(gq->runtime_remaining);

	if (!hdr || !grp_bw_limited(hdr) || rem <= (s64)NSEC_PER_MSEC)
		return;

	/* A slice taken under a limit that has since moved is dropped, not
	 * given back: it is not this limit's time to hand out.
	 */
	if (READ_ONCE(gq->bw_gen) != READ_ONCE(hdr->bw_gen)) {
		WRITE_ONCE(gq->runtime_remaining, 0);
		return;
	}

	WRITE_ONCE(gq->runtime_remaining, (s64)NSEC_PER_MSEC);
	__sync_fetch_and_add(&hdr->pool, rem - NSEC_PER_MSEC);
}

/*
 * Give @hdr a slot among the limited cgroups, or leave it without one when
 * they are all taken.
 */
static void grp_bw_register(struct grp_hdr __arena *hdr)
{
	u32 slot;

	if (hdr->bw_slot < BW_MAX_LIMITED)
		return;

	bpf_for(slot, 0, BW_MAX_LIMITED) {
		u32 i = slot & (BW_MAX_LIMITED - 1);

		if (READ_ONCE(bw_hdrs[i]) ||
		    __sync_val_compare_and_swap(&bw_hdrs[i], 0, (u64)hdr))
			continue;
		hdr->bw_slot = i;
		if (i >= bw_hdrs_nr)
			bw_hdrs_nr = i + 1;
		return;
	}
}

/*
 * Give the slot back. Either the cgroup ops or the drain does this, so the
 * entry is exchanged rather than written: the drain is the one that knows a
 * cgroup which has stopped being limited has no tasks left waiting on it.
 */
static void grp_bw_unregister(struct grp_hdr __arena *hdr)
{
	u64 slot = hdr->bw_slot;

	if (slot >= BW_MAX_LIMITED)
		return;

	hdr->bw_slot = BW_SLOT_NONE;
	__sync_val_compare_and_swap(&bw_hdrs[slot & (BW_MAX_LIMITED - 1)],
				    (u64)hdr, 0);
}

/*
 * Set or clear the bit of @gq's cid in its cgroup's live bitmap. By compare
 * and swap: the verifier takes no atomic or/and on arena memory.
 */
static void grp_live_update(grp_q_t *gq, bool live)
{
	u64 __arena *word = &grp_live(gq->hdr, nr_cids)[gq->cid / 64];
	u64 bit = 1ULL << (gq->cid & 63), old;

	while (can_loop) {
		old = READ_ONCE(*word);
		if (!!(old & bit) == live)
			return;
		if (__sync_val_compare_and_swap(word, old,
						live ? old | bit : old & ~bit) == old)
			return;
	}
}

/*
 * Decay the averages of @gq, a queue with no members left on its cid, and
 * take what they add to its cgroup's sums along: update_blocked_averages()
 * for a group whose cfs_rq has gone quiet. The cid that owns the queue only
 * keeps them from its tick while the group runs there, and without this a
 * cid the group has left would hold its last contribution for good, inflating
 * tg_load_avg and shrinking the group's shares everywhere else.
 */
__noinline int grp_decay(grp_q_t *gq __arg_arena, u64 now)
{
	struct grp_hdr __arena *hdr;
	u64 la, na;

	TOUCH_ARENA();

	if (!gq || READ_ONCE(gq->load) || !grp_avg_trylock(gq))
		return 0;
	/* A task may have joined between the look and the lock. */
	if (READ_ONCE(gq->load)) {
		grp_avg_unlock(gq);
		return 0;
	}
	hdr = gq->hdr;

	if (bw_enabled())
		grp_bw_return(gq);

	ravg_accumulate_arena(&gq->load_avg, 0, now);
	ravg_accumulate_arena(&gq->nr_avg, 0, now);
	la = ravg_read_arena(&gq->load_avg, now) >> RAVG_FRAC_BITS;
	na = ravg_read_arena(&gq->nr_avg, now);
	/* A 64th of a task decays to nothing more that matters. */
	if (na < (1ULL << RAVG_FRAC_BITS) / 64)
		na = 0;

	if (la != gq->load_avg_contrib) {
		__sync_fetch_and_add(&hdr->load_avg, (s64)(la - gq->load_avg_contrib));
		gq->load_avg_contrib = la;
	}
	if (na != gq->nr_avg_contrib) {
		__sync_fetch_and_add(&hdr->nr_avg, (s64)(na - gq->nr_avg_contrib));
		gq->nr_avg_contrib = na;
	}

	if (!la && !na)
		grp_live_update(gq, false);
	grp_avg_unlock(gq);

	return 0;
}

/*
 * One step of grp_sweep() from @pos, cgroup slot in the high 32 bits and cid
 * in the low: decay the next live queue at or after it in that cgroup, or
 * move to the next cgroup. Return the position to go on from, or ~0 past the
 * last slot. A global function, so that the walk is a loop over an opaque
 * cursor and verifies once.
 */
__noinline u64 grp_sweep_step(u64 pos, u64 now)
{
	u32 slot = pos >> 32, cid = (u32)pos, words = (nr_cids + 63) / 64, k;
	struct grp_hdr __arena *hdr;
	u64 __arena *live;
	u64 w;

	TOUCH_ARENA();

	if (!grp_hdrs || slot >= grp_hdrs_nr || slot >= GRP_MAX_CGROUPS)
		return ~0ULL;
	hdr = (struct grp_hdr __arena *)grp_hdrs[slot];
	k = cid / 64;
	if (!hdr || k >= words)
		return (u64)(slot + 1) << 32;

	live = grp_live(hdr, nr_cids);
	w = READ_ONCE(live[k]) & (~0ULL << (cid & 63));
	if (!w)
		return (u64)slot << 32 | ((k + 1) * 64);
	cid = k * 64 + __builtin_ctzll(w);
	if (cid >= nr_cids)
		return (u64)(slot + 1) << 32;

	grp_decay(&grp_ents(hdr)[cid], now);
	return (u64)slot << 32 | (cid + 1);
}

/*
 * Hand the block of a removed cgroup over to be freed by the next sweep, when
 * a sweep that may still be looking at it holds grp_sweep_lock and the block
 * cannot be freed from under it. Producers push without a lock and the sweep
 * pops with compare and swap, see grp_free_pop(). A push that cannot complete
 * leaks the block, which is safe.
 */
static void grp_free_defer(struct grp_hdr __arena *hdr)
{
	u64 old;

	while (can_loop) {
		old = READ_ONCE(grp_free_head);
		hdr->next_free = old;
		if (__sync_val_compare_and_swap(&grp_free_head, old, (u64)hdr) == old)
			return;
	}
}

/* Keep reclamation from adding an unbounded amount of work to one tick. */
#define GRP_FREE_BUDGET	8

/*
 * Pop one block from the deferred-free list. The sweep lock serializes
 * consumers, while cgroup exits may still push new blocks concurrently.
 */
__noinline u64 grp_free_pop(void)
{
	u64 head, next;

	TOUCH_ARENA();

	while (can_loop) {
		struct grp_hdr __arena *hdr;

		head = READ_ONCE(grp_free_head);
		if (!head)
			return 0;
		hdr = (struct grp_hdr __arena *)head;
		next = hdr->next_free;
		if (__sync_val_compare_and_swap(&grp_free_head, head, next) == head)
			return head;
	}

	return 0;
}

/*
 * Free a bounded number of blocks grp_free_defer() handed over. Called with
 * grp_sweep_lock held, after the walk: a block pushed during the walk may be
 * the one it looked at, and one pushed later is out of the registry and out
 * of any later walk. Anything left stays linked for a later sweep.
 */
__noinline int grp_free_drain(void)
{
	u32 i;

	TOUCH_ARENA();

	bpf_for(i, 0, GRP_FREE_BUDGET) {
		u64 next = grp_free_pop();
		struct grp_hdr __arena *hdr;

		if (!next)
			break;
		hdr = (struct grp_hdr __arena *)next;
		bpf_arena_free_pages(&arena, hdr, hdr->pages);
	}

	return 0;
}

/*
 * Walk the queues that still add to their cgroup's sums, a few per
 * GRP_SWEEP_NS, and decay the ones that have gone quiet, see grp_decay().
 * One cid at a time does it, from its tick, where fair.c's idle balancer
 * updates the blocked averages of idle CPUs.
 *
 * A global function, verified once rather than in the tick's context.
 */
__noinline int grp_sweep(u64 now)
{
	u64 at = READ_ONCE(grp_sweep_at), pos;
	bool wrapped = false;
	u32 i;

	TOUCH_ARENA();

	if (!grp_hdrs || (!grp_hdrs_nr && !READ_ONCE(grp_free_head)) ||
	    now - at < GRP_SWEEP_NS ||
	    __sync_val_compare_and_swap(&grp_sweep_at, at, now) != at)
		return 0;
	if (__sync_val_compare_and_swap(&grp_sweep_lock, 0, 1))
		return 0;

	pos = READ_ONCE(grp_sweep_pos);
	bpf_for(i, 0, GRP_SWEEP_BUDGET) {
		pos = grp_sweep_step(pos, now);
		if (pos == ~0ULL) {
			if (wrapped)
				break;
			wrapped = true;
			pos = 0;
		}
	}
	WRITE_ONCE(grp_sweep_pos, pos == ~0ULL ? 0 : pos);
	if (READ_ONCE(grp_free_head))
		grp_free_drain();
	WRITE_ONCE(grp_sweep_lock, 0);

	return 0;
}

/*
 * Bring what @gq adds to its cgroup's sums up to date, and recompute the
 * group's shares on the cid, update_cfs_group() with fair.c's default
 * cgroup_mode, "concur", calc_concur_shares():
 *
 *	nr = min(tg_tasks(tg), tg_cpus(tg));
 *	return __calc_smp_shares(cfs_rq, nr * tg_shares, nr * tg_shares);
 *
 * which is the load-proportional share of the group's weight on this cid,
 * the "icky" shares_weight approximation of __calc_smp_shares(),
 *
 *	load   = max(grq->load.weight, grq->avg.load_avg)
 *	shares = tg->weight * load / (tg->load_avg - contrib + load)
 *
 * with the weight scaled by how many CPUs' worth of tasks the group runs.
 * cpu.weight then means the weight per active CPU: a group of one task has
 * its cpu.weight on the cid the task runs on, and a group running a task on
 * every CPU has it on every CPU. Without the scaling, the shares of a group
 * spread over N cids would average 1/N of the weight and nested groups
 * 1/N^depth, which a single runqueue cannot afford. tg_cpus() counts the
 * CPUs of the group's cpuset; the cids of the scheduler stand in for them.
 *
 * The averages are kept from the owner of the cid, where the tick runs, and
 * the sums shared by every cid of the cgroup are written at most once a
 * millisecond per queue, and only for a move of more than a 64th.
 */
static void grp_update_shares(grp_q_t *gq, u64 now)
{
	struct grp_hdr __arena *hdr = gq->hdr;
	u64 load = READ_ONCE(gq->load), la, na, nr, total, tg_load, shares;
	s64 d;

	if (!grp_avg_trylock(gq))
		return;

	ravg_accumulate_arena(&gq->load_avg, load, now);
	ravg_accumulate_arena(&gq->nr_avg, READ_ONCE(gq->nr), now);
	la = ravg_read_arena(&gq->load_avg, now) >> RAVG_FRAC_BITS;
	na = ravg_read_arena(&gq->nr_avg, now);

	if (now - gq->shares_at < GRP_SUM_NS) {
		grp_avg_unlock(gq);
		return;
	}
	gq->shares_at = now;

	d = (s64)(la - gq->load_avg_contrib);
	if ((u64)(d < 0 ? -d : d) > gq->load_avg_contrib / 64) {
		__sync_fetch_and_add(&hdr->load_avg, d);
		gq->load_avg_contrib = la;
	}
	d = (s64)(na - gq->nr_avg_contrib);
	if ((u64)(d < 0 ? -d : d) > gq->nr_avg_contrib / 64) {
		__sync_fetch_and_add(&hdr->nr_avg, d);
		gq->nr_avg_contrib = na;
	}
	if (gq->load_avg_contrib || gq->nr_avg_contrib)
		grp_live_update(gq, true);
	grp_avg_unlock(gq);

	nr = READ_ONCE(hdr->nr_avg) >> RAVG_FRAC_BITS;
	nr = MIN(MAX(nr, 1ULL), (u64)nr_cids);
	total = nr * READ_ONCE(hdr->weight);

	load = MAX(load, la);
	tg_load = READ_ONCE(hdr->load_avg);
	tg_load = (tg_load > gq->load_avg_contrib ? tg_load - gq->load_avg_contrib : 0) +
		  load;
	shares = tg_load ? total * load / tg_load : total;
	shares = MIN(MAX(shares, (u64)GRP_MIN_SHARES), total);

	if (shares != READ_ONCE(gq->shares)) {
		WRITE_ONCE(gq->shares, shares);
		/* Take the new shares to the parent's load. */
		grp_contrib_sync(gq);
	}
}

/*
 * The scale cpu.weight is written on: what a cgroup nobody has touched
 * carries.
 */
#define CGROUP_WEIGHT_DFL	100

/*
 * The load weight of a group written @weight in cpu.weight,
 * sched_weight_from_cgroup():
 *
 *	return DIV_ROUND_CLOSEST_ULL(cgrp_weight * 1024, CGROUP_WEIGHT_DFL);
 */
static u64 cgrp_load_weight(u32 weight)
{
	u64 w = ((u64)weight * NICE_0_WEIGHT + CGROUP_WEIGHT_DFL / 2) /
		CGROUP_WEIGHT_DFL;

	return w ? w : 1;
}

/*
 * How long the timer waits when a group is already owed its tasks back but
 * the drain has not managed it yet.
 */
#define BW_TIMER_MIN_NS		NSEC_PER_MSEC

/*
 * Arm the timer for the first period that ends among the groups with tasks
 * waiting. bpf_timer_start() moves an armed timer, and the earliest deadline
 * is recomputed every time, so this can be called from anywhere that parks a
 * task or refills a group.
 */
static void bw_timer_arm(u64 now)
{
	struct bw_timer *bt;
	u64 next = 0, delta;
	u32 slot, key = 0;
	bool locked;

	/*
	 * The walk reads blocks ops.cpuctl_exit() may be freeing, and the
	 * sweep lock is what keeps one alive across that, see grp_free_defer().
	 * Without it, arm for the shortest wait and work the deadline out on
	 * the next pass rather than touching a block that may be gone.
	 */
	locked = __sync_val_compare_and_swap(&grp_sweep_lock, 0, 1) == 0;
	if (!locked)
		goto arm;

	bpf_for(slot, 0, bw_hdrs_nr) {
		struct grp_hdr __arena *hdr;
		u64 due;

		hdr = (struct grp_hdr __arena *)READ_ONCE(bw_hdrs[slot & (BW_MAX_LIMITED - 1)]);
		if (!hdr || !READ_ONCE(hdr->nr_parked))
			continue;
		due = READ_ONCE(hdr->throttled) ?
		      READ_ONCE(hdr->period_start) + READ_ONCE(hdr->period) : now;
		if (!next || time_before(due, next))
			next = due;
	}
	WRITE_ONCE(grp_sweep_lock, 0);
	if (!next)
		return;

arm:
	bt = bpf_map_lookup_elem(&bw_timers, &key);
	if (!bt)
		return;
	delta = locked && time_before(now, next) ? next - now : BW_TIMER_MIN_NS;
	bpf_timer_start(&bt->timer, MAX(delta, BW_TIMER_MIN_NS), 0);
}

/*
 * Tell one idle cid to go through ops.dispatch(), where the tasks that may run
 * again are let go. Nothing to do when no cid is idle: every one of them
 * dispatches by the end of the slice it is running.
 */
static void bw_kick_idle(void)
{
	u32 words = (nr_cids + 63) / 64, k;

	bpf_for(k, 0, words) {
		u64 w = cmask_word(idle_cids, k);

		if (!w)
			continue;
		scx_bpf_kick_cid(k * 64 + __builtin_ctzll(w), SCX_KICK_IDLE);
		return;
	}
}

/*
 * The first period among the groups with tasks waiting has ended: turn over
 * the ones that are due and see that somebody goes and lets their tasks run.
 */
static int bw_timer_fire(void *map, int *key, struct bw_timer *bt)
{
	u64 now = scx_bpf_now();
	bool runnable = false;
	u32 slot;

	TOUCH_ARENA();

	/* Same blocks, same reason as bw_timer_arm(): come back if it is busy. */
	if (__sync_val_compare_and_swap(&grp_sweep_lock, 0, 1) != 0) {
		struct bw_timer *bt;
		u32 key = 0;

		bt = bpf_map_lookup_elem(&bw_timers, &key);
		if (bt)
			bpf_timer_start(&bt->timer, BW_TIMER_MIN_NS, 0);
		return 0;
	}

	bpf_for(slot, 0, bw_hdrs_nr) {
		struct grp_hdr __arena *hdr;

		hdr = (struct grp_hdr __arena *)READ_ONCE(bw_hdrs[slot & (BW_MAX_LIMITED - 1)]);
		if (!hdr || !READ_ONCE(hdr->nr_parked))
			continue;
		grp_bw_refill(hdr, now);
		if (!READ_ONCE(hdr->throttled))
			runnable = true;
	}
	WRITE_ONCE(grp_sweep_lock, 0);

	if (runnable)
		bw_kick_idle();
	bw_timer_arm(now);

	return 0;
}

/*
 * Put @p aside until the cgroup of @hdr has bandwidth again, which is what
 * dequeue_throttled_task() does to a task whose group has run out.
 *
 * It leaves its pack and its group's load on the way: a task waiting on a
 * period is not competing for the cid, and a weight left behind would move the
 * reference every other task there is measured against for as long as the
 * throttle lasts, and would be counted in the group's load and task count,
 * which its shares everywhere else are computed from.
 *
 * It waits in its cgroup's backlog rather than in the cid's queue: the pick
 * descends an AVL tree by deadline, pruning on the least eligible vruntime of
 * a subtree, and has no way to step over a task, so a task that may not run
 * has to be somewhere else. The backlog is ordered by the vruntime it stopped
 * at, so the least served of the group's tasks is the first to go back.
 */
static bool cid_park(struct task_struct *p, task_ctx_t *tctx,
		     struct grp_hdr __arena *hdr, s32 cid)
{
	cid_edq_task_t *at = cid_edq_task(tctx);
	int ret;

	/*
	 * A node an older workflow still holds, or one already in a queue, is
	 * not ours to move; the task runs this once more and is parked at its
	 * next enqueue.
	 */
	if (!at || READ_ONCE(at->common.holdcnt) ||
	    READ_ONCE(at->state) == CID_EDQ_ENQUEUED)
		return false;

	/*
	 * A task on its way out is not held to a limit. scx_eevdf asks for
	 * exiting tasks with SCX_OPS_ENQ_EXITING so that it can get them off
	 * the machine, and making one wait a period for a cgroup it is leaving
	 * anyway works against that. fair.c has nothing to hold back either:
	 * the task is dequeued for good rather than put on a throttled list.
	 */
	if (p->flags & PF_EXITING)
		return false;

	task_vref_leave(tctx);
	/* A debt to a pack it may not come back to for a period is forgiven. */
	tctx->delay_cid = -1;

	at->slice = task_request(p);
	at->enq_flags = 0;
	at->cid = cid;
	WRITE_ONCE(at->state, CID_EDQ_PARKED);
	ret = scx_edq_insert(&hdr->bq, &at->common, tctx->se.vruntime,
			      tctx->se.vruntime, at->slice);
	if (ret) {
		__sync_val_compare_and_swap(&at->state, CID_EDQ_PARKED,
					    CID_EDQ_NONE);
		scx_bpf_error("cpu.max park failed for pid %d: %d", p->pid, ret);
		return false;
	}

	tctx->bw_hdr = hdr;
	__sync_fetch_and_add(&hdr->nr_parked, 1);
	__sync_fetch_and_add(&bw_nr_parked, 1);

	/* Somebody has to come back for it if every cid goes to sleep. */
	bw_timer_arm(scx_bpf_now());

	return true;
}

/*
 * Let one task of @hdr run again: take it out of the backlog and put it
 * through placement and the queue of the cid the kernel has it on, the way a
 * task that slept through the throttle would come back. It is placed as a
 * sleeper, since that is what it was: it was out of the pack for the whole
 * period, and the lag it left with is stale by that much.
 *
 * Returns whether the backlog had anything, not whether the task was requeued:
 * one that left in the meantime is simply gone from it.
 */
static __noinline bool bw_unpark_one(struct grp_hdr __arena *hdr, u64 now)
{
	struct grp_hdr __arena *out;
	struct task_struct *p;
	cid_edq_task_t *at;
	task_ctx_t *tctx;
	s32 cid;

	at = (cid_edq_task_t *)scx_edq_pop(&hdr->bq, true);
	if (!at)
		return false;

	/*
	 * The node is the front of the context that embeds it, so the task it
	 * belongs to is reached without a lookup, and the accounting is settled
	 * by whoever took it out of the queue: here, or ops.dequeue().
	 */
	tctx = (task_ctx_t *)at;
	task_bw_unparked(tctx);

	/* Somebody else ended this enqueue workflow while it waited. */
	if (__sync_val_compare_and_swap(&at->state, CID_EDQ_PARKED,
					CID_EDQ_NONE) != CID_EDQ_PARKED)
		goto drop;

	p = scx_bpf_tid_to_task(at->tid);
	if (!p) {
		scx_bpf_error("cpu.max cannot resolve parked tid %llu", at->tid);
		goto drop;
	}
	if (!is_task_queued(p))
		goto drop;
	cid = scx_bpf_task_cid(p);
	if (!cid_valid(cid))
		goto drop;

	/*
	 * The task waited on the nearest group that had run out, and a group
	 * above that one can have run out since, or still be out. Ask the whole
	 * chain again rather than the one backlog it came from, or a child
	 * would run while an ancestor is throttled until the tick noticed.
	 */
	out = task_bw_throttled(tctx, cid, now);
	if (out) {
		scx_edq_task_drop(&at->common);
		cid_park(p, tctx, out, cid);
		return true;
	}

	/* The node has to be free of holds before it can be queued again. */
	scx_edq_task_drop(&at->common);

	place_task(cid, p, tctx, now, true);
	if (!cid_queue_insert(p, tctx, cid, task_request(p), task_dl(p, tctx),
			      tctx->se.vruntime, 0))
		return true;
	cid_queued_set(cid);
	if (cid != scx_bpf_this_cid())
		scx_bpf_kick_cid(cid, SCX_KICK_IDLE);

	return true;
drop:
	scx_edq_task_drop(&at->common);
	return true;
}


/*
 * How many tasks one pass lets go at a time. A period's worth of them can be
 * waiting, and requeueing all of them from a single dispatch would hold the
 * cid that happened to run it for as long as it takes.
 */
#define BW_UNPARK_BATCH		4

/*
 * Give back the tasks of every group that has bandwidth again.
 *
 * One cid at a time: the walk reads cgroup blocks that ops.cpuctl_exit() may
 * be freeing, and the sweep lock is what keeps a block alive across that, see
 * grp_free_defer(). Whoever does not get it goes on with its own queue and
 * leaves the work to the next dispatch or to the timer.
 */
__noinline int bw_unpark(u64 now)
{
	u32 slot, n = 0;

	TOUCH_ARENA();

	if (!READ_ONCE(bw_nr_parked) ||
	    __sync_val_compare_and_swap(&grp_sweep_lock, 0, 1) != 0)
		return 0;

	bpf_for(slot, 0, bw_hdrs_nr) {
		struct grp_hdr __arena *hdr;

		if (n >= BW_UNPARK_BATCH)
			break;
		hdr = (struct grp_hdr __arena *)READ_ONCE(bw_hdrs[slot & (BW_MAX_LIMITED - 1)]);
		if (!hdr)
			continue;
		if (!READ_ONCE(hdr->nr_parked)) {
			/* Nothing is left waiting on a cpu.max that is gone. */
			if (!grp_bw_limited(hdr))
				grp_bw_unregister(hdr);
			continue;
		}
		grp_bw_refill(hdr, now);
		if (READ_ONCE(hdr->throttled))
			continue;
		while (READ_ONCE(hdr->nr_parked) && n < BW_UNPARK_BATCH && can_loop) {
			if (!bw_unpark_one(hdr, now))
				break;
			n++;
		}
	}

	if (READ_ONCE(grp_free_head))
		grp_free_drain();
	WRITE_ONCE(grp_sweep_lock, 0);

	return 0;
}

/*
 * The queues of the cgroup @p is in, NULL for the root cgroup or a kernel
 * without the cpu controller's hooks. From ops.enable(), the first op
 * scx_bpf_task_cgroup() can be asked about @p in; the cgroup of
 * ops.init_task() is not a pointer the verifier trusts.
 */
static grp_q_t *task_cgrp_ents(struct task_struct *p)
{
	struct cgrp_ctx *cgc;
	struct cgroup *cgrp;
	grp_q_t *ents;

	if (!cgroup_enabled)
		return NULL;
	cgrp = scx_bpf_task_cgroup(p);
	if (!cgrp)
		return NULL;
	cgc = bpf_cgrp_storage_get(&cgrp_ctx_stor, cgrp, 0, 0);
	ents = cgc ? cgc->ents : NULL;
	bpf_cgroup_release(cgrp);

	return ents;
}

/*
 * Return true if @cgrp is set cpu.idle. ops.cpuctl_set_idle() only reports
 * changes, and struct scx_cgroup_init_args has no idle state, so a cgroup that
 * was made idle before the scheduler was loaded is read off its task_group,
 * whose css the cpu controller's is.
 */
static bool cgrp_is_idle(struct cgroup *cgrp)
{
	struct task_group *tg;
	int idle = 0;

	if (!bpf_core_field_exists(struct task_group, idle))
		return false;
	tg = (struct task_group *)cgrp->subsys[bpf_core_enum_value(enum cgroup_subsys_id,
								     cpu_cgrp_id)];
	if (!tg)
		return false;
	if (bpf_core_read(&idle, sizeof(idle), &tg->idle))
		return false;

	return idle > 0;
}

/*
 * A cgroup the cpu controller is putting under this scheduler, either one
 * that already existed when it was loaded or one just created, parents
 * before their children: give it a queue on every cid, each adding to its
 * parent's queue on that cid, see struct grp_q.
 */
s32 BPF_STRUCT_OPS_SLEEPABLE(eevdf_cpuctl_init, struct cgroup *cgrp,
			     struct scx_cgroup_init_args *args)
{
	struct cgrp_ctx *cgc, *pcgc = NULL;
	grp_q_t *ents, *pents = NULL;
	struct grp_hdr __arena *hdr;
	struct cgroup *parent;
	u64 bytes, pages;
	u32 depth = 1, cid;

	TOUCH_ARENA();

	cgc = bpf_cgrp_storage_get(&cgrp_ctx_stor, cgrp, 0,
				   BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!cgc)
		return -ENOMEM;
	cgc->ents = NULL;
	cgc->hdr = NULL;
	cgc->depth = 0;
	if (!cgrp->level)
		return 0;

	parent = bpf_cgroup_ancestor(cgrp, cgrp->level - 1);
	if (parent) {
		pcgc = bpf_cgrp_storage_get(&cgrp_ctx_stor, parent, 0, 0);
		bpf_cgroup_release(parent);
	}
	if (pcgc && pcgc->ents) {
		pents = pcgc->ents;
		depth = pcgc->depth + 1;
	}
	if (depth > GRP_MAX_DEPTH) {
		cgc->ents = pents;
		cgc->depth = pcgc->depth;
		return 0;
	}

	bytes = sizeof(struct grp_hdr) + (u64)nr_cids * sizeof(struct grp_q) +
		(u64)((nr_cids + 63) / 64) * sizeof(u64);
	pages = (bytes + PAGE_SIZE - 1) / PAGE_SIZE;
	hdr = bpf_arena_alloc_pages(&arena, NULL, pages, NUMA_NO_NODE, 0);
	if (!hdr)
		return -ENOMEM;
	hdr->idle = cgrp_is_idle(cgrp);
	hdr->weight = hdr->idle ? WEIGHT_IDLEPRIO : cgrp_load_weight(args->weight);
	hdr->pages = pages;
	ents = (grp_q_t *)((char __arena *)hdr + sizeof(struct grp_hdr));

	/* Fresh arena pages read as zero: only what is not zero is stored. */
	bpf_for(cid, 0, nr_cids) {
		grp_q_t *gq = &ents[cid];

		gq->hdr = hdr;
		gq->cid = cid;
		gq->shares = hdr->weight;
		if (pents)
			gq->parent = &pents[cid];
	}

	cgc->ents = ents;
	cgc->hdr = hdr;

	/* A slot for grp_sweep(); a cgroup without one is simply not swept. */
	hdr->slot = GRP_MAX_CGROUPS;
	/* One among the limited cgroups is taken only if a cpu.max is set. */
	hdr->bw_slot = BW_SLOT_NONE;
	if (grp_hdrs) {
		u32 slot;

		bpf_for(slot, 0, GRP_MAX_CGROUPS) {
			if (!grp_hdrs[slot]) {
				hdr->slot = slot;
				grp_hdrs[slot] = (u64)hdr;
				if (slot >= grp_hdrs_nr)
					grp_hdrs_nr = slot + 1;
				break;
			}
		}
	}
	cgc->depth = depth;

	return 0;
}

/*
 * The cgroup is going away, or the scheduler is.
 *
 * A cgroup that is removed has no tasks left and nothing adds to its
 * queues, so the memory goes back. The scheduler going away exits every
 * cgroup before any task leaves it, scx_root_disable(), and those tasks
 * still take their weights out of their groups' loads on the way out. The
 * cgroup is still online then, where cgroup_destroy_locked() takes it
 * offline before its controllers are, and the memory goes with the arena.
 */
void BPF_STRUCT_OPS(eevdf_cpuctl_exit, struct cgroup *cgrp)
{
	struct grp_hdr __arena *hdr;
	struct cgrp_ctx *cgc;

	TOUCH_ARENA();

	cgc = bpf_cgrp_storage_get(&cgrp_ctx_stor, cgrp, 0, 0);
	if (!cgc || !cgc->hdr)
		return;
	hdr = cgc->hdr;
	cgc->ents = NULL;
	cgc->hdr = NULL;

	/*
	 * Its cpu.max goes with it. Tasks waiting on it are let go rather than
	 * left to wait on a limit nobody will refill: the scheduler being
	 * unloaded exits every cgroup while its tasks are still in them, and
	 * the dequeue each of them is about to get takes them out of the
	 * backlog. A cgroup that is removed is empty before it gets here.
	 */
	if (grp_bw_limited(hdr)) {
		WRITE_ONCE(hdr->quota, 0);
		bw_nr_limited--;
	}
	grp_bw_unthrottle(hdr, scx_bpf_now());
	grp_bw_unregister(hdr);

	/* Out of the registry: no sweep that starts from now on can find it. */
	if (grp_hdrs && hdr->slot < GRP_MAX_CGROUPS)
		WRITE_ONCE(grp_hdrs[hdr->slot], 0);

	if (cgrp->self.flags & CSS_ONLINE)
		return;

	/*
	 * Nothing may still point into the block that is about to go: a task
	 * left waiting in its backlog holds the queue it is in. An empty
	 * cgroup has none, so this only ever leaks the pages of a block the
	 * arena takes back anyway when the scheduler goes.
	 */
	if (READ_ONCE(hdr->nr_parked))
		return;

	/*
	 * A sweep already walking may still hold a pointer to the block. Free
	 * it only with the sweep lock held, or leave it to the sweep, which
	 * frees it once its walk is over, see grp_free_drain().
	 */
	if (__sync_val_compare_and_swap(&grp_sweep_lock, 0, 1) == 0) {
		bpf_arena_free_pages(&arena, hdr, hdr->pages);
		WRITE_ONCE(grp_sweep_lock, 0);
	} else {
		grp_free_defer(hdr);
	}
}

/*
 * Somebody wrote cpu.weight: the shares of the cgroup's groups follow the
 * next time the tick recomputes them, see grp_update_shares().
 */
void BPF_STRUCT_OPS(eevdf_cpuctl_set_weight, struct cgroup *cgrp, u32 weight)
{
	struct cgrp_ctx *cgc;

	TOUCH_ARENA();

	cgc = bpf_cgrp_storage_get(&cgrp_ctx_stor, cgrp, 0, 0);
	if (!cgc || !cgc->hdr)
		return;

	cgc->hdr->weight = cgrp_load_weight(weight);
}

/*
 * Somebody wrote cpu.idle, sched_group_set_idle(): an idle cgroup has the
 * weight of a SCHED_IDLE task, and one that stops being idle goes back to the
 * default weight, not to the cpu.weight it had, which the kernel does not
 * let be written while the cgroup is idle. The shares follow the next time
 * the tick recomputes them, see grp_update_shares().
 *
 * A task under an idle cgroup also counts as SCHED_IDLE work on its cid for
 * placement, see cid_sched_idle_target(). It does not change how the task
 * preempts or is preempted: with a single runqueue, wakeup_preempt_fair()
 * compares the tasks' own policies.
 */
void BPF_STRUCT_OPS(eevdf_cpuctl_set_idle, struct cgroup *cgrp, bool idle)
{
	struct cgrp_ctx *cgc;

	TOUCH_ARENA();

	cgc = bpf_cgrp_storage_get(&cgrp_ctx_stor, cgrp, 0, 0);
	if (!cgc || !cgc->hdr)
		return;

	cgc->hdr->weight = idle ? WEIGHT_IDLEPRIO : cgrp_load_weight(CGROUP_WEIGHT_DFL);
	WRITE_ONCE(cgc->hdr->idle, idle);
}

/*
 * Somebody wrote cpu.max, tg_set_bandwidth(): the cgroup may run for
 * @quota_us of every @period_us, and carry what it leaves unused into the next
 * period, up to @burst_us. The kernel keeps "max" as RUNTIME_INF and refuses a
 * quota or a period below a millisecond, so zero stands for no limit here.
 *
 * The limits are kept in nanoseconds, what the rest of the scheduler times in.
 * A cgroup nested deeper than GRP_MAX_DEPTH has no block of its own to keep
 * them in, and runs under the limits of the ancestor whose block it shares.
 */
void BPF_STRUCT_OPS(eevdf_cpuctl_set_bandwidth, struct cgroup *cgrp,
		    u64 period_us, u64 quota_us, u64 burst_us)
{
	u64 quota, period, burst, now;
	struct grp_hdr __arena *hdr;
	struct cgrp_ctx *cgc;
	bool was, limited;

	TOUCH_ARENA();

	cgc = bpf_cgrp_storage_get(&cgrp_ctx_stor, cgrp, 0, 0);
	if (!cgc || !cgc->hdr)
		return;
	hdr = cgc->hdr;

	quota = quota_us == BW_QUOTA_INF ? 0 : quota_us * NSEC_PER_USEC;
	period = MAX(period_us * NSEC_PER_USEC, NSEC_PER_MSEC);
	burst = quota ? burst_us * NSEC_PER_USEC : 0;
	now = scx_bpf_now();

	/*
	 * A limit that is new or has moved starts a period of its own, as
	 * tg_set_cfs_bandwidth() refills the group and restarts its timer. The
	 * period and the burst go in before the quota that makes them count.
	 */
	was = grp_bw_limited(hdr);
	if (quota)
		grp_bw_register(hdr);
	WRITE_ONCE(hdr->period, period);
	WRITE_ONCE(hdr->burst, burst);
	WRITE_ONCE(hdr->period_start, now);
	WRITE_ONCE(hdr->pool, quota);
	/* Whatever the cids are holding was taken under the old limit. */
	__sync_fetch_and_add(&hdr->bw_gen, 1);
	WRITE_ONCE(hdr->quota, quota);
	grp_bw_unthrottle(hdr, now);

	limited = quota != 0;
	if (limited != was)
		bw_nr_limited += limited ? 1 : -1;
	/*
	 * A cgroup that is no longer limited keeps its slot until its tasks
	 * have been let go: they wait in a backlog the drain reaches through
	 * it. The unthrottle above is what lets that happen.
	 */
	if (!limited && !READ_ONCE(hdr->nr_parked))
		grp_bw_unregister(hdr);
}

/*
 * @p is now in another cgroup. The task is off its runqueue here: it left its
 * pack and its group's load in ops.quiescent(), and joins the new group's the
 * next time it is placed or runs. A debt it owes the old pack is forgiven.
 */
void BPF_STRUCT_OPS(eevdf_cpuctl_move, struct task_struct *p,
		    struct cgroup *from, struct cgroup *to)
{
	task_ctx_t *tctx = try_lookup_task_ctx(p);
	struct cgrp_ctx *cgc;

	if (!tctx)
		return;
	cgc = bpf_cgrp_storage_get(&cgrp_ctx_stor, to, 0, 0);
	tctx->grp = cgc ? cgc->ents : NULL;
	tctx->delay_cid = -1;
}
