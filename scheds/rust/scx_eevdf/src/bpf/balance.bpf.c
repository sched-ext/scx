/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.
 *
 * The balancing that does not wait for a cid to run dry, the counterpart of
 * the idle pull in newidle.bpf.c. Nothing goes idle in either case here, so
 * nothing else notices. Two parts, both modelled on fair.c:
 *
 *   - the periodic pass, what sched_balance_domains() does when the tick
 *     calls into the balancer: work is queued unevenly while every CPU is
 *     busy, so walk the domains on averaged loads, find the group above the
 *     average, and move queued tasks off its busiest cid;
 *
 *   - the active balance, for the task a queue walk cannot reach: the one
 *     currently *running* on the source. Asymmetric packing, SMT and misfit
 *     balancing are all about that task - it is on the wrong CPU and it is
 *     in no queue to be pulled out of. fair.c stops the source with a
 *     stopper thread; here an idle cid kicks the source, which ends the
 *     task's slice itself and lets it be enqueued again, landing on the
 *     destination by the ordinary placement rules.
 *
 *
 * Periodic balance
 * ----------------
 *
 * It runs from ops.tick(), on averaged loads, and one cid owns each pass
 * the way should_we_balance() elects one CPU per group - here the group
 * leader, since an idle cid cannot be running the tick at all:
 *
 *   ops.tick()
 *     |
 *     +- system domain: all cids,  its groups are the nodes
 *     +- node domain:   the node,  its groups are the LLCs
 *     +- LLC domain:    the LLC,   its groups are the cores
 *     |     widest first, each at nr * busy_balance_factor ms, dephased by
 *     |     a tick as get_sd_balance_interval() does, and only one pass
 *     |     per tick actually reserves anything
 *     v
 *   avg_load over the domain, each cid's load divided by the capacity it
 *   really delivers (load.bpf.c), and the local group's room against it
 *     |
 *     v
 *   local group below the average, busiest group above it by more than
 *   imbalance_pct, something queued in it?   -- no --> back off, x2 up to
 *     |                                                2 * the interval
 *     v
 *   its busiest queued cid, then a bounded prefix of that cid's EDQ in
 *   deadline order, for a task that is cold, allowed on the destination,
 *   and no heavier than the imbalance asks to move - detach_tasks(), with
 *   the same relaxation of both bounds after a pass that found an
 *   imbalance but could move nothing
 *     |
 *     v
 *   the destination keeps the selection and the load left to move, and
 *   drains it from its own ops.dispatch(), one task at a time and only
 *   while the task it would take wins its own pick. attach_task() does not
 *   run what it pulls either: it enqueues and lets wakeup_preempt() decide.
 *
 *
 * Active balance
 * --------------
 *
 * The periodic pass detaches tasks that are *waiting* in a cid's EDQ. It
 * has no answer for a task that is on the wrong CPU while it runs: nothing
 * of it is in any queue to be walked. That is precisely what asymmetric
 * packing (a task on a lower-priority cid while a higher-priority one is
 * idle), SMT (a task on a busy core while a whole core is free) and misfit
 * (a task too big for the capacity it is on) are about.
 *
 * fair.c stops the source CPU with a stopper thread and migrates the task
 * from under it. There is no stopper here, so the two sides hand it over
 * across their own callbacks instead:
 *
 *     idle destination                        busy source
 *          |  reserve its own interval             |
 *          |  (so two sources cannot kick          |
 *          |   the same idle cid)                  |
 *          |------------- kick ------------------->|  ops.dispatch()
 *          |                                       |  consumes the request
 *          |                                       |  and revalidates it:
 *          |                                       |  is the destination
 *          |                                       |  still idle, is this
 *          |                                       |  still the task that
 *          |                                       |  should move (packing
 *          |                                       |  priority, a busy SMT
 *          |                                       |  sibling, capacity)
 *          |                                       |
 *          |<--- ops.stopping() charges it --------|  its slice ends
 *          |     ops.enqueue() places it here      |
 *          v                                       v
 *
 * so the task is placed and queued on the destination by the ordinary
 * rules, not forced onto it: the source never migrates it, it only stops
 * running it.
 *
 * The reservation is what keeps two balances from colliding.
 * active_balance_reserve() claims the destination's own interval with a CAS
 * on active_balance_pending, and the requester writes itself into the
 * source's active_balance_cid, so two idle cids cannot aim at the same
 * source and two sources cannot aim at the same idle cid;
 * active_balance_target() is where the source reads that back, revalidates
 * it and drops what went stale. The intervals, the backoff and the failure
 * counts live on the destination, where fair.c keeps them for the CPU
 * running the balance.
 *
 * Either side can start it, and the destination always runs it: an idle cid
 * looks for a source from its own ops.dispatch() once the newidle pull has
 * found nothing queued worth taking (request_active_balance(), which scans
 * for the source whose running task has the most to gain - packing before
 * SMT before capacity, then place tier, nr_running and utilization), and a
 * source tick that sees its own current task belongs on an idle peer
 * reserves that peer and kicks it awake, the way nohz_balancer_kick() asks
 * an idle CPU to run the balance.
 *
 * capacity_pressure_target() is the same handoff for a different reason: a
 * task that a higher scheduling class keeps displacing on a constrained
 * cid is given a less loaded one to be requeued on, paced at the LLC
 * balance interval and bounded by the same imbalance and hotness rules.
 */
#include "eevdf.bpf.h"
#include "balance.bpf.h"
#include "cgroup.bpf.h"
#include "idle.bpf.h"
#include "load.bpf.h"
#include "preempt.bpf.h"
#include "queue.bpf.h"
#include "task.bpf.h"

#define ACTIVE_BALANCE_MAX_INTERVAL_MS 512U

static bool active_balance_due(s32 cid, u64 now);

/* select_idle_smt_cpu(), restricted to active-balance destinations that are due. */
static s32 select_idle_smt_balance_cid(const struct task_struct *p, s32 cid,
				       u64 now)
{
	struct cid_topo __arena *topo;
	s32 best = cid;
	u32 sibling;

	if (!smt_asym_active(cid))
		return cid;
	topo = cid_topo(cid);
	bpf_arena_for(sibling, topo->core_base, topo->core_base + topo->core_nr) {
		if (sibling == (u32)best || !cid_idle_test(sibling) ||
		    !cid_allowed(p, sibling) || !active_balance_due(sibling, now))
			continue;
		if (smt_prefer(sibling, best))
			best = sibling;
	}

	return best;
}

/*
 * fair.c keeps the balance interval on the idle CPU which runs the balance,
 * not on the busy CPU which asks for one. scx_eevdf has one active-balance
 * level covering the placement domain, so its minimum interval is the
 * domain weight in milliseconds. Ordinary misses back off only to twice
 * that interval; affinity failures may use the longer migration backoff.
 */
static u32 active_balance_min_ms(s32 cid)
{
	struct cid_topo __arena *topo = cid_topo(cid);

	return numa_enabled ? topo->node_nr : nr_cids;
}

static bool active_balance_due(s32 cid, u64 now)
{
	struct cid_ctx __arena *cctx;

	if (!cid_valid(cid))
		return false;
	cctx = cid_ctx(cid);

	return !READ_ONCE(cctx->active_balance_pending) &&
	       !time_before(now, READ_ONCE(cctx->active_balance_next));
}

/*
 * Claim a due destination before sending its IPI. Stamping the next balance
 * while the claim is held prevents two source ticks from kicking the same
 * idle CPU for one interval.
 */
static bool active_balance_reserve(s32 cid, u64 now)
{
	struct cid_ctx __arena *cctx;
	u32 interval;

	if (!active_balance_due(cid, now) || !cid_idle_test(cid))
		return false;
	cctx = cid_ctx(cid);
	/* 1 is an unpublished reservation; dispatch consumes only state 2. */
	if (__sync_val_compare_and_swap(&cctx->active_balance_pending, 0, 1))
		return false;
	if (!cid_idle_test(cid) ||
	    time_before(now, READ_ONCE(cctx->active_balance_next))) {
		WRITE_ONCE(cctx->active_balance_pending, 0);
		return false;
	}
	interval = MAX(READ_ONCE(cctx->active_balance_interval_ms),
		       active_balance_min_ms(cid));
	WRITE_ONCE(cctx->active_balance_next,
		   now + (u64)interval * NSEC_PER_MSEC);
	__sync_val_compare_and_swap(&cctx->active_balance_pending, 1, 2);

	return true;
}

static void active_balance_complete(s32 cid, u32 outcome)
{
	struct cid_ctx __arena *cctx;
	u32 min_ms, interval, max_ms;

	if (!cid_valid(cid))
		return;
	cctx = cid_ctx(cid);
	min_ms = active_balance_min_ms(cid);
	interval = MAX(READ_ONCE(cctx->active_balance_interval_ms), min_ms);
	if (outcome == ACTIVE_BALANCE_MOVED)
		interval = min_ms;
	else {
		max_ms = outcome == ACTIVE_BALANCE_PINNED ?
			 ACTIVE_BALANCE_MAX_INTERVAL_MS : min_ms * 2;
		interval = MIN(interval * 2, max_ms);
	}
	WRITE_ONCE(cctx->active_balance_interval_ms, interval);
}

/*
 * Scan packing tier @t for a fully idle, due active-balance destination.
 * Unlike wake placement this does not claim the idle bit; reservation is a
 * separate atomic step immediately before the kick.
 */
static __always_inline s32
balance_scan_range(const struct task_struct *p, s32 t, u32 base, u32 nr,
		   bool restricted, u64 now)
{
	u32 k, last;

	if (!nr)
		return -EBUSY;
	last = (base + nr - 1) / 64;
	bpf_arena_for(k, base / 64, last + 1) {
		u64 w = cmask_word(idle_cids, k) &
			cmask_range_word(idle_cids, k, base, nr);

		if (t >= 0)
			w &= place_tier_word(t, k);

		while (w && can_loop) {
			s32 cid = k * 64 + __builtin_ctzll(w);

			w &= w - 1;
			if (!cid_valid(cid) || !cid_idle_test(cid) ||
			    (smt_enabled && !core_is_idle(cid)) ||
			    (restricted && !cid_allowed(p, cid)) ||
			    !active_balance_due(cid, now))
				continue;
			return cid;
		}
	}

	return -EBUSY;
}

/*
 * Find the idle destination that fair.c's asymmetric active balance would
 * use to pull @p off @src_cid. Across cores, sched_use_asym_prio() requires
 * the destination core to be fully idle under SMT. Within an SMT domain CPU
 * priority is always usable, so a preferred idle sibling is considered first.
 */
static s32 idle_asym_packing_cid(const struct task_struct *p, s32 src_cid,
				 u64 now)
{
	struct cid_topo __arena *src;
	task_ctx_t *tctx;
	bool restricted;
	u32 base, nr, nr_tiers, sibling, t;

	if (!asym_packing || !cid_valid(src_cid) || is_pcpu_task(p))
		return -EBUSY;
	src = cid_topo(src_cid);
	restricted = is_restricted(p);

	if (smt_enabled && src->smt_asym_packing) {
		bpf_arena_for(sibling, src->core_base, src->core_base + src->core_nr) {
			if (sibling != (u32)src_cid && cid_idle_test(sibling) &&
			    cid_topo(sibling)->place_tier < src->place_tier &&
			    (!restricted || cid_allowed(p, sibling)) &&
			    active_balance_due(sibling, now))
				return sibling;
		}
	}

	/*
	 * scx_eevdf has no fair-style group load attached to the running task.
	 * Do not actively chase a bursty current task through transient idle
	 * gaps; queued work is handled independently by the detach scan.
	 */
	tctx = try_lookup_task_ctx(p);
	if (!tctx || util_fits_cap(task_util(tctx, now), src->cap))
		return -EBUSY;

	/* Balance the child LLC domain before walking its parent, as fair.c does. */
	nr_tiers = src->place_tier;
	if (smt_enabled && !siblings_idle(src_cid))
		nr_tiers = nr_place_tiers;
	if (!nr_tiers)
		goto parent;
	bpf_arena_for(t, 0, nr_tiers) {
		s32 cid = balance_scan_range(p, t, src->llc_base, src->llc_nr,
					     restricted, now);

		if (cid >= 0)
			return cid;
	}

parent:
	/*
	 * At the parent domain, compare scheduling groups by their preferred
	 * CPU, not an arbitrary source CPU. The local-LLC scan above already
	 * exhausted these tiers, so a global scan cannot select it again.
	 */
	nr_tiers = src->llc_place_tier;
	if (!nr_tiers)
		return -EBUSY;
	base = numa_enabled ? src->node_base : 0;
	nr = numa_enabled ? src->node_nr : nr_cids;
	bpf_arena_for(t, 0, nr_tiers) {
		s32 cid = balance_scan_range(p, t, base, nr, restricted, now);

		if (cid >= 0 && cid_topo(cid)->llc_base != src->llc_base)
			return cid;
	}

	return -EBUSY;
}

/*
 * Find a fully idle CPU of the highest capacity available to a task that does
 * not fit @src_cid, mirroring fair.c's misfit active-balance case. A saturated
 * task does not pass fits_capacity() even on the fastest CPU; fair.c stops
 * treating it as misfit there through p->max_allowed_capacity instead. Thus
 * the destination is the task's highest allowed capacity, not necessarily a
 * CPU on which its current utilization passes the headroom test.
 */
static s32 idle_misfit_cid(const struct task_struct *p, s32 src_cid, u64 now)
{
	task_ctx_t *tctx;
	bool restricted;
	u64 util, src_cap, max_cap = 0;
	s32 best = -EBUSY;
	u32 cid;

	if (!asym_capacity || !cid_valid(src_cid) || is_pcpu_task(p) ||
	    cmask_empty(idle_cids))
		return -EBUSY;
	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return -EBUSY;
	util = task_util(tctx, now);
	src_cap = cid_topo(src_cid)->cap;
	restricted = is_restricted(p);

	bpf_arena_for(cid, 0, nr_cids) {
		struct cid_topo __arena *dst;

		if (restricted && !cid_allowed(p, cid))
			continue;
		dst = cid_topo(cid);
		if (dst->cap > max_cap)
			max_cap = dst->cap;
	}
	if (src_cap == max_cap || util_fits_cap(util, src_cap))
		return -EBUSY;

	bpf_arena_for(cid, 0, nr_cids) {
		struct cid_topo __arena *dst = cid_topo(cid);

		if (dst->cap != max_cap || cid == (u32)src_cid ||
		    !cid_idle_test(cid) ||
		    (smt_enabled && !core_is_idle(cid)) ||
		    (restricted && !cid_allowed(p, cid)) ||
		    !active_balance_due(cid, now))
			continue;
		best = cid;
		break;
	}

	return best;
}

static s32 idle_balance_cid(const struct task_struct *p, s32 src_cid, u64 now)
{
	struct cid_topo __arena *src;
	s32 cid;

	if (cmask_empty(idle_cids) || !cid_valid(src_cid) || is_pcpu_task(p))
		return -EBUSY;

	/*
	 * fair.c's group_smt_balance: a task sharing its core is moved to a
	 * fully idle core of the LLC first. The tick asks every millisecond
	 * and fair.c samples once a balance interval, so the contention has
	 * to have lasted a slice before a core is asked to split it: a
	 * sibling that is busy for one wakeup is not a core worth splitting.
	 */
	src = cid_topo(src_cid);
	if (smt_enabled && !siblings_idle(src_cid)) {
		struct cid_ctx __arena *cctx = cid_ctx(src_cid);

		if (!cctx->smt_busy_since)
			cctx->smt_busy_since = now;
		else if (!time_before(now, cctx->smt_busy_since + slice_ns)) {
			cid = balance_scan_range(p, -1, src->llc_base,
						 src->llc_nr, is_restricted(p),
						 now);
			if (cid >= 0)
				return select_idle_smt_balance_cid(p, cid, now);
		}
	} else if (smt_enabled) {
		cid_ctx(src_cid)->smt_busy_since = 0;
	}

	if (!asym_packing && !asym_capacity)
		return -EBUSY;
	cid = idle_asym_packing_cid(p, src_cid, now);
	if (cid < 0)
		cid = idle_misfit_cid(p, src_cid, now);

	return cid >= 0 ? select_idle_smt_balance_cid(p, cid, now) : cid;
}

enum active_balance_type {
	ACTIVE_BALANCE_NONE,
	ACTIVE_BALANCE_CAPACITY,
	ACTIVE_BALANCE_REMOTE_PACKING,
	ACTIVE_BALANCE_LOCAL_SMT,
	ACTIVE_BALANCE_LOCAL_PACKING,
};

/*
 * Classify the imbalance between an idle destination and a source. This is
 * task-independent: affinity and capacity fit are checked when a queued task
 * is detached or the source revalidates its current task.
 */
static u32 active_balance_type(s32 dst_cid, s32 src_cid)
{
	struct cid_topo __arena *dst, *src;

	if (!cid_valid(dst_cid) || !cid_valid(src_cid) || dst_cid == src_cid ||
	    cid_idle_test(src_cid))
		return ACTIVE_BALANCE_NONE;
	dst = cid_topo(dst_cid);
	src = cid_topo(src_cid);
	/*
	 * Between the threads of one core only a kernel-provided priority
	 * moves a running task; --smt-asym-packing ranks equal threads for
	 * placement and never migrates between them.
	 */
	if (dst->core_base == src->core_base)
		return asym_packing && dst->smt_asym_packing &&
		       dst->place_tier < src->place_tier ?
		       ACTIVE_BALANCE_LOCAL_PACKING : ACTIVE_BALANCE_NONE;
	if (smt_enabled && dst->llc_base == src->llc_base &&
	    core_is_idle(dst_cid) && !siblings_idle(src_cid))
		return ACTIVE_BALANCE_LOCAL_SMT;

	if (asym_packing) {
		if (dst->llc_base == src->llc_base &&
		    (!smt_enabled || core_is_idle(dst_cid))) {
			if (dst->place_tier < src->place_tier)
				return ACTIVE_BALANCE_LOCAL_PACKING;
			if (smt_enabled && !siblings_idle(src_cid))
				return ACTIVE_BALANCE_LOCAL_SMT;
		}
		if (dst->llc_base != src->llc_base &&
		    (!numa_enabled || dst->node_base == src->node_base) &&
		    (!smt_enabled || core_is_idle(dst_cid)) &&
		    dst->llc_place_tier < src->llc_place_tier) {
			return ACTIVE_BALANCE_REMOTE_PACKING;
		}
	}

	if (asym_capacity && dst->cap > src->cap &&
	    (!smt_enabled || core_is_idle(dst_cid)))
		return ACTIVE_BALANCE_CAPACITY;

	return ACTIVE_BALANCE_NONE;
}

/*
 * Select the busiest source with the strongest asymmetric imbalance. Try to
 * detach an eligible queued task from it first; only if that fails ask for its
 * current task through active balance. This is the focused equivalent of
 * sched_balance_find_src_group(), sched_balance_find_src_rq(), detach_tasks()
 * and the active-balance fallback.
 */
static bool request_active_balance(s32 dst_cid, u64 now)
{
	struct cid_ctx __arena *dst = cid_ctx(dst_cid);
	u32 base = numa_enabled ? cid_topo(dst_cid)->node_base : 0;
	u32 nr = numa_enabled ? cid_topo(dst_cid)->node_nr : nr_cids;
	u32 start = dst->steal_cursor;
	u32 best_type = ACTIVE_BALANCE_NONE, best_tier = 0;
	u32 best_nr_running = 0;
	u32 detach = ACTIVE_BALANCE_MISS;
	u64 best_util = 0;
	s32 best = -1;
	u32 i;

	if ((!smt_enabled && !asym_packing && !asym_capacity) ||
	    !cid_idle_test(dst_cid))
		return false;
	if (start < base || start >= base + nr)
		start = base;

	bpf_arena_for(i, 0, nr) {
		s32 src_cid = base + (start - base + i) % nr;
		struct cid_ctx __arena *src = cid_ctx(src_cid);
		u32 type = active_balance_type(dst_cid, src_cid);
		u32 nr_running;
		u64 util;

		if (!type)
			continue;
		nr_running = cid_queue_nr(src_cid) +
			     !!READ_ONCE(src->pack.curr_w);
		if (!nr_running)
			continue;
		util = cid_util(src_cid, now);
		if (best >= 0 && type < best_type)
			continue;
		if (best >= 0 && type == best_type &&
		    cid_topo(src_cid)->place_tier < best_tier)
			continue;
		if (best >= 0 && type == best_type &&
		    cid_topo(src_cid)->place_tier == best_tier &&
		    nr_running < best_nr_running)
			continue;
		if (best >= 0 && type == best_type &&
		    cid_topo(src_cid)->place_tier == best_tier &&
		    nr_running == best_nr_running && util <= best_util)
			continue;
		best = src_cid;
		best_type = type;
		best_tier = cid_topo(src_cid)->place_tier;
		best_nr_running = nr_running;
		best_util = util;
	}

	if (best < 0) {
		active_balance_complete(dst_cid, ACTIVE_BALANCE_MISS);
		return false;
	}
	dst->steal_cursor = best + 1;
	if (cid_queued_test(best)) {
		detach = detach_one_queued_task(dst_cid, best, now);
		if (detach == ACTIVE_BALANCE_MOVED) {
			active_balance_complete(dst_cid, detach);
			return true;
		}
	}
	if (!READ_ONCE(cid_pack(best)->curr_w) ||
	    __sync_val_compare_and_swap(&cid_ctx(best)->active_balance_cid, -1,
					    dst_cid) != -1) {
		active_balance_complete(dst_cid, detach);
		return false;
	}
	scx_bpf_kick_cid(best, SCX_KICK_PREEMPT);

	return false;
}

/*
 * Consume and revalidate an idle destination's active-balance request against
 * the task which is actually running on @src_cid now.
 */
static s32 active_balance_target(const struct task_struct *p, s32 src_cid,
				 u64 now)
{
	struct cid_ctx __arena *cctx = cid_ctx(src_cid);
	struct cid_topo __arena *src, *dst;
	task_ctx_t *tctx = NULL;
	s32 dst_cid = READ_ONCE(cctx->active_balance_cid);
	s32 target = -EBUSY;
	u32 outcome = ACTIVE_BALANCE_MISS;
	u32 type;
	bool restricted;

	if (dst_cid < 0 ||
	    __sync_val_compare_and_swap(&cctx->active_balance_cid, dst_cid,
					 -1) != dst_cid)
		return -EBUSY;
	if (!cid_valid(dst_cid))
		return -EBUSY;
	if (is_pcpu_task(p) || !cid_allowed(p, dst_cid)) {
		outcome = ACTIVE_BALANCE_PINNED;
		goto out;
	}
	if (!cid_idle_test(dst_cid))
		goto out;
	src = cid_topo(src_cid);
	dst = cid_topo(dst_cid);

	type = active_balance_type(dst_cid, src_cid);
	if (type > ACTIVE_BALANCE_CAPACITY) {
		/* Preferred SMT siblings remain fair.c's direct priority case. */
		if (dst->core_base == src->core_base) {
			target = dst_cid;
			goto out;
		}
		if (type == ACTIVE_BALANCE_LOCAL_SMT) {
			target = dst_cid;
			goto out;
		}
		tctx = try_lookup_task_ctx(p);
		if (tctx && !util_fits_cap(task_util(tctx, now), src->cap))
			target = dst_cid;
		goto out;
	}

	if (!asym_capacity || dst->cap <= src->cap ||
	    (smt_enabled && !core_is_idle(dst_cid)))
		goto out;
	if (!tctx)
		tctx = try_lookup_task_ctx(p);
	if (!tctx)
		goto out;

	/* Match update_misfit_status(): stop at the maximum allowed capacity. */
	restricted = is_restricted(p);
	if (!util_fits_cap(task_util(tctx, now), src->cap)) {
		u64 max_cap = 0;
		u32 cid;

		bpf_arena_for(cid, 0, nr_cids) {
			if ((!restricted || cid_allowed(p, cid)) &&
			    cid_topo(cid)->cap > max_cap)
				max_cap = cid_topo(cid)->cap;
		}
		if (dst->cap == max_cap)
			target = dst_cid;
	}

out:
	if (target >= 0)
		outcome = ACTIVE_BALANCE_MOVED;
	active_balance_complete(dst_cid, outcome);
	return target;
}

/*
 * Periodic busy load balancing, corresponding to fair.c's rebalance_domains().
 *
 * There is one interval for each sched-domain-like range scx_eevdf represents:
 * LLC, NUMA node and machine. Equal adjacent ranges are skipped by the caller.
 * The range weight times @busy_balance_factor is its initial interval in
 * milliseconds, fair's sd->min_interval scaled by sd->busy_factor for a busy
 * CPU, and balanced ranges back off to twice that, sd->max_interval. Different
 * destination cids are staggered across that interval instead of all walking
 * the same shared state on one tick.
 *
 * The old dispatch-time sampler compared instantaneous EDQ depths and moved a
 * task whenever a sampled queue happened to be deeper. Wakeup-heavy workloads
 * made that transient condition true millions of times. Here the decision is
 * calculate_imbalance()'s, on time-averaged, capacity-normalized loads. Like
 * update_sd_lb_stats(), each range is split into the sched groups immediately
 * below it: NUMA nodes below the machine, LLCs below a node, and cores below
 * an LLC. A pull requires capacity below the range average in the local group
 * and load above it in the source group. The movable load is the smaller of
 * that room and excess, and sd->imbalance_pct (117%) is required between busy
 * groups. Like sched_balance_find_src_group() and
 * sched_balance_find_src_rq(), the busiest eligible child group is selected
 * first, then its busiest queued cid. The individual source and destination
 * cids get the same guard when the destination has something queued. A bounded
 * deadline-ordered prefix is searched for a movable task whose weight fits the
 * group imbalance, as detach_tasks() does for migrate_load.
 *
 * Like should_we_balance(), one cid owns a pass for each local group. It
 * retains the calculated imbalance as a budget and dispatch drains it one
 * cold, affinity-compatible EDQ candidate at a time. If the task cannot run
 * on the owner, can_migrate_task()'s new_dst_cpu rule redirects the reservation
 * to another allowed cid in the same local group.
 */
/*
 * The capacity-normalized load of the whole range, sds->avg_load, one read
 * per cid like update_sd_lb_stats().
 */
__noinline u64 busy_balance_avg_load(u32 base, u32 nr, u64 now,
				     u64 *sum_util __arg_nonnull)
{
	u64 load = 0, cap = 0, util = 0;
	u32 i;

	TOUCH_ARENA();
	bpf_arena_for(i, base, base + nr) {
		s32 cid = i;
		u64 sample, sample_cap;

		if (!cid_valid(cid))
			break;
		sample = cid_load(cid, now);
		sample_cap = capacity_pressure &&
			READ_ONCE(cid_ctx(cid)->pressure_demand) &&
			READ_ONCE(cid_ctx(cid)->pressure_valid) ?
			READ_ONCE(cid_ctx(cid)->busy_balance_cap) :
			cid_topo(cid)->cap;
		if (!sample_cap)
			sample_cap = cid_topo(cid)->cap;
		/* Group totals below reuse the samples collected by this pass. */
		WRITE_ONCE(cid_ctx(cid)->busy_balance_load, sample);
		WRITE_ONCE(cid_ctx(cid)->busy_balance_scan_cap, sample_cap);
		load += sample;
		cap += sample_cap;
		/* What SIS_UTIL wants, off the walk that is happening anyway. */
		if (sis_util)
			util += cid_util(cid, now);
	}

	*sum_util = util;

	return cap ? load * 1024 / cap : 0;
}

/*
 * update_idle_cpu_scan(): cache how much of an LLC wakeups should search. The
 * utilization it needs is summed by the walk the balance is doing anyway, as
 * update_sd_lb_stats() collects sum_util for it rather than walking again.
 * With x equal to its average utilization per CPU, fair.c computes
 *
 *   y = 1024 - min(x^2 * imbalance_pct^2 / (10000 * 1024), 1024)
 *   nr_idle_scan = llc_weight * y / 1024
 *
 * so the scan shrinks quadratically and reaches zero at 100 / 117, about
 * 85% utilization. This runs only from periodic balance on the LLC owner.
 */
static __noinline void update_sis_idle_scan(u32 base, u32 nr, u64 sum)
{
	u64 x, scaled, y;

	if (!sis_util || !nr)
		return;
	x = sum / nr;
	scaled = x * x * BUSY_BALANCE_IMBALANCE_PCT *
		 BUSY_BALANCE_IMBALANCE_PCT;
	scaled /= 10000 * 1024;
	y = 1024 - MIN(scaled, 1024ULL);
	WRITE_ONCE(cid_ctx(base)->sis_idle_scan, nr * y / 1024);
	__sync_fetch_and_add(&sis_scan_sum, nr * y / 1024);
	__sync_fetch_and_add(&nr_sis_updates, 1);
}

/* Load above or capacity below @avg_norm for one sched group. */
__noinline u64
busy_balance_group_delta(s32 dst_cid, u64 group, u64 avg_norm, bool excess)
{
	struct busy_balance_env __arena *env = &cid_ctx(dst_cid)->busy_balance_env;
	u64 load = 0, cap = 0;
	u32 base = group, nr = group >> 32;
	u32 i;

	TOUCH_ARENA();
	env->group_queued = 0;
	bpf_arena_for(i, base, base + nr) {
		if (!cid_valid(i))
			break;
		load += READ_ONCE(cid_ctx(i)->busy_balance_load);
		cap += READ_ONCE(cid_ctx(i)->busy_balance_scan_cap);
		if (cid_queued_test(i))
			env->group_queued = 1;
	}
	env->group_load = load;
	env->group_cap = cap;

	if (excess)
		return load > avg_norm * cap / 1024 ?
			load - avg_norm * cap / 1024 : 0;
	return avg_norm * cap / 1024 > load ?
		avg_norm * cap / 1024 - load : 0;
}

/*
 * Pick the busiest sched group outside the destination's local group, as
 * sched_balance_find_src_group() does before looking at individual runqueues.
 * The group load samples were collected by busy_balance_avg_load(), so this
 * pass only aggregates those samples at the child level of the domain.
 */
__noinline bool busy_balance_find_src_group(s32 dst_cid, u32 base, u32 nr)
{
	struct busy_balance_env __arena *env = &cid_ctx(dst_cid)->busy_balance_env;
	u64 best_load = 0, best_cap = 1, best_excess = 0;
	u32 best_base = 0, best_nr = 0;
	u32 i;

	TOUCH_ARENA();
	bpf_arena_for(i, base, base + nr) {
		u32 group_base, group_nr;
		u64 excess, norm;

		if (!cid_valid(i))
			break;
		if (env->level == BUSY_BALANCE_SYSTEM) {
			group_base = cid_topo(i)->node_base;
			group_nr = cid_topo(i)->node_nr;
		} else if (env->level == BUSY_BALANCE_NODE) {
			group_base = cid_topo(i)->llc_base;
			group_nr = cid_topo(i)->llc_nr;
		} else {
			group_base = cid_topo(i)->core_base;
			group_nr = cid_topo(i)->core_nr;
		}
		/* Each child group is contiguous; aggregate it only at its base. */
		if (i != group_base ||
		    group_base == env->local_base || !group_nr)
			continue;
		excess = busy_balance_group_delta(
					dst_cid,
					(u64)group_nr << 32 | group_base,
					env->avg_norm, true);
		if (!excess || !env->group_queued)
			continue;
		norm = env->group_load * 1024 / MAX(env->group_cap, 1ULL);
		if (env->local_overloaded &&
		    norm * 100 <=
		    env->local_norm * BUSY_BALANCE_IMBALANCE_PCT)
			continue;
		/* Compare load / capacity without losing precision to division. */
		if (env->group_load * best_cap <= best_load * env->group_cap)
			continue;
		best_load = env->group_load;
		best_cap = env->group_cap;
		best_excess = excess;
		best_base = group_base;
		best_nr = group_nr;
	}

	if (!best_nr)
		return false;
	env->group_base = best_base;
	env->group_nr = best_nr;
	env->source_excess = best_excess;
	return true;
}

/*
 * Within the busiest group, select the busiest queued cid, corresponding to
 * sched_balance_find_src_rq(). Rotate equal-load choices after the previous
 * source so that repeated passes do not always drain the lowest cid.
 */
__noinline s32 busy_balance_find_src_cid(s32 dst_cid, u32 start)
{
	struct busy_balance_env __arena *env = &cid_ctx(dst_cid)->busy_balance_env;
	u64 best_load = 0, best_cap = 1;
	s32 best = -1;
	u32 off;

	TOUCH_ARENA();
	if (!env->group_nr)
		return -1;
	if (start < env->group_base ||
	    start >= env->group_base + env->group_nr)
		start = env->group_base;
	bpf_arena_for(off, 0, env->group_nr) {
		s32 cid = env->group_base +
			  (start - env->group_base + off) % env->group_nr;
		u64 load, cap, norm;

		if (!cid_valid(cid) || cid_idle_test(cid) || !cid_queued_test(cid))
			continue;
		load = READ_ONCE(cid_ctx(cid)->busy_balance_load);
		cap = MAX(READ_ONCE(cid_ctx(cid)->busy_balance_scan_cap), 1ULL);
		norm = load * 1024 / cap;
		if (norm <= env->avg_norm)
			continue;
		if (env->dst_overloaded &&
		    norm * 100 <=
		    env->dst_norm * BUSY_BALANCE_IMBALANCE_PCT)
			continue;
		if (load * best_cap > best_load * cap) {
			best_load = load;
			best_cap = cap;
			best = cid;
		}
	}

	return best;
}

/*
 * fair.c's can_migrate_task() records new_dst_cpu when a task cannot run on
 * the CPU elected by should_we_balance(), but can run on another CPU in its
 * local scheduling group. The elected cid still owns and serializes the scan;
 * return the first destination in that group which can consume its result.
 */
static __always_inline s32
busy_balance_dst_cid(const struct task_struct *p, s32 owner_cid)
{
	struct busy_balance_env __arena *env =
		&cid_ctx(owner_cid)->busy_balance_env;
	u32 i;

	if (cid_allowed(p, owner_cid))
		return owner_cid;
	bpf_arena_for(i, 0, env->local_nr) {
		s32 cid = env->local_base + i;

		if (cid == owner_cid || !cid_valid(cid) ||
		    !cid_allowed(p, cid) ||
		    READ_ONCE(cid_ctx(cid)->busy_balance_cid) != -1)
			continue;
		return cid;
	}

	return -1;
}

/*
 * Like detach_tasks(), walk a bounded prefix of the selected source queue
 * instead of letting one pinned, hot, or oversized head hide movable work.
 * EDQ order is deadline order, so the first task accepted here is the one
 * scx_eevdf would prefer among the inspected candidates.
 */
static __noinline bool
busy_balance_has_movable_task(s32 dst_cid, s32 src_cid, u64 now)
{
	struct busy_balance_env __arena *env = &cid_ctx(dst_cid)->busy_balance_env;
	scx_edq_cursor_t *cursor = &cid_ctx(src_cid)->busy_scan_cursor;
	u64 budget = MIN(env->local_room, env->source_excess);
	u32 failed = READ_ONCE(cid_ctx(dst_cid)->busy_balance_failed[env->level]);
	u32 nth;

	env->alternate_dst_cid = -1;
	TOUCH_ARENA();
	bpf_for(nth, 0, BALANCE_TASK_SCAN) {
		cid_edq_task_t *at;
		struct task_struct *p;
		u64 candidate_deadline, candidate_seq, candidate_weight;
		s32 move_dst;
		int ret;

		ret = edq_scan_next(src_cid, cursor, &at);
		if (ret)
			return false;
		if (!at) {
			if (!nth)
				cid_queued_check(src_cid);
			break;
		}
		candidate_weight = ((task_ctx_t *)at)->se.vjoin_w;
		if (READ_ONCE(at->state) != CID_EDQ_ENQUEUED ||
		    (candidate_weight >> MIN(failed, 63U)) > budget ||
		    (task_hot((task_ctx_t *)at, src_cid, dst_cid, now) &&
		     failed <= cache_nice_tries)) {
			scx_edq_task_drop(&at->common);
			continue;
		}
		candidate_deadline = at->common.node.deadline;
		candidate_seq = at->common.node.seq;
		p = scx_bpf_tid_to_task(at->tid);
		move_dst = p ? busy_balance_dst_cid(p, dst_cid) : -1;
		scx_edq_task_drop(&at->common);
		if (move_dst < 0)
			continue;
		/*
		 * can_migrate_task() first drains tasks which can use the
		 * elected destination. LBF_DST_PINNED only revisits an alternate
		 * CPU in the local group if imbalance remains after that scan.
		 * Remember the first such candidate, but keep looking for work
		 * that does not need the redirect.
		 */
		if (move_dst != dst_cid) {
			if (env->alternate_dst_cid < 0) {
				env->alternate_dst_cid = move_dst;
				env->alternate_deadline = candidate_deadline;
				env->alternate_seq = candidate_seq;
			}
			continue;
		}
		env->move_budget = budget;
		env->move_dst_cid = move_dst;
		/* Dispatch must begin at, rather than after, this candidate. */
		env->scan_deadline = candidate_deadline;
		env->scan_seq = candidate_seq;
		env->scan_valid = SCX_EDQ_CURSOR_AT;
		return true;
	}
	if (env->alternate_dst_cid >= 0) {
		env->move_budget = budget;
		env->move_dst_cid = env->alternate_dst_cid;
		env->scan_deadline = env->alternate_deadline;
		env->scan_seq = env->alternate_seq;
		env->scan_valid = SCX_EDQ_CURSOR_AT;
		return true;
	}

	return false;
}

static __always_inline s32
busy_balance_from_range(s32 dst_cid, u32 base, u32 nr, u32 start, u64 now,
			u32 level)
{
	struct busy_balance_env __arena *env = &cid_ctx(dst_cid)->busy_balance_env;
	u64 sum_util = 0;
	s32 cid;

	env->detach_failed = 0;
	if (!nr)
		return -1;
	env->avg_norm = busy_balance_avg_load(base, nr, now, &sum_util);
	if (level == BUSY_BALANCE_LLC)
		update_sis_idle_scan(base, nr, sum_util);
	env->dst_norm = cid_load(dst_cid, now) * 1024 /
			MAX(READ_ONCE(cid_ctx(dst_cid)->busy_balance_scan_cap), 1ULL);
	if (env->dst_norm >= env->avg_norm)
		return -1;
	env->dst_overloaded = cid_queue_nr(dst_cid) > 0;
	if (level == BUSY_BALANCE_SYSTEM) {
		env->local_base = cid_topo(dst_cid)->node_base;
		env->local_nr = cid_topo(dst_cid)->node_nr;
	} else if (level == BUSY_BALANCE_NODE) {
		env->local_base = cid_topo(dst_cid)->llc_base;
		env->local_nr = cid_topo(dst_cid)->llc_nr;
	} else {
		env->local_base = cid_topo(dst_cid)->core_base;
		env->local_nr = cid_topo(dst_cid)->core_nr;
	}
	env->local_room = busy_balance_group_delta(dst_cid,
						    (u64)env->local_nr << 32 |
						    env->local_base,
						    env->avg_norm, false);
	env->local_norm = env->group_load * 1024 / MAX(env->group_cap, 1ULL);
	env->local_overloaded = env->group_load > env->group_cap;
	env->level = level;
	if (!env->local_room)
		return -1;
	if (!busy_balance_find_src_group(dst_cid, base, nr))
		return -1;
	cid = busy_balance_find_src_cid(dst_cid, start);
	if (cid < 0)
		return -1;
	if (!busy_balance_has_movable_task(dst_cid, cid, now)) {
		u32 failed = READ_ONCE(cid_ctx(dst_cid)->busy_balance_failed[level]);

		/*
		 * detach_tasks() progressively relaxes both its migration-size
		 * bound and cache-hotness after a periodic pass found imbalance
		 * but could not detach anything. Without that relaxation, an
		 * imbalance smaller than one task can never be repaired.
		 */
		env->detach_failed = 1;
		WRITE_ONCE(cid_ctx(dst_cid)->busy_balance_failed[level],
			   MIN(failed + 1, 63U));
		return -1;
	}
	return cid;
}

static __noinline bool
busy_balance_domain(s32 dst_cid, u32 base, u32 nr, u32 level, u64 now)
{
	struct cid_ctx __arena *dst = cid_ctx(dst_cid);
	struct cid_ctx __arena *move = dst;
	u32 min_ms, max_ms, interval, start;
	s32 src, move_dst = dst_cid;

	if (!nr || level >= BUSY_BALANCE_LEVELS)
		return false;
	/*
	 * fair.c's should_we_balance() lets one CPU in each local group run a
	 * periodic balance pass, falling back to group_balance_cpu() when the
	 * group is busy. scx_eevdf's periodic pass runs from ops.tick(), so an
	 * idle cid cannot be its owner; newly-idle balance handles that case.
	 * Use the fixed group leader here, which is the fair.c choice once all
	 * CPUs in the group are busy, and let it drain the calculated imbalance
	 * over successive dispatch callbacks below.
	 */
	if ((level == BUSY_BALANCE_SYSTEM &&
	     dst_cid != cid_topo(dst_cid)->node_base) ||
	    (level == BUSY_BALANCE_NODE &&
	     dst_cid != cid_topo(dst_cid)->llc_base) ||
	    (level == BUSY_BALANCE_LLC &&
	     dst_cid != cid_topo(dst_cid)->core_base))
		return false;
	/* A fair-style detach pass is still draining through dispatch. */
	if (READ_ONCE(dst->busy_balance_cid) != -1)
		return true;
	min_ms = MAX(nr * busy_balance_factor, 1U);
	/*
	 * get_sd_balance_interval() subtracts one tick from a busy interval so
	 * adjacent domains, and periodic activity such as RT runtime, cannot
	 * remain phase-locked to the balance pass.
	 */
	if (min_ms > 1)
		min_ms--;
	max_ms = 2 * min_ms;
	interval = READ_ONCE(dst->busy_balance_interval_ms[level]);
	if (!interval) {
		WRITE_ONCE(dst->busy_balance_interval_ms[level], min_ms);
		WRITE_ONCE(dst->busy_balance_next[level],
			   now + (u64)(1 + (dst_cid - base) % min_ms) *
				 NSEC_PER_MSEC);
		return false;
	}
	if (time_before(now, READ_ONCE(dst->busy_balance_next[level])) ||
	    scx_bpf_dsq_nr_queued(SCX_DSQ_LOCAL))
		return false;

	start = READ_ONCE(dst->busy_balance_cursor[level]);
	if (start < base || start >= base + nr)
		start = base;
	src = busy_balance_from_range(dst_cid, base, nr, start, now,
				      level);
	/* fair resets nr_balance_failed once the domain is balanced again. */
	if (src < 0 && !dst->busy_balance_env.detach_failed)
		WRITE_ONCE(dst->busy_balance_failed[level], 0);
	if (src >= 0) {
		move_dst = dst->busy_balance_env.move_dst_cid;
		if (!cid_valid(move_dst))
			src = -1;
		else
			move = cid_ctx(move_dst);
	}
	if (src >= 0) {
		/* Claim first, so a failed selection cannot extend an older one. */
		if (__sync_val_compare_and_swap(&move->busy_balance_cid,
							-1, -2) != -1)
			src = -1;
	}
	if (src >= 0) {
		scx_edq_cursor_t *cursor =
			&move->busy_dispatch_cursor;

		cursor->deadline = dst->busy_balance_env.scan_deadline;
		cursor->seq = dst->busy_balance_env.scan_seq;
		cursor->valid = dst->busy_balance_env.scan_valid;
		WRITE_ONCE(move->busy_balance_expire,
			   now + (u64)min_ms * NSEC_PER_MSEC);
		WRITE_ONCE(move->busy_balance_budget,
			   dst->busy_balance_env.move_budget);
		WRITE_ONCE(move->busy_balance_owner, dst_cid);
		WRITE_ONCE(move->busy_balance_level, level);
		WRITE_ONCE(move->busy_balance_cid, src);
		if (move_dst != dst_cid)
			scx_bpf_kick_cid(move_dst, SCX_KICK_IDLE);
	}
	WRITE_ONCE(dst->busy_balance_cursor[level],
		   src >= 0 ? src + 1 : start + 1);
	interval = src >= 0 ? min_ms : MIN(interval * 2, max_ms);
	WRITE_ONCE(dst->busy_balance_interval_ms[level], interval);
	WRITE_ONCE(dst->busy_balance_next[level],
		   now + (u64)interval * NSEC_PER_MSEC);

	return src >= 0;
}

/*
 * A higher scheduling class just displaced @p from @src_cid. Once the
 * measured capacity is materially reduced, choose a less-loaded allowed cid
 * for the now-detached task. ops.enqueue() puts it into that cid's EDQ, where
 * it competes by the ordinary EEVDF rules. This is the sched_ext equivalent
 * of fair's detach_tasks() followed by attach_tasks(), not a forced dispatch.
 */
static __noinline s32
capacity_pressure_target(const struct task_struct *p, s32 src_cid, u64 now)
{
	task_ctx_t *tctx = try_lookup_task_ctx(p);
	u64 src_load, src_cap, src_norm;
	u64 best_load = 0, best_cap = 1;
	u64 move_budget, weight;
	u32 best_smt_rank = 0;
	u32 failed;
	u32 interval_ms;
	s32 best = -1;
	u32 i;

	if (!tctx || !capacity_pressure || !cid_valid(src_cid) ||
	    time_before(now, READ_ONCE(cid_ctx(src_cid)->pressure_migrate_next)) ||
	    !cid_capacity_reduced(src_cid))
		return -1;
	src_cap = READ_ONCE(cid_ctx(src_cid)->busy_balance_cap);
	/* Pace the scan, including misses, at the LLC busy-balance interval. */
	interval_ms = MAX(cid_topo(src_cid)->llc_nr * busy_balance_factor, 1U);
	if (interval_ms > 1)
		interval_ms--;
	WRITE_ONCE(cid_ctx(src_cid)->pressure_migrate_next,
		   now + (u64)interval_ms * NSEC_PER_MSEC);
	src_load = READ_ONCE(cid_pack(src_cid)->vsum_w);
	if (!src_load)
		return -1;

	TOUCH_ARENA();
	bpf_arena_for(i, 0, nr_cids) {
		u64 load, cap;
		u32 smt_rank = 0;
		s32 cid = i;

		if (cid == src_cid || !cid_valid(cid) || !cid_allowed(p, cid))
			continue;
		if (smt_whole_core && smt_enabled) {
			if (core_is_idle(cid))
				smt_rank = 0;
			else if (!cid_idle_test(cid))
				smt_rank = 1;
			else
				smt_rank = 2;
		}
		load = READ_ONCE(cid_pack(cid)->vsum_w);
		cap = READ_ONCE(cid_ctx(cid)->pressure_demand) &&
		      READ_ONCE(cid_ctx(cid)->pressure_valid) ?
			READ_ONCE(cid_ctx(cid)->busy_balance_cap) :
			cid_topo(cid)->cap;
		if (!cap)
			cap = cid_topo(cid)->cap;
		if (best < 0 || smt_rank < best_smt_rank ||
		    (smt_rank == best_smt_rank &&
		     (load * best_cap < best_load * cap ||
		      (load * best_cap == best_load * cap &&
		       smt_prefer(cid, best))))) {
			best = cid;
			best_load = load;
			best_cap = cap;
			best_smt_rank = smt_rank;
		}
	}
	if (best < 0)
		return -1;
	src_norm = src_load * 1024 / src_cap;
	if (src_norm * 100 <= best_load * 1024 / best_cap *
				 BUSY_BALANCE_IMBALANCE_PCT)
		return -1;

	/*
	 * detach_tasks() does not move more load than calculate_imbalance()
	 * requested, and relaxes that bound together with cache hotness after
	 * failed passes. Do the same for this single detached current task.
	 */
	move_budget = (src_load * best_cap - best_load * src_cap) /
		      (src_cap + best_cap);
	weight = tctx->se.vjoin_w;
	failed = READ_ONCE(cid_ctx(src_cid)->pressure_migrate_failed);
	if ((weight >> MIN(failed, 63U)) > move_budget ||
	    (task_hot(tctx, src_cid, best, now) &&
	     failed <= cache_nice_tries)) {
		WRITE_ONCE(cid_ctx(src_cid)->pressure_migrate_failed,
			   MIN(failed + 1, 255U));
		return -1;
	}
	WRITE_ONCE(cid_ctx(src_cid)->pressure_migrate_failed, 0);
	return best;
}

/*
 * Move a task from the bounded deadline-ordered prefix of @src_cid selected by
 * periodic busy balance for @dst_cid, but only once it is the task @dst_cid
 * would pick.
 *
 * attach_task() does not run what it pulls: it enqueues it and lets
 * wakeup_preempt() decide, and pick_eevdf() then runs it only once it is
 * the eligible task with the earliest deadline, the running one and the
 * queued ones included. A task on LOCAL runs before either here, so the
 * pick is taken before the move instead. The task is placed the way
 * ops.running() will place it, at the lag it carries from its pack, with
 * the relative deadline it was queued with, and compared with what
 * keep_running() would keep and with this cid's queue head. With nothing
 * eligible to compete against, the pull wins.
 *
 * Return 1 when the task moved, 0 when the selection is gone, and -EAGAIN
 * when it stands but would not be the pick yet.
 */
static __noinline int
busy_balance_move_to_local(s32 dst_cid, s32 src_cid, bool has_prev,
			   u64 now, u64 tnow)
{
	struct cid_ctx __arena *dst = cid_ctx(dst_cid);
	scx_edq_cursor_t *cursor = &dst->busy_dispatch_cursor;
	u64 rival_dl = 0, head_dl = 0, min_slice;
	s32 owner = READ_ONCE(dst->busy_balance_owner);
	u32 level = READ_ONCE(dst->busy_balance_level);
	u32 failed = cid_valid(owner) && level < BUSY_BALANCE_LEVELS ?
		READ_ONCE(cid_ctx(owner)->busy_balance_failed[level]) : 0;
	bool rival = false;
	bool retry = false;
	u32 nth;

	if (has_prev && curr_pick_dl(cid_pack(dst_cid), tnow, &rival_dl))
		rival = true;
	if (cid_queued_test(dst_cid) &&
	    pack_pick_head_dl(&dst->pack, tnow, &head_dl, &min_slice) &&
	    (!rival || time_before(head_dl, rival_dl))) {
		rival_dl = head_dl;
		rival = true;
	}
	bpf_for(nth, 0, BALANCE_TASK_SCAN) {
		cid_edq_task_t *at;
		struct task_struct *p;
		s64 lag;
		u64 dl, v, weight;
		int ret;

		ret = edq_scan_next(src_cid, cursor, &at);
		if (ret)
			return ret == -EBUSY ? -EAGAIN : 0;
		if (!at) {
			if (!nth)
				cid_queued_check(src_cid);
			break;
		}
		weight = ((task_ctx_t *)at)->se.vjoin_w;
		if (READ_ONCE(at->state) != CID_EDQ_ENQUEUED ||
		    (weight >> MIN(failed, 63U)) >
			    READ_ONCE(dst->busy_balance_budget) ||
		    (task_hot((task_ctx_t *)at, src_cid, dst_cid, now) &&
		     failed <= cache_nice_tries)) {
			scx_edq_task_drop(&at->common);
			continue;
		}
		p = scx_bpf_tid_to_task(at->tid);
		if (!p || !cid_allowed(p, dst_cid)) {
			scx_edq_task_drop(&at->common);
			continue;
		}
		lag = task_lag_at(p, (task_ctx_t *)at,
				  task_pack((task_ctx_t *)at, src_cid), now);
		v = pack_vref_place(task_pack((task_ctx_t *)at, dst_cid), tnow) - lag;
		dl = v + (at->common.node.deadline -
			  at->common.node.eligibility);
		if (rival &&
		    ((!no_eligibility && lag < 0) || !time_before(dl, rival_dl))) {
			retry = true;
			scx_edq_task_drop(&at->common);
			continue;
		}
		ret = cid_edq_remove_held_to_local(src_cid, dst_cid, at, p);
		if (ret == CID_EDQ_MOVE_BUSY)
			return -EAGAIN;
		if (ret != CID_EDQ_MOVE_MOVED)
			continue;
		edq_scan_reset(cursor);
		dst->busy_balance_budget = weight >= dst->busy_balance_budget ? 0 :
					   dst->busy_balance_budget - weight;
		return 1;
	}

	return retry ? -EAGAIN : 0;
}

/*
 * Periodic tick on a cid that is running an scx task.
 *
 * A queue building up beside an idle CPU is nobody's job to notice, and
 * fair.c has the same problem: an idle CPU that has already been through
 * newidle_balance() will not look again by itself. It is told to, from
 * the tick, by nohz_balancer_kick():
 *
 *	if (rq->nr_running >= 2) {
 *		flags = NOHZ_STATS_KICK | NOHZ_BALANCE_KICK;
 *		goto out;
 *	}
 *
 * and that is the only place the kernel sends it: sched_balance_trigger()
 * has one caller, sched_tick(). Nothing on the enqueue or the wakeup path
 * ever wakes a third CPU to come and pull. Here it is not sent at all,
 * since sched_tick() skips sched_balance_trigger() once sched_ext has
 * taken every task, so this is the whole of it.
 *
 * One task queued beside the running one is @rq->nr_running == 2, the
 * condition above. The task woken for is the head of the queue, the one
 * a scan would take, and only a cid it is allowed on is worth waking:
 * it is that task the woken cid would come to pull, see try_steal_task().
 * One cid is enough, since the scan it wakes into reads every queue of
 * the node anyway.
 *
 * The tick is also the right rate. Scanning on every enqueue instead puts
 * the walk and an IPI on the wakeup path, where they cost more than the
 * idle CPU they are meant to recover, and pulls a wakee off the cid that
 * wake_affine_cid() has just stacked it on.
 */
void BPF_STRUCT_OPS(eevdf_tick, struct task_struct *p)
{
	struct cid_topo __arena *topo;
	bool queued;
	s32 cid = scx_bpf_this_cid(), peer;
	struct task_struct *head;
	u64 now, tid;

	TOUCH_ARENA();
	now = scx_bpf_now();
	if (latency_credit && latency_credit_user_thresh) {
		task_ctx_t *tctx = try_lookup_task_ctx(p);

		if (tctx)
			update_cid_user(p, cid, tctx, now);
	}

	if (!cid_valid(cid))
		return;
	topo = cid_topo(cid);
	credit_stats_fold(cid);

	/*
	 * The share a task's groups give it moves with the tasks that come and
	 * go in them: take the running task over to it, as task_tick_fair()
	 * does through update_cfs_group() and reweight_eevdf(), charging what it
	 * ran at the old weight first.
	 */
	if (cgroup_enabled) {
		task_ctx_t *tctx = try_lookup_task_ctx(p);
		grp_q_t *gq = tctx ? tctx->gq : NULL;
		int i;

		grp_sweep(now);

		/* update_cfs_group() for every level the task runs in. */
		for (i = 0; gq && i < GRP_MAX_DEPTH; i++) {
			grp_update_shares(gq, now);
			gq = gq->parent;
		}

		if (tctx && tctx->gq && tctx->se.vpack &&
		    grp_h_weight(tctx->gq, tctx->gw, false) != tctx->se.vjoin_w) {
			u64 tnow = cid_clock_task_owned(cid, now);

			keep_charge(p, cid, tnow);
			task_h_refresh(tctx, now);
			keep_charge(p, cid, tnow);
		}

		/*
		 * Bring the bandwidth of the groups it runs in up to date and
		 * end its slice if they have run out, entity_tick() asking
		 * check_cfs_rq_runtime(). The dispatch that follows the ended
		 * slice is where the task is actually given up, see
		 * eevdf_dispatch(); doing it here only means a task is not
		 * left running a whole slice past a limit it has reached.
		 */
		if (bw_enabled() && tctx) {
			keep_charge(p, cid, cid_clock_task_owned(cid, now));
			if (task_bw_throttled(tctx, cid, now))
				scx_bpf_task_set_slice(p, 0);
		}
	}

	if (!no_newidle_cost)
		newidle_decay(cid_ctx(cid), now);
	cid_load_accumulate(cid, now);
	update_balance_cap(cid, now);

	/*
	 * Run wider, less frequent domains first when two happen to be due on
	 * the same tick. Stop after one successfully reserved source rather than
	 * stacking migrations from multiple levels at one scheduling boundary.
	 */
	if (nr_cids > topo->node_nr &&
	    busy_balance_domain(cid, 0, nr_cids, BUSY_BALANCE_SYSTEM, now))
		return;
	if (topo->node_nr > topo->llc_nr &&
	    busy_balance_domain(cid, topo->node_base, topo->node_nr,
				BUSY_BALANCE_NODE, now))
		return;
	if (busy_balance_domain(cid, topo->llc_base, topo->llc_nr,
				BUSY_BALANCE_LLC, now))
		return;
	queued = cid_queue_nr(cid);

	/*
	 * update_misfit_status() records the running task even when other work is
	 * queued, and nohz_balancer_kick() asks an idle CPU to run the
	 * group_misfit_task balance when nr_running >= 2. Do the equivalent from
	 * the source tick while @p is exact: a queued, pinned head must not hide a
	 * current task which needs a larger CPU. The destination still consumes
	 * and revalidates the request through active_balance_target(), preserving
	 * the deferred detach used by the other active-balance cases.
	 */
	if (asym_capacity && queued) {
		peer = idle_misfit_cid(p, cid, now);
		if (peer >= 0 && peer != cid && active_balance_reserve(peer, now)) {
			scx_bpf_kick_cid(peer, SCX_KICK_IDLE);
			return;
		}
	}
	if (!queued) {
		/*
		 * nohz_balancer_kick() also wakes an idle balancer when the sole
		 * runnable task is on a lower-priority or undersized CPU. Serialize
		 * that trigger once per placement domain, initially at fair.c's
		 * domain-weight interval. The interval belongs to the idle
		 * destination, as fair.c's balance interval does. Reserve that
		 * destination before the kick so concurrent source ticks cannot
		 * request the same balance.
		 */
		peer = idle_balance_cid(p, cid, now);
		if (peer >= 0 && peer != cid && active_balance_reserve(peer, now)) {
			scx_bpf_kick_cid(peer, SCX_KICK_IDLE);
		}
		return;
	}

	/*
	 * The head is only looked up for idle_peer_cid(), which has nothing
	 * to offer when no cid is idle; that is the common case on a busy
	 * machine, and the lookup is the expensive part of this tick.
	 */
	if (cmask_empty(idle_cids))
		return;
	tid = cid_edq_peek_tid_owned(cid);
	head = tid ? scx_bpf_tid_to_task(tid) : NULL;
	if (!head)
		return;

	peer = idle_peer_cid(head, cid);
	if (peer >= 0 && peer != cid) {
		/*
		 * If the ordinary head pull fails, let the idle cid walk past a
		 * pinned or cache-hot head before considering active balance. The
		 * ordinary pull is not paced; only reserve its active-balance
		 * fallback when the destination interval is due.
		 */
		active_balance_reserve(peer, now);
		scx_bpf_kick_cid(peer, SCX_KICK_IDLE);
	}
}
