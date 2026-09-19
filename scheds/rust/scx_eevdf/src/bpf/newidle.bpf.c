/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.
 *
 * The idle pull, sched_balance_newidle(): a cid that has run out of work
 * looks for some on its neighbours, under the budget its idle periods have
 * paid for and the sampling its success rate asks for.
 */
#include "eevdf.bpf.h"
#include "balance.bpf.h"
#include "idle.bpf.h"
#include "queue.bpf.h"

/*
 * newidle_cost(): the budget of an idle pull, sched_balance_newidle()'s.
 *
 * A cid that runs out of work looks for some, and fair.c asks first
 * whether the look is worth it. The rq keeps avg_idle, how long the CPU
 * has been staying idle after a newidle balance, every domain keeps
 * max_newidle_lb_cost, the most a pull at that level has cost, and the
 * balance is skipped before it starts and stopped at the level the
 * budget runs out at:
 *
 *	if (!get_rd_overloaded(this_rq->rd) ||
 *	    this_rq->avg_idle < sd->max_newidle_lb_cost)
 *		goto out;
 *	for_each_domain(this_cpu, sd) {
 *		if (this_rq->avg_idle < curr_cost + sd->max_newidle_lb_cost)
 *			break;
 *		...
 *		domain_cost = t1 - t0;
 *		curr_cost += domain_cost;
 *		update_newidle_cost(sd, domain_cost, ...);
 *	}
 *	if (curr_cost > this_rq->max_idle_balance_cost)
 *		this_rq->max_idle_balance_cost = curr_cost;
 *
 * A CPU whose idle periods are shorter than a scan is one its own wakeups
 * keep bringing back: a task pulled for it comes off a queue whose owner
 * was about to run it, onto a CPU about to have work of its own, and the
 * pull costs more than the idle time it fills. The period is measured
 * from the moment the pull begins, idle_stamp, to the moment the CPU
 * leaves idle, update_rq_avg_idle(), as an average that moves an eighth
 * of the way to every sample and is capped at twice the rq's worst pull,
 * so that one long idle spell does not license scans for the next second
 * of storm:
 *
 *	u64 delta = rq_clock(rq) - rq->idle_stamp;
 *	u64 max = 2*rq->max_idle_balance_cost;
 *	update_avg(&rq->avg_idle, delta);
 *	if (rq->avg_idle > max)
 *		rq->avg_idle = max;
 *
 * A level's cost decays by 1% a second once it stops being raised,
 * update_newidle_cost(), so a spike does not close the budget for good,
 * and the rq's worst pull is refreshed from the sum of the levels when
 * they decay, floored at sysctl_sched_migration_cost. Both start where
 * sched_init() starts them, at twice and once that cost.
 *
 * The levels here are the three an idle cid walks, its LLC, the rest of
 * the node, and the rest of the system (fair.c's top-level sched domain).
 * The climb up the capacity tiers that precedes the first is charged to the LLC.
 * A pull kicked for a specific waiter, see ops.tick(), is not budgeted:
 * that is the idle balancer running for
 * nohz_balancer_kick(), which fair.c does not gate by avg_idle either.
 * The stamp is only read once the cid has gone idle, and every way there
 * passes through the pull, so a stamp left behind by a pull that found
 * something is never read.
 */
#define NEWIDLE_DECAY_NS	1000000000ULL

/*
 * Feed one scan result into fair.c's newidle success and call-rate
 * estimator. @success is one for an ordinary scan and its inverse sampling
 * weight for a scan admitted by newidle_should_scan().
 */
static void update_newidle_stats(s32 cid, u32 level, u32 success, u64 now)
{
	struct newidle_stats __arena *stats = &newidle_stats[cid];
	u64 delta, ratio;

	stats->call[level]++;
	stats->success[level] += success;
	if (stats->call[level] < 1024)
		return;

	delta = time_before(now, stats->stamp[level]) ? 0 :
		now - stats->stamp[level];
	stats->stamp[level] = now;

	/* NI_RATE: 4.194 ms between calls contributes one ratio point. */
	ratio = (delta >> 22) + stats->success[level];
	stats->ratio[level] = MIN(1024, ratio);
	stats->call[level] /= 2;
	stats->success[level] /= 2;
}

/*
 * NI_RANDOM: admit a scan in proportion to the success and call-rate ratio.
 * Return the inverse sampling weight used to account a successful scan.
 */
static bool newidle_should_scan(s32 cid, u32 level, u64 now, u32 *weight)
{
	struct newidle_stats __arena *stats = &newidle_stats[cid];
	u32 ratio = stats->ratio[level], sample;

	*weight = 1;
	if (ratio >= 1024)
		return true;

	sample = 1 + ratio;
	if ((bpf_get_prandom_u32() & 1023) > sample) {
		update_newidle_stats(cid, level, 0, now);
		return false;
	}

	*weight = (1024 + sample / 2) / sample;
	return true;
}

/*
 * Decay the level costs of @cctx that have not been raised for a second,
 * and refresh its worst pull from them: sched_balance_domains(), which
 * does this from the tick.
 */
static void newidle_decay(struct cid_ctx __arena *cctx, u64 now)
{
	bool decayed = false;
	u64 sum = 0;
	int i;

	for (i = 0; i < NEWIDLE_LEVELS; i++) {
		if (time_after(now, cctx->newidle_decay_at[i] + NEWIDLE_DECAY_NS)) {
			cctx->newidle_cost[i] = cctx->newidle_cost[i] * 253 / 256;
			cctx->newidle_decay_at[i] = now;
			decayed = true;
		}
		sum += cctx->newidle_cost[i];
	}
	if (decayed)
		cctx->max_idle_balance_cost = MAX(migration_cost_ns, sum);
}

/*
 * Charge a pull that cost @cost to level @level of @cctx,
 * update_newidle_cost().
 */
static void update_newidle_cost(struct cid_ctx __arena *cctx, u32 level,
				u64 cost, u64 now)
{
	if (cost > cctx->newidle_cost[level]) {
		cctx->newidle_cost[level] = cost;
		cctx->newidle_decay_at[level] = now;
	} else if (time_after(now, cctx->newidle_decay_at[level] + NEWIDLE_DECAY_NS)) {
		cctx->newidle_cost[level] = cctx->newidle_cost[level] * 253 / 256;
		cctx->newidle_decay_at[level] = now;
	}
}

/*
 * @cctx leaves idle at @now: fold the period since its pull began into
 * the average, update_rq_avg_idle().
 */
static void update_avg_idle(struct cid_ctx __arena *cctx, u64 now)
{
	u64 idle = now - cctx->idle_stamp;
	u64 max = 2 * cctx->max_idle_balance_cost;

	if (idle > cctx->avg_idle)
		cctx->avg_idle += (idle - cctx->avg_idle) / 8;
	else
		cctx->avg_idle -= (cctx->avg_idle - idle) / 8;
	if (cctx->avg_idle > max)
		cctx->avg_idle = max;
	cctx->idle_stamp = 0;
}

/*
 * Validate and remove the first usable task in a bounded deadline-ordered EDQ
 * prefix. Holding each node across the affinity and hotness checks and
 * removing that exact node prevents a concurrent enqueue from substituting a
 * different task before the steal, giving EDQ the same validate-the-entity
 * semantics as fair's locked detach.
 */
static __noinline enum cid_edq_move_result
cid_edq_move_usable_task_to_local(s32 dst_cid, s32 src_cid, u64 now,
				  bool check_hot)
{
	scx_edq_cursor_t *cursor = &cid_ctx(src_cid)->detach_cursor;
	u32 nth;

	bpf_for(nth, 0, BALANCE_TASK_SCAN) {
		cid_edq_task_t *at;
		struct task_struct *p;
		enum cid_edq_move_result move;
		int ret;

		ret = edq_scan_next(src_cid, cursor, &at);
		if (ret)
			return ret == -EBUSY ? CID_EDQ_MOVE_BUSY :
					      CID_EDQ_MOVE_MISS;
		if (!at) {
			if (!nth)
				cid_queued_check(src_cid);
			break;
		}
		if (READ_ONCE(at->state) != CID_EDQ_ENQUEUED ||
		    (check_hot &&
		     task_hot((task_ctx_t *)at, src_cid, dst_cid, now))) {
			scx_edq_task_drop(&at->common);
			continue;
		}
		p = scx_bpf_tid_to_task(at->tid);
		if (!p || !cid_allowed(p, dst_cid)) {
			scx_edq_task_drop(&at->common);
			continue;
		}
		move = cid_edq_remove_held_to_local(src_cid, dst_cid, at, p);
		if (move != CID_EDQ_MOVE_MISS)
			return move;
	}

	return CID_EDQ_MOVE_MISS;
}

/*
 * Detach one eligible queued task from the selected source. Scan past an
 * affinity-restricted or cache-hot EDQ head, as fair.c's detach_tasks() walks
 * the CFS task list looking for a candidate.
 */
static __noinline u32 detach_one_queued_task(s32 dst_cid, s32 src_cid,
					     u64 now)
{
	scx_edq_cursor_t *cursor = &cid_ctx(src_cid)->detach_cursor;
	bool pinned = false;
	u32 nth;

	TOUCH_ARENA();
	bpf_for(nth, 0, BALANCE_TASK_SCAN) {
		cid_edq_task_t *at;
		enum cid_edq_move_result move;
		struct task_struct *p;
		bool movable;
		int ret;

		ret = edq_scan_next(src_cid, cursor, &at);
		if (ret == -EBUSY)
			break;
		if (ret || !at) {
			if (!nth)
				cid_queued_check(src_cid);
			break;
		}
		p = scx_bpf_tid_to_task(at->tid);
		if (!p || READ_ONCE(at->state) != CID_EDQ_ENQUEUED) {
			scx_edq_task_drop(&at->common);
			continue;
		}
		movable = !is_pcpu_task(p) &&
			  bpf_cpumask_test_cpu(cid_topo(dst_cid)->cpu,
					       p->cpus_ptr);
		if (!movable)
			pinned = true;
		else if (task_hot((task_ctx_t *)at, src_cid, dst_cid, now))
			movable = false;
		if (!movable) {
			scx_edq_task_drop(&at->common);
			continue;
		}
		move = cid_edq_remove_held_to_local(src_cid, dst_cid, at, p);
		if (move == CID_EDQ_MOVE_MOVED) {
			cid_queued_check(src_cid);
			return ACTIVE_BALANCE_MOVED;
		}
		if (move == CID_EDQ_MOVE_BUSY)
			break;
	}
	return pinned ? ACTIVE_BALANCE_PINNED : ACTIVE_BALANCE_MISS;
}

/*
 * Look at the queued cids of @w, word @k rotated by @s (packed in @ks as
 * k << 16 | s), and return the first one with a task @dst_cid can take, or
 * -1, in the low 32 bits, with the number of queues still allowed in the high
 * 32 bits. A bounded deadline-ordered EDQ prefix is held, revalidated and
 * dispatched here. @ctl packs the number of queues to look at and whether a
 * task still hot on its CPU is skipped. A queue found empty has its bit
 * cleared.
 *
 * A global function: it is verified once, not once per call site and
 * loop iteration, which keeps ops.dispatch() within the verifier's
 * budget.
 */
__noinline u64 steal_from_word(s32 dst_cid, u64 w, u32 ks, u64 now, u32 ctl)
{
	u32 k = ks >> 16, s = ks & 63;
	u32 limit = (ctl >> 8) & 0xff;
	bool check_hot = ctl & 1;
	s32 ret = -1;

	TOUCH_ARENA();

	w = rotr64(w, s);
	while (w && limit && can_loop) {
		enum cid_edq_move_result move;
		s32 cid;

		cid = k * 64 + ((__builtin_ctzll(w) + s) & 63);
		w &= w - 1;
		if (cid == dst_cid || !cid_valid(cid))
			continue;
		limit--;

		move = cid_edq_move_usable_task_to_local(dst_cid, cid, now,
						     check_hot);
		if (move == CID_EDQ_MOVE_MOVED) {
			ret = cid;
			break;
		}
		if (move != CID_EDQ_MOVE_BUSY)
			cid_queued_check(cid);
	}

	return ((u64)limit << 32) | (u32)ret;
}

/*
 * Walk the queued cids of [@base, @base + @nr), restricted to tier @t if
 * @t is not negative, starting after @start and wrapping around, and
 * return the first one @dst_cid can steal from, or -1.
 */
static __always_inline s32
steal_from_range(s32 dst_cid, s32 t, u32 base, u32 nr, u32 start, u64 now,
		 bool check_hot, u32 limit)
{
	u32 first = base / 64, last, kstart, i, span;

	if (!nr)
		return -1;
	last = (base + nr - 1) / 64;
	span = last - first + 1;
	if (start < base || start >= base + nr)
		start = base;
	kstart = start / 64;

	bpf_arena_for(i, 0, span) {
		u32 k = first + (kstart - first + i) % span;
		u64 w, ret;
		s32 cid;

		w = cmask_word(queued_cids, k) & cmask_range_word(queued_cids, k, base, nr);
		if (t >= 0)
			w &= place_tier_word(t, k);
		if (!w)
			continue;
		ret = steal_from_word(dst_cid, w, (k << 16) | (i ? 0 : start & 63),
				      now, (limit << 8) | check_hot);
		cid = (s32)(u32)ret;
		limit = ret >> 32;
		if (cid >= 0)
			return cid;
		if (!limit)
			break;
	}

	return -1;
}

/*
 * Dispatch on @dst_cid a task from its own EDQ or from the EDQ of another
 * cid of the node.
 *
 * @has_prev says the CPU still has the task it was running: @prev is
 * runnable and merely off the EDQ while dispatch decides whether to renew
 * its slice. A cid in that state is busy, not idle, and fair.c draws the
 * line in the same place, in pick_task_fair():
 *
 *	if (!cfs_rq->h_nr_queued)
 *		goto idle;
 *	...
 * idle:
 *	new_tasks = sched_balance_newidle(rq, rf);
 *
 * A task whose slice has expired is still on the runqueue, so no newidle
 * balance is run for it. Taking the slice end for an idle CPU here instead
 * ran a full pull once per slice on every CPU, took a task off a neighbour
 * that had no imbalance to correct, and left that neighbour with nothing to
 * run and nothing cold to take back: under `stress-ng -c 0` that alone kept
 * the CPUs at 99.6% busy where fair.c holds every one of them at 100%.
 *
 * A cid with nothing to run pulls the first task it finds: from the slower
 * cids first, once the task is no longer cache-hot on its previous CPU. This
 * carries queued load up the capacity ladder. Asymmetric packing and misfit
 * balancing separately move a running task when fair.c's active-balance
 * conditions are met; this pull path still leaves cache-hot queued tasks
 * alone. A pull onto a faster core is only attempted when the whole core is
 * idle, as a fast thread sharing its core is no better than a whole slow one
 * and asym_smt_can_pull_tasks() refuses that move too; then the cid scans its
 * own LLC, the rest of the node, and finally the rest of the system with
 * the same hot-task check.
 *
 * The check is given up, on the climb as much as on the scans that
 * follow it, once the cid has come back empty from @cache_nice_tries
 * scans in a row with work queued somewhere it could not take: an idle
 * CPU beside a runnable task is worse than a cold cache, and a
 * preference that never yields is a barrier. This is what
 * can_migrate_task() does with sd->nr_balance_failed, and the counter
 * is cleared as soon as a scan finds something, or finds the system
 * genuinely empty.
 *
 * A cid that has work of its own does not pull. Sampling instantaneous
 * queue depths from busy cids moved tasks back and forth under wakeup-heavy
 * load, where fair.c's busy balancer instead acts periodically on averaged
 * load and a computed imbalance.
 *
 * Only the heads are considered, a queue whose head cannot run on @dst_cid
 * (or is still hot there) is skipped as a whole.
 *
 * Return true if a task has been dispatched, false otherwise.
 */
static bool try_steal_task(s32 dst_cid, bool has_prev, bool keep, u64 now,
			   bool kicked)
{
	struct cid_ctx __arena *cctx = cid_ctx(dst_cid);
	struct cid_topo __arena *topo = cid_topo(dst_cid);
	bool own = !keep && cid_queued_test(dst_cid) && cid_queue_nr(dst_cid);
	bool busy = own || has_prev;
	bool force_steal = !busy && READ_ONCE(cctx->force_steal);
	u32 node_base = numa_enabled ? topo->node_base : 0;
	u32 node_nr = numa_enabled ? topo->node_nr : nr_cids;
	u32 failed = cctx->nr_balance_failed;
	bool sample_newidle = newidle_sampling && !force_steal && !kicked;
	bool budget = false, node_skipped = false, system_skipped = false;
	bool scanned = false, admitted;
	u64 curr_cost = 0, t0 = 0;
	u32 weight;
	u32 start;
	s32 src = -1;

	/*
	 * The kick that set this bought one dispatch, and it is spent here
	 * whatever that dispatch finds: the waiter it was sent for is often
	 * taken back by its own cid first, and a permission outliving that
	 * would fire on an unrelated scan later on.
	 */
	if (force_steal)
		WRITE_ONCE(cctx->force_steal, 0);

	/*
	 * A cid that is keeping the task it is running has nothing to pull:
	 * not its own queue, whose head it has just been preferred to, and
	 * not a neighbour's, since anything pulled in would displace it.
	 */
	if (keep)
		goto own;

	if (busy)
		goto own;

	start = cctx->steal_cursor;
	if (start >= nr_cids)
		start = 0;

	/*
	 * sched_balance_newidle(): the idle period is measured from here,
	 * and a cid that has not been staying idle long enough to pay for
	 * a scan of its LLC does not start one, see newidle_cost().
	 *
	 * A cid woken by a balance kick, for a waiter or for an active
	 * balance, is not ending an idle period: fair.c runs the idle
	 * balancer in softirq on the idle task and rq->avg_idle never
	 * hears of it. Stamping here would make the wakeup that does
	 * end the period measure it from the kick, and under a busy
	 * tick that kicks a preferred idle core a hundred times a
	 * second the average collapsed, the budget closed, and the
	 * idle pull stopped: half the steals, 17% off messaging.
	 */
	if (!force_steal && !kicked)
		cctx->idle_stamp = now;
	budget = !no_newidle_cost && !force_steal && !kicked;
	/*
	 * The cost is measured on a fresh clock, sched_clock_cpu() in
	 * sched_balance_newidle(): the rq clock stands still under the
	 * lock and would read every pull as free.
	 */
	if (budget)
		t0 = bpf_ktime_get_ns();
	if (budget && cctx->avg_idle < cctx->newidle_cost[NEWIDLE_LLC]) {
		return false;
	}

	/*
	 * An idle cid walks its own LLC before the rest of the node and then
	 * the system, honouring hotness until it has failed often enough to
	 * stop. With NUMA disabled the node level covers the whole machine.
	 * A domain that is the whole of the next one is not walked twice.
	 */
	admitted = !sample_newidle ||
		newidle_should_scan(dst_cid, NEWIDLE_LLC, now, &weight);
	if (admitted) {
		u64 t1;

		scanned = true;
		if (nr_place_tiers > 1 &&
		    (!smt_enabled || core_is_idle(dst_cid))) {
			u32 t;

			/* Less-preferred tiers first, leaving hot tasks alone. */
			bpf_arena_for(t, 0, nr_place_tiers - topo->place_tier - 1) {
				src = steal_from_range(dst_cid,
						nr_place_tiers - 1 - t,
						node_base, node_nr, node_base,
						now, !force_steal &&
						failed <= cache_nice_tries,
						0xff);
				if (src >= 0)
					break;
			}
		}
		if (src < 0)
			src = steal_from_range(dst_cid, -1, topo->llc_base,
					       topo->llc_nr, start + 1, now,
					       !force_steal &&
					       failed <= cache_nice_tries,
					       0xff);

		t1 = (budget || sample_newidle) ? bpf_ktime_get_ns() : now;
		if (budget) {
			curr_cost = t1 - t0;
			update_newidle_cost(cctx, NEWIDLE_LLC, curr_cost, t1);
			t0 = t1;
		}
		if (sample_newidle)
			update_newidle_stats(dst_cid, NEWIDLE_LLC,
					     src >= 0 ? weight : 0, t1);
	}
	if (budget && node_nr > topo->llc_nr)
		node_skipped = cctx->avg_idle <
			       curr_cost + cctx->newidle_cost[NEWIDLE_NODE];
	if (src < 0 && node_nr > topo->llc_nr && !node_skipped) {
		admitted = !sample_newidle ||
			newidle_should_scan(dst_cid, NEWIDLE_NODE, now, &weight);
		if (admitted) {
			u64 t1, cost;

			scanned = true;
			src = steal_from_range(dst_cid, -1, node_base, node_nr,
					       start + 1, now,
					       !force_steal &&
					       failed <= cache_nice_tries + 1,
					       0xff);
			t1 = (budget || sample_newidle) ? bpf_ktime_get_ns() : now;
			if (budget) {
				cost = t1 - t0;
				curr_cost += cost;
				update_newidle_cost(cctx, NEWIDLE_NODE, cost, t1);
				t0 = t1;
			}
			if (sample_newidle)
				update_newidle_stats(dst_cid, NEWIDLE_NODE,
						     src >= 0 ? weight : 0, t1);
		}
	}
	if (budget && nr_cids > node_nr)
		system_skipped = node_skipped ||
			cctx->avg_idle <
			curr_cost + cctx->newidle_cost[NEWIDLE_SYSTEM];
	if (src < 0 && nr_cids > node_nr && !system_skipped) {
		admitted = !sample_newidle ||
			newidle_should_scan(dst_cid, NEWIDLE_SYSTEM, now, &weight);
		if (admitted) {
			u64 t1, cost;

			scanned = true;
			src = steal_from_range(dst_cid, -1, 0, nr_cids,
					       start + 1, now,
					       !force_steal &&
					       failed <= cache_nice_tries + 2,
					       0xff);
			t1 = (budget || sample_newidle) ? bpf_ktime_get_ns() : now;
			if (budget) {
				cost = t1 - t0;
				curr_cost += cost;
				update_newidle_cost(cctx, NEWIDLE_SYSTEM, cost, t1);
			}
			if (sample_newidle)
				update_newidle_stats(dst_cid, NEWIDLE_SYSTEM,
						     src >= 0 ? weight : 0, t1);
		}
	}
	if (curr_cost > cctx->max_idle_balance_cost)
		cctx->max_idle_balance_cost = curr_cost;

	if (scanned) {
		/* Nothing queued anywhere is a balanced system, not a failure. */
		if (src >= 0 || cmask_empty(queued_cids))
			cctx->nr_balance_failed = 0;
		else
			cctx->nr_balance_failed = failed + 1;
		cctx->steal_cursor = src >= 0 ? src : start + 1;
	}

own:
	if (src < 0 && own)
		src = dst_cid;

	if (src < 0)
		return false;

	/* Remote scans already validated, removed and dispatched one node. */
	if (src == dst_cid) {
		if (!((src == dst_cid && !no_eligible_scan && !no_eligibility) ?
		      move_first_eligible_to_local(src, cid_clock_task_at(src, now), has_prev) :
		      cid_queue_move_head_to_local(src))) {
			cid_queued_check(src);
			return false;
		}
	}
	cid_queued_check(src);

	return true;
}
