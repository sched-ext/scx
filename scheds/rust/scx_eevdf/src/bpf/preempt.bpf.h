/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.
 *
 * The pick: whether the task running on a cid keeps it, and what the
 * protection it was given still covers. The hrtick that ends a request on
 * time, the wakeup preemption test and ops.yield() are in preempt.bpf.c.
 */
#pragma once

#include "eevdf.bpf.h"
#include "queue.bpf.h"
#include "task.bpf.h"

/*
 * A wakeup which does not win the pick can still shorten the current
 * entity's protection. fair.c does this after pick_next_entity() returns a
 * different entity: vprot never moves forward, and is clipped to one minimum
 * competing request beyond the current vruntime.
 */
static void update_protect_slice(pack_t *pk, u64 now, u64 wakee_slice,
				 u64 queued_min_slice)
{
	u64 slice = MIN(pk->curr_request, wakee_slice);
	u64 vprot;

	if (no_run_to_parity || no_eligibility || !pk->curr_w)
		return;
	if (queued_min_slice && queued_min_slice < slice)
		slice = queued_min_slice;
	vprot = curr_vruntime_at(pk, now) +
		slice * NICE_0_WEIGHT / pk->curr_w;
	shorten_protect_slice(pk, vprot);
}

static void cancel_protect_slice(pack_t *pk, u64 now)
{
	if (pk->curr_w)
		shorten_protect_slice(pk, curr_vruntime_at(pk, now));
}

/*
 * Shortest an hrtick is armed for, the floor hrtick_start() in core.c
 * applies to its own:
 *
 *	delta = max_t(s64, delay, 10000LL);
 */
#define HRTICK_MIN_NS	10000ULL

/*
 * Wall-clock time the entity running in @pk needs to reach its deadline,
 * read off @pk's published view of it, or 0 if it is there already or
 * nothing is running.
 *
 * The view is read without a lock, from other cids too, and can be of a
 * task picked after @now was taken: that task has consumed nothing yet.
 */
static s64 curr_dl_in(pack_t *pk, u64 now)
{
	u64 w = pk->curr_w, run_at = pk->curr_run_at, v;
	s64 vdelta;

	if (!w)
		return 0;

	if (time_before(now, run_at))
		now = run_at;
	v = pk->curr_v + (now - run_at) * NICE_0_WEIGHT / w;
	vdelta = (s64)(pk->curr_dl - v);
	if (vdelta <= 0)
		return 0;

	return (u64)vdelta * w / NICE_0_WEIGHT;
}

/*
 * Longest a task may hold a CPU across the end of its slice before the
 * queue gets its turn whatever the deadlines say, see keep_running().
 *
 * The share a weight buys is charged in the vruntime and is untouched by
 * this: what it bounds is how long the task at the back of the queue can
 * wait. fair.c lets that run to whatever the weights ask for, and a nice
 * -20 task against a nice 19 one asks for a ratio of 5917, four seconds
 * of one holding the CPU at the default slice. sched_ext does not have
 * that much room: ops.timeout_ms ends the scheduler when a runnable task
 * has not run for as long, and it does so before the ratio is served.
 * Every nice pair inside a factor of a hundred and forty is exact at the
 * default slice; past that the interleaving is forced finer than fair.c
 * would make it, which costs the light task nothing.
 */
#define KEEP_RUNNING_MAX_NS	100000000ULL

/*
 * The deadline the entity running in @pk would be picked again with at @now,
 * or false when it is not in the pick at all.
 */
static bool curr_pick_dl(pack_t *pk, u64 now, u64 *dlp)
{
	u64 w, v, dl;

	w = pk->curr_w;
	if (!w)
		return false;

	if (now - pk->curr_since >= KEEP_RUNNING_MAX_NS)
		return false;

	v = pk->curr_v + (now - pk->curr_run_at) * NICE_0_WEIGHT / w;

	/*
	 * A task that has had more than its share is not in the pick at all,
	 * whatever its deadline: pick_eevdf() drops it before it looks at
	 * the tree,
	 *
	 *	if (curr && (!curr->on_rq || !entity_eligible(cfs_rq, curr)))
	 *		curr = NULL;
	 *
	 * and this is the same test kick_queued_cid() applies when a task
	 * wakes against it. Applied here too, the two agree: a task kicked
	 * off the CPU for being over-served was kept by the dispatch that
	 * followed whenever its deadline happened to be the earlier one,
	 * and got a whole new slice out of it. A probe waking next to a hog
	 * waited 1.6 ms for that on one wakeup in four, 0.3 ms under fair.c.
	 */
	if (!no_eligibility && time_after(v, pack_vref_at(pk, now)))
		return false;

	/*
	 * A deadline stands until the request it was issued for is consumed,
	 * see task_dl(); past that it is reissued from where the vruntime
	 * has reached, which is what puts a task that has had its turn behind
	 * the ones that have not.
	 */
	dl = pk->curr_dl;
	if (!dl || !time_before(v, dl)) {
		if (w < MIN_DL_WEIGHT)
			w = MIN_DL_WEIGHT;
		dl = v + pk->curr_request * NICE_0_WEIGHT / w;
	}

	*dlp = dl;
	return true;
}

/*
 * The deadline of the task @pk would pick from its queue at @now, the
 * earliest one among those eligible, which is what pick_eevdf() searches
 * the tree for:
 *
 *	if (left && vruntime_eligible(cfs_rq,
 *				__node_2_se(left)->min_vruntime)) {
 *		node = left;
 *		continue;
 *	}
 *	se = __node_2_se(node);
 *	if (entity_eligible(cfs_rq, se)) {
 *		best = se;
 *		break;
 *	}
 *
 * or false when nothing queued is eligible. Take the exact eligible pick and
 * minimum slice when the EDQ lock is immediately available. A remote balance
 * operation can hold the independent EDQ lock while this callback owns the
 * runqueue; do not spin behind it. Fall back to the lockless queue head and
 * cached minimum instead. The head can be ineligible, which conservatively
 * suppresses a preemption rather than letting a wakee bypass queued work.
 */
static bool pack_pick_head_dl(pack_t *pk, u64 now, u64 *dlp,
			      u64 *min_slice)
{
	int ret;

	if (no_eligible_scan || no_eligibility) {
		*min_slice = 0;
		return !scx_edq_first_deadline(&pk->edq, dlp);
	}

	ret = scx_edq_try_first_eligible_deadline(&pk->edq,
						pack_vref_place(pk, now), dlp,
						min_slice);
	if (ret == -EBUSY) {
		scx_edq_min_slice(&pk->edq, min_slice);
		return !scx_edq_first_deadline(&pk->edq, dlp);
	}

	return !ret;
}

/*
 * Does the task running on @cid keep it, rather than hand it to the head
 * of @cid's queue?
 *
 * fair.c asks this at every pick. pick_next_task_fair() calls
 * pick_next_entity(), which runs pick_eevdf() over the queued entities
 * *and* curr, so a task whose slice has just ended goes on running
 * whenever nothing queued has an earlier deadline. A slice bounds how
 * long a task may hold a CPU without being asked again; it is not a turn
 * it has to give up at the end of.
 *
 * Without the question there is no answer to give. A dispatch that always
 * takes the head hands the CPU over in strict rotation, and the weights
 * stop meaning anything wherever the queue holds a single task - which is
 * every CPU running two runnable tasks, the shape a build next to a video
 * call has. A nice 0 and a nice 6 task pinned together measured 1.02 to
 * one where fair.c gives 3.76, and cpu.weight fared the same. Queue a
 * third task and the deadline order picks among them and the ratios come
 * out right, which is how this went unnoticed.
 *
 * The comparison is the one ops.stopping() and task_dl() would reach a
 * moment later, taken from @cid's published view of what it is running so
 * that nothing has to be looked up to decide: the service taken since it
 * was last charged, charged at its weight, is the vruntime it is about to
 * carry, and a request that vruntime has consumed is a deadline about to
 * be reissued from there.
 */
static bool keep_running(s32 cid, u64 now)
{
	pack_t *pk = cid_pack(cid);
	u64 dl, head_dl, min_slice;

	if (!curr_pick_dl(pk, now, &dl))
		return false;

	/*
	 * Only now the head: the queue lookup is the expensive step, and a
	 * yielder that has just forfeited its request fails the test above.
	 *
	 * Nothing queued here to be preferred to. Say so rather than keep
	 * the task: the queued bitmap is the only thing consulted, and the
	 * dispatch that follows has a lookup of the EDQ itself to fall back
	 * on for the races the bitmap loses.
	 */
	if (!cid_queued_test(cid))
		return false;
	/* Nothing queued is eligible: pick_eevdf() returns curr. */
	if (!pack_pick_head_dl(pk, now, &head_dl, &min_slice))
		return true;

	/* A tie is kept: giving the CPU up costs a switch. */
	return !time_after(dl, head_dl);
}
