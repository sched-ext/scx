/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.
 *
 * The pick, from the two sides that are not ops.dispatch() itself:
 * whether a task that has just woken is worth interrupting the running one
 * for, and when the running one should be asked again.
 *
 *
 * Wakeup preemption
 * -----------------
 *
 * wakeup_preempt_fair() asks what the runqueue would pick now and
 * reschedules when the answer is the task that just woke. Everything it
 * compares has to be available here without a lookup, so each cid
 * publishes what it is running - deadline, vruntime, weight, request, the
 * protected endpoint and when it was last charged - and this reads that,
 * projecting the service taken since the last charge onto both sides of
 * every comparison, which is the update_curr() fair.c does first:
 *
 *   curr is SCHED_IDLE and the wakee is not     -> preempt, and drop the
 *                                                  protection with it
 *   the wakee is SCHED_IDLE or SCHED_BATCH      -> queue it: those give up
 *                                                  latency by definition
 *   the wakee is over-served, v > V             -> queue it: pick_eevdf()
 *                                                  only looks at the
 *                                                  eligible part of the tree
 *   PREEMPT_SHORT: the wakee asks for less      -> preempt
 *   curr is owed service and still protected    -> queue it (RUN_TO_PARITY)
 *   curr is owed service and its deadline is
 *   not later than the wakee's                  -> queue it
 *   the queue's first eligible task has an
 *   earlier deadline than the wakee             -> queue it: the wakee is
 *                                                  not the pick, and
 *                                                  preempting for it would
 *                                                  trade curr for the head
 *                                                  a slice early, once per
 *                                                  wakeup
 *   otherwise                                   -> preempt
 *
 * A wakee that loses still clips curr's protection to one shortest
 * competing request past where curr has reached, update_protect_slice(),
 * and arms the hrtick.
 *
 *
 * The hrtick
 * ----------
 *
 * Without one, a request that ends between two ticks holds the CPU until
 * the next tick, and the task that woke behind it waits that long:
 *
 *   picked                      deadline            next tick
 *     |                            |                    |
 *     v                            v                    v
 *     [------ protected ----------][- over its share --].
 *                                  ^                    ^
 *                                  fair.c reschedules   this scheduler
 *                                  here, from HRTICK    would wait to here
 *
 * Under a saturated schbench that was ~900 us of wakeup latency at the
 * median against a 700 us request. sched_ext has no hrtick, so this is a
 * bpf_timer per cid, armed for the deadline of whatever is running, and
 * only when that task has company - the same condition
 * hrtick_start_fair() applies. When it fires it kicks the CPU, and the
 * dispatch that follows asks keep_running(), which is the pick.
 *
 * Two details are forced by where this runs. Every callback runs with
 * interrupts off, so bpf_timer_start() cannot touch the hrtimer directly:
 * it queues an irq_work, which is a self-IPI per arming, which is why an
 * already-armed timer that fires early enough is left alone rather than
 * moved - under perf bench sched messaging that was 1.5 million armings
 * for 4000 that ever fired. And the timer is not pinned: it queues on
 * whichever CPU arms it, so a waker arming it for another cid does not
 * wake an idle CPU for a deadline that is not its own.
 *
 *
 * yield
 * -----
 *
 * ops.yield() is here too. It charges the yielder the rest of the request
 * it was in the middle of, moving its vruntime to its deadline and
 * reissuing one from there, which is yield_task_fair(): a task that yields
 * in a loop falls behind at exactly the rate its forfeits say. Whether the
 * CPU changes hands is then the pick's decision, not the yield's, so the
 * slice is only ended when the dispatch that follows would not hand the
 * CPU straight back.
 */
#include "eevdf.bpf.h"
#include "preempt.bpf.h"
#include "queue.bpf.h"
#include "task.bpf.h"

/*
 * One hrtick per cid, see hrtick_start(). The map is sized to the cid
 * space by user space before the program is loaded.
 */
struct hrtick {
	struct bpf_timer timer;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, struct hrtick);
	__uint(max_entries, 1);
} hrticks SEC(".maps");

/*
 * Arm @cid's hrtick for the deadline of the task running there, when it
 * has company in the queue, or kick @cid if the deadline has passed.
 *
 * A request is only enforced from task_tick_scx(): a task whose request
 * runs out between two ticks holds the CPU until the next one, up to a
 * whole tick late, and a task that woke behind it and did not win the
 * pick waits that long for its turn. Under a saturated schbench that was
 * a wakeup latency of ~900 us at the median, at a request of 700 us, and
 * shortening the request only buys the tick back at the cost of
 * throughput. fair.c has an hrtimer for exactly this, HRTICK, which
 * set_next_task_fair() arms at every pick for the time the running
 * task's vruntime takes to reach its deadline, whenever it has company,
 *
 *	if (rq->cfs.h_nr_queued <= 1)
 *		return;
 *	vdelta = se->deadline - se->vruntime;
 *	delta = (se->h_load.weight * vdelta) / NICE_0_LOAD;
 *	hrtick_start(rq, delta);
 *
 * and enqueue_task_fair() arms, through hrtick_update(), the moment a
 * task joins a lone runner. When it fires, task_tick_fair() runs
 * update_curr(), which reissues the deadline and asks for a reschedule,
 * and pick_eevdf() decides. A deadline already behind is a reschedule on
 * the spot:
 *
 *	if ((s64)vdelta < 0) {
 *		if (task_current_donor(rq, p))
 *			resched_curr(rq);
 *		return;
 *	}
 *
 * sched_ext has no hrtick, so this is a bpf_timer per cid. It fires at
 * the deadline and kicks the CPU if the cid still has something queued,
 * which is the reschedule; the dispatch that follows asks keep_running(),
 * which is the pick. Every op runs with interrupts off, and from there
 * bpf_timer_start() cannot touch the hrtimer itself: it queues the arming
 * to an irq_work of this CPU, which runs on the way out of the op. That
 * is a self-IPI per arming, and why it is only armed with company, as
 * fair.c does.
 *
 * The timer is not pinned. It queues on the CPU that arms it, this one
 * when the pick does and the waker's when a wakeup does, and an idle CPU
 * hands it to a busy one when it is armed again, so a CPU is not woken
 * for a deadline that is not its own. It cannot be cancelled from an op
 * either, so one left behind by a task that blocked fires once for
 * nothing, and hrtick_fire() finds nothing running and lets it lapse.
 */
static void hrtick_start(s32 cid, u64 tnow)
{
	struct cid_ctx __arena *cctx = cid_ctx(cid);
	struct hrtick *ht;
	u32 key = cid;
	s64 delta;
	u64 now, at;

	if (no_hrtick || !cctx->pack.curr_w)
		return;

	delta = curr_dl_in(&cctx->pack, tnow);
	if (!delta) {
		scx_bpf_kick_cid(cid, SCX_KICK_PREEMPT);
		return;
	}
	if (delta < HRTICK_MIN_NS)
		delta = HRTICK_MIN_NS;

	/*
	 * The distance is in the task clock. The timer is armed relative
	 * to now; @at, the rq clock it fires at through the offset
	 * ops.stopping() last sampled, is what the check below compares.
	 */
	now = tnow + cctx->clock_off;
	at = now + delta;
	/*
	 * The due time is taken on the rq clock itself: the offset is only
	 * sampled when a task stops, and with IRQ time accounted apart it can
	 * be milliseconds stale by now.
	 */
	cctx->hrtick_due = scx_bpf_now() + delta;
	cctx->hrtick_run_at = cctx->pack.curr_run_at;

	/*
	 * A timer still pending for no later than this is left alone: it
	 * fires early for this task and hrtick_fire() arms it again for the
	 * deadline from there, where that costs nothing. Moving it from here
	 * is an irq_work and a self-IPI every time, and under perf bench
	 * sched messaging that was one per context switch, 1.5 million of
	 * them for 4000 that ever fired.
	 */
	if (time_before(now, cctx->hrtick_at) &&
	    !time_after(cctx->hrtick_at, at + HRTICK_MIN_NS))
		return;

	ht = bpf_map_lookup_elem(&hrticks, &key);
	if (!ht)
		return;

	cctx->hrtick_at = at;
	bpf_timer_start(&ht->timer, delta, 0);
}

/*
 * @cid's hrtick fired. Ask the running task to give the CPU up if it has
 * company and its hrtick is due, hrtick() in core.c:
 *
 *	rq->donor->sched_class->task_tick(rq, rq->donor, 1);
 *
 * The timer was armed for the deadline of whatever was running when it
 * was armed, or earlier, see hrtick_start(). If it is early for the run it
 * was armed for, or the cid has since picked something else whose deadline
 * is still ahead, arm it again for that, which can be done from here
 * directly, interrupts being on.
 */
static int hrtick_fire(void *map, int *key, struct hrtick *ht)
{
	struct cid_ctx __arena *cctx;
	s32 cid = *key;
	s64 delta;
	u64 now;

	TOUCH_ARENA();

	if (!cid_valid(cid))
		return 0;

	cctx = cid_ctx(cid);
	if (!cctx->pack.curr_w || !cid_queued_test(cid))
		return 0;

	now = scx_bpf_now();

	/*
	 * The due time stands for the run it was armed for: that run is asked
	 * to reschedule when it comes, whatever its task clock reads by then,
	 * as entity_tick() does for a queued tick. A timer left from another
	 * run, which fair.c would have cancelled at the switch, measures the
	 * running task's own distance to its deadline instead.
	 */
	if (cctx->hrtick_run_at == cctx->pack.curr_run_at)
		delta = (s64)(cctx->hrtick_due - now);
	else
		delta = curr_dl_in(&cctx->pack, now - cctx->clock_off);
	if (delta > (s64)HRTICK_MIN_NS) {
		cctx->hrtick_at = now + delta;
		bpf_timer_start(&ht->timer, delta, 0);
		return 0;
	}

	scx_bpf_kick_cid(cid, SCX_KICK_PREEMPT);
	return 0;
}

/*
 * Prepare to queue the task of @tctx on @cid with deadline @dl, and return
 * whether it should be inserted on the local DSQ as a preempting task.
 *
 * An idle cid needs nothing from here. The task is being enqueued on that
 * very cid, and once ops.enqueue() returns the kernel asks wakeup_preempt()
 * for it, which reschedules an idle CPU for any class above the idle one
 * before it looks at what the class itself would do. A kick from here made
 * the same request again through an irq_work of the waker, which took the
 * target's rq lock a second time; with many wakers filling the same CPUs
 * that lock was the busiest line of the wakeup path. A busy cid is running
 * a task of its own, and what this has to decide is whether that task
 * should be interrupted.
 *
 * This is EEVDF's wakeup preemption. wakeup_preempt_fair() asks what the
 * runqueue would pick now and reschedules when the answer is the task
 * that just woke. When the two tasks ask for the same slice, that pick
 * comes down to what pick_eevdf() opens with:
 *
 *	if (curr && (!curr->on_rq || !entity_eligible(cfs_rq, curr)))
 *		curr = NULL;
 *	if (curr && protect && protect_slice(curr))
 *		return curr;
 *
 * plus the queued task being eligible itself and holding the earlier
 * deadline, which is what makes it the pick. set_protect_slice() gives the
 * running task an explicit virtual-time protection bounded by the shortest
 * request in the queue. A normal wakeup that does not win the pick clips the
 * endpoint again through update_protect_slice(), including the new wakee's
 * request even though it has not entered the EDQ yet. The EDQ's augmented
 * minimum makes both operations constant time.
 *
 * Eligibility still comes first: once the current entity has been served
 * past the average of its pack, pick_eevdf() drops it before testing its
 * protection. PREEMPT_SHORT does the inverse for an eligible shorter wakee:
 * it cancels the endpoint before requesting preemption. What the running
 * task gives up is protected service, not its place in the order; it keeps
 * the deadline it was picked with, see task_dl().
 *
 * Nothing here reads a reference that is behind: the service the running
 * task has taken since it was picked is folded into both sides of every
 * comparison, see pack_vref_at() and curr_owed_service(), the way
 * wakeup_preempt_fair() calls update_curr_fair() before deciding
 * anything.
 *
 * All of it compares because all of it is in @cid's virtual time: the
 * running task joined that reference in ops.running() and the wakee was
 * placed against it just above. Two cids' references do not compare, which
 * is why the only cid this looks at is the one the task will be queued on.
 *
 * Before any of that, the policies. wakeup_preempt_fair() settles a
 * SCHED_IDLE task on either side without looking at the virtual times:
 *
 *	if (cse_is_idle && !pse_is_idle)
 *		goto preempt;
 *	update_curr_fair(rq);
 *	if (cse_is_idle != pse_is_idle)
 *		goto update;
 *	if (unlikely(!normal_policy(p->policy)))
 *		goto update;
 *
 * A SCHED_IDLE task is interrupted for any task that is not one, before
 * anything is asked about eligibility or deadlines, and a SCHED_IDLE or
 * SCHED_BATCH task never interrupts anything: both are policies for work
 * that gives up latency, not for work that is served less. What the
 * weight of 3 already does for a SCHED_IDLE task is to be interrupted
 * almost at once, since it is owed almost nothing, and to be queued
 * behind everything else; the policy rule is what keeps it from being
 * kicked for at all, and takes the running one off the CPU without
 * waiting for the tick to find it.
 *
 * The @curr_ fields describe the last task of ours to run there and say
 * nothing about a cid running something else. A zero @curr_w covers both
 * the idle task and a higher class: nothing of ours is running, so there
 * is nothing to interrupt and nothing to protect. It is read from the pack
 * line this needs anyway, not from the idle bitmap, a word that every CPU
 * writes on each of its idle transitions and that a remote reader misses
 * on nearly every time.
 */
static bool queued_cid_should_preempt(s32 cid, const struct task_struct *p,
				      const task_ctx_t *tctx, u64 dl,
				      u64 now, bool *cancel_protect)
{
	struct cid_ctx __arena *cctx;
	bool owed, p_idle, has_head;
	u64 head_dl, min_slice = 0;
	pack_t *pk;

	*cancel_protect = false;
	cctx = cid_ctx(cid);
	pk = task_pack(tctx, cid);
	if (!pk->curr_w)
		goto idle;

	if (no_wakeup_preempt)
		goto queued;

	/*
	 * A SCHED_IDLE task running is interrupted for anything else, and a
	 * SCHED_IDLE or SCHED_BATCH task queued interrupts nothing. The three
	 * tests above collapse to these two: once the first has taken the
	 * idle curr with a non-idle wakee, what the second and third turn
	 * away between them is any wakee that is not of a normal policy.
	 */
	p_idle = p->policy == SCHED_IDLE;
	if (cctx->curr_idle && !p_idle) {
		*cancel_protect = true;
		goto preempt;
	}
	if (p_idle || p->policy == SCHED_BATCH)
		goto queued;

	/*
	 * Take the eligible head and the queue's shortest request under the
	 * same EDQ lock. Even when the current entity keeps the CPU, the latter
	 * is needed to apply update_protect_slice().
	 */
	has_head = pack_pick_head_dl(pk, now, &head_dl, &min_slice);

	/*
	 * The queued task has to be owed service to be a candidate at all:
	 * pick_eevdf() only ever looks at the eligible part of the tree.
	 */
	if (!no_eligibility &&
	    time_after(tctx->se.vruntime, pack_vref_place(pk, now)))
		goto update;

	/*
	 * PREEMPT_SHORT lets an eligible task with a shorter request override
	 * the running task's protection. fair.c makes it the short buddy so it
	 * is selected next even when another task has an earlier deadline. The
	 * local-DSQ insertion made after this returns is the same one-shot
	 * override when that DSQ is available: it runs before the
	 * deadline-ordered per-cid EDQ. An existing local waiter is not
	 * displaced because the built-in DSQ is FIFO-only; that waiter already
	 * requested rescheduling and the new wakee retains deadline order on
	 * the per-cid EDQ.
	 *
	 * Both requests are already cached. task_dl() recorded the wakee's in
	 * @tctx, and ops.running() or keep_charge() published the current one.
	 * Equal default requests therefore add only this comparison and branch
	 * to the existing wakeup path.
	 */
	if (!no_preempt_short && tctx->se.request < pk->curr_request &&
	    pk->curr_w) {
		*cancel_protect = true;
		goto preempt;
	}

	/*
	 * Is the running task still owed service? Once it has run for a
	 * whole request it is past its deadline as well, and either way it
	 * has no protection left. This is the half of the pick that
	 * RUN_TO_PARITY governed, and --no-run-to-parity drops it alone.
	 */
	owed = !no_eligibility && curr_owed_service(pk, now);
	if (owed && !no_run_to_parity &&
	    time_before(curr_vruntime_at(pk, now), pk->curr_vprot))
		goto update;

	/*
	 * Only a curr that is still owed service is in the running at all:
	 *
	 *	if (curr && (!curr->on_rq || !entity_eligible(cfs_rq, curr)))
	 *		curr = NULL;
	 *
	 * pick_eevdf() drops it before it looks at the tree, so a curr that
	 * has had its share loses to the queued task whatever the deadlines
	 * say. --no-eligibility keeps deciding on the deadlines alone.
	 */
	if ((owed || no_eligibility) && !time_before(dl, pk->curr_dl))
		goto update;

	/*
	 * The task is only worth interrupting the CPU for if it is what the
	 * CPU would run next. wakeup_preempt_fair() preempts for the woken
	 * task alone,
	 *
	 *	nse = pick_next_entity(rq, ...);
	 *	if (nse == pse)
	 *		goto preempt;
	 *
	 * and a curr that has lost the pick to some other queued task is
	 * left running until its slice ends, or until a wakeup that does win
	 * it. The next pick is the earliest deadline among the queued tasks that
	 * are eligible, see pack_pick_head_dl(), so the woken task must have a
	 * strictly earlier deadline than that one. An ineligible task with an
	 * earlier deadline is skipped, as pick_eevdf() skips it. A task already
	 * queued is not displaced by one that ties it.
	 * A preemption for a task that queues behind others only trades the
	 * running task for the head a slice early, once for
	 * every wakeup that lands in the queue: with sixteen tasks queued per
	 * CPU that was one context switch in three, and perf bench sched
	 * messaging ran at half its speed.
	 */
	if (has_head) {
		bool loses = !time_before(dl, head_dl);

		if (loses)
			goto update;
	}

preempt:
	return true;
update:
	update_protect_slice(pk, now, tctx->se.request, min_slice);
queued:
	/*
	 * The task waits behind the running one. See that the running one
	 * is asked again when its deadline comes rather than at the tick
	 * after it, hrtick_update():
	 *
	 *	hrtick_start_fair(rq, donor);
	 */
	hrtick_start(cid, now);
idle:
	return false;
}

/*
 * @from gives up the CPU, sched_yield().
 *
 * This is yield_task_fair():
 *
 *	if (unlikely(rq->nr_running == 1))
 *		return;
 *	...
 *	update_curr(cfs_rq);
 *	...
 *	if (entity_eligible(cfs_rq, se)) {
 *		se->vruntime = se->deadline;
 *		update_deadline(cfs_rq, se);
 *	}
 *
 * What a yield costs is the rest of the request the task is in the middle
 * of. Its vruntime is moved up to the deadline it was issued, as if it had
 * run the whole of it, and a deadline is reissued from there. That puts it
 * behind the pack it is in rather than at the back of the queue or nowhere
 * at all: a task that yields in a loop is charged for every request it
 * does not use and falls behind at exactly the rate that says so, and one
 * that yields once has given up one turn.
 *
 * fair.c guards the forfeit with the eligibility test and says why: under
 * core scheduling an ineligible task can be picked, and one that yields
 * every time it is picked would run its vruntime away. The same guard is
 * kept here for the same reason.
 *
 * Whether the CPU changes hands is then the pick's decision, not the
 * yield's: yield_task_fair() ends in schedule(), and pick_eevdf() hands
 * the CPU back to the yielder when, forfeit and all, it is still the
 * eligible task with the earliest deadline. Without this op the kernel
 * zeroes the slice,
 *
 *	if (SCX_HAS_OP(sch, yield))
 *		SCX_CALL_OP_2TASKS_RET(sch, yield, rq, p, NULL);
 *	else
 *		scx_set_task_slice(p, 0);
 *
 * so installing one takes that over, and the slice is ended only when
 * the dispatch would not keep the task, which is the same question
 * keep_running() answers there: a task that would be handed straight
 * back keeps its slice and the schedule() picks it on the cheap path,
 * where a forced slice end cost it a full dispatch for nothing. A task
 * on the local DSQ has already won a preemption and is the pick.
 * yield_task_scx() has already called scx_task_slice_ended(), which
 * drops the %SCX_TASK_PROTECTED that would otherwise refuse the write.
 *
 * @to is a directed yield, yield_to(), and it is refused. fair.c honours
 * one with set_next_buddy(), which pick_next_entity() reads under
 * PICK_BUDDY; there is no buddy here and nothing that would read one.
 * Charging the caller a request for a request that will not be honoured
 * buys nothing, so a directed yield does nothing at all - yield_to() reads
 * false as "not implemented" and skips even the schedule() it would
 * otherwise make, leaving the caller free to try another target.
 */
bool BPF_STRUCT_OPS(eevdf_yield, struct task_struct *from,
		    struct task_struct *to)
{
	s32 cid = scx_bpf_this_cid();
	task_ctx_t *tctx;
	u64 now, tnow;

	TOUCH_ARENA();

	if (to || !cid_valid(cid))
		return false;

	/*
	 * Nothing else can run here, so there is nobody the forfeit would
	 * hand the CPU to. This is fair.c's rq->nr_running == 1:
	 *
	 *	if (unlikely(rq->nr_running == 1))
	 *		return;
	 *
	 * and like it this returns before anything else, the slice included:
	 * the schedule() a yield ends in then picks the same task back on the
	 * cheap path. It also has to be about as cheap as fair.c's one load,
	 * since a task that yields in a loop asks this millions of times a
	 * second: the queued bitmap is that load, where a pair of DSQ queries
	 * halved the yield rate of a task running alone. A task on the local
	 * DSQ is not covered; it is the run-now fast path and is drained at
	 * the next dispatch, a slice end away at most.
	 */
	if (!cid_queued_test(cid) && !scx_bpf_dsq_nr_queued(SCX_DSQ_LOCAL))
		return false;

	tctx = try_lookup_task_ctx(from);
	if (!tctx)
		return false;

	/*
	 * update_curr(), which leaves a deadline ahead of the vruntime
	 * whether or not the one it was issued has been consumed, and the
	 * cid's published view of what it is running up to date with both.
	 * The reference read below is then exact rather than projected.
	 */
	now = scx_bpf_now();
	tnow = cid_clock_task_owned(cid, now);
	keep_charge(from, cid, tnow);

	if (time_after(tctx->se.vruntime,
		       pack_vref_place(task_pack(tctx, cid), tnow)))
		goto pick;

	tctx->se.vruntime = tctx->se.deadline;

	/*
	 * The jump is service as far as the pack is concerned, the way
	 * avg_vruntime() folds curr in at whatever vruntime it is carrying,
	 * and it is a consumed request as far as the deadline is concerned.
	 * Both are what this second settle-up is for.
	 */
	keep_charge(from, cid, tnow);

pick:
	/*
	 * pick_eevdf(): the yielder keeps the CPU only if it is still the
	 * eligible task with the earliest deadline, see keep_running().
	 */
	if (scx_bpf_dsq_nr_queued(SCX_DSQ_LOCAL) || !keep_running(cid, tnow))
		scx_bpf_task_set_slice(from, 0);

	return false;
}
