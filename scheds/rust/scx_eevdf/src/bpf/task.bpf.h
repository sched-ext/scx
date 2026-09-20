/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.
 *
 * EEVDF itself: what a task weighs, what it is owed, where it is placed
 * and what it is charged. All of it runs on the switch and wakeup paths,
 * several times each. The callbacks that drive it are in task.bpf.c.
 */
#pragma once

#include "eevdf.bpf.h"
#include "cgroup.bpf.h"
#include "latency.bpf.h"
#include "queue.bpf.h"

/*
 * Return the weight the kernel gives @p, on the kernel's own scale.
 *
 * Not @p->scx.weight: that is this weight put through
 * sched_weight_to_cgroup(),
 *
 *	clamp(DIV_ROUND_CLOSEST(weight * 100, 1024), 1, 10000)
 *
 * which is coarse at the light end. A nice 19 task weighs 15, that is 1.46
 * on the cgroup scale, and comes out as 1. Charging the vruntime against
 * that makes it pay 100x the service it used where calc_delta_fair()
 * charges 1024/15 = 68x, so it waits half again as long as EEVDF asks
 * before its pack catches up - long enough, under a deep backlog, to turn
 * a fair-share wait into an ops.timeout_ms stall. SCHED_IDLE fares worse:
 * its weight of 3 rounds to 0 and is clamped back up to 1, so it is
 * charged the same as nice 19.
 *
 * @p->se.load.weight is not the answer either, even though set_load_weight()
 * fills it from this same table: for a task in the sched_ext class the
 * store goes through reweight_task_scx(), which derives @p->scx.weight from
 * the new load weight and drops it, leaving @p->se.load holding whatever
 * the fair class last left there. Go back to the table.
 *
 * A task in a cgroup weighs its nice weight against the other members of its
 * group on the cid, and what EEVDF charges and orders it by is its share of
 * the whole hierarchy, cached in @tctx, see task_h_refresh().
 */
static u64 task_nice_weight(const struct task_struct *p)
{
	u32 idx;

	if (p->policy == SCHED_IDLE)
		return WEIGHT_IDLEPRIO;

	idx = p->static_prio - MAX_RT_PRIO;
	return idx < ARRAY_SIZE(prio_to_weight) ? prio_to_weight[idx] :
						   NICE_0_WEIGHT;
}

static u64 task_weight(const struct task_struct *p, const task_ctx_t *tctx)
{
	if (tctx && tctx->grp && tctx->se.vw)
		return tctx->se.vw;

	return task_nice_weight(p);
}

/*
 * Charge @delta of service to a task of @p's weight, the way
 * calc_delta_fair() does:
 *
 *	delta_fair = delta * NICE_0_LOAD / se->load.weight
 */
static u64 calc_delta_fair(const struct task_struct *p,
			   const task_ctx_t *tctx, u64 delta)
{
	return delta * NICE_0_WEIGHT / task_weight(p, tctx);
}

/*
 * Floor on the weight used to stretch the request and the lag bound.
 *
 * A nice 19 task has a weight of 15, so its request would be sixty eight
 * times the base slice and the lag it can carry a hundred and thirty six
 * times: under a deep backlog V takes many seconds to cover that, well
 * past the watchdog. The vruntime is still charged with the real weight,
 * so the share is what nice asks for; only how far ahead the deadline and
 * the lag can stretch is capped, which update_deadline() itself notes is
 * "probably good enough".
 */
#define MIN_DL_WEIGHT	(NICE_0_WEIGHT / 4)

static u64 scale_by_dl_weight(const struct task_struct *p,
			      const task_ctx_t *tctx, u64 value)
{
	u64 weight = task_weight(p, tctx);

	if (weight < MIN_DL_WEIGHT)
		weight = MIN_DL_WEIGHT;

	return value * NICE_0_WEIGHT / weight;
}

/*
 * Bound on the lag a task can carry, in virtual time. This is the one
 * entity_lag() clamps to:
 *
 *	u64 max_slice = cfs_rq_max_slice(cfs_rq) + TICK_NSEC;
 *	limit = calc_delta_fair(max_slice, se);
 *	return clamp(vlag, -limit, limit);
 *
 * EEVDF's steady state bound, -r_max < lag < max(r_max, q), where r_max
 * is the largest request on the queue and q the timing granularity.
 *
 * cfs_rq_max_slice() walks the queue for that largest request; there is
 * no equivalent to walk here, so the largest of this task's own and the
 * default stands in for it. The two agree unless some other task on the
 * cid asked for more than the default, in which case the bound is the
 * tighter of the two, which errs the safe way.
 */
static u64 task_request(const struct task_struct *p);

static u64 lag_limit(const struct task_struct *p, const task_ctx_t *tctx)
{
	u64 request = task_request(p);

	if (request < slice_ns)
		request = slice_ns;

	return scale_by_dl_weight(p, tctx, request + tick_ns);
}

/*
 * Return the task's effective request. sched_runtime is the request hint for
 * fair policies, including SCHED_EXT; zero leaves scx_eevdf's default in force.
 */
static u64 task_request(const struct task_struct *p)
{
	return p->se.custom_slice ? p->se.slice : slice_ns;
}

/*
 * Calculate and return the virtual deadline for the given task.
 *
 * This is EEVDF's virtual deadline, see update_deadline():
 *
 *	vd_i = ve_i + r_i / w_i
 *
 * The request size r_i is @slice_ns by default, like sysctl_sched_base_slice,
 * and a task can override it with sched_attr.sched_runtime. The weight does
 * not buy a task a longer time slice, it buys it an earlier deadline, so it
 * runs more often instead of running longer.
 *
 * The deadline is the EDQ key and nothing else. The vruntime is stored
 * separately in task_ctx.vruntime and copied into the EDQ augmentation.
 *
 * pick_eevdf() considers only the eligible tasks, v_i <= V, and picks the
 * earliest deadline among them. The EDQ subtree augmentation applies that
 * filter at dispatch without changing the deadline key.
 *
 * The deadline stands until the request it was issued for is consumed,
 * which is the test update_deadline() opens with:
 *
 *	if ((s64)(se->vruntime - se->deadline) < 0)
 *		return;
 *
 * A task queued again without having run for its whole request keeps the
 * deadline it was queued with, instead of being pushed a full request
 * further back for the fraction it did get.
 *
 * A re-placed vruntime takes the deadline with it, see set_vruntime(): a
 * deadline is a position in the virtual time of one cid and the packs
 * drift apart, so what is carried is its distance from the vruntime, not
 * the value, and only for a task that did not sleep.
 */
static u64 task_dl(const struct task_struct *p, task_ctx_t *tctx)
{
	u64 request = task_request(p);

	/*
	 * sched_setattr() can change a runnable task's request between two
	 * enqueues. A deadline belongs to the request that created it, so do
	 * not carry one calculated from the old request into the new one.
	 */
	if (tctx->se.request != request) {
		tctx->se.request = request;
		tctx->se.deadline = 0;
	}

	if (tctx->se.deadline && time_before(tctx->se.vruntime, tctx->se.deadline))
		return tctx->se.deadline;

	/*
	 * A task that has just been forked asks for half a request the
	 * first time, which is PLACE_DEADLINE_INITIAL:
	 *
	 *	if (sched_feat(PLACE_DEADLINE_INITIAL) && (flags & ENQUEUE_INITIAL))
	 *		vslice /= 2;
	 *
	 * The tasks it is joining are on average halfway through requests
	 * of their own, so a whole one puts it behind all of them and it
	 * waits out the competition before it has run at all. Half a
	 * request is the average of what they have left, which is what
	 * joining in the middle should cost. It buys no extra service: the
	 * deadline is where the task sits in the order, the vruntime is
	 * what it is charged, and only the first one is halved.
	 */
	if (tctx->initial) {
		tctx->initial = false;
		request /= 2;
	}

	tctx->se.deadline = tctx->se.vruntime + scale_by_dl_weight(p, tctx, request);

	return tctx->se.deadline;
}

/*
 * Per-cid vruntime reference.
 *
 * With one deadline queue per CPU, each queue is a pack of tasks that
 * advance in lockstep, and the packs drift apart from the system-wide V
 * with their load: a CPU running nine hogs accrues vruntime slower than
 * one running six, and slower than V, which follows the average. A task
 * placed at V minus its lag then lands behind the whole pack of a crowded
 * CPU and waits for the pack to climb past it, or ahead of everything on a
 * lightly loaded one. EEVDF's reference is per runqueue for that reason:
 * the weighted average of the tasks queued there, kept incrementally,
 *
 *	V = \Sum (w_i * v_i) / \Sum w_i
 *
 * and a task is placed against the runqueue it joins with the lag it took
 * from the one it left, which is also how a migration keeps its fairness.
 *
 * Do the same per cid: a task joins the cid it is queued on or runs on,
 * leaves it when it stops being runnable, and its contribution follows
 * the vruntime it is charged in ops.stopping().
 *
 * Keep V itself rather than the two sums it is the quotient of. A cfs_rq
 * divides \Sum w_i*v_i by \Sum w_i under its rq lock and always gets a
 * pair that belongs together; here the words are updated by whichever CPU
 * the task is on, so a reader can take one from either side of a join and
 * divide sums that never coexisted. The miss is the joining weight over
 * the old total, which a nice -20 task landing on a pack of one nice 19
 * task inflates by almost six thousand, and the result is not merely read
 * but assigned as a task's vruntime in place_task().
 *
 * So move V by the exact increment each event is worth, and let a reader
 * take it in a single load, which cannot tear:
 *
 *	join    V' = (W*V + w_i*v_i) / (W + w_i) = V + w_i*(v_i - V)/(W + w_i)
 *	leave   V' = (W*V - w_i*v_i) / (W - w_i) = V + w_i*(V - v_i)/(W - w_i)
 *	charge  dV = w_i * dv_i / W
 *
 * The W each increment divides by is read without a lock too, but a stale
 * W only scales a bounded increment slightly wrong, where a stale divisor
 * under a quotient produced a number with no relation to the pack.
 *
 * The last member out divides by nothing and leaves V where it stands,
 * which is what an empty pack wants: the clock of an idle cid stops,
 * nothing is served there so nothing is owed there, and a task arriving
 * later starts from where the cid was left. That is cfs_rq->zero_vruntime
 * without a field of its own.
 */
/*
 * Divide a signed value by a positive one. BPF has no signed division, so
 * take the magnitude through the unsigned divide and put the sign back.
 */
static s64 vdiv(s64 v, u64 d)
{
	if (v < 0)
		return -(s64)((u64)(-v) / d);

	return (s64)((u64)v / d);
}

/*
 * The reference of @pk.
 */
static u64 pack_vref(pack_t *pk)
{
	return pk->vref;
}

/*
 * The reference of @pk at @now, with the service the task running there
 * has taken since it was picked folded in, see pack_vref().
 *
 * A running task's vruntime is only charged in ops.stopping(), so between
 * two context switches the reference stands still while the CPU goes on
 * delivering service, and everything read off it in between is behind by
 * as much as a whole request. A task placed against a reference that low
 * is placed further back than it should be, and one tested against it
 * looks over-served when it is not.
 *
 * fair.c has no such window. update_curr() runs before every
 * place_entity() and every entity_eligible(), so V is exact wherever it
 * is used. This is that update, for the one task a cid knows it is
 * running,
 *
 *	dV = w_i * dv_i / W
 *
 * and it is only a read: the service is charged for real, once, by
 * vref_charge() when the task stops. ops.stopping() clears @curr_w, so a
 * cid with nothing of ours on it projects nothing, and past a whole
 * request there is nothing worth projecting either: the task is due to
 * be rescheduled, and if it is kept it is charged for real at that
 * point, see eevdf_dispatch(), so the estimate would be running past
 * what it can know.
 */
static u64 pack_vref_at(pack_t *pk, u64 now)
{
	u64 w, sum_w, delta, dv;

	w = pk->curr_w;
	sum_w = pk->vsum_w;
	delta = now - pk->curr_run_at;
	if (!w || !sum_w || delta >= pk->curr_request)
		return pk->vref;

	dv = delta * NICE_0_WEIGHT / w;

	return pk->vref + dv * w / sum_w;
}

/*
 * The reference to place a task against and to test it against, which is
 * pack_vref_at() unless --no-vref-update pins it to the stored value.
 */
static u64 pack_vref_place(pack_t *pk, u64 now)
{
	return no_vref_update ? pack_vref(pk) : pack_vref_at(pk, now);
}

/*
 * The reference to place @se against when it is about to join @pk with
 * weight @join_w.
 *
 * pack_vref_at() projects the running task's uncharged service over the
 * pack's current weight W. Once a task of weight w joins, the same service
 * is projected over W + w instead. Placing at the pre-join projection can
 * therefore leave a zero-lag task one unit above the post-join reference
 * through integer truncation, and incorrectly make it ineligible.
 *
 * Let q be the projection after the join. Place against
 *
 *	V' = V + q * (W + w) / W.
 *
 * vref_join() then contributes w * (V' - V) / (W + w), and adding q
 * reconstructs V'. Thus a zero-lag task remains eligible after joining,
 * with the same left bias avg_vruntime() gives fair.c's reference.
 */
static u64 pack_vref_before_join(pack_t *pk, const sched_ent_t *se,
				 u64 join_w, u64 now)
{
	u64 curr_w, sum_w, delta, dv, projection;

	if (no_vref_update || se->vpack == pk)
		return pack_vref_place(pk, now);

	curr_w = pk->curr_w;
	sum_w = pk->vsum_w;
	delta = now - pk->curr_run_at;
	if (!curr_w || !sum_w || delta >= pk->curr_request)
		return pk->vref;

	dv = delta * NICE_0_WEIGHT / curr_w;
	projection = dv * curr_w / (sum_w + join_w);

	return pk->vref + projection * (sum_w + join_w) / sum_w;
}

/*
 * Return the lag of @se against @pk at @now, rq clock, clamped to @limit
 * both ways as entity_lag() does.
 */
static s64 ent_lag_at(const sched_ent_t *se, pack_t *pk, s64 limit, u64 now)
{
	s64 lag;

	lag = (s64)(pack_vref_place(pk, cid_clock_task_at(pk->cid, now)) - se->vruntime);
	if (lag > limit)
		lag = limit;
	else if (lag < -limit)
		lag = -limit;

	return lag;
}

/* Return @p's current lag against @pk, clamped as entity_lag() does. */
static s64 task_lag_at(const struct task_struct *p,
		       const task_ctx_t *tctx, pack_t *pk, u64 now)
{
	return ent_lag_at(&tctx->se, pk, (s64)lag_limit(p, tctx), now);
}

/*
 * Is the entity running in @pk still owed service at @now?
 *
 * Its vruntime is only charged in ops.stopping() too, so the service it
 * has taken since it was picked is added to it here, and to the reference
 * it is measured against by pack_vref_at(). This is what
 * wakeup_preempt_fair() calls update_curr_fair() for before deciding
 * anything. A task that has run for a whole request is past its deadline
 * as well and has no protection left either way.
 */
static bool curr_owed_service(pack_t *pk, u64 now)
{
	u64 w = pk->curr_w, delta = now - pk->curr_run_at;
	u64 dv;

	if (!w || delta >= pk->curr_request)
		return false;
	dv = delta * NICE_0_WEIGHT / w;

	return !time_after(pk->curr_v + dv, pack_vref_at(pk, now));
}

/* Project the running entity's vruntime to @now. */
static u64 curr_vruntime_at(pack_t *pk, u64 now)
{
	u64 run_at = pk->curr_run_at;

	if (time_before(now, run_at))
		now = run_at;

	return pk->curr_v + (now - run_at) * NICE_0_WEIGHT / pk->curr_w;
}

/*
 * Give the entity just picked the protection set_protect_slice() gives
 * fair.c's current entity. The EDQ augmentation supplies the shortest
 * queued request, so protection is bounded by the smallest competitor
 * instead of always extending to the current entity's deadline.
 */
static void set_protect_slice(pack_t *pk, u64 weight)
{
	u64 slice = pk->curr_request, min_slice;
	u64 vprot = pk->curr_dl;

	if (no_run_to_parity) {
		pk->curr_vprot = pk->curr_v;
		return;
	}

	if (!scx_edq_min_slice(&pk->edq, &min_slice) && min_slice < slice)
		slice = min_slice;
	if (slice != pk->curr_request) {
		u64 limit = pk->curr_v +
			slice * NICE_0_WEIGHT / weight;

		if (time_before(limit, vprot))
			vprot = limit;
	}
	pk->curr_vprot = vprot;
}

/* Never let concurrent wakeups move the protection endpoint forward. */
static void shorten_protect_slice(pack_t *pk, u64 vprot)
{
	u64 old = READ_ONCE(pk->curr_vprot);

	while (time_before(vprot, old) && can_loop) {
		u64 prev = cmpxchg(&pk->curr_vprot, old, vprot);

		if (prev == old)
			return;
		old = prev;
	}
}

/*
 * Drop @se out of its pack's reference, see pack_vref().
 */
static void vref_leave(sched_ent_t *se)
{
	pack_t *pk = se->vpack;
	u64 w;
	s64 d;

	if (!pk)
		return;

	w = __sync_fetch_and_sub(&pk->vsum_w, se->vjoin_w);

	/*
	 * V' = V + w_i*(V - v_i) / (W - w_i), and the last one out leaves
	 * the reference standing where it is.
	 */
	if (w > se->vjoin_w) {
		d = (s64)(pk->vref - se->vjoin_v);
		__sync_fetch_and_add(&pk->vref,
				     vdiv((s64)se->vjoin_w * d, w - se->vjoin_w));
	} else {
		/* Nothing left to pay a debt off, see delay_settle(). */
		__sync_fetch_and_add(&pk->empty_gen, 1);
	}

	se->vpack = NULL;
}

/*
 * Fold @se, of weight @join_w, into @pk's reference, see pack_vref(). The
 * entity is not a member of any pack.
 */
static void vref_join(pack_t *pk, sched_ent_t *se, u64 join_w)
{
	u64 w;
	s64 d;

	se->vjoin_w = join_w;
	se->vjoin_v = se->vruntime;
	se->vpack = pk;

	/*
	 * V' = V + w_i*(v_i - V) / (W + w_i). On an empty pack W is 0 and
	 * the increment is exactly v_i - V, so the first member becomes the
	 * reference, which is what the average of one is.
	 */
	w = __sync_fetch_and_add(&pk->vsum_w, join_w);
	d = (s64)(se->vruntime - pk->vref);
	__sync_fetch_and_add(&pk->vref, vdiv((s64)join_w * d, w + join_w));
}

/*
 * Bring the lag and the deadline of @tctx over to the weight @w, the part of
 * reweight_task() that is not about the pack, see there.
 */
static void task_rescale(task_ctx_t *tctx, u64 w)
{
	sched_ent_t *se = &tctx->se;
	u64 old = se->vw;

	if (w == old)
		return;
	se->vw = w;
	if (!old)
		return;

	se->vlag = vdiv(se->vlag * (s64)old, w);
	if (se->deadline && time_before(se->vruntime, se->deadline))
		se->deadline = se->vruntime + (se->deadline - se->vruntime) * old / w;
}

/*
 * The weight the task of @tctx will have in @cid's pack once it has joined
 * it: its nice weight, or its share of its group hierarchy on @cid.
 */
static u64 task_join_weight(const struct task_struct *p, const task_ctx_t *tctx,
			    s32 cid)
{
	u64 w = task_nice_weight(p);

	if (!tctx->grp)
		return w;
	if (tctx->gq == &tctx->grp[cid])
		return grp_h_weight(tctx->gq, tctx->gw, false);

	return grp_h_weight(&tctx->grp[cid], w, true);
}

/*
 * Take @tctx out of its pack's reference and out of its group's load, the
 * two memberships a task has on a cid and gives up together.
 */
static void task_vref_leave(task_ctx_t *tctx)
{
	grp_q_t *gq = tctx->gq;

	vref_leave(&tctx->se);
	if (gq) {
		tctx->gq = NULL;
		grp_load_add(gq, -(s64)tctx->gw);
		grp_nr_add(gq, -1);
	}
}

/*
 * Make @p a member of its pack on @cid, leaving the one it was in, see
 * vref_join(), and of its group's load there. A task in a group joins at the
 * share its group then gives it, and its lag and deadline follow.
 */
static void task_vref_join(s32 cid, const struct task_struct *p,
			   task_ctx_t *tctx)
{
	pack_t *pk = cid_valid(cid) ? task_pack(tctx, cid) : NULL;
	u64 w;

	if (tctx->se.vpack == pk)
		return;
	task_vref_leave(tctx);

	if (!pk)
		return;
	if (tctx->grp) {
		tctx->gw = task_nice_weight(p);
		tctx->gq = &tctx->grp[cid];
		grp_load_add(tctx->gq, tctx->gw);
		grp_nr_add(tctx->gq, 1);
		w = grp_h_weight(tctx->gq, tctx->gw, false);
		task_rescale(tctx, w);
	} else {
		w = task_weight(p, tctx);
	}
	vref_join(pk, &tctx->se, w);
}

/*
 * Bring a member of a pack over to the share its group hierarchy gives it
 * now, which moves with every task that joins or leaves the groups above
 * it on the cid: the entity leaves the pack's reference and joins it again
 * at the new weight with its lag carried over, reweight_eevdf(), which
 * fair.c runs on enqueue, set_next_task() and the tick. @now is on the rq
 * clock.
 */
static void task_h_refresh(task_ctx_t *tctx, u64 now)
{
	sched_ent_t *se = &tctx->se;
	pack_t *pk = se->vpack;
	u64 w, old, tnow, vref;
	s64 lag;

	if (!tctx->gq || !pk)
		return;
	w = grp_h_weight(tctx->gq, tctx->gw, false);
	old = se->vjoin_w;
	if (w == old || !old)
		return;

	tnow = cid_clock_task_at(pk->cid, now);
	vref = pack_vref_place(pk, tnow);
	lag = vdiv((s64)(vref - se->vruntime) * (s64)old, w);
	vref_leave(se);
	task_rescale(tctx, w);
	se->deadline = se->deadline && time_before(se->vruntime, se->deadline) ?
		       vref - lag + (se->deadline - se->vruntime) : 0;
	se->vruntime = vref - lag;
	vref_join(pk, se, w);
}

/*
 * Bring the contribution of @se up to date with its vruntime.
 *
 *	dV = w_i * dv_i / W
 *
 * EEVDF's identity for the service just delivered, taken against the pack
 * that received it. The division truncates, and a pack heavy enough that
 * w_i * dv_i falls below W would advance by nothing at all and freeze, so
 * carry the remainder. Only the cid the task ran on is touched, so the
 * carry needs no atomic.
 */
static void vref_charge(sched_ent_t *se)
{
	pack_t *pk = se->vpack;
	u64 acc, delta, w;
	s64 dv;

	if (!pk)
		return;

	dv = (s64)(se->vruntime - se->vjoin_v);
	if (dv <= 0)
		return;
	se->vjoin_v = se->vruntime;

	w = pk->vsum_w;
	if (!w)
		return;

	acc = se->vjoin_w * (u64)dv + pk->vref_rem;
	delta = acc / w;
	pk->vref_rem = acc - delta * w;
	if (delta)
		__sync_fetch_and_add(&pk->vref, delta);
}

/*
 * Settle up with the task that is keeping @cid across the end of its
 * slice, see keep_running().
 *
 * A task that goes on running is a task that was picked again, and every
 * reader of @cid has to see it that way: the service it has taken is
 * charged to its vruntime and to its pack, the way ops.stopping() does,
 * and what it is owed from here is published, the way ops.running() does.
 * Without it a cid whose task keeps winning would hold a reference that
 * stands still for as long as the task does, and everything placed or
 * tested against that cid meanwhile is placed against a clock that
 * stopped. @curr_since is what is not touched: it marks the moment the
 * CPU last actually changed hands.
 */
static void keep_charge(struct task_struct *p, s32 cid, u64 now)
{
	struct cid_ctx __arena *cctx = cid_ctx(cid);
	task_ctx_t *tctx = try_lookup_task_ctx(p);
	u64 delta, weight;
	pack_t *pk;

	if (!tctx)
		return;
	pk = task_pack(tctx, cid);

	delta = now - tctx->last_run_at;
	task_bw_charge(tctx, cid, delta);
	tctx->se.vruntime += calc_delta_fair(p, tctx, delta);
	tctx->last_run_at = now;
	vref_charge(&tctx->se);

	pk->curr_dl = task_dl(p, tctx);
	pk->curr_v = tctx->se.vruntime;
	pk->curr_run_at = now;
	pk->curr_request = task_request(p);
	weight = task_weight(p, tctx);
	set_protect_slice(pk, weight);
	pk->curr_w = weight;
	cctx->curr_idle = p->policy == SCHED_IDLE;
}

/*
 * Move @se's vruntime to @vruntime, where it has just been placed against
 * a pack, and decide what becomes of its deadline.
 *
 * A task that slept gets a new request when it wakes: place_entity()
 * issues a fresh deadline, and here the deadline is dropped so that
 * task_dl() issues one from the new vruntime. A task that did not sleep,
 * moved to another cid or queued again after a bounced dispatch or a
 * preemption by a higher class, was partway through a request, and
 * fair.c keeps what is left of it, PLACE_REL_DEADLINE: the deadline is
 * stored relative to the vruntime on the way out of the runqueue,
 *
 *	if (sched_feat(PLACE_REL_DEADLINE) && !task_sleep) {
 *		se->deadline -= se->vruntime;
 *		se->rel_deadline = 1;
 *	}
 *
 * and re-based on the way in,
 *
 *	if (sched_feat(PLACE_REL_DEADLINE) && se->rel_deadline) {
 *		se->deadline += se->vruntime;
 *		se->rel_deadline = 0;
 *		return;
 *	}
 *
 * Without it the task is granted a whole request wherever it lands and
 * sorts behind tasks that were queued after it, once per migration. A
 * deadline the vruntime has already reached is a consumed request, and
 * is dropped either way, as update_deadline() would reissue it.
 */
static void set_vruntime(sched_ent_t *se, u64 vruntime, bool sleep)
{
	u64 rel = 0;

	if (!sleep && !no_place_rel_deadline && se->deadline &&
	    time_before(se->vruntime, se->deadline))
		rel = se->deadline - se->vruntime;

	se->vruntime = vruntime;
	se->deadline = rel ? vruntime + rel : 0;
}

/*
 * Pay off what a task owed the pack it blocked in, with the service that
 * pack has delivered since, which is DELAY_DEQUEUE and DELAY_ZERO.
 *
 * fair.c does not dequeue a task that blocks while it is over-served. It
 * is left in the tree, sched_delayed, still counted in W and still
 * holding its place, so that the reference goes on moving past it while
 * it sleeps: pick_next_entity() dequeues it the moment pick_eevdf()
 * would have run it, which is the moment it becomes eligible, and a
 * wakeup that comes sooner finds it where it was, with the part of the
 * debt that has been paid,
 *
 *	if (se->sched_delayed) {
 *		vlag = max(vlag, se->vlag);
 *		if (sched_feat(DELAY_ZERO))
 *			vlag = min(vlag, 0);
 *	}
 *
 * Either way it never wakes owing more than it did when it blocked, and
 * DELAY_ZERO sees to it that the pack's progress is not turned into
 * credit either. A task that is dequeued at once, as it is here, would
 * carry the whole debt across a sleep of any length and pay it in full
 * on waking, against a pack that may have long since moved on.
 *
 * There is no tree to leave the task in: ops.quiescent() is the end of
 * the kernel's interest in it, and the EDQ holds runnable tasks. So the
 * task leaves its pack, and what is remembered is where the pack stood
 * when it left, @delay_vref, and what the pack weighed without it,
 * @delay_w. When the task is placed again the pack's reference has
 * moved by the service delivered there since, and the delayed task
 * would have seen it move at
 *
 *	dV = w_j * dv_j / (W_o + w_i)
 *
 * with its own weight w_i still in the denominator, where the pack it
 * left advances at w_j * dv_j / W_o: the advance is scaled by
 * W_o / (W_o + w_i), which is exact while the pack keeps its weight and
 * an estimate otherwise. That much is credited to the debt and not a
 * unit more, DELAY_ZERO.
 *
 * A pack that has emptied since forgives the debt whole. That is what
 * pick_next_entity() does the moment the delayed task is the only thing
 * left to pick, and what it would do a moment later anyway, V being the
 * task's own vruntime once nothing else is there.
 *
 * Where the task wakes follows too, see delay_requeue_cid().
 */
static s64 delay_debt(const task_ctx_t *tctx, u64 now)
{
	s32 cid = tctx->delay_cid;
	pack_t *pk = task_pack(tctx, cid);
	s64 adv, lag = tctx->se.vlag;

	if (pk->empty_gen != tctx->delay_gen || lag >= 0)
		return 0;

	adv = (s64)(pack_vref_place(pk, cid_clock_task_at(cid, now)) - tctx->delay_vref);
	if (adv <= 0)
		return lag;
	adv = vdiv(adv * (s64)tctx->delay_w, tctx->delay_w + tctx->se.vw);

	lag += adv;
	return lag > 0 ? 0 : lag;
}

static void delay_settle(task_ctx_t *tctx, u64 now)
{
	if (!cid_valid(tctx->delay_cid))
		return;
	tctx->se.vlag = delay_debt(tctx, now);
	tctx->delay_cid = -1;
}

/*
 * The cid a waking task goes back to without being placed, or -1.
 *
 * ttwu_runnable() runs before select_task_rq(). A delayed task is still on
 * the runqueue it blocked on, so its wakeup requeues it there,
 *
 *	if (task_on_rq_queued(p)) {
 *		if (p->se.sched_delayed)
 *			enqueue_task(rq, p, ENQUEUE_NOCLOCK | ENQUEUE_DELAYED);
 *		if (!task_on_cpu(rq, p))
 *			wakeup_preempt(rq, p, wake_flags);
 *		ttwu_do_wakeup(p);
 *		return 1;
 *	}
 *
 * and no CPU is chosen for it: not the waker's, not an idle one. It runs
 * where it was once it is picked there, or wherever a balance moves it.
 *
 * The task is "still on the runqueue it blocked on" for as long as fair.c
 * would have kept it in the tree: while the pack it left is still there
 * and the debt it owes that pack is not yet paid, see delay_settle(). A
 * task whose debt is paid was dequeued by the pick that would have run
 * it, and wakes through the placement like any other. So is a task whose
 * affinity no longer covers the cid: a change of affinity takes a queued
 * task off its runqueue.
 *
 * The cid is handed back to the kernel and the task reaches ops.enqueue()
 * on it, where place_task() settles what is left of the debt and the
 * wakeup preemption test runs, which is requeue_delayed_entity() followed
 * by wakeup_preempt(). What is skipped is wake_affine() and the idle
 * scan, as ttwu_runnable() skips select_task_rq().
 */
static s32 delay_requeue_cid(const struct task_struct *p,
			     const task_ctx_t *tctx, u64 now)
{
	s32 cid = tctx->delay_cid;

	if (no_delay_requeue || !cid_valid(cid))
		return -1;
	if (is_restricted(p) && !cid_allowed(p, cid))
		return -1;
	if (!delay_debt(tctx, now))
		return -1;

	return cid;
}

/*
 * Place @p on @cid: a task that is not running is put at the cid's
 * reference minus the lag it carries, the way place_entity() does, and
 * either way it becomes a member of @cid's reference.
 *
 * The lag only means something against a pack. place_entity() applies it
 * under
 *
 *	if (sched_feat(PLACE_LAG) && cfs_rq->nr_queued && se->vlag)
 *
 * and skips it on an empty runqueue, where there is nobody to be ahead of
 * or behind: the task is placed at the base with neither credit nor debt,
 * and being the only member it becomes the reference itself. Applying the
 * lag there would only move the cid's clock, since the task's vruntime is
 * the average when it is alone, and a task carrying credit would take it
 * to an idle cid and have it silently absorbed. An idle cid is the
 * preferred wake target, see pick_idle_cid(), so this is the common
 * placement, not a corner of one.
 */
/*
 * Inflate a placement offset so that joining the destination pack does not
 * dilute it. If the pack has weight W and @p has weight w, placing @p at
 * V - offset moves the weighted-average reference to
 *
 *	V' = V - w * offset / (W + w).
 *
 * The lag visible after the join is therefore only W / (W + w) of the
 * requested offset. PLACE_LAG in fair.c compensates by (W + w) / W; write
 * that as offset + offset * w / W here to avoid forming W + w first.
 *
 * A task already in this pack is only being re-placed, not joined, because
 * vref_join() is a no-op for it. Its offset therefore needs no correction.
 */
static s64 compensate_place_offset(pack_t *pk, const sched_ent_t *se,
				   u64 weight, s64 offset)
{
	u64 load = pk->vsum_w;

	if (no_place_lag || !load || se->vpack == pk || !offset)
		return offset;

	return offset + vdiv(offset * (s64)weight, load);
}

static void place_task(s32 cid, const struct task_struct *p,
		       task_ctx_t *tctx, u64 now, bool sleep)
{
	/* The pack's progress is in its own task clock; the credit is timed. */
	u64 tnow = cid_valid(cid) ? cid_clock_task_at(cid, now) : now;

	if (!scx_bpf_task_running(p) && cid_valid(cid)) {
		pack_t *pk = task_pack(tctx, cid);
		u64 w = task_join_weight(p, tctx, cid);
		u64 vruntime;

		/* The lag is carried at the weight the task is placed with. */
		task_rescale(tctx, w);
		vruntime = pack_vref_before_join(pk, &tctx->se, w, tnow);

		/*
		 * ops.quiescent() does not run when the kernel migrates a queued
		 * task. Refresh its lag against the pack it is leaving instead of
		 * reusing the value saved at its last sleep.
		 */
		if (!sleep && tctx->se.vpack)
			tctx->se.vlag = task_lag_at(p, tctx, tctx->se.vpack, now);
		delay_settle(tctx, now);
		if (pk->vsum_w) {
			s64 offset = sleep ? task_place_offset(cid, p, tctx, now) :
					     tctx->se.vlag;

			offset = compensate_place_offset(pk, &tctx->se, w, offset);
			vruntime -= offset;
		}
		set_vruntime(&tctx->se, vruntime, sleep);
	}
	task_vref_join(cid, p, tctx);
}

/*
 * Bring the task's lag and deadline over to a new weight.
 *
 * Both are distances in the task's own virtual time, which runs at
 * NICE_0_WEIGHT / weight, so a change of weight changes what they are
 * worth in service. reweight_eevdf() has rescale_entity() carry the two
 * across:
 *
 *	se->vlag = div64_long(se->vlag * old_weight, weight);
 *	...
 *	if (se->rel_deadline)
 *		se->deadline = div64_long(se->deadline * old_weight, weight);
 *
 * so that the lag stays the service it was, w * (V - v), and the deadline
 * stays the request it was issued for, d' = v' + (d - v) * w / w'. Both
 * are called for by the derivation above rescale_entity(), and nothing
 * else about the task is. An entity that is on the runqueue is then
 * placed again from the rescaled lag, v' = V - vl': its vruntime moved at
 * the old rate for as long as it ran, and left where it is it would be
 * off by the whole difference.
 *
 * @dequeued says the task was taken off the runqueue for the change and
 * is about to be put back, which is how set_user_nice() and
 * __setscheduler_params() do it: ops.quiescent() has just taken its lag,
 * fresh, and the vruntime is placed from it here, since a running task's
 * enqueue never reaches ops.enqueue(), see eevdf_set_weight(). A queued
 * task is placed once more by place_task() on the enqueue that follows,
 * against the cid it lands on. A sleeping task is only rescaled, what it
 * carries is spent when it wakes.
 */
static void reweight_task(const struct task_struct *p, task_ctx_t *tctx,
			  bool dequeued)
{
	u64 w, old = tctx->se.vw;
	s32 cid = scx_bpf_task_cid((struct task_struct *)p);

	/*
	 * A task in a group first changes what it weighs in its group, and
	 * then takes the share that gives it.
	 */
	if (tctx->gq) {
		u64 nice_w = task_nice_weight(p);

		grp_load_add(tctx->gq, (s64)nice_w - (s64)tctx->gw);
		tctx->gw = nice_w;
		w = grp_h_weight(tctx->gq, nice_w, false);
	} else if (tctx->grp && cid_valid(cid)) {
		w = grp_h_weight(&tctx->grp[cid], task_nice_weight(p), true);
	} else {
		w = task_nice_weight(p);
	}

	if (w == old)
		return;
	if (dequeued && tctx->se.vpack)
		tctx->se.vlag = task_lag_at(p, tctx, tctx->se.vpack, scx_bpf_now());
	task_rescale(tctx, w);

	if (!dequeued || !old)
		return;
	if (cid_valid(cid)) {
		pack_t *pk = task_pack(tctx, cid);
		u64 now = scx_bpf_now();
		u64 vruntime = pack_vref_place(pk, cid_clock_task_at(cid, now));

		if (pk->vsum_w)
			vruntime -= tctx->se.vlag;
		set_vruntime(&tctx->se, vruntime, false);
	}
}

/*
 * Direct dispatch @p to the local DSQ of @cid from ops.select_cid().
 *
 * Insert with SCX_ENQ_IMMED so that the kernel bounces @p back through
 * ops.enqueue() (and from there into a per-cid EDQ, where the deadline
 * ordering applies) whenever @p can't run on @cid right away. This keeps
 * the local DSQ a pure "run now" fast path instead of an unbounded queue
 * that outranks the deadline-ordered EDQs.
 *
 * @cid is idle here, so the bounce is the exception: the kernel triggers
 * it (rq_is_open() in dispatch_one()) whenever a task is waiting on @cid
 * or a higher scheduling class took it in the meantime. Only call this for
 * a cid that is idle, never to stack @p behind a task that is running: the
 * bounce would be certain and the direct dispatch pure overhead.
 */
static void direct_dispatch_local(struct task_struct *p, task_ctx_t *tctx, s32 cid,
				  u64 now)
{
	/*
	 * @cid is idle, and its pack is empty more often than not: nothing
	 * runs there and nothing is waiting. A placement against an empty
	 * pack does not depend on what the task weighs, so the walk of its
	 * groups that finds the weight and the join that publishes it are
	 * left to ops.running() on @cid, where the pack and the group queues
	 * are lines of the CPU's own. Done from here they were read and
	 * written across CPUs on the waker's path, and for a task in a
	 * cgroup that walk and its atomics were the largest item of the
	 * wakeup. A pack with a member, queued there a moment ago, gives the
	 * placement an offset and is placed against here as before.
	 */
	if (READ_ONCE(task_pack(tctx, cid)->vsum_w))
		place_task(cid, p, tctx, now, true);
	else
		tctx->place_pending = true;
	cid_edq_mark_dispatched(tctx);
	scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, task_request(p), SCX_ENQ_IMMED);
}
