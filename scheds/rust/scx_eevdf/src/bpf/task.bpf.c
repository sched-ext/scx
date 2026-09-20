/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.
 *
 * The life of a task under EEVDF: the callbacks that drive the accounting
 * in task.bpf.h, and what each of them owes the rest of the scheduler.
 *
 *
 * The model
 * ---------
 *
 * Each cid has a pack, which is its runqueue: the entities queued there
 * plus the one running, and a reference V that is their weighted-average
 * virtual time. A task is charged service in virtual time at its own
 * weight, v += delta * NICE_0 / w, and is eligible while v <= V; its
 * deadline is v + r/w, and the pick is the earliest deadline among the
 * eligible. What a task carries across a sleep or a migration is its lag,
 * V - v, not v itself, because two packs drift apart and a vruntime from
 * one means nothing in the other.
 *
 *
 * The callbacks
 * -------------
 *
 *   ops.enable()       the task joins the scheduler. Its arena context is
 *                      attached and its vruntime starts at the reference
 *                      of the pack it is on rather than at zero, which an
 *                      old pack may be seconds past.
 *        |
 *        v
 *   ops.running()      it gets a CPU:
 *                        - placed here if a direct dispatch left that to
 *                          us, which is what keeps a wakeup onto an empty
 *                          pack off the waker's CPU
 *                        - if it comes from another cid, its lag is
 *                          carried: v = V(new pack) - lag, place_entity()
 *                        - it joins this pack's reference at the weight
 *                          its cgroup hierarchy gives it here
 *                        - the cid publishes what it is running: deadline,
 *                          vruntime, weight, request, protected endpoint,
 *                          and when it was last charged, so that a remote
 *                          wakeup can decide whether to preempt without
 *                          looking anything up
 *                        - the hrtick is armed and the cpufreq hint given
 *        |
 *        v
 *   ops.stopping()     it gives the CPU up: the service it took since
 *                      ops.running() is charged to its vruntime, folded
 *                      into the pack's reference, and charged to its
 *                      cgroup's bandwidth; the published view is cleared
 *                      so nothing projects service onto a cid that is
 *                      running something else. If a higher class took the
 *                      CPU, this is also where a better cid is asked for.
 *        |
 *        v
 *   ops.quiescent()    it goes to sleep: its lag against the pack is
 *                      measured and kept, it leaves the pack and its
 *                      group's load, and if it blocked while over-served
 *                      what it owes is remembered with the pack it owes it
 *                      to - DELAY_DEQUEUE and DELAY_ZERO, so the pack's
 *                      progress pays the debt off while it sleeps instead
 *                      of the task waking up owing all of it.
 *
 * Between those: set_weight() and cpuctl_move() change what the task
 * weighs, and reweight_eevdf() is what carries its lag and its deadline
 * across that change; set_cmask() settles a delayed-dequeue debt when the
 * pack it owes can no longer be reached, the one piece of state the core
 * affinity path cannot fix for us. init_task() and exit_task() are the
 * life of the arena context itself.
 *
 * core_sched_before() answers the one question core scheduling asks: of
 * two tasks picked independently by the two runqueues of one core, which
 * has had less of its share. Their vruntimes are not comparable across
 * packs, so each is measured from an origin snapshotted when its pack was
 * last empty - sched_ext is not told when forced idle begins, so this is
 * an approximation of fair.c's zero_vruntime_fi.
 */
#include "eevdf.bpf.h"
#include "balance.bpf.h"
#include "cgroup.bpf.h"
#include "load.bpf.h"
#include "preempt.bpf.h"
#include "queue.bpf.h"
#include "task.bpf.h"

/*
 * Return @p's virtual service in the coordinate shared by contenders on an
 * SMT core. Core scheduling compares tasks selected independently by two cid
 * runqueues, so their absolute vruntimes are meaningful only relative to the
 * epoch in which their pack has stayed non-empty. Snapshot a new origin after
 * the pack empties; continuous contenders then accumulate service from
 * comparable zeroes, while a task entering a reused cid does not inherit the
 * old pack's coordinate.
 *
 * Unlike fair.c's zero_vruntime_fi, sched_ext is not told when forced idle
 * starts or ends. This is therefore an ABI-free approximation: the empty
 * generation supplies a stable epoch, and the running task is projected to
 * @now because ops.stopping() has not charged its latest service yet.
 */
static u64 core_vruntime(const struct task_struct *p, task_ctx_t *tctx, u64 now)
{
	pack_t *pk = tctx->se.vpack;
	struct core_sched_state __arena *state;
	u64 gen, zero, v = tctx->se.vruntime;

	if (!pk)
		return v;
	state = &core_sched_states[pk->cid];

	gen = READ_ONCE(pk->empty_gen) + 1;
	if (READ_ONCE(state->gen) != gen) {
		WRITE_ONCE(state->vzero, READ_ONCE(pk->vref));
		WRITE_ONCE(state->gen, gen);
	}
	zero = READ_ONCE(state->vzero);

	if (scx_bpf_task_running(p) && READ_ONCE(pk->curr_w))
		v = curr_vruntime_at(pk, cid_clock_task_at(pk->cid, now));

	return v - zero;
}

bool BPF_STRUCT_OPS(eevdf_core_sched_before, struct task_struct *a,
			   struct task_struct *b)
{
	task_ctx_t *at, *bt;
	u64 av, bv, now;
	bool ar, br;

	TOUCH_ARENA();
	at = try_lookup_task_ctx(a);
	bt = try_lookup_task_ctx(b);
	if (!at || !bt || !at->se.vpack || !bt->se.vpack) {
		ar = scx_bpf_task_running(a);
		br = scx_bpf_task_running(b);
		if (ar != br)
			return !ar;
		return time_before(a->scx.runnable_at, b->scx.runnable_at);
	}

	now = scx_bpf_now();
	av = core_vruntime(a, at, now);
	bv = core_vruntime(b, bt, now);

	return time_before(av, bv);
}

void BPF_STRUCT_OPS(eevdf_quiescent, struct task_struct *p, u64 deq_flags)
{
	cid_edq_task_t *at;
	task_ctx_t *tctx;
	pack_t *pk;
	s64 lag;
	u64 now;
	s32 cid;

	TOUCH_ARENA();

	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return;
	at = cid_edq_task(tctx);
	if (at)
		WRITE_ONCE(at->state, CID_EDQ_NONE);

	now = scx_bpf_now();
	util_est_update(tctx, now);
	if (deq_flags & SCX_DEQ_SLEEP) {
		task_runnable_update(tctx, now);
		tctx->last_sleep_at = now;
	}
	tctx->place_pending = false;

	/*
	 * Remember how far the task is from the reference as it stops being
	 * runnable, clamped both ways, like update_entity_lag():
	 *
	 *	vlag = avg_vruntime(cfs_rq) - se->vruntime;
	 *	se->vlag = clamp(vlag, -limit, limit);
	 *
	 * What is preserved across a sleep is the position relative to the
	 * reference, not the absolute vruntime. Restoring the vruntime
	 * against the reference alone would hand every task that sleeps long
	 * enough the full credit, no matter whether it had earned it.
	 */
	pk = tctx->se.vpack;
	cid = pk ? pk->cid : scx_bpf_task_cid(p);
	if (cid_valid(cid)) {
		if (!pk)
			pk = task_pack(tctx, cid);
		/*
		 * update_curr() first: dequeue_entity() charges the service
		 * the task has taken before it measures the lag, and this op
		 * runs before ops.stopping() does the charging here. Without
		 * it the lag is taken against a reference that has the last
		 * run projected in, from a vruntime that has not, and comes
		 * out too generous by that run. The charge is real and once;
		 * ops.stopping() finds nothing left to add.
		 */
		if (scx_bpf_task_running(p) && cid == scx_bpf_task_cid(p))
			keep_charge(p, cid, cid_clock_task_owned(cid, now));
		lag = task_lag_at(p, tctx, pk, now);
		tctx->se.vlag = lag;
	}
	task_vref_leave(tctx);

	/*
	 * A task that blocks over-served is what fair.c keeps in the tree,
	 *
	 *	if (sched_feat(DELAY_DEQUEUE) && delay &&
	 *	    !entity_eligible(cfs_rq, se)) {
	 *		...
	 *		set_delayed(se);
	 *		return false;
	 *	}
	 *
	 * and only for a sleep: a task dequeued for a change of its
	 * parameters is put straight back. Remember what is needed to pay
	 * the debt off with the pack's progress when the task returns, see
	 * delay_settle(). The reference is read after the task has left,
	 * since that is the value that goes on moving.
	 */
	if (!no_delay_dequeue && (deq_flags & SCX_DEQ_SLEEP) && lag < 0 &&
	    pk) {
		tctx->delay_cid = cid;
		tctx->delay_vref = pk->vref;
		tctx->delay_w = pk->vsum_w;
		tctx->delay_gen = pk->empty_gen;
	}
}

void BPF_STRUCT_OPS(eevdf_running, struct task_struct *p)
{
	task_ctx_t *tctx;
	u64 now, weight;
	bool placed = false;
	s32 cid;

	TOUCH_ARENA();

	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return;
	cid = scx_bpf_task_cid(p);

	/*
	 * The stamp the service is charged from is in the task clock,
	 * update_curr(); the running averages are fractions of wall time
	 * and follow the rq clock, which a task carries across CPUs.
	 */
	now = scx_bpf_now();

	/*
	 * The placement a direct dispatch left to this op, see
	 * direct_dispatch_local(). This is a switch to @p, which is not the
	 * current task yet, so place_task() places it as it would have on
	 * the wakeup, against the pack as it is now.
	 */
	if (tctx->place_pending) {
		tctx->place_pending = false;
		if (cid_valid(cid)) {
			place_task(cid, p, tctx, now, true);
			placed = true;
		}
	}
	tctx->last_run_at = cid_valid(cid) ? cid_clock_task_owned(cid, now) : now;
	cid_pressure_resumed(cid, tctx->last_run_at);
	if (latency_credit && latency_credit_user_thresh)
		tctx->last_utime = p->utime;
	util_set_running(tctx, true, now);
	cid_util_set_running(cid, true, now);
	cid_demand_set(cid, true, now);

	/*
	 * A task that was moved here from another cid's queue, by the
	 * balancer or an idle pull, carries a vruntime that means nothing
	 * against this cid's pack: taken from a pack that was far ahead it
	 * would wait here until the pack climbs past it, seconds under
	 * load. Carry the lag instead, the way a migration does in
	 * place_entity(): how far the task was from the pack it left is how
	 * far it is placed from the pack it joins.
	 */
	if (tctx->se.vpack && cid_valid(cid) &&
	    tctx->se.vpack != task_pack(tctx, cid)) {
		s64 lag = task_lag_at(p, tctx, tctx->se.vpack, now);

		set_vruntime(&tctx->se,
			     pack_vref_place(task_pack(tctx, cid),
					     tctx->last_run_at) - lag,
			     false);
	}

	/*
	 * After the lag has been carried, which reads the pack the task is
	 * leaving, and before the join that snapshots what it weighs.
	 */
	task_vref_join(cid, p, tctx);

	/*
	 * A task in a group is picked at the share of the hierarchy it has now,
	 * set_next_task_fair() running reweight_eevdf(). One placed just above
	 * joined at that share.
	 */
	if (tctx->gq && !placed)
		task_h_refresh(tctx, now);

	/*
	 * Publish what this cid is running. A task queued here later is
	 * compared against that deadline to decide whether it is worth
	 * interrupting, see kick_queued_cid().
	 */
	if (cid_valid(cid)) {
		struct cid_ctx __arena *cctx = cid_ctx(cid);
		pack_t *pk = task_pack(tctx, cid);

		pk->curr_dl = task_dl(p, tctx);
		pk->curr_v = tctx->se.vruntime;
		pk->curr_run_at = tctx->last_run_at;
		pk->curr_since = tctx->last_run_at;
		pk->curr_request = task_request(p);
		weight = task_weight(p, tctx);
		set_protect_slice(pk, weight);
		/* Publish a complete current-task snapshot to remote wakeups. */
		pk->curr_w = weight;
		cctx->curr_idle = p->policy == SCHED_IDLE;
		if ((cctx->curr_idle ||
		     (tctx->grp && task_in_idle_cgroup(tctx))) &&
		    !cctx->curr_sched_idle) {
			cctx->curr_sched_idle = 1;
			__sync_fetch_and_add(&nr_sched_idle_curr, 1);
		}

		/*
		 * A pick with company is given an hrtick, set_next_task_fair():
		 *
		 *	if (hrtick_enabled_fair(rq))
		 *		hrtick_start_fair(rq, p);
		 */
		if (cid_queued_test(cid))
			hrtick_start(cid, tctx->last_run_at);
	}

	/*
	 * Refresh cpufreq performance level.
	 */
	update_cpufreq(cid, now);
}

void BPF_STRUCT_OPS(eevdf_stopping, struct task_struct *p, bool runnable)
{
	task_ctx_t *tctx;
	u64 slice, tnow;
	s32 cid;

	TOUCH_ARENA();

	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return;
	cid = scx_bpf_task_cid(p);

	/*
	 * Evaluate the used time slice. Reuse the same timestamp and task
	 * context for user-time and normal EEVDF accounting: ops.stopping() is
	 * a hot path, so neither needs to be obtained twice.
	 */
	/*
	 * The service is charged in the task clock, update_curr(); the stop
	 * stamp cache hotness reads from other CPUs stays on the rq clock.
	 */
	tctx->last_stop_at = scx_bpf_now();
	tnow = cid_valid(cid) ? cid_clock_task_owned(cid, tctx->last_stop_at) :
			       tctx->last_stop_at;
	update_cid_user(p, cid, tctx, tctx->last_stop_at);
	slice = tnow - tctx->last_run_at;
	util_set_running(tctx, false, tctx->last_stop_at);
	cid_util_set_running(cid, false, tctx->last_stop_at);
	cid_demand_set(cid, runnable ||
			       (cid_valid(cid) && cid_queue_nr(cid) > 0),
		       tctx->last_stop_at);
	if (runnable && p->scx.slice)
		cid_pressure_displaced(cid, tnow);

	/*
	 * The runtime is charged as wall-clock time whatever the CPU it was
	 * spent on. Charging a slow CPU at a discount reads fair, but with
	 * one system-wide reference it isn't: the tasks on the slow CPUs
	 * drift below V without bound while the reference follows the
	 * average, their keys keep getting earlier, and a task waking up on
	 * a slow CPU, placed at V minus a bounded lag, sorts behind all of
	 * them and waits until their vruntime has climbed past it, hundreds
	 * of milliseconds after a second of load. EEVDF charges wall-clock
	 * time and uses the capacity only to balance the load.
	 *
	 * Charge the service just consumed to the task's vruntime, the way
	 * update_curr() does:
	 *
	 *	se->vruntime += calc_delta_fair(delta_exec, se);
	 */
	tctx->se.vruntime += calc_delta_fair(p, tctx, slice);
	vref_charge(&tctx->se);

	/* The same service against the bandwidth of the task's cgroup. */
	task_bw_charge(tctx, cid, slice);

	/*
	 * A runnable task stopped with slice left was displaced rather than
	 * yielding at a scx_eevdf boundary. Once the measured capacity is reduced,
	 * detach it for requeueing on a less-loaded cid. The enqueue path inserts
	 * it into that cid's EDQ, so this migration does not bypass EEVDF order.
	 */
	if (capacity_pressure && runnable && p->scx.slice && cid_valid(cid)) {
		s32 target = capacity_pressure_target(p, cid, tctx->last_stop_at);

		if (target >= 0) {
			tctx->dispatch_migrate_cid = target;
			tctx->pressure_migrate = true;
			scx_bpf_task_set_slice(p, 0);
		}
	}

	/*
	 * The service just charged is in the reference for real now, so
	 * there is nothing left for pack_vref_at() to project on this cid
	 * until ops.running() picks the next task.
	 */
	if (cid_valid(cid)) {
		struct cid_ctx __arena *cctx = cid_ctx(cid);

		task_pack(tctx, cid)->curr_w = 0;
		if (cctx->curr_sched_idle) {
			cctx->curr_sched_idle = 0;
			__sync_fetch_and_sub(&nr_sched_idle_curr, 1);
		}
	}
}

void BPF_STRUCT_OPS(eevdf_enable, struct task_struct *p)
{
	task_ctx_t *tctx = try_lookup_task_ctx(p);
	s32 cid = scx_bpf_task_cid(p);

	TOUCH_ARENA();

	if (tctx) {
		scx_bpf_task_set_dsq_vtime(p, (u64)tctx);
		tctx->grp = task_cgrp_ents(p);
		tctx->gq = NULL;
		/*
		 * ops.enable() is also called when a task switches back from a
		 * higher scheduling class at run time. Place it at the current
		 * pack reference instead of at the zero used during scheduler
		 * startup; an old pack may have advanced arbitrarily far by then.
		 */
		tctx->se.vruntime = cid_valid(cid) ?
				    pack_vref(task_pack(tctx, cid)) : 0;
		tctx->se.vlag = 0;
		tctx->se.deadline = 0;
		tctx->se.vpack = NULL;
		tctx->delay_cid = -1;
		tctx->recent_used_cid = -1;
		tctx->dispatch_migrate_cid = -1;
		tctx->pressure_migrate = false;
		tctx->place_pending = false;
	}
}

/*
 * The task's weight changed: a nice level, or a policy switched to or from
 * SCHED_IDLE. set_load_weight() gets here through reweight_task_scx() for
 * the sched_ext class as it gets to reweight_task_fair() for the fair
 * class, from inside the dequeue and enqueue set_user_nice() and
 * __setscheduler_params() wrap the change in, with the new static_prio
 * and policy already written, which is what task_weight() reads. @weight
 * itself is on the cgroup scale and too coarse at the light end, see
 * task_weight().
 *
 * A task that was on the runqueue has been dequeued for this, running or
 * not: enqueue_task_scx() sends a restored curr straight to the local
 * queue, so for a running task this is the only callback between the
 * dequeue and ops.running() that sees the change at all. A sleeping task
 * was not dequeued and is only rescaled.
 */
void BPF_STRUCT_OPS(eevdf_set_weight, struct task_struct *p, u32 weight)
{
	task_ctx_t *tctx;

	TOUCH_ARENA();

	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return;

	reweight_task(p, tctx, p->on_rq);
}

/*
 * The core affinity path already moves a queued or running task whose current
 * CPU is no longer allowed, and every scx_eevdf placement and balance handoff
 * reads or revalidates p->cpus_ptr. The one state the core cannot update is a
 * sleeping task's simulated delayed-dequeue membership: unlike fair.c's
 * sched_delayed entity, it is not physically left on the runqueue for the
 * affinity change to dequeue.
 *
 * Stop paying that task's debt when the pack it blocked in is excluded. If
 * the old cid remains allowed, fair leaves the delayed entity there too and
 * there is nothing to do.
 */
void BPF_STRUCT_OPS(eevdf_set_cmask, struct task_struct *p,
		    const struct scx_cmask __arena *cmask)
{
	task_ctx_t *tctx;
	s32 cid;

	TOUCH_ARENA();

	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return;
	cid = tctx->delay_cid;
	if (cid_valid(cid) && !cmask_test(cid, cmask))
		delay_settle(tctx, scx_bpf_now());
}

s32 BPF_STRUCT_OPS_SLEEPABLE(eevdf_init_task, struct task_struct *p,
		   struct scx_init_task_args *args)
{
	struct task_ctx_ref *ref;
	cid_edq_task_t *at;
	task_ctx_t *tctx;

	ref = bpf_task_storage_get(&task_ctx_stor, p, 0,
				   BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!ref)
		return -ENOMEM;
	tctx = scx_alloc(&task_ctx_allocator);
	if (!tctx)
		return -ENOMEM;
	at = &tctx->se.edq;
	/*
	 * No memset: LLVM 19 expands one on arena memory through the uncast
	 * pointer and the verifier rejects the program, see
	 * scx_edq_task_init(). Adjacent zero stores can be folded into the
	 * same thing, hence WRITE_ONCE for the two that are.
	 */
	scx_edq_task_init(&at->common);
	at->tid = p->scx.tid;
	at->cid = -1;
	at->state = CID_EDQ_NONE;
	WRITE_ONCE(at->slice, 0);
	WRITE_ONCE(at->enq_flags, 0);
	WRITE_ONCE(tctx->se.vpack, NULL);
	tctx->delay_cid = -1;
	tctx->recent_used_cid = -1;
	WRITE_ONCE(tctx->grp, NULL);
	WRITE_ONCE(tctx->gq, NULL);
	tctx->se.vw = task_nice_weight(p);

	/*
	 * @fork tells a task that is being created apart from one that was
	 * already running when the scheduler was loaded, which is the
	 * distinction ENQUEUE_INITIAL draws: wake_up_new_task() sets it and
	 * nothing else does, see task_dl().
	 */
	tctx->initial = args->fork;
	ref->tctx = tctx;

	return 0;
}

void BPF_STRUCT_OPS(eevdf_exit_task, struct task_struct *p,
		    struct scx_exit_task_args *args)
{
	struct task_ctx_ref *ref;
	task_ctx_t *tctx;
	int ret;

	TOUCH_ARENA();
	ref = bpf_task_storage_get(&task_ctx_stor, p, 0, 0);
	if (!ref || !ref->tctx)
		return;
	tctx = ref->tctx;
	ref->tctx = NULL;
	ret = scx_edq_task_detach(&tctx->se.edq.common);
	if (ret) {
		scx_bpf_error("EDQ detach failed for pid %d: %d", p->pid, ret);
		return;
	}
	scx_free(&task_ctx_allocator, tctx);
}
