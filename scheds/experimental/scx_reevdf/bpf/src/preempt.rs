// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.

//! The pick, as far as a callback can make it: whether a task that has
//! just been queued preempts the one running on its CID,
//! wakeup_preempt_fair(), and whether the running task keeps the CPU when
//! its slice ends, as pick_eevdf() considers curr beside the queued tasks.
//!
//! ops.enqueue() asks the first and ops.dispatch() the second. Both read
//! what the CID's pack publishes about its running task, see pack.rs, and
//! the head of its queue.
//!
//! Counterpart in scx_eevdf: preempt.bpf.c.

use crate::{
    SCHED_BATCH, SCHED_IDLE, accounting::time_before, charge, clock, effective_weight, features,
    hrtick, pack, prepare_request, task_policy, task_request, taskctx,
};
use scx_rustsched::dsq::{self, Edq};
use scx_rustsched::sched::Cid;
use scx_rustsched::task::Task;

/// Does a task queued on `cid` with `deadline` preempt the task running
/// there? wakeup_preempt_fair() reschedules when the pick would now be the
/// wakee, which with equal requests takes all of:
///
/// - something of ours running there, or there is nothing to interrupt;
/// - the wakee eligible, since pick_eevdf() only looks at eligible tasks;
/// - the running task past its protection (RUN_TO_PARITY), or no longer
///   owed service, in which case pick_eevdf() drops it;
/// - an earlier deadline than the running task's, unless that one is no
///   longer owed service;
/// - an earlier deadline than the first eligible queued task, or the
///   preemption only trades the running task for the head a slice early.
///
/// Everything is in `cid`'s virtual time, with the running task's uncharged
/// service projected onto both sides.
#[inline(never)]
pub(crate) fn should_preempt(
    cid: Cid,
    task: &Task,
    state: &taskctx::Context,
    deadline: u64,
    now: u64,
) -> bool {
    if !pack::running(cid) {
        return false;
    }
    // A wakee that waits behind the running task has that one asked
    // again when its request ends, not at the tick after,
    // hrtick_update(): on every way out below that does not preempt.
    if !features::wakeup_preempt() {
        hrtick::start(cid, now);
        return false;
    }
    // The policies first, wakeup_preempt_fair(): a SCHED_IDLE task
    // running is interrupted for anything else, protection and all, and
    // a SCHED_IDLE or SCHED_BATCH wakee interrupts nothing. Those are
    // policies for work that gives up latency, not for work served less.
    let policy = task_policy(task);
    if pack::curr_idle(cid) && policy != SCHED_IDLE {
        pack::shorten_protect(cid, now, 0);
        return true;
    }
    if policy == SCHED_IDLE || policy == SCHED_BATCH {
        hrtick::start(cid, now);
        return false;
    }
    let request = task_request(task);
    let curr_request = pack::curr_request(cid);
    let reference = pack::reference_at(cid, now);
    // The eligible head and the shortest queued request together, under
    // one trylock: the latter clips the protection even when the
    // running task keeps the CPU.
    let dsq::Head {
        deadline: head,
        min_slice: queued_min_slice,
    } = self::head(cid, reference);
    let eligibility = features::eligibility();
    let preempt = 'decide: {
        // Only a wakee owed service is in the pick at all.
        if eligibility && time_before(reference, state.vtime().get()) {
            break 'decide false;
        }
        // PREEMPT_SHORT: an eligible wakee asking for less than the
        // running task overrides its protection.
        if features::preempt_short() && request < curr_request {
            break 'decide true;
        }
        let owed = eligibility && pack::curr_owed(cid, now);
        let (curr_deadline, protect) = pack::curr_deadline(cid);
        if owed && features::run_to_parity() && time_before(pack::curr_vtime_at(cid, now), protect)
        {
            break 'decide false;
        }
        // Only a running task owed service is in the pick, and one
        // that is not loses it whatever the deadlines say; without the
        // eligibility test, the deadlines alone decide.
        if (owed || !eligibility) && !time_before(deadline, curr_deadline) {
            break 'decide false;
        }
        match head {
            Some(head) => time_before(deadline, head),
            None => true,
        }
    };
    // A wakee that loses still clips the running task's protection to
    // the shortest competing request past where it has reached, so that
    // it is asked again no later than that one would be,
    // update_protect_slice().
    if !preempt && features::run_to_parity() {
        let mut slice = request.min(curr_request);
        if queued_min_slice != 0 {
            slice = slice.min(queued_min_slice);
        }
        pack::shorten_protect(cid, now, slice);
    }
    if !preempt {
        hrtick::start(cid, now);
    }
    preempt
}

/// Settle up with the task running on `cid` as if it had just been picked
/// again: charge the service it has taken, reissue a consumed request and
/// publish it with fresh protection, keep_charge().
#[inline(always)]
pub(crate) fn keep_charge(task: &Task, state: &taskctx::Context, cid: Cid, now: u64) {
    // keep_charge() runs from ops that hold `cid`'s runqueue lock.
    charge(task, state, cid, clock::owned(cid, now));
    prepare_request(task, state);
    let request = task_request(task);
    pack::publish(
        cid,
        state,
        effective_weight(task, state),
        request,
        now,
        true,
        cid.min_slice(),
    );
}

/// What `cid`'s pick would take from its queue against `reference`, and
/// the shortest request queued there, without taking anything: the first
/// eligible task with the eligible scan, the head without it, where
/// nothing bounds the protection either. It never waits for a CPU that is
/// working on the queue, and then answers with the head, which can be
/// ineligible and so errs toward not preempting.
#[inline(always)]
pub(crate) fn head(cid: Cid, reference: u64) -> dsq::Head {
    dsq::peek(
        Edq::Cid(cid),
        features::eligible_scan().then_some(reference),
    )
}

/// Does the task running on `cid` keep it, rather than hand it to the head
/// of `cid`'s queue?
///
/// fair.c asks this at every pick: pick_eevdf() searches the queued
/// entities and curr, so a task whose slice has ended goes on running
/// whenever nothing eligible has an earlier deadline. Without it, dispatch
/// hands the CPU over in strict rotation and weights stop meaning anything
/// on a CPU with one task queued behind the running one. The service taken
/// so far is charged first and a consumed request reissued, as
/// update_curr() and update_deadline() would.
#[inline(always)]
pub(crate) fn keep_running(task: &Task, state: &taskctx::Context, cid: Cid, now: u64) -> bool {
    keep_charge(task, state, cid, now);
    let reference = pack::reference(cid);
    // An over-served task gives the CPU up, eligible or not the rest.
    if features::eligibility() && time_before(reference, state.vtime().get()) {
        return false;
    }
    match head(cid, reference).deadline {
        // Nothing queued is eligible: pick_eevdf() returns curr.
        None => true,
        // A tie is kept: giving the CPU up costs a switch.
        Some(deadline) => !time_before(deadline, state.deadline().get()),
    }
}
