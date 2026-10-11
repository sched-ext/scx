// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.

//! Per-CID EEVDF references.
//!
//! Each CID has a pack: the tasks queued on it or running there. Its
//! reference is the weighted average vruntime of its members, maintained
//! incrementally as they join, leave and are charged. Both fields change
//! with atomic adds, so a CID that runs a task stolen from another can take
//! it out of the victim's pack without that CID's lock. The truncation
//! remainder is touched only by the CID that charges its own running task.
//!
//! A pack also publishes what its CID is running: weight, request,
//! vruntime, deadline, the end of its protection, and when it was last
//! charged. A
//! wakee queued on the CID decides from that whether to preempt it,
//! projecting the service taken since the charge onto both sides, as
//! wakeup_preempt_fair() calls update_curr() first. Only the CID's own
//! callbacks write it, and enqueues read it, all under that CID's rq lock.
//!
//! Counterpart in scx_eevdf: task.bpf.h.

use scx_rustsched::var::Var;

use crate::{
    accounting::{
        advance, charge as fold, delay_debt, join_delta, lag, lag_limit, leave_delta,
        place as placed, reference_at as projected, reference_before_join as projected_for,
        time_before, vdiv,
    },
    cgroup, cid_table,
    taskctx::Context,
};
use scx_rustsched::sched::Cid;

scx_rustsched::arena_struct! {
    /// The pack of a CID: 128 bytes, two cache lines of its own.
    pub struct Pack {
        reference: u64,
        weight: u64,
        remainder: u64,
        /// The running task's weight, or 0 when nothing of ours runs there.
        curr_weight: u64,
        curr_vtime: u64,
        curr_deadline: u64,
        curr_charged_at: u64,
        /// The vruntime up to which the running task is protected,
        /// RUN_TO_PARITY.
        curr_protect: u64,
        curr_request: u64,
        /// How many times the last member has left, which forgives a
        /// delayed debt.
        empty_generation: u64,
        /// When the CID's hrtick is armed to fire, when the running task
        /// is due, and the charge stamp of the run it was armed for, see
        /// hrtick::start().
        hrtick_at: u64,
        hrtick_due: u64,
        hrtick_run_at: u64,
        /// Whether the running task is SCHED_IDLE, which any other wakee
        /// preempts, and whether it is SCHED_IDLE work at all, by policy
        /// or by an idle cgroup, which makes the CID a wakeup target, see
        /// curr_sched_idle().
        curr_idle: u64,
        curr_sched_idle: u64,
        /// The context of the running task, see lone_reference().
        curr_task: Option<Context>,
    }
}

scx_rustsched::cid_slot!(Pack, PACKS in ".data.packs");

/// The pack of `cid`, which the caller knows is a CID, see valid().
#[inline(always)]
pub(crate) fn pack(cid: Cid) -> Pack {
    cid_table::entry(cid)
}

scx_rustsched::shared! {
    /// How many CIDs run SCHED_IDLE work, so that the placement test costs one
    /// load while none does, which is nearly always. On a line of its own, away
    /// from the table address every pack access reads.
    static SCHED_IDLE_CIDS in ".data.schedidle": SchedIdle = SchedIdle {
        count: Var::new(0),
        pad: [0; 7],
    };
}

#[repr(C)]
struct SchedIdle {
    count: Var<u64>,
    pad: [u64; 7],
}

scx_rustsched::arena_struct! {
    /// The core-scheduling origin of a CID: the reference snapshotted when
    /// the pack was last empty and that empty generation plus one, zero
    /// being none, see core_vtime().
    struct CoreSched {
        origin: u64,
        generation: u64,
    }
}

scx_rustsched::cid_slot!(CoreSched, CORE_SCHED in ".data.coresched");

#[inline(always)]
fn core_sched(cid: Cid) -> CoreSched {
    cid_table::entry(cid)
}

pub fn init(_count: u32) -> i32 {
    let result = cid_table::init_slots::<Pack>();
    if result != 0 {
        return result;
    }
    cid_table::init_slots::<CoreSched>()
}

/// The task of `state`'s vruntime in the coordinate core scheduling
/// compares, or None outside a pack. Core scheduling compares tasks picked
/// independently by the runqueues of one core, and vruntimes only mean
/// something within the time their pack has stayed non-empty. So each is
/// measured from the pack's reference when it was last empty, snapshotted
/// the first time it is asked for after that; a task entering a reused CID
/// does not inherit the old pack's coordinate. fair.c's zero_vruntime_fi
/// moves at forced idle, which sched_ext is not told about, so this is an
/// approximation of it. A `running` task is projected to `now`, as its
/// latest service has not been charged yet.
#[inline(always)]
pub fn core_vtime(state: &Context, running: bool, now: u64) -> Option<u64> {
    let member = state.member().get();
    if member == 0 {
        return None;
    }
    let cid = member_cid(member);
    if !valid(Cid(cid.raw() as i32)) {
        return None;
    }
    let generation = pack(Cid(cid.raw() as i32)).empty_generation().get() + 1;
    if core_sched(Cid(cid.raw() as i32)).generation().get() != generation {
        core_sched(Cid(cid.raw() as i32))
            .origin()
            .set(pack(Cid(cid.raw() as i32)).reference().get());
        core_sched(Cid(cid.raw() as i32))
            .generation()
            .set(generation);
    }
    let zero = core_sched(Cid(cid.raw() as i32)).origin().get();
    let vtime = if running && pack(Cid(cid.raw() as i32)).curr_weight().get() != 0 {
        curr_vtime_at(Cid(cid.raw() as i32), now)
    } else {
        state.vtime().get()
    };
    Some(vtime.wrapping_sub(zero))
}

#[inline(always)]
pub fn valid(cid: Cid) -> bool {
    cid_table::valid::<Pack>(cid)
}

/// The reference of `cid`.
#[inline(always)]
pub fn reference(cid: Cid) -> u64 {
    pack(cid).reference().get()
}

/// Publish the task `cid` has just picked or charged and kept, with its
/// request of `request` ns. A `picked` task is protected up to its deadline,
/// bounded by one `queued_min_slice` (the shortest queued request, 0 for
/// none) past its vruntime when that is shorter, set_protect_slice(): the
/// smallest competitor, not the task's own deadline, says how long it may
/// run before it is asked again.
#[inline(always)]
pub fn publish(
    cid: Cid,
    state: &Context,
    weight: u64,
    request: u64,
    now: u64,
    picked: bool,
    queued_min_slice: u64,
) {
    if !valid(cid) {
        return;
    }
    let deadline = state.deadline().get();
    pack(cid).curr_weight().set(weight);
    pack(cid).curr_request().set(request);
    pack(cid).curr_vtime().set(state.vtime().get());
    pack(cid).curr_deadline().set(deadline);
    pack(cid).curr_charged_at().set(crate::clock::at(cid, now));
    pack(cid)
        .curr_task()
        .set(Some(Context::from_address(state.address())));
    if picked {
        let mut protect = deadline;
        // Without RUN_TO_PARITY the task is protected for nothing.
        if !crate::features::run_to_parity() {
            protect = state.vtime().get();
        } else if queued_min_slice != 0 && queued_min_slice < request {
            let limit = state
                .vtime()
                .get()
                .wrapping_add(queued_min_slice * crate::accounting::NICE_0_WEIGHT / weight.max(1));
            if time_before(limit, protect) {
                protect = limit;
            }
        }
        pack(cid).curr_protect().set(protect);
    }
}

/// Nothing of ours runs on `cid` any more.
#[inline(always)]
pub fn unpublish(cid: Cid) {
    if valid(cid) {
        pack(cid).curr_weight().set(0);
        set_class(cid, false, false);
    }
}

/// Record what the task starting on `cid` is: SCHED_IDLE by policy, and
/// SCHED_IDLE work by policy or by an idle cgroup.
#[inline(always)]
pub fn set_class(cid: Cid, idle: bool, sched_idle: bool) {
    if !valid(cid) {
        return;
    }
    if (pack(cid).curr_idle().get() != 0) != idle {
        pack(cid).curr_idle().set(u64::from(idle));
    }
    let was = pack(cid).curr_sched_idle().get() != 0;
    if was != sched_idle {
        pack(cid).curr_sched_idle().set(u64::from(sched_idle));
        SCHED_IDLE_CIDS
            .count
            .fetch_add(if sched_idle { 1 } else { u64::MAX });
    }
}

/// Does any CID run SCHED_IDLE work?
#[inline(always)]
pub fn any_sched_idle() -> bool {
    SCHED_IDLE_CIDS.count.get() != 0
}

/// Is the task running on `cid` SCHED_IDLE?
#[inline(always)]
pub fn curr_idle(cid: Cid) -> bool {
    valid(cid) && pack(cid).curr_weight().get() != 0 && pack(cid).curr_idle().get() != 0
}

/// Does `cid` run SCHED_IDLE work, a task of SCHED_IDLE policy or one in an
/// idle cgroup? Zero load while no CID does.
#[inline(always)]
pub fn curr_sched_idle(cid: Cid) -> bool {
    SCHED_IDLE_CIDS.count.get() != 0
        && valid(cid)
        && pack(cid).curr_weight().get() != 0
        && pack(cid).curr_sched_idle().get() != 0
}

/// Does a task of ours run on `cid`?
#[inline(always)]
pub fn running(cid: Cid) -> bool {
    valid(cid) && pack(cid).curr_weight().get() != 0
}

/// The running task's charged-at stamp and weight, for the projections.
#[inline(always)]
fn uncharged(cid: Cid, now: u64) -> (u64, u64) {
    // The run is charged from a stamp in the CID's task clock.
    let now = crate::clock::at(cid, now);
    let since = pack(cid).curr_charged_at().get();
    let delta = if (now.wrapping_sub(since) as i64) > 0 {
        now - since
    } else {
        0
    };
    (delta, pack(cid).curr_weight().get())
}

/// The reference of `cid` at `now`, with the running task's uncharged
/// service projected in, pack_vref_at().
#[inline(always)]
pub fn reference_at(cid: Cid, now: u64) -> u64 {
    // --no-vref-update reads the reference as stored.
    if !crate::features::vref_update() {
        return pack(cid).reference().get();
    }
    if let Some(reference) = lone_reference(cid, now) {
        return reference;
    }
    let (delta, weight) = uncharged(cid, now);
    let request = pack(cid).curr_request().get();
    projected(
        pack(cid).reference().get(),
        pack(cid).weight().get(),
        weight,
        delta,
        request,
    )
}

/// The reference of `cid` when the running task is the only member of its
/// pack: that task's vruntime at `now`, which is what avg_vruntime()
/// returns for a lone entity. The stored reference can sit a unit below
/// it, since every member that leaves truncates its share away, and a
/// task woken against it would find the running one over-served by that
/// unit and preempt it. The running task's context is read only once the
/// weights say it may be alone, and it must still be a member at the
/// pack's whole weight: one that has just blocked has left already.
#[inline(always)]
fn lone_reference(cid: Cid, now: u64) -> Option<u64> {
    lone_member(cid, pack(cid).weight().get())?;
    Some(curr_vtime_at(cid, now))
}

/// The vruntime the running task of `cid` last folded into its pack, when
/// that task is the pack's only member, at its whole weight `sum`.
#[inline(always)]
fn lone_member(cid: Cid, sum: u64) -> Option<u64> {
    if sum == 0 || pack(cid).curr_weight().get() != sum {
        return None;
    }
    let curr = pack(cid).curr_task().get()?;
    if curr.member().get() != member_word(cid, sum) {
        return None;
    }
    Some(curr.joined().get())
}

/// The reference to place a task of `join` weight against on `cid`, see
/// accounting::reference_before_join().
#[inline(always)]
fn reference_for(cid: Cid, now: u64, join: u64) -> u64 {
    if !crate::features::vref_update() {
        return pack(cid).reference().get();
    }
    if let Some(reference) = lone_reference(cid, now) {
        return reference;
    }
    let (delta, weight) = uncharged(cid, now);
    let request = pack(cid).curr_request().get();
    projected_for(
        pack(cid).reference().get(),
        pack(cid).weight().get(),
        weight,
        delta,
        request,
        join,
    )
}

/// When the running task was picked or last charged.
#[inline(always)]
pub fn curr_charged_at(cid: Cid) -> u64 {
    pack(cid).curr_charged_at().get()
}

/// Wall-clock time the running task needs to reach its deadline at `now`,
/// or 0 if it is there already or nothing runs, curr_dl_in().
#[inline(always)]
pub fn curr_deadline_in(cid: Cid, now: u64) -> u64 {
    let weight = pack(cid).curr_weight().get();
    if weight == 0 {
        return 0;
    }
    let distance = pack(cid)
        .curr_deadline()
        .get()
        .wrapping_sub(curr_vtime_at(cid, now)) as i64;
    if distance <= 0 {
        return 0;
    }
    distance as u64 * weight / crate::accounting::NICE_0_WEIGHT
}

/// The weight of `cid`'s pack: its queued tasks and the one running there.
#[inline(always)]
pub fn weight(cid: Cid) -> u64 {
    pack(cid).weight().get()
}

/// The running task's weight, 0 when nothing of ours runs.
#[inline(always)]
pub fn curr_weight(cid: Cid) -> u64 {
    pack(cid).curr_weight().get()
}

/// The running task's request.
#[inline(always)]
pub fn curr_request(cid: Cid) -> u64 {
    pack(cid).curr_request().get()
}

/// Clip the running task's protection to one `request` past where it has
/// reached. Protection never moves forward, update_protect_slice().
#[inline(always)]
pub fn shorten_protect(cid: Cid, now: u64, request: u64) {
    let weight = pack(cid).curr_weight().get();
    if weight == 0 {
        return;
    }
    let limit =
        curr_vtime_at(cid, now).wrapping_add(request * crate::accounting::NICE_0_WEIGHT / weight);
    if time_before(limit, pack(cid).curr_protect().get()) {
        pack(cid).curr_protect().set(limit);
    }
}

/// The running task's vruntime at `now`, curr_vruntime_at().
#[inline(always)]
pub fn curr_vtime_at(cid: Cid, now: u64) -> u64 {
    let (delta, weight) = uncharged(cid, now);
    advance(pack(cid).curr_vtime().get(), delta, weight)
}

/// Is the task running on `cid` still owed service at `now`? Past a whole
/// request it is due for rescheduling and owed nothing either way,
/// curr_owed_service().
#[inline(always)]
pub fn curr_owed(cid: Cid, now: u64) -> bool {
    let (delta, weight) = uncharged(cid, now);
    weight != 0
        && delta < pack(cid).curr_request().get()
        && !time_before(reference_at(cid, now), curr_vtime_at(cid, now))
}

/// The running task's deadline and the end of its protection.
#[inline(always)]
pub fn curr_deadline(cid: Cid) -> (u64, u64) {
    (
        pack(cid).curr_deadline().get(),
        pack(cid).curr_protect().get(),
    )
}

/// A membership of `cid`'s pack at `weight`, as Context::member holds it.
#[inline(always)]
fn member_word(cid: Cid, weight: u64) -> u64 {
    (u64::from(cid.index()) + 1) << 32 | weight
}

#[inline(always)]
fn member_cid(member: u64) -> Cid {
    Cid(((member >> 32) as u32 - 1) as i32)
}

#[inline(always)]
fn member_weight(member: u64) -> u64 {
    member & u64::from(u32::MAX)
}

#[inline(always)]
fn join(state: &Context, cid: Cid, weight: u64) {
    let vtime = state.vtime().get();
    let sum = pack(Cid(cid.raw() as i32)).weight().fetch_add(weight);
    let stored = pack(Cid(cid.raw() as i32)).reference().get();
    // A pack whose only member is its running task has that task's
    // vruntime as its average, and the placement was made against it,
    // lone_reference(). The stored reference can have drifted from it by
    // the truncation of every join and leave since the pack last emptied,
    // and a join against that would hand the drift to the joining task as
    // lag. Join against the member's vruntime instead, as far as it has
    // been folded in, which also drops the drift.
    let reference = match lone_member(Cid(cid.raw() as i32), sum) {
        Some(joined) => joined,
        None => stored,
    };
    pack(Cid(cid.raw() as i32)).reference().fetch_add(
        reference
            .wrapping_sub(stored)
            .wrapping_add(join_delta(reference, sum, vtime, weight)),
    );
    state.joined().set(vtime);
    state.member().set(member_word(cid, weight));
    state.joined_weight().set(weight);
}

/// Take the task out of its pack, if it has one, and out of its group's
/// load: the two memberships a task has on a CID and gives up together.
#[inline(always)]
pub fn leave(state: &Context) {
    cgroup::exit(state);
    leave_pack(state, true);
}

/// Take the task out of its pack's reference and weight. A pack the last
/// member leaves counts as emptied, which forgives the debts owed to it,
/// unless the member is only rejoining at another weight.
#[inline(always)]
fn leave_pack(state: &Context, emptied: bool) {
    let member = state.member().get();
    if member == 0 {
        return;
    }
    let cid = member_cid(member);
    let weight = member_weight(member);
    let sum = pack(Cid(cid.raw() as i32))
        .weight()
        .fetch_add(weight.wrapping_neg());
    // The last member out leaves the reference where it is. Never add a
    // known zero: LLVM turns that into a fetching OR, which the
    // verifier rejects on arena memory.
    if sum > weight {
        let reference = pack(Cid(cid.raw() as i32)).reference().get();
        let delta = leave_delta(reference, sum, state.joined().get(), weight);
        if delta != 0 {
            pack(Cid(cid.raw() as i32)).reference().fetch_add(delta);
        }
    } else if emptied {
        pack(Cid(cid.raw() as i32)).empty_generation().fetch_add(1);
    }
    state.member().set(0);
}

/// Leave the pack for good, saving the lag a later placement restores.
/// `limit` is the request the lag is bounded by, see lag_limit().
///
/// A task that blocks over-served, `sleep` with a negative lag, is one
/// fair.c leaves in the tree under DELAY_DEQUEUE, so that the pack moves on
/// past it while it sleeps. There is no tree to leave it in here, so where
/// the pack stood once it had left is recorded instead, and the debt is
/// settled against the pack's progress when the task is placed again.
#[inline(always)]
pub fn quiesce(state: &Context, limit: u64, now: u64, sleep: bool) {
    let member = state.member().get();
    if member == 0 {
        return;
    }
    let cid = member_cid(member);
    let reference = reference_at(Cid(cid.raw() as i32), now);
    let limit = lag_limit(limit, member_weight(member));
    let owed = lag(reference, state.vtime().get(), limit);
    state.lag().set(owed);
    leave(state);
    if sleep && owed < 0 && crate::features::delay_dequeue() {
        state.set_delay([
            u64::from(cid.index()) + 1,
            pack(Cid(cid.raw() as i32)).reference().get(),
            pack(Cid(cid.raw() as i32)).weight().get(),
            pack(Cid(cid.raw() as i32)).empty_generation().get(),
        ]);
    }
}

/// The CID a waking task goes back to without an idle search, or `None`.
///
/// fair.c leaves a task that blocked over-served in its runqueue until the
/// debt is paid, and ttwu_runnable() requeues it there before
/// select_task_rq() is ever asked. That holds here while the pack it left
/// has not emptied and the debt is not yet paid off, see settle(). The
/// enqueue that follows settles what is left and runs the preemption test,
/// requeue_delayed_entity() and wakeup_preempt(), delay_requeue_cid().
#[inline(always)]
pub fn requeue_cid(state: &Context, weight: u64, now: u64) -> Option<i32> {
    let [cid, reference, sum, generation] = state.delay();
    if cid == 0 || !crate::features::delay_requeue() {
        return None;
    }
    let cid = (cid - 1) as u32;
    if pack(Cid(cid as i32)).empty_generation().get() != generation {
        return None;
    }
    let progress = reference_at(Cid(cid as i32), now).wrapping_sub(reference) as i64;
    if delay_debt(state.lag().get(), progress, sum, weight) == 0 {
        return None;
    }
    Some(cid as i32)
}

/// The CID whose pack the task of `state` blocked in owing it, if any.
#[inline(always)]
pub fn delay_cid(state: &Context) -> Option<i32> {
    let [cid, ..] = state.delay();
    if cid == 0 {
        None
    } else {
        Some((cid - 1) as i32)
    }
}

/// Settle the delayed debt of the task of `state`, of weight `weight`, at
/// what is left of it at `now`: the pack's progress stops paying it off
/// from here, as for a delayed entity dequeued from its runqueue.
#[inline(always)]
pub fn settle_delay(state: &Context, weight: u64, now: u64) {
    let owed = settle(state, weight, now);
    state.lag().set(owed);
}

/// The lag a task that is not a member of any pack joins with: what it
/// saved when it left, less what its pack has paid off of a delayed debt
/// since. A pack that has emptied in between forgives the debt, as the pick
/// that runs the last delayed task would. The record is used up.
#[inline(always)]
fn settle(state: &Context, weight: u64, now: u64) -> i64 {
    let owed = state.lag().get();
    let [cid, reference, sum, generation] = state.delay();
    if cid == 0 {
        return owed;
    }
    state.set_delay([0; 4]);
    let cid = (cid - 1) as u32;
    if pack(Cid(cid as i32)).empty_generation().get() != generation {
        return 0;
    }
    let progress = reference_at(Cid(cid as i32), now).wrapping_sub(reference) as i64;
    delay_debt(owed, progress, sum, weight)
}

/// Make the task a member of `cid`'s pack, at its nice weight `nice` or at
/// the share its cgroup hierarchy gives it there, see cgroup.rs.
///
/// Lags are taken and placements made against the references projected to
/// `now`, pack_vref_place(), so that the running task's uncharged service
/// is not credited to the task as lag.
///
/// A task moving between packs keeps its lag against the pack it leaves.
/// One that was not a member gets back the lag it left with. Its vruntime
/// moves with the placement, and so does an unfinished request, unless the
/// placement is for a wakeup, `sleep`: fair.c keeps a deadline relative to
/// the vruntime only for a task dequeued without sleeping,
///
///	if (sched_feat(PLACE_REL_DEADLINE) && !task_sleep) {
///		se->deadline -= se->vruntime;
///		se->rel_deadline = 1;
///	}
///
/// and place_entity() issues a waking task a whole new request. Returns
/// false when the task already belonged to `cid`.
#[inline(always)]
pub fn place(state: &Context, cid: Cid, limit: u64, nice: u64, now: u64, sleep: bool) -> bool {
    if !valid(cid) {
        return false;
    }
    let member = state.member().get();
    if member != 0 && member_cid(member) == cid {
        return false;
    }
    let weight = cgroup::join_weight(state, cid, nice);
    let vtime = state.vtime().get();
    let (owed, old) = if member == 0 {
        (settle(state, weight, now), state.joined_weight().get())
    } else {
        let reference = reference_at(Cid(member_cid(member).raw() as i32), now);
        let old = member_weight(member);
        (lag(reference, vtime, lag_limit(limit, old)), old)
    };
    // A lag taken at another weight keeps its service in real time,
    // reweight_entity(): vlag = vlag * old / weight.
    let owed = if old != 0 && old != weight {
        vdiv(owed * old as i64, weight)
    } else {
        owed
    };
    leave(state);
    let reference = reference_for(Cid(cid.raw() as i32), now, weight);
    // PLACE_LAG inflates the lag by what the reference gives way as
    // the task joins; --no-place-lag places it as it is. An empty pack
    // takes the task at the reference with neither credit nor debt,
    // place_entity():
    //
    //	if (sched_feat(PLACE_LAG) && cfs_rq->nr_queued && se->vlag)
    //
    // There is nobody there to be ahead of or behind, and the lag
    // would only move the CID's clock.
    let members = pack(Cid(cid.raw() as i32)).weight().get();
    let target = if members == 0 {
        reference
    } else if crate::features::place_lag() {
        placed(reference, members, owed, weight)
    } else {
        placed(reference, 0, owed, weight)
    };
    let mut request = state.request();
    // Without PLACE_REL_DEADLINE a task placed anywhere is granted a
    // whole new request.
    if sleep || !crate::features::place_rel_deadline() {
        request.sleep();
    }
    request.rebase(vtime, target);
    state.set_request(request);
    state.vtime().set(target);
    let weight = cgroup::enter(state, cid, nice);
    join(state, cid, weight);

    true
}

/// Take the member over to `weight`, the share its cgroup hierarchy now
/// gives it: it leaves the pack's reference and joins again at the new
/// weight with its lag carried over, reweight_eevdf(), as fair.c does on
/// the tick through update_cfs_group(). The caller has charged it, and
/// reissues its request at the new weight.
#[inline(always)]
pub fn reweight(state: &Context, weight: u64, now: u64) {
    let member = state.member().get();
    let old = member_weight(member);
    if member == 0 || weight == 0 || old == weight {
        return;
    }
    let cid = member_cid(member);
    let reference = reference_at(Cid(cid.raw() as i32), now);
    let vtime = state.vtime().get();
    let owed = vdiv(reference.wrapping_sub(vtime) as i64 * old as i64, weight);
    leave_pack(state, false);
    let target = reference.wrapping_sub(owed as u64);
    let mut request = state.request();
    if !crate::features::place_rel_deadline() {
        request.sleep();
    }
    request.rebase(vtime, target);
    state.set_request(request);
    state.vtime().set(target);
    join(state, cid, weight);
}

/// Fold the service charged to the task since it last joined or was
/// charged into its pack's reference. Only the CID running the task
/// calls this, so the remainder needs no atomic.
#[inline(always)]
pub fn charge(state: &Context) {
    let member = state.member().get();
    if member == 0 {
        return;
    }
    let vtime = state.vtime().get();
    let distance = vtime.wrapping_sub(state.joined().get()) as i64;
    if distance <= 0 {
        return;
    }
    state.joined().set(vtime);
    let cid = member_cid(member);
    let sum = pack(Cid(cid.raw() as i32)).weight().get();
    if sum == 0 {
        return;
    }
    let (advance, rest) = fold(
        member_weight(member),
        distance as u64,
        sum,
        pack(Cid(cid.raw() as i32)).remainder().get(),
    );
    pack(Cid(cid.raw() as i32)).remainder().set(rest);
    if advance != 0 {
        pack(Cid(cid.raw() as i32)).reference().fetch_add(advance);
    }
}
