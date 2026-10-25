// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.

//! ops.select_cid(): where a waking or forked task goes, fair.c's
//! select_task_rq_fair(). select_cid() below is the whole decision, top to
//! bottom, and what it calls follows it in the order it calls them:
//!
//! ```text
//! select_cid()
//!   allowed_near()            a previous CID the task may still run on
//!   find_idlest_fork()        a fork is placed by load, find_idlest_cpu()
//!   wake_affine().raw()             search around the waker's CID or the previous
//!     wake_wide()?            each of the pair wakes many tasks: previous
//!     wake_affine_idle()      the waker's CID is idle: an interrupt
//!     sync, nothing queued?   the waker is about to sleep: its CID
//!     wake_affine_weight()    which of the two ends up better balanced
//!   take(target)              select_idle_sibling(): the target if idle,
//!   cached(prev)              the previous CID,
//!   cached(recent)            the recently used one
//!   select_idle_capacity()  where capacities differ, in place of the
//!                             scans below
//!   sched_idle_pick()    a CID that runs only SCHED_IDLE work
//!   idle_scan()          the idle scans around the target:
//!     select_idle_cpu(FullCore)  a whole idle core of its LLC
//!     select_idle_smt()       an idle sibling of the previous CID
//!     select_idle_cpu(AnyCpu) an idle CID of the LLC, its cluster first
//!     pick_wide()             --llc-extend: on to the node and the machine
//!   the target                nothing idle: queue the task there
//! ```
//!
//! The idle masks, the claim of an idle CID and the scans, pick() by scope
//! and kind, are scx_rustsched's cid_idle, the port of lib/cid_idle.h. What is
//! here is fair.c's policy over them: the order the steps run in and what
//! this scheduler knows that they need, the load of load.rs, the packs, and
//! the CIDs that run only SCHED_IDLE work.
//!
//! A claimed idle CID is returned as such, and ops.select_cid() dispatches
//! a wakeup there at once. A fork is left to enqueue, which joins the task
//! to its pack before it inserts it: inserted from here, the task would
//! weigh nothing until it runs, and a burst of forks would all see the same
//! group as the emptiest. Otherwise the task is queued on the target, where
//! its own CID runs it or an idle one steals it.
//!
//! Counterpart in scx_eevdf: idle.bpf.c.

use scx_rustsched::dsq::{self, Dsq};
use scx_rustsched::sched::{Cid, OptCid, WakeFlags};
use scx_rustsched::time;

use crate::{
    accounting::{
        ForkGroup, UTIL_HALF_LIFE_NS, fork_group_wins, time_before, wake_affine_weight, wake_wide,
    },
    cid_idle::{self, ANY_TIER, Kind, Scope},
    cids, load, pack, task,
    taskctx::{self, Context},
    tiers,
};
use scx_rustsched::task::Task;

/// Capacity of a CID; every CPU counts the same until capacities are known.
const CID_CAPACITY: u64 = 1024;
/// fork_group_stats() flags.
const FORK_CORE_LEVEL: u32 = 1 << 0;
const FORK_RESTRICTED: u32 = 1 << 1;
/// Where ops.select_cid() places a task.
pub enum Placement {
    /// On a CID that was idle and has been claimed for the task, which no
    /// other wakeup will pick: the task can be dispatched there at once.
    Claimed(i32),
    /// On a CID that has work, or whose claim was lost, to be queued.
    Queued(i32),
}

/// Words of a task's wakeup history, kept in its task context, see
/// taskctx.rs, and zeroed by `Wake::reset()`.
pub const WAKE_WORDS: usize = 4;
const WAKEE_DECAY_NS: u64 = 1_000_000_000;

scx_rustsched::arena_struct! {
    /// A task's wakeup history: record_wakee()'s count of how often the task
    /// switches wakees, when that was last decayed and the tid it last woke,
    /// and p->recent_used_cpu.
    pub struct Wake {
        wakee_flips: u64,
        wakee_decay_at: u64,
        last_wakee: u64,
        /// The CID + 1, or 0.
        recent_used: u64,
    }
}

impl Wake {
    /// Clear the history of a new task.
    #[inline(always)]
    pub fn reset(&self) {
        self.wakee_flips().set(0);
        self.wakee_decay_at().set(0);
        self.last_wakee().set(0);
        self.recent_used().set(0);
    }

    /// How often the task switches wakees, for wake_wide().
    #[inline(always)]
    pub fn flips(&self) -> u64 {
        self.wakee_flips().get()
    }

    /// record_wakee(): the task, a waker, wakes `wakee_tid` at `now`.
    /// Count how often it switches between wakees, halving the count every
    /// second.
    #[inline(always)]
    pub fn record_wakee(&self, wakee_tid: u64, now: u64) {
        let mut flips = self.wakee_flips().get();
        let mut decay_at = self.wakee_decay_at().get();
        let mut last = self.last_wakee().get();
        if time_before(decay_at.wrapping_add(WAKEE_DECAY_NS), now) {
            flips >>= 1;
            decay_at = now;
        }
        if last != wakee_tid {
            last = wakee_tid;
            flips += 1;
        }
        self.wakee_flips().set(flips);
        self.wakee_decay_at().set(decay_at);
        self.last_wakee().set(last);
    }

    /// p->recent_used_cpu: record `prev`, the CID the task last ran on, and
    /// return the one recorded before it, or -1.
    #[inline(always)]
    pub fn swap_recent(&self, prev: Cid) -> i32 {
        let old = self.recent_used().get();
        self.recent_used().set(prev.raw() as u32 as u64 + 1);
        old as i32 - 1
    }
}

/// Claim `cid` for `task` if it is idle and the task may run there, or the
/// sibling placement prefers in its place where the threads of a core
/// rank. Returns the CID claimed, or -1.
#[inline(always)]
fn take(task: &Task, cid: Cid) -> OptCid {
    if !cid.is_idle() || !cid_idle::allowed_by_mask(task, cid) {
        return OptCid::NONE;
    }
    let cid = cid_idle::smt_preferred(task, cid);
    if cid.claim() {
        OptCid::from_raw(cid.raw())
    } else {
        OptCid::NONE
    }
}

/// wake_affine_idle(): an idle waking CID, `this`, means the wakeup came
/// from interrupt context. Returns `prev` if it is idle too, `this` if
/// not, and -1 if `this` is not idle and the choice is still open.
#[inline(always)]
fn wake_affine_idle(this: Cid, prev: Cid) -> OptCid {
    if !this.is_idle() {
        return OptCid::NONE;
    }
    if prev.is_idle() {
        OptCid::from_raw(prev.raw())
    } else {
        OptCid::from_raw(this.raw())
    }
}

/// fits_capacity(): does a task of utilization `util`, in 0..=1024, fit
/// `cid`'s capacity with a fifth to spare?
#[inline(always)]
fn fits_capacity(util: u64, cid: Cid) -> bool {
    util * 1280 < cid.capacity() * 1024
}

/// The first CID in `start..end` that `task` may run on, or -1.
#[inline(never)]
fn first_allowed(task: &Task, start: u32, end: u32) -> OptCid {
    let mut found = -1;
    for value in crate::loops::range(start, end) {
        if cid_idle::allowed_by_mask(task, Cid(value as i32)) {
            found = value as i32;
            break;
        }
    }

    OptCid::from_raw(found)
}

/// An allowed CID as close to `cid` as possible, for a task whose affinity
/// no longer covers the CID it last ran on: its LLC, then anywhere, or -1.
/// The kernel leaves a sleeping task's CPU stale when its affinity changes.
#[inline(never)]
fn allowed_near(task: &Task, cid: Cid) -> OptCid {
    let (span, base) = cid.llc_span();
    if let Some(found) = first_allowed(task, base, base + span).get() {
        return OptCid::from_raw(found.raw());
    }
    first_allowed(task, 0, cids::count())
}

/// The CIDs of `cid`'s asymmetric capacity domain, `nr << 32 | base`: the
/// kernel's SD_ASYM_CPUCAPACITY_FULL width rounded up to the core, LLC,
/// node or machine holding `cid`, as scx_cid_domain_range() rounds it, and
/// the machine where capacity is forced and the kernel has none. 0 for
/// none.
#[inline(always)]
pub fn asym_range(cid: Cid) -> u64 {
    let span = cid.asym_span();
    if span == 0 && !tiers::forced_asym_capacity() {
        return 0;
    }
    let count = cids::count();
    let width = if span == 0 { count } else { span };
    let ends = cid.ends();
    let core = ends.core.saturating_sub(ends.core_base);
    if width <= core {
        return u64::from(core) << 32 | u64::from(ends.core_base);
    }
    let (llc_nr, llc_base) = cid.llc_span();
    if width <= llc_nr {
        return u64::from(llc_nr) << 32 | u64::from(llc_base);
    }
    let (node_nr, node_base) = cid.node_span();
    if width <= node_nr {
        return u64::from(node_nr) << 32 | u64::from(node_base);
    }
    u64::from(count) << 32
}

/// Does `cid`'s asymmetric capacity domain, `range`, keep shared state of
/// its own, asym_domain_shared()? fair.c keeps nr_idle_scan and
/// has_idle_cores on that domain when it is not built from NUMA, and on the
/// LLC otherwise. Domain widths are rounded to CID ranges: one wider than
/// the LLC and within a node is the node, one wider than the node is NUMA,
/// and one the width of the LLC shares the LLC's state.
#[inline(always)]
pub fn asym_domain_shared(cid: Cid, range: u64) -> bool {
    let nr = (range >> 32) as u32;
    (tiers::sched_asym_capacity() || tiers::forced_asym_capacity())
        && nr > cid.llc_span().0
        && nr <= cid.node_span().0
}

/// The budget of select_idle_capacity() for `cid`, whose asymmetric
/// capacity domain is `range`, nr:base: nr_idle_scan of that domain, of
/// the LLC where the domain shares the LLC's state, and u32::MAX for a
/// domain built from NUMA, which has none, or without SIS_UTIL.
#[inline(always)]
fn asym_scan_budget(cid: Cid, range: u64) -> u32 {
    let (base, nr) = (range as u32, (range >> 32) as u32);
    if !cid_idle::scan_bounded() || !cids::valid(cid) || !cids::valid(Cid(base as i32)) {
        return u32::MAX;
    }
    if nr > cid.node_span().0 {
        return u32::MAX;
    }
    if !asym_domain_shared(cid, range) {
        return cid.scan_budget();
    }
    match cid_idle::asym_budget(base as i32) {
        0 => nr,
        scan => scan - 1,
    }
}

/// wake_affine().raw(): the CID to look for an idle one around.
#[inline(never)]
fn wake_affine(task: &Task, state: &Context, prev: Cid, wake_flags: WakeFlags, now: u64) -> Cid {
    let this = Cid::current();
    if !wake_flags.contains(WakeFlags::TTWU) || !pack::valid(this) {
        return prev;
    }
    let waker = Task::current();
    let waker_state = match waker {
        Some(waker) => taskctx::lookup_optional(waker),
        None => None,
    };
    if let Some(waker_state) = &waker_state {
        waker_state.wake().record_wakee(task.tid(), now);
    }
    if !cid_idle::allowed_by_mask(task, this) || !prev.same_node(this) {
        return prev;
    }
    if let Some(waker_state) = &waker_state {
        let factor = u64::from(this.llc_span().0);
        if wake_wide(waker_state.wake().flips(), state.wake().flips(), factor) {
            return prev;
        }
    }
    // An idle waking CID means the wakeup came from interrupt context:
    // keep an idle previous CID when both are.
    if let Some(cid) = wake_affine_idle(this, prev).get() {
        return cid;
    }
    let sync = crate::features::wake_sync()
        && wake_flags.contains(WakeFlags::SYNC)
        && waker.is_some_and(|waker| !task::exiting(waker));
    // A running CID with nothing queued is nr_running == 1: the waker
    // is about to sleep and hand it over.
    if sync && dsq::nr_queued(Dsq::Local) == 0 && !this.has_queued() {
        return this;
    }
    if crate::NO_WA_WEIGHT.get() || prev.is_idle() {
        return prev;
    }
    let waker_load = if !sync {
        None
    } else if let Some(waker_state) = &waker_state
        && let Some(waker) = waker
    {
        Some(load::task_load(
            waker,
            waker_state,
            crate::effective_weight(waker, waker_state),
            now,
        ))
    } else {
        Some(0)
    };
    let this_load = load::cid_wake_load(this).max(pack::weight(this));
    let prev_load = load::cid_wake_load(prev).max(pack::weight(prev));
    let task_load = load::task_load(task, state, crate::effective_weight(task, state), now);
    let same_core = cid_idle::smt() && prev.same_core(this);
    if wake_affine_weight(this_load, prev_load, waker_load, task_load, same_core) {
        this
    } else {
        prev
    }
}

/// Does the task of `state` fit `cid`'s capacity, fits_capacity()? Always,
/// unless placement follows capacity.
#[inline(always)]
fn task_fits(state: &Context, cid: Cid, now: u64) -> bool {
    !tiers::asym_capacity() || fits_capacity(load::task_util(state, now), cid)
}

/// asym_fits_cpu(): with asymmetric capacity, a CPU the task fits, on a
/// whole idle core on SMT machines.
#[inline(always)]
fn asym_fits(state: &Context, cid: Cid, now: u64) -> bool {
    (!tiers::sched_asym_capacity() && !tiers::forced_asym_capacity())
        || task_fits(state, cid, now) && (!cid_idle::smt() || cid.is_core_idle())
}

/// choose_sched_idle_rq(): a task that is not SCHED_IDLE itself may share a
/// CID whose runqueue holds only SCHED_IDLE work rather than wait behind a
/// normal task elsewhere. Remote queues are not counted by policy, so only
/// the exact cheap case counts: SCHED_IDLE work running, nothing queued.
/// Work in an idle cgroup counts as SCHED_IDLE work, the way fair.c counts
/// it in h_nr_idle.
#[inline(always)]
fn sched_idle_target(task: &Task, cid: Cid) -> bool {
    pack::curr_sched_idle(cid)
        && task::task_policy(task) != task::SCHED_IDLE
        && !cid.is_idle()
        && !cid.has_queued()
        && cid_idle::allowed_by_mask(task, cid)
}

/// The scan of select_idle_cpu() takes a CPU that runs only SCHED_IDLE work
/// as readily as an idle one, choose_idle_cpu(), and select_idle_core()
/// keeps one as the fallback when no core is wholly idle. The idle scans
/// read the idle masks, which hold no such CID, so find the first one here,
/// over the walk and the windows the idle scan covers: the same order, and
/// the same SIS_UTIL budget counted on the CIDs `task` may run on. With
/// `has_idle_core` the walk is not bounded, as in fair.c. A global
/// function, so the loop is verified once.
#[scx_rustsched::global]
pub fn sched_idle_scan(task: &Task, target: Cid, cluster_first: u32, has_idle_core: u32) -> OptCid {
    // select_idle_cpu() gives up on a zero SIS_UTIL budget before any walk.
    let budget = target.scan_budget();
    if !pack::any_sched_idle() || !pack::valid(target) || budget == 0 {
        return OptCid::NONE;
    }
    let budget = if has_idle_core != 0 { u32::MAX } else { budget };
    let windows = cid_idle::llc_windows(task, target, budget, cluster_first);
    // A window is cut short only where the budget ran out, which leaves the
    // ones after it empty: their CIDs are consecutive in the walk.
    let nr = (windows & cid_idle::WINDOW_MASK)
        + ((windows >> cid_idle::WINDOW_BITS) & cid_idle::WINDOW_MASK)
        + (windows >> (2 * cid_idle::WINDOW_BITS));
    let mut found = -1;
    for value in crate::loops::range(0, nr as u32) {
        let cid = cid_idle::llc_walk_cid(target, cluster_first != 0, value).raw();
        if !pack::valid(Cid(cid)) {
            break;
        }
        if sched_idle_target(task, Cid(cid)) {
            found = cid;
            break;
        }
    }

    OptCid::from_raw(found)
}

/// select_idle_cpu() takes the first CID of its walk that is idle or runs
/// only SCHED_IDLE work. The idle scan cannot see the latter, so find the
/// first of them and take it if no idle CID comes before it in the walk.
/// While the LLC has an idle core, a core wins wherever it is and such a
/// CID is only the fallback. Without an idle core, select_idle_smt() comes
/// before the walk and takes a sibling of `prev` that is idle or runs only
/// SCHED_IDLE work. Returns the CID to place the task on in the lower 32
/// bits, -1 to go on to the idle scan, and the fallback found plus one in
/// the upper 32. A global function, so that ops.select_cid() is verified
/// with one call instead of the walks; `task` is tagged trusted by
/// build.rs.
#[scx_rustsched::global]
pub fn sched_idle_pick(task: &Task, prev: Cid, target: Cid) -> u64 {
    if !pack::valid(target) {
        return u64::from(u32::MAX);
    }
    let cluster_first = target.cluster_active();
    let has_idle_core = cid_idle::smt() && target.has_idle_cores();
    if !has_idle_core && !tiers::asym_capacity() {
        if let Some(cid) = select_idle_smt_any(task, prev, target).get() {
            return u64::from(cid.raw() as u32);
        }
    }
    let sched_idle = sched_idle_scan(
        task,
        target,
        u32::from(cluster_first),
        u32::from(has_idle_core),
    )
    .raw();
    if sched_idle < 0 {
        return u64::from(u32::MAX);
    }
    if !has_idle_core {
        let idle = cid_idle::probe(task, target).raw();
        if idle < 0
            || cid_idle::llc_walk_pos(target, cluster_first, Cid(sched_idle))
                < cid_idle::llc_walk_pos(target, cluster_first, Cid(idle))
        {
            return u64::from(sched_idle as u32);
        }
    }
    (sched_idle as u64 + 1) << 32 | u64::from(u32::MAX)
}

/// select_idle_smt() while some CID runs SCHED_IDLE work: choose_idle_cpu()
/// takes the first sibling of `prev` that is idle or runs only such work,
/// in sibling order. An idle one is claimed. The plain select_idle_smt() of
/// the idle scan looks at idle siblings only and serves the common case,
/// where there is no SCHED_IDLE work to find.
#[inline(never)]
fn select_idle_smt_any(task: &Task, prev: Cid, target: Cid) -> OptCid {
    if !cid_idle::smt() || !pack::valid(prev) || !pack::valid(target) || !prev.same_idle_llc(target)
    {
        return OptCid::NONE;
    }
    let ends = prev.ends();
    let mut found = -1;
    for value in crate::loops::range(ends.core_base, ends.core) {
        let sibling = Cid(value as i32);
        if sibling == prev || !cid_idle::allowed_by_mask(task, sibling) {
            continue;
        }
        if sibling.is_idle() {
            if let Some(cid) = take(task, sibling).get() {
                found = mark(cid, true);
                break;
            }
            continue;
        }
        if sched_idle_target(task, sibling) {
            found = sibling.raw();
            break;
        }
    }
    OptCid::from_raw(found)
}

/// The idle search ops.enqueue() makes for a task ops.select_cid() did not
/// place, pick_idle_cid(p, prev_cid, prev_cid): the scan of
/// select_idle_sibling() around `prev`, its CID. A task bound to its CPU can
/// only take that one. Returns the CID claimed, or -1. A global function, so
/// that ops.enqueue() pays for the scan only in instructions it runs.
#[scx_rustsched::global]
pub fn enqueue_pick(task: &Task, state: Context, prev: Cid, now: u64) -> OptCid {
    if state.address() == 0 || !pack::valid(prev) {
        return OptCid::NONE;
    }
    if task::pinned(task) {
        return take(task, prev);
    }
    pick_by_capacity(task, &state, prev, prev, now)
}

/// Marks a CID the placement helpers return as claimed idle for the task,
/// which ops.select_cid() then dispatches to at once. CIDs stay below it.
pub(crate) const CLAIMED: u32 = 1 << 30;

/// A CID, `cid`, with CLAIMED set if `claimed`.
#[inline(always)]
fn mark(cid: Cid, claimed: bool) -> i32 {
    if claimed {
        cid.raw() | CLAIMED as i32
    } else {
        cid.raw()
    }
}

/// cached(): the CID is held back for after the scan around the target.
const DEFERRED: i32 = -2;

/// The previous CID or the recently used one, `cid`, which select_idle_sibling()
/// tries before it scans: claim it if it is idle, shares the target's LLC
/// and the task fits there, or take it if it runs only SCHED_IDLE work. One
/// outside the target's share domain, cpus_share_resources(), is held back
/// so that the scan around the target searches its own cluster first.
/// Returns the CID, marked if claimed, DEFERRED, or -1.
#[inline(never)]
fn cached(task: &Task, state: &Context, cid: Cid, target: Cid, now: u64) -> i32 {
    if !cid.same_idle_llc(target) || !asym_fits(state, cid, now) {
        return -1;
    }
    let share = cid.same_share_domain(target);
    let mut found = -1;
    if cid.is_idle() && cid_idle::allowed_by_mask(task, cid) {
        if share {
            if let Some(claimed) = take(task, cid).get() {
                return mark(claimed, true);
            }
        } else {
            found = DEFERRED;
        }
    }
    if sched_idle_target(task, cid) {
        if share {
            return cid.raw();
        }
        found = DEFERRED;
    }
    found
}

/// Is `cid` idle with nothing queued, idle as fork placement counts it?
#[scx_rustsched::global]
pub fn cid_vacant(cid: Cid) -> u32 {
    u32::from(cid.is_idle() && !cid.has_queued())
}

/// Is `task` allowed on fewer CPUs than there are?
#[inline(always)]
fn restricted(task: &Task) -> bool {
    task.nr_cpus_allowed() < Cid::nr_cpus()
}

/// Tasks runnable on `cid`: queued, on its local DSQ, or running there.
/// Global functions, verified once on their own: the fork scans call them
/// for every CID of a domain.
#[scx_rustsched::global]
pub fn cid_runnable(cid: Cid) -> u32 {
    let queued = cid.nr_queued() as u32;
    let local = dsq::nr_queued(Dsq::LocalOn(cid));
    let running = pack::running(cid);
    let mut nr = queued + local + u32::from(running);
    // A running task alone in its pack is counted in the queue too
    // while it is being handed over.
    if running && queued + local != 0 && pack::weight(cid) == pack::curr_weight(cid) {
        nr -= 1;
    }
    // Cover a task between its dispatch and ops.running().
    if nr == 0 && pack::weight(cid) != 0 {
        nr = 1;
    }
    nr
}

/// Sum the CIDs from `range & 0xffffffff` to `range >> 32` into `group`,
/// the group that holds `anchor` being the local one. `flags` says whether
/// the groups are cores and whether `task` is restricted.
///
/// A global function, verified once on its own: as a static one its loop was
/// walked again for every group in every state of the caller's. The loader's
/// build tags `task` as a trusted argument, which a global function needs to
/// take a kernel pointer and which Rust has no syntax for.
#[scx_rustsched::global]
pub fn fork_group_stats(
    task: &Task,
    range: u64,
    anchor: Cid,
    flags: u32,
    group: Option<&mut ForkGroup>,
) -> u32 {
    let (base, end) = (range as u32, (range >> 32) as u32);
    let core_level = flags & FORK_CORE_LEVEL != 0;
    let restricted = flags & FORK_RESTRICTED != 0;
    let now = time::now();
    let mut recent = if core_level {
        load::fork_placed_at(Cid(base as i32), true)
    } else {
        0
    };
    if recent != 0 && now.wrapping_sub(recent) as i64 >= i64::from(UTIL_HALF_LIFE_NS) {
        recent = 0;
    }
    let mut stats = ForkGroup {
        base,
        nr: end - base,
        idle: 0,
        load: 0,
        util: 0,
        cap: 0,
        recent,
        runnable: 0,
        allowed: u32::from(!restricted),
        local: anchor >= Cid(base as i32) && ((anchor).raw() as u32) < end,
    };
    for value in crate::loops::range(base, end) {
        let cid = Cid(value as i32);
        stats.cap += CID_CAPACITY;
        if restricted {
            if !cid_idle::allowed_by_mask(task, cid) {
                continue;
            }
            stats.allowed += 1;
            stats.runnable += cid_runnable(cid);
        }
        stats.idle += cid_vacant(cid);
        if restricted {
            stats.load += load::cid_load(cid, now);
            stats.util += load::cid_util(cid, now);
        } else {
            stats.load += pack::weight(cid);
        }
    }
    // A global function's pointer argument may be NULL to the verifier.
    if let Some(group) = group {
        *group = stats;
    }

    0
}

/// The idlest child group, LLCs or cores per `core_level`, of the `nr` CIDs
/// from `base`, as `nr << 32 | base`, or the range itself if none qualifies:
/// find_idlest_group() over one level of the fork domain. Packed, since a
/// returned pair would take a hidden sixth argument, one past BPF's limit.
/// The groups are walked by their range ends and each summed apart, which
/// keeps the verifier's paths through either loop short.
#[inline(never)]
fn fork_pick_child(task: &Task, base: u32, nr: u32, anchor: Cid, core_level: bool) -> u64 {
    let restricted = restricted(task);
    let flags =
        if core_level { FORK_CORE_LEVEL } else { 0 } | if restricted { FORK_RESTRICTED } else { 0 };
    let end = base + nr;
    let mut start = base;
    let mut best: Option<ForkGroup> = None;
    // Where each group is summed. The call below writes it whole.
    let mut group = ForkGroup::default();
    for _ in crate::loops::range(0, nr) {
        if start >= end {
            break;
        }
        let ends = Cid(start as i32).ends();
        // The next start is only ever a range end loaded from the
        // arena, never derived from this one, so that the verifier sees
        // an unknown value and the loop converges.
        let group_end = if core_level { ends.core } else { ends.llc };
        if group_end <= start {
            break;
        }
        let group_end = group_end.min(end);
        fork_group_stats(
            task,
            u64::from(group_end) << 32 | u64::from(start),
            anchor,
            flags,
            Some(&mut group),
        );
        if fork_group_wins(&group, best.as_ref(), restricted, core_level) {
            best = Some(group);
        }
        start = group_end;
    }
    match best {
        Some(best) => u64::from(best.nr) << 32 | u64::from(best.base),
        None => u64::from(nr) << 32 | u64::from(base),
    }
}

/// fair.c's choice inside the idlest group: the idle CID that has been least
/// busy, the one idle longest on a tie, or else the least loaded CID.
#[inline(never)]
fn fork_pick_cid(task: &Task, base: u32, nr: u32) -> OptCid {
    let now = time::now();
    let restricted = restricted(task);
    let (mut best_idle, mut idle_util, mut idle_stamp) = (-1, 0, 0);
    let (mut best, mut best_load, mut best_recent) = (-1, 0, 0);
    for value in crate::loops::range(base, base + nr) {
        let cid = Cid(value as i32);
        if restricted && !cid_idle::allowed_by_mask(task, cid) {
            continue;
        }
        if cid_vacant(cid) != 0 {
            let util = load::cid_util(cid, now);
            let stamp = load::idle_stamp(cid);
            if best_idle < 0 || util < idle_util || (util == idle_util && stamp > idle_stamp) {
                (best_idle, idle_util, idle_stamp) = (cid.raw(), util, stamp);
            }
            continue;
        }
        let cid_load = if restricted {
            load::cid_load(cid, now)
        } else {
            pack::weight(cid)
        };
        // A short-lived child leaves the pack before the next fork.
        let recent = load::fork_placed_at(cid, false);
        if best < 0
            || cid_load < best_load
            || (!restricted && cid_load == best_load && recent < best_recent)
        {
            (best, best_load, best_recent) = (cid.raw(), cid_load, recent);
        }
    }

    if best_idle >= 0 {
        OptCid::from_raw(best_idle)
    } else {
        OptCid::from_raw(best)
    }
}

/// Descend the fork domain to the idlest CPU, find_idlest_cpu() for
/// SD_BALANCE_FORK: the anchor's node, then its idlest LLC, then its idlest
/// core, then a CID in that. A fork is placed by load; fair.c never runs the
/// idle sibling search for one, which packs every child near its parent.
#[inline(never)]
fn find_idlest_fork(task: &Task, anchor: Cid) -> OptCid {
    let (mut nr, mut base) = anchor.node_span();
    let mut anchor = anchor;
    let (llc_nr, _) = anchor.llc_span();
    if nr > llc_nr {
        let child = fork_pick_child(task, base, nr, anchor, false);
        (base, nr) = (child as u32, (child >> 32) as u32);
    }
    if ((anchor).raw() as u32) < base || anchor.raw() as u32 >= base + nr {
        anchor = Cid(base as i32);
    }
    let ends = anchor.ends();
    if nr > ends.core.saturating_sub(ends.core_base) {
        let child = fork_pick_child(task, base, nr, anchor, true);
        (base, nr) = (child as u32, (child >> 32) as u32);
    }
    let found = fork_pick_cid(task, base, nr);
    if let Some(cid) = found.get() {
        load::fork_placed(cid, Cid(cid.ends().core_base as i32), time::now());
    }
    found
}

/// capacity_rank(): a CID neither idle nor running only SCHED_IDLE
/// work, the ranks of the others, best first, and whether the CID is idle.
const UNRANKED: u32 = u32::MAX;
const RANK_FIT: u32 = 3;
const RANKED_IDLE: u32 = 1 << 8;

/// How select_idle_capacity() ranks `cid` for a task of utilization
/// `util`: choose_idle_cpu() takes it if it is idle or runs only SCHED_IDLE
/// work, which never counts as an idle core and is not claimed. RANK_FIT
/// for an idle core the task fits, or any such CID without
/// `has_idle_core`; otherwise an idle-core misfit, then a fitting SMT
/// thread, then a thread misfit, 0 to 2, with RANKED_IDLE if idle. A global
/// function, so that the scan's loop is verified with one call per CID;
/// `task` is tagged trusted by build.rs.
#[scx_rustsched::global]
pub fn capacity_rank(task: &Task, cid: Cid, has_idle_core: u32, util: u64) -> u32 {
    if !pack::valid(cid) {
        return UNRANKED;
    }
    let idle = cid.is_idle();
    if !idle && !sched_idle_target(task, cid) {
        return UNRANKED;
    }
    let core = has_idle_core == 0 || (idle && cid.is_core_idle());
    let fits = fits_capacity(util, cid);
    let rank = if core && fits {
        RANK_FIT
    } else if core {
        0
    } else if fits {
        1
    } else {
        2
    };
    if idle { rank | RANKED_IDLE } else { rank }
}

/// select_idle_capacity(): an idle CID of `target`'s asymmetric capacity
/// domain for `task`, of utilization `util`, walking CPU numbers from
/// `target`'s and wrapping, since that is fair.c's order and CIDs follow
/// the topology instead. The first idle CID the task fits wins, on a whole
/// idle core if the domain's hint says it has one; failing that, an idle
/// core it does not fit, then an SMT thread it fits, then any thread, the
/// biggest of the best kind. Without an idle core the walk is bounded by
/// the domain's SIS_UTIL budget, counted on the CIDs the task may run on.
/// The CID is claimed if it can be; fair.c returns the CPU it settles on
/// without claiming anything, so one lost to another wakeup is returned
/// all the same. -1 if none. A global function; `task` is tagged trusted
/// by build.rs.
#[scx_rustsched::global]
pub fn select_idle_capacity(task: &Task, target: Cid, util: u64) -> i32 {
    if target < Cid(0) || target.raw() as u32 >= cids::count() {
        return OptCid::NONE.raw();
    }
    let range = asym_range(target);
    let (base, nr) = (range as u32, (range >> 32) as u32);
    if nr == 0 || (cid_idle::idle_empty() && !pack::any_sched_idle()) {
        return OptCid::NONE.raw();
    }
    // A zero budget ends select_idle_capacity() before the hint.
    let mut budget = asym_scan_budget(target, range);
    if budget == 0 {
        return OptCid::NONE.raw();
    }
    let shared = asym_domain_shared(target, range);
    let has_idle_core = cid_idle::smt() && cid_idle::asym_has_idle_core(target, range, shared);
    let cpus = Cid::nr_cpus();
    let start = target.cpu().max(0) as u32;
    let (mut found, mut best, mut best_rank, mut best_cap) = (-1, -1, 3, 0);
    let mut best_idle = false;
    for value in crate::loops::range(0, cpus) {
        let mut cpu = start + value;
        if cpu >= cpus {
            cpu -= cpus;
        }
        let cid = Cid::from_cpu(cpu as i32);
        if cid < Cid(base as i32)
            || cid >= Cid((base + nr) as i32)
            || !cid_idle::allowed_by_mask(task, cid)
        {
            continue;
        }
        // The budget is spent only without an idle core.
        if !has_idle_core && budget != u32::MAX {
            if budget == 0 {
                break;
            }
            budget -= 1;
        }
        let ranked = capacity_rank(task, cid, u32::from(has_idle_core), util);
        if ranked == UNRANKED {
            continue;
        }
        let (rank, idle) = (ranked & 0xff, ranked & RANKED_IDLE != 0);
        if rank == RANK_FIT {
            found = cid.raw();
            if idle {
                let preferred = cid_idle::smt_preferred(task, cid).raw();
                if Cid(preferred).claim() {
                    found = mark(Cid(preferred), true);
                }
            }
            break;
        }
        let capacity = cid.capacity();
        if best < 0 || rank < best_rank || (rank == best_rank && capacity > best_cap) {
            (best, best_rank, best_cap, best_idle) = (cid.raw(), rank, capacity, idle);
        }
    }
    if found >= 0 {
        return OptCid::from_raw(found).raw();
    }
    // This path never reaches the whole-core scan that clears a stale
    // hint, so clear it here unless an idle core ranked best, as the
    // tail of select_idle_capacity() does.
    if has_idle_core && best_rank > 0 {
        cid_idle::asym_clear_idle_cores(target, range, shared);
    }
    if best < 0 || !best_idle {
        return OptCid::from_raw(best).raw();
    }
    let preferred = cid_idle::smt_preferred(task, Cid(best)).raw();
    if Cid(preferred).claim() {
        (OptCid::from_raw(mark(Cid(preferred), true))).raw()
    } else {
        OptCid::from_raw(best).raw()
    }
}

/// --llc-extend: an idle CID of `kind` past `target`'s LLC, which fair.c
/// does not look for: its LLC, then its node, then the machine, each
/// skipped where it holds the same CIDs as the one before it. Out of line:
/// three passes call it.
#[inline(never)]
fn pick_wide(task: &Task, target: Cid, kind: Kind, tier: u32) -> OptCid {
    if let Some(cid) = cid_idle::pick_in_tier(task, target, Scope::Llc, kind, tier).get() {
        return OptCid::from_raw(cid.raw());
    }
    if !cid_idle::scope_same(target, Scope::Llc, Scope::Node) {
        if let Some(cid) = cid_idle::pick_in_tier(task, target, Scope::Node, kind, tier).get() {
            return OptCid::from_raw(cid.raw());
        }
    }
    if cid_idle::scope_same(target, Scope::Node, Scope::Anywhere) {
        return OptCid::NONE;
    }
    cid_idle::pick_in_tier(task, target, Scope::Anywhere, kind, tier)
}

/// The idle scans around `target`, in fair.c's order:
///   1. select_idle_core(): a whole idle core of the LLC, if its hint says
///      there is one; a zero SIS_UTIL budget ends select_idle_cpu() before
///      it looks at the hint, and leaves the hint as it is
///   2. --llc-extend with --smt-whole-core: a whole idle core anywhere,
///      while any LLC's hint says it has one
///   3. select_idle_smt(): an idle sibling of `prev`, without a hinted idle
///      core and unless placement follows capacity
///   4. select_idle_cpu(): any idle CID of the LLC, its cluster first,
///      within the SIS_UTIL budget
///   5. --llc-extend: a whole idle core anywhere, unless pass 2 ran
///   6. --llc-extend: any idle CID anywhere
/// A walk of the LLC that SIS_UTIL bounded ends the search after pass 4,
/// where select_idle_cpu() returns -1: every pass after it would cover the
/// LLC again unbounded. `tier` restricts the scans to one capacity tier.
/// Returns the CID claimed, or -1.
#[inline(always)]
fn scan_passes(task: &Task, target: Cid, prev: Cid, tier: u32, extend: bool) -> OptCid {
    let has_idle_core = cid_idle::smt() && target.has_idle_cores();
    if has_idle_core && target.scan_budget() != 0 {
        if let Some(cid) = cid_idle::select_idle_cpu(task, target, Kind::FullCore, tier).get() {
            return OptCid::from_raw(cid.raw());
        }
        // A pass restricted to one capacity tier says nothing of the
        // others.
        if tier == ANY_TIER {
            cid_idle::clear_idle_cores(target);
        }
    }
    let whole_scanned =
        extend && cid_idle::smt() && cid_idle::smt_whole_core() && cid_idle::any_idle_core();
    if whole_scanned {
        if let Some(cid) = pick_wide(task, target, Kind::FullCore, tier).get() {
            return OptCid::from_raw(cid.raw());
        }
    }
    if !has_idle_core && !tiers::asym_capacity() {
        if let Some(cid) = cid_idle::select_idle_smt(task, prev, target).get() {
            return OptCid::from_raw(cid.raw());
        }
    }
    let cid = cid_idle::select_idle_cpu(task, target, Kind::AnyCpu, tier).raw();
    if cid >= 0 || !extend || target.scan_budget() < target.llc_span().0 {
        return OptCid::from_raw(cid);
    }
    if cid_idle::smt() && !whole_scanned {
        if let Some(cid) = pick_wide(task, target, Kind::FullCore, tier).get() {
            return OptCid::from_raw(cid.raw());
        }
    }
    pick_wide(task, target, Kind::AnyCpu, tier)
}

/// The idle scans of select_idle_sibling() around `target` for `task`,
/// which last ran on `prev`: scan_passes(), in the target's LLC alone if
/// `llc_only`. A task that cannot migrate takes `target` or nothing. A
/// global function, verified once rather than at each step of a capacity
/// tier walk; `task` is tagged trusted by build.rs.
#[scx_rustsched::global]
pub fn idle_scan(task: &Task, target: Cid, llc_only: u32, tier: u32, prev: Cid) -> OptCid {
    if task.as_ptr().is_null() {
        return OptCid::NONE;
    }
    if task::migration_disabled(task) || cids::count() == 0 {
        return if target.claim() {
            OptCid::from_raw(target.raw())
        } else {
            OptCid::NONE
        };
    }
    // Nothing idle at all is the common case under load: say so
    // without walking the passes.
    if cid_idle::idle_empty() {
        return OptCid::NONE;
    }
    let found = scan_passes(task, target, prev, tier, llc_only == 0).raw();
    // The scan claimed what it found; a preferred sibling takes its
    // place.
    cid_idle::claim_preferred(task, found)
}

/// idle_scan(), fastest capacity tier first when placement follows
/// capacity, as pick_idle_cid_topology() walks them: an idle previous CID
/// the task fits wins first, keeping it where its cache is warm, and each
/// tier is then scanned around `target`.
#[inline(always)]
fn pick_by_capacity(task: &Task, state: &Context, prev: Cid, target: Cid, now: u64) -> OptCid {
    let llc_only = !crate::LLC_EXTEND.get();
    if !tiers::asym_capacity() {
        return idle_scan(task, target, u32::from(llc_only), ANY_TIER, prev);
    }
    if task_fits(state, prev, now) {
        if let Some(cid) = take(task, prev).get() {
            return OptCid::from_raw(cid.raw());
        }
    }
    let mut found = -1;
    for value in crate::loops::range(0, tiers::nr_capacity_tiers()) {
        found = idle_scan(task, target, u32::from(llc_only), value, prev).raw();
        if found >= 0 {
            break;
        }
    }
    OptCid::from_raw(found)
}

/// The placement on a CID that may carry CLAIMED.
#[inline(always)]
fn placed(cid: i32) -> Placement {
    if cid >= 0 && cid & CLAIMED as i32 != 0 {
        Placement::Claimed(cid & !(CLAIMED as i32))
    } else {
        Placement::Queued(cid)
    }
}

/// ops.select_cid() for a task with a context, select_task_rq_fair().
#[inline(always)]
pub fn select_cid(
    task: &Task,
    state: &Context,
    prev: Cid,
    wake_flags: WakeFlags,
    now: u64,
) -> Placement {
    // The kernel leaves a sleeping task's CPU stale when its affinity
    // changes: start from a CID the task may run on.
    let mut prev = prev;
    if !cid_idle::allowed_by_mask(task, prev) {
        let Some(near) = allowed_near(task, prev).get() else {
            return Placement::Queued(prev.raw());
        };
        prev = near;
    }
    // find_idlest_cpu(): a fork is placed by load, from the waker's
    // CID down to the idlest CID of the idlest core. The waker's CID is
    // read where it is needed: wake_affine() reads its own.
    if wake_flags.contains(WakeFlags::FORK) {
        let this = Cid::current();
        let anchor = if pack::valid(this) { this } else { prev };
        if let Some(cid) = find_idlest_fork(task, anchor).get() {
            if let Some(claimed) = take(task, cid).get() {
                return Placement::Claimed(claimed.raw());
            }
            return Placement::Queued(cid.raw());
        }
    }

    // WF_CURRENT_CPU: the waker is about to hand the wakee the CPU it
    // is on.
    if wake_flags.contains(WakeFlags::CURRENT_CPU) {
        let this = Cid::current();
        if cid_idle::allowed_by_mask(task, this) {
            return Placement::Queued(this.raw());
        }
    }

    // wake_affine().raw(): search around the waker's CID or the previous one.
    let target = wake_affine(task, state, prev, wake_flags, now);
    if !wake_flags.contains(WakeFlags::TTWU) {
        return Placement::Queued(target.raw());
    }

    // select_idle_sibling(): the target itself, if idle.
    if asym_fits(state, target, now) {
        if let Some(cid) = take(task, target).get() {
            return Placement::Claimed(cid.raw());
        }
        if sched_idle_target(task, target) {
            return Placement::Queued(target.raw());
        }
    }

    // The previous CID, where the task's cache is.
    let mut deferred_prev = -1;
    if prev != target {
        let cid = cached(task, state, prev, target, now);
        if cid >= 0 {
            return placed(cid);
        }
        if cid == DEFERRED {
            deferred_prev = prev.raw();
        }
    }

    // The recently used CID, p->recent_used_cpu, rotated where fair.c
    // rotates it.
    let mut deferred_recent = -1;
    let recent = state.wake().swap_recent(prev);
    if recent >= 0 && recent != prev.raw() && recent != target.raw() {
        let cid = cached(task, state, Cid(recent), target, now);
        if cid >= 0 {
            return placed(cid);
        }
        if cid == DEFERRED {
            deferred_recent = recent;
        }
    }

    // select_idle_capacity(): with an asymmetric capacity domain around
    // the target, fair.c returns what it finds there, or the target,
    // and never runs the scans below.
    if tiers::asym_capacity()
        && (tiers::sched_asym_capacity() || tiers::forced_asym_capacity())
        && asym_range(target) != 0
    {
        let cid = select_idle_capacity(task, target, load::task_util(state, now));
        if cid < 0 {
            return Placement::Queued(target.raw());
        }
        return placed(cid);
    }

    // choose_sched_idle_rq(): a CID that runs only SCHED_IDLE work is
    // taken where the scans would take it, and kept as the fallback
    // while the LLC has an idle core.
    let mut sched_idle = -1;
    if pack::any_sched_idle() {
        let found = sched_idle_pick(task, prev, target);
        if found as u32 as i32 >= 0 {
            return placed(found as u32 as i32);
        }
        sched_idle = (found >> 32) as i32 - 1;
    }

    // select_idle_core(), select_idle_smt(), select_idle_cpu(): the
    // idle scans around the target, see scan_passes().
    if let Some(cid) = pick_by_capacity(task, state, prev, target, now).get() {
        return Placement::Claimed(cid.raw());
    }
    if sched_idle >= 0 {
        return Placement::Queued(sched_idle);
    }

    // The previous and the recently used CID held back for the scan,
    // in that order: claimed if still idle, returned anyway if not, as
    // fair.c hands them back without looking again.
    let held = if deferred_prev >= 0 {
        deferred_prev
    } else {
        deferred_recent
    };
    if held >= 0 {
        if let Some(claimed) = take(task, Cid(held)).get() {
            return Placement::Claimed(claimed.raw());
        }
        return Placement::Queued(held);
    }

    // Nothing idle: queue the task on the target.
    Placement::Queued(target.raw())
}
