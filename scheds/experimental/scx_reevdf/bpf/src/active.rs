// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.

//! Active balance, for CPUs of equal capacity: moving the task a queue walk
//! cannot reach, because it is running.
//!
//! balance.rs and newidle.rs move tasks that wait in a queue: they compare
//! loads or look for an idle CID, and pop. A running task is in no queue,
//! so there is nothing to pop, and moving it takes the protocol below
//! between the two CPUs. All three keep their per-CID state in the table
//! newidle.rs declares.
//!
//! On an SMT machine a task running beside a busy sibling while a whole core
//! sits idle belongs on that core, and nothing of it is queued to be pulled.
//! fair.c stops the source CPU with a stopper thread; here the two sides
//! hand the task over across their own callbacks:
//!
//! ```text
//!   idle destination                         busy source
//!     reserve its own interval
//!     ---------------- kick ----------------> ops.dispatch() takes the
//!                                             request, revalidates it and
//!                                             lets the task's slice end
//!     <------------- ops.enqueue() places the task on the destination,
//!                    if it is still idle, by the ordinary rules
//! ```
//!
//! The reservation, a compare and exchange on the destination's pending
//! state, keeps two sources from aiming at one idle CID, and the request
//! written into the source keeps two destinations from asking one source.
//! The interval and its backoff live on the destination, where fair.c keeps
//! them for the CPU running the balance.
//!
//! Either side starts it. A source tick that sees its task belongs on an
//! idle whole core reserves that core and kicks it, and a tick with work
//! queued kicks an idle peer to pull it, nohz_balancer_kick(). A kicked
//! destination that finds nothing queued to pull asks the source with the
//! most to gain for its running task.
//!
//! With asymmetric packing, an idle CID of a better packing tier also takes
//! a busy task off a worse one, as fair.c's sched_asym_prefer() balance
//! does: from a source tick, which looks for such a CID in its LLC and then
//! in the LLCs of its node whose best tier beats its own, and from a kicked
//! destination, which prefers the strongest kind of imbalance among the
//! sources it could relieve.
//!
//! When placement follows capacity, misfit balance moves a running task
//! too big for its CPU to an idle CID of the highest capacity it may use,
//! as fair.c's misfit active balance does.
//!
//! Counterpart in scx_eevdf: balance.bpf.c.

use scx_rustsched::dsq::{self, Cursor, Edq, Next};
use scx_rustsched::sched::KickFlags;
use scx_rustsched::sched::{Cid, OptCid};
use scx_rustsched::time;

use crate::{accounting::time_before, cid_idle, load, newidle, pack, taskctx::Context, tiers};
use scx_rustsched::task::Task;

/// The destination's pending states: free, reserved but not published, and
/// published for its dispatch to consume.
const FREE: u64 = 0;
const RESERVED: u64 = 1;
const PUBLISHED: u64 = 2;

/// How a request ended, which sets the destination's next interval.
pub const MOVED: u32 = 0;
pub const MISS: u32 = 1;
pub const PINNED: u32 = 2;

const MAX_INTERVAL_MS: u64 = 512;
const NSEC_PER_MSEC: u64 = 1_000_000;

/// What an idle destination gains from a busy source, weakest first, as
/// scx_eevdf ranks them: nothing, more capacity, a better packing tier in
/// another LLC, a
/// whole idle core in the LLC for a task beside a busy sibling, and a
/// better packing tier in the LLC.
const NONE: u32 = 0;
const CAPACITY: u32 = 1;
const REMOTE_PACKING: u32 = 2;
const LOCAL_SMT: u32 = 3;
const LOCAL_PACKING: u32 = 4;

/// The shortest interval between requests on a destination: the node's
/// CIDs in milliseconds, here the machine's.
#[inline(always)]
fn min_ms() -> u64 {
    u64::from(Cid::count()).max(1)
}

#[inline(always)]
fn slice_ns() -> u64 {
    crate::DEFAULT_REQUEST_NS.get()
}

/// Is `cid` free for a request, and is its interval up?
#[inline(always)]
fn due(cid: Cid, now: u64) -> bool {
    newidle::valid(cid)
        && newidle::entry(cid).active_pending().get() == FREE
        && !time_before(now, newidle::entry(cid).active_next().get())
}

/// Reserve the idle `cid` for a request, active_balance_reserve(): claim
/// its pending state, recheck it under the claim, and start its interval.
pub fn reserve(cid: Cid, now: u64) -> bool {
    if !due(cid, now) || !cid.is_idle() {
        return false;
    }
    if newidle::entry(cid)
        .active_pending()
        .compare_exchange(FREE, RESERVED)
        != FREE
    {
        return false;
    }
    if !cid.is_idle() || time_before(now, newidle::entry(cid).active_next().get()) {
        newidle::entry(cid).active_pending().set(FREE);
        return false;
    }
    let interval = newidle::entry(cid).active_interval().get().max(min_ms());
    newidle::entry(cid)
        .active_next()
        .set(now + interval * NSEC_PER_MSEC);
    newidle::entry(cid)
        .active_pending()
        .compare_exchange(RESERVED, PUBLISHED);
    true
}

/// Consume a request published on `cid`, from its dispatch.
pub fn take_pending(cid: Cid) -> bool {
    newidle::valid(cid) && {
        newidle::entry(cid).active_pending().get() == PUBLISHED
            && newidle::entry(cid)
                .active_pending()
                .compare_exchange(PUBLISHED, FREE)
                == PUBLISHED
    }
}

/// A request on the destination `cid` ended with `outcome`: back to the
/// shortest interval after a move, doubling otherwise, up to 512 ms for a
/// task that may not move at all.
pub fn complete(cid: Cid, outcome: u32) {
    if !newidle::valid(cid) {
        return;
    }
    let min = min_ms();
    let interval = newidle::entry(cid).active_interval().get().max(min);
    let interval = match outcome {
        MOVED => min,
        PINNED => (interval * 2).min(MAX_INTERVAL_MS),
        _ => (interval * 2).min(2 * min),
    };
    newidle::entry(cid).active_interval().set(interval);
}

/// Does the core of `dst` count as idle for an active balance to it? Every
/// CID of it must be idle, except that a `newly_idle` dst, still in the
/// dispatch that finds it idle and not idle yet, needs only its siblings
/// idle, as is_core_idle() leaves the CPU itself out.
#[inline(always)]
fn dst_whole_core(dst: Cid, newly_idle: bool) -> bool {
    !cid_idle::smt()
        || if newly_idle {
            dst.siblings_idle()
        } else {
            dst.is_core_idle()
        }
}

/// What the idle `dst` gains from the busy `src`, active_balance_type():
/// independent of the task, whose affinity and size are checked when it is
/// moved. Between the threads of one core, only a kernel priority does.
/// `whole_core` says whether the core of `dst` counts as idle, see
/// dst_whole_core().
#[inline(always)]
fn balance_type(dst: Cid, src: Cid, whole_core: bool) -> u32 {
    if dst == src || src.is_idle() {
        return NONE;
    }
    let packing = tiers::asym_packing();
    if dst.same_core(src) {
        return if packing && dst.smt_asym_packing() && dst.place_tier() < src.place_tier() {
            LOCAL_PACKING
        } else {
            NONE
        };
    }
    let smt = cid_idle::smt();
    let same_llc = dst.same_llc(src);
    if smt && same_llc && whole_core && !src.siblings_idle() {
        return LOCAL_SMT;
    }
    if packing && whole_core {
        if same_llc && dst.place_tier() < src.place_tier() {
            return LOCAL_PACKING;
        }
        if !same_llc && dst.same_node(src) && dst.llc_place_tier() < src.llc_place_tier() {
            return REMOTE_PACKING;
        }
    }
    if tiers::asym_capacity() && whole_core && dst.capacity() > src.capacity() {
        return CAPACITY;
    }
    NONE
}

/// Is the task of `state` too big for `cid`, fits_capacity() failing? A
/// misfit move takes only such a task.
#[inline(always)]
fn busy_on(state: &Context, cid: Cid, now: u64) -> bool {
    let util = load::task_util(state, now);
    util * 1280 >= cid.capacity() * 1024
}

/// The first CID of `range`, `nr << 32 | base`, in packing tier `tier` if
/// it is not negative, whose whole core is idle, that `task` may run on and
/// that is free for a request; -1 if none. A global function; `task` is
/// tagged trusted by build.rs.
#[scx_rustsched::global]
pub fn active_scan(task: &Task, range: u64, now: u64, tier: i32) -> OptCid {
    let (base, nr) = (range as u32, (range >> 32) as u32);
    let mut found = -1;
    for value in crate::loops::range(base, base + nr) {
        let cid = Cid(value as i32);
        if cid.is_idle()
            && (tier < 0 || cid.place_tier() == tier as u32)
            && cid.is_core_idle()
            && cid_idle::allowed_by_mask(task, cid)
            && due(cid, now)
        {
            found = cid.raw();
            break;
        }
    }

    OptCid::from_raw(found)
}

/// An idle CID for `task` that `cid` can kick to come and pull it, without
/// claiming it, cid_idle::idle_peer(); -1 if none. A global function, so
/// that the scan's frames stay off its callers'; `task` is tagged trusted
/// by build.rs.
#[scx_rustsched::global]
pub fn idle_peer(task: &Task, cid: Cid) -> OptCid {
    if task.as_ptr().is_null() {
        return OptCid::NONE;
    }
    cid_idle::idle_peer(task, cid)
}

/// The first task queued on `cid`, held by nobody once returned, if any.
#[inline(never)]
fn queue_head<'task>(cid: Cid) -> Option<&'task Task> {
    let mut cursor = Cursor::start();
    match dsq::peek_next::<Context>(Edq::Cid(cid), &mut cursor) {
        Next::Task(held) => held.task(),
        _ => None,
    }
}

/// An idle CID of a better packing tier for the running `task` of `src`,
/// idle_asym_packing_cid(); -1 if none. Within a core whose SMT domain
/// packs, a better sibling; across cores, a whole idle core of a better
/// tier in the LLC, then in the node's other LLCs whose best tier beats the
/// LLC of `src`, as fair.c compares groups by their preferred CPU. As in
/// asym_active_balance(), the size of the task does not matter. A global
/// function; `task` is tagged trusted by build.rs.
#[scx_rustsched::global]
pub fn packing_peer(task: &Task, src: Cid, now: u64) -> OptCid {
    if !tiers::asym_packing() || !newidle::valid(src) || crate::pinned(task) {
        return OptCid::NONE;
    }
    let tier = src.place_tier();
    let smt = cid_idle::smt();
    if smt && src.smt_asym_packing() {
        let ends = src.ends();
        let mut found = -1;
        for_each(
            ends.core_base,
            ends.core.saturating_sub(ends.core_base),
            |sibling| {
                if sibling != src.raw()
                    && Cid(sibling).is_idle()
                    && Cid(sibling).place_tier() < tier
                    && cid_idle::allowed_by_mask(task, Cid(sibling))
                    && due(Cid(sibling), now)
                {
                    found = sibling;
                    return false;
                }
                true
            },
        );
        if found >= 0 {
            return OptCid::from_raw(found);
        }
    }
    // With a busy sibling every tier is better, as the LLC is balanced
    // before its parent.
    let (llc_nr, llc_base) = src.llc_span();
    let local = if smt && !src.siblings_idle() {
        tiers::nr_place_tiers()
    } else {
        tier
    };
    let mut found = -1;
    for_each(0, local, |better| {
        found = active_scan(
            task,
            u64::from(llc_nr) << 32 | u64::from(llc_base),
            now,
            better,
        )
        .raw();
        found < 0
    });
    if found >= 0 {
        return OptCid::from_raw(found);
    }
    let (node_nr, node_base) = src.node_span();
    for_each(0, src.llc_place_tier(), |better| {
        let cid = active_scan(
            task,
            u64::from(node_nr) << 32 | u64::from(node_base),
            now,
            better,
        )
        .raw();
        if cid >= 0 && !Cid(cid).same_llc(src) {
            found = cid;
            return false;
        }
        true
    });
    OptCid::from_raw(found)
}

/// select_idle_smt_balance_cid(): the most preferred idle sibling of the
/// destination `cid` that `task` may run on and that is free for a request,
/// or `cid`.
#[inline(always)]
fn smt_balance_preferred(task: &Task, cid: Cid, now: u64) -> Cid {
    if !cid.smt_asym_active() {
        return cid;
    }
    let ends = cid.ends();
    let mut best = cid;
    for_each(
        ends.core_base,
        ends.core.saturating_sub(ends.core_base),
        |sibling| {
            if sibling != best.raw()
                && Cid(sibling).is_idle()
                && cid_idle::allowed_by_mask(task, Cid(sibling))
                && due(Cid(sibling), now)
                && Cid(sibling).smt_prefer(best)
            {
                best = Cid(sibling);
            }
            true
        },
    );
    best
}

/// The highest capacity among the CIDs `task` may run on, which bounds
/// misfit balance as p->max_allowed_capacity bounds update_misfit_status():
/// a task too big for every CPU it may use is not chased. A global
/// function; `task` is tagged trusted by build.rs.
#[scx_rustsched::global]
pub fn max_capacity(task: &Task) -> u64 {
    if task.as_ptr().is_null() {
        return 0;
    }
    let mut best = 0;
    for_each(0, Cid::count(), |cid| {
        let capacity = Cid(cid).capacity();
        if capacity > best && cid_idle::allowed_by_mask(task, Cid(cid)) {
            best = capacity;
        }
        true
    });
    best
}

/// An idle CID of the highest capacity `task` may use, for a task too big
/// for `src`, idle_misfit_cid(); -1 if none, or if `src` already is one of
/// the biggest. A whole idle core on SMT machines. A global function;
/// `task` is tagged trusted by build.rs.
#[scx_rustsched::global]
pub fn misfit_peer(task: &Task, src: Cid, now: u64) -> OptCid {
    if !tiers::asym_capacity() || !newidle::valid(src) || crate::pinned(task) {
        return OptCid::NONE;
    }
    let Some(state) = crate::taskctx::lookup_optional(task) else {
        return OptCid::NONE;
    };
    let max = max_capacity(task);
    if src.capacity() >= max || !busy_on(&state, src, now) {
        return OptCid::NONE;
    }
    let smt = cid_idle::smt();
    let mut found = -1;
    for_each(0, Cid::count(), |cid| {
        if cid != src.raw()
            && Cid(cid).capacity() == max
            && Cid(cid).is_idle()
            && (!smt || Cid(cid).is_core_idle())
            && cid_idle::allowed_by_mask(task, Cid(cid))
            && due(Cid(cid), now)
        {
            found = cid;
            return false;
        }
        true
    });
    OptCid::from_raw(found)
}

/// Run `body` for each of `nr` values from `base`, until it returns false.
#[inline(always)]
fn for_each(base: u32, nr: u32, mut body: impl FnMut(i32) -> bool) {
    for value in crate::loops::range(base, base + nr) {
        if !body(value as i32) {
            break;
        }
    }
}

/// The source side of a tick, after periodic balance found nothing, as
/// scx_eevdf's eevdf_tick() ends: a misfit running `task` is offered to a
/// bigger idle CID even with work queued; with nothing queued, the running
/// task is offered to an idle CID, see idle_balance(); with work queued, an
/// idle peer is kicked to pull it. Out of line, so that its locals stay off
/// the periodic balance chain, whose frames come within the verifier's 512
/// bytes.
#[inline(never)]
pub fn tick(task: &Task, cid: Cid, now: u64) {
    if !newidle::valid(cid) {
        return;
    }
    let queued = cid.has_queued();
    // update_misfit_status() records the running task even with work
    // queued, and nohz_balancer_kick() asks an idle CPU for a misfit
    // balance when nr_running >= 2: a queued, pinned head must not hide
    // a running task that needs a bigger CPU.
    if tiers::asym_capacity() && queued {
        let peer = misfit_peer(task, cid, now).raw();
        if peer >= 0 && peer != cid.raw() && reserve(Cid(peer), now) {
            Cid(peer).kick(KickFlags::IDLE);
            return;
        }
    }
    if !queued {
        let peer = idle_balance(task, cid, now).raw();
        if peer >= 0 && peer != cid.raw() && reserve(Cid(peer), now) {
            Cid(peer).kick(KickFlags::IDLE);
        }
        return;
    }
    // The head is only looked up for an idle peer, and there is none
    // to offer when no CID is idle, the common case on a busy machine,
    // where the lookup is the expensive part of this tick.
    if cid_idle::idle_empty() {
        return;
    }
    let Some(head) = queue_head(cid) else {
        return;
    };
    // A queued task is only RCU protected, and idle_peer() takes a trusted
    // one: hold a reference across the scan.
    let held = unsafe { scx_rustsched::kfuncs::bpf_task_acquire(head.as_ptr()) };
    if held.is_null() {
        return;
    }
    let peer = idle_peer(unsafe { Task::from_ptr(held) }, cid).raw();
    unsafe { scx_rustsched::kfuncs::bpf_task_release(held) };
    if peer >= 0 && peer != cid.raw() {
        reserve(Cid(peer), now);
        Cid(peer).kick(KickFlags::IDLE);
    }
}

/// An idle CID to offer the running `task` of `src` to, with nothing queued
/// there, idle_balance_cid(); -1 if none: a whole idle core of the LLC once
/// a sibling has been busy for a request's time, group_smt_balance, or else
/// an idle CID of a better packing tier or, for a misfit, of a bigger
/// capacity.
#[inline(never)]
fn idle_balance(task: &Task, src: Cid, now: u64) -> OptCid {
    if cid_idle::idle_empty() || crate::pinned(task) {
        return OptCid::NONE;
    }
    let mut peer = -1;
    if cid_idle::smt() {
        if src.siblings_idle() {
            newidle::entry(src).smt_busy_since().set(0);
        } else {
            let since = newidle::entry(src).smt_busy_since().get();
            if since == 0 {
                newidle::entry(src).smt_busy_since().set(now);
            } else if !time_before(now, since + slice_ns()) {
                let (llc_nr, llc_base) = src.llc_span();
                peer =
                    active_scan(task, u64::from(llc_nr) << 32 | u64::from(llc_base), now, -1).raw();
            }
        }
    }
    if peer < 0 && !tiers::asym_packing() && !tiers::asym_capacity() {
        return OptCid::NONE;
    }
    if peer < 0 {
        peer = packing_peer(task, src, now).raw();
    }
    if peer < 0 {
        peer = misfit_peer(task, src, now).raw();
    }
    // One call for every source of the peer: inlined twice, its
    // closure was outlined into a function the kernel's BTF check
    // rejects for its unnamed environment parameter.
    if peer >= 0 {
        OptCid::from_raw(smt_balance_preferred(task, Cid(peer), now).raw())
    } else {
        OptCid::NONE
    }
}

/// request_active_balance(): the kicked `dst` found nothing queued to pull.
/// Ask the source it would relieve most for its running task, after one
/// more try at its queue.
pub fn request(dst: Cid, now: u64) {
    if (!cid_idle::smt() && !tiers::asym_packing() && !tiers::asym_capacity()) || !dst.is_idle() {
        return;
    }
    let best = best_source(dst, now, 0);
    if best < 0 {
        complete(dst, MISS);
        return;
    }
    if Cid(best).has_queued() && crate::newidle::steal_from(dst, Cid(best), true, now) {
        complete(dst, MOVED);
        return;
    }
    if !ask(dst, Cid(best)) {
        complete(dst, MISS);
    }
}

/// need_active_balance() for `dst`, in the dispatch that finds it newly
/// idle, if its pull took nothing while the system is overloaded, see
/// newidle_stuck: ask the source it would relieve most for its running
/// task at once, as sched_balance_rq() does for CPU_NEWLY_IDLE, with no
/// interval of its own between requests. A source with work queued is left to the pulls.
/// Returns 1 if a request went out. A global function, so that
/// ops.dispatch() is verified with one call instead of the source walk.
#[scx_rustsched::global]
pub fn newidle_request(dst: Cid, now: u64) -> u32 {
    if (!cid_idle::smt() && !tiers::asym_packing() && !tiers::asym_capacity())
        || newidle::entry(dst).newidle_stuck().get() == 0
    {
        return 0;
    }
    let best = best_source(dst, now, 1);
    u32::from(best >= 0 && !Cid(best).has_queued() && ask(dst, Cid(best)))
}

/// Ask `src` for its running task on behalf of `dst`: one request in
/// flight per source, as busiest->active_balance allows, and the source
/// kicked to hand the task over from its dispatch.
fn ask(dst: Cid, src: Cid) -> bool {
    if !pack::running(src)
        || newidle::entry(src)
            .active_target()
            .compare_exchange(0, dst.raw() as u32 as u64 + 1)
            != 0
    {
        return false;
    }
    newidle::note_active_balance();
    src.kick(KickFlags::PREEMPT);
    true
}

/// The source the idle `dst` would relieve most, or -1: the strongest kind
/// of imbalance, then the worst packing tier, then the most tasks runnable,
/// then the busiest. `newly_idle` as for dst_whole_core(). A global
/// function, so that the walk is verified once for both callers.
#[scx_rustsched::global]
pub fn best_source(dst: Cid, now: u64, newly_idle: u32) -> i32 {
    let count = Cid::count();
    let whole_core = dst_whole_core(dst, newly_idle != 0);
    let mut best = -1;
    // kind << 48 | tier << 32 | running, compared whole, then the
    // utilization.
    let (mut best_rank, mut best_util) = (0, 0);
    for_each(0, count, |src| {
        let kind = balance_type(dst, Cid(src), whole_core);
        if kind == NONE {
            return true;
        }
        let running = Cid(src).nr_queued() + u64::from(pack::running(Cid(src)));
        if running == 0 {
            return true;
        }
        let rank = u64::from(kind) << 48
            | u64::from(Cid(src).place_tier()) << 32
            | running.min(u64::from(u32::MAX));
        let util = load::cid_util(Cid(src), now);
        if best < 0 || rank > best_rank || (rank == best_rank && util > best_util) {
            (best, best_rank, best_util) = (src, rank, util);
        }
        true
    });
    best
}

/// active_balance_target(): on the source `src`, whose dispatch runs with
/// `task` still current, take a destination's request and revalidate it:
/// the destination idle, the task allowed there and still better off: the
/// imbalance itself, whatever the size of the task, as for
/// asym_active_balance(), except that a misfit move needs a task too big
/// for `src`. Returns the destination its enqueue hands the task to, or -1.
pub fn target(task: &Task, src: Cid) -> OptCid {
    if !newidle::valid(src) {
        return OptCid::NONE;
    }
    let requested = newidle::entry(src).active_target().get();
    if requested == 0
        || newidle::entry(src)
            .active_target()
            .compare_exchange(requested, 0)
            != requested
    {
        return OptCid::NONE;
    }
    let dst = requested as i32 - 1;
    if !newidle::valid(Cid(dst)) {
        return OptCid::NONE;
    }
    if crate::pinned(task) || !cid_idle::allowed_by_mask(task, Cid(dst)) {
        complete(Cid(dst), PINNED);
        return OptCid::NONE;
    }
    // A donor running a mutex owner stays, see Task::is_blocked().
    let kind = if !task.is_blocked() && Cid(dst).is_idle() {
        balance_type(Cid(dst), src, dst_whole_core(Cid(dst), false))
    } else {
        NONE
    };
    let moves = match kind {
        LOCAL_SMT | LOCAL_PACKING | REMOTE_PACKING => true,
        // update_misfit_status(): still too big for `src`, and `dst` is
        // as big as a CPU the task may use gets.
        CAPACITY => match crate::taskctx::lookup_optional(task) {
            Some(state) => {
                busy_on(&state, src, time::now()) && Cid(dst).capacity() == max_capacity(task)
            }
            None => false,
        },
        _ => false,
    };
    if !moves {
        complete(Cid(dst), MISS);
        return OptCid::NONE;
    }
    complete(Cid(dst), MOVED);
    OptCid::from_raw(dst)
}

/// `src` dispatches and the task it was running is gone: drop a request
/// for it, as the stopper fair.c queues on the source finds nothing to
/// move and completes. Otherwise the request outlives the task it was made
/// for, keeps other destinations off the source and is later applied to
/// whatever the source runs next. A global function, so that ops.dispatch()
/// is verified with one call.
#[scx_rustsched::global]
pub fn drop_request(src: Cid) -> u32 {
    if !newidle::valid(src) {
        return 0;
    }
    let requested = newidle::entry(src).active_target().get();
    if requested == 0
        || newidle::entry(src)
            .active_target()
            .compare_exchange(requested, 0)
            != requested
    {
        return 0;
    }
    complete(Cid(requested as i32 - 1), MISS);
    1
}

/// The enqueue of a task an active balance moves: claim its destination if
/// still idle and run the task there, placed in that CID's pack. Returns
/// whether the task went there.
pub fn hand_over(task: &Task, state: &Context, dst: Cid, cid: Cid) -> bool {
    if dst == cid || !dst.is_idle() || !cid_idle::allowed_by_mask(task, dst) || !dst.claim() {
        return false;
    }
    let now = time::now();
    pack::place(
        state,
        dst,
        crate::lag_request(task),
        crate::task_weight(task),
        now,
        false,
    );
    true
}
