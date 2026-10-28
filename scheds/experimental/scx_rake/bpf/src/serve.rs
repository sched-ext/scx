// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Piotr Gorski <lucjan.lucjanov@gmail.com>

//! What a CID runs next: ops.dispatch() and the pools.
//!
//! A dispatch takes, in order: an offer another LLC made this CID when it
//! found its own LLC full; the earlier of its own queue's head and its
//! pool's head, the pool's needing a slice of lead so that not every CID
//! takes the shared queue first; a steal from the other queues of its LLC,
//! from the CID after this one on, so that idle CIDs do not all take from
//! the same victim; then the heads of other LLCs' queues and pools that are
//! a whole slice behind the frontier, or whose pool went unserved for the
//! wall. A seat with an empty queue leaves pool work to an idle CID that is
//! nobody's seat, unless the pool is starved. With nothing found, the task
//! that ran keeps the CID with a fresh slice.
//!
//! The order by virtual time is what makes this free of starvation: a head
//! left in a pool keeps its virtual time while the others advance past it.
//!
//! scx_cake publishes a pending-insert token, a may-hold-work mark and a
//! bitmask of non-empty CPU queues, because its queues are the kernel's
//! DSQs: an insert lands after the op that made it returns, and a count is
//! a hash lookup. The runtime's queues are in the arena and an insert is
//! there when it returns, so the counts are exact and the runtime's own
//! queued bits are the mask. None of the three is needed.
//!
//! Counterpart in scx_cake: cake_dispatch(), cake_dispatch_search(),
//! cake_ring_walk(), cake_llc_pool_rescue(), cake_take_remote() and
//! cake_offer_remote().

use scx_rustsched::loops;
use scx_rustsched::prelude::*;

use crate::policy;
use crate::{
    CidCtx, FRONTIER, MAX_LLCS, NR_POOLS, POOL_SERVED, multi_pool, pool_of, seat, set_vtime,
    task_slice,
};

/// The queue of pool `pool`.
#[inline(always)]
fn pool_edq(pool: u32) -> Edq {
    Edq::User(u64::from(pool))
}

/// The virtual time of the first task of `edq`, None when it is empty.
#[inline(always)]
fn head(edq: Edq) -> Option<u64> {
    dsq::peek(edq, None).deadline
}

/// Queue a task on the pool of `cid`'s LLC, with `key`.
#[inline(always)]
pub fn pool_insert(task: &Task, cid: Cid, slice: u64, key: u64, flags: EnqFlags) {
    set_vtime(task, key);
    dsq::insert_vtime(task, pool_edq(pool_of(cid)), slice, key, flags);
}

/// When pool `pool` was last served.
#[inline(always)]
fn served(pool: u32) -> u64 {
    match POOL_SERVED.get(pool as usize) {
        Some(stamp) => stamp.get(),
        None => 0,
    }
}

/// Has pool `pool` gone unserved for the wall?
#[inline(always)]
fn starved(pool: u32) -> bool {
    policy::pool_starved(served(pool), time::now())
}

/// Pool `pool` was served now.
#[inline(always)]
fn serve_stamp(pool: u32) {
    if let Some(stamp) = POOL_SERVED.get(pool as usize) {
        stamp.set(time::now());
    }
}

/// An empty pool counts as served, so that its starvation clock runs only
/// while something waits there. The stamp is refreshed once it is half a
/// wall old, judged by this CID's last run stamp, so that the clock stays
/// off the path and every dispatch does not dirty the word.
#[inline(always)]
fn idle_refresh(pool: u32, cid: Cid) {
    let Some(here) = cid.slot::<CidCtx>() else {
        return;
    };
    if policy::pool_refresh_due(served(pool), here.stamp().get()) {
        let now = time::now();
        if policy::pool_refresh_due(served(pool), now) {
            serve_stamp(pool);
        }
    }
}

/// Offer the pool of `cid`'s LLC to an idle CID of another LLC that may run
/// `task`: the producer found its own LLC full. The offer is taken at the
/// claimed CID's next dispatch.
#[scx_rustsched::global]
pub fn offer_remote(task: &Task, cid: Cid) -> bool {
    let Some(target) = idle::pick(task, cid, Scope::Anywhere, Kind::AnyCpu) else {
        return false;
    };
    if !target.same_llc(cid)
        && let Some(there) = target.slot::<CidCtx>()
    {
        there.offer().set(u64::from(pool_of(cid)) + 1);
    }
    target.kick(KickFlags::IDLE);
    true
}

// The moves. Each kind of move is made in one global function and nowhere
// else: the runtime's moves loop through closures, and with a move inlined
// at every call site the linker outlines a closure into a function of its
// own, whose unnamed environment parameter the kernel's BTF check refuses.
// A global function keeps one copy of each, in a body as small as
// scx_rvtime's dispatch.

/// Move the first task of pool `pool` to `cid`'s local DSQ.
#[scx_rustsched::global]
fn take_pool(pool: u32, cid: Cid) -> bool {
    dsq::move_to_local(pool_edq(pool), cid)
}

/// Move the first task of `cid`'s own queue to its local DSQ.
#[scx_rustsched::global]
fn take_own(cid: Cid) -> bool {
    dsq::move_to_local(Edq::Cid(cid), cid)
}

/// Move a task from `victim`'s queue to `cid`'s local DSQ.
#[scx_rustsched::global]
fn take_peer(victim: Cid, cid: Cid) -> bool {
    dsq::move_to_local(Edq::Cid(victim), cid)
}

/// Take the pool another LLC offered `cid`, if any. The offer is cleared
/// even when the pool turns out empty, so that no stale one stays.
#[inline(always)]
fn take_offer(cid: Cid) -> bool {
    let Some(here) = cid.slot::<CidCtx>() else {
        return false;
    };
    let offer = here.offer().get();
    if offer == 0 || here.offer().compare_exchange(offer, 0) != offer {
        return false;
    }
    let pool = (offer - 1) as u32;
    if pool >= NR_POOLS.get() || pool == pool_of(cid) {
        return false;
    }
    if !take_pool(pool, cid) {
        return false;
    }
    serve_stamp(pool);
    true
}

/// Steal for `cid` from the other queues of its LLC, from the CID after it
/// on and then from the ones before it, then from the queues of other
/// LLCs whose head is a whole slice behind the frontier: across an LLC
/// only a task that has waited that long is worth the fabric, and a fresh
/// wake waits for its own.
#[scx_rustsched::global]
fn steal(cid: Cid) -> bool {
    for peer in dsq::queued(cid, Scope::Llc) {
        if peer > cid && take_peer(peer, cid) {
            return true;
        }
    }
    for peer in dsq::queued(cid, Scope::Llc) {
        if peer >= cid {
            break;
        }
        if take_peer(peer, cid) {
            return true;
        }
    }
    if !multi_pool() {
        return false;
    }
    let frontier = FRONTIER.get();
    for peer in dsq::queued(cid, Scope::Anywhere) {
        if peer.same_llc(cid) {
            continue;
        }
        if let Some(head) = head(Edq::Cid(peer))
            && policy::head_behind(head, frontier)
            && take_peer(peer, cid)
        {
            return true;
        }
    }
    false
}

/// Serve another LLC's pool whose head is a slice behind the frontier, or
/// which went unserved for the wall.
#[scx_rustsched::global]
fn rescue(cid: Cid) -> bool {
    let own = pool_of(cid);
    let frontier = FRONTIER.get();
    for pool in loops::range(0, NR_POOLS.get().min(MAX_LLCS)) {
        if pool == own {
            continue;
        }
        let Some(head) = head(pool_edq(pool)) else {
            continue;
        };
        if (policy::head_behind(head, frontier) || starved(pool)) && take_pool(pool, cid) {
            serve_stamp(pool);
            return true;
        }
    }
    false
}

/// Nothing queued here or in the pool: refresh the pool's stamp, then
/// steal or rescue.
#[inline(always)]
fn search_empty(cid: Cid, pool: u32) -> bool {
    idle_refresh(pool, cid);
    steal(cid) || (multi_pool() && rescue(cid))
}

/// Claim an idle CID of `cid`'s LLC that is nobody's seat and may run the
/// pool's head, for the work a seat or a CID the head may not run on
/// leaves. The pool head is held only for the claim.
#[scx_rustsched::global]
fn claim_for_head(cid: Cid, pool: u32) -> OptCid {
    let mut cursor = dsq::Cursor::start();
    let dsq::Next::Task(held) = dsq::peek_next::<crate::TaskCtx>(pool_edq(pool), &mut cursor)
    else {
        return OptCid::NONE;
    };
    let Some(task) = held.task() else {
        return OptCid::NONE;
    };
    let Some(target) = idle::pick(task, cid, Scope::Llc, Kind::AnyCpu) else {
        return OptCid::NONE;
    };
    if target == cid || seat::held(target) {
        target.unclaim();
        return OptCid::NONE;
    }
    OptCid::some(target)
}

/// Does the pool's head go before `cid`'s own: a slice of lead, or a pool
/// unserved for the wall? A head that drained in between leaves the order
/// to the moves.
#[inline(always)]
fn pool_leads(cid: Cid, pool: u32) -> bool {
    let Some(wake) = head(pool_edq(pool)) else {
        return false;
    };
    let Some(mine) = head(Edq::Cid(cid)) else {
        return true;
    };
    policy::pool_before(wake, mine) || starved(pool)
}

/// The dispatch search: true when it moved a task to `cid`'s local DSQ.
#[inline(always)]
fn search(cid: Cid) -> bool {
    if multi_pool() && take_offer(cid) {
        return true;
    }
    let pool = pool_of(cid);
    let own = cid.has_queued();
    let pooled = dsq::nr_queued(pool_edq(pool)) != 0;
    if !own && !pooled {
        return search_empty(cid, pool);
    }
    // A held seat with nothing of its own stays idle for its holder while
    // another CID of the LLC is idle and unheld, which is kicked for the
    // pool's work instead. A pool unserved for the wall is served here.
    if !own
        && pooled
        && seat::held(cid)
        && !starved(pool)
        && let Some(target) = claim_for_head(cid, pool).get()
    {
        target.kick(KickFlags::IDLE);
        return false;
    }
    if !pooled {
        idle_refresh(pool, cid);
    }
    let pool_first = !own || (pooled && pool_leads(cid, pool));
    // The second move is unconditional: a healing net under a head that
    // drained between the count and the move.
    if pool_first {
        if take_pool(pool, cid) {
            serve_stamp(pool);
            return true;
        }
        if take_own(cid) {
            return true;
        }
    } else {
        if take_own(cid) {
            return true;
        }
        if take_pool(pool, cid) {
            serve_stamp(pool);
            return true;
        }
    }
    // Both moves failed: this CID may not run the pool's head. Hand it to
    // an idle CID of the LLC that may.
    if pooled && let Some(target) = claim_for_head(cid, pool).get() {
        target.kick(KickFlags::IDLE);
    }
    steal(cid) || (multi_pool() && rescue(cid))
}

/// ops.dispatch(): the search, and with nothing anywhere the task that ran
/// keeps the CID with a fresh slice rather than leave it idle.
#[inline(always)]
pub fn dispatch(cid: Cid, prev: Option<&Task>) {
    if search(cid) {
        return;
    }
    if let Some(prev) = prev
        && prev.queued()
        && dsq::nr_queued(Dsq::LocalOn(cid)) == 0
    {
        prev.set_slice(task_slice(prev));
    }
}
