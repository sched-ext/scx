// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Piotr Gorski <lucjan.lucjanov@gmail.com>
//
// Ported from scx_lavd, Copyright (c) 2023-2025 Valve Corporation.
// Author of scx_lavd: Changwoo Min <changwoo@igalia.com>

//! Where a task runs: pick_idle_cpu().
//!
//! A task sticks to the domain it ran in, where its cache is, unless its
//! performance criticality says it belongs on the other core type. In
//! that domain it takes, in order: its previous CPU if its whole core is
//! idle, any whole idle core, its previous CPU if idle at all, the
//! waker's CPU on a synchronous wakeup, a whole idle core of a neighbor
//! domain that has work to give away, any idle CPU of its domain, and,
//! from ops.select_cid(), any idle CPU of a neighbor domain. Without an
//! idle CPU it stays where it was.
//!
//! The idle state is scx_rustsched's: a pick claims the CID it returns.
//!
//! Counterpart in scx_lavd: idle.bpf.c. The active and overflow sets of
//! core compaction are not ported, and with them neither is the overflow
//! extension, nor the warm-CPU wait: every CPU is active.

use scx_rustsched::cid_idle::{self, ANY_TIER};
use scx_rustsched::dsq::{self, Dsq};
use scx_rustsched::prelude::{Kind, Scope};
use scx_rustsched::sched::{Cid, OptCid};
use scx_rustsched::task::Task;

use crate::NO_WAKE_SYNC;
use crate::cpdom::{self, Cpdom};
use crate::cpuctx;
use crate::power::is_perf_cri;
use crate::taskctx::TaskCtx;
use crate::util::is_pinned;

/// Where pick_idle_cpu() placed a task, and whether it claimed the CID
/// idle.
pub struct Pick {
    pub cid: Cid,
    pub idle: bool,
}

/// The capacity tier of domain `dom`'s CIDs, or ANY_TIER on a machine of
/// one.
#[inline(always)]
fn tier(dom: Cpdom) -> u32 {
    if cpdom::have_little_core() {
        dom.tier().get() as u32
    } else {
        ANY_TIER
    }
}

/// Claim an idle CID of `kind` in domain `dom`, around `anchor` if it is
/// one of the domain's, pick_idle_cpu_at_cpdom().
#[inline(always)]
fn pick_at_cpdom(task: &Task, dom_id: u64, dom: Cpdom, anchor: Cid, kind: Kind) -> OptCid {
    // Compared by id: a comparison of two Options is a match on a pair,
    // which the verifier has refused.
    let in_dom = match cpuctx::get(anchor) {
        Some(cpuc) => cpuc.cpdom_id().get() == dom_id,
        None => false,
    };
    let anchor = if in_dom {
        anchor
    } else {
        Cid(dom.first_cid().get() as i32)
    };
    cid_idle::pick_in_tier(task, anchor, Scope::Llc, kind, tier(dom))
}

/// Claim an idle CID of `kind` in a neighbor of domain `from`, nearest
/// first, of the same core type, migrate_to_neighbor(). With
/// `stealer_only`, for a task leaving a stealee, only a stealer takes it,
/// and the two give up their roles for the round, as lavd's balancer has
/// them do after one migration. A global function: it loops over the
/// domains.
#[scx_rustsched::global]
fn migrate_to_neighbor(task: &Task, from: u64, full_core: bool, stealer_only: bool) -> i32 {
    let Some(src) = cpdom::get(from) else {
        return -1;
    };
    let kind = if full_core {
        Kind::FullCore
    } else {
        Kind::AnyCpu
    };
    let nr = cpdom::nr_cpdoms() as u32;
    for distance in scx_rustsched::loops::range(0, crate::lavd::LAVD_CPDOM_MAX_DIST) {
        for id in scx_rustsched::loops::range(0, nr) {
            let id = u64::from(id);
            if id == from {
                continue;
            }
            let Some(dom) = cpdom::get(id) else {
                continue;
            };
            if cpdom::distance(src, dom) != distance || (stealer_only && !dom.is_stealer().get()) {
                continue;
            }
            if let Some(cid) = pick_at_cpdom(task, id, dom, Cid::NONE, kind).get() {
                if stealer_only {
                    src.is_stealee().set(false);
                    dom.is_stealer().set(false);
                }
                return cid.raw();
            }
        }
    }
    -1
}

/// The domain the task sticks to and the CID in it, find_sticky_cpu_and_cpdom():
/// the previous CPU's, or the alternative domain without a CID if the task
/// belongs on the other core type.
#[inline(always)]
fn find_sticky(taskc: TaskCtx, prev: Cid) -> (OptCid, u64) {
    let Some(cpuc) = cpuctx::get(prev) else {
        return (OptCid::NONE, 0);
    };
    let dom_id = cpuc.cpdom_id().get();
    if cpdom::have_little_core()
        && let Some(dom) = cpdom::get(dom_id)
        && dom.is_big().get() != is_perf_cri(taskc)
    {
        return (OptCid::NONE, dom.alt_id().get());
    }
    (OptCid::some(prev), dom_id)
}

/// On a synchronous wakeup the waker is about to sleep: take its CPU if
/// nothing waits there and it is in the task's domain, is_sync_waker_idle().
#[inline(always)]
fn sync_waker(task: &Task, taskc: TaskCtx, dom_id: u64) -> OptCid {
    if NO_WAKE_SYNC.get() || !taskc.test_flag(crate::lavd::LAVD_FLAG_IS_SYNC_WAKEUP) {
        return OptCid::NONE;
    }
    let waker = Cid::current();
    let Some(cpuc) = cpuctx::get(waker) else {
        return OptCid::NONE;
    };
    if cpuc.cpdom_id().get() != dom_id
        || !task.allowed_on(waker)
        || waker.has_queued()
        || dsq::nr_queued(Dsq::LocalOn(waker)) != 0
    {
        return OptCid::NONE;
    }
    OptCid::some(waker)
}

/// pick_idle_cpu(): where `task`, which ran on `prev`, goes. `extend`
/// lets it look for any idle CPU of a neighbor domain, as ops.select_cid()
/// does and ops.enqueue() does not.
#[inline(always)]
pub fn pick_idle_cpu(task: &Task, taskc: TaskCtx, prev: Cid, extend: bool) -> Pick {
    // A CPU the task may not run on is no anchor, and a pinned task has
    // no choice.
    let prev = crate::util::allowed_cid(task, prev);
    if is_pinned(task) {
        return Pick {
            cid: prev,
            idle: false,
        };
    }
    let (sticky, dom_id) = find_sticky(taskc, prev);
    let Some(dom) = cpdom::get(dom_id) else {
        return Pick {
            cid: prev,
            idle: false,
        };
    };

    // The sticky CPU, if its whole core is idle, then any whole idle core
    // of the domain, then the sticky CPU if it is idle at all.
    if let Some(cid) = sticky.get()
        && cid.is_core_idle()
        && task.allowed_on(cid)
        && cid.claim()
    {
        return Pick { cid, idle: true };
    }
    if let Some(cid) = pick_at_cpdom(task, dom_id, dom, prev, Kind::FullCore).get() {
        return Pick { cid, idle: true };
    }
    if let Some(cid) = sticky.get()
        && task.allowed_on(cid)
        && cid.claim()
    {
        return Pick { cid, idle: true };
    }

    if let Some(cid) = sync_waker(task, taskc, dom_id).get() {
        return Pick { cid, idle: false };
    }

    // A whole idle core of a neighbor, if this domain has work to give.
    if cpdom::nr_cpdoms() > 1 && dom.is_stealee().get() {
        let cid = migrate_to_neighbor(task, dom_id, true, true);
        if cid >= 0 {
            return Pick {
                cid: Cid(cid),
                idle: true,
            };
        }
    }

    if let Some(cid) = pick_at_cpdom(task, dom_id, dom, prev, Kind::AnyCpu).get() {
        return Pick { cid, idle: true };
    }

    if extend && cpdom::nr_cpdoms() > 1 {
        let cid = migrate_to_neighbor(task, dom_id, false, false);
        if cid >= 0 {
            return Pick {
                cid: Cid(cid),
                idle: true,
            };
        }
    }

    // No idle CPU: stay on the sticky CPU, or where the task was.
    let cid = sticky.get().unwrap_or(prev);
    if task.allowed_on(cid) {
        Pick { cid, idle: false }
    } else {
        Pick {
            cid: prev,
            idle: false,
        }
    }
}
