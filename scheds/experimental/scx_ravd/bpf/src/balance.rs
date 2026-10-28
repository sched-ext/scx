// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Piotr Gorski <lucjan.lucjanov@gmail.com>
//
// Ported from scx_lavd, Copyright (c) 2023-2025 Valve Corporation.
// Author of scx_lavd: Changwoo Min <changwoo@igalia.com>

//! Load balancing between compute domains, and what a CPU runs next.
//!
//! Every interval, the timer compares each domain's load, its average
//! utilization plus how many tasks wait per unit of capacity, with the
//! average of the domains. One well under it becomes a stealer, one well
//! over it a stealee: a CPU of a stealer takes a task from a stealee now
//! and then, with a probability that spreads the migrations over the
//! interval, and every CPU that finds nothing in its own domain takes from
//! any neighbor.
//!
//! Counterpart in scx_lavd: balance.bpf.c, the balancer lavd runs with
//! --no-fast-lb. Its default, which budgets migrations by the queued load
//! each task brings, needs every task's load accounted as it is queued and
//! dequeued, which is not ported.

use scx_rustsched::dsq;
use scx_rustsched::sched::Cid;

use crate::cpdom::{self, Cpdom};
use crate::lavd::*;
use crate::sys_stat::SYS_STAT;
use crate::util::{one, prob_x_out_of_y};

/// A queue a global function can take: a domain's, `Edq::User(id)`, by
/// its id, or with this bit, the CID's own, `Edq::Cid`.
const OWN_QUEUE: u64 = 1 << 63;

/// Move the first task of `queue`, see OWN_QUEUE, that may run on `cid` to
/// its local DSQ. Every pop of the scheduler goes through here, so that
/// the runtime's pop loop is inlined in one place: inlined into each of
/// several callers, LLVM outlined its closure, whose unnamed environment
/// parameter the kernel's BTF check refuses. One copy is also one for the
/// verifier to walk.
#[scx_rustsched::global]
fn move_to_local(queue: u64, cid: Cid) -> bool {
    let edq = if queue & OWN_QUEUE != 0 {
        dsq::Edq::Cid(cid)
    } else {
        cpdom::queue(queue)
    };
    dsq::move_to_local(edq, cid)
}

/// calc_mig_delta(): the margin around the average, wider when few
/// domains have work and narrower when all do.
#[inline(always)]
fn calc_mig_delta(avg: u64, nz_qlen: u64) -> u64 {
    if nz_qlen >= SYS_STAT.nr_active_cpdoms.get() {
        return avg >> LAVD_CPDOM_MIG_SHIFT_OL;
    }
    if nz_qlen == 0 {
        return avg >> LAVD_CPDOM_MIG_SHIFT_UL;
    }
    avg >> LAVD_CPDOM_MIG_SHIFT
}

/// The roles of domain `dom` for this interval, classify_cpdom(). True if
/// it is a stealee.
#[inline(always)]
fn classify_cpdom(dom: Cpdom, avg: u64, delta: u64) -> bool {
    let load = dom.load_invr().get();
    let stealer = load <= avg.saturating_sub(delta);
    let stealee = load >= avg + delta && dom.nr_queued_task().get() != 0;
    dom.is_stealer().set(stealer);
    dom.is_stealee().set(stealee && !stealer);
    stealee && !stealer
}

/// plan_x_cpdom_migration(), from the timer.
#[scx_rustsched::global]
pub fn plan_x_cpdom_migration() -> u32 {
    let nr = cpdom::nr_cpdoms() as u32;
    let mut total = 0;
    let mut nz_qlen = 0;
    for id in scx_rustsched::loops::range(0, nr) {
        let Some(dom) = cpdom::get(u64::from(id)) else {
            continue;
        };
        let nr_cpus = dom.nr_cpus().get().max(1);
        let cap_sum = dom.cap_sum().get().max(1);
        let util = (dom.avg_util_wall_sum().get() << LAVD_SHIFT)
            .checked_div(nr_cpus)
            .unwrap_or(0);
        let qlen = dom.nr_queued_task().get();
        let qlen_invr = (qlen << (LAVD_SHIFT * 3)).checked_div(cap_sum).unwrap_or(0);
        dom.load_invr().set(util + qlen_invr);
        if qlen != 0 {
            nz_qlen += one();
        }
        total += util + qlen_invr;
    }
    let avg = total.checked_div(u64::from(nr)).unwrap_or(0);
    let delta = calc_mig_delta(avg, nz_qlen);
    let mut nr_stealee = 0;
    for id in scx_rustsched::loops::range(0, nr) {
        if let Some(dom) = cpdom::get(u64::from(id))
            && classify_cpdom(dom, avg, delta)
        {
            nr_stealee += one();
        }
    }
    SYS_STAT.nr_stealee.set(nr_stealee);
    0
}

/// Take a task for `cid` from the queue of a neighbor of `from`, nearest
/// first: a stealee only, or any neighbor with `force`, try_to_steal_task()
/// and force_to_steal_task().
#[scx_rustsched::global]
fn steal(cid: Cid, from: u64, force: bool) -> bool {
    let Some(src) = cpdom::get(from) else {
        return false;
    };
    let nr = cpdom::nr_cpdoms() as u32;
    // A forced steal goes on to the other core type, after every domain
    // of the same.
    let max_distance = if force {
        2 * LAVD_CPDOM_MAX_DIST
    } else {
        LAVD_CPDOM_MAX_DIST
    };
    for distance in scx_rustsched::loops::range(0, max_distance) {
        for id in scx_rustsched::loops::range(0, nr) {
            let id = u64::from(id);
            if id == from {
                continue;
            }
            let Some(dom) = cpdom::get(id) else {
                continue;
            };
            if cpdom::distance(src, dom) != distance || (!force && !dom.is_stealee().get()) {
                continue;
            }
            if dsq::nr_queued(cpdom::queue(id)) != 0 && move_to_local(id, cid) {
                if !force {
                    // One migration per stealer and stealee each round.
                    dom.is_stealee().set(false);
                    src.is_stealer().set(false);
                }
                return true;
            }
        }
        // Go farther only now and then.
        if !force && !prob_x_out_of_y(1, LAVD_CPDOM_MIG_PROB_FT) {
            break;
        }
    }
    false
}

/// consume_task(): run on `cid` the earliest deadline of its own queue and
/// its domain's, after a steal if the domain is a stealer, or one from a
/// neighbor if both are empty.
#[inline(always)]
pub fn consume_task(cid: Cid, dom_id: u64) -> bool {
    let Some(dom) = cpdom::get(dom_id) else {
        return false;
    };
    let multi = cpdom::nr_cpdoms() > 1;
    if multi
        && dom.is_stealer().get()
        && prob_x_out_of_y(1, dom.nr_cpus().get() * LAVD_CPDOM_MIG_PROB_FT)
        && steal(cid, dom_id, false)
    {
        return true;
    }

    // The CID's own queue holds the pinned tasks: compare its head with
    // the domain's and take the earlier deadline first.
    let own = dsq::Edq::Cid(cid);
    let shared = cpdom::queue(dom_id);
    let own_head = if cid.has_queued() {
        dsq::peek(own, None).deadline
    } else {
        None
    };
    let shared_head = if dsq::nr_queued(shared) != 0 {
        dsq::peek(shared, None).deadline
    } else {
        None
    };
    // One Option at a time: the verifier has refused a match on a tuple
    // of two.
    let own_first = match own_head {
        Some(a) => match shared_head {
            Some(b) => scx_rustsched::time_before(a, b),
            None => true,
        },
        None => false,
    };
    if own_first {
        if move_to_local(OWN_QUEUE, cid) || move_to_local(dom_id, cid) {
            return true;
        }
    } else if move_to_local(dom_id, cid) || (own_head.is_some() && move_to_local(OWN_QUEUE, cid)) {
        return true;
    }

    multi && steal(cid, dom_id, true)
}
