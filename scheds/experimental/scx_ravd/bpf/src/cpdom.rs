// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Piotr Gorski <lucjan.lucjanov@gmail.com>
//
// Ported from scx_lavd, Copyright (c) 2023-2025 Valve Corporation.
// Author of scx_lavd: Changwoo Min <changwoo@igalia.com>

//! Compute domains, lavd's struct cpdom_ctx: the CPUs of one LLC and one
//! core type, big or little, which share a queue.
//!
//! lavd's user space builds the domains from the topology and hands them
//! over with their neighbor lists. Here ops.init() builds them from the
//! CID topology: the CIDs of an LLC are contiguous, so a domain is the
//! CIDs of one LLC in one capacity tier, and its neighbors are found by
//! distance as they are needed, with no list kept: another domain of the
//! same LLC is at distance 0, one of the same node at 1, and the rest at 2.
//!
//! The domain table is a per-CID table, since there are never more domains
//! than CIDs: domain `id` is the entry of `Cid(id)`.
//!
//! Each domain has one queue, `Edq::User(id)`, ordered by virtual deadline.
//! lavd splits a domain's queue in two, one for its steady CPUs and one for
//! those turbulent with IRQ and steal time, which needs the PELT clock to
//! tell apart: here there is one.
//!
//! Counterpart in scx_lavd: struct cpdom_ctx in lavd.bpf.h, init_cpdoms()
//! in main.bpf.c, and the compute domain part of cpu_order.rs.

use scx_rustsched::cid_table;
use scx_rustsched::dsq::Edq;
use scx_rustsched::sched::Cid;
use scx_rustsched::tiers;
use scx_rustsched::var::Var;

use crate::cpuctx;

/// The compute domains: one queue each, `Edq::User(id)`, so at most as
/// many as scx_rustsched has such queues.
pub const LAVD_CPDOM_MAX_NR: u64 = scx_rustsched::dsq::USER_MAX;

scx_rustsched::arena_struct! {
    /// A compute domain.
    pub struct Cpdom {
        /// The domain's LLC and node, by their first CID, its capacity
        /// tier, and whether it is of big cores.
        llc_base: u64,
        node_base: u64,
        tier: u64,
        is_big: bool,
        /// Its first CID, an anchor for idle picks, how many CIDs it has
        /// and the sum of their capacities.
        first_cid: u64,
        nr_cpus: u64,
        cap_sum: u64,
        /// The closest domain of the other core type, or this one.
        alt_id: u64,
        /// Roles the load balancer gave it for this interval.
        is_stealer: bool,
        is_stealee: bool,
        /// What sys_stat.rs collected for it in the last interval.
        nr_queued_task: u64,
        cur_util_wall_sum: u64,
        avg_util_wall_sum: u64,
        avg_util_invr_sum: u64,
        load_invr: u64,
    }
}

scx_rustsched::cid_slot!(Cpdom, CPDOMS in ".data.cpdoms");

scx_rustsched::shared! {
    /// The number of compute domains, for the loader too.
    pub static NR_CPDOMS in ".data.nr_cpdoms": Var<u64> = Var::new(0);
}

/// Is there more than one core type?
#[inline(always)]
pub fn have_little_core() -> bool {
    tiers::nr_capacity_tiers() > 1
}

#[inline(always)]
pub fn nr_cpdoms() -> u64 {
    NR_CPDOMS.get()
}

/// Domain `id`, None for a number that is not one.
#[inline(always)]
pub fn get(id: u64) -> Option<Cpdom> {
    if id >= nr_cpdoms() {
        return None;
    }
    Cid(id as i32).slot()
}

/// The queue of domain `id`, cpdom_to_dsq().
#[inline(always)]
pub fn queue(id: u64) -> Edq {
    Edq::User(id)
}

/// The capacity tier a CID's domain is keyed by: 0 on a machine of one.
#[inline(always)]
fn tier_of(cid: Cid) -> u64 {
    if have_little_core() {
        u64::from(cid.capacity_tier())
    } else {
        0
    }
}

/// How far domain `b` is from domain `a`: 0 in the same LLC, 1 in the same
/// node, 2 otherwise, and a domain of the other core type farther than
/// every domain of the same, as lavd's cpu_order.rs orders them.
#[inline(always)]
pub fn distance(a: Cpdom, b: Cpdom) -> u32 {
    let topology = if a.llc_base().get() == b.llc_base().get() {
        0
    } else if a.node_base().get() == b.node_base().get() {
        1
    } else {
        2
    };
    if a.is_big().get() == b.is_big().get() {
        topology
    } else {
        topology + crate::lavd::LAVD_CPDOM_MAX_DIST
    }
}

/// Build the domains, from ops.init(), after the runtime set up the CID
/// topology and the capacity tiers. 0, or a negative errno.
///
/// Each loop's body is a global function, which the verifier checks once:
/// inlined, the search over the domains made so far inside the loop over
/// the CIDs took ops.init() past a million instructions.
pub fn init() -> i32 {
    let result = cid_table::init_slots::<Cpdom>();
    if result != 0 {
        return result;
    }
    for index in scx_rustsched::loops::range(0, Cid::count()) {
        let result = init_cid(index);
        if result != 0 {
            return result;
        }
    }
    let nr = nr_cpdoms() as u32;
    for id in scx_rustsched::loops::range(0, nr) {
        init_alt(u64::from(id));
    }
    for id in scx_rustsched::loops::range(0, nr) {
        if scx_rustsched::dsq::create(queue(u64::from(id))).is_err() {
            return -22;
        }
    }
    0
}

/// The domain of LLC `llc`, by its first CID, and capacity tier `tier`,
/// if a CID before made it, or u64::MAX.
#[inline(always)]
fn find(llc: u64, tier: u64) -> u64 {
    for id in scx_rustsched::loops::range(0, nr_cpdoms() as u32) {
        if let Some(dom) = get(u64::from(id))
            && dom.llc_base().get() == llc
            && dom.tier().get() == tier
        {
            return u64::from(id);
        }
    }
    u64::MAX
}

/// Put CID `index` in the domain of its LLC and tier, making the domain if
/// it is the first CID of it. 0, or a negative errno.
#[scx_rustsched::global]
fn init_cid(index: u32) -> i32 {
    let cid = Cid(index as i32);
    let (_, llc) = cid.llc_span();
    let (_, node) = cid.node_span();
    let (llc, tier) = (u64::from(llc), tier_of(cid));
    let mut found = find(llc, tier);
    if found == u64::MAX {
        let nr = nr_cpdoms();
        if nr >= LAVD_CPDOM_MAX_NR {
            return -7; // E2BIG
        }
        let Some(dom) = Cid(nr as i32).slot::<Cpdom>() else {
            return -22;
        };
        dom.llc_base().set(llc);
        dom.node_base().set(u64::from(node));
        dom.tier().set(tier);
        dom.is_big().set(tier == 0);
        dom.first_cid().set(u64::from(index));
        dom.alt_id().set(nr);
        NR_CPDOMS.set(nr + 1);
        found = nr;
    }
    let Some(dom) = get(found) else {
        return -22;
    };
    dom.nr_cpus().update(|nr| nr + 1);
    dom.cap_sum().update(|sum| sum + cid.capacity());
    let Some(cpuc) = cpuctx::get(cid) else {
        return -22;
    };
    cpuc.cpdom_id().set(found);
    cpuc.big_core().set(tier == 0);
    0
}

/// Give domain `id` its alternative: the closest domain of the other core
/// type, the one of the same LLC first.
#[scx_rustsched::global]
fn init_alt(id: u64) -> u32 {
    let Some(dom) = get(id) else {
        return 0;
    };
    let mut best = id;
    let mut best_distance = u32::MAX;
    for other in scx_rustsched::loops::range(0, nr_cpdoms() as u32) {
        let other = u64::from(other);
        if other == id {
            continue;
        }
        let Some(candidate) = get(other) else {
            continue;
        };
        if candidate.is_big().get() == dom.is_big().get() {
            continue;
        }
        let d = distance(dom, candidate);
        if d < best_distance {
            best = other;
            best_distance = d;
        }
    }
    dom.alt_id().set(best);
    0
}
