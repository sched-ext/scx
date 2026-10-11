// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.

//! The capacity a CID actually delivers.
//!
//! fair.c scales a runqueue's capacity by what RT, deadline, IRQ and steal
//! time take from that CPU, so that balance compares CPUs by what they can
//! still give to fair tasks. A sched_ext scheduler is told none of that, and
//! without it, work displaced by a higher class stays where it is: the
//! balancer reads that CID's load as normal and its capacity as full. So it
//! is inferred from what the scheduler does see:
//!
//! ```text
//!   demand    |<---------------- 32 ms window ---------------->|
//!   ours       ====      =========        ====   ===========
//!   displaced      xxxxxx         xxxxxxxx    xxx
//!                  ^     ^
//!                  |     ops.running(): one of ours runs again
//!                  ops.stopping() with slice left: something above us
//!                  took the CPU
//!
//!   available = 1024 - lost / elapsed        (smoothed 3:1 over windows)
//!   balance capacity = capacity * available / 1024
//! ```
//!
//! IRQ and steal time are the drift between the runqueue's clock and its
//! task clock over the same window. The window runs only while the CID has
//! sched_ext work, so a CPU that is merely idle cannot look constrained, and
//! the estimate is dropped once demand goes away for a second. Periodic
//! balance divides a CID's load by its balance capacity, and a task
//! displaced on a CID reduced below check_cpu_capacity()'s 117% gets a
//! paced, budgeted search for a less loaded one, whose queue it joins.
//!
//! Counterpart in scx_eevdf: load.bpf.c.

use crate::{
    cid_idle, clock,
    load::{self, load},
    newidle, pack,
};
use scx_rustsched::sched::{Cid, OptCid};
use scx_rustsched::task::Task;

// The words this module keeps per CID are the pressure_* fields of
// load::Load.

const EVAL_NS: u64 = 32_000_000;
const NSEC_PER_SEC: u64 = 1_000_000_000;
const NSEC_PER_MSEC: u64 = 1_000_000;
/// fair.c's imbalance_pct, which check_cpu_capacity() uses too.
const IMBALANCE_PCT: u64 = 117;

#[inline(always)]
pub fn enabled() -> bool {
    !crate::NO_CAPACITY_PRESSURE.get()
}

/// Whether `cid` has sched_ext work that could use the CPU. A new demand
/// period starts a fresh sample, so that an old reduced estimate does not
/// steer anything until the current demand has seen the pressure again.
pub fn demand(cid: Cid, demand: bool, now: u64) {
    if !enabled() || !load::valid(cid) {
        return;
    }
    if (load(cid).pressure_demand().get() != 0) == demand {
        return;
    }
    load(cid).pressure_demand().set(u64::from(demand));
    if demand {
        // There is no clock while nothing of ours wants the CID, unlike
        // fair.c's RT PELT, which decays by itself: keep short gaps, so
        // that pressure does not attract work straight back, but forget
        // an old event after a second.
        let idle_at = load(cid).pressure_idle_at().get();
        if idle_at != 0 && now.wrapping_sub(idle_at) >= NSEC_PER_SEC {
            load(cid).pressure_avail().set(1024);
            load(cid).pressure_migrate_next().set(0);
            load(cid).pressure_migrate_failed().set(0);
            load(cid).pressure_cap().set(cid.capacity());
        }
        load(cid).pressure_idle_at().set(0);
        load(cid).pressure_at().set(now);
        load(cid)
            .pressure_lost_at()
            .set(load(cid).pressure_lost().get());
        load(cid).pressure_clock_off_at().set(clock::offset(cid));
    } else {
        load(cid).pressure_idle_at().set(now);
        load(cid).pressure_blocked_at().set(0);
        load(cid).pressure_migrate_next().set(0);
        load(cid).pressure_migrate_failed().set(0);
        load(cid).pressure_cap().set(cid.capacity());
    }
    load(cid).pressure_valid().set(0);
}

/// A runnable task stopped on `cid` with slice left, at task clock `tnow`:
/// a higher class or core scheduling took the CPU. The interval runs until
/// one of ours runs there again, so that dispatch and switch overhead does
/// not count.
pub fn displaced(cid: Cid, tnow: u64) {
    if enabled()
        && load::valid(cid)
        && load(cid).pressure_demand().get() != 0
        && load(cid).pressure_blocked_at().get() == 0
    {
        load(cid).pressure_blocked_at().set(tnow);
    }
}

/// One of ours runs on `cid` again, at task clock `tnow`.
pub fn resumed(cid: Cid, tnow: u64) {
    if !enabled() || !load::valid(cid) {
        return;
    }
    let blocked_at = load(cid).pressure_blocked_at().get();
    if blocked_at != 0 {
        load(cid)
            .pressure_lost()
            .set(load(cid).pressure_lost().get() + tnow.saturating_sub(blocked_at));
        load(cid).pressure_blocked_at().set(0);
    }
}

/// Close the window on `cid` from its tick once it has run its length: the
/// fraction of it lost, smoothed 3:1, sets the balance capacity. Out of
/// line, so that its locals stay off the tick's balance chain, which comes
/// within the verifier's 512 bytes of stack.
#[inline(never)]
pub fn update(cid: Cid, now: u64) {
    if !enabled() || !load::valid(cid) {
        return;
    }
    if load(cid).pressure_demand().get() == 0 {
        return;
    }
    let at = load(cid).pressure_at().get();
    let elapsed = now.saturating_sub(at);
    if elapsed < EVAL_NS {
        return;
    }
    crate::clock::owned(cid, now);
    let offset = clock::offset(cid);
    let mut lost = load(cid).pressure_lost().get() - load(cid).pressure_lost_at().get();
    lost += offset.saturating_sub(load(cid).pressure_clock_off_at().get());
    let available = 1024 - (lost * 1024).checked_div(elapsed).unwrap_or(0).min(1024);
    let avail = if load(cid).pressure_valid().get() != 0 {
        (3 * load(cid).pressure_avail().get() + available) / 4
    } else {
        available
    };
    load(cid).pressure_avail().set(avail);
    load(cid).pressure_at().set(now);
    load(cid)
        .pressure_lost_at()
        .set(load(cid).pressure_lost().get());
    load(cid).pressure_clock_off_at().set(offset);
    load(cid).pressure_valid().set(1);
    load(cid)
        .pressure_cap()
        .set((cid.capacity() * avail / 1024).max(1));
}

/// The capacity periodic balance divides `cid`'s load by: what it delivers
/// while measured, its own capacity otherwise. A global function, so that
/// a loop summing it converges, see tiers::rust_cid_capacity().
#[scx_rustsched::global]
pub fn cid_balance_capacity(cid: Cid) -> u64 {
    if enabled()
        && load::valid(cid)
        && load(cid).pressure_demand().get() != 0
        && load(cid).pressure_valid().get() != 0
    {
        let cap = load(cid).pressure_cap().get();
        if cap != 0 {
            return cap;
        }
    }
    cid.capacity()
}

/// check_cpu_capacity(): is `cid` delivering less than its capacity by
/// more than the imbalance margin?
#[inline(always)]
fn reduced(cid: Cid) -> bool {
    enabled()
        && load::valid(cid)
        && load(cid).pressure_demand().get() != 0
        && load(cid).pressure_valid().get() != 0
        && load(cid).pressure_cap().get() * IMBALANCE_PCT < cid.capacity() * 100
}

/// A CID for `task`, displaced on the reduced `src` at `now`, to be queued
/// on instead, capacity_pressure_target(); -1 to stay. The scan is paced at
/// the LLC's busy balance interval, misses included, and picks the least
/// loaded CID per balance capacity that `task` may run on, if `src` is
/// loaded beyond it by the imbalance margin. Like detach_tasks(), it moves
/// no more weight than the imbalance, relaxing that and cache hotness after
/// failures. A global function; `task` is tagged trusted by build.rs.
#[scx_rustsched::global]
pub fn pressure_target(task: &Task, src: Cid, now: u64) -> OptCid {
    if !reduced(src) || crate::accounting::time_before(now, load(src).pressure_migrate_next().get())
    {
        return OptCid::NONE;
    }
    let Some(state) = crate::taskctx::lookup_optional(task) else {
        return OptCid::NONE;
    };
    let (llc_nr, _) = src.llc_span();
    let mut interval = (u64::from(llc_nr) * crate::BUSY_BALANCE_FACTOR.get()).max(1);
    if interval > 1 {
        interval -= 1;
    }
    load(src)
        .pressure_migrate_next()
        .set(now + interval * NSEC_PER_MSEC);
    let src_load = pack::weight(src);
    let src_cap = load(src).pressure_cap().get().max(1);
    if src_load == 0 {
        return OptCid::NONE;
    }
    let (mut best, mut best_load, mut best_cap, mut best_rank) = (-1, 0, 1, 0);
    // With --smt-whole-core a whole idle core ranks first, then a busy
    // CPU, then an idle sibling of a busy core.
    let whole_core = cid_idle::smt_whole_core() && cid_idle::smt();
    for value in crate::loops::range(0, Cid::count()) {
        let cid = Cid(value as i32);
        if cid == src || !cid_idle::allowed_by_mask(task, cid) {
            continue;
        }
        let rank = if !whole_core || cid.is_core_idle() {
            0
        } else if !cid.is_idle() {
            1
        } else {
            2
        };
        let load = pack::weight(cid);
        let cap = cid_balance_capacity(cid).max(1);
        if best < 0
            || rank < best_rank
            || (rank == best_rank
                && (load * best_cap < best_load * cap
                    || (load * best_cap == best_load * cap && cid.smt_prefer(Cid(best)))))
        {
            (best, best_load, best_cap, best_rank) = (cid.raw(), load, cap, rank);
        }
    }
    if best < 0
        || (src_load * 1024).checked_div(src_cap).unwrap_or(0) * 100
            <= (best_load * 1024).checked_div(best_cap).unwrap_or(0) * IMBALANCE_PCT
    {
        return OptCid::NONE;
    }
    let budget = (src_load * best_cap)
        .saturating_sub(best_load * src_cap)
        .checked_div(src_cap + best_cap)
        .unwrap_or(0);
    let weight = state.member().get() & u64::from(u32::MAX);
    let failed = load(src).pressure_migrate_failed().get();
    if (weight >> failed.min(63)) > budget
        || (newidle::task_hot(&state, src, Cid(best), now) && failed <= newidle::cache_nice_tries())
    {
        load(src)
            .pressure_migrate_failed()
            .set((failed + 1).min(255));
        return OptCid::NONE;
    }
    load(src).pressure_migrate_failed().set(0);
    OptCid::from_raw(best)
}

/// Set up `cid`: nothing lost yet.
pub fn init_cid(cid: Cid) {
    load(cid).pressure_avail().set(1024);
    load(cid).pressure_cap().set(cid.capacity());
}
