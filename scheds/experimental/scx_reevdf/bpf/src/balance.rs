// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.

//! Periodic balance, sched_balance_domains(): the balancing that does not
//! wait for a CID to run dry. While every CPU is busy nothing goes idle to
//! pull, and work queued unevenly stays where it is.
//!
//! This is one of three ways work moves between CIDs, and the one that
//! moves a task waiting in a queue between two CIDs that are both busy.
//! newidle.rs moves a queued task to a CID that has run out of work, and
//! active.rs moves a task that is running, which no queue walk reaches.
//!
//! ```text
//! ops.tick() on a local group's leader, when its interval is due
//!   system domain: all CIDs,  groups are the nodes
//!   node domain:   the node,  groups are the LLCs
//!   LLC domain:    the LLC,   groups are the cores
//!     -> average load per capacity over the domain
//!     -> the local group below it, the busiest group above it by more than
//!        the imbalance margin with something queued, its busiest CID
//!     -> a task of that CID's queue that is cold, allowed here and no
//!        heavier than the imbalance asks to move, detach_tasks()
//!     -> a task allowed only on another CID of the local group goes there,
//!        if nothing can come here, can_migrate_task()'s new_dst_cpu
//!     -> nothing found: back off, doubling the interval up to twice it
//! ops.dispatch() on the destination
//!     -> drain the selection one task at a time, and only a task that
//!        wins this CID's own pick, as attach_task() lets
//!        wakeup_preempt() decide rather than run what it pulls
//! ```
//!
//! Every scan is a global BPF function with scalar arguments, verified once
//! on its own, and keeps its working values in the CID's balance state in
//! the arena rather than in the callers' frames.
//!
//! Counterpart in scx_eevdf: balance.bpf.c.

use scx_rustsched::dsq::{self, CURSOR_AT, CURSOR_START, Cursor, Dsq, Edq, Moved, Next};
use scx_rustsched::sched::KickFlags;
use scx_rustsched::sched::{Cid, OptCid};
use scx_rustsched::time;
use scx_rustsched::var::Var;

use crate::{
    accounting::{lag, lag_limit, time_before},
    balance_state, cid_idle, idle, load, newidle, pack, pressure,
    taskctx::Context,
    tiers,
};
use scx_rustsched::task::Task;

const NO_SOURCE: u64 = u64::MAX;
/// A pass on another CID is writing a selection for this one.
const CLAIMING: u64 = u64::MAX - 1;
const NO_DST: u64 = u64::MAX;

const SYSTEM: u64 = balance_state::BUSY_SYSTEM;
const NODE: u64 = balance_state::BUSY_NODE;
const LLC: u64 = balance_state::BUSY_LLC;

/// fair.c's imbalance_pct for the busy domains this walks.
const IMBALANCE_PCT: u64 = 117;
const NSEC_PER_MSEC: u64 = 1_000_000;
/// Tasks a pass or a drain looks at in one queue, BALANCE_TASK_SCAN.
const TASK_SCAN: i32 = 8;

/// Milliseconds of balance interval per CID of a domain, busy_factor.
#[inline(always)]
fn interval_factor() -> u64 {
    crate::BUSY_BALANCE_FACTOR.get()
}

scx_rustsched::shared! {
    /// SIS_UTIL updates and the sum of the budgets they set, for --stats.
    pub static SIS_STATS in ".data.sstats": SisStats = SisStats {
        updates: Var::new(0),
        scanned: Var::new(0),
    };
}

#[repr(C)]
pub struct SisStats {
    updates: Var<u64>,
    scanned: Var<u64>,
}

/// Nothing selected yet, and an LLC's whole width to scan until its first
/// balance has measured it.
pub fn init_cid(cid: Cid) {
    newidle::entry(cid).source().set(NO_SOURCE);
    let (llc_nr, llc_base) = cid.llc_span();
    if cid.raw() as u32 == llc_base {
        cid_idle::set_llc_budget(cid.raw(), llc_nr);
    }
}

/// Is the idle scan bounded by SIS_UTIL?
#[inline(always)]
pub fn sis_util() -> bool {
    !crate::NO_SIS_UTIL.get()
}

/// update_idle_cpu_scan(): how much of the LLC `nr` from `base` wakeups
/// should search, from `util`, the utilization summed over it. With x the
/// average utilization per CPU, fair.c computes
///
///   y = 1024 - min(x^2 * imbalance_pct^2 / (10000 * 1024), 1024)
///   nr_idle_scan = llc_weight * y / 1024
///
/// so the scan shrinks quadratically and reaches zero at 100 / 117, about
/// 85% utilization.
/// With `asym`, the range is an asymmetric capacity domain wider than the
/// LLC, see asym_domain_shared().
#[inline(always)]
fn update_idle_scan(base: u32, nr: u32, util: u64, asym: bool) {
    let x = util.checked_div(u64::from(nr)).unwrap_or(0);
    let scaled = x * x * IMBALANCE_PCT * IMBALANCE_PCT / (10000 * 1024);
    let scan = u64::from(nr) * (1024 - scaled.min(1024)) / 1024;
    if asym {
        cid_idle::set_asym_budget(base as i32, scan as u32 + 1);
        return;
    }
    cid_idle::set_llc_budget(base as i32, scan as u32);
    SIS_STATS.updates.add(1);
    SIS_STATS.scanned.add(scan);
}

/// Run `body` for each of `nr` CIDs from `base`, until it returns false.
#[inline(always)]
fn for_each(base: u32, nr: u32, mut body: impl FnMut(i32) -> bool) {
    for value in crate::loops::range(base, base + nr) {
        if !body(value as i32) {
            break;
        }
    }
}

/// The child groups of a domain at `level` that hold `cid`, as (base, nr):
/// nodes, LLCs or cores.
#[inline(always)]
fn child_group(cid: Cid, level: u64) -> (u32, u32) {
    match level {
        SYSTEM => {
            let (nr, base) = cid.node_span();
            (base, nr)
        }
        NODE => {
            let (nr, base) = cid.llc_span();
            (base, nr)
        }
        _ => {
            let ends = cid.ends();
            (
                ends.core_base,
                ends.core.saturating_sub(ends.core_base).max(1),
            )
        }
    }
}

/// Sample the load of every CID in `nr` from `base` and return the domain's
/// average load per capacity, scaled by 1024. For a domain with shared
/// state, an LLC (`sis` 1) or an asymmetric capacity domain wider than one
/// (`sis` 2), also sum what SIS_UTIL needs off the same walk, as
/// update_sd_lb_stats() collects sum_util for update_idle_cpu_scan()
/// rather than walking again.
#[scx_rustsched::global]
pub fn balance_avg_load(base: u32, nr: u32, now: u64, sis: u32) -> u64 {
    let asym = sis == 2;
    let sis = sis != 0 && sis_util();
    let (mut total, mut cap, mut util) = (0, 0, 0);
    for_each(base, nr, |cid| {
        if !newidle::valid(Cid(cid)) {
            return false;
        }
        let sample = load::cid_load(Cid(cid), now);
        newidle::entry(Cid(cid)).sample().set(sample);
        total += sample;
        cap += pressure::cid_balance_capacity(Cid(cid));
        if sis {
            util += load::cid_util(Cid(cid), now);
        }
        true
    });
    if sis && newidle::valid(Cid(base as i32)) {
        update_idle_scan(base, nr, util, asym);
    }
    if cap == 0 { 0 } else { total * 1024 / cap }
}

/// The load a group, `nr << 32 | base`, has above the domain average if
/// `excess`, or the room it has below it. Leaves the group's load, capacity
/// and whether anything is queued there in `dst`'s working values.
#[scx_rustsched::global]
pub fn balance_group_delta(dst: Cid, group: u64, avg_norm: u64, excess: u32) -> u64 {
    let (base, nr) = (group as u32, (group >> 32) as u32);
    let (mut total, mut cap) = (0, 0);
    let mut queued = 0;
    for_each(base, nr, |cid| {
        if !newidle::valid(Cid(cid)) {
            return false;
        }
        total += newidle::entry(Cid(cid)).sample().get();
        cap += pressure::cid_balance_capacity(Cid(cid));
        if dsq::queued_test(Cid(cid)) {
            queued = 1;
        }
        true
    });
    newidle::entry(dst).group_load().set(total);
    newidle::entry(dst).group_cap().set(cap);
    newidle::entry(dst).group_queued().set(queued);

    let fair = avg_norm * cap / 1024;
    if excess != 0 {
        total.saturating_sub(fair)
    } else {
        fair.saturating_sub(total)
    }
}

/// The busiest child group of the domain, other than the local one, whose
/// load is above the average and that has something queued; left in `dst`'s
/// working values. With the local group itself overloaded, the busiest has
/// to beat it by the imbalance margin.
#[scx_rustsched::global]
pub fn balance_find_group(dst: Cid, base: u32, nr: u32) -> u32 {
    let level = newidle::entry(dst).level().get();
    let local_base = newidle::entry(dst).local_base().get() as u32;
    let avg_norm = newidle::entry(dst).avg_norm().get();
    let local_norm = newidle::entry(dst).local_norm().get();
    let local_overloaded = newidle::entry(dst).local_overloaded().get() != 0;
    let (mut best_load, mut best_cap, mut best_excess) = (0, 1, 0);
    let (mut best_base, mut best_nr) = (0, 0);
    for_each(base, nr, |cid| {
        let (group_base, group_nr) = child_group(Cid(cid), level);
        // Each group is contiguous; sum it only at its base.
        if cid as u32 != group_base || group_base == local_base || group_nr == 0 {
            return true;
        }
        let excess = balance_group_delta(
            dst,
            u64::from(group_nr) << 32 | u64::from(group_base),
            avg_norm,
            1,
        );
        if excess == 0 || newidle::entry(dst).group_queued().get() == 0 {
            return true;
        }
        let (load, cap) = (
            newidle::entry(dst).group_load().get(),
            newidle::entry(dst).group_cap().get().max(1),
        );
        if local_overloaded && load * 1024 / cap * 100 <= local_norm * IMBALANCE_PCT {
            return true;
        }
        if load * best_cap > best_load * cap {
            (best_load, best_cap, best_excess) = (load, cap, excess);
            (best_base, best_nr) = (group_base, group_nr);
        }
        true
    });
    if best_nr == 0 {
        return 0;
    }
    newidle::entry(dst).src_base().set(u64::from(best_base));
    newidle::entry(dst).src_nr().set(u64::from(best_nr));
    newidle::entry(dst).src_excess().set(best_excess);
    1
}

/// The busiest CID of the chosen group that is busy, has work queued and
/// is above the average, walked from `start`; -1 if none.
#[scx_rustsched::global]
pub fn balance_find_cid(dst: Cid, start: u32) -> OptCid {
    let (base, nr) = (
        newidle::entry(dst).src_base().get() as u32,
        newidle::entry(dst).src_nr().get() as u32,
    );
    if nr == 0 {
        return OptCid::NONE;
    }
    let offset = if start >= base && start < base + nr {
        start - base
    } else {
        0
    };
    let avg_norm = newidle::entry(dst).avg_norm().get();
    let dst_norm = newidle::entry(dst).dst_norm().get();
    let dst_overloaded = newidle::entry(dst).dst_overloaded().get() != 0;
    let (mut best, mut best_load) = (-1, 0);
    for_each(0, nr, |index| {
        let cid = (base + (offset + index as u32).checked_rem(nr).unwrap_or(0)) as i32;
        if !newidle::valid(Cid(cid)) || Cid(cid).is_idle() || !dsq::queued_test(Cid(cid)) {
            return true;
        }
        let load = newidle::entry(Cid(cid)).sample().get();
        let norm = load * 1024 / pressure::cid_balance_capacity(Cid(cid)).max(1);
        if norm <= avg_norm || (dst_overloaded && norm * 100 <= dst_norm * IMBALANCE_PCT) {
            return true;
        }
        if load > best_load {
            (best, best_load) = (cid, load);
        }
        true
    });
    OptCid::from_raw(best)
}

/// Where a task of `owner`'s pass goes: `owner` if the task may run
/// there, or else the first other CID of the local group it may run on with
/// no selection of its own pending, -1 if none. fair.c's can_migrate_task()
/// records that CPU as new_dst_cpu: the elected CID still runs the pass,
/// and another can consume its result. Not a global function: the task is
/// a queued one, only RCU protected, which a global's task parameter does
/// not take.
#[inline(never)]
fn balance_destination(task: &Task, owner: Cid) -> OptCid {
    if !newidle::valid(owner) {
        return OptCid::NONE;
    }
    if crate::allowed_on(task, owner) {
        return OptCid::from_raw(owner.raw());
    }
    let (base, nr) = (
        newidle::entry(owner).local_base().get() as u32,
        newidle::entry(owner).local_nr().get() as u32,
    );
    let mut found = -1;
    for_each(base, nr, |cid| {
        if cid != owner.raw()
            && newidle::valid(Cid(cid))
            && newidle::entry(Cid(cid)).source().get() == NO_SOURCE
            && crate::allowed_on(task, Cid(cid))
        {
            found = cid;
            return false;
        }
        true
    });
    OptCid::from_raw(found)
}

/// Whether a task of `src`'s queue could move to `dst`, or failing that to
/// another CID of the local group: still queued, no heavier than the
/// imbalance asks to move once halved for each failed pass, and cold unless
/// enough passes failed. Leaves the destination, the drain cursor at that
/// task and the weight to move in `dst`'s working values.
///
/// can_migrate_task() first drains what can use the elected destination,
/// and LBF_DST_PINNED revisits an alternate only if imbalance remains after
/// that scan: the first task that needs the redirect is remembered, but a
/// task that does not is preferred.
#[scx_rustsched::global]
pub fn balance_movable(dst: Cid, src: Cid, now: u64) -> u32 {
    let level = newidle::entry(dst).level().get();
    let budget = newidle::entry(dst)
        .local_room()
        .get()
        .min(newidle::entry(dst).src_excess().get());
    let failed = newidle::entry(dst).busy_failed().get_at(level);
    let tries = newidle::cache_nice_tries();
    let mut cursor = newidle::load_cursor(newidle::entry(src).busy_scan_cursor());
    let mut found = 0;
    newidle::entry(dst).alt_dst().set(NO_DST);
    for_each(0, TASK_SCAN as u32, |_| {
        let Next::Task(held) = dsq::peek_next::<Context>(Edq::Cid(src), &mut cursor) else {
            return false;
        };
        let state = held.slot();
        let weight = state.member().get() & u64::from(u32::MAX);
        let movable = held.is_queued()
            && (weight >> failed.min(63)) <= budget
            && !(newidle::task_hot(&state, src, dst, now) && failed <= tries);
        let (deadline, _, seq) = held.key();
        // A proxy-execution donor stays where it is, see Task::is_blocked().
        let task = if movable {
            held.task().filter(|task| !task.is_blocked())
        } else {
            None
        };
        let target = match task {
            Some(task) => balance_destination(task, dst).raw(),
            None => -1,
        };
        drop(held);
        if target == dst.raw() {
            newidle::entry(dst).scan_deadline().set(deadline);
            newidle::entry(dst).scan_seq().set(seq);
            newidle::entry(dst).move_dst().set(dst.raw() as u64);
            found = 1;
        } else if target >= 0 && newidle::entry(dst).alt_dst().get() == NO_DST {
            newidle::entry(dst).alt_dst().set(target as u64);
            newidle::entry(dst).alt_deadline().set(deadline);
            newidle::entry(dst).alt_seq().set(seq);
        }
        found == 0
    });
    newidle::store_cursor(newidle::entry(src).busy_scan_cursor(), &cursor);
    if found == 0 && newidle::entry(dst).alt_dst().get() != NO_DST {
        newidle::entry(dst)
            .scan_deadline()
            .set(newidle::entry(dst).alt_deadline().get());
        newidle::entry(dst)
            .scan_seq()
            .set(newidle::entry(dst).alt_seq().get());
        newidle::entry(dst)
            .move_dst()
            .set(newidle::entry(dst).alt_dst().get());
        found = 1;
    }
    if found != 0 {
        newidle::entry(dst).move_budget().set(budget);
    } else {
        dsq::queued_check(src);
    }
    found
}

/// One periodic pass over the domain of `nr << 32 | base` at `level`, from
/// `dst` if it leads its local group there: returns whether a selection is pending, which ends the
/// tick's balancing.
#[scx_rustsched::global]
pub fn balance_domain(dst: Cid, range: u64, level: u64, now: u64) -> u32 {
    let (base, nr) = (range as u32, (range >> 32) as u32);
    if nr == 0 || !newidle::valid(dst) {
        return 0;
    }
    // One leader per local group, should_we_balance(): its first CID,
    // so that every group of the domain gets to pull, not only the
    // one holding the domain's first CID.
    if level != LLC && dst.raw() as u32 != child_group(dst, level).0 {
        return 0;
    }
    // A selection still draining through dispatch.
    if newidle::entry(dst).source().get() != NO_SOURCE {
        return 1;
    }
    let mut min_ms = (u64::from(nr) * interval_factor()).max(1);
    if min_ms > 1 {
        min_ms -= 1;
    }
    let max_ms = 2 * min_ms;
    let interval = newidle::entry(dst).busy_interval().get_at(level);
    if interval == 0 {
        // Dephase the leaders by a millisecond each,
        // get_sd_balance_interval().
        newidle::entry(dst).busy_interval().set_at(level, min_ms);
        let phase = 1
            + ((dst.raw() as u32 - base.min(dst.raw() as u32)) as u64)
                .checked_rem(min_ms)
                .unwrap_or(0);
        newidle::entry(dst)
            .busy_next()
            .set_at(level, now + phase * NSEC_PER_MSEC);
        return 0;
    }
    if level == LLC {
        // Of an SMT core, the least loaded sibling balances its LLC.
        let ends = dst.ends();
        let own = load::cid_load(dst, now);
        let mut lighter = false;
        for_each(
            ends.core_base,
            ends.core.saturating_sub(ends.core_base),
            |cid| {
                if cid != dst.raw() {
                    let other = load::cid_load(Cid(cid), now);
                    if other < own || (other == own && cid < dst.raw()) {
                        lighter = true;
                        return false;
                    }
                }
                true
            },
        );
        if lighter {
            return 0;
        }
    }
    if time_before(now, newidle::entry(dst).busy_next().get_at(level))
        || dsq::nr_queued(Dsq::Local) > 0
    {
        return 0;
    }
    if nr == Cid::count() {
        newidle::update_overloaded(base, nr);
    }
    let mut start = newidle::entry(dst).scan_from().get_at(level) as u32;
    if start < base || start >= base + nr {
        start = base;
    }
    newidle::entry(dst).detach_failed().set(0);
    newidle::entry(dst).level().set(level);
    let src = 'select: {
        // update_idle_cpu_scan() runs for every domain with shared
        // state: the LLC, and the asymmetric capacity domain where it
        // is a wider one.
        let sis = if level == LLC {
            1
        } else if level == NODE
            && tiers::asym_capacity()
            && idle::asym_range(dst) == range
            && idle::asym_domain_shared(dst, range)
        {
            2
        } else {
            0
        };
        let avg_norm = balance_avg_load(base, nr, now, sis);
        newidle::entry(dst).avg_norm().set(avg_norm);
        let dst_norm =
            newidle::entry(dst).sample().get() * 1024 / pressure::cid_balance_capacity(dst).max(1);
        newidle::entry(dst).dst_norm().set(dst_norm);
        if dst_norm >= avg_norm {
            break 'select -1;
        }
        newidle::entry(dst)
            .dst_overloaded()
            .set(u64::from(dst.has_queued()));
        let (local_base, local_nr) = child_group(dst, level);
        newidle::entry(dst).local_base().set(u64::from(local_base));
        newidle::entry(dst).local_nr().set(u64::from(local_nr));
        let room = balance_group_delta(
            dst,
            u64::from(local_nr) << 32 | u64::from(local_base),
            avg_norm,
            0,
        );
        newidle::entry(dst).local_room().set(room);
        let (load, cap) = (
            newidle::entry(dst).group_load().get(),
            newidle::entry(dst).group_cap().get().max(1),
        );
        newidle::entry(dst).local_norm().set(load * 1024 / cap);
        newidle::entry(dst)
            .local_overloaded()
            .set(u64::from(load > cap));
        if room == 0 || balance_find_group(dst, base, nr) == 0 {
            break 'select -1;
        }
        let src = balance_find_cid(dst, start).raw();
        if src < 0 {
            break 'select -1;
        }
        if balance_movable(dst, Cid(src), now) == 0 {
            newidle::entry(dst).detach_failed().set(1);
            newidle::entry(dst).busy_failed().set_at(
                level,
                (newidle::entry(dst).busy_failed().get_at(level) + 1).min(63),
            );
            break 'select -1;
        }
        src
    };
    // fair.c resets nr_balance_failed once the domain is balanced.
    if src < 0 && newidle::entry(dst).detach_failed().get() == 0 {
        newidle::entry(dst).busy_failed().set_at(level, 0);
    }
    // The selection can go to another CID, whose dispatch drains it:
    // claim that CID's slot first, so that a pass failing to cannot
    // extend an older selection, and publish the source last.
    let mut selected = src >= 0;
    let target = newidle::entry(dst).move_dst().get() as i32;
    if selected
        && (!newidle::valid(Cid(target))
            || newidle::entry(Cid(target))
                .source()
                .compare_exchange(NO_SOURCE, CLAIMING)
                != NO_SOURCE)
    {
        selected = false;
    }
    if selected {
        newidle::entry(Cid(target))
            .drain_deadline()
            .set(newidle::entry(dst).scan_deadline().get());
        newidle::entry(Cid(target))
            .drain_seq()
            .set(newidle::entry(dst).scan_seq().get());
        newidle::entry(Cid(target)).drain_valid().set(CURSOR_AT);
        newidle::entry(Cid(target))
            .expire()
            .set(now + min_ms * NSEC_PER_MSEC);
        newidle::entry(Cid(target))
            .budget()
            .set(newidle::entry(dst).move_budget().get());
        newidle::entry(Cid(target)).owner().set(dst.raw() as u64);
        newidle::entry(Cid(target)).owner_level().set(level);
        newidle::entry(Cid(target)).source().release(src as u64);
        if target != dst.raw() {
            Cid(target).kick(KickFlags::IDLE);
        }
    }
    newidle::entry(dst).scan_from().set_at(
        level,
        if selected {
            src as u64 + 1
        } else {
            u64::from(start) + 1
        },
    );
    let interval = if selected {
        min_ms
    } else {
        (interval * 2).min(max_ms)
    };
    newidle::entry(dst).busy_interval().set_at(level, interval);
    newidle::entry(dst)
        .busy_next()
        .set_at(level, now + interval * NSEC_PER_MSEC);
    u32::from(selected)
}

/// The tick's periodic balance on `cid`: the system, node and LLC domains
/// in turn, the widest first, stopping at a pending selection. Returns
/// whether one is pending.
#[inline(always)]
pub fn tick(cid: Cid, now: u64) -> bool {
    let count = Cid::count();
    let (node_nr, node_base) = cid.node_span();
    let (llc_nr, llc_base) = cid.llc_span();
    if count > node_nr && balance_domain(cid, u64::from(count) << 32, SYSTEM, now) != 0 {
        return true;
    }
    if node_nr > llc_nr
        && balance_domain(
            cid,
            u64::from(node_nr) << 32 | u64::from(node_base),
            NODE,
            now,
        ) != 0
    {
        return true;
    }
    balance_domain(cid, u64::from(llc_nr) << 32 | u64::from(llc_base), LLC, now) != 0
}

/// Move the next task of the selection on `dst`, from `src`, if it wins
/// `dst`'s own pick against `rival`, the deadline of what `dst` would run
/// otherwise, 0 for nothing. Returns 1 if a task moved, 0 if there was
/// nothing to move, -1 if a task lost or the queue was busy, so that the
/// selection is tried again at the next dispatch.
#[scx_rustsched::global]
pub fn balance_drain(dst: Cid, src: Cid, rival: u64) -> i32 {
    let now = time::now();
    let owner = newidle::entry(dst).owner().get() as i32;
    let level = newidle::entry(dst).owner_level().get();
    let failed = if newidle::valid(Cid(owner)) && level <= LLC {
        newidle::entry(Cid(owner)).busy_failed().get_at(level)
    } else {
        0
    };
    let tries = newidle::cache_nice_tries();
    let budget = newidle::entry(dst).budget().get();
    let mut cursor = Cursor {
        deadline: newidle::entry(dst).drain_deadline().get(),
        seq: newidle::entry(dst).drain_seq().get(),
        valid: newidle::entry(dst).drain_valid().get(),
    };
    let mut outcome = 0;
    for_each(0, TASK_SCAN as u32, |_| {
        let held = match dsq::peek_next::<Context>(Edq::Cid(src), &mut cursor) {
            Next::Task(held) => held,
            Next::Busy => {
                outcome = -1;
                return false;
            }
            Next::End => return false,
        };
        let state = held.slot();
        let weight = state.member().get() & u64::from(u32::MAX);
        let task = held.task();
        // A task passed over is let go as `held` is dropped.
        let Some(task) = task.filter(|task| {
            held.is_queued()
                && (weight >> failed.min(63)) <= budget
                && !(newidle::task_hot(&state, src, dst, now) && failed <= tries)
                && crate::allowed_on(task, dst)
                && !task.is_blocked()
        }) else {
            return true;
        };
        // Where the task would stand here, with the lag it has on `src`.
        let limit = lag_limit(crate::lag_request(task), weight);
        let owed = lag(pack::reference_at(src, now), state.vtime().get(), limit);
        let (deadline, eligibility, _) = held.key();
        let placed = pack::reference_at(dst, now).wrapping_sub(owed as u64);
        let placed_deadline = placed.wrapping_add(deadline.wrapping_sub(eligibility));
        if rival != 0
            && ((crate::features::eligibility() && owed < 0)
                || !time_before(placed_deadline, rival))
        {
            outcome = -1;
            return true;
        }
        match held.move_to_local(dst) {
            Moved::Done => {}
            Moved::Lost => return true,
            Moved::Busy => {
                outcome = -1;
                return false;
            }
        }
        newidle::entry(dst)
            .budget()
            .set(budget.saturating_sub(weight));
        newidle::entry(dst).drain_valid().set(CURSOR_START);
        outcome = 1;
        false
    });
    if outcome != 1 {
        newidle::entry(dst).drain_deadline().set(cursor.deadline);
        newidle::entry(dst).drain_seq().set(cursor.seq);
        newidle::entry(dst).drain_valid().set(cursor.valid);
    }
    outcome
}

/// Drain the selection pending on `dst`, from its dispatch, against
/// `rival`, see balance_drain(). Returns whether a task moved. A
/// selection that lapsed is dropped, and one with weight left to move is
/// kept for the next dispatch. Only this dispatch clears the slot once a
/// selection is published in it, so plain stores do.
/// Is a selection pending on `dst` for its dispatch to drain?
#[inline(always)]
pub fn pending(dst: Cid) -> bool {
    newidle::valid(dst) && {
        let source = newidle::entry(dst).source().get();
        source != NO_SOURCE && source != CLAIMING
    }
}

pub fn dispatch(dst: Cid, rival: u64, now: u64) -> bool {
    if !newidle::valid(dst) {
        return false;
    }
    let source = newidle::entry(dst).source().get();
    if source == NO_SOURCE || source == CLAIMING {
        return false;
    }
    if !time_before(now, newidle::entry(dst).expire().get()) {
        newidle::entry(dst).source().set(NO_SOURCE);
        return false;
    }
    let src = source as i32;
    let moved = balance_drain(dst, Cid(src), rival);
    if moved == 1 {
        // The pass that made the selection found something to move.
        let (owner, level) = (
            newidle::entry(dst).owner().get() as i32,
            newidle::entry(dst).owner_level().get(),
        );
        if newidle::valid(Cid(owner)) && level <= LLC {
            newidle::entry(Cid(owner)).busy_failed().set_at(level, 0);
        }
    }
    if moved >= 0 {
        dsq::queued_check(Cid(src));
    }
    let keep =
        (moved == 1 && newidle::entry(dst).budget().get() != 0 && dsq::queued_test(Cid(src)))
            || moved < 0;
    if !keep {
        newidle::entry(dst).source().set(NO_SOURCE);
    }
    moved == 1
}
