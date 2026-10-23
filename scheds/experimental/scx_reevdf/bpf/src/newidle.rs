// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.

//! The idle pull, sched_balance_newidle(): a CID that has run out of work
//! looks for some on its neighbours before it lets the CPU go idle.
//!
//! Work moves between CIDs in two other ways: balance.rs moves queued
//! tasks between CIDs that stay busy, and active.rs moves a task that is
//! running. The per-CID table declared here holds the state of all three.
//!
//! ```text
//! is the CID staying idle longer than an LLC scan costs?   no -> go idle
//! NI_RANDOM: admit the scan as often as scans have paid    no -> go idle
//! its own LLC, the rest of the node, the rest of the system, stopping at
//! the first task taken and at a level the idle budget no longer covers
//! ```
//!
//! A CPU whose idle periods are shorter than a scan is one its own wakeups
//! keep bringing back, and pulling for it costs more than the idle time it
//! fills. As in fair.c, `avg_idle` tracks how long the CID stays idle after
//! a pull, each level keeps the worst pull it has cost, decayed 1% a second,
//! and a level is skipped once the budget left is smaller than its record.
//! On top of that, NI_RANDOM admits a level's scans in proportion to how
//! often they have found anything, weighing a success by the inverse of its
//! sampling probability.
//!
//! Cache hotness is honoured until `cache_nice_tries` scans in a row came
//! back empty with work queued somewhere, and is then dropped one level at
//! a time, can_migrate_task() against sd->nr_balance_failed: an idle CPU
//! beside a runnable task is worse than a cold cache.
//!
//! Counterpart in scx_eevdf: newidle.bpf.c.

use crate::{
    accounting::{
        NEWIDLE_DECAY_NS, avg_idle_update, newidle_cost_update, newidle_sample, newidle_stats_fold,
        time_before,
    },
    balance_state, cid_idle, cid_table, helpers,
    taskctx::Context,
    tiers,
};
use scx_rustsched::arena::{Field, Words};
use scx_rustsched::dsq::{self, Edq};
use scx_rustsched::sched::Cid;
use scx_rustsched::time;
use scx_rustsched::var::Var;

/// Words of a CID's balance state; balance.rs uses those after CURSOR, and
/// active.rs those after balance.rs, followed again by balance.rs's. The
/// ones the loader reads for its statistics are balance_state.rs's.

const LLC: u64 = balance_state::NEWIDLE_LLC;
const NODE: u64 = balance_state::NEWIDLE_NODE;
const SYSTEM: u64 = balance_state::NEWIDLE_SYSTEM;

/// scan_range() results besides a victim.
const NOTHING_TAKEN: i32 = -1;
const NOTHING_QUEUED: i32 = -2;

scx_rustsched::arena_struct! {
    /// What the balancers keep per CID: the idle pull's words here, periodic
    /// balance's in balance.rs and active balance's in active.rs. 1024
    /// bytes. The words the loader watches are at the indexes
    /// balance_state.rs gives it, which the checks below hold to this
    /// layout. A field of three words has one per level.
    pub struct Balance {
        avg_idle: u64,
        /// When the current pull began, 0 outside one: the idle period it starts
        /// ends when the CID leaves idle.
        idle_stamp: u64,
        /// The worst whole pull, rq->max_idle_balance_cost.
        max_balance_cost: u64,
        /// Per level: the worst pull, when it decayed, and NI_RANDOM's calls,
        /// successes, fold stamp and ratio.
        newidle_cost: [u64; 3],
        newidle_cost_at: [u64; 3],
        newidle_calls: [u64; 3],
        newidle_successes: [u64; 3],
        newidle_stats_at: [u64; 3],
        newidle_ratio: [u64; 3],
        /// Scans in a row that found work queued but took nothing.
        newidle_failed: u64,
        /// Where the last scan stopped, so that successive ones cover the domain.
        newidle_cursor: u64,
        /// Words of a CID's balance state after the newidle ones, per level for
        /// the first four.
        busy_interval: [u64; 3],
        busy_next: [u64; 3],
        scan_from: [u64; 3],
        busy_failed: [u64; 3],
        /// The pending selection a destination drains: the source CID, or
        /// NO_SOURCE, when it lapses, the weight it may still move, the pass's
        /// owner and level, and the drain cursor.
        source: u64,
        expire: u64,
        budget: u64,
        owner: u64,
        owner_level: u64,
        drain_deadline: u64,
        drain_seq: u64,
        drain_valid: u64,
        /// This pass's load sample of the CID.
        sample: u64,
        pad0: u64,
        /// The pass's working values, on the balancing CID.
        avg_norm: u64,
        dst_norm: u64,
        dst_overloaded: u64,
        local_base: u64,
        local_nr: u64,
        local_room: u64,
        local_norm: u64,
        local_overloaded: u64,
        level: u64,
        group_load: u64,
        group_cap: u64,
        group_queued: u64,
        src_base: u64,
        src_nr: u64,
        src_excess: u64,
        move_budget: u64,
        scan_deadline: u64,
        scan_seq: u64,
        detach_failed: u64,
        /// Words of a CID's balance state after balance.rs's.
        active_pending: u64,
        active_next: u64,
        active_interval: u64,
        /// On a source: the destination that asked for its running task, plus one.
        active_target: u64,
        /// When the CID's SMT siblings became busy beside it, 0 if they are not.
        smt_busy_since: u64,
        /// After active.rs's words: where the selection goes, and the first task
        /// found that could only go to another CID of the local group, with that
        /// CID.
        move_dst: u64,
        alt_dst: u64,
        alt_deadline: u64,
        alt_seq: u64,
        pad1: Words<3>,
        /// An enqueue kicked this CID to pull its last task, see force_steal().
        /// After balance.rs's and active.rs's words.
        force_steal: u64,
        /// Where the last pull from this CID's queue stopped, a
        /// [`dsq::Cursor`]'s three words, so that the next one resumes past
        /// the tasks it passed over. After FORCE_STEAL.
        detach_cursor: [u64; 3],
        /// Where the last scan of this CID's queue for a movable task stopped, so
        /// that the next one resumes past the tasks it passed over: three words
        /// after newidle.rs's detach cursor.
        busy_scan_cursor: [u64; 3],
        /// Whether the last pull took nothing while the system is
        /// overloaded, see overload_check().
        newidle_stuck: u64,
        pad2: Words<44>,
    }
}

scx_rustsched::cid_slot!(Balance, BALANCE in ".data.balance");

const _: () = {
    use core::mem::offset_of;
    type Layout = <Balance as scx_rustsched::arena::Struct>::Layout;
    assert!(<Balance as scx_rustsched::arena::Struct>::SIZE == balance_state::BYTES);
    assert!(offset_of!(Layout, avg_idle) as u64 == balance_state::AVG_IDLE * 8);
    assert!(offset_of!(Layout, max_balance_cost) as u64 == balance_state::MAX_BALANCE_COST * 8);
    assert!(offset_of!(Layout, newidle_cost) as u64 == balance_state::NEWIDLE_COST * 8);
    assert!(offset_of!(Layout, newidle_ratio) as u64 == balance_state::NEWIDLE_RATIO * 8);
    assert!(offset_of!(Layout, newidle_failed) as u64 == balance_state::NEWIDLE_FAILED * 8);
    assert!(offset_of!(Layout, busy_interval) as u64 == balance_state::BUSY_INTERVAL * 8);
    assert!(offset_of!(Layout, busy_failed) as u64 == balance_state::BUSY_FAILED * 8);
    assert!(offset_of!(Layout, active_interval) as u64 == balance_state::ACTIVE_INTERVAL * 8);
};

/// The entry of `cid`, which the caller knows is a CID, see valid().
#[inline(always)]
pub(crate) fn entry(cid: Cid) -> Balance {
    cid_table::entry(cid)
}

#[inline(always)]
fn migration_cost_ns() -> u64 {
    crate::MIGRATION_COST_NS.get()
}

#[inline(always)]
pub(crate) fn cache_nice_tries() -> u64 {
    crate::CACHE_NICE_TRIES.get()
}

#[inline(always)]
pub(crate) fn valid(cid: Cid) -> bool {
    cid_table::valid::<Balance>(cid)
}

/// The cursor pulls from `cid`'s queue resume at, see DETACH_CURSOR.
#[inline(always)]
pub(crate) fn detach_cursor(cid: Cid) -> dsq::Cursor {
    load_cursor(entry(cid).detach_cursor())
}

#[inline(always)]
pub(crate) fn save_detach_cursor(cid: Cid, cursor: &dsq::Cursor) {
    store_cursor(entry(cid).detach_cursor(), cursor)
}

/// Take a task that can run on `dst`, the dispatching CID, from `victim`'s
/// queue: with `check_hot`, a task cache hot on the victim is passed over,
/// and the scan resumes where the last pull from `victim` stopped.
#[inline(always)]
pub(crate) fn steal_from(dst: Cid, victim: Cid, check_hot: bool, now: u64) -> bool {
    let mut cursor = detach_cursor(victim);
    let moved = dsq::move_to_local_scan(Edq::Cid(victim), dst, &mut cursor, |state: Context| {
        check_hot && task_hot(&state, victim, dst, now)
    });
    save_detach_cursor(victim, &cursor);
    moved
}

/// A cursor kept in three words of a CID's entry.
#[inline(always)]
pub(crate) fn load_cursor<const O: u64>(words: Field<[u64; 3], O>) -> dsq::Cursor {
    let [deadline, seq, valid] = words.get();
    dsq::Cursor {
        deadline,
        seq,
        valid,
    }
}

#[inline(always)]
pub(crate) fn store_cursor<const O: u64>(words: Field<[u64; 3], O>, cursor: &dsq::Cursor) {
    words.set([cursor.deadline, cursor.seq, cursor.valid]);
}

/// Allocate the table and start every CID with fair.c's initial idle
/// average, twice the migration cost, and a sampling ratio of one half.
pub fn init(_count: u32) -> i32 {
    cid_table::init_slots::<Balance>()
}

/// Initialize `cid`'s entry, from `init`.
pub fn init_cid(cid: Cid) {
    if !valid(cid) {
        return;
    }
    entry(cid).avg_idle().set(2 * migration_cost_ns());
    entry(cid).max_balance_cost().set(migration_cost_ns());
    for level in [LLC, NODE, SYSTEM] {
        entry(cid).newidle_ratio().set_at(level, 512);
    }
    crate::balance::init_cid(cid);
}

/// task_hot(): did the task of `state` run on `src` too recently to leave
/// its cache for `dst`? SMT siblings share the cache and never count as hot.
#[inline(always)]
pub fn task_hot(state: &Context, src: Cid, dst: Cid, now: u64) -> bool {
    if cid_idle::smt() && src.same_core(dst) {
        return false;
    }
    time_before(
        now,
        state.last_stop_at().get().wrapping_add(migration_cost_ns()),
    )
}

/// The CID leaves idle: the idle period that a pull started ends here.
#[inline(always)]
pub fn idle_ended(cid: Cid, now: u64) {
    if !valid(cid) {
        return;
    }
    let stamp = entry(cid).idle_stamp().get();
    if stamp == 0 {
        return;
    }
    let average = avg_idle_update(
        entry(cid).avg_idle().get(),
        now.wrapping_sub(stamp),
        entry(cid).max_balance_cost().get(),
    );
    entry(cid).avg_idle().set(average);
    entry(cid).idle_stamp().set(0);
}

/// Decay the per-level records from the CID's tick, so that one spike does
/// not close the budget for good.
#[inline(always)]
pub fn decay(cid: Cid, now: u64) {
    if !valid(cid) {
        return;
    }
    let mut decayed = false;
    let mut sum = 0;
    for level in [LLC, NODE, SYSTEM] {
        let record = entry(cid).newidle_cost().get_at(level);
        if time_before(
            entry(cid)
                .newidle_cost_at()
                .get_at(level)
                .wrapping_add(NEWIDLE_DECAY_NS),
            now,
        ) {
            entry(cid).newidle_cost().set_at(level, record * 253 / 256);
            entry(cid).newidle_cost_at().set_at(level, now);
            decayed = true;
        }
        sum += entry(cid).newidle_cost().get_at(level);
    }
    if decayed {
        entry(cid)
            .max_balance_cost()
            .set(sum.max(migration_cost_ns()));
    }
}

/// Count a scan at `level` that found work with `weight`, or nothing with 0.
#[inline(always)]
fn sampled(cid: Cid, level: u64, weight: u64, now: u64) {
    let calls = entry(cid).newidle_calls().get_at(level) + 1;
    let successes = entry(cid).newidle_successes().get_at(level) + weight;
    let (calls, successes, stamp, ratio) = newidle_stats_fold(
        calls,
        successes,
        entry(cid).newidle_stats_at().get_at(level),
        entry(cid).newidle_ratio().get_at(level),
        now,
    );
    entry(cid).newidle_calls().set_at(level, calls);
    entry(cid).newidle_successes().set_at(level, successes);
    entry(cid).newidle_stats_at().set_at(level, stamp);
    entry(cid).newidle_ratio().set_at(level, ratio);
}

/// Take a task for `dst` from the queued CIDs of `word`, mask word `index`
/// rotated right by `shift`, packed as `index << 16 | shift`. Returns the
/// victim, NOTHING_TAKEN if none of them had a task to give, or
/// NOTHING_QUEUED if there were none.
///
/// A global function with scalar arguments, which the verifier checks once
/// on its own rather than again inside the dispatch callback's states.
#[scx_rustsched::global]
pub fn steal_word(dst: Cid, word: u64, packed: u32, check_hot: u32) -> i32 {
    let (index, shift) = (packed >> 16, packed & 63);
    let now = time::now();
    let mut bits = word.rotate_right(shift);
    let mut found = NOTHING_QUEUED;
    for _ in crate::loops::range(0, 64) {
        if bits == 0 {
            break;
        }
        let victim = (index * 64 + ((bits.trailing_zeros() + shift) & 63)) as i32;
        bits &= bits - 1;
        if victim == dst.raw() || !valid(Cid(victim)) {
            continue;
        }
        if steal_from(dst, Cid(victim), check_hot != 0, now) {
            found = victim;
            break;
        }
        found = NOTHING_TAKEN;
    }

    found
}

scx_rustsched::shared! {
    /// The root domain's overload indicator, rd->overloaded: set when a CID
    /// gets a task queued behind the one it runs, as add_nr_running() sets
    /// it when a runqueue reaches two tasks, or is asked for its running
    /// task, see note_active_balance(), and recomputed by any balance
    /// of the whole system, periodic or newly idle, as update_sd_lb_stats()
    /// does at the root. Written only when it changes, on a line of its
    /// own, as it is read on every enqueue.
    static OVERLOADED in ".data.overload": Var<u64> = Var::new(0);
}

/// A task was queued on `cid`: if something runs there, the system is
/// overloaded.
#[inline(always)]
pub fn note_queued(cid: Cid) {
    if OVERLOADED.get() == 0 && crate::pack::running(cid) {
        OVERLOADED.set(1);
    }
}

/// An active balance request went out to a CID. fair.c queues the stopper
/// beside the task running there, and that second runnable task sets the
/// indicator as any other would.
#[inline(always)]
pub fn note_active_balance() {
    if OVERLOADED.get() == 0 {
        OVERLOADED.set(1);
    }
}

/// A periodic balance of the whole system, `nr` CIDs from `base`: the
/// system is overloaded while some CID has work queued.
pub fn update_overloaded(base: u32, nr: u32) {
    let mut queued = 0;
    if nr != 0 {
        for index in crate::loops::range(base / 64, (base + nr - 1) / 64 + 1) {
            if dsq::queued_word(index) & range_bits(index, base, nr) != 0 {
                queued = 1;
                break;
            }
        }
    }
    if OVERLOADED.get() != queued {
        OVERLOADED.set(queued);
    }
}

/// The bits of mask word `index` that fall in [base, base + nr).
#[inline(always)]
fn range_bits(index: u32, base: u32, nr: u32) -> u64 {
    let (first, end) = (index * 64, index * 64 + 64);
    let low = base.max(first) - first;
    let high = (base + nr).min(end).saturating_sub(first);
    if high <= low {
        0
    } else if high - low == 64 {
        u64::MAX
    } else {
        ((1 << (high - low)) - 1) << low
    }
}

/// Take a task for `dst` from the CIDs of `range`, `nr << 32 | base`, walked
/// from `start` with wraparound, a word of the queued mask at a time.
/// `control` packs whether cache-hot tasks stay, in bit 0, and a packing
/// tier plus one to restrict the scan to, 0 for none, from bit 8. Returns
/// the victim, NOTHING_TAKEN if work was queued but none could be taken,
/// or NOTHING_QUEUED.
#[scx_rustsched::global]
pub fn steal_range(dst: Cid, range: u64, start: u32, control: u32) -> i32 {
    let (check_hot, tier) = (control & 1, control >> 8);
    let (base, nr) = (range as u32, (range >> 32) as u32);
    if nr == 0 {
        return NOTHING_QUEUED;
    }
    let start = if start >= base && start < base + nr {
        start
    } else {
        base
    };
    let (first, last) = (base / 64, (base + nr - 1) / 64);
    let span = last - first + 1;
    let offset = start / 64 - first;
    let mut found = NOTHING_QUEUED;
    for value in crate::loops::range(0, span) {
        let step = value;
        let index = first + (offset + step).checked_rem(span).unwrap_or(0);
        let mut word = dsq::queued_word(index) & range_bits(index, base, nr);
        if tier != 0 {
            word &= tiers::place_word(tier - 1, index);
        }
        if word == 0 {
            continue;
        }
        // The first word starts at `start`, and the CIDs before it in
        // that word come last.
        let shift = if step == 0 { start & 63 } else { 0 };
        match steal_word(dst, word, index << 16 | shift, check_hot) {
            NOTHING_QUEUED => {}
            NOTHING_TAKEN => found = NOTHING_TAKEN,
            victim => {
                found = victim;
                break;
            }
        }
    }
    found
}

/// Take a task for `dst` from the packing tiers worse than its own across
/// `range`, `nr << 32 | base`, the worst first; `check_hot` as for
/// steal_range(). Returns the victim, NOTHING_TAKEN or NOTHING_QUEUED.
/// A global function, verified once rather than within ops.dispatch().
#[scx_rustsched::global]
pub fn steal_tiers(dst: Cid, range: u64, check_hot: u32) -> i32 {
    let places = tiers::nr_place_tiers();
    let own = dst.place_tier();
    if places <= own + 1 {
        return NOTHING_QUEUED;
    }
    let mut found = NOTHING_QUEUED;
    for value in crate::loops::range(0, places - own - 1) {
        // Tier places - 1 - step, plus one.
        let tier = places - value;
        let result = steal_range(dst, range, range as u32, check_hot & 1 | tier << 8);
        if result >= 0 {
            found = result;
            break;
        }
        if result == NOTHING_TAKEN {
            found = NOTHING_TAKEN;
        }
    }
    found
}

#[inline(never)]
/// Let `cid`, kicked by an enqueue that left a CPU's last task queued alone,
/// pull without the idle-time budget, the sampling or cache hotness on its
/// next dispatch, scx_eevdf's force_steal: it is not ending an idle period
/// of its own, and the task it was sent for has nowhere else to run soon.
pub fn force_steal(cid: Cid) {
    if valid(cid) {
        entry(cid).force_steal().set(1);
    }
}

/// The end of an idle pull that took nothing, `found` being its result:
/// whether it balanced, `scanned`, while the system is overloaded or had
/// `work` queued it could not take, the case in which sched_balance_rq()
/// goes on to need_active_balance(). As in fair.c, a balance at the root
/// that found nothing queued, `root_empty`, recomputes the indicator only
/// after the pass that read it. A global function, so that ops.dispatch()
/// is verified without the branches.
#[scx_rustsched::global]
pub fn overload_check(found: i32, scanned: u32, work: u32, root_empty: u32) -> u32 {
    let overloaded = OVERLOADED.get() != 0;
    if root_empty != 0 && overloaded {
        OVERLOADED.set(0);
    }
    u32::from(found < 0 && scanned != 0 && (work != 0 || overloaded))
}

/// Pull a task for `cid`, which has nothing of its own left to run, from
/// its LLC, its node and the system in turn. Returns whether one was taken,
/// and records in newidle_stuck whether an active balance should follow,
/// see overload_check(). A pull `kicked` for an active
/// balance is neither budgeted nor sampled and does not start an idle
/// period: that is the idle balancer running for nohz_balancer_kick(),
/// which fair.c does not gate by avg_idle either.
pub fn try_steal(cid: Cid, kicked: bool) -> bool {
    if !valid(cid) {
        return false;
    }
    if entry(cid).newidle_stuck().get() != 0 {
        entry(cid).newidle_stuck().set(0);
    }
    let now = time::now();
    // The kick that set this bought one dispatch, spent here whatever
    // it finds: the task it was sent for is often taken back by its
    // own CID first, and a permission outliving that would fire on an
    // unrelated pull later.
    let forced = entry(cid).force_steal().get() != 0;
    if forced {
        entry(cid).force_steal().set(0);
    }
    let kicked = kicked || forced;
    let count = Cid::count();
    let failed = entry(cid).newidle_failed().get();
    let mut start = entry(cid).newidle_cursor().get() as u32;
    if start >= count {
        start = 0;
    }
    if !kicked {
        entry(cid).idle_stamp().set(now);
    }
    let budget = !kicked && !crate::NO_NEWIDLE_COST.get();
    let sampling = !kicked && !crate::NO_NEWIDLE_SAMPLING.get();
    let avg_idle = entry(cid).avg_idle().get();
    if budget && avg_idle < entry(cid).newidle_cost().get_at(LLC) {
        return false;
    }
    let (llc_nr, llc_base) = cid.llc_span();
    let (node_nr, node_base) = cid.node_span();
    let tries = cache_nice_tries();
    let mut t0 = helpers::ktime_get_ns();
    let mut spent = 0;
    let mut found = NOTHING_QUEUED;
    let mut scanned = false;
    let mut saw_work = false;
    // Whether a scan of every CID found nothing queued, the root domain's
    // update_sd_lb_stats() finding no runqueue with a task waiting.
    let mut root_empty = false;
    for (level, base, nr, wider) in [
        (LLC, llc_base, llc_nr, true),
        (NODE, node_base, node_nr, node_nr > llc_nr),
        (SYSTEM, 0, count, count > node_nr),
    ] {
        if found >= 0 || !wider {
            continue;
        }
        // Skip a level whose worst pull the idle time left will not pay.
        if budget && level != LLC && avg_idle < spent + entry(cid).newidle_cost().get_at(level) {
            break;
        }
        let weight = if sampling {
            match newidle_sample(
                entry(cid).newidle_ratio().get_at(level),
                helpers::get_prandom_u32(),
            ) {
                Some(weight) => weight,
                None => {
                    sampled(cid, level, 0, now);
                    continue;
                }
            }
        } else {
            1
        };
        scanned = true;
        let check_hot = !forced && failed <= tries + level;
        // An idle CID of a better packing tier first takes what is
        // queued on the node's worse tiers, the worst first, as fair.c
        // lets sched_asym_prefer() pull to a preferred CPU. Only a whole
        // idle core counts as idle there.
        let places = tiers::nr_place_tiers();
        let own = cid.place_tier();
        if level == LLC && places > own + 1 && (!cid_idle::smt() || cid.is_core_idle()) {
            found = steal_tiers(
                cid,
                u64::from(node_nr) << 32 | u64::from(node_base),
                u32::from(failed <= tries),
            );
        }
        if found < 0 {
            let result = steal_range(
                cid,
                u64::from(nr) << 32 | u64::from(base),
                start + 1,
                u32::from(check_hot),
            );
            if result != NOTHING_QUEUED || found == NOTHING_QUEUED {
                found = result;
            }
        }
        if found != NOTHING_QUEUED {
            saw_work = true;
        }
        if nr == count {
            root_empty = found == NOTHING_QUEUED;
        }
        let t1 = helpers::ktime_get_ns();
        if budget {
            let cost = t1 - t0;
            spent += cost;
            let (record, stamp) = newidle_cost_update(
                entry(cid).newidle_cost().get_at(level),
                entry(cid).newidle_cost_at().get_at(level),
                cost,
                t1,
            );
            entry(cid).newidle_cost().set_at(level, record);
            entry(cid).newidle_cost_at().set_at(level, stamp);
            t0 = t1;
        }
        if sampling {
            sampled(cid, level, if found >= 0 { weight } else { 0 }, t1);
        }
    }
    if spent > entry(cid).max_balance_cost().get() {
        entry(cid).max_balance_cost().set(spent);
    }
    if scanned {
        // Nothing queued anywhere it looked is balance, not failure.
        entry(cid).newidle_failed().set(if found >= 0 || !saw_work {
            0
        } else {
            failed + 1
        });
        entry(cid).newidle_cursor().set(if found >= 0 {
            found as u64
        } else {
            u64::from(start + 1)
        });
    }
    let stuck = overload_check(
        found,
        u32::from(scanned),
        u32::from(saw_work),
        u32::from(root_empty),
    );
    entry(cid).newidle_stuck().set(u64::from(stuck));
    found >= 0
}
