// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Piotr Gorski <lucjan.lucjanov@gmail.com>

//! The arithmetic of the policy, over plain numbers: the classes a task's
//! history puts it in, the slice it is granted, the virtual time it is
//! queued at and the verdicts on the task running where it wakes.
//!
//! Nothing here reads the kernel or the arena, so the loader's tests
//! include this file as it is and check it on the host, tests/policy.rs.
//!
//! Every product and difference wraps as scx_cake's do in C: the
//! overflows the C side accepts are accepted here too, and none of them
//! may become a panic path the BPF object cannot have.
//!
//! Counterpart in scx_cake: the inline helpers of cake.bpf.c and the
//! constants of intf.h.

pub const NSEC_PER_USEC: u64 = 1000;
pub const NSEC_PER_MSEC: u64 = 1000 * NSEC_PER_USEC;

/// The slice every task gets where no adaptive one applies, and the unit
/// most margins below are counted in.
pub const SLICE_NS: u64 = 3 * NSEC_PER_MSEC;

/// The fractions of SLICE_NS an occupant runs before a wakeup preempts
/// it: on the wakee's own CID, and on a neighbour's.
pub const PREEMPT_PROTECT_SHIFT: u32 = 4;
pub const PROBE_PROTECT_SHIFT: u32 = 2;

/// The adaptive slice is capped at SLICE_NS >> this, and the task's mean
/// cycle is its age >> this.
pub const PERIOD_SLICE_CAP_SHIFT: u32 = 1;

/// Pre-scale of the wait and run totals in the starvation tests: it cancels
/// in the cross-multiplication and keeps the products from overflowing.
pub const RATIO_SHIFT: u32 = 16;

/// A pool not served for this long is taken first, from any LLC.
pub const WAKE_STARVE_WALL_NS: u64 = 24 * NSEC_PER_MSEC;
/// An empty pool counts as served, refreshed at most this often.
pub const WAKE_STARVE_REFRESH_NS: u64 = WAKE_STARVE_WALL_NS / 2;

/// Fixed-point weight reciprocals: (NICE_0_WEIGHT << RECIP_SHIFT) / weight.
pub const RECIP_SHIFT: u32 = 20;
pub const RECIP_MASK: u64 = (1 << RECIP_SHIFT) - 1;
pub const NICE_0_WEIGHT: u64 = 1024;
/// The reciprocal of WEIGHT_IDLEPRIO, 3, the largest a task has.
pub const MAX_RECIP_WEIGHT: u64 = 357_913_941;

/// A mean burst of at least this makes a task a stage, which earns a seat.
pub const SEAT_BURST_MIN_NS: u64 = 64 * NSEC_PER_USEC;

/// How short a quantum still counts as having woken someone and got out of
/// the way: a property of the CPU's switch path, not of the slice. It is
/// also the floor of the adaptive slice.
pub const HANDOFF_MAX_NS: u64 = 1464;

/// The frontier moves in steps of this: its readers work at slice scale.
pub const FRONTIER_GRAIN_NS: u64 = 1 << 16;

/// The serial-handoff hint of a CID: the bit the last select_cid there set,
/// and a saturating count of quanta that woke a task and blocked quickly.
pub const HINT_WOKE: u64 = 1;
pub const HINT_CONF_SHIFT: u32 = 8;
pub const HINT_CONF_MAX: u64 = 3;

/// Neighbours a wakeup that found no idle CID tries to preempt.
pub const NEIGHBOUR_PROBE_DEPTH: u32 = 3;

/// Is `first` before `second`, for two times or virtual times less than
/// half the range apart?
#[inline(always)]
pub fn time_before(first: u64, second: u64) -> bool {
    (first.wrapping_sub(second) as i64) < 0
}

/// `later - earlier`, or 0 when `later` is not later: deltas between the
/// clocks of two CPUs.
#[inline(always)]
pub fn time_delta(later: u64, earlier: u64) -> u64 {
    if time_before(earlier, later) {
        later.wrapping_sub(earlier)
    } else {
        0
    }
}

/// The voluntary switch count as a divisor: odd and never zero.
#[inline(always)]
pub fn switches(nvcsw: u64) -> u64 {
    nvcsw | 1
}

/// Mean burst: the runtime per voluntary switch.
#[inline(always)]
pub fn burst_ns(runtime: u64, nvcsw: u64) -> u64 {
    runtime.checked_div(switches(nvcsw)).unwrap_or(0)
}

/// Is the mean burst shorter than one handoff? Then no move costs less
/// than the wait it would cure. Past 2^32 switches the task leaves the
/// class.
#[inline(always)]
pub fn subhandoff(runtime: u64, nvcsw: u64) -> bool {
    let n = switches(nvcsw);
    n >> 32 == 0 && runtime < HANDOFF_MAX_NS.wrapping_mul(n)
}

/// Is the task a stage, a mean burst of at least SEAT_BURST_MIN_NS? The
/// product is formed only while it fits: beyond that no runtime reaches
/// the threshold.
#[inline(always)]
pub fn stage(runtime: u64, nvcsw: u64) -> bool {
    let n = switches(nvcsw);
    n <= u64::MAX / SEAT_BURST_MIN_NS && runtime >= SEAT_BURST_MIN_NS.wrapping_mul(n)
}

/// Does the task wait longer than it runs, mean wait (run_delay / pcount)
/// against mean burst (runtime / nvcsw), cross-multiplied? With
/// `turn_margin` the wait has to exceed two bursts: one turn of its own,
/// the least a move has to save to pay for itself.
#[inline(always)]
pub fn starved(runtime: u64, nvcsw: u64, run_delay: u64, pcount: u64, turn_margin: bool) -> bool {
    let wait = run_delay >> RATIO_SHIFT;
    let run = runtime >> RATIO_SHIFT;
    if run == 0 {
        return false;
    }
    let run = if turn_margin { run << 1 } else { run };
    wait.wrapping_mul(switches(nvcsw)) > run.wrapping_mul(pcount | 1)
}

/// The adaptive slice and the quotient behind it:
///
/// ```text
/// slice = max(HANDOFF_MAX_NS, min(2 * floor(runtime / n),
///                                 floor(age / (2 * n)),
///                                 SLICE_NS >> PERIOD_SLICE_CAP_SHIFT))
/// ```
///
/// with one division: q = floor(min(runtime, age / 4) / n), and the low
/// bit of the minimum is set only when both terms reach 2 * q + 1. q is
/// the mean burst whenever the runtime term is the smaller.
#[inline(always)]
pub fn slice_from_service(runtime: u64, age: u64, n: u64) -> (u64, u64) {
    let cycle_budget = age >> PERIOD_SLICE_CAP_SHIFT;
    let work = (cycle_budget >> 1).min(runtime);
    let q = work.checked_div(n).unwrap_or(0);
    let base = q.wrapping_mul(n);
    let odd = runtime.wrapping_sub(base) >= n && cycle_budget.wrapping_sub(base << 1) >= n;
    let want = (q << 1) + u64::from(odd);
    let want = want.min(SLICE_NS >> PERIOD_SLICE_CAP_SHIFT);
    (want.max(HANDOFF_MAX_NS), q)
}

/// A task younger than one slice counts as one slice old.
#[inline(always)]
pub fn task_age(age: u64) -> u64 {
    age.max(SLICE_NS)
}

/// The adaptive slice of a task, from its runtime, age and switches.
#[inline(always)]
pub fn task_slice(runtime: u64, age: u64, nvcsw: u64) -> u64 {
    slice_from_service(runtime, task_age(age), switches(nvcsw)).0
}

/// `vtime`, or `floor` if it is behind it: the sleeper clamp, wrap-safe.
#[inline(always)]
pub fn clamp_floor(floor: u64, vtime: u64) -> u64 {
    if time_before(vtime, floor) {
        floor
    } else {
        vtime
    }
}

/// The key of a continuation: its own virtual time, at most one slice
/// behind the frontier.
#[inline(always)]
pub fn continuation_key(frontier: u64, vtime: u64) -> u64 {
    clamp_floor(frontier.wrapping_sub(SLICE_NS), vtime)
}

/// Three quarters of the unused slice.
#[inline(always)]
pub fn sleeper_dose(unused: u64) -> u64 {
    (unused >> 1) + (unused >> 2)
}

/// A wakeup's slice and key, from one set of task inputs. The key is the
/// sleeper clamp against a floor that a starved task gets deeper, by
/// three quarters of the slice its mean burst leaves unused: a task that
/// waits more than it runs and runs briefly comes back ahead.
#[inline(always)]
pub fn admit(
    runtime: u64,
    age: u64,
    nvcsw: u64,
    starved: bool,
    frontier: u64,
    vtime: u64,
) -> (u64, u64) {
    let age = task_age(age);
    let n = switches(nvcsw);
    let (slice, q) = slice_from_service(runtime, age, n);
    let mut depth = 0;
    if starved {
        let burst = if runtime <= (age >> PERIOD_SLICE_CAP_SHIFT) >> 1 {
            q
        } else {
            runtime.checked_div(n).unwrap_or(0)
        };
        if burst < SLICE_NS {
            depth = sleeper_dose(SLICE_NS - burst);
        }
    }
    let floor = frontier.wrapping_sub(SLICE_NS).wrapping_sub(depth);
    (slice, clamp_floor(floor, vtime))
}

/// The fixed-point reciprocal of a weight, (NICE_0_WEIGHT << RECIP_SHIFT)
/// / weight: 1 << RECIP_SHIFT at nice 0, MAX_RECIP_WEIGHT for SCHED_IDLE.
#[inline(always)]
pub fn reciprocal(weight: u64) -> u64 {
    (NICE_0_WEIGHT << RECIP_SHIFT)
        .checked_div(weight)
        .unwrap_or(1 << RECIP_SHIFT)
}

/// `base` plus `runtime` scaled by the reciprocal weight. The product is
/// split at the radix where it would wrap, which is exact past years of
/// SCHED_IDLE runtime.
#[inline(always)]
pub fn scale_vtime_add(base: u64, runtime: u64, recip: u64) -> u64 {
    if recip <= MAX_RECIP_WEIGHT && runtime <= u64::MAX / MAX_RECIP_WEIGHT {
        return base.wrapping_add(runtime.wrapping_mul(recip) >> RECIP_SHIFT);
    }
    base.wrapping_add((runtime >> RECIP_SHIFT).wrapping_mul(recip))
        .wrapping_add((runtime & RECIP_MASK).wrapping_mul(recip) >> RECIP_SHIFT)
}

/// How long an occupant runs before a wakeup may preempt it: the wakee's
/// own slice, at most SLICE_NS >> shift, so a microsecond sleeper does not
/// wait out a whole fixed window.
#[inline(always)]
pub fn wake_protect(shift: u32, slice: u64) -> u64 {
    slice.min(SLICE_NS >> shift)
}

/// The arithmetic of a wakeup preemption: the occupant has run `ran`, past
/// `protect`, and the wakee's key is before the occupant's live virtual
/// time `live`, 0 for no occupant to price. The class gates are the
/// caller's.
#[inline(always)]
pub fn preempts(live: u64, ran: u64, protect: u64, wakee: u64) -> bool {
    live != 0 && ran >= protect && time_before(wakee, live)
}

/// Is an occupant that has run `ran` within one handoff of the end of its
/// mean burst, so that it is about to block? Cross-multiplied while the
/// operands fit, divided beyond.
#[inline(always)]
pub fn handoff_yields(ran: u64, runtime: u64, nvcsw: u64) -> bool {
    let n = switches(nvcsw);
    let limit = ran.wrapping_add(HANDOFF_MAX_NS);
    if (limit | n) >> 32 == 0 {
        return runtime < limit.wrapping_mul(n);
    }
    let burst = burst_ns(runtime, nvcsw);
    burst <= ran || burst - ran < HANDOFF_MAX_NS
}

/// Does the wakeup of a pinned task preempt the occupant? `depth` is how
/// far the wakee's own virtual time is past the continuation floor,
/// negative for a sleeper; its key is that depth from one slice further
/// back, and the margin is its own slice.
#[inline(always)]
pub fn pinned_preempts(frontier: u64, depth: u64, slice: u64, live: u64) -> bool {
    if live == 0 {
        return false;
    }
    let floor = frontier.wrapping_sub(SLICE_NS);
    let key = floor
        .wrapping_sub(SLICE_NS)
        .wrapping_add(clamp_floor(0, depth.wrapping_add(SLICE_NS)));
    time_before(key.wrapping_add(slice), live)
}

/// The handoff hint after a task stops: a quantum that followed a wakeup
/// and blocked within a handoff raises the count, anything else that
/// blocked clears it, a preemption leaves it. The woke bit goes.
#[inline(always)]
pub fn hint_after(hint: u64, runnable: bool, used: u64) -> u64 {
    let mut confidence = (hint >> HINT_CONF_SHIFT) & HINT_CONF_MAX;
    if !runnable {
        confidence = if hint & HINT_WOKE != 0 && used < HANDOFF_MAX_NS {
            (confidence + 1).min(HINT_CONF_MAX)
        } else {
            0
        };
    }
    confidence << HINT_CONF_SHIFT
}

/// Has the CID woken and blocked quickly enough times in a row to bet on
/// co-locating the next wakee?
#[inline(always)]
pub fn hint_serial(hint: u64) -> bool {
    (hint >> HINT_CONF_SHIFT) & HINT_CONF_MAX >= HINT_CONF_MAX
}

/// Is almost nothing runnable: at least three quarters of `online` idle?
#[inline(always)]
pub fn system_serial(idle: u32, online: u32) -> bool {
    idle.wrapping_mul(4) >= online.wrapping_mul(3)
}

/// Does `vtime` move the frontier, by at least a grain?
#[inline(always)]
pub fn frontier_moves(frontier: u64, vtime: u64) -> bool {
    time_before(frontier.wrapping_add(FRONTIER_GRAIN_NS), vtime)
}

/// Is `vtime` an outlier, more than a slice ahead of the frontier, that
/// has to be checked against the service other CIDs see?
#[inline(always)]
pub fn frontier_outlier(frontier: u64, vtime: u64) -> bool {
    time_before(frontier.wrapping_add(SLICE_NS), vtime)
}

/// Is a queue head a whole slice behind the frontier, worth taking across
/// an LLC?
#[inline(always)]
pub fn head_behind(head: u64, frontier: u64) -> bool {
    time_before(head.wrapping_add(SLICE_NS), frontier)
}

/// Does the pool head go before the own queue's: a slice of hysteresis,
/// so that not every CPU takes the shared pool first?
#[inline(always)]
pub fn pool_before(pool_head: u64, own_head: u64) -> bool {
    time_before(pool_head.wrapping_add(SLICE_NS), own_head)
}

/// Has a pool last served at `served` gone unserved for the wall at `now`?
#[inline(always)]
pub fn pool_starved(served: u64, now: u64) -> bool {
    time_before(served.wrapping_add(WAKE_STARVE_WALL_NS), now)
}

/// Is the served stamp half a wall old at `now`, so that an empty pool
/// refreshes it?
#[inline(always)]
pub fn pool_refresh_due(served: u64, now: u64) -> bool {
    time_before(served.wrapping_add(WAKE_STARVE_REFRESH_NS), now)
}

/// What is left of a grant of `grant` after `ran`: 0 once past it.
#[inline(always)]
pub fn grant_left(ran: u64, grant: u64) -> u64 {
    grant.saturating_sub(ran)
}

/// What an LLC's idle count changes by when ops.update_idle() moves a
/// CID's flag from `was` to `idle`: 1, minus 1 as its two's complement for
/// an atomic add, or 0 for a report that changes nothing.
#[inline(always)]
pub fn census_delta(was: bool, idle: bool) -> u64 {
    if was == idle {
        0
    } else if idle {
        1
    } else {
        u64::MAX
    }
}

/// The serial test on an LLC's idle count: None when the count is not one
/// an LLC of `size` CIDs can have, a broken count to report rather than
/// read as an idle LLC.
#[inline(always)]
pub fn census_serial(count: u64, size: u32) -> Option<bool> {
    if count > u64::from(size) {
        return None;
    }
    Some(system_serial(count as u32, size))
}
