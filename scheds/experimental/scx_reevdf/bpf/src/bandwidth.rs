// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.

//! cpu.max: the bandwidth the cpu controller gives a cgroup, `quota` of
//! every `period`, plus what it carried over, up to `burst`. A group is held
//! to the limits of every group above it as well as its own.
//!
//! Each limited cgroup has a pool refilled once a period. A CID takes a slice
//! of it at a time rather than charging every switch, and gives back what it
//! did not use when its queue for that group goes quiet. A group that runs
//! out throttles, and its tasks may not run:
//!
//! ```text
//! charge         every level, from the charge -> pool empty -> throttled
//! enqueue        no runtime on its CID? -> park: the task leaves its pack
//!                and its group's load and waits in the cgroup's backlog,
//!                in the order it was put there
//! period ends    refill -> unpark from the next dispatch, a few tasks at
//!                a time, and from a timer for when every CPU is asleep
//! ```
//!
//! A CID runs a group's tasks only while it holds runtime, as a cfs_rq runs
//! only while its runtime_remaining is positive, see admit().
//!
//! The backlog is a queue of its own because the pick descends the CID's
//! tree by deadline and cannot step over a task that may not run. Only the
//! cgroups that carry a limit have a slot, so that a CID looking for tasks
//! to let go reads a handful of blocks, and nothing here costs more than a
//! load until somebody writes a cpu.max.
//!
//! Counterpart in scx_eevdf: cgroup.bpf.[ch].

use scx_rustsched::arena::{Struct, Words};
use scx_rustsched::cgroup::{Cgroup, CgroupArgs};
use scx_rustsched::dsq::{self, Backlog, Edq};
use scx_rustsched::sched::Cid;
use scx_rustsched::sched::EnqFlags;
use scx_rustsched::sched::KickFlags;
use scx_rustsched::task::Task;
use scx_rustsched::time;
use scx_rustsched::var::{Var, VarArray};

use crate::{
    cgroup::{Group, MAX_DEPTH, Queue, cids, numbers, sweep_trylock, sweep_unlock},
    pack,
    taskctx::Context,
    timer::{Timer, TimerMap},
};

/// cpu.max is off: by --disable-cpu-max, with the cgroups, or on a kernel
/// without the cgroup callbacks.
#[inline(always)]
fn off() -> bool {
    crate::DISABLE_CPU_MAX.get() || crate::DISABLE_CGROUPS.get() || crate::NO_CGROUP_OPS.get()
}

// CONFIG words: scx_cgroup_init_args.bw_period_us, bw_quota_us and
// bw_burst_us, 0 on a kernel whose init arguments have none.

scx_rustsched::arena_struct! {
    /// A cgroup's cpu.max, in its block, see cgroup.rs.
    struct Limit {
        quota: u64,
        period: u64,
        burst: u64,
        period_start: u64,
        pool: u64,
        throttled: u64,
        throttled_at: u64,
        throttled_ns: u64,
        nr_throttled: u64,
        /// Bumped when cpu.max changes, see bw_charge().
        generation: u64,
        slot: u64,
        nr_parked: u64,
        _unused: [u64; 4],
        /// The backlog EDQ, on a line of its own.
        backlog: Words<{ Backlog::WORDS as usize }>,
    }
}

/// The pool is taken from and given back to by compare and swap, and
/// replaced outright when cpu.max is written, see set(). A swap must not
/// succeed against a replaced pool that happens to hold the amount it read,
/// so the word carries the low bits of the generation that wrote it above
/// the amount: a replaced pool differs even where the amounts are equal. 48
/// bits of nanoseconds are 78 hours of runtime in one period, and an amount
/// beyond that is held to it.
const POOL_BITS: u32 = 48;
const POOL_MAX: u64 = (1 << POOL_BITS) - 1;

#[inline(always)]
fn pool_ns(word: u64) -> u64 {
    word & POOL_MAX
}

/// `word` with its amount replaced by `ns`.
#[inline(always)]
fn pool_set_ns(word: u64, ns: u64) -> u64 {
    (word & !POOL_MAX) | ns.min(POOL_MAX)
}

/// A pool of `ns` written under generation `generation`.
#[inline(always)]
fn pool_new(generation: u64, ns: u64) -> u64 {
    generation << POOL_BITS | ns.min(POOL_MAX)
}

/// Is `word` the pool that generation `generation` wrote? set() moves the
/// generation and then replaces the pool, and in between the pool is still
/// the old limit's: nothing may be taken from it or given back to it as the
/// new one's.
#[inline(always)]
fn pool_is_generation(word: u64, generation: u64) -> bool {
    word >> POOL_BITS == generation & (u64::MAX >> POOL_BITS)
}

/// How often bw_assign() tries: it starts over when another CID moved the pool
/// first, and while set() has moved the generation and not yet written its
/// pool, two stores away unless that op was preempted. A CID that gives up
/// gets nothing, and is throttled until the next refill at worst.
const ASSIGN_TRIES: u64 = 64;

/// A queue's generation while a CID resets it, see sync_generation().
const GENERATION_SYNCING: u64 = u64::MAX;

scx_rustsched::arena_struct! {
    /// What a group queue's CID holds of the group's bandwidth, and the
    /// generation of the cpu.max it took it under.
    struct Held {
        runtime: u64,
        generation: u64,
    }
}

impl Group {
    #[inline(always)]
    fn limit(&self) -> Limit {
        self.limit_words().view()
    }
}

impl Queue {
    #[inline(always)]
    fn held(&self) -> Held {
        self.held_words().view()
    }
}

/// cpu.max "max", RUNTIME_INF.
const QUOTA_INF: u64 = u64::MAX;
/// What a CID takes of a group's pool at a time, and what it keeps once
/// the group is spent: sysctl_sched_cfs_bandwidth_slice, and the
/// millisecond __return_cfs_rq_runtime() leaves behind.
const SLICE_NS: u64 = 5_000_000;
const NSEC_PER_MSEC: u64 = 1_000_000;
const NSEC_PER_USEC: u64 = 1_000;
/// Limited cgroups with a slot, and tasks let go per pass.
const MAX_LIMITED: u64 = 1024;
const UNPARK_BATCH: u32 = 4;
/// How long the timer waits when a group is owed its tasks already.
const TIMER_MIN_NS: u64 = NSEC_PER_MSEC;

/// The fields of BANDWIDTH: how many cgroups carry a limit, how many slots have
/// ever been used, and how many tasks are parked. The cgroup ops write the
/// first two, serialized by the kernel.
#[repr(C)]
struct Globals {
    limited: Var<u64>,
    slots_used: Var<u64>,
    parked: Var<u64>,
    pad: [u64; 5],
}

scx_rustsched::shared! {
    static BANDWIDTH in ".data.bandwidth": Globals = Globals {
        limited: Var::new(0),
        slots_used: Var::new(0),
        parked: Var::new(0),
        pad: [0; 5],
    };
}

scx_rustsched::shared! {
    /// The blocks of the cgroups that carry a limit, by slot.
    static LIMITED_GROUPS in ".data.bwslots": VarArray<{ MAX_LIMITED as usize }> = VarArray::new();
}

/// The block in slot `index` of the limited cgroups, if any.
#[inline(always)]
fn limited_group(index: u64) -> Option<Group> {
    Group::try_from_address(LIMITED_GROUPS.get(index))
}

// The one timer cpu.max needs: a CID with nothing to run never reaches
// ops.dispatch(), so a group whose tasks all wait on a period would wait
// past its end with every CPU asleep. Armed only while something waits.
scx_rustsched::timer_map!(pub bw_timers: BwTimerMap, entries: 1, callback: fire);

/// Is cpu.max enforced, and does any cgroup carry a limit?
#[inline(always)]
pub fn enabled() -> bool {
    !off() && BANDWIDTH.limited.get() != 0
}

/// Are tasks parked anywhere?
#[inline(always)]
pub fn any_parked() -> bool {
    BANDWIDTH.parked.get() != 0
}

#[inline(always)]
fn limited(group: Group) -> bool {
    group.limit().quota().get() != 0
}

/// A cgroup that runs out of bandwidth can be held to it only with a slot,
/// or its backlog could not be found again.
#[inline(always)]
fn enforced(group: Group) -> bool {
    group.limit().slot().get() < MAX_LIMITED
}

/// Does `group`'s backlog hold tasks?
#[inline(always)]
pub fn has_parked(group: Group) -> bool {
    group.limit().nr_parked().get() != 0
}

/// The group has run out for this period. Its tasks keep running until
/// somebody looks.
#[inline(always)]
fn throttle(group: Group, now: u64) {
    if !enforced(group)
        || group.limit().throttled().get() != 0
        || group.limit().throttled().compare_exchange(0, 1) != 0
    {
        return;
    }
    group.limit().throttled_at().set(now);
    group.limit().nr_throttled().add(1);
}

/// The group has bandwidth again, a new period or a wider cpu.max.
#[inline(always)]
fn unthrottle(group: Group, now: u64) {
    if group.limit().throttled().get() == 0 {
        return;
    }
    let at = group.limit().throttled_at().get();
    if now > at {
        group.limit().throttled_ns().add(now - at);
    }
    group.limit().throttled().set(0);
}

/// Start the group's next period if its current one has ended,
/// __refill_cfs_bandwidth_runtime(): its quota back, and what it left
/// unused as far as its burst covers. Whoever moves the start refills.
#[inline(always)]
fn refill(group: Group, now: u64) {
    let generation = group.limit().generation().get();
    let period = group.limit().period().get();
    let start = group.limit().period_start().get();
    if period == 0
        || now.wrapping_sub(start) < period
        || group.limit().period_start().compare_exchange(start, now) != start
    {
        return;
    }
    let quota = group.limit().quota().get();
    let burst = group.limit().burst().get();
    for _ in 0..8 {
        let pool = group.limit().pool().get();
        // The limit moved, or is moving: the quota read above may not
        // be this pool's, and set() fills the new pool itself.
        if group.limit().generation().get() != generation || !pool_is_generation(pool, generation) {
            return;
        }
        let refilled = pool_set_ns(pool, (pool_ns(pool) + quota).min(quota + burst));
        if group.limit().pool().compare_exchange(pool, refilled) == pool {
            break;
        }
    }
    unthrottle(group, now);
}

/// Hand `queue`'s CID, which has run out, `want` of the group's pool, and
/// `ahead` more so that it does not come back for every charge,
/// assign_cfs_rq_runtime(). Returns what there was.
///
/// The limit may move meanwhile. The generation is checked between reading
/// the pool and taking from it, see set(): a CID that finds it moved drops
/// what it held and takes from the new pool, once that pool is there.
///
/// The tries are walked by a loop the verifier checks once, and without a
/// closure, which LLVM can outline into a function whose BTF the kernel
/// refuses. A global function: inlined at every level of bw_charge(), the
/// loop is a nest the verifier may not get through.
#[scx_rustsched::global]
pub fn bw_assign(queue: Queue, group: Group, want: u64, ahead: u64) -> u64 {
    let mut taken = 0;
    for _ in crate::loops::range(0, ASSIGN_TRIES as u32) {
        let pool = group.limit().pool().get();
        let generation = group.limit().generation().get();
        if queue.held().generation().get() != generation {
            sync_generation(queue, group);
            continue;
        }
        // set() is between its two stores: look again.
        if !pool_is_generation(pool, generation) {
            continue;
        }
        let ns = pool_ns(pool);
        if ns == 0 {
            break;
        }
        let take = ns.min(want + ahead);
        if group.limit().pool().compare_exchange(pool, pool - take) == pool {
            taken = take;
            break;
        }
    }

    taken
}

/// Add `delta` to what `queue`'s CID holds of its group's bandwidth and
/// return the result. The owner of the CID charges it and other CIDs admit
/// tasks to it, see admit(), so it moves by compare and swap.
#[inline(always)]
fn runtime_add(queue: Queue, delta: i64) -> i64 {
    for _ in 0..8 {
        let old = queue.held().runtime().get();
        let new = (old as i64).wrapping_add(delta) as u64;
        if queue.held().runtime().compare_exchange(old, new) == old {
            return new as i64;
        }
    }
    queue.held().runtime().get() as i64
}

/// What a CID holds was taken under one cpu.max: tg_set_cfs_bandwidth()
/// resets every cfs_rq when the limit moves, so a new generation drops it.
///
/// Several CIDs can get here for one queue, see admit(). Only the one that
/// takes the generation resets the runtime, and the others wait for it, so
/// that none of them resets what another has already taken from the pool
/// under the new limit.
#[inline(always)]
fn sync_generation(queue: Queue, group: Group) {
    let generation = group.limit().generation().get();
    for _ in 0..8 {
        let old = queue.held().generation().get();
        if old == generation {
            return;
        }
        if old == GENERATION_SYNCING
            || queue
                .held()
                .generation()
                .compare_exchange(old, GENERATION_SYNCING)
                != old
        {
            continue;
        }
        queue.held().runtime().set(0);
        queue.held().generation().set(generation);
        return;
    }
}

/// May `queue`'s CID run its group's tasks? Only with runtime in hand. A
/// CID in debt pays it off from the pool first and takes just enough to be
/// positive, as distribute_cfs_runtime() unthrottles at a refill only the
/// cfs_rqs it can bring back; the next charge takes a slice ahead. Without
/// this the tasks let go at a refill would run on every CID at once, each
/// until its tick found the pool empty, a tick per CID over every period.
///
/// Only an op holding the CID's runqueue, or one handing a task to it,
/// takes from the pool. Without `take`, a remote look reports whether the
/// CID holds runtime or the pool has some.
#[inline(always)]
fn admit(queue: Queue, group: Group, take: bool) -> bool {
    let current = queue.held().generation().get() == group.limit().generation().get();
    let left = if current {
        queue.held().runtime().get() as i64
    } else {
        0
    };
    if left > 0 {
        return true;
    }
    if !take {
        return pool_ns(group.limit().pool().get()) != 0;
    }
    sync_generation(queue, group);
    // Another CID may have admitted a task to this one since the look
    // above.
    let left = queue.held().runtime().get() as i64;
    if left > 0 {
        return true;
    }
    let got = bw_assign(queue, group, left.unsigned_abs() + 1, 0);
    got != 0 && runtime_add(queue, got as i64) > 0
}

/// Charge `delta` of runtime to `queue`'s group and every group above it,
/// account_cfs_rq_runtime() at each level. A level that runs through what
/// its CID holds asks its pool for more, and one whose pool is empty
/// throttles. What a CID holds was taken under one cpu.max: a change of the
/// limit drops it, as tg_set_cfs_bandwidth() resets every cfs_rq.
#[scx_rustsched::global]
pub fn bw_charge(queue: Queue, delta: u64, now: u64) -> u64 {
    let mut queue = queue;
    for _ in 0..MAX_DEPTH {
        if let Some(group) = queue.group().get()
            && limited(group)
        {
            refill(group, now);
            sync_generation(queue, group);
            let mut left = runtime_add(queue, (delta as i64).wrapping_neg());
            if left < 0 {
                let got = bw_assign(queue, group, left.unsigned_abs(), SLICE_NS);
                if got != 0 {
                    left = runtime_add(queue, got as i64);
                }
            }
            if left < 0 {
                throttle(group, now);
            }
        }
        let Some(parent) = queue.parent().get() else {
            break;
        };
        queue = parent;
    }
    0
}

/// The block of the nearest group at or above `queue` that its CID cannot
/// run for, or 0: a group out of bandwidth on a CID takes everything under
/// it along, as a throttled cfs_rq does. With `take`, a CID in debt pays it
/// off, see admit(). A group with no slot is never held, since its backlog
/// could not be found again. Periods turn over here as well as on the
/// charge, so that a group whose tasks all wait, and which charges nothing,
/// is found runnable again.
#[scx_rustsched::global]
pub fn bw_throttled(queue: Queue, now: u64, take: u64) -> u64 {
    let mut queue = queue;
    for _ in 0..MAX_DEPTH {
        if let Some(group) = queue.group().get()
            && limited(group)
            && enforced(group)
        {
            refill(group, now);
            if !admit(queue, group, take != 0) {
                if take != 0 {
                    throttle(group, now);
                }
                return group.address();
            }
        }
        let Some(parent) = queue.parent().get() else {
            break;
        };
        queue = parent;
    }
    0
}

/// Charge `delta`, in its CID's task clock, to the cgroup of `state` for
/// the time it ran on `cid`. The period counts wall time.
#[inline(always)]
pub fn charge(state: &Context, cid: Cid, delta: u64) {
    if !enabled() || delta == 0 {
        return;
    }
    if let Some(queue) = state.group().get().and_then(|group| group.queue(cid)) {
        bw_charge(queue, delta, time::now());
    }
}

/// The block of the nearest group the task of `state` runs under that `cid`
/// cannot run for, or None. With `take`, from an op that holds `cid`'s
/// runqueue or hands it the task, a CID in debt may pay it off.
#[inline(always)]
pub fn throttled(state: &Context, cid: Cid, now: u64, take: bool) -> Option<Group> {
    if !enabled() {
        return None;
    }
    let queue = state.group().get()?.queue(cid)?;
    Group::try_from_address(bw_throttled(queue, now, u64::from(take)))
}

/// Nothing of the group is left on `queue`'s CID: give back what it holds of
/// the group's bandwidth, less the millisecond kept for whoever runs there
/// next, or a group that moves around is held to a fraction of its quota.
/// A slice taken under a limit that has since moved is dropped.
#[inline(always)]
pub fn give_back(queue: Queue) {
    if !enabled() {
        return;
    }
    let Some(group) = queue.group().get() else {
        return;
    };
    let left = queue.held().runtime().get() as i64;
    if !limited(group) || left <= NSEC_PER_MSEC as i64 {
        return;
    }
    if queue.held().generation().get() != group.limit().generation().get() {
        queue.held().runtime().compare_exchange(left as u64, 0);
        return;
    }
    // Other CIDs admit tasks to it: give back only what was there.
    if queue
        .held()
        .runtime()
        .compare_exchange(left as u64, NSEC_PER_MSEC)
        != left as u64
    {
        return;
    }
    // The limit may move while the pool is credited. set() bumps the
    // generation before it replaces the pool, so a credit that checks
    // the generation after reading the pool either sees the bump and
    // drops the slice, or lands before the pool is replaced, or fails its
    // swap on the replaced pool and sees the bump then. The replaced pool
    // fails the swap whatever amount it holds.
    for _ in 0..8 {
        let pool = group.limit().pool().get();
        let generation = group.limit().generation().get();
        if queue.held().generation().get() != generation || !pool_is_generation(pool, generation) {
            return;
        }
        let credited = pool_set_ns(pool, pool_ns(pool) + left as u64 - NSEC_PER_MSEC);
        if group.limit().pool().compare_exchange(pool, credited) == pool {
            return;
        }
    }
}

/// Give `group` a slot among the limited cgroups, or leave it without one
/// when they are all taken: it is accounted, but never throttles.
fn register(group: Group) {
    if group.limit().slot().get() < MAX_LIMITED {
        return;
    }
    numbers(0, MAX_LIMITED, |index| {
        if LIMITED_GROUPS.get(index) != 0
            || LIMITED_GROUPS.compare_exchange(index, 0, group.address()) != 0
        {
            return true;
        }
        group.limit().slot().set(index);
        if index >= BANDWIDTH.slots_used.get() {
            BANDWIDTH.slots_used.set(index + 1);
        }
        false
    });
}

/// Give the slot back. The cgroup ops or the unpark pass do this, so the
/// entry is exchanged rather than written.
fn unregister(group: Group) {
    let index = group.limit().slot().get();
    if index >= MAX_LIMITED {
        return;
    }
    group.limit().slot().set(MAX_LIMITED);
    LIMITED_GROUPS.compare_exchange(index, group.address(), 0);
}

/// Set `group`'s cpu.max, tg_set_bandwidth(): `quota_us` of every
/// `period_us`, carrying up to `burst_us`. The kernel keeps "max" as
/// RUNTIME_INF and refuses a period below a millisecond, so zero stands for
/// no limit. A new or moved limit starts a period of its own, as
/// tg_set_cfs_bandwidth() refills the group, and the period and burst go
/// in before the quota that makes them count.
fn set(group: Group, period_us: u64, quota_us: u64, burst_us: u64) {
    let quota = if quota_us == QUOTA_INF {
        0
    } else {
        quota_us * NSEC_PER_USEC
    };
    let period = (period_us * NSEC_PER_USEC).max(NSEC_PER_MSEC);
    let burst = if quota != 0 {
        burst_us * NSEC_PER_USEC
    } else {
        0
    };
    let now = time::now();
    let was = limited(group);
    if quota != 0 {
        register(group);
    }
    group.limit().period().set(period);
    group.limit().burst().set(burst);
    group.limit().period_start().set(now);
    group.limit().quota().set(quota);
    // Whatever the CIDs hold was taken under the old limit. The
    // generation moves before the pool is replaced: a CID that takes
    // from the pool or gives back to it checks the generation in
    // between, see bw_assign() and give_back(), and that the pool is the
    // one this generation wrote, so nothing crosses from one limit's
    // pool into the other's.
    group.limit().generation().add(1);
    let generation = group.limit().generation().get();
    group.limit().pool().set(pool_new(generation, quota));
    unthrottle(group, now);
    let limited = quota != 0;
    if limited != was {
        let count = BANDWIDTH.limited.get();
        BANDWIDTH
            .limited
            .set(if limited { count + 1 } else { count - 1 });
    }
    // A cgroup no longer limited keeps its slot until its tasks are let
    // go: they wait in a backlog the unpark pass reaches through it.
    if !limited && !has_parked(group) {
        unregister(group);
    }
}

/// From ops.cpuctl_init(): no slot yet, and the cpu.max the cgroup already
/// has, which the init arguments carry and no set_bandwidth reports.
pub fn init_group(group: Group, args: &CgroupArgs) {
    group.limit().slot().set(MAX_LIMITED);
    if !args.has_bandwidth() || off() {
        return;
    }
    let quota_us = args.quota_us();
    if quota_us == QUOTA_INF {
        return;
    }
    set(group, args.period_us(), quota_us, args.burst_us());
}

/// From ops.cpuctl_exit(): the cpu.max goes with the cgroup. Tasks still
/// parked are let go by the dequeue the unloading scheduler gives each of
/// them; a removed cgroup is empty before it gets here.
pub fn exit_group(group: Group) {
    if limited(group) {
        group.limit().quota().set(0);
        BANDWIDTH.limited.set(BANDWIDTH.limited.get() - 1);
    }
    unthrottle(group, time::now());
    unregister(group);
}

/// Somebody wrote cpu.max.
#[inline(always)]
pub fn cpuctl_set_bandwidth(cgroup: &Cgroup, period_us: u64, quota_us: u64, burst_us: u64) {
    if off() {
        return;
    }
    let Some(reference) = cgroup.state::<crate::cgroup::CgroupRef>() else {
        return;
    };
    if let Some(group) = reference.block() {
        set(group, period_us, quota_us, burst_us);
    }
}

/// The task of `state` no longer waits on the cgroup it was parked for:
/// the unpark pass took it out of the backlog, or it left custody from
/// there. Whoever took the node out does this, once.
#[inline(always)]
pub fn unparked(state: &Context) {
    let Some(group) = state.parked_on().get() else {
        return;
    };
    state.parked_on().set(None);
    group.limit().nr_parked().add(u64::MAX);
    BANDWIDTH.parked.fetch_add(u64::MAX);
}

/// The tasks parked for the cgroup of `group`.
#[inline(always)]
fn backlog(group: Group) -> Backlog {
    Backlog::at(group.limit().backlog().address())
}

/// Put `task` aside until the cgroup of `group` has bandwidth again,
/// dequeue_throttled_task(). It leaves its pack and its group's load: a
/// task waiting on a period does not compete for the CID, and a weight left
/// behind would move every other task's reference for as long as the
/// throttle lasts. A debt to its pack is forgiven. A task on its way out is
/// not held to a limit.
///
/// The backlog is in the order tasks were put in it, as fair.c unthrottles
/// cfs_rqs in the order they throttled. A refill lets go only as many tasks
/// as its runtime admits, and one that cannot run on its CID goes to the
/// back, so every task is let go within a bounded number of periods.
/// Vruntimes would not do: tasks from different CIDs' packs do not compare,
/// and the same few would go first while the others waited past the
/// watchdog.
#[inline(always)]
pub fn park(task: &Task, state: &Context, group: Group, now: u64) -> bool {
    if crate::task::exiting(task) {
        return false;
    }
    pack::quiesce(state, crate::lag_request(task), now, false);
    state.set_delay([0; 4]);
    let slice = crate::task_request(task);
    if !backlog(group).park(task, time::now(), slice) {
        return false;
    }
    state.parked_on().set(Some(group));
    group.limit().nr_parked().add(1);
    BANDWIDTH.parked.fetch_add(1);
    // Somebody has to come back for it if every CID goes to sleep.
    arm(now);
    true
}

/// Let one task of `group` run again: out of the backlog and through
/// placement and the queue of the CID the kernel has it on, as a sleeper,
/// which is what it was. Returns whether the backlog had anything.
#[scx_rustsched::global]
pub fn bw_unpark_one(group: Group, now: u64) -> u64 {
    let Some(parked) = backlog(group).pop::<Context>() else {
        return 0;
    };
    let state = parked.slot();
    unparked(&state);
    // The task is held until `parked` is dropped.
    'requeue: {
        if !parked.unpark() {
            break 'requeue;
        }
        let Some(task) = parked.task() else {
            break 'requeue;
        };
        if !crate::task_queued(task) {
            break 'requeue;
        }
        let cid = task.cid();
        if !pack::valid(cid) {
            break 'requeue;
        }
        // A group above the one it waited on can have run out since:
        // ask the whole chain again, or a child would run while an
        // ancestor is throttled.
        let out = throttled(&state, cid, now, true);
        drop(parked);
        if let Some(out) = out {
            park(task, &state, out, now);
            return 1;
        }
        pack::place(
            &state,
            cid,
            crate::lag_request(task),
            crate::task_weight(task),
            now,
            true,
        );
        crate::prepare_request(task, &state);
        let request = crate::task_request(task);
        // A task that cannot be queued goes to cid's local DSQ.
        if dsq::insert_deadline(
            task,
            Edq::Cid(cid),
            request,
            state.vtime().get(),
            state.deadline().get(),
            EnqFlags::NONE,
        ) {
            crate::newidle::note_queued(cid);
            if cid != Cid::current() {
                cid.kick(KickFlags::IDLE);
            }
        }
        return 1;
    }
    1
}

/// Let go of the tasks of every group with bandwidth again, a few per pass,
/// from ops.dispatch(). One CID at a time: the walk reads blocks that a
/// cgroup exit may be freeing, and the sweep lock keeps them alive.
#[scx_rustsched::global]
pub fn bw_unpark(now: u64) -> u64 {
    if !any_parked() || !sweep_trylock() {
        return 0;
    }
    let mut count = 0;
    numbers(0, BANDWIDTH.slots_used.get(), |index| {
        if count >= UNPARK_BATCH {
            return false;
        }
        let Some(group) = limited_group(index) else {
            return true;
        };
        if !has_parked(group) {
            // Nothing waits on a cpu.max that is gone.
            if !limited(group) {
                unregister(group);
            }
            return true;
        }
        refill(group, now);
        if group.limit().throttled().get() != 0 {
            return true;
        }
        // A task let go onto a CID that cannot get runtime goes back and
        // throttles the group: stop there rather than pop it again.
        for _ in 0..UNPARK_BATCH {
            if count >= UNPARK_BATCH
                || !has_parked(group)
                || group.limit().throttled().get() != 0
                || bw_unpark_one(group, now) == 0
            {
                break;
            }
            count += 1;
        }
        true
    });

    sweep_unlock();
    0
}

/// Arm the timer for the first period that ends among the groups with tasks
/// waiting. Timer::start() moves an armed timer, so this can be called
/// from anywhere that parks a task or refills a group.
#[scx_rustsched::global]
pub fn bw_arm(now: u64) -> u64 {
    // The walk reads blocks a cgroup exit may be freeing. Without the
    // sweep lock, arm for the shortest wait and look again then.
    let locked = sweep_trylock();
    let mut next = 0_u64;
    if locked {
        numbers(0, BANDWIDTH.slots_used.get(), |index| {
            let Some(group) = limited_group(index).filter(|&group| has_parked(group)) else {
                return true;
            };
            let due = if group.limit().throttled().get() != 0 {
                group.limit().period_start().get() + group.limit().period().get()
            } else {
                now
            };
            if next == 0 || crate::accounting::time_before(due, next) {
                next = due;
            }
            true
        });
        sweep_unlock();
        if next == 0 {
            return 0;
        }
    }
    let delta = if locked && now < next {
        next - now
    } else {
        TIMER_MIN_NS
    };
    BwTimerMap::start(0, delta.max(TIMER_MIN_NS));

    0
}

#[inline(always)]
fn arm(now: u64) {
    bw_arm(now);
}

/// Tell one idle CID to go through ops.dispatch(), where tasks that may run
/// again are let go. With none idle, every CID dispatches by the end of the
/// slice it runs.
#[inline(always)]
fn kick_idle() {
    numbers(0, cids(), |cid| {
        if Cid(cid as i32).is_idle() {
            Cid(cid as i32).kick(KickFlags::IDLE);
            return false;
        }
        true
    });
}

/// The first period among the groups with tasks waiting has ended: turn
/// over the ones that are due and see that somebody lets their tasks run.
fn fire(_key: u32, timer: &Timer) {
    let now = time::now();
    if !sweep_trylock() {
        timer.start(TIMER_MIN_NS);
        return;
    }
    let mut runnable = false;
    numbers(0, BANDWIDTH.slots_used.get(), |index| {
        let Some(group) = limited_group(index).filter(|&group| has_parked(group)) else {
            return true;
        };
        refill(group, now);
        if group.limit().throttled().get() == 0 {
            runnable = true;
        }
        true
    });
    sweep_unlock();
    if runnable {
        kick_idle();
    }
    arm(now);
}

/// Set up the timer, from ops.init(), unless --disable-cpu-max.
pub fn init() -> i32 {
    if off() {
        return 0;
    }
    BwTimerMap::init(0)
}
