// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.

//! Group scheduling, cpu.weight: what the cgroup of a task does to the
//! weight it is queued at.
//!
//! fair.c with a single runqueue, commit 85570f10a4c6 ("sched/eevdf: Move to
//! a single runqueue"): a cgroup's task on a CID joins the CID's own pack
//! beside every other task, at an effective weight that stands for its place
//! in the hierarchy. A cgroup keeps one queue per CID, the load of fair.c's
//! cfs_rq of the group there: `LOAD` is the weight of the group's members on
//! the CID, its tasks at their nice weights and its child groups at their
//! shares, and `CONTRIB` is what the group adds to its parent's load there,
//! its shares while it has any member and nothing otherwise. A task's
//! effective weight is its nice weight scaled by shares / load at every level
//! up to the CID's own, __calc_prop_weight() in enqueue_hierarchy().
//!
//! The shares of a queue are update_cfs_group() in fair.c's default "concur"
//! mode, see accounting::group_shares(): the group's weight times the CIDs'
//! worth of tasks it runs, distributed over its queues by their averaged
//! loads. The averages advance only from the tick of the CID that owns the
//! queue, under a trylock, and what they add to the per-cgroup sums moves at
//! most once a millisecond. A group that stops running on a CID would hold
//! that CID's last contribution for good, so a sweep walks the queues that
//! still count, a few per millisecond, and decays the quiet ones: what
//! update_blocked_averages() does for an idle CPU.
//!
//! The same walk keeps the CPU count of every cgroup's cpuset, which bounds
//! that scaling, tg_cpus(): the kernel reports no cpuset change, so it is
//! read again once a second, see cpus_refresh().
//!
//! cpu.idle is the same machinery at a different weight: a group that has it
//! set carries WEIGHT_IDLEPRIO in place of its cpu.weight.
//!
//! One arena block per cgroup holds a header and the queues, then a bitmap of
//! the CIDs whose queue still adds to the sums. A BPF program cannot walk the
//! cgroup tree, so every block has a slot in a registry for the sweep. A
//! cgroup at the root has no queues: its tasks weigh their nice weights. One
//! nested deeper than MAX_DEPTH shares its ancestor's queues at that depth.
//!
//! Counterpart in scx_eevdf: cgroup.bpf.[ch].

use scx_rustsched::arena::{Array, Struct, Words};
use scx_rustsched::cgroup::{Cgroup, CgroupArgs};
use scx_rustsched::pool;
use scx_rustsched::sched::Cid;
use scx_rustsched::task::Task;
use scx_rustsched::time;
use scx_rustsched::var::Var;

use crate::{
    WEIGHT_IDLEPRIO,
    accounting::{
        GROUP_WEIGHT_SHIFT, UTIL_HALF_LIFE_NS, cgroup_load_weight, group_shares, prop_weight,
        round_weight,
    },
    ravg::{FRAC_BITS, Ravg, accumulate, read},
    taskctx::{self, Context},
};

/// Levels of the hierarchy that get queues of their own, GRP_MAX_DEPTH.
pub const MAX_DEPTH: u32 = 8;

// CONFIG words the loader fills from kernel BTF: cgroup.level,
// cgroup.self.flags, the value of CSS_ONLINE,
// scx_cgroup_init_args.weight, where in a cgroup the cpu controller's css
// pointer is, and task_group.idle, 0 when the kernel has none.

scx_rustsched::arena_struct! {
    /// A cgroup's block: these header fields, then its queues, one per CID,
    /// then the bitmap of the CIDs whose queue still adds to the sums. The
    /// sums every CID moves are on a line of their own, away from what the
    /// hot paths read.
    pub struct Group {
        weight: u64,
        pages: u64,
        idle: bool,
        slot: u64,
        next_free: Option<Group>,
        /// The cgroup's id, the CPUs of its effective cpuset and when they
        /// were last read, see cpus_refresh().
        cgid: u64,
        nr_cpus: u64,
        nr_cpus_at: u64,
        /// cpu.max's, see bandwidth.rs.
        limit_words: Words<24>,
        _unused: Words<24>,
        load_avg: u64,
        nr_avg: u64,
        _tail: Words<6>,
    }
}

scx_rustsched::arena_struct! {
    /// A cgroup's queue on one CID: what joins and leaves move and the
    /// hierarchy weight reads, on the first line; the averages on the
    /// second; the bookkeeping of the sums on the third.
    pub struct Queue {
        load: u64,
        contrib: u64,
        shares: u64,
        nr: u64,
        parent: Option<Queue>,
        group: Option<Group>,
        cid: u64,
        avg_lock: u64,
        load_avg: Ravg,
        nr_avg: Ravg,
        load_avg_contrib: u64,
        nr_avg_contrib: u64,
        shares_at: u64,
        /// cpu.max's, see bandwidth.rs: what the CID holds of the group's
        /// bandwidth, and the tasks waiting on it on this CID, the backlog
        /// on a line of its own.
        held_words: Words<2>,
        nr_parked: u64,
        _tail: Words<2>,
        backlog_words: Words<{ scx_rustsched::dsq::Backlog::WORDS as usize }>,
        _pad: u64,
    }
}

const _: () = assert!(<Group as Struct>::SIZE == 512 && <Queue as Struct>::SIZE == 256);

scx_rustsched::arena_struct! {
    /// A word of a group's live bitmap.
    struct LiveWord {
        bits: u64,
    }
}

scx_rustsched::arena_struct! {
    /// A registry slot: a block the sweep walks.
    struct Slot {
        group: Option<Group>,
    }
}

impl Group {
    /// The group's queues, one per CID.
    #[inline(always)]
    pub fn queues(&self) -> Array<Queue> {
        Array::from_address(self.address() + <Group as Struct>::SIZE, cids())
    }

    /// The group's queue on `cid`, or None for a number that is not a CID.
    #[inline(always)]
    pub fn queue(&self, cid: Cid) -> Option<Queue> {
        self.queues().get(u64::from(cid.index()))
    }

    #[inline(always)]
    fn live(&self) -> Array<LiveWord> {
        Array::from_address(self.queues().end(), cids().div_ceil(64))
    }

    /// The bytes of a block for `cids` CIDs.
    #[inline(always)]
    fn bytes(cids: u64) -> u64 {
        <Group as Struct>::SIZE
            + Array::<Queue>::bytes(cids)
            + Array::<LiveWord>::bytes(cids.div_ceil(64))
    }
}

/// Registry slots, GRP_MAX_CGROUPS.
const MAX_CGROUPS: u64 = 16384;
/// How long the per-cgroup sums are left alone after an update, and how
/// often the sweep runs, over how many queues at most.
const SUM_NS: u64 = 1_000_000;
const SWEEP_NS: u64 = 1_000_000;
const SWEEP_BUDGET: u32 = 64;
/// How long the CPU count of a cgroup's cpuset is trusted.
const CPUS_NS: u64 = 1_000_000_000;
/// Blocks freed per sweep at most.
const FREE_BUDGET: u32 = 8;

/// The fields of CGROUPS: the registry's address and the slots ever used, the
/// sweep's last run, lock and position, the blocks waiting to be freed, the
/// number of CIDs, and how many cgroups are set cpu.idle, which only the
/// cgroup ops write, serialized by the kernel.
#[repr(C)]
struct Globals {
    registry: Var<u64>,
    slots_used: Var<u64>,
    sweep_at: Var<u64>,
    sweep_lock: Var<u64>,
    sweep_pos: Var<u64>,
    free_head: Var<u64>,
    cids: Var<u64>,
    idle_groups: Var<u64>,
}

scx_rustsched::shared! {
    static CGROUPS in ".data.cgroups": Globals = Globals {
        registry: Var::new(0),
        slots_used: Var::new(0),
        sweep_at: Var::new(0),
        sweep_lock: Var::new(0),
        sweep_pos: Var::new(0),
        free_head: Var::new(0),
        cids: Var::new(0),
        idle_groups: Var::new(0),
    };
}

/// Per-cgroup storage: the block whose queues the cgroup's tasks join, its
/// own block when the queues are its own, and its depth.
#[repr(C)]
pub struct CgroupRef {
    group: Var<u64>,
    block: Var<u64>,
    depth: Var<u64>,
}

impl CgroupRef {
    /// The cgroup's own block, None at the root and below MAX_DEPTH.
    #[inline(always)]
    pub fn block(&self) -> Option<Group> {
        Group::try_from_address(self.block.get())
    }
}

scx_rustsched::cgroup_state!(CgroupRef, cgroup_refs);

/// Run `body` over `start..end`, a loop the verifier checks once however
/// long the range, until it returns false.
#[inline(always)]
pub(crate) fn numbers(start: u64, end: u64, mut body: impl FnMut(u64) -> bool) {
    for value in crate::loops::range(start as u32, end as u32) {
        if !body(u64::from(value)) {
            break;
        }
    }
}

#[inline(always)]
pub fn enabled() -> bool {
    !crate::DISABLE_CGROUPS.get() && !crate::NO_CGROUP_OPS.get()
}

#[inline(always)]
pub(crate) fn cids() -> u64 {
    CGROUPS.cids.get()
}

/// Bring what `queue` and each group above it add to their parents in line
/// with their loads and shares, the sums of enqueue_hierarchy() and
/// dequeue_hierarchy().
///
/// Loads change from whichever CID a task joins or leaves a pack from,
/// without a lock, so a contribution is moved by compare and swap to what
/// its load says it should be, the delta goes to the parent, and the group
/// is looked at again before going up: whoever changes a load last leaves
/// the contributions above it matching. A global function, verified once.
#[scx_rustsched::global]
pub fn group_contrib_sync(queue: Queue) -> u64 {
    let mut queue = queue;
    let mut moved = false;
    for _ in 0..4 * MAX_DEPTH {
        let Some(parent) = queue.parent().get() else {
            break;
        };
        let target = if queue.load().get() != 0 {
            queue.shares().get()
        } else {
            0
        };
        let current = queue.contrib().get();
        if current != target {
            if queue.contrib().compare_exchange(current, target) == current {
                parent.load().add(target.wrapping_sub(current));
                moved = true;
            }
            continue;
        }
        if !moved {
            break;
        }
        queue = parent;
        moved = false;
    }
    0
}

/// The effective weight of a member of `queue` that weighs `weight` in it:
/// `weight` scaled by shares / load at every level, __calc_prop_weight().
/// With `joining`, the weight it will have once it has joined, its own
/// weight and those of the groups that join with it counted in. The product
/// is carried in fixed point and rounded once.
#[scx_rustsched::global]
pub fn group_weight(queue: Queue, weight: u64, joining: u64) -> u64 {
    let joining = joining != 0;
    let mut queue = queue;
    let mut add = if joining { weight } else { 0 };
    let mut fixed = weight << GROUP_WEIGHT_SHIFT;
    for _ in 0..MAX_DEPTH {
        let shares = queue.shares().get();
        let load = queue.load().get() + add;
        add = if joining && queue.contrib().get() == 0 {
            shares
        } else {
            0
        };
        fixed = prop_weight(fixed, shares, load);
        let Some(parent) = queue.parent().get() else {
            break;
        };
        queue = parent;
    }
    round_weight(fixed)
}

/// Add `delta` to the load of `queue` and take the change up the hierarchy.
#[inline(always)]
fn load_add(queue: Queue, delta: u64) {
    queue.load().add(delta);
    group_contrib_sync(queue);
}

/// Count a task in or out of `queue` and every group above it on the CID,
/// cfs_rq->h_nr_runnable.
#[inline(always)]
fn nr_add(queue: Queue, delta: u64) {
    let mut queue = queue;
    for _ in 0..MAX_DEPTH {
        queue.nr().add(delta);
        let Some(parent) = queue.parent().get() else {
            break;
        };
        queue = parent;
    }
}

/// What a task weighs in packs: its share of its groups as of when it last
/// joined one, or `nice` outside of any.
#[inline(always)]
pub fn weight(state: &Context, nice: u64) -> u64 {
    let joined = state.joined_weight().get();
    if state.group().get().is_some() && joined != 0 {
        joined
    } else {
        nice
    }
}

/// The weight the task will have in `cid`'s pack once it has joined it: its
/// nice weight, or its share of its group hierarchy on `cid`.
#[inline(always)]
pub fn join_weight(state: &Context, cid: Cid, nice: u64) -> u64 {
    let Some(queue) = state.group().get().and_then(|group| group.queue(cid)) else {
        return nice;
    };
    if state.group_queue().get() == Some(queue) {
        return group_weight(queue, state.group_weight().get(), 0);
    }
    group_weight(queue, nice, 1)
}

/// Make the task a member of its group's load on `cid` at `nice`, as it
/// joins `cid`'s pack, and return the weight it joins the pack at.
#[inline(always)]
pub fn enter(state: &Context, cid: Cid, nice: u64) -> u64 {
    exit(state);
    let Some(queue) = state.group().get().and_then(|group| group.queue(cid)) else {
        return nice;
    };
    state.group_weight().set(nice);
    state.group_queue().set(Some(queue));
    load_add(queue, nice);
    nr_add(queue, 1);
    group_weight(queue, nice, 0)
}

/// Is the task of `state` in an idle cgroup or under one, cfs_rq_is_idle()
/// on the way up enqueue_hierarchy()? A group has the same ancestors on
/// every CID, so the chain of its first queue stands for all.
#[inline(always)]
pub fn in_idle_group(state: &Context) -> bool {
    // Nearly always none is, and the walk is a load per level.
    if CGROUPS.idle_groups.get() == 0 {
        return false;
    }
    let Some(mut queue) = state.group().get().and_then(|group| group.queues().get(0)) else {
        return false;
    };
    for _ in 0..MAX_DEPTH {
        if queue.group().get().is_some_and(|group| group.idle().get()) {
            return true;
        }
        let Some(parent) = queue.parent().get() else {
            break;
        };
        queue = parent;
    }
    false
}

/// Take the task out of its group's load, as it leaves its pack.
#[inline(always)]
pub fn exit(state: &Context) {
    let Some(queue) = state.group_queue().get() else {
        return;
    };
    state.group_queue().set(None);
    load_add(queue, state.group_weight().get().wrapping_neg());
    nr_add(queue, u64::MAX);
}

/// The averages of a group queue, what they add to the per-cgroup sums,
/// and its live bit are updated by the CID that owns the queue and by the
/// sweep. fair.c does both under the runqueue's lock; here the two take the
/// queue's own lock and give way to each other rather than wait.
#[inline(always)]
fn try_lock(queue: Queue) -> bool {
    queue.avg_lock().get() == 0 && queue.avg_lock().compare_exchange(0, 1) == 0
}

#[inline(always)]
fn unlock(queue: Queue) {
    queue.avg_lock().compare_exchange(1, 0);
}

/// Set or clear the bit of `queue`'s CID in its cgroup's live bitmap, by
/// compare and swap: the verifier takes no atomic OR or AND on the arena.
#[inline(always)]
fn live_update(queue: Queue, live: bool) {
    let cid = queue.cid().get();
    let Some(word) = queue
        .group()
        .get()
        .and_then(|group| group.live().get(cid / 64))
    else {
        return;
    };
    let bit = 1_u64 << (cid % 64);
    for _ in 0..8 {
        let old = word.bits().get();
        if (old & bit != 0) == live {
            return;
        }
        let new = if live { old | bit } else { old & !bit };
        if word.bits().compare_exchange(old, new) == old {
            return;
        }
    }
}

/// Bring what `queue` adds to its cgroup's sums up to date and recompute
/// the group's shares on its CID, see accounting::group_shares(). From the
/// tick of the CID that owns the queue.
#[scx_rustsched::global]
pub fn group_update_shares(queue: Queue, now: u64) -> u64 {
    let Some(group) = queue.group().get() else {
        return 0;
    };
    let load = queue.load().get();
    if !try_lock(queue) {
        return 0;
    }
    let half = UTIL_HALF_LIFE_NS;
    let mut load_avg = queue.load_avg().get();
    accumulate(&mut load_avg, load, now, half);
    queue.load_avg().set(load_avg);
    let mut nr_avg = queue.nr_avg().get();
    accumulate(&mut nr_avg, queue.nr().get(), now, half);
    queue.nr_avg().set(nr_avg);
    let averaged = read(&load_avg, now, half) >> FRAC_BITS;
    let tasks = read(&nr_avg, now, half);
    if now.wrapping_sub(queue.shares_at().get()) < SUM_NS {
        unlock(queue);
        return 0;
    }
    queue.shares_at().set(now);
    let contrib = queue.load_avg_contrib().get();
    if averaged.abs_diff(contrib) > contrib / 64 {
        group.load_avg().add(averaged.wrapping_sub(contrib));
        queue.load_avg_contrib().set(averaged);
    }
    let contrib = queue.nr_avg_contrib().get();
    if tasks.abs_diff(contrib) > contrib / 64 {
        group.nr_avg().add(tasks.wrapping_sub(contrib));
        queue.nr_avg_contrib().set(tasks);
    }
    if queue.load_avg_contrib().get() != 0 || queue.nr_avg_contrib().get() != 0 {
        live_update(queue, true);
    }
    unlock(queue);
    let shares = group_shares(
        group.weight().get(),
        group.nr_avg().get() >> FRAC_BITS,
        group.nr_cpus().get(),
        load,
        averaged,
        group.load_avg().get(),
        queue.load_avg_contrib().get(),
    );
    if shares != queue.shares().get() {
        queue.shares().set(shares);
        group_contrib_sync(queue);
    }

    0
}

/// update_cfs_group() for every level `queue` is in, from its CID's tick.
#[scx_rustsched::global]
pub fn group_tick(queue: Queue, now: u64) -> u64 {
    let mut queue = queue;
    for _ in 0..MAX_DEPTH {
        group_update_shares(queue, now);
        let Some(parent) = queue.parent().get() else {
            break;
        };
        queue = parent;
    }
    0
}

/// The tick of the CID running the task of `state`, whose nice weight is
/// `nice`: bring its groups' shares up to date and return the weight its
/// groups now give it, when that is not what it joined its pack at. A nice
/// level changed since it joined is moved into its group's load first.
#[inline(always)]
pub fn tick(state: &Context, nice: u64, now: u64) -> Option<u64> {
    let queue = state.group_queue().get()?;
    let old = state.group_weight().get();
    if nice != old {
        load_add(queue, nice.wrapping_sub(old));
        state.group_weight().set(nice);
    }
    group_tick(queue, now);
    let weight = group_weight(queue, nice, 0);
    if weight != state.joined_weight().get() {
        Some(weight)
    } else {
        None
    }
}

/// The weight the task of `state` would join its pack at now, as a member
/// of its group queue on its CID, or None outside of one.
#[inline(always)]
pub fn member_weight(state: &Context) -> Option<u64> {
    let queue = state.group_queue().get()?;
    Some(group_weight(queue, state.group_weight().get(), 0))
}

/// Decay the averages of `queue`, which has no members left on its CID, and
/// what they add to its cgroup's sums: update_blocked_averages() for a group
/// whose cfs_rq has gone quiet. Without this a CID the group has left would
/// hold its last contribution for good, inflating the group's load and
/// shrinking its shares everywhere else.
#[scx_rustsched::global]
pub fn group_decay(queue: Queue, now: u64) -> u64 {
    if queue.load().get() != 0 || !try_lock(queue) {
        return 0;
    }
    // A task may have joined between the look and the lock.
    if queue.load().get() != 0 {
        unlock(queue);
        return 0;
    }
    let Some(group) = queue.group().get() else {
        unlock(queue);
        return 0;
    };
    crate::bandwidth::give_back(queue);
    let half = UTIL_HALF_LIFE_NS;
    let mut load_avg = queue.load_avg().get();
    accumulate(&mut load_avg, 0, now, half);
    queue.load_avg().set(load_avg);
    let mut nr_avg = queue.nr_avg().get();
    accumulate(&mut nr_avg, 0, now, half);
    queue.nr_avg().set(nr_avg);
    let averaged = read(&load_avg, now, half) >> FRAC_BITS;
    let mut tasks = read(&nr_avg, now, half);
    // A 64th of a task decays to nothing more that matters.
    if tasks < (1 << FRAC_BITS) / 64 {
        tasks = 0;
    }
    let contrib = queue.load_avg_contrib().get();
    if averaged != contrib {
        group.load_avg().add(averaged.wrapping_sub(contrib));
        queue.load_avg_contrib().set(averaged);
    }
    let contrib = queue.nr_avg_contrib().get();
    if tasks != contrib {
        group.nr_avg().add(tasks.wrapping_sub(contrib));
        queue.nr_avg_contrib().set(tasks);
    }
    if averaged == 0 && tasks == 0 {
        live_update(queue, false);
    }
    unlock(queue);

    0
}

/// Read how many CPUs the effective cpuset of `cgroup` has, tg_cpus(), which
/// bounds the scaling of the group's weight in accounting::group_shares(). A
/// kernel without the kfunc leaves the CIDs of the scheduler to bound it.
#[inline(always)]
fn cpus_set(group: Group, cgroup: &Cgroup, now: u64) {
    let cids = cids();
    let count = cgroup
        .nr_cpus()
        .map_or(cids, |count| u64::from(count).max(1).min(cids));
    if count != group.nr_cpus().get() {
        group.nr_cpus().set(count);
    }
    group.nr_cpus_at().set(now);
}

/// Read the CPU count of the cpuset of `group`'s cgroup again if it is
/// older than CPUS_NS. Nothing tells the scheduler when a cpuset changes or
/// a CPU goes away, so the sweep polls on its way past the cgroup. A cgroup
/// on its way out is not found by its id any more and keeps its count.
#[inline(always)]
fn cpus_refresh(group: Group, now: u64) {
    let id = group.cgid().get();
    if !Cgroup::has_nr_cpus() || id == 0 || now.wrapping_sub(group.nr_cpus_at().get()) < CPUS_NS {
        return;
    }
    if let Some(cgroup) = Cgroup::from_id(id) {
        cpus_set(group, &cgroup, now);
    }
}

/// The registry, once ops.init() has allocated it.
#[inline(always)]
fn registry() -> Option<Array<Slot>> {
    let address = CGROUPS.registry.get();
    if address == 0 {
        None
    } else {
        Some(Array::from_address(address, MAX_CGROUPS))
    }
}

/// One step of the sweep from `position`, the cgroup slot in the high 32
/// bits and the CID in the low: decay the next live queue at or after it in
/// that cgroup, or move to the next cgroup. Returns the position to go on
/// from, or u64::MAX past the last slot.
#[scx_rustsched::global]
pub fn group_sweep_step(position: u64, now: u64) -> u64 {
    let slot = position >> 32;
    let cid = position & u64::from(u32::MAX);
    let Some(entry) = registry().and_then(|registry| registry.get(slot)) else {
        return u64::MAX;
    };
    if slot >= CGROUPS.slots_used.get() {
        return u64::MAX;
    }
    let index = cid / 64;
    let Some((group, word)) = entry
        .group()
        .get()
        .and_then(|group| Some((group, group.live().get(index)?)))
    else {
        return (slot + 1) << 32;
    };
    if cid == 0 {
        cpus_refresh(group, now);
    }
    let live = word.bits().get() & (u64::MAX << (cid % 64));
    if live == 0 {
        return slot << 32 | (index + 1) * 64;
    }
    let cid = index * 64 + u64::from(live.trailing_zeros());
    let Some(queue) = group.queues().get(cid) else {
        return (slot + 1) << 32;
    };
    group_decay(queue, now);
    slot << 32 | (cid + 1)
}

/// Pop one block from the deferred-free list. The sweep lock serializes the
/// consumers; cgroup exits may still push concurrently.
#[inline(always)]
fn free_pop() -> Option<Group> {
    for _ in 0..8 {
        let head = Group::try_from_address(CGROUPS.free_head.get())?;
        let next = head.next_free().get().map_or(0, |next| next.address());
        if CGROUPS.free_head.compare_exchange(head.address(), next) == head.address() {
            return Some(head);
        }
    }
    None
}

/// Hand a block to the next sweep to free, when one that may still be
/// looking at it holds the sweep lock. A push that cannot complete leaks
/// the block, which is safe.
#[inline(always)]
fn free_defer(group: Group) {
    for _ in 0..8 {
        let old = CGROUPS.free_head.get();
        group.next_free().set(Group::try_from_address(old));
        if CGROUPS.free_head.compare_exchange(old, group.address()) == old {
            return;
        }
    }
}

#[inline(always)]
fn free_block(group: Group) {
    pool::free_pages(group.address(), group.pages().get() as u32);
}

#[inline(always)]
pub(crate) fn sweep_trylock() -> bool {
    CGROUPS.sweep_lock.get() == 0 && CGROUPS.sweep_lock.compare_exchange(0, 1) == 0
}

#[inline(always)]
pub(crate) fn sweep_unlock() {
    CGROUPS.sweep_lock.set(0);
}

/// Walk the queues that still add to their cgroup's sums, a few every
/// SWEEP_NS, and decay the quiet ones; then free the blocks of removed
/// cgroups that nothing can be looking at any more. One CID at a time does
/// it, from its tick, where fair.c's idle balancer updates the blocked
/// averages of idle CPUs.
#[scx_rustsched::global]
pub fn group_sweep(now: u64) -> u64 {
    let at = CGROUPS.sweep_at.get();
    if CGROUPS.registry.get() == 0
        || (CGROUPS.slots_used.get() == 0 && CGROUPS.free_head.get() == 0)
        || now.wrapping_sub(at) < SWEEP_NS
        || CGROUPS.sweep_at.compare_exchange(at, now) != at
        || !sweep_trylock()
    {
        return 0;
    }
    let mut position = CGROUPS.sweep_pos.get();
    let mut wrapped = false;
    for _ in 0..SWEEP_BUDGET {
        position = group_sweep_step(position, now);
        if position == u64::MAX {
            if wrapped {
                break;
            }
            wrapped = true;
            position = 0;
        }
    }
    CGROUPS
        .sweep_pos
        .set(if position == u64::MAX { 0 } else { position });
    for _ in 0..FREE_BUDGET {
        let Some(group) = free_pop() else {
            break;
        };
        free_block(group);
    }
    sweep_unlock();

    0
}

/// From ops.init(): the registry, when cgroups are scheduled as groups.
pub fn init(count: u32) -> i32 {
    CGROUPS.cids.set(u64::from(count));
    if !enabled() {
        return 0;
    }
    let pages = Array::<Slot>::bytes(MAX_CGROUPS).div_ceil(4096) as u32;
    let registry = pool::alloc_pages(pages);
    if registry == 0 {
        return -12;
    }
    CGROUPS.registry.set(registry);

    0
}

/// The block whose queues the tasks of the cgroup `task` is in join, None
/// for the root cgroup. From ops.enable(), the first op
/// scx_bpf_task_cgroup() can be asked in.
#[inline(always)]
pub fn task_group(task: &Task) -> Option<Group> {
    if !enabled() {
        return None;
    }
    let cgroup = task.cgroup()?;
    let reference = cgroup.state::<CgroupRef>()?;
    Group::try_from_address(reference.group.get())
}

/// A cgroup the cpu controller puts under this scheduler, one that existed
/// when it was loaded or one just created, parents before their children:
/// give it a queue on every CID, each adding to its parent's queue there.
#[inline(always)]
pub fn cpuctl_init(cgroup: &Cgroup, args: &CgroupArgs) -> i32 {
    let Some(reference) = cgroup.state_or_create::<CgroupRef>() else {
        return -12;
    };
    reference.group.set(0);
    reference.block.set(0);
    reference.depth.set(0);
    let level = cgroup.level();
    if !enabled() || level == 0 {
        return 0;
    }
    let mut parent_group = None;
    let mut parent_depth = 0;
    if let Some(parent) = cgroup.ancestor(level - 1)
        && let Some(parent_reference) = parent.state::<CgroupRef>()
    {
        parent_group = Group::try_from_address(parent_reference.group.get());
        parent_depth = parent_reference.depth.get();
    }
    let depth = if parent_group.is_some() {
        parent_depth + 1
    } else {
        1
    };
    if depth > u64::from(MAX_DEPTH) {
        reference
            .group
            .set(parent_group.map_or(0, |parent| parent.address()));
        reference.depth.set(parent_depth);
        return 0;
    }
    let cids = cids();
    if cids == 0 {
        return 0;
    }
    let pages = Group::bytes(cids).div_ceil(4096);
    let Some(group) = Group::try_from_address(pool::alloc_pages(pages as u32)) else {
        return -12;
    };
    let idle = cgroup.is_idle();
    let weight = if idle {
        WEIGHT_IDLEPRIO
    } else {
        cgroup_load_weight(u64::from(args.weight()))
    };
    group.weight().set(weight);
    if idle {
        group.idle().set(true);
        CGROUPS.idle_groups.set(CGROUPS.idle_groups.get() + 1);
    }
    group.pages().set(pages);
    group.cgid().set(cgroup.id());
    cpus_set(group, cgroup, time::now());
    group.slot().set(MAX_CGROUPS);
    crate::bandwidth::init_group(group, args);
    // Fresh arena pages read as zero: only what is not zero is stored.
    let queues = group.queues();
    numbers(0, cids, |cid| {
        let Some(queue) = queues.get(cid) else {
            return false;
        };
        queue.group().set(Some(group));
        queue.cid().set(cid);
        queue.shares().set(weight);
        if let Some(parent) = parent_group {
            queue.parent().set(parent.queues().get(cid));
        }
        true
    });
    reference.group.set(group.address());
    reference.block.set(group.address());
    reference.depth.set(depth);
    // A slot for the sweep; a cgroup without one is simply not swept.
    if let Some(registry) = registry() {
        numbers(0, MAX_CGROUPS, |slot| {
            let Some(entry) = registry.get(slot) else {
                return false;
            };
            if entry.group().get().is_some() {
                return true;
            }
            group.slot().set(slot);
            entry.group().set(Some(group));
            if slot >= CGROUPS.slots_used.get() {
                CGROUPS.slots_used.set(slot + 1);
            }
            false
        });
    }

    0
}

/// The cgroup goes away, or the scheduler does.
///
/// A removed cgroup has no tasks left and nothing adds to its queues, so its
/// block goes back. The scheduler going away exits every cgroup before its
/// tasks leave, and they still take their weights out of their groups' loads
/// on the way out. The cgroup is still online then, and its block goes with
/// the arena.
#[inline(always)]
pub fn cpuctl_exit(cgroup: &Cgroup) {
    let Some(reference) = cgroup.state::<CgroupRef>() else {
        return;
    };
    let Some(group) = reference.block() else {
        return;
    };
    reference.group.set(0);
    reference.block.set(0);
    if group.idle().get() {
        group.idle().set(false);
        CGROUPS.idle_groups.set(CGROUPS.idle_groups.get() - 1);
    }
    crate::bandwidth::exit_group(group);
    // Out of the registry: no sweep that starts from now on finds it.
    if let Some(entry) = registry().and_then(|registry| registry.get(group.slot().get())) {
        entry.group().set(None);
    }
    // A task left waiting in its backlog still holds the block; only
    // the scheduler going away leaves one, and the arena goes with it.
    if cgroup.is_online() || crate::bandwidth::has_parked(group) {
        return;
    }
    // A sweep already walking may still hold the block: free it under
    // the sweep lock, or leave it to the sweep.
    if sweep_trylock() {
        free_block(group);
        sweep_unlock();
    } else {
        free_defer(group);
    }
}

/// Somebody wrote cpu.weight: the shares of the cgroup's queues follow the
/// next time the tick recomputes them.
#[inline(always)]
pub fn cpuctl_set_weight(cgroup: &Cgroup, weight: u32) {
    let Some(reference) = cgroup.state::<CgroupRef>() else {
        return;
    };
    if let Some(group) = reference.block() {
        group.weight().set(cgroup_load_weight(u64::from(weight)));
    }
}

/// Somebody wrote cpu.idle, sched_group_set_idle(): an idle cgroup has the
/// weight of a SCHED_IDLE task, and one that stops being idle goes back to
/// the default weight, not to the cpu.weight it had, which the kernel does
/// not let be written while the cgroup is idle. The shares follow the next
/// time the tick recomputes them.
#[inline(always)]
pub fn cpuctl_set_idle(cgroup: &Cgroup, idle: bool) {
    let Some(reference) = cgroup.state::<CgroupRef>() else {
        return;
    };
    if let Some(group) = reference.block() {
        group.weight().set(if idle {
            WEIGHT_IDLEPRIO
        } else {
            cgroup_load_weight(100)
        });
        if group.idle().get() != idle {
            group.idle().set(idle);
            let count = CGROUPS.idle_groups.get();
            CGROUPS
                .idle_groups
                .set(if idle { count + 1 } else { count - 1 });
        }
    }
}

/// The task is now in another cgroup. It is off its runqueue here: it left
/// its pack and its group's load in ops.quiescent(), and joins the new
/// group's the next time it is placed. A debt it owes its old pack is
/// forgiven.
#[inline(always)]
pub fn cpuctl_move(task: &Task, to: &Cgroup) {
    let Some(state) = taskctx::lookup(task) else {
        return;
    };
    let group = match to.state::<CgroupRef>() {
        Some(reference) if enabled() => Group::try_from_address(reference.group.get()),
        _ => None,
    };
    state.group().set(group);
    state.set_delay([0; 4]);
}
