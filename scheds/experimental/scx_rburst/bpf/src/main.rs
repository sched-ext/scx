// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.

//! scx_rburst: one queue per CPU, in which the task that runs next is
//! the one with the earliest virtual deadline among those that are owed
//! service, as in EEVDF.
//!
//! Each CID has a virtual clock, which advances as its tasks run, by the
//! time they run over the weight of all the tasks runnable there at the
//! time, see advance(): it is the virtual time a task would be at had it
//! received exactly its share.
//! A task's own virtual time advances by the time it ran over its weight.
//! The difference is its lag. A task behind the clock is owed service and
//! is eligible to run, and one ahead of it has had more than its share.
//!
//! A task is queued with a deadline past its virtual time by what it asks
//! for, see request(). A CID runs the eligible task with the earliest
//! deadline, so a task that used little of its share runs soon, and none
//! can run ahead of its share for long. The task whose slice ends is part
//! of that pick, and keeps the CPU while it wins it, see keep_running().
//!
//! The queues are scx_rustsched's, in the arena: they keep the tasks in
//! deadline order and find the first eligible one, which a DSQ cannot. A
//! queued task is in the scheduler's custody, with its queue node in its
//! task slot, until a CPU moves it to its local DSQ or the kernel takes it
//! back in ops.dequeue().
//!
//! Tasks are placed as the kernel's fair class places them, in outline. A
//! waking task looks for an idle CPU in the LLC of its last one, where its
//! cache is: a core that is idle as a whole first, then any idle CPU, and
//! its last CPU first either way. A forked task has no cache yet, and with
//! nothing idle in the LLC it starts on an idle CPU of the node or of the
//! machine.
//!
//! Two simple load balancers move tasks after that, both toward idle CPUs.
//! A pull balancer in ops.dispatch(): a CPU whose queue is empty steals
//! from the closest queue that has a task, in its LLC, then its node, then
//! the whole machine, see steal(). And an active balancer at the tick, for
//! a task that never sleeps and so is never placed again: its CPU moves it
//! to a whole idle core while its SMT sibling is busy, or to an idle CPU
//! of a better rank, in the LLC, see balance_target(). So wakeups stay
//! local, and load crosses LLCs and nodes at fork and when a CPU runs out
//! of work. Neither balancer compares loads, so nothing moves a task
//! between two CPUs that both stay busy.
//!
//! A task that moves keeps its lag: its virtual time is restated in the
//! clock of the CID it moved to. A task that sleeps keeps it too: it wakes
//! as far from the clock as it was when it went to sleep, so sleeping
//! neither earns service nor pays off what the task ran beyond its share.
//!
//! A task's deadline is its virtual time plus what it asks for, which is
//! how long it runs between two sleeps. A task that works for a moment
//! and sleeps again has an early deadline and, when it wakes beside a task
//! that asks for more, takes the CPU from it. That keeps such tasks
//! responsive beside tasks that compute without a pause, at no cost to
//! fairness: nothing is taken off their virtual time, so they get their
//! share and no more.
//!
//! A waking task is also let to borrow virtual time, which does put it
//! ahead of the tasks that stayed runnable, see borrow().
//! --no-vtime-borrowing turns that off.

#![no_std]
#![no_main]

use scx::prelude::*;
// What the framework does not wrap: the kernel's ranking of the CPUs and
// the hint of an LLC's whole idle cores.
use scx::{cid_idle, tiers};
use scx_rustsched as scx;

// The tunables: one for each option of the loader, ../src/main.rs, named
// as the option in upper case, a time in microseconds as _NS.
scx::opts!();

/// The weight of a task at nice 0: virtual time is real time at it.
const NICE_0_WEIGHT: u64 = 1024;

scx::arena_struct! {
    /// What the scheduler keeps per task, in the arena.
    struct TaskCtx {
        /// The task's virtual time, in the clock of its home CID.
        vtime: u64,
        /// The CID whose clock `vtime` is in, and whose load counts the
        /// task while it is runnable.
        home: u64,
        /// The weight the home's load counts the task with, 0 while the
        /// task is not runnable.
        counted: u64,
        /// The task's lag when it stopped being runnable, how far behind
        /// its home's clock it was, negative if ahead: where it is put
        /// back when it is runnable again.
        vlag: u64,
        /// When the task last got a CPU.
        started_at: u64,
        /// What the task has run since it last slept, and the average of
        /// that over its past sleeps: how long it runs at a time.
        burst: u64,
        burst_avg: u64,
        /// The idle CID ops.tick() found the task better off on, plus 1,
        /// for its next enqueue to move it to; 0 for none.
        target: u64,
    }
}

impl scx::slots::TaskSlot for TaskCtx {}

scx::arena_struct! {
    /// What the scheduler keeps per CID, in the arena.
    struct CidCtx {
        /// The CID's virtual clock.
        clock: u64,
        /// When the clock was last brought up to date, and whether a task
        /// has been running here since, see advance().
        clock_at: u64,
        busy: bool,
        /// The weights of the runnable tasks whose home this is.
        load: u64,
        /// The request and the virtual deadline of the task running here:
        /// what a waking task has to beat to take the CPU.
        running_request: u64,
        running_deadline: u64,
        /// From when the task running here may be preempted.
        preempt_after: u64,
        /// The task running here asks for a whole slice and is counted
        /// as such, see long_running().
        long: bool,
    }
}

scx::params! {
    /// Count for the statistics: the loader sets it with --stats. It is a
    /// constant once the scheduler is loaded, so without --stats the
    /// counting is not in the program at all.
    STATS: bool = false;
}

scx::arena_struct! {
    /// What a CPU counts for the statistics, a cache line of its own: only
    /// the CPU a callback runs on writes its counters, so that counting
    /// costs no line another CPU reads. The loader sums them, see
    /// ../src/stats.rs, which names the words in this order.
    struct Counters {
        /// Wakeups sent straight to an idle CPU.
        direct: u64,
        /// Wakeups placed on borrowed virtual time.
        borrowed: u64,
        /// Wakeups queued on another CPU to take it, and searches for
        /// one that found none.
        moved: u64,
        missed: u64,
        /// Preemptions of a running task by a waking one.
        preempts: u64,
        /// Tasks taken from another CPU's queue.
        steals: u64,
        /// Running tasks moved by the tick to a better idle CPU.
        balanced: u64,
        pad: u64,
    }
}

scx::cid_slot!(Counters, COUNTERS in ".data.counters");

/// The counters of the CPU this callback runs on, if it counts.
#[inline(always)]
fn counters() -> Option<Counters> {
    if !STATS.get() {
        return None;
    }
    Cid::current().slot()
}

/// The shortest request a task is given: tasks that run for less at a time
/// are all served alike, and none of them preempts another.
#[inline(always)]
fn min_request() -> u64 {
    SLICE_NS.get() / 8
}

/// What the task asks for at a time: how long it runs between two sleeps,
/// by its average over the past ones and by what it has run since the
/// last, no less than the shortest request and no more than a slice.
///
/// EEVDF gives the task with the earliest deadline the CPU, and a task's
/// deadline is its virtual time plus its request. A task that works for a
/// moment and sleeps again asks for little, so its deadline comes before
/// that of a task that computes without a pause and asks for a whole
/// slice: it runs first, and for no more than its share, since nothing is
/// taken off its virtual time.
#[inline(always)]
fn request(ctx: TaskCtx) -> u64 {
    let burst = ctx.burst().get().max(ctx.burst_avg().get());
    burst.max(min_request()).min(SLICE_NS.get())
}

/// Make `to` the task's home, keeping its lag: its virtual time is as far
/// from the new clock as it was from the old, and its weight moves to the
/// new load.
fn rehome(ctx: TaskCtx, to: Cid) {
    let from = Cid(ctx.home().get() as i32);
    if from == to {
        return;
    }
    let (Some(old), Some(new)) = (from.slot::<CidCtx>(), to.slot::<CidCtx>()) else {
        return;
    };
    let lag = old.clock().get().wrapping_sub(ctx.vtime().get());
    ctx.vtime().set(new.clock().get().wrapping_sub(lag));
    let weight = ctx.counted().get();
    if weight != 0 {
        old.load().fetch_add(weight.wrapping_neg());
        new.load().fetch_add(weight);
    }
    ctx.home().set(to.raw() as u64);
}

/// Does `wider` hold CIDs around `cid` that `scope` does not? An LLC that
/// is its node, or a node that is the machine, would only be searched
/// again.
#[inline(always)]
fn widens(cid: Cid, scope: Scope, wider: Scope) -> bool {
    !idle::scope_same(cid, scope, wider)
}

/// Claim an idle CID of `kind` for `task` in `prev`'s LLC: `prev` itself
/// if it will do, where the task's cache is, then its SMT siblings, then
/// the rest of the LLC.
#[inline(always)]
fn pick_near(task: &Task, prev: Cid, kind: Kind) -> Option<Cid> {
    if let Some(cid) = idle::pick(task, prev, Scope::Core, kind) {
        return Some(cid);
    }
    idle::pick(task, prev, Scope::Llc, kind)
}

/// Does placement follow the kernel's ranking of the CPUs? It ranks them
/// where they differ, SD_ASYM_PACKING, as on a hybrid x86 machine with
/// performance and efficiency cores.
#[inline(always)]
fn packing() -> bool {
    !NO_ASYM_PACKING.get() && tiers::asym_packing()
}

/// Is `cid` an idle CID that `task` may run on, with its core idle as a
/// whole if `whole_core`?
#[inline(always)]
fn fits(task: &Task, cid: Cid, whole_core: bool) -> bool {
    cid.is_idle() && (!whole_core || cid.is_core_idle()) && cid_idle::allowed_by_mask(task, cid)
}

/// pick_near() where the CPUs rank: claim the idle CID of `prev`'s LLC that
/// the kernel prefers most. `prev`, then its core, then the nearest win
/// among equals, since that is where the task's cache is.
///
/// The ordinary pick comes first, a scan of the idle mask by the word, so
/// an LLC with nothing idle costs no more than it does without ranks.
/// Only when that found a CID that is not of the best rank is every CID of
/// the LLC looked at for a better one. A global function, which the
/// verifier checks once: it loops over the LLC.
#[scx::global]
fn pick_ranked(task: &Task, prev: Cid, whole_core: bool) -> OptCid {
    let kind = if whole_core {
        Kind::FullCore
    } else {
        Kind::AnyCpu
    };
    let Some(found) = pick_near(task, prev, kind) else {
        return OptCid::NONE;
    };
    // The lower the tier, the more the kernel prefers the CID.
    let mut best = found;
    let mut rank = found.place_tier();
    for cid in prev.scope(Scope::Llc) {
        if rank == 0 {
            break;
        }
        let tier = cid.place_tier();
        if tier < rank && fits(task, cid, whole_core) {
            best = cid;
            rank = tier;
        }
    }
    // A better CID another CPU claims first leaves the one already held.
    if best != found && best.claim() {
        found.unclaim();
        return OptCid::some(best);
    }
    OptCid::some(found)
}

/// Claim an idle CID of `prev`'s LLC for a waking task. A core whose SMT
/// siblings are all idle comes first, since a task there shares the core
/// with nobody. Only with no such core left in the LLC does the task take
/// any idle CID, and shares a core. Either way `prev` is tried first.
///
/// Where the CPUs rank, the same two searches take the CID the kernel
/// prefers most rather than the nearest: work packs on the fast cores and
/// spills to the others as those fill, asymmetric packing.
///
/// The search for a whole idle core is made only while the LLC's hint
/// says it has one, and a search that finds none clears the hint: a busy
/// machine, which has none, then makes one search per wakeup, not two.
#[inline(always)]
fn pick_idle(task: &Task, prev: Cid) -> Option<Cid> {
    if idle::smt() && prev.has_idle_cores() {
        let whole = if packing() {
            pick_ranked(task, prev, true).get()
        } else {
            pick_near(task, prev, Kind::FullCore)
        };
        if whole.is_some() {
            return whole;
        }
        cid_idle::clear_idle_cores(prev);
    }
    if packing() {
        return pick_ranked(task, prev, false).get();
    }
    pick_near(task, prev, Kind::AnyCpu)
}

/// Claim an idle CID for `task` outside `anchor`'s LLC, the closest there
/// is: in its node, then anywhere. For a task that has no cache to lose,
/// and for a CID that is to come and take a task from `anchor`'s queue,
/// which the steal reaches that far for.
#[inline(always)]
fn pick_beyond(task: &Task, anchor: Cid) -> Option<Cid> {
    if widens(anchor, Scope::Llc, Scope::Node) {
        if let Some(cid) = idle::pick(task, anchor, Scope::Node, Kind::AnyCpu) {
            return Some(cid);
        }
    }
    if widens(anchor, Scope::Node, Scope::Anywhere) {
        return idle::pick(task, anchor, Scope::Anywhere, Kind::AnyCpu);
    }
    None
}

/// Claim an idle CID that is to come and take `task` from `anchor`'s
/// queue: any of the LLC, the one the kernel prefers where the CPUs rank,
/// or the closest outside it. This runs at every enqueue that is not a
/// wakeup, so an LLC with nothing idle is searched once.
#[inline(always)]
fn pick_stealer(task: &Task, anchor: Cid) -> Option<Cid> {
    let near = if packing() {
        // A whole idle core of a lower rank is worth more than a thread
        // beside a busy one of a higher rank, as for a wakeup. The LLC
        // says whether it has one, so a busy LLC is searched once.
        let mut whole = None;
        if idle::smt() && anchor.has_idle_cores() {
            whole = pick_ranked(task, anchor, true).get();
            if whole.is_none() {
                cid_idle::clear_idle_cores(anchor);
            }
        }
        match whole {
            Some(cid) => Some(cid),
            None => pick_ranked(task, anchor, false).get(),
        }
    } else {
        idle::pick(task, anchor, Scope::Llc, Kind::AnyCpu)
    };
    match near {
        Some(cid) => Some(cid),
        None => pick_beyond(task, anchor),
    }
}

/// Take a task for `cid` from another queue of `scope` around it. The
/// queued bits name the queues worth a look, a word of them for 64 CIDs.
#[inline(always)]
fn steal_in(cid: Cid, scope: Scope) -> bool {
    for peer in dsq::queued(cid, scope) {
        if peer != cid && dsq::move_to_local(Edq::Cid(peer), cid) {
            return true;
        }
    }
    false
}

/// The pull balancer, from ops.dispatch() when `cid`'s own queue is empty:
/// take a task for `cid` from another queue, the closest that has one it
/// may run: in its LLC, then in its node, then anywhere.
#[scx::global]
fn steal(cid: Cid) -> bool {
    steal_in(cid, Scope::Llc)
        || (widens(cid, Scope::Llc, Scope::Node) && steal_in(cid, Scope::Node))
        || (widens(cid, Scope::Node, Scope::Anywhere) && steal_in(cid, Scope::Anywhere))
}

// The active balancer, at the tick.
//
// A task that does not sleep is never placed again once it runs: no wakeup
// goes through ops.select_cid() for it, and alone on its CPU it keeps the
// CPU at the end of every slice, out of the reach of a steal. Started
// beside a busy SMT sibling, or on a slow core while the fast ones were
// busy, it would stay there with better CPUs idle.
//
// So the tick of the CPU it runs on looks for a better idle CPU in the
// LLC, ends the slice when it finds one, and the enqueue that follows
// moves the task there, as fair.c's active balance does for SMT and
// asymmetric packing. Only the task's own CPU moves it, and the claim of
// the idle CPU at the enqueue keeps two from going to the same one: no
// handshake between the two CPUs is needed.

/// An idle CID of `src`'s LLC that the running `task` is better off on: a
/// whole idle core while a sibling of `src` is busy, or one of a better
/// packing tier where the CPUs rank, a whole core on SMT, so that a move
/// never lands beside a busy sibling. The best tier there is, the first of
/// it. A global function, which the verifier checks once: it loops over
/// the LLC.
#[scx::global]
fn balance_target(task: &Task, src: Cid) -> OptCid {
    let smt = idle::smt();
    let shared = smt && !src.siblings_idle() && src.has_idle_cores();
    let packing = packing();
    let best = src.llc_place_tier();
    if !shared && !(packing && src.place_tier() > best) {
        return OptCid::NONE;
    }
    // Any whole idle core is better than a shared one, else only a better
    // tier is.
    let mut rank = if shared { u32::MAX } else { src.place_tier() };
    let mut found = OptCid::NONE;
    for cid in src.scope(Scope::Llc) {
        if rank <= best {
            break;
        }
        let tier = if packing { cid.place_tier() } else { best };
        if tier < rank && fits(task, cid, smt) {
            found = OptCid::some(cid);
            rank = tier;
        }
    }
    found
}

// Virtual-time borrowing, which --no-vtime-borrowing turns off.
//
// The idea is that of the Borrowed Virtual Time scheduler of Duda and
// Cheriton, "Borrowed-virtual-time (BVT) scheduling: supporting
// latency-sensitive threads in a general-purpose scheduler", SOSP '99,
// https://dl.acm.org/doi/10.1145/319151.319169, applied at wakeup only.
//
// A task that used up its share before it slept wakes at the clock or
// ahead of it, and waits for the tasks that stayed runnable, although it
// would run for a moment and sleep again. With the credit a waking task
// is placed at least that far behind the clock instead, which makes it
// eligible with a deadline ahead of theirs, and it preempts the task that
// is running. What the task then runs is charged as ever.
//
// Nothing limits what a task borrows over many wakeups.
//
// A waking task is also credited part of the run it interrupts, see
// advance_wakeup(), which gives tasks that wake often more than their
// weight's share beside tasks that never sleep, at most twice.
//
// One more rule comes with it. A waking task that found nothing idle is
// queued where it can take the CPU: on a CPU whose running task asks for
// more than it does, which is what the preemption test of ops.enqueue()
// wants. Left on its last CPU it often finds a task like itself there,
// and waits.
//
// This does take from the tasks that never sleep, which the short request
// of a task that sleeps does not: --no-vtime-borrowing leaves them their
// share.

/// How many CPUs run a task that asks for a whole slice, one that does not
/// sleep. The search for a CPU to take has something to find only when
/// one does, and reads this first: a load of tasks that all sleep then
/// pays one read for it, and not a read of every CPU's state.
///
/// Only a CPU that runs such a task writes it, when the task starts and
/// when it stops, which is once a slice.
static NR_LONG: Var<u64> = Var::new(0);

/// A task asking for `request` starts running on the CID of `here`.
#[inline(always)]
fn long_running(here: CidCtx, request: u64) {
    if !NO_VTIME_BORROWING.get() && request >= SLICE_NS.get() && !here.long().get() {
        here.long().set(true);
        NR_LONG.fetch_add(1);
    }
}

/// The task running on the CID of `here` stops.
#[inline(always)]
fn long_stopping(here: CidCtx) {
    if here.long().get() {
        here.long().set(false);
        NR_LONG.fetch_add(u64::MAX);
    }
}

/// Where a waking task goes in its CID's virtual time, given where its
/// lag puts it and the CID's clock: at least a credit behind the clock. A
/// task whose own lag carries it that far borrows nothing.
#[inline(always)]
fn borrow(task: &Task, clock: u64, vtime: u64) -> u64 {
    if NO_VTIME_BORROWING.get() {
        return vtime;
    }
    let borrowed = clock.wrapping_sub(task.scale_inverse(VTIME_BORROWING_NS.get()));
    if time::before(borrowed, vtime) {
        borrowed
    } else {
        vtime
    }
}

/// Would a task asking for `request` take `cid` from what runs there:
/// does that task ask for more, is it past the time it is left alone for,
/// and may `task` run there?
#[inline(always)]
fn wins(task: &Task, cid: Cid, request: u64, now: u64, restricted: bool) -> bool {
    let Some(there) = cid.slot::<CidCtx>() else {
        return false;
    };
    there.running_request().get() > request
        && !time::before(now, there.preempt_after().get())
        && (!restricted || cid_idle::allowed_by_mask(task, cid))
}

/// The CID a waking task is queued on when no CPU was idle: `prev` if the
/// task can take it, where its cache is, or the first CID of `prev`'s LLC
/// that it can take, or `prev` after all.
///
/// The search begins at a different CID each time, by the clock, so that
/// tasks waking together do not all go for the same CPU. It reads the
/// state of every CID of the LLC at worst, so it is made only while some
/// CPU runs a task that does not sleep.
#[scx::global]
fn preempt_target(task: &Task, prev: Cid) -> Cid {
    if NO_VTIME_BORROWING.get() || task.pinned() {
        return prev;
    }
    let Some(ctx) = task.slot::<TaskCtx>() else {
        return prev;
    };
    let request = request(ctx);
    let now = time::now();
    let restricted = task.nr_cpus_allowed() < Cid::count();
    if wins(task, prev, request, now, restricted) || NR_LONG.get() == 0 {
        return prev;
    }
    let (base, count) = cid_idle::scope_cids(prev, Scope::Llc);
    let start = (now >> 10) as u32;
    for step in scx::loops::range(0, count) {
        let offset = start.wrapping_add(step).checked_rem(count).unwrap_or(0);
        let cid = Cid((base + offset) as i32);
        if wins(task, cid, request, now, restricted) {
            if let Some(counters) = counters() {
                counters.moved().update(|count| count + 1);
            }
            return cid;
        }
    }
    if let Some(counters) = counters() {
        counters.missed().update(|count| count + 1);
    }
    prev
}

/// Bring the clock of the CID of `here` up to `now`, and return it. While
/// a task runs there the clock advances by the time over the weight of
/// every runnable task there, the running one among them.
///
/// This is done before every change of the load, as fair.c's update_curr()
/// is before an entity is enqueued or dequeued, so that each stretch of
/// time counts at the load it ran with. Charged only when the running task
/// stopped, the time a nice 0 task ran alone was divided by the weight of
/// a nice -20 task that had just woken, at every one of its wakeups, and
/// the clock all but stopped.
#[inline(always)]
fn advance(here: CidCtx, now: u64) -> u64 {
    advance_by(here, now, 0)
}

/// advance(), with the time since the last update counted at the load
/// and `extra` more weight.
#[inline(always)]
fn advance_by(here: CidCtx, now: u64, extra: u64) -> u64 {
    let last = here.clock_at().get();
    if time::before(now, last) {
        return here.clock().get();
    }
    here.clock_at().set(now);
    if !here.busy().get() {
        return here.clock().get();
    }
    let load = here.load().get().wrapping_add(extra).max(1);
    let delta = (now.wrapping_sub(last) * NICE_0_WEIGHT)
        .checked_div(load)
        .unwrap_or(0);
    here.clock().update(|clock| clock.wrapping_add(delta))
}

/// Bring the clock of the CID of `here` up to `now` for `task`, which wakes
/// there, and return it.
///
/// A task that wakes on a busy CPU is credited part of the run it
/// interrupts, which is the other half of virtual-time borrowing (see
/// borrow()): the time since the clock was last brought up to date counts
/// as if the waking task had been runnable for it too. The clock then
/// advances less than the running task's virtual time does, and a task
/// that never sleeps falls behind the tasks that wake beside it. That is
/// what keeps a frame pipeline running beside CPU hogs, whose threads
/// barely sleep and would otherwise get no more than their weight's share.
///
/// The waking task counts for no more weight than is runnable there
/// already, so the clock advances at least half as fast as it should and
/// every task keeps at least half its share. Credited in full, a nice -20
/// task waking every 200 us beside a nice 19 one all but stopped the
/// clock, and the nice 19 task starved.
#[inline(always)]
fn advance_wakeup(here: CidCtx, task: &Task, now: u64) -> u64 {
    if NO_VTIME_BORROWING.get() {
        return advance(here, now);
    }
    let extra = task.weight().min(here.load().get());
    advance_by(here, now, extra)
}

/// Charge the task of `ctx` for what it ran since it last got the CPU, or
/// since the last charge: its virtual time and its burst advance as they
/// do when it stops, and its home's clock is brought up to date.
#[inline(always)]
fn charge(task: &Task, ctx: TaskCtx, now: u64) -> Option<CidCtx> {
    let ran = now.wrapping_sub(ctx.started_at().get());
    ctx.started_at().set(now);
    ctx.vtime()
        .update(|vtime| vtime.wrapping_add(task.scale_inverse(ran)));
    ctx.burst().update(|burst| burst.saturating_add(ran));
    let home = Cid(ctx.home().get() as i32).slot::<CidCtx>()?;
    advance(home, now);
    Some(home)
}

/// Does `prev`, whose slice has ended on `cid` and which is still runnable,
/// keep the CPU for another slice?
///
/// The kernel calls ops.dispatch() before it puts `prev` back through
/// ops.enqueue(), so `prev` is in no queue when the pick is made. Taking
/// the head of the queue then hands the CPU over in strict rotation, and
/// a nice 19 task got as much of it as a nice 0 one. As pick_eevdf() does
/// with curr, `prev` is charged for what it ran and keeps the CPU while
/// it is eligible and nothing eligible queued has an earlier deadline. A
/// task the tick is moving, see balance_target(), goes through its
/// enqueue instead.
#[inline(always)]
fn keep_running(prev: &Task, cid: Cid) -> bool {
    if !prev.queued() {
        return false;
    }
    let Some(ctx) = prev.slot::<TaskCtx>() else {
        return false;
    };
    if ctx.target().get() != 0 {
        return false;
    }
    let Some(home) = charge(prev, ctx, time::now()) else {
        return false;
    };
    let clock = home.clock().get();
    let vtime = ctx.vtime().get();
    if !NO_ELIGIBILITY.get() && time::before(clock, vtime) {
        return false;
    }
    let request = request(ctx);
    let deadline = vtime.wrapping_add(prev.scale_inverse(request));
    let reference = (!NO_ELIGIBILITY.get()).then_some(clock);
    // A tie is kept: giving the CPU up costs a switch.
    let keep = match dsq::peek(Edq::Cid(cid), reference).deadline {
        Some(head) => !time::before(head, deadline),
        None => true,
    };
    if keep {
        // What a waking task has to beat from now on, see ops.enqueue().
        home.running_request().set(request);
        home.running_deadline().set(deadline);
    }
    keep
}

#[scx::scheduler(
    name = "rburst",
    flags = ENQ_LAST | ENQ_EXITING | ENQ_MIGRATION_DISABLED | ALLOW_QUEUED_WAKEUP,
    task_slot = TaskCtx,
    cid_slot = CidCtx
)]
impl Deadline {
    fn init() -> Result<(), Error> {
        // The CPUs' ranks, as the loader read them from the kernel.
        Error::check(tiers::init(Cid::count()))?;
        Error::check(scx::cid_table::init_slots::<Counters>())
    }

    fn select_cid(task: &Task, prev: Cid, flags: WakeFlags) -> Cid {
        let mut pick = pick_idle(task, prev);
        // A task that has never run has no cache to stay near: with
        // nothing idle in the LLC it starts wherever something is, which
        // spreads the load before it has to be moved.
        if pick.is_none() && flags.contains(WakeFlags::FORK) {
            pick = pick_beyond(task, prev);
        }
        match pick {
            Some(cid) => {
                dsq::insert(task, Dsq::Local, SLICE_NS.get(), EnqFlags::NONE);
                if let Some(counters) = counters() {
                    counters.direct().update(|count| count + 1);
                }
                cid
            }
            // Nothing idle: the task is queued, on `prev` unless it
            // borrows virtual time and can take another CPU.
            None => preempt_target(task, prev),
        }
    }

    fn enqueue(task: &Task, flags: EnqFlags) {
        let ctx = task.slot::<TaskCtx>();
        // A proxy-execution donor that has just blocked on a mutex goes
        // back on its own CID, as fair.c leaves it on its runqueue, with
        // what is left of its slice: it is in the middle of a request.
        // None of the moves below apply to it. Only proxy execution moves
        // a donor, to the CID of the mutex owner, where it arrives here
        // again and is queued the same way.
        let blocked = flags.blocked();
        let slice = if blocked && task.slice() != 0 {
            task.slice()
        } else {
            SLICE_NS.get()
        };
        // A task whose slice ops.tick() ended to move it: it goes to the
        // CID found then if that is still idle, and the claim keeps
        // another CPU from sending a task there too. A task that slept in
        // between is placed by its wakeup instead.
        if let Some(ctx) = ctx {
            let target = ctx.target().get();
            if target != 0 {
                ctx.target().set(0);
                let dst = Cid(target as i32 - 1);
                if !flags.contains(EnqFlags::WAKEUP)
                    && !blocked
                    && dst.is_idle()
                    && cid_idle::allowed_by_mask(task, dst)
                    && dst.claim()
                {
                    dsq::insert(task, Dsq::LocalOn(dst), SLICE_NS.get(), flags);
                    dst.kick(KickFlags::IDLE);
                    if let Some(counters) = counters() {
                        counters.balanced().update(|count| count + 1);
                    }
                    return;
                }
            }
        }
        // With ENQ_LAST the kernel hands over the last task of a CPU that
        // found nothing else to run, instead of keeping it running. The
        // task keeps its CPU: on a queue, the first CPU to run out of work
        // would take it, and a task alone on its CPU would move at every
        // slice. The CPU has made its pick by now and may be going idle,
        // so it is told to look again.
        if flags.last() {
            dsq::insert(task, Dsq::Local, slice, flags);
            return task.cid().kick(KickFlags::IDLE);
        }
        let cid = task.cid();
        let Some(ctx) = ctx else {
            return dsq::insert(task, Dsq::Global, SLICE_NS.get(), flags);
        };
        let Some(here) = cid.slot::<CidCtx>() else {
            return dsq::insert(task, Dsq::Global, SLICE_NS.get(), flags);
        };
        // A wakeup the kernel queued to the task's CPU did not go through
        // ops.select_cid(). Give the task the same chance of an idle CID
        // here, and of running there at once.
        if !flags.cid_selected() && !task.running() && !blocked {
            if let Some(idle) = pick_idle(task, cid) {
                dsq::insert(task, Dsq::LocalOn(idle), SLICE_NS.get(), flags);
                idle.kick(KickFlags::IDLE);
                if let Some(counters) = counters() {
                    counters.direct().update(|count| count + 1);
                }
                return;
            }
        }
        rehome(ctx, cid);
        // The lag bound: a task is at most this far behind the clock,
        // however long it slept, and at most this far ahead of it. It is
        // less virtual time for a heavier task, as a slice is.
        let bound = task.scale_inverse(LAG_BOUND_NS.get());
        let clock = advance(here, time::now());
        let (floor, ceiling) = (clock.wrapping_sub(bound), clock.wrapping_add(bound));
        let vtime = ctx.vtime().update(|vtime| {
            if time::before(vtime, floor) {
                floor
            } else if time::before(ceiling, vtime) {
                ceiling
            } else {
                vtime
            }
        });
        // A waking task may borrow virtual time, which places it further
        // behind the clock than its lag does, see borrow().
        let vtime = if flags.contains(EnqFlags::WAKEUP) {
            let placed = borrow(task, clock, vtime);
            if placed != vtime {
                ctx.vtime().set(placed);
                if let Some(counters) = counters() {
                    counters.borrowed().update(|count| count + 1);
                }
            }
            placed
        } else {
            vtime
        };
        // The deadline is where the task's virtual time is after what it
        // asks for, see request(). A donor goes on with the request it was
        // in, so its deadline is where it was.
        let request = if blocked && task.slice() != 0 {
            task.slice()
        } else {
            request(ctx)
        };
        let deadline = vtime.wrapping_add(task.scale_inverse(request));
        dsq::insert_deadline(task, Edq::Cid(cid), slice, vtime, deadline, flags);
        // Wakeup preemption. The task running here was the eligible one
        // with the earliest deadline when it was picked, and keeps the CPU
        // for its slice. A task that wakes eligible, if eligibility is
        // asked for, asking for less than the running one and with an
        // earlier deadline, takes the CPU now:
        // the running task goes back in the queue, charged for what it
        // ran. Two tasks that ask for the same do not preempt each other,
        // which keeps a load of tasks that all sleep from switching at
        // every wakeup.
        //
        // A CPU is also left alone for a while after a task starts running
        // on it, and after it is preempted. A task that takes the CPU gets
        // to do some work before the next one takes it, however many wake
        // up in a row, and the one waking waits for that long at most.
        if !NO_PREEMPT.get()
            && flags.contains(EnqFlags::WAKEUP)
            && request < here.running_request().get()
            && (NO_ELIGIBILITY.get() || !time::before(clock, vtime))
            && time::before(deadline, here.running_deadline().get())
        {
            let now = time::now();
            if !time::before(now, here.preempt_after().get()) {
                here.preempt_after()
                    .set(now.wrapping_add(MIN_GRANULARITY_NS.get()));
                if let Some(counters) = counters() {
                    counters.preempts().update(|count| count + 1);
                }
                return cid.kick(KickFlags::PREEMPT);
            }
        }
        // An idle CPU can take it from here. Not for a wakeup: the idle
        // search of ops.select_cid(), or the one above for a wakeup that
        // skipped it, has just found nothing idle, and searching again
        // mostly finds a CPU that has gone idle since and moves the task
        // there, which cost schbench 1.1% of its throughput. A task put
        // back at the end of its slice or after a preemption had no search,
        // and a CPU left idle in the meantime would sleep through it: that
        // is what the kick is for, as nothing balances otherwise. A donor
        // cannot be stolen, see Task::is_blocked().
        if !flags.contains(EnqFlags::WAKEUP) && !blocked {
            if let Some(idle) = pick_stealer(task, cid) {
                idle.kick(KickFlags::IDLE);
            }
        }
    }

    fn dispatch(cid: Cid, prev: Option<&Task>) {
        if let Some(prev) = prev
            && keep_running(prev, cid)
        {
            prev.set_slice(SLICE_NS.get());
            return;
        }
        // The eligible task with the earliest deadline, or the one with
        // the earliest deadline of all if eligibility is not asked for.
        let moved = if !NO_ELIGIBILITY.get() {
            let clock = cid.slot::<CidCtx>().map_or(0, |here| here.clock().get());
            dsq::move_to_local_eligible(Edq::Cid(cid), cid, clock)
        } else {
            dsq::move_to_local(Edq::Cid(cid), cid)
        };
        if !moved && steal(cid) && STATS.get() {
            // This callback runs on `cid`: the counters are its own.
            if let Some(counters) = cid.slot::<Counters>() {
                counters.steals().update(|count| count + 1);
            }
        }
    }

    fn tick(task: &Task) {
        // Under load nothing is idle, and one look at the idle summary
        // says so.
        if cid_idle::idle_empty() {
            return;
        }
        let Some(ctx) = task.slot::<TaskCtx>() else {
            return;
        };
        // Only a task that does not sleep is moved: one that does is
        // placed again at its next wakeup, and chasing it would cost its
        // cache for nothing. A donor running a mutex owner stays, see
        // Task::is_blocked().
        if request(ctx) < SLICE_NS.get() || task.pinned() || task.is_blocked() {
            return;
        }
        if let Some(dst) = balance_target(task, task.cid()).get() {
            ctx.target().set(dst.raw() as u64 + 1);
            task.set_slice(0);
        }
    }

    fn runnable(task: &Task, flags: EnqFlags) {
        let Some(ctx) = task.slot::<TaskCtx>() else {
            return;
        };
        let Some(home) = task.cid().slot::<CidCtx>() else {
            return;
        };
        // The time run here so far counts at the load without this task,
        // or, for a wakeup, with it, see advance_wakeup().
        let now = time::now();
        let clock = if flags.contains(EnqFlags::WAKEUP) {
            advance_wakeup(home, task, now)
        } else {
            advance(home, now)
        };
        if !NO_VLAG.get() {
            // The task comes back with the lag it left with, against the
            // clock of the CID it comes back on: what the clock did in
            // the meantime is neither owed to the task nor forgiven.
            ctx.vtime().set(clock.wrapping_sub(ctx.vlag().get()));
            ctx.home().set(task.cid().raw() as u64);
        } else {
            rehome(ctx, task.cid());
        }
        ctx.counted().set(task.weight());
        home.load().fetch_add(task.weight());
    }

    fn running(task: &Task) {
        let Some(ctx) = task.slot::<TaskCtx>() else {
            return;
        };
        // The CID the task runs on is not always the one it was queued
        // on: another may have taken it.
        rehome(ctx, task.cid());
        let now = time::now();
        ctx.started_at().set(now);
        // What a waking task has to beat to take the CPU, see
        // ops.enqueue().
        if let Some(here) = task.cid().slot::<CidCtx>() {
            // The clock runs from here on, see advance().
            advance(here, now);
            here.busy().set(true);
            let request = request(ctx);
            here.preempt_after()
                .set(now.wrapping_add(MIN_GRANULARITY_NS.get()));
            here.running_request().set(request);
            here.running_deadline()
                .set(ctx.vtime().get().wrapping_add(task.scale_inverse(request)));
            long_running(here, request);
        }
    }

    fn stopping(task: &Task, _runnable: bool) {
        let Some(ctx) = task.slot::<TaskCtx>() else {
            return;
        };
        if let Some(home) = charge(task, ctx, time::now()) {
            home.busy().set(false);
            long_stopping(home);
        }
    }

    fn quiescent(task: &Task, flags: DeqFlags) {
        let Some(ctx) = task.slot::<TaskCtx>() else {
            return;
        };
        // The task sleeps: what it ran since the last sleep goes into its
        // average, a quarter of it at a time, and a new burst begins.
        if flags.contains(DeqFlags::SLEEP) {
            let burst = ctx.burst().get().min(SLICE_NS.get());
            ctx.burst_avg().update(|average| (average * 3 + burst) / 4);
            ctx.burst().set(0);
        }
        let Some(home) = Cid(ctx.home().get() as i32).slot::<CidCtx>() else {
            return;
        };
        // The time run here so far counts at the load with this task.
        let clock = advance(home, time::now());
        ctx.vlag().set(clock.wrapping_sub(ctx.vtime().get()));
        let weight = ctx.counted().get();
        if weight != 0 {
            home.load().fetch_add(weight.wrapping_neg());
            ctx.counted().set(0);
        }
    }

    fn set_weight(task: &Task, _weight: u32) {
        // A runnable task whose weight changes, nice or setpriority() on a
        // task that never sleeps for one: the load follows it at once, and
        // the task keeps its lag in real time, as fair.c's reweight_entity()
        // keeps it. Counted with its old weight while its virtual time ran
        // at the new one, a task reniced to 19 beside a nice 0 one stayed
        // ahead of a clock that moved too slowly, and starved.
        let Some(ctx) = task.slot::<TaskCtx>() else {
            return;
        };
        let (old, new) = (ctx.counted().get(), task.weight());
        if old == 0 || new == 0 || old == new {
            return;
        }
        let Some(home) = Cid(ctx.home().get() as i32).slot::<CidCtx>() else {
            return;
        };
        let clock = advance(home, time::now());
        home.load().fetch_add(new.wrapping_sub(old));
        ctx.counted().set(new);
        // The lag is signed, and BPF divides only unsigned: scale its
        // magnitude. The lag bound keeps it far from overflowing.
        let lag = clock.wrapping_sub(ctx.vtime().get());
        let ahead = (lag as i64) < 0;
        let size = if ahead { lag.wrapping_neg() } else { lag };
        let size = size.wrapping_mul(old) / new;
        let lag = if ahead { size.wrapping_neg() } else { size };
        ctx.vtime().set(clock.wrapping_sub(lag));
    }

    fn dump_cid(_dump: &DumpCtx, cid: Cid, _idle: bool) {
        if let Some(here) = cid.slot::<CidCtx>() {
            scx::dump!(
                "rburst clock=%llu load=%llu running_request=%llu",
                here.clock().get(),
                here.load().get(),
                here.running_request().get()
            );
        }
    }

    fn dump_task(_dump: &DumpCtx, task: &Task) {
        if let Some(ctx) = task.slot::<TaskCtx>() {
            scx::dump!(
                "rburst vtime=%llu home=%llu counted=%llu request=%llu",
                ctx.vtime().get(),
                ctx.home().get(),
                ctx.counted().get(),
                request(ctx)
            );
        }
    }

    fn enable(task: &Task) {
        let Some(ctx) = task.slot::<TaskCtx>() else {
            return;
        };
        // A new task starts on the clock, owed nothing and owing nothing,
        // and asking for a whole slice until it has shown that it sleeps.
        ctx.burst_avg().set(SLICE_NS.get());
        ctx.vlag().set(0);
        ctx.home().set(task.cid().raw() as u64);
        if let Some(here) = task.cid().slot::<CidCtx>() {
            ctx.vtime().set(here.clock().get());
        }
    }
}
