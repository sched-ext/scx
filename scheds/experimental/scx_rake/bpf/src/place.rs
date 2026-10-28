// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Piotr Gorski <lucjan.lucjanov@gmail.com>

//! Where a task goes: ops.select_cid() and ops.enqueue().
//!
//! ops.select_cid() decides a wakeup when it can. In order: a serial
//! handoff to the waker's CID, when the waker is about to block and the
//! LLC is almost idle; the retake of a stage's seat from a stranger; the
//! task's own CID while its core is idle; and any idle CID near it. A task
//! admitted there goes to that CID's local DSQ at once. A wakeup none of
//! these decide stays on its previous CID and ops.enqueue() routes it.
//!
//! ops.enqueue() routes what is left. A kernel thread's wakeup runs on a
//! claimed idle CID or its own. A wakeup that waits longer than one turn
//! of its own, or that finds its CID held by an equally served task, is
//! placed by wake_place(): an idle CID, a preemption of the occupant or a
//! neighbour's, or the LLC's pool and a kick. A continuation stays on its
//! CID's own queue, where the CID finds it first and its LLC can steal it.
//! A task the kernel handed back, and the stranger evicted from a seat, go
//! to the pool, where any CID of the LLC can serve them.
//!
//! An idle claim is the runtime's: the claim keeps other picks off the
//! CID, and the kick wakes it.
//!
//! Counterpart in scx_cake: cake_select_cpu(), cake_enqueue(),
//! cake_enqueue_wake(), cake_wake_place() and the claim helpers.

use scx_rustsched::loops;
use scx_rustsched::prelude::*;

use crate::policy::{self, NEIGHBOUR_PROBE_DEPTH, PREEMPT_PROTECT_SHIFT, PROBE_PROTECT_SHIFT};
use crate::{
    CidCtx, FRONTIER, admit, admit_direct, immed, is_stage, is_starved, is_subhandoff, price,
    reenq, same_task, seat, serve, set_vtime, task_slice, vtime_of,
};

/// Claim an idle CID of `kind` near `anchor`: the anchor and its SMT
/// siblings first, where the task's cache is, then the rest of its LLC.
#[inline(always)]
fn pick_near(task: &Task, anchor: Cid, kind: Kind) -> Option<Cid> {
    if let Some(cid) = idle::pick(task, anchor, Scope::Core, kind) {
        return Some(cid);
    }
    idle::pick(task, anchor, Scope::Llc, kind)
}

/// A whole idle core first, then any idle CID.
#[inline(always)]
fn pick_any(task: &Task, anchor: Cid) -> Option<Cid> {
    if idle::smt()
        && let Some(cid) = pick_near(task, anchor, Kind::FullCore)
    {
        return Some(cid);
    }
    pick_near(task, anchor, Kind::AnyCpu)
}

/// Claim an idle CID for `task` in `anchor`'s LLC, preferring one that is
/// not another task's held seat: a seat is a preference, never a
/// reservation, so a seat is taken when nothing else is idle.
#[scx_rustsched::global]
pub fn claim(task: &Task, anchor: Cid) -> OptCid {
    let pid = task.pid() as u32;
    let Some(first) = pick_any(task, anchor) else {
        return OptCid::NONE;
    };
    if !seat::blocks(first, pid) {
        return OptCid::some(first);
    }
    // The first claim keeps the next pick off the seat.
    let Some(second) = pick_any(task, anchor) else {
        return OptCid::some(first);
    };
    if seat::blocks(second, pid) {
        second.unclaim();
        return OptCid::some(first);
    }
    first.unclaim();
    OptCid::some(second)
}

/// Insert `task` on `cid`'s local DSQ with the slice and key of its
/// admission, and tell `cid` when it was idle.
#[inline(always)]
fn admit_on(task: &Task, cid: Cid, slice: u64, flags: EnqFlags) {
    dsq::insert(task, Dsq::LocalOn(cid), slice, flags);
    if flags.raw() & EnqFlags::PREEMPT.raw() == 0 {
        cid.kick(KickFlags::IDLE);
    }
}

/// A decided wakeup from ops.select_cid(): admitted on `cid` now.
#[inline(always)]
fn place(task: &Task, cid: Cid, flags: EnqFlags) -> Cid {
    dsq::insert(task, Dsq::LocalOn(cid), admit_direct(task), flags);
    cid
}

/// Is almost nothing runnable in `cid`'s LLC: three quarters of its CIDs
/// idle? A co-location bets that nothing beats the waker's CID, which is
/// true only then, and the emptiness of one CID cannot tell.
///
/// The count is the LLC's, kept by ops.update_idle(): a loop that counts
/// idle CIDs here is a counter the verifier tracks exactly, a new state
/// at every CID, and took ops.select_cid() past its limit.
///
/// It counts CIDs that are idle, as scx_cake's census on wide hosts does,
/// not CIDs that are free to claim, as its idle word on narrow ones does:
/// a CID another wakeup just claimed still counts until it runs. A burst
/// of claimed wakeups can then read an LLC as serial for the instant
/// before those CIDs leave idle, and a handoff it allows still queues
/// behind a task that is about to block.
///
/// A count past the LLC's size is broken, not an idle LLC: it is counted
/// for the dump and allows no handoff.
#[inline(always)]
fn llc_serial(cid: Cid) -> bool {
    let (size, _) = cid.llc_span();
    let Some(first) = crate::llc_base(cid).slot::<CidCtx>() else {
        return false;
    };
    match policy::census_serial(first.nr_idle().get(), size) {
        Some(serial) => serial,
        None => {
            crate::CENSUS_BROKEN.add(1);
            false
        }
    }
}

/// Is the task running on `cid` within one handoff of the end of its mean
/// burst? A CID that waits for its task to block reads empty while it
/// runs, so this is what says it will be free soon.
#[inline(always)]
fn handoff_yields(cid: Cid, here: CidCtx) -> bool {
    let Some(curr) = cid.curr() else {
        return false;
    };
    if !curr.queued() || curr.slot_optional::<crate::TaskCtx>().is_none() {
        return false;
    }
    if here.pid().get() != u64::from(curr.pid() as u32) {
        return false;
    }
    let ran = policy::time_delta(time::now(), here.stamp().get());
    policy::handoff_yields(ran, curr.sum_exec_runtime(), curr.nvcsw())
}

/// The serial handoff: the waker woke and blocked quickly three times in a
/// row, the wakeup is not SYNC (SYNC wakes collapse pipe throughput here),
/// the wakee may run on the waker's CID, the LLC is almost idle, nothing
/// waits on the CID and its task is about to block. The wakee queues
/// behind it, without a preemption.
#[inline(always)]
fn serial_handoff(task: &Task, flags: WakeFlags) -> OptCid {
    let waker = Cid::current();
    let Some(here) = waker.slot::<CidCtx>() else {
        return OptCid::NONE;
    };
    let hint = here.hint().get();
    if hint & policy::HINT_WOKE == 0 {
        here.hint().set(hint | policy::HINT_WOKE);
    }
    if policy::hint_serial(hint)
        && !flags.contains(WakeFlags::SYNC)
        && task.allowed_on(waker)
        && llc_serial(waker)
        && !waker.has_queued()
        && dsq::nr_queued(Dsq::LocalOn(waker)) == 0
        && handoff_yields(waker, here)
    {
        return OptCid::some(waker);
    }
    OptCid::NONE
}

/// The seat retake: a stage whose seat on `prev` runs a stranger takes it
/// back at once, behind the stranger with a preemption, and the stranger
/// goes to the pool when it comes back. A task of another class, the idle
/// task, a pinned task and another stage are never evicted.
#[inline(always)]
fn retakes(task: &Task, prev: Cid) -> bool {
    let pid = task.pid() as u32;
    if seat::held(prev) || !seat::owns(prev, pid) || !task.allowed_on(prev) {
        return false;
    }
    let Some(curr) = prev.curr() else {
        return false;
    };
    if !curr.queued()
        || curr.slot_optional::<crate::TaskCtx>().is_none()
        || same_task(&curr, task)
        || curr.pinned()
        || is_stage(&curr)
    {
        return false;
    }
    if let Some(here) = prev.slot::<CidCtx>() {
        here.retake().set(1);
    }
    true
}

/// A wakeup no rule above decided, whose CID runs a task that is served
/// as well as it is, claims an idle CID from here: an insert on it from
/// ops.select_cid() is synchronous, where the same claim from
/// ops.enqueue() takes the deferred path.
#[inline(always)]
fn undecided(task: &Task, prev: Cid) -> Cid {
    if task.kthread() || is_starved(task, true) {
        return prev;
    }
    let Some(curr) = prev.curr() else {
        return prev;
    };
    if same_task(&curr, task) || curr.idle_task() || is_starved(&curr, false) {
        return prev;
    }
    let Some(cid) = claim(task, prev).get() else {
        // ops.enqueue() routes it, to the pool.
        return prev;
    };
    place(task, cid, immed())
}

/// ops.select_cid().
#[inline(always)]
pub fn select_cid(task: &Task, prev: Cid, flags: WakeFlags) -> Cid {
    if let Some(waker) = serial_handoff(task, flags).get() {
        return place(task, waker, EnqFlags::NONE);
    }
    let stage = is_stage(task);
    if stage && retakes(task, prev) {
        return place(task, prev, EnqFlags::PREEMPT);
    }
    // The home: a stage keeps it even on a SYNC wakeup, since its own
    // cache outweighs the waker's line. It has to be free as a whole core.
    let sync = flags.contains(WakeFlags::SYNC);
    if (!sync || stage) && prev.is_core_idle() && !seat::blocks(prev, task.pid() as u32) {
        let declined = (is_starved(task, true) && !is_subhandoff(task)) || !task.allowed_on(prev);
        if !declined && prev.claim() {
            return place(task, prev, immed());
        }
    }
    // A claimed warm CID, near the task's own on a single LLC, near the
    // waker's for a worker on several, where the data it was woken for is.
    let anchor = if crate::multi_pool() && !stage {
        Cid::current()
    } else {
        prev
    };
    if let Some(cid) = claim(task, anchor).get() {
        return place(task, cid, immed());
    }
    undecided(task, prev)
}

/// Bind a wakeup to `cid`'s local DSQ, with the key it was admitted with.
/// `flags` is IMMED for a claimed idle CID, which is kicked, or PREEMPT for
/// an occupant that yields.
#[inline(always)]
fn bind(task: &Task, cid: Cid, slice: u64, key: u64, flags: EnqFlags) {
    set_vtime(task, key);
    admit_on(task, cid, slice, EnqFlags::WAKEUP | flags);
}

/// Does the wakee preempt `curr` on `cid`? The occupant has run past
/// `protect` and its live virtual time is behind the wakee's own, before
/// the wakee's clamp, as scx_cake tests it. A task that waits more than
/// it runs is never the victim, nor a stage on its own seat, which runs
/// more than it waits and whose virtual time is high by nature.
#[inline(always)]
fn preempts(own: u64, curr: &Task, cid: Cid, protect: u64, now: u64) -> bool {
    let price = price(curr, cid, now);
    if !policy::preempts(price.live, price.ran, protect, own) {
        return false;
    }
    !is_starved(curr, false) && !seat::owns(cid, curr.pid() as u32)
}

/// A wakeup that found no idle CID hunts a mid-slice occupant among
/// `cid`'s neighbours: its SMT siblings, then the next CIDs of its LLC, up
/// to NEIGHBOUR_PROBE_DEPTH of them, each with the shorter protection a
/// neighbour gets.
#[scx_rustsched::global]
fn probe_neighbours(task: &Task, cid: Cid, slice: u64, own: u64, now: u64) -> OptCid {
    let protect = policy::wake_protect(PROBE_PROTECT_SHIFT, slice);
    let mut tried = 0;
    for peer in cid.scope(Scope::Core) {
        if peer == cid {
            continue;
        }
        tried += 1;
        if task.allowed_on(peer)
            && let Some(curr) = peer.curr()
            && preempts(own, &curr, peer, protect, now)
        {
            return OptCid::some(peer);
        }
        if tried >= NEIGHBOUR_PROBE_DEPTH {
            return OptCid::NONE;
        }
    }
    let (size, base) = cid.llc_span();
    let offset = cid.index().wrapping_sub(base);
    for step in loops::range(1, size) {
        let mut index = offset + step;
        if index >= size {
            index -= size;
        }
        let peer = Cid((base + index) as i32);
        if peer.same_core(cid) {
            continue;
        }
        tried += 1;
        if task.allowed_on(peer)
            && let Some(curr) = peer.curr()
            && preempts(own, &curr, peer, protect, now)
        {
            return OptCid::some(peer);
        }
        if tried >= NEIGHBOUR_PROBE_DEPTH {
            break;
        }
    }
    OptCid::NONE
}

/// Place a wakeup that ops.select_cid() did not decide: a claimed idle
/// CID, a preemption of `cid`'s occupant `curr` or of a neighbour's, or the
/// pool. Every route owes the CID a decision, since nothing ticks: the
/// occupant loses the CPU or the wakee waits because the occupant
/// deserves it.
#[inline(always)]
fn wake_place(task: &Task, cid: Cid, slice: u64, key: u64, curr: Option<&Task>) {
    if let Some(idle) = claim(task, task.cid()).get() {
        return bind(task, idle, slice, key, immed());
    }
    let now = time::now();
    let own = vtime_of(task);
    let protect = policy::wake_protect(PREEMPT_PROTECT_SHIFT, slice);
    if let Some(curr) = curr
        && preempts(own, curr, cid, protect, now)
    {
        return bind(task, cid, slice, key, EnqFlags::PREEMPT);
    }
    if let Some(peer) = probe_neighbours(task, cid, slice, own, now).get() {
        return bind(task, peer, slice, key, EnqFlags::PREEMPT);
    }
    // Undecided: the pool, which every CID of the LLC sees, then the idle
    // search only the insert makes complete, since a CID that went idle in
    // between found the pool empty.
    serve::pool_insert(task, cid, slice, key, EnqFlags::WAKEUP);
    if let Some(idle) = claim(task, task.cid()).get() {
        return idle.kick(KickFlags::IDLE);
    }
    if crate::multi_pool() {
        serve::offer_remote(task, cid);
    }
}

/// The wake half of ops.enqueue().
#[scx_rustsched::global]
fn enqueue_wake(task: &Task, cid: Cid) -> bool {
    let curr = cid.curr();
    // Waking the task this CID is still switching out, the pipe and futex
    // shape: home is right even behind a queue.
    if let Some(running) = &curr
        && same_task(running, task)
    {
        let slice = admit_direct(task);
        dsq::insert_vtime(task, Edq::Cid(cid), slice, vtime_of(task), EnqFlags::WAKEUP);
        return true;
    }
    let (slice, key) = admit(task);
    wake_place(task, cid, slice, key, curr.as_deref());
    true
}

/// Does a pinned task's wakeup preempt the occupant of its CID? It cannot
/// be stolen, so without this it waits out the occupant's slice. `depth`
/// is its virtual time against the continuation floor.
#[inline(always)]
fn pinned_preempts(cid: Cid, depth: u64, slice: u64) -> bool {
    let Some(curr) = cid.curr() else {
        return false;
    };
    let price = price(&curr, cid, time::now());
    policy::pinned_preempts(FRONTIER.get(), depth, slice, price.live)
}

/// A kernel thread's wakeup: a claimed idle CID, or its own with a
/// preemption for a pinned one that out-deserves the occupant. Without an
/// idle CID, an unpinned one is routed as any wakeup, so that it does not
/// wait behind a worker while a CID of the LLC is idle.
#[inline(always)]
fn enqueue_kthread(task: &Task, cid: Cid, flags: EnqFlags) {
    // Only the key below: a kernel thread's grant is the fixed slice.
    if !task.pinned() {
        if let Some(target) = claim(task, cid).get() {
            admit_direct(task);
            return admit_on(task, target, policy::SLICE_NS, flags | immed());
        }
        enqueue_wake(task, cid);
        return;
    }
    let floor = FRONTIER.get().wrapping_sub(policy::SLICE_NS);
    let flags = if pinned_preempts(cid, vtime_of(task).wrapping_sub(floor), policy::SLICE_NS) {
        flags | EnqFlags::PREEMPT
    } else {
        flags
    };
    admit_direct(task);
    dsq::insert(task, Dsq::LocalOn(cid), policy::SLICE_NS, flags);
}

/// The continuation of a task that the kernel handed back, or that a
/// seat's holder evicted: an idle CID of the LLC serves it directly, and
/// the pool takes it when no claim wins.
#[inline(always)]
fn enqueue_evicted(task: &Task, cid: Cid, key: u64, flags: EnqFlags) {
    if let Some(idle) = claim(task, cid).get() {
        set_vtime(task, key);
        return admit_on(task, idle, task_slice(task), flags | immed());
    }
    serve::pool_insert(task, cid, task_slice(task), key, flags);
    kick_idle(task, cid, true);
}

/// After an insert on a queue, kick an idle CID of the LLC that can steal
/// it, so that the wakers fan out. A pool insert no idle CID of its own
/// LLC can serve is offered to another LLC.
#[inline(always)]
fn kick_idle(task: &Task, cid: Cid, pooled: bool) {
    if !task.pinned()
        && let Some(idle) = claim(task, cid).get()
    {
        return idle.kick(KickFlags::IDLE);
    }
    if pooled && crate::multi_pool() {
        serve::offer_remote(task, cid);
    }
}

/// ops.enqueue().
#[inline(always)]
pub fn enqueue(task: &Task, flags: EnqFlags) {
    let cid = task.cid();
    let wakeup = flags.contains(EnqFlags::WAKEUP);
    let unpinned = !task.pinned();
    if wakeup && task.kthread() {
        return enqueue_kthread(task, cid, flags);
    }
    // Wakeups that wait longer than a turn of their own are placed anew.
    if wakeup && unpinned && is_starved(task, true) {
        enqueue_wake(task, cid);
        return;
    }
    let frontier = FRONTIER.get();
    let floor = frontier.wrapping_sub(policy::SLICE_NS);
    let own = vtime_of(task);
    let key = policy::continuation_key(frontier, own);
    // Anti-collision: a wakeup whose CID runs an equally served task would
    // wait out that task's whole slice while other CIDs may be idle.
    if wakeup
        && unpinned
        && let Some(curr) = cid.curr()
        && !same_task(&curr, task)
        && !curr.idle_task()
        && !is_starved(&curr, false)
    {
        // An occupant past its grant that the tick has not stopped yet
        // yields now. A stage on its own seat keeps the CID, and a forced
        // requeue keeps its way to the pool.
        if !reenq(flags) && !seat::owns(cid, curr.pid() as u32) && grant_spent(&curr, cid) {
            let slice = admit_direct(task);
            return dsq::insert(task, Dsq::LocalOn(cid), slice, flags | EnqFlags::PREEMPT);
        }
        let (slice, key) = admit(task);
        serve::pool_insert(task, cid, slice, key, flags);
        return kick_idle(task, cid, true);
    }
    // A forced requeue cannot count on service at its CID, and the
    // stranger on a seat its holder took back has to leave it. Pinned
    // tasks cannot.
    let evicted = retaken(cid) && !seat::owns(cid, task.pid() as u32);
    if unpinned && (reenq(flags) || evicted) {
        return enqueue_evicted(task, cid, key, flags);
    }
    // The continuation: the CID's own queue, warm, which the LLC steals
    // from.
    let slice = task_slice(task);
    // A task its CID is still switching out is served by that CID's next
    // pick, and a kicked idle CID would lose the race or take it cold.
    let alone = !wakeup && task.running() && !cid.has_queued();
    // The own queue is the scheduler's, where a PREEMPT flag means
    // nothing: the verdict goes as a kick after the insert.
    let preempt = wakeup && !unpinned && pinned_preempts(cid, own.wrapping_sub(floor), slice);
    set_vtime(task, key);
    dsq::insert_vtime(task, Edq::Cid(cid), slice, key, flags);
    if preempt {
        cid.kick(KickFlags::PREEMPT);
    }
    if alone && dsq::nr_queued(Dsq::LocalOn(cid)) == 0 {
        return;
    }
    kick_idle(task, cid, false);
}

/// Has `cid`'s seat holder just been placed behind its occupant?
#[inline(always)]
fn retaken(cid: Cid) -> bool {
    match cid.slot::<CidCtx>() {
        Some(here) => here.retake().get() != 0,
        None => false,
    }
}

/// Has the task running on `cid` used up the slice ops.running() granted
/// it? A CID in mid-switch has not.
#[inline(always)]
fn grant_spent(curr: &Task, cid: Cid) -> bool {
    let Some(here) = cid.slot::<CidCtx>() else {
        return false;
    };
    if !curr.queued() || curr.slot_optional::<crate::TaskCtx>().is_none() {
        return false;
    }
    if here.pid().get() != u64::from(curr.pid() as u32) {
        return false;
    }
    let ran = policy::time_delta(time::now(), here.stamp().get());
    policy::grant_left(ran, here.grant().get()) == 0
}
