// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.

//! The per-CID runnable queues: one EDQ per CID in the arena, and the
//! ownership of the tasks in them.
//!
//! A queued task is in BPF custody, and the kernel can take it back behind
//! the scheduler's back while another CID is halfway through stealing it.
//! Its state says who may move it on:
//!
//! ```text
//!          enqueue          pop             insert on the
//!   NONE ----------> ENQUEUED ----> DISPATCHING ----> local DSQ
//!     ^                  |               |
//!     +------------------+---------------+  ops.dequeue(), a property change
//! ```
//!
//! A task whose cgroup is out of cpu.max bandwidth waits PARKED in its
//! cgroup's backlog instead, see bandwidth.rs, and goes back to NONE when
//! the backlog lets it go.
//!
//! A pop has to win ENQUEUED -> DISPATCHING and then find the task still
//! queued and still in that state before it inserts it. A dequeue publishes
//! its state before unlinking, so a pop in flight fails its check instead
//! of dispatching a task the kernel has taken back. Nodes are held across
//! the unlocked part, which keeps a context alive while a remote CID looks
//! at it, and an enqueue that finds its node still held by an older pop
//! dispatches directly instead of reusing it.
//!
//! One bit per CID says whether its queue has anything in it, so that a CID
//! looking for work to pull walks a word of the mask instead of reading the
//! queue of every CID of the node. The bit is set after a task is queued and
//! cleared by whoever finds the queue empty, with a second look after the
//! clear in case a task was queued in between. It is a hint: a bit left set
//! is cleared by the first CID that looks and finds nothing.

use crate::sched::Cid;
use crate::task::Task;
use core::ptr::null_mut;

use crate::kfuncs::{bpf_arena_alloc_pages, scx_bpf_dsq_insert, scx_bpf_tid_to_task};
use crate::{
    cid_table::CidTable,
    edq::{self, Cursor, ENOENT, Memory},
    mem,
    ops::{SCX_DEQ_SCHED_CHANGE, SCX_DSQ_LOCAL, SCX_DSQ_LOCAL_ON},
    pool::{self, arena},
    time_before,
};

const NONE: u64 = 0;
const ENQUEUED: u64 = 1;
const DISPATCHING: u64 = 2;
const DISPATCHED: u64 = 3;
const PARKED: u64 = 4;

const QUEUE_BYTES: u64 = edq::QUEUE_BYTES;
/// Pops a dispatch retries when the popped task was lost to a race.
const MAX_POPS: u32 = 64;
/// Tasks a steal looks at in one victim's queue, BALANCE_TASK_SCAN.
const STEAL_SCAN: u32 = 8;

/// A queued task's bookkeeping, at its node: the EDQ's words, then the tid
/// the task is found by, its custody state, and the slice and enqueue
/// flags its dispatch uses. A scheduler's task context embeds these words
/// in this order.
#[derive(Clone, Copy)]
pub struct Node(pub u64);

/// Words a node takes in a task context.
pub const NODE_WORDS: u64 = edq::TASK_WORDS + 4;

impl Node {
    const TID: u64 = edq::TASK_WORDS;
    const STATE: u64 = Self::TID + 1;
    const SLICE: u64 = Self::STATE + 1;
    const ENQ_FLAGS: u64 = Self::SLICE + 1;

    #[inline(always)]
    pub fn tid(&self) -> u64 {
        mem::load(self.0, Self::TID * 8)
    }

    #[inline(always)]
    pub fn set_tid(&self, value: u64) {
        mem::store(self.0, Self::TID * 8, value)
    }

    #[inline(always)]
    pub fn state(&self) -> u64 {
        mem::load(self.0, Self::STATE * 8)
    }

    #[inline(always)]
    pub fn set_state(&self, value: u64) {
        mem::store(self.0, Self::STATE * 8, value)
    }

    /// The address of the custody state, for compare and exchange.
    #[inline(always)]
    pub fn state_address(&self) -> u64 {
        self.0 + Self::STATE * 8
    }

    /// The slice and enqueue flags a dispatch of the queued task uses.
    #[inline(always)]
    pub fn dispatch_args(&self) -> (u64, u64) {
        (
            mem::load(self.0, Self::SLICE * 8),
            mem::load(self.0, Self::ENQ_FLAGS * 8),
        )
    }

    #[inline(always)]
    pub fn set_dispatch_args(&self, slice: u64, enq_flags: u64) {
        mem::store(self.0, Self::SLICE * 8, slice);
        mem::store(self.0, Self::ENQ_FLAGS * 8, enq_flags);
    }
}

// The queue table, with the address of the queued mask in its header's
// extra word. The loader reads the header.
crate::cid_table!(Queues, QUEUES in ".data.queues", bytes: QUEUE_BYTES, extra: 1);

pub use crate::pool::Arena;

pub fn init(count: u32) -> i32 {
    let result = unsafe { Queues::init(count) };
    if result != 0 {
        return result;
    }
    let words = u64::from(count).div_ceil(64);
    let mask = unsafe {
        bpf_arena_alloc_pages(
            (&raw mut arena).cast(),
            null_mut(),
            (words * 8).div_ceil(4096) as u32,
            -1,
            0,
        )
    };
    if mask.is_null() {
        return -12;
    }
    unsafe { Queues::set_extra(0, mask as u64) };
    0
}

/// The address of word `index` of the queued mask.
#[inline(always)]
fn mask_word(index: u32) -> u64 {
    Queues::extra(0) + u64::from(index) * 8
}

/// Word `index` of the queued mask, one bit per CID from `index * 64`.
#[inline(always)]
pub fn queued_word(index: u32) -> u64 {
    mem::load(mask_word(index), 0)
}

/// Is `cid`'s queued bit set?
#[inline(always)]
pub fn queued_test(cid: Cid) -> bool {
    let cid = cid.raw() as u32;
    cid < cid_count() && queued_word(cid / 64) & (1 << (cid % 64)) != 0
}

/// Set `cid`'s queued bit, after a task was queued there. A bit already set
/// is not written again: the word is shared by 64 CPUs.
#[inline(always)]
fn queued_set(cid: Cid) {
    if cid.raw() as u32 >= cid_count() || queued_test(cid) {
        return;
    }
    let cid = cid.raw() as u32;
    mem::or(mask_word(cid / 64), 1 << (cid % 64));
}

/// Clear `cid`'s queued bit if its queue is empty, and set it again if a
/// task was queued in the meantime. A global function, verified once
/// rather than at each of the scans that call it.
#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn rust_queued_check(cid: i32) {
    if cid as u32 >= cid_count() || Cid(cid).nr_queued() != 0 || !queued_test(Cid(cid)) {
        return;
    }
    let cid = cid as u32;
    mem::and(mask_word(cid / 64), !(1 << (cid % 64)));
    if Cid(cid as i32).nr_queued() != 0 {
        queued_set(Cid(cid as i32));
    }
}

/// Initialize `cid`'s queue, from `init`.
pub fn init_cid(cid: Cid) {
    edq::queue_init(Arena, queue(cid));
}

#[inline(always)]
pub fn queue(cid: Cid) -> u64 {
    Queues::address(cid, 0)
}

/// The number of CIDs.
#[inline(always)]
pub fn cid_count() -> u32 {
    Queues::count()
}

/// Queue the task whose node is `node` on `cid`, keyed by `deadline` and
/// `vtime`, to be dispatched with `slice` and `enq_flags`. Returns false
/// if it could not be queued, and the caller dispatches it directly
/// instead: its node is still held by a pop from an older enqueue that a
/// property change ended, and that pop must find it dispatched rather
/// than see the one node stand for both. Always inline: with more than
/// five arguments it cannot be a BPF function call.
#[inline(always)]
pub fn insert(
    node: u64,
    cid: Cid,
    slice: u64,
    enq_flags: u64,
    deadline: u64,
    vtime: u64,
    request: u64,
) -> bool {
    let task = Node(node);
    if edq::held(Arena, node) {
        task.set_state(DISPATCHED);
        return false;
    }
    task.set_dispatch_args(slice, enq_flags);
    // Custody is published before another CID's pop can see the node.
    task.set_state(ENQUEUED);
    let result = rust_queue_insert(queue(cid), node, deadline, vtime, request);
    if result != 0 {
        Arena.cas(task.state_address(), ENQUEUED, NONE);
        if result != edq::ECANCELED {
            pool::count_error();
        }
        return false;
    }
    queued_set(cid);
    true
}

/// Put the task whose node is `node` in a backlog at `backlog`, a queue
/// ordered by `key` alone, such as the cpu.max backlog ordered by the time
/// the task was parked, see bandwidth::park(). A node an older pop still
/// holds, or one already queued, is not ours to move: the task runs once
/// more and is parked at its next enqueue.
#[inline(always)]
pub fn park(node: u64, backlog: u64, key: u64, slice: u64) -> bool {
    let task = Node(node);
    if edq::held(Arena, node) || task.state() == ENQUEUED {
        return false;
    }
    task.set_dispatch_args(slice, 0);
    task.set_state(PARKED);
    if rust_queue_insert(backlog, node, key, key, slice) != 0 {
        Arena.cas(task.state_address(), PARKED, NONE);
        pool::count_error();
        return false;
    }
    true
}

/// End the parked state of a task the backlog has let go. False when
/// something else ended its enqueue meanwhile.
#[inline(always)]
pub fn unpark(node: u64) -> bool {
    Arena.cas(Node(node).state_address(), PARKED, NONE) == PARKED
}

/// Insert a task popped from a queue into this CPU's local DSQ, for
/// `dst_cid`, if it is still ours to dispatch, and drop its hold.
#[inline(always)]
pub fn dispatch_popped(node: u64, dst_cid: Cid) -> bool {
    rust_dispatch_popped(node, dst_cid.raw()) != 0
}

/// dispatch_popped(), as a global function: ops.dispatch() reaches it from
/// every scan, and the verifier checks it once rather than at each call,
/// which kept ops.dispatch() within its instruction budget.
#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn rust_dispatch_popped(node: u64, dst_cid: i32) -> u32 {
    let state = Node(node);
    let dispatched = 'dispatch: {
        unsafe {
            if Arena.cas(state.state_address(), ENQUEUED, DISPATCHING) != ENQUEUED {
                break 'dispatch false;
            }
            let task = scx_bpf_tid_to_task(state.tid());
            if task.is_null() {
                // The tid resolves through exit; a queued node outliving its
                // task is a corruption.
                pool::count_error();
                break 'dispatch false;
            }
            if !crate::task::task_queued(Task::from_ptr(task)) || state.state() != DISPATCHING {
                break 'dispatch false;
            }
            let (slice, enq_flags) = state.dispatch_args();
            // A task this CPU may not run goes to the local DSQ of its own
            // CID instead, where it can. Dropping it would rely on a property
            // change to enqueue it again, and a remote reader can see a
            // transient affinity that no dequeue follows: such a task stayed
            // out of every queue until the watchdog. If a change is in
            // flight, the kernel discards this insertion as stale and the
            // change enqueues the task again.
            if !crate::task::allowed_on(Task::from_ptr(task), Cid(dst_cid)) {
                let cid = crate::task::task_cid(Task::from_ptr(task)).raw();
                scx_bpf_dsq_insert(task, SCX_DSQ_LOCAL_ON | cid as u32 as u64, slice, enq_flags);
                break 'dispatch false;
            }
            scx_bpf_dsq_insert(task, SCX_DSQ_LOCAL, slice, enq_flags);
            true
        }
    };
    edq::drop_task(Arena, node);
    u32::from(dispatched)
}

/// What a dispatch from a CID's own queue found.
pub enum Pick {
    Nothing,
    /// The first eligible task, which was also the first in the queue.
    Eligible,
    /// The first eligible task, behind ineligible ones.
    SkippedIneligible,
    /// Nothing was eligible, and the first task was taken anyway.
    Fallback,
}

/// Move the first task of `cid`'s queue eligible against `reference` to
/// this CPU, or the first task if none is, so that a queue that is
/// transiently all ineligible is not stranded. A pop that loses its task to
/// a race has still removed the node, so pop again rather than leave the
/// CPU idle over tasks that are ready.
///
/// A queue left empty has its queued bit cleared, unless `requeue` says the
/// task that was running goes back in it as soon as the dispatch returns,
/// which it does only if this found something to run instead.
/// Clearing the bit and setting it again then is two atomic writes per
/// switch to a word that 64 CPUs share, and scx_eevdf measured a pinned
/// pair of yielders per CPU five times slower than fair.c that way.
pub fn move_first_eligible(cid: Cid, reference: u64, requeue: bool, take_head: bool) -> Pick {
    let queue = queue(cid);
    let mut pick = Pick::Nothing;
    Arena.repeat(MAX_POPS, || {
        let head = edq::first_deadline(Arena, queue);
        let node = if take_head {
            edq::pop_first(Arena, queue, true)
        } else {
            edq::pop_first_eligible_or_first(Arena, queue, reference, true)
        };
        if node == 0 {
            return false;
        }
        let (deadline, vtime, _) = edq::key(Arena, node);
        let found = if time_before(reference, vtime) {
            Pick::Fallback
        } else if head != Some(deadline) {
            Pick::SkippedIneligible
        } else {
            Pick::Eligible
        };
        if dispatch_popped(node, cid) {
            pick = found;
            return false;
        }
        true
    });
    if !requeue || matches!(pick, Pick::Nothing) {
        rust_queued_check(cid.raw());
    }
    pick
}

/// The deadline of the first task of `cid`'s queue eligible against
/// `reference`, and the shortest queued request. Never waits for a remote
/// holder of the queue lock: a contended queue answers with its lockless
/// first deadline, which can be ineligible and so errs toward not
/// preempting. Without `eligible_scan` the head is the pick, whatever its
/// eligibility, and nothing bounds the protection.
pub fn head_deadline(cid: Cid, reference: u64, eligible_scan: bool) -> (Option<u64>, u64) {
    let queue = queue(cid);
    if !eligible_scan {
        return (edq::first_deadline(Arena, queue), 0);
    }
    let (result, deadline, min_slice) = edq::try_first_eligible_deadline(Arena, queue, reference);
    match result {
        0 => (Some(deadline), min_slice),
        ENOENT => (None, min_slice),
        _ => (
            edq::first_deadline(Arena, queue),
            edq::min_slice(Arena, queue),
        ),
    }
}

/// Take a task that can run on `dst`'s CPU from `victim`'s queue: the
/// first of a few in deadline order that is still queued, allowed there and
/// not one `skip` passes over, such as a task cache hot on the victim. The
/// scan holds each node while it checks it and claims that exact node, so
/// that a concurrent enqueue cannot substitute another task between the
/// check and the steal, the semantics of fair.c's locked detach. A
/// contended queue is passed over.
///
/// The scan resumes from `cursor`, where the caller's last pull from
/// `victim` stopped, so that hot or pinned tasks at the head are not
/// checked again on every pull, and wraps to the head at the end, like
/// scx_eevdf's detach cursor.
#[inline(always)]
pub fn steal_from(
    dst: Cid,
    victim: Cid,
    cpu: i32,
    cursor: &mut Cursor,
    mut skip: impl FnMut(u64) -> bool,
) -> bool {
    let queue = queue(victim);
    if edq::nr_queued(Arena, queue) == 0 {
        rust_queued_check(victim.raw());
        return false;
    }
    let mut moved = false;
    let mut busy = false;
    // A plain loop rather than a closure: called from more than one place,
    // the closure was outlined into a function whose environment parameter
    // has no name, which the kernel's BTF check rejects.
    unsafe {
        for _ in crate::loops::range(0, STEAL_SCAN) {
            let (result, node) = edq::try_peek_next_hold(Arena, queue, cursor);
            if result != 0 {
                busy = result == edq::EBUSY;
                break;
            }
            if node == 0 {
                break;
            }
            let state = Node(node);
            if state.state() != ENQUEUED || skip(node) {
                edq::drop_task(Arena, node);
                continue;
            }
            let task = scx_bpf_tid_to_task(state.tid());
            // A proxy-execution donor stays where it is, see
            // Task::is_blocked().
            if task.is_null()
                || !crate::task::runs_on(Task::from_ptr(task), cpu)
                || Task::from_ptr(task).is_blocked()
            {
                edq::drop_task(Arena, node);
                continue;
            }
            // Claim the exact node the scan looked at.
            let result = rust_queue_try_remove(queue, node);
            if result != 0 {
                edq::drop_task(Arena, node);
                if result == edq::EINVAL {
                    continue;
                }
                busy = true;
                break;
            }
            moved = dispatch_popped(node, dst);
            if moved {
                break;
            }
        }
    }
    if !busy {
        rust_queued_check(victim.raw());
    }
    moved
}

/// Hold the next task in `cid`'s queue after `cursor`, advancing it: the
/// node, 0 at the end, or an error when the queue is contended.
#[inline(always)]
pub fn peek_next(cid: Cid, cursor: &mut Cursor) -> (i32, u64) {
    edq::try_peek_next_hold(Arena, queue(cid), cursor)
}

/// Take the exact `node` out of `cid`'s queue, if the queue is free.
#[inline(always)]
pub fn try_remove(cid: Cid, node: u64) -> i32 {
    rust_queue_try_remove(queue(cid), node)
}

/// edq::insert() into the queue at `queue`, as a global function with five
/// scalar arguments: outlined as itself, its prototype would count the
/// zero-sized memory handle as a sixth, which BPF passes on the stack.
#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn rust_queue_insert(
    queue: u64,
    node: u64,
    deadline: u64,
    vtime: u64,
    request: u64,
) -> i32 {
    edq::insert(Arena, queue, node, deadline, vtime, request)
}

/// Take the exact `node` out of the queue at `queue`, as a global function:
/// the tree's rebalancing is checked once by the verifier rather than in
/// every scan loop that removes a task.
#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn rust_queue_try_remove(queue: u64, node: u64) -> i32 {
    edq::try_remove(Arena, queue, node)
}

/// Bring the node of a task context just handed out to the state of one
/// queued nowhere and held by nobody.
#[inline(always)]
pub fn node_init(node: u64) {
    edq::task_init(Arena, node);
}

/// Take the first task out of the backlog at `backlog`, a queue park()
/// filled, and return its node, held, or 0 if the backlog is empty or
/// its lock could not be had.
#[inline(always)]
pub fn pop_parked(backlog: u64) -> u64 {
    edq::pop_first(Arena, backlog, true)
}

/// How many pops and peeks hold the node, for the debug dump.
#[inline(always)]
pub fn hold_count(node: u64) -> i64 {
    edq::hold_count(Arena, node)
}

/// Is the node linked in `cid`'s queue, for the debug dump?
#[inline(always)]
pub fn linked_on(node: u64, cid: Cid) -> bool {
    edq::membership(Arena, node) == queue(cid)
}

/// The deadline at the head of `cid`'s queue, or 0 if it is empty, for the
/// debug dump.
#[inline(always)]
pub fn first_deadline(cid: Cid) -> u64 {
    edq::first_deadline(Arena, queue(cid)).unwrap_or(0)
}

/// Drop a hold on a queued task's node.
#[inline(always)]
pub fn drop_held(node: u64) {
    edq::drop_task(Arena, node);
}

/// Is the queued task whose node is `node` still waiting there, ours to
/// move?
#[inline(always)]
pub fn still_queued(node: u64) -> bool {
    Node(node).state() == ENQUEUED
}

/// The deadline and eligibility a queued task was keyed with.
#[inline(always)]
pub fn queued_key(node: u64) -> (u64, u64, u64) {
    edq::key(Arena, node)
}

/// The task whose node is `node` leaves BPF custody, ops.dequeue(). A
/// property change ends this enqueue: publish NONE before unlinking, so
/// that a concurrent pop cannot dispatch it. Otherwise the task leaves for
/// a DSQ or to run. Returns true when the task was taken out of a backlog
/// here, so that the caller stops counting it there.
pub fn dequeue(node: u64, cid: Cid, deq_flags: u64) -> bool {
    let state = Node(node);
    let current = state.state();
    if deq_flags & SCX_DEQ_SCHED_CHANGE != 0 {
        state.set_state(NONE);
    } else if current == ENQUEUED || current == DISPATCHING {
        state.set_state(DISPATCHED);
    }
    match edq::task_fini(Arena, node) {
        1.. if current == PARKED => return true,
        1.. => rust_queued_check(cid.raw()),
        0 => {}
        _ => pool::count_error(),
    }
    false
}

/// Take the task whose node is `node` out of every queue for good and
/// wait for its holders, before its context is reused.
pub fn detach(node: u64) -> bool {
    edq::task_detach(Arena, node) == 0
}

/// The CID-centred part of this module, as methods.
impl Cid {
    /// Does `cid` have anything queued?
    #[inline(always)]
    pub fn has_queued(self) -> bool {
        let cid = self;
        edq::nr_queued(Arena, queue(cid)) != 0
    }

    /// How many tasks `cid` has queued.
    #[inline(always)]
    pub fn nr_queued(self) -> u64 {
        let cid = self;
        edq::nr_queued(Arena, queue(cid))
    }

    /// Lockless snapshot of the shortest request queued on `cid`, 0 for none.
    #[inline(always)]
    pub fn min_slice(self) -> u64 {
        let cid = self;
        edq::min_slice(Arena, queue(cid))
    }
}
