// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.

//! The dispatch queues.
//!
//! A task the scheduler is asked to enqueue goes into a queue, and a CPU
//! runs what is on its local DSQ. There are two kinds of queue.
//!
//! A `Dsq` is the kernel's. `Dsq::Local` and `Dsq::LocalOn` are the local
//! DSQs, and `Dsq::Global` is the kernel's own shared queue, which every
//! CPU of a node takes from by itself when its local DSQ is empty.
//!
//! An `Edq` is the scheduler's own, an eligible deadline queue in the
//! arena, see queue.rs: `Edq::Cid`, one per CID, and `Edq::User`, which
//! belong to no CID. They are used as the kernel's user DSQs are, filled
//! in ops.enqueue() and moved to a local DSQ in ops.dispatch(), and take
//! their place: there are no user DSQs of the kernel's here. Being in the
//! arena, any CPU can look into any of them, they can be ordered by a
//! deadline as well as by virtual time, and the field the kernel orders a
//! DSQ by is left to hold the address of the task's slot, see slots.rs.
//! The node a task is queued by lives in its slot, see slots.rs.
//!
//! ```ignore
//! const SHARED: Edq = Edq::User(0);
//!
//! // ops.init()
//! dsq::create(SHARED)?;
//! // ops.enqueue()
//! dsq::insert_vtime(task, SHARED, slice, vtime, flags);
//! // ops.dispatch()
//! dsq::move_to_local(SHARED, cid);
//! ```
//!
//! Some calls have no counterpart in the kernel's DSQs. insert_deadline()
//! orders a task by a deadline and keeps its virtual time beside it, and
//! move_to_local_eligible() takes the earliest deadline among the tasks
//! whose virtual time has come. peek() says what such a pick would find
//! without making it, and move_to_local_scan() takes from the queue of
//! another CID with a say on each task.
//!
//! peek_next() walks a queue a task at a time, each one held while the
//! scheduler looks at it and decides whether to take it. A `Backlog` is a
//! queue tasks are parked in rather than run from. See each of them.
//!
//! An `Edq::Cid` queue is mostly taken by its own CPU, which is where the
//! arena pays. Every CPU takes the lock of an `Edq::User` queue to queue a
//! task and to pick one, so one queue for a whole machine does not scale.

pub use crate::edq::{CURSOR_AT, CURSOR_START, Cursor};
use crate::queue::Key;
pub use crate::queue::{USER_MAX, queued, queued_test, queued_word};
use crate::sched::DeqFlags;
use crate::sched::Error;
use crate::slots::TaskSlot;
use crate::{
    kfuncs::{scx_bpf_dsq_insert, scx_bpf_dsq_nr_queued},
    ops::{SCX_DSQ_LOCAL, SCX_DSQ_LOCAL_ON},
    sched::{Cid, EnqFlags},
    task::Task,
};
use core::marker::PhantomData;

const SCX_DSQ_GLOBAL: u64 = (1 << 63) | 1;

/// The default time slice, the kernel's SCX_SLICE_DFL.
pub const SLICE_DFL: u64 = 20_000_000;

/// A dispatch queue of the kernel's.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Dsq {
    /// The local DSQ of the CPU the callback runs for.
    Local,
    /// The local DSQ of a CID.
    LocalOn(Cid),
    /// The kernel's shared DSQ. CPUs take from it without being asked.
    Global,
}

impl Dsq {
    /// The id the kfuncs take.
    #[inline(always)]
    pub fn id(self) -> u64 {
        match self {
            Dsq::Local => SCX_DSQ_LOCAL,
            Dsq::LocalOn(cid) => SCX_DSQ_LOCAL_ON | cid.0 as u32 as u64,
            Dsq::Global => SCX_DSQ_GLOBAL,
        }
    }
}

/// A queue of the scheduler's, in the arena.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Edq {
    /// The queue of a CID. There is one per CID from the start.
    Cid(Cid),
    /// A queue that belongs to no CID, by its id, which is below
    /// `USER_MAX`.
    User(u64),
}

/// What insert() and nr_queued() take: a `Dsq` or an `Edq`.
pub trait Queue: Copy {
    #[doc(hidden)]
    fn insert(self, task: &Task, slice: u64, flags: EnqFlags);
    #[doc(hidden)]
    fn nr_queued(self) -> u32;
}

impl Queue for Dsq {
    #[inline(always)]
    fn insert(self, task: &Task, slice: u64, flags: EnqFlags) {
        unsafe { scx_bpf_dsq_insert(task.as_ptr(), self.id(), slice, flags.0) };
    }

    #[inline(always)]
    fn nr_queued(self) -> u32 {
        scx_bpf_dsq_nr_queued(self.id()).max(0) as u32
    }
}

impl Queue for Edq {
    #[inline(always)]
    fn insert(self, task: &Task, slice: u64, flags: EnqFlags) {
        insert_edq(task, self, Key::fifo(slice), slice, flags);
    }

    #[inline(always)]
    fn nr_queued(self) -> u32 {
        match self.address() {
            Some(queue) => crate::edq::nr_queued(crate::queue::Arena, queue) as u32,
            None => 0,
        }
    }
}

impl Edq {
    /// The queue in the arena, None for an id that is out of range.
    #[inline(always)]
    fn address(self) -> Option<u64> {
        match self {
            Edq::Cid(cid) => Some(crate::queue::queue(cid)),
            Edq::User(id) if id < USER_MAX => Some(crate::queue::user_queue(id)),
            Edq::User(_) => None,
        }
    }
}

/// Check the id of an `Edq::User` queue, from ops.init(). The queues are
/// there from the start, so this creates nothing: it is where an id out
/// of range fails the load rather than every insert.
#[inline(always)]
pub fn create(edq: Edq) -> Result<(), Error> {
    match edq.address() {
        Some(_) => Ok(()),
        None => Err(Error::EINVAL),
    }
}

/// Queue `task` on `queue` to run for `slice` nanoseconds, from
/// ops.enqueue() or, for an idle CID it picked, ops.select_cid(). On an
/// `Edq` the task goes behind what is there, and a queue takes either
/// this or the ordered inserts, not both.
#[inline(always)]
pub fn insert(task: &Task, queue: impl Queue, slice: u64, flags: EnqFlags) {
    queue.insert(task, slice, flags)
}

/// Queue `task` on `edq` ordered by `vtime`: the lowest runs first. False
/// if the task could not be queued there and went to a kernel DSQ, the
/// local one of the CID for an `Edq::Cid` and the global one otherwise.
#[inline(always)]
pub fn insert_vtime(task: &Task, edq: Edq, slice: u64, vtime: u64, flags: EnqFlags) -> bool {
    insert_edq(task, edq, Key::vtime(vtime, slice), slice, flags)
}

/// insert_vtime() for a queue ordered by `deadline`: the earliest runs
/// first, and `vtime` is the virtual time the task is eligible from, for
/// move_to_local_eligible().
#[inline(always)]
pub fn insert_deadline(
    task: &Task,
    edq: Edq,
    slice: u64,
    vtime: u64,
    deadline: u64,
    flags: EnqFlags,
) -> bool {
    let key = Key {
        deadline,
        vtime,
        request: slice,
    };
    insert_edq(task, edq, key, slice, flags)
}

/// A task that cannot be queued in the arena goes to a kernel DSQ: the
/// local one of the CID whose queue it was meant for, or the global one.
/// That is a task with no slot, or one whose node a CPU still holds from
/// an enqueue that a property change ended.
#[inline(always)]
fn insert_edq(task: &Task, edq: Edq, key: Key, slice: u64, flags: EnqFlags) -> bool {
    let queued = match (unsafe { crate::slots::node(task.as_ptr()) }, edq.address()) {
        (Some(node), Some(queue)) => {
            crate::queue::Node(node).set_tid(task.tid());
            let (deadline, vtime, request) = (key.deadline, key.vtime, key.request);
            match edq {
                Edq::Cid(cid) => {
                    crate::queue::insert(node, cid, slice, flags.0, deadline, vtime, request)
                }
                Edq::User(_) => {
                    crate::queue::insert_at(queue, node, slice, flags.0, deadline, vtime, request)
                }
            }
        }
        _ => false,
    };
    if !queued {
        let fallback = match edq {
            Edq::Cid(cid) => Dsq::LocalOn(cid),
            Edq::User(_) => Dsq::Global,
        };
        unsafe { scx_bpf_dsq_insert(task.as_ptr(), fallback.id(), slice, flags.0) };
    }
    queued
}

/// Move the first task of `edq` that may run on `cid` to its local DSQ,
/// from ops.dispatch(). Returns whether it moved one. From the queue of
/// another CID this looks at a few tasks from the head, and passes over a
/// queue another CPU is working on.
///
/// `cid` is the one ops.dispatch() was called for. It is not always the
/// CPU the callback runs on: with core scheduling a CPU dispatches for
/// its sibling too, so `Cid::current()` is not a substitute.
#[inline(always)]
pub fn move_to_local(edq: Edq, cid: Cid) -> bool {
    move_edq(edq, cid, None, false)
}

/// move_to_local() with eligibility: the first task whose virtual time is
/// not past `vtime_now`, which is the earliest deadline among the tasks
/// that are owed service, as insert_deadline() ordered them. With none
/// eligible the first task goes, so that the CPU does not idle over a
/// queue that has work. The queue of another CID is taken from as
/// move_to_local() does.
#[inline(always)]
pub fn move_to_local_eligible(edq: Edq, cid: Cid, vtime_now: u64) -> bool {
    move_edq(edq, cid, Some(vtime_now), false)
}

/// move_to_local(), or move_to_local_eligible() given a `vtime_now`, with
/// a hint: `requeue` says the task that was running on `cid` goes back on
/// this queue as soon as the dispatch returns. A queue this leaves empty is
/// then not marked empty for the CIDs that look for work, unless it found
/// nothing, which saves two writes per switch to a word 64 CPUs share.
#[inline(always)]
pub fn move_to_local_with(edq: Edq, cid: Cid, vtime_now: Option<u64>, requeue: bool) -> bool {
    move_edq(edq, cid, vtime_now, requeue)
}

/// What a pick from a queue would find, from peek().
#[derive(Clone, Copy)]
pub struct Head {
    /// The deadline of the task the pick would take, None for no task.
    pub deadline: Option<u64>,
    /// The shortest slice queued, 0 for none or when it was not read.
    pub min_slice: u64,
}

/// What move_to_local_eligible(edq, vtime_now) would take, without taking
/// it, or what move_to_local(edq) would without a `vtime_now`. It never
/// waits for a CPU that is working on the queue: it then answers with the
/// first deadline, which can be ineligible.
#[inline(always)]
pub fn peek(edq: Edq, vtime_now: Option<u64>) -> Head {
    let Some(queue) = edq.address() else {
        return Head {
            deadline: None,
            min_slice: 0,
        };
    };
    let (deadline, min_slice) =
        crate::queue::head_deadline_at(queue, vtime_now.unwrap_or(0), vtime_now.is_some());
    Head {
        deadline,
        min_slice,
    }
}

/// move_to_local() from the queue of another CID, with a say on each
/// task: one whose slot `skip` returns true for is passed over, such as a
/// task whose cache is hot where it is. The scan resumes from `cursor`,
/// where the caller's last one of this queue stopped, so that the tasks
/// it passed over are not looked at again every time, and wraps at the
/// end. Start with `Cursor::start()`. False for an `Edq::User`.
#[inline(always)]
pub fn move_to_local_scan<T: crate::slots::TaskSlot>(
    edq: Edq,
    cid: Cid,
    cursor: &mut Cursor,
    mut skip: impl FnMut(T) -> bool,
) -> bool {
    let Edq::Cid(victim) = edq else {
        return false;
    };
    crate::queue::steal_from(cid, victim, cid.cpu(), cursor, |node| {
        skip(T::from_address(crate::slots::of_node(node)))
    })
}

#[inline(always)]
fn move_edq(edq: Edq, here: Cid, reference: Option<u64>, requeue: bool) -> bool {
    use crate::queue::{Pick, move_first_eligible, pop_to_local, steal_from};
    let (reference, head) = match reference {
        Some(reference) => (reference, false),
        None => (0, true),
    };
    match edq {
        Edq::Cid(cid) if cid == here => !matches!(
            move_first_eligible(cid, reference, requeue, head),
            Pick::Nothing
        ),
        Edq::Cid(cid) => {
            let mut cursor = crate::edq::Cursor::start();
            steal_from(here, cid, here.cpu(), &mut cursor, |_| false)
        }
        Edq::User(_) => {
            let Some(queue) = edq.address() else {
                return false;
            };
            if crate::edq::nr_queued(crate::queue::Arena, queue) == 0 {
                return false;
            }
            !matches!(pop_to_local(queue, here, reference, head), Pick::Nothing)
        }
    }
}

/// Look at `cid`'s queue again and clear its queued bit if it is empty:
/// after a scan that took the last task some other way than a move, or
/// that expected a task to come back on the queue and it did not.
#[inline(always)]
pub fn queued_check(cid: Cid) {
    crate::queue::rust_queued_check(cid.raw());
}

/// A task met in a walk of a queue, from peek_next(). It is held: its
/// slot is not handed to another task while this is alive, whatever
/// happens to the task meanwhile. Dropping it lets go.
pub struct Held<T: TaskSlot> {
    queue: u64,
    node: u64,
    slot: PhantomData<T>,
}

/// What peek_next() found.
pub enum Next<T: TaskSlot> {
    /// Another CPU is working on the queue.
    Busy,
    /// There is no task past the cursor.
    End,
    Task(Held<T>),
}

/// What became of a task Held::move_to_local() was asked to move.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Moved {
    /// It is on this CPU's local DSQ.
    Done,
    /// It was no longer there to take: it left the queue, or the kernel
    /// took it back.
    Lost,
    /// Another CPU is working on the queue.
    Busy,
}

/// Hold the next task of `edq` after `cursor`, in the queue's order, and
/// advance the cursor, so that a walk of a few tasks at a time resumes
/// where it stopped even after those tasks have left. It never waits for
/// a CPU that is working on the queue.
#[inline(always)]
pub fn peek_next<T: TaskSlot>(edq: Edq, cursor: &mut Cursor) -> Next<T> {
    let Some(queue) = edq.address() else {
        return Next::End;
    };
    let (result, node) = crate::edq::try_peek_next_hold(crate::queue::Arena, queue, cursor);
    if result != 0 {
        Next::Busy
    } else if node == 0 {
        Next::End
    } else {
        Next::Task(Held {
            queue,
            node,
            slot: PhantomData,
        })
    }
}

impl<T: TaskSlot> Held<T> {
    /// The scheduler's state of the task.
    #[inline(always)]
    pub fn slot(&self) -> T {
        T::from_address(crate::slots::of_node(self.node))
    }

    /// The task, valid until the callback returns. None once it is gone.
    #[inline(always)]
    pub fn task<'task>(&self) -> Option<&'task Task> {
        Task::from_tid(crate::queue::Node(self.node).tid())
    }

    /// Is the task still waiting in the queue, the scheduler's to move?
    #[inline(always)]
    pub fn is_queued(&self) -> bool {
        crate::queue::still_queued(self.node)
    }

    /// The deadline and the virtual time the task was queued with, and
    /// its place in the order of insertion, which with the deadline is a
    /// `Cursor` to it.
    #[inline(always)]
    pub fn key(&self) -> (u64, u64, u64) {
        crate::queue::queued_key(self.node)
    }

    /// Take this very task out of the queue and move it to the local DSQ
    /// of `cid`, the one ops.dispatch() was called for. A task `cid` may
    /// not run goes to the local DSQ of its own CID instead, and counts
    /// as lost.
    #[inline(always)]
    pub fn move_to_local(self, cid: Cid) -> Moved {
        let (queue, node) = (self.queue, self.node);
        if crate::queue::rust_queue_try_remove(queue, node) != 0 {
            // Dropped here, which lets go of the task.
            return Moved::Busy;
        }
        // The dispatch lets go of the task itself.
        core::mem::forget(self);
        if crate::queue::dispatch_popped(node, cid) {
            Moved::Done
        } else {
            Moved::Lost
        }
    }
}

impl<T: TaskSlot> Drop for Held<T> {
    #[inline(always)]
    fn drop(&mut self) {
        crate::queue::drop_held(self.node);
    }
}

/// A queue tasks wait in without being run from it, such as the tasks of
/// a cgroup that is out of bandwidth: the scheduler parks a task there,
/// and pops it when it may run again, to queue it on an `Edq`. It is in
/// the scheduler's own arena memory, `Backlog::WORDS` words that start as
/// zeroes, and orders tasks by the key they were parked with.
#[derive(Clone, Copy)]
pub struct Backlog(u64);

/// A task popped from a `Backlog`, held as a `Held` is.
pub struct Parked<T: TaskSlot> {
    node: u64,
    slot: PhantomData<T>,
}

impl Backlog {
    /// Words a backlog takes.
    pub const WORDS: u64 = crate::edq::QUEUE_WORDS;

    /// The backlog at `address` in the arena.
    #[inline(always)]
    pub fn at(address: u64) -> Backlog {
        Backlog(address)
    }

    /// Park `task`, from ops.enqueue(), behind the tasks with a lower
    /// `key`, to be dispatched with `slice` when it is let go. False if
    /// it cannot be parked now, because a CPU still holds it or it is
    /// queued: the caller then lets it run once more.
    #[inline(always)]
    pub fn park(self, task: &Task, key: u64, slice: u64) -> bool {
        let Some(node) = (unsafe { crate::slots::node(task.as_ptr()) }) else {
            return false;
        };
        crate::queue::Node(node).set_tid(task.tid());
        crate::queue::park(node, self.0, key, slice)
    }

    /// Take the first task out. None if the backlog is empty or another
    /// CPU is working on it.
    #[inline(always)]
    pub fn pop<T: TaskSlot>(self) -> Option<Parked<T>> {
        match crate::queue::pop_parked(self.0) {
            0 => None,
            node => Some(Parked {
                node,
                slot: PhantomData,
            }),
        }
    }
}

impl<T: TaskSlot> Parked<T> {
    /// The scheduler's state of the task.
    #[inline(always)]
    pub fn slot(&self) -> T {
        T::from_address(crate::slots::of_node(self.node))
    }

    /// The task, valid until the callback returns. None once it is gone.
    #[inline(always)]
    pub fn task<'task>(&self) -> Option<&'task Task> {
        Task::from_tid(crate::queue::Node(self.node).tid())
    }

    /// End the task's wait, so that it can be queued again. False if the
    /// kernel took it back meanwhile, and there is nothing to queue.
    #[inline(always)]
    pub fn unpark(&self) -> bool {
        crate::queue::unpark(self.node)
    }
}

impl<T: TaskSlot> Drop for Parked<T> {
    #[inline(always)]
    fn drop(&mut self) {
        crate::queue::drop_held(self.node);
    }
}

/// The kernel takes `task` back, from the scheduler's own ops.dequeue()
/// when its slot type sets `TaskSlot::OWN_DEQUEUE`: out of the `Edq` or
/// the `Backlog` it waits in, or away from the CPU that is moving it.
/// Returns true if it was taken out of a `Backlog`, which whoever counts
/// the parked tasks needs to know.
#[inline(always)]
pub fn dequeue(task: &Task, flags: DeqFlags) -> bool {
    match unsafe { crate::slots::node(task.as_ptr()) } {
        Some(node) => crate::queue::dequeue_any(node, flags.0),
        None => false,
    }
}

/// What the queues know of a task, for a debug dump.
#[derive(Clone, Copy)]
pub struct Inspect {
    /// Its custody state, see queue.rs.
    pub state: u64,
    /// Is it linked in the `Edq` asked about?
    pub linked: bool,
    /// How many CPUs hold it.
    pub holds: i64,
    /// The deadline and the virtual time it was last queued with.
    pub deadline: u64,
    pub vtime: u64,
}

/// What the queues know of `task`, and whether it is in `edq`.
#[inline(always)]
pub fn inspect(task: &Task, edq: Edq) -> Option<Inspect> {
    let node = unsafe { crate::slots::node(task.as_ptr()) }?;
    let (deadline, vtime, _) = crate::queue::queued_key(node);
    Some(Inspect {
        state: crate::queue::Node(node).state(),
        linked: edq.address() == Some(crate::edq::membership(crate::queue::Arena, node)),
        holds: crate::queue::hold_count(node),
        deadline,
        vtime,
    })
}

/// How many tasks `queue` holds.
#[inline(always)]
pub fn nr_queued(queue: impl Queue) -> u32 {
    queue.nr_queued()
}
