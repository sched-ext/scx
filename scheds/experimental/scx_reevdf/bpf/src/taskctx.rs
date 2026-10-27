// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.

//! The task context: what the scheduler keeps per task in its arena slot,
//! declared with scx_rustsched's arena_struct!, which gives each field its typed
//! accessor. The slot pool itself is scx_rustsched's slots.
//!
//! A slot is 512 bytes. It holds the task's virtual runtime, its request
//! (the deadline, its size and the weight the deadline was issued at), the
//! pack it is a member of, the lag it saved when it left one, its load
//! estimates, its cgroup, and the node its CID's queue links it by.
//!
//! The runtime allocates and resets a context in ops.init_task() and
//! returns it after ops.exit_task(), see `#[scheduler(task_slot = ...)]`.
//! A lookup takes the address kept in the task once it is enabled, and
//! falls back to task storage before that, where it checks that the
//! context is the task's. A handle stays local to a callback: nothing may
//! touch a context after its slot was returned.

use scx_rustsched::arena::Words;
use scx_rustsched::sched::Cid;
use scx_rustsched::task::Task;

use crate::cgroup::{Group, Queue};
use crate::slots;

/// In migrate_to: capacity pressure asked for the move, see pressure.rs.
const PRESSURE_MIGRATE: u64 = 1 << 32;

scx_rustsched::arena_struct! {
    /// A task's context: a handle to its slot in the arena.
    pub struct Context {
        vtime: u64,
        deadline: u64,
        request_slice: u64,
        request_weight: u64,
        /// The pack the task is a member of, (cid + 1) << 32 | weight, or 0.
        member: u64,
        /// The vruntime last folded into the member pack's reference.
        joined: u64,
        /// The lag saved when the task last left a pack.
        lag: i64,
        /// se.sum_exec_runtime at the last charge, see charge().
        charged: u64,
        /// Set until a forked task's first deadline has been issued.
        initial: bool,
        /// A debt to the pack the task blocked in, see pack::quiesce(): that
        /// pack's CID + 1 or 0, its reference and weight once the task had
        /// left, and how many times it had emptied.
        delay_cid: u64,
        delay_reference: u64,
        delay_weight: u64,
        delay_generation: u64,
        /// Whether the task runs, averaged over time, see load.rs.
        run_avg_words: [u64; 4],
        /// What the task used over its recent activations, util_est.
        util_est: u64,
        /// The fraction of wall time the task spends runnable, of 1024.
        runnable_est: u64,
        /// When the task last went to sleep, and last woke up.
        last_sleep_at: u64,
        runnable_at: u64,
        /// The wakeup history of placement, see idle::Wake.
        wake_words: Words<{ crate::idle::WAKE_WORDS }>,
        /// When the task last stopped running, for cache hotness.
        last_stop_at: u64,
        /// An idle CID an active balance hands the task to as it is enqueued
        /// again, plus one, or 0.
        migrate_to: u64,
        /// The block whose queues the task's cgroup joins, None outside of
        /// one, the queue it is a member of while in a pack, and its nice
        /// weight in that queue's load, see cgroup.rs.
        group: Option<Group>,
        group_queue: Option<Queue>,
        group_weight: u64,
        /// The weight the task last joined a pack at, its share of its cgroup
        /// hierarchy then.
        joined_weight: u64,
        /// The cgroup queue whose backlog the task waits in for cpu.max, see
        /// bandwidth.rs.
        parked_in: Option<Queue>,
    }
}

impl slots::TaskSlot for Context {
    /// ops.dequeue() needs to know when it took a task out of a cpu.max
    /// backlog, so it calls dsq::dequeue() itself.
    const OWN_DEQUEUE: bool = true;

    /// Every field a reader may see before the first write to it.
    #[inline(always)]
    fn reset(&self) {
        self.vtime().set(0);
        self.member().set(0);
        self.joined().set(0);
        self.lag().set(0);
        self.charged().set(0);
        self.initial().set(false);
        self.last_stop_at().set(0);
        self.group().set(None);
        self.group_queue().set(None);
        self.group_weight().set(0);
        self.joined_weight().set(0);
        self.parked_in().set(None);
        self.set_delay([0; 4]);
        self.set_request(crate::accounting::Request::default());
        self.set_run_avg(&crate::ravg::Ravg::default());
        self.set_load_state([0; 4]);
        self.wake().reset();
        let _ = self.take_migrate();
    }
}

/// The context of a task that may have none, such as the task that runs
/// a wakeup: the idle task, or one of a higher class.
#[inline(always)]
pub fn lookup_optional(task: &Task) -> Option<Context> {
    task.slot_optional()
}

#[inline(always)]
pub fn lookup(task: &Task) -> Option<Context> {
    task.slot()
}

impl Context {
    /// The task's wakeup history: its wakee flips and recently used CID.
    #[inline(always)]
    pub fn wake(&self) -> crate::idle::Wake {
        self.wake_words().view()
    }

    /// The recorded debt: CID + 1 (0 for none), reference, weight and
    /// generation.
    #[inline(always)]
    pub fn delay(&self) -> [u64; 4] {
        [
            self.delay_cid().get(),
            self.delay_reference().get(),
            self.delay_weight().get(),
            self.delay_generation().get(),
        ]
    }

    #[inline(always)]
    pub fn set_delay(&self, delay: [u64; 4]) {
        self.delay_cid().set(delay[0]);
        self.delay_reference().set(delay[1]);
        self.delay_weight().set(delay[2]);
        self.delay_generation().set(delay[3]);
    }

    #[inline(always)]
    pub fn run_avg(&self) -> crate::ravg::Ravg {
        let [val, val_at, old, cur] = self.run_avg_words().get();
        crate::ravg::Ravg {
            val,
            val_at,
            old,
            cur,
        }
    }

    #[inline(always)]
    pub fn set_run_avg(&self, average: &crate::ravg::Ravg) {
        self.run_avg_words()
            .set([average.val, average.val_at, average.old, average.cur]);
    }

    /// The utilization estimate, the runnable estimate, and when the task
    /// last slept and woke.
    #[inline(always)]
    pub fn load_state(&self) -> [u64; 4] {
        [
            self.util_est().get(),
            self.runnable_est().get(),
            self.last_sleep_at().get(),
            self.runnable_at().get(),
        ]
    }

    #[inline(always)]
    pub fn set_load_state(&self, values: [u64; 4]) {
        self.util_est().set(values[0]);
        self.runnable_est().set(values[1]);
        self.last_sleep_at().set(values[2]);
        self.runnable_at().set(values[3]);
    }

    /// Take the CID the task is to be moved to as it is enqueued, if any,
    /// and whether capacity pressure rather than an active balance asked.
    #[inline(always)]
    pub fn take_migrate(&self) -> Option<(i32, bool)> {
        let target = self.migrate_to().get();
        self.migrate_to().set(0);
        if target == 0 {
            None
        } else {
            Some(((target as u32) as i32 - 1, target & PRESSURE_MIGRATE != 0))
        }
    }

    /// An active balance hands the task to the idle `cid`.
    #[inline(always)]
    pub fn set_migrate(&self, cid: Cid) {
        self.migrate_to().set(cid.raw() as u32 as u64 + 1)
    }

    /// Capacity pressure moves the task to `cid`'s queue.
    #[inline(always)]
    pub fn set_pressure_migrate(&self, cid: Cid) {
        self.migrate_to()
            .set((cid.raw() as u32 as u64 + 1) | PRESSURE_MIGRATE)
    }

    #[inline(always)]
    pub fn request(&self) -> crate::accounting::Request {
        crate::accounting::Request {
            deadline: self.deadline().get(),
            slice: self.request_slice().get(),
            weight: self.request_weight().get(),
        }
    }

    /// End the pending request, Request::sleep() without reading the rest.
    #[inline(always)]
    pub fn end_request(&self) {
        self.request_slice().set(0)
    }

    #[inline(always)]
    pub fn set_request(&self, request: crate::accounting::Request) {
        self.deadline().set(request.deadline);
        self.request_slice().set(request.slice);
        self.request_weight().set(request.weight);
    }
}
