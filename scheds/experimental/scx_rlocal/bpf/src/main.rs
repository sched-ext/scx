// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.

//! scx_rlocal: one queue per CPU, ordered by weighted virtual time, and
//! CPUs that take from their LLC when their own queue is empty.
//!
//! A task waits on the queue of the CPU it was placed on, so it tends to
//! run where its cache is. A CPU with nothing queued takes the first task
//! it may run from another queue of its LLC, which keeps a CPU from idling
//! beside a queue that has work.
//!
//! The queues are scx_rustsched's per-CID DSQs, `Edq::Cid`, which live in the
//! arena: any CPU can look into any of them.

#![no_std]
#![no_main]

use scx::prelude::*;
use scx_rustsched as scx;

// The tunables: one for each option of the loader, ../src/main.rs, named
// as the option in upper case, a time in microseconds as _NS.
scx::opts!();

scx::arena_struct! {
    /// What the scheduler keeps per task, in the arena.
    struct TaskCtx {
        vtime: u64,
        /// When the task last got a CPU.
        started_at: u64,
    }
}

impl scx::slots::TaskSlot for TaskCtx {}

scx::arena_struct! {
    /// What the scheduler keeps per CID, in the arena.
    struct CidCtx {
        /// The highest virtual time that ran here: where this queue is.
        vtime_now: u64,
    }
}

/// Take a task for `cid` from another queue of its LLC.
#[scx::global]
fn steal(cid: Cid) -> bool {
    for peer in dsq::queued(cid, Scope::Llc) {
        if peer != cid && dsq::move_to_local(Edq::Cid(peer), cid) {
            return true;
        }
    }
    false
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

/// Claim an idle CID of `prev`'s LLC for a waking task. A core whose SMT
/// siblings are all idle comes first, since a task there shares the core
/// with nobody. Only with no such core left in the LLC does the task take
/// any idle CID, and shares a core. Either way `prev` is tried first.
#[inline(always)]
fn pick_idle(task: &Task, prev: Cid) -> Option<Cid> {
    if idle::smt() {
        if let Some(cid) = pick_near(task, prev, Kind::FullCore) {
            return Some(cid);
        }
    }
    pick_near(task, prev, Kind::AnyCpu)
}

#[scx::scheduler(
    name = "rlocal",
    flags = ENQ_LAST | ENQ_EXITING | ENQ_MIGRATION_DISABLED | ALLOW_QUEUED_WAKEUP,
    task_slot = TaskCtx,
    cid_slot = CidCtx
)]
impl Local {
    fn select_cid(task: &Task, prev: Cid, _flags: WakeFlags) -> Cid {
        match pick_idle(task, prev) {
            Some(cid) => {
                dsq::insert(task, Dsq::Local, SLICE_NS.get(), EnqFlags::NONE);
                cid
            }
            None => prev,
        }
    }

    fn enqueue(task: &Task, flags: EnqFlags) {
        // With ENQ_LAST the kernel hands over the last task of a CPU that
        // found nothing else to run, instead of keeping it running. The
        // task keeps its CPU: on a queue, the first CPU to run out of work
        // would take it, and a task alone on its CPU would move at every
        // slice. The CPU has made its pick by now and may be going idle,
        // so it is told to look again.
        if flags.last() {
            dsq::insert(task, Dsq::Local, SLICE_NS.get(), flags);
            return task.cid().kick(KickFlags::IDLE);
        }
        let cid = task.cid();
        let Some(ctx) = task.slot::<TaskCtx>() else {
            return dsq::insert(task, Dsq::Global, SLICE_NS.get(), flags);
        };
        let Some(here) = cid.slot::<CidCtx>() else {
            return dsq::insert(task, Dsq::Global, SLICE_NS.get(), flags);
        };
        // A wakeup the kernel queued to the task's CPU did not go through
        // ops.select_cid(). Give the task the same chance of an idle CID
        // here, and of running there at once.
        if !flags.cid_selected() && !task.running() {
            if let Some(idle) = pick_idle(task, cid) {
                dsq::insert(task, Dsq::LocalOn(idle), SLICE_NS.get(), flags);
                idle.kick(KickFlags::IDLE);
                return;
            }
        }
        // A task that slept, or comes from a queue that is behind this
        // one, starts at most one slice behind. One that comes from a
        // queue that is ahead starts at most one slice of its own ahead:
        // the queues do not share a clock, and a task kept as far ahead as
        // it arrived would wait until this queue caught up.
        let now = here.vtime_now().get();
        let floor = now.wrapping_sub(SLICE_NS.get());
        let ceiling = now.wrapping_add(task.scale_inverse(SLICE_NS.get()));
        let vtime = ctx.vtime().update(|vtime| {
            if time::before(vtime, floor) {
                floor
            } else if time::before(ceiling, vtime) {
                ceiling
            } else {
                vtime
            }
        });
        dsq::insert_vtime(task, Edq::Cid(cid), SLICE_NS.get(), vtime, flags);
        // An idle CPU of the LLC can take it from here.
        if let Some(idle) = idle::pick(task, cid, Scope::Llc, Kind::AnyCpu) {
            idle.kick(KickFlags::IDLE);
        }
    }

    fn dispatch(cid: Cid, _prev: Option<&Task>) {
        if !dsq::move_to_local(Edq::Cid(cid), cid) && !NO_STEAL.get() {
            steal(cid);
        }
    }

    fn running(task: &Task) {
        let Some(ctx) = task.slot::<TaskCtx>() else {
            return;
        };
        ctx.started_at().set(time::now());
        // The CID the task runs on, which is not always the one this
        // callback runs on.
        if let Some(here) = task.cid().slot::<CidCtx>() {
            if time::before(here.vtime_now().get(), ctx.vtime().get()) {
                here.vtime_now().set(ctx.vtime().get());
            }
        }
    }

    fn stopping(task: &Task, _runnable: bool) {
        let Some(ctx) = task.slot::<TaskCtx>() else {
            return;
        };
        let ran = time::now().wrapping_sub(ctx.started_at().get());
        ctx.vtime()
            .update(|vtime| vtime.wrapping_add(task.scale_inverse(ran)));
    }

    fn enable(task: &Task) {
        let Some(ctx) = task.slot::<TaskCtx>() else {
            return;
        };
        if let Some(here) = task.cid().slot::<CidCtx>() {
            ctx.vtime().set(here.vtime_now().get());
        }
    }
}
