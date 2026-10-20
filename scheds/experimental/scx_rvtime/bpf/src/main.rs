// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.

//! scx_rvtime: a weighted virtual time scheduler, as scx_simple is in C.
//!
//! Every task waits in one queue ordered by virtual time, which advances
//! with the time the task ran, scaled inversely by its weight. A task that
//! slept comes back at most one slice behind the queue, so that it runs
//! soon without starving the rest.
//!
//! The queue is an `Edq`, a queue of scx_rustsched's in the arena.

#![no_std]
#![no_main]

use scx::prelude::*;
use scx_rustsched as scx;

// The tunables: one for each option of the loader, ../src/main.rs, named
// as the option in upper case, a time in microseconds as _NS.
scx::opts!();

const SHARED: Edq = Edq::User(0);

/// The virtual time of the task that ran last: where the queue is.
static VTIME_NOW: Var<u64> = Var::new(0);

scx::arena_struct! {
    /// What the scheduler keeps per task, in the arena.
    struct TaskCtx {
        vtime: u64,
        /// When the task last got a CPU.
        started_at: u64,
    }
}

impl scx::slots::TaskSlot for TaskCtx {}

#[scx::scheduler(name = "rvtime", task_slot = TaskCtx)]
impl Vtime {
    fn init() -> Result<(), Error> {
        dsq::create(SHARED)
    }

    fn select_cid(task: &Task, prev: Cid, _flags: WakeFlags) -> Cid {
        match idle::pick(task, prev, Scope::Llc, Kind::AnyCpu) {
            Some(cid) => {
                dsq::insert(task, Dsq::Local, SLICE_NS.get(), EnqFlags::NONE);
                cid
            }
            None => prev,
        }
    }

    fn enqueue(task: &Task, flags: EnqFlags) {
        let Some(ctx) = task.slot::<TaskCtx>() else {
            return dsq::insert(task, Dsq::Global, SLICE_NS.get(), flags);
        };
        let floor = VTIME_NOW.get().wrapping_sub(SLICE_NS.get());
        let vtime = ctx.vtime().update(|vtime| {
            if time::before(vtime, floor) {
                floor
            } else {
                vtime
            }
        });
        dsq::insert_vtime(task, SHARED, SLICE_NS.get(), vtime, flags);
    }

    fn dispatch(cid: Cid, _prev: Option<&Task>) {
        dsq::move_to_local(SHARED, cid);
    }

    fn running(task: &Task) {
        let Some(ctx) = task.slot::<TaskCtx>() else {
            return;
        };
        ctx.started_at().set(time::now());
        if time::before(VTIME_NOW.get(), ctx.vtime().get()) {
            VTIME_NOW.set(ctx.vtime().get());
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
        if let Some(ctx) = task.slot::<TaskCtx>() {
            ctx.vtime().set(VTIME_NOW.get());
        }
    }

    fn dump(_dump: &DumpCtx) {
        scx::dump!("rvtime now=%llu", VTIME_NOW.get());
    }

    fn dump_task(_dump: &DumpCtx, task: &Task) {
        if let Some(ctx) = task.slot::<TaskCtx>() {
            scx::dump!("rvtime vtime=%llu", ctx.vtime().get());
        }
    }
}
