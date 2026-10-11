// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.

//! The kernel's dispatch queues.
//!
//! A task the scheduler is asked to enqueue goes into a DSQ, and a CPU
//! runs what is on its local DSQ. `Dsq::Local` and `Dsq::LocalOn` are
//! those. `Dsq::Global` is the kernel's own shared queue, which every CPU
//! of a node takes from by itself when its local DSQ is empty. A
//! `Dsq::User` queue is the scheduler's: created in ops.init(), filled in
//! ops.enqueue() and moved to a local DSQ in ops.dispatch().

use crate::{
    kfuncs::{
        scx_bpf_create_dsq, scx_bpf_dsq_insert, scx_bpf_dsq_move_to_local___v2,
        scx_bpf_dsq_nr_queued,
    },
    ops::{SCX_DSQ_LOCAL, SCX_DSQ_LOCAL_ON},
    sched::{Cid, EnqFlags},
    task::Task,
};

const SCX_DSQ_GLOBAL: u64 = (1 << 63) | 1;

/// The default time slice, the kernel's SCX_SLICE_DFL.
pub const SLICE_DFL: u64 = 20_000_000;

/// A dispatch queue.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Dsq {
    /// The local DSQ of the CPU the callback runs for.
    Local,
    /// The local DSQ of a CID.
    LocalOn(Cid),
    /// The kernel's shared DSQ. CPUs take from it without being asked.
    Global,
    /// A queue of the scheduler's, by the id it was created with, which
    /// must leave the top bit clear.
    User(u64),
}

impl Dsq {
    /// The id the kfuncs take.
    #[inline(always)]
    pub fn id(self) -> u64 {
        match self {
            Dsq::Local => SCX_DSQ_LOCAL,
            Dsq::LocalOn(cid) => SCX_DSQ_LOCAL_ON | cid.0 as u32 as u64,
            Dsq::Global => SCX_DSQ_GLOBAL,
            Dsq::User(id) => id,
        }
    }
}

/// Create `Dsq::User(id)`, from ops.init(). Returns a negative errno if
/// the kernel refuses.
#[inline(always)]
pub fn create(id: u64) -> Result<(), i32> {
    match unsafe { scx_bpf_create_dsq(id, -1) } {
        0 => Ok(()),
        errno => Err(errno),
    }
}

/// Queue `task` on `dsq` to run for `slice` nanoseconds, from
/// ops.enqueue() or, for an idle CID it picked, ops.select_cid().
#[inline(always)]
pub fn insert(task: &Task, dsq: Dsq, slice: u64, flags: EnqFlags) {
    unsafe { scx_bpf_dsq_insert(task.as_ptr(), dsq.id(), slice, flags.0) };
}

/// Move the first task of `dsq` that may run here to this CPU's local DSQ,
/// from ops.dispatch(). Returns whether it moved one. The kernel does this
/// for `Dsq::Global` before it calls ops.dispatch(), so for that queue
/// there is nothing left to move and this returns false.
#[inline(always)]
pub fn move_to_local(dsq: Dsq) -> bool {
    match dsq {
        Dsq::User(id) => unsafe { scx_bpf_dsq_move_to_local___v2(id, 0) },
        _ => false,
    }
}

/// How many tasks `dsq` holds.
#[inline(always)]
pub fn nr_queued(dsq: Dsq) -> u32 {
    unsafe { scx_bpf_dsq_nr_queued(dsq.id()) }.max(0) as u32
}
