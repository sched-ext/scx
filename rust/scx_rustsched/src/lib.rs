// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.

//! The sched_ext runtime for a scheduler whose BPF program is written in
//! Rust: what every such scheduler needs and no policy owns. It is two
//! layers.
//!
//! The framework is what a scheduler is written in. A scheduler that uses
//! nothing else has no `unsafe`:
//!
//! - `sched`: a scheduler as an `impl` block of typed callbacks,
//!   `#[scheduler]`, over `Task` and `Cid`, and `#[global]` for a function
//!   the verifier checks once.
//! - `dsq`, `idle`: the kernel's dispatch queues, and the picks of an idle
//!   CID by topology.
//! - `var`, `state`, `param`, `time`: what the callbacks share, as `Var`
//!   globals and a typed state per task and per CID, the tunables the
//!   loader sets by name, and the clock.
//!
//! The core is what the framework stands on, and what a scheduler reaches
//! for when it needs more than the framework wraps:
//!
//! - `ops`: the kernel types the callbacks take, the enqueue, dequeue, kick
//!   and ops flags, and `scx_ops!`, which declares the struct_ops map from
//!   the callbacks the scheduler implements.
//! - `kfuncs`: the kfuncs, declared from the catalog in ../kfuncs.rs, which
//!   the build reads too.
//! - `helpers`, `timer`: the BPF helpers, called by number, and the timer
//!   maps built on them.
//! - `config`: the configuration table the loader fills in from the
//!   running kernel's BTF, laid out as `scx_rustsched_abi` says.
//! - `task`: what the program reads from a task_struct.
//! - `pool`, `mem`, `loops`: the arena, loads, stores and atomic updates
//!   in it by arena address, and loops the verifier can bound.
//! - `cid_table`, `cids`, `cid_idle`, `cid_ranges`, `tiers`, `topology`:
//!   tables in the arena with one entry per CID, the idle CIDs and the
//!   scans of them by topology, the capacity tiers and what the kernel's
//!   asymmetric packing says.
//! - `edq`, `slab`, `ravg`, `clock`: the eligible deadline queue and the
//!   free list, over any memory, running averages, and the per-CID task
//!   clock.
//! - `queue`: an eligible deadline queue per CID, with the custody of the
//!   tasks in them.
//! - `slots`: the pool of per-task slots in the arena, where a queued
//!   task's node lives.
//! - `uei`: the exit record.
//!
//! The crate is built for the BPF target by the scheduler's build script.
//! Its global functions,
//! `rust_*`, are BPF global functions the verifier checks once, as are the
//! scheduler's own under `#[global]`; the build tags their task
//! parameters `arg:trusted`. Everything else is `#[inline(always)]`, and the
//! scheduler's release profile links with LTO so that it stays so across
//! the crate boundary.

#![no_std]
#![allow(non_camel_case_types)]
#![feature(core_intrinsics)]
#![feature(asm_experimental_arch)]
#![allow(internal_features)]

mod builtins;
pub mod cid_idle;
pub mod cid_ranges;
pub mod cid_table;
pub mod cids;
pub mod clock;
pub mod config;
pub mod dsq;
pub mod edq;
pub mod helpers;
pub mod idle;
pub mod kfuncs;
pub mod loops;
pub mod mem;
pub mod ops;
pub mod param;
pub mod pool;
pub mod queue;
pub mod ravg;
pub mod sched;
pub mod slab;
pub mod slots;
pub mod state;
pub mod task;
pub mod tiers;
pub mod time;
pub mod timer;
pub mod topology;
pub mod uei;
pub mod var;

pub use ops::{cpumask, task_struct};
pub use sched::{global, scheduler};
pub use scx_rustsched_macros::opts;

/// What a scheduler written with `#[scheduler]` uses, see `sched`.
pub mod prelude {
    pub use crate::dsq::{self, Dsq, SLICE_DFL};
    pub use crate::idle::{self, Kind, Scope};
    pub use crate::params;
    pub use crate::sched::{Cid, DeqFlags, EnqFlags, Error, KickFlags, WakeFlags};
    pub use crate::task::Task;
    pub use crate::time;
    pub use crate::var::Var;
}

/// Wrapping time comparison: is `first` before `second`?
#[inline(always)]
pub fn time_before(first: u64, second: u64) -> bool {
    (first.wrapping_sub(second) as i64) < 0
}
