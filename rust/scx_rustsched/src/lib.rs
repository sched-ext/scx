// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.

//! The sched_ext runtime for a scheduler whose BPF program is written in
//! Rust: what every such scheduler needs and no policy owns.
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
//! - `loops`: loops the verifier can bound.
//! - `uei`: the exit record.
//!
//! The crate is built for the BPF target by the scheduler's build script.
//! Its global functions,
//! `rust_*`, are BPF global functions the verifier checks once; the
//! scheduler's build lists the ones whose kernel-pointer parameters need
//! an `arg:trusted` tag. Everything else is `#[inline(always)]`, and the
//! scheduler's release profile links with LTO so that it stays so across
//! the crate boundary.

#![no_std]
#![allow(non_camel_case_types)]
#![feature(core_intrinsics)]
#![feature(asm_experimental_arch)]
#![allow(internal_features)]

pub mod config;
pub mod helpers;
pub mod kfuncs;
pub mod loops;
pub mod ops;
pub mod task;
pub mod timer;
pub mod uei;

pub use ops::{cpumask, task_struct};

/// Wrapping time comparison: is `first` before `second`?
#[inline(always)]
pub fn time_before(first: u64, second: u64) -> bool {
    (first.wrapping_sub(second) as i64) < 0
}
