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
//! - `loops`: loops the verifier can bound.
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
#![feature(asm_experimental_arch)]

pub mod helpers;
pub mod kfuncs;
pub mod loops;
pub mod ops;
pub mod timer;

pub use ops::{cpumask, task_struct};

/// Wrapping time comparison: is `first` before `second`?
#[inline(always)]
pub fn time_before(first: u64, second: u64) -> bool {
    (first.wrapping_sub(second) as i64) < 0
}
