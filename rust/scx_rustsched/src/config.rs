// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.

//! The configuration table, `.rodata.config`: what the loader resolves
//! from the running kernel's BTF, the enumerators of the kernel's
//! sched_ext ABI, and the scheduler's tunables, filled in before the
//! object is loaded and frozen. The verifier then resolves each field
//! access to a constant offset, so the program carries no CO-RE records
//! and no kernel layout. The indexes are `scx_rustsched_abi`'s, which the loader
//! fills by the same names.

use core::ptr::{addr_of, read_volatile};

pub use scx_rustsched_abi::*;

/// The table, in a map of its own, frozen by the loader.
#[used]
#[unsafe(no_mangle)]
#[unsafe(link_section = ".rodata.config")]
pub static CONFIG: [u64; WORDS] = [0; WORDS];

/// Entry `index` of the table.
#[inline(always)]
pub fn get(index: usize) -> u64 {
    unsafe { read_volatile(addr_of!(CONFIG[index])) }
}

/// Entry `index`, as a byte offset.
#[inline(always)]
pub fn offset(index: usize) -> usize {
    get(index) as usize
}
