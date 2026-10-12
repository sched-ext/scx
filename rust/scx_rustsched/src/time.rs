// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.

//! Time, in nanoseconds, and the comparison of times that wrap.

use crate::kfuncs::scx_bpf_now;

/// The current time: the runqueue's clock where the callback holds one,
/// which costs nothing to read.
#[inline(always)]
pub fn now() -> u64 {
    scx_bpf_now()
}

/// Is `first` before `second`? Right for two times, or two virtual times,
/// less than half the range apart, whether or not either wrapped.
#[inline(always)]
pub fn before(first: u64, second: u64) -> bool {
    crate::time_before(first, second)
}
