// SPDX-License-Identifier: GPL-2.0
//! Flat hint helpers for the flow scheduler.
//!
//! Copyright (c) 2026 Galih Tama <galpt@v.recipes>

//! Holds the flat period hint table shared by BPF and userspace tests.
//! The flat view tunes the period only, and no group or pool shapes
//! order. The BPF hints live in cgroup.bpf.c with rows in hint_stor,
//! and this file mirrors the table with no map use. Full tables miss
//! to the default period with no eviction.

/// Max hint rows bound shared with the BPF header.
pub const HINT_MAX: u64 = 4096;

/// Period hint in micros for one weight with a fixed table.
/// Light shares map to long periods and heavy shares map to short
/// periods, so the hint tunes admission with no share use.
#[cfg(test)]
pub fn hint_period_us(weight: u32) -> u64 {
    let w = weight.clamp(crate::flow_slice::WEIGHT_MIN, crate::flow_slice::WEIGHT_MAX);
    if w < 64 {
        32_000
    } else if w < 128 {
        16_000
    } else if w < 512 {
        8_000
    } else {
        4_000
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_maps_light_long_heavy_short() {
        assert_eq!(hint_period_us(1), 32_000);
        assert_eq!(hint_period_us(100), 16_000);
        assert_eq!(hint_period_us(200), 8_000);
        assert_eq!(hint_period_us(1000), 4_000);
    }
}
