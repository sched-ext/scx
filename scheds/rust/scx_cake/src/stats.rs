// SPDX-License-Identifier: GPL-2.0
// Statistics module for scx_cake - utilities for reading/formatting scheduler stats from BPF maps

/// Priority tier names (4-tier system classified by avg_runtime)
pub const TIER_NAMES: [&str; 4] = [
    "Critical",    // T0: <100µs
    "Interactive", // T1: <2ms
    "Frame",       // T2: <8ms
    "Bulk",        // T3: ≥8ms
];
