// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Will Clingan
// MIRROR OF src/bpf/intf.h CONSTANTS. KEEP IN SYNC WITH THE C HEADER.
// THE STATIC ASSERT IN scheduler.rs CATCHES MAX_AFFINITY_CANDIDATES
// DRIFT AT COMPILE TIME.

pub const MAX_CPUS: u32 = 1024;
pub const MAX_AFFINITY_CANDIDATES: u32 = MAX_CPUS >> 3;
pub const EWMA_HIST_BUCKETS: usize = 16;
pub const CODEL_FLOOR_MIN_NS: u64 = 200_000;
pub const STEAL_REF_ROW: usize = 4;
pub const STEAL_REF_SLOTS: usize = 4 * STEAL_REF_ROW;
