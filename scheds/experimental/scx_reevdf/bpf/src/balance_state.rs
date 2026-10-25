// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.

//! Where a CID's balance state keeps what is worth watching from outside.
//! The loader builds this very file and reads these words from the arena's
//! mapping, see src/balance.rs, and newidle.rs checks at build time that
//! each index is where its structure has the field. Nothing is written
//! for the reader's sake: every word is state the balancers keep for
//! themselves.

/// Bytes of a CID's entry in the table.
pub const BYTES: u64 = 1024;

/// The idle pull's words. Per level, in the order LLC, node, system: the
/// worst pull and NI_RANDOM's ratio.
pub const AVG_IDLE: u64 = 0;
pub const MAX_BALANCE_COST: u64 = 2;
pub const NEWIDLE_COST: u64 = 3;
pub const NEWIDLE_RATIO: u64 = 18;
pub const NEWIDLE_FAILED: u64 = 21;
pub const NEWIDLE_LLC: u64 = 0;
pub const NEWIDLE_NODE: u64 = 1;
pub const NEWIDLE_SYSTEM: u64 = 2;

/// Periodic balance's words, per level in the order system, node, LLC.
pub const BUSY_INTERVAL: u64 = 23;
pub const BUSY_FAILED: u64 = 32;
pub const BUSY_SYSTEM: u64 = 0;
pub const BUSY_NODE: u64 = 1;
pub const BUSY_LLC: u64 = 2;

/// Active balance's interval.
pub const ACTIVE_INTERVAL: u64 = 66;

/// What one CID's balancers have settled on, as of the read. The per-level
/// arrays are in the order LLC, node, system.
#[allow(dead_code)]
#[derive(Clone, Copy, Debug, Default)]
pub struct State {
    /// How long the CID stays idle after a pull, rq->avg_idle.
    pub avg_idle_ns: u64,
    /// The worst whole pull, rq->max_idle_balance_cost.
    pub newidle_cost_ns: u64,
    /// Of 1024, how often NI_RANDOM admits a scan of the level.
    pub newidle_ratio: [u64; 3],
    /// Pulls in a row that found work queued but took nothing.
    pub newidle_failed: u64,
    /// Milliseconds between two periodic passes of the level.
    pub busy_interval_ms: [u64; 3],
    /// Periodic passes in a row that found an imbalance and moved nothing.
    pub busy_failed: [u64; 3],
    /// Milliseconds before the CID may ask for a running task again.
    pub active_interval_ms: u64,
}
