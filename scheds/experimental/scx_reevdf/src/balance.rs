// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.

//! The balancers' per-CID state, observed from the loader: what the idle
//! pull, periodic balance and active balance have settled on for each CID.
//! Like the queues, it is read from the arena's mapping, at the word
//! indexes the BPF program is built with, bpf/src/balance_state.rs, and
//! nothing is added to the scheduling paths for it.

use std::ffi::OsStr;

use anyhow::{Context, Result, ensure};
use libbpf_rs::{MapCore, MapFlags};
use scx_rustsched_loader::{ArenaView, Loaded, tiers::MAX_CPUS};

pub use crate::balance_state::State;
use crate::balance_state::{
    ACTIVE_INTERVAL, AVG_IDLE, BUSY_FAILED, BUSY_INTERVAL, BUSY_LLC, BUSY_NODE, BUSY_SYSTEM, BYTES,
    MAX_BALANCE_COST, NEWIDLE_FAILED, NEWIDLE_LLC, NEWIDLE_NODE, NEWIDLE_RATIO, NEWIDLE_SYSTEM,
};

/// Read the state of the CID whose entry is at `entry`. The words are read
/// one at a time without a lock, so they need not be of the same instant.
fn read(view: &ArenaView, entry: u64) -> State {
    let word = |index: u64| view.read(entry + index * 8);
    State {
        avg_idle_ns: word(AVG_IDLE),
        newidle_cost_ns: word(MAX_BALANCE_COST),
        newidle_ratio: [
            word(NEWIDLE_RATIO + NEWIDLE_LLC),
            word(NEWIDLE_RATIO + NEWIDLE_NODE),
            word(NEWIDLE_RATIO + NEWIDLE_SYSTEM),
        ],
        newidle_failed: word(NEWIDLE_FAILED),
        busy_interval_ms: [
            word(BUSY_INTERVAL + BUSY_LLC),
            word(BUSY_INTERVAL + BUSY_NODE),
            word(BUSY_INTERVAL + BUSY_SYSTEM),
        ],
        busy_failed: [
            word(BUSY_FAILED + BUSY_LLC),
            word(BUSY_FAILED + BUSY_NODE),
            word(BUSY_FAILED + BUSY_SYSTEM),
        ],
        active_interval_ms: word(ACTIVE_INTERVAL),
    }
}

/// Reads every CID's balance state.
pub struct BalanceReader {
    view: ArenaView,
    table: u64,
    count: u64,
}

impl BalanceReader {
    /// The balance table of the attached scheduler in `object`, whose
    /// header is the table's arena address and the number of CIDs.
    pub fn new(object: &Loaded) -> Result<Self> {
        let view = ArenaView::new(object)?;
        let header = object
            .maps()
            .find(|map| map.name() == OsStr::new(".data.balance"))
            .context("find the balance table")?;
        let mut data = [0_u8; 16];
        ensure!(
            header.lookup_into(&0_u32.to_ne_bytes(), &mut data, MapFlags::ANY)?,
            "read the balance table"
        );
        let table = u64::from_ne_bytes(data[..8].try_into()?);
        let count = u64::from_ne_bytes(data[8..].try_into()?);
        ensure!(
            table != 0 && count != 0 && count <= MAX_CPUS as u64,
            "the balance table is not set up"
        );
        Ok(Self { view, table, count })
    }

    /// Every CID's state as of now, indexed by CID.
    pub fn read(&self) -> Vec<State> {
        (0..self.count)
            .map(|cid| read(&self.view, self.table + cid * BYTES))
            .collect()
    }
}
