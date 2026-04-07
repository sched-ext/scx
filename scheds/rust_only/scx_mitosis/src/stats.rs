// SPDX-License-Identifier: GPL-2.0
//
// Statistics collection and formatting for scx_mitosis.
//
// Ported from the C version's stats.rs and main.rs stats infrastructure.
// The C version uses scx_stats/scx_stats_derive for a JSON stats server;
// we implement equivalent functionality with plain Rust structs.

use std::collections::BTreeMap;
use std::fmt;

// ── Constants matching eBPF side ────────────────────────────────────

pub const MAX_CELLS: usize = 256;
pub const NR_CSTATS: usize = 5;

// Stat indices matching eBPF CellStat enum.
pub const CSTAT_LOCAL: usize = 0;
pub const CSTAT_CPU_DSQ: usize = 1;
pub const CSTAT_CELL_DSQ: usize = 2;
pub const CSTAT_AFFN_VIOL: usize = 3;
pub const CSTAT_STEAL: usize = 4;

/// Queue stat indices used for distribution calculation.
/// Local + CPU_DSQ + Cell_DSQ = Total Decisions.
/// Affinity violations and steals are reported separately.
pub const QUEUE_STATS_IDX: [usize; 3] = [CSTAT_LOCAL, CSTAT_CPU_DSQ, CSTAT_CELL_DSQ];

// ── Distribution stats ──────────────────────────────────────────────

/// Per-scope (global or per-cell) distribution statistics.
///
/// Mirrors the C version's DistributionStats struct.
#[derive(Clone, Debug, Default)]
pub struct DistributionStats {
    /// Total scheduling decisions in this scope.
    pub total_decisions: u64,
    /// This scope's share of global decisions (%).
    pub share_of_decisions_pct: f64,
    /// Percentage dispatched to LOCAL DSQ (idle CPU found in select_cpu).
    pub local_q_pct: f64,
    /// Percentage dispatched to per-CPU DSQ (pinned tasks).
    pub cpu_q_pct: f64,
    /// Percentage dispatched to cell+LLC DSQ (normal path).
    pub cell_q_pct: f64,
    /// Affinity violations as % of total decisions.
    pub affn_viol_pct: f64,
    /// Work steals as % of total decisions.
    pub steal_pct: f64,
    /// Global total for formatting alignment.
    pub global_queue_decisions: u64,
}

impl fmt::Display for DistributionStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let width = if self.global_queue_decisions > 0 {
            std::cmp::max(5, (self.global_queue_decisions as f64).log10().ceil() as usize)
        } else {
            5
        };
        write!(
            f,
            "{:width$} {:5.1}% | Local:{:4.1}% From: CPU:{:4.1}% Cell:{:4.1}% | V:{:4.1}% S:{:4.1}%",
            self.total_decisions,
            self.share_of_decisions_pct,
            self.local_q_pct,
            self.cpu_q_pct,
            self.cell_q_pct,
            self.affn_viol_pct,
            self.steal_pct,
            width = width,
        )
    }
}

// ── Per-cell metrics ────────────────────────────────────────────────

/// Metrics for a single scheduling cell.
///
/// Mirrors the C version's CellMetrics.
#[derive(Clone, Debug, Default)]
pub struct CellMetrics {
    /// Number of CPUs assigned to this cell.
    pub num_cpus: u32,
    /// Local queue dispatch percentage.
    pub local_q_pct: f64,
    /// Per-CPU DSQ dispatch percentage.
    pub cpu_q_pct: f64,
    /// Cell+LLC DSQ dispatch percentage.
    pub cell_q_pct: f64,
    /// Affinity violations as % of total.
    pub affn_violations_pct: f64,
    /// Steal percentage.
    pub steal_pct: f64,
    /// This cell's share of global decisions.
    pub share_of_decisions_pct: f64,
    /// Total scheduling decisions for this cell.
    pub total_decisions: u64,
}

impl CellMetrics {
    pub fn update(&mut self, ds: &DistributionStats) {
        self.local_q_pct = ds.local_q_pct;
        self.cpu_q_pct = ds.cpu_q_pct;
        self.cell_q_pct = ds.cell_q_pct;
        self.affn_violations_pct = ds.affn_viol_pct;
        self.steal_pct = ds.steal_pct;
        self.share_of_decisions_pct = ds.share_of_decisions_pct;
        self.total_decisions = ds.total_decisions;
    }
}

// ── Global metrics ──────────────────────────────────────────────────

/// Aggregate scheduler metrics across all cells.
///
/// Mirrors the C version's Metrics.
#[derive(Clone, Debug, Default)]
pub struct Metrics {
    /// Number of active cells.
    pub num_cells: u32,
    /// Global local queue dispatch percentage.
    pub local_q_pct: f64,
    /// Global CPU DSQ dispatch percentage.
    pub cpu_q_pct: f64,
    /// Global cell DSQ dispatch percentage.
    pub cell_q_pct: f64,
    /// Global affinity violations percentage.
    pub affn_violations_pct: f64,
    /// Global steal percentage.
    pub steal_pct: f64,
    /// Always 100% for global scope.
    pub share_of_decisions_pct: f64,
    /// Total scheduling decisions globally.
    pub total_decisions: u64,
    /// Per-cell metrics, keyed by cell index.
    pub cells: BTreeMap<u32, CellMetrics>,
}

impl Metrics {
    pub fn update(&mut self, ds: &DistributionStats) {
        self.local_q_pct = ds.local_q_pct;
        self.cpu_q_pct = ds.cpu_q_pct;
        self.cell_q_pct = ds.cell_q_pct;
        self.affn_violations_pct = ds.affn_viol_pct;
        self.steal_pct = ds.steal_pct;
        self.share_of_decisions_pct = ds.share_of_decisions_pct;
        self.total_decisions = ds.total_decisions;
    }
}

impl fmt::Display for Metrics {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "cells={} decisions={} local={:.1}% cpu={:.1}% cell={:.1}% viol={:.1}% steal={:.1}%",
            self.num_cells,
            self.total_decisions,
            self.local_q_pct,
            self.cpu_q_pct,
            self.cell_q_pct,
            self.affn_violations_pct,
            self.steal_pct,
        )
    }
}

// ── Stats collector ─────────────────────────────────────────────────

/// Collects and computes scheduling statistics from BPF map data.
///
/// Maintains a snapshot of per-cell stats to compute deltas between
/// collection intervals.
pub struct StatsCollector {
    /// Previous per-cell stats snapshot for delta computation.
    prev_cell_stats: [[u64; NR_CSTATS]; MAX_CELLS],
    /// Current metrics.
    pub metrics: Metrics,
}

impl StatsCollector {
    pub fn new() -> Self {
        Self {
            prev_cell_stats: [[0; NR_CSTATS]; MAX_CELLS],
            metrics: Metrics::default(),
        }
    }

    /// Calculate distribution stats for a scope (global or per-cell).
    ///
    /// Mirrors C calculate_distribution_stats() — main.rs:312-368.
    pub fn calculate_distribution_stats(
        queue_counts: &[u64; QUEUE_STATS_IDX.len()],
        global_queue_decisions: u64,
        scope_queue_decisions: u64,
        scope_affn_viols: u64,
        scope_steals: u64,
    ) -> DistributionStats {
        let share_of_global = if global_queue_decisions > 0 {
            100.0 * (scope_queue_decisions as f64) / (global_queue_decisions as f64)
        } else {
            0.0
        };

        let queue_pct: [f64; QUEUE_STATS_IDX.len()] = if scope_queue_decisions == 0 {
            [0.0; QUEUE_STATS_IDX.len()]
        } else {
            core::array::from_fn(|i| {
                100.0 * (queue_counts[i] as f64) / (scope_queue_decisions as f64)
            })
        };

        let affn_viol_pct = if scope_queue_decisions == 0 {
            0.0
        } else {
            100.0 * (scope_affn_viols as f64) / (scope_queue_decisions as f64)
        };

        let steal_pct = if scope_queue_decisions == 0 {
            0.0
        } else {
            100.0 * (scope_steals as f64) / (scope_queue_decisions as f64)
        };

        DistributionStats {
            total_decisions: scope_queue_decisions,
            share_of_decisions_pct: share_of_global,
            local_q_pct: queue_pct[0],
            cpu_q_pct: queue_pct[1],
            cell_q_pct: queue_pct[2],
            affn_viol_pct,
            steal_pct,
            global_queue_decisions,
        }
    }

    /// Compute per-cell stat deltas from aggregated CPU contexts.
    ///
    /// `aggregated_cell_stats` should contain the sum of each stat across
    /// all CPUs, for each cell: `aggregated_cell_stats[cell][stat]`.
    ///
    /// Mirrors C calculate_cell_stat_delta() — main.rs:487-511.
    pub fn calculate_cell_stat_delta(
        &mut self,
        aggregated_cell_stats: &[[u64; NR_CSTATS]; MAX_CELLS],
    ) -> [[u64; NR_CSTATS]; MAX_CELLS] {
        let mut delta = [[0u64; NR_CSTATS]; MAX_CELLS];
        for cell in 0..MAX_CELLS {
            for stat in 0..NR_CSTATS {
                let cur = aggregated_cell_stats[cell][stat];
                delta[cell][stat] = cur.wrapping_sub(self.prev_cell_stats[cell][stat]);
                self.prev_cell_stats[cell][stat] = cur;
            }
        }
        delta
    }

    /// Update metrics from a stats delta.
    ///
    /// Mirrors C log_all_queue_stats() + update_and_log_* — main.rs:469-486.
    pub fn update_metrics(
        &mut self,
        cell_stats_delta: &[[u64; NR_CSTATS]; MAX_CELLS],
    ) {
        // Global totals
        let global_queue_decisions: u64 = cell_stats_delta
            .iter()
            .flat_map(|cell| QUEUE_STATS_IDX.iter().map(|&idx| cell[idx]))
            .sum();

        if global_queue_decisions == 0 {
            return;
        }

        // Global distribution
        let mut global_queue_counts = [0u64; QUEUE_STATS_IDX.len()];
        for cell in cell_stats_delta {
            for (i, &idx) in QUEUE_STATS_IDX.iter().enumerate() {
                global_queue_counts[i] += cell[idx];
            }
        }
        let global_affn_viols: u64 = cell_stats_delta
            .iter()
            .map(|c| c[CSTAT_AFFN_VIOL])
            .sum();
        let global_steals: u64 = cell_stats_delta.iter().map(|c| c[CSTAT_STEAL]).sum();

        let global_stats = Self::calculate_distribution_stats(
            &global_queue_counts,
            global_queue_decisions,
            global_queue_decisions,
            global_affn_viols,
            global_steals,
        );
        self.metrics.update(&global_stats);

        // Per-cell distribution
        for cell_idx in 0..MAX_CELLS {
            let cell_decisions: u64 = QUEUE_STATS_IDX
                .iter()
                .map(|&idx| cell_stats_delta[cell_idx][idx])
                .sum();

            if cell_decisions == 0 {
                continue;
            }

            let mut cell_queue_counts = [0u64; QUEUE_STATS_IDX.len()];
            for (i, &idx) in QUEUE_STATS_IDX.iter().enumerate() {
                cell_queue_counts[i] = cell_stats_delta[cell_idx][idx];
            }

            let cell_affn = cell_stats_delta[cell_idx][CSTAT_AFFN_VIOL];
            let cell_steals = cell_stats_delta[cell_idx][CSTAT_STEAL];

            let stats = Self::calculate_distribution_stats(
                &cell_queue_counts,
                global_queue_decisions,
                cell_decisions,
                cell_affn,
                cell_steals,
            );

            self.metrics
                .cells
                .entry(cell_idx as u32)
                .or_default()
                .update(&stats);
        }
    }

    /// Format a one-line stats summary for logging.
    pub fn format_summary(&self) -> String {
        format!("{}", self.metrics)
    }

    /// Format detailed per-cell stats for logging.
    pub fn format_detailed(&self) -> String {
        let mut out = format!("Total: {}\n", self.metrics);
        for (cell_id, cell) in &self.metrics.cells {
            out.push_str(&format!(
                "  Cell {:3}: {:6} decisions {:5.1}% | Local:{:4.1}% CPU:{:4.1}% Cell:{:4.1}% | V:{:4.1}% S:{:4.1}%\n",
                cell_id,
                cell.total_decisions,
                cell.share_of_decisions_pct,
                cell.local_q_pct,
                cell.cpu_q_pct,
                cell.cell_q_pct,
                cell.affn_violations_pct,
                cell.steal_pct,
            ));
        }
        out
    }
}

// ── Debug events ────────────────────────────────────────────────────
//
// These types are the userspace API for reading the BPF debug event
// circular buffer. They'll be used when percpu map reading is wired up.

/// Debug event types matching the eBPF DebugEventType enum.
#[derive(Clone, Copy, Debug)]
#[allow(dead_code)]
pub enum DebugEventType {
    CgroupInit,
    InitTask,
    CgroupExit,
    Unknown(u32),
}

impl From<u32> for DebugEventType {
    fn from(v: u32) -> Self {
        match v {
            0 => DebugEventType::CgroupInit,
            1 => DebugEventType::InitTask,
            2 => DebugEventType::CgroupExit,
            other => DebugEventType::Unknown(other),
        }
    }
}

impl fmt::Display for DebugEventType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DebugEventType::CgroupInit => write!(f, "cgroup_init"),
            DebugEventType::InitTask => write!(f, "init_task"),
            DebugEventType::CgroupExit => write!(f, "cgroup_exit"),
            DebugEventType::Unknown(v) => write!(f, "unknown({})", v),
        }
    }
}

/// A parsed debug event from the BPF circular buffer.
#[derive(Clone, Debug)]
#[allow(dead_code)]
pub struct DebugEvent {
    pub timestamp: u64,
    pub event_type: DebugEventType,
    pub cgid: u64,
    /// Only populated for InitTask events.
    pub pid: Option<u32>,
}

impl fmt::Display for DebugEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{:>12}] {}", self.timestamp, self.event_type)?;
        write!(f, " cgid={}", self.cgid)?;
        if let Some(pid) = self.pid {
            write!(f, " pid={}", pid)?;
        }
        Ok(())
    }
}

/// Read and parse debug events from a BPF array map.
///
/// `raw_events` is the array of raw event bytes, indexed by position
/// in the circular buffer. `write_pos` is the current write position
/// (DEBUG_EVENT_POS global).
///
/// Returns events in chronological order (oldest first).
#[allow(dead_code)]
pub fn parse_debug_events(
    raw_events: &[RawDebugEvent],
    write_pos: u32,
) -> Vec<DebugEvent> {
    let buf_size = raw_events.len() as u32;
    if buf_size == 0 {
        return Vec::new();
    }

    let mut events = Vec::new();
    let count = std::cmp::min(write_pos, buf_size);
    let start = if write_pos > buf_size {
        write_pos % buf_size
    } else {
        0
    };

    for i in 0..count {
        let idx = ((start + i) % buf_size) as usize;
        let raw = &raw_events[idx];

        // Skip uninitialized entries
        if raw.timestamp == 0 && raw.event_type == 0 {
            continue;
        }

        let event_type = DebugEventType::from(raw.event_type);
        let pid = match event_type {
            DebugEventType::InitTask => Some(raw.pid),
            _ => None,
        };

        events.push(DebugEvent {
            timestamp: raw.timestamp,
            event_type,
            cgid: raw.cgid,
            pid,
        });
    }

    events
}

/// Raw debug event matching the BPF DebugEvent struct layout.
///
/// This must match the #[repr(C)] layout in the eBPF program.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
#[allow(dead_code)]
pub struct RawDebugEvent {
    pub timestamp: u64,
    pub event_type: u32,
    pub cgid: u64,
    pub pid: u32,
    pub _pad: u32,
}
