// SPDX-License-Identifier: GPL-2.0
//! Stats server for the flow scheduler.
//!
//! Copyright (c) 2026 Galih Tama <galpt@v.recipes>

//! Exports the counters view plus the dashboard view from the BPF maps.
//! The stats server carries deltas while the dashboard carries raw
//! counters plus per CPU cards for the loopback page.

use std::io::Write;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::time::Duration;

use anyhow::Result;
use scx_stats::prelude::*;
use scx_stats_derive::Stats;
use scx_stats_derive::stat_doc;
use serde::Deserialize;
use serde::Serialize;

#[stat_doc]
#[derive(Clone, Debug, Default, Serialize, Deserialize, Stats)]
#[stat(top)]
/// Counters with placement, admission, and miss detail.
/// BPF holds 15 counters, Rust adds display-only uptime for 16.
pub struct Metrics {
    #[stat(desc = "Tasks now on a CPU")]
    #[serde(default)]
    pub on_cpu: u64,
    #[stat(desc = "Total runtime in nanoseconds")]
    #[serde(default)]
    pub total_runtime: u64,
    /// Display-only uptime since attach in nanos with no BPF use.
    /// Filled from the start instant, never from the BPF counters.
    #[stat(desc = "Uptime since attach in nanoseconds")]
    #[serde(default)]
    pub uptime_ns: u64,
    #[stat(desc = "Fresh deadline joins")]
    #[serde(default)]
    pub inserts: u64,
    #[stat(desc = "Runnable slice ends with requeue")]
    #[serde(default)]
    pub requeues: u64,
    #[stat(desc = "Blocks and exits with release")]
    #[serde(default)]
    pub completions: u64,
    #[stat(desc = "Moves from the local tier")]
    #[serde(default)]
    pub local_moves: u64,
    #[stat(desc = "Moves from the node tier")]
    #[serde(default)]
    pub node_moves: u64,
    #[stat(desc = "Moves from the machine tier")]
    #[serde(default)]
    pub machine_moves: u64,
    #[stat(desc = "Moves from the overflow tail")]
    #[serde(default)]
    pub over_moves: u64,
    #[stat(desc = "Idle wakeup kicks sent after insert")]
    #[serde(default)]
    pub kicks: u64,
    #[stat(desc = "Tasks admitted under the use bound")]
    #[serde(default)]
    pub admits: u64,
    #[stat(desc = "Tasks parked on admission reject")]
    #[serde(default)]
    pub rejects: u64,
    #[stat(desc = "Wall completions past release plus deadline")]
    #[serde(default)]
    pub misses: u64,
    #[stat(desc = "Overflow parks from misses plus rejects")]
    #[serde(default)]
    pub parks: u64,
    #[stat(desc = "Closed gate rejects on stale CPUs plus tasks")]
    #[serde(default)]
    pub gate_rejects: u64,
}

/// One card of the per CPU grid.
/// Id plus SMT stay fixed while pid plus slice refresh on each poll.
/// Pid holds zero when idle and slice holds the shared quantum.
/// SMT marks the second thread of one core for display only with
/// no placement use and false on old JSON.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct PerCpuMetrics {
    /// CPU id.
    #[serde(default)]
    pub id: u32,
    /// True for the second thread of one core with false on single thread.
    /// Display only with no placement use plus false on old JSON.
    #[serde(default)]
    pub smt: bool,
    /// Pid now on the CPU with zero when idle.
    #[serde(default)]
    pub running_pid: u32,
    /// Fixed slice in nanos with the shared quantum.
    #[serde(default)]
    pub slice_ns: u64,
}

/// Snapshot for the web dashboard.
/// Counters stay raw with the on CPU gauge plus the live pid view.
/// The run loop pushes one per poll and the web thread keeps the
/// newest behind a lock for the page plus the JSON routes.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct WebMetrics {
    /// Scheduler wide counters with raw values.
    pub stats: Metrics,
    /// One entry per online CPU in rank order.
    #[serde(default)]
    pub per_cpu: Vec<PerCpuMetrics>,
    /// Scheduler version for the page plus the log.
    #[serde(default)]
    pub version: String,
    /// Wall time in nanos since epoch for the log.
    #[serde(default)]
    pub timestamp_ns: u64,
    /// One line topology summary for the page.
    #[serde(default)]
    pub topology: String,
}

/// Stats printer loop for the monitor flag.
/// Polls the stats server on the interval with plain text lines.
pub fn monitor(intv: Duration, shutdown: Arc<AtomicBool>) -> Result<()> {
    scx_utils::monitor_stats::<Metrics>(
        &[],
        intv,
        || shutdown.load(Ordering::Relaxed),
        |metrics| metrics.format(&mut std::io::stdout()),
    )
}

/// Server data for the stats server.
/// A single top op reports interval deltas of the counters.
pub fn server_data() -> StatsServerData<(), Metrics> {
    let open: Box<dyn StatsOpener<(), Metrics>> = Box::new(move |(req_ch, res_ch)| {
        req_ch.send(())?;
        let mut prev = res_ch.recv()?;
        let read: Box<dyn StatsReader<(), Metrics>> = Box::new(move |_args, (req_ch, res_ch)| {
            req_ch.send(())?;
            let cur = res_ch.recv()?;
            let delta = cur.delta(&prev);
            prev = cur;
            delta.to_json()
        });
        Ok(read)
    });
    StatsServerData::new()
        .add_meta(Metrics::meta())
        .add_ops("top", StatsOps { open, close: None })
}

impl Metrics {
    fn format<W: Write>(&self, w: &mut W) -> Result<()> {
        writeln!(
            w,
            "[{}] run={} runtime_ns={} uptime_ns={} ins={} req={} done={} \
             local={} node={} machine={} over={} kick={} adm={} rej={} \
             miss={} park={} gate={}",
            crate::SCHEDULER_NAME,
            self.on_cpu,
            self.total_runtime,
            self.uptime_ns,
            self.inserts,
            self.requeues,
            self.completions,
            self.local_moves,
            self.node_moves,
            self.machine_moves,
            self.over_moves,
            self.kicks,
            self.admits,
            self.rejects,
            self.misses,
            self.parks,
            self.gate_rejects,
        )?;
        Ok(())
    }

    /// Interval delta of the counters over the poll interval.
    /// Gauges like on_cpu plus uptime_ns pass through as live values.
    pub fn delta(&self, rhs: &Self) -> Self {
        Self {
            on_cpu: self.on_cpu,
            total_runtime: self.total_runtime.wrapping_sub(rhs.total_runtime),
            uptime_ns: self.uptime_ns,
            inserts: self.inserts.wrapping_sub(rhs.inserts),
            requeues: self.requeues.wrapping_sub(rhs.requeues),
            completions: self.completions.wrapping_sub(rhs.completions),
            local_moves: self.local_moves.wrapping_sub(rhs.local_moves),
            node_moves: self.node_moves.wrapping_sub(rhs.node_moves),
            machine_moves: self.machine_moves.wrapping_sub(rhs.machine_moves),
            over_moves: self.over_moves.wrapping_sub(rhs.over_moves),
            kicks: self.kicks.wrapping_sub(rhs.kicks),
            admits: self.admits.wrapping_sub(rhs.admits),
            rejects: self.rejects.wrapping_sub(rhs.rejects),
            misses: self.misses.wrapping_sub(rhs.misses),
            parks: self.parks.wrapping_sub(rhs.parks),
            gate_rejects: self.gate_rejects.wrapping_sub(rhs.gate_rejects),
        }
    }
}
