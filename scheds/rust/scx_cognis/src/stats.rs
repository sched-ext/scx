// Copyright (c) scx_cognis contributors
// SPDX-License-Identifier: GPL-2.0-only
//
// Metrics and statistics for scx_cognis.

use std::io::Write;
use std::time::Duration;

use anyhow::Result;
use scx_stats::prelude::*;
use scx_stats_derive::stat_doc;
use scx_stats_derive::Stats;
use serde::Deserialize;
use serde::Serialize;

/// Top-level metrics snapshot exported via scx_stats.
#[stat_doc]
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, Stats)]
#[stat(top)]
pub struct Metrics {
    #[stat(desc = "Elapsed uptime in seconds")]
    pub elapsed_secs: u64,
    #[stat(desc = "Number of online CPUs")]
    pub nr_cpus: u64,
    #[stat(desc = "Tasks currently running")]
    pub nr_running: u64,
    #[stat(desc = "Tasks queued to the userspace compatibility fallback")]
    pub nr_queued: u64,
    #[stat(desc = "Tasks still waiting inside the userspace compatibility fallback")]
    pub nr_scheduled: u64,
    #[stat(desc = "Major page faults in the scheduler process (non-zero = swap pressure)")]
    pub nr_page_faults: u64,
    #[stat(desc = "Tasks dispatched by the userspace compatibility fallback")]
    pub nr_user_dispatches: u64,
    #[stat(desc = "Tasks dispatched directly by the BPF scheduler")]
    pub nr_kernel_dispatches: u64,
    #[stat(desc = "BPF routes that stayed on a CPU-local DSQ")]
    pub nr_local_dispatches: u64,
    #[stat(desc = "BPF routes that spilled into an LLC DSQ")]
    pub nr_llc_dispatches: u64,
    #[stat(desc = "BPF routes that spilled into a node-wide DSQ")]
    pub nr_node_dispatches: u64,
    #[stat(desc = "BPF routes that spilled into the global shared DSQ")]
    pub nr_shared_dispatches: u64,
    #[stat(desc = "Cross-LLC steals after the local LLC queue ran empty")]
    pub nr_xllc_steals: u64,
    #[stat(desc = "Cross-node steals after the local node queue ran empty")]
    pub nr_xnode_steals: u64,
    #[stat(desc = "Cancelled dispatches")]
    pub nr_cancel_dispatches: u64,
    #[stat(desc = "Dispatches bounced to another DSQ")]
    pub nr_bounce_dispatches: u64,
    #[stat(desc = "Failed dispatches")]
    pub nr_failed_dispatches: u64,
    #[stat(desc = "Scheduler congestion events")]
    pub nr_sched_congested: u64,

    // ── Scheduling policy metrics ──────────────────────────────────────────
    #[stat(desc = "Fallback events labeled Interactive")]
    pub nr_interactive: u64,
    #[stat(desc = "Fallback events labeled Compute")]
    pub nr_compute: u64,
    #[stat(desc = "Fallback events labeled I/O Wait")]
    pub nr_iowait: u64,
    #[stat(desc = "Fallback events labeled RealTime")]
    pub nr_realtime: u64,
    #[stat(
        desc = "Tasks classified as Unknown (reserved bucket; normally zero with the current heuristic)"
    )]
    pub nr_unknown: u64,
    #[stat(desc = "PIDs currently below the observability trust threshold")]
    pub nr_quarantined: u64,
    #[stat(desc = "PIDs with repeated adverse exit observations")]
    pub nr_flagged: u64,
    #[stat(desc = "Configured BPF profile slice ceiling (µs)")]
    pub base_slice_us: u64,
    #[stat(desc = "Recent EMA of fallback-assigned per-task slices (µs)")]
    pub assigned_slice_us: u64,
    #[stat(desc = "Configured BPF profile minimum slice (µs)")]
    pub slice_min_us: u64,
    #[stat(desc = "Configured BPF profile maximum slice (µs)")]
    pub slice_max_us: u64,
    #[stat(desc = "Average userspace fallback scheduling latency (µs)")]
    pub inference_us: u64,
    #[stat(desc = "Userspace fallback scheduling latency p50 (µs)")]
    pub sched_p50_us: u64,
    #[stat(desc = "Userspace fallback scheduling latency p95 (µs)")]
    pub sched_p95_us: u64,
    #[stat(desc = "Userspace fallback scheduling latency p99 (µs)")]
    pub sched_p99_us: u64,
}

impl Metrics {
    /// Derive a human-readable one-liner summarising current system health.
    /// Scenarios are checked highest-severity first so the most pressing issue
    /// always surfaces in the output.
    pub fn tldr(&self) -> &'static str {
        let cpus = self.nr_cpus.max(1);
        let load = self.nr_running as f64 / cpus as f64;
        let classified = self.nr_interactive + self.nr_compute + self.nr_iowait + self.nr_realtime;
        let compute_heavy = classified > 0 && self.nr_compute > classified / 2;
        let interactive_heavy = classified > 0 && self.nr_interactive > classified / 2;

        if self.nr_page_faults > 0 {
            return "Scheduler hit major page faults; check memory pressure.";
        }
        if self.nr_failed_dispatches > 0 {
            return "Dispatch failures detected; inspect dmesg.";
        }
        if self.nr_queued > 0 || self.nr_scheduled > 0 {
            return "Userspace fallback is active; BPF fast path is not covering this load.";
        }
        if self.nr_sched_congested > 0 {
            return "Compatibility fallback is congested; BPF-side dispatch needs attention.";
        }
        if self.nr_flagged > 0 || self.nr_quarantined > 0 {
            return "Observability watchlist has active PIDs; review repeated adverse exits.";
        }
        if load >= 0.90
            && self.nr_shared_dispatches
                > self
                    .nr_llc_dispatches
                    .saturating_add(self.nr_node_dispatches)
                    .saturating_mul(2)
            && self.nr_shared_dispatches > 0
        {
            return "System saturated; shared spill dominates, check LLC and node balance.";
        }
        if load >= 0.90 && self.nr_kernel_dispatches > 0 {
            return "System saturated; BPF local/LLC/node/shared hierarchy is carrying the load.";
        }
        if load >= 0.85 && compute_heavy {
            return "Heavy compute load detected; watch fallback activity and tail latency.";
        }
        if load >= 0.85 && interactive_heavy {
            return "Interactive-heavy load is running hot; check frame pacing and wake behavior.";
        }
        if load >= 0.85 {
            return "Heavy mixed load; BPF fast path is still the primary scheduler.";
        }
        if load >= 0.65 {
            return "Moderate load; locality and LLC spill behavior look nominal.";
        }
        if interactive_heavy && load < 0.5 {
            return "Mostly interactive load; BPF wakeup path is staying responsive.";
        }
        if compute_heavy && load < 0.65 {
            return "Compute work is present without saturation.";
        }
        if load < 0.1 {
            return "System mostly idle.";
        }
        if load < 0.5 {
            return "Balanced light load; BPF fast path is in control.";
        }
        "Scheduler healthy."
    }

    pub fn format<W: Write>(&self, w: &mut W) -> Result<()> {
        let days_total = self.elapsed_secs / 86_400;
        let years = days_total / 365;
        let days_after_years = days_total % 365;
        let months = days_after_years / 30;
        let days = days_after_years % 30;
        let hours = (self.elapsed_secs % 86_400) / 3600;
        let minutes = (self.elapsed_secs % 3600) / 60;
        let seconds = self.elapsed_secs % 60;

        writeln!(
            w,
            "[cognis v{}] elapsed: {}y{}m{}d {:02}h:{:02}m:{:02}s | tldr: {:<55} | r:{:>3}/{:<3} q:{:<3}/{:<3} | pf:{:<4} | d→u:{:<6} k:{:<4} c:{:<4} b:{:<4} f:{:<4} sched:{:<5}/{:<5}/{:<5} | cong:{:<4} |",
            env!("CARGO_PKG_VERSION"),
            years,
            months,
            days,
            hours,
            minutes,
            seconds,
            self.tldr(),
            self.nr_running,
            self.nr_cpus,
            self.nr_queued,
            self.nr_scheduled,
            self.nr_page_faults,
            self.nr_user_dispatches,
            self.nr_kernel_dispatches,
            self.nr_cancel_dispatches,
            self.nr_bounce_dispatches,
            self.nr_failed_dispatches,
            self.sched_p50_us,
            self.sched_p95_us,
            self.sched_p99_us,
            self.nr_sched_congested,
        )?;

        writeln!(
            w,
            "             route(local/llc/node/shared/xllc/xnode): {}/{}/{}/{}/{}/{} | slice(base/assigned):{}/{}µs",
            self.nr_local_dispatches,
            self.nr_llc_dispatches,
            self.nr_node_dispatches,
            self.nr_shared_dispatches,
            self.nr_xllc_steals,
            self.nr_xnode_steals,
            self.base_slice_us,
            self.assigned_slice_us,
        )?;

        writeln!(
            w,
            "             fallback labels(I/C/IO/RT/U): {}/{}/{}/{}/{} | watchlist:{}/{}",
            self.nr_interactive,
            self.nr_compute,
            self.nr_iowait,
            self.nr_realtime,
            self.nr_unknown,
            self.nr_quarantined,
            self.nr_flagged,
        )?;
        Ok(())
    }

    pub fn delta(&self, rhs: &Self) -> Self {
        Self {
            // Dispatch counters — per-interval deltas.
            nr_user_dispatches: self
                .nr_user_dispatches
                .saturating_sub(rhs.nr_user_dispatches),
            nr_kernel_dispatches: self
                .nr_kernel_dispatches
                .saturating_sub(rhs.nr_kernel_dispatches),
            nr_local_dispatches: self
                .nr_local_dispatches
                .saturating_sub(rhs.nr_local_dispatches),
            nr_llc_dispatches: self.nr_llc_dispatches.saturating_sub(rhs.nr_llc_dispatches),
            nr_node_dispatches: self
                .nr_node_dispatches
                .saturating_sub(rhs.nr_node_dispatches),
            nr_shared_dispatches: self
                .nr_shared_dispatches
                .saturating_sub(rhs.nr_shared_dispatches),
            nr_xllc_steals: self.nr_xllc_steals.saturating_sub(rhs.nr_xllc_steals),
            nr_xnode_steals: self.nr_xnode_steals.saturating_sub(rhs.nr_xnode_steals),
            nr_cancel_dispatches: self
                .nr_cancel_dispatches
                .saturating_sub(rhs.nr_cancel_dispatches),
            nr_bounce_dispatches: self
                .nr_bounce_dispatches
                .saturating_sub(rhs.nr_bounce_dispatches),
            nr_failed_dispatches: self
                .nr_failed_dispatches
                .saturating_sub(rhs.nr_failed_dispatches),
            nr_sched_congested: self
                .nr_sched_congested
                .saturating_sub(rhs.nr_sched_congested),
            // Major page faults — per-interval delta so --monitor shows faults/sec.
            // (nr_page_faults is already baseline-subtracted in get_metrics(), but
            // delta() must subtract again so each --monitor line shows only the faults
            // that occurred during *that* interval, not the lifetime total.)
            nr_page_faults: self.nr_page_faults.saturating_sub(rhs.nr_page_faults),
            // Classification counters — per-interval deltas so --monitor shows
            // events-per-interval instead of ever-growing cumulative totals.
            nr_interactive: self.nr_interactive.saturating_sub(rhs.nr_interactive),
            nr_compute: self.nr_compute.saturating_sub(rhs.nr_compute),
            nr_iowait: self.nr_iowait.saturating_sub(rhs.nr_iowait),
            nr_realtime: self.nr_realtime.saturating_sub(rhs.nr_realtime),
            nr_unknown: self.nr_unknown.saturating_sub(rhs.nr_unknown),
            ..*self
        }
    }
}

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

pub fn monitor(intv: Duration) -> Result<()> {
    scx_utils::monitor_stats::<Metrics>(
        &[],
        intv,
        || false,
        |metrics| metrics.format(&mut std::io::stdout()),
    )
}
