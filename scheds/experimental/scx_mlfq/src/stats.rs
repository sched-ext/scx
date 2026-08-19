// SPDX-License-Identifier: GPL-2.0
//
// Copyright (c) 2026 Galih Tama <galpt@v.recipes>
//
// This software may be used and distributed according to the terms of the GNU
// General Public License version 2.

//! Stats server, `#[derive(Stats)]` metrics and monitor loop.
//!
//! `Metrics` corresponds to the BPF-side `struct mlfq_stats`: the type is
//! defined in `src/bpf/intf.h` and the `volatile` instance lives in
//! `src/bpf/main.bpf.c`, plus a userspace uptime gauge. Field names match
//! the BPF struct 1:1; the `top` stats op reports deltas over the poll
//! interval.

use std::io::Write;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use scx_stats::prelude::*;
use scx_stats_derive::stat_doc;
use scx_stats_derive::Stats;
use serde::Deserialize;
use serde::Serialize;

#[stat_doc]
#[derive(Clone, Debug, Default, Serialize, Deserialize, Stats)]
#[stat(top)]
pub struct Metrics {
    #[stat(desc = "Tasks currently executing on a CPU")]
    pub on_cpu: u64,
    #[stat(desc = "Total CPU runtime in ns")]
    pub total_runtime: u64,
    #[stat(desc = "Scheduler uptime (wall clock since attach)")]
    pub uptime_ns: u64,
    #[stat(desc = "Tasks placed in Q1")]
    pub q1_placements: u64,
    #[stat(desc = "Tasks placed in Q2")]
    pub q2_placements: u64,
    #[stat(desc = "Tasks placed in Q3")]
    pub q3_placements: u64,
    #[stat(desc = "Queue promotions")]
    pub promotions: u64,
    #[stat(desc = "Queue demotions")]
    pub demotions: u64,
    #[stat(desc = "Aging boosts to Q1")]
    pub aging_boosts: u64,
    #[stat(desc = "Short-sleep and I/O wakeup boosts")]
    pub short_sleep_boosts: u64,
    #[stat(desc = "Wakeup preemption kicks")]
    pub preemption_kicks: u64,
    #[stat(desc = "Q1 cpuperf target boosts set on running")]
    pub cpuperf_boosts: u64,
    #[stat(desc = "Dispatch moves from remote queue DSQs")]
    pub steals: u64,
    #[stat(desc = "Solo-task keep-running grants on empty dispatch")]
    pub keep_running: u64,
    #[stat(desc = "Enqueues dropped when task state cannot be allocated")]
    pub enq_no_tctx: u64,
    #[stat(desc = "Enqueues dropped for bad weight")]
    pub enq_bad_weight: u64,
    #[stat(desc = "Enqueues dropped for missing placement")]
    pub enq_no_deadline: u64,
    #[stat(desc = "Fast-path enqueues")]
    pub enq_fastpath: u64,
    #[stat(desc = "Regular-path enqueues")]
    pub enq_regular: u64,
    #[stat(desc = "Pinned enqueues to idle CPUs")]
    pub enq_pinned_idle: u64,
    #[stat(desc = "Pinned enqueues to busy CPUs")]
    pub enq_pinned_busy: u64,
    #[stat(desc = "Pinned enqueues to the global DSQ")]
    pub enq_pinned_global: u64,
}

impl Metrics {
    fn format<W: Write>(&self, w: &mut W) -> Result<()> {
        writeln!(
            w,
            "[{}] run={} runtime_ns={} uptime_ns={} \
             placements: Q1={} Q2={} Q3={} \
             promotions={} demotions={} aging_boosts={} short_sleep_boosts={} \
             preemption_kicks={} cpuperf_boosts={}",
            crate::SCHEDULER_NAME,
            self.on_cpu,
            self.total_runtime,
            self.uptime_ns,
            self.q1_placements,
            self.q2_placements,
            self.q3_placements,
            self.promotions,
            self.demotions,
            self.aging_boosts,
            self.short_sleep_boosts,
            self.preemption_kicks,
            self.cpuperf_boosts,
        )?;
        Ok(())
    }

    /// Interval delta: counters are wrapping deltas over the poll interval;
    /// gauges (`on_cpu`, `uptime_ns`) pass through as instantaneous values.
    pub fn delta(&self, rhs: &Self) -> Self {
        Self {
            on_cpu: self.on_cpu,
            total_runtime: self.total_runtime.wrapping_sub(rhs.total_runtime),
            uptime_ns: self.uptime_ns,
            q1_placements: self.q1_placements.wrapping_sub(rhs.q1_placements),
            q2_placements: self.q2_placements.wrapping_sub(rhs.q2_placements),
            q3_placements: self.q3_placements.wrapping_sub(rhs.q3_placements),
            promotions: self.promotions.wrapping_sub(rhs.promotions),
            demotions: self.demotions.wrapping_sub(rhs.demotions),
            aging_boosts: self.aging_boosts.wrapping_sub(rhs.aging_boosts),
            short_sleep_boosts: self.short_sleep_boosts.wrapping_sub(rhs.short_sleep_boosts),
            preemption_kicks: self.preemption_kicks.wrapping_sub(rhs.preemption_kicks),
            cpuperf_boosts: self.cpuperf_boosts.wrapping_sub(rhs.cpuperf_boosts),
            steals: self.steals.wrapping_sub(rhs.steals),
            keep_running: self.keep_running.wrapping_sub(rhs.keep_running),
            enq_no_tctx: self.enq_no_tctx.wrapping_sub(rhs.enq_no_tctx),
            enq_bad_weight: self.enq_bad_weight.wrapping_sub(rhs.enq_bad_weight),
            enq_no_deadline: self.enq_no_deadline.wrapping_sub(rhs.enq_no_deadline),
            enq_fastpath: self.enq_fastpath.wrapping_sub(rhs.enq_fastpath),
            enq_regular: self.enq_regular.wrapping_sub(rhs.enq_regular),
            enq_pinned_idle: self.enq_pinned_idle.wrapping_sub(rhs.enq_pinned_idle),
            enq_pinned_busy: self.enq_pinned_busy.wrapping_sub(rhs.enq_pinned_busy),
            enq_pinned_global: self.enq_pinned_global.wrapping_sub(rhs.enq_pinned_global),
        }
    }
}

/// Stats server definition: a single `top` op reporting interval deltas.
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

/// Monitor loop: periodically poll the stats server and print a one-line
/// summary. Runs in its own thread (see `main.rs`); exits on shutdown.
pub fn monitor(intv: Duration, shutdown: Arc<AtomicBool>) -> Result<()> {
    scx_utils::monitor_stats::<Metrics>(
        &[],
        intv,
        || shutdown.load(Ordering::Relaxed),
        |metrics| metrics.format(&mut std::io::stdout()),
    )
}
