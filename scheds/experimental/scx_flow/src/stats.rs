// SPDX-License-Identifier: GPL-2.0
//
// Copyright (c) 2026 Galih Tama <galpt@v.recipes>

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

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct PerCpuMetrics {
    pub id: u32,
    pub freq_khz: u64,
    pub llc_id: u32,
    pub smt: bool,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct WebMetrics {
    pub stats: Metrics,
    pub per_cpu: Vec<PerCpuMetrics>,
    pub carriage_filling_count: u64,
}

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
    #[stat(desc = "Tasks dispatched via the wakeup fast path")]
    pub prio_dispatches: u64,
    #[stat(desc = "Tasks dispatched from the per-CPU pinned DSQ")]
    pub pinned_dispatches: u64,

    #[stat(desc = "Carriage pool slot index")]
    pub carriage_producer: u64,

    #[stat(desc = "Times a task ran its budget down to zero or below")]
    pub budget_exhaustions: u64,
    #[stat(desc = "Runnable wakeups observed")]
    pub runnable_wakeups: u64,
    #[stat(desc = "Observed task migrations")]
    pub cpu_migrations: u64,
}

impl Metrics {
    fn format<W: Write>(&self, w: &mut W) -> Result<()> {
        writeln!(
            w,
            "[{}] run={} runtime_ns={} uptime_ns={} quick_disp={} pinned_disp={} \
             pool: slot={} \
              exhaust={} runnable={} migrations={}",
            crate::SCHEDULER_NAME,
            self.on_cpu,
            self.total_runtime,
            self.uptime_ns,
            self.prio_dispatches,
            self.pinned_dispatches,
             self.carriage_producer & 63,
             self.budget_exhaustions,
            self.runnable_wakeups,
            self.cpu_migrations,
        )?;
        Ok(())
    }

    pub fn delta(&self, rhs: &Self) -> Self {
        Self {
            on_cpu: self.on_cpu,
            total_runtime: self.total_runtime.wrapping_sub(rhs.total_runtime),
            uptime_ns: self.uptime_ns,
            prio_dispatches: self.prio_dispatches.wrapping_sub(rhs.prio_dispatches),
            pinned_dispatches: self.pinned_dispatches.wrapping_sub(rhs.pinned_dispatches),
            carriage_producer: self.carriage_producer.wrapping_sub(rhs.carriage_producer),

            budget_exhaustions: self.budget_exhaustions.wrapping_sub(rhs.budget_exhaustions),
            runnable_wakeups: self.runnable_wakeups.wrapping_sub(rhs.runnable_wakeups),
            cpu_migrations: self.cpu_migrations.wrapping_sub(rhs.cpu_migrations),
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

pub fn monitor(intv: Duration, shutdown: Arc<AtomicBool>) -> Result<()> {
    scx_utils::monitor_stats::<Metrics>(
        &[],
        intv,
        || shutdown.load(Ordering::Relaxed),
        |metrics| metrics.format(&mut std::io::stdout()),
    )
}
