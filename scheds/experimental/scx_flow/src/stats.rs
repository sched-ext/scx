// Copyright (c) 2026 Galih Tama <galpt@v.recipes>
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

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
    #[stat(desc = "Number of running tasks")]
    pub nr_running: u64,
    #[stat(desc = "Total CPU runtime in ns")]
    pub total_runtime: u64,
    pub uptime_ns: u64,
    #[stat(desc = "Tasks enqueued via the wakeup fast path (FLOW_DSQ_LOCAL_ON)")]
    pub prio_dispatches: u64,
    #[stat(desc = "Tasks dispatched from the per-CPU pinned DSQ (non-migratable tasks)")]
    pub pinned_dispatches: u64,
    #[stat(desc = "Tasks dispatched from the PRIORITY tier (budget >= 11 ms)")]
    pub tier_priority_dispatches: u64,
    #[stat(desc = "Tasks dispatched from the NORMAL tier (3 ms <= budget < 11 ms)")]
    pub tier_normal_dispatches: u64,
    #[stat(desc = "Tasks dispatched from the LOW tier (1 ms <= budget < 3 ms)")]
    pub tier_low_dispatches: u64,
    #[stat(desc = "Tasks dispatched from the DEFICIT tier (budget < 1 ms)")]
    pub tier_deficit_dispatches: u64,
    #[stat(desc = "Wakeups that refilled task budget")]
    pub budget_refill_events: u64,
    #[stat(desc = "Times a task ran its budget down to zero or below")]
    pub budget_exhaustions: u64,
    #[stat(desc = "Runnable wakeups observed before enqueue/select_cpu decisions")]
    pub runnable_wakeups: u64,
    #[stat(desc = "Observed task migrations between successive runs")]
    pub cpu_migrations: u64,
}

impl Metrics {
    fn format<W: Write>(&self, w: &mut W) -> Result<()> {
        writeln!(
            w,
            "[{}] run={} runtime_ns={} uptime_ns={} quick_disp={} pinned_disp={} tier_P={} tier_N={} tier_L={} tier_D={} refill={} exhaust={} runnable={} migrations={}",
            crate::SCHEDULER_NAME,
            self.nr_running,
            self.total_runtime,
            self.uptime_ns,
            self.prio_dispatches,
            self.pinned_dispatches,
            self.tier_priority_dispatches,
            self.tier_normal_dispatches,
            self.tier_low_dispatches,
            self.tier_deficit_dispatches,
            self.budget_refill_events,
            self.budget_exhaustions,
            self.runnable_wakeups,
            self.cpu_migrations,
        )?;
        Ok(())
    }

    pub fn delta(&self, rhs: &Self) -> Self {
        Self {
            nr_running: self.nr_running,
            total_runtime: self.total_runtime.wrapping_sub(rhs.total_runtime),
            uptime_ns: self.uptime_ns.wrapping_sub(rhs.uptime_ns),
            prio_dispatches: self.prio_dispatches.wrapping_sub(rhs.prio_dispatches),
            pinned_dispatches: self.pinned_dispatches.wrapping_sub(rhs.pinned_dispatches),
            tier_priority_dispatches: self
                .tier_priority_dispatches
                .wrapping_sub(rhs.tier_priority_dispatches),
            tier_normal_dispatches: self
                .tier_normal_dispatches
                .wrapping_sub(rhs.tier_normal_dispatches),
            tier_low_dispatches: self
                .tier_low_dispatches
                .wrapping_sub(rhs.tier_low_dispatches),
            tier_deficit_dispatches: self
                .tier_deficit_dispatches
                .wrapping_sub(rhs.tier_deficit_dispatches),
            budget_refill_events: self
                .budget_refill_events
                .wrapping_sub(rhs.budget_refill_events),
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
