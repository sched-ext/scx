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
    #[stat(desc = "Tasks dispatched from the reserved DSQ")]
    pub reserved_dispatches: u64,
    #[stat(desc = "Tasks dispatched from the shared DSQ")]
    pub shared_dispatches: u64,
    #[stat(desc = "Wakeups that refilled task budget")]
    pub budget_refill_events: u64,
    #[stat(desc = "Times a task ran its budget down to zero or below")]
    pub budget_exhaustions: u64,
    #[stat(desc = "Runnable wakeups observed before enqueue/select_cpu decisions")]
    pub runnable_wakeups: u64,
    #[stat(desc = "Local DSQ tasks rescued during cpu_release")]
    pub cpu_release_reenqueues: u64,
    #[stat(desc = "Tasks initialized through init_task task storage setup")]
    pub init_task_events: u64,
    #[stat(desc = "Tasks explicitly initialized on entry into scx_flow")]
    pub enable_events: u64,
    #[stat(desc = "Tasks explicitly cleaned up on exit from scx_flow")]
    pub exit_task_events: u64,
    #[stat(desc = "Observed task migrations between successive runs")]
    pub cpu_migrations: u64,
    #[stat(desc = "Adaptive tuning generation counter")]
    pub autotune_generation: u64,
    #[stat(desc = "Adaptive tuning mode (0=balanced, 1=latency, 2=throughput)")]
    pub autotune_mode: u64,
    #[stat(desc = "Current reserved slice cap in ns")]
    pub tune_reserved_max_ns: u64,
    #[stat(desc = "Current shared slice in ns")]
    pub tune_shared_slice_ns: u64,
    #[stat(desc = "Current interactive wake refill floor in ns")]
    pub tune_interactive_floor_ns: u64,
}

impl Metrics {
    fn autotune_mode_name(&self) -> &'static str {
        match self.autotune_mode {
            1 => "latency",
            2 => "throughput",
            _ => "balanced",
        }
    }

    fn format<W: Write>(&self, w: &mut W) -> Result<()> {
        writeln!(
            w,
            "[{}] mode={} gen={} run={} reserve_disp={} shared_disp={} refill={} exhaust={} runnable={} cpu_release={} init_task={} enable={} exit_task={} migrations={} reserve_cap_us={} shared_slice_us={} refill_floor_us={}",
            crate::SCHEDULER_NAME,
            self.autotune_mode_name(),
            self.autotune_generation,
            self.nr_running,
            self.reserved_dispatches,
            self.shared_dispatches,
            self.budget_refill_events,
            self.budget_exhaustions,
            self.runnable_wakeups,
            self.cpu_release_reenqueues,
            self.init_task_events,
            self.enable_events,
            self.exit_task_events,
            self.cpu_migrations,
            self.tune_reserved_max_ns / 1000,
            self.tune_shared_slice_ns / 1000,
            self.tune_interactive_floor_ns / 1000,
        )?;
        Ok(())
    }

    pub fn delta(&self, rhs: &Self) -> Self {
        Self {
            nr_running: self.nr_running,
            total_runtime: self.total_runtime.wrapping_sub(rhs.total_runtime),
            reserved_dispatches: self
                .reserved_dispatches
                .wrapping_sub(rhs.reserved_dispatches),
            shared_dispatches: self.shared_dispatches.wrapping_sub(rhs.shared_dispatches),
            budget_refill_events: self
                .budget_refill_events
                .wrapping_sub(rhs.budget_refill_events),
            budget_exhaustions: self.budget_exhaustions.wrapping_sub(rhs.budget_exhaustions),
            runnable_wakeups: self.runnable_wakeups.wrapping_sub(rhs.runnable_wakeups),
            cpu_release_reenqueues: self
                .cpu_release_reenqueues
                .wrapping_sub(rhs.cpu_release_reenqueues),
            init_task_events: self.init_task_events.wrapping_sub(rhs.init_task_events),
            enable_events: self.enable_events.wrapping_sub(rhs.enable_events),
            exit_task_events: self.exit_task_events.wrapping_sub(rhs.exit_task_events),
            cpu_migrations: self.cpu_migrations.wrapping_sub(rhs.cpu_migrations),
            autotune_generation: self.autotune_generation,
            autotune_mode: self.autotune_mode,
            tune_reserved_max_ns: self.tune_reserved_max_ns,
            tune_shared_slice_ns: self.tune_shared_slice_ns,
            tune_interactive_floor_ns: self.tune_interactive_floor_ns,
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
