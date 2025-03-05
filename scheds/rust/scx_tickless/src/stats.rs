// SPDX-License-Identifier: GPL-2.0
//
// Copyright (c) 2025 Andrea Righi <arighi@nvidia.com>

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
    #[stat(desc = "Number of ticks")]
    pub nr_ticks: u64,
    #[stat(desc = "Number of preemption events")]
    pub nr_preemptions: u64,
    #[stat(desc = "Number of dispatches directly consumed from the shared queue")]
    pub nr_direct_dispatches: u64,
    #[stat(desc = "Number of dispatches routed by the primary CPUs")]
    pub nr_primary_dispatches: u64,
    #[stat(desc = "Number of dispatches routed by the primary CPU timers")]
    pub nr_timer_dispatches: u64,
}

impl Metrics {
    fn format<W: Write>(&self, w: &mut W) -> Result<()> {
        writeln!(
            w,
            "[{}] ticks -> {:<5} preempts -> {:<5} dispatch -> d: {:<5} p: {:<5} t: {:<5}",
            crate::SCHEDULER_NAME,
            self.nr_ticks,
            self.nr_preemptions,
            self.nr_direct_dispatches,
            self.nr_primary_dispatches,
            self.nr_timer_dispatches
        )?;
        Ok(())
    }

    fn delta(&self, rhs: &Self) -> Self {
        Self {
            nr_ticks: self.nr_ticks - rhs.nr_ticks,
            nr_preemptions: self.nr_preemptions - rhs.nr_preemptions,
            nr_direct_dispatches: self.nr_direct_dispatches - rhs.nr_direct_dispatches,
            nr_primary_dispatches: self.nr_primary_dispatches - rhs.nr_primary_dispatches,
            nr_timer_dispatches: self.nr_timer_dispatches - rhs.nr_timer_dispatches,
            ..self.clone()
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
