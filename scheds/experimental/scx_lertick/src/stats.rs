// SPDX-License-Identifier: GPL-2.0
//
// Copyright (c) 2026 Hungyu Lin <dennylin0707@gmail.com>

// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

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
pub struct Metrics {
    #[stat(desc = "Number of tasks dispatched directly to a local DSQ on wakeup")]
    pub nr_local_dispatches: u64,
    #[stat(desc = "Number of tasks queued on the shared DSQ")]
    pub nr_shared_dispatches: u64,
    #[stat(desc = "Number of times a running task kept its CPU")]
    pub nr_continuations: u64,
    #[stat(desc = "Number of time slices set from a learned prediction")]
    pub nr_adaptive_slices: u64,
    #[stat(desc = "Number of model updates from completed CPU bursts")]
    pub nr_training_updates: u64,
}

impl Metrics {
    fn format<W: Write>(&self, w: &mut W) -> Result<()> {
        writeln!(
            w,
            "[{}] dispatch -> l: {:<6} s: {:<6} c: {:<6} | model -> slices: {:<6} updates: {:<6}",
            crate::SCHEDULER_NAME,
            self.nr_local_dispatches,
            self.nr_shared_dispatches,
            self.nr_continuations,
            self.nr_adaptive_slices,
            self.nr_training_updates
        )?;
        Ok(())
    }

    fn delta(&self, rhs: &Self) -> Self {
        Self {
            nr_local_dispatches: self.nr_local_dispatches - rhs.nr_local_dispatches,
            nr_shared_dispatches: self.nr_shared_dispatches - rhs.nr_shared_dispatches,
            nr_continuations: self.nr_continuations - rhs.nr_continuations,
            nr_adaptive_slices: self.nr_adaptive_slices - rhs.nr_adaptive_slices,
            nr_training_updates: self.nr_training_updates - rhs.nr_training_updates,
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
