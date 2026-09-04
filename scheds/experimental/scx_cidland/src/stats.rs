// SPDX-License-Identifier: GPL-2.0
//
// Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.
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
    #[stat(desc = "Number of tasks dispatched directly to an idle cid")]
    pub nr_direct_dispatches: u64,
    #[stat(desc = "Number of tasks queued to the shared FIFO")]
    pub nr_shared_enqueues: u64,
    #[stat(desc = "Number of idle cids kicked to consume the shared FIFO")]
    pub nr_idle_kicks: u64,
    #[stat(desc = "Number of idle cids picked in the previous LLC")]
    pub nr_local_llc: u64,
    #[stat(desc = "Number of idle cids picked outside of the previous LLC")]
    pub nr_remote_llc: u64,
}

impl Metrics {
    fn format<W: Write>(&self, w: &mut W) -> Result<()> {
        writeln!(
            w,
            "[{}] dispatch -> direct: {:<7} shared: {:<7} kicks: {:<7} | idle cid -> local llc: {:<7} remote llc: {:<7}",
            crate::SCHEDULER_NAME,
            self.nr_direct_dispatches,
            self.nr_shared_enqueues,
            self.nr_idle_kicks,
            self.nr_local_llc,
            self.nr_remote_llc,
        )?;
        Ok(())
    }

    fn delta(&self, rhs: &Self) -> Self {
        Self {
            nr_direct_dispatches: self.nr_direct_dispatches - rhs.nr_direct_dispatches,
            nr_shared_enqueues: self.nr_shared_enqueues - rhs.nr_shared_enqueues,
            nr_idle_kicks: self.nr_idle_kicks - rhs.nr_idle_kicks,
            nr_local_llc: self.nr_local_llc - rhs.nr_local_llc,
            nr_remote_llc: self.nr_remote_llc - rhs.nr_remote_llc,
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
