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
    #[stat(desc = "Direct dispatch due to high perf events (migration)")]
    pub nr_event_dispatches: u64,
    #[stat(desc = "Kept on same CPU due to perf sticky threshold")]
    pub nr_ev_sticky_dispatches: u64,
    #[stat(desc = "Direct dispatch due to GPU affinity")]
    pub nr_gpu_dispatches: u64,
}

impl Metrics {
    fn format<W: Write>(&self, w: &mut W) -> Result<()> {
        writeln!(
            w,
            "[{}] ev_dispatches={} ev_sticky_dispatches={} gpu_dispatches={}",
            crate::SCHEDULER_NAME,
            self.nr_event_dispatches,
            self.nr_ev_sticky_dispatches,
            self.nr_gpu_dispatches,
        )?;
        Ok(())
    }

    fn delta(&self, rhs: &Self) -> Self {
        Self {
            nr_event_dispatches: self.nr_event_dispatches - rhs.nr_event_dispatches,
            nr_ev_sticky_dispatches: self.nr_ev_sticky_dispatches - rhs.nr_ev_sticky_dispatches,
            nr_gpu_dispatches: self.nr_gpu_dispatches - rhs.nr_gpu_dispatches,
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
