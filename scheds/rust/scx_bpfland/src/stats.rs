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
    #[stat(desc = "Wakeups sent straight to an idle CPU")]
    pub nr_direct: u64,
    #[stat(desc = "Wakeups placed on borrowed virtual time")]
    pub nr_borrowed: u64,
    #[stat(desc = "Wakeups queued on another CPU to take it")]
    pub nr_moved: u64,
    #[stat(desc = "Searches for a CPU to take that found none")]
    pub nr_missed: u64,
    #[stat(desc = "Preemptions of a running task by a waking one")]
    pub nr_preempts: u64,
    #[stat(desc = "Tasks taken from another CPU's queue")]
    pub nr_steals: u64,
    #[stat(desc = "Running tasks moved by the tick to a better idle CPU")]
    pub nr_balanced: u64,
    #[stat(desc = "Tasks handed from a worse CPU to a CPU of the best tier")]
    pub nr_rotated: u64,
}

impl Metrics {
    fn format<W: Write>(&self, w: &mut W) -> Result<()> {
        writeln!(
            w,
            "[{}] direct: {:<6} borrowed: {:<6} moved: {:<6} missed: {:<6} preempts: {:<6} steals: {:<6} balanced: {:<6} rotated: {:<6}",
            crate::SCHEDULER_NAME,
            self.nr_direct,
            self.nr_borrowed,
            self.nr_moved,
            self.nr_missed,
            self.nr_preempts,
            self.nr_steals,
            self.nr_balanced,
            self.nr_rotated,
        )?;
        Ok(())
    }

    fn delta(&self, rhs: &Self) -> Self {
        Self {
            nr_direct: self.nr_direct - rhs.nr_direct,
            nr_borrowed: self.nr_borrowed - rhs.nr_borrowed,
            nr_moved: self.nr_moved - rhs.nr_moved,
            nr_missed: self.nr_missed - rhs.nr_missed,
            nr_preempts: self.nr_preempts - rhs.nr_preempts,
            nr_steals: self.nr_steals - rhs.nr_steals,
            nr_balanced: self.nr_balanced - rhs.nr_balanced,
            nr_rotated: self.nr_rotated - rhs.nr_rotated,
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
