use std::io::Write;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use scx_stats::prelude::*;
use scx_stats_derive::Stats;
use serde::Deserialize;
use serde::Serialize;

#[derive(Clone, Debug, Default, Serialize, Deserialize, Stats)]
#[stat(top)]
pub struct Metrics {
    #[stat(desc = "Number of kthread direct dispatches")]
    pub nr_kthread_dispatches: u64,
    #[stat(desc = "Number of task direct dispatches")]
    pub nr_direct_dispatches: u64,
    #[stat(desc = "Number of task global dispatches")]
    pub nr_shared_dispatches: u64,
    #[stat(desc = "Number of migrated task dispatches")]
    pub nr_migrate_dispatches: u64,
}

impl Metrics {
    fn format<W: Write>(&self, w: &mut W) -> Result<()> {
        writeln!(
            w,
            "[{}] dispatch -> kthread: {:<5} direct: {:<5} shared: {:<5} migrated: {:<5}",
            crate::SCHEDULER_NAME,
            self.nr_kthread_dispatches,
            self.nr_direct_dispatches,
            self.nr_shared_dispatches,
            self.nr_migrate_dispatches
        )?;
        Ok(())
    }

    fn delta(&self, rhs: &Self) -> Self {
        Self {
            nr_kthread_dispatches: self.nr_kthread_dispatches - rhs.nr_kthread_dispatches,
            nr_direct_dispatches: self.nr_direct_dispatches - rhs.nr_direct_dispatches,
            nr_shared_dispatches: self.nr_shared_dispatches - rhs.nr_shared_dispatches,
            nr_migrate_dispatches: self.nr_migrate_dispatches - rhs.nr_migrate_dispatches,
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
        &vec![],
        intv,
        || shutdown.load(Ordering::Relaxed),
        |metrics| metrics.format(&mut std::io::stdout()),
    )
}
