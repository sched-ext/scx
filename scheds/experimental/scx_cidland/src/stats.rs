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
    #[stat(desc = "Tasks stolen from another CPU's queue")]
    pub nr_steals: u64,

    #[stat(desc = "Queued tasks moved by periodic busy load balance")]
    pub nr_busy_balances: u64,

    #[stat(desc = "Running tasks moved to an idle core by asymmetric balance")]
    pub nr_active_balances: u64,

    #[stat(desc = "Running tasks interrupted for a woken task")]
    pub nr_preempts: u64,

    #[stat(desc = "Wakeups sent back to the CPU the task blocked on while over-served")]
    pub nr_delay_requeues: u64,

    #[stat(desc = "Running tasks asked to give the CPU up at their deadline")]
    pub nr_hrticks: u64,

    #[stat(desc = "Idle scans skipped for costing more than the CPU's idle time")]
    pub nr_newidle_skips: u64,
}

impl Metrics {
    fn format<W: Write>(&self, w: &mut W) -> Result<()> {
        writeln!(
            w,
            "[{}] steals={} busy_balances={} active_balances={} preempts={} delay_requeues={} hrticks={} newidle_skips={}",
            crate::SCHEDULER_NAME,
            self.nr_steals,
            self.nr_busy_balances,
            self.nr_active_balances,
            self.nr_preempts,
            self.nr_delay_requeues,
            self.nr_hrticks,
            self.nr_newidle_skips,
        )?;
        Ok(())
    }

    fn delta(&self, rhs: &Self) -> Self {
        Self {
            nr_steals: self.nr_steals - rhs.nr_steals,
            nr_busy_balances: self.nr_busy_balances - rhs.nr_busy_balances,
            nr_active_balances: self.nr_active_balances - rhs.nr_active_balances,
            nr_preempts: self.nr_preempts - rhs.nr_preempts,
            nr_delay_requeues: self.nr_delay_requeues - rhs.nr_delay_requeues,
            nr_hrticks: self.nr_hrticks - rhs.nr_hrticks,
            nr_newidle_skips: self.nr_newidle_skips - rhs.nr_newidle_skips,
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
