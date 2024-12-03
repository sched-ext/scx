use std::io::Write;
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
    #[stat(desc = "Number of online CPUs")]
    pub nr_cpus: u64,
    #[stat(desc = "Amount of tasks currently running")]
    pub nr_running: u64,
    #[stat(desc = "Amount of tasks queued to the user-space scheduler")]
    pub nr_queued: u64,
    #[stat(desc = "Amount of tasks in the user-space scheduler waiting to be dispatched")]
    pub nr_scheduled: u64,
    #[stat(desc = "Amount of user-space scheduler's page faults (should be always 0)")]
    pub nr_page_faults: u64,
    #[stat(desc = "Number of task dispatched by the user-space scheduler")]
    pub nr_user_dispatches: u64,
    #[stat(desc = "Number of task dispatched directly by the kernel")]
    pub nr_kernel_dispatches: u64,
    #[stat(desc = "Number of cancelled dispatches")]
    pub nr_cancel_dispatches: u64,
    #[stat(desc = "Number of dispatches bounced to another DSQ")]
    pub nr_bounce_dispatches: u64,
    #[stat(desc = "Number of failed dispatches")]
    pub nr_failed_dispatches: u64,
    #[stat(desc = "Number of scheduler congestion events")]
    pub nr_sched_congested: u64,
}

impl Metrics {
    fn format<W: Write>(&self, w: &mut W) -> Result<()> {
        writeln!(
            w,
            "[{}] tasks -> r: {:>2}/{:<2} w: {:<2}/{:<2} | pf: {:<5} | dispatch -> u: {:<5} k: {:<5} c: {:<5} b: {:<5} f: {:<5} | cg: {:<5}",
            crate::SCHEDULER_NAME,
            self.nr_running,
            self.nr_cpus,
            self.nr_queued,
            self.nr_scheduled,
            self.nr_page_faults,
            self.nr_user_dispatches,
            self.nr_kernel_dispatches,
            self.nr_cancel_dispatches,
            self.nr_bounce_dispatches,
            self.nr_failed_dispatches,
            self.nr_sched_congested,
        )?;
        Ok(())
    }

    fn delta(&self, rhs: &Self) -> Self {
        Self {
            nr_user_dispatches: self.nr_user_dispatches - rhs.nr_user_dispatches,
            nr_kernel_dispatches: self.nr_kernel_dispatches - rhs.nr_kernel_dispatches,
            nr_cancel_dispatches: self.nr_cancel_dispatches - rhs.nr_cancel_dispatches,
            nr_bounce_dispatches: self.nr_bounce_dispatches - rhs.nr_bounce_dispatches,
            nr_failed_dispatches: self.nr_failed_dispatches - rhs.nr_failed_dispatches,
            nr_sched_congested: self.nr_sched_congested - rhs.nr_sched_congested,
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

pub fn monitor(intv: Duration) -> Result<()> {
    scx_utils::monitor_stats::<Metrics>(
        &vec![],
        intv,
        || false,
        |metrics| metrics.format(&mut std::io::stdout()),
    )
}
