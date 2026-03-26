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
    #[stat(desc = "Number of online CPUs")]
    pub nr_cpus: u64,
    #[stat(desc = "Number of kthread direct dispatches")]
    pub nr_kthread_dispatches: u64,
    #[stat(desc = "Number of task direct dispatches")]
    pub nr_direct_dispatches: u64,
    #[stat(desc = "Number of regular task dispatches")]
    pub nr_shared_dispatches: u64,
    #[stat(desc = "Number of queue-delay-driven slice reductions")]
    pub nr_delay_scaled_dispatches: u64,
    #[stat(desc = "Number of queue-delay-gradient slice reductions")]
    pub nr_delay_gradient_dispatches: u64,
    #[stat(desc = "Number of low-region additive Timely increases")]
    pub nr_delay_recovery_dispatches: u64,
    #[stat(desc = "Number of middle-region additive Timely increases")]
    pub nr_delay_middle_add_dispatches: u64,
    #[stat(desc = "Number of middle-region HAI Timely increases")]
    pub nr_delay_fast_recovery_dispatches: u64,
    #[stat(desc = "Number of fresh delay samples skipped by the minimum control interval")]
    pub nr_delay_rate_limited_dispatches: u64,
    #[stat(desc = "Number of control updates that hit the minimum Timely gain")]
    pub nr_gain_floor_dispatches: u64,
    #[stat(desc = "Number of control updates that recovered to the maximum Timely gain")]
    pub nr_gain_ceiling_dispatches: u64,
    #[stat(desc = "Number of local-DSQ rescues triggered from cpu_release")]
    pub nr_cpu_release_reenqueue: u64,
}

impl Metrics {
    pub fn summary_line(&self) -> String {
        format!(
            "tasks r={}/{} dispatch k={} d={} s={} q={} g={} rec={} mid={} hai={} rl={} min={} max={} rel={}",
            self.nr_running,
            self.nr_cpus,
            self.nr_kthread_dispatches,
            self.nr_direct_dispatches,
            self.nr_shared_dispatches,
            self.nr_delay_scaled_dispatches,
            self.nr_delay_gradient_dispatches,
            self.nr_delay_recovery_dispatches,
            self.nr_delay_middle_add_dispatches,
            self.nr_delay_fast_recovery_dispatches,
            self.nr_delay_rate_limited_dispatches,
            self.nr_gain_floor_dispatches,
            self.nr_gain_ceiling_dispatches,
            self.nr_cpu_release_reenqueue
        )
    }

    fn format<W: Write>(&self, w: &mut W) -> Result<()> {
        writeln!(
            w,
            "[{}] tasks -> r: {:>2}/{:<2} | dispatch -> k: {:<5} d: {:<5} s: {:<5} q: {:<5} g: {:<5} rec: {:<5} mid: {:<5} hai: {:<5} rl: {:<5} min: {:<5} max: {:<5} rel: {:<5}",
            crate::SCHEDULER_NAME,
            self.nr_running,
            self.nr_cpus,
            self.nr_kthread_dispatches,
            self.nr_direct_dispatches,
            self.nr_shared_dispatches,
            self.nr_delay_scaled_dispatches,
            self.nr_delay_gradient_dispatches,
            self.nr_delay_recovery_dispatches,
            self.nr_delay_middle_add_dispatches,
            self.nr_delay_fast_recovery_dispatches,
            self.nr_delay_rate_limited_dispatches,
            self.nr_gain_floor_dispatches,
            self.nr_gain_ceiling_dispatches,
            self.nr_cpu_release_reenqueue
        )?;
        Ok(())
    }

    fn delta(&self, rhs: &Self) -> Self {
        Self {
            nr_kthread_dispatches: self.nr_kthread_dispatches - rhs.nr_kthread_dispatches,
            nr_direct_dispatches: self.nr_direct_dispatches - rhs.nr_direct_dispatches,
            nr_shared_dispatches: self.nr_shared_dispatches - rhs.nr_shared_dispatches,
            nr_delay_scaled_dispatches: self.nr_delay_scaled_dispatches
                - rhs.nr_delay_scaled_dispatches,
            nr_delay_gradient_dispatches: self.nr_delay_gradient_dispatches
                - rhs.nr_delay_gradient_dispatches,
            nr_delay_recovery_dispatches: self.nr_delay_recovery_dispatches
                - rhs.nr_delay_recovery_dispatches,
            nr_delay_middle_add_dispatches: self.nr_delay_middle_add_dispatches
                - rhs.nr_delay_middle_add_dispatches,
            nr_delay_fast_recovery_dispatches: self.nr_delay_fast_recovery_dispatches
                - rhs.nr_delay_fast_recovery_dispatches,
            nr_delay_rate_limited_dispatches: self.nr_delay_rate_limited_dispatches
                - rhs.nr_delay_rate_limited_dispatches,
            nr_gain_floor_dispatches: self.nr_gain_floor_dispatches - rhs.nr_gain_floor_dispatches,
            nr_gain_ceiling_dispatches: self.nr_gain_ceiling_dispatches
                - rhs.nr_gain_ceiling_dispatches,
            nr_cpu_release_reenqueue: self.nr_cpu_release_reenqueue - rhs.nr_cpu_release_reenqueue,
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
