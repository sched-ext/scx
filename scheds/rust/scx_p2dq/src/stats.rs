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
    #[stat(desc = "Number of times a task was enqueued to a ATQ")]
    pub atq_enq: u64,
    #[stat(desc = "Number of times a task was re-enqueued to a ATQ")]
    pub atq_reenq: u64,
    #[stat(desc = "Number of times tasks have switched DSQs")]
    pub dsq_change: u64,
    #[stat(desc = "Number of times tasks have stayed on the same DSQ")]
    pub same_dsq: u64,
    #[stat(desc = "Number of times a task kept running")]
    pub keep: u64,
    #[stat(desc = "Number of times a task was enqueued to CPUC DSQ")]
    pub enq_cpu: u64,
    #[stat(desc = "Number of times a task was enqueued to LLC DSQ")]
    pub enq_llc: u64,
    #[stat(desc = "Number of times a task was enqueued to interactive DSQ")]
    pub enq_intr: u64,
    #[stat(desc = "Number of times a task was enqueued to migration DSQ")]
    pub enq_mig: u64,
    #[stat(desc = "Number of times a select_cpu pick 2 load balancing occured")]
    pub select_pick2: u64,
    #[stat(desc = "Number of times a dispatch pick 2 load balancing occured")]
    pub dispatch_pick2: u64,
    #[stat(desc = "Number of times a task migrated LLCs")]
    pub llc_migrations: u64,
    #[stat(desc = "Number of times a task migrated NUMA nodes")]
    pub node_migrations: u64,
    #[stat(desc = "Number of times tasks have directly been dispatched to local per CPU DSQs")]
    pub direct: u64,
    #[stat(desc = "Number of times tasks have dispatched to an idle local per CPU DSQs")]
    pub idle: u64,
    #[stat(desc = "Number of times tasks have been woken to the previous CPU")]
    pub wake_prev: u64,
    #[stat(desc = "Number of times tasks have been woken to the previous llc")]
    pub wake_llc: u64,
    #[stat(desc = "Number of times tasks have been woken and migrated llc")]
    pub wake_mig: u64,
    #[stat(desc = "Number of times affinity changed between enqueue and dispatch")]
    pub affinity_changed: u64,
}

impl Metrics {
    fn format<W: Write>(&self, w: &mut W) -> Result<()> {
        writeln!(
            w,
            "direct/idle/keep {}/{}/{}\n\tdsq same/migrate {}/{}\n\tatq enq/reenq {}/{}\n\tenq cpu/llc/intr/mig {}/{}/{}/{}",
            self.direct,
            self.idle,
            self.keep,
            self.same_dsq,
            self.dsq_change,
            self.atq_enq,
            self.atq_reenq,
            self.enq_cpu,
            self.enq_llc,
            self.enq_intr,
            self.enq_mig,
        )?;
        writeln!(
            w,
            "\twake prev/llc/mig {}/{}/{}\n\tpick2 select/dispatch {}/{}\n\tmigrations llc/node: {}/{}\n\taffinity_changed: {}",
            self.wake_prev,
            self.wake_llc,
            self.wake_mig,
            self.select_pick2,
            self.dispatch_pick2,
            self.llc_migrations,
            self.node_migrations,
            self.affinity_changed,
        )?;
        Ok(())
    }

    fn delta(&self, rhs: &Self) -> Self {
        Self {
            atq_enq: self.atq_enq - rhs.atq_enq,
            atq_reenq: self.atq_reenq - rhs.atq_reenq,
            direct: self.direct - rhs.direct,
            idle: self.idle - rhs.idle,
            dsq_change: self.dsq_change - rhs.dsq_change,
            same_dsq: self.same_dsq - rhs.same_dsq,
            keep: self.keep - rhs.keep,
            enq_cpu: self.enq_cpu - rhs.enq_cpu,
            enq_llc: self.enq_llc - rhs.enq_llc,
            enq_intr: self.enq_intr - rhs.enq_intr,
            enq_mig: self.enq_mig - rhs.enq_mig,
            select_pick2: self.select_pick2 - rhs.select_pick2,
            dispatch_pick2: self.dispatch_pick2 - rhs.dispatch_pick2,
            llc_migrations: self.llc_migrations - rhs.llc_migrations,
            node_migrations: self.node_migrations - rhs.node_migrations,
            wake_prev: self.wake_prev - rhs.wake_prev,
            wake_llc: self.wake_llc - rhs.wake_llc,
            wake_mig: self.wake_mig - rhs.wake_mig,
            affinity_changed: self.affinity_changed - rhs.affinity_changed,
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
