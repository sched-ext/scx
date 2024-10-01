use std::collections::BTreeMap;
use std::io::Write;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;
use std::time::UNIX_EPOCH;

use anyhow::Result;
use chrono::DateTime;
use chrono::Local;
use scx_stats::prelude::*;
use scx_stats_derive::stat_doc;
use scx_stats_derive::Stats;
use scx_utils::Cpumask;
use serde::Deserialize;
use serde::Serialize;

use crate::StatsCtx;

fn signed(x: f64) -> String {
    if x >= 0.0f64 {
        format!("{:+7.2}", x)
    } else {
        format!("{:7.2}", x)
    }
}

#[stat_doc]
#[derive(Clone, Debug, Default, Serialize, Deserialize, Stats)]
#[stat(_om_prefix = "d_", _om_label = "domain")]
pub struct DomainStats {
    #[stat(desc = "sum of weight * duty_cycle for all tasks")]
    pub load: f64,
    #[stat(desc = "load imbalance from average")]
    pub imbal: f64,
    #[stat(desc = "load migrated for load balancing")]
    pub delta: f64,
}

impl DomainStats {
    pub fn format<W: Write>(&self, w: &mut W, id: usize) -> Result<()> {
        writeln!(
            w,
            "   DOM[{:02}] load={:6.2} imbal={} delta={}",
            id,
            self.load,
            signed(self.imbal),
            signed(self.delta)
        )?;
        Ok(())
    }
}

#[stat_doc]
#[derive(Clone, Debug, Default, Serialize, Deserialize, Stats)]
#[stat(_om_prefix = "n_", _om_label = "node")]
pub struct NodeStats {
    #[stat(desc = "sum of weight * duty_cycle for all tasks")]
    pub load: f64,
    #[stat(desc = "load imbalance from average")]
    pub imbal: f64,
    #[stat(desc = "load migrated for load balancing")]
    pub delta: f64,
    #[stat(desc = "per-domain statistics")]
    pub doms: BTreeMap<usize, DomainStats>,
}

impl NodeStats {
    pub fn format<W: Write>(&self, w: &mut W, id: usize) -> Result<()> {
        writeln!(
            w,
            "  NODE[{:02}] load={:6.2} imbal={} delta={}",
            id,
            self.load,
            signed(self.imbal),
            signed(self.delta)
        )?;
        Ok(())
    }
}

#[stat_doc]
#[derive(Clone, Debug, Default, Serialize, Deserialize, Stats)]
#[stat(top)]
pub struct ClusterStats {
    #[stat(desc = "timestamp")]
    pub at_us: u64,
    #[stat(desc = "timestamp of the last load balancing")]
    pub lb_at_us: u64,
    #[stat(desc = "# sched events duringg the period")]
    pub total: u64,
    #[stat(desc = "scheduling slice in usecs")]
    pub slice_us: u64,

    #[stat(desc = "CPU busy % (100% means all CPU)")]
    pub cpu_busy: f64,
    #[stat(desc = "sum of weight * duty_cycle for all tasks")]
    pub load: f64,
    #[stat(desc = "# of migrations from load balancing")]
    pub nr_migrations: u64,

    #[stat(desc = "# of BPF task get errors")]
    pub task_get_err: u64,
    #[stat(desc = "# of BPF lb data get errros")]
    pub lb_data_err: u64,
    #[stat(desc = "time spent running scheduler userspace")]
    pub time_used: f64,

    #[stat(desc = "% WAKE_SYNC directly dispatched to idle previous CPU")]
    pub sync_prev_idle: f64,
    #[stat(desc = "% WAKE_SYNC directly dispatched to waker CPU")]
    pub wake_sync: f64,
    #[stat(desc = "% directly dispatched to idle previous CPU")]
    pub prev_idle: f64,
    #[stat(desc = "% directly dispatched to idle previous CPU in a different domain")]
    pub greedy_idle: f64,
    #[stat(desc = "% directly dispatched to CPU due to restricted to one CPU")]
    pub pinned: f64,
    #[stat(desc = "% directly dispatched to CPU (--kthreads-local or local domain)")]
    pub direct: f64,
    #[stat(desc = "% directly dispatched to CPU (foreign domain, local node)")]
    pub greedy: f64,
    #[stat(desc = "% directly dispatched to CPU (foreign node)")]
    pub greedy_far: f64,
    #[stat(desc = "% scheduled from local domain")]
    pub dsq_dispatch: f64,
    #[stat(desc = "% scheduled from foreign domain")]
    pub greedy_local: f64,
    #[stat(desc = "% scheduled from foreign node")]
    pub greedy_xnuma: f64,
    #[stat(desc = "% foreign domain CPU kicked on enqueue")]
    pub kick_greedy: f64,
    #[stat(desc = "% repatriated to local domain on enqueue")]
    pub repatriate: f64,
    #[stat(desc = "% accumulated vtime budget clamped")]
    pub dl_clamp: f64,
    #[stat(desc = "% accumulated vtime budget used as-is")]
    pub dl_preset: f64,

    #[stat(_om_skip)]
    pub direct_greedy_cpus: Vec<u64>,
    #[stat(_om_skip)]
    pub kick_greedy_cpus: Vec<u64>,

    #[stat(desc = "per-node statistics")]
    pub nodes: BTreeMap<usize, NodeStats>,
}

impl ClusterStats {
    pub fn format<W: Write>(&self, w: &mut W) -> Result<()> {
        writeln!(
            w,
            "cpu={:7.2} load={:8.2} mig={} task_err={} lb_data_err={} time_used={:4.1}ms",
            self.cpu_busy,
            self.load,
            self.nr_migrations,
            self.task_get_err,
            self.lb_data_err,
            self.time_used * 1000.0,
        )?;
        writeln!(
            w,
            "tot={:7} sync_prev_idle={:5.2} wsync={:5.2}",
            self.total, self.sync_prev_idle, self.wake_sync,
        )?;
        writeln!(
            w,
            "prev_idle={:5.2} greedy_idle={:5.2} pin={:5.2}",
            self.prev_idle, self.greedy_idle, self.pinned
        )?;

        writeln!(
            w,
            "dir={:5.2} dir_greedy={:5.2} dir_greedy_far={:5.2}",
            self.direct, self.greedy, self.greedy_far,
        )?;

        writeln!(
            w,
            "dsq={:5.2} greedy_local={:5.2} greedy_xnuma={:5.2}",
            self.dsq_dispatch, self.greedy_local, self.greedy_xnuma,
        )?;

        writeln!(
            w,
            "kick_greedy={:5.2} rep={:5.2}",
            self.kick_greedy, self.repatriate
        )?;
        writeln!(
            w,
            "dl_clamp={:5.2} dl_preset={:5.2}",
            self.dl_clamp, self.dl_preset,
        )?;

        writeln!(w, "slice={}us", self.slice_us)?;
        writeln!(
            w,
            "direct_greedy_cpus={:x}",
            Cpumask::from_vec(self.direct_greedy_cpus.clone())
        )?;
        writeln!(
            w,
            "  kick_greedy_cpus={:x}",
            Cpumask::from_vec(self.kick_greedy_cpus.clone())
        )?;

        for (nid, node) in self.nodes.iter() {
            node.format(w, *nid)?;
            for (did, dom) in node.doms.iter() {
                dom.format(w, *did)?;
            }
        }

        Ok(())
    }
}

pub fn server_data() -> StatsServerData<StatsCtx, (StatsCtx, ClusterStats)> {
    let open: Box<dyn StatsOpener<StatsCtx, (StatsCtx, ClusterStats)>> =
        Box::new(move |(req_ch, res_ch)| {
            // Send one bogus request on open to establish prev_sc.
            let mut prev_sc = StatsCtx::blank();
            req_ch.send(prev_sc.clone())?;
            let (cur_sc, _) = res_ch.recv()?;
            prev_sc = cur_sc;

            let read: Box<dyn StatsReader<StatsCtx, (StatsCtx, ClusterStats)>> =
                Box::new(move |_args, (req_ch, res_ch)| {
                    req_ch.send(prev_sc.clone())?;
                    let (cur_sc, cluster_stats) = res_ch.recv()?;
                    prev_sc = cur_sc;
                    cluster_stats.to_json()
                });
            Ok(read)
        });

    StatsServerData::new()
        .add_meta(DomainStats::meta())
        .add_meta(NodeStats::meta())
        .add_meta(ClusterStats::meta())
        .add_ops("top", StatsOps { open, close: None })
}

pub fn monitor(intv: Duration, shutdown: Arc<AtomicBool>) -> Result<()> {
    scx_utils::monitor_stats::<ClusterStats>(
        &vec![],
        intv,
        || shutdown.load(Ordering::Relaxed),
        |cst| {
            let dt = DateTime::<Local>::from(UNIX_EPOCH + Duration::from_micros(cst.at_us));
            println!(
                "###### {}, load balance @ {:7.1}ms ######",
                dt.to_rfc2822(),
                (cst.lb_at_us as i64 - cst.at_us as i64) as f64 / 1000.0
            );
            cst.format(&mut std::io::stdout())
        },
    )
}
