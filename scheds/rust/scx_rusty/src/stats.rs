use crate::StatsCtx;
use anyhow::Result;
use chrono::DateTime;
use chrono::Local;
use log::info;
use scx_stats::Meta;
use scx_stats::ScxStatsClient;
use scx_stats::ScxStatsOps;
use scx_stats::ScxStatsServer;
use scx_stats::StatsOpener;
use scx_stats::StatsReader;
use scx_stats::ToJson;
use scx_stats_derive::Stats;
use scx_utils::Cpumask;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;
use std::io::Write;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::thread::sleep;
use std::time::Duration;
use std::time::UNIX_EPOCH;

fn signed(x: f64) -> String {
    if x >= 0.0f64 {
        format!("{:+7.2}", x)
    } else {
        format!("{:7.2}", x)
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, Stats)]
#[stat(_om_prefix = "d_", _om_label = "domain")]
pub struct DomainStats {
    pub load: f64,
    pub imbal: f64,
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

#[derive(Clone, Debug, Default, Serialize, Deserialize, Stats)]
#[stat(_om_prefix = "n_", _om_label = "node")]
pub struct NodeStats {
    pub load: f64,
    pub imbal: f64,
    pub delta: f64,
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

#[derive(Clone, Debug, Default, Serialize, Deserialize, Stats)]
#[stat(top)]
pub struct ClusterStats {
    pub at_us: u64,
    pub lb_at_us: u64,
    pub cpu_busy: f64,
    pub load: f64,
    pub nr_migrations: u64,

    pub task_get_err: u64,
    pub lb_data_err: u64,
    pub cpu_used: f64,

    pub total: u64,

    pub sync_prev_idle: f64,
    pub wake_sync: f64,
    pub prev_idle: f64,
    pub greedy_idle: f64,
    pub pinned: f64,
    pub dispatch: f64,
    pub greedy: f64,
    pub greedy_far: f64,
    pub dsq_dispatch: f64,
    pub greedy_local: f64,
    pub greedy_xnuma: f64,
    pub kick_greedy: f64,
    pub repatriate: f64,
    pub dl_clamp: f64,
    pub dl_preset: f64,

    pub slice_us: u64,
    #[stat(_om_skip)]
    pub direct_greedy_cpus: Vec<u64>,
    #[stat(_om_skip)]
    pub kick_greedy_cpus: Vec<u64>,

    pub nodes: BTreeMap<usize, NodeStats>,
}

impl ClusterStats {
    pub fn format<W: Write>(&self, w: &mut W) -> Result<()> {
        writeln!(
            w,
            "cpu={:7.2} load={:8.2} mig={} task_err={} lb_data_err={} cpu_used={:4.1}ms",
            self.cpu_busy,
            self.load,
            self.nr_migrations,
            self.task_get_err,
            self.lb_data_err,
            self.cpu_used * 1000.0,
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
            self.dispatch, self.greedy, self.greedy_far,
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

pub fn launch_server() -> Result<ScxStatsServer<StatsCtx, (StatsCtx, ClusterStats)>> {
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

    Ok(ScxStatsServer::new()
        .add_stats_meta(DomainStats::meta())
        .add_stats_meta(NodeStats::meta())
        .add_stats_meta(ClusterStats::meta())
        .add_stats_ops("top", ScxStatsOps { open, close: None })
        .launch()?)
}

pub fn monitor(intv: Duration, shutdown: Arc<AtomicBool>) -> Result<()> {
    let mut retry_cnt: u32 = 0;
    while !shutdown.load(Ordering::Relaxed) {
        let mut client = match ScxStatsClient::new().connect() {
            Ok(v) => v,
            Err(e) => match e.downcast_ref::<std::io::Error>() {
                Some(ioe) if ioe.kind() == std::io::ErrorKind::ConnectionRefused => {
                    if retry_cnt == 1 {
                        info!("Stats server not avaliable, retrying...");
                    }
                    retry_cnt += 1;
                    sleep(Duration::from_secs(1));
                    continue;
                }
                _ => Err(e)?,
            },
        };
        retry_cnt = 0;

        while !shutdown.load(Ordering::Relaxed) {
            let cst = match client.request::<ClusterStats>("stats", vec![]) {
                Ok(v) => v,
                Err(e) => match e.downcast_ref::<std::io::Error>() {
                    Some(ioe) => {
                        info!("Connection to stats_server failed ({})", &ioe);
                        sleep(Duration::from_secs(1));
                        break;
                    }
                    None => Err(e)?,
                },
            };
            let dt = DateTime::<Local>::from(UNIX_EPOCH + Duration::from_micros(cst.at_us));
            println!(
                "###### {}, load balance @ {:7.1}ms ######",
                dt.to_rfc2822(),
                (cst.lb_at_us as i64 - cst.at_us as i64) as f64 / 1000.0
            );
            cst.format(&mut std::io::stdout())?;
            sleep(intv);
        }
    }

    Ok(())
}
