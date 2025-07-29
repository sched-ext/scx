use std::collections::BTreeMap;
use std::io::Write;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use serde::Deserialize;
use serde::Serialize;

use scx_stats::prelude::*;
use scx_stats_derive::stat_doc;
use scx_stats_derive::Stats;

use crate::DistributionStats;

#[stat_doc]
#[derive(Clone, Debug, Default, Serialize, Deserialize, Stats)]
#[stat(_om_prefix = "c_")]
#[stat(top)]
pub struct CellMetrics {
    #[stat(desc = "Number of cpus")]
    pub num_cpus: u32,
    #[stat(desc = "Local queue %")]
    pub local_q_pct: f64,
    #[stat(desc = "CPU queue %")]
    pub cpu_q_pct: f64,
    #[stat(desc = "Cell queue %")]
    pub cell_q_pct: f64,
    #[stat(desc = "Affinity violations % of global")]
    pub affn_violations_pct: f64,
    #[stat(desc = "Decision share % of global")]
    pub share_of_decisions_pct: f64,
    #[stat(desc = "Cell scheduling decisions")]
    total_decisions: u64,
}

impl CellMetrics {
    pub fn update(&mut self, ds: &DistributionStats) {
        self.local_q_pct = ds.local_q_pct;
        self.cpu_q_pct = ds.cpu_q_pct;
        self.cell_q_pct = ds.cell_q_pct;
        self.affn_violations_pct = ds.affn_viol_pct;
        self.share_of_decisions_pct = ds.share_of_decisions_pct;
        self.total_decisions = ds.total_decisions;
    }
}

#[stat_doc]
#[derive(Clone, Debug, Default, Serialize, Deserialize, Stats)]
#[stat(top)]
pub struct Metrics {
    #[stat(desc = "Number of cells")]
    pub num_cells: u32,
    #[stat(desc = "Local queue %")]
    pub local_q_pct: f64,
    #[stat(desc = "CPU queue %")]
    pub cpu_q_pct: f64,
    #[stat(desc = "Cell queue %")]
    pub cell_q_pct: f64,
    #[stat(desc = "Affinity violations % of global")]
    pub affn_violations_pct: f64,
    #[stat(desc = "Decision share % of global")]
    pub share_of_decisions_pct: f64,
    #[stat(desc = "Cell scheduling decisions")]
    total_decisions: u64,
    #[stat(desc = "Per-cell metrics")] // TODO: cell names
    pub cells: BTreeMap<u32, CellMetrics>,
}

impl Metrics {
    pub fn update(&mut self, ds: &DistributionStats) {
        self.local_q_pct = ds.local_q_pct;
        self.cpu_q_pct = ds.cpu_q_pct;
        self.cell_q_pct = ds.cell_q_pct;
        self.affn_violations_pct = ds.affn_viol_pct;
        self.share_of_decisions_pct = ds.share_of_decisions_pct;
        self.total_decisions = ds.total_decisions;
    }

    fn delta(&self, _: &Self) -> Self {
        Self { ..self.clone() }
    }

    fn format<W: Write>(&self, w: &mut W) -> Result<()> {
        writeln!(w, "{}", serde_json::to_string_pretty(self)?)?;
        Ok(())
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
        .add_meta(CellMetrics::meta())
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
