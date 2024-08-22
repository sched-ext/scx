use anyhow::Result;
use scx_utils::Cpumask;
use std::collections::BTreeMap;
use std::io::Write;

fn signed(x: f64) -> String {
    if x >= 0.0f64 {
        format!("{:+7.2}", x)
    } else {
        format!("{:7.2}", x)
    }
}

#[derive(Clone, Debug, Default)]
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

#[derive(Clone, Debug, Default)]
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

#[derive(Clone, Debug, Default)]
pub struct ClusterStats {
    pub cpu_busy: f64,
    pub load: f64,
    pub nr_load_balances: u64,

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
    pub direct_greedy_cpus: Vec<u64>,
    pub kick_greedy_cpus: Vec<u64>,

    pub nodes: BTreeMap<usize, NodeStats>,
}

impl ClusterStats {
    pub fn format<W: Write>(&self, w: &mut W) -> Result<()> {
        writeln!(
            w,
            "cpu={:7.2} load={:8.2} bal={} task_err={} lb_data_err={} cpu_used={:4.1}ms",
            self.cpu_busy,
            self.load,
            self.nr_load_balances,
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
