use std::collections::BTreeMap;
use std::io::Write;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::thread::current;
use std::thread::ThreadId;
use std::time::Duration;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use anyhow::bail;
use anyhow::Result;
use bitvec::prelude::*;
use chrono::DateTime;
use chrono::Local;
use log::warn;
use scx_stats::prelude::*;
use scx_stats_derive::Stats;
use serde::Deserialize;
use serde::Serialize;

use crate::bpf_intf;
use crate::BpfStats;
use crate::Layer;
use crate::LayerKind;
use crate::Stats;

fn fmt_pct(v: f64) -> String {
    if v >= 99.995 {
        format!("{:5.1}", v)
    } else {
        format!("{:5.2}", v)
    }
}

fn fmt_num(v: u64) -> String {
    if v > 1_000_000 {
        format!("{:5.1}m", v as f64 / 1_000_000.0)
    } else if v > 1_000 {
        format!("{:5.1}k", v as f64 / 1_000.0)
    } else {
        format!("{:5.0} ", v)
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, Stats)]
#[stat(_om_prefix = "l_", _om_label = "layer_name")]
pub struct LayerStats {
    #[stat(desc = "CPU utilization (100% means one full CPU)")]
    pub util: f64,
    #[stat(desc = "fraction of total CPU utilization")]
    pub util_frac: f64,
    #[stat(desc = "sum of weight * duty_cycle for tasks")]
    pub load: f64,
    #[stat(desc = "fraction of total load")]
    pub load_frac: f64,
    #[stat(desc = "# tasks")]
    pub tasks: u32,
    #[stat(desc = "# sched events duringg the period")]
    pub total: u64,
    #[stat(desc = "% dispatched into idle CPU")]
    pub sel_local: f64,
    #[stat(desc = "% enqueued after wakeup")]
    pub enq_wakeup: f64,
    #[stat(desc = "% enqueued after slice expiration")]
    pub enq_expire: f64,
    #[stat(desc = "% re-enqueued due to RT preemption")]
    pub enq_reenq: f64,
    #[stat(desc = "# times exec duration < min_exec_us")]
    pub min_exec: f64,
    #[stat(desc = "total exec durations extended due to min_exec_us")]
    pub min_exec_us: u64,
    #[stat(desc = "% dispatched into idle CPUs occupied by other layers")]
    pub open_idle: f64,
    #[stat(desc = "% preempted other tasks")]
    pub preempt: f64,
    #[stat(desc = "% preempted XLLC tasks")]
    pub preempt_xllc: f64,
    #[stat(desc = "% preempted XNUMA tasks")]
    pub preempt_xnuma: f64,
    #[stat(desc = "% first-preempted other tasks")]
    pub preempt_first: f64,
    #[stat(desc = "% idle-preempted other tasks")]
    pub preempt_idle: f64,
    #[stat(desc = "% attempted to preempt other tasks but failed")]
    pub preempt_fail: f64,
    #[stat(desc = "% violated config due to CPU affinity")]
    pub affn_viol: f64,
    #[stat(desc = "% continued executing after slice expiration")]
    pub keep: f64,
    #[stat(desc = "% disallowed to continue executing due to max_exec")]
    pub keep_fail_max_exec: f64,
    #[stat(desc = "% disallowed to continue executing due to other tasks")]
    pub keep_fail_busy: f64,
    #[stat(desc = "whether is exclusive", _om_skip)]
    pub is_excl: u32,
    #[stat(desc = "# times an excl task skipped a CPU as the sibling was also excl")]
    pub excl_collision: f64,
    #[stat(desc = "% a sibling CPU was preempted for an exclusive task")]
    pub excl_preempt: f64,
    #[stat(desc = "% kicked a CPU from enqueue path")]
    pub kick: f64,
    #[stat(desc = "% yielded")]
    pub yielded: f64,
    #[stat(desc = "# times yield was ignored")]
    pub yield_ignore: u64,
    #[stat(desc = "% migrated across CPUs")]
    pub migration: f64,
    #[stat(desc = "% migrated across NUMA nodes")]
    pub xnuma_migration: f64,
    #[stat(desc = "% migrated across LLCs")]
    pub xllc_migration: f64,
    #[stat(desc = "mask of allocated CPUs", _om_skip)]
    pub cpus: Vec<u32>,
    #[stat(desc = "# of CPUs assigned")]
    pub cur_nr_cpus: u32,
    #[stat(desc = "minimum # of CPUs assigned")]
    pub min_nr_cpus: u32,
    #[stat(desc = "maximum # of CPUs assigned")]
    pub max_nr_cpus: u32,
}

impl LayerStats {
    fn bitvec_to_u32s(bitvec: &BitVec) -> Vec<u32> {
        let mut vals = Vec::<u32>::new();
        let mut val: u32 = 0;
        for (idx, bit) in bitvec.iter().enumerate() {
            if idx > 0 && idx % 32 == 0 {
                vals.push(val);
                val = 0;
            }
            if *bit {
                val |= 1 << (idx % 32);
            }
        }
        vals.push(val);
        vals
    }

    pub fn new(
        lidx: usize,
        layer: &Layer,
        stats: &Stats,
        bstats: &BpfStats,
        nr_cpus_range: (usize, usize),
    ) -> Self {
        let lstat = |sidx| bstats.lstats[lidx][sidx as usize];
        let ltotal = lstat(bpf_intf::layer_stat_idx_LSTAT_SEL_LOCAL)
            + lstat(bpf_intf::layer_stat_idx_LSTAT_ENQ_WAKEUP)
            + lstat(bpf_intf::layer_stat_idx_LSTAT_ENQ_EXPIRE)
            + lstat(bpf_intf::layer_stat_idx_LSTAT_ENQ_REENQ);
        let lstat_pct = |sidx| {
            if ltotal != 0 {
                lstat(sidx) as f64 / ltotal as f64 * 100.0
            } else {
                0.0
            }
        };
        let calc_frac = |a, b| {
            if b != 0.0 { a / b * 100.0 } else { 0.0 }
        };

        let is_excl = match &layer.kind {
            LayerKind::Confined { exclusive, .. }
            | LayerKind::Grouped { exclusive, .. }
            | LayerKind::Open { exclusive, .. } => *exclusive,
        } as u32;

        Self {
            util: stats.layer_utils[lidx] * 100.0,
            util_frac: calc_frac(stats.layer_utils[lidx], stats.total_util),
            load: stats.layer_loads[lidx],
            load_frac: calc_frac(stats.layer_loads[lidx], stats.total_load),
            tasks: stats.nr_layer_tasks[lidx] as u32,
            total: ltotal,
            sel_local: lstat_pct(bpf_intf::layer_stat_idx_LSTAT_SEL_LOCAL),
            enq_wakeup: lstat_pct(bpf_intf::layer_stat_idx_LSTAT_ENQ_WAKEUP),
            enq_expire: lstat_pct(bpf_intf::layer_stat_idx_LSTAT_ENQ_EXPIRE),
            enq_reenq: lstat_pct(bpf_intf::layer_stat_idx_LSTAT_ENQ_REENQ),
            min_exec: lstat_pct(bpf_intf::layer_stat_idx_LSTAT_MIN_EXEC),
            min_exec_us: (lstat(bpf_intf::layer_stat_idx_LSTAT_MIN_EXEC_NS) / 1000) as u64,
            open_idle: lstat_pct(bpf_intf::layer_stat_idx_LSTAT_OPEN_IDLE),
            preempt: lstat_pct(bpf_intf::layer_stat_idx_LSTAT_PREEMPT),
            preempt_xllc: lstat_pct(bpf_intf::layer_stat_idx_LSTAT_PREEMPT_XLLC),
            preempt_xnuma: lstat_pct(bpf_intf::layer_stat_idx_LSTAT_PREEMPT_XNUMA),
            preempt_first: lstat_pct(bpf_intf::layer_stat_idx_LSTAT_PREEMPT_FIRST),
            preempt_idle: lstat_pct(bpf_intf::layer_stat_idx_LSTAT_PREEMPT_IDLE),
            preempt_fail: lstat_pct(bpf_intf::layer_stat_idx_LSTAT_PREEMPT_FAIL),
            affn_viol: lstat_pct(bpf_intf::layer_stat_idx_LSTAT_AFFN_VIOL),
            keep: lstat_pct(bpf_intf::layer_stat_idx_LSTAT_KEEP),
            keep_fail_max_exec: lstat_pct(bpf_intf::layer_stat_idx_LSTAT_KEEP_FAIL_MAX_EXEC),
            keep_fail_busy: lstat_pct(bpf_intf::layer_stat_idx_LSTAT_KEEP_FAIL_BUSY),
            is_excl,
            excl_collision: lstat_pct(bpf_intf::layer_stat_idx_LSTAT_EXCL_COLLISION),
            excl_preempt: lstat_pct(bpf_intf::layer_stat_idx_LSTAT_EXCL_PREEMPT),
            kick: lstat_pct(bpf_intf::layer_stat_idx_LSTAT_KICK),
            yielded: lstat_pct(bpf_intf::layer_stat_idx_LSTAT_YIELD),
            yield_ignore: lstat(bpf_intf::layer_stat_idx_LSTAT_YIELD_IGNORE) as u64,
            migration: lstat_pct(bpf_intf::layer_stat_idx_LSTAT_MIGRATION),
            xnuma_migration: lstat_pct(bpf_intf::layer_stat_idx_LSTAT_XNUMA_MIGRATION),
            xllc_migration: lstat_pct(bpf_intf::layer_stat_idx_LSTAT_XLLC_MIGRATION),
            cpus: Self::bitvec_to_u32s(&layer.cpus),
            cur_nr_cpus: layer.cpus.count_ones() as u32,
            min_nr_cpus: nr_cpus_range.0 as u32,
            max_nr_cpus: nr_cpus_range.1 as u32,
        }
    }

    pub fn format<W: Write>(&self, w: &mut W, name: &str, header_width: usize) -> Result<()> {
        writeln!(
            w,
            "  {:<width$}: util/frac={:7.1}/{:5.1} load/frac={:9.1}/{:5.1} tasks={:6}",
            name,
            self.util,
            self.util_frac,
            self.load,
            self.load_frac,
            self.tasks,
            width = header_width,
        )?;

        writeln!(
            w,
            "  {:<width$}  tot={:7} local={} wake/exp/reenq={}/{}/{}",
            "",
            self.total,
            fmt_pct(self.sel_local),
            fmt_pct(self.enq_wakeup),
            fmt_pct(self.enq_expire),
            fmt_pct(self.enq_reenq),
            width = header_width,
        )?;

        writeln!(
            w,
            "  {:<width$}  keep/max/busy={}/{}/{} kick={} yield/ign={}/{}",
            "",
            fmt_pct(self.keep),
            fmt_pct(self.keep_fail_max_exec),
            fmt_pct(self.keep_fail_busy),
            fmt_pct(self.kick),
            fmt_pct(self.yielded),
            fmt_num(self.yield_ignore),
            width = header_width,
        )?;

        writeln!(
            w,
            "  {:<width$}  open_idle={} mig={} xnuma_mig={} xllc_mig={} affn_viol={}",
            "",
            fmt_pct(self.open_idle),
            fmt_pct(self.migration),
            fmt_pct(self.xnuma_migration),
            fmt_pct(self.xllc_migration),
            fmt_pct(self.affn_viol),
            width = header_width,
        )?;

        writeln!(
            w,
            "  {:<width$}  preempt/first/xllc/xnuma/idle/fail={}/{}/{}/{}/{}/{} min_exec={}/{:7.2}ms",
            "",
            fmt_pct(self.preempt),
            fmt_pct(self.preempt_first),
            fmt_pct(self.preempt_xllc),
            fmt_pct(self.preempt_xnuma),
            fmt_pct(self.preempt_idle),
            fmt_pct(self.preempt_fail),
            fmt_pct(self.min_exec),
            self.min_exec_us as f64 / 1000.0,
            width = header_width,
        )?;

        let mut cpus = self
            .cpus
            .iter()
            .fold(String::new(), |string, v| format!("{}{:08x} ", string, v));
        cpus.pop();

        writeln!(
            w,
            "  {:<width$}  cpus={:3} [{:3},{:3}] {}",
            "",
            self.cur_nr_cpus,
            self.min_nr_cpus,
            self.max_nr_cpus,
            &cpus,
            width = header_width
        )?;

        if self.is_excl != 0 {
            writeln!(
                w,
                "  {:<width$}  excl_coll={} excl_preempt={}",
                "",
                fmt_pct(self.excl_collision),
                fmt_pct(self.excl_preempt),
                width = header_width,
            )?;
        } else if self.excl_collision != 0.0 || self.excl_preempt != 0.0 {
            warn!(
                "{}: exclusive is off but excl_coll={} excl_preempt={}",
                name,
                fmt_pct(self.excl_collision),
                fmt_pct(self.excl_preempt),
            );
        }

        Ok(())
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, Stats)]
#[stat(top)]
pub struct SysStats {
    #[stat(desc = "timestamp", _om_skip)]
    pub at: f64,
    #[stat(desc = "# sched events during the period")]
    pub total: u64,
    #[stat(desc = "% dispatched directly into an idle CPU")]
    pub local: f64,
    #[stat(desc = "% open layer tasks scheduled into allocated but idle CPUs")]
    pub open_idle: f64,
    #[stat(desc = "% violated config due to CPU affinity")]
    pub affn_viol: f64,
    #[stat(desc = "# times an excl task skipped a CPU as the sibling was also excl")]
    pub excl_collision: f64,
    #[stat(desc = "# times a sibling CPU was preempted for an excl task")]
    pub excl_preempt: f64,
    #[stat(desc = "# times a CPU skipped dispatching due to an excl task on the sibling")]
    pub excl_idle: f64,
    #[stat(desc = "# times an idle sibling CPU was woken up after an excl task is finished")]
    pub excl_wakeup: f64,
    #[stat(desc = "CPU time this binary consumed during the period")]
    pub proc_ms: u64,
    #[stat(desc = "CPU busy % (100% means all CPU)")]
    pub busy: f64,
    #[stat(desc = "CPU util % (100% means one CPU)")]
    pub util: f64,
    #[stat(desc = "sum of weight * duty_cycle for all tasks")]
    pub load: f64,
    #[stat(desc = "fallback CPU")]
    pub fallback_cpu: u32,
    #[stat(desc = "per-layer statistics")]
    pub layers: BTreeMap<String, LayerStats>,
}

impl SysStats {
    pub fn new(stats: &Stats, bstats: &BpfStats, fallback_cpu: usize) -> Result<Self> {
        let lsum = |idx| stats.bpf_stats.lstats_sums[idx as usize];
        let total = lsum(bpf_intf::layer_stat_idx_LSTAT_SEL_LOCAL)
            + lsum(bpf_intf::layer_stat_idx_LSTAT_ENQ_WAKEUP)
            + lsum(bpf_intf::layer_stat_idx_LSTAT_ENQ_EXPIRE)
            + lsum(bpf_intf::layer_stat_idx_LSTAT_ENQ_REENQ);
        let lsum_pct = |idx| {
            if total != 0 {
                lsum(idx) as f64 / total as f64 * 100.0
            } else {
                0.0
            }
        };

        Ok(Self {
            at: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs_f64(),
            total,
            local: lsum_pct(bpf_intf::layer_stat_idx_LSTAT_SEL_LOCAL),
            open_idle: lsum_pct(bpf_intf::layer_stat_idx_LSTAT_OPEN_IDLE),
            affn_viol: lsum_pct(bpf_intf::layer_stat_idx_LSTAT_AFFN_VIOL),
            excl_collision: lsum_pct(bpf_intf::layer_stat_idx_LSTAT_EXCL_COLLISION),
            excl_preempt: lsum_pct(bpf_intf::layer_stat_idx_LSTAT_EXCL_PREEMPT),
            excl_idle: bstats.gstats[bpf_intf::global_stat_idx_GSTAT_EXCL_IDLE as usize] as f64
                / total as f64,
            excl_wakeup: bstats.gstats[bpf_intf::global_stat_idx_GSTAT_EXCL_WAKEUP as usize] as f64
                / total as f64,
            proc_ms: stats.processing_dur.as_millis() as u64,
            busy: stats.cpu_busy * 100.0,
            util: stats.total_util * 100.0,
            load: stats.total_load,
            fallback_cpu: fallback_cpu as u32,
            layers: BTreeMap::new(),
        })
    }

    pub fn format<W: Write>(&self, w: &mut W) -> Result<()> {
        writeln!(
            w,
            "tot={:7} local={} open_idle={} affn_viol={} proc={:?}ms",
            self.total,
            fmt_pct(self.local),
            fmt_pct(self.open_idle),
            fmt_pct(self.affn_viol),
            self.proc_ms,
        )?;

        writeln!(
            w,
            "busy={:5.1} util={:7.1} load={:9.1} fallback_cpu={:3}",
            self.busy, self.util, self.load, self.fallback_cpu,
        )?;

        writeln!(
            w,
            "excl_coll={:.2} excl_preempt={:.2} excl_idle={:.2} excl_wakeup={:.2}",
            self.excl_collision, self.excl_preempt, self.excl_idle, self.excl_wakeup
        )?;

        Ok(())
    }

    pub fn format_all<W: Write>(&self, w: &mut W) -> Result<()> {
        self.format(w)?;

        let header_width = self
            .layers
            .keys()
            .map(|name| name.len())
            .max()
            .unwrap_or(0)
            .max(4);

        for (name, layer) in self.layers.iter() {
            layer.format(w, name, header_width)?;
        }

        Ok(())
    }
}

#[derive(Debug)]
pub enum StatsReq {
    Hello(ThreadId),
    Refresh(ThreadId, Stats),
    Bye(ThreadId),
}

#[derive(Debug)]
pub enum StatsRes {
    Hello(Stats),
    Refreshed((Stats, SysStats)),
    Bye,
}

pub fn server_data() -> StatsServerData<StatsReq, StatsRes> {
    let open: Box<dyn StatsOpener<StatsReq, StatsRes>> = Box::new(move |(req_ch, res_ch)| {
        let tid = current().id();
        req_ch.send(StatsReq::Hello(tid))?;
        let mut stats = Some(match res_ch.recv()? {
            StatsRes::Hello(v) => v,
            res => bail!("invalid response to Hello: {:?}", &res),
        });

        let read: Box<dyn StatsReader<StatsReq, StatsRes>> =
            Box::new(move |_args, (req_ch, res_ch)| {
                req_ch.send(StatsReq::Refresh(tid, stats.take().unwrap()))?;
                let (new_stats, sys_stats) = match res_ch.recv()? {
                    StatsRes::Refreshed(v) => v,
                    res => bail!("invalid response to Refresh: {:?}", &res),
                };
                stats = Some(new_stats);
                sys_stats.to_json()
            });

        Ok(read)
    });

    let close: Box<dyn StatsCloser<StatsReq, StatsRes>> = Box::new(move |(req_ch, res_ch)| {
        req_ch.send(StatsReq::Bye(current().id())).unwrap();
        match res_ch.recv().unwrap() {
            StatsRes::Bye => {}
            res => panic!("invalid response to Bye: {:?}", &res),
        }
    });

    StatsServerData::new()
        .add_meta(LayerStats::meta())
        .add_meta(SysStats::meta())
        .add_ops(
            "top",
            StatsOps {
                open,
                close: Some(close),
            },
        )
}

pub fn monitor(intv: Duration, shutdown: Arc<AtomicBool>) -> Result<()> {
    scx_utils::monitor_stats::<SysStats>(
        &vec![],
        intv,
        || shutdown.load(Ordering::Relaxed),
        |sst| {
            let dt = DateTime::<Local>::from(UNIX_EPOCH + Duration::from_secs_f64(sst.at));
            println!("###### {} ######", dt.to_rfc2822());
            sst.format_all(&mut std::io::stdout())
        },
    )
}
