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
use chrono::DateTime;
use chrono::Local;
use scx_stats::prelude::*;
use scx_stats_derive::stat_doc;
use scx_stats_derive::Stats;
use scx_utils::Cpumask;
use serde::Deserialize;
use serde::Serialize;
use tracing::warn;

use crate::bpf_intf;
use crate::BpfStats;
use crate::Layer;
use crate::LayerKind;
use crate::Stats;
use crate::LAYER_USAGE_OPEN;
use crate::LAYER_USAGE_PROTECTED;
use crate::LAYER_USAGE_PROTECTED_PREEMPT;
use crate::LAYER_USAGE_SUM_UPTO;

const GSTAT_EXCL_IDLE: usize = bpf_intf::global_stat_id_GSTAT_EXCL_IDLE as usize;
const GSTAT_EXCL_WAKEUP: usize = bpf_intf::global_stat_id_GSTAT_EXCL_WAKEUP as usize;
const GSTAT_HI_FB_EVENTS: usize = bpf_intf::global_stat_id_GSTAT_HI_FB_EVENTS as usize;
const GSTAT_HI_FB_USAGE: usize = bpf_intf::global_stat_id_GSTAT_HI_FB_USAGE as usize;
const GSTAT_LO_FB_EVENTS: usize = bpf_intf::global_stat_id_GSTAT_LO_FB_EVENTS as usize;
const GSTAT_LO_FB_USAGE: usize = bpf_intf::global_stat_id_GSTAT_LO_FB_USAGE as usize;
const GSTAT_FB_CPU_USAGE: usize = bpf_intf::global_stat_id_GSTAT_FB_CPU_USAGE as usize;
const GSTAT_ANTISTALL: usize = bpf_intf::global_stat_id_GSTAT_ANTISTALL as usize;
const GSTAT_SKIP_PREEMPT: usize = bpf_intf::global_stat_id_GSTAT_SKIP_PREEMPT as usize;
const GSTAT_FIXUP_VTIME: usize = bpf_intf::global_stat_id_GSTAT_FIXUP_VTIME as usize;
const GSTAT_PREEMPTING_MISMATCH: usize =
    bpf_intf::global_stat_id_GSTAT_PREEMPTING_MISMATCH as usize;

const LSTAT_SEL_LOCAL: usize = bpf_intf::layer_stat_id_LSTAT_SEL_LOCAL as usize;
const LSTAT_ENQ_LOCAL: usize = bpf_intf::layer_stat_id_LSTAT_ENQ_LOCAL as usize;
const LSTAT_ENQ_WAKEUP: usize = bpf_intf::layer_stat_id_LSTAT_ENQ_WAKEUP as usize;
const LSTAT_ENQ_EXPIRE: usize = bpf_intf::layer_stat_id_LSTAT_ENQ_EXPIRE as usize;
const LSTAT_ENQ_REENQ: usize = bpf_intf::layer_stat_id_LSTAT_ENQ_REENQ as usize;
const LSTAT_ENQ_DSQ: usize = bpf_intf::layer_stat_id_LSTAT_ENQ_DSQ as usize;
const LSTAT_MIN_EXEC: usize = bpf_intf::layer_stat_id_LSTAT_MIN_EXEC as usize;
const LSTAT_MIN_EXEC_NS: usize = bpf_intf::layer_stat_id_LSTAT_MIN_EXEC_NS as usize;
const LSTAT_OPEN_IDLE: usize = bpf_intf::layer_stat_id_LSTAT_OPEN_IDLE as usize;
const LSTAT_AFFN_VIOL: usize = bpf_intf::layer_stat_id_LSTAT_AFFN_VIOL as usize;
const LSTAT_KEEP: usize = bpf_intf::layer_stat_id_LSTAT_KEEP as usize;
const LSTAT_KEEP_FAIL_MAX_EXEC: usize = bpf_intf::layer_stat_id_LSTAT_KEEP_FAIL_MAX_EXEC as usize;
const LSTAT_KEEP_FAIL_BUSY: usize = bpf_intf::layer_stat_id_LSTAT_KEEP_FAIL_BUSY as usize;
const LSTAT_PREEMPT: usize = bpf_intf::layer_stat_id_LSTAT_PREEMPT as usize;
const LSTAT_PREEMPT_FIRST: usize = bpf_intf::layer_stat_id_LSTAT_PREEMPT_FIRST as usize;
const LSTAT_PREEMPT_XLLC: usize = bpf_intf::layer_stat_id_LSTAT_PREEMPT_XLLC as usize;
const LSTAT_PREEMPT_XNUMA: usize = bpf_intf::layer_stat_id_LSTAT_PREEMPT_XNUMA as usize;
const LSTAT_PREEMPT_IDLE: usize = bpf_intf::layer_stat_id_LSTAT_PREEMPT_IDLE as usize;
const LSTAT_PREEMPT_FAIL: usize = bpf_intf::layer_stat_id_LSTAT_PREEMPT_FAIL as usize;
const LSTAT_EXCL_COLLISION: usize = bpf_intf::layer_stat_id_LSTAT_EXCL_COLLISION as usize;
const LSTAT_EXCL_PREEMPT: usize = bpf_intf::layer_stat_id_LSTAT_EXCL_PREEMPT as usize;
const LSTAT_YIELD: usize = bpf_intf::layer_stat_id_LSTAT_YIELD as usize;
const LSTAT_YIELD_IGNORE: usize = bpf_intf::layer_stat_id_LSTAT_YIELD_IGNORE as usize;
const LSTAT_MIGRATION: usize = bpf_intf::layer_stat_id_LSTAT_MIGRATION as usize;
const LSTAT_XNUMA_MIGRATION: usize = bpf_intf::layer_stat_id_LSTAT_XNUMA_MIGRATION as usize;
const LSTAT_XLLC_MIGRATION: usize = bpf_intf::layer_stat_id_LSTAT_XLLC_MIGRATION as usize;
const LSTAT_XLLC_MIGRATION_SKIP: usize = bpf_intf::layer_stat_id_LSTAT_XLLC_MIGRATION_SKIP as usize;
const LSTAT_XLAYER_WAKE: usize = bpf_intf::layer_stat_id_LSTAT_XLAYER_WAKE as usize;
const LSTAT_XLAYER_REWAKE: usize = bpf_intf::layer_stat_id_LSTAT_XLAYER_REWAKE as usize;
const LSTAT_LLC_DRAIN_TRY: usize = bpf_intf::layer_stat_id_LSTAT_LLC_DRAIN_TRY as usize;
const LSTAT_LLC_DRAIN: usize = bpf_intf::layer_stat_id_LSTAT_LLC_DRAIN as usize;
const LSTAT_SKIP_REMOTE_NODE: usize = bpf_intf::layer_stat_id_LSTAT_SKIP_REMOTE_NODE as usize;

const LLC_LSTAT_LAT: usize = bpf_intf::llc_layer_stat_id_LLC_LSTAT_LAT as usize;
const LLC_LSTAT_CNT: usize = bpf_intf::llc_layer_stat_id_LLC_LSTAT_CNT as usize;

fn calc_frac(a: f64, b: f64) -> f64 {
    if b != 0.0 {
        a / b * 100.0
    } else {
        0.0
    }
}

fn fmt_pct(v: f64) -> String {
    if v >= 99.995 {
        format!("{:5.1}", v)
    } else if v > 0.0 && v < 0.01 {
        format!("{:5.2}", 0.01)
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

#[stat_doc]
#[derive(Clone, Debug, Default, Serialize, Deserialize, Stats)]
#[stat(_om_prefix = "l_", _om_label = "layer_name")]
pub struct LayerStats {
    #[stat(desc = "index", _om_skip)]
    pub index: usize,
    #[stat(desc = "Total CPU utilization (100% means one full CPU)")]
    pub util: f64,
    #[stat(desc = "Protected CPU utilization %")]
    pub util_protected_frac: f64,
    #[stat(desc = "Preempt-protected CPU utilization %")]
    pub util_protected_preempt_frac: f64,
    #[stat(desc = "Open CPU utilization %")]
    pub util_open_frac: f64,
    #[stat(desc = "fraction of total CPU utilization")]
    pub util_frac: f64,
    #[stat(desc = "number of tasks")]
    pub tasks: u32,
    #[stat(desc = "count of sched events during the period")]
    pub total: u64,
    #[stat(desc = "% dispatched into idle CPU from select_cpu")]
    pub sel_local: f64,
    #[stat(desc = "% dispatched into idle CPU from enqueue")]
    pub enq_local: f64,
    #[stat(desc = "% enqueued after wakeup")]
    pub enq_wakeup: f64,
    #[stat(desc = "% enqueued after slice expiration")]
    pub enq_expire: f64,
    #[stat(desc = "% re-enqueued due to RT preemption")]
    pub enq_reenq: f64,
    #[stat(desc = "% enqueued into the layer's LLC DSQs")]
    pub enq_dsq: f64,
    #[stat(desc = "count of times exec duration < min_exec_us")]
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
    #[stat(desc = "count of times an excl task skipped a CPU as the sibling was also excl")]
    pub excl_collision: f64,
    #[stat(desc = "% a sibling CPU was preempted for an exclusive task")]
    pub excl_preempt: f64,
    #[stat(desc = "% yielded")]
    pub yielded: f64,
    #[stat(desc = "count of times yield was ignored")]
    pub yield_ignore: u64,
    #[stat(desc = "% migrated across CPUs")]
    pub migration: f64,
    #[stat(desc = "% migrated across NUMA nodes")]
    pub xnuma_migration: f64,
    #[stat(desc = "% migrated across LLCs")]
    pub xllc_migration: f64,
    #[stat(desc = "% migration skipped across LLCs due to xllc_mig_min_us")]
    pub xllc_migration_skip: f64,
    #[stat(desc = "% wakers across layers")]
    pub xlayer_wake: f64,
    #[stat(desc = "% rewakers across layers where waker has waken the task previously")]
    pub xlayer_rewake: f64,
    #[stat(desc = "% LLC draining tried")]
    pub llc_drain_try: f64,
    #[stat(desc = "% LLC draining succeeded")]
    pub llc_drain: f64,
    #[stat(desc = "% skip LLC dispatch on remote node")]
    pub skip_remote_node: f64,
    #[stat(desc = "mask of allocated CPUs", _om_skip)]
    pub cpus: Vec<u64>,
    #[stat(desc = "count of CPUs assigned")]
    pub cur_nr_cpus: u32,
    #[stat(desc = "minimum # of CPUs assigned")]
    pub min_nr_cpus: u32,
    #[stat(desc = "maximum # of CPUs assigned")]
    pub max_nr_cpus: u32,
    #[stat(desc = "count of CPUs assigned per LLC")]
    pub nr_llc_cpus: Vec<u32>,
    #[stat(desc = "slice duration config")]
    pub slice_us: u64,
    #[stat(desc = "Per-LLC scheduling event fractions")]
    pub llc_fracs: Vec<f64>,
    #[stat(desc = "Per-LLC average latency")]
    pub llc_lats: Vec<f64>,
    #[stat(desc = "Layer memory bandwidth as a % of total allowed (0 for \"no limit\"")]
    pub membw_pct: f64,
    #[stat(desc = "DSQ insertion ratio EWMA (10s window)")]
    pub dsq_insert_ewma: f64,
}

impl LayerStats {
    pub fn new(
        lidx: usize,
        layer: &Layer,
        stats: &Stats,
        bstats: &BpfStats,
        nr_cpus_range: (usize, usize),
    ) -> Self {
        let lstat = |sidx| bstats.lstats[lidx][sidx];
        let ltotal = lstat(LSTAT_SEL_LOCAL)
            + lstat(LSTAT_ENQ_LOCAL)
            + lstat(LSTAT_ENQ_WAKEUP)
            + lstat(LSTAT_ENQ_EXPIRE)
            + lstat(LSTAT_ENQ_REENQ)
            + lstat(LSTAT_KEEP);
        let lstat_pct = |sidx| {
            if ltotal != 0 {
                lstat(sidx) as f64 / ltotal as f64 * 100.0
            } else {
                0.0
            }
        };

        let util_sum = stats.layer_utils[lidx]
            .iter()
            .take(LAYER_USAGE_SUM_UPTO + 1)
            .sum::<f64>();

        let membw_frac = match &layer.kind {
            // Open layer's can't have a memory BW limit.
            LayerKind::Open { .. } => 0.0,
            LayerKind::Confined { membw_gb, .. } | LayerKind::Grouped { membw_gb, .. } => {
                // Check if we have set a memory BW limit.
                if let Some(membw_limit_gb) = membw_gb {
                    stats.layer_membws[lidx]
                        .iter()
                        .take(LAYER_USAGE_SUM_UPTO + 1)
                        .sum::<f64>()
                        / ((*membw_limit_gb * (1024_u64.pow(3) as f64)) as f64)
                } else {
                    0.0
                }
            }
        };

        Self {
            index: lidx,
            util: util_sum * 100.0,
            util_open_frac: calc_frac(stats.layer_utils[lidx][LAYER_USAGE_OPEN], util_sum),
            util_protected_frac: calc_frac(
                stats.layer_utils[lidx][LAYER_USAGE_PROTECTED],
                util_sum,
            ),
            util_protected_preempt_frac: calc_frac(
                stats.layer_utils[lidx][LAYER_USAGE_PROTECTED_PREEMPT],
                util_sum,
            ),
            util_frac: calc_frac(util_sum, stats.total_util),
            tasks: stats.nr_layer_tasks[lidx] as u32,
            total: ltotal,
            sel_local: lstat_pct(LSTAT_SEL_LOCAL),
            enq_local: lstat_pct(LSTAT_ENQ_LOCAL),
            enq_wakeup: lstat_pct(LSTAT_ENQ_WAKEUP),
            enq_expire: lstat_pct(LSTAT_ENQ_EXPIRE),
            enq_reenq: lstat_pct(LSTAT_ENQ_REENQ),
            enq_dsq: lstat_pct(LSTAT_ENQ_DSQ),
            min_exec: lstat_pct(LSTAT_MIN_EXEC),
            min_exec_us: (lstat(LSTAT_MIN_EXEC_NS) / 1000) as u64,
            open_idle: lstat_pct(LSTAT_OPEN_IDLE),
            preempt: lstat_pct(LSTAT_PREEMPT),
            preempt_xllc: lstat_pct(LSTAT_PREEMPT_XLLC),
            preempt_xnuma: lstat_pct(LSTAT_PREEMPT_XNUMA),
            preempt_first: lstat_pct(LSTAT_PREEMPT_FIRST),
            preempt_idle: lstat_pct(LSTAT_PREEMPT_IDLE),
            preempt_fail: lstat_pct(LSTAT_PREEMPT_FAIL),
            affn_viol: lstat_pct(LSTAT_AFFN_VIOL),
            keep: lstat_pct(LSTAT_KEEP),
            keep_fail_max_exec: lstat_pct(LSTAT_KEEP_FAIL_MAX_EXEC),
            keep_fail_busy: lstat_pct(LSTAT_KEEP_FAIL_BUSY),
            is_excl: layer.kind.common().exclusive as u32,
            excl_collision: lstat_pct(LSTAT_EXCL_COLLISION),
            excl_preempt: lstat_pct(LSTAT_EXCL_PREEMPT),
            yielded: lstat_pct(LSTAT_YIELD),
            yield_ignore: lstat(LSTAT_YIELD_IGNORE) as u64,
            migration: lstat_pct(LSTAT_MIGRATION),
            xnuma_migration: lstat_pct(LSTAT_XNUMA_MIGRATION),
            xlayer_wake: lstat_pct(LSTAT_XLAYER_WAKE),
            xlayer_rewake: lstat_pct(LSTAT_XLAYER_REWAKE),
            xllc_migration: lstat_pct(LSTAT_XLLC_MIGRATION),
            xllc_migration_skip: lstat_pct(LSTAT_XLLC_MIGRATION_SKIP),
            llc_drain_try: lstat_pct(LSTAT_LLC_DRAIN_TRY),
            llc_drain: lstat_pct(LSTAT_LLC_DRAIN),
            skip_remote_node: lstat_pct(LSTAT_SKIP_REMOTE_NODE),
            cpus: layer.cpus.as_raw_slice().to_vec(),
            cur_nr_cpus: layer.cpus.weight() as u32,
            min_nr_cpus: nr_cpus_range.0 as u32,
            max_nr_cpus: nr_cpus_range.1 as u32,
            nr_llc_cpus: layer.nr_llc_cpus.iter().map(|&v| v as u32).collect(),
            slice_us: stats.layer_slice_us[lidx],
            llc_fracs: {
                let sid = LLC_LSTAT_CNT;
                let sum = bstats.llc_lstats[lidx]
                    .iter()
                    .map(|lstats| lstats[sid])
                    .sum::<u64>() as f64;
                bstats.llc_lstats[lidx]
                    .iter()
                    .map(|lstats| calc_frac(lstats[sid] as f64, sum))
                    .collect()
            },
            llc_lats: bstats.llc_lstats[lidx]
                .iter()
                .map(|lstats| lstats[LLC_LSTAT_LAT] as f64 / 1_000_000_000.0)
                .collect(),
            membw_pct: membw_frac * 100.0,
            dsq_insert_ewma: stats.layer_dsq_insert_ewma[lidx] * 100.0,
        }
    }

    pub fn format<W: Write>(&self, w: &mut W, name: &str, header_width: usize) -> Result<()> {
        writeln!(
            w,
            "  {:<width$}: util/open/frac={:6.1}/{}/{:7.1} prot/prot_preempt={}/{} tasks={:6}",
            name,
            self.util,
            fmt_pct(self.util_open_frac),
            self.util_frac,
            fmt_pct(self.util_protected_frac),
            fmt_pct(self.util_protected_preempt_frac),
            self.tasks,
            width = header_width,
        )?;

        writeln!(
            w,
            "  {:<width$}  tot={:7} local_sel/enq={}/{} enq_dsq={} wake/exp/reenq={}/{}/{} dsq_ewma={}",
            "",
            self.total,
            fmt_pct(self.sel_local),
            fmt_pct(self.enq_local),
            fmt_pct(self.enq_dsq),
            fmt_pct(self.enq_wakeup),
            fmt_pct(self.enq_expire),
            fmt_pct(self.enq_reenq),
            fmt_pct(self.dsq_insert_ewma),
            width = header_width,
        )?;

        writeln!(
            w,
            "  {:<width$}  keep/max/busy={}/{}/{} yield/ign={}/{}",
            "",
            fmt_pct(self.keep),
            fmt_pct(self.keep_fail_max_exec),
            fmt_pct(self.keep_fail_busy),
            fmt_pct(self.yielded),
            fmt_num(self.yield_ignore),
            width = header_width,
        )?;

        writeln!(
            w,
            "  {:<width$}  open_idle={} mig={} xnuma_mig={} xllc_mig/skip={}/{} affn_viol={}",
            "",
            fmt_pct(self.open_idle),
            fmt_pct(self.migration),
            fmt_pct(self.xnuma_migration),
            fmt_pct(self.xllc_migration),
            fmt_pct(self.xllc_migration_skip),
            fmt_pct(self.affn_viol),
            width = header_width,
        )?;

        writeln!(
            w,
            "  {:<width$}  preempt/first/xllc/xnuma/idle/fail={}/{}/{}/{}/{}/{}",
            "",
            fmt_pct(self.preempt),
            fmt_pct(self.preempt_first),
            fmt_pct(self.preempt_xllc),
            fmt_pct(self.preempt_xnuma),
            fmt_pct(self.preempt_idle),
            fmt_pct(self.preempt_fail),
            width = header_width,
        )?;

        writeln!(
            w,
            "  {:<width$}  xlayer_wake/re={}/{} llc_drain/try={}/{} skip_rnode={}",
            "",
            fmt_pct(self.xlayer_wake),
            fmt_pct(self.xlayer_rewake),
            fmt_pct(self.llc_drain),
            fmt_pct(self.llc_drain_try),
            fmt_pct(self.skip_remote_node),
            width = header_width,
        )?;

        writeln!(
            w,
            "  {:<width$}  slice={}ms min_exec={}/{:7.2}ms",
            "",
            self.slice_us as f64 / 1000.0,
            fmt_pct(self.min_exec),
            self.min_exec_us as f64 / 1000.0,
            width = header_width
        )?;

        let cpumask = Cpumask::from_vec(self.cpus.clone());

        writeln!(
            w,
            "  {:<width$}  cpus={:3} [{:3},{:3}] {}",
            "",
            self.cur_nr_cpus,
            self.min_nr_cpus,
            self.max_nr_cpus,
            &cpumask,
            width = header_width
        )?;

        write!(
            w,
            "  {:<width$}  [LLC] nr_cpus: sched% lat_ms",
            "",
            width = header_width
        )?;

        for (i, (&frac, &lat)) in self.llc_fracs.iter().zip(self.llc_lats.iter()).enumerate() {
            if (i % 4) == 0 {
                writeln!(w, "")?;
                write!(w, "  {:<width$}  [{:03}]", "", i, width = header_width)?;
            } else {
                write!(w, " |")?;
            }
            write!(
                w,
                " {:2}:{}%{:7.2}",
                self.nr_llc_cpus[i],
                fmt_pct(frac),
                lat * 1_000.0
            )?;
        }
        writeln!(w, "")?;

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

#[stat_doc]
#[derive(Clone, Debug, Default, Serialize, Deserialize, Stats)]
#[stat(top)]
pub struct SysStats {
    #[stat(desc = "timestamp", _om_skip)]
    pub at: f64,
    #[stat(desc = "# of NUMA nodes")]
    pub nr_nodes: usize,
    #[stat(desc = "# sched events during the period")]
    pub total: u64,
    #[stat(desc = "% dispatched directly into an idle CPU from select_cpu")]
    pub local_sel: f64,
    #[stat(desc = "% dispatched directly into an idle CPU from enqueue")]
    pub local_enq: f64,
    #[stat(desc = "% open layer tasks scheduled into allocated but idle CPUs")]
    pub open_idle: f64,
    #[stat(desc = "% violated config due to CPU affinity")]
    pub affn_viol: f64,
    #[stat(desc = "% sent to hi fallback DSQs")]
    pub hi_fb: f64,
    #[stat(desc = "% sent to lo fallback DSQs")]
    pub lo_fb: f64,
    #[stat(desc = "count of times an excl task skipped a CPU as the sibling was also excl")]
    pub excl_collision: f64,
    #[stat(desc = "count of times a sibling CPU was preempted for an excl task")]
    pub excl_preempt: f64,
    #[stat(desc = "count of times a CPU skipped dispatching due to an excl task on the sibling")]
    pub excl_idle: f64,
    #[stat(
        desc = "count of times an idle sibling CPU was woken up after an excl task is finished"
    )]
    pub excl_wakeup: f64,
    #[stat(desc = "CPU time this binary consumed during the period")]
    pub proc_ms: u64,
    #[stat(desc = "CPU busy % (100% means all CPU)")]
    pub busy: f64,
    #[stat(desc = "CPU util % (100% means one CPU)")]
    pub util: f64,
    #[stat(desc = "CPU util % used by hi fallback DSQs")]
    pub hi_fb_util: f64,
    #[stat(desc = "CPU util % used by lo fallback DSQs")]
    pub lo_fb_util: f64,
    #[stat(desc = "Number of tasks dispatched via antistall")]
    pub antistall: u64,
    #[stat(desc = "Number of times preemptions of non-scx tasks were avoided")]
    pub skip_preempt: u64,
    #[stat(desc = "Number of times vtime was out of range and fixed up")]
    pub fixup_vtime: u64,
    #[stat(desc = "Number of times cpuc->preempting_task didn't come on the CPU")]
    pub preempting_mismatch: u64,
    #[stat(desc = "fallback CPU")]
    pub fallback_cpu: u32,
    #[stat(desc = "per-layer statistics")]
    pub fallback_cpu_util: f64,
    #[stat(desc = "fallback CPU util %")]
    pub layers: BTreeMap<String, LayerStats>,
    #[stat(desc = "Number of gpu tasks affinitized since scheduler start")]
    pub gpu_tasks_affinitized: u64,
    #[stat(desc = "Time (in ms) of last affinitization run.")]
    pub gpu_task_affinitization_ms: u64,
    #[stat(desc = "System CPU utilization EWMA (10s window)")]
    pub system_cpu_util_ewma: f64,
}

impl SysStats {
    pub fn new(stats: &Stats, bstats: &BpfStats, fallback_cpu: usize) -> Result<Self> {
        let lsum = |idx| stats.bpf_stats.lstats_sums[idx];
        let total = lsum(LSTAT_SEL_LOCAL)
            + lsum(LSTAT_ENQ_LOCAL)
            + lsum(LSTAT_ENQ_WAKEUP)
            + lsum(LSTAT_ENQ_EXPIRE)
            + lsum(LSTAT_ENQ_REENQ)
            + lsum(LSTAT_KEEP);
        let lsum_pct = |idx| {
            if total != 0 {
                lsum(idx) as f64 / total as f64 * 100.0
            } else {
                0.0
            }
        };

        let elapsed_ns = stats.elapsed.as_nanos();

        Ok(Self {
            at: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs_f64(),
            nr_nodes: stats.nr_nodes,
            total,
            local_sel: lsum_pct(LSTAT_SEL_LOCAL),
            local_enq: lsum_pct(LSTAT_ENQ_LOCAL),
            open_idle: lsum_pct(LSTAT_OPEN_IDLE),
            affn_viol: lsum_pct(LSTAT_AFFN_VIOL),
            hi_fb: calc_frac(
                stats.bpf_stats.gstats[GSTAT_HI_FB_EVENTS] as f64,
                total as f64,
            ),
            lo_fb: calc_frac(
                stats.bpf_stats.gstats[GSTAT_LO_FB_EVENTS] as f64,
                total as f64,
            ),
            excl_collision: lsum_pct(LSTAT_EXCL_COLLISION),
            excl_preempt: lsum_pct(LSTAT_EXCL_PREEMPT),
            excl_idle: bstats.gstats[GSTAT_EXCL_IDLE] as f64 / total as f64,
            excl_wakeup: bstats.gstats[GSTAT_EXCL_WAKEUP] as f64 / total as f64,
            proc_ms: stats.processing_dur.as_millis() as u64,
            busy: stats.cpu_busy * 100.0,
            util: stats.total_util * 100.0,
            hi_fb_util: stats.bpf_stats.gstats[GSTAT_HI_FB_USAGE] as f64 / elapsed_ns as f64
                * 100.0,
            lo_fb_util: stats.bpf_stats.gstats[GSTAT_LO_FB_USAGE] as f64 / elapsed_ns as f64
                * 100.0,
            antistall: stats.bpf_stats.gstats[GSTAT_ANTISTALL],
            skip_preempt: stats.bpf_stats.gstats[GSTAT_SKIP_PREEMPT],
            fixup_vtime: stats.bpf_stats.gstats[GSTAT_FIXUP_VTIME],
            preempting_mismatch: stats.bpf_stats.gstats[GSTAT_PREEMPTING_MISMATCH],
            fallback_cpu: fallback_cpu as u32,
            fallback_cpu_util: stats.bpf_stats.gstats[GSTAT_FB_CPU_USAGE] as f64
                / elapsed_ns as f64
                * 100.0,
            layers: BTreeMap::new(),
            gpu_tasks_affinitized: stats.gpu_tasks_affinitized,
            gpu_task_affinitization_ms: stats.gpu_task_affinitization_ms,
            system_cpu_util_ewma: stats.system_cpu_util_ewma * 100.0,
        })
    }

    pub fn format<W: Write>(&self, w: &mut W) -> Result<()> {
        writeln!(
            w,
            "tot={:7} local_sel/enq={}/{} open_idle={} affn_viol={} hi/lo={}/{}",
            self.total,
            fmt_pct(self.local_sel),
            fmt_pct(self.local_enq),
            fmt_pct(self.open_idle),
            fmt_pct(self.affn_viol),
            fmt_pct(self.hi_fb),
            fmt_pct(self.lo_fb),
        )?;

        writeln!(
            w,
            "busy={:5.1} util/hi/lo={:7.1}/{}/{} fallback_cpu/util={:3}/{:4.1} proc={:?}ms sys_util_ewma={:5.1}",
            self.busy,
            self.util,
            fmt_pct(self.hi_fb_util),
            fmt_pct(self.lo_fb_util),
            self.fallback_cpu,
            self.fallback_cpu_util,
            self.proc_ms,
            self.system_cpu_util_ewma,
        )?;

        writeln!(
            w,
            "excl_coll={:.2} excl_preempt={:.2} excl_idle={:.2} excl_wakeup={:.2}",
            self.excl_collision, self.excl_preempt, self.excl_idle, self.excl_wakeup
        )?;

        writeln!(
            w,
            "skip_preempt={} antistall={} fixup_vtime={} preempting_mismatch={}",
            self.skip_preempt, self.antistall, self.fixup_vtime, self.preempting_mismatch
        )?;

        writeln!(
            w,
            "gpu_tasks_affinitized={} gpu_task_affinitization_time={}",
            self.gpu_tasks_affinitized, self.gpu_task_affinitization_ms
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

        let mut idx_to_name: Vec<(usize, &String)> =
            self.layers.iter().map(|(k, v)| (v.index, k)).collect();

        idx_to_name.sort();

        for (_idx, name) in &idx_to_name {
            self.layers[*name].format(w, name, header_width)?;
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
            res => bail!("invalid response to Hello: {:?}", res),
        });

        let read: Box<dyn StatsReader<StatsReq, StatsRes>> =
            Box::new(move |_args, (req_ch, res_ch)| {
                req_ch.send(StatsReq::Refresh(tid, stats.take().unwrap()))?;
                let (new_stats, sys_stats) = match res_ch.recv()? {
                    StatsRes::Refreshed(v) => v,
                    res => bail!("invalid response to Refresh: {:?}", res),
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
            res => panic!("invalid response to Bye: {:?}", res),
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
        &[],
        intv,
        || shutdown.load(Ordering::Relaxed),
        |sst| {
            let dt = DateTime::<Local>::from(UNIX_EPOCH + Duration::from_secs_f64(sst.at));
            println!("###### {} ######", dt.to_rfc2822());
            sst.format_all(&mut std::io::stdout())
        },
    )
}
