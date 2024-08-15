use crate::bpf_intf;
use crate::now_monotonic;
use crate::BpfStats;
use crate::Layer;
use crate::LayerKind;
use crate::Stats;
use anyhow::Result;
use log::info;
use log::warn;
use scx_stats::Meta;
use scx_stats::ScxStatsClient;
use scx_stats::ScxStatsServer;
use scx_stats::ToJson;
use scx_stats_derive::Stats;
use serde::Deserialize;
use serde::Serialize;
use std::sync::Mutex;
use std::collections::BTreeMap;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

#[derive(Clone, Debug, Default, Serialize, Deserialize, Stats)]
pub struct LayerStats {
    #[stat(desc = "CPU utilization of the layer (100% means one CPU was fully occupied)")]
    pub util: f64,
    #[stat(desc = "Fraction of total CPU utilization consumed by the layer")]
    pub util_frac: f64,
    #[stat(desc = "Sum of weight * duty_cycle for tasks in the layer")]
    pub load: f64,
    #[stat(desc = "Fraction of total load consumed by the layer")]
    pub load_frac: f64,
    #[stat(desc = "Number of tasks in the layer")]
    pub tasks: u32,
    #[stat(desc = "Number of scheduling events in the layer")]
    pub total: u64,
    #[stat(desc = "% of scheduling events directly into an idle CPU")]
    pub sel_local: f64,
    #[stat(desc = "% of scheduling events enqueued to layer after wakeup")]
    pub enq_wakeup: f64,
    #[stat(desc = "% of scheduling events enqueued to layer after slice expiration")]
    pub enq_expire: f64,
    #[stat(desc = "% of scheduling events enqueued as last runnable task on CPU")]
    pub enq_last: f64,
    #[stat(desc = "% of scheduling events re-enqueued due to RT preemption")]
    pub enq_reenq: f64,
    #[stat(desc = "Number of times execution duration was shorter than min_exec_us")]
    pub min_exec: f64,
    #[stat(desc = "Total execution duration extended due to min_exec_us")]
    pub min_exec_us: u64,
    #[stat(desc = "% of scheduling events into idle CPUs occupied by other layers")]
    pub open_idle: f64,
    #[stat(desc = "% of scheduling events that preempted other tasks")]
    pub preempt: f64,
    #[stat(desc = "% of scheduling events that first-preempted other tasks")]
    pub preempt_first: f64,
    #[stat(desc = "% of scheduling events that idle-preempted other tasks")]
    pub preempt_idle: f64,
    #[stat(desc = "% of scheduling events that attempted to preempt other tasks but failed")]
    pub preempt_fail: f64,
    #[stat(
        desc = "% of scheduling events that violated configured policies due to CPU affinity restrictions"
    )]
    pub affn_viol: f64,
    #[stat(desc = "% of scheduling events that continued executing after slice expiration")]
    pub keep: f64,
    #[stat(
        desc = "% of scheduling events that weren't allowed to continue executing after slice expiration due to overrunning max_exec duration limit"
    )]
    pub keep_fail_max_exec: f64,
    #[stat(
        desc = "% of scheduling events that weren't allowed to continue executing after slice expiration to accommodate other tasks"
    )]
    pub keep_fail_busy: f64,
    #[stat(desc = "Whether layer is exclusive")]
    pub is_excl: u32,
    #[stat(
        desc = "Number of times an exclusive task skipped a CPU as the sibling was also exclusive"
    )]
    pub excl_collision: f64,
    #[stat(desc = "Number of times a sibling CPU was preempted for an exclusive task")]
    pub excl_preempt: f64,
    #[stat(desc = "% of schduling events that kicked a CPU from enqueue path")]
    pub kick: f64,
    #[stat(desc = "% of scheduling events that yielded")]
    pub yielded: f64,
    #[stat(desc = "Number of times yield was ignored")]
    pub yield_ignore: u64,
    #[stat(desc = "% of scheduling events that migrated across CPUs")]
    pub migration: f64,
    #[stat(desc = "Current # of CPUs assigned to the layer")]
    pub cur_nr_cpus: u32,
    #[stat(desc = "Minimum # of CPUs assigned to the layer")]
    pub min_nr_cpus: u32,
    #[stat(desc = "Maximum # of CPUs assigned to the layer")]
    pub max_nr_cpus: u32,
}

impl LayerStats {
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
            + lstat(bpf_intf::layer_stat_idx_LSTAT_ENQ_LAST)
            + lstat(bpf_intf::layer_stat_idx_LSTAT_ENQ_REENQ);
        let lstat_pct = |sidx| {
            if ltotal != 0 {
                lstat(sidx) as f64 / ltotal as f64 * 100.0
            } else {
                0.0
            }
        };
        let calc_frac = |a, b| {
            if b != 0.0 {
                a / b * 100.0
            } else {
                0.0
            }
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
            enq_last: lstat_pct(bpf_intf::layer_stat_idx_LSTAT_ENQ_LAST),
            enq_reenq: lstat_pct(bpf_intf::layer_stat_idx_LSTAT_ENQ_REENQ),
            min_exec: lstat_pct(bpf_intf::layer_stat_idx_LSTAT_MIN_EXEC),
            min_exec_us: (lstat(bpf_intf::layer_stat_idx_LSTAT_MIN_EXEC_NS) / 1000) as u64,
            open_idle: lstat_pct(bpf_intf::layer_stat_idx_LSTAT_OPEN_IDLE),
            preempt: lstat_pct(bpf_intf::layer_stat_idx_LSTAT_PREEMPT),
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
            cur_nr_cpus: layer.cpus.count_ones() as u32,
            min_nr_cpus: nr_cpus_range.0 as u32,
            max_nr_cpus: nr_cpus_range.1 as u32,
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, Stats)]
pub struct SysStats {
    #[stat(desc = "Update interval")]
    pub intv: f64,
    #[stat(desc = "Timestamp")]
    pub at: u64,
    #[stat(desc = "Total scheduling events in the period")]
    pub total: u64,
    #[stat(desc = "% that got scheduled directly into an idle CPU")]
    pub local: f64,
    #[stat(desc = "% of open layer tasks scheduled into occupied idle CPUs")]
    pub open_idle: f64,
    #[stat(desc = "% which violated configured policies due to CPU affinity restrictions")]
    pub affn_viol: f64,
    #[stat(
        desc = "Number of times an exclusive task skipped a CPU as the sibling was also exclusive"
    )]
    pub excl_collision: f64,
    #[stat(desc = "Number of times a sibling CPU was preempted for an exclusive task")]
    pub excl_preempt: f64,
    #[stat(
        desc = "Number of times a CPU skipped dispatching due to sibling running an exclusive task"
    )]
    pub excl_idle: f64,
    #[stat(
        desc = "Number of times an idle sibling CPU was woken up after an exclusive task is finished"
    )]
    pub excl_wakeup: f64,
    #[stat(desc = "CPU time this binary has consumed during the period")]
    pub proc_ms: u64,
    #[stat(desc = "CPU busy % (100% means all CPUs were fully occupied)")]
    pub busy: f64,
    #[stat(desc = "CPU utilization % (100% means one CPU was fully occupied)")]
    pub util: f64,
    #[stat(desc = "Sum of weight * duty_cycle for all tasks")]
    pub load: f64,
    #[stat(desc = "Fallback CPU")]
    pub fallback_cpu: u32,
    #[stat(desc = "Per-layer statistics")]
    pub layers: BTreeMap<String, LayerStats>,
}

impl SysStats {
    pub fn new(
        stats: &Stats,
        bstats: &BpfStats,
        intv: &Duration,
        proc_dur: &Duration,
        fallback_cpu: usize,
    ) -> Self {
        let lsum = |idx| stats.bpf_stats.lstats_sums[idx as usize];
        let total = lsum(bpf_intf::layer_stat_idx_LSTAT_SEL_LOCAL)
            + lsum(bpf_intf::layer_stat_idx_LSTAT_ENQ_WAKEUP)
            + lsum(bpf_intf::layer_stat_idx_LSTAT_ENQ_EXPIRE)
            + lsum(bpf_intf::layer_stat_idx_LSTAT_ENQ_LAST)
            + lsum(bpf_intf::layer_stat_idx_LSTAT_ENQ_REENQ);
        let lsum_pct = |idx| {
            if total != 0 {
                lsum(idx) as f64 / total as f64 * 100.0
            } else {
                0.0
            }
        };

        Self {
            intv: intv.as_secs_f64(),
            at: now_monotonic(),
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
            proc_ms: proc_dur.as_millis() as u64,
            busy: stats.cpu_busy * 100.0,
            util: stats.total_util * 100.0,
            load: stats.total_load,
            fallback_cpu: fallback_cpu as u32,
            layers: BTreeMap::new(),
        }
    }
}

fn print_sys_stats(s: &SysStats) {
    let fmt_pct = |v: f64| {
        if v >= 99.995 {
            format!("{:5.1}", v)
        } else {
            format!("{:5.2}", v)
        }
    };

    let fmt_num = |v: u64| {
        if v > 1_000_000 {
            format!("{:5.1}m", v as f64 / 1_000_000.0)
        } else if v > 1_000 {
            format!("{:5.1}k", v as f64 / 1_000.0)
        } else {
            format!("{:5.0} ", v)
        }
    };

    info!(
        "tot={:7} local={} open_idle={} affn_viol={} proc={:?}ms",
        s.total,
        fmt_pct(s.local),
        fmt_pct(s.open_idle),
        fmt_pct(s.affn_viol),
        s.proc_ms,
    );

    info!(
        "busy={:5.1} util={:7.1} load={:9.1} fallback_cpu={:3}",
        s.busy, s.util, s.load, s.fallback_cpu,
    );

    info!(
        "excl_coll={} excl_preempt={} excl_idle={} excl_wakeup={}",
        s.excl_collision, s.excl_preempt, s.excl_idle, s.excl_wakeup
    );

    let header_width = s
        .layers
        .keys()
        .map(|name| name.len())
        .max()
        .unwrap_or(0)
        .max(4);

    for (name, l) in s.layers.iter() {
        info!(
            "  {:<width$}: util/frac={:7.1}/{:5.1} load/frac={:9.1}:{:5.1} tasks={:6}",
            name,
            l.util,
            l.util_frac,
            l.load,
            l.load_frac,
            l.tasks,
            width = header_width,
        );
        info!(
            "  {:<width$}  tot={:7} local={} wake/exp/last/reenq={}/{}/{}/{}",
            "",
            l.total,
            fmt_pct(l.sel_local),
            fmt_pct(l.enq_wakeup),
            fmt_pct(l.enq_expire),
            fmt_pct(l.enq_last),
            fmt_pct(l.enq_reenq),
            width = header_width,
        );
        info!(
            "  {:<width$}  keep/max/busy={}/{}/{} kick={} yield/ign={}/{}",
            "",
            fmt_pct(l.keep),
            fmt_pct(l.keep_fail_max_exec),
            fmt_pct(l.keep_fail_busy),
            fmt_pct(l.kick),
            fmt_pct(l.yielded),
            fmt_num(l.yield_ignore),
            width = header_width,
        );
        info!(
            "  {:<width$}  open_idle={} mig={} affn_viol={}",
            "",
            fmt_pct(l.open_idle),
            fmt_pct(l.migration),
            fmt_pct(l.affn_viol),
            width = header_width,
        );
        info!(
            "  {:<width$}  preempt/first/idle/fail={}/{}/{}/{} min_exec={}/{:7.2}ms",
            "",
            fmt_pct(l.preempt),
            fmt_pct(l.preempt_first),
            fmt_pct(l.preempt_idle),
            fmt_pct(l.preempt_fail),
            fmt_pct(l.min_exec),
            l.min_exec_us as f64 / 1000.0,
            width = header_width,
        );
        info!(
            "  {:<width$}  cpus={:3} [{:3},{:3}]",
            "",
            l.cur_nr_cpus,
            l.min_nr_cpus,
            l.max_nr_cpus,
            //format_bitvec(&layer.cpus),
            width = header_width
        );
        if l.is_excl != 0 {
            info!(
                "  {:<width$}  excl_coll={} excl_preempt={}",
                "",
                fmt_pct(l.excl_collision),
                fmt_pct(l.excl_preempt),
                width = header_width,
            );
        } else if l.excl_collision != 0.0 || l.excl_preempt != 0.0 {
            warn!(
                "{}: exclusive is off but excl_coll={} excl_preempt={}",
                name,
                fmt_pct(l.excl_collision),
                fmt_pct(l.excl_preempt),
            );
        }
    }
}

pub fn launch_server(sys_stats: Arc<Mutex<SysStats>>) -> Result<()> {
    ScxStatsServer::new()
        .add_stats_meta(LayerStats::meta())
        .add_stats_meta(SysStats::meta())
        .add_stats(
            "all",
            Box::new(move |_| sys_stats.lock().unwrap().to_json()),
        )
        .launch()?;
    Ok(())
}

pub fn monitor(shutdown: Arc<AtomicBool>) -> Result<()> {
    let mut client = ScxStatsClient::new().connect()?;
    while !shutdown.load(Ordering::Relaxed) {
        let sst = client.request::<SysStats>("stat", vec![])?;
        print_sys_stats(&sst);
        std::thread::sleep(Duration::from_secs_f64(sst.intv));
    }
    Ok(())
}
