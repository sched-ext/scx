// SPDX-License-Identifier: GPL-2.0
//
// Copyright (c) 2026 Galih Tama <galpt@v.recipes>
//
// This software may be used and distributed according to the terms of the GNU
// General Public License version 2.

//! Stats server, `#[derive(Stats)]` metrics and monitor loop.
//!
//! `Metrics` corresponds to the BPF-side `struct mlfq_stats`: the type is
//! defined in `src/bpf/intf.h` and the `volatile` instance lives in
//! `src/bpf/main.bpf.c`, plus a userspace uptime gauge. Field names match
//! the BPF struct 1:1. The `top` stats op reports deltas over the poll
//! interval.

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
    #[stat(desc = "Tasks currently executing on a CPU")]
    pub on_cpu: u64,
    #[stat(desc = "Total CPU runtime in ns")]
    pub total_runtime: u64,
    #[stat(desc = "Scheduler uptime (wall clock since attach)")]
    pub uptime_ns: u64,
    #[stat(desc = "Tasks placed in Q1")]
    pub q1_placements: u64,
    #[stat(desc = "Tasks placed in Q2")]
    pub q2_placements: u64,
    #[stat(desc = "Tasks placed in Q3")]
    pub q3_placements: u64,
    #[stat(desc = "Queue promotions")]
    pub promotions: u64,
    #[stat(desc = "Queue demotions")]
    pub demotions: u64,
    #[stat(desc = "Aging boosts to Q1")]
    pub aging_boosts: u64,
    #[stat(desc = "Short-sleep and I/O wakeup boosts")]
    pub short_sleep_boosts: u64,
    #[stat(desc = "Wakeup preemption kicks")]
    pub preemption_kicks: u64,
    #[stat(desc = "Q1 cpuperf target boosts set on running")]
    pub cpuperf_boosts: u64,
    #[stat(desc = "Dispatch moves from remote queue DSQs")]
    pub steals: u64,
    /*
     * The dispatch steal is split by cache domain (see the two-tier
     * steal scan). The same-LLC tier moves work inside a domain, the
     * cross-LLC tier moves it between domains. steals == steals_same_llc +
     * steals_cross_llc whenever the LLC data is populated (mlfq_nr_llcs
     * > 0). A machine with LLC awareness disabled leaves the split
     * counters at 0 and all moves count as `steals`.
     */
    #[stat(desc = "Dispatch moves from remote queue DSQs within the same LLC")]
    pub steals_same_llc: u64,
    #[stat(desc = "Dispatch moves from remote queue DSQs across LLC domains")]
    pub steals_cross_llc: u64,
    #[stat(desc = "Solo-task keep-running grants on empty dispatch")]
    pub keep_running: u64,
    #[stat(desc = "Enqueues dropped when task state cannot be allocated")]
    pub enq_no_tctx: u64,
    #[stat(desc = "Enqueues dropped for bad weight")]
    pub enq_bad_weight: u64,
    #[stat(desc = "Enqueues dropped for missing placement")]
    pub enq_no_deadline: u64,
    #[stat(desc = "Fast-path enqueues")]
    pub enq_fastpath: u64,
    #[stat(desc = "Regular-path enqueues")]
    pub enq_regular: u64,
    #[stat(desc = "Pinned enqueues to idle CPUs")]
    pub enq_pinned_idle: u64,
    #[stat(desc = "Pinned enqueues to busy CPUs")]
    pub enq_pinned_busy: u64,
    #[stat(desc = "Pinned enqueues to the global DSQ")]
    pub enq_pinned_global: u64,
    #[stat(desc = "MLFQ tree inference walks run")]
    pub tree_inference: u64,
    #[stat(desc = "Classifications served by the EMA fallback while untrained")]
    pub tree_fallback: u64,
    #[stat(desc = "Tree queue mappings that disagree with the base EMA mapping")]
    pub tree_disagree: u64,
    #[stat(desc = "Training samples emitted to the daemon")]
    pub tree_samples_emitted: u64,
    #[stat(desc = "Training samples dropped (ring buffer full)")]
    pub tree_samples_dropped: u64,
    #[stat(desc = "Realtime/DL/stop takeovers of SCX CPUs observed by the sched_switch hook")]
    pub rt_takeovers: u64,
    #[stat(desc = "DSQ evacuation passes that ran on realtime takeovers")]
    pub rt_evacuations: u64,
    #[stat(desc = "Placements redirected off realtime-occupied CPUs")]
    pub rt_redirects: u64,
    #[stat(desc = "SCX_ENQ_REENQ re-enqueues counted at enqueue")]
    pub rt_reenqs: u64,
    #[stat(
        desc = "Per-op callback latency histogram, 4 ops x 8 buckets in microseconds (stopping, dispatch, enqueue, cpu_release)"
    )]
    pub op_lat: Vec<u64>,
    #[stat(desc = "Training samples dropped by the per-pid window cap")]
    pub tree_samples_cap_dropped: u64,
    #[stat(desc = "Committed tree model generation, 0 while untrained")]
    pub tree_model_generation: u64,
    #[stat(desc = "Training samples behind the committed tree model")]
    pub tree_model_samples: u64,
    #[stat(desc = "Nodes of the committed tree model")]
    pub tree_model_nodes: u64,
    #[stat(
        desc = "Committed tree MAE in microseconds on the held-out slice of its training window"
    )]
    pub tree_mae_tree_us: u64,
    #[stat(desc = "Exact EMA-baseline MAE in microseconds on the same held-out slice")]
    pub tree_mae_ema_us: u64,
    /* Pearson correlation of the committed model's burst predictions
     * with the labels on its held-out slice, scaled by 1000. Web UI
     * only, so it carries no stat description. */
    pub tree_corr_milli: i64,
    /*
     * System wakeup gauges and the effective adaptation state. The
     * gauges and the effective values are instantaneous pass-throughs
     * (the top op reports them as-is, like uptime_ns). The two counters
     * are interval deltas like the placement counters.
     */
    #[stat(desc = "System wakeup-latency gauge (1s half-life EMA), microseconds")]
    pub sys_lat_ema_us: u64,
    #[stat(desc = "System wakeup-rate gauge (1s half-life EMA), fixed point; >> 8 = wakeups/s")]
    pub sys_rate_ema: u64,
    #[stat(desc = "Effective EMA Q1/Q2 band edge, microseconds")]
    pub t_l_eff_us: u64,
    #[stat(desc = "Effective EMA Q2/Q3 band edge, microseconds")]
    pub t_h_eff_us: u64,
    #[stat(desc = "Effective tree Q1/Q2 band edge, microseconds")]
    pub t_int_eff_us: u64,
    #[stat(desc = "Effective tree Q2/Q3 band edge, microseconds")]
    pub t_bnd_eff_us: u64,
    #[stat(desc = "Effective same-queue preemption residency guard, microseconds")]
    pub guard_eff_us: u64,
    #[stat(desc = "Adaptation shift, fixed point (FP_ONE = 1.0)")]
    pub adapt_shift: i64,
    #[stat(desc = "Wakeup arrivals (interval delta)")]
    pub wakeup_total: u64,
    #[stat(desc = "Adaptation steps run (interval delta)")]
    pub adapt_steps: u64,
}

/// One entry of the web UI's per-CPU card grid.
///
/// The static fields (`freq_khz`, `llc_id`, `smt`) are seeded once at
/// attach from the host topology (`topology::web_cpu_static`); the
/// dynamic fields (`running_queue`, `running_pid`, `rt_occupied`,
/// `running_gpu_submit`) are refreshed from the BPF per-CPU maps on
/// every web-metrics poll. The carriers do not take part in the stats
/// server's `delta()` accounting.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct PerCpuMetrics {
    /// CPU id.
    pub id: u32,
    /// Maximum operating frequency of the CPU, in kHz.
    pub freq_khz: u64,
    /// Current operating frequency of the CPU, in kHz, refreshed from
    /// sysfs at most once per second while the web UI serves stats. 0
    /// when the cpufreq driver exposes no current frequency.
    pub cur_freq_khz: u64,
    /// LLC domain id of the CPU (0 when the domain is unknown).
    pub llc_id: u32,
    /// True when the CPU is the non-primary thread of an SMT core, the
    /// virtual sibling. Display-only, see `topology::web_cpu_static`.
    pub smt: bool,
    /// Queue of the currently running task (0 = idle, 1..3).
    pub running_queue: i32,
    /// PID of the currently running task, 0 when idle.
    pub running_pid: u32,
    /// True when a realtime-class task currently occupies the CPU.
    pub rt_occupied: bool,
    /// The `gpu_submit` value of the task now on this CPU, 0..4 in steps
    /// of FP_SHIFT. This is a snapshot of `mlfq_cpu_state.running_gpu_submit`
    /// (which mirrors `task_ctx.gpu_submit` at `ops.running()`), not a
    /// counter. It decays by one on long idle and is bumped at most once
    /// per 10 ms, so a burst of trace hits for one job counts as one.
    /// The system-wide lifetime total is `WebMetrics.gpu_submit_total`.
    #[serde(alias = "gpu_submit")]
    pub running_gpu_submit: u32,
}

/// Snapshot served by the web UI's `/api/stats` endpoint.
///
/// The run loop pushes one of these every iteration (both the stats
/// request and the idle-timeout branches); the webui thread keeps the
/// newest snapshot behind a mutex for the HTTP handlers. All fields are
/// instantaneous gauges, not interval deltas: the gauges bypass the
/// stats server's `delta()` entirely.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct WebMetrics {
    /// The scheduler-wide counters, raw (no delta applied).
    pub stats: Metrics,
    /// One entry per online CPU.
    pub per_cpu: Vec<PerCpuMetrics>,
    /// Tracked runnable tasks per queue; index 0 unused, 1..3 = Q1..Q3.
    pub queue_runnable: Vec<u64>,
    /// Tracked runnable tasks per LLC domain.
    pub llc_runnable: Vec<u64>,
    /// Lifetime count of deduped gpu_submit bumps since attach, one per
    /// 10 ms per-task window. This is the global hit counter
    /// (`mlfq_gpu_submit_total`), not the per-task 0..4 quant. Each
    /// logical GPU job that fires 2-3 tracepoints in a burst counts as
    /// one here, same window as `PerCpuMetrics.running_gpu_submit`.
    pub gpu_submit_total: u64,
    /// Bitmask of GPU tracepoints that are attached on this run (bit0
    /// amdgpu_cs, bit1 amdgpu_cs_ioctl, bit2 gpu_sched). Like
    /// `gpu_submit_total` this is a system gauge, not a per-task value.
    pub gpu_trace_mask: u32,
}

/// Bucket edges of the op-latency histogram, matching `enum
/// mlfq_op_lat_consts` in `src/bpf/intf.h`, in microseconds.
const OP_LAT_EDGES_US: [u64; 7] = [
    crate::bpf_intf::mlfq_op_lat_consts_MLFQ_OP_LAT_EDGE_2 as u64,
    crate::bpf_intf::mlfq_op_lat_consts_MLFQ_OP_LAT_EDGE_5 as u64,
    crate::bpf_intf::mlfq_op_lat_consts_MLFQ_OP_LAT_EDGE_10 as u64,
    crate::bpf_intf::mlfq_op_lat_consts_MLFQ_OP_LAT_EDGE_20 as u64,
    crate::bpf_intf::mlfq_op_lat_consts_MLFQ_OP_LAT_EDGE_50 as u64,
    crate::bpf_intf::mlfq_op_lat_consts_MLFQ_OP_LAT_EDGE_100 as u64,
    crate::bpf_intf::mlfq_op_lat_consts_MLFQ_OP_LAT_EDGE_250 as u64,
];

/// Format one op's eight bucket counts with their microsecond edges as
/// "low-high=count" pairs. A histogram shorter than eight buckets (the
/// untracked default) formats as "n/a".
fn fmt_op_lat(op: &[u64]) -> String {
    if op.len() < 8 {
        return "n/a".to_string();
    }
    let mut parts = Vec::new();
    parts.push(format!("0-{}={}", OP_LAT_EDGES_US[0], op[0]));
    for (i, edge) in OP_LAT_EDGES_US.iter().enumerate().skip(1) {
        parts.push(format!("{}-{}={}", OP_LAT_EDGES_US[i - 1], edge, op[i]));
    }
    parts.push(format!("{}+={}", OP_LAT_EDGES_US[6], op[7]));
    parts.join(" ")
}

impl Metrics {
    fn format<W: Write>(&self, w: &mut W) -> Result<()> {
        writeln!(
            w,
            "[{}] run={} runtime_ns={} uptime_ns={} \
             placements: Q1={} Q2={} Q3={} \
             promotions={} demotions={} aging_boosts={} short_sleep_boosts={} \
             preemption_kicks={} cpuperf_boosts={}",
            crate::SCHEDULER_NAME,
            self.on_cpu,
            self.total_runtime,
            self.uptime_ns,
            self.q1_placements,
            self.q2_placements,
            self.q3_placements,
            self.promotions,
            self.demotions,
            self.aging_boosts,
            self.short_sleep_boosts,
            self.preemption_kicks,
            self.cpuperf_boosts,
        )?;
        writeln!(
            w,
            "[{}] tree: gen={} nodes={} samples={} mae_tree={}us mae_ema={}us \
             inf={} fallback={} disagree={} emitted={} dropped={} cap_dropped={}",
            crate::SCHEDULER_NAME,
            self.tree_model_generation,
            self.tree_model_nodes,
            self.tree_model_samples,
            self.tree_mae_tree_us,
            self.tree_mae_ema_us,
            self.tree_inference,
            self.tree_fallback,
            self.tree_disagree,
            self.tree_samples_emitted,
            self.tree_samples_dropped,
            self.tree_samples_cap_dropped,
        )?;
        writeln!(
            w,
            "[{}] op_lat_us: stopping[{}] dispatch[{}]",
            crate::SCHEDULER_NAME,
            fmt_op_lat(self.op_lat.get(0..8).unwrap_or(&[])),
            fmt_op_lat(self.op_lat.get(8..16).unwrap_or(&[])),
        )?;
        writeln!(
            w,
            "[{}] op_lat_us: enqueue[{}] cpu_release[{}]",
            crate::SCHEDULER_NAME,
            fmt_op_lat(self.op_lat.get(16..24).unwrap_or(&[])),
            fmt_op_lat(self.op_lat.get(24..32).unwrap_or(&[])),
        )?;
        writeln!(
            w,
            "[{}] adapt: lat_ema={}us rate_ema={}w/s shift={}% T_L_eff={}us T_H_eff={}us T_INT_eff={}us T_BND_eff={}us guard_eff={}us wakeups={} steps={}",
            crate::SCHEDULER_NAME,
            self.sys_lat_ema_us,
            self.sys_rate_ema >> crate::bpf_intf::mlfq_consts_FP_SHIFT,
            self.adapt_shift * 100 / crate::bpf_intf::mlfq_consts_FP_ONE as i64,
            self.t_l_eff_us,
            self.t_h_eff_us,
            self.t_int_eff_us,
            self.t_bnd_eff_us,
            self.guard_eff_us,
            self.wakeup_total,
            self.adapt_steps,
        )?;
        Ok(())
    }

    /// Interval delta. Counters are wrapping deltas over the poll interval.
    /// Gauges (`on_cpu`, `uptime_ns`, the tree model metadata) pass through
    /// as instantaneous values.
    pub fn delta(&self, rhs: &Self) -> Self {
        Self {
            on_cpu: self.on_cpu,
            total_runtime: self.total_runtime.wrapping_sub(rhs.total_runtime),
            uptime_ns: self.uptime_ns,
            q1_placements: self.q1_placements.wrapping_sub(rhs.q1_placements),
            q2_placements: self.q2_placements.wrapping_sub(rhs.q2_placements),
            q3_placements: self.q3_placements.wrapping_sub(rhs.q3_placements),
            promotions: self.promotions.wrapping_sub(rhs.promotions),
            demotions: self.demotions.wrapping_sub(rhs.demotions),
            aging_boosts: self.aging_boosts.wrapping_sub(rhs.aging_boosts),
            short_sleep_boosts: self.short_sleep_boosts.wrapping_sub(rhs.short_sleep_boosts),
            preemption_kicks: self.preemption_kicks.wrapping_sub(rhs.preemption_kicks),
            cpuperf_boosts: self.cpuperf_boosts.wrapping_sub(rhs.cpuperf_boosts),
            steals: self.steals.wrapping_sub(rhs.steals),
            steals_same_llc: self.steals_same_llc.wrapping_sub(rhs.steals_same_llc),
            steals_cross_llc: self.steals_cross_llc.wrapping_sub(rhs.steals_cross_llc),
            keep_running: self.keep_running.wrapping_sub(rhs.keep_running),
            enq_no_tctx: self.enq_no_tctx.wrapping_sub(rhs.enq_no_tctx),
            enq_bad_weight: self.enq_bad_weight.wrapping_sub(rhs.enq_bad_weight),
            enq_no_deadline: self.enq_no_deadline.wrapping_sub(rhs.enq_no_deadline),
            enq_fastpath: self.enq_fastpath.wrapping_sub(rhs.enq_fastpath),
            enq_regular: self.enq_regular.wrapping_sub(rhs.enq_regular),
            enq_pinned_idle: self.enq_pinned_idle.wrapping_sub(rhs.enq_pinned_idle),
            enq_pinned_busy: self.enq_pinned_busy.wrapping_sub(rhs.enq_pinned_busy),
            enq_pinned_global: self.enq_pinned_global.wrapping_sub(rhs.enq_pinned_global),
            tree_inference: self.tree_inference.wrapping_sub(rhs.tree_inference),
            tree_fallback: self.tree_fallback.wrapping_sub(rhs.tree_fallback),
            tree_disagree: self.tree_disagree.wrapping_sub(rhs.tree_disagree),
            tree_samples_emitted: self
                .tree_samples_emitted
                .wrapping_sub(rhs.tree_samples_emitted),
            tree_samples_dropped: self
                .tree_samples_dropped
                .wrapping_sub(rhs.tree_samples_dropped),
            rt_takeovers: self.rt_takeovers.wrapping_sub(rhs.rt_takeovers),
            rt_evacuations: self.rt_evacuations.wrapping_sub(rhs.rt_evacuations),
            rt_redirects: self.rt_redirects.wrapping_sub(rhs.rt_redirects),
            rt_reenqs: self.rt_reenqs.wrapping_sub(rhs.rt_reenqs),
            /* The histogram is a per-interval delta like the counters. */
            op_lat: self
                .op_lat
                .iter()
                .zip(rhs.op_lat.iter())
                .map(|(lhs, rhs)| lhs.wrapping_sub(*rhs))
                .collect(),
            tree_samples_cap_dropped: self
                .tree_samples_cap_dropped
                .wrapping_sub(rhs.tree_samples_cap_dropped),
            /* Model metadata is a gauge: the currently committed model. */
            tree_model_generation: self.tree_model_generation,
            tree_model_samples: self.tree_model_samples,
            tree_model_nodes: self.tree_model_nodes,
            tree_mae_tree_us: self.tree_mae_tree_us,
            tree_mae_ema_us: self.tree_mae_ema_us,
            tree_corr_milli: self.tree_corr_milli,
            /* Gauges pass through; the adaptation counters are deltas. */
            sys_lat_ema_us: self.sys_lat_ema_us,
            sys_rate_ema: self.sys_rate_ema,
            t_l_eff_us: self.t_l_eff_us,
            t_h_eff_us: self.t_h_eff_us,
            t_int_eff_us: self.t_int_eff_us,
            t_bnd_eff_us: self.t_bnd_eff_us,
            guard_eff_us: self.guard_eff_us,
            adapt_shift: self.adapt_shift,
            wakeup_total: self.wakeup_total.wrapping_sub(rhs.wakeup_total),
            adapt_steps: self.adapt_steps.wrapping_sub(rhs.adapt_steps),
        }
    }
}

/// The stats server definition. A single `top` op reporting interval deltas.
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

/// The monitor loop. It periodically polls the stats server and prints a
/// one-line summary. It runs in its own thread (see `main.rs`) and exits
/// on shutdown.
pub fn monitor(intv: Duration, shutdown: Arc<AtomicBool>) -> Result<()> {
    scx_utils::monitor_stats::<Metrics>(
        &[],
        intv,
        || shutdown.load(Ordering::Relaxed),
        |metrics| metrics.format(&mut std::io::stdout()),
    )
}
