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
    #[stat(desc = "Number of fresh delay samples observed in the low Timely region")]
    pub nr_delay_low_region_samples: u64,
    #[stat(desc = "Number of fresh delay samples observed in the middle Timely region")]
    pub nr_delay_mid_region_samples: u64,
    #[stat(desc = "Number of fresh delay samples observed in the high Timely region")]
    pub nr_delay_high_region_samples: u64,
    #[stat(
        desc = "Number of fresh delay samples observed while the Timely gain was already at the floor"
    )]
    pub nr_gain_floor_resident_samples: u64,
    #[stat(
        desc = "Number of fresh delay samples observed while the Timely gain was between floor and ceiling"
    )]
    pub nr_gain_mid_resident_samples: u64,
    #[stat(
        desc = "Number of fresh delay samples observed while the Timely gain was already at the ceiling"
    )]
    pub nr_gain_ceiling_resident_samples: u64,
    #[stat(desc = "Number of idle-CPU picks completed from select_cpu")]
    pub nr_idle_select_path_picks: u64,
    #[stat(desc = "Number of idle-CPU picks completed from the enqueue fallback path")]
    pub nr_idle_enqueue_path_picks: u64,
    #[stat(desc = "Number of idle-CPU picks that reused prev_cpu")]
    pub nr_idle_prev_cpu_picks: u64,
    #[stat(desc = "Number of idle-CPU picks that stayed inside the primary domain")]
    pub nr_idle_primary_picks: u64,
    #[stat(desc = "Number of idle-CPU picks that spilled outside the primary domain")]
    pub nr_idle_spill_picks: u64,
    #[stat(desc = "Number of idle-CPU pick attempts that failed to find an idle target")]
    pub nr_idle_pick_failures: u64,
    #[stat(desc = "Number of idle-pick attempts that failed inside the primary domain")]
    pub nr_idle_primary_domain_misses: u64,
    #[stat(desc = "Number of idle-pick attempts that failed globally after all fallback")]
    pub nr_idle_global_misses: u64,
    #[stat(desc = "Number of wakeup decisions that biased placement toward the waker CPU")]
    pub nr_waker_cpu_biases: u64,
    #[stat(
        desc = "Number of dispatch rounds that simply replenished and kept the current task running"
    )]
    pub nr_keep_running_reuses: u64,
    #[stat(desc = "Number of keep-running refusals because the task was no longer queued")]
    pub nr_keep_running_queue_empty: u64,
    #[stat(desc = "Number of keep-running refusals because the CPU stayed SMT-contended")]
    pub nr_keep_running_smt_blocked: u64,
    #[stat(
        desc = "Number of dispatch rounds where keep-running was blocked because DSQ heads still had work"
    )]
    pub nr_keep_running_queued_work: u64,
    #[stat(desc = "Number of dispatch rounds that consumed from the per-CPU DSQ")]
    pub nr_dispatch_cpu_dsq_consumes: u64,
    #[stat(desc = "Number of dispatch rounds that consumed from the per-node DSQ")]
    pub nr_dispatch_node_dsq_consumes: u64,
    #[stat(
        desc = "Number of global-idle-miss fallbacks that steered work to prev_cpu's local DSQ"
    )]
    pub nr_v2_locality_cpu_dispatches: u64,
    #[stat(desc = "Number of locality fallbacks that used the wider congested-node v2 path")]
    pub nr_v2_congested_locality_cpu_dispatches: u64,
    #[stat(desc = "Number of locality fallbacks that were triggered by Timely delay pressure")]
    pub nr_v2_delay_locality_cpu_dispatches: u64,
    #[stat(
        desc = "Number of dispatch rounds where a small v2 local-head deadline bias preferred the per-CPU DSQ"
    )]
    pub nr_v2_local_head_biases: u64,
    #[stat(desc = "Number of tasks that entered v2 pressure mode after sustained delay pressure")]
    pub nr_v2_pressure_mode_entries: u64,
    #[stat(desc = "Number of tasks that exited v2 pressure mode after sustained recovery")]
    pub nr_v2_pressure_mode_exits: u64,
    #[stat(desc = "Number of pressure-mode enqueue decisions that stayed on the shared path")]
    pub nr_v2_pressure_shared_dispatches: u64,
    #[stat(desc = "Number of shared dispatches that happened while in expand mode")]
    pub nr_v2_expand_mode_dispatches: u64,
    #[stat(desc = "Number of shared dispatches that happened while in contract mode")]
    pub nr_v2_contract_mode_dispatches: u64,
    #[stat(desc = "Number of local-DSQ rescues triggered from cpu_release")]
    pub nr_cpu_release_reenqueue: u64,
}

impl Metrics {
    pub fn summary_line(&self) -> String {
        format!(
            "tasks r={}/{} dispatch k={} d={} s={} q={} g={} rec={} mid={} hai={} rl={} min={} max={} lowr={} midr={} highr={} gfloor={} gint={} gceil={} isel={} ienq={} iprev={} iprim={} ispill={} imiss={} pmiss={} gmiss={} wbias={} krun={} kempty={} ksmt={} kbusy={} cpuq={} nodeq={} v2loc={} v2cong={} v2dloc={} v2bias={} v2pme={} v2pmx={} v2pms={} v2exp={} v2con={} rel={}",
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
            self.nr_delay_low_region_samples,
            self.nr_delay_mid_region_samples,
            self.nr_delay_high_region_samples,
            self.nr_gain_floor_resident_samples,
            self.nr_gain_mid_resident_samples,
            self.nr_gain_ceiling_resident_samples,
            self.nr_idle_select_path_picks,
            self.nr_idle_enqueue_path_picks,
            self.nr_idle_prev_cpu_picks,
            self.nr_idle_primary_picks,
            self.nr_idle_spill_picks,
            self.nr_idle_pick_failures,
            self.nr_idle_primary_domain_misses,
            self.nr_idle_global_misses,
            self.nr_waker_cpu_biases,
            self.nr_keep_running_reuses,
            self.nr_keep_running_queue_empty,
            self.nr_keep_running_smt_blocked,
            self.nr_keep_running_queued_work,
            self.nr_dispatch_cpu_dsq_consumes,
            self.nr_dispatch_node_dsq_consumes,
            self.nr_v2_locality_cpu_dispatches,
            self.nr_v2_congested_locality_cpu_dispatches,
            self.nr_v2_delay_locality_cpu_dispatches,
            self.nr_v2_local_head_biases,
            self.nr_v2_pressure_mode_entries,
            self.nr_v2_pressure_mode_exits,
            self.nr_v2_pressure_shared_dispatches,
            self.nr_v2_expand_mode_dispatches,
            self.nr_v2_contract_mode_dispatches,
            self.nr_cpu_release_reenqueue
        )
    }

    fn format<W: Write>(&self, w: &mut W) -> Result<()> {
        writeln!(
            w,
            "[{}] tasks -> r: {:>2}/{:<2} | dispatch -> k: {:<5} d: {:<5} s: {:<5} q: {:<5} g: {:<5} rec: {:<5} mid: {:<5} hai: {:<5} rl: {:<5} min: {:<5} max: {:<5} | region -> low: {:<5} mid: {:<5} high: {:<5} | gain -> floor: {:<5} int: {:<5} ceil: {:<5} | idle -> sel: {:<5} enq: {:<5} prev: {:<5} prim: {:<5} spill: {:<5} miss: {:<5} pmiss: {:<5} gmiss: {:<5} wbias: {:<5} | keep: {:<5} empty: {:<5} smt: {:<5} busy: {:<5} | dsq -> cpu: {:<5} node: {:<5} v2loc: {:<5} v2cong: {:<5} v2dloc: {:<5} v2bias: {:<5} pme: {:<5} pmx: {:<5} pms: {:<5} v2exp: {:<5} v2con: {:<5} | rel: {:<5}",
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
            self.nr_delay_low_region_samples,
            self.nr_delay_mid_region_samples,
            self.nr_delay_high_region_samples,
            self.nr_gain_floor_resident_samples,
            self.nr_gain_mid_resident_samples,
            self.nr_gain_ceiling_resident_samples,
            self.nr_idle_select_path_picks,
            self.nr_idle_enqueue_path_picks,
            self.nr_idle_prev_cpu_picks,
            self.nr_idle_primary_picks,
            self.nr_idle_spill_picks,
            self.nr_idle_pick_failures,
            self.nr_idle_primary_domain_misses,
            self.nr_idle_global_misses,
            self.nr_waker_cpu_biases,
            self.nr_keep_running_reuses,
            self.nr_keep_running_queue_empty,
            self.nr_keep_running_smt_blocked,
            self.nr_keep_running_queued_work,
            self.nr_dispatch_cpu_dsq_consumes,
            self.nr_dispatch_node_dsq_consumes,
            self.nr_v2_locality_cpu_dispatches,
            self.nr_v2_congested_locality_cpu_dispatches,
            self.nr_v2_delay_locality_cpu_dispatches,
            self.nr_v2_local_head_biases,
            self.nr_v2_pressure_mode_entries,
            self.nr_v2_pressure_mode_exits,
            self.nr_v2_pressure_shared_dispatches,
            self.nr_v2_expand_mode_dispatches,
            self.nr_v2_contract_mode_dispatches,
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
            nr_delay_low_region_samples: self.nr_delay_low_region_samples
                - rhs.nr_delay_low_region_samples,
            nr_delay_mid_region_samples: self.nr_delay_mid_region_samples
                - rhs.nr_delay_mid_region_samples,
            nr_delay_high_region_samples: self.nr_delay_high_region_samples
                - rhs.nr_delay_high_region_samples,
            nr_gain_floor_resident_samples: self.nr_gain_floor_resident_samples
                - rhs.nr_gain_floor_resident_samples,
            nr_gain_mid_resident_samples: self.nr_gain_mid_resident_samples
                - rhs.nr_gain_mid_resident_samples,
            nr_gain_ceiling_resident_samples: self.nr_gain_ceiling_resident_samples
                - rhs.nr_gain_ceiling_resident_samples,
            nr_idle_select_path_picks: self.nr_idle_select_path_picks
                - rhs.nr_idle_select_path_picks,
            nr_idle_enqueue_path_picks: self.nr_idle_enqueue_path_picks
                - rhs.nr_idle_enqueue_path_picks,
            nr_idle_prev_cpu_picks: self.nr_idle_prev_cpu_picks - rhs.nr_idle_prev_cpu_picks,
            nr_idle_primary_picks: self.nr_idle_primary_picks - rhs.nr_idle_primary_picks,
            nr_idle_spill_picks: self.nr_idle_spill_picks - rhs.nr_idle_spill_picks,
            nr_idle_pick_failures: self.nr_idle_pick_failures - rhs.nr_idle_pick_failures,
            nr_idle_primary_domain_misses: self.nr_idle_primary_domain_misses
                - rhs.nr_idle_primary_domain_misses,
            nr_idle_global_misses: self.nr_idle_global_misses - rhs.nr_idle_global_misses,
            nr_waker_cpu_biases: self.nr_waker_cpu_biases - rhs.nr_waker_cpu_biases,
            nr_keep_running_reuses: self.nr_keep_running_reuses - rhs.nr_keep_running_reuses,
            nr_keep_running_queue_empty: self.nr_keep_running_queue_empty
                - rhs.nr_keep_running_queue_empty,
            nr_keep_running_smt_blocked: self.nr_keep_running_smt_blocked
                - rhs.nr_keep_running_smt_blocked,
            nr_keep_running_queued_work: self.nr_keep_running_queued_work
                - rhs.nr_keep_running_queued_work,
            nr_dispatch_cpu_dsq_consumes: self.nr_dispatch_cpu_dsq_consumes
                - rhs.nr_dispatch_cpu_dsq_consumes,
            nr_dispatch_node_dsq_consumes: self.nr_dispatch_node_dsq_consumes
                - rhs.nr_dispatch_node_dsq_consumes,
            nr_v2_locality_cpu_dispatches: self.nr_v2_locality_cpu_dispatches
                - rhs.nr_v2_locality_cpu_dispatches,
            nr_v2_congested_locality_cpu_dispatches: self.nr_v2_congested_locality_cpu_dispatches
                - rhs.nr_v2_congested_locality_cpu_dispatches,
            nr_v2_delay_locality_cpu_dispatches: self.nr_v2_delay_locality_cpu_dispatches
                - rhs.nr_v2_delay_locality_cpu_dispatches,
            nr_v2_local_head_biases: self.nr_v2_local_head_biases - rhs.nr_v2_local_head_biases,
            nr_v2_pressure_mode_entries: self.nr_v2_pressure_mode_entries
                - rhs.nr_v2_pressure_mode_entries,
            nr_v2_pressure_mode_exits: self.nr_v2_pressure_mode_exits
                - rhs.nr_v2_pressure_mode_exits,
            nr_v2_pressure_shared_dispatches: self.nr_v2_pressure_shared_dispatches
                - rhs.nr_v2_pressure_shared_dispatches,
            nr_v2_expand_mode_dispatches: self.nr_v2_expand_mode_dispatches
                - rhs.nr_v2_expand_mode_dispatches,
            nr_v2_contract_mode_dispatches: self.nr_v2_contract_mode_dispatches
                - rhs.nr_v2_contract_mode_dispatches,
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
