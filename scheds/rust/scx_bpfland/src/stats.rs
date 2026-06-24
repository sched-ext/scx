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
    // TIMELY stats (zero when timely mode is disabled)
    #[stat(desc = "Number of delay recovery dispatches")]
    pub nr_delay_recovery_dispatches: u64,
    #[stat(desc = "Number of delay middle add dispatches")]
    pub nr_delay_middle_add_dispatches: u64,
    #[stat(desc = "Number of delay fast recovery dispatches")]
    pub nr_delay_fast_recovery_dispatches: u64,
    #[stat(desc = "Number of delay rate-limited dispatches")]
    pub nr_delay_rate_limited_dispatches: u64,
    #[stat(desc = "Number of gain floor dispatches")]
    pub nr_gain_floor_dispatches: u64,
    #[stat(desc = "Number of gain ceiling dispatches")]
    pub nr_gain_ceiling_dispatches: u64,
    #[stat(desc = "Number of delay low region samples")]
    pub nr_delay_low_region_samples: u64,
    #[stat(desc = "Number of delay mid region samples")]
    pub nr_delay_mid_region_samples: u64,
    #[stat(desc = "Number of delay high region samples")]
    pub nr_delay_high_region_samples: u64,
    #[stat(desc = "Number of gain floor resident samples")]
    pub nr_gain_floor_resident_samples: u64,
    #[stat(desc = "Number of gain mid resident samples")]
    pub nr_gain_mid_resident_samples: u64,
    #[stat(desc = "Number of gain ceiling resident samples")]
    pub nr_gain_ceiling_resident_samples: u64,
    #[stat(desc = "Number of idle select path picks")]
    pub nr_idle_select_path_picks: u64,
    #[stat(desc = "Number of idle enqueue path picks")]
    pub nr_idle_enqueue_path_picks: u64,
    #[stat(desc = "Number of idle prev CPU picks")]
    pub nr_idle_prev_cpu_picks: u64,
    #[stat(desc = "Number of idle primary picks")]
    pub nr_idle_primary_picks: u64,
    #[stat(desc = "Number of idle spill picks")]
    pub nr_idle_spill_picks: u64,
    #[stat(desc = "Number of idle pick failures")]
    pub nr_idle_pick_failures: u64,
    #[stat(desc = "Number of idle primary domain misses")]
    pub nr_idle_primary_domain_misses: u64,
    #[stat(desc = "Number of idle global misses")]
    pub nr_idle_global_misses: u64,
    #[stat(desc = "Number of waker CPU biases")]
    pub nr_waker_cpu_biases: u64,
    #[stat(desc = "Number of keep running reuses")]
    pub nr_keep_running_reuses: u64,
    #[stat(desc = "Number of keep running queue empty")]
    pub nr_keep_running_queue_empty: u64,
    #[stat(desc = "Number of keep running SMT blocked")]
    pub nr_keep_running_smt_blocked: u64,
    #[stat(desc = "Number of keep running queued work")]
    pub nr_keep_running_queued_work: u64,
    #[stat(desc = "Number of dispatch CPU DSQ consumes")]
    pub nr_dispatch_cpu_dsq_consumes: u64,
    #[stat(desc = "Number of dispatch node DSQ consumes")]
    pub nr_dispatch_node_dsq_consumes: u64,
    #[stat(desc = "Number of CPU release reenqueues")]
    pub nr_cpu_release_reenqueue: u64,
}

impl Metrics {
    fn format<W: Write>(&self, w: &mut W) -> Result<()> {
        writeln!(
            w,
            "[{}] tasks -> r: {:>2}/{:<2} | dispatch -> k: {:<5} d: {:<5} s: {:<5} | timely -> rec: {:<5} mid: {:<5} rl: {:<5} min: {:<5} max: {:<5}",
            crate::SCHEDULER_NAME,
            self.nr_running,
            self.nr_cpus,
            self.nr_kthread_dispatches,
            self.nr_direct_dispatches,
            self.nr_shared_dispatches,
            self.nr_delay_recovery_dispatches,
            self.nr_delay_middle_add_dispatches,
            self.nr_delay_rate_limited_dispatches,
            self.nr_gain_floor_dispatches,
            self.nr_gain_ceiling_dispatches
        )?;
        Ok(())
    }

    fn delta(&self, rhs: &Self) -> Self {
        Self {
            nr_kthread_dispatches: self.nr_kthread_dispatches - rhs.nr_kthread_dispatches,
            nr_direct_dispatches: self.nr_direct_dispatches - rhs.nr_direct_dispatches,
            nr_shared_dispatches: self.nr_shared_dispatches - rhs.nr_shared_dispatches,
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
