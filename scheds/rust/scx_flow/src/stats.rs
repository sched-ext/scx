// Copyright (c) 2026 Galih Tama <galpt@v.recipes>
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

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
    #[stat(desc = "Total CPU runtime in ns")]
    pub total_runtime: u64,
    #[stat(desc = "Tasks dispatched from the reserved positive-budget DSQ")]
    pub reserved_dispatches: u64,
    #[stat(desc = "Tasks dispatched from the urgent latency lane DSQ")]
    pub urgent_latency_dispatches: u64,
    #[stat(desc = "Urgent-latency dispatches granted through the bounded burst path")]
    pub urgent_latency_burst_grants: u64,
    #[stat(desc = "Urgent-latency dispatches that continued an already-active burst window")]
    pub urgent_latency_burst_continuations: u64,
    #[stat(desc = "Tasks dispatched from the dedicated latency lane DSQ")]
    pub latency_dispatches: u64,
    #[stat(desc = "Tasks dispatched from the shared DSQ")]
    pub shared_dispatches: u64,
    #[stat(desc = "Tasks dispatched from the contained throughput/background DSQ")]
    pub contained_dispatches: u64,
    #[stat(desc = "Tasks fast-dispatched to local DSQs")]
    pub local_fast_dispatches: u64,
    #[stat(desc = "Positive-budget wakeups sent to local DSQs with preempt kicks")]
    pub wake_preempt_dispatches: u64,
    #[stat(desc = "Wakeups that refilled task budget")]
    pub budget_refill_events: u64,
    #[stat(desc = "Times a task ran its budget down to zero or below")]
    pub budget_exhaustions: u64,
    #[stat(desc = "Wakeups that still had positive budget at enqueue time")]
    pub positive_budget_wakeups: u64,
    #[stat(desc = "Latency-debt wakeups inserted into the urgent latency lane")]
    pub urgent_latency_enqueues: u64,
    #[stat(desc = "Interactive wakeups inserted into the dedicated latency lane")]
    pub latency_lane_enqueues: u64,
    #[stat(desc = "Soft latency-lane candidates observed before final routing decisions")]
    pub latency_lane_candidates: u64,
    #[stat(desc = "Latency-lane candidates that were consumed by the local reserved fast path")]
    pub latency_candidate_local_enqueues: u64,
    #[stat(desc = "Soft latency-lane candidates blocked because they were already contained hogs")]
    pub latency_candidate_hog_blocks: u64,
    #[stat(desc = "Interactive budget exhaustions that raised per-task latency debt")]
    pub latency_debt_raises: u64,
    #[stat(desc = "Times latency debt decayed after the scheduler gave a debt-bearing task latency service")]
    pub latency_debt_decays: u64,
    #[stat(desc = "Latency-lane enqueues driven by accumulated latency debt rather than fresh wake credit alone")]
    pub latency_debt_urgent_enqueues: u64,
    #[stat(desc = "Urgent-debt wakeups that still missed the urgent lane and fell back to ordinary routing")]
    pub urgent_latency_misses: u64,
    #[stat(desc = "Positive-budget tasks inserted directly into selected local DSQs")]
    pub reserved_local_enqueues: u64,
    #[stat(desc = "Positive-budget tasks enqueued to the reserved global DSQ")]
    pub reserved_global_enqueues: u64,
    #[stat(desc = "Wakeups that fell back to the shared DSQ")]
    pub shared_wakeup_enqueues: u64,
    #[stat(desc = "Runnable wakeups observed before enqueue/select_cpu decisions")]
    pub runnable_wakeups: u64,
    #[stat(desc = "Local DSQ tasks rescued during cpu_release")]
    pub cpu_release_reenqueues: u64,
    #[stat(desc = "Maximum current consecutive urgent-latency dispatches within the bounded burst window across CPUs")]
    pub urgent_latency_burst_rounds: u64,
    #[stat(desc = "Maximum current consecutive high-priority dispatches since shared or contained service last ran across CPUs")]
    pub high_priority_burst_rounds: u64,
    #[stat(desc = "Maximum current consecutive ordinary local-reserved fast-path enqueues under pressure across CPUs")]
    pub local_reserved_burst_rounds: u64,
    #[stat(desc = "Ordinary local-reserved fast-path grants that counted toward the local burst window")]
    pub local_reserved_fast_grants: u64,
    #[stat(desc = "Ordinary local-reserved fast-path grants that continued an already-active local burst window")]
    pub local_reserved_burst_continuations: u64,
    #[stat(desc = "Ordinary local-reserved fast-path enqueues skipped by the local burst cap")]
    pub local_quota_skips: u64,
    #[stat(desc = "Dispatch rounds where a lower-lane quota check skipped the normal reserved/high-priority order")]
    pub reserved_quota_skips: u64,
    #[stat(desc = "Shared-lane dispatches forced early by the bounded quota")]
    pub quota_shared_forces: u64,
    #[stat(desc = "Contained-lane dispatches forced early by the bounded quota")]
    pub quota_contained_forces: u64,
    #[stat(desc = "Tasks initialized through init_task task storage setup")]
    pub init_task_events: u64,
    #[stat(desc = "Tasks explicitly initialized on entry into scx_flow")]
    pub enable_events: u64,
    #[stat(desc = "Tasks explicitly cleaned up on exit from scx_flow")]
    pub exit_task_events: u64,
    #[stat(desc = "Wakeups where select_cpu() biased toward the task's last CPU")]
    pub cpu_stability_biases: u64,
    #[stat(desc = "Wakeups where the chosen target CPU matched the task's last CPU")]
    pub last_cpu_matches: u64,
    #[stat(desc = "Observed task migrations between successive runs")]
    pub cpu_migrations: u64,
    #[stat(desc = "Pinned positive-budget wakeups classified into the RT-sensitive lane")]
    pub rt_sensitive_wakeups: u64,
    #[stat(desc = "RT-sensitive wakeups inserted directly into selected local DSQs")]
    pub rt_sensitive_local_enqueues: u64,
    #[stat(desc = "RT-sensitive wakeups that used the preempt path")]
    pub rt_sensitive_preempts: u64,
    #[stat(desc = "Maximum current consecutive dispatches from the reserved global DSQ across CPUs")]
    pub reserved_lane_burst_rounds: u64,
    #[stat(desc = "Dispatches granted from the reserved global DSQ while reserved-lane shaping was active")]
    pub reserved_lane_grants: u64,
    #[stat(desc = "Reserved global dispatches that continued an already-active reserved-lane burst window")]
    pub reserved_lane_burst_continuations: u64,
    #[stat(desc = "Reserved global dispatches skipped because the reserved-lane burst cap engaged")]
    pub reserved_lane_skips: u64,
    #[stat(desc = "Shared-lane dispatches forced by the reserved-lane burst cap")]
    pub reserved_lane_shared_forces: u64,
    #[stat(desc = "Contained-lane dispatches forced by the reserved-lane burst cap")]
    pub reserved_lane_contained_forces: u64,
    #[stat(desc = "Reserved-lane cap attempts that wanted shared service but found no immediately dispatchable shared work")]
    pub reserved_lane_shared_misses: u64,
    #[stat(desc = "Reserved-lane cap attempts that wanted contained service but found no immediately dispatchable contained work")]
    pub reserved_lane_contained_misses: u64,
    #[stat(desc = "Contained-lane enqueues promoted to the head because the contained lane was already meaningfully starved")]
    pub contained_starved_head_enqueues: u64,
    #[stat(desc = "Shared-lane enqueues promoted to the head because the shared lane was already meaningfully starved")]
    pub shared_starved_head_enqueues: u64,
    #[stat(desc = "Stable-local wakeups that were eligible for last-CPU routing before final fast-path checks")]
    pub stable_local_candidates: u64,
    #[stat(desc = "Stable positive-budget wakeups routed directly to their last CPU without using the RT-sensitive path")]
    pub stable_local_enqueues: u64,
    #[stat(desc = "Stable-local candidates that lost the fast path and decayed back toward ordinary routing")]
    pub stable_local_rejections: u64,
    #[stat(desc = "Wakeups where the chosen target CPU did not match the remembered last CPU")]
    pub stable_local_mismatches: u64,
    #[stat(desc = "Tasks routed into the dedicated contained throughput/background DSQ")]
    pub contained_enqueues: u64,
    #[stat(desc = "Enqueues where a persistent hog-like task had latency privileges reduced")]
    pub hog_containment_enqueues: u64,
    #[stat(desc = "Times a previously contained hog-like task decayed back below containment")]
    pub hog_recoveries: u64,
    #[stat(desc = "Maximum current consecutive dispatch rounds since a contained/background task last ran across CPUs")]
    pub contained_starvation_rounds: u64,
    #[stat(desc = "Maximum current consecutive dispatch rounds since a shared-fallback task last ran across CPUs")]
    pub shared_starvation_rounds: u64,
    #[stat(desc = "Contained/background tasks rescued early by the fairness floor")]
    pub contained_rescue_dispatches: u64,
    #[stat(desc = "Shared-fallback tasks rescued early by the fairness floor")]
    pub shared_rescue_dispatches: u64,
    #[stat(desc = "Current latency-credit grant per strong interactive refill")]
    pub tune_latency_credit_grant: u64,
    #[stat(desc = "Current latency-credit decay applied when credit is consumed or exhausted")]
    pub tune_latency_credit_decay: u64,
    #[stat(desc = "Current debt threshold required before a wakeup qualifies for the urgent latency lane")]
    pub tune_latency_debt_urgent_min: u64,
    #[stat(desc = "Current maximum consecutive urgent-latency dispatches allowed in one burst")]
    pub tune_urgent_latency_burst_max: u64,
    #[stat(desc = "Current maximum consecutive high-priority dispatches before lower-lane quota checks engage")]
    pub tune_reserved_quota_burst_max: u64,
    #[stat(desc = "Current contained-lane fairness-floor threshold")]
    pub tune_contained_starvation_max: u64,
    #[stat(desc = "Current shared-lane fairness-floor threshold")]
    pub tune_shared_starvation_max: u64,
    #[stat(desc = "Current runnable-pressure cap for the ordinary local fast path")]
    pub tune_local_fast_nr_running_max: u64,
    #[stat(desc = "Current maximum consecutive ordinary local-reserved fast-path enqueues allowed under pressure")]
    pub tune_local_reserved_burst_max: u64,
    #[stat(desc = "Current maximum consecutive dispatches allowed from the reserved global DSQ before forcing a lower-lane rotation")]
    pub tune_reserved_lane_burst_max: u64,
    #[stat(desc = "Adaptive tuning generation counter")]
    pub autotune_generation: u64,
    #[stat(desc = "Adaptive tuning mode (0=balanced, 1=latency, 2=throughput)")]
    pub autotune_mode: u64,
    #[stat(desc = "Current reserved slice cap in ns")]
    pub tune_reserved_max_ns: u64,
    #[stat(desc = "Current shared slice in ns")]
    pub tune_shared_slice_ns: u64,
    #[stat(desc = "Current interactive wake refill floor in ns")]
    pub tune_interactive_floor_ns: u64,
    #[stat(desc = "Current preempt budget threshold in ns")]
    pub tune_preempt_budget_min_ns: u64,
    #[stat(desc = "Current preempt refill threshold in ns")]
    pub tune_preempt_refill_min_ns: u64,
}

impl Metrics {
    fn autotune_mode_name(&self) -> &'static str {
        match self.autotune_mode {
            1 => "latency",
            2 => "throughput",
            _ => "balanced",
        }
    }

    fn format<W: Write>(&self, w: &mut W) -> Result<()> {
        writeln!(
            w,
            "[{}] mode={} gen={} run={} urgent_lat_disp={} urgent_grant={} urgent_cont={} latency_disp={} reserve_disp={} contained_disp={} shared_disp={} local_fast={} wake_preempt={} refill={} exhaust={} pos_wake={} urgent_lat_enq={} latency_enq={} latency_cand={} latency_local={} latency_hog_block={} debt_raise={} debt_decay={} debt_urgent={} urgent_miss={} reserve_local={} reserve_global={} shared_wake={} runnable={} cpu_release={} urgent_burst={} high_prio_burst={} reserved_burst={} reserved_grant={} reserved_cont={} reserved_skip={} reserved_shared={} reserved_contained={} reserved_miss_shared={} reserved_miss_contained={} contained_head={} shared_head={} local_burst={} local_grant={} local_cont={} local_quota_skip={} quota_skip={} quota_shared={} quota_contained={} init_task={} enable={} exit_task={} cpu_bias={} last_cpu_hit={} migrations={} rt_wake={} rt_local={} rt_preempt={} stable_cand={} stable_local={} stable_reject={} stable_mismatch={} contained_enq={} hog_contain={} hog_recover={} contained_starve={} shared_starve={} contained_rescue={} shared_rescue={} reserve_cap_us={} shared_slice_us={} refill_floor_us={} preempt_budget_us={} preempt_refill_us={} credit_grant={} credit_decay={} debt_min={} urgent_burst_max={} reserved_quota_max={} reserved_lane_max={} contained_floor={} shared_floor={} local_fast_cap={} local_burst_max={}",
            crate::SCHEDULER_NAME,
            self.autotune_mode_name(),
            self.autotune_generation,
            self.nr_running,
            self.urgent_latency_dispatches,
            self.urgent_latency_burst_grants,
            self.urgent_latency_burst_continuations,
            self.latency_dispatches,
            self.reserved_dispatches,
            self.contained_dispatches,
            self.shared_dispatches,
            self.local_fast_dispatches,
            self.wake_preempt_dispatches,
            self.budget_refill_events,
            self.budget_exhaustions,
            self.positive_budget_wakeups,
            self.urgent_latency_enqueues,
            self.latency_lane_enqueues,
            self.latency_lane_candidates,
            self.latency_candidate_local_enqueues,
            self.latency_candidate_hog_blocks,
            self.latency_debt_raises,
            self.latency_debt_decays,
            self.latency_debt_urgent_enqueues,
            self.urgent_latency_misses,
            self.reserved_local_enqueues,
            self.reserved_global_enqueues,
            self.shared_wakeup_enqueues,
            self.runnable_wakeups,
            self.cpu_release_reenqueues,
            self.urgent_latency_burst_rounds,
            self.high_priority_burst_rounds,
            self.reserved_lane_burst_rounds,
            self.reserved_lane_grants,
            self.reserved_lane_burst_continuations,
            self.reserved_lane_skips,
            self.reserved_lane_shared_forces,
            self.reserved_lane_contained_forces,
            self.reserved_lane_shared_misses,
            self.reserved_lane_contained_misses,
            self.contained_starved_head_enqueues,
            self.shared_starved_head_enqueues,
            self.local_reserved_burst_rounds,
            self.local_reserved_fast_grants,
            self.local_reserved_burst_continuations,
            self.local_quota_skips,
            self.reserved_quota_skips,
            self.quota_shared_forces,
            self.quota_contained_forces,
            self.init_task_events,
            self.enable_events,
            self.exit_task_events,
            self.cpu_stability_biases,
            self.last_cpu_matches,
            self.cpu_migrations,
            self.rt_sensitive_wakeups,
            self.rt_sensitive_local_enqueues,
            self.rt_sensitive_preempts,
            self.stable_local_candidates,
            self.stable_local_enqueues,
            self.stable_local_rejections,
            self.stable_local_mismatches,
            self.contained_enqueues,
            self.hog_containment_enqueues,
            self.hog_recoveries,
            self.contained_starvation_rounds,
            self.shared_starvation_rounds,
            self.contained_rescue_dispatches,
            self.shared_rescue_dispatches,
            self.tune_reserved_max_ns / 1000,
            self.tune_shared_slice_ns / 1000,
            self.tune_interactive_floor_ns / 1000,
            self.tune_preempt_budget_min_ns / 1000,
            self.tune_preempt_refill_min_ns / 1000,
            self.tune_latency_credit_grant,
            self.tune_latency_credit_decay,
            self.tune_latency_debt_urgent_min,
            self.tune_urgent_latency_burst_max,
            self.tune_reserved_quota_burst_max,
            self.tune_reserved_lane_burst_max,
            self.tune_contained_starvation_max,
            self.tune_shared_starvation_max,
            self.tune_local_fast_nr_running_max,
            self.tune_local_reserved_burst_max,
        )?;
        Ok(())
    }

    pub fn delta(&self, rhs: &Self) -> Self {
        Self {
            nr_running: self.nr_running,
            total_runtime: self.total_runtime.wrapping_sub(rhs.total_runtime),
            reserved_dispatches: self
                .reserved_dispatches
                .wrapping_sub(rhs.reserved_dispatches),
            urgent_latency_dispatches: self
                .urgent_latency_dispatches
                .wrapping_sub(rhs.urgent_latency_dispatches),
            urgent_latency_burst_grants: self
                .urgent_latency_burst_grants
                .wrapping_sub(rhs.urgent_latency_burst_grants),
            urgent_latency_burst_continuations: self
                .urgent_latency_burst_continuations
                .wrapping_sub(rhs.urgent_latency_burst_continuations),
            latency_dispatches: self
                .latency_dispatches
                .wrapping_sub(rhs.latency_dispatches),
            contained_dispatches: self
                .contained_dispatches
                .wrapping_sub(rhs.contained_dispatches),
            shared_dispatches: self.shared_dispatches.wrapping_sub(rhs.shared_dispatches),
            local_fast_dispatches: self
                .local_fast_dispatches
                .wrapping_sub(rhs.local_fast_dispatches),
            wake_preempt_dispatches: self
                .wake_preempt_dispatches
                .wrapping_sub(rhs.wake_preempt_dispatches),
            budget_refill_events: self
                .budget_refill_events
                .wrapping_sub(rhs.budget_refill_events),
            budget_exhaustions: self.budget_exhaustions.wrapping_sub(rhs.budget_exhaustions),
            positive_budget_wakeups: self
                .positive_budget_wakeups
                .wrapping_sub(rhs.positive_budget_wakeups),
            urgent_latency_enqueues: self
                .urgent_latency_enqueues
                .wrapping_sub(rhs.urgent_latency_enqueues),
            latency_lane_enqueues: self
                .latency_lane_enqueues
                .wrapping_sub(rhs.latency_lane_enqueues),
            latency_lane_candidates: self
                .latency_lane_candidates
                .wrapping_sub(rhs.latency_lane_candidates),
            latency_candidate_local_enqueues: self
                .latency_candidate_local_enqueues
                .wrapping_sub(rhs.latency_candidate_local_enqueues),
            latency_candidate_hog_blocks: self
                .latency_candidate_hog_blocks
                .wrapping_sub(rhs.latency_candidate_hog_blocks),
            latency_debt_raises: self
                .latency_debt_raises
                .wrapping_sub(rhs.latency_debt_raises),
            latency_debt_decays: self
                .latency_debt_decays
                .wrapping_sub(rhs.latency_debt_decays),
            latency_debt_urgent_enqueues: self
                .latency_debt_urgent_enqueues
                .wrapping_sub(rhs.latency_debt_urgent_enqueues),
            urgent_latency_misses: self
                .urgent_latency_misses
                .wrapping_sub(rhs.urgent_latency_misses),
            reserved_local_enqueues: self
                .reserved_local_enqueues
                .wrapping_sub(rhs.reserved_local_enqueues),
            reserved_global_enqueues: self
                .reserved_global_enqueues
                .wrapping_sub(rhs.reserved_global_enqueues),
            shared_wakeup_enqueues: self
                .shared_wakeup_enqueues
                .wrapping_sub(rhs.shared_wakeup_enqueues),
            runnable_wakeups: self.runnable_wakeups.wrapping_sub(rhs.runnable_wakeups),
            cpu_release_reenqueues: self
                .cpu_release_reenqueues
                .wrapping_sub(rhs.cpu_release_reenqueues),
            urgent_latency_burst_rounds: self.urgent_latency_burst_rounds,
            high_priority_burst_rounds: self.high_priority_burst_rounds,
            local_reserved_burst_rounds: self.local_reserved_burst_rounds,
            local_reserved_fast_grants: self
                .local_reserved_fast_grants
                .wrapping_sub(rhs.local_reserved_fast_grants),
            local_reserved_burst_continuations: self
                .local_reserved_burst_continuations
                .wrapping_sub(rhs.local_reserved_burst_continuations),
            local_quota_skips: self.local_quota_skips.wrapping_sub(rhs.local_quota_skips),
            reserved_quota_skips: self
                .reserved_quota_skips
                .wrapping_sub(rhs.reserved_quota_skips),
            quota_shared_forces: self
                .quota_shared_forces
                .wrapping_sub(rhs.quota_shared_forces),
            quota_contained_forces: self
                .quota_contained_forces
                .wrapping_sub(rhs.quota_contained_forces),
            init_task_events: self.init_task_events.wrapping_sub(rhs.init_task_events),
            enable_events: self.enable_events.wrapping_sub(rhs.enable_events),
            exit_task_events: self.exit_task_events.wrapping_sub(rhs.exit_task_events),
            cpu_stability_biases: self
                .cpu_stability_biases
                .wrapping_sub(rhs.cpu_stability_biases),
            last_cpu_matches: self.last_cpu_matches.wrapping_sub(rhs.last_cpu_matches),
            cpu_migrations: self.cpu_migrations.wrapping_sub(rhs.cpu_migrations),
            rt_sensitive_wakeups: self
                .rt_sensitive_wakeups
                .wrapping_sub(rhs.rt_sensitive_wakeups),
            rt_sensitive_local_enqueues: self
                .rt_sensitive_local_enqueues
                .wrapping_sub(rhs.rt_sensitive_local_enqueues),
            rt_sensitive_preempts: self
                .rt_sensitive_preempts
                .wrapping_sub(rhs.rt_sensitive_preempts),
            reserved_lane_burst_rounds: self.reserved_lane_burst_rounds,
            reserved_lane_grants: self
                .reserved_lane_grants
                .wrapping_sub(rhs.reserved_lane_grants),
            reserved_lane_burst_continuations: self
                .reserved_lane_burst_continuations
                .wrapping_sub(rhs.reserved_lane_burst_continuations),
            reserved_lane_skips: self
                .reserved_lane_skips
                .wrapping_sub(rhs.reserved_lane_skips),
            reserved_lane_shared_forces: self
                .reserved_lane_shared_forces
                .wrapping_sub(rhs.reserved_lane_shared_forces),
            reserved_lane_contained_forces: self
                .reserved_lane_contained_forces
                .wrapping_sub(rhs.reserved_lane_contained_forces),
            reserved_lane_shared_misses: self
                .reserved_lane_shared_misses
                .wrapping_sub(rhs.reserved_lane_shared_misses),
            reserved_lane_contained_misses: self
                .reserved_lane_contained_misses
                .wrapping_sub(rhs.reserved_lane_contained_misses),
            contained_starved_head_enqueues: self
                .contained_starved_head_enqueues
                .wrapping_sub(rhs.contained_starved_head_enqueues),
            shared_starved_head_enqueues: self
                .shared_starved_head_enqueues
                .wrapping_sub(rhs.shared_starved_head_enqueues),
            stable_local_candidates: self
                .stable_local_candidates
                .wrapping_sub(rhs.stable_local_candidates),
            stable_local_enqueues: self
                .stable_local_enqueues
                .wrapping_sub(rhs.stable_local_enqueues),
            stable_local_rejections: self
                .stable_local_rejections
                .wrapping_sub(rhs.stable_local_rejections),
            stable_local_mismatches: self
                .stable_local_mismatches
                .wrapping_sub(rhs.stable_local_mismatches),
            contained_enqueues: self
                .contained_enqueues
                .wrapping_sub(rhs.contained_enqueues),
            hog_containment_enqueues: self
                .hog_containment_enqueues
                .wrapping_sub(rhs.hog_containment_enqueues),
            hog_recoveries: self.hog_recoveries.wrapping_sub(rhs.hog_recoveries),
            contained_starvation_rounds: self.contained_starvation_rounds,
            shared_starvation_rounds: self.shared_starvation_rounds,
            contained_rescue_dispatches: self
                .contained_rescue_dispatches
                .wrapping_sub(rhs.contained_rescue_dispatches),
            shared_rescue_dispatches: self
                .shared_rescue_dispatches
                .wrapping_sub(rhs.shared_rescue_dispatches),
            tune_latency_credit_grant: self.tune_latency_credit_grant,
            tune_latency_credit_decay: self.tune_latency_credit_decay,
            tune_latency_debt_urgent_min: self.tune_latency_debt_urgent_min,
            tune_urgent_latency_burst_max: self.tune_urgent_latency_burst_max,
            tune_reserved_quota_burst_max: self.tune_reserved_quota_burst_max,
            tune_contained_starvation_max: self.tune_contained_starvation_max,
            tune_shared_starvation_max: self.tune_shared_starvation_max,
            tune_local_fast_nr_running_max: self.tune_local_fast_nr_running_max,
            tune_local_reserved_burst_max: self.tune_local_reserved_burst_max,
            tune_reserved_lane_burst_max: self.tune_reserved_lane_burst_max,
            autotune_generation: self.autotune_generation,
            autotune_mode: self.autotune_mode,
            tune_reserved_max_ns: self.tune_reserved_max_ns,
            tune_shared_slice_ns: self.tune_shared_slice_ns,
            tune_interactive_floor_ns: self.tune_interactive_floor_ns,
            tune_preempt_budget_min_ns: self.tune_preempt_budget_min_ns,
            tune_preempt_refill_min_ns: self.tune_preempt_refill_min_ns,
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
