// SPDX-License-Identifier: GPL-2.0

use super::*;
use crate::telemetry_report::{
    AcceleratorSummary, CoverageItem, CoverageQuality, GraphSummary, HealthSummary,
    LifecycleSummary, TelemetryReport,
};

pub(super) fn build_telemetry_report(stats: &cake_stats, app: &TuiApp) -> TelemetryReport {
    let timeline_window = Duration::from_secs(60);
    let timeline_step = Duration::from_secs(1);
    let timeline_samples = app.timeline_samples(timeline_window, timeline_step);
    let timeline_expected = expected_timeline_samples(timeline_window, timeline_step);
    let total_dispatches = stats.nr_local_dispatches + stats.nr_stolen_dispatches;
    let total_wakes = stats.nr_wakeup_direct_dispatches
        + stats.nr_wakeup_dsq_fallback_busy
        + stats.nr_wakeup_dsq_fallback_queued;
    let dsq_depth = stats.nr_dsq_queued.saturating_sub(stats.nr_dsq_consumed);
    let wake_events: u64 = app.wake_edges.iter().map(|edge| edge.wake_count).sum();
    let wait_samples: u64 = app.wake_edges.iter().map(|edge| edge.wait_count).sum();
    let wait_max_us = app
        .wake_edges
        .iter()
        .map(|edge| edge.wait_max_ns / 1000)
        .max()
        .unwrap_or(0);
    let accelerator = build_accelerator_summary(stats, app);

    let mut coverage = Vec::new();
    coverage.push(CoverageItem::new(
        "global.stats",
        "bpf_per_cpu_stats",
        CoverageQuality::Exact,
        "lifetime",
        0,
        "aggregated from cake_stats",
    ));
    coverage.push(CoverageItem::new(
        "task.rows",
        "bpf_task_iter",
        if app.bpf_task_count > 0 {
            CoverageQuality::Exact
        } else {
            CoverageQuality::Missing
        },
        "latest",
        0,
        if app.bpf_task_count > 0 {
            "live BPF task rows observed"
        } else {
            "no BPF task rows observed yet"
        },
    ));
    coverage.push(CoverageItem::new(
        "task.lifecycle",
        "bpf_task_iter+bpf_exit_task",
        CoverageQuality::Exact,
        "lifetime",
        0,
        "global averages from cake_stats; live task age from iterator snapshot",
    ));
    coverage.push(CoverageItem::new(
        "timeline.60s",
        "userspace_delta_snapshots",
        if timeline_samples.len() >= timeline_expected.saturating_sub(2) {
            CoverageQuality::Sampled
        } else {
            CoverageQuality::Missing
        },
        "60s",
        0,
        format!(
            "samples={}/{} avg_step={:.2}s",
            timeline_samples.len(),
            timeline_expected,
            average_timeline_sample_secs(&timeline_samples)
        ),
    ));
    coverage.push(CoverageItem::new(
        "wakegraph.ringbuf",
        "debug_ringbuf_sampled",
        if app.wake_edge_missed_updates > 0 {
            CoverageQuality::Dropped
        } else {
            CoverageQuality::Sampled
        },
        "runtime",
        app.wake_edge_missed_updates,
        if app.wake_edges.is_empty() {
            format!(
                "sampled wake-edge stream active; observed={} weight_sum={}",
                app.wake_edge_observed_events, app.wake_edge_sample_weight_sum
            )
        } else {
            format!(
                "userspace weighted graph from sampled wake-edge events observed={} weight_sum={} important={}",
                app.wake_edge_observed_events,
                app.wake_edge_sample_weight_sum,
                app.wake_edge_important_events
            )
        },
    ));
    coverage.push(CoverageItem::new(
        "wakegraph.derived",
        "task_iter_latest_waker",
        CoverageQuality::Derived,
        "latest",
        0,
        "approximate fallback from task rows",
    ));
    coverage.push(CoverageItem::new(
        "wakepolicy.strict",
        "task_anatomy_shadow",
        CoverageQuality::Derived,
        "latest",
        0,
        "userspace shadow classifier; policy_effect=none",
    ));
    coverage.push(CoverageItem::new(
        "debug.events.recent",
        "debug_ringbuf",
        CoverageQuality::Bounded,
        "recent",
        0,
        format!("recent_events={}", app.debug_events.len()),
    ));
    coverage.push(CoverageItem::new(
        "accelerator.confidence",
        "cpu_bss.decision_confidence+bpf_stats",
        CoverageQuality::Exact,
        "lifetime+60s",
        0,
        format!(
            "source={} trained_cpus={} route_ready_cpus={} floor_ready_cpus={} trust_prev_active_cpus={} trust_prev_blocked_cpus={}",
            accelerator.source,
            accelerator.trained_cpus,
            accelerator.route_ready_cpus,
            accelerator.floor_ready_cpus,
            accelerator.trust_prev_active_cpus,
            accelerator.trust_prev_blocked_cpus
        ),
    ));

    TelemetryReport::new(
        coverage,
        HealthSummary {
            dsq_depth,
            total_dispatches,
            total_wakes,
            timeline_samples: timeline_samples.len(),
            timeline_expected,
        },
        GraphSummary {
            wake_edges: app.wake_edges.len(),
            wake_events,
            wait_samples,
            wait_max_us,
            event_drops: app.wake_edge_missed_updates,
            observed_events: app.wake_edge_observed_events,
            sample_weight_sum: app.wake_edge_sample_weight_sum,
            important_events: app.wake_edge_important_events,
            wake_events_est: wake_events,
            wait_samples_est: wait_samples,
        },
    )
    .with_lifecycle(LifecycleSummary {
        init_enqueue_avg_us: avg_us(
            stats.lifecycle_init_enqueue_us,
            stats.lifecycle_init_enqueue_count,
        ),
        init_enqueue_count: stats.lifecycle_init_enqueue_count,
        init_select_avg_us: avg_us(
            stats.lifecycle_init_select_us,
            stats.lifecycle_init_select_count,
        ),
        init_select_count: stats.lifecycle_init_select_count,
        init_run_avg_us: avg_us(stats.lifecycle_init_run_us, stats.lifecycle_init_run_count),
        init_run_count: stats.lifecycle_init_run_count,
        run_stop_avg_us: avg_ns(stats.task_runtime_ns, stats.task_run_count) / 1000,
        run_stop_count: stats.task_run_count,
        init_exit_avg_us: avg_us(
            stats.lifecycle_init_exit_us,
            stats.lifecycle_init_exit_count,
        ),
        init_exit_count: stats.lifecycle_init_exit_count,
    })
    .with_accelerator(accelerator)
}

fn report_conf_value(confidence: u64, shift: u32) -> u64 {
    (confidence >> shift) & CAKE_CONF_NIBBLE_MASK
}

fn report_conf_effective_value(confidence: u64, shift: u32) -> u64 {
    let value = report_conf_value(confidence, shift);
    if value == 0 {
        8
    } else {
        value
    }
}

fn report_load_shock_value(confidence: u64) -> u64 {
    report_conf_value(confidence, CAKE_CONF_LOAD_SHOCK_SHIFT)
}

fn report_floor_owner_ready(confidence: u64) -> bool {
    let owner_stable = report_conf_effective_value(confidence, CAKE_CONF_OWNER_STABLE_SHIFT);
    let route = report_conf_effective_value(confidence, CAKE_CONF_ROUTE_SHIFT);
    let trust = report_conf_effective_value(confidence, CAKE_CONF_STATUS_TRUST_SHIFT);
    let pull = report_conf_effective_value(confidence, CAKE_CONF_PULL_SHAPE_SHIFT);
    let shock = report_load_shock_value(confidence);

    owner_stable >= 12 || (route == 15 && trust == 15 && pull >= 12 && shock < 8)
}

fn report_floor_ready(confidence: u64) -> bool {
    report_conf_value(confidence, CAKE_CONF_FLOOR_GEAR_SHIFT) == 3
        && report_conf_effective_value(confidence, CAKE_CONF_ROUTE_SHIFT) >= 12
        && report_conf_effective_value(confidence, CAKE_CONF_SELECT_EARLY_SHIFT) >= 12
        && report_conf_effective_value(confidence, CAKE_CONF_STATUS_TRUST_SHIFT) >= 12
        && report_floor_owner_ready(confidence)
        && report_load_shock_value(confidence) < 8
        && report_conf_effective_value(confidence, CAKE_CONF_PULL_SHAPE_SHIFT) >= 8
}

fn report_route_ready(confidence: u64) -> bool {
    report_conf_effective_value(confidence, CAKE_CONF_ROUTE_SHIFT) >= 12
        && report_conf_effective_value(confidence, CAKE_CONF_SELECT_EARLY_SHIFT) >= 12
        && report_conf_effective_value(confidence, CAKE_CONF_STATUS_TRUST_SHIFT) >= 12
        && report_load_shock_value(confidence) < 12
}

fn report_accelerator_source() -> &'static str {
    #[cfg(cake_bpf_release)]
    {
        "release"
    }
    #[cfg(all(not(cake_bpf_release), cake_hot_telemetry))]
    {
        "debug-hot-telemetry"
    }
    #[cfg(all(not(cake_bpf_release), not(cake_hot_telemetry)))]
    {
        "debug-no-hot-telemetry"
    }
}

fn build_accelerator_summary(stats: &cake_stats, app: &TuiApp) -> AcceleratorSummary {
    let mut summary = AcceleratorSummary {
        source: report_accelerator_source().to_string(),
        select_tunnel: stats.select_path_count[5],
        select_idle: stats.select_path_count[4],
        wake_target_hit: stats.wake_target_hit_count[1..].iter().sum(),
        wake_target_miss: stats.wake_target_miss_count[1..].iter().sum(),
        wake_direct: stats.nr_wakeup_direct_dispatches,
        wake_busy: stats.nr_wakeup_dsq_fallback_busy,
        wake_queued: stats.nr_wakeup_dsq_fallback_queued,
        dispatch_hit: stats.nr_dispatch_llc_local_hit + stats.nr_dispatch_llc_steal_hit,
        dispatch_miss: stats.nr_dispatch_misses,
        route_attempt_counts: stats.accel_route_attempt_count,
        route_hit_counts: stats.accel_route_hit_count,
        route_miss_counts: stats.accel_route_miss_count,
        fast_attempt_counts: stats.accel_fast_attempt_count,
        fast_hit_counts: stats.accel_fast_hit_count,
        fast_miss_counts: stats.accel_fast_miss_count,
        route_block_counts: stats.accel_route_block_count,
        scoreboard_probe_counts: stats.accel_scoreboard_probe_count,
        pull_mode_counts: stats.accel_pull_mode_count,
        pull_probe_counts: stats.accel_pull_probe_count,
        native_fallback_counts: stats.accel_native_fallback_count,
        accounting_relaxed: stats.accel_accounting_relaxed,
        accounting_audit: stats.accel_accounting_audit,
        trust_prev_attempts: stats.accel_trust_prev_attempt,
        trust_prev_hits: stats.accel_trust_prev_hit,
        trust_prev_misses: stats.accel_trust_prev_miss,
        ..AcceleratorSummary::default()
    };

    for counter in app
        .per_cpu_work
        .iter()
        .filter(|counter| counter.decision_confidence != 0)
    {
        let confidence = counter.decision_confidence;
        let gear = report_conf_value(confidence, CAKE_CONF_FLOOR_GEAR_SHIFT) as usize;
        let route = report_conf_value(confidence, CAKE_CONF_ROUTE_KIND_SHIFT) as usize;

        summary.trained_cpus += 1;
        if gear < summary.gear_counts.len() {
            summary.gear_counts[gear] += 1;
        }
        if route < summary.route_counts.len() {
            summary.route_counts[route] += 1;
        }
        if report_route_ready(confidence) {
            summary.route_ready_cpus += 1;
        }
        if report_floor_ready(confidence) {
            summary.floor_ready_cpus += 1;
        }
        if report_load_shock_value(confidence) >= 8 {
            summary.shock_cpus += 1;
        }
        if report_conf_effective_value(confidence, CAKE_CONF_STATUS_TRUST_SHIFT) < 12 {
            summary.trust_low_cpus += 1;
        }
        if report_conf_effective_value(confidence, CAKE_CONF_OWNER_STABLE_SHIFT) < 12 {
            summary.owner_low_cpus += 1;
        }
    }
    for counter in &app.per_cpu_work {
        if counter.trust.prev_direct_enabled() {
            summary.trust_prev_enabled_cpus += 1;
        }
        if counter.trust.prev_direct_active() {
            summary.trust_prev_active_cpus += 1;
        }
        if counter.trust.prev_direct_blocked() {
            summary.trust_prev_blocked_cpus += 1;
        }
        summary.trust_prev_demotions = summary
            .trust_prev_demotions
            .saturating_add(counter.trust.demotion_count as u64);
    }

    summary
}
