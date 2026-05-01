// SPDX-License-Identifier: GPL-2.0

use super::*;
use crate::telemetry_report::{
    CoverageItem, CoverageQuality, GraphSummary, HealthSummary, LifecycleSummary, TelemetryReport,
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
}
