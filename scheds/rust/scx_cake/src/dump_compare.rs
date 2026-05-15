// SPDX-License-Identifier: GPL-2.0

use std::fs;
use std::path::Path;

use anyhow::{Context, Result};

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct DumpMetrics {
    pub life: ScopeMetrics,
    pub win30: ScopeMetrics,
    pub win60: ScopeMetrics,
    pub coverage: CoverageMetrics,
    pub service: ServiceMetrics,
    pub top_app: AppHealthMetrics,
    pub wakegraph_tail: WakegraphEdgeMetrics,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct CoverageMetrics {
    pub status: String,
    pub degraded: u64,
    pub sections: u64,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ServiceMetrics {
    pub status: String,
    pub active_codes: u64,
    pub freeze_frames: u64,
    pub pass: u64,
    pub warn: u64,
    pub fail: u64,
    pub not_ready: u64,
    pub dtc_active: u64,
    pub dtc_warn: u64,
    pub dtc_fail: u64,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ScopeMetrics {
    pub busy_wakes: u64,
    pub busy_preempt_allow: u64,
    pub busy_preempt_skip: u64,
    pub direct_wait_avg_us: u64,
    pub direct_wait_max_us: u64,
    pub busy_wait_avg_us: u64,
    pub busy_wait_max_us: u64,
    pub queued_wait_avg_us: u64,
    pub queued_wait_max_us: u64,
    pub primary_scan_guarded: u64,
    pub primary_scan_hot_guarded: u64,
    pub primary_scan_credit_used: u64,
    pub wake_chain_locality_guarded: u64,
    pub wake_chain_locality_credit_used: u64,
    pub smt_runtime_contended_tenths: u64,
    pub smt_runs_contended_tenths: u64,
    pub shield_samples: u64,
    pub contain_samples: u64,
    pub strict_busy_preempt_allow: u64,
    pub strict_busy_preempt_skip: u64,
    pub strict_shield_samples: u64,
    pub strict_contain_samples: u64,
    pub strict_shield_wait_max_us: u64,
    pub strict_contain_wait_max_us: u64,
    pub storm_candidate: u64,
    pub storm_base_allow: u64,
    pub storm_shadow: u64,
    pub storm_shield_allow: u64,
    pub storm_full_allow: u64,
    pub storm_smt_block: u64,
    pub storm_unknown_owner: u64,
    pub storm_disabled: u64,
    pub storm_reject: u64,
    pub direct_wake_bins: [u64; 5],
    pub busy_wake_bins: [u64; 5],
    pub queued_wake_bins: [u64; 5],
    pub path_home: u64,
    pub path_core: u64,
    pub path_primary: u64,
    pub path_idle: u64,
    pub path_tunnel: u64,
    pub select_migrate_path: [u64; 5],
    pub select_migrate_reason: [u64; 11],
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct AppHealthMetrics {
    pub label: String,
    pub share_tenths: u64,
    pub wake_total: u64,
    pub wait_max_us: u64,
    pub migration_rate_tenths: u64,
    pub yield_count: u64,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct WakegraphEdgeMetrics {
    pub label: String,
    pub wake_count: u64,
    pub wait_max_us: u64,
    pub ge5ms_count: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WindowScope {
    Win30,
    Win60,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ParseSection {
    None,
    AppHealth,
    DtcActive,
    Wakegraph,
}

pub fn run_compare(baseline: &Path, candidate: &Path) -> Result<()> {
    let baseline_text = fs::read_to_string(baseline)
        .with_context(|| format!("failed to read baseline dump {}", baseline.display()))?;
    let candidate_text = fs::read_to_string(candidate)
        .with_context(|| format!("failed to read candidate dump {}", candidate.display()))?;

    let baseline = parse_metrics(&baseline_text);
    let candidate = parse_metrics(&candidate_text);

    println!("scx_cake dump comparison");
    print_coverage(&baseline.coverage, &candidate.coverage);
    print_service(&baseline.service, &candidate.service);
    print_scope("life", &baseline.life, &candidate.life);
    print_scope("30s", &baseline.win30, &candidate.win30);
    print_scope("60s", &baseline.win60, &candidate.win60);
    print_app_health(&baseline.top_app, &candidate.top_app);
    print_wakegraph_tail(&baseline.wakegraph_tail, &candidate.wakegraph_tail);

    Ok(())
}

fn parse_metrics(dump: &str) -> DumpMetrics {
    let mut metrics = DumpMetrics::default();
    let mut current_window = None;
    let mut section = ParseSection::None;

    for raw_line in dump.lines() {
        let line = raw_line.trim_start();

        if !raw_line.starts_with(' ') {
            section = ParseSection::None;
        }

        if line.starts_with("window:") {
            current_window = parse_window_scope(line);
            continue;
        }

        if line.starts_with("coverage:") {
            parse_coverage_line(&mut metrics.coverage, line);
            continue;
        }

        if line.starts_with("service.header:") {
            parse_service_header_line(&mut metrics.service, line);
            continue;
        }

        if line.starts_with("readiness:") {
            parse_readiness_line(&mut metrics.service, line);
            continue;
        }

        if line.starts_with("dtc.active:") {
            section = ParseSection::DtcActive;
            continue;
        }

        if line.starts_with("app.health.life:") {
            section = ParseSection::AppHealth;
            continue;
        }

        if line.starts_with("wakegraph.top:") || line.starts_with("wakegraph.latency:") {
            section = ParseSection::Wakegraph;
            continue;
        }

        match section {
            ParseSection::AppHealth if line.starts_with("tgid=") => {
                if let Some(app) = parse_app_health_line(line) {
                    if app.share_tenths > metrics.top_app.share_tenths {
                        metrics.top_app = app;
                    }
                }
                continue;
            }
            ParseSection::DtcActive if raw_line.starts_with("  ") && line.starts_with("code=") => {
                parse_dtc_active_line(&mut metrics.service, line);
                continue;
            }
            ParseSection::Wakegraph if raw_line.starts_with("  ") && line.contains(" -> ") => {
                if let Some(edge) = parse_wakegraph_edge_line(line) {
                    if edge.wait_max_us > metrics.wakegraph_tail.wait_max_us {
                        metrics.wakegraph_tail = edge;
                    }
                }
                continue;
            }
            _ => {}
        }

        if line.starts_with("disp:") {
            parse_disp_line(&mut metrics.life, line);
            continue;
        }

        if line.starts_with("win.disp:") {
            if let Some(scope) = scope_for_window(&mut metrics, current_window) {
                parse_disp_line(scope, line);
            }
            continue;
        }

        if line.starts_with("wakewait.all:") {
            parse_wakewait_line(&mut metrics.life, line);
            continue;
        }

        if line.starts_with("win.wakewait.all:") {
            if let Some(scope) = scope_for_window(&mut metrics, current_window) {
                parse_wakewait_line(scope, line);
            }
            continue;
        }

        if line.starts_with("smt:") {
            parse_smt_line(&mut metrics.life, line);
            continue;
        }

        if line.starts_with("win.smt:") {
            if let Some(scope) = scope_for_window(&mut metrics, current_window) {
                parse_smt_line(scope, line);
            }
            continue;
        }

        if line.starts_with("wakebins:") {
            parse_wakebins_line(&mut metrics.life, line);
            continue;
        }

        if line.starts_with("win.wakebins:") {
            if let Some(scope) = scope_for_window(&mut metrics, current_window) {
                parse_wakebins_line(scope, line);
            }
            continue;
        }

        if line.starts_with("decision.migrate:") {
            parse_select_migrate_line(&mut metrics.life, line);
            continue;
        }

        if line.starts_with("win.decision.migrate:") {
            if let Some(scope) = scope_for_window(&mut metrics, current_window) {
                parse_select_migrate_line(scope, line);
            }
            continue;
        }

        if line.starts_with("place.path:") {
            parse_path_line(&mut metrics.life, line);
            continue;
        }

        if line.starts_with("win.path:") {
            if let Some(scope) = scope_for_window(&mut metrics, current_window) {
                parse_path_line(scope, line);
            }
            continue;
        }

        if line.starts_with("wakepolicy.life:") {
            parse_wakepolicy_line(&mut metrics.life, line);
            continue;
        }

        if line.starts_with("wakepolicy.strict.life:") {
            parse_strict_wakepolicy_line(&mut metrics.life, line);
            continue;
        }

        if line.starts_with("accelerator.life.storm_guard:") {
            parse_storm_guard_line(&mut metrics.life, line);
            continue;
        }

        if line.starts_with("accelerator.60s.storm_guard:") {
            parse_storm_guard_line(&mut metrics.win60, line);
            continue;
        }

        if line.starts_with("win.wakepolicy.strict.") {
            if let Some(scope) = strict_wakepolicy_window_scope(line)
                .and_then(|scope| scope_for_window(&mut metrics, Some(scope)))
            {
                parse_strict_wakepolicy_line(scope, line);
            }
            continue;
        }

        if line.starts_with("win.wakepolicy.") {
            if let Some(scope) = wakepolicy_window_scope(line)
                .and_then(|scope| scope_for_window(&mut metrics, Some(scope)))
            {
                parse_wakepolicy_line(scope, line);
            }
            continue;
        }
    }

    metrics
}

fn print_scope(name: &str, baseline: &ScopeMetrics, candidate: &ScopeMetrics) {
    if !baseline.has_data() && !candidate.has_data() {
        return;
    }

    println!();
    println!("{name}:");
    print_metric("busy_wakes", baseline.busy_wakes, candidate.busy_wakes, "");
    print_metric(
        "busy_preempt_allow",
        baseline.busy_preempt_allow,
        candidate.busy_preempt_allow,
        "",
    );
    print_metric(
        "busy_preempt_skip",
        baseline.busy_preempt_skip,
        candidate.busy_preempt_skip,
        "",
    );
    print_metric(
        "direct_wait_avg",
        baseline.direct_wait_avg_us,
        candidate.direct_wait_avg_us,
        "us",
    );
    print_metric(
        "direct_wait_max",
        baseline.direct_wait_max_us,
        candidate.direct_wait_max_us,
        "us",
    );
    print_metric(
        "busy_wait_avg",
        baseline.busy_wait_avg_us,
        candidate.busy_wait_avg_us,
        "us",
    );
    print_metric(
        "busy_wait_max",
        baseline.busy_wait_max_us,
        candidate.busy_wait_max_us,
        "us",
    );
    print_metric(
        "queued_wait_avg",
        baseline.queued_wait_avg_us,
        candidate.queued_wait_avg_us,
        "us",
    );
    print_metric(
        "queued_wait_max",
        baseline.queued_wait_max_us,
        candidate.queued_wait_max_us,
        "us",
    );
    print_metric(
        "primary_scan_guarded",
        baseline.primary_scan_guarded,
        candidate.primary_scan_guarded,
        "",
    );
    print_metric(
        "primary_scan_hot_guarded",
        baseline.primary_scan_hot_guarded,
        candidate.primary_scan_hot_guarded,
        "",
    );
    print_metric(
        "primary_scan_credit_used",
        baseline.primary_scan_credit_used,
        candidate.primary_scan_credit_used,
        "",
    );
    print_metric(
        "wake_chain_locality_guarded",
        baseline.wake_chain_locality_guarded,
        candidate.wake_chain_locality_guarded,
        "",
    );
    print_metric(
        "wake_chain_locality_credit_used",
        baseline.wake_chain_locality_credit_used,
        candidate.wake_chain_locality_credit_used,
        "",
    );
    print_pct_metric(
        "smt_runtime_contended",
        baseline.smt_runtime_contended_tenths,
        candidate.smt_runtime_contended_tenths,
    );
    print_pct_metric(
        "smt_runs_contended",
        baseline.smt_runs_contended_tenths,
        candidate.smt_runs_contended_tenths,
    );
    print_metric(
        "shield_samples",
        baseline.shield_samples,
        candidate.shield_samples,
        "",
    );
    print_metric(
        "contain_samples",
        baseline.contain_samples,
        candidate.contain_samples,
        "",
    );
    print_metric(
        "strict_busy_preempt_allow",
        baseline.strict_busy_preempt_allow,
        candidate.strict_busy_preempt_allow,
        "",
    );
    print_metric(
        "strict_busy_preempt_skip",
        baseline.strict_busy_preempt_skip,
        candidate.strict_busy_preempt_skip,
        "",
    );
    print_metric(
        "strict_shield_samples",
        baseline.strict_shield_samples,
        candidate.strict_shield_samples,
        "",
    );
    print_metric(
        "strict_contain_samples",
        baseline.strict_contain_samples,
        candidate.strict_contain_samples,
        "",
    );
    print_metric(
        "strict_shield_wait_max",
        baseline.strict_shield_wait_max_us,
        candidate.strict_shield_wait_max_us,
        "us",
    );
    print_metric(
        "strict_contain_wait_max",
        baseline.strict_contain_wait_max_us,
        candidate.strict_contain_wait_max_us,
        "us",
    );
    print_metric(
        "storm_candidate",
        baseline.storm_candidate,
        candidate.storm_candidate,
        "",
    );
    print_metric(
        "storm_base_allow",
        baseline.storm_base_allow,
        candidate.storm_base_allow,
        "",
    );
    print_metric(
        "storm_shadow",
        baseline.storm_shadow,
        candidate.storm_shadow,
        "",
    );
    print_metric(
        "storm_shield_allow",
        baseline.storm_shield_allow,
        candidate.storm_shield_allow,
        "",
    );
    print_metric(
        "storm_full_allow",
        baseline.storm_full_allow,
        candidate.storm_full_allow,
        "",
    );
    print_metric(
        "storm_smt_block",
        baseline.storm_smt_block,
        candidate.storm_smt_block,
        "",
    );
    print_metric(
        "storm_unknown_owner",
        baseline.storm_unknown_owner,
        candidate.storm_unknown_owner,
        "",
    );
    print_metric(
        "storm_disabled",
        baseline.storm_disabled,
        candidate.storm_disabled,
        "",
    );
    print_metric(
        "storm_reject",
        baseline.storm_reject,
        candidate.storm_reject,
        "",
    );
    print_bins(
        "wakebins.direct",
        &baseline.direct_wake_bins,
        &candidate.direct_wake_bins,
    );
    print_bins(
        "wakebins.busy",
        &baseline.busy_wake_bins,
        &candidate.busy_wake_bins,
    );
    print_bins(
        "wakebins.queued",
        &baseline.queued_wake_bins,
        &candidate.queued_wake_bins,
    );
    print_path(baseline, candidate);
    print_select_migrate_path(baseline, candidate);
    print_select_migrate_reason(baseline, candidate);
}

impl ScopeMetrics {
    fn has_data(&self) -> bool {
        self.busy_wakes != 0
            || self.busy_preempt_allow != 0
            || self.busy_preempt_skip != 0
            || self.direct_wait_avg_us != 0
            || self.direct_wait_max_us != 0
            || self.busy_wait_avg_us != 0
            || self.busy_wait_max_us != 0
            || self.queued_wait_avg_us != 0
            || self.queued_wait_max_us != 0
            || self.primary_scan_guarded != 0
            || self.primary_scan_hot_guarded != 0
            || self.primary_scan_credit_used != 0
            || self.wake_chain_locality_guarded != 0
            || self.wake_chain_locality_credit_used != 0
            || self.smt_runtime_contended_tenths != 0
            || self.smt_runs_contended_tenths != 0
            || self.shield_samples != 0
            || self.contain_samples != 0
            || self.strict_busy_preempt_allow != 0
            || self.strict_busy_preempt_skip != 0
            || self.strict_shield_samples != 0
            || self.strict_contain_samples != 0
            || self.strict_shield_wait_max_us != 0
            || self.strict_contain_wait_max_us != 0
            || self.storm_candidate != 0
            || self.storm_base_allow != 0
            || self.storm_shadow != 0
            || self.storm_shield_allow != 0
            || self.storm_full_allow != 0
            || self.storm_smt_block != 0
            || self.storm_unknown_owner != 0
            || self.storm_disabled != 0
            || self.storm_reject != 0
            || self.direct_wake_bins.iter().any(|count| *count != 0)
            || self.busy_wake_bins.iter().any(|count| *count != 0)
            || self.queued_wake_bins.iter().any(|count| *count != 0)
            || self.path_home != 0
            || self.path_core != 0
            || self.path_primary != 0
            || self.path_idle != 0
            || self.path_tunnel != 0
            || self.select_migrate_path.iter().any(|count| *count != 0)
            || self.select_migrate_reason.iter().any(|count| *count != 0)
    }
}

fn print_app_health(baseline: &AppHealthMetrics, candidate: &AppHealthMetrics) {
    if !baseline.has_data() && !candidate.has_data() {
        return;
    }

    println!();
    println!("top_app:");
    println!(
        "label: baseline={} candidate={}",
        label_or_dash(&baseline.label),
        label_or_dash(&candidate.label)
    );
    print_pct_metric(
        "runtime_share",
        baseline.share_tenths,
        candidate.share_tenths,
    );
    print_metric("wake_total", baseline.wake_total, candidate.wake_total, "");
    print_metric(
        "sched_yield",
        baseline.yield_count,
        candidate.yield_count,
        "",
    );
    print_metric(
        "wait_max",
        baseline.wait_max_us,
        candidate.wait_max_us,
        "us",
    );
    print_decimal_metric(
        "migration_rate",
        baseline.migration_rate_tenths,
        candidate.migration_rate_tenths,
        "/s",
    );
}

impl AppHealthMetrics {
    fn has_data(&self) -> bool {
        !self.label.is_empty()
            || self.share_tenths != 0
            || self.wake_total != 0
            || self.wait_max_us != 0
            || self.migration_rate_tenths != 0
            || self.yield_count != 0
    }
}

fn print_wakegraph_tail(baseline: &WakegraphEdgeMetrics, candidate: &WakegraphEdgeMetrics) {
    if !baseline.has_data() && !candidate.has_data() {
        return;
    }

    println!();
    println!("wakegraph_tail:");
    println!(
        "edge: baseline={} candidate={}",
        label_or_dash(&baseline.label),
        label_or_dash(&candidate.label)
    );
    print_metric("wake_count", baseline.wake_count, candidate.wake_count, "");
    print_metric(
        "wait_max",
        baseline.wait_max_us,
        candidate.wait_max_us,
        "us",
    );
    print_metric(
        "ge5ms_bucket",
        baseline.ge5ms_count,
        candidate.ge5ms_count,
        "",
    );
}

impl WakegraphEdgeMetrics {
    fn has_data(&self) -> bool {
        !self.label.is_empty()
            || self.wake_count != 0
            || self.wait_max_us != 0
            || self.ge5ms_count != 0
    }
}

fn label_or_dash(label: &str) -> &str {
    if label.is_empty() {
        "-"
    } else {
        label
    }
}

fn scope_for_window(
    metrics: &mut DumpMetrics,
    window: Option<WindowScope>,
) -> Option<&mut ScopeMetrics> {
    match window {
        Some(WindowScope::Win30) => Some(&mut metrics.win30),
        Some(WindowScope::Win60) => Some(&mut metrics.win60),
        None => None,
    }
}

fn parse_disp_line(metrics: &mut ScopeMetrics, line: &str) {
    metrics.busy_wakes = field_u64(line, "busy=").unwrap_or(0);
    metrics.primary_scan_guarded = field_u64(line, "guard:primary_scan=").unwrap_or(0);
    metrics.primary_scan_hot_guarded = field_u64(line, "hot_guard:primary_scan=").unwrap_or(0);
    metrics.primary_scan_credit_used = field_u64(line, "credit:primary_scan=").unwrap_or(0);
    metrics.wake_chain_locality_guarded = field_u64(line, "chain:guard=").unwrap_or(0);
    metrics.wake_chain_locality_credit_used = field_u64(line, "chain:credit=").unwrap_or(0);
}

fn parse_wakewait_line(metrics: &mut ScopeMetrics, line: &str) {
    let (direct_avg, direct_max) = wakewait_avg_max_us(line, "dir=");
    let (busy_avg, busy_max) = wakewait_avg_max_us(line, "busy=");
    let (queued_avg, queued_max) = wakewait_avg_max_us(line, "queue=");

    metrics.direct_wait_avg_us = direct_avg;
    metrics.direct_wait_max_us = direct_max;
    metrics.busy_wait_avg_us = busy_avg;
    metrics.busy_wait_max_us = busy_max;
    metrics.queued_wait_avg_us = queued_avg;
    metrics.queued_wait_max_us = queued_max;
}

fn parse_smt_line(metrics: &mut ScopeMetrics, line: &str) {
    metrics.smt_runtime_contended_tenths = percent_tenths(line, "runtime_contended=").unwrap_or(0);
    metrics.smt_runs_contended_tenths = percent_tenths(line, "runs_contended=").unwrap_or(0);
}

fn parse_wakebins_line(metrics: &mut ScopeMetrics, line: &str) {
    metrics.direct_wake_bins = bucket_array(line, "direct=");
    metrics.busy_wake_bins = bucket_array(line, "busy=");
    metrics.queued_wake_bins = bucket_array(line, "queued=");
}

fn parse_path_line(metrics: &mut ScopeMetrics, line: &str) {
    metrics.path_home = field_u64(line, "home=").unwrap_or(0);
    metrics.path_core = field_u64(line, "core=").unwrap_or(0);
    metrics.path_primary = field_u64(line, "primary=").unwrap_or(0);
    metrics.path_idle = field_u64(line, "idle=").unwrap_or(0);
    metrics.path_tunnel = field_u64(line, "tunnel=").unwrap_or(0);
}

fn parse_select_migrate_line(metrics: &mut ScopeMetrics, line: &str) {
    if let Some(path) = bracket_body(line, "path=[") {
        metrics.select_migrate_path = [
            field_u64(path, "home=").unwrap_or(0),
            field_u64(path, "core=").unwrap_or(0),
            field_u64(path, "primary=").unwrap_or(0),
            field_u64(path, "idle=").unwrap_or(0),
            field_u64(path, "tunnel=").unwrap_or(0),
        ];
    }

    if let Some(reason) = bracket_body(line, "reason=[") {
        metrics.select_migrate_reason = [
            field_u64(reason, "hm=").unwrap_or(0),
            field_u64(reason, "hc=").unwrap_or(0),
            field_u64(reason, "pp=").unwrap_or(0),
            field_u64(reason, "ps=").unwrap_or(0),
            field_u64(reason, "hy=").unwrap_or(0),
            field_u64(reason, "kp=").unwrap_or(0),
            field_u64(reason, "ki=").unwrap_or(0),
            field_u64(reason, "tn=").unwrap_or(0),
            field_u64(reason, "pc=").unwrap_or(0),
            field_u64(reason, "sbp=").unwrap_or(0),
            field_u64(reason, "sbs=").unwrap_or(0),
        ];
    }
}

fn parse_wakepolicy_line(metrics: &mut ScopeMetrics, line: &str) {
    metrics.busy_preempt_allow = field_u64(line, "allow=").unwrap_or(0);
    metrics.busy_preempt_skip = field_u64(line, "skip=").unwrap_or(0);
    if let Some(class_counts) = bracket_body(line, "class=[") {
        metrics.shield_samples = field_u64(class_counts, "shield=").unwrap_or(0);
        metrics.contain_samples = field_u64(class_counts, "contain=").unwrap_or(0);
    }
}

fn parse_strict_wakepolicy_line(metrics: &mut ScopeMetrics, line: &str) {
    metrics.strict_busy_preempt_allow = field_u64(line, "allow=").unwrap_or(0);
    metrics.strict_busy_preempt_skip = field_u64(line, "skip=").unwrap_or(0);
    if let Some(class_counts) = bracket_body(line, "class=[") {
        metrics.strict_shield_samples = field_u64(class_counts, "shield=").unwrap_or(0);
        metrics.strict_contain_samples = field_u64(class_counts, "contain=").unwrap_or(0);
    }
    if let Some(wait) = bracket_body(line, "wait=[") {
        metrics.strict_shield_wait_max_us = wakewait_avg_max_us(wait, "shield=").1;
        metrics.strict_contain_wait_max_us = wakewait_avg_max_us(wait, "contain=").1;
    }
}

fn parse_storm_guard_line(metrics: &mut ScopeMetrics, line: &str) {
    if let Some(decisions) = bracket_body(line, "decisions=[") {
        metrics.storm_candidate = field_u64(decisions, "candidate=").unwrap_or(0);
        metrics.storm_base_allow = field_u64(decisions, "base_allow=").unwrap_or(0);
        metrics.storm_shadow = field_u64(decisions, "shadow=").unwrap_or(0);
        metrics.storm_shield_allow = field_u64(decisions, "shield_allow=").unwrap_or(0);
        metrics.storm_full_allow = field_u64(decisions, "full_allow=").unwrap_or(0);
        metrics.storm_smt_block = field_u64(decisions, "smt_block=").unwrap_or(0);
        metrics.storm_unknown_owner = field_u64(decisions, "unknown_owner=").unwrap_or(0);
        metrics.storm_disabled = field_u64(decisions, "disabled=").unwrap_or(0);
        metrics.storm_reject = field_u64(decisions, "reject=").unwrap_or(0);
    }
}

fn parse_coverage_line(metrics: &mut CoverageMetrics, line: &str) {
    metrics.status = token_after(line, "status=")
        .unwrap_or("unknown")
        .to_string();
    metrics.degraded = field_u64(line, "degraded=").unwrap_or(0);
    metrics.sections = field_u64(line, "sections=").unwrap_or(0);
}

fn parse_service_header_line(metrics: &mut ServiceMetrics, line: &str) {
    metrics.status = token_after(line, "status=")
        .unwrap_or("unknown")
        .to_string();
    metrics.active_codes = field_u64(line, "active_codes=").unwrap_or(0);
    metrics.freeze_frames = field_u64(line, "freeze_frames=").unwrap_or(0);
}

fn parse_readiness_line(metrics: &mut ServiceMetrics, line: &str) {
    metrics.pass = field_u64(line, "pass=").unwrap_or(0);
    metrics.warn = field_u64(line, "warn=").unwrap_or(0);
    metrics.fail = field_u64(line, "action=")
        .or_else(|| field_u64(line, "fail="))
        .unwrap_or(0);
    metrics.not_ready = field_u64(line, "warmup=")
        .or_else(|| field_u64(line, "not_ready="))
        .unwrap_or(0);
}

fn parse_dtc_active_line(metrics: &mut ServiceMetrics, line: &str) {
    metrics.dtc_active = metrics.dtc_active.saturating_add(1);
    match token_after(line, "severity=") {
        Some("warn") => metrics.dtc_warn = metrics.dtc_warn.saturating_add(1),
        Some("fail") => metrics.dtc_fail = metrics.dtc_fail.saturating_add(1),
        _ => {}
    }
}

fn parse_app_health_line(line: &str) -> Option<AppHealthMetrics> {
    let tgid = field_u64(line, "tgid=")?;
    let comm = token_after(line, "comm=")?;
    let share_tenths = percent_tenths(line, "share=")?;
    let migration_rate_tenths = decimal_tenths(line, "mig/s=").unwrap_or(0);
    let yield_count = field_u64(line, "syld=").unwrap_or(0);
    let wake_total = slash_values(line, "wake[self/in/out]=")
        .iter()
        .copied()
        .sum();
    let wait_self_max = wakewait_avg_max_us(line, "wait_self=").1;
    let wait_out_max = wakewait_avg_max_us(line, "wait_out=").1;

    Some(AppHealthMetrics {
        label: format!("{comm}/{tgid}"),
        share_tenths,
        wake_total,
        wait_max_us: wait_self_max.max(wait_out_max),
        migration_rate_tenths,
        yield_count,
    })
}

fn parse_wakegraph_edge_line(line: &str) -> Option<WakegraphEdgeMetrics> {
    let (label, rest) = line
        .split_once(" wake_est=")
        .or_else(|| line.split_once(" wake="))?;
    let wake_count = field_u64(rest, "").unwrap_or(0);
    let wait_max_us = if rest.contains("wait_est=") {
        wakewait_avg_max_us(rest, "wait_est=").1
    } else {
        wakewait_avg_max_us(rest, "wait=").1
    };
    let ge5ms_count = field_u64(rest, ">=5ms=").unwrap_or(0);

    Some(WakegraphEdgeMetrics {
        label: label.trim().to_string(),
        wake_count,
        wait_max_us,
        ge5ms_count,
    })
}

fn parse_window_scope(line: &str) -> Option<WindowScope> {
    let label = line.strip_prefix("window:")?.trim_start();
    if label.starts_with("30s ") {
        Some(WindowScope::Win30)
    } else if label.starts_with("60s ") {
        Some(WindowScope::Win60)
    } else {
        None
    }
}

fn wakepolicy_window_scope(line: &str) -> Option<WindowScope> {
    if line.starts_with("win.wakepolicy.30s:") {
        Some(WindowScope::Win30)
    } else if line.starts_with("win.wakepolicy.60s:") {
        Some(WindowScope::Win60)
    } else {
        None
    }
}

fn strict_wakepolicy_window_scope(line: &str) -> Option<WindowScope> {
    if line.starts_with("win.wakepolicy.strict.30s:") {
        Some(WindowScope::Win30)
    } else if line.starts_with("win.wakepolicy.strict.60s:") {
        Some(WindowScope::Win60)
    } else {
        None
    }
}

fn print_metric(name: &str, baseline: u64, candidate: u64, suffix: &str) {
    let delta = candidate as i128 - baseline as i128;
    println!(
        "{name}: baseline={}{} candidate={}{} delta={:+}{}",
        baseline, suffix, candidate, suffix, delta, suffix
    );
}

fn print_coverage(baseline: &CoverageMetrics, candidate: &CoverageMetrics) {
    let baseline_status = if baseline.status.is_empty() {
        "unknown"
    } else {
        &baseline.status
    };
    let candidate_status = if candidate.status.is_empty() {
        "unknown"
    } else {
        &candidate.status
    };
    println!("\n=== coverage ===");
    println!(
        "status: baseline={} candidate={}",
        baseline_status, candidate_status
    );
    print_metric(
        "coverage_degraded",
        baseline.degraded,
        candidate.degraded,
        "",
    );
    print_metric(
        "coverage_sections",
        baseline.sections,
        candidate.sections,
        "",
    );
}

fn print_service(baseline: &ServiceMetrics, candidate: &ServiceMetrics) {
    if !baseline.has_data() && !candidate.has_data() {
        return;
    }

    let baseline_status = if baseline.status.is_empty() {
        "unknown"
    } else {
        &baseline.status
    };
    let candidate_status = if candidate.status.is_empty() {
        "unknown"
    } else {
        &candidate.status
    };
    println!("\n=== service ===");
    println!(
        "status: baseline={} candidate={}",
        baseline_status, candidate_status
    );
    print_metric(
        "active_codes",
        baseline.active_codes,
        candidate.active_codes,
        "",
    );
    print_metric(
        "freeze_frames",
        baseline.freeze_frames,
        candidate.freeze_frames,
        "",
    );
    print_metric("monitor_pass", baseline.pass, candidate.pass, "");
    print_metric("monitor_warn", baseline.warn, candidate.warn, "");
    print_metric("monitor_fail", baseline.fail, candidate.fail, "");
    print_metric(
        "monitor_not_ready",
        baseline.not_ready,
        candidate.not_ready,
        "",
    );
    print_metric("dtc_active", baseline.dtc_active, candidate.dtc_active, "");
    print_metric("dtc_warn", baseline.dtc_warn, candidate.dtc_warn, "");
    print_metric("dtc_fail", baseline.dtc_fail, candidate.dtc_fail, "");
}

impl ServiceMetrics {
    fn has_data(&self) -> bool {
        !self.status.is_empty()
            || self.active_codes != 0
            || self.freeze_frames != 0
            || self.pass != 0
            || self.warn != 0
            || self.fail != 0
            || self.not_ready != 0
            || self.dtc_active != 0
            || self.dtc_warn != 0
            || self.dtc_fail != 0
    }
}

fn print_pct_metric(name: &str, baseline: u64, candidate: u64) {
    let delta = candidate as i128 - baseline as i128;
    println!(
        "{name}: baseline={} candidate={} delta={:+}",
        format_tenths_pct(baseline),
        format_tenths_pct(candidate),
        format_signed_tenths_pct(delta),
    );
}

fn print_decimal_metric(name: &str, baseline: u64, candidate: u64, suffix: &str) {
    let delta = candidate as i128 - baseline as i128;
    println!(
        "{name}: baseline={}{} candidate={}{} delta={}{}",
        format_tenths_decimal(baseline),
        suffix,
        format_tenths_decimal(candidate),
        suffix,
        format_signed_tenths_decimal(delta),
        suffix,
    );
}

fn print_bins(name: &str, baseline: &[u64; 5], candidate: &[u64; 5]) {
    let delta = std::array::from_fn(|idx| candidate[idx] as i128 - baseline[idx] as i128);
    println!(
        "{name}: baseline={} candidate={} delta={}",
        format_bins_u64(baseline),
        format_bins_u64(candidate),
        format_bins_i128(&delta)
    );
}

fn print_path(baseline: &ScopeMetrics, candidate: &ScopeMetrics) {
    let baseline_values = [
        baseline.path_home,
        baseline.path_core,
        baseline.path_primary,
        baseline.path_idle,
        baseline.path_tunnel,
    ];
    let candidate_values = [
        candidate.path_home,
        candidate.path_core,
        candidate.path_primary,
        candidate.path_idle,
        candidate.path_tunnel,
    ];
    let delta =
        std::array::from_fn(|idx| candidate_values[idx] as i128 - baseline_values[idx] as i128);
    println!(
        "path: baseline={} candidate={} delta={}",
        format_labeled_u64(
            &["home", "core", "primary", "idle", "tunnel"],
            &baseline_values
        ),
        format_labeled_u64(
            &["home", "core", "primary", "idle", "tunnel"],
            &candidate_values
        ),
        format_labeled_i128(&["home", "core", "primary", "idle", "tunnel"], &delta),
    );
}

fn print_select_migrate_path(baseline: &ScopeMetrics, candidate: &ScopeMetrics) {
    let delta = std::array::from_fn(|idx| {
        candidate.select_migrate_path[idx] as i128 - baseline.select_migrate_path[idx] as i128
    });
    println!(
        "select_migrate.path: baseline={} candidate={} delta={}",
        format_labeled_u64(
            &["home", "core", "primary", "idle", "tunnel"],
            &baseline.select_migrate_path
        ),
        format_labeled_u64(
            &["home", "core", "primary", "idle", "tunnel"],
            &candidate.select_migrate_path
        ),
        format_labeled_i128(&["home", "core", "primary", "idle", "tunnel"], &delta),
    );
}

fn print_select_migrate_reason(baseline: &ScopeMetrics, candidate: &ScopeMetrics) {
    let delta = std::array::from_fn(|idx| {
        candidate.select_migrate_reason[idx] as i128 - baseline.select_migrate_reason[idx] as i128
    });
    println!(
        "select_migrate.reason: baseline={} candidate={} delta={}",
        format_labeled_u64(
            &["hm", "hc", "pp", "ps", "hy", "kp", "ki", "tn", "pc", "sbp", "sbs"],
            &baseline.select_migrate_reason
        ),
        format_labeled_u64(
            &["hm", "hc", "pp", "ps", "hy", "kp", "ki", "tn", "pc", "sbp", "sbs"],
            &candidate.select_migrate_reason
        ),
        format_labeled_i128(
            &["hm", "hc", "pp", "ps", "hy", "kp", "ki", "tn", "pc", "sbp", "sbs"],
            &delta
        ),
    );
}

fn format_tenths_pct(value: u64) -> String {
    format!("{}.{:01}%", value / 10, value % 10)
}

fn format_signed_tenths_pct(value: i128) -> String {
    let sign = if value < 0 { "-" } else { "+" };
    let abs = value.abs();
    format!("{sign}{}.{:01}%", abs / 10, abs % 10)
}

fn format_tenths_decimal(value: u64) -> String {
    format!("{}.{:01}", value / 10, value % 10)
}

fn format_signed_tenths_decimal(value: i128) -> String {
    let sign = if value < 0 { "-" } else { "+" };
    let abs = value.abs();
    format!("{sign}{}.{:01}", abs / 10, abs % 10)
}

fn format_bins_u64(values: &[u64; 5]) -> String {
    format_labeled_u64(&["<50us", "<200us", "<1ms", "<5ms", ">=5ms"], values)
}

fn format_bins_i128(values: &[i128; 5]) -> String {
    format_labeled_i128(&["<50us", "<200us", "<1ms", "<5ms", ">=5ms"], values)
}

fn format_labeled_u64<const N: usize>(labels: &[&str; N], values: &[u64; N]) -> String {
    labels
        .iter()
        .zip(values.iter())
        .map(|(label, value)| format!("{label}={value}"))
        .collect::<Vec<_>>()
        .join(" ")
}

fn format_labeled_i128<const N: usize>(labels: &[&str; N], values: &[i128; N]) -> String {
    labels
        .iter()
        .zip(values.iter())
        .map(|(label, value)| format!("{label}={value:+}"))
        .collect::<Vec<_>>()
        .join(" ")
}

fn field_u64(text: &str, key: &str) -> Option<u64> {
    let rest = if key.is_empty() {
        text
    } else {
        text.split_once(key)?.1
    };
    let digits: String = rest.chars().take_while(|ch| ch.is_ascii_digit()).collect();
    digits.parse().ok()
}

fn wakewait_avg_max_us(line: &str, key: &str) -> (u64, u64) {
    let Some(rest) = line.split_once(key).map(|(_, rest)| rest) else {
        return (0, 0);
    };
    let Some((avg, after_slash)) = rest.split_once('/') else {
        return (0, 0);
    };
    let avg = avg.parse().unwrap_or(0);
    let max = after_slash
        .chars()
        .take_while(|ch| ch.is_ascii_digit())
        .collect::<String>()
        .parse()
        .unwrap_or(0);
    (avg, max)
}

fn bucket_array(line: &str, key: &str) -> [u64; 5] {
    let Some(rest) = line.split_once(key).map(|(_, rest)| rest) else {
        return [0; 5];
    };
    let values = rest
        .split_whitespace()
        .next()
        .unwrap_or("")
        .split('/')
        .filter_map(|value| value.parse::<u64>().ok())
        .collect::<Vec<_>>();
    std::array::from_fn(|idx| values.get(idx).copied().unwrap_or(0))
}

fn slash_values(line: &str, key: &str) -> Vec<u64> {
    line.split_once(key)
        .map(|(_, rest)| {
            rest.split_whitespace()
                .next()
                .unwrap_or("")
                .split('/')
                .filter_map(|value| value.parse::<u64>().ok())
                .collect()
        })
        .unwrap_or_default()
}

fn percent_tenths(text: &str, key: &str) -> Option<u64> {
    decimal_tenths(text, key)
}

fn decimal_tenths(text: &str, key: &str) -> Option<u64> {
    let rest = text.split_once(key)?.1;
    let mut parts = rest.splitn(2, |ch: char| !(ch.is_ascii_digit() || ch == '.'));
    let raw = parts.next()?;
    let (whole, frac) = raw.split_once('.').unwrap_or((raw, ""));
    let whole = whole.parse::<u64>().ok()?;
    let tenth = frac
        .chars()
        .next()
        .filter(char::is_ascii_digit)
        .map(|ch| ch as u64 - b'0' as u64)
        .unwrap_or(0);
    Some(whole * 10 + tenth)
}

fn bracket_body<'a>(text: &'a str, prefix: &str) -> Option<&'a str> {
    let rest = text.split_once(prefix)?.1;
    rest.split_once(']').map(|(body, _)| body)
}

fn token_after<'a>(text: &'a str, key: &str) -> Option<&'a str> {
    text.split_once(key)?.1.split_whitespace().next()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn compact_source(text: &str) -> String {
        text.split_whitespace().collect::<Vec<_>>().join(" ")
    }

    fn source_contains(text: &str, needle: &str) -> bool {
        compact_source(text).contains(&compact_source(needle))
    }

    fn source_body_between<'a>(text: &'a str, start: &str, end: &str) -> Option<&'a str> {
        let (_, rest) = text.split_once(start)?;
        let (body, _) = rest.split_once(end)?;
        Some(body)
    }

    #[test]
    fn bpf_debug_busy_wake_policy_has_owner_runtime_guard() {
        let src = include_str!("bpf/cake.bpf.c");

        assert!(src.contains("cake_busy_wake_policy_should_preempt("));
        assert!(!src.contains("if (is_wakeup && !idle_hint && wake_target_local)"));
        assert!(src.contains("CAKE_BUSY_OWNER_SHORT_RUN_NS 100000U"));
        assert!(src.contains("CAKE_BUSY_OWNER_MIN_RUNS 32U"));
        assert!(src.contains("CAKE_PRIMARY_SCAN_CREDIT_PERIOD 8U"));
        assert!(src.contains("primary_scan_credit"));
        assert!(src.contains("nr_primary_scan_credit_used"));
        assert!(src.contains("CAKE_HOT_PRIMARY_SCAN_CREDIT_PERIOD 8U"));
        assert!(src.contains("CAKE_HOT_PRIMARY_SCAN_UTIL_MAX 256U"));
        assert!(src.contains("CAKE_HOT_PRIMARY_SCAN_MIN_RUNS 128U"));
        assert!(src.contains("CAKE_HOT_PRIMARY_SCAN_AVG_RUN_NS 50000ULL"));
        assert!(source_contains(
            src,
            "#ifdef CAKE_RELEASE return false; #else"
        ));
        assert!(src.contains("total_runtime_ns <= (u64)runs * CAKE_HOT_PRIMARY_SCAN_AVG_RUN_NS"));
        assert!(src.contains("cake_should_guard_hot_primary_scan("));
        assert!(src.contains("nr_primary_scan_hot_guarded"));

        let hot_guard_body = source_body_between(
            src,
            "cake_should_guard_hot_primary_scan",
            "cake_should_hold_wake_chain_locality",
        )
        .expect("hot primary scan guard body should be present");
        assert!(hot_guard_body.contains("behavior shape instead of the wake-sync flag"));
        assert!(!hot_guard_body.contains("wake_flags & SCX_WAKE_SYNC"));
    }

    #[test]
    fn bpf_wake_chain_locality_policy_is_identity_free() {
        let src = include_str!("bpf/cake.bpf.c");
        let intf = include_str!("bpf/intf.h");
        let dump = include_str!("tui/dump.rs");

        assert!(src.contains("CAKE_WAKE_CHAIN_POLICY_SCORE_MIN 8U"));
        assert!(src.contains("cake_wake_chain_policy_update("));
        assert!(src.contains("cake_should_hold_wake_chain_locality("));
        assert!(intf.contains("nr_wake_chain_locality_guarded"));
        assert!(intf.contains("nr_wake_chain_locality_credit_used"));
        assert!(dump.contains("chain:guard="));

        let guard_body = source_body_between(
            src,
            "cake_should_hold_wake_chain_locality",
            "cake_wake_chain_credit_allows",
        )
        .expect("wake-chain locality guard body should be present");
        assert!(!guard_body.contains("comm"));
        assert!(!guard_body.contains("pid"));
        assert!(!guard_body.contains("tgid"));
    }

    #[test]
    fn bpf_wake_chain_locality_policy_has_release_bake_and_debug_disable() {
        let src = include_str!("bpf/cake.bpf.c");
        let main = include_str!("main.rs");
        let readme = include_str!("../README.md");

        assert!(src.contains("#if defined(CAKE_RELEASE)"));
        assert!(source_contains(
            src,
            "#if defined(CAKE_RELEASE)
             #define CAKE_LEARNED_LOCALITY_COMPILED CAKE_LEARNED_LOCALITY_VALUE
             #define CAKE_WAKE_CHAIN_LOCALITY_COMPILED CAKE_WAKE_CHAIN_LOCALITY_VALUE
             #define CAKE_LEARNED_LOCALITY_ENABLED CAKE_LEARNED_LOCALITY_VALUE
             #define CAKE_WAKE_CHAIN_LOCALITY_ENABLED CAKE_WAKE_CHAIN_LOCALITY_VALUE"
        ));
        assert!(source_contains(
            src,
            "#elif !CAKE_LOCALITY_EXPERIMENTS
             #define CAKE_LEARNED_LOCALITY_COMPILED 0
             #define CAKE_WAKE_CHAIN_LOCALITY_COMPILED 0
             #define CAKE_LEARNED_LOCALITY_ENABLED 0
             #define CAKE_WAKE_CHAIN_LOCALITY_ENABLED 0"
        ));
        assert!(src.contains("const volatile bool enable_wake_chain_locality"));
        assert!(src.contains("CAKE_WAKE_CHAIN_LOCALITY_ENABLED"));
        assert!(src.contains("if (!CAKE_WAKE_CHAIN_LOCALITY_ENABLED)"));
        assert!(main.contains("wake_chain_locality"));
        assert!(main.contains("#[cfg(not(cake_bpf_release))]"));
        assert!(main.contains("rodata.enable_wake_chain_locality = args.wake_chain_locality"));
        assert!(readme.contains("SCX_CAKE_WAKE_CHAIN_LOCALITY"));
    }

    #[test]
    fn release_quantum_and_queue_policy_are_compile_locked() {
        let src = include_str!("bpf/cake.bpf.c");
        let main = include_str!("main.rs");
        let build = include_str!("../build.rs");
        let readme = include_str!("../README.md");

        assert!(build.contains("SCX_CAKE_PROFILE"));
        assert!(build.contains("SCX_CAKE_QUANTUM_US"));
        assert!(build.contains("SCX_CAKE_QUEUE_POLICY"));
        assert!(build.contains("SCX_CAKE_STORM_GUARD"));
        assert!(build.contains("SCX_CAKE_LEARNED_LOCALITY"));
        assert!(build.contains("SCX_CAKE_WAKE_CHAIN_LOCALITY"));
        assert!(build.contains("-DCAKE_QUANTUM_NS="));
        assert!(build.contains("-DCAKE_QUEUE_POLICY_VALUE="));
        assert!(build.contains("-DCAKE_STORM_GUARD_VALUE="));
        assert!(build.contains("-DCAKE_LEARNED_LOCALITY_VALUE="));
        assert!(build.contains("-DCAKE_WAKE_CHAIN_LOCALITY_VALUE="));
        assert!(build.contains("BAKED_QUANTUM_US"));
        assert!(build.contains("BAKED_QUEUE_POLICY"));
        assert!(build.contains("BAKED_STORM_GUARD"));
        assert!(build.contains("BAKED_LEARNED_LOCALITY"));
        assert!(build.contains("BAKED_WAKE_CHAIN_LOCALITY"));

        assert!(src.contains("const u64 quantum_ns = CAKE_QUANTUM_NS;"));
        assert!(src.contains("#define CAKE_QUEUE_POLICY CAKE_QUEUE_POLICY_VALUE"));
        assert!(src.contains("#define CAKE_STORM_GUARD_MODE CAKE_STORM_GUARD_VALUE"));
        assert!(source_contains(
            src,
            "const volatile u64 quantum_ns = CAKE_DEFAULT_QUANTUM_NS;"
        ));
        assert!(source_contains(
            src,
            "const volatile u32 queue_policy = CAKE_QUEUE_POLICY_LLC_VTIME;"
        ));
        assert!(source_contains(
            src,
            "const volatile u32 storm_guard_mode = CAKE_STORM_GUARD_OFF;"
        ));

        assert!(main.contains("#[cfg(not(cake_bpf_release))]"));
        assert!(main.contains("rodata.quantum_ns = quantum * 1000"));
        assert!(main.contains("rodata.queue_policy = args.queue_policy as u32"));
        assert!(main.contains("rodata.storm_guard_mode = args.storm_guard as u32"));
        assert!(main.contains("topology::BAKED_QUANTUM_US"));
        assert!(main.contains("topology::BAKED_QUEUE_POLICY"));
        assert!(main.contains("topology::BAKED_STORM_GUARD"));
        assert!(main.contains("topology::BAKED_LEARNED_LOCALITY"));
        assert!(main.contains("topology::BAKED_WAKE_CHAIN_LOCALITY"));

        assert!(readme.contains("SCX_CAKE_PROFILE=esports"));
        assert!(readme.contains("SCX_CAKE_QUEUE_POLICY=local"));
        assert!(readme.contains("SCX_CAKE_STORM_GUARD=shadow"));
        assert!(readme.contains("SCX_CAKE_LEARNED_LOCALITY=off"));
        assert!(readme.contains("SCX_CAKE_WAKE_CHAIN_LOCALITY=off"));
        assert!(readme.contains("Release builds bake profile, quantum, queue policy, storm guard"));
    }

    #[test]
    fn locality_ab_knobs_debug_default_off_release_build_tunable() {
        let src = include_str!("bpf/cake.bpf.c");
        let build = include_str!("../build.rs");
        let main = include_str!("main.rs");
        let readme = include_str!("../README.md");
        let wake_chain_arg = main
            .split_once("wake_chain_locality: bool")
            .and_then(|(prefix, _)| prefix.rsplit_once("#[arg("))
            .map(|(_, arg)| arg)
            .expect("wake-chain locality CLI arg should be present");
        let learned_arg = main
            .split_once("learned_locality: bool")
            .and_then(|(prefix, _)| prefix.rsplit_once("#[arg("))
            .map(|(_, arg)| arg)
            .expect("learned locality CLI arg should be present");

        assert!(source_contains(
            src,
            "const volatile bool enable_learned_locality = false;"
        ));
        assert!(source_contains(
            src,
            "const volatile bool enable_wake_chain_locality = false;"
        ));
        assert!(source_contains(
            src,
            "#if defined(CAKE_RELEASE)
             #define CAKE_LEARNED_LOCALITY_COMPILED CAKE_LEARNED_LOCALITY_VALUE
             #define CAKE_WAKE_CHAIN_LOCALITY_COMPILED CAKE_WAKE_CHAIN_LOCALITY_VALUE
             #define CAKE_LEARNED_LOCALITY_ENABLED CAKE_LEARNED_LOCALITY_VALUE
             #define CAKE_WAKE_CHAIN_LOCALITY_ENABLED CAKE_WAKE_CHAIN_LOCALITY_VALUE"
        ));
        assert!(source_contains(
            src,
            "#elif !CAKE_LOCALITY_EXPERIMENTS
             #define CAKE_LEARNED_LOCALITY_COMPILED 0
             #define CAKE_WAKE_CHAIN_LOCALITY_COMPILED 0
             #define CAKE_LEARNED_LOCALITY_ENABLED 0
             #define CAKE_WAKE_CHAIN_LOCALITY_ENABLED 0"
        ));
        assert!(build.contains("baked_bool(\"SCX_CAKE_LEARNED_LOCALITY\", false)"));
        assert!(build.contains("baked_bool(\"SCX_CAKE_WAKE_CHAIN_LOCALITY\", false)"));
        assert!(build.contains("release_learned_locality || release_wake_chain_locality"));
        assert!(wake_chain_arg.contains("default_value_t = false"));
        assert!(learned_arg.contains("default_value_t = false"));
        assert!(readme.contains("--learned-locality=true"));
        assert!(readme.contains("--wake-chain-locality=true"));
        assert!(readme.contains("SCX_CAKE_LEARNED_LOCALITY=off"));
        assert!(readme.contains("SCX_CAKE_WAKE_CHAIN_LOCALITY=off"));
        assert!(readme.contains("SCX_CAKE_LEARNED_LOCALITY=on"));
        assert!(readme.contains("SCX_CAKE_WAKE_CHAIN_LOCALITY=on"));
    }

    #[test]
    fn bpf_game_perf_ab_knobs_cover_locality_and_busy_kicks() {
        let src = include_str!("bpf/cake.bpf.c");
        let main = include_str!("main.rs");
        let readme = include_str!("../README.md");

        assert!(src.contains("const volatile bool enable_learned_locality"));
        assert!(src.contains("CAKE_LEARNED_LOCALITY_ENABLED"));
        assert!(src.contains("cake_select_learned_locality("));
        assert!(src.contains("!CAKE_LEARNED_LOCALITY_ENABLED || !cake_should_steer"));
        assert!(source_contains(
            src,
            "const volatile u32 busy_wake_kick_mode"
        ));
        assert!(src.contains("#define CAKE_BUSY_WAKE_KICK_MODE CAKE_BUSY_WAKE_KICK_POLICY"));
        assert!(src.contains("CAKE_BUSY_WAKE_KICK_PREEMPT"));
        assert!(src.contains("CAKE_BUSY_WAKE_KICK_IDLE"));
        assert!(src.contains("CAKE_STORM_GUARD_SHADOW"));
        assert!(src.contains("cake_storm_guard_accept_busy_wake("));
        assert!(main.contains("enum BusyWakeKickMode"));
        assert!(main.contains("enum StormGuardMode"));
        assert!(main.contains("learned_locality"));
        assert!(main.contains("busy_wake_kick"));
        assert!(main.contains("storm_guard"));
        assert!(main.contains("#[cfg(not(cake_bpf_release))]"));
        assert!(main.contains("rodata.enable_learned_locality = args.learned_locality"));
        assert!(main.contains("rodata.busy_wake_kick_mode = args.busy_wake_kick as u32"));
        assert!(main.contains("rodata.storm_guard_mode = args.storm_guard as u32"));
        assert!(readme.contains("runtime A/B controls"));
        assert!(readme.contains("--busy-wake-kick=preempt"));
        assert!(readme.contains("--storm-guard=shadow"));
    }

    #[test]
    fn bpf_release_fast_probe_uses_slot_specific_quality_gates() {
        let src = include_str!("bpf/cake.bpf.c");

        assert!(src.contains("cake_idle_scoreboard_clean("));
        assert!(src.contains("cake_status_owner_pressure("));
        assert!(src.contains("owner_class >= CAKE_CPU_OWNER_BULK"));
        assert!(src.contains("pressure >= CAKE_CPU_PRESSURE_HIGH"));
        assert!(src.contains("cake_smt_interactive_neighbor_busy(candidate)"));
        assert!(src.contains("cake_try_clean_idle_candidate_record("));
        assert!(src.contains("cake_try_smt_idle_candidate_record("));
    }

    #[test]
    fn bpf_release_fast_probe_is_task_biased() {
        let src = include_str!("bpf/cake.bpf.c");

        assert!(src.contains("cake_task_latency_biased("));
        assert!(src.contains("wake_flags & SCX_WAKE_SYNC"));
        assert!(src.contains("p->prio < 120"));
        assert!(src.contains("p->scx.weight > 120"));
        assert!(src.contains("latency_biased = cake_task_latency_biased(p, wake_flags);"));
        assert!(src.contains("cake_select_fast_scan_limit(local_bss)"));
        assert!(source_contains(
            src,
            "cake_select_cpu_fast_scan(p, prev_cpu, wake_flags, select_bss)"
        ));
    }

    #[test]
    fn bpf_release_decision_accelerator_uses_packed_confidence() {
        let src = include_str!("bpf/cake.bpf.c");
        let intf = include_str!("bpf/intf.h");

        assert!(intf.contains("decision_confidence"));
        assert!(src.contains("#define CAKE_ACCEL_PATH 1"));
        assert!(src.contains("#if defined(CAKE_RELEASE) || CAKE_HOT_TELEMETRY"));
        assert!(src.contains("CAKE_CONF_SELECT_EARLY_SHIFT"));
        assert!(src.contains("CAKE_CONF_SELECT_ROW4_SHIFT"));
        assert!(src.contains("CAKE_CONF_DISPATCH_EMPTY_SHIFT"));
        assert!(src.contains("cake_conf_update_select_route("));
        assert!(src.contains("scx_bpf_dsq_nr_queued(dsq_id)"));
    }

    #[test]
    fn bpf_release_scoreboard_has_kick_and_pull_confidence_lanes() {
        let src = include_str!("bpf/cake.bpf.c");

        assert!(src.contains("CAKE_CONF_KICK_SHAPE_SHIFT"));
        assert!(src.contains("CAKE_CONF_PULL_SHAPE_SHIFT"));
        assert!(src.contains("cake_kick_shape_mode("));
        assert!(src.contains("cake_pull_shape_mode("));
        assert!(src.contains("cake_conf_update(bss, CAKE_CONF_KICK_SHAPE_SHIFT"));
        assert!(src.contains("cake_dispatch_record_probe_empty("));
        assert!(src.contains("cake_dispatch_record_pull_result("));
    }

    #[test]
    fn bpf_release_scoreboard_shapes_wake_kicks() {
        let src = include_str!("bpf/cake.bpf.c");

        assert!(src.contains("CAKE_KICK_SHAPE_NONE"));
        assert!(src.contains("CAKE_KICK_SHAPE_IDLE"));
        assert!(src.contains("CAKE_KICK_SHAPE_PREEMPT"));
        assert!(src.contains("cake_scoreboard_kick_cpu("));
        assert!(src.contains("owner_class >= CAKE_CPU_OWNER_BULK"));
        assert!(src.contains("cake_scoreboard_kick_cpu_known(target_cpu, target_status);"));
    }

    #[test]
    fn bpf_release_scoreboard_shapes_dsq_pulls() {
        let src = include_str!("bpf/cake.bpf.c");

        assert!(src.contains("cake_dispatch_dsq_should_pull("));
        assert!(src.contains("cake_pull_shape_mode("));
        assert!(src.contains("CAKE_PULL_SHAPE_PROBE"));
        assert!(src.contains("scx_bpf_dsq_nr_queued(dsq_id)"));
        assert!(src.contains("cake_dispatch_record_probe_work(bss);"));
        assert!(src.contains("cake_dispatch_record_pull_result("));
    }

    #[test]
    fn bpf_release_prediction_misses_use_kernel_default_fallback() {
        let src = include_str!("bpf/cake.bpf.c");

        assert!(src.contains("cake_route_predict_ready("));
        assert!(src.contains("if (!cake_route_predict_ready(confidence))"));
        assert!(src.contains("cpu = select_cpu_and_idle(p, prev_cpu, wake_flags, 0);"));
        assert!(!src.contains("cake_select_fallback_mode("));
        assert!(!src.contains("cake_select_fallback_audit_due("));
        assert!(!src.contains("if (fallback_mode == CAKE_SELECT_FALLBACK_SKIP)"));
        assert!(!src.contains("CAKE_ROUTE_FALLBACK"));
        assert!(!src.contains("cake_route_update(select_bss, CAKE_ROUTE_FALLBACK, true);"));
        assert!(!src.contains("cake_conf_update(select_bss, CAKE_CONF_SELECT_FALLBACK_SHIFT"));
    }

    #[test]
    fn bpf_release_scoreboard_precedes_native_idle_helpers() {
        let src = include_str!("bpf/cake.bpf.c");
        let compact = compact_source(src);
        let route_predict = compact
            .find("cpu = cake_select_route_predict(p, prev_cpu, wake_flags,")
            .expect("route predictor call exists");
        let fast_scan = compact
            .find("cpu = cake_select_cpu_fast_scan(p, prev_cpu, wake_flags, select_bss);")
            .expect("scoreboard fast scan call exists");
        let native_dfl = compact
            .find("cpu = select_cpu_dfl_idle(p, prev_cpu, wake_flags);")
            .expect("native dfl fallback call exists");
        let native_and = compact
            .find("cpu = select_cpu_and_idle(p, prev_cpu, wake_flags, 0);")
            .expect("native and fallback call exists");

        assert!(route_predict < native_dfl);
        assert!(fast_scan < native_dfl);
        assert!(route_predict < native_and);
        assert!(fast_scan < native_and);
        assert!(src.contains("Native helpers are deliberately behind"));
    }

    #[test]
    fn bpf_release_trusted_prev_direct_precedes_confidence_work() {
        let src = include_str!("bpf/cake.bpf.c");
        let intf = include_str!("bpf/intf.h");
        let trust = include_str!("trust.rs");
        let tui = include_str!("tui.rs");

        assert!(intf.contains("struct cake_trust_user"));
        assert!(intf.contains("struct cake_trust_bpf"));
        assert!(intf.contains("CAKE_TRUST_FLAG_PREV_DIRECT"));
        assert!(source_contains(
            src,
            "struct cake_trust_user trust_user[CAKE_MAX_CPUS]"
        ));
        assert!(source_contains(
            src,
            "struct cake_trust_bpf trust_bpf[CAKE_MAX_CPUS]"
        ));
        assert!(src.contains("cake_trust_prev_direct_claim(prev_cpu);"));
        assert!(src.contains("CAKE_ROUTE_PREDICT_TRUST_MISS"));
        assert!(src.contains("cake_trust_demote(cpu, CAKE_TRUST_FLAG_PREV_DIRECT"));

        let affinity_gate = src
            .find("if (cake_task_is_affinitized(p))")
            .expect("affinity gate exists");
        let trusted_claim = src
            .find("selected = cake_trust_prev_direct_claim(prev_cpu);")
            .expect("trusted direct prev claim exists");
        let confidence_read = src
            .find("confidence = READ_ONCE(local_bss->decision_confidence);")
            .expect("confidence read exists");
        let native_fallback = src
            .find("cake_record_accel_native(CAKE_ACCEL_NATIVE_ENTRY);")
            .expect("native fallback marker exists");

        assert!(affinity_gate < trusted_claim);
        assert!(trusted_claim < confidence_read);
        assert!(trusted_claim < native_fallback);
        assert!(
            trust.contains("bss.trust_user[idx].generation = generation.wrapping_add(1).max(1);")
        );
        assert!(trust.contains("if !ready || cooling_down"));
        assert!(!trust.contains("if !ready || cooling_down || bpf_blocked"));
        assert!(tui.contains("bss.trust_user = Default::default();"));
        assert!(tui.contains("bss.trust_bpf = Default::default();"));
    }

    #[test]
    fn bpf_release_route_token_can_collapse_select_tree() {
        let src = include_str!("bpf/cake.bpf.c");

        assert!(src.contains("CAKE_CONF_ROUTE_SHIFT"));
        assert!(src.contains("CAKE_CONF_CLAIM_HEALTH_SHIFT"));
        assert!(src.contains("CAKE_ROUTE_PREV"));
        assert!(src.contains("CAKE_ROUTE_SLOT0"));
        assert!(src.contains("CAKE_ROUTE_SLOT2"));
        assert!(src.contains("CAKE_ROUTE_SLOT3"));
        assert!(src.contains("CAKE_ROUTE_TUNNEL"));
        assert!(src.contains("cake_select_route_predict("));
        assert!(src.contains("== local_cpu"));
        assert!(src.contains("route_kind = cake_route_kind_value(confidence);"));
        assert!(src.contains("cake_route_update(local_bss, route_kind, selected >= 0);"));
        assert!(src.contains("cake_conf_update_select_route(local_bss, hit_route"));
        assert!(source_contains(
            src,
            "cake_try_clean_idle_candidate_record(local_bss, candidate"
        ));
        assert!(source_contains(
            src,
            "cake_try_smt_idle_candidate_record(local_bss, candidate"
        ));
        assert!(src.contains("if (cpu == CAKE_ROUTE_PREDICT_TUNNEL)"));
        assert!(src.contains("cake_route_update(select_bss, CAKE_ROUTE_TUNNEL, true);"));
    }

    #[test]
    fn bpf_release_fast_scan_batches_select_and_route_confidence() {
        let src = include_str!("bpf/cake.bpf.c");

        assert!(src.contains("cake_conf_update_select_route("));
        assert!(src.contains("cake_conf_update_select(local_bss, false, true, false);"));
        assert!(!src.contains(
            "cake_conf_update(local_bss, CAKE_CONF_SELECT_EARLY_SHIFT, true);\n\t\tcake_route_update(local_bss, CAKE_ROUTE_SLOT0, true);"
        ));
        assert!(!src.contains(
            "cake_conf_update(local_bss, CAKE_CONF_SELECT_EARLY_SHIFT, false);\n\tcake_conf_update(local_bss, CAKE_CONF_SELECT_ROW4_SHIFT, false);"
        ));
    }

    #[test]
    fn bpf_release_pull_confidence_audits_before_pull() {
        let src = include_str!("bpf/cake.bpf.c");

        assert!(!src.contains("CAKE_PULL_SHAPE_AUDIT"));
        assert!(src.contains("CAKE_CONF_PULL_AUDIT_SHIFT"));
        assert!(src.contains("cake_pull_audit_due("));
        assert!(src.contains("pull_conf >= CAKE_CONF_HIGH && !cake_pull_audit_due(bss)"));
        assert!(src.contains("scx_bpf_dsq_nr_queued(dsq_id)"));
        assert!(!src.contains("if (mode == CAKE_PULL_SHAPE_AUDIT)\n\t\treturn false;"));
    }

    #[test]
    fn bpf_release_kick_reuses_known_scoreboard_status() {
        let src = include_str!("bpf/cake.bpf.c");
        let body = source_body_between(
            src,
            "static __always_inline void cake_scoreboard_kick_cpu_known",
            "static __always_inline __maybe_unused void",
        )
        .expect("known kick helper body exists");

        assert!(src.contains("cake_scoreboard_kick_cpu_known("));
        assert!(src.contains("cake_scoreboard_kick_cpu_known(target_cpu, target_status);"));
        assert!(source_contains(
            src,
            "u32 local_cpu = bpf_get_smp_processor_id() & (CAKE_MAX_CPUS - 1);
             struct cake_cpu_bss *bss = &cpu_bss[local_cpu];"
        ));
        assert!(source_contains(
            body,
            "mode = cake_kick_shape_mode(bss, target_status);"
        ));
        assert!(body.contains("(target_cpu & (CAKE_MAX_CPUS - 1)) != local_cpu"));
        assert!(source_contains(
            body,
            "if ((target_cpu & (CAKE_MAX_CPUS - 1)) != local_cpu) {
                     if (target_status & CAKE_CPU_STATUS_IDLE) {
                             scx_bpf_kick_cpu(target_cpu, SCX_KICK_IDLE);
                             return;
                     }
                     if (!(target_status & CAKE_CPU_STATUS_IDLE)) {
                             u32 busy_mode = CAKE_BUSY_WAKE_KICK_MODE;"
        ));
    }

    #[test]
    fn bpf_release_confidence_can_relax_accounting_cadence() {
        let src = include_str!("bpf/cake.bpf.c");

        assert!(src.contains("CAKE_CONF_ACCOUNT_AUDIT_SHIFT"));
        assert!(src.contains("CAKE_ACCOUNT_RELAX_MIN_RUNS"));
        assert!(src.contains("cake_accounting_relaxed("));
        assert!(src.contains("owner_run_count) < CAKE_ACCOUNT_RELAX_MIN_RUNS"));
        assert!(src.contains("bool relaxed = cake_accounting_relaxed(bss);"));
        assert!(source_contains(
            src,
            "u32 owner_avg_runtime_ns = cake_update_owner_avg(bss, rt_raw);
             cake_route_pred_observe(bss, p, rt_raw, runnable);
             cake_publish_cpu_owner(cpu, bss, owner_avg_runtime_ns);
             if (!cake_accounting_relaxed(bss))
                     cake_scoreboard_owner_result(bss, owner_avg_runtime_ns);"
        ));
    }

    #[test]
    fn bpf_release_select_confidence_uses_executing_cpu_row() {
        let src = include_str!("bpf/cake.bpf.c");
        let select_body = source_body_between(
            src,
            "s32 BPF_STRUCT_OPS(cake_select_cpu",
            "cake_record_accel_native(CAKE_ACCEL_NATIVE_ENTRY);",
        )
        .expect("select_cpu body before native fallback exists");
        let guarded_scoreboard =
            source_body_between(select_body, "if (prev_cpu >= 0 &&", "} else {")
                .expect("scoreboard predictor is guarded by executing CPU row");

        assert!(source_contains(
            src,
            "u32 local_cpu = bpf_get_smp_processor_id() & (CAKE_MAX_CPUS - 1);"
        ));
        assert!(source_contains(
            src,
            "struct cake_cpu_bss *select_bss = &cpu_bss[local_cpu];"
        ));
        assert!(source_contains(
            src,
            "if (prev_cpu >= 0 &&
             (((u32)prev_cpu) & (CAKE_MAX_CPUS - 1)) == local_cpu) {
                     cpu = cake_select_route_predict(p, prev_cpu, wake_flags,
                                                     select_bss);"
        ));
        assert!(source_contains(
            src,
            "cpu = cake_select_cpu_fast_scan(p, prev_cpu, wake_flags,
                                             select_bss);"
        ));
        assert!(guarded_scoreboard.contains("cake_select_route_predict("));
        assert!(src.contains("cpu = cake_select_cpu_fast_scan(p, prev_cpu, wake_flags,"));
        assert!(!src.contains("select_cpu_idx"));
    }

    #[test]
    fn bpf_release_scoreboard_status_carries_epoch_and_latency_class() {
        let intf = include_str!("bpf/intf.h");
        let src = include_str!("bpf/cake.bpf.c");

        assert!(intf.contains("CAKE_CPU_STATUS_EPOCH_SHIFT"));
        assert!(intf.contains("CAKE_CPU_STATUS_LATENCY_SHIFT"));
        assert!(intf.contains("CAKE_CPU_LATENCY_LATENCY"));
        assert!(src.contains("cake_status_epoch("));
        assert!(src.contains("cake_status_next_epoch("));
        assert!(src.contains("cake_owner_latency_class("));
        assert!(source_contains(
            src,
            "cake_make_cpu_status(false, owner_class, pressure, latency_class"
        ));
    }

    #[test]
    fn bpf_release_confidence_has_floor_gear_and_trust_lanes() {
        let src = include_str!("bpf/cake.bpf.c");
        let dump = include_str!("tui/dump.rs");

        assert!(src.contains("CAKE_CONF_FLOOR_GEAR_SHIFT"));
        assert!(src.contains("CAKE_CONF_STATUS_TRUST_SHIFT"));
        assert!(src.contains("CAKE_CONF_OWNER_STABLE_SHIFT"));
        assert!(src.contains("CAKE_CONF_LOAD_SHOCK_SHIFT"));
        assert!(src.contains("cake_floor_gear_for("));
        assert!(src.contains("cake_refresh_floor_gear_packed("));
        assert!(dump.contains("gear={}"));
        assert!(dump.contains("trust={}"));
        assert!(dump.contains("stable={}"));
        assert!(dump.contains("shock={}"));
    }

    #[test]
    fn bpf_release_floor_prediction_requires_peak_meta_confidence() {
        let src = include_str!("bpf/cake.bpf.c");

        assert!(src.contains("cake_floor_mode_ready("));
        assert!(src.contains("CAKE_FLOOR_GEAR_FLOOR"));
        assert!(src.contains("status_trust && !(status_trust & 8U)"));
        assert!(src.contains("high & (1ULL << CAKE_CONF_OWNER_STABLE_SHIFT)"));
        assert!(src.contains("0xfULL << CAKE_CONF_ROUTE_SHIFT"));
        assert!(src.contains("0xfULL << CAKE_CONF_STATUS_TRUST_SHIFT"));
        assert!(src.contains("return gear == CAKE_FLOOR_GEAR_FLOOR;"));
        assert!(src.contains("confidence & (8ULL << CAKE_CONF_LOAD_SHOCK_SHIFT)"));
        assert!(!src.contains("fallback_conf >= CAKE_CONF_INIT"));
        assert!(src.contains("if (!cake_floor_mode_ready(confidence))"));
    }

    #[test]
    fn bpf_release_slot_claims_update_scoreboard_trust_and_shock() {
        let src = include_str!("bpf/cake.bpf.c");

        assert!(src.contains("cake_scoreboard_claim_result("));
        assert!(src.contains("CAKE_CONF_STATUS_TRUST_SHIFT"));
        assert!(src.contains("CAKE_CONF_LOAD_SHOCK_SHIFT"));
        assert!(src.contains("cake_try_idle_candidate_release(local_bss"));
        assert!(src.contains("candidate_mode & 0x80000000U"));
        assert!(src.contains("(candidate) | 0x80000000U"));
    }

    #[test]
    fn bpf_release_scoreboard_claim_health_skips_before_idle_claim() {
        let src = include_str!("bpf/cake.bpf.c");

        assert!(src.contains("CAKE_CONF_CLAIM_HEALTH_SHIFT 8U"));
        assert!(src.contains("cake_claim_health_allows(local_bss)"));

        let candidate_body = source_body_between(
            src,
            "static CAKE_TRY_IDLE_ATTR s32 cake_try_idle_candidate(",
            "static __noinline s32\ncake_try_idle_candidate_release",
        )
        .expect("idle candidate core body should be present");
        let clean_gate = candidate_body
            .find("if (!cake_claim_health_allows(local_bss))")
            .expect("clean candidate should gate stale claim lanes");
        let clean_claim = candidate_body
            .find("claimed = scx_bpf_test_and_clear_cpu_idle(candidate);")
            .expect("clean candidate should still claim native idle state");
        assert!(clean_gate < clean_claim);

        assert!(src.contains("cake_try_idle_candidate_release("));
    }

    #[test]
    fn bpf_release_scoreboard_claim_health_updates_after_claim_result() {
        let src = include_str!("bpf/cake.bpf.c");

        assert!(src.contains("#define CAKE_CLAIM_HEALTH_MISS_STEP"));
        assert!(src.contains("static __always_inline u64 cake_claim_health_update("));
        assert!(src.contains("cake_claim_health_update(confidence, success);"));
        assert!(src.contains("cake_scoreboard_claim_result(local_bss, status, claimed);"));
    }

    #[test]
    fn bpf_release_scoreboard_claim_health_records_claim_skips() {
        let src = include_str!("bpf/cake.bpf.c");
        let intf = include_str!("bpf/intf.h");
        let dump = include_str!("tui/dump.rs");

        assert!(intf.contains("CAKE_ACCEL_PROBE_CLAIM_SKIP"));
        assert!(dump.contains("claim_skip"));

        let candidate_body = source_body_between(
            src,
            "static CAKE_TRY_IDLE_ATTR s32 cake_try_idle_candidate(",
            "static __noinline s32\ncake_try_idle_candidate_release",
        )
        .expect("idle candidate core body should be present");
        assert!(candidate_body.contains("CAKE_ACCEL_PROBE_CLAIM_SKIP"));
        assert!(source_contains(
            candidate_body,
            "if (!cake_claim_health_allows(local_bss)) {
                cake_record_accel_probe(route_kind,
                                        CAKE_ACCEL_PROBE_CLAIM_SKIP);
                return -1;
            }"
        ));
    }

    #[test]
    fn tui_dump_decodes_release_confidence_lanes() {
        let tui = include_str!("tui.rs");
        let dump = include_str!("tui/dump.rs");
        let report = include_str!("telemetry_report.rs");

        assert!(tui.contains("decision_confidence: bss.cpu_bss[idx].decision_confidence"));
        assert!(tui.contains("trust::extract_trust_snapshots"));
        assert!(tui.contains("trust_prev={}/{}/{}"));
        assert!(tui.contains("total.accel_trust_prev_attempt += s.accel_trust_prev_attempt;"));
        assert!(tui.contains("delta.accel_trust_prev_attempt = current"));
        assert!(tui.contains("CAKE_CONF_ROUTE_KIND_SHIFT"));
        assert!(dump.contains("accelerator.life"));
        assert!(dump.contains("accelerator.60s"));
        assert!(dump.contains(".trust: prev_direct[state active/enabled/blocked]"));
        assert!(dump.contains("last_reason_cpus"));
        assert!(dump.contains("rate[a/h/m]"));
        assert!(dump.contains("format_trust_state"));
        assert!(dump.contains("fail_flags"));
        assert!(dump.contains("conf={}"));
        assert!(dump.contains("format_decision_confidence(row.decision_confidence)"));
        assert!(dump.contains("route={}"));
        assert!(dump.contains("claim={}"));
        assert!(dump.contains("acct_audit={}"));
        assert!(report.contains("trust_prev_active_cpus"));
        assert!(report.contains("trust_prev_attempts"));
    }

    #[test]
    fn accelerator_telemetry_explains_prediction_and_fallbacks() {
        let bpf = concat!(
            include_str!("bpf/intf.h"),
            "\n",
            include_str!("bpf/telemetry.bpf.h"),
            "\n",
            include_str!("bpf/cake.bpf.c")
        );
        let tui = include_str!("tui.rs");
        let dump = include_str!("tui/dump.rs");
        let diagnostics = include_str!("tui/diagnostics.rs");
        let report = include_str!("telemetry_report.rs");

        assert!(bpf.contains("accel_route_attempt_count"));
        assert!(bpf.contains("accel_route_block_count"));
        assert!(bpf.contains("accel_scoreboard_probe_count"));
        assert!(bpf.contains("cake_record_accel_route_attempt"));
        assert!(bpf.contains("cake_record_accel_route_block"));
        assert!(bpf.contains("cake_record_accel_native"));
        assert!(bpf.contains("cake_record_accel_accounting"));
        assert!(bpf.contains("CAKE_ACCEL_BLOCK_LATENCY_GATE"));
        assert!(bpf.contains("CAKE_ACCEL_PROBE_CLAIM_FAIL"));
        assert!(bpf.contains("CAKE_ACCEL_PROBE_CLAIM_SKIP"));
        assert!(tui.contains("for reason in 0..SELECT_REASON_MAX"));
        assert!(!tui.contains("for reason in 0..10"));
        assert!(dump.contains(".route_pred: route[attempt/hit/miss(hit%)]"));
        assert!(dump.contains(".fastscan: route[attempt/hit/miss(hit%)]"));
        assert!(dump.contains(".fallback: {}"));
        assert!(dump.contains("format_service_report_text"));
        assert!(dump.contains("format_service_report_json"));
        assert!(diagnostics.contains("SERVICE_SCHEMA_VERSION: u32 = 8"));
        assert!(diagnostics.contains("CAKE-TRUST-010"));
        assert!(diagnostics.contains("MonitorSnapshot"));
        assert!(diagnostics.contains("FreezeFrame"));
        assert!(report.contains("route_attempt_counts"));
        assert!(report.contains("native_fallback_counts"));
        assert!(report.contains("serde_json::to_string_pretty"));
    }

    #[test]
    fn bpf_release_scoreboard_obsoletes_legacy_bss_hint_lanes() {
        let src = include_str!("bpf/cake.bpf.c");
        let intf = include_str!("bpf/intf.h");
        let tui = include_str!("tui.rs");
        let readme = include_str!("../README.md");
        let bss_body = intf
            .split_once("struct cake_cpu_bss {")
            .and_then(|(_, rest)| rest.split_once("} __attribute__((aligned(4096)));"))
            .map(|(body, _)| body)
            .expect("cake_cpu_bss body should be present");

        assert!(source_contains(
            bss_body,
            "#ifndef CAKE_RELEASE u8 idle_hint"
        ));
        assert!(source_contains(
            bss_body,
            "#ifndef CAKE_RELEASE u8 cpu_pressure"
        ));
        assert!(src.contains("Release wake placement reads cpu_status/cpu_frontier"));
        assert!(source_contains(
            src,
            "u8 scoreboard_idle = !!(target_status & CAKE_CPU_STATUS_IDLE);"
        ));
        assert!(!source_contains(
            src,
            "u8 idle_hint = !!(target_status & CAKE_CPU_STATUS_IDLE);"
        ));
        assert!(src.contains("cake_publish_cpu_idle(cpu_idx);"));
        assert!(src.contains("cake_publish_cpu_running(cpu, task_changed);"));
        assert!(tui.contains("fn cake_cpu_status_pressure_bucket(flags: u64) -> u8"));
        assert!(tui.contains("bss.cpu_status[idx].flags"));
        assert!(readme.contains("debug-only private mirror"));
        assert!(readme.contains("release scoreboard publishes pressure"));
    }

    #[test]
    fn debug_coverage_uses_compact_event_stream_not_disabled_bpf_analytics() {
        let bpf = concat!(
            include_str!("bpf/cake.bpf.c"),
            "\n",
            include_str!("bpf/telemetry.bpf.h"),
            "\n",
            include_str!("bpf/debug_events.bpf.h")
        );
        let intf = include_str!("bpf/intf.h");
        let tui = concat!(
            include_str!("tui.rs"),
            "\n",
            include_str!("tui/dump.rs"),
            "\n",
            include_str!("tui/report.rs")
        );

        assert!(intf.contains("CAKE_DEBUG_EVENT_STREAM"));
        assert!(intf.contains("CAKE_WAKE_EDGE_SAMPLE_NS"));
        assert!(intf.contains("CAKE_WAKE_EDGE_SAMPLE_DENOM"));
        assert!(intf.contains("CAKE_WAKE_EDGE_EVENT_FLAG_SAMPLED"));
        assert!(intf.contains("CAKE_WAKE_EDGE_EVENT_FLAG_IMPORTANT"));
        assert!(!intf.contains("CAKE_WAKE_EDGE_TELEMETRY 0"));
        assert!(!intf.contains("CAKE_WAKE_EDGE_EVENT_TELEMETRY 0"));
        assert!(!intf.contains("CAKE_STRICT_WAKE_POLICY_BPF_TELEMETRY 0"));
        assert!(!bpf.contains("CAKE_WAKE_EDGE_TELEMETRY"));
        assert!(!bpf.contains("CAKE_WAKE_EDGE_EVENT_TELEMETRY"));
        assert!(!bpf.contains("CAKE_STRICT_WAKE_POLICY_BPF_TELEMETRY"));
        assert!(bpf.contains("#if CAKE_DEBUG_EVENT_STREAM"));
        assert!(bpf.contains("cake_debug_should_sample_wake_edge"));
        assert!(bpf.contains("ev->aux = cake_debug_wake_edge_sample_weight(important)"));
        assert!(bpf.contains("ev->aux = CAKE_WAKE_EDGE_SAMPLE_DENOM"));
        assert!(bpf.contains("if (!important && !cake_debug_should_sample_wake_edge"));
        assert!(bpf.contains("if (same_cpu && !cake_debug_should_sample_wake_edge"));
        assert!(bpf.contains("cake_emit_wake_edge_run_event"));
        assert!(!bpf.contains("cake_wake_edge_lookup"));
        assert!(!bpf.contains("cake_shadow_classify_task_strict"));
        assert!(tui.contains("wake_est="));
        assert!(tui.contains("observed="));
        assert!(tui.contains("weight_sum="));
        assert!(!tui.contains(
            "append_strict_wake_policy_section(output, &format!(\"win.wakepolicy.strict."
        ));
        assert!(!tui
            .contains("append_strict_wake_policy_section(&mut output, \"wakepolicy.strict.life\""));
    }

    #[test]
    fn parses_core_dump_metrics_by_scope() {
        let dump = "\
service.header: schema=8 text=4 status=warn uptime=61s degraded=2 monitors=9 active_codes=2 freeze_frames=3
readiness: pass=5 warn=2 action=1 warmup=1
readiness.monitors:
  id=prediction state=pass score=100 window=60s source=accel cpus=- tasks=- summary=route predictor 99.9% over 1000 attempts
dtc.active:
  code=CAKE-TRUST-010 severity=warn count=4 first=t+11s last=t+61s cpus=C02 summary=trust.prev_direct unstable
  code=CAKE-FALL-030 severity=fail count=1 first=t+60s last=t+61s cpus=- summary=native fallback rate failed
freeze_frames:
  code=CAKE-TRUST-010 t+61s cpu=C02 tgid=42 comm=Game summary=active=2 hit=97.0% demote=0.50/s metrics=hit_pct=97.0%
coverage: status=degraded degraded=2 sections=7
disp: dsq_total=100 local=90 steal=10 miss=2 queue=0 ins:direct=12 affine=3 shared=4 shared[w/r/p/o]=1/2/3/4 direct[k/o]=5/6 wake:direct=7 busy=8 queued=9 total=24 busy_local=5 busy_remote=3 guard:primary_scan=66 hot_guard:primary_scan=7 credit:primary_scan=6 chain:guard=5 chain:credit=4
wakewait.all: dir=10/111us(7) busy=20/222us(8) queue=30/333us(9)
smt: runtime_contended=12.3% overlap=4.5% runs_contended=6.7% avg_run_us[s/c]=1/2 wake_avg_us[s/c]=3/4 active_start/stop=5/6
wakebins: direct=1/2/3/4/5 busy=6/7/8/9/10 queued=11/12/13/14/15
decision.migrate: path=[home=21 core=22 primary=23 idle=24 tunnel=25] reason=[hm=31 hc=32 pp=33 ps=34 hy=35 kp=36 ki=37 tn=38 pc=39 sbp=40 sbs=41] total=315
place.path: home=16 core=17 primary=18 idle=19 tunnel=20 deps:same_tgid=1 cross_tgid=2
wakepolicy.life: class=[none=1 normal=2 shield=3 contain=4] reasons=[none=0] transitions=[none->normal=1] busy_shadow:allow=11 skip=12 owner_class=[none=0 normal=0 shield=0 contain=0]
wakepolicy.strict.life: class=[none=5 normal=6 shield=7 contain=8] reasons=[yield_heavy=9] wait=[normal=1/101us(6) shield=2/202us(7) contain=3/303us(8)] transitions=[normal->contain=2] busy_shadow:allow=13 skip=14 owner_class=[none=0 normal=0 shield=0 contain=0]
accelerator.life.storm_guard: mode=[shadow=10] decisions=[candidate=11 base_allow=12 shadow=13 shield_allow=14 full_allow=15 smt_block=16 unknown_owner=17 disabled=18 reject=19]
app.health.life: apps=2 total_runtime_ms=10 source=task_rollup quantum=exact_u64/1000us wake=debug_bounded
  tgid=42 comm=Game leader=- role=GAME runtime_ms=100.0 share=55.5% run=10 avg_run_us=1 max_run_us=10 syld=77 mig/s=12.3 wake[self/in/out]=1/2/3 wait_self=4/500us(1) wait_out=5/600us(2)
  tgid=43 comm=Browser leader=- role=UI runtime_ms=90.0 share=44.4% run=10 avg_run_us=1 max_run_us=10 syld=88 mig/s=1.2 wake[self/in/out]=10/20/30 wait_self=4/100us(1) wait_out=5/200us(2)
wakegraph.top:
  A/1 -> B/2 wake=40 wait=1/900us(40) bucket=[<50us=35 >=5ms=5] target[h/m]=40/0 follow[s/m]=1/0 deps[s/c]=40/0
wakegraph.latency:
  C/3 -> D/4 wake=5 wait=2/1000us(5) bucket=[<50us=3 >=5ms=2] target[h/m]=5/0 follow[s/m]=1/0 deps[s/c]=5/0
window: 30s sampled=30.0s
win.disp: dsq_total=200 (1.0/s) local=190 steal=10 miss=2 (0.1/s) queue_now=0 ins:direct=12 (0.1/s) affine=3 (0.1/s) shared=4 (0.1/s) shared[w/r/p/o]=1/2/3/4 direct[k/o]=5/6 wake:direct=17 (70.8%) busy=18 (75.0%) queued=19 (79.2%) total=54 (1.0/s) guard:primary_scan=76 hot_guard:primary_scan=17 credit:primary_scan=7 chain:guard=15 chain:credit=14
win.wakewait.all: dir=40/444us(17) busy=50/555us(18) queue=60/666us(19)
win.smt: runtime_contended=23.4% overlap=5.6% runs_contended=7.8% avg_run_us[s/c]=1/2 wake_avg_us[s/c]=3/4 active_start/stop=5/6
win.wakebins: direct=21/22/23/24/25 busy=26/27/28/29/30 queued=31/32/33/34/35
win.decision.migrate: path=[home=41 core=42 primary=43 idle=44 tunnel=45] reason=[hm=51 hc=52 pp=53 ps=54 hy=55 kp=56 ki=57 tn=58 pc=59 sbp=60 sbs=61] total=495
win.path: home=36 core=37 primary=38 idle=39 tunnel=40 deps:same_tgid=1 (1.0/s) cross_tgid=2 (2.0/s)
win.wakepolicy.30s: class=[none=10 normal=20 shield=30 contain=40] reasons=[none=0] transitions=[normal->shield=1] busy_shadow:allow=21 skip=22 owner_class=[none=0 normal=0 shield=0 contain=0]
win.wakepolicy.strict.30s: class=[none=11 normal=22 shield=33 contain=44] reasons=[yield_heavy=55] wait=[normal=4/404us(22) shield=5/505us(33) contain=6/606us(44)] transitions=[normal->contain=3] busy_shadow:allow=23 skip=24 owner_class=[none=0 normal=0 shield=0 contain=0]
window: 60s sampled=60.0s
win.disp: dsq_total=300 (1.0/s) local=290 steal=10 miss=2 (0.1/s) queue_now=0 ins:direct=12 (0.1/s) affine=3 (0.1/s) shared=4 (0.1/s) shared[w/r/p/o]=1/2/3/4 direct[k/o]=5/6 wake:direct=27 (70.8%) busy=28 (75.0%) queued=29 (79.2%) total=84 (1.0/s) guard:primary_scan=86 hot_guard:primary_scan=18 credit:primary_scan=8 chain:guard=25 chain:credit=24
win.wakewait.all: dir=70/777us(27) busy=80/888us(28) queue=90/999us(29)
win.smt: runtime_contended=34.5% overlap=5.6% runs_contended=8.9% avg_run_us[s/c]=1/2 wake_avg_us[s/c]=3/4 active_start/stop=5/6
win.wakebins: direct=41/42/43/44/45 busy=46/47/48/49/50 queued=51/52/53/54/55
win.decision.migrate: path=[home=61 core=62 primary=63 idle=64 tunnel=65] reason=[hm=71 hc=72 pp=73 ps=74 hy=75 kp=76 ki=77 tn=78 pc=79 sbp=80 sbs=81] total=675
win.path: home=56 core=57 primary=58 idle=59 tunnel=60 deps:same_tgid=1 (1.0/s) cross_tgid=2 (2.0/s)
win.wakepolicy.60s: class=[none=100 normal=200 shield=300 contain=400] reasons=[none=0] transitions=[normal->shield=1] busy_shadow:allow=31 skip=32 owner_class=[none=0 normal=0 shield=0 contain=0]
win.wakepolicy.strict.60s: class=[none=101 normal=202 shield=303 contain=404] reasons=[yield_heavy=505] wait=[normal=7/707us(202) shield=8/808us(303) contain=9/909us(404)] transitions=[normal->contain=4] busy_shadow:allow=33 skip=34 owner_class=[none=0 normal=0 shield=0 contain=0]
accelerator.60s.storm_guard: mode=[full=20] decisions=[candidate=21 base_allow=22 shadow=23 shield_allow=24 full_allow=25 smt_block=26 unknown_owner=27 disabled=28 reject=29]
";

        let metrics = parse_metrics(dump);

        assert_eq!(metrics.coverage.status, "degraded");
        assert_eq!(metrics.coverage.degraded, 2);
        assert_eq!(metrics.coverage.sections, 7);

        assert_eq!(metrics.service.status, "warn");
        assert_eq!(metrics.service.active_codes, 2);
        assert_eq!(metrics.service.freeze_frames, 3);
        assert_eq!(metrics.service.pass, 5);
        assert_eq!(metrics.service.warn, 2);
        assert_eq!(metrics.service.fail, 1);
        assert_eq!(metrics.service.not_ready, 1);
        assert_eq!(metrics.service.dtc_active, 2);
        assert_eq!(metrics.service.dtc_warn, 1);
        assert_eq!(metrics.service.dtc_fail, 1);

        assert_eq!(metrics.life.busy_wakes, 8);
        assert_eq!(metrics.life.busy_preempt_allow, 11);
        assert_eq!(metrics.life.busy_preempt_skip, 12);
        assert_eq!(metrics.life.direct_wait_avg_us, 10);
        assert_eq!(metrics.life.direct_wait_max_us, 111);
        assert_eq!(metrics.life.busy_wait_avg_us, 20);
        assert_eq!(metrics.life.busy_wait_max_us, 222);
        assert_eq!(metrics.life.queued_wait_avg_us, 30);
        assert_eq!(metrics.life.queued_wait_max_us, 333);
        assert_eq!(metrics.life.primary_scan_guarded, 66);
        assert_eq!(metrics.life.primary_scan_hot_guarded, 7);
        assert_eq!(metrics.life.primary_scan_credit_used, 6);
        assert_eq!(metrics.life.wake_chain_locality_guarded, 5);
        assert_eq!(metrics.life.wake_chain_locality_credit_used, 4);
        assert_eq!(metrics.life.smt_runtime_contended_tenths, 123);
        assert_eq!(metrics.life.smt_runs_contended_tenths, 67);
        assert_eq!(metrics.life.shield_samples, 3);
        assert_eq!(metrics.life.contain_samples, 4);
        assert_eq!(metrics.life.strict_busy_preempt_allow, 13);
        assert_eq!(metrics.life.strict_busy_preempt_skip, 14);
        assert_eq!(metrics.life.strict_shield_samples, 7);
        assert_eq!(metrics.life.strict_contain_samples, 8);
        assert_eq!(metrics.life.strict_shield_wait_max_us, 202);
        assert_eq!(metrics.life.strict_contain_wait_max_us, 303);
        assert_eq!(metrics.life.storm_candidate, 11);
        assert_eq!(metrics.life.storm_base_allow, 12);
        assert_eq!(metrics.life.storm_shadow, 13);
        assert_eq!(metrics.life.storm_shield_allow, 14);
        assert_eq!(metrics.life.storm_full_allow, 15);
        assert_eq!(metrics.life.storm_smt_block, 16);
        assert_eq!(metrics.life.storm_unknown_owner, 17);
        assert_eq!(metrics.life.storm_disabled, 18);
        assert_eq!(metrics.life.storm_reject, 19);
        assert_eq!(metrics.life.direct_wake_bins, [1, 2, 3, 4, 5]);
        assert_eq!(metrics.life.busy_wake_bins, [6, 7, 8, 9, 10]);
        assert_eq!(metrics.life.queued_wake_bins, [11, 12, 13, 14, 15]);
        assert_eq!(metrics.life.path_home, 16);
        assert_eq!(metrics.life.path_core, 17);
        assert_eq!(metrics.life.path_primary, 18);
        assert_eq!(metrics.life.path_idle, 19);
        assert_eq!(metrics.life.path_tunnel, 20);
        assert_eq!(metrics.life.select_migrate_path, [21, 22, 23, 24, 25]);
        assert_eq!(
            metrics.life.select_migrate_reason,
            [31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41]
        );

        assert_eq!(metrics.win30.busy_wakes, 18);
        assert_eq!(metrics.win30.busy_preempt_allow, 21);
        assert_eq!(metrics.win30.busy_preempt_skip, 22);
        assert_eq!(metrics.win30.direct_wait_avg_us, 40);
        assert_eq!(metrics.win30.direct_wait_max_us, 444);
        assert_eq!(metrics.win30.busy_wait_avg_us, 50);
        assert_eq!(metrics.win30.busy_wait_max_us, 555);
        assert_eq!(metrics.win30.queued_wait_avg_us, 60);
        assert_eq!(metrics.win30.queued_wait_max_us, 666);
        assert_eq!(metrics.win30.primary_scan_guarded, 76);
        assert_eq!(metrics.win30.primary_scan_hot_guarded, 17);
        assert_eq!(metrics.win30.primary_scan_credit_used, 7);
        assert_eq!(metrics.win30.wake_chain_locality_guarded, 15);
        assert_eq!(metrics.win30.wake_chain_locality_credit_used, 14);
        assert_eq!(metrics.win30.smt_runtime_contended_tenths, 234);
        assert_eq!(metrics.win30.smt_runs_contended_tenths, 78);
        assert_eq!(metrics.win30.shield_samples, 30);
        assert_eq!(metrics.win30.contain_samples, 40);
        assert_eq!(metrics.win30.strict_busy_preempt_allow, 23);
        assert_eq!(metrics.win30.strict_busy_preempt_skip, 24);
        assert_eq!(metrics.win30.strict_shield_samples, 33);
        assert_eq!(metrics.win30.strict_contain_samples, 44);
        assert_eq!(metrics.win30.strict_shield_wait_max_us, 505);
        assert_eq!(metrics.win30.strict_contain_wait_max_us, 606);
        assert_eq!(metrics.win30.direct_wake_bins, [21, 22, 23, 24, 25]);
        assert_eq!(metrics.win30.busy_wake_bins, [26, 27, 28, 29, 30]);
        assert_eq!(metrics.win30.queued_wake_bins, [31, 32, 33, 34, 35]);
        assert_eq!(metrics.win30.path_home, 36);
        assert_eq!(metrics.win30.path_core, 37);
        assert_eq!(metrics.win30.path_primary, 38);
        assert_eq!(metrics.win30.path_idle, 39);
        assert_eq!(metrics.win30.path_tunnel, 40);
        assert_eq!(metrics.win30.select_migrate_path, [41, 42, 43, 44, 45]);
        assert_eq!(
            metrics.win30.select_migrate_reason,
            [51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61]
        );

        assert_eq!(metrics.win60.busy_wakes, 28);
        assert_eq!(metrics.win60.busy_preempt_allow, 31);
        assert_eq!(metrics.win60.busy_preempt_skip, 32);
        assert_eq!(metrics.win60.direct_wait_avg_us, 70);
        assert_eq!(metrics.win60.direct_wait_max_us, 777);
        assert_eq!(metrics.win60.busy_wait_avg_us, 80);
        assert_eq!(metrics.win60.busy_wait_max_us, 888);
        assert_eq!(metrics.win60.queued_wait_avg_us, 90);
        assert_eq!(metrics.win60.queued_wait_max_us, 999);
        assert_eq!(metrics.win60.primary_scan_guarded, 86);
        assert_eq!(metrics.win60.primary_scan_hot_guarded, 18);
        assert_eq!(metrics.win60.primary_scan_credit_used, 8);
        assert_eq!(metrics.win60.wake_chain_locality_guarded, 25);
        assert_eq!(metrics.win60.wake_chain_locality_credit_used, 24);
        assert_eq!(metrics.win60.smt_runtime_contended_tenths, 345);
        assert_eq!(metrics.win60.smt_runs_contended_tenths, 89);
        assert_eq!(metrics.win60.shield_samples, 300);
        assert_eq!(metrics.win60.contain_samples, 400);
        assert_eq!(metrics.win60.strict_busy_preempt_allow, 33);
        assert_eq!(metrics.win60.strict_busy_preempt_skip, 34);
        assert_eq!(metrics.win60.strict_shield_samples, 303);
        assert_eq!(metrics.win60.strict_contain_samples, 404);
        assert_eq!(metrics.win60.strict_shield_wait_max_us, 808);
        assert_eq!(metrics.win60.strict_contain_wait_max_us, 909);
        assert_eq!(metrics.win60.storm_candidate, 21);
        assert_eq!(metrics.win60.storm_base_allow, 22);
        assert_eq!(metrics.win60.storm_shadow, 23);
        assert_eq!(metrics.win60.storm_shield_allow, 24);
        assert_eq!(metrics.win60.storm_full_allow, 25);
        assert_eq!(metrics.win60.storm_smt_block, 26);
        assert_eq!(metrics.win60.storm_unknown_owner, 27);
        assert_eq!(metrics.win60.storm_disabled, 28);
        assert_eq!(metrics.win60.storm_reject, 29);
        assert_eq!(metrics.win60.direct_wake_bins, [41, 42, 43, 44, 45]);
        assert_eq!(metrics.win60.busy_wake_bins, [46, 47, 48, 49, 50]);
        assert_eq!(metrics.win60.queued_wake_bins, [51, 52, 53, 54, 55]);
        assert_eq!(metrics.win60.path_home, 56);
        assert_eq!(metrics.win60.path_core, 57);
        assert_eq!(metrics.win60.path_primary, 58);
        assert_eq!(metrics.win60.path_idle, 59);
        assert_eq!(metrics.win60.path_tunnel, 60);
        assert_eq!(metrics.win60.select_migrate_path, [61, 62, 63, 64, 65]);
        assert_eq!(
            metrics.win60.select_migrate_reason,
            [71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81]
        );

        assert_eq!(metrics.top_app.label, "Game/42");
        assert_eq!(metrics.top_app.share_tenths, 555);
        assert_eq!(metrics.top_app.wake_total, 6);
        assert_eq!(metrics.top_app.wait_max_us, 600);
        assert_eq!(metrics.top_app.migration_rate_tenths, 123);
        assert_eq!(metrics.top_app.yield_count, 77);

        assert_eq!(metrics.wakegraph_tail.label, "C/3 -> D/4");
        assert_eq!(metrics.wakegraph_tail.wake_count, 5);
        assert_eq!(metrics.wakegraph_tail.wait_max_us, 1000);
        assert_eq!(metrics.wakegraph_tail.ge5ms_count, 2);
    }
}
