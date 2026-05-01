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
    pub top_app: AppHealthMetrics,
    pub wakegraph_tail: WakegraphEdgeMetrics,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct CoverageMetrics {
    pub status: String,
    pub degraded: u64,
    pub sections: u64,
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
    pub direct_wake_bins: [u64; 5],
    pub busy_wake_bins: [u64; 5],
    pub queued_wake_bins: [u64; 5],
    pub path_home: u64,
    pub path_core: u64,
    pub path_primary: u64,
    pub path_idle: u64,
    pub path_tunnel: u64,
    pub select_migrate_path: [u64; 5],
    pub select_migrate_reason: [u64; 9],
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

fn parse_coverage_line(metrics: &mut CoverageMetrics, line: &str) {
    metrics.status = token_after(line, "status=")
        .unwrap_or("unknown")
        .to_string();
    metrics.degraded = field_u64(line, "degraded=").unwrap_or(0);
    metrics.sections = field_u64(line, "sections=").unwrap_or(0);
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
            &["hm", "hc", "pp", "ps", "hy", "kp", "ki", "tn", "pc"],
            &baseline.select_migrate_reason
        ),
        format_labeled_u64(
            &["hm", "hc", "pp", "ps", "hy", "kp", "ki", "tn", "pc"],
            &candidate.select_migrate_reason
        ),
        format_labeled_i128(
            &["hm", "hc", "pp", "ps", "hy", "kp", "ki", "tn", "pc"],
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

    #[test]
    fn bpf_debug_busy_wake_policy_has_owner_runtime_guard() {
        let src = include_str!("bpf/cake.bpf.c");

        assert!(src.contains("cake_busy_wake_policy_should_preempt("));
        assert!(src.contains("CAKE_BUSY_OWNER_SHORT_RUN_NS 100000U"));
        assert!(src.contains("CAKE_BUSY_OWNER_MIN_RUNS 32U"));
        assert!(src.contains("CAKE_PRIMARY_SCAN_CREDIT_PERIOD 8U"));
        assert!(src.contains("primary_scan_credit"));
        assert!(src.contains("nr_primary_scan_credit_used"));
        assert!(src.contains("CAKE_HOT_PRIMARY_SCAN_CREDIT_PERIOD 8U"));
        assert!(src.contains("CAKE_HOT_PRIMARY_SCAN_UTIL_MAX 256U"));
        assert!(src.contains("CAKE_HOT_PRIMARY_SCAN_MIN_RUNS 128U"));
        assert!(src.contains("CAKE_HOT_PRIMARY_SCAN_AVG_RUN_NS 50000ULL"));
        assert!(src.contains("#ifdef CAKE_RELEASE\n\treturn false;\n#else"));
        assert!(src.contains("total_runtime_ns <= (u64)runs * CAKE_HOT_PRIMARY_SCAN_AVG_RUN_NS"));
        assert!(src.contains("cake_should_guard_hot_primary_scan("));
        assert!(src.contains("nr_primary_scan_hot_guarded"));

        let hot_guard_body = src
            .split_once("static __always_inline bool cake_should_guard_hot_primary_scan")
            .and_then(|(_, rest)| {
                rest.split_once("static __always_inline bool cake_should_hold_wake_chain_locality")
            })
            .map(|(body, _)| body)
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

        let guard_body = src
            .split_once("static __always_inline bool cake_should_hold_wake_chain_locality")
            .and_then(|(_, rest)| {
                rest.split_once(
                    "static __always_inline bool cake_primary_scan_credit_allows_period",
                )
            })
            .map(|(body, _)| body)
            .expect("wake-chain locality guard body should be present");
        assert!(!guard_body.contains("comm"));
        assert!(!guard_body.contains("pid"));
        assert!(!guard_body.contains("tgid"));
    }

    #[test]
    fn bpf_wake_chain_locality_policy_has_runtime_disable() {
        let src = include_str!("bpf/cake.bpf.c");
        let main = include_str!("main.rs");
        let readme = include_str!("../README.md");

        assert!(src.contains("#ifdef CAKE_RELEASE"));
        assert!(src.contains("#define CAKE_WAKE_CHAIN_LOCALITY_ENABLED 0"));
        assert!(src.contains("const volatile bool enable_wake_chain_locality"));
        assert!(src.contains("CAKE_WAKE_CHAIN_LOCALITY_ENABLED"));
        assert!(src.contains("if (!CAKE_WAKE_CHAIN_LOCALITY_ENABLED)"));
        assert!(main.contains("wake_chain_locality"));
        assert!(main.contains("#[cfg(not(cake_bpf_release))]"));
        assert!(main.contains("rodata.enable_wake_chain_locality = args.wake_chain_locality"));
        assert!(readme.contains("debug/telemetry A/B controls"));
    }

    #[test]
    fn locality_ab_knobs_default_off_for_latency_first_policy() {
        let src = include_str!("bpf/cake.bpf.c");
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

        assert!(src.contains("const volatile bool enable_learned_locality = false;"));
        assert!(src.contains("const volatile bool enable_wake_chain_locality = false;"));
        assert!(src.contains("#define CAKE_LEARNED_LOCALITY_ENABLED 0"));
        assert!(src.contains("#define CAKE_WAKE_CHAIN_LOCALITY_ENABLED 0"));
        assert!(wake_chain_arg.contains("default_value_t = false"));
        assert!(learned_arg.contains("default_value_t = false"));
        assert!(readme.contains("--learned-locality=true"));
        assert!(readme.contains("--wake-chain-locality=true"));
    }

    #[test]
    fn bpf_game_perf_ab_knobs_cover_locality_and_busy_kicks() {
        let src = include_str!("bpf/cake.bpf.c");
        let main = include_str!("main.rs");
        let readme = include_str!("../README.md");

        assert!(src.contains("const volatile bool enable_learned_locality"));
        assert!(src.contains("CAKE_LEARNED_LOCALITY_ENABLED"));
        assert!(src.contains("CAKE_LEARNED_LOCALITY_ENABLED && cake_should_steer"));
        assert!(src.contains("const volatile u32 busy_wake_kick_mode"));
        assert!(src.contains("#define CAKE_BUSY_WAKE_KICK_MODE CAKE_BUSY_WAKE_KICK_POLICY"));
        assert!(src.contains("CAKE_BUSY_WAKE_KICK_PREEMPT"));
        assert!(src.contains("CAKE_BUSY_WAKE_KICK_IDLE"));
        assert!(main.contains("enum BusyWakeKickMode"));
        assert!(main.contains("learned_locality"));
        assert!(main.contains("busy_wake_kick"));
        assert!(main.contains("#[cfg(not(cake_bpf_release))]"));
        assert!(main.contains("rodata.enable_learned_locality = args.learned_locality"));
        assert!(main.contains("rodata.busy_wake_kick_mode = args.busy_wake_kick as u32"));
        assert!(readme.contains("debug/telemetry A/B controls"));
        assert!(readme.contains("--busy-wake-kick=preempt"));
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
        assert!(bpf.contains("ev->aux = sample_weight"));
        assert!(bpf.contains("if (!important && !cake_debug_should_sample_wake_edge"));
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
coverage: status=degraded degraded=2 sections=7
disp: dsq_total=100 local=90 steal=10 miss=2 queue=0 ins:direct=12 affine=3 shared=4 shared[w/r/p/o]=1/2/3/4 direct[k/o]=5/6 wake:direct=7 busy=8 queued=9 total=24 busy_local=5 busy_remote=3 guard:primary_scan=66 hot_guard:primary_scan=7 credit:primary_scan=6 chain:guard=5 chain:credit=4
wakewait.all: dir=10/111us(7) busy=20/222us(8) queue=30/333us(9)
smt: runtime_contended=12.3% overlap=4.5% runs_contended=6.7% avg_run_us[s/c]=1/2 wake_avg_us[s/c]=3/4 active_start/stop=5/6
wakebins: direct=1/2/3/4/5 busy=6/7/8/9/10 queued=11/12/13/14/15
decision.migrate: path=[home=21 core=22 primary=23 idle=24 tunnel=25] reason=[hm=31 hc=32 pp=33 ps=34 hy=35 kp=36 ki=37 tn=38 pc=39] total=315
place.path: home=16 core=17 primary=18 idle=19 tunnel=20 deps:same_tgid=1 cross_tgid=2
wakepolicy.life: class=[none=1 normal=2 shield=3 contain=4] reasons=[none=0] transitions=[none->normal=1] busy_shadow:allow=11 skip=12 owner_class=[none=0 normal=0 shield=0 contain=0]
wakepolicy.strict.life: class=[none=5 normal=6 shield=7 contain=8] reasons=[yield_heavy=9] wait=[normal=1/101us(6) shield=2/202us(7) contain=3/303us(8)] transitions=[normal->contain=2] busy_shadow:allow=13 skip=14 owner_class=[none=0 normal=0 shield=0 contain=0]
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
win.decision.migrate: path=[home=41 core=42 primary=43 idle=44 tunnel=45] reason=[hm=51 hc=52 pp=53 ps=54 hy=55 kp=56 ki=57 tn=58 pc=59] total=495
win.path: home=36 core=37 primary=38 idle=39 tunnel=40 deps:same_tgid=1 (1.0/s) cross_tgid=2 (2.0/s)
win.wakepolicy.30s: class=[none=10 normal=20 shield=30 contain=40] reasons=[none=0] transitions=[normal->shield=1] busy_shadow:allow=21 skip=22 owner_class=[none=0 normal=0 shield=0 contain=0]
win.wakepolicy.strict.30s: class=[none=11 normal=22 shield=33 contain=44] reasons=[yield_heavy=55] wait=[normal=4/404us(22) shield=5/505us(33) contain=6/606us(44)] transitions=[normal->contain=3] busy_shadow:allow=23 skip=24 owner_class=[none=0 normal=0 shield=0 contain=0]
window: 60s sampled=60.0s
win.disp: dsq_total=300 (1.0/s) local=290 steal=10 miss=2 (0.1/s) queue_now=0 ins:direct=12 (0.1/s) affine=3 (0.1/s) shared=4 (0.1/s) shared[w/r/p/o]=1/2/3/4 direct[k/o]=5/6 wake:direct=27 (70.8%) busy=28 (75.0%) queued=29 (79.2%) total=84 (1.0/s) guard:primary_scan=86 hot_guard:primary_scan=18 credit:primary_scan=8 chain:guard=25 chain:credit=24
win.wakewait.all: dir=70/777us(27) busy=80/888us(28) queue=90/999us(29)
win.smt: runtime_contended=34.5% overlap=5.6% runs_contended=8.9% avg_run_us[s/c]=1/2 wake_avg_us[s/c]=3/4 active_start/stop=5/6
win.wakebins: direct=41/42/43/44/45 busy=46/47/48/49/50 queued=51/52/53/54/55
win.decision.migrate: path=[home=61 core=62 primary=63 idle=64 tunnel=65] reason=[hm=71 hc=72 pp=73 ps=74 hy=75 kp=76 ki=77 tn=78 pc=79] total=675
win.path: home=56 core=57 primary=58 idle=59 tunnel=60 deps:same_tgid=1 (1.0/s) cross_tgid=2 (2.0/s)
win.wakepolicy.60s: class=[none=100 normal=200 shield=300 contain=400] reasons=[none=0] transitions=[normal->shield=1] busy_shadow:allow=31 skip=32 owner_class=[none=0 normal=0 shield=0 contain=0]
win.wakepolicy.strict.60s: class=[none=101 normal=202 shield=303 contain=404] reasons=[yield_heavy=505] wait=[normal=7/707us(202) shield=8/808us(303) contain=9/909us(404)] transitions=[normal->contain=4] busy_shadow:allow=33 skip=34 owner_class=[none=0 normal=0 shield=0 contain=0]
";

        let metrics = parse_metrics(dump);

        assert_eq!(metrics.coverage.status, "degraded");
        assert_eq!(metrics.coverage.degraded, 2);
        assert_eq!(metrics.coverage.sections, 7);

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
            [31, 32, 33, 34, 35, 36, 37, 38, 39]
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
            [51, 52, 53, 54, 55, 56, 57, 58, 59]
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
            [71, 72, 73, 74, 75, 76, 77, 78, 79]
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
