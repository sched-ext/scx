// SPDX-License-Identifier: GPL-2.0

use std::fs;
use std::path::Path;

use anyhow::{Context, Result};

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct DumpMetrics {
    pub life: ScopeMetrics,
    pub win30: ScopeMetrics,
    pub win60: ScopeMetrics,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ScopeMetrics {
    pub busy_wakes: u64,
    pub busy_preempt_allow: u64,
    pub busy_preempt_skip: u64,
    pub direct_wait_max_us: u64,
    pub busy_wait_max_us: u64,
    pub smt_runtime_contended_tenths: u64,
    pub shield_samples: u64,
    pub contain_samples: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WindowScope {
    Win30,
    Win60,
}

pub fn run_compare(baseline: &Path, candidate: &Path) -> Result<()> {
    let baseline_text = fs::read_to_string(baseline)
        .with_context(|| format!("failed to read baseline dump {}", baseline.display()))?;
    let candidate_text = fs::read_to_string(candidate)
        .with_context(|| format!("failed to read candidate dump {}", candidate.display()))?;

    let baseline = parse_metrics(&baseline_text);
    let candidate = parse_metrics(&candidate_text);

    println!("scx_cake dump comparison");
    print_scope("life", baseline.life, candidate.life);
    print_scope("30s", baseline.win30, candidate.win30);
    print_scope("60s", baseline.win60, candidate.win60);

    Ok(())
}

fn parse_metrics(dump: &str) -> DumpMetrics {
    let mut metrics = DumpMetrics::default();
    let mut current_window = None;

    for line in dump.lines().map(str::trim_start) {
        if line.starts_with("window:") {
            current_window = parse_window_scope(line);
            continue;
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

        if line.starts_with("wakepolicy.life:") {
            parse_wakepolicy_line(&mut metrics.life, line);
            continue;
        }

        if line.starts_with("win.wakepolicy.") {
            if let Some(scope) = wakepolicy_window_scope(line)
                .and_then(|scope| scope_for_window(&mut metrics, Some(scope)))
            {
                parse_wakepolicy_line(scope, line);
            }
        }
    }

    metrics
}

fn print_scope(name: &str, baseline: ScopeMetrics, candidate: ScopeMetrics) {
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
        "direct_wait_max",
        baseline.direct_wait_max_us,
        candidate.direct_wait_max_us,
        "us",
    );
    print_metric(
        "busy_wait_max",
        baseline.busy_wait_max_us,
        candidate.busy_wait_max_us,
        "us",
    );
    print_pct_metric(
        "smt_runtime_contended",
        baseline.smt_runtime_contended_tenths,
        candidate.smt_runtime_contended_tenths,
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
}

impl ScopeMetrics {
    fn has_data(self) -> bool {
        self.busy_wakes != 0
            || self.busy_preempt_allow != 0
            || self.busy_preempt_skip != 0
            || self.direct_wait_max_us != 0
            || self.busy_wait_max_us != 0
            || self.smt_runtime_contended_tenths != 0
            || self.shield_samples != 0
            || self.contain_samples != 0
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
}

fn parse_wakewait_line(metrics: &mut ScopeMetrics, line: &str) {
    metrics.direct_wait_max_us = wakewait_max_us(line, "dir=");
    metrics.busy_wait_max_us = wakewait_max_us(line, "busy=");
}

fn parse_smt_line(metrics: &mut ScopeMetrics, line: &str) {
    metrics.smt_runtime_contended_tenths = percent_tenths(line, "runtime_contended=").unwrap_or(0);
}

fn parse_wakepolicy_line(metrics: &mut ScopeMetrics, line: &str) {
    metrics.busy_preempt_allow = field_u64(line, "allow=").unwrap_or(0);
    metrics.busy_preempt_skip = field_u64(line, "skip=").unwrap_or(0);
    if let Some(class_counts) = bracket_body(line, "class=[") {
        metrics.shield_samples = field_u64(class_counts, "shield=").unwrap_or(0);
        metrics.contain_samples = field_u64(class_counts, "contain=").unwrap_or(0);
    }
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

fn print_metric(name: &str, baseline: u64, candidate: u64, suffix: &str) {
    let delta = candidate as i128 - baseline as i128;
    println!(
        "{name}: baseline={}{} candidate={}{} delta={:+}{}",
        baseline, suffix, candidate, suffix, delta, suffix
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

fn format_tenths_pct(value: u64) -> String {
    format!("{}.{:01}%", value / 10, value % 10)
}

fn format_signed_tenths_pct(value: i128) -> String {
    let sign = if value < 0 { "-" } else { "+" };
    let abs = value.abs();
    format!("{sign}{}.{:01}%", abs / 10, abs % 10)
}

fn field_u64(text: &str, key: &str) -> Option<u64> {
    let rest = text.split_once(key)?.1;
    let digits: String = rest.chars().take_while(|ch| ch.is_ascii_digit()).collect();
    digits.parse().ok()
}

fn wakewait_max_us(line: &str, key: &str) -> u64 {
    let Some(rest) = line.split_once(key).map(|(_, rest)| rest) else {
        return 0;
    };
    let Some((_, after_slash)) = rest.split_once('/') else {
        return 0;
    };
    after_slash
        .chars()
        .take_while(|ch| ch.is_ascii_digit())
        .collect::<String>()
        .parse()
        .unwrap_or(0)
}

fn percent_tenths(text: &str, key: &str) -> Option<u64> {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_core_dump_metrics_by_scope() {
        let dump = "\
disp: dsq_total=100 local=90 steal=10 miss=2 queue=0 ins:direct=12 affine=3 shared=4 shared[w/r/p/o]=1/2/3/4 direct[k/o]=5/6 wake:direct=7 busy=8 queued=9 total=24 busy_local=5 busy_remote=3
wakewait.all: dir=10/111us(7) busy=20/222us(8) queue=30/333us(9)
smt: runtime_contended=12.3% overlap=4.5% runs_contended=6.7% avg_run_us[s/c]=1/2 wake_avg_us[s/c]=3/4 active_start/stop=5/6
wakepolicy.life: class=[none=1 normal=2 shield=3 contain=4] reasons=[none=0] transitions=[none->normal=1] busy_shadow:allow=11 skip=12 owner_class=[none=0 normal=0 shield=0 contain=0]
window: 30s sampled=30.0s
win.disp: dsq_total=200 (1.0/s) local=190 steal=10 miss=2 (0.1/s) queue_now=0 ins:direct=12 (0.1/s) affine=3 (0.1/s) shared=4 (0.1/s) shared[w/r/p/o]=1/2/3/4 direct[k/o]=5/6 wake:direct=17 (70.8%) busy=18 (75.0%) queued=19 (79.2%) total=54 (1.0/s)
win.wakewait.all: dir=40/444us(17) busy=50/555us(18) queue=60/666us(19)
win.smt: runtime_contended=23.4% overlap=5.6% runs_contended=7.8% avg_run_us[s/c]=1/2 wake_avg_us[s/c]=3/4 active_start/stop=5/6
win.wakepolicy.30s: class=[none=10 normal=20 shield=30 contain=40] reasons=[none=0] transitions=[normal->shield=1] busy_shadow:allow=21 skip=22 owner_class=[none=0 normal=0 shield=0 contain=0]
window: 60s sampled=60.0s
win.disp: dsq_total=300 (1.0/s) local=290 steal=10 miss=2 (0.1/s) queue_now=0 ins:direct=12 (0.1/s) affine=3 (0.1/s) shared=4 (0.1/s) shared[w/r/p/o]=1/2/3/4 direct[k/o]=5/6 wake:direct=27 (70.8%) busy=28 (75.0%) queued=29 (79.2%) total=84 (1.0/s)
win.wakewait.all: dir=70/777us(27) busy=80/888us(28) queue=90/999us(29)
win.smt: runtime_contended=34.5% overlap=5.6% runs_contended=7.8% avg_run_us[s/c]=1/2 wake_avg_us[s/c]=3/4 active_start/stop=5/6
win.wakepolicy.60s: class=[none=100 normal=200 shield=300 contain=400] reasons=[none=0] transitions=[normal->shield=1] busy_shadow:allow=31 skip=32 owner_class=[none=0 normal=0 shield=0 contain=0]
";

        let metrics = parse_metrics(dump);

        assert_eq!(metrics.life.busy_wakes, 8);
        assert_eq!(metrics.life.busy_preempt_allow, 11);
        assert_eq!(metrics.life.busy_preempt_skip, 12);
        assert_eq!(metrics.life.direct_wait_max_us, 111);
        assert_eq!(metrics.life.busy_wait_max_us, 222);
        assert_eq!(metrics.life.smt_runtime_contended_tenths, 123);
        assert_eq!(metrics.life.shield_samples, 3);
        assert_eq!(metrics.life.contain_samples, 4);

        assert_eq!(metrics.win30.busy_wakes, 18);
        assert_eq!(metrics.win30.busy_preempt_allow, 21);
        assert_eq!(metrics.win30.busy_preempt_skip, 22);
        assert_eq!(metrics.win30.direct_wait_max_us, 444);
        assert_eq!(metrics.win30.busy_wait_max_us, 555);
        assert_eq!(metrics.win30.smt_runtime_contended_tenths, 234);
        assert_eq!(metrics.win30.shield_samples, 30);
        assert_eq!(metrics.win30.contain_samples, 40);

        assert_eq!(metrics.win60.busy_wakes, 28);
        assert_eq!(metrics.win60.busy_preempt_allow, 31);
        assert_eq!(metrics.win60.busy_preempt_skip, 32);
        assert_eq!(metrics.win60.direct_wait_max_us, 777);
        assert_eq!(metrics.win60.busy_wait_max_us, 888);
        assert_eq!(metrics.win60.smt_runtime_contended_tenths, 345);
        assert_eq!(metrics.win60.shield_samples, 300);
        assert_eq!(metrics.win60.contain_samples, 400);
    }
}
