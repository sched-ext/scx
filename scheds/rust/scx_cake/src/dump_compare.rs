// SPDX-License-Identifier: GPL-2.0

use std::fs;
use std::path::Path;

use anyhow::{Context, Result};

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct DumpMetrics {
    pub busy_wakes: u64,
    pub busy_preempt_allow: u64,
    pub busy_preempt_skip: u64,
    pub direct_wait_max_us: u64,
    pub busy_wait_max_us: u64,
    pub smt_runtime_contended_tenths: u64,
    pub shield_samples: u64,
    pub contain_samples: u64,
}

pub fn run_compare(baseline: &Path, candidate: &Path) -> Result<()> {
    let baseline_text = fs::read_to_string(baseline)
        .with_context(|| format!("failed to read baseline dump {}", baseline.display()))?;
    let candidate_text = fs::read_to_string(candidate)
        .with_context(|| format!("failed to read candidate dump {}", candidate.display()))?;

    let baseline = parse_metrics(&baseline_text);
    let candidate = parse_metrics(&candidate_text);

    println!("scx_cake dump comparison");
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

    Ok(())
}

fn parse_metrics(dump: &str) -> DumpMetrics {
    let mut metrics = DumpMetrics::default();

    for line in dump.lines().map(str::trim_start) {
        if line.starts_with("disp:") || line.starts_with("win.disp:") {
            metrics.busy_wakes += field_u64(line, "busy=").unwrap_or(0);
            continue;
        }

        if line.starts_with("wakewait.all:") || line.starts_with("win.wakewait.all:") {
            metrics.direct_wait_max_us = metrics
                .direct_wait_max_us
                .max(wakewait_max_us(line, "dir="));
            metrics.busy_wait_max_us = metrics.busy_wait_max_us.max(wakewait_max_us(line, "busy="));
            continue;
        }

        if line.starts_with("smt:") || line.starts_with("win.smt:") {
            metrics.smt_runtime_contended_tenths = metrics
                .smt_runtime_contended_tenths
                .max(percent_tenths(line, "runtime_contended=").unwrap_or(0));
            continue;
        }

        if line.starts_with("wakepolicy.life:") || line.starts_with("win.wakepolicy.") {
            metrics.busy_preempt_allow += field_u64(line, "allow=").unwrap_or(0);
            metrics.busy_preempt_skip += field_u64(line, "skip=").unwrap_or(0);
            if let Some(class_counts) = bracket_body(line, "class=[") {
                metrics.shield_samples += field_u64(class_counts, "shield=").unwrap_or(0);
                metrics.contain_samples += field_u64(class_counts, "contain=").unwrap_or(0);
            }
        }
    }

    metrics
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
    fn parses_core_dump_metrics() {
        let dump = "\
disp: dsq_total=100 local=90 steal=10 miss=2 queue=0 ins:direct=12 affine=3 shared=4 shared[w/r/p/o]=1/2/3/4 direct[k/o]=5/6 wake:direct=7 busy=8 queued=9 total=24 busy_local=5 busy_remote=3
wakewait.all: dir=10/111us(7) busy=20/222us(8) queue=30/333us(9)
smt: runtime_contended=12.3% overlap=4.5% runs_contended=6.7% avg_run_us[s/c]=1/2 wake_avg_us[s/c]=3/4 active_start/stop=5/6
wakepolicy.life: class=[none=1 normal=2 shield=3 contain=4] reasons=[none=0] transitions=[none->normal=1] busy_shadow:allow=11 skip=12 owner_class=[none=0 normal=0 shield=0 contain=0]
win.disp: dsq_total=200 (1.0/s) local=190 steal=10 miss=2 (0.1/s) queue_now=0 ins:direct=12 (0.1/s) affine=3 (0.1/s) shared=4 (0.1/s) shared[w/r/p/o]=1/2/3/4 direct[k/o]=5/6 wake:direct=17 (70.8%) busy=18 (75.0%) queued=19 (79.2%) total=54 (1.0/s)
win.wakewait.all: dir=40/444us(17) busy=50/555us(18) queue=60/666us(19)
win.smt: runtime_contended=23.4% overlap=5.6% runs_contended=7.8% avg_run_us[s/c]=1/2 wake_avg_us[s/c]=3/4 active_start/stop=5/6
win.wakepolicy.60s: class=[none=10 normal=20 shield=30 contain=40] reasons=[none=0] transitions=[normal->shield=1] busy_shadow:allow=21 skip=22 owner_class=[none=0 normal=0 shield=0 contain=0]
";

        let metrics = parse_metrics(dump);

        assert_eq!(metrics.busy_wakes, 26);
        assert_eq!(metrics.busy_preempt_allow, 32);
        assert_eq!(metrics.busy_preempt_skip, 34);
        assert_eq!(metrics.direct_wait_max_us, 444);
        assert_eq!(metrics.busy_wait_max_us, 555);
        assert_eq!(metrics.smt_runtime_contended_tenths, 234);
        assert_eq!(metrics.shield_samples, 33);
        assert_eq!(metrics.contain_samples, 44);
    }
}
