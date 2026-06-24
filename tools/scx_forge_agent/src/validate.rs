// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: GPL-2.0-only
//! Native validation harness: the agent's reward function.
//!
//! Builds the scheduler, attaches it on the host (as root), drives a workload,
//! extracts a single metric, always tears the scheduler down (verifying the
//! kernel returns to `disabled`), and returns a [`Verdict`]. Runs in-process;
//! the equivalent logic previously lived in a separate `run_validation.py`.
//!
//! Stages mirror the old harness: `spec` / `build` / `preflight` / `attach` /
//! `metric` / `complete`. A non-complete verdict means the candidate did not
//! build, attach, or produce a measurable result this round.

use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::AtomicBool;
use std::thread::sleep;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use serde_json::{json, Value};

use crate::cargo_program;
use crate::color::Style;
use crate::interrupt;
use crate::progress::ProgressSpinner;
use crate::spec::{Spec, METRIC_NAME};
use crate::sudo::Sudo;

const SCX_STATE_PATH: &str = "/sys/kernel/sched_ext/state";

#[derive(Debug, Clone)]
pub struct Verdict {
    pub ok: bool,
    pub stage: String,
    pub metric_name: String,
    pub goal: String,
    pub value: Option<f64>,
    pub median: Option<f64>,
    pub stddev: Option<f64>,
    pub errors: Vec<String>,
    pub raw: Value,
}

impl Verdict {
    pub fn is_complete(&self) -> bool {
        self.ok && self.stage == "complete" && self.value.is_some()
    }
}

/// Return the sched_ext root state ("disabled"/"enabled"/...) or None.
fn scx_state() -> Option<String> {
    std::fs::read_to_string(SCX_STATE_PATH)
        .ok()
        .map(|s| s.trim().to_string())
}

/// Poll the sched_ext state until it equals `want` or the timeout elapses.
fn wait_for_state(want: &str, timeout: Duration, interrupted: &AtomicBool) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        if scx_state().as_deref() == Some(want) {
            return true;
        }
        if interrupt::requested(interrupted) {
            return false;
        }
        if Instant::now() >= deadline {
            return scx_state().as_deref() == Some(want);
        }
        sleep(Duration::from_millis(100));
    }
}

fn scx_is_enabled(state: Option<&str>) -> bool {
    state == Some("enabled")
}

/// Sleep up to `duration`, returning true if interrupted before the deadline.
fn sleep_interruptible(duration: Duration, interrupted: &AtomicBool) -> bool {
    let deadline = Instant::now() + duration;
    loop {
        if interrupt::requested(interrupted) {
            return true;
        }
        let now = Instant::now();
        if now >= deadline {
            return false;
        }
        sleep((deadline - now).min(Duration::from_millis(100)));
    }
}

/// cargo build the candidate. Returns (ok, combined stdout+stderr).
fn cargo_build(
    repo_root: &Path,
    package: &str,
    profile: &str,
    interrupted: &AtomicBool,
) -> (bool, String) {
    let cargo = cargo_program();
    let mut command = Command::new(&cargo);
    command
        .args(["build", "--profile", profile, "-p", package])
        .current_dir(repo_root)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    unsafe {
        command.pre_exec(|| {
            libc::setsid();
            Ok(())
        });
    }
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(e) => {
            return (
                false,
                format!("spawn {} build: {e}", cargo.to_string_lossy()),
            )
        }
    };
    let pid = child.id() as i32;
    loop {
        if interrupt::requested(interrupted) {
            unsafe {
                libc::kill(-pid, libc::SIGINT);
            }
            let deadline = Instant::now() + Duration::from_secs(2);
            loop {
                match child.try_wait() {
                    Ok(Some(_)) | Err(_) => break,
                    Ok(None) if Instant::now() >= deadline => {
                        unsafe {
                            libc::kill(-pid, libc::SIGKILL);
                        }
                        break;
                    }
                    Ok(None) => sleep(Duration::from_millis(50)),
                }
            }
            let out = match child.wait_with_output() {
                Ok(out) => out,
                Err(e) => {
                    return (
                        false,
                        format!("cargo build interrupted; collect output: {e}"),
                    )
                }
            };
            let mut s = String::from("cargo build interrupted by Ctrl-C\n");
            s.push_str(&String::from_utf8_lossy(&out.stdout));
            s.push_str(&String::from_utf8_lossy(&out.stderr));
            return (false, s);
        }
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) => sleep(Duration::from_millis(100)),
            Err(e) => {
                return (
                    false,
                    format!("poll {} build: {e}", cargo.to_string_lossy()),
                )
            }
        }
    }
    let out = match child.wait_with_output() {
        Ok(out) => out,
        Err(e) => {
            return (
                false,
                format!("collect {} build output: {e}", cargo.to_string_lossy()),
            )
        }
    };
    let mut s = String::from_utf8_lossy(&out.stdout).to_string();
    s.push_str(&String::from_utf8_lossy(&out.stderr));
    (out.status.success(), s)
}

/// cargo maps release/dev to target/{release,debug}; named profiles land in
/// target/<profile>.
pub(crate) fn binary_path(repo_root: &Path, package: &str, profile: &str) -> PathBuf {
    let subdir = match profile {
        "release" => "release",
        "dev" => "debug",
        other => other,
    };
    repo_root.join("target").join(subdir).join(package)
}

fn read_lossy(path: &Path) -> String {
    std::fs::read(path)
        .map(|b| String::from_utf8_lossy(&b).into_owned())
        .unwrap_or_default()
}

fn trace_cmd_available() -> bool {
    // Some trace-cmd builds print help/version but still exit non-zero. For
    // availability, only require that the executable can be spawned; record/report
    // errors are captured later in trace.run<N>.log and sched_trace.
    Command::new("trace-cmd")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok()
}

/// Per-CPU `-m` value in KB for `trace-cmd record`, derived from a total byte
/// budget split across the online CPUs (at least 1 KB). `trace-cmd record -m`
/// takes a *per-CPU* limit in KB and records into a circular file (oldest data
/// is overwritten once the cap is hit), so the combined `trace.dat` stays within
/// roughly `max_total_bytes`.
fn trace_max_kb_per_cpu(max_total_bytes: u64) -> u64 {
    let cpus = std::thread::available_parallelism()
        .map(|n| n.get() as u64)
        .unwrap_or(1)
        .max(1);
    (max_total_bytes / 1024 / cpus).max(1)
}

#[derive(Default, Debug)]
struct TraceStats {
    sched_switch: u64,
    sched_wakeup: u64,
    sched_wakeup_new: u64,
    sched_migrate_task: u64,
    switch_cpu: HashMap<String, u64>,
    next_comm: HashMap<String, u64>,
    prev_comm: HashMap<String, u64>,
    prev_state: HashMap<String, u64>,
    wakeup_comm: HashMap<String, u64>,
    wakeup_target_cpu: HashMap<String, u64>,
    wakeup_new_comm: HashMap<String, u64>,
    wakeup_new_target_cpu: HashMap<String, u64>,
    migrate_comm: HashMap<String, u64>,
    migrate_orig_cpu: HashMap<String, u64>,
    migrate_dest_cpu: HashMap<String, u64>,
    migrate_path: HashMap<String, u64>,
}

fn bump(map: &mut HashMap<String, u64>, key: Option<String>) {
    if let Some(key) = key.filter(|s| !s.is_empty()) {
        *map.entry(key).or_insert(0) += 1;
    }
}

fn trace_field(line: &str, key: &str) -> Option<String> {
    let marker = format!("{key}=");
    let start = line.find(&marker)? + marker.len();
    let rest = &line[start..];
    let end = rest.find(char::is_whitespace).unwrap_or(rest.len());
    Some(rest[..end].trim_end_matches(',').to_string())
}

fn trace_cpu(line: &str) -> Option<String> {
    let start = line.find('[')? + 1;
    let end = line[start..].find(']')? + start;
    Some(line[start..end].trim().to_string())
}

fn trace_cpu_path(line: &str) -> Option<String> {
    let orig = trace_field(line, "orig_cpu")?;
    let dest = trace_field(line, "dest_cpu")?;
    Some(format!("{orig}->{dest}"))
}

fn update_trace_stats(stats: &mut TraceStats, line: &str) {
    if line.contains("sched_switch:") {
        stats.sched_switch += 1;
        bump(&mut stats.switch_cpu, trace_cpu(line));
        bump(&mut stats.next_comm, trace_field(line, "next_comm"));
        bump(&mut stats.prev_comm, trace_field(line, "prev_comm"));
        bump(&mut stats.prev_state, trace_field(line, "prev_state"));
    } else if line.contains("sched_wakeup_new:") {
        stats.sched_wakeup_new += 1;
        bump(&mut stats.wakeup_new_comm, trace_field(line, "comm"));
        bump(
            &mut stats.wakeup_new_target_cpu,
            trace_field(line, "target_cpu"),
        );
    } else if line.contains("sched_wakeup:") {
        stats.sched_wakeup += 1;
        bump(&mut stats.wakeup_comm, trace_field(line, "comm"));
        bump(
            &mut stats.wakeup_target_cpu,
            trace_field(line, "target_cpu"),
        );
    } else if line.contains("sched_migrate_task:") {
        stats.sched_migrate_task += 1;
        bump(&mut stats.migrate_comm, trace_field(line, "comm"));
        bump(&mut stats.migrate_orig_cpu, trace_field(line, "orig_cpu"));
        bump(&mut stats.migrate_dest_cpu, trace_field(line, "dest_cpu"));
        bump(&mut stats.migrate_path, trace_cpu_path(line));
    }
}

fn top_counts(map: &HashMap<String, u64>, limit: usize) -> Value {
    let mut v = map.iter().collect::<Vec<_>>();
    v.sort_by(|(ka, va), (kb, vb)| vb.cmp(va).then_with(|| ka.cmp(kb)));
    json!(v
        .into_iter()
        .take(limit)
        .map(|(name, count)| json!({"name": name, "count": count}))
        .collect::<Vec<_>>())
}

fn trace_stats_json(
    stats: &TraceStats,
    trace_path: &Path,
    report_path: &Path,
    events: &[String],
) -> Value {
    json!({
        "enabled": true,
        "events": events,
        "artifacts": {
            "trace_dat": trace_path.display().to_string(),
            "report": report_path.display().to_string(),
        },
        "sched_switch": stats.sched_switch,
        "sched_wakeup": stats.sched_wakeup,
        "sched_wakeup_new": stats.sched_wakeup_new,
        "sched_migrate_task": stats.sched_migrate_task,
        "top_switch_cpu": top_counts(&stats.switch_cpu, 8),
        "top_next_comm": top_counts(&stats.next_comm, 8),
        "top_prev_comm": top_counts(&stats.prev_comm, 8),
        "top_prev_state": top_counts(&stats.prev_state, 8),
        "top_wakeup_comm": top_counts(&stats.wakeup_comm, 8),
        "top_wakeup_target_cpu": top_counts(&stats.wakeup_target_cpu, 8),
        "top_wakeup_new_comm": top_counts(&stats.wakeup_new_comm, 8),
        "top_wakeup_new_target_cpu": top_counts(&stats.wakeup_new_target_cpu, 8),
        "top_migrate_comm": top_counts(&stats.migrate_comm, 8),
        "top_migrate_orig_cpu": top_counts(&stats.migrate_orig_cpu, 8),
        "top_migrate_dest_cpu": top_counts(&stats.migrate_dest_cpu, 8),
        "top_migrate_path": top_counts(&stats.migrate_path, 8),
    })
}

struct TraceRecorder {
    child: Child,
    trace_path: PathBuf,
    log_path: PathBuf,
}

impl TraceRecorder {
    fn start(
        sudo: &Sudo,
        trace_path: PathBuf,
        log_path: PathBuf,
        max_total_bytes: u64,
        events: &[String],
    ) -> Result<Self> {
        let _ = std::fs::remove_file(&trace_path);
        let _ = sudo
            .command("rm", &["-f".to_string(), trace_path.display().to_string()])
            .status();
        let log = File::create(&log_path)
            .with_context(|| format!("create trace-cmd log {}", log_path.display()))?;
        let log_err = log.try_clone().context("clone trace-cmd log handle")?;
        let mut args = vec![
            "record".to_string(),
            "-o".to_string(),
            trace_path.display().to_string(),
            // Bound the per-CPU output so the combined trace.dat stays within
            // max_total_bytes even for long/busy workloads.
            "-m".to_string(),
            trace_max_kb_per_cpu(max_total_bytes).to_string(),
        ];
        for event in events {
            args.push("-e".to_string());
            args.push(event.to_string());
        }
        let mut command = sudo.command("trace-cmd", &args);
        command.stdout(log).stderr(log_err).stdin(Stdio::null());
        unsafe {
            command.pre_exec(|| {
                libc::setsid();
                Ok(())
            });
        }
        let mut child = command
            .spawn()
            .with_context(|| format!("spawn trace-cmd record {}", trace_path.display()))?;
        sleep(Duration::from_millis(250));
        if let Some(status) = child.try_wait().context("poll trace-cmd startup")? {
            anyhow::bail!(
                "trace-cmd exited during startup with {status}; log tail:\n{}",
                tail(&read_lossy(&log_path), 1000)
            );
        }
        Ok(Self {
            child,
            trace_path,
            log_path,
        })
    }

    fn stop(mut self, sudo: &Sudo, events: &[String]) -> Value {
        let pid = self.child.id() as i32;
        unsafe {
            libc::kill(-pid, libc::SIGINT);
        }
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut stopped = false;
        loop {
            match self.child.try_wait() {
                Ok(Some(_)) => {
                    stopped = true;
                    break;
                }
                Ok(None) => {
                    if Instant::now() >= deadline {
                        break;
                    }
                    sleep(Duration::from_millis(100));
                }
                Err(_) => break,
            }
        }
        if !stopped {
            unsafe {
                libc::kill(-pid, libc::SIGKILL);
            }
            let _ = self.child.wait();
        }
        summarize_trace(sudo, &self.trace_path, &self.log_path, events)
    }
}

fn summarize_trace(sudo: &Sudo, trace_path: &Path, log_path: &Path, events: &[String]) -> Value {
    if !trace_path.exists() {
        return json!({
            "enabled": false,
            "error": format!("trace-cmd did not create {}", trace_path.display()),
            "log_tail": tail(&read_lossy(log_path), 1000),
        });
    }
    let report_path = trace_path.with_extension("report");
    let report = match File::create(&report_path) {
        Ok(f) => f,
        Err(e) => {
            return json!({
                "enabled": false,
                "trace_dat": trace_path.display().to_string(),
                "error": format!("create trace report {}: {e}", report_path.display()),
                "log_tail": tail(&read_lossy(log_path), 1000),
            })
        }
    };
    let report_err = match report.try_clone() {
        Ok(f) => f,
        Err(e) => {
            return json!({
                "enabled": false,
                "trace_dat": trace_path.display().to_string(),
                "error": format!("clone trace report handle: {e}"),
                "log_tail": tail(&read_lossy(log_path), 1000),
            })
        }
    };
    let args = vec![
        "report".to_string(),
        "-i".to_string(),
        trace_path.display().to_string(),
    ];
    let status = sudo
        .command("trace-cmd", &args)
        .stdout(report)
        .stderr(report_err)
        .status();
    if !matches!(status, Ok(s) if s.success()) {
        return json!({
            "enabled": false,
            "trace_dat": trace_path.display().to_string(),
            "report": report_path.display().to_string(),
            "error": format!("trace-cmd report failed: {:?}", status),
            "report_tail": tail(&read_lossy(&report_path), 1000),
            "log_tail": tail(&read_lossy(log_path), 1000),
        });
    }

    let file = match File::open(&report_path) {
        Ok(f) => f,
        Err(e) => {
            return json!({
                "enabled": false,
                "trace_dat": trace_path.display().to_string(),
                "report": report_path.display().to_string(),
                "error": format!("open trace report: {e}"),
                "log_tail": tail(&read_lossy(log_path), 1000),
            })
        }
    };
    let mut stats = TraceStats::default();
    for line in BufReader::new(file).lines().map_while(Result::ok) {
        update_trace_stats(&mut stats, &line);
    }
    trace_stats_json(&stats, trace_path, &report_path, events)
}

/// Run a shell command to completion or until `timeout`, capturing combined
/// stdout+stderr to `out_path`. A fixed-duration workload is expected to be cut
/// off at the timeout; its partial output is still returned.
fn run_capture(
    cmd: &str,
    timeout: Duration,
    out_path: &Path,
    progress: Option<Style>,
    label: String,
    interrupted: &AtomicBool,
) -> Result<String> {
    let out = File::create(out_path)
        .with_context(|| format!("create workload log {}", out_path.display()))?;
    let err = out.try_clone().context("clone workload log handle")?;
    let mut command = Command::new("sh");
    command
        .arg("-c")
        .arg(cmd)
        .stdout(out)
        .stderr(err)
        .stdin(Stdio::null());
    // New session so we can signal the whole process group on timeout.
    unsafe {
        command.pre_exec(|| {
            libc::setsid();
            Ok(())
        });
    }
    let mut child = command
        .spawn()
        .with_context(|| format!("spawn workload: {cmd}"))?;
    let _spinner = progress.map(|style| ProgressSpinner::stdout(label, style));
    let pid = child.id() as i32;
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait().context("poll workload")? {
            Some(_) => break,
            None => {
                if interrupt::requested(interrupted) {
                    unsafe {
                        libc::kill(-pid, libc::SIGINT);
                    }
                    let deadline = Instant::now() + Duration::from_secs(2);
                    loop {
                        match child.try_wait().context("poll interrupted workload")? {
                            Some(_) => break,
                            None if Instant::now() >= deadline => {
                                unsafe {
                                    libc::kill(-pid, libc::SIGKILL);
                                }
                                let _ = child.wait();
                                break;
                            }
                            None => sleep(Duration::from_millis(50)),
                        }
                    }
                    break;
                }
                if Instant::now() >= deadline {
                    unsafe {
                        libc::kill(-pid, libc::SIGKILL);
                    }
                    let _ = child.wait();
                    break;
                }
                sleep(Duration::from_millis(100));
            }
        }
    }
    Ok(read_lossy(out_path))
}

/// Parse the workload command output as the single numeric metric value. Any
/// extraction or aggregation belongs in the command itself.
fn extract_metric(text: &str) -> Option<f64> {
    let value = text.trim();
    if value.is_empty() {
        return None;
    }
    value.parse::<f64>().ok()
}

fn median(values: &[f64]) -> f64 {
    let mut v = values.to_vec();
    v.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let n = v.len();
    if n % 2 == 1 {
        v[n / 2]
    } else {
        (v[n / 2 - 1] + v[n / 2]) / 2.0
    }
}

/// Population standard deviation (matches Python statistics.pstdev).
fn pstdev(values: &[f64]) -> f64 {
    let n = values.len();
    if n <= 1 {
        return 0.0;
    }
    let mean = values.iter().sum::<f64>() / n as f64;
    let var = values.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / n as f64;
    var.sqrt()
}

/// Capture the scheduler binary's `--help` text (stdout+stderr) so we can probe
/// which optional flags it supports before launching it. Passing an unknown
/// argument makes the scheduler exit before attaching, so flags that are not
/// universal must be gated on this. Empty string on any failure.
fn binary_help(binary: &Path) -> String {
    match std::process::Command::new(binary).arg("--help").output() {
        Ok(out) => {
            let mut help = String::from_utf8_lossy(&out.stdout).into_owned();
            help.push_str(&String::from_utf8_lossy(&out.stderr));
            help
        }
        Err(_) => String::new(),
    }
}

/// Launch/teardown of the scheduler with hard safety guarantees.
struct Scheduler {
    binary: PathBuf,
    stats_interval: u64,
    supports_stats: bool,
    supports_verbose: bool,
    log_path: PathBuf,
    child: Option<Child>,
}

impl Scheduler {
    fn new(binary: PathBuf, stats_interval: u64, log_path: PathBuf) -> Self {
        let help = binary_help(&binary);
        Scheduler {
            binary,
            stats_interval,
            supports_stats: help.contains("--stats"),
            supports_verbose: help.contains("--verbose"),
            log_path,
            child: None,
        }
    }

    fn start(&mut self, sudo: &Sudo) -> Result<()> {
        let log = File::create(&self.log_path)
            .with_context(|| format!("create scheduler log {}", self.log_path.display()))?;
        let log_err = log.try_clone().context("clone scheduler log handle")?;
        let mut full_args: Vec<String> = Vec::new();
        // Run verbose so libbpf prints the BPF verifier log to the scheduler
        // log: when a candidate fails to load/attach, that log is the only way
        // to see why (the rejected program and the verifier's reason).
        if self.supports_verbose {
            full_args.push("--verbose".into());
        }
        // Only request periodic stats from schedulers that implement `--stats`;
        // passing it to one that does not makes it exit before attaching.
        if self.supports_stats {
            full_args.push("--stats".into());
            full_args.push(self.stats_interval.to_string());
        }
        let mut command = sudo.command(&self.binary.to_string_lossy(), &full_args);
        command.stdout(log).stderr(log_err).stdin(Stdio::null());
        // New session so teardown can signal the whole process group.
        unsafe {
            command.pre_exec(|| {
                libc::setsid();
                Ok(())
            });
        }
        self.child = Some(
            command
                .spawn()
                .with_context(|| format!("spawn scheduler {}", self.binary.display()))?,
        );
        Ok(())
    }

    fn log_text(&self) -> String {
        read_lossy(&self.log_path)
    }

    /// Best-effort graceful then forceful teardown. Returns the final scx state.
    fn stop(&mut self, sudo: &Sudo) -> Option<String> {
        if let Some(child) = self.child.as_mut() {
            if matches!(child.try_wait(), Ok(None)) {
                // sudo forwards SIGINT to its child; this is the clean path.
                unsafe {
                    libc::kill(child.id() as i32, libc::SIGINT);
                }
                let deadline = Instant::now() + Duration::from_secs(8);
                loop {
                    match child.try_wait() {
                        Ok(Some(_)) | Err(_) => break,
                        Ok(None) => {
                            if Instant::now() >= deadline {
                                break;
                            }
                            sleep(Duration::from_millis(100));
                        }
                    }
                }
            }
        }
        // If still attached, escalate with sudo pkill on the binary basename
        // (our child is the sudo wrapper, so a plain kill is not enough to reach
        // a root-owned scheduler).
        let base = self
            .binary
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_default();
        for sig in ["-INT", "-KILL"] {
            if !matches!(scx_state().as_deref(), None | Some("disabled")) {
                let _ = sudo
                    .command("pkill", &[sig.into(), "-x".into(), base.clone()])
                    .status();
                let never_interrupted = AtomicBool::new(false);
                wait_for_state("disabled", Duration::from_secs(6), &never_interrupted);
            }
        }
        scx_state()
    }
}

/// Replace this process with the scheduler in the current terminal.
///
/// This is used only for `--keep-running`, after the final report has been
/// printed. It intentionally passes no scheduler flags, so the final handoff does
/// not force `--verbose` or periodic `--stats` output.
pub fn exec_scheduler_foreground(
    repo_root: &Path,
    package: &str,
    profile: &str,
    sudo: &Sudo,
) -> Result<()> {
    match scx_state() {
        None => {
            anyhow::bail!("{SCX_STATE_PATH} not found; kernel lacks sched_ext");
        }
        Some(s) if s != "disabled" => {
            anyhow::bail!("a scheduler is already attached (state={s:?})");
        }
        _ => {}
    }
    sudo.authenticate().context("sudo authentication failed")?;

    let sched_bin = binary_path(repo_root, package, profile);
    if !sched_bin.exists() {
        anyhow::bail!("scheduler binary not found at {}", sched_bin.display());
    }

    let sched_prog = sched_bin.to_string_lossy().into_owned();
    let args = Vec::new();
    let mut command = sudo.command(&sched_prog, &args);
    Err::<(), _>(command.exec()).with_context(|| format!("exec scheduler {}", sched_bin.display()))
}

/// One scheduler+workload run.
struct Measurement {
    value: Option<f64>,
    scheduler_stats: String,
    runtime_ok: bool,
    sched_trace: Option<Value>,
}

fn measure_once(
    spec: &Spec,
    sched_bin: &Path,
    workdir: &Path,
    run_idx: u64,
    sudo: &Sudo,
    errors: &mut Vec<String>,
    progress: Option<Style>,
    trace_enabled: bool,
    interrupted: &AtomicBool,
) -> Result<Measurement> {
    let log_path = workdir.join(format!("sched.run{run_idx}.log"));
    let mut sched = Scheduler::new(
        sched_bin.to_path_buf(),
        spec.scheduler.stats_interval,
        log_path,
    );

    sched.start(sudo)?;
    let warmup = spec.scheduler.warmup_time;
    let mut wl_out = String::new();
    let mut sched_trace = None;
    let attached = wait_for_state("enabled", Duration::from_secs(warmup + 6), interrupted);
    if attached {
        if !sleep_interruptible(Duration::from_secs(warmup), interrupted) {
            let duration = Duration::from_secs(spec.workload.duration);
            let cmd = spec
                .workload
                .command
                .as_deref()
                .context("[workload].command is required")?;
            let out_path = workdir.join(format!("wl.run{run_idx}.out"));
            let total_runs = spec.runs();
            let label = if total_runs > 1 {
                format!("running workload ({}/{total_runs})...", run_idx + 1)
            } else {
                "running workload...".to_string()
            };
            let trace_recorder = if trace_enabled {
                let trace_path = workdir.join(format!("trace.run{run_idx}.dat"));
                let trace_log_path = workdir.join(format!("trace.run{run_idx}.log"));
                let max_trace_bytes = spec.tracing.max_trace_bytes()?;
                match TraceRecorder::start(
                    sudo,
                    trace_path,
                    trace_log_path,
                    max_trace_bytes,
                    &spec.tracing.trace_events,
                ) {
                    Ok(recorder) => Some(recorder),
                    Err(e) => {
                        sched_trace = Some(json!({
                            "enabled": false,
                            "error": format!("{e:#}"),
                        }));
                        None
                    }
                }
            } else {
                None
            };
            let workload = run_capture(cmd, duration, &out_path, progress, label, interrupted);
            if let Some(recorder) = trace_recorder {
                sched_trace = Some(recorder.stop(sudo, &spec.tracing.trace_events));
            }
            wl_out = workload?;
        }
    } else {
        errors.push(format!(
            "run {run_idx}: scheduler did not attach; log tail:\n{}",
            tail(&sched.log_text(), 2000)
        ));
    }

    let runtime_ok = if attached {
        let post_workload_state = scx_state();
        if scx_is_enabled(post_workload_state.as_deref()) {
            true
        } else {
            errors.push(format!(
                "run {run_idx}: scheduler is no longer enabled after workload \
                 (scx state={:?}); treating candidate as a regression to avoid \
                 measuring the default scheduler; log tail:\n{}",
                post_workload_state,
                tail(&sched.log_text(), 2000)
            ));
            false
        }
    } else {
        true
    };

    let final_state = sched.stop(sudo);
    if !matches!(final_state.as_deref(), None | Some("disabled")) {
        errors.push(format!(
            "run {run_idx}: teardown failed, scx state={:?}",
            final_state
        ));
    }
    if !attached {
        return Ok(Measurement {
            value: None,
            scheduler_stats: sched.log_text(),
            runtime_ok,
            sched_trace,
        });
    }
    if !runtime_ok {
        return Ok(Measurement {
            value: None,
            scheduler_stats: sched.log_text(),
            runtime_ok,
            sched_trace,
        });
    }

    let val = extract_metric(&wl_out);
    if val.is_none() {
        errors.push(format!(
            "run {run_idx}: workload command output was not a plain number"
        ));
    }
    Ok(Measurement {
        value: val,
        scheduler_stats: sched.log_text(),
        runtime_ok,
        sched_trace,
    })
}

fn tail(s: &str, n: usize) -> String {
    if s.len() > n {
        s[s.len() - n..].to_string()
    } else {
        s.to_string()
    }
}

/// Build a non-complete verdict (build/preflight/attach/metric/spec stages).
#[allow(clippy::too_many_arguments)]
fn fail(
    stage: &str,
    spec: Option<&Spec>,
    errors: Vec<String>,
    extra: Vec<(&str, Value)>,
) -> Verdict {
    let (metric_name, goal, package) = match spec {
        Some(s) => (
            METRIC_NAME.to_string(),
            s.goal.direction.clone(),
            Some(s.scheduler.package.clone()),
        ),
        None => (METRIC_NAME.to_string(), "minimize".to_string(), None),
    };
    let mut raw = serde_json::Map::new();
    raw.insert("ok".into(), json!(false));
    raw.insert("stage".into(), json!(stage));
    if let Some(p) = &package {
        raw.insert("package".into(), json!(p));
    }
    raw.insert("errors".into(), json!(errors));
    for (k, v) in extra {
        raw.insert(k.into(), v);
    }
    Verdict {
        ok: false,
        stage: stage.to_string(),
        metric_name,
        goal,
        value: None,
        median: None,
        stddev: None,
        errors,
        raw: Value::Object(raw),
    }
}

/// Build the candidate, attach it, drive the workload, and return a verdict.
pub fn run_validation(
    repo_root: &Path,
    spec_path: &Path,
    sudo: &Sudo,
    verbose: bool,
    progress: Option<Style>,
    tracing_enabled: bool,
    interrupted: &AtomicBool,
) -> Result<Verdict> {
    let spec = match Spec::load(spec_path) {
        Ok(s) => s,
        Err(e) => return Ok(fail("spec", None, vec![format!("{e:#}")], vec![])),
    };

    if interrupt::requested(interrupted) {
        return Ok(fail(
            "interrupted",
            Some(&spec),
            vec!["interrupted by Ctrl-C".to_string()],
            vec![],
        ));
    }

    if spec.workload.command.is_none() {
        return Ok(fail(
            "spec",
            Some(&spec),
            vec![
                "[workload].command is required; it must run the workload and print one numeric \
                 metric value"
                    .to_string(),
            ],
            vec![],
        ));
    }

    let package = spec.scheduler.package.clone();
    let profile = spec.scheduler.profile.clone();

    // Stage 1: build (cheap correctness / verifier-source gate).
    if verbose {
        eprintln!(
            "  validate: {} build --profile {profile} -p {package}",
            cargo_program().to_string_lossy()
        );
    }
    let _spinner = progress.map(|style| {
        ProgressSpinner::stdout(
            format!("building scheduler {package} for validation..."),
            style,
        )
    });
    let (ok, build_out) = cargo_build(repo_root, &package, &profile, interrupted);
    drop(_spinner);
    if interrupt::requested(interrupted) {
        return Ok(fail(
            "interrupted",
            Some(&spec),
            vec!["interrupted by Ctrl-C".to_string()],
            vec![("stderr", json!(tail(&build_out, 4000)))],
        ));
    }
    if !ok {
        return Ok(fail(
            "build",
            Some(&spec),
            vec!["cargo build failed".to_string()],
            vec![("stderr", json!(tail(&build_out, 4000)))],
        ));
    }
    let sched_bin = binary_path(repo_root, &package, &profile);
    if !sched_bin.exists() {
        return Ok(fail(
            "build",
            Some(&spec),
            vec![format!("built binary not found at {}", sched_bin.display())],
            vec![],
        ));
    }

    // Stage 2: pre-flight. Require a sched_ext-capable kernel, nothing attached,
    // and working sudo.
    match scx_state() {
        None => {
            return Ok(fail(
                "preflight",
                Some(&spec),
                vec![format!(
                    "{SCX_STATE_PATH} not found; kernel lacks sched_ext"
                )],
                vec![],
            ));
        }
        Some(s) if s != "disabled" => {
            return Ok(fail(
                "preflight",
                Some(&spec),
                vec![format!("a scheduler is already attached (state={s:?})")],
                vec![],
            ));
        }
        _ => {}
    }
    if let Err(e) = sudo.authenticate() {
        return Ok(fail(
            "preflight",
            Some(&spec),
            vec![
                "sudo authentication failed; run as root, configure passwordless \
                 sudo, set [system].sudo_passwd_file in the spec, or point \
                 SCX_SUDO_PASSWORD_FILE at a file containing the sudo password"
                    .to_string(),
                tail(&format!("{e}"), 500),
            ],
            vec![],
        ));
    }

    let workdir = repo_root.join("target").join(format!("{package}_validate"));
    std::fs::create_dir_all(&workdir)
        .with_context(|| format!("create workdir {}", workdir.display()))?;

    let mut errors: Vec<String> = Vec::new();
    let mut runtime_failed = false;
    let trace_enabled = tracing_enabled && trace_cmd_available();
    if verbose && tracing_enabled && !trace_enabled {
        eprintln!("  validate: trace-cmd not available; sched tracing disabled");
    }

    // Measured runs (target scheduler attached). There is no no-scheduler
    // baseline: the objective is to improve the scheduler relative to its own
    // starting point, so running the workload under the default kernel scheduler
    // would just waste a run.
    let mut values: Vec<f64> = Vec::new();
    let mut last_stats = String::new();
    let mut trace_runs: Vec<Value> = Vec::new();
    for i in 0..spec.runs() {
        if interrupt::requested(interrupted) {
            break;
        }
        if verbose {
            eprintln!("  validate: run {}/{}", i + 1, spec.runs());
        }
        let measurement = measure_once(
            &spec,
            &sched_bin,
            &workdir,
            i,
            sudo,
            &mut errors,
            progress,
            trace_enabled,
            interrupted,
        )?;
        runtime_failed |= !measurement.runtime_ok;
        last_stats = measurement.scheduler_stats;
        if let Some(trace) = measurement.sched_trace {
            trace_runs.push(json!({
                "run": i,
                "summary": trace,
            }));
        }
        if let Some(v) = measurement.value {
            values.push(v);
        }
        if interrupt::requested(interrupted) {
            break;
        }
    }

    if interrupt::requested(interrupted) {
        return Ok(fail(
            "interrupted",
            Some(&spec),
            vec!["interrupted by Ctrl-C".to_string()],
            vec![
                ("scheduler_log_tail", json!(tail(&last_stats, 2000))),
                ("sched_trace", json!(trace_runs)),
            ],
        ));
    }

    if runtime_failed {
        return Ok(fail(
            "runtime",
            Some(&spec),
            errors,
            vec![
                ("scheduler_log_tail", json!(tail(&last_stats, 2000))),
                ("sched_trace", json!(trace_runs)),
            ],
        ));
    }
    if values.is_empty() && scx_state().as_deref() != Some("disabled") {
        return Ok(fail(
            "attach",
            Some(&spec),
            errors,
            vec![
                ("scheduler_log_tail", json!(tail(&last_stats, 2000))),
                ("sched_trace", json!(trace_runs)),
            ],
        ));
    }
    if values.is_empty() {
        let errs = if errors.is_empty() {
            vec!["no metric value extracted".to_string()]
        } else {
            errors
        };
        return Ok(fail(
            "metric",
            Some(&spec),
            errs,
            vec![
                ("scheduler_log_tail", json!(tail(&last_stats, 2000))),
                ("sched_trace", json!(trace_runs)),
            ],
        ));
    }

    let med = median(&values);
    let std = pstdev(&values);
    let raw = json!({
        "ok": true,
        "stage": "complete",
        "package": package,
        "metric": {"name": METRIC_NAME, "goal": spec.goal.direction, "value": med},
        "runs": values,
        "median": med,
        "stddev": std,
        "scheduler_log_tail": tail(&last_stats, 2000),
        "sched_trace": trace_runs,
        "errors": errors,
    });
    Ok(Verdict {
        ok: true,
        stage: "complete".to_string(),
        metric_name: METRIC_NAME.to_string(),
        goal: spec.goal.direction.clone(),
        value: Some(med),
        median: Some(med),
        stddev: Some(std),
        errors,
        raw,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_metric_parses_plain_number() {
        assert_eq!(extract_metric(" 42.5\n"), Some(42.5));
        assert_eq!(extract_metric(""), None);
        assert_eq!(extract_metric("value=42.5"), None);
        assert_eq!(extract_metric("42.5\n43.5"), None);
    }

    #[test]
    fn trace_stats_parse_sched_events() {
        let mut stats = TraceStats::default();
        update_trace_stats(
            &mut stats,
            "bash-10 [003] d..2. 1.000: sched_switch: prev_comm=bash prev_pid=10 prev_prio=120 prev_state=R ==> next_comm=schbench next_pid=11 next_prio=120",
        );
        update_trace_stats(
            &mut stats,
            "kworker-7 [001] d..2. 1.001: sched_wakeup: comm=schbench pid=11 prio=120 target_cpu=003",
        );
        update_trace_stats(
            &mut stats,
            "kworker-8 [002] d..2. 1.002: sched_wakeup_new: comm=worker pid=12 prio=120 target_cpu=004",
        );
        update_trace_stats(
            &mut stats,
            "bash-10 [003] d..2. 1.003: sched_migrate_task: comm=schbench pid=11 prio=120 orig_cpu=003 dest_cpu=005",
        );

        assert_eq!(stats.sched_switch, 1);
        assert_eq!(stats.sched_wakeup, 1);
        assert_eq!(stats.sched_wakeup_new, 1);
        assert_eq!(stats.sched_migrate_task, 1);
        assert_eq!(stats.switch_cpu.get("003"), Some(&1));
        assert_eq!(stats.next_comm.get("schbench"), Some(&1));
        assert_eq!(stats.prev_comm.get("bash"), Some(&1));
        assert_eq!(stats.prev_state.get("R"), Some(&1));
        assert_eq!(stats.wakeup_comm.get("schbench"), Some(&1));
        assert_eq!(stats.wakeup_target_cpu.get("003"), Some(&1));
        assert_eq!(stats.wakeup_new_comm.get("worker"), Some(&1));
        assert_eq!(stats.wakeup_new_target_cpu.get("004"), Some(&1));
        assert_eq!(stats.migrate_comm.get("schbench"), Some(&1));
        assert_eq!(stats.migrate_orig_cpu.get("003"), Some(&1));
        assert_eq!(stats.migrate_dest_cpu.get("005"), Some(&1));
        assert_eq!(stats.migrate_path.get("003->005"), Some(&1));
    }

    #[test]
    fn scx_is_enabled_only_accepts_enabled_state() {
        assert!(scx_is_enabled(Some("enabled")));
        assert!(!scx_is_enabled(Some("disabled")));
        assert!(!scx_is_enabled(Some("enabling")));
        assert!(!scx_is_enabled(None));
    }

    #[test]
    fn median_odd_even() {
        assert_eq!(median(&[3.0, 1.0, 2.0]), 2.0);
        assert_eq!(median(&[1.0, 2.0, 3.0, 4.0]), 2.5);
    }

    #[test]
    fn pstdev_matches_population() {
        // pstdev([1,2,3,4,5]) == sqrt(2) == 1.4142...
        let s = pstdev(&[1.0, 2.0, 3.0, 4.0, 5.0]);
        assert!((s - 1.414_213_562).abs() < 1e-6);
        assert_eq!(pstdev(&[42.0]), 0.0);
    }

    #[test]
    fn binary_path_profiles() {
        let r = Path::new("/repo");
        assert_eq!(
            binary_path(r, "scx_forge", "release"),
            Path::new("/repo/target/release/scx_forge")
        );
        assert_eq!(
            binary_path(r, "scx_forge", "dev"),
            Path::new("/repo/target/debug/scx_forge")
        );
        assert_eq!(
            binary_path(r, "scx_forge", "bench"),
            Path::new("/repo/target/bench/scx_forge")
        );
    }
}
