use std::fs::{self, File};
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{bail, Result};
use clap::ValueEnum;

use super::child_guard::ChildGuard;
use super::report::{format_delta, format_latency_delta, mean_stdev, percentile, save_report};
use super::{binary_path, is_scx_active, self_exe, wait_for_activation, LOG_DIR, TARGET_DIR};

#[derive(Clone, ValueEnum)]
pub enum BenchMode {
    /// A/B using own compilation as workload
    #[value(name = "self")]
    SelfBuild,
    /// Compile + interactive probe (wakeup latency)
    Contention,
    /// Compile + audio playback (xruns)
    Mixed,
    /// A/B with user-provided command
    Cmd,
}

// BUILD RELEASE BINARY AND RUN BENCH, SAVING LOGS
pub fn run_bench_run(
    mode: BenchMode,
    cmd: Option<&str>,
    iterations: usize,
    clean_cmd: Option<&str>,
    sched_args: &[String],
) -> Result<()> {
    fs::create_dir_all(LOG_DIR)?;

    let build_out = File::create(format!("{}/build.out", LOG_DIR))?;
    let build_err = File::create(format!("{}/build.err", LOG_DIR))?;
    let status = Command::new("cargo")
        .args(["build", "--release"])
        .env("CARGO_TARGET_DIR", TARGET_DIR)
        .stdout(Stdio::from(build_out))
        .stderr(Stdio::from(build_err))
        .status()?;
    if !status.success() {
        bail!("BUILD FAILED. SEE {}/build.err", LOG_DIR);
    }

    let extra_args: Vec<String> = sched_args.to_vec();

    let bench_out = File::create(format!("{}/bench.out", LOG_DIR))?;
    let bench_err = File::create(format!("{}/bench.err", LOG_DIR))?;
    let mut bench_cmd = Command::new(binary_path());
    let mode_name = mode
        .to_possible_value()
        .ok_or_else(|| anyhow::anyhow!("INVALID BENCH MODE"))?
        .get_name()
        .to_string();
    bench_cmd
        .arg("bench")
        .arg("--mode")
        .arg(mode_name)
        .arg("--iterations")
        .arg(iterations.to_string());
    if let Some(c) = cmd {
        bench_cmd.arg("--cmd").arg(c);
    }
    if let Some(cc) = clean_cmd {
        bench_cmd.arg("--clean-cmd").arg(cc);
    }
    if !extra_args.is_empty() {
        bench_cmd.arg("--").args(extra_args);
    }

    let status = bench_cmd
        .stdout(Stdio::from(bench_out))
        .stderr(Stdio::from(bench_err))
        .status()?;
    if !status.success() {
        bail!("BENCH FAILED. SEE {}/bench.err", LOG_DIR);
    }

    log_info!("Build logs: {}/build.out {}/build.err", LOG_DIR, LOG_DIR);
    log_info!("Bench logs: {}/bench.out {}/bench.err", LOG_DIR, LOG_DIR);
    Ok(())
}

fn timed_run(cmd: &str) -> Option<f64> {
    log_info!("Running: {}", cmd);
    let start = Instant::now();
    let result = Command::new("sh")
        .args(["-c", cmd])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output();
    let elapsed = start.elapsed().as_secs_f64();
    match result {
        Ok(r) if r.status.success() => {
            log_info!("Completed in {:.2}s", elapsed);
            Some(elapsed)
        }
        Ok(r) => {
            let stderr = String::from_utf8_lossy(&r.stderr);
            log_error!(
                "Command failed (exit {}): {}",
                r.status.code().unwrap_or(-1),
                &stderr[..stderr.len().min(500)]
            );
            None
        }
        Err(e) => {
            log_error!("Command failed: {}", e);
            None
        }
    }
}

fn start_scheduler(sched_args: &[String]) -> Result<ChildGuard> {
    let bin = binary_path();
    let mut args = Vec::new();
    args.extend(sched_args.iter().cloned());

    let child = Command::new("sudo")
        .arg(&bin)
        .args(&args)
        .process_group(0)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    Ok(ChildGuard::new(child))
}

fn stop_scheduler(guard: &mut ChildGuard) {
    guard.stop();
}

fn ensure_scheduler_started(sched_args: &[String]) -> Result<ChildGuard> {
    let guard = start_scheduler(sched_args)?;
    if !wait_for_activation(10) {
        bail!("PANDEMONIUM DID NOT ACTIVATE WITHIN 10S");
    }
    log_info!("PANDEMONIUM is active");
    std::thread::sleep(Duration::from_secs(2));
    Ok(guard)
}

pub fn run_bench(
    mode: BenchMode,
    cmd: Option<&str>,
    iterations: usize,
    clean_cmd: Option<&str>,
    sched_args: &[String],
) -> Result<()> {
    match mode {
        BenchMode::SelfBuild => bench_general(
            &format!("CARGO_TARGET_DIR={} cargo build --release", TARGET_DIR),
            iterations,
            Some(&format!("cargo clean --target-dir {}", TARGET_DIR)),
            sched_args,
        ),
        BenchMode::Cmd => {
            let cmd = cmd.ok_or_else(|| anyhow::anyhow!("--cmd required for --mode cmd"))?;
            bench_general(cmd, iterations, clean_cmd, sched_args)
        }
        BenchMode::Mixed => bench_mixed(sched_args),
        BenchMode::Contention => bench_contention(sched_args),
    }
}

// A/B BENCHMARK: EEVDF VS PANDEMONIUM (GENERIC)
fn bench_general(
    cmd: &str,
    iterations: usize,
    clean_cmd: Option<&str>,
    sched_args: &[String],
) -> Result<()> {
    let sep = "=".repeat(60);
    log_info!("PANDEMONIUM A/B benchmark");
    log_info!("Command: {}", cmd);
    log_info!("Iterations: {}", iterations);
    if let Some(cc) = clean_cmd {
        log_info!("Clean cmd: {}", cc);
    }

    if is_scx_active() {
        bail!("SCHED_EXT IS ALREADY ACTIVE. STOP IT BEFORE BENCHMARKING.");
    }

    // PHASE 1: EEVDF BASELINE
    log_info!("Phase 1: EEVDF baseline");
    let mut eevdf_times = Vec::new();
    for i in 0..iterations {
        log_info!("Iteration {}/{}", i + 1, iterations);
        if let Some(cc) = clean_cmd {
            let _ = Command::new("sh")
                .args(["-c", cc])
                .output();
        }
        match timed_run(cmd) {
            Some(t) => eevdf_times.push(t),
            None => bail!("ABORTING BENCHMARK: COMMAND FAILED"),
        }
    }

    // PHASE 2: START PANDEMONIUM
    log_info!("Phase 2: starting PANDEMONIUM");
    let mut pand_proc = ensure_scheduler_started(sched_args)?;

    // PHASE 3: PANDEMONIUM BENCHMARK
    log_info!("Phase 3: PANDEMONIUM benchmark");
    let mut pand_times = Vec::new();
    for i in 0..iterations {
        log_info!("Iteration {}/{}", i + 1, iterations);
        if let Some(cc) = clean_cmd {
            let _ = Command::new("sh")
                .args(["-c", cc])
                .output();
        }
        match timed_run(cmd) {
            Some(t) => pand_times.push(t),
            None => {
                stop_scheduler(&mut pand_proc);
                bail!("ABORTING BENCHMARK: COMMAND FAILED");
            }
        }
    }

    // PHASE 4: STOP
    log_info!("Phase 4: stopping PANDEMONIUM");
    stop_scheduler(&mut pand_proc);
    log_info!("PANDEMONIUM stopped");

    // RESULTS
    let (eevdf_mean, eevdf_std) = mean_stdev(&eevdf_times);
    let (pand_mean, pand_std) = mean_stdev(&pand_times);
    let delta_pct = if eevdf_mean > 0.0 {
        ((pand_mean - eevdf_mean) / eevdf_mean) * 100.0
    } else {
        0.0
    };

    let mut report = Vec::new();
    report.push(sep.clone());
    report.push("BENCHMARK RESULTS".to_string());
    report.push(sep.clone());
    report.push(format!("COMMAND: {}", cmd));
    report.push(format!("ITERATIONS: {}", iterations));
    report.push(String::new());
    report.push(format!(
        "EEVDF:       {:.2}s +/- {:.2}s",
        eevdf_mean, eevdf_std
    ));
    report.push(format!(
        "  RUNS: {}",
        eevdf_times
            .iter()
            .map(|t| format!("{:.2}s", t))
            .collect::<Vec<_>>()
            .join(", ")
    ));
    report.push(format!(
        "PANDEMONIUM: {:.2}s +/- {:.2}s",
        pand_mean, pand_std
    ));
    report.push(format!(
        "  RUNS: {}",
        pand_times
            .iter()
            .map(|t| format!("{:.2}s", t))
            .collect::<Vec<_>>()
            .join(", ")
    ));
    report.push(String::new());
    report.push(format_delta(delta_pct, "BUILD"));
    report.push(sep.clone());

    let report_text = report.join("\n") + "\n";
    for line in &report {
        println!("{}", line);
    }

    let path = save_report(&report_text, "benchmark")?;
    println!("\nSAVED TO {}", path);
    Ok(())
}

// PW-TOP SNAPSHOT: CAPTURE PIPEWIRE XRUN COUNTS
fn pw_top_snapshot() -> Vec<(String, i64)> {
    let mut child = match Command::new("pw-top")
        .arg("-b")
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };

    std::thread::sleep(Duration::from_millis(1500));
    let _ = child.kill();
    let output = match child.wait_with_output() {
        Ok(o) => o,
        Err(_) => return Vec::new(),
    };

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut entries = Vec::new();
    for line in stdout.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with("S ") {
            continue;
        }
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 10 {
            continue;
        }
        if !matches!(parts[0], "R" | "S" | "C") {
            continue;
        }
        if let Ok(err) = parts[8].parse::<i64>() {
            let name = parts[9..].join(" ").trim_start_matches(['+', ' ']).to_string();
            entries.push((name, err));
        }
    }
    entries
}

fn pw_audio_playing() -> bool {
    Command::new("pactl")
        .args(["list", "sink-inputs", "short"])
        .output()
        .map(|o| o.status.success() && !o.stdout.is_empty())
        .unwrap_or(false)
}

fn pw_get_xruns() -> i64 {
    pw_top_snapshot().iter().map(|(_, err)| err).sum()
}

// MIXED BENCHMARK: COMPILE + AUDIO
fn bench_mixed(sched_args: &[String]) -> Result<()> {
    let sep = "=".repeat(60);
    log_info!("PANDEMONIUM mixed workload benchmark");

    if !pw_audio_playing() {
        bail!("NO AUDIO PLAYING. START AUDIO PLAYBACK FIRST.");
    }

    let entries = pw_top_snapshot();
    log_info!("Active PipeWire nodes:");
    for (name, err) in &entries {
        log_info!("  {} (xruns: {})", name, err);
    }

    if is_scx_active() {
        bail!("SCHED_EXT IS ALREADY ACTIVE. STOP IT BEFORE BENCHMARKING.");
    }

    let build_cmd = format!("CARGO_TARGET_DIR={} cargo build --release", TARGET_DIR);
    let clean_cmd = format!("cargo clean --target-dir {}", TARGET_DIR);

    let sched_args = sched_args.to_vec();

    // PHASE 1: EEVDF
    log_info!("Phase 1: EEVDF (default scheduler)");
    let _ = Command::new("sh").args(["-c", &clean_cmd]).output();
    let xruns_before = pw_get_xruns();
    log_info!("Xruns before: {}", xruns_before);
    let eevdf_time = timed_run(&build_cmd).ok_or_else(|| anyhow::anyhow!("BUILD FAILED"))?;
    let xruns_after = pw_get_xruns();
    let eevdf_xruns = xruns_after - xruns_before;
    log_info!("Xruns after: {} (delta: {})", xruns_after, eevdf_xruns);

    // PHASE 2: START PANDEMONIUM
    log_info!("Phase 2: starting PANDEMONIUM");
    let mut pand_proc = ensure_scheduler_started(&sched_args)?;

    // PHASE 3: PANDEMONIUM
    log_info!("Phase 3: PANDEMONIUM");
    let _ = Command::new("sh").args(["-c", &clean_cmd]).output();
    let xruns_before = pw_get_xruns();
    log_info!("Xruns before: {}", xruns_before);
    let pand_time = match timed_run(&build_cmd) {
        Some(t) => t,
        None => {
            stop_scheduler(&mut pand_proc);
            bail!("BUILD FAILED");
        }
    };
    let xruns_after = pw_get_xruns();
    let pand_xruns = xruns_after - xruns_before;
    log_info!("Xruns after: {} (delta: {})", xruns_after, pand_xruns);

    // PHASE 4: STOP
    log_info!("Phase 4: stopping PANDEMONIUM");
    stop_scheduler(&mut pand_proc);
    log_info!("PANDEMONIUM stopped");

    // RESULTS
    let delta_pct = if eevdf_time > 0.0 {
        ((pand_time - eevdf_time) / eevdf_time) * 100.0
    } else {
        0.0
    };
    let xrun_delta = pand_xruns - eevdf_xruns;

    let mut report = Vec::new();
    report.push(sep.clone());
    report.push("MIXED WORKLOAD BENCHMARK RESULTS".to_string());
    report.push(sep.clone());
    report.push("WORKLOAD: CARGO BUILD --RELEASE + AUDIO PLAYBACK".to_string());
    report.push(String::new());
    report.push(format!(
        "{:<16} {:>12} {:>12}",
        "SCHEDULER", "BUILD TIME", "AUDIO XRUNS"
    ));
    report.push(format!("{} {} {}", "-".repeat(16), "-".repeat(12), "-".repeat(12)));
    report.push(format!(
        "{:<16} {:>11.2}s {:>12}",
        "EEVDF", eevdf_time, eevdf_xruns
    ));
    report.push(format!(
        "{:<16} {:>11.2}s {:>12}",
        "PANDEMONIUM", pand_time, pand_xruns
    ));
    report.push(String::new());
    report.push(format_delta(delta_pct, "BUILD"));
    if xrun_delta < 0 {
        report.push(format!(
            "XRUN DELTA:  {:+} (PANDEMONIUM HAS FEWER AUDIO GLITCHES)",
            xrun_delta
        ));
    } else if xrun_delta > 0 {
        report.push(format!(
            "XRUN DELTA:  {:+} (PANDEMONIUM HAS MORE AUDIO GLITCHES)",
            xrun_delta
        ));
    } else {
        report.push("XRUN DELTA:  0 (SAME AUDIO QUALITY)".to_string());
    }
    report.push(sep.clone());

    let report_text = report.join("\n") + "\n";
    for line in &report {
        println!("{}", line);
    }

    let path = save_report(&report_text, "mixed")?;
    println!("\nSAVED TO {}", path);
    Ok(())
}

// CONTENTION BENCHMARK: COMPILE + INTERACTIVE PROBE
fn bench_contention(sched_args: &[String]) -> Result<()> {
    let sep = "=".repeat(60);
    log_info!("PANDEMONIUM contention benchmark");
    log_info!("Workload: cargo build --release + interactive probe (10ms sleep/wake)");

    if is_scx_active() {
        bail!("SCHED_EXT IS ALREADY ACTIVE. STOP IT BEFORE BENCHMARKING.");
    }

    let build_cmd = format!("CARGO_TARGET_DIR={} cargo build --release", TARGET_DIR);
    let clean_cmd = format!("cargo clean --target-dir {}", TARGET_DIR);

    // COPY SELF TO SAFE LOCATION -- cargo clean DELETES THE TARGET DIR
    // WHICH CONTAINS THE VERY BINARY WE'RE RUNNING FROM
    std::fs::create_dir_all(super::LOG_DIR)?;
    let probe_exe = format!("{}/probe", super::LOG_DIR);
    std::fs::copy(self_exe(), &probe_exe)?;

    let sched_args = sched_args.to_vec();

    struct PhaseResult {
        name: String,
        build_time: f64,
        samples: usize,
        median: f64,
        p99: f64,
        worst: f64,
    }

    let phases: Vec<(&str, bool)> = vec![
        ("EEVDF (DEFAULT)", false),
        ("PANDEMONIUM", true),
    ];

    let mut results = Vec::new();

    for (phase_name, use_scheduler) in &phases {
        log_info!("Phase: {}", phase_name);

        let mut pand_proc = if *use_scheduler {
            Some(ensure_scheduler_started(&sched_args)?)
        } else {
            None
        };

        // CLEAN BUILD
        let _ = Command::new("sh").args(["-c", &clean_cmd]).output();

        // START PROBE WITH DEATH PIPE + PROCESS GROUP
        let (death_read, death_write) = super::death_pipe::create_death_pipe()
            .map_err(|e| anyhow::anyhow!("DEATH PIPE: {}", e))?;
        let death_write_copy = death_write;
        let probe_proc = unsafe {
            Command::new(&probe_exe)
                .arg("probe")
                .arg("--death-pipe-fd")
                .arg(death_read.to_string())
                .process_group(0)
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .pre_exec(move || {
                    libc::close(death_write_copy);
                    libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM as libc::c_ulong);
                    Ok(())
                })
                .spawn()?
        };
        super::death_pipe::close_fd(death_read);
        let probe_guard = ChildGuard::new(probe_proc);

        // RUN BUILD
        log_info!("Building...");
        let build_start = Instant::now();
        let build_result = Command::new("sh")
            .args(["-c", &build_cmd])
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .output()?;
        let build_time = build_start.elapsed().as_secs_f64();

        if !build_result.status.success() {
            log_error!(
                "Build failed (exit {})",
                build_result.status.code().unwrap_or(-1)
            );
            drop(probe_guard);
            super::death_pipe::close_fd(death_write);
            if let Some(ref mut p) = pand_proc {
                stop_scheduler(p);
            }
            bail!("BUILD FAILED");
        }

        // LET PROBE SETTLE
        std::thread::sleep(Duration::from_secs(1));

        // STOP PROBE AND COLLECT OUTPUT
        unsafe {
            libc::killpg(probe_guard.id() as i32, libc::SIGTERM);
        }
        let probe_child = probe_guard.into_child();
        let probe_output = probe_child.wait_with_output()?;
        super::death_pipe::close_fd(death_write);
        let probe_stdout = String::from_utf8_lossy(&probe_output.stdout);

        // STOP SCHEDULER IF RUNNING
        if let Some(ref mut p) = pand_proc {
            stop_scheduler(p);
            log_info!("PANDEMONIUM stopped");
        }

        // PARSE PROBE OUTPUT
        let mut overshoots: Vec<f64> = probe_stdout
            .lines()
            .filter_map(|line| line.trim().parse::<f64>().ok())
            .collect();
        overshoots.sort_by(|a, b| a.partial_cmp(b).unwrap());

        let n = overshoots.len();
        let med = percentile(&overshoots, 50.0);
        let p99 = percentile(&overshoots, 99.0);
        let worst = overshoots.last().copied().unwrap_or(0.0);

        log_info!("Build time: {:.2}s", build_time);
        log_info!("Probe samples: {}", n);
        log_info!("Median overshoot: {:.0}us", med);
        log_info!("P99 overshoot: {:.0}us", p99);
        log_info!("Worst overshoot: {:.0}us", worst);

        results.push(PhaseResult {
            name: phase_name.to_string(),
            build_time,
            samples: n,
            median: med,
            p99,
            worst,
        });
    }

    // REPORT
    let eevdf = &results[0];
    let pand = &results[1];

    let build_delta = if eevdf.build_time > 0.0 {
        ((pand.build_time - eevdf.build_time) / eevdf.build_time) * 100.0
    } else {
        0.0
    };
    let med_delta = pand.median - eevdf.median;
    let p99_delta = pand.p99 - eevdf.p99;

    let mut report = Vec::new();
    report.push(sep.clone());
    report.push("CONTENTION BENCHMARK RESULTS".to_string());
    report.push(sep.clone());
    report.push(
        "WORKLOAD: CARGO BUILD --RELEASE + INTERACTIVE PROBE (10MS SLEEP/WAKE)".to_string(),
    );
    report.push(String::new());
    report.push(format!(
        "{:<24} {:>8} {:>8} {:>8} {:>8} {:>8}",
        "SCHEDULER", "BUILD", "SAMPLES", "MEDIAN", "P99", "WORST"
    ));
    report.push(format!(
        "{} {} {} {} {} {}",
        "-".repeat(24),
        "-".repeat(8),
        "-".repeat(8),
        "-".repeat(8),
        "-".repeat(8),
        "-".repeat(8),
    ));
    for r in &results {
        report.push(format!(
            "{:<24} {:>7.2}s {:>8} {:>7.0}us {:>7.0}us {:>7.0}us",
            r.name, r.build_time, r.samples, r.median, r.p99, r.worst,
        ));
    }
    report.push(String::new());
    report.push(format_delta(build_delta, "BUILD"));
    report.push(format_latency_delta(med_delta, "MEDIAN"));
    report.push(format_latency_delta(p99_delta, "P99"));
    report.push(sep.clone());

    let report_text = report.join("\n") + "\n";
    for line in &report {
        println!("{}", line);
    }

    let path = save_report(&report_text, "contention")?;
    println!("\nSAVED TO {}", path);
    Ok(())
}
