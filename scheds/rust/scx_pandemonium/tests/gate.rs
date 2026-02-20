// PANDEMONIUM TEST GATE
// INTEGRATION TESTS FOR THE SCHED_EXT SCHEDULER
//
// LAYERS 2-4 REQUIRE ROOT AND A COMPATIBLE KERNEL.
// RUN: sudo cargo test --test gate --release -- --ignored --test-threads=1
//
// LAYER 2: LOAD, CLASSIFY, UNLOAD (BPF END-TO-END)
// LAYER 3: LATENCY GATE (CYCLICTEST)
// LAYER 4: INTERACTIVE RESPONSIVENESS (WAKEUP LATENCY)

use std::fs;
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use regex::Regex;

const LOG_DIR: &str = "/tmp/pandemonium";
const ACTIVATION_TIMEOUT: Duration = Duration::from_secs(10);
const ACTIVATION_POLL: Duration = Duration::from_millis(500);

// HELPERS

fn binary_path() -> String {
    let target_dir =
        std::env::var("CARGO_TARGET_DIR").unwrap_or_else(|_| "/tmp/pandemonium-build".to_string());
    format!("{}/release/pandemonium", target_dir)
}

fn is_scx_active() -> bool {
    fs::read_to_string("/sys/kernel/sched_ext/root/ops")
        .map(|s| !s.trim().is_empty())
        .unwrap_or(false)
}

fn wait_for_activation() -> bool {
    let deadline = Instant::now() + ACTIVATION_TIMEOUT;
    while Instant::now() < deadline {
        if is_scx_active() {
            return true;
        }
        thread::sleep(ACTIVATION_POLL);
    }
    false
}

fn wait_for_deactivation() -> bool {
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if !is_scx_active() {
            return true;
        }
        thread::sleep(Duration::from_millis(200));
    }
    false
}

/// Start pandemonium with optional extra args, return the child process.
/// Caller is responsible for stopping it.
fn start_pandemonium(extra_args: &[&str]) -> std::process::Child {
    let bin = binary_path();
    assert!(
        std::path::Path::new(&bin).exists(),
        "BINARY NOT FOUND AT {}. BUILD FIRST.",
        bin
    );
    assert!(!is_scx_active(), "SCHED_EXT ALREADY ACTIVE");

    Command::new(&bin)
        .args(extra_args)
        .process_group(0)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("FAILED TO START PANDEMONIUM")
}

/// Send SIGINT and wait for exit. Returns captured stdout.
fn stop_pandemonium(child: &mut std::process::Child) -> String {
    let pgid = child.id() as i32;
    unsafe {
        libc::killpg(pgid, libc::SIGINT);
    }

    // DRAIN STDOUT BEFORE WAITING
    let stdout = child.stdout.take();
    let output = if let Some(pipe) = stdout {
        std::io::read_to_string(pipe).unwrap_or_default()
    } else {
        String::new()
    };

    match child.wait() {
        Ok(_) => {}
        Err(_) => {
            child.kill().ok();
            child.wait().ok();
        }
    }

    // WAIT FOR KERNEL TO FULLY UNLOAD
    wait_for_deactivation();
    output
}

fn which(name: &str) -> bool {
    Command::new("which")
        .arg(name)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn save_report(stamp: &str, results: &[(String, Option<bool>, String)], verdict: &str) {
    fs::create_dir_all(LOG_DIR).ok();
    let path = format!("{}/test-{}.log", LOG_DIR, stamp);
    let mut lines = Vec::new();
    lines.push(format!("PANDEMONIUM TEST GATE -- {}", stamp));
    lines.push("=".repeat(60));
    for (label, passed, detail) in results {
        let status = match passed {
            Some(true) => "PASS",
            Some(false) => "FAIL",
            None => "SKIP",
        };
        if detail.is_empty() {
            lines.push(format!("{}: {}", label, status));
        } else {
            lines.push(format!("{}: {} ({})", label, status, detail));
        }
    }
    lines.push("=".repeat(60));
    lines.push(format!("VERDICT: {}", verdict));
    lines.push(String::new());
    fs::write(&path, lines.join("\n")).ok();
    eprintln!("REPORT: {}", path);
}

fn timestamp() -> String {
    // SIMPLE TIMESTAMP WITHOUT CHRONO
    let dur = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = dur.as_secs();
    // APPROXIMATE: GOOD ENOUGH FOR LOG FILENAMES
    let days = secs / 86400;
    let y = 1970 + (days * 400 / 146097); // ROUGH YEAR
    format!("{}-{:06}", y, secs % 1_000_000)
}

// LAYER 2: INTEGRATION (LOAD/CLASSIFY/UNLOAD)

#[test]
#[ignore]
fn layer2_load_classify_unload() {
    let bin = binary_path();
    assert!(std::path::Path::new(&bin).exists(), "BINARY NOT FOUND");
    assert!(!is_scx_active(), "SCHED_EXT ALREADY ACTIVE");

    // START PANDEMONIUM WITH BUILD_MODE TO TEST classify_weight()
    let mut child = start_pandemonium(&["--build-mode"]);
    assert!(wait_for_activation(), "DID NOT ACTIVATE WITHIN 10S");

    // COLLECT BASELINE STATS
    thread::sleep(Duration::from_secs(2));

    // COMPILE REAL CODE -- TESTS BPF classify_weight()
    // SCALE WORKLOAD BY CORE COUNT TO ACTUALLY STRESS THE SCHEDULER
    // WRITE TO LOG_DIR (NOT /tmp DIRECTLY) TO AVOID fs.protected_regular=2 BLOCKING
    fs::create_dir_all(LOG_DIR).ok();
    let test_src = format!("{}/test_workload.c", LOG_DIR);
    fs::write(&test_src, "int main() { return 0; }\n").unwrap();
    let ncpu = thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);
    let iterations = std::cmp::max(5, ncpu * 2);
    for _ in 0..iterations {
        Command::new("gcc")
            .args(["-o", "/dev/null", &test_src])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .ok();
    }

    // LET STATS FLUSH (1-SECOND MONITORING CYCLE)
    thread::sleep(Duration::from_secs(2));

    // STOP AND CAPTURE OUTPUT
    let output = stop_pandemonium(&mut child);

    // VERIFY DISPATCHES
    let dispatch_re = Regex::new(r"dispatches/s:\s+[1-9]").unwrap();
    assert!(
        dispatch_re.is_match(&output),
        "NO DISPATCHES RECORDED.\nOUTPUT:\n{}",
        &output[..output.len().min(2000)]
    );

    // VERIFY BPF CLASSIFICATION: BOOSTED > 0
    let boosted_re = Regex::new(r"boosted:\s+(\d+)").unwrap();
    let has_boost = boosted_re
        .captures_iter(&output)
        .any(|cap| cap[1].parse::<u64>().unwrap_or(0) > 0);
    assert!(
        has_boost,
        "BPF CLASSIFICATION FAILED (boosted=0 AFTER gcc)\nOUTPUT:\n{}",
        &output[..output.len().min(2000)]
    );

    // VERIFY UNLOADED
    assert!(!is_scx_active(), "SCHED_EXT STILL ACTIVE AFTER STOP");
}

// LAYER 3: LATENCY GATE (CYCLICTEST)

#[test]
#[ignore]
fn layer3_latency_gate() {
    if !which("cyclictest") {
        eprintln!("LAYER 3: SKIP (cyclictest not installed)");
        return;
    }

    assert!(!is_scx_active(), "SCHED_EXT ALREADY ACTIVE");

    let mut child = start_pandemonium(&[]);
    assert!(wait_for_activation(), "DID NOT ACTIVATE WITHIN 10S");

    // WARMUP: LET SCHEDULER STABILIZE (EWMA COLD-START, TASK MIGRATION)
    thread::sleep(Duration::from_secs(2));

    // RUN CYCLICTEST (10 SECONDS, ALL CPUS)
    let ncpu = thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);

    let ct = Command::new("cyclictest")
        .args(["-D", "10", "-q", "-m", &format!("-t{}", ncpu)])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output();

    let output = stop_pandemonium(&mut child);
    let _ = output; // SCHEDULER OUTPUT NOT NEEDED FOR THIS LAYER

    let ct_output = ct.expect("FAILED TO RUN CYCLICTEST");
    let ct_stdout = String::from_utf8_lossy(&ct_output.stdout);

    // PARSE AVG AND MAX LATENCIES
    let avg_re = Regex::new(r"Avg:\s+(\d+)").unwrap();
    let max_re = Regex::new(r"Max:\s+(\d+)").unwrap();

    let avg_vals: Vec<u64> = avg_re
        .captures_iter(&ct_stdout)
        .filter_map(|cap| cap[1].parse().ok())
        .collect();
    let max_vals: Vec<u64> = max_re
        .captures_iter(&ct_stdout)
        .filter_map(|cap| cap[1].parse().ok())
        .collect();

    assert!(!avg_vals.is_empty(), "COULD NOT PARSE CYCLICTEST OUTPUT");

    let worst_avg = *avg_vals.iter().max().unwrap();
    let worst_max = *max_vals.iter().max().unwrap_or(&0);

    eprintln!(
        "LAYER 3: LATENCY (worst_avg={}us worst_max={}us)",
        worst_avg, worst_max
    );

    // GATE ON AVERAGE LATENCY (STABLE METRIC)
    // MAX IS REPORTED BUT NOT GATED -- SINGLE OUTLIERS ARE NORMAL ON NON-RT KERNELS
    // THRESHOLD SCALES WITH CORE COUNT:
    //   2 CORES: 1000us  (FULL SATURATION, HIGH CONTENTION)
    //   4 CORES:  750us
    //   8 CORES:  625us
    //  16 CORES:  563us
    let avg_limit = 500 + (500 * 2 / ncpu as u64);
    assert!(
        worst_avg <= avg_limit,
        "AVG LATENCY TOO HIGH: {}us (LIMIT: {}us, {} CORES)",
        worst_avg,
        avg_limit,
        ncpu
    );
}

// LAYER 4: INTERACTIVE RESPONSIVENESS (WAKEUP LATENCY)

#[test]
#[ignore]
fn layer4_interactive_responsiveness() {
    assert!(!is_scx_active(), "SCHED_EXT ALREADY ACTIVE");

    let mut child = start_pandemonium(&[]);
    assert!(wait_for_activation(), "DID NOT ACTIVATE WITHIN 10S");

    // MEASURE WAKEUP LATENCY (1000 x 10MS SLEEP)
    let target = Duration::from_millis(10);
    let mut overshoots_us: Vec<f64> = Vec::with_capacity(1000);

    for _ in 0..1000 {
        let t0 = Instant::now();
        thread::sleep(target);
        let elapsed = t0.elapsed();
        let overshoot = elapsed.saturating_sub(target);
        overshoots_us.push(overshoot.as_nanos() as f64 / 1000.0);
    }

    let output = stop_pandemonium(&mut child);
    let _ = output;

    // COMPUTE STATS
    overshoots_us.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let median = overshoots_us[overshoots_us.len() / 2];
    let p99 = overshoots_us[(overshoots_us.len() as f64 * 0.99) as usize];

    eprintln!(
        "LAYER 4: INTERACTIVE (med={:.0}us p99={:.0}us)",
        median, p99
    );

    assert!(
        median <= 500.0,
        "MEDIAN OVERSHOOT TOO HIGH: {:.0}us (LIMIT: 500us)",
        median
    );
}

// LAYER 5: CONTENTION LATENCY (INTERACTIVE UNDER BATCH PRESSURE)

#[test]
#[ignore]
fn layer5_contention_latency() {
    assert!(!is_scx_active(), "SCHED_EXT ALREADY ACTIVE");

    let mut child = start_pandemonium(&[]);
    assert!(wait_for_activation(), "DID NOT ACTIVATE WITHIN 10S");

    // WARMUP
    thread::sleep(Duration::from_secs(2));

    // SPAWN CPU STRESS: ncpu BUSY-SPIN THREADS
    let ncpu = thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);

    let stress_running = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
    let mut stress_threads = Vec::new();
    for _ in 0..ncpu {
        let flag = stress_running.clone();
        stress_threads.push(thread::spawn(move || {
            while flag.load(std::sync::atomic::Ordering::Relaxed) {
                std::hint::spin_loop();
            }
        }));
    }

    // INTERACTIVE PROBE: 500 x 10MS SLEEP/WAKE
    let target = Duration::from_millis(10);
    let mut overshoots_us: Vec<f64> = Vec::with_capacity(500);

    for _ in 0..500 {
        let t0 = Instant::now();
        thread::sleep(target);
        let elapsed = t0.elapsed();
        let overshoot = elapsed.saturating_sub(target);
        overshoots_us.push(overshoot.as_nanos() as f64 / 1000.0);
    }

    // STOP STRESS
    stress_running.store(false, std::sync::atomic::Ordering::Relaxed);
    for t in stress_threads {
        t.join().ok();
    }

    let output = stop_pandemonium(&mut child);
    let _ = output;

    // COMPUTE STATS
    overshoots_us.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let median = overshoots_us[overshoots_us.len() / 2];
    let p99 = overshoots_us[(overshoots_us.len() as f64 * 0.99) as usize];

    eprintln!(
        "LAYER 5: CONTENTION (med={:.0}us p99={:.0}us, {} stress threads)",
        median, p99, ncpu
    );

    // THRESHOLDS SCALE WITH CORE COUNT
    // MORE CORES = MORE SCHEDULING OPPORTUNITY = TIGHTER EXPECTATION
    let med_limit = 200.0 + (300.0 * 2.0 / ncpu as f64);
    let p99_limit = 2000.0 + (2000.0 * 2.0 / ncpu as f64);

    assert!(
        median <= med_limit,
        "CONTENTION MEDIAN TOO HIGH: {:.0}us (LIMIT: {:.0}us, {} CORES)",
        median,
        med_limit,
        ncpu
    );
    assert!(
        p99 <= p99_limit,
        "CONTENTION P99 TOO HIGH: {:.0}us (LIMIT: {:.0}us, {} CORES)",
        p99,
        p99_limit,
        ncpu
    );
}

// FULL TEST GATE (RUN ALL LAYERS, PRODUCE REPORT)

#[test]
#[ignore]
fn full_gate() {
    let stamp = timestamp();
    let mut results: Vec<(String, Option<bool>, String)> = Vec::new();
    let mut any_fail = false;

    eprintln!();
    eprintln!("PANDEMONIUM TEST GATE");
    eprintln!("{}", "=".repeat(60));

    // LAYER 2: INTEGRATION
    let l2 = std::panic::catch_unwind(|| {
        layer2_load_classify_unload();
    });
    let (l2_pass, l2_detail) = match l2 {
        Ok(()) => (true, "LOAD/CLASSIFY/UNLOAD OK".to_string()),
        Err(e) => {
            let msg = if let Some(s) = e.downcast_ref::<String>() {
                s.clone()
            } else if let Some(s) = e.downcast_ref::<&str>() {
                s.to_string()
            } else {
                "UNKNOWN ERROR".to_string()
            };
            // TRUNCATE LONG MESSAGES
            let short = if msg.len() > 100 { &msg[..100] } else { &msg };
            (false, short.to_string())
        }
    };
    let status = if l2_pass { "PASS" } else { "FAIL" };
    eprintln!("LAYER 2: INTEGRATION ... {}", status);
    results.push((
        "LAYER 2: INTEGRATION (LOAD/UNLOAD)".to_string(),
        Some(l2_pass),
        l2_detail,
    ));
    if !l2_pass {
        any_fail = true;
    }

    // LAYER 3: LATENCY GATE
    if !any_fail {
        let l3 = std::panic::catch_unwind(|| {
            layer3_latency_gate();
        });
        let has_cyclictest = which("cyclictest");
        if !has_cyclictest {
            eprintln!("LAYER 3: LATENCY GATE ... SKIP");
            results.push((
                "LAYER 3: LATENCY GATE".to_string(),
                None,
                "cyclictest not installed".to_string(),
            ));
        } else {
            let (l3_pass, l3_detail) = match l3 {
                Ok(()) => (true, String::new()),
                Err(e) => {
                    let msg = if let Some(s) = e.downcast_ref::<String>() {
                        s.clone()
                    } else {
                        "UNKNOWN ERROR".to_string()
                    };
                    let short = if msg.len() > 100 { &msg[..100] } else { &msg };
                    (false, short.to_string())
                }
            };
            let status = if l3_pass { "PASS" } else { "FAIL" };
            eprintln!("LAYER 3: LATENCY GATE ... {}", status);
            results.push((
                "LAYER 3: LATENCY GATE".to_string(),
                Some(l3_pass),
                l3_detail,
            ));
            if !l3_pass {
                any_fail = true;
            }
        }
    }

    // LAYER 4: INTERACTIVE RESPONSIVENESS
    if !any_fail {
        let l4 = std::panic::catch_unwind(|| {
            layer4_interactive_responsiveness();
        });
        let (l4_pass, l4_detail) = match l4 {
            Ok(()) => (true, String::new()),
            Err(e) => {
                let msg = if let Some(s) = e.downcast_ref::<String>() {
                    s.clone()
                } else {
                    "UNKNOWN ERROR".to_string()
                };
                let short = if msg.len() > 100 { &msg[..100] } else { &msg };
                (false, short.to_string())
            }
        };
        let status = if l4_pass { "PASS" } else { "FAIL" };
        eprintln!("LAYER 4: INTERACTIVE ... {}", status);
        results.push(("LAYER 4: INTERACTIVE".to_string(), Some(l4_pass), l4_detail));
        if !l4_pass {
            any_fail = true;
        }
    }

    // LAYER 5: CONTENTION LATENCY
    if !any_fail {
        let l5 = std::panic::catch_unwind(|| {
            layer5_contention_latency();
        });
        let (l5_pass, l5_detail) = match l5 {
            Ok(()) => (true, String::new()),
            Err(e) => {
                let msg = if let Some(s) = e.downcast_ref::<String>() {
                    s.clone()
                } else {
                    "UNKNOWN ERROR".to_string()
                };
                let short = if msg.len() > 100 { &msg[..100] } else { &msg };
                (false, short.to_string())
            }
        };
        let status = if l5_pass { "PASS" } else { "FAIL" };
        eprintln!("LAYER 5: CONTENTION ... {}", status);
        results.push(("LAYER 5: CONTENTION".to_string(), Some(l5_pass), l5_detail));
        if !l5_pass {
            any_fail = true;
        }
    }

    let verdict = if any_fail { "FAIL" } else { "PASS" };
    eprintln!("{}", "=".repeat(60));
    eprintln!("VERDICT: {}", verdict);

    save_report(&stamp, &results, verdict);

    assert!(!any_fail, "TEST GATE FAILED");
}
