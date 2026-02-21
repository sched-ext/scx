//! Empirical PMU skid measurement tool.
//!
//! Measures the difference between the *requested* RBC (Retired Branch
//! Conditional) overflow point and the *actual* point at which the overflow
//! signal is delivered. This difference is called "skid" and is caused by
//! CPU pipeline depth, interrupt delivery latency, and microarchitecture.
//!
//! Usage:
//!   cargo run --release --example measure_skid
//!
//! The tool tests several target periods (10, 100, 1000, 2000 branches)
//! and for each one reports the distribution of skid values.

use std::sync::atomic::{AtomicI32, AtomicU64, Ordering};

use scx_perf::{PmuConfig, RbcTimer, PERF_IOC_DISABLE};

/// Number of trials per target period.
const TRIALS: usize = 500;

/// Target periods to test.
const TARGETS: &[u64] = &[10, 100, 1000, 2000];

// --- Globals for async-signal-safe communication with signal handler ---

/// The perf fd of the active timer (set before each trial).
static TIMER_FD: AtomicI32 = AtomicI32::new(-1);

/// The RBC count read inside the signal handler.
static ACTUAL_COUNT: AtomicU64 = AtomicU64::new(0);

/// Flag: signal handler has fired for the current trial.
static SIGNAL_FIRED: AtomicU64 = AtomicU64::new(0);

/// Signal handler — reads counter and disables timer immediately.
///
/// SAFETY: Only uses async-signal-safe operations (read, ioctl, atomic store).
extern "C" fn handler(_signo: libc::c_int, _info: *mut libc::siginfo_t, _ctx: *mut libc::c_void) {
    let fd = TIMER_FD.load(Ordering::Relaxed);
    if fd < 0 {
        return;
    }

    // Disable timer first to prevent re-fire.
    unsafe {
        libc::ioctl(fd, PERF_IOC_DISABLE, 0usize);
    }

    // Read counter value — this is the actual RBC count at signal delivery.
    let mut count: u64 = 0;
    unsafe {
        libc::read(fd, &mut count as *mut u64 as *mut libc::c_void, 8);
    }

    ACTUAL_COUNT.store(count, Ordering::SeqCst);
    SIGNAL_FIRED.store(1, Ordering::SeqCst);
}

/// Generate conditional branches in a tight loop.
///
/// Each iteration has 2 conditional branches (the `if` conditions), so
/// `n` iterations produce roughly `2*n` conditional branches (plus loop
/// control). This is intentionally simple and predictable.
#[inline(never)]
fn branch_workload(n: u64) -> u64 {
    let mut sum = 0u64;
    for i in 0..n {
        if i % 2 == 0 {
            sum = sum.wrapping_add(i);
        }
        if i % 3 == 0 {
            sum = sum.wrapping_add(i >> 1);
        }
    }
    std::hint::black_box(sum)
}

struct SkidStats {
    target: u64,
    skids: Vec<i64>,
}

impl SkidStats {
    fn mean(&self) -> f64 {
        let sum: i64 = self.skids.iter().sum();
        sum as f64 / self.skids.len() as f64
    }

    fn stddev(&self) -> f64 {
        let m = self.mean();
        let variance: f64 = self
            .skids
            .iter()
            .map(|&s| {
                let d = s as f64 - m;
                d * d
            })
            .sum::<f64>()
            / self.skids.len() as f64;
        variance.sqrt()
    }

    fn min(&self) -> i64 {
        *self.skids.iter().min().unwrap_or(&0)
    }

    fn max(&self) -> i64 {
        *self.skids.iter().max().unwrap_or(&0)
    }

    fn median(&self) -> i64 {
        let mut sorted = self.skids.clone();
        sorted.sort();
        sorted[sorted.len() / 2]
    }

    fn p95(&self) -> i64 {
        let mut sorted = self.skids.clone();
        sorted.sort();
        sorted[(sorted.len() as f64 * 0.95) as usize]
    }

    fn p99(&self) -> i64 {
        let mut sorted = self.skids.clone();
        sorted.sort();
        sorted[(sorted.len() as f64 * 0.99) as usize]
    }
}

fn install_signal_handler() {
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = handler as libc::sighandler_t;
        sa.sa_flags = libc::SA_SIGINFO | libc::SA_RESTART;
        libc::sigemptyset(&mut sa.sa_mask);
        let ret = libc::sigaction(libc::SIGSTKFLT, &sa, std::ptr::null_mut());
        assert_eq!(ret, 0, "failed to install SIGSTKFLT handler");
    }
}

fn measure_skid_for_target(target: u64) -> SkidStats {
    let config = PmuConfig::detect().expect("CPU not supported for RBC counting");
    let mut skids = Vec::with_capacity(TRIALS);
    let mut timeouts = 0usize;

    for _ in 0..TRIALS {
        // Create a fresh timer for each trial to avoid counter accumulation issues.
        let timer = RbcTimer::new(&config, target).expect("failed to create RBC timer");

        let tid = unsafe { libc::syscall(libc::SYS_gettid) } as libc::pid_t;
        timer
            .set_signal_delivery(tid, libc::SIGSTKFLT)
            .expect("set_signal_delivery");

        TIMER_FD.store(timer.raw_fd(), Ordering::SeqCst);
        ACTUAL_COUNT.store(0, Ordering::SeqCst);
        SIGNAL_FIRED.store(0, Ordering::SeqCst);

        timer.reset().expect("reset");
        timer.enable().expect("enable");

        // Run enough branches to guarantee overflow even with large skid.
        // For target=2000, we want at least 2000 + generous_skid branches.
        // Each loop iteration is ~3 conditional branches (loop cond + 2 ifs).
        let iterations = (target as u64 + 50_000).max(100_000);
        branch_workload(iterations);

        timer.disable().expect("disable");

        if SIGNAL_FIRED.load(Ordering::SeqCst) == 1 {
            let actual = ACTUAL_COUNT.load(Ordering::SeqCst);
            let skid = actual as i64 - target as i64;
            skids.push(skid);
        } else {
            timeouts += 1;
        }

        // Drop timer (closes fd).
        TIMER_FD.store(-1, Ordering::SeqCst);
    }

    if timeouts > 0 {
        eprintln!(
            "  WARNING: {timeouts}/{TRIALS} trials for target={target} did not fire a signal"
        );
    }

    SkidStats { target, skids }
}

fn main() {
    // Detect CPU info for the header.
    let info = detect_cpu_info();
    println!("PMU Skid Measurement");
    println!("====================");
    println!("CPU: {info}");
    println!("Trials per target: {TRIALS}");
    println!();

    install_signal_handler();

    // Pin to a single CPU to avoid cross-core migration noise.
    pin_to_cpu(0);

    let mut all_stats = Vec::new();

    for &target in TARGETS {
        let stats = measure_skid_for_target(target);
        all_stats.push(stats);
    }

    // Print results table.
    println!(
        "{:>8} {:>8} {:>10} {:>8} {:>8} {:>8} {:>8} {:>8} {:>8}",
        "Target", "N", "Mean", "StdDev", "Min", "Median", "Max", "P95", "P99"
    );
    println!("{}", "-".repeat(86));

    for stats in &all_stats {
        if stats.skids.is_empty() {
            println!(
                "{:>8} {:>8} {:>10} {:>8} {:>8} {:>8} {:>8} {:>8} {:>8}",
                stats.target, 0, "N/A", "N/A", "N/A", "N/A", "N/A", "N/A", "N/A"
            );
        } else {
            println!(
                "{:>8} {:>8} {:>10.1} {:>8.1} {:>8} {:>8} {:>8} {:>8} {:>8}",
                stats.target,
                stats.skids.len(),
                stats.mean(),
                stats.stddev(),
                stats.min(),
                stats.median(),
                stats.max(),
                stats.p95(),
                stats.p99(),
            );
        }
    }

    println!();
    println!("Skid = actual_count_at_signal - target_period");
    println!("Positive skid means the signal arrived AFTER the target (late delivery).");
    println!("Negative skid would mean the signal arrived BEFORE the target (should not happen).");
}

/// Pin the current thread to a specific CPU.
fn pin_to_cpu(cpu: usize) {
    unsafe {
        let mut set: libc::cpu_set_t = std::mem::zeroed();
        libc::CPU_ZERO(&mut set);
        libc::CPU_SET(cpu, &mut set);
        let ret = libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &set);
        if ret != 0 {
            eprintln!(
                "WARNING: failed to pin to CPU {cpu}: {}",
                std::io::Error::last_os_error()
            );
        } else {
            println!("Pinned to CPU {cpu}");
        }
    }
}

/// Get a human-readable CPU identification string.
fn detect_cpu_info() -> String {
    // Read from /proc/cpuinfo for the model name.
    if let Ok(contents) = std::fs::read_to_string("/proc/cpuinfo") {
        for line in contents.lines() {
            if line.starts_with("model name") {
                if let Some(name) = line.split(':').nth(1) {
                    return name.trim().to_string();
                }
            }
        }
    }
    "unknown".to_string()
}
