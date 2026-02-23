// PANDEMONIUM -- SCHED_EXT KERNEL SCHEDULER
// ADAPTIVE DESKTOP SCHEDULING FOR LINUX
//
// SCHEDULING DECISIONS HAPPEN IN BPF (ZERO KERNEL-USERSPACE ROUND TRIPS)
// RUST USERSPACE HANDLES: ADAPTIVE CONTROL LOOP, MONITORING, BENCHMARKING

#[allow(non_upper_case_globals)]
#[allow(non_camel_case_types)]
#[allow(non_snake_case)]
#[allow(dead_code)]
mod bpf_skel;

#[macro_use]
mod log;
mod adaptive;
mod cli;
mod procdb;
mod scheduler;
mod topology;
mod tuning;

use std::mem::MaybeUninit;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::Result;
use clap::{Parser, Subcommand};

use scheduler::Scheduler;

static SHUTDOWN: AtomicBool = AtomicBool::new(false);

#[derive(Parser)]
#[command(name = "pandemonium")]
#[command(version)]
#[command(about = "PANDEMONIUM -- ADAPTIVE LINUX SCHEDULER")]
struct Cli {
    #[command(subcommand)]
    command: Option<SubCmd>,

    #[arg(long)]
    verbose: bool,

    #[arg(long)]
    dump_log: bool,

    /// Override CPU count for scaling formulas (default: auto-detect)
    #[arg(long)]
    nr_cpus: Option<u64>,

    /// Run BPF scheduler only, disable Rust adaptive control loop
    #[arg(long)]
    no_adaptive: bool,

    /// Additional compositor process names to boost to LAT_CRITICAL
    #[arg(long)]
    compositor: Vec<String>,
}

#[derive(Subcommand)]
enum SubCmd {
    /// Check dependencies and kernel config
    Check,

    /// Run interactive wakeup probe (stdout: overshoot_us per line)
    Probe(ProbeArgs),

    /// Build, run with sudo, capture output + dmesg, save logs
    Start(StartArgs),

    /// Show filtered kernel dmesg for sched_ext/pandemonium
    Dmesg,

    /// A/B benchmark (EEVDF baseline vs PANDEMONIUM)
    Bench(BenchArgs),

    /// Build release then run bench (logs to /tmp/pandemonium)
    BenchRun(BenchRunArgs),

    /// Run test gate (unit + integration)
    Test,

    /// CPU-pinned stress worker for bench-scale (internal use)
    StressWorker(StressWorkerArgs),
}

#[derive(Parser)]
struct ProbeArgs {
    /// Death pipe FD for orphan detection (internal use)
    #[arg(long)]
    death_pipe_fd: Option<i32>,
}

#[derive(Parser)]
struct StressWorkerArgs {
    /// CPU to pin the stress worker to
    #[arg(long)]
    cpu: u32,
}

#[derive(Parser)]
struct StartArgs {
    /// Run with --verbose --dump-log
    #[arg(long)]
    observe: bool,

    /// Extra args forwarded to `pandemonium run`
    #[arg(last = true)]
    sched_args: Vec<String>,
}

#[derive(Parser)]
struct BenchArgs {
    /// Benchmark mode
    #[arg(long, value_enum)]
    mode: cli::bench::BenchMode,

    /// Command to benchmark (for --mode cmd)
    #[arg(long)]
    cmd: Option<String>,

    /// Number of iterations per phase
    #[arg(long, default_value_t = 3)]
    iterations: usize,

    /// Clean command between iterations (for --mode cmd)
    #[arg(long)]
    clean_cmd: Option<String>,

    /// Extra args forwarded to `pandemonium run`
    #[arg(last = true)]
    sched_args: Vec<String>,
}

#[derive(Parser)]
struct BenchRunArgs {
    /// Benchmark mode
    #[arg(long, value_enum)]
    mode: cli::bench::BenchMode,

    /// Command to benchmark (for --mode cmd)
    #[arg(long)]
    cmd: Option<String>,

    /// Number of iterations per phase
    #[arg(long, default_value_t = 3)]
    iterations: usize,

    /// Clean command between iterations (for --mode cmd)
    #[arg(long)]
    clean_cmd: Option<String>,

    /// Extra args forwarded to `pandemonium run`
    #[arg(last = true)]
    sched_args: Vec<String>,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    let verbose = cli.verbose;
    let dump_log = cli.dump_log;
    let nr_cpus = cli.nr_cpus;
    let no_adaptive = cli.no_adaptive;
    let extra_compositors = cli.compositor;

    match cli.command {
        None => run_scheduler(verbose, dump_log, nr_cpus, no_adaptive, &extra_compositors),
        Some(SubCmd::Check) => cli::check::run_check(),
        Some(SubCmd::Probe(args)) => {
            cli::probe::run_probe(args.death_pipe_fd);
            Ok(())
        }
        Some(SubCmd::Start(args)) => cli::run::run_start(args.observe, &args.sched_args),
        Some(SubCmd::Dmesg) => cli::run::run_dmesg(),
        Some(SubCmd::Bench(args)) => cli::bench::run_bench(
            args.mode,
            args.cmd.as_deref(),
            args.iterations,
            args.clean_cmd.as_deref(),
            &args.sched_args,
        ),
        Some(SubCmd::BenchRun(args)) => cli::bench::run_bench_run(
            args.mode,
            args.cmd.as_deref(),
            args.iterations,
            args.clean_cmd.as_deref(),
            &args.sched_args,
        ),
        Some(SubCmd::Test) => cli::test_gate::run_test_gate(),
        Some(SubCmd::StressWorker(args)) => {
            cli::stress::run_stress_worker(args.cpu);
            Ok(())
        }
    }
}

// DEFAULT COMPOSITORS: BOOSTED TO LAT_CRITICAL VIA BPF MAP LOOKUP
const DEFAULT_COMPOSITORS: &[&str] =
    &["kwin", "gnome-shell", "sway", "Hyprland", "picom", "weston"];

fn run_scheduler(
    verbose: bool,
    dump_log: bool,
    nr_cpus: Option<u64>,
    no_adaptive: bool,
    extra_compositors: &[String],
) -> Result<()> {
    ctrlc::set_handler(move || {
        SHUTDOWN.store(true, Ordering::Relaxed);
    })?;

    let nr_cpus_display =
        nr_cpus.unwrap_or_else(|| libbpf_rs::num_possible_cpus().unwrap_or(1) as u64);
    let governor = std::fs::read_to_string("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor")
        .unwrap_or_default()
        .trim()
        .to_string();

    log_info!("PANDEMONIUM v{}", env!("CARGO_PKG_VERSION"));
    log_info!(
        "CPUS: {} (governor: {})",
        nr_cpus_display,
        if governor.is_empty() {
            "unknown"
        } else {
            &governor
        }
    );
    log_info!("VERBOSE: {}", verbose);

    let mut open_object = MaybeUninit::uninit();

    loop {
        let mut sched = Scheduler::init(&mut open_object, nr_cpus)?;

        // POPULATE CACHE TOPOLOGY MAP AT STARTUP
        match topology::CpuTopology::detect(nr_cpus_display as usize) {
            Ok(topo) => {
                topo.log_summary();
                if let Err(e) = topo.populate_bpf_map(&sched) {
                    log_warn!("CACHE TOPOLOGY MAP WRITE FAILED: {}", e);
                }
                if let Err(e) = topo.populate_l2_siblings_map(&sched) {
                    log_warn!("L2 SIBLINGS MAP WRITE FAILED: {}", e);
                }
            }
            Err(e) => log_warn!("CACHE TOPOLOGY DETECT FAILED: {}", e),
        }

        // POPULATE COMPOSITOR MAP: DEFAULT + USER-SUPPLIED NAMES
        for name in DEFAULT_COMPOSITORS {
            if let Err(e) = sched.write_compositor(name) {
                log_warn!("COMPOSITOR MAP WRITE FAILED: {} ({})", name, e);
            }
        }
        for name in extra_compositors {
            if let Err(e) = sched.write_compositor(name) {
                log_warn!("COMPOSITOR MAP WRITE FAILED: {} ({})", name, e);
            }
        }

        let should_restart = if no_adaptive {
            // BPF-ONLY MODE: SCHEDULER RUNS WITH DEFAULT KNOBS, NO RUST TUNING
            // STILL PRINTS STATS SO BENCHMARKS GET TELEMETRY FOR BOTH PHASES
            log_info!("PANDEMONIUM IS ACTIVE (BPF ONLY, CTRL+C TO EXIT)");
            let mut prev = scheduler::PandemoniumStats::default();
            while !SHUTDOWN.load(Ordering::Relaxed) && !sched.exited() {
                std::thread::sleep(Duration::from_secs(1));

                let stats = sched.read_stats();

                let delta_d = stats.nr_dispatches.wrapping_sub(prev.nr_dispatches);
                let delta_idle = stats.nr_idle_hits.wrapping_sub(prev.nr_idle_hits);
                let delta_shared = stats.nr_shared.wrapping_sub(prev.nr_shared);
                let delta_preempt = stats.nr_preempt.wrapping_sub(prev.nr_preempt);
                let delta_keep = stats.nr_keep_running.wrapping_sub(prev.nr_keep_running);
                let delta_wake_sum = stats.wake_lat_sum.wrapping_sub(prev.wake_lat_sum);
                let delta_wake_samples = stats.wake_lat_samples.wrapping_sub(prev.wake_lat_samples);
                let delta_hard = stats.nr_hard_kicks.wrapping_sub(prev.nr_hard_kicks);
                let delta_soft = stats.nr_soft_kicks.wrapping_sub(prev.nr_soft_kicks);
                let delta_enq_wake = stats.nr_enq_wakeup.wrapping_sub(prev.nr_enq_wakeup);
                let delta_enq_requeue = stats.nr_enq_requeue.wrapping_sub(prev.nr_enq_requeue);
                let wake_avg_us = if delta_wake_samples > 0 {
                    delta_wake_sum / delta_wake_samples / 1000
                } else {
                    0
                };

                let d_idle_sum = stats.wake_lat_idle_sum.wrapping_sub(prev.wake_lat_idle_sum);
                let d_idle_cnt = stats.wake_lat_idle_cnt.wrapping_sub(prev.wake_lat_idle_cnt);
                let d_kick_sum = stats.wake_lat_kick_sum.wrapping_sub(prev.wake_lat_kick_sum);
                let d_kick_cnt = stats.wake_lat_kick_cnt.wrapping_sub(prev.wake_lat_kick_cnt);
                let lat_idle_us = if d_idle_cnt > 0 {
                    d_idle_sum / d_idle_cnt / 1000
                } else {
                    0
                };
                let lat_kick_us = if d_kick_cnt > 0 {
                    d_kick_sum / d_kick_cnt / 1000
                } else {
                    0
                };
                let delta_guard = stats.nr_guard_clamps.wrapping_sub(prev.nr_guard_clamps);
                let delta_procdb = stats.nr_procdb_hits.wrapping_sub(prev.nr_procdb_hits);
                let delta_reenq = stats.nr_reenqueue.wrapping_sub(prev.nr_reenqueue);

                // L2 CACHE AFFINITY DELTAS
                let dl2_hb = stats.nr_l2_hit_batch.wrapping_sub(prev.nr_l2_hit_batch);
                let dl2_mb = stats.nr_l2_miss_batch.wrapping_sub(prev.nr_l2_miss_batch);
                let dl2_hi = stats
                    .nr_l2_hit_interactive
                    .wrapping_sub(prev.nr_l2_hit_interactive);
                let dl2_mi = stats
                    .nr_l2_miss_interactive
                    .wrapping_sub(prev.nr_l2_miss_interactive);
                let dl2_hl = stats
                    .nr_l2_hit_lat_crit
                    .wrapping_sub(prev.nr_l2_hit_lat_crit);
                let dl2_ml = stats
                    .nr_l2_miss_lat_crit
                    .wrapping_sub(prev.nr_l2_miss_lat_crit);
                let l2_pct_b = if dl2_hb + dl2_mb > 0 {
                    dl2_hb * 100 / (dl2_hb + dl2_mb)
                } else {
                    0
                };
                let l2_pct_i = if dl2_hi + dl2_mi > 0 {
                    dl2_hi * 100 / (dl2_hi + dl2_mi)
                } else {
                    0
                };
                let l2_pct_l = if dl2_hl + dl2_ml > 0 {
                    dl2_hl * 100 / (dl2_hl + dl2_ml)
                } else {
                    0
                };

                let idle_pct = if delta_d > 0 {
                    delta_idle * 100 / delta_d
                } else {
                    0
                };

                if verbose {
                    println!(
                        "d/s: {:<8} idle: {}% shared: {:<6} preempt: {:<4} keep: {:<4} kick: H={:<4} S={:<4} enq: W={:<4} R={:<4} wake: {}us lat_idle: {}us lat_kick: {}us procdb: {} guard: {} reenq: {} l2: B={}% I={}% L={}% [BPF]",
                        delta_d, idle_pct, delta_shared, delta_preempt, delta_keep,
                        delta_hard, delta_soft, delta_enq_wake, delta_enq_requeue,
                        wake_avg_us, lat_idle_us, lat_kick_us, delta_procdb, delta_guard,
                        delta_reenq, l2_pct_b, l2_pct_i, l2_pct_l,
                    );
                }

                sched.log.snapshot(
                    delta_d,
                    delta_idle,
                    delta_shared,
                    delta_preempt,
                    delta_keep,
                    wake_avg_us,
                    delta_hard,
                    delta_soft,
                    lat_idle_us,
                    lat_kick_us,
                );

                prev = stats;
            }

            // KNOBS SUMMARY: CAPTURED BY TEST HARNESS FOR ARCHIVE
            let knobs = sched.read_tuning_knobs();
            let final_stats = sched.read_stats();
            let l2_total_b = final_stats.nr_l2_hit_batch + final_stats.nr_l2_miss_batch;
            let l2_total_i = final_stats.nr_l2_hit_interactive + final_stats.nr_l2_miss_interactive;
            let l2_total_l = final_stats.nr_l2_hit_lat_crit + final_stats.nr_l2_miss_lat_crit;
            let l2_cum_b = if l2_total_b > 0 {
                final_stats.nr_l2_hit_batch * 100 / l2_total_b
            } else {
                0
            };
            let l2_cum_i = if l2_total_i > 0 {
                final_stats.nr_l2_hit_interactive * 100 / l2_total_i
            } else {
                0
            };
            let l2_cum_l = if l2_total_l > 0 {
                final_stats.nr_l2_hit_lat_crit * 100 / l2_total_l
            } else {
                0
            };
            println!(
                "[KNOBS] regime=BPF slice_ns={} batch_ns={} preempt_ns={} demotion_ns={} lag={} l2_hit=B:{}%/I:{}%/L:{}%",
                knobs.slice_ns, knobs.batch_slice_ns,
                knobs.preempt_thresh_ns, knobs.cpu_bound_thresh_ns,
                knobs.lag_scale, l2_cum_b, l2_cum_i, l2_cum_l,
            );

            sched.read_exit_info()
        } else {
            // ADAPTIVE MODE: BPF + SINGLE-THREAD MONITOR LOOP
            log_info!("PANDEMONIUM IS ACTIVE (CTRL+C TO EXIT)");
            adaptive::monitor_loop(&mut sched, &SHUTDOWN, verbose)?
        };

        log_info!("PANDEMONIUM IS SHUTTING DOWN");

        if dump_log {
            sched.log.dump();
        }
        sched.log.summary();

        if !should_restart || SHUTDOWN.load(Ordering::Relaxed) {
            break;
        }

        // RESET SHUTDOWN FOR RESTART
        SHUTDOWN.store(false, Ordering::Relaxed);
        log_info!("RESTARTING PANDEMONIUM...");
    }

    log_info!("Shutdown complete");
    Ok(())
}
