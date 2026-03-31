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

mod bpf_intf;

#[macro_use]
mod log;
mod adaptive;
mod chaos;
mod cli;
mod procdb;
mod scheduler;
mod topology;
mod tuning;
mod watchdog;

use std::mem::MaybeUninit;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::Result;
use clap::CommandFactory;
use clap::{Parser, Subcommand};
use clap_complete::generate;
use clap_complete::Shell;

use scheduler::Scheduler;
use scx_utils::build_id;

static SHUTDOWN: AtomicBool = AtomicBool::new(false);

#[derive(Parser)]
#[command(name = "scx_pandemonium")]
#[command(
    version,
    disable_version_flag = true,
    about = "PANDEMONIUM -- ADAPTIVE LINUX SCHEDULER"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<SubCmd>,

    #[arg(short, long)]
    verbose: bool,

    /// Print scheduler version and exit.
    #[arg(long)]
    version: bool,

    /// Internal: dump in-memory ring log on shutdown
    #[arg(long, hide = true)]
    dump_log: bool,

    /// Internal: override CPU count for scaling formulas (test harness use)
    #[arg(long, hide = true)]
    nr_cpus: Option<u64>,

    /// Run BPF scheduler only, disable Rust adaptive control loop
    #[arg(long)]
    no_adaptive: bool,

    /// Generate shell completions for the given shell and exit.
    #[clap(long, value_name = "SHELL", hide = true)]
    completions: Option<Shell>,
}

#[derive(Subcommand)]
enum SubCmd {
    /// Internal: interactive wakeup probe (Python test harness use)
    #[command(hide = true)]
    Probe,

    /// Internal: CPU-pinned stress worker (Python test harness use)
    #[command(hide = true)]
    StressWorker(StressWorkerArgs),
}

#[derive(Parser)]
struct StressWorkerArgs {
    /// CPU to pin the stress worker to
    #[arg(long)]
    cpu: u32,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    if let Some(shell) = cli.completions {
        generate(
            shell,
            &mut Cli::command(),
            "scx_pandemonium",
            &mut std::io::stdout(),
        );
        return Ok(());
    }

    let verbose = cli.verbose;
    let dump_log = cli.dump_log;
    let nr_cpus = cli.nr_cpus;
    let no_adaptive = cli.no_adaptive;

    if cli.version {
        println!(
            "scx_pandemonium {}",
            build_id::full_version(env!("CARGO_PKG_VERSION"))
        );
        return Ok(());
    }

    match cli.command {
        None => run_scheduler(verbose, dump_log, nr_cpus, no_adaptive),
        Some(SubCmd::Probe) => {
            cli::probe::run_probe();
            Ok(())
        }
        Some(SubCmd::StressWorker(args)) => {
            cli::stress::run_stress_worker(args.cpu);
            Ok(())
        }
    }
}

fn run_scheduler(
    verbose: bool,
    dump_log: bool,
    nr_cpus: Option<u64>,
    no_adaptive: bool,
) -> Result<()> {
    ctrlc::set_handler(move || {
        SHUTDOWN.store(true, Ordering::Relaxed);
    })?;

    // WATCHDOG: ABORTS IF THE CONTROL LOOP STALLS FOR MORE THAN 10 SECONDS.
    // LIBBPF MAP OPERATIONS CAN HANG ON KERNEL STALL / VERIFIER RELOAD /
    // PERCPU CONTENTION; WITHOUT THIS, TELEMETRY AND KNOB WRITES STOP SILENTLY.
    watchdog::spawn(&SHUTDOWN, Duration::from_secs(10));

    let nr_cpus_display =
        nr_cpus.unwrap_or_else(|| libbpf_rs::num_possible_cpus().unwrap_or(1) as u64);
    let governor = std::fs::read_to_string("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor")
        .unwrap_or_default()
        .trim()
        .to_string();

    let smt_on = std::fs::read_to_string("/sys/devices/system/cpu/smt/active")
        .map(|s| s.trim() == "1")
        .unwrap_or(false);

    log_info!(
        "scx_pandemonium {} SMT {}",
        build_id::full_version(env!("CARGO_PKG_VERSION")),
        if smt_on { "on" } else { "off" }
    );
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

    let mut is_restart = false;
    loop {
        // ON RESTART, WAIT FOR KERNEL STRUCT_OPS CLEANUP.
        // DETACH IS ASYNCHRONOUS -- UNDER HEAVY LOAD (12C SATURATED),
        // THE KERNEL NEEDS TIME TO FULLY UNREGISTER THE OLD SCHEDULER.
        if is_restart {
            std::thread::sleep(Duration::from_secs(2));
        }

        let mut open_object = MaybeUninit::uninit();
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
                // RESISTANCE AFFINITY: COMPUTE R_EFF VIA LAPLACIAN PSEUDOINVERSE
                // AND POPULATE BPF AFFINITY RANK MAP. SPECTRUM CARRIES lambda_2
                // AND tau_ns FOR UNIVERSAL TOPOLOGY-DERIVED SCALING.
                let (reff, rank, spectrum) = topo.compute_resistance_affinity();
                topo.log_resistance_affinity(&reff, &rank, spectrum);
                if let Err(e) = topo.populate_affinity_rank_map(&sched, &rank) {
                    log_warn!("AFFINITY RANK MAP WRITE FAILED: {}", e);
                }
                // WRITE tau_ns + codel_eq_ns INTO tuning_knobs. BPF'S tick() ON
                // CPU 0 PICKS THESE UP AND DERIVES THE TAU-SCALED TIMING STATICS
                // AND THE R_eff-DERIVED CODEL EQUILIBRIUM TARGET.
                if let Err(e) = sched.write_topology_fields(spectrum.tau_ns, spectrum.codel_eq_ns) {
                    log_warn!("TOPOLOGY KNOB WRITE FAILED: {}", e);
                }
            }
            Err(e) => log_warn!("CACHE TOPOLOGY DETECT FAILED: {}", e),
        }

        let should_restart = if no_adaptive {
            // BPF-ONLY MODE: SCHEDULER RUNS WITH DEFAULT KNOBS, NO RUST TUNING
            // STILL PRINTS STATS SO BENCHMARKS GET TELEMETRY FOR BOTH PHASES
            log_info!("PANDEMONIUM IS ACTIVE (BPF ONLY, CTRL+C TO EXIT)");
            let mut prev = scheduler::PandemoniumStats::default();
            while !SHUTDOWN.load(Ordering::Relaxed) && !sched.exited() {
                watchdog::LOOP_HEARTBEAT.fetch_add(1, Ordering::Relaxed);
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

                let sojourn_ms = stats.batch_sojourn_ns / 1_000_000;
                let longrun_label = if stats.longrun_mode_active > 0 {
                    " LONGRUN"
                } else {
                    ""
                };

                if verbose {
                    println!(
                        "d/s: {:<8} idle: {}% shared: {:<6} preempt: {:<4} keep: {:<4} kick: H={:<4} S={:<4} enq: W={:<4} R={:<4} wake: {}us lat_idle: {}us lat_kick: {}us reenq: {} sjrn: {}ms l2: B={}% I={}% L={}% [BPF{}]",
                        delta_d, idle_pct, delta_shared, delta_preempt, delta_keep,
                        delta_hard, delta_soft, delta_enq_wake, delta_enq_requeue,
                        wake_avg_us, lat_idle_us, lat_kick_us,
                        delta_reenq, sojourn_ms, l2_pct_b, l2_pct_i, l2_pct_l,
                        longrun_label,
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
                "[KNOBS] regime=BPF slice_ns={} batch_ns={} preempt_ns={} lag={} l2_hit=B:{}%/I:{}%/L:{}%",
                knobs.slice_ns, knobs.batch_slice_ns,
                knobs.preempt_thresh_ns,
                knobs.lag_scale, l2_cum_b, l2_cum_i, l2_cum_l,
            );

            sched.read_exit_info()
        } else {
            // ADAPTIVE MODE: BPF + SINGLE-THREAD MONITOR LOOP
            log_info!("PANDEMONIUM IS ACTIVE (CTRL+C TO EXIT)");
            adaptive::monitor_loop(&mut sched, &SHUTDOWN, verbose, nr_cpus_display)?
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
        is_restart = true;
    }

    log_info!("Shutdown complete");
    Ok(())
}
