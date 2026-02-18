//! scxsim — Run sched_ext scheduler simulations from rt-app workloads.

use std::path::{Path, PathBuf};

use clap::Parser;

use scx_simulator::scenario::{parse_duration_ns, parse_seed};
use scx_simulator::{
    discover_schedulers, load_rtapp, DynamicScheduler, SimFormat, Simulator, SIM_LOCK,
};

/// Run sched_ext scheduler simulations from rt-app workloads.
#[derive(Parser)]
#[command(name = "scxsim")]
struct Cli {
    /// Path to an rt-app JSON workload file.
    workload: Option<PathBuf>,

    /// Scheduler name.
    #[arg(short, long, default_value = "simple")]
    scheduler: String,

    /// Number of simulated CPUs.
    #[arg(short, long, default_value_t = 4)]
    cpus: u32,

    /// SMT threads per core.
    #[arg(long, default_value_t = 1)]
    smt: u32,

    /// PRNG seed (u32 integer or "entropy" for OS randomness).
    ///
    /// Controls deterministic simulation: tick jitter, context-switch
    /// overhead noise, and event tiebreaking all derive from this seed.
    /// Falls back to SCX_SIM_SEED env var, then default (42).
    #[arg(long, env = "SCX_SIM_SEED")]
    seed: Option<String>,

    /// Use insertion-order event tiebreaking instead of randomized.
    ///
    /// By default, events at the same timestamp are processed in a
    /// PRNG-randomized order to detect ordering-dependent bugs.
    /// This flag restores the deterministic insertion-order behavior.
    #[arg(long)]
    fixed_priority: bool,

    /// Simulation end time (overrides workload duration).
    ///
    /// Accepts durations with units: "1s", "0.5s", "500ms", "100us", "1000ns".
    /// A bare number is interpreted as nanoseconds.
    #[arg(long, value_name = "DURATION")]
    end_time: Option<String>,

    /// Write Perfetto trace JSON to file.
    #[arg(long, value_name = "PATH")]
    perfetto: Option<PathBuf>,

    /// Print trace events to stderr.
    #[arg(long)]
    dump_trace: bool,

    /// Disable tick jitter noise.
    #[arg(long)]
    no_noise: bool,

    /// Disable context-switch overhead.
    #[arg(long)]
    no_overhead: bool,

    /// Nanoseconds of logical time per retired conditional branch in scheduler
    /// code. Enables PMU-based scheduler overhead measurement.
    #[arg(long, value_name = "NS")]
    rbc_ns: Option<u64>,

    /// List available schedulers and exit.
    #[arg(long)]
    list_schedulers: bool,
}

fn main() {
    let cli = Cli::parse();
    init_tracing();

    if let Err(e) = run(&cli) {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

fn run(cli: &Cli) -> Result<(), String> {
    if cli.list_schedulers {
        list_schedulers();
        return Ok(());
    }

    let workload_path = cli
        .workload
        .as_ref()
        .ok_or("missing required argument: <WORKLOAD>")?;

    let json = std::fs::read_to_string(workload_path)
        .map_err(|e| format!("failed to read {}: {e}", workload_path.display()))?;

    let mut scenario =
        load_rtapp(&json, cli.cpus).map_err(|e| format!("failed to parse workload: {e}"))?;

    // Override scenario fields from CLI flags.
    scenario.smt_threads_per_core = cli.smt;
    if cli.no_noise {
        scenario.noise.enabled = false;
    }
    if cli.no_overhead {
        scenario.overhead.enabled = false;
    }
    if let Some(ref seed_str) = cli.seed {
        scenario.seed = parse_seed(Some(seed_str));
    }
    if cli.fixed_priority {
        scenario.fixed_priority = true;
    }
    if let Some(ref end_time) = cli.end_time {
        scenario.duration_ns =
            parse_duration_ns(end_time).map_err(|e| format!("--end-time: {e}"))?;
    }
    if let Some(rbc_ns) = cli.rbc_ns {
        scenario.sched_overhead_rbc_ns = Some(rbc_ns);
    }

    let sched = load_scheduler(&cli.scheduler, cli.cpus)?;
    let _lock = SIM_LOCK.lock().unwrap();
    let trace = Simulator::new(sched).run(scenario);

    if cli.dump_trace {
        trace.dump();
    }

    if let Some(path) = &cli.perfetto {
        let mut file = std::fs::File::create(path)
            .map_err(|e| format!("failed to create {}: {e}", path.display()))?;
        trace
            .write_perfetto_json(&mut file)
            .map_err(|e| format!("failed to write perfetto trace: {e}"))?;
        eprintln!("wrote perfetto trace to {}", path.display());
    }

    Ok(())
}

fn load_scheduler(name: &str, nr_cpus: u32) -> Result<DynamicScheduler, String> {
    let dir = env!("SCHEDULER_SO_DIR");
    let so_path = format!("{dir}/libscx_{name}.so");
    if Path::new(&so_path).exists() {
        Ok(DynamicScheduler::load(&so_path, name, nr_cpus))
    } else {
        Err(format!(
            "unknown scheduler {name:?}; use --list-schedulers to see available schedulers"
        ))
    }
}

fn list_schedulers() {
    let dir = env!("SCHEDULER_SO_DIR");
    let schedulers = discover_schedulers(Path::new(dir));
    if schedulers.is_empty() {
        eprintln!("no schedulers found in {dir}");
    } else {
        for info in &schedulers {
            println!("{:<16} {}", info.name, info.path.display());
        }
    }
}

fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .event_format(SimFormat)
        .try_init();
}
