//! scxsim — Run sched_ext scheduler simulations from rt-app workloads.

use std::path::{Path, PathBuf};

use clap::Parser;

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
