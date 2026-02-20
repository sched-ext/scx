//! scxsim — Run sched_ext scheduler simulations from rt-app workloads.

use std::path::{Path, PathBuf};

use clap::{Parser, ValueEnum};

use scx_simulator::scenario::{parse_duration_ns, parse_seed};
use scx_simulator::{
    discover_schedulers, load_rtapp, DynamicScheduler, PreemptiveConfig, SimFormat, Simulator,
    SIM_LOCK,
};

mod real_run;

/// How to run the workload.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, ValueEnum)]
pub enum RealRunMode {
    /// Simulation only (default).
    #[default]
    Off,
    /// Launch virtme-ng VM with rt-app and scheduler.
    Vm,
}

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
    /// code. Enables PMU-based scheduler overhead measurement. Default: 10.
    #[arg(long, value_name = "NS", conflicts_with = "no_rbc")]
    rbc_ns: Option<u64>,

    /// Disable PMU-based RBC scheduler overhead (equivalent to --rbc-ns 0).
    #[arg(long, conflicts_with = "rbc_ns")]
    no_rbc: bool,

    /// Watchdog timeout for stall detection.
    ///
    /// If a runnable task is not scheduled within this duration (simulated
    /// time), the simulation exits with an error. Accepts durations with
    /// units: "2s", "500ms", etc. Default: 30s.
    #[arg(long, value_name = "DURATION")]
    watchdog_timeout: Option<String>,

    /// Enable concurrent callback interleaving at kfunc yield points.
    ///
    /// Runs dispatch callbacks for multiple idle CPUs on separate OS
    /// threads with PRNG-driven token passing, enabling deterministic
    /// exploration of different interleavings.
    #[arg(long)]
    interleave: bool,

    /// Enable preemptive interleaving via PMU retired branch counter signals.
    ///
    /// Like --interleave, but also preempts mid-C-code at random retired
    /// conditional branch intervals. Implies --interleave. Falls back to
    /// cooperative-only interleaving if PMU counters are unavailable (VM).
    #[arg(long)]
    preemptive: bool,

    /// Minimum preemptive timeslice in retired conditional branches.
    ///
    /// Controls the lower bound of the random timeslice range used by
    /// --preemptive mode. Default: 100.
    #[arg(long, default_value_t = 100, requires = "preemptive")]
    timeslice_min: u64,

    /// Maximum preemptive timeslice in retired conditional branches.
    ///
    /// Controls the upper bound of the random timeslice range used by
    /// --preemptive mode. Default: 1000.
    #[arg(long, default_value_t = 1000, requires = "preemptive")]
    timeslice_max: u64,

    /// List available schedulers and exit.
    #[arg(long)]
    list_schedulers: bool,

    /// Run workload in real environment.
    ///
    /// off: simulation only (default)
    /// vm: launch virtme-ng VM with rt-app and scheduler
    #[arg(long, value_enum, default_value_t = RealRunMode::Off)]
    real_run: RealRunMode,

    /// Record a Perfetto trace using wprof during VM execution.
    ///
    /// Requires --real-run vm. When enabled, an extra CPU is added to the VM
    /// and isolated using isolcpus for running the wprof tracer. The trace
    /// file is written to the current working directory.
    #[arg(long, conflicts_with = "bpf_trace")]
    wprof: bool,

    /// Trace scheduler ops callbacks and kfunc calls using bpftrace.
    ///
    /// Requires --real-run vm. When enabled, an extra CPU is added to the VM
    /// and isolated for running bpftrace with trace_scx_ops.bt. This traces
    /// sched_class entry points, scx_bpf_* kfunc calls with return values,
    /// and sched_switch/sched_wakeup lifecycle events.
    ///
    /// The trace is written to bpf_trace.log in the current working directory.
    /// This is an alternative to --wprof for comparing simulator vs real runs.
    #[arg(long, conflicts_with = "wprof")]
    bpf_trace: bool,
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
    if cli.interleave {
        scenario.interleave = true;
    }
    if cli.preemptive {
        scenario.preemptive = Some(PreemptiveConfig {
            timeslice_min: cli.timeslice_min,
            timeslice_max: cli.timeslice_max,
        });
        scenario.interleave = true;
    }
    if let Some(ref end_time) = cli.end_time {
        scenario.duration_ns =
            parse_duration_ns(end_time).map_err(|e| format!("--end-time: {e}"))?;
    }
    if let Some(rbc_ns) = cli.rbc_ns {
        scenario.sched_overhead_rbc_ns = Some(rbc_ns);
    }
    if cli.no_rbc {
        scenario.sched_overhead_rbc_ns = Some(0);
    }
    if let Some(ref timeout) = cli.watchdog_timeout {
        scenario.watchdog_timeout_ns =
            Some(parse_duration_ns(timeout).map_err(|e| format!("--watchdog-timeout: {e}"))?);
    }

    // Validate --wprof and --bpf-trace require --real-run vm
    if cli.wprof && cli.real_run != RealRunMode::Vm {
        return Err("--wprof requires --real-run vm".into());
    }
    if cli.bpf_trace && cli.real_run != RealRunMode::Vm {
        return Err("--bpf-trace requires --real-run vm".into());
    }

    // Determine trace mode
    let trace_mode = if cli.wprof {
        real_run::TraceMode::Wprof
    } else if cli.bpf_trace {
        real_run::TraceMode::BpfTrace
    } else {
        real_run::TraceMode::None
    };

    // Handle --real-run mode
    match cli.real_run {
        RealRunMode::Off => {
            run_simulation(cli, scenario)?;
        }
        RealRunMode::Vm => {
            real_run::run_vm(workload_path, &cli.scheduler, cli.cpus, trace_mode)?;
        }
    }

    Ok(())
}

fn run_simulation(cli: &Cli, scenario: scx_simulator::Scenario) -> Result<(), String> {
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

    if trace.has_error() {
        return Err(format!("simulation error: {:?}", trace.exit_kind()));
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
