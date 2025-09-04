// SPDX-License-Identifier: GPL-2.0
//
// Copyright (c) 2025 Andrea Righi <arighi@nvidia.com>

// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

mod bpf_skel;
pub use bpf_skel::*;
pub mod bpf_intf;
pub use bpf_intf::*;

mod stats;
use std::collections::HashSet;
use std::ffi::c_int;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::mem::MaybeUninit;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::bail;
use anyhow::Context;
use anyhow::Result;
use clap::Parser;
use crossbeam::channel::RecvTimeoutError;
use libbpf_rs::OpenObject;
use libbpf_rs::ProgramInput;
use log::{debug, info, warn};
use scx_stats::prelude::*;
use scx_utils::build_id;
use scx_utils::compat;
use scx_utils::libbpf_clap_opts::LibbpfOpts;
use scx_utils::scx_ops_attach;
use scx_utils::scx_ops_load;
use scx_utils::scx_ops_open;
use scx_utils::try_set_rlimit_infinity;
use scx_utils::uei_exited;
use scx_utils::uei_report;
use scx_utils::CoreType;
use scx_utils::Topology;
use scx_utils::UserExitInfo;
use scx_utils::NR_CPU_IDS;
use stats::Metrics;

const SCHEDULER_NAME: &str = "scx_cosmos";

#[derive(Debug, clap::Parser)]
#[command(
    name = "scx_cosmos",
    version,
    disable_version_flag = true,
    about = "Lightweight scheduler optimized for preserving task-to-CPU locality."
)]
struct Opts {
    /// Exit debug dump buffer length. 0 indicates default.
    #[clap(long, default_value = "0")]
    exit_dump_len: u32,

    /// Maximum scheduling slice duration in microseconds.
    #[clap(short = 's', long, default_value = "10")]
    slice_us: u64,

    /// Maximum runtime (since last sleep) that can be charged to a task in microseconds.
    #[clap(short = 'l', long, default_value = "20000")]
    slice_lag_us: u64,

    /// CPU busy threshold.
    ///
    /// Specifies the CPU utilization percentage (0-100%) at which the scheduler considers the
    /// system to be busy.
    ///
    /// When the average CPU utilization reaches this threshold, the scheduler switches from using
    /// multiple per-CPU round-robin dispatch queues (which favor locality and reduced locking
    /// contention) to a global deadline-based dispatch queue (which improves load balancing).
    ///
    /// The global dispatch queue can increase task migrations and improve responsiveness for
    /// interactive tasks under heavy load. Lower values make the scheduler switch to deadline
    /// mode sooner, improving overall responsiveness at the cost of reducing single-task
    /// performance due to the additional migrations. Higher values makes task more "sticky" to
    /// their CPU, improving workloads that benefit from cache locality.
    ///
    /// A higher value is recommended for server-type workloads, while a lower value is recommended
    /// for interactive-type workloads.
    #[clap(short = 'c', long, default_value = "75")]
    cpu_busy_thresh: u64,

    /// Polling time (ms) to refresh the CPU utilization.
    ///
    /// This interval determines how often the scheduler refreshes the CPU utilization that is
    /// compared with the CPU busy threshold (option -c) to decide if the system is busy or not
    /// and trigger the switch between using multiple per-CPU dispatch queues or a single global
    /// deadline-based dispatch queue.
    ///
    /// Value is clamped to the range [10 .. 1000].
    ///
    /// 0 = disabled.
    #[clap(short = 'p', long, default_value = "250")]
    polling_ms: u64,

    /// Specifies a list of CPUs to prioritize.
    ///
    /// Accepts a comma-separated list of CPUs or ranges (i.e., 0-3,12-15) or the following special
    /// keywords:
    ///
    /// "turbo" = automatically detect and prioritize the CPUs with the highest max frequency,
    /// "performance" = automatically detect and prioritize the fastest CPUs,
    /// "powersave" = automatically detect and prioritize the slowest CPUs,
    /// "all" = all CPUs assigned to the primary domain.
    ///
    /// By default "all" CPUs are used.
    #[clap(short = 'm', long)]
    primary_domain: Option<String>,

    /// Enable NUMA optimizations.
    #[clap(short = 'n', long, action = clap::ArgAction::SetTrue)]
    enable_numa: bool,

    /// Disable CPU frequency control.
    #[clap(short = 'f', long, action = clap::ArgAction::SetTrue)]
    disable_cpufreq: bool,

    /// Enable flat idle CPU scanning.
    ///
    /// This option can help reducing some overhead when trying to allocate idle CPUs and it can be
    /// quite effective with simple CPU topologies.
    #[arg(short = 'i', long, action = clap::ArgAction::SetTrue)]
    flat_idle_scan: bool,

    /// Enable preferred idle CPU scanning.
    ///
    /// With this option enabled, the scheduler will prioritize assigning tasks to higher-ranked
    /// cores before considering lower-ranked ones.
    #[clap(short = 'P', long, action = clap::ArgAction::SetTrue)]
    preferred_idle_scan: bool,

    /// Disable SMT.
    ///
    /// This option can only be used together with --flat-idle-scan or --preferred-idle-scan,
    /// otherwise it is ignored.
    #[clap(long, action = clap::ArgAction::SetTrue)]
    disable_smt: bool,

    /// SMT contention avoidance.
    ///
    /// When enabled, the scheduler aggressively avoids placing tasks on sibling SMT threads.
    /// This may increase task migrations and lower overall throughput, but can lead to more
    /// consistent performance by reducing contention on shared SMT cores.
    #[clap(short = 'S', long, action = clap::ArgAction::SetTrue)]
    avoid_smt: bool,

    /// Disable direct dispatch during synchronous wakeups.
    ///
    /// Enabling this option can lead to a more uniform load distribution across available cores,
    /// potentially improving performance in certain scenarios. However, it may come at the cost of
    /// reduced efficiency for pipe-intensive workloads that benefit from tighter producer-consumer
    /// coupling.
    #[clap(short = 'w', long, action = clap::ArgAction::SetTrue)]
    no_wake_sync: bool,

    /// Disable deferred wakeups.
    ///
    /// Enabling this option can reduce throughput and performance for certain workloads, but it
    /// can also reduce power consumption (useful on battery-powered systems).
    #[clap(short = 'd', long, action = clap::ArgAction::SetTrue)]
    no_deferred_wakeup: bool,

    /// Enable address space affinity.
    ///
    /// This option allows to keep tasks that share the same address space (e.g., threads of the
    /// same process) on the same CPU across wakeups.
    ///
    /// This can improve locality and performance in certain cache-sensitive workloads.
    #[clap(short = 'a', long, action = clap::ArgAction::SetTrue)]
    mm_affinity: bool,

    /// Enable stats monitoring with the specified interval.
    #[clap(long)]
    stats: Option<f64>,

    /// Run in stats monitoring mode with the specified interval. Scheduler
    /// is not launched.
    #[clap(long)]
    monitor: Option<f64>,

    /// Enable verbose output, including libbpf details.
    #[clap(short = 'v', long, action = clap::ArgAction::SetTrue)]
    verbose: bool,

    /// Print scheduler version and exit.
    #[clap(short = 'V', long, action = clap::ArgAction::SetTrue)]
    version: bool,

    /// Show descriptions for statistics.
    #[clap(long)]
    help_stats: bool,

    #[clap(flatten, next_help_heading = "Libbpf Options")]
    pub libbpf: LibbpfOpts,
}

#[derive(PartialEq)]
enum Powermode {
    Turbo,
    Performance,
    Powersave,
    Any,
}

/*
 * TODO: this code is shared between scx_bpfland, scx_flash and scx_cosmos; consder to move it to
 * scx_utils.
 */
fn get_primary_cpus(mode: Powermode) -> std::io::Result<Vec<usize>> {
    let cpus: Vec<usize> = Topology::new()
        .unwrap()
        .all_cores
        .values()
        .flat_map(|core| &core.cpus)
        .filter_map(|(cpu_id, cpu)| match (&mode, &cpu.core_type) {
            // Turbo mode: prioritize CPUs with the highest max frequency
            (Powermode::Turbo, CoreType::Big { turbo: true }) |
            // Performance mode: add all the Big CPUs (either Turbo or non-Turbo)
            (Powermode::Performance, CoreType::Big { .. }) |
            // Powersave mode: add all the Little CPUs
            (Powermode::Powersave, CoreType::Little) => Some(*cpu_id),
            (Powermode::Any, ..) => Some(*cpu_id),
            _ => None,
        })
        .collect();

    Ok(cpus)
}

pub fn parse_cpu_list(optarg: &str) -> Result<Vec<usize>, String> {
    let mut cpus = Vec::new();
    let mut seen = HashSet::new();

    // Handle special keywords
    if let Some(mode) = match optarg {
        "powersave" => Some(Powermode::Powersave),
        "performance" => Some(Powermode::Performance),
        "turbo" => Some(Powermode::Turbo),
        "all" => Some(Powermode::Any),
        _ => None,
    } {
        return get_primary_cpus(mode).map_err(|e| e.to_string());
    }

    // Validate input characters
    if optarg
        .chars()
        .any(|c| !c.is_ascii_digit() && c != '-' && c != ',' && !c.is_whitespace())
    {
        return Err("Invalid character in CPU list".to_string());
    }

    // Replace all whitespace with tab (or just trim later)
    let cleaned = optarg.replace(' ', "\t");

    for token in cleaned.split(',') {
        let token = token.trim_matches(|c: char| c.is_whitespace());

        if token.is_empty() {
            continue;
        }

        if let Some((start_str, end_str)) = token.split_once('-') {
            let start = start_str
                .trim()
                .parse::<usize>()
                .map_err(|_| "Invalid range start")?;
            let end = end_str
                .trim()
                .parse::<usize>()
                .map_err(|_| "Invalid range end")?;

            if start > end {
                return Err(format!("Invalid CPU range: {}-{}", start, end));
            }

            for i in start..=end {
                if cpus.len() >= *NR_CPU_IDS {
                    return Err(format!("Too many CPUs specified (max {})", *NR_CPU_IDS));
                }
                if seen.insert(i) {
                    cpus.push(i);
                }
            }
        } else {
            let cpu = token
                .parse::<usize>()
                .map_err(|_| format!("Invalid CPU: {}", token))?;
            if cpus.len() >= *NR_CPU_IDS {
                return Err(format!("Too many CPUs specified (max {})", *NR_CPU_IDS));
            }
            if seen.insert(cpu) {
                cpus.push(cpu);
            }
        }
    }

    Ok(cpus)
}

#[derive(Debug, Clone, Copy)]
struct CpuTimes {
    user: u64,
    nice: u64,
    total: u64,
}

struct Scheduler<'a> {
    skel: BpfSkel<'a>,
    opts: &'a Opts,
    struct_ops: Option<libbpf_rs::Link>,
    stats_server: StatsServer<(), Metrics>,
}

impl<'a> Scheduler<'a> {
    fn init(opts: &'a Opts, open_object: &'a mut MaybeUninit<OpenObject>) -> Result<Self> {
        try_set_rlimit_infinity();

        // Initialize CPU topology.
        let topo = Topology::new().unwrap();

        // Check host topology to determine if we need to enable SMT capabilities.
        let smt_enabled = !opts.disable_smt && topo.smt_enabled;

        info!(
            "{} {} {}",
            SCHEDULER_NAME,
            build_id::full_version(env!("CARGO_PKG_VERSION")),
            if smt_enabled { "SMT on" } else { "SMT off" }
        );

        // Print command line.
        info!(
            "scheduler options: {}",
            std::env::args().collect::<Vec<_>>().join(" ")
        );

        // Initialize BPF connector.
        let mut skel_builder = BpfSkelBuilder::default();
        skel_builder.obj_builder.debug(opts.verbose);
        let open_opts = opts.libbpf.clone().into_bpf_open_opts();
        let mut skel = scx_ops_open!(skel_builder, open_object, cosmos_ops, open_opts)?;

        skel.struct_ops.cosmos_ops_mut().exit_dump_len = opts.exit_dump_len;

        // Override default BPF scheduling parameters.
        let rodata = skel.maps.rodata_data.as_mut().unwrap();
        rodata.slice_ns = opts.slice_us * 1000;
        rodata.slice_lag = opts.slice_lag_us * 1000;
        rodata.cpufreq_enabled = !opts.disable_cpufreq;
        rodata.deferred_wakeups = !opts.no_deferred_wakeup;
        rodata.flat_idle_scan = opts.flat_idle_scan;
        rodata.smt_enabled = smt_enabled;
        rodata.numa_enabled = opts.enable_numa;
        rodata.no_wake_sync = opts.no_wake_sync;
        rodata.avoid_smt = opts.avoid_smt;
        rodata.mm_affinity = opts.mm_affinity;

        // Normalize CPU busy threshold in the range [0 .. 1024].
        rodata.busy_threshold = opts.cpu_busy_thresh * 1024 / 100;

        // Generate the list of available CPUs sorted by capacity in descending order.
        if opts.preferred_idle_scan {
            let mut cpus: Vec<_> = topo.all_cpus.values().collect();
            cpus.sort_by_key(|cpu| std::cmp::Reverse(cpu.cpu_capacity));
            for (i, cpu) in cpus.iter().enumerate() {
                rodata.preferred_cpus[i] = cpu.id as u64;
            }
            info!(
                "Preferred CPUs: {:?}",
                &rodata.preferred_cpus[0..cpus.len()]
            );
        }
        rodata.preferred_idle_scan = opts.preferred_idle_scan;

        // Define the primary scheduling domain.
        let primary_cpus = if let Some(ref domain) = opts.primary_domain {
            match parse_cpu_list(domain) {
                Ok(cpus) => cpus,
                Err(e) => bail!("Error parsing primary domain: {}", e),
            }
        } else {
            (0..*NR_CPU_IDS).collect()
        };
        if primary_cpus.len() < *NR_CPU_IDS {
            info!("Primary CPUs: {:?}", primary_cpus);
            rodata.primary_all = false;
        } else {
            rodata.primary_all = true;
        }

        // Set scheduler flags.
        skel.struct_ops.cosmos_ops_mut().flags = *compat::SCX_OPS_ENQ_EXITING
            | *compat::SCX_OPS_ENQ_LAST
            | *compat::SCX_OPS_ENQ_MIGRATION_DISABLED
            | *compat::SCX_OPS_ALLOW_QUEUED_WAKEUP
            | if opts.enable_numa {
                *compat::SCX_OPS_BUILTIN_IDLE_PER_NODE
            } else {
                0
            };
        info!(
            "scheduler flags: {:#x}",
            skel.struct_ops.cosmos_ops_mut().flags
        );

        // Load the BPF program for validation.
        let mut skel = scx_ops_load!(skel, cosmos_ops, uei)?;

        // Enable primary scheduling domain, if defined.
        if primary_cpus.len() < *NR_CPU_IDS {
            for cpu in primary_cpus {
                if let Err(err) = Self::enable_primary_cpu(&mut skel, cpu as i32) {
                    bail!("failed to add CPU {} to primary domain: error {}", cpu, err);
                }
            }
        }

        // Attach the scheduler.
        let struct_ops = Some(scx_ops_attach!(skel, cosmos_ops)?);
        let stats_server = StatsServer::new(stats::server_data()).launch()?;

        Ok(Self {
            skel,
            opts,
            struct_ops,
            stats_server,
        })
    }

    fn enable_primary_cpu(skel: &mut BpfSkel<'_>, cpu: i32) -> Result<(), u32> {
        let prog = &mut skel.progs.enable_primary_cpu;
        let mut args = cpu_arg {
            cpu_id: cpu as c_int,
        };
        let input = ProgramInput {
            context_in: Some(unsafe {
                std::slice::from_raw_parts_mut(
                    &mut args as *mut _ as *mut u8,
                    std::mem::size_of_val(&args),
                )
            }),
            ..Default::default()
        };
        let out = prog.test_run(input).unwrap();
        if out.return_value != 0 {
            return Err(out.return_value);
        }

        Ok(())
    }

    fn get_metrics(&self) -> Metrics {
        Metrics {
            cpu_thresh: self.skel.maps.rodata_data.as_ref().unwrap().busy_threshold,
            cpu_util: self.skel.maps.bss_data.as_ref().unwrap().cpu_util,
        }
    }

    pub fn exited(&mut self) -> bool {
        uei_exited!(&self.skel, uei)
    }

    fn compute_user_cpu_pct(prev: &CpuTimes, curr: &CpuTimes) -> Option<u64> {
        // Evaluate total user CPU time as user + nice.
        let user_diff = (curr.user + curr.nice).saturating_sub(prev.user + prev.nice);
        let total_diff = curr.total.saturating_sub(prev.total);

        if total_diff > 0 {
            let user_ratio = user_diff as f64 / total_diff as f64;
            Some((user_ratio * 1024.0).round() as u64)
        } else {
            None
        }
    }

    fn read_cpu_times() -> Option<CpuTimes> {
        let file = File::open("/proc/stat").ok()?;
        let reader = BufReader::new(file);

        for line in reader.lines() {
            let line = line.ok()?;
            if line.starts_with("cpu ") {
                let fields: Vec<&str> = line.split_whitespace().collect();
                if fields.len() < 5 {
                    return None;
                }

                let user: u64 = fields[1].parse().ok()?;
                let nice: u64 = fields[2].parse().ok()?;

                // Sum the first 8 fields as total time, including idle, system, etc.
                let total: u64 = fields
                    .iter()
                    .skip(1)
                    .take(8)
                    .filter_map(|v| v.parse::<u64>().ok())
                    .sum();

                return Some(CpuTimes { user, nice, total });
            }
        }

        None
    }

    fn run(&mut self, shutdown: Arc<AtomicBool>) -> Result<UserExitInfo> {
        let (res_ch, req_ch) = self.stats_server.channels();

        // Periodically evaluate user CPU utilization from user-space and update a global variable
        // in BPF.
        //
        // The BPF scheduler will use this value to determine when the system is idle (using local
        // DSQs and simple round-robin scheduler) or busy (switching to a deadline-based policy).
        let polling_time = Duration::from_millis(self.opts.polling_ms).min(Duration::from_secs(1));
        let mut prev_cputime = Self::read_cpu_times().expect("Failed to read initial CPU stats");
        let mut last_update = Instant::now();

        while !shutdown.load(Ordering::Relaxed) && !self.exited() {
            // Update CPU utilization.
            if !polling_time.is_zero() && last_update.elapsed() >= polling_time {
                if let Some(curr_cputime) = Self::read_cpu_times() {
                    Self::compute_user_cpu_pct(&prev_cputime, &curr_cputime)
                        .map(|util| self.skel.maps.bss_data.as_mut().unwrap().cpu_util = util);
                    prev_cputime = curr_cputime;
                }
                last_update = Instant::now();
            }

            // Update statistics and check for exit condition.
            let timeout = if polling_time.is_zero() {
                Duration::from_secs(1)
            } else {
                polling_time
            };
            match req_ch.recv_timeout(timeout) {
                Ok(()) => res_ch.send(self.get_metrics())?,
                Err(RecvTimeoutError::Timeout) => {}
                Err(e) => Err(e)?,
            }
        }

        let _ = self.struct_ops.take();
        uei_report!(&self.skel, uei)
    }
}

impl Drop for Scheduler<'_> {
    fn drop(&mut self) {
        info!("Unregister {SCHEDULER_NAME} scheduler");
    }
}

fn main() -> Result<()> {
    let opts = Opts::parse();

    if opts.version {
        println!(
            "{} {}",
            SCHEDULER_NAME,
            build_id::full_version(env!("CARGO_PKG_VERSION"))
        );
        return Ok(());
    }

    if opts.help_stats {
        stats::server_data().describe_meta(&mut std::io::stdout(), None)?;
        return Ok(());
    }

    let loglevel = simplelog::LevelFilter::Info;

    let mut lcfg = simplelog::ConfigBuilder::new();
    lcfg.set_time_offset_to_local()
        .expect("Failed to set local time offset")
        .set_time_level(simplelog::LevelFilter::Error)
        .set_location_level(simplelog::LevelFilter::Off)
        .set_target_level(simplelog::LevelFilter::Off)
        .set_thread_level(simplelog::LevelFilter::Off);
    simplelog::TermLogger::init(
        loglevel,
        lcfg.build(),
        simplelog::TerminalMode::Stderr,
        simplelog::ColorChoice::Auto,
    )?;

    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_clone = shutdown.clone();
    ctrlc::set_handler(move || {
        shutdown_clone.store(true, Ordering::Relaxed);
    })
    .context("Error setting Ctrl-C handler")?;

    if let Some(intv) = opts.monitor.or(opts.stats) {
        let shutdown_copy = shutdown.clone();
        let jh = std::thread::spawn(move || {
            match stats::monitor(Duration::from_secs_f64(intv), shutdown_copy) {
                Ok(_) => {
                    debug!("stats monitor thread finished successfully")
                }
                Err(error_object) => {
                    warn!(
                        "stats monitor thread finished because of an error {}",
                        error_object
                    )
                }
            }
        });
        if opts.monitor.is_some() {
            let _ = jh.join();
            return Ok(());
        }
    }

    let mut open_object = MaybeUninit::uninit();
    loop {
        let mut sched = Scheduler::init(&opts, &mut open_object)?;
        if !sched.run(shutdown.clone())?.should_restart() {
            break;
        }
    }

    Ok(())
}
