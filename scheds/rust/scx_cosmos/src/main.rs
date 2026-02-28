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
use std::collections::{HashMap, HashSet};
use std::ffi::{c_int, c_ulong};
use std::fs;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::mem::MaybeUninit;
use std::path::Path;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::bail;
use anyhow::Context;
use anyhow::Result;
use clap::Parser;
use crossbeam::channel::RecvTimeoutError;
use libbpf_rs::MapCore;
use libbpf_rs::MapFlags;
use libbpf_rs::OpenObject;
use libbpf_rs::ProgramInput;
use log::{debug, info, warn};
use nvml_wrapper::bitmasks::InitFlags;
use nvml_wrapper::Nvml;
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
use scx_utils::GpuIndex;
use scx_utils::Topology;
use scx_utils::UserExitInfo;
use scx_utils::NR_CPU_IDS;
use stats::Metrics;

const SCHEDULER_NAME: &str = "scx_cosmos";

/// Parse hexadecimal value from command line (requires "0x" prefix, e.g., "0x2")
fn parse_hex(s: &str) -> Result<u64, String> {
    if let Some(hex_str) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(hex_str, 16).map_err(|e| format!("Invalid hexadecimal value: {}", e))
    } else {
        Err("Hexadecimal value must start with '0x' prefix (e.g., 0x2)".to_string())
    }
}

/// Must match lib/pmu.bpf.c SCX_PMU_STRIDE for perf_events map key layout.
const PERF_MAP_STRIDE: u32 = 4096;

/// Setup performance counter events for a specific CPU and counter index.
/// counter_idx 0 = migration event (-e), 1 = sticky event (-y).
fn setup_perf_events(
    skel: &mut BpfSkel,
    cpu: i32,
    perf_config: u64,
    counter_idx: u32,
) -> Result<()> {
    use perf_event_open_sys as sys;

    let map = &skel.maps.scx_pmu_map;

    let mut attrs = sys::bindings::perf_event_attr::default();
    attrs.type_ = sys::bindings::PERF_TYPE_RAW;
    attrs.config = perf_config;
    attrs.size = std::mem::size_of::<sys::bindings::perf_event_attr>() as u32;
    attrs.set_disabled(0);
    attrs.set_inherit(0);

    let fd = unsafe { sys::perf_event_open(&mut attrs, -1, cpu, -1, 0) };

    if fd < 0 {
        let err = std::io::Error::last_os_error();
        return Err(anyhow::anyhow!(
            "Failed to open perf event 0x{:x} on CPU {}: {}",
            perf_config,
            cpu,
            err
        ));
    }

    let key = cpu as u32 + counter_idx * PERF_MAP_STRIDE;

    map.update(
        &key.to_ne_bytes(),
        &fd.to_ne_bytes(),
        libbpf_rs::MapFlags::ANY,
    )
    .with_context(|| "Failed to update perf_events map")?;

    Ok(())
}

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
    #[clap(short = 's', long, default_value = "1000")]
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

    /// Hardware perf event to monitor (0x0 = disabled).
    #[clap(short = 'e', long, default_value = "0x0", value_parser = parse_hex)]
    perf_config: u64,

    /// Threshold (perf events/msec) to classify a task as event heavy; exceeding it triggers migration.
    #[clap(short = 'E', default_value = "0", long)]
    perf_threshold: u64,

    /// Sticky perf event (0x0 = disabled). When a task exceeds -Y for this event, keep it on the same CPU.
    #[clap(short = 'y', long, default_value = "0x0", value_parser = parse_hex)]
    perf_sticky: u64,

    /// Sticky perf threshold; task is kept on same CPU when its count for -y event exceeds this.
    #[clap(short = 'Y', default_value = "0", long)]
    perf_sticky_threshold: u64,

    /// Enable GPU-aware scheduling.
    #[clap(short = 'g', long, action = clap::ArgAction::SetTrue)]
    gpu: bool,

    /// Only treat a process as GPU-bound if its GPU utilization is at least this percentage (0–100).
    ///
    /// Uses NVML process utilization (SM + memory). 0 = no filter (all processes on the GPU are
    /// considered GPU-bound). Requires driver support (Maxwell or newer).
    #[clap(long, default_value = "0", value_parser = clap::value_parser!(u32).range(0..=100))]
    gpu_util_threshold: u32,

    /// Disable NUMA optimizations.
    #[clap(short = 'n', long, action = clap::ArgAction::SetTrue)]
    disable_numa: bool,

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

    /// ***DEPRECATED*** Disable deferred wakeups.
    #[clap(short = 'd', long, action = clap::ArgAction::SetTrue)]
    no_deferred_wakeup: bool,

    /// Disable tick-based preemption enforcement.
    ///
    /// By default, the scheduler preempts tasks that exceed their time slice when the system is
    /// busy or SMT contention is detected. Use this flag to disable this behavior.
    #[clap(long, action = clap::ArgAction::SetTrue)]
    no_tick_preempt: bool,

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

/// Initial value for the dynamic threshold (in BPF units).
const DYNAMIC_THRESHOLD_INIT_VALUE: u64 = 1000;

/// Target event rate (per second) above which we consider migrations/sticky dispatches too high.
const DYNAMIC_THRESHOLD_RATE_HIGH: f64 = 4000.0;

/// Target event rate (per second) below which we consider migrations/sticky dispatches too low.
const DYNAMIC_THRESHOLD_RATE_LOW: f64 = 2000.0;

/// Minimum scale factor when just outside the target band (slow convergence near optimal).
const DYNAMIC_THRESHOLD_SCALE_MIN: f64 = 0.0001;

/// Maximum scale factor when far from target (fast convergence when initial threshold is way off).
const DYNAMIC_THRESHOLD_SCALE_MAX: f64 = 1000.0;

/// Slope for "too high" case: scale grows with (rate/HIGH - 1) so we step much harder when rate is
/// many times over target.
const DYNAMIC_THRESHOLD_SLOPE_HIGH: f64 = 0.35;

/// Slope for "too low" case: scale grows with deficit so we step harder when rate is near zero.
const DYNAMIC_THRESHOLD_SLOPE_LOW: f64 = 0.58;

/// Minimum interval between NVML GPU PID syncs. Kept separate from CPU polling so that fast
/// polling (e.g. 100 ms) does not trigger expensive NVML calls every tick.
const GPU_SYNC_INTERVAL: Duration = Duration::from_secs(1);

fn dynamic_threshold_scale(rate_per_sec: f64, too_high: bool) -> f64 {
    if too_high {
        let excess = ((rate_per_sec / DYNAMIC_THRESHOLD_RATE_HIGH) - 1.0).max(0.0);
        let scale = DYNAMIC_THRESHOLD_SCALE_MIN + DYNAMIC_THRESHOLD_SLOPE_HIGH * excess.min(4.0);
        scale.min(DYNAMIC_THRESHOLD_SCALE_MAX)
    } else {
        if rate_per_sec <= 0.0 {
            return DYNAMIC_THRESHOLD_SCALE_MAX;
        }
        let deficit = (DYNAMIC_THRESHOLD_RATE_LOW - rate_per_sec) / DYNAMIC_THRESHOLD_RATE_LOW;
        let t = deficit.min(1.0).max(0.0);
        DYNAMIC_THRESHOLD_SCALE_MIN + DYNAMIC_THRESHOLD_SLOPE_LOW * t
    }
}

fn adjust_dynamic_threshold(current: u64, rate_per_sec: f64, base_threshold: u64) -> u64 {
    let (scale_pct, raise_threshold) = if rate_per_sec > DYNAMIC_THRESHOLD_RATE_HIGH {
        (dynamic_threshold_scale(rate_per_sec, true), true)
    } else if rate_per_sec < DYNAMIC_THRESHOLD_RATE_LOW && rate_per_sec >= 0.0 {
        (dynamic_threshold_scale(rate_per_sec, false), false)
    } else {
        return current;
    };

    let factor = if raise_threshold {
        1.0 + scale_pct
    } else {
        1.0 - scale_pct
    };
    let new = ((current as f64) * factor).round() as u64;

    let min_val = if base_threshold == 0 {
        1
    } else {
        base_threshold / 100
    };
    let max_val = if base_threshold == 0 {
        u64::MAX
    } else {
        base_threshold.saturating_mul(10000)
    };

    new.clamp(min_val.max(1), max_val)
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
    /// GPU device index -> NUMA node (for NVML PID sync). Only set when --gpu and NUMA enabled.
    gpu_index_to_node: Option<HashMap<u32, u32>>,
    /// Previous (pid, node) set so we can remove PIDs that stopped using the GPU.
    previous_gpu_pids: Option<HashMap<u32, u32>>,
    /// Reused NVML handle to avoid re-initializing on every sync (expensive).
    nvml: Option<Nvml>,
}

impl<'a> Scheduler<'a> {
    fn init(opts: &'a Opts, open_object: &'a mut MaybeUninit<OpenObject>) -> Result<Self> {
        try_set_rlimit_infinity();

        // Initialize CPU topology.
        let topo = Topology::new().unwrap();

        // Check host topology to determine if we need to enable SMT capabilities.
        let smt_enabled = !opts.disable_smt && topo.smt_enabled;

        // Determine the amount of non-empty NUMA nodes in the system.
        let nr_nodes = topo
            .nodes
            .values()
            .filter(|node| !node.all_cpus.is_empty())
            .count();
        info!("NUMA nodes: {}", nr_nodes);

        // Automatically disable NUMA optimizations when running on non-NUMA systems.
        let numa_enabled = !opts.disable_numa && nr_nodes > 1;
        if !numa_enabled {
            info!("Disabling NUMA optimizations");
        }

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
        rodata.flat_idle_scan = opts.flat_idle_scan;
        rodata.smt_enabled = smt_enabled;
        rodata.numa_enabled = numa_enabled;
        rodata.nr_node_ids = topo.nodes.len() as u32;
        rodata.no_wake_sync = opts.no_wake_sync;
        rodata.avoid_smt = opts.avoid_smt;
        rodata.tick_preempt = !opts.no_tick_preempt;
        rodata.mm_affinity = opts.mm_affinity;

        // Enable perf event scheduling settings.
        rodata.perf_config = opts.perf_config;
        rodata.perf_sticky = opts.perf_sticky;

        // Normalize CPU busy threshold in the range [0 .. 1024].
        rodata.busy_threshold = opts.cpu_busy_thresh * 1024 / 100;

        // Generate the list of available CPUs sorted by capacity in descending order.
        let mut cpus: Vec<_> = topo.all_cpus.values().collect();
        cpus.sort_by_key(|cpu| std::cmp::Reverse(cpu.cpu_capacity));
        for (i, cpu) in cpus.iter().enumerate() {
            rodata.cpu_capacity[cpu.id] = cpu.cpu_capacity as c_ulong;
            rodata.preferred_cpus[i] = cpu.id as u64;
        }
        if opts.preferred_idle_scan {
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

        // Enable GPU support and build GPU index -> node for NVML PID sync. Init NVML once here
        // so we reuse the handle in the run loop (re-initing every sync is very expensive).
        let (gpu_index_to_node, previous_gpu_pids, nvml) = if opts.gpu && numa_enabled {
            match Nvml::init_with_flags(InitFlags::NO_GPUS) {
                Ok(nvml) => {
                    info!("NVIDIA GPU-aware scheduling enabled (NVML PID sync)");
                    rodata.gpu_enabled = true;
                    let mut idx_to_node = HashMap::new();
                    for (id, gpu) in topo.gpus() {
                        let GpuIndex::Nvidia { nvml_id } = id;
                        idx_to_node.insert(nvml_id, gpu.node_id as u32);
                    }
                    (Some(idx_to_node), Some(HashMap::new()), Some(nvml))
                }
                Err(e) => {
                    warn!("NVML init failed, disabling GPU-aware scheduling: {}", e);
                    rodata.gpu_enabled = false;
                    (None, None, None)
                }
            }
        } else {
            rodata.gpu_enabled = false;
            (None, None, None)
        };

        // Set scheduler flags.
        skel.struct_ops.cosmos_ops_mut().flags = *compat::SCX_OPS_ENQ_EXITING
            | *compat::SCX_OPS_ENQ_LAST
            | *compat::SCX_OPS_ENQ_MIGRATION_DISABLED
            | *compat::SCX_OPS_ALLOW_QUEUED_WAKEUP;

        info!(
            "scheduler flags: {:#x}",
            skel.struct_ops.cosmos_ops_mut().flags
        );

        // Load the BPF program for validation.
        let mut skel = scx_ops_load!(skel, cosmos_ops, uei)?;

        // Initial perf thresholds in bss. When threshold is 0 we use dynamic logic; when user
        // specifies a value > 0 we use it as a static threshold.
        let bss = skel.maps.bss_data.as_mut().unwrap();
        if opts.perf_config > 0 {
            bss.perf_threshold = if opts.perf_threshold == 0 {
                DYNAMIC_THRESHOLD_INIT_VALUE
            } else {
                opts.perf_threshold
            };
        }
        if opts.perf_sticky > 0 {
            bss.perf_sticky_threshold = if opts.perf_sticky_threshold == 0 {
                DYNAMIC_THRESHOLD_INIT_VALUE
            } else {
                opts.perf_sticky_threshold
            };
        }

        // Configure CPU->node mapping (must be done after skeleton is loaded).
        for node in topo.nodes.values() {
            for cpu in node.all_cpus.values() {
                if opts.verbose {
                    info!("CPU{} -> node{}", cpu.id, node.id);
                }
                skel.maps.cpu_node_map.update(
                    &(cpu.id as u32).to_ne_bytes(),
                    &(node.id as u32).to_ne_bytes(),
                    MapFlags::ANY,
                )?;
            }
        }

        // Setup performance events for all CPUs.
        // Counter indices must match PMU library install order: migration first (0), then sticky (1).
        // When only sticky is used, it gets index 0; when both are used, sticky gets index 1.
        let nr_cpus = *NR_CPU_IDS;
        info!("Setting up performance counters for {} CPUs...", nr_cpus);
        let mut perf_available = true;
        let sticky_counter_idx = if opts.perf_config > 0 { 1 } else { 0 };
        for cpu in 0..nr_cpus {
            if opts.perf_config > 0 {
                if let Err(e) = setup_perf_events(&mut skel, cpu as i32, opts.perf_config, 0) {
                    if cpu == 0 {
                        let err_str = e.to_string();
                        if err_str.contains("errno 2") || err_str.contains("os error 2") {
                            warn!("Performance counters not available on this CPU architecture");
                            warn!("PMU event 0x{:x} not supported - scheduler will run without perf monitoring", opts.perf_config);
                        } else {
                            warn!("Failed to setup perf events: {}", e);
                        }
                        perf_available = false;
                        break;
                    }
                }
            }
            if opts.perf_sticky > 0 {
                if let Err(e) =
                    setup_perf_events(&mut skel, cpu as i32, opts.perf_sticky, sticky_counter_idx)
                {
                    if cpu == 0 {
                        let err_str = e.to_string();
                        if err_str.contains("errno 2") || err_str.contains("os error 2") {
                            warn!("Performance counters not available on this CPU architecture");
                            warn!("PMU event 0x{:x} not supported - scheduler will run without perf monitoring", opts.perf_sticky);
                        } else {
                            warn!("Failed to setup perf events: {}", e);
                        }
                        perf_available = false;
                        break;
                    }
                }
            }
        }
        if perf_available {
            info!("Performance counters configured successfully for all CPUs");
        }

        // Configure GPU->node mapping.
        if opts.gpu && numa_enabled {
            for (id, gpu) in topo.gpus() {
                let GpuIndex::Nvidia { nvml_id } = id;
                if opts.verbose {
                    info!("GPU{} -> node{}", nvml_id, gpu.node_id);
                }
                skel.maps.gpu_node_map.update(
                    &(nvml_id as u32).to_ne_bytes(),
                    &(gpu.node_id as u32).to_ne_bytes(),
                    MapFlags::ANY,
                )?;
            }
        }

        // Enable primary scheduling domain, if defined.
        if primary_cpus.len() < *NR_CPU_IDS {
            for cpu in primary_cpus {
                if let Err(err) = Self::enable_primary_cpu(&mut skel, cpu as i32) {
                    bail!("failed to add CPU {} to primary domain: error {}", cpu, err);
                }
            }
        }

        // Initialize SMT domains.
        if smt_enabled {
            Self::init_smt_domains(&mut skel, &topo)?;
        }

        // Attach the scheduler.
        let struct_ops = Some(scx_ops_attach!(skel, cosmos_ops)?);
        let stats_server = StatsServer::new(stats::server_data()).launch()?;

        Ok(Self {
            skel,
            opts,
            struct_ops,
            stats_server,
            gpu_index_to_node,
            previous_gpu_pids,
            nvml,
        })
    }

    /// Sync PID -> GPU (node) map from NVML. When gpu_util_threshold > 0, only PIDs with
    /// GPU utilization (SM or memory) >= threshold are added. Map is keyed by task pid.
    /// Only processes using a single GPU are added; multi-GPU processes are excluded.
    fn sync_gpu_pids(&mut self) -> Result<()> {
        let gpu_index_to_node = match &self.gpu_index_to_node {
            Some(m) => m,
            None => return Ok(()),
        };
        let nvml = match &self.nvml {
            Some(n) => n,
            None => return Ok(()),
        };
        let threshold = self.opts.gpu_util_threshold;
        let previous = self.previous_gpu_pids.as_ref().unwrap();
        // First collect pid -> set of nodes (GPUs) per process.
        let mut pid_to_nodes: HashMap<u32, HashSet<u32>> = HashMap::new();

        let count = nvml.device_count().context("NVML device count")?;
        for i in 0..count {
            let node = match gpu_index_to_node.get(&i) {
                Some(&n) => n,
                None => continue,
            };
            let device = nvml.device_by_index(i).context("NVML device_by_index")?;

            if threshold > 0 {
                // Use process utilization; only add PIDs above threshold.
                match device.process_utilization_stats(None::<u64>) {
                    Ok(samples) => {
                        for sample in samples {
                            let util = sample.sm_util.max(sample.mem_util);
                            if util >= threshold {
                                pid_to_nodes.entry(sample.pid).or_default().insert(node);
                            }
                        }
                    }
                    Err(_) => {
                        // NotSupported or other: fall back to all running processes.
                        Self::add_running_gpu_processes_to_set(&device, node, &mut pid_to_nodes);
                    }
                }
            } else {
                Self::add_running_gpu_processes_to_set(&device, node, &mut pid_to_nodes);
            }
        }

        // Only add PIDs that use exactly one GPU to the map.
        let mut current: HashMap<u32, u32> = HashMap::new();
        for (tgid, nodes) in pid_to_nodes {
            if nodes.len() == 1 {
                let node = nodes.into_iter().next().unwrap();
                current.insert(tgid, node);
                for tid in Self::task_tids(tgid) {
                    current.insert(tid, node);
                }
            }
        }

        let map = &self.skel.maps.gpu_pid_map;
        for (pid, node) in &current {
            map.update(&pid.to_ne_bytes(), &node.to_ne_bytes(), MapFlags::ANY)
                .context("gpu_pid_map update")?;
        }
        for pid in previous.keys() {
            if !current.contains_key(pid) {
                let _ = map.delete(&pid.to_ne_bytes());
            }
        }
        *self.previous_gpu_pids.as_mut().unwrap() = current;
        Ok(())
    }

    /// Record running compute/graphics process PIDs and the GPU node in pid_to_nodes.
    fn add_running_gpu_processes_to_set(
        device: &nvml_wrapper::Device<'_>,
        node: u32,
        pid_to_nodes: &mut HashMap<u32, HashSet<u32>>,
    ) {
        for proc in device
            .running_compute_processes()
            .unwrap_or_default()
            .into_iter()
            .chain(device.running_graphics_processes().unwrap_or_default())
        {
            pid_to_nodes.entry(proc.pid).or_default().insert(node);
        }
    }

    /// Return all thread IDs (tids) of the process with the given pid (tgid).
    fn task_tids(pid: u32) -> Vec<u32> {
        let task_dir = format!("/proc/{}/task", pid);
        let Ok(entries) = fs::read_dir(Path::new(&task_dir)) else {
            return Vec::new();
        };
        entries
            .filter_map(|e| e.ok())
            .filter_map(|e| e.file_name().to_str().and_then(|s| s.parse::<u32>().ok()))
            .collect()
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

    fn enable_sibling_cpu(
        skel: &mut BpfSkel<'_>,
        cpu: usize,
        sibling_cpu: usize,
    ) -> Result<(), u32> {
        let prog = &mut skel.progs.enable_sibling_cpu;
        let mut args = domain_arg {
            cpu_id: cpu as c_int,
            sibling_cpu_id: sibling_cpu as c_int,
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

    fn init_smt_domains(skel: &mut BpfSkel<'_>, topo: &Topology) -> Result<(), std::io::Error> {
        let smt_siblings = topo.sibling_cpus();

        info!("SMT sibling CPUs: {:?}", smt_siblings);
        for (cpu, sibling_cpu) in smt_siblings.iter().enumerate() {
            Self::enable_sibling_cpu(skel, cpu, *sibling_cpu as usize).unwrap();
        }

        Ok(())
    }

    fn get_metrics(&self) -> Metrics {
        let bss_data = self.skel.maps.bss_data.as_ref().unwrap();
        Metrics {
            cpu_thresh: self.skel.maps.rodata_data.as_ref().unwrap().busy_threshold,
            cpu_util: self.skel.maps.bss_data.as_ref().unwrap().cpu_util,
            nr_event_dispatches: bss_data.nr_event_dispatches,
            nr_ev_sticky_dispatches: bss_data.nr_ev_sticky_dispatches,
            nr_gpu_dispatches: bss_data.nr_gpu_dispatches,
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
        let mut last_gpu_sync = Instant::now();

        // Dynamic perf thresholds: scale based on migration and sticky dispatch rates.
        let mut prev_nr_event_dispatches: u64 = 0;
        let mut prev_nr_ev_sticky_dispatches: u64 = 0;

        while !shutdown.load(Ordering::Relaxed) && !self.exited() {
            // Update CPU utilization and GPU PID -> node map (NVML).
            if !polling_time.is_zero() && last_update.elapsed() >= polling_time {
                if let Some(curr_cputime) = Self::read_cpu_times() {
                    Self::compute_user_cpu_pct(&prev_cputime, &curr_cputime)
                        .map(|util| self.skel.maps.bss_data.as_mut().unwrap().cpu_util = util);
                    prev_cputime = curr_cputime;
                }

                // Update dynamic perf thresholds based on event rates.
                let nr_event = self
                    .skel
                    .maps
                    .bss_data
                    .as_ref()
                    .unwrap()
                    .nr_event_dispatches;
                let nr_sticky = self
                    .skel
                    .maps
                    .bss_data
                    .as_ref()
                    .unwrap()
                    .nr_ev_sticky_dispatches;
                let elapsed_secs = last_update.elapsed().as_secs_f64();
                if elapsed_secs > 0.0 {
                    let migration_rate =
                        (nr_event.saturating_sub(prev_nr_event_dispatches) as f64) / elapsed_secs;
                    let sticky_rate = (nr_sticky.saturating_sub(prev_nr_ev_sticky_dispatches)
                        as f64)
                        / elapsed_secs;

                    let bss = self.skel.maps.bss_data.as_mut().unwrap();
                    // Dynamic threshold only when user did not specify a value (threshold == 0).
                    if self.opts.perf_config > 0 && self.opts.perf_threshold == 0 {
                        let base = 0u64; // dynamic mode: use 0 so clamp is [1, u64::MAX]
                        let current = bss.perf_threshold;
                        let new_thresh = adjust_dynamic_threshold(current, migration_rate, base);
                        if new_thresh != current {
                            bss.perf_threshold = new_thresh;
                            if self.opts.verbose {
                                info!(
                                    "perf_threshold: {} (migration rate {:.1}/s)",
                                    new_thresh, migration_rate
                                );
                            }
                        }
                    }
                    if self.opts.perf_sticky > 0 && self.opts.perf_sticky_threshold == 0 {
                        let base = 0u64;
                        let current = bss.perf_sticky_threshold;
                        let new_thresh = adjust_dynamic_threshold(current, sticky_rate, base);
                        if new_thresh != current {
                            bss.perf_sticky_threshold = new_thresh;
                            if self.opts.verbose {
                                info!(
                                    "perf_sticky_threshold: {} (sticky rate {:.1}/s)",
                                    new_thresh, sticky_rate
                                );
                            }
                        }
                    }

                    prev_nr_event_dispatches = nr_event;
                    prev_nr_ev_sticky_dispatches = nr_sticky;
                }

                // GPU PID sync is throttled to GPU_SYNC_INTERVAL (NVML is expensive).
                if self.gpu_index_to_node.is_some() && last_gpu_sync.elapsed() >= GPU_SYNC_INTERVAL
                {
                    if let Err(e) = self.sync_gpu_pids() {
                        debug!("GPU PID sync: {}", e);
                    }
                    last_gpu_sync = Instant::now();
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
