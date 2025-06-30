// SPDX-License-Identifier: GPL-2.0
//
// Copyright (c) 2024 Andrea Righi <andrea.righi@linux.dev>

// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

mod bpf_skel;
pub use bpf_skel::*;
pub mod bpf_intf;
pub use bpf_intf::*;

// DSQ mode constants
const DSQ_MODE_CPU: u32 = 1;
const DSQ_MODE_SHARED: u32 = 2;

// CPU mask type constants
const MASK_TYPE_PRIMARY: i32 = 0;
const MASK_TYPE_BIG: i32 = 1;
const MASK_TYPE_LITTLE: i32 = 2;
const MASK_TYPE_TURBO: i32 = 3;

mod stats;
use std::collections::BTreeMap;
use std::ffi::c_int;
use std::fmt::Write;
use std::mem::MaybeUninit;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use anyhow::Result;
use clap::Parser;
use crossbeam::channel::RecvTimeoutError;
use libbpf_rs::OpenObject;
use libbpf_rs::ProgramInput;
use libbpf_rs::OpenProgramImpl;
use libbpf_rs::AsRawLibbpf;
use libbpf_rs::libbpf_sys::bpf_program__set_autoload;

use log::warn;
use log::{debug, info};
use scx_stats::prelude::*;
use scx_utils::autopower::{fetch_power_profile, PowerProfile};
use scx_utils::build_id;
use scx_utils::compat;
use scx_utils::pm::{cpu_idle_resume_latency_supported, update_cpu_idle_resume_latency};
use scx_utils::scx_ops_attach;
use scx_utils::scx_ops_load;
use scx_utils::scx_ops_open;
use scx_utils::set_rlimit_infinity;
use scx_utils::uei_exited;
use scx_utils::uei_report;
use scx_utils::CoreType;
use scx_utils::Cpumask;
use scx_utils::Topology;
use scx_utils::UserExitInfo;
use scx_utils::NR_CPU_IDS;
use stats::Metrics;

const SCHEDULER_NAME: &str = "scx_spark";

#[derive(PartialEq)]
enum Powermode {
    Performance,
    Powersave,
    Any,
}

fn get_primary_cpus(mode: Powermode) -> std::io::Result<Vec<usize>> {
    let topo = Topology::new().unwrap();

    let cpus: Vec<usize> = topo
        .all_cores
        .values()
        .flat_map(|core| &core.cpus)
        .filter_map(|(cpu_id, cpu)| match (&mode, &cpu.core_type) {
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

fn get_big_cpus() -> std::io::Result<Vec<usize>> {
    let topo = Topology::new().unwrap();

    let cpus: Vec<usize> = topo
        .all_cores
        .values()
        .flat_map(|core| &core.cpus)
        .filter_map(|(cpu_id, cpu)| match &cpu.core_type {
            CoreType::Big { .. } => Some(*cpu_id),
            _ => None,
        })
        .collect();

    Ok(cpus)
}

fn get_little_cpus() -> std::io::Result<Vec<usize>> {
    let topo = Topology::new().unwrap();

    let cpus: Vec<usize> = topo
        .all_cores
        .values()
        .flat_map(|core| &core.cpus)
        .filter_map(|(cpu_id, cpu)| match &cpu.core_type {
            CoreType::Little => Some(*cpu_id),
            _ => None,
        })
        .collect();

    Ok(cpus)
}

/// Get a list of CPU IDs that have turbo boost capability.
fn get_turbo_cpus() -> std::io::Result<Vec<usize>> {
    let topo = Topology::new().unwrap();

    let cpus: Vec<usize> = topo
        .all_cores
        .values()
        .flat_map(|core| &core.cpus)
        .filter_map(|(cpu_id, cpu)| match &cpu.core_type {
            CoreType::Big { turbo: true } => Some(*cpu_id),
            _ => None,
        })
        .collect();

    Ok(cpus)
}

// Convert an array of CPUs to the corresponding cpumask of any arbitrary size.
fn cpus_to_cpumask(cpus: &Vec<usize>) -> String {
    if cpus.is_empty() {
        return String::from("none");
    }

    // Determine the maximum CPU ID to create a sufficiently large byte vector.
    let max_cpu_id = *cpus.iter().max().unwrap();

    // Create a byte vector with enough bytes to cover all CPU IDs.
    let mut bitmask = vec![0u8; (max_cpu_id + 1 + 7) / 8];

    // Set the appropriate bits for each CPU ID.
    for cpu_id in cpus {
        let byte_index = cpu_id / 8;
        let bit_index = cpu_id % 8;
        bitmask[byte_index] |= 1 << bit_index;
    }

    // Convert the byte vector to a hexadecimal string.
    let hex_str: String = bitmask.iter().rev().fold(String::new(), |mut f, byte| {
        let _ = write!(&mut f, "{:02x}", byte);
        f
    });

    format!("0x{}", hex_str)
}

/// scx_bpfland: a vruntime-based sched_ext scheduler that prioritizes interactive workloads.
///
/// This scheduler is derived from scx_rustland, but it is fully implemented in BPF. It has a minimal
/// user-space part written in Rust to process command line options, collect metrics and log out
/// scheduling statistics.
///
/// The BPF part makes all the scheduling decisions (see src/bpf/main.bpf.c).
#[derive(Debug, Parser)]
struct Opts {
    /// Exit debug dump buffer length. 0 indicates default.
    #[clap(long, default_value = "0")]
    exit_dump_len: u32,

    /// Maximum scheduling slice duration in microseconds.
    #[clap(short = 's', long, default_value = "20000")]
    slice_us: u64,

    /// Minimum scheduling slice duration in microseconds.
    #[clap(short = 'S', long, default_value = "1000")]
    slice_us_min: u64,

    /// Maximum time slice lag in microseconds.
    ///
    /// A positive value can help to enhance the responsiveness of interactive tasks, but it can
    /// also make performance more "spikey".
    ///
    /// A negative value can make performance more consistent, but it can also reduce the
    /// responsiveness of interactive tasks (by smoothing the effect of the vruntime scheduling and
    /// making the task ordering closer to a FIFO).
    #[clap(short = 'l', long, allow_hyphen_values = true, default_value = "20000")]
    slice_us_lag: i64,

    /// Throttle the running CPUs by periodically injecting idle cycles.
    ///
    /// This option can help extend battery life on portable devices, reduce heating, fan noise
    /// and overall energy consumption (0 = disable).
    #[clap(short = 't', long, default_value = "0")]
    throttle_us: u64,

    /// Set CPU idle QoS resume latency in microseconds (-1 = disabled).
    ///
    /// Setting a lower latency value makes CPUs less likely to enter deeper idle states, enhancing
    /// performance at the cost of higher power consumption. Alternatively, increasing the latency
    /// value may reduce performance, but also improve power efficiency.
    #[clap(short = 'I', long, allow_hyphen_values = true, default_value = "-1")]
    idle_resume_us: i64,

    /// Disable preemption.
    ///
    /// Never allow tasks to be directly dispatched. This can help to increase fairness
    /// over responsiveness.
    #[clap(short = 'n', long, action = clap::ArgAction::SetTrue)]
    no_preempt: bool,

    /// Enable per-CPU tasks prioritization.
    ///
    /// This allows to prioritize per-CPU tasks that usually tend to be de-prioritized (since they
    /// can't be migrated when their only usable CPU is busy). Enabling this option can introduce
    /// unfairness and potentially trigger stalls, but it can improve performance of server-type
    /// workloads (such as large parallel builds).
    #[clap(short = 'p', long, action = clap::ArgAction::SetTrue)]
    local_pcpu: bool,

    /// Enable kthreads prioritization (EXPERIMENTAL).
    ///
    /// Enabling this can improve system performance, but it may also introduce noticeable
    /// interactivity issues or unfairness in scenarios with high kthread activity, such as heavy
    /// I/O or network traffic.
    ///
    /// Use it only when conducting specific experiments or if you have a clear understanding of
    /// its implications.
    #[clap(short = 'k', long, action = clap::ArgAction::SetTrue)]
    local_kthreads: bool,

    /// Keep tasks on CPUs where kthreads are running (EXPERIMENTAL).
    ///
    /// When enabled, tasks will tend to stay on CPUs that currently have active kernel threads
    /// instead of migrating to other CPUs. This can help with cache locality and reduce
    /// context switching overhead in kthread-heavy workloads.
    #[clap(long, action = clap::ArgAction::SetTrue)]
    stay_with_kthread: bool,

    /// Disable direct dispatch during synchronous wakeups.
    ///
    /// Enabling this option can lead to a more uniform load distribution across available cores,
    /// potentially improving performance in certain scenarios. However, it may come at the cost of
    /// reduced efficiency for pipe-intensive workloads that benefit from tighter producer-consumer
    /// coupling.
    #[clap(short = 'w', long, action = clap::ArgAction::SetTrue)]
    no_wake_sync: bool,

    /// Specifies the initial set of CPUs, represented as a bitmask in hex (e.g., 0xff), that the
    /// scheduler will use to dispatch tasks, until the system becomes saturated, at which point
    /// tasks may overflow to other available CPUs.
    ///
    /// Special values:
    ///  - "auto" = automatically detect the CPUs based on the active power profile
    ///  - "performance" = automatically detect and prioritize the fastest CPUs
    ///  - "powersave" = automatically detect and prioritize the slowest CPUs
    ///  - "all" = all CPUs assigned to the primary domain
    ///  - "none" = no prioritization, tasks are dispatched on the first CPU available
    #[clap(short = 'm', long, default_value = "auto")]
    primary_domain: String,

    /// Disable L3 cache awareness.
    #[clap(long, action = clap::ArgAction::SetTrue)]
    disable_l3: bool,

    /// DSQ dispatch mode.
    ///
    /// This option determines how dispatch queues (DSQs) are organized:
    ///  - "cpu" = per-CPU DSQs (best for CPU affinity and cache locality)
    ///  - "shared" = single shared DSQ for all CPUs (default, simplest, good for uniform workloads)
    #[clap(long, default_value = "shared")]
    dsq_mode: String,

    /// Enable CPU frequency control (only with schedutil governor).
    ///
    /// With this option enabled the CPU frequency will be automatically scaled based on the load.
    #[clap(short = 'f', long, action = clap::ArgAction::SetTrue)]
    cpufreq: bool,

    /// [DEPRECATED] Maximum threshold of voluntary context switches per second. This is used to
    /// classify interactive.
    ///
    /// tasks (0 = disable interactive tasks classification).
    #[clap(short = 'c', long, default_value = "10", hide = true)]
    nvcsw_max_thresh: u64,

    /// Enable stats monitoring with the specified interval.
    #[clap(long)]
    stats: Option<f64>,

    /// Run in stats monitoring mode with the specified interval. Scheduler
    /// is not launched.
    #[clap(long)]
    monitor: Option<f64>,

    /// Enable BPF debugging via /sys/kernel/tracing/trace_pipe.
    #[clap(short = 'd', long, action = clap::ArgAction::SetTrue)]
    debug: bool,


    /// Enable GPU support for task detection and prioritization.
    ///
    /// When enabled, tasks that use GPU operations (detected via kprobes on NVIDIA driver
    /// functions) will be prioritized on fast cores to improve GPU-CPU coordination.
    #[clap(long, action = clap::ArgAction::SetTrue)]
    enable_gpu_support: bool,

    /// Aggressive GPU task mode: only GPU tasks can use big/performance cores.
    ///
    /// When enabled with --enable-gpu-support, non-GPU tasks will be restricted to
    /// non-primary domain CPUs (little cores in big.LITTLE systems), ensuring that
    /// only GPU tasks can utilize the fastest cores for maximum GPU-CPU coordination.
    #[clap(long, action = clap::ArgAction::SetTrue)]
    aggressive_gpu_tasks: bool,

    /// Enable advanced workload type detection for ML workloads.
    ///
    /// When enabled, the scheduler will attempt to classify tasks as inference,
    /// training, validation, preprocessing, data loading, or model loading based
    /// on process names, GPU usage patterns, and system call behavior.
    #[clap(long, action = clap::ArgAction::SetTrue)]
    enable_workload_detection: bool,

    /// Workload-aware scheduling mode.
    ///
    /// When enabled with --enable-workload-detection, the scheduler will make
    /// CPU selection decisions based on workload type: inference tasks get
    /// priority on big cores, data loading/preprocessing prefer little cores,
    /// and training tasks can use either based on availability.
    #[clap(long, action = clap::ArgAction::SetTrue)]
    workload_aware_scheduling: bool,

    /// Enable verbose output, including libbpf details.
    #[clap(short = 'v', long, action = clap::ArgAction::SetTrue)]
    verbose: bool,

    /// Print scheduler version and exit.
    #[clap(short = 'V', long, action = clap::ArgAction::SetTrue)]
    version: bool,

    /// Show descriptions for statistics.
    #[clap(long)]
    help_stats: bool,
}

struct Scheduler<'a> {
    skel: BpfSkel<'a>,
    struct_ops: Option<libbpf_rs::Link>,
    opts: &'a Opts,
    topo: Topology,
    power_profile: PowerProfile,
    stats_server: StatsServer<(), Metrics>,
    user_restart: bool,
}

impl<'a> Scheduler<'a> {
    fn init(opts: &'a Opts, open_object: &'a mut MaybeUninit<OpenObject>) -> Result<Self> {
        set_rlimit_infinity();

        // Validate command line arguments.
        assert!(opts.slice_us >= opts.slice_us_min);
        assert!(matches!(opts.dsq_mode.as_str(), "cpu" | "shared"),
                "Invalid DSQ mode: '{}'. Valid options: cpu, shared", opts.dsq_mode);

        // Initialize CPU topology.
        let topo = Topology::new().unwrap();

        let dsq_mode_str = match opts.dsq_mode.as_str() {
            "cpu" => "per-CPU DSQs",
            "shared" | _ => "shared DSQ",
        };

        info!(
            "{} {} ({})",
            SCHEDULER_NAME,
            build_id::full_version(env!("CARGO_PKG_VERSION")),
            dsq_mode_str
        );

        if opts.idle_resume_us >= 0 {
            if !cpu_idle_resume_latency_supported() {
                warn!("idle resume latency not supported");
            } else {
                info!("Setting idle QoS to {} us", opts.idle_resume_us);
                for cpu in topo.all_cpus.values() {
                    update_cpu_idle_resume_latency(
                        cpu.id,
                        opts.idle_resume_us.try_into().unwrap(),
                    )?;
                }
            }
        }

        // Initialize BPF connector.
        let mut skel_builder = BpfSkelBuilder::default();
        skel_builder.obj_builder.debug(opts.verbose);
        let mut skel = scx_ops_open!(skel_builder, open_object, bpfland_ops)?;

        skel.struct_ops.bpfland_ops_mut().exit_dump_len = opts.exit_dump_len;

        // Override default BPF scheduling parameters.
        skel.maps.rodata_data.debug = opts.debug;
        skel.maps.rodata_data.local_pcpu = opts.local_pcpu;
        skel.maps.rodata_data.no_preempt = opts.no_preempt;
        skel.maps.rodata_data.no_wake_sync = opts.no_wake_sync;
        skel.maps.rodata_data.slice_max = opts.slice_us * 1000;
        skel.maps.rodata_data.slice_min = opts.slice_us_min * 1000;
        skel.maps.rodata_data.slice_lag = opts.slice_us_lag * 1000;
        skel.maps.rodata_data.throttle_ns = opts.throttle_us * 1000;
        skel.maps.rodata_data.dsq_mode = match opts.dsq_mode.as_str() {
            "cpu" => DSQ_MODE_CPU,
            "shared" | _ => DSQ_MODE_SHARED,
        };

        skel.maps.rodata_data.enable_gpu_support = opts.enable_gpu_support;

        if opts.enable_gpu_support {
            info!("GPU support enabled.");
        }

        skel.maps.rodata_data.aggressive_gpu_tasks = opts.aggressive_gpu_tasks && opts.enable_gpu_support;

    if opts.aggressive_gpu_tasks && !opts.enable_gpu_support {
            return Err(anyhow::anyhow!(
                "Error: --aggressive-gpu-tasks requires --enable-gpu-support to be enabled.\n\n\
                Correct usage:\n\
                sudo scx_spark --enable-gpu-support --aggressive-gpu-tasks\n\n"
            ));
        }

        if opts.enable_workload_detection {
            info!("Woorkload detection enabled. Classifying ML workloads");
            if opts.workload_aware_scheduling {
                info!("Workload-aware scheduling enabled. Optimizing CPU selection based on workload type");
            }
        }

        // Implicitly enable direct dispatch of per-CPU kthreads if CPU throttling is enabled
        // (it's never a good idea to throttle per-CPU kthreads).
        skel.maps.rodata_data.local_kthreads = opts.local_kthreads || opts.throttle_us > 0;
        skel.maps.rodata_data.stay_with_kthread = opts.stay_with_kthread;

        // Set scheduler flags.
        skel.struct_ops.bpfland_ops_mut().flags = *compat::SCX_OPS_ENQ_EXITING
            | *compat::SCX_OPS_ENQ_LAST
            | *compat::SCX_OPS_ENQ_MIGRATION_DISABLED
            | *compat::SCX_OPS_ALLOW_QUEUED_WAKEUP;
        info!(
            "scheduler flags: {:#x}",
            skel.struct_ops.bpfland_ops_mut().flags
        );
                   
        if !opts.enable_gpu_support {
            unsafe {
                bpf_program__set_autoload(
                    skel.progs
                        .kprobe_nvidia_poll
                        .as_libbpf_object()
                        .as_ptr(),
                    false,
                );
               
                    bpf_program__set_autoload(
                        skel.progs
                            .kprobe_nvidia_open
                            .as_libbpf_object()
                            .as_ptr(),
                        false,
                    );
            
                    bpf_program__set_autoload(
                        skel.progs
                            .kprobe_nvidia_mmap
                            .as_libbpf_object()
                            .as_ptr(),
                        false,
                    );
                }
        }

        // Load the BPF program for validation.
        let mut skel = scx_ops_load!(skel, bpfland_ops, uei)?;


        // Initialize the primary scheduling domain and the preferred domain.
        let power_profile = Self::power_profile();
        if let Err(err) = Self::init_energy_domain(&mut skel, &opts.primary_domain, power_profile) {
            warn!("failed to initialize primary domain: error {}", err);
        }
        if let Err(err) = Self::init_cpufreq_perf(&mut skel, &opts.primary_domain, opts.cpufreq) {
            warn!(
                "failed to initialize cpufreq performance level: error {}",
                err
            );
        }

        // Initialize L3 cache domains.
        if !opts.disable_l3 {
            Self::init_l3_cache_domains(&mut skel, &topo)?;
        }

        // Initialize big and little CPU domains.
        if let Err(err) = Self::init_big_cpu_domain(&mut skel) {
            warn!("failed to initialize big CPU domain: error {}", err);
        }
        if let Err(err) = Self::init_little_cpu_domain(&mut skel) {
            warn!("failed to initialize little CPU domain: error {}", err);
        }

        // Attach the scheduler.
        let struct_ops = Some(scx_ops_attach!(skel, bpfland_ops)?);
        
        let stats_server = StatsServer::new(stats::server_data()).launch()?;

        Ok(Self {
            skel,
            struct_ops,
            opts,
            topo,
            power_profile,
            stats_server,
            user_restart: false,
        })
    }

    fn enable_cpu(skel: &mut BpfSkel<'_>, cpu: i32, mask_type: i32) -> Result<(), u32> {
        let prog = &mut skel.progs.enable_cpu;
        let mut args = enable_cpu_arg {
            cpu_id: cpu as c_int,
            mask_type: mask_type as c_int,
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

    fn epp_to_cpumask(profile: Powermode) -> Result<Cpumask> {
        let mut cpus = get_primary_cpus(profile).unwrap_or_default();
        if cpus.is_empty() {
            cpus = get_primary_cpus(Powermode::Any).unwrap_or_default();
        }
        Cpumask::from_str(&cpus_to_cpumask(&cpus))
    }

    fn init_energy_domain(
        skel: &mut BpfSkel<'_>,
        primary_domain: &str,
        power_profile: PowerProfile,
    ) -> Result<()> {
        let domain = match primary_domain {
            "powersave" => Self::epp_to_cpumask(Powermode::Powersave)?,
            "performance" => Self::epp_to_cpumask(Powermode::Performance)?,
            "auto" => match power_profile {
                PowerProfile::Powersave => Self::epp_to_cpumask(Powermode::Powersave)?,
                PowerProfile::Balanced { power: true } => {
                    Self::epp_to_cpumask(Powermode::Powersave)?
                }
                PowerProfile::Balanced { power: false } => Self::epp_to_cpumask(Powermode::Any)?,
                PowerProfile::Performance => Self::epp_to_cpumask(Powermode::Any)?,
                PowerProfile::Unknown => Self::epp_to_cpumask(Powermode::Any)?,
            },
            "all" => Self::epp_to_cpumask(Powermode::Any)?,
            &_ => Cpumask::from_str(primary_domain)?,
        };

        info!("primary CPU domain = 0x{:x}", domain);

        // Clear the primary domain by passing a negative CPU id.
        if let Err(err) = Self::enable_cpu(skel, -1, MASK_TYPE_PRIMARY) {
            warn!("failed to reset primary domain: error {}", err);
        }
        // Update primary scheduling domain.
        for cpu in 0..*NR_CPU_IDS {
            if domain.test_cpu(cpu) {
                if let Err(err) = Self::enable_cpu(skel, cpu as i32, MASK_TYPE_PRIMARY) {
                    warn!("failed to add CPU {} to primary domain: error {}", cpu, err);
                }
            }
        }

        Ok(())
    }

    fn init_big_cpu_domain(skel: &mut BpfSkel<'_>) -> Result<()> {
        let big_cpus = get_big_cpus()?;
        
        if big_cpus.is_empty() {
            info!("No big cores detected in the system");
            return Ok(());
        }

        info!("Big cores detected: {:?}", big_cpus);

        // Clear the big domain by passing a negative CPU id.
        if let Err(err) = Self::enable_cpu(skel, -1, MASK_TYPE_BIG) {
            warn!("failed to reset big domain: error {}", err);
        }
        
        for cpu in big_cpus {
            if let Err(err) = Self::enable_cpu(skel, cpu as i32, MASK_TYPE_BIG) {
                warn!("failed to add CPU {} to big domain: error {}", cpu, err);
            }
        }

        // Also add big CPUs with turbo capability to the turbo cpumask
        let turbo_cpus = get_turbo_cpus()?;
        println!("Turbo CPUs: {:?}", turbo_cpus);
        if !turbo_cpus.is_empty() {
            info!("Big cores with turbo capability detected: {:?}", turbo_cpus);
            
            // Clear the turbo domain by passing a negative CPU id.
            if let Err(err) = Self::enable_cpu(skel, -1, MASK_TYPE_TURBO) {
                warn!("failed to reset turbo domain: error {}", err);
            }
            
            for cpu in turbo_cpus {
                if let Err(err) = Self::enable_cpu(skel, cpu as i32, MASK_TYPE_TURBO) {
                    warn!("failed to add CPU {} to turbo domain: error {}", cpu, err);
                }
            }
        }

        Ok(())
    }

    fn init_little_cpu_domain(skel: &mut BpfSkel<'_>) -> Result<()> {
        let little_cpus = get_little_cpus()?;
        
        if little_cpus.is_empty() {
            info!("No little cores detected in the system");
            return Ok(());
        }

        info!("Little cores detected: {:?}", little_cpus);

        // Clear the little domain by passing a negative CPU id.
        if let Err(err) = Self::enable_cpu(skel, -1, MASK_TYPE_LITTLE) {
            warn!("failed to reset little domain: error {}", err);
        }
        
        for cpu in little_cpus {
            if let Err(err) = Self::enable_cpu(skel, cpu as i32, MASK_TYPE_LITTLE) {
                warn!("failed to add CPU {} to little domain: error {}", cpu, err);
            }
        }

        Ok(())
    }

    // Update hint for the cpufreq governor.
    fn init_cpufreq_perf(
        skel: &mut BpfSkel<'_>,
        primary_domain: &String,
        auto: bool,
    ) -> Result<()> {
        // If we are using the powersave profile always scale the CPU frequency to the minimum,
        // otherwise use the maximum, unless automatic frequency scaling is enabled.
        let perf_lvl: i64 = match primary_domain.as_str() {
            "powersave" => 0,
            _ if auto => -1,
            _ => 1024,
        };
        info!(
            "cpufreq performance level: {}",
            match perf_lvl {
                1024 => "max".into(),
                0 => "min".into(),
                n if n < 0 => "auto".into(),
                _ => perf_lvl.to_string(),
            }
        );
        skel.maps.bss_data.cpufreq_perf_lvl = perf_lvl;

        Ok(())
    }

    fn power_profile() -> PowerProfile {
        let profile = fetch_power_profile(true);
        if profile == PowerProfile::Unknown {
            fetch_power_profile(false)
        } else {
            profile
        }
    }

    fn refresh_sched_domain(&mut self) -> bool {
        if self.power_profile != PowerProfile::Unknown {
            let power_profile = Self::power_profile();
            if power_profile != self.power_profile {
                self.power_profile = power_profile;

                if self.opts.primary_domain == "auto" {
                    return true;
                }
                if let Err(err) = Self::init_cpufreq_perf(
                    &mut self.skel,
                    &self.opts.primary_domain,
                    self.opts.cpufreq,
                ) {
                    warn!("failed to refresh cpufreq performance level: error {}", err);
                }
            }
        }

        false
    }

    fn enable_sibling_cpu(
        skel: &mut BpfSkel<'_>,
        lvl: usize,
        cpu: usize,
        sibling_cpu: usize,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let prog = &mut skel.progs.enable_sibling_cpu;
        let mut args = domain_arg {
            lvl_id: lvl as c_int,
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
        let out = prog.test_run(input)?;
        if out.return_value != 0 {
            return Err(format!("BPF function returned error: {}", out.return_value).into());
        }

        Ok(())
    }

    fn init_cache_domains(
        skel: &mut BpfSkel<'_>,
        topo: &Topology,
        cache_lvl: usize,
        enable_sibling_cpu_fn: &dyn Fn(&mut BpfSkel<'_>, usize, usize, usize) -> Result<(), Box<dyn std::error::Error>>,
    ) -> Result<(), std::io::Error> {
        // Determine the list of CPU IDs associated to each cache node.
        let mut cache_id_map: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
        for core in topo.all_cores.values() {
            for (cpu_id, cpu) in &core.cpus {
                let cache_id = match cache_lvl {
                    3 => cpu.llc_id,
                    _ => panic!("invalid cache level {}", cache_lvl),
                };
                cache_id_map.entry(cache_id).or_default().push(*cpu_id);
            }
        }

        // Update the BPF cpumasks for the cache domains.
        for (cache_id, cpus) in cache_id_map {
            // Ignore the cache domain if it includes a single CPU.
            if cpus.len() <= 1 {
                continue;
            }

            info!(
                "L{} cache ID {}: sibling CPUs: {:?}",
                cache_lvl, cache_id, cpus
            );
            for cpu in &cpus {
                for sibling_cpu in &cpus {
                    if let Err(err) = enable_sibling_cpu_fn(skel, cache_lvl, *cpu, *sibling_cpu) {
                        warn!(
                            "L{} cache ID {}: failed to set CPU {} sibling {}: {}",
                            cache_lvl, cache_id, *cpu, *sibling_cpu, err
                        );
                    }
                }
            }
        }

        Ok(())
    }

    fn init_l3_cache_domains(
        skel: &mut BpfSkel<'_>,
        topo: &Topology,
    ) -> Result<(), std::io::Error> {
        Self::init_cache_domains(skel, topo, 3, &|skel, lvl, cpu, sibling_cpu| {
            Self::enable_sibling_cpu(skel, lvl, cpu, sibling_cpu)
        })
    }

    fn get_metrics(&self) -> Metrics {
        Metrics {
            nr_running: self.skel.maps.bss_data.nr_running,
            nr_cpus: self.skel.maps.bss_data.nr_online_cpus,
            nr_kthread_dispatches: self.skel.maps.bss_data.nr_kthread_dispatches,
            nr_direct_dispatches: self.skel.maps.bss_data.nr_direct_dispatches,
            nr_shared_dispatches: self.skel.maps.bss_data.nr_shared_dispatches,
            nr_gpu_task_dispatches: self.skel.maps.bss_data.nr_gpu_task_dispatches,
            nr_inference_dispatches: self.skel.maps.bss_data.nr_inference_dispatches,
            nr_training_dispatches: self.skel.maps.bss_data.nr_training_dispatches,
            nr_validation_dispatches: self.skel.maps.bss_data.nr_validation_dispatches,
            nr_preprocessing_dispatches: self.skel.maps.bss_data.nr_preprocessing_dispatches,
            nr_data_loading_dispatches: self.skel.maps.bss_data.nr_data_loading_dispatches,
            nr_model_loading_dispatches: self.skel.maps.bss_data.nr_model_loading_dispatches,
        }
    }


    pub fn exited(&mut self) -> bool {
        uei_exited!(&self.skel, uei)
    }

    fn run(&mut self, shutdown: Arc<AtomicBool>) -> Result<UserExitInfo> {
        let (res_ch, req_ch) = self.stats_server.channels();
        while !shutdown.load(Ordering::Relaxed) && !self.exited() {
            if self.refresh_sched_domain() {
                self.user_restart = true;
                break;
            }
            match req_ch.recv_timeout(Duration::from_secs(1)) {
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
        info!("Unregister {} scheduler", SCHEDULER_NAME);

        // Restore default CPU idle QoS resume latency.
        if self.opts.idle_resume_us >= 0 {
            if cpu_idle_resume_latency_supported() {
                for cpu in self.topo.all_cpus.values() {
                    update_cpu_idle_resume_latency(cpu.id, cpu.pm_qos_resume_latency_us as i32)
                        .unwrap();
                }
            }
        }
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
    lcfg.set_time_level(simplelog::LevelFilter::Error)
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
            if sched.user_restart {
                continue;
            }
            break;
        }
    }

    Ok(())
}
