// SPDX-License-Identifier: GPL-2.0
//
// Copyright (c) 2024 Andrea Righi <arighi@nvidia.com>

// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

mod bpf_skel;
pub use bpf_skel::*;
pub mod bpf_intf;
pub use bpf_intf::*;

mod stats;
use std::collections::BTreeMap;
use std::ffi::c_int;
use std::fmt::Write;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::mem::MaybeUninit;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use anyhow::anyhow;
use anyhow::bail;
use anyhow::Context;
use anyhow::Result;
use clap::Parser;
use crossbeam::channel::RecvTimeoutError;
use libbpf_rs::OpenObject;
use libbpf_rs::ProgramInput;
use log::{debug, info, warn};
use scx_stats::prelude::*;
use scx_utils::autopower::{fetch_power_profile, PowerProfile};
use scx_utils::build_id;
use scx_utils::compat;
use scx_utils::libbpf_clap_opts::LibbpfOpts;
use scx_utils::pm::{cpu_idle_resume_latency_supported, update_cpu_idle_resume_latency};
use scx_utils::scx_ops_attach;
use scx_utils::scx_ops_load;
use scx_utils::scx_ops_open;
use scx_utils::try_set_rlimit_infinity;
use scx_utils::uei_exited;
use scx_utils::uei_report;
use scx_utils::CoreType;
use scx_utils::Cpumask;
use scx_utils::Topology;
use scx_utils::UserExitInfo;
use scx_utils::NR_CPU_IDS;
use stats::Metrics;

const SCHEDULER_NAME: &str = "scx_flash";

#[derive(PartialEq)]
enum Powermode {
    Turbo,
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

#[derive(Debug, clap::Parser)]
#[command(
    name = "scx_flash",
    version,
    disable_version_flag = true,
    about = "A deadline-based scheduler focused on fairness and performance predictability.",
    long_about = r#"
scx_flash is scheduler that focuses on ensuring fairness and performance predictability.

It operates using an earliest deadline first (EDF) policy. The deadline of each task deadline is
defined as:

    deadline = vruntime + exec_vruntime

Here, `vruntime` represents the task's total accumulated runtime, inversely scaled by its weight,
while `exec_vruntime` accounts for the scaled runtime accumulated since the last sleep event.

Fairness is driven by `vruntime`, while `exec_vruntime` helps prioritize latency-sensitive tasks
that sleep frequently and use the CPU in short bursts.

To prevent sleeping tasks from gaining excessive priority, the maximum vruntime credit a task can
accumulate while sleeping is capped by `slice_lag`, scaled by the task’s voluntary context switch
rate (`max_avg_nvcsw`): tasks that sleep frequently can receive a larger credit, while tasks that
perform fewer, longer sleeps are granted a smaller credit. This encourages responsive behavior
without excessively boosting idle tasks.

When dynamic fairness is enabled (`--slice-lag-scaling`), the maximum vruntime sleep credit is also
scaled depending on the user-mode CPU utilization:

 - At low utilization (mostly idle system), the impact of `vruntime` is reduced, and scheduling
   decisions are driven primarily by `exec_vruntime`. This favors bursty, latency-sensitive
   workloads (i.e., hackbench), improving their performance and latency.

 - At high utilization, sleeping tasks regain their vruntime credit, increasing the influence of
   `vruntime` in deadline calculation. This restores fairness and ensures system responsiveness
   under load.

This adaptive behavior allows the scheduler to prioritize intense message-passing workloads when
the system is lightly loaded, while maintaining fairness and responsiveness when the system is
saturated or overcommitted.
"#
)]
struct Opts {
    /// Exit debug dump buffer length. 0 indicates default.
    #[clap(long, default_value = "0")]
    exit_dump_len: u32,

    /// Maximum scheduling slice duration in microseconds.
    #[clap(short = 's', long, default_value = "4096")]
    slice_us: u64,

    /// Minimum scheduling slice duration in microseconds.
    #[clap(short = 'S', long, default_value = "128")]
    slice_us_min: u64,

    /// Maximum runtime budget that a task can accumulate while sleeping (in microseconds).
    ///
    /// Increasing this value can help to enhance the responsiveness of interactive tasks, but it
    /// can also make performance more "spikey".
    #[clap(short = 'l', long, default_value = "4096")]
    slice_us_lag: u64,

    /// Dynamically adjust task's maximum sleep budget based on CPU utilization.
    ///
    /// Enabling this option allows to increase the throughput of highly message passing workloads,
    /// but it can also reduce the overall system responsiveness.
    #[clap(short = 'L', long, action = clap::ArgAction::SetTrue)]
    slice_lag_scaling: bool,

    /// Maximum runtime penalty that a task can accumulate while running (in microseconds).
    ///
    /// Increasing this value can help to enhance the responsiveness of interactive tasks, but it
    /// can also make performance more "spikey".
    #[clap(short = 'r', long, default_value = "32768")]
    run_us_lag: u64,

    /// Maximum rate of voluntary context switches.
    ///
    /// Increasing this value can help prioritize interactive tasks with a higher sleep frequency
    /// over interactive tasks with lower sleep frequency.
    ///
    /// Decreasing this value makes the scheduler more robust and fair.
    ///
    /// (0 = disable voluntary context switch prioritization).
    #[clap(short = 'c', long, default_value = "128")]
    max_avg_nvcsw: u64,

    /// Utilization percentage to consider a CPU as busy (-1 = auto).
    ///
    /// A value close to 0 forces tasks to migrate quickier, increasing work conservation and
    /// potentially system responsiveness.
    ///
    /// A value close to 100 makes tasks more sticky to their CPU, increasing cache-sensivite and
    /// server-type workloads.
    ///
    /// In auto mode (-1) the scheduler autoomatically tries to determine the optimal value in
    /// function of the current workload.
    #[clap(short = 'C', long, allow_hyphen_values = true, default_value = "-1")]
    cpu_busy_thresh: i64,

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
    #[clap(short = 'I', long, allow_hyphen_values = true, default_value = "32")]
    idle_resume_us: i64,

    /// Enable tickless mode.
    ///
    /// This option enables tickless mode: tasks get an infinite time slice and they are preempted
    /// only in case of CPU contention. This can help reduce the OS noise and provide a better
    /// level of performance isolation.
    #[clap(short = 'T', long, action = clap::ArgAction::SetTrue)]
    tickless: bool,

    /// Enable round-robin scheduling.
    ///
    /// Each task is given a fixed time slice (defined by --slice-us) and run in a cyclic, fair
    /// order.
    #[clap(short = 'R', long, action = clap::ArgAction::SetTrue)]
    rr_sched: bool,

    /// Disable in-kernel idle CPU selection policy.
    ///
    /// Set this option to disable the in-kernel built-in idle CPU selection policy and rely on the
    /// custom CPU selection policy.
    #[clap(short = 'b', long, action = clap::ArgAction::SetTrue)]
    no_builtin_idle: bool,

    /// Enable per-CPU tasks prioritization.
    ///
    /// Enabling this option allows to prioritize per-CPU tasks that usually tend to be
    /// de-prioritized, since they can't be migrated when their only usable CPU is busy. This
    /// improves fairness, but it can also reduce the overall system throughput.
    ///
    /// This option is recommended for gaming or latency-sensitive workloads.
    #[clap(short = 'p', long, action = clap::ArgAction::SetTrue)]
    local_pcpu: bool,

    /// Always allow direct dispatch to idle CPUs.
    ///
    /// By default tasks are not directly dispatched to idle CPUs if there are other tasks waiting
    /// in the scheduler's queues. This prevents potential starvation of the already queued tasks.
    ///
    /// Enabling this option allows tasks to be always dispatched directly to idle CPUs,
    /// potentially bypassing the scheduler queues.
    ///
    /// This allows to improve system throughput, especially with server workloads, but it can
    /// introduce unfairness and potentially trigger stall conditions.
    #[clap(short = 'D', long, action = clap::ArgAction::SetTrue)]
    direct_dispatch: bool,

    /// Enable CPU stickiness.
    ///
    /// Enabling this option can reduce the amount of task migrations, but it can also make
    /// performance less consistent on systems with hybrid cores.
    ///
    /// This option has no effect if the primary scheduling domain includes all the CPUs
    /// (e.g., `--primary-domain all`).
    #[clap(short = 'y', long, action = clap::ArgAction::SetTrue)]
    sticky_cpu: bool,

    /// Native tasks priorities.
    ///
    /// By default, the scheduler normalizes task priorities to avoid large gaps that could lead to
    /// stalls or starvation. This option disables normalization and uses the default Linux priority
    /// range instead.
    #[clap(short = 'n', long, action = clap::ArgAction::SetTrue)]
    native_priority: bool,

    /// Enable per-CPU kthread prioritization.
    ///
    /// Enabling this can improve system performance, but it may also introduce interactivity
    /// issues or unfairness in scenarios with high kthread activity, such as heavy I/O or network
    /// traffic.
    #[clap(short = 'k', long, action = clap::ArgAction::SetTrue)]
    local_kthreads: bool,

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
    ///  - "turbo" = automatically detect and prioritize the CPUs with the highest max frequency
    ///  - "performance" = automatically detect and prioritize the fastest CPUs
    ///  - "powersave" = automatically detect and prioritize the slowest CPUs
    ///  - "all" = all CPUs assigned to the primary domain
    ///  - "none" = no prioritization, tasks are dispatched on the first CPU available
    #[clap(short = 'm', long, default_value = "auto")]
    primary_domain: String,

    /// Disable L2 cache awareness.
    #[clap(long, action = clap::ArgAction::SetTrue)]
    disable_l2: bool,

    /// Disable L3 cache awareness.
    #[clap(long, action = clap::ArgAction::SetTrue)]
    disable_l3: bool,

    /// Disable SMT awareness.
    #[clap(long, action = clap::ArgAction::SetTrue)]
    disable_smt: bool,

    /// Disable NUMA rebalancing.
    #[clap(long, action = clap::ArgAction::SetTrue)]
    disable_numa: bool,

    /// Enable CPU frequency control (only with schedutil governor).
    ///
    /// With this option enabled the CPU frequency will be automatically scaled based on the load.
    #[clap(short = 'f', long, action = clap::ArgAction::SetTrue)]
    cpufreq: bool,

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

#[derive(Debug, Clone, Copy)]
struct CpuTimes {
    user: u64,
    nice: u64,
    total: u64,
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
        try_set_rlimit_infinity();

        // Validate command line arguments.
        assert!(opts.slice_us >= opts.slice_us_min);

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

        // Determine the amount of non-empty NUMA nodes in the system.
        let nr_nodes = topo
            .nodes
            .values()
            .filter(|node| !node.all_cpus.is_empty())
            .count();
        info!("NUMA nodes: {}", nr_nodes);

        // Automatically disable NUMA optimizations when running on non-NUMA systems.
        let numa_disabled = opts.disable_numa || nr_nodes == 1;
        if numa_disabled {
            info!("Disabling NUMA optimizations");
        }

        // Determine the primary scheduling domain.
        let power_profile = Self::power_profile();
        let domain =
            Self::resolve_energy_domain(&opts.primary_domain, power_profile).map_err(|err| {
                anyhow!(
                    "failed to resolve primary domain '{}': {}",
                    &opts.primary_domain,
                    err
                )
            })?;

        // Initialize BPF connector.
        let mut skel_builder = BpfSkelBuilder::default();
        skel_builder.obj_builder.debug(opts.verbose);
        let open_opts = opts.libbpf.clone().into_bpf_open_opts();
        let mut skel = scx_ops_open!(skel_builder, open_object, flash_ops, open_opts)?;

        skel.struct_ops.flash_ops_mut().exit_dump_len = opts.exit_dump_len;

        // Override default BPF scheduling parameters.
        let rodata = skel.maps.rodata_data.as_mut().unwrap();
        rodata.debug = opts.debug;
        rodata.smt_enabled = smt_enabled;
        rodata.numa_disabled = numa_disabled;
        rodata.rr_sched = opts.rr_sched;
        rodata.local_pcpu = opts.local_pcpu;
        rodata.direct_dispatch = opts.direct_dispatch;
        rodata.sticky_cpu = opts.sticky_cpu;
        rodata.no_wake_sync = opts.no_wake_sync;
        rodata.tickless_sched = opts.tickless;
        rodata.native_priority = opts.native_priority;
        rodata.slice_lag_scaling = opts.slice_lag_scaling;
        rodata.builtin_idle = !opts.no_builtin_idle;
        rodata.slice_max = opts.slice_us * 1000;
        rodata.slice_min = opts.slice_us_min * 1000;
        rodata.slice_lag = opts.slice_us_lag * 1000;
        rodata.run_lag = opts.run_us_lag * 1000;
        rodata.throttle_ns = opts.throttle_us * 1000;
        rodata.max_avg_nvcsw = opts.max_avg_nvcsw;
        rodata.primary_all = domain.weight() == *NR_CPU_IDS;

        // Normalize CPU busy threshold in the range [0 .. 1024].
        rodata.cpu_busy_thresh = if opts.cpu_busy_thresh < 0 {
            opts.cpu_busy_thresh
        } else {
            opts.cpu_busy_thresh * 1024 / 100
        };

        // Implicitly enable direct dispatch of per-CPU kthreads if CPU throttling is enabled
        // (it's never a good idea to throttle per-CPU kthreads).
        rodata.local_kthreads = opts.local_kthreads || opts.throttle_us > 0;

        // Set scheduler compatibility flags.
        rodata.__COMPAT_SCX_PICK_IDLE_IN_NODE = *compat::SCX_PICK_IDLE_IN_NODE;

        // Set scheduler flags.
        skel.struct_ops.flash_ops_mut().flags = *compat::SCX_OPS_ENQ_EXITING
            | *compat::SCX_OPS_ENQ_LAST
            | *compat::SCX_OPS_ENQ_MIGRATION_DISABLED
            | *compat::SCX_OPS_ALLOW_QUEUED_WAKEUP
            | if numa_disabled {
                0
            } else {
                *compat::SCX_OPS_BUILTIN_IDLE_PER_NODE
            };
        info!(
            "scheduler flags: {:#x}",
            skel.struct_ops.flash_ops_mut().flags
        );

        // Load the BPF program for validation.
        let mut skel = scx_ops_load!(skel, flash_ops, uei)?;

        // Initialize the primary scheduling domain and the preferred domain.
        Self::init_energy_domain(&mut skel, &domain).map_err(|err| {
            anyhow!(
                "failed to initialize primary domain 0x{:x}: {}",
                domain,
                err
            )
        })?;

        if let Err(err) = Self::init_cpufreq_perf(&mut skel, &opts.primary_domain, opts.cpufreq) {
            bail!(
                "failed to initialize cpufreq performance level: error {}",
                err
            );
        }

        // Initialize SMT domains.
        if smt_enabled {
            Self::init_smt_domains(&mut skel, &topo)?;
        }

        // Initialize L2 cache domains.
        if !opts.disable_l2 {
            Self::init_l2_cache_domains(&mut skel, &topo)?;
        }
        // Initialize L3 cache domains.
        if !opts.disable_l3 {
            Self::init_l3_cache_domains(&mut skel, &topo)?;
        }

        // Attach the scheduler.
        let struct_ops = Some(scx_ops_attach!(skel, flash_ops)?);
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

    fn epp_to_cpumask(profile: Powermode) -> Result<Cpumask> {
        let mut cpus = get_primary_cpus(profile).unwrap_or_default();
        if cpus.is_empty() {
            cpus = get_primary_cpus(Powermode::Any).unwrap_or_default();
        }
        Cpumask::from_str(&cpus_to_cpumask(&cpus))
    }

    fn resolve_energy_domain(primary_domain: &str, power_profile: PowerProfile) -> Result<Cpumask> {
        let domain = match primary_domain {
            "powersave" => Self::epp_to_cpumask(Powermode::Powersave)?,
            "performance" => Self::epp_to_cpumask(Powermode::Performance)?,
            "turbo" => Self::epp_to_cpumask(Powermode::Turbo)?,
            "auto" => match power_profile {
                PowerProfile::Powersave => Self::epp_to_cpumask(Powermode::Powersave)?,
                PowerProfile::Balanced { power: true } => {
                    Self::epp_to_cpumask(Powermode::Powersave)?
                }
                PowerProfile::Balanced { power: false }
                | PowerProfile::Performance
                | PowerProfile::Unknown => Self::epp_to_cpumask(Powermode::Any)?,
            },
            "all" => Self::epp_to_cpumask(Powermode::Any)?,
            &_ => Cpumask::from_str(primary_domain)?,
        };

        Ok(domain)
    }

    fn init_energy_domain(skel: &mut BpfSkel<'_>, domain: &Cpumask) -> Result<()> {
        info!("primary CPU domain = 0x{:x}", domain);

        // Clear the primary domain by passing a negative CPU id.
        if let Err(err) = Self::enable_primary_cpu(skel, -1) {
            bail!("failed to reset primary domain: error {}", err);
        }

        // Update primary scheduling domain.
        for cpu in 0..*NR_CPU_IDS {
            if domain.test_cpu(cpu) {
                if let Err(err) = Self::enable_primary_cpu(skel, cpu as i32) {
                    bail!("failed to add CPU {} to primary domain: error {}", cpu, err);
                }
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
        skel.maps.bss_data.as_mut().unwrap().cpufreq_perf_lvl = perf_lvl;

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
    ) -> Result<(), u32> {
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
            Self::enable_sibling_cpu(skel, 0, cpu, *sibling_cpu as usize).unwrap();
        }

        Ok(())
    }

    fn are_smt_siblings(topo: &Topology, cpus: &[usize]) -> bool {
        // Single CPU or empty array are considered siblings.
        if cpus.len() <= 1 {
            return true;
        }

        // Check if each CPU is a sibling of the first CPU.
        let first_cpu = cpus[0];
        let smt_siblings = topo.sibling_cpus();
        cpus.iter().all(|&cpu| {
            cpu == first_cpu
                || smt_siblings[cpu] == first_cpu as i32
                || (smt_siblings[first_cpu] >= 0 && smt_siblings[first_cpu] == cpu as i32)
        })
    }

    fn init_cache_domains(
        skel: &mut BpfSkel<'_>,
        topo: &Topology,
        cache_lvl: usize,
        enable_sibling_cpu_fn: &dyn Fn(&mut BpfSkel<'_>, usize, usize, usize) -> Result<(), u32>,
    ) -> Result<(), std::io::Error> {
        // Determine the list of CPU IDs associated to each cache node.
        let mut cache_id_map: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
        for core in topo.all_cores.values() {
            for (cpu_id, cpu) in &core.cpus {
                let cache_id = match cache_lvl {
                    2 => cpu.l2_id,
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

            // Ignore the cache domain if all the CPUs are part of the same SMT core.
            if Self::are_smt_siblings(topo, &cpus) {
                continue;
            }

            info!(
                "L{} cache ID {}: sibling CPUs: {:?}",
                cache_lvl, cache_id, cpus
            );
            for cpu in &cpus {
                for sibling_cpu in &cpus {
                    if enable_sibling_cpu_fn(skel, cache_lvl, *cpu, *sibling_cpu).is_err() {
                        warn!(
                            "L{} cache ID {}: failed to set CPU {} sibling {}",
                            cache_lvl, cache_id, *cpu, *sibling_cpu
                        );
                    }
                }
            }
        }

        Ok(())
    }

    fn init_l2_cache_domains(
        skel: &mut BpfSkel<'_>,
        topo: &Topology,
    ) -> Result<(), std::io::Error> {
        Self::init_cache_domains(skel, topo, 2, &|skel, lvl, cpu, sibling_cpu| {
            Self::enable_sibling_cpu(skel, lvl, cpu, sibling_cpu)
        })
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
        let bss_data = self.skel.maps.bss_data.as_ref().unwrap();
        Metrics {
            nr_running: bss_data.nr_running,
            nr_cpus: bss_data.nr_online_cpus,
            nr_kthread_dispatches: bss_data.nr_kthread_dispatches,
            nr_direct_dispatches: bss_data.nr_direct_dispatches,
            nr_shared_dispatches: bss_data.nr_shared_dispatches,
        }
    }

    pub fn exited(&mut self) -> bool {
        uei_exited!(&self.skel, uei)
    }

    fn compute_user_cpu_pct(prev: &CpuTimes, curr: &CpuTimes) -> Option<u64> {
        let total_diff = curr.total.saturating_sub(prev.total);
        let user_diff = (curr.user + curr.nice).saturating_sub(prev.user + prev.nice);

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
        let mut prev_cputime = Self::read_cpu_times().expect("Failed to read initial CPU stats");
        let (res_ch, req_ch) = self.stats_server.channels();

        while !shutdown.load(Ordering::Relaxed) && !self.exited() {
            if self.refresh_sched_domain() {
                self.user_restart = true;
                break;
            }

            if self.opts.cpu_busy_thresh < 0 {
                if let Some(curr_cputime) = Self::read_cpu_times() {
                    if let Some(cpu_util) = Self::compute_user_cpu_pct(&prev_cputime, &curr_cputime)
                    {
                        self.skel.maps.bss_data.as_mut().unwrap().cpu_util = cpu_util;
                    }
                    prev_cputime = curr_cputime;
                }
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
        info!("Unregister {SCHEDULER_NAME} scheduler");

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
            if sched.user_restart {
                continue;
            }
            break;
        }
    }

    Ok(())
}
