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
use std::ffi::c_int;
use std::fmt::Write;
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
accumulate while sleeping is capped by `slice_lag`: tasks that sleep frequently can receive a larger
credit, while tasks that perform fewer, longer sleeps are granted a smaller credit. This encourages
responsive behavior without excessively boosting idle tasks.

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
    #[clap(short = 's', long, default_value = "700")]
    slice_us: u64,

    /// Maximum runtime budget that a task can accumulate while sleeping (in microseconds).
    ///
    /// Increasing this value can help to enhance the responsiveness of interactive tasks, but it
    /// can also make performance more "spikey".
    #[clap(short = 'l', long, default_value = "20000")]
    slice_us_lag: u64,

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
        rodata.tickless_sched = opts.tickless;
        rodata.slice_max = opts.slice_us * 1000;
        rodata.slice_lag = opts.slice_us_lag * 1000;
        rodata.throttle_ns = opts.throttle_us * 1000;
        rodata.primary_all = domain.weight() == *NR_CPU_IDS;

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
