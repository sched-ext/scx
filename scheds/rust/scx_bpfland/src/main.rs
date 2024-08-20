// SPDX-License-Identifier: GPL-2.0
//
// Copyright (c) 2024 Andrea Righi <andrea.righi@linux.dev>

// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

mod bpf_skel;
pub use bpf_skel::*;
pub mod bpf_intf;
pub use bpf_intf::*;

use std::collections::HashMap;
use std::ffi::c_int;
use std::fs::File;
use std::io::Read;
use std::mem::MaybeUninit;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use anyhow::bail;
use anyhow::Context;
use anyhow::Result;
use clap::Parser;
use log::info;
use log::warn;

use metrics::{gauge, Gauge};
use metrics_exporter_prometheus::PrometheusBuilder;

use rlimit::{getrlimit, setrlimit, Resource};

use libbpf_rs::skel::OpenSkel;
use libbpf_rs::skel::Skel;
use libbpf_rs::skel::SkelBuilder;
use libbpf_rs::OpenObject;
use libbpf_rs::ProgramInput;

use scx_utils::build_id;
use scx_utils::scx_ops_attach;
use scx_utils::scx_ops_load;
use scx_utils::scx_ops_open;
use scx_utils::uei_exited;
use scx_utils::uei_report;
use scx_utils::UserExitInfo;
use scx_utils::Cpumask;
use scx_utils::Topology;

const SCHEDULER_NAME: &'static str = "scx_bpfland";

fn get_primary_cpus(powersave: bool) -> std::io::Result<Vec<usize>> {
    let topo = Topology::new().unwrap();

    // Iterate over each CPU directory and collect CPU ID and its max frequency.
    let mut cpu_freqs = Vec::new();
    for core in topo.cores().into_iter() {
        for (cpu_id, cpu) in core.cpus() {
            cpu_freqs.push((*cpu_id, cpu.max_freq()));
        }
    }
    if cpu_freqs.is_empty() {
        return Ok(Vec::new());
    }

    // Find the smallest maximum frequency.
    let min_freq = cpu_freqs.iter().map(|&(_, freq)| freq).min().unwrap();

    // Check if all CPUs have the smallest frequency.
    let all_have_min_freq = cpu_freqs.iter().all(|&(_, freq)| freq == min_freq);

    let selected_cpu_ids: Vec<usize> = if all_have_min_freq {
        // If all CPUs have the smallest frequency, return all CPU IDs.
        cpu_freqs.into_iter().map(|(cpu_id, _)| cpu_id).collect()
    } else if powersave {
        // If powersave is true, return the CPUs with the smallest frequency.
        cpu_freqs.into_iter()
            .filter(|&(_, freq)| freq == min_freq)
            .map(|(cpu_id, _)| cpu_id)
            .collect()
    } else {
        // If powersave is false, return the CPUs with the highest frequency.
        cpu_freqs.into_iter()
            .filter(|&(_, freq)| freq != min_freq)
            .map(|(cpu_id, _)| cpu_id)
            .collect()
    };

    Ok(selected_cpu_ids)
}

// Convert an array of CPUs to the corresponding cpumask of any arbitrary size.
fn cpus_to_cpumask(cpus: &Vec<usize>) -> String {
    if cpus.is_empty() {
        return String::from("0x0");
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
    let hex_str: String = bitmask.iter()
        .rev()
        .map(|byte| format!("{:02x}", byte))
        .collect();

    format!("0x{}", hex_str)
}

fn parse_cpumask(cpu_str: &str) -> Result<Cpumask, anyhow::Error> {
    if cpu_str == "performance" {
        let cpus = get_primary_cpus(false).unwrap();
        Cpumask::from_str(&cpus_to_cpumask(&cpus))
    } else if cpu_str == "powersave" {
        let cpus = get_primary_cpus(true).unwrap();
        Cpumask::from_str(&cpus_to_cpumask(&cpus))
    } else if !cpu_str.is_empty() {
        Cpumask::from_str(&cpu_str.to_string())
    } else {
        let mut cpumask = Cpumask::new()?;
        cpumask.setall();

        Ok(cpumask)
    }
}

/// scx_bpfland: a vruntime-based sched_ext scheduler that prioritizes interactive workloads.
///
/// This scheduler is derived from scx_rustland, but it is fully implemented in BFP with minimal
/// user-space part written in Rust to process command line options, collect metrics and logs out
/// scheduling statistics.
///
/// The BPF part makes all the scheduling decisions (see src/bpf/main.bpf.c).
#[derive(Debug, Parser)]
struct Opts {
    /// Exit debug dump buffer length. 0 indicates default.
    #[clap(long, default_value = "0")]
    exit_dump_len: u32,

    /// Maximum scheduling slice duration in microseconds.
    #[clap(short = 's', long, default_value = "5000")]
    slice_us: u64,

    /// Minimum scheduling slice duration in microseconds.
    #[clap(short = 'S', long, default_value = "500")]
    slice_us_min: u64,

    /// Maximum time slice lag in microseconds.
    ///
    /// A positive value can help to enhance the responsiveness of interactive tasks, but it can
    /// also make performance more "spikey".
    ///
    /// A negative value can make performance more consistent, but it can also reduce the
    /// responsiveness of interactive tasks (by smoothing the effect of the vruntime scheduling and
    /// making the task ordering closer to a FIFO).
    #[clap(short = 'l', long, allow_hyphen_values = true, default_value = "0")]
    slice_us_lag: i64,

    /// Enable per-CPU kthreads prioritization.
    ///
    /// Enabling this can enhance the performance of interrupt-driven workloads (e.g., networking
    /// throughput) over regular system/user workloads. However, it may also introduce
    /// interactivity issues or unfairness under heavy interrupt-driven loads, such as high RX
    /// network traffic.
    #[clap(short = 'k', long, action = clap::ArgAction::SetTrue)]
    local_kthreads: bool,

    /// Specifies the initial set of CPUs, represented as a bitmask in hex (e.g., 0xff), that the
    /// scheduler will use to dispatch tasks, until the system becomes saturated, at which point
    /// tasks may overflow to other available CPUs.
    ///
    /// Special values:
    ///  - "performance" = automatically detect and use the fastest CPUs
    ///  - "powersave" = automatically detect and use the slowest CPUs
    ///
    /// By default all CPUs are used for the primary scheduling domain.
    #[clap(short = 'm', long, default_value = "", value_parser = parse_cpumask)]
    primary_domain: Cpumask,

    /// Disable L2 cache awareness.
    #[clap(long, action = clap::ArgAction::SetTrue)]
    disable_l2: bool,

    /// Disable L3 cache awareness.
    #[clap(long, action = clap::ArgAction::SetTrue)]
    disable_l3: bool,

    /// Maximum threshold of voluntary context switch per second, used to classify interactive
    /// tasks (0 = disable interactive tasks classification).
    #[clap(short = 'c', long, default_value = "10")]
    nvcsw_max_thresh: u64,

    /// Prevent the starvation making sure that at least one lower priority task is scheduled every
    /// starvation_thresh_us (0 = disable starvation prevention).
    #[clap(short = 't', long, default_value = "5000")]
    starvation_thresh_us: u64,

    /// Enable the Prometheus endpoint for metrics on port 9000.
    #[clap(short = 'p', long, action = clap::ArgAction::SetTrue)]
    enable_prometheus: bool,

    /// Enable BPF debugging via /sys/kernel/debug/tracing/trace_pipe.
    #[clap(short = 'd', long, action = clap::ArgAction::SetTrue)]
    debug: bool,

    /// Enable verbose output, including libbpf details.
    #[clap(short = 'v', long, action = clap::ArgAction::SetTrue)]
    verbose: bool,

    /// Print scheduler version and exit.
    #[clap(short = 'V', long, action = clap::ArgAction::SetTrue)]
    version: bool,
}

struct Metrics {
    nr_running: Gauge,
    nr_interactive: Gauge,
    nr_waiting: Gauge,
    nvcsw_avg_thresh: Gauge,
    nr_direct_dispatches: Gauge,
    nr_prio_dispatches: Gauge,
    nr_shared_dispatches: Gauge,
}

impl Metrics {
    fn new() -> Self {
        Metrics {
            nr_running: gauge!(
                "nr_running", "info" => "Number of running tasks"
            ),
            nr_interactive: gauge!(
                "nr_interactive", "info" => "Number of running interactive tasks"
            ),
            nr_waiting: gauge!(
                "nr_waiting", "info" => "Average amount of tasks waiting to be dispatched"
            ),
            nvcsw_avg_thresh: gauge!(
                "nvcsw_avg_thresh", "info" => "Average of voluntary context switches"
            ),
            nr_direct_dispatches: gauge!(
                "nr_direct_dispatches", "info" => "Number of task direct dispatches"
            ),
            nr_prio_dispatches: gauge!(
                "nr_prio_dispatches", "info" => "Number of interactive task dispatches"
            ),
            nr_shared_dispatches: gauge!(
                "nr_shared_dispatches", "info" => "Number of regular task dispatches"
            ),
        }
    }
}

fn is_smt_active() -> std::io::Result<i32> {
    let mut file = File::open("/sys/devices/system/cpu/smt/active")?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;

    let smt_active: i32 = contents.trim().parse().unwrap_or(0);

    Ok(smt_active)
}

struct Scheduler<'a> {
    skel: BpfSkel<'a>,
    struct_ops: Option<libbpf_rs::Link>,
    opts: &'a Opts,
    metrics: Metrics,
    cpu_hotplug_cnt: u64,
}

impl<'a> Scheduler<'a> {
    fn init(opts: &'a Opts, open_object: &'a mut MaybeUninit<OpenObject>) -> Result<Self> {
        let (soft_limit, _) = getrlimit(Resource::MEMLOCK).unwrap();
        setrlimit(Resource::MEMLOCK, soft_limit, rlimit::INFINITY).unwrap();

        // Validate command line arguments.
        assert!(opts.slice_us >= opts.slice_us_min);

        // Check host topology to determine if we need to enable SMT capabilities.
        let smt_enabled = match is_smt_active() {
            Ok(value) => value == 1,
            Err(e) => bail!("Failed to read SMT status: {}", e),
        };
        info!(
            "{} {} {}",
            SCHEDULER_NAME,
            *build_id::SCX_FULL_VERSION,
            if smt_enabled { "SMT on" } else { "SMT off" }
        );

        // Initialize BPF connector.
        let mut skel_builder = BpfSkelBuilder::default();
        skel_builder.obj_builder.debug(opts.verbose);
        let mut skel = scx_ops_open!(skel_builder, open_object, bpfland_ops)?;

        skel.struct_ops.bpfland_ops_mut().exit_dump_len = opts.exit_dump_len;

        // Override default BPF scheduling parameters.
        skel.maps.rodata_data.debug = opts.debug;
        skel.maps.rodata_data.smt_enabled = smt_enabled;
        skel.maps.rodata_data.local_kthreads = opts.local_kthreads;
        skel.maps.rodata_data.slice_ns = opts.slice_us * 1000;
        skel.maps.rodata_data.slice_ns_min = opts.slice_us_min * 1000;
        skel.maps.rodata_data.slice_ns_lag = opts.slice_us_lag * 1000;
        skel.maps.rodata_data.starvation_thresh_ns = opts.starvation_thresh_us * 1000;
        skel.maps.rodata_data.nvcsw_max_thresh = opts.nvcsw_max_thresh;

        // Load the BPF program for validation.
        let mut skel = scx_ops_load!(skel, bpfland_ops, uei)?;

        // Initialize CPU topology.
        let topo = Topology::new().unwrap();

        // Initialize the primary scheduling domain (based on the --primary-domain option).
        Self::init_primary_domain(&mut skel, &topo, &opts.primary_domain)?;

        // Initialize L2 cache domains.
        if !opts.disable_l2 {
            Self::init_l2_cache_domains(&mut skel, &topo)?;
        }
        // Initialize L3 cache domains.
        if !opts.disable_l3 {
            Self::init_l3_cache_domains(&mut skel, &topo)?;
        }

        // Attach the scheduler.
        let struct_ops = Some(scx_ops_attach!(skel, bpfland_ops)?);

        // Enable Prometheus metrics.
        if opts.enable_prometheus {
            info!("Enabling Prometheus endpoint: http://localhost:9000");
            PrometheusBuilder::new()
                .install()
                .expect("failed to install Prometheus recorder");
        }

        Ok(Self {
            skel,
            struct_ops,
            opts,
            metrics: Metrics::new(),
            cpu_hotplug_cnt: 0,
        })
    }

    fn enable_primary_cpu(skel: &mut BpfSkel<'_>, cpu: usize) -> Result<(), u32> {
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

    fn init_primary_domain(skel: &mut BpfSkel<'_>, topo: &Topology, primary_domain: &Cpumask) -> Result<()> {
        info!("primary CPU domain = 0x{:x}", primary_domain);

        for cpu in 0..topo.nr_cpu_ids() {
            if primary_domain.test_cpu(cpu) {
                if let Err(err) = Self::enable_primary_cpu(skel, cpu) {
                    warn!("failed to add CPU {} to primary domain: error {}", cpu, err);
                }
            }
        }

        Ok(())
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

    fn init_cache_domains(
        skel: &mut BpfSkel<'_>,
        topo: &Topology,
        cache_lvl: usize,
        enable_sibling_cpu_fn: &dyn Fn(&mut BpfSkel<'_>, usize, usize, usize) -> Result<(), u32>
    ) -> Result<(), std::io::Error> {
        // Determine the list of CPU IDs associated to each cache node.
        let mut cache_id_map: HashMap<usize, Vec<usize>> = HashMap::new();
        for core in topo.cores().into_iter() {
            for (cpu_id, cpu) in core.cpus() {
                let cache_id = match cache_lvl {
                    2 => cpu.l2_id(),
                    3 => cpu.l3_id(),
                    _ => panic!("invalid cache level {}", cache_lvl),
                };
                cache_id_map
                    .entry(cache_id)
                    .or_insert_with(Vec::new)
                    .push(*cpu_id);
            }
        }

        // Update the BPF cpumasks for the cache domains.
        for (cache_id, cpus) in cache_id_map {
            info!(
                "L{} cache ID {}: sibling CPUs: {:?}",
                cache_lvl, cache_id, cpus
            );
            for cpu in &cpus {
                for sibling_cpu in &cpus {
                    match enable_sibling_cpu_fn(skel, cache_lvl, *cpu, *sibling_cpu) {
                        Ok(()) => {},
                        Err(_) => {
                            warn!(
                                "L{} cache ID {}: failed to set CPU {} sibling {}",
                                cache_lvl, cache_id, *cpu, *sibling_cpu
                            );
                        }
                    }
                }
            }
        }

        Ok(())
    }

    fn init_l2_cache_domains(skel: &mut BpfSkel<'_>, topo: &Topology) -> Result<(), std::io::Error> {
        Self::init_cache_domains(skel, topo, 2, &|skel, lvl, cpu, sibling_cpu| {
            Self::enable_sibling_cpu(skel, lvl, cpu, sibling_cpu)
        })
    }

    fn init_l3_cache_domains(skel: &mut BpfSkel<'_>, topo: &Topology) -> Result<(), std::io::Error> {
        Self::init_cache_domains(skel, topo, 3, &|skel, lvl, cpu, sibling_cpu| {
            Self::enable_sibling_cpu(skel, lvl, cpu, sibling_cpu)
        })
    }

    fn refresh_cache_domains(&mut self) {
        // Check if we need to refresh the CPU cache information.
        if self.cpu_hotplug_cnt == self.skel.maps.bss_data.cpu_hotplug_cnt {
            return;
        }

        // Re-initialize CPU topology.
        let topo = Topology::new().unwrap();

        // Re-initialize L2 cache domains.
        if !self.opts.disable_l2 {
            if let Err(e) = Self::init_l2_cache_domains(&mut self.skel, &topo) {
                warn!("failed to initialize L2 cache domains: {}", e);
            }
        }

        // Re-initialize L3 cache domains.
        if !self.opts.disable_l3 {
            if let Err(e) = Self::init_l3_cache_domains(&mut self.skel, &topo) {
                warn!("failed to initialize L3 cache domains: {}", e);
            }
        }

        // Update CPU hotplug generation counter.
        self.cpu_hotplug_cnt = self.skel.maps.bss_data.cpu_hotplug_cnt;
    }

    fn update_stats(&mut self) {
        let nr_cpus = self.skel.maps.bss_data.nr_online_cpus;
        let nr_running = self.skel.maps.bss_data.nr_running;
        let nr_interactive = self.skel.maps.bss_data.nr_interactive;
        let nr_waiting = self.skel.maps.bss_data.nr_waiting;
        let nvcsw_avg_thresh = self.skel.maps.bss_data.nvcsw_avg_thresh;
        let nr_direct_dispatches = self.skel.maps.bss_data.nr_direct_dispatches;
        let nr_prio_dispatches = self.skel.maps.bss_data.nr_prio_dispatches;
        let nr_shared_dispatches = self.skel.maps.bss_data.nr_shared_dispatches;

        // Update Prometheus statistics.
        self.metrics.nr_running.set(nr_running as f64);
        self.metrics.nr_interactive.set(nr_interactive as f64);
        self.metrics.nr_waiting.set(nr_waiting as f64);
        self.metrics.nvcsw_avg_thresh.set(nvcsw_avg_thresh as f64);
        self.metrics
            .nr_direct_dispatches
            .set(nr_direct_dispatches as f64);
        self.metrics
            .nr_prio_dispatches
            .set(nr_prio_dispatches as f64);
        self.metrics
            .nr_shared_dispatches
            .set(nr_shared_dispatches as f64);

        // Log scheduling statistics.
        info!("[{}] tasks -> run: {:>2}/{:<2} int: {:<2} wait: {:<4} | nvcsw: {:<4} | dispatch -> dir: {:<5} prio: {:<5} shr: {:<5}",
            SCHEDULER_NAME,
            nr_running,
            nr_cpus,
            nr_interactive,
            nr_waiting,
            nvcsw_avg_thresh,
            nr_direct_dispatches,
            nr_prio_dispatches,
            nr_shared_dispatches);
    }

    pub fn exited(&mut self) -> bool {
        uei_exited!(&self.skel, uei)
    }

    fn run(&mut self, shutdown: Arc<AtomicBool>) -> Result<UserExitInfo> {
        while !shutdown.load(Ordering::Relaxed) && !self.exited() {
            self.refresh_cache_domains();
            self.update_stats();
            std::thread::sleep(Duration::from_millis(1000));
        }
        self.update_stats();

        self.struct_ops.take();
        uei_report!(&self.skel, uei)
    }
}

impl<'a> Drop for Scheduler<'a> {
    fn drop(&mut self) {
        info!("Unregister {} scheduler", SCHEDULER_NAME);
    }
}

fn main() -> Result<()> {
    let opts = Opts::parse();

    if opts.version {
        println!("{} {}", SCHEDULER_NAME, *build_id::SCX_FULL_VERSION);
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

    let mut open_object = MaybeUninit::uninit();
    loop {
        let mut sched = Scheduler::init(&opts, &mut open_object)?;
        if !sched.run(shutdown.clone())?.should_restart() {
            break;
        }
    }

    Ok(())
}
