// SPDX-License-Identifier: GPL-2.0
//
// Copyright (c) 2024 Andrea Righi <andrea.righi@linux.dev>.

// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

mod bpf_skel;
pub use bpf_skel::*;
pub mod bpf_intf;
pub use bpf_intf::*;

use std::fs::File;
use std::io::Read;
use std::mem::MaybeUninit;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use std::str;

use anyhow::bail;
use anyhow::Context;
use anyhow::Result;
use clap::Parser;
use log::info;

use metrics::{gauge, Gauge};
use metrics_exporter_prometheus::PrometheusBuilder;

use rlimit::{getrlimit, setrlimit, Resource};

use libbpf_rs::OpenObject;
use libbpf_rs::skel::OpenSkel;
use libbpf_rs::skel::Skel;
use libbpf_rs::skel::SkelBuilder;

use scx_utils::build_id;
use scx_utils::scx_ops_attach;
use scx_utils::scx_ops_load;
use scx_utils::scx_ops_open;
use scx_utils::uei_exited;
use scx_utils::uei_report;
use scx_utils::UserExitInfo;

const SCHEDULER_NAME: &'static str = "scx_asdf";

#[derive(Debug, Clone)]
struct CpuMask {
    mask: Vec<u64>,
    num_bits: usize,
}

impl CpuMask {
    pub fn from_mask(mask: Vec<u64>, num_bits: usize) -> Self {
        Self { mask, num_bits }
    }

    pub fn is_cpu_set(&self, cpu: usize) -> bool {
        if self.num_bits == 0 {
            return true;
        }
        if cpu >= self.num_bits {
            return false;
        }
        let idx = cpu / 64;
        let bit = cpu % 64;
        self.mask.get(idx).map_or(false, |&val| val & (1 << bit) != 0)
    }

    pub fn from_str(hex_str: &str) -> Result<Self, std::num::ParseIntError> {
        let hex_str = hex_str.trim_start_matches("0x");
        let num_bits = hex_str.len() * 4;

        let num_u64s = (num_bits + 63) / 64;
        let padded_hex_str = format!("{:0>width$}", hex_str, width = num_u64s * 16);

        let mask = (0..num_u64s)
            .rev()
            .map(|i| u64::from_str_radix(&padded_hex_str[i * 16..(i + 1) * 16], 16))
            .collect::<Result<Vec<_>, _>>()?;

        Ok(CpuMask::from_mask(mask, num_bits))
    }

    pub fn to_string(&self) -> String {
        if self.num_bits == 0 {
            return "all".to_string();
        }
        let mut hex_str = String::new();
        for &chunk in self.mask.iter().rev() {
            hex_str.push_str(&format!("{:016x}", chunk));
        }

        // Remove leading zeros, but keep at least one digit.
        hex_str = hex_str.trim_start_matches('0').to_string();
        if hex_str.is_empty() {
            hex_str = "0".to_string();
        }
        format!("0x{}", hex_str)
    }
}

// Custom parser function for cpumask using CpuMask's from_str method
fn parse_cpumask(hex_str: &str) -> Result<CpuMask, std::num::ParseIntError> {
    CpuMask::from_str(hex_str)
}

/// scx_asdf: a vruntime-based sched_ext scheduler that prioritizes interactive workloads.
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

    /// When a CPU doesn't have any more tasks to consume it doesn't immediately go idle, but it
    /// remains active for a little bit (idle_decay_ns) trying to speculate on the fact that
    /// another task may come in, so the CPU is immediately able to consume that task.
    ///
    /// This can speed up some systems that are using an aggressive cpufreq governor (aggressive in
    /// terms of power saving), but it has the downside of also using more power.
    ///
    /// (0 = disabled, CPUs can immediately go idle)
    #[clap(short = 'i', long, default_value = "0")]
    idle_decay_us: u64,

    /// Enable per-CPU kthreads prioritization.
    ///
    /// Enabling this can enhance the performance of interrupt-driven workloads (e.g., networking
    /// throughput) over regular system/user workloads. However, it may also introduce
    /// interactivity issues or unfairness under heavy interrupt-driven loads, such as high RX
    /// network traffic.
    #[clap(short = 'k', long, action = clap::ArgAction::SetTrue)]
    local_kthreads: bool,

    /// Maximum threshold of voluntary context switch per second, used to classify interactive
    /// tasks (0 = disable interactive tasks classification).
    #[clap(short = 'c', long, default_value = "10")]
    nvcsw_max_thresh: u64,

    /// Prevent the starvation making sure that at least one lower priority task is scheduled every
    /// starvation_thresh_us (0 = disable starvation prevention).
    #[clap(short = 't', long, default_value = "5000")]
    starvation_thresh_us: u64,

    /// Allowed CPU mask, specified as a hexadecimal number (e.g., 0xffff),
    /// (0 = all CPUs allowed).
    #[clap(short = 'm', long, default_value = "", value_parser = parse_cpumask)]
    cpumask: CpuMask,

    /// Enable the Prometheus endpoint for metrics on port 9000.
    #[clap(short = 'p', long, action = clap::ArgAction::SetTrue)]
    enable_prometheus: bool,

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
    metrics: Metrics,
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
        let mut skel = scx_ops_open!(skel_builder, open_object, asdf_ops)?;

        skel.struct_ops.asdf_ops_mut().exit_dump_len = opts.exit_dump_len;

        // Override default BPF scheduling parameters.
        skel.maps.rodata_data.smt_enabled = smt_enabled;
        skel.maps.rodata_data.local_kthreads = opts.local_kthreads;
        skel.maps.rodata_data.slice_ns = opts.slice_us * 1000;
        skel.maps.rodata_data.slice_ns_min = opts.slice_us_min * 1000;
        skel.maps.rodata_data.slice_ns_lag = opts.slice_us_lag * 1000;
        skel.maps.rodata_data.idle_decay_ns = opts.idle_decay_us * 1000;
        skel.maps.rodata_data.starvation_thresh_ns = opts.starvation_thresh_us * 1000;
        skel.maps.rodata_data.nvcsw_max_thresh = opts.nvcsw_max_thresh;

        info!("allowed cpumask = {}", opts.cpumask.to_string());
        for cpu in 0..consts_MAX_CPUS as usize {
            let allowed = opts.cpumask.is_cpu_set(cpu) as i32;
            skel.maps.rodata_data.cpu_allowed[cpu] = allowed;
        }

        // Attach the scheduler.
        let mut skel = scx_ops_load!(skel, asdf_ops, uei)?;
        let struct_ops = Some(scx_ops_attach!(skel, asdf_ops)?);

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
            metrics: Metrics::new(),
        })
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
        self.metrics
            .nr_running
            .set(nr_running as f64);
        self.metrics
            .nr_interactive
            .set(nr_interactive as f64);
        self.metrics
            .nr_waiting
            .set(nr_waiting as f64);
        self.metrics
            .nvcsw_avg_thresh.set(nvcsw_avg_thresh as f64);
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
        info!("[ASDF] tasks -> run: {:>2}/{:<2} int: {:<2} wait: {:<4} | nvcsw: {:<4} | dispatch -> dir: {:<5} prio: {:<5} shr: {:<5}",
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
