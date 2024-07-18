// SPDX-License-Identifier: GPL-2.0
//
// Copyright (c) 2024 Andrea Righi <righi.andrea@gmail.com>.

// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

mod bpf_skel;
pub use bpf_skel::*;
pub mod bpf_intf;
pub use bpf_intf::*;

use std::fs::File;
use std::io::Read;
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

const SCHEDULER_NAME: &'static str = "scx_bpfland";

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
    /// Increasing this value can help to increase the responsiveness of interactive tasks at the
    /// cost of making regular and newly created tasks less responsive (0 = disabled).
    #[clap(short = 'l', long, default_value = "0")]
    slice_us_lag: u64,

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
    nvcsw_avg_thresh: Gauge,
    nr_kthread_dispatches: Gauge,
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
            nvcsw_avg_thresh: gauge!(
                "nvcsw_avg_thresh", "info" => "Average of voluntary context switches"
            ),
            nr_kthread_dispatches: gauge!(
                "nr_kthread_dispatches", "info" => "Number of kthread direct dispatches"
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
    fn init(opts: &'a Opts) -> Result<Self> {
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
        let mut skel = scx_ops_open!(skel_builder, bpfland_ops)?;

        skel.struct_ops.bpfland_ops_mut().exit_dump_len = opts.exit_dump_len;

        // Override default BPF scheduling parameters.
        skel.rodata_mut().debug = opts.debug;
        skel.rodata_mut().smt_enabled = smt_enabled;
        skel.rodata_mut().local_kthreads = opts.local_kthreads;
        skel.rodata_mut().slice_ns = opts.slice_us * 1000;
        skel.rodata_mut().slice_ns_min = opts.slice_us_min * 1000;
        skel.rodata_mut().slice_ns_lag = opts.slice_us_lag * 1000;
        skel.rodata_mut().starvation_thresh_ns = opts.starvation_thresh_us * 1000;
        skel.rodata_mut().nvcsw_max_thresh = opts.nvcsw_max_thresh;

        // Attach the scheduler.
        let mut skel = scx_ops_load!(skel, bpfland_ops, uei)?;
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
            metrics: Metrics::new(),
        })
    }

    fn update_stats(&mut self) {
        let nr_cpus = self.skel.bss().nr_online_cpus;
        let nr_running = self.skel.bss().nr_running;
        let nr_interactive = self.skel.bss().nr_interactive;
        let nvcsw_avg_thresh = self.skel.bss().nvcsw_avg_thresh;
        let nr_kthread_dispatches = self.skel.bss().nr_kthread_dispatches;
        let nr_direct_dispatches = self.skel.bss().nr_direct_dispatches;
        let nr_prio_dispatches = self.skel.bss().nr_prio_dispatches;
        let nr_shared_dispatches = self.skel.bss().nr_shared_dispatches;

        // Update Prometheus statistics.
        self.metrics
            .nr_running
            .set(nr_running as f64);
        self.metrics
            .nr_interactive
            .set(nr_interactive as f64);
        self.metrics
            .nvcsw_avg_thresh.set(nvcsw_avg_thresh as f64);
        self.metrics
            .nr_kthread_dispatches
            .set(nr_kthread_dispatches as f64);
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
        info!("running: {:>4}/{:<4} interactive: {:>4} | nvcsw: {:<4} | kthread: {:<6} | direct: {:<6} | prio: {:<6} | shared: {:<6}",
            nr_running,
            nr_cpus,
            nr_interactive,
            nvcsw_avg_thresh,
            nr_kthread_dispatches,
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

    loop {
        let mut sched = Scheduler::init(&opts)?;
        if !sched.run(shutdown.clone())?.should_restart() {
            break;
        }
    }

    Ok(())
}
