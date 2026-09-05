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

use std::collections::BTreeMap;
use std::ffi::c_ulong;
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
use scx_utils::Topology;
use scx_utils::UserExitInfo;
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
    #[clap(short = 's', long, default_value = "1000")]
    slice_us: u64,

    /// Maximum lag, in microseconds of virtual time, that a task can carry across a sleep.
    ///
    /// This bounds both the credit a task can bring back from a sleep and the debt it can
    /// carry after consuming more than its share: an over-served task waits for the system
    /// vruntime to cover the debt before it runs again, and under heavy load that reference
    /// moves slowly. EEVDF bounds the lag to twice the base slice (max(2 * slice, tick)).
    #[clap(short = 'l', long, default_value = "2000")]
    slice_lag_us: u64,

    /// CPU busy threshold.
    ///
    /// Specifies the user CPU utilization percentage (0-100%) at which the scheduler considers a
    /// CPU to be busy. Only user time counts: sleep-intensive workloads burn most of their CPU
    /// time in the kernel and their CPUs are deliberately not considered busy, so that tasks stay
    /// on their CPU / local dispatch queue, reducing the scheduling overhead and the balancing
    /// pressure in dispatch.
    ///
    /// When a CPU crosses this threshold, the scheduler switches it from using its local
    /// round-robin dispatch queue (which favors locality and reduced locking contention) to its
    /// deadline-ordered dispatch queue, from which the other CPUs can pull (which improves load
    /// balancing).
    ///
    /// The deadline-ordered queues can increase task migrations and improve responsiveness for
    /// interactive tasks under heavy load. Lower values make the scheduler switch to deadline
    /// mode sooner, improving overall responsiveness at the cost of reducing single-task
    /// performance due to the additional migrations. Higher values makes task more "sticky" to
    /// their CPU, improving workloads that benefit from cache locality.
    ///
    /// A higher value is recommended for server-type workloads, while a lower value is recommended
    /// for interactive-type workloads.
    ///
    /// 0 = utilization tracking disabled: every CPU is always considered busy (pure deadline
    /// mode) with no tracking overhead.
    #[clap(short = 'c', long, default_value = "0")]
    cpu_busy_thresh: u64,

    /// Disable NUMA optimizations.
    #[clap(short = 'n', long, action = clap::ArgAction::SetTrue)]
    disable_numa: bool,

    /// Disable CPU frequency control.
    #[clap(short = 'f', long, action = clap::ArgAction::SetTrue)]
    disable_cpufreq: bool,

    /// Disable SMT.
    #[clap(long, action = clap::ArgAction::SetTrue)]
    disable_smt: bool,

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

    /// Enable high-resolution timer preemption.
    ///
    /// By default, the scheduler preempts tasks that exceed their time slice, measuring the time
    /// slice via the tick handler. Add an option to enforce preemption based on the high-precision
    /// timer and CPU occupancy. Enable this option to improve latency-sensitive workloads.
    #[clap(long, action = clap::ArgAction::SetTrue)]
    time_preemption: bool,

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

struct Scheduler<'a> {
    skel: BpfSkel<'a>,
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
        rodata.numa_enabled = numa_enabled;
        rodata.no_wake_sync = opts.no_wake_sync;
        rodata.time_preemption = opts.time_preemption;

        // Normalize CPU busy threshold in the range [0 .. 1024].
        rodata.busy_threshold = opts.cpu_busy_thresh * 1024 / 100;

        // Generate the list of available CPUs sorted by capacity in descending order.
        let mut cpus: Vec<_> = topo.all_cpus.values().collect();
        cpus.sort_by_key(|cpu| std::cmp::Reverse(cpu.cpu_capacity));
        // Normalize CPU capacities to 1..1024 so the highest capacity is always 1024.
        let max_cap = cpus.first().map(|c| c.cpu_capacity).unwrap_or(1).max(1);
        for (i, cpu) in cpus.iter().enumerate() {
            let normalized = (cpu.cpu_capacity * 1024 / max_cap).clamp(1, 1024);
            rodata.cpu_capacity[cpu.id] = normalized as c_ulong;
            rodata.cpu_llc[cpu.id] = cpu.llc_id as u64;
            rodata.cpu_nodes[cpu.id] = cpu.node_id as u32;
            rodata.preferred_cpus[i] = cpu.id as u64;
        }
        // SMT siblings of each CPU as a ring around the core, for the SMT
        // preference of the idle CPU scan. With SMT disabled every CPU is a
        // core of its own.
        let mut core_cpus: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
        for cpu in cpus.iter() {
            let core = if smt_enabled { cpu.core_id } else { cpu.id };
            core_cpus.entry(core).or_default().push(cpu.id);
        }
        for ids in core_cpus.values_mut() {
            ids.sort_unstable();
            for (i, &id) in ids.iter().enumerate() {
                rodata.cpu_sibling_next[id] = ids[(i + 1) % ids.len()] as u32;
            }
        }
        rodata.all_cpus_same_capacity = cpus.iter().all(|cpu| cpu.cpu_capacity == max_cap);
        if !rodata.all_cpus_same_capacity {
            info!(
                "CPUs by capacity: {:?}",
                &rodata.preferred_cpus[0..cpus.len()]
            );
        }

        // Set scheduler flags.
        skel.struct_ops.cosmos_ops_mut().flags = *compat::SCX_OPS_ENQ_EXITING
            | *compat::SCX_OPS_ENQ_LAST
            | *compat::SCX_OPS_ENQ_MIGRATION_DISABLED
            | *compat::SCX_OPS_ALLOW_QUEUED_WAKEUP
            | if numa_enabled {
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

        // Attach the scheduler.
        let struct_ops = Some(scx_ops_attach!(skel, cosmos_ops)?);
        let stats_server = StatsServer::new(stats::server_data()).launch()?;

        Ok(Self {
            skel,
            struct_ops,
            stats_server,
        })
    }

    fn get_metrics(&self) -> Metrics {
        let bss_data = self.skel.maps.bss_data.as_ref().unwrap();
        Metrics {
            nr_steals: bss_data.nr_steals,
        }
    }

    pub fn exited(&mut self) -> bool {
        uei_exited!(&self.skel, uei)
    }

    fn run(&mut self, shutdown: Arc<AtomicBool>) -> Result<UserExitInfo> {
        let (res_ch, req_ch) = self.stats_server.channels();

        while !shutdown.load(Ordering::Relaxed) && !self.exited() {
            // Update statistics and check for exit condition.
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
