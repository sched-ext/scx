// Copyright (c) Meta Platforms, Inc. and affiliates.

// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.
mod bpf_skel;
pub use bpf_skel::*;
pub mod bpf_intf;
pub mod stats;
use stats::Metrics;

use std::mem::MaybeUninit;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use anyhow::Result;
use clap::Parser;
use crossbeam::channel::RecvTimeoutError;
use libbpf_rs::skel::OpenSkel;
use libbpf_rs::skel::Skel;
use libbpf_rs::skel::SkelBuilder;
use libbpf_rs::MapCore as _;
use libbpf_rs::OpenObject;
use log::{debug, info, warn};
use scx_stats::prelude::*;
use scx_utils::build_id;
use scx_utils::import_enums;
use scx_utils::init_libbpf_logging;
use scx_utils::scx_enums;
use scx_utils::scx_ops_attach;
use scx_utils::scx_ops_load;
use scx_utils::scx_ops_open;
use scx_utils::uei_exited;
use scx_utils::uei_report;
use scx_utils::CoreType;
use scx_utils::Topology;
use scx_utils::UserExitInfo;
use scx_utils::NR_CPU_IDS;

use crate::bpf_intf::stat_idx_P2DQ_NR_STATS;
use crate::bpf_intf::stat_idx_P2DQ_STAT_DIRECT;
use crate::bpf_intf::stat_idx_P2DQ_STAT_DISPATCH_PICK2;
use crate::bpf_intf::stat_idx_P2DQ_STAT_DSQ_CHANGE;
use crate::bpf_intf::stat_idx_P2DQ_STAT_DSQ_SAME;
use crate::bpf_intf::stat_idx_P2DQ_STAT_GREEDY_IDLE;
use crate::bpf_intf::stat_idx_P2DQ_STAT_IDLE;
use crate::bpf_intf::stat_idx_P2DQ_STAT_KEEP;
use crate::bpf_intf::stat_idx_P2DQ_STAT_LLC_MIGRATION;
use crate::bpf_intf::stat_idx_P2DQ_STAT_NODE_MIGRATION;
use crate::bpf_intf::stat_idx_P2DQ_STAT_SELECT_PICK2;

lazy_static::lazy_static! {
        pub static ref TOPO: Topology = Topology::new().unwrap();
}

fn get_default_pick2_nr_queued() -> u32 {
    let max_llc_cpus = TOPO
        .all_llcs
        .values()
        .map(|llc| llc.cores.len())
        .max()
        .unwrap_or(1) as u32;
    if max_llc_cpus > 1 {
        max_llc_cpus / 2
    } else {
        max_llc_cpus
    }
}

/// scx_p2dq: A pick 2 dumb queuing load balancing scheduler.
///
/// The BPF part does simple vtime or round robin scheduling in each domain
/// while tracking average load of each domain and duty cycle of each task.
///
#[derive(Debug, Parser)]
struct Opts {
    /// Disables per-cpu kthreads directly dispatched into local dsqs.
    #[clap(short = 'k', long, action = clap::ArgAction::SetTrue)]
    disable_kthreads_local: bool,

    /// Enables autoslice tuning
    #[clap(short = 'a', long, action = clap::ArgAction::SetTrue)]
    autoslice: bool,

    /// Ratio of interactive tasks for autoslice tuning, percent value from 1-99.
    #[clap(short = 'r', long, default_value = "10")]
    interactive_ratio: usize,

    /// Disables eager pick2 load balancing.
    #[clap(short = 'e', long, action = clap::ArgAction::SetTrue)]
    eager_load_balance: bool,

    /// Disables greedy idle CPU selection, may cause better load balancing on multi-LLC systems.
    #[clap(short = 'g', long, action = clap::ArgAction::SetTrue)]
    greedy_idle_disable: bool,

    /// Interactive tasks stay sticky to their CPU if no idle CPU is found.
    #[clap(short = 'y', long, action = clap::ArgAction::SetTrue)]
    interactive_sticky: bool,

    /// Disables pick2 load balancing on the dispatch path.
    #[clap(short = 'd', long, action = clap::ArgAction::SetTrue)]
    dispatch_pick2_disable: bool,

    /// Enable tasks to run beyond their timeslice if the CPU is idle.
    #[clap(long, action = clap::ArgAction::SetTrue)]
    keep_running: bool,

    /// Only pick2 load balance from the max DSQ.
    #[clap(long, action = clap::ArgAction::SetTrue)]
    max_dsq_pick2: bool,

    /// Scheduling min slice duration in microseconds.
    #[clap(short = 's', long, default_value = "100")]
    min_slice_us: u64,

    /// Number of runs on the LLC before a task becomes eligbile for pick2 migration on the wakeup
    /// path.
    #[clap(short = 'l', long, default_value = "1")]
    min_llc_runs_pick2: u64,

    /// Manual definition of slice intervals in microseconds for DSQs, must be equal to number of
    /// dumb_queues.
    #[clap(short = 't', long, value_parser = clap::value_parser!(u64), default_values_t = [0;0])]
    dsq_time_slices: Vec<u64>,

    /// DSQ scaling shift, each queue min timeslice is shifted by the scaling shift.
    #[clap(short = 'x', long, default_value = "4")]
    dsq_shift: u64,

    /// Minimum number of queued tasks to use pick2 balancing, 0 to always enabled.
    #[clap(short = 'm', long, default_value_t = get_default_pick2_nr_queued())]
    min_nr_queued_pick2: u32,

    /// Number of dumb DSQs.
    #[clap(short = 'q', long, default_value = "3")]
    dumb_queues: usize,

    /// Initial DSQ for tasks.
    #[clap(short = 'i', long, default_value = "0")]
    init_dsq_index: usize,

    /// Enable verbose output, including libbpf details. Specify multiple
    /// times to increase verbosity.
    #[clap(short = 'v', long, action = clap::ArgAction::Count)]
    verbose: u8,

    /// Enable stats monitoring with the specified interval.
    #[clap(long)]
    stats: Option<f64>,

    /// Run in stats monitoring mode with the specified interval. Scheduler
    /// is not launched.
    #[clap(long)]
    monitor: Option<f64>,

    /// Print version and exit.
    #[clap(long)]
    version: bool,
}

fn dsq_slice_ns(dsq_index: u64, min_slice_us: u64, dsq_shift: u64) -> u64 {
    let result = if dsq_index == 0 {
        1000 * min_slice_us
    } else {
        1000 * (min_slice_us << (dsq_index as u32) << dsq_shift)
    };
    result
}

struct Scheduler<'a> {
    skel: BpfSkel<'a>,
    struct_ops: Option<libbpf_rs::Link>,

    stats_server: StatsServer<(), Metrics>,
}

impl<'a> Scheduler<'a> {
    fn init(opts: &Opts, open_object: &'a mut MaybeUninit<OpenObject>) -> Result<Self> {
        // Open the BPF prog first for verification.
        let mut skel_builder = BpfSkelBuilder::default();
        skel_builder.obj_builder.debug(opts.verbose > 1);
        init_libbpf_logging(None);
        info!(
            "Running scx_p2dq (build ID: {})",
            build_id::full_version(env!("CARGO_PKG_VERSION"))
        );
        let mut skel = scx_ops_open!(skel_builder, open_object, p2dq).unwrap();

        if opts.init_dsq_index > opts.dumb_queues - 1 {
            panic!("Invalid init_dsq_index {}", opts.init_dsq_index);
        }
        if opts.dsq_time_slices.len() > 0 {
            if opts.dsq_time_slices.len() != opts.dumb_queues {
                panic!(
                    "Invalid number of dsq_time_slices, got {} need {}",
                    opts.dsq_time_slices.len(),
                    opts.dumb_queues,
                )
            }
            for vals in opts.dsq_time_slices.windows(2) {
                assert!(
                    vals[0] < vals[1],
                    "DSQ time slices must be in increasing order"
                );
            }
            for (i, slice) in opts.dsq_time_slices.iter().enumerate() {
                info!("DSQ[{}] slice_ns {}", i, slice * 1000);
                skel.maps.bss_data.dsq_time_slices[i] = slice * 1000;
            }
        } else {
            for i in 0..=opts.dumb_queues - 1 {
                let slice_ns = dsq_slice_ns(i as u64, opts.min_slice_us, opts.dsq_shift);
                info!("DSQ[{}] slice_ns {}", i, slice_ns);
                skel.maps.bss_data.dsq_time_slices[i] = slice_ns;
            }
        }
        if opts.autoslice {
            if opts.interactive_ratio == 0 || opts.interactive_ratio > 99 {
                panic!(
                    "Invalid interactive_ratio {}, must be between 1-99",
                    opts.interactive_ratio
                );
            }
        }

        skel.maps.rodata_data.interactive_ratio = opts.interactive_ratio as u32;
        skel.maps.rodata_data.min_slice_us = opts.min_slice_us;
        skel.maps.rodata_data.min_nr_queued_pick2 = opts.min_nr_queued_pick2;
        skel.maps.rodata_data.min_llc_runs_pick2 = opts.min_llc_runs_pick2;
        skel.maps.rodata_data.dsq_shift = opts.dsq_shift as u64;
        skel.maps.rodata_data.kthreads_local = !opts.disable_kthreads_local;
        skel.maps.rodata_data.nr_cpus = *NR_CPU_IDS as u32;
        skel.maps.rodata_data.nr_dsqs_per_llc = opts.dumb_queues as u32;
        skel.maps.rodata_data.init_dsq_index = opts.init_dsq_index as i32;
        skel.maps.rodata_data.nr_llcs = TOPO.all_llcs.clone().keys().len() as u32;
        skel.maps.rodata_data.nr_nodes = TOPO.nodes.clone().keys().len() as u32;

        skel.maps.rodata_data.autoslice = opts.autoslice;
        skel.maps.rodata_data.debug = opts.verbose as u32;
        skel.maps.rodata_data.dispatch_pick2_disable = opts.dispatch_pick2_disable;
        skel.maps.rodata_data.eager_load_balance = !opts.eager_load_balance;
        skel.maps.rodata_data.greedy_idle = !opts.greedy_idle_disable;
        skel.maps.rodata_data.has_little_cores = TOPO.has_little_cores();
        skel.maps.rodata_data.interactive_sticky = opts.interactive_sticky;
        skel.maps.rodata_data.keep_running_enabled = opts.keep_running;
        skel.maps.rodata_data.max_dsq_pick2 = opts.max_dsq_pick2;
        skel.maps.rodata_data.smt_enabled = TOPO.smt_enabled;

        let mut skel = scx_ops_load!(skel, p2dq, uei)?;

        for cpu in TOPO.all_cpus.values() {
            skel.maps.bss_data.big_core_ids[cpu.id] =
                if cpu.core_type == (CoreType::Big { turbo: true }) {
                    1
                } else {
                    0
                };
            skel.maps.bss_data.cpu_llc_ids[cpu.id] = cpu.llc_id as u64;
            skel.maps.bss_data.cpu_node_ids[cpu.id] = cpu.node_id as u64;
        }

        let struct_ops = Some(scx_ops_attach!(skel, p2dq)?);

        let stats_server = StatsServer::new(stats::server_data()).launch()?;

        info!("P2DQ scheduler started! Run `scx_p2dq --monitor` for metrics.");

        Ok(Self {
            skel,
            struct_ops,
            stats_server,
        })
    }

    fn get_metrics(&self) -> Metrics {
        let mut stats = vec![0u64; stat_idx_P2DQ_NR_STATS as usize];
        let stats_map = &self.skel.maps.stats;
        for stat in 0..stat_idx_P2DQ_NR_STATS {
            let cpu_stat_vec: Vec<Vec<u8>> = stats_map
                .lookup_percpu(&stat.to_ne_bytes(), libbpf_rs::MapFlags::ANY)
                .unwrap()
                .unwrap();
            let sum: u64 = cpu_stat_vec
                .iter()
                .map(|val| u64::from_ne_bytes(val.as_slice().try_into().unwrap()))
                .sum();
            stats[stat as usize] = sum;
        }
        Metrics {
            direct: stats[stat_idx_P2DQ_STAT_DIRECT as usize],
            idle: stats[stat_idx_P2DQ_STAT_IDLE as usize],
            greedy_idle: stats[stat_idx_P2DQ_STAT_GREEDY_IDLE as usize],
            sched_mode: self.skel.maps.bss_data.sched_mode,
            dsq_change: stats[stat_idx_P2DQ_STAT_DSQ_CHANGE as usize],
            same_dsq: stats[stat_idx_P2DQ_STAT_DSQ_SAME as usize],
            keep: stats[stat_idx_P2DQ_STAT_KEEP as usize],
            select_pick2: stats[stat_idx_P2DQ_STAT_SELECT_PICK2 as usize],
            dispatch_pick2: stats[stat_idx_P2DQ_STAT_DISPATCH_PICK2 as usize],
            llc_migrations: stats[stat_idx_P2DQ_STAT_LLC_MIGRATION as usize],
            node_migrations: stats[stat_idx_P2DQ_STAT_NODE_MIGRATION as usize],
        }
    }

    fn run(&mut self, shutdown: Arc<AtomicBool>) -> Result<UserExitInfo> {
        let (res_ch, req_ch) = self.stats_server.channels();

        while !shutdown.load(Ordering::Relaxed) && !uei_exited!(&self.skel, uei) {
            match req_ch.recv_timeout(Duration::from_secs(1)) {
                Ok(()) => res_ch.send(self.get_metrics())?,
                Err(RecvTimeoutError::Timeout) => {}
                Err(e) => Err(e)?,
            }
        }

        self.struct_ops.take();
        uei_report!(&self.skel, uei)
    }
}

impl Drop for Scheduler<'_> {
    fn drop(&mut self) {
        if let Some(struct_ops) = self.struct_ops.take() {
            drop(struct_ops);
        }
    }
}

fn main() -> Result<()> {
    let opts = Opts::parse();

    if opts.version {
        println!(
            "scx_p2dq: {}",
            build_id::full_version(env!("CARGO_PKG_VERSION"))
        );
        return Ok(());
    }

    let llv = match opts.verbose {
        0 => simplelog::LevelFilter::Info,
        1 => simplelog::LevelFilter::Debug,
        _ => simplelog::LevelFilter::Trace,
    };
    let mut lcfg = simplelog::ConfigBuilder::new();
    lcfg.set_time_level(simplelog::LevelFilter::Error)
        .set_location_level(simplelog::LevelFilter::Off)
        .set_target_level(simplelog::LevelFilter::Off)
        .set_thread_level(simplelog::LevelFilter::Off);
    simplelog::TermLogger::init(
        llv,
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
