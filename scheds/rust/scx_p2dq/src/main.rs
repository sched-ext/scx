// Copyright (c) Meta Platforms, Inc. and affiliates.

// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

//mod bpf_skel;
//pub use bpf_skel::*;
pub use scx_p2dq::bpf_skel::*; // TODO: PUT ME BACK after the abstraction exists

pub mod bpf_intf;
pub mod stats;
use stats::Metrics;

use scx_p2dq::SchedulerOpts;
use scx_p2dq::TOPO;

use std::mem::MaybeUninit;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use anyhow::Result;
use clap::Parser;
use crossbeam::channel::RecvTimeoutError;
use libbpf_rs::MapCore as _;
use libbpf_rs::OpenObject;
use log::{debug, info, warn};
use scx_stats::prelude::*;
use scx_utils::build_id;
use scx_utils::compat;
use scx_utils::init_libbpf_logging;
use scx_utils::pm::{cpu_idle_resume_latency_supported, update_cpu_idle_resume_latency};
use scx_utils::scx_ops_attach;
use scx_utils::scx_ops_load;
use scx_utils::scx_ops_open;
use scx_utils::uei_exited;
use scx_utils::uei_report;
use scx_utils::UserExitInfo;

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
use crate::bpf_intf::stat_idx_P2DQ_STAT_WAKE_LLC;
use crate::bpf_intf::stat_idx_P2DQ_STAT_WAKE_MIG;
use crate::bpf_intf::stat_idx_P2DQ_STAT_WAKE_PREV;

/// scx_p2dq: A pick 2 dumb queuing load balancing scheduler.
///
/// The BPF part does simple vtime or round robin scheduling in each domain
/// while tracking average load of each domain and duty cycle of each task.
///
#[derive(Debug, Parser)]
struct CliOpts {
    /// Enable verbose output, including libbpf details. Specify multiple
    /// times to increase verbosity.
    #[clap(short = 'v', long, action = clap::ArgAction::Count)]
    pub verbose: u8,

    /// Enable stats monitoring with the specified interval.
    #[clap(long)]
    pub stats: Option<f64>,

    /// Run in stats monitoring mode with the specified interval. Scheduler
    /// is not launched.
    #[clap(long)]
    pub monitor: Option<f64>,

    /// Print version and exit.
    #[clap(long)]
    pub version: bool,

    #[clap(flatten)]
    pub sched: SchedulerOpts,
}

struct Scheduler<'a> {
    skel: BpfSkel<'a>,
    struct_ops: Option<libbpf_rs::Link>,

    stats_server: StatsServer<(), Metrics>,
}

impl<'a> Scheduler<'a> {
    fn init(
        opts: &SchedulerOpts,
        open_object: &'a mut MaybeUninit<OpenObject>,
        verbose: u8,
    ) -> Result<Self> {
        // Open the BPF prog first for verification.
        let mut skel_builder = BpfSkelBuilder::default();
        skel_builder.obj_builder.debug(verbose > 1);
        init_libbpf_logging(None);
        info!(
            "Running scx_p2dq (build ID: {})",
            build_id::full_version(env!("CARGO_PKG_VERSION"))
        );
        let mut open_skel = scx_ops_open!(skel_builder, open_object, p2dq).unwrap();
        scx_p2dq::init_open_skel!(&mut open_skel, opts, verbose)?;

        match compat::SCX_OPS_ALLOW_QUEUED_WAKEUP {
            0 => info!("Kernel does not support queued wakeup optimization."),
            v => skel.struct_ops.p2dq_mut().flags |= v,
        };

        let mut skel = scx_ops_load!(open_skel, p2dq, uei)?;
        scx_p2dq::init_skel!(&mut skel);

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
            wake_prev: stats[stat_idx_P2DQ_STAT_WAKE_PREV as usize],
            wake_llc: stats[stat_idx_P2DQ_STAT_WAKE_LLC as usize],
            wake_mig: stats[stat_idx_P2DQ_STAT_WAKE_MIG as usize],
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
    let opts = CliOpts::parse();

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

    if let Some(idle_resume_us) = opts.sched.idle_resume_us {
        if !cpu_idle_resume_latency_supported() {
            warn!("idle resume latency not supported");
        } else {
            if idle_resume_us > 0 {
                info!("Setting idle QoS to {}us", idle_resume_us);
                for cpu in TOPO.all_cpus.values() {
                    update_cpu_idle_resume_latency(cpu.id, idle_resume_us.try_into().unwrap())?;
                }
            }
        }
    }

    let mut open_object = MaybeUninit::uninit();
    loop {
        let mut sched = Scheduler::init(&opts.sched, &mut open_object, opts.verbose)?;
        if !sched.run(shutdown.clone())?.should_restart() {
            break;
        }
    }
    Ok(())
}
