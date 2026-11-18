// SPDX-License-Identifier: GPL-2.0
//
// Copyright (c) 2026 Hungyu Lin <dennylin0707@gmail.com>

// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

mod bpf_skel;
pub use bpf_skel::*;
pub mod bpf_intf;
pub use bpf_intf::*;

mod stats;
use std::mem::MaybeUninit;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::time::Duration;

use anyhow::Context;
use anyhow::Result;
use anyhow::bail;
use clap::Parser;
use crossbeam::channel::RecvTimeoutError;
use libbpf_rs::MapCore as _;
use libbpf_rs::MapFlags;
use libbpf_rs::OpenObject;
use log::{debug, info, warn};
use scx_stats::prelude::*;
use scx_utils::NR_CPU_IDS;
use scx_utils::Topology;
use scx_utils::UserExitInfo;
use scx_utils::build_id;
use scx_utils::libbpf_clap_opts::LibbpfOpts;
use scx_utils::scx_ops_attach;
use scx_utils::scx_ops_load;
use scx_utils::scx_ops_open;
use scx_utils::try_set_rlimit_infinity;
use scx_utils::uei_exited;
use scx_utils::uei_report;
use stats::Metrics;

const SCHEDULER_NAME: &str = "scx_lertick";

/// scx_lertick: weighted virtual-time scheduling with learned time slices.
///
/// Tasks wait in one queue per LLC, ordered by weighted virtual time. In online
/// mode each task trains a small linear model inside BPF on its own completed
/// CPU bursts, and the prediction sets its next time slice. Fairness always
/// charges the CPU time actually used.
///
/// The BPF part makes all the scheduling decisions (see src/bpf/main.bpf.c).
#[derive(Debug, Parser)]
struct Opts {
    /// Exit debug dump buffer length. 0 indicates default.
    #[clap(long, default_value = "0")]
    exit_dump_len: u32,

    /// Use the same time slice for every task instead of learning it.
    #[clap(short = 'f', long, action = clap::ArgAction::SetTrue)]
    fixed: bool,

    /// Time slice in microseconds in fixed mode, and before a task has enough
    /// completed bursts in online mode.
    #[clap(short = 's', long, default_value = "2000")]
    slice_us: u64,

    /// Minimum learned time slice in microseconds.
    #[clap(short = 'L', long, default_value = "500")]
    slice_min_us: u64,

    /// Maximum learned time slice in microseconds.
    #[clap(short = 'M', long, default_value = "3000")]
    slice_max_us: u64,

    /// Bursts a task's model must have learned from before its prediction
    /// sets its slice. A task that starts from its program's model counts as
    /// having learned 2.
    #[clap(long, default_value = "2")]
    min_train_samples: u32,

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

/// Longest accepted time slice in microseconds: one second, far below the
/// watchdog timeout and far from overflowing the nanosecond conversion.
const MAX_SLICE_US: u64 = 1_000_000;

struct Scheduler<'a> {
    skel: BpfSkel<'a>,
    struct_ops: Option<libbpf_rs::Link>,
    stats_server: StatsServer<(), Metrics>,
}

impl<'a> Scheduler<'a> {
    fn init(opts: &'a Opts, open_object: &'a mut MaybeUninit<OpenObject>) -> Result<Self> {
        try_set_rlimit_infinity();

        for (name, us) in [
            ("--slice-us", opts.slice_us),
            ("--slice-min-us", opts.slice_min_us),
            ("--slice-max-us", opts.slice_max_us),
        ] {
            if !(1..=MAX_SLICE_US).contains(&us) {
                bail!("{name} must be between 1 and {MAX_SLICE_US}");
            }
        }
        if opts.slice_min_us > opts.slice_max_us {
            bail!("--slice-min-us must not be above --slice-max-us");
        }

        info!(
            "{} {} {} mode",
            SCHEDULER_NAME,
            build_id::full_version(env!("CARGO_PKG_VERSION")),
            if opts.fixed { "fixed" } else { "online" }
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
        let mut skel = scx_ops_open!(skel_builder, open_object, lertick_ops, open_opts)?;

        skel.struct_ops.lertick_ops_mut().exit_dump_len = opts.exit_dump_len;

        // Override default BPF scheduling parameters.
        let rodata = skel.maps.rodata_data.as_mut().unwrap();
        rodata.mode = if opts.fixed {
            lertick_mode_LERTICK_MODE_FIXED
        } else {
            lertick_mode_LERTICK_MODE_ONLINE
        };
        rodata.slice_fixed = opts.slice_us * 1000;
        rodata.slice_min = opts.slice_min_us * 1000;
        rodata.slice_max = opts.slice_max_us * 1000;
        rodata.min_train_samples = opts.min_train_samples;

        // One queue per last-level cache; a single queue when there is one LLC.
        let topo = Topology::new()?;
        let nr_cpus = (*NR_CPU_IDS).min(LERTICK_MAX_CPUS as usize);
        let nr_llcs = topo.all_llcs.len();
        if nr_llcs > 1 && nr_llcs <= LERTICK_MAX_DOMAINS as usize {
            for (domain, llc) in topo.all_llcs.values().enumerate() {
                for &cpu in llc.all_cpus.keys() {
                    if cpu < nr_cpus {
                        rodata.cpu_domain[cpu] = domain as u8;
                    }
                }
            }
            rodata.nr_domains = nr_llcs as u32;
        }
        info!(
            "{} CPUs, {} queue(s)",
            nr_cpus,
            if rodata.nr_domains > 1 { nr_llcs } else { 1 }
        );

        // Load the BPF program for validation.
        let mut skel = scx_ops_load!(skel, lertick_ops, uei)?;

        // Attach the scheduler.
        let struct_ops = Some(scx_ops_attach!(skel, lertick_ops)?);
        let stats_server = StatsServer::new(stats::server_data()).launch()?;

        Ok(Self {
            skel,
            struct_ops,
            stats_server,
        })
    }

    /// Sum one statistic over the per-CPU slots of the stats map.
    fn stat(&self, idx: u32) -> u64 {
        self.skel
            .maps
            .stats
            .lookup_percpu(&idx.to_ne_bytes(), MapFlags::ANY)
            .ok()
            .flatten()
            .map_or(0, |cpus| {
                cpus.iter()
                    .map(|v| u64::from_ne_bytes(v.as_slice().try_into().unwrap_or([0; 8])))
                    .sum()
            })
    }

    fn get_metrics(&self) -> Metrics {
        Metrics {
            nr_local_dispatches: self.stat(lertick_stat_LERTICK_STAT_LOCAL_DISPATCHES),
            nr_shared_dispatches: self.stat(lertick_stat_LERTICK_STAT_SHARED_DISPATCHES),
            nr_continuations: self.stat(lertick_stat_LERTICK_STAT_CONTINUATIONS),
            nr_adaptive_slices: self.stat(lertick_stat_LERTICK_STAT_ADAPTIVE_SLICES),
            nr_training_updates: self.stat(lertick_stat_LERTICK_STAT_TRAINING_UPDATES),
        }
    }

    pub fn exited(&mut self) -> bool {
        uei_exited!(&self.skel, uei)
    }

    fn run(&mut self, shutdown: Arc<AtomicBool>) -> Result<UserExitInfo> {
        let (res_ch, req_ch) = self.stats_server.channels();
        while !shutdown.load(Ordering::Relaxed) && !self.exited() {
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
