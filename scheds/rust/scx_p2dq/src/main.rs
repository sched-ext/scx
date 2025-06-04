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

use anyhow::bail;
use anyhow::Context;
use anyhow::Result;
use clap::Parser;
use crossbeam::channel::RecvTimeoutError;
use libbpf_rs::MapCore as _;
use libbpf_rs::OpenObject;
use libbpf_rs::ProgramInput;
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
use scx_utils::Topology;
use scx_utils::UserExitInfo;
use scx_utils::NR_CPU_IDS;
use scx_utils::{Core, Llc};

use std::ffi::c_ulong;

use bpf_intf::stat_idx_P2DQ_NR_STATS;
use bpf_intf::stat_idx_P2DQ_STAT_DIRECT;
use bpf_intf::stat_idx_P2DQ_STAT_DISPATCH_PICK2;
use bpf_intf::stat_idx_P2DQ_STAT_DSQ_CHANGE;
use bpf_intf::stat_idx_P2DQ_STAT_DSQ_SAME;
use bpf_intf::stat_idx_P2DQ_STAT_IDLE;
use bpf_intf::stat_idx_P2DQ_STAT_KEEP;
use bpf_intf::stat_idx_P2DQ_STAT_LLC_MIGRATION;
use bpf_intf::stat_idx_P2DQ_STAT_NODE_MIGRATION;
use bpf_intf::stat_idx_P2DQ_STAT_SELECT_PICK2;
use bpf_intf::stat_idx_P2DQ_STAT_WAKE_LLC;
use bpf_intf::stat_idx_P2DQ_STAT_WAKE_MIG;
use bpf_intf::stat_idx_P2DQ_STAT_WAKE_PREV;
use scx_p2dq::SchedulerOpts;
use scx_p2dq::TOPO;

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
    verbose: u8,

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
        open_skel.maps.rodata_data.nr_cpu_ids = *NR_CPU_IDS as u32;
        scx_p2dq::init_open_skel!(&mut open_skel, opts, verbose)?;

        match *compat::SCX_OPS_ALLOW_QUEUED_WAKEUP {
            0 => info!("Kernel does not support queued wakeup optimization."),
            v => open_skel.struct_ops.p2dq_mut().flags |= v,
        };

        let mut skel = scx_ops_load!(open_skel, p2dq, uei)?;

        scx_p2dq::init_skel!(&mut skel);

        let stats_server = StatsServer::new(stats::server_data()).launch()?;

        Ok(Self {
            skel,
            struct_ops: None,
            verbose,
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

    fn setup_arenas(&mut self) -> Result<()> {
        // Allocate the arena memory from the BPF side so userspace initializes it before starting
        // the scheduler. Despite the function call's name this is neither a test nor a test run,
        // it's the recommended way of executing SEC("syscall") probes.
        let mut args = types::arena_init_args {
            static_pages: bpf_intf::consts_STATIC_ALLOC_PAGES_GRANULARITY as c_ulong,
            task_ctx_size: std::mem::size_of::<types::task_p2dq>() as c_ulong,
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

        let output = self.skel.progs.arena_init.test_run(input)?;
        if output.return_value != 0 {
            bail!(
                "Could not initialize arenas, p2dq_setup returned {}",
                output.return_value as i32
            );
        }

        Ok(())
    }

    fn setup_topology_node(&mut self, mask: &[u64]) -> Result<()> {
        let mut args = types::arena_alloc_mask_args {
            bitmap: 0 as c_ulong,
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

        let output = self.skel.progs.arena_alloc_mask.test_run(input)?;
        if output.return_value != 0 {
            bail!(
                "Could not initialize arenas, setup_topology_node returned {}",
                output.return_value as i32
            );
        }

        let ptr = unsafe { std::mem::transmute::<u64, &mut [u64; 10]>(args.bitmap) };

        let (valid_mask, _) = ptr.split_at_mut(mask.len());
        valid_mask.clone_from_slice(mask);

        let mut args = types::arena_topology_node_init_args {
            bitmap: args.bitmap as c_ulong,
            data_size: 0 as c_ulong,
            id: 0 as c_ulong,
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

        let output = self.skel.progs.arena_topology_node_init.test_run(input)?;
        if output.return_value != 0 {
            bail!(
                "p2dq_topology_node_init returned {}",
                output.return_value as i32
            );
        }

        Ok(())
    }

    fn setup_topology(&mut self) -> Result<()> {
        let topo = Topology::new().expect("Failed to build host topology");

        self.setup_topology_node(topo.span.as_raw_slice())?;

        for (_, node) in topo.nodes {
            self.setup_topology_node(node.span.as_raw_slice())?;
        }

        for (_, llc) in topo.all_llcs {
            self.setup_topology_node(
                Arc::<Llc>::into_inner(llc)
                    .expect("missing llc")
                    .span
                    .as_raw_slice(),
            )?;
        }

        for (_, core) in topo.all_cores {
            self.setup_topology_node(
                Arc::<Core>::into_inner(core)
                    .expect("missing core")
                    .span
                    .as_raw_slice(),
            )?;
        }
        for (_, cpu) in topo.all_cpus {
            let mut mask = [0; 9];
            mask[cpu.id.checked_shr(64).unwrap_or(0)] |= 1 << (cpu.id % 64);
            self.setup_topology_node(&mask)?;
        }

        Ok(())
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

        let _ = self.struct_ops.take();
        uei_report!(&self.skel, uei)
    }

    fn print_topology(&mut self) -> Result<()> {
        let input = ProgramInput {
            ..Default::default()
        };

        let output = self.skel.progs.arena_topology_print.test_run(input)?;
        if output.return_value != 0 {
            bail!(
                "Could not initialize arenas, topo_print returned {}",
                output.return_value as i32
            );
        }

        Ok(())
    }

    fn start(&mut self) -> Result<()> {
        self.setup_arenas()?;
        self.setup_topology()?;

        self.struct_ops = Some(scx_ops_attach!(self.skel, p2dq)?);

        if self.verbose > 1 {
            self.print_topology()?;
        }

        info!("P2DQ scheduler started! Run `scx_p2dq --monitor` for metrics.");

        Ok(())
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
    lcfg.set_time_offset_to_local()
        .unwrap()
        .set_time_level(simplelog::LevelFilter::Error)
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
        sched.start()?;

        if !sched.run(shutdown.clone())?.should_restart() {
            break;
        }
    }
    Ok(())
}
