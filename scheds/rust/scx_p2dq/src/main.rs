// Copyright (c) Meta Platforms, Inc. and affiliates.

// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.
mod bpf_skel;
pub use bpf_skel::*;

pub mod bpf_intf;
pub mod stats;
use stats::Metrics;

use scx_p2dq::SchedulerOpts;
use scx_p2dq::TOPO;

use std::mem;
use std::mem::MaybeUninit;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};
use std::{ffi::CString, io};

use libc::{ftok, msgget, msgrcv, IPC_NOWAIT};
use scx_utils::mangoapp::{mangoapp_msg_v1, MANGOAPP_PROJ_ID};

use anyhow::Context;
use anyhow::Result;
use clap::Parser;
use crossbeam::channel::RecvTimeoutError;
use libbpf_rs::MapCore as _;
use libbpf_rs::OpenObject;
use log::{debug, error, info, warn};
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
use crate::bpf_intf::stat_idx_P2DQ_STAT_IDLE;
use crate::bpf_intf::stat_idx_P2DQ_STAT_KEEP;
use crate::bpf_intf::stat_idx_P2DQ_STAT_LLC_MIGRATION;
use crate::bpf_intf::stat_idx_P2DQ_STAT_MANGO;
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

#[derive(Debug, Clone)]
struct MangoAppAction {
    pid: u32,
    vis_frametime: u64,
    app_frametime: u64,
    fsr_upscale: u32,
    fsr_sharpness: u32,
    latency_ns: u64,
    output_width: u32,
    output_height: u32,
    display_refresh: u32,
}

struct Scheduler<'a> {
    skel: BpfSkel<'a>,
    struct_ops: Option<libbpf_rs::Link>,

    stats_server: StatsServer<(), Metrics>,

    mangoapp_scheduling: bool,
    mangoapp_key: i32,
    mangoapp_poll_ms: Duration,
    mangoapp_path: CString,
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

        match *compat::SCX_OPS_ALLOW_QUEUED_WAKEUP {
            0 => info!("Kernel does not support queued wakeup optimization."),
            v => open_skel.struct_ops.p2dq_mut().flags |= v,
        };

        let mut skel = scx_ops_load!(open_skel, p2dq, uei)?;
        scx_p2dq::init_skel!(&mut skel);

        let struct_ops = Some(scx_ops_attach!(skel, p2dq)?);

        let stats_server = StatsServer::new(stats::server_data()).launch()?;

        let mangoapp_scheduling = opts.mangoapp_scheduling;
        let mangoapp_poll_ms = Duration::from_millis(opts.mangoapp_poll_ms as u64);
        let mangoapp_path = CString::new(opts.mangoapp_path.clone())?;
        let mangoapp_key = -1;

        info!("P2DQ scheduler started! Run `scx_p2dq --monitor` for metrics.");

        let mut sched = Self {
            skel,
            struct_ops,
            stats_server,
            mangoapp_scheduling,
            mangoapp_key,
            mangoapp_poll_ms,
            mangoapp_path,
        };
        sched.init_mangoapp()?;
        Ok(sched)
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
            mango: stats[stat_idx_P2DQ_STAT_MANGO as usize],
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

    fn init_mangoapp(&mut self) -> Result<()> {
        if !self.mangoapp_scheduling {
            return Ok(());
        }
        let key = unsafe { ftok(self.mangoapp_path.as_ptr(), MANGOAPP_PROJ_ID) };
        if key == -1 {
            return Err(anyhow::anyhow!(
                "failed to ftok: {}",
                io::Error::last_os_error()
            ));
        }

        let msgid = unsafe { msgget(key, 0) };
        if msgid == -1 {
            return Err(anyhow::anyhow!(
                "msgget failed: {}",
                std::io::Error::last_os_error()
            ));
        }
        self.mangoapp_key = msgid;

        Ok(())
    }

    fn poll_mangoapp(&self) -> Result<Option<MangoAppAction>> {
        let mut raw_msg: mangoapp_msg_v1 = unsafe { mem::zeroed() };
        let msg_size = unsafe {
            msgrcv(
                self.mangoapp_key,
                &mut raw_msg as *mut _ as *mut libc::c_void,
                mem::size_of::<mangoapp_msg_v1>() - mem::size_of::<i64>(),
                0,
                IPC_NOWAIT, // XXX: this should probably use MSG_COPY
            )
        };
        if msg_size as isize == -1 {
            if io::Error::last_os_error().kind() != io::ErrorKind::WouldBlock {
                info!(
                    "mangoapp: msgrcv returned -1 with error {}",
                    io::Error::last_os_error()
                );
            }
            return Ok(None);
        }

        let vis_frametime = raw_msg.visible_frametime_ns;
        let fsr_upscale = raw_msg.fsr_upscale;
        let fsr_sharpness = raw_msg.fsr_sharpness;
        let app_frametime = raw_msg.app_frametime_ns;
        let pid = raw_msg.pid;
        let latency_ns = raw_msg.latency_ns;
        let output_width = raw_msg.output_width;
        let output_height = raw_msg.output_height;
        let display_refresh = raw_msg.display_refresh;
        let action = MangoAppAction {
            pid,
            vis_frametime,
            app_frametime,
            fsr_upscale: fsr_upscale.into(),
            fsr_sharpness: fsr_sharpness.into(),
            latency_ns,
            output_width,
            output_height,
            display_refresh: display_refresh.into(),
        };

        Ok(Some(action))
    }

    fn run(&mut self, shutdown: Arc<AtomicBool>) -> Result<UserExitInfo> {
        let (res_ch, req_ch) = self.stats_server.channels();
        let mut mangoapp_last_poll = Instant::now();

        while !shutdown.load(Ordering::Relaxed) && !uei_exited!(&self.skel, uei) {
            let now = Instant::now();
            if self.mangoapp_scheduling && now - mangoapp_last_poll >= self.mangoapp_poll_ms {
                match self.poll_mangoapp() {
                    Ok(Some(action)) => {
                        info!("Received MangoApp action: {:?}", action);
                        self.skel.maps.bss_data.mangoapp_tgid = action.pid as i32;
                        self.skel.maps.bss_data.mangoapp_slice = action.app_frametime;
                    }
                    Ok(None) => {
                        // No MangoApp message
                    }
                    Err(e) => {
                        error!("Error polling MangoApp: {}", e);
                        // Disable bpf scheduling
                        self.skel.maps.bss_data.mangoapp_tgid = 0;
                    }
                }
                mangoapp_last_poll = now;
            }
            match req_ch.recv_timeout(self.mangoapp_poll_ms) {
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
