// SPDX-License-Identifier: GPL-2.0
//
// Copyright (c) 2026 Galih Tama <galpt@v.recipes>
//
// This software may be used and distributed according to the terms of the GNU
// General Public License version 2.

mod bpf_skel;
pub use bpf_skel::*;
pub mod bpf_intf;
pub use bpf_intf::*;

mod stats;
mod webui;
use std::mem::MaybeUninit;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use clap::CommandFactory;
use clap::Parser;
use clap_complete::generate;
use clap_complete::Shell;
use crossbeam::channel::RecvTimeoutError;
use libbpf_rs::MapCore;
use log::info;
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
use scx_utils::UserExitInfo;

use stats::Metrics;

const SCHEDULER_NAME: &str = "scx_flow";

fn full_version() -> String {
    build_id::full_version(env!("CARGO_PKG_VERSION"))
}

#[derive(Debug, Parser)]
#[command(name = SCHEDULER_NAME, version, disable_version_flag = true)]
struct Opts {
    /// Enable stats monitoring with the specified interval.
    #[clap(long)]
    stats: Option<f64>,

    /// Run in stats monitoring mode with the specified interval. Scheduler is not launched.
    #[clap(long)]
    monitor: Option<f64>,

    /// Debug mode
    #[clap(short, long, action = clap::ArgAction::SetTrue)]
    debug: bool,

    /// Print scheduler version and exit.
    #[clap(short = 'V', long, action = clap::ArgAction::SetTrue)]
    version: bool,

    /// Disable the web UI (http://localhost:50005).
    #[clap(long = "no-webui", action = clap::ArgAction::SetTrue)]
    no_webui: bool,

    /// Disable adaptive runtime tuning (no-op, kept for backward compatibility).
    #[clap(long, action = clap::ArgAction::SetTrue)]
    no_autotune: bool,

    /// Generate shell completions for the given shell and exit.
    #[clap(long, value_name = "SHELL", hide = true)]
    completions: Option<Shell>,

    #[clap(flatten, next_help_heading = "Libbpf Options")]
    libbpf: LibbpfOpts,
}

struct Scheduler<'a> {
    skel: BpfSkel<'a>,
    struct_ops: Option<libbpf_rs::Link>,
    stats_server: StatsServer<(), Metrics>,
    webui_tx: Option<crossbeam::channel::Sender<Metrics>>,
    started_at: std::time::Instant,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct CpuPolicyStateAgg {
    budget_exhaustions: u64,
    runnable_wakeups: u64,
    cpu_migrations: u64,
}

impl<'a> Scheduler<'a> {
    fn read_cpu_policy_state(&self) -> CpuPolicyStateAgg {
        let key = 0u32.to_ne_bytes();
        let mut agg = CpuPolicyStateAgg::default();

        let percpu_vals: Vec<Vec<u8>> = match self
            .skel
            .maps
            .cpu_state
            .lookup_percpu(&key, libbpf_rs::MapFlags::ANY)
        {
            Ok(Some(vals)) => vals,
            _ => return agg,
        };

        for cpu_val in percpu_vals.iter() {
            if cpu_val.len() < std::mem::size_of::<bpf_intf::flow_cpu_state>() {
                continue;
            }

            let state = unsafe {
                std::ptr::read_unaligned(cpu_val.as_ptr() as *const bpf_intf::flow_cpu_state)
            };

            agg.budget_exhaustions = agg
                .budget_exhaustions
                .saturating_add(state.budget_exhaustions);
            agg.runnable_wakeups = agg.runnable_wakeups.saturating_add(state.runnable_wakeups);
            agg.cpu_migrations = agg.cpu_migrations.saturating_add(state.cpu_migrations);
        }

        agg
    }

    fn init(
        opts: &'a Opts,
        open_object: &'a mut MaybeUninit<libbpf_rs::OpenObject>,
        shutdown: Arc<AtomicBool>,
    ) -> Result<Self> {
        try_set_rlimit_infinity();

        let mut skel_builder = BpfSkelBuilder::default();
        skel_builder.obj_builder.debug(opts.debug);

        let open_opts = opts.libbpf.clone().into_bpf_open_opts();
        let mut skel = scx_ops_open!(skel_builder, open_object, flow_ops, open_opts)?;

        skel.struct_ops.flow_ops_mut().flags = *compat::SCX_OPS_ENQ_EXITING
            | *compat::SCX_OPS_ENQ_LAST
            | *compat::SCX_OPS_ENQ_MIGRATION_DISABLED
            | *compat::SCX_OPS_ALLOW_QUEUED_WAKEUP;

        let mut skel = scx_ops_load!(skel, flow_ops, uei)?;

        let struct_ops = scx_ops_attach!(skel, flow_ops)?;

        // Expose live metrics for monitor and stats clients.
        let stats_server = StatsServer::new(stats::server_data()).launch()?;

        // Start the web UI thread (unless disabled).
        let webui_tx: Option<crossbeam::channel::Sender<Metrics>> = if !opts.no_webui {
            let (tx, rx) = crossbeam::channel::unbounded::<Metrics>();
            let shutdown = shutdown.clone();
            std::thread::spawn(move || {
                webui::start(rx, shutdown);
            });
            Some(tx)
        } else {
            None
        };

        Ok(Self {
            skel,
            struct_ops: Some(struct_ops),
            stats_server,
            webui_tx,
            started_at: std::time::Instant::now(),
        })
    }

    fn get_metrics(&self) -> Metrics {
        let bss_data = self.skel.maps.bss_data.as_ref().unwrap();
        let cpu_policy_state = self.read_cpu_policy_state();
        Metrics {
            nr_running: bss_data.nr_running,
            total_runtime: bss_data.total_runtime,
            prio_dispatches: bss_data.prio_dispatches,
            pinned_dispatches: bss_data.pinned_dispatches,
            tier_priority_dispatches: bss_data.tier_priority_dispatches,
            tier_normal_dispatches: bss_data.tier_normal_dispatches,
            tier_low_dispatches: bss_data.tier_low_dispatches,
            tier_deficit_dispatches: bss_data.tier_deficit_dispatches,
            budget_refill_events: bss_data.budget_refill_events,
            budget_exhaustions: bss_data.budget_exhaustions + cpu_policy_state.budget_exhaustions,
            runnable_wakeups: bss_data.runnable_wakeups + cpu_policy_state.runnable_wakeups,
            cpu_migrations: bss_data.cpu_migrations + cpu_policy_state.cpu_migrations,
            uptime_ns: self.started_at.elapsed().as_nanos() as u64,
        }
    }

    fn exited(&self) -> bool {
        uei_exited!(&self.skel, uei)
    }

    fn run(&mut self, shutdown: Arc<AtomicBool>) -> Result<UserExitInfo> {
        let (res_ch, req_ch) = self.stats_server.channels();

        while !shutdown.load(Ordering::Relaxed) && !self.exited() {
            match req_ch.recv_timeout(Duration::from_millis(250)) {
                Ok(()) => {
                    let m = self.get_metrics();
                    if let Some(ref tx) = self.webui_tx {
                        let _ = tx.try_send(m.clone());
                    }
                    res_ch.send(m)?;
                }
                Err(RecvTimeoutError::Timeout) => {
                    // No stats client connected — still push metrics to web UI.
                    let m = self.get_metrics();
                    if let Some(ref tx) = self.webui_tx {
                        let _ = tx.try_send(m);
                    }
                }
                Err(e) => Err(e)?,
            }
        }

        let _ = self.struct_ops.take();
        uei_report!(&self.skel, uei)
    }
}

fn main() -> Result<()> {
    let opts = Opts::parse();

    if let Some(shell) = opts.completions {
        generate(
            shell,
            &mut Opts::command(),
            SCHEDULER_NAME,
            &mut std::io::stdout(),
        );
        return Ok(());
    }

    let monitor_only = opts.monitor.is_some();

    if opts.version {
        println!("{} {}", SCHEDULER_NAME, full_version());
        return Ok(());
    }

    if !monitor_only {
        simplelog::SimpleLogger::init(
            if opts.debug {
                simplelog::LevelFilter::Debug
            } else {
                simplelog::LevelFilter::Info
            },
            simplelog::Config::default(),
        )?;

        info!("{} {}", SCHEDULER_NAME, full_version());
        info!("Starting {} scheduler", SCHEDULER_NAME);
    }

    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_clone = shutdown.clone();

    ctrlc::set_handler(move || {
        shutdown_clone.store(true, Ordering::Relaxed);
    })?;

    if let Some(intv) = opts.monitor.or(opts.stats) {
        let monitor_shutdown = shutdown.clone();
        let jh = std::thread::spawn(move || {
            if let Err(err) = stats::monitor(Duration::from_secs_f64(intv), monitor_shutdown) {
                log::warn!("stats monitor thread finished with error: {err}");
            }
        });

        if monitor_only {
            let _ = jh.join();
            return Ok(());
        }
    }

    let mut open_object = MaybeUninit::<libbpf_rs::OpenObject>::uninit();
    let mut sched = Scheduler::init(&opts, &mut open_object, shutdown.clone())?;
    sched.run(shutdown)?;

    info!("Scheduler exited");

    Ok(())
}
