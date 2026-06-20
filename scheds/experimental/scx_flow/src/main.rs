// SPDX-License-Identifier: GPL-2.0
//
// Copyright (c) 2026 Galih Tama <galpt@v.recipes>
//
// This software may be used and distributed according to the terms of the GNU
// General Public License version 2.

mod bpf_skel;
pub use bpf_skel::*;
pub use bpf_skel::types;
pub mod bpf_intf;
pub use bpf_intf::*;

mod carriage;
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
    #[clap(long)]
    stats: Option<f64>,

    #[clap(long)]
    monitor: Option<f64>,

    #[clap(short, long, action = clap::ArgAction::SetTrue)]
    debug: bool,

    #[clap(short = 'V', long, action = clap::ArgAction::SetTrue)]
    version: bool,

    #[clap(long = "no-webui", action = clap::ArgAction::SetTrue)]
    no_webui: bool,

    #[clap(long, action = clap::ArgAction::SetTrue)]
    no_autotune: bool,

    #[clap(long, value_name = "SHELL", hide = true)]
    completions: Option<Shell>,

    #[clap(flatten, next_help_heading = "Libbpf Options")]
    libbpf: LibbpfOpts,
}

struct Scheduler<'a> {
    skel: BpfSkel<'a>,
    struct_ops: Option<libbpf_rs::Link>,
    stats_server: StatsServer<(), Metrics>,
    webui_tx: Option<crossbeam::channel::Sender<stats::WebMetrics>>,
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

        // Write scheduler PID to BSS so BPF can bypass the carriage.
        {
            let key: u32 = 0;
            let mut bss_raw = skel.maps.bss
                .lookup(&key.to_ne_bytes(), libbpf_rs::MapFlags::ANY)
                .ok()
                .flatten()
                .unwrap_or_default();
            let pid_offset = std::mem::offset_of!(types::bss, flow_scheduler_pid);
            let pid_bytes = (std::process::id() as u64).to_ne_bytes();
            let bss_slice = bss_raw.as_mut_slice();
            if pid_offset + 8 <= bss_slice.len() {
                bss_slice[pid_offset..pid_offset + 8].copy_from_slice(&pid_bytes);
            }
            let _ = skel.maps.bss.update(&key.to_ne_bytes(), &bss_raw,
                                         libbpf_rs::MapFlags::ANY);
        }

        // Discover topology and write into BSS.
        carriage::init_topology(&mut skel)?;

        let struct_ops = scx_ops_attach!(skel, flow_ops)?;

        let stats_server = StatsServer::new(stats::server_data()).launch()?;

        let webui_tx: Option<crossbeam::channel::Sender<stats::WebMetrics>> = if !opts.no_webui {
            let (tx, rx) = crossbeam::channel::unbounded::<stats::WebMetrics>();
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
        let bss_data = self.skel.maps.bss_data.as_ref().expect("bss_data missing — BPF object has no .bss section");
        let cpu_policy_state = self.read_cpu_policy_state();
        Metrics {
            on_cpu: bss_data.on_cpu,
            total_runtime: bss_data.total_runtime,
            uptime_ns: self.started_at.elapsed().as_nanos() as u64,

            prio_dispatches: bss_data.prio_dispatches,
            pinned_dispatches: bss_data.pinned_dispatches,

            carriage_producer: bss_data.carriage_producer,


            budget_exhaustions: bss_data.budget_exhaustions + cpu_policy_state.budget_exhaustions,
            runnable_wakeups: bss_data.runnable_wakeups + cpu_policy_state.runnable_wakeups,
            cpu_migrations: bss_data.cpu_migrations + cpu_policy_state.cpu_migrations,
        }
    }

    fn get_web_metrics(&self) -> stats::WebMetrics {
        let metrics = self.get_metrics();
        let bss_data = self.skel.maps.bss_data.as_ref().expect("bss_data missing — BPF object has no .bss section");

        let nr_cpus = bss_data.nr_cpu_ids as usize;
        let mut per_cpu = Vec::with_capacity(nr_cpus);
        for cpu in 0..nr_cpus {
            if cpu >= 1024 {
                break;
            }
            per_cpu.push(stats::PerCpuMetrics {
                id: cpu as u32,
                freq_khz: bss_data.per_cpu_max_freq_khz[cpu],
                llc_id: bss_data.per_cpu_llc_id[cpu] as u32,
                smt: bss_data.per_cpu_is_smt[cpu] != 0,
            });
        }

        let closed_slot = (bss_data.carriage_producer.wrapping_sub(1) & 63) as usize;
        let carriage_filling_count = if closed_slot < 64 {
            bss_data.carriage_pool[closed_slot].count as u64
        } else {
            0
        };

        stats::WebMetrics {
            stats: metrics,
            per_cpu,
            carriage_filling_count,
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
                        let wm = self.get_web_metrics();
                        let _ = tx.try_send(wm);
                    }
                    res_ch.send(m)?;
                }
                Err(RecvTimeoutError::Timeout) => {
                    if let Some(ref tx) = self.webui_tx {
                        let wm = self.get_web_metrics();
                        let _ = tx.try_send(wm);
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
