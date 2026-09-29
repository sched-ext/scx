// SPDX-License-Identifier: GPL-2.0
//! Flow scheduler front end.
//!
//! Copyright (c) 2026 Galih Tama <galpt@v.recipes>

//! Loads the BPF object, seeds the topology view, then drives the loop.
//! Observability is counters through the stats server plus the loopback
//! dashboard with per CPU cards plus a JSON snapshot for debugging.

mod bpf_skel;
pub use bpf_skel::*;
pub mod bpf_intf;
pub use bpf_intf::*;
#[path = "rust/config.rs"]
mod config;
#[path = "rust/flow.rs"]
mod flow;
#[path = "rust/flow_cgrp.rs"]
mod flow_cgrp;
#[path = "rust/flow_edf.rs"]
mod flow_edf;
#[path = "rust/flow_preempt.rs"]
mod flow_preempt;
#[path = "rust/flow_runtime.rs"]
mod flow_runtime;
#[path = "rust/flow_select.rs"]
mod flow_select;
#[path = "rust/flow_slice.rs"]
mod flow_slice;
/* Test-only queue id mirror with no production use, so it stays out of */
/* the binary and only builds for tests. */
#[cfg(test)]
#[path = "rust/flow_slot.rs"]
mod flow_slot;
#[path = "rust/snapshot.rs"]
mod snapshot;
#[path = "rust/stats.rs"]
mod stats;
#[path = "rust/topology.rs"]
mod topology;
#[path = "rust/webui.rs"]
mod webui;

use std::mem::MaybeUninit;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::time::Duration;

use anyhow::Result;
use clap::CommandFactory;
use clap::Parser;
use clap_complete::Shell;
use clap_complete::generate;
use crossbeam::channel::RecvTimeoutError;
use log::info;
use scx_stats::prelude::*;
use scx_utils::UserExitInfo;
use scx_utils::build_id;
use scx_utils::libbpf_clap_opts::LibbpfOpts;
use scx_utils::scx_ops_attach;
use scx_utils::scx_ops_load;
use scx_utils::scx_ops_open;
use scx_utils::try_set_rlimit_infinity;
use scx_utils::uei_exited;
use scx_utils::uei_report;

use config::Config;
use stats::Metrics;

/* Binary name used in logs and stats. */
const SCHEDULER_NAME: &str = "scx_flow";
/* CPU bound shared with the BPF header. */
#[cfg(test)]
const MAX_CPUS: usize = crate::bpf_intf::flow_consts_FLOW_MAX_CPUS as usize;

fn full_version() -> String {
    build_id::full_version(env!("CARGO_PKG_VERSION"))
}

#[derive(Debug, Parser)]
#[command(name = SCHEDULER_NAME, version, disable_version_flag = true)]
struct Opts {
    /* Poll interval for the stats printer. */
    #[clap(long)]
    stats: Option<f64>,
    /* Run the stats printer only. */
    #[clap(long)]
    monitor: Option<f64>,
    /* Verbose BPF logging. */
    #[clap(short = 'd', long, action = clap::ArgAction::SetTrue)]
    debug: bool,
    /* Verbose output with libbpf detail. */
    #[clap(short = 'v', long, action = clap::ArgAction::SetTrue)]
    verbose: bool,
    /* Exit dump buffer length in bytes. */
    #[clap(long, default_value = "1048576")]
    exit_dump_len: u32,
    /* Print version and exit. */
    #[clap(short = 'V', long, action = clap::ArgAction::SetTrue)]
    version: bool,
    /* Show stat descriptions. */
    #[clap(long)]
    help_stats: bool,
    /* Generate shell completions and exit. */
    #[clap(long, value_name = "SHELL", hide = true)]
    completions: Option<Shell>,
    /* Disable the loopback dashboard thread. */
    #[clap(long = "no-webui", action = clap::ArgAction::SetTrue)]
    no_webui: bool,
    #[clap(flatten, next_help_heading = "Libbpf Options")]
    libbpf: LibbpfOpts,
}

/*
 * Scheduler owns the skeleton, the link, the stats
 * server plus the dashboard channel. It drives the run
 * loop until shutdown or exit.
 */
pub(crate) struct Scheduler<'a> {
    skel: BpfSkel<'a>,
    struct_ops: Option<libbpf_rs::Link>,
    stats_server: StatsServer<(), Metrics>,
    started_at: std::time::Instant,
    /* Dashboard sender with None when disabled. */
    webui_tx: Option<crossbeam::channel::Sender<stats::WebMetrics>>,
    /* Online ids once at init in rank order. */
    online_cpus: Vec<u32>,
    /* SMT flag per online CPU in rank order for the cards. */
    smt: Vec<bool>,
    /* One line topology summary for the page. */
    topology: String,
}

impl<'a> Scheduler<'a> {
    fn init(
        opts: &'a Opts,
        open_object: &'a mut MaybeUninit<libbpf_rs::OpenObject>,
        shutdown: Arc<AtomicBool>,
    ) -> Result<Self> {
        try_set_rlimit_infinity();
        let mut bld = BpfSkelBuilder::default();
        bld.obj_builder.debug(opts.debug || opts.verbose);
        let open_opts = opts.libbpf.clone().into_bpf_open_opts();
        let mut skel = scx_ops_open!(bld, open_object, flow_ops, open_opts)?;
        /* Validate the constants before load. */
        let cfg = Config::default();
        cfg.validate()?;
        info!("Config: {}", cfg.describe());
        /* Ops flags live in the BPF object for kernel 7.2 and up. */
        skel.struct_ops.flow_ops_mut().exit_dump_len = opts.exit_dump_len;
        let mut skel = scx_ops_load!(skel, flow_ops, uei)?;
        let _ = &mut skel;
        /* Seed the BPF topology view with sibling plus node rows. */
        /* Failures keep the BPF defaults with node zero. */
        let rows = topology::topo_rows();
        Self::seed_topo_with(&mut skel, &rows);
        let struct_ops = scx_ops_attach!(skel, flow_ops)?;
        let stats_server = StatsServer::new(stats::server_data()).launch()?;
        /* Bounded dashboard channel drops a frame when full. */
        let webui_tx = if opts.no_webui {
            None
        } else {
            let (tx, rx) = crossbeam::channel::bounded::<stats::WebMetrics>(16);
            let sd = shutdown.clone();
            std::thread::spawn(move || {
                webui::start(rx, sd);
            });
            Some(tx)
        };
        let online_cpus: Vec<u32> = rows.iter().map(|(cpu, _, _)| *cpu).collect();
        /* SMT flags cache the sibling view with no sysfs use on poll. */
        let smt: Vec<bool> = rows
            .iter()
            .map(|(cpu, sib, _)| topology::is_smt_thread(*cpu, *sib))
            .collect();
        let topology = topology::describe_topology(&rows);
        info!("Topology: {topology}");
        Ok(Self {
            skel,
            struct_ops: Some(struct_ops),
            stats_server,
            started_at: std::time::Instant::now(),
            webui_tx,
            online_cpus,
            smt,
            topology,
        })
    }

    fn exited(&self) -> bool {
        uei_exited!(&self.skel, uei)
    }

    /* Seed one topology row per CPU into the BPF view. */
    /* Each row carries the thread sibling and the node id. */
    /* A failed update keeps the BPF default with no trap. */
    fn seed_topo_with(skel: &mut BpfSkel<'_>, rows: &[(u32, u32, u32)]) {
        use libbpf_rs::MapCore;
        for (cpu, sib, node) in rows {
            let key = cpu.to_ne_bytes();
            let mut val = [0u8; 8];
            val[0..4].copy_from_slice(&sib.to_ne_bytes());
            val[4..8].copy_from_slice(&node.to_ne_bytes());
            if let Err(e) = skel
                .maps
                .topo_stor
                .update(&key, &val, libbpf_rs::MapFlags::ANY)
            {
                log::warn!("topo seed failed for cpu {cpu}: {e}");
            }
        }
    }

    fn run(&mut self, shutdown: Arc<AtomicBool>) -> Result<UserExitInfo> {
        let (res_ch, req_ch) = self.stats_server.channels();
        /* Short tick keeps stats polls prompt while the page polls */
        /* once per second, so most ticks only refresh the bound */
        /* channel when the dashboard is on plus the queue has room. */
        /* One BPF read serves both the stats reply plus the page. */
        while !shutdown.load(Ordering::Relaxed) && !self.exited() {
            match req_ch.recv_timeout(Duration::from_millis(100)) {
                Ok(()) => {
                    if let Some(ref tx) = self.webui_tx {
                        if !tx.is_full() {
                            let web = self.get_web_metrics();
                            let stats = web.stats.clone();
                            let _ = tx.try_send(web);
                            res_ch.send(stats)?
                        } else {
                            res_ch.send(self.get_metrics())?
                        }
                    } else {
                        res_ch.send(self.get_metrics())?
                    }
                }
                Err(RecvTimeoutError::Timeout) => {
                    if let Some(ref tx) = self.webui_tx
                        && !tx.is_full()
                    {
                        let web = self.get_web_metrics();
                        let _ = tx.try_send(web);
                    }
                }
                Err(e) => Err(e)?,
            }
        }
        let m = self.get_metrics();
        info!(
            "exit ins={} req={} done={} local={} node={} machine={} over={} kick={} adm={} rej={} miss={} park={} gate={} runtime={} oncpu={}",
            m.inserts,
            m.requeues,
            m.completions,
            m.local_moves,
            m.node_moves,
            m.machine_moves,
            m.over_moves,
            m.kicks,
            m.admits,
            m.rejects,
            m.misses,
            m.parks,
            m.gate_rejects,
            m.total_runtime,
            m.on_cpu,
        );
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
    let only = opts.monitor.is_some();
    if opts.version {
        println!("{} {}", SCHEDULER_NAME, full_version());
        return Ok(());
    }
    if opts.help_stats {
        println!("stats: top");
        return Ok(());
    }
    if !only {
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
    let sd = shutdown.clone();
    ctrlc::set_handler(move || {
        sd.store(true, Ordering::Relaxed);
    })?;
    if let Some(intv) = opts.monitor.or(opts.stats) {
        let sd = shutdown.clone();
        let jh = std::thread::spawn(move || {
            if let Err(e) = stats::monitor(Duration::from_secs_f64(intv), sd) {
                log::warn!("monitor failed: {e}");
            }
        });
        if only {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scheduler_name_is_flow() {
        assert_eq!(SCHEDULER_NAME, "scx_flow");
    }

    #[test]
    fn max_cpus_matches_header() {
        assert_eq!(
            MAX_CPUS,
            crate::bpf_intf::flow_consts_FLOW_MAX_CPUS as usize
        );
    }

    #[test]
    fn batch_matches_header() {
        assert_eq!(
            crate::config::Config::default().dispatch_batch,
            crate::bpf_intf::flow_consts_FLOW_DISPATCH_MAX_BATCH
        );
        assert_eq!(crate::config::Config::default().dispatch_batch, 16);
    }

    #[test]
    fn quantum_matches_header() {
        assert_eq!(
            crate::flow_slice::QUANTUM_NS,
            crate::bpf_intf::flow_consts_FLOW_QUANTUM_NS as u64
        );
        assert_eq!(crate::flow_slice::QUANTUM_NS, 2_000_000);
        assert_eq!(crate::flow_slice::WEIGHT_BASE, 128);
        assert_eq!(crate::flow_slice::WEIGHT_MIN, 1);
        assert_eq!(crate::flow_slice::WEIGHT_MAX, 16_384);
    }

    #[test]
    fn slot_matches_header() {
        assert_eq!(
            crate::flow_slot::SLOT_OVERFLOW,
            crate::bpf_intf::flow_consts_FLOW_OVERFLOW as u64
        );
        assert_eq!(crate::flow_slot::SLOT_OVERFLOW, 0x5A01);
        assert_eq!(
            crate::flow_slot::SLOT_MACHINE,
            crate::bpf_intf::flow_consts_FLOW_MACHINE as u64
        );
        assert_eq!(
            crate::flow_slot::SLOT_MAX_DSQS,
            crate::bpf_intf::flow_consts_FLOW_MAX_DSQS as u64
        );
        assert_eq!(crate::flow_slot::SLOT_MAX_DSQS, 522);
    }

    #[test]
    fn period_matches_header() {
        assert_eq!(
            crate::flow_edf::PERIOD_NS,
            crate::bpf_intf::flow_consts_FLOW_PERIOD_NS as u64
        );
        assert_eq!(crate::flow_edf::PERIOD_NS, 16_000_000);
    }

    #[test]
    fn task_size_is_72() {
        assert_eq!(std::mem::size_of::<crate::bpf_intf::flow_task_ctx>(), 72);
    }

    #[test]
    fn cpu_size_is_8() {
        assert_eq!(std::mem::size_of::<crate::bpf_intf::flow_cpu_state>(), 8);
    }

    #[test]
    fn topo_size_is_8() {
        assert_eq!(std::mem::size_of::<crate::bpf_intf::flow_topo>(), 8);
    }

    #[test]
    fn sched_stats_size_is_120() {
        assert_eq!(
            std::mem::size_of::<crate::bpf_intf::flow_sched_stats>(),
            120
        );
    }

    #[test]
    fn kick_rule_matches_header() {
        assert!(crate::flow::arrival_kicks(10, 20));
        assert!(!crate::flow::arrival_kicks(20, 20));
    }

    #[test]
    fn runtime_advance_matches_base() {
        assert_eq!(crate::flow::runtime_advance(0, 2_000_000, 128), 2_000_000);
    }

    #[test]
    fn hint_matches_header() {
        assert_eq!(
            crate::flow_cgrp::HINT_MAX,
            crate::bpf_intf::flow_consts_FLOW_HINT_MAX as u64
        );
    }
}
