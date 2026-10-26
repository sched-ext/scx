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
/* Resume gap in seconds shared with FLOW_RESUME_GAP_NS in intf.h. A loop */
/* stall past this bound reads as a suspend plus resume gap, so the run */
/* loop refreshes the topology view once while BPF clamps stale deltas. */
/* Monotonic pauses across S3, so the boot gap trips S3 here. */
const RESUME_GAP_SECS: u64 = 5;
/* Boot clock id for suspend-aware gaps. Value 7 on Linux. */
const CLOCK_BOOTTIME: i32 = 7;

/// Boot time including suspend, else None on fault.
/// Uses clock_gettime with no extra dep, so S3 trips the gap where
/// Instant plus monotonic pause with no false trip on bad reads.
fn boot_now() -> Option<Duration> {
    #[repr(C)]
    struct Timespec {
        tv_sec: i64,
        tv_nsec: i64,
    }
    unsafe extern "C" {
        fn clock_gettime(clk_id: i32, tp: *mut Timespec) -> i32;
    }
    let mut ts = Timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: clock_gettime writes a valid timespec on success.
    let rc = unsafe { clock_gettime(CLOCK_BOOTTIME, &mut ts) };
    if rc != 0 {
        return None;
    }
    if ts.tv_sec < 0 || ts.tv_nsec < 0 || ts.tv_nsec >= 1_000_000_000 {
        return None;
    }
    Some(Duration::new(ts.tv_sec as u64, ts.tv_nsec as u32))
}

/// True when the boot gap passes the 5s resume bound.
/// Pure for host injection with no clock use, so start at now minus
/// 6s trips while a short stall stays quiet with wrap safety.
fn boot_gap_exceeded(last: Duration, now: Duration) -> bool {
    match now.checked_sub(last) {
        Some(d) => d > Duration::from_secs(RESUME_GAP_SECS),
        None => false,
    }
}
/* CPU bound shared with the BPF header. */
#[cfg(test)]
const MAX_CPUS: usize = crate::bpf_intf::flow_consts_FLOW_MAX_CPUS as usize;

fn full_version() -> String {
    build_id::full_version(env!("CARGO_PKG_VERSION"))
}

/// Validated poll interval from float seconds.
/// Rejects NaN plus infinite plus non-positive plus over one hour, so
/// a bad flag fails closed before any timer starts with no panic.
fn poll_interval_secs(v: f64) -> Result<Duration> {
    if !v.is_finite() || v <= 0.0 || v > 3600.0 {
        anyhow::bail!("interval bad {v}");
    }
    Ok(Duration::from_secs_f64(v))
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
    /* Seeded rows in rank order for the resume watch. */
    seeded: Vec<(u32, u32, u32)>,
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
            seeded: rows,
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
        /* Resume watch on the loop tick: a stall past 5s reads as a */
        /* suspend plus resume gap, so the topology view reseeds once */
        /* with no hotplug use. BPF monotonic heals s2idle stalls via */
        /* the 5s delta clamp, while boot time trips S3 where monotonic */
        /* pauses plus long stalls reseed here. Manual check: run then */
        /* echo mem > /sys/power/state, resume, expect one refresh. */
        let mut last_tick = std::time::Instant::now();
        let mut last_boot = boot_now();
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
            /* One resume check per tick keeps the reseed to one refresh */
            /* per stall with no extra poll. */
            let now = std::time::Instant::now();
            let stalled = now.duration_since(last_tick);
            last_tick = now;
            let boot = boot_now();
            let boot_stalled = match (last_boot, boot) {
                (Some(l), Some(n)) => boot_gap_exceeded(l, n),
                _ => false,
            };
            if boot.is_some() {
                last_boot = boot;
            }
            if stalled > Duration::from_secs(RESUME_GAP_SECS) || boot_stalled {
                if boot_stalled {
                    info!("resume suspected on boot gap, refreshing topology");
                } else {
                    info!("resume suspected after {stalled:?}, refreshing topology");
                }
                if let Some(rows) = topology::reseed_if_changed(&mut self.seeded) {
                    Self::seed_topo_with(&mut self.skel, &rows);
                    self.online_cpus = rows.iter().map(|(cpu, _, _)| *cpu).collect();
                    self.smt = rows
                        .iter()
                        .map(|(cpu, sib, _)| topology::is_smt_thread(*cpu, *sib))
                        .collect();
                    self.topology = topology::describe_topology(&rows);
                    info!("Topology: {}", self.topology);
                }
            }
        }
        let m = self.get_metrics();
        info!(
            "exit ins={} req={} done={} local={} node={} machine={} kick={} adm={} rej={} miss={} gate={} pkick={} pskip={} redrej={} redrec={} runtime={} oncpu={}",
            m.inserts,
            m.requeues,
            m.completions,
            m.local_moves,
            m.node_moves,
            m.machine_moves,
            m.kicks,
            m.admits,
            m.rejects,
            m.misses,
            m.gate_rejects,
            m.preempt_kicks,
            m.preempt_skipped,
            m.red_rejects,
            m.red_reclaims,
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
        let dur = poll_interval_secs(intv)?;
        let sd = shutdown.clone();
        let jh = std::thread::spawn(move || {
            if let Err(e) = stats::monitor(dur, sd) {
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
        assert!(poll_interval_secs(1.0).is_ok());
        assert!(poll_interval_secs(0.0).is_err());
        assert!(poll_interval_secs(-1.0).is_err());
        assert!(poll_interval_secs(f64::NAN).is_err());
        assert!(poll_interval_secs(f64::INFINITY).is_err());
        assert!(poll_interval_secs(3601.0).is_err());
    }

    #[test]
    fn max_cpus_matches_header() {
        assert_eq!(
            MAX_CPUS,
            crate::bpf_intf::flow_consts_FLOW_MAX_CPUS as usize
        );
    }

    #[test]
    fn quantum_matches_header() {
        assert_eq!(
            crate::config::QUANTUM_NS,
            crate::bpf_intf::flow_consts_FLOW_QUANTUM_NS as u64
        );
        assert_eq!(crate::config::QUANTUM_NS, 1_000_000);
        assert_eq!(crate::config::WEIGHT_BASE, 128);
        assert_eq!(crate::config::WEIGHT_MIN, 1);
        assert_eq!(crate::config::WEIGHT_MAX, 16_384);
    }

    #[test]
    fn slot_matches_header() {
        assert_eq!(crate::bpf_intf::flow_consts_FLOW_MACHINE as u64, 0x5A00);
        assert_eq!(crate::bpf_intf::flow_consts_FLOW_OVERFLOW as u64, 0x5A01);
        assert_eq!(crate::bpf_intf::flow_consts_FLOW_MAX_DSQS as u64, 1042);
    }

    #[test]
    fn period_matches_header() {
        assert_eq!(
            crate::config::PERIOD_NS,
            crate::bpf_intf::flow_consts_FLOW_PERIOD_NS as u64
        );
        assert_eq!(crate::config::PERIOD_NS, 80_000_000);
    }

    #[test]
    fn task_size_is_72() {
        assert_eq!(std::mem::size_of::<crate::bpf_intf::flow_task_ctx>(), 72);
    }

    #[test]
    fn cpu_size_is_16() {
        assert_eq!(std::mem::size_of::<crate::bpf_intf::flow_cpu_state>(), 16);
    }

    #[test]
    fn topo_size_is_8() {
        assert_eq!(std::mem::size_of::<crate::bpf_intf::flow_topo>(), 8);
    }

    #[test]
    fn sched_stats_size_is_136() {
        assert_eq!(
            std::mem::size_of::<crate::bpf_intf::flow_sched_stats>(),
            136
        );
    }

    #[test]
    fn fixed_red_matches_header() {
        assert_eq!(
            crate::bpf_intf::flow_consts_FLOW_RED_TOL_NS as u64,
            crate::config::RED_TOL_NS
        );
        assert_eq!(crate::config::RED_TOL_NS, 64_000);
        assert_eq!(
            crate::bpf_intf::flow_consts_FLOW_RED_EMAX_NS as u64,
            crate::config::RED_EMAX_NS
        );
        assert_eq!(crate::config::RED_EMAX_NS, 256_000);
    }

    #[test]
    fn kick_rule_matches_header() {
        assert_eq!(
            crate::bpf_intf::flow_consts_FLOW_PREEMPT_MARGIN_NS as u64,
            crate::config::PREEMPT_MARGIN_NS
        );
        assert_eq!(crate::config::PREEMPT_MARGIN_NS, 100_000);
        assert_eq!(
            crate::bpf_intf::flow_consts_FLOW_PREEMPT_TAIL_NS as u64,
            crate::config::PREEMPT_TAIL_NS
        );
        assert_eq!(crate::config::PREEMPT_TAIL_NS, 100_000);
    }

    #[test]
    fn hint_matches_header() {
        assert_eq!(
            crate::config::HINT_MAX,
            crate::bpf_intf::flow_consts_FLOW_HINT_MAX as u64
        );
        assert_eq!(crate::config::HINT_MAX, 8192);
    }

    #[test]
    fn resume_gap_matches_header() {
        assert_eq!(RESUME_GAP_SECS, 5);
        assert_eq!(
            crate::bpf_intf::flow_consts_FLOW_RESUME_GAP_NS as u64,
            RESUME_GAP_SECS * 1_000_000_000
        );
    }

    #[test]
    fn boot_gap_trips_on_6s_stall() {
        // Injected boot gap of 6s trips S3 where monotonic pauses.
        let last = Duration::from_secs(100);
        let now = last + Duration::from_secs(6);
        assert!(boot_gap_exceeded(last, now));
        // Short 1s stall stays quiet with no reseed.
        assert!(!boot_gap_exceeded(last, last + Duration::from_secs(1)));
        // Exact 5s bound stays quiet, past trips with no wrap trip.
        assert!(!boot_gap_exceeded(last, last + Duration::from_secs(5)));
        assert!(!boot_gap_exceeded(now, last));
        if let Some(t) = boot_now() {
            assert!(t.as_secs() > 0);
        }
    }
}
