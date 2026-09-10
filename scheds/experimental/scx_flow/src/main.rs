/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 *
 * Flow scheduler front end. Loads the BPF object, wires
 * stats and the dashboard, and drives the run loop until
 * shutdown or exit. Snapshot reads live in snapshot.
 */
mod bpf_skel;
pub use bpf_skel::*;
pub mod bpf_intf;
pub use bpf_intf::*;
mod config;
mod flow;
mod flow_edf;
mod flow_group;
mod flow_preempt;
mod flow_select;
mod flow_slice;
#[cfg(test)]
mod flow_tests_edf;
#[cfg(test)]
mod flow_tests_group;
#[cfg(test)]
mod flow_tests_preempt;
mod snapshot;
mod stats;
mod topology;
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
use scx_utils::compat;
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
 * server and the dashboard channel. It drives the run
 * loop until shutdown or exit. Snapshot reads live in
 * the snapshot module.
 */
pub(crate) struct Scheduler<'a> {
    skel: BpfSkel<'a>,
    struct_ops: Option<libbpf_rs::Link>,
    stats_server: StatsServer<(), Metrics>,
    /* Dashboard sender. None when disabled. */
    webui_tx: Option<crossbeam::channel::Sender<stats::WebMetrics>>,
    /* Static per-CPU cards seeded at attach. */
    cpu_static: Vec<stats::PerCpuMetrics>,
    /* Live frequency cache for the cards. */
    cur_freq_khz: Vec<u64>,
    freq_read_at: Option<std::time::Instant>,
    started_at: std::time::Instant,
    /* Per CPU group table plus ready flag. */
    group_table: [u8; crate::flow_group::GROUP_TABLE_LEN],
    /* Zero keeps halves fallback in snapshot. */
    group_ready: u8,
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
        /* Honor exiting tasks and waiting wakeups. */
        let flags = *compat::SCX_OPS_ENQ_EXITING
            | *compat::SCX_OPS_ENQ_LAST
            | *compat::SCX_OPS_ENQ_MIGRATION_DISABLED
            | *compat::SCX_OPS_ALLOW_QUEUED_WAKEUP;
        skel.struct_ops.flow_ops_mut().flags = flags;
        skel.struct_ops.flow_ops_mut().exit_dump_len = opts.exit_dump_len;
        /* Static cards seed the start log and the cards. */
        /* Live frequency plus CPU cards stay display */
        /* only and never shape placement. Max frequency */
        /* plus capacity plus LLC plus siblings seed groups. */
        let cards = topology::web_cpu_static();
        /* Seed the per CPU group table. Uniform hosts keep */
        /* ready cleared with halves fallback and no trap. */
        /* All singleton cores keep prior halves plus */
        /* interleave exactly with no trap. */
        let nr_groups = cards
            .iter()
            .map(|c| c.id as usize + 1)
            .max()
            .unwrap_or(0)
            .min(MAX_CPUS);
        let (group_table, group_ready) = topology::group_seed(nr_groups);
        let (sibling_table, sibling_fallbacks) = topology::sibling_seed(nr_groups);
        if let Some(bss) = skel.maps.bss_data.as_mut() {
            bss.flow_group_by_cpu = group_table;
            bss.flow_group_ready = group_ready;
            bss.flow_sibling_by_cpu = sibling_table;
        }
        let mut skel = scx_ops_load!(skel, flow_ops, uei)?;
        let _ = &mut skel;
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
        /* Static cards seed the start log and the cards. */
        /* Frequency stays display only here. */
        info!("Topology: {}", topology::describe_topology(&cards));
        info!("siblings: {} fallbacks to singleton", sibling_fallbacks);
        let cpu_static = if opts.no_webui { Vec::new() } else { cards };
        Ok(Self {
            skel,
            struct_ops: Some(struct_ops),
            stats_server,
            webui_tx,
            cpu_static,
            cur_freq_khz: Vec::with_capacity(MAX_CPUS),
            freq_read_at: None,
            started_at: std::time::Instant::now(),
            group_table,
            group_ready,
        })
    }

    fn exited(&self) -> bool {
        uei_exited!(&self.skel, uei)
    }

    fn run(&mut self, shutdown: Arc<AtomicBool>) -> Result<UserExitInfo> {
        let (res_ch, req_ch) = self.stats_server.channels();
        while !shutdown.load(Ordering::Relaxed) && !self.exited() {
            match req_ch.recv_timeout(Duration::from_millis(100)) {
                Ok(()) => {
                    let web = self.get_web_metrics();
                    if let Some(ref tx) = self.webui_tx {
                        let _ = tx.try_send(web);
                    }
                    res_ch.send(self.get_metrics())?
                }
                Err(RecvTimeoutError::Timeout) => {
                    let web = self.get_web_metrics();
                    if let Some(ref tx) = self.webui_tx {
                        let _ = tx.try_send(web);
                    }
                }
                Err(e) => Err(e)?,
            }
        }
        let m = self.get_metrics();
        let (runtime, oncpu) = (m.total_runtime, m.on_cpu);
        info!(
            "exit ins={} req={} done={} park={} steal={} \
            kick={} noctx={} edfenq={} edfclamp={} edford={} \
            demote={} promote={} wpromote={} pinfl={} gskip={} \
            pkick={} pskip={} kcoal={} runtime={} oncpu={}",
            m.inserts,
            m.requeues,
            m.completions,
            m.park_moves,
            m.steal_moves,
            m.kicks,
            m.enq_no_tctx,
            m.edf_enqueued,
            m.edf_clamped,
            m.edf_ordered,
            m.group_demote,
            m.group_promote,
            m.group_wake_promote,
            m.pinned_hog_inflated,
            m.group_steal_skipped,
            m.preempt_kicks,
            m.preempt_skipped,
            m.kick_coalesced,
            runtime,
            oncpu,
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
            crate::flow_edf::DISPATCH_BATCH as u64,
            crate::bpf_intf::flow_consts_FLOW_DISPATCH_MAX_BATCH as u64
        );
    }

    #[test]
    fn slice_matches_header() {
        assert_eq!(
            crate::flow_slice::SLICE_NS,
            crate::bpf_intf::flow_consts_FLOW_SLICE_NS as u64
        );
        assert_eq!(crate::flow_slice::SLICE_NS, 1_000_000);
        assert_eq!(
            crate::flow_slice::EST_MIN_NS,
            crate::bpf_intf::flow_consts_FLOW_EST_MIN_NS as u64
        );
        assert_eq!(
            crate::flow_slice::EST_MAX_NS,
            crate::bpf_intf::flow_consts_FLOW_EST_MAX_NS as u64
        );
    }

    #[test]
    fn dsq_matches_header() {
        assert_eq!(
            crate::flow_edf::DSQ_BASE,
            crate::bpf_intf::flow_consts_FLOW_DSQ_BASE as u64
        );
        assert_eq!(
            crate::flow_edf::DSQ_PARK,
            crate::bpf_intf::flow_consts_FLOW_DSQ_PARK as u64
        );
    }

    #[test]
    fn edf_matches_header() {
        assert_eq!(
            crate::flow_slice::WEIGHT,
            crate::bpf_intf::flow_consts_FLOW_WEIGHT as u64
        );
        assert_eq!(crate::bpf_intf::flow_consts_FLOW_WEIGHT as u64, 1024);
    }

    #[test]
    fn steal_matches_header() {
        assert_eq!(
            crate::flow_select::STEAL_MIN_DEPTH,
            crate::bpf_intf::flow_consts_FLOW_STEAL_MIN_DEPTH as u64
        );
        assert_eq!(
            crate::flow_select::STEAL_BOUND as u64,
            crate::bpf_intf::flow_consts_FLOW_STEAL_BOUND as u64
        );
    }

    #[test]
    fn task_size_is_48() {
        assert_eq!(std::mem::size_of::<crate::bpf_intf::flow_task_ctx>(), 48);
    }

    #[test]
    fn cpu_size_within_32() {
        assert!(std::mem::size_of::<crate::bpf_intf::flow_cpu_state>() <= 32);
        assert_eq!(std::mem::size_of::<crate::bpf_intf::flow_cpu_state>(), 32);
    }

    #[test]
    fn sched_stats_size_is_160() {
        assert_eq!(
            std::mem::size_of::<crate::bpf_intf::flow_sched_stats>(),
            160
        );
    }

    #[test]
    fn groups_match_header() {
        assert_eq!(
            crate::flow_group::NGROUPS,
            crate::bpf_intf::flow_consts_FLOW_NGROUPS as u64
        );
        assert_eq!(
            crate::flow_group::GROUP_LIGHT as u64,
            crate::bpf_intf::flow_consts_FLOW_GROUP_LIGHT as u64
        );
        assert_eq!(
            crate::flow_group::GROUP_HOG as u64,
            crate::bpf_intf::flow_consts_FLOW_GROUP_HOG as u64
        );
        assert_eq!(
            crate::flow_group::PARK_LIGHT,
            crate::bpf_intf::flow_consts_FLOW_DSQ_PARK as u64
        );
        assert_eq!(
            crate::flow_group::PARK_HOG,
            crate::bpf_intf::flow_consts_FLOW_DSQ_PARK_HOG as u64
        );
    }
}
