// SPDX-License-Identifier: GPL-2.0
//
// Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

mod bpf_skel;
pub use bpf_skel::*;
pub mod bpf_intf;
pub use bpf_intf::*;

mod stats;

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
use libbpf_rs::OpenObject;
use log::debug;
use log::info;
use log::warn;
use scx_stats::prelude::*;
use scx_utils::build_id;
use scx_utils::compat;
use scx_utils::get_primary_cpus;
use scx_utils::libbpf_clap_opts::LibbpfOpts;
use scx_utils::scx_ops_attach;
use scx_utils::scx_ops_cid_load;
use scx_utils::scx_ops_cid_open;
use scx_utils::try_set_rlimit_infinity;
use scx_utils::uei_exited;
use scx_utils::uei_report;
use scx_utils::Powermode;
use scx_utils::Topology;
use scx_utils::UserExitInfo;
use scx_utils::NR_CPUS_POSSIBLE;
use scx_utils::NR_CPU_IDS;
use stats::Metrics;

const SCHEDULER_NAME: &str = "scx_cidland";

/// scx_cidland: a cid-based, topology-aware scheduler.
///
/// Rather than raw CPU numbers, this scheduler addresses CPUs by their cid
/// (topological CPU ID), a dense id space where the CPUs of a core, of an LLC
/// and of a NUMA node occupy contiguous ranges. Idle CPU selection is a plain
/// range scan over a bitmap of idle cids, preferring a fully idle core in the
/// LLC the task last ran on.
///
/// Tasks that can't be dispatched to an idle cid are queued to a single shared
/// DSQ, ordered by a virtual deadline that prioritizes tasks which sleep often
/// and run in short bursts, and consumed by the first cid that runs out of
/// work.
///
/// This requires a kernel with cid-form sched_ext support (struct
/// sched_ext_ops_cid).
#[derive(Debug, Parser)]
struct Opts {
    /// Time slice assigned to each task in microseconds.
    #[clap(short = 's', long, default_value = "1000")]
    slice_us: u64,

    /// Maximum time slice credit, in microseconds, that a task can accumulate
    /// while sleeping.
    ///
    /// Larger values give a bigger priority boost to tasks that sleep a lot,
    /// at the cost of fairness towards CPU intensive tasks.
    #[clap(short = 'l', long, default_value = "20000")]
    slice_lag_us: u64,

    /// Specifies a group of CPUs to be preferred when looking for an idle CPU.
    ///
    /// Accepts a comma-separated list of CPUs or ranges (e.g. 0-3,8-11), or one
    /// of the following keywords:
    ///
    /// "performance" = prioritize the fastest CPUs,
    /// "powersave" = prioritize the slowest CPUs,
    /// "turbo" = prioritize the CPUs with the highest max frequency,
    /// "all" = all CPUs assigned to the primary domain.
    ///
    /// This is a preference, not an isolation mechanism: tasks still overflow
    /// to the other CPUs when the primary domain has nothing idle to offer.
    ///
    /// By default all CPUs are used.
    #[clap(short = 'm', long, value_name = "CPU_LIST")]
    primary_domain: Option<String>,

    /// Exit debug dump buffer length. 0 indicates default.
    #[clap(long, default_value = "0")]
    exit_dump_len: u32,

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

/// Resolve the --primary-domain argument: either one of the topology keywords
/// or an explicit CPU list.
fn parse_primary_domain(arg: &str) -> Result<Vec<usize>> {
    let mode = match arg {
        "performance" => Some(Powermode::Performance),
        "powersave" => Some(Powermode::Powersave),
        "turbo" => Some(Powermode::Turbo),
        "all" => Some(Powermode::Any),
        _ => None,
    };

    let Some(mode) = mode else {
        return parse_cpu_list(arg);
    };

    let mut cpus = get_primary_cpus(mode).context("detecting the primary CPUs")?;
    if cpus.is_empty() {
        bail!("no CPU matches \"{arg}\" on this system");
    }
    cpus.sort_unstable();
    cpus.dedup();

    Ok(cpus)
}

/// Parse a comma-separated list of CPUs and ranges, e.g. "0-3,8,10-11".
fn parse_cpu_list(arg: &str) -> Result<Vec<usize>> {
    let mut cpus = Vec::new();

    for token in arg.split(',') {
        let token = token.trim();

        if token.is_empty() {
            continue;
        }

        if let Some((start, end)) = token.split_once('-') {
            let start: usize = start
                .trim()
                .parse()
                .with_context(|| format!("invalid range start in {token:?}"))?;
            let end: usize = end
                .trim()
                .parse()
                .with_context(|| format!("invalid range end in {token:?}"))?;
            if start > end {
                bail!("invalid range {token:?}");
            }
            cpus.extend(start..=end);
        } else {
            cpus.push(
                token
                    .parse()
                    .with_context(|| format!("invalid cpu id {token:?}"))?,
            );
        }
    }

    if cpus.is_empty() {
        bail!("no CPU specified");
    }
    cpus.sort_unstable();
    cpus.dedup();

    Ok(cpus)
}

struct Scheduler<'a> {
    skel: BpfSkel<'a>,
    struct_ops: Option<libbpf_rs::Link>,
    stats_server: StatsServer<(), Metrics>,
}

impl<'a> Scheduler<'a> {
    fn init(opts: &'a Opts, open_object: &'a mut MaybeUninit<OpenObject>) -> Result<Self> {
        try_set_rlimit_infinity();

        if opts.slice_us == 0 {
            bail!("--slice-us must be greater than 0");
        }

        // The cid space is always num_possible_cpus() entries wide.
        if *NR_CPUS_POSSIBLE > MAX_CIDS as usize {
            bail!(
                "too many CPUs: {} (max {}), rebuild with a larger MAX_CIDS",
                *NR_CPUS_POSSIBLE,
                MAX_CIDS
            );
        }

        let topo = Topology::new().context("detecting system topology")?;
        info!(
            "{} {} ({} CPUs, {} LLCs)",
            SCHEDULER_NAME,
            build_id::full_version(env!("CARGO_PKG_VERSION")),
            *NR_CPUS_POSSIBLE,
            topo.all_llcs.len(),
        );

        // Initialize BPF connector.
        let mut skel_builder = BpfSkelBuilder::default();
        skel_builder.obj_builder.debug(opts.verbose);
        let open_opts = opts.libbpf.clone().into_bpf_open_opts();
        let mut skel = scx_ops_cid_open!(skel_builder, open_object, cidland_ops, open_opts)
            .context("opening BPF skeleton (does this kernel support cid-form sched_ext?)")?;

        skel.struct_ops.cidland_ops_mut().exit_dump_len = opts.exit_dump_len;

        let rodata = skel
            .maps
            .rodata_data
            .as_mut()
            .expect("rodata_data missing after skel open");
        rodata.slice_ns = opts.slice_us * 1000;
        rodata.slice_lag = opts.slice_lag_us * 1000;

        // Define the primary scheduling domain, in cpu space: the BPF side
        // translates it to cids once the kernel has built the cid layout.
        if let Some(ref domain) = opts.primary_domain {
            let cpus = parse_primary_domain(domain).context("parsing primary domain")?;

            if let Some(cpu) = cpus.iter().find(|cpu| **cpu >= *NR_CPU_IDS) {
                bail!(
                    "primary domain cpu {} exceeds nr_cpu_ids {}",
                    cpu,
                    *NR_CPU_IDS
                );
            }
            if cpus.len() < *NR_CPU_IDS {
                info!("primary domain: {:?}", cpus);
                for cpu in cpus {
                    rodata.primary_cpus[cpu / 64] |= 1u64 << (cpu % 64);
                }
                rodata.primary_all = false;
            }
        }

        // Set scheduler flags.
        //
        // SCX_OPS_BUILTIN_IDLE_PER_NODE is intentionally left out: cid-form
        // schedulers can't use the built-in idle tracking at all, this one
        // does its own via ops.update_idle().
        skel.struct_ops.cidland_ops_mut().flags = *compat::SCX_OPS_ENQ_EXITING
            | *compat::SCX_OPS_ENQ_LAST
            | *compat::SCX_OPS_ENQ_MIGRATION_DISABLED
            | *compat::SCX_OPS_ALLOW_QUEUED_WAKEUP;
        info!(
            "scheduler flags: {:#x}",
            skel.struct_ops.cidland_ops_mut().flags
        );

        // Load and attach the scheduler.
        let mut skel = scx_ops_cid_load!(skel, cidland_ops, uei).context("loading BPF skeleton")?;
        let struct_ops = Some(scx_ops_attach!(skel, cidland_ops).context("attaching scheduler")?);
        let stats_server = StatsServer::new(stats::server_data()).launch()?;

        Ok(Self {
            skel,
            struct_ops,
            stats_server,
        })
    }

    fn get_metrics(&self) -> Metrics {
        let bss_data = self
            .skel
            .maps
            .bss_data
            .as_ref()
            .expect("bss_data missing after skel load");
        Metrics {
            nr_direct_dispatches: bss_data.nr_direct_dispatches,
            nr_shared_enqueues: bss_data.nr_shared_enqueues,
            nr_idle_kicks: bss_data.nr_idle_kicks,
            nr_local_llc: bss_data.nr_local_llc,
            nr_remote_llc: bss_data.nr_remote_llc,
        }
    }

    fn exited(&mut self) -> bool {
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
                Ok(_) => debug!("stats monitor thread finished successfully"),
                Err(error_object) => {
                    warn!("stats monitor thread finished because of an error {error_object}")
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
