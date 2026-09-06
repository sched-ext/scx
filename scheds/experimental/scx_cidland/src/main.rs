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
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::time::Duration;

use anyhow::Context;
use anyhow::Result;
use anyhow::bail;
use clap::Parser;
use crossbeam::channel::RecvTimeoutError;
use libbpf_rs::OpenObject;
use libbpf_rs::ProgramInput;
use libbpf_rs::skel::Skel;
use log::debug;
use log::info;
use log::warn;
use scx_arena::ArenaLib;
use scx_stats::prelude::*;
use scx_utils::NR_CPU_IDS;
use scx_utils::NR_CPUS_POSSIBLE;
use scx_utils::Topology;
use scx_utils::UserExitInfo;
use scx_utils::build_id;
use scx_utils::compat;
use scx_utils::libbpf_clap_opts::LibbpfOpts;
use scx_utils::scx_ops_attach;
use scx_utils::scx_ops_cid_load;
use scx_utils::scx_ops_cid_open;
use scx_utils::try_set_rlimit_infinity;
use scx_utils::uei_exited;
use scx_utils::uei_report;
use stats::Metrics;

const SCHEDULER_NAME: &str = "scx_cidland";

/// Run a SEC("syscall") program with @args as its context.
///
/// Despite the name this is not a test run, it's the supported way of invoking
/// a syscall program from userspace.
fn run_syscall_prog<T>(prog: &libbpf_rs::ProgramMut<'_>, args: &mut T) -> Result<()> {
    let input = ProgramInput {
        context_in: Some(unsafe {
            std::slice::from_raw_parts_mut(args as *mut T as *mut u8, std::mem::size_of::<T>())
        }),
        ..Default::default()
    };

    let output = prog.test_run(input)?;
    if output.return_value != 0 {
        bail!(
            "{} returned {}",
            prog.name().to_string_lossy(),
            output.return_value as i32
        );
    }

    Ok(())
}

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

    /// Maximum lag, in microseconds of virtual time, that a task can carry across a sleep.
    ///
    /// This bounds both the credit a task can bring back from a sleep and the debt it can
    /// carry after consuming more than its share: an over-served task waits for the system
    /// vruntime to cover the debt before it runs again, and under heavy load that reference
    /// moves slowly. EEVDF bounds the lag to twice the base slice (max(2 * slice, tick)).
    #[clap(short = 'l', long, default_value = "2000")]
    slice_lag_us: u64,

    /// Disable NUMA optimizations.
    #[clap(short = 'n', long, action = clap::ArgAction::SetTrue)]
    disable_numa: bool,

    /// Disable SMT awareness: every cid is treated as a core of its own.
    #[clap(short = 'S', long, action = clap::ArgAction::SetTrue)]
    disable_smt: bool,

    /// Ignore synchronous wakeup events.
    #[clap(short = 'w', long, action = clap::ArgAction::SetTrue)]
    no_wake_sync: bool,

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

struct Scheduler<'a> {
    _arenalib: ArenaLib,
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

        let topo = Topology::new().context("detecting system topology")?;
        info!(
            "{} {} ({} CPUs, {} LLCs)",
            SCHEDULER_NAME,
            build_id::full_version(env!("CARGO_PKG_VERSION")),
            *NR_CPUS_POSSIBLE,
            topo.all_llcs.len(),
        );

        // Only walk the node ranges when there is more than one node with
        // CPUs on it: on a single node system they cover everything and the
        // extra pass is pure overhead.
        let nr_nodes = topo
            .nodes
            .values()
            .filter(|node| !node.all_cpus.is_empty())
            .count();
        let numa_enabled = !opts.disable_numa && nr_nodes > 1;
        if !numa_enabled {
            info!("NUMA optimizations disabled");
        }

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
        rodata.numa_enabled = numa_enabled;
        rodata.smt_enabled = !opts.disable_smt && topo.smt_enabled;
        rodata.no_wake_sync = opts.no_wake_sync;

        // Capacity tiers: CPUs sorted by capacity in descending order, one
        // tier per distinct capacity, 0 being the fastest. Capacities are
        // normalized to 1..1024 so the highest is always 1024.
        let mut cpus: Vec<_> = topo.all_cpus.values().collect();
        cpus.sort_by_key(|cpu| std::cmp::Reverse(cpu.cpu_capacity));
        let max_cap = cpus.first().map(|c| c.cpu_capacity).unwrap_or(1).max(1);
        let mut tier = 0u64;
        let mut cpu_tiers: Vec<(u64, u64, u64)> = Vec::new();
        for (i, cpu) in cpus.iter().enumerate() {
            let normalized = (cpu.cpu_capacity * 1024 / max_cap).clamp(1, 1024);
            if i > 0 && cpus[i - 1].cpu_capacity != cpu.cpu_capacity {
                tier += 1;
            }
            cpu_tiers.push((cpu.id as u64, normalized as u64, tier));
        }
        let nr_tiers = tier + 1;
        if nr_tiers > 1 {
            info!(
                "CPUs by capacity: {:?}",
                cpus.iter().map(|cpu| cpu.id).collect::<Vec<_>>()
            );
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

        // Bring up the arena: this sizes everything that is indexed by cid
        // and the per-task contexts. It has to happen before the scheduler is
        // visible to the kernel, so it sits between load and attach.
        //
        // The cid space is num_possible_cpus() wide, so the CPU count is all
        // the BPF side needs to size itself.
        let nr_cpus = (*NR_CPU_IDS).max(*NR_CPUS_POSSIBLE);
        let mut args = types::cidland_arena_args {
            nr_cpus: nr_cpus as u64,
            nr_tiers,
        };
        run_syscall_prog(&skel.progs.cidland_arena_init, &mut args)
            .context("running cidland_arena_init")?;

        // Hand over the capacity and the tier of each CPU, in cpu space: the
        // cid layout is only known once the kernel has built it, at attach, so
        // ops.init() translates.
        for (cpu, capacity, tier) in cpu_tiers {
            let mut args = types::cidland_cpu_args {
                cpu,
                capacity,
                tier,
            };
            run_syscall_prog(&skel.progs.cidland_set_cpu, &mut args)
                .context("running cidland_set_cpu")?;
        }

        // The BPF side has a scheduler-specific initialization path, but the
        // allocator still needs ArenaLib's userspace services. In particular,
        // scx_task_free_rcu() relies on its reclaim daemon to return exited
        // task contexts to the allocator.
        let arenalib =
            ArenaLib::start(skel.object_mut()).context("starting arena userspace services")?;

        let struct_ops = Some(scx_ops_attach!(skel, cidland_ops).context("attaching scheduler")?);
        let stats_server = StatsServer::new(stats::server_data()).launch()?;

        Ok(Self {
            _arenalib: arenalib,
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
            nr_queued: bss_data.nr_queued,
            nr_steals: bss_data.nr_steals,
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
