// SPDX-License-Identifier: GPL-2.0
//
// Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.

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

#[derive(Debug, clap::Parser)]
#[command(
    name = "scx_cidland",
    version,
    disable_version_flag = true,
    about = "Topology-aware scheduler that preserves task-to-CPU locality, built on EEVDF concepts."
)]
struct Opts {
    /// Exit debug dump buffer length. 0 indicates default.
    #[clap(long, default_value = "0")]
    exit_dump_len: u32,

    /// Maximum scheduling slice duration in microseconds.
    ///
    /// A slice is only ever acted on from the tick: update_curr_scx() charges
    /// the time a task has run against it, and task_tick_scx() is the one
    /// place that reschedules once it is spent, so the granularity of the
    /// whole thing is 1/HZ no matter what is asked for here. A slice of
    /// exactly one tick therefore buys two: the task is handed the CPU a few
    /// microseconds after the tick that freed it, so at the next tick it is
    /// those few microseconds short of its slice and runs a whole further
    /// tick. Keep the default under a tick of a HZ=1000 kernel, at the
    /// normalized_sysctl_sched_base_slice of fair.c.
    #[clap(short = 's', long, default_value = "700")]
    slice_us: u64,

    /// Time, in microseconds, that a task stays cache hot on the CPU it last ran on.
    ///
    /// A task that stopped running within this long is left alone by the idle CPUs
    /// looking for work to steal: its own CPU takes it back within a slice, while
    /// moving it costs its cache. This is the equivalent of task_hot() with
    /// sysctl_sched_migration_cost in fair.c. 0 makes every queued task stealable
    /// right away, which spreads the load faster at the cost of cache locality.
    #[clap(short = 'm', long, default_value = "500")]
    migration_cost_us: u64,

    /// Number of remote queues a busy CPU samples on each dispatch.
    ///
    /// A CPU with a queue of its own looks at this many other queues, rotating
    /// through them across dispatches, and takes the head of one that is more than
    /// twice as deep as its own and at least two tasks deeper; this is what spreads
    /// out a pile-up created on a single CPU, the way the load balancer moves tasks
    /// off the busiest runqueue. A larger value finds an imbalance sooner and costs
    /// more work on every dispatch; 0 disables the sampling, leaving a busy CPU with
    /// its own queue only. Idle CPUs are not affected: they always scan the whole
    /// node for work.
    #[clap(short = 'b', long, default_value = "2", value_parser = clap::value_parser!(u32).range(0..=255))]
    balance_sample: u32,

    /// Failed scans an idle CPU tolerates before it stops honouring cache hotness.
    ///
    /// An idle CPU that finds nothing it is allowed to take, while work is queued
    /// somewhere it could have run, counts the attempt; once it has counted more
    /// than this many in a row it takes the head of a queue whether or not the
    /// task is still hot on the CPU it ran on. This is sd->cache_nice_tries
    /// against sd->nr_balance_failed in can_migrate_task(), and the value applies
    /// to a scan within the LLC; one more is allowed beyond it. 0 gives up cache
    /// locality on the first failure, a large value never gives it up and lets a
    /// CPU stay idle beside a runnable task for as long as the task keeps being
    /// hot.
    #[clap(short = 'c', long, default_value = "1", value_parser = clap::value_parser!(u32).range(0..=255))]
    cache_nice_tries: u32,

    /// Disable NUMA optimizations.
    #[clap(short = 'n', long, action = clap::ArgAction::SetTrue)]
    disable_numa: bool,

    /// Disable CPU frequency control.
    #[clap(short = 'f', long, action = clap::ArgAction::SetTrue)]
    disable_cpufreq: bool,

    /// Disable SMT.
    #[clap(short = 'S', long, action = clap::ArgAction::SetTrue)]
    disable_smt: bool,

    /// Ignore the cpu controller: schedule on the nice levels alone.
    ///
    /// By default a task's weight is its nice weight scaled by the cpu.weight
    /// of the cgroup it is in and of the cgroups that one sits under. This
    /// unhooks the scheduler from the cpu controller entirely, which is also
    /// what happens on a kernel built without CONFIG_EXT_GROUP_SCHED.
    #[clap(short = 'g', long, action = clap::ArgAction::SetTrue)]
    disable_cgroups: bool,

    /// Report every CPU at the same capacity, collapsing the capacity tiers.
    ///
    /// The capacity is guessed from ACPI CPPC or cpufreq, which separates the
    /// P-cores, the favored P-cores and the E-cores of a hybrid x86 into three
    /// tiers. The kernel's own cpu_capacity is uniform on those machines, so
    /// fair.c has no fast-core preference on the wakeup path. This makes cidland
    /// see what fair.c sees, for comparing the placement decisions of the two.
    #[clap(short = 'u', long, action = clap::ArgAction::SetTrue)]
    uniform_capacity: bool,

    /// Maximum capacity difference, in percent, within one capacity tier.
    ///
    /// Capacities are compared with the fastest CPU in the current tier, so
    /// small differences such as favored versus ordinary P-cores do not make
    /// wakeups chase a marginally faster CPU. A larger gap still starts a new
    /// tier and retains the preference for P-cores over E-cores. 0 restores
    /// one tier per distinct reported capacity.
    #[clap(short = 't', long, default_value = "5", value_parser = clap::value_parser!(u32).range(0..=50))]
    capacity_tier_tolerance_pct: u32,

    /// Disable direct dispatch during synchronous wakeups.
    ///
    /// Enabling this option can lead to a more uniform load distribution across available cores,
    /// potentially improving performance in certain scenarios. However, it may come at the cost of
    /// reduced efficiency for pipe-intensive workloads that benefit from tighter producer-consumer
    /// coupling.
    #[clap(short = 'w', long, action = clap::ArgAction::SetTrue)]
    no_wake_sync: bool,

    /// Interrupt on the deadlines alone, without asking who is owed service.
    ///
    /// The wakeup preemption normally fires only when the woken task is owed
    /// service and the running one is not, the way pick_eevdf() drops an
    /// ineligible current task and then picks an eligible waiter. This skips
    /// both tests and decides on the deadlines alone. For comparing the two
    /// rules against each other.
    #[clap(short = 'e', long, action = clap::ArgAction::SetTrue)]
    no_eligibility: bool,

    /// Interrupt a running task that is still owed service.
    ///
    /// The wakeup preemption normally leaves a running task alone until it has
    /// had the share its pack owes it, so a woken task with an earlier deadline
    /// waits for parity rather than for the slice to end. This drops that
    /// protection: the woken task takes the CPU as soon as it is eligible
    /// itself. Unlike --no-eligibility the woken task is still asked whether it
    /// is owed service; only the task already running loses its protection.
    ///
    /// This is RUN_TO_PARITY off, in the sense the feature had when EEVDF was
    /// merged. For comparing the two rules against each other.
    #[clap(short = 'r', long, action = clap::ArgAction::SetTrue)]
    no_run_to_parity: bool,

    /// Give a task a new request every time it is placed.
    ///
    /// A task that is moved to another CPU, or queued again without having
    /// slept, normally keeps what is left of the request it was in the middle
    /// of: its deadline is carried relative to its vruntime and re-based where
    /// it lands. This grants it a whole new request instead, so it sorts
    /// behind tasks that were queued after it. A task that slept gets a new
    /// request either way.
    ///
    /// This is PLACE_REL_DEADLINE off. For comparing the two rules against
    /// each other.
    #[clap(short = 'R', long, action = clap::ArgAction::SetTrue)]
    no_place_rel_deadline: bool,

    /// Never interrupt a running task for a woken one with an earlier deadline.
    ///
    /// Every task then runs until its slice ends or it blocks, and a woken task
    /// waits for that, up to a full slice. This is the behavior before wakeup
    /// preemption was added, kept for comparison.
    #[clap(short = 'p', long, action = clap::ArgAction::SetTrue)]
    no_wakeup_preempt: bool,

    /// Place and test tasks against a pack reference that is not up to date.
    ///
    /// A running task's vruntime is only charged when it stops, so the
    /// reference of its pack stands still while it runs and everything read
    /// off it in between is behind by up to a request. It is normally brought
    /// up to date on the spot, the way update_curr() does before every
    /// place_entity() and every entity_eligible(). This reads it as stored,
    /// for comparing the two against each other.
    #[clap(short = 'U', long, action = clap::ArgAction::SetTrue)]
    no_vref_update: bool,

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
    /// The arena's user-space services. Nothing here needs reclaiming, the
    /// arena is carved once at start, but the stream watcher turns an arena
    /// fault in a BPF program, which the kernel would otherwise fix up
    /// silently by dropping the access, into a report and an abort.
    _arenalib: ArenaLib,
    skel: BpfSkel<'a>,
    struct_ops: Option<libbpf_rs::Link>,
    stats_server: StatsServer<(), Metrics>,
}

/// Return TICK_NSEC, the kernel's timing granularity.
///
/// The coarse clocks are updated from the timer interrupt and nowhere else, so
/// what clock_getres() reports for one is the tick period: 1ms on a HZ=1000
/// kernel, 4ms on HZ=250. This is the bound EEVDF puts on the lag a task
/// carries, see entity_lag(), and CONFIG_HZ is not otherwise readable without
/// a kernel config that may not be mounted.
fn tick_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };

    let ret = unsafe { libc::clock_getres(libc::CLOCK_MONOTONIC_COARSE, &mut ts) };
    if ret == 0 && ts.tv_sec == 0 && ts.tv_nsec > 0 {
        return ts.tv_nsec as u64;
    }

    warn!("could not read the tick period, assuming HZ=1000");

    1_000_000
}

/// Assign sorted, descending CPU capacities to tiers.
///
/// Each capacity is compared with the fastest CPU in the current tier rather
/// than with the preceding CPU. This prevents a chain of individually small
/// differences from merging CPUs whose capacities differ significantly.
fn capacity_tiers(capacities: &[usize], tolerance_pct: u32) -> Vec<u64> {
    let Some(&first) = capacities.first() else {
        return Vec::new();
    };
    let keep_pct = 100usize - tolerance_pct as usize;
    let mut anchor = first;
    let mut tier = 0u64;
    let mut tiers = Vec::with_capacity(capacities.len());

    for &capacity in capacities {
        debug_assert!(capacity <= anchor);
        if capacity.saturating_mul(100) < anchor.saturating_mul(keep_pct) {
            tier += 1;
            anchor = capacity;
        }
        tiers.push(tier);
    }

    tiers
}

impl<'a> Scheduler<'a> {
    fn init(opts: &'a Opts, open_object: &'a mut MaybeUninit<OpenObject>) -> Result<Self> {
        try_set_rlimit_infinity();

        if opts.slice_us == 0 {
            bail!("--slice-us must be greater than 0");
        }

        // Initialize CPU topology.
        let topo = Topology::new().unwrap();

        // Check host topology to determine if we need to enable SMT capabilities.
        let smt_enabled = !opts.disable_smt && topo.smt_enabled;

        // Determine the amount of non-empty NUMA nodes in the system.
        let nr_nodes = topo
            .nodes
            .values()
            .filter(|node| !node.all_cpus.is_empty())
            .count();
        info!("NUMA nodes: {}", nr_nodes);

        // Automatically disable NUMA optimizations when running on non-NUMA systems.
        let numa_enabled = !opts.disable_numa && nr_nodes > 1;
        if !numa_enabled {
            info!("Disabling NUMA optimizations");
        }

        info!(
            "{} {} {}",
            SCHEDULER_NAME,
            build_id::full_version(env!("CARGO_PKG_VERSION")),
            if smt_enabled { "SMT on" } else { "SMT off" }
        );
        info!(
            "tick: {} us (HZ={})",
            tick_ns() / 1000,
            1_000_000_000 / tick_ns()
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
        let mut skel = scx_ops_cid_open!(skel_builder, open_object, cidland_ops, open_opts)
            .context("opening BPF skeleton (does this kernel support cid-form sched_ext?)")?;

        skel.struct_ops.cidland_ops_mut().exit_dump_len = opts.exit_dump_len;

        // Honor cpu.weight, unless it was turned off or the kernel has no cpu
        // controller support for sched_ext to hook into. Detaching the
        // callbacks from the struct_ops keeps the kernel from delivering them
        // at all, and lets the scheduler load on a kernel whose
        // sched_ext_ops_cid has no cpuctl_* members to bind them to.
        let cgroup_enabled = !opts.disable_cgroups
            && compat::struct_has_field("sched_ext_ops_cid", "cpuctl_set_weight").unwrap_or(false);
        if !cgroup_enabled {
            let ops = skel.struct_ops.cidland_ops_mut();
            ops.cpuctl_init = std::ptr::null_mut();
            ops.cpuctl_set_weight = std::ptr::null_mut();
            ops.cpuctl_move = std::ptr::null_mut();
            info!("cgroup weights: off");
        }

        // Override default BPF scheduling parameters.
        let rodata = skel.maps.rodata_data.as_mut().unwrap();
        rodata.slice_ns = opts.slice_us * 1000;
        rodata.tick_ns = tick_ns();
        rodata.migration_cost_ns = opts.migration_cost_us * 1000;
        rodata.balance_sample = opts.balance_sample;
        rodata.cache_nice_tries = opts.cache_nice_tries;
        rodata.cpufreq_enabled = !opts.disable_cpufreq;
        rodata.cgroup_enabled = cgroup_enabled;
        rodata.numa_enabled = numa_enabled;
        rodata.smt_enabled = smt_enabled;
        rodata.no_wake_sync = opts.no_wake_sync;
        rodata.no_wakeup_preempt = opts.no_wakeup_preempt;
        rodata.no_eligibility = opts.no_eligibility;
        rodata.no_run_to_parity = opts.no_run_to_parity;
        rodata.no_place_rel_deadline = opts.no_place_rel_deadline;
        rodata.no_vref_update = opts.no_vref_update;

        // Capacity tiers: CPUs sorted by capacity in descending order, with
        // close capacities coalesced into a tier, 0 being the fastest.
        // Capacities are normalized to 1..1024 so the highest is always 1024.
        let mut cpus: Vec<_> = topo.all_cpus.values().collect();
        cpus.sort_by_key(|cpu| std::cmp::Reverse(cpu.cpu_capacity));
        let max_cap = cpus.first().map(|c| c.cpu_capacity).unwrap_or(1).max(1);
        let capacities: Vec<_> = cpus.iter().map(|cpu| cpu.cpu_capacity).collect();
        let tiers = capacity_tiers(&capacities, opts.capacity_tier_tolerance_pct);
        let mut cpu_tiers: Vec<(u64, u64, u64)> = Vec::new();
        for (i, cpu) in cpus.iter().enumerate() {
            if opts.uniform_capacity {
                cpu_tiers.push((cpu.id as u64, 1024, 0));
                continue;
            }
            let normalized = (cpu.cpu_capacity * 1024 / max_cap).clamp(1, 1024);
            cpu_tiers.push((cpu.id as u64, normalized as u64, tiers[i]));
        }
        let nr_tiers = if opts.uniform_capacity {
            1
        } else {
            tiers.last().copied().unwrap_or(0) + 1
        };
        if nr_tiers > 1 {
            info!(
                "CPUs by capacity: {:?}",
                cpus.iter().map(|cpu| cpu.id).collect::<Vec<_>>()
            );
        }

        // Set scheduler flags.
        //
        // SCX_OPS_BUILTIN_IDLE_PER_NODE is left out: a cid-form scheduler
        // cannot use the built-in idle tracking, this one does its own.
        skel.struct_ops.cidland_ops_mut().flags = *compat::SCX_OPS_ENQ_EXITING
            | *compat::SCX_OPS_ENQ_LAST
            | *compat::SCX_OPS_ENQ_MIGRATION_DISABLED
            | *compat::SCX_OPS_ALLOW_QUEUED_WAKEUP;

        info!(
            "scheduler flags: {:#x}",
            skel.struct_ops.cidland_ops_mut().flags
        );

        // Load the BPF program for validation.
        let mut skel = scx_ops_cid_load!(skel, cidland_ops, uei)?;

        // Size the arena for the cid space, which is num_possible_cpus()
        // wide, and hand over the capacity of each CPU. The cid layout is
        // only known once the kernel has built it, at attach, so this is in
        // cpu space and ops.init() translates. It has to happen between
        // load and attach: the tables must be in place before ops.init().
        let nr_cpus = (*NR_CPU_IDS).max(*NR_CPUS_POSSIBLE);
        let mut args = types::cidland_arena_args {
            nr_cpus: nr_cpus as u64,
            nr_tiers,
        };
        run_syscall_prog(&skel.progs.cidland_arena_init, &mut args)
            .context("running cidland_arena_init")?;
        for (cpu, capacity, tier) in cpu_tiers {
            let mut args = types::cidland_cpu_args {
                cpu,
                capacity,
                tier,
            };
            run_syscall_prog(&skel.progs.cidland_set_cpu, &mut args)
                .context("running cidland_set_cpu")?;
        }

        // Watch the BPF streams: an arena fault is reported and fatal rather
        // than silently fixed up.
        let arenalib =
            ArenaLib::start(skel.object_mut()).context("starting arena userspace services")?;

        // Attach the scheduler.
        let struct_ops = Some(scx_ops_attach!(skel, cidland_ops)?);
        let stats_server = StatsServer::new(stats::server_data()).launch()?;

        Ok(Self {
            _arenalib: arenalib,
            skel,
            struct_ops,
            stats_server,
        })
    }

    fn get_metrics(&self) -> Metrics {
        let bss_data = self.skel.maps.bss_data.as_ref().unwrap();
        Metrics {
            nr_steals: bss_data.nr_steals,
            nr_preempts: bss_data.nr_preempts,
        }
    }

    pub fn exited(&mut self) -> bool {
        uei_exited!(&self.skel, uei)
    }

    fn run(&mut self, shutdown: Arc<AtomicBool>) -> Result<UserExitInfo> {
        let (res_ch, req_ch) = self.stats_server.channels();

        while !shutdown.load(Ordering::Relaxed) && !self.exited() {
            // Update statistics and check for exit condition.
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

#[cfg(test)]
mod tests {
    use super::capacity_tiers;

    #[test]
    fn capacity_tiers_use_current_tier_anchor() {
        assert_eq!(capacity_tiers(&[1024, 980, 940], 5), vec![0, 0, 1]);
    }

    #[test]
    fn capacity_tiers_keep_meaningful_gaps() {
        assert_eq!(capacity_tiers(&[1024, 1000, 700, 680], 5), vec![0, 0, 1, 1]);
    }

    #[test]
    fn zero_tolerance_keeps_distinct_capacities() {
        assert_eq!(capacity_tiers(&[1024, 1024, 1000], 0), vec![0, 0, 1]);
    }
}
