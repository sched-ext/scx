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
use scx_utils::SchedDomainSource;
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
    /// The default is fair.c's sysctl_sched_base_slice as update_sysctl()
    /// sets it: the normalized 700 us scaled by 1 + ilog2(min(nr_cpus, 8)),
    /// 2.8 ms on eight CPUs or more, so the two schedulers issue requests of
    /// the same size on the same machine. A kernel that runs fair.c at some
    /// other slice, /sys/kernel/debug/sched/base_slice_ns says which, is
    /// matched by setting it here. A task that has company on its CPU is asked for the CPU when
    /// its request runs out, by a timer armed for its deadline, see
    /// --no-hrtick, so the slice is what it says whatever the kernel's HZ.
    /// Without the timer a slice is only acted on from the tick, and one of
    /// exactly a tick buys two: the task is handed the CPU a few microseconds
    /// after the tick that freed it, so at the next tick it is those few
    /// microseconds short of its slice and runs a whole further tick.
    #[clap(short = 's', long)]
    slice_us: Option<u64>,

    /// Time, in microseconds, that a task stays cache hot on the CPU it last ran on.
    ///
    /// A task that stopped running within this long is left alone by the idle CPUs
    /// looking for work to steal: its own CPU takes it back within a slice, while
    /// moving it costs its cache. This is the equivalent of task_hot() with
    /// sysctl_sched_migration_cost in fair.c. 0 makes every queued task stealable
    /// right away, which spreads the load faster at the cost of cache locality.
    #[clap(short = 'm', long, default_value = "500")]
    migration_cost_us: u64,

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

    /// Scan for work on an idle CPU whatever the scan costs.
    ///
    /// An idle CPU keeps an average of how long it stays idle after a scan and
    /// the most a scan at each level has cost, and does not start a scan its
    /// idle time would not pay for, since a CPU its own wakeups keep bringing
    /// back is about to have work of its own: sched_balance_newidle()'s
    /// avg_idle against sd->max_newidle_lb_cost. This drops the budget and
    /// scans every time.
    #[clap(long, action = clap::ArgAction::SetTrue)]
    no_newidle_cost: bool,

    /// Disable NUMA optimizations.
    #[clap(short = 'n', long, action = clap::ArgAction::SetTrue)]
    disable_numa: bool,

    /// Disable CPU frequency control.
    #[clap(short = 'f', long, action = clap::ArgAction::SetTrue)]
    disable_cpufreq: bool,

    /// Disable SMT.
    #[clap(short = 'S', long, action = clap::ArgAction::SetTrue)]
    disable_smt: bool,

    /// Schedule the cpu controller's cgroups as groups.
    ///
    /// A cgroup then competes with its siblings at its cpu.weight and its
    /// tasks share what it gets, the way fair.c's group scheduling does, with
    /// cpu.weight meaning the weight per active CPU (fair.c's default
    /// cgroup_mode, "concur").
    ///
    /// Off by default: tasks are scheduled on their nice levels alone and
    /// cpu.weight is ignored. Keeping the group loads and effective weights
    /// up to date costs every wakeup of a task in a nested cgroup a walk of
    /// its hierarchy, which on a systemd machine is every task, and shows up
    /// as wakeup latency and throughput.
    ///
    /// Needs a kernel built with CONFIG_EXT_GROUP_SCHED.
    #[clap(short = 'g', long, action = clap::ArgAction::SetTrue)]
    enable_cgroups: bool,

    /// Force every CPU to have the same capacity.
    ///
    /// By default cidland uses the kernel-exported cpu_capacity values when the
    /// kernel has an active SD_ASYM_CPUCAPACITY domain.
    #[clap(
        short = 'u',
        long,
        action = clap::ArgAction::SetTrue,
        conflicts_with = "asym_capacity"
    )]
    uniform_capacity: bool,

    /// Force asymmetric capacities using the best available hardware estimate.
    ///
    /// This uses ACPI CPPC, cpufreq, or cpu_capacity through scx_utils rather
    /// than following the kernel's selected capacity classes. It can therefore
    /// expose hybrid x86 capacity differences that fair.c does not use.
    #[clap(
        long,
        action = clap::ArgAction::SetTrue,
        conflicts_with = "uniform_capacity"
    )]
    asym_capacity: bool,

    /// Maximum capacity difference, in percent, within one capacity tier.
    ///
    /// Capacities are compared with the fastest CPU in the current tier, so
    /// small differences such as favored versus ordinary P-cores do not make
    /// wakeups chase a marginally faster CPU. A larger gap still starts a new
    /// tier and retains the preference for P-cores over E-cores. 0 restores
    /// one tier per distinct reported capacity. The default is 0 when following
    /// the kernel and 5 with --asym-capacity.
    #[clap(short = 't', long, value_parser = clap::value_parser!(u32).range(0..=50))]
    capacity_tier_tolerance_pct: Option<u32>,

    /// Disable the kernel's SD_ASYM_PACKING CPU preference.
    ///
    /// Placement then follows the capacity tiers selected by the default
    /// kernel capacity, --uniform-capacity, or --asym-capacity mode.
    #[clap(long, action = clap::ArgAction::SetTrue)]
    disable_asym_packing: bool,

    /// Prefer lower-numbered CPUs within each SMT core.
    ///
    /// When the kernel exposes no priority between the threads of a core,
    /// pick the lowest-numbered idle sibling of the selected core, at wakeup
    /// and for balance destinations. Placement only: cores are not ranked by
    /// CPU ID and no task is migrated between the threads of one core. A
    /// determinism aid for comparisons, not a performance policy.
    #[clap(
        long,
        action = clap::ArgAction::SetTrue,
        conflicts_with = "disable_smt"
    )]
    smt_asym_packing: bool,

    /// Let a wakeup leave its LLC to find a whole idle core.
    ///
    /// An idle SMT sibling of a busy core is half of a core that is already
    /// working: placing a task there costs the thread running on the other
    /// sibling about half its throughput for as long as the two overlap. By
    /// default the idle scan follows select_idle_sibling() and takes that
    /// sibling, because fair.c stops at the LLC and leaves the rest to the
    /// periodic balancer. This makes the scan prefer a whole idle core in
    /// another LLC instead, trading cache locality for core throughput, and
    /// only while such a core exists.
    ///
    /// It matters on machines whose LLC spans a whole NUMA node: once that
    /// node is saturated, everything the machine wakes lands on its busy
    /// cores' siblings while another node's cores sit fully idle. Barrier-
    /// synchronized workloads pay for it many times over, since every thread
    /// waits for the halved one. Balancing cannot repair it, as those visits
    /// are far shorter than any balance interval.
    #[clap(
        long,
        action = clap::ArgAction::SetTrue,
        conflicts_with = "disable_smt"
    )]
    smt_whole_core: bool,

    /// Disable direct dispatch during synchronous wakeups.
    ///
    /// Enabling this option can lead to a more uniform load distribution across available cores,
    /// potentially improving performance in certain scenarios. However, it may come at the cost of
    /// reduced efficiency for pipe-intensive workloads that benefit from tighter producer-consumer
    /// coupling.
    #[clap(short = 'w', long, action = clap::ArgAction::SetTrue)]
    no_wake_sync: bool,

    /// Weigh the waking CPU against the previous one when both are busy.
    ///
    /// By default a wakee whose previous CPU and waking CPU are both busy
    /// stays where it last ran. With this, it goes to the one the two loads
    /// say is lighter, the time-averaged weight of what is runnable on each,
    /// so that a waker that runs a little and sleeps a lot takes its wakee
    /// onto its own CPU: wake_affine_weight(). It matters on a saturated
    /// machine with many short wakeups; elsewhere it costs a few percent of
    /// wakeup throughput for no measured gain, as it does in fair.c.
    #[clap(long, action = clap::ArgAction::SetTrue)]
    wa_weight: bool,

    /// Periodic busy load balancing runs every domain-weight milliseconds
    /// times this factor, sd->busy_factor (16 in fair.c).
    #[clap(long, default_value = "16", value_parser = clap::value_parser!(u32).range(1..=64))]
    busy_balance_factor: u32,

    /// Service is charged in rq_clock_task(), the clock update_curr() uses:
    /// wall time less the interrupt time and the hypervisor steal time the
    /// CPU spent on something else. This charges plain wall time, the rq
    /// clock, instead, so a task pays for the interrupts that land on its
    /// CPU and for the time the host took from its vCPU.
    #[clap(long, action = clap::ArgAction::SetTrue)]
    no_task_clock: bool,

    /// Interrupt on the deadlines alone, without asking who is owed service.
    ///
    /// The wakeup preemption normally fires only when the woken task is owed
    /// service and the running one is not, the way pick_eevdf() drops an
    /// ineligible current task and then picks an eligible waiter. This skips
    /// both tests and decides on the deadlines alone. For comparing the two
    /// rules against each other.
    #[clap(short = 'e', long, action = clap::ArgAction::SetTrue)]
    no_eligibility: bool,

    /// Take the head of a deadline-ordered queue at dispatch, eligible or not.
    ///
    /// The EDQ normally uses its augmented tree to find the earliest-deadline
    /// task whose vruntime is eligible in logarithmic time. This option takes
    /// the head instead; --no-eligibility implies it. Wakeup preemption and
    /// keep-running decisions are head-based either way because they cannot
    /// observe the current task, queue, and virtual-time frontier atomically.
    #[clap(long, action = clap::ArgAction::SetTrue)]
    no_eligible_scan: bool,

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

    /// Keep a longer-request running task protected from shorter wakees.
    ///
    /// Normally an eligible waking task that asks for a shorter request than
    /// the task currently running can preempt it despite RUN_TO_PARITY. The
    /// wakee is put on an available local DSQ as a one-shot short buddy,
    /// matching the wakeup side of PREEMPT_SHORT in fair.c. This option keeps
    /// the ordinary protection for comparison.
    #[clap(long, action = clap::ArgAction::SetTrue)]
    no_preempt_short: bool,

    /// Do not compensate placement lag for joining a virtual-time pack.
    ///
    /// Normally cidland inflates a task's placement offset before adding its
    /// weight to the destination pack, so the movement of the weighted-average
    /// reference does not dilute the requested lag. This disables that
    /// PLACE_LAG compensation and restores the older behavior where lag can
    /// evaporate as a task repeatedly sleeps and wakes. For comparing the two
    /// placement rules against each other.
    #[clap(long, action = clap::ArgAction::SetTrue)]
    no_place_lag: bool,

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

    /// Let a task that blocks over-served carry its whole debt across the sleep.
    ///
    /// A task that blocks while it is over-served normally has the debt paid
    /// off by the pack it left, with the service delivered there while it
    /// slept, and never more than paid off: it wakes owing at most what it
    /// owed, and often nothing. This makes it carry the whole debt to its next
    /// placement instead, however long it slept.
    ///
    /// This is DELAY_DEQUEUE and DELAY_ZERO off. For comparing the two rules
    /// against each other.
    #[clap(short = 'D', long, action = clap::ArgAction::SetTrue)]
    no_delay_dequeue: bool,
    /// Wake a task that blocked over-served through the placement.
    ///
    /// A task that blocks while it is over-served is still on the runqueue it
    /// blocked on as far as fair.c is concerned, and a wakeup that comes
    /// before its debt is paid requeues it there, ttwu_runnable(), without
    /// choosing a CPU for it: it runs there once it is picked, or wherever a
    /// balance moves it. That is what happens here too. This option sends
    /// such a task through wake_affine() and the idle scan like any other
    /// wakeup instead, so it gets an idle CPU when there is one. Implied by
    /// --no-delay-dequeue. For comparing the two rules against each other.
    #[clap(long, action = clap::ArgAction::SetTrue)]
    no_delay_requeue: bool,

    /// Notice the end of a request at the tick after it, not when it happens.
    ///
    /// A request is normally ended on the spot by a timer armed for the
    /// running task's deadline whenever it has company, the way HRTICK does
    /// in fair.c. Without it a task holds the CPU until the tick that follows
    /// the end of its request, up to a whole tick late, and a task waiting
    /// behind it waits that long. For comparing the two against each other.
    #[clap(short = 'H', long, action = clap::ArgAction::SetTrue)]
    no_hrtick: bool,
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

/// The request size fair.c hands out by default on this machine.
///
/// sysctl_sched_base_slice is not the 700 us the kernel is compiled with.
/// update_sysctl() scales that at boot, and again on hotplug, by a factor
/// taken from the number of online CPUs:
///
///	unsigned int cpus = min_t(unsigned int, num_online_cpus(), 8);
///	case SCHED_TUNABLESCALING_LOG:
///		factor = 1 + ilog2(cpus);
///	sysctl_sched_base_slice = factor * normalized_sysctl_sched_base_slice;
///
/// so a machine with eight CPUs or more runs a 2.8 ms slice. This is the
/// upstream rule with its default log scaling; a kernel whose distribution
/// changed the normalized value or an administrator who tuned the sysctl
/// runs fair.c at some other slice, and --slice-us is how to match it.
/// Return the number of cgroups with a cpu.weight other than the default, and
/// one of them, walking the cgroup v2 hierarchy. A cgroup has a cpu.weight
/// file only where its parent enables the cpu controller.
fn cgroups_with_cpu_weight(root: &std::path::Path) -> (usize, Option<String>) {
    const CGROUP_WEIGHT_DFL: u64 = 100;
    let mut stack = vec![(root.to_path_buf(), 0)];
    let (mut count, mut example, mut visited) = (0, None, 0);

    while let Some((dir, depth)) = stack.pop() {
        visited += 1;
        if visited > 100_000 {
            break;
        }
        if let Ok(val) = std::fs::read_to_string(dir.join("cpu.weight")) {
            if val
                .trim()
                .parse::<u64>()
                .is_ok_and(|w| w != CGROUP_WEIGHT_DFL)
            {
                count += 1;
                if example.is_none() {
                    let name = dir.strip_prefix(root).unwrap_or(&dir);
                    example = Some(format!("/{} ({})", name.display(), val.trim()));
                }
            }
        }
        if depth >= 64 {
            continue;
        }
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            if entry.file_type().is_ok_and(|t| t.is_dir()) {
                stack.push((entry.path(), depth + 1));
            }
        }
    }

    (count, example)
}

/// Tell whether cgroup scheduling can do what the options ask for: warn when
/// it was asked for and the kernel or the cgroup setup leaves nothing to
/// hook into, and when it is off while some cgroup has a cpu.weight that is
/// then ignored.
fn check_cgroup_support(requested: bool, kernel_support: bool) {
    let root = std::path::Path::new("/sys/fs/cgroup");
    let cpu_controller = std::fs::read_to_string(root.join("cgroup.subtree_control"))
        .is_ok_and(|ctrl| ctrl.split_whitespace().any(|c| c == "cpu"));

    if requested {
        if !kernel_support {
            warn!(
                "--enable-cgroups: the kernel has no sched_ext cgroup support \
                 (CONFIG_EXT_GROUP_SCHED), cgroups are not scheduled as groups"
            );
        } else if !cpu_controller {
            warn!(
                "--enable-cgroups: the cpu controller is not enabled in {}, \
                 every task is scheduled as part of the root cgroup",
                root.join("cgroup.subtree_control").display()
            );
        }
        return;
    }

    if !cpu_controller {
        return;
    }
    let (count, example) = cgroups_with_cpu_weight(root);
    if count > 0 {
        warn!(
            "{} cgroup(s) set cpu.weight, e.g. {}, which is ignored without \
             --enable-cgroups",
            count,
            example.unwrap_or_default()
        );
    }
}

fn base_slice_ns(nr_cpus: usize) -> u64 {
    const NORMALIZED_BASE_SLICE_NS: u64 = 700_000;
    let cpus = nr_cpus.clamp(1, 8) as u64;
    let factor = 1 + cpus.ilog2() as u64;

    factor * NORMALIZED_BASE_SLICE_NS
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

        if opts.slice_us == Some(0) {
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

        let slice_ns = match opts.slice_us {
            Some(us) => {
                let ns = us * 1000;
                info!("slice: {} us (--slice-us)", us);
                ns
            }
            None => {
                let ns = base_slice_ns(topo.all_cpus.len());
                info!(
                    "slice: {} us (700 us scaled as update_sysctl() does)",
                    ns / 1000
                );
                ns
            }
        };

        // Print command line.
        info!(
            "scheduler options: {}",
            std::env::args().collect::<Vec<_>>().join(" ")
        );

        // Initialize BPF connector.
        let mut skel_builder = BpfSkelBuilder::default();
        skel_builder.obj_builder.debug(opts.verbose);
        let open_opts = opts.libbpf.clone().into_bpf_open_opts();

        // The cid form's cgroup callbacks were renamed from cgroup_* to
        // cpuctl_*. The BPF object defines the ops under both names, as two
        // struct_ops maps sharing the same programs: use the one the running
        // kernel matches and leave the other uncreated.
        let cpuctl_names =
            compat::struct_has_field("sched_ext_ops_cid", "cpuctl_set_weight").unwrap_or(false);
        let cgroup_names = !cpuctl_names
            && compat::struct_has_field("sched_ext_ops_cid", "cgroup_set_weight").unwrap_or(false);
        let mut skel = if cgroup_names {
            scx_ops_cid_open!(skel_builder, open_object, cidland_ops_cgroup, open_opts)
        } else {
            scx_ops_cid_open!(skel_builder, open_object, cidland_ops, open_opts)
        }
        .context("opening BPF skeleton (does this kernel support cid-form sched_ext?)")?;
        if cgroup_names {
            skel.maps.cidland_ops.set_autocreate(false)?;
        } else {
            skel.maps.cidland_ops_cgroup.set_autocreate(false)?;
        }

        skel.struct_ops.cidland_ops_mut().exit_dump_len = opts.exit_dump_len;
        skel.struct_ops.cidland_ops_cgroup_mut().exit_dump_len = opts.exit_dump_len;

        // Schedule cgroups as groups only when asked to and when the kernel
        // has cpu controller support for sched_ext to hook into. Detaching
        // the callbacks from the struct_ops keeps the kernel from delivering
        // them at all, and lets the scheduler load on a kernel whose
        // sched_ext_ops_cid has no cgroup members to bind them to.
        let cgroup_enabled = opts.enable_cgroups && (cpuctl_names || cgroup_names);
        check_cgroup_support(opts.enable_cgroups, cpuctl_names || cgroup_names);
        if !cgroup_enabled {
            let ops = skel.struct_ops.cidland_ops_mut();
            ops.cpuctl_init = std::ptr::null_mut();
            ops.cpuctl_exit = std::ptr::null_mut();
            ops.cpuctl_set_weight = std::ptr::null_mut();
            ops.cpuctl_set_idle = std::ptr::null_mut();
            ops.cpuctl_move = std::ptr::null_mut();
            let ops = skel.struct_ops.cidland_ops_cgroup_mut();
            ops.cgroup_init = std::ptr::null_mut();
            ops.cgroup_exit = std::ptr::null_mut();
            ops.cgroup_set_weight = std::ptr::null_mut();
            ops.cgroup_set_idle = std::ptr::null_mut();
            ops.cgroup_move = std::ptr::null_mut();
            info!("cgroup scheduling: off");
        } else {
            info!(
                "cgroup scheduling: on ({}_* callbacks)",
                if cgroup_names { "cgroup" } else { "cpuctl" }
            );
        }

        // Override default BPF scheduling parameters.
        let rodata = skel.maps.rodata_data.as_mut().unwrap();
        rodata.slice_ns = slice_ns;
        rodata.tick_ns = tick_ns();
        rodata.migration_cost_ns = opts.migration_cost_us * 1000;
        rodata.cache_nice_tries = opts.cache_nice_tries;
        rodata.no_newidle_cost = opts.no_newidle_cost;
        rodata.cpufreq_enabled = !opts.disable_cpufreq;
        rodata.cgroup_enabled = cgroup_enabled;
        rodata.numa_enabled = numa_enabled;
        rodata.smt_enabled = smt_enabled;
        rodata.force_smt_asym_packing = opts.smt_asym_packing;
        if opts.smt_asym_packing {
            info!("SMT sibling priority: lower CPU IDs first (--smt-asym-packing)");
        }
        rodata.smt_whole_core = opts.smt_whole_core && smt_enabled;
        if opts.smt_whole_core && smt_enabled {
            info!("Idle scan: a whole idle core wins over a busy core's sibling, across LLCs");
        }
        rodata.no_wake_sync = opts.no_wake_sync;
        rodata.wa_weight = opts.wa_weight;
        rodata.busy_balance_factor = opts.busy_balance_factor;
        rodata.no_task_clock = opts.no_task_clock;
        info!(
            "service clock: {}",
            if opts.no_task_clock {
                "ktime"
            } else {
                "rq_clock_task"
            }
        );
        rodata.no_wakeup_preempt = opts.no_wakeup_preempt;
        rodata.no_eligibility = opts.no_eligibility;
        rodata.no_eligible_scan = opts.no_eligible_scan;
        rodata.no_run_to_parity = opts.no_run_to_parity;
        rodata.no_preempt_short = opts.no_preempt_short;
        rodata.no_place_lag = opts.no_place_lag;
        rodata.no_place_rel_deadline = opts.no_place_rel_deadline;
        rodata.no_delay_dequeue = opts.no_delay_dequeue;
        rodata.no_delay_requeue = opts.no_delay_requeue;
        rodata.no_hrtick = opts.no_hrtick;
        rodata.no_vref_update = opts.no_vref_update;

        // Follow the capacity classes selected by the kernel unless explicitly
        // overridden. cpu_capacity is topology_get_cpu_scale(), the same input
        // used to construct SD_ASYM_CPUCAPACITY domains. scx_utils deliberately
        // has a more aggressive hardware-derived estimate, retained here for
        // the --asym-capacity override.
        let (mut cpus, capacity_mode, default_tolerance): (Vec<_>, _, u32) = if opts
            .uniform_capacity
        {
            (
                topo.all_cpus
                    .values()
                    .map(|cpu| (cpu.clone(), 1024usize))
                    .collect(),
                "forced uniform",
                0,
            )
        } else if opts.asym_capacity {
            (
                topo.all_cpus
                    .values()
                    .map(|cpu| (cpu.clone(), cpu.cpu_capacity))
                    .collect(),
                "forced hardware-derived",
                5,
            )
        } else {
            let kernel_cpus: Option<Vec<_>> = topo
                .all_cpus
                .values()
                .map(|cpu| Some((cpu.clone(), cpu.kernel_cpu_capacity?)))
                .collect();

            match kernel_cpus {
                Some(cpus) => (cpus, "kernel", 0),
                None => {
                    warn!(
                        "kernel CPU capacity classes are not exported by sysfs; falling back to hardware-derived capacities"
                    );
                    (
                        topo.all_cpus
                            .values()
                            .map(|cpu| (cpu.clone(), cpu.cpu_capacity))
                            .collect(),
                        "hardware-derived fallback",
                        5,
                    )
                }
            }
        };

        // Capacity tiers: CPUs sorted by capacity in descending order, with
        // close capacities coalesced into a tier, 0 being the fastest.
        // Capacities are normalized to 1..1024 so the highest is always 1024.
        cpus.sort_by_key(|(_, capacity)| std::cmp::Reverse(*capacity));
        let max_cap = cpus
            .first()
            .map(|(_, capacity)| *capacity)
            .unwrap_or(1)
            .max(1);
        let capacities: Vec<_> = cpus.iter().map(|(_, capacity)| *capacity).collect();
        let tolerance = opts
            .capacity_tier_tolerance_pct
            .unwrap_or(default_tolerance);
        let tiers = capacity_tiers(&capacities, tolerance);
        let nr_capacity_tiers = tiers.last().copied().unwrap_or(0) + 1;
        let has_capacity_tiers = nr_capacity_tiers > 1;
        // Keep capacity and SD_ASYM_PACKING tiers independent. fair.c uses
        // them in different paths; collapsing them into one ordering makes
        // packing priority affect every ordinary idle-CPU search.
        let mut cpu_tiers: Vec<(u64, u64, u64, u64, bool, u64, u64, u64)> = Vec::new();
        let mut sched_domain_source = None;
        for (i, (cpu, capacity)) in cpus.iter().enumerate() {
            let normalized = (*capacity * 1024 / max_cap).clamp(1, 1024);
            let domains = topo
                .sched_domain_info(cpu.id)
                .context("discovering scheduler-domain policy")?;
            sched_domain_source.get_or_insert(domains.source);
            cpu_tiers.push((
                cpu.id as u64,
                normalized as u64,
                tiers[i],
                tiers[i],
                false,
                domains.fork_span as u64,
                domains.wake_affine_span as u64,
                domains.asym_capacity_span as u64,
            ));
        }
        info!(
            "CPU capacity mode: {capacity_mode} ({nr_capacity_tiers} tier{}, tolerance {tolerance}%)",
            if nr_capacity_tiers == 1 { "" } else { "s" }
        );
        if has_capacity_tiers {
            info!(
                "CPUs by capacity: {:?}",
                cpus.iter().map(|(cpu, _)| cpu.id).collect::<Vec<_>>()
            );
        }

        // Set scheduler flags.
        //
        // SCX_OPS_BUILTIN_IDLE_PER_NODE is left out: a cid-form scheduler
        // cannot use the built-in idle tracking, this one does its own.
        let flags = *compat::SCX_OPS_ENQ_LAST
            | *compat::SCX_OPS_ENQ_MIGRATION_DISABLED
            | *compat::SCX_OPS_ALLOW_QUEUED_WAKEUP
            | *compat::SCX_OPS_ENQ_EXITING
            | *compat::SCX_OPS_TID_TO_TASK;
        skel.struct_ops.cidland_ops_mut().flags = flags;
        skel.struct_ops.cidland_ops_cgroup_mut().flags = flags;

        info!("scheduler flags: {:#x}", flags);

        // One hrtick per cid, over the same cid space the arena is sized
        // for below. A map is sized before the program is loaded.
        let nr_cpus = (*NR_CPU_IDS).max(*NR_CPUS_POSSIBLE);
        skel.maps
            .hrticks
            .set_max_entries(nr_cpus as u32)
            .context("sizing the hrtick map")?;

        // Load the BPF program for validation.
        let mut skel = if cgroup_names {
            scx_ops_cid_load!(skel, cidland_ops_cgroup, uei)
        } else {
            scx_ops_cid_load!(skel, cidland_ops, uei)
        }?;

        // Capacity and asymmetric packing are separate kernel policies.
        // Topology reconstructs the portable domain spans, but neither
        // SD_ASYM_PACKING nor arch_asym_cpu_priority() has a userspace ABI.
        // Keep this narrow BPF query until sched_ext provides one.
        let mut priorities = Vec::with_capacity(cpu_tiers.len());
        let mut all_asym_packing = !opts.disable_asym_packing;
        for (cpu, _, _, _, smt_asym_packing, _, _, _) in &mut cpu_tiers {
            let mut args = types::cidland_cpu_priority_args {
                cpu: *cpu,
                priority: 0,
                asym_packing: 0,
                smt_asym_packing: 0,
            };
            run_syscall_prog(&skel.progs.cidland_get_cpu_priority, &mut args)
                .context("querying CPU asymmetric-packing policy")?;
            if !opts.disable_asym_packing {
                all_asym_packing &= args.asym_packing != 0;
                *smt_asym_packing = args.smt_asym_packing != 0;
                priorities.push((*cpu, args.priority));
            }
        }

        let mut domain_spans = cpu_tiers
            .iter()
            .map(|entry| (entry.5, entry.6, entry.7))
            .collect::<Vec<_>>();
        domain_spans.sort_unstable();
        domain_spans.dedup();
        info!(
            "scheduler domain spans (fork, wake-affine, asym-capacity, source={}): {:?}",
            match sched_domain_source {
                Some(SchedDomainSource::Schedstat) => "schedstat",
                Some(SchedDomainSource::Topology) | None => "topology",
            },
            domain_spans
        );

        let sched_asym_capacity =
            !opts.uniform_capacity && cpu_tiers.iter().any(|entry| entry.7 != 0);
        let asym_capacity = has_capacity_tiers && (sched_asym_capacity || opts.asym_capacity);
        if has_capacity_tiers && !asym_capacity {
            info!("CPU capacity placement: off (no kernel SD_ASYM_CPUCAPACITY domain)");
        }

        priorities.sort_by_key(|(_, priority)| std::cmp::Reverse(*priority));
        let distinct_priorities = priorities.windows(2).any(|pair| pair[0].1 != pair[1].1);
        let asym_packing = all_asym_packing && distinct_priorities;
        let mut nr_place_tiers = if asym_capacity { nr_capacity_tiers } else { 1 };
        if asym_packing {
            let mut tier = 0u64;
            for i in 0..priorities.len() {
                if i > 0 && priorities[i - 1].1 != priorities[i].1 {
                    tier += 1;
                }
                let cpu = priorities[i].0;
                let entry = cpu_tiers
                    .iter_mut()
                    .find(|entry| entry.0 == cpu)
                    .expect("priority CPU must be present in topology");
                entry.3 = tier;
            }
            nr_place_tiers = tier + 1;
            info!(
                "CPU asymmetric packing: kernel ({} priority tiers, CPUs {:?})",
                nr_place_tiers,
                priorities.iter().map(|(cpu, _)| cpu).collect::<Vec<_>>()
            );
        } else {
            for (_, _, capacity_tier, place_tier, smt_asym_packing, _, _, _) in &mut cpu_tiers {
                *place_tier = if asym_capacity { *capacity_tier } else { 0 };
                *smt_asym_packing = false;
            }
            info!(
                "CPU asymmetric packing: {}; placement follows {}",
                if opts.disable_asym_packing {
                    "disabled"
                } else {
                    "off"
                },
                if asym_capacity {
                    format!("{capacity_mode} capacity tiers")
                } else {
                    "uniform capacity".to_string()
                },
            );
        }

        // Size the arena for the cid space, which is num_possible_cpus()
        // wide, and hand over the capacity of each CPU. The cid layout is
        // only known once the kernel has built it, at attach, so this is in
        // cpu space and ops.init() translates. It has to happen between
        // load and attach: the tables must be in place before ops.init().
        let mut args = types::cidland_arena_args {
            nr_cpus: nr_cpus as u64,
            nr_place_tiers,
            nr_capacity_tiers,
            asym_capacity: asym_capacity as u64,
            sched_asym_capacity: sched_asym_capacity as u64,
            force_asym_capacity: opts.asym_capacity as u64,
            asym_packing: asym_packing as u64,
        };
        run_syscall_prog(&skel.progs.cidland_arena_init, &mut args)
            .context("running cidland_arena_init")?;
        for (
            cpu,
            capacity,
            capacity_tier,
            place_tier,
            smt_asym_packing,
            fork_span,
            wake_affine_span,
            asym_capacity_span,
        ) in cpu_tiers
        {
            let mut args = types::cidland_cpu_args {
                cpu,
                capacity,
                place_tier,
                capacity_tier,
                smt_asym_packing: smt_asym_packing as u64,
                fork_span,
                wake_affine_span,
                asym_capacity_span,
            };
            run_syscall_prog(&skel.progs.cidland_set_cpu, &mut args)
                .context("running cidland_set_cpu")?;
        }

        // Watch the BPF streams: an arena fault is reported and fatal rather
        // than silently fixed up.
        let arenalib =
            ArenaLib::start(skel.object_mut()).context("starting arena userspace services")?;

        // Attach the scheduler.
        let struct_ops = Some(if cgroup_names {
            scx_ops_attach!(skel, cidland_ops_cgroup)
        } else {
            scx_ops_attach!(skel, cidland_ops)
        }?);
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
            nr_busy_balances: bss_data.nr_busy_balances,
            nr_active_balances: bss_data.nr_active_balances,
            nr_preempts: bss_data.nr_preempts,
            nr_delay_requeues: bss_data.nr_delay_requeues,
            nr_hrticks: bss_data.nr_hrticks,
            nr_newidle_skips: bss_data.nr_newidle_skips,
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
