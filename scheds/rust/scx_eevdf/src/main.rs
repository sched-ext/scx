// SPDX-License-Identifier: GPL-2.0
//
// Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.

// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

mod bpf_skel;
pub use bpf_skel::*;
pub mod bpf_intf;
pub use bpf_intf::*;

mod console;
mod stats;

use std::collections::BTreeMap;
use std::ffi::CStr;
use std::mem::MaybeUninit;
use std::os::fd::AsFd;
use std::os::fd::AsRawFd;
use std::os::fd::FromRawFd;
use std::os::fd::OwnedFd;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::time::Duration;
use std::time::Instant;

use anyhow::Context;
use anyhow::Result;
use anyhow::bail;
use clap::Parser;
use crossbeam::channel::RecvTimeoutError;
use libbpf_rs::MapCore;
use libbpf_rs::OpenObject;
use libbpf_rs::ProgramInput;
use libbpf_rs::ProgramType;
use libbpf_rs::skel::Skel;
use log::debug;
use log::warn;
use scx_arena::ArenaLib;
use scx_stats::prelude::*;
use scx_utils::NR_CPU_IDS;
use scx_utils::NR_CPUS_POSSIBLE;
use scx_utils::SchedDomainSource;
use scx_utils::ScxExitKind;
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
use scx_utils::uei_read;
use stats::Metrics;
use stats::OpStats;

const SCHEDULER_NAME: &str = "scx_eevdf";

fn kernel_major_minor(release: &str) -> Option<(u32, u32)> {
    let mut fields = release.split('.');
    let major = fields.next()?.parse().ok()?;
    let minor = fields
        .next()?
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect::<String>()
        .parse()
        .ok()?;

    Some((major, minor))
}

fn warn_on_old_kernel() {
    let mut uts = MaybeUninit::<libc::utsname>::uninit();

    if unsafe { libc::uname(uts.as_mut_ptr()) } != 0 {
        return;
    }

    let uts = unsafe { uts.assume_init() };
    let release = unsafe { CStr::from_ptr(uts.release.as_ptr()) }.to_string_lossy();

    if kernel_major_minor(&release).is_some_and(|version| version < (7, 2)) {
        warn!(
            "kernel {release} is older than v7.2; scx_eevdf requires the sched_ext cid/tid support introduced in v7.2 and may fail to load (a kernel with the support backported may still work)"
        );
    }
}

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
    name = "scx_eevdf",
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
    /// avg_idle against sd->max_newidle_lb_cost. This drops only the cost
    /// budget; --no-newidle-sampling separately disables success-rate
    /// sampling.
    #[clap(long, action = clap::ArgAction::SetTrue)]
    no_newidle_cost: bool,

    /// Do not sample new-idle scans from their observed success rate.
    ///
    /// fair.c's NI_RANDOM and NI_RATE features avoid repeatedly scanning a
    /// domain that rarely supplies work. Each cid and topology level tracks
    /// successful pulls and call frequency, then probabilistically admits
    /// scans in proportion to that estimate. The estimator compensates a
    /// successful sampled scan by its inverse sampling probability.
    ///
    /// Sampling is enabled by default, as both fair.c features are. This
    /// option makes every new-idle level eligible to scan, subject only to
    /// the separate avg-idle cost budget controlled by --no-newidle-cost.
    #[clap(long, action = clap::ArgAction::SetTrue)]
    no_newidle_sampling: bool,

    /// Do not bound wakeup idle scans by the target LLC's utilization.
    ///
    /// fair.c stops looking for an idle CPU once the LLC it is searching is
    /// busy enough to make the search unlikely to pay, SIS_UTIL: periodic load
    /// balance leaves a scan budget behind, computed from the LLC's average
    /// utilization, which falls quadratically and reaches zero at about 85%.
    /// scx_eevdf does the same, over a window that starts at the target and
    /// wraps inside the LLC so a bounded scan still reaches every CPU across
    /// successive wakeups, and gives up where select_idle_cpu() returns -1
    /// rather than carrying the search on to the node and the machine.
    ///
    /// This disables it and scans the whole LLC on every wakeup. Worth trying
    /// on a machine whose LLC is small: the scan reads the idle bitmap a word
    /// at a time, so an LLC of 64 CPUs or fewer costs one read whatever the
    /// budget says, and the bound then only loses idle CPUs it would have
    /// found.
    #[clap(long, action = clap::ArgAction::SetTrue)]
    no_sis_util: bool,

    /// Look past the target LLC for an idle CPU.
    ///
    /// By default, match select_idle_sibling(), which is scoped to sd_llc: when
    /// the LLC has no idle CPU, queue the task on its affine target and leave
    /// spreading across LLCs to load balance, where the migration cost is
    /// weighed against the idle time it would use. This instead extends the
    /// wakeup scan to the node and then the whole machine.
    ///
    /// This can keep work off a busy SMT sibling when a whole idle core exists
    /// in another LLC, at the cost of weaker cache locality and a scan fair.c
    /// never pays. It has no effect when one LLC spans every CPU.
    #[clap(long, action = clap::ArgAction::SetTrue)]
    llc_extend: bool,

    /// Disable NUMA optimizations.
    #[clap(short = 'n', long, action = clap::ArgAction::SetTrue)]
    disable_numa: bool,

    /// Disable CPU frequency control.
    #[clap(short = 'f', long, action = clap::ArgAction::SetTrue)]
    disable_cpufreq: bool,

    /// Disable SMT.
    #[clap(short = 'S', long, action = clap::ArgAction::SetTrue)]
    disable_smt: bool,

    /// Do not schedule the cpu controller's cgroups as groups.
    ///
    /// By default, a cgroup competes with its siblings at its cpu.weight and its
    /// tasks share what it gets, the way fair.c's group scheduling does, with
    /// cpu.weight meaning the weight per active CPU (fair.c's default
    /// cgroup_mode, "concur").
    ///
    /// This schedules tasks on their nice levels alone and ignores cpu.weight.
    /// It avoids walking a nested cgroup hierarchy as tasks wake and sleep,
    /// trading the cpu controller's isolation semantics for some throughput.
    ///
    /// Group scheduling needs a kernel built with CONFIG_EXT_GROUP_SCHED. If
    /// the running kernel lacks it, scx_eevdf falls back to this behavior.
    #[clap(long, action = clap::ArgAction::SetTrue)]
    disable_cgroups: bool,

    /// Deprecated compatibility alias; cgroup scheduling is already enabled.
    #[clap(
        short = 'g',
        long,
        hide = true,
        action = clap::ArgAction::SetTrue,
        conflicts_with = "disable_cgroups"
    )]
    enable_cgroups: bool,

    /// Ignore cpu.max while scheduling cgroups as groups.
    ///
    /// A cgroup is normally held to the bandwidth its cpu.max asks for: it
    /// runs for at most its quota in every period, and its tasks wait for the
    /// next one once it is spent. This turns that off and leaves cpu.weight
    /// and cpu.idle in place, which is what the comparison against a kernel
    /// with no bandwidth control needs.
    ///
    /// Has no further effect with --disable-cgroups.
    #[clap(long, action = clap::ArgAction::SetTrue)]
    disable_cpu_max: bool,

    /// Force every CPU to have the same capacity.
    ///
    /// By default scx_eevdf uses the kernel-exported cpu_capacity values when the
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

    /// Do not weigh the waking CPU against the previous one when both are busy.
    ///
    /// By default, send the wakee to whichever of its previous CPU and the
    /// waking CPU would be lighter after the move. Cid load is sampled from
    /// the tick and task load reuses its execution-utilization estimate, so
    /// the comparison adds no runnable-state accounting. Disable this on
    /// systems where the resulting placement performs worse, such as large
    /// asymmetric-SMT systems.
    #[clap(long, action = clap::ArgAction::SetTrue)]
    no_wa_weight: bool,

    /// Periodic busy load balancing runs every domain-weight milliseconds
    /// times this factor, sd->busy_factor (16 in fair.c).
    #[clap(long, default_value = "16", value_parser = clap::value_parser!(u32).range(1..=64))]
    busy_balance_factor: u32,

    /// Do not account for CPU capacity unavailable to sched_ext.
    ///
    /// By default, measure higher-class displacement from stopping/running
    /// events and IRQ/steal time from rq_clock - rq_clock_task. Periodic
    /// balance normalizes load by the resulting effective capacity, while
    /// retaining its normal imbalance, affinity, hotness, and EEVDF gates.
    /// A task displaced by a higher class may be requeued into a less-loaded
    /// cid's EDQ, where it still competes in EEVDF order. Hardware capacity
    /// and wakeup placement remain unchanged.
    #[clap(long, action = clap::ArgAction::SetTrue)]
    no_capacity_pressure: bool,

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
    /// Normally scx_eevdf inflates a task's placement offset before adding its
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

    /// Let a waking task borrow virtual time under peer CPU pressure.
    ///
    /// A task is normally placed with the lag it took out of the queue it left,
    /// so one that ran right up to the moment it slept carries none and comes
    /// back behind everything already queued. When peer user utilization
    /// admits the intervention, this floors its offset from the destination
    /// reference at the configured virtual-time credit.
    ///
    /// This deliberately departs from ordinary EEVDF placement. The borrowed
    /// service is charged normally once the task runs, and admission excludes
    /// CPUs whose pressure comes from system rather than user time.
    #[clap(short = 'i', long, action = clap::ArgAction::SetTrue)]
    latency_credit: bool,

    /// Virtual-time loan for --latency-credit, in microseconds.
    ///
    /// The credit is a placement scale expressed as real service before
    /// deadline-weight scaling. It is neither a response-time guarantee nor a
    /// bound on total displacement when the task carries more lag.
    #[clap(short = 'I', long, default_value = "20000")]
    latency_credit_us: u64,

    /// User CPU utilization at which a CPU enables latency credit.
    ///
    /// Only user time counts. CPUs busy with syscall-heavy sleep workloads keep
    /// ordinary EEVDF placement, while CPUs saturated by user-space work enable
    /// the latency credit for waking tasks. 0 restores unconditional credit.
    #[clap(long, default_value = "80", value_parser = clap::value_parser!(u64).range(0..=100))]
    latency_credit_user_busy_pct: u64,

    /// How recently a task must have slept to count as one that sleeps.
    ///
    /// A CPU whose current task slept within this many milliseconds is running
    /// work of the wakee's own kind, and a credited wakee is not moved onto it
    /// by the packing below. A hog never sleeps and never qualifies.
    #[clap(long, default_value = "2000")]
    latency_credit_sleep_ms: u64,

    /// Do not move a credited wakee up the CPU priority tiers.
    ///
    /// With --latency-credit, a wakee that would queue on a busy CPU of a
    /// lower asymmetric-packing priority is queued instead on a higher-priority
    /// CPU whose current task never sleeps, where the credit lets it win the
    /// CPU at once. Nothing is idle under a hog per CPU, so packing alone never
    /// moves it: the aquarium's render thread sat on an E-core for as long as
    /// the hogs ran. This keeps the wakeup's own choice.
    #[clap(long, action = clap::ArgAction::SetTrue)]
    no_latency_credit_pack: bool,

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

/// Kernel run-time accounting of the sched_ext callbacks, BPF_ENABLE_STATS.
///
/// Each callback is its own BPF program and the kernel keeps a run count and
/// a run time per program once the accounting is switched on. That costs two
/// clock reads around every callback, so it is on only while a stats client
/// is polling and goes away by itself once nobody has asked for a while.
struct OpsProfiler {
    /// Holding the descriptor keeps the accounting enabled.
    enabled: Option<OwnedFd>,
    last_read: Instant,
    warned: bool,
}

impl OpsProfiler {
    /// How long without a stats request before the accounting is dropped.
    const IDLE: Duration = Duration::from_secs(5);

    fn new() -> Self {
        Self {
            enabled: None,
            last_read: Instant::now(),
            warned: false,
        }
    }

    fn enable(&mut self) {
        if self.enabled.is_some() {
            return;
        }
        let fd = unsafe {
            libbpf_rs::libbpf_sys::bpf_enable_stats(libbpf_rs::libbpf_sys::BPF_STATS_RUN_TIME)
        };
        if fd < 0 {
            if !self.warned {
                warn!(
                    "BPF run-time stats unavailable: {}",
                    std::io::Error::last_os_error()
                );
                self.warned = true;
            }
            return;
        }
        debug!("BPF run-time stats enabled");
        self.enabled = Some(unsafe { OwnedFd::from_raw_fd(fd) });
    }

    /// Drop the accounting once no client has polled for a while.
    fn expire(&mut self) {
        if self.enabled.is_some() && self.last_read.elapsed() > Self::IDLE {
            debug!("BPF run-time stats disabled");
            self.enabled = None;
        }
    }

    /// Cumulative counts and times of every struct_ops program, keyed by the
    /// callback name. The kernel truncates program names, so the names come
    /// from the skeleton.
    fn sample(&mut self, skel: &BpfSkel<'_>) -> BTreeMap<String, OpStats> {
        self.last_read = Instant::now();
        self.enable();

        let mut ops = BTreeMap::new();
        if self.enabled.is_none() {
            return ops;
        }
        for prog in skel.object().progs() {
            if prog.prog_type() != ProgramType::StructOps {
                continue;
            }
            let mut info: libbpf_rs::libbpf_sys::bpf_prog_info = unsafe { std::mem::zeroed() };
            let mut len = std::mem::size_of_val(&info) as u32;
            let rc = unsafe {
                libbpf_rs::libbpf_sys::bpf_prog_get_info_by_fd(
                    prog.as_fd().as_raw_fd(),
                    &mut info,
                    &mut len,
                )
            };
            if rc != 0 {
                continue;
            }
            let name = prog.name().to_string_lossy();
            let name = name.strip_prefix("eevdf_").unwrap_or(&name).to_string();
            ops.insert(
                name,
                OpStats {
                    calls: info.run_cnt,
                    ns: info.run_time_ns,
                    misses: info.recursion_misses,
                },
            );
        }
        ops
    }
}

/// What the arena holds, in bytes, and the size of the map. Kernels from
/// 7.3 account the allocated pages in the map's memlock; before that the
/// figure is the one kept at the allocator by eevdf_arena_alloc_pages(),
/// when @counted says those programs are attached, and None otherwise.
fn arena_usage(skel: &BpfSkel, counted: bool) -> (Option<u64>, u64) {
    let map = &skel.maps.arena;
    let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) }.max(1) as u64;
    let max = map.max_entries() as u64 * page;
    let fd = map.as_fd().as_raw_fd();
    let memlock: u64 = std::fs::read_to_string(format!("/proc/self/fdinfo/{fd}"))
        .ok()
        .and_then(|info| {
            info.lines()
                .find_map(|line| line.strip_prefix("memlock:"))
                .and_then(|v| v.trim().parse().ok())
        })
        .unwrap_or(0);
    let used = if memlock > 0 {
        Some(memlock)
    } else if counted {
        let bss = skel.maps.bss_data.as_ref().unwrap();
        Some(
            bss.arena_pages_allocated
                .saturating_sub(bss.arena_pages_freed)
                * page,
        )
    } else {
        None
    };
    (used, max)
}

struct Scheduler<'a> {
    /// The arena's user-space services. Nothing here needs reclaiming, the
    /// arena is carved once at start, but the stream watcher turns an arena
    /// fault in a BPF program, which the kernel would otherwise fix up
    /// silently by dropping the access, into a report and an abort.
    _arenalib: ArenaLib,
    /// The page counters of eevdf_arena_alloc_pages(), attached to the
    /// kernel's arena allocator for the life of the scheduler.
    _arena_links: Vec<libbpf_rs::Link>,
    skel: BpfSkel<'a>,
    struct_ops: Option<libbpf_rs::Link>,
    stats_server: StatsServer<(), Metrics>,
    ops_profiler: OpsProfiler,
    started: Instant,
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
/// Return the number of cgroups whose `file` holds a value `set` accepts, and
/// one of them, walking the cgroup v2 hierarchy. A cgroup has the cpu
/// controller's files only where its parent enables the controller.
fn cgroups_with(
    root: &std::path::Path,
    file: &str,
    set: impl Fn(&str) -> bool,
) -> (usize, Option<String>) {
    let mut stack = vec![(root.to_path_buf(), 0)];
    let (mut count, mut example, mut visited) = (0, None, 0);

    while let Some((dir, depth)) = stack.pop() {
        visited += 1;
        if visited > 100_000 {
            break;
        }
        if let Ok(val) = std::fs::read_to_string(dir.join(file)) {
            if set(val.trim()) {
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
/// hook into, and when a cpu.weight or a cpu.max somebody set is ignored
/// because the feature that reads it is off.
fn check_cgroup_support(requested: bool, kernel_support: bool, cpu_max: bool) {
    let root = std::path::Path::new("/sys/fs/cgroup");
    let cpu_controller = std::fs::read_to_string(root.join("cgroup.subtree_control"))
        .is_ok_and(|ctrl| ctrl.split_whitespace().any(|c| c == "cpu"));

    if cpu_controller && !cpu_max {
        let (count, example) = cgroups_with(root, "cpu.max", |v| {
            v.split_whitespace().next().is_some_and(|q| q != "max")
        });
        if count > 0 {
            warn!(
                "{} cgroup(s) set cpu.max, e.g. {}, which is ignored: cgroup \
                 bandwidth control is disabled by --disable-cgroups or \
                 --disable-cpu-max",
                count,
                example.unwrap_or_default()
            );
        }
    }

    if requested {
        if !kernel_support {
            warn!(
                "the kernel has no sched_ext cgroup support \
                 (CONFIG_EXT_GROUP_SCHED), cgroups are not scheduled as groups"
            );
        } else if !cpu_controller {
            warn!(
                "the cpu controller is not enabled in {}, \
                 every task is scheduled as part of the root cgroup",
                root.join("cgroup.subtree_control").display()
            );
        }
        return;
    }

    if !cpu_controller {
        return;
    }
    const CGROUP_WEIGHT_DFL: u64 = 100;
    let (count, example) = cgroups_with(root, "cpu.weight", |v| {
        v.parse::<u64>().is_ok_and(|w| w != CGROUP_WEIGHT_DFL)
    });
    if count > 0 {
        warn!(
            "{} cgroup(s) set cpu.weight, e.g. {}, which is ignored with \
             --disable-cgroups",
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
        // Automatically disable NUMA optimizations when running on non-NUMA systems.
        let numa_enabled = !opts.disable_numa && nr_nodes > 1;

        // The startup report, one block in the style of the stats blocks,
        // printed once everything below has settled.
        let mut report = console::Report::new();
        report.field(format!("{} CPUs", topo.all_cpus.len()));
        report.field(format!(
            "{} NUMA node{}{}",
            nr_nodes,
            if nr_nodes == 1 { "" } else { "s" },
            if nr_nodes > 1 && !numa_enabled {
                " (--disable-numa)"
            } else {
                ""
            }
        ));
        report.field(if smt_enabled { "SMT on" } else { "SMT off" });
        report.row("build", build_id::full_version(env!("CARGO_PKG_VERSION")));
        report.row("kernel", console::kernel_release());
        report.row(
            "tick",
            format!("{} us (HZ={})", tick_ns() / 1000, 1_000_000_000 / tick_ns()),
        );

        let slice_ns = match opts.slice_us {
            Some(us) => {
                let ns = us * 1000;
                report.row("slice", format!("{us} us (--slice-us)"));
                ns
            }
            None => {
                let ns = base_slice_ns(topo.all_cpus.len());
                report.row(
                    "slice",
                    format!("{} us (700 us scaled as update_sysctl() does)", ns / 1000),
                );
                ns
            }
        };

        // Print command line.
        report.row(
            "options",
            std::env::args().skip(1).collect::<Vec<_>>().join(" "),
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
            scx_ops_cid_open!(skel_builder, open_object, eevdf_ops_cgroup, open_opts)
        } else {
            scx_ops_cid_open!(skel_builder, open_object, eevdf_ops, open_opts)
        }
        .context("opening BPF skeleton (does this kernel support cid-form sched_ext?)")?;
        if cgroup_names {
            skel.maps.eevdf_ops.set_autocreate(false)?;
        } else {
            skel.maps.eevdf_ops_cgroup.set_autocreate(false)?;
        }
        // The arena page counters are loaded only with --stats, and then
        // attached by hand after load, before the first allocation, not
        // with the rest at attach.
        for prog in [
            &mut skel.progs.eevdf_arena_alloc_pages,
            &mut skel.progs.eevdf_arena_free_pages,
        ] {
            prog.set_autoload(opts.stats.is_some());
            prog.set_autoattach(false);
        }

        skel.struct_ops.eevdf_ops_mut().exit_dump_len = opts.exit_dump_len;
        skel.struct_ops.eevdf_ops_cgroup_mut().exit_dump_len = opts.exit_dump_len;

        // Schedule cgroups as groups by default when the kernel
        // has cpu controller support for sched_ext to hook into. Detaching
        // the callbacks from the struct_ops keeps the kernel from delivering
        // them at all, and lets the scheduler load on a kernel whose
        // sched_ext_ops_cid has no cgroup members to bind them to.
        let cgroup_requested = opts.enable_cgroups || !opts.disable_cgroups;
        let cgroup_enabled = cgroup_requested && (cpuctl_names || cgroup_names);

        // cpu.max arrived after the rest of the cpu controller's callbacks, so
        // it is probed on its own: a kernel that delivers cpu.weight may still
        // have no member to bind the bandwidth callback to.
        let bw_field = if cgroup_names {
            "cgroup_set_bandwidth"
        } else {
            "cpuctl_set_bandwidth"
        };
        let bw_support = compat::struct_has_field("sched_ext_ops_cid", bw_field).unwrap_or(false);
        let cpu_max_enabled = cgroup_enabled && !opts.disable_cpu_max && bw_support;
        check_cgroup_support(
            cgroup_requested,
            cpuctl_names || cgroup_names,
            cpu_max_enabled,
        );
        if !cgroup_enabled {
            let ops = skel.struct_ops.eevdf_ops_mut();
            ops.cpuctl_init = std::ptr::null_mut();
            ops.cpuctl_exit = std::ptr::null_mut();
            ops.cpuctl_set_weight = std::ptr::null_mut();
            ops.cpuctl_set_idle = std::ptr::null_mut();
            ops.cpuctl_move = std::ptr::null_mut();
            let ops = skel.struct_ops.eevdf_ops_cgroup_mut();
            ops.cgroup_init = std::ptr::null_mut();
            ops.cgroup_exit = std::ptr::null_mut();
            ops.cgroup_set_weight = std::ptr::null_mut();
            ops.cgroup_set_idle = std::ptr::null_mut();
            ops.cgroup_move = std::ptr::null_mut();
            report.row("cgroup scheduling", "off");
        } else {
            report.row(
                "cgroup scheduling",
                format!(
                    "on ({}_* callbacks)",
                    if cgroup_names { "cgroup" } else { "cpuctl" }
                ),
            );
            if cgroup_requested && !opts.disable_cpu_max && !bw_support {
                warn!("the kernel has no ops.{bw_field}(), cpu.max is ignored");
            }
        }
        if !cpu_max_enabled {
            skel.struct_ops.eevdf_ops_mut().cpuctl_set_bandwidth = std::ptr::null_mut();
            skel.struct_ops.eevdf_ops_cgroup_mut().cgroup_set_bandwidth = std::ptr::null_mut();
        }

        // Override default BPF scheduling parameters.
        let rodata = skel.maps.rodata_data.as_mut().unwrap();
        rodata.slice_ns = slice_ns;
        rodata.tick_ns = tick_ns();
        rodata.migration_cost_ns = opts.migration_cost_us * 1000;
        rodata.cache_nice_tries = opts.cache_nice_tries;
        rodata.no_newidle_cost = opts.no_newidle_cost;
        rodata.newidle_sampling = !opts.no_newidle_sampling;
        rodata.sis_util = !opts.no_sis_util;
        rodata.llc_extend = opts.llc_extend;
        rodata.cpufreq_enabled = !opts.disable_cpufreq;
        rodata.cgroup_enabled = cgroup_enabled;
        rodata.cpu_max_enabled = cpu_max_enabled;
        rodata.numa_enabled = numa_enabled;
        rodata.smt_enabled = smt_enabled;
        rodata.force_smt_asym_packing = opts.smt_asym_packing;
        if opts.smt_asym_packing {
            report.row(
                "SMT sibling priority",
                "lower CPU IDs first (--smt-asym-packing)",
            );
        }
        rodata.smt_whole_core = opts.smt_whole_core && smt_enabled;
        if opts.smt_whole_core && smt_enabled {
            report.row(
                "idle scan",
                "a whole idle core wins over a busy core's sibling, across LLCs",
            );
        }
        rodata.no_wake_sync = opts.no_wake_sync;
        rodata.wa_weight = !opts.no_wa_weight;
        rodata.busy_balance_factor = opts.busy_balance_factor;
        rodata.capacity_pressure = !opts.no_capacity_pressure;
        if opts.no_capacity_pressure {
            report.row(
                "RT/IRQ capacity pressure",
                "disabled (--no-capacity-pressure)",
            );
        }
        rodata.no_task_clock = opts.no_task_clock;
        report.row(
            "service clock",
            if opts.no_task_clock {
                "ktime"
            } else {
                "rq_clock_task"
            },
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
        rodata.latency_credit = opts.latency_credit;
        rodata.latency_credit_ns = opts.latency_credit_us * 1000;
        rodata.latency_credit_user_thresh = opts.latency_credit_user_busy_pct * 1024 / 100;
        rodata.latency_credit_sleep_ns = opts.latency_credit_sleep_ms * 1000000;
        rodata.no_latency_credit_pack = opts.no_latency_credit_pack;
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
        report.row(
            "CPU capacity",
            format!(
                "{capacity_mode} ({nr_capacity_tiers} tier{}, tolerance {tolerance}%)",
                if nr_capacity_tiers == 1 { "" } else { "s" }
            ),
        );
        if has_capacity_tiers {
            report.row(
                "CPUs by capacity",
                format!(
                    "{:?}",
                    cpus.iter().map(|(cpu, _)| cpu.id).collect::<Vec<_>>()
                ),
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
        skel.struct_ops.eevdf_ops_mut().flags = flags;
        skel.struct_ops.eevdf_ops_cgroup_mut().flags = flags;

        report.row("scheduler flags", format!("{flags:#x}"));

        // One hrtick per cid, over the same cid space the arena is sized
        // for below. A map is sized before the program is loaded.
        let nr_cpus = (*NR_CPU_IDS).max(*NR_CPUS_POSSIBLE);
        skel.maps
            .hrticks
            .set_max_entries(nr_cpus as u32)
            .context("sizing the hrtick map")?;

        // Load the BPF program for validation.
        let mut skel = if cgroup_names {
            scx_ops_cid_load!(skel, eevdf_ops_cgroup, uei)
        } else {
            scx_ops_cid_load!(skel, eevdf_ops, uei)
        }?;

        // Count arena pages at the allocator, see eevdf_arena_alloc_pages():
        // attached before the first allocation, which is eevdf_arena_init()
        // below, so the count is exact. Without --stats the programs are not
        // even loaded and the allocator pays nothing.
        let mut arena_links = Vec::new();
        if opts.stats.is_some() {
            skel.maps.bss_data.as_mut().unwrap().arena_map_id = skel.maps.arena.info()?.info.id;
            for (prog, name) in [
                (&skel.progs.eevdf_arena_alloc_pages, "bpf_arena_alloc_pages"),
                (&skel.progs.eevdf_arena_free_pages, "bpf_arena_free_pages"),
            ] {
                match prog.attach() {
                    Ok(link) => arena_links.push(link),
                    Err(e) => warn!("arena memory will not be counted: attaching to {name}: {e}"),
                }
            }
        }

        // Capacity and asymmetric packing are separate kernel policies.
        // Topology reconstructs the portable domain spans, but neither
        // SD_ASYM_PACKING nor arch_asym_cpu_priority() has a userspace ABI.
        // Keep this narrow BPF query until sched_ext provides one.
        let mut priorities = Vec::with_capacity(cpu_tiers.len());
        let mut all_asym_packing = !opts.disable_asym_packing;
        for (cpu, _, _, _, smt_asym_packing, _, _, _) in &mut cpu_tiers {
            let mut args = types::eevdf_cpu_priority_args {
                cpu: *cpu,
                priority: 0,
                asym_packing: 0,
                smt_asym_packing: 0,
            };
            run_syscall_prog(&skel.progs.eevdf_get_cpu_priority, &mut args)
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
        report.row(
            "domain spans",
            format!(
                "(fork, wake-affine, asym-capacity, source={}): {:?}",
                match sched_domain_source {
                    Some(SchedDomainSource::Schedstat) => "schedstat",
                    Some(SchedDomainSource::Topology) | None => "topology",
                },
                domain_spans
            ),
        );

        let sched_asym_capacity =
            !opts.uniform_capacity && cpu_tiers.iter().any(|entry| entry.7 != 0);
        let asym_capacity = has_capacity_tiers && (sched_asym_capacity || opts.asym_capacity);
        if has_capacity_tiers && !asym_capacity {
            report.row(
                "CPU capacity placement",
                "off (no kernel SD_ASYM_CPUCAPACITY domain)",
            );
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
            report.row(
                "asymmetric packing",
                format!(
                    "kernel ({} priority tiers, CPUs {:?})",
                    nr_place_tiers,
                    priorities.iter().map(|(cpu, _)| cpu).collect::<Vec<_>>()
                ),
            );
        } else {
            for (_, _, capacity_tier, place_tier, smt_asym_packing, _, _, _) in &mut cpu_tiers {
                *place_tier = if asym_capacity { *capacity_tier } else { 0 };
                *smt_asym_packing = false;
            }
            report.row(
                "asymmetric packing",
                format!(
                    "{}; placement follows {}",
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
                ),
            );
        }

        // Size the arena for the cid space, which is num_possible_cpus()
        // wide, and hand over the capacity of each CPU. The cid layout is
        // only known once the kernel has built it, at attach, so this is in
        // cpu space and ops.init() translates. It has to happen between
        // load and attach: the tables must be in place before ops.init().
        let mut args = types::eevdf_arena_args {
            nr_cpus: nr_cpus as u64,
            nr_place_tiers,
            nr_capacity_tiers,
            asym_capacity: asym_capacity as u64,
            sched_asym_capacity: sched_asym_capacity as u64,
            force_asym_capacity: opts.asym_capacity as u64,
            asym_packing: asym_packing as u64,
        };
        run_syscall_prog(&skel.progs.eevdf_arena_init, &mut args)
            .context("running eevdf_arena_init")?;
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
            let mut args = types::eevdf_cpu_args {
                cpu,
                capacity,
                place_tier,
                capacity_tier,
                smt_asym_packing: smt_asym_packing as u64,
                fork_span,
                wake_affine_span,
                asym_capacity_span,
            };
            run_syscall_prog(&skel.progs.eevdf_set_cpu, &mut args)
                .context("running eevdf_set_cpu")?;
        }

        // Watch the BPF streams: an arena fault is reported and fatal rather
        // than silently fixed up.
        let arenalib =
            ArenaLib::start(skel.object_mut()).context("starting arena userspace services")?;

        // Attach the scheduler.
        let struct_ops = Some(if cgroup_names {
            scx_ops_attach!(skel, eevdf_ops_cgroup)
        } else {
            scx_ops_attach!(skel, eevdf_ops)
        }?);
        let stats_server = StatsServer::new(stats::server_data()).launch()?;

        // Only when the usage is known: counted with --stats, or by the kernel.
        let (arena_bytes, arena_max_bytes) = arena_usage(&skel, !arena_links.is_empty());
        if let Some(bytes) = arena_bytes {
            report.row(
                "BPF arena memory",
                format!(
                    "{} of {} allocated",
                    stats::human_bytes(bytes),
                    stats::human_bytes(arena_max_bytes)
                ),
            );
        }
        report.print();
        console::status("scheduler attached and running");

        Ok(Self {
            _arenalib: arenalib,
            _arena_links: arena_links,
            skel,
            struct_ops,
            stats_server,
            ops_profiler: OpsProfiler::new(),
            started: Instant::now(),
        })
    }

    fn get_metrics(&mut self) -> Metrics {
        let bss_data = self.skel.maps.bss_data.as_ref().unwrap();
        let (arena_bytes, arena_max_bytes) = arena_usage(&self.skel, !self._arena_links.is_empty());
        let mut m = Metrics {
            elapsed_ns: self.started.elapsed().as_nanos() as u64,
            nr_cpus: *NR_CPU_IDS as u64,
            nr_sis_updates: bss_data.nr_sis_updates,
            sis_scan_sum: bss_data.sis_scan_sum,
            arena_bytes: arena_bytes.unwrap_or(0),
            arena_max_bytes,
            arena_counted: arena_bytes.is_some() as u64,
            arena_active_allocs: bss_data.alloc_stats.active_allocs,
            arena_alloc_failures: bss_data.alloc_stats.alloc_nomem,
            ..Default::default()
        };
        m.ops = self.ops_profiler.sample(&self.skel);
        m.ops_profiled = self.ops_profiler.enabled.is_some() as u64;
        m
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
            self.ops_profiler.expire();
        }

        let _ = self.struct_ops.take();

        // A graceful unregister is reported in the console style; an error
        // exit keeps the standard report, with the debug dump on stderr.
        let uei = uei_read!(&self.skel, uei);
        if let Some(why) = self.exit_summary() {
            console::status(&format!("scheduler stopped: {why}"));
            return Ok(uei);
        }
        uei.report().map(|_| uei)
    }

    /// A graceful unregister as one line, "reason" or "reason (msg)", read
    /// off the BPF-side exit info. None when the scheduler was kicked out
    /// by an error, which keeps the standard report and its debug dump.
    fn exit_summary(&self) -> Option<String> {
        let uei = &self.skel.maps.data_data.as_ref().unwrap().uei;
        if uei.kind == ScxExitKind::None as i32 || uei.kind > ScxExitKind::UnregKern as i32 {
            return None;
        }
        // The skeleton types the arrays after the BPF target, where char is
        // signed, while c_char is u8 on aarch64: take i8 and cast.
        let text = |chars: &[i8]| {
            // NUL-terminated by the BPF side, and the array is never full.
            unsafe { CStr::from_ptr(chars.as_ptr().cast()) }
                .to_string_lossy()
                .into_owned()
        };
        let reason = text(&uei.reason);
        let msg = text(&uei.msg);
        if reason.is_empty() {
            return Some("unknown reason".to_string());
        }
        Some(if msg.is_empty() {
            reason
        } else {
            format!("{reason} ({msg})")
        })
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

    // The stats client, in its own thread: alone in --monitor mode, or
    // beside the scheduler in --stats mode, where it starts only once the
    // scheduler is attached and its stats server is up, so it never has to
    // retry a connection.
    let spawn_monitor = |intv: f64| {
        let shutdown_copy = shutdown.clone();
        std::thread::spawn(move || {
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
        })
    };

    if let Some(intv) = opts.monitor {
        let _ = spawn_monitor(intv).join();
        return Ok(());
    }

    warn_on_old_kernel();

    let mut open_object = MaybeUninit::uninit();
    let mut monitor = None;
    loop {
        let mut sched = Scheduler::init(&opts, &mut open_object)?;
        if let (Some(intv), None) = (opts.stats, &monitor) {
            monitor = Some(spawn_monitor(intv));
        }
        if !sched.run(shutdown.clone())?.should_restart() {
            break;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::capacity_tiers;
    use super::kernel_major_minor;

    #[test]
    fn parses_kernel_major_minor() {
        assert_eq!(kernel_major_minor("7.2.0-rc1"), Some((7, 2)));
        assert_eq!(kernel_major_minor("6.18.12-arch1-1"), Some((6, 18)));
        assert_eq!(kernel_major_minor("7.2-custom"), Some((7, 2)));
        assert_eq!(kernel_major_minor("not-a-version"), None);
    }

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
