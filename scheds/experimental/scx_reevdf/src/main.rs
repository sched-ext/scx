// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.

use std::{cell::RefCell, ffi::OsStr, rc::Rc, time::Instant};

use libbpf_rs::{MapCore, MapFlags, Object};

/// The balance state's layout, from the source the BPF program is built
/// from.
#[path = "../bpf/src/balance_state.rs"]
#[allow(dead_code)]
mod balance_state;

mod balance;
mod stats;

use log::info;
use scx_rustsched_abi::runtime;
use scx_rustsched_loader::tiers::CapacityMode;
use scx_rustsched_loader::{
    Attached, Capacity, Loaded, OpsProfiler, Params, QueueSampler, Result, Scheduler, Stats,
    arena_usage, compat,
};

/// The scheduler's options. `scx_rustsched::opts!()` in bpf/src/main.rs declares
/// a tunable for each, named as the option in upper case, and the loader
/// sets each from its option. The ones marked `no_bpf` are the loader's
/// alone: what the scheduler asks of the runtime, and how capacities are
/// read.
#[derive(clap::Args, scx_rustsched_loader::Opts)]
struct Opts {
    /// The default request in microseconds. 0, the default, is fair.c's
    /// sysctl_sched_base_slice as update_sysctl() sets it: 700 us scaled by
    /// 1 + ilog2(min(nr_cpus, 8)), computed by the BPF program at init.
    #[arg(short = 's', long, default_value_t = 0)]
    slice_us: u64,
    /// Do not drive cpufreq from how busy each CPU is.
    #[arg(short = 'f', long)]
    disable_cpufreq: bool,
    /// Look past the target LLC for an idle CPU on wakeup. By default the
    /// search is scoped to the LLC, as select_idle_sibling() is, and
    /// spreading across LLCs is left to stealing.
    #[arg(long)]
    llc_extend: bool,
    /// Decide wake_affine() without comparing the loads of the two CPUs,
    /// fair.c's WA_WEIGHT.
    #[arg(long)]
    no_wa_weight: bool,
    /// Microseconds after it stopped that a task is still cache hot on its
    /// CPU and is not pulled by an idle one, sysctl_sched_migration_cost.
    #[arg(short = 'm', long, default_value_t = 500)]
    migration_cost_us: u64,
    /// Idle pulls in a row that may find work queued but take nothing
    /// before cache hotness is ignored, one domain level at a time:
    /// sd->cache_nice_tries.
    #[arg(short = 'c', long, default_value_t = 1)]
    cache_nice_tries: u64,
    /// Do not bound idle pulls by how long the CPU stays idle against what
    /// a pull costs, sched_balance_newidle()'s avg_idle budget.
    #[arg(long)]
    no_newidle_cost: bool,
    /// Do not sample idle pulls by how often they find work, NI_RANDOM.
    #[arg(long)]
    no_newidle_sampling: bool,
    /// Scan the whole LLC for an idle CPU on every wakeup. By default the
    /// scan is bounded by the LLC's average utilization, fair.c's SIS_UTIL,
    /// which periodic balance refreshes, and a bounded scan that finds
    /// nothing leaves the task on its target.
    #[arg(long)]
    no_sis_util: bool,
    /// Do not take the waker's CPU on a synchronous wakeup.
    ///
    /// A synchronous wakeup says the waker is about to sleep, and
    /// wake_affine() hands the wakee the waker's CPU when nothing else is
    /// queued there. Turning that off can spread load more evenly, at the
    /// cost of producer-consumer pairs that benefit from sharing a cache.
    #[arg(short = 'w', long)]
    no_wake_sync: bool,
    /// Never interrupt a running task for a woken one with an earlier deadline.
    ///
    /// Every task then runs until its slice ends or it blocks, and a woken task
    /// waits for that, up to a full slice. This is the behavior before wakeup
    /// preemption was added, kept for comparison.
    #[arg(short = 'p', long)]
    no_wakeup_preempt: bool,
    /// Interrupt on the deadlines alone, without asking who is owed service.
    ///
    /// The wakeup preemption normally fires only when the woken task is owed
    /// service and the running one is not, the way pick_eevdf() drops an
    /// ineligible current task and then picks an eligible waiter. This skips
    /// both tests and decides on the deadlines alone. For comparing the two
    /// rules against each other.
    #[arg(short = 'e', long)]
    no_eligibility: bool,
    /// Take the head of a deadline-ordered queue at dispatch, eligible or not.
    ///
    /// The EDQ normally uses its augmented tree to find the earliest-deadline
    /// task whose vruntime is eligible in logarithmic time. This option takes
    /// the head instead; --no-eligibility implies it. Wakeup preemption and
    /// keep-running decisions are head-based either way because they cannot
    /// observe the current task, queue, and virtual-time frontier atomically.
    #[arg(long)]
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
    #[arg(short = 'r', long)]
    no_run_to_parity: bool,
    /// Keep a longer-request running task protected from shorter wakees.
    ///
    /// Normally an eligible waking task that asks for a shorter request than
    /// the task currently running can preempt it despite RUN_TO_PARITY. The
    /// wakee is put on an available local DSQ as a one-shot short buddy,
    /// matching the wakeup side of PREEMPT_SHORT in fair.c. This option keeps
    /// the ordinary protection for comparison.
    #[arg(long)]
    no_preempt_short: bool,
    /// Do not compensate placement lag for joining a virtual-time pack.
    ///
    /// Normally scx_reevdf inflates a task's placement offset before adding its
    /// weight to the destination pack, so the movement of the weighted-average
    /// reference does not dilute the requested lag. This disables that
    /// PLACE_LAG compensation and restores the older behavior where lag can
    /// evaporate as a task repeatedly sleeps and wakes. For comparing the two
    /// placement rules against each other.
    #[arg(long)]
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
    #[arg(short = 'R', long)]
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
    #[arg(short = 'D', long)]
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
    #[arg(long)]
    no_delay_requeue: bool,
    /// Let a task blocked on a mutex block instead of donating its turn.
    ///
    /// With proxy execution, a task that blocks on a mutex stays runnable as
    /// a donor, and when it is picked its scheduling context runs the mutex
    /// owner, which gets the lock released sooner. The donor keeps its place
    /// in the queue and is charged for what the owner runs on its behalf, as
    /// fair.c does. This makes such a task block and leave the queue instead.
    /// Proxy execution is used only on kernels that support it for sched_ext.
    #[opts(no_bpf)]
    #[arg(long)]
    no_proxy_exec: bool,
    /// Notice the end of a request at the tick after it, not when it happens.
    ///
    /// A request is normally ended on the spot by a timer armed for the
    /// running task's deadline whenever it has company, the way HRTICK does
    /// in fair.c. Without it a task holds the CPU until the tick that follows
    /// the end of its request, up to a whole tick late, and a task waiting
    /// behind it waits that long. For comparing the two against each other.
    #[arg(short = 'H', long)]
    no_hrtick: bool,
    /// Place and test tasks against a pack reference that is not up to date.
    ///
    /// A running task's vruntime is only charged when it stops, so the
    /// reference of its pack stands still while it runs and everything read
    /// off it in between is behind by up to a request. It is normally brought
    /// up to date on the spot, the way update_curr() does before every
    /// place_entity() and every entity_eligible(). This reads it as stored,
    /// for comparing the two against each other.
    #[arg(short = 'U', long)]
    no_vref_update: bool,
    /// Milliseconds of periodic balance interval per CPU of a domain while
    /// it is busy, sd->busy_factor; doubles up to twice that while it is
    /// balanced.
    #[arg(long, default_value_t = 16)]
    busy_balance_factor: u64,
    /// Do not account for the CPU capacity higher scheduling classes, IRQs
    /// and steal time take: balance then counts every CPU at its full
    /// capacity, and a task displaced on a reduced CPU is not moved.
    #[arg(long)]
    no_capacity_pressure: bool,
    /// Schedule every task at its own nice weight, rather than at its share
    /// of its cgroups' cpu.weight hierarchy.
    #[arg(long)]
    disable_cgroups: bool,
    /// Do not hold cgroups to their cpu.max bandwidth.
    #[arg(long)]
    disable_cpu_max: bool,
    /// Treat the machine as one NUMA node: wakeups, idle pulls and balance
    /// see a node spanning every CPU.
    #[opts(no_bpf)]
    #[arg(short = 'n', long)]
    disable_numa: bool,
    /// Treat every CPU as a core of its own: no whole-core preference in
    /// wakeups, balance or idle pulls, and no SMT sibling ranking.
    #[opts(no_bpf)]
    #[arg(short = 'S', long)]
    disable_smt: bool,
    /// Give every CPU the same capacity. By default capacities are the
    /// kernel's cpu_capacity, which placement follows when the kernel has an
    /// SD_ASYM_CPUCAPACITY domain.
    #[opts(no_bpf)]
    #[arg(short = 'u', long, conflicts_with = "asym_capacity")]
    uniform_capacity: bool,
    /// Make placement follow capacity, taking capacities from the hardware
    /// estimate (CPPC, cpufreq) rather than the kernel's. This can tell
    /// hybrid x86 cores apart where fair.c does not.
    #[opts(no_bpf)]
    #[arg(long, conflicts_with = "uniform_capacity")]
    asym_capacity: bool,
    /// Largest capacity difference, in percent, within one capacity tier.
    /// The default is 0 with the kernel's capacities and 5 otherwise.
    #[opts(no_bpf)]
    #[arg(short = 't', long, value_parser = clap::value_parser!(u32).range(0..=50))]
    capacity_tier_tolerance_pct: Option<u32>,
    /// Ignore the kernel's SD_ASYM_PACKING CPU priorities.
    #[opts(no_bpf)]
    #[arg(long)]
    disable_asym_packing: bool,
    /// Prefer the lower-numbered CPUs within each SMT core, when the kernel
    /// ranks the threads of a core no differently: a wakeup or a balance
    /// destination on a core goes to its lowest-numbered idle thread. For
    /// placement only: cores are not ranked by CPU number and no task is
    /// moved between the threads of a core. A determinism aid for
    /// comparisons, not a performance policy.
    #[opts(no_bpf)]
    #[arg(long, conflicts_with = "disable_smt")]
    smt_asym_packing: bool,
    /// Let a wakeup leave its LLC to find a whole idle core, with
    /// --llc-extend. An idle SMT sibling of a busy core is half of a core
    /// that is already working: placing a task there costs the thread on
    /// the other sibling about half its throughput while the two overlap.
    /// By default the scan follows select_idle_sibling() and takes that
    /// sibling, since fair.c stops at the LLC and leaves the rest to the
    /// periodic balancer. This makes it prefer a whole idle core in another
    /// LLC, and capacity-pressure moves rank whole idle cores first,
    /// trading cache locality for core throughput while such a core exists.
    /// It matters where an LLC spans a whole node: once that node is
    /// saturated, everything the machine wakes lands on its busy cores'
    /// siblings while another node's cores sit idle.
    #[opts(no_bpf)]
    #[arg(long, conflicts_with = "disable_smt")]
    smt_whole_core: bool,
    /// Charge virtual time in wall-clock time, interrupts and steal time
    /// included, rather than in each CPU's task clock, rq_clock_task().
    #[opts(no_bpf)]
    #[arg(long)]
    no_task_clock: bool,
}

impl Scheduler for Opts {
    fn settings(&self, params: &mut Params) -> Result<()> {
        // Proxy execution: SCX_OPS_ENQ_BLOCKED hands mutex-blocked donors to
        // ops.enqueue() with SCX_ENQ_BLOCKED. The flag reads as zero on a
        // kernel without it, which leaves proxy execution off.
        params.add_flags(if self.no_proxy_exec {
            0
        } else {
            *compat::SCX_OPS_ENQ_BLOCKED
        });
        // The cgroup callbacks stay off on a kernel that has none.
        params.set(
            "no_cgroup_ops",
            &[scx_rustsched_loader::cgroup_ops()?.is_none()],
        )
    }

    fn runtime(&self) -> u64 {
        [
            (self.disable_smt, runtime::DISABLE_SMT),
            (self.disable_numa, runtime::DISABLE_NUMA),
            (self.smt_whole_core, runtime::SMT_WHOLE_CORE),
            (self.smt_asym_packing, runtime::SMT_ASYM_PACKING),
            (self.no_task_clock, runtime::NO_TASK_CLOCK),
        ]
        .iter()
        .fold(0, |bits, (on, bit)| if *on { bits | bit } else { bits })
    }

    fn capacity(&self) -> Capacity {
        Capacity {
            mode: if self.uniform_capacity {
                CapacityMode::Uniform
            } else if self.asym_capacity {
                CapacityMode::Hardware
            } else {
                CapacityMode::Kernel
            },
            tolerance_pct: self.capacity_tier_tolerance_pct,
            no_asym_packing: self.disable_asym_packing,
        }
    }

    fn attached(&self, attached: &Attached<'_>) {
        print_startup(self, attached);
        info!("{} scheduler attached and running", attached.name());
    }

    fn stopped(&self, name: &str, why: &str) {
        info!("{name} scheduler stopped: {why}");
    }

    fn stats(&self) -> Option<Stats> {
        // What reads the arena's mapping is set up at the first sample,
        // once the scheduler runs.
        let sampler = Rc::new(RefCell::new(None::<Sampler>));
        let idle = sampler.clone();
        Some(
            Stats::new(
                stats::server_data,
                move |object| {
                    sampler
                        .borrow_mut()
                        .get_or_insert_with(|| Sampler::new(object))
                        .metrics(object)
                },
                stats::show(),
            )
            .idle(move |_| {
                if let Some(sampler) = idle.borrow_mut().as_mut() {
                    sampler.profiler.expire();
                }
            }),
        )
    }
}

/// Print what the scheduler runs with, in scx_eevdf's layout: a header line
/// of `|`-separated fields, then `key  value` rows aligned on the longest
/// key.
fn print_startup(opts: &Opts, attached: &Attached<'_>) {
    let mut header = vec![format!("{} {}", attached.name(), attached.version())];
    if let Some(nr_cpus) = attached.nr_cpus() {
        header.push(format!("{nr_cpus} CPUs"));
    }
    if let Some(nr_nodes) = attached.nr_nodes() {
        header.push(format!(
            "{nr_nodes} NUMA node{}{}",
            if nr_nodes == 1 { "" } else { "s" },
            if nr_nodes > 1 && attached.numa_disabled() {
                " (--disable-numa)"
            } else {
                ""
            }
        ));
    }
    if let Some(smt) = attached.smt() {
        header.push(if smt { "SMT on" } else { "SMT off" }.to_string());
    }

    let mut rows: Vec<(&str, String)> = Vec::new();
    rows.push(("build", attached.build()));
    rows.push(("kernel", attached.kernel_release()));
    let tick = attached.tick_ns();
    rows.push((
        "tick",
        format!("{} us (HZ={})", tick / 1000, 1_000_000_000 / tick),
    ));
    rows.push((
        "slice",
        if opts.slice_us != 0 {
            format!("{} us (--slice-us)", opts.slice_us)
        } else {
            // What init computed from the number of CPUs.
            format!(
                "{} us (700 us scaled as update_sysctl() does)",
                read_u64(attached.object(), ".data.slice") / 1000
            )
        },
    ));
    rows.push((
        "options",
        std::env::args().skip(1).collect::<Vec<_>>().join(" "),
    ));
    rows.push((
        "cgroup scheduling",
        match scx_rustsched_loader::cgroup_ops() {
            _ if opts.disable_cgroups => "off".to_string(),
            Ok(Some(ops)) => format!(
                "on ({}_* callbacks)",
                if ops == "rust_ops" {
                    "cpuctl"
                } else {
                    "cgroup"
                }
            ),
            _ => "off (not supported by the kernel)".to_string(),
        },
    ));
    rows.push((
        "service clock",
        if opts.no_task_clock {
            "ktime"
        } else {
            "rq_clock_task"
        }
        .to_string(),
    ));
    rows.push((
        "proxy execution",
        if attached.ops_flags() & *compat::SCX_OPS_ENQ_BLOCKED != 0 {
            "on"
        } else if opts.no_proxy_exec {
            "off (--no-proxy-exec)"
        } else {
            "off (not supported by the kernel)"
        }
        .to_string(),
    ));
    if let Some(tiers) = attached.tiers() {
        let mode = match tiers.mode {
            CapacityMode::Kernel => "kernel",
            CapacityMode::Uniform => "forced uniform",
            CapacityMode::Hardware => "hardware-derived",
        };
        rows.push((
            "CPU capacity",
            format!(
                "{mode} ({} tier{}, tolerance {}%)",
                tiers.nr_capacity_tiers,
                if tiers.nr_capacity_tiers == 1 {
                    ""
                } else {
                    "s"
                },
                tiers.tolerance,
            ),
        ));
        if tiers.nr_capacity_tiers > 1 {
            rows.push((
                "CPUs by capacity",
                format!(
                    "{:?}",
                    tiers.cpus.iter().map(|cpu| cpu.id).collect::<Vec<_>>()
                ),
            ));
            if !tiers.asym_capacity {
                rows.push((
                    "CPU capacity placement",
                    "off (no kernel SD_ASYM_CPUCAPACITY domain)".to_string(),
                ));
            }
        }
        rows.push((
            "asymmetric packing",
            if tiers.asym_packing {
                let mut order = tiers.cpus.clone();
                order.sort_by_key(|cpu| (cpu.place_tier, cpu.id));
                format!(
                    "kernel ({} priority tiers, CPUs {:?})",
                    tiers.nr_place_tiers,
                    order.iter().map(|cpu| cpu.id).collect::<Vec<_>>()
                )
            } else if tiers.asym_capacity {
                format!("off; placement follows {mode} capacity tiers")
            } else {
                "off; placement follows uniform capacity".to_string()
            },
        ));
    }
    rows.push(("scheduler flags", format!("{:#x}", attached.ops_flags())));
    // Only when the kernel accounts the arena's pages, from 7.3.
    if let (Some(bytes), max) = attached.arena_usage() {
        rows.push((
            "BPF arena memory",
            format!("{} of {} allocated", human_bytes(bytes), human_bytes(max)),
        ));
    }

    info!("{}", header.join(" | "));
    let width = rows.iter().map(|(key, _)| key.len()).max().unwrap_or(0);
    for (key, value) in rows {
        info!("{key:<width$}  {value}");
    }
}

/// `bytes` in binary units, one decimal.
fn human_bytes(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit + 1 < UNITS.len() {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

/// The first word of the BPF object's data section `section`, 0 when it
/// cannot be read.
fn read_u64(object: &Object, section: &str) -> u64 {
    let mut bytes = [0_u8; 8];
    if let Some(map) = object.maps().find(|map| map.name() == OsStr::new(section)) {
        let _ = map.lookup_into(&0_u32.to_ne_bytes(), &mut bytes, MapFlags::ANY);
    }
    u64::from_ne_bytes(bytes)
}

/// What the metrics are read with, and since when.
struct Sampler {
    profiler: OpsProfiler,
    queues: Option<QueueSampler>,
    balance: Option<balance::BalanceReader>,
    started: Instant,
}

impl Sampler {
    fn new(object: &Loaded) -> Self {
        Self {
            profiler: OpsProfiler::new(),
            queues: QueueSampler::new(object)
                .inspect_err(|error| eprintln!("queue statistics unavailable: {error:#}"))
                .ok(),
            balance: balance::BalanceReader::new(object)
                .inspect_err(|error| eprintln!("balance statistics unavailable: {error:#}"))
                .ok(),
            started: Instant::now(),
        }
    }

    fn metrics(&mut self, object: &Object) -> stats::Metrics {
        metrics(
            object,
            &mut self.profiler,
            self.queues.as_ref(),
            self.balance.as_ref(),
            self.started,
        )
    }
}

/// Kernel run-time accounting of the sched_ext callbacks, BPF_ENABLE_STATS,
/// as scx_eevdf keeps it, and the per-CID queues and balance state as
/// `queues` and `balance` read them from the arena.
///
/// One sample of the metrics, cumulative since `started`.
fn metrics(
    object: &Object,
    profiler: &mut OpsProfiler,
    queues: Option<&QueueSampler>,
    balance: Option<&balance::BalanceReader>,
    started: Instant,
) -> stats::Metrics {
    let (arena_bytes, arena_max_bytes) = arena_usage(object);
    let mut counters = [0_u8; 48];
    if let Some(map) = object
        .maps()
        .find(|map| map.name() == OsStr::new(".data.astats"))
    {
        let _ = map.lookup_into(&0_u32.to_ne_bytes(), &mut counters, MapFlags::ANY);
    }
    let counter =
        |index: usize| u64::from_ne_bytes(counters[index * 8..index * 8 + 8].try_into().unwrap());
    let mut m = stats::Metrics {
        elapsed_ns: started.elapsed().as_nanos() as u64,
        nr_cpus: libbpf_rs::num_possible_cpus().unwrap_or(1) as u64,
        arena_bytes: arena_bytes.unwrap_or(0),
        arena_max_bytes,
        arena_counted: u64::from(arena_bytes.is_some()),
        arena_active_allocs: counter(0).saturating_sub(counter(1)),
        arena_alloc_failures: counter(3),
        ..Default::default()
    };
    let mut sis = [0_u8; 16];
    if let Some(map) = object
        .maps()
        .find(|map| map.name() == OsStr::new(".data.sstats"))
    {
        let _ = map.lookup_into(&0_u32.to_ne_bytes(), &mut sis, MapFlags::ANY);
    }
    m.nr_sis_updates = u64::from_ne_bytes(sis[..8].try_into().unwrap());
    m.sis_scan_sum = u64::from_ne_bytes(sis[8..].try_into().unwrap());
    m.ops = profiler
        .sample(object)
        .into_iter()
        .map(|(name, op)| {
            (
                name,
                stats::OpStats {
                    calls: op.calls,
                    ns: op.ns,
                    misses: op.misses,
                },
            )
        })
        .collect();
    m.ops_profiled = u64::from(profiler.enabled.is_some());
    if let Some(queues) = queues {
        let (samples, queues) = queues.sample();
        m.edq_samples = samples;
        m.queues = queues
            .into_iter()
            .enumerate()
            .map(|(cid, queue)| {
                (
                    cid.to_string(),
                    stats::QueueStats {
                        inserts: queue.inserts,
                        depth_sum: queue.depth_sum,
                        busy: queue.busy,
                        locked: queue.locked,
                    },
                )
            })
            .collect();
    }
    if let Some(balance) = balance {
        m.balance = balance
            .read()
            .into_iter()
            .enumerate()
            .map(|(cid, state)| (cid.to_string(), stats::BalanceStats::from(state)))
            .collect();
    }
    m
}

scx_rustsched_loader::main!(
    "EEVDF sched_ext scheduler completely written in Rust, after scx_eevdf",
    Opts
);
