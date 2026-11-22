// SPDX-License-Identifier: GPL-2.0
//
// Copyright (c) 2024 Andrea Righi <andrea.righi@linux.dev>

// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

mod bpf_skel;
pub use bpf_skel::*;
pub mod bpf_intf;
pub use bpf_intf::*;

mod stats;
use std::collections::BTreeMap;
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
use libbpf_rs::MapCore;
use libbpf_rs::OpenObject;
use libbpf_rs::ProgramInput;
use libbpf_rs::skel::Skel;
use log::{debug, info, warn};
use scx_arena::ArenaLib;
use scx_stats::prelude::*;
use scx_utils::CoreType;
use scx_utils::Cpumask;
use scx_utils::NR_CPU_IDS;
use scx_utils::Topology;
use scx_utils::UserExitInfo;
use scx_utils::autopower::{PowerProfile, fetch_power_profile};
use scx_utils::build_id;
use scx_utils::compat;
use scx_utils::libbpf_clap_opts::LibbpfOpts;
use scx_utils::scx_ops_attach;
use scx_utils::scx_ops_load;
use scx_utils::scx_ops_open;
use scx_utils::try_set_rlimit_infinity;
use scx_utils::uei_exited;
use scx_utils::uei_report;
use stats::Metrics;

const SCHEDULER_NAME: &str = "scx_bpfland";

/// The most CPUs the BPF side handles, MAX_CPUS in src/bpf/intf.h.
const MAX_CPUS: usize = 1024;

/// The bits of the queued mask of the BPF side, QUEUED_WORDS in src/bpf/intf.h.
const QUEUED_BITS: usize = 2048 * 64;

/// The bits of a cache line.
const LINE_BITS: usize = 512;

/// The most CPU tiers the BPF side tells apart, MAX_TIERS in src/bpf/main.bpf.c.
const MAX_TIERS: u32 = 8;

/// How much less capacity a CPU may have than the largest of its tier, in percent. Cores of one
/// type can differ by a few percent, and a move between two of them would gain nothing.
const CAPACITY_TOLERANCE_PCT: usize = 5;

/// scx_bpfland: an EEVDF-style scheduler with one queue per CPU, virtual-time borrowing and
/// requests sized by the CPU burst.
///
/// Each CPU runs the eligible task with the earliest virtual deadline from its own queue. A task's
/// deadline is its virtual time plus how long it runs between two sleeps, so tasks that run in
/// short bursts take the CPU from those that compute without a pause. A waking task also borrows
/// virtual time, which keeps interactive workloads responsive beside CPU-intensive ones.
///
/// The BPF part makes all the scheduling decisions (see src/bpf/main.bpf.c).
#[derive(Debug, Parser)]
struct Opts {
    /// Exit debug dump buffer length. 0 indicates default.
    #[clap(long, default_value = "0")]
    exit_dump_len: u32,

    /// Scheduling slice duration in microseconds.
    #[clap(short = 's', long, default_value = "1600")]
    slice_us: u64,

    /// The CPUs to place tasks on: a preference among all of them, or a domain they are kept in.
    ///
    /// A preference orders the CPUs that placement tries first, and tasks still use every CPU
    /// when those are busy:
    ///  - "performance" = the fastest CPUs first, the default where the CPUs rank
    ///  - "powersave" = the slowest CPUs first
    ///  - "turbo" = the CPUs that boost highest first, then the fastest
    ///  - "auto" = "powersave" under the power-saver profile, otherwise "performance"
    ///  - "cores" = one thread of each physical core first, then its SMT siblings
    ///
    /// A CPU list is a domain: it keeps tasks on its CPUs, queued there rather than spilled onto
    /// other CPUs when those are busy. Tasks whose affinity excludes the domain, and
    /// migration-disabled tasks, may run outside it. "all" uses every online CPU, which is the
    /// default.
    #[clap(short = 'm', long, value_name = "DOMAIN")]
    primary_domain: Option<String>,

    /// Do not place tasks on the CPUs they are better off on, where the CPUs rank: by the
    /// kernel's packing priorities, or by their capacities on a machine with big and little cores.
    #[clap(long)]
    no_asym_packing: bool,

    /// Do not let a waking task with a shorter request and an earlier deadline take the CPU from
    /// the running task.
    #[clap(long)]
    no_preempt: bool,

    /// Pick the earliest deadline whatever the virtual time, instead of among the eligible tasks,
    /// the ones not ahead of the clock.
    #[clap(long)]
    no_eligibility: bool,

    /// Do not keep a task's lag across a sleep, as EEVDF does: sleeping then earns service, up to
    /// the lag bound.
    #[clap(long)]
    no_vlag: bool,

    /// Maximum lag of a task when it is queued, behind the clock or ahead of it, in microseconds
    /// of service at nice 0.
    #[clap(short = 'l', long, default_value = "10000")]
    lag_bound_us: u64,

    /// Minimum time a task runs before a waking task can take the CPU from it, in microseconds.
    #[clap(short = 'g', long, default_value = "100")]
    min_granularity_us: u64,

    /// Do not let a waking task borrow virtual time. By default it is queued at least
    /// --vtime-borrowing-us behind the clock, ahead of the tasks that stayed runnable, and on a
    /// CPU where it preempts the one that runs.
    #[clap(long)]
    no_vtime_borrowing: bool,

    /// How much a waking task borrows, in microseconds of service at nice 0.
    #[clap(long, default_value = "20000")]
    vtime_borrowing_us: u64,

    /// Maximum time (us) that a task can run on the CPUs of a worse tier before it is handed to
    /// a CPU of the best one, where the CPUs rank.
    ///
    /// A task that never sleeps keeps its CPU slice after slice. On a machine with big and
    /// little cores, CPU-bound tasks then stay where they started, and the ones on the little
    /// cores fall behind. Past this threshold, a task whose slice ends on a worse CPU swaps
    /// places with one that has run on CPUs of the best tier of its LLC for as long without
    /// sleeping, so that CPU-bound tasks take turns on the best CPUs.
    ///
    /// 0 = rotation disabled.
    #[clap(long, default_value = "0")]
    rotate_us: u64,

    /// Enable stats monitoring with the specified interval.
    #[clap(long)]
    stats: Option<f64>,

    /// Run in stats monitoring mode with the specified interval. Scheduler is not launched.
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

/// The order in which placement tries the CPUs, see --primary-domain.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Preference {
    Performance,
    Powersave,
    Turbo,
    Cores,
}

/// The preference --primary-domain names, if it names one, and whether it follows the power
/// profile.
fn preference(spec: &str, profile: PowerProfile) -> Option<(Preference, bool)> {
    match spec {
        "performance" => Some((Preference::Performance, false)),
        "powersave" => Some((Preference::Powersave, false)),
        "turbo" => Some((Preference::Turbo, false)),
        "cores" => Some((Preference::Cores, false)),
        "auto" => Some((
            if profile == PowerProfile::Powersave {
                Preference::Powersave
            } else {
                Preference::Performance
            },
            true,
        )),
        _ => None,
    }
}

/// The active power profile, from power-profiles-daemon where it runs.
fn power_profile() -> PowerProfile {
    let profile = fetch_power_profile(true);
    if profile == PowerProfile::Unknown {
        fetch_power_profile(false)
    } else {
        profile
    }
}

fn primary_domain(spec: &str, topo: &Topology) -> Result<Cpumask> {
    let mut mask = Cpumask::new();
    if spec == "all" || preference(spec, PowerProfile::Unknown).is_some() {
        for &cpu in topo.all_cpus.keys() {
            mask.set_cpu(cpu)?;
        }
    } else {
        for part in spec.split(',') {
            let part = part.trim();
            let (first, last) = match part.split_once('-') {
                Some((first, last)) => (first.trim().parse::<usize>()?, last.trim().parse()?),
                None => {
                    let cpu = part.parse::<usize>()?;
                    (cpu, cpu)
                }
            };
            if first > last || last >= MAX_CPUS {
                bail!("invalid primary CPU range: {part}");
            }
            for cpu in first..=last {
                if !topo.all_cpus.contains_key(&cpu) {
                    bail!("primary CPU {cpu} is not online");
                }
                mask.set_cpu(cpu)?;
            }
        }
    }
    if mask.iter().next().is_none() {
        bail!("the primary domain must contain an online CPU");
    }
    Ok(mask)
}

/// The CPUs of each domain, listed one domain after the other: what the BPF side iterates a
/// domain with, from its base for its length.
struct Domains {
    of_cpu: Vec<i32>,
    base: Vec<u32>,
    len: Vec<u32>,
    cpus: Vec<u16>,
}

impl Domains {
    /// Group the CPUs by `key`, numbering the domains densely in key order.
    fn new(topo: &Topology, key: impl Fn(&scx_utils::Cpu) -> usize) -> Self {
        let mut groups: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
        for cpu in topo.all_cpus.values() {
            groups.entry(key(cpu)).or_default().push(cpu.id);
        }
        let mut domains = Domains {
            of_cpu: vec![0; MAX_CPUS],
            base: vec![0; MAX_CPUS],
            len: vec![0; MAX_CPUS],
            cpus: Vec::with_capacity(MAX_CPUS),
        };
        for (dom, cpus) in groups.values().enumerate() {
            domains.base[dom] = domains.cpus.len() as u32;
            domains.len[dom] = cpus.len() as u32;
            for &cpu in cpus {
                domains.of_cpu[cpu] = dom as i32;
                domains.cpus.push(cpu as u16);
            }
        }
        domains.cpus.resize(MAX_CPUS, 0);
        domains
    }

    /// The bit of each CPU in the queued mask of the BPF side: the bits of each domain from a
    /// cache line of their own, or the CPU's number where the mask has too few lines for that.
    fn queued_bits(&self) -> Vec<u32> {
        let mut bits: Vec<u32> = (0..MAX_CPUS as u32).collect();
        let lens: Vec<usize> = self
            .len
            .iter()
            .take_while(|&&len| len > 0)
            .map(|&len| len as usize)
            .collect();
        let lines: usize = lens.iter().map(|len| len.div_ceil(LINE_BITS)).sum();
        if lines * LINE_BITS > QUEUED_BITS {
            return bits;
        }
        let mut line = 0;
        for (dom, &len) in lens.iter().enumerate() {
            let base = self.base[dom] as usize;
            for pos in 0..len {
                bits[self.cpus[base + pos] as usize] = (line * LINE_BITS + pos) as u32;
            }
            line += len.div_ceil(LINE_BITS);
        }
        bits
    }
}

struct Scheduler<'a> {
    skel: BpfSkel<'a>,
    struct_ops: Option<libbpf_rs::Link>,
    stats_server: StatsServer<(), Metrics>,
    _arenalib: ArenaLib,
    /// The power profile "auto" was resolved by, to restart when it changes.
    auto_profile: Option<PowerProfile>,
    user_restart: bool,
}

impl<'a> Scheduler<'a> {
    fn init(opts: &'a Opts, open_object: &'a mut MaybeUninit<OpenObject>) -> Result<Self> {
        try_set_rlimit_infinity();

        let topo = Topology::new().context("reading the CPU topology")?;
        let nr_cpus = *NR_CPU_IDS;
        if nr_cpus > MAX_CPUS {
            bail!("{} CPUs, at most {} are supported", nr_cpus, MAX_CPUS);
        }

        let spec = opts.primary_domain.as_deref().unwrap_or("all");
        let primary = primary_domain(spec, &topo).context("parsing the primary domain")?;
        let profile = if spec == "auto" {
            power_profile()
        } else {
            PowerProfile::Unknown
        };
        let (pref, auto) = preference(spec, profile).unwrap_or((Preference::Performance, false));

        info!(
            "{} {} {}",
            SCHEDULER_NAME,
            build_id::full_version(env!("CARGO_PKG_VERSION")),
            if topo.smt_enabled {
                "SMT on"
            } else {
                "SMT off"
            }
        );
        info!(
            "scheduler options: {}",
            std::env::args().collect::<Vec<_>>().join(" ")
        );

        let mut skel_builder = BpfSkelBuilder::default();
        skel_builder.obj_builder.debug(opts.verbose);
        let open_opts = opts.libbpf.clone().into_bpf_open_opts();
        let mut skel = scx_ops_open!(skel_builder, open_object, bpfland_ops, open_opts)?;

        skel.struct_ops.bpfland_ops_mut().exit_dump_len = opts.exit_dump_len;

        let rodata = skel.maps.rodata_data.as_mut().unwrap();
        rodata.slice_ns = opts.slice_us * 1000;
        rodata.lag_bound_ns = opts.lag_bound_us * 1000;
        rodata.min_granularity_ns = opts.min_granularity_us * 1000;
        rodata.vtime_borrowing_ns = opts.vtime_borrowing_us * 1000;
        rodata.rotate_ns = opts.rotate_us * 1000;
        rodata.no_asym_packing = opts.no_asym_packing;
        rodata.no_preempt = opts.no_preempt;
        rodata.no_eligibility = opts.no_eligibility;
        rodata.no_vlag = opts.no_vlag;
        rodata.no_vtime_borrowing = opts.no_vtime_borrowing;
        rodata.stats_enabled = opts.stats.is_some();
        rodata.smt_enabled = topo.smt_enabled;
        rodata.nr_cpus = nr_cpus as u32;
        rodata.primary_all = primary.iter().count() == topo.all_cpus.len();
        for cpu in primary.iter() {
            rodata.primary_cpus[cpu] = true;
        }
        if !rodata.primary_all {
            info!("Primary CPUs: {} (no spillover)", primary.to_cpulist());
        }

        // The topology: the LLC, node and core of each CPU, and the CPUs of each.
        let llcs = Domains::new(&topo, |cpu| cpu.llc_id);
        let nodes = Domains::new(&topo, |cpu| cpu.node_id);
        let cores = Domains::new(&topo, |cpu| cpu.core_id);
        let queued_bits = llcs.queued_bits();
        for i in 0..MAX_CPUS {
            rodata.cpu_llc[i] = llcs.of_cpu[i];
            rodata.cpu_node[i] = nodes.of_cpu[i];
            rodata.cpu_core[i] = cores.of_cpu[i];
            rodata.llc_base[i] = llcs.base[i];
            rodata.llc_len[i] = llcs.len[i];
            rodata.node_base[i] = nodes.base[i];
            rodata.node_len[i] = nodes.len[i];
            rodata.core_base[i] = cores.base[i];
            rodata.core_len[i] = cores.len[i];
            rodata.llc_cpus[i] = llcs.cpus[i];
            rodata.node_cpus[i] = nodes.cpus[i];
            rodata.core_cpus[i] = cores.cpus[i];
            rodata.cpu_queued_bit[i] = queued_bits[i];
        }

        skel.struct_ops.bpfland_ops_mut().flags = *compat::SCX_OPS_ENQ_LAST
            | *compat::SCX_OPS_ENQ_MIGRATION_DISABLED
            | *compat::SCX_OPS_ALLOW_QUEUED_WAKEUP
            | *compat::SCX_OPS_KEEP_BUILTIN_IDLE
            | *compat::SCX_OPS_TID_TO_TASK;
        // Find queued tasks by their scx tid where the kernel can, which reads as zero on a
        // kernel without it.
        skel.maps.rodata_data.as_mut().unwrap().tid_lookup = *compat::SCX_OPS_TID_TO_TASK != 0;
        // PID lookup can lose unhashed exiting tasks. Let the kernel dispatch them directly
        // unless TID lookup can find them reliably.
        if *compat::SCX_OPS_TID_TO_TASK != 0 {
            skel.struct_ops.bpfland_ops_mut().flags |= *compat::SCX_OPS_ENQ_EXITING;
        }
        info!(
            "scheduler flags: {:#x}",
            skel.struct_ops.bpfland_ops_mut().flags
        );

        let mut skel = scx_ops_load!(skel, bpfland_ops, uei)?;

        Self::init_place_tiers(&mut skel, &topo, &llcs, pref)?;

        // Watch the BPF streams: an arena fault is reported and fatal rather than silently fixed
        // up.
        let arenalib =
            ArenaLib::start(skel.object_mut()).context("starting arena userspace services")?;

        let struct_ops = Some(scx_ops_attach!(skel, bpfland_ops)?);
        let stats_server = StatsServer::new(stats::server_data()).launch()?;

        info!("{} attached", SCHEDULER_NAME);

        Ok(Self {
            skel,
            struct_ops,
            stats_server,
            _arenalib: arenalib,
            auto_profile: auto.then_some(profile),
            user_restart: false,
        })
    }

    /// Rank the CPUs, after load and before attach: tier 0 is the one placement tries first. The
    /// kernel's packing priorities rank them where every CPU packs asymmetrically,
    /// SD_ASYM_PACKING, and the priorities differ. Otherwise their capacities rank them where
    /// those differ. @pref then orders the tiers, see --primary-domain.
    fn init_place_tiers(
        skel: &mut BpfSkel<'_>,
        topo: &Topology,
        llcs: &Domains,
        pref: Preference,
    ) -> Result<()> {
        let (mut tiers, source) = match Self::packing_tiers(skel, topo)? {
            Some(tiers) => (tiers, "packing priority"),
            None => match Self::capacity_tiers(topo) {
                Some(tiers) => (tiers, "capacity"),
                None => (topo.all_cpus.keys().map(|&cpu| (cpu, 0)).collect(), ""),
            },
        };
        let mut nr_tiers = tiers.iter().map(|&(_, tier)| tier + 1).max().unwrap_or(1);
        match pref {
            Preference::Performance => {}
            // The slowest first.
            Preference::Powersave => {
                for (_, tier) in tiers.iter_mut() {
                    *tier = nr_tiers - 1 - *tier;
                }
            }
            // The CPUs that boost highest ahead of the tier they are in.
            Preference::Turbo if nr_tiers < MAX_TIERS => {
                let turbo = |cpu: usize| {
                    matches!(
                        topo.all_cpus.get(&cpu).map(|cpu| &cpu.core_type),
                        Some(CoreType::Big { turbo: true })
                    )
                };
                if tiers.iter().any(|&(cpu, _)| turbo(cpu)) {
                    for (cpu, tier) in tiers.iter_mut() {
                        if !turbo(*cpu) {
                            *tier += 1;
                        }
                    }
                }
            }
            Preference::Turbo => {}
            // Within each tier, the first thread of every core ahead of its siblings.
            Preference::Cores => {
                let first = |cpu: usize| {
                    topo.all_cores.values().any(|core| {
                        core.cpus.keys().find(|cpu| topo.all_cpus.contains_key(cpu)) == Some(&cpu)
                    })
                };
                for (cpu, tier) in tiers.iter_mut() {
                    *tier = (*tier * 2 + u32::from(!first(*cpu))).min(MAX_TIERS - 1);
                }
            }
        }
        // Number the tiers densely: one that the order left empty is dropped.
        let mut levels: Vec<u32> = tiers.iter().map(|&(_, tier)| tier).collect();
        levels.sort_unstable();
        levels.dedup();
        for (_, tier) in tiers.iter_mut() {
            *tier = levels.iter().position(|&level| level == *tier).unwrap_or(0) as u32;
        }
        nr_tiers = levels.len().max(1) as u32;

        let bss = skel.maps.bss_data.as_mut().unwrap();
        bss.cpus_ranked = nr_tiers > 1;
        bss.nr_place_tiers = nr_tiers;
        for llc in 0..MAX_CPUS {
            bss.llc_place_tier[llc] = u32::MAX;
        }
        for &(cpu, tier) in &tiers {
            bss.place_tier[cpu] = tier;
            let llc = llcs.of_cpu[cpu] as usize;
            bss.llc_place_tier[llc] = bss.llc_place_tier[llc].min(tier);
        }
        if nr_tiers > 1 {
            info!(
                "CPU ranking: by {}, {} tiers, {} order",
                source,
                nr_tiers,
                format!("{pref:?}").to_lowercase()
            );
        } else {
            info!("CPU ranking: off");
        }

        Ok(())
    }

    /// Each CPU's tier by the kernel's packing priority, highest first, or None if the kernel
    /// does not rank the CPUs.
    fn packing_tiers(skel: &mut BpfSkel<'_>, topo: &Topology) -> Result<Option<Vec<(usize, u32)>>> {
        let mut priorities = Vec::new();
        let mut all_pack = true;
        for cpu in topo.all_cpus.values() {
            let mut args = cpu_priority_args {
                cpu: cpu.id as u64,
                priority: 0,
                asym_packing: 0,
            };
            let input = ProgramInput {
                context_in: Some(unsafe {
                    std::slice::from_raw_parts_mut(
                        &mut args as *mut _ as *mut u8,
                        std::mem::size_of_val(&args),
                    )
                }),
                ..Default::default()
            };
            let out = skel
                .progs
                .bpfland_cpu_priority
                .test_run(input)
                .context("running bpfland_cpu_priority")?;
            if out.return_value != 0 {
                bail!("bpfland_cpu_priority failed: {}", out.return_value);
            }
            all_pack &= args.asym_packing != 0;
            priorities.push((cpu.id, args.priority));
        }
        let distinct = priorities.windows(2).any(|pair| pair[0].1 != pair[1].1);
        if !all_pack || !distinct {
            return Ok(None);
        }

        // The distinct priorities, highest first: a CPU's tier is the index of its own.
        let mut levels: Vec<i64> = priorities.iter().map(|&(_, prio)| prio).collect();
        levels.sort_unstable_by(|a, b| b.cmp(a));
        levels.dedup();
        Ok(Some(
            priorities
                .iter()
                .map(|&(cpu, prio)| {
                    let tier = levels.iter().position(|&level| level == prio).unwrap_or(0);
                    (cpu, (tier as u32).min(MAX_TIERS - 1))
                })
                .collect(),
        ))
    }

    /// Each CPU's tier by the capacity the kernel gives it, largest first, or None if the
    /// capacities are not known or do not differ. A new tier begins at a capacity more than
    /// CAPACITY_TOLERANCE_PCT below the largest of the tier before.
    fn capacity_tiers(topo: &Topology) -> Option<Vec<(usize, u32)>> {
        let mut capacities: Vec<(usize, usize)> = topo
            .all_cpus
            .values()
            .map(|cpu| Some((cpu.id, cpu.kernel_cpu_capacity?)))
            .collect::<Option<_>>()?;
        capacities.sort_by_key(|&(cpu, capacity)| (std::cmp::Reverse(capacity), cpu));
        let mut anchor = capacities.first()?.1;
        let mut tier = 0;
        let tiers: Vec<(usize, u32)> = capacities
            .iter()
            .map(|&(cpu, capacity)| {
                if capacity * 100 < anchor * (100 - CAPACITY_TOLERANCE_PCT) {
                    tier = (tier + 1).min(MAX_TIERS - 1);
                    anchor = capacity;
                }
                (cpu, tier)
            })
            .collect();
        (tier > 0).then_some(tiers)
    }

    fn get_metrics(&self) -> Metrics {
        let mut metrics = Metrics::default();
        let key = 0_u32.to_ne_bytes();
        if let Ok(Some(values)) = self
            .skel
            .maps
            .counters_stor
            .lookup_percpu(&key, libbpf_rs::MapFlags::ANY)
        {
            for value in values {
                if value.len() < std::mem::size_of::<counters>() {
                    continue;
                }
                let c: counters =
                    unsafe { std::ptr::read_unaligned(value.as_ptr() as *const counters) };
                metrics.nr_direct += c.direct;
                metrics.nr_borrowed += c.borrowed;
                metrics.nr_moved += c.moved;
                metrics.nr_missed += c.missed;
                metrics.nr_preempts += c.preempts;
                metrics.nr_steals += c.steals;
                metrics.nr_balanced += c.balanced;
                metrics.nr_rotated += c.rotated;
            }
        }
        metrics
    }

    pub fn exited(&mut self) -> bool {
        uei_exited!(&self.skel, uei)
    }

    fn run(&mut self, shutdown: Arc<AtomicBool>) -> Result<UserExitInfo> {
        let (res_ch, req_ch) = self.stats_server.channels();
        while !shutdown.load(Ordering::Relaxed) && !self.exited() {
            // "auto" follows the power profile: a new one ranks the CPUs again.
            if self
                .auto_profile
                .is_some_and(|profile| power_profile() != profile)
            {
                info!("power profile changed, restarting");
                self.user_restart = true;
                break;
            }
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

    let release =
        std::fs::read_to_string("/proc/sys/kernel/osrelease").context("reading kernel release")?;
    let mut fields = release.trim().split(['.', '-']);
    let major: u32 = fields
        .next()
        .context("missing kernel major version")?
        .parse()?;
    let minor: u32 = fields
        .next()
        .context("missing kernel minor version")?
        .parse()?;
    if (major, minor) < (6, 16) {
        bail!(
            "scx_bpfland requires Linux 6.16 or newer (running {})",
            release.trim()
        );
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
            if sched.user_restart {
                continue;
            }
            break;
        }
    }

    Ok(())
}
