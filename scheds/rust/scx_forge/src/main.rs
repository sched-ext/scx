// SPDX-License-Identifier: GPL-2.0
//
// Copyright (c) 2026 Andrea Righi <arighi@nvidia.com>

// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

mod bpf_skel;
pub use bpf_skel::*;
pub mod bpf_intf;
pub use bpf_intf::*;

mod stats;
use std::collections::HashSet;
use std::ffi::c_int;
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
use libbpf_rs::MapCore;
use libbpf_rs::MapFlags;
use libbpf_rs::OpenObject;
use libbpf_rs::ProgramInput;
use log::warn;
use log::{debug, info};
use scx_stats::prelude::*;
use scx_utils::build_id;
use scx_utils::compat;
use scx_utils::get_primary_cpus;
use scx_utils::libbpf_clap_opts::LibbpfOpts;
use scx_utils::perf::parse_perf_event;
use scx_utils::perf::setup_perf_events;
use scx_utils::perf::PerfEventSpec;
use scx_utils::scx_ops_attach;
use scx_utils::scx_ops_load;
use scx_utils::scx_ops_open;
use scx_utils::try_set_rlimit_infinity;
use scx_utils::uei_exited;
use scx_utils::uei_report;
use scx_utils::CoreType;
use scx_utils::Cpumask;
use scx_utils::Powermode;
use scx_utils::Topology;
use scx_utils::UserExitInfo;
use scx_utils::NR_CPUS_POSSIBLE;
use scx_utils::NR_CPU_IDS;
use stats::Metrics;

const SCHEDULER_NAME: &str = "scx_forge";
const FORGE_MAX_TOPO_DOMAINS_USIZE: usize = 4096;
const FORGE_MAX_TOPO_DISTANCES_USIZE: usize = 65536;
const FORGE_TOPO_CPUMASK_WORDS_USIZE: usize = FORGE_MAX_TOPO_DOMAINS_USIZE / 64;

/// Topology level of the user-created DSQs. Each variant maps to a value of
/// `enum topology_dsq_type` from src/bpf/intf.h (the single source of truth),
/// so the two cannot drift.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
enum DsqTopology {
    /// Per-CPU DSQs.
    Cpu,
    /// Per-LLC DSQs.
    Llc,
    /// Per-node DSQs.
    Node,
    /// Single shared DSQ.
    Global,
}

impl DsqTopology {
    /// Return the matching `enum topology_dsq_type` value from the BPF intf.
    fn to_bpf(self) -> u32 {
        match self {
            DsqTopology::Cpu => bpf_intf::topology_dsq_type_TOPO_DSQ_CPU,
            DsqTopology::Llc => bpf_intf::topology_dsq_type_TOPO_DSQ_LLC,
            DsqTopology::Node => bpf_intf::topology_dsq_type_TOPO_DSQ_NODE,
            DsqTopology::Global => bpf_intf::topology_dsq_type_TOPO_DSQ_GLOBAL,
        }
    }
}

/// Ordering algorithm for the queue key of vtime-ordered DSQs. Each variant
/// maps to a value of `enum ordering_type` from src/bpf/intf.h.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
enum QueueOrdering {
    /// Virtual-runtime (CFS-like) fair ordering.
    Vruntime,
    /// Earliest-deadline-first (weighted).
    Deadline,
    /// First-in-first-out (by enqueue time).
    Fifo,
}

impl QueueOrdering {
    /// Return the matching `enum ordering_type` value from the BPF intf.
    fn to_bpf(self) -> u32 {
        match self {
            QueueOrdering::Vruntime => bpf_intf::ordering_type_ORDER_VRUNTIME,
            QueueOrdering::Deadline => bpf_intf::ordering_type_ORDER_DEADLINE,
            QueueOrdering::Fifo => bpf_intf::ordering_type_ORDER_FIFO,
        }
    }
}

/// Wakeup idle-CPU selection policy. Each variant maps to a value of
/// `enum idle_policy_type` from src/bpf/intf.h.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
enum IdlePolicy {
    /// Capacity-aware waker preference (performance oriented).
    Capacity,
    /// Keep the wakee on its previous CPU (cache affinity).
    Wakee,
    /// Move the wakee toward the waker CPU (wakeup locality).
    Waker,
    /// Move the wakee toward the waker CPU only when both are threads of the
    /// same task (multi-thread locality).
    Thread,
    /// Keep the wakee on its previous CPU, even if system is busy (tail-latency).
    Sticky,
}

impl IdlePolicy {
    /// Return the matching `enum idle_policy_type` value from the BPF intf.
    fn to_bpf(self) -> u32 {
        match self {
            IdlePolicy::Capacity => bpf_intf::idle_policy_type_IDLE_CAPACITY,
            IdlePolicy::Wakee => bpf_intf::idle_policy_type_IDLE_WAKEE,
            IdlePolicy::Waker => bpf_intf::idle_policy_type_IDLE_WAKER,
            IdlePolicy::Thread => bpf_intf::idle_policy_type_IDLE_THREAD,
            IdlePolicy::Sticky => bpf_intf::idle_policy_type_IDLE_STICKY,
        }
    }
}

#[derive(Debug, Parser)]
struct Opts {
    /// Maximum scheduling slice duration in microseconds.
    #[clap(short = 's', long, default_value = "1000")]
    slice_us: u64,

    /// Topology level of the user-created DSQs.
    #[clap(long, value_enum, default_value_t = DsqTopology::Global)]
    dsq_topology: DsqTopology,

    /// Ordering algorithm for the queue key of vtime-ordered DSQs.
    #[clap(long, value_enum, default_value_t = QueueOrdering::Vruntime)]
    ordering: QueueOrdering,

    /// Wakeup idle-CPU selection policy.
    #[clap(long, value_enum, default_value_t = IdlePolicy::Wakee)]
    idle_policy: IdlePolicy,

    /// Disable synchronous-wakeup bias during idle CPU selection.
    #[clap(short = 'w', long, action = clap::ArgAction::SetTrue)]
    no_wake_sync: bool,

    /// Specifies a list of CPUs to prioritize.
    ///
    /// Accepts a comma-separated list of CPUs or ranges (i.e., 0-3,12-15) or the following special
    /// keywords:
    ///
    /// "performance" = automatically detect and prioritize the fastest CPUs,
    /// "powersave" = automatically detect and prioritize the slowest CPUs,
    /// "all" = all CPUs assigned to the primary domain.
    ///
    /// By default "all" CPUs are used.
    #[clap(short = 'm', long)]
    primary_domain: Option<String>,

    /// Enable preempting the running task when an eligible sleeper wakes up on
    /// its CPU.
    #[clap(short = 'p', long, action = clap::ArgAction::SetTrue)]
    enable_preemption: bool,

    /// Hardware/software perf event to monitor for the event-heavy migration
    /// hint (0x0 = disabled). Accepts hex (0xN) or a symbolic name (e.g.
    /// cache-misses, LLC-load-misses, page-faults, branch-misses).
    #[clap(short = 'e', long, default_value = "0x0", value_parser = parse_perf_event)]
    perf_config: PerfEventSpec,

    /// Threshold (events accumulated over a slice) above which a task is
    /// classified as event-heavy and biased toward migrating to an idle CPU.
    /// The behavior is gated on --perf-config.
    #[clap(short = 'E', long, default_value = "1000")]
    perf_threshold: u64,

    /// Sticky perf event (0x0 = disabled). When a task exceeds
    /// --perf-sticky-threshold for this event, keep it on its previous CPU.
    /// Accepts hex (0xN) or a symbolic name.
    #[clap(short = 'y', long, default_value = "0x0", value_parser = parse_perf_event)]
    perf_sticky: PerfEventSpec,

    /// Sticky perf threshold; a task is kept on its previous CPU when its count
    /// for the --perf-sticky event exceeds this. The behavior is gated on
    /// --perf-sticky.
    #[clap(short = 'Y', long, default_value = "1000")]
    perf_sticky_threshold: u64,

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

    /// Enable BPF debugging via /sys/kernel/tracing/trace_pipe.
    #[clap(short = 'd', long, action = clap::ArgAction::SetTrue)]
    debug: bool,

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

pub fn parse_cpu_list(optarg: &str) -> Result<Vec<usize>, String> {
    let mut cpus = Vec::new();
    let mut seen = HashSet::new();

    // Handle special keywords.
    if let Some(mode) = match optarg {
        "powersave" => Some(Powermode::Powersave),
        "performance" => Some(Powermode::Performance),
        "all" => Some(Powermode::Any),
        _ => None,
    } {
        return get_primary_cpus(mode).map_err(|e| e.to_string());
    }

    // Validate input characters.
    if optarg
        .chars()
        .any(|c| !c.is_ascii_digit() && c != '-' && c != ',' && !c.is_whitespace())
    {
        return Err("Invalid character in CPU list".to_string());
    }

    let cleaned = optarg.replace(' ', "\t");

    for token in cleaned.split(',') {
        let token = token.trim_matches(|c: char| c.is_whitespace());

        if token.is_empty() {
            continue;
        }

        if let Some((start_str, end_str)) = token.split_once('-') {
            let start = start_str
                .trim()
                .parse::<usize>()
                .map_err(|_| "Invalid range start")?;
            let end = end_str
                .trim()
                .parse::<usize>()
                .map_err(|_| "Invalid range end")?;

            if start > end {
                return Err(format!("Invalid CPU range: {}-{}", start, end));
            }

            for i in start..=end {
                if cpus.len() >= *NR_CPU_IDS {
                    return Err(format!("Too many CPUs specified (max {})", *NR_CPU_IDS));
                }
                if seen.insert(i) {
                    cpus.push(i);
                }
            }
        } else {
            let cpu = token
                .parse::<usize>()
                .map_err(|_| format!("Invalid CPU: {}", token))?;
            if cpus.len() >= *NR_CPU_IDS {
                return Err(format!("Too many CPUs specified (max {})", *NR_CPU_IDS));
            }
            if seen.insert(cpu) {
                cpus.push(cpu);
            }
        }
    }

    Ok(cpus)
}

struct Scheduler<'a> {
    skel: BpfSkel<'a>,
    struct_ops: Option<libbpf_rs::Link>,
    stats_server: StatsServer<(), Metrics>,
    user_restart: bool,
}

impl<'a> Scheduler<'a> {
    fn init(opts: &'a Opts, open_object: &'a mut MaybeUninit<OpenObject>) -> Result<Self> {
        try_set_rlimit_infinity();

        info!(
            "{} {}",
            SCHEDULER_NAME,
            build_id::full_version(env!("CARGO_PKG_VERSION")),
        );

        // Initialize CPU topology.
        let topo = Topology::new().unwrap();
        if *NR_CPU_IDS > FORGE_TOPO_CPUMASK_WORDS_USIZE * 64 {
            bail!(
                "CPU ID space {} exceeds scx_forge topology map limit {}",
                *NR_CPU_IDS,
                FORGE_TOPO_CPUMASK_WORDS_USIZE * 64
            );
        }

        // Check host topology to determine if we need to enable SMT capabilities.
        let smt_enabled = topo.smt_enabled;
        if !smt_enabled {
            info!("Disabling SMT optimizations");
        }

        // Determine the amount of non-empty NUMA nodes in the system.
        let nr_nodes = topo
            .nodes
            .values()
            .filter(|node| !node.all_cpus.is_empty())
            .count();
        info!("NUMA nodes: {}", nr_nodes);

        // Print command line.
        info!(
            "scheduler options: {}",
            std::env::args().collect::<Vec<_>>().join(" ")
        );

        // Initialize BPF connector.
        let mut skel_builder = BpfSkelBuilder::default();
        skel_builder.obj_builder.debug(opts.verbose);
        let open_opts = opts.libbpf.clone().into_bpf_open_opts();
        let mut skel = scx_ops_open!(skel_builder, open_object, forge_ops, open_opts)?;

        if !compat::struct_has_field("sched_ext_ops", "cgroup_init").unwrap_or(false) {
            warn!("kernel doesn't support ops.cgroup_init(), disabling");
            skel.struct_ops.forge_ops_mut().cgroup_init = std::ptr::null_mut();
        }
        if !compat::struct_has_field("sched_ext_ops", "cgroup_exit").unwrap_or(false) {
            warn!("kernel doesn't support ops.cgroup_exit(), disabling");
            skel.struct_ops.forge_ops_mut().cgroup_exit = std::ptr::null_mut();
        }
        if !compat::struct_has_field("sched_ext_ops", "cgroup_set_weight").unwrap_or(false) {
            warn!("kernel doesn't support ops.cgroup_set_weight(), disabling");
            skel.struct_ops.forge_ops_mut().cgroup_set_weight = std::ptr::null_mut();
        }
        if !compat::struct_has_field("sched_ext_ops", "cgroup_move").unwrap_or(false) {
            warn!("kernel doesn't support ops.cgroup_move(), disabling");
            skel.struct_ops.forge_ops_mut().cgroup_move = std::ptr::null_mut();
        }

        skel.struct_ops.forge_ops_mut().exit_dump_len = opts.exit_dump_len;

        // Override default BPF scheduling parameters.
        let rodata = skel.maps.rodata_data.as_mut().unwrap();
        rodata.slice_ns = opts.slice_us * 1000;
        rodata.debug = opts.debug;
        rodata.smt_enabled = smt_enabled;
        rodata.topo_dsq = opts.dsq_topology.to_bpf();
        rodata.ordering = opts.ordering.to_bpf();
        rodata.idle_policy = opts.idle_policy.to_bpf();
        rodata.no_wake_sync = opts.no_wake_sync;
        rodata.preemption = opts.enable_preemption;

        // PMU event monitoring. The event ids select which counters the BPF
        // side reads; the thresholds (0 = behavior disabled, tracking only)
        // gate the event-heavy migration and sticky placement hints.
        rodata.perf_config = opts.perf_config.event_id;
        rodata.perf_threshold = opts.perf_threshold;
        rodata.perf_sticky = opts.perf_sticky.event_id;
        rodata.perf_sticky_threshold = opts.perf_sticky_threshold;

        // Define the primary scheduling domain.
        let primary_cpus = if let Some(ref domain) = opts.primary_domain {
            match parse_cpu_list(domain) {
                Ok(cpus) => cpus,
                Err(e) => bail!("Error parsing primary domain: {}", e),
            }
        } else {
            (0..*NR_CPU_IDS).collect()
        };
        if primary_cpus.len() < *NR_CPU_IDS {
            info!("Primary CPUs: {:?}", primary_cpus);
            rodata.primary_all = false;
        } else {
            rodata.primary_all = true;
        }

        // Normalize CPU capacities to 1..1024 so the highest capacity is always 1024.
        let cpus: Vec<_> = topo.all_cpus.values().collect();
        let max_cap = cpus
            .iter()
            .map(|cpu| cpu.cpu_capacity)
            .max()
            .unwrap_or(1)
            .max(1);
        let cpu_capacities: std::collections::HashMap<_, _> = cpus
            .iter()
            .map(|cpu| {
                let normalized = (cpu.cpu_capacity * 1024 / max_cap).clamp(1, 1024);
                (cpu.id, normalized as u64)
            })
            .collect();
        rodata.all_cpus_same_capacity = cpus.iter().all(|cpu| cpu.cpu_capacity == max_cap);

        // Build dense LLC index for topology lookup maps.
        let mut llc_id_to_dense = std::collections::HashMap::new();
        for (dense_id, (_, llc)) in topo.all_llcs.iter().enumerate() {
            llc_id_to_dense.insert(llc.id, dense_id);
        }

        // Set scheduler flags.
        skel.struct_ops.forge_ops_mut().flags = *compat::SCX_OPS_ENQ_EXITING
            | *compat::SCX_OPS_ENQ_LAST
            | *compat::SCX_OPS_ENQ_MIGRATION_DISABLED
            | *compat::SCX_OPS_ALLOW_QUEUED_WAKEUP
            | *compat::SCX_OPS_BUILTIN_IDLE_PER_NODE;
        info!(
            "scheduler flags: {:#x}",
            skel.struct_ops.forge_ops_mut().flags
        );

        // Load the BPF program for validation.
        let mut skel = scx_ops_load!(skel, forge_ops, uei)?;

        Self::init_topology_maps(
            &mut skel,
            &topo,
            &llc_id_to_dense,
            &cpu_capacities,
            smt_enabled,
        )?;

        // Initialize SMT sibling cpumasks (populate per-CPU smt via enable_sibling_cpu prog).
        if smt_enabled {
            Self::init_smt_domains(&mut skel, &topo)?;
        }

        // Enable primary scheduling domain, if defined.
        if primary_cpus.len() < *NR_CPU_IDS {
            for cpu in primary_cpus {
                if let Err(err) = Self::enable_primary_cpu(&mut skel, cpu as i32) {
                    bail!("failed to add CPU {} to primary domain: error {}", cpu, err);
                }
            }
        }

        // Configure CPU topology mappings (must be done after skeleton is loaded).
        for cpu in topo.all_cpus.values() {
            let dense_llc = llc_id_to_dense.get(&cpu.llc_id).copied().unwrap_or(0);
            if opts.verbose {
                let cap = cpu_capacities.get(&cpu.id).copied().unwrap_or(0);
                info!(
                    "CPU{} -> node{} LLC{} (cpu capacity: {})",
                    cpu.id, cpu.node_id, dense_llc, cap
                );
            }
            skel.maps.cpu_node_map.update(
                &(cpu.id as u32).to_ne_bytes(),
                &(cpu.node_id as u32).to_ne_bytes(),
                MapFlags::ANY,
            )?;
            skel.maps.cpu_llc_map.update(
                &(cpu.id as u32).to_ne_bytes(),
                &(dense_llc as u32).to_ne_bytes(),
                MapFlags::ANY,
            )?;
        }

        // Set up PMU counters on every CPU (must be done after load so the
        // scx_pmu_map fd is available). Counter indices match the BPF install
        // order: migration event first (0), then sticky (1); when only the
        // sticky event is used it takes index 0.
        if opts.perf_config.event_id > 0 || opts.perf_sticky.event_id > 0 {
            let nr_cpus = *NR_CPU_IDS;
            info!("Setting up performance counters for {} CPUs...", nr_cpus);
            let sticky_counter_idx = if opts.perf_config.event_id > 0 { 1 } else { 0 };
            for cpu in 0..nr_cpus {
                if opts.perf_config.event_id > 0 {
                    setup_perf_events(&skel.maps.scx_pmu_map, cpu as i32, &opts.perf_config, 0)
                        .with_context(|| {
                            format!(
                                "setting up perf event '{}' on CPU {}",
                                opts.perf_config.display_name, cpu
                            )
                        })?;
                }
                if opts.perf_sticky.event_id > 0 {
                    setup_perf_events(
                        &skel.maps.scx_pmu_map,
                        cpu as i32,
                        &opts.perf_sticky,
                        sticky_counter_idx,
                    )
                    .with_context(|| {
                        format!(
                            "setting up sticky perf event '{}' on CPU {}",
                            opts.perf_sticky.display_name, cpu
                        )
                    })?;
                }
            }
            info!("Performance counters configured for all CPUs");
        }

        info!("{SCHEDULER_NAME} can be used with scx-forge-agent for policy optimization");

        // Attach the scheduler.
        let struct_ops = Some(scx_ops_attach!(skel, forge_ops, false)?);
        let stats_server = StatsServer::new(stats::server_data()).launch()?;

        Ok(Self {
            skel,
            struct_ops,
            stats_server,
            user_restart: false,
        })
    }

    fn bytes_of<T>(value: &T) -> &[u8] {
        unsafe {
            std::slice::from_raw_parts(value as *const T as *const u8, std::mem::size_of::<T>())
        }
    }

    fn topo_core_type(core_type: &CoreType) -> u32 {
        match core_type {
            CoreType::Big { turbo: true } => 1,
            CoreType::Big { turbo: false } => 0,
            CoreType::Little => 2,
        }
    }

    fn topo_cpumask(mask: &Cpumask) -> Result<forge_topo_cpumask> {
        let raw = mask.as_raw_slice();
        if raw.len() > FORGE_TOPO_CPUMASK_WORDS_USIZE {
            bail!(
                "topology cpumask uses {} words, but scx_forge supports {}",
                raw.len(),
                FORGE_TOPO_CPUMASK_WORDS_USIZE
            );
        }

        let mut topo_mask: forge_topo_cpumask = unsafe { std::mem::zeroed() };
        topo_mask.bits[..raw.len()].copy_from_slice(raw);
        Ok(topo_mask)
    }

    fn init_topology_maps(
        skel: &mut BpfSkel<'_>,
        topo: &Topology,
        llc_id_to_dense: &std::collections::HashMap<usize, usize>,
        cpu_capacities: &std::collections::HashMap<usize, u64>,
        smt_enabled: bool,
    ) -> Result<()> {
        if topo.all_cpus.len() > FORGE_MAX_TOPO_DOMAINS_USIZE
            || topo.all_cores.len() > FORGE_MAX_TOPO_DOMAINS_USIZE
            || topo.all_llcs.len() > FORGE_MAX_TOPO_DOMAINS_USIZE
            || topo.nodes.len() > FORGE_MAX_TOPO_DOMAINS_USIZE
        {
            bail!(
                "topology exceeds scx_forge map limits: cpus={} cores={} llcs={} nodes={} max={}",
                topo.all_cpus.len(),
                topo.all_cores.len(),
                topo.all_llcs.len(),
                topo.nodes.len(),
                FORGE_MAX_TOPO_DOMAINS_USIZE
            );
        }

        let nr_distances = topo
            .nodes
            .values()
            .map(|node| node.distance.len())
            .sum::<usize>();
        if nr_distances > FORGE_MAX_TOPO_DISTANCES_USIZE {
            bail!(
                "NUMA distance entries {} exceed scx_forge map limit {}",
                nr_distances,
                FORGE_MAX_TOPO_DISTANCES_USIZE
            );
        }

        let mut topo_info: forge_topology = unsafe { std::mem::zeroed() };
        topo_info.nr_cpu_ids = *NR_CPU_IDS as u32;
        topo_info.nr_possible_cpus = *NR_CPUS_POSSIBLE as u32;
        topo_info.nr_online_cpus = topo.all_cpus.len() as u32;
        topo_info.nr_nodes = topo.nodes.len() as u32;
        topo_info.nr_llcs = topo.all_llcs.len() as u32;
        topo_info.nr_cores = topo.all_cores.len() as u32;
        topo_info.nr_cpus = topo.all_cpus.len() as u32;
        topo_info.smt_enabled = smt_enabled as u8;
        topo_info.span = Self::topo_cpumask(&topo.span)?;
        skel.maps.topo_info_map.update(
            &0u32.to_ne_bytes(),
            Self::bytes_of(&topo_info),
            MapFlags::ANY,
        )?;

        for (idx, cpu_id) in topo.all_cpus.keys().enumerate() {
            skel.maps.topo_cpu_ids.update(
                &(idx as u32).to_ne_bytes(),
                &(*cpu_id as u32).to_ne_bytes(),
                MapFlags::ANY,
            )?;
        }
        for (idx, core_id) in topo.all_cores.keys().enumerate() {
            skel.maps.topo_core_ids.update(
                &(idx as u32).to_ne_bytes(),
                &(*core_id as u32).to_ne_bytes(),
                MapFlags::ANY,
            )?;
        }
        for (idx, llc_id) in topo.all_llcs.keys().enumerate() {
            skel.maps.topo_llc_ids.update(
                &(idx as u32).to_ne_bytes(),
                &(*llc_id as u32).to_ne_bytes(),
                MapFlags::ANY,
            )?;
        }
        for (idx, node_id) in topo.nodes.keys().enumerate() {
            skel.maps.topo_node_ids.update(
                &(idx as u32).to_ne_bytes(),
                &(*node_id as u32).to_ne_bytes(),
                MapFlags::ANY,
            )?;
        }

        for cpu in topo.all_cpus.values() {
            let dense_llc = llc_id_to_dense.get(&cpu.llc_id).copied().unwrap_or(0);
            let mut topo_cpu: forge_topo_cpu = unsafe { std::mem::zeroed() };
            topo_cpu.id = cpu.id as u32;
            topo_cpu.core_id = cpu.core_id as u32;
            topo_cpu.llc_id = cpu.llc_id as u32;
            topo_cpu.llc_dense_id = dense_llc as u32;
            topo_cpu.node_id = cpu.node_id as u32;
            topo_cpu.package_id = cpu.package_id as u32;
            topo_cpu.cluster_id = cpu.cluster_id as i32;
            topo_cpu.l2_id = cpu.l2_id as u32;
            topo_cpu.l3_id = cpu.l3_id as u32;
            topo_cpu.smt_level = cpu.smt_level as u32;
            topo_cpu.core_type = Self::topo_core_type(&cpu.core_type);
            topo_cpu.min_freq = cpu.min_freq as u64;
            topo_cpu.max_freq = cpu.max_freq as u64;
            topo_cpu.base_freq = cpu.base_freq as u64;
            topo_cpu.cpu_capacity = cpu_capacities.get(&cpu.id).copied().unwrap_or(1);
            topo_cpu.pm_qos_resume_latency_us = cpu.pm_qos_resume_latency_us as u64;
            topo_cpu.trans_lat_ns = cpu.trans_lat_ns as u64;
            topo_cpu.cache_size = cpu.cache_size as u64;
            skel.maps.topo_cpu_map.update(
                &(cpu.id as u32).to_ne_bytes(),
                Self::bytes_of(&topo_cpu),
                MapFlags::ANY,
            )?;
        }

        for core in topo.all_cores.values() {
            let dense_llc = llc_id_to_dense.get(&core.llc_id).copied().unwrap_or(0);
            let mut topo_core: forge_topo_core = unsafe { std::mem::zeroed() };
            topo_core.id = core.id as u32;
            topo_core.kernel_id = core.kernel_id as u32;
            topo_core.cluster_id = core.cluster_id as i32;
            topo_core.llc_id = core.llc_id as u32;
            topo_core.llc_dense_id = dense_llc as u32;
            topo_core.node_id = core.node_id as u32;
            topo_core.nr_cpus = core.cpus.len() as u32;
            topo_core.core_type = Self::topo_core_type(&core.core_type);
            topo_core.span = Self::topo_cpumask(&core.span)?;
            skel.maps.topo_core_map.update(
                &(core.id as u32).to_ne_bytes(),
                Self::bytes_of(&topo_core),
                MapFlags::ANY,
            )?;
        }

        for llc in topo.all_llcs.values() {
            let dense_llc = llc_id_to_dense.get(&llc.id).copied().unwrap_or(0);
            let mut topo_llc: forge_topo_llc = unsafe { std::mem::zeroed() };
            topo_llc.id = llc.id as u32;
            topo_llc.kernel_id = llc.kernel_id as u32;
            topo_llc.dense_id = dense_llc as u32;
            topo_llc.node_id = llc.node_id as u32;
            topo_llc.nr_cores = llc.cores.len() as u32;
            topo_llc.nr_cpus = llc.all_cpus.len() as u32;
            topo_llc.span = Self::topo_cpumask(&llc.span)?;
            skel.maps.topo_llc_map.update(
                &(llc.id as u32).to_ne_bytes(),
                Self::bytes_of(&topo_llc),
                MapFlags::ANY,
            )?;
        }

        for node in topo.nodes.values() {
            let mut topo_node: forge_topo_node = unsafe { std::mem::zeroed() };
            topo_node.id = node.id as u32;
            topo_node.nr_llcs = node.llcs.len() as u32;
            topo_node.nr_cores = node.all_cores.len() as u32;
            topo_node.nr_cpus = node.all_cpus.len() as u32;
            topo_node.nr_distances = node.distance.len() as u32;
            topo_node.span = Self::topo_cpumask(&node.span)?;
            skel.maps.topo_node_map.update(
                &(node.id as u32).to_ne_bytes(),
                Self::bytes_of(&topo_node),
                MapFlags::ANY,
            )?;

            for (distance_idx, distance) in node.distance.iter().enumerate() {
                let key = forge_topo_distance_key {
                    node_id: node.id as u32,
                    distance_idx: distance_idx as u32,
                };
                skel.maps.topo_distance_map.update(
                    Self::bytes_of(&key),
                    &(*distance as u32).to_ne_bytes(),
                    MapFlags::ANY,
                )?;
            }
        }

        Ok(())
    }

    fn enable_primary_cpu(skel: &mut BpfSkel<'_>, cpu: i32) -> Result<(), u32> {
        let prog = &mut skel.progs.enable_primary_cpu;
        let mut args = cpu_arg {
            cpu_id: cpu as c_int,
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
        let out = prog.test_run(input).unwrap();
        if out.return_value != 0 {
            return Err(out.return_value);
        }

        Ok(())
    }

    fn enable_sibling_cpu(
        skel: &mut BpfSkel<'_>,
        cpu: usize,
        sibling_cpu: usize,
    ) -> Result<(), u32> {
        let prog = &mut skel.progs.enable_sibling_cpu;
        let mut args = domain_arg {
            cpu_id: cpu as c_int,
            sibling_cpu_id: sibling_cpu as c_int,
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
        let out = prog.test_run(input).unwrap();
        if out.return_value != 0 {
            return Err(out.return_value as u32);
        }
        Ok(())
    }

    fn init_smt_domains(skel: &mut BpfSkel<'_>, topo: &Topology) -> Result<(), std::io::Error> {
        let smt_siblings = topo.sibling_cpus();
        info!("SMT sibling CPUs: {:?}", smt_siblings);
        for (cpu, sibling_cpu) in smt_siblings.iter().enumerate() {
            Self::enable_sibling_cpu(skel, cpu, *sibling_cpu as usize).map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("enable_sibling_cpu: {}", e),
                )
            })?;
        }
        Ok(())
    }

    fn get_metrics(&self) -> Metrics {
        let bss_data = self.skel.maps.bss_data.as_ref().unwrap();
        Metrics {
            nr_direct_dispatches: bss_data.nr_direct_dispatches,
            nr_enqueues: bss_data.nr_enqueues,
            nr_preempt_dispatches: bss_data.nr_preempt_dispatches,
            nr_local_dispatches: bss_data.nr_local_dispatches,
            nr_remote_dispatches: bss_data.nr_remote_dispatches,
            nr_llc_dispatches: bss_data.nr_llc_dispatches,
            nr_node_dispatches: bss_data.nr_node_dispatches,
            nr_global_dispatches: bss_data.nr_global_dispatches,
            nr_dequeues: bss_data.nr_dequeues,
            nr_dispatch_dequeues: bss_data.nr_dispatch_dequeues,
            nr_sched_change_dequeues: bss_data.nr_sched_change_dequeues,
            nr_task_state_errors: bss_data.nr_task_state_errors,
            nr_event_dispatches: bss_data.nr_event_dispatches,
            nr_ev_sticky_dispatches: bss_data.nr_ev_sticky_dispatches,
        }
    }

    pub fn exited(&mut self) -> bool {
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
