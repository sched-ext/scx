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
use clap::CommandFactory;
use clap::Parser;
use clap_complete::generate;
use clap_complete::Shell;
use crossbeam::channel::RecvTimeoutError;
use libbpf_rs::OpenObject;
use libbpf_rs::ProgramInput;
use libbpf_rs::MapCore;
use libbpf_rs::MapFlags;
use log::warn;
use log::{debug, info};
use scx_stats::prelude::*;
use scx_utils::build_id;
use scx_utils::compat;
use scx_utils::CoreType;
use scx_utils::libbpf_clap_opts::LibbpfOpts;
use scx_utils::NR_CPU_IDS;
use scx_utils::scx_ops_attach;
use scx_utils::scx_ops_load;
use scx_utils::scx_ops_open;
use scx_utils::try_set_rlimit_infinity;
use scx_utils::uei_exited;
use scx_utils::uei_report;
use scx_utils::Topology;
use scx_utils::UserExitInfo;
use stats::Metrics;

const SCHEDULER_NAME: &str = "scx_maestro";

#[derive(Debug, Parser)]
struct Opts {
    /// Maximum scheduling slice duration in microseconds.
    #[clap(short = 's', long, default_value = "700")]
    slice_us: u64,

    /// Maximum runtime (since last sleep) that can be charged to a task in microseconds.
    #[clap(short = 'l', long, default_value = "20000")]
    slice_lag_us: u64,

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

    /// Disable SMT optimizations.
    #[clap(long, action = clap::ArgAction::SetTrue)]
    disable_smt: bool,

    /// Disable NUMA optimizations.
    #[clap(long, action = clap::ArgAction::SetTrue)]
    disable_numa: bool,

    /// Enable BPF debugging via /sys/kernel/tracing/trace_pipe.
    #[clap(short = 'd', long, action = clap::ArgAction::SetTrue)]
    debug: bool,

    /// Specifies a list of CPUs to prioritize.
    ///
    /// Accepts a comma-separated list of CPUs or ranges (i.e., 0-3,12-15) or the following special
    /// keywords:
    ///
    /// "all" = all CPUs assigned to the primary domain.
    /// "performance" = automatically detect and prioritize the fastest CPUs,
    /// "powersave" = automatically detect and prioritize the slowest CPUs,
    ///
    /// By default "all" CPUs are used.
    #[clap(short = 'm', long)]
    primary_domain: Option<String>,

    /// Enable core compaction (try to minimize the number of active CPUs).
    #[clap(long, action = clap::ArgAction::SetTrue)]
    compaction: bool,

    /// Throttle the running CPUs by periodically injecting idle cycles.
    ///
    /// This option can help extend battery life on portable devices, reduce heating, fan noise and
    /// overall energy consumption (0 = disable).
    #[clap(short = 't', long, default_value = "0")]
    throttle_us: u64,

    /// Enable low-latency mode (aggressively migrate tasks).
    #[clap(long, action = clap::ArgAction::SetTrue)]
    lowlatency: bool,

    /// Enable completely fair scheduling policy.
    #[clap(long, action = clap::ArgAction::SetTrue)]
    fair: bool,

    /// Attach the scheduler to a specified cgroup (by path).
    #[clap(short = 'c', long)]
    cgroup: Option<String>,

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
    /// Generate shell completions for the given shell and exit.
    #[clap(long, value_name = "SHELL", hide = true)]
    completions: Option<Shell>,
}

#[derive(PartialEq)]
enum Powermode {
    Performance,
    Powersave,
    Any,
}

fn get_primary_cpus(mode: Powermode) -> std::io::Result<Vec<usize>> {
    let cpus: Vec<usize> = Topology::new()
        .unwrap()
        .all_cores
        .values()
        .flat_map(|core| &core.cpus)
        .filter_map(|(cpu_id, cpu)| match (&mode, &cpu.core_type) {
            (Powermode::Performance, CoreType::Big { .. }) |
            (Powermode::Powersave, CoreType::Little) => Some(*cpu_id),
            (Powermode::Any, ..) => Some(*cpu_id),
            _ => None,
        })
        .collect();

    Ok(cpus)
}

pub fn parse_cpu_list(optarg: &str) -> Result<Vec<usize>, String> {
    let mut cpus = Vec::new();
    let mut seen = HashSet::new();

    if let Some(mode) = match optarg {
        "all" => Some(Powermode::Any),
        "performance" => Some(Powermode::Performance),
        "powersave" => Some(Powermode::Powersave),
        _ => None,
    } {
        return get_primary_cpus(mode).map_err(|e| e.to_string());
    }

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

        // Initialize CPU topology.
        let topo = Topology::new().unwrap();

        // Check host topology to determine if we need to enable SMT capabilities.
        let smt_enabled = !opts.disable_smt && topo.smt_enabled;
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

        // Automatically disable NUMA optimizations when running on non-NUMA systems.
        let numa_enabled = !opts.disable_numa && nr_nodes > 1;
        if !numa_enabled {
            info!("Disabling NUMA optimizations");
        }

        info!(
            "{} {}",
            SCHEDULER_NAME,
            build_id::full_version(env!("CARGO_PKG_VERSION")),
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
        let mut skel = scx_ops_open!(skel_builder, open_object, maestro_ops, open_opts)?;

        if !compat::struct_has_field("sched_ext_ops", "cgroup_init").unwrap_or(false) {
            warn!("kernel doesn't support ops.cgroup_init(), disabling");
            skel.struct_ops.maestro_ops_mut().cgroup_init = std::ptr::null_mut();
        }
        if !compat::struct_has_field("sched_ext_ops", "cgroup_exit").unwrap_or(false) {
            warn!("kernel doesn't support ops.cgroup_exit(), disabling");
            skel.struct_ops.maestro_ops_mut().cgroup_exit = std::ptr::null_mut();
        }
        if !compat::struct_has_field("sched_ext_ops", "cgroup_set_weight").unwrap_or(false) {
            warn!("kernel doesn't support ops.cgroup_set_weight(), disabling");
            skel.struct_ops.maestro_ops_mut().cgroup_set_weight = std::ptr::null_mut();
        }
        if !compat::struct_has_field("sched_ext_ops", "cgroup_move").unwrap_or(false) {
            warn!("kernel doesn't support ops.cgroup_move(), disabling");
            skel.struct_ops.maestro_ops_mut().cgroup_move = std::ptr::null_mut();
        }
        if !compat::struct_has_field("sched_ext_ops", "sub_attach").unwrap_or(false) {
            warn!("kernel doesn't support ops.sub_attach(), disabling");
            skel.struct_ops.maestro_ops_mut().sub_attach = std::ptr::null_mut();
        }
        if !compat::struct_has_field("sched_ext_ops", "sub_detach").unwrap_or(false) {
            warn!("kernel doesn't support ops.sub_detach(), disabling");
            skel.struct_ops.maestro_ops_mut().sub_detach = std::ptr::null_mut();
        }

        skel.struct_ops.maestro_ops_mut().exit_dump_len = opts.exit_dump_len;

        // Override default BPF scheduling parameters.
        let rodata = skel.maps.rodata_data.as_mut().unwrap();
        rodata.slice_ns = opts.slice_us * 1000;
        rodata.slice_lag_ns = opts.slice_lag_us * 1000;
        rodata.debug = opts.debug;
        rodata.smt_enabled = smt_enabled;
        rodata.numa_enabled = numa_enabled;
        rodata.throttle_ns = opts.throttle_us * 1000;
        rodata.compaction = opts.compaction;
        rodata.lowlatency = opts.lowlatency;
        rodata.fair = opts.fair;

        let is_subsched = if let Some(ref cgroup_path) = opts.cgroup {
            let meta = std::fs::metadata(cgroup_path)
                .with_context(|| format!("failed to stat cgroup path: {}", cgroup_path))?;
            let ino = std::os::unix::fs::MetadataExt::ino(&meta);
            skel.struct_ops.maestro_ops_mut().sub_cgroup_id = ino;
            let subsched = ino != 1;
            info!(
                "Limiting to cgroup {} (inode {}, sub-scheduler: {})",
                cgroup_path, ino, subsched,
            );
            subsched
        } else {
            false
        };

        // Skip scx_bpf_sub_dispatch() in maestro_dispatch() on leaf sub-scheduler instances.
        rodata.sub_sched_enabled = !is_subsched;

        // Normalize CPU capacities to 1..1024 so the highest capacity is always 1024 (Rust-only).
        let mut cpus: Vec<_> = topo.all_cpus.values().collect();
        cpus.sort_by_key(|cpu| std::cmp::Reverse(cpu.cpu_capacity));
        let max_cap = cpus.first().map(|c| c.cpu_capacity).unwrap_or(1).max(1);

        // Build dense LLC index (node for each DSQ is resolved in BPF via first CPU in LLC).
        let nr_llc_ids = topo.all_llcs.len();
        let mut llc_id_to_dense = std::collections::HashMap::new();
        for (dense_id, (_, llc)) in topo.all_llcs.iter().enumerate() {
            llc_id_to_dense.insert(llc.id, dense_id);
        }
        rodata.nr_llc_ids = nr_llc_ids as u64;

        // Precompute average CPU capacity per LLC (sum of normalized capacities / nr_cpus) for BPF rodata.
        for (dense_id, (_, llc)) in topo.all_llcs.iter().enumerate() {
            let (sum, count) = llc.all_cpus.values().fold((0u64, 0u32), |(sum, count), cpu| {
                let normalized =
                    (cpu.cpu_capacity * 1024 / max_cap).clamp(1, 1024) as u64;
                (sum + normalized, count + 1)
            });
            rodata.llc_capacity[dense_id] = if count > 0 {
                sum / count as u64
            } else {
                0
            };
        }
        let llc_capacities: Vec<u64> = (0..nr_llc_ids).map(|i| rodata.llc_capacity[i]).collect();
        rodata.llc_id_max = (0..nr_llc_ids)
            .max_by_key(|&i| rodata.llc_capacity[i])
            .unwrap_or(0) as u32;

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

        // Set scheduler flags.
        skel.struct_ops.maestro_ops_mut().flags = *compat::SCX_OPS_ENQ_EXITING
            | *compat::SCX_OPS_ENQ_LAST
            | *compat::SCX_OPS_ENQ_MIGRATION_DISABLED
            | *compat::SCX_OPS_ALLOW_QUEUED_WAKEUP
            | if numa_enabled {
                *compat::SCX_OPS_BUILTIN_IDLE_PER_NODE
            } else {
                0
            }
            | if opts.lowlatency {
                *compat::SCX_OPS_ALWAYS_ENQ_IMMED
            } else {
                0
            };
        info!(
            "scheduler flags: {:#x}",
            skel.struct_ops.maestro_ops_mut().flags
        );

        // Load the BPF program for validation.
        let mut skel = scx_ops_load!(skel, maestro_ops, uei)?;

        // Enable primary scheduling domain, if defined.
        if primary_cpus.len() < *NR_CPU_IDS {
            for cpu in primary_cpus {
                if let Err(err) = Self::enable_primary_cpu(&mut skel, cpu as i32) {
                    bail!("failed to add CPU {} to primary domain: error {}", cpu, err);
                }
            }
        }

        // Initialize SMT sibling cpumasks (populate per-CPU smt via enable_sibling_cpu prog).
        if smt_enabled {
            Self::init_smt_domains(&mut skel, &topo)?;
        }

        // Configure CPU->LLC mapping (must be done after skeleton is loaded).
        for cpu in topo.all_cpus.values() {
            let dense_llc = llc_id_to_dense
                .get(&cpu.llc_id)
                .copied()
                .unwrap_or(0);
            if opts.verbose {
                let cap = llc_capacities.get(dense_llc).copied().unwrap_or(0);
                info!("CPU{} -> LLC{} (capacity: {})", cpu.id, dense_llc, cap);
            }
            skel.maps.cpu_llc_map.update(
                &(cpu.id as u32).to_ne_bytes(),
                &(dense_llc as u32).to_ne_bytes(),
                MapFlags::ANY,
            )?;
        }

        // Attach the scheduler.
        let struct_ops = Some(scx_ops_attach!(skel, maestro_ops, is_subsched)?);
        let stats_server = StatsServer::new(stats::server_data()).launch()?;

        Ok(Self {
            skel,
            struct_ops,
            stats_server,
            user_restart: false,
        })
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
            Self::enable_sibling_cpu(skel, cpu, *sibling_cpu as usize)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("enable_sibling_cpu: {}", e)))?;
        }
        Ok(())
    }

    fn get_metrics(&self) -> Metrics {
        let bss_data = self.skel.maps.bss_data.as_ref().unwrap();
        Metrics {
            nr_direct_dispatches: bss_data.nr_direct_dispatches,
            nr_shared_dispatches: bss_data.nr_shared_dispatches,
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

    if let Some(shell) = opts.completions {
        generate(
            shell,
            &mut Opts::command(),
                 "scx_maestro",
                 &mut std::io::stdout(),
        );
        return Ok(());
    }

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
