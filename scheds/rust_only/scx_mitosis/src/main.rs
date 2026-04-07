// SPDX-License-Identifier: GPL-2.0
//
// scx_mitosis userspace loader — pure Rust BPF scheduler
//
// Cell-based cgroup scheduler. Cgroups are assigned to a dynamic number
// of Cells which are assigned to a dynamic set of CPUs. The BPF part does
// simple vtime scheduling for each cell; userspace makes the dynamic
// decisions of which Cells should be merged/split and which CPUs they
// should be assigned to.
//
// PORT_TODO: Userspace loader gaps vs C version (scx/scheds/rust/scx_mitosis/src/main.rs):
//
// Missing CLI flags:
// - log_level with tracing_subscriber EnvFilter — see C main.rs:68-69
// - exit_dump_len — see C main.rs:73
// - monitor mode (--monitor, stats-only without running scheduler) — see C main.rs:90-91
// - run_id — see C main.rs:98
// - exiting_task_workaround (default true) — see C main.rs:108-109
// - libbpf options (--libbpf-* flags) — see C main.rs:130-131
//
// Missing rodata population — see C main.rs:235-268:
// - slice_ns = SCX_SLICE_DFL
// - smt_enabled (currently detected but not passed to BPF)
// - all_cpus[] bitmask (currently built but not passed to BPF)
// - nr_possible_cpus (currently detected but not passed to BPF)
// - debug_events_enabled
// - exiting_task_workaround_enabled
// - cpu_controller_disabled
// - reject_multicpu_pinning
// - cpu_to_llc[] and llc_to_cpus[] (currently built but not passed to BPF)
// These need aya override_global or BPF map data section support.
//
// Missing struct_ops flags:
// - SCX_OPS_ALLOW_QUEUED_WAKEUP — see C main.rs:254-257
// - exit_dump_len on struct_ops — see C main.rs:233
//
// Missing runtime monitoring — see C main.rs:286-603:
// - Scheduler struct with full cell tracking, configuration_seq sync
// - refresh_bpf_cells() — reads applied_configuration_seq atomically,
//   rebuilds cell map from CPU contexts
// - calculate_cell_stat_delta() — reads percpu cpu_ctx stats, computes deltas
// - log_all_queue_stats() — DistributionStats with per-cell and global breakdown
// - read_cpu_ctxs() — percpu map reading (not yet supported by aya)
//
// Missing stats module — see C main.rs:9, stats.rs:
// - CellMetrics, Metrics structs
// - StatsServer integration for external monitoring
// - monitor() function for stats-only mode
//
// Missing UEI (User Exit Info) — see C main.rs:37, 293, 305:
// - uei_exited!() check in main loop
// - uei_report!() for structured exit info to userspace

use std::collections::BTreeMap;
use std::fs;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use aya::{EbpfLoader, include_bytes_aligned};
use clap::Parser;
use log::info;

// ── Constants matching eBPF side ─────────────────────────────────────

const MAX_LLCS: usize = 16;

// ── CLI Options ──────────────────────────────────────────────────────

/// scx_mitosis: A dynamic affinity scheduler (pure Rust BPF).
///
/// Cgroups are assigned to a dynamic number of Cells which are assigned to a
/// dynamic set of CPUs. The BPF part does simple vtime scheduling for each cell.
/// Userspace makes the dynamic decisions of which Cells should be merged or
/// split and which CPUs they should be assigned to.
#[derive(Debug, Parser)]
#[command(name = "scx_mitosis")]
struct Opts {
    /// Enable verbose logging output.
    #[clap(short = 'v', long, action = clap::ArgAction::SetTrue)]
    verbose: bool,

    /// Interval to consider reconfiguring the Cells (e.g. merge or split).
    #[clap(long, default_value = "10")]
    reconfiguration_interval_s: u64,

    /// Interval to consider rebalancing CPUs to Cells.
    #[clap(long, default_value = "5")]
    rebalance_cpus_interval_s: u64,

    /// Interval to report monitoring information.
    #[clap(long, default_value = "1")]
    monitor_interval_s: u64,

    /// Enable debug event tracking for cgroup_init, init_task, and cgroup_exit.
    #[clap(long, action = clap::ArgAction::SetTrue)]
    debug_events: bool,

    /// Disable SCX cgroup callbacks (for when CPU cgroup controller is disabled).
    /// Uses tracepoints and cgroup iteration instead.
    #[clap(long, action = clap::ArgAction::SetTrue)]
    cpu_controller_disabled: bool,

    /// Reject tasks with multi-CPU pinning that doesn't cover the entire cell.
    #[clap(long, action = clap::ArgAction::SetTrue)]
    reject_multicpu_pinning: bool,

    /// Enable LLC-awareness. Populates the scheduler's LLC maps and causes it
    /// to use LLC-aware scheduling.
    #[clap(long, action = clap::ArgAction::SetTrue)]
    enable_llc_awareness: bool,

    /// Enable work stealing. Only relevant when LLC-awareness is enabled.
    #[clap(long, action = clap::ArgAction::SetTrue)]
    enable_work_stealing: bool,

    /// Print scheduler version and exit.
    #[clap(short = 'V', long, action = clap::ArgAction::SetTrue)]
    version: bool,
}

// ── CPU Topology ─────────────────────────────────────────────────────

/// Detected CPU topology from sysfs.
struct Topology {
    /// Total number of possible CPUs.
    nr_cpus: usize,
    /// LLC ID for each CPU (indexed by CPU number).
    cpu_to_llc: Vec<u32>,
    /// Number of distinct LLCs.
    nr_llcs: usize,
    /// NUMA node ID -> list of CPU IDs.
    numa_nodes: BTreeMap<u32, Vec<u32>>,
    /// Whether any CPU has an SMT sibling.
    smt_enabled: bool,
}

impl Topology {
    /// Detect CPU topology from sysfs.
    fn detect() -> Result<Self> {
        let nr_cpus = Self::read_nr_cpus()?;
        let cpu_to_llc = Self::read_llc_map(nr_cpus);
        let nr_llcs = {
            let mut ids: Vec<u32> = cpu_to_llc.clone();
            ids.sort();
            ids.dedup();
            ids.len().max(1)
        };
        let numa_nodes = Self::read_numa_nodes();
        let smt_enabled = Self::detect_smt(nr_cpus);

        Ok(Self {
            nr_cpus,
            cpu_to_llc,
            nr_llcs,
            numa_nodes,
            smt_enabled,
        })
    }

    /// Read number of possible CPUs from sysfs.
    fn read_nr_cpus() -> Result<usize> {
        let content = fs::read_to_string("/sys/devices/system/cpu/possible")
            .context("Failed to read /sys/devices/system/cpu/possible")?;
        let mut max_cpu: usize = 0;
        for range in content.trim().split(',') {
            let range = range.trim();
            if let Some((_start, end)) = range.split_once('-') {
                if let Ok(end_cpu) = end.parse::<usize>() {
                    if end_cpu > max_cpu {
                        max_cpu = end_cpu;
                    }
                }
            } else if let Ok(cpu) = range.parse::<usize>() {
                if cpu > max_cpu {
                    max_cpu = cpu;
                }
            }
        }
        Ok(max_cpu + 1)
    }

    /// Read CPU -> LLC mapping from sysfs.
    ///
    /// Uses /sys/devices/system/cpu/cpu*/cache/index*/shared_cpu_list to
    /// find the last-level cache for each CPU.
    fn read_llc_map(nr_cpus: usize) -> Vec<u32> {
        let mut cpu_to_llc = vec![0u32; nr_cpus];

        for cpu in 0..nr_cpus {
            // Find the highest-index cache (last level).
            let mut max_index = 0;
            let cache_dir = format!("/sys/devices/system/cpu/cpu{}/cache", cpu);
            if let Ok(entries) = fs::read_dir(&cache_dir) {
                for entry in entries.flatten() {
                    let name = entry.file_name();
                    let name_str = name.to_string_lossy();
                    if let Some(idx_str) = name_str.strip_prefix("index") {
                        if let Ok(idx) = idx_str.parse::<u32>() {
                            if idx > max_index {
                                max_index = idx;
                            }
                        }
                    }
                }
            }

            // Read the shared_cpu_list of the LLC to build a canonical LLC ID.
            // We use the lowest CPU number in the shared_cpu_list as the LLC ID.
            let llc_path = format!(
                "/sys/devices/system/cpu/cpu{}/cache/index{}/shared_cpu_list",
                cpu, max_index
            );
            if let Ok(content) = fs::read_to_string(&llc_path) {
                let cpus = Self::parse_cpu_list(content.trim());
                if let Some(&first) = cpus.first() {
                    cpu_to_llc[cpu] = first;
                }
            }
        }

        cpu_to_llc
    }

    /// Read NUMA node topology.
    fn read_numa_nodes() -> BTreeMap<u32, Vec<u32>> {
        let mut nodes = BTreeMap::new();
        if let Ok(entries) = fs::read_dir("/sys/devices/system/node") {
            for entry in entries.flatten() {
                let name = entry.file_name();
                let name_str = name.to_string_lossy();
                if !name_str.starts_with("node") {
                    continue;
                }
                let node_id: u32 = match name_str[4..].parse() {
                    Ok(id) => id,
                    Err(_) => continue,
                };
                let cpulist_path = format!("/sys/devices/system/node/{}/cpulist", name_str);
                if let Ok(content) = fs::read_to_string(&cpulist_path) {
                    let cpus = Self::parse_cpu_list(content.trim());
                    if !cpus.is_empty() {
                        nodes.insert(node_id, cpus);
                    }
                }
            }
        }
        if nodes.is_empty() {
            nodes.insert(0, Vec::new());
        }
        nodes
    }

    /// Detect SMT by checking thread_siblings_list.
    fn detect_smt(nr_cpus: usize) -> bool {
        for cpu in 0..nr_cpus {
            let path = format!(
                "/sys/devices/system/cpu/cpu{}/topology/thread_siblings_list",
                cpu
            );
            if let Ok(content) = fs::read_to_string(&path) {
                let siblings = Self::parse_cpu_list(content.trim());
                if siblings.len() > 1 {
                    return true;
                }
            }
        }
        false
    }

    /// Parse "0-3,8-11" into sorted Vec<u32>.
    fn parse_cpu_list(s: &str) -> Vec<u32> {
        let mut cpus = Vec::new();
        for range in s.split(',') {
            let range = range.trim();
            if range.is_empty() {
                continue;
            }
            if let Some((start, end)) = range.split_once('-') {
                if let (Ok(s), Ok(e)) = (start.parse::<u32>(), end.parse::<u32>()) {
                    for cpu in s..=e {
                        cpus.push(cpu);
                    }
                }
            } else if let Ok(cpu) = range.parse::<u32>() {
                cpus.push(cpu);
            }
        }
        cpus.sort();
        cpus
    }

    /// Build LLC -> CPU bitmask arrays for BPF global override.
    ///
    /// Returns (cpu_to_llc_arr, llc_to_cpus_bitmasks) where:
    /// - cpu_to_llc_arr[cpu] = LLC ID
    /// - llc_to_cpus_bitmasks[llc] = [u64; 8] bitmask of CPUs
    fn build_llc_arrays(&self) -> ([u32; 512], [[u64; 8]; MAX_LLCS]) {
        let mut cpu_to_llc_arr = [0u32; 512];
        let mut llc_to_cpus = [[0u64; 8]; MAX_LLCS];

        // Normalize LLC IDs to contiguous 0..n range.
        let mut llc_ids: Vec<u32> = self.cpu_to_llc.clone();
        llc_ids.sort();
        llc_ids.dedup();

        let mut id_map = BTreeMap::new();
        for (i, &id) in llc_ids.iter().enumerate() {
            id_map.insert(id, i as u32);
        }

        for (cpu, &raw_llc) in self.cpu_to_llc.iter().enumerate() {
            let llc = id_map.get(&raw_llc).copied().unwrap_or(0);
            if cpu < 512 {
                cpu_to_llc_arr[cpu] = llc;
            }
            if (llc as usize) < MAX_LLCS && cpu < 512 {
                let word = cpu / 64;
                let bit = cpu % 64;
                if word < 8 {
                    llc_to_cpus[llc as usize][word] |= 1u64 << bit;
                }
            }
        }

        (cpu_to_llc_arr, llc_to_cpus)
    }

    /// Format CPU range for display.
    fn format_cpu_range(cpus: &[u32]) -> String {
        if cpus.is_empty() {
            return String::new();
        }
        let mut ranges = Vec::new();
        let mut start = cpus[0];
        let mut end = cpus[0];
        for &cpu in &cpus[1..] {
            if cpu == end + 1 {
                end = cpu;
            } else {
                if start == end {
                    ranges.push(format!("{}", start));
                } else {
                    ranges.push(format!("{}-{}", start, end));
                }
                start = cpu;
                end = cpu;
            }
        }
        if start == end {
            ranges.push(format!("{}", start));
        } else {
            ranges.push(format!("{}-{}", start, end));
        }
        ranges.join(",")
    }

    fn print_summary(&self) {
        println!("Topology:");
        println!("  CPUs: {}", self.nr_cpus);
        println!("  LLCs: {}", self.nr_llcs);
        println!(
            "  NUMA nodes: {} ({})",
            self.numa_nodes.len(),
            if self.numa_nodes.len() > 1 { "multi-node" } else { "single-node" }
        );
        for (node_id, cpus) in &self.numa_nodes {
            if !cpus.is_empty() {
                println!(
                    "    node {}: {} CPUs ({})",
                    node_id,
                    cpus.len(),
                    Self::format_cpu_range(cpus)
                );
            }
        }
        println!(
            "  SMT: {}",
            if self.smt_enabled { "enabled" } else { "disabled" }
        );
    }
}

// ── Scheduler exit detection ─────────────────────────────────────────

/// Check if the mitosis scheduler is still attached.
fn is_scheduler_attached() -> bool {
    match fs::read_to_string("/sys/kernel/sched_ext/root/ops") {
        Ok(name) => name.trim() == "mitosis",
        Err(_) => false,
    }
}

// ── Formatting helpers ──────────────────────────────────────────────

fn format_uptime(d: Duration) -> String {
    let secs = d.as_secs();
    let hours = secs / 3600;
    let mins = (secs % 3600) / 60;
    let s = secs % 60;
    if hours > 0 {
        format!("{}h {}m {}s", hours, mins, s)
    } else if mins > 0 {
        format!("{}m {}s", mins, s)
    } else {
        format!("{}s", s)
    }
}

// ── Main ─────────────────────────────────────────────────────────────

fn main() -> Result<()> {
    let opts = Opts::parse();

    // Version check.
    if opts.version {
        println!("scx_mitosis {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }

    // Initialize logging.
    if opts.verbose {
        env_logger::Builder::from_default_env()
            .filter_level(log::LevelFilter::Debug)
            .init();
    } else {
        env_logger::Builder::from_default_env()
            .filter_level(log::LevelFilter::Info)
            .init();
    }

    // Validate args.
    if opts.enable_work_stealing && !opts.enable_llc_awareness {
        bail!("Work stealing requires LLC-aware mode (--enable-llc-awareness)");
    }

    // ── Topology detection ───────────────────────────────────────────
    let topo = Topology::detect().context("Failed to detect CPU topology")?;
    topo.print_summary();

    let nr_llc = topo.nr_llcs as u32;
    let nr_cpus = topo.nr_cpus;

    info!("Loading scx_mitosis BPF program...");
    info!("  nr_llc             = {}", nr_llc);
    info!("  enable_llc_awareness = {}", opts.enable_llc_awareness);
    info!("  enable_work_stealing = {}", opts.enable_work_stealing);
    info!("  monitor_interval   = {}s", opts.monitor_interval_s);
    info!("  reconfig_interval  = {}s", opts.reconfiguration_interval_s);
    info!("  rebalance_interval = {}s", opts.rebalance_cpus_interval_s);

    // ── Build LLC topology arrays ────────────────────────────────────
    let (cpu_to_llc_arr, llc_to_cpus_arr) = topo.build_llc_arrays();

    // ── Build all-CPUs bitmask ───────────────────────────────────────
    let mut all_cpus = [0u8; 64]; // 512 bits = 64 bytes
    for cpu in 0..nr_cpus {
        if cpu < 512 {
            all_cpus[cpu / 8] |= 1 << (cpu % 8);
        }
    }

    // ── Load BPF with global overrides ───────────────────────────────
    let llc_aware: u8 = opts.enable_llc_awareness as u8;
    let work_stealing: u8 = opts.enable_work_stealing as u8;

    // PORT_TODO: Missing global overrides — the following BPF globals need to be
    // set before load but are not yet passed:
    //   SMT_ENABLED, SLICE_NS, all_cpus[], nr_possible_cpus,
    //   debug_events_enabled, exiting_task_workaround_enabled,
    //   cpu_controller_disabled, reject_multicpu_pinning,
    //   cpu_to_llc[], llc_to_cpus[]
    // The arrays (all_cpus, cpu_to_llc, llc_to_cpus) are already computed above
    // but override_global for arrays may need special handling in aya.
    // See C main.rs:235-268

    let mut ebpf = EbpfLoader::new()
        .allow_unsupported_maps()
        .override_global("NR_LLC", &nr_llc, false)
        .override_global("ENABLE_LLC_AWARENESS", &llc_aware, false)
        .override_global("ENABLE_WORK_STEALING", &work_stealing, false)
        .load(include_bytes_aligned!(concat!(
            env!("OUT_DIR"),
            "/scx_mitosis"
        )))
        .context("Failed to load BPF object")?;

    // ── Attach the struct_ops scheduler ──────────────────────────────
    let link = ebpf
        .attach_struct_ops("_scx_ops")
        .context("Failed to attach struct_ops scheduler")?;

    println!();
    println!("scx_mitosis: scheduler attached (pure Rust BPF)");
    println!("  cells        = 1 (root only, dynamic split not yet implemented)");
    println!("  nr_llc       = {}", nr_llc);
    println!("  llc_aware    = {}", opts.enable_llc_awareness);
    println!("  work_steal   = {}", opts.enable_work_stealing);
    println!("  cpus         = {}", nr_cpus);
    println!("  smt          = {}", if topo.smt_enabled { "yes" } else { "no" });
    if topo.numa_nodes.len() > 1 {
        println!("  numa_nodes   = {}", topo.numa_nodes.len());
    }
    println!("Press Ctrl-C to detach and exit.");

    // ── Set up Ctrl-C handler ────────────────────────────────────────
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })
    .context("Failed to set Ctrl-C handler")?;

    // ── Main scheduler loop ─────────────────────────────────────────
    //
    // Periodically:
    //   - Check if scheduler is still attached
    //   - Collect per-cell stats from BPF maps (once they're populated)
    //   - Report metrics
    //
    // Future: cell reconfiguration and CPU rebalancing will go here.

    let monitor_interval = Duration::from_secs(opts.monitor_interval_s);
    let start_time = Instant::now();
    let mut last_monitor = Instant::now();

    while running.load(Ordering::SeqCst) {
        std::thread::sleep(Duration::from_millis(100));

        // ── Periodic monitoring ──────────────────────────────────────
        if last_monitor.elapsed() >= monitor_interval {
            let uptime = start_time.elapsed();

            // Check if the kernel detached us.
            if !is_scheduler_attached() {
                eprintln!(
                    "\nscx_mitosis: scheduler was detached by the kernel (uptime {})",
                    format_uptime(uptime),
                );
                break;
            }

            // PORT_TODO: Read CPU_CTX percpu array to collect per-cell stats.
            // Requires aya support for reading BPF_MAP_TYPE_PERCPU_ARRAY.
            // The C version does this via libbpf_rs lookup_percpu().
            // See C main.rs:490-535 (collect_metrics, calculate_cell_stat_delta)
            // and C main.rs:606-627 (read_cpu_ctxs).
            //
            // When implemented:
            // 1. Read the CPU_CTX percpu array via aya map API
            // 2. Aggregate cstats per cell across all CPUs
            // 3. Calculate deltas from previous snapshot
            // 4. Log distribution stats (local/cpu_dsq/cell_dsq/affinity_viol/steal %)

            println!(
                "[scx_mitosis] cells: 1  uptime {}",
                format_uptime(uptime),
            );

            last_monitor = Instant::now();
        }
    }

    // ── Cleanup ──────────────────────────────────────────────────────
    drop(link);
    println!(
        "\nscx_mitosis: scheduler detached (uptime {})",
        format_uptime(start_time.elapsed()),
    );

    Ok(())
}
