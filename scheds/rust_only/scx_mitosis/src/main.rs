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
// Remaining userspace loader gaps vs C version:
//
// Missing CLI flags:
// - log_level with tracing_subscriber EnvFilter
// - exit_dump_len, monitor mode, run_id, libbpf options
//
// Missing struct_ops flags:
// - SCX_OPS_ALLOW_QUEUED_WAKEUP, exit_dump_len
//
// Missing runtime monitoring:
// - refresh_bpf_cells() with configuration_seq sync
// - percpu map reading for full stats collection
//
// Missing UEI (User Exit Info):
// - uei_exited!() check in main loop
// - uei_report!() for structured exit info
//
// DONE (previously listed as missing):
// ✓ smt_enabled, nr_possible_cpus — passed via override_global
// ✓ debug_events_enabled, cpu_controller_disabled — passed via override_global
// ✓ reject_multicpu_pinning — passed via override_global
// ✓ cpu_to_llc[] — passed via override_global
// ✓ all_cpus[] bitmask — built and passed via override_global
// ✓ slice_ns — passed via override_global
// ✓ CellMetrics, Metrics, StatsCollector — implemented in stats.rs
// ✓ exiting_task_workaround — CLI flag + override_global
// ✓ init_cgrp_ids[] — userspace walks /sys/fs/cgroup, passes via override_global

mod mitosis_topology_utils;
mod stats;

use std::collections::BTreeMap;
use std::fs;
use std::os::fd::{AsFd, AsRawFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use aya::{EbpfLoader, include_bytes_aligned};
use clap::Parser;
use log::{info, debug, warn};

use mitosis_topology_utils::{LlcTopology, TopologySource, format_cpu_range};

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

/// Detected CPU topology from sysfs (general, non-LLC info).
///
/// LLC-specific topology is handled by `mitosis_topology_utils::LlcTopology`.
struct Topology {
    /// Total number of possible CPUs.
    nr_cpus: usize,
    /// NUMA node ID -> list of CPU IDs.
    numa_nodes: BTreeMap<u32, Vec<u32>>,
    /// Whether any CPU has an SMT sibling.
    smt_enabled: bool,
}

impl Topology {
    /// Detect CPU topology from sysfs.
    fn detect() -> Result<Self> {
        let nr_cpus = Self::read_nr_cpus()?;
        let numa_nodes = Self::read_numa_nodes();
        let smt_enabled = Self::detect_smt(nr_cpus);

        Ok(Self {
            nr_cpus,
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
                    let cpus = mitosis_topology_utils::parse_cpu_list(content.trim());
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
                let siblings = mitosis_topology_utils::parse_cpu_list(content.trim());
                if siblings.len() > 1 {
                    return true;
                }
            }
        }
        false
    }

    fn print_summary(&self, llc_topo: &LlcTopology) {
        println!("Topology:");
        println!("  CPUs: {}", self.nr_cpus);
        println!("  LLCs: {}", llc_topo.nr_llcs);
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
                    format_cpu_range(cpus)
                );
            }
        }
        println!(
            "  SMT: {}",
            if self.smt_enabled { "enabled" } else { "disabled" }
        );
        llc_topo.print_summary();
    }
}

// ── BPF percpu map reader ────────────────────────────────────────────

/// Userspace mirror of the eBPF CpuCtx struct.
///
/// Must match the exact layout in scx_mitosis-ebpf/src/main.rs.
/// The eBPF side defines: cstats[MAX_CELLS][NR_CSTATS], cell_cycles[MAX_CELLS],
/// vtime_now, cell, llc.
#[repr(C)]
#[derive(Clone)]
struct CpuCtx {
    cstats: [[u64; stats::NR_CSTATS]; stats::MAX_CELLS],
    cell_cycles: [u64; stats::MAX_CELLS],
    vtime_now: u64,
    cell: u32,
    llc: u32,
}

const CPU_CTX_SIZE: usize = core::mem::size_of::<CpuCtx>();

/// Reads per-cell statistics from the BPF CPU_CTX percpu array.
///
/// For a percpu array map, BPF_MAP_LOOKUP_ELEM returns `nr_cpus` copies
/// of the value (one per possible CPU). We aggregate the cstats across
/// all CPUs to get per-cell totals.
struct BpfStatsReader {
    map_fd: i32,
    nr_cpus: usize,
}

impl BpfStatsReader {
    /// Try to locate the CPU_CTX map in the loaded BPF object.
    fn find(ebpf: &aya::Ebpf, nr_cpus: usize) -> Option<Self> {
        let map = ebpf.map("CPU_CTX")?;

        // Get the raw fd. The map is a PerCpuArray internally.
        let fd = match map {
            aya::maps::Map::PerCpuArray(ref data) => data.fd().as_fd().as_raw_fd(),
            _ => {
                // Try other map types that might hold CPU_CTX
                warn!("CPU_CTX map has unexpected type, stats disabled");
                return None;
            }
        };

        // Validate value_size matches our CpuCtx struct.
        if let Ok(map_info) = match map {
            aya::maps::Map::PerCpuArray(ref data) => data.info(),
            _ => return None,
        } {
            let value_size = map_info.value_size() as usize;
            if value_size != CPU_CTX_SIZE {
                warn!(
                    "CPU_CTX value_size {} != expected {} — layout mismatch, stats disabled",
                    value_size, CPU_CTX_SIZE
                );
                return None;
            }
        }

        info!(
            "CPU_CTX map found: fd={}, value_size={}, nr_cpus={}",
            fd, CPU_CTX_SIZE, nr_cpus
        );

        Some(Self { map_fd: fd, nr_cpus })
    }

    /// Read the CPU_CTX percpu array and aggregate cstats per cell.
    ///
    /// Returns aggregated `[cell][stat]` totals across all CPUs, plus
    /// a map of active cells (cells that have CPUs assigned to them).
    fn read_aggregated_stats(
        &self,
    ) -> Result<([[u64; stats::NR_CSTATS]; stats::MAX_CELLS], BTreeMap<u32, u32>)> {
        // For percpu maps, the kernel returns nr_possible_cpus * value_size bytes.
        // We need to use nr_possible_cpus (from /sys/devices/system/cpu/possible),
        // which may differ from online CPUs.
        let nr_possible = self.nr_cpus;
        let total_size = nr_possible * CPU_CTX_SIZE;
        let mut buf = vec![0u8; total_size];
        let key: u32 = 0;

        #[repr(C)]
        #[derive(Default)]
        struct BpfAttrLookup {
            map_fd: u32,
            _pad0: u32,
            key: u64,
            value: u64,
            flags: u64,
        }

        let mut attr = BpfAttrLookup {
            map_fd: self.map_fd as u32,
            key: &key as *const u32 as u64,
            value: buf.as_mut_ptr() as u64,
            ..Default::default()
        };

        let ret = unsafe {
            libc::syscall(
                libc::SYS_bpf,
                1i32, // BPF_MAP_LOOKUP_ELEM
                &mut attr as *mut _ as *mut libc::c_void,
                core::mem::size_of::<BpfAttrLookup>(),
            )
        };
        if ret < 0 {
            anyhow::bail!(
                "BPF_MAP_LOOKUP_ELEM for CPU_CTX failed: {}",
                std::io::Error::last_os_error()
            );
        }

        // Parse per-CPU CpuCtx values and aggregate.
        let mut aggregated = [[0u64; stats::NR_CSTATS]; stats::MAX_CELLS];
        let mut cell_cpu_counts: BTreeMap<u32, u32> = BTreeMap::new();

        for cpu in 0..nr_possible {
            let offset = cpu * CPU_CTX_SIZE;
            let cpu_bytes = &buf[offset..offset + CPU_CTX_SIZE];

            // Safety: buf is properly aligned (allocated by Vec) and CpuCtx is repr(C).
            let cpu_ctx = unsafe { &*(cpu_bytes.as_ptr() as *const CpuCtx) };

            // Track which cell this CPU belongs to.
            *cell_cpu_counts.entry(cpu_ctx.cell).or_insert(0) += 1;

            // Aggregate per-cell stats across all CPUs.
            for cell in 0..stats::MAX_CELLS {
                for stat in 0..stats::NR_CSTATS {
                    aggregated[cell][stat] += cpu_ctx.cstats[cell][stat];
                }
            }
        }

        Ok((aggregated, cell_cpu_counts))
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

// ── Cgroup hierarchy walk ───────────────────────────────────────────

/// Maximum number of cgroup IDs to pass to BPF for init-time walk.
/// Matches `MAX_INIT_CGRPS` on the BPF side.
const MAX_INIT_CGRPS: usize = 1024;

/// Walk /sys/fs/cgroup recursively and collect cgroup inode numbers.
///
/// On the unified cgroup v2 hierarchy, each directory's inode number
/// equals its `kernfs_node->id`, which is the value `bpf_cgroup_from_id`
/// expects. This lets the BPF side look up and initialize each cgroup
/// without needing the CSS iterator.
fn collect_cgroup_ids() -> Vec<u64> {
    let mut ids = Vec::new();
    collect_cgroup_ids_recursive(std::path::Path::new("/sys/fs/cgroup"), &mut ids);
    ids
}

fn collect_cgroup_ids_recursive(path: &std::path::Path, ids: &mut Vec<u64>) {
    // Stop collecting if we've hit the limit
    if ids.len() >= MAX_INIT_CGRPS {
        return;
    }

    // Read the inode number (= kn->id on cgroupfs)
    if let Ok(meta) = fs::metadata(path) {
        use std::os::unix::fs::MetadataExt;
        let ino = meta.ino();
        if ino > 0 {
            ids.push(ino);
        }
    }

    // Recurse into subdirectories
    if let Ok(entries) = fs::read_dir(path) {
        for entry in entries.flatten() {
            if let Ok(ft) = entry.file_type() {
                if ft.is_dir() {
                    collect_cgroup_ids_recursive(&entry.path(), ids);
                }
            }
        }
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
    let nr_cpus = topo.nr_cpus;

    // Build LLC topology (auto-detect from sysfs).
    let llc_topo = LlcTopology::new(TopologySource::Sysfs, nr_cpus)
        .context("Failed to detect LLC topology")?;
    let nr_llc = llc_topo.nr_llcs;

    topo.print_summary(&llc_topo);

    info!("Loading scx_mitosis BPF program...");
    info!("  nr_llc             = {}", nr_llc);
    info!("  enable_llc_awareness = {}", opts.enable_llc_awareness);
    info!("  enable_work_stealing = {}", opts.enable_work_stealing);
    info!("  monitor_interval   = {}s", opts.monitor_interval_s);
    info!("  reconfig_interval  = {}s", opts.reconfiguration_interval_s);
    info!("  rebalance_interval = {}s", opts.rebalance_cpus_interval_s);

    // ── Load BPF with global overrides ───────────────────────────────
    let llc_aware: u8 = opts.enable_llc_awareness as u8;
    let work_stealing: u8 = opts.enable_work_stealing as u8;
    let smt: u8 = topo.smt_enabled as u8;
    let nr_cpus_u32 = nr_cpus as u32;
    let debug_events: u8 = opts.debug_events as u8;
    let cpu_ctrl_disabled: u8 = opts.cpu_controller_disabled as u8;
    let reject_pin: u8 = opts.reject_multicpu_pinning as u8;

    // Build ALL_CPUS bitmask (1 bit per CPU, up to 512 CPUs = 64 bytes).
    // The BPF side uses this to know which CPUs are present.
    let mut all_cpus = [0u8; 64]; // MAX_CPUS / 8
    for cpu in 0..nr_cpus.min(512) {
        all_cpus[cpu / 8] |= 1 << (cpu % 8);
    }

    // SCX_SLICE_DFL = 20ms (matches kernel default, see include/linux/sched/ext.h)
    let slice_ns: u64 = 20_000_000;
    let root_cgid: u64 = 1; // Root cgroup kn->id (always 1 on unified hierarchy)

    // Collect cgroup IDs for init-time walk (only when CPU controller disabled).
    // Userspace walks /sys/fs/cgroup and collects inode numbers (= kn->id),
    // which the BPF side uses to proactively initialize cgrp_ctx for all
    // pre-existing cgroups. Any cgroups beyond MAX_INIT_CGRPS are lazily
    // initialized via init_task's fallback path.
    let mut init_cgrp_ids = [0u64; MAX_INIT_CGRPS];
    let nr_init_cgrps: u32 = if opts.cpu_controller_disabled {
        let ids = collect_cgroup_ids();
        let nr = ids.len().min(MAX_INIT_CGRPS);
        for (i, &id) in ids.iter().take(MAX_INIT_CGRPS).enumerate() {
            init_cgrp_ids[i] = id;
        }
        info!("Collected {} cgroup IDs for init-time walk (max {})",
              nr, MAX_INIT_CGRPS);
        nr as u32
    } else {
        0
    };

    // Remaining: llc_to_cpus[] (LlcCpumask array — 1024 bytes per entry,
    // exceeds override_global size limit; needs BpfArray map instead)

    let mut ebpf = EbpfLoader::new()
        .allow_unsupported_maps()
        .override_global("NR_LLC", &nr_llc, false)
        .override_global("ENABLE_LLC_AWARENESS", &llc_aware, false)
        .override_global("ENABLE_WORK_STEALING", &work_stealing, false)
        .override_global("SMT_ENABLED", &smt, false)
        .override_global("NR_POSSIBLE_CPUS", &nr_cpus_u32, false)
        .override_global("DEBUG_EVENTS_ENABLED", &debug_events, false)
        .override_global("CPU_CONTROLLER_DISABLED", &cpu_ctrl_disabled, false)
        .override_global("REJECT_MULTICPU_PINNING", &reject_pin, false)
        .override_global("CPU_TO_LLC", &llc_topo.cpu_to_llc, false)
        .override_global("ALL_CPUS", &all_cpus, false)
        .override_global("SLICE_NS", &slice_ns, false)
        .override_global("ROOT_CGID", &root_cgid, false)
        .override_global("INIT_CGRP_IDS", &init_cgrp_ids, false)
        .override_global("NR_INIT_CGRPS", &nr_init_cgrps, false)
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

    // ── Set up stats reader ──────────────────────────────────────────
    let stats_reader = BpfStatsReader::find(&ebpf, nr_cpus);
    if stats_reader.is_none() {
        info!("CPU_CTX map not found or layout mismatch — stats will show zeroes");
    }

    // ── Set up Ctrl-C handler ────────────────────────────────────────
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })
    .context("Failed to set Ctrl-C handler")?;

    // ── Main scheduler loop ─────────────────────────────────────────
    //
    // Every stats_interval:
    //   1. Read CPU_CTX percpu array, aggregate per-cell stats
    //   2. Compute deltas from last snapshot
    //   3. Print stats line (dispatches/s, queue distribution, etc.)
    //   4. Check if scheduler is still attached

    let stats_interval = Duration::from_secs(2);
    let start_time = Instant::now();
    let mut last_stats = Instant::now();
    let mut stats_collector = stats::StatsCollector::new();

    while running.load(Ordering::SeqCst) {
        std::thread::sleep(Duration::from_millis(100));

        if last_stats.elapsed() >= stats_interval {
            let uptime = start_time.elapsed();
            let elapsed_secs = last_stats.elapsed().as_secs_f64();

            // Check if the kernel detached us.
            if !is_scheduler_attached() {
                eprintln!(
                    "\nscx_mitosis: scheduler was detached by the kernel (uptime {})",
                    format_uptime(uptime),
                );
                break;
            }

            // Read and aggregate stats from BPF percpu map.
            if let Some(ref reader) = stats_reader {
                match reader.read_aggregated_stats() {
                    Ok((aggregated, cell_cpus)) => {
                        let delta = stats_collector.calculate_cell_stat_delta(&aggregated);
                        stats_collector.update_metrics(&delta);
                        stats_collector.metrics.num_cells =
                            cell_cpus.len().max(1) as u32;

                        // Update per-cell CPU counts.
                        for (&cell_id, &cpu_count) in &cell_cpus {
                            stats_collector
                                .metrics
                                .cells
                                .entry(cell_id)
                                .or_default()
                                .num_cpus = cpu_count;
                        }

                        // Compute rate.
                        let decisions = stats_collector.metrics.total_decisions;
                        let rate = if elapsed_secs > 0.0 {
                            (decisions as f64 / elapsed_secs) as u64
                        } else {
                            0
                        };

                        if decisions > 0 {
                            println!(
                                "[scx_mitosis] {:>7}/s  {}  uptime {}",
                                rate,
                                stats_collector.format_summary(),
                                format_uptime(uptime),
                            );

                            if opts.verbose {
                                print!("{}", stats_collector.format_detailed());
                            }
                        } else {
                            println!(
                                "[scx_mitosis] cells: {}  uptime {}",
                                stats_collector.metrics.num_cells,
                                format_uptime(uptime),
                            );
                        }
                    }
                    Err(e) => {
                        debug!("Failed to read CPU_CTX: {}", e);
                        println!(
                            "[scx_mitosis] cells: 1  uptime {}  (stats read failed)",
                            format_uptime(uptime),
                        );
                    }
                }
            } else {
                println!(
                    "[scx_mitosis] cells: 1  uptime {}",
                    format_uptime(uptime),
                );
            }

            last_stats = Instant::now();
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
