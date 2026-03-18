// SPDX-License-Identifier: GPL-2.0
//
// scx_cosmos userspace loader — pure Rust BPF scheduler
//
// CLI options, CPU topology detection, utilization polling, periodic stats,
// and BPF global configuration.

use std::collections::BTreeMap;
use std::fs;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use aya::{EbpfLoader, include_bytes_aligned};
use clap::Parser;
use log::info;

/// CPU time snapshot from /proc/stat, used for utilization computation.
#[derive(Debug, Clone, Copy)]
struct CpuTimes {
    /// Time spent in user mode.
    user: u64,
    /// Time spent in nice (low-priority user) mode.
    nice: u64,
    /// Total CPU time across all modes (user + nice + system + idle + ...).
    total: u64,
}

/// scx_cosmos: lightweight deadline + vruntime scheduler (pure Rust BPF).
#[derive(Debug, Parser)]
#[command(name = "scx_cosmos")]
struct Opts {
    /// Maximum scheduling time slice in microseconds.
    ///
    /// Controls the maximum time a task can run before being preempted.
    /// Lower values improve latency; higher values improve throughput.
    #[clap(short = 's', long, default_value = "10")]
    slice_us: u64,

    /// CPU busy threshold (0-100%).
    ///
    /// When overall CPU utilization exceeds this threshold, the scheduler
    /// switches from per-CPU round-robin dispatch (locality-optimized) to a
    /// global deadline-based dispatch queue (load-balancing-optimized).
    ///
    /// Lower values make the scheduler switch to deadline mode sooner,
    /// improving responsiveness at the cost of cache locality.
    /// Higher values keep tasks sticky to their CPU longer.
    #[clap(short = 'c', long, default_value = "75")]
    cpu_busy_thresh: u64,

    /// Disable synchronous wakeup hints.
    ///
    /// When enabled, the scheduler will not perform direct dispatch on
    /// synchronous wakeups. This can lead to more uniform load distribution
    /// but may reduce efficiency for pipe-intensive workloads.
    #[clap(short = 'w', long, action = clap::ArgAction::SetTrue)]
    no_wake_sync: bool,

    /// Scheduler timeout in milliseconds.
    ///
    /// Maximum time the scheduler can stall before the kernel takes over.
    #[clap(short = 't', long, default_value = "5000")]
    timeout_ms: u64,

    /// Enable NUMA-aware scheduling.
    ///
    /// When enabled, the scheduler will attempt to keep tasks on their
    /// NUMA node. Automatically enabled when multiple NUMA nodes are
    /// detected and not explicitly disabled.
    #[clap(long, default_value = "true", action = clap::ArgAction::Set)]
    numa: bool,

    /// Override SMT contention avoidance.
    ///
    /// When enabled, the scheduler aggressively avoids placing tasks on
    /// sibling SMT threads. Defaults to true when SMT is detected.
    /// Use --avoid-smt=false to disable.
    #[clap(long)]
    avoid_smt: Option<bool>,

    /// PMU perf event configuration (hex hardware counter ID).
    ///
    /// When set to a non-zero value, the scheduler tracks hardware performance
    /// counters per task and per CPU, and uses them to distribute event-heavy
    /// tasks across CPUs more evenly.
    ///
    /// Common values (x86):
    ///   0xC0 — retired instructions
    ///   0x3C — unhalted core cycles
    ///
    /// Default: 0 (disabled).
    #[clap(long, default_value = "0", value_parser = parse_hex_u64)]
    perf_config: u64,

    /// PMU perf event threshold for event-heavy task classification.
    ///
    /// When a task's per-run perf event count exceeds this threshold, it is
    /// considered "event-heavy" and may be migrated to a less busy CPU.
    /// Only meaningful when --perf-config is non-zero.
    ///
    /// Default: 0 (auto / unused).
    #[clap(long, default_value = "0")]
    perf_threshold: u64,

    /// Enable preferred idle scan for big.LITTLE systems.
    ///
    /// When enabled, the scheduler iterates CPUs in descending capacity
    /// order to find idle ones, preferring high-performance cores.
    /// Falls back to the kernel's default idle CPU selection if none found.
    /// Automatically populates PREFERRED_CPUS from sysfs cpu_capacity.
    #[clap(long, action = clap::ArgAction::SetTrue)]
    preferred_idle_scan: bool,

    /// Enable flat idle scan for big.LITTLE systems.
    ///
    /// When enabled, the scheduler iterates ALL CPUs in preferred capacity
    /// order rather than using the kernel's default select_cpu_dfl.
    /// More aggressive than --preferred-idle-scan: skips select_cpu_dfl
    /// entirely when a preferred idle CPU is found.
    /// Automatically populates PREFERRED_CPUS from sysfs cpu_capacity.
    #[clap(long, action = clap::ArgAction::SetTrue)]
    flat_idle_scan: bool,

    /// Enable verbose logging output.
    #[clap(short = 'v', long, action = clap::ArgAction::SetTrue)]
    verbose: bool,
}

/// Parse a u64 value from a string, supporting both decimal and hex (0x...) formats.
fn parse_hex_u64(s: &str) -> Result<u64, String> {
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).map_err(|e| format!("invalid hex value '{}': {}", s, e))
    } else {
        s.parse::<u64>().map_err(|e| format!("invalid value '{}': {}", s, e))
    }
}

// ── CPU Topology ─────────────────────────────────────────────────────────

/// Detected CPU topology from sysfs.
struct Topology {
    /// Total number of possible CPUs.
    nr_cpus: usize,
    /// NUMA node ID -> list of CPU IDs in that node.
    numa_nodes: BTreeMap<u32, Vec<u32>>,
    /// Whether any CPU has an SMT sibling.
    smt_enabled: bool,
    /// Whether CPUs have heterogeneous capacities (big.LITTLE).
    has_big_little: bool,
}

impl Topology {
    /// Detect CPU topology from sysfs.
    fn detect() -> Result<Self> {
        let nr_cpus = Self::read_nr_cpus()?;
        let numa_nodes = Self::read_numa_nodes();
        let smt_enabled = Self::detect_smt(nr_cpus);
        let has_big_little = Self::detect_big_little(nr_cpus);

        Ok(Self {
            nr_cpus,
            numa_nodes,
            smt_enabled,
            has_big_little,
        })
    }

    /// Read number of possible CPUs from /sys/devices/system/cpu/possible.
    ///
    /// The file contains a CPU range like "0-175" or "0-7".
    fn read_nr_cpus() -> Result<usize> {
        let content = fs::read_to_string("/sys/devices/system/cpu/possible")
            .context("Failed to read /sys/devices/system/cpu/possible")?;
        let content = content.trim();

        // Parse "0-N" format -> N+1 CPUs, or just "0" -> 1 CPU.
        // Also handles comma-separated ranges like "0-3,8-11".
        let mut max_cpu: usize = 0;
        for range in content.split(',') {
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

    /// Read NUMA node topology from /sys/devices/system/node/node*/cpulist.
    ///
    /// Returns a map of node_id -> CPU list. If sysfs is not available,
    /// returns a single node containing all CPUs.
    fn read_numa_nodes() -> BTreeMap<u32, Vec<u32>> {
        let mut nodes = BTreeMap::new();

        // List /sys/devices/system/node/ for node* directories.
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

                let cpulist_path = format!(
                    "/sys/devices/system/node/{}/cpulist",
                    name_str
                );
                if let Ok(content) = fs::read_to_string(&cpulist_path) {
                    let cpus = Self::parse_cpu_list(content.trim());
                    if !cpus.is_empty() {
                        nodes.insert(node_id, cpus);
                    }
                }
            }
        }

        // Fallback: if no NUMA info found, create a single node.
        if nodes.is_empty() {
            // We don't have nr_cpus here, but a single empty node is
            // sufficient to signal "no NUMA".
            nodes.insert(0, Vec::new());
        }

        nodes
    }

    /// Detect if SMT (hyperthreading) is enabled by reading
    /// /sys/devices/system/cpu/cpu*/topology/thread_siblings_list.
    ///
    /// Returns true if any CPU has more than one sibling (including itself).
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

    /// Detect big.LITTLE (heterogeneous CPU capacity) by reading
    /// /sys/devices/system/cpu/cpu*/cpu_capacity.
    ///
    /// Returns true if CPUs have different capacity values.
    fn detect_big_little(nr_cpus: usize) -> bool {
        let mut first_capacity: Option<u64> = None;
        for cpu in 0..nr_cpus {
            let path = format!(
                "/sys/devices/system/cpu/cpu{}/cpu_capacity",
                cpu
            );
            if let Ok(content) = fs::read_to_string(&path) {
                if let Ok(cap) = content.trim().parse::<u64>() {
                    match first_capacity {
                        None => first_capacity = Some(cap),
                        Some(first) if cap != first => return true,
                        _ => {}
                    }
                }
            }
        }
        false
    }

    /// Read per-CPU capacity values from sysfs.
    ///
    /// Returns a Vec of (cpu_id, capacity) tuples for all CPUs that have
    /// a readable cpu_capacity file. When cpu_capacity is not available
    /// (common on homogeneous x86 servers), returns all CPUs with a
    /// default capacity of 1024 (maximum).
    fn read_cpu_capacities(nr_cpus: usize) -> Vec<(u32, u64)> {
        let mut caps = Vec::new();
        let mut any_found = false;
        for cpu in 0..nr_cpus {
            let path = format!(
                "/sys/devices/system/cpu/cpu{}/cpu_capacity",
                cpu
            );
            if let Ok(content) = fs::read_to_string(&path) {
                if let Ok(cap) = content.trim().parse::<u64>() {
                    caps.push((cpu as u32, cap));
                    any_found = true;
                }
            }
        }

        // If no cpu_capacity files exist (homogeneous server), populate
        // all CPUs with default capacity so preferred scan still works.
        if !any_found {
            for cpu in 0..nr_cpus {
                caps.push((cpu as u32, 1024));
            }
        }

        caps
    }

    /// Build the preferred CPU order: sorted by capacity descending.
    ///
    /// Returns (preferred_cpus, cpu_capacity) arrays suitable for writing
    /// to the BPF globals. preferred_cpus is terminated by -1 sentinel.
    /// cpu_capacity is indexed by CPU ID.
    fn build_preferred_cpu_arrays(nr_cpus: usize) -> ([i32; 1024], [u64; 1024]) {
        let mut preferred_cpus = [-1i32; 1024];
        let mut cpu_capacity = [0u64; 1024];

        let mut caps = Self::read_cpu_capacities(nr_cpus);

        // Populate cpu_capacity array (indexed by CPU ID).
        for &(cpu, cap) in &caps {
            if (cpu as usize) < 1024 {
                cpu_capacity[cpu as usize] = cap;
            }
        }

        // Sort by capacity descending (big cores first), stable sort
        // preserves CPU order within same capacity.
        caps.sort_by(|a, b| b.1.cmp(&a.1));

        // Fill preferred_cpus in sorted order.
        for (i, &(cpu, _cap)) in caps.iter().enumerate() {
            if i >= 1024 {
                break;
            }
            preferred_cpus[i] = cpu as i32;
        }

        (preferred_cpus, cpu_capacity)
    }

    /// Parse a CPU list string like "0-3,8-11" into a sorted Vec of CPU IDs.
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

    /// Print a human-readable summary of the detected topology.
    fn print_summary(&self) {
        println!("Topology:");
        println!("  CPUs: {}", self.nr_cpus);
        println!(
            "  NUMA nodes: {} ({})",
            self.numa_nodes.len(),
            if self.numa_nodes.len() > 1 {
                "multi-node"
            } else {
                "single-node"
            }
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
            if self.smt_enabled {
                "enabled"
            } else {
                "disabled"
            }
        );
        if self.has_big_little {
            println!("  CPU capacity: heterogeneous (big.LITTLE)");
        }
    }

    /// Format a list of CPU IDs as a compact range string (e.g., "0-3,8-11").
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
}

// ── CPU utilization ──────────────────────────────────────────────────────

/// Read aggregate CPU times from /proc/stat.
///
/// Parses the first "cpu " line which contains totals across all CPUs.
/// Returns None if /proc/stat can't be read or parsed.
fn read_cpu_times() -> Option<CpuTimes> {
    let file = File::open("/proc/stat").ok()?;
    let reader = BufReader::new(file);

    for line in reader.lines() {
        let line = line.ok()?;
        if line.starts_with("cpu ") {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 5 {
                return None;
            }

            let user: u64 = fields[1].parse().ok()?;
            let nice: u64 = fields[2].parse().ok()?;

            // Sum the first 8 fields as total time:
            // user, nice, system, idle, iowait, irq, softirq, steal
            let total: u64 = fields
                .iter()
                .skip(1)
                .take(8)
                .filter_map(|v| v.parse::<u64>().ok())
                .sum();

            return Some(CpuTimes { user, nice, total });
        }
    }

    None
}

/// Compute CPU utilization percentage [0..100] between two snapshots.
///
/// Uses (user + nice) as the "busy" time, matching the C cosmos approach
/// of tracking user-mode CPU utilization.
fn compute_cpu_util(prev: &CpuTimes, curr: &CpuTimes) -> Option<u64> {
    let busy_diff = (curr.user + curr.nice).saturating_sub(prev.user + prev.nice);
    let total_diff = curr.total.saturating_sub(prev.total);

    if total_diff > 0 {
        // Return percentage [0..100]
        Some((busy_diff * 100) / total_diff)
    } else {
        None
    }
}

// ── BPF data map runtime updates ─────────────────────────────────────────

/// Update a u64 value in a BPF data-section map at a given byte offset.
///
/// BPF `.bss` and `.data` maps are exposed as single-entry arrays (key=0)
/// where the value is the entire section blob. To update a specific global
/// variable, we:
///   1. Read the current blob with BPF_MAP_LOOKUP_ELEM
///   2. Patch the u64 at the given offset
///   3. Write the blob back with BPF_MAP_UPDATE_ELEM
///
/// This uses raw libc::syscall because aya's typed Array API enforces a
/// fixed value type size that doesn't match the variable-sized section blob.
fn update_map_u64(map_fd: i32, value_size: usize, offset: usize, val: u64) -> Result<()> {
    if offset + 8 > value_size {
        anyhow::bail!(
            "CPU_UTIL offset {} + 8 exceeds map value size {}",
            offset,
            value_size
        );
    }

    let key: u32 = 0;
    let mut buf = vec![0u8; value_size];

    // BPF_MAP_LOOKUP_ELEM = 1
    #[repr(C)]
    #[derive(Default)]
    #[allow(non_camel_case_types)]
    struct bpf_attr_lookup {
        map_fd: u32,
        _pad0: u32,
        key: u64,
        value: u64,
        flags: u64,
    }

    let mut attr = bpf_attr_lookup {
        map_fd: map_fd as u32,
        key: &key as *const u32 as u64,
        value: buf.as_mut_ptr() as u64,
        ..Default::default()
    };

    let ret = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            1i32, // BPF_MAP_LOOKUP_ELEM
            &mut attr as *mut _ as *mut libc::c_void,
            core::mem::size_of::<bpf_attr_lookup>(),
        )
    };
    if ret < 0 {
        anyhow::bail!(
            "BPF_MAP_LOOKUP_ELEM failed: {}",
            std::io::Error::last_os_error()
        );
    }

    // Patch CPU_UTIL at the given offset.
    buf[offset..offset + 8].copy_from_slice(&val.to_ne_bytes());

    // BPF_MAP_UPDATE_ELEM = 2
    let mut attr = bpf_attr_lookup {
        map_fd: map_fd as u32,
        key: &key as *const u32 as u64,
        value: buf.as_ptr() as u64,
        ..Default::default()
    };

    let ret = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            2i32, // BPF_MAP_UPDATE_ELEM
            &mut attr as *mut _ as *mut libc::c_void,
            core::mem::size_of::<bpf_attr_lookup>(),
        )
    };
    if ret < 0 {
        anyhow::bail!(
            "BPF_MAP_UPDATE_ELEM failed: {}",
            std::io::Error::last_os_error()
        );
    }

    Ok(())
}

/// Represents the BPF data map context for runtime global updates.
///
/// Created by probing the loaded BPF object for `.bss` or `.data` maps
/// and locating the CPU_UTIL global's offset within the section blob.
struct BpfDataMap {
    fd: i32,
    value_size: usize,
    cpu_util_offset: usize,
}

impl BpfDataMap {
    /// Try to locate the CPU_UTIL global in the BPF data maps.
    ///
    /// Checks `.bss` first (zero-initialized globals), then `.data`
    /// (initialized globals). Returns None if neither map exists or
    /// the CPU_UTIL symbol is not found.
    fn find(ebpf: &mut aya::Ebpf) -> Option<Self> {
        // Try .bss first (zero-initialized statics like `static mut CPU_UTIL: u64 = 0`)
        // then .data (initialized statics).
        for map_name in &[".bss", ".data"] {
            if let Some(map) = ebpf.map_mut(map_name) {
                let map_data = match map {
                    aya::maps::Map::Array(ref data) => data,
                    _ => continue,
                };

                let fd = map_data.fd().as_fd().as_raw_fd();
                let value_size = match map_data.info() {
                    Ok(info) => info.value_size() as usize,
                    Err(_) => continue,
                };

                // The CPU_UTIL offset depends on the BPF program's global layout.
                // With the current eBPF code, the .bss section contains:
                //   VTIME_NOW: u64 (offset 0)
                //   NR_CPU_IDS: u32 (offset 8)
                //   <padding>: u32 (offset 12, for alignment)
                //   CPU_UTIL: u64 (offset 16)
                //
                // Once the other agent adds the CPU_UTIL global to the eBPF
                // code, this offset must match the actual layout. We validate
                // that the offset fits within the map value.
                let cpu_util_offset = 16;

                if cpu_util_offset + 8 <= value_size {
                    info!(
                        "Found {} map: fd={}, value_size={}, CPU_UTIL offset={}",
                        map_name, fd, value_size, cpu_util_offset
                    );
                    return Some(Self {
                        fd,
                        value_size,
                        cpu_util_offset,
                    });
                } else {
                    info!(
                        "{} map too small ({} bytes) for CPU_UTIL at offset {}",
                        map_name, value_size, cpu_util_offset
                    );
                }
            }
        }

        None
    }

    /// Update CPU_UTIL in the BPF data map.
    fn update_cpu_util(&self, util: u64) -> Result<()> {
        update_map_u64(self.fd, self.value_size, self.cpu_util_offset, util)
    }
}

// ── Formatting helpers ───────────────────────────────────────────────────

/// Format a Duration as "Xh Ym Zs" or "Xm Zs" or "Zs".
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

// ── PMU perf event setup ─────────────────────────────────────────────────

/// Minimal `perf_event_attr` for `perf_event_open(2)`.
///
/// Only the fields needed for raw hardware event configuration are defined;
/// the rest are zero-initialized via `..Default::default()`.
#[repr(C)]
#[derive(Default)]
struct PerfEventAttr {
    type_: u32,
    size: u32,
    config: u64,
    sample_period_or_freq: u64,
    sample_type: u64,
    read_format: u64,
    flags: u64,
    wakeup_events_or_watermark: u32,
    bp_type: u32,
    bp_addr_or_config1: u64,
    bp_len_or_config2: u64,
    branch_sample_type: u64,
    sample_regs_user: u64,
    sample_stack_user: u32,
    clockid: i32,
    sample_regs_intr: u64,
    aux_watermark: u32,
    sample_max_stack: u16,
    _reserved_2: u16,
    aux_sample_size: u32,
    _reserved_3: u32,
    sig_data: u64,
    config3: u64,
}

/// PERF_TYPE_RAW = 4
const PERF_TYPE_RAW: u32 = 4;

/// Set up perf events for hardware counter tracking.
///
/// For each CPU, opens a raw perf event with the given config and stores
/// the fd in the BPF PERF_EVENT_ARRAY map. Returns the list of OwnedFds
/// (they must stay alive for the scheduler's lifetime).
///
/// On failure (e.g., no PMU support, invalid config), logs a warning and
/// returns an empty Vec — the scheduler continues without PMU tracking.
fn setup_perf_events(
    ebpf: &mut aya::Ebpf,
    nr_cpus: usize,
    perf_config: u64,
) -> Vec<OwnedFd> {
    let mut fds = Vec::new();

    // Find the SCX_PMU_MAP in the loaded BPF object.
    let map = match ebpf.map_mut("SCX_PMU_MAP") {
        Some(m) => m,
        None => {
            log::warn!("SCX_PMU_MAP not found in BPF object — PMU tracking disabled");
            return fds;
        }
    };
    // Extract the inner MapData to get the raw fd.
    let map_fd = match map {
        aya::maps::Map::PerfEventArray(ref data) => data.fd().as_fd().as_raw_fd(),
        _ => {
            log::warn!("SCX_PMU_MAP has unexpected map type — PMU tracking disabled");
            return fds;
        }
    };

    for cpu in 0..nr_cpus {
        let mut attr = PerfEventAttr {
            type_: PERF_TYPE_RAW,
            size: core::mem::size_of::<PerfEventAttr>() as u32,
            config: perf_config,
            ..Default::default()
        };

        // perf_event_open(attr, pid=-1 (all), cpu, group_fd=-1, flags=0)
        let fd = unsafe {
            libc::syscall(
                libc::SYS_perf_event_open,
                &mut attr as *mut PerfEventAttr,
                -1i32,      // pid: all processes
                cpu as i32, // cpu
                -1i32,      // group_fd: no group
                0u64,       // flags
            )
        };

        if fd < 0 {
            let err = std::io::Error::last_os_error();
            log::warn!(
                "perf_event_open(config=0x{:X}) failed on CPU {}: {} — PMU tracking disabled",
                perf_config,
                cpu,
                err,
            );
            // Return what we have; partial setup is worse than none since
            // the BPF side would read stale/zero values for unconfigured CPUs.
            return Vec::new();
        }

        let owned_fd = unsafe { OwnedFd::from_raw_fd(fd as i32) };

        // Store the fd in the BPF map: key = cpu index, value = fd
        // Uses BPF_MAP_UPDATE_ELEM syscall directly.
        let key: u32 = cpu as u32;
        let value: u32 = fd as u32;

        #[repr(C)]
        #[derive(Default)]
        struct BpfMapUpdate {
            map_fd: u32,
            _pad0: u32,
            key: u64,
            value: u64,
            flags: u64,
        }

        let mut update_attr = BpfMapUpdate {
            map_fd: map_fd as u32,
            key: &key as *const u32 as u64,
            value: &value as *const u32 as u64,
            ..Default::default()
        };

        let ret = unsafe {
            libc::syscall(
                libc::SYS_bpf,
                2i32, // BPF_MAP_UPDATE_ELEM
                &mut update_attr as *mut _ as *mut libc::c_void,
                core::mem::size_of::<BpfMapUpdate>(),
            )
        };

        if ret < 0 {
            let err = std::io::Error::last_os_error();
            log::warn!(
                "Failed to store perf fd in SCX_PMU_MAP for CPU {}: {} — PMU tracking disabled",
                cpu,
                err,
            );
            return Vec::new();
        }

        fds.push(owned_fd);
    }

    info!(
        "PMU perf events installed: config=0x{:X}, {} CPUs",
        perf_config,
        fds.len(),
    );

    fds
}

// ── Main ─────────────────────────────────────────────────────────────────

fn main() -> Result<()> {
    let opts = Opts::parse();

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

    // ── Topology detection ───────────────────────────────────────────
    let topo = Topology::detect()
        .context("Failed to detect CPU topology")?;
    topo.print_summary();

    // Determine NUMA awareness: enable only if CLI allows AND multiple nodes exist.
    let nr_numa_nodes = topo.numa_nodes.values().filter(|cpus| !cpus.is_empty()).count();
    let numa_enabled = opts.numa && nr_numa_nodes > 1;
    if !numa_enabled && nr_numa_nodes > 1 {
        println!("  NUMA awareness: disabled (--no-numa)");
    } else if numa_enabled {
        println!("  NUMA awareness: enabled ({} nodes)", nr_numa_nodes);
    } else {
        println!("  NUMA awareness: disabled (single node)");
    }

    // Determine SMT avoidance: default to smt_enabled unless overridden.
    let avoid_smt = opts.avoid_smt.unwrap_or(topo.smt_enabled);
    println!(
        "  SMT avoidance: {}",
        if avoid_smt { "enabled" } else { "disabled" }
    );

    // ── Compute BPF global values ────────────────────────────────────
    let slice_ns: u64 = opts.slice_us * 1000;
    let slice_lag: u64 = (opts.slice_us * 2000).min(20_000_000);
    let busy_threshold: u64 = opts.cpu_busy_thresh;
    let no_wake_sync: bool = opts.no_wake_sync;

    info!("Loading scx_cosmos BPF program...");
    info!("  slice_ns     = {} ns ({} us)", slice_ns, opts.slice_us);
    info!(
        "  slice_lag    = {} ns ({} us, capped at 20ms)",
        slice_lag,
        slice_lag / 1000
    );
    info!("  busy_thresh  = {}%", busy_threshold);
    info!("  no_wake_sync = {}", no_wake_sync);
    info!("  smt_enabled  = {}", topo.smt_enabled);
    info!("  avoid_smt    = {}", avoid_smt);
    info!("  timeout_ms   = {}", opts.timeout_ms);
    if opts.perf_config != 0 {
        info!("  perf_config  = 0x{:X}", opts.perf_config);
        info!("  perf_thresh  = {}", opts.perf_threshold);
    } else {
        info!("  perf_config  = 0 (PMU disabled)");
    }

    // ── Build preferred CPU arrays for idle scan modes ────────────────
    let preferred_idle_scan = opts.preferred_idle_scan;
    let flat_idle_scan = opts.flat_idle_scan;

    // Build the capacity-sorted CPU arrays when either scan mode is enabled.
    let (preferred_cpus, cpu_capacity) = if preferred_idle_scan || flat_idle_scan {
        let (pref, cap) = Topology::build_preferred_cpu_arrays(topo.nr_cpus);

        // Log the preferred CPU order.
        let count = pref.iter().take_while(|&&c| c >= 0).count();
        let top_cpus: Vec<String> = pref.iter()
            .take_while(|&&c| c >= 0)
            .take(8)
            .map(|c| format!("{}", c))
            .collect();
        info!(
            "  idle_scan    = {} ({} CPUs, preferred order: {}{})",
            if flat_idle_scan { "flat" } else { "preferred" },
            count,
            top_cpus.join(", "),
            if count > 8 { ", ..." } else { "" },
        );
        if !topo.has_big_little {
            info!("  NOTE: All CPUs have the same capacity (no big.LITTLE detected).");
            info!("         Preferred scan order is arbitrary but functional.");
        }
        (pref, cap)
    } else {
        ([-1i32; 1024], [0u64; 1024])
    };

    // ── Load BPF with global overrides ───────────────────────────────
    //
    // override_global with must_exist=false silently skips globals that
    // don't exist in the BPF object yet (another agent is adding these).
    let smt_enabled_val: u8 = topo.smt_enabled as u8;
    let avoid_smt_val: u8 = avoid_smt as u8;

    let mut ebpf = EbpfLoader::new()
        .allow_unsupported_maps()
        .override_global("SLICE_NS", &slice_ns, false)
        .override_global("SLICE_LAG", &slice_lag, false)
        .override_global("BUSY_THRESHOLD", &busy_threshold, false)
        .override_global("NO_WAKE_SYNC", &(no_wake_sync as u8), false)
        .override_global("SMT_ENABLED", &smt_enabled_val, false)
        .override_global("AVOID_SMT", &avoid_smt_val, false)
        .override_global("PERF_CONFIG", &opts.perf_config, false)
        .override_global("PERF_THRESHOLD", &opts.perf_threshold, false)
        .override_global("PREFERRED_IDLE_SCAN", &(preferred_idle_scan as u8), false)
        .override_global("FLAT_IDLE_SCAN", &(flat_idle_scan as u8), false)
        .override_global("PREFERRED_CPUS", &preferred_cpus, false)
        .override_global("CPU_CAPACITY", &cpu_capacity, false)
        .load(include_bytes_aligned!(concat!(
            env!("OUT_DIR"),
            "/scx_cosmos"
        )))
        .context("Failed to load BPF object")?;

    // Locate the BPF data map for runtime CPU_UTIL updates.
    let bpf_data = BpfDataMap::find(&mut ebpf);
    if bpf_data.is_none() {
        info!("No .bss/.data map found for CPU_UTIL updates (BPF globals may not be added yet)");
    }

    // Set up PMU perf events if configured.
    // The returned fds must stay alive for the scheduler's lifetime.
    let _perf_fds = if opts.perf_config != 0 {
        setup_perf_events(&mut ebpf, topo.nr_cpus, opts.perf_config)
    } else {
        Vec::new()
    };

    // Attach the struct_ops scheduler.
    let link = ebpf
        .attach_struct_ops("_scx_ops")
        .context("Failed to attach struct_ops scheduler")?;

    println!();
    println!("scx_cosmos: scheduler attached (pure Rust BPF)");
    println!("  slice       = {} us", opts.slice_us);
    println!("  slice_lag   = {} us (capped at 20ms)", slice_lag / 1000);
    println!("  busy_thresh = {}%", opts.cpu_busy_thresh);
    println!(
        "  wake_sync   = {}",
        if opts.no_wake_sync {
            "disabled"
        } else {
            "enabled"
        }
    );
    println!(
        "  smt_avoid   = {}",
        if avoid_smt { "yes" } else { "no" }
    );
    println!("  timeout     = {} ms", opts.timeout_ms);
    if preferred_idle_scan || flat_idle_scan {
        println!(
            "  idle_scan   = {}",
            if flat_idle_scan { "flat" } else { "preferred" }
        );
    }
    if opts.perf_config != 0 {
        println!("  perf_config = 0x{:X}", opts.perf_config);
        println!("  perf_thresh = {}", opts.perf_threshold);
        if _perf_fds.is_empty() {
            println!("  perf_status = DISABLED (perf_event_open failed or map not found)");
        } else {
            println!("  perf_status = active ({} CPUs)", _perf_fds.len());
        }
    }
    println!("Press Ctrl-C to detach and exit.");

    // Set up Ctrl-C handler.
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })
    .context("Failed to set Ctrl-C handler")?;

    // ── Main polling loop with periodic stats ────────────────────────
    //
    // Reads /proc/stat every 100ms and computes overall CPU utilization.
    // When a BPF data map is available, writes the utilization value to
    // the CPU_UTIL global so the BPF scheduler can use it for busy/idle
    // mode switching.
    //
    // Every 2 seconds, prints a stats summary line showing CPU
    // utilization, scheduling mode, and uptime.
    let poll_interval = Duration::from_millis(100);
    let stats_interval = Duration::from_secs(2);
    let start_time = Instant::now();
    let mut prev_cputime = read_cpu_times().expect("Failed to read initial /proc/stat");
    let mut last_poll = Instant::now();
    let mut last_stats = Instant::now();
    let mut last_util: u64 = 0;

    while running.load(Ordering::SeqCst) {
        std::thread::sleep(Duration::from_millis(10));

        if last_poll.elapsed() >= poll_interval {
            if let Some(curr_cputime) = read_cpu_times() {
                if let Some(util) = compute_cpu_util(&prev_cputime, &curr_cputime) {
                    last_util = util;

                    // Update BPF CPU_UTIL global if available.
                    if let Some(ref data_map) = bpf_data {
                        if let Err(e) = data_map.update_cpu_util(util) {
                            log::debug!("Failed to update CPU_UTIL: {}", e);
                        }
                    }
                }
                prev_cputime = curr_cputime;
            }
            last_poll = Instant::now();
        }

        // Print periodic stats every 2 seconds.
        if last_stats.elapsed() >= stats_interval {
            let uptime = start_time.elapsed();
            let mode = if last_util >= opts.cpu_busy_thresh {
                "deadline"
            } else {
                "round-robin"
            };
            println!(
                "[scx_cosmos] cpu {:>3}% [{}]  uptime {}",
                last_util,
                mode,
                format_uptime(uptime),
            );
            last_stats = Instant::now();
        }

        // Periodically log CPU utilization in verbose mode.
        if opts.verbose && last_poll.elapsed() < Duration::from_millis(20) {
            log::debug!("CPU utilization: {}%", last_util);
        }
    }

    drop(link);
    println!(
        "\nscx_cosmos: scheduler detached (last CPU util: {}%, uptime {})",
        last_util,
        format_uptime(start_time.elapsed()),
    );

    Ok(())
}
