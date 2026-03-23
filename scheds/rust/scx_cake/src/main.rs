// SPDX-License-Identifier: GPL-2.0
// scx_cake - sched_ext scheduler applying CAKE bufferbloat concepts to CPU scheduling

mod detect;
mod topology;
mod tui;

use core::sync::atomic::Ordering;
use std::io::IsTerminal;

use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::{Parser, ValueEnum};
use log::{info, warn};

use scx_arena::ArenaLib;
use scx_utils::build_id;
use scx_utils::UserExitInfo;
use scx_utils::NR_CPU_IDS;
// Include the generated interface bindings
#[allow(non_camel_case_types, non_upper_case_globals, dead_code)]
mod bpf_intf {
    include!(concat!(env!("OUT_DIR"), "/bpf_intf.rs"));
}

// Include the generated BPF skeleton
#[allow(non_camel_case_types, non_upper_case_globals, dead_code)]
mod bpf_skel {
    include!(concat!(env!("OUT_DIR"), "/bpf_skel.rs"));
}
use bpf_skel::*;

const SCHEDULER_NAME: &str = "scx_cake";

/// Scheduler profile presets
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Profile {
    /// Ultra-low-latency for competitive esports (1ms quantum)
    Esports,
    /// Optimized for older/lower-power hardware (4ms quantum)
    Legacy,
    /// Low-latency profile optimized for gaming and interactive workloads
    Gaming,
    /// Balanced profile for general desktop use (same as gaming for now)
    Default,
    /// Power-efficient profile for handhelds/laptops on battery (DVFS enabled)
    Battery,
}

impl Profile {
    /// Returns (quantum_us, new_flow_bonus_us, starvation_us)
    fn values(&self) -> (u64, u64, u64) {
        match self {
            // Esports: Ultra-aggressive, 1ms quantum for maximum responsiveness
            Profile::Esports => (1000, 4000, 50000),
            // Legacy: High efficiency, 4ms quantum to reduce overhead on older CPUs
            Profile::Legacy => (4000, 12000, 200000),
            // Gaming: Aggressive latency, 2ms quantum
            Profile::Gaming => (2000, 8000, 100000),
            // Default: Same as gaming for now
            Profile::Default => (2000, 8000, 100000),
            // Battery: 4ms quantum — fewer context switches = less power
            Profile::Battery => (4000, 12000, 200000),
        }
    }

    // DVFS — disabled (tick architecture removed, no runtime effect).
    // RODATA symbols retained in BPF for loader compat; JIT eliminates.
}

/// 🍰 scx_cake: A sched_ext scheduler applying CAKE bufferbloat concepts
///
/// This scheduler adapts CAKE's DRR++ (Deficit Round Robin++) algorithm
/// for CPU scheduling, providing low-latency scheduling for gaming and
/// interactive workloads while maintaining fairness.
///
/// PROFILES set all tuning parameters at once. Individual options override profile defaults.
///
/// 4-CLASS SYSTEM (classified by PELT utilization + game family detection):
///   GAME:    game process tree + audio + compositor (during GAMING)
///   NORMAL:  default class — interactive desktop tasks
///   HOG:     high PELT utilization (≥78% CPU) non-game tasks
///   BG:      low PELT utilization non-game tasks during GAMING
///
/// EXAMPLES:
///   scx_cake                          # Run with gaming profile (default)
///   scx_cake -p esports               # Ultra-low-latency for competitive play
///   scx_cake --quantum 1500           # Gaming profile with custom quantum
///   scx_cake -v                       # Run with live TUI stats display
#[derive(Parser, Debug, Clone)]
#[command(
    author,
    version,
    disable_version_flag = true,
    about = "🍰 A sched_ext scheduler applying CAKE bufferbloat concepts to CPU scheduling",
    verbatim_doc_comment
)]
struct Args {
    /// Scheduler profile preset.
    ///
    /// Profiles configure all tier thresholds, quantum multipliers, and wait budgets.
    /// Individual CLI options (--quantum, etc.) override profile values.
    ///
    /// ESPORTS: Ultra-low-latency for competitive gaming.
    ///   - Quantum: 1000µs, Starvation: 50ms
    ///
    /// LEGACY: Optimized for older/lower-power hardware.
    ///   - Quantum: 4000µs, Starvation: 200ms
    ///
    /// GAMING: Optimized for low-latency gaming and interactive workloads.
    ///   - Quantum: 2000µs, Starvation: 100ms
    ///
    /// DEFAULT: Balanced profile for general desktop use.
    ///   - Currently same as gaming; will diverge in future versions
    ///
    /// BATTERY: Power-efficient for handhelds/laptops on battery.
    ///   - Quantum: 4000µs, reduced context switch overhead
    #[arg(long, short, value_enum, default_value_t = Profile::Gaming, verbatim_doc_comment)]
    profile: Profile,

    /// Base scheduling time slice in MICROSECONDS [default: 2000].
    ///
    /// How long a task runs before potentially yielding.
    ///
    /// Smaller quantum = more responsive but higher overhead.
    /// Esports: 1000µs | Gaming: 2000µs | Legacy: 4000µs
    /// Recommended range: 1000-8000µs
    #[arg(long, verbatim_doc_comment)]
    quantum: Option<u64>,

    /// Bonus time for newly woken tasks in MICROSECONDS [default: 8000].
    ///
    /// Tasks waking from sleep get this extra time added to their deficit,
    /// allowing them to run longer on first dispatch. Helps bursty workloads.
    ///
    /// Esports: 4000µs | Gaming: 8000µs
    /// Recommended range: 4000-16000µs
    #[arg(long, verbatim_doc_comment)]
    new_flow_bonus: Option<u64>,

    /// Max run time before forced preemption in MICROSECONDS [default: 100000].
    ///
    /// Safety limit: tasks running longer than this are forcibly preempted.
    /// Prevents any single task from monopolizing the CPU.
    ///
    /// Esports: 50000µs (50ms) | Gaming: 100000µs (100ms) | Legacy: 200000µs (200ms)
    /// Recommended range: 50000-200000µs
    #[arg(long, verbatim_doc_comment)]
    starvation: Option<u64>,

    /// Enable live TUI (Terminal User Interface) with real-time statistics.
    ///
    /// Shows dispatch counts per tier, tier transitions,
    /// wait time stats, and system topology information.
    /// Press 'q' to exit TUI mode.
    #[arg(long, short, verbatim_doc_comment)]
    verbose: bool,

    /// Statistics refresh interval in SECONDS (only with --verbose).
    ///
    /// How often the TUI updates. Lower values = more responsive but
    /// higher overhead. Has no effect without --verbose.
    ///
    /// Default: 1 second
    #[arg(long, default_value_t = 1, verbatim_doc_comment)]
    interval: u64,

    /// Live in-kernel testing mode for automated benchmarking.
    ///
    /// Runs the scheduler for 10 seconds, collects BPF data points,
    /// and prints a structured JSON output to stdout.
    #[arg(long, verbatim_doc_comment)]
    testing: bool,

    /// Print scheduler version and exit.
    #[arg(short = 'V', long, action = clap::ArgAction::SetTrue)]
    version: bool,
}

impl Args {
    /// Get effective values (profile defaults with CLI overrides applied)
    fn effective_values(&self) -> (u64, u64, u64) {
        let (q, nfb, starv) = self.profile.values();
        (
            self.quantum.unwrap_or(q),
            self.new_flow_bonus.unwrap_or(nfb),
            self.starvation.unwrap_or(starv),
        )
    }
}

struct Scheduler<'a> {
    skel: BpfSkel<'a>,
    args: Args,
    topology: topology::TopologyInfo,
    latency_matrix: Vec<Vec<f64>>,
    struct_ops: Option<libbpf_rs::Link>,
}

impl<'a> Scheduler<'a> {
    fn new(
        args: Args,
        open_object: &'a mut std::mem::MaybeUninit<libbpf_rs::OpenObject>,
    ) -> Result<Self> {
        use libbpf_rs::skel::{OpenSkel, Skel, SkelBuilder};

        // ═══ scx_ops_open! equivalent ═══
        // Matches scx_ops_open!(skel_builder, open_object, cake_ops, None)
        // Cake can't use the macro directly (custom arena architecture),
        // so we inline the critical functionality.
        scx_utils::compat::check_min_requirements()?;

        let skel_builder = BpfSkelBuilder::default();
        let mut open_skel = skel_builder
            .open(open_object)
            .context("Failed to open BPF skeleton")?;

        // Inject version suffix into ops name: "cake" → "cake_1.1.0_g<hash>_<target>"
        // This is what scx_loader reads from /sys/kernel/sched_ext/root/ops
        {
            let ops = open_skel.struct_ops.cake_ops_mut();
            let name_field = &mut ops.name;

            let version_suffix = scx_utils::build_id::ops_version_suffix(env!("CARGO_PKG_VERSION"));
            let bytes = version_suffix.as_bytes();
            let mut i = 0;
            let mut bytes_idx = 0;
            let mut found_null = false;

            while i < name_field.len() - 1 {
                found_null |= name_field[i] == 0;
                if !found_null {
                    i += 1;
                    continue;
                }

                if bytes_idx < bytes.len() {
                    name_field[i] = bytes[bytes_idx] as i8;
                    bytes_idx += 1;
                } else {
                    break;
                }
                i += 1;
            }
            name_field[i] = 0;
        }

        // Read hotplug sequence number — enables kernel-requested restarts on CPU hotplug
        {
            let path = std::path::Path::new("/sys/kernel/sched_ext/hotplug_seq");
            let val = std::fs::read_to_string(path)
                .context("Failed to read /sys/kernel/sched_ext/hotplug_seq")?;
            open_skel.struct_ops.cake_ops_mut().hotplug_seq = val
                .trim()
                .parse::<u64>()
                .context("Failed to parse hotplug_seq")?;
        }

        // Honor SCX_TIMEOUT_MS environment variable (matches scx_ops_open! behavior)
        if let Ok(s) = std::env::var("SCX_TIMEOUT_MS") {
            let ms: u32 = s.parse().context("SCX_TIMEOUT_MS has invalid value")?;
            info!("Setting timeout_ms to {} based on environment", ms);
            open_skel.struct_ops.cake_ops_mut().timeout_ms = ms;
        }

        // Populate SCX enum RODATA from kernel BTF (SCX_DSQ_LOCAL_ON, SCX_KICK_PREEMPT, etc.)
        scx_utils::import_enums!(open_skel);

        // Detect system topology (CCDs, P/E cores)
        let topo = topology::detect()?;

        // Get effective values (profile + CLI overrides)
        let (quantum, new_flow_bonus, _starvation) = args.effective_values();

        // Latency matrix: zeroed, populated by TUI Topology tab if --verbose
        let latency_matrix = vec![vec![0.0; topo.nr_cpus]; topo.nr_cpus];

        // ALPHADEV Phase 7.3: Lockless Cache Definitions
        let mut audio_tgids: Vec<u32> = Vec::new();
        let mut compositor_tgids: Vec<u32> = Vec::new();

        // Configure the scheduler via rodata (read-only data)
        if let Some(rodata) = &mut open_skel.maps.rodata_data {
            rodata.quantum_ns = quantum * 1000;
            rodata.new_flow_bonus_ns = new_flow_bonus * 1000;
            // Stats/telemetry: only available in debug builds (CAKE_RELEASE omits the field).
            // In release, --verbose is silently ignored — zero overhead for production gaming.
            #[cfg(debug_assertions)]
            {
                rodata.enable_stats = args.verbose || args.testing;
            }

            // has_hybrid removed: smt_sibling now uses pre-filled cpu_sibling_map only
            // Per-LLC DSQ partitioning: populate CPU→LLC mapping
            let llc_count = topo.llc_cpu_mask.iter().filter(|&&m| m != 0).count() as u32;
            rodata.nr_llcs = llc_count.max(1);
            rodata.nr_cpus = topo.nr_cpus.min(topology::MAX_CPUS) as u32;
            rodata.nr_phys_cpus = topo.nr_phys_cpus.min(topology::MAX_CPUS) as u32;

            // Ferry topology arrays into BPF RODATA — compile-time scaled

            // Heterogeneous Gaming Topology — only compiled when CAKE_HAS_HYBRID
            #[cfg(cake_has_hybrid)]
            {
                for i in 0..topo
                    .big_core_phys_mask
                    .len()
                    .min(rodata.big_core_phys_mask.len())
                {
                    rodata.big_core_phys_mask[i] = topo.big_core_phys_mask[i];
                }
                for i in 0..topo
                    .big_core_smt_mask
                    .len()
                    .min(rodata.big_core_smt_mask.len())
                {
                    rodata.big_core_smt_mask[i] = topo.big_core_smt_mask[i];
                }
                for i in 0..topo
                    .little_core_mask
                    .len()
                    .min(rodata.little_core_mask.len())
                {
                    rodata.little_core_mask[i] = topo.little_core_mask[i];
                }
                rodata.has_hybrid_cores = topo.big_core_phys_mask.iter().any(|&w| w != 0);
            }
            for i in 0..topo.vcache_llc_mask.len().min(rodata.vcache_llc_mask.len()) {
                rodata.vcache_llc_mask[i] = topo.vcache_llc_mask[i];
            }
            rodata.has_vcache = topo.has_vcache;

            for i in 0..topo.cpu_sibling_map.len().min(rodata.cpu_sibling_map.len()) {
                rodata.cpu_sibling_map[i] = topo.cpu_sibling_map[i] as _;
            }
            for i in 0..topo.llc_cpu_mask.len().min(rodata.llc_cpu_mask.len()) {
                rodata.llc_cpu_mask[i] = topo.llc_cpu_mask[i];
            }
            for i in 0..topo.core_cpu_mask.len().min(rodata.core_cpu_mask.len()) {
                rodata.core_cpu_mask[i] = topo.core_cpu_mask[i];
            }

            for (i, &llc_id) in topo.cpu_llc_id.iter().enumerate() {
                rodata.cpu_llc_id[i] = llc_id as u32;
            }

            // ALPHADEV Phase 11: Multi-CCD Gaming Steer & Evict
            {
                let mut best_llc: u8 = 0;
                let mut max_rank = 0;

                if topo.has_vcache {
                    for (i, &mask) in topo.llc_cpu_mask.iter().enumerate() {
                        if mask == topo.vcache_llc_mask[0] && mask != 0 {
                            best_llc = i as u8;
                            break;
                        }
                    }
                } else if topo.nr_cpus > 1 {
                    // Fall back to amd_pstate_prefcore_ranking if symmetric.
                    for cpu in 0..topo.nr_cpus {
                        let path = format!(
                            "/sys/devices/system/cpu/cpu{}/cpufreq/amd_pstate_prefcore_ranking",
                            cpu
                        );
                        let rank = std::fs::read_to_string(&path)
                            .ok()
                            .and_then(|s| s.trim().parse::<u32>().ok())
                            .unwrap_or(100);
                        if rank > max_rank {
                            max_rank = rank;
                            best_llc = topo.cpu_llc_id[cpu] as u8;
                        }
                    }
                }

                let fallback_llc = if rodata.nr_llcs > 1 {
                    (best_llc + 1) % (rodata.nr_llcs as u8)
                } else {
                    best_llc
                };

                // ALPHADEV Phase 8: Oracle Array Fetch (Locks LLC bounds at startup)
                rodata.oracle_llc_by_class[bpf_intf::cake_class_CAKE_CLASS_GAME as usize] =
                    best_llc;
                rodata.oracle_llc_by_class[bpf_intf::cake_class_CAKE_CLASS_NORMAL as usize] =
                    best_llc;
                rodata.oracle_llc_by_class[bpf_intf::cake_class_CAKE_CLASS_BG as usize] =
                    fallback_llc;
                rodata.oracle_llc_by_class[bpf_intf::cake_class_CAKE_CLASS_HOG as usize] =
                    fallback_llc;

                // ALPHADEV Phase 8: Offset Map (Pre-calculating cross-CCD jumps)
                for my_llc in 0..rodata.nr_llcs as usize {
                    for i in 1..rodata.nr_llcs as usize {
                        let mut victim = my_llc + i;
                        if victim >= rodata.nr_llcs as usize {
                            victim -= rodata.nr_llcs as usize;
                        }
                        rodata.victim_scan_order[my_llc][i] = victim as u8;
                    }
                }

                // ALPHADEV Phase 3: Asymmetric SIMD topological scan matrices
                for class_idx in 0..4 {
                    for home_llc in 0..rodata.nr_llcs as u8 {
                        let mut order = Vec::new();

                        if class_idx == 1 {
                            // GAME: Strictly confined to Primary Game LLC
                            order.push(best_llc);
                        } else if class_idx == 2 || class_idx == 3 {
                            // BG/HOG: Start at Fallback LLC, scan all EXCEPT Primary Game LLC
                            order.push(fallback_llc);
                            for l in 0..rodata.nr_llcs as u8 {
                                if l != fallback_llc && l != best_llc {
                                    order.push(l);
                                }
                            }
                        } else {
                            // NORMAL: Start at its Home LLC (preserve cache affinity)
                            order.push(home_llc);
                            // Then scan Fallback LLC if saturated
                            if fallback_llc != home_llc {
                                order.push(fallback_llc);
                            }
                            // Then scan all other available LLCs
                            for l in 0..rodata.nr_llcs as u8 {
                                if l != home_llc && l != fallback_llc && l != best_llc {
                                    order.push(l);
                                }
                            }
                            // Evict: ONLY spill to Primary Game LLC as absolute last resort
                            if best_llc != home_llc && best_llc != fallback_llc {
                                order.push(best_llc);
                            }
                        }

                        // Write directly to RO Data tensor mapping
                        for (i, &llc) in order.iter().enumerate() {
                            if i < rodata.llc_scan_order[class_idx][home_llc as usize].len() {
                                rodata.llc_scan_order[class_idx][home_llc as usize][i] = llc;
                            }
                        }
                        // Sentinel the tail bytes
                        for i in
                            order.len()..rodata.llc_scan_order[class_idx][home_llc as usize].len()
                        {
                            rodata.llc_scan_order[class_idx][home_llc as usize][i] = 0xFF;
                        }
                    }
                }

                info!(
                    "Topology Strategy: Primary Game LLC={}, Fallback BG LLC={}, Max Rank={}",
                    best_llc, fallback_llc, max_rank
                );
            }

            // Performance-ordered CPU scan arrays — HYBRID ONLY
            #[cfg(cake_has_hybrid)]
            {
                let nr = topo.nr_cpus.min(topology::MAX_CPUS);
                let mut rankings: Vec<(usize, u32)> = (0..nr)
                    .map(|cpu| {
                        let path = format!(
                            "/sys/devices/system/cpu/cpu{}/cpufreq/amd_pstate_prefcore_ranking",
                            cpu
                        );
                        let rank = std::fs::read_to_string(&path)
                            .ok()
                            .and_then(|s| s.trim().parse::<u32>().ok())
                            .unwrap_or(100);
                        (cpu, rank)
                    })
                    .collect();

                rankings.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));

                let mut fast_to_slow: Vec<u16> = Vec::with_capacity(nr);
                let mut used = vec![false; nr];
                for &(cpu, _) in &rankings {
                    if used[cpu] {
                        continue;
                    }
                    fast_to_slow.push(cpu as u16);
                    used[cpu] = true;
                    let sib = topo.cpu_sibling_map.get(cpu).copied().unwrap_or(0xFFFF);
                    if (sib as usize) < nr && !used[sib as usize] {
                        fast_to_slow.push(sib);
                        used[sib as usize] = true;
                    }
                }

                for i in 0..topology::MAX_CPUS {
                    if i >= rodata.cpus_fast_to_slow.len() {
                        break;
                    }
                    if i < fast_to_slow.len() {
                        rodata.cpus_fast_to_slow[i] = fast_to_slow[i] as _;
                        rodata.cpus_slow_to_fast[i] = fast_to_slow[fast_to_slow.len() - 1 - i] as _;
                    } else {
                        rodata.cpus_fast_to_slow[i] = rodata.cpus_fast_to_slow[i].wrapping_sub(1);
                        rodata.cpus_slow_to_fast[i] = rodata.cpus_slow_to_fast[i].wrapping_sub(1);
                    }
                }

                let top_cpus: Vec<_> = fast_to_slow.iter().take(4).collect();
                info!(
                    "Core steering: fast→slow order {:?} ({} CPUs)",
                    top_cpus, nr
                );
            }

            // ═══ Per-CPU capacity table (F1 correctness fix) ═══
            // Read arch_scale_cpu_capacity from sysfs for P/E core vruntime scaling.
            // Scale: 0-1024, where 1024 = fastest core. On SMP all = 1024 → JIT folds.
            // Intel hybrid: P-cores ~1024, E-cores ~600-700.
            // AMD SMP: all 1024 → cap > 0 && cap < 1024 is always false → zero overhead.
            {
                let nr = topo.nr_cpus.min(topology::MAX_CPUS);
                let mut all_equal = true;
                let mut first_cap: u32 = 0;

                for cpu in 0..nr {
                    let path = format!("/sys/devices/system/cpu/cpu{}/cpu_capacity", cpu);
                    let cap = std::fs::read_to_string(&path)
                        .ok()
                        .and_then(|s| s.trim().parse::<u32>().ok())
                        .unwrap_or(1024);

                    rodata.cpuperf_cap_table[cpu] = cap;

                    if cpu == 0 {
                        first_cap = cap;
                    } else if cap != first_cap {
                        all_equal = false;
                    }
                }

                if !all_equal {
                    info!(
                        "Capacity scaling: heterogeneous (P/E cores, range {}-{})",
                        rodata.cpuperf_cap_table[..nr].iter().min().unwrap_or(&0),
                        rodata.cpuperf_cap_table[..nr].iter().max().unwrap_or(&1024)
                    );
                }
            }

            // Arena library: nr_cpu_ids must be set before load() — arena_init
            // checks this and returns -ENODEV (errno 19) if uninitialized.
            rodata.nr_cpu_ids = *NR_CPU_IDS as u32;

            // ═══ Audio stack detection ═══
            // Phase 1: Core audio daemons by comm name.
            // Phase 2: PipeWire socket clients (mixers like goxlr-daemon).
            // Both are session-persistent → populated to BSS cache post-load.
            {
                use std::collections::HashSet;

                const AUDIO_COMMS: &[&str] = &[
                    "pipewire",
                    "wireplumber",
                    "pipewire-pulse",
                    "pulseaudio",
                    "jackd",
                    "jackdbus",
                    "goxlr-daemon",
                ];
                let mut audio_tgid_set: HashSet<u32> = HashSet::new();

                // Phase 1: comm-based detection
                if let Ok(entries) = std::fs::read_dir("/proc") {
                    for entry in entries.flatten() {
                        let name = entry.file_name();
                        let name_str = name.to_string_lossy();
                        if !name_str.chars().all(|c| c.is_ascii_digit()) {
                            continue;
                        }
                        let pid: u32 = match name_str.parse() {
                            Ok(p) => p,
                            Err(_) => continue,
                        };
                        if let Ok(comm) = std::fs::read_to_string(format!("/proc/{}/comm", pid)) {
                            let comm = comm.trim();
                            if AUDIO_COMMS.contains(&comm) && audio_tgid_set.insert(pid) {
                                audio_tgids.push(pid);
                            }
                        }
                    }
                }

                // Phase 2: PipeWire socket client detection.
                // Scan /proc/net/unix for pipewire-0 socket inodes, then find
                // processes with fds pointing to those inodes. This catches any
                // audio mixer daemon (goxlr-daemon, easyeffects, etc.) without
                // brittle comm lists.
                let core_count = audio_tgids.len();
                'pw_detect: {
                    let uid = unsafe { libc::getuid() };
                    let pw_socket_path = format!("/run/user/{}/pipewire-0", uid);

                    // Collect inodes for the PipeWire socket
                    let unix_content = match std::fs::read_to_string("/proc/net/unix") {
                        Ok(c) => c,
                        Err(_) => break 'pw_detect,
                    };
                    let mut pw_inodes: HashSet<u64> = HashSet::new();
                    for line in unix_content.lines().skip(1) {
                        if line.ends_with(&pw_socket_path)
                            || line.contains(&format!("{} ", pw_socket_path))
                        {
                            // Format: Num RefCount Protocol Flags Type St Inode Path
                            let fields: Vec<&str> = line.split_whitespace().collect();
                            if fields.len() >= 7 {
                                if let Ok(inode) = fields[6].parse::<u64>() {
                                    if inode > 0 {
                                        pw_inodes.insert(inode);
                                    }
                                }
                            }
                        }
                    }
                    if pw_inodes.is_empty() {
                        break 'pw_detect;
                    }

                    // Scan /proc/*/fd for socket links matching PipeWire inodes.
                    // Only check thread-group leaders (dirs in /proc with numeric names).
                    if let Ok(proc_entries) = std::fs::read_dir("/proc") {
                        for entry in proc_entries.flatten() {
                            if audio_tgids.len() >= 8 {
                                break;
                            }
                            let name = entry.file_name();
                            let name_str = name.to_string_lossy();
                            if !name_str.chars().all(|c| c.is_ascii_digit()) {
                                continue;
                            }
                            let pid: u32 = match name_str.parse() {
                                Ok(p) => p,
                                Err(_) => continue,
                            };
                            // Skip PIDs already detected as core audio
                            if audio_tgid_set.contains(&pid) {
                                continue;
                            }
                            let fd_dir = format!("/proc/{}/fd", pid);
                            let fd_entries = match std::fs::read_dir(&fd_dir) {
                                Ok(e) => e,
                                Err(_) => continue,
                            };
                            for fd_entry in fd_entries.flatten() {
                                if let Ok(link) = std::fs::read_link(fd_entry.path()) {
                                    let link_str = link.to_string_lossy();
                                    // Socket links look like "socket:[12345]"
                                    if let Some(inode_str) = link_str
                                        .strip_prefix("socket:[")
                                        .and_then(|s| s.strip_suffix(']'))
                                    {
                                        if let Ok(inode) = inode_str.parse::<u64>() {
                                            if pw_inodes.contains(&inode) {
                                                if audio_tgid_set.insert(pid) {
                                                    audio_tgids.push(pid);
                                                }
                                                break; // Found one match, move to next PID
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                /* Audio TGIDs populated into BSS post-load */
                let client_count = audio_tgids.len() - core_count;
                if !audio_tgids.is_empty() {
                    info!(
                        "Audio stack detected: {} daemons{} (TGIDs: {:?})",
                        audio_tgids.len(),
                        if client_count > 0 {
                            format!(
                                ", {} PipeWire client{}",
                                client_count,
                                if client_count == 1 { "" } else { "s" }
                            )
                        } else {
                            String::new()
                        },
                        audio_tgids
                    );
                }
            }

            // ═══ Compositor detection ═══
            // Wayland compositors present every frame to the display.
            // Session-persistent → bake into RODATA.
            {
                const COMPOSITOR_COMMS: &[&str] = &[
                    "kwin_wayland",
                    "kwin_x11",
                    "mutter",
                    "gnome-shell",
                    "sway",
                    "Hyprland",
                    "weston",
                    "labwc",
                    "wayfire",
                    "river",
                    "gamescope",
                    "Xwayland", // Input routing for Proton/Wine games on Wayland
                    "Xorg",     // X11 display server + input handler
                    "X",        // Xorg alternate comm name
                ];
                if let Ok(entries) = std::fs::read_dir("/proc") {
                    for entry in entries.flatten() {
                        let name = entry.file_name();
                        let name_str = name.to_string_lossy();
                        if !name_str.chars().all(|c| c.is_ascii_digit()) {
                            continue;
                        }
                        let pid: u32 = match name_str.parse() {
                            Ok(p) => p,
                            Err(_) => continue,
                        };
                        if let Ok(comm) = std::fs::read_to_string(format!("/proc/{}/comm", pid)) {
                            let comm = comm.trim();
                            if COMPOSITOR_COMMS.contains(&comm) {
                                compositor_tgids.push(pid);
                                if compositor_tgids.len() >= 4 {
                                    break;
                                }
                            }
                        }
                    }
                }
                /* Compositor TGIDs populated into BSS post-load */
                if !compositor_tgids.is_empty() {
                    info!(
                        "Compositor detected: {} (TGIDs: {:?})",
                        compositor_tgids.len(),
                        compositor_tgids
                    );
                }
            }
        }

        // ═══ scx_ops_load! equivalent ═══
        // Set UEI dump buffer size before load (matches scx_ops_load! behavior)
        scx_utils::uei_set_size!(open_skel, cake_ops, uei);

        let mut skel = open_skel.load().context("Failed to load BPF program")?;

        // Initialize the BPF arena library.
        // Must happen after load() (BPF maps are now live) but before attach_struct_ops()
        // (scheduler not yet running, so init_task hasn't fired yet).
        // ArenaLib::setup() runs SEC("syscall") probes:
        //   1. arena_init: allocates static pages, inits task stack allocator
        //   2. arena_topology_node_init: registers topology nodes for arena traversal
        let task_ctx_size = std::mem::size_of::<bpf_intf::cake_task_ctx>();
        let arena = ArenaLib::init(skel.object_mut(), task_ctx_size, topo.nr_cpus)
            .context("Failed to create ArenaLib")?;
        arena.setup().context("Failed to initialize BPF arena")?;
        info!(
            "BPF arena initialized (task_ctx_size={}B, nr_cpus={})",
            task_ctx_size, topo.nr_cpus
        );

        // Set initial BSS values before attach (zero-init'd in BPF for BSS placement).
        // quantum_ceiling_ns: default IDLE/GAMING → 2ms. TUI updates at ~2Hz.
        if let Some(bss) = &mut skel.maps.bss_data {
            bss.quantum_ceiling_ns = 2_000_000; // AQ_BULK_CEILING_NS

            // ALPHADEV Phase 7.3: Muscle/Brain offload. Hydrate O(1) Cache locklessly.
            let mask = (bpf_intf::BRAIN_CLASS_CACHE_SIZE as u32) - 1;
            for &tgid in &audio_tgids {
                let idx = (tgid & mask) as usize;
                bss.brain_class_cache[idx].pid = tgid;
                bss.brain_class_cache[idx].task_class = bpf_intf::cake_class_CAKE_CLASS_GAME as u8;
            }
            for &tgid in &compositor_tgids {
                let idx = (tgid & mask) as usize;
                bss.brain_class_cache[idx].pid = tgid;
                bss.brain_class_cache[idx].task_class = bpf_intf::cake_class_CAKE_CLASS_GAME as u8;
            }
        }

        Ok(Self {
            skel,
            args,
            topology: topo,
            latency_matrix,
            struct_ops: None,
        })
    }

    fn run(&mut self, shutdown: Arc<AtomicBool>) -> Result<UserExitInfo> {
        use libbpf_rs::skel::Skel;

        // ═══ scx_ops_attach! equivalent ═══
        // Guard: prevent loading if another sched_ext scheduler is already active
        if scx_utils::compat::is_sched_ext_enabled().unwrap_or(false) {
            anyhow::bail!("another sched_ext scheduler is already running");
        }

        // Attach non-struct_ops BPF programs first, then struct_ops
        self.skel
            .attach()
            .context("Failed to attach non-struct_ops BPF programs")?;
        self.struct_ops = Some(
            self.skel
                .maps
                .cake_ops
                .attach_struct_ops()
                .context("Failed to attach struct_ops BPF programs")?,
        );

        // Release builds: --verbose and --testing are unavailable (stats compiled out).
        // Warn early so user knows these flags require a debug build.
        #[cfg(not(debug_assertions))]
        if self.args.verbose || self.args.testing {
            warn!("--verbose and --testing require a debug build (telemetry is compiled out in release).");
            warn!("Rebuild without --release: cargo build -p scx_cake");
            self.args.verbose = false;
            self.args.testing = false;
        }

        // Standard startup banner: follows scx_cosmos/scx_bpfland convention
        info!(
            "{} {} {}",
            SCHEDULER_NAME,
            build_id::full_version(env!("CARGO_PKG_VERSION")),
            if self.topology.smt_enabled {
                "SMT on"
            } else {
                "SMT off"
            }
        );

        // Print command line.
        info!(
            "scheduler options: {}",
            std::env::args().collect::<Vec<_>>().join(" ")
        );

        info!(
            "{} CPUs, {} LLCs, profile: {:?}",
            self.topology.nr_cpus,
            self.topology
                .llc_cpu_mask
                .iter()
                .filter(|&&m| m != 0)
                .count()
                .max(1),
            self.args.profile
        );
        if self.args.testing {
            info!("Running in benchmarking mode for 10 seconds...");
            std::thread::sleep(std::time::Duration::from_secs(1)); // Warmup

            let mut start_dispatches = 0u64;
            for cpu in 0..self.topology.nr_cpus {
                let stats = &self.skel.maps.bss_data.as_ref().unwrap().global_stats[cpu];
                start_dispatches += stats.nr_new_flow_dispatches + stats.nr_old_flow_dispatches;
            }

            let start_time = std::time::Instant::now();
            let mut elapsed = 0;
            while elapsed < 10 && !shutdown.load(Ordering::Relaxed) {
                std::thread::sleep(std::time::Duration::from_secs(1));
                elapsed += 1;
            }
            let duration = start_time.elapsed().as_secs_f64();

            let mut end_dispatches = 0u64;
            for cpu in 0..self.topology.nr_cpus {
                let stats = &self.skel.maps.bss_data.as_ref().unwrap().global_stats[cpu];
                end_dispatches += stats.nr_new_flow_dispatches + stats.nr_old_flow_dispatches;
            }

            let delta = end_dispatches.saturating_sub(start_dispatches);
            let throughput = delta as f64 / duration;
            println!("{{\"duration_sec\": {:.2}, \"total_dispatches\": {}, \"dispatches_per_sec\": {:.2}}}",
                     duration, delta, throughput);

            shutdown.store(true, Ordering::Relaxed);
        } else if self.args.verbose && std::io::stdout().is_terminal() {
            // Run TUI mode
            tui::run_tui(
                &mut self.skel,
                shutdown.clone(),
                self.args.interval,
                self.topology.clone(),
                self.latency_matrix.clone(),
            )?;
        } else {
            if self.args.verbose && !std::io::stdout().is_terminal() {
                warn!("TUI disabled: no terminal detected (headless mode)");
            }
            // Headless mode with game detection.
            // Polls /proc every 1s for Steam/Wine/.exe game processes and
            // compiler activity. Writes results to BPF BSS so the reclassifier
            // can transition to GAMING state and activate the 4-class system.
            let nr_cpus = self.topology.nr_cpus;
            let mut detector = detect::GameDetector::new_headless();
            while !shutdown.load(Ordering::Relaxed) {
                std::thread::sleep(std::time::Duration::from_secs(1));
                if scx_utils::uei_exited!(&self.skel, uei) {
                    break;
                }
                // Run game + compiler detection
                let result = detector.poll();
                // Propagate to BPF BSS — drives reclassifier sched_state gate,
                // class-aware kick guard, SYNC strip, and quantum ceiling.
                if let Some(bss) = &mut self.skel.maps.bss_data {
                    bss.game_tgid = result.game_tgid;
                    bss.game_ppid = result.game_ppid;
                    bss.game_confidence = result.game_confidence;
                    bss.sched_state = result.sched_state as u32;
                    // Per-CPU sched_state_local: eliminates remote global BSS
                    // cache line fetch at 5 BPF hot-path sites.
                    for i in 0..nr_cpus.min(bss.cpu_bss.len()) {
                        bss.cpu_bss[i].sched_state_local = result.sched_state;
                    }
                    bss.quantum_ceiling_ns = result.quantum_ceiling_ns;
                }
            }
        }

        info!("{SCHEDULER_NAME} scheduler shutting down");

        // Drop struct_ops link BEFORE uei_report — this triggers the kernel to
        // set UEI kind=SCX_EXIT_UNREG. Matches scx_bpfland/scx_cosmos/scx_lavd
        // pattern: `let _ = self.struct_ops.take(); uei_report!(...)`
        let _ = self.struct_ops.take();

        // Standard UEI exit report — returns UserExitInfo for should_restart().
        scx_utils::uei_report!(&self.skel, uei)
    }
}

impl Drop for Scheduler<'_> {
    fn drop(&mut self) {
        info!("Unregister {SCHEDULER_NAME} scheduler");
    }
}

fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    // Route libbpf messages through log crate — trim trailing \n to avoid double-newlines.
    libbpf_rs::set_print(Some((libbpf_rs::PrintLevel::Debug, |level, msg| {
        let msg = msg.trim_end();
        match level {
            libbpf_rs::PrintLevel::Debug => log::debug!("{msg}"),
            libbpf_rs::PrintLevel::Info => log::info!("{msg}"),
            libbpf_rs::PrintLevel::Warn => log::warn!("{msg}"),
        }
    })));

    let args = Args::parse();

    // Handle --version before anything else (matches cosmos/bpfland)
    if args.version {
        println!(
            "{} {}",
            SCHEDULER_NAME,
            build_id::full_version(env!("CARGO_PKG_VERSION"))
        );
        return Ok(());
    }

    // Set up signal handler: ctrlc handles both SIGINT and SIGTERM on Linux.
    // This is the same pattern cosmos/bpfland use — no SigSet blocking or
    // SignalFd complexity needed.
    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_clone = shutdown.clone();

    ctrlc::set_handler(move || {
        info!("Received shutdown signal");
        shutdown_clone.store(true, Ordering::Relaxed);
    })?;

    // Create open object for BPF - needs to outlive scheduler
    let mut open_object = std::mem::MaybeUninit::uninit();

    // Restart loop: matches cosmos/bpfland pattern.
    // Kernel can request restart via UEI (e.g., CPU hotplug).
    loop {
        let mut scheduler = Scheduler::new(args.clone(), &mut open_object)?;
        if !scheduler.run(shutdown.clone())?.should_restart() {
            break;
        }
    }

    Ok(())
}
