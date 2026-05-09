// SPDX-License-Identifier: GPL-2.0
// scx_cake - CAKE-inspired sched_ext scheduler for low-latency CPU scheduling

mod dump_compare;
#[cfg(debug_assertions)]
mod task_anatomy;
mod telemetry_report;
mod topology;
mod trust;
mod tui;

use core::sync::atomic::Ordering;
use std::io::IsTerminal;
use std::path::PathBuf;

use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::{Parser, ValueEnum};
use log::info;

#[cfg(cake_needs_arena)]
use scx_arena::ArenaLib;
use scx_utils::build_id;
use scx_utils::UserExitInfo;
#[cfg(cake_needs_arena)]
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
    /// Ultra-low-latency for competitive esports (750us quantum)
    Esports,
    /// Low-latency profile optimized for gaming and interactive workloads
    Gaming,
    /// Balanced profile for general desktop use
    Balanced,
    /// Optimized for older/lower-power hardware (4ms quantum)
    Legacy,
}

impl Profile {
    #[cfg(not(cake_bpf_release))]
    fn quantum_us(&self) -> u64 {
        match self {
            Profile::Esports => 750,
            Profile::Gaming => 1000,
            Profile::Balanced => 2000,
            Profile::Legacy => 4000,
        }
    }

    #[cfg(not(cake_bpf_release))]
    fn as_str(&self) -> &'static str {
        match self {
            Profile::Esports => "esports",
            Profile::Gaming => "gaming",
            Profile::Balanced => "balanced",
            Profile::Legacy => "legacy",
        }
    }

    // Older DVFS controls were removed. Profiles currently only select quantum.
}

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum BusyWakeKickMode {
    /// Use Cake's owner-runtime pressure policy.
    Policy = 0,
    /// Always preempt on same-CPU busy wakeups.
    Preempt = 1,
    /// Always use an idle kick on same-CPU busy wakeups.
    Idle = 2,
}

#[cfg(not(cake_bpf_release))]
impl BusyWakeKickMode {
    fn as_str(&self) -> &'static str {
        match self {
            BusyWakeKickMode::Policy => "policy",
            BusyWakeKickMode::Preempt => "preempt",
            BusyWakeKickMode::Idle => "idle",
        }
    }
}

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum StormGuardMode {
    /// Keep the baseline busy-wake policy.
    Off = 0,
    /// Count storm-guard candidates without changing placement.
    Shadow = 1,
    /// Allow conservative extra local busy handoff for saturated owners.
    Shield = 2,
    /// Allow broad local busy handoff for wake-storm A/B testing.
    Full = 3,
}

impl StormGuardMode {
    #[cfg(not(cake_bpf_release))]
    fn as_str(&self) -> &'static str {
        match self {
            StormGuardMode::Off => "off",
            StormGuardMode::Shadow => "shadow",
            StormGuardMode::Shield => "shield",
            StormGuardMode::Full => "full",
        }
    }
}

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum QueuePolicy {
    /// 1.1.1 local-first fallback policy retained for A/B testing.
    Local = 0,
    /// Default per-LLC vtime fallback queues similar to the 1.1.0 queue shape.
    LlcVtime = 1,
}

impl QueuePolicy {
    #[cfg(not(cake_bpf_release))]
    fn as_str(&self) -> &'static str {
        match self {
            QueuePolicy::Local => "local",
            QueuePolicy::LlcVtime => "llc-vtime",
        }
    }
}

const LLC_DSQ_BASE: u64 = 200;
const CPU_FAST_SCAN_SLOTS: usize = 4;
const CPU_FAST_PROBE_SLOTS: usize = 4;
const CPU_META_PRIMARY: u64 = 1u64 << 48;
const CPU_META_SMT: u64 = 1u64 << 49;

#[inline]
fn pack_cpu_meta(
    sibling_cpu: u16,
    primary_cpu: u16,
    llc_id: u32,
    core_id: u32,
    is_primary: bool,
    has_smt_sibling: bool,
) -> u64 {
    let mut meta = (u64::from(sibling_cpu) & 0xffff)
        | ((u64::from(primary_cpu) & 0xffff) << 16)
        | ((u64::from(llc_id) & 0xff) << 32)
        | ((u64::from(core_id) & 0xff) << 40);

    if is_primary {
        meta |= CPU_META_PRIMARY;
    }
    if has_smt_sibling {
        meta |= CPU_META_SMT;
    }
    meta
}

#[inline]
fn precompute_cpu_llc_dsq_id(llc_id: u32) -> u64 {
    LLC_DSQ_BASE + u64::from(llc_id)
}

#[inline]
fn primary_cpu_for(topo: &topology::TopologyInfo, cpu: usize, nr_cpus: usize) -> u16 {
    if cpu >= nr_cpus {
        return u16::MAX;
    }
    if topo.cpu_thread_bit[cpu] == 1 {
        return cpu as u16;
    }

    let sibling = topo.cpu_sibling_map[cpu] as usize;
    if sibling < nr_cpus && topo.cpu_thread_bit[sibling] == 1 {
        return sibling as u16;
    }

    cpu as u16
}

fn build_fast_scan_slots(
    cpu: usize,
    nr_cpus: usize,
    cpu_sibling_map: &[u16],
    cpu_thread_bit: &[u8],
    cpu_llc_id: &[u8],
) -> [u16; CPU_FAST_SCAN_SLOTS] {
    fn push_unique(
        slots: &mut [u16; CPU_FAST_SCAN_SLOTS],
        next: &mut usize,
        cpu: usize,
        nr: usize,
    ) {
        if cpu >= nr || *next >= CPU_FAST_SCAN_SLOTS {
            return;
        }
        let cpu = cpu as u16;
        if slots.iter().take(*next).any(|&seen| seen == cpu) {
            return;
        }
        slots[*next] = cpu;
        *next += 1;
    }

    let mut slots = [u16::MAX; CPU_FAST_SCAN_SLOTS];
    let mut next = 0;
    if cpu >= nr_cpus {
        return slots;
    }

    push_unique(&mut slots, &mut next, cpu, nr_cpus);

    let sibling = cpu_sibling_map.get(cpu).copied().unwrap_or(u16::MAX) as usize;
    let primary = if cpu_thread_bit.get(cpu).copied().unwrap_or(0) == 1 {
        cpu
    } else if sibling < nr_cpus && cpu_thread_bit.get(sibling).copied().unwrap_or(0) == 1 {
        sibling
    } else {
        cpu
    };
    push_unique(&mut slots, &mut next, primary, nr_cpus);

    let llc = cpu_llc_id.get(cpu).copied().unwrap_or(0);
    for candidate in 0..nr_cpus {
        if cpu_llc_id.get(candidate).copied().unwrap_or(u8::MAX) != llc {
            continue;
        }
        if cpu_thread_bit.get(candidate).copied().unwrap_or(0) != 1 {
            continue;
        }
        push_unique(&mut slots, &mut next, candidate, nr_cpus);
        if next >= CPU_FAST_SCAN_SLOTS {
            break;
        }
    }
    push_unique(&mut slots, &mut next, sibling, nr_cpus);

    slots
}

#[inline]
fn active_fast_scan_probe_slots(slots: [u16; CPU_FAST_SCAN_SLOTS]) -> [u16; CPU_FAST_PROBE_SLOTS] {
    [slots[0], slots[1], slots[2], slots[3]]
}

/// 🍰 scx_cake: A CAKE-inspired sched_ext CPU scheduler
///
/// This scheduler adapts CAKE's low-latency scheduling ideas to CPU time.
/// The current design centers on topology-aware CPU selection, per-LLC
/// vtime fallback queues, and lightweight per-task accounting in BPF.
///
/// Release builds bake profile, quantum, queue policy, and storm guard at compile time.
/// Debug builds keep those options as runtime A/B controls.
///
/// Game detection and older multi-mode policy logic have been removed.
/// The scheduler now runs one general low-latency policy for all tasks.
///
/// EXAMPLES:
///   scx_cake                          # Run with gaming profile (default)
///   scx_cake -p esports               # Ultra-low-latency for competitive play
///   scx_cake -p balanced              # Balanced desktop / mixed-use profile
///   scx_cake --quantum 1500           # Gaming profile with custom quantum
///   scx_cake --wake-chain-locality=true # A/B enable learned wake-chain guard
///   scx_cake --learned-locality=true # A/B enable learned locality steering
///   scx_cake --busy-wake-kick=preempt # A/B force same-CPU busy wake preemption
///   scx_cake --queue-policy local # A/B use 1.1.1 local fallback queues
///   scx_cake -v                       # Run with live TUI stats display
///   scx_cake -v --diag-dir /tmp/cake  # Headless recorder; directory must exist
#[derive(Parser, Debug, Clone)]
#[command(
    author,
    version,
    disable_version_flag = true,
    about = "🍰 A CAKE-inspired sched_ext scheduler for low-latency CPU scheduling",
    verbatim_doc_comment
)]
struct Args {
    /// Scheduler profile preset.
    ///
    /// Profiles configure the base quantum in debug builds. Release builds use
    /// SCX_CAKE_PROFILE at build time.
    ///
    /// ESPORTS: Ultra-low-latency for competitive gaming.
    ///   - Quantum: 750µs
    ///
    /// GAMING: Optimized for low-latency gaming and interactive workloads.
    ///   - Quantum: 1000µs
    ///
    /// BALANCED: Balanced profile for general desktop use.
    ///   - Quantum: 2000µs
    ///
    /// LEGACY: Optimized for older/lower-power hardware.
    ///   - Quantum: 4000µs
    #[arg(long, short, value_enum, default_value_t = Profile::Gaming, verbatim_doc_comment)]
    profile: Profile,

    /// Base scheduling time slice in MICROSECONDS [default: 1000].
    ///
    /// Debug builds patch this at startup. Release builds use
    /// SCX_CAKE_QUANTUM_US at build time.
    ///
    /// How long a task runs before potentially yielding.
    ///
    /// Smaller quantum = more responsive but higher overhead.
    /// Esports: 750µs | Gaming: 1000µs | Balanced: 2000µs | Legacy: 4000µs
    /// Recommended range: 1000-8000µs
    #[arg(long, verbatim_doc_comment)]
    quantum: Option<u64>,

    /// Enable learned wake-chain locality guard.
    ///
    /// This generic behavior-based guard keeps hot short blocking wake chains
    /// near their learned CPU instead of broadening every idle scan. It defaults
    /// off because latency tails are worse than migration for the current policy.
    #[arg(
        long,
        default_value_t = false,
        num_args = 0..=1,
        require_equals = true,
        default_missing_value = "true",
        action = clap::ArgAction::Set,
        verbatim_doc_comment
    )]
    wake_chain_locality: bool,

    /// Enable learned locality steering.
    ///
    /// This controls the arena-backed home/core/primary steering policy used
    /// after a task has enough history. It defaults off so the baseline stays
    /// latency-first and idle-selector driven.
    #[arg(
        long,
        default_value_t = false,
        num_args = 0..=1,
        require_equals = true,
        default_missing_value = "true",
        action = clap::ArgAction::Set,
        verbatim_doc_comment
    )]
    learned_locality: bool,

    /// Same-CPU busy wake kick behavior.
    ///
    /// POLICY uses Cake's current owner-runtime/pressure policy.
    /// PREEMPT forces immediate preempt kicks for local busy wakeups.
    /// IDLE forces gentler idle kicks for local busy wakeups.
    #[arg(long, value_enum, default_value_t = BusyWakeKickMode::Policy, verbatim_doc_comment)]
    busy_wake_kick: BusyWakeKickMode,

    /// Storm-guard busy-wake handoff policy.
    ///
    /// OFF keeps the baseline policy.
    /// SHADOW records storm-guard candidates without changing placement.
    /// SHIELD allows conservative extra local handoff for saturated owners.
    /// FULL allows broad local handoff during wake-storm A/B testing.
    #[arg(long, value_enum, default_value_t = StormGuardMode::Off, verbatim_doc_comment)]
    storm_guard: StormGuardMode,

    /// Queueing policy for busy fallback work.
    ///
    /// Debug builds patch this at startup. Release builds use
    /// SCX_CAKE_QUEUE_POLICY at build time.
    ///
    /// LLC-VTIME keeps the default 1.1.0-style shape: fallback work is inserted
    /// into a per-LLC vtime DSQ that dispatch() pulls from.
    /// LOCAL A/B tests the 1.1.1 local-only shape: fallback work is inserted
    /// into the selected CPU's local DSQ.
    #[arg(long, value_enum, default_value_t = QueuePolicy::LlcVtime, verbatim_doc_comment)]
    queue_policy: QueuePolicy,

    /// Enable live TUI (Terminal User Interface) with real-time statistics.
    ///
    /// Shows live scheduler stats, wait/run timing, and system topology
    /// information. Debug builds compile the full verbose capture surface by
    /// default; release builds compile telemetry out.
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

    /// Directory for headless --verbose diagnostic snapshots.
    ///
    /// When --verbose is used without an interactive terminal, scx_cake records
    /// text and JSON diagnostic dumps here instead of trying to draw the TUI.
    #[arg(long, default_value = ".", verbatim_doc_comment)]
    diag_dir: PathBuf,

    /// Headless --verbose diagnostic write interval in SECONDS.
    ///
    /// A value of 0 disables periodic latest writes. A timestamped final dump
    /// is still written when scx_cake exits.
    #[arg(long, default_value_t = 60, verbatim_doc_comment)]
    diag_period: u64,

    /// Print scheduler version and exit.
    #[arg(short = 'V', long, action = clap::ArgAction::SetTrue)]
    version: bool,

    /// Compare two scx_cake TUI dump files and exit without loading BPF.
    #[arg(long, value_names = ["BASELINE", "CANDIDATE"], num_args = 2)]
    compare_dump: Option<Vec<PathBuf>>,
}

impl Args {
    #[cfg(not(cake_bpf_release))]
    fn quantum_us(&self) -> u64 {
        self.quantum.unwrap_or(self.profile.quantum_us())
    }

    fn effective_quantum_us(&self) -> u64 {
        #[cfg(cake_bpf_release)]
        {
            topology::BAKED_QUANTUM_US
        }
        #[cfg(not(cake_bpf_release))]
        {
            self.quantum_us()
        }
    }

    fn effective_profile(&self) -> &'static str {
        #[cfg(cake_bpf_release)]
        {
            topology::BAKED_PROFILE
        }
        #[cfg(not(cake_bpf_release))]
        {
            self.profile.as_str()
        }
    }

    fn effective_queue_policy(&self) -> &'static str {
        #[cfg(cake_bpf_release)]
        {
            topology::BAKED_QUEUE_POLICY
        }
        #[cfg(not(cake_bpf_release))]
        {
            self.queue_policy.as_str()
        }
    }

    fn effective_storm_guard(&self) -> &'static str {
        #[cfg(cake_bpf_release)]
        {
            topology::BAKED_STORM_GUARD
        }
        #[cfg(not(cake_bpf_release))]
        {
            self.storm_guard.as_str()
        }
    }

    fn effective_busy_wake_kick(&self) -> &'static str {
        #[cfg(cake_bpf_release)]
        {
            topology::BAKED_BUSY_WAKE_KICK
        }
        #[cfg(not(cake_bpf_release))]
        {
            self.busy_wake_kick.as_str()
        }
    }
}

#[cfg(cake_bpf_release)]
fn cli_arg_present(long: &str, short: Option<&str>) -> bool {
    let long_with_value = format!("{long}=");
    std::env::args().skip(1).any(|arg| {
        arg == long
            || arg.starts_with(&long_with_value)
            || short.map_or(false, |short| arg == short)
    })
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
        #[cfg(cake_needs_arena)]
        use libbpf_rs::skel::Skel;
        use libbpf_rs::skel::{OpenSkel, SkelBuilder};

        // ═══ scx_ops_open! equivalent ═══
        // Matches scx_ops_open!(skel_builder, open_object, cake_ops, None)
        // Cake can't use the macro directly (custom arena architecture),
        // so we inline the critical functionality.
        scx_utils::compat::check_min_requirements()?;

        let skel_builder = BpfSkelBuilder::default();
        let mut open_skel = skel_builder
            .open(open_object)
            .context("Failed to open BPF skeleton")?;

        // Inject version suffix into ops name: "cake" → "cake_1.1.1_g<hash>_<target>"
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

        // Get effective values. Release bakes these in build.rs; debug keeps
        // profile + CLI overrides for runtime A/B.
        #[cfg(not(cake_bpf_release))]
        let quantum = args.effective_quantum_us();

        // Latency matrix: zeroed, populated by TUI Topology tab if --verbose
        let latency_matrix = vec![vec![0.0; topo.nr_cpus]; topo.nr_cpus];

        // Configure the scheduler via rodata (read-only data)
        if let Some(rodata) = &mut open_skel.maps.rodata_data {
            #[cfg(not(cake_bpf_release))]
            {
                rodata.quantum_ns = quantum * 1000;
                rodata.queue_policy = args.queue_policy as u32;
                rodata.enable_learned_locality = args.learned_locality;
                rodata.enable_wake_chain_locality = args.wake_chain_locality;
                rodata.busy_wake_kick_mode = args.busy_wake_kick as u32;
                rodata.storm_guard_mode = args.storm_guard as u32;
            }
            // Stats/telemetry: only available in debug builds (CAKE_RELEASE omits the field).
            // In release, --verbose is silently ignored.
            #[cfg(debug_assertions)]
            {
                rodata.enable_stats = args.verbose;
            }

            // Populate topology metadata used by local-first steering and telemetry.
            let llc_count = topo.llc_cpu_mask.iter().filter(|&&m| m != 0).count() as u32;
            rodata.nr_llcs = llc_count.max(1);
            rodata.nr_cpus = topo.nr_cpus.min(topology::MAX_CPUS) as u32;
            // nr_phys_cpus REMOVED: zero BPF readers.

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
            // vcache_llc_mask/has_vcache REMOVED from BPF: zero BPF readers.
            // Rust TUI reads topology directly.

            for i in 0..topo.cpu_sibling_map.len().min(rodata.cpu_sibling_map.len()) {
                rodata.cpu_sibling_map[i] = topo.cpu_sibling_map[i] as _;
            }
            for i in 0..topo.cpu_thread_bit.len().min(rodata.cpu_thread_bit.len()) {
                rodata.cpu_thread_bit[i] = topo.cpu_thread_bit[i];
            }
            for i in 0..topo.llc_cpu_mask.len().min(rodata.llc_cpu_mask.len()) {
                rodata.llc_cpu_mask[i] = topo.llc_cpu_mask[i];
            }
            // core_cpu_mask REMOVED from BPF: zero BPF readers.

            for (i, &llc_id) in topo.cpu_llc_id.iter().enumerate() {
                rodata.cpu_llc_id[i] = llc_id as u32;
            }
            for i in 0..topo.cpu_core_id.len().min(rodata.cpu_core_id.len()) {
                rodata.cpu_core_id[i] = topo.cpu_core_id[i];
            }

            let nr = topo.nr_cpus.min(topology::MAX_CPUS);
            for i in 0..nr.min(rodata.cpu_meta.len()) {
                let sibling = topo.cpu_sibling_map[i];
                let has_smt_sibling = (sibling as usize) < nr && sibling as usize != i;
                let primary = primary_cpu_for(&topo, i, nr);
                let is_primary = primary as usize == i;
                let llc_id = topo.cpu_llc_id[i] as u32;

                rodata.cpu_meta[i] = pack_cpu_meta(
                    sibling,
                    primary,
                    llc_id,
                    topo.cpu_core_id[i] as u32,
                    is_primary,
                    has_smt_sibling,
                );
                rodata.cpu_llc_dsq[i] = precompute_cpu_llc_dsq_id(llc_id);
                let fast_scan = build_fast_scan_slots(
                    i,
                    nr,
                    &topo.cpu_sibling_map,
                    &topo.cpu_thread_bit,
                    &topo.cpu_llc_id,
                );
                rodata.cpu_fast_probe[i] = active_fast_scan_probe_slots(fast_scan);
            }

            info!("Topology Strategy: Per-CPU local-first dispatch");

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

            #[cfg(cake_needs_arena)]
            {
                // Arena library: nr_cpu_ids must be set before load() — arena_init
                // checks this and returns -ENODEV (errno 19) if uninitialized.
                rodata.nr_cpu_ids = *NR_CPU_IDS as u32;
            }
        }

        // ═══ scx_ops_load! equivalent ═══
        // Set UEI dump buffer size before load (matches scx_ops_load! behavior)
        scx_utils::uei_set_size!(open_skel, cake_ops, uei);

        #[cfg(cake_needs_arena)]
        let mut skel = open_skel.load().context("Failed to load BPF program")?;
        #[cfg(not(cake_needs_arena))]
        let skel = open_skel.load().context("Failed to load BPF program")?;

        #[cfg(cake_needs_arena)]
        {
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

        // Release builds: --verbose is unavailable (stats compiled out).
        // Warn early so user knows this flag requires a debug build.
        #[cfg(not(debug_assertions))]
        if self.args.verbose {
            log::warn!("--verbose requires a debug build (telemetry is compiled out in release).");
            log::warn!("Rebuild without --release: cargo build -p scx_cake");
            self.args.verbose = false;
        }

        #[cfg(cake_bpf_release)]
        if self.args.quantum.is_some()
            || cli_arg_present("--profile", Some("-p"))
            || cli_arg_present("--queue-policy", None)
            || cli_arg_present("--storm-guard", None)
            || cli_arg_present("--busy-wake-kick", None)
        {
            log::warn!(
                "release build uses baked profile={}, quantum={}us, queue-policy={}, storm-guard={}, busy-wake-kick={}; rebuild with SCX_CAKE_PROFILE, SCX_CAKE_QUANTUM_US, SCX_CAKE_QUEUE_POLICY, SCX_CAKE_STORM_GUARD, or SCX_CAKE_BUSY_WAKE_KICK to change hot-path knobs",
                topology::BAKED_PROFILE,
                topology::BAKED_QUANTUM_US,
                topology::BAKED_QUEUE_POLICY,
                topology::BAKED_STORM_GUARD,
                topology::BAKED_BUSY_WAKE_KICK
            );
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
            "{} CPUs, {} LLCs, profile: {}, quantum: {}us, queue-policy: {}, storm-guard: {}, busy-wake-kick: {}",
            self.topology.nr_cpus,
            self.topology
                .llc_cpu_mask
                .iter()
                .filter(|&&m| m != 0)
                .count()
                .max(1),
            self.args.effective_profile(),
            self.args.effective_quantum_us(),
            self.args.effective_queue_policy(),
            self.args.effective_storm_guard(),
            self.args.effective_busy_wake_kick()
        );
        let mut trust_governor = trust::TrustGovernor::new(self.topology.nr_cpus);
        if self.args.verbose && std::io::stdout().is_terminal() {
            tui::run_tui(
                &mut self.skel,
                &mut trust_governor,
                shutdown.clone(),
                self.args.interval,
                self.args.effective_quantum_us(),
                self.topology.clone(),
                self.latency_matrix.clone(),
            )?;
        } else if self.args.verbose {
            tui::run_headless_recorder(
                &mut self.skel,
                &mut trust_governor,
                tui::HeadlessRecorderConfig {
                    shutdown: shutdown.clone(),
                    interval_secs: self.args.interval,
                    quantum_us: self.args.effective_quantum_us(),
                    topology: self.topology.clone(),
                    latency_matrix: self.latency_matrix.clone(),
                    diag_dir: self.args.diag_dir.clone(),
                    diag_period_secs: self.args.diag_period,
                },
            )?;
        } else {
            while !shutdown.load(Ordering::Relaxed) {
                trust_governor.tick(&mut self.skel, self.topology.nr_cpus);
                std::thread::sleep(std::time::Duration::from_secs(1));
                if scx_utils::uei_exited!(&self.skel, uei) {
                    break;
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

    if let Some(paths) = args.compare_dump.as_ref() {
        dump_compare::run_compare(&paths[0], &paths[1])?;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn queue_policy_defaults_to_llc_vtime() {
        let args = Args::try_parse_from(["scx_cake"]).unwrap();

        assert_eq!(args.queue_policy, QueuePolicy::LlcVtime);
    }

    #[test]
    fn queue_policy_parses_local() {
        let args = Args::try_parse_from(["scx_cake", "--queue-policy", "local"]).unwrap();

        assert_eq!(args.queue_policy, QueuePolicy::Local);
    }

    #[test]
    fn storm_guard_defaults_to_off_and_parses_full() {
        let args = Args::try_parse_from(["scx_cake"]).unwrap();
        assert_eq!(args.storm_guard, StormGuardMode::Off);

        let args = Args::try_parse_from(["scx_cake", "--storm-guard", "full"]).unwrap();
        assert_eq!(args.storm_guard, StormGuardMode::Full);
    }

    #[test]
    fn cpu_meta_packs_static_topology_fact() {
        let meta = pack_cpu_meta(300, 260, 12, 44, true, true);

        assert_eq!(meta & 0xffff, 300);
        assert_eq!((meta >> 16) & 0xffff, 260);
        assert_eq!((meta >> 32) & 0xff, 12);
        assert_eq!((meta >> 40) & 0xff, 44);
        assert_ne!(meta & CPU_META_PRIMARY, 0);
        assert_ne!(meta & CPU_META_SMT, 0);
    }

    #[test]
    fn precomputed_dsq_ids_match_bpf_layout() {
        assert_eq!(precompute_cpu_llc_dsq_id(2), 202);
    }

    #[test]
    fn fast_scan_slots_are_init_built_nearby_cpu_order() {
        let siblings = [1, 0, 3, 2];
        let thread_bits = [1, 2, 1, 2];
        let llcs = [0, 0, 0, 0];

        let slots = build_fast_scan_slots(1, 4, &siblings, &thread_bits, &llcs);

        assert_eq!(slots, [1, 0, 2, u16::MAX]);

        let primary_slots = build_fast_scan_slots(0, 4, &siblings, &thread_bits, &llcs);

        assert_eq!(primary_slots, [0, 2, 1, u16::MAX]);
    }

    #[test]
    fn active_fast_scan_probe_slots_are_prev_then_primary() {
        let slots = [7, 4, 2, u16::MAX];

        assert_eq!(active_fast_scan_probe_slots(slots), [7, 4, 2, u16::MAX]);
    }
}
