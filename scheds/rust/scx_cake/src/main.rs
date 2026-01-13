// SPDX-License-Identifier: GPL-2.0
//
// scx_cake - A sched_ext scheduler applying CAKE bufferbloat concepts
//
// This is the userspace component that loads the BPF scheduler,
// configures it, and displays statistics.

mod stats;
mod topology;
mod tui;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::{Parser, ValueEnum};
use libbpf_rs::MapCore;
use log::{info, warn};

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
}

impl Profile {
    /// Returns (quantum_us, new_flow_bonus_us, sparse_threshold_permille, starvation_us)
    fn values(&self) -> (u64, u64, u64, u64) {
        match self {
            // Esports: Ultra-aggressive, 1ms quantum for maximum responsiveness
            Profile::Esports => (1000, 4000, 50, 50000),
            // Legacy: High efficiency, 4ms quantum to reduce overhead on older CPUs
            Profile::Legacy => (4000, 12000, 30, 200000),
            // Gaming: Aggressive latency, 2ms quantum, sensitive sparse detection
            Profile::Gaming => (2000, 8000, 50, 100000),
            // Default: Same as gaming for now
            Profile::Default => (2000, 8000, 50, 100000),
        }
    }

    /// Per-tier starvation thresholds in nanoseconds (pre-computed, zero overhead)
    fn starvation_threshold(&self) -> [u64; 8] {
        match self {
            // Esports: Tighter starvation for faster preemption
            Profile::Esports => [
                2_500_000,  // Tier 0: Critical Latency - 2.5ms
                1_500_000,  // Tier 1: Realtime - 1.5ms
                2_000_000,  // Tier 2: Critical - 2ms
                4_000_000,  // Tier 3: Gaming - 4ms
                8_000_000,  // Tier 4: Interactive - 8ms
                20_000_000, // Tier 5: Batch - 20ms
                50_000_000, // Tier 6: Background - 50ms
                50_000_000, // Padding
            ],
            // Legacy: Relaxed starvation for older hardware
            Profile::Legacy => [
                10_000_000,  // Tier 0: 10ms
                6_000_000,   // Tier 1: 6ms
                8_000_000,   // Tier 2: 8ms
                16_000_000,  // Tier 3: 16ms
                32_000_000,  // Tier 4: 32ms
                80_000_000,  // Tier 5: 80ms
                200_000_000, // Tier 6: 200ms
                200_000_000, // Padding
            ],
            Profile::Gaming | Profile::Default => [
                5_000_000,   // Tier 0: Critical Latency - 5ms
                3_000_000,   // Tier 1: Realtime - 3ms
                4_000_000,   // Tier 2: Critical - 4ms
                8_000_000,   // Tier 3: Gaming - 8ms
                16_000_000,  // Tier 4: Interactive - 16ms
                40_000_000,  // Tier 5: Batch - 40ms
                100_000_000, // Tier 6: Background - 100ms
                100_000_000, // Padding
            ],
        }
    }

    /// Tier quantum multipliers (fixed-point, 1024 = 1.0x)
    fn tier_multiplier(&self) -> [u32; 8] {
        match self {
            // All profiles currently use standard DRR++ scaling
            Profile::Esports | Profile::Legacy | Profile::Gaming | Profile::Default => [
                717,  // Critical Latency: 0.7x
                819,  // Realtime: 0.8x
                922,  // Critical: 0.9x
                1024, // Gaming: 1.0x
                1126, // Interactive: 1.1x
                1229, // Batch: 1.2x
                1331, // Background: 1.3x
                1024, // Padding
            ],
        }
    }

    /// Wait budget per tier in nanoseconds
    fn wait_budget(&self) -> [u64; 8] {
        match self {
            // Esports: Tighter wait budgets
            Profile::Esports => [
                50_000,     // Critical Latency: 50µs
                375_000,    // Realtime: 375µs
                1_000_000,  // Critical: 1ms
                2_000_000,  // Gaming: 2ms
                4_000_000,  // Interactive: 4ms
                10_000_000, // Batch: 10ms
                0,          // Background: no limit
                0,          // Padding
            ],
            // Legacy: Very relaxed budgets for high-latency hardware
            Profile::Legacy => [
                200_000,    // Critical Latency: 200µs
                1_500_000,  // Realtime: 1.5ms
                4_000_000,  // Critical: 4ms
                8_000_000,  // Gaming: 8ms
                16_000_000, // Interactive: 16ms
                40_000_000, // Batch: 40ms
                0,          // Background: no limit
                0,          // Padding
            ],
            Profile::Gaming | Profile::Default => [
                100_000,    // Critical Latency: 100µs
                750_000,    // Realtime: 750µs
                2_000_000,  // Critical: 2ms
                4_000_000,  // Gaming: 4ms
                8_000_000,  // Interactive: 8ms
                20_000_000, // Batch: 20ms
                0,          // Background: no limit
                0,          // Padding
            ],
        }
    }

    /// Consolidated tier configuration (AoS optimization)
    ///
    /// Generates a single array of cake_tier_config structs from the
    /// individual tier parameter methods. This reduces cache line fetches
    /// from 3 to 1 in the BPF hot path.
    fn tier_configs(&self) -> [bpf_skel::types::cake_tier_config; 8] {
        let starvation = self.starvation_threshold();
        let multiplier = self.tier_multiplier();
        let budget = self.wait_budget();

        [
            bpf_skel::types::cake_tier_config {
                starvation_ns: starvation[0],
                wait_budget_ns: budget[0],
                multiplier: multiplier[0],
                _pad: [0; 3],
            },
            bpf_skel::types::cake_tier_config {
                starvation_ns: starvation[1],
                wait_budget_ns: budget[1],
                multiplier: multiplier[1],
                _pad: [0; 3],
            },
            bpf_skel::types::cake_tier_config {
                starvation_ns: starvation[2],
                wait_budget_ns: budget[2],
                multiplier: multiplier[2],
                _pad: [0; 3],
            },
            bpf_skel::types::cake_tier_config {
                starvation_ns: starvation[3],
                wait_budget_ns: budget[3],
                multiplier: multiplier[3],
                _pad: [0; 3],
            },
            bpf_skel::types::cake_tier_config {
                starvation_ns: starvation[4],
                wait_budget_ns: budget[4],
                multiplier: multiplier[4],
                _pad: [0; 3],
            },
            bpf_skel::types::cake_tier_config {
                starvation_ns: starvation[5],
                wait_budget_ns: budget[5],
                multiplier: multiplier[5],
                _pad: [0; 3],
            },
            bpf_skel::types::cake_tier_config {
                starvation_ns: starvation[6],
                wait_budget_ns: budget[6],
                multiplier: multiplier[6],
                _pad: [0; 3],
            },
            bpf_skel::types::cake_tier_config {
                starvation_ns: starvation[7],
                wait_budget_ns: budget[7],
                multiplier: multiplier[7],
                _pad: [0; 3],
            },
        ]
    }
}

/// 🍰 scx_cake: A sched_ext scheduler applying CAKE bufferbloat concepts
///
/// This scheduler adapts CAKE's DRR++ (Deficit Round Robin++) algorithm
/// for CPU scheduling, providing low-latency scheduling for gaming and
/// interactive workloads while maintaining fairness.
///
/// PROFILES set all tuning parameters at once. Individual options override profile defaults.
///
/// SPARSE SCORE SYSTEM:
///   Tasks are scored 0-100 based on CPU usage behavior.
///   - GROWTH: +4 points per sparse run (runtime < threshold)
///   - DECAY:  -6 points per heavy run (runtime >= threshold)
///   - Threshold = quantum × sparse_threshold / 1024
///
/// EXAMPLES:
///   scx_cake                          # Run with gaming profile (default)
///   scx_cake -p esports               # Ultra-low-latency for competitive play
///   scx_cake --quantum 1500           # Gaming profile with custom quantum
///   scx_cake -v                       # Run with live TUI stats display
#[derive(Parser, Debug)]
#[command(
    author,
    version,
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
    ///   - Quantum: 1000µs, Sparse threshold: 50‰, Starvation: 50ms
    ///   - Sparse cutoff: ~49µs (1ms × 50 / 1024)
    ///   - Tighter wait budgets, faster preemption
    ///
    /// LEGACY: Optimized for older/lower-power hardware.
    ///   - Quantum: 4000µs, Sparse threshold: 30‰, Starvation: 200ms
    ///   - Sparse cutoff: ~117µs (4ms × 30 / 1024)
    ///   - Relaxed requirements to reduce scheduling overhead
    ///
    /// GAMING: Optimized for low-latency gaming and interactive workloads.
    ///   - Quantum: 2000µs, Sparse threshold: 50‰, Starvation: 100ms
    ///   - Sparse cutoff: ~98µs (2ms × 50 / 1024)
    ///
    /// DEFAULT: Balanced profile for general desktop use.
    ///   - Currently same as gaming; will diverge in future versions
    #[arg(long, short, value_enum, default_value_t = Profile::Gaming, verbatim_doc_comment)]
    profile: Profile,

    /// Base scheduling time slice in MICROSECONDS [default: 2000].
    ///
    /// How long a task runs before potentially yielding. Affects sparse detection:
    ///   Sparse cutoff = quantum × sparse_threshold / 1024
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

    /// Sparse flow threshold in PERMILLE (0-1000) [default: 50].
    ///
    /// Tasks using less than (quantum × threshold / 1024) nanoseconds
    /// are classified as "sparse" and gain +4 score points.
    /// Tasks above this lose -6 points (asymmetric for stability).
    ///
    /// Example with default values (Gaming profile):
    ///   2,000,000ns × 50 / 1024 = 97,656ns (~98µs)
    ///   Task running <98µs = sparse (+4), >=98µs = heavy (-6)
    ///
    /// Legacy: 40,000ns (4000µs * 30 / 1024 approx 117µs cutoff)
    /// Lower values = stricter sparse classification.
    /// Recommended range: 30-200
    #[arg(long, verbatim_doc_comment)]
    sparse_threshold: Option<u64>,

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
    /// Shows dispatch counts per tier, sparse promotions/demotions,
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
}

impl Args {
    /// Get effective values (profile defaults with CLI overrides applied)
    fn effective_values(&self) -> (u64, u64, u64, u64) {
        let (q, nfb, st, starv) = self.profile.values();
        (
            self.quantum.unwrap_or(q),
            self.new_flow_bonus.unwrap_or(nfb),
            self.sparse_threshold.unwrap_or(st),
            self.starvation.unwrap_or(starv),
        )
    }
}

struct Scheduler<'a> {
    skel: BpfSkel<'a>,
    args: Args,
    topology: topology::TopologyInfo,
}

impl<'a> Scheduler<'a> {
    fn new(
        args: Args,
        open_object: &'a mut std::mem::MaybeUninit<libbpf_rs::OpenObject>,
    ) -> Result<Self> {
        use libbpf_rs::skel::{OpenSkel, SkelBuilder};

        // Open and load the BPF skeleton
        let skel_builder = BpfSkelBuilder::default();

        let mut open_skel = skel_builder
            .open(open_object)
            .context("Failed to open BPF skeleton")?;

        // Detect system topology (CCDs, P/E cores)
        let topo = topology::detect()?;

        // Get effective values (profile + CLI overrides)
        let (quantum, new_flow_bonus, sparse_threshold, starvation) = args.effective_values();

        // Configure the scheduler via rodata (read-only data)
        // All values are pre-computed here - zero runtime overhead in BPF
        if let Some(rodata) = &mut open_skel.maps.rodata_data {
            // Top-level configuration
            rodata.quantum_ns = quantum * 1000;
            rodata.new_flow_bonus_ns = new_flow_bonus * 1000;
            rodata.sparse_threshold = sparse_threshold;
            rodata.starvation_ns = starvation * 1000;
            rodata.enable_stats = args.verbose;

            // Pre-computed tier configuration (AoS - single cache line per tier)
            rodata.tier_configs = args.profile.tier_configs();

            // Topology arrays (zero runtime overhead)
            rodata.has_multi_llc = topo.has_dual_ccd;
            rodata.has_hybrid = topo.has_hybrid_cores;
            rodata.smt_enabled = topo.smt_enabled;
            rodata.cpu_llc_id = topo.cpu_llc_id;
            rodata.cpu_is_big = topo.cpu_is_big;
            rodata.cpu_sibling_map = topo.cpu_sibling_map;
            rodata.llc_cpu_mask = topo.llc_cpu_mask;
            rodata.big_cpu_mask = topo.big_cpu_mask;
        }

        // Load the BPF program
        let skel = open_skel.load().context("Failed to load BPF program")?;

        // Populate Static Topology Preference Map (Data-Oriented Design)
        // Pre-compute CPU preference lists at startup for O(1) BPF lookup.
        // This replaces runtime topology calculation with simple array iteration.
        let preference_vectors = topo.generate_preference_map();
        for (cpu, vec) in preference_vectors.iter().enumerate() {
            let key = (cpu as u32).to_ne_bytes();
            skel.maps
                .topo_preference_map
                .update(&key, vec.as_bytes(), libbpf_rs::MapFlags::ANY)
                .with_context(|| format!("Failed to update topo_preference_map for CPU {}", cpu))?;
        }
        info!(
            "Populated topology preference map for {} CPUs",
            topo.nr_cpus
        );

        Ok(Self {
            skel,
            args,
            topology: topo,
        })
    }

    fn run(&mut self, shutdown: Arc<AtomicBool>) -> Result<()> {
        // Attach the scheduler
        let _link = self
            .skel
            .maps
            .cake_ops
            .attach_struct_ops()
            .context("Failed to attach scheduler")?;

        let (quantum, new_flow_bonus, sparse_threshold, starvation) = self.args.effective_values();

        info!(
            "scx_cake scheduler started (profile: {:?})",
            self.args.profile
        );
        info!("  Quantum:          {} µs", quantum);
        info!("  New flow bonus:   {} µs", new_flow_bonus);
        info!("  Sparse threshold: {}‰", sparse_threshold);
        info!("  Starvation limit: {} µs", starvation);

        if self.args.verbose {
            // Run TUI mode
            tui::run_tui(
                &mut self.skel,
                shutdown.clone(),
                self.args.interval,
                self.topology.clone(),
            )?;
        } else {
            // Silent mode - just wait for shutdown
            while !shutdown.load(Ordering::Relaxed) {
                std::thread::sleep(Duration::from_secs(self.args.interval));

                // Check for scheduler exit using the UEI
                if scx_utils::uei_exited!(&self.skel, uei) {
                    match scx_utils::uei_report!(&self.skel, uei) {
                        Ok(reason) => {
                            warn!("BPF scheduler exited: {:?}", reason);
                        }
                        Err(e) => {
                            warn!("BPF scheduler exited (failed to get reason: {})", e);
                        }
                    }
                    break;
                }
            }
        }

        info!("scx_cake scheduler shutting down");
        Ok(())
    }
}

fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let args = Args::parse();

    // Set up signal handler
    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_clone = shutdown.clone();

    ctrlc::set_handler(move || {
        info!("Received shutdown signal");
        shutdown_clone.store(true, Ordering::Relaxed);
    })?;

    // Create open object for BPF - needs to outlive scheduler
    let mut open_object = std::mem::MaybeUninit::uninit();

    // Create and run the scheduler
    let mut scheduler = Scheduler::new(args, &mut open_object)?;
    scheduler.run(shutdown)?;

    Ok(())
}
