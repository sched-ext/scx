// SPDX-License-Identifier: GPL-2.0
// scx_cake - sched_ext scheduler applying CAKE bufferbloat concepts to CPU scheduling

mod topology;
mod tui;

use core::sync::atomic::Ordering;
use std::io::IsTerminal;
use std::os::fd::AsRawFd;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::{Parser, ValueEnum};
use log::{info, warn};
use nix::sys::signal::{SigSet, Signal};
use nix::sys::signalfd::{SfdFlags, SignalFd};
use scx_arena::ArenaLib;
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

    /// DVFS enabled — only Battery profile activates frequency steering
    fn dvfs_enabled(&self) -> bool {
        matches!(self, Profile::Battery)
    }

    /// DVFS per-tier CPU performance targets (SCX_CPUPERF_ONE = 1024 = max)
    /// Returns None for profiles that don't use DVFS.
    fn dvfs_targets(&self) -> Option<[u32; 8]> {
        match self {
            Profile::Battery => Some([
                1024, // T0 Critical: 100% — IRQ, input, audio (never throttle)
                896,  // T1 Interactive: 87.5% — compositor, physics
                768,  // T2 Frame: 75% — game render (P ∘ V²f savings)
                512,  // T3 Bulk: 50% — background tasks at half speed
                512, 512, 512, 512, // Padding
            ]),
            _ => None,
        }
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
/// 4-TIER SYSTEM (classified by avg_runtime):
///   T0 Critical  (<100µs): IRQ, input, audio, network
///   T1 Interact  (<2ms):   compositor, physics, AI
///   T2 Frame     (<8ms):   game render, encoding
///   T3 Bulk      (≥8ms):   compilation, background
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
    ///   - Quantum: 4000µs, DVFS enabled, per-tier frequency scaling
    ///   - T0: 100%, T1: 87.5%, T2: 75%, T3: 50%
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
}

impl<'a> Scheduler<'a> {
    fn new(
        args: Args,
        open_object: &'a mut std::mem::MaybeUninit<libbpf_rs::OpenObject>,
    ) -> Result<Self> {
        use libbpf_rs::skel::{OpenSkel, Skel, SkelBuilder};

        // Open and load the BPF skeleton
        let skel_builder = BpfSkelBuilder::default();

        let mut open_skel = skel_builder
            .open(open_object)
            .context("Failed to open BPF skeleton")?;

        // Populate SCX enum RODATA from kernel BTF (SCX_DSQ_LOCAL_ON, SCX_KICK_PREEMPT, etc.)
        scx_utils::import_enums!(open_skel);

        // Detect system topology (CCDs, P/E cores)
        let topo = topology::detect()?;

        // Get effective values (profile + CLI overrides)
        let (quantum, new_flow_bonus, _starvation) = args.effective_values();

        // Latency matrix: zeroed, populated by TUI Topology tab if --verbose
        let latency_matrix = vec![vec![0.0; topo.nr_cpus]; topo.nr_cpus];

        // Configure the scheduler via rodata (read-only data)
        if let Some(rodata) = &mut open_skel.maps.rodata_data {
            rodata.quantum_ns = quantum * 1000;
            rodata.new_flow_bonus_ns = new_flow_bonus * 1000;
            rodata.enable_stats = args.verbose || args.testing;

            // DVFS: Battery profile enables per-tier CPU frequency steering
            rodata.enable_dvfs = args.profile.dvfs_enabled();
            if let Some(targets) = args.profile.dvfs_targets() {
                rodata.tier_perf_target = targets;
            }

            // Topology: has_hybrid enables P/E-core DVFS scaling in cake_tick
            rodata.has_hybrid = topo.has_hybrid_cores;

            // Per-LLC DSQ partitioning: populate CPU→LLC mapping
            let llc_count = topo.llc_cpu_mask.iter().filter(|&&m| m != 0).count() as u32;
            rodata.nr_llcs = llc_count.max(1);
            rodata.nr_cpus = topo.nr_cpus.min(64) as u32; // Rule 39: bounds kick scan loop
            rodata.nr_phys_cpus = topo.nr_phys_cpus.min(64) as u32; // V3: PHYS_FIRST scan mask

            // Ferry explicit 64-bit topology arrays down into BPF (O(1) execution replacements)

            // Heterogeneous Gaming Topology
            rodata.big_core_phys_mask = topo.big_core_phys_mask;
            rodata.big_core_smt_mask = topo.big_core_smt_mask;
            rodata.little_core_mask = topo.little_core_mask;
            rodata.vcache_llc_mask = topo.vcache_llc_mask;
            rodata.has_vcache = topo.has_vcache;

            for i in 0..topo.cpu_sibling_map.len() {
                rodata.cpu_sibling_map[i] = topo.cpu_sibling_map[i];
            }
            for i in 0..topo.llc_cpu_mask.len().min(8) {
                rodata.llc_cpu_mask[i] = topo.llc_cpu_mask[i];
            }
            for i in 0..topo.core_cpu_mask.len().min(32) {
                rodata.core_cpu_mask[i] = topo.core_cpu_mask[i];
            }

            for (i, &llc_id) in topo.cpu_llc_id.iter().enumerate() {
                rodata.cpu_llc_id[i] = llc_id as u32;
            }
            // Arena library: nr_cpu_ids must be set before load() — arena_init
            // checks this and returns -ENODEV (errno 19) if uninitialized.
            rodata.nr_cpu_ids = *NR_CPU_IDS as u32;
        }

        // Load the BPF program
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

        Ok(Self {
            skel,
            args,
            topology: topo,
            latency_matrix,
        })
    }

    fn run(&mut self, shutdown: Arc<AtomicBool>) -> Result<()> {
        // Attach the scheduler
        let link = self
            .skel
            .maps
            .cake_ops
            .attach_struct_ops()
            .context("Failed to attach scheduler")?;

        // Standard startup: simple log message like other sched_ext schedulers
        let version = env!("CARGO_PKG_VERSION");
        info!(
            "scx_cake v{} started ({} CPUs, {} LLCs, profile: {:?})",
            version,
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
            // Event-based silent mode - block on signalfd, poll with 60s timeout for UEI check
            // Signals are already blocked from main() — just create signalfd to read them
            let mut mask = SigSet::empty();
            mask.add(Signal::SIGINT);
            mask.add(Signal::SIGTERM);

            // Create signalfd to receive signals as readable events
            let sfd = SignalFd::with_flags(&mask, SfdFlags::SFD_NONBLOCK)
                .context("Failed to create signalfd")?;

            use nix::poll::{poll, PollFd, PollFlags};
            use std::os::fd::BorrowedFd;

            loop {
                // Block for up to 60 seconds, then check UEI
                // poll() returns: >0 = readable, 0 = timeout, -1 = error
                // SAFETY: sfd is valid for the duration of this loop
                let poll_fd = unsafe {
                    PollFd::new(BorrowedFd::borrow_raw(sfd.as_raw_fd()), PollFlags::POLLIN)
                };
                let mut fds = [poll_fd];
                let result = poll(&mut fds, nix::poll::PollTimeout::from(60_000u16)); // 60 seconds

                match result {
                    Ok(n) if n > 0 => {
                        // Signal received - read it to clear and exit
                        if let Ok(Some(siginfo)) = sfd.read_signal() {
                            info!("Received signal {} - shutting down", siginfo.ssi_signo);
                            shutdown.store(true, Ordering::Relaxed);
                        }
                        break;
                    }
                    Ok(_) => {
                        // Timeout - check UEI
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
                    Err(nix::errno::Errno::EINTR) => {
                        // Interrupted - check shutdown flag
                        if shutdown.load(Ordering::Relaxed) {
                            break;
                        }
                    }
                    Err(e) => {
                        warn!("poll() error: {}", e);
                        break;
                    }
                }
            }
        }

        info!("scx_cake scheduler shutting down");

        // Drop struct_ops link BEFORE uei_report — this triggers the kernel to
        // set UEI kind=SCX_EXIT_UNREG. Matches scx_bpfland/scx_p2dq/scx_lavd
        // pattern: `let _ = self.struct_ops.take(); uei_report!(...)`
        drop(link);

        // Standard UEI exit report — produces "EXIT: unregistered from user space".
        scx_utils::uei_report!(&self.skel, uei).map(|_| ())
    }
}

fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let args = Args::parse();

    // Block SIGINT/SIGTERM early, before any threads spawn (ctrlc crate spawns one).
    // This ensures signals are never delivered via default handler (which would
    // exit with 128+signum=143 in CI). signalfd in run() reads them cleanly.
    {
        let mut mask = SigSet::empty();
        mask.add(Signal::SIGINT);
        mask.add(Signal::SIGTERM);
        mask.thread_block().ok(); // best-effort; signalfd will catch in run()
    }

    // Set up signal handler (ctrlc thread inherits our signal mask)
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
