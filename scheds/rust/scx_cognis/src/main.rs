// Copyright (c) scx_cognis contributors
// SPDX-License-Identifier: GPL-2.0-only
//
// scx_cognis — BPF-first CPU Scheduler
//
// Cognis v2 keeps the scheduling policy in BPF and uses Rust as the control
// plane for loading, stats, restart handling, and a narrow compatibility
// fallback when work intentionally crosses into userspace:
//
//   ┌─────────────────────────────────────────────────────────────────────┐
//   │  ops.enqueue    → BPF local CPU / LLC / node / shared hierarchy      │
//   │  ops.dispatch   → bounded wake credit + virtual deadline handoff     │
//   │  fallback path  → dormant userspace compatibility path               │
//   │  ops.select_cpu → kernel idle-CPU query (pick_idle_cpu, atomic)     │
//   │  housekeeping   → slice-base refresh + observability cleanup         │
//   └─────────────────────────────────────────────────────────────────────┘
//
// Rust-side scheduler tables are fixed-size and allocated once at startup:
// no HashMap, BTreeSet, or per-event heap allocations on the scheduling path.
// The BPF side uses bounded DSQs and per-task local storage that is created
// when a task joins sched_ext, not on every dispatch event.
//
// The current implementation still uses scx_rustland_core as the userspace
// scaffold around sched_ext, but the policy shape is intentionally closer to
// bpfland/lavd: BPF owns placement and deadline ordering for the common case.

mod bpf_skel;
pub use bpf_skel::*;
pub mod bpf_intf;

#[rustfmt::skip]
mod bpf;
use bpf::*;

mod ai;
mod stats;
mod task_queue;
mod tui;

use std::io;
use std::mem::MaybeUninit;
use std::panic::{self, AssertUnwindSafe};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use std::os::unix::process::CommandExt;
use std::time::{Duration, Instant, SystemTime};

use anyhow::Context;
use anyhow::Result;
use clap::{Parser, ValueEnum};
use libbpf_rs::OpenObject;
use log::{debug, info, warn};
use procfs::process::Process;

use scx_stats::prelude::*;
use scx_utils::build_id;
use scx_utils::libbpf_clap_opts::LibbpfOpts;
use scx_utils::UserExitInfo;

use ai::{
    ExitObservation, HeuristicClassifier, SliceController, TaskFeatures, TaskLabel, TrustTable,
    SHAME_MAX,
};
use stats::Metrics;
use task_queue::{QueuePush, TaskQueue};
use tui::SharedState;

const SCHEDULER_NAME: &str = "Cognis";
const NSEC_PER_USEC: u64 = 1_000;
const NSEC_PER_SEC: u64 = 1_000_000_000;
const DEFAULT_DESKTOP_SLICE_NS: u64 = 1_000_000;
const DEFAULT_SERVER_SLICE_NS: u64 = 8_000_000;
const DEFAULT_DESKTOP_SLICE_MIN_NS: u64 = 250_000;
const DEFAULT_SERVER_SLICE_MIN_NS: u64 = 1_000_000;
const DEFAULT_DESKTOP_SLICE_LAG_NS: u64 = 40_000_000;
const DEFAULT_SERVER_SLICE_LAG_NS: u64 = 1_500_000;
const IDLE_BACKOFF: Duration = Duration::from_millis(5);
const RESTART_BACKOFF: Duration = Duration::from_millis(250);
const RAPID_FAILURE_WINDOW: Duration = Duration::from_secs(30);
const RAPID_FAILURE_LIMIT: u32 = 20;
const EXIT_CODE_SCHED_EXT_RUNTIME_FAILURE: i32 = 86;

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum SchedulerMode {
    Desktop,
    Server,
}

impl SchedulerMode {
    fn as_str(self) -> &'static str {
        match self {
            SchedulerMode::Desktop => "desktop",
            SchedulerMode::Server => "server",
        }
    }
}

// ── CLI Options ────────────────────────────────────────────────────────────

/// scx_cognis: a BPF-first CPU scheduler with a minimal userspace fallback.
///
/// Scheduling pipeline: a BPF local CPU / LLC / node / shared hierarchy owns
/// normal dispatch, while Rust stays available for stats, restart handling,
/// and a narrow compatibility fallback path.
#[derive(Debug, Parser)]
struct Opts {
    /// Maximum scheduling slice duration in microseconds.
    ///
    /// Set to 0 (default) to use the active profile default:
    /// desktop = 1000 µs, server = 8000 µs.
    ///
    /// This acts as the BPF-side slice ceiling and the userspace fallback
    /// slice reference.
    #[clap(short = 's', long, default_value = "0")]
    slice_us: u64,

    /// Minimum scheduling slice duration in microseconds.
    ///
    /// Set to 0 (default) to use the active profile default:
    /// desktop = 250 µs, server = 1000 µs.
    #[clap(short = 'S', long, default_value = "0")]
    slice_us_min: u64,

    /// Scheduling profile.
    ///
    /// `desktop` favors wake responsiveness, locality, and sticky short bursts.
    /// `server` favors shared overflow and steadier throughput under saturation.
    #[clap(long, value_enum, default_value = "desktop")]
    mode: SchedulerMode,

    /// If set, per-CPU tasks are dispatched directly to their only eligible CPU.
    #[clap(short = 'l', long, action = clap::ArgAction::SetTrue)]
    percpu_local: bool,

    /// If set, only tasks with SCHED_EXT policy are managed.
    #[clap(short = 'p', long, action = clap::ArgAction::SetTrue)]
    partial: bool,

    /// Exit debug dump buffer length. 0 = default.
    #[clap(long, default_value = "0")]
    exit_dump_len: u32,

    /// Enable verbose output (BPF details + tracefs events).
    #[clap(short = 'v', long, action = clap::ArgAction::SetTrue)]
    verbose: bool,

    /// Launch the ratatui TUI dashboard.
    #[clap(short = 't', long, action = clap::ArgAction::SetTrue)]
    tui: bool,

    /// Enable stats monitoring with the specified interval (seconds).
    #[clap(long)]
    stats: Option<f64>,

    /// Run in stats monitoring mode only (scheduler not launched).
    #[clap(long)]
    monitor: Option<f64>,

    /// Show descriptions for statistics.
    #[clap(long)]
    help_stats: bool,

    /// Print scheduler version and exit.
    #[clap(short = 'V', long, action = clap::ArgAction::SetTrue)]
    version: bool,

    #[clap(flatten, next_help_heading = "Libbpf Options")]
    pub libbpf: LibbpfOpts,
}

#[derive(Debug, Clone, Copy)]
struct BpfProfile {
    mode: SchedulerMode,
    slice_ns: u64,
    slice_min_ns: u64,
    slice_lag_ns: u64,
    no_wake_sync: bool,
    sticky_tasks: bool,
}

impl BpfProfile {
    fn from_opts(opts: &Opts) -> Self {
        let (default_slice_ns, default_min_ns, default_lag_ns, no_wake_sync, sticky_tasks) =
            match opts.mode {
                SchedulerMode::Desktop => (
                    DEFAULT_DESKTOP_SLICE_NS,
                    DEFAULT_DESKTOP_SLICE_MIN_NS,
                    DEFAULT_DESKTOP_SLICE_LAG_NS,
                    false,
                    true,
                ),
                SchedulerMode::Server => (
                    DEFAULT_SERVER_SLICE_NS,
                    DEFAULT_SERVER_SLICE_MIN_NS,
                    DEFAULT_SERVER_SLICE_LAG_NS,
                    true,
                    false,
                ),
            };

        let slice_ns = if opts.slice_us > 0 {
            opts.slice_us.saturating_mul(NSEC_PER_USEC)
        } else {
            default_slice_ns
        };
        let slice_min_ns = if opts.slice_us_min > 0 {
            opts.slice_us_min.saturating_mul(NSEC_PER_USEC)
        } else {
            default_min_ns
        };

        Self {
            mode: opts.mode,
            slice_ns: slice_ns.max(slice_min_ns),
            slice_min_ns,
            slice_lag_ns: default_lag_ns,
            no_wake_sync,
            sticky_tasks,
        }
    }

    fn is_server(self) -> bool {
        matches!(self.mode, SchedulerMode::Server)
    }
}

fn enabled_flag_summary(opts: &Opts) -> String {
    let mut flags = Vec::new();

    if opts.partial {
        flags.push("partial");
    }
    if opts.percpu_local {
        flags.push("percpu_local");
    }
    if opts.verbose {
        flags.push("verbose");
    }
    if opts.tui {
        flags.push("tui");
    }
    if opts.stats.is_some() {
        flags.push("stats");
    }

    if flags.is_empty() {
        "none".to_string()
    } else {
        flags.join(",")
    }
}

// ── Task record ────────────────────────────────────────────────────────────

/// A task in the user-space scheduler queues.
///
/// The compatibility fallback keeps only three effective lanes:
/// RT, wake-boosted, and general fair. `label` is retained for fallback
/// observability and minor wake-sensitive decisions, while `deadline` is used
/// for dispatch-time vtime handoff back into BPF.
#[derive(Debug, PartialEq, Clone)]
struct Task {
    qtask: QueuedTask,
    deadline: u64,
    timestamp: u64,
    label: TaskLabel,
    wake_boosted: bool,
    wake_credit_ns: u64,
    latency_sensitive: bool,
    /// Kernel worker threads should stay on their previously used CPU even
    /// when they reach Rust with a widened affinity mask on newer kernels.
    is_kernel_worker: bool,
    slice_ns: u64,
}

// ── Per-task lifetime tracking (for trust updates on exit) ─────────

#[derive(Debug, Default, Clone, Copy)]
struct TaskLifetime {
    slice_assigned_ns: u64,
    slice_used_ns: u64,
    preempted: bool,
    cheat_flagged: bool,
    /// Bounded per-task interactive slice credit. This acts like a small
    /// budget bank for wake-heavy desktop tasks so they do not restart every
    /// burst from the same purely global slice recommendation.
    interactive_slice_credit_ns: u64,
    /// Bounded per-PID additive renewal bias. Positive values add headroom to
    /// future latency-sensitive interactive slices; negative values trim that
    /// headroom back when the task stops using it.
    interactive_slice_bias_ns: i64,
    /// The time-slice (ns) that was assigned to this task on its most recent
    /// scheduling event.  Used in the next cycle as the denominator for
    /// `cpu_intensity = burst_ns / last_slice_ns`, which gives a reliable
    /// slice-usage fraction. Defaults to 0 (→ base_slice_ns is used instead).
    last_slice_ns: u64,
    /// Nanosecond timestamp from [`Scheduler::now_ns`] of the last time this
    /// PID was dequeued from BPF. Used to detect genuinely departed tasks so
    /// trust eviction only fires for tasks that have actually
    /// left, not for still-active tasks on every scheduling loop.
    last_seen_ns: u64,
    /// Monotonic BPF timestamp of the last time this PID released the CPU.
    /// The next enqueue uses this together with the new `start_ts` to measure
    /// the task's actual sleep gap instead of userspace queueing delay.
    last_stop_ts: u64,
}

// ── Main Scheduler Struct ──────────────────────────────────────────────────

/// Fixed capacity of each per-label task ring.
///
/// This is intentionally much larger than the upstream kernel→userspace ring
/// buffer depth so the userspace side can absorb bursts without reallocating.
/// One ring is allocated once per label at init and never grows afterwards.
const QUEUE_DEPTH: usize = 16_384;

/// Lifetime table size — must be a power of 2.  Sized to hold all concurrent
/// PIDs on even the largest NUMA servers with comfortable headroom.
const LIFETIME_TABLE_SIZE: usize = 4096;
const PID_SLOT_EMPTY: i32 = 0;
const PID_SLOT_TOMBSTONE: i32 = -1;

/// Fibonacci multiplier for i32 → table-slot hashing.
const FIB32_MAIN: u32 = 2_654_435_769;

struct Scheduler<'a> {
    bpf: BpfScheduler<'a>,
    opts: &'a Opts,
    profile: BpfProfile,
    stats_server: StatsServer<(), Metrics>,

    // Userspace fallback lanes:
    //   - RT
    //   - boosted wake-sensitive
    //   - general fair lane
    boosted_interactive_queue: TaskQueue<Task>,
    // Each queue has one inline deferred slot so a single saturation event can
    // be absorbed without losing a runnable task.
    rt_queue: TaskQueue<Task>,
    interactive_queue: TaskQueue<Task>,

    // Time tracking.
    vruntime_now: u64,
    init_page_faults: u64,
    /// Process start time used to compute uptime/elapsed for monitoring.
    start_time: Instant,
    base_slice_ns: u64,
    slice_ns_min: u64,

    // Scheduling policy components.
    classifier: HeuristicClassifier,
    trust: Box<TrustTable>,
    slice_controller: SliceController,

    // Fixed-size per-PID lifetime table (Fibonacci hash, zero-alloc after init).
    lifetime_table: Box<[TaskLifetime; LIFETIME_TABLE_SIZE]>,
    lifetime_pids: Box<[i32; LIFETIME_TABLE_SIZE]>,

    // TUI shared state (None if TUI not requested).
    tui_state: Option<SharedState>,
    /// Inline TUI terminal handle — avoids spawning a thread (prevents EPERM
    /// from cgroup pids.max limits when running under sudo).
    tui_term: Option<tui::Term>,
    tui_quit: bool,
    last_tui_render: Instant,
    last_tui_hist: Instant,

    // Periodic tick timers.
    last_trust_tick: Instant,
    last_slice_tick: Instant,
    /// Rate-limiter for [`flush_trust_updates`]: only runs once per second
    /// and only evicts PIDs that have not been seen for ≥ 2 s.
    last_trust_flush: Instant,
    /// True once stats response channel fails (e.g. broken pipe). Scheduling
    /// must continue regardless of stats client lifecycle.
    stats_channel_failed: bool,

    // Running counters for scheduling policy metrics.
    label_counts: [u64; 5],
    total_inference_ns: u64,
    inference_samples: u64,
    /// Exponential moving average of the final slice assigned after all
    /// per-task adjustments. Exported so monitor/TUI can show what tasks have
    /// actually been receiving instead of only the global slice base.
    assigned_slice_ema_ns: u64,
}

fn alloc_zeroed_boxed_array<T, const N: usize>(label: &'static str) -> Result<Box<[T; N]>> {
    let layout = std::alloc::Layout::array::<T>(N).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{label} layout overflow"),
        )
    })?;

    unsafe {
        let ptr = std::alloc::alloc_zeroed(layout) as *mut [T; N];
        if ptr.is_null() {
            return Err(io::Error::new(
                io::ErrorKind::OutOfMemory,
                format!("{label} allocation failed"),
            )
            .into());
        }
        Ok(Box::from_raw(ptr))
    }
}

impl<'a> Scheduler<'a> {
    fn init(
        opts: &'a Opts,
        open_object: &'a mut MaybeUninit<OpenObject>,
        shutdown: Arc<AtomicBool>,
    ) -> Result<Self> {
        let stats_server = StatsServer::new(stats::server_data()).launch()?;
        let profile = BpfProfile::from_opts(opts);
        let enabled_flags = enabled_flag_summary(opts);

        let base_slice_ns = profile.slice_ns;
        let slice_ns_min = profile.slice_min_ns;

        let slice_controller = SliceController::new(base_slice_ns);
        let initial_assigned_slice_ns = slice_controller.read_slice_ns();

        info!(
            "Starting {} v{} (mode={}, slice={}us, min_slice={}us, flags={})",
            SCHEDULER_NAME,
            build_id::full_version(env!("CARGO_PKG_VERSION")),
            profile.mode.as_str(),
            profile.slice_ns / NSEC_PER_USEC,
            profile.slice_min_ns / NSEC_PER_USEC,
            enabled_flags
        );

        let bpf = BpfScheduler::init(
            shutdown,
            open_object,
            opts.libbpf.clone().into_bpf_open_opts(),
            opts.exit_dump_len,
            opts.partial,
            opts.verbose,
            true,
            &profile,
            "cognis",
        )?;

        info!("Registered {SCHEDULER_NAME} scheduler");

        let tui_state = if opts.tui {
            Some(tui::new_shared_state())
        } else {
            None
        };
        // Set up TUI terminal inline — no thread spawned. The TUI is driven
        // from within the scheduler's main run() loop via tick_tui().
        let tui_term = if opts.tui {
            match tui::setup_terminal() {
                Ok(t) => Some(t),
                Err(e) => {
                    eprintln!("[WARN] TUI init failed: {e}; continuing without TUI");
                    None
                }
            }
        } else {
            None
        };

        debug!(
            "{} is using scx_rustland_core {}",
            SCHEDULER_NAME,
            scx_rustland_core::VERSION
        );

        Ok(Self {
            bpf,
            opts,
            profile,
            stats_server,
            boosted_interactive_queue: TaskQueue::with_capacity(QUEUE_DEPTH),
            rt_queue: TaskQueue::with_capacity(QUEUE_DEPTH),
            interactive_queue: TaskQueue::with_capacity(QUEUE_DEPTH),
            vruntime_now: 0,
            init_page_faults: 0,
            base_slice_ns,
            slice_ns_min,
            classifier: HeuristicClassifier::new(),
            trust: TrustTable::new().context("failed to allocate trust table")?,
            slice_controller,
            lifetime_table: alloc_zeroed_boxed_array("lifetime_table")?,
            lifetime_pids: alloc_zeroed_boxed_array("lifetime_pids")?,
            tui_state,
            tui_term,
            tui_quit: false,
            last_tui_render: Instant::now(),
            last_tui_hist: Instant::now(),
            start_time: Instant::now(),
            last_trust_tick: Instant::now(),
            last_slice_tick: Instant::now(),
            last_trust_flush: Instant::now(),
            stats_channel_failed: false,
            label_counts: [0; 5],
            total_inference_ns: 0,
            inference_samples: 0,
            assigned_slice_ema_ns: initial_assigned_slice_ns,
        })
    }

    // ── Helpers ────────────────────────────────────────────────────────────

    fn now_ns() -> u64 {
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64
    }

    #[inline(always)]
    fn sample_assigned_slice(&mut self, slice_ns: u64) {
        if self.assigned_slice_ema_ns == 0 {
            self.assigned_slice_ema_ns = slice_ns;
        } else {
            self.assigned_slice_ema_ns =
                (self.assigned_slice_ema_ns.saturating_mul(7) + slice_ns) / 8;
        }
    }

    #[inline(always)]
    fn effective_slice_pressure(nr_running: u64, nr_queued: u64, nr_scheduled: u64) -> u64 {
        nr_running
            .saturating_add(nr_queued)
            .saturating_add(nr_scheduled)
    }

    #[inline(always)]
    fn recent_sleep_gap_ns(prev_stop_ts: u64, current_start_ts: u64) -> u64 {
        if prev_stop_ts == 0 {
            0
        } else {
            current_start_ts.saturating_sub(prev_stop_ts)
        }
    }

    fn get_page_faults() -> Result<u64, io::Error> {
        let me = Process::myself().map_err(io::Error::other)?;
        let st = me.stat().map_err(io::Error::other)?;
        // Only count *major* faults (requires disk I/O — genuine swap pressure).
        // Minor faults (minflt) are normal anonymous-memory / CoW events and
        // accumulate constantly during ordinary operation; including them would
        // produce a permanently non-zero pf counter and a bogus TLDR warning.
        Ok(st.majflt)
    }

    fn scale_by_weight_inverse(task: &QueuedTask, value: u64) -> u64 {
        let weight = task.weight.max(1);
        value.saturating_mul(100) / weight
    }

    /// Returns true if the task's comm identifies a kernel worker thread.
    ///
    /// The upstream BPF backend fast-dispatches strictly per-CPU kthreads
    /// (`PF_KTHREAD && nr_cpus_allowed == 1`) before they reach Rust.  On
    /// Linux >= 6.13 the workqueue subsystem reworked per-CPU worker affinity:
    /// nominally per-CPU workers such as `kworker/N:M` may now carry
    /// `nr_cpus_allowed > 1` and fall through to the Rust scheduling loop.
    /// The heuristic classifier assigns them `Compute` (high cpu_intensity,
    /// low exec_ratio — they burst through slices without sleeping) — the
    /// lowest-priority bucket — where they starve behind Interactive and IoWait
    /// traffic until the 5 s sched_ext watchdog fires.
    ///
    /// This function detects such threads from their comm name and the caller
    /// forces them into the `RealTime` bucket so they are always dispatched
    /// before any user-space task.
    ///
    /// Zero allocation — operates directly on the fixed `[c_char; 16]` byte
    /// array.  Bounded by `TASK_COMM_LEN` (16 bytes) — O(1).
    #[inline(always)]
    fn is_kernel_worker(task: &QueuedTask) -> bool {
        // Reinterpret c_char (i8 on Linux) as bytes for ASCII comparison.
        let bytes: &[u8] =
            unsafe { std::slice::from_raw_parts(task.comm.as_ptr() as *const u8, task.comm.len()) };
        let len = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
        let s = &bytes[..len];

        // Kernel threads that embed '/' in their comm name:
        //   kworker/N:M, kworker/uN:M, ksoftirqd/N, rcuop/N, rcuog/N,
        //   migration/N, irq/N-name, idle_inject/N, cpuhp/N, watchdog/N.
        if s.contains(&b'/') {
            return true;
        }

        // Kernel daemons whose comm name does not include '/'.
        const KPREFIXES: &[&[u8]] = &[
            b"kswapd",
            b"khugepaged",
            b"kcompactd",
            b"kthreadd",
            b"kdevtmpfs",
            b"kauditd",
            b"kcryptd",
            b"kblockd",
        ];
        for prefix in KPREFIXES {
            if s.starts_with(prefix) {
                return true;
            }
        }
        false
    }

    // ── Fixed-table lifetime helpers ───────────────────────────────────

    /// Fibonacci hash: map PID → lifetime table slot.
    #[inline(always)]
    fn lifetime_slot(pid: i32) -> usize {
        ((pid as u32).wrapping_mul(FIB32_MAIN) >> 20) as usize
    }

    #[inline(always)]
    fn lifetime_find_slot(&self, pid: i32) -> Option<usize> {
        let start = Self::lifetime_slot(pid);

        for step in 0..LIFETIME_TABLE_SIZE {
            let s = (start + step) & (LIFETIME_TABLE_SIZE - 1);
            let cur = self.lifetime_pids[s];

            if cur == pid {
                return Some(s);
            }
            if cur == PID_SLOT_EMPTY {
                return None;
            }
        }

        None
    }

    #[inline(always)]
    fn lifetime_find_or_insert_slot(&mut self, pid: i32) -> usize {
        let start = Self::lifetime_slot(pid);
        let mut first_tombstone = None;

        for step in 0..LIFETIME_TABLE_SIZE {
            let s = (start + step) & (LIFETIME_TABLE_SIZE - 1);
            let cur = self.lifetime_pids[s];

            if cur == pid {
                return s;
            }
            if cur == PID_SLOT_TOMBSTONE && first_tombstone.is_none() {
                first_tombstone = Some(s);
                continue;
            }
            if cur == PID_SLOT_EMPTY {
                let dst = first_tombstone.unwrap_or(s);
                self.lifetime_pids[dst] = pid;
                self.lifetime_table[dst] = TaskLifetime::default();
                return dst;
            }
        }

        let dst = first_tombstone.unwrap_or(start);
        self.lifetime_pids[dst] = pid;
        self.lifetime_table[dst] = TaskLifetime::default();
        dst
    }

    /// Return shared reference to lifetime entry if this PID owns the slot.
    #[inline(always)]
    fn lifetime_get(&self, pid: i32) -> Option<&TaskLifetime> {
        self.lifetime_find_slot(pid)
            .filter(|_| pid > 0)
            .map(|s| &self.lifetime_table[s])
    }

    /// Return mutable reference to lifetime entry, evicting stale PID if needed.
    #[inline(always)]
    fn lifetime_get_mut_or_default(&mut self, pid: i32) -> &mut TaskLifetime {
        let s = self.lifetime_find_or_insert_slot(pid);
        &mut self.lifetime_table[s]
    }

    /// Evict the lifetime entry for a PID.
    #[inline(always)]
    fn lifetime_evict(&mut self, pid: i32) {
        if let Some(s) = self.lifetime_find_slot(pid) {
            self.lifetime_pids[s] = PID_SLOT_TOMBSTONE;
            self.lifetime_table[s] = TaskLifetime::default();
        }
    }

    fn drain_exited_tasks(&mut self, max_batch: usize) {
        for _ in 0..max_batch {
            match self.bpf.dequeue_exited_pid() {
                Ok(Some(pid)) if pid > 0 => {
                    self.lifetime_evict(pid);
                    self.trust.evict(pid);
                }
                Ok(Some(_)) => {}
                Ok(None) => break,
                Err(err) => {
                    warn!("dequeue_exited_pid error: {err}");
                    break;
                }
            }
        }
    }

    // ── Per-label fixed-capacity task queue helpers ────────────────────

    #[inline(always)]
    fn queue_is_starved(front: Option<&Task>, now: u64, threshold_ns: u64) -> bool {
        front.is_some_and(|t| now.saturating_sub(t.timestamp) >= threshold_ns)
    }

    #[inline(always)]
    fn has_deferred_tasks(&self) -> bool {
        self.boosted_interactive_queue.has_deferred()
            || self.rt_queue.has_deferred()
            || self.interactive_queue.has_deferred()
    }

    #[inline(always)]
    fn should_wake_boost(
        latency_sensitive: bool,
        exec_ratio: f32,
        cpu_intensity: f32,
        sleep_ns: u64,
    ) -> bool {
        const WAKE_BOOST_MIN_SLEEP_NS: u64 = 750_000;
        const WAKE_BOOST_MAX_SLEEP_NS: u64 = 25_000_000;

        latency_sensitive
            && (WAKE_BOOST_MIN_SLEEP_NS..=WAKE_BOOST_MAX_SLEEP_NS).contains(&sleep_ns)
            && exec_ratio >= 0.60
            && cpu_intensity >= 0.45
    }

    #[inline(always)]
    fn should_wake_preempt(
        wake_boosted: bool,
        latency_sensitive: bool,
        wake_credit_ns: u64,
        queued_ns: u64,
    ) -> bool {
        const WAKE_PREEMPT_MIN_CREDIT_NS: u64 = 1_000_000;
        const WAKE_PREEMPT_MAX_QUEUE_NS: u64 = 6_000_000;

        wake_boosted
            && latency_sensitive
            && wake_credit_ns >= WAKE_PREEMPT_MIN_CREDIT_NS
            && queued_ns <= WAKE_PREEMPT_MAX_QUEUE_NS
    }

    #[inline(always)]
    fn wake_deadline_credit_ns(&self, task: &Task) -> u64 {
        const WAKE_DEADLINE_CREDIT_NS: u64 = 4_000_000;

        if task.wake_boosted {
            task.wake_credit_ns
                .max(task.slice_ns / 2)
                .min(WAKE_DEADLINE_CREDIT_NS)
        } else {
            0
        }
    }

    #[inline(always)]
    fn interactive_sleep_bonus_ns(&self, sleep_ns: u64, ref_base: u64) -> u64 {
        const WAKE_BOOST_MIN_SLEEP_NS: u64 = 750_000;
        const WAKE_BOOST_MAX_SLEEP_NS: u64 = 25_000_000;

        if !(WAKE_BOOST_MIN_SLEEP_NS..=WAKE_BOOST_MAX_SLEEP_NS).contains(&sleep_ns) {
            return 0;
        }

        (sleep_ns / 4).clamp(self.slice_ns_min / 2, ref_base.max(self.slice_ns_min))
    }

    /// Route a task to the minimal set of userspace lanes:
    ///   - `rt_queue` for kernel workers / RT tasks
    ///   - `boosted_interactive_queue` for fresh short sleepers
    ///   - `interactive_queue` as the general fair fallback lane
    ///
    /// Buckets are allocated once at scheduler init and never resized. If a
    /// primary bucket is momentarily full, one inline deferred slot absorbs the
    /// extra task so the scheduler never drops runnable work on local queue
    /// saturation.
    #[inline(always)]
    fn push_task(&mut self, task: Task) {
        let label = task.label;
        let pid = task.qtask.pid;
        let (result, capacity) = {
            let q = match label {
                TaskLabel::RealTime => &mut self.rt_queue,
                _ if task.wake_boosted => &mut self.boosted_interactive_queue,
                _ => &mut self.interactive_queue,
            };
            (q.push_back(task), q.capacity())
        };

        match result {
            Ok(QueuePush::Primary) => {}
            Ok(QueuePush::Deferred) => {
                let congested = self.bpf.nr_sched_congested_mut();
                *congested = congested.saturating_add(1);
                warn!(
                    "userspace task queue saturated for pid {} (label {:?}, capacity {}); deferred intake without dropping runnable work",
                    pid,
                    label,
                    capacity
                );
            }
            Err(task) => {
                warn!(
                    "userspace task queue invariant violated for pid {} (label {:?}, capacity {}); no free deferred slot remained",
                    task.qtask.pid,
                    task.label,
                    capacity
                );
                debug_assert!(false, "deferred queue invariant violated");
            }
        }
    }

    /// Pop the highest-priority task available across the three active lanes.
    ///
    /// This intentionally keeps userspace arbitration minimal:
    ///   - RT lane first
    ///   - then a bounded wake-sensitive lane
    ///   - then a general fair lane
    ///
    /// Fine-grained ordering among non-RT tasks is delegated to BPF's
    /// vtime-ordered shared DSQ via the dispatched virtual deadline.
    #[inline(always)]
    fn pop_highest_priority_task(&mut self) -> Option<Task> {
        const BOOSTED_INTERACTIVE_STARVATION_NS: u64 = 12_000_000;

        if let Some(t) = self.rt_queue.pop_front() {
            return Some(t);
        }

        let now = Self::now_ns();

        if self.boosted_interactive_queue.front().is_some_and(|task| {
            Self::should_wake_preempt(
                task.wake_boosted,
                task.latency_sensitive,
                task.wake_credit_ns,
                now.saturating_sub(task.timestamp),
            )
        }) {
            return self.boosted_interactive_queue.pop_front();
        }

        if Self::queue_is_starved(
            self.boosted_interactive_queue.front(),
            now,
            BOOSTED_INTERACTIVE_STARVATION_NS,
        ) {
            return self.boosted_interactive_queue.pop_front();
        }

        if let Some(t) = self.boosted_interactive_queue.pop_front() {
            return Some(t);
        }
        self.interactive_queue.pop_front()
    }

    /// True when all active task lanes are empty.
    #[inline(always)]
    fn tasks_empty(&self) -> bool {
        self.boosted_interactive_queue.is_empty()
            && self.rt_queue.is_empty()
            && self.interactive_queue.is_empty()
    }

    /// Total number of tasks across all active lanes.
    #[inline(always)]
    fn tasks_len(&self) -> usize {
        self.boosted_interactive_queue.len() + self.rt_queue.len() + self.interactive_queue.len()
    }

    // ── Scheduling pipeline (ops.enqueue) ───────────────────────────────

    /// Compute task features from a QueuedTask.
    ///
    /// `prev_slice_ns` is the slice duration that was assigned to this task
    /// on its most recent scheduling event (read from `lifetimes`).  If no
    /// history is available yet, the caller passes `base_slice_ns` instead.
    ///
    /// The key feature is `cpu_intensity = burst_ns / prev_slice_ns`, i.e.
    /// "what fraction of its assigned slice did the task actually consume?".
    /// This is unambiguous and stable:
    ///   • ≈ 1.0  task ran to the end of its slice → CPU-bound (Compute)
    ///   • ≈ 0.0  task released the CPU long before the slice expired → I/O-bound
    ///   • ≈ 0.3–0.8  task yields regularly → Interactive
    ///
    /// No dependency on `exec_runtime` semantics, no normalisation against a
    /// global constant that can produce degenerate extreme values.
    fn compute_features(
        task: &QueuedTask,
        base_slice_ns: u64,
        prev_slice_ns: u64,
        nr_cpus: i32,
    ) -> TaskFeatures {
        let burst_ns = task.stop_ts.saturating_sub(task.start_ts);

        // Primary classification feature: slice-usage fraction.
        // prev_slice_ns is the slice assigned in the *previous* cycle for this PID.
        // On a task's very first scheduling event, base_slice_ns is used as a stand-in.
        let denominator = prev_slice_ns.max(1);
        let cpu_intensity = (burst_ns as f64 / denominator as f64).clamp(0.0, 1.0) as f32;

        // Secondary feature: burst relative to the *target* base slice.
        // Kept for lightweight behavioral labelling and observability.
        let runnable_ratio = if base_slice_ns > 0 {
            (burst_ns as f64 / base_slice_ns as f64).clamp(0.0, 1.0) as f32
        } else {
            0.0
        };

        // Freshness: how fresh is this burst relative to accumulated CPU time?
        // Near 1.0 → task just woke (interactive/IO); near 0.0 → never sleeps (compute).
        let exec_ratio = if task.exec_runtime > 0 {
            (burst_ns as f64 / task.exec_runtime as f64).clamp(0.0, 1.0) as f32
        } else {
            1.0
        };

        let weight_norm = (task.weight as f32 / 10000.0).clamp(0.0, 1.0);

        TaskFeatures {
            runnable_ratio,
            cpu_intensity,
            exec_ratio,
            weight_norm,
            cpu_affinity: (task.nr_cpus_allowed as f32 / (nr_cpus as f32).max(1.0)).clamp(0.0, 1.0),
        }
    }

    #[inline(always)]
    fn is_latency_sensitive(label: TaskLabel, features: &TaskFeatures, sleep_ns: u64) -> bool {
        const WAKE_BOOST_MIN_SLEEP_NS: u64 = 750_000;
        const WAKE_BOOST_MAX_SLEEP_NS: u64 = 25_000_000;

        matches!(label, TaskLabel::Interactive | TaskLabel::IoWait)
            && (WAKE_BOOST_MIN_SLEEP_NS..=WAKE_BOOST_MAX_SLEEP_NS).contains(&sleep_ns)
            && features.exec_ratio >= 0.55
            && features.cpu_intensity >= 0.30
    }

    fn derive_task_policy(
        &mut self,
        task: &mut QueuedTask,
    ) -> (u64, u64, TaskLabel, bool, bool, bool, u64) {
        let t0 = Self::now_ns();

        let nr_cpus = (*self.bpf.nr_online_cpus_mut()).max(1) as i32;

        // Use the slice assigned to this PID in the previous cycle as the
        // denominator for cpu_intensity (= burst_ns / prev_slice_ns).
        //
        // On the very first event for a new PID there is no lifetime entry yet.
        // Fall back to the configured profile slice ceiling, clamped to at
        // least 1 ms so cpu_intensity remains meaningful on fresh tasks.
        let prev_slice_ns = self
            .lifetime_get(task.pid)
            .filter(|lt| lt.last_slice_ns > 0)
            .map(|lt| lt.last_slice_ns)
            .unwrap_or_else(|| self.base_slice_ns.max(NSEC_PER_USEC * 1_000));
        let recent_sleep_ns = self
            .lifetime_get(task.pid)
            .map(|lt| Self::recent_sleep_gap_ns(lt.last_stop_ts, task.start_ts))
            .unwrap_or(0);

        // Build features.
        let features = Self::compute_features(task, self.base_slice_ns, prev_slice_ns, nr_cpus);

        // Detect kernel workers before the label is computed.
        // Unbound kthreads (nr_cpus_allowed > 1 on Linux >= 6.13) are not
        // always caught by the BPF per-CPU fast-dispatch guard. Force them
        // into the RT lane here so they never wait behind user-space fallback
        // traffic.
        let is_kworker = Self::is_kernel_worker(task);

        // Classify using a small deterministic heuristic.
        // Labels are primarily observational now; the userspace fallback does
        // not build a deep multi-class priority tree from them.
        let label = if is_kworker {
            TaskLabel::RealTime
        } else {
            self.classifier.classify(&features)
        };
        let latency_sensitive = Self::is_latency_sensitive(label, &features, recent_sleep_ns);
        self.label_counts[label as usize] += 1;

        // Load-adjusted deterministic base slice.
        let ai_slice = self.slice_controller.read_slice_ns();
        let ref_base = self.base_slice_ns;

        // Research-driven userspace fallback:
        //   - one pressure-based base slice
        //   - weight-scaled service
        //   - bounded wakeup credit for recent sleepers
        // Avoid hot-path reputation / prediction / per-app whitelists.
        let mut slice = ai_slice.saturating_mul(task.weight.max(1)) / 100;

        let wake_boosted = Self::should_wake_boost(
            latency_sensitive,
            features.exec_ratio,
            features.cpu_intensity,
            recent_sleep_ns,
        );
        if wake_boosted {
            slice = slice
                .saturating_add(self.interactive_sleep_bonus_ns(recent_sleep_ns, ref_base) / 2);
        }

        let clamp_max = (ref_base * 4).max(self.slice_ns_min);
        slice = slice.clamp(self.slice_ns_min, clamp_max);
        if matches!(label, TaskLabel::RealTime) {
            slice = slice.max(ref_base).min(clamp_max);
        }
        self.sample_assigned_slice(slice);

        let burst_ns = task.stop_ts.saturating_sub(task.start_ts);
        let wake_credit_ns = if wake_boosted {
            self.interactive_sleep_bonus_ns(recent_sleep_ns, ref_base)
                .max(self.slice_ns_min / 2)
                .min(slice)
                .min(4_000_000)
        } else {
            0
        };

        // Update vruntime / deadline.
        //
        // vruntime_now tracks the MAXIMUM observed task vtime — the "virtual
        // clock front".  This matches the scx_rustland reference pattern:
        //   1. New tasks (vtime == 0) start exactly at the current front so
        //      they enter the BTreeSet at the end of the queue, not at the
        //      very beginning (which would give them spurious burst priority).
        //   2. Sleeping tasks can reclaim at most one base_slice of credit,
        //      preventing any preemption cascade when they wake up.
        //   3. Using max() instead of a leaky ÷8 additive keeps vruntime_now
        //      aligned with the true task-vtime front regardless of how many
        //      tasks drain_queued_tasks() processes in a single batch.
        task.vtime = if task.vtime == 0 {
            self.vruntime_now
        } else {
            // Sleeping tasks gain at most one auto/base-slice of credit.
            // Use `ref_base` (policy auto_base or user override) as the cap so
            // the credit stays meaningful even in auto-slice mode.
            let vruntime_min = self.vruntime_now.saturating_sub(ref_base);
            task.vtime.max(vruntime_min)
        };
        let slice_ns_actual = burst_ns;
        let vslice = Self::scale_by_weight_inverse(task, slice_ns_actual);
        task.vtime = task.vtime.saturating_add(vslice);
        // Advance the virtual clock to the new task vtime front.
        self.vruntime_now = self.vruntime_now.max(task.vtime);

        // Approximate an EEVDF-style virtual deadline with a bounded wakeup
        // credit. This keeps the userspace fallback mechanically simple:
        // fair virtual service first, then a small latency credit for
        // short-sleeping tasks.
        let deadline = if matches!(label, TaskLabel::RealTime) {
            0
        } else {
            task.vtime
                .saturating_add(Self::scale_by_weight_inverse(task, slice))
        };

        // Track inference latency.
        let elapsed = Self::now_ns().saturating_sub(t0);
        self.total_inference_ns += elapsed;
        self.inference_samples += 1;

        (
            deadline,
            slice,
            label,
            is_kworker,
            latency_sensitive,
            wake_boosted,
            wake_credit_ns,
        )
    }

    // ── Drain queued tasks (runs scheduling pipeline per task) ──────────────

    fn drain_queued_tasks(&mut self, max_batch: usize) {
        let mut drained = 0usize;

        while drained < max_batch {
            // Once any queue has a deferred task, stop pulling more work from
            // BPF until the dispatch phase folds that deferred task back into
            // its primary FIFO. This prevents any runnable task from being
            // removed from the kernel ring without a guaranteed local slot.
            if self.has_deferred_tasks() {
                break;
            }

            // NOTE: the two early-break guards that existed here previously
            // ("stop if rt_queue non-empty" and "break on first RT task")
            // were removed because they caused a slow-drain loop of 1 task
            // per schedule() call under SCHED_FIFO load.  Priority ordering
            // is maintained by pop_highest_priority_task() in the dispatch
            // phase, which always dequeues RT tasks first regardless of drain
            // order.

            match self.bpf.dequeue_task() {
                Ok(Some(mut task)) => {
                    let (
                        deadline,
                        slice_ns,
                        label,
                        is_kernel_worker,
                        latency_sensitive,
                        wake_boosted,
                        wake_credit_ns,
                    ) = self.derive_task_policy(&mut task);
                    let timestamp = Self::now_ns();

                    // Track lifetime for trust updates.
                    let e = self.lifetime_get_mut_or_default(task.pid);
                    e.slice_assigned_ns = slice_ns;
                    // Store the assigned slice so the next scheduling event
                    // for this PID can compute cpu_intensity = burst / last_slice.
                    e.last_slice_ns = slice_ns;
                    e.slice_used_ns = task.stop_ts.saturating_sub(task.start_ts);
                    e.preempted = e.slice_used_ns >= slice_ns.saturating_sub(slice_ns / 8);
                    e.cheat_flagged = false;
                    e.interactive_slice_bias_ns = 0;
                    e.interactive_slice_credit_ns = 0;
                    e.last_seen_ns = Self::now_ns();
                    e.last_stop_ts = task.stop_ts;

                    self.push_task(Task {
                        deadline,
                        timestamp,
                        label,
                        wake_boosted,
                        wake_credit_ns,
                        latency_sensitive,
                        is_kernel_worker,
                        slice_ns,
                        qtask: task,
                    });

                    drained += 1;
                }
                Ok(None) => break,
                Err(err) => {
                    warn!("dequeue_task error: {err}");
                    break;
                }
            }
        }
    }

    // ── Dispatch one task (ops.dispatch) ──────────────────────────────────

    fn dispatch_task(&mut self) -> bool {
        let Some(task) = self.pop_highest_priority_task() else {
            return true;
        };

        let mut dispatched = DispatchedTask::new(&task.qtask);
        dispatched.slice_ns = task.slice_ns;
        // RealTime tasks (kworkers, SCHED_FIFO/RR) get vtime = 0 so they are
        // inserted at the front of BPF's vtime-ordered SHARED_DSQ.  Without
        // this, a kworker with a large exec_runtime would sort *behind* regular
        // tasks whose vtimes are near the global minimum, causing BPF-level
        // starvation even after the Rust scheduler dispatches them first.
        dispatched.vtime = if matches!(task.label, TaskLabel::RealTime) {
            0
        } else {
            task.deadline
                .saturating_sub(self.wake_deadline_credit_ns(&task))
        };

        // Keep userspace-managed work on the shared DSQ unless the user
        // explicitly requested per-CPU affinity or the task is a kernel worker.
        // Ordinary locality preservation now happens on the BPF enqueue fast
        // path before tasks ever cross into Rust.
        dispatched.cpu = if self.opts.percpu_local || task.is_kernel_worker {
            task.qtask.cpu
        } else {
            RL_CPU_ANY
        };

        if self.bpf.dispatch_task(&dispatched).is_err() {
            self.push_task(task);
            return false;
        }
        true
    }

    // ── Periodic housekeeping ───────────────────────────────────────────

    /// Trust/anomaly tick (every 100 ms).
    ///
    /// trust.tick() is an intentional no-op: the TrustTable is updated
    /// synchronously on each task exit (flush_trust_updates), so no
    /// periodic batch scan is needed.  The call is preserved for API symmetry
    /// and to leave a clear hook if periodic decay is added in the future.
    fn tick_trust(&mut self) {
        if self.last_trust_tick.elapsed() < Duration::from_millis(100) {
            return;
        }
        self.last_trust_tick = Instant::now();
        let now = Self::now_ns();
        let (_flagged, _n) = self.trust.tick(now);
        // No per-TGID warning needed; trust.worst_actors() exposes bad actors
        // through the TUI trust watchlist instead.
    }

    /// Deterministic slice update (every 50 ms).
    fn tick_slice_controller(&mut self) {
        if self.last_slice_tick.elapsed() < Duration::from_millis(50) {
            return;
        }
        self.last_slice_tick = Instant::now();

        let nr_cpus = (*self.bpf.nr_online_cpus_mut()).max(1);
        let nr_running = *self.bpf.nr_running_mut();
        let nr_queued = *self.bpf.nr_queued_mut();
        let nr_scheduled = *self.bpf.nr_scheduled_mut();
        let effective_pressure =
            Self::effective_slice_pressure(nr_running, nr_queued, nr_scheduled);

        // Keep the slice controller deterministic: one load-derived base slice,
        // no online exploration or adaptive sidecar policy.
        self.slice_controller.update(effective_pressure, nr_cpus);
    }

    /// Emit trust updates for finished tasks.
    ///
    /// Uses a staleness heuristic: any PID not seen for > 2 seconds is
    /// assumed to have exited. Called once per second.
    ///
    /// Zero heap allocations: stale PIDs are collected into a stack-allocated
    /// fixed array instead of a Vec.
    fn flush_trust_updates(&mut self) {
        // Run at most once per second.
        if self.last_trust_flush.elapsed() < Duration::from_secs(1) {
            return;
        }
        self.last_trust_flush = Instant::now();

        // Staleness-based exit detection remains as a fallback if the explicit
        // task-exit ring buffer overflows or the kernel misses an ops.disable
        // transition for a task.
        let now = Self::now_ns();
        const STALE_THRESHOLD_NS: u64 = 2 * NSEC_PER_SEC;

        // Collect stale PIDs into a fixed stack array (no heap allocation).
        let mut stale = [0i32; 256];
        let mut stale_n = 0usize;

        for s in 0..LIFETIME_TABLE_SIZE {
            let pid = self.lifetime_pids[s];
            if pid <= 0 {
                continue;
            }
            let lt = &self.lifetime_table[s];
            if lt.last_seen_ns > 0
                && now.saturating_sub(lt.last_seen_ns) >= STALE_THRESHOLD_NS
                && stale_n < stale.len()
            {
                stale[stale_n] = pid;
                stale_n += 1;
            }
        }

        for &pid in &stale[..stale_n] {
            // Snapshot the lifetime entry before evicting the slot.
            let lt = {
                if let Some(s) = self.lifetime_find_slot(pid) {
                    self.lifetime_table[s]
                } else {
                    continue;
                }
            };
            self.lifetime_evict(pid);

            let obs = ExitObservation {
                slice_underrun: lt.slice_used_ns < lt.slice_assigned_ns / 2,
                preempted: lt.preempted,
                clean_exit: !lt.cheat_flagged,
                cheat_flagged: lt.cheat_flagged,
                fork_count: 0,
                involuntary_ctx_sw: 0,
            };
            self.trust.update_on_exit(pid, pid, &obs, "");
        }
    }

    // ── Metrics snapshot ───────────────────────────────────────────────────

    fn get_metrics(&mut self) -> Metrics {
        let page_faults = Self::get_page_faults().unwrap_or_default();
        if self.init_page_faults == 0 {
            self.init_page_faults = page_faults;
        }

        let _total_labeled = self.label_counts.iter().sum::<u64>().max(1);

        let avg_inference_us = if self.inference_samples > 0 {
            self.total_inference_ns as f64 / self.inference_samples as f64 / 1000.0
        } else {
            0.0
        };

        let quarantined_count = self.trust.quarantined_count();

        // Scheduling latency percentiles (ns → µs)
        let (p50_ns, p95_ns, p99_ns) = self.slice_controller.compute_sched_percentiles();
        let p50_us = p50_ns / NSEC_PER_USEC;
        let p95_us = p95_ns / NSEC_PER_USEC;
        let p99_us = p99_ns / NSEC_PER_USEC;

        let dur = Instant::now().duration_since(self.start_time);
        let secs_total = dur.as_secs();

        Metrics {
            elapsed_secs: secs_total,
            nr_running: *self.bpf.nr_running_mut(),
            nr_cpus: *self.bpf.nr_online_cpus_mut(),
            nr_queued: *self.bpf.nr_queued_mut(),
            nr_scheduled: *self.bpf.nr_scheduled_mut(),
            nr_page_faults: page_faults.saturating_sub(self.init_page_faults),
            nr_user_dispatches: *self.bpf.nr_user_dispatches_mut(),
            nr_kernel_dispatches: *self.bpf.nr_kernel_dispatches_mut(),
            nr_local_dispatches: *self.bpf.nr_local_dispatches_mut(),
            nr_llc_dispatches: *self.bpf.nr_llc_dispatches_mut(),
            nr_node_dispatches: *self.bpf.nr_node_dispatches_mut(),
            nr_shared_dispatches: *self.bpf.nr_shared_dispatches_mut(),
            nr_xllc_steals: *self.bpf.nr_xllc_steals_mut(),
            nr_xnode_steals: *self.bpf.nr_xnode_steals_mut(),
            nr_cancel_dispatches: *self.bpf.nr_cancel_dispatches_mut(),
            nr_bounce_dispatches: *self.bpf.nr_bounce_dispatches_mut(),
            nr_failed_dispatches: *self.bpf.nr_failed_dispatches_mut(),
            nr_sched_congested: *self.bpf.nr_sched_congested_mut(),
            nr_interactive: self.label_counts[TaskLabel::Interactive as usize],
            nr_compute: self.label_counts[TaskLabel::Compute as usize],
            nr_iowait: self.label_counts[TaskLabel::IoWait as usize],
            nr_realtime: self.label_counts[TaskLabel::RealTime as usize],
            nr_unknown: self.label_counts[TaskLabel::Unknown as usize],
            nr_quarantined: quarantined_count,
            nr_flagged: self.trust.flagged_count(),
            base_slice_us: self.profile.slice_ns / NSEC_PER_USEC,
            assigned_slice_us: self.assigned_slice_ema_ns / NSEC_PER_USEC,
            slice_min_us: self.profile.slice_min_ns / NSEC_PER_USEC,
            slice_max_us: self.profile.slice_ns / NSEC_PER_USEC,
            inference_us: avg_inference_us as u64,
            sched_p50_us: p50_us,
            sched_p95_us: p95_us,
            sched_p99_us: p99_us,
        }
    }

    // ── Main scheduling loop ───────────────────────────────────────────────

    fn schedule(&mut self) {
        // Measure end-to-end scheduling pipeline latency for telemetry.
        let sched_t0 = Self::now_ns();

        // 1. Drain queued tasks in a bounded batch.
        //
        // Bound the batch so each schedule() call reaches the dispatch phase
        // quickly. 4× nr_cpus is enough to absorb normal bursts; any tasks
        // left in the BPF ring buffer trigger a re-invocation via
        // usersched_has_pending_tasks() automatically.
        let nr_cpus = (*self.bpf.nr_online_cpus_mut()).max(1) as usize;
        let drain_budget = nr_cpus.saturating_mul(4).max(16);
        self.drain_queued_tasks(drain_budget);

        // 2. Dispatch ALL queued tasks — no per-cycle cap.
        //
        // This is the critical fix for runnable-task stall crashes:
        //
        //   notify_complete(N > 0) sets nr_scheduled > 0, which makes
        //   usersched_has_pending_tasks() return true in BPF.  ops.dispatch
        //   then prioritises running the cognis kthread (SCHED_DSQ) over
        //   cpu_to_dsq(X) on every CPU X.  Kworkers dispatched by BPF to
        //   cpu_to_dsq(X) — the CPU currently hosting cognis — can only be
        //   consumed once that CPU stops picking cognis from SCHED_DSQ; if
        //   nr_scheduled stays > 0 for 5+ seconds the sched_ext watchdog fires.
        //
        //   By dispatching every internally-queued task before returning,
        //   tasks_len() == 0 → notify_complete(0) → nr_scheduled = 0 →
        //   usersched_has_pending_tasks() returns false → every CPU's
        //   ops.dispatch falls through to its local per-CPU DSQ and drains
        //   kworkers normally.
        //
        // Dispatch order is maintained by pop_highest_priority_task() (RT
        // first). User-space managed tasks fall back to SHARED_DSQ unless
        // they are explicitly per-CPU or kernel workers.
        while !self.tasks_empty() {
            if !self.dispatch_task() {
                break;
            }
        }

        // 3. Notify BPF dispatcher of remaining pending work.
        self.bpf.notify_complete(self.tasks_len() as u64);

        // Record the end-to-end schedule() latency (cheap, lock-free ring write).
        let sched_elapsed = Self::now_ns().saturating_sub(sched_t0);
        self.slice_controller
            .record_sched_event_latency(sched_elapsed);
    }

    // ── Background housekeeping ─────────────────────────────────────────────
    //
    // Kept OFF the schedule() critical path.  schedule() is called in a
    // tight BPF dispatch loop; any stall there risks the sched_ext watchdog
    // (which fires if ops.dispatch is not called for several seconds).
    //
    // All three inner functions carry their own rate-limit timers, so
    // calling housekeeping() every ~50 ms from run() is safe: each will
    // no-op immediately if its own timer has not elapsed.
    fn housekeeping(&mut self) {
        self.tick_trust();
        self.tick_slice_controller();
        self.flush_trust_updates();
    }

    // ── TUI state refresh ─────────────────────────────────────────────────

    fn update_tui(&mut self, metrics: &Metrics) {
        let Some(ref state) = self.tui_state else {
            return;
        };
        let avg_us = if self.inference_samples > 0 {
            self.total_inference_ns as f64 / self.inference_samples as f64 / 1_000.0
        } else {
            0.0
        };

        let (actors, n_actors) = self.trust.worst_actors();
        let mut watchlist = [tui::WallEntry::ZERO; SHAME_MAX];
        for (dst, src) in watchlist.iter_mut().zip(actors.iter()).take(n_actors) {
            *dst = tui::WallEntry {
                pid: src.pid,
                comm: src.comm,
                trust: src.trust as f64,
                is_flagged: src.flagged,
            };
        }

        if let Ok(mut s) = state.lock() {
            s.metrics = *metrics;
            s.inference_us = avg_us;
            s.set_watchlist(&watchlist, n_actors);
        }
    }

    fn run(&mut self) -> Result<UserExitInfo> {
        let (res_ch, req_ch) = self.stats_server.channels();
        let mut last_housekeeping = Instant::now();

        while !self.bpf.exited() {
            let has_userspace_work = !self.tasks_empty()
                || *self.bpf.nr_queued_mut() > 0
                || *self.bpf.nr_scheduled_mut() > 0;

            // Only run the compatibility fallback loop when work actually
            // crossed into userspace. Otherwise stay out of the way and let
            // the BPF-owned policy run without a busy Rust spin loop.
            if has_userspace_work {
                self.schedule();
            }
            self.drain_exited_tasks(128);

            // Stats: non-blocking try_recv so a disconnected client can't
            // block or crash the scheduler.
            if !self.stats_channel_failed && req_ch.try_recv().is_ok() {
                let m = self.get_metrics();
                self.update_tui(&m);
                if let Err(err) = res_ch.send(m) {
                    warn!(
                        "Stats response channel failed ({err}); continuing scheduler without stats responses"
                    );
                    self.stats_channel_failed = true;
                }
            }

            // Background housekeeping (trust engine tick, deterministic slice update, trust flush).
            // Runs outside schedule() so the BPF dispatch path is never
            // delayed by periodic work.  50 ms outer gate plus each
            // function's inner timer ensures at most one unit of work
            // executes between two consecutive schedule() calls.
            if last_housekeeping.elapsed() >= Duration::from_millis(50) {
                last_housekeeping = Instant::now();
                self.housekeeping();
            }

            // Inline TUI handling (no separate thread — avoids EPERM under sudo).
            // Input is polled every loop with a zero-timeout non-blocking poll
            // so 'q' / Esc remain responsive even under load. Rendering is
            // rate-limited to 10 FPS to keep terminal I/O bounded without
            // waiting for the scheduler to become completely idle.
            if self.tui_term.is_some() {
                if tui::poll_tui_quit() {
                    self.tui_quit = true;
                }

                let should_render = self.last_tui_render.elapsed() >= Duration::from_millis(100);
                if should_render {
                    self.last_tui_render = Instant::now();
                    // Feed fresh metrics to TUI state regardless of whether a
                    // stats client is connected (update_tui is normally only
                    // called when req_ch delivers a client request).
                    let m = self.get_metrics();
                    self.update_tui(&m);
                    if let (Some(ref state), Some(ref mut term)) =
                        (&self.tui_state, &mut self.tui_term)
                    {
                        tui::tick_tui(state, term, &mut self.last_tui_hist);
                    }
                }
            }
            if self.tui_quit {
                break;
            }

            if !has_userspace_work {
                std::thread::sleep(IDLE_BACKOFF);
            }
        }

        self.bpf.shutdown_and_report()
    }
}

impl Drop for Scheduler<'_> {
    fn drop(&mut self) {
        if let Some(ref mut term) = self.tui_term {
            let _ = tui::restore_terminal(term);
        }
        if let Some(name) = self.bpf.wait_for_detach() {
            warn!(
                "{SCHEDULER_NAME} scheduler stop requested, but {ROOT} still reports {name}",
                ROOT = "/sys/kernel/sched_ext/root/ops"
            );
        } else {
            info!("Unregistered {SCHEDULER_NAME} scheduler");
        }
    }
}

fn panic_payload_to_string(payload: &(dyn std::any::Any + Send)) -> String {
    if let Some(msg) = payload.downcast_ref::<&'static str>() {
        (*msg).to_string()
    } else if let Some(msg) = payload.downcast_ref::<String>() {
        msg.clone()
    } else {
        "unknown panic payload".to_string()
    }
}

fn runtime_exit_reason(err: &anyhow::Error) -> Option<String> {
    err.to_string()
        .strip_prefix("EXIT:")
        .map(|reason| reason.trim().to_string())
}

fn is_watchdog_runtime_exit(reason: &str) -> bool {
    reason.contains("runnable task stall") || reason.contains("watchdog failed to check in")
}

fn log_cognis_failure(reason: &str) {
    tui::emergency_restore_terminal();
    eprintln!();
    eprintln!("\x1b[31;1m╬══════════════════════════════════════════════════════════════╬\x1b[0m");
    eprintln!("\x1b[31;1m║  COGNIS SCHEDULER — PERMANENT FAILURE                        ║\x1b[0m");
    eprintln!("\x1b[31;1m╟──────────────────────────────────────────────────────────────╢\x1b[0m");
    eprintln!("\x1b[31;1m║  Cognis could not recover.  Your system has automatically     ║\x1b[0m");
    eprintln!("\x1b[31;1m║  fallen back to the kernel EEVDF scheduler.                  ║\x1b[0m");
    eprintln!("\x1b[31;1m╬══════════════════════════════════════════════════════════════╬\x1b[0m");
    eprintln!("  Reason  : {}", reason);
    eprintln!("  Recovery: sudo systemctl restart scx");
    eprintln!("            or: sudo scx_cognis --tui");
    eprintln!("  Report  : https://github.com/sched-ext/scx/issues/new");
    eprintln!();
    log::error!(
        "COGNIS PERMANENT FAILURE — system fell back to kernel EEVDF: {}",
        reason
    );
}

fn install_terminal_panic_hook() {
    let default_hook = panic::take_hook();
    panic::set_hook(Box::new(move |panic_info| {
        tui::emergency_restore_terminal();
        default_hook(panic_info);
    }));
}

// ── Entry point ────────────────────────────────────────────────────────────

fn main() -> Result<()> {
    let opts = Opts::parse();

    if opts.version {
        println!(
            "{} version {} — scx_rustland_core {}",
            SCHEDULER_NAME,
            build_id::full_version(env!("CARGO_PKG_VERSION")),
            scx_rustland_core::VERSION
        );
        return Ok(());
    }

    if opts.help_stats {
        stats::server_data().describe_meta(&mut std::io::stdout(), None)?;
        return Ok(());
    }

    // Logger.
    let mut lcfg = simplelog::ConfigBuilder::new();
    if lcfg.set_time_offset_to_local().is_err() {
        eprintln!("[WARN] Failed to set local time offset");
    }
    lcfg.set_time_level(simplelog::LevelFilter::Error)
        .set_location_level(simplelog::LevelFilter::Off)
        .set_target_level(simplelog::LevelFilter::Off)
        .set_thread_level(simplelog::LevelFilter::Off);
    simplelog::TermLogger::init(
        simplelog::LevelFilter::Info,
        lcfg.build(),
        simplelog::TerminalMode::Stderr,
        simplelog::ColorChoice::Auto,
    )?;
    install_terminal_panic_hook();

    // Stats monitor mode.
    if let Some(intv) = opts.monitor.or(opts.stats) {
        let jh = std::thread::spawn(move || {
            if let Err(err) = stats::monitor(Duration::from_secs_f64(intv)) {
                eprintln!("[WARN] stats monitor exited: {err}");
            }
        });
        if opts.monitor.is_some() {
            let _ = jh.join();
            return Ok(());
        }
    }

    // Shared shutdown flag and ctrlc/SIGTERM handler — registered ONCE for the
    // entire process lifetime.  The same Arc is passed into every
    // Scheduler::init() call (including after restarts), so a SIGTERM received
    // at any point — including the restart backoff window between two run()
    // iterations — is always observed and stops the outer restart loop.
    let shutdown = Arc::new(AtomicBool::new(false));
    {
        let sd = shutdown.clone();
        ctrlc::set_handler(move || {
            sd.store(true, Ordering::Relaxed);
        })
        .context("Error setting Ctrl-C / SIGTERM handler")?;
    }

    // Main scheduler loop with restart support.
    let mut open_object = MaybeUninit::uninit();
    let mut rapid_failures = 0u32;
    let mut last_failure_at: Option<Instant> = None;

    loop {
        // A SIGTERM received during the restart backoff (or while init is
        // still in progress) must not be silently dropped — check the flag
        // before starting a new instance.
        if shutdown.load(Ordering::Relaxed) {
            break;
        }

        let loop_result = panic::catch_unwind(AssertUnwindSafe(|| -> Result<bool> {
            let mut sched = Scheduler::init(&opts, &mut open_object, shutdown.clone())?;
            Ok(sched.run()?.should_restart())
        }));

        match loop_result {
            Ok(Ok(true)) => continue,
            Ok(Ok(false)) => break,
            Ok(Err(err)) if runtime_exit_reason(&err).is_some() => {
                tui::emergency_restore_terminal();
                let reason =
                    runtime_exit_reason(&err).unwrap_or_else(|| "unknown sched_ext exit".into());

                if is_watchdog_runtime_exit(&reason) {
                    warn!(
                        "sched_ext watchdog exit detected; refusing automatic restart and \
                         leaving the system on the kernel scheduler: {}",
                        reason
                    );
                } else {
                    warn!(
                        "non-restartable sched_ext runtime exit detected; refusing automatic \
                         restart: {}",
                        reason
                    );
                }

                log_cognis_failure(&format!("non-restartable sched_ext exit: {reason}"));
                std::process::exit(EXIT_CODE_SCHED_EXT_RUNTIME_FAILURE);
            }
            Ok(Err(err)) => {
                tui::emergency_restore_terminal();
                return Err(err);
            }
            Err(payload) => {
                tui::emergency_restore_terminal();
                let now = Instant::now();
                rapid_failures = if last_failure_at
                    .is_some_and(|prev| now.duration_since(prev) <= RAPID_FAILURE_WINDOW)
                {
                    rapid_failures.saturating_add(1)
                } else {
                    1
                };
                last_failure_at = Some(now);

                if rapid_failures > RAPID_FAILURE_LIMIT {
                    log_cognis_failure(&format!(
                        "exceeded {} restart attempts in {:?}: {}",
                        RAPID_FAILURE_LIMIT,
                        RAPID_FAILURE_WINDOW,
                        panic_payload_to_string(payload.as_ref())
                    ));
                    std::process::exit(1);
                }

                warn!(
                    "scheduler panic detected (attempt {}/{} in {:?}): {}; re-executing for \
                     clean restart in {:?}",
                    rapid_failures,
                    RAPID_FAILURE_LIMIT,
                    RAPID_FAILURE_WINDOW,
                    panic_payload_to_string(payload.as_ref()),
                    RESTART_BACKOFF
                );
                std::thread::sleep(RESTART_BACKOFF);

                // Re-exec for clean OS state (see runtime failure branch above).
                let exe = std::env::current_exe()
                    .unwrap_or_else(|_| std::path::PathBuf::from("/proc/self/exe"));
                let exec_err = std::process::Command::new(&exe)
                    .args(std::env::args_os().skip(1))
                    .exec();
                warn!(
                    "re-exec failed ({}); falling back to in-process restart",
                    exec_err
                );
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        enabled_flag_summary, is_watchdog_runtime_exit, runtime_exit_reason, BpfProfile, Opts,
        Scheduler, DEFAULT_DESKTOP_SLICE_LAG_NS, DEFAULT_DESKTOP_SLICE_MIN_NS,
        DEFAULT_DESKTOP_SLICE_NS, DEFAULT_SERVER_SLICE_LAG_NS, DEFAULT_SERVER_SLICE_MIN_NS,
        DEFAULT_SERVER_SLICE_NS,
    };
    use clap::Parser;

    #[test]
    fn wake_boost_requires_latency_sensitive_task() {
        assert!(!Scheduler::should_wake_boost(true, 0.80, 0.70, 200_000));
        assert!(!Scheduler::should_wake_boost(false, 0.80, 0.70, 8_000_000));
    }

    #[test]
    fn wake_boost_accepts_frame_sized_sleep_gap() {
        assert!(Scheduler::should_wake_boost(true, 0.92, 0.78, 8_000_000));
    }

    #[test]
    fn wake_boost_rejects_long_sleepers() {
        assert!(!Scheduler::should_wake_boost(true, 0.92, 0.78, 40_000_000));
    }

    #[test]
    fn wake_preempt_requires_recent_creditful_task() {
        assert!(!Scheduler::should_wake_preempt(
            true, true, 500_000, 1_000_000
        ));
        assert!(!Scheduler::should_wake_preempt(
            true, true, 2_000_000, 10_000_000
        ));
        assert!(!Scheduler::should_wake_preempt(
            false, true, 2_000_000, 1_000_000
        ));
    }

    #[test]
    fn wake_preempt_accepts_fresh_high_credit_wakeup() {
        assert!(Scheduler::should_wake_preempt(
            true, true, 2_000_000, 1_500_000
        ));
    }

    #[test]
    fn recent_sleep_gap_uses_previous_stop_timestamp() {
        assert_eq!(Scheduler::recent_sleep_gap_ns(0, 50), 0);
        assert_eq!(Scheduler::recent_sleep_gap_ns(10, 50), 40);
        assert_eq!(Scheduler::recent_sleep_gap_ns(80, 50), 0);
    }

    #[test]
    fn effective_slice_pressure_counts_queued_work() {
        assert_eq!(Scheduler::effective_slice_pressure(15, 2, 0), 17);
        assert_eq!(Scheduler::effective_slice_pressure(15, 2, 3), 20);
    }

    #[test]
    fn effective_slice_pressure_saturates() {
        assert_eq!(
            Scheduler::effective_slice_pressure(u64::MAX, 1, 1),
            u64::MAX
        );
    }

    #[test]
    fn desktop_profile_defaults_match_cli_mode() {
        let opts = Opts::parse_from(["scx_cognis"]);
        let profile = BpfProfile::from_opts(&opts);

        assert_eq!(profile.slice_ns, DEFAULT_DESKTOP_SLICE_NS);
        assert_eq!(profile.slice_min_ns, DEFAULT_DESKTOP_SLICE_MIN_NS);
        assert_eq!(profile.slice_lag_ns, DEFAULT_DESKTOP_SLICE_LAG_NS);
        assert!(profile.sticky_tasks);
        assert!(!profile.no_wake_sync);
    }

    #[test]
    fn server_profile_defaults_match_cli_mode() {
        let opts = Opts::parse_from(["scx_cognis", "--mode", "server"]);
        let profile = BpfProfile::from_opts(&opts);

        assert_eq!(profile.slice_ns, DEFAULT_SERVER_SLICE_NS);
        assert_eq!(profile.slice_min_ns, DEFAULT_SERVER_SLICE_MIN_NS);
        assert_eq!(profile.slice_lag_ns, DEFAULT_SERVER_SLICE_LAG_NS);
        assert!(!profile.sticky_tasks);
        assert!(profile.no_wake_sync);
    }

    #[test]
    fn enabled_flag_summary_defaults_to_none() {
        let opts = Opts::parse_from(["scx_cognis"]);
        assert_eq!(enabled_flag_summary(&opts), "none");
    }

    #[test]
    fn enabled_flag_summary_lists_behavioral_flags() {
        let opts = Opts::parse_from([
            "scx_cognis",
            "--mode",
            "server",
            "-p",
            "-l",
            "-v",
            "-t",
            "--stats",
            "1",
        ]);

        assert_eq!(
            enabled_flag_summary(&opts),
            "partial,percpu_local,verbose,tui,stats"
        );
    }

    #[test]
    fn runtime_exit_reason_extracts_sched_ext_exit_message() {
        let err = anyhow::anyhow!("EXIT: runnable task stall (watchdog failed to check in)");
        assert_eq!(
            runtime_exit_reason(&err).as_deref(),
            Some("runnable task stall (watchdog failed to check in)")
        );
    }

    #[test]
    fn watchdog_runtime_exit_detection_matches_stall_message() {
        assert!(is_watchdog_runtime_exit(
            "runnable task stall (watchdog failed to check in)"
        ));
        assert!(!is_watchdog_runtime_exit("scheduler requested restart"));
    }
}
