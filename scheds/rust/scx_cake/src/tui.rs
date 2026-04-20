// SPDX-License-Identifier: GPL-2.0
// TUI module - ratatui-based terminal UI for real-time scheduler statistics

use std::io::{self, Stdout};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use arboard::Clipboard;
use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind},
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
    ExecutableCommand,
};
use ratatui::{
    buffer::Buffer,
    prelude::*,
    widgets::{
        Block, BorderType, Borders, Cell, Padding, Paragraph, Row, Table, TableState, Tabs, Widget,
        Wrap,
    },
};
use std::collections::{HashMap, VecDeque};
use sysinfo::{Components, System};

use crate::bpf_intf::cake_debug_event;
use crate::bpf_skel::types::cake_stats;
use crate::bpf_skel::BpfSkel;

use crate::topology::TopologyInfo;

const STATS_HISTORY_MAX_AGE: Duration = Duration::from_secs(600);
const STATS_HISTORY_MAX_SAMPLES: usize = 2048;

/// System hardware and kernel information, collected once at startup.
#[derive(Clone, Debug)]
pub struct SystemInfo {
    pub cpu_model: String,
    pub cpu_arch: String,
    pub phys_cores: usize,
    pub logical_cpus: usize,
    pub smt_enabled: bool,
    pub dual_ccd: bool,
    pub has_vcache: bool,
    pub has_hybrid: bool,
    pub total_ram_mb: u64,
    pub kernel_version: String,
}

impl SystemInfo {
    pub fn detect(topo: &TopologyInfo) -> Self {
        // CPU model from /proc/cpuinfo
        let cpu_model = std::fs::read_to_string("/proc/cpuinfo")
            .ok()
            .and_then(|s| {
                s.lines()
                    .find(|l| l.starts_with("model name"))
                    .and_then(|l| l.split(':').nth(1))
                    .map(|v| v.trim().to_string())
            })
            .unwrap_or_else(|| "Unknown".to_string());

        // Architecture from uname
        let cpu_arch = std::fs::read_to_string("/proc/sys/kernel/arch")
            .map(|s| s.trim().to_string())
            .or_else(|_| {
                // Fallback: parse from uname -m via /proc
                std::process::Command::new("uname")
                    .arg("-m")
                    .output()
                    .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            })
            .unwrap_or_else(|_| "unknown".to_string());

        // Total RAM from /proc/meminfo
        let total_ram_mb = std::fs::read_to_string("/proc/meminfo")
            .ok()
            .and_then(|s| {
                s.lines()
                    .find(|l| l.starts_with("MemTotal:"))
                    .and_then(|l| {
                        l.split_whitespace()
                            .nth(1)
                            .and_then(|v| v.parse::<u64>().ok())
                    })
            })
            .map(|kb| kb / 1024)
            .unwrap_or(0);

        // Kernel version from /proc/version
        let kernel_version = std::fs::read_to_string("/proc/version")
            .ok()
            .and_then(|s| s.split_whitespace().nth(2).map(|v| v.to_string()))
            .unwrap_or_else(|| "Unknown".to_string());

        Self {
            cpu_model,
            cpu_arch,
            phys_cores: topo.nr_phys_cpus,
            logical_cpus: topo.nr_cpus,
            smt_enabled: topo.smt_enabled,
            dual_ccd: topo.has_dual_ccd,
            has_vcache: topo.has_vcache,
            has_hybrid: topo.has_hybrid_cores,
            total_ram_mb,
            kernel_version,
        }
    }

    /// Format as compact one-line header for dump files (AI-optimized, all data)
    pub fn format_header(&self) -> String {
        let ram_display = if self.total_ram_mb >= 1024 {
            format!("{:.1}GB", self.total_ram_mb as f64 / 1024.0)
        } else {
            format!("{}MB", self.total_ram_mb)
        };
        let smt_label = if self.smt_enabled { "SMT" } else { "no-SMT" };
        let mut topo_tags = Vec::new();
        if self.dual_ccd {
            topo_tags.push("DualCCD");
        }
        if self.has_vcache {
            topo_tags.push("VCache");
        }
        if self.has_hybrid {
            topo_tags.push("HybridPE");
        }
        if topo_tags.is_empty() {
            topo_tags.push("Sym");
        }
        format!(
            "sys: cpu={} arch={} cores={}P/{}T {} [{}] ram={} kernel={}\n",
            self.cpu_model,
            self.cpu_arch,
            self.phys_cores,
            self.logical_cpus,
            smt_label,
            topo_tags.join(","),
            ram_display,
            self.kernel_version,
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TuiTab {
    Dashboard = 0,
    Topology = 1,
    BenchLab = 2,
    ReferenceGuide = 3,
}

impl TuiTab {
    fn next(self) -> Self {
        match self {
            TuiTab::Dashboard => TuiTab::Topology,
            TuiTab::Topology => TuiTab::BenchLab,
            TuiTab::BenchLab => TuiTab::ReferenceGuide,
            TuiTab::ReferenceGuide => TuiTab::Dashboard,
        }
    }

    fn previous(self) -> Self {
        match self {
            TuiTab::Dashboard => TuiTab::ReferenceGuide,
            TuiTab::Topology => TuiTab::Dashboard,
            TuiTab::BenchLab => TuiTab::Topology,
            TuiTab::ReferenceGuide => TuiTab::BenchLab,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TaskStatus {
    Alive, // In sysinfo + has BPF telemetry (total_runs > 0)
    Idle,  // In sysinfo but no BPF telemetry (sleeping/background)
    Dead,  // Not in sysinfo, stale arena entry
}

impl TaskStatus {
    fn short_label(&self) -> &'static str {
        match self {
            TaskStatus::Alive => "●",
            TaskStatus::Idle => "○",
            TaskStatus::Dead => "✗",
        }
    }

    fn color(&self) -> Color {
        match self {
            TaskStatus::Alive => Color::Green,
            TaskStatus::Idle => Color::DarkGray,
            TaskStatus::Dead => Color::Red,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum SortColumn {
    Pid,
    Pelt,
    MaxRuntime,
    Jitter,
    Wait,
    RunsPerSec,
    TargetCpu,
    Spread,
    Residency,
    SelectCpu,
    Enqueue,
    Gap,
    Gate1Pct,
    Class,
    Migrations,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TaskFilter {
    BpfTracked,
    LiveOnly,
    AllTasks,
}

impl TaskFilter {
    fn next(self) -> Self {
        match self {
            TaskFilter::BpfTracked => TaskFilter::LiveOnly,
            TaskFilter::LiveOnly => TaskFilter::AllTasks,
            TaskFilter::AllTasks => TaskFilter::BpfTracked,
        }
    }

    fn label(self) -> &'static str {
        match self {
            TaskFilter::BpfTracked => "BPF-tracked",
            TaskFilter::LiveOnly => "Live-only",
            TaskFilter::AllTasks => "All tasks",
        }
    }
}

/// TUI Application state
pub struct TuiApp {
    start_time: Instant,
    status_message: Option<(String, Instant)>,
    pub topology: TopologyInfo,
    pub latency_matrix: Vec<Vec<f64>>,
    pub task_rows: HashMap<u32, TaskTelemetryRow>,
    pub sorted_pids: Vec<u32>,
    pub table_state: TableState,
    pub bench_table_state: TableState,
    pub active_tab: TuiTab,
    pub sort_column: SortColumn,
    pub sort_descending: bool,

    pub sys: System,
    pub components: Components,
    pub cpu_stats: Vec<(f32, f32)>, // (Load %, Temp C)
    pub task_filter: TaskFilter,
    pub arena_active: usize,                   // Arena slots with tid != 0
    pub arena_max: usize,                      // Arena pool max_elems
    pub bpf_task_count: usize,                 // Tasks with total_runs > 0
    pub prev_deltas: HashMap<u32, (u32, u16)>, // (total_runs, migration_count) — lightweight delta snapshot
    pub active_pids_buf: std::collections::HashSet<u32>, // Reused per-tick to avoid alloc
    pub collapsed_tgids: std::collections::HashSet<u32>, // Collapsed process groups
    pub collapsed_ppids: std::collections::HashSet<u32>, // Collapsed PPID groups
    pub bench_latency_handle: Option<thread::JoinHandle<Vec<Vec<f64>>>>, // Background c2c bench
    pub _prev_stats: Option<cake_stats>,       // Previous global stats for rate calc
    // BenchLab cached results
    pub bench_entries: [(u64, u64, u64, u64); 67], // (min_ns, max_ns, total_ns, last_value)
    pub bench_samples: Vec<Vec<u64>>, // Per-entry accumulated raw samples for percentiles
    pub bench_cpu: u32,
    pub bench_iterations: u32,
    pub bench_timestamp: u64,
    pub bench_run_count: u32,
    pub last_bench_timestamp: u64, // to detect new results
    pub system_info: SystemInfo,
    pub debug_events: VecDeque<DebugEventRow>,
    stats_history: VecDeque<StatsSnapshot>,
}

#[derive(Clone, Copy)]
struct StatsSnapshot {
    at: Instant,
    stats: cake_stats,
}

#[derive(Clone, Debug)]
pub struct DebugEventRow {
    pub ts_ns: u64,
    pub value_ns: u64,
    pub pid: u32,
    pub aux: u32,
    pub cpu: u16,
    pub kind: u8,
    pub slot: u8,
    pub comm: String,
}

#[derive(Clone, Debug)]
pub struct TaskTelemetryRow {
    pub pid: u32,
    pub comm: String,
    pub pelt_util: u32,
    pub wait_duration_ns: u64,
    pub gate_hit_pcts: [f64; 10], // G1, G2, G1W, G3, G1P, G1C, G1CP, G1D, G1WC, GTUN
    pub home_steer_hits: u32,
    pub primary_steer_hits: u32,
    pub select_cpu_ns: u32,
    pub enqueue_ns: u32,
    pub core_placement: u16,
    pub dsq_insert_ns: u32,
    pub migration_count: u16,
    pub preempt_count: u16,
    pub yield_count: u16,
    pub total_runs: u32,
    pub jitter_accum_ns: u64,
    pub direct_dispatch_count: u16,
    pub cpumask_change_count: u16,
    pub stopping_duration_ns: u32,
    pub running_duration_ns: u32,
    pub max_runtime_us: u32,
    // Scheduling period (dispatch gap)
    pub dispatch_gap_us: u64,
    pub max_dispatch_gap_us: u64,
    // Wait latency histogram
    pub wait_hist: [u32; 4], // <10µs, <100µs, <1ms, >=1ms
    // Delta mode: per-interval rates
    pub runs_per_sec: f64,
    pub migrations_per_sec: f64,
    pub status: TaskStatus,
    pub is_bpf_tracked: bool,
    pub tgid: u32,
    // Phase B: blind spot metrics
    pub slice_util_pct: u16,
    pub llc_id: u16,
    pub llc_run_mask: u16,
    pub same_cpu_streak: u16,
    pub wakeup_source_pid: u32,
    // Voluntary/involuntary context switch tracking (GPU detection)
    pub nvcsw_delta: u32,
    pub nivcsw_delta: u32,
    pub _pad_recomp: u16,
    pub is_kcritical: bool,
    pub ppid: u32,
    // Per-callback sub-function stopwatch (ns)
    pub gate_cascade_ns: u32,  // select_cpu: full gate cascade duration
    pub idle_probe_ns: u32,    // select_cpu: winning gate idle probe cost
    pub vtime_compute_ns: u32, // enqueue: vtime calculation + tier weighting
    pub mbox_staging_ns: u32,  // running: mailbox CL0 write burst
    pub _pad_ewma: u32,
    pub legacy_classify_ns: u32,
    pub vtime_staging_ns: u32, // stopping: dsq_vtime bit packing + writes
    pub warm_history_ns: u32,  // stopping: warm CPU ring shift
    // Quantum completion tracking
    pub quantum_full_count: u16,    // Task consumed entire slice
    pub quantum_yield_count: u16,   // Task yielded before slice exhaustion
    pub quantum_preempt_count: u16, // Task was kicked/preempted mid-slice
    // Wake chain tracking
    pub waker_cpu: u16,  // CPU the waker was running on
    pub waker_tgid: u32, // TGID of the waker (process group)
    pub wake_reason_wait_ns: [u64; 3],
    pub wake_reason_count: [u32; 3],
    pub wake_reason_max_us: [u32; 3],
    pub last_select_path: u8,
    pub last_place_class: u8,
    pub last_waker_place_class: u8,
    pub wake_same_tgid_count: u32,
    pub wake_cross_tgid_count: u32,
    pub home_place_wait_ns: [u64; 4],
    pub home_place_wait_count: [u32; 4],
    pub home_place_wait_max_us: [u32; 4],
    // CPU core distribution histogram
    pub cpu_run_count: [u16; crate::topology::MAX_CPUS], // Per-CPU run count (TUI normalizes to %)
    // EEVDF telemetry
    pub task_weight: u16, // Task weight (100=nice0, >100=high-pri, <100=low-pri)
}

impl Default for TaskTelemetryRow {
    fn default() -> Self {
        Self {
            pid: 0,
            comm: String::new(),
            pelt_util: 0,
            wait_duration_ns: 0,
            gate_hit_pcts: [0.0; 10],
            home_steer_hits: 0,
            primary_steer_hits: 0,
            select_cpu_ns: 0,
            enqueue_ns: 0,
            core_placement: 0,
            dsq_insert_ns: 0,
            migration_count: 0,
            preempt_count: 0,
            yield_count: 0,
            total_runs: 0,
            jitter_accum_ns: 0,
            direct_dispatch_count: 0,
            cpumask_change_count: 0,
            stopping_duration_ns: 0,
            running_duration_ns: 0,
            max_runtime_us: 0,
            dispatch_gap_us: 0,
            max_dispatch_gap_us: 0,
            wait_hist: [0; 4],
            runs_per_sec: 0.0,
            migrations_per_sec: 0.0,
            status: TaskStatus::Idle,
            is_bpf_tracked: false,
            tgid: 0,
            slice_util_pct: 0,
            llc_id: 0,
            llc_run_mask: 0,
            same_cpu_streak: 0,
            wakeup_source_pid: 0,
            nvcsw_delta: 0,
            nivcsw_delta: 0,
            _pad_recomp: 0,
            is_kcritical: false,
            ppid: 0,
            // Telemetry fields
            gate_cascade_ns: 0,
            idle_probe_ns: 0,
            vtime_compute_ns: 0,
            mbox_staging_ns: 0,
            _pad_ewma: 0,
            legacy_classify_ns: 0,
            vtime_staging_ns: 0,
            warm_history_ns: 0,
            quantum_full_count: 0,
            quantum_yield_count: 0,
            quantum_preempt_count: 0,
            waker_cpu: 0,
            waker_tgid: 0,
            wake_reason_wait_ns: [0; 3],
            wake_reason_count: [0; 3],
            wake_reason_max_us: [0; 3],
            last_select_path: 0,
            last_place_class: 0,
            last_waker_place_class: 0,
            wake_same_tgid_count: 0,
            wake_cross_tgid_count: 0,
            home_place_wait_ns: [0; 4],
            home_place_wait_count: [0; 4],
            home_place_wait_max_us: [0; 4],
            cpu_run_count: [0u16; crate::topology::MAX_CPUS],
            task_weight: 100,
        }
    }
}

fn aggregate_stats(skel: &BpfSkel) -> cake_stats {
    let mut total: cake_stats = Default::default();

    if let Some(bss) = &skel.maps.bss_data {
        // Bound to actual CPU count — at compile-time MAX_CPUS=16,
        // global_stats.len() is already 16. .take(nr_cpus) further
        // ensures only populated entries are summed at runtime.
        let nr = skel
            .maps
            .rodata_data
            .as_ref()
            .map(|r| r.nr_cpus as usize)
            .unwrap_or(bss.global_stats.len());
        for s in bss.global_stats.iter().take(nr) {
            // Sum all fields
            total.nr_dropped_allocations += s.nr_dropped_allocations;
            total.nr_prev_cpu_tunnels += s.nr_prev_cpu_tunnels;
            total.nr_steer_eligible += s.nr_steer_eligible;
            total.nr_home_cpu_steers += s.nr_home_cpu_steers;
            total.nr_home_core_steers += s.nr_home_core_steers;
            total.nr_primary_cpu_steers += s.nr_primary_cpu_steers;
            total.nr_home_cpu_busy_misses += s.nr_home_cpu_busy_misses;
            total.nr_prev_primary_busy_misses += s.nr_prev_primary_busy_misses;
            total.nr_primary_scan_misses += s.nr_primary_scan_misses;
            total.nr_busy_handoff_dispatches += s.nr_busy_handoff_dispatches;
            total.nr_busy_keep_suppressed += s.nr_busy_keep_suppressed;
            total.nr_wakeup_busy_local_target += s.nr_wakeup_busy_local_target;
            total.nr_wakeup_busy_remote_target += s.nr_wakeup_busy_remote_target;

            total.total_gate1_latency_ns += s.total_gate1_latency_ns;
            total.total_gate2_latency_ns += s.total_gate2_latency_ns;
            total.total_enqueue_latency_ns += s.total_enqueue_latency_ns;

            // Callback profiling aggregation
            total.total_select_cpu_ns += s.total_select_cpu_ns;
            total.total_stopping_ns += s.total_stopping_ns;
            total.total_running_ns += s.total_running_ns;
            total.max_select_cpu_ns = total.max_select_cpu_ns.max(s.max_select_cpu_ns);
            total.max_stopping_ns = total.max_stopping_ns.max(s.max_stopping_ns);
            total.max_running_ns = total.max_running_ns.max(s.max_running_ns);
            total.nr_stop_deferred_skip += s.nr_stop_deferred_skip;
            total.nr_stop_deferred += s.nr_stop_deferred;

            // Dispatch locality (cake_dispatch stats)
            total.nr_local_dispatches += s.nr_local_dispatches;
            total.nr_stolen_dispatches += s.nr_stolen_dispatches;
            total.nr_dispatch_misses += s.nr_dispatch_misses;
            total.nr_direct_local_inserts += s.nr_direct_local_inserts;
            total.nr_direct_affine_inserts += s.nr_direct_affine_inserts;
            total.nr_direct_kthread_inserts += s.nr_direct_kthread_inserts;
            total.nr_direct_other_inserts += s.nr_direct_other_inserts;
            total.nr_dsq_queued += s.nr_dsq_queued;
            total.nr_dsq_consumed += s.nr_dsq_consumed;
            total.nr_shared_vtime_inserts += s.nr_shared_vtime_inserts;
            total.nr_shared_wakeup_inserts += s.nr_shared_wakeup_inserts;
            total.nr_shared_requeue_inserts += s.nr_shared_requeue_inserts;
            total.nr_shared_preserve_inserts += s.nr_shared_preserve_inserts;
            total.nr_shared_other_inserts += s.nr_shared_other_inserts;

            // Dispatch callback timing
            total.total_dispatch_ns += s.total_dispatch_ns;
            total.max_dispatch_ns = total.max_dispatch_ns.max(s.max_dispatch_ns);

            // Wakeup enqueue gate telemetry
            total.nr_wakeup_direct_dispatches += s.nr_wakeup_direct_dispatches;
            total.nr_wakeup_dsq_fallback_busy += s.nr_wakeup_dsq_fallback_busy;
            total.nr_wakeup_dsq_fallback_queued += s.nr_wakeup_dsq_fallback_queued;
            total.nr_select_cpu_calls += s.nr_select_cpu_calls;
            total.nr_enqueue_calls += s.nr_enqueue_calls;
            total.nr_dispatch_calls += s.nr_dispatch_calls;
            total.nr_running_calls += s.nr_running_calls;
            total.nr_stopping_calls += s.nr_stopping_calls;
            total.nr_idle_hint_remote_reads += s.nr_idle_hint_remote_reads;
            total.nr_idle_hint_remote_busy += s.nr_idle_hint_remote_busy;
            total.nr_idle_hint_remote_idle += s.nr_idle_hint_remote_idle;
            total.nr_busy_pending_remote_sets += s.nr_busy_pending_remote_sets;
            total.nr_enqueue_requeue_fastpath += s.nr_enqueue_requeue_fastpath;
            total.nr_enqueue_busy_local_skip_depth += s.nr_enqueue_busy_local_skip_depth;
            total.nr_enqueue_busy_remote_skip_depth += s.nr_enqueue_busy_remote_skip_depth;
            total.nr_busy_pending_set_skips += s.nr_busy_pending_set_skips;
            total.nr_idle_hint_set_writes += s.nr_idle_hint_set_writes;
            total.nr_idle_hint_clear_writes += s.nr_idle_hint_clear_writes;
            total.nr_idle_hint_set_skips += s.nr_idle_hint_set_skips;
            total.nr_idle_hint_clear_skips += s.nr_idle_hint_clear_skips;
            for cb in 0..5 {
                total.callback_slow[cb] += s.callback_slow[cb];
                for bucket in 0..7 {
                    total.callback_hist[cb][bucket] += s.callback_hist[cb][bucket];
                }
            }
            for reason in 0..4 {
                total.wake_reason_wait_ns[reason] += s.wake_reason_wait_ns[reason];
                total.wake_reason_wait_count[reason] += s.wake_reason_wait_count[reason];
                total.wake_reason_wait_max_ns[reason] =
                    total.wake_reason_wait_max_ns[reason].max(s.wake_reason_wait_max_ns[reason]);
            }
            for path in 0..6 {
                total.select_path_count[path] += s.select_path_count[path];
            }
            for cls in 0..4 {
                total.home_place_wait_ns[cls] += s.home_place_wait_ns[cls];
                total.home_place_wait_count[cls] += s.home_place_wait_count[cls];
                total.home_place_wait_max_ns[cls] =
                    total.home_place_wait_max_ns[cls].max(s.home_place_wait_max_ns[cls]);
                total.home_place_run_ns[cls] += s.home_place_run_ns[cls];
                total.home_place_run_count[cls] += s.home_place_run_count[cls];
                total.home_place_run_max_ns[cls] =
                    total.home_place_run_max_ns[cls].max(s.home_place_run_max_ns[cls]);
                total.waker_place_wait_ns[cls] += s.waker_place_wait_ns[cls];
                total.waker_place_wait_count[cls] += s.waker_place_wait_count[cls];
                total.waker_place_wait_max_ns[cls] =
                    total.waker_place_wait_max_ns[cls].max(s.waker_place_wait_max_ns[cls]);
            }
            total.nr_wake_same_tgid += s.nr_wake_same_tgid;
            total.nr_wake_cross_tgid += s.nr_wake_cross_tgid;
        }
    }

    total
}

fn stats_delta(current: &cake_stats, previous: &cake_stats) -> cake_stats {
    let mut delta: cake_stats = Default::default();

    delta.nr_prev_cpu_tunnels = current
        .nr_prev_cpu_tunnels
        .saturating_sub(previous.nr_prev_cpu_tunnels);
    delta.nr_steer_eligible = current
        .nr_steer_eligible
        .saturating_sub(previous.nr_steer_eligible);
    delta.nr_home_cpu_steers = current
        .nr_home_cpu_steers
        .saturating_sub(previous.nr_home_cpu_steers);
    delta.nr_home_core_steers = current
        .nr_home_core_steers
        .saturating_sub(previous.nr_home_core_steers);
    delta.nr_primary_cpu_steers = current
        .nr_primary_cpu_steers
        .saturating_sub(previous.nr_primary_cpu_steers);
    delta.nr_home_cpu_busy_misses = current
        .nr_home_cpu_busy_misses
        .saturating_sub(previous.nr_home_cpu_busy_misses);
    delta.nr_prev_primary_busy_misses = current
        .nr_prev_primary_busy_misses
        .saturating_sub(previous.nr_prev_primary_busy_misses);
    delta.nr_primary_scan_misses = current
        .nr_primary_scan_misses
        .saturating_sub(previous.nr_primary_scan_misses);
    delta.nr_busy_handoff_dispatches = current
        .nr_busy_handoff_dispatches
        .saturating_sub(previous.nr_busy_handoff_dispatches);
    delta.nr_busy_keep_suppressed = current
        .nr_busy_keep_suppressed
        .saturating_sub(previous.nr_busy_keep_suppressed);
    delta.nr_wakeup_busy_local_target = current
        .nr_wakeup_busy_local_target
        .saturating_sub(previous.nr_wakeup_busy_local_target);
    delta.nr_wakeup_busy_remote_target = current
        .nr_wakeup_busy_remote_target
        .saturating_sub(previous.nr_wakeup_busy_remote_target);
    for i in 0..current.nr_tier_dispatches.len() {
        delta.nr_tier_dispatches[i] =
            current.nr_tier_dispatches[i].saturating_sub(previous.nr_tier_dispatches[i]);
        delta.nr_starvation_preempts_tier[i] = current.nr_starvation_preempts_tier[i]
            .saturating_sub(previous.nr_starvation_preempts_tier[i]);
    }
    delta.total_gate1_latency_ns = current
        .total_gate1_latency_ns
        .saturating_sub(previous.total_gate1_latency_ns);
    delta.total_gate2_latency_ns = current
        .total_gate2_latency_ns
        .saturating_sub(previous.total_gate2_latency_ns);
    delta.total_enqueue_latency_ns = current
        .total_enqueue_latency_ns
        .saturating_sub(previous.total_enqueue_latency_ns);
    delta.nr_dropped_allocations = current
        .nr_dropped_allocations
        .saturating_sub(previous.nr_dropped_allocations);
    delta.nr_local_dispatches = current
        .nr_local_dispatches
        .saturating_sub(previous.nr_local_dispatches);
    delta.nr_stolen_dispatches = current
        .nr_stolen_dispatches
        .saturating_sub(previous.nr_stolen_dispatches);
    delta.nr_dispatch_misses = current
        .nr_dispatch_misses
        .saturating_sub(previous.nr_dispatch_misses);
    delta.nr_direct_local_inserts = current
        .nr_direct_local_inserts
        .saturating_sub(previous.nr_direct_local_inserts);
    delta.nr_direct_affine_inserts = current
        .nr_direct_affine_inserts
        .saturating_sub(previous.nr_direct_affine_inserts);
    delta.nr_direct_kthread_inserts = current
        .nr_direct_kthread_inserts
        .saturating_sub(previous.nr_direct_kthread_inserts);
    delta.nr_direct_other_inserts = current
        .nr_direct_other_inserts
        .saturating_sub(previous.nr_direct_other_inserts);
    delta.nr_dsq_queued = current.nr_dsq_queued.saturating_sub(previous.nr_dsq_queued);
    delta.nr_dsq_consumed = current
        .nr_dsq_consumed
        .saturating_sub(previous.nr_dsq_consumed);
    delta.nr_shared_vtime_inserts = current
        .nr_shared_vtime_inserts
        .saturating_sub(previous.nr_shared_vtime_inserts);
    delta.nr_shared_wakeup_inserts = current
        .nr_shared_wakeup_inserts
        .saturating_sub(previous.nr_shared_wakeup_inserts);
    delta.nr_shared_requeue_inserts = current
        .nr_shared_requeue_inserts
        .saturating_sub(previous.nr_shared_requeue_inserts);
    delta.nr_shared_preserve_inserts = current
        .nr_shared_preserve_inserts
        .saturating_sub(previous.nr_shared_preserve_inserts);
    delta.nr_shared_other_inserts = current
        .nr_shared_other_inserts
        .saturating_sub(previous.nr_shared_other_inserts);
    delta.total_select_cpu_ns = current
        .total_select_cpu_ns
        .saturating_sub(previous.total_select_cpu_ns);
    delta.total_stopping_ns = current
        .total_stopping_ns
        .saturating_sub(previous.total_stopping_ns);
    delta.total_running_ns = current
        .total_running_ns
        .saturating_sub(previous.total_running_ns);
    delta.nr_stop_deferred_skip = current
        .nr_stop_deferred_skip
        .saturating_sub(previous.nr_stop_deferred_skip);
    delta.nr_stop_deferred = current
        .nr_stop_deferred
        .saturating_sub(previous.nr_stop_deferred);
    delta.total_dispatch_ns = current
        .total_dispatch_ns
        .saturating_sub(previous.total_dispatch_ns);
    delta.nr_select_cpu_calls = current
        .nr_select_cpu_calls
        .saturating_sub(previous.nr_select_cpu_calls);
    delta.nr_enqueue_calls = current
        .nr_enqueue_calls
        .saturating_sub(previous.nr_enqueue_calls);
    delta.nr_dispatch_calls = current
        .nr_dispatch_calls
        .saturating_sub(previous.nr_dispatch_calls);
    delta.nr_running_calls = current
        .nr_running_calls
        .saturating_sub(previous.nr_running_calls);
    delta.nr_stopping_calls = current
        .nr_stopping_calls
        .saturating_sub(previous.nr_stopping_calls);
    delta.nr_wakeup_direct_dispatches = current
        .nr_wakeup_direct_dispatches
        .saturating_sub(previous.nr_wakeup_direct_dispatches);
    delta.nr_wakeup_dsq_fallback_busy = current
        .nr_wakeup_dsq_fallback_busy
        .saturating_sub(previous.nr_wakeup_dsq_fallback_busy);
    delta.nr_wakeup_dsq_fallback_queued = current
        .nr_wakeup_dsq_fallback_queued
        .saturating_sub(previous.nr_wakeup_dsq_fallback_queued);
    for cb in 0..current.callback_hist.len() {
        for bucket in 0..current.callback_hist[cb].len() {
            delta.callback_hist[cb][bucket] = current.callback_hist[cb][bucket]
                .saturating_sub(previous.callback_hist[cb][bucket]);
        }
        delta.callback_slow[cb] =
            current.callback_slow[cb].saturating_sub(previous.callback_slow[cb]);
    }
    for reason in 0..current.wake_reason_wait_ns.len() {
        delta.wake_reason_wait_ns[reason] = current.wake_reason_wait_ns[reason]
            .saturating_sub(previous.wake_reason_wait_ns[reason]);
        delta.wake_reason_wait_count[reason] = current.wake_reason_wait_count[reason]
            .saturating_sub(previous.wake_reason_wait_count[reason]);
    }
    for path in 0..current.select_path_count.len() {
        delta.select_path_count[path] = current.select_path_count[path]
            .saturating_sub(previous.select_path_count[path]);
    }
    for cls in 0..current.home_place_wait_ns.len() {
        delta.home_place_wait_ns[cls] = current.home_place_wait_ns[cls]
            .saturating_sub(previous.home_place_wait_ns[cls]);
        delta.home_place_wait_count[cls] = current.home_place_wait_count[cls]
            .saturating_sub(previous.home_place_wait_count[cls]);
        delta.home_place_wait_max_ns[cls] = current.home_place_wait_max_ns[cls];
        delta.home_place_run_ns[cls] = current.home_place_run_ns[cls]
            .saturating_sub(previous.home_place_run_ns[cls]);
        delta.home_place_run_count[cls] = current.home_place_run_count[cls]
            .saturating_sub(previous.home_place_run_count[cls]);
        delta.home_place_run_max_ns[cls] = current.home_place_run_max_ns[cls];
        delta.waker_place_wait_ns[cls] = current.waker_place_wait_ns[cls]
            .saturating_sub(previous.waker_place_wait_ns[cls]);
        delta.waker_place_wait_count[cls] = current.waker_place_wait_count[cls]
            .saturating_sub(previous.waker_place_wait_count[cls]);
        delta.waker_place_wait_max_ns[cls] = current.waker_place_wait_max_ns[cls];
    }
    delta.nr_wake_same_tgid = current
        .nr_wake_same_tgid
        .saturating_sub(previous.nr_wake_same_tgid);
    delta.nr_wake_cross_tgid = current
        .nr_wake_cross_tgid
        .saturating_sub(previous.nr_wake_cross_tgid);
    delta.nr_idle_hint_remote_reads = current
        .nr_idle_hint_remote_reads
        .saturating_sub(previous.nr_idle_hint_remote_reads);
    delta.nr_idle_hint_remote_busy = current
        .nr_idle_hint_remote_busy
        .saturating_sub(previous.nr_idle_hint_remote_busy);
    delta.nr_idle_hint_remote_idle = current
        .nr_idle_hint_remote_idle
        .saturating_sub(previous.nr_idle_hint_remote_idle);
    delta.nr_busy_pending_remote_sets = current
        .nr_busy_pending_remote_sets
        .saturating_sub(previous.nr_busy_pending_remote_sets);
    delta.nr_enqueue_requeue_fastpath = current
        .nr_enqueue_requeue_fastpath
        .saturating_sub(previous.nr_enqueue_requeue_fastpath);
    delta.nr_enqueue_busy_local_skip_depth = current
        .nr_enqueue_busy_local_skip_depth
        .saturating_sub(previous.nr_enqueue_busy_local_skip_depth);
    delta.nr_enqueue_busy_remote_skip_depth = current
        .nr_enqueue_busy_remote_skip_depth
        .saturating_sub(previous.nr_enqueue_busy_remote_skip_depth);
    delta.nr_busy_pending_set_skips = current
        .nr_busy_pending_set_skips
        .saturating_sub(previous.nr_busy_pending_set_skips);
    delta.nr_idle_hint_set_writes = current
        .nr_idle_hint_set_writes
        .saturating_sub(previous.nr_idle_hint_set_writes);
    delta.nr_idle_hint_clear_writes = current
        .nr_idle_hint_clear_writes
        .saturating_sub(previous.nr_idle_hint_clear_writes);
    delta.nr_idle_hint_set_skips = current
        .nr_idle_hint_set_skips
        .saturating_sub(previous.nr_idle_hint_set_skips);
    delta.nr_idle_hint_clear_skips = current
        .nr_idle_hint_clear_skips
        .saturating_sub(previous.nr_idle_hint_clear_skips);

    delta
}

fn cstr_comm(bytes: &[i8; 16]) -> String {
    let len = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    let raw: Vec<u8> = bytes[..len].iter().map(|&b| b as u8).collect();
    String::from_utf8_lossy(&raw).into_owned()
}

fn count_active_llcs(mask: u16) -> u32 {
    mask.count_ones()
}

#[derive(Debug, Clone, Default)]
struct PlacementSummary {
    total_samples: u64,
    active_cpu_count: usize,
    active_core_count: usize,
    active_llc_count: u32,
    top_cpu: Option<(usize, u64)>,
    top_core: Option<(usize, u64)>,
    smt_secondary_pct: u64,
}

fn placement_summary(row: &TaskTelemetryRow, topology: &TopologyInfo) -> PlacementSummary {
    let mut summary = PlacementSummary::default();
    let mut core_counts = [0u64; crate::topology::MAX_CORES];
    let nr_cpus = topology.nr_cpus.min(crate::topology::MAX_CPUS);
    let mut smt_secondary_samples = 0u64;

    for cpu in 0..nr_cpus {
        let count = row.cpu_run_count[cpu] as u64;
        if count == 0 {
            continue;
        }

        summary.total_samples += count;
        summary.active_cpu_count += 1;

        match summary.top_cpu {
            Some((_, top_count)) if top_count >= count => {}
            _ => summary.top_cpu = Some((cpu, count)),
        }

        let core = topology.cpu_core_id[cpu] as usize;
        if core < crate::topology::MAX_CORES {
            if core_counts[core] == 0 {
                summary.active_core_count += 1;
            }
            core_counts[core] += count;
        }

        if topology.smt_enabled
            && topology.cpu_sibling_map[cpu] as usize != cpu
            && topology.cpu_thread_bit[cpu] != 1
        {
            smt_secondary_samples += count;
        }
    }

    summary.active_llc_count = count_active_llcs(row.llc_run_mask);

    for (core, &count) in core_counts.iter().enumerate() {
        if count == 0 {
            continue;
        }
        match summary.top_core {
            Some((_, top_count)) if top_count >= count => {}
            _ => summary.top_core = Some((core, count)),
        }
    }

    if summary.total_samples > 0 {
        summary.smt_secondary_pct = (smt_secondary_samples * 100) / summary.total_samples;
    }

    summary
}

fn placement_spread_label(summary: &PlacementSummary) -> String {
    format!("{}/{}", summary.active_cpu_count, summary.active_core_count)
}

fn placement_residency_label(summary: &PlacementSummary) -> String {
    let top_cpu_pct = summary
        .top_cpu
        .map(|(_, count)| (count * 100) / summary.total_samples.max(1))
        .unwrap_or(0);
    let top_core_pct = summary
        .top_core
        .map(|(_, count)| (count * 100) / summary.total_samples.max(1))
        .unwrap_or(0);
    format!("{}/{}", top_cpu_pct, top_core_pct)
}

fn top_cpu_distribution(
    hist: &[u16; crate::topology::MAX_CPUS],
    topology: &TopologyInfo,
    limit: usize,
) -> String {
    let total: u64 = hist.iter().map(|&count| count as u64).sum();
    if total == 0 {
        return "-".to_string();
    }

    let mut entries: Vec<(usize, u64)> = hist
        .iter()
        .enumerate()
        .take(topology.nr_cpus.min(crate::topology::MAX_CPUS))
        .filter_map(|(cpu, &count)| {
            if count > 0 {
                Some((cpu, count as u64))
            } else {
                None
            }
        })
        .collect();
    entries.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));

    let mut parts: Vec<String> = entries
        .iter()
        .take(limit)
        .map(|(cpu, count)| format!("cpu{}:{}%", cpu, (count * 100) / total))
        .collect();
    if entries.len() > limit {
        parts.push(format!("+{}", entries.len() - limit));
    }
    parts.join(" ")
}

fn top_core_distribution(
    hist: &[u16; crate::topology::MAX_CPUS],
    topology: &TopologyInfo,
    limit: usize,
) -> String {
    let total: u64 = hist.iter().map(|&count| count as u64).sum();
    if total == 0 {
        return "-".to_string();
    }

    let mut core_counts = [0u64; crate::topology::MAX_CORES];
    for (cpu, &count) in hist
        .iter()
        .enumerate()
        .take(topology.nr_cpus.min(crate::topology::MAX_CPUS))
    {
        if count == 0 {
            continue;
        }
        let core = topology.cpu_core_id[cpu] as usize;
        if core < crate::topology::MAX_CORES {
            core_counts[core] += count as u64;
        }
    }

    let mut entries: Vec<(usize, u64)> = core_counts
        .iter()
        .enumerate()
        .filter_map(|(core, &count)| if count > 0 { Some((core, count)) } else { None })
        .collect();
    entries.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));

    let mut parts: Vec<String> = entries
        .iter()
        .take(limit)
        .map(|(core, count)| format!("core{}:{}%", core, (count * 100) / total))
        .collect();
    if entries.len() > limit {
        parts.push(format!("+{}", entries.len() - limit));
    }
    parts.join(" ")
}

fn callback_hist_summary(stats: &cake_stats, idx: usize) -> String {
    let buckets = stats.callback_hist[idx];
    let total: u64 = buckets.iter().sum();
    if total == 0 {
        return "0".to_string();
    }
    let sub_1us = buckets[0] + buckets[1] + buckets[2];
    let sub_5us = sub_1us + buckets[3] + buckets[4];
    let slow = stats.callback_slow[idx];
    format!(
        "<1u:{}% <5u:{}% slow:{}",
        (sub_1us * 100) / total,
        (sub_5us * 100) / total,
        slow
    )
}

fn push_debug_event(queue: &Arc<Mutex<VecDeque<DebugEventRow>>>, ev: DebugEventRow) {
    if let Ok(mut q) = queue.lock() {
        q.push_front(ev);
        while q.len() > 32 {
            q.pop_back();
        }
    }
}

fn display_runtime_us(us: u32) -> String {
    if us >= 65_535 {
        "65ms+".to_string()
    } else {
        us.to_string()
    }
}

fn display_gap_us(us: u64) -> String {
    if us > 1_000_000 {
        "sleep".to_string()
    } else {
        us.to_string()
    }
}

fn avg_jitter_us(row: &TaskTelemetryRow) -> u64 {
    if row.total_runs > 0 {
        row.jitter_accum_ns / row.total_runs as u64 / 1000
    } else {
        0
    }
}

#[derive(Copy, Clone, Debug, Default, Eq, PartialEq, Hash)]
enum WorkloadRole {
    Critical,
    Game,
    Render,
    Ui,
    Audio,
    Build,
    #[default]
    Other,
}

impl WorkloadRole {
    fn label(self) -> &'static str {
        match self {
            WorkloadRole::Critical => "KCRIT",
            WorkloadRole::Game => "GAME",
            WorkloadRole::Render => "RENDER",
            WorkloadRole::Ui => "UI",
            WorkloadRole::Audio => "AUDIO",
            WorkloadRole::Build => "BUILD",
            WorkloadRole::Other => "OTHER",
        }
    }

    fn color(self) -> Color {
        match self {
            WorkloadRole::Critical => Color::LightRed,
            WorkloadRole::Game => Color::LightGreen,
            WorkloadRole::Render => Color::LightCyan,
            WorkloadRole::Ui => Color::LightMagenta,
            WorkloadRole::Audio => Color::LightYellow,
            WorkloadRole::Build => Color::Yellow,
            WorkloadRole::Other => Color::Gray,
        }
    }
}

#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
enum CapacityBand {
    HardLatency,
    SoftLatency,
    Build,
    #[default]
    Other,
}

impl CapacityBand {
    fn label(self) -> &'static str {
        match self {
            CapacityBand::HardLatency => "hard",
            CapacityBand::SoftLatency => "soft",
            CapacityBand::Build => "build",
            CapacityBand::Other => "other",
        }
    }
}

#[derive(Clone, Debug, Default)]
struct TgidRoleState {
    thread_count: u32,
    max_pelt: u32,
    max_runs_per_sec: f64,
    leader_comm: String,
    has_render: bool,
    has_ui: bool,
    has_audio: bool,
    has_build: bool,
    has_game_hint: bool,
    has_browser_ui_hint: bool,
}

#[derive(Copy, Clone, Debug, Default)]
struct CapacitySummary {
    hard_latency_tasks: u32,
    hard_latency_hot: u32,
    soft_latency_tasks: u32,
    soft_latency_hot: u32,
    build_tasks: u32,
    build_hot: u32,
    game_tasks: u32,
    render_tasks: u32,
    ui_tasks: u32,
    audio_tasks: u32,
    critical_tasks: u32,
    shared_top_cores: u32,
    build_shared_tasks: u32,
    hard_latency_smt_heavy: u32,
    hard_latency_scattered: u32,
    focus_scattered: u32,
}

fn comm_has_any(comm: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| comm.contains(needle))
}

fn browser_ui_hint(comm: &str) -> bool {
    comm_has_any(
        comm,
        &[
            "steamwebhelper",
            "discord",
            "chrome",
            "chromium",
            "electron",
            "cef",
            "firefox",
            "browser",
            "webhelper",
        ],
    )
}

fn critical_ui_hint(comm: &str) -> bool {
    comm_has_any(
        comm,
        &[
            "gamescope",
            "xwayland",
            "kwin",
            "gnome-shell",
            "hyprland",
            "sway",
            "waylandeventthr",
            "sdl_joystick",
            "libinput",
        ],
    )
}

fn explicit_thread_role(row: &TaskTelemetryRow) -> Option<WorkloadRole> {
    if row.is_kcritical {
        return Some(WorkloadRole::Critical);
    }

    let comm = row.comm.to_ascii_lowercase();
    if comm_has_any(
        &comm,
        &[
            "rustc",
            "cargo",
            "ninja",
            "clang",
            "clang++",
            "gcc",
            "g++",
            "cc1",
            "cc1plus",
            "ld.lld",
            "mold",
            "cmake",
            "make",
            "ccache",
            "rust-analyzer",
        ],
    ) {
        return Some(WorkloadRole::Build);
    }
    if comm_has_any(&comm, &["pipewire", "wireplumber", "pulseaudio", "audio"]) {
        return Some(WorkloadRole::Audio);
    }
    if comm_has_any(
        &comm,
        &[
            "gamescope",
            "xwayland",
            "kwin",
            "gnome-shell",
            "hyprland",
            "sway",
            "wayland",
            "compositor",
            "vizcompositor",
            "vizdisplay",
            "sdl_joystick",
            "libinput",
        ],
    ) {
        return Some(WorkloadRole::Ui);
    }
    if comm_has_any(
        &comm,
        &[
            "unitygfx",
            "dxvk",
            "vkd3d",
            "swapchain",
            "wined3d",
            "render",
            "gfx",
            "gpu",
            "vkrt",
            "vkps",
            "vulkan",
            "d3d",
        ],
    ) {
        return Some(WorkloadRole::Render);
    }
    if comm.ends_with(".exe") || comm.contains("wow") {
        return Some(WorkloadRole::Game);
    }
    None
}

fn infer_tgid_roles(rows: &HashMap<u32, TaskTelemetryRow>) -> HashMap<u32, WorkloadRole> {
    let mut states = HashMap::<u32, TgidRoleState>::new();

    for row in rows.values() {
        if !row.is_bpf_tracked || row.total_runs == 0 || row.status == TaskStatus::Dead {
            continue;
        }
        let tgid = if row.tgid > 0 { row.tgid } else { row.pid };
        let state = states.entry(tgid).or_default();
        state.thread_count += 1;
        state.max_pelt = state.max_pelt.max(row.pelt_util);
        state.max_runs_per_sec = state.max_runs_per_sec.max(row.runs_per_sec);
        if row.pid == tgid || state.leader_comm.is_empty() {
            state.leader_comm = row.comm.clone();
        }
        match explicit_thread_role(row) {
            Some(WorkloadRole::Build) => state.has_build = true,
            Some(WorkloadRole::Render) => state.has_render = true,
            Some(WorkloadRole::Ui) => state.has_ui = true,
            Some(WorkloadRole::Audio) => state.has_audio = true,
            Some(WorkloadRole::Game) => state.has_game_hint = true,
            _ => {}
        }
        if browser_ui_hint(&row.comm.to_ascii_lowercase()) {
            state.has_browser_ui_hint = true;
        }
    }

    let mut roles = HashMap::new();
    for (tgid, state) in states {
        let leader = state.leader_comm.to_ascii_lowercase();
        let probable_ui = state.has_ui
            || state.has_browser_ui_hint
            || browser_ui_hint(&leader)
            || (state.thread_count >= 3
                && !state.has_build
                && !state.has_game_hint
                && comm_has_any(&leader, &["steamwebhelper", "discord", "chrome", "chromium", "cef", "electron"]));
        let probable_game = state.has_game_hint
            || leader.ends_with(".exe")
            || leader.contains("wow")
            || (!state.has_build
                && !probable_ui
                && ((state.thread_count >= 4
                    && (state.max_pelt >= 64 || state.max_runs_per_sec >= 75.0))
                    || (state.has_render && !browser_ui_hint(&leader))));
        let probable_render = state.has_render && !probable_ui && !probable_game;
        let role = if state.has_build {
            WorkloadRole::Build
        } else if probable_game {
            WorkloadRole::Game
        } else if probable_render {
            WorkloadRole::Render
        } else if probable_ui {
            WorkloadRole::Ui
        } else if state.has_audio {
            WorkloadRole::Audio
        } else {
            WorkloadRole::Other
        };
        roles.insert(tgid, role);
    }

    roles
}

fn task_role(row: &TaskTelemetryRow, tgid_roles: &HashMap<u32, WorkloadRole>) -> WorkloadRole {
    match explicit_thread_role(row) {
        Some(WorkloadRole::Game) | None => {
            let tgid = if row.tgid > 0 { row.tgid } else { row.pid };
            tgid_roles
                .get(&tgid)
                .copied()
                .unwrap_or_else(|| explicit_thread_role(row).unwrap_or_default())
        }
        Some(role) => role,
    }
}

fn row_is_hot(row: &TaskTelemetryRow) -> bool {
    row.pelt_util >= 64 || row.runs_per_sec >= 50.0
}

fn capacity_band(row: &TaskTelemetryRow, role: WorkloadRole) -> CapacityBand {
    if row.is_kcritical {
        return CapacityBand::HardLatency;
    }

    match role {
        WorkloadRole::Critical | WorkloadRole::Game | WorkloadRole::Render | WorkloadRole::Audio => {
            CapacityBand::HardLatency
        }
        WorkloadRole::Ui => {
            let comm = row.comm.to_ascii_lowercase();
            if critical_ui_hint(&comm) {
                CapacityBand::HardLatency
            } else {
                CapacityBand::SoftLatency
            }
        }
        WorkloadRole::Build => CapacityBand::Build,
        WorkloadRole::Other => CapacityBand::Other,
    }
}

fn class_label(row: &TaskTelemetryRow) -> &'static str {
    if row.is_kcritical {
        "KCR"
    } else if row.task_weight > 100 {
        "N-"
    } else if row.task_weight < 100 {
        "N+"
    } else {
        "N0"
    }
}

fn class_color(row: &TaskTelemetryRow) -> Color {
    if row.is_kcritical {
        Color::LightRed
    } else if row.task_weight > 100 {
        Color::Yellow
    } else if row.task_weight < 100 {
        Color::DarkGray
    } else {
        Color::Blue
    }
}

fn class_rank(row: &TaskTelemetryRow) -> u8 {
    if row.is_kcritical {
        3
    } else if row.task_weight > 100 {
        2
    } else if row.task_weight == 100 {
        1
    } else {
        0
    }
}

fn top_core_residency_pct(summary: &PlacementSummary) -> u64 {
    if summary.total_samples == 0 {
        0
    } else {
        summary
            .top_core
            .map(|(_, count)| (count * 100) / summary.total_samples)
            .unwrap_or(0)
    }
}

fn inferred_top_cpu(summary: &PlacementSummary, row: &TaskTelemetryRow) -> Option<usize> {
    summary
        .top_cpu
        .map(|(cpu, _)| cpu)
        .or_else(|| Some(row.core_placement as usize))
}

fn inferred_top_core(
    summary: &PlacementSummary,
    row: &TaskTelemetryRow,
    topology: &TopologyInfo,
) -> Option<usize> {
    summary.top_core.map(|(core, _)| core).or_else(|| {
        let cpu = inferred_top_cpu(summary, row)?;
        (cpu < topology.nr_cpus).then_some(topology.cpu_core_id[cpu] as usize)
    })
}

fn capacity_summary(app: &TuiApp, tgid_roles: &HashMap<u32, WorkloadRole>) -> CapacitySummary {
    let mut summary = CapacitySummary::default();
    let mut core_role_mask = HashMap::<usize, u8>::new();

    for row in app.task_rows.values() {
        if !row.is_bpf_tracked || row.total_runs == 0 || row.status == TaskStatus::Dead {
            continue;
        }
        let role = task_role(row, tgid_roles);
        let band = capacity_band(row, role);
        let placement = placement_summary(row, &app.topology);
        let top_core = inferred_top_core(&placement, row, &app.topology);

        match role {
            WorkloadRole::Critical => summary.critical_tasks += 1,
            WorkloadRole::Game => summary.game_tasks += 1,
            WorkloadRole::Render => summary.render_tasks += 1,
            WorkloadRole::Ui => summary.ui_tasks += 1,
            WorkloadRole::Audio => summary.audio_tasks += 1,
            WorkloadRole::Build => summary.build_tasks += 1,
            WorkloadRole::Other => {}
        }

        if band == CapacityBand::Build {
            if row_is_hot(row) {
                summary.build_hot += 1;
            }
            if let Some(core) = top_core {
                *core_role_mask.entry(core).or_insert(0) |= 0b10;
            }
        }

        if band == CapacityBand::HardLatency {
            summary.hard_latency_tasks += 1;
            if row_is_hot(row) {
                summary.hard_latency_hot += 1;
            }
            if placement.smt_secondary_pct >= 25 {
                summary.hard_latency_smt_heavy += 1;
            }
            if placement.active_core_count > 3 || top_core_residency_pct(&placement) < 50 {
                summary.hard_latency_scattered += 1;
                if matches!(role, WorkloadRole::Game | WorkloadRole::Render) {
                    summary.focus_scattered += 1;
                }
            }
            if let Some(core) = top_core {
                *core_role_mask.entry(core).or_insert(0) |= 0b01;
            }
        } else if band == CapacityBand::SoftLatency {
            summary.soft_latency_tasks += 1;
            if row_is_hot(row) {
                summary.soft_latency_hot += 1;
            }
        }
    }

    summary.shared_top_cores = core_role_mask
        .values()
        .filter(|mask| **mask == 0b11)
        .count() as u32;

    for row in app.task_rows.values() {
        if !row.is_bpf_tracked || row.total_runs == 0 || row.status == TaskStatus::Dead {
            continue;
        }
        if task_role(row, tgid_roles) != WorkloadRole::Build {
            continue;
        }
        let placement = placement_summary(row, &app.topology);
        if let Some(core) = inferred_top_core(&placement, row, &app.topology) {
            if core_role_mask.get(&core).copied().unwrap_or(0) == 0b11 {
                summary.build_shared_tasks += 1;
            }
        }
    }

    summary
}

fn debug_event_label(ev: &DebugEventRow) -> String {
    let kind = match ev.kind {
        1 => "cb",
        2 => "wait",
        _ => "evt",
    };
    format!(
        "{}:{} {} {}us c{}",
        kind,
        ev.slot,
        ev.comm,
        ev.value_ns / 1000,
        ev.cpu
    )
}

fn low_is_good_style(value: u64, good_max: u64, warn_max: u64) -> Style {
    if value <= good_max {
        Style::default().fg(Color::Green)
    } else if value <= warn_max {
        Style::default().fg(Color::Yellow)
    } else {
        Style::default()
            .fg(Color::LightRed)
            .add_modifier(Modifier::BOLD)
    }
}

fn high_is_good_style(value: f64, warn_min: f64, good_min: f64) -> Style {
    if value >= good_min {
        Style::default().fg(Color::Green)
    } else if value >= warn_min {
        Style::default().fg(Color::Yellow)
    } else {
        Style::default()
            .fg(Color::LightRed)
            .add_modifier(Modifier::BOLD)
    }
}

fn spread_style(cpu_count: usize, core_count: usize) -> Style {
    match (cpu_count, core_count) {
        (0..=2, 0..=2) => Style::default().fg(Color::Green),
        (3..=6, 2..=4) => Style::default().fg(Color::Yellow),
        _ => Style::default()
            .fg(Color::LightRed)
            .add_modifier(Modifier::BOLD),
    }
}

impl TuiApp {
    pub fn new(topology: TopologyInfo, latency_matrix: Vec<Vec<f64>>) -> Self {
        let nr_cpus = topology.nr_cpus;

        let mut sys = System::new();
        // Only load CPU specific metrics to reduce background overhead
        sys.refresh_cpu_usage();

        let components = Components::new_with_refreshed_list();

        // Collect system info once at startup (cold path only)
        let system_info = SystemInfo::detect(&topology);

        Self {
            start_time: Instant::now(),
            status_message: None,
            topology,
            latency_matrix,
            task_rows: HashMap::new(),
            sorted_pids: Vec::new(),
            table_state: TableState::default(),
            bench_table_state: TableState::default(),
            active_tab: TuiTab::Dashboard,
            sort_column: SortColumn::Pelt,
            sort_descending: true,

            sys,
            components,
            cpu_stats: vec![(0.0, 0.0); nr_cpus],
            task_filter: TaskFilter::BpfTracked,
            arena_active: 0,
            arena_max: 0,
            bpf_task_count: 0,
            prev_deltas: HashMap::new(),
            active_pids_buf: std::collections::HashSet::new(),
            collapsed_tgids: std::collections::HashSet::new(),
            collapsed_ppids: std::collections::HashSet::new(),
            bench_latency_handle: None,
            _prev_stats: None,
            bench_entries: [(0, 0, 0, 0); 67],
            bench_samples: vec![Vec::new(); 67],
            bench_cpu: 0,
            bench_iterations: 0,
            bench_timestamp: 0,
            bench_run_count: 0,
            last_bench_timestamp: 0,
            system_info,
            debug_events: VecDeque::new(),
            stats_history: VecDeque::new(),
        }
    }

    /// Format uptime as "Xm Ys" or "Xh Ym"
    fn format_uptime(&self) -> String {
        let elapsed = self.start_time.elapsed();
        let secs = elapsed.as_secs();
        if secs < 3600 {
            format!("{}m {}s", secs / 60, secs % 60)
        } else {
            format!("{}h {}m", secs / 3600, (secs % 3600) / 60)
        }
    }

    /// Set a temporary status message that disappears after 2 seconds
    fn set_status(&mut self, msg: &str) {
        self.status_message = Some((msg.to_string(), Instant::now()));
    }

    /// Get current status message if not expired
    fn get_status(&self) -> Option<&str> {
        match &self.status_message {
            Some((msg, timestamp)) if timestamp.elapsed() < Duration::from_secs(2) => Some(msg),
            _ => None,
        }
    }

    fn record_stats_snapshot(&mut self, stats: &cake_stats) {
        let now = Instant::now();
        self.stats_history.push_back(StatsSnapshot {
            at: now,
            stats: *stats,
        });
        while self.stats_history.len() > STATS_HISTORY_MAX_SAMPLES {
            self.stats_history.pop_front();
        }
        while let Some(front) = self.stats_history.front() {
            if now.saturating_duration_since(front.at) > STATS_HISTORY_MAX_AGE {
                self.stats_history.pop_front();
            } else {
                break;
            }
        }
    }

    fn windowed_stats(
        &self,
        current: &cake_stats,
        window: Duration,
    ) -> Option<(Duration, cake_stats)> {
        let newest = self.stats_history.back()?;
        let target = newest.at.checked_sub(window).unwrap_or(newest.at);
        let baseline = self
            .stats_history
            .iter()
            .rev()
            .find(|snap| snap.at <= target)
            .or_else(|| self.stats_history.front())?;
        let elapsed = newest.at.saturating_duration_since(baseline.at);
        if elapsed < Duration::from_secs(1) {
            return None;
        }
        Some((elapsed, stats_delta(current, &baseline.stats)))
    }

    pub fn next_tab(&mut self) {
        self.active_tab = self.active_tab.next();
    }

    pub fn previous_tab(&mut self) {
        self.active_tab = self.active_tab.previous();
    }

    pub fn cycle_sort(&mut self) {
        self.sort_column = match self.sort_column {
            SortColumn::Pid => SortColumn::Pelt,
            SortColumn::Pelt => SortColumn::MaxRuntime,
            SortColumn::MaxRuntime => SortColumn::Jitter,
            SortColumn::Jitter => SortColumn::Wait,
            SortColumn::Wait => SortColumn::RunsPerSec,
            SortColumn::RunsPerSec => SortColumn::TargetCpu,
            SortColumn::TargetCpu => SortColumn::Spread,
            SortColumn::Spread => SortColumn::Residency,
            SortColumn::Residency => SortColumn::SelectCpu,
            SortColumn::SelectCpu => SortColumn::Enqueue,
            SortColumn::Enqueue => SortColumn::Gap,
            SortColumn::Gap => SortColumn::Gate1Pct,
            SortColumn::Gate1Pct => SortColumn::Class,
            SortColumn::Class => SortColumn::Migrations,
            SortColumn::Migrations => SortColumn::Pid,
        };
    }

    pub fn scroll_table_down(&mut self) {
        let i = match self.table_state.selected() {
            Some(i) => {
                if i >= self.sorted_pids.len().saturating_sub(1) {
                    0
                } else {
                    i + 1
                }
            }
            None => 0,
        };
        self.table_state.select(Some(i));
    }

    pub fn scroll_table_up(&mut self) {
        let i = match self.table_state.selected() {
            Some(i) => {
                if i == 0 {
                    self.sorted_pids.len().saturating_sub(1)
                } else {
                    i - 1
                }
            }
            None => 0,
        };
        self.table_state.select(Some(i));
    }

    pub fn scroll_bench_down(&mut self) {
        let max = 32; // bench rows + category headers
        let i = match self.bench_table_state.selected() {
            Some(i) => {
                if i >= max {
                    0
                } else {
                    i + 1
                }
            }
            None => 0,
        };
        self.bench_table_state.select(Some(i));
    }

    pub fn scroll_bench_up(&mut self) {
        let max = 32;
        let i = match self.bench_table_state.selected() {
            Some(i) => {
                if i == 0 {
                    max
                } else {
                    i - 1
                }
            }
            None => 0,
        };
        self.bench_table_state.select(Some(i));
    }

    pub fn toggle_filter(&mut self) {
        self.task_filter = self.task_filter.next();
    }
}

/// Initialize the terminal for TUI mode
fn setup_terminal() -> Result<Terminal<CrosstermBackend<Stdout>>> {
    enable_raw_mode().context("Failed to enable raw mode")?;
    io::stdout()
        .execute(EnterAlternateScreen)
        .context("Failed to enter alternate screen")?;
    let backend = CrosstermBackend::new(io::stdout());
    Terminal::new(backend).context("Failed to create terminal")
}

/// Restore terminal to normal mode
fn restore_terminal() -> Result<()> {
    disable_raw_mode().context("Failed to disable raw mode")?;
    io::stdout()
        .execute(LeaveAlternateScreen)
        .context("Failed to leave alternate screen")?;
    Ok(())
}

/// A very compact topology display: shows LLC clusters cleanly formatted.
// Includes active Sysinfo hardware polling (load & temperature).
fn build_cpu_topology_grid_compact<'a>(
    topo: &'a TopologyInfo,
    cpu_stats: &'a [(f32, f32)],
) -> impl Widget + 'a {
    let mut text = Vec::new();

    text.push(Line::from(vec![
        Span::styled("Node 0 Topology", Style::default().fg(Color::DarkGray)),
        Span::styled("  [ Load% | Temp°C ]", Style::default().fg(Color::Yellow)),
    ]));

    // Group CPUs by LLC
    let mut llc_groups: HashMap<u32, Vec<usize>> = HashMap::new();
    for (cpu_id, &llc_id) in topo.cpu_llc_id.iter().enumerate() {
        llc_groups.entry(llc_id as u32).or_default().push(cpu_id);
    }

    let mut sorted_llcs: Vec<_> = llc_groups.into_iter().collect();
    sorted_llcs.sort_by_key(|k| k.0); // Sort by LLC ID

    for (llc_idx, (llc_id, cpus)) in sorted_llcs.iter().enumerate() {
        let l3_color = match llc_idx % 4 {
            0 => Color::Cyan,
            1 => Color::Magenta,
            2 => Color::Yellow,
            _ => Color::Green,
        };

        // Determine if this LLC has 3D V-Cache
        let has_vcache = {
            let word = (*llc_id as usize) >> 6;
            let bit = 1u64 << ((*llc_id as usize) & 63);
            word < topo.vcache_llc_mask.len() && (topo.vcache_llc_mask[word] & bit) != 0
        };
        let vcache_label = if has_vcache { " [3D V-Cache]" } else { "" };

        text.push(Line::from(vec![Span::styled(
            format!(" L3 Cache {}{}", llc_id, vcache_label),
            Style::default().fg(l3_color).add_modifier(Modifier::BOLD),
        )]));

        let mut sorted_cpus = cpus.clone();
        sorted_cpus.sort(); // Sort CPUs within LLC

        // Arrange CPUs in a compact grid
        let cpus_per_row = 4;
        for chunk in sorted_cpus.chunks(cpus_per_row) {
            let mut line_spans = vec![Span::raw("  ")]; // Indent
            for &cpu in chunk {
                let is_e_core = {
                    let word = cpu >> 6;
                    let bit = 1u64 << (cpu & 63);
                    word < topo.little_core_mask.len() && (topo.little_core_mask[word] & bit) != 0
                };
                let core_color = if is_e_core {
                    Color::DarkGray
                } else {
                    Color::White
                };

                let (load, temp) = cpu_stats.get(cpu).copied().unwrap_or((0.0, 0.0));

                // Color scaling based on load and temp
                let load_color = if load > 90.0 {
                    Color::Red
                } else if load > 50.0 {
                    Color::Yellow
                } else {
                    Color::Green
                };
                let temp_color = if temp > 85.0 {
                    Color::Red
                } else if temp > 70.0 {
                    Color::LightRed
                } else {
                    Color::Cyan
                };

                line_spans.push(Span::styled(
                    format!("CPU{:02} ", cpu),
                    Style::default().fg(core_color),
                ));
                line_spans.push(Span::styled("[", Style::default().fg(Color::DarkGray)));
                line_spans.push(Span::styled(
                    format!("{:>3.0}%", load),
                    Style::default().fg(load_color),
                ));
                line_spans.push(Span::styled("|", Style::default().fg(Color::DarkGray)));
                line_spans.push(Span::styled(
                    format!("{:<2.0}°C", temp),
                    Style::default().fg(temp_color),
                ));
                line_spans.push(Span::styled("]  ", Style::default().fg(Color::DarkGray)));
            }
            text.push(Line::from(line_spans));
        }
    }

    Paragraph::new(text).block(
        Block::default()
            .title(" Topology ")
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(Color::Cyan).dim())
            .padding(Padding::horizontal(1)),
    )
}

/// Custom Widget for high-density Latency Heatmap
struct LatencyHeatmap<'a> {
    matrix: &'a [Vec<f64>],
    topology: &'a TopologyInfo,
    title: &'a str,
}

impl<'a> LatencyHeatmap<'a> {
    fn new(matrix: &'a [Vec<f64>], topology: &'a TopologyInfo, title: &'a str) -> Self {
        Self {
            matrix,
            topology,
            title,
        }
    }
}

impl<'a> Widget for LatencyHeatmap<'a> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let nr_cpus = self.matrix.len();

        let block = Block::default()
            .title(self.title)
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(Color::Cyan).dim());

        let inner_area = block.inner(area);
        block.render(area, buf);

        if inner_area.width < 10 || inner_area.height < 5 {
            return;
        }

        // Header for Target CPUs (X-axis)
        for j in 0..nr_cpus {
            let x = inner_area.x + 6 + (j as u16 * 2);
            if x < inner_area.right() {
                buf.set_string(
                    x,
                    inner_area.y,
                    format!("{:1}", j % 10),
                    Style::default().fg(Color::Cyan).dim(),
                );
            }
        }

        for i in 0..nr_cpus {
            let y = inner_area.y + 1 + i as u16;
            if y >= inner_area.bottom() {
                break;
            }

            // Row Label (Source CPU)
            buf.set_string(
                inner_area.x + 1,
                y,
                format!("C{:02}", i),
                Style::default().fg(Color::Cyan).dim(),
            );

            for j in 0..nr_cpus {
                let x = inner_area.x + 6 + (j as u16 * 2);
                if x >= inner_area.right() - 1 {
                    continue;
                }

                let is_self = i == j;
                let is_smt = self.topology.cpu_sibling_map[i] as usize == j;
                let same_ccd = self.topology.cpu_llc_id[i] == self.topology.cpu_llc_id[j];

                let style = if is_self {
                    Style::default().fg(Color::Rgb(40, 40, 40))
                } else if is_smt {
                    Style::default().fg(Color::Rgb(0, 255, 150)) // Turquoise
                } else if same_ccd {
                    Style::default().fg(Color::Rgb(0, 200, 255)) // Cyan
                } else {
                    Style::default().fg(Color::Rgb(255, 180, 0)) // Amber
                };

                buf.set_string(x, y, "█", style);
                buf.set_string(x + 1, y, " ", Style::default());
            }
        }

        // Legend at bottom
        let legend_y = inner_area.bottom().saturating_sub(1);
        let legend_x = inner_area.x + 1;
        if legend_y > inner_area.y + nr_cpus as u16 {
            buf.set_string(
                legend_x,
                legend_y,
                "█ SMT",
                Style::default().fg(Color::Rgb(0, 255, 150)),
            );
            buf.set_string(
                legend_x + 9,
                legend_y,
                "█ Same CCD",
                Style::default().fg(Color::Rgb(0, 200, 255)),
            );
            buf.set_string(
                legend_x + 22,
                legend_y,
                "█ Cross-CCD",
                Style::default().fg(Color::Rgb(255, 180, 0)),
            );
        }
    }
}

/// Custom Widget for numerical latency table
struct LatencyTable<'a> {
    matrix: &'a [Vec<f64>],
    topology: &'a TopologyInfo,
}

impl<'a> LatencyTable<'a> {
    fn new(matrix: &'a [Vec<f64>], topology: &'a TopologyInfo) -> Self {
        Self { matrix, topology }
    }
}

impl<'a> Widget for LatencyTable<'a> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let nr_cpus = self.matrix.len();

        let block = Block::default()
            .title(" Latency Data ")
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(Color::Cyan).dim());

        let inner_area = block.inner(area);
        block.render(area, buf);

        if inner_area.width < 10 || inner_area.height < 5 {
            return;
        }

        // Header for Target CPUs
        for j in 0..nr_cpus {
            let x = inner_area.x + 5 + (j as u16 * 3);
            if x < inner_area.right() {
                buf.set_string(
                    x,
                    inner_area.y,
                    format!("{:>2}", j),
                    Style::default().fg(Color::Cyan).dim(),
                );
            }
        }

        for i in 0..nr_cpus {
            let y = inner_area.y + 1 + i as u16;
            if y >= inner_area.bottom() {
                break;
            }

            buf.set_string(
                inner_area.x + 1,
                y,
                format!("C{:02}", i),
                Style::default().fg(Color::Cyan).dim(),
            );

            for j in 0..nr_cpus {
                let x = inner_area.x + 5 + (j as u16 * 3);
                if x >= inner_area.right() - 2 {
                    continue;
                }

                let val = self.matrix[i][j].min(999.0);
                let is_self = i == j;
                let is_smt = self.topology.cpu_sibling_map[i] as usize == j;
                let same_ccd = self.topology.cpu_llc_id[i] == self.topology.cpu_llc_id[j];

                let style = if is_self {
                    Style::default().fg(Color::Rgb(40, 40, 40))
                } else if is_smt {
                    Style::default().fg(Color::Rgb(0, 255, 150))
                } else if same_ccd {
                    Style::default().fg(Color::Rgb(0, 200, 255))
                } else {
                    Style::default().fg(Color::Rgb(255, 180, 0))
                };

                buf.set_string(x, y, format!("{:>2.0}", val), style);
            }
        }
    }
}

/// Format BenchLab results as a copyable text string (tab-specific copy)
fn format_bench_for_clipboard(app: &TuiApp) -> String {
    // (index, name, category, source: K=kernel kfunc, C=cake custom code)
    // Groups: kfunc baseline first, then cake replacements. SPEED is per-group.
    let bench_items: &[(usize, &str, &str, &str)] = &[
        // Timing: all available clock sources
        (0, "bpf_ktime_get_ns()", "Timing", "K"),
        (1, "scx_bpf_now()", "Timing", "K"),
        (24, "bpf_ktime_get_boot_ns()", "Timing", "K"),
        (10, "Timing harness (cal)", "Timing", "C"),
        // Task Lookup: kfunc vs arena direct access
        (3, "bpf_task_from_pid()", "Task Lookup", "K"),
        (29, "bpf_get_current_task_btf()", "Task Lookup", "K"),
        (36, "bpf_task_storage_get()", "Task Lookup", "K"),
        (6, "get_task_ctx() [arena]", "Task Lookup", "C"),
        (22, "get_task_ctx+arena CL0", "Task Lookup", "C"),
        // Process Info: kfunc alternatives
        (28, "bpf_get_current_pid_tgid()", "Process Info", "K"),
        (30, "bpf_get_current_comm()", "Process Info", "K"),
        (14, "task_struct p->scx+nvcsw", "Process Info", "K"),
        (32, "scx_bpf_task_running(p)", "Process Info", "K"),
        (33, "scx_bpf_task_cpu(p)", "Process Info", "K"),
        (46, "Arena tctx.pid+tgid", "Process Info", "C"),
        (47, "Mbox CL0 cached_cpu", "Process Info", "C"),
        // CPU Identification: kfunc vs mailbox cached
        (2, "bpf_get_smp_proc_id()", "CPU ID", "K"),
        (31, "bpf_get_numa_node_id()", "CPU ID", "K"),
        (11, "Mbox CL0 cached CPU", "CPU ID", "C"),
        // Idle Probing: kfunc vs cake probes
        (4, "test_and_clear_idle()", "Idle Probing", "K"),
        (37, "scx_bpf_pick_idle_cpu()", "Idle Probing", "K"),
        (38, "idle_cpumask get+put", "Idle Probing", "K"),
        (19, "idle_probe(remote) MESI", "Idle Probing", "C"),
        (20, "smtmask read-only check", "Idle Probing", "C"),
        // Data Read: kernel struct vs cake data paths
        (8, "BSS global_stats[cpu]", "Data Read", "C"),
        (9, "Arena per_cpu.mbox", "Data Read", "C"),
        (15, "RODATA llc+quantum_ns", "Data Read", "C"),
        // Mailbox CL0: cake's Disruptor handoff variants
        (12, "Mbox CL0 tctx+deref", "Mailbox CL0", "C"),
        (18, "CL0 ptr+fused+packed", "Mailbox CL0", "C"),
        (21, "Disruptor CL0 full read", "Mailbox CL0", "C"),
        // Composite: cake-only multi-step operations
        (16, "Bitflag shift+mask+brless", "Composite Ops", "C"),
        (17, "(reserved, was compute_ewma)", "Composite Ops", "C"),
        // DVFS / Performance: CPU frequency queries
        (35, "scx_bpf_cpuperf_cur(cpu)", "DVFS / Perf", "K"),
        (42, "scx_bpf_cpuperf_cap(cpu)", "DVFS / Perf", "K"),
        (45, "RODATA cpuperf_cap[cpu]", "DVFS / Perf", "C"),
        // Topology Constants: kfunc vs RODATA
        (5, "scx_bpf_nr_cpu_ids()", "Topology", "K"),
        (34, "scx_bpf_nr_node_ids()", "Topology", "K"),
        (43, "RODATA nr_cpus const", "Topology", "C"),
        (44, "RODATA nr_nodes const", "Topology", "C"),
        // Standalone Kfuncs: reference costs
        (7, "scx_bpf_dsq_nr_queued()", "Standalone Kfuncs", "K"),
        (13, "ringbuf reserve+discard", "Standalone Kfuncs", "K"),
        (39, "scx_bpf_kick_cpu(self)", "Standalone Kfuncs", "K"),
        // Synchronization: lock/RNG costs
        (41, "bpf_spin_lock+unlock", "Synchronization", "K"),
        (40, "bpf_get_prandom_u32()", "Synchronization", "K"),
        (48, "CL0 lock-free 3-field", "Synchronization", "C"),
        (49, "BSS xorshift32 PRNG", "Synchronization", "C"),
        // TLB/Memory: arena access pattern cost
        (23, "Arena stride (TLB/hugepage)", "TLB/Memory", "C"),
        // Kernel Free Data: zero-cost task_struct field reads
        (50, "PELT util+runnable_avg", "Kernel Free Data", "K"),
        (51, "PELT runnable_avg only", "Kernel Free Data", "K"),
        (52, "schedstats nr_wakeups", "Kernel Free Data", "K"),
        (53, "p->policy+prio+flags", "Kernel Free Data", "K"),
        (54, "PELT read+legacy bucket", "Kernel Free Data", "K"),
        // End-to-End Workflow Comparisons
        (55, "task_storage write+read", "Storage Roundtrip", "C"),
        (56, "Arena write+read", "Storage Roundtrip", "C"),
        (57, "3-probe cascade (cake)", "Idle Selection", "C"),
        (58, "pick_idle_cpu full", "Idle Selection", "K"),
        (59, "Weight-vtime calc (bpfland)", "Classification", "C"),
        (60, "Latency score calc (lavd)", "Classification", "C"),
        (61, "SMT: cake sib probe", "SMT Probing", "C"),
        (62, "SMT: cpumask probe", "SMT Probing", "K"),
        // ═══ Fairness Fixes (cold-cache + remote) ═══
        // Note: cold probes use arena-stride L1 pollution. storage_get cold
        // can't evict task_struct — add ~10ns (L3 hit) conservatively.
        // kick_cpu remote measures bit-set only — add ~100ns for IPI delivery.
        (63, "storage_get COLD ~est", "Cold Cache", "K"),
        (64, "PELT bucket COLD", "Cold Cache", "K"),
        (65, "legacy EWMA COLD", "Cold Cache", "C"),
        (66, "kick_cpu REMOTE ~est", "Cold Cache", "K"),
    ];

    let percentile = |samples: &[u64], pct: f64| -> u64 {
        if samples.is_empty() {
            return 0;
        }
        let mut sorted = samples.to_vec();
        sorted.sort_unstable();
        let idx = ((pct / 100.0) * (sorted.len() as f64 - 1.0)).round() as usize;
        sorted[idx.min(sorted.len() - 1)]
    };

    let mut output = String::new();
    // System hardware context header
    output.push_str(&app.system_info.format_header());
    output.push('\n');
    output.push_str(&format!(
        "=== BenchLab ({} runs, {} samples, CPU {}) ===\n\n",
        app.bench_run_count, app.bench_iterations, app.bench_cpu
    ));
    output.push_str(&format!(
        "{:<30} {:>7} {:>7} {:>7} {:>7} {:>8} {:>7} {:>8} {:>7}\n",
        "HELPER", "MIN", "P1 LOW", "P50", "AVG", "P1 HIGH", "MAX", "JITTER", "SPEED"
    ));
    output.push_str(&format!("{}\n", "─".repeat(100)));

    let mut last_cat = "";
    let mut cat_baseline: u64 = 1; // per-category baseline AVG
    for &(idx, name, cat, src) in bench_items {
        if cat != last_cat {
            last_cat = cat;
            // Reset baseline for new category — first entry with data becomes base
            cat_baseline = 0;
            output.push_str(&format!("\n▸ {}\n", cat));
        }
        let (min_ns, max_ns, total_ns, _) = app.bench_entries[idx];
        if app.bench_iterations > 0 && total_ns > 0 {
            let avg_ns = total_ns / app.bench_iterations as u64;
            let samples = &app.bench_samples[idx];
            let p1 = percentile(samples, 1.0);
            let p50 = percentile(samples, 50.0);
            let p99 = percentile(samples, 99.0);
            let jitter = max_ns.saturating_sub(min_ns);
            let speedup = if cat_baseline == 0 {
                cat_baseline = avg_ns.max(1);
                "base".to_string()
            } else if avg_ns > 0 {
                format!("{:.1}×", cat_baseline as f64 / avg_ns as f64)
            } else {
                "--".to_string()
            };
            let tagged = format!("[{}] {}", src, name);
            output.push_str(&format!(
                "  {:<30} {:>5}ns {:>5}ns {:>5}ns {:>5}ns {:>6}ns {:>5}ns {:>6}ns {:>5}\n",
                tagged, min_ns, p1, p50, avg_ns, p99, max_ns, jitter, speedup
            ));
        }
    }
    output
}

fn avg_ns(total_ns: u64, calls: u64) -> u64 {
    if calls > 0 {
        total_ns / calls
    } else {
        0
    }
}

fn pct(part: u64, total: u64) -> f64 {
    if total > 0 {
        (part as f64 / total as f64) * 100.0
    } else {
        0.0
    }
}

fn per_sec(count: u64, secs: f64) -> f64 {
    if secs > 0.0 {
        count as f64 / secs
    } else {
        0.0
    }
}

fn place_class_label(cls: usize) -> &'static str {
    match cls {
        0 => "cpu",
        1 => "core",
        2 => "llc",
        3 => "remote",
        _ => "?",
    }
}

fn select_path_label(path: usize) -> &'static str {
    match path {
        1 => "home",
        2 => "core",
        3 => "prim",
        4 => "idle",
        5 => "tun",
        _ => "-",
    }
}

fn bucket_avg_us(sum_ns: u64, count: u64) -> u64 {
    if count > 0 {
        sum_ns / count / 1000
    } else {
        0
    }
}

fn format_place_wait_summary(sum_ns: &[u64], count: &[u64], max_ns: &[u64]) -> String {
    let mut parts = Vec::new();
    for cls in 0..4 {
        if count[cls] == 0 {
            continue;
        }
        parts.push(format!(
            "{}={}/{}/{}",
            place_class_label(cls),
            bucket_avg_us(sum_ns[cls], count[cls]),
            max_ns[cls] / 1000,
            count[cls]
        ));
    }
    if parts.is_empty() {
        "none".to_string()
    } else {
        parts.join(" ")
    }
}

fn format_path_summary(count: &[u64]) -> String {
    let mut parts = Vec::new();
    for path in 1..count.len() {
        if count[path] == 0 {
            continue;
        }
        parts.push(format!("{}={}", select_path_label(path), count[path]));
    }
    if parts.is_empty() {
        "none".to_string()
    } else {
        parts.join(" ")
    }
}

fn format_row_place_wait_summary(row: &TaskTelemetryRow) -> String {
    let mut parts = Vec::new();
    for cls in 0..4 {
        let count = row.home_place_wait_count[cls];
        if count == 0 {
            continue;
        }
        let avg_us = row.home_place_wait_ns[cls] / count as u64 / 1000;
        parts.push(format!(
            "{}={}/{}/{}",
            place_class_label(cls),
            avg_us,
            row.home_place_wait_max_us[cls],
            count
        ));
    }
    if parts.is_empty() {
        "none".to_string()
    } else {
        parts.join(" ")
    }
}

fn append_window_stats(
    output: &mut String,
    label: &str,
    elapsed: Duration,
    stats: &cake_stats,
    queue_now: u64,
) {
    let secs = elapsed.as_secs_f64().max(0.1);
    let total_dsq_dispatches = stats.nr_local_dispatches + stats.nr_stolen_dispatches;
    let wake_total = stats.nr_wakeup_direct_dispatches
        + stats.nr_wakeup_dsq_fallback_busy
        + stats.nr_wakeup_dsq_fallback_queued;
    let direct_total = stats.nr_direct_local_inserts;
    let shared_total = stats.nr_shared_vtime_inserts;

    output.push_str(&format!("\nwindow: {} sampled={:.1}s\n", label, secs));
    output.push_str(&format!(
        "win.disp: dsq_total={} ({:.1}/s) local={} steal={} miss={} ({:.1}/s) queue_now={} ins:direct={} ({:.1}/s) affine={} ({:.1}/s) shared={} ({:.1}/s) shared[w/r/p/o]={}/{}/{}/{} direct[k/o]={}/{} wake:direct={} ({:.1}%) busy={} ({:.1}%) queued={} ({:.1}%) total={} ({:.1}/s) steer:elig={} ({:.1}/s) home={} ({:.1}/s) core={} ({:.1}/s) primary={} ({:.1}/s) miss:home_busy={} prev_busy={} scan={}\n",
        total_dsq_dispatches,
        per_sec(total_dsq_dispatches, secs),
        stats.nr_local_dispatches,
        stats.nr_stolen_dispatches,
        stats.nr_dispatch_misses,
        per_sec(stats.nr_dispatch_misses, secs),
        queue_now,
        direct_total,
        per_sec(direct_total, secs),
        stats.nr_direct_affine_inserts,
        per_sec(stats.nr_direct_affine_inserts, secs),
        shared_total,
        per_sec(shared_total, secs),
        stats.nr_shared_wakeup_inserts,
        stats.nr_shared_requeue_inserts,
        stats.nr_shared_preserve_inserts,
        stats.nr_shared_other_inserts,
        stats.nr_direct_kthread_inserts,
        stats.nr_direct_other_inserts,
        stats.nr_wakeup_direct_dispatches,
        pct(stats.nr_wakeup_direct_dispatches, wake_total),
        stats.nr_wakeup_dsq_fallback_busy,
        pct(stats.nr_wakeup_dsq_fallback_busy, wake_total),
        stats.nr_wakeup_dsq_fallback_queued,
        pct(stats.nr_wakeup_dsq_fallback_queued, wake_total),
        wake_total,
        per_sec(wake_total, secs),
        stats.nr_steer_eligible,
        per_sec(stats.nr_steer_eligible, secs),
        stats.nr_home_cpu_steers,
        per_sec(stats.nr_home_cpu_steers, secs),
        stats.nr_home_core_steers,
        per_sec(stats.nr_home_core_steers, secs),
        stats.nr_primary_cpu_steers,
        per_sec(stats.nr_primary_cpu_steers, secs),
        stats.nr_home_cpu_busy_misses,
        stats.nr_prev_primary_busy_misses,
        stats.nr_primary_scan_misses,
    ));
    output.push_str(&format!(
        "win.cb: sel_avg_ns={} enq_avg_ns={} disp_avg_ns={} run_avg_ns={} stop_avg_ns={} slow=sel:{} enq:{} disp:{} run:{} stop:{}\n",
        avg_ns(stats.total_select_cpu_ns, stats.nr_select_cpu_calls),
        avg_ns(stats.total_enqueue_latency_ns, stats.nr_enqueue_calls),
        avg_ns(stats.total_dispatch_ns, stats.nr_dispatch_calls),
        avg_ns(stats.total_running_ns, stats.nr_running_calls),
        avg_ns(stats.total_stopping_ns, stats.nr_stopping_calls),
        stats.callback_slow[0],
        stats.callback_slow[1],
        stats.callback_slow[2],
        stats.callback_slow[3],
        stats.callback_slow[4],
    ));
    output.push_str(&format!(
        "win.cbhist: sel[{}] enq[{}] disp[{}] run[{}] stop[{}]\n",
        callback_hist_summary(stats, 0),
        callback_hist_summary(stats, 1),
        callback_hist_summary(stats, 2),
        callback_hist_summary(stats, 3),
        callback_hist_summary(stats, 4),
    ));
    output.push_str("win.wakewait<5ms:");
    for reason in 1..4 {
        let count = stats.wake_reason_wait_count[reason];
        let avg_us = if count > 0 {
            stats.wake_reason_wait_ns[reason] / count / 1000
        } else {
            0
        };
        output.push_str(&format!(
            " {}={}/{}({:.1}/s)",
            ["dir", "busy", "queue"][reason - 1],
            avg_us,
            count,
            per_sec(count, secs),
        ));
    }
    output.push('\n');
    output.push_str(&format!(
        "win.path: {}  deps:same_tgid={} ({:.1}/s) cross_tgid={} ({:.1}/s)\n",
        format_path_summary(&stats.select_path_count),
        stats.nr_wake_same_tgid,
        per_sec(stats.nr_wake_same_tgid, secs),
        stats.nr_wake_cross_tgid,
        per_sec(stats.nr_wake_cross_tgid, secs),
    ));
    output.push_str(&format!(
        "win.place.home: {}\n",
        format_place_wait_summary(
            &stats.home_place_wait_ns,
            &stats.home_place_wait_count,
            &stats.home_place_wait_max_ns,
        )
    ));
    output.push_str(&format!(
        "win.place.run: {}\n",
        format_place_wait_summary(
            &stats.home_place_run_ns,
            &stats.home_place_run_count,
            &stats.home_place_run_max_ns,
        )
    ));
    output.push_str(&format!(
        "win.place.waker: {}\n",
        format_place_wait_summary(
            &stats.waker_place_wait_ns,
            &stats.waker_place_wait_count,
            &stats.waker_place_wait_max_ns,
        )
    ));
    output.push_str(&format!(
        "win.coh/s: idle_remote={:.1} busy={:.1} idle={:.1} pend_remote={:.1} set={:.1} clr={:.1}\n",
        per_sec(stats.nr_idle_hint_remote_reads, secs),
        per_sec(stats.nr_idle_hint_remote_busy, secs),
        per_sec(stats.nr_idle_hint_remote_idle, secs),
        per_sec(stats.nr_busy_pending_remote_sets, secs),
        per_sec(stats.nr_idle_hint_set_writes + stats.nr_idle_hint_set_skips, secs),
        per_sec(stats.nr_idle_hint_clear_writes + stats.nr_idle_hint_clear_skips, secs),
    ));
    output.push_str(&format!(
        "win.bypass/s: requeue_fast={:.1} busy_local_skip={:.1} busy_remote_skip={:.1} busy_pending_skip={:.1}\n",
        per_sec(stats.nr_enqueue_requeue_fastpath, secs),
        per_sec(stats.nr_enqueue_busy_local_skip_depth, secs),
        per_sec(stats.nr_enqueue_busy_remote_skip_depth, secs),
        per_sec(stats.nr_busy_pending_set_skips, secs),
    ));
}

/// Format stats as a copyable text string
fn format_stats_for_clipboard(stats: &cake_stats, app: &TuiApp) -> String {
    let total_dsq_dispatches = stats.nr_local_dispatches + stats.nr_stolen_dispatches;
    let wake_names = ["dir", "busy", "queue"];
    let tgid_roles = infer_tgid_roles(&app.task_rows);
    let cap = capacity_summary(app, &tgid_roles);

    let mut output = String::new();
    output.push_str(&app.system_info.format_header());

    output.push_str(&format!(
        "cake: uptime={} state=IDLE detector=disabled\n",
        app.format_uptime(),
    ));
    output.push_str("scope: lifetime\n");

    // Compact dispatch stats
    let dsq_depth = stats.nr_dsq_queued.saturating_sub(stats.nr_dsq_consumed);
    let wake_total = stats.nr_wakeup_direct_dispatches
        + stats.nr_wakeup_dsq_fallback_busy
        + stats.nr_wakeup_dsq_fallback_queued;
    let direct_total = stats.nr_direct_local_inserts;
    let shared_total = stats.nr_shared_vtime_inserts;
    output.push_str(&format!(
        "disp: dsq_total={} local={} steal={} miss={} queue={} ins:direct={} affine={} shared={} shared[w/r/p/o]={}/{}/{}/{} direct[k/o]={}/{} wake:direct={} busy={} queued={} total={} busy_local={} busy_remote={} flow:tunnel_prev={} handoff={} supp={} steer:elig={} home={} core={} primary={} miss:home_busy={} prev_busy={} scan={}\n",
        total_dsq_dispatches,
        stats.nr_local_dispatches,
        stats.nr_stolen_dispatches,
        stats.nr_dispatch_misses,
        dsq_depth,
        direct_total,
        stats.nr_direct_affine_inserts,
        shared_total,
        stats.nr_shared_wakeup_inserts,
        stats.nr_shared_requeue_inserts,
        stats.nr_shared_preserve_inserts,
        stats.nr_shared_other_inserts,
        stats.nr_direct_kthread_inserts,
        stats.nr_direct_other_inserts,
        stats.nr_wakeup_direct_dispatches,
        stats.nr_wakeup_dsq_fallback_busy,
        stats.nr_wakeup_dsq_fallback_queued,
        wake_total,
        stats.nr_wakeup_busy_local_target,
        stats.nr_wakeup_busy_remote_target,
        stats.nr_prev_cpu_tunnels,
        stats.nr_busy_handoff_dispatches,
        stats.nr_busy_keep_suppressed,
        stats.nr_steer_eligible,
        stats.nr_home_cpu_steers,
        stats.nr_home_core_steers,
        stats.nr_primary_cpu_steers,
        stats.nr_home_cpu_busy_misses,
        stats.nr_prev_primary_busy_misses,
        stats.nr_primary_scan_misses,
    ));

    // Compact callback profile (all on 2 lines)
    let stop_total = stats.nr_stop_deferred_skip + stats.nr_stop_deferred;
    let stop_total_f = (stop_total as f64).max(1.0);
    output.push_str(&format!(
        "cb.stop: tot_µs={} max_ns={} calls={} skip={:.1}% deferred={:.1}%\n",
        stats.total_stopping_ns / 1000,
        stats.max_stopping_ns,
        stop_total,
        stats.nr_stop_deferred_skip as f64 / stop_total_f * 100.0,
        stats.nr_stop_deferred as f64 / stop_total_f * 100.0,
    ));
    output.push_str(&format!(
        "cb.run: tot_µs={} max_ns={} calls={}  cb.enq: tot_µs={} calls={}  sel: tot_µs={} g1_µs={} g2_µs={} calls={}  cb.disp: tot_µs={} max_ns={} calls={}\n",
        stats.total_running_ns / 1000, stats.max_running_ns, stats.nr_running_calls,
        stats.total_enqueue_latency_ns / 1000, stats.nr_enqueue_calls,
        stats.total_select_cpu_ns / 1000, stats.total_gate1_latency_ns / 1000, stats.total_gate2_latency_ns / 1000, stats.nr_select_cpu_calls,
        stats.total_dispatch_ns / 1000, stats.max_dispatch_ns, stats.nr_dispatch_calls,
    ));
    output.push_str(&format!(
        "cb.hist: sel[{}] enq[{}] disp[{}] run[{}] stop[{}]\n",
        callback_hist_summary(stats, 0),
        callback_hist_summary(stats, 1),
        callback_hist_summary(stats, 2),
        callback_hist_summary(stats, 3),
        callback_hist_summary(stats, 4),
    ));
    output.push_str("wakewait<5ms:");
    for reason in 1..4 {
        let count = stats.wake_reason_wait_count[reason];
        let avg_us = if count > 0 {
            stats.wake_reason_wait_ns[reason] / count / 1000
        } else {
            0
        };
        let max_us = stats.wake_reason_wait_max_ns[reason] / 1000;
        output.push_str(&format!(
            " {}={}/{}us({})",
            wake_names[reason - 1],
            avg_us,
            max_us,
            count
        ));
    }
    output.push('\n');
    output.push_str(&format!(
        "place.path: {}  deps:same_tgid={} cross_tgid={}\n",
        format_path_summary(&stats.select_path_count),
        stats.nr_wake_same_tgid,
        stats.nr_wake_cross_tgid,
    ));
    output.push_str(&format!(
        "place.home.wait: {}\n",
        format_place_wait_summary(
            &stats.home_place_wait_ns,
            &stats.home_place_wait_count,
            &stats.home_place_wait_max_ns,
        )
    ));
    output.push_str(&format!(
        "place.home.run: {}\n",
        format_place_wait_summary(
            &stats.home_place_run_ns,
            &stats.home_place_run_count,
            &stats.home_place_run_max_ns,
        )
    ));
    output.push_str(&format!(
        "place.waker.wait: {}\n",
        format_place_wait_summary(
            &stats.waker_place_wait_ns,
            &stats.waker_place_wait_count,
            &stats.waker_place_wait_max_ns,
        )
    ));
    output.push_str(&format!(
        "coh: idle_remote={} busy={} idle={} pend_remote={} set_w/s={}/{} clr_w/s={}/{}\n",
        stats.nr_idle_hint_remote_reads,
        stats.nr_idle_hint_remote_busy,
        stats.nr_idle_hint_remote_idle,
        stats.nr_busy_pending_remote_sets,
        stats.nr_idle_hint_set_writes,
        stats.nr_idle_hint_set_skips,
        stats.nr_idle_hint_clear_writes,
        stats.nr_idle_hint_clear_skips,
    ));
    output.push_str(&format!(
        "bypass: requeue_fast={} busy_local_skip_depth={} busy_remote_skip_depth={} busy_pending_skip={}\n",
        stats.nr_enqueue_requeue_fastpath,
        stats.nr_enqueue_busy_local_skip_depth,
        stats.nr_enqueue_busy_remote_skip_depth,
        stats.nr_busy_pending_set_skips,
    ));
    output.push_str(&format!(
        "cap: hard={} hot={} soft={} hot={} build={} hot={} shared_top_cores={} build_shared={} hard_smt={} hard_scatter={} focus_scatter={}\n",
        cap.hard_latency_tasks,
        cap.hard_latency_hot,
        cap.soft_latency_tasks,
        cap.soft_latency_hot,
        cap.build_tasks,
        cap.build_hot,
        cap.shared_top_cores,
        cap.build_shared_tasks,
        cap.hard_latency_smt_heavy,
        cap.hard_latency_scattered,
        cap.focus_scattered,
    ));
    output.push_str(&format!(
        "roles: game={} render={} ui={} audio={} build={} kcritical={}\n",
        cap.game_tasks,
        cap.render_tasks,
        cap.ui_tasks,
        cap.audio_tasks,
        cap.build_tasks,
        cap.critical_tasks,
    ));
    if let Some((elapsed, delta)) = app.windowed_stats(stats, Duration::from_secs(30)) {
        append_window_stats(&mut output, "30s", elapsed, &delta, dsq_depth);
    }
    if let Some((elapsed, delta)) = app.windowed_stats(stats, Duration::from_secs(60)) {
        append_window_stats(&mut output, "60s", elapsed, &delta, dsq_depth);
    }
    if !app.debug_events.is_empty() {
        output.push_str("events:\n");
        for ev in app.debug_events.iter().take(8) {
            let kind = match ev.kind {
                1 => "cb",
                2 => "wait",
                _ => "evt",
            };
            output.push_str(&format!(
                "  {} ts={} slot={} pid={} cpu={} val={}ns aux={} comm={}\n",
                kind, ev.ts_ns, ev.slot, ev.pid, ev.cpu, ev.value_ns, ev.aux, ev.comm
            ));
        }
    }

    if app.bench_run_count > 0 {
        output.push_str(&format_bench_for_clipboard(app));
    }

    // Task matrix header — compact column key
    output.push_str(
        "\ntasks: [PPID PID ST COMM CLS PELT MAXRTus GAPus JITus LASTWus RUN/s CPU SPRD RES% SMT% SELns ENQns STOPns RUNns G1% G3% DSQ% MIG/s]\n",
    );
    output.push_str(
        "       [detail: ROLE STEER(home/primary) DIRECT YIELD PRMPT MASK MAXGAPus DSQINSns RUNS SUTIL LLC/COUNT PLACE(cpu/core sampled) STREAK WAKER TGID CLS V/ICSW WAKEus(dir/busy/q) WHIST]\n",
    );

    const MAX_DUMP_ROWS: usize = 32;
    // Dump captures the busiest BPF-tracked tasks only so exported files stay compact.
    let mut dump_pids: Vec<u32> = app
        .task_rows
        .iter()
        .filter(|(_, row)| row.is_bpf_tracked && row.total_runs > 0)
        .map(|(pid, _)| *pid)
        .collect();
    dump_pids.sort_by(|a, b| {
        let r_a = app.task_rows.get(a).unwrap();
        let r_b = app.task_rows.get(b).unwrap();
        r_b.pelt_util.cmp(&r_a.pelt_util)
    });
    // TGID grouping (same logic as TUI)
    let mut tgid_rank: std::collections::HashMap<u32, usize> = std::collections::HashMap::new();
    for (i, pid) in dump_pids.iter().enumerate() {
        if let Some(row) = app.task_rows.get(pid) {
            let tgid = if row.tgid > 0 { row.tgid } else { *pid };
            tgid_rank.entry(tgid).or_insert(i);
        }
    }
    dump_pids.sort_by(|a, b| {
        let r_a = app.task_rows.get(a).unwrap();
        let r_b = app.task_rows.get(b).unwrap();
        let tgid_a = if r_a.tgid > 0 { r_a.tgid } else { *a };
        let tgid_b = if r_b.tgid > 0 { r_b.tgid } else { *b };
        let rank_a = tgid_rank.get(&tgid_a).copied().unwrap_or(usize::MAX);
        let rank_b = tgid_rank.get(&tgid_b).copied().unwrap_or(usize::MAX);
        rank_a
            .cmp(&rank_b)
            .then_with(|| r_b.pelt_util.cmp(&r_a.pelt_util))
    });
    let dump_total_rows = dump_pids.len();
    if dump_pids.len() > MAX_DUMP_ROWS {
        dump_pids.truncate(MAX_DUMP_ROWS);
    }
    output.push_str(&format!(
        "dump: top {} of {} BPF-tracked rows by grouped PELT activity\n",
        dump_pids.len(),
        dump_total_rows,
    ));

    // Pre-compute thread counts per tgid
    let mut tgid_counts: std::collections::HashMap<u32, u32> = std::collections::HashMap::new();
    for &pid in &dump_pids {
        if let Some(row) = app.task_rows.get(&pid) {
            let tgid = if row.tgid > 0 { row.tgid } else { pid };
            *tgid_counts.entry(tgid).or_insert(0) += 1;
        }
    }

    let mut last_tgid: u32 = 0;
    for &pid in &dump_pids {
        if let Some(row) = app.task_rows.get(&pid) {
            let tgid = if row.tgid > 0 { row.tgid } else { pid };

            // Process group header
            if tgid != last_tgid {
                let count = tgid_counts.get(&tgid).copied().unwrap_or(1);
                let proc_name = if let Some(tgid_row) = app.task_rows.get(&tgid) {
                    tgid_row.comm.clone()
                } else {
                    row.comm.clone()
                };
                let group_role = tgid_roles
                    .get(&tgid)
                    .copied()
                    .unwrap_or(WorkloadRole::Other);
                if count > 1 || tgid != pid {
                    output.push_str(&format!(
                        "\n▼ {} (PID {} PPID {}) — {} threads [{}]\n",
                        proc_name,
                        tgid,
                        row.ppid,
                        count,
                        group_role.label(),
                    ));
                }
                last_tgid = tgid;
            }

            let j_us = avg_jitter_us(row);
            let status_str = match row.status {
                TaskStatus::Alive => "●",
                TaskStatus::Idle => "○",
                TaskStatus::Dead => "✗",
            };
            let indent = if tgid != pid { "  " } else { "" };
            let cls_str = class_label(row);
            let last_wait_us = row.wait_duration_ns / 1000;
            let placement = placement_summary(row, &app.topology);
            let role = task_role(row, &tgid_roles);
            let wake_avg = |idx: usize| -> u64 {
                if row.wake_reason_count[idx] > 0 {
                    row.wake_reason_wait_ns[idx] / row.wake_reason_count[idx] as u64 / 1000
                } else {
                    0
                }
            };
            let wait_str = if row.status == TaskStatus::Dead && last_wait_us > 10000 {
                format!("{}†", last_wait_us)
            } else {
                format!("{}", last_wait_us)
            };
            output.push_str(&format!(
                "{}{:<5} {:<7} {:<3} {:<15} {:<4} {:<4} {:<7} {:<7} {:<6} {:<7} {:<7.1} C{:<3} {:<5} {:<7} {:<5} {:<5} {:<6} {:<6} {:<6} {:<4.0} {:<4.0} {:<4.0} {:<7.1}\n",
                indent,
                row.ppid,
                row.pid,
                status_str,
                row.comm,
                cls_str,
                row.pelt_util,  // PELT utilization (0-1024)
                display_runtime_us(row.max_runtime_us),
                display_gap_us(row.dispatch_gap_us),
                j_us,
                wait_str,
                row.runs_per_sec,
                row.core_placement,
                placement_spread_label(&placement),
                placement_residency_label(&placement),
                placement.smt_secondary_pct,
                row.select_cpu_ns,
                row.enqueue_ns,
                row.stopping_duration_ns,
                row.running_duration_ns,
                row.gate_hit_pcts[0],  // G1
                row.gate_hit_pcts[3],  // G3
                row.gate_hit_pcts[9],  // DSQ
                row.migrations_per_sec,
            ));
            // detail-A: gate % (G1/G3/DSQ) + all extended fields, compact labels
            output.push_str(&format!(
                "{}  role={}/{} steer={}/{} path={}/{} waker={} deps={}/{} dir={} yld={} prmpt={} mask={} maxgap={} dsqins={}ns runs={} sutil={}% llc=L{:02}/{} place=[{}|{} smt={}%] streak={} tgid={} cls={} v/icsw={}/{} wakeus={}/{}/{} hwait=[{}] whist={}/{}/{}/{}\n",
                indent,
                role.label(),
                capacity_band(row, role).label(),
                row.home_steer_hits,
                row.primary_steer_hits,
                select_path_label(row.last_select_path as usize),
                place_class_label(row.last_place_class as usize),
                place_class_label(row.last_waker_place_class as usize),
                row.wake_same_tgid_count,
                row.wake_cross_tgid_count,
                row.direct_dispatch_count, row.yield_count,
                row.preempt_count, row.cpumask_change_count,
                display_gap_us(row.max_dispatch_gap_us), row.dsq_insert_ns, row.total_runs,
                row.slice_util_pct,
                row.llc_id,
                placement.active_llc_count,
                top_cpu_distribution(&row.cpu_run_count, &app.topology, 3),
                top_core_distribution(&row.cpu_run_count, &app.topology, 3),
                placement.smt_secondary_pct,
                row.same_cpu_streak,
                row.tgid,
                class_label(row),
                row.nvcsw_delta,
                row.nivcsw_delta,
                wake_avg(0), wake_avg(1), wake_avg(2),
                format_row_place_wait_summary(row),
                row.wait_hist[0], row.wait_hist[1], row.wait_hist[2], row.wait_hist[3],
            ));
        }
    }

    output
}

/// Draw the UI
fn draw_ui(frame: &mut Frame, app: &mut TuiApp, stats: &cake_stats) {
    let area = frame.area();

    // --- Tab Bar ---
    let tab_titles = vec![" Dashboard ", " Topology ", " BenchLab ", " Reference "];
    let tabs = Tabs::new(tab_titles)
        .select(match app.active_tab {
            TuiTab::Dashboard => 0,
            TuiTab::Topology => 1,
            TuiTab::BenchLab => 2,
            TuiTab::ReferenceGuide => 3,
        })
        .style(Style::default().fg(Color::DarkGray))
        .highlight_style(
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD | Modifier::UNDERLINED),
        )
        .divider("│")
        .block(
            Block::default()
                .title(format!(" scx_cake v{} ", env!("CARGO_PKG_VERSION")))
                .title_style(
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                )
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::DarkGray))
                .border_type(BorderType::Rounded),
        );

    // Create main outer layout
    let main_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Tab bar (bordered)
            Constraint::Min(0),    // Active View
            Constraint::Length(3), // Footer
        ])
        .split(area);

    frame.render_widget(tabs, main_layout[0]);

    // Render active view
    match app.active_tab {
        TuiTab::Dashboard => draw_dashboard_tab(frame, app, stats, main_layout[1]),
        TuiTab::Topology => draw_topology_tab(frame, app, main_layout[1]),
        TuiTab::BenchLab => draw_bench_tab(frame, app, main_layout[1]),
        TuiTab::ReferenceGuide => draw_reference_tab(frame, main_layout[1]),
    }

    // --- Footer (key bindings + status) ---
    let arrow = if app.sort_descending { "▼" } else { "▲" };
    let sort_label = match app.sort_column {
        SortColumn::Pid => format!("[PID]{}", arrow),
        SortColumn::Pelt => format!("[PELT]{}", arrow),
        SortColumn::MaxRuntime => format!("[MAXµs]{}", arrow),
        SortColumn::Jitter => format!("[JITµs]{}", arrow),
        SortColumn::Wait => format!("[WAITµs]{}", arrow),
        SortColumn::RunsPerSec => format!("[RUN/s]{}", arrow),
        SortColumn::TargetCpu => format!("[CPU]{}", arrow),
        SortColumn::Spread => format!("[SPRD]{}", arrow),
        SortColumn::Residency => format!("[RES%]{}", arrow),
        SortColumn::SelectCpu => format!("[SELns]{}", arrow),
        SortColumn::Enqueue => format!("[ENQns]{}", arrow),
        SortColumn::Gap => format!("[GAPµs]{}", arrow),
        SortColumn::Gate1Pct => format!("[G1%]{}", arrow),
        SortColumn::Class => format!("[CLS]{}", arrow),
        SortColumn::Migrations => format!("[MIG/s]{}", arrow),
    };

    let footer_text = match app.get_status() {
        Some(status) => format!(
            " {} [s]Sort [S]Rev [+/-]Rate [↑↓]Scrl [T]Top [⏎]Fold [␣]Grp [x]FoldAll [Tab]Tabs [f]Filt [r]Reset [b]Bench [c]Copy [d]Dump [q]Quit │ {}",
            sort_label, status
        ),
        None => format!(
            " {} [s]Sort [S]Rev [+/-]Rate [↑↓]Scrl [T]Top [⏎]Fold [␣]Grp [x]FoldAll [Tab]Tabs [f]Filt [r]Reset [b]Bench [c]Copy [d]Dump [q]Quit",
            sort_label
        ),
    };
    let (fg_color, border_color) = if app.get_status().is_some() {
        (Color::Green, Color::Green)
    } else {
        (Color::DarkGray, Color::DarkGray)
    };
    let footer = Paragraph::new(footer_text)
        .style(Style::default().fg(fg_color))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(border_color)),
        );
    frame.render_widget(footer, main_layout[2]);
}

fn draw_dashboard_tab(frame: &mut Frame, app: &mut TuiApp, stats: &cake_stats, area: Rect) {
    let tgid_roles = infer_tgid_roles(&app.task_rows);
    let cap = capacity_summary(app, &tgid_roles);

    // Full-width stacked layout: compact header → tier performance → task matrix
    let outer_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(5), // Header: 3 content lines (stats + sched + state/game) + 2 borders
            Constraint::Length(8), // Tier performance panel (4 rows + header + borders)
            Constraint::Min(10),   // Full-width Task Matrix
        ])
        .split(area);

    // --- Compact Header: system info + tier counts on one line ---
    let total_dsq_dispatches = stats.nr_local_dispatches + stats.nr_stolen_dispatches;

    // PELT tier summary: count tasks by utilization bands
    let (mut wc0, mut wc1, mut wc2, mut wc3) = (0u32, 0u32, 0u32, 0u32);
    for row in app.task_rows.values() {
        if !row.is_bpf_tracked || row.total_runs == 0 {
            continue;
        }
        match row.pelt_util {
            0..=49 => wc0 += 1,
            50..=255 => wc1 += 1,
            256..=799 => wc2 += 1,
            _ => wc3 += 1,
        }
    }

    let topo_flags = format!(
        "{}C{}{}{}",
        app.topology.nr_cpus,
        if app.topology.has_dual_ccd {
            " 2CCD"
        } else {
            ""
        },
        if app.topology.has_hybrid_cores {
            " HYB"
        } else {
            ""
        },
        if app.topology.smt_enabled { " SMT" } else { "" },
    );

    let drop_warn = if stats.nr_dropped_allocations > 0 {
        format!("  ⚠ {}×ENOMEM", stats.nr_dropped_allocations)
    } else {
        String::new()
    };

    // CPU frequency from sysfs (best-effort, CPU 0 as representative)
    let cpu_freq_str =
        std::fs::read_to_string("/sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq")
            .ok()
            .and_then(|s| s.trim().parse::<u64>().ok())
            .map(|khz| format!(" {:.1}GHz", khz as f64 / 1_000_000.0))
            .unwrap_or_default();

    // Line 1: CPU | DSQ dispatches | Tier Distribution
    let line1 = format!(
        " CPU: {}{}  │  DSQ Dispatches: {}  │  Tiers: T0:{} T1:{} T2:{} T3:{}  │  {}{}",
        topo_flags,
        cpu_freq_str,
        total_dsq_dispatches,
        wc0,
        wc1,
        wc2,
        wc3,
        app.format_uptime(),
        drop_warn,
    );

    // Line 2: Dispatch locality | Queue depth | Tasks | Filter
    let dsq_depth = stats.nr_dsq_queued.saturating_sub(stats.nr_dsq_consumed);
    let _filter_label = app.task_filter.label();

    // Queue depth warning: if tasks are piling up, fallback pressure is rising
    let queue_str = if dsq_depth > 10 {
        format!("⚠ Queue:{}", dsq_depth)
    } else {
        format!("Queue:{}", dsq_depth)
    };

    let line2 = format!(
        " Dispatch: Local:{} Steal:{} Miss:{}  │  {}  │  Wake: Dir:{} Busy:{} Queued:{}  │  Flow: Tunnel:{} Handoff:{} Supp:{}  │  Steer: E:{} H:{} C:{} P:{} M:{}/{}/{}",
        stats.nr_local_dispatches,
        stats.nr_stolen_dispatches,
        stats.nr_dispatch_misses,
        queue_str,
        stats.nr_wakeup_direct_dispatches,
        stats.nr_wakeup_dsq_fallback_busy,
        stats.nr_wakeup_dsq_fallback_queued,
        stats.nr_prev_cpu_tunnels,
        stats.nr_busy_handoff_dispatches,
        stats.nr_busy_keep_suppressed,
        stats.nr_steer_eligible,
        stats.nr_home_cpu_steers,
        stats.nr_home_core_steers,
        stats.nr_primary_cpu_steers,
        stats.nr_home_cpu_busy_misses,
        stats.nr_prev_primary_busy_misses,
        stats.nr_primary_scan_misses,
    );

    let line3 = format!(
        " State: IDLE | detector disabled  │  C2C idle={} pend={} set={}/{} clr={}/{}",
        stats.nr_idle_hint_remote_reads,
        stats.nr_busy_pending_remote_sets,
        stats.nr_idle_hint_set_writes,
        stats.nr_idle_hint_set_skips,
        stats.nr_idle_hint_clear_writes,
        stats.nr_idle_hint_clear_skips,
    );

    let header_text = format!("{}\n{}\n{}", line1, line2, line3);

    let header_border_color = if stats.nr_dropped_allocations > 0 {
        Color::Red
    } else {
        Color::Blue
    };

    let header = Paragraph::new(header_text).block(
        Block::default()
            .title(" scx_cake Dashboard ")
            .title_style(
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            )
            .borders(Borders::ALL)
            .border_style(Style::default().fg(header_border_color)),
    );
    frame.render_widget(header, outer_layout[0]);

    // --- PELT Utilization Tier Panel ---
    // Aggregate by fixed PELT bands for display only.
    let mut tier_pids = [0u32; 4];
    let mut tier_avg_rt_sum = [0u64; 4];
    let mut tier_jitter_sum = [0u64; 4];
    let mut tier_runs_per_sec = [0.0f64; 4];
    let mut tier_wait_sum = [0u64; 4];
    let mut tier_active = [0u32; 4];

    for row in app.task_rows.values() {
        if !row.is_bpf_tracked || row.total_runs == 0 {
            continue;
        }
        // PELT tier aggregation
        let t = match row.pelt_util {
            0..=49 => 0,
            50..=255 => 1,
            256..=799 => 2,
            _ => 3,
        };
        tier_pids[t] += 1;
        tier_avg_rt_sum[t] += row.pelt_util as u64;
        tier_active[t] += 1;
        let j = row.jitter_accum_ns / row.total_runs as u64;
        tier_jitter_sum[t] += j / 1000;
        tier_runs_per_sec[t] += row.runs_per_sec;
        tier_wait_sum[t] += row.wait_duration_ns / 1000;
    }

    let total_runs_sec: f64 = tier_runs_per_sec.iter().sum();

    // Split tier row into two side-by-side panels
    let tier_cols = Layout::horizontal([Constraint::Percentage(55), Constraint::Percentage(45)])
        .split(outer_layout[1]);

    // ── Left: PELT Utilization Tiers ──
    let tier_names = ["P0 <5%", "P1 5-25%", "P2 25-78%", "P3 >=78%"];
    let tier_colors = [Color::LightCyan, Color::Green, Color::Yellow, Color::Red];

    let tier_header = Row::new(vec![
        Cell::from("PELT").style(
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        ),
        Cell::from("PIDs").style(
            Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        ),
        Cell::from("AVG PELT").style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Cell::from("JIT µs").style(
            Style::default()
                .fg(Color::LightCyan)
                .add_modifier(Modifier::BOLD),
        ),
        Cell::from("LASTW µs").style(
            Style::default()
                .fg(Color::LightYellow)
                .add_modifier(Modifier::BOLD),
        ),
        Cell::from("RUNS/s").style(
            Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD),
        ),
        Cell::from("WORK%").style(
            Style::default()
                .fg(Color::Magenta)
                .add_modifier(Modifier::BOLD),
        ),
    ])
    .height(1);

    let tier_rows: Vec<Row> = (0..4)
        .map(|t| {
            let count = tier_active[t].max(1) as u64;
            let avg_rt = tier_avg_rt_sum[t] / count;
            let avg_jit = tier_jitter_sum[t] / count;
            let avg_wait = tier_wait_sum[t] / count;
            let work_pct = if total_runs_sec > 0.0 {
                (tier_runs_per_sec[t] / total_runs_sec) * 100.0
            } else {
                0.0
            };

            Row::new(vec![
                Cell::from(tier_names[t]).style(
                    Style::default()
                        .fg(tier_colors[t])
                        .add_modifier(Modifier::BOLD),
                ),
                Cell::from(format!("{}", tier_pids[t])),
                Cell::from(format!("{}", avg_rt)),
                Cell::from(format!("{} µs", avg_jit)).style(low_is_good_style(avg_jit, 10, 100)),
                Cell::from(format!("{}", avg_wait)).style(low_is_good_style(avg_wait, 10, 100)),
                Cell::from(format!("{:.1}", tier_runs_per_sec[t])),
                Cell::from(format!("{:.1}%", work_pct)),
            ])
        })
        .collect();

    let tier_table = Table::new(
        tier_rows,
        [
            Constraint::Length(15), // TIER
            Constraint::Length(6),  // PIDs
            Constraint::Length(10), // AVG PELT
            Constraint::Length(10), // JIT µs
            Constraint::Length(10), // LASTW µs
            Constraint::Length(9),  // RUNS/s
            Constraint::Length(7),  // WORK%
        ],
    )
    .header(tier_header)
    .block(
        Block::default()
            .title(" PELT Utilization Tiers ")
            .title_style(
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            )
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::DarkGray))
            .border_type(BorderType::Rounded),
    );
    frame.render_widget(tier_table, tier_cols[0]);

    let wakewait_line = {
        let mut parts = Vec::new();
        for (idx, label) in ["dir", "busy", "queue"].iter().enumerate() {
            let count = stats.wake_reason_wait_count[idx + 1];
            let avg_us = if count > 0 {
                stats.wake_reason_wait_ns[idx + 1] / count / 1000
            } else {
                0
            };
            let max_us = stats.wake_reason_wait_max_ns[idx + 1] / 1000;
            parts.push(format!("{} {}/{}us ({})", label, avg_us, max_us, count));
        }
        format!("Wake<5ms: {}", parts.join("  "))
    };
    let callback_line = format!(
        "CB Hist: sel[{}] enq[{}] disp[{}] run[{}] stop[{}]",
        callback_hist_summary(stats, 0),
        callback_hist_summary(stats, 1),
        callback_hist_summary(stats, 2),
        callback_hist_summary(stats, 3),
        callback_hist_summary(stats, 4),
    );
    let place_path_line = format!(
        "Placement: path[{}] deps same/cross={}/{}",
        format_path_summary(&stats.select_path_count),
        stats.nr_wake_same_tgid,
        stats.nr_wake_cross_tgid,
    );
    let place_cost_line = format!(
        "WarmCost: home[{}] run[{}] waker[{}]",
        format_place_wait_summary(
            &stats.home_place_wait_ns,
            &stats.home_place_wait_count,
            &stats.home_place_wait_max_ns,
        ),
        format_place_wait_summary(
            &stats.home_place_run_ns,
            &stats.home_place_run_count,
            &stats.home_place_run_max_ns,
        ),
        format_place_wait_summary(
            &stats.waker_place_wait_ns,
            &stats.waker_place_wait_count,
            &stats.waker_place_wait_max_ns,
        ),
    );
    let coh_line = format!(
        "Coherency: idle_remote={} busy={} idle={} pend_remote={}",
        stats.nr_idle_hint_remote_reads,
        stats.nr_idle_hint_remote_busy,
        stats.nr_idle_hint_remote_idle,
        stats.nr_busy_pending_remote_sets,
    );
    let bypass_line = format!(
        "Bypass: requeue={} busy_local={} busy_remote={} pend_skip={}",
        stats.nr_enqueue_requeue_fastpath,
        stats.nr_enqueue_busy_local_skip_depth,
        stats.nr_enqueue_busy_remote_skip_depth,
        stats.nr_busy_pending_set_skips,
    );
    let steer_line = format!(
        "Steering: home_hits={} primary_hits={}",
        stats.nr_home_cpu_steers, stats.nr_primary_cpu_steers,
    );
    let capacity_line = format!(
        "Capacity: hard={} soft={} build={} shared_cores={} build_shared={} hard_smt={} hard_scatter={} focus_scatter={}",
        cap.hard_latency_tasks,
        cap.soft_latency_tasks,
        cap.build_tasks,
        cap.shared_top_cores,
        cap.build_shared_tasks,
        cap.hard_latency_smt_heavy,
        cap.hard_latency_scattered,
        cap.focus_scattered,
    );
    let role_line = format!(
        "Roles: game={} render={} ui={} audio={} build={} kcritical={}",
        cap.game_tasks,
        cap.render_tasks,
        cap.ui_tasks,
        cap.audio_tasks,
        cap.build_tasks,
        cap.critical_tasks,
    );
    let write_line = format!(
        "idle_hint writes/skips: set {}/{}  clear {}/{}",
        stats.nr_idle_hint_set_writes,
        stats.nr_idle_hint_set_skips,
        stats.nr_idle_hint_clear_writes,
        stats.nr_idle_hint_clear_skips,
    );
    let mut debug_lines = vec![
        Line::from(wakewait_line),
        Line::from(callback_line),
        Line::from(place_path_line),
        Line::from(place_cost_line),
        Line::from(coh_line),
        Line::from(bypass_line),
        Line::from(steer_line),
        Line::from(capacity_line),
        Line::from(role_line),
        Line::from(write_line),
    ];
    if !app.debug_events.is_empty() {
        debug_lines.push(Line::from("Recent events:"));
        for ev in app.debug_events.iter().take(3) {
            debug_lines.push(Line::from(format!("  {}", debug_event_label(ev))));
        }
    } else {
        debug_lines.push(Line::from("Recent events: none"));
    }
    let debug_panel = Paragraph::new(debug_lines)
        .block(
            Block::default()
                .title(" Scheduler Signals ")
                .title_style(
                    Style::default()
                        .fg(Color::LightMagenta)
                        .add_modifier(Modifier::BOLD),
                )
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::DarkGray))
                .border_type(BorderType::Rounded),
        )
        .wrap(Wrap { trim: false });
    frame.render_widget(debug_panel, tier_cols[1]);

    let matrix_header = Row::new(vec![
        // ── Identity (DarkGray = secondary, Yellow = primary key) ──
        Cell::from("PPID").style(
            Style::default()
                .fg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        ),
        Cell::from("PID").style(
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        ),
        Cell::from("ST").style(
            Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        ),
        Cell::from("COMM").style(
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        ),
        // ── Classification (LightMagenta) ──
        Cell::from("CLS").style(
            Style::default()
                .fg(Color::LightMagenta)
                .add_modifier(Modifier::BOLD),
        ),
        // ── Activity / latency (Cyan) ──
        Cell::from("PELT").style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Cell::from("MAXµs").style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Cell::from("GAPµs").style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Cell::from("JITµs").style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Cell::from("WAITµs").style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Cell::from("RUNS/s").style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        // ── Placement (Magenta) ──
        Cell::from("CPU").style(
            Style::default()
                .fg(Color::Magenta)
                .add_modifier(Modifier::BOLD),
        ),
        Cell::from("SPRD").style(
            Style::default()
                .fg(Color::Magenta)
                .add_modifier(Modifier::BOLD),
        ),
        Cell::from("RES%").style(
            Style::default()
                .fg(Color::Magenta)
                .add_modifier(Modifier::BOLD),
        ),
        Cell::from("SMT%").style(
            Style::default()
                .fg(Color::Magenta)
                .add_modifier(Modifier::BOLD),
        ),
        // ── Callback Overhead (LightCyan) ──
        Cell::from("SELns").style(
            Style::default()
                .fg(Color::LightCyan)
                .add_modifier(Modifier::BOLD),
        ),
        Cell::from("ENQns").style(
            Style::default()
                .fg(Color::LightCyan)
                .add_modifier(Modifier::BOLD),
        ),
        Cell::from("STOPns").style(
            Style::default()
                .fg(Color::LightCyan)
                .add_modifier(Modifier::BOLD),
        ),
        Cell::from("RUNns").style(
            Style::default()
                .fg(Color::LightCyan)
                .add_modifier(Modifier::BOLD),
        ),
        // ── Gate Distribution (Green) ──
        Cell::from("G1%").style(
            Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD),
        ),
        Cell::from("G3%").style(
            Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD),
        ),
        Cell::from("DSQ%").style(
            Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD),
        ),
        // ── Placement / churn (Magenta) ──
        Cell::from("MIGR/s").style(
            Style::default()
                .fg(Color::Magenta)
                .add_modifier(Modifier::BOLD),
        ),
    ])
    .height(1);

    let mut matrix_rows: Vec<Row> = Vec::new();
    let mut last_tgid: u32 = 0;

    // Pre-compute thread counts per tgid for the header
    let mut tgid_thread_counts: std::collections::HashMap<u32, u32> =
        std::collections::HashMap::new();
    for pid in &app.sorted_pids {
        if let Some(row) = app.task_rows.get(pid) {
            let tgid = if row.tgid > 0 { row.tgid } else { *pid };
            *tgid_thread_counts.entry(tgid).or_insert(0) += 1;
        }
    }

    for pid in &app.sorted_pids {
        let row = match app.task_rows.get(pid) {
            Some(r) => r,
            None => continue,
        };
        let tgid = if row.tgid > 0 { row.tgid } else { *pid };

        // Insert process group header when tgid changes
        if tgid != last_tgid {
            let thread_count = tgid_thread_counts.get(&tgid).copied().unwrap_or(1);
            let proc_name = if let Some(tgid_row) = app.task_rows.get(&tgid) {
                tgid_row.comm.as_str()
            } else {
                row.comm.as_str()
            };
            let is_collapsed = app.collapsed_tgids.contains(&tgid);
            if thread_count > 1 || tgid != *pid {
                let arrow = if is_collapsed { "▶" } else { "▼" };
                let header_text = format!(
                    "{} {} (PID {}) — {} threads",
                    arrow, proc_name, tgid, thread_count
                );
                let header_cells = vec![Cell::from(header_text).style(
                    Style::default()
                        .fg(Color::White)
                        .add_modifier(Modifier::BOLD | Modifier::UNDERLINED),
                )];
                matrix_rows.push(Row::new(header_cells).height(1));
            }
            last_tgid = tgid;
        }

        // Skip entire PPID group if collapsed
        if app.collapsed_ppids.contains(&row.ppid) && row.ppid > 0 {
            continue;
        }

        // Skip child threads if their TGID is collapsed
        if tgid != *pid && app.collapsed_tgids.contains(&tgid) {
            continue;
        }

        let jitter_us = avg_jitter_us(row);
        let indent = if tgid != *pid { "  " } else { "" };
        let placement = placement_summary(row, &app.topology);
        let role = task_role(row, &tgid_roles);
        let last_wait_us = row.wait_duration_ns / 1000;
        let gap_style = if row.dispatch_gap_us > 1_000_000 {
            Style::default().fg(Color::DarkGray)
        } else {
            low_is_good_style(row.dispatch_gap_us, 50, 500)
        };
        let cells = vec![
            Cell::from(format!("{}{}", indent, row.ppid)),
            Cell::from(format!("{}", row.pid)),
            Cell::from(row.status.short_label()).style(Style::default().fg(row.status.color())),
            Cell::from(row.comm.as_str()).style(Style::default().fg(role.color())),
            Cell::from(class_label(row)).style(Style::default().fg(class_color(row))),
            Cell::from(format!("{}", row.pelt_util)),
            Cell::from(display_runtime_us(row.max_runtime_us)).style(low_is_good_style(
                row.max_runtime_us as u64,
                500,
                2_000,
            )),
            Cell::from(display_gap_us(row.dispatch_gap_us)).style(gap_style),
            Cell::from(format!("{}", jitter_us)).style(low_is_good_style(jitter_us, 10, 100)),
            Cell::from(format!("{}", last_wait_us)).style(low_is_good_style(last_wait_us, 10, 100)),
            Cell::from(format!("{:.1}", row.runs_per_sec)),
            Cell::from(format!("C{:02}", row.core_placement)),
            Cell::from(placement_spread_label(&placement)).style(spread_style(
                placement.active_cpu_count,
                placement.active_core_count,
            )),
            Cell::from(placement_residency_label(&placement)).style(high_is_good_style(
                placement
                    .top_core
                    .map(|(_, count)| (count * 100) as f64 / placement.total_samples.max(1) as f64)
                    .unwrap_or(0.0),
                70.0,
                90.0,
            )),
            Cell::from(format!("{}", placement.smt_secondary_pct)).style(low_is_good_style(
                placement.smt_secondary_pct,
                5,
                20,
            )),
            Cell::from(format!("{}", row.select_cpu_ns)).style(low_is_good_style(
                row.select_cpu_ns as u64,
                1_000,
                5_000,
            )),
            Cell::from(format!("{}", row.enqueue_ns)).style(low_is_good_style(
                row.enqueue_ns as u64,
                1_000,
                5_000,
            )),
            Cell::from(format!("{}", row.stopping_duration_ns)).style(low_is_good_style(
                row.stopping_duration_ns as u64,
                1_000,
                5_000,
            )),
            Cell::from(format!("{}", row.running_duration_ns)).style(low_is_good_style(
                row.running_duration_ns as u64,
                1_000,
                5_000,
            )),
            Cell::from(format!("{:.0}", row.gate_hit_pcts[0])).style(high_is_good_style(
                row.gate_hit_pcts[0],
                25.0,
                60.0,
            )),
            Cell::from(format!("{:.0}", row.gate_hit_pcts[3])).style(low_is_good_style(
                row.gate_hit_pcts[3] as u64,
                20,
                50,
            )),
            Cell::from(format!("{:.0}", row.gate_hit_pcts[9])).style(low_is_good_style(
                row.gate_hit_pcts[9] as u64,
                10,
                25,
            )),
            Cell::from(format!("{:.1}", row.migrations_per_sec)).style(low_is_good_style(
                row.migrations_per_sec as u64,
                1,
                10,
            )),
        ];
        matrix_rows.push(Row::new(cells).height(1));
    }
    let filter_label = app.task_filter.label();

    let matrix_table = Table::new(
        matrix_rows,
        [
            Constraint::Length(6),  // PPID
            Constraint::Length(8),  // PID
            Constraint::Length(3),  // ST
            Constraint::Length(15), // COMM
            Constraint::Length(5),  // CLS
            Constraint::Length(6),  // PELT
            Constraint::Length(7),  // MAXµs
            Constraint::Length(7),  // GAPµs
            Constraint::Length(7),  // JITµs
            Constraint::Length(8),  // WAITµs
            Constraint::Length(7),  // RUNS/s
            Constraint::Length(4),  // CPU
            Constraint::Length(5),  // SPRD
            Constraint::Length(7),  // RES%
            Constraint::Length(5),  // SMT%
            Constraint::Length(6),  // SELns
            Constraint::Length(6),  // ENQns
            Constraint::Length(7),  // STOPns
            Constraint::Length(6),  // RUNns
            Constraint::Length(4),  // G1%
            Constraint::Length(4),  // G3%
            Constraint::Length(4),  // DSQ%
            Constraint::Length(7),  // MIGR/s
        ],
    )
    .header(matrix_header)
    .block(
        Block::default()
            .title(format!(
                " Live Task Matrix (PELT raw 0-1024 │ latency: µs │ callbacks: ns │ placement sampled) [{}] ",
                filter_label
            ))
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Blue)),
    )
    .row_highlight_style(Style::default().add_modifier(Modifier::REVERSED))
    .highlight_symbol(">> ");

    // Using render_stateful_widget instead of render_widget to manage scroll table state
    frame.render_stateful_widget(matrix_table, outer_layout[2], &mut app.table_state);
}

fn draw_topology_tab(frame: &mut Frame, app: &TuiApp, area: Rect) {
    let nr_cpus = app.latency_matrix.len();
    let heatmap_min_width = (6 + nr_cpus * 2 + 4) as u16;
    let data_min_width = (5 + nr_cpus * 3 + 4) as u16;

    let layout = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Min(22),
            Constraint::Min(heatmap_min_width),
            Constraint::Min(data_min_width),
        ])
        .split(area);
    let topology_grid = build_cpu_topology_grid_compact(&app.topology, &app.cpu_stats);
    frame.render_widget(topology_grid, layout[0]);

    // Dynamic heatmap title based on benchmark state
    let heatmap_title = if app.bench_latency_handle.is_some() {
        " Latency Heatmap ⏱ Benchmarking... ".to_string()
    } else if app
        .latency_matrix
        .iter()
        .any(|row| row.iter().any(|&v| v > 0.0))
    {
        " Latency Heatmap (ns) ".to_string()
    } else {
        " Latency Heatmap [b] Benchmark ".to_string()
    };
    let heatmap = LatencyHeatmap::new(&app.latency_matrix, &app.topology, &heatmap_title);
    frame.render_widget(heatmap, layout[1]);

    let data_table = LatencyTable::new(&app.latency_matrix, &app.topology);
    frame.render_widget(data_table, layout[2]);
}

fn draw_reference_tab(frame: &mut Frame, area: Rect) {
    // 2-column layout: left = matrix columns, right = dump/profile/keys
    let cols =
        Layout::horizontal([Constraint::Percentage(50), Constraint::Percentage(50)]).split(area);

    // Helper: styled section header
    fn section(text: &str) -> Line<'_> {
        Line::from(Span::styled(
            text,
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        ))
    }
    // Helper: styled subsection header
    fn subsection(text: &str) -> Line<'_> {
        Line::from(Span::styled(
            text,
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ))
    }
    // Helper: column definition entry
    fn col(name: &str, desc: &str) -> Line<'static> {
        Line::from(vec![
            Span::styled(
                format!("{:<8}", name),
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(desc.to_string()),
        ])
    }
    // Helper: indented sub-entry
    fn sub(prefix: &str, desc: &str, color: Color) -> Line<'static> {
        Line::from(vec![
            Span::styled(format!("          {}", prefix), Style::default().fg(color)),
            Span::raw(format!(" {}", desc)),
        ])
    }

    // ═══ LEFT PANEL: Matrix Columns ═══
    let left_text = vec![
        section("═══ LIVE MATRIX COLUMNS ═══"),
        Line::from(""),
        subsection("── Identity & Current Slot ──"),
        col("PPID", "Parent PID — groups threads by launcher"),
        col("PID", "Thread ID (per-thread, not process)"),
        col("ST", "Task status:"),
        sub(
            "●LIVE",
            "Alive — actively scheduled, has telemetry",
            Color::Green,
        ),
        sub(
            "○IDLE",
            "Idle — in sysinfo but no BPF telemetry",
            Color::DarkGray,
        ),
        sub("✗DEAD", "Dead — exited since last refresh", Color::DarkGray),
        col("COMM", "Thread name (first 15 chars, from /proc)"),
        col("CLS", "Current cake role:"),
        sub("KCR", "Kernel-critical helper thread", Color::LightRed),
        sub("N-", "Raised weight / negative nice task", Color::Yellow),
        sub("N0", "Default nice-0 task", Color::Blue),
        sub("N+", "Reduced weight / positive nice task", Color::DarkGray),
        Line::from(""),
        subsection("── Activity & Latency ──"),
        col(
            "PELT",
            "Kernel PELT util_avg (0-1024), not a cake-private metric",
        ),
        col(
            "MAXµs",
            "Largest runtime seen for the task in this interval",
        ),
        col(
            "GAPµs",
            "Time since previous run start ('sleep' = long sleeper)",
        ),
        col("JITµs", "Average inter-run jitter in this interval"),
        col("WAITµs", "Last enqueue→run wait before the current run"),
        col("RUNS/s", "Runs per second — scheduling frequency"),
        Line::from(""),
        subsection("── Placement ──"),
        col("CPU", "Last CPU this task ran on"),
        col(
            "SPRD",
            "Sampled logical CPU / physical-core spread (e.g. 6/3)",
        ),
        col(
            "RES%",
            "Sampled residency on top logical CPU / top physical core",
        ),
        col("SMT%", "Sampled share of runs on non-primary SMT threads"),
        col(
            "COMM color",
            "Heuristic role: GAME / RENDER / UI / AUDIO / BUILD / KCRIT",
        ),
        Line::from(""),
        subsection("── Callback Overhead (ns) ──"),
        col("SELns", "select_cpu callback wall time"),
        col("ENQns", "enqueue callback wall time"),
        col("STOPns", "stopping callback wall time"),
        col("RUNns", "running callback wall time"),
        Line::from(""),
        subsection("── Wake / Placement Shape (%) ──"),
        col("G1%", "Fast local/idle gate hit rate"),
        col("G3%", "Kernel select fallback gate hit rate"),
        col("DSQ%", "Shared DSQ / tunnel fallback rate"),
        col("MIGR/s", "CPU migrations per second"),
        Line::from(""),
        subsection("── Color Semantics ──"),
        col("Green", "Healthy / low latency / good locality"),
        col("Yellow", "Watch value / moderate cost"),
        col("Red", "Poor latency / churn / high callback cost"),
    ];

    let left_paragraph = Paragraph::new(left_text)
        .block(
            Block::default()
                .title(" Matrix Columns ")
                .title_style(
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD),
                )
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Blue))
                .border_type(BorderType::Rounded),
        )
        .wrap(Wrap { trim: false });

    // ═══ RIGHT PANEL: Dump Fields + Units + Keys ═══
    let right_text = vec![
        section("═══ DUMP / COPY FIELDS ═══"),
        Line::from(""),
        subsection("── Unit Conventions ──"),
        col("PELT", "Kernel util_avg raw scale 0-1024"),
        col("...µs", "Task latency/runtime/jitter values"),
        col("...ns", "Callback stopwatch values"),
        col(
            "SPRD",
            "Sampled logical CPU / physical-core spread in the interval",
        ),
        col(
            "RES%",
            "Sampled top logical/top physical residency percentages",
        ),
        col("SMT%", "Sampled residency on SMT secondary threads"),
        col("scope", "Lifetime totals plus rolling 30s/60s windows"),
        col("cap", "Current hard-latency vs soft UI vs build overlap snapshot"),
        col("roles", "Current live role counts from heuristics"),
        Line::from(""),
        subsection("── Per-Callback Stopwatch (ns) ──"),
        col("gate_cas", "select_cpu: full gate cascade duration"),
        col("idle_prb", "select_cpu: winning gate idle probe cost"),
        col("vtime_cm", "enqueue: vtime adjustment overhead"),
        col("mbox", "running: per-CPU mailbox CL0 write burst"),
        col("classify", "reserved legacy timing slot"),
        col("vtime_st", "stopping: dsq_vtime bit packing + write"),
        col("warm", "stopping: warm CPU ring shift (migration)"),
        Line::from(""),
        subsection("── Extended Detail Fields ──"),
        col("ROLE", "Heuristic workload role plus capacity band"),
        col("STEER", "Per-thread home/primary steering hit counters"),
        col("path/place", "Last select path and home-locality outcome"),
        col("waker", "Last waker locality vs chosen CPU"),
        col("deps", "Wake source counts: same TGID / cross TGID"),
        col("DIRECT", "Direct dispatch count (bypassed DSQ)"),
        col("CLS", "Current cake role: KCR / N- / N0 / N+"),
        col("SUTIL", "Slice util % (actual_run / slice)"),
        col("LLC", "Last LLC (L3 cache) node"),
        col("STREAK", "Consecutive same-CPU runs (locality)"),
        col("WHIST", "Wait histogram: <10µ/<100µ/<1m/≥1ms"),
        col("hwait", "Per-task wait by home locality: avg/max/count"),
        Line::from(""),
        section("═══ DASHBOARD SIGNALS ═══"),
        Line::from(""),
        col(
            "Wake<5ms",
            "Avg/max/count split by direct, busy, queued paths",
        ),
        col(
            "CB Hist",
            "How often callbacks stay <1us/<5us plus slow-call count",
        ),
        col(
            "Coherency",
            "Remote idle_hint reads + pending-flag remote sets",
        ),
        col(
            "Capacity",
            "Current hard-latency/build overlap, SMT pressure, scatter",
        ),
        col(
            "Roles",
            "Current mix of build, render, UI, audio, game, kcritical",
        ),
        col("Events", "Recent slow callback / wake-wait outliers"),
        Line::from(""),
        section("═══ KEY BINDINGS ═══"),
        Line::from(""),
        col("←/→ Tab", "Switch tabs"),
        col("↑/↓ j/k", "Scroll task list / navigate"),
        col("s / S", "Cycle sort column / reverse direction"),
        col("+ / -", "Adjust refresh rate"),
        col("f", "Cycle filters: BPF-tracked -> live-only -> all"),
        col("T", "Jump to first task row"),
        col("Enter", "Fold / unfold PPID group"),
        col("Space", "Fold / unfold process thread group"),
        col("x", "Clear folds"),
        col(
            "c",
            "Copy current tab (includes lifetime + 30s/60s windows)",
        ),
        col(
            "d",
            "Dump dashboard to tui_dump_*.txt with lifetime + 30s/60s",
        ),
        col("b", "Run BenchLab benchmark iteration"),
        col("r", "Reset state"),
        col("q / Esc", "Quit scx_cake"),
        Line::from(""),
        subsection("── Scheduler State ──"),
        sub(
            "IDLE",
            "General low-latency mode; detector removed",
            Color::DarkGray,
        ),
    ];

    let right_paragraph = Paragraph::new(right_text)
        .block(
            Block::default()
                .title(" Fields & Keybindings ")
                .title_style(
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD),
                )
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Blue))
                .border_type(BorderType::Rounded),
        )
        .wrap(Wrap { trim: false });

    frame.render_widget(left_paragraph, cols[0]);
    frame.render_widget(right_paragraph, cols[1]);
}

fn draw_bench_tab(frame: &mut Frame, app: &mut TuiApp, area: Rect) {
    // (index, name, category, source: K=kernel kfunc, C=cake custom code)
    // Groups: kfunc baseline first, then cake replacements. SPEED is per-group.
    let bench_items: &[(usize, &str, &str, &str)] = &[
        // Timing: all available clock sources
        (0, "bpf_ktime_get_ns()", "Timing", "K"),
        (1, "scx_bpf_now()", "Timing", "K"),
        (24, "bpf_ktime_get_boot_ns()", "Timing", "K"),
        (10, "Timing harness (cal)", "Timing", "C"),
        // Task Lookup: kfunc vs arena direct access
        (3, "bpf_task_from_pid()", "Task Lookup", "K"),
        (29, "bpf_get_current_task_btf()", "Task Lookup", "K"),
        (36, "bpf_task_storage_get()", "Task Lookup", "K"),
        (6, "get_task_ctx() [arena]", "Task Lookup", "C"),
        (22, "get_task_ctx+arena CL0", "Task Lookup", "C"),
        // Process Info: kfunc alternatives
        (28, "bpf_get_current_pid_tgid()", "Process Info", "K"),
        (30, "bpf_get_current_comm()", "Process Info", "K"),
        (14, "task_struct p->scx+nvcsw", "Process Info", "K"),
        (32, "scx_bpf_task_running(p)", "Process Info", "K"),
        (33, "scx_bpf_task_cpu(p)", "Process Info", "K"),
        (46, "Arena tctx.pid+tgid", "Process Info", "C"),
        (47, "Mbox CL0 cached_cpu", "Process Info", "C"),
        // CPU Identification: kfunc vs mailbox cached
        (2, "bpf_get_smp_proc_id()", "CPU ID", "K"),
        (31, "bpf_get_numa_node_id()", "CPU ID", "K"),
        (11, "Mbox CL0 cached CPU", "CPU ID", "C"),
        // Idle Probing: kfunc vs cake probes
        (4, "test_and_clear_idle()", "Idle Probing", "K"),
        (37, "scx_bpf_pick_idle_cpu()", "Idle Probing", "K"),
        (38, "idle_cpumask get+put", "Idle Probing", "K"),
        (19, "idle_probe(remote) MESI", "Idle Probing", "C"),
        (20, "smtmask read-only check", "Idle Probing", "C"),
        // Data Read: kernel struct vs cake data paths
        (8, "BSS global_stats[cpu]", "Data Read", "C"),
        (9, "Arena per_cpu.mbox", "Data Read", "C"),
        (15, "RODATA llc+quantum_ns", "Data Read", "C"),
        // Mailbox CL0: cake's Disruptor handoff variants
        (12, "Mbox CL0 tctx+deref", "Mailbox CL0", "C"),
        (18, "CL0 ptr+fused+packed", "Mailbox CL0", "C"),
        (21, "Disruptor CL0 full read", "Mailbox CL0", "C"),
        // Composite: cake-only multi-step operations
        (16, "Bitflag shift+mask+brless", "Composite Ops", "C"),
        (17, "(reserved, was compute_ewma)", "Composite Ops", "C"),
        // DVFS / Performance: CPU frequency queries
        (35, "scx_bpf_cpuperf_cur(cpu)", "DVFS / Perf", "K"),
        (42, "scx_bpf_cpuperf_cap(cpu)", "DVFS / Perf", "K"),
        (45, "RODATA cpuperf_cap[cpu]", "DVFS / Perf", "C"),
        // Topology Constants: kfunc vs RODATA
        (5, "scx_bpf_nr_cpu_ids()", "Topology", "K"),
        (34, "scx_bpf_nr_node_ids()", "Topology", "K"),
        (43, "RODATA nr_cpus const", "Topology", "C"),
        (44, "RODATA nr_nodes const", "Topology", "C"),
        // Standalone Kfuncs: reference costs
        (7, "scx_bpf_dsq_nr_queued()", "Standalone Kfuncs", "K"),
        (13, "ringbuf reserve+discard", "Standalone Kfuncs", "K"),
        (39, "scx_bpf_kick_cpu(self)", "Standalone Kfuncs", "K"),
        // Synchronization: lock/RNG costs
        (41, "bpf_spin_lock+unlock", "Synchronization", "K"),
        (40, "bpf_get_prandom_u32()", "Synchronization", "K"),
        (48, "CL0 lock-free 3-field", "Synchronization", "C"),
        (49, "BSS xorshift32 PRNG", "Synchronization", "C"),
        // TLB/Memory: arena access pattern cost
        (23, "Arena stride (TLB/hugepage)", "TLB/Memory", "C"),
        // Kernel Free Data: zero-cost task_struct field reads
        (50, "PELT util+runnable_avg", "Kernel Free Data", "K"),
        (51, "PELT runnable_avg only", "Kernel Free Data", "K"),
        (52, "schedstats nr_wakeups", "Kernel Free Data", "K"),
        (53, "p->policy+prio+flags", "Kernel Free Data", "K"),
        (54, "PELT read+legacy bucket", "Kernel Free Data", "K"),
        // End-to-End Workflow Comparisons
        (55, "task_storage write+read", "Storage Roundtrip", "C"),
        (56, "Arena write+read", "Storage Roundtrip", "C"),
        (57, "3-probe cascade (cake)", "Idle Selection", "C"),
        (58, "pick_idle_cpu full", "Idle Selection", "K"),
        (59, "Weight classify (bpfland)", "Classification", "C"),
        (60, "Lat-cri classify (lavd)", "Classification", "C"),
        (61, "SMT: cake sib probe", "SMT Probing", "C"),
        (62, "SMT: cpumask probe", "SMT Probing", "K"),
        // ═══ Fairness Fixes (cold-cache + remote) ═══
        (63, "storage_get COLD ~est", "Cold Cache", "K"),
        (64, "PELT classify COLD", "Cold Cache", "K"),
        (65, "legacy EWMA COLD", "Cold Cache", "C"),
        (66, "kick_cpu REMOTE ~est", "Cold Cache", "K"),
    ];

    // Pre-compute percentiles: sort once per entry, extract p1/p50/p99 together.
    // Old approach sorted 3× per entry per frame (7200 sorts/sec at 60fps) — killed navigation.
    let percentiles_for = |samples: &[u64]| -> (u64, u64, u64) {
        if samples.is_empty() {
            return (0, 0, 0);
        }
        let mut sorted = samples.to_vec();
        sorted.sort_unstable();
        let len = sorted.len() as f64 - 1.0;
        let p1 = sorted[((1.0 / 100.0 * len).round() as usize).min(sorted.len() - 1)];
        let p50 = sorted[((50.0 / 100.0 * len).round() as usize).min(sorted.len() - 1)];
        let p99 = sorted[((99.0 / 100.0 * len).round() as usize).min(sorted.len() - 1)];
        (p1, p50, p99)
    };

    let age_s = if app.bench_timestamp > 0 {
        let uptime = app.start_time.elapsed().as_nanos() as u64;
        format!(
            "{:.1}s ago",
            (uptime.saturating_sub(app.bench_timestamp)) as f64 / 1e9
        )
    } else {
        "never".to_string()
    };

    let header = Row::new(vec![
        Cell::from("HELPER").style(
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        ),
        Cell::from("MIN").style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Cell::from("P1 LOW").style(
            Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD),
        ),
        Cell::from("P50 MED").style(
            Style::default()
                .fg(Color::LightCyan)
                .add_modifier(Modifier::BOLD),
        ),
        Cell::from("AVG").style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Cell::from("P1 HIGH").style(
            Style::default()
                .fg(Color::LightRed)
                .add_modifier(Modifier::BOLD),
        ),
        Cell::from("MAX").style(Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)),
        Cell::from("JITTER").style(
            Style::default()
                .fg(Color::LightMagenta)
                .add_modifier(Modifier::BOLD),
        ),
        Cell::from("SPEED").style(
            Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        ),
    ])
    .height(1);

    let mut rows: Vec<Row> = Vec::new();
    let mut last_cat = "";
    let mut cat_baseline: u64 = 0; // per-category baseline AVG

    for &(idx, name, cat, src) in bench_items {
        if cat != last_cat {
            last_cat = cat;
            cat_baseline = 0; // reset for new category
            rows.push(
                Row::new(vec![Cell::from(format!("▸ {}", cat)).style(
                    Style::default()
                        .fg(Color::White)
                        .add_modifier(Modifier::BOLD | Modifier::UNDERLINED),
                )])
                .height(1),
            );
        }

        let (min_ns, max_ns, total_ns, _last_val) = app.bench_entries[idx];
        if app.bench_iterations == 0 || total_ns == 0 {
            rows.push(Row::new(vec![
                Cell::from(format!("  [{}] {}", src, name))
                    .style(Style::default().fg(Color::DarkGray)),
                Cell::from("--"),
                Cell::from("--"),
                Cell::from("--"),
                Cell::from("--"),
                Cell::from("--"),
                Cell::from("--"),
                Cell::from("--"),
                Cell::from("--"),
            ]));
            continue;
        }

        let avg_ns = total_ns / app.bench_iterations as u64;
        let samples = &app.bench_samples[idx];
        let (p1, p50, p99) = percentiles_for(samples);
        let jitter = max_ns.saturating_sub(min_ns);

        let speedup = if cat_baseline == 0 {
            cat_baseline = avg_ns.max(1);
            "base".to_string()
        } else if avg_ns > 0 {
            format!("{:.1}×", cat_baseline as f64 / avg_ns as f64)
        } else {
            "--".to_string()
        };

        // Color: green if faster than baseline, yellow if comparable, white otherwise
        let color = if cat_baseline == avg_ns || cat_baseline == 0 {
            Color::Yellow // baseline entry
        } else if avg_ns < cat_baseline / 2 {
            Color::Green // >2× faster
        } else if avg_ns < cat_baseline {
            Color::Cyan // faster
        } else {
            Color::White // slower or same
        };

        rows.push(Row::new(vec![
            Cell::from(format!("  [{}] {}", src, name)).style(Style::default().fg(color)),
            Cell::from(format!("{}ns", min_ns)).style(Style::default().fg(Color::Cyan)),
            Cell::from(format!("{}ns", p1)).style(Style::default().fg(Color::Green)),
            Cell::from(format!("{}ns", p50)).style(Style::default().fg(Color::LightCyan)),
            Cell::from(format!("{}ns", avg_ns)).style(Style::default().fg(color)),
            Cell::from(format!("{}ns", p99)).style(Style::default().fg(Color::LightRed)),
            Cell::from(format!("{}ns", max_ns)).style(Style::default().fg(Color::Red)),
            Cell::from(format!("{}ns", jitter)).style(Style::default().fg(Color::LightMagenta)),
            Cell::from(speedup).style(Style::default().fg(Color::White)),
        ]));
    }

    let table = Table::new(
        rows,
        [
            Constraint::Length(34), // Name
            Constraint::Length(8),  // MIN
            Constraint::Length(8),  // P1 LOW
            Constraint::Length(9),  // P50 MED
            Constraint::Length(8),  // AVG
            Constraint::Length(9),  // P1 HIGH
            Constraint::Length(8),  // MAX
            Constraint::Length(10), // JITTER
            Constraint::Length(7),  // SPEED
        ],
    )
    .header(header)
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::DarkGray))
            .border_type(BorderType::Rounded)
            .title(ratatui::text::Span::styled(
                format!(
                    " ⚡ BenchLab  [b=run]  Runs: {}  Samples: {}  CPU: {}  Ran: {} ",
                    app.bench_run_count, app.bench_iterations, app.bench_cpu, age_s
                ),
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            )),
    )
    .row_highlight_style(Style::default().add_modifier(Modifier::REVERSED))
    .highlight_symbol(">> ");

    // Split area into header and table
    let bench_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(7), // System Info Header (6 lines + 1 padding)
            Constraint::Min(0),    // Bench table
        ])
        .split(area);

    let info_text = app.system_info.format_header();
    let info_paragraph = Paragraph::new(info_text)
        .style(Style::default().fg(Color::DarkGray))
        .block(Block::default().padding(Padding::new(1, 1, 0, 1)));

    frame.render_widget(info_paragraph, bench_layout[0]);
    frame.render_stateful_widget(table, bench_layout[1], &mut app.bench_table_state);
}

/// Run a core-to-core latency benchmark using atomic ping-pong.
/// Hot loop uses only `wrapping_add(1)` — no multiply or checked add —
/// so debug builds don't inflate measurements with overflow checks.
/// Runs 3 attempts per pair with warmup, takes the minimum.
fn run_core_latency_bench(nr_cpus: usize) -> Vec<Vec<f64>> {
    let mut matrix = vec![vec![0.0f64; nr_cpus]; nr_cpus];
    const ITERATIONS: u64 = 5000;
    const WARMUP: u64 = 500;
    const RUNS: usize = 3;

    #[allow(clippy::needless_range_loop)]
    for i in 0..nr_cpus {
        for j in (i + 1)..nr_cpus {
            let mut best = f64::MAX;

            for _run in 0..RUNS {
                let flag = Arc::new(AtomicU64::new(0));
                let flag_a = flag.clone();
                let flag_b = flag.clone();
                let core_a = i;
                let core_b = j;

                // Thread A: pinger
                let handle_a = thread::spawn(move || {
                    unsafe {
                        let mut set: libc::cpu_set_t = std::mem::zeroed();
                        libc::CPU_SET(core_a, &mut set);
                        libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &set);
                    }

                    // Warmup — same code path as measurement, just uncounted
                    let mut val = 0u64;
                    for _ in 0..WARMUP {
                        val = val.wrapping_add(1); // odd: ping
                        flag_a.store(val, Ordering::Release);
                        val = val.wrapping_add(1); // even: expect pong
                        while flag_a.load(Ordering::Acquire) != val {
                            std::hint::spin_loop();
                        }
                    }

                    // Measured run — zero arithmetic in hot path
                    let start = std::time::Instant::now();
                    for _ in 0..ITERATIONS {
                        val = val.wrapping_add(1);
                        flag_a.store(val, Ordering::Release);
                        val = val.wrapping_add(1);
                        while flag_a.load(Ordering::Acquire) != val {
                            std::hint::spin_loop();
                        }
                    }
                    start.elapsed().as_nanos() as f64 / ITERATIONS as f64
                });

                // Thread B: ponger
                let handle_b = thread::spawn(move || {
                    unsafe {
                        let mut set: libc::cpu_set_t = std::mem::zeroed();
                        libc::CPU_SET(core_b, &mut set);
                        libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &set);
                    }

                    let mut val = 0u64;
                    // Warmup
                    for _ in 0..WARMUP {
                        val = val.wrapping_add(1); // odd: expect ping
                        while flag_b.load(Ordering::Acquire) != val {
                            std::hint::spin_loop();
                        }
                        val = val.wrapping_add(1); // even: pong
                        flag_b.store(val, Ordering::Release);
                    }

                    // Measured run
                    for _ in 0..ITERATIONS {
                        val = val.wrapping_add(1);
                        while flag_b.load(Ordering::Acquire) != val {
                            std::hint::spin_loop();
                        }
                        val = val.wrapping_add(1);
                        flag_b.store(val, Ordering::Release);
                    }
                });

                let latency_ns = handle_a.join().unwrap_or(f64::MAX);
                let _ = handle_b.join();
                if latency_ns < best {
                    best = latency_ns;
                }
            }

            // Each round-trip = 2 hops, one-way = half
            let one_way = best / 2.0;
            matrix[i][j] = one_way;
            matrix[j][i] = one_way;
        }
    }
    matrix
}

/// Run the TUI event loop
pub fn run_tui(
    skel: &mut BpfSkel,
    shutdown: Arc<AtomicBool>,
    interval_secs: u64,
    topology: TopologyInfo,
    latency_matrix: Vec<Vec<f64>>,
) -> Result<()> {
    let mut terminal = setup_terminal()?;
    let mut app = TuiApp::new(topology, latency_matrix);
    let mut tick_rate = Duration::from_secs(interval_secs);
    let debug_events = Arc::new(Mutex::new(VecDeque::with_capacity(32)));
    let mut debug_ringbuf = {
        let queue = debug_events.clone();
        let mut builder = libbpf_rs::RingBufferBuilder::new();
        builder
            .add(&skel.maps.debug_ringbuf, move |data: &[u8]| {
                if data.len() < std::mem::size_of::<cake_debug_event>() {
                    return 0;
                }
                let ev = unsafe { *(data.as_ptr() as *const cake_debug_event) };
                push_debug_event(
                    &queue,
                    DebugEventRow {
                        ts_ns: ev.ts_ns,
                        value_ns: ev.value_ns,
                        pid: ev.pid,
                        aux: ev.aux,
                        cpu: ev.cpu,
                        kind: ev.kind,
                        slot: ev.slot,
                        comm: cstr_comm(&ev.comm),
                    },
                );
                0
            })
            .context("failed to add debug ringbuf callback")?;
        Some(builder.build().context("failed to build debug ringbuf")?)
    };
    // Backdate last_tick so the first loop instantly populates the matrix
    let mut last_tick = Instant::now()
        .checked_sub(tick_rate)
        .unwrap_or(Instant::now());

    // Initialize clipboard (may fail on headless systems)
    let mut clipboard = Clipboard::new().ok();

    loop {
        // Check for shutdown signal
        if shutdown.load(Ordering::Relaxed) {
            break;
        }

        // Check for UEI exit
        if scx_utils::uei_exited!(skel, uei) {
            break;
        }

        if let Some(rb) = debug_ringbuf.as_mut() {
            let _ = rb.consume();
        }
        if let Ok(queue) = debug_events.lock() {
            app.debug_events = queue.clone();
        }

        // Get current stats (aggregate from per-cpu BSS array)
        let stats = aggregate_stats(skel);

        // Read bench results from BSS (for BenchLab tab)
        if let Some(bss) = &skel.maps.bss_data {
            let br = &bss.bench_results;
            if br.bench_timestamp > 0 && br.bench_timestamp != app.last_bench_timestamp {
                // New bench results — accumulate (merge min/max, sum totals)
                app.last_bench_timestamp = br.bench_timestamp;
                app.bench_cpu = br.cpu;
                app.bench_run_count += 1;
                app.bench_timestamp = br.bench_timestamp;
                for i in 0..67 {
                    let new_min = br.entries[i].min_ns;
                    let new_max = br.entries[i].max_ns;
                    let new_total = br.entries[i].total_ns;
                    let new_value = br.entries[i].last_value;
                    let (old_min, old_max, old_total, _) = app.bench_entries[i];
                    app.bench_entries[i] = (
                        if app.bench_run_count == 1 {
                            new_min
                        } else {
                            old_min.min(new_min)
                        },
                        old_max.max(new_max),
                        old_total + new_total,
                        new_value,
                    );
                    // Accumulate raw samples for percentile computation
                    for s in 0..8 {
                        let sample = br.entries[i].samples[s];
                        if sample > 0 {
                            app.bench_samples[i].push(sample);
                        }
                    }
                }
                app.bench_iterations += br.iterations;
            }
        }

        // Poll for core-to-core latency benchmark completion
        if let Some(handle) = app.bench_latency_handle.take() {
            if handle.is_finished() {
                match handle.join() {
                    Ok(matrix) => {
                        app.latency_matrix = matrix;
                        app.set_status("✓ Core-to-core latency benchmark complete");
                    }
                    Err(_) => {
                        app.set_status("✗ Latency benchmark failed");
                    }
                }
            } else {
                // Not done yet, put it back
                app.bench_latency_handle = Some(handle);
            }
        }

        // Draw UI
        terminal.draw(|frame| draw_ui(frame, &mut app, &stats))?;

        // Handle events with timeout
        let timeout = tick_rate.saturating_sub(last_tick.elapsed());
        if event::poll(timeout)? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press {
                    match key.code {
                        KeyCode::Char('q') | KeyCode::Esc => {
                            shutdown.store(true, Ordering::Relaxed);
                            break;
                        }
                        KeyCode::Enter => {
                            // Toggle collapse/expand for selected row's PPID group
                            if app.active_tab == TuiTab::Dashboard {
                                if let Some(i) = app.table_state.selected() {
                                    if let Some(pid) = app.sorted_pids.get(i) {
                                        if let Some(row) = app.task_rows.get(pid) {
                                            let ppid = row.ppid;
                                            if ppid > 0 {
                                                if app.collapsed_ppids.contains(&ppid) {
                                                    app.collapsed_ppids.remove(&ppid);
                                                } else {
                                                    app.collapsed_ppids.insert(ppid);
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        KeyCode::Tab | KeyCode::Right => {
                            app.next_tab();
                        }
                        KeyCode::BackTab | KeyCode::Left => {
                            app.previous_tab();
                        }
                        KeyCode::Down | KeyCode::PageDown => match app.active_tab {
                            TuiTab::BenchLab => app.scroll_bench_down(),
                            _ => app.scroll_table_down(),
                        },
                        KeyCode::Up | KeyCode::PageUp => match app.active_tab {
                            TuiTab::BenchLab => app.scroll_bench_up(),
                            _ => app.scroll_table_up(),
                        },
                        KeyCode::Char('t') | KeyCode::Char('T')
                            if key.modifiers.is_empty()
                                || key.modifiers == crossterm::event::KeyModifiers::SHIFT =>
                        {
                            match app.active_tab {
                                TuiTab::BenchLab => app.bench_table_state.select(Some(0)),
                                _ => app.table_state.select(Some(0)),
                            }
                        }
                        KeyCode::Char(' ') => {
                            // Toggle collapse/expand for selected row's TGID group
                            if app.active_tab == TuiTab::Dashboard {
                                if let Some(i) = app.table_state.selected() {
                                    if let Some(pid) = app.sorted_pids.get(i) {
                                        if let Some(row) = app.task_rows.get(pid) {
                                            let tgid = if row.tgid > 0 { row.tgid } else { *pid };
                                            if app.collapsed_tgids.contains(&tgid) {
                                                app.collapsed_tgids.remove(&tgid);
                                            } else {
                                                app.collapsed_tgids.insert(tgid);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        KeyCode::Char('x') => {
                            // Toggle fold all: collapse all PPIDs, or expand all if already collapsed
                            if app.active_tab == TuiTab::Dashboard {
                                if app.collapsed_ppids.is_empty() {
                                    // Collapse all — collect all unique PPIDs
                                    let ppids: Vec<u32> = app
                                        .task_rows
                                        .values()
                                        .filter(|r| r.ppid > 0)
                                        .map(|r| r.ppid)
                                        .collect();
                                    for ppid in ppids {
                                        app.collapsed_ppids.insert(ppid);
                                    }
                                    app.set_status("Folded all PPID groups");
                                } else {
                                    app.collapsed_ppids.clear();
                                    app.set_status("Unfolded all PPID groups");
                                }
                            }
                        }
                        KeyCode::Char('s') => {
                            app.cycle_sort();
                        }
                        KeyCode::Char('S') => {
                            app.sort_descending = !app.sort_descending;
                            let dir = if app.sort_descending {
                                "descending"
                            } else {
                                "ascending"
                            };
                            app.set_status(&format!("Sort: {}", dir));
                        }
                        KeyCode::Char('+') | KeyCode::Char('=') => {
                            // Faster refresh: halve tick_rate (min 250ms)
                            let current_ms = tick_rate.as_millis() as u64;
                            if current_ms > 250 {
                                tick_rate = Duration::from_millis(current_ms / 2);
                                app.set_status(&format!("Refresh: {}ms", tick_rate.as_millis()));
                            }
                        }
                        KeyCode::Char('-') => {
                            // Slower refresh: double tick_rate (max 5s)
                            let current_ms = tick_rate.as_millis() as u64;
                            if current_ms < 5000 {
                                tick_rate = Duration::from_millis(current_ms * 2);
                                app.set_status(&format!("Refresh: {}ms", tick_rate.as_millis()));
                            }
                        }
                        KeyCode::Char('c') => {
                            // Copy ACTIVE TAB data to clipboard (tab-aware)
                            let text = match app.active_tab {
                                TuiTab::BenchLab => format_bench_for_clipboard(&app),
                                _ => format_stats_for_clipboard(&stats, &app),
                            };
                            match &mut clipboard {
                                Some(cb) => match cb.set_text(text) {
                                    Ok(_) => app.set_status(&format!(
                                        "✓ Copied {:?} tab to clipboard!",
                                        app.active_tab
                                    )),
                                    Err(_) => app.set_status("✗ Failed to copy"),
                                },
                                None => app.set_status("✗ Clipboard not available"),
                            }
                        }
                        KeyCode::Char('d') => {
                            // Dump full snapshot to timestamped file
                            let text = format_stats_for_clipboard(&stats, &app);
                            let secs = std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .unwrap_or_default()
                                .as_secs();
                            let filename = format!("tui_dump_{}.txt", secs);
                            match std::fs::write(&filename, &text) {
                                Ok(_) => app.set_status(&format!("✓ Dumped to {}", filename)),
                                Err(e) => app.set_status(&format!("✗ Dump failed: {}", e)),
                            }
                        }
                        KeyCode::Char('r') => {
                            // Reset stats (clear the BSS array)
                            if let Some(bss) = &mut skel.maps.bss_data {
                                for s in &mut bss.global_stats {
                                    *s = Default::default();
                                }
                                app.stats_history.clear();
                                app.set_status("✓ Stats reset");
                            }
                        }
                        KeyCode::Char('b') => {
                            if app.active_tab == TuiTab::Topology
                                && app.bench_latency_handle.is_none()
                            {
                                // Core-to-core latency benchmark (Topology tab)
                                let nr_cpus = app.topology.nr_cpus;
                                app.bench_latency_handle =
                                    Some(thread::spawn(move || run_core_latency_bench(nr_cpus)));
                                app.set_status("⏱ Running core-to-core latency benchmark...");
                            } else if app.active_tab != TuiTab::Topology {
                                // Trigger kfunc benchmark (BenchLab)
                                if let Some(bss) = &mut skel.maps.bss_data {
                                    bss.bench_request = 1;
                                    app.set_status(&format!(
                                        "⚡ BenchLab: run #{} queued...",
                                        app.bench_run_count + 1
                                    ));
                                }
                            }
                        }
                        KeyCode::Char('f') => {
                            app.toggle_filter();
                            app.set_status(&format!("Filter: {}", app.task_filter.label()));
                        }
                        _ => {}
                    }
                }
            }
        }

        if last_tick.elapsed() >= tick_rate {
            // Skip dashboard updates while c2c benchmark is running —
            // avoids BPF map reads and sysinfo polls that could create noise
            if app.bench_latency_handle.is_some() {
                last_tick = std::time::Instant::now();
                terminal.draw(|frame| draw_ui(frame, &mut app, &Default::default()))?;
                continue;
            }
            // Hardware Poll Vector
            app.sys.refresh_cpu_usage();
            app.sys
                .refresh_processes(sysinfo::ProcessesToUpdate::All, true);
            app.components.refresh(true);

            // Map thermals by sorting them (assuming matching logical order, or picking the best reading per CPU)
            // On AMD/Intel, core temps usually align with `core_id`. Let's grab Tdie or Core X temps.
            let mut temp_map: HashMap<usize, f32> = HashMap::new();
            for comp in &app.components {
                let name = comp.label().to_lowercase();
                if name.contains("core") || name.contains("tctl") || name.contains("cpu") {
                    // Try to extract core number (e.g. "core 0" or "Tctl")
                    if let Some(core_id) = name
                        .split_whitespace()
                        .next_back()
                        .and_then(|s| s.parse::<usize>().ok())
                    {
                        if let Some(temp) = comp.temperature() {
                            temp_map.insert(core_id, temp);
                        }
                    } else if temp_map.is_empty() {
                        // If we can't parse core ID, stash a global fallback temp at ID 0
                        if let Some(temp) = comp.temperature() {
                            temp_map.insert(0, temp);
                        }
                    }
                }
            }

            for (i, cpu) in app.sys.cpus().iter().enumerate() {
                if i < app.topology.nr_cpus {
                    let load = cpu.cpu_usage();
                    // If per-core temp is missing, fallback to 0 (global) or 0.0
                    let temp = temp_map
                        .get(&(i / 2))
                        .copied()
                        .or_else(|| temp_map.get(&0).copied())
                        .unwrap_or(0.0);
                    app.cpu_stats[i] = (load, temp);
                }
            }

            // --- Attach cake_task_iter BPF iterator (once, at first tick) ---
            // cake_task_iter is SEC("iter/task") — no map_fd needed.
            // We store the raw *mut bpf_link as usize in a static to avoid lifetime issues.
            // bpf_program__attach_iter(prog, NULL) → *mut bpf_link (NULL = task iter, no map).
            static mut TASK_ITER_LINK_RAW: usize = 0; // 0 = uninit, 1 = failed, else ptr
            if unsafe { TASK_ITER_LINK_RAW } == 0 {
                // AsRawLibbpf trait: as_libbpf_object() → NonNull<bpf_program> → .as_ptr()
                use libbpf_rs::AsRawLibbpf;
                let link_ptr = unsafe {
                    libbpf_rs::libbpf_sys::bpf_program__attach_iter(
                        skel.progs.cake_task_iter.as_libbpf_object().as_ptr(),
                        std::ptr::null(),
                    )
                };
                unsafe {
                    TASK_ITER_LINK_RAW = if link_ptr.is_null() {
                        1 // sentinel: attach failed, don't retry
                    } else {
                        link_ptr as usize
                    };
                }
            }

            // --- Arena Telemetry Sweep (via cake_task_iter bpf_iter_task) ---
            // Track currently active PIDs in this sweep to prune dead tasks
            app.active_pids_buf.clear();

            let link_raw = unsafe { TASK_ITER_LINK_RAW };
            if link_raw > 1 {
                // bpf_iter_create(link_fd: c_int) — get fd from the stored *mut bpf_link
                let link_fd_c = unsafe {
                    libbpf_rs::libbpf_sys::bpf_link__fd(
                        link_raw as *mut libbpf_rs::libbpf_sys::bpf_link,
                    )
                };
                let iter_fd = unsafe { libbpf_rs::libbpf_sys::bpf_iter_create(link_fd_c) };
                if iter_fd >= 0 {
                    // Read cake_iter_record structs sequentially from the iter fd
                    use std::os::unix::io::FromRawFd;
                    let mut f = unsafe { std::fs::File::from_raw_fd(iter_fd) };
                    let rec_size = std::mem::size_of::<crate::bpf_intf::cake_iter_record>();
                    let mut buf = vec![0u8; rec_size];
                    use std::io::Read;
                    while f.read_exact(&mut buf).is_ok() {
                        let rec: crate::bpf_intf::cake_iter_record =
                            unsafe { std::ptr::read_unaligned(buf.as_ptr() as *const _) };

                        let pid = rec.telemetry.pid_inner;
                        let ppid = rec.ppid;
                        let packed = rec.packed_info;
                        let is_kcritical = ((packed >> 23) & 1) != 0;

                        if pid == 0 {
                            continue;
                        }

                        app.active_pids_buf.insert(pid);

                        let comm_bytes: [u8; 16] =
                            unsafe { std::mem::transmute(rec.telemetry.comm) };
                        let comm = match std::ffi::CStr::from_bytes_until_nul(&comm_bytes) {
                            Ok(c) => c.to_string_lossy().into_owned(),
                            Err(_) => String::from_utf8_lossy(&comm_bytes)
                                .trim_end_matches('\0')
                                .to_string(),
                        };
                        let pelt_util = rec.pelt_util as u32;

                        let g1 = rec.telemetry.gate_1_hits;
                        let g2 = rec.telemetry.gate_2_hits;
                        let g1w = rec.telemetry.gate_1w_hits;
                        let g3 = rec.telemetry.gate_3_hits;
                        let g1p = rec.telemetry.gate_1p_hits;
                        let g1c = rec.telemetry.gate_1c_hits;
                        let g1cp = rec.telemetry.gate_1cp_hits;
                        let g1d = rec.telemetry.gate_1d_hits;
                        let g1wc = rec.telemetry.gate_1wc_hits;
                        let g5 = rec.telemetry.gate_tun_hits;
                        let total_sel = g1 + g2 + g1w + g3 + g1p + g1c + g1cp + g1d + g1wc + g5;
                        let gate_hit_pcts = if total_sel > 0 {
                            [
                                (g1 as f64 / total_sel as f64) * 100.0,
                                (g2 as f64 / total_sel as f64) * 100.0,
                                (g1w as f64 / total_sel as f64) * 100.0,
                                (g3 as f64 / total_sel as f64) * 100.0,
                                (g1p as f64 / total_sel as f64) * 100.0,
                                (g1c as f64 / total_sel as f64) * 100.0,
                                (g1cp as f64 / total_sel as f64) * 100.0,
                                (g1d as f64 / total_sel as f64) * 100.0,
                                (g1wc as f64 / total_sel as f64) * 100.0,
                                (g5 as f64 / total_sel as f64) * 100.0,
                            ]
                        } else {
                            [0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0]
                        };
                        let total_runs = rec.telemetry.total_runs;
                        let jitter_accum_ns = rec.telemetry.jitter_accum_ns;

                        let row = app
                            .task_rows
                            .entry(pid)
                            .or_insert_with(|| TaskTelemetryRow {
                                pid,
                                comm: comm.clone(),
                                pelt_util,
                                wait_duration_ns: rec.telemetry.wait_duration_ns,
                                select_cpu_ns: rec.telemetry.select_cpu_duration_ns,
                                enqueue_ns: rec.telemetry.enqueue_duration_ns,
                                gate_hit_pcts,
                                home_steer_hits: rec.telemetry.gate_1c_hits,
                                primary_steer_hits: rec.telemetry.gate_1cp_hits,
                                core_placement: rec.telemetry.core_placement,
                                dsq_insert_ns: rec.telemetry.dsq_insert_ns,
                                migration_count: rec.telemetry.migration_count,
                                preempt_count: rec.telemetry.preempt_count,
                                yield_count: rec.telemetry.yield_count,
                                total_runs,
                                jitter_accum_ns,
                                direct_dispatch_count: rec.telemetry.direct_dispatch_count,
                                cpumask_change_count: rec.telemetry.cpumask_change_count,
                                stopping_duration_ns: rec.telemetry.stopping_duration_ns,
                                running_duration_ns: rec.telemetry.running_duration_ns,
                                max_runtime_us: rec.telemetry.max_runtime_us,
                                dispatch_gap_us: rec.telemetry.dispatch_gap_ns / 1000,
                                max_dispatch_gap_us: rec.telemetry.max_dispatch_gap_ns / 1000,
                                wait_hist: [
                                    rec.telemetry.wait_hist_lt10us,
                                    rec.telemetry.wait_hist_lt100us,
                                    rec.telemetry.wait_hist_lt1ms,
                                    rec.telemetry.wait_hist_ge1ms,
                                ],
                                runs_per_sec: 0.0,
                                migrations_per_sec: 0.0,
                                status: TaskStatus::Alive,
                                is_bpf_tracked: true,
                                tgid: rec.telemetry.tgid,
                                slice_util_pct: rec.telemetry.slice_util_pct,
                                llc_id: rec.telemetry.llc_id,
                                llc_run_mask: rec.telemetry.llc_run_mask,
                                same_cpu_streak: rec.telemetry.same_cpu_streak,
                                wakeup_source_pid: rec.telemetry.wakeup_source_pid,
                                nvcsw_delta: rec.telemetry.nvcsw_delta,
                                nivcsw_delta: rec.telemetry.nivcsw_delta,
                                _pad_recomp: rec.telemetry._pad_recomp,
                                is_kcritical,
                                ppid,
                                gate_cascade_ns: rec.telemetry.gate_cascade_ns,
                                idle_probe_ns: rec.telemetry.idle_probe_ns,
                                vtime_compute_ns: rec.telemetry.vtime_compute_ns,
                                mbox_staging_ns: rec.telemetry.mbox_staging_ns,
                                _pad_ewma: rec.telemetry._pad_ewma,
                                legacy_classify_ns: rec.telemetry.legacy_classify_ns,
                                vtime_staging_ns: rec.telemetry.vtime_staging_ns,
                                warm_history_ns: rec.telemetry.warm_history_ns,
                                quantum_full_count: rec.telemetry.quantum_full_count,
                                quantum_yield_count: rec.telemetry.quantum_yield_count,
                                quantum_preempt_count: rec.telemetry.quantum_preempt_count,
                                waker_cpu: rec.telemetry.waker_cpu,
                                waker_tgid: rec.telemetry.waker_tgid,
                                wake_reason_wait_ns: rec.telemetry.wake_reason_wait_ns,
                                wake_reason_count: rec.telemetry.wake_reason_count,
                                wake_reason_max_us: rec.telemetry.wake_reason_max_us,
                                last_select_path: rec.telemetry.last_select_path,
                                last_place_class: rec.telemetry.last_place_class,
                                last_waker_place_class: rec.telemetry.last_waker_place_class,
                                wake_same_tgid_count: rec.telemetry.wake_same_tgid_count,
                                wake_cross_tgid_count: rec.telemetry.wake_cross_tgid_count,
                                home_place_wait_ns: rec.telemetry.home_place_wait_ns,
                                home_place_wait_count: rec.telemetry.home_place_wait_count,
                                home_place_wait_max_us: rec.telemetry.home_place_wait_max_us,
                                cpu_run_count: rec.telemetry.cpu_run_count,
                                task_weight: rec.task_weight,
                            });

                        // Update dynamic row elements
                        row.pelt_util = pelt_util;
                        row.wait_duration_ns = rec.telemetry.wait_duration_ns;
                        row.select_cpu_ns = rec.telemetry.select_cpu_duration_ns;
                        row.enqueue_ns = rec.telemetry.enqueue_duration_ns;
                        row.gate_hit_pcts = gate_hit_pcts;
                        row.home_steer_hits = rec.telemetry.gate_1c_hits;
                        row.primary_steer_hits = rec.telemetry.gate_1cp_hits;
                        row.core_placement = rec.telemetry.core_placement;
                        row.dsq_insert_ns = rec.telemetry.dsq_insert_ns;
                        row.migration_count = rec.telemetry.migration_count;
                        row.preempt_count = rec.telemetry.preempt_count;
                        row.yield_count = rec.telemetry.yield_count;
                        row.total_runs = total_runs;
                        row.jitter_accum_ns = jitter_accum_ns;
                        row.direct_dispatch_count = rec.telemetry.direct_dispatch_count;
                        row.cpumask_change_count = rec.telemetry.cpumask_change_count;
                        row.stopping_duration_ns = rec.telemetry.stopping_duration_ns;
                        row.running_duration_ns = rec.telemetry.running_duration_ns;
                        row.max_runtime_us = rec.telemetry.max_runtime_us;
                        row.dispatch_gap_us = rec.telemetry.dispatch_gap_ns / 1000;
                        row.max_dispatch_gap_us = rec.telemetry.max_dispatch_gap_ns / 1000;
                        row.wait_hist = [
                            rec.telemetry.wait_hist_lt10us,
                            rec.telemetry.wait_hist_lt100us,
                            rec.telemetry.wait_hist_lt1ms,
                            rec.telemetry.wait_hist_ge1ms,
                        ];
                        row.is_bpf_tracked = true;
                        row.slice_util_pct = rec.telemetry.slice_util_pct;
                        row.llc_id = rec.telemetry.llc_id;
                        row.llc_run_mask = rec.telemetry.llc_run_mask;
                        row.same_cpu_streak = rec.telemetry.same_cpu_streak;
                        row.wakeup_source_pid = rec.telemetry.wakeup_source_pid;
                        row._pad_recomp = rec.telemetry._pad_recomp;
                        row.is_kcritical = is_kcritical;
                        row.ppid = ppid;
                        row.task_weight = rec.task_weight;
                        row.gate_cascade_ns = rec.telemetry.gate_cascade_ns;
                        row.idle_probe_ns = rec.telemetry.idle_probe_ns;
                        row.vtime_compute_ns = rec.telemetry.vtime_compute_ns;
                        row.mbox_staging_ns = rec.telemetry.mbox_staging_ns;
                        row._pad_ewma = rec.telemetry._pad_ewma;
                        row.legacy_classify_ns = rec.telemetry.legacy_classify_ns;
                        row.vtime_staging_ns = rec.telemetry.vtime_staging_ns;
                        row.warm_history_ns = rec.telemetry.warm_history_ns;
                        row.quantum_full_count = rec.telemetry.quantum_full_count;
                        row.quantum_yield_count = rec.telemetry.quantum_yield_count;
                        row.quantum_preempt_count = rec.telemetry.quantum_preempt_count;
                        row.waker_cpu = rec.telemetry.waker_cpu;
                        row.waker_tgid = rec.telemetry.waker_tgid;
                        row.wake_reason_wait_ns = rec.telemetry.wake_reason_wait_ns;
                        row.wake_reason_count = rec.telemetry.wake_reason_count;
                        row.wake_reason_max_us = rec.telemetry.wake_reason_max_us;
                        row.last_select_path = rec.telemetry.last_select_path;
                        row.last_place_class = rec.telemetry.last_place_class;
                        row.last_waker_place_class = rec.telemetry.last_waker_place_class;
                        row.wake_same_tgid_count = rec.telemetry.wake_same_tgid_count;
                        row.wake_cross_tgid_count = rec.telemetry.wake_cross_tgid_count;
                        row.home_place_wait_ns = rec.telemetry.home_place_wait_ns;
                        row.home_place_wait_count = rec.telemetry.home_place_wait_count;
                        row.home_place_wait_max_us = rec.telemetry.home_place_wait_max_us;
                        row.cpu_run_count = rec.telemetry.cpu_run_count;
                    } // end read loop
                      // f drops here, closing the iter fd automatically
                } // end if iter_fd >= 0
            } // end if link_ptr > 0

            // --- Inject ALL System PIDs (Fallback) ---
            // Ensures visibility for PIDs that never triggered cake_init_task
            let sysinfo_pids: std::collections::HashSet<u32> =
                app.sys.processes().keys().map(|p| p.as_u32()).collect();

            for (pid, process) in app.sys.processes() {
                let pid_u32 = pid.as_u32();
                app.task_rows
                    .entry(pid_u32)
                    .or_insert_with(|| TaskTelemetryRow {
                        pid: pid_u32,
                        comm: process.name().to_string_lossy().to_string(),
                        ..Default::default()
                    });
            }

            // --- Liveness Detection: cross-reference arena with sysinfo ---
            let mut bpf_count = 0usize;
            for (pid, row) in app.task_rows.iter_mut() {
                let in_sysinfo = sysinfo_pids.contains(pid);
                row.status = if row.is_bpf_tracked && in_sysinfo {
                    TaskStatus::Alive
                } else if in_sysinfo {
                    TaskStatus::Idle
                } else {
                    TaskStatus::Dead
                };
                if row.is_bpf_tracked && row.total_runs > 0 {
                    bpf_count += 1;
                }
            }
            app.bpf_task_count = bpf_count;

            // --- Delta Mode: compute per-second rates ---
            let actual_elapsed = last_tick.elapsed().as_secs_f64().max(0.1);
            for (pid, row) in app.task_rows.iter_mut() {
                if let Some(&(prev_runs, prev_migr)) = app.prev_deltas.get(pid) {
                    let d_runs = row.total_runs.saturating_sub(prev_runs);
                    let d_migr = row.migration_count.saturating_sub(prev_migr);
                    row.runs_per_sec = d_runs as f64 / actual_elapsed;
                    row.migrations_per_sec = d_migr as f64 / actual_elapsed;
                }
            }
            // Lightweight delta snapshot: only (total_runs, migration_count)
            // Eliminates ~500 String allocs/drops per tick from deep-cloning task_rows
            app.prev_deltas.clear();
            for (pid, row) in app.task_rows.iter() {
                app.prev_deltas
                    .insert(*pid, (row.total_runs, row.migration_count));
            }

            // --- Arena diagnostics ---
            app.arena_max = 0; // arena max not tracked via iter path
            app.arena_active = app.active_pids_buf.len();

            /* EXPLICITLY DISABLED: Dead Tasks are no longer removed so users can view
             * the absolute hardware scheduling history of all tasks on the system.
             * app.task_rows.retain(|pid, _| active_pids.contains(pid)); */

            // Re-sort with smart ordering:
            //   - Primary: BPF-tracked (is_bpf_tracked) descending
            //   - Secondary: current sort column
            //   - Dead tasks always last
            let mut sorted_pids: Vec<u32> = match app.task_filter {
                TaskFilter::AllTasks => app.task_rows.keys().copied().collect(),
                TaskFilter::LiveOnly => app
                    .task_rows
                    .iter()
                    .filter(|(_, row)| row.status == TaskStatus::Alive)
                    .map(|(pid, _)| *pid)
                    .collect(),
                TaskFilter::BpfTracked => app
                    .task_rows
                    .iter()
                    .filter(|(_, row)| row.is_bpf_tracked && row.total_runs > 0)
                    .map(|(pid, _)| *pid)
                    .collect(),
            };
            // Apply sort with direction support
            let desc = app.sort_descending;
            match app.sort_column {
                SortColumn::Pid => sorted_pids.sort_by(|a, b| {
                    let cmp = a.cmp(b);
                    if desc {
                        cmp.reverse()
                    } else {
                        cmp
                    }
                }),
                SortColumn::Pelt => sorted_pids.sort_by(|a, b| {
                    let r_a = app.task_rows.get(a).unwrap();
                    let r_b = app.task_rows.get(b).unwrap();
                    let cmp = r_b.pelt_util.cmp(&r_a.pelt_util);
                    if desc {
                        cmp
                    } else {
                        cmp.reverse()
                    }
                }),
                SortColumn::MaxRuntime => sorted_pids.sort_by(|a, b| {
                    let r_a = app.task_rows.get(a).unwrap();
                    let r_b = app.task_rows.get(b).unwrap();
                    let cmp = r_b.max_runtime_us.cmp(&r_a.max_runtime_us);
                    if desc {
                        cmp
                    } else {
                        cmp.reverse()
                    }
                }),
                SortColumn::Jitter => sorted_pids.sort_by(|a, b| {
                    let r_a = app.task_rows.get(a).unwrap();
                    let r_b = app.task_rows.get(b).unwrap();
                    let cmp = avg_jitter_us(r_b).cmp(&avg_jitter_us(r_a));
                    if desc {
                        cmp
                    } else {
                        cmp.reverse()
                    }
                }),
                SortColumn::Wait => sorted_pids.sort_by(|a, b| {
                    let r_a = app.task_rows.get(a).unwrap();
                    let r_b = app.task_rows.get(b).unwrap();
                    let cmp = r_b.wait_duration_ns.cmp(&r_a.wait_duration_ns);
                    if desc {
                        cmp
                    } else {
                        cmp.reverse()
                    }
                }),
                SortColumn::RunsPerSec => sorted_pids.sort_by(|a, b| {
                    let r_a = app.task_rows.get(a).unwrap();
                    let r_b = app.task_rows.get(b).unwrap();
                    let cmp = r_b
                        .runs_per_sec
                        .partial_cmp(&r_a.runs_per_sec)
                        .unwrap_or(std::cmp::Ordering::Equal);
                    if desc {
                        cmp
                    } else {
                        cmp.reverse()
                    }
                }),
                SortColumn::TargetCpu => sorted_pids.sort_by(|a, b| {
                    let r_a = app.task_rows.get(a).unwrap();
                    let r_b = app.task_rows.get(b).unwrap();
                    let cmp = r_a.core_placement.cmp(&r_b.core_placement);
                    if desc {
                        cmp.reverse()
                    } else {
                        cmp
                    }
                }),
                SortColumn::Spread => sorted_pids.sort_by(|a, b| {
                    let r_a = app.task_rows.get(a).unwrap();
                    let r_b = app.task_rows.get(b).unwrap();
                    let p_a = placement_summary(r_a, &app.topology);
                    let p_b = placement_summary(r_b, &app.topology);
                    let spread_a = (p_a.active_core_count, p_a.active_cpu_count);
                    let spread_b = (p_b.active_core_count, p_b.active_cpu_count);
                    let cmp = spread_b.cmp(&spread_a);
                    if desc {
                        cmp
                    } else {
                        cmp.reverse()
                    }
                }),
                SortColumn::Residency => sorted_pids.sort_by(|a, b| {
                    let r_a = app.task_rows.get(a).unwrap();
                    let r_b = app.task_rows.get(b).unwrap();
                    let p_a = placement_summary(r_a, &app.topology);
                    let p_b = placement_summary(r_b, &app.topology);
                    let res_a = p_a
                        .top_core
                        .map(|(_, count)| (count * 100) / p_a.total_samples.max(1))
                        .unwrap_or(0);
                    let res_b = p_b
                        .top_core
                        .map(|(_, count)| (count * 100) / p_b.total_samples.max(1))
                        .unwrap_or(0);
                    let cmp = res_b.cmp(&res_a);
                    if desc {
                        cmp
                    } else {
                        cmp.reverse()
                    }
                }),
                SortColumn::SelectCpu => sorted_pids.sort_by(|a, b| {
                    let r_a = app.task_rows.get(a).unwrap();
                    let r_b = app.task_rows.get(b).unwrap();
                    let cmp = r_b.select_cpu_ns.cmp(&r_a.select_cpu_ns);
                    if desc {
                        cmp
                    } else {
                        cmp.reverse()
                    }
                }),
                SortColumn::Enqueue => sorted_pids.sort_by(|a, b| {
                    let r_a = app.task_rows.get(a).unwrap();
                    let r_b = app.task_rows.get(b).unwrap();
                    let cmp = r_b.enqueue_ns.cmp(&r_a.enqueue_ns);
                    if desc {
                        cmp
                    } else {
                        cmp.reverse()
                    }
                }),
                SortColumn::Gap => sorted_pids.sort_by(|a, b| {
                    let r_a = app.task_rows.get(a).unwrap();
                    let r_b = app.task_rows.get(b).unwrap();
                    let cmp = r_b.dispatch_gap_us.cmp(&r_a.dispatch_gap_us);
                    if desc {
                        cmp
                    } else {
                        cmp.reverse()
                    }
                }),
                SortColumn::Gate1Pct => sorted_pids.sort_by(|a, b| {
                    let r_a = app.task_rows.get(a).unwrap();
                    let r_b = app.task_rows.get(b).unwrap();
                    let cmp = r_b.gate_hit_pcts[0]
                        .partial_cmp(&r_a.gate_hit_pcts[0])
                        .unwrap_or(std::cmp::Ordering::Equal);
                    if desc {
                        cmp
                    } else {
                        cmp.reverse()
                    }
                }),
                SortColumn::Class => sorted_pids.sort_by(|a, b| {
                    let r_a = app.task_rows.get(a).unwrap();
                    let r_b = app.task_rows.get(b).unwrap();
                    let cmp = class_rank(r_a).cmp(&class_rank(r_b));
                    if desc {
                        cmp
                    } else {
                        cmp.reverse()
                    }
                }),
                SortColumn::Migrations => sorted_pids.sort_by(|a, b| {
                    let r_a = app.task_rows.get(a).unwrap();
                    let r_b = app.task_rows.get(b).unwrap();
                    let cmp = r_b
                        .migrations_per_sec
                        .partial_cmp(&r_a.migrations_per_sec)
                        .unwrap_or(std::cmp::Ordering::Equal);
                    if desc {
                        cmp
                    } else {
                        cmp.reverse()
                    }
                }),
            }

            // TGID grouping: stable-sort by tgid so threads of the
            // same process stay adjacent. The first thread in each
            // group (after the primary sort) defines the group rank,
            // so processes with high-priority threads sort first.
            let mut tgid_rank: std::collections::HashMap<u32, usize> =
                std::collections::HashMap::new();
            for (i, pid) in sorted_pids.iter().enumerate() {
                if let Some(row) = app.task_rows.get(pid) {
                    let tgid = if row.tgid > 0 { row.tgid } else { *pid };
                    tgid_rank.entry(tgid).or_insert(i);
                }
            }
            sorted_pids.sort_by(|a, b| {
                let r_a = app.task_rows.get(a).unwrap();
                let r_b = app.task_rows.get(b).unwrap();
                let tgid_a = if r_a.tgid > 0 { r_a.tgid } else { *a };
                let tgid_b = if r_b.tgid > 0 { r_b.tgid } else { *b };
                let rank_a = tgid_rank.get(&tgid_a).copied().unwrap_or(usize::MAX);
                let rank_b = tgid_rank.get(&tgid_b).copied().unwrap_or(usize::MAX);
                rank_a.cmp(&rank_b).then_with(|| {
                    // Within same tgid group, keep original sort order
                    r_b.pelt_util.cmp(&r_a.pelt_util)
                })
            });

            app.sorted_pids = sorted_pids;
            app.record_stats_snapshot(&stats);

            last_tick = Instant::now();
        }
    }

    restore_terminal()?;
    Ok(())
}
