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
const TIMELINE_HISTORY_MAX_SAMPLES: usize = 3600;
const TIMELINE_SAMPLE_PERIOD: Duration = Duration::from_secs(1);
const STATUS_MESSAGE_TTL: Duration = Duration::from_secs(4);
const DEAD_TASK_RETENTION: Duration = Duration::from_secs(300);
const FULL_SWEEP_MIN_INTERVAL: Duration = Duration::from_secs(1);
const SELECT_REASON_MAX: usize = 10;
const PRESSURE_SITE_MAX: usize = 2;
const PRESSURE_OUTCOME_MAX: usize = 6;
const WAKE_REASON_MAX: usize = 4;
const WAKE_BUCKET_MAX: usize = 5;

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
    pub sorted_pids_dirty: bool,
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
    pub bpf_task_count: usize,                 // Live BPF-tracked tasks with total_runs > 0
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
    per_cpu_work: Vec<CpuWorkCounters>,
    pressure_probe: PressureProbeCounters,
    stats_history: VecDeque<StatsSnapshot>,
    cpu_work_history: VecDeque<CpuWorkSnapshot>,
    pressure_probe_history: VecDeque<PressureProbeSnapshot>,
    timeline_history: VecDeque<TimelineBucket>,
    timeline_last_sample: Option<StatsSnapshot>,
    timeline_next_sample_at: Option<Instant>,
}

#[derive(Clone, Copy)]
struct StatsSnapshot {
    at: Instant,
    stats: cake_stats,
}

#[derive(Clone, Copy)]
struct TimelineBucket {
    elapsed: Duration,
    stats: cake_stats,
}

#[derive(Clone, Copy)]
struct TimelineSample {
    start_ago_secs: u64,
    end_ago_secs: u64,
    elapsed: Duration,
    stats: cake_stats,
}

#[derive(Clone, Copy, Debug, Default)]
struct CpuWorkCounters {
    task_runtime_ns: u64,
    task_run_count: u64,
    local_dispatches: u64,
    stolen_dispatches: u64,
    quantum_full: u64,
    quantum_yield: u64,
    quantum_preempt: u64,
    select_target_total: u64,
    select_prev_total: u64,
    select_target_reason: [u64; SELECT_REASON_MAX],
    select_prev_reason: [u64; SELECT_REASON_MAX],
    pressure_probe: [[u64; PRESSURE_OUTCOME_MAX]; PRESSURE_SITE_MAX],
    cpu_pressure: u8,
    local_pending: u32,
    local_pending_max: u32,
    local_pending_inserts: u64,
    local_pending_runs: u64,
    wake_direct_target: u64,
    wake_busy_target: u64,
    wake_busy_local_target: u64,
    wake_busy_remote_target: u64,
    target_wait_ns: [u64; WAKE_REASON_MAX],
    target_wait_count: [u64; WAKE_REASON_MAX],
    target_wait_max_ns: [u64; WAKE_REASON_MAX],
    target_wait_bucket: [[u64; WAKE_BUCKET_MAX]; WAKE_REASON_MAX],
}

#[derive(Clone, Debug)]
struct CpuWorkSnapshot {
    at: Instant,
    counters: Vec<CpuWorkCounters>,
}

#[derive(Clone, Copy, Debug, Default)]
struct PressureProbeCounters {
    total: [[u64; PRESSURE_OUTCOME_MAX]; PRESSURE_SITE_MAX],
}

#[derive(Clone, Copy)]
struct PressureProbeSnapshot {
    at: Instant,
    counters: PressureProbeCounters,
}

#[derive(Clone, Debug)]
struct SchedulerCpuRow {
    cpu: usize,
    core: usize,
    llc: usize,
    is_secondary_smt: bool,
    share_pct: f64,
    runs: u64,
    runs_per_sec: f64,
    total_runtime_ns: u64,
    avg_run_us: u64,
    full_pct: f64,
    yield_pct: f64,
    preempt_pct: f64,
    system_load: f32,
    temp_c: f32,
}

#[derive(Clone, Debug)]
struct SchedulerCoreRow {
    core: usize,
    cpu_label: String,
    share_pct: f64,
    runs: u64,
    runs_per_sec: f64,
    total_runtime_ns: u64,
    avg_run_us: u64,
    full_pct: f64,
    yield_pct: f64,
    preempt_pct: f64,
    top_cpu_share_pct: f64,
    secondary_smt_pct: f64,
    avg_system_load: f32,
}

#[derive(Clone, Debug)]
struct SelectCpuRow {
    cpu: usize,
    target_total: u64,
    target_pct: f64,
    prev_total: u64,
    prev_pct: f64,
    target_reason: [u64; SELECT_REASON_MAX],
    prev_reason: [u64; SELECT_REASON_MAX],
}

#[derive(Clone, Debug)]
struct PressureProbeRow {
    cpu: usize,
    eval_total: u64,
    eval_pct: f64,
    outcome: [u64; PRESSURE_OUTCOME_MAX],
}

#[derive(Clone, Debug)]
struct LocalQueueRow {
    cpu: usize,
    pressure: u8,
    pending: u32,
    pending_max: u32,
    inserts: u64,
    runs: u64,
    direct: u64,
    busy: u64,
    busy_local: u64,
    busy_remote: u64,
    wait_ns: [u64; WAKE_REASON_MAX],
    wait_count: [u64; WAKE_REASON_MAX],
    wait_max_ns: [u64; WAKE_REASON_MAX],
    wait_bucket: [[u64; WAKE_BUCKET_MAX]; WAKE_REASON_MAX],
}

#[derive(Clone, Debug, Default)]
struct BalanceDiagnosis {
    top_cpu_share_label: String,
    top_cpu_share_pct: f64,
    top_cpu_avg_run_us: u64,
    top_cpu_runs_per_sec: f64,
    top_cpu_rate_label: String,
    top_cpu_rate_runs_per_sec: f64,
    top_cpu_rate_avg_run_us: u64,
    top_core_share_label: String,
    top_core_share_pct: f64,
    top_core_hot_thr_pct: f64,
    top_core_sib_pct: f64,
    top_core_rate_label: String,
    top_core_rate_runs_per_sec: f64,
    cpu_skew: f64,
    core_skew: f64,
    hot_cpu_count: usize,
    cold_cpu_count: usize,
    hot_core_count: usize,
    cold_core_count: usize,
    driver: &'static str,
    sticky_core: bool,
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
    pub last_seen_at: Instant,
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
    pub quantum_full_count: u16,    // Task consumed the full slice
    pub quantum_yield_count: u16,   // Task stopped with slice left and became non-runnable
    pub quantum_preempt_count: u16, // Task was kicked/preempted while still runnable
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
            last_seen_at: Instant::now(),
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
            total.task_runtime_ns += s.task_runtime_ns;
            total.task_run_count += s.task_run_count;
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
                total.wake_reason_wait_all_ns[reason] += s.wake_reason_wait_all_ns[reason];
                total.wake_reason_wait_all_count[reason] += s.wake_reason_wait_all_count[reason];
                total.wake_reason_wait_all_max_ns[reason] = total.wake_reason_wait_all_max_ns
                    [reason]
                    .max(s.wake_reason_wait_all_max_ns[reason]);
                total.wake_reason_wait_ns[reason] += s.wake_reason_wait_ns[reason];
                total.wake_reason_wait_count[reason] += s.wake_reason_wait_count[reason];
                total.wake_reason_wait_max_ns[reason] =
                    total.wake_reason_wait_max_ns[reason].max(s.wake_reason_wait_max_ns[reason]);
                for bucket in 0..5 {
                    total.wake_reason_bucket_count[reason][bucket] +=
                        s.wake_reason_bucket_count[reason][bucket];
                }
                total.wake_target_hit_count[reason] += s.wake_target_hit_count[reason];
                total.wake_target_miss_count[reason] += s.wake_target_miss_count[reason];
                total.wake_followup_same_cpu_count[reason] +=
                    s.wake_followup_same_cpu_count[reason];
                total.wake_followup_migrate_count[reason] += s.wake_followup_migrate_count[reason];
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
            total.nr_wake_kick_idle += s.nr_wake_kick_idle;
            total.nr_wake_kick_preempt += s.nr_wake_kick_preempt;
            total.nr_affine_kick_idle += s.nr_affine_kick_idle;
            total.nr_affine_kick_preempt += s.nr_affine_kick_preempt;
            total.nr_quantum_full += s.nr_quantum_full;
            total.nr_quantum_yield += s.nr_quantum_yield;
            total.nr_quantum_preempt += s.nr_quantum_preempt;
            total.nr_sched_yield_calls += s.nr_sched_yield_calls;
            for kind in 0..3 {
                total.nr_wake_kick_observed[kind] += s.nr_wake_kick_observed[kind];
                total.nr_wake_kick_quick[kind] += s.nr_wake_kick_quick[kind];
                total.total_wake_kick_to_run_ns[kind] += s.total_wake_kick_to_run_ns[kind];
                total.max_wake_kick_to_run_ns[kind] =
                    total.max_wake_kick_to_run_ns[kind].max(s.max_wake_kick_to_run_ns[kind]);
                for bucket in 0..5 {
                    total.wake_kick_bucket_count[kind][bucket] +=
                        s.wake_kick_bucket_count[kind][bucket];
                }
            }
        }
    }

    total
}

fn extract_cpu_work(skel: &BpfSkel, nr_cpus: usize) -> Vec<CpuWorkCounters> {
    let mut work = vec![CpuWorkCounters::default(); nr_cpus];

    if let Some(bss) = &skel.maps.bss_data {
        for (idx, stats) in bss.global_stats.iter().take(nr_cpus).enumerate() {
            #[cfg(debug_assertions)]
            let (
                select_target_reason,
                select_prev_reason,
                pressure_probe,
                target_wait_ns,
                target_wait_count,
                target_wait_max_ns,
                target_wait_bucket,
            ) = {
                let mut select_target_reason = [0; SELECT_REASON_MAX];
                let mut select_prev_reason = [0; SELECT_REASON_MAX];
                let mut pressure_probe = [[0; PRESSURE_OUTCOME_MAX]; PRESSURE_SITE_MAX];
                let mut target_wait_ns = [0; WAKE_REASON_MAX];
                let mut target_wait_count = [0; WAKE_REASON_MAX];
                let mut target_wait_max_ns = [0; WAKE_REASON_MAX];
                let mut target_wait_bucket = [[0; WAKE_BUCKET_MAX]; WAKE_REASON_MAX];

                for reason in 0..SELECT_REASON_MAX {
                    select_target_reason[reason] = bss.select_reason_target_count[reason][idx];
                    select_prev_reason[reason] = bss.select_reason_prev_count[reason][idx];
                }

                for site in 0..PRESSURE_SITE_MAX {
                    for outcome in 0..PRESSURE_OUTCOME_MAX {
                        pressure_probe[site][outcome] =
                            bss.pressure_probe_cpu_count[site][outcome][idx];
                    }
                }

                for reason in 0..WAKE_REASON_MAX {
                    target_wait_ns[reason] = bss.wake_target_wait_ns[reason][idx];
                    target_wait_count[reason] = bss.wake_target_wait_count[reason][idx];
                    target_wait_max_ns[reason] = bss.wake_target_wait_max_ns[reason][idx];
                    for bucket in 0..WAKE_BUCKET_MAX {
                        target_wait_bucket[reason][bucket] =
                            bss.wake_target_wait_bucket_count[reason][idx][bucket];
                    }
                }

                (
                    select_target_reason,
                    select_prev_reason,
                    pressure_probe,
                    target_wait_ns,
                    target_wait_count,
                    target_wait_max_ns,
                    target_wait_bucket,
                )
            };
            #[cfg(not(debug_assertions))]
            let (
                select_target_reason,
                select_prev_reason,
                pressure_probe,
                target_wait_ns,
                target_wait_count,
                target_wait_max_ns,
                target_wait_bucket,
            ) = (
                [0; SELECT_REASON_MAX],
                [0; SELECT_REASON_MAX],
                [[0; PRESSURE_OUTCOME_MAX]; PRESSURE_SITE_MAX],
                [0; WAKE_REASON_MAX],
                [0; WAKE_REASON_MAX],
                [0; WAKE_REASON_MAX],
                [[0; WAKE_BUCKET_MAX]; WAKE_REASON_MAX],
            );
            #[cfg(debug_assertions)]
            let local_pending = bss.local_pending_est[idx];
            #[cfg(not(debug_assertions))]
            let local_pending = 0;
            #[cfg(debug_assertions)]
            let local_pending_max = bss.local_pending_max[idx];
            #[cfg(not(debug_assertions))]
            let local_pending_max = 0;
            #[cfg(debug_assertions)]
            let local_pending_inserts = bss.local_pending_insert_count[idx];
            #[cfg(not(debug_assertions))]
            let local_pending_inserts = 0;
            #[cfg(debug_assertions)]
            let local_pending_runs = bss.local_pending_run_count[idx];
            #[cfg(not(debug_assertions))]
            let local_pending_runs = 0;
            #[cfg(debug_assertions)]
            let wake_direct_target = bss.wake_direct_target_count[idx];
            #[cfg(not(debug_assertions))]
            let wake_direct_target = 0;
            #[cfg(debug_assertions)]
            let wake_busy_target = bss.wake_busy_target_count[idx];
            #[cfg(not(debug_assertions))]
            let wake_busy_target = 0;
            #[cfg(debug_assertions)]
            let wake_busy_local_target = bss.wake_busy_local_target_count[idx];
            #[cfg(not(debug_assertions))]
            let wake_busy_local_target = 0;
            #[cfg(debug_assertions)]
            let wake_busy_remote_target = bss.wake_busy_remote_target_count[idx];
            #[cfg(not(debug_assertions))]
            let wake_busy_remote_target = 0;

            work[idx] = CpuWorkCounters {
                task_runtime_ns: stats.task_runtime_ns,
                task_run_count: stats.task_run_count,
                local_dispatches: stats.nr_local_dispatches,
                stolen_dispatches: stats.nr_stolen_dispatches,
                quantum_full: stats.nr_quantum_full,
                quantum_yield: stats.nr_quantum_yield,
                quantum_preempt: stats.nr_quantum_preempt,
                select_target_total: select_target_reason[1..].iter().sum(),
                select_prev_total: select_prev_reason[1..].iter().sum(),
                select_target_reason,
                select_prev_reason,
                pressure_probe,
                cpu_pressure: bss.cpu_bss[idx].cpu_pressure,
                local_pending,
                local_pending_max,
                local_pending_inserts,
                local_pending_runs,
                wake_direct_target,
                wake_busy_target,
                wake_busy_local_target,
                wake_busy_remote_target,
                target_wait_ns,
                target_wait_count,
                target_wait_max_ns,
                target_wait_bucket,
            };
        }
    }

    work
}

#[cfg(debug_assertions)]
fn extract_pressure_probe(skel: &BpfSkel) -> PressureProbeCounters {
    let mut pressure_probe = PressureProbeCounters::default();

    if let Some(bss) = &skel.maps.bss_data {
        for site in 0..PRESSURE_SITE_MAX {
            for outcome in 0..PRESSURE_OUTCOME_MAX {
                pressure_probe.total[site][outcome] = bss.pressure_probe_total[site][outcome];
            }
        }
    }

    pressure_probe
}

#[cfg(not(debug_assertions))]
fn extract_pressure_probe(_skel: &BpfSkel) -> PressureProbeCounters {
    PressureProbeCounters::default()
}

fn cpu_work_delta(
    current: &[CpuWorkCounters],
    previous: &[CpuWorkCounters],
) -> Vec<CpuWorkCounters> {
    current
        .iter()
        .enumerate()
        .map(|(idx, cur)| {
            let prev = previous.get(idx).copied().unwrap_or_default();
            CpuWorkCounters {
                task_runtime_ns: cur.task_runtime_ns.saturating_sub(prev.task_runtime_ns),
                task_run_count: cur.task_run_count.saturating_sub(prev.task_run_count),
                local_dispatches: cur.local_dispatches.saturating_sub(prev.local_dispatches),
                stolen_dispatches: cur.stolen_dispatches.saturating_sub(prev.stolen_dispatches),
                quantum_full: cur.quantum_full.saturating_sub(prev.quantum_full),
                quantum_yield: cur.quantum_yield.saturating_sub(prev.quantum_yield),
                quantum_preempt: cur.quantum_preempt.saturating_sub(prev.quantum_preempt),
                select_target_total: cur
                    .select_target_total
                    .saturating_sub(prev.select_target_total),
                select_prev_total: cur.select_prev_total.saturating_sub(prev.select_prev_total),
                select_target_reason: std::array::from_fn(|reason| {
                    cur.select_target_reason[reason]
                        .saturating_sub(prev.select_target_reason[reason])
                }),
                select_prev_reason: std::array::from_fn(|reason| {
                    cur.select_prev_reason[reason].saturating_sub(prev.select_prev_reason[reason])
                }),
                pressure_probe: std::array::from_fn(|site| {
                    std::array::from_fn(|outcome| {
                        cur.pressure_probe[site][outcome]
                            .saturating_sub(prev.pressure_probe[site][outcome])
                    })
                }),
                cpu_pressure: cur.cpu_pressure,
                local_pending: cur.local_pending,
                local_pending_max: cur.local_pending_max,
                local_pending_inserts: cur
                    .local_pending_inserts
                    .saturating_sub(prev.local_pending_inserts),
                local_pending_runs: cur
                    .local_pending_runs
                    .saturating_sub(prev.local_pending_runs),
                wake_direct_target: cur
                    .wake_direct_target
                    .saturating_sub(prev.wake_direct_target),
                wake_busy_target: cur.wake_busy_target.saturating_sub(prev.wake_busy_target),
                wake_busy_local_target: cur
                    .wake_busy_local_target
                    .saturating_sub(prev.wake_busy_local_target),
                wake_busy_remote_target: cur
                    .wake_busy_remote_target
                    .saturating_sub(prev.wake_busy_remote_target),
                target_wait_ns: std::array::from_fn(|reason| {
                    cur.target_wait_ns[reason].saturating_sub(prev.target_wait_ns[reason])
                }),
                target_wait_count: std::array::from_fn(|reason| {
                    cur.target_wait_count[reason].saturating_sub(prev.target_wait_count[reason])
                }),
                target_wait_max_ns: cur.target_wait_max_ns,
                target_wait_bucket: std::array::from_fn(|reason| {
                    std::array::from_fn(|bucket| {
                        cur.target_wait_bucket[reason][bucket]
                            .saturating_sub(prev.target_wait_bucket[reason][bucket])
                    })
                }),
            }
        })
        .collect()
}

fn pressure_probe_delta(
    current: PressureProbeCounters,
    previous: PressureProbeCounters,
) -> PressureProbeCounters {
    PressureProbeCounters {
        total: std::array::from_fn(|site| {
            std::array::from_fn(|outcome| {
                current.total[site][outcome].saturating_sub(previous.total[site][outcome])
            })
        }),
    }
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
    delta.task_runtime_ns = current
        .task_runtime_ns
        .saturating_sub(previous.task_runtime_ns);
    delta.task_run_count = current
        .task_run_count
        .saturating_sub(previous.task_run_count);
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
        delta.wake_reason_wait_all_ns[reason] = current.wake_reason_wait_all_ns[reason]
            .saturating_sub(previous.wake_reason_wait_all_ns[reason]);
        delta.wake_reason_wait_all_count[reason] = current.wake_reason_wait_all_count[reason]
            .saturating_sub(previous.wake_reason_wait_all_count[reason]);
        delta.wake_reason_wait_all_max_ns[reason] = current.wake_reason_wait_all_max_ns[reason];
        delta.wake_reason_wait_ns[reason] = current.wake_reason_wait_ns[reason]
            .saturating_sub(previous.wake_reason_wait_ns[reason]);
        delta.wake_reason_wait_count[reason] = current.wake_reason_wait_count[reason]
            .saturating_sub(previous.wake_reason_wait_count[reason]);
        delta.wake_reason_wait_max_ns[reason] = current.wake_reason_wait_max_ns[reason];
        for bucket in 0..current.wake_reason_bucket_count[reason].len() {
            delta.wake_reason_bucket_count[reason][bucket] = current.wake_reason_bucket_count
                [reason][bucket]
                .saturating_sub(previous.wake_reason_bucket_count[reason][bucket]);
        }
        delta.wake_target_hit_count[reason] = current.wake_target_hit_count[reason]
            .saturating_sub(previous.wake_target_hit_count[reason]);
        delta.wake_target_miss_count[reason] = current.wake_target_miss_count[reason]
            .saturating_sub(previous.wake_target_miss_count[reason]);
        delta.wake_followup_same_cpu_count[reason] = current.wake_followup_same_cpu_count[reason]
            .saturating_sub(previous.wake_followup_same_cpu_count[reason]);
        delta.wake_followup_migrate_count[reason] = current.wake_followup_migrate_count[reason]
            .saturating_sub(previous.wake_followup_migrate_count[reason]);
    }
    for path in 0..current.select_path_count.len() {
        delta.select_path_count[path] =
            current.select_path_count[path].saturating_sub(previous.select_path_count[path]);
    }
    for cls in 0..current.home_place_wait_ns.len() {
        delta.home_place_wait_ns[cls] =
            current.home_place_wait_ns[cls].saturating_sub(previous.home_place_wait_ns[cls]);
        delta.home_place_wait_count[cls] =
            current.home_place_wait_count[cls].saturating_sub(previous.home_place_wait_count[cls]);
        delta.home_place_wait_max_ns[cls] = current.home_place_wait_max_ns[cls];
        delta.home_place_run_ns[cls] =
            current.home_place_run_ns[cls].saturating_sub(previous.home_place_run_ns[cls]);
        delta.home_place_run_count[cls] =
            current.home_place_run_count[cls].saturating_sub(previous.home_place_run_count[cls]);
        delta.home_place_run_max_ns[cls] = current.home_place_run_max_ns[cls];
        delta.waker_place_wait_ns[cls] =
            current.waker_place_wait_ns[cls].saturating_sub(previous.waker_place_wait_ns[cls]);
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
    delta.nr_wake_kick_idle = current
        .nr_wake_kick_idle
        .saturating_sub(previous.nr_wake_kick_idle);
    delta.nr_wake_kick_preempt = current
        .nr_wake_kick_preempt
        .saturating_sub(previous.nr_wake_kick_preempt);
    delta.nr_affine_kick_idle = current
        .nr_affine_kick_idle
        .saturating_sub(previous.nr_affine_kick_idle);
    delta.nr_affine_kick_preempt = current
        .nr_affine_kick_preempt
        .saturating_sub(previous.nr_affine_kick_preempt);
    delta.nr_quantum_full = current
        .nr_quantum_full
        .saturating_sub(previous.nr_quantum_full);
    delta.nr_quantum_yield = current
        .nr_quantum_yield
        .saturating_sub(previous.nr_quantum_yield);
    delta.nr_quantum_preempt = current
        .nr_quantum_preempt
        .saturating_sub(previous.nr_quantum_preempt);
    delta.nr_sched_yield_calls = current
        .nr_sched_yield_calls
        .saturating_sub(previous.nr_sched_yield_calls);
    for kind in 0..current.nr_wake_kick_observed.len() {
        delta.nr_wake_kick_observed[kind] = current.nr_wake_kick_observed[kind]
            .saturating_sub(previous.nr_wake_kick_observed[kind]);
        delta.nr_wake_kick_quick[kind] =
            current.nr_wake_kick_quick[kind].saturating_sub(previous.nr_wake_kick_quick[kind]);
        delta.total_wake_kick_to_run_ns[kind] = current.total_wake_kick_to_run_ns[kind]
            .saturating_sub(previous.total_wake_kick_to_run_ns[kind]);
        delta.max_wake_kick_to_run_ns[kind] = current.max_wake_kick_to_run_ns[kind];
        for bucket in 0..current.wake_kick_bucket_count[kind].len() {
            delta.wake_kick_bucket_count[kind][bucket] = current.wake_kick_bucket_count[kind]
                [bucket]
                .saturating_sub(previous.wake_kick_bucket_count[kind][bucket]);
        }
    }

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

fn is_secondary_smt_cpu(topology: &TopologyInfo, cpu: usize) -> bool {
    topology.smt_enabled
        && topology.cpu_sibling_map[cpu] as usize != cpu
        && topology.cpu_thread_bit[cpu] != 1
}

fn scheduler_cpu_rows(
    counters: &[CpuWorkCounters],
    topology: &TopologyInfo,
    cpu_stats: &[(f32, f32)],
    elapsed: Duration,
) -> Vec<SchedulerCpuRow> {
    let total_runtime_ns: u64 = counters.iter().map(|c| c.task_runtime_ns).sum();
    let secs = elapsed.as_secs_f64();
    let mut rows = Vec::new();

    for (cpu, counter) in counters.iter().enumerate() {
        let quantum_total = counter.quantum_full + counter.quantum_yield + counter.quantum_preempt;
        let avg_run_us = if counter.task_run_count > 0 {
            counter.task_runtime_ns / counter.task_run_count / 1000
        } else {
            0
        };
        let (system_load, temp_c) = cpu_stats.get(cpu).copied().unwrap_or((0.0, 0.0));
        rows.push(SchedulerCpuRow {
            cpu,
            core: topology.cpu_core_id[cpu] as usize,
            llc: topology.cpu_llc_id[cpu] as usize,
            is_secondary_smt: is_secondary_smt_cpu(topology, cpu),
            share_pct: pct(counter.task_runtime_ns, total_runtime_ns),
            runs: counter.task_run_count,
            runs_per_sec: per_sec(counter.task_run_count, secs),
            total_runtime_ns: counter.task_runtime_ns,
            avg_run_us,
            full_pct: pct(counter.quantum_full, quantum_total),
            yield_pct: pct(counter.quantum_yield, quantum_total),
            preempt_pct: pct(counter.quantum_preempt, quantum_total),
            system_load,
            temp_c,
        });
    }

    rows.sort_by(|a, b| {
        b.total_runtime_ns
            .cmp(&a.total_runtime_ns)
            .then_with(|| a.cpu.cmp(&b.cpu))
    });
    rows
}

fn cpu_label_for_core(cpus: &[usize]) -> String {
    let mut ids: Vec<String> = cpus.iter().map(|cpu| cpu.to_string()).collect();
    if ids.len() > 4 {
        ids.truncate(4);
        ids.push("+".to_string());
    }
    ids.join("/")
}

fn scheduler_core_rows(
    counters: &[CpuWorkCounters],
    topology: &TopologyInfo,
    cpu_stats: &[(f32, f32)],
    elapsed: Duration,
) -> Vec<SchedulerCoreRow> {
    let total_runtime_ns: u64 = counters.iter().map(|c| c.task_runtime_ns).sum();
    let secs = elapsed.as_secs_f64();
    let mut grouped: HashMap<usize, Vec<usize>> = HashMap::new();
    for cpu in 0..counters.len() {
        grouped
            .entry(topology.cpu_core_id[cpu] as usize)
            .or_default()
            .push(cpu);
    }

    let mut rows = Vec::new();
    for (core, cpus) in grouped {
        let mut runtime_ns = 0u64;
        let mut runs = 0u64;
        let mut quantum_full = 0u64;
        let mut quantum_yield = 0u64;
        let mut quantum_preempt = 0u64;
        let mut system_load = 0.0f32;
        let mut top_cpu_runtime = 0u64;
        let mut secondary_runtime = 0u64;

        for &cpu in &cpus {
            let counter = counters.get(cpu).copied().unwrap_or_default();
            runtime_ns += counter.task_runtime_ns;
            runs += counter.task_run_count;
            quantum_full += counter.quantum_full;
            quantum_yield += counter.quantum_yield;
            quantum_preempt += counter.quantum_preempt;
            system_load += cpu_stats.get(cpu).map(|(load, _)| *load).unwrap_or(0.0);
            top_cpu_runtime = top_cpu_runtime.max(counter.task_runtime_ns);
            if is_secondary_smt_cpu(topology, cpu) {
                secondary_runtime += counter.task_runtime_ns;
            }
        }

        let avg_run_us = if runs > 0 {
            runtime_ns / runs / 1000
        } else {
            0
        };
        let quantum_total = quantum_full + quantum_yield + quantum_preempt;
        let avg_system_load = if cpus.is_empty() {
            0.0
        } else {
            system_load / cpus.len() as f32
        };
        rows.push(SchedulerCoreRow {
            core,
            cpu_label: cpu_label_for_core(&cpus),
            share_pct: pct(runtime_ns, total_runtime_ns),
            runs,
            runs_per_sec: per_sec(runs, secs),
            total_runtime_ns: runtime_ns,
            avg_run_us,
            full_pct: pct(quantum_full, quantum_total),
            yield_pct: pct(quantum_yield, quantum_total),
            preempt_pct: pct(quantum_preempt, quantum_total),
            top_cpu_share_pct: pct(top_cpu_runtime, runtime_ns),
            secondary_smt_pct: pct(secondary_runtime, runtime_ns),
            avg_system_load,
        });
    }

    rows.sort_by(|a, b| {
        b.total_runtime_ns
            .cmp(&a.total_runtime_ns)
            .then_with(|| a.core.cmp(&b.core))
    });
    rows
}

fn scheduler_share_by_cpu(counters: &[CpuWorkCounters]) -> Vec<f64> {
    let total_runtime_ns: u64 = counters.iter().map(|c| c.task_runtime_ns).sum();
    counters
        .iter()
        .map(|counter| pct(counter.task_runtime_ns, total_runtime_ns))
        .collect()
}

fn scheduler_balance_ratio(counters: &[CpuWorkCounters]) -> f64 {
    let mut active: Vec<u64> = counters
        .iter()
        .map(|counter| counter.task_runtime_ns)
        .filter(|&runtime| runtime > 0)
        .collect();
    if active.len() < 2 {
        return 1.0;
    }
    active.sort_unstable();
    let min = active[0].max(1);
    let max = *active.last().unwrap_or(&min);
    max as f64 / min as f64
}

fn select_balance_ratio(counters: &[CpuWorkCounters], prev_side: bool) -> f64 {
    let mut active: Vec<u64> = counters
        .iter()
        .map(|counter| {
            if prev_side {
                counter.select_prev_total
            } else {
                counter.select_target_total
            }
        })
        .filter(|&count| count > 0)
        .collect();
    if active.len() < 2 {
        return 1.0;
    }
    active.sort_unstable();
    let min = active[0].max(1);
    let max = *active.last().unwrap_or(&min);
    max as f64 / min as f64
}

fn select_reason_short_label(reason: usize) -> &'static str {
    match reason {
        1 => "hm",
        2 => "hc",
        3 => "pp",
        4 => "ps",
        5 => "hy",
        6 => "kp",
        7 => "ki",
        8 => "tn",
        9 => "pc",
        _ => "-",
    }
}

fn pressure_probe_site_label(site: usize) -> &'static str {
    match site {
        0 => "home",
        1 => "prev",
        _ => "unknown",
    }
}

fn pressure_probe_outcome_short_label(outcome: usize) -> &'static str {
    match outcome {
        0 => "ev",
        1 => "ba",
        2 => "bs",
        3 => "bd",
        4 => "bb",
        5 => "ok",
        _ => "-",
    }
}

fn select_reason_totals(counters: &[CpuWorkCounters], prev_side: bool) -> [u64; SELECT_REASON_MAX] {
    let mut total = [0; SELECT_REASON_MAX];
    for counter in counters {
        for reason in 0..SELECT_REASON_MAX {
            total[reason] += if prev_side {
                counter.select_prev_reason[reason]
            } else {
                counter.select_target_reason[reason]
            };
        }
    }
    total
}

fn pressure_probe_balance_ratio(counters: &[CpuWorkCounters], site: usize) -> f64 {
    let mut active: Vec<u64> = counters
        .iter()
        .map(|counter| counter.pressure_probe[site][0])
        .filter(|&count| count > 0)
        .collect();
    if active.len() < 2 {
        return 1.0;
    }
    active.sort_unstable();
    let min = active[0].max(1);
    let max = *active.last().unwrap_or(&min);
    max as f64 / min as f64
}

fn format_select_reason_summary(counts: &[u64]) -> String {
    let total: u64 = counts[1..].iter().sum();
    let mut parts = Vec::new();
    for reason in 1..counts.len() {
        if counts[reason] == 0 {
            continue;
        }
        parts.push(format!(
            "{}={:.0}%({})",
            select_reason_short_label(reason),
            pct(counts[reason], total),
            counts[reason]
        ));
    }
    if parts.is_empty() {
        "none".to_string()
    } else {
        parts.join(" ")
    }
}

fn format_pressure_probe_summary(counts: &[u64]) -> String {
    let evaluated = counts[0];
    if evaluated == 0 {
        return "none".to_string();
    }

    let mut parts = vec![format!("ev={}", evaluated)];
    for outcome in 1..counts.len() {
        if counts[outcome] == 0 {
            continue;
        }
        parts.push(format!(
            "{}={:.0}%({})",
            pressure_probe_outcome_short_label(outcome),
            pct(counts[outcome], evaluated),
            counts[outcome]
        ));
    }
    parts.join(" ")
}

fn format_select_reason_mix(counts: &[u64], total: u64) -> String {
    let mut parts = Vec::new();
    for reason in 1..counts.len() {
        if counts[reason] == 0 {
            continue;
        }
        parts.push(format!(
            "{}:{:.0}",
            select_reason_short_label(reason),
            pct(counts[reason], total)
        ));
    }
    if parts.is_empty() {
        "-".to_string()
    } else {
        parts.join(" ")
    }
}

fn format_pressure_probe_mix(counts: &[u64], evaluated: u64) -> String {
    if evaluated == 0 {
        return "-".to_string();
    }

    let mut parts = Vec::new();
    for outcome in 1..counts.len() {
        if counts[outcome] == 0 {
            continue;
        }
        parts.push(format!(
            "{}:{:.0}",
            pressure_probe_outcome_short_label(outcome),
            pct(counts[outcome], evaluated)
        ));
    }
    if parts.is_empty() {
        "-".to_string()
    } else {
        parts.join(" ")
    }
}

fn select_cpu_rows(counters: &[CpuWorkCounters]) -> Vec<SelectCpuRow> {
    let total_target: u64 = counters
        .iter()
        .map(|counter| counter.select_target_total)
        .sum();
    let total_prev: u64 = counters
        .iter()
        .map(|counter| counter.select_prev_total)
        .sum();
    let mut rows: Vec<SelectCpuRow> = counters
        .iter()
        .enumerate()
        .filter_map(|(cpu, counter)| {
            if counter.select_target_total == 0 && counter.select_prev_total == 0 {
                return None;
            }
            Some(SelectCpuRow {
                cpu,
                target_total: counter.select_target_total,
                target_pct: pct(counter.select_target_total, total_target),
                prev_total: counter.select_prev_total,
                prev_pct: pct(counter.select_prev_total, total_prev),
                target_reason: counter.select_target_reason,
                prev_reason: counter.select_prev_reason,
            })
        })
        .collect();

    rows.sort_by(|a, b| {
        b.target_total
            .cmp(&a.target_total)
            .then_with(|| b.prev_total.cmp(&a.prev_total))
            .then_with(|| a.cpu.cmp(&b.cpu))
    });
    rows
}

fn pressure_probe_rows(counters: &[CpuWorkCounters], site: usize) -> Vec<PressureProbeRow> {
    let total_eval: u64 = counters
        .iter()
        .map(|counter| counter.pressure_probe[site][0])
        .sum();
    let mut rows: Vec<PressureProbeRow> = counters
        .iter()
        .enumerate()
        .filter_map(|(cpu, counter)| {
            let eval_total = counter.pressure_probe[site][0];
            if eval_total == 0 {
                return None;
            }
            Some(PressureProbeRow {
                cpu,
                eval_total,
                eval_pct: pct(eval_total, total_eval),
                outcome: counter.pressure_probe[site],
            })
        })
        .collect();

    rows.sort_by(|a, b| {
        b.eval_total
            .cmp(&a.eval_total)
            .then_with(|| a.cpu.cmp(&b.cpu))
    });
    rows
}

fn target_wait_total_count(counter: &CpuWorkCounters) -> u64 {
    counter.target_wait_count[1..].iter().sum()
}

fn target_wait_total_ns(counter: &CpuWorkCounters) -> u64 {
    counter.target_wait_ns[1..].iter().sum()
}

fn local_queue_rows(counters: &[CpuWorkCounters]) -> Vec<LocalQueueRow> {
    let mut rows: Vec<LocalQueueRow> = counters
        .iter()
        .enumerate()
        .filter_map(|(cpu, counter)| {
            let active = counter.local_pending > 0
                || counter.local_pending_max > 0
                || counter.local_pending_inserts > 0
                || counter.local_pending_runs > 0
                || counter.wake_direct_target > 0
                || counter.wake_busy_target > 0
                || target_wait_total_count(counter) > 0
                || counter.cpu_pressure > 0;
            if !active {
                return None;
            }
            Some(LocalQueueRow {
                cpu,
                pressure: counter.cpu_pressure,
                pending: counter.local_pending,
                pending_max: counter.local_pending_max,
                inserts: counter.local_pending_inserts,
                runs: counter.local_pending_runs,
                direct: counter.wake_direct_target,
                busy: counter.wake_busy_target,
                busy_local: counter.wake_busy_local_target,
                busy_remote: counter.wake_busy_remote_target,
                wait_ns: counter.target_wait_ns,
                wait_count: counter.target_wait_count,
                wait_max_ns: counter.target_wait_max_ns,
                wait_bucket: counter.target_wait_bucket,
            })
        })
        .collect();

    rows.sort_by(|a, b| {
        b.pending
            .cmp(&a.pending)
            .then_with(|| b.pending_max.cmp(&a.pending_max))
            .then_with(|| b.busy.cmp(&a.busy))
            .then_with(|| {
                let b_wait: u64 = b.wait_ns[1..].iter().sum();
                let a_wait: u64 = a.wait_ns[1..].iter().sum();
                b_wait.cmp(&a_wait)
            })
            .then_with(|| b.pressure.cmp(&a.pressure))
            .then_with(|| a.cpu.cmp(&b.cpu))
    });
    rows
}

fn share_balance_ratio(shares: &[f64]) -> f64 {
    let mut active: Vec<f64> = shares
        .iter()
        .copied()
        .filter(|share| *share > 0.0)
        .collect();
    if active.len() < 2 {
        return 1.0;
    }
    active.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let min = active[0].max(0.0001);
    let max = *active.last().unwrap_or(&min);
    max / min
}

fn balance_counts(shares: &[f64]) -> (usize, usize) {
    let active: Vec<f64> = shares
        .iter()
        .copied()
        .filter(|share| *share > 0.0)
        .collect();
    if active.is_empty() {
        return (0, 0);
    }
    let avg = 100.0 / active.len() as f64;
    let hot = active.iter().filter(|share| **share > avg * 1.5).count();
    let cold = active.iter().filter(|share| **share < avg * 0.5).count();
    (hot, cold)
}

fn balance_driver(top_share_cpu: &SchedulerCpuRow, top_rate_cpu: &SchedulerCpuRow) -> &'static str {
    if top_share_cpu.avg_run_us > top_rate_cpu.avg_run_us.saturating_mul(2)
        && top_share_cpu.runs_per_sec < top_rate_cpu.runs_per_sec * 0.5
    {
        "long_runs"
    } else if top_share_cpu.cpu == top_rate_cpu.cpu {
        "rate+runtime"
    } else {
        "high_rate"
    }
}

fn build_balance_diagnosis(
    cpu_rows: &[SchedulerCpuRow],
    core_rows: &[SchedulerCoreRow],
) -> Option<BalanceDiagnosis> {
    let top_share_cpu = cpu_rows.first()?;
    let top_rate_cpu = cpu_rows.iter().max_by(|a, b| {
        a.runs_per_sec
            .partial_cmp(&b.runs_per_sec)
            .unwrap_or(std::cmp::Ordering::Equal)
    })?;
    let top_share_core = core_rows.first()?;
    let top_rate_core = core_rows.iter().max_by(|a, b| {
        a.runs_per_sec
            .partial_cmp(&b.runs_per_sec)
            .unwrap_or(std::cmp::Ordering::Equal)
    })?;
    let cpu_shares: Vec<f64> = cpu_rows.iter().map(|row| row.share_pct).collect();
    let core_shares: Vec<f64> = core_rows.iter().map(|row| row.share_pct).collect();
    let (hot_cpu_count, cold_cpu_count) = balance_counts(&cpu_shares);
    let (hot_core_count, cold_core_count) = balance_counts(&core_shares);

    Some(BalanceDiagnosis {
        top_cpu_share_label: format!("C{:02}", top_share_cpu.cpu),
        top_cpu_share_pct: top_share_cpu.share_pct,
        top_cpu_avg_run_us: top_share_cpu.avg_run_us,
        top_cpu_runs_per_sec: top_share_cpu.runs_per_sec,
        top_cpu_rate_label: format!("C{:02}", top_rate_cpu.cpu),
        top_cpu_rate_runs_per_sec: top_rate_cpu.runs_per_sec,
        top_cpu_rate_avg_run_us: top_rate_cpu.avg_run_us,
        top_core_share_label: format!("K{:02}", top_share_core.core),
        top_core_share_pct: top_share_core.share_pct,
        top_core_hot_thr_pct: top_share_core.top_cpu_share_pct,
        top_core_sib_pct: top_share_core.secondary_smt_pct,
        top_core_rate_label: format!("K{:02}", top_rate_core.core),
        top_core_rate_runs_per_sec: top_rate_core.runs_per_sec,
        cpu_skew: share_balance_ratio(&cpu_shares),
        core_skew: share_balance_ratio(&core_shares),
        hot_cpu_count,
        cold_cpu_count,
        hot_core_count,
        cold_core_count,
        driver: balance_driver(top_share_cpu, top_rate_cpu),
        sticky_core: top_share_core.top_cpu_share_pct >= 85.0
            && top_share_core.secondary_smt_pct <= 15.0,
    })
}

fn format_runtime_ms(runtime_ns: u64) -> String {
    format!("{:.1}", runtime_ns as f64 / 1_000_000.0)
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
                && comm_has_any(
                    &leader,
                    &[
                        "steamwebhelper",
                        "discord",
                        "chrome",
                        "chromium",
                        "cef",
                        "electron",
                    ],
                ));
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
        WorkloadRole::Critical
        | WorkloadRole::Game
        | WorkloadRole::Render
        | WorkloadRole::Audio => CapacityBand::HardLatency,
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
    match ev.kind {
        1 => format!(
            "cb:{} {} {}us c{}",
            ev.slot,
            ev.comm,
            ev.value_ns / 1000,
            ev.cpu
        ),
        2 => format!(
            "wait:{} {} {}us c{}",
            wake_reason_label(ev.slot as usize),
            ev.comm,
            ev.value_ns / 1000,
            ev.cpu
        ),
        3 => format!(
            "miss:{} {} {}us tgt={} run={} c{}",
            wake_reason_label(ev.slot as usize),
            ev.comm,
            ev.value_ns / 1000,
            ev.aux >> 16,
            ev.aux & 0xffff,
            ev.cpu
        ),
        4 => format!(
            "kick:{} {} {}us reason={} tgt={} c{}",
            kick_kind_label(ev.slot as usize),
            ev.comm,
            ev.value_ns / 1000,
            ev.aux >> 16,
            ev.aux & 0xffff,
            ev.cpu
        ),
        5 => format!(
            "mig:{} {} gap={}us first={} next={} c{}",
            wake_reason_label(ev.slot as usize),
            ev.comm,
            ev.value_ns / 1000,
            ev.aux >> 16,
            ev.aux & 0xffff,
            ev.cpu
        ),
        6 => format!("gap {} {}us c{}", ev.comm, ev.value_ns / 1000, ev.cpu),
        7 => format!("preempt-chain {} n={} c{}", ev.comm, ev.aux, ev.cpu),
        _ => format!(
            "evt:{} {} {}us c{}",
            ev.slot,
            ev.comm,
            ev.value_ns / 1000,
            ev.cpu
        ),
    }
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

fn dashboard_label(text: impl Into<String>) -> Span<'static> {
    Span::styled(text.into(), Style::default().fg(Color::Gray))
}

fn dashboard_value(text: impl Into<String>, style: Style) -> Span<'static> {
    Span::styled(text.into(), style.add_modifier(Modifier::BOLD))
}

fn dashboard_sep(text: impl Into<String>) -> Span<'static> {
    Span::styled(text.into(), Style::default().fg(Color::DarkGray))
}

fn dashboard_note(text: impl Into<String>) -> Span<'static> {
    Span::styled(text.into(), Style::default().fg(Color::DarkGray))
}

fn footer_key(text: impl Into<String>) -> Span<'static> {
    Span::styled(
        format!("[{}]", text.into()),
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD),
    )
}

fn push_dashboard_metric(
    spans: &mut Vec<Span<'static>>,
    label: impl Into<String>,
    value: impl Into<String>,
    style: Style,
) {
    spans.push(dashboard_label(label));
    spans.push(dashboard_value(value, style));
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
            sorted_pids_dirty: true,
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
            per_cpu_work: vec![CpuWorkCounters::default(); nr_cpus],
            pressure_probe: PressureProbeCounters::default(),
            stats_history: VecDeque::new(),
            cpu_work_history: VecDeque::new(),
            pressure_probe_history: VecDeque::new(),
            timeline_history: VecDeque::new(),
            timeline_last_sample: None,
            timeline_next_sample_at: None,
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
            Some((msg, timestamp)) if timestamp.elapsed() < STATUS_MESSAGE_TTL => Some(msg),
            _ => None,
        }
    }

    fn record_stats_snapshot(&mut self, stats: &cake_stats) {
        let now = Instant::now();
        let snapshot = StatsSnapshot {
            at: now,
            stats: *stats,
        };
        self.stats_history.push_back(snapshot);
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

        match self.timeline_last_sample {
            None => {
                self.timeline_last_sample = Some(snapshot);
                self.timeline_next_sample_at = Some(now + TIMELINE_SAMPLE_PERIOD);
            }
            Some(prev) => {
                let next_at = self
                    .timeline_next_sample_at
                    .unwrap_or(prev.at + TIMELINE_SAMPLE_PERIOD);
                if now >= next_at {
                    let elapsed = now.saturating_duration_since(prev.at);
                    if elapsed >= TIMELINE_SAMPLE_PERIOD / 2 {
                        self.timeline_history.push_back(TimelineBucket {
                            elapsed,
                            stats: stats_delta(stats, &prev.stats),
                        });
                        while self.timeline_history.len() > TIMELINE_HISTORY_MAX_SAMPLES {
                            self.timeline_history.pop_front();
                        }
                    }
                    self.timeline_last_sample = Some(snapshot);
                    self.timeline_next_sample_at = Some(now + TIMELINE_SAMPLE_PERIOD);
                }
            }
        }
    }

    fn record_cpu_work_snapshot(&mut self) {
        let now = Instant::now();
        self.cpu_work_history.push_back(CpuWorkSnapshot {
            at: now,
            counters: self.per_cpu_work.clone(),
        });
        while self.cpu_work_history.len() > STATS_HISTORY_MAX_SAMPLES {
            self.cpu_work_history.pop_front();
        }
        while let Some(front) = self.cpu_work_history.front() {
            if now.saturating_duration_since(front.at) > STATS_HISTORY_MAX_AGE {
                self.cpu_work_history.pop_front();
            } else {
                break;
            }
        }
    }

    fn record_pressure_probe_snapshot(&mut self) {
        let now = Instant::now();
        self.pressure_probe_history
            .push_back(PressureProbeSnapshot {
                at: now,
                counters: self.pressure_probe,
            });
        while self.pressure_probe_history.len() > STATS_HISTORY_MAX_SAMPLES {
            self.pressure_probe_history.pop_front();
        }
        while let Some(front) = self.pressure_probe_history.front() {
            if now.saturating_duration_since(front.at) > STATS_HISTORY_MAX_AGE {
                self.pressure_probe_history.pop_front();
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

    fn cpu_work_window(&self, window: Duration) -> Option<(Duration, Vec<CpuWorkCounters>)> {
        let newest = self.cpu_work_history.back()?;
        let target = newest.at.checked_sub(window).unwrap_or(newest.at);
        let baseline = self
            .cpu_work_history
            .iter()
            .rev()
            .find(|snap| snap.at <= target)
            .or_else(|| self.cpu_work_history.front())?;
        let elapsed = newest.at.saturating_duration_since(baseline.at);
        if elapsed < Duration::from_secs(1) {
            return None;
        }
        Some((
            elapsed,
            cpu_work_delta(&self.per_cpu_work, &baseline.counters),
        ))
    }

    fn pressure_probe_window(&self, window: Duration) -> Option<(Duration, PressureProbeCounters)> {
        let newest = self.pressure_probe_history.back()?;
        let target = newest.at.checked_sub(window).unwrap_or(newest.at);
        let baseline = self
            .pressure_probe_history
            .iter()
            .rev()
            .find(|snap| snap.at <= target)
            .or_else(|| self.pressure_probe_history.front())?;
        let elapsed = newest.at.saturating_duration_since(baseline.at);
        if elapsed < Duration::from_secs(1) {
            return None;
        }
        Some((
            elapsed,
            pressure_probe_delta(self.pressure_probe, baseline.counters),
        ))
    }

    fn timeline_samples(&self, window: Duration, step: Duration) -> Vec<TimelineSample> {
        let step_secs = step.as_secs();
        if step_secs == 0 {
            return Vec::new();
        }
        let buckets = (window.as_secs() / step_secs).max(1);
        let start_idx = self.timeline_history.len().saturating_sub(buckets as usize);
        self.timeline_history
            .iter()
            .skip(start_idx)
            .enumerate()
            .map(|(idx, bucket)| {
                let remaining = (buckets as usize).saturating_sub(idx);
                TimelineSample {
                    start_ago_secs: remaining as u64,
                    end_ago_secs: remaining.saturating_sub(1) as u64,
                    elapsed: bucket.elapsed,
                    stats: bucket.stats,
                }
            })
            .collect()
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
        self.sorted_pids_dirty = true;
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
        self.sorted_pids_dirty = true;
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
    scheduler_share: &'a [f64],
    scheduler_label: &'a str,
) -> impl Widget + 'a {
    let mut text = Vec::new();

    text.push(Line::from(vec![
        Span::styled(
            "Node 0 Topology",
            Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            "  cells = Ck runtime share | Ld system load | temp",
            Style::default().fg(Color::Yellow),
        ),
        Span::styled(
            format!("  {}", scheduler_label),
            Style::default().fg(Color::Cyan),
        ),
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
        let cpus_per_row = 3;
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
                let sched_share = scheduler_share.get(cpu).copied().unwrap_or(0.0);

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
                let sched_color = if sched_share > 20.0 {
                    Color::LightRed
                } else if sched_share > 10.0 {
                    Color::Yellow
                } else if sched_share > 0.0 {
                    Color::Green
                } else {
                    Color::DarkGray
                };

                line_spans.push(Span::styled(
                    format!("CPU{:02} ", cpu),
                    Style::default().fg(core_color),
                ));
                line_spans.push(Span::styled("[", Style::default().fg(Color::DarkGray)));
                line_spans.push(Span::styled(
                    format!("Ck{:>2.0}", sched_share),
                    Style::default().fg(sched_color),
                ));
                line_spans.push(Span::styled("|", Style::default().fg(Color::DarkGray)));
                line_spans.push(Span::styled(
                    format!("L{:>2.0}", load),
                    Style::default().fg(load_color),
                ));
                line_spans.push(Span::styled("|", Style::default().fg(Color::DarkGray)));
                line_spans.push(Span::styled(
                    format!("{:>2.0}°", temp),
                    Style::default().fg(temp_color),
                ));
                line_spans.push(Span::styled("]  ", Style::default().fg(Color::DarkGray)));
            }
            text.push(Line::from(line_spans));
        }
    }

    Paragraph::new(text).block(
        Block::default()
            .title(" Topology [Ck | Ld | Temp] ")
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(Color::Cyan).dim())
            .padding(Padding::horizontal(1)),
    )
}

fn build_scheduler_cpu_table<'a>(
    rows: &'a [SchedulerCpuRow],
    title: &'a str,
    limit: usize,
) -> Table<'a> {
    let header = Row::new(vec![
        Cell::from("CPU"),
        Cell::from("C/L3"),
        Cell::from("Cake%"),
        Cell::from("Runs/s"),
        Cell::from("Avgµs"),
        Cell::from("Full%"),
        Cell::from("Blk%"),
        Cell::from("Pre%"),
        Cell::from("Sys%"),
    ])
    .style(
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD),
    );

    let table_rows: Vec<Row<'a>> = rows
        .iter()
        .take(limit)
        .map(|row| {
            let cpu_style = if row.is_secondary_smt {
                Style::default().fg(Color::Yellow)
            } else {
                Style::default().fg(Color::White)
            };
            let share_style = if row.share_pct > 15.0 {
                Style::default()
                    .fg(Color::LightRed)
                    .add_modifier(Modifier::BOLD)
            } else if row.share_pct > 5.0 {
                Style::default().fg(Color::Yellow)
            } else {
                Style::default().fg(Color::Green)
            };
            let load_style = if row.system_load > 90.0 {
                Style::default().fg(Color::LightRed)
            } else if row.system_load > 50.0 {
                Style::default().fg(Color::Yellow)
            } else {
                Style::default().fg(Color::Green)
            };
            Row::new(vec![
                Cell::from(Span::styled(
                    format!("C{:02}", row.cpu),
                    cpu_style.add_modifier(Modifier::BOLD),
                )),
                Cell::from(format!("{}/{}", row.core, row.llc)),
                Cell::from(Span::styled(format!("{:>5.1}", row.share_pct), share_style)),
                Cell::from(format!("{:>6.1}", row.runs_per_sec)),
                Cell::from(format!("{:>6}", row.avg_run_us)),
                Cell::from(format!("{:>5.0}", row.full_pct)),
                Cell::from(format!("{:>4.0}", row.yield_pct)),
                Cell::from(format!("{:>4.0}", row.preempt_pct)),
                Cell::from(Span::styled(
                    format!("{:>4.0}", row.system_load),
                    load_style,
                )),
            ])
        })
        .collect();

    Table::new(
        table_rows,
        [
            Constraint::Length(4),
            Constraint::Length(6),
            Constraint::Length(7),
            Constraint::Length(7),
            Constraint::Length(7),
            Constraint::Length(5),
            Constraint::Length(5),
            Constraint::Length(5),
            Constraint::Length(5),
        ],
    )
    .header(header)
    .block(dashboard_block(title, Color::Yellow))
}

fn build_scheduler_core_table<'a>(
    rows: &'a [SchedulerCoreRow],
    title: &'a str,
    limit: usize,
) -> Table<'a> {
    let header = Row::new(vec![
        Cell::from("Core"),
        Cell::from("CPUs"),
        Cell::from("Cake%"),
        Cell::from("Runs/s"),
        Cell::from("Avgµs"),
        Cell::from("HotThr%"),
        Cell::from("Sib%"),
        Cell::from("Sys%"),
    ])
    .style(
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD),
    );

    let table_rows: Vec<Row<'a>> = rows
        .iter()
        .take(limit)
        .map(|row| {
            let share_style = if row.share_pct > 20.0 {
                Style::default()
                    .fg(Color::LightRed)
                    .add_modifier(Modifier::BOLD)
            } else if row.share_pct > 8.0 {
                Style::default().fg(Color::Yellow)
            } else {
                Style::default().fg(Color::Green)
            };
            Row::new(vec![
                Cell::from(Span::styled(
                    format!("K{:02}", row.core),
                    Style::default()
                        .fg(Color::White)
                        .add_modifier(Modifier::BOLD),
                )),
                Cell::from(row.cpu_label.clone()),
                Cell::from(Span::styled(format!("{:>5.1}", row.share_pct), share_style)),
                Cell::from(format!("{:>6.1}", row.runs_per_sec)),
                Cell::from(format!("{:>6}", row.avg_run_us)),
                Cell::from(format!("{:>7.0}", row.top_cpu_share_pct)),
                Cell::from(format!("{:>5.0}", row.secondary_smt_pct)),
                Cell::from(format!("{:>4.0}", row.avg_system_load)),
            ])
        })
        .collect();

    Table::new(
        table_rows,
        [
            Constraint::Length(5),
            Constraint::Length(8),
            Constraint::Length(7),
            Constraint::Length(7),
            Constraint::Length(7),
            Constraint::Length(8),
            Constraint::Length(6),
            Constraint::Length(5),
        ],
    )
    .header(header)
    .block(dashboard_block(title, Color::Green))
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

fn signed_diff_u64(lhs: u64, rhs: u64) -> i128 {
    i128::from(lhs) - i128::from(rhs)
}

fn slice_util_display_pct(raw_score: u16) -> u32 {
    ((raw_score as u32) * 100 + 64) / 128
}

fn expected_timeline_samples(window: Duration, step: Duration) -> usize {
    let step_secs = step.as_secs();
    if step_secs == 0 {
        0
    } else {
        (window.as_secs() / step_secs).max(1) as usize
    }
}

fn timeline_history_span(samples: &VecDeque<TimelineBucket>) -> Duration {
    samples
        .iter()
        .fold(Duration::ZERO, |acc, sample| acc + sample.elapsed)
}

fn average_timeline_sample_secs(samples: &[TimelineSample]) -> f64 {
    if samples.is_empty() {
        0.0
    } else {
        samples
            .iter()
            .map(|sample| sample.elapsed.as_secs_f64())
            .sum::<f64>()
            / samples.len() as f64
    }
}

fn percentile_f64(samples: &[f64], pct: f64) -> f64 {
    if samples.is_empty() {
        return 0.0;
    }
    let mut sorted = samples.to_vec();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let idx = ((pct / 100.0) * (sorted.len() as f64 - 1.0)).round() as usize;
    sorted[idx.min(sorted.len() - 1)]
}

fn summarize_timeline_samples(
    samples: &[TimelineSample],
    expected_samples: usize,
) -> Option<[Line<'static>; 3]> {
    if samples.is_empty() {
        return None;
    }

    let mut run_rates = Vec::with_capacity(samples.len());
    let mut wake_rates = Vec::with_capacity(samples.len());
    let mut total_select_ns = 0u64;
    let mut total_select_calls = 0u64;
    let mut total_enqueue_ns = 0u64;
    let mut total_enqueue_calls = 0u64;
    let mut total_running_ns = 0u64;
    let mut total_running_calls = 0u64;
    let mut total_stopping_ns = 0u64;
    let mut total_stopping_calls = 0u64;
    let mut total_wait_ns = [0u64; 4];
    let mut total_wait_count = [0u64; 4];
    let mut total_paths = [0u64; 6];
    let mut total_quantum = [0u64; 3];
    let mut total_sched_yield_calls = 0u64;
    let mut total_sample_secs = 0.0f64;

    for sample in samples {
        let secs = sample.elapsed.as_secs_f64().max(0.1);
        let wake_total = sample.stats.nr_wakeup_direct_dispatches
            + sample.stats.nr_wakeup_dsq_fallback_busy
            + sample.stats.nr_wakeup_dsq_fallback_queued;
        total_sample_secs += secs;
        run_rates.push(per_sec(sample.stats.nr_running_calls, secs));
        wake_rates.push(per_sec(wake_total, secs));

        total_select_ns += sample.stats.total_select_cpu_ns;
        total_select_calls += sample.stats.nr_select_cpu_calls;
        total_enqueue_ns += sample.stats.total_enqueue_latency_ns;
        total_enqueue_calls += sample.stats.nr_enqueue_calls;
        total_running_ns += sample.stats.total_running_ns;
        total_running_calls += sample.stats.nr_running_calls;
        total_stopping_ns += sample.stats.total_stopping_ns;
        total_stopping_calls += sample.stats.nr_stopping_calls;

        for reason in 1..4 {
            total_wait_ns[reason] += sample.stats.wake_reason_wait_ns[reason];
            total_wait_count[reason] += sample.stats.wake_reason_wait_count[reason];
        }
        for path in 1..6 {
            total_paths[path] += sample.stats.select_path_count[path];
        }

        total_quantum[0] += sample.stats.nr_quantum_full;
        total_quantum[1] += sample.stats.nr_quantum_yield;
        total_quantum[2] += sample.stats.nr_quantum_preempt;
        total_sched_yield_calls += sample.stats.nr_sched_yield_calls;
    }

    let mean = |values: &[f64]| -> f64 {
        if values.is_empty() {
            0.0
        } else {
            values.iter().sum::<f64>() / values.len() as f64
        }
    };
    let path_total: u64 = total_paths[1..6].iter().sum();
    let quantum_total: u64 = total_quantum.iter().sum();

    let mut line1 = vec![dashboard_label("Runs/s ")];
    push_dashboard_metric(
        &mut line1,
        "avg ",
        format!("{:.1}", mean(&run_rates)),
        Style::default().fg(Color::Green),
    );
    line1.push(dashboard_sep("  "));
    push_dashboard_metric(
        &mut line1,
        "1% low ",
        format!("{:.1}", percentile_f64(&run_rates, 1.0)),
        Style::default().fg(Color::LightCyan),
    );
    line1.push(dashboard_sep("  "));
    push_dashboard_metric(
        &mut line1,
        "median ",
        format!("{:.1}", percentile_f64(&run_rates, 50.0)),
        Style::default().fg(Color::Cyan),
    );
    line1.push(dashboard_sep("  "));
    push_dashboard_metric(
        &mut line1,
        "p99 ",
        format!("{:.1}", percentile_f64(&run_rates, 99.0)),
        Style::default().fg(Color::Yellow),
    );
    line1.push(dashboard_sep("  "));
    push_dashboard_metric(
        &mut line1,
        "wake/s ",
        format!("{:.1}", mean(&wake_rates)),
        Style::default().fg(Color::LightMagenta),
    );
    line1.push(dashboard_sep("  "));
    push_dashboard_metric(
        &mut line1,
        "samples ",
        if expected_samples > 0 {
            format!("{}/{}", samples.len(), expected_samples)
        } else {
            samples.len().to_string()
        },
        Style::default().fg(Color::Blue),
    );

    let sel_avg = avg_ns(total_select_ns, total_select_calls);
    let enq_avg = avg_ns(total_enqueue_ns, total_enqueue_calls);
    let run_avg = avg_ns(total_running_ns, total_running_calls);
    let stop_avg = avg_ns(total_stopping_ns, total_stopping_calls);
    let wait_dir = bucket_avg_us(total_wait_ns[1], total_wait_count[1]);
    let wait_busy = bucket_avg_us(total_wait_ns[2], total_wait_count[2]);
    let wait_queue = bucket_avg_us(total_wait_ns[3], total_wait_count[3]);

    let mut line2 = vec![dashboard_label("Callback avg ")];
    push_dashboard_metric(
        &mut line2,
        "select ",
        format!("{}ns", sel_avg),
        low_is_good_style(sel_avg, 1_000, 5_000),
    );
    line2.push(dashboard_sep("  "));
    push_dashboard_metric(
        &mut line2,
        "enqueue ",
        format!("{}ns", enq_avg),
        low_is_good_style(enq_avg, 1_000, 5_000),
    );
    line2.push(dashboard_sep("  "));
    push_dashboard_metric(
        &mut line2,
        "running ",
        format!("{}ns", run_avg),
        low_is_good_style(run_avg, 1_000, 5_000),
    );
    line2.push(dashboard_sep("  "));
    push_dashboard_metric(
        &mut line2,
        "stopping ",
        format!("{}ns", stop_avg),
        low_is_good_style(stop_avg, 1_000, 5_000),
    );
    line2.push(dashboard_sep("  "));
    push_dashboard_metric(
        &mut line2,
        "wake wait<=5ms ",
        format!("{}/{}/{}", wait_dir, wait_busy, wait_queue),
        low_is_good_style(wait_dir.max(wait_busy).max(wait_queue), 10, 100),
    );

    let mut line3 = vec![dashboard_label("Path share ")];
    push_dashboard_metric(
        &mut line3,
        "home ",
        format!("{:.0}%", pct(total_paths[1], path_total)),
        Style::default().fg(Color::Green),
    );
    line3.push(dashboard_sep("  "));
    push_dashboard_metric(
        &mut line3,
        "same core ",
        format!("{:.0}%", pct(total_paths[2], path_total)),
        Style::default().fg(Color::Yellow),
    );
    line3.push(dashboard_sep("  "));
    push_dashboard_metric(
        &mut line3,
        "primary ",
        format!("{:.0}%", pct(total_paths[3], path_total)),
        Style::default().fg(Color::Magenta),
    );
    line3.push(dashboard_sep("  "));
    push_dashboard_metric(
        &mut line3,
        "idle ",
        format!("{:.0}%", pct(total_paths[4], path_total)),
        Style::default().fg(Color::Cyan),
    );
    line3.push(dashboard_sep("  "));
    push_dashboard_metric(
        &mut line3,
        "tunnel ",
        format!("{:.0}%", pct(total_paths[5], path_total)),
        Style::default().fg(Color::LightRed),
    );
    line3.push(dashboard_sep("  "));
    push_dashboard_metric(
        &mut line3,
        "quantum f/b/p ",
        format!(
            "{:.0}/{:.0}/{:.0}%",
            pct(total_quantum[0], quantum_total),
            pct(total_quantum[1], quantum_total),
            pct(total_quantum[2], quantum_total),
        ),
        Style::default().fg(Color::LightMagenta),
    );
    line3.push(dashboard_sep("  "));
    push_dashboard_metric(
        &mut line3,
        "sched_yield/s ",
        format!("{:.1}", per_sec(total_sched_yield_calls, total_sample_secs)),
        Style::default().fg(Color::Yellow),
    );

    Some([Line::from(line1), Line::from(line2), Line::from(line3)])
}

fn format_timeline_sample_row(sample: &TimelineSample) -> String {
    let secs = sample.elapsed.as_secs_f64().max(0.1);
    let wake_total = sample.stats.nr_wakeup_direct_dispatches
        + sample.stats.nr_wakeup_dsq_fallback_busy
        + sample.stats.nr_wakeup_dsq_fallback_queued;
    let path_total: u64 = sample.stats.select_path_count[1..6].iter().sum();
    let quantum_total = sample.stats.nr_quantum_full
        + sample.stats.nr_quantum_yield
        + sample.stats.nr_quantum_preempt;

    format!(
        "  slot-{:>2}..{:>2} span={:>4.2}s run/s={:>7.1} wake/s={:>7.1} wake%={:>4.0}/{:>4.0}/{:>4.0} path%={:>4.0}/{:>4.0}/{:>4.0}/{:>4.0}/{:>4.0} cbns={}/{}/{}/{} waitus<=5ms={}/{}/{} slice%={:.0}/{:.0}/{:.0}",
        sample.start_ago_secs,
        sample.end_ago_secs,
        secs,
        per_sec(sample.stats.nr_running_calls, secs),
        per_sec(wake_total, secs),
        pct(sample.stats.nr_wakeup_direct_dispatches, wake_total),
        pct(sample.stats.nr_wakeup_dsq_fallback_busy, wake_total),
        pct(sample.stats.nr_wakeup_dsq_fallback_queued, wake_total),
        pct(sample.stats.select_path_count[1], path_total),
        pct(sample.stats.select_path_count[2], path_total),
        pct(sample.stats.select_path_count[3], path_total),
        pct(sample.stats.select_path_count[4], path_total),
        pct(sample.stats.select_path_count[5], path_total),
        avg_ns(sample.stats.total_select_cpu_ns, sample.stats.nr_select_cpu_calls),
        avg_ns(sample.stats.total_enqueue_latency_ns, sample.stats.nr_enqueue_calls),
        avg_ns(sample.stats.total_running_ns, sample.stats.nr_running_calls),
        avg_ns(sample.stats.total_stopping_ns, sample.stats.nr_stopping_calls),
        bucket_avg_us(sample.stats.wake_reason_wait_ns[1], sample.stats.wake_reason_wait_count[1]),
        bucket_avg_us(sample.stats.wake_reason_wait_ns[2], sample.stats.wake_reason_wait_count[2]),
        bucket_avg_us(sample.stats.wake_reason_wait_ns[3], sample.stats.wake_reason_wait_count[3]),
        pct(sample.stats.nr_quantum_full, quantum_total),
        pct(sample.stats.nr_quantum_yield, quantum_total),
        pct(sample.stats.nr_quantum_preempt, quantum_total),
    )
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
        3 => "primary",
        4 => "idle",
        5 => "tunnel",
        _ => "-",
    }
}

fn wake_reason_label(reason: usize) -> &'static str {
    match reason {
        1 => "direct",
        2 => "busy",
        3 => "queued",
        _ => "?",
    }
}

fn wake_reason_short_label(reason: usize) -> &'static str {
    match reason {
        1 => "dir",
        2 => "busy",
        3 => "queue",
        _ => "?",
    }
}

fn wake_bucket_label(bucket: usize) -> &'static str {
    match bucket {
        0 => "<50us",
        1 => "<200us",
        2 => "<1ms",
        3 => "<5ms",
        4 => ">=5ms",
        _ => "?",
    }
}

fn wake_bucket_p99_label(buckets: &[u64; WAKE_BUCKET_MAX]) -> &'static str {
    let total: u64 = buckets.iter().sum();
    if total == 0 {
        return "-";
    }
    let target = total.saturating_mul(99).saturating_add(99) / 100;
    let mut seen = 0;
    for (bucket, count) in buckets.iter().enumerate() {
        seen += *count;
        if seen >= target {
            return wake_bucket_label(bucket);
        }
    }
    wake_bucket_label(WAKE_BUCKET_MAX - 1)
}

fn format_local_queue_wait(row: &LocalQueueRow) -> String {
    let mut parts = Vec::new();
    for reason in 1..WAKE_REASON_MAX {
        let samples = row.wait_count[reason];
        if samples == 0 {
            continue;
        }
        parts.push(format!(
            "{}={}/{}us/{}({})",
            wake_reason_short_label(reason),
            row.wait_ns[reason] / samples / 1000,
            row.wait_max_ns[reason] / 1000,
            wake_bucket_p99_label(&row.wait_bucket[reason]),
            samples,
        ));
    }
    if parts.is_empty() {
        "none".to_string()
    } else {
        parts.join(" ")
    }
}

fn kick_kind_label(kind: usize) -> &'static str {
    match kind {
        1 => "idle",
        2 => "preempt",
        _ => "?",
    }
}

fn format_wake_bucket_summary(buckets: &[[u64; 5]]) -> String {
    let mut parts = Vec::new();
    for reason in 1..buckets.len() {
        let row = buckets[reason];
        if row.iter().all(|count| *count == 0) {
            continue;
        }
        parts.push(format!(
            "{}={}/{}/{}/{}/{}",
            wake_reason_label(reason),
            row[0],
            row[1],
            row[2],
            row[3],
            row[4],
        ));
    }
    if parts.is_empty() {
        "none".to_string()
    } else {
        parts.join(" ")
    }
}

fn format_wake_target_summary(hit: &[u64], miss: &[u64]) -> String {
    let mut parts = Vec::new();
    for reason in 1..hit.len() {
        let total = hit[reason] + miss[reason];
        if total == 0 {
            continue;
        }
        parts.push(format!(
            "{}={}/{}",
            wake_reason_label(reason),
            hit[reason],
            miss[reason]
        ));
    }
    if parts.is_empty() {
        "none".to_string()
    } else {
        parts.join(" ")
    }
}

fn format_wake_followup_summary(same: &[u64], migrate: &[u64]) -> String {
    let mut parts = Vec::new();
    for reason in 1..same.len() {
        let total = same[reason] + migrate[reason];
        if total == 0 {
            continue;
        }
        parts.push(format!(
            "{}={}/{}",
            wake_reason_label(reason),
            same[reason],
            migrate[reason]
        ));
    }
    if parts.is_empty() {
        "none".to_string()
    } else {
        parts.join(" ")
    }
}

fn format_kick_bucket_summary(buckets: &[[u64; 5]]) -> String {
    let mut parts = Vec::new();
    for kind in 1..buckets.len() {
        let row = buckets[kind];
        if row.iter().all(|count| *count == 0) {
            continue;
        }
        parts.push(format!(
            "{}={}/{}/{}/{}/{}",
            kick_kind_label(kind),
            row[0],
            row[1],
            row[2],
            row[3],
            row[4],
        ));
    }
    if parts.is_empty() {
        "none".to_string()
    } else {
        parts.join(" ")
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

fn append_select_cpu_section(
    output: &mut String,
    label: &str,
    counters: &[CpuWorkCounters],
    elapsed: Duration,
) {
    let rows = select_cpu_rows(counters);
    let target_total: u64 = counters
        .iter()
        .map(|counter| counter.select_target_total)
        .sum();
    let prev_total: u64 = counters
        .iter()
        .map(|counter| counter.select_prev_total)
        .sum();
    if target_total == 0 && prev_total == 0 {
        return;
    }

    let target_reason = select_reason_totals(counters, false);
    let prev_reason = select_reason_totals(counters, true);
    let top_target = rows
        .iter()
        .max_by_key(|row| row.target_total)
        .map(|row| format!("C{:02}", row.cpu))
        .unwrap_or_else(|| "-".to_string());
    let top_target_pct = rows
        .iter()
        .max_by_key(|row| row.target_total)
        .map(|row| row.target_pct)
        .unwrap_or(0.0);
    let top_prev = rows
        .iter()
        .max_by_key(|row| row.prev_total)
        .map(|row| format!("C{:02}", row.cpu))
        .unwrap_or_else(|| "-".to_string());
    let top_prev_pct = rows
        .iter()
        .max_by_key(|row| row.prev_total)
        .map(|row| row.prev_pct)
        .unwrap_or(0.0);

    output.push_str(&format!(
        "{}: sampled={:.1}s target_total={} prev_total={} top_target={} {:.1}% top_prev={} {:.1}% target_skew={:.1}x prev_skew={:.1}x\n",
        label,
        elapsed.as_secs_f64(),
        target_total,
        prev_total,
        top_target,
        top_target_pct,
        top_prev,
        top_prev_pct,
        select_balance_ratio(counters, false),
        select_balance_ratio(counters, true),
    ));
    output.push_str(&format!(
        "{}.legend: hm=home_cpu hc=home_core pp=prev_primary ps=primary_scan hy=hybrid_scan kp=kernel_prev ki=kernel_idle tn=tunnel pc=pressure_core\n",
        label
    ));
    output.push_str(&format!(
        "{}.reasons.target: {}\n",
        label,
        format_select_reason_summary(&target_reason)
    ));
    output.push_str(&format!(
        "{}.reasons.prev: {}\n",
        label,
        format_select_reason_summary(&prev_reason)
    ));
    output.push_str(&format!("{}.rows:\n", label));
    for row in rows {
        output.push_str(&format!(
            "  cpu=C{:02} target={} ({:.1}%) prev={} ({:.1}%) tgt={} prev={}\n",
            row.cpu,
            row.target_total,
            row.target_pct,
            row.prev_total,
            row.prev_pct,
            format_select_reason_mix(&row.target_reason, row.target_total),
            format_select_reason_mix(&row.prev_reason, row.prev_total),
        ));
    }
}

fn append_pressure_probe_section(
    output: &mut String,
    label: &str,
    counters: &[CpuWorkCounters],
    totals: &PressureProbeCounters,
    elapsed: Duration,
) {
    let total_eval: u64 = totals.total.iter().map(|site| site[0]).sum();
    if total_eval == 0 {
        return;
    }

    output.push_str(&format!(
        "{}.legend: ev=evaluated ba=anchor(structural blocker) bs=score bd=delta bb=sibling_busy ok=success\n",
        label
    ));

    for site in 0..PRESSURE_SITE_MAX {
        let rows = pressure_probe_rows(counters, site);
        let eval_total = totals.total[site][0];
        if eval_total == 0 {
            continue;
        }

        let accounted_eval: u64 = rows.iter().map(|row| row.eval_total).sum();
        let unattributed = eval_total.saturating_sub(accounted_eval);
        let top_anchor = rows
            .iter()
            .max_by_key(|row| row.eval_total)
            .map(|row| format!("C{:02}", row.cpu))
            .unwrap_or_else(|| "-".to_string());
        let top_anchor_pct = rows
            .iter()
            .max_by_key(|row| row.eval_total)
            .map(|row| row.eval_pct)
            .unwrap_or(0.0);

        output.push_str(&format!(
            "{}.{}: sampled={:.1}s eval={} unattributed={} top_anchor={} {:.1}% eval_skew={:.1}x outcomes={}\n",
            label,
            pressure_probe_site_label(site),
            elapsed.as_secs_f64(),
            eval_total,
            unattributed,
            top_anchor,
            top_anchor_pct,
            pressure_probe_balance_ratio(counters, site),
            format_pressure_probe_summary(&totals.total[site]),
        ));
        output.push_str(&format!(
            "{}.{}.rows:\n",
            label,
            pressure_probe_site_label(site)
        ));
        for row in rows {
            output.push_str(&format!(
                "  cpu=C{:02} eval={} ({:.1}%) outcomes={}\n",
                row.cpu,
                row.eval_total,
                row.eval_pct,
                format_pressure_probe_mix(&row.outcome, row.eval_total),
            ));
        }
    }
}

fn append_local_queue_section(
    output: &mut String,
    label: &str,
    counters: &[CpuWorkCounters],
    elapsed: Duration,
) {
    let rows = local_queue_rows(counters);
    if rows.is_empty() {
        return;
    }

    let secs = elapsed.as_secs_f64().max(0.1);
    let inserts: u64 = counters
        .iter()
        .map(|counter| counter.local_pending_inserts)
        .sum();
    let runs: u64 = counters
        .iter()
        .map(|counter| counter.local_pending_runs)
        .sum();
    let pending_now: u64 = counters
        .iter()
        .map(|counter| counter.local_pending as u64)
        .sum();
    let max_cpu_pending = counters
        .iter()
        .map(|counter| counter.local_pending_max)
        .max()
        .unwrap_or(0);
    let direct: u64 = counters
        .iter()
        .map(|counter| counter.wake_direct_target)
        .sum();
    let busy: u64 = counters
        .iter()
        .map(|counter| counter.wake_busy_target)
        .sum();
    let busy_local: u64 = counters
        .iter()
        .map(|counter| counter.wake_busy_local_target)
        .sum();
    let busy_remote: u64 = counters
        .iter()
        .map(|counter| counter.wake_busy_remote_target)
        .sum();
    let top_pending = rows
        .iter()
        .max_by_key(|row| row.pending)
        .filter(|row| row.pending > 0)
        .map(|row| format!("C{:02}", row.cpu))
        .unwrap_or_else(|| "-".to_string());
    let top_busy = rows
        .iter()
        .max_by_key(|row| row.busy)
        .filter(|row| row.busy > 0)
        .map(|row| format!("C{:02}", row.cpu))
        .unwrap_or_else(|| "-".to_string());
    let top_wait = counters
        .iter()
        .enumerate()
        .max_by_key(|(_, counter)| target_wait_total_ns(counter))
        .filter(|(_, counter)| target_wait_total_ns(counter) > 0)
        .map(|(cpu, _)| format!("C{:02}", cpu))
        .unwrap_or_else(|| "-".to_string());
    let top_pressure = rows
        .iter()
        .max_by_key(|row| row.pressure)
        .filter(|row| row.pressure > 0)
        .map(|row| format!("C{:02}", row.cpu))
        .unwrap_or_else(|| "-".to_string());

    output.push_str(&format!(
        "{}: sampled={:.1}s inserts={} ({:.1}/s) runs_seen={} ({:.1}/s) pending_now={} max_cpu_pending={} wake_target:direct={} busy={} busy_local={} busy_remote={} top_pending={} top_busy={} top_wait={} top_pressure={}\n",
        label,
        elapsed.as_secs_f64(),
        inserts,
        per_sec(inserts, secs),
        runs,
        per_sec(runs, secs),
        pending_now,
        max_cpu_pending,
        direct,
        busy,
        busy_local,
        busy_remote,
        top_pending,
        top_busy,
        top_wait,
        top_pressure,
    ));
    output.push_str(&format!(
        "{}.legend: pend=estimated SCX_DSQ_LOCAL_ON inserts not yet observed running max=per-cpu peak since reset press=cpu_pressure wait=target wake-to-run avg/max/p99bucket(samples)\n",
        label
    ));
    output.push_str(&format!("{}.rows:\n", label));
    for row in rows.iter().take(32) {
        output.push_str(&format!(
            "  cpu=C{:02} press={} pend={} max={} ins={} ({:.1}/s) run_seen={} ({:.1}/s) wake_target[d/b/l/r]={}/{}/{}/{} wait={}\n",
            row.cpu,
            row.pressure,
            row.pending,
            row.pending_max,
            row.inserts,
            per_sec(row.inserts, secs),
            row.runs,
            per_sec(row.runs, secs),
            row.direct,
            row.busy,
            row.busy_local,
            row.busy_remote,
            format_local_queue_wait(row),
        ));
    }
    if rows.len() > 32 {
        output.push_str(&format!("  ... +{} more CPUs\n", rows.len() - 32));
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

fn format_wakewait_summary(sum_ns: &[u64], count: &[u64], max_ns: &[u64]) -> String {
    let mut parts = Vec::new();
    for reason in 1..4 {
        let samples = count[reason];
        let avg_us = if samples > 0 {
            sum_ns[reason] / samples / 1000
        } else {
            0
        };
        let max_us = max_ns[reason] / 1000;
        parts.push(format!(
            "{}={}/{}us({})",
            ["dir", "busy", "queue"][reason - 1],
            avg_us,
            max_us,
            samples
        ));
    }
    parts.join(" ")
}

fn append_cpu_work_section(
    output: &mut String,
    label: &str,
    counters: &[CpuWorkCounters],
    topology: &TopologyInfo,
    cpu_stats: &[(f32, f32)],
    elapsed: Duration,
) {
    let cpu_rows = scheduler_cpu_rows(counters, topology, cpu_stats, elapsed);
    let core_rows = scheduler_core_rows(counters, topology, cpu_stats, elapsed);
    let active_cpu_count = counters
        .iter()
        .filter(|counter| counter.task_runtime_ns > 0 || counter.task_run_count > 0)
        .count();
    let active_core_count = core_rows
        .iter()
        .filter(|row| row.total_runtime_ns > 0 || row.runs > 0)
        .count();
    let total_runtime_ns: u64 = counters.iter().map(|counter| counter.task_runtime_ns).sum();
    let total_runs: u64 = counters.iter().map(|counter| counter.task_run_count).sum();
    let top_cpu = cpu_rows
        .first()
        .map(|row| format!("C{:02} {:.1}%", row.cpu, row.share_pct))
        .unwrap_or_else(|| "-".to_string());
    let top_core = core_rows
        .first()
        .map(|row| format!("K{:02} {:.1}%", row.core, row.share_pct))
        .unwrap_or_else(|| "-".to_string());

    output.push_str(&format!(
        "{}: sampled={:.1}s active_cpu={}/{} active_core={}/{} runtime_ms={} runs={} top_cpu_cake={} top_core_cake={} skew={:.1}x\n",
        label,
        elapsed.as_secs_f64(),
        active_cpu_count,
        counters.len(),
        active_core_count,
        topology.nr_phys_cpus,
        format_runtime_ms(total_runtime_ns),
        total_runs,
        top_cpu,
        top_core,
        scheduler_balance_ratio(counters),
    ));
    output.push_str(&format!(
        "{}.legend: cake=tracked runtime share sys=system cpu load hot_thr=share on the busier sibling sib=share on the SMT sibling q%[f/b/p]=quantum full/blocked/preempt mix\n",
        label
    ));
    output.push_str(&format!("{}.rows:\n", label));
    for row in &cpu_rows {
        output.push_str(&format!(
            "  cpu=C{:02} core={} llc={} thr={} cake={:.1}% runs={} runs/s={:.1} runtime_ms={} avg_run_us={} q%[f/b/p]={:.0}/{:.0}/{:.0} q[f/b/p]={}/{}/{} sys={:.0}% temp={:.0}C\n",
            row.cpu,
            row.core,
            row.llc,
            if row.is_secondary_smt { "smt2" } else { "prim" },
            row.share_pct,
            row.runs,
            row.runs_per_sec,
            format_runtime_ms(row.total_runtime_ns),
            row.avg_run_us,
            row.full_pct,
            row.yield_pct,
            row.preempt_pct,
            counters[row.cpu].quantum_full,
            counters[row.cpu].quantum_yield,
            counters[row.cpu].quantum_preempt,
            row.system_load,
            row.temp_c,
        ));
    }
    output.push_str(&format!("{}.cores:\n", label));
    for row in &core_rows {
        output.push_str(&format!(
            "  core=K{:02} cpus={} cake={:.1}% runs={} runs/s={:.1} runtime_ms={} avg_run_us={} q%[f/b/p]={:.0}/{:.0}/{:.0} hot_thr={:.0}% sib={:.0}% sys={:.0}%\n",
            row.core,
            row.cpu_label,
            row.share_pct,
            row.runs,
            row.runs_per_sec,
            format_runtime_ms(row.total_runtime_ns),
            row.avg_run_us,
            row.full_pct,
            row.yield_pct,
            row.preempt_pct,
            row.top_cpu_share_pct,
            row.secondary_smt_pct,
            row.avg_system_load,
        ));
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
    let queue_net = signed_diff_u64(stats.nr_dsq_queued, stats.nr_dsq_consumed);

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
        "win.queue.shared: depth_now={} in={} ({:.1}/s) out={} ({:.1}/s) net={:+} ({:+.1}/s)\n",
        queue_now,
        stats.nr_dsq_queued,
        per_sec(stats.nr_dsq_queued, secs),
        stats.nr_dsq_consumed,
        per_sec(stats.nr_dsq_consumed, secs),
        queue_net,
        queue_net as f64 / secs,
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
    output.push_str(&format!(
        "win.wakewait.all: {}\n",
        format_wakewait_summary(
            &stats.wake_reason_wait_all_ns,
            &stats.wake_reason_wait_all_count,
            &stats.wake_reason_wait_all_max_ns,
        )
    ));
    output.push_str(&format!(
        "win.wakewait<=5ms: {}\n",
        format_wakewait_summary(
            &stats.wake_reason_wait_ns,
            &stats.wake_reason_wait_count,
            &stats.wake_reason_wait_max_ns,
        )
    ));
    let quantum_total = stats.nr_quantum_full + stats.nr_quantum_yield + stats.nr_quantum_preempt;
    output.push_str(&format!(
        "win.slice: full={} ({:.1}%) blocked={} ({:.1}%) preempt={} ({:.1}%) sched_yield={} kick:wake[i/p]={}/{} affine[i/p]={}/{}\n",
        stats.nr_quantum_full,
        pct(stats.nr_quantum_full, quantum_total),
        stats.nr_quantum_yield,
        pct(stats.nr_quantum_yield, quantum_total),
        stats.nr_quantum_preempt,
        pct(stats.nr_quantum_preempt, quantum_total),
        stats.nr_sched_yield_calls,
        stats.nr_wake_kick_idle,
        stats.nr_wake_kick_preempt,
        stats.nr_affine_kick_idle,
        stats.nr_affine_kick_preempt,
    ));
    output.push_str(&format!(
        "win.wakebins: {}\n",
        format_wake_bucket_summary(&stats.wake_reason_bucket_count)
    ));
    output.push_str(&format!(
        "win.postwake.target_hit/miss: {}  win.postwake.follow_same/mig: {}\n",
        format_wake_target_summary(&stats.wake_target_hit_count, &stats.wake_target_miss_count),
        format_wake_followup_summary(
            &stats.wake_followup_same_cpu_count,
            &stats.wake_followup_migrate_count,
        )
    ));
    output.push_str(&format!(
        "win.kickrun: idle={}/{} avg={}us max={}us preempt={}/{} avg={}us max={}us\n",
        stats.nr_wake_kick_quick[1],
        stats.nr_wake_kick_observed[1],
        bucket_avg_us(
            stats.total_wake_kick_to_run_ns[1],
            stats.nr_wake_kick_observed[1]
        ),
        stats.max_wake_kick_to_run_ns[1] / 1000,
        stats.nr_wake_kick_quick[2],
        stats.nr_wake_kick_observed[2],
        bucket_avg_us(
            stats.total_wake_kick_to_run_ns[2],
            stats.nr_wake_kick_observed[2]
        ),
        stats.max_wake_kick_to_run_ns[2] / 1000,
    ));
    output.push_str(&format!(
        "win.kickbins: {}\n",
        format_kick_bucket_summary(&stats.wake_kick_bucket_count)
    ));
    output.push_str(&format!(
        "win.path: {}  deps:same_tgid={} ({:.1}/s) cross_tgid={} ({:.1}/s)\n",
        format_path_summary(&stats.select_path_count),
        stats.nr_wake_same_tgid,
        per_sec(stats.nr_wake_same_tgid, secs),
        stats.nr_wake_cross_tgid,
        per_sec(stats.nr_wake_cross_tgid, secs),
    ));
    output.push_str(&format!(
        "win.place.home.wait<=5ms: {}\n",
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
        "win.place.waker.wait<=5ms: {}\n",
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
    let tgid_roles = infer_tgid_roles(&app.task_rows);
    let cap = capacity_summary(app, &tgid_roles);

    let mut output = String::new();
    output.push_str(&app.system_info.format_header());

    output.push_str(&format!(
        "cake: uptime={} state=IDLE detector=disabled\n",
        app.format_uptime(),
    ));
    output.push_str("scope: lifetime\n");
    output.push_str(
        "capture: global=exact task.life=exact task.rate=delta_per_tick task.stage=latest_observed wakewait.all=exact wakewait<=5ms=bounded localq=debug_estimate windows=delta_snapshots history=rolling_1s_samples\n",
    );
    output.push_str(
        "task.fields: latest={LASTWus,SELns,ENQns,STOPns,RUNns,GAPus,path/place} rate={RUN/s,MIG/s} life={MAXRTus,JITus,wakeus<=5ms,WHIST,Qf/b/p,SYLD,cpu/core spread}\n",
    );
    output.push_str(
        "slice.meaning: blocked=task stopped with slice left and was not runnable; sched_yield=explicit cake_yield callback count\n",
    );
    let life_elapsed = app.start_time.elapsed().max(Duration::from_secs(1));
    let life_cpu_rows = scheduler_cpu_rows(
        &app.per_cpu_work,
        &app.topology,
        &app.cpu_stats,
        life_elapsed,
    );
    let life_core_rows = scheduler_core_rows(
        &app.per_cpu_work,
        &app.topology,
        &app.cpu_stats,
        life_elapsed,
    );
    let life_balance = build_balance_diagnosis(&life_cpu_rows, &life_core_rows);
    let timeline_window = Duration::from_secs(60);
    let timeline_step = Duration::from_secs(1);
    let timeline_samples = app.timeline_samples(timeline_window, timeline_step);
    let timeline_expected = expected_timeline_samples(timeline_window, timeline_step);
    let timeline_span = timeline_history_span(&app.timeline_history);

    // Compact dispatch stats
    let dsq_depth = stats.nr_dsq_queued.saturating_sub(stats.nr_dsq_consumed);
    let queue_net = signed_diff_u64(stats.nr_dsq_queued, stats.nr_dsq_consumed);
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
    output.push_str(&format!(
        "queue.shared: depth_now={} in={} out={} net={:+}\n",
        dsq_depth, stats.nr_dsq_queued, stats.nr_dsq_consumed, queue_net,
    ));

    // Compact callback profile (totals + averages)
    let stop_total = stats.nr_stop_deferred_skip + stats.nr_stop_deferred;
    output.push_str(&format!(
        "cb.stop: tot_µs={} max_ns={} calls={} task_telemetry={} sampled_skip={}\n",
        stats.total_stopping_ns / 1000,
        stats.max_stopping_ns,
        stop_total,
        if stats.nr_stop_deferred_skip == 0 {
            "exact"
        } else {
            "mixed"
        },
        stats.nr_stop_deferred_skip,
    ));
    output.push_str(&format!(
        "cb.run: tot_µs={} max_ns={} calls={}  cb.enq: tot_µs={} calls={}  sel: tot_µs={} g1_µs={} g2_µs={} calls={}  cb.disp: tot_µs={} max_ns={} calls={}\n",
        stats.total_running_ns / 1000, stats.max_running_ns, stats.nr_running_calls,
        stats.total_enqueue_latency_ns / 1000, stats.nr_enqueue_calls,
        stats.total_select_cpu_ns / 1000, stats.total_gate1_latency_ns / 1000, stats.total_gate2_latency_ns / 1000, stats.nr_select_cpu_calls,
        stats.total_dispatch_ns / 1000, stats.max_dispatch_ns, stats.nr_dispatch_calls,
    ));
    output.push_str(&format!(
        "cb.avg: sel={}ns enq={}ns disp={}ns run={}ns stop={}ns\n",
        avg_ns(stats.total_select_cpu_ns, stats.nr_select_cpu_calls),
        avg_ns(stats.total_enqueue_latency_ns, stats.nr_enqueue_calls),
        avg_ns(stats.total_dispatch_ns, stats.nr_dispatch_calls),
        avg_ns(stats.total_running_ns, stats.nr_running_calls),
        avg_ns(stats.total_stopping_ns, stop_total),
    ));
    output.push_str(&format!(
        "cb.hist: sel[{}] enq[{}] disp[{}] run[{}] stop[{}]\n",
        callback_hist_summary(stats, 0),
        callback_hist_summary(stats, 1),
        callback_hist_summary(stats, 2),
        callback_hist_summary(stats, 3),
        callback_hist_summary(stats, 4),
    ));
    output.push_str(&format!(
        "wakewait.all: {}\n",
        format_wakewait_summary(
            &stats.wake_reason_wait_all_ns,
            &stats.wake_reason_wait_all_count,
            &stats.wake_reason_wait_all_max_ns,
        )
    ));
    output.push_str(&format!(
        "wakewait<=5ms: {}\n",
        format_wakewait_summary(
            &stats.wake_reason_wait_ns,
            &stats.wake_reason_wait_count,
            &stats.wake_reason_wait_max_ns,
        )
    ));
    let quantum_total = stats.nr_quantum_full + stats.nr_quantum_yield + stats.nr_quantum_preempt;
    output.push_str(&format!(
        "slice: full={} ({:.1}%) blocked={} ({:.1}%) preempt={} ({:.1}%) sched_yield={} kick:wake[i/p]={}/{} affine[i/p]={}/{}\n",
        stats.nr_quantum_full,
        pct(stats.nr_quantum_full, quantum_total),
        stats.nr_quantum_yield,
        pct(stats.nr_quantum_yield, quantum_total),
        stats.nr_quantum_preempt,
        pct(stats.nr_quantum_preempt, quantum_total),
        stats.nr_sched_yield_calls,
        stats.nr_wake_kick_idle,
        stats.nr_wake_kick_preempt,
        stats.nr_affine_kick_idle,
        stats.nr_affine_kick_preempt,
    ));
    output.push_str(&format!(
        "wakebins: {}\n",
        format_wake_bucket_summary(&stats.wake_reason_bucket_count)
    ));
    output.push_str(&format!(
        "postwake.target_hit/miss: {}  postwake.follow_same/mig: {}\n",
        format_wake_target_summary(&stats.wake_target_hit_count, &stats.wake_target_miss_count),
        format_wake_followup_summary(
            &stats.wake_followup_same_cpu_count,
            &stats.wake_followup_migrate_count,
        )
    ));
    output.push_str(&format!(
        "kickrun: idle={}/{} avg={}us max={}us  preempt={}/{} avg={}us max={}us\n",
        stats.nr_wake_kick_quick[1],
        stats.nr_wake_kick_observed[1],
        bucket_avg_us(
            stats.total_wake_kick_to_run_ns[1],
            stats.nr_wake_kick_observed[1]
        ),
        stats.max_wake_kick_to_run_ns[1] / 1000,
        stats.nr_wake_kick_quick[2],
        stats.nr_wake_kick_observed[2],
        bucket_avg_us(
            stats.total_wake_kick_to_run_ns[2],
            stats.nr_wake_kick_observed[2]
        ),
        stats.max_wake_kick_to_run_ns[2] / 1000,
    ));
    output.push_str(&format!(
        "kickbins: {}\n",
        format_kick_bucket_summary(&stats.wake_kick_bucket_count)
    ));
    output.push_str(&format!(
        "place.path: {}  deps:same_tgid={} cross_tgid={}\n",
        format_path_summary(&stats.select_path_count),
        stats.nr_wake_same_tgid,
        stats.nr_wake_cross_tgid,
    ));
    output.push_str(&format!(
        "place.home.wait<=5ms: {}\n",
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
        "place.waker.wait<=5ms: {}\n",
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
        "cap: hard_tasks={} hard_hot={} soft_tasks={} soft_hot={} build_tasks={} build_hot={} shared_top_cores={} build_shared={} hard_smt={} hard_scatter={} focus_scatter={}\n",
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
    output.push_str(&format!(
        "context: lifetime_sampled={:.1}s cpu_work_life={:.1}s timeline_history={} timeline_span={:.1}s avg_step={:.2}s last60s_coverage={}/{}\n",
        app.start_time.elapsed().as_secs_f64(),
        life_elapsed.as_secs_f64(),
        app.timeline_history.len(),
        timeline_span.as_secs_f64(),
        if app.timeline_history.is_empty() {
            0.0
        } else {
            timeline_span.as_secs_f64() / app.timeline_history.len() as f64
        },
        timeline_samples.len(),
        timeline_expected,
    ));
    if let Some(diag) = &life_balance {
        output.push_str(&format!(
            "balance.life: driver={} top_cpu={} {:.1}% {}us {:.1}/s top_rate_cpu={} {:.1}/s {}us top_core={} {:.1}% hot_thr={:.0}% sib={:.0}% top_rate_core={} {:.1}/s cpu_skew={:.1}x core_skew={:.1}x hot/cold cpu={}/{} core={}/{} sticky_core={} hard_scatter={} focus_scatter={} hard_smt={}\n",
            diag.driver,
            diag.top_cpu_share_label,
            diag.top_cpu_share_pct,
            diag.top_cpu_avg_run_us,
            diag.top_cpu_runs_per_sec,
            diag.top_cpu_rate_label,
            diag.top_cpu_rate_runs_per_sec,
            diag.top_cpu_rate_avg_run_us,
            diag.top_core_share_label,
            diag.top_core_share_pct,
            diag.top_core_hot_thr_pct,
            diag.top_core_sib_pct,
            diag.top_core_rate_label,
            diag.top_core_rate_runs_per_sec,
            diag.cpu_skew,
            diag.core_skew,
            diag.hot_cpu_count,
            diag.cold_cpu_count,
            diag.hot_core_count,
            diag.cold_core_count,
            if diag.sticky_core { "yes" } else { "no" },
            cap.hard_latency_scattered,
            cap.focus_scattered,
            cap.hard_latency_smt_heavy,
        ));
    }
    append_cpu_work_section(
        &mut output,
        "cpu.work.life",
        &app.per_cpu_work,
        &app.topology,
        &app.cpu_stats,
        app.start_time.elapsed(),
    );
    append_local_queue_section(
        &mut output,
        "localq.life",
        &app.per_cpu_work,
        app.start_time.elapsed(),
    );
    append_select_cpu_section(
        &mut output,
        "select.life",
        &app.per_cpu_work,
        app.start_time.elapsed(),
    );
    append_pressure_probe_section(
        &mut output,
        "pressure.life",
        &app.per_cpu_work,
        &app.pressure_probe,
        app.start_time.elapsed(),
    );
    if let Some((elapsed, delta)) = app.windowed_stats(stats, Duration::from_secs(30)) {
        append_window_stats(&mut output, "30s", elapsed, &delta, dsq_depth);
    }
    if let Some((elapsed, delta)) = app.windowed_stats(stats, Duration::from_secs(60)) {
        append_window_stats(&mut output, "60s", elapsed, &delta, dsq_depth);
    }
    if let Some((elapsed, window)) = app.cpu_work_window(Duration::from_secs(60)) {
        let cpu_rows_60 = scheduler_cpu_rows(&window, &app.topology, &app.cpu_stats, elapsed);
        let core_rows_60 = scheduler_core_rows(&window, &app.topology, &app.cpu_stats, elapsed);
        if let Some(diag) = build_balance_diagnosis(&cpu_rows_60, &core_rows_60) {
            output.push_str(&format!(
                "balance.60s: sampled={:.1}s driver={} top_cpu={} {:.1}% {}us {:.1}/s top_rate_cpu={} {:.1}/s {}us top_core={} {:.1}% hot_thr={:.0}% sib={:.0}% top_rate_core={} {:.1}/s cpu_skew={:.1}x core_skew={:.1}x hot/cold cpu={}/{} core={}/{} sticky_core={}\n",
                elapsed.as_secs_f64(),
                diag.driver,
                diag.top_cpu_share_label,
                diag.top_cpu_share_pct,
                diag.top_cpu_avg_run_us,
                diag.top_cpu_runs_per_sec,
                diag.top_cpu_rate_label,
                diag.top_cpu_rate_runs_per_sec,
                diag.top_cpu_rate_avg_run_us,
                diag.top_core_share_label,
                diag.top_core_share_pct,
                diag.top_core_hot_thr_pct,
                diag.top_core_sib_pct,
                diag.top_core_rate_label,
                diag.top_core_rate_runs_per_sec,
                diag.cpu_skew,
                diag.core_skew,
                diag.hot_cpu_count,
                diag.cold_cpu_count,
                diag.hot_core_count,
                diag.cold_core_count,
                if diag.sticky_core { "yes" } else { "no" },
            ));
        }
        append_cpu_work_section(
            &mut output,
            "cpu.work.60s",
            &window,
            &app.topology,
            &app.cpu_stats,
            elapsed,
        );
        append_local_queue_section(&mut output, "localq.60s", &window, elapsed);
        append_select_cpu_section(&mut output, "select.60s", &window, elapsed);
        if let Some((pressure_elapsed, pressure_window)) =
            app.pressure_probe_window(Duration::from_secs(60))
        {
            append_pressure_probe_section(
                &mut output,
                "pressure.60s",
                &window,
                &pressure_window,
                pressure_elapsed,
            );
        }
    }
    if let Some(summary_lines) = summarize_timeline_samples(&timeline_samples, timeline_expected) {
        output.push_str("\nwindow: last60s sampled=rolling_1s history=latest_60\n");
        for line in summary_lines {
            output.push_str(&line.to_string());
            output.push('\n');
        }
        output.push_str(
            "timeline.cols: [slot span run/s wake/s wake%=dir/busy/q path%=home/core/prim/idle/tun cbns=sel/enq/run/stop waitus<=5ms=dir/busy/q slice%=full/block/preempt]\n",
        );
        for sample in &timeline_samples {
            output.push_str(&format!("{}\n", format_timeline_sample_row(sample)));
        }
    }
    if !app.debug_events.is_empty() {
        output.push_str("events:\n");
        for ev in app.debug_events.iter().take(8) {
            output.push_str(&format!(
                "  ts={} pid={} {}\n",
                ev.ts_ns,
                ev.pid,
                debug_event_label(ev)
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
        "       [detail: ROLE STEER(home/primary) DIRECT Q[f/b/p] SYLD PRMPT MASK MAXGAPus DSQINSns RUNS SUTIL% LLC/COUNT PLACE(cpu/core dist) STREAK WAKER TGID CLS V/ICSW WAKEus<=5ms(dir/busy/q) HWAIT<=5ms WHIST]\n",
    );

    let all_dump_pids: Vec<u32> = app
        .task_rows
        .iter()
        .filter(|(_, row)| row.is_bpf_tracked && row.total_runs > 0)
        .map(|(pid, _)| *pid)
        .collect();
    let dead_hidden = all_dump_pids
        .iter()
        .filter(|pid| {
            app.task_rows
                .get(pid)
                .map(|row| row.status == TaskStatus::Dead)
                .unwrap_or(false)
        })
        .count();
    // Prefer live rows so dump reviews stay benchmark-focused even if stale tasks are retained in TUI state.
    let mut dump_pids: Vec<u32> = all_dump_pids
        .iter()
        .copied()
        .filter(|pid| {
            app.task_rows
                .get(pid)
                .map(|row| row.status != TaskStatus::Dead)
                .unwrap_or(false)
        })
        .collect();
    let live_only = !dump_pids.is_empty();
    if !live_only {
        dump_pids = all_dump_pids.clone();
    }
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
    let dump_group_count = tgid_rank.len();
    output.push_str(&format!(
        "dump: full {} of {} {} BPF-tracked rows across {} TGIDs ordered by grouped PELT activity dead_hidden={}\n",
        dump_pids.len(),
        dump_total_rows,
        if live_only { "live" } else { "tracked" },
        dump_group_count,
        dead_hidden,
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
                "{}  role={}/{} steer={}/{} path={}/{} waker={} deps={}/{} dir={} q={}/{}/{} syld={} prmpt={} mask={} maxgap={} dsqins={}ns runs={} sutil={}% llc=L{:02}/{} place=[{}|{} smt={}%] streak={} tgid={} cls={} v/icsw={}/{} wakeus<=5ms={}/{}/{} hwait<=5ms=[{}] whist={}/{}/{}/{}\n",
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
                row.direct_dispatch_count,
                row.quantum_full_count,
                row.quantum_yield_count,
                row.quantum_preempt_count,
                row.yield_count,
                row.preempt_count,
                row.cpumask_change_count,
                display_gap_us(row.max_dispatch_gap_us), row.dsq_insert_ns, row.total_runs,
                slice_util_display_pct(row.slice_util_pct),
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
            Constraint::Length(4), // Footer
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
        SortColumn::Pid => format!("PID {}", arrow),
        SortColumn::Pelt => format!("PELT {}", arrow),
        SortColumn::MaxRuntime => format!("MAXµs {}", arrow),
        SortColumn::Jitter => format!("JITµs {}", arrow),
        SortColumn::Wait => format!("WAITµs {}", arrow),
        SortColumn::RunsPerSec => format!("RUN/s {}", arrow),
        SortColumn::TargetCpu => format!("CPU {}", arrow),
        SortColumn::Spread => format!("SPRD {}", arrow),
        SortColumn::Residency => format!("RES% {}", arrow),
        SortColumn::SelectCpu => format!("SELns {}", arrow),
        SortColumn::Enqueue => format!("ENQns {}", arrow),
        SortColumn::Gap => format!("GAPµs {}", arrow),
        SortColumn::Gate1Pct => format!("G1% {}", arrow),
        SortColumn::Class => format!("CLS {}", arrow),
        SortColumn::Migrations => format!("MIG/s {}", arrow),
    };

    let (fg_color, border_color) = if app.get_status().is_some() {
        (Color::Green, Color::Green)
    } else {
        (Color::DarkGray, Color::DarkGray)
    };

    let footer_line1 = Line::from(vec![
        dashboard_label("Sort "),
        footer_key("s"),
        dashboard_note(" next "),
        footer_key("S"),
        dashboard_note(" reverse "),
        dashboard_sep("  "),
        dashboard_label("Current "),
        dashboard_value(sort_label, Style::default().fg(Color::Yellow)),
        dashboard_sep("  |  "),
        dashboard_label("Move "),
        footer_key("↑↓"),
        dashboard_note(" rows "),
        footer_key("T"),
        dashboard_note(" top "),
        footer_key("Tab"),
        dashboard_note(" views"),
    ]);

    let mut footer_line2 = Vec::new();
    if let Some(status) = app.get_status() {
        footer_line2.push(dashboard_label("Status "));
        footer_line2.push(dashboard_value(status, Style::default().fg(Color::Green)));
        footer_line2.push(dashboard_sep("  |  "));
    }
    footer_line2.extend([
        dashboard_label("Groups "),
        footer_key("Enter"),
        dashboard_note(" parent "),
        footer_key("Space"),
        dashboard_note(" threads "),
        footer_key("x"),
        dashboard_note(" clear "),
        dashboard_sep("  |  "),
        dashboard_label("Data "),
        footer_key("f"),
        dashboard_note(" filter "),
        footer_key("c"),
        dashboard_note(" copy "),
        footer_key("d"),
        dashboard_note(" dump "),
        footer_key("b"),
        dashboard_note(" bench "),
        footer_key("r"),
        dashboard_note(" reset "),
        footer_key("q"),
        dashboard_note(" quit"),
    ]);

    let footer = Paragraph::new(vec![footer_line1, Line::from(footer_line2)])
        .style(Style::default().fg(fg_color))
        .wrap(Wrap { trim: false })
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(border_color))
                .border_type(BorderType::Rounded)
                .padding(Padding::new(1, 1, 0, 0)),
        );
    frame.render_widget(footer, main_layout[2]);
}

fn dashboard_block<'a>(title: &'a str, accent: Color) -> Block<'a> {
    Block::default()
        .title(format!(" {} ", title))
        .title_style(Style::default().fg(accent).add_modifier(Modifier::BOLD))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::DarkGray))
        .border_type(BorderType::Rounded)
        .padding(Padding::new(1, 1, 0, 0))
}

fn draw_dashboard_tab(frame: &mut Frame, app: &mut TuiApp, stats: &cake_stats, area: Rect) {
    let tgid_roles = infer_tgid_roles(&app.task_rows);
    let minute_window = Duration::from_secs(60);
    let minute_step = Duration::from_secs(1);
    let minute_samples = app.timeline_samples(minute_window, minute_step);
    let minute_expected = expected_timeline_samples(minute_window, minute_step);
    let minute_avg_step = average_timeline_sample_secs(&minute_samples);
    let minute_history_span = timeline_history_span(&app.timeline_history);
    let (balance_scope, balance_diag) =
        if let Some((elapsed, window)) = app.cpu_work_window(Duration::from_secs(60)) {
            let cpu_rows = scheduler_cpu_rows(&window, &app.topology, &app.cpu_stats, elapsed);
            let core_rows = scheduler_core_rows(&window, &app.topology, &app.cpu_stats, elapsed);
            (
                format!("{:.0}s", elapsed.as_secs_f64()),
                build_balance_diagnosis(&cpu_rows, &core_rows),
            )
        } else {
            let elapsed = app.start_time.elapsed().max(Duration::from_secs(1));
            let cpu_rows =
                scheduler_cpu_rows(&app.per_cpu_work, &app.topology, &app.cpu_stats, elapsed);
            let core_rows =
                scheduler_core_rows(&app.per_cpu_work, &app.topology, &app.cpu_stats, elapsed);
            (
                "life".to_string(),
                build_balance_diagnosis(&cpu_rows, &core_rows),
            )
        };

    let total_dsq_dispatches = stats.nr_local_dispatches + stats.nr_stolen_dispatches;
    let wake_total = stats.nr_wakeup_direct_dispatches
        + stats.nr_wakeup_dsq_fallback_busy
        + stats.nr_wakeup_dsq_fallback_queued;
    let dsq_depth = stats.nr_dsq_queued.saturating_sub(stats.nr_dsq_consumed);
    let path_total: u64 = stats.select_path_count[1..6].iter().sum();
    let quantum_total = stats.nr_quantum_full + stats.nr_quantum_yield + stats.nr_quantum_preempt;

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

    let outer_layout = Layout::vertical([
        Constraint::Length(10),
        Constraint::Length(11),
        Constraint::Min(10),
    ])
    .split(area);

    let summary_rows =
        Layout::vertical([Constraint::Length(5), Constraint::Length(5)]).split(outer_layout[0]);
    let summary_top = Layout::horizontal([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(summary_rows[0]);
    let summary_bottom =
        Layout::horizontal([Constraint::Percentage(50), Constraint::Percentage(50)])
            .split(summary_rows[1]);

    let queue_style = if dsq_depth <= 4 {
        Style::default().fg(Color::Green)
    } else if dsq_depth <= 10 {
        Style::default().fg(Color::Yellow)
    } else {
        Style::default().fg(Color::LightRed)
    };
    let shared_queue_net = signed_diff_u64(stats.nr_dsq_queued, stats.nr_dsq_consumed);
    let shared_queue_net_style = if shared_queue_net > 0 {
        Style::default().fg(Color::Yellow)
    } else if shared_queue_net < 0 {
        Style::default().fg(Color::Green)
    } else {
        Style::default().fg(Color::Cyan)
    };
    let runtime_panel = Paragraph::new(vec![
        Line::from(vec![
            dashboard_label("Topology "),
            dashboard_value(topo_flags, Style::default().fg(Color::Cyan)),
            dashboard_sep("  "),
            dashboard_label("Uptime "),
            dashboard_value(app.format_uptime(), Style::default().fg(Color::LightCyan)),
        ]),
        Line::from(vec![
            dashboard_label("Tracked tasks "),
            dashboard_value(
                app.bpf_task_count.to_string(),
                Style::default().fg(Color::Green),
            ),
            dashboard_sep("  "),
            dashboard_label("Arena "),
            dashboard_value(
                app.arena_active.to_string(),
                Style::default().fg(Color::Yellow),
            ),
            dashboard_sep("  "),
            dashboard_label("View "),
            dashboard_value(
                app.task_filter.label(),
                Style::default().fg(Color::LightMagenta),
            ),
        ]),
        Line::from({
            let mut spans = vec![
                dashboard_label("Queue depth "),
                dashboard_value(dsq_depth.to_string(), queue_style),
                dashboard_sep("  "),
                dashboard_label("PELT bands "),
                dashboard_value(
                    format!("idle {}", wc0),
                    Style::default().fg(Color::LightCyan),
                ),
                dashboard_sep("  "),
                dashboard_value(format!("light {}", wc1), Style::default().fg(Color::Green)),
                dashboard_sep("  "),
                dashboard_value(format!("busy {}", wc2), Style::default().fg(Color::Yellow)),
                dashboard_sep("  "),
                dashboard_value(format!("hot {}", wc3), Style::default().fg(Color::LightRed)),
            ];
            if stats.nr_dropped_allocations > 0 {
                spans.push(dashboard_sep("  "));
                spans.push(dashboard_label("ENOMEM "));
                spans.push(dashboard_value(
                    stats.nr_dropped_allocations.to_string(),
                    Style::default().fg(Color::LightRed),
                ));
            }
            spans
        }),
    ])
    .style(Style::default().fg(Color::Gray))
    .block(dashboard_block("Runtime", Color::Cyan))
    .wrap(Wrap { trim: false });
    frame.render_widget(runtime_panel, summary_top[0]);

    let dispatch_panel = Paragraph::new(vec![
        Line::from(vec![
            dashboard_label("Dispatches "),
            dashboard_value(
                total_dsq_dispatches.to_string(),
                Style::default().fg(Color::Yellow),
            ),
            dashboard_sep("  "),
            dashboard_label("local / steal / miss "),
            dashboard_value(
                format!(
                    "{} / {} / {}",
                    stats.nr_local_dispatches, stats.nr_stolen_dispatches, stats.nr_dispatch_misses
                ),
                Style::default().fg(Color::LightCyan),
            ),
        ]),
        Line::from(vec![
            dashboard_label("Shared Q depth/in/out/net "),
            dashboard_value(
                format!(
                    "{} / {} / {} / {:+}",
                    dsq_depth, stats.nr_dsq_queued, stats.nr_dsq_consumed, shared_queue_net
                ),
                shared_queue_net_style,
            ),
        ]),
        Line::from(vec![
            dashboard_label("Wake d/b/q "),
            dashboard_value(
                format!(
                    "{:.0}/{:.0}/{:.0}%",
                    pct(stats.nr_wakeup_direct_dispatches, wake_total),
                    pct(stats.nr_wakeup_dsq_fallback_busy, wake_total),
                    pct(stats.nr_wakeup_dsq_fallback_queued, wake_total)
                ),
                Style::default().fg(Color::Green),
            ),
            dashboard_sep("  "),
            dashboard_label("Path h/i/t "),
            dashboard_value(
                format!(
                    "{:.0}/{:.0}/{:.0}%",
                    pct(stats.select_path_count[1], path_total),
                    pct(stats.select_path_count[4], path_total),
                    pct(stats.select_path_count[5], path_total)
                ),
                Style::default().fg(Color::Cyan),
            ),
            dashboard_sep("  "),
            dashboard_label("steer home "),
            dashboard_value(
                format!(
                    "{:.0}%",
                    pct(stats.nr_home_cpu_steers, stats.nr_steer_eligible)
                ),
                Style::default().fg(Color::Yellow),
            ),
        ]),
    ])
    .style(Style::default().fg(Color::Gray))
    .block(dashboard_block("Dispatch", Color::Yellow))
    .wrap(Wrap { trim: false });
    frame.render_widget(dispatch_panel, summary_top[1]);

    let select_avg = avg_ns(stats.total_select_cpu_ns, stats.nr_select_cpu_calls);
    let enqueue_avg = avg_ns(stats.total_enqueue_latency_ns, stats.nr_enqueue_calls);
    let running_avg = avg_ns(stats.total_running_ns, stats.nr_running_calls);
    let stopping_avg = avg_ns(stats.total_stopping_ns, stats.nr_stopping_calls);
    let dir_wait_us = bucket_avg_us(
        stats.wake_reason_wait_ns[1],
        stats.wake_reason_wait_count[1],
    );
    let busy_wait_us = bucket_avg_us(
        stats.wake_reason_wait_ns[2],
        stats.wake_reason_wait_count[2],
    );
    let queue_wait_us = bucket_avg_us(
        stats.wake_reason_wait_ns[3],
        stats.wake_reason_wait_count[3],
    );
    let timing_panel = Paragraph::new(vec![
        Line::from(vec![
            dashboard_label("Callback avg "),
            dashboard_value(
                format!("select {}ns", select_avg),
                low_is_good_style(select_avg, 1_000, 5_000),
            ),
            dashboard_sep("  "),
            dashboard_value(
                format!("enqueue {}ns", enqueue_avg),
                low_is_good_style(enqueue_avg, 1_000, 5_000),
            ),
        ]),
        Line::from(vec![
            dashboard_label("Callback avg "),
            dashboard_value(
                format!("running {}ns", running_avg),
                low_is_good_style(running_avg, 1_000, 5_000),
            ),
            dashboard_sep("  "),
            dashboard_value(
                format!("stopping {}ns", stopping_avg),
                low_is_good_style(stopping_avg, 1_000, 5_000),
            ),
        ]),
        Line::from(vec![
            dashboard_label("Wake wait avg "),
            dashboard_value(
                format!("direct {}us", dir_wait_us),
                low_is_good_style(dir_wait_us, 10, 100),
            ),
            dashboard_sep("  "),
            dashboard_value(
                format!("busy {}us", busy_wait_us),
                low_is_good_style(busy_wait_us, 10, 100),
            ),
            dashboard_sep("  "),
            dashboard_value(
                format!("queue {}us", queue_wait_us),
                low_is_good_style(queue_wait_us, 10, 100),
            ),
        ]),
    ])
    .style(Style::default().fg(Color::Gray))
    .block(dashboard_block("Timing", Color::Green))
    .wrap(Wrap { trim: false });
    frame.render_widget(timing_panel, summary_bottom[0]);

    let health_panel = Paragraph::new(vec![
        Line::from(vec![
            dashboard_label("Quantum outcome "),
            dashboard_value(
                format!("full {:.0}%", pct(stats.nr_quantum_full, quantum_total)),
                Style::default().fg(Color::Green),
            ),
            dashboard_sep("  "),
            dashboard_value(
                format!("block {:.0}%", pct(stats.nr_quantum_yield, quantum_total)),
                Style::default().fg(Color::Yellow),
            ),
            dashboard_sep("  "),
            dashboard_value(
                format!(
                    "preempt {:.0}%",
                    pct(stats.nr_quantum_preempt, quantum_total)
                ),
                Style::default().fg(Color::LightRed),
            ),
        ]),
        Line::from(vec![
            dashboard_label("Literal sched_yield "),
            dashboard_value(
                stats.nr_sched_yield_calls.to_string(),
                Style::default().fg(Color::Yellow),
            ),
            dashboard_sep("  "),
            dashboard_label("Kick-to-run avg "),
            dashboard_value(
                format!(
                    "idle {}us",
                    bucket_avg_us(
                        stats.total_wake_kick_to_run_ns[1],
                        stats.nr_wake_kick_observed[1]
                    )
                ),
                low_is_good_style(
                    bucket_avg_us(
                        stats.total_wake_kick_to_run_ns[1],
                        stats.nr_wake_kick_observed[1],
                    ),
                    10,
                    100,
                ),
            ),
            dashboard_sep("  "),
            dashboard_value(
                format!(
                    "preempt {}us",
                    bucket_avg_us(
                        stats.total_wake_kick_to_run_ns[2],
                        stats.nr_wake_kick_observed[2]
                    )
                ),
                low_is_good_style(
                    bucket_avg_us(
                        stats.total_wake_kick_to_run_ns[2],
                        stats.nr_wake_kick_observed[2],
                    ),
                    10,
                    100,
                ),
            ),
        ]),
        Line::from(vec![
            dashboard_label("Target hit / miss "),
            dashboard_value(
                format!(
                    "direct {}/{}",
                    stats.wake_target_hit_count[1], stats.wake_target_miss_count[1]
                ),
                Style::default().fg(Color::Cyan),
            ),
            dashboard_sep("  "),
            dashboard_value(
                format!(
                    "busy {}/{}",
                    stats.wake_target_hit_count[2], stats.wake_target_miss_count[2]
                ),
                Style::default().fg(Color::LightMagenta),
            ),
        ]),
    ])
    .style(Style::default().fg(Color::Gray))
    .block(dashboard_block("Lifecycle", Color::LightMagenta))
    .wrap(Wrap { trim: false });
    frame.render_widget(health_panel, summary_bottom[1]);

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

    let analysis_layout =
        Layout::horizontal([Constraint::Percentage(56), Constraint::Percentage(44)])
            .split(outer_layout[1]);
    let analysis_right =
        Layout::vertical([Constraint::Length(5), Constraint::Min(0)]).split(analysis_layout[1]);

    let tier_names = ["Idle <5%", "Light 5-25%", "Busy 25-78%", "Hot >=78%"];
    let tier_colors = [Color::LightCyan, Color::Green, Color::Yellow, Color::Red];

    let tier_header = Row::new(vec![
        Cell::from("Band").style(
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        ),
        Cell::from("Tasks").style(
            Style::default()
                .fg(Color::Gray)
                .add_modifier(Modifier::BOLD),
        ),
        Cell::from("Avg util").style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Cell::from("Jitter").style(
            Style::default()
                .fg(Color::LightCyan)
                .add_modifier(Modifier::BOLD),
        ),
        Cell::from("Last wait").style(
            Style::default()
                .fg(Color::LightYellow)
                .add_modifier(Modifier::BOLD),
        ),
        Cell::from("Runs/s").style(
            Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD),
        ),
        Cell::from("Work %").style(
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
                Cell::from(format!("{}", tier_pids[t])).style(Style::default().fg(Color::Gray)),
                Cell::from(format!("{}", avg_rt)).style(Style::default().fg(Color::Cyan)),
                Cell::from(format!("{} µs", avg_jit)).style(low_is_good_style(avg_jit, 10, 100)),
                Cell::from(format!("{}", avg_wait)).style(low_is_good_style(avg_wait, 10, 100)),
                Cell::from(format!("{:.1}", tier_runs_per_sec[t]))
                    .style(Style::default().fg(Color::Green)),
                Cell::from(format!("{:.1}%", work_pct)).style(Style::default().fg(Color::Magenta)),
            ])
        })
        .collect();

    let tier_table = Table::new(
        tier_rows,
        [
            Constraint::Length(15), // Band
            Constraint::Length(6),  // Tasks
            Constraint::Length(10), // Avg util
            Constraint::Length(10), // Jitter
            Constraint::Length(10), // Last wait
            Constraint::Length(9),  // RUNS/s
            Constraint::Length(7),  // Work %
        ],
    )
    .header(tier_header)
    .block(dashboard_block("PELT Utilization Bands", Color::Yellow));
    frame.render_widget(tier_table, analysis_layout[0]);

    let wakewait_line = {
        let mut parts = Vec::new();
        for (idx, label) in ["direct", "busy", "queued"].iter().enumerate() {
            let count = stats.wake_reason_wait_count[idx + 1];
            let avg_us = if count > 0 {
                stats.wake_reason_wait_ns[idx + 1] / count / 1000
            } else {
                0
            };
            let max_us = stats.wake_reason_wait_max_ns[idx + 1] / 1000;
            parts.push(format!("{} {}/{}us ({})", label, avg_us, max_us, count));
        }
        parts.join("  ")
    };
    let coverage_style = if minute_samples.len() >= minute_expected && minute_avg_step <= 1.25 {
        Style::default().fg(Color::Green)
    } else if minute_samples.len() >= minute_expected.saturating_sub(2) {
        Style::default().fg(Color::Yellow)
    } else {
        Style::default().fg(Color::LightRed)
    };
    let coverage_line = Line::from(vec![
        dashboard_label("Coverage "),
        dashboard_value(
            format!(
                "{}/{}  avg step {:.2}s  history {:.0}s",
                minute_samples.len(),
                minute_expected,
                minute_avg_step,
                minute_history_span.as_secs_f64()
            ),
            coverage_style,
        ),
    ]);
    let minute_lines = summarize_timeline_samples(&minute_samples, minute_expected)
        .map(|lines| {
            let mut collected = vec![coverage_line.clone()];
            collected.extend(lines);
            collected
        })
        .unwrap_or_else(|| {
            vec![
                coverage_line,
                Line::from(vec![
                    dashboard_label("Runs/s "),
                    dashboard_note("collecting samples"),
                ]),
                Line::from(vec![
                    dashboard_label("Callback avg "),
                    dashboard_note("waiting for enough history"),
                ]),
                Line::from(vec![
                    dashboard_label("Path share "),
                    dashboard_note("waiting for enough history"),
                ]),
            ]
        });
    let minute_panel = Paragraph::new(minute_lines)
        .style(Style::default().fg(Color::Gray))
        .block(dashboard_block("Last 60s @1s Samples", Color::Cyan))
        .wrap(Wrap { trim: false });
    frame.render_widget(minute_panel, analysis_right[0]);

    let target_line = format!(
        "postwake target hit/miss {}  follow same/mig {}",
        format_wake_target_summary(&stats.wake_target_hit_count, &stats.wake_target_miss_count),
        format_wake_followup_summary(
            &stats.wake_followup_same_cpu_count,
            &stats.wake_followup_migrate_count,
        )
    );
    let slice_line = format!(
        "full={} ({:.1}%) block={} ({:.1}%) preempt={} ({:.1}%) sched_yield={} wake_kick i/p={}/{} affine i/p={}/{}",
        stats.nr_quantum_full,
        pct(stats.nr_quantum_full, quantum_total),
        stats.nr_quantum_yield,
        pct(stats.nr_quantum_yield, quantum_total),
        stats.nr_quantum_preempt,
        pct(stats.nr_quantum_preempt, quantum_total),
        stats.nr_sched_yield_calls,
        stats.nr_wake_kick_idle,
        stats.nr_wake_kick_preempt,
        stats.nr_affine_kick_idle,
        stats.nr_affine_kick_preempt,
    );
    let kick_line = format!(
        "idle {}/{} avg={}us max={}us  preempt {}/{} avg={}us max={}us bins {}",
        stats.nr_wake_kick_quick[1],
        stats.nr_wake_kick_observed[1],
        bucket_avg_us(
            stats.total_wake_kick_to_run_ns[1],
            stats.nr_wake_kick_observed[1]
        ),
        stats.max_wake_kick_to_run_ns[1] / 1000,
        stats.nr_wake_kick_quick[2],
        stats.nr_wake_kick_observed[2],
        bucket_avg_us(
            stats.total_wake_kick_to_run_ns[2],
            stats.nr_wake_kick_observed[2]
        ),
        stats.max_wake_kick_to_run_ns[2] / 1000,
        format_kick_bucket_summary(&stats.wake_kick_bucket_count),
    );
    let place_path_line = format!(
        "path[{}] deps same/cross={}/{}",
        format_path_summary(&stats.select_path_count),
        stats.nr_wake_same_tgid,
        stats.nr_wake_cross_tgid,
    );
    let mut signal_lines = Vec::new();
    if let Some(diag) = &balance_diag {
        let balance_style = if diag.cpu_skew <= 4.0 {
            Style::default().fg(Color::Green)
        } else if diag.cpu_skew <= 10.0 {
            Style::default().fg(Color::Yellow)
        } else {
            Style::default().fg(Color::LightRed)
        };
        signal_lines.push(Line::from(vec![
            dashboard_label("Balance "),
            dashboard_value(
                format!(
                    "{} top {} {:.1}% {}us {:.1}/s  core {} {:.1}% hot {:.0}% sib {:.0}%  {}",
                    balance_scope,
                    diag.top_cpu_share_label,
                    diag.top_cpu_share_pct,
                    diag.top_cpu_avg_run_us,
                    diag.top_cpu_runs_per_sec,
                    diag.top_core_share_label,
                    diag.top_core_share_pct,
                    diag.top_core_hot_thr_pct,
                    diag.top_core_sib_pct,
                    diag.driver,
                ),
                balance_style,
            ),
        ]));
        signal_lines.push(Line::from(vec![
            dashboard_label("Balance "),
            dashboard_value(
                format!(
                    "rate leader {} {:.1}/s {}us  skew c/c {:.1}x/{:.1}x  hot/cold cpu {}/{} core {}/{}  sticky {}",
                    diag.top_cpu_rate_label,
                    diag.top_cpu_rate_runs_per_sec,
                    diag.top_cpu_rate_avg_run_us,
                    diag.cpu_skew,
                    diag.core_skew,
                    diag.hot_cpu_count,
                    diag.cold_cpu_count,
                    diag.hot_core_count,
                    diag.cold_core_count,
                    if diag.sticky_core { "yes" } else { "no" },
                ),
                Style::default().fg(Color::LightCyan),
            ),
        ]));
    }
    signal_lines.extend([
        Line::from(vec![
            dashboard_label("Wake wait (<5ms) "),
            dashboard_value(wakewait_line, Style::default().fg(Color::LightCyan)),
        ]),
        Line::from(vec![
            dashboard_label("Target accuracy "),
            dashboard_value(target_line, Style::default().fg(Color::Cyan)),
        ]),
        Line::from(vec![
            dashboard_label("Kick to run "),
            dashboard_value(kick_line, Style::default().fg(Color::Yellow)),
        ]),
        Line::from(vec![
            dashboard_label("Placement paths "),
            dashboard_value(place_path_line, Style::default().fg(Color::LightMagenta)),
        ]),
        Line::from(vec![
            dashboard_label("Quantum outcomes "),
            dashboard_value(slice_line, Style::default().fg(Color::Green)),
        ]),
    ]);
    if !app.debug_events.is_empty() {
        if let Some(ev) = app.debug_events.front() {
            signal_lines.push(Line::from(vec![
                dashboard_label("Latest event "),
                dashboard_value(debug_event_label(ev), Style::default().fg(Color::LightRed)),
            ]));
        }
    } else {
        signal_lines.push(Line::from(vec![
            dashboard_label("Latest event "),
            dashboard_note("none"),
        ]));
    }
    let debug_panel = Paragraph::new(signal_lines)
        .style(Style::default().fg(Color::Gray))
        .block(dashboard_block(
            "Scheduler Health, Balance & Outliers",
            Color::LightMagenta,
        ))
        .wrap(Wrap { trim: false });
    frame.render_widget(debug_panel, analysis_right[1]);

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
                .fg(Color::Gray)
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
                        .fg(Color::LightBlue)
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
            Cell::from(format!("{}{}", indent, row.ppid))
                .style(Style::default().fg(Color::DarkGray)),
            Cell::from(format!("{}", row.pid)).style(Style::default().fg(Color::Yellow)),
            Cell::from(row.status.short_label()).style(Style::default().fg(row.status.color())),
            Cell::from(row.comm.as_str()).style(Style::default().fg(role.color())),
            Cell::from(class_label(row)).style(Style::default().fg(class_color(row))),
            Cell::from(format!("{}", row.pelt_util)).style(Style::default().fg(Color::Cyan)),
            Cell::from(display_runtime_us(row.max_runtime_us)).style(low_is_good_style(
                row.max_runtime_us as u64,
                500,
                2_000,
            )),
            Cell::from(display_gap_us(row.dispatch_gap_us)).style(gap_style),
            Cell::from(format!("{}", jitter_us)).style(low_is_good_style(jitter_us, 10, 100)),
            Cell::from(format!("{}", last_wait_us)).style(low_is_good_style(last_wait_us, 10, 100)),
            Cell::from(format!("{:.1}", row.runs_per_sec)).style(Style::default().fg(Color::Green)),
            Cell::from(format!("C{:02}", row.core_placement))
                .style(Style::default().fg(Color::Magenta)),
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
    let matrix_title = format!(
        "Live Task Matrix  [{}]  rows={}  tracked={}  legend in Reference",
        filter_label,
        app.sorted_pids.len(),
        app.bpf_task_count
    );

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
    .block(dashboard_block(&matrix_title, Color::Blue))
    .row_highlight_style(Style::default().add_modifier(Modifier::REVERSED))
    .highlight_symbol(">> ");

    // Using render_stateful_widget instead of render_widget to manage scroll table state
    frame.render_stateful_widget(matrix_table, outer_layout[2], &mut app.table_state);
}

fn draw_topology_tab(frame: &mut Frame, app: &TuiApp, area: Rect) {
    let nr_cpus = app.latency_matrix.len();
    let heatmap_min_width = (6 + nr_cpus * 2 + 4) as u16;
    let cpu_work_window = app.cpu_work_window(Duration::from_secs(60));
    let (work_elapsed, cpu_work, work_label) = if let Some((elapsed, window)) = cpu_work_window {
        (
            elapsed,
            window,
            format!("Cake runtime share {}s", elapsed.as_secs()),
        )
    } else {
        (
            app.start_time.elapsed().max(Duration::from_secs(1)),
            app.per_cpu_work.clone(),
            "Cake runtime share lifetime".to_string(),
        )
    };
    let cpu_rows = scheduler_cpu_rows(&cpu_work, &app.topology, &app.cpu_stats, work_elapsed);
    let core_rows = scheduler_core_rows(&cpu_work, &app.topology, &app.cpu_stats, work_elapsed);
    let scheduler_share = scheduler_share_by_cpu(&cpu_work);
    let right_min_width = 68u16;

    let layout = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Min(22),
            Constraint::Min(heatmap_min_width),
            Constraint::Min(right_min_width),
        ])
        .split(area);
    let topology_grid = build_cpu_topology_grid_compact(
        &app.topology,
        &app.cpu_stats,
        &scheduler_share,
        &work_label,
    );
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

    let right_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(52), Constraint::Percentage(48)])
        .split(layout[2]);
    let cpu_title = format!(
        "Scheduler CPU Work [Cake | Sys] ({:.0}s, skew {:.1}x)",
        work_elapsed.as_secs_f64(),
        scheduler_balance_ratio(&cpu_work)
    );
    let core_title = format!(
        "Scheduler Core Balance [Cake | HotThr | Sib | Sys] ({:.0}s)",
        work_elapsed.as_secs_f64()
    );
    let cpu_table = build_scheduler_cpu_table(
        &cpu_rows,
        &cpu_title,
        right_layout[0].height.saturating_sub(3) as usize,
    );
    let core_table = build_scheduler_core_table(
        &core_rows,
        &core_title,
        right_layout[1].height.saturating_sub(3) as usize,
    );
    frame.render_widget(cpu_table, right_layout[0]);
    frame.render_widget(core_table, right_layout[1]);
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
        col(
            "cap",
            "Current hard-latency vs soft UI vs build overlap snapshot",
        ),
        col(
            "queue.shared",
            "Shared DSQ depth plus cumulative enqueue/consume net flow",
        ),
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
        col(
            "Q[f/b/p]",
            "Per-task stop outcomes: full slice / blocked-slept with slice left / preempted runnable",
        ),
        col("SYLD", "Explicit sched_yield callbacks for this task"),
        col("PRMPT", "Explicit enqueue-preempt callbacks for this task"),
        col("CLS", "Current cake role: KCR / N- / N0 / N+"),
        col(
            "SUTIL%",
            "Approx slice occupancy percent from the 128-scale sample; >100 means runtime exceeded slice",
        ),
        col("LLC", "Last LLC (L3 cache) node"),
        col("STREAK", "Consecutive same-CPU runs (locality)"),
        col("WHIST", "Wait histogram: <10µ/<100µ/<1m/≥1ms"),
        col("hwait<=5ms", "Per-task wait by home locality: avg/max/count"),
        Line::from(""),
        section("═══ DASHBOARD PANELS ═══"),
        Line::from(""),
        subsection("── Summary Cards ──"),
        col(
            "Runtime",
            "Topology, uptime, tracked tasks, queue depth, PELT band counts",
        ),
        col(
            "Dispatch",
            "Dispatch volume, local/steal/miss counts, shared queue flow, wake routing, and path share",
        ),
        col(
            "Timing",
            "Average select/enqueue/running/stopping callback cost plus wake wait<=5ms",
        ),
        col(
            "Lifecycle",
            "Quantum stop mix (full / blocked / preempt), literal sched_yield count, kick-to-run latency, and post-wake target/follow-up outcomes",
        ),
        Line::from(""),
        subsection("── Analysis Panels ──"),
        col(
            "PELT band",
            "Task counts and averages grouped by idle/light/busy/hot util bands",
        ),
        col(
            "Last60s",
            "Rolling 1-second samples: runs/s, 1% low, callback avg, path share, quantum f/b/p, sched_yield/s, coverage, and retained history span",
        ),
        col(
            "Signals",
            "Balance diagnosis, wake waits<=5ms, post-wake target accuracy, kick latency, placement mix, latest anomaly event",
        ),
        Line::from(""),
        subsection("── Topology Tab ──"),
        col(
            "Topology",
            "Per-CPU cells read as Ck runtime share, Ld system load, and temperature over the latest 60s window",
        ),
        col(
            "CPU work",
            "Per-CPU scheduler distribution: Cake runtime share, runs/s, avg run time, quantum full/blocked/preempt mix, system load",
        ),
        col(
            "Core work",
            "Per-core balance: combined Cake share, hottest thread share, SMT sibling share, quantum mix in dump, average system load",
        ),
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
    let mut last_full_sweep = Instant::now()
        .checked_sub(FULL_SWEEP_MIN_INTERVAL)
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
        app.per_cpu_work = extract_cpu_work(skel, app.topology.nr_cpus);
        app.pressure_probe = extract_pressure_probe(skel);

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
                            app.sorted_pids_dirty = true;
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
                                Ok(_) => app.set_status(&format!("✓ Dump saved: {}", filename)),
                                Err(e) => app.set_status(&format!("✗ Dump failed: {}", e)),
                            }
                        }
                        KeyCode::Char('r') => {
                            // Reset stats (clear the BSS array)
                            if let Some(bss) = &mut skel.maps.bss_data {
                                for s in &mut bss.global_stats {
                                    *s = Default::default();
                                }
                                #[cfg(debug_assertions)]
                                {
                                    for reason in &mut bss.select_reason_target_count {
                                        *reason = Default::default();
                                    }
                                    for reason in &mut bss.select_reason_prev_count {
                                        *reason = Default::default();
                                    }
                                    for site in &mut bss.pressure_probe_total {
                                        *site = Default::default();
                                    }
                                    for site in &mut bss.pressure_probe_cpu_count {
                                        *site = Default::default();
                                    }
                                    bss.wake_direct_target_count = Default::default();
                                    bss.wake_busy_target_count = Default::default();
                                    bss.wake_busy_local_target_count = Default::default();
                                    bss.wake_busy_remote_target_count = Default::default();
                                    for reason in &mut bss.wake_target_wait_ns {
                                        *reason = Default::default();
                                    }
                                    for reason in &mut bss.wake_target_wait_count {
                                        *reason = Default::default();
                                    }
                                    for reason in &mut bss.wake_target_wait_max_ns {
                                        *reason = Default::default();
                                    }
                                    for reason in &mut bss.wake_target_wait_bucket_count {
                                        *reason = Default::default();
                                    }
                                    bss.local_pending_est = Default::default();
                                    bss.local_pending_max = Default::default();
                                    bss.local_pending_insert_count = Default::default();
                                    bss.local_pending_run_count = Default::default();
                                }
                                app.stats_history.clear();
                                app.cpu_work_history.clear();
                                app.pressure_probe_history.clear();
                                app.timeline_history.clear();
                                app.timeline_last_sample = None;
                                app.timeline_next_sample_at = None;
                                app.per_cpu_work
                                    .iter_mut()
                                    .for_each(|counter| *counter = CpuWorkCounters::default());
                                app.pressure_probe = PressureProbeCounters::default();
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
            let do_full_sweep = last_full_sweep.elapsed() >= FULL_SWEEP_MIN_INTERVAL;
            // Hardware Poll Vector
            app.sys.refresh_cpu_usage();
            for (i, cpu) in app.sys.cpus().iter().enumerate() {
                if i < app.topology.nr_cpus {
                    let load = cpu.cpu_usage();
                    let temp = app.cpu_stats[i].1;
                    app.cpu_stats[i] = (load, temp);
                }
            }

            if do_full_sweep {
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
                let sweep_seen_at = Instant::now();
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

                            let row =
                                app.task_rows
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
                                        max_dispatch_gap_us: rec.telemetry.max_dispatch_gap_ns
                                            / 1000,
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
                                        last_seen_at: sweep_seen_at,
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
                                        last_waker_place_class: rec
                                            .telemetry
                                            .last_waker_place_class,
                                        wake_same_tgid_count: rec.telemetry.wake_same_tgid_count,
                                        wake_cross_tgid_count: rec.telemetry.wake_cross_tgid_count,
                                        home_place_wait_ns: rec.telemetry.home_place_wait_ns,
                                        home_place_wait_count: rec.telemetry.home_place_wait_count,
                                        home_place_wait_max_us: rec
                                            .telemetry
                                            .home_place_wait_max_us,
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
                            row.last_seen_at = sweep_seen_at;
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

                if app.task_filter != TaskFilter::BpfTracked {
                    for (pid, process) in app.sys.processes() {
                        let pid_u32 = pid.as_u32();
                        let row =
                            app.task_rows
                                .entry(pid_u32)
                                .or_insert_with(|| TaskTelemetryRow {
                                    pid: pid_u32,
                                    comm: process.name().to_string_lossy().to_string(),
                                    ..Default::default()
                                });
                        row.last_seen_at = sweep_seen_at;
                    }
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
                    if row.is_bpf_tracked && row.total_runs > 0 && row.status != TaskStatus::Dead {
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

                let prune_before = Instant::now();
                app.task_rows.retain(|_, row| {
                    row.status != TaskStatus::Dead
                        || prune_before.saturating_duration_since(row.last_seen_at)
                            <= DEAD_TASK_RETENTION
                });
                app.prev_deltas
                    .retain(|pid, _| app.task_rows.contains_key(pid));
                app.sorted_pids_dirty = true;
            }

            if app.sorted_pids_dirty {
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
                        .filter(|(_, row)| {
                            row.is_bpf_tracked
                                && row.total_runs > 0
                                && row.status != TaskStatus::Dead
                        })
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
                app.sorted_pids_dirty = false;
            }

            if do_full_sweep {
                last_full_sweep = Instant::now();
            }
            app.record_stats_snapshot(&stats);
            app.record_cpu_work_snapshot();
            app.record_pressure_probe_snapshot();

            last_tick = Instant::now();
        }
    }

    restore_terminal()?;
    Ok(())
}
