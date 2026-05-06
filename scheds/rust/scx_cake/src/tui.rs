// SPDX-License-Identifier: GPL-2.0
// TUI module - ratatui-based terminal UI for real-time scheduler statistics

use std::io::{self, Stdout};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
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

#[cfg(not(cake_bpf_release))]
use crate::bpf_intf::cake_debug_event;
use crate::bpf_intf::cake_stats;
use crate::bpf_skel::BpfSkel;
use crate::topology::TopologyInfo;
use crate::trust::{self, CpuTrustSnapshot};

mod apps_tab;
mod dashboard_tab;
mod diagnostics;
mod dump;
mod graphs_tab;
mod latency_probe;
mod reference;
mod report;
mod topology_tab;

use apps_tab::draw_apps_tab;
use dashboard_tab::draw_dashboard_tab;
use diagnostics::{draw_codes_tab, draw_live_data_tab, draw_monitors_tab};
use dump::{
    build_app_health_rows, format_stats_for_clipboard, format_stats_json,
    format_tgid_health_summary,
};
use graphs_tab::draw_graphs_tab;
use latency_probe::run_core_latency_probe;
use reference::draw_reference_tab;
use report::build_telemetry_report;
use topology_tab::draw_topology_tab;

const STATS_HISTORY_MAX_AGE: Duration = Duration::from_secs(600);
const STATS_HISTORY_MAX_SAMPLES: usize = 2048;
const TIMELINE_HISTORY_MAX_SAMPLES: usize = 7200;
const TIMELINE_SAMPLE_PERIOD: Duration = Duration::from_secs(1);
const STATUS_MESSAGE_TTL: Duration = Duration::from_secs(4);
const DEAD_TASK_RETENTION: Duration = Duration::from_secs(300);
const FULL_SWEEP_MIN_INTERVAL: Duration = Duration::from_secs(1);
const SELECT_REASON_MAX: usize = 12;
const ACCEL_ROUTE_MAX: usize = 7;
const ACCEL_ROUTE_BLOCK_MAX: usize = 13;
const ACCEL_PROBE_OUTCOME_MAX: usize = 7;
const PRESSURE_SITE_MAX: usize = 2;
const PRESSURE_OUTCOME_MAX: usize = 6;
const PRESSURE_ANCHOR_REASON_MAX: usize = 4;
const WAKE_REASON_MAX: usize = 4;
const WAKE_BUCKET_MAX: usize = 5;
#[cfg(cake_bpf_release)]
const CAKE_CPU_STATUS_PRESS_SHIFT: u64 = 12;
#[cfg(cake_bpf_release)]
const CAKE_CPU_STATUS_PRESS_MASK: u64 = 0x3;

fn zero_cake_stats() -> cake_stats {
    // cake_stats is a C POD shared with BPF. Zero is its reset/default state.
    unsafe { std::mem::zeroed() }
}

#[cfg(cake_bpf_release)]
fn cake_cpu_status_pressure_bucket(flags: u64) -> u8 {
    ((flags >> CAKE_CPU_STATUS_PRESS_SHIFT) & CAKE_CPU_STATUS_PRESS_MASK) as u8
}

#[cfg(debug_assertions)]
const WAKE_CLASS_MAX: usize = 4;
#[cfg(debug_assertions)]
const WAKE_CLASS_REASON_MAX: usize = 9;
#[cfg(debug_assertions)]
const BUSY_PREEMPT_SHADOW_ALLOW: usize = 0;
#[cfg(debug_assertions)]
const BUSY_PREEMPT_SHADOW_SKIP: usize = 1;
#[cfg(debug_assertions)]
const BUSY_PREEMPT_SHADOW_MAX: usize = 2;
const DBG_EVENT_WAKE_EDGE_ENQUEUE: u8 = 8;
const DBG_EVENT_WAKE_EDGE_RUN: u8 = 9;
const DBG_EVENT_WAKE_EDGE_FOLLOW: u8 = 10;
const WAKE_EDGE_EVENT_FLAG_HIT_OR_SAME: u8 = 1;
const WAKE_EDGE_EVENT_FLAG_SAMPLED: u8 = 2;
const WAKE_EDGE_EVENT_FLAG_IMPORTANT: u8 = 4;
#[cfg(test)]
const CAKE_WAKE_EDGE_SAMPLE_DENOM: u32 = 64;
const SELECT_PATH_MAX: usize = 6;
const CAKE_CONF_SELECT_EARLY_SHIFT: u32 = 0;
const CAKE_CONF_SELECT_ROW4_SHIFT: u32 = 4;
const CAKE_CONF_CLAIM_HEALTH_SHIFT: u32 = 8;
const CAKE_CONF_DISPATCH_EMPTY_SHIFT: u32 = 12;
const CAKE_CONF_KICK_SHAPE_SHIFT: u32 = 20;
const CAKE_CONF_PULL_SHAPE_SHIFT: u32 = 24;
const CAKE_CONF_ROUTE_SHIFT: u32 = 28;
const CAKE_CONF_ROUTE_KIND_SHIFT: u32 = 32;
const CAKE_CONF_ROUTE_AUDIT_SHIFT: u32 = 36;
const CAKE_CONF_PULL_AUDIT_SHIFT: u32 = 40;
const CAKE_CONF_ACCOUNT_AUDIT_SHIFT: u32 = 44;
const CAKE_CONF_FLOOR_GEAR_SHIFT: u32 = 48;
const CAKE_CONF_STATUS_TRUST_SHIFT: u32 = 52;
const CAKE_CONF_OWNER_STABLE_SHIFT: u32 = 56;
const CAKE_CONF_LOAD_SHOCK_SHIFT: u32 = 60;
const CAKE_CONF_NIBBLE_MASK: u64 = 0xf;
const STARTUP_PHASE_ENQUEUE: u8 = 1;
const STARTUP_PHASE_SELECT: u8 = 2;
const STARTUP_PHASE_RUNNING: u8 = 3;
const STARTUP_MASK_ENQUEUE: u8 = 1 << 0;
const STARTUP_MASK_SELECT: u8 = 1 << 1;
const STARTUP_MASK_RUNNING: u8 = 1 << 2;

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
    Overview = 0,
    LiveData = 1,
    Monitors = 2,
    Codes = 3,
    Apps = 4,
    Topology = 5,
    Trends = 6,
    ReferenceGuide = 7,
}

impl TuiTab {
    fn next(self) -> Self {
        match self {
            TuiTab::Overview => TuiTab::LiveData,
            TuiTab::LiveData => TuiTab::Monitors,
            TuiTab::Monitors => TuiTab::Codes,
            TuiTab::Codes => TuiTab::Apps,
            TuiTab::Apps => TuiTab::Topology,
            TuiTab::Topology => TuiTab::Trends,
            TuiTab::Trends => TuiTab::ReferenceGuide,
            TuiTab::ReferenceGuide => TuiTab::Overview,
        }
    }

    fn previous(self) -> Self {
        match self {
            TuiTab::Overview => TuiTab::ReferenceGuide,
            TuiTab::LiveData => TuiTab::Overview,
            TuiTab::Monitors => TuiTab::LiveData,
            TuiTab::Codes => TuiTab::Monitors,
            TuiTab::Apps => TuiTab::Codes,
            TuiTab::Topology => TuiTab::Apps,
            TuiTab::Trends => TuiTab::Topology,
            TuiTab::ReferenceGuide => TuiTab::Trends,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TaskStatus {
    Alive, // In sysinfo + visible in the BPF task iterator
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
    pub app_table_state: TableState,
    pub focused_tgid: Option<u32>,
    pub active_tab: TuiTab,
    pub sort_column: SortColumn,
    pub sort_descending: bool,

    pub sys: System,
    pub components: Components,
    pub cpu_stats: Vec<(f32, f32)>, // (Load %, Temp C)
    pub task_filter: TaskFilter,
    pub arena_active: usize,   // Arena slots with tid != 0
    pub arena_max: usize,      // Arena pool max_elems
    pub bpf_task_count: usize, // Live rows visible through the BPF task iterator
    #[cfg(debug_assertions)]
    pub debug_cost: crate::task_anatomy::DebugTelemetryCost,
    pub prev_deltas: HashMap<u32, (u32, u16, u64)>, // (total_runs, migration_count, total_runtime_ns)
    pub active_pids_buf: std::collections::HashSet<u32>, // Reused per-tick to avoid alloc
    pub collapsed_tgids: std::collections::HashSet<u32>, // Collapsed process groups
    pub collapsed_ppids: std::collections::HashSet<u32>, // Collapsed PPID groups
    pub latency_probe_handle: Option<thread::JoinHandle<Vec<Vec<f64>>>>,
    pub _prev_stats: Option<cake_stats>, // Previous global stats for rate calc
    pub quantum_us: u64,
    pub system_info: SystemInfo,
    pub debug_events: VecDeque<DebugEventRow>,
    wake_edges: Vec<WakeEdgeRow>,
    wake_edge_slots_used: u64,
    wake_edge_missed_updates: u64,
    wake_edge_observed_events: u64,
    wake_edge_sample_weight_sum: u64,
    wake_edge_important_events: u64,
    per_cpu_work: Vec<CpuWorkCounters>,
    pressure_probe: PressureProbeCounters,
    stats_history: VecDeque<StatsSnapshot>,
    cpu_work_history: VecDeque<CpuWorkSnapshot>,
    pressure_probe_history: VecDeque<PressureProbeSnapshot>,
    timeline_history: VecDeque<TimelineBucket>,
    timeline_last_sample: Option<StatsSnapshot>,
    timeline_next_sample_at: Option<Instant>,
    diagnostic_recorder: diagnostics::DiagnosticRecorder,
}

#[derive(Clone, Copy)]
struct StatsSnapshot {
    at: Instant,
    stats: cake_stats,
}

#[derive(Clone, Copy, Debug, Default)]
struct TimelineSystemSample {
    cpu_load_avg_pct: f32,
    cpu_load_max_pct: f32,
    cpu_load_hot_cpu: Option<u16>,
    cpu_temp_avg_c: f32,
    cpu_temp_max_c: f32,
    cpu_temp_hot_cpu: Option<u16>,
}

#[derive(Clone, Copy)]
struct TimelineBucket {
    elapsed: Duration,
    end_elapsed: Duration,
    stats: cake_stats,
    system: TimelineSystemSample,
}

#[derive(Clone, Copy)]
struct TimelineSample {
    start_ago_secs: u64,
    end_ago_secs: u64,
    start_elapsed: Duration,
    end_elapsed: Duration,
    elapsed: Duration,
    stats: cake_stats,
    system: TimelineSystemSample,
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
    smt_solo_runtime_ns: u64,
    smt_contended_runtime_ns: u64,
    smt_overlap_runtime_ns: u64,
    smt_solo_run_count: u64,
    smt_contended_run_count: u64,
    smt_sibling_active_start_count: u64,
    smt_sibling_active_stop_count: u64,
    smt_wake_wait_ns: [u64; 2],
    smt_wake_wait_count: [u64; 2],
    smt_wake_wait_max_ns: [u64; 2],
    select_target_total: u64,
    select_prev_total: u64,
    select_target_reason: [u64; SELECT_REASON_MAX],
    select_prev_reason: [u64; SELECT_REASON_MAX],
    home_seed_total: u64,
    home_seed_reason: [u64; SELECT_REASON_MAX],
    pressure_probe: [[u64; PRESSURE_OUTCOME_MAX]; PRESSURE_SITE_MAX],
    pressure_anchor_block: [[u64; PRESSURE_ANCHOR_REASON_MAX]; PRESSURE_SITE_MAX],
    cpu_pressure: u8,
    decision_confidence: u64,
    trust: CpuTrustSnapshot,
    local_pending: u32,
    local_pending_max: u32,
    local_pending_inserts: u64,
    local_pending_runs: u64,
    wake_direct_target: u64,
    wake_busy_target: u64,
    wake_busy_local_target: u64,
    wake_busy_remote_target: u64,
    blocked_owner_pid: u32,
    blocked_waiter_pid: u32,
    blocked_owner_wait_ns: u64,
    blocked_owner_wait_count: u64,
    blocked_owner_wait_max_ns: u64,
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
    anchor_block: [[u64; PRESSURE_ANCHOR_REASON_MAX]; PRESSURE_SITE_MAX],
}

#[derive(Clone, Copy)]
struct PressureProbeSnapshot {
    at: Instant,
    counters: PressureProbeCounters,
}

#[derive(Clone, Debug, Default)]
struct WakeEdgeRow {
    waker_pid: u32,
    waker_tgid: u32,
    wakee_pid: u32,
    wakee_tgid: u32,
    wake_count: u64,
    same_tgid_count: u64,
    cross_tgid_count: u64,
    wait_ns: u64,
    wait_count: u64,
    wait_max_ns: u64,
    wait_bucket_count: [u64; WAKE_BUCKET_MAX],
    target_hit_count: u64,
    target_miss_count: u64,
    follow_same_cpu_count: u64,
    follow_migrate_count: u64,
    waker_place_count: [u64; 4],
    home_place_count: [u64; 4],
    reason_count: [u64; WAKE_REASON_MAX],
    path_count: [u64; SELECT_PATH_MAX],
    last_seen_ns: u64,
    observed_event_count: u64,
    sample_weight_sum: u64,
    important_event_count: u64,
}

#[derive(Clone, Debug, Default)]
struct WakeGraphCounters {
    edges: Vec<WakeEdgeRow>,
    slots_used: u64,
    missed_updates: u64,
    observed_events: u64,
    sample_weight_sum: u64,
    important_events: u64,
}

#[cfg(debug_assertions)]
#[derive(Clone, Debug, Default)]
struct DerivedStrictWakePolicy {
    source_rows: u64,
    class_sample_count: [u64; WAKE_CLASS_MAX],
    reason_count: [u64; WAKE_CLASS_REASON_MAX],
    transition_count: [[u64; WAKE_CLASS_MAX]; WAKE_CLASS_MAX],
    wait_ns: [u64; WAKE_CLASS_MAX],
    wait_count: [u64; WAKE_CLASS_MAX],
    wait_max_ns: [u64; WAKE_CLASS_MAX],
    bucket_count: [[u64; WAKE_BUCKET_MAX]; WAKE_CLASS_MAX],
    busy_shadow_count: [u64; BUSY_PREEMPT_SHADOW_MAX],
    busy_shadow_wakee_class_count: [u64; WAKE_CLASS_MAX],
    busy_shadow_owner_class_count: [u64; WAKE_CLASS_MAX],
    busy_shadow_local: u64,
    busy_shadow_remote: u64,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct WakeEdgeKey {
    waker_pid: u32,
    waker_tgid: u32,
    wakee_pid: u32,
    wakee_tgid: u32,
}

#[cfg_attr(cake_bpf_release, allow(dead_code))]
#[derive(Debug, Default)]
struct WakeGraphState {
    edges: HashMap<WakeEdgeKey, WakeEdgeRow>,
    missed_updates: u64,
}

#[cfg(not(cake_bpf_release))]
fn wake_edge_event_weight(ev: &cake_debug_event) -> u64 {
    if ev.flags & WAKE_EDGE_EVENT_FLAG_SAMPLED != 0 {
        u64::from(ev.aux.max(1))
    } else {
        1
    }
}

#[cfg_attr(cake_bpf_release, allow(dead_code))]
impl WakeGraphState {
    fn clear(&mut self) {
        self.edges.clear();
        self.missed_updates = 0;
    }

    #[cfg(not(cake_bpf_release))]
    fn record_event(&mut self, ev: &cake_debug_event) {
        if ev.kind != DBG_EVENT_WAKE_EDGE_ENQUEUE
            && ev.kind != DBG_EVENT_WAKE_EDGE_RUN
            && ev.kind != DBG_EVENT_WAKE_EDGE_FOLLOW
        {
            return;
        }
        if ev.pid == 0 || ev.peer_pid == 0 {
            return;
        }
        let weight = wake_edge_event_weight(ev);

        let key = WakeEdgeKey {
            waker_pid: ev.peer_pid,
            waker_tgid: ev.peer_tgid,
            wakee_pid: ev.pid,
            wakee_tgid: ev.tgid,
        };
        let edge = self.edges.entry(key).or_insert_with(|| WakeEdgeRow {
            waker_pid: ev.peer_pid,
            waker_tgid: ev.peer_tgid,
            wakee_pid: ev.pid,
            wakee_tgid: ev.tgid,
            ..WakeEdgeRow::default()
        });
        edge.last_seen_ns = edge.last_seen_ns.max(ev.ts_ns);
        edge.observed_event_count = edge.observed_event_count.saturating_add(1);
        edge.sample_weight_sum = edge.sample_weight_sum.saturating_add(weight);
        if ev.flags & WAKE_EDGE_EVENT_FLAG_IMPORTANT != 0 {
            edge.important_event_count = edge.important_event_count.saturating_add(1);
        }

        match ev.kind {
            DBG_EVENT_WAKE_EDGE_ENQUEUE => {
                edge.wake_count = edge.wake_count.saturating_add(weight);
                if ev.peer_tgid == ev.tgid {
                    edge.same_tgid_count = edge.same_tgid_count.saturating_add(weight);
                } else {
                    edge.cross_tgid_count = edge.cross_tgid_count.saturating_add(weight);
                }
            }
            DBG_EVENT_WAKE_EDGE_RUN => {
                edge.wait_count = edge.wait_count.saturating_add(weight);
                edge.wait_ns = edge
                    .wait_ns
                    .saturating_add(ev.value_ns.saturating_mul(weight));
                edge.wait_max_ns = edge.wait_max_ns.max(ev.value_ns);
                let bucket = wake_bucket_index(ev.value_ns);
                edge.wait_bucket_count[bucket] =
                    edge.wait_bucket_count[bucket].saturating_add(weight);

                let reason = ev.reason as usize;
                if reason > 0 && reason < WAKE_REASON_MAX {
                    edge.reason_count[reason] = edge.reason_count[reason].saturating_add(weight);
                }
                let path = ev.path as usize;
                if path > 0 && path < SELECT_PATH_MAX {
                    edge.path_count[path] = edge.path_count[path].saturating_add(weight);
                }
                let home_place = ev.home_place as usize;
                if home_place < edge.home_place_count.len() {
                    edge.home_place_count[home_place] =
                        edge.home_place_count[home_place].saturating_add(weight);
                }
                let waker_place = ev.waker_place as usize;
                if waker_place < edge.waker_place_count.len() {
                    edge.waker_place_count[waker_place] =
                        edge.waker_place_count[waker_place].saturating_add(weight);
                }
                if ev.target_cpu < crate::topology::MAX_CPUS as u16 {
                    if ev.flags & WAKE_EDGE_EVENT_FLAG_HIT_OR_SAME != 0 {
                        edge.target_hit_count = edge.target_hit_count.saturating_add(weight);
                    } else {
                        edge.target_miss_count = edge.target_miss_count.saturating_add(weight);
                    }
                }
            }
            DBG_EVENT_WAKE_EDGE_FOLLOW => {
                if ev.flags & WAKE_EDGE_EVENT_FLAG_HIT_OR_SAME != 0 {
                    edge.follow_same_cpu_count = edge.follow_same_cpu_count.saturating_add(weight);
                } else {
                    edge.follow_migrate_count = edge.follow_migrate_count.saturating_add(weight);
                }
            }
            _ => {}
        }
    }

    #[cfg(debug_assertions)]
    fn snapshot(&self) -> WakeGraphCounters {
        let mut graph = WakeGraphCounters {
            edges: self.edges.values().cloned().collect(),
            slots_used: self.edges.len() as u64,
            missed_updates: self.missed_updates,
            observed_events: 0,
            sample_weight_sum: 0,
            important_events: 0,
        };
        for edge in &graph.edges {
            graph.observed_events = graph
                .observed_events
                .saturating_add(edge.observed_event_count);
            graph.sample_weight_sum = graph
                .sample_weight_sum
                .saturating_add(edge.sample_weight_sum);
            graph.important_events = graph
                .important_events
                .saturating_add(edge.important_event_count);
        }
        graph.edges.sort_by(|a, b| {
            b.wait_count
                .cmp(&a.wait_count)
                .then_with(|| b.wake_count.cmp(&a.wake_count))
                .then_with(|| b.wait_ns.cmp(&a.wait_ns))
                .then_with(|| b.observed_event_count.cmp(&a.observed_event_count))
        });
        graph
    }
}

#[cfg(test)]
mod wake_graph_sampling_tests {
    use super::*;

    #[test]
    fn sampled_wake_graph_events_are_weighted_but_observed_once() {
        let mut state = WakeGraphState::default();
        let mut ev: cake_debug_event = unsafe { std::mem::zeroed() };
        ev.ts_ns = 100;
        ev.kind = DBG_EVENT_WAKE_EDGE_ENQUEUE;
        ev.pid = 20;
        ev.tgid = 2;
        ev.peer_pid = 10;
        ev.peer_tgid = 1;
        ev.aux = CAKE_WAKE_EDGE_SAMPLE_DENOM;
        ev.flags = WAKE_EDGE_EVENT_FLAG_SAMPLED;

        state.record_event(&ev);

        let graph = state.snapshot();
        assert_eq!(graph.edges.len(), 1);
        assert_eq!(graph.observed_events, 1);
        assert_eq!(graph.sample_weight_sum, CAKE_WAKE_EDGE_SAMPLE_DENOM as u64);

        let edge = &graph.edges[0];
        assert_eq!(edge.wake_count, CAKE_WAKE_EDGE_SAMPLE_DENOM as u64);
        assert_eq!(edge.cross_tgid_count, CAKE_WAKE_EDGE_SAMPLE_DENOM as u64);
        assert_eq!(edge.observed_event_count, 1);
        assert_eq!(edge.sample_weight_sum, CAKE_WAKE_EDGE_SAMPLE_DENOM as u64);
    }
}

#[derive(Clone, Debug, Default)]
struct WakeTgidSummary {
    tgid: u32,
    edge_count: u64,
    inbound_edges: u64,
    internal_edges: u64,
    outbound_edges: u64,
    inbound_wake_count: u64,
    internal_wake_count: u64,
    outbound_wake_count: u64,
    self_wait_ns: u64,
    self_wait_count: u64,
    self_wait_max_ns: u64,
    outbound_wait_ns: u64,
    outbound_wait_count: u64,
    outbound_wait_max_ns: u64,
    self_target_hit_count: u64,
    self_target_miss_count: u64,
    outbound_target_hit_count: u64,
    outbound_target_miss_count: u64,
    self_follow_same_cpu_count: u64,
    self_follow_migrate_count: u64,
}

impl WakeTgidSummary {
    fn self_wake_count(&self) -> u64 {
        self.inbound_wake_count
            .saturating_add(self.internal_wake_count)
    }

    fn total_wake_count(&self) -> u64 {
        self.self_wake_count()
            .saturating_add(self.outbound_wake_count)
    }
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
    smt_contended_pct: f64,
    smt_overlap_pct: f64,
    smt_contended_avg_run_us: u64,
    smt_wait_solo_us: u64,
    smt_wait_contended_us: u64,
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
    smt_overlap_pct: f64,
    primary_contended_pct: f64,
    secondary_contended_pct: f64,
    primary_smt_impact: f64,
    smt_wait_solo_us: u64,
    smt_wait_contended_us: u64,
    full_pct: f64,
    yield_pct: f64,
    preempt_pct: f64,
    top_cpu_share_pct: f64,
    secondary_smt_pct: f64,
    avg_system_load: f32,
}

#[derive(Clone, Debug)]
struct LongRunOwnerRow {
    pid: u32,
    tgid: u32,
    ppid: u32,
    comm: String,
    role: WorkloadRole,
    pelt_util: u32,
    total_runtime_ns: u64,
    runtime_share_pct: f64,
    runtime_ns_per_sec: f64,
    runs: u32,
    runs_per_sec: f64,
    avg_run_us: u64,
    max_runtime_us: u32,
    top_cpu: Option<usize>,
    top_cpu_pct: u64,
    top_core: Option<usize>,
    top_core_pct: u64,
    active_cpu_count: usize,
    active_core_count: usize,
    smt_secondary_pct: u64,
    allowed_cpus: u16,
    home_cpu: u16,
    home_score: u8,
    home_busy_pct: f64,
    home_change_count: u32,
    blocked_wait_max_us: u32,
    blocked_count: u16,
    smt_contended_pct: f64,
    smt_overlap_pct: f64,
}

#[derive(Clone, Debug, Default)]
struct AppHealthRow {
    tgid: u32,
    comm: String,
    leader_comm: String,
    dominant_runtime_comm: String,
    dominant_runtime_ns: u64,
    dominant_thread_comm: String,
    dominant_thread_count: usize,
    comm_kinds: usize,
    role: WorkloadRole,
    tasks: usize,
    hot_tasks: usize,
    restricted_tasks: usize,
    sticky_hogs: usize,
    pelt_max: u32,
    runtime_ns: u64,
    runtime_ns_per_sec: f64,
    runs_per_sec: f64,
    runs: u64,
    migrations_per_sec: f64,
    quantum_full: u64,
    quantum_yield: u64,
    quantum_preempt: u64,
    yield_count: u64,
    max_runtime_us: u32,
    min_allowed_cpus: u16,
    max_allowed_cpus: u16,
    smt_contended_runtime_ns: u64,
    smt_overlap_runtime_ns: u64,
    blocked_count: u64,
    blocked_wait_max_us: u32,
    wake_self: u64,
    wake_in: u64,
    wake_out: u64,
    wait_self_ns: u64,
    wait_out_ns: u64,
    wait_self_count: u64,
    wait_out_count: u64,
    wait_self_max_ns: u64,
    wait_out_max_ns: u64,
}

#[derive(Clone, Debug, Default)]
struct TgidIdentity {
    leader_comm: String,
    app_comm: String,
    dominant_runtime_comm: String,
    dominant_runtime_ns: u64,
    dominant_thread_comm: String,
    dominant_thread_count: usize,
    comm_kinds: usize,
    total_runtime_ns: u64,
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
    anchor_block: [u64; PRESSURE_ANCHOR_REASON_MAX],
}

#[derive(Clone, Debug)]
struct HomeSeedRow {
    cpu: usize,
    seeds: u64,
    seed_pct: f64,
    reason: [u64; SELECT_REASON_MAX],
}

#[derive(Clone, Debug)]
struct LocalQueueRow {
    cpu: usize,
    pressure: u8,
    decision_confidence: u64,
    trust: CpuTrustSnapshot,
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
    pub tgid: u32,
    pub peer_pid: u32,
    pub peer_tgid: u32,
    pub cpu: u16,
    pub target_cpu: u16,
    pub peer_cpu: u16,
    pub kind: u8,
    pub slot: u8,
    pub reason: u8,
    pub path: u8,
    pub flags: u8,
    pub comm: String,
}

#[derive(Clone, Debug)]
#[allow(dead_code)]
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
    pub total_runtime_ns: u64,
    pub jitter_accum_ns: u64,
    pub direct_dispatch_count: u16,
    pub cpumask_change_count: u16,
    pub allowed_cpus: u16,
    pub home_cpu: u16,
    pub home_score: u8,
    pub home_core: u8,
    pub home_try_count: u32,
    pub home_busy_count: u32,
    pub home_change_count: u32,
    pub smt_contended_runs: u32,
    pub smt_solo_runs: u32,
    pub smt_contended_runtime_ns: u64,
    pub smt_overlap_runtime_ns: u64,
    pub last_blocker_pid: u32,
    pub last_blocker_cpu: u16,
    pub blocked_wait_last_us: u32,
    pub blocked_wait_max_us: u32,
    pub blocked_count: u16,
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
    pub runtime_ns_per_sec: f64,
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
    pub gate_cascade_ns: u32,   // select_cpu: full gate cascade duration
    pub lifecycle_init_ms: u32, // BPF monotonic init timestamp, for lifecycle math
    pub vtime_compute_ns: u32,  // enqueue: vtime calculation + tier weighting
    pub mbox_staging_ns: u32,   // running: mailbox CL0 write burst
    pub startup_latency_us: u32,
    pub startup_enqueue_us: u32,
    pub lifecycle_live_ms: u32, // live task age at the iterator snapshot
    pub startup_select_us: u32,
    pub startup_first_phase: u8,
    pub startup_phase_mask: u8,
    // Quantum completion tracking
    pub quantum_full_count: u64,    // Task consumed the full slice
    pub quantum_yield_count: u64,   // Task stopped with slice left and became non-runnable
    pub quantum_preempt_count: u64, // Task was kicked/preempted while still runnable
    // Wake chain tracking
    pub waker_cpu: u16,  // CPU the waker was running on
    pub waker_tgid: u32, // TGID of the waker (process group)
    pub wake_reason_wait_ns: [u64; 3],
    pub wake_reason_count: [u32; 3],
    pub wake_reason_max_us: [u32; 3],
    pub last_select_reason: u8,
    pub last_select_path: u8,
    pub last_place_class: u8,
    pub last_waker_place_class: u8,
    pub wake_same_tgid_count: u32,
    pub wake_cross_tgid_count: u32,
    pub wake_chain_policy_score: u8,
    pub home_place_wait_ns: [u64; 4],
    pub home_place_wait_count: [u32; 4],
    pub home_place_wait_max_us: [u32; 4],
    // CPU core distribution histogram
    pub cpu_run_count: [u16; crate::topology::MAX_CPUS], // Per-CPU run count (TUI normalizes to %)
    // EEVDF telemetry
    pub task_weight: u16, // Task weight (100=nice0, >100=high-pri, <100=low-pri)
    #[cfg(debug_assertions)]
    pub task_flags: u32,
    #[cfg(debug_assertions)]
    pub task_policy: u32,
    #[cfg(debug_assertions)]
    pub task_prio: u32,
    #[cfg(debug_assertions)]
    pub task_static_prio: u32,
    #[cfg(debug_assertions)]
    pub task_normal_prio: u32,
    #[cfg(debug_assertions)]
    pub task_has_mm: bool,
    #[cfg(debug_assertions)]
    pub task_is_kthread: bool,
    #[cfg(debug_assertions)]
    pub proc_snapshot_seen: bool,
    #[cfg(debug_assertions)]
    pub proc_schedstat_seen: bool,
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
            total_runtime_ns: 0,
            jitter_accum_ns: 0,
            direct_dispatch_count: 0,
            cpumask_change_count: 0,
            allowed_cpus: 0,
            home_cpu: 0,
            home_score: 0,
            home_core: 0,
            home_try_count: 0,
            home_busy_count: 0,
            home_change_count: 0,
            smt_contended_runs: 0,
            smt_solo_runs: 0,
            smt_contended_runtime_ns: 0,
            smt_overlap_runtime_ns: 0,
            last_blocker_pid: 0,
            last_blocker_cpu: 0,
            blocked_wait_last_us: 0,
            blocked_wait_max_us: 0,
            blocked_count: 0,
            stopping_duration_ns: 0,
            running_duration_ns: 0,
            max_runtime_us: 0,
            dispatch_gap_us: 0,
            max_dispatch_gap_us: 0,
            wait_hist: [0; 4],
            runs_per_sec: 0.0,
            migrations_per_sec: 0.0,
            runtime_ns_per_sec: 0.0,
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
            lifecycle_init_ms: 0,
            vtime_compute_ns: 0,
            mbox_staging_ns: 0,
            startup_latency_us: 0,
            startup_enqueue_us: 0,
            lifecycle_live_ms: 0,
            startup_select_us: 0,
            startup_first_phase: 0,
            startup_phase_mask: 0,
            quantum_full_count: 0,
            quantum_yield_count: 0,
            quantum_preempt_count: 0,
            waker_cpu: 0,
            waker_tgid: 0,
            wake_reason_wait_ns: [0; 3],
            wake_reason_count: [0; 3],
            wake_reason_max_us: [0; 3],
            last_select_reason: 0,
            last_select_path: 0,
            last_place_class: 0,
            last_waker_place_class: 0,
            wake_same_tgid_count: 0,
            wake_cross_tgid_count: 0,
            wake_chain_policy_score: 0,
            home_place_wait_ns: [0; 4],
            home_place_wait_count: [0; 4],
            home_place_wait_max_us: [0; 4],
            cpu_run_count: [0u16; crate::topology::MAX_CPUS],
            task_weight: 100,
            #[cfg(debug_assertions)]
            task_flags: 0,
            #[cfg(debug_assertions)]
            task_policy: 0,
            #[cfg(debug_assertions)]
            task_prio: 0,
            #[cfg(debug_assertions)]
            task_static_prio: 0,
            #[cfg(debug_assertions)]
            task_normal_prio: 0,
            #[cfg(debug_assertions)]
            task_has_mm: false,
            #[cfg(debug_assertions)]
            task_is_kthread: false,
            #[cfg(debug_assertions)]
            proc_snapshot_seen: false,
            #[cfg(debug_assertions)]
            proc_schedstat_seen: false,
        }
    }
}

#[cfg(not(cake_bpf_release))]
fn aggregate_stats(skel: &BpfSkel) -> cake_stats {
    let mut total = zero_cake_stats();

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
            total.nr_primary_scan_guarded += s.nr_primary_scan_guarded;
            total.nr_primary_scan_credit_used += s.nr_primary_scan_credit_used;
            total.nr_primary_scan_hot_guarded += s.nr_primary_scan_hot_guarded;
            total.nr_wake_chain_locality_guarded += s.nr_wake_chain_locality_guarded;
            total.nr_wake_chain_locality_credit_used += s.nr_wake_chain_locality_credit_used;
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
            total.smt_solo_runtime_ns += s.smt_solo_runtime_ns;
            total.smt_contended_runtime_ns += s.smt_contended_runtime_ns;
            total.smt_overlap_runtime_ns += s.smt_overlap_runtime_ns;
            total.smt_solo_run_count += s.smt_solo_run_count;
            total.smt_contended_run_count += s.smt_contended_run_count;
            total.smt_sibling_active_start_count += s.smt_sibling_active_start_count;
            total.smt_sibling_active_stop_count += s.smt_sibling_active_stop_count;
            for bucket in 0..2 {
                total.smt_wake_wait_ns[bucket] += s.smt_wake_wait_ns[bucket];
                total.smt_wake_wait_count[bucket] += s.smt_wake_wait_count[bucket];
                total.smt_wake_wait_max_ns[bucket] =
                    total.smt_wake_wait_max_ns[bucket].max(s.smt_wake_wait_max_ns[bucket]);
            }
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
            total.nr_running_same_task += s.nr_running_same_task;
            total.nr_running_task_change += s.nr_running_task_change;
            total.nr_stopping_runnable += s.nr_stopping_runnable;
            total.nr_stopping_blocked += s.nr_stopping_blocked;
            total.nr_enqueue_path_kthread += s.nr_enqueue_path_kthread;
            total.nr_enqueue_path_initial += s.nr_enqueue_path_initial;
            total.nr_enqueue_path_preserve += s.nr_enqueue_path_preserve;
            total.nr_enqueue_path_requeue += s.nr_enqueue_path_requeue;
            total.nr_enqueue_path_wakeup += s.nr_enqueue_path_wakeup;
            total.nr_enqueue_path_affine_preserve += s.nr_enqueue_path_affine_preserve;
            total.nr_enqueue_path_affine_requeue += s.nr_enqueue_path_affine_requeue;
            total.nr_enqueue_path_affine_dispatch += s.nr_enqueue_path_affine_dispatch;
            total.nr_llc_vtime_wake_idle_direct += s.nr_llc_vtime_wake_idle_direct;
            total.nr_llc_vtime_wake_busy_shared += s.nr_llc_vtime_wake_busy_shared;
            total.nr_llc_vtime_nonwake_shared += s.nr_llc_vtime_nonwake_shared;
            total.nr_dispatch_llc_local_hit += s.nr_dispatch_llc_local_hit;
            total.nr_dispatch_llc_local_miss += s.nr_dispatch_llc_local_miss;
            total.nr_dispatch_llc_steal_hit += s.nr_dispatch_llc_steal_hit;
            total.nr_dispatch_keep_running += s.nr_dispatch_keep_running;
            total.lifecycle_init_enqueue_us += s.lifecycle_init_enqueue_us;
            total.lifecycle_init_enqueue_count += s.lifecycle_init_enqueue_count;
            total.lifecycle_init_select_us += s.lifecycle_init_select_us;
            total.lifecycle_init_select_count += s.lifecycle_init_select_count;
            total.lifecycle_init_run_us += s.lifecycle_init_run_us;
            total.lifecycle_init_run_count += s.lifecycle_init_run_count;
            total.lifecycle_init_exit_us += s.lifecycle_init_exit_us;
            total.lifecycle_init_exit_count += s.lifecycle_init_exit_count;
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
                total.select_path_migration_count[path] += s.select_path_migration_count[path];
            }
            for reason in 0..SELECT_REASON_MAX {
                total.select_reason_migration_count[reason] +=
                    s.select_reason_migration_count[reason];
                total.select_reason_wait_ns[reason] += s.select_reason_wait_ns[reason];
                total.select_reason_wait_count[reason] += s.select_reason_wait_count[reason];
                total.select_reason_wait_max_ns[reason] = total.select_reason_wait_max_ns[reason]
                    .max(s.select_reason_wait_max_ns[reason]);
                for bucket in 0..5 {
                    total.select_reason_bucket_count[reason][bucket] +=
                        s.select_reason_bucket_count[reason][bucket];
                }
                total.select_reason_select_ns[reason] += s.select_reason_select_ns[reason];
                total.select_reason_select_count[reason] += s.select_reason_select_count[reason];
                total.select_reason_select_max_ns[reason] = total.select_reason_select_max_ns
                    [reason]
                    .max(s.select_reason_select_max_ns[reason]);
            }
            for route in 0..ACCEL_ROUTE_MAX {
                total.accel_route_attempt_count[route] += s.accel_route_attempt_count[route];
                total.accel_route_hit_count[route] += s.accel_route_hit_count[route];
                total.accel_route_miss_count[route] += s.accel_route_miss_count[route];
                total.accel_fast_attempt_count[route] += s.accel_fast_attempt_count[route];
                total.accel_fast_hit_count[route] += s.accel_fast_hit_count[route];
                total.accel_fast_miss_count[route] += s.accel_fast_miss_count[route];
                for outcome in 0..ACCEL_PROBE_OUTCOME_MAX {
                    total.accel_scoreboard_probe_count[route][outcome] +=
                        s.accel_scoreboard_probe_count[route][outcome];
                }
            }
            for reason in 0..ACCEL_ROUTE_BLOCK_MAX {
                total.accel_route_block_count[reason] += s.accel_route_block_count[reason];
            }
            for mode in 0..total.accel_pull_mode_count.len() {
                total.accel_pull_mode_count[mode] += s.accel_pull_mode_count[mode];
            }
            for outcome in 0..total.accel_pull_probe_count.len() {
                total.accel_pull_probe_count[outcome] += s.accel_pull_probe_count[outcome];
            }
            for kind in 0..total.accel_native_fallback_count.len() {
                total.accel_native_fallback_count[kind] += s.accel_native_fallback_count[kind];
            }
            total.accel_accounting_relaxed += s.accel_accounting_relaxed;
            total.accel_accounting_audit += s.accel_accounting_audit;
            total.accel_trust_prev_attempt += s.accel_trust_prev_attempt;
            total.accel_trust_prev_hit += s.accel_trust_prev_hit;
            total.accel_trust_prev_miss += s.accel_trust_prev_miss;
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
            for class in 0..total.wake_class_sample_count.len() {
                total.wake_class_sample_count[class] += s.wake_class_sample_count[class];
                total.strict_wake_class_sample_count[class] +=
                    s.strict_wake_class_sample_count[class];
                total.busy_preempt_shadow_wakee_class_count[class] +=
                    s.busy_preempt_shadow_wakee_class_count[class];
                total.busy_preempt_shadow_owner_class_count[class] +=
                    s.busy_preempt_shadow_owner_class_count[class];
                total.strict_busy_preempt_shadow_wakee_class_count[class] +=
                    s.strict_busy_preempt_shadow_wakee_class_count[class];
                total.strict_busy_preempt_shadow_owner_class_count[class] +=
                    s.strict_busy_preempt_shadow_owner_class_count[class];
                total.strict_wake_class_wait_ns[class] += s.strict_wake_class_wait_ns[class];
                total.strict_wake_class_wait_count[class] += s.strict_wake_class_wait_count[class];
                total.strict_wake_class_wait_max_ns[class] = total.strict_wake_class_wait_max_ns
                    [class]
                    .max(s.strict_wake_class_wait_max_ns[class]);
                for next in 0..total.wake_class_transition_count[class].len() {
                    total.wake_class_transition_count[class][next] +=
                        s.wake_class_transition_count[class][next];
                    total.strict_wake_class_transition_count[class][next] +=
                        s.strict_wake_class_transition_count[class][next];
                }
                for bucket in 0..total.strict_wake_class_bucket_count[class].len() {
                    total.strict_wake_class_bucket_count[class][bucket] +=
                        s.strict_wake_class_bucket_count[class][bucket];
                }
            }
            for reason in 0..total.wake_class_reason_count.len() {
                total.wake_class_reason_count[reason] += s.wake_class_reason_count[reason];
                total.strict_wake_class_reason_count[reason] +=
                    s.strict_wake_class_reason_count[reason];
            }
            for decision in 0..total.busy_preempt_shadow_count.len() {
                total.busy_preempt_shadow_count[decision] += s.busy_preempt_shadow_count[decision];
                total.strict_busy_preempt_shadow_count[decision] +=
                    s.strict_busy_preempt_shadow_count[decision];
            }
            total.busy_preempt_shadow_local += s.busy_preempt_shadow_local;
            total.busy_preempt_shadow_remote += s.busy_preempt_shadow_remote;
            total.strict_busy_preempt_shadow_local += s.strict_busy_preempt_shadow_local;
            total.strict_busy_preempt_shadow_remote += s.strict_busy_preempt_shadow_remote;
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

#[cfg(cake_bpf_release)]
fn aggregate_stats(_skel: &BpfSkel) -> cake_stats {
    zero_cake_stats()
}

#[cfg(not(cake_bpf_release))]
fn extract_cpu_work(skel: &BpfSkel, nr_cpus: usize) -> Vec<CpuWorkCounters> {
    let mut work = vec![CpuWorkCounters::default(); nr_cpus];
    let trust_rows = trust::extract_trust_snapshots(skel, nr_cpus);

    if let Some(bss) = &skel.maps.bss_data {
        for (idx, stats) in bss.global_stats.iter().take(nr_cpus).enumerate() {
            #[cfg(debug_assertions)]
            let (
                select_target_reason,
                select_prev_reason,
                home_seed_reason,
                pressure_probe,
                pressure_anchor_block,
                target_wait_ns,
                target_wait_count,
                target_wait_max_ns,
                target_wait_bucket,
            ) = {
                let mut select_target_reason = [0; SELECT_REASON_MAX];
                let mut select_prev_reason = [0; SELECT_REASON_MAX];
                let mut home_seed_reason = [0; SELECT_REASON_MAX];
                let mut pressure_probe = [[0; PRESSURE_OUTCOME_MAX]; PRESSURE_SITE_MAX];
                let mut pressure_anchor_block =
                    [[0; PRESSURE_ANCHOR_REASON_MAX]; PRESSURE_SITE_MAX];
                let mut target_wait_ns = [0; WAKE_REASON_MAX];
                let mut target_wait_count = [0; WAKE_REASON_MAX];
                let mut target_wait_max_ns = [0; WAKE_REASON_MAX];
                let mut target_wait_bucket = [[0; WAKE_BUCKET_MAX]; WAKE_REASON_MAX];

                for reason in 0..SELECT_REASON_MAX {
                    select_target_reason[reason] = bss.select_reason_target_count[reason][idx];
                    select_prev_reason[reason] = bss.select_reason_prev_count[reason][idx];
                    home_seed_reason[reason] = bss.home_seed_reason_count[reason][idx];
                }

                for (site, outcomes) in pressure_probe
                    .iter_mut()
                    .enumerate()
                    .take(PRESSURE_SITE_MAX)
                {
                    for (outcome, slot) in
                        outcomes.iter_mut().enumerate().take(PRESSURE_OUTCOME_MAX)
                    {
                        *slot = bss.pressure_probe_cpu_count[site][outcome][idx];
                    }
                    for (reason, slot) in pressure_anchor_block[site]
                        .iter_mut()
                        .enumerate()
                        .take(PRESSURE_ANCHOR_REASON_MAX)
                    {
                        *slot = bss.pressure_anchor_block_cpu_count[site][reason][idx];
                    }
                }

                for (reason, buckets) in target_wait_bucket
                    .iter_mut()
                    .enumerate()
                    .take(WAKE_REASON_MAX)
                {
                    target_wait_ns[reason] = bss.wake_target_wait_ns[reason][idx];
                    target_wait_count[reason] = bss.wake_target_wait_count[reason][idx];
                    target_wait_max_ns[reason] = bss.wake_target_wait_max_ns[reason][idx];
                    for (bucket, slot) in buckets.iter_mut().enumerate().take(WAKE_BUCKET_MAX) {
                        *slot = bss.wake_target_wait_bucket_count[reason][idx][bucket];
                    }
                }

                (
                    select_target_reason,
                    select_prev_reason,
                    home_seed_reason,
                    pressure_probe,
                    pressure_anchor_block,
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
                home_seed_reason,
                pressure_probe,
                pressure_anchor_block,
                target_wait_ns,
                target_wait_count,
                target_wait_max_ns,
                target_wait_bucket,
            ) = (
                [0; SELECT_REASON_MAX],
                [0; SELECT_REASON_MAX],
                [0; SELECT_REASON_MAX],
                [[0; PRESSURE_OUTCOME_MAX]; PRESSURE_SITE_MAX],
                [[0; PRESSURE_ANCHOR_REASON_MAX]; PRESSURE_SITE_MAX],
                [0; WAKE_REASON_MAX],
                [0; WAKE_REASON_MAX],
                [0; WAKE_REASON_MAX],
                [[0; WAKE_BUCKET_MAX]; WAKE_REASON_MAX],
            );
            #[cfg(debug_assertions)]
            let home_seed_total = bss.home_seed_count[idx];
            #[cfg(not(debug_assertions))]
            let home_seed_total = 0;
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
            #[cfg(debug_assertions)]
            let blocked_owner_pid = bss.blocked_owner_pid[idx];
            #[cfg(not(debug_assertions))]
            let blocked_owner_pid = 0;
            #[cfg(debug_assertions)]
            let blocked_waiter_pid = bss.blocked_waiter_pid[idx];
            #[cfg(not(debug_assertions))]
            let blocked_waiter_pid = 0;
            #[cfg(debug_assertions)]
            let blocked_owner_wait_ns = bss.blocked_owner_wait_ns[idx];
            #[cfg(not(debug_assertions))]
            let blocked_owner_wait_ns = 0;
            #[cfg(debug_assertions)]
            let blocked_owner_wait_count = bss.blocked_owner_wait_count[idx];
            #[cfg(not(debug_assertions))]
            let blocked_owner_wait_count = 0;
            #[cfg(debug_assertions)]
            let blocked_owner_wait_max_ns = bss.blocked_owner_wait_max_ns[idx];
            #[cfg(not(debug_assertions))]
            let blocked_owner_wait_max_ns = 0;

            work[idx] = CpuWorkCounters {
                task_runtime_ns: stats.task_runtime_ns,
                task_run_count: stats.task_run_count,
                local_dispatches: stats.nr_local_dispatches,
                stolen_dispatches: stats.nr_stolen_dispatches,
                quantum_full: stats.nr_quantum_full,
                quantum_yield: stats.nr_quantum_yield,
                quantum_preempt: stats.nr_quantum_preempt,
                smt_solo_runtime_ns: stats.smt_solo_runtime_ns,
                smt_contended_runtime_ns: stats.smt_contended_runtime_ns,
                smt_overlap_runtime_ns: stats.smt_overlap_runtime_ns,
                smt_solo_run_count: stats.smt_solo_run_count,
                smt_contended_run_count: stats.smt_contended_run_count,
                smt_sibling_active_start_count: stats.smt_sibling_active_start_count,
                smt_sibling_active_stop_count: stats.smt_sibling_active_stop_count,
                smt_wake_wait_ns: stats.smt_wake_wait_ns,
                smt_wake_wait_count: stats.smt_wake_wait_count,
                smt_wake_wait_max_ns: stats.smt_wake_wait_max_ns,
                select_target_total: select_target_reason[1..].iter().sum(),
                select_prev_total: select_prev_reason[1..].iter().sum(),
                select_target_reason,
                select_prev_reason,
                home_seed_total,
                home_seed_reason,
                pressure_probe,
                pressure_anchor_block,
                cpu_pressure: bss.cpu_bss[idx].cpu_pressure,
                decision_confidence: bss.cpu_bss[idx].decision_confidence,
                trust: trust_rows.get(idx).copied().unwrap_or_default(),
                local_pending,
                local_pending_max,
                local_pending_inserts,
                local_pending_runs,
                wake_direct_target,
                wake_busy_target,
                wake_busy_local_target,
                wake_busy_remote_target,
                blocked_owner_pid,
                blocked_waiter_pid,
                blocked_owner_wait_ns,
                blocked_owner_wait_count,
                blocked_owner_wait_max_ns,
                target_wait_ns,
                target_wait_count,
                target_wait_max_ns,
                target_wait_bucket,
            };
        }
    }

    work
}

#[cfg(cake_bpf_release)]
fn extract_cpu_work(skel: &BpfSkel, nr_cpus: usize) -> Vec<CpuWorkCounters> {
    let mut work = vec![CpuWorkCounters::default(); nr_cpus];
    let trust_rows = trust::extract_trust_snapshots(skel, nr_cpus);

    if let Some(bss) = &skel.maps.bss_data {
        for idx in 0..nr_cpus.min(bss.cpu_status.len()) {
            work[idx].cpu_pressure = cake_cpu_status_pressure_bucket(bss.cpu_status[idx].flags);
            work[idx].decision_confidence = bss.cpu_bss[idx].decision_confidence;
            work[idx].trust = trust_rows.get(idx).copied().unwrap_or_default();
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
            for reason in 0..PRESSURE_ANCHOR_REASON_MAX {
                pressure_probe.anchor_block[site][reason] =
                    bss.pressure_anchor_block_total[site][reason];
            }
        }
    }

    pressure_probe
}

#[cfg(debug_assertions)]
fn extract_wake_graph(skel: &BpfSkel, state: &Arc<Mutex<WakeGraphState>>) -> WakeGraphCounters {
    let mut graph = state
        .lock()
        .map(|state| state.snapshot())
        .unwrap_or_default();
    if let Some(bss) = &skel.maps.bss_data {
        graph.missed_updates = graph
            .missed_updates
            .saturating_add(bss.wake_edge_missed_updates);
    }
    graph
}

#[cfg(not(debug_assertions))]
fn extract_wake_graph(_skel: &BpfSkel, _state: &Arc<Mutex<WakeGraphState>>) -> WakeGraphCounters {
    WakeGraphCounters::default()
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
            let mut trust = cur.trust;
            trust.demotion_count = cur
                .trust
                .demotion_count
                .saturating_sub(prev.trust.demotion_count);
            CpuWorkCounters {
                task_runtime_ns: cur.task_runtime_ns.saturating_sub(prev.task_runtime_ns),
                task_run_count: cur.task_run_count.saturating_sub(prev.task_run_count),
                local_dispatches: cur.local_dispatches.saturating_sub(prev.local_dispatches),
                stolen_dispatches: cur.stolen_dispatches.saturating_sub(prev.stolen_dispatches),
                quantum_full: cur.quantum_full.saturating_sub(prev.quantum_full),
                quantum_yield: cur.quantum_yield.saturating_sub(prev.quantum_yield),
                quantum_preempt: cur.quantum_preempt.saturating_sub(prev.quantum_preempt),
                smt_solo_runtime_ns: cur
                    .smt_solo_runtime_ns
                    .saturating_sub(prev.smt_solo_runtime_ns),
                smt_contended_runtime_ns: cur
                    .smt_contended_runtime_ns
                    .saturating_sub(prev.smt_contended_runtime_ns),
                smt_overlap_runtime_ns: cur
                    .smt_overlap_runtime_ns
                    .saturating_sub(prev.smt_overlap_runtime_ns),
                smt_solo_run_count: cur
                    .smt_solo_run_count
                    .saturating_sub(prev.smt_solo_run_count),
                smt_contended_run_count: cur
                    .smt_contended_run_count
                    .saturating_sub(prev.smt_contended_run_count),
                smt_sibling_active_start_count: cur
                    .smt_sibling_active_start_count
                    .saturating_sub(prev.smt_sibling_active_start_count),
                smt_sibling_active_stop_count: cur
                    .smt_sibling_active_stop_count
                    .saturating_sub(prev.smt_sibling_active_stop_count),
                smt_wake_wait_ns: std::array::from_fn(|bucket| {
                    cur.smt_wake_wait_ns[bucket].saturating_sub(prev.smt_wake_wait_ns[bucket])
                }),
                smt_wake_wait_count: std::array::from_fn(|bucket| {
                    cur.smt_wake_wait_count[bucket].saturating_sub(prev.smt_wake_wait_count[bucket])
                }),
                smt_wake_wait_max_ns: cur.smt_wake_wait_max_ns,
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
                home_seed_total: cur.home_seed_total.saturating_sub(prev.home_seed_total),
                home_seed_reason: std::array::from_fn(|reason| {
                    cur.home_seed_reason[reason].saturating_sub(prev.home_seed_reason[reason])
                }),
                pressure_probe: std::array::from_fn(|site| {
                    std::array::from_fn(|outcome| {
                        cur.pressure_probe[site][outcome]
                            .saturating_sub(prev.pressure_probe[site][outcome])
                    })
                }),
                pressure_anchor_block: std::array::from_fn(|site| {
                    std::array::from_fn(|reason| {
                        cur.pressure_anchor_block[site][reason]
                            .saturating_sub(prev.pressure_anchor_block[site][reason])
                    })
                }),
                cpu_pressure: cur.cpu_pressure,
                decision_confidence: cur.decision_confidence,
                trust,
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
                blocked_owner_pid: cur.blocked_owner_pid,
                blocked_waiter_pid: cur.blocked_waiter_pid,
                blocked_owner_wait_ns: cur
                    .blocked_owner_wait_ns
                    .saturating_sub(prev.blocked_owner_wait_ns),
                blocked_owner_wait_count: cur
                    .blocked_owner_wait_count
                    .saturating_sub(prev.blocked_owner_wait_count),
                blocked_owner_wait_max_ns: cur.blocked_owner_wait_max_ns,
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
        anchor_block: std::array::from_fn(|site| {
            std::array::from_fn(|reason| {
                current.anchor_block[site][reason]
                    .saturating_sub(previous.anchor_block[site][reason])
            })
        }),
    }
}

fn stats_delta(current: &cake_stats, previous: &cake_stats) -> cake_stats {
    let mut delta = zero_cake_stats();

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
    delta.nr_primary_scan_guarded = current
        .nr_primary_scan_guarded
        .saturating_sub(previous.nr_primary_scan_guarded);
    delta.nr_primary_scan_credit_used = current
        .nr_primary_scan_credit_used
        .saturating_sub(previous.nr_primary_scan_credit_used);
    delta.nr_primary_scan_hot_guarded = current
        .nr_primary_scan_hot_guarded
        .saturating_sub(previous.nr_primary_scan_hot_guarded);
    delta.nr_wake_chain_locality_guarded = current
        .nr_wake_chain_locality_guarded
        .saturating_sub(previous.nr_wake_chain_locality_guarded);
    delta.nr_wake_chain_locality_credit_used = current
        .nr_wake_chain_locality_credit_used
        .saturating_sub(previous.nr_wake_chain_locality_credit_used);
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
    delta.smt_solo_runtime_ns = current
        .smt_solo_runtime_ns
        .saturating_sub(previous.smt_solo_runtime_ns);
    delta.smt_contended_runtime_ns = current
        .smt_contended_runtime_ns
        .saturating_sub(previous.smt_contended_runtime_ns);
    delta.smt_overlap_runtime_ns = current
        .smt_overlap_runtime_ns
        .saturating_sub(previous.smt_overlap_runtime_ns);
    delta.smt_solo_run_count = current
        .smt_solo_run_count
        .saturating_sub(previous.smt_solo_run_count);
    delta.smt_contended_run_count = current
        .smt_contended_run_count
        .saturating_sub(previous.smt_contended_run_count);
    delta.smt_sibling_active_start_count = current
        .smt_sibling_active_start_count
        .saturating_sub(previous.smt_sibling_active_start_count);
    delta.smt_sibling_active_stop_count = current
        .smt_sibling_active_stop_count
        .saturating_sub(previous.smt_sibling_active_stop_count);
    for bucket in 0..2 {
        delta.smt_wake_wait_ns[bucket] =
            current.smt_wake_wait_ns[bucket].saturating_sub(previous.smt_wake_wait_ns[bucket]);
        delta.smt_wake_wait_count[bucket] = current.smt_wake_wait_count[bucket]
            .saturating_sub(previous.smt_wake_wait_count[bucket]);
        delta.smt_wake_wait_max_ns[bucket] = current.smt_wake_wait_max_ns[bucket];
    }
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
    delta.nr_running_same_task = current
        .nr_running_same_task
        .saturating_sub(previous.nr_running_same_task);
    delta.nr_running_task_change = current
        .nr_running_task_change
        .saturating_sub(previous.nr_running_task_change);
    delta.nr_stopping_runnable = current
        .nr_stopping_runnable
        .saturating_sub(previous.nr_stopping_runnable);
    delta.nr_stopping_blocked = current
        .nr_stopping_blocked
        .saturating_sub(previous.nr_stopping_blocked);
    delta.nr_enqueue_path_kthread = current
        .nr_enqueue_path_kthread
        .saturating_sub(previous.nr_enqueue_path_kthread);
    delta.nr_enqueue_path_initial = current
        .nr_enqueue_path_initial
        .saturating_sub(previous.nr_enqueue_path_initial);
    delta.nr_enqueue_path_preserve = current
        .nr_enqueue_path_preserve
        .saturating_sub(previous.nr_enqueue_path_preserve);
    delta.nr_enqueue_path_requeue = current
        .nr_enqueue_path_requeue
        .saturating_sub(previous.nr_enqueue_path_requeue);
    delta.nr_enqueue_path_wakeup = current
        .nr_enqueue_path_wakeup
        .saturating_sub(previous.nr_enqueue_path_wakeup);
    delta.nr_enqueue_path_affine_preserve = current
        .nr_enqueue_path_affine_preserve
        .saturating_sub(previous.nr_enqueue_path_affine_preserve);
    delta.nr_enqueue_path_affine_requeue = current
        .nr_enqueue_path_affine_requeue
        .saturating_sub(previous.nr_enqueue_path_affine_requeue);
    delta.nr_enqueue_path_affine_dispatch = current
        .nr_enqueue_path_affine_dispatch
        .saturating_sub(previous.nr_enqueue_path_affine_dispatch);
    delta.nr_llc_vtime_wake_idle_direct = current
        .nr_llc_vtime_wake_idle_direct
        .saturating_sub(previous.nr_llc_vtime_wake_idle_direct);
    delta.nr_llc_vtime_wake_busy_shared = current
        .nr_llc_vtime_wake_busy_shared
        .saturating_sub(previous.nr_llc_vtime_wake_busy_shared);
    delta.nr_llc_vtime_nonwake_shared = current
        .nr_llc_vtime_nonwake_shared
        .saturating_sub(previous.nr_llc_vtime_nonwake_shared);
    delta.nr_dispatch_llc_local_hit = current
        .nr_dispatch_llc_local_hit
        .saturating_sub(previous.nr_dispatch_llc_local_hit);
    delta.nr_dispatch_llc_local_miss = current
        .nr_dispatch_llc_local_miss
        .saturating_sub(previous.nr_dispatch_llc_local_miss);
    delta.nr_dispatch_llc_steal_hit = current
        .nr_dispatch_llc_steal_hit
        .saturating_sub(previous.nr_dispatch_llc_steal_hit);
    delta.nr_dispatch_keep_running = current
        .nr_dispatch_keep_running
        .saturating_sub(previous.nr_dispatch_keep_running);
    delta.lifecycle_init_enqueue_us = current
        .lifecycle_init_enqueue_us
        .saturating_sub(previous.lifecycle_init_enqueue_us);
    delta.lifecycle_init_enqueue_count = current
        .lifecycle_init_enqueue_count
        .saturating_sub(previous.lifecycle_init_enqueue_count);
    delta.lifecycle_init_select_us = current
        .lifecycle_init_select_us
        .saturating_sub(previous.lifecycle_init_select_us);
    delta.lifecycle_init_select_count = current
        .lifecycle_init_select_count
        .saturating_sub(previous.lifecycle_init_select_count);
    delta.lifecycle_init_run_us = current
        .lifecycle_init_run_us
        .saturating_sub(previous.lifecycle_init_run_us);
    delta.lifecycle_init_run_count = current
        .lifecycle_init_run_count
        .saturating_sub(previous.lifecycle_init_run_count);
    delta.lifecycle_init_exit_us = current
        .lifecycle_init_exit_us
        .saturating_sub(previous.lifecycle_init_exit_us);
    delta.lifecycle_init_exit_count = current
        .lifecycle_init_exit_count
        .saturating_sub(previous.lifecycle_init_exit_count);
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
        delta.select_path_migration_count[path] = current.select_path_migration_count[path]
            .saturating_sub(previous.select_path_migration_count[path]);
    }
    for reason in 0..current.select_reason_wait_ns.len() {
        delta.select_reason_migration_count[reason] = current.select_reason_migration_count[reason]
            .saturating_sub(previous.select_reason_migration_count[reason]);
        delta.select_reason_wait_ns[reason] = current.select_reason_wait_ns[reason]
            .saturating_sub(previous.select_reason_wait_ns[reason]);
        delta.select_reason_wait_count[reason] = current.select_reason_wait_count[reason]
            .saturating_sub(previous.select_reason_wait_count[reason]);
        delta.select_reason_wait_max_ns[reason] = current.select_reason_wait_max_ns[reason];
        for bucket in 0..current.select_reason_bucket_count[reason].len() {
            delta.select_reason_bucket_count[reason][bucket] = current.select_reason_bucket_count
                [reason][bucket]
                .saturating_sub(previous.select_reason_bucket_count[reason][bucket]);
        }
        delta.select_reason_select_ns[reason] = current.select_reason_select_ns[reason]
            .saturating_sub(previous.select_reason_select_ns[reason]);
        delta.select_reason_select_count[reason] = current.select_reason_select_count[reason]
            .saturating_sub(previous.select_reason_select_count[reason]);
        delta.select_reason_select_max_ns[reason] = current.select_reason_select_max_ns[reason];
    }
    for route in 0..current.accel_route_attempt_count.len() {
        delta.accel_route_attempt_count[route] = current.accel_route_attempt_count[route]
            .saturating_sub(previous.accel_route_attempt_count[route]);
        delta.accel_route_hit_count[route] = current.accel_route_hit_count[route]
            .saturating_sub(previous.accel_route_hit_count[route]);
        delta.accel_route_miss_count[route] = current.accel_route_miss_count[route]
            .saturating_sub(previous.accel_route_miss_count[route]);
        delta.accel_fast_attempt_count[route] = current.accel_fast_attempt_count[route]
            .saturating_sub(previous.accel_fast_attempt_count[route]);
        delta.accel_fast_hit_count[route] = current.accel_fast_hit_count[route]
            .saturating_sub(previous.accel_fast_hit_count[route]);
        delta.accel_fast_miss_count[route] = current.accel_fast_miss_count[route]
            .saturating_sub(previous.accel_fast_miss_count[route]);
        for outcome in 0..current.accel_scoreboard_probe_count[route].len() {
            delta.accel_scoreboard_probe_count[route][outcome] = current
                .accel_scoreboard_probe_count[route][outcome]
                .saturating_sub(previous.accel_scoreboard_probe_count[route][outcome]);
        }
    }
    for reason in 0..current.accel_route_block_count.len() {
        delta.accel_route_block_count[reason] = current.accel_route_block_count[reason]
            .saturating_sub(previous.accel_route_block_count[reason]);
    }
    for mode in 0..current.accel_pull_mode_count.len() {
        delta.accel_pull_mode_count[mode] = current.accel_pull_mode_count[mode]
            .saturating_sub(previous.accel_pull_mode_count[mode]);
    }
    for outcome in 0..current.accel_pull_probe_count.len() {
        delta.accel_pull_probe_count[outcome] = current.accel_pull_probe_count[outcome]
            .saturating_sub(previous.accel_pull_probe_count[outcome]);
    }
    for kind in 0..current.accel_native_fallback_count.len() {
        delta.accel_native_fallback_count[kind] = current.accel_native_fallback_count[kind]
            .saturating_sub(previous.accel_native_fallback_count[kind]);
    }
    delta.accel_accounting_relaxed = current
        .accel_accounting_relaxed
        .saturating_sub(previous.accel_accounting_relaxed);
    delta.accel_accounting_audit = current
        .accel_accounting_audit
        .saturating_sub(previous.accel_accounting_audit);
    delta.accel_trust_prev_attempt = current
        .accel_trust_prev_attempt
        .saturating_sub(previous.accel_trust_prev_attempt);
    delta.accel_trust_prev_hit = current
        .accel_trust_prev_hit
        .saturating_sub(previous.accel_trust_prev_hit);
    delta.accel_trust_prev_miss = current
        .accel_trust_prev_miss
        .saturating_sub(previous.accel_trust_prev_miss);
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
    for class in 0..current.wake_class_sample_count.len() {
        delta.wake_class_sample_count[class] = current.wake_class_sample_count[class]
            .saturating_sub(previous.wake_class_sample_count[class]);
        delta.strict_wake_class_sample_count[class] = current.strict_wake_class_sample_count[class]
            .saturating_sub(previous.strict_wake_class_sample_count[class]);
        delta.busy_preempt_shadow_wakee_class_count[class] = current
            .busy_preempt_shadow_wakee_class_count[class]
            .saturating_sub(previous.busy_preempt_shadow_wakee_class_count[class]);
        delta.busy_preempt_shadow_owner_class_count[class] = current
            .busy_preempt_shadow_owner_class_count[class]
            .saturating_sub(previous.busy_preempt_shadow_owner_class_count[class]);
        delta.strict_busy_preempt_shadow_wakee_class_count[class] = current
            .strict_busy_preempt_shadow_wakee_class_count[class]
            .saturating_sub(previous.strict_busy_preempt_shadow_wakee_class_count[class]);
        delta.strict_busy_preempt_shadow_owner_class_count[class] = current
            .strict_busy_preempt_shadow_owner_class_count[class]
            .saturating_sub(previous.strict_busy_preempt_shadow_owner_class_count[class]);
        delta.strict_wake_class_wait_ns[class] = current.strict_wake_class_wait_ns[class]
            .saturating_sub(previous.strict_wake_class_wait_ns[class]);
        delta.strict_wake_class_wait_count[class] = current.strict_wake_class_wait_count[class]
            .saturating_sub(previous.strict_wake_class_wait_count[class]);
        delta.strict_wake_class_wait_max_ns[class] = current.strict_wake_class_wait_max_ns[class];
        for next in 0..current.wake_class_transition_count[class].len() {
            delta.wake_class_transition_count[class][next] = current.wake_class_transition_count
                [class][next]
                .saturating_sub(previous.wake_class_transition_count[class][next]);
            delta.strict_wake_class_transition_count[class][next] = current
                .strict_wake_class_transition_count[class][next]
                .saturating_sub(previous.strict_wake_class_transition_count[class][next]);
        }
        for bucket in 0..current.strict_wake_class_bucket_count[class].len() {
            delta.strict_wake_class_bucket_count[class][bucket] = current
                .strict_wake_class_bucket_count[class][bucket]
                .saturating_sub(previous.strict_wake_class_bucket_count[class][bucket]);
        }
    }
    for reason in 0..current.wake_class_reason_count.len() {
        delta.wake_class_reason_count[reason] = current.wake_class_reason_count[reason]
            .saturating_sub(previous.wake_class_reason_count[reason]);
        delta.strict_wake_class_reason_count[reason] = current.strict_wake_class_reason_count
            [reason]
            .saturating_sub(previous.strict_wake_class_reason_count[reason]);
    }
    for decision in 0..current.busy_preempt_shadow_count.len() {
        delta.busy_preempt_shadow_count[decision] = current.busy_preempt_shadow_count[decision]
            .saturating_sub(previous.busy_preempt_shadow_count[decision]);
        delta.strict_busy_preempt_shadow_count[decision] = current.strict_busy_preempt_shadow_count
            [decision]
            .saturating_sub(previous.strict_busy_preempt_shadow_count[decision]);
    }
    delta.busy_preempt_shadow_local = current
        .busy_preempt_shadow_local
        .saturating_sub(previous.busy_preempt_shadow_local);
    delta.busy_preempt_shadow_remote = current
        .busy_preempt_shadow_remote
        .saturating_sub(previous.busy_preempt_shadow_remote);
    delta.strict_busy_preempt_shadow_local = current
        .strict_busy_preempt_shadow_local
        .saturating_sub(previous.strict_busy_preempt_shadow_local);
    delta.strict_busy_preempt_shadow_remote = current
        .strict_busy_preempt_shadow_remote
        .saturating_sub(previous.strict_busy_preempt_shadow_remote);
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

#[cfg(not(cake_bpf_release))]
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

fn avg_task_runtime_us(row: &TaskTelemetryRow) -> u64 {
    if row.total_runs > 0 {
        row.total_runtime_ns / row.total_runs as u64 / 1000
    } else {
        0
    }
}

#[cfg(debug_assertions)]
fn read_thread_schedstat(tgid: u32, pid: u32) -> Option<(u64, u64, u64)> {
    let owner = if tgid > 0 { tgid } else { pid };
    let primary = format!("/proc/{}/task/{}/schedstat", owner, pid);
    let fallback = format!("/proc/{}/schedstat", pid);
    let data = std::fs::read_to_string(&primary)
        .or_else(|_| std::fs::read_to_string(&fallback))
        .ok()?;
    let mut fields = data.split_whitespace();
    let runtime_ns = fields.next()?.parse().ok()?;
    let wait_ns = fields.next()?.parse().ok()?;
    let slices = fields.next()?.parse().ok()?;

    Some((runtime_ns, wait_ns, slices))
}

#[cfg(debug_assertions)]
#[derive(Clone, Debug, Default)]
struct ProcThreadSnapshot {
    status_seen: bool,
    stat_seen: bool,
    tgid: u32,
    ppid: u32,
    comm: Option<String>,
    processor: Option<u16>,
    allowed_cpus: Option<u16>,
    task_policy: Option<u32>,
    task_prio: Option<u32>,
    task_static_prio: Option<u32>,
    task_normal_prio: Option<u32>,
}

#[cfg(debug_assertions)]
fn parse_cpu_list_count(value: &str) -> Option<u16> {
    let mut total = 0u32;

    for part in value.trim().split(',').filter(|part| !part.is_empty()) {
        let mut ends = part.splitn(2, '-');
        let start = ends.next()?.trim().parse::<u32>().ok()?;
        let end = ends
            .next()
            .map(|raw| raw.trim().parse::<u32>().ok())
            .unwrap_or(Some(start))?;
        if end < start {
            continue;
        }
        total = total.saturating_add(end - start + 1);
    }

    Some(total.min(u16::MAX as u32) as u16)
}

#[cfg(debug_assertions)]
impl ProcThreadSnapshot {
    fn seen(&self) -> bool {
        self.status_seen || self.stat_seen
    }
}

#[cfg(debug_assertions)]
fn read_thread_status_snapshot(tgid: u32, pid: u32, snap: &mut ProcThreadSnapshot) -> bool {
    let owner = if tgid > 0 { tgid } else { pid };
    let primary = format!("/proc/{}/task/{}/status", owner, pid);
    let fallback = format!("/proc/{}/status", pid);
    let Ok(data) =
        std::fs::read_to_string(&primary).or_else(|_| std::fs::read_to_string(&fallback))
    else {
        return false;
    };
    snap.status_seen = true;

    for line in data.lines() {
        if let Some(value) = line.strip_prefix("Tgid:") {
            snap.tgid = value.trim().parse().unwrap_or(snap.tgid);
        } else if let Some(value) = line.strip_prefix("PPid:") {
            snap.ppid = value.trim().parse().unwrap_or(snap.ppid);
        } else if let Some(value) = line.strip_prefix("Cpus_allowed_list:") {
            snap.allowed_cpus = parse_cpu_list_count(value);
        }
    }
    true
}

#[cfg(debug_assertions)]
fn read_thread_stat_snapshot(tgid: u32, pid: u32, snap: &mut ProcThreadSnapshot) -> bool {
    let owner = if tgid > 0 { tgid } else { pid };
    let primary = format!("/proc/{}/task/{}/stat", owner, pid);
    let fallback = format!("/proc/{}/stat", pid);
    let Ok(data) =
        std::fs::read_to_string(&primary).or_else(|_| std::fs::read_to_string(&fallback))
    else {
        return false;
    };
    let Some(open) = data.find('(') else {
        return false;
    };
    let Some(close) = data.rfind(')') else {
        return false;
    };
    snap.stat_seen = true;
    if close > open + 1 {
        snap.comm = Some(data[open + 1..close].to_string());
    }
    let fields: Vec<&str> = data[close + 1..].split_whitespace().collect();

    if snap.ppid == 0 {
        snap.ppid = fields
            .get(1)
            .and_then(|value| value.parse().ok())
            .unwrap_or(0);
    }
    snap.task_prio = fields.get(15).and_then(|value| value.parse().ok());
    snap.task_static_prio = fields
        .get(16)
        .and_then(|value| value.parse::<i32>().ok())
        .map(|nice| (nice + 120).clamp(0, 255) as u32);
    snap.task_normal_prio = snap.task_prio;
    snap.processor = fields
        .get(36)
        .and_then(|value| value.parse::<u32>().ok())
        .map(|cpu| cpu.min(u16::MAX as u32) as u16);
    snap.task_policy = fields.get(38).and_then(|value| value.parse().ok());
    true
}

#[cfg(debug_assertions)]
fn read_thread_proc_snapshot(tgid: u32, pid: u32) -> ProcThreadSnapshot {
    let mut snap = ProcThreadSnapshot {
        tgid: if tgid > 0 { tgid } else { pid },
        ..Default::default()
    };

    let _ = read_thread_status_snapshot(tgid, pid, &mut snap);
    let _ = read_thread_stat_snapshot(snap.tgid, pid, &mut snap);
    if snap.tgid == 0 {
        snap.tgid = if tgid > 0 { tgid } else { pid };
    }
    snap
}

fn row_has_bpf_matrix_data(row: &TaskTelemetryRow) -> bool {
    if !row.is_bpf_tracked || row.status == TaskStatus::Dead {
        return false;
    }

    #[cfg(cake_needs_arena)]
    {
        row.pid > 0
    }
    #[cfg(not(cake_needs_arena))]
    {
        true
    }
}

fn row_has_runtime_telemetry(row: &TaskTelemetryRow) -> bool {
    row.is_bpf_tracked && row.total_runs > 0 && row.status != TaskStatus::Dead
}

fn task_smt_contended_pct(row: &TaskTelemetryRow) -> f64 {
    pct(row.smt_contended_runtime_ns, row.total_runtime_ns)
}

fn task_smt_overlap_pct(row: &TaskTelemetryRow) -> f64 {
    pct(row.smt_overlap_runtime_ns, row.total_runtime_ns)
}

fn runtime_rate_ms(row: &TaskTelemetryRow) -> f64 {
    row.runtime_ns_per_sec / 1_000_000.0
}

#[cfg(debug_assertions)]
fn task_anatomy_input_from_row(
    row: &TaskTelemetryRow,
    system_cpus: u16,
) -> crate::task_anatomy::TaskAnatomyInput {
    crate::task_anatomy::TaskAnatomyInput {
        pid: row.pid,
        tgid: row.tgid,
        ppid: row.ppid,
        comm: row.comm.clone(),
        pelt_util: row.pelt_util,
        runs_per_sec: row.runs_per_sec,
        migrations_per_sec: row.migrations_per_sec,
        runtime_ms_per_sec: runtime_rate_ms(row),
        avg_runtime_us: avg_task_runtime_us(row),
        max_runtime_us: row.max_runtime_us,
        last_wait_us: row.wait_duration_ns / 1000,
        max_dispatch_gap_us: row.max_dispatch_gap_us,
        allowed_cpus: row.allowed_cpus,
        system_cpus,
        smt_contended_pct: task_smt_contended_pct(row),
        smt_overlap_pct: task_smt_overlap_pct(row),
        wake_same_tgid_count: row.wake_same_tgid_count,
        wake_cross_tgid_count: row.wake_cross_tgid_count,
        quantum_full: row.quantum_full_count,
        quantum_yield: row.quantum_yield_count,
        quantum_preempt: row.quantum_preempt_count,
        task_flags: row.task_flags,
        task_policy: row.task_policy,
        task_prio: row.task_prio,
        task_static_prio: row.task_static_prio,
        task_normal_prio: row.task_normal_prio,
        task_has_mm: row.task_has_mm,
        task_is_kthread: row.task_is_kthread,
        last_select_path: row.last_select_path,
        last_select_reason: row.last_select_reason,
        last_place_class: row.last_place_class,
        last_waker_place_class: row.last_waker_place_class,
    }
}

#[cfg(debug_assertions)]
fn strict_wake_policy_input_from_row(
    row: &TaskTelemetryRow,
) -> crate::task_anatomy::StrictWakePolicyInput {
    crate::task_anatomy::StrictWakePolicyInput {
        task_prio: if row.task_prio == 0 {
            120
        } else {
            row.task_prio
        },
        task_weight: row.task_weight,
        total_runs: row.total_runs as u64,
        total_runtime_ns: row.total_runtime_ns,
        quantum_full: row.quantum_full_count,
        quantum_yield: row.quantum_yield_count,
        quantum_preempt: row.quantum_preempt_count,
        yield_count: row.yield_count as u64,
        wait_duration_ns: row.wait_duration_ns,
    }
}

fn affinity_label(row: &TaskTelemetryRow, topology: &TopologyInfo) -> String {
    let allowed = if row.allowed_cpus == 0 {
        topology.nr_cpus as u16
    } else {
        row.allowed_cpus
    };
    let suffix = if allowed as usize >= topology.nr_cpus {
        "wide"
    } else if allowed <= 1 {
        "pin"
    } else {
        "rest"
    };
    format!(
        "{}/{}:{} chg={}",
        allowed, topology.nr_cpus, suffix, row.cpumask_change_count
    )
}

fn home_quality_label(row: &TaskTelemetryRow) -> String {
    let home = if row.home_cpu == 0xff {
        "-".to_string()
    } else {
        format!("C{:02}/K{:02}", row.home_cpu, row.home_core)
    };
    format!("{} score={}", home, row.home_score)
}

fn blocker_label(row: &TaskTelemetryRow, tasks: &HashMap<u32, TaskTelemetryRow>) -> String {
    if row.last_blocker_pid == 0 || row.blocked_count == 0 {
        return "-".to_string();
    }
    let blocker = tasks
        .get(&row.last_blocker_pid)
        .map(|task| task.comm.as_str())
        .unwrap_or("unknown");
    format!(
        "{}[{}]@C{:02} last={}us max={}us n={}",
        blocker,
        row.last_blocker_pid,
        row.last_blocker_cpu,
        row.blocked_wait_last_us,
        row.blocked_wait_max_us,
        row.blocked_count
    )
}

fn apply_blocked_wait_attribution(app: &mut TuiApp) {
    let blocked: Vec<(u32, u32, u16, u32, u32, u16)> = app
        .per_cpu_work
        .iter()
        .enumerate()
        .filter_map(|(cpu, counter)| {
            if counter.blocked_waiter_pid == 0 || counter.blocked_owner_wait_count == 0 {
                return None;
            }

            let avg_wait_us =
                (counter.blocked_owner_wait_ns / counter.blocked_owner_wait_count.max(1) / 1000)
                    .min(u32::MAX as u64) as u32;
            let max_wait_us =
                (counter.blocked_owner_wait_max_ns / 1000).min(u32::MAX as u64) as u32;
            let count = counter.blocked_owner_wait_count.min(u16::MAX as u64) as u16;

            Some((
                counter.blocked_waiter_pid,
                counter.blocked_owner_pid,
                cpu.min(u16::MAX as usize) as u16,
                avg_wait_us,
                max_wait_us,
                count,
            ))
        })
        .collect();

    for row in app.task_rows.values_mut() {
        row.last_blocker_pid = 0;
        row.last_blocker_cpu = 0;
        row.blocked_wait_last_us = 0;
        row.blocked_wait_max_us = 0;
        row.blocked_count = 0;
    }

    for (waiter_pid, owner_pid, cpu, avg_wait_us, max_wait_us, count) in blocked {
        if let Some(row) = app.task_rows.get_mut(&waiter_pid) {
            row.last_blocker_pid = owner_pid;
            row.last_blocker_cpu = cpu;
            row.blocked_wait_last_us = avg_wait_us;
            row.blocked_wait_max_us = row.blocked_wait_max_us.max(max_wait_us);
            row.blocked_count = row.blocked_count.saturating_add(count);
        }
    }
}

fn is_game_identity_comm(comm: &str) -> bool {
    let comm = comm.to_ascii_lowercase();
    comm.ends_with(".exe")
        || comm.contains("wow")
        || comm_has_any(&comm, &["dxvk", "vkd3d", "unitygfx", "game"])
}

fn is_generic_worker_identity_comm(comm: &str) -> bool {
    let comm = comm.to_ascii_lowercase();
    comm_has_any(
        &comm,
        &[
            "threadpool",
            "thread_pool",
            "worker",
            "workqueue",
            "tokio-runtime",
            "chrome_childio",
            "utility",
        ],
    )
}

fn choose_app_comm(identity: &TgidIdentity) -> String {
    if identity.leader_comm.is_empty() {
        return identity.dominant_runtime_comm.clone();
    }
    if browser_ui_hint(&identity.leader_comm.to_ascii_lowercase())
        && is_game_identity_comm(&identity.dominant_thread_comm)
    {
        return identity.dominant_thread_comm.clone();
    }
    if !identity.dominant_runtime_comm.is_empty()
        && identity.dominant_runtime_comm != identity.leader_comm
        && !is_generic_worker_identity_comm(&identity.dominant_runtime_comm)
    {
        return identity.dominant_runtime_comm.clone();
    }
    if !identity.dominant_thread_comm.is_empty()
        && identity.dominant_thread_comm != identity.leader_comm
        && is_game_identity_comm(&identity.dominant_thread_comm)
    {
        return identity.dominant_thread_comm.clone();
    }
    identity.leader_comm.clone()
}

fn build_tgid_identities(app: &TuiApp) -> HashMap<u32, TgidIdentity> {
    let mut identities = HashMap::<u32, TgidIdentity>::new();
    let mut runtime_by_comm = HashMap::<u32, HashMap<String, u64>>::new();
    let mut count_by_comm = HashMap::<u32, HashMap<String, usize>>::new();
    let mut live_count_by_comm = HashMap::<u32, HashMap<String, usize>>::new();

    for row in app.task_rows.values() {
        if !row.is_bpf_tracked || row.status == TaskStatus::Dead {
            continue;
        }
        let tgid = if row.tgid > 0 { row.tgid } else { row.pid };
        let identity = identities.entry(tgid).or_default();
        if row.pid == tgid || identity.leader_comm.is_empty() {
            identity.leader_comm = row.comm.clone();
        }

        *live_count_by_comm
            .entry(tgid)
            .or_default()
            .entry(row.comm.clone())
            .or_default() += 1;

        if row.total_runs == 0 {
            continue;
        }

        identity.total_runtime_ns = identity
            .total_runtime_ns
            .saturating_add(row.total_runtime_ns);
        *runtime_by_comm
            .entry(tgid)
            .or_default()
            .entry(row.comm.clone())
            .or_default() += row.total_runtime_ns;
        *count_by_comm
            .entry(tgid)
            .or_default()
            .entry(row.comm.clone())
            .or_default() += 1;
    }

    for (tgid, identity) in identities.iter_mut() {
        let counts = count_by_comm
            .get(tgid)
            .or_else(|| live_count_by_comm.get(tgid));
        let Some(counts) = counts else {
            continue;
        };
        let runtimes = runtime_by_comm.get(tgid);
        identity.comm_kinds = counts.len();

        let mut top_runtime_comm = String::new();
        let mut top_runtime_ns = 0u64;
        let mut top_runtime_count = 0usize;
        for (comm, count) in counts {
            let runtime_ns = runtimes
                .and_then(|by_comm| by_comm.get(comm))
                .copied()
                .unwrap_or(0);
            if runtime_ns > top_runtime_ns
                || (runtime_ns == top_runtime_ns
                    && (*count > top_runtime_count
                        || (*count == top_runtime_count && comm < &top_runtime_comm)))
            {
                top_runtime_comm = comm.clone();
                top_runtime_ns = runtime_ns;
                top_runtime_count = *count;
            }
        }
        identity.dominant_runtime_comm = top_runtime_comm;
        identity.dominant_runtime_ns = top_runtime_ns;

        let mut top_thread_comm = String::new();
        let mut top_thread_count = 0usize;
        let mut top_thread_runtime_ns = 0u64;
        for (comm, count) in counts {
            let runtime_ns = runtimes
                .and_then(|by_comm| by_comm.get(comm))
                .copied()
                .unwrap_or(0);
            if *count > top_thread_count
                || (*count == top_thread_count
                    && (runtime_ns > top_thread_runtime_ns
                        || (runtime_ns == top_thread_runtime_ns && comm < &top_thread_comm)))
            {
                top_thread_comm = comm.clone();
                top_thread_count = *count;
                top_thread_runtime_ns = runtime_ns;
            }
        }
        identity.dominant_thread_comm = top_thread_comm;
        identity.dominant_thread_count = top_thread_count;
        if identity.leader_comm.is_empty() {
            identity.leader_comm = identity.dominant_thread_comm.clone();
        }
        identity.app_comm = choose_app_comm(identity);
    }

    identities
}

fn fallback_tgid_identity(_tgid: u32, row: &TaskTelemetryRow) -> TgidIdentity {
    let leader_comm = row.comm.clone();
    TgidIdentity {
        leader_comm: leader_comm.clone(),
        app_comm: leader_comm.clone(),
        dominant_runtime_comm: leader_comm.clone(),
        dominant_runtime_ns: row.total_runtime_ns,
        dominant_thread_comm: leader_comm,
        dominant_thread_count: 1,
        comm_kinds: 1,
        total_runtime_ns: row.total_runtime_ns,
    }
}

fn tgid_header_name(identity: &TgidIdentity) -> String {
    if !identity.leader_comm.is_empty() && identity.app_comm != identity.leader_comm {
        format!("{} leader={}", identity.app_comm, identity.leader_comm)
    } else if !identity.app_comm.is_empty() {
        identity.app_comm.clone()
    } else {
        identity.leader_comm.clone()
    }
}

fn build_long_run_owner_rows(
    app: &TuiApp,
    tgid_roles: &HashMap<u32, WorkloadRole>,
    limit: usize,
) -> Vec<LongRunOwnerRow> {
    let total_runtime_ns: u64 = app
        .task_rows
        .values()
        .filter(|row| row_has_runtime_telemetry(row))
        .map(|row| row.total_runtime_ns)
        .sum();

    if total_runtime_ns == 0 {
        return Vec::new();
    }

    let mut rows: Vec<LongRunOwnerRow> = app
        .task_rows
        .values()
        .filter(|row| row_has_runtime_telemetry(row) && row.total_runtime_ns > 0)
        .map(|row| {
            let placement = placement_summary(row, &app.topology);
            let tgid = if row.tgid > 0 { row.tgid } else { row.pid };
            LongRunOwnerRow {
                pid: row.pid,
                tgid,
                ppid: row.ppid,
                comm: row.comm.clone(),
                role: task_role(row, tgid_roles),
                pelt_util: row.pelt_util,
                total_runtime_ns: row.total_runtime_ns,
                runtime_share_pct: pct(row.total_runtime_ns, total_runtime_ns),
                runtime_ns_per_sec: row.runtime_ns_per_sec,
                runs: row.total_runs,
                runs_per_sec: row.runs_per_sec,
                avg_run_us: avg_task_runtime_us(row),
                max_runtime_us: row.max_runtime_us,
                top_cpu: placement.top_cpu.map(|(cpu, _)| cpu),
                top_cpu_pct: placement
                    .top_cpu
                    .map(|(_, count)| (count * 100) / placement.total_samples.max(1))
                    .unwrap_or(0),
                top_core: placement.top_core.map(|(core, _)| core),
                top_core_pct: placement
                    .top_core
                    .map(|(_, count)| (count * 100) / placement.total_samples.max(1))
                    .unwrap_or(0),
                active_cpu_count: placement.active_cpu_count,
                active_core_count: placement.active_core_count,
                smt_secondary_pct: placement.smt_secondary_pct,
                allowed_cpus: row.allowed_cpus,
                home_cpu: row.home_cpu,
                home_score: row.home_score,
                home_busy_pct: pct(row.home_busy_count as u64, row.home_try_count as u64),
                home_change_count: row.home_change_count,
                blocked_wait_max_us: row.blocked_wait_max_us,
                blocked_count: row.blocked_count,
                smt_contended_pct: task_smt_contended_pct(row),
                smt_overlap_pct: task_smt_overlap_pct(row),
            }
        })
        .collect();

    rows.sort_by(|a, b| {
        b.total_runtime_ns
            .cmp(&a.total_runtime_ns)
            .then_with(|| b.max_runtime_us.cmp(&a.max_runtime_us))
            .then_with(|| a.pid.cmp(&b.pid))
    });
    rows.truncate(limit);
    rows
}

fn cpu_owner_label(row: &LongRunOwnerRow) -> String {
    row.top_cpu
        .map(|cpu| format!("C{:02}/{}%", cpu, row.top_cpu_pct))
        .unwrap_or_else(|| "-".to_string())
}

fn core_owner_label(row: &LongRunOwnerRow) -> String {
    row.top_core
        .map(|core| format!("K{:02}/{}%", core, row.top_core_pct))
        .unwrap_or_else(|| "-".to_string())
}

fn long_run_owner_compact(row: &LongRunOwnerRow) -> String {
    format!(
        "{}[{}] {} {:.1}% avg={}us max={} rt/s={:.1}ms {} {}",
        row.comm,
        row.pid,
        row.role.label(),
        row.runtime_share_pct,
        row.avg_run_us,
        display_runtime_us(row.max_runtime_us),
        row.runtime_ns_per_sec / 1_000_000.0,
        cpu_owner_label(row),
        core_owner_label(row),
    )
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
        let smt_runtime_ns = counter.smt_solo_runtime_ns + counter.smt_contended_runtime_ns;
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
            smt_contended_pct: pct(counter.smt_contended_runtime_ns, smt_runtime_ns),
            smt_overlap_pct: pct(counter.smt_overlap_runtime_ns, smt_runtime_ns),
            smt_contended_avg_run_us: avg_ns(
                counter.smt_contended_runtime_ns,
                counter.smt_contended_run_count,
            ) / 1000,
            smt_wait_solo_us: avg_ns(counter.smt_wake_wait_ns[0], counter.smt_wake_wait_count[0])
                / 1000,
            smt_wait_contended_us: avg_ns(
                counter.smt_wake_wait_ns[1],
                counter.smt_wake_wait_count[1],
            ) / 1000,
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
        let mut smt_solo_runtime_ns = 0u64;
        let mut smt_contended_runtime_ns = 0u64;
        let mut smt_overlap_runtime_ns = 0u64;
        let mut primary_solo_runtime_ns = 0u64;
        let mut primary_contended_runtime_ns = 0u64;
        let mut primary_solo_run_count = 0u64;
        let mut primary_contended_run_count = 0u64;
        let mut secondary_solo_runtime_ns = 0u64;
        let mut secondary_contended_runtime_ns = 0u64;
        let mut smt_wait_ns = [0u64; 2];
        let mut smt_wait_count = [0u64; 2];

        for &cpu in &cpus {
            let counter = counters.get(cpu).copied().unwrap_or_default();
            let is_secondary = is_secondary_smt_cpu(topology, cpu);
            runtime_ns += counter.task_runtime_ns;
            runs += counter.task_run_count;
            quantum_full += counter.quantum_full;
            quantum_yield += counter.quantum_yield;
            quantum_preempt += counter.quantum_preempt;
            system_load += cpu_stats.get(cpu).map(|(load, _)| *load).unwrap_or(0.0);
            top_cpu_runtime = top_cpu_runtime.max(counter.task_runtime_ns);
            smt_solo_runtime_ns += counter.smt_solo_runtime_ns;
            smt_contended_runtime_ns += counter.smt_contended_runtime_ns;
            smt_overlap_runtime_ns += counter.smt_overlap_runtime_ns;
            smt_wait_ns[0] += counter.smt_wake_wait_ns[0];
            smt_wait_ns[1] += counter.smt_wake_wait_ns[1];
            smt_wait_count[0] += counter.smt_wake_wait_count[0];
            smt_wait_count[1] += counter.smt_wake_wait_count[1];
            if is_secondary {
                secondary_runtime += counter.task_runtime_ns;
                secondary_solo_runtime_ns += counter.smt_solo_runtime_ns;
                secondary_contended_runtime_ns += counter.smt_contended_runtime_ns;
            } else {
                primary_solo_runtime_ns += counter.smt_solo_runtime_ns;
                primary_contended_runtime_ns += counter.smt_contended_runtime_ns;
                primary_solo_run_count += counter.smt_solo_run_count;
                primary_contended_run_count += counter.smt_contended_run_count;
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
        let smt_runtime_ns = smt_solo_runtime_ns + smt_contended_runtime_ns;
        let primary_runtime_ns = primary_solo_runtime_ns + primary_contended_runtime_ns;
        let secondary_smt_runtime_ns = secondary_solo_runtime_ns + secondary_contended_runtime_ns;
        let primary_solo_avg_ns = avg_ns(primary_solo_runtime_ns, primary_solo_run_count);
        let primary_contended_avg_ns =
            avg_ns(primary_contended_runtime_ns, primary_contended_run_count);
        let primary_smt_impact = if primary_solo_avg_ns > 0 && primary_contended_avg_ns > 0 {
            primary_contended_avg_ns as f64 / primary_solo_avg_ns as f64
        } else {
            0.0
        };
        rows.push(SchedulerCoreRow {
            core,
            cpu_label: cpu_label_for_core(&cpus),
            share_pct: pct(runtime_ns, total_runtime_ns),
            runs,
            runs_per_sec: per_sec(runs, secs),
            total_runtime_ns: runtime_ns,
            avg_run_us,
            smt_overlap_pct: pct(smt_overlap_runtime_ns, smt_runtime_ns),
            primary_contended_pct: pct(primary_contended_runtime_ns, primary_runtime_ns),
            secondary_contended_pct: pct(secondary_contended_runtime_ns, secondary_smt_runtime_ns),
            primary_smt_impact,
            smt_wait_solo_us: avg_ns(smt_wait_ns[0], smt_wait_count[0]) / 1000,
            smt_wait_contended_us: avg_ns(smt_wait_ns[1], smt_wait_count[1]) / 1000,
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

fn home_seed_balance_ratio(counters: &[CpuWorkCounters]) -> f64 {
    let mut active: Vec<u64> = counters
        .iter()
        .map(|counter| counter.home_seed_total)
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
        10 => "sbp",
        11 => "sbs",
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

fn pressure_anchor_reason_short_label(reason: usize) -> &'static str {
    match reason {
        0 => "inv",
        1 => "sec",
        2 => "nosib",
        3 => "aff",
        _ => "-",
    }
}

fn select_reason_totals(counters: &[CpuWorkCounters], prev_side: bool) -> [u64; SELECT_REASON_MAX] {
    let mut total = [0; SELECT_REASON_MAX];
    for counter in counters {
        for (reason, slot) in total.iter_mut().enumerate().take(SELECT_REASON_MAX) {
            *slot += if prev_side {
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
    for (reason, count) in counts.iter().enumerate().skip(1) {
        if *count == 0 {
            continue;
        }
        parts.push(format!(
            "{}={:.0}%({})",
            select_reason_short_label(reason),
            pct(*count, total),
            count
        ));
    }
    if parts.is_empty() {
        "none".to_string()
    } else {
        parts.join(" ")
    }
}

fn format_select_reason_count_summary(counts: &[u64]) -> String {
    let mut parts = Vec::new();
    for (reason, count) in counts.iter().enumerate().skip(1) {
        if *count == 0 {
            continue;
        }
        parts.push(format!("{}={}", select_reason_short_label(reason), count));
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
    for (outcome, count) in counts.iter().enumerate().skip(1) {
        if *count == 0 {
            continue;
        }
        parts.push(format!(
            "{}={:.0}%({})",
            pressure_probe_outcome_short_label(outcome),
            pct(*count, evaluated),
            count
        ));
    }
    parts.join(" ")
}

fn format_pressure_anchor_summary(counts: &[u64], blocked_anchor: u64) -> String {
    if blocked_anchor == 0 {
        return "-".to_string();
    }

    let mut parts = Vec::new();
    for (reason, count) in counts.iter().enumerate() {
        if *count == 0 {
            continue;
        }
        parts.push(format!(
            "{}={:.0}%({})",
            pressure_anchor_reason_short_label(reason),
            pct(*count, blocked_anchor),
            count
        ));
    }
    if parts.is_empty() {
        "-".to_string()
    } else {
        parts.join(" ")
    }
}

fn format_select_reason_mix(counts: &[u64], total: u64) -> String {
    let mut parts = Vec::new();
    for (reason, count) in counts.iter().enumerate().skip(1) {
        if *count == 0 {
            continue;
        }
        parts.push(format!(
            "{}:{:.0}",
            select_reason_short_label(reason),
            pct(*count, total)
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
    for (outcome, count) in counts.iter().enumerate().skip(1) {
        if *count == 0 {
            continue;
        }
        parts.push(format!(
            "{}:{:.0}",
            pressure_probe_outcome_short_label(outcome),
            pct(*count, evaluated)
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

fn home_seed_rows(counters: &[CpuWorkCounters]) -> Vec<HomeSeedRow> {
    let total: u64 = counters.iter().map(|counter| counter.home_seed_total).sum();
    let mut rows: Vec<HomeSeedRow> = counters
        .iter()
        .enumerate()
        .filter_map(|(cpu, counter)| {
            if counter.home_seed_total == 0 {
                return None;
            }
            Some(HomeSeedRow {
                cpu,
                seeds: counter.home_seed_total,
                seed_pct: pct(counter.home_seed_total, total),
                reason: counter.home_seed_reason,
            })
        })
        .collect();

    rows.sort_by(|a, b| b.seeds.cmp(&a.seeds).then_with(|| a.cpu.cmp(&b.cpu)));
    rows
}

fn home_seed_reason_totals(counters: &[CpuWorkCounters]) -> [u64; SELECT_REASON_MAX] {
    let mut total = [0; SELECT_REASON_MAX];
    for counter in counters {
        for (reason, slot) in total.iter_mut().enumerate().take(SELECT_REASON_MAX) {
            *slot += counter.home_seed_reason[reason];
        }
    }
    total
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
                anchor_block: counter.pressure_anchor_block[site],
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
                || counter.decision_confidence > 0
                || counter.trust.policy > 0
                || counter.trust.blocked > 0
                || counter.trust.demotion_count > 0
                || counter.cpu_pressure > 0;
            if !active {
                return None;
            }
            Some(LocalQueueRow {
                cpu,
                pressure: counter.cpu_pressure,
                decision_confidence: counter.decision_confidence,
                trust: counter.trust,
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

#[cfg(not(cake_bpf_release))]
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

fn display_startup_phase_us(us: u32, phase_mask: u8, phase_bit: u8) -> String {
    if phase_mask & phase_bit == 0 {
        "-".to_string()
    } else {
        format!("{}us", us)
    }
}

fn display_lifecycle_live_ms(ms: u32) -> String {
    if ms == 0 {
        "live".to_string()
    } else {
        format!("live{}ms", ms)
    }
}

fn display_startup_phase_short(us: u32, phase_mask: u8, phase_bit: u8) -> String {
    if phase_mask & phase_bit == 0 {
        "-".to_string()
    } else if us >= 1_000_000 {
        format!("{}s", us / 1_000_000)
    } else if us >= 10_000 {
        format!("{}k", us / 1000)
    } else {
        us.to_string()
    }
}

fn display_lifecycle_live_short(ms: u32) -> String {
    if ms == 0 {
        "live".to_string()
    } else if ms >= 1000 {
        format!("{}s", ms / 1000)
    } else {
        format!("{}ms", ms)
    }
}

fn startup_first_phase_label(phase: u8) -> &'static str {
    match phase {
        STARTUP_PHASE_ENQUEUE => "e",
        STARTUP_PHASE_SELECT => "s",
        STARTUP_PHASE_RUNNING => "r",
        _ => "-",
    }
}

fn startup_phase_mask_label(mask: u8) -> String {
    let mut out = String::new();
    if mask & STARTUP_MASK_ENQUEUE != 0 {
        out.push('e');
    }
    if mask & STARTUP_MASK_SELECT != 0 {
        out.push('s');
    }
    if mask & STARTUP_MASK_RUNNING != 0 {
        out.push('r');
    }
    if out.is_empty() {
        out.push('-');
    }
    out
}

fn format_startup_phase(row: &TaskTelemetryRow) -> String {
    format!(
        "i0/e{}/s{}/r{}/x{}:first={} seen={}",
        display_startup_phase_us(
            row.startup_enqueue_us,
            row.startup_phase_mask,
            STARTUP_MASK_ENQUEUE,
        ),
        display_startup_phase_us(
            row.startup_select_us,
            row.startup_phase_mask,
            STARTUP_MASK_SELECT,
        ),
        display_startup_phase_us(
            row.startup_latency_us,
            row.startup_phase_mask,
            STARTUP_MASK_RUNNING,
        ),
        display_lifecycle_live_ms(row.lifecycle_live_ms),
        startup_first_phase_label(row.startup_first_phase),
        startup_phase_mask_label(row.startup_phase_mask),
    )
}

fn format_lifecycle_compact(row: &TaskTelemetryRow) -> String {
    format!(
        "e{}/s{}/r{}|{}",
        display_startup_phase_short(
            row.startup_enqueue_us,
            row.startup_phase_mask,
            STARTUP_MASK_ENQUEUE,
        ),
        display_startup_phase_short(
            row.startup_select_us,
            row.startup_phase_mask,
            STARTUP_MASK_SELECT,
        ),
        display_startup_phase_short(
            row.startup_latency_us,
            row.startup_phase_mask,
            STARTUP_MASK_RUNNING,
        ),
        display_lifecycle_live_short(row.lifecycle_live_ms),
    )
}

#[cfg(test)]
mod lifecycle_format_tests {
    use super::*;

    #[test]
    fn startup_phase_format_includes_live_exit_state() {
        let row = TaskTelemetryRow {
            startup_enqueue_us: 12,
            startup_select_us: 34,
            startup_latency_us: 56,
            startup_first_phase: STARTUP_PHASE_ENQUEUE,
            startup_phase_mask: STARTUP_MASK_ENQUEUE | STARTUP_MASK_SELECT | STARTUP_MASK_RUNNING,
            ..TaskTelemetryRow::default()
        };

        assert_eq!(
            format_startup_phase(&row),
            "i0/e12us/s34us/r56us/xlive:first=e seen=esr"
        );
    }

    #[test]
    fn avg_jitter_us_tolerates_zero_run_rows() {
        let row = TaskTelemetryRow {
            jitter_accum_ns: 42_000,
            total_runs: 0,
            ..TaskTelemetryRow::default()
        };

        assert_eq!(avg_jitter_us(&row), 0);
    }
}

fn avg_jitter_us(row: &TaskTelemetryRow) -> u64 {
    row.jitter_accum_ns
        .checked_div(row.total_runs as u64)
        .unwrap_or(0)
        / 1000
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
        if !row_has_bpf_matrix_data(row) {
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
        .or(Some(row.core_placement as usize))
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
        if !row_has_runtime_telemetry(row) {
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
        if !row_has_runtime_telemetry(row) {
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
        DBG_EVENT_WAKE_EDGE_ENQUEUE => format!(
            "edge-wake {}/{} -> {}/{} c{} weight={} sampled={} important={}",
            ev.peer_pid,
            ev.peer_tgid,
            ev.pid,
            ev.tgid,
            ev.cpu,
            ev.aux.max(1),
            ev.flags & WAKE_EDGE_EVENT_FLAG_SAMPLED != 0,
            ev.flags & WAKE_EDGE_EVENT_FLAG_IMPORTANT != 0
        ),
        DBG_EVENT_WAKE_EDGE_RUN => format!(
            "edge-run:{} {}/{} -> {}/{} wait={}us tgt={} run={} path={} weight={} important={}",
            wake_reason_label(ev.reason as usize),
            ev.peer_pid,
            ev.peer_tgid,
            ev.pid,
            ev.tgid,
            ev.value_ns / 1000,
            ev.target_cpu,
            ev.cpu,
            select_path_label(ev.path as usize),
            ev.aux.max(1),
            ev.flags & WAKE_EDGE_EVENT_FLAG_IMPORTANT != 0,
        ),
        DBG_EVENT_WAKE_EDGE_FOLLOW => format!(
            "edge-follow:{} {}/{} -> {}/{} gap={}us first={} next={} same={} weight={} important={}",
            wake_reason_label(ev.reason as usize),
            ev.peer_pid,
            ev.peer_tgid,
            ev.pid,
            ev.tgid,
            ev.value_ns / 1000,
            ev.peer_cpu,
            ev.cpu,
            ev.flags & WAKE_EDGE_EVENT_FLAG_HIT_OR_SAME != 0,
            ev.aux.max(1),
            ev.flags & WAKE_EDGE_EVENT_FLAG_IMPORTANT != 0,
        ),
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
    pub fn new(topology: TopologyInfo, latency_matrix: Vec<Vec<f64>>, quantum_us: u64) -> Self {
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
            app_table_state: TableState::default(),
            focused_tgid: None,
            active_tab: TuiTab::Overview,
            sort_column: SortColumn::Pelt,
            sort_descending: true,

            sys,
            components,
            cpu_stats: vec![(0.0, 0.0); nr_cpus],
            task_filter: TaskFilter::BpfTracked,
            arena_active: 0,
            arena_max: 0,
            bpf_task_count: 0,
            #[cfg(debug_assertions)]
            debug_cost: crate::task_anatomy::DebugTelemetryCost::default(),
            prev_deltas: HashMap::new(),
            active_pids_buf: std::collections::HashSet::new(),
            collapsed_tgids: std::collections::HashSet::new(),
            collapsed_ppids: std::collections::HashSet::new(),
            latency_probe_handle: None,
            _prev_stats: None,
            quantum_us,
            system_info,
            debug_events: VecDeque::new(),
            wake_edges: Vec::new(),
            wake_edge_slots_used: 0,
            wake_edge_missed_updates: 0,
            wake_edge_observed_events: 0,
            wake_edge_sample_weight_sum: 0,
            wake_edge_important_events: 0,
            per_cpu_work: vec![CpuWorkCounters::default(); nr_cpus],
            pressure_probe: PressureProbeCounters::default(),
            stats_history: VecDeque::new(),
            cpu_work_history: VecDeque::new(),
            pressure_probe_history: VecDeque::new(),
            timeline_history: VecDeque::new(),
            timeline_last_sample: None,
            timeline_next_sample_at: None,
            diagnostic_recorder: diagnostics::DiagnosticRecorder::default(),
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
                            end_elapsed: now.saturating_duration_since(self.start_time),
                            stats: stats_delta(stats, &prev.stats),
                            system: timeline_system_sample(&self.cpu_stats),
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

    fn record_diagnostic_snapshot(&mut self, stats: &cake_stats) {
        let report = build_telemetry_report(stats, self);
        let evaluation = diagnostics::evaluate_diagnostics(stats, self, &report);
        self.diagnostic_recorder.update(evaluation.current_codes);
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
            .map(|bucket| self.timeline_sample_from_bucket(bucket))
            .collect()
    }

    fn retained_timeline_samples(&self) -> Vec<TimelineSample> {
        self.timeline_history
            .iter()
            .map(|bucket| self.timeline_sample_from_bucket(bucket))
            .collect()
    }

    fn timeline_sample_from_bucket(&self, bucket: &TimelineBucket) -> TimelineSample {
        let now_elapsed = self.start_time.elapsed();
        let start_elapsed = bucket.end_elapsed.saturating_sub(bucket.elapsed);
        TimelineSample {
            start_ago_secs: now_elapsed.saturating_sub(start_elapsed).as_secs(),
            end_ago_secs: now_elapsed.saturating_sub(bucket.end_elapsed).as_secs(),
            start_elapsed,
            end_elapsed: bucket.end_elapsed,
            elapsed: bucket.elapsed,
            stats: bucket.stats,
            system: bucket.system,
        }
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

    pub fn scroll_app_down(&mut self, len: usize) {
        if len == 0 {
            self.app_table_state.select(None);
            return;
        }
        let i = match self.app_table_state.selected() {
            Some(i) if i + 1 < len => i + 1,
            _ => 0,
        };
        self.app_table_state.select(Some(i));
    }

    pub fn scroll_app_up(&mut self, len: usize) {
        if len == 0 {
            self.app_table_state.select(None);
            return;
        }
        let i = match self.app_table_state.selected() {
            Some(0) | None => len.saturating_sub(1),
            Some(i) => i.saturating_sub(1),
        };
        self.app_table_state.select(Some(i));
    }

    pub fn toggle_selected_app_focus(&mut self) {
        let Some(row) = selected_app_health_row(self) else {
            self.set_status("No app row selected");
            return;
        };

        if self.focused_tgid == Some(row.tgid) {
            self.focused_tgid = None;
            self.set_status("Cleared app focus");
        } else {
            self.focused_tgid = Some(row.tgid);
            self.set_status(&format!("Focused app: {} [{}]", row.comm, row.tgid));
        }
    }

    pub fn clear_app_focus(&mut self) {
        self.focused_tgid = None;
        self.set_status("Cleared app focus");
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
    focus_label: Option<&'a str>,
    focus_cpu_mask: Option<&'a [bool]>,
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
        Span::styled(
            focus_label
                .map(|label| format!("  ◆ focus {}", label))
                .unwrap_or_default(),
            Style::default().fg(Color::LightMagenta),
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
                let focus_hit = focus_cpu_mask
                    .and_then(|mask| mask.get(cpu))
                    .copied()
                    .unwrap_or(false);
                let cell_edge_color = if focus_hit {
                    Color::LightMagenta
                } else {
                    Color::DarkGray
                };

                line_spans.push(Span::styled(
                    format!("CPU{:02}{}", cpu, if focus_hit { "◆" } else { " " }),
                    Style::default().fg(core_color),
                ));
                line_spans.push(Span::styled("[", Style::default().fg(cell_edge_color)));
                line_spans.push(Span::styled(
                    format!("Ck{:>2.0}", sched_share),
                    Style::default().fg(sched_color),
                ));
                line_spans.push(Span::styled("|", Style::default().fg(cell_edge_color)));
                line_spans.push(Span::styled(
                    format!("L{:>2.0}", load),
                    Style::default().fg(load_color),
                ));
                line_spans.push(Span::styled("|", Style::default().fg(cell_edge_color)));
                line_spans.push(Span::styled(
                    format!("{:>2.0}°", temp),
                    Style::default().fg(temp_color),
                ));
                line_spans.push(Span::styled("]  ", Style::default().fg(cell_edge_color)));
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
        Cell::from("SMT%"),
        Cell::from("Ov%"),
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
                Cell::from(format!("{:>4.0}", row.smt_contended_pct)).style(low_is_good_style(
                    row.smt_contended_pct as u64,
                    25,
                    60,
                )),
                Cell::from(format!("{:>3.0}", row.smt_overlap_pct)).style(low_is_good_style(
                    row.smt_overlap_pct as u64,
                    15,
                    40,
                )),
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
            Constraint::Length(4),
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
        Cell::from("Ov%"),
        Cell::from("Pcnt%"),
        Cell::from("Sys%"),
    ])
    .style(
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD),
    );

    let table_rows: Vec<Row<'a>> =
        rows.iter()
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
                    Cell::from(format!("{:>3.0}", row.smt_overlap_pct)).style(low_is_good_style(
                        row.smt_overlap_pct as u64,
                        15,
                        40,
                    )),
                    Cell::from(format!("{:>4.0}", row.primary_contended_pct))
                        .style(low_is_good_style(row.primary_contended_pct as u64, 25, 60)),
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
            Constraint::Length(4),
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

fn avg_ns(total_ns: u64, calls: u64) -> u64 {
    if calls > 0 {
        total_ns / calls
    } else {
        0
    }
}

fn avg_us(total_us: u64, calls: u64) -> u64 {
    if calls > 0 {
        total_us / calls
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

fn pelt_util_pct(raw_util: u64) -> f64 {
    pct(raw_util, 1024)
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

fn slice_occupancy_display_pct(raw_score: u16) -> u32 {
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

fn timeline_system_sample(cpu_stats: &[(f32, f32)]) -> TimelineSystemSample {
    let mut load_sum = 0.0f32;
    let mut load_count = 0usize;
    let mut load_max = 0.0f32;
    let mut load_hot_cpu = None;
    let mut temp_sum = 0.0f32;
    let mut temp_count = 0usize;
    let mut temp_max = 0.0f32;
    let mut temp_hot_cpu = None;

    for (cpu, (load, temp)) in cpu_stats.iter().copied().enumerate() {
        if load.is_finite() {
            load_sum += load;
            load_count += 1;
            if load >= load_max {
                load_max = load;
                load_hot_cpu = Some(cpu as u16);
            }
        }
        if temp.is_finite() && temp > 0.0 {
            temp_sum += temp;
            temp_count += 1;
            if temp >= temp_max {
                temp_max = temp;
                temp_hot_cpu = Some(cpu as u16);
            }
        }
    }

    TimelineSystemSample {
        cpu_load_avg_pct: if load_count > 0 {
            load_sum / load_count as f32
        } else {
            0.0
        },
        cpu_load_max_pct: load_max,
        cpu_load_hot_cpu: load_hot_cpu,
        cpu_temp_avg_c: if temp_count > 0 {
            temp_sum / temp_count as f32
        } else {
            0.0
        },
        cpu_temp_max_c: temp_max,
        cpu_temp_hot_cpu: temp_hot_cpu,
    }
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

fn timeline_elapsed_label(elapsed: Duration) -> String {
    let secs = elapsed.as_secs();
    let hours = secs / 3600;
    let minutes = (secs % 3600) / 60;
    let seconds = secs % 60;
    if hours > 0 {
        format!("{hours:02}:{minutes:02}:{seconds:02}")
    } else {
        format!("{minutes:02}:{seconds:02}")
    }
}

fn timeline_cpu_label(cpu: Option<u16>) -> String {
    cpu.map(|cpu| cpu.to_string())
        .unwrap_or_else(|| "-".to_string())
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
        for (path, slot) in total_paths.iter_mut().enumerate().skip(1).take(5) {
            *slot += sample.stats.select_path_count[path];
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
        "  t+{}..{} ago={:>4}..{:>4}s span={:>4.2}s run/s={:>7.1} wake/s={:>7.1} wake%={:>4.0}/{:>4.0}/{:>4.0} path%={:>4.0}/{:>4.0}/{:>4.0}/{:>4.0}/{:>4.0} cbns={}/{}/{}/{} waitus<=5ms={}/{}/{} slice%={:.0}/{:.0}/{:.0} load={:.0}/{:.0}%@{} temp={:.1}/{:.1}C@{}",
        timeline_elapsed_label(sample.start_elapsed),
        timeline_elapsed_label(sample.end_elapsed),
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
        sample.system.cpu_load_avg_pct,
        sample.system.cpu_load_max_pct,
        timeline_cpu_label(sample.system.cpu_load_hot_cpu),
        sample.system.cpu_temp_avg_c,
        sample.system.cpu_temp_max_c,
        timeline_cpu_label(sample.system.cpu_temp_hot_cpu),
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

fn wake_class_label(class: usize) -> &'static str {
    match class {
        1 => "normal",
        2 => "shield",
        3 => "contain",
        _ => "none",
    }
}

fn wake_class_reason_label(reason: usize) -> &'static str {
    match reason {
        0 => "low_util",
        1 => "short_run",
        2 => "wake_dense",
        3 => "latency_prio",
        4 => "runtime_heavy",
        5 => "preempt_heavy",
        6 => "pressure_high",
        7 => "yield_heavy",
        8 => "wait_tail",
        _ => "unknown",
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
    for (reason, row) in buckets.iter().enumerate().skip(1) {
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

fn format_select_decision_wait_summary(
    wait_ns: &[u64; SELECT_REASON_MAX],
    wait_count: &[u64; SELECT_REASON_MAX],
    wait_max_ns: &[u64; SELECT_REASON_MAX],
    buckets: &[[u64; WAKE_BUCKET_MAX]; SELECT_REASON_MAX],
) -> String {
    let mut parts = Vec::new();
    for reason in 1..SELECT_REASON_MAX {
        let samples = wait_count[reason];
        if samples == 0 {
            continue;
        }
        parts.push(format!(
            "{}={}/{}us/{}({})",
            select_reason_short_label(reason),
            wait_ns[reason] / samples / 1000,
            wait_max_ns[reason] / 1000,
            wake_bucket_p99_label(&buckets[reason]),
            samples,
        ));
    }
    if parts.is_empty() {
        "none".to_string()
    } else {
        parts.join(" ")
    }
}

fn format_select_decision_cost_summary(
    select_ns: &[u64; SELECT_REASON_MAX],
    select_count: &[u64; SELECT_REASON_MAX],
    select_max_ns: &[u64; SELECT_REASON_MAX],
) -> String {
    let mut parts = Vec::new();
    for reason in 1..SELECT_REASON_MAX {
        let samples = select_count[reason];
        if samples == 0 {
            continue;
        }
        parts.push(format!(
            "{}={}/{}ns({})",
            select_reason_short_label(reason),
            select_ns[reason] / samples,
            select_max_ns[reason],
            samples,
        ));
    }
    if parts.is_empty() {
        "none".to_string()
    } else {
        parts.join(" ")
    }
}

fn format_select_migration_summary(
    path_count: &[u64; SELECT_PATH_MAX],
    reason_count: &[u64; SELECT_REASON_MAX],
) -> String {
    let total: u64 = path_count[1..].iter().sum();

    format!(
        "path=[{}] reason=[{}] total={}",
        format_path_summary(path_count),
        format_select_reason_count_summary(reason_count),
        total
    )
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
    for (kind, row) in buckets.iter().enumerate().skip(1) {
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

#[cfg(not(cake_bpf_release))]
fn wake_bucket_index(wait_ns: u64) -> usize {
    if wait_ns < 50_000 {
        0
    } else if wait_ns < 200_000 {
        1
    } else if wait_ns < 1_000_000 {
        2
    } else if wait_ns < 5_000_000 {
        3
    } else {
        4
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
    for (path, value) in count.iter().enumerate().skip(1) {
        if *value == 0 {
            continue;
        }
        parts.push(format!("{}={}", select_path_label(path), value));
    }
    if parts.is_empty() {
        "none".to_string()
    } else {
        parts.join(" ")
    }
}

fn wake_edge_task_label(app: &TuiApp, pid: u32, tgid: u32) -> String {
    if let Some(row) = app.task_rows.get(&pid) {
        return format!("{}/{}", row.comm, pid);
    }
    if tgid > 0 {
        if let Some(row) = app.task_rows.get(&tgid) {
            return format!("{}/{}", row.comm, pid);
        }
    }
    if pid > 0 {
        pid.to_string()
    } else {
        "-".to_string()
    }
}

fn format_wake_edge_bucket_summary(edge: &WakeEdgeRow) -> String {
    let labels = ["<50us", "<200us", "<1ms", "<5ms", ">=5ms"];
    let mut parts = Vec::new();
    for (idx, label) in labels.iter().enumerate() {
        let count = edge.wait_bucket_count[idx];
        if count > 0 {
            parts.push(format!("{}={}", label, count));
        }
    }
    if parts.is_empty() {
        "none".to_string()
    } else {
        parts.join(" ")
    }
}

fn format_wake_edge_reason_mix(edge: &WakeEdgeRow) -> String {
    let mut parts = Vec::new();
    for reason in 1..WAKE_REASON_MAX {
        let count = edge.reason_count[reason];
        if count > 0 {
            parts.push(format!("{}={}", wake_reason_short_label(reason), count));
        }
    }
    if parts.is_empty() {
        "none".to_string()
    } else {
        parts.join(" ")
    }
}

fn format_wake_edge_path_mix(edge: &WakeEdgeRow) -> String {
    let mut parts = Vec::new();
    for path in 1..SELECT_PATH_MAX {
        let count = edge.path_count[path];
        if count > 0 {
            parts.push(format!("{}={}", select_path_label(path), count));
        }
    }
    if parts.is_empty() {
        "none".to_string()
    } else {
        parts.join(" ")
    }
}

fn format_wake_edge_place_mix(counts: &[u64; 4]) -> String {
    let mut parts = Vec::new();
    for (cls, count) in counts.iter().enumerate() {
        if *count > 0 {
            parts.push(format!("{}={}", place_class_label(cls), count));
        }
    }
    if parts.is_empty() {
        "none".to_string()
    } else {
        parts.join(" ")
    }
}

fn wake_edge_avg_us(edge: &WakeEdgeRow) -> u64 {
    bucket_avg_us(edge.wait_ns, edge.wait_count)
}

fn wake_edge_line(app: &TuiApp, edge: &WakeEdgeRow) -> String {
    format!(
        "{} -> {} wake_est={} obs={} weight_sum={} important={} wait_est={}/{}us({}) bucket_est=[{}] target_est[h/m]={}/{} follow_est[s/m]={}/{} deps_est[s/c]={}/{} reason_est=[{}] path_est=[{}] waker_place_est=[{}] home_est=[{}] seen_ns={}",
        wake_edge_task_label(app, edge.waker_pid, edge.waker_tgid),
        wake_edge_task_label(app, edge.wakee_pid, edge.wakee_tgid),
        edge.wake_count,
        edge.observed_event_count,
        edge.sample_weight_sum,
        edge.important_event_count,
        wake_edge_avg_us(edge),
        edge.wait_max_ns / 1000,
        edge.wait_count,
        format_wake_edge_bucket_summary(edge),
        edge.target_hit_count,
        edge.target_miss_count,
        edge.follow_same_cpu_count,
        edge.follow_migrate_count,
        edge.same_tgid_count,
        edge.cross_tgid_count,
        format_wake_edge_reason_mix(edge),
        format_wake_edge_path_mix(edge),
        format_wake_edge_place_mix(&edge.waker_place_count),
        format_wake_edge_place_mix(&edge.home_place_count),
        edge.last_seen_ns,
    )
}

fn wake_graph_update_total(app: &TuiApp) -> u64 {
    app.wake_edge_observed_events
        .saturating_add(app.wake_edge_missed_updates)
}

fn wake_graph_miss_pct(app: &TuiApp) -> f64 {
    pct(app.wake_edge_missed_updates, wake_graph_update_total(app))
}

fn wake_graph_capture_label(app: &TuiApp) -> &'static str {
    if app.wake_edge_missed_updates > 0 {
        "sampled_loss"
    } else if app.wake_edge_observed_events > 0 {
        "sampled"
    } else {
        "sampled_empty"
    }
}

fn wake_tgid_label(app: &TuiApp, tgid: u32) -> String {
    if let Some(row) = app.task_rows.get(&tgid) {
        return format!("{}/{}", row.comm, tgid);
    }
    if let Some(row) = app.task_rows.values().find(|row| row.tgid == tgid) {
        return format!("{}/{}", row.comm, tgid);
    }
    if tgid > 0 {
        tgid.to_string()
    } else {
        "-".to_string()
    }
}

fn wake_tgid_summaries_from_edges(edges: &[WakeEdgeRow]) -> Vec<WakeTgidSummary> {
    let mut summaries: HashMap<u32, WakeTgidSummary> = HashMap::new();

    for edge in edges {
        if edge.wakee_tgid > 0 {
            let summary = summaries.entry(edge.wakee_tgid).or_default();
            summary.tgid = edge.wakee_tgid;
            summary.edge_count += 1;
            summary.self_wait_ns = summary.self_wait_ns.saturating_add(edge.wait_ns);
            summary.self_wait_count = summary.self_wait_count.saturating_add(edge.wait_count);
            summary.self_wait_max_ns = summary.self_wait_max_ns.max(edge.wait_max_ns);
            summary.self_target_hit_count = summary
                .self_target_hit_count
                .saturating_add(edge.target_hit_count);
            summary.self_target_miss_count = summary
                .self_target_miss_count
                .saturating_add(edge.target_miss_count);
            summary.self_follow_same_cpu_count = summary
                .self_follow_same_cpu_count
                .saturating_add(edge.follow_same_cpu_count);
            summary.self_follow_migrate_count = summary
                .self_follow_migrate_count
                .saturating_add(edge.follow_migrate_count);

            if edge.waker_tgid == edge.wakee_tgid {
                summary.internal_edges += 1;
                summary.internal_wake_count =
                    summary.internal_wake_count.saturating_add(edge.wake_count);
            } else {
                summary.inbound_edges += 1;
                summary.inbound_wake_count =
                    summary.inbound_wake_count.saturating_add(edge.wake_count);
            }
        }

        if edge.waker_tgid > 0 && edge.waker_tgid != edge.wakee_tgid {
            let summary = summaries.entry(edge.waker_tgid).or_default();
            summary.tgid = edge.waker_tgid;
            summary.edge_count += 1;
            summary.outbound_edges += 1;
            summary.outbound_wake_count =
                summary.outbound_wake_count.saturating_add(edge.wake_count);
            summary.outbound_wait_ns = summary.outbound_wait_ns.saturating_add(edge.wait_ns);
            summary.outbound_wait_count =
                summary.outbound_wait_count.saturating_add(edge.wait_count);
            summary.outbound_wait_max_ns = summary.outbound_wait_max_ns.max(edge.wait_max_ns);
            summary.outbound_target_hit_count = summary
                .outbound_target_hit_count
                .saturating_add(edge.target_hit_count);
            summary.outbound_target_miss_count = summary
                .outbound_target_miss_count
                .saturating_add(edge.target_miss_count);
        }
    }

    let mut summaries: Vec<_> = summaries.into_values().collect();
    summaries.sort_by(|a, b| {
        b.total_wake_count()
            .cmp(&a.total_wake_count())
            .then_with(|| b.self_wake_count().cmp(&a.self_wake_count()))
            .then_with(|| b.self_wait_max_ns.cmp(&a.self_wait_max_ns))
            .then_with(|| a.tgid.cmp(&b.tgid))
    });
    summaries
}

fn wake_tgid_summaries(app: &TuiApp) -> Vec<WakeTgidSummary> {
    wake_tgid_summaries_from_edges(&app.wake_edges)
}

fn wake_tgid_line(app: &TuiApp, summary: &WakeTgidSummary) -> String {
    format!(
        "{} edges={} e[in/int/out]={}/{}/{} wake[in/int/out]={}/{}/{} wait_self={}/{}us({}) wait_out={}/{}us({}) target_self[h/m]={}/{} target_out[h/m]={}/{} follow_self[s/m]={}/{}",
        wake_tgid_label(app, summary.tgid),
        summary.edge_count,
        summary.inbound_edges,
        summary.internal_edges,
        summary.outbound_edges,
        summary.inbound_wake_count,
        summary.internal_wake_count,
        summary.outbound_wake_count,
        bucket_avg_us(summary.self_wait_ns, summary.self_wait_count),
        summary.self_wait_max_ns / 1000,
        summary.self_wait_count,
        bucket_avg_us(summary.outbound_wait_ns, summary.outbound_wait_count),
        summary.outbound_wait_max_ns / 1000,
        summary.outbound_wait_count,
        summary.self_target_hit_count,
        summary.self_target_miss_count,
        summary.outbound_target_hit_count,
        summary.outbound_target_miss_count,
        summary.self_follow_same_cpu_count,
        summary.self_follow_migrate_count,
    )
}

#[cfg(debug_assertions)]
fn derive_wake_graph_from_task_rows(app: &TuiApp) -> WakeGraphCounters {
    let mut edges: HashMap<WakeEdgeKey, WakeEdgeRow> = HashMap::new();

    for row in app
        .task_rows
        .values()
        .filter(|row| row.is_bpf_tracked && row.status != TaskStatus::Dead)
    {
        if row.pid == 0 || row.wakeup_source_pid == 0 {
            continue;
        }

        let wake_reason_count: u64 = row
            .wake_reason_count
            .iter()
            .map(|count| *count as u64)
            .sum();
        let recorded_wakes =
            (row.wake_same_tgid_count as u64).saturating_add(row.wake_cross_tgid_count as u64);
        if wake_reason_count == 0 && recorded_wakes == 0 {
            continue;
        }

        let waker_pid = row.wakeup_source_pid;
        let waker_tgid = app
            .task_rows
            .get(&waker_pid)
            .map(|waker| waker.tgid)
            .filter(|tgid| *tgid > 0)
            .unwrap_or(row.waker_tgid);
        let wakee_tgid = if row.tgid > 0 { row.tgid } else { row.pid };
        let key = WakeEdgeKey {
            waker_pid,
            waker_tgid,
            wakee_pid: row.pid,
            wakee_tgid,
        };
        let edge = edges.entry(key).or_insert_with(|| WakeEdgeRow {
            waker_pid,
            waker_tgid,
            wakee_pid: row.pid,
            wakee_tgid,
            ..WakeEdgeRow::default()
        });

        let edge_wakes = recorded_wakes.max(wake_reason_count);
        edge.wake_count = edge.wake_count.saturating_add(edge_wakes);
        edge.observed_event_count = edge.observed_event_count.saturating_add(edge_wakes);
        edge.sample_weight_sum = edge.sample_weight_sum.saturating_add(edge_wakes);
        edge.same_tgid_count = edge
            .same_tgid_count
            .saturating_add(row.wake_same_tgid_count as u64);
        edge.cross_tgid_count = edge
            .cross_tgid_count
            .saturating_add(row.wake_cross_tgid_count as u64);

        for idx in 0..row.wake_reason_count.len() {
            let reason = idx + 1;
            let count = row.wake_reason_count[idx] as u64;
            if reason >= WAKE_REASON_MAX || count == 0 {
                continue;
            }
            let wait_ns = row.wake_reason_wait_ns[idx];
            let max_ns = row.wake_reason_max_us[idx] as u64 * 1000;
            edge.reason_count[reason] = edge.reason_count[reason].saturating_add(count);
            edge.wait_count = edge.wait_count.saturating_add(count);
            edge.wait_ns = edge.wait_ns.saturating_add(wait_ns);
            edge.wait_max_ns = edge.wait_max_ns.max(max_ns);

            let avg_ns = if count > 0 { wait_ns / count } else { 0 };
            let bucket = wake_bucket_index(avg_ns.max(max_ns));
            edge.wait_bucket_count[bucket] = edge.wait_bucket_count[bucket].saturating_add(count);
        }

        let placement_samples = wake_reason_count.max(1);
        let path = row.last_select_path as usize;
        if path > 0 && path < SELECT_PATH_MAX {
            edge.path_count[path] = edge.path_count[path].saturating_add(placement_samples);
        }
        let home_place = row.last_place_class as usize;
        if home_place < edge.home_place_count.len() {
            edge.home_place_count[home_place] =
                edge.home_place_count[home_place].saturating_add(placement_samples);
        }
        let waker_place = row.last_waker_place_class as usize;
        if waker_place < edge.waker_place_count.len() {
            edge.waker_place_count[waker_place] =
                edge.waker_place_count[waker_place].saturating_add(placement_samples);
        }
    }

    let mut graph = WakeGraphCounters {
        edges: edges.into_values().collect(),
        slots_used: 0,
        missed_updates: 0,
        observed_events: 0,
        sample_weight_sum: 0,
        important_events: 0,
    };
    graph.slots_used = graph.edges.len() as u64;
    for edge in &graph.edges {
        graph.observed_events = graph
            .observed_events
            .saturating_add(edge.observed_event_count);
        graph.sample_weight_sum = graph
            .sample_weight_sum
            .saturating_add(edge.sample_weight_sum);
    }
    graph.edges.sort_by(|a, b| {
        b.wait_count
            .cmp(&a.wait_count)
            .then_with(|| b.wake_count.cmp(&a.wake_count))
            .then_with(|| b.wait_ns.cmp(&a.wait_ns))
    });
    graph
}

fn draw_ui(frame: &mut Frame, app: &mut TuiApp, stats: &cake_stats) {
    let area = frame.area();

    // --- Tab Bar ---
    let tab_titles = vec![
        " Overview ",
        " Live Data ",
        " Monitors ",
        " Codes ",
        " Apps ",
        " Topology ",
        " Trends ",
        " Reference ",
    ];
    let tabs = Tabs::new(tab_titles)
        .select(match app.active_tab {
            TuiTab::Overview => 0,
            TuiTab::LiveData => 1,
            TuiTab::Monitors => 2,
            TuiTab::Codes => 3,
            TuiTab::Apps => 4,
            TuiTab::Topology => 5,
            TuiTab::Trends => 6,
            TuiTab::ReferenceGuide => 7,
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
        TuiTab::Overview => draw_dashboard_tab(frame, app, stats, main_layout[1]),
        TuiTab::LiveData => draw_live_data_tab(frame, app, stats, main_layout[1]),
        TuiTab::Monitors => draw_monitors_tab(frame, app, stats, main_layout[1]),
        TuiTab::Codes => draw_codes_tab(frame, app, stats, main_layout[1]),
        TuiTab::Apps => draw_apps_tab(frame, app, main_layout[1]),
        TuiTab::Topology => draw_topology_tab(frame, app, main_layout[1]),
        TuiTab::Trends => draw_graphs_tab(frame, app, stats, main_layout[1]),
        TuiTab::ReferenceGuide => draw_reference_tab(frame, main_layout[1]),
    }

    // --- Footer (key bindings + status) ---
    let arrow = if app.sort_descending { "▼" } else { "▲" };
    let sort_label = match app.sort_column {
        SortColumn::Pid => format!("PID {}", arrow),
        SortColumn::Pelt => format!("UTIL% {}", arrow),
        SortColumn::MaxRuntime => format!("MAXRµs {}", arrow),
        SortColumn::Jitter => format!("RJITµs {}", arrow),
        SortColumn::Wait => format!("LASTWµs {}", arrow),
        SortColumn::RunsPerSec => format!("RUN/s {}", arrow),
        SortColumn::TargetCpu => format!("CPU {}", arrow),
        SortColumn::Spread => format!("SPRD {}", arrow),
        SortColumn::Residency => format!("RES% {}", arrow),
        SortColumn::SelectCpu => format!("SELns {}", arrow),
        SortColumn::Enqueue => format!("ENQns {}", arrow),
        SortColumn::Gap => format!("LGAPµs {}", arrow),
        SortColumn::Gate1Pct => format!("FAST% {}", arrow),
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
        footer_key("↑↓/j/k"),
        dashboard_note(" rows "),
        footer_key("T"),
        dashboard_note(" top "),
        footer_key("Tab"),
        dashboard_note(" views "),
        dashboard_sep("  |  "),
        dashboard_label("Focus "),
        dashboard_value(
            focused_app_label(app),
            Style::default().fg(Color::LightMagenta),
        ),
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
        footer_key("p"),
        dashboard_note(" pin app "),
        dashboard_sep("  |  "),
        dashboard_label("Data "),
        footer_key("f"),
        dashboard_note(" filter "),
        footer_key("c"),
        dashboard_note(" copy "),
        footer_key("d"),
        dashboard_note(" dump "),
        footer_key("b"),
        dashboard_note(" measure "),
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

fn app_health_row_count(app: &TuiApp) -> usize {
    let tgid_roles = infer_tgid_roles(&app.task_rows);
    build_app_health_rows(app, &tgid_roles).len()
}

fn app_health_state(row: &AppHealthRow) -> (&'static str, Style) {
    let quantum_total = row.quantum_full + row.quantum_yield + row.quantum_preempt;
    let preempt_pct = pct(row.quantum_preempt, quantum_total);
    let max_wait_us = row
        .blocked_wait_max_us
        .max((row.wait_self_max_ns / 1000).min(u32::MAX as u64) as u32);
    if max_wait_us >= 5_000 || preempt_pct >= 10.0 || row.sticky_hogs > 0 {
        ("watch", Style::default().fg(Color::LightRed))
    } else if max_wait_us >= 1_000 || preempt_pct >= 3.0 {
        ("warm", Style::default().fg(Color::Yellow))
    } else {
        ("healthy", Style::default().fg(Color::Green))
    }
}

fn selected_app_health_row(app: &TuiApp) -> Option<AppHealthRow> {
    let tgid_roles = infer_tgid_roles(&app.task_rows);
    let rows = build_app_health_rows(app, &tgid_roles);
    let selected_idx = app
        .app_table_state
        .selected()
        .unwrap_or(0)
        .min(rows.len().saturating_sub(1));
    rows.get(selected_idx).cloned()
}

fn focused_app_with_total(
    app: &TuiApp,
    tgid_roles: &HashMap<u32, WorkloadRole>,
) -> Option<(AppHealthRow, u64)> {
    let focused_tgid = app.focused_tgid?;
    let rows = build_app_health_rows(app, tgid_roles);
    let total_runtime_ns: u64 = rows.iter().map(|row| row.runtime_ns).sum();
    rows.into_iter()
        .find(|row| row.tgid == focused_tgid)
        .map(|row| (row, total_runtime_ns))
}

fn focused_app_label(app: &TuiApp) -> String {
    let tgid_roles = infer_tgid_roles(&app.task_rows);
    if let Some((row, _)) = focused_app_with_total(app, &tgid_roles) {
        let (state, _) = app_health_state(&row);
        format!("{}[{}] {}", row.comm, row.tgid, state)
    } else if let Some(tgid) = app.focused_tgid {
        format!("tgid {} stale", tgid)
    } else {
        "none".to_string()
    }
}

fn app_top_cpu_entries(app: &TuiApp, tgid: u32, limit: usize) -> Vec<(usize, u64)> {
    let mut counts = [0u64; crate::topology::MAX_CPUS];
    let nr_cpus = app.topology.nr_cpus.min(crate::topology::MAX_CPUS);
    let mut total = 0u64;

    for row in app.task_rows.values().filter(|row| {
        row_has_runtime_telemetry(row)
            && if row.tgid > 0 {
                row.tgid == tgid
            } else {
                row.pid == tgid
            }
    }) {
        for (cpu, count) in row.cpu_run_count.iter().enumerate().take(nr_cpus) {
            let count = *count as u64;
            counts[cpu] = counts[cpu].saturating_add(count);
            total = total.saturating_add(count);
        }
    }

    let mut entries: Vec<(usize, u64, u64)> = counts
        .iter()
        .enumerate()
        .take(nr_cpus)
        .filter_map(|(cpu, &count)| {
            if count > 0 {
                Some((cpu, count, (count * 100) / total.max(1)))
            } else {
                None
            }
        })
        .collect();
    entries.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    entries
        .into_iter()
        .take(limit)
        .map(|(cpu, _, pct)| (cpu, pct))
        .collect()
}

fn app_top_core_entries(app: &TuiApp, tgid: u32, limit: usize) -> Vec<(usize, u64)> {
    let mut counts = [0u64; crate::topology::MAX_CORES];
    let nr_cpus = app.topology.nr_cpus.min(crate::topology::MAX_CPUS);
    let mut total = 0u64;

    for row in app.task_rows.values().filter(|row| {
        row_has_runtime_telemetry(row)
            && if row.tgid > 0 {
                row.tgid == tgid
            } else {
                row.pid == tgid
            }
    }) {
        for (cpu, count) in row.cpu_run_count.iter().enumerate().take(nr_cpus) {
            let count = *count as u64;
            if count == 0 {
                continue;
            }
            let core = app.topology.cpu_core_id[cpu] as usize;
            if core < crate::topology::MAX_CORES {
                counts[core] = counts[core].saturating_add(count);
                total = total.saturating_add(count);
            }
        }
    }

    let mut entries: Vec<(usize, u64, u64)> = counts
        .iter()
        .enumerate()
        .filter_map(|(core, &count)| {
            if count > 0 {
                Some((core, count, (count * 100) / total.max(1)))
            } else {
                None
            }
        })
        .collect();
    entries.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    entries
        .into_iter()
        .take(limit)
        .map(|(core, _, pct)| (core, pct))
        .collect()
}

fn app_cpu_distribution_label(app: &TuiApp, tgid: u32, limit: usize) -> String {
    let entries = app_top_cpu_entries(app, tgid, limit);
    if entries.is_empty() {
        "-".to_string()
    } else {
        entries
            .into_iter()
            .map(|(cpu, pct)| format!("C{:02}/{}%", cpu, pct))
            .collect::<Vec<_>>()
            .join(" ")
    }
}

fn app_core_distribution_label(app: &TuiApp, tgid: u32, limit: usize) -> String {
    let entries = app_top_core_entries(app, tgid, limit);
    if entries.is_empty() {
        "-".to_string()
    } else {
        entries
            .into_iter()
            .map(|(core, pct)| format!("K{:02}/{}%", core, pct))
            .collect::<Vec<_>>()
            .join(" ")
    }
}

fn app_focus_cpu_mask(app: &TuiApp, tgid: u32, limit: usize) -> Vec<bool> {
    let mut mask = vec![false; app.topology.nr_cpus.min(crate::topology::MAX_CPUS)];
    for (cpu, _) in app_top_cpu_entries(app, tgid, limit) {
        if let Some(slot) = mask.get_mut(cpu) {
            *slot = true;
        }
    }
    mask
}

fn app_task_rows(app: &TuiApp, tgid: u32) -> Vec<&TaskTelemetryRow> {
    let mut rows: Vec<&TaskTelemetryRow> = app
        .task_rows
        .values()
        .filter(|row| {
            row_has_runtime_telemetry(row)
                && if row.tgid > 0 {
                    row.tgid == tgid
                } else {
                    row.pid == tgid
                }
        })
        .collect();
    rows.sort_by(|a, b| {
        b.total_runtime_ns
            .cmp(&a.total_runtime_ns)
            .then_with(|| b.runtime_ns_per_sec.total_cmp(&a.runtime_ns_per_sec))
            .then_with(|| a.pid.cmp(&b.pid))
    });
    rows
}

fn app_trust_summary(app: &TuiApp) -> (usize, usize, usize, u64) {
    let mut enabled = 0;
    let mut active = 0;
    let mut blocked = 0;
    let mut demotions = 0_u64;

    for row in &app.per_cpu_work {
        if row.trust.prev_direct_enabled() {
            enabled += 1;
        }
        if row.trust.prev_direct_active() {
            active += 1;
        }
        if row.trust.prev_direct_blocked() {
            blocked += 1;
        }
        demotions = demotions.saturating_add(row.trust.demotion_count as u64);
    }

    (enabled, active, blocked, demotions)
}

fn app_data_quality_line(app: &TuiApp) -> Line<'static> {
    let capture_style = if app.wake_edge_missed_updates > 0 {
        Style::default().fg(Color::LightRed)
    } else {
        Style::default().fg(Color::Green)
    };
    let (trust_enabled, trust_active, trust_blocked, trust_demotions) = app_trust_summary(app);
    Line::from(vec![
        dashboard_label("Data "),
        dashboard_value(
            format!(
                "tasks=exact rates=delta/tick wakegraph={} edges={} obs={} weight={} drops={} drop~{:.0}% trust_prev={}/{}/{} demote={}",
                wake_graph_capture_label(app),
                app.wake_edges.len(),
                app.wake_edge_observed_events,
                app.wake_edge_sample_weight_sum,
                app.wake_edge_missed_updates,
                wake_graph_miss_pct(app),
                trust_active,
                trust_enabled,
                trust_blocked,
                trust_demotions
            ),
            capture_style,
        ),
    ])
}

struct TuiKeyContext<'a, 'skel> {
    app: &'a mut TuiApp,
    skel: &'a mut BpfSkel<'skel>,
    stats: &'a cake_stats,
    shutdown: &'a Arc<AtomicBool>,
    wake_graph_state: &'a Arc<Mutex<WakeGraphState>>,
    tick_rate: &'a mut Duration,
    clipboard: &'a mut Option<Clipboard>,
}

fn handle_tui_key(key: crossterm::event::KeyEvent, ctx: TuiKeyContext<'_, '_>) -> Result<bool> {
    let TuiKeyContext {
        app,
        skel,
        stats,
        shutdown,
        wake_graph_state,
        tick_rate,
        clipboard,
    } = ctx;
    #[cfg(cake_bpf_release)]
    {
        let _ = &skel;
        let _ = wake_graph_state;
    }

    if key.kind != KeyEventKind::Press {
        return Ok(false);
    }

    match key.code {
        KeyCode::Char('q') | KeyCode::Char('Q') | KeyCode::Esc => {
            shutdown.store(true, Ordering::Relaxed);
            return Ok(true);
        }
        KeyCode::Enter => match app.active_tab {
            TuiTab::Apps => app.toggle_selected_app_focus(),
            TuiTab::Overview => {
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
            _ => {}
        },
        KeyCode::Tab | KeyCode::Right => {
            app.next_tab();
        }
        KeyCode::BackTab | KeyCode::Left => {
            app.previous_tab();
        }
        KeyCode::Down | KeyCode::PageDown | KeyCode::Char('j') if key.modifiers.is_empty() => {
            match app.active_tab {
                TuiTab::Apps => {
                    let len = app_health_row_count(app);
                    app.scroll_app_down(len);
                }
                _ => app.scroll_table_down(),
            }
        }
        KeyCode::Up | KeyCode::PageUp | KeyCode::Char('k') if key.modifiers.is_empty() => {
            match app.active_tab {
                TuiTab::Apps => {
                    let len = app_health_row_count(app);
                    app.scroll_app_up(len);
                }
                _ => app.scroll_table_up(),
            }
        }
        KeyCode::Char('t') | KeyCode::Char('T')
            if key.modifiers.is_empty()
                || key.modifiers == crossterm::event::KeyModifiers::SHIFT =>
        {
            match app.active_tab {
                TuiTab::Apps => app.app_table_state.select(Some(0)),
                _ => app.table_state.select(Some(0)),
            }
        }
        KeyCode::Char(' ') => {
            if app.active_tab == TuiTab::Overview {
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
        KeyCode::Char('x') => match app.active_tab {
            TuiTab::Apps => app.clear_app_focus(),
            TuiTab::Overview => {
                if app.collapsed_ppids.is_empty() {
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
            _ => {}
        },
        KeyCode::Char('p') if key.modifiers.is_empty() && app.active_tab == TuiTab::Apps => {
            app.toggle_selected_app_focus();
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
            let current_ms = tick_rate.as_millis() as u64;
            if current_ms > 250 {
                *tick_rate = Duration::from_millis(current_ms / 2);
                app.set_status(&format!("Refresh: {}ms", tick_rate.as_millis()));
            }
        }
        KeyCode::Char('-') => {
            let current_ms = tick_rate.as_millis() as u64;
            if current_ms < 5000 {
                *tick_rate = Duration::from_millis(current_ms * 2);
                app.set_status(&format!("Refresh: {}ms", tick_rate.as_millis()));
            }
        }
        KeyCode::Char('c') => {
            let text = format_stats_for_clipboard(stats, app);
            match clipboard {
                Some(cb) => match cb.set_text(text) {
                    Ok(_) => {
                        app.set_status(&format!("✓ Copied {:?} tab to clipboard!", app.active_tab))
                    }
                    Err(_) => app.set_status("✗ Failed to copy"),
                },
                None => app.set_status("✗ Clipboard not available"),
            }
        }
        KeyCode::Char('d') => {
            let text = format_stats_for_clipboard(stats, app);
            let json = format_stats_json(stats, app);
            let secs = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let text_filename = format!("tui_dump_{}.txt", secs);
            let json_filename = format!("tui_dump_{}.json", secs);
            match std::fs::write(&text_filename, &text)
                .and_then(|_| std::fs::write(&json_filename, &json))
            {
                Ok(_) => app.set_status(&format!(
                    "✓ Dump saved: {} + {}",
                    text_filename, json_filename
                )),
                Err(e) => app.set_status(&format!("✗ Dump failed: {}", e)),
            }
        }
        KeyCode::Char('r') => {
            #[cfg(not(cake_bpf_release))]
            {
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
                        bss.home_seed_count = Default::default();
                        for reason in &mut bss.home_seed_reason_count {
                            *reason = Default::default();
                        }
                        for site in &mut bss.pressure_probe_total {
                            *site = Default::default();
                        }
                        for site in &mut bss.pressure_probe_cpu_count {
                            *site = Default::default();
                        }
                        for site in &mut bss.pressure_anchor_block_total {
                            *site = Default::default();
                        }
                        for site in &mut bss.pressure_anchor_block_cpu_count {
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
                        bss.wake_edge_missed_updates = 0;
                        bss.local_pending_est = Default::default();
                        bss.local_pending_max = Default::default();
                        bss.local_pending_insert_count = Default::default();
                        bss.local_pending_run_count = Default::default();
                        bss.blocked_owner_pid = Default::default();
                        bss.blocked_waiter_pid = Default::default();
                        bss.blocked_owner_wait_ns = Default::default();
                        bss.blocked_owner_wait_count = Default::default();
                        bss.blocked_owner_wait_max_ns = Default::default();
                        bss.trust_user = Default::default();
                        bss.trust_bpf = Default::default();
                    }
                    app.stats_history.clear();
                    app.cpu_work_history.clear();
                    app.pressure_probe_history.clear();
                    app.timeline_history.clear();
                    app.timeline_last_sample = None;
                    app.timeline_next_sample_at = None;
                    app.diagnostic_recorder.clear();
                    app.per_cpu_work
                        .iter_mut()
                        .for_each(|counter| *counter = CpuWorkCounters::default());
                    app.pressure_probe = PressureProbeCounters::default();
                    app.wake_edges.clear();
                    app.wake_edge_slots_used = 0;
                    app.wake_edge_missed_updates = 0;
                    app.wake_edge_observed_events = 0;
                    app.wake_edge_sample_weight_sum = 0;
                    app.wake_edge_important_events = 0;
                    if let Ok(mut wake_graph) = wake_graph_state.lock() {
                        wake_graph.clear();
                    }
                    app.set_status("✓ Stats reset");
                }
            }
            #[cfg(cake_bpf_release)]
            {
                app.set_status("Release build has no BPF debug stats to reset");
            }
        }
        KeyCode::Char('b') => {
            if app.active_tab == TuiTab::Topology && app.latency_probe_handle.is_none() {
                let nr_cpus = app.topology.nr_cpus;
                app.latency_probe_handle =
                    Some(thread::spawn(move || run_core_latency_probe(nr_cpus)));
                app.set_status("Running core-to-core latency measurement...");
            } else if app.active_tab != TuiTab::Topology {
                app.set_status("Open Topology and press b to measure core-to-core latency");
            }
        }
        KeyCode::Char('f') => {
            app.toggle_filter();
            app.set_status(&format!("Filter: {}", app.task_filter.label()));
        }
        _ => {}
    }

    Ok(false)
}

fn write_diag_pair(dir: &Path, stem: &str, stats: &cake_stats, app: &TuiApp) -> Result<()> {
    std::fs::create_dir_all(dir)
        .with_context(|| format!("failed to create diagnostic directory {}", dir.display()))?;
    let text_path = dir.join(format!("{stem}.txt"));
    let json_path = dir.join(format!("{stem}.json"));
    std::fs::write(&text_path, format_stats_for_clipboard(stats, app))
        .with_context(|| format!("failed to write {}", text_path.display()))?;
    std::fs::write(&json_path, format_stats_json(stats, app))
        .with_context(|| format!("failed to write {}", json_path.display()))?;
    Ok(())
}

fn epoch_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn refresh_headless_snapshot(
    skel: &BpfSkel,
    app: &mut TuiApp,
    wake_graph_state: &Arc<Mutex<WakeGraphState>>,
) -> cake_stats {
    let stats = aggregate_stats(skel);
    app.per_cpu_work = extract_cpu_work(skel, app.topology.nr_cpus);
    app.pressure_probe = extract_pressure_probe(skel);
    let wake_graph = extract_wake_graph(skel, wake_graph_state);
    app.wake_edges = wake_graph.edges;
    app.wake_edge_slots_used = wake_graph.slots_used;
    app.wake_edge_missed_updates = wake_graph.missed_updates;
    app.wake_edge_observed_events = wake_graph.observed_events;
    app.wake_edge_sample_weight_sum = wake_graph.sample_weight_sum;
    app.wake_edge_important_events = wake_graph.important_events;

    app.sys.refresh_cpu_usage();
    for (i, cpu) in app.sys.cpus().iter().enumerate() {
        if i < app.topology.nr_cpus {
            let temp = app.cpu_stats[i].1;
            app.cpu_stats[i] = (cpu.cpu_usage(), temp);
        }
    }

    app.record_stats_snapshot(&stats);
    app.record_cpu_work_snapshot();
    app.record_pressure_probe_snapshot();
    app.record_diagnostic_snapshot(&stats);
    stats
}

/// Run --verbose without an interactive terminal as a low-rate diagnostic recorder.
pub struct HeadlessRecorderConfig {
    pub shutdown: Arc<AtomicBool>,
    pub interval_secs: u64,
    pub quantum_us: u64,
    pub topology: TopologyInfo,
    pub latency_matrix: Vec<Vec<f64>>,
    pub diag_dir: PathBuf,
    pub diag_period_secs: u64,
}

pub fn run_headless_recorder(
    skel: &mut BpfSkel,
    trust_governor: &mut trust::TrustGovernor,
    config: HeadlessRecorderConfig,
) -> Result<()> {
    let HeadlessRecorderConfig {
        shutdown,
        interval_secs,
        quantum_us,
        topology,
        latency_matrix,
        diag_dir,
        diag_period_secs,
    } = config;
    let tick_rate = Duration::from_secs(interval_secs.max(1));
    let diag_period = (diag_period_secs > 0).then(|| Duration::from_secs(diag_period_secs));
    let mut app = TuiApp::new(topology, latency_matrix, quantum_us);
    app.set_status("headless diagnostic recorder");
    let debug_events = Arc::new(Mutex::new(VecDeque::with_capacity(32)));
    let wake_graph_state = Arc::new(Mutex::new(WakeGraphState::default()));
    #[cfg(not(cake_bpf_release))]
    let mut debug_ringbuf = {
        let queue = debug_events.clone();
        let wake_graph = wake_graph_state.clone();
        let mut builder = libbpf_rs::RingBufferBuilder::new();
        builder
            .add(&skel.maps.debug_ringbuf, move |data: &[u8]| {
                if data.len() < std::mem::size_of::<cake_debug_event>() {
                    return 0;
                }
                let ev = unsafe { *(data.as_ptr() as *const cake_debug_event) };
                if let Ok(mut graph) = wake_graph.lock() {
                    graph.record_event(&ev);
                }
                push_debug_event(
                    &queue,
                    DebugEventRow {
                        ts_ns: ev.ts_ns,
                        value_ns: ev.value_ns,
                        pid: ev.pid,
                        aux: ev.aux,
                        tgid: ev.tgid,
                        peer_pid: ev.peer_pid,
                        peer_tgid: ev.peer_tgid,
                        cpu: ev.cpu,
                        target_cpu: ev.target_cpu,
                        peer_cpu: ev.peer_cpu,
                        kind: ev.kind,
                        slot: ev.slot,
                        reason: ev.reason,
                        path: ev.path,
                        flags: ev.flags,
                        comm: cstr_comm(&ev.comm),
                    },
                );
                0
            })
            .context("failed to add debug ringbuf callback")?;
        Some(builder.build().context("failed to build debug ringbuf")?)
    };
    let mut latest_stats = aggregate_stats(skel);
    let mut last_diag_write = Instant::now()
        .checked_sub(diag_period.unwrap_or(Duration::ZERO))
        .unwrap_or_else(Instant::now);

    std::fs::create_dir_all(&diag_dir).with_context(|| {
        format!(
            "failed to create diagnostic directory {}",
            diag_dir.display()
        )
    })?;
    log::info!(
        "headless --verbose recorder writing diagnostics to {}",
        diag_dir.display()
    );

    loop {
        if shutdown.load(Ordering::Relaxed) {
            break;
        }
        if scx_utils::uei_exited!(skel, uei) {
            break;
        }

        #[cfg(not(cake_bpf_release))]
        {
            if let Some(rb) = debug_ringbuf.as_mut() {
                let _ = rb.consume();
            }
        }
        if let Ok(queue) = debug_events.lock() {
            app.debug_events = queue.clone();
        }

        trust_governor.tick(skel, app.topology.nr_cpus);
        latest_stats = refresh_headless_snapshot(skel, &mut app, &wake_graph_state);

        if diag_period
            .map(|period| last_diag_write.elapsed() >= period)
            .unwrap_or(false)
        {
            write_diag_pair(&diag_dir, "cake_diag_latest", &latest_stats, &app)?;
            last_diag_write = Instant::now();
        }

        std::thread::sleep(tick_rate);
    }

    write_diag_pair(&diag_dir, "cake_diag_latest", &latest_stats, &app)?;
    write_diag_pair(
        &diag_dir,
        &format!("cake_diag_{}", epoch_secs()),
        &latest_stats,
        &app,
    )?;
    Ok(())
}

/// Run the TUI event loop
pub fn run_tui(
    skel: &mut BpfSkel,
    trust_governor: &mut trust::TrustGovernor,
    shutdown: Arc<AtomicBool>,
    interval_secs: u64,
    quantum_us: u64,
    topology: TopologyInfo,
    latency_matrix: Vec<Vec<f64>>,
) -> Result<()> {
    let mut terminal = setup_terminal()?;
    let mut app = TuiApp::new(topology, latency_matrix, quantum_us);
    let mut tick_rate = Duration::from_secs(interval_secs);
    let debug_events = Arc::new(Mutex::new(VecDeque::with_capacity(32)));
    let wake_graph_state = Arc::new(Mutex::new(WakeGraphState::default()));
    #[cfg(not(cake_bpf_release))]
    let mut debug_ringbuf = {
        let queue = debug_events.clone();
        let wake_graph = wake_graph_state.clone();
        let mut builder = libbpf_rs::RingBufferBuilder::new();
        builder
            .add(&skel.maps.debug_ringbuf, move |data: &[u8]| {
                if data.len() < std::mem::size_of::<cake_debug_event>() {
                    return 0;
                }
                let ev = unsafe { *(data.as_ptr() as *const cake_debug_event) };
                if let Ok(mut graph) = wake_graph.lock() {
                    graph.record_event(&ev);
                }
                push_debug_event(
                    &queue,
                    DebugEventRow {
                        ts_ns: ev.ts_ns,
                        value_ns: ev.value_ns,
                        pid: ev.pid,
                        aux: ev.aux,
                        tgid: ev.tgid,
                        peer_pid: ev.peer_pid,
                        peer_tgid: ev.peer_tgid,
                        cpu: ev.cpu,
                        target_cpu: ev.target_cpu,
                        peer_cpu: ev.peer_cpu,
                        kind: ev.kind,
                        slot: ev.slot,
                        reason: ev.reason,
                        path: ev.path,
                        flags: ev.flags,
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
    let mut latest_stats = aggregate_stats(skel);

    'tui_loop: loop {
        // Check for shutdown signal
        if shutdown.load(Ordering::Relaxed) {
            break;
        }

        // Check for UEI exit
        if scx_utils::uei_exited!(skel, uei) {
            break;
        }

        while event::poll(Duration::ZERO)? {
            if let Event::Key(key) = event::read()? {
                if handle_tui_key(
                    key,
                    TuiKeyContext {
                        app: &mut app,
                        skel,
                        stats: &latest_stats,
                        shutdown: &shutdown,
                        wake_graph_state: &wake_graph_state,
                        tick_rate: &mut tick_rate,
                        clipboard: &mut clipboard,
                    },
                )? {
                    break 'tui_loop;
                }
            }
        }

        #[cfg(not(cake_bpf_release))]
        {
            if let Some(rb) = debug_ringbuf.as_mut() {
                let _ = rb.consume();
            }
        }
        if let Ok(queue) = debug_events.lock() {
            app.debug_events = queue.clone();
        }

        trust_governor.tick(skel, app.topology.nr_cpus);

        // Get current stats (aggregate from per-cpu BSS array)
        latest_stats = aggregate_stats(skel);
        let stats = latest_stats;
        app.per_cpu_work = extract_cpu_work(skel, app.topology.nr_cpus);
        app.pressure_probe = extract_pressure_probe(skel);
        let wake_graph = extract_wake_graph(skel, &wake_graph_state);
        app.wake_edges = wake_graph.edges;
        app.wake_edge_slots_used = wake_graph.slots_used;
        app.wake_edge_missed_updates = wake_graph.missed_updates;
        app.wake_edge_observed_events = wake_graph.observed_events;
        app.wake_edge_sample_weight_sum = wake_graph.sample_weight_sum;
        app.wake_edge_important_events = wake_graph.important_events;

        // Poll for core-to-core latency measurement completion
        if let Some(handle) = app.latency_probe_handle.take() {
            if handle.is_finished() {
                match handle.join() {
                    Ok(matrix) => {
                        app.latency_matrix = matrix;
                        app.set_status("Core-to-core latency measurement complete");
                    }
                    Err(_) => {
                        app.set_status("Latency measurement failed");
                    }
                }
            } else {
                // Not done yet, put it back
                app.latency_probe_handle = Some(handle);
            }
        }

        // Draw UI
        #[cfg(debug_assertions)]
        let render_start = Instant::now();
        terminal.draw(|frame| draw_ui(frame, &mut app, &stats))?;
        #[cfg(debug_assertions)]
        {
            app.debug_cost.render_us = render_start.elapsed().as_micros() as u64;
        }

        // Handle events with timeout through the same key path used by drain polling.
        let timeout = tick_rate.saturating_sub(last_tick.elapsed());
        if event::poll(timeout)? {
            if let Event::Key(key) = event::read()? {
                if handle_tui_key(
                    key,
                    TuiKeyContext {
                        app: &mut app,
                        skel,
                        stats: &stats,
                        shutdown: &shutdown,
                        wake_graph_state: &wake_graph_state,
                        tick_rate: &mut tick_rate,
                        clipboard: &mut clipboard,
                    },
                )? {
                    break;
                }
            }
        }

        if last_tick.elapsed() >= tick_rate {
            // Skip dashboard updates while c2c latency measurement is running —
            // avoids BPF map reads and sysinfo polls that could create noise
            if app.latency_probe_handle.is_some() {
                last_tick = std::time::Instant::now();
                let empty_stats = zero_cake_stats();
                #[cfg(debug_assertions)]
                let render_start = Instant::now();
                terminal.draw(|frame| draw_ui(frame, &mut app, &empty_stats))?;
                #[cfg(debug_assertions)]
                {
                    app.debug_cost.render_us = render_start.elapsed().as_micros() as u64;
                }
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

                // --- Arena Telemetry Sweep (via cake_task_iter bpf_iter_task) ---
                // Track currently active PIDs in this sweep to prune dead tasks
                let sweep_seen_at = Instant::now();
                app.active_pids_buf.clear();

                #[cfg(debug_assertions)]
                let iter_read_us;
                #[cfg(debug_assertions)]
                let mut proc_refresh_us = 0u64;
                #[cfg(debug_assertions)]
                let mut proc_refreshes = 0u32;

                #[cfg(not(cake_bpf_release))]
                {
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

                    #[cfg(debug_assertions)]
                    let iter_read_start = Instant::now();
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
                                let home_core = (packed & 0xff) as u8;
                                let home_score = ((packed >> 8) & 0xff) as u8;
                                let wake_chain_policy_score = ((packed >> 16) & 0x0f) as u8;

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
                                #[cfg(debug_assertions)]
                                let proc_snapshot = {
                                    let proc_read_start = Instant::now();
                                    let snapshot =
                                        read_thread_proc_snapshot(rec.telemetry.tgid, pid);
                                    proc_refresh_us = proc_refresh_us.saturating_add(
                                        proc_read_start.elapsed().as_micros() as u64,
                                    );
                                    proc_refreshes = proc_refreshes.saturating_add(1);
                                    snapshot
                                };
                                #[cfg(debug_assertions)]
                                let row_tgid = if rec.telemetry.tgid > 0 {
                                    rec.telemetry.tgid
                                } else {
                                    proc_snapshot.tgid
                                };
                                #[cfg(not(debug_assertions))]
                                let row_tgid = rec.telemetry.tgid;
                                #[cfg(debug_assertions)]
                                let row_ppid = if ppid > 0 { ppid } else { proc_snapshot.ppid };
                                #[cfg(not(debug_assertions))]
                                let row_ppid = ppid;
                                #[cfg(debug_assertions)]
                                let row_comm = if comm.is_empty() {
                                    proc_snapshot
                                        .comm
                                        .clone()
                                        .unwrap_or_else(|| format!("pid{}", pid))
                                } else {
                                    comm.clone()
                                };
                                #[cfg(not(debug_assertions))]
                                let row_comm = comm.clone();
                                #[cfg(debug_assertions)]
                                let row_allowed_cpus = if rec.allowed_cpus > 0 {
                                    rec.allowed_cpus
                                } else {
                                    proc_snapshot.allowed_cpus.unwrap_or(0)
                                };
                                #[cfg(not(debug_assertions))]
                                let row_allowed_cpus = rec.allowed_cpus;
                                #[cfg(debug_assertions)]
                                let row_core_placement = if rec.telemetry.total_runs == 0 {
                                    proc_snapshot
                                        .processor
                                        .unwrap_or(rec.telemetry.core_placement)
                                } else {
                                    rec.telemetry.core_placement
                                };
                                #[cfg(not(debug_assertions))]
                                let row_core_placement = rec.telemetry.core_placement;

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
                                let total_sel =
                                    g1 + g2 + g1w + g3 + g1p + g1c + g1cp + g1d + g1wc + g5;
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
                                let mut total_runs = rec.telemetry.total_runs;
                                let mut total_runtime_ns = rec.telemetry.total_runtime_ns;
                                let jitter_accum_ns = rec.telemetry.jitter_accum_ns;
                                #[cfg(debug_assertions)]
                                let mut proc_schedstat_seen = false;
                                if total_runs == 0 || total_runtime_ns == 0 {
                                    #[cfg(debug_assertions)]
                                    if let Some((runtime_ns, _wait_ns, slices)) = {
                                        let proc_read_start = Instant::now();
                                        let schedstat = read_thread_schedstat(row_tgid, pid);
                                        proc_refresh_us = proc_refresh_us.saturating_add(
                                            proc_read_start.elapsed().as_micros() as u64,
                                        );
                                        schedstat
                                    } {
                                        proc_schedstat_seen = true;
                                        total_runtime_ns = runtime_ns;
                                        total_runs = slices.min(u32::MAX as u64) as u32;
                                    }
                                }

                                let row =
                                    app.task_rows
                                        .entry(pid)
                                        .or_insert_with(|| TaskTelemetryRow {
                                            pid,
                                            comm: row_comm.clone(),
                                            pelt_util,
                                            wait_duration_ns: rec.telemetry.wait_duration_ns,
                                            select_cpu_ns: rec.telemetry.select_cpu_duration_ns,
                                            enqueue_ns: rec.telemetry.enqueue_duration_ns,
                                            gate_hit_pcts,
                                            home_steer_hits: rec.telemetry.gate_1c_hits,
                                            primary_steer_hits: rec.telemetry.gate_1cp_hits,
                                            core_placement: row_core_placement,
                                            dsq_insert_ns: rec.telemetry.dsq_insert_ns,
                                            migration_count: rec.telemetry.migration_count,
                                            preempt_count: rec.telemetry.preempt_count,
                                            yield_count: rec.telemetry.yield_count,
                                            total_runs,
                                            total_runtime_ns,
                                            jitter_accum_ns,
                                            direct_dispatch_count: rec
                                                .telemetry
                                                .direct_dispatch_count,
                                            cpumask_change_count: rec
                                                .telemetry
                                                .cpumask_change_count,
                                            allowed_cpus: row_allowed_cpus,
                                            home_cpu: rec.home_cpu,
                                            home_score,
                                            home_core,
                                            home_try_count: 0,
                                            home_busy_count: 0,
                                            home_change_count: 0,
                                            smt_contended_runs: rec
                                                .telemetry
                                                .smt_contended_run_count,
                                            smt_solo_runs: rec.telemetry.smt_solo_run_count,
                                            smt_contended_runtime_ns: rec
                                                .telemetry
                                                .smt_contended_runtime_ns,
                                            smt_overlap_runtime_ns: rec
                                                .telemetry
                                                .smt_overlap_runtime_ns,
                                            last_blocker_pid: 0,
                                            last_blocker_cpu: 0,
                                            blocked_wait_last_us: 0,
                                            blocked_wait_max_us: 0,
                                            blocked_count: 0,
                                            stopping_duration_ns: rec
                                                .telemetry
                                                .stopping_duration_ns,
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
                                            runtime_ns_per_sec: 0.0,
                                            status: TaskStatus::Alive,
                                            is_bpf_tracked: true,
                                            tgid: row_tgid,
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
                                            ppid: row_ppid,
                                            gate_cascade_ns: rec.telemetry.gate_cascade_ns,
                                            lifecycle_init_ms: rec.telemetry.lifecycle_init_ms,
                                            vtime_compute_ns: rec.telemetry.vtime_compute_ns,
                                            mbox_staging_ns: rec.telemetry.mbox_staging_ns,
                                            startup_latency_us: rec.telemetry.startup_latency_us,
                                            startup_enqueue_us: rec.telemetry.startup_enqueue_us,
                                            lifecycle_live_ms: rec.telemetry.lifecycle_live_ms,
                                            startup_select_us: rec.telemetry.startup_select_us,
                                            startup_first_phase: rec.telemetry.startup_first_phase,
                                            startup_phase_mask: rec.telemetry.startup_phase_mask,
                                            quantum_full_count: rec.telemetry.quantum_full_count,
                                            quantum_yield_count: rec.telemetry.quantum_yield_count,
                                            quantum_preempt_count: rec
                                                .telemetry
                                                .quantum_preempt_count,
                                            waker_cpu: rec.telemetry.waker_cpu,
                                            waker_tgid: rec.telemetry.waker_tgid,
                                            wake_reason_wait_ns: rec.telemetry.wake_reason_wait_ns,
                                            wake_reason_count: rec.telemetry.wake_reason_count,
                                            wake_reason_max_us: rec.telemetry.wake_reason_max_us,
                                            last_select_reason: rec.telemetry.last_select_reason,
                                            last_select_path: rec.telemetry.last_select_path,
                                            last_place_class: rec.telemetry.last_place_class,
                                            last_waker_place_class: rec
                                                .telemetry
                                                .last_waker_place_class,
                                            wake_same_tgid_count: rec
                                                .telemetry
                                                .wake_same_tgid_count,
                                            wake_cross_tgid_count: rec
                                                .telemetry
                                                .wake_cross_tgid_count,
                                            wake_chain_policy_score,
                                            home_place_wait_ns: rec.telemetry.home_place_wait_ns,
                                            home_place_wait_count: rec
                                                .telemetry
                                                .home_place_wait_count,
                                            home_place_wait_max_us: rec
                                                .telemetry
                                                .home_place_wait_max_us,
                                            cpu_run_count: rec.telemetry.cpu_run_count,
                                            task_weight: rec.task_weight,
                                            #[cfg(debug_assertions)]
                                            task_flags: rec.telemetry._pad2,
                                            #[cfg(debug_assertions)]
                                            task_policy: proc_snapshot
                                                .task_policy
                                                .unwrap_or(rec.telemetry._pad3 as u32),
                                            #[cfg(debug_assertions)]
                                            task_prio: proc_snapshot
                                                .task_prio
                                                .unwrap_or(rec.telemetry._pad4 & 0xff),
                                            #[cfg(debug_assertions)]
                                            task_static_prio: proc_snapshot
                                                .task_static_prio
                                                .unwrap_or((rec.telemetry._pad4 >> 8) & 0xff),
                                            #[cfg(debug_assertions)]
                                            task_normal_prio: proc_snapshot
                                                .task_normal_prio
                                                .unwrap_or((rec.telemetry._pad4 >> 16) & 0xff),
                                            #[cfg(debug_assertions)]
                                            task_has_mm: (rec.telemetry._pad_recomp & 1) != 0,
                                            #[cfg(debug_assertions)]
                                            task_is_kthread: (rec.telemetry._pad_recomp & 2) != 0,
                                            #[cfg(debug_assertions)]
                                            proc_snapshot_seen: proc_snapshot.seen(),
                                            #[cfg(debug_assertions)]
                                            proc_schedstat_seen,
                                        });

                                // Update dynamic row elements
                                row.comm = row_comm;
                                row.pelt_util = pelt_util;
                                row.wait_duration_ns = rec.telemetry.wait_duration_ns;
                                row.select_cpu_ns = rec.telemetry.select_cpu_duration_ns;
                                row.enqueue_ns = rec.telemetry.enqueue_duration_ns;
                                row.gate_hit_pcts = gate_hit_pcts;
                                row.home_steer_hits = rec.telemetry.gate_1c_hits;
                                row.primary_steer_hits = rec.telemetry.gate_1cp_hits;
                                row.core_placement = row_core_placement;
                                row.dsq_insert_ns = rec.telemetry.dsq_insert_ns;
                                row.migration_count = rec.telemetry.migration_count;
                                row.preempt_count = rec.telemetry.preempt_count;
                                row.yield_count = rec.telemetry.yield_count;
                                row.total_runs = total_runs;
                                row.total_runtime_ns = total_runtime_ns;
                                row.jitter_accum_ns = jitter_accum_ns;
                                row.direct_dispatch_count = rec.telemetry.direct_dispatch_count;
                                row.cpumask_change_count = rec.telemetry.cpumask_change_count;
                                row.allowed_cpus = row_allowed_cpus;
                                row.home_cpu = rec.home_cpu;
                                row.home_score = home_score;
                                row.home_core = home_core;
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
                                row.tgid = row_tgid;
                                row.last_seen_at = sweep_seen_at;
                                row.slice_util_pct = rec.telemetry.slice_util_pct;
                                row.llc_id = rec.telemetry.llc_id;
                                row.llc_run_mask = rec.telemetry.llc_run_mask;
                                row.same_cpu_streak = rec.telemetry.same_cpu_streak;
                                row.wakeup_source_pid = rec.telemetry.wakeup_source_pid;
                                row._pad_recomp = rec.telemetry._pad_recomp;
                                row.is_kcritical = is_kcritical;
                                row.ppid = row_ppid;
                                row.task_weight = rec.task_weight;
                                row.gate_cascade_ns = rec.telemetry.gate_cascade_ns;
                                row.lifecycle_init_ms = rec.telemetry.lifecycle_init_ms;
                                row.vtime_compute_ns = rec.telemetry.vtime_compute_ns;
                                row.mbox_staging_ns = rec.telemetry.mbox_staging_ns;
                                row.startup_latency_us = rec.telemetry.startup_latency_us;
                                row.startup_enqueue_us = rec.telemetry.startup_enqueue_us;
                                row.lifecycle_live_ms = rec.telemetry.lifecycle_live_ms;
                                row.startup_select_us = rec.telemetry.startup_select_us;
                                row.startup_first_phase = rec.telemetry.startup_first_phase;
                                row.startup_phase_mask = rec.telemetry.startup_phase_mask;
                                row.quantum_full_count = rec.telemetry.quantum_full_count;
                                row.quantum_yield_count = rec.telemetry.quantum_yield_count;
                                row.quantum_preempt_count = rec.telemetry.quantum_preempt_count;
                                row.smt_contended_runs = rec.telemetry.smt_contended_run_count;
                                row.smt_solo_runs = rec.telemetry.smt_solo_run_count;
                                row.smt_contended_runtime_ns =
                                    rec.telemetry.smt_contended_runtime_ns;
                                row.smt_overlap_runtime_ns = rec.telemetry.smt_overlap_runtime_ns;
                                row.waker_cpu = rec.telemetry.waker_cpu;
                                row.waker_tgid = rec.telemetry.waker_tgid;
                                row.wake_reason_wait_ns = rec.telemetry.wake_reason_wait_ns;
                                row.wake_reason_count = rec.telemetry.wake_reason_count;
                                row.wake_reason_max_us = rec.telemetry.wake_reason_max_us;
                                row.last_select_reason = rec.telemetry.last_select_reason;
                                row.last_select_path = rec.telemetry.last_select_path;
                                row.last_place_class = rec.telemetry.last_place_class;
                                row.last_waker_place_class = rec.telemetry.last_waker_place_class;
                                row.wake_same_tgid_count = rec.telemetry.wake_same_tgid_count;
                                row.wake_cross_tgid_count = rec.telemetry.wake_cross_tgid_count;
                                row.wake_chain_policy_score = wake_chain_policy_score;
                                row.home_place_wait_ns = rec.telemetry.home_place_wait_ns;
                                row.home_place_wait_count = rec.telemetry.home_place_wait_count;
                                row.home_place_wait_max_us = rec.telemetry.home_place_wait_max_us;
                                row.cpu_run_count = rec.telemetry.cpu_run_count;
                                #[cfg(debug_assertions)]
                                {
                                    row.task_flags = rec.telemetry._pad2;
                                    row.task_policy = proc_snapshot
                                        .task_policy
                                        .unwrap_or(rec.telemetry._pad3 as u32);
                                    row.task_prio = proc_snapshot
                                        .task_prio
                                        .unwrap_or(rec.telemetry._pad4 & 0xff);
                                    row.task_static_prio = proc_snapshot
                                        .task_static_prio
                                        .unwrap_or((rec.telemetry._pad4 >> 8) & 0xff);
                                    row.task_normal_prio = proc_snapshot
                                        .task_normal_prio
                                        .unwrap_or((rec.telemetry._pad4 >> 16) & 0xff);
                                    row.task_has_mm = (rec.telemetry._pad_recomp & 1) != 0;
                                    row.task_is_kthread = (rec.telemetry._pad_recomp & 2) != 0;
                                    row.proc_snapshot_seen = proc_snapshot.seen();
                                    row.proc_schedstat_seen = proc_schedstat_seen;
                                }
                            } // end read loop
                              // f drops here, closing the iter fd automatically
                        } // end if iter_fd >= 0
                    } // end if link_ptr > 0
                    #[cfg(debug_assertions)]
                    {
                        iter_read_us = iter_read_start.elapsed().as_micros() as u64;
                    }
                }

                // --- Inject ALL System PIDs (Fallback) ---
                // Ensures visibility for PIDs that never triggered cake_init_task
                let sysinfo_pids: std::collections::HashSet<u32> =
                    app.sys.processes().keys().map(|p| p.as_u32()).collect();

                if app.task_filter != TaskFilter::BpfTracked {
                    for (pid, process) in app.sys.processes() {
                        let pid_u32 = pid.as_u32();
                        #[cfg(debug_assertions)]
                        let proc_snapshot = {
                            let proc_read_start = Instant::now();
                            let snapshot = read_thread_proc_snapshot(pid_u32, pid_u32);
                            proc_refresh_us = proc_refresh_us
                                .saturating_add(proc_read_start.elapsed().as_micros() as u64);
                            proc_refreshes = proc_refreshes.saturating_add(1);
                            snapshot
                        };
                        #[cfg(debug_assertions)]
                        let schedstat = {
                            let proc_read_start = Instant::now();
                            let schedstat = read_thread_schedstat(proc_snapshot.tgid, pid_u32);
                            proc_refresh_us = proc_refresh_us
                                .saturating_add(proc_read_start.elapsed().as_micros() as u64);
                            schedstat
                        };
                        #[cfg(debug_assertions)]
                        let proc_schedstat_seen = schedstat.is_some();
                        let row =
                            app.task_rows
                                .entry(pid_u32)
                                .or_insert_with(|| TaskTelemetryRow {
                                    pid: pid_u32,
                                    comm: process.name().to_string_lossy().to_string(),
                                    ..Default::default()
                                });
                        #[cfg(debug_assertions)]
                        {
                            row.tgid = if proc_snapshot.tgid > 0 {
                                proc_snapshot.tgid
                            } else {
                                pid_u32
                            };
                            row.ppid = proc_snapshot.ppid;
                            if let Some(comm) = proc_snapshot.comm.clone() {
                                row.comm = comm;
                            }
                            if let Some(cpu) = proc_snapshot.processor {
                                row.core_placement = cpu;
                            }
                            if let Some(allowed) = proc_snapshot.allowed_cpus {
                                row.allowed_cpus = allowed;
                            }
                            if let Some((runtime_ns, _wait_ns, slices)) = schedstat {
                                row.total_runtime_ns = runtime_ns;
                                row.total_runs = slices.min(u32::MAX as u64) as u32;
                            }
                            if let Some(policy) = proc_snapshot.task_policy {
                                row.task_policy = policy;
                            }
                            if let Some(prio) = proc_snapshot.task_prio {
                                row.task_prio = prio;
                            }
                            if let Some(prio) = proc_snapshot.task_static_prio {
                                row.task_static_prio = prio;
                            }
                            if let Some(prio) = proc_snapshot.task_normal_prio {
                                row.task_normal_prio = prio;
                            }
                            row.proc_snapshot_seen = proc_snapshot.seen();
                            row.proc_schedstat_seen = proc_schedstat_seen;
                        }
                        row.last_seen_at = sweep_seen_at;
                    }
                }

                apply_blocked_wait_attribution(&mut app);

                // --- Liveness Detection: cross-reference arena with sysinfo ---
                let mut bpf_count = 0usize;
                for (pid, row) in app.task_rows.iter_mut() {
                    let in_bpf_iter = app.active_pids_buf.contains(pid);
                    let in_sysinfo = sysinfo_pids.contains(pid);
                    row.status = if row.is_bpf_tracked && in_bpf_iter {
                        TaskStatus::Alive
                    } else if in_sysinfo {
                        TaskStatus::Idle
                    } else {
                        TaskStatus::Dead
                    };
                    if row_has_bpf_matrix_data(row) {
                        bpf_count += 1;
                    }
                }
                app.bpf_task_count = bpf_count;
                #[cfg(debug_assertions)]
                {
                    app.debug_cost.iter_read_us = iter_read_us;
                    app.debug_cost.iter_rows = bpf_count as u32;
                    app.debug_cost.proc_refresh_us = proc_refresh_us;
                    app.debug_cost.proc_refreshes = proc_refreshes;
                    app.debug_cost.proc_cache_hits = 0;
                }

                // --- Delta Mode: compute per-second rates ---
                let actual_elapsed = last_tick.elapsed().as_secs_f64().max(0.1);
                for (pid, row) in app.task_rows.iter_mut() {
                    if let Some(&(prev_runs, prev_migr, prev_runtime_ns)) = app.prev_deltas.get(pid)
                    {
                        let d_runs = row.total_runs.saturating_sub(prev_runs);
                        let d_migr = row.migration_count.saturating_sub(prev_migr);
                        let d_runtime_ns = row.total_runtime_ns.saturating_sub(prev_runtime_ns);
                        row.runs_per_sec = d_runs as f64 / actual_elapsed;
                        row.migrations_per_sec = d_migr as f64 / actual_elapsed;
                        row.runtime_ns_per_sec = d_runtime_ns as f64 / actual_elapsed;
                    }
                }
                // Lightweight delta snapshot: hot task counters only.
                // Eliminates ~500 String allocs/drops per tick from deep-cloning task_rows
                app.prev_deltas.clear();
                for (pid, row) in app.task_rows.iter() {
                    app.prev_deltas.insert(
                        *pid,
                        (row.total_runs, row.migration_count, row.total_runtime_ns),
                    );
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
                        .filter(|(_, row)| row_has_bpf_matrix_data(row))
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
            app.record_diagnostic_snapshot(&stats);

            last_tick = Instant::now();
        }
    }

    restore_terminal()?;
    Ok(())
}
