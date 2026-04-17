// SPDX-License-Identifier: GPL-2.0
// TUI module - ratatui-based terminal UI for real-time scheduler statistics

use std::io::{self, Stdout};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
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
use std::collections::HashMap;
use sysinfo::{Components, System};

use crate::bpf_skel::types::cake_stats;
use crate::bpf_skel::BpfSkel;

use crate::topology::TopologyInfo;

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
    fn label(&self) -> &'static str {
        match self {
            TaskStatus::Alive => "●LIVE",
            TaskStatus::Idle => "○IDLE",
            TaskStatus::Dead => "✗DEAD",
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
    TargetCpu,
    Pid,
    RunDuration,
    SelectCpu,
    Enqueue,
    Gate1Pct,
    Jitter,
    Tier,
    Pelt,
    Vcsw,
    Hog,
    RunsPerSec,
    Gap,
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
    pub cpu_stats: Vec<(f32, f32)>,            // (Load %, Temp C)
    pub show_all_tasks: bool,                  // false = BPF-tracked only, true = all
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
}

#[derive(Clone, Debug)]
pub struct TaskTelemetryRow {
    pub pid: u32,
    pub comm: String,
    pub class_slot: u8,
    pub pelt_util: u32,
    pub legacy_slot_u16: u32,
    pub wait_duration_ns: u64,
    pub gate_hit_pcts: [f64; 10], // G1, G2, G1W, G3, G1P, G1C, G1CP, G1D, G1WC, GTUN
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
    pub enqueue_count: u16,
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
    pub same_cpu_streak: u16,
    pub wakeup_source_pid: u32,
    // Voluntary/involuntary context switch tracking (GPU detection)
    pub nvcsw_delta: u32,
    pub nivcsw_delta: u32,
    pub _pad_recomp: u16,
    pub is_legacy2: bool,
    pub is_legacy3: bool,
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
            class_slot: 0,
            pelt_util: 0,
            legacy_slot_u16: 0,
            wait_duration_ns: 0,
            gate_hit_pcts: [0.0; 10],
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
            enqueue_count: 0,
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
            same_cpu_streak: 0,
            wakeup_source_pid: 0,
            nvcsw_delta: 0,
            nivcsw_delta: 0,
            _pad_recomp: 0,
            is_legacy2: false,
            is_legacy3: false,
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
            total.nr_stop_ramp += s.nr_stop_ramp;
            total.nr_stop_miss += s.nr_stop_miss;

            // Dispatch locality (cake_dispatch stats)
            total.nr_local_dispatches += s.nr_local_dispatches;
            total.nr_stolen_dispatches += s.nr_stolen_dispatches;
            total.nr_dispatch_misses += s.nr_dispatch_misses;
            total.nr_dispatch_hint_skip += s.nr_dispatch_hint_skip;
            total.nr_dsq_queued += s.nr_dsq_queued;
            total.nr_dsq_consumed += s.nr_dsq_consumed;

            // Dispatch callback timing
            total.total_dispatch_ns += s.total_dispatch_ns;
            total.max_dispatch_ns = total.max_dispatch_ns.max(s.max_dispatch_ns);

            // Wakeup enqueue gate telemetry
            total.nr_wakeup_direct_dispatches += s.nr_wakeup_direct_dispatches;
            total.nr_wakeup_dsq_fallback_busy += s.nr_wakeup_dsq_fallback_busy;
            total.nr_wakeup_dsq_fallback_queued += s.nr_wakeup_dsq_fallback_queued;
        }
    }

    total
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
            sort_column: SortColumn::RunDuration,
            sort_descending: true,

            sys,
            components,
            cpu_stats: vec![(0.0, 0.0); nr_cpus],
            show_all_tasks: false,
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

    pub fn next_tab(&mut self) {
        self.active_tab = self.active_tab.next();
    }

    pub fn previous_tab(&mut self) {
        self.active_tab = self.active_tab.previous();
    }

    pub fn cycle_sort(&mut self) {
        self.sort_column = match self.sort_column {
            SortColumn::RunDuration => SortColumn::Jitter,
            SortColumn::Jitter => SortColumn::Gate1Pct,
            SortColumn::Gate1Pct => SortColumn::TargetCpu,
            SortColumn::TargetCpu => SortColumn::Pid,
            SortColumn::Pid => SortColumn::Tier,
            SortColumn::Tier => SortColumn::Pelt,
            SortColumn::Pelt => SortColumn::Vcsw,
            SortColumn::Vcsw => SortColumn::Hog,
            SortColumn::Hog => SortColumn::RunsPerSec,
            SortColumn::RunsPerSec => SortColumn::Gap,
            SortColumn::Gap => SortColumn::SelectCpu,
            SortColumn::SelectCpu => SortColumn::Enqueue,
            SortColumn::Enqueue => SortColumn::RunDuration,
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
        self.show_all_tasks = !self.show_all_tasks;
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

/// Format stats as a copyable text string
fn format_stats_for_clipboard(stats: &cake_stats, app: &TuiApp) -> String {
    let total_dsq_dispatches = stats.nr_local_dispatches + stats.nr_stolen_dispatches;

    let mut output = String::new();
    output.push_str(&app.system_info.format_header());

    output.push_str(&format!(
        "cake: uptime={} state=IDLE detector=disabled\n",
        app.format_uptime(),
    ));

    // Compact dispatch stats
    let dsq_depth = stats.nr_dsq_queued.saturating_sub(stats.nr_dsq_consumed);
    let total_dispatch_calls = stats.nr_dispatch_hint_skip
        + stats.nr_dispatch_misses
        + stats.nr_local_dispatches
        + stats.nr_stolen_dispatches;
    let hint_pct = if total_dispatch_calls > 0 {
        (stats.nr_dispatch_hint_skip as f64 / total_dispatch_calls as f64) * 100.0
    } else {
        0.0
    };
    let wake_total = stats.nr_wakeup_direct_dispatches
        + stats.nr_wakeup_dsq_fallback_busy
        + stats.nr_wakeup_dsq_fallback_queued;
    output.push_str(&format!(
        "disp: dsq_total={} local={} steal={} miss={} hint_skip={} hint%={:.0} queue={} wake:direct={} busy={} queued={} total={} busy_local={} busy_remote={} flow:tunnel_prev={} handoff={} supp={}\n",
        total_dsq_dispatches,
        stats.nr_local_dispatches,
        stats.nr_stolen_dispatches,
        stats.nr_dispatch_misses,
        stats.nr_dispatch_hint_skip,
        hint_pct,
        dsq_depth,
        stats.nr_wakeup_direct_dispatches,
        stats.nr_wakeup_dsq_fallback_busy,
        stats.nr_wakeup_dsq_fallback_queued,
        wake_total,
        stats.nr_wakeup_busy_local_target,
        stats.nr_wakeup_busy_remote_target,
        stats.nr_prev_cpu_tunnels,
        stats.nr_busy_handoff_dispatches,
        stats.nr_busy_keep_suppressed,
    ));

    // Compact callback profile (all on 2 lines)
    let stop_total = stats.nr_stop_deferred_skip
        + stats.nr_stop_deferred
        + stats.nr_stop_ramp
        + stats.nr_stop_miss;
    let stop_total_f = (stop_total as f64).max(1.0);
    output.push_str(&format!(
        "cb.stop: tot_µs={} max_ns={} calls={} skip={:.1}% deferred={:.1}% legacy1={:.1}% legacy2={:.1}%\n",
        stats.total_stopping_ns / 1000,
        stats.max_stopping_ns,
        stop_total,
        stats.nr_stop_deferred_skip as f64 / stop_total_f * 100.0,
        stats.nr_stop_deferred as f64 / stop_total_f * 100.0,
        stats.nr_stop_ramp as f64 / stop_total_f * 100.0,
        stats.nr_stop_miss as f64 / stop_total_f * 100.0,
    ));
    output.push_str(&format!(
        "cb.run: tot_µs={} max_ns={} calls={}  cb.enq: tot_µs={} calls={}  sel: g1_µs={} g2_µs={}  cb.disp: tot_µs={} max_ns={} calls={}\n",
        stats.total_running_ns / 1000, stats.max_running_ns, total_dsq_dispatches,
        stats.total_enqueue_latency_ns / 1000, total_dsq_dispatches,
        stats.total_gate1_latency_ns / 1000, stats.total_gate2_latency_ns / 1000,
        stats.total_dispatch_ns / 1000, stats.max_dispatch_ns, total_dispatch_calls,
    ));

    if app.bench_run_count > 0 {
        output.push_str(&format_bench_for_clipboard(app));
    }

    // Task matrix header — compact column key
    output.push_str("\ntasks: [PPID PID ST COMM CLS PELT AVG MAX GAP JIT WAIT R/s CPU SEL ENQ STOP RUN G1 G3 DSQ MIG/s WHIST]\n");
    output.push_str("       [detail: gates% + DIRECT DEFI YIELD PRMPT ENQ MASK MAX_GAP DSQ_INS RUNS SUTIL LLC STREAK WAKER VCSW ICSW CONF TGID]\n");

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
                if count > 1 || tgid != pid {
                    output.push_str(&format!(
                        "\n▼ {} (PID {} PPID {}) — {} threads\n",
                        proc_name, tgid, row.ppid, count
                    ));
                }
                last_tgid = tgid;
            }

            let j_us = if row.total_runs > 0 {
                row.jitter_accum_ns / row.total_runs as u64 / 1000
            } else {
                0
            };
            let status_str = match row.status {
                TaskStatus::Alive if row.is_legacy2 => "●L2",
                TaskStatus::Alive if row.is_legacy3 => "●L3",
                TaskStatus::Alive => "●",
                TaskStatus::Idle => "○",
                TaskStatus::Dead => "✗",
            };
            let indent = if tgid != pid { "  " } else { "" };
            let cls_str = match row.class_slot {
                1 => "RESV1",
                2 => "LEG2",
                3 => "LEG3",
                _ => "NORM",
            };
            let avg_wait_us = if row.total_runs > 0 {
                row.wait_duration_ns / row.total_runs as u64 / 1000
            } else {
                0
            };
            let wait_str = if row.status == TaskStatus::Dead && avg_wait_us > 10000 {
                format!("{}†", avg_wait_us)
            } else {
                format!("{}", avg_wait_us)
            };
            output.push_str(&format!(
                "{}{:<5} {:<7} {:<3} {:<15} {:<4} {:<4} {:<6} {:<7} {:<7} {:<6} {:<7.1} C{:<3} {:<5} {:<5} {:<5} {:<5} {:<4.0} {:<4.0} {:<4.0} {:<7.1} {}/{}/{}/{}\n",
                indent,
                row.ppid,
                row.pid,
                status_str,
                row.comm,
                cls_str,
                row.pelt_util,  // PELT utilization (0-1024)
                row.max_runtime_us,
                row.dispatch_gap_us,
                j_us,
                wait_str,
                row.runs_per_sec,
                row.core_placement,
                row.select_cpu_ns,
                row.enqueue_ns,
                row.stopping_duration_ns,
                row.running_duration_ns,
                row.gate_hit_pcts[0],  // G1
                row.gate_hit_pcts[3],  // G3
                row.gate_hit_pcts[9],  // DSQ
                row.migrations_per_sec,
                row.wait_hist[0], row.wait_hist[1], row.wait_hist[2], row.wait_hist[3],
            ));
            // detail-A: gate % (G1/G3/DSQ) + all extended fields, compact labels
            output.push_str(&format!(
                "{}  g={:.0}/{:.0}/{:.0} dir={} defi={}µs yld={} prmpt={} enq={} mask={} maxgap={}µs dsqins={}ns runs={} sutil={}% llc=L{:02} streak={} waker={} vcsw={} icsw={} conf={}/{} tgid={}\n",
                indent,
                row.gate_hit_pcts[0], row.gate_hit_pcts[3], row.gate_hit_pcts[9],
                row.direct_dispatch_count, row.legacy_slot_u16, row.yield_count,
                row.preempt_count, row.enqueue_count, row.cpumask_change_count,
                row.max_dispatch_gap_us, row.dsq_insert_ns, row.total_runs,
                row.slice_util_pct, row.llc_id, row.same_cpu_streak,
                row.wakeup_source_pid, row.nvcsw_delta, row.nivcsw_delta,
                row._pad_recomp, row.total_runs, row.tgid,
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
        SortColumn::RunDuration => format!("[RunTM]{}", arrow),
        SortColumn::Gate1Pct => format!("[G1%]{}", arrow),
        SortColumn::TargetCpu => format!("[CPU]{}", arrow),
        SortColumn::Pid => format!("[PID]{}", arrow),
        SortColumn::SelectCpu => format!("[SEL_NS]{}", arrow),
        SortColumn::Enqueue => format!("[ENQ_NS]{}", arrow),
        SortColumn::Jitter => format!("[JITTER]{}", arrow),
        SortColumn::Tier => format!("[TIER]{}", arrow),
        SortColumn::Pelt => format!("[PELT]{}", arrow),
        SortColumn::Vcsw => format!("[VCSW]{}", arrow),
        SortColumn::Hog => format!("[HOG]{}", arrow),
        SortColumn::RunsPerSec => format!("[RUN/s]{}", arrow),
        SortColumn::Gap => format!("[GAP]{}", arrow),
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

    // Legacy class-slot counts for header visibility
    let hog_count = app.task_rows.values().filter(|r| r.is_legacy2).count();
    let bg_count = app.task_rows.values().filter(|r| r.is_legacy3).count();
    let squeeze_str = match (hog_count > 0, bg_count > 0) {
        (true, true) => format!("  LEG2:{}  LEG3:{}", hog_count, bg_count),
        (true, false) => format!("  LEG2:{}", hog_count),
        (false, true) => format!("  LEG3:{}", bg_count),
        (false, false) => String::new(),
    };

    // Line 1: CPU | DSQ dispatches | Tier Distribution
    let line1 =
        format!(
        " CPU: {}{}  │  DSQ Dispatches: {}  │  Tiers: T0:{} T1:{} T2:{} T3:{}  │  {}{}{}",
        topo_flags,
        cpu_freq_str,
        total_dsq_dispatches,
        wc0, wc1, wc2, wc3,
        app.format_uptime(),
        squeeze_str,
        drop_warn,
    );

    // Line 2: Dispatch locality | Queue depth | Tasks | Filter
    let dsq_depth = stats.nr_dsq_queued.saturating_sub(stats.nr_dsq_consumed);
    let _filter_label = if app.show_all_tasks {
        "ALL tasks"
    } else {
        "BPF-tracked only"
    };

    // Hint effectiveness: what % of dispatch calls skipped the kfunc
    let total_dispatch_calls = stats.nr_dispatch_hint_skip
        + stats.nr_dispatch_misses
        + stats.nr_local_dispatches
        + stats.nr_stolen_dispatches;
    let hint_pct = if total_dispatch_calls > 0 {
        (stats.nr_dispatch_hint_skip as f64 / total_dispatch_calls as f64) * 100.0
    } else {
        0.0
    };

    // Queue depth warning: if tasks are piling up, the hint may be causing stalls
    let queue_str = if dsq_depth > 10 {
        format!("⚠ Queue:{}", dsq_depth)
    } else {
        format!("Queue:{}", dsq_depth)
    };

    let line2 = format!(
        " Dispatch: Local:{} Steal:{} Miss:{} HintSkip:{} ({:.0}%)  │  {}  │  Wake: Dir:{} Busy:{} Queued:{}  │  Flow: Tunnel:{} Handoff:{} Supp:{}",
        stats.nr_local_dispatches,
        stats.nr_stolen_dispatches,
        stats.nr_dispatch_misses,
        stats.nr_dispatch_hint_skip,
        hint_pct,
        queue_str,
        stats.nr_wakeup_direct_dispatches,
        stats.nr_wakeup_dsq_fallback_busy,
        stats.nr_wakeup_dsq_fallback_queued,
        stats.nr_prev_cpu_tunnels,
        stats.nr_busy_handoff_dispatches,
        stats.nr_busy_keep_suppressed,
    );

    let header_text = format!("{}\n{}\n State: IDLE | detector disabled", line1, line2);

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

    // --- CLASS Distribution Panel ---
    // Aggregate by current/legacy class slots carried in telemetry.
    let mut cls_pids = [0u32; 4];
    let mut cls_pelt_sum = [0u64; 4];
    let mut cls_wait_sum = [0u64; 4];
    let mut cls_runs_per_sec = [0.0f64; 4];
    let mut cls_active = [0u32; 4];

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
        tier_wait_sum[t] += row.wait_duration_ns / row.total_runs as u64 / 1000;

        // CLASS aggregation (tier field: 0=NORM, 1=reserved, 2=legacy2, 3=legacy3)
        let c = match row.class_slot {
            1 => 0, // reserved legacy slot
            0 => 1, // NORM
            2 => 2, // LEG2
            3 => 3, // LEG3
            _ => 1, // default NORM
        };
        cls_pids[c] += 1;
        cls_pelt_sum[c] += row.pelt_util as u64;
        cls_wait_sum[c] += row.wait_duration_ns / row.total_runs as u64 / 1000;
        cls_runs_per_sec[c] += row.runs_per_sec;
        cls_active[c] += 1;
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
        Cell::from("AVG RT").style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Cell::from("AVG JIT").style(
            Style::default()
                .fg(Color::LightCyan)
                .add_modifier(Modifier::BOLD),
        ),
        Cell::from("WAIT µs").style(
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
                Cell::from(format!("{} µs", avg_rt)),
                Cell::from(format!("{} µs", avg_jit)),
                Cell::from(format!("{}", avg_wait)),
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
            Constraint::Length(10), // AVG RT
            Constraint::Length(10), // AVG JIT
            Constraint::Length(9),  // WAIT µs
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

    // ── Right: CLASS Distribution ──
    let cls_names = ["RESV1", "NORM", "LEG2", "LEG3"];
    let cls_colors = [Color::DarkGray, Color::Blue, Color::Yellow, Color::Red];

    let cls_header = Row::new(vec![
        Cell::from("CLASS").style(
            Style::default()
                .fg(Color::LightMagenta)
                .add_modifier(Modifier::BOLD),
        ),
        Cell::from("PIDs").style(
            Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        ),
        Cell::from("PELT").style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Cell::from("WAIT µs").style(
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

    let cls_rows: Vec<Row> = (0..4)
        .map(|c| {
            let count = cls_active[c].max(1) as u64;
            let avg_pelt = cls_pelt_sum[c] / count;
            let avg_wait = cls_wait_sum[c] / count;
            let work_pct = if total_runs_sec > 0.0 {
                (cls_runs_per_sec[c] / total_runs_sec) * 100.0
            } else {
                0.0
            };

            Row::new(vec![
                Cell::from(cls_names[c]).style(
                    Style::default()
                        .fg(cls_colors[c])
                        .add_modifier(Modifier::BOLD),
                ),
                Cell::from(format!("{}", cls_pids[c])),
                Cell::from(format!("{}", avg_pelt)),
                Cell::from(format!("{}", avg_wait)),
                Cell::from(format!("{:.1}", cls_runs_per_sec[c])),
                Cell::from(format!("{:.1}%", work_pct)),
            ])
        })
        .collect();

    let cls_table = Table::new(
        cls_rows,
        [
            Constraint::Length(7), // CLASS
            Constraint::Length(6), // PIDs
            Constraint::Length(6), // PELT
            Constraint::Length(9), // WAIT µs
            Constraint::Length(9), // RUNS/s
            Constraint::Length(7), // WORK%
        ],
    )
    .header(cls_header)
    .block(
        Block::default()
            .title(" Class Distribution ")
            .title_style(
                Style::default()
                    .fg(Color::LightMagenta)
                    .add_modifier(Modifier::BOLD),
            )
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::DarkGray))
            .border_type(BorderType::Rounded),
    );
    frame.render_widget(cls_table, tier_cols[1]);

    // All timing columns standardized to µs (noted in block title)
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
        // ── Timing (Cyan) ──
        Cell::from("VCSW").style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Cell::from("AVGRT").style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Cell::from("MAXRT").style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Cell::from("GAP").style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Cell::from("JITTER").style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Cell::from("WAIT").style(
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
        // ── Callback Overhead (LightCyan) ──
        Cell::from("SEL").style(
            Style::default()
                .fg(Color::LightCyan)
                .add_modifier(Modifier::BOLD),
        ),
        Cell::from("ENQ").style(
            Style::default()
                .fg(Color::LightCyan)
                .add_modifier(Modifier::BOLD),
        ),
        Cell::from("STOP").style(
            Style::default()
                .fg(Color::LightCyan)
                .add_modifier(Modifier::BOLD),
        ),
        Cell::from("RUN").style(
            Style::default()
                .fg(Color::LightCyan)
                .add_modifier(Modifier::BOLD),
        ),
        // ── Gate Distribution (Green) ──
        Cell::from("G1").style(
            Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD),
        ),
        Cell::from("G3").style(
            Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD),
        ),
        Cell::from("DSQ").style(
            Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD),
        ),
        // ── Placement (Magenta) ──
        Cell::from("MIGR/s").style(
            Style::default()
                .fg(Color::Magenta)
                .add_modifier(Modifier::BOLD),
        ),
        // ── Identity (DarkGray) ──
        Cell::from("TGID").style(
            Style::default()
                .fg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        ),
        // ── Quantum Completion (LightYellow) ──
        Cell::from("Q%F").style(
            Style::default()
                .fg(Color::LightYellow)
                .add_modifier(Modifier::BOLD),
        ),
        Cell::from("Q%Y").style(
            Style::default()
                .fg(Color::LightYellow)
                .add_modifier(Modifier::BOLD),
        ),
        Cell::from("Q%P").style(
            Style::default()
                .fg(Color::LightYellow)
                .add_modifier(Modifier::BOLD),
        ),
        // ── EEVDF (LightGreen) ──
        Cell::from("WAKER").style(
            Style::default()
                .fg(Color::LightGreen)
                .add_modifier(Modifier::BOLD),
        ),
        // ── Classification (LightMagenta) ──
        Cell::from("NICE").style(
            Style::default()
                .fg(Color::LightMagenta)
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

        // Voluntary context switch color: higher = more GPU/IO activity
        let vcsw_style = match row.nvcsw_delta {
            0..=10 => Style::default().fg(Color::DarkGray),
            11..=64 => Style::default().fg(Color::Green),
            65..=200 => Style::default()
                .fg(Color::LightGreen)
                .add_modifier(Modifier::BOLD),
            _ => Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        };
        let jitter_us = if row.total_runs > 0 {
            row.jitter_accum_ns / row.total_runs as u64 / 1000
        } else {
            0
        };
        let indent = if tgid != *pid { "  " } else { "" };
        // Quantum completion percentages
        let q_total = row.quantum_full_count as u32
            + row.quantum_yield_count as u32
            + row.quantum_preempt_count as u32;
        let (q_full_pct, q_yield_pct, q_preempt_pct) = if q_total > 0 {
            (
                row.quantum_full_count as f64 / q_total as f64 * 100.0,
                row.quantum_yield_count as f64 / q_total as f64 * 100.0,
                row.quantum_preempt_count as f64 / q_total as f64 * 100.0,
            )
        } else {
            (0.0, 0.0, 0.0)
        };
        // All ns → µs conversions at render time
        let cells = vec![
            Cell::from(format!("{}{}", indent, row.ppid)),
            Cell::from(format!("{}", row.pid)),
            Cell::from(if row.is_legacy2 {
                "●L2"
            } else if row.is_legacy3 {
                "●L3"
            } else {
                row.status.label()
            })
            .style(Style::default().fg(if row.is_legacy2 {
                Color::LightRed
            } else if row.is_legacy3 {
                Color::Rgb(255, 165, 0) // orange for bg_noise
            } else {
                row.status.color()
            })),
            Cell::from(row.comm.as_str()),
            Cell::from(match row.class_slot {
                1 => "RESV",
                2 => "LEG2",
                3 => "LEG3",
                _ => "NORM",
            })
            .style(Style::default().fg(match row.class_slot {
                1 => Color::DarkGray,
                2 => Color::Yellow,
                3 => Color::Red,
                _ => Color::Blue,
            })),
            Cell::from(format!("{}", row.nvcsw_delta)).style(vcsw_style),
            Cell::from(format!("{}", row.pelt_util)),
            Cell::from(format!("{}", row.max_runtime_us)),
            Cell::from(format!("{}", row.dispatch_gap_us)),
            Cell::from(format!("{}", jitter_us)),
            Cell::from(format!(
                "{}",
                if row.total_runs > 0 {
                    row.wait_duration_ns / row.total_runs as u64 / 1000
                } else {
                    0
                }
            )),
            Cell::from(format!("{:.1}", row.runs_per_sec)),
            Cell::from(format!("C{:02}", row.core_placement)),
            Cell::from(format!("{}", row.select_cpu_ns)),
            Cell::from(format!("{}", row.enqueue_ns)),
            Cell::from(format!("{}", row.stopping_duration_ns)),
            Cell::from(format!("{}", row.running_duration_ns)),
            Cell::from(format!("{:.0}", row.gate_hit_pcts[0])), // G1
            Cell::from(format!("{:.0}", row.gate_hit_pcts[3])), // G3
            Cell::from(format!("{:.0}", row.gate_hit_pcts[9])), // DSQ (tunnel)
            Cell::from(format!("{:.1}", row.migrations_per_sec)),
            Cell::from(format!("{}", row.tgid)),
            Cell::from(format!("{:.0}", q_full_pct)),
            Cell::from(format!("{:.0}", q_yield_pct)),
            Cell::from(format!("{:.0}", q_preempt_pct)),
            Cell::from(format!("{}", row.wakeup_source_pid)),
            Cell::from(if row.task_weight == 100 {
                "N0".to_string()
            } else if row.task_weight > 100 {
                // weight > 100 = negative nice = high priority
                "N-".to_string()
            } else {
                // weight < 100 = positive nice = low priority
                "N+".to_string()
            })
            .style(Style::default().fg(if row.task_weight > 100 {
                Color::LightGreen
            } else if row.task_weight < 100 {
                Color::LightRed
            } else {
                Color::DarkGray
            })),
        ];
        matrix_rows.push(Row::new(cells).height(1));
    }
    let filter_label = if app.show_all_tasks {
        "ALL Tasks"
    } else {
        "BPF-Tracked"
    };

    let matrix_table = Table::new(
        matrix_rows,
        [
            Constraint::Length(6),  // PPID
            Constraint::Length(8),  // PID
            Constraint::Length(3),  // ST
            Constraint::Length(15), // COMM
            Constraint::Length(5),  // CLS
            Constraint::Length(5),  // VCSW
            Constraint::Length(6),  // AVGRT
            Constraint::Length(6),  // MAXRT
            Constraint::Length(7),  // GAP
            Constraint::Length(7),  // JITTER
            Constraint::Length(6),  // WAIT
            Constraint::Length(7),  // RUNS/s
            Constraint::Length(4),  // CPU
            Constraint::Length(5),  // SEL
            Constraint::Length(5),  // ENQ
            Constraint::Length(5),  // STOP
            Constraint::Length(5),  // RUN
            Constraint::Length(3),  // G1
            Constraint::Length(3),  // G3
            Constraint::Length(4),  // DSQ
            Constraint::Length(7),  // MIGR/s
            Constraint::Length(7),  // TGID
            Constraint::Length(4),  // Q%F
            Constraint::Length(4),  // Q%Y
            Constraint::Length(4),  // Q%P
            Constraint::Length(7),  // WAKER
            Constraint::Length(4),  // NICE
            Constraint::Length(6),  // TIER∆
        ],
    )
    .header(matrix_header)
    .block(
        Block::default()
            .title(format!(
                " Live Task Matrix (times: µs │ SEL/ENQ/STOP/RUN: ns) [{}] ",
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
        section("═══ MATRIX COLUMNS (28) ═══"),
        Line::from(""),
        subsection("── Identity & Status ──"),
        col("PPID", "Parent PID — groups threads by launcher"),
        col("PID", "Thread ID (per-thread, not process)"),
        col("ST", "Task status:"),
        sub(
            "●",
            "Alive — actively scheduled, has telemetry",
            Color::Green,
        ),
        sub("●L2", "Legacy class-slot 2 marker", Color::Red),
        sub(
            "●L3",
            "Legacy class-slot 3 marker",
            Color::Rgb(255, 165, 0),
        ),
        sub(
            "○",
            "Idle — in sysinfo but no BPF telemetry",
            Color::DarkGray,
        ),
        sub("✗", "Dead — exited since last refresh", Color::DarkGray),
        col("COMM", "Thread name (first 15 chars, from /proc)"),
        col("CLS", "Current class slot / legacy debug slot:"),
        sub("NORM", "Normal interactive task (default)", Color::Blue),
        sub("RESV1", "Reserved legacy class slot 1", Color::DarkGray),
        sub("LEG2", "Reserved legacy class slot 2", Color::Yellow),
        sub("LEG3", "Reserved legacy class slot 3", Color::Red),
        col("TGID", "Thread Group ID (process that owns thread)"),
        Line::from(""),
        subsection("── Timing ──"),
        col("VCSW", "Voluntary context switches (high = GPU/IO)"),
        col("AVGRT", "PELT util_avg (0-1024) — kernel CPU usage"),
        col("MAXRT", "Max runtime seen this interval (µs)"),
        col("GAP", "Dispatch gap: time between runs (µs)"),
        col("JITTER", "Avg jitter: variance in inter-run gap (µs)"),
        col("WAIT", "Last DSQ wait before scheduling (µs)"),
        col("RUNS/s", "Runs per second — scheduling frequency"),
        Line::from(""),
        subsection("── Placement ──"),
        col("CPU", "Last CPU core this task ran on (Cxx)"),
        col("MIGR/s", "CPU migrations per second"),
        Line::from(""),
        subsection("── Callback Overhead (ns) ──"),
        col("SEL", "select_cpu: gate cascade to find idle CPU"),
        col("ENQ", "enqueue: vtime calc + DSQ insert kfunc"),
        col("STOP", "stopping: runtime accounting + optional debug telemetry"),
        col("RUN", "running: mailbox writes + arena telemetry"),
        Line::from(""),
        subsection("── Gate Distribution (%) ──"),
        col("G1", "Gate 1: prev_cpu idle — direct dispatch"),
        col("G3", "Gate 3: kernel scx_select_cpu_dfl fallback"),
        col("DSQ", "Tunnel: all busy → LLC DSQ vtime ordering"),
        Line::from(""),
        subsection("── Quantum Completion (%) ──"),
        col("Q%F", "Full: slice exhausted (preempted at expiry)"),
        col("Q%Y", "Yield: voluntarily slept before expiry"),
        col("Q%P", "Preempt: forcibly kicked mid-slice"),
        Line::from(""),
        subsection("── EEVDF ──"),
        col("WAKER", "PID of last waker (0 = self/kernel-woken)"),
        col("NICE", "Nice tier: N0=baseline, N-x=high, N+x=low"),
        sub(
            "N-x",
            "Higher priority (lower nice, weight > 100)",
            Color::LightGreen,
        ),
        sub("N0", "Baseline (nice 0, weight = 100)", Color::DarkGray),
        sub(
            "N+x",
            "Lower priority (higher nice, weight < 100)",
            Color::LightRed,
        ),
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

    // ═══ RIGHT PANEL: Dump Fields + Profile + Keys ═══
    let right_text = vec![
        section("═══ DUMP / COPY FIELDS ═══"),
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
        col("DIRECT", "Direct dispatch count (bypassed DSQ)"),
        col("DEFICIT", "Reserved legacy field (retained for layout compatibility)"),
        col("SUTIL", "Slice util % (actual_run / slice)"),
        col("LLC", "Last LLC (L3 cache) node"),
        col("STREAK", "Consecutive same-CPU runs (locality)"),
        col("WHIST", "Wait histogram: <10µ/<100µ/<1m/≥1ms"),
        Line::from(""),
        section("═══ CALLBACK PROFILE ═══"),
        Line::from(""),
        col("stopping", "runtime accounting + deferred telemetry"),
        sub(
            "skip",
            "Most stops skip deferred telemetry work",
            Color::DarkGray,
        ),
        sub(
            "deferred",
            "Every 64th stop runs the heavier deferred telemetry block",
            Color::DarkGray,
        ),
        col("running", "Mailbox stamping + arena telemetry"),
        col("enqueue", "Vtime + scx_bpf_dsq_insert_vtime"),
        col("select", "Gate cascade probing idle CPUs"),
        col("dispatch", "Per-LLC DSQ consume + cross-LLC steal"),
        Line::from(""),
        section("═══ KEY BINDINGS ═══"),
        Line::from(""),
        col("←/→ Tab", "Switch tabs"),
        col("↑/↓ j/k", "Scroll task list / navigate"),
        col("Enter", "Open Task Inspector for selected task"),
        col("r", "Sort by Runtime"),
        col("g", "Sort by Gate 1 %"),
        col("c", "Sort by CPU / Copy to clipboard"),
        col("p", "Sort by PID"),
        col("s", "Sort by runs/Second"),
        col("a", "Toggle all tasks vs BPF-tracked only"),
        col("d", "Dump to file (tui_dump_*.txt)"),
        col("b", "Run BenchLab benchmark iteration"),
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
                            if app.show_all_tasks {
                                app.set_status("Filter: ALL tasks");
                            } else {
                                app.set_status("Filter: BPF-tracked only");
                            }
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
                        let class_slot = (packed >> 28) & 0x03;
                        let is_legacy2 = (packed >> 27) & 1 != 0;
                        let is_legacy3 = (packed >> 22) & 1 != 0;

                        if pid == 0 || class_slot > 3 {
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

                        // pelt_util is in the iter record; legacy_slot_u16 is a reserved slot.
                        let pelt_util = rec.pelt_util as u32;
                        let legacy_slot_u16: u32 = rec.legacy_slot_u16 as u32;

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
                                class_slot: class_slot as u8,
                                pelt_util,
                                legacy_slot_u16,
                                wait_duration_ns: rec.telemetry.wait_duration_ns,
                                select_cpu_ns: rec.telemetry.select_cpu_duration_ns,
                                enqueue_ns: rec.telemetry.enqueue_duration_ns,
                                gate_hit_pcts,
                                core_placement: rec.telemetry.core_placement,
                                dsq_insert_ns: rec.telemetry.dsq_insert_ns,
                                migration_count: rec.telemetry.migration_count,
                                preempt_count: rec.telemetry.preempt_count,
                                yield_count: rec.telemetry.yield_count,
                                total_runs,
                                jitter_accum_ns,
                                direct_dispatch_count: rec.telemetry.direct_dispatch_count,
                                enqueue_count: rec.telemetry.enqueue_count,
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
                                same_cpu_streak: rec.telemetry.same_cpu_streak,
                                wakeup_source_pid: rec.telemetry.wakeup_source_pid,
                                nvcsw_delta: rec.telemetry.nvcsw_delta,
                                nivcsw_delta: rec.telemetry.nivcsw_delta,
                                _pad_recomp: rec.telemetry._pad_recomp,
                                is_legacy2,
                                is_legacy3,
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
                                cpu_run_count: rec.telemetry.cpu_run_count,
                                task_weight: rec.task_weight,
                            });

                        // Update dynamic row elements
                        row.class_slot = class_slot as u8;
                        row.pelt_util = pelt_util;
                        row.legacy_slot_u16 = legacy_slot_u16;
                        row.wait_duration_ns = rec.telemetry.wait_duration_ns;
                        row.select_cpu_ns = rec.telemetry.select_cpu_duration_ns;
                        row.enqueue_ns = rec.telemetry.enqueue_duration_ns;
                        row.gate_hit_pcts = gate_hit_pcts;
                        row.core_placement = rec.telemetry.core_placement;
                        row.dsq_insert_ns = rec.telemetry.dsq_insert_ns;
                        row.migration_count = rec.telemetry.migration_count;
                        row.preempt_count = rec.telemetry.preempt_count;
                        row.yield_count = rec.telemetry.yield_count;
                        row.total_runs = total_runs;
                        row.jitter_accum_ns = jitter_accum_ns;
                        row.direct_dispatch_count = rec.telemetry.direct_dispatch_count;
                        row.enqueue_count = rec.telemetry.enqueue_count;
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
                        row.same_cpu_streak = rec.telemetry.same_cpu_streak;
                        row.wakeup_source_pid = rec.telemetry.wakeup_source_pid;
                        row._pad_recomp = rec.telemetry._pad_recomp;
                        row.is_legacy2 = is_legacy2;
                        row.is_legacy3 = is_legacy3;
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
                        class_slot: 3,
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
            let mut sorted_pids: Vec<u32> = if app.show_all_tasks {
                app.task_rows.keys().copied().collect()
            } else {
                // Filter: only BPF-tracked tasks with total_runs > 0
                app.task_rows
                    .iter()
                    .filter(|(_, row)| row.is_bpf_tracked && row.total_runs > 0)
                    .map(|(pid, _)| *pid)
                    .collect()
            };
            // Apply sort with direction support
            let desc = app.sort_descending;
            match app.sort_column {
                SortColumn::RunDuration => sorted_pids.sort_by(|a, b| {
                    let r_a = app.task_rows.get(a).unwrap();
                    let r_b = app.task_rows.get(b).unwrap();
                    let cmp = r_b.pelt_util.cmp(&r_a.pelt_util);
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
                SortColumn::Pid => sorted_pids.sort_by(|a, b| {
                    let cmp = a.cmp(b);
                    if desc {
                        cmp.reverse()
                    } else {
                        cmp
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
                SortColumn::Jitter => sorted_pids.sort_by(|a, b| {
                    let r_a = app.task_rows.get(a).unwrap();
                    let r_b = app.task_rows.get(b).unwrap();
                    let j_a = if r_a.total_runs > 0 {
                        r_a.jitter_accum_ns / r_a.total_runs as u64
                    } else {
                        0
                    };
                    let j_b = if r_b.total_runs > 0 {
                        r_b.jitter_accum_ns / r_b.total_runs as u64
                    } else {
                        0
                    };
                    let cmp = j_b.cmp(&j_a);
                    if desc {
                        cmp
                    } else {
                        cmp.reverse()
                    }
                }),
                SortColumn::Tier => sorted_pids.sort_by(|a, b| {
                    let r_a = app.task_rows.get(a).unwrap();
                    let r_b = app.task_rows.get(b).unwrap();
                    let cmp = r_a.class_slot.cmp(&r_b.class_slot);
                    if desc {
                        cmp
                    } else {
                        cmp.reverse()
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
                SortColumn::Vcsw => sorted_pids.sort_by(|a, b| {
                    let r_a = app.task_rows.get(a).unwrap();
                    let r_b = app.task_rows.get(b).unwrap();
                    let cmp = r_b.nvcsw_delta.cmp(&r_a.nvcsw_delta);
                    if desc {
                        cmp
                    } else {
                        cmp.reverse()
                    }
                }),
                SortColumn::Hog => sorted_pids.sort_by(|a, b| {
                    let r_a = app.task_rows.get(a).unwrap();
                    let r_b = app.task_rows.get(b).unwrap();
                    // Hogs first when descending
                    let cmp = (r_b.is_legacy2 as u8).cmp(&(r_a.is_legacy2 as u8));
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

            last_tick = Instant::now();
        }
    }

    restore_terminal()?;
    Ok(())
}
