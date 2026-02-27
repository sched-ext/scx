// SPDX-License-Identifier: GPL-2.0
// TUI module - ratatui-based terminal UI for real-time scheduler statistics

use std::io::{self, Stdout};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
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

    /// Format as a multi-line header for dump files and clipboard
    pub fn format_header(&self) -> String {
        let ram_display = if self.total_ram_mb >= 1024 {
            format!("{:.1} GB", self.total_ram_mb as f64 / 1024.0)
        } else {
            format!("{} MB", self.total_ram_mb)
        };
        let smt_label = if self.smt_enabled {
            "SMT ON"
        } else {
            "SMT OFF"
        };

        // Build topology tags
        let mut topo_tags = Vec::new();
        if self.dual_ccd {
            topo_tags.push("Dual-CCD");
        }
        if self.has_vcache {
            topo_tags.push("V-Cache");
        }
        if self.has_hybrid {
            topo_tags.push("Hybrid P+E");
        }
        let topo_str = if topo_tags.is_empty() {
            "Symmetric".to_string()
        } else {
            topo_tags.join(", ")
        };

        format!(
            "=== System Info ===\n\
             CPU:    {} ({})\n\
             Cores:  {}P/{}T ({})  [{}]\n\
             RAM:    {}\n\
             Kernel: {}\n",
            self.cpu_model,
            self.cpu_arch,
            self.phys_cores,
            self.logical_cpus,
            smt_label,
            topo_str,
            ram_display,
            self.kernel_version,
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TuiTab {
    Dashboard = 0,
    Topology = 1,
    TaskInspector = 2,
    BenchLab = 3,
}

impl TuiTab {
    fn next(self) -> Self {
        match self {
            TuiTab::Dashboard => TuiTab::Topology,
            TuiTab::Topology => TuiTab::BenchLab,
            TuiTab::BenchLab => TuiTab::Dashboard,
            TuiTab::TaskInspector => TuiTab::TaskInspector,
        }
    }

    fn previous(self) -> Self {
        match self {
            TuiTab::Dashboard => TuiTab::BenchLab,
            TuiTab::Topology => TuiTab::Dashboard,
            TuiTab::BenchLab => TuiTab::Topology,
            TuiTab::TaskInspector => TuiTab::TaskInspector,
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
    Ewma,
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
    pub selected_pid: Option<u32>,
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
    pub _prev_stats: Option<cake_stats>,       // Previous global stats for rate calc
    // BenchLab cached results
    pub bench_entries: [(u64, u64, u64, u64); 50], // (min_ns, max_ns, total_ns, last_value)
    pub bench_samples: Vec<Vec<u64>>, // Per-entry accumulated raw samples for percentiles
    pub bench_cpu: u32,
    pub bench_iterations: u32,
    pub bench_timestamp: u64,
    pub bench_run_count: u32,
    pub last_bench_timestamp: u64, // to detect new results
    pub system_info: SystemInfo,
    // Game TGID detection: process-level yielder promotion
    pub tracked_game_tgid: u32, // currently detected game tgid (0 = none)
    pub tracked_game_ppid: u32, // PPID of the locked game family (for hysteresis comparison)
    pub game_thread_count: usize, // thread count for detected game
    pub game_name: String,      // process name from /proc/{tgid}/comm
    // Hysteresis: challenger must beat current game for 15s to take over
    pub game_challenger_ppid: u32, // PPID contesting game slot (0 = none)
    pub game_challenger_since: Option<Instant>, // When challenger first appeared
}

#[derive(Clone, Debug)]
pub struct TaskTelemetryRow {
    pub pid: u32,
    pub comm: String,
    pub tier: u8,
    pub avg_runtime_us: u32,
    pub deficit_us: u32,
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
    pub ewma_recomp_count: u16,
    pub is_hog: bool, // Hog squeeze: BULK + non-yielder + deprioritized
    pub is_bg: bool,  // Background noise squeeze: non-game, non-wb, non-kernel
    pub ppid: u32,    // Parent PID for game family detection
}

impl Default for TaskTelemetryRow {
    fn default() -> Self {
        Self {
            pid: 0,
            comm: String::new(),
            tier: 0,
            avg_runtime_us: 0,
            deficit_us: 0,
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
            ewma_recomp_count: 0,
            is_hog: false,
            is_bg: false,
            ppid: 0,
        }
    }
}

fn aggregate_stats(skel: &BpfSkel) -> cake_stats {
    let mut total: cake_stats = Default::default();

    if let Some(bss) = &skel.maps.bss_data {
        for s in &bss.global_stats {
            // Sum all fields
            total.nr_new_flow_dispatches += s.nr_new_flow_dispatches;
            total.nr_old_flow_dispatches += s.nr_old_flow_dispatches;
            total.nr_dropped_allocations += s.nr_dropped_allocations;

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
            total.nr_stop_confidence_skip += s.nr_stop_confidence_skip;
            total.nr_stop_ewma += s.nr_stop_ewma;
            total.nr_stop_ramp += s.nr_stop_ramp;
            total.nr_stop_miss += s.nr_stop_miss;

            // Dispatch locality (cake_dispatch stats)
            total.nr_local_dispatches += s.nr_local_dispatches;
            total.nr_stolen_dispatches += s.nr_stolen_dispatches;
            total.nr_dispatch_misses += s.nr_dispatch_misses;
            total.nr_dispatch_hint_skip += s.nr_dispatch_hint_skip;
            total.nr_dsq_queued += s.nr_dsq_queued;
            total.nr_dsq_consumed += s.nr_dsq_consumed;
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
            selected_pid: None,
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
            _prev_stats: None,
            bench_entries: [(0, 0, 0, 0); 50],
            bench_samples: vec![Vec::new(); 50],
            bench_cpu: 0,
            bench_iterations: 0,
            bench_timestamp: 0,
            bench_run_count: 0,
            last_bench_timestamp: 0,
            system_info,
            tracked_game_tgid: 0,
            tracked_game_ppid: 0,
            game_thread_count: 0,
            game_name: String::new(),
            game_challenger_ppid: 0,
            game_challenger_since: None,
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
        if self.active_tab == TuiTab::TaskInspector {
            self.active_tab = TuiTab::Dashboard;
            self.selected_pid = None;
            return;
        }
        self.active_tab = self.active_tab.next();
    }

    pub fn previous_tab(&mut self) {
        if self.active_tab == TuiTab::TaskInspector {
            self.active_tab = TuiTab::Dashboard;
            self.selected_pid = None;
            return;
        }
        self.active_tab = self.active_tab.previous();
    }

    pub fn cycle_sort(&mut self) {
        self.sort_column = match self.sort_column {
            SortColumn::RunDuration => SortColumn::Jitter,
            SortColumn::Jitter => SortColumn::Gate1Pct,
            SortColumn::Gate1Pct => SortColumn::TargetCpu,
            SortColumn::TargetCpu => SortColumn::Pid,
            SortColumn::Pid => SortColumn::Tier,
            SortColumn::Tier => SortColumn::Ewma,
            SortColumn::Ewma => SortColumn::Vcsw,
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
        let has_vcache = (topo.vcache_llc_mask & (1 << *llc_id)) != 0;
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
                let is_e_core = (topo.little_core_mask & (1 << cpu)) != 0;
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
}

impl<'a> LatencyHeatmap<'a> {
    fn new(matrix: &'a [Vec<f64>], topology: &'a TopologyInfo) -> Self {
        Self { matrix, topology }
    }
}

impl<'a> Widget for LatencyHeatmap<'a> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let nr_cpus = self.matrix.len();

        let block = Block::default()
            .title(" Latency Heatmap ")
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
        (15, "RODATA llc+tier_slice", "Data Read", "C"),
        // Mailbox CL0: cake's Disruptor handoff variants
        (12, "Mbox CL0 tctx+deref", "Mailbox CL0", "C"),
        (18, "CL0 ptr+fused+packed", "Mailbox CL0", "C"),
        (21, "Disruptor CL0 full read", "Mailbox CL0", "C"),
        // Composite: cake-only multi-step operations
        (16, "Bitflag shift+mask+brless", "Composite Ops", "C"),
        (17, "compute_ewma() full", "Composite Ops", "C"),
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
    output.push_str("\n");
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
    let total_dispatches = stats.nr_new_flow_dispatches + stats.nr_old_flow_dispatches;
    let new_pct = if total_dispatches > 0 {
        (stats.nr_new_flow_dispatches as f64 / total_dispatches as f64) * 100.0
    } else {
        0.0
    };

    let mut output = String::new();
    // System hardware context header
    output.push_str(&app.system_info.format_header());
    output.push_str("\n");
    output.push_str(&format!(
        "=== scx_cake Statistics (Uptime: {}) ===\n",
        app.format_uptime()
    ));
    // Game TGID detection status
    if app.tracked_game_tgid > 0 {
        output.push_str(&format!(
            "Game:   {} (PID {}, {} threads boosted)\n\n",
            if app.game_name.is_empty() {
                "unknown"
            } else {
                &app.game_name
            },
            app.tracked_game_tgid,
            app.game_thread_count
        ));
    } else {
        output.push_str("Game:   none detected\n\n");
    }
    output.push_str(&format!(
        "Dispatches: {} total ({:.1}% new-flow)\n",
        total_dispatches, new_pct
    ));

    // Dispatch locality and DSQ hint health
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
    output.push_str(&format!(
        "Dispatch: Local:{} Steal:{} Miss:{} HintSkip:{} ({:.0}%)  Queue:{}\n\n",
        stats.nr_local_dispatches,
        stats.nr_stolen_dispatches,
        stats.nr_dispatch_misses,
        stats.nr_dispatch_hint_skip,
        hint_pct,
        dsq_depth,
    ));

    // Callback Profile section
    output.push_str("\n=== Callback Profile (system-wide) ===\n");
    output.push_str("CALLBACK       TOTAL_µs      MAX_ns    CALLS\n");
    output.push_str("──────────────────────────────────────────────────────\n");

    // Stopping breakdown
    let stop_total = stats.nr_stop_confidence_skip
        + stats.nr_stop_ewma
        + stats.nr_stop_ramp
        + stats.nr_stop_miss;
    let stop_total_f = (stop_total as f64).max(1.0);
    output.push_str(&format!(
        "stopping       {:<13} {:<9} {}\n",
        stats.total_stopping_ns / 1000,
        stats.max_stopping_ns,
        stop_total,
    ));
    output.push_str(&format!(
        "  ├─ conf_skip                         {} ({:.1}%)\n",
        stats.nr_stop_confidence_skip,
        stats.nr_stop_confidence_skip as f64 / stop_total_f * 100.0,
    ));
    output.push_str(&format!(
        "  ├─ ewma                              {} ({:.1}%)\n",
        stats.nr_stop_ewma,
        stats.nr_stop_ewma as f64 / stop_total_f * 100.0,
    ));
    output.push_str(&format!(
        "  ├─ ramp                              {} ({:.1}%)\n",
        stats.nr_stop_ramp,
        stats.nr_stop_ramp as f64 / stop_total_f * 100.0,
    ));
    output.push_str(&format!(
        "  └─ miss                              {} ({:.1}%)\n",
        stats.nr_stop_miss,
        stats.nr_stop_miss as f64 / stop_total_f * 100.0,
    ));

    // Running
    let total_dispatches: u64 = stats.nr_new_flow_dispatches + stats.nr_old_flow_dispatches;
    output.push_str(&format!(
        "running        {:<13} {:<9} {}\n",
        stats.total_running_ns / 1000,
        stats.max_running_ns,
        total_dispatches,
    ));

    // Enqueue (already tracked)
    output.push_str(&format!(
        "enqueue        {:<13}           {}\n",
        stats.total_enqueue_latency_ns / 1000,
        total_dispatches,
    ));

    // Select CPU (gate latencies as proxy)
    output.push_str(&format!(
        "select_cpu     gate1:{:<8}µs  gate2:{}µs\n",
        stats.total_gate1_latency_ns / 1000,
        stats.total_gate2_latency_ns / 1000,
    ));

    // BenchLab section — reuse the grouped clipboard format
    if app.bench_run_count > 0 {
        output.push_str(&format_bench_for_clipboard(app));
    }

    output.push_str(
        "\n=== Live Task Matrix (times: µs │ SEL/ENQ/STOP/RUN: ns) — ALL BPF-tracked tasks ===\n",
    );
    output.push_str("PID     ST  COMM            EWMA  AVGRT  MAXRT  GAP     JITTER  WAIT   RUNS/s  CPU  SEL   ENQ   STOP  RUN   G1   G2   G1W  G3   G1P  G1C  G1CP G1D  G1WC G5   MIGR/s  PREEMPT  WHIST\n");
    output.push_str("──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────\n");

    // Dump always captures ALL BPF-tracked tasks (not filtered by TUI view)
    let mut dump_pids: Vec<u32> = app
        .task_rows
        .iter()
        .filter(|(_, row)| row.is_bpf_tracked && row.total_runs > 0)
        .map(|(pid, _)| *pid)
        .collect();
    dump_pids.sort_by(|a, b| {
        let r_a = app.task_rows.get(a).unwrap();
        let r_b = app.task_rows.get(b).unwrap();
        r_b.avg_runtime_us.cmp(&r_a.avg_runtime_us)
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
            .then_with(|| r_b.avg_runtime_us.cmp(&r_a.avg_runtime_us))
    });

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
                        "\n▼ {} (PID {}) — {} threads\n",
                        proc_name, tgid, count
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
                TaskStatus::Alive if row.is_hog => "●HOG",
                TaskStatus::Alive if row.is_bg => "●BG",
                TaskStatus::Alive => "●",
                TaskStatus::Idle => "○",
                TaskStatus::Dead => "✗",
            };
            let indent = if tgid != pid { "  " } else { "" };
            let wait_us = row.wait_duration_ns / 1000;
            let wait_str = if row.status == TaskStatus::Dead && wait_us > 10000 {
                format!("{}†", wait_us)
            } else {
                format!("{}", wait_us)
            };
            output.push_str(&format!(
                "{}{:<7} {:<3} {:<15} {:<4} {:<6} {:<6} {:<7} {:<7} {:<6} {:<7.1} C{:<3} {:<5} {:<5} {:<5} {:<5} {:<4.0} {:<4.0} {:<4.0} {:<4.0} {:<4.0} {:<4.0} {:<4.0} {:<4.0} {:<4.0} {:<4.0} {:<7.1} {}/{}/{}/{}\n",
                indent,
                row.pid,
                status_str,
                row.comm,
                row.avg_runtime_us,  // EWMA runtime µs
                row.avg_runtime_us,
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
                row.gate_hit_pcts[1],  // G2
                row.gate_hit_pcts[2],  // G1W
                row.gate_hit_pcts[3],  // G3
                row.gate_hit_pcts[4],  // G1P
                row.gate_hit_pcts[5],  // G1C
                row.gate_hit_pcts[6],  // G1CP
                row.gate_hit_pcts[7],  // G1D
                row.gate_hit_pcts[8],  // G1WC
                row.gate_hit_pcts[9],  // G5
                row.migrations_per_sec,
                row.wait_hist[0], row.wait_hist[1], row.wait_hist[2], row.wait_hist[3],
            ));
            output.push_str(&format!(
                "{}         G1:{:.0}% G2:{:.0}% G1W:{:.0}% G3:{:.0}% G1P:{:.0}% G1C:{:.0}% G1CP:{:.0}% G1D:{:.0}% G1WC:{:.0}% G5:{:.0}%  DIRECT:{}  DEFICIT:{}µs  YIELD:{}  PRMPT_CNT:{}  ENQ_CNT:{}  MASK∆:{}  MAX_GAP:{}µs  DSQ_INS:{}ns  TOTAL_RUNS:{}  SUTIL:{}%  LLC:L{:02}  STREAK:{}  WAKER:{}  VCSW:{}  ICSW:{}  CONF:{}/{}  TGID:{}\n",
                indent,
                row.gate_hit_pcts[0],
                row.gate_hit_pcts[1],
                row.gate_hit_pcts[2],
                row.gate_hit_pcts[3],
                row.gate_hit_pcts[4],
                row.gate_hit_pcts[5],
                row.gate_hit_pcts[6],
                row.gate_hit_pcts[7],
                row.gate_hit_pcts[8],
                row.gate_hit_pcts[9],
                row.direct_dispatch_count,
                row.deficit_us,
                row.yield_count,
                row.preempt_count,
                row.enqueue_count,
                row.cpumask_change_count,
                row.max_dispatch_gap_us,
                row.dsq_insert_ns,
                row.total_runs,
                row.slice_util_pct,
                row.llc_id,
                row.same_cpu_streak,
                row.wakeup_source_pid,
                row.nvcsw_delta,
                row.nivcsw_delta,
                row.ewma_recomp_count,
                row.total_runs,
                row.tgid,
            ));
        }
    }

    output
}

/// Draw the UI
fn draw_ui(frame: &mut Frame, app: &mut TuiApp, stats: &cake_stats) {
    let area = frame.area();

    // --- Tab Bar ---
    let tab_titles = vec![
        " ● Dashboard ",
        " ◎ Topology ",
        " ◉ Inspector ",
        " ⚡ BenchLab ",
    ];
    let tabs = Tabs::new(tab_titles)
        .select(match app.active_tab {
            TuiTab::Dashboard => 0,
            TuiTab::Topology => 1,
            TuiTab::TaskInspector => 2,
            TuiTab::BenchLab => 3,
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
                .title(" scx_cake ")
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
        TuiTab::TaskInspector => draw_inspector_tab(frame, app, main_layout[1]),
        TuiTab::BenchLab => draw_bench_tab(frame, app, main_layout[1]),
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
        SortColumn::Ewma => format!("[EWMA]{}", arrow),
        SortColumn::Vcsw => format!("[VCSW]{}", arrow),
        SortColumn::Hog => format!("[HOG]{}", arrow),
        SortColumn::RunsPerSec => format!("[RUN/s]{}", arrow),
        SortColumn::Gap => format!("[GAP]{}", arrow),
    };

    let quit_label = if app.active_tab == TuiTab::TaskInspector {
        "[Esc] Back"
    } else {
        "[q] Quit"
    };

    let footer_text = match app.get_status() {
        Some(status) => format!(
            " Sort:{}  [s] Cycle  [S] Rev  [+/-] Rate  [↑↓] Scroll  [Tab] Views  [f] Filter  [c] Copy  [d] Dump  {}  │  {}",
            sort_label, quit_label, status
        ),
        None => format!(
            " Sort:{}  [s] Cycle  [S] Rev  [+/-] Rate  [↑↓] Scroll  [Tab] Views  [f] Filter  [c] Copy  [d] Dump  {}",
            sort_label, quit_label
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
            Constraint::Length(if app.tracked_game_tgid > 0 { 5 } else { 4 }), // Header: 2-3 content lines + borders
            Constraint::Length(8), // Tier performance panel (4 rows + header + borders)
            Constraint::Min(10),   // Full-width Task Matrix
        ])
        .split(area);

    // --- Compact Header: system info + tier counts on one line ---
    let total_dispatches = stats.nr_new_flow_dispatches + stats.nr_old_flow_dispatches;
    let new_pct = if total_dispatches > 0 {
        (stats.nr_new_flow_dispatches as f64 / total_dispatches as f64) * 100.0
    } else {
        0.0
    };

    // EWMA tier summary: count tasks by runtime bands
    let (mut wc0, mut wc1, mut wc2, mut wc3) = (0u32, 0u32, 0u32, 0u32);
    for row in app.task_rows.values() {
        if !row.is_bpf_tracked || row.total_runs == 0 {
            continue;
        }
        match row.avg_runtime_us {
            0..=49 => wc0 += 1,
            50..=499 => wc1 += 1,
            500..=4999 => wc2 += 1,
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

    // Hog count for header visibility
    let hog_count = app.task_rows.values().filter(|r| r.is_hog).count();
    let bg_count = app.task_rows.values().filter(|r| r.is_bg).count();
    let squeeze_str = match (hog_count > 0, bg_count > 0) {
        (true, true) => format!("  HOG:{}  BG:{}", hog_count, bg_count),
        (true, false) => format!("  HOG:{}", hog_count),
        (false, true) => format!("  BG:{}", bg_count),
        (false, false) => String::new(),
    };

    // Line 1: CPU | Dispatches | Tier Distribution
    let line1 =
        format!(
        " CPU: {}{}  │  Dispatches: {} ({:.0}% new)  │  Tiers: T0:{} T1:{} T2:{} T3:{}  │  {}{}{}",
        topo_flags,
        cpu_freq_str,
        total_dispatches,
        new_pct,
        wc0, wc1, wc2, wc3,
        app.format_uptime(),
        squeeze_str,
        drop_warn,
    );

    // Line 2: Dispatch locality | Queue depth | Tasks | Filter
    let dsq_depth = stats.nr_dsq_queued.saturating_sub(stats.nr_dsq_consumed);
    let filter_label = if app.show_all_tasks {
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
        " Dispatch: Local:{} Steal:{} Miss:{} HintSkip:{} ({:.0}%)  │  {}  │  Tasks: {} ({} arena)  │  [f] {}",
        stats.nr_local_dispatches,
        stats.nr_stolen_dispatches,
        stats.nr_dispatch_misses,
        stats.nr_dispatch_hint_skip,
        hint_pct,
        queue_str,
        app.bpf_task_count,
        app.arena_active,
        filter_label,
    );

    let header_text = if app.tracked_game_tgid > 0 {
        let mut game_line = format!(
            " Game: {} (PID {}, {} threads)",
            if app.game_name.is_empty() {
                "unknown"
            } else {
                &app.game_name
            },
            app.tracked_game_tgid,
            app.game_thread_count,
        );
        // Show challenger holdoff status if active
        if app.game_challenger_ppid > 0 {
            if let Some(since) = app.game_challenger_since {
                let elapsed = since.elapsed().as_secs();
                game_line.push_str(&format!(" [contender: {}s/15s]", elapsed));
            }
        }
        format!("{}\n{}\n{}", line1, line2, game_line)
    } else {
        format!("{}\n{}", line1, line2)
    };

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

    // --- EWMA Class Performance Panel ---
    // Aggregate by EWMA bands: E0 <50µs, E1 50-500µs, E2 500µs-5ms, E3 ≥5ms
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
        let t = match row.avg_runtime_us {
            0..=49 => 0,
            50..=499 => 1,
            500..=4999 => 2,
            _ => 3,
        };
        tier_pids[t] += 1;
        tier_avg_rt_sum[t] += row.avg_runtime_us as u64;
        tier_active[t] += 1;
        let j = row.jitter_accum_ns / row.total_runs as u64;
        tier_jitter_sum[t] += j / 1000;
        tier_runs_per_sec[t] += row.runs_per_sec;
        tier_wait_sum[t] += row.wait_duration_ns / 1000;
    }

    let total_runs_sec: f64 = tier_runs_per_sec.iter().sum();

    let tier_names = ["E0 <50µs", "E1 <500µs", "E2 <5ms", "E3 ≥5ms"];
    let tier_colors = [Color::LightCyan, Color::Green, Color::Yellow, Color::Red];

    let tier_header = Row::new(vec![
        Cell::from("EWMA").style(
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
            .title(" EWMA Class Performance (vtime offset = EWMA runtime) ")
            .title_style(
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            )
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::DarkGray))
            .border_type(BorderType::Rounded),
    );
    frame.render_widget(tier_table, outer_layout[1]);

    // All timing columns standardized to µs (noted in block title)
    let matrix_header = Row::new(vec![
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
        Cell::from("VCSW").style(
            Style::default()
                .fg(Color::LightGreen)
                .add_modifier(Modifier::BOLD),
        ),
        Cell::from("AVGRT").style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Cell::from("MAXRT").style(
            Style::default()
                .fg(Color::LightRed)
                .add_modifier(Modifier::BOLD),
        ),
        Cell::from("GAP").style(
            Style::default()
                .fg(Color::LightMagenta)
                .add_modifier(Modifier::BOLD),
        ),
        Cell::from("JITTER").style(
            Style::default()
                .fg(Color::LightCyan)
                .add_modifier(Modifier::BOLD),
        ),
        Cell::from("WAIT").style(
            Style::default()
                .fg(Color::LightYellow)
                .add_modifier(Modifier::BOLD),
        ),
        Cell::from("RUNS/s").style(
            Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD),
        ),
        Cell::from("CPU").style(
            Style::default()
                .fg(Color::Magenta)
                .add_modifier(Modifier::BOLD),
        ),
        Cell::from("SEL").style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Cell::from("ENQ").style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Cell::from("STOP").style(
            Style::default()
                .fg(Color::LightRed)
                .add_modifier(Modifier::BOLD),
        ),
        Cell::from("RUN").style(
            Style::default()
                .fg(Color::LightCyan)
                .add_modifier(Modifier::BOLD),
        ),
        Cell::from("G1").style(
            Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD),
        ),
        Cell::from("G2").style(
            Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD),
        ),
        Cell::from("G1W").style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Cell::from("G3").style(
            Style::default()
                .fg(Color::LightRed)
                .add_modifier(Modifier::BOLD),
        ),
        Cell::from("G1P").style(
            Style::default()
                .fg(Color::LightMagenta)
                .add_modifier(Modifier::BOLD),
        ),
        Cell::from("G1C").style(
            Style::default()
                .fg(Color::LightYellow)
                .add_modifier(Modifier::BOLD),
        ),
        Cell::from("G1CP").style(
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        ),
        Cell::from("G1D").style(
            Style::default()
                .fg(Color::LightCyan)
                .add_modifier(Modifier::BOLD),
        ),
        Cell::from("G1WC").style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Cell::from("G5").style(
            Style::default()
                .fg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        ),
        Cell::from("MIGR/s").style(
            Style::default()
                .fg(Color::LightMagenta)
                .add_modifier(Modifier::BOLD),
        ),
        Cell::from("TGID").style(
            Style::default()
                .fg(Color::DarkGray)
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
        // All ns → µs conversions at render time
        let cells = vec![
            Cell::from(format!("{}{}", indent, row.pid)),
            Cell::from(if row.is_hog {
                "●HOG"
            } else if row.is_bg {
                "●BG"
            } else {
                row.status.label()
            })
            .style(Style::default().fg(if row.is_hog {
                Color::LightRed
            } else if row.is_bg {
                Color::Rgb(255, 165, 0) // orange for bg_noise
            } else {
                row.status.color()
            })),
            Cell::from(row.comm.as_str()),
            Cell::from(format!("{}", row.nvcsw_delta)).style(vcsw_style),
            Cell::from(format!("{}", row.avg_runtime_us)),
            Cell::from(format!("{}", row.max_runtime_us)),
            Cell::from(format!("{}", row.dispatch_gap_us)),
            Cell::from(format!("{}", jitter_us)),
            Cell::from(format!("{}", row.wait_duration_ns / 1000)),
            Cell::from(format!("{:.1}", row.runs_per_sec)),
            Cell::from(format!("C{:02}", row.core_placement)),
            Cell::from(format!("{}", row.select_cpu_ns)),
            Cell::from(format!("{}", row.enqueue_ns)),
            Cell::from(format!("{}", row.stopping_duration_ns)),
            Cell::from(format!("{}", row.running_duration_ns)),
            Cell::from(format!("{:.0}", row.gate_hit_pcts[0])),
            Cell::from(format!("{:.0}", row.gate_hit_pcts[1])),
            Cell::from(format!("{:.0}", row.gate_hit_pcts[2])),
            Cell::from(format!("{:.0}", row.gate_hit_pcts[3])),
            Cell::from(format!("{:.0}", row.gate_hit_pcts[4])),
            Cell::from(format!("{:.0}", row.gate_hit_pcts[5])),
            Cell::from(format!("{:.0}", row.gate_hit_pcts[6])),
            Cell::from(format!("{:.0}", row.gate_hit_pcts[7])),
            Cell::from(format!("{:.0}", row.gate_hit_pcts[8])),
            Cell::from(format!("{:.0}", row.gate_hit_pcts[9])),
            Cell::from(format!("{:.1}", row.migrations_per_sec)),
            Cell::from(format!("{}", row.tgid)),
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
            Constraint::Length(8),  // PID
            Constraint::Length(3),  // ST
            Constraint::Length(15), // COMM
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
            Constraint::Length(3),  // G2
            Constraint::Length(4),  // G1W
            Constraint::Length(3),  // G3
            Constraint::Length(4),  // G1P
            Constraint::Length(4),  // G1C
            Constraint::Length(5),  // G1CP
            Constraint::Length(4),  // G1D
            Constraint::Length(5),  // G1WC
            Constraint::Length(3),  // G5
            Constraint::Length(7),  // MIGR/s
            Constraint::Length(7),  // TGID
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

    let heatmap = LatencyHeatmap::new(&app.latency_matrix, &app.topology);
    frame.render_widget(heatmap, layout[1]);

    let data_table = LatencyTable::new(&app.latency_matrix, &app.topology);
    frame.render_widget(data_table, layout[2]);
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
        (15, "RODATA llc+tier_slice", "Data Read", "C"),
        // Mailbox CL0: cake's Disruptor handoff variants
        (12, "Mbox CL0 tctx+deref", "Mailbox CL0", "C"),
        (18, "CL0 ptr+fused+packed", "Mailbox CL0", "C"),
        (21, "Disruptor CL0 full read", "Mailbox CL0", "C"),
        // Composite: cake-only multi-step operations
        (16, "Bitflag shift+mask+brless", "Composite Ops", "C"),
        (17, "compute_ewma() full", "Composite Ops", "C"),
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

fn draw_inspector_tab(frame: &mut Frame, app: &TuiApp, area: Rect) {
    let pid = match app.selected_pid {
        Some(p) => p,
        None => return,
    };

    let row = match app.task_rows.get(&pid) {
        Some(r) => r,
        None => {
            // Task might have died or left the arena
            let msg = Paragraph::new(format!("Task {} not found in active telemetry arena.", pid))
                .style(Style::default().fg(Color::Red));
            frame.render_widget(msg, area);
            return;
        }
    };

    let title = format!(" Task Inspector: {} (PID: {}) ", row.comm, row.pid);

    let layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(5), // Overview
            Constraint::Min(7),    // Event Latencies
            Constraint::Length(5), // Counters
        ])
        .split(area);

    let overview_text = vec![
        Line::from(vec![
            Span::styled("Tier: ", Style::default().fg(Color::DarkGray)),
            Span::styled(format!("T{}", row.tier), tier_style(row.tier as usize)),
            Span::styled(
                "  |  Avg Runtime (EWMA): ",
                Style::default().fg(Color::DarkGray),
            ),
            Span::styled(
                format!("{} µs", row.avg_runtime_us),
                Style::default().fg(Color::Cyan),
            ),
            Span::styled("  |  Deficit: ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                format!("{} µs", row.deficit_us),
                Style::default().fg(Color::Cyan),
            ),
        ]),
        Line::from(vec![
            Span::styled("Core Placement: ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                format!("CPU{:02}", row.core_placement),
                Style::default().fg(Color::Magenta),
            ),
            Span::styled(
                "  |  Gate 1 Hit Rate: ",
                Style::default().fg(Color::DarkGray),
            ),
            Span::styled(
                format!("{:.1}%", row.gate_hit_pcts[0]),
                Style::default().fg(Color::Green),
            ),
        ]),
    ];
    let overview_par = Paragraph::new(overview_text).block(
        Block::default()
            .title(title)
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Blue)),
    );
    frame.render_widget(overview_par, layout[0]);

    let event_text = vec![
        Line::from(vec![
            Span::styled("Enqueue Sort: ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                format!("{:>8} ns", row.enqueue_ns),
                Style::default().fg(Color::Yellow),
            ),
        ]),
        Line::from(vec![
            Span::styled("DSQ Wait Time: ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                format!("{:>8} ns", row.wait_duration_ns),
                Style::default().fg(Color::Red),
            ),
        ]),
        Line::from(vec![
            Span::styled("Select CPU Routing: ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                format!("{:>8} ns", row.select_cpu_ns),
                Style::default().fg(Color::Cyan),
            ),
        ]),
        Line::from(vec![
            Span::styled(
                "  └─ DSQ Insert Overhead: ",
                Style::default().fg(Color::DarkGray),
            ),
            Span::styled(
                format!("{:>8} ns", row.dsq_insert_ns),
                Style::default().fg(Color::Gray),
            ),
        ]),
    ];
    let event_par = Paragraph::new(event_text).block(
        Block::default()
            .title(" Dispatch Latencies (Last Wakeup) ")
            .borders(Borders::ALL),
    );
    frame.render_widget(event_par, layout[1]);

    let jitter_us = if row.total_runs > 0 {
        (row.jitter_accum_ns / row.total_runs as u64) / 1000
    } else {
        0
    };

    let counter_text = vec![
        Line::from(vec![
            Span::styled("Migrations: ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                format!("{:<6}", row.migration_count),
                Style::default().fg(Color::Yellow),
            ),
            Span::styled("  |  Preemptions: ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                format!("{:<6}", row.preempt_count),
                Style::default().fg(Color::Red),
            ),
            Span::styled("  |  Yields: ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                format!("{:<6}", row.yield_count),
                Style::default().fg(Color::LightBlue),
            ),
        ]),
        Line::from(vec![
            Span::styled("Total Runs: ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                format!("{:<6}", row.total_runs),
                Style::default().fg(Color::Green),
            ),
            Span::styled("  |  Avg Jitter:  ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                format!("{} µs", jitter_us),
                Style::default().fg(Color::LightCyan),
            ),
        ]),
    ];
    let counter_par = Paragraph::new(counter_text).block(
        Block::default()
            .title(" Lifetime State Changes ")
            .borders(Borders::ALL),
    );
    frame.render_widget(counter_par, layout[2]);
}

/// Get color style for a tier
fn tier_style(tier: usize) -> Style {
    match tier {
        0 => Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD), // Critical (<100µs)
        1 => Style::default().fg(Color::Green), // Interactive (<2ms)
        2 => Style::default().fg(Color::Yellow), // Frame (<8ms)
        3 => Style::default().fg(Color::DarkGray), // Bulk (≥8ms)
        _ => Style::default(),
    }
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
                for i in 0..50 {
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

        // Draw UI
        terminal.draw(|frame| draw_ui(frame, &mut app, &stats))?;

        // Handle events with timeout
        let timeout = tick_rate.saturating_sub(last_tick.elapsed());
        if event::poll(timeout)? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press {
                    match key.code {
                        KeyCode::Char('q') | KeyCode::Esc => {
                            if app.active_tab == TuiTab::TaskInspector {
                                app.active_tab = TuiTab::Dashboard;
                                app.selected_pid = None;
                            } else {
                                shutdown.store(true, Ordering::Relaxed);
                                break;
                            }
                        }
                        KeyCode::Enter => {
                            if app.active_tab == TuiTab::Dashboard {
                                if let Some(i) = app.table_state.selected() {
                                    if let Some(pid) = app.sorted_pids.get(i) {
                                        app.selected_pid = Some(*pid);
                                        app.active_tab = TuiTab::TaskInspector;
                                    }
                                }
                            }
                            app.next_tab();
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
                            // Trigger kfunc benchmark
                            if let Some(bss) = &mut skel.maps.bss_data {
                                bss.bench_request = 1;
                                app.set_status(&format!(
                                    "⚡ BenchLab: run #{} queued...",
                                    app.bench_run_count + 1
                                ));
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
                        .last()
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

            // --- Arena Telemetry Sweep (via pid_to_tctx BPF hash map) ---
            if let Some(bss) = &skel.maps.bss_data {
                let pool = &bss.scx_task_allocator.pool;
                let _slab_ptr = pool.slab as *const u8;
                let max_elems = pool.max_elems as usize;
                let _elem_size = pool.elem_size as usize;

                // Track currently active PIDs in this sweep to prune dead tasks
                // Reuse active_pids buffer to avoid per-tick allocation
                app.active_pids_buf.clear();

                // PRIMARY: Iterate pid_to_tctx BPF hash map for 100% task coverage.
                // For each PID, lookup the arena tctx pointer and read telemetry directly.
                // The arena is mmap'd so these pointers are valid userspace addresses.
                {
                    use std::os::fd::{AsFd, AsRawFd};
                    let map = &skel.maps.pid_to_tctx;
                    let bpf_fd = map.as_fd().as_raw_fd();
                    if bpf_fd >= 0 {
                        let mut key: u32 = 0;
                        let mut next_key: u32 = 0;
                        let mut first = true;

                        loop {
                            let ret = unsafe {
                                libbpf_rs::libbpf_sys::bpf_map_get_next_key(
                                    bpf_fd,
                                    if first {
                                        std::ptr::null()
                                    } else {
                                        &key as *const u32 as *const std::ffi::c_void
                                    },
                                    &mut next_key as *mut u32 as *mut std::ffi::c_void,
                                )
                            };
                            if ret != 0 {
                                break;
                            }
                            first = false;
                            key = next_key;

                            // Look up the arena tctx pointer
                            let mut tctx_ptr_val: u64 = 0;
                            let lookup_ret = unsafe {
                                libbpf_rs::libbpf_sys::bpf_map_lookup_elem(
                                    bpf_fd,
                                    &key as *const u32 as *const std::ffi::c_void,
                                    &mut tctx_ptr_val as *mut u64 as *mut std::ffi::c_void,
                                )
                            };
                            if lookup_ret != 0 || tctx_ptr_val == 0 {
                                continue;
                            }

                            // Read cake_task_ctx directly from the mmap'd arena pointer
                            let ctx_ptr = tctx_ptr_val as *const crate::bpf_intf::cake_task_ctx;
                            let ctx = unsafe { std::ptr::read_unaligned(ctx_ptr) };

                            let pid = ctx.telemetry.pid;
                            let packed =
                                unsafe { ctx.__bindgen_anon_1.__bindgen_anon_1.packed_info };
                            let tier = (packed >> 28) & 0x03;
                            let is_hog = (packed >> 27) & 1 != 0; /* CAKE_FLOW_HOG at bit 24+3 */
                            let is_bg = (packed >> 22) & 1 != 0; /* BIT_BG_NOISE at bit 22 */

                            if pid == 0 || tier > 3 {
                                continue;
                            }

                            app.active_pids_buf.insert(pid);

                            let comm_bytes: [u8; 16] =
                                unsafe { std::mem::transmute(ctx.telemetry.comm) };
                            let comm = match std::ffi::CStr::from_bytes_until_nul(&comm_bytes) {
                                Ok(c) => c.to_string_lossy().into_owned(),
                                Err(_) => String::from_utf8_lossy(&comm_bytes)
                                    .trim_end_matches('\0')
                                    .to_string(),
                            };

                            // Extract deficit and avg runtime using the bindgen anonymous union paths
                            let deficit_us = unsafe {
                                ctx.__bindgen_anon_1
                                    .__bindgen_anon_1
                                    .__bindgen_anon_1
                                    .__bindgen_anon_1
                                    .deficit_us as u32
                            };
                            let avg_runtime_us = unsafe {
                                ctx.__bindgen_anon_1
                                    .__bindgen_anon_1
                                    .__bindgen_anon_1
                                    .__bindgen_anon_1
                                    .avg_runtime_us as u32
                            };

                            // Map all 6 gates from BPF telemetry
                            let g1 = ctx.telemetry.gate_1_hits;
                            let g2 = ctx.telemetry.gate_2_hits;
                            let g1w = ctx.telemetry.gate_1w_hits;
                            let g3 = ctx.telemetry.gate_3_hits;
                            let g1p = ctx.telemetry.gate_1p_hits;
                            let g1c = ctx.telemetry.gate_1c_hits;
                            let g1cp = ctx.telemetry.gate_1cp_hits;
                            let g1d = ctx.telemetry.gate_1d_hits;
                            let g1wc = ctx.telemetry.gate_1wc_hits;
                            let g5 = ctx.telemetry.gate_tun_hits;
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

                            let total_runs = ctx.telemetry.total_runs;
                            let jitter_accum_ns = ctx.telemetry.jitter_accum_ns;

                            // Use the HashMap to persist old data until overwritten cleanly
                            let row =
                                app.task_rows
                                    .entry(pid)
                                    .or_insert_with(|| TaskTelemetryRow {
                                        pid,
                                        comm: comm.clone(),
                                        tier: tier as u8,
                                        avg_runtime_us,
                                        deficit_us,
                                        wait_duration_ns: ctx.telemetry.wait_duration_ns,
                                        select_cpu_ns: ctx.telemetry.select_cpu_duration_ns,
                                        enqueue_ns: ctx.telemetry.enqueue_duration_ns,
                                        gate_hit_pcts,
                                        core_placement: ctx.telemetry.core_placement,
                                        dsq_insert_ns: ctx.telemetry.dsq_insert_ns,
                                        migration_count: ctx.telemetry.migration_count,
                                        preempt_count: ctx.telemetry.preempt_count,
                                        yield_count: ctx.telemetry.yield_count,
                                        total_runs,
                                        jitter_accum_ns,
                                        direct_dispatch_count: ctx.telemetry.direct_dispatch_count,
                                        enqueue_count: ctx.telemetry.enqueue_count,
                                        cpumask_change_count: ctx.telemetry.cpumask_change_count,
                                        stopping_duration_ns: ctx.telemetry.stopping_duration_ns,
                                        running_duration_ns: ctx.telemetry.running_duration_ns,
                                        max_runtime_us: ctx.telemetry.max_runtime_us,
                                        dispatch_gap_us: ctx.telemetry.dispatch_gap_ns / 1000,
                                        max_dispatch_gap_us: ctx.telemetry.max_dispatch_gap_ns
                                            / 1000,
                                        wait_hist: [
                                            ctx.telemetry.wait_hist_lt10us,
                                            ctx.telemetry.wait_hist_lt100us,
                                            ctx.telemetry.wait_hist_lt1ms,
                                            ctx.telemetry.wait_hist_ge1ms,
                                        ],
                                        runs_per_sec: 0.0,
                                        migrations_per_sec: 0.0,
                                        status: TaskStatus::Alive,
                                        is_bpf_tracked: true,
                                        tgid: ctx.telemetry.tgid,
                                        slice_util_pct: ctx.telemetry.slice_util_pct,
                                        llc_id: ctx.telemetry.llc_id,
                                        same_cpu_streak: ctx.telemetry.same_cpu_streak,
                                        wakeup_source_pid: ctx.telemetry.wakeup_source_pid,
                                        nvcsw_delta: ctx.telemetry.nvcsw_delta,
                                        nivcsw_delta: ctx.telemetry.nivcsw_delta,
                                        ewma_recomp_count: ctx.telemetry.ewma_recomp_count,
                                        is_hog,
                                        is_bg,
                                        ppid: ctx.ppid,
                                    });

                            // Update dynamic row elements
                            row.tier = tier as u8;
                            row.avg_runtime_us = avg_runtime_us;
                            row.deficit_us = deficit_us;
                            row.wait_duration_ns = ctx.telemetry.wait_duration_ns;
                            row.select_cpu_ns = ctx.telemetry.select_cpu_duration_ns;
                            row.enqueue_ns = ctx.telemetry.enqueue_duration_ns;
                            row.gate_hit_pcts = gate_hit_pcts;
                            row.core_placement = ctx.telemetry.core_placement;
                            row.dsq_insert_ns = ctx.telemetry.dsq_insert_ns;
                            row.migration_count = ctx.telemetry.migration_count;
                            row.preempt_count = ctx.telemetry.preempt_count;
                            row.yield_count = ctx.telemetry.yield_count;
                            row.total_runs = total_runs;
                            row.jitter_accum_ns = jitter_accum_ns;
                            row.direct_dispatch_count = ctx.telemetry.direct_dispatch_count;
                            row.enqueue_count = ctx.telemetry.enqueue_count;
                            row.cpumask_change_count = ctx.telemetry.cpumask_change_count;
                            row.stopping_duration_ns = ctx.telemetry.stopping_duration_ns;
                            row.running_duration_ns = ctx.telemetry.running_duration_ns;
                            row.max_runtime_us = ctx.telemetry.max_runtime_us;
                            row.dispatch_gap_us = ctx.telemetry.dispatch_gap_ns / 1000;
                            row.max_dispatch_gap_us = ctx.telemetry.max_dispatch_gap_ns / 1000;
                            row.wait_hist = [
                                ctx.telemetry.wait_hist_lt10us,
                                ctx.telemetry.wait_hist_lt100us,
                                ctx.telemetry.wait_hist_lt1ms,
                                ctx.telemetry.wait_hist_ge1ms,
                            ];
                            row.is_bpf_tracked = true;
                            row.slice_util_pct = ctx.telemetry.slice_util_pct;
                            row.llc_id = ctx.telemetry.llc_id;
                            row.same_cpu_streak = ctx.telemetry.same_cpu_streak;
                            row.wakeup_source_pid = ctx.telemetry.wakeup_source_pid;
                            row.ewma_recomp_count = ctx.telemetry.ewma_recomp_count;
                            row.is_hog = is_hog;
                            row.is_bg = is_bg;
                            row.ppid = ctx.ppid;
                            // Status set below after sysinfo cross-reference
                        } // end loop iteration
                    } // end if bpf_fd >= 0
                } // end outer block

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
                            tier: 3,
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

                // --- Game Detection: aggregate yields per PPID, pick winner ---
                // Proton/Wine: all siblings (wineserver, game.exe, winedevice)
                // share the same parent (pv-adverb). Aggregating by PPID means
                // wineserver's yields + game yields combine, giving a stronger
                // signal and ensuring the entire Wine prefix is detected as a family.
                {
                    let mut best_ppid: u32 = 0;
                    let mut best_yields: u64 = 0;
                    let mut best_thread_count: usize = 0;
                    // Aggregate yields by PPID (parent process)
                    let mut ppid_yields: std::collections::HashMap<u32, (u64, usize)> =
                        std::collections::HashMap::new();
                    for (_pid, row) in app.task_rows.iter() {
                        if row.status == TaskStatus::Dead || row.yield_count == 0 || row.ppid == 0 {
                            continue;
                        }
                        let entry = ppid_yields.entry(row.ppid).or_insert((0, 0));
                        entry.0 += row.yield_count as u64;
                        entry.1 += 1;
                    }
                    for (ppid, (total_yields, thread_count)) in &ppid_yields {
                        if *total_yields > best_yields {
                            best_yields = *total_yields;
                            best_ppid = *ppid;
                            best_thread_count = *thread_count;
                        }
                    }
                    // Threshold: need at least 64 total yields to qualify as a game.
                    // Game workers hit this in <100ms. Prevents false positives from
                    // language servers or build tools with occasional yields.
                    let new_game_ppid = if best_yields >= 64 { best_ppid } else { 0 };

                    // Helper: resolve best TGID + name for a given PPID (cold path)
                    let resolve_game =
                        |ppid: u32, rows: &HashMap<u32, TaskTelemetryRow>| -> (u32, String) {
                            let mut best_tgid: u32 = 0;
                            let mut best_tgid_yields: u64 = 0;
                            let mut tgid_yields: std::collections::HashMap<u32, u64> =
                                std::collections::HashMap::new();
                            for (_pid, row) in rows.iter() {
                                if row.ppid == ppid && row.yield_count > 0 {
                                    let tgid = if row.tgid > 0 { row.tgid } else { row.pid };
                                    *tgid_yields.entry(tgid).or_insert(0) += row.yield_count as u64;
                                }
                            }
                            for (tgid, yields) in &tgid_yields {
                                if *yields > best_tgid_yields {
                                    best_tgid_yields = *yields;
                                    best_tgid = *tgid;
                                }
                            }
                            let game_tgid = if best_tgid > 0 { best_tgid } else { ppid };
                            // Read game name from /proc (cold path, only on game switch)
                            let name = {
                                let mut n = String::from("unknown");
                                if let Ok(cmdline) =
                                    std::fs::read(format!("/proc/{}/cmdline", game_tgid))
                                {
                                    for arg in cmdline.split(|&b| b == 0) {
                                        if let Ok(s) = std::str::from_utf8(arg) {
                                            if s.to_lowercase().ends_with(".exe") {
                                                let basename =
                                                    s.rsplit(['\\', '/']).next().unwrap_or(s);
                                                n = basename
                                                    .trim_end_matches(".exe")
                                                    .trim_end_matches(".EXE")
                                                    .to_string();
                                                break;
                                            }
                                        }
                                    }
                                }
                                if n == "unknown" {
                                    if let Ok(comm) =
                                        std::fs::read_to_string(format!("/proc/{}/comm", game_tgid))
                                    {
                                        n = comm.trim().to_string();
                                    }
                                }
                                n
                            };
                            (game_tgid, name)
                        };

                    // Game exit detection: if current game process is gone, clear immediately
                    if app.tracked_game_tgid > 0 {
                        let proc_path = format!("/proc/{}", app.tracked_game_tgid);
                        if !std::path::Path::new(&proc_path).exists() {
                            app.tracked_game_tgid = 0;
                            app.tracked_game_ppid = 0;
                            app.game_thread_count = 0;
                            app.game_name.clear();
                            app.game_challenger_ppid = 0;
                            app.game_challenger_since = None;
                        }
                    }

                    // --- Hysteresis State Machine ---
                    // Once a game is locked, a challenger must sustain the yield lead
                    // for 15 consecutive seconds before the scheduler accepts the swap.
                    // This prevents harsh alt-tab flips from transient yield spikes.
                    const GAME_HOLDOFF_SECS: u64 = 15;

                    if app.tracked_game_tgid == 0 {
                        // No game locked — accept immediately (first detection, instant)
                        if new_game_ppid > 0 {
                            let (tgid, name) = resolve_game(new_game_ppid, &app.task_rows);
                            app.tracked_game_tgid = tgid;
                            app.tracked_game_ppid = new_game_ppid;
                            app.game_thread_count = best_thread_count;
                            app.game_name = name;
                            app.game_challenger_ppid = 0;
                            app.game_challenger_since = None;
                        }
                    } else if new_game_ppid == app.tracked_game_ppid {
                        // Same game family still winning — update thread count, reset challenger
                        app.game_thread_count = best_thread_count;
                        app.game_challenger_ppid = 0;
                        app.game_challenger_since = None;
                    } else if new_game_ppid > 0 {
                        // Different PPID is winning — challenger detected
                        if app.game_challenger_ppid != new_game_ppid {
                            // New challenger appeared, start the 15s timer
                            app.game_challenger_ppid = new_game_ppid;
                            app.game_challenger_since = Some(Instant::now());
                        } else if let Some(since) = app.game_challenger_since {
                            // Same challenger persisting — check if 15s holdoff expired
                            if since.elapsed() >= Duration::from_secs(GAME_HOLDOFF_SECS) {
                                // Challenger sustained the lead — swap game
                                let (tgid, name) = resolve_game(new_game_ppid, &app.task_rows);
                                app.tracked_game_tgid = tgid;
                                app.tracked_game_ppid = new_game_ppid;
                                app.game_thread_count = best_thread_count;
                                app.game_name = name;
                                app.game_challenger_ppid = 0;
                                app.game_challenger_since = None;
                            }
                            // else: keep waiting, don't switch yet
                        }
                    } else {
                        // No qualifying PPID above threshold — challenger gone, but keep current game
                        app.game_challenger_ppid = 0;
                        app.game_challenger_since = None;
                    }
                }

                // Write game_ppid to BPF BSS — drives all scheduling decisions.
                // PPID sourced directly from arena (BPF caches p->real_parent->tgid).
                // game_tgid still written for display/TUI purposes.
                if let Some(bss) = &mut skel.maps.bss_data {
                    bss.game_tgid = app.tracked_game_tgid;
                    // Use tracked_game_ppid directly — already resolved by hysteresis FSM
                    bss.game_ppid = app.tracked_game_ppid;
                }

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
                app.arena_max = max_elems;
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
                        let cmp = r_b.avg_runtime_us.cmp(&r_a.avg_runtime_us);
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
                        let cmp = r_a.tier.cmp(&r_b.tier);
                        if desc {
                            cmp
                        } else {
                            cmp.reverse()
                        }
                    }),
                    SortColumn::Ewma => sorted_pids.sort_by(|a, b| {
                        let r_a = app.task_rows.get(a).unwrap();
                        let r_b = app.task_rows.get(b).unwrap();
                        let cmp = r_b.avg_runtime_us.cmp(&r_a.avg_runtime_us);
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
                        let cmp = (r_b.is_hog as u8).cmp(&(r_a.is_hog as u8));
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
                        r_b.avg_runtime_us.cmp(&r_a.avg_runtime_us)
                    })
                });

                app.sorted_pids = sorted_pids;
            }

            last_tick = Instant::now();
        }
    }

    restore_terminal()?;
    Ok(())
}
