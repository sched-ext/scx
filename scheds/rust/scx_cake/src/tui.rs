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
    // Confidence-based polling throttle (Rule 40)
    pub game_stable_polls: u32, // consecutive polls with same PPID winner
    pub game_skip_counter: u32, // how many polls we've skipped this interval
    // Scheduler state machine (IDLE=0, COMPILATION=1, GAMING=2)
    pub sched_state: u8,           // current operating state written to BPF BSS
    pub compile_task_count: usize, // active compiler task count for display
    // Game detection confidence tier (100=Steam, 90=Wine .exe, 0=none)
    pub game_confidence: u8,
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
    pub is_hog: bool,         // Hog squeeze: BULK + non-yielder + deprioritized
    pub is_bg: bool,          // Background noise squeeze: non-game, non-wb, non-kernel
    pub is_game_member: bool, // Task is in the game PPID family (tgid==game_tgid or ppid==game_ppid)
    pub ppid: u32,            // Parent PID for game family detection
    // Phase 8: Per-callback sub-function stopwatch (ns)
    pub gate_cascade_ns: u32,  // select_cpu: full gate cascade duration
    pub idle_probe_ns: u32,    // select_cpu: winning gate idle probe cost
    pub vtime_compute_ns: u32, // enqueue: vtime calculation + tier weighting
    pub mbox_staging_ns: u32,  // running: mailbox CL0 write burst
    pub ewma_compute_ns: u32,  // stopping: compute_ewma() call
    pub classify_ns: u32,      // stopping: tier classify + squeeze fusion
    pub vtime_staging_ns: u32, // stopping: dsq_vtime bit packing + writes
    pub warm_history_ns: u32,  // stopping: warm CPU ring shift
    // Phase 8: Quantum completion tracking
    pub quantum_full_count: u16,    // Task consumed entire slice
    pub quantum_yield_count: u16,   // Task yielded before slice exhaustion
    pub quantum_preempt_count: u16, // Task was kicked/preempted mid-slice
    // Phase 8: Wake chain enhancement
    pub waker_cpu: u16,  // CPU the waker was running on
    pub waker_tgid: u32, // TGID of the waker (process group)
    // Phase 8: CPU core distribution histogram
    pub cpu_run_count: [u16; 64], // Per-CPU run count (TUI normalizes to %)
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
            is_game_member: false,
            ppid: 0,
            // Phase 8
            gate_cascade_ns: 0,
            idle_probe_ns: 0,
            vtime_compute_ns: 0,
            mbox_staging_ns: 0,
            ewma_compute_ns: 0,
            classify_ns: 0,
            vtime_staging_ns: 0,
            warm_history_ns: 0,
            quantum_full_count: 0,
            quantum_yield_count: 0,
            quantum_preempt_count: 0,
            waker_cpu: 0,
            waker_tgid: 0,
            cpu_run_count: [0u16; 64],
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

            // Phase 8: dispatch callback timing
            total.total_dispatch_ns += s.total_dispatch_ns;
            total.max_dispatch_ns = total.max_dispatch_ns.max(s.max_dispatch_ns);
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
            game_stable_polls: 0,
            game_skip_counter: 0,
            sched_state: 0,
            compile_task_count: 0,
            game_confidence: 0,
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
    output.push_str(&app.system_info.format_header());

    // Compact state/game/uptime line
    let state_str = match app.sched_state {
        2 => {
            let conf_label = match app.game_confidence {
                100 => "Steam",
                90 => "Wine",
                _ => "?",
            };
            format!(
                "GAMING game={} pid={} threads={} conf={}%[{}]",
                if app.game_name.is_empty() {
                    "?"
                } else {
                    &app.game_name
                },
                app.tracked_game_tgid,
                app.game_thread_count,
                app.game_confidence,
                conf_label,
            )
        }

        1 => format!("COMPILATION compile_tasks={}", app.compile_task_count),
        _ => "IDLE".to_string(),
    };
    output.push_str(&format!(
        "cake: uptime={} state={}\n",
        app.format_uptime(),
        state_str
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
    output.push_str(&format!(
        "disp: total={} new={:.1}% local={} steal={} miss={} hint_skip={} hint%={:.0} queue={}\n",
        total_dispatches,
        new_pct,
        stats.nr_local_dispatches,
        stats.nr_stolen_dispatches,
        stats.nr_dispatch_misses,
        stats.nr_dispatch_hint_skip,
        hint_pct,
        dsq_depth,
    ));

    // Compact callback profile (all on 2 lines)
    let stop_total = stats.nr_stop_confidence_skip
        + stats.nr_stop_ewma
        + stats.nr_stop_ramp
        + stats.nr_stop_miss;
    let stop_total_f = (stop_total as f64).max(1.0);
    output.push_str(&format!(
        "cb.stop: tot_µs={} max_ns={} calls={} skip={:.1}% ewma={:.1}% ramp={:.1}% miss={:.1}%\n",
        stats.total_stopping_ns / 1000,
        stats.max_stopping_ns,
        stop_total,
        stats.nr_stop_confidence_skip as f64 / stop_total_f * 100.0,
        stats.nr_stop_ewma as f64 / stop_total_f * 100.0,
        stats.nr_stop_ramp as f64 / stop_total_f * 100.0,
        stats.nr_stop_miss as f64 / stop_total_f * 100.0,
    ));
    output.push_str(&format!(
        "cb.run: tot_µs={} max_ns={} calls={}  cb.enq: tot_µs={} calls={}  sel: g1_µs={} g2_µs={}  cb.disp: tot_µs={} max_ns={} calls={}\n",
        stats.total_running_ns / 1000, stats.max_running_ns, total_dispatches,
        stats.total_enqueue_latency_ns / 1000, total_dispatches,
        stats.total_gate1_latency_ns / 1000, stats.total_gate2_latency_ns / 1000,
        stats.total_dispatch_ns / 1000, stats.max_dispatch_ns, total_dispatch_calls,
    ));

    if app.bench_run_count > 0 {
        output.push_str(&format_bench_for_clipboard(app));
    }

    // Task matrix header — compact column key
    output.push_str("\ntasks: [PPID PID ST COMM EWMA AVG MAX GAP JIT WAIT R/s CPU SEL ENQ STOP RUN G1 G2 G1W G3 G1P G1C G1CP G1D G1WC G5 MIG/s WHIST]\n");
    output.push_str("       [detail-A: gates% + DIRECT DEFI YIELD PRMPT ENQ MASK MAX_GAP DSQ_INS RUNS SUTIL LLC STREAK WAKER VCSW ICSW CONF TGID]\n");
    output.push_str("       [detail-B: sw=cascade/probe/vtime/mbox/ewma/classify/vstg/warm(ns) qc=F%/Y%/P% wk=pid/tgid@cpu dist=C:pct,...]\n");

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
                // Game family member: show ●GAME badge to signal boost status.
                // This takes priority over HOG/BG which are cosmetic EWMA labels.
                // Note: BPF's can_squeeze = !is_game so game tasks are NEVER squeezed.
                TaskStatus::Alive if row.is_game_member => "●GAME",
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
                "{}{:<5} {:<7} {:<3} {:<15} {:<4} {:<6} {:<6} {:<7} {:<7} {:<6} {:<7.1} C{:<3} {:<5} {:<5} {:<5} {:<5} {:<4.0} {:<4.0} {:<4.0} {:<4.0} {:<4.0} {:<4.0} {:<4.0} {:<4.0} {:<4.0} {:<4.0} {:<7.1} {}/{}/{}/{}\n",
                indent,
                row.ppid,
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
            // detail-A: gate % (G1..G5) + all extended fields, compact labels
            output.push_str(&format!(
                "{}  g={:.0}/{:.0}/{:.0}/{:.0}/{:.0}/{:.0}/{:.0}/{:.0}/{:.0}/{:.0} dir={} defi={}µs yld={} prmpt={} enq={} mask={} maxgap={}µs dsqins={}ns runs={} sutil={}% llc=L{:02} streak={} waker={} vcsw={} icsw={} conf={}/{} tgid={}\n",
                indent,
                row.gate_hit_pcts[0], row.gate_hit_pcts[1], row.gate_hit_pcts[2],
                row.gate_hit_pcts[3], row.gate_hit_pcts[4], row.gate_hit_pcts[5],
                row.gate_hit_pcts[6], row.gate_hit_pcts[7], row.gate_hit_pcts[8],
                row.gate_hit_pcts[9],
                row.direct_dispatch_count, row.deficit_us, row.yield_count,
                row.preempt_count, row.enqueue_count, row.cpumask_change_count,
                row.max_dispatch_gap_us, row.dsq_insert_ns, row.total_runs,
                row.slice_util_pct, row.llc_id, row.same_cpu_streak,
                row.wakeup_source_pid, row.nvcsw_delta, row.nivcsw_delta,
                row.ewma_recomp_count, row.total_runs, row.tgid,
            ));
            // detail-B: stopwatch(ns) + quantum completion % + waker + cpu dist — all one line
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
            let total_cpu_runs: u32 = row.cpu_run_count.iter().map(|&c| c as u32).sum();
            let dist_str = if total_cpu_runs > 0 {
                let mut cpu_pcts: Vec<(usize, f64)> = row
                    .cpu_run_count
                    .iter()
                    .enumerate()
                    .filter(|(_, &c)| c > 0)
                    .map(|(i, &c)| (i, c as f64 / total_cpu_runs as f64 * 100.0))
                    .collect();
                cpu_pcts.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
                cpu_pcts
                    .iter()
                    .take(8)
                    .map(|(cpu, pct)| format!("C{}:{:.0}", cpu, pct))
                    .collect::<Vec<_>>()
                    .join(",")
            } else {
                "-".to_string()
            };
            output.push_str(&format!(
                "{}  sw={}/{}/{}/{}/{}/{}/{}/{} qc=F{:.0}/Y{:.0}/P{:.0} wk={}/{}@{} ppid={} dist={}\n",
                indent,
                row.gate_cascade_ns, row.idle_probe_ns, row.vtime_compute_ns,
                row.mbox_staging_ns, row.ewma_compute_ns, row.classify_ns,
                row.vtime_staging_ns, row.warm_history_ns,
                q_full_pct, q_yield_pct, q_preempt_pct,
                row.wakeup_source_pid, row.waker_tgid, row.waker_cpu,
                row.ppid, dist_str,
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
        " BenchLab ",
        " ⓘ Reference ",
    ];
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
        SortColumn::Ewma => format!("[EWMA]{}", arrow),
        SortColumn::Vcsw => format!("[VCSW]{}", arrow),
        SortColumn::Hog => format!("[HOG]{}", arrow),
        SortColumn::RunsPerSec => format!("[RUN/s]{}", arrow),
        SortColumn::Gap => format!("[GAP]{}", arrow),
    };

    let quit_label = "[q] Quit";

    let footer_text = match app.get_status() {
        Some(status) => format!(
            " Sort:{}  [s] Cycle  [S] Rev  [+/-] Rate  [↑↓] Scroll  [T] Top  [Enter] Fold  [x] Fold All  [Tab] Views  [f] Filter  [c] Copy  [d] Dump  {}  │  {}",
            sort_label, quit_label, status
        ),
        None => format!(
            " Sort:{}  [s] Cycle  [S] Rev  [+/-] Rate  [↑↓] Scroll  [T] Top  [Enter] Fold  [x] Fold All  [Tab] Views  [f] Filter  [c] Copy  [d] Dump  {}",
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
            Constraint::Length(5), // Header: 3 content lines (stats + sched + state/game) + 2 borders
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

    // State label — shown in header for all three operating states
    let state_line = match app.sched_state {
        2 => String::new(), // GAMING: state shown inline in game_line below
        1 => format!(
            " State: COMPILATION | {} compiler task{} active",
            app.compile_task_count,
            if app.compile_task_count == 1 { "" } else { "s" }
        ),
        _ => " State: IDLE".to_string(),
    };

    let header_text = if app.tracked_game_tgid > 0 {
        // Confidence tag: shows detection tier + poll stability
        let conf_label = match app.game_confidence {
            100 => "Steam",
            90 => "Wine/.exe",
            _ => "unknown",
        };
        let stability = if app.game_stable_polls >= 20 {
            "\u{1F512}".to_string()
        } else {
            format!("{}/20", app.game_stable_polls)
        };
        let mut game_line = format!(
            " State: GAMING | Game: {} (PID {}, {} threads) [{}% {} {}]",
            if app.game_name.is_empty() {
                "unknown"
            } else {
                &app.game_name
            },
            app.tracked_game_tgid,
            app.game_thread_count,
            app.game_confidence,
            conf_label,
            stability,
        );
        // Show challenger holdoff status if active
        if app.game_challenger_ppid > 0 {
            if let Some(since) = app.game_challenger_since {
                let elapsed = since.elapsed().as_secs();
                game_line.push_str(&format!(" [contender: {}s/15s]", elapsed));
            }
        }
        format!("{}\n{}\n{}", line1, line2, game_line)
    } else if !state_line.is_empty() {
        format!("{}\n{}\n{}", line1, line2, state_line)
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
        Cell::from("Q%F").style(
            Style::default()
                .fg(Color::LightRed)
                .add_modifier(Modifier::BOLD),
        ),
        Cell::from("Q%Y").style(
            Style::default()
                .fg(Color::LightGreen)
                .add_modifier(Modifier::BOLD),
        ),
        Cell::from("Q%P").style(
            Style::default()
                .fg(Color::LightYellow)
                .add_modifier(Modifier::BOLD),
        ),
        Cell::from("WAKER").style(
            Style::default()
                .fg(Color::Cyan)
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
            Cell::from(format!("{:.0}", q_full_pct)),
            Cell::from(format!("{:.0}", q_yield_pct)),
            Cell::from(format!("{:.0}", q_preempt_pct)),
            Cell::from(format!("{}", row.wakeup_source_pid)),
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
            Constraint::Length(4),  // Q%F
            Constraint::Length(4),  // Q%Y
            Constraint::Length(4),  // Q%P
            Constraint::Length(7),  // WAKER
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
    let ref_text = vec![
        Line::from(Span::styled(
            "═══ DASHBOARD MATRIX COLUMNS ═══",
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(Span::styled(
            "── Identity & Status ──",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(vec![
            Span::styled(
                "PPID    ",
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("Parent Process ID — groups threads by launcher"),
        ]),
        Line::from(vec![
            Span::styled(
                "PID     ",
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("Thread ID (per-thread, not process)"),
        ]),
        Line::from(vec![
            Span::styled(
                "ST      ",
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("Task status indicator:"),
        ]),
        Line::from(vec![
            Span::styled("          ●   ", Style::default().fg(Color::Green)),
            Span::raw("Alive — actively scheduled by BPF, has telemetry"),
        ]),
        Line::from(vec![
            Span::styled("          ●HOG", Style::default().fg(Color::Red)),
            Span::raw(" Hog — detected as CPU hog, squeeze penalty applied"),
        ]),
        Line::from(vec![
            Span::styled("          ●BG ", Style::default().fg(Color::DarkGray)),
            Span::raw("Background — low-priority noise task (short runtime, infrequent)"),
        ]),
        Line::from(vec![
            Span::styled("          ○   ", Style::default().fg(Color::DarkGray)),
            Span::raw("Idle — in sysinfo but no BPF telemetry (sleeping/suspended)"),
        ]),
        Line::from(vec![
            Span::styled("          ✗   ", Style::default().fg(Color::DarkGray)),
            Span::raw("Dead — exited since last TUI refresh, pending cleanup"),
        ]),
        Line::from(vec![
            Span::styled(
                "COMM    ",
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("Thread command name (first 15 chars)"),
        ]),
        Line::from(vec![
            Span::styled(
                "TGID    ",
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("Thread Group ID (process PID that owns this thread)"),
        ]),
        Line::from(""),
        Line::from(Span::styled(
            "── Timing (all values in µs unless noted) ──",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(vec![
            Span::styled(
                "VCSW    ",
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("Voluntary context switches this interval (high = GPU/IO)"),
        ]),
        Line::from(vec![
            Span::styled(
                "AVGRT   ",
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("EWMA avg runtime per run (µs) — how long task runs each time"),
        ]),
        Line::from(vec![
            Span::styled(
                "MAXRT   ",
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("Max runtime seen this TUI interval (µs)"),
        ]),
        Line::from(vec![
            Span::styled(
                "GAP     ",
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("Dispatch gap — time between consecutive runs (µs)"),
        ]),
        Line::from(vec![
            Span::styled(
                "JITTER  ",
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("Avg jitter: variance in inter-run gap (µs)"),
        ]),
        Line::from(vec![
            Span::styled(
                "WAIT    ",
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("Last wait duration before being scheduled (µs)"),
        ]),
        Line::from(vec![
            Span::styled(
                "RUNS/s  ",
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("Runs per second — scheduling frequency"),
        ]),
        Line::from(""),
        Line::from(Span::styled(
            "── Placement ──",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(vec![
            Span::styled(
                "CPU     ",
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("Last CPU core this task ran on (Cxx)"),
        ]),
        Line::from(vec![
            Span::styled(
                "MIGR/s  ",
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("CPU migrations per second — how often task moves cores"),
        ]),
        Line::from(""),
        Line::from(Span::styled(
            "── Callback Overhead (ns) ──",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(vec![
            Span::styled(
                "SEL     ",
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("select_cpu duration (ns) — gate cascade to find idle CPU"),
        ]),
        Line::from(vec![
            Span::styled(
                "ENQ     ",
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("enqueue duration (ns) — vtime calc + DSQ insert"),
        ]),
        Line::from(vec![
            Span::styled(
                "STOP    ",
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("stopping duration (ns) — EWMA + classify + staging"),
        ]),
        Line::from(vec![
            Span::styled(
                "RUN     ",
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("running duration (ns) — mailbox writes + arena telemetry"),
        ]),
        Line::from(""),
        Line::from(Span::styled(
            "── Gate Hit Distribution (%) ──",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(vec![
            Span::styled(
                "G1      ",
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("Gate 1: prev_cpu idle — best case, 0 migration"),
        ]),
        Line::from(vec![
            Span::styled(
                "G2      ",
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("Gate 1b: prev_cpu SMT sibling idle"),
        ]),
        Line::from(vec![
            Span::styled(
                "G1W     ",
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("Gate 1w: warm_cpus[0..2] idle — recently used cache"),
        ]),
        Line::from(vec![
            Span::styled(
                "G3      ",
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("Gate 3: LLC-wide idle scan — fallback, broader search"),
        ]),
        Line::from(vec![
            Span::styled(
                "G1P     ",
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("Gate 1p: prev_cpu physical idle, SMT busy"),
        ]),
        Line::from(vec![
            Span::styled(
                "G1C     ",
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("Gate 1c: warm CPU — cache-warm but not idle"),
        ]),
        Line::from(vec![
            Span::styled(
                "G1CP    ",
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("Gate 1cp: warm CPU physical — phys core idle, SMT busy"),
        ]),
        Line::from(vec![
            Span::styled(
                "G1D     ",
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("Gate 1d: dedicated core fallback"),
        ]),
        Line::from(vec![
            Span::styled(
                "G1WC    ",
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("Gate 1wc: warm+cache combined probe"),
        ]),
        Line::from(vec![
            Span::styled(
                "G5      ",
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("Gate 5 (tunnel): enqueue fallback — no direct dispatch"),
        ]),
        Line::from(""),
        Line::from(Span::styled(
            "── Quantum Completion (%) ──",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(vec![
            Span::styled(
                "Q%F     ",
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("Full: task exhausted its entire slice (preempted at expiry)"),
        ]),
        Line::from(vec![
            Span::styled(
                "Q%Y     ",
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("Yield: task voluntarily slept/yielded before slice expired"),
        ]),
        Line::from(vec![
            Span::styled(
                "Q%P     ",
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("Preempt: task was forcibly kicked mid-slice by higher priority"),
        ]),
        Line::from(""),
        Line::from(Span::styled(
            "── Wake Chain ──",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(vec![
            Span::styled(
                "WAKER   ",
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("PID of the task that last woke this task (0 = self-wake / kernel-woken)"),
        ]),
        Line::from(""),
        Line::from(Span::styled(
            "═══ DUMP / COPY ADDITIONAL FIELDS ═══",
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(Span::styled(
            "── Per-Callback Stopwatch (ns, in STOPWATCH line) ──",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(vec![
            Span::styled(
                "gate_cascade ",
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("select_cpu: full gate cascade duration"),
        ]),
        Line::from(vec![
            Span::styled(
                "idle_probe   ",
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("select_cpu: winning gate idle probe cost"),
        ]),
        Line::from(vec![
            Span::styled(
                "vtime_comp   ",
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("enqueue: vtime calculation + tier weighting overhead"),
        ]),
        Line::from(vec![
            Span::styled(
                "mbox         ",
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("running: per-CPU mailbox CL0 write burst"),
        ]),
        Line::from(vec![
            Span::styled(
                "ewma         ",
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("stopping: compute_ewma() call (every 64th stop)"),
        ]),
        Line::from(vec![
            Span::styled(
                "classify     ",
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("stopping: tier classify + DRR++ + squeeze fusion"),
        ]),
        Line::from(vec![
            Span::styled(
                "vtime_stg    ",
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("stopping: dsq_vtime bit packing + slice/vtime write"),
        ]),
        Line::from(vec![
            Span::styled(
                "warm         ",
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("stopping: warm CPU ring shift (only on migration)"),
        ]),
        Line::from(""),
        Line::from(Span::styled(
            "── QCOMP Line ──",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(vec![
            Span::styled(
                "Full         ",
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("%(count) — slice fully consumed. CPU-bound tasks."),
        ]),
        Line::from(vec![
            Span::styled(
                "Yield        ",
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("%(count) — voluntary yield. Cooperative/IO tasks."),
        ]),
        Line::from(vec![
            Span::styled(
                "Preempt      ",
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("%(count) — forcibly preempted. Contention indicator."),
        ]),
        Line::from(""),
        Line::from(Span::styled(
            "── WAKER Line ──",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(vec![
            Span::styled(
                "PID          ",
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("Waker thread PID"),
        ]),
        Line::from(vec![
            Span::styled(
                "TGID         ",
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("Waker process TGID (for cross-process chain detection)"),
        ]),
        Line::from(vec![
            Span::styled(
                "@CPU         ",
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("CPU the waker was running on when it woke this task"),
        ]),
        Line::from(""),
        Line::from(Span::styled(
            "── CPU_DIST Line ──",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from("Per-CPU run count histogram — top 8 cores by % usage."),
        Line::from("Identifies affinity patterns: 1 core = pinned, many = migrating."),
        Line::from(""),
        Line::from(Span::styled(
            "── Extended Detail Fields ──",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(vec![
            Span::styled(
                "DIRECT       ",
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("Direct dispatch count (bypassed DSQ, placed on CPU)"),
        ]),
        Line::from(vec![
            Span::styled(
                "DEFICIT      ",
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("DRR++ deficit (µs) — 0 for yielders, 9750 for bulk"),
        ]),
        Line::from(vec![
            Span::styled(
                "SUTIL        ",
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("Slice utilization % (actual_run / allocated_slice)"),
        ]),
        Line::from(vec![
            Span::styled(
                "LLC          ",
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("Last LLC (L3 cache) node this task ran on"),
        ]),
        Line::from(vec![
            Span::styled(
                "STREAK       ",
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("Consecutive runs on same CPU (locality indicator)"),
        ]),
        Line::from(vec![
            Span::styled(
                "CONF         ",
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("EWMA confidence x/y (recomp_count/total_runs)"),
        ]),
        Line::from(vec![
            Span::styled(
                "WHIST        ",
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("Wait histogram: <10µs/<100µs/<1ms/≥1ms bucket counts"),
        ]),
        Line::from(""),
        Line::from(Span::styled(
            "═══ CALLBACK PROFILE (system-wide) ═══",
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(vec![
            Span::styled(
                "stopping     ",
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("EWMA + classify + staging + warm history. Heaviest callback."),
        ]),
        Line::from(vec![
            Span::styled("  conf_skip  ", Style::default().fg(Color::DarkGray)),
            Span::raw("  98.4% of stops — confidence gate skips full EWMA recompute"),
        ]),
        Line::from(vec![
            Span::styled("  ewma       ", Style::default().fg(Color::DarkGray)),
            Span::raw("  ~1.6% — full EWMA recomputation (every 64th stop)"),
        ]),
        Line::from(vec![
            Span::styled("  ramp       ", Style::default().fg(Color::DarkGray)),
            Span::raw("  Stability ramp — new task building confidence"),
        ]),
        Line::from(vec![
            Span::styled("  miss       ", Style::default().fg(Color::DarkGray)),
            Span::raw("  Cold/self-seed — first runs with no history"),
        ]),
        Line::from(vec![
            Span::styled(
                "running      ",
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("Mailbox stamping + arena telemetry writes"),
        ]),
        Line::from(vec![
            Span::styled(
                "enqueue      ",
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("Vtime computation + scx_bpf_dsq_insert_vtime kfunc"),
        ]),
        Line::from(vec![
            Span::styled(
                "select_cpu   ",
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("Gate cascade probing idle CPUs for direct dispatch"),
        ]),
        Line::from(vec![
            Span::styled(
                "dispatch     ",
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("Per-LLC DSQ consume + cross-LLC steal + dsq_gen optimization"),
        ]),
        Line::from(""),
        Line::from(Span::styled(
            "═══ KEY BINDINGS ═══",
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(vec![
            Span::styled(
                "←/→  Tab/S-Tab",
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("  Switch tabs"),
        ]),
        Line::from(vec![
            Span::styled(
                "↑/↓  j/k      ",
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("  Scroll task list / navigate"),
        ]),
        Line::from(vec![
            Span::styled(
                "Enter          ",
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("  Open Task Inspector for selected task"),
        ]),
        Line::from(vec![
            Span::styled(
                "r/g/c/p/s      ",
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("  Sort: Runtime / Gate1% / CPU / PID / runs/Second"),
        ]),
        Line::from(vec![
            Span::styled(
                "a              ",
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("  Toggle all tasks vs BPF-tracked only"),
        ]),
        Line::from(vec![
            Span::styled(
                "c              ",
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("  Copy full dump to clipboard"),
        ]),
        Line::from(vec![
            Span::styled(
                "d              ",
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("  Dump to file (target/debug/tui_dump_*.txt)"),
        ]),
        Line::from(vec![
            Span::styled(
                "b              ",
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("  Run BenchLab benchmark iteration"),
        ]),
        Line::from(vec![
            Span::styled(
                "q / Esc        ",
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("  Quit scx_cake"),
        ]),
    ];

    let paragraph = Paragraph::new(ref_text)
        .block(
            Block::default()
                .title(" Reference Guide — Column Definitions ")
                .title_style(
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD),
                )
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Blue))
                .border_type(BorderType::Rounded),
        )
        .wrap(Wrap { trim: false })
        .scroll((0, 0));

    frame.render_widget(paragraph, area);
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

/// Run a core-to-core latency benchmark using atomic ping-pong.
/// Hot loop uses only `wrapping_add(1)` — no multiply or checked add —
/// so debug builds don't inflate measurements with overflow checks.
/// Runs 3 attempts per pair with warmup, takes the minimum.
fn run_core_latency_bench(nr_cpus: usize) -> Vec<Vec<f64>> {
    let mut matrix = vec![vec![0.0f64; nr_cpus]; nr_cpus];
    const ITERATIONS: u64 = 5000;
    const WARMUP: u64 = 500;
    const RUNS: usize = 3;

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
                                    app.set_status("Folded all PPID groups".into());
                                } else {
                                    app.collapsed_ppids.clear();
                                    app.set_status("Unfolded all PPID groups".into());
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
                    loop {
                        match f.read_exact(&mut buf) {
                            Ok(()) => {}
                            Err(_) => break, // EOF or error — all records read
                        }
                        let rec: crate::bpf_intf::cake_iter_record =
                            unsafe { std::ptr::read_unaligned(buf.as_ptr() as *const _) };

                        let pid = rec.telemetry.pid_inner;
                        let ppid = rec.ppid;
                        let packed = rec.packed_info;
                        let tier = (packed >> 28) & 0x03;
                        let is_hog = (packed >> 27) & 1 != 0;
                        let is_bg = (packed >> 22) & 1 != 0;

                        if pid == 0 || tier > 3 {
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

                        // avg_runtime_us and deficit_us now directly in cake_iter_record
                        let avg_runtime_us = rec.avg_runtime_us as u32;
                        let deficit_us: u32 = rec.deficit_us as u32;

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
                                tier: tier as u8,
                                avg_runtime_us,
                                deficit_us,
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
                                ewma_recomp_count: rec.telemetry.ewma_recomp_count,
                                is_hog,
                                is_bg,
                                ppid,
                                gate_cascade_ns: rec.telemetry.gate_cascade_ns,
                                idle_probe_ns: rec.telemetry.idle_probe_ns,
                                vtime_compute_ns: rec.telemetry.vtime_compute_ns,
                                mbox_staging_ns: rec.telemetry.mbox_staging_ns,
                                ewma_compute_ns: rec.telemetry.ewma_compute_ns,
                                classify_ns: rec.telemetry.classify_ns,
                                vtime_staging_ns: rec.telemetry.vtime_staging_ns,
                                warm_history_ns: rec.telemetry.warm_history_ns,
                                quantum_full_count: rec.telemetry.quantum_full_count,
                                quantum_yield_count: rec.telemetry.quantum_yield_count,
                                quantum_preempt_count: rec.telemetry.quantum_preempt_count,
                                waker_cpu: rec.telemetry.waker_cpu,
                                waker_tgid: rec.telemetry.waker_tgid,
                                cpu_run_count: rec.telemetry.cpu_run_count,
                                is_game_member: false,
                            });

                        // Update dynamic row elements
                        row.tier = tier as u8;
                        row.avg_runtime_us = avg_runtime_us;
                        row.deficit_us = deficit_us;
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
                        row.ewma_recomp_count = rec.telemetry.ewma_recomp_count;
                        row.is_hog = is_hog;
                        row.is_bg = is_bg;
                        row.is_game_member = app.tracked_game_tgid > 0
                            && (row.tgid == app.tracked_game_tgid
                                || (row.ppid > 0 && row.ppid == app.tracked_game_ppid));
                        row.ppid = ppid;
                        row.gate_cascade_ns = rec.telemetry.gate_cascade_ns;
                        row.idle_probe_ns = rec.telemetry.idle_probe_ns;
                        row.vtime_compute_ns = rec.telemetry.vtime_compute_ns;
                        row.mbox_staging_ns = rec.telemetry.mbox_staging_ns;
                        row.ewma_compute_ns = rec.telemetry.ewma_compute_ns;
                        row.classify_ns = rec.telemetry.classify_ns;
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
            //
            // GATE: Minimum 5 threads at PPID-family level.
            //   Prevents idle browsers (1-3 yield-active threads) from qualifying.
            //   Games under Proton easily satisfy: game.exe + wineserver +
            //   winedevice + render workers = 5+ threads always.
            //   Native Linux games also easily satisfy (main + audio + IO + render).
            //
            // CONFIDENCE THROTTLE (Rule 40): After GAME_CONFIDENCE_THRESHOLD
            //   stable polls with the same PPID winning, reduce detection sweep
            //   to every GAME_CONFIDENCE_SKIP-th poll (~2s effective instead of 500ms).
            //   Resets immediately on game exit or PPID switch.
            const GAME_MIN_THREADS: usize = 5;
            const GAME_CONFIDENCE_THRESHOLD: u32 = 20; // 20 × 500ms = 10s stable
            const GAME_CONFIDENCE_SKIP: u32 = 4; // check every 4th poll when confident

            // Game exit detection fires before the throttle check so a dead game
            // always clears on the very next poll, regardless of confidence state.
            if app.tracked_game_tgid > 0 {
                let proc_path = format!("/proc/{}", app.tracked_game_tgid);
                if !std::path::Path::new(&proc_path).exists() {
                    app.tracked_game_tgid = 0;
                    app.tracked_game_ppid = 0;
                    app.game_thread_count = 0;
                    app.game_name.clear();
                    app.game_challenger_ppid = 0;
                    app.game_challenger_since = None;
                    app.game_stable_polls = 0;
                    app.game_skip_counter = 0;
                }
            }

            // Confidence throttle: if we've been stable long enough, skip
            // the full PPID aggregation sweep on most polls.
            let should_skip_sweep = app.game_stable_polls >= GAME_CONFIDENCE_THRESHOLD
                && app.game_skip_counter > 0
                && app.game_skip_counter < GAME_CONFIDENCE_SKIP;

            if should_skip_sweep {
                // Confident path: reuse existing winner, just bump skip counter.
                // BPF write still happens below unconditionally.
                app.game_skip_counter += 1;
            } else {
                // Full detection sweep.
                app.game_skip_counter = 0;

                // --- Three-phase game detection ---
                // Priority: Steam (100) → Wine .exe (90) → yield fallback (50)
                //
                // Phase 1 + 2 scan qualifying PPIDs (≥GAME_MIN_THREADS threads with
                // any activity). No yield threshold required for Steam/.exe —
                // the binary signal is definitive on its own.
                //
                // Phase 3 (yield fallback) retains the 64-yield + 5-thread dual gate
                // for unrecognised native games: guards against browsers, IDEs, etc.

                // Reusable Steam env probe (cold path, ~1 file read per PPID).
                let has_steam_env = |pid: u32| -> bool {
                    if let Ok(env) = std::fs::read(format!("/proc/{}/environ", pid)) {
                        env.split(|&b| b == 0)
                            .filter_map(|kv| std::str::from_utf8(kv).ok())
                            .any(|s| s.starts_with("SteamGameId=") || s.starts_with("STEAM_GAME="))
                    } else {
                        false
                    }
                };

                // Reusable .exe probe (cold path, ~1 file read per PPID).
                let has_exe_cmdline = |pid: u32| -> bool {
                    if let Ok(cmdline) = std::fs::read(format!("/proc/{}/cmdline", pid)) {
                        cmdline
                            .split(|&b| b == 0)
                            .filter_map(|arg| std::str::from_utf8(arg).ok())
                            .any(|s| s.to_lowercase().ends_with(".exe"))
                    } else {
                        false
                    }
                };

                // Aggregate thread counts by PPID for Phase 1 + 2 thread-count gate.
                let mut ppid_data: std::collections::HashMap<u32, usize> =
                    std::collections::HashMap::new(); // ppid → thread_count
                for (_pid, row) in app.task_rows.iter() {
                    if row.status == TaskStatus::Dead || row.ppid == 0 {
                        continue;
                    }
                    *ppid_data.entry(row.ppid).or_insert(0) += 1;
                }

                // Phase 1: Steam scan — highest priority, no yield threshold.
                // Covers: Proton games, native Linux Steam games, Battle.net/Epic via Steam.
                let mut steam_ppid: u32 = 0;
                for (&ppid, &thread_count) in &ppid_data {
                    if thread_count >= GAME_MIN_THREADS && has_steam_env(ppid) {
                        // Validate: skip the Steam launcher's own process group.
                        // Find any thread under this PPID and check if its cmdline
                        // is a real game binary (not "steam" or "steamwebhelper").
                        // Inlined here because resolve_game closure is defined later.
                        let has_game_binary = app.task_rows.values().any(|row| {
                            row.ppid == ppid && {
                                let comm_lc = row.comm.to_lowercase();
                                let is_steam_infra = comm_lc.contains("steam")
                                    || comm_lc.contains("steamwebhelper")
                                    || comm_lc.contains("pressure-vessel");
                                !is_steam_infra && (comm_lc.ends_with(".exe") || row.tgid == ppid)
                            }
                        });
                        if has_game_binary {
                            steam_ppid = ppid;
                            break;
                        }
                        // Launcher group only — keep scanning.
                    }
                }

                // Phase 2: .exe scan — Wine/Proton without Steam env (Heroic, Lutris, etc.).
                let mut exe_ppid: u32 = 0;
                if steam_ppid == 0 {
                    for (&ppid, &thread_count) in &ppid_data {
                        if thread_count >= GAME_MIN_THREADS && has_exe_cmdline(ppid) {
                            exe_ppid = ppid;
                            break;
                        }
                    }
                }

                // Resolve winning PPID: Steam wins → .exe wins → no game.
                // Phase 3 (yield fallback) removed: yield-heavy non-games (Brave, Chrome,
                // IDEs, Electron apps) too easily exceed the threshold and false-positive.
                // If it has no Steam env and no .exe process, it is not a game.
                let new_game_ppid = if steam_ppid > 0 {
                    steam_ppid
                } else if exe_ppid > 0 {
                    exe_ppid
                } else {
                    0
                };

                // Helper: resolve best TGID + name for a given PPID (cold path only).
                // Selects the TGID with the highest avg_runtime_us — the game's main/render
                // loop runs for milliseconds; Windows service exes (Services.exe, pluginhost,
                // winedevice) run for microseconds and are filtered by the blocklist.
                let resolve_game = |ppid: u32,
                                    rows: &HashMap<u32, TaskTelemetryRow>|
                 -> (u32, String) {
                    // Known Windows infrastructure exes that appear in Proton/Wine trees
                    // but are never the actual game. Skip these when selecting game TGID.
                    const WIN_INFRA_EXES: &[&str] = &[
                        "services",
                        "pluginhost",
                        "winedevice",
                        "rpcss",
                        "svchost",
                        "explorer",
                        "wineboot",
                        "start",
                        "conhost",
                        "dxvk-cache-me",
                        "crashhandler",
                        "unitycrashhandler64",
                        "werfault",
                        "ngen",
                        "mscorsvw",
                        "gamebarfullscreensession",
                        "gamebarpresencewriter",
                        "rundll32",
                        "regsvr32",
                        "winedbg",
                        "cmd",
                    ];

                    // Build per-TGID max avg_runtime. The game thread always wins —
                    // render frames take ms, infra processes take µs.
                    let mut tgid_max_rt: std::collections::HashMap<u32, u32> =
                        std::collections::HashMap::new();
                    for (_pid, row) in rows.iter() {
                        if row.ppid == ppid && row.avg_runtime_us > 0 {
                            let tgid = if row.tgid > 0 { row.tgid } else { row.pid };
                            let entry = tgid_max_rt.entry(tgid).or_insert(0);
                            if row.avg_runtime_us > *entry {
                                *entry = row.avg_runtime_us;
                            }
                        }
                    }

                    // Sort TGIDs by max runtime descending; skip Windows infra exes.
                    let mut ranked: Vec<(u32, u32)> = tgid_max_rt.into_iter().collect();
                    ranked.sort_unstable_by(|a, b| b.1.cmp(&a.1));

                    let mut game_tgid: u32 = ppid; // fallback
                    'outer: for (tgid, _rt) in &ranked {
                        // Read cmdline to get exe name (cold path).
                        if let Ok(cmdline) = std::fs::read(format!("/proc/{}/cmdline", tgid)) {
                            for arg in cmdline.split(|&b| b == 0) {
                                if let Ok(s) = std::str::from_utf8(arg) {
                                    let low = s.to_lowercase();
                                    if low.ends_with(".exe") {
                                        let basename = s.rsplit(['\\', '/']).next().unwrap_or(s);
                                        let bare = basename
                                            .trim_end_matches(".exe")
                                            .trim_end_matches(".EXE")
                                            .to_lowercase();
                                        if WIN_INFRA_EXES.iter().any(|&b| bare == b) {
                                            continue 'outer; // skip infra exe
                                        }
                                        game_tgid = *tgid;
                                        break 'outer;
                                    }
                                }
                            }
                        }
                        // No .exe in cmdline — could be native, take it as fallback.
                        if game_tgid == ppid {
                            game_tgid = *tgid;
                        }
                    }

                    // Read display name: prefer .exe basename, fall back to comm.
                    let name = {
                        let mut n = String::from("unknown");
                        if let Ok(cmdline) = std::fs::read(format!("/proc/{}/cmdline", game_tgid)) {
                            for arg in cmdline.split(|&b| b == 0) {
                                if let Ok(s) = std::str::from_utf8(arg) {
                                    if s.to_lowercase().ends_with(".exe") {
                                        let basename = s.rsplit(['\\', '/']).next().unwrap_or(s);
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

                // Confidence for the candidate comes from the winning detection phase.
                // Phase 1 (Steam) → 100, Phase 2 (.exe) → 90, no game → 0.
                let new_game_confidence: u8 = if new_game_ppid == 0 {
                    0
                } else if new_game_ppid == steam_ppid {
                    100
                } else {
                    90 // exe match
                };

                // Holdoff by confidence tier:
                //   100 (Steam) → instant lock
                //    90 (.exe)  → 5s holdoff (Wine apps nearly always games, but brief wait)
                let holdoff_for_conf = |conf: u8| -> u64 {
                    if conf >= 100 {
                        0
                    } else {
                        5
                    }
                };

                // --- Hysteresis State Machine ---
                // Challenger can only displace a locked game if challenger_confidence >=
                // locked_game_confidence. Steam (100) always beats .exe (90).

                if app.tracked_game_tgid == 0 {
                    // No game locked — try to lock now.
                    if new_game_confidence > 0 {
                        let holdoff = holdoff_for_conf(new_game_confidence);
                        if holdoff == 0 || app.game_challenger_ppid == new_game_ppid {
                            // Either instant (Steam) or challenger already waited enough.
                            let accept = holdoff == 0
                                || app
                                    .game_challenger_since
                                    .map_or(false, |s| s.elapsed() >= Duration::from_secs(holdoff));
                            if accept {
                                let (tgid, name) = resolve_game(new_game_ppid, &app.task_rows);
                                app.tracked_game_tgid = tgid;
                                app.tracked_game_ppid = new_game_ppid;
                                app.game_thread_count =
                                    ppid_data.get(&new_game_ppid).copied().unwrap_or(0);
                                app.game_name = name;
                                app.game_confidence = new_game_confidence;
                                app.game_challenger_ppid = 0;
                                app.game_challenger_since = None;
                                app.game_stable_polls = 1;
                            }
                        } else {
                            // Start or continue holdoff timer.
                            if app.game_challenger_ppid != new_game_ppid {
                                app.game_challenger_ppid = new_game_ppid;
                                app.game_challenger_since = Some(Instant::now());
                            }
                        }
                    }
                } else if new_game_ppid == app.tracked_game_ppid {
                    // Same game family still winning — update thread count, reset challenger.
                    app.game_thread_count = ppid_data.get(&new_game_ppid).copied().unwrap_or(0);
                    app.game_challenger_ppid = 0;
                    app.game_challenger_since = None;
                    app.game_stable_polls = app.game_stable_polls.saturating_add(1);
                } else if new_game_confidence > 0 && new_game_confidence > app.game_confidence {
                    // Only strictly higher confidence can contest the incumbent.
                    // Equal confidence (e.g. two Steam-env PPIDs) is irrelevant — the locked
                    // game stays sticky until its /proc entry dies (checked above).
                    // This prevents HashMap iteration non-determinism from resetting stable_polls
                    // when the Steam launcher and game.exe both have SteamGameId in env.
                    app.game_stable_polls = 0;
                    if app.game_challenger_ppid != new_game_ppid {
                        app.game_challenger_ppid = new_game_ppid;
                        app.game_challenger_since = Some(Instant::now());
                    } else if let Some(since) = app.game_challenger_since {
                        let holdoff = holdoff_for_conf(new_game_confidence);
                        if since.elapsed() >= Duration::from_secs(holdoff) {
                            let (tgid, name) = resolve_game(new_game_ppid, &app.task_rows);
                            app.tracked_game_tgid = tgid;
                            app.tracked_game_ppid = new_game_ppid;
                            app.game_thread_count =
                                ppid_data.get(&new_game_ppid).copied().unwrap_or(0);
                            app.game_name = name;
                            app.game_confidence = new_game_confidence;
                            app.game_challenger_ppid = 0;
                            app.game_challenger_since = None;
                            app.game_stable_polls = 1;
                        }
                    }
                } else {
                    // No qualifying candidate or lower-confidence challenger — hold current.
                    app.game_challenger_ppid = 0;
                    app.game_challenger_since = None;
                    app.game_stable_polls = 0;
                }
            }

            // Write game state to BPF BSS — drives all scheduling decisions.
            // game_ppid is the primary family signal (includes wineserver + siblings).
            // game_tgid written for display/existence checks.
            // sched_state drives HOG/bg/Gate1P/quantum policy.
            if let Some(bss) = &mut skel.maps.bss_data {
                bss.game_tgid = app.tracked_game_tgid;
                bss.game_ppid = app.tracked_game_ppid;
                bss.game_confidence = app.game_confidence;
                // --- State machine: GAMING > COMPILATION > IDLE ---
                const CAKE_STATE_IDLE: u8 = 0;
                const CAKE_STATE_COMPILATION: u8 = 1;
                const CAKE_STATE_GAMING: u8 = 2;

                let new_state = if app.tracked_game_tgid > 0 {
                    CAKE_STATE_GAMING
                } else {
                    // Detect active compiler processes: avg_runtime >= 8ms AND
                    // comm matches a known compiler binary. Require >=2 to avoid
                    // false positives from a single transient ld/as invocation.
                    const COMPILE_COMMS: &[&str] = &[
                        "cc1", "rustc", "clang", "clang++", "ld", "ld.lld", "lld", "ninja",
                        "cmake", "as", "gcc", "g++", "link",
                    ];
                    let compile_count = app
                        .task_rows
                        .values()
                        .filter(|r| {
                            r.status != TaskStatus::Dead
                                && r.avg_runtime_us >= 8000
                                && COMPILE_COMMS.iter().any(|&c| r.comm.contains(c))
                        })
                        .count();
                    app.compile_task_count = compile_count;
                    if compile_count >= 2 {
                        CAKE_STATE_COMPILATION
                    } else {
                        CAKE_STATE_IDLE
                    }
                };
                app.sched_state = new_state;
                bss.sched_state = new_state as u32;
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
            // Pin game-family rows to the top, preserving the user's sort order within
            // each group. Uses stable_sort so relative order is unchanged.
            if app.tracked_game_tgid > 0 {
                sorted_pids.sort_by(|a, b| {
                    let gm_a = app.task_rows.get(a).map_or(false, |r| r.is_game_member);
                    let gm_b = app.task_rows.get(b).map_or(false, |r| r.is_game_member);
                    // true sorts before false (1 > 0), so game members come first.
                    gm_b.cmp(&gm_a)
                });
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

            last_tick = Instant::now();
        }
    }

    restore_terminal()?;
    Ok(())
}
