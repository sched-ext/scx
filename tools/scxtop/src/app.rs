// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use crate::available_kprobe_events;
use crate::available_perf_events;
use crate::bpf_intf;
use crate::bpf_prog_data::{BpfProgData, BpfProgStats};
use crate::bpf_skel::BpfSkel;
use crate::bpf_stats::BpfStats;
use crate::columns::{
    get_bpf_program_columns, get_perf_top_columns, get_perf_top_columns_no_bpf,
    get_process_columns, get_process_columns_no_bpf, get_thread_columns, get_thread_columns_no_bpf,
    Columns,
};
use crate::config::get_config_path;
use crate::config::Config;
use crate::get_default_events;
use crate::render::bpf_programs::{ProgramDetailParams, ProgramsListParams};
use crate::render::scheduler::{SchedulerStatsParams, SchedulerViewParams};
use crate::render::{
    BpfProgramRenderer, MemoryRenderer, NetworkRenderer, ProcessRenderer, SchedulerRenderer,
};
use crate::search;
use crate::symbol_data::SymbolData;
use crate::util::{
    check_perf_capability, default_scxtop_sched_ext_stats, format_hz, read_file_string,
    sanitize_nbsp, u32_to_i32,
};
use crate::AppState;
use crate::AppTheme;
use crate::ComponentViewState;
use crate::CpuData;
use crate::CpuStatTracker;
use crate::EventData;
use crate::FilterItem;
use crate::FilteredState;
use crate::KprobeEvent;
use crate::LlcData;
use crate::MemStatSnapshot;
use crate::NetworkStatSnapshot;
use crate::NodeData;
use crate::PerfEvent;
use crate::PerfettoTraceManager;
use crate::ProcData;
use crate::ProfilingEvent;
use crate::ThreadData;
use crate::VecStats;
use crate::ViewState;
use crate::APP;
use crate::LICENSE;
use crate::SCHED_NAME_PATH;
use crate::{
    Action, CpuhpEnterAction, CpuhpExitAction, ExecAction, ExitAction, ForkAction, GpuMemAction,
    HwPressureAction, IPIAction, KprobeAction, MangoAppAction, SchedCpuPerfSetAction,
    SchedHangAction, SchedMigrateTaskAction, SchedSwitchAction, SchedWakeupAction,
    SchedWakingAction, SoftIRQAction, TraceStartedAction, TraceStoppedAction,
    UpdateColVisibilityAction, WaitAction,
};
use scx_utils::perf;

use anyhow::{bail, Result};
use glob::glob;
use libbpf_rs::Link;
use libbpf_rs::ProgramInput;
use num_format::{SystemLocale, ToFormattedString};
use procfs::process::all_processes;
use ratatui::prelude::Constraint;
use ratatui::{
    layout::{Alignment, Direction, Layout, Margin, Rect},
    prelude::Stylize,
    style::{Color, Modifier, Style},
    symbols::bar::{NINE_LEVELS, THREE_LEVELS},
    symbols::line::THICK,
    text::{Line, Span},
    widgets::{
        Axis, Bar, BarChart, BarGroup, Block, BorderType, Borders, Cell, Chart, Clear, Dataset,
        Gauge, LineGauge, Paragraph, RenderDirection, Row, Scrollbar, ScrollbarOrientation,
        ScrollbarState, Sparkline, Table, TableState, Wrap,
    },
    Frame,
};
use regex::Regex;
use scx_stats::prelude::StatsClient;
use scx_utils::misc::read_from_file;
use scx_utils::scx_enums;
use scx_utils::Topology;
use serde_json::Value as JsonValue;
use sysinfo::System;
use tokio::sync::mpsc::UnboundedSender;
use tokio::sync::Mutex as TokioMutex;

use std::collections::{btree_map::Entry, BTreeMap, VecDeque};
use std::os::fd::{AsFd, AsRawFd};
use std::path::Path;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex, RwLock};

/// App is the struct for scxtop application state.
pub struct App<'a> {
    config: Config,
    hw_pressure: bool,
    localize: bool,
    locale: SystemLocale,
    stats_client: Option<Arc<TokioMutex<StatsClient>>>,
    cpu_stat_tracker: Arc<RwLock<CpuStatTracker>>,
    sched_stats_raw: String,
    sys: Arc<StdMutex<System>>,
    /// CPU frequency refresh interval shared with background thread (in milliseconds)
    cpu_freq_refresh_interval_ms: Arc<AtomicU64>,
    mem_info: MemStatSnapshot,
    memory_view_state: ComponentViewState,
    network_view_state: ComponentViewState,

    scheduler: String,
    max_cpu_events: usize,
    max_sched_events: usize,
    state: AppState,
    prev_state: AppState,
    view_state: ViewState,
    pub should_quit: Arc<AtomicBool>,
    pub action_tx: UnboundedSender<Action>,
    pub skel: Option<BpfSkel<'a>>,
    topo: Topology,
    large_core_count: bool,
    collect_cpu_freq: bool,
    collect_uncore_freq: bool,
    layered_enabled: bool,

    process_columns: Columns<i32, ProcData>,
    thread_columns: Columns<i32, ThreadData>,
    perf_top_columns: Columns<String, crate::symbol_data::SymbolSample>,
    selected_process: Option<i32>,
    in_thread_view: bool,

    cpu_data: BTreeMap<usize, CpuData>,
    llc_data: BTreeMap<usize, LlcData>,
    node_data: BTreeMap<usize, NodeData>,
    dsq_data: BTreeMap<u64, EventData>,
    proc_data: BTreeMap<i32, ProcData>,
    network_stats: NetworkStatSnapshot,

    // BPF program statistics
    bpf_program_stats: BpfProgStats,
    bpf_program_columns: Columns<u32, BpfProgData>,
    bpf_program_table_state: TableState,
    selected_bpf_program_id: Option<u32>,
    cached_bpf_symbol_info: Option<crate::bpf_prog_data::BpfSymbolInfo>,
    filtered_bpf_programs: Vec<(u32, crate::bpf_prog_data::BpfProgData)>,
    bpf_stats_fd: Option<i32>,

    // System-wide CPU time tracking for overhead calculation
    total_cpu_time_ns: u64,
    prev_total_cpu_time_ns: u64,
    prev_bpf_total_runtime_ns: u64,
    bpf_overhead_history: VecDeque<f64>,
    terminal_width: u16,

    // BPF program detail view perf data
    #[allow(dead_code)]
    bpf_program_symbol_data: SymbolData,
    bpf_program_symbol_table_state: TableState,
    bpf_program_filtered_symbols: Vec<crate::symbol_data::SymbolSample>,

    // Perf sampling control
    bpf_perf_sampling_active: bool,

    // Event related
    active_event: ProfilingEvent,
    active_hw_event_id: usize,
    active_prof_events: BTreeMap<usize, ProfilingEvent>,
    available_events: Vec<ProfilingEvent>,
    event_input_buffer: String,
    perf_events: Vec<String>,
    kprobe_events: Vec<String>,
    kprobe_links: Vec<Link>,

    filtered_state: Arc<StdMutex<FilteredState>>,
    filtering: bool,

    // stats from scxtop's bpf side
    bpf_stats: BpfStats,
    scx_stats: bpf_intf::scxtop_sched_ext_stats,

    // power monitoring
    power_snapshot: crate::PowerSnapshot,
    power_collector: crate::PowerDataCollector,

    // layout related
    events_list_size: u16,

    // trace related
    trace_manager: PerfettoTraceManager,
    trace_start: u64,
    prev_bpf_sample_rate: u32,
    process_id: i32,
    prev_process_id: i32,
    trace_links: Vec<Link>,

    // mangoapp related
    last_mangoapp_action: Option<MangoAppAction>,
    frames_since_update: u64,
    max_fps: u16,

    // perf top related
    symbol_data: crate::symbol_data::SymbolData,
    perf_sample_rate: u32,
    perf_links: Vec<Link>,
    selected_symbol_index: usize,
    current_sampling_event: Option<ProfilingEvent>,
    perf_top_table_state: TableState,
    perf_top_filtered_symbols: Vec<(String, crate::symbol_data::SymbolSample)>,
    has_perf_cap: bool,

    // capability warnings for non-root users
    capability_warnings: Vec<String>,
}

impl<'a> App<'a> {
    /// Creates a new application.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        config: Config,
        scheduler: String,
        max_cpu_events: usize,
        process_id: i32,
        layered_enabled: bool,
        action_tx: UnboundedSender<Action>,
        skel: BpfSkel<'a>,
    ) -> Result<Self> {
        let topo = Topology::new()?;
        let mut cpu_data = BTreeMap::new();
        let mut llc_data = BTreeMap::new();
        let mut node_data = BTreeMap::new();
        let mut proc_data = BTreeMap::new();
        let cpu_stat_tracker = Arc::new(RwLock::new(CpuStatTracker::default()));
        let mut mem_info = MemStatSnapshot::default();
        mem_info.update()?;

        let active_event = ProfilingEvent::from_str_args(
            &config.default_profiling_event(),
            Some(cpu_stat_tracker.clone()),
        )?;

        let mut active_prof_events = BTreeMap::new();
        let mut default_events = get_default_events(cpu_stat_tracker.clone());

        let config_perf_events = PerfEvent::from_config(&config)?;

        default_events.extend(
            config_perf_events
                .iter()
                .cloned()
                .map(ProfilingEvent::Perf)
                .collect::<Vec<_>>(),
        );

        let default_events_str: Vec<&str> = default_events
            .iter()
            .map(|event| event.event_name())
            .collect();

        for cpu in topo.all_cpus.values() {
            let event = active_event.initialize_for_cpu(cpu.id, process_id)?;
            active_prof_events.insert(cpu.id, event);
            let mut data =
                CpuData::new(cpu.id, cpu.core_id, cpu.llc_id, cpu.node_id, max_cpu_events);
            data.initialize_events(&default_events_str);
            cpu_data.insert(cpu.id, data);
        }
        for llc in topo.all_llcs.values() {
            let mut data = LlcData::new(llc.id, llc.node_id, llc.all_cpus.len(), max_cpu_events);
            data.initialize_events(&default_events_str);
            llc_data.insert(llc.id, data);
        }
        for node in topo.nodes.values() {
            let mut data = NodeData::new(node.id, node.all_cpus.len(), max_cpu_events);
            data.initialize_events(&default_events_str);
            node_data.insert(node.id, data);
        }

        for process in all_processes()?.flatten() {
            if let Ok(data) = ProcData::new(&process, max_cpu_events) {
                proc_data.insert(process.pid, data);
            }
        }

        let mut initial_perf_events_list: Vec<String> = available_perf_events()?
            .iter()
            .flat_map(|(subsystem, events)| {
                events
                    .iter()
                    .map(|event| format!("{}:{}", subsystem.clone(), event.clone()))
            })
            .collect();
        initial_perf_events_list.sort();

        let mut initial_kprobe_events_list = available_kprobe_events()?;
        initial_kprobe_events_list.sort();

        let filtered_state = Arc::new(StdMutex::new(FilteredState::default()));

        let mut stats_client = StatsClient::new();
        let stats_socket_path = config.stats_socket_path();
        if !stats_socket_path.is_empty() {
            stats_client = stats_client.set_path(stats_socket_path);
        }
        stats_client = stats_client.connect(None).unwrap_or_else(|_| {
            let mut client = StatsClient::new();
            if !stats_socket_path.is_empty() {
                client = client.set_path(stats_socket_path);
            }
            client
        });
        let stats_client = Some(Arc::new(TokioMutex::new(stats_client)));
        let sample_rate = skel.maps.data_data.as_ref().unwrap().sample_rate;
        let trace_file_prefix = config.trace_file_prefix().to_string();
        let trace_manager = PerfettoTraceManager::new(trace_file_prefix, None);

        // There isn't a 'is_loaded' method on a prog in libbpf-rs so do the next best thing and
        // try to infer from the fd
        let hw_pressure = skel.progs.on_hw_pressure_update.as_fd().as_raw_fd() > 0;

        // Create System object and spawn background thread for CPU frequency refresh
        let sys = Arc::new(StdMutex::new(System::new_all()));
        let sys_clone = sys.clone();
        let tick_rate_ms = config.tick_rate_ms();
        let should_quit = Arc::new(AtomicBool::new(false));
        let should_quit_clone = should_quit.clone();

        // Create shared atomic for CPU frequency refresh interval
        let cpu_freq_refresh_interval_ms = Arc::new(AtomicU64::new(tick_rate_ms as u64));
        let interval_clone = cpu_freq_refresh_interval_ms.clone();

        // Spawn background thread to refresh CPU frequencies at the same rate as tick_rate
        // This moves the expensive sysfs reads off the main thread
        std::thread::spawn(move || {
            while !should_quit_clone.load(std::sync::atomic::Ordering::Relaxed) {
                if let Ok(mut system_guard) = sys_clone.lock() {
                    system_guard.refresh_cpu_frequency();
                }
                let interval_ms = interval_clone.load(std::sync::atomic::Ordering::Relaxed);
                std::thread::sleep(std::time::Duration::from_millis(interval_ms));
            }
        });

        let mut app = Self {
            config,
            localize: true,
            hw_pressure,
            locale: SystemLocale::default()?,
            stats_client,
            cpu_stat_tracker,
            sched_stats_raw: "".to_string(),
            sys,
            cpu_freq_refresh_interval_ms,
            mem_info,
            memory_view_state: ComponentViewState::Default,
            network_view_state: ComponentViewState::Default,
            scheduler,
            max_cpu_events,
            max_sched_events: max_cpu_events,
            state: AppState::Default,
            view_state: ViewState::BarChart,
            prev_state: AppState::Default,
            should_quit,
            action_tx,
            skel: Some(skel),
            large_core_count: topo.all_cpus.len() >= 128,
            topo,
            collect_cpu_freq: true,
            collect_uncore_freq: true,
            layered_enabled,
            process_columns: Columns::new(get_process_columns()),
            thread_columns: Columns::new(get_thread_columns()),
            perf_top_columns: Columns::new(get_perf_top_columns(layered_enabled)),
            has_perf_cap: check_perf_capability(),
            selected_process: None,
            in_thread_view: false,
            cpu_data,
            llc_data,
            node_data,
            dsq_data: BTreeMap::new(),
            proc_data,
            network_stats: NetworkStatSnapshot::new(100),

            // BPF program statistics
            bpf_program_stats: BpfProgStats::new(),
            bpf_program_columns: Columns::new(get_bpf_program_columns()),
            bpf_program_table_state: TableState::default(),
            selected_bpf_program_id: None,
            cached_bpf_symbol_info: None,
            filtered_bpf_programs: Vec::new(),
            bpf_stats_fd: None,

            // System-wide CPU time tracking
            total_cpu_time_ns: 0,
            prev_total_cpu_time_ns: 0,
            prev_bpf_total_runtime_ns: 0,
            bpf_overhead_history: VecDeque::new(),
            terminal_width: 80, // Default value, will be updated on first render

            // BPF program detail view perf data
            bpf_program_symbol_data: SymbolData::new(),
            bpf_program_symbol_table_state: TableState::default(),
            bpf_program_filtered_symbols: Vec::new(),

            // Perf sampling control
            bpf_perf_sampling_active: false,

            active_hw_event_id: 0,
            active_event,
            active_prof_events,
            available_events: default_events,
            event_input_buffer: String::new(),
            perf_events: initial_perf_events_list,
            kprobe_events: initial_kprobe_events_list,
            kprobe_links: Vec::new(),
            filtered_state,
            filtering: false,
            events_list_size: 1,
            prev_bpf_sample_rate: sample_rate,
            trace_start: 0,
            trace_manager,
            bpf_stats: Default::default(),
            scx_stats: default_scxtop_sched_ext_stats(),
            power_snapshot: crate::PowerSnapshot::new(),
            power_collector: crate::PowerDataCollector::new().unwrap_or_else(|e| {
                log::warn!("Failed to initialize power collector with MSR support: {e}");
                crate::PowerDataCollector::default()
            }),
            process_id,
            prev_process_id: -1,
            trace_links: vec![],
            last_mangoapp_action: None,
            frames_since_update: 0,
            max_fps: 1,
            perf_sample_rate: 1_000_000, // Default perf sample rate (1 million cycles)
            symbol_data: crate::symbol_data::SymbolData::new(),
            perf_links: Vec::new(),
            selected_symbol_index: 0,
            current_sampling_event: None,
            perf_top_table_state: TableState::default(),
            perf_top_filtered_symbols: Vec::new(),
            capability_warnings: Vec::new(),
        };

        // Set the initial filter state
        app.filtering = true;
        app.event_input_buffer.clear();
        app.filter_events();
        app.filtering = false;

        Ok(app)
    }

    /// Creates a new application without BPF functionality for non-root users.
    #[allow(clippy::too_many_arguments)]
    pub fn new_without_bpf(
        config: Config,
        scheduler: String,
        max_cpu_events: usize,
        process_id: i32,
        layered_enabled: bool,
        action_tx: UnboundedSender<Action>,
    ) -> Result<Self> {
        let topo = Topology::new()?;
        let mut cpu_data = BTreeMap::new();
        let mut llc_data = BTreeMap::new();
        let mut node_data = BTreeMap::new();
        let mut proc_data = BTreeMap::new();
        let cpu_stat_tracker = Arc::new(RwLock::new(CpuStatTracker::default()));
        let mut mem_info = MemStatSnapshot::default();
        mem_info.update()?;

        // For non-BPF mode, use a basic profiling event that doesn't require BPF
        let active_event = ProfilingEvent::from_str_args(
            &config.default_profiling_event(),
            Some(cpu_stat_tracker.clone()),
        )?;

        let mut active_prof_events = BTreeMap::new();
        let mut default_events = get_default_events(cpu_stat_tracker.clone());

        let config_perf_events = PerfEvent::from_config(&config)?;

        default_events.extend(
            config_perf_events
                .iter()
                .cloned()
                .map(ProfilingEvent::Perf)
                .collect::<Vec<_>>(),
        );

        let default_events_str: Vec<&str> = default_events
            .iter()
            .map(|event| event.event_name())
            .collect();

        for cpu in topo.all_cpus.values() {
            // In non-BPF mode, we may not be able to initialize events for all CPUs
            let event = active_event
                .initialize_for_cpu(cpu.id, process_id)
                .unwrap_or_else(|_| {
                    // Create a fallback event if initialization fails
                    active_event.clone()
                });
            active_prof_events.insert(cpu.id, event);
            let mut data =
                CpuData::new(cpu.id, cpu.core_id, cpu.llc_id, cpu.node_id, max_cpu_events);
            data.initialize_events(&default_events_str);
            cpu_data.insert(cpu.id, data);
        }
        for llc in topo.all_llcs.values() {
            let mut data = LlcData::new(llc.id, llc.node_id, llc.all_cpus.len(), max_cpu_events);
            data.initialize_events(&default_events_str);
            llc_data.insert(llc.id, data);
        }
        for node in topo.nodes.values() {
            let mut data = NodeData::new(node.id, node.all_cpus.len(), max_cpu_events);
            data.initialize_events(&default_events_str);
            node_data.insert(node.id, data);
        }

        for process in all_processes()?.flatten() {
            if let Ok(data) = ProcData::new(&process, max_cpu_events) {
                proc_data.insert(process.pid, data);
            }
        }

        let mut initial_perf_events_list: Vec<String> = available_perf_events()
            .unwrap_or_default()
            .iter()
            .flat_map(|(subsystem, events)| {
                events
                    .iter()
                    .map(|event| format!("{}:{}", subsystem.clone(), event.clone()))
            })
            .collect();
        initial_perf_events_list.sort();

        let mut initial_kprobe_events_list = available_kprobe_events().unwrap_or_default();
        initial_kprobe_events_list.sort();

        let filtered_state = Arc::new(StdMutex::new(FilteredState::default()));

        let mut stats_client = StatsClient::new();
        let stats_socket_path = config.stats_socket_path();
        if !stats_socket_path.is_empty() {
            stats_client = stats_client.set_path(stats_socket_path);
        }
        // In non-BPF mode, stats client connection may fail, so we handle it gracefully
        stats_client = stats_client.connect(None).unwrap_or_else(|_| {
            let mut client = StatsClient::new();
            if !stats_socket_path.is_empty() {
                client = client.set_path(stats_socket_path);
            }
            client
        });
        let stats_client = Some(Arc::new(TokioMutex::new(stats_client)));

        // Default sample rate for non-BPF mode
        let sample_rate = 1000; // Default value when BPF is not available
        let trace_file_prefix = config.trace_file_prefix().to_string();
        let trace_manager = PerfettoTraceManager::new(trace_file_prefix, None);

        // No hardware pressure monitoring without BPF
        let hw_pressure = false;

        // Create System object and spawn background thread for CPU frequency refresh
        let sys = Arc::new(StdMutex::new(System::new_all()));
        let sys_clone = sys.clone();
        let tick_rate_ms = config.tick_rate_ms();
        let should_quit = Arc::new(AtomicBool::new(false));
        let should_quit_clone = should_quit.clone();

        // Create shared atomic for CPU frequency refresh interval
        let cpu_freq_refresh_interval_ms = Arc::new(AtomicU64::new(tick_rate_ms as u64));
        let interval_clone = cpu_freq_refresh_interval_ms.clone();

        // Spawn background thread to refresh CPU frequencies at the same rate as tick_rate
        // This moves the expensive sysfs reads off the main thread
        std::thread::spawn(move || {
            while !should_quit_clone.load(std::sync::atomic::Ordering::Relaxed) {
                if let Ok(mut system_guard) = sys_clone.lock() {
                    system_guard.refresh_cpu_frequency();
                }
                let interval_ms = interval_clone.load(std::sync::atomic::Ordering::Relaxed);
                std::thread::sleep(std::time::Duration::from_millis(interval_ms));
            }
        });

        let mut app = Self {
            config,
            localize: true,
            hw_pressure,
            locale: SystemLocale::default()?,
            stats_client,
            cpu_stat_tracker,
            sched_stats_raw: "".to_string(),
            sys,
            cpu_freq_refresh_interval_ms,
            mem_info,
            memory_view_state: ComponentViewState::Default,
            network_view_state: ComponentViewState::Default,
            scheduler,
            max_cpu_events,
            max_sched_events: max_cpu_events,
            state: AppState::Default,
            view_state: ViewState::BarChart,
            prev_state: AppState::Default,
            should_quit,
            action_tx,
            skel: None, // No BPF skeleton in non-BPF mode
            large_core_count: topo.all_cpus.len() >= 128,
            topo,
            collect_cpu_freq: true,
            collect_uncore_freq: true,
            layered_enabled,
            process_columns: Columns::new(get_process_columns_no_bpf()),
            thread_columns: Columns::new(get_thread_columns_no_bpf()),
            perf_top_columns: Columns::new(get_perf_top_columns_no_bpf()),
            selected_process: None,
            in_thread_view: false,
            cpu_data,
            llc_data,
            node_data,
            dsq_data: BTreeMap::new(),
            proc_data,
            network_stats: NetworkStatSnapshot::new(100),

            // BPF program statistics
            bpf_program_stats: BpfProgStats::new(),
            bpf_program_columns: Columns::new(get_bpf_program_columns()),
            bpf_program_table_state: TableState::default(),
            selected_bpf_program_id: None,
            cached_bpf_symbol_info: None,
            filtered_bpf_programs: Vec::new(),
            bpf_stats_fd: None,

            // System-wide CPU time tracking
            total_cpu_time_ns: 0,
            prev_total_cpu_time_ns: 0,
            prev_bpf_total_runtime_ns: 0,
            bpf_overhead_history: VecDeque::new(),
            terminal_width: 80, // Default value, will be updated on first render

            // BPF program detail view perf data
            bpf_program_symbol_data: SymbolData::new(),
            bpf_program_symbol_table_state: TableState::default(),
            bpf_program_filtered_symbols: Vec::new(),

            // Perf sampling control
            bpf_perf_sampling_active: false,

            active_hw_event_id: 0,
            active_event,
            active_prof_events,
            available_events: default_events,
            event_input_buffer: String::new(),
            perf_events: initial_perf_events_list,
            kprobe_events: initial_kprobe_events_list,
            kprobe_links: Vec::new(),
            filtered_state,
            filtering: false,
            events_list_size: 1,
            prev_bpf_sample_rate: sample_rate,
            trace_start: 0,
            trace_manager,
            bpf_stats: Default::default(),
            scx_stats: default_scxtop_sched_ext_stats(),
            power_snapshot: crate::PowerSnapshot::new(),
            power_collector: crate::PowerDataCollector::new().unwrap_or_else(|e| {
                log::warn!("Failed to initialize power collector with MSR support: {e}");
                crate::PowerDataCollector::default()
            }),
            has_perf_cap: check_perf_capability(),
            process_id,
            prev_process_id: -1,
            trace_links: vec![],
            last_mangoapp_action: None,
            frames_since_update: 0,
            max_fps: 1,
            perf_sample_rate: 1_000_000, // Default perf sample rate
            symbol_data: crate::symbol_data::SymbolData::new(),
            perf_links: Vec::new(),
            selected_symbol_index: 0,
            current_sampling_event: None,
            perf_top_table_state: TableState::default(),
            perf_top_filtered_symbols: Vec::new(),
            capability_warnings: Vec::new(),
        };

        // Set the initial filter state
        app.filtering = true;
        app.event_input_buffer.clear();
        app.filter_events();
        app.filtering = false;

        Ok(app)
    }

    /// Returns the state of the application.
    pub fn state(&self) -> AppState {
        self.state.clone()
    }

    /// Sets the state of the application.
    pub fn set_state(&mut self, mut state: AppState) {
        if self.state == AppState::Tracing {
            return;
        }

        if state == self.state {
            state = self.prev_state.clone();
        }

        if self.state != AppState::Help
            && self.state != AppState::PerfEvent
            && self.state != AppState::KprobeEvent
            && self.state != AppState::Pause
        {
            self.prev_state = self.state.clone();
        }
        self.state = state;

        // Handle perf sampling attachment/detachment for PerfTop view
        match (self.prev_state.clone(), self.state.clone()) {
            (prev, AppState::PerfTop) if prev != AppState::PerfTop => {
                if self.has_perf_cap {
                    // Entering PerfTop view - attach perf sampling and reset selection
                    self.selected_symbol_index = 0;
                    if let Err(e) = self.attach_perf_sampling() {
                        eprintln!("Failed to attach perf sampling: {e}");
                    }
                }
            }
            (AppState::PerfTop, new) if new != AppState::PerfTop => {
                // Leaving PerfTop view - detach perf sampling
                if self.has_perf_cap {
                    self.detach_perf_sampling();
                }
            }
            _ => {}
        }

        if self.state == AppState::PerfEvent
            || self.state == AppState::KprobeEvent
            || self.state == AppState::Default
            || self.state == AppState::Llc
            || self.state == AppState::Node
            || self.state == AppState::Process
        {
            self.filtered_state.lock().unwrap().reset();
            self.filter_events();
        }
        if self.state == AppState::PerfTop {
            self.filtered_state.lock().unwrap().reset();
            self.filter_symbols();
        }

        if self.prev_state == AppState::MangoApp {
            self.process_id = self.prev_process_id;
            // reactivate the prev profiling event with the previous pid
            if self.has_perf_cap {
                let prof_event = &self.available_events[self.active_hw_event_id].clone();
                let _ = self.activate_prof_event(prof_event);
                self.max_fps = 1;
                self.frames_since_update = 0;
            }
        }

        // Manage BPF stats collection based on current state
        let is_bpf_related_state = matches!(
            self.state,
            AppState::BpfPrograms | AppState::BpfProgramDetail
        );
        let was_bpf_related_state = matches!(
            self.prev_state,
            AppState::BpfPrograms | AppState::BpfProgramDetail
        );

        // If transitioning away from BPF-related states, disable BPF stats tracking
        if was_bpf_related_state && !is_bpf_related_state {
            self.disable_bpf_stats();
        }

        // Manage BPF stats collection based on current state
        let is_bpf_related_state = matches!(
            self.state,
            AppState::BpfPrograms | AppState::BpfProgramDetail
        );
        let was_bpf_related_state = matches!(
            self.prev_state,
            AppState::BpfPrograms | AppState::BpfProgramDetail
        );

        // If transitioning away from BPF-related states, disable BPF stats tracking
        if was_bpf_related_state && !is_bpf_related_state {
            self.disable_bpf_stats();
        }
    }

    /// Returns the current theme of the application
    pub fn theme(&self) -> &AppTheme {
        self.config.theme()
    }

    /// Sets the theme of the application.
    pub fn set_theme(&mut self, theme: AppTheme) {
        self.config.set_theme(theme)
    }

    /// Returns whether we are currently filtering or not
    pub fn filtering(&self) -> bool {
        self.filtering
    }

    /// Returns whether layered mode is enabled
    pub fn layered_enabled(&self) -> bool {
        self.layered_enabled
    }

    /// Sets capability warnings for non-root users
    pub fn set_capability_warnings(&mut self, warnings: Vec<String>) {
        self.capability_warnings = warnings;
    }

    /// Returns capability warnings
    pub fn get_capability_warnings(&self) -> &Vec<String> {
        &self.capability_warnings
    }

    /// Returns whether there are capability warnings
    pub fn has_capability_warnings(&self) -> bool {
        !self.capability_warnings.is_empty()
    }

    /// Renders capability warnings at the top of the screen
    fn render_capability_warnings(&self, frame: &mut Frame, area: Rect) -> Result<()> {
        if self.capability_warnings.is_empty() {
            return Ok(());
        }

        let warning_lines: Vec<Line> = self
            .capability_warnings
            .iter()
            .map(|warning| {
                Line::from(vec![Span::styled(
                    warning.clone(),
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD),
                )])
            })
            .collect();

        let warning_paragraph = Paragraph::new(warning_lines)
            .block(
                Block::bordered()
                    .title("⚠️  Capability Warnings")
                    .title_alignment(Alignment::Center)
                    .border_type(BorderType::Rounded)
                    .style(Style::default().fg(Color::Yellow)),
            )
            .wrap(Wrap { trim: true })
            .style(Style::default().fg(Color::Yellow));

        frame.render_widget(warning_paragraph, area);
        Ok(())
    }

    fn selected_proc_data(&mut self) -> Option<&mut ProcData> {
        self.selected_process
            .and_then(|tgid| self.proc_data.get_mut(&tgid))
    }

    fn selected_proc_data_immut(&self) -> Option<&ProcData> {
        self.selected_process
            .and_then(|tgid| self.proc_data.get(&tgid))
    }

    /// Stop all active profiling events.
    fn stop_prof_events(&mut self) {
        for cpu_data in self.cpu_data.values_mut() {
            cpu_data.data.clear();
        }
        self.active_prof_events.clear();
    }

    /// Resets profiling events to default
    fn reset_prof_events(&mut self) -> Result<()> {
        self.stop_prof_events();
        self.kprobe_links.clear();

        self.available_events = get_default_events(self.cpu_stat_tracker.clone());
        let config_perf_events = PerfEvent::from_config(&self.config)?;

        self.available_events.extend(
            config_perf_events
                .iter()
                .cloned()
                .map(ProfilingEvent::Perf)
                .collect::<Vec<_>>(),
        );

        self.active_hw_event_id = 0;
        let prof_event = &self.available_events[self.active_hw_event_id].clone();
        self.active_event = prof_event.clone();
        self.activate_prof_event(prof_event)
    }

    /// Activates the next event.
    fn next_event(&mut self) -> Result<()> {
        self.active_prof_events.clear();
        if self.active_hw_event_id == self.available_events.len() - 1 {
            self.active_hw_event_id = 0;
        } else {
            self.active_hw_event_id += 1;
        }
        let prof_event = &self.available_events[self.active_hw_event_id].clone();

        self.active_event = prof_event.clone();

        // Clear perf top data when switching events
        if self.state == AppState::PerfTop {
            self.symbol_data.clear();
            self.selected_symbol_index = 0;
            self.filter_symbols(); // Update filtered symbols after clearing
        }

        self.activate_prof_event(prof_event)
    }

    /// Activates the previous event.
    fn prev_event(&mut self) -> Result<()> {
        self.active_prof_events.clear();
        if self.active_hw_event_id == 0 {
            self.active_hw_event_id = self.available_events.len() - 1;
        } else {
            self.active_hw_event_id -= 1;
        }
        let prof_event = &self.available_events[self.active_hw_event_id].clone();

        self.active_event = prof_event.clone();

        // Clear perf top data when switching events
        if self.state == AppState::PerfTop {
            self.symbol_data.clear();
            self.selected_symbol_index = 0;
            self.filter_symbols(); // Update filtered symbols after clearing
        }

        self.activate_prof_event(prof_event)
    }

    /// Activates the next view state.
    fn next_view_state(&mut self) {
        self.view_state = self.view_state.next();
    }

    /// Activates a profiling event, stopping any active profiling events.
    fn activate_prof_event(&mut self, prof_event: &ProfilingEvent) -> Result<()> {
        if !self.active_prof_events.is_empty() {
            self.stop_prof_events();
        }

        for &cpu_id in self.topo.all_cpus.keys() {
            let event = prof_event.initialize_for_cpu(cpu_id, self.process_id)?;
            self.active_prof_events.insert(cpu_id, event);
        }
        Ok(())
    }

    fn record_cpu_freq(&mut self) -> Result<()> {
        let cpu_util_data = &self.cpu_stat_tracker.read().unwrap().current;
        for (cpu_id, data) in cpu_util_data.iter() {
            let cpu_data = self
                .cpu_data
                .get_mut(cpu_id)
                .expect("CpuData should have been present");
            cpu_data.add_event_data("cpu_freq", data.freq_khz * 1000);
        }
        Ok(())
    }

    fn record_uncore_freq(&mut self) -> Result<()> {
        // XXX: this only works with intel uncore frequency kernel module
        let base_path = Path::new("/sys/devices/system/cpu/intel_uncore_frequency");
        if self.collect_uncore_freq && !base_path.exists() {
            self.collect_uncore_freq = false;
            return Ok(());
        }

        let glob_match = glob("/sys/devices/system/cpu/intel_uncore_frequency/*/current_freq_khz");
        if let Ok(entries) = glob_match {
            let re = Regex::new(r"package_(\d+)_die_\d+").unwrap();
            for raw_path in entries.flatten() {
                let path = Path::new(&raw_path);
                if let Some(caps) =
                    re.captures(raw_path.to_str().expect("failed to get str from path"))
                {
                    let package_id: usize = caps[1].parse().unwrap();
                    let uncore_freq = read_from_file(path).unwrap_or(0_usize);
                    for cpu in self.topo.all_cpus.values() {
                        if cpu.package_id != package_id {
                            continue;
                        }
                        let node_data = self
                            .node_data
                            .get_mut(&cpu.node_id)
                            .expect("NodeData should have been present");
                        node_data.add_event_data("uncore_freq", uncore_freq as u64);
                    }
                }
            }
        }
        Ok(())
    }

    /// resizes existing sched event data based on new max value.
    fn resize_events(&mut self, max_events: usize) {
        for node in self.topo.nodes.keys() {
            let node_data = self
                .node_data
                .get_mut(node)
                .expect("NodeData should have been present");
            node_data.data.set_max_size(max_events);
        }
        for llc in self.topo.all_llcs.keys() {
            let llc_data = self
                .llc_data
                .get_mut(llc)
                .expect("LlcData should have been present");
            llc_data.data.set_max_size(max_events);
        }
        for cpu in self.active_prof_events.keys() {
            let cpu_data = self
                .cpu_data
                .get_mut(cpu)
                .expect("CpuData should have been present");
            cpu_data.data.set_max_size(max_events);
        }
        self.max_cpu_events = max_events;
    }

    /// Saves the current config.
    fn on_save_config(&mut self) -> Result<()> {
        self.config.save()
    }

    /// Handles when scheduler stats are received.
    fn on_sched_stats(&mut self, stats_raw: String) {
        self.sched_stats_raw = stats_raw;
    }

    /// Reloads stats client
    fn reload_stats_client(&mut self) -> Result<()> {
        let stats_socket_path = self.config.stats_socket_path();
        let mut new_client = StatsClient::new();
        new_client = new_client.set_path(stats_socket_path);
        new_client = new_client.connect(None)?;
        if let Some(client_ref) = &self.stats_client {
            let mut client = client_ref.blocking_lock();
            *client = new_client;
        }
        Ok(())
    }

    /// Runs callbacks to update application state on tick.
    /// Uses view-specific data collection to optimize performance.
    fn on_tick(&mut self) -> Result<()> {
        match self.state {
            AppState::BpfProgramDetail => self.on_tick_bpf_program_detail(),
            AppState::BpfPrograms => self.on_tick_bpf_programs(),
            AppState::Default => self.on_tick_default(),
            AppState::Help | AppState::Pause | AppState::Tracing => self.on_tick_static(),
            AppState::Llc => self.on_tick_llc(),
            AppState::MangoApp => self.on_tick_mango_app(),
            AppState::Memory => self.on_tick_memory(),
            AppState::Network => self.on_tick_network(),
            AppState::Node => self.on_tick_node(),
            AppState::PerfEvent | AppState::KprobeEvent => self.on_tick_events(),
            AppState::PerfTop => self.on_tick_perf_top(),
            AppState::Power => self.on_tick_power(),
            AppState::Process => self.on_tick_process(),
            AppState::Scheduler => self.on_tick_scheduler(),
        }
    }

    /// Filters BPF programs based on the current filter input
    fn filter_bpf_programs(&mut self) {
        self.filtered_bpf_programs.clear();

        if self.event_input_buffer.is_empty() {
            // No filter, show all programs
            self.filtered_bpf_programs = self
                .bpf_program_stats
                .programs
                .iter()
                .map(|(id, data)| (*id, data.clone()))
                .collect();
        } else {
            let filter_text = self.event_input_buffer.to_lowercase();

            // Special filter for sched_ext programs
            if filter_text == "sched_ext" || filter_text == "scheduler" {
                self.filtered_bpf_programs = self
                    .bpf_program_stats
                    .programs
                    .iter()
                    .filter_map(|(id, data)| {
                        if data.is_sched_ext {
                            Some((*id, data.clone()))
                        } else {
                            None
                        }
                    })
                    .collect();
            } else {
                // Apply substring filter with scheduler name included
                self.filtered_bpf_programs = self
                    .bpf_program_stats
                    .programs
                    .iter()
                    .filter_map(|(id, data)| {
                        // Search in program name, type, scheduler name, and ID
                        let search_text = format!(
                            "{} {} {} {}",
                            data.name.to_lowercase(),
                            data.prog_type.to_lowercase(),
                            data.sched_ext_ops_name
                                .as_ref()
                                .unwrap_or(&"".to_string())
                                .to_lowercase(),
                            id
                        );

                        if search_text.contains(&filter_text) {
                            Some((*id, data.clone()))
                        } else {
                            None
                        }
                    })
                    .collect();
            }
        }

        // Sort by average runtime descending (same as the main view)
        self.filtered_bpf_programs.sort_by(|a, b| {
            b.1.avg_runtime_ns()
                .partial_cmp(&a.1.avg_runtime_ns())
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        // Reset table selection to the first item
        if !self.filtered_bpf_programs.is_empty() {
            self.bpf_program_table_state.select(Some(0));
        } else {
            self.bpf_program_table_state.select(None);
        }
    }

    /// Generates a CPU bar chart with gradient coloring based on relative value.
    fn cpu_bar_with_gradient(&self, cpu: usize, event: &str, min: u64, max: u64) -> Bar<'_> {
        let cpu_data = self
            .cpu_data
            .get(&cpu)
            .expect("CpuData should have been present");
        let value = cpu_data
            .event_data_immut(event)
            .last()
            .copied()
            .unwrap_or(0_u64);

        let gradient_color = self.gradient5_color(value, max, min);

        Bar::default()
            .value(value)
            .style(Style::default().fg(gradient_color))
            .value_style(self.theme().text_color())
            .label(
                Line::from(format!(
                    "{}{}{}",
                    cpu,
                    if self.collect_cpu_freq {
                        format!(
                            " {}",
                            format_hz(
                                cpu_data
                                    .event_data_immut("cpu_freq")
                                    .last()
                                    .copied()
                                    .unwrap_or(0)
                            )
                        )
                    } else {
                        "".to_string()
                    },
                    if self.hw_pressure {
                        let hw_pressure = cpu_data
                            .event_data_immut("hw_pressure")
                            .last()
                            .copied()
                            .unwrap_or(0);
                        if hw_pressure > 0 {
                            format!("{hw_pressure}")
                        } else {
                            "".to_string()
                        }
                    } else {
                        "".to_string()
                    }
                ))
                .style(self.theme().text_color()),
            )
            .text_value(if self.localize {
                sanitize_nbsp(value.to_formatted_string(&self.locale))
            } else {
                format!("{value}")
            })
    }

    /// Creates a sparkline for a CPU with gradient coloring based on current value relative to min/max.
    fn cpu_sparkline_with_gradient(
        &self,
        cpu: usize,
        max: u64,
        min: u64,
        borders: Borders,
        small: bool,
    ) -> Sparkline<'_> {
        let mut cpu_freq: u64 = 0;
        let mut hw_pressure: u64 = 0;
        let data = if self.cpu_data.contains_key(&cpu) {
            let cpu_data = self
                .cpu_data
                .get(&cpu)
                .expect("CpuData should have been present");
            if self.collect_cpu_freq {
                cpu_freq = cpu_data
                    .event_data_immut("cpu_freq")
                    .last()
                    .copied()
                    .unwrap_or(0);
            }
            if self.hw_pressure {
                hw_pressure = cpu_data
                    .event_data_immut("hw_pressure")
                    .last()
                    .copied()
                    .unwrap_or(0);
            }
            cpu_data.event_data_immut(self.active_event.event_name())
        } else {
            Vec::new()
        };

        let current_value = data.last().copied().unwrap_or(0);
        let gradient_color = self.gradient5_color(current_value, max, min);

        Sparkline::default()
            .data(&data)
            .max(max)
            .direction(RenderDirection::RightToLeft)
            .style(Style::default().fg(gradient_color))
            .bar_set(if small { THREE_LEVELS } else { NINE_LEVELS })
            .block(
                Block::new()
                    .title(format!(
                        "{}{}{}",
                        cpu,
                        if self.collect_cpu_freq {
                            format!(" {}", format_hz(cpu_freq))
                        } else {
                            "".to_string()
                        },
                        if self.hw_pressure && hw_pressure > 0 {
                            format!(" hw_pressure({hw_pressure})")
                        } else {
                            "".to_string()
                        }
                    ))
                    .borders(borders)
                    .border_type(BorderType::Rounded)
                    .style(self.theme().border_style()),
            )
    }

    /// creates as sparkline for a llc.
    fn llc_sparkline(&self, llc: usize, max: u64, bottom_border: bool) -> Sparkline<'_> {
        let llc_data = self
            .llc_data
            .get(&llc)
            .expect("LlcData should have been present");
        let divisor = match self.active_event {
            ProfilingEvent::CpuUtil(_) => llc_data.num_cpus,
            _ => 1,
        };
        let data: Vec<u64> = llc_data
            .event_data_immut(self.active_event.event_name())
            .iter()
            .map(|x| x / divisor as u64)
            .collect();

        let stats = VecStats::new(&data, None);

        Sparkline::default()
            .data(&data)
            .max(max)
            .direction(RenderDirection::RightToLeft)
            .style(self.theme().sparkline_style())
            .block(
                Block::new()
                    .borders(if bottom_border {
                        Borders::LEFT | Borders::RIGHT | Borders::BOTTOM
                    } else {
                        Borders::LEFT | Borders::RIGHT
                    })
                    .style(self.theme().border_style())
                    .border_type(BorderType::Rounded)
                    .title_top(
                        Line::from(if self.localize {
                            format!(
                                "LLC {} avg {} max {} min {}",
                                llc,
                                sanitize_nbsp(stats.avg.to_formatted_string(&self.locale)),
                                sanitize_nbsp(stats.max.to_formatted_string(&self.locale)),
                                sanitize_nbsp(stats.min.to_formatted_string(&self.locale))
                            )
                        } else {
                            format!(
                                "LLC {} avg {} max {} min {}",
                                llc, stats.avg, stats.max, stats.min
                            )
                        })
                        .style(self.theme().title_style())
                        .left_aligned(),
                    ),
            )
    }

    /// creates as sparkline for a node.
    fn node_sparkline(&self, node: usize, max: u64, bottom_border: bool) -> Sparkline<'_> {
        let node_data = self
            .node_data
            .get(&node)
            .expect("NodeData should have been present");
        let divisor = match self.active_event {
            ProfilingEvent::CpuUtil(_) => node_data.num_cpus,
            _ => 1,
        };
        let data: Vec<u64> = node_data
            .event_data_immut(self.active_event.event_name())
            .iter()
            .map(|x| x / divisor as u64)
            .collect();

        let stats = VecStats::new(&data, None);

        Sparkline::default()
            .data(&data)
            .max(max)
            .direction(RenderDirection::RightToLeft)
            .style(self.theme().sparkline_style())
            .block(
                Block::new()
                    .borders(if bottom_border {
                        Borders::LEFT | Borders::RIGHT | Borders::BOTTOM
                    } else {
                        Borders::LEFT | Borders::RIGHT
                    })
                    .border_type(BorderType::Rounded)
                    .style(self.theme().border_style())
                    .title_top(
                        Line::from(if self.collect_uncore_freq {
                            "uncore ".to_string()
                                + format_hz(
                                    self.node_data
                                        .get(&node)
                                        .expect("NodeData should have been present")
                                        .event_data_immut("uncore_freq")
                                        .last()
                                        .copied()
                                        .unwrap_or(0_u64),
                                )
                                .as_str()
                        } else {
                            "".to_string()
                        })
                        .style(self.theme().text_important_color())
                        .right_aligned(),
                    )
                    .title_top(
                        Line::from(if self.localize {
                            format!(
                                "Node {} avg {} max {} min {}",
                                node,
                                sanitize_nbsp(stats.avg.to_formatted_string(&self.locale)),
                                sanitize_nbsp(stats.max.to_formatted_string(&self.locale)),
                                sanitize_nbsp(stats.min.to_formatted_string(&self.locale))
                            )
                        } else {
                            format!(
                                "Node {} avg {} max {} min {}",
                                node, stats.avg, stats.max, stats.min,
                            )
                        })
                        .style(self.theme().title_style())
                        .left_aligned(),
                    ),
            )
    }

    /// Renders the llc application state.
    fn render_llc(&mut self, frame: &mut Frame) -> Result<()> {
        let area = frame.area();
        let area_events = (area.width / 2) as usize;
        if self.max_cpu_events != area_events {
            self.resize_events(area_events);
        }
        let [left, right] = Layout::horizontal([Constraint::Fill(1); 2]).areas(area);
        let num_llcs = self.topo.all_llcs.len();

        let llc_iter = self
            .llc_data
            .values()
            .flat_map(|llc_data| {
                let divisor = match self.active_event {
                    ProfilingEvent::CpuUtil(_) => llc_data.num_cpus,
                    _ => 1,
                };
                llc_data
                    .event_data_immut(self.active_event.event_name())
                    .iter()
                    .map(|&x| x / divisor as u64)
                    .collect::<Vec<u64>>()
            })
            .collect::<Vec<u64>>();

        let stats = VecStats::new(&llc_iter, None);

        match self.view_state {
            ViewState::Sparkline => {
                let mut llcs_constraints = vec![Constraint::Length(1)];
                for _ in 0..num_llcs {
                    llcs_constraints.push(Constraint::Ratio(1, num_llcs as u32));
                }
                let llcs_verticle = Layout::vertical(llcs_constraints).split(right);

                let llc_block = Block::bordered()
                    .title_top(
                        Line::from(if self.localize {
                            format!(
                                "LLCs ({}) avg {} max {} min {}",
                                self.active_event.event_name(),
                                sanitize_nbsp(stats.avg.to_formatted_string(&self.locale)),
                                sanitize_nbsp(stats.max.to_formatted_string(&self.locale)),
                                sanitize_nbsp(stats.min.to_formatted_string(&self.locale))
                            )
                        } else {
                            format!(
                                "LLCs ({}) avg {} max {} min {}",
                                self.active_event.event_name(),
                                stats.avg,
                                stats.max,
                                stats.min,
                            )
                        })
                        .style(self.theme().title_style())
                        .centered(),
                    )
                    .border_type(BorderType::Rounded)
                    .title_top(
                        Line::from(format!("{}ms", self.config.tick_rate_ms()))
                            .style(self.theme().text_important_color())
                            .right_aligned(),
                    )
                    .style(self.theme().border_style());

                frame.render_widget(llc_block, llcs_verticle[0]);

                self.topo
                    .all_llcs
                    .keys()
                    .map(|llc_id| self.llc_sparkline(*llc_id, stats.max, *llc_id == num_llcs - 1))
                    .enumerate()
                    .for_each(|(i, llc_sparkline)| {
                        frame.render_widget(llc_sparkline, llcs_verticle[i + 1]);
                    });
            }
            ViewState::BarChart => {
                let llc_block = Block::default()
                    .title_top(
                        Line::from(if self.localize {
                            format!(
                                "LLCs ({}) avg {} max {} min {}",
                                self.active_event.event_name(),
                                sanitize_nbsp(stats.avg.to_formatted_string(&self.locale)),
                                sanitize_nbsp(stats.max.to_formatted_string(&self.locale)),
                                sanitize_nbsp(stats.min.to_formatted_string(&self.locale))
                            )
                        } else {
                            format!(
                                "LLCs ({}) avg {} max {} min {}",
                                self.active_event.event_name(),
                                stats.avg,
                                stats.max,
                                stats.min,
                            )
                        })
                        .style(self.theme().title_style())
                        .centered(),
                    )
                    .title_top(
                        Line::from(format!("{}ms", self.config.tick_rate_ms()))
                            .style(self.theme().text_important_color())
                            .right_aligned(),
                    )
                    .style(self.theme().border_style())
                    .borders(Borders::ALL)
                    .border_type(BorderType::Rounded);

                let llc_bars: Vec<Bar> = self.llc_bars(self.active_event.event_name());

                let barchart = BarChart::default()
                    .data(BarGroup::default().bars(&llc_bars))
                    .block(llc_block)
                    .max(stats.max)
                    .direction(Direction::Horizontal)
                    .bar_gap(0)
                    .bar_width(1);

                frame.render_widget(barchart, right);
            }
            ViewState::LineGauge => {
                let llc_block = Block::bordered()
                    .title_top(
                        Line::from(if self.localize {
                            format!(
                                "LLCs ({}) avg {} max {} min {}",
                                self.active_event.event_name(),
                                sanitize_nbsp(stats.avg.to_formatted_string(&self.locale)),
                                sanitize_nbsp(stats.max.to_formatted_string(&self.locale)),
                                sanitize_nbsp(stats.min.to_formatted_string(&self.locale))
                            )
                        } else {
                            format!(
                                "LLCs ({}) avg {} max {} min {}",
                                self.active_event.event_name(),
                                stats.avg,
                                stats.max,
                                stats.min,
                            )
                        })
                        .style(self.theme().title_style())
                        .centered(),
                    )
                    .title_top(
                        Line::from(format!("{}ms", self.config.tick_rate_ms()))
                            .style(self.theme().text_important_color())
                            .right_aligned(),
                    )
                    .border_type(BorderType::Rounded);

                let inner_area = llc_block.inner(right);
                let num_llcs = self.topo.all_llcs.len();

                // Create constraints for LLCs layout
                let constraints =
                    vec![Constraint::Length(1); num_llcs.min(inner_area.height as usize)];
                let llc_areas = Layout::vertical(constraints).split(inner_area);

                // Render LineGauge for each LLC
                for (i, llc_id) in self.topo.all_llcs.keys().enumerate() {
                    if i >= llc_areas.len() {
                        break; // Don't exceed available area
                    }

                    let llc_data = self.llc_data.get(llc_id);
                    let current_value = if let Some(data) = llc_data {
                        let divisor = match self.active_event {
                            ProfilingEvent::CpuUtil(_) => data.num_cpus,
                            _ => 1,
                        };
                        data.event_data_immut(self.active_event.event_name())
                            .last()
                            .copied()
                            .unwrap_or(0)
                            / divisor as u64
                    } else {
                        0
                    };

                    // Calculate utilization ratio (0.0 to 1.0) based on max value
                    let ratio = if stats.max > 0 {
                        (current_value as f64 / stats.max as f64).clamp(0.0, 1.0)
                    } else {
                        0.0
                    };

                    // Get colorization based on actual value like sparklines/bar charts do
                    let gradient_color = self.gradient5_color(current_value, stats.max, stats.min);

                    let label = format!(
                        "LLC{} {}",
                        llc_id,
                        if self.localize {
                            sanitize_nbsp(current_value.to_formatted_string(&self.locale))
                        } else {
                            format!("{current_value}")
                        }
                    );

                    let line_gauge = LineGauge::default()
                        .ratio(ratio)
                        .line_set(THICK)
                        .label(Line::from(label).style(self.theme().text_color()))
                        .filled_style(Style::default().fg(gradient_color).bg(Color::Reset))
                        .unfilled_style(
                            Style::default()
                                .fg(self.theme().border_style().fg.unwrap_or(Color::Gray))
                                .bg(Color::Reset),
                        );

                    frame.render_widget(line_gauge, llc_areas[i]);
                }

                frame.render_widget(llc_block, right);
            }
        }

        self.render_table(frame, left, false)
    }

    /// Renders the node application state.
    fn render_node(&mut self, frame: &mut Frame) -> Result<()> {
        let area = frame.area();
        let area_events = (area.width / 2) as usize;
        if self.max_cpu_events != area_events {
            self.resize_events(area_events);
        }
        let [left, right] = Layout::horizontal([Constraint::Fill(1); 2]).areas(area);
        let num_nodes = self.topo.nodes.len();

        let node_iter = self
            .node_data
            .values()
            .flat_map(|node_data| {
                let divisor = match self.active_event {
                    ProfilingEvent::CpuUtil(_) => node_data.num_cpus,
                    _ => 1,
                };
                node_data
                    .event_data_immut(self.active_event.event_name())
                    .iter()
                    .map(|&x| x / divisor as u64)
                    .collect::<Vec<u64>>()
            })
            .collect::<Vec<u64>>();

        let stats = VecStats::new(&node_iter, None);

        match self.view_state {
            ViewState::Sparkline => {
                let mut node_constraints = vec![Constraint::Length(1)];
                for _ in 0..num_nodes {
                    node_constraints.push(Constraint::Ratio(1, num_nodes as u32));
                }
                let nodes_verticle = Layout::vertical(node_constraints).split(right);

                let node_sparklines: Vec<Sparkline> = self
                    .topo
                    .nodes
                    .keys()
                    .map(|node_id| {
                        self.node_sparkline(*node_id, stats.max, *node_id == num_nodes - 1)
                    })
                    .collect();

                let node_block = Block::bordered()
                    .title_top(
                        Line::from(if self.localize {
                            format!(
                                "Node ({}) avg {} max {} min {}",
                                self.active_event.event_name(),
                                sanitize_nbsp(stats.avg.to_formatted_string(&self.locale)),
                                sanitize_nbsp(stats.max.to_formatted_string(&self.locale)),
                                sanitize_nbsp(stats.min.to_formatted_string(&self.locale))
                            )
                        } else {
                            format!(
                                "Node ({}) avg {} max {} min {}",
                                self.active_event.event_name(),
                                stats.avg,
                                stats.max,
                                stats.min,
                            )
                        })
                        .style(self.theme().title_style())
                        .centered(),
                    )
                    .title_top(
                        Line::from(format!("{}ms", self.config.tick_rate_ms()))
                            .style(self.theme().text_important_color())
                            .right_aligned(),
                    )
                    .border_type(BorderType::Rounded)
                    .style(self.theme().border_style());

                frame.render_widget(node_block, nodes_verticle[0]);
                node_sparklines
                    .iter()
                    .enumerate()
                    .for_each(|(i, node_sparkline)| {
                        frame.render_widget(node_sparkline, nodes_verticle[i + 1]);
                    });
            }
            ViewState::BarChart => {
                let node_block = Block::default()
                    .title_top(
                        Line::from(if self.localize {
                            format!(
                                "NUMA Nodes ({}) avg {} max {} min {}",
                                self.active_event.event_name(),
                                sanitize_nbsp(stats.avg.to_formatted_string(&self.locale)),
                                sanitize_nbsp(stats.max.to_formatted_string(&self.locale)),
                                sanitize_nbsp(stats.min.to_formatted_string(&self.locale))
                            )
                        } else {
                            format!(
                                "NUMA Nodes ({}) avg {} max {} min {}",
                                self.active_event.event_name(),
                                stats.avg,
                                stats.max,
                                stats.min,
                            )
                        })
                        .style(self.theme().title_style())
                        .centered(),
                    )
                    .title_top(
                        Line::from(format!("{}ms", self.config.tick_rate_ms()))
                            .style(self.theme().text_important_color())
                            .right_aligned(),
                    )
                    .style(self.theme().border_style())
                    .borders(Borders::ALL)
                    .border_type(BorderType::Rounded);

                let node_bars: Vec<Bar> = self.node_bars(self.active_event.event_name());

                let barchart = BarChart::default()
                    .data(BarGroup::default().bars(&node_bars))
                    .block(node_block)
                    .max(stats.max)
                    .direction(Direction::Horizontal)
                    .bar_gap(0)
                    .bar_width(1);

                frame.render_widget(barchart, right);
            }
            ViewState::LineGauge => {
                let node_block = Block::bordered()
                    .title_top(
                        Line::from(if self.localize {
                            format!(
                                "NUMA Nodes ({}) avg {} max {} min {}",
                                self.active_event.event_name(),
                                sanitize_nbsp(stats.avg.to_formatted_string(&self.locale)),
                                sanitize_nbsp(stats.max.to_formatted_string(&self.locale)),
                                sanitize_nbsp(stats.min.to_formatted_string(&self.locale))
                            )
                        } else {
                            format!(
                                "NUMA Nodes ({}) avg {} max {} min {}",
                                self.active_event.event_name(),
                                stats.avg,
                                stats.max,
                                stats.min,
                            )
                        })
                        .style(self.theme().title_style())
                        .centered(),
                    )
                    .title_top(
                        Line::from(format!("{}ms", self.config.tick_rate_ms()))
                            .style(self.theme().text_important_color())
                            .right_aligned(),
                    )
                    .border_type(BorderType::Rounded);

                let inner_area = node_block.inner(right);
                let num_nodes = self.topo.nodes.len();

                // Create constraints for NUMA nodes layout
                let constraints =
                    vec![Constraint::Length(1); num_nodes.min(inner_area.height as usize)];
                let node_areas = Layout::vertical(constraints).split(inner_area);

                // Render LineGauge for each NUMA node
                for (i, node_id) in self.topo.nodes.keys().enumerate() {
                    if i >= node_areas.len() {
                        break; // Don't exceed available area
                    }

                    let node_data = self.node_data.get(node_id);
                    let current_value = if let Some(data) = node_data {
                        let divisor = match self.active_event {
                            ProfilingEvent::CpuUtil(_) => data.num_cpus,
                            _ => 1,
                        };
                        data.event_data_immut(self.active_event.event_name())
                            .last()
                            .copied()
                            .unwrap_or(0)
                            / divisor as u64
                    } else {
                        0
                    };

                    // Calculate utilization ratio (0.0 to 1.0) based on max value
                    let ratio = if stats.max > 0 {
                        (current_value as f64 / stats.max as f64).clamp(0.0, 1.0)
                    } else {
                        0.0
                    };

                    // Get colorization based on actual value like sparklines/bar charts do
                    let gradient_color = self.gradient5_color(current_value, stats.max, stats.min);

                    let label = format!(
                        "Node{} {}",
                        node_id,
                        if self.localize {
                            sanitize_nbsp(current_value.to_formatted_string(&self.locale))
                        } else {
                            format!("{current_value}")
                        }
                    );

                    let line_gauge = LineGauge::default()
                        .ratio(ratio)
                        .label(Line::from(label).style(self.theme().text_color()))
                        .line_set(THICK)
                        .filled_style(Style::default().fg(gradient_color).bg(Color::Reset))
                        .unfilled_style(
                            Style::default()
                                .fg(self.theme().border_style().fg.unwrap_or(Color::Gray))
                                .bg(Color::Reset),
                        );

                    frame.render_widget(line_gauge, node_areas[i]);
                }

                frame.render_widget(node_block, right);
            }
        }

        self.render_table(frame, left, false)
    }

    /// Returns the gradient color.
    fn gradient5_color(&self, value: u64, max: u64, min: u64) -> Color {
        if max > min {
            let range = max - min;
            let very_low_threshold = min as f64 + (range as f64 * 0.2);
            let low_threshold = min as f64 + (range as f64 * 0.4);
            let high_threshold = min as f64 + (range as f64 * 0.6);
            let very_high_threshold = min as f64 + (range as f64 * 0.8);

            self.theme().gradient_5(
                value as f64,
                very_low_threshold,
                low_threshold,
                high_threshold,
                very_high_threshold,
                false,
            )
        } else {
            self.theme().sparkline_style().fg.unwrap_or_default()
        }
    }

    /// Generates a LLC bar chart.
    fn event_bar(&self, id: usize, value: u64, avg: u64, max: u64, min: u64) -> Bar<'_> {
        let gradient_color = self.gradient5_color(value, max, min);

        Bar::default()
            .value(value)
            .style(Style::default().fg(gradient_color))
            .label(Line::from(if self.localize {
                format!(
                    "{} avg {} max {} min {}",
                    id,
                    sanitize_nbsp(avg.to_formatted_string(&self.locale)),
                    sanitize_nbsp(max.to_formatted_string(&self.locale)),
                    sanitize_nbsp(min.to_formatted_string(&self.locale))
                )
            } else {
                format!("{id} avg {avg} max {max} min {min}",)
            }))
            .text_value(if self.localize {
                sanitize_nbsp(value.to_formatted_string(&self.locale))
            } else {
                format!("{value}")
            })
    }

    /// Generates LLC bar charts.
    fn llc_bars(&self, event: &str) -> Vec<Bar<'_>> {
        self.llc_data
            .iter()
            .filter(|(_llc_id, llc_data)| llc_data.data.data.contains_key(event))
            .map(|(llc_id, llc_data)| {
                let divisor = match self.active_event {
                    ProfilingEvent::CpuUtil(_) => llc_data.num_cpus,
                    _ => 1,
                };
                let values = llc_data
                    .event_data_immut(event)
                    .iter()
                    .map(|&x| x / divisor as u64)
                    .collect::<Vec<u64>>();
                let value = values.last().copied().unwrap_or(0_u64);
                let stats = VecStats::new(&values, None);
                self.event_bar(*llc_id, value, stats.avg, stats.max, stats.min)
            })
            .collect()
    }

    /// Generates Node bar charts.
    fn node_bars(&self, event: &str) -> Vec<Bar<'_>> {
        self.node_data
            .iter()
            .filter(|(_node_id, node_data)| node_data.data.data.contains_key(event))
            .map(|(node_id, node_data)| {
                let divisor = match self.active_event {
                    ProfilingEvent::CpuUtil(_) => node_data.num_cpus,
                    _ => 1,
                };
                let values = node_data
                    .event_data_immut(event)
                    .iter()
                    .map(|&x| x / divisor as u64)
                    .collect::<Vec<u64>>();
                let value = values.last().copied().unwrap_or(0_u64);
                let stats = VecStats::new(&values, None);
                self.event_bar(*node_id, value, stats.avg, stats.max, stats.min)
            })
            .collect()
    }

    /// Renders scheduler stats.
    fn render_error_msg(&self, frame: &mut Frame, area: Rect, msg: &str) {
        frame.render_widget(Clear, area);

        let top_pad = area.height.saturating_sub(1) / 2;

        let mut lines: Vec<Line> = Vec::with_capacity(top_pad as usize + 1);
        for _ in 0..top_pad {
            lines.push(Line::raw(""));
        }
        lines.push(Line::from(Span::styled(
            msg,
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        )));

        let block = Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .style(Style::default().fg(Color::Red));

        let para = Paragraph::new(lines)
            .alignment(Alignment::Center)
            .block(block);

        frame.render_widget(para, area);
    }

    fn render_event_sparkline(&mut self, frame: &mut Frame, area: Rect) -> Result<()> {
        let num_nodes = self.topo.nodes.len();
        let constraints = vec![Constraint::Ratio(1, num_nodes.try_into().unwrap()); num_nodes];
        let node_areas = Layout::vertical(constraints).split(area);

        let area = frame.area();
        let area_events = if !self.large_core_count {
            (area.width / 4) as usize
        } else {
            (area.width / 8) as usize
        };
        if self.max_cpu_events != area_events {
            self.resize_events(area_events);
        }

        for (i, node) in self.topo.nodes.values().enumerate() {
            let node_constraints = vec![Constraint::Percentage(2), Constraint::Percentage(98)];
            let node_cpus = node.all_cpus.len();
            let [top, center] = Layout::vertical(node_constraints).areas(node_areas[i]);
            let col_scale = if node_cpus <= 128 { 2 } else { 4 };
            let mut cpus_constraints = Vec::with_capacity(node_cpus / col_scale);
            for _ in 0..node_cpus / col_scale {
                cpus_constraints.push(Constraint::Ratio(1, (node_cpus / col_scale) as u32));
            }
            let cpus_areas = Layout::vertical(cpus_constraints).split(center);
            let mut spark_areas = vec![];
            for j in 0..node_cpus / col_scale {
                let spark_constraints = vec![Constraint::Ratio(1, col_scale as u32); col_scale];
                spark_areas.push(Layout::horizontal(spark_constraints).split(cpus_areas[j]));
            }

            let node_iter = self
                .cpu_data
                .values()
                .filter(|cpu_data| cpu_data.node == node.id)
                .flat_map(|cpu_data| cpu_data.event_data_immut(self.active_event.event_name()))
                .collect::<Vec<u64>>();
            let stats = VecStats::new(&node_iter, None);

            let node_block = Block::bordered()
                .title_top(
                    Line::from(if self.localize {
                        format!(
                            "Node{} ({}) avg {} max {} min {}",
                            node.id,
                            self.active_event.event_name(),
                            sanitize_nbsp(stats.avg.to_formatted_string(&self.locale)),
                            sanitize_nbsp(stats.max.to_formatted_string(&self.locale)),
                            sanitize_nbsp(stats.min.to_formatted_string(&self.locale))
                        )
                    } else {
                        format!(
                            "Node{} ({}) avg {} max {} min {}",
                            node.id,
                            self.active_event.event_name(),
                            stats.avg,
                            stats.max,
                            stats.min,
                        )
                    })
                    .style(self.theme().title_style())
                    .centered(),
                )
                .title_top(if i == 0 {
                    Line::from(format!("{}ms", self.config.tick_rate_ms()))
                        .style(self.theme().text_important_color())
                        .right_aligned()
                } else {
                    Line::from("")
                })
                .title_top(
                    Line::from(if self.collect_uncore_freq {
                        "uncore ".to_string()
                            + format_hz(
                                self.node_data
                                    .get(&node.id)
                                    .expect("NodeData should have been present")
                                    .event_data_immut("uncore_freq")
                                    .last()
                                    .copied()
                                    .unwrap_or(0_u64),
                            )
                            .as_str()
                    } else {
                        "".to_string()
                    })
                    .style(self.theme().text_important_color())
                    .left_aligned(),
                )
                .border_type(BorderType::Rounded)
                .style(self.theme().border_style());

            frame.render_widget(node_block, top);

            let cpu_sparklines: Vec<Sparkline> = self
                .topo
                .all_cpus
                .values()
                .filter(|cpu| cpu.node_id == node.id)
                .enumerate()
                .map(|(j, cpu)| {
                    self.cpu_sparkline_with_gradient(
                        cpu.id,
                        stats.max,
                        stats.min,
                        if j > col_scale && j == node_cpus - col_scale {
                            Borders::LEFT | Borders::BOTTOM
                        } else if j > col_scale && j == node_cpus - 1 {
                            Borders::RIGHT | Borders::BOTTOM
                        } else if j > col_scale && j > node_cpus - col_scale {
                            Borders::BOTTOM
                        } else if j == 0 || j % col_scale == 0 {
                            Borders::LEFT
                        } else if j == col_scale - 1 || j % col_scale == col_scale - 1 {
                            Borders::RIGHT
                        } else {
                            Borders::NONE
                        },
                        node_cpus > 32,
                    )
                })
                .collect();

            cpu_sparklines
                .iter()
                .enumerate()
                .for_each(|(j, cpu_sparkline)| {
                    let area_id = (j as f64 / col_scale as f64).floor() as usize;
                    let spark_id = j % col_scale;
                    frame.render_widget(cpu_sparkline, spark_areas[area_id][spark_id]);
                });
        }
        Ok(())
    }

    fn render_event_barchart(&mut self, frame: &mut Frame, area: Rect) -> Result<()> {
        let num_nodes = self.topo.nodes.len();
        let constraints = vec![Constraint::Ratio(1, num_nodes.try_into().unwrap()); num_nodes];
        let node_areas = Layout::vertical(constraints).split(area);

        for (i, node) in self.topo.nodes.values().enumerate() {
            let node_iter = self
                .cpu_data
                .values()
                .filter(|cpu_data| cpu_data.node == node.id)
                .flat_map(|cpu_data| cpu_data.event_data_immut(self.active_event.event_name()))
                .collect::<Vec<u64>>();
            let stats = VecStats::new(&node_iter, None);

            let node_block = Block::bordered()
                .title_top(
                    Line::from(if self.localize {
                        format!(
                            "Node{} ({}) avg {} max {} min {}",
                            node.id,
                            self.active_event.event_name(),
                            sanitize_nbsp(stats.avg.to_formatted_string(&self.locale)),
                            sanitize_nbsp(stats.max.to_formatted_string(&self.locale)),
                            sanitize_nbsp(stats.min.to_formatted_string(&self.locale))
                        )
                    } else {
                        format!(
                            "Node{} ({}) avg {} max {} min {}",
                            node.id,
                            self.active_event.event_name(),
                            stats.avg,
                            stats.max,
                            stats.min,
                        )
                    })
                    .style(self.theme().text_important_color())
                    .centered(),
                )
                .title_top(if i == 0 {
                    Line::from(format!("{}ms", self.config.tick_rate_ms()))
                        .style(self.theme().text_important_color())
                        .right_aligned()
                } else {
                    Line::from("")
                })
                .title_top(
                    Line::from(if self.collect_uncore_freq {
                        "uncore ".to_string()
                            + format_hz(
                                self.node_data
                                    .get(&node.id)
                                    .expect("NodeData should have been present")
                                    .event_data_immut("uncore_freq")
                                    .last()
                                    .copied()
                                    .unwrap_or(0_u64),
                            )
                            .as_str()
                    } else {
                        "".to_string()
                    })
                    .style(self.theme().text_important_color())
                    .left_aligned(),
                )
                .border_type(BorderType::Rounded)
                .border_style(self.theme().border_style());

            let node_area = node_areas[i];
            let node_cpus = node.all_cpus.len();
            let col_scale = if node_cpus <= 128 { 2 } else { 4 };

            let cpus_constraints =
                vec![Constraint::Ratio(1, col_scale); col_scale.try_into().unwrap()];
            let cpus_areas =
                Layout::horizontal(cpus_constraints).split(node_block.inner(node_area));

            let mut bar_col_data: Vec<Vec<Bar>> = vec![Vec::new(); 4];
            let _: Vec<_> = node
                .all_cpus
                .keys()
                .enumerate()
                .map(|(j, cpu)| {
                    let cpu_bar = self.cpu_bar_with_gradient(
                        *cpu,
                        self.active_event.event_name(),
                        stats.min,
                        stats.max,
                    );
                    bar_col_data[j % col_scale as usize].push(cpu_bar);
                })
                .collect();

            for (j, col_data) in bar_col_data.iter().enumerate() {
                let bar_chart = BarChart::default()
                    .data(BarGroup::default().bars(col_data))
                    .max(stats.max)
                    .direction(Direction::Horizontal)
                    .bar_gap(0)
                    .bar_width(1);
                frame.render_widget(bar_chart, cpus_areas[j % col_scale as usize]);
            }
            frame.render_widget(node_block, node_area);
        }
        Ok(())
    }

    fn render_event_linegauge(&mut self, frame: &mut Frame, area: Rect) -> Result<()> {
        let num_nodes = self.topo.nodes.len();
        let constraints = vec![Constraint::Ratio(1, num_nodes.try_into().unwrap()); num_nodes];
        let node_areas = Layout::vertical(constraints).split(area);

        for (i, node) in self.topo.nodes.values().enumerate() {
            let node_iter = self
                .cpu_data
                .values()
                .filter(|cpu_data| cpu_data.node == node.id)
                .flat_map(|cpu_data| cpu_data.event_data_immut(self.active_event.event_name()))
                .collect::<Vec<u64>>();
            let stats = VecStats::new(&node_iter, None);

            let node_block = Block::bordered()
                .title_top(
                    Line::from(if self.localize {
                        format!(
                            "Node{} ({}) avg {} max {} min {}",
                            node.id,
                            self.active_event.event_name(),
                            sanitize_nbsp(stats.avg.to_formatted_string(&self.locale)),
                            sanitize_nbsp(stats.max.to_formatted_string(&self.locale)),
                            sanitize_nbsp(stats.min.to_formatted_string(&self.locale))
                        )
                    } else {
                        format!(
                            "Node{} ({}) avg {} max {} min {}",
                            node.id,
                            self.active_event.event_name(),
                            stats.avg,
                            stats.max,
                            stats.min,
                        )
                    })
                    .style(self.theme().title_style())
                    .centered(),
                )
                .title_top(if i == 0 {
                    Line::from(format!("{}ms", self.config.tick_rate_ms()))
                        .style(self.theme().text_important_color())
                        .right_aligned()
                } else {
                    Line::from("")
                })
                .title_top(
                    Line::from(if self.collect_uncore_freq {
                        "uncore ".to_string()
                            + format_hz(
                                self.node_data
                                    .get(&node.id)
                                    .expect("NodeData should have been present")
                                    .event_data_immut("uncore_freq")
                                    .last()
                                    .copied()
                                    .unwrap_or(0_u64),
                            )
                            .as_str()
                    } else {
                        "".to_string()
                    })
                    .style(self.theme().text_important_color())
                    .left_aligned(),
                )
                .border_type(BorderType::Rounded);

            let node_area = node_areas[i];
            let node_cpus = node.all_cpus.len();
            let col_scale = if node_cpus <= 128 { 2 } else { 4 };

            // Create horizontal layout for columns
            let cpus_constraints =
                vec![Constraint::Ratio(1, col_scale); col_scale.try_into().unwrap()];
            let cpus_areas =
                Layout::horizontal(cpus_constraints).split(node_block.inner(node_area));

            // Distribute CPUs into columns
            let mut cpu_col_data: Vec<Vec<usize>> = vec![Vec::new(); col_scale as usize];
            for (j, cpu) in node.all_cpus.keys().enumerate() {
                cpu_col_data[j % col_scale as usize].push(*cpu);
            }

            // Render each column
            for (col_idx, col_cpus) in cpu_col_data.iter().enumerate() {
                if col_cpus.is_empty() {
                    continue;
                }

                let col_area = cpus_areas[col_idx];
                let available_height = col_area.height as usize;
                let num_cpus_in_col = col_cpus.len().min(available_height);

                if num_cpus_in_col == 0 {
                    continue;
                }

                // Create vertical layout for CPUs in this column
                let cpu_constraints = vec![Constraint::Length(1); num_cpus_in_col];
                let cpu_areas = Layout::vertical(cpu_constraints).split(col_area);

                // Render LineGauge for each CPU in this column
                for (cpu_idx, &cpu) in col_cpus.iter().take(num_cpus_in_col).enumerate() {
                    let cpu_data = self.cpu_data.get(&cpu);
                    let current_value = if let Some(data) = cpu_data {
                        data.event_data_immut(self.active_event.event_name())
                            .last()
                            .copied()
                            .unwrap_or(0)
                    } else {
                        0
                    };

                    // Calculate utilization ratio (0.0 to 1.0) based on max value
                    let ratio = if stats.max > 0 {
                        (current_value as f64 / stats.max as f64).clamp(0.0, 1.0)
                    } else {
                        0.0
                    };

                    // Get colorization based on the ratio (0-100 scale for gradient function)
                    let ratio_scaled = (ratio * 100.0) as u64;
                    let gradient_color = self.gradient5_color(ratio_scaled, 100, 0);

                    // Get CPU frequency and HW pressure info for label
                    let mut cpu_freq: u64 = 0;
                    let mut hw_pressure: u64 = 0;
                    if let Some(data) = cpu_data {
                        if self.collect_cpu_freq {
                            cpu_freq = data
                                .event_data_immut("cpu_freq")
                                .last()
                                .copied()
                                .unwrap_or(0);
                        }
                        if self.hw_pressure {
                            hw_pressure = data
                                .event_data_immut("hw_pressure")
                                .last()
                                .copied()
                                .unwrap_or(0);
                        }
                    }

                    let label = format!(
                        "CPU{}{}{} {}",
                        cpu,
                        if self.collect_cpu_freq {
                            format!(" {}", format_hz(cpu_freq))
                        } else {
                            "".to_string()
                        },
                        if self.hw_pressure && hw_pressure > 0 {
                            format!(" hw_pressure({hw_pressure})")
                        } else {
                            "".to_string()
                        },
                        if self.localize {
                            sanitize_nbsp(current_value.to_formatted_string(&self.locale))
                        } else {
                            format!("{current_value}")
                        }
                    );

                    let line_gauge = LineGauge::default()
                        .ratio(ratio)
                        .label(Line::from(label).style(self.theme().text_color()))
                        .line_set(THICK)
                        .filled_style(Style::default().fg(gradient_color))
                        .unfilled_style(
                            Style::default().fg(self
                                .theme()
                                .border_style()
                                .fg
                                .unwrap_or(Color::Gray)),
                        );

                    frame.render_widget(line_gauge, cpu_areas[cpu_idx]);
                }
            }

            frame.render_widget(node_block, node_area);
        }
        Ok(())
    }

    /// Renders the event state.
    fn render_event(&mut self, frame: &mut Frame, area: Rect) -> Result<()> {
        match self.view_state {
            ViewState::Sparkline => self.render_event_sparkline(frame, area)?,
            ViewState::BarChart => self.render_event_barchart(frame, area)?,
            ViewState::LineGauge => self.render_event_linegauge(frame, area)?,
        }
        Ok(())
    }

    /// Renders the default application state.
    fn render_default(&mut self, frame: &mut Frame) -> Result<()> {
        let [left, right] = Layout::horizontal([Constraint::Fill(1); 2]).areas(frame.area());

        self.render_event(frame, right)?;

        // Determine how to split the left area based on memory and network view states
        let show_memory = self.memory_view_state == ComponentViewState::Default;
        let show_network = self.network_view_state == ComponentViewState::Default;

        match (show_memory, show_network) {
            (false, false) => {
                // Neither memory nor network summary shown, process table takes the entire left side
                self.render_table(frame, left, false)?;
            }
            (true, false) => {
                // Only memory summary is shown, split between table and memory
                let [table_area, memory_area] =
                    Layout::vertical([Constraint::Fill(10), Constraint::Min(8)]).areas(left);
                self.render_table(frame, table_area, false)?;
                self.render_memory_summary(frame, memory_area)?;
            }
            (false, true) => {
                // Only network summary is shown, split between table and network
                let [table_area, network_area] =
                    Layout::vertical([Constraint::Fill(10), Constraint::Min(8)]).areas(left);
                self.render_table(frame, table_area, false)?;
                self.render_network_summary(frame, network_area)?;
            }
            (true, true) => {
                // Both memory and network summaries are shown, split into three areas
                let [table_area, memory_area, network_area] = Layout::vertical([
                    Constraint::Fill(10),
                    Constraint::Min(8),
                    Constraint::Min(8),
                ])
                .areas(left);
                self.render_table(frame, table_area, false)?;
                self.render_memory_summary(frame, memory_area)?;
                self.render_network_summary(frame, network_area)?;
            }
        }

        Ok(())
    }

    /// Renders a memory summary in the default view.
    fn render_memory_summary(&mut self, frame: &mut Frame, area: Rect) -> Result<()> {
        // Only render memory summary if the memory view state is Default
        if self.memory_view_state != ComponentViewState::Default {
            anyhow::bail!("invalid memory view state: ComponentViewState::Default");
        }

        let theme = self.theme();
        MemoryRenderer::render_memory_summary(
            frame,
            area,
            &self.mem_info,
            &self.config.active_keymap,
            theme,
        )
    }

    /// Renders a simplified network summary for the default view.
    fn render_network_summary(&mut self, frame: &mut Frame, area: Rect) -> Result<()> {
        let theme = self.theme();
        NetworkRenderer::render_network_summary(
            frame,
            area,
            &self.network_stats,
            &self.config.active_keymap,
            self.localize,
            &self.locale,
            theme,
        )
    }

    /// Renders the application to the frame.
    pub fn render(&mut self, frame: &mut Frame) -> Result<()> {
        let area = frame.area();
        // Update terminal width for overhead history sizing
        self.terminal_width = area.width;
        match self.state {
            AppState::BpfPrograms => self.render_bpf_programs(frame),
            AppState::BpfProgramDetail => self.render_bpf_program_detail(frame),
            AppState::Help => self.render_help(frame),
            AppState::PerfEvent | AppState::KprobeEvent => self.render_event_list(frame),
            AppState::Process => self.render_table(frame, area, true),
            AppState::MangoApp => self.render_mangoapp(frame),
            AppState::Memory => self.render_memory(frame),
            AppState::Network => self.render_network(frame),
            AppState::Node => self.render_node(frame),
            AppState::Llc => self.render_llc(frame),
            AppState::PerfTop => self.render_perf_top(frame),
            AppState::Power => self.render_power(frame),
            AppState::Scheduler => {
                if self.has_capability_warnings() {
                    self.render_capability_warnings(frame, area)?;
                    return Ok(());
                }
                let [left, right] = Layout::horizontal([Constraint::Fill(1); 2]).areas(area);
                let [left_top, left_center, left_bottom] = Layout::vertical([
                    Constraint::Ratio(1, 3),
                    Constraint::Ratio(1, 3),
                    Constraint::Ratio(1, 3),
                ])
                .areas(left);
                let [right_top, right_bottom] =
                    Layout::vertical(vec![Constraint::Ratio(2, 3), Constraint::Ratio(1, 3)])
                        .areas(right);

                let sample_rate = self
                    .skel
                    .as_ref()
                    .map(|s| s.maps.data_data.as_ref().unwrap().sample_rate)
                    .unwrap_or(0);

                let params1 = SchedulerViewParams {
                    event: "dsq_lat_us",
                    scheduler_name: &self.scheduler,
                    dsq_data: &self.dsq_data,
                    sample_rate,
                    localize: self.localize,
                    locale: &self.locale,
                    theme: self.theme(),
                    render_title: false,
                    render_sample_rate: true,
                };
                let new_max = SchedulerRenderer::render_scheduler_view(
                    frame,
                    left_top,
                    &self.view_state,
                    self.max_sched_events,
                    &params1,
                )?;
                self.max_sched_events = new_max;

                let params2 = SchedulerViewParams {
                    event: "dsq_slice_consumed",
                    scheduler_name: &self.scheduler,
                    dsq_data: &self.dsq_data,
                    sample_rate,
                    localize: self.localize,
                    locale: &self.locale,
                    theme: self.theme(),
                    render_title: false,
                    render_sample_rate: false,
                };
                SchedulerRenderer::render_scheduler_view(
                    frame,
                    left_center,
                    &self.view_state,
                    self.max_sched_events,
                    &params2,
                )?;

                let params3 = SchedulerViewParams {
                    event: "dsq_vtime",
                    scheduler_name: &self.scheduler,
                    dsq_data: &self.dsq_data,
                    sample_rate,
                    localize: self.localize,
                    locale: &self.locale,
                    theme: self.theme(),
                    render_title: false,
                    render_sample_rate: false,
                };
                SchedulerRenderer::render_scheduler_view(
                    frame,
                    left_bottom,
                    &self.view_state,
                    self.max_sched_events,
                    &params3,
                )?;

                let params4 = SchedulerViewParams {
                    event: "dsq_nr_queued",
                    scheduler_name: &self.scheduler,
                    dsq_data: &self.dsq_data,
                    sample_rate,
                    localize: self.localize,
                    locale: &self.locale,
                    theme: self.theme(),
                    render_title: false,
                    render_sample_rate: false,
                };
                SchedulerRenderer::render_scheduler_view(
                    frame,
                    right_bottom,
                    &self.view_state,
                    self.max_sched_events,
                    &params4,
                )?;
                let stats_params = SchedulerStatsParams {
                    scheduler_name: &self.scheduler,
                    sched_stats_raw: &self.sched_stats_raw,
                    tick_rate_ms: self.config.tick_rate_ms(),
                    dispatch_keep_last: self.scx_stats.dispatch_keep_last,
                    select_cpu_fallback: self.scx_stats.select_cpu_fallback,
                    theme: self.theme(),
                };
                SchedulerRenderer::render_scheduler_stats(frame, right_top, &stats_params)
            }
            AppState::Tracing => self.render_tracing(frame),
            _ => self.render_default(frame),
        }
    }

    /// Renders the help TUI.
    fn render_help(&mut self, frame: &mut Frame) -> Result<()> {
        let area = frame.area();
        let theme = self.theme();
        let mut pause = self
            .config
            .active_keymap
            .action_keys_string(Action::SetState(AppState::Pause));
        if pause == " " {
            pause = "Space".to_string();
        }
        let text = vec![
            Line::from(Span::styled(
                LICENSE,
                Style::default().add_modifier(Modifier::ITALIC),
            )),
            "\n".into(),
            "\n".into(),
            Line::from(Span::styled("General Key Bindings:", Style::default())),
            Line::from(Span::styled(
                format!(
                    "{}: (press to exit help)",
                    self.config
                        .active_keymap
                        .action_keys_string(Action::SetState(AppState::Help))
                ),
                Style::default(),
            )),
            Line::from(Span::styled(
                format!(
                    "{}: quit",
                    self.config.active_keymap.action_keys_string(Action::Quit),
                ),
                Style::default(),
            )),
            Line::from(Span::styled(
                format!("{pause}: pause/unpause"),
                Style::default(),
            )),
            Line::from(Span::styled(
                format!(
                    "{}: list scroll up",
                    self.config.active_keymap.action_keys_string(Action::Up)
                ),
                Style::default(),
            )),
            Line::from(Span::styled(
                format!(
                    "{}: list scroll down",
                    self.config.active_keymap.action_keys_string(Action::Down)
                ),
                Style::default(),
            )),
            Line::from(Span::styled(
                format!(
                    "{}: list scroll page up",
                    self.config.active_keymap.action_keys_string(Action::PageUp)
                ),
                Style::default(),
            )),
            Line::from(Span::styled(
                format!(
                    "{}: list scroll page down",
                    self.config
                        .active_keymap
                        .action_keys_string(Action::PageDown)
                ),
                Style::default(),
            )),
            Line::from(Span::styled(
                format!(
                    "{}: record perfetto trace",
                    self.config
                        .active_keymap
                        .action_keys_string(Action::RequestTrace),
                ),
                Style::default(),
            )),
            Line::from(Span::styled(
                format!(
                    "{}: Enable CPU frequency ({})",
                    self.config
                        .active_keymap
                        .action_keys_string(Action::ToggleCpuFreq),
                    self.collect_cpu_freq
                ),
                Style::default(),
            )),
            Line::from(Span::styled(
                format!(
                    "{}: Enable localization ({})",
                    self.config
                        .active_keymap
                        .action_keys_string(Action::ToggleLocalization),
                    self.localize
                ),
                Style::default(),
            )),
            Line::from(Span::styled(
                format!(
                    "{}: Enable uncore frequency ({})",
                    self.config
                        .active_keymap
                        .action_keys_string(Action::ToggleUncoreFreq),
                    self.collect_uncore_freq
                ),
                Style::default(),
            )),
            "\n".into(),
            Line::from(Span::styled("Event Key Bindings:", Style::default())),
            Line::from(Span::styled(
                format!(
                    "{}: show CPU perf event menu",
                    self.config
                        .active_keymap
                        .action_keys_string(Action::SetState(AppState::PerfEvent))
                ),
                Style::default(),
            )),
            Line::from(Span::styled(
                format!(
                    "{}: show kprobe event menu",
                    self.config
                        .active_keymap
                        .action_keys_string(Action::SetState(AppState::KprobeEvent))
                ),
                Style::default(),
            )),
            Line::from(Span::styled(
                format!(
                    "{}: clear active profiling events",
                    self.config
                        .active_keymap
                        .action_keys_string(Action::ClearEvent),
                ),
                Style::default(),
            )),
            Line::from(Span::styled(
                format!(
                    "{}: next profiling event",
                    self.config
                        .active_keymap
                        .action_keys_string(Action::NextEvent),
                ),
                Style::default(),
            )),
            Line::from(Span::styled(
                format!(
                    "{}: previous profiling event",
                    self.config
                        .active_keymap
                        .action_keys_string(Action::PrevEvent)
                ),
                Style::default(),
            )),
            "\n".into(),
            Line::from(Span::styled("View Key Bindings:", Style::default())),
            Line::from(Span::styled(
                format!(
                    "{}: filter processes/threads",
                    self.config.active_keymap.action_keys_string(Action::Filter)
                ),
                Style::default(),
            )),
            Line::from(Span::styled(
                format!(
                    "{}: display BPF programs view",
                    self.config
                        .active_keymap
                        .action_keys_string(Action::SetState(AppState::BpfPrograms))
                ),
                Style::default(),
            )),
            Line::from(Span::styled(
                format!(
                    "{}: display process view",
                    self.config
                        .active_keymap
                        .action_keys_string(Action::SetState(AppState::Process))
                ),
                Style::default(),
            )),
            Line::from(Span::styled(
                format!(
                    "{}: display default view",
                    self.config
                        .active_keymap
                        .action_keys_string(Action::SetState(AppState::Default))
                ),
                Style::default(),
            )),
            Line::from(Span::styled(
                format!(
                    "{}: display LLC view",
                    self.config
                        .active_keymap
                        .action_keys_string(Action::SetState(AppState::Llc))
                ),
                Style::default(),
            )),
            Line::from(Span::styled(
                format!(
                    "{}: display NUMA Node view",
                    self.config
                        .active_keymap
                        .action_keys_string(Action::SetState(AppState::Node))
                ),
                Style::default(),
            )),
            Line::from(Span::styled(
                format!(
                    "{}: display Network view",
                    self.config
                        .active_keymap
                        .action_keys_string(Action::SetState(AppState::Network))
                ),
                Style::default(),
            )),
            Line::from(Span::styled(
                format!(
                    "{}: display scheduler view",
                    self.config
                        .active_keymap
                        .action_keys_string(Action::SetState(AppState::Scheduler))
                ),
                Style::default(),
            )),
            Line::from(Span::styled(
                format!(
                    "{}: display perf top view (symbolized sampling)",
                    self.config
                        .active_keymap
                        .action_keys_string(Action::SetState(AppState::PerfTop))
                ),
                Style::default(),
            )),
            Line::from(Span::styled(
                format!(
                    "{}: display power monitoring view",
                    self.config
                        .active_keymap
                        .action_keys_string(Action::SetState(AppState::Power))
                ),
                Style::default(),
            )),
            Line::from(Span::styled(
                format!(
                    "{}: display next memory view ({})",
                    self.config
                        .active_keymap
                        .action_keys_string(Action::SetState(AppState::Memory)),
                    self.memory_view_state
                ),
                Style::default(),
            )),
            Line::from(Span::styled(
                format!(
                    "{}: change theme ({})",
                    self.config
                        .active_keymap
                        .action_keys_string(Action::ChangeTheme),
                    serde_json::to_string_pretty(&theme)?
                ),
                Style::default(),
            )),
            Line::from(Span::styled(
                format!(
                    "{}: change view state ({})",
                    self.config
                        .active_keymap
                        .action_keys_string(Action::NextViewState),
                    self.view_state
                ),
                Style::default(),
            )),
            "\n".into(),
            Line::from(Span::styled("Adjust Rates:", Style::default())),
            Line::from(Span::styled(
                format!(
                    "{}: decrease tick rate ({}ms)",
                    self.config
                        .active_keymap
                        .action_keys_string(Action::DecTickRate),
                    self.config.tick_rate_ms()
                ),
                Style::default(),
            )),
            Line::from(Span::styled(
                format!(
                    "{}: increase tick rate ({}ms)",
                    self.config
                        .active_keymap
                        .action_keys_string(Action::IncTickRate),
                    self.config.tick_rate_ms()
                ),
                Style::default(),
            )),
            Line::from(Span::styled(
                format!(
                    "{}: decrease bpf sample rate ({})",
                    self.config
                        .active_keymap
                        .action_keys_string(Action::DecBpfSampleRate),
                    if let Some(ref skel) = self.skel {
                        skel.maps.data_data.as_ref().unwrap().sample_rate
                    } else {
                        0
                    }
                ),
                Style::default(),
            )),
            Line::from(Span::styled(
                format!(
                    "{}: increase bpf sample rate ({})",
                    self.config
                        .active_keymap
                        .action_keys_string(Action::IncBpfSampleRate),
                    if let Some(ref skel) = self.skel {
                        skel.maps.data_data.as_ref().unwrap().sample_rate
                    } else {
                        0
                    }
                ),
                Style::default(),
            )),
            "\n".into(),
            Line::from(Span::styled(
                format!(
                    "{}: Saves the current config ({})",
                    self.config
                        .active_keymap
                        .action_keys_string(Action::SaveConfig),
                    get_config_path()?.to_string_lossy()
                ),
                Style::default(),
            )),
            "\n".into(),
            Line::from(Span::styled(
                "For bug reporting and project updates, visit:",
                Style::default(),
            )),
            Line::from(Span::styled(
                "https://github.com/sched-ext/scx",
                Style::default(),
            )),
        ];
        frame.render_widget(
            Paragraph::new(text)
                .block(
                    Block::default()
                        .title_top(Line::from(APP).style(self.theme().title_style()).centered())
                        .borders(Borders::ALL)
                        .border_type(BorderType::Rounded),
                )
                .style(self.theme().border_style())
                .alignment(Alignment::Left),
            area,
        );
        Ok(())
    }

    /// Renders the event list TUI.
    fn render_event_list(&mut self, frame: &mut Frame) -> Result<()> {
        let area = frame.area();
        let default_style = Style::default().fg(self.theme().text_color());
        let chunks = Layout::vertical([
            Constraint::Min(1),
            Constraint::Percentage(98),
            Constraint::Min(3),
        ])
        .split(area);

        self.update_events_list_size(area);

        let list_type = match self.state {
            AppState::PerfEvent => "perf",
            AppState::KprobeEvent => "kprobe",
            _ => bail!("Invalid AppState in event list"),
        };

        let title = Block::new()
            .style(default_style)
            .title_alignment(Alignment::Center)
            .title(
                format!(
                    "Type to filter {} list, use ▲ ▼  ({}/{}) to scroll, {} to select, Esc to exit",
                    list_type,
                    self.config.active_keymap.action_keys_string(Action::PageUp),
                    self.config
                        .active_keymap
                        .action_keys_string(Action::PageDown),
                    self.config.active_keymap.action_keys_string(Action::Enter),
                )
                .bold(),
            );
        frame.render_widget(title, chunks[0]);

        let filtered_state = self.filtered_state.lock().unwrap();

        let events: Vec<Line> = filtered_state
            .list
            .iter()
            .enumerate()
            .map(|(i, event)| {
                if i == filtered_state.selected {
                    Line::from(event.as_string()).fg(self.theme().text_important_color())
                } else {
                    Line::from(event.as_string()).fg(self.theme().text_color())
                }
            })
            .collect();

        let paragraph = Paragraph::new(events)
            .style(default_style)
            .scroll((filtered_state.scroll, 0));
        frame.render_widget(paragraph, chunks[1]);

        let input_box = Paragraph::new(format!("# > {}", self.event_input_buffer))
            .style(default_style)
            .bold()
            .block(Block::new().borders(Borders::ALL));
        frame.render_widget(input_box, chunks[2]);

        frame.render_stateful_widget(
            Scrollbar::new(ScrollbarOrientation::VerticalRight)
                .begin_symbol(Some("↑"))
                .end_symbol(Some("↓")),
            chunks[1],
            &mut ScrollbarState::new(filtered_state.count.into())
                .position(filtered_state.scroll as usize),
        );

        Ok(())
    }

    /// Renders the tracing state.
    fn render_tracing(&mut self, frame: &mut Frame) -> Result<()> {
        let block = Block::new()
            .title_top(
                Line::from(self.scheduler.clone())
                    .style(self.theme().title_style())
                    .centered(),
            )
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .style(self.theme().border_style());

        let label = Span::styled(
            format!(
                "recording trace to {}. {} dropped events.",
                self.trace_manager.trace_file(),
                self.bpf_stats.dropped_events
            ),
            self.theme().title_style(),
        );
        let gauge = Gauge::default()
            .block(block)
            .gauge_style(self.theme().text_important_color())
            .ratio({
                let now = std::time::Duration::from(nix::time::clock_gettime(
                    nix::time::ClockId::CLOCK_MONOTONIC,
                )?)
                .as_nanos() as u64;
                (((now as f64) - self.trace_start as f64)
                    / (self.config.trace_duration_ns() as f64))
                    .clamp(0.0_f64, 1.0_f64)
            })
            .label(label);
        frame.render_widget(gauge, frame.area());

        Ok(())
    }

    /// Handles MangoApp pressure events.
    pub fn on_mangoapp(&mut self, action: &MangoAppAction) -> Result<()> {
        self.last_mangoapp_action = Some(action.clone());
        // Update the profiling event to the mangoapp event
        if action.pid as i32 != self.process_id && action.pid > 0 {
            self.prev_process_id = self.process_id;
            self.process_id = action.pid as i32;
            // reactivate the active profiling event with the pid from mangoapp
            if self.has_perf_cap {
                let prof_event = &self.available_events[self.active_hw_event_id].clone();
                let _ = self.activate_prof_event(prof_event);
            }
        }
        Ok(())
    }

    /// Renders the mangoapp TUI.
    fn render_mangoapp(&mut self, frame: &mut Frame) -> Result<()> {
        let [left, right] = Layout::horizontal([Constraint::Fill(1); 2]).areas(frame.area());

        let left_constraints = vec![
            Constraint::Percentage(2),
            Constraint::Percentage(49),
            Constraint::Percentage(49),
        ];
        let left_areas = Layout::vertical(left_constraints).split(left);
        let theme = self.theme();

        let mut comm = if self.process_id > 0 {
            read_file_string(&format!("/proc/{}/comm", self.process_id)).unwrap_or("".to_string())
        } else {
            "".to_string()
        };
        comm = comm.trim_end().to_string();
        let last_action = self.last_mangoapp_action.clone();

        let block = Block::new()
            .title_top(
                Line::from(if let Some(action) = last_action {
                    format!(
                        "{}:{} {}x{}:{}",
                        comm,
                        self.process_id,
                        action.output_width,
                        action.output_height,
                        action.display_refresh,
                    )
                } else {
                    "mangoapp not available".to_string()
                })
                .style(theme.title_style())
                .centered(),
            )
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .style(theme.border_style());

        self.render_event(frame, right)?;
        frame.render_widget(block, left_areas[0]);

        let sample_rate = self
            .skel
            .as_ref()
            .map(|s| s.maps.data_data.as_ref().unwrap().sample_rate)
            .unwrap_or(0);

        let params1 = SchedulerViewParams {
            event: "dsq_lat_us",
            scheduler_name: &self.scheduler,
            dsq_data: &self.dsq_data,
            sample_rate,
            localize: self.localize,
            locale: &self.locale,
            theme: self.theme(),
            render_title: false,
            render_sample_rate: true,
        };
        SchedulerRenderer::render_scheduler_view(
            frame,
            left_areas[1],
            &self.view_state,
            self.max_sched_events,
            &params1,
        )?;

        let params2 = SchedulerViewParams {
            event: "dsq_slice_consumed",
            scheduler_name: &self.scheduler,
            dsq_data: &self.dsq_data,
            sample_rate,
            localize: self.localize,
            locale: &self.locale,
            theme: self.theme(),
            render_title: false,
            render_sample_rate: false,
        };
        SchedulerRenderer::render_scheduler_view(
            frame,
            left_areas[2],
            &self.view_state,
            self.max_sched_events,
            &params2,
        )?;

        Ok(())
    }

    /// Common helper to update events list size
    fn update_events_list_size(&mut self, area: Rect) {
        let height = if area.height > 0 { area.height - 1 } else { 1 };
        if height != self.events_list_size {
            self.events_list_size = height;
        }
    }

    /// Render the process view.
    fn render_process_table(
        &mut self,
        frame: &mut Frame,
        area: Rect,
        render_tick_rate: bool,
    ) -> Result<()> {
        let visible_columns: Vec<_> = self.process_columns.visible_columns().collect();
        let filtered_state = self.filtered_state.lock().unwrap();
        let sample_rate = self
            .skel
            .as_ref()
            .map(|s| s.maps.data_data.as_ref().unwrap().sample_rate)
            .unwrap_or(0);

        let theme = self.theme();
        let (selected_pid, new_size) = ProcessRenderer::render_process_table(
            frame,
            area,
            &self.proc_data,
            visible_columns,
            &filtered_state,
            self.filtering,
            &self.event_input_buffer,
            sample_rate,
            self.config.tick_rate_ms(),
            render_tick_rate,
            theme,
            self.events_list_size,
        )?;

        self.events_list_size = new_size;
        if let Some(pid) = selected_pid {
            self.selected_process = Some(pid);
        }

        Ok(())
    }

    fn render_thread_table(
        &mut self,
        frame: &mut Frame,
        area: Rect,
        render_tick_rate: bool,
    ) -> Result<()> {
        let error_str = format!(
            "Process has been killed. Press escape or {} to return to process view.",
            self.config.active_keymap.action_keys_string(Action::Quit)
        );
        let Some(tgid) = self.selected_process else {
            self.render_error_msg(frame, area, &error_str);
            return Ok(());
        };
        let Some(proc_data) = self.proc_data.get(&tgid) else {
            self.render_error_msg(frame, area, &error_str);
            return Ok(());
        };

        let visible_columns: Vec<_> = self.thread_columns.visible_columns().collect();
        let filtered_state = self.filtered_state.lock().unwrap();
        let sample_rate = self
            .skel
            .as_ref()
            .map(|s| s.maps.data_data.as_ref().unwrap().sample_rate)
            .unwrap_or(0);
        let _quit_keys = self.config.active_keymap.action_keys_string(Action::Quit);
        let theme = self.theme();

        let new_size = ProcessRenderer::render_thread_table(
            frame,
            area,
            tgid,
            proc_data,
            visible_columns,
            &filtered_state,
            self.filtering,
            &self.event_input_buffer,
            sample_rate,
            self.config.tick_rate_ms(),
            render_tick_rate,
            theme,
            self.events_list_size,
        )?;

        self.events_list_size = new_size;
        Ok(())
    }

    fn render_table(
        &mut self,
        frame: &mut Frame,
        area: Rect,
        render_tick_rate: bool,
    ) -> Result<()> {
        if self.in_thread_view {
            self.render_thread_table(frame, area, render_tick_rate)
        } else {
            self.render_process_table(frame, area, render_tick_rate)
        }
    }

    /// Renders the perf top view with symbolized samples.
    fn render_perf_top(&mut self, frame: &mut Frame) -> Result<()> {
        let area = frame.area();
        if self.has_capability_warnings() {
            self.render_capability_warnings(frame, area)?;
            return Ok(());
        }

        // Split the area into left (table) and right (details) sections
        let [left_area, right_area] = Layout::horizontal([
            Constraint::Percentage(50), // Symbol table
            Constraint::Percentage(50), // Symbol details
        ])
        .areas(area);
        // Get the top symbols and convert to owned data
        let max_symbols = (left_area.height as usize).saturating_sub(4); // Account for borders and header
        let top_symbols_borrowed = self.symbol_data.get_top_symbols(max_symbols);

        // Convert to owned data to avoid borrowing issues
        let top_symbols: Vec<crate::symbol_data::SymbolSample> =
            top_symbols_borrowed.iter().map(|s| (*s).clone()).collect();

        // Ensure selected index is within bounds
        if self.selected_symbol_index >= top_symbols.len() && !top_symbols.is_empty() {
            self.selected_symbol_index = top_symbols.len() - 1;
        }

        // Render left side - symbol table
        self.render_symbol_table(frame, left_area)?;

        // Render right side - symbol details
        self.render_symbol_details(frame, right_area, &top_symbols)?;

        Ok(())
    }

    /// Renders the symbol table on the left side
    fn render_symbol_table(&mut self, frame: &mut Frame, area: Rect) -> Result<()> {
        let total_samples = self.symbol_data.total_samples();
        let block = Block::bordered()
            .title_top(
                Line::from({
                    let filtered_count = self.perf_top_filtered_symbols.len();
                    if self.filtering && !self.event_input_buffer.is_empty() {
                        format!(
                            "Perf Top - {} of {} symbols ({} samples)",
                            filtered_count,
                            self.symbol_data.get_top_symbols(1000).len(),
                            total_samples
                        )
                    } else {
                        format!("Perf Top - {total_samples} samples")
                    }
                })
                .style(self.theme().title_style())
                .centered(),
            )
            .title_top(
                Line::from({
                    format!(
                        "sample rate {} --- {}ms",
                        self.perf_sample_rate,
                        self.config.tick_rate_ms()
                    )
                })
                .style(self.theme().text_important_color())
                .right_aligned(),
            )
            .title_top(
                Line::from(vec![
                    Span::styled("f", self.theme().text_important_color()),
                    Span::styled(
                        if self.filtering {
                            format!(" {}_", self.event_input_buffer)
                        } else {
                            "ilter".to_string()
                        },
                        self.theme().text_color(),
                    ),
                ])
                .left_aligned(),
            )
            .title_bottom(
                Line::from(vec![
                    Span::styled(
                        "[K] ",
                        Style::default().fg(self.theme().kernel_symbol_color()),
                    ),
                    Span::styled("Kernel  ", Style::default().fg(self.theme().text_color())),
                    Span::styled(
                        "[U] ",
                        Style::default().fg(self.theme().userspace_symbol_color()),
                    ),
                    Span::styled("Userspace ", Style::default().fg(self.theme().text_color())),
                ])
                .left_aligned(),
            )
            .title_bottom(
                Line::from({
                    let clear_key = self
                        .config
                        .active_keymap
                        .action_keys_string(Action::ClearEvent);
                    let inc_key = self
                        .config
                        .active_keymap
                        .action_keys_string(Action::IncBpfSampleRate);
                    let dec_key = self
                        .config
                        .active_keymap
                        .action_keys_string(Action::DecBpfSampleRate);
                    let up_key = self.config.active_keymap.action_keys_string(Action::Up);
                    let down_key = self.config.active_keymap.action_keys_string(Action::Down);

                    format!(
                        "clear [{clear_key}]  • {dec_key}/{inc_key} adjust rate • {up_key}/{down_key} navigate"
                    )
                })
                .style(self.theme().text_color())
                .right_aligned(),
            )
            .border_type(BorderType::Rounded)
            .style(self.theme().border_style());

        // Extract colors first to avoid borrow conflicts
        let kernel_color = self.theme().kernel_symbol_color();
        let userspace_color = self.theme().userspace_symbol_color();
        let text_important_color = self.theme().text_important_color();
        let text_color = self.theme().text_color();

        // Create table header manually to avoid borrowing conflicts
        let visible_columns: Vec<_> = self.perf_top_columns.visible_columns().collect();

        let header = visible_columns
            .iter()
            .map(|col| Cell::from(col.header))
            .collect::<Row>()
            .height(1)
            .style(text_color)
            .bold()
            .underlined();

        let constraints = visible_columns
            .iter()
            .map(|col| col.constraint)
            .collect::<Vec<_>>();

        // Use filtered symbols for display - clone to avoid borrowing conflicts
        let symbol_data = self.perf_top_filtered_symbols.clone();

        let rows: Vec<Row> = symbol_data
            .iter()
            .map(|(symbol_name, sample)| {
                let style = if sample.is_kernel {
                    Style::default().fg(kernel_color)
                } else {
                    Style::default().fg(userspace_color)
                };

                visible_columns
                    .iter()
                    .map(|col| {
                        let cell_value = (col.value_fn)(symbol_name.clone(), sample);
                        Cell::from(cell_value)
                    })
                    .collect::<Row>()
                    .height(1)
                    .style(style)
            })
            .collect();

        let table = Table::new(rows, constraints)
            .header(header.style(text_important_color).bottom_margin(1))
            .block(block)
            .row_highlight_style(Style::default().add_modifier(Modifier::REVERSED));

        // Render table with proper scrolling state
        frame.render_stateful_widget(table, area, &mut self.perf_top_table_state);

        // Render scrollbar if there are more items than can fit on screen
        let visible_rows = area.height.saturating_sub(4) as usize; // Account for borders and header
        if symbol_data.len() > visible_rows {
            let scrollbar = Scrollbar::default()
                .orientation(ScrollbarOrientation::VerticalRight)
                .begin_symbol(Some("↑"))
                .end_symbol(Some("↓"));
            let mut scrollbar_state =
                ScrollbarState::new(symbol_data.len()).position(self.selected_symbol_index);
            frame.render_stateful_widget(
                scrollbar,
                area.inner(Margin {
                    vertical: 1,
                    horizontal: 0,
                }),
                &mut scrollbar_state,
            );
        }
        Ok(())
    }

    /// Renders the symbol details on the right side
    fn render_symbol_details(
        &mut self,
        frame: &mut Frame,
        area: Rect,
        top_symbols: &[crate::symbol_data::SymbolSample],
    ) -> Result<()> {
        // Get the current event name
        let event_name = if let Some(ref event) = self.current_sampling_event {
            event.event_name()
        } else {
            self.active_event.event_name()
        };

        let block = Block::bordered()
            .title_top(
                Line::from(format!("Symbol Details - Event: {event_name}"))
                    .style(self.theme().title_style())
                    .centered(),
            )
            .title_top(
                Line::from(vec![
                    Span::styled("f", self.theme().text_important_color()),
                    Span::styled(
                        if self.filtering {
                            format!(" {}_", self.event_input_buffer)
                        } else {
                            "ilter".to_string()
                        },
                        self.theme().text_color(),
                    ),
                ])
                .left_aligned(),
            )
            .border_type(BorderType::Rounded)
            .style(self.theme().border_style());

        if top_symbols.is_empty() || self.selected_symbol_index >= top_symbols.len() {
            let paragraph = Paragraph::new("No symbol selected")
                .alignment(Alignment::Center)
                .block(block);
            frame.render_widget(paragraph, area);
            return Ok(());
        }

        let selected_symbol = &top_symbols[self.selected_symbol_index];
        let symbol_info = &selected_symbol.symbol_info;

        let mut details = vec![
            Line::from(vec![
                Span::styled("Symbol: ", Style::default().fg(Color::Yellow)),
                Span::raw(&symbol_info.symbol_name),
            ]),
            Line::from(vec![
                Span::styled("Module: ", Style::default().fg(Color::Yellow)),
                Span::raw(&symbol_info.module_name),
            ]),
            Line::from(vec![
                Span::styled("Address: ", Style::default().fg(Color::Yellow)),
                Span::raw(format!("0x{:x}", symbol_info.address)),
            ]),
            Line::from(vec![
                Span::styled("Samples: ", Style::default().fg(Color::Yellow)),
                Span::raw(if self.localize {
                    selected_symbol.count.to_formatted_string(&self.locale)
                } else {
                    selected_symbol.count.to_string()
                }),
            ]),
            Line::from(vec![
                Span::styled("Percentage: ", Style::default().fg(Color::Yellow)),
                Span::raw(format!("{:.2}%", selected_symbol.percentage)),
            ]),
            Line::from(""),
            Line::from(vec![Span::styled(
                "Process Details:",
                Style::default()
                    .fg(self.theme().text_important_color())
                    .add_modifier(Modifier::BOLD),
            )]),
            Line::from(vec![
                Span::styled("PID: ", Style::default().fg(Color::Yellow)),
                Span::raw(selected_symbol.pid.to_string()),
            ]),
        ];

        // Add detailed process information if available
        if let Some(proc_data) = self.proc_data.get(&(selected_symbol.pid as i32)) {
            // First row: Process name, TGID, State
            let first_row = vec![
                Span::styled("Name: ", Style::default().fg(Color::Yellow)),
                Span::raw(&proc_data.process_name),
                Span::raw("  "),
                Span::styled("TGID: ", Style::default().fg(Color::Yellow)),
                Span::raw(proc_data.tgid.to_string()),
                Span::raw("  "),
                Span::styled("State: ", Style::default().fg(Color::Yellow)),
                Span::raw(format!("{:?}", proc_data.state)),
            ];
            details.push(Line::from(first_row));

            // Second row: CPU Util, Threads, CPU
            let second_row = vec![
                Span::styled("CPU Util: ", Style::default().fg(Color::Yellow)),
                Span::raw(format!("{:.2}%", proc_data.cpu_util_perc)),
                Span::raw("  "),
                Span::styled("Threads: ", Style::default().fg(Color::Yellow)),
                Span::raw(proc_data.num_threads.to_string()),
                Span::raw("  "),
                Span::styled("CPU: ", Style::default().fg(Color::Yellow)),
                Span::raw(selected_symbol.cpu_id.to_string()),
            ];
            details.push(Line::from(second_row));

            // Third row: Scheduler info (only if available)
            let mut third_row = Vec::new();
            let mut has_third_row_content = false;

            if let Some(layer_id) = proc_data.layer_id {
                if self.layered_enabled && layer_id >= 0 {
                    third_row.extend(vec![
                        Span::styled("Layer: ", Style::default().fg(Color::Yellow)),
                        Span::raw(layer_id.to_string()),
                        Span::raw("  "),
                    ]);
                    has_third_row_content = true;
                }
            }

            if let Some(dsq) = proc_data.dsq {
                third_row.extend(vec![
                    Span::styled("DSQ: ", Style::default().fg(Color::Yellow)),
                    Span::raw(format!("0x{:x}", App::classify_dsq(dsq))),
                ]);
                has_third_row_content = true;
            }

            if has_third_row_content {
                details.push(Line::from(third_row));
            }

            // Command line (on its own line due to potential length)
            if !proc_data.cmdline.is_empty() {
                let cmdline = proc_data.cmdline.join(" ");
                let truncated_cmdline = if cmdline.len() > 60 {
                    format!("{}...", &cmdline[..57])
                } else {
                    cmdline
                };
                details.push(Line::from(vec![
                    Span::styled("Cmd: ", Style::default().fg(Color::Yellow)),
                    Span::raw(truncated_cmdline),
                ]));
            }
        } else {
            // Process data not available, show basic info with CPU
            details.push(Line::from(vec![
                Span::styled("Process Info: ", Style::default().fg(Color::Red)),
                Span::raw("Not available"),
                Span::raw("  "),
                Span::styled("CPU: ", Style::default().fg(Color::Yellow)),
                Span::raw(selected_symbol.cpu_id.to_string()),
            ]));
        }

        if let Some(file_name) = &symbol_info.file_name {
            details.push(Line::from(vec![
                Span::styled("File: ", Style::default().fg(Color::Yellow)),
                Span::raw(file_name),
            ]));
        }

        if let Some(line_number) = symbol_info.line_number {
            details.push(Line::from(vec![
                Span::styled("Line: ", Style::default().fg(Color::Yellow)),
                Span::raw(line_number.to_string()),
            ]));
        }

        // Add the last stack trace if available - symbolize on demand
        if !selected_symbol.stack_traces.is_empty() {
            let raw_stack_trace = selected_symbol.stack_traces.last().unwrap();
            let symbolized_trace = self.symbol_data.symbolize_stack_trace(raw_stack_trace);

            details.push(Line::from(""));
            details.push(Line::from(vec![Span::styled(
                format!("Latest Stack Trace ({} samples):", symbolized_trace.count),
                Style::default()
                    .fg(self.theme().text_important_color())
                    .add_modifier(Modifier::BOLD),
            )]));

            // Show kernel stack if present
            if !symbolized_trace.kernel_stack.is_empty() {
                details.push(Line::from(""));
                details.push(Line::from(vec![Span::styled(
                    "Kernel Stack:",
                    Style::default()
                        .fg(self.theme().kernel_symbol_color())
                        .add_modifier(Modifier::BOLD),
                )]));

                for (frame_idx, symbol) in symbolized_trace.kernel_stack.iter().enumerate() {
                    let frame_info =
                        if let (Some(file), Some(line)) = (&symbol.file_name, symbol.line_number) {
                            format!(
                                "  #{}: {} ({}:{})",
                                frame_idx, symbol.symbol_name, file, line
                            )
                        } else {
                            format!(
                                "  #{}: {} [0x{:x}]",
                                frame_idx, symbol.symbol_name, symbol.address
                            )
                        };
                    details.push(Line::from(vec![Span::styled(
                        frame_info,
                        Style::default().fg(self.theme().kernel_symbol_color()),
                    )]));
                }
            }

            // Show user stack if present
            if !symbolized_trace.user_stack.is_empty() {
                details.push(Line::from(""));
                details.push(Line::from(vec![Span::styled(
                    "User Stack:",
                    Style::default()
                        .fg(self.theme().userspace_symbol_color())
                        .add_modifier(Modifier::BOLD),
                )]));

                for (frame_idx, symbol) in symbolized_trace.user_stack.iter().enumerate() {
                    let frame_info =
                        if let (Some(file), Some(line)) = (&symbol.file_name, symbol.line_number) {
                            format!(
                                "  #{}: {} ({}:{})",
                                frame_idx, symbol.symbol_name, file, line
                            )
                        } else {
                            format!(
                                "  #{}: {} [0x{:x}]",
                                frame_idx, symbol.symbol_name, symbol.address
                            )
                        };
                    details.push(Line::from(vec![Span::styled(
                        frame_info,
                        Style::default().fg(self.theme().userspace_symbol_color()),
                    )]));
                }
            }
        }

        let paragraph = Paragraph::new(details)
            .block(block)
            .wrap(Wrap { trim: true });

        frame.render_widget(paragraph, area);
        Ok(())
    }

    /// Renders the memory application state.
    fn render_memory(&mut self, frame: &mut Frame) -> Result<()> {
        let theme = self.theme();
        let sample_rate = self
            .skel
            .as_ref()
            .map(|s| s.maps.data_data.as_ref().unwrap().sample_rate)
            .unwrap_or(0);

        MemoryRenderer::render_memory_view(
            frame,
            &self.mem_info,
            sample_rate,
            self.config.tick_rate_ms(),
            theme,
        )
    }

    /// Renders the network application state.
    fn render_network(&mut self, frame: &mut Frame) -> Result<()> {
        let theme = self.theme();
        NetworkRenderer::render_network_view(
            frame,
            &self.network_stats,
            self.config.tick_rate_ms(),
            self.localize,
            &self.locale,
            theme,
        )
    }

    /// Renders the BPF programs view
    fn render_bpf_programs(&mut self, frame: &mut Frame) -> Result<()> {
        // Use filtered programs if filtering is active, otherwise use all programs
        let programs_to_display: Vec<(u32, BpfProgData)> = if self.filtering {
            self.filtered_bpf_programs.clone()
        } else {
            // Create sorted list of BPF programs for display
            let mut programs: Vec<(u32, BpfProgData)> = self
                .bpf_program_stats
                .programs
                .iter()
                .map(|(id, data)| (*id, data.clone()))
                .collect();

            // Sort by average runtime descending
            programs.sort_by(|a, b| {
                b.1.avg_runtime_ns()
                    .partial_cmp(&a.1.avg_runtime_ns())
                    .unwrap_or(std::cmp::Ordering::Equal)
            });
            programs
        };

        let list_params = ProgramsListParams {
            bpf_program_stats: &self.bpf_program_stats,
            filtered_programs: &programs_to_display,
            bpf_program_columns: &self.bpf_program_columns,
            bpf_overhead_history: &self.bpf_overhead_history,
            filtering: self.filtering,
            filter_input: &self.event_input_buffer,
            event_input_buffer: &self.event_input_buffer,
            theme: self.config.theme(),
            tick_rate_ms: self.config.tick_rate_ms(),
        };
        BpfProgramRenderer::render_programs_list(
            frame,
            &mut self.bpf_program_table_state,
            &list_params,
        )
    }

    /// Renders the BPF program detail view using real BPF_ENABLE_STATS data
    fn render_bpf_program_detail(&mut self, frame: &mut Frame) -> Result<()> {
        // Get the selected program data and clone it to avoid borrowing issues
        let selected_program_data = if let Some(prog_id) = self.selected_bpf_program_id {
            self.bpf_program_stats.programs.get(&prog_id).cloned()
        } else {
            None
        };

        let active_event_name = self.active_event.event_name();

        let detail_params = ProgramDetailParams {
            selected_program_data: selected_program_data.as_ref(),
            bpf_program_stats: &self.bpf_program_stats,
            filtered_symbols: &self.bpf_program_filtered_symbols,
            bpf_perf_sampling_active: self.bpf_perf_sampling_active,
            active_event_name,
            theme: self.config.theme(),
            tick_rate_ms: self.config.tick_rate_ms(),
        };
        BpfProgramRenderer::render_program_detail(
            frame,
            &mut self.bpf_program_symbol_table_state,
            &detail_params,
        )
    }

    /// Updates app state when the down arrow or mapped key is pressed.
    fn on_down(&mut self) {
        if self.state == AppState::BpfPrograms {
            // Handle navigation for BPF programs view
            let programs_to_display: Vec<(u32, crate::bpf_prog_data::BpfProgData)> =
                if self.filtering {
                    self.filtered_bpf_programs.clone()
                } else {
                    let mut programs: Vec<(u32, crate::bpf_prog_data::BpfProgData)> = self
                        .bpf_program_stats
                        .programs
                        .iter()
                        .map(|(id, data)| (*id, data.clone()))
                        .collect();
                    programs.sort_by(|a, b| {
                        b.1.avg_runtime_ns()
                            .partial_cmp(&a.1.avg_runtime_ns())
                            .unwrap_or(std::cmp::Ordering::Equal)
                    });
                    programs
                };

            if !programs_to_display.is_empty() {
                let current_selected = self.bpf_program_table_state.selected().unwrap_or(0);
                let new_selected = if current_selected < programs_to_display.len() - 1 {
                    current_selected + 1
                } else {
                    0 // Wrap to top
                };
                self.bpf_program_table_state.select(Some(new_selected));

                // Update selected program ID to preserve selection across refreshes
                if let Some((prog_id, _)) = programs_to_display.get(new_selected) {
                    self.selected_bpf_program_id = Some(*prog_id);
                }
            }
        } else if self.state == AppState::BpfProgramDetail {
            // Handle navigation for BPF program detail symbol table
            let symbols_count = self.bpf_program_filtered_symbols.len();
            if symbols_count > 0 {
                let current_selected = self.bpf_program_symbol_table_state.selected().unwrap_or(0);
                let new_selected = if current_selected < symbols_count - 1 {
                    current_selected + 1
                } else {
                    0 // Wrap to top
                };
                self.bpf_program_symbol_table_state
                    .select(Some(new_selected));
            }
        } else if self.state == AppState::PerfTop {
            // Handle PerfTop navigation separately
            let max_index = self.perf_top_filtered_symbols.len().saturating_sub(1);
            if self.selected_symbol_index < max_index {
                self.selected_symbol_index += 1;
                self.perf_top_table_state
                    .select(Some(self.selected_symbol_index));
            }
        } else {
            let mut filtered_state = self.filtered_state.lock().unwrap();
            if (self.state == AppState::PerfEvent
                || self.state == AppState::KprobeEvent
                || self.state == AppState::Default
                || self.state == AppState::Llc
                || self.state == AppState::Node
                || self.state == AppState::Process)
                && filtered_state.scroll < filtered_state.count - 1
            {
                filtered_state.scroll += 1;
                filtered_state.selected += 1;
            }
        }
    }

    /// Updates app state when the up arrow or mapped key is pressed.
    fn on_up(&mut self) {
        if self.state == AppState::BpfPrograms {
            // Handle navigation for BPF programs view
            let programs_to_display: Vec<(u32, crate::bpf_prog_data::BpfProgData)> =
                if self.filtering {
                    self.filtered_bpf_programs.clone()
                } else {
                    let mut programs: Vec<(u32, crate::bpf_prog_data::BpfProgData)> = self
                        .bpf_program_stats
                        .programs
                        .iter()
                        .map(|(id, data)| (*id, data.clone()))
                        .collect();
                    programs.sort_by(|a, b| {
                        b.1.avg_runtime_ns()
                            .partial_cmp(&a.1.avg_runtime_ns())
                            .unwrap_or(std::cmp::Ordering::Equal)
                    });
                    programs
                };

            if !programs_to_display.is_empty() {
                let current_selected = self.bpf_program_table_state.selected().unwrap_or(0);
                let new_selected = if current_selected > 0 {
                    current_selected - 1
                } else {
                    programs_to_display.len() - 1 // Wrap to bottom
                };
                self.bpf_program_table_state.select(Some(new_selected));

                // Update selected program ID to preserve selection across refreshes
                if let Some((prog_id, _)) = programs_to_display.get(new_selected) {
                    self.selected_bpf_program_id = Some(*prog_id);
                }
            }
        } else if self.state == AppState::BpfProgramDetail {
            // Handle navigation for BPF program detail symbol table
            let symbols_count = self.bpf_program_filtered_symbols.len();
            if symbols_count > 0 {
                let current_selected = self.bpf_program_symbol_table_state.selected().unwrap_or(0);
                let new_selected = if current_selected > 0 {
                    current_selected - 1
                } else {
                    symbols_count - 1 // Wrap to bottom
                };
                self.bpf_program_symbol_table_state
                    .select(Some(new_selected));
            }
        } else if self.state == AppState::PerfTop {
            // Handle navigation for PerfTop view
            if self.selected_symbol_index > 0 {
                self.selected_symbol_index -= 1;
            }
            self.perf_top_table_state
                .select(Some(self.selected_symbol_index));
        } else if self.state == AppState::Help {
        } else {
            let mut filtered_state = self.filtered_state.lock().unwrap();
            if (self.state == AppState::PerfEvent
                || self.state == AppState::KprobeEvent
                || self.state == AppState::Default
                || self.state == AppState::Llc
                || self.state == AppState::Node
                || self.state == AppState::Process)
                && filtered_state.selected > 0
            {
                filtered_state.scroll -= 1;
                filtered_state.selected -= 1;
            }
        }
    }

    /// Updates app state when page down or mapped key is pressed.
    fn on_pg_down(&mut self) {
        if self.state == AppState::BpfPrograms {
            // Handle page down for BPF programs view
            let page_size = 10;
            let programs_to_display: Vec<(u32, crate::bpf_prog_data::BpfProgData)> =
                if self.filtering {
                    self.filtered_bpf_programs.clone()
                } else {
                    let mut programs: Vec<(u32, crate::bpf_prog_data::BpfProgData)> = self
                        .bpf_program_stats
                        .programs
                        .iter()
                        .map(|(id, data)| (*id, data.clone()))
                        .collect();
                    programs.sort_by(|a, b| {
                        b.1.avg_runtime_ns()
                            .partial_cmp(&a.1.avg_runtime_ns())
                            .unwrap_or(std::cmp::Ordering::Equal)
                    });
                    programs
                };

            if !programs_to_display.is_empty() {
                let current_selected = self.bpf_program_table_state.selected().unwrap_or(0);
                let max_index = programs_to_display.len() - 1;

                let new_selected = if current_selected + page_size <= max_index {
                    current_selected + page_size
                } else {
                    max_index
                };

                self.bpf_program_table_state.select(Some(new_selected));

                // Update selected program ID to preserve selection across refreshes
                if let Some((prog_id, _)) = programs_to_display.get(new_selected) {
                    self.selected_bpf_program_id = Some(*prog_id);
                }
            }
        } else if self.state == AppState::PerfTop {
            // Handle page down for PerfTop view
            let page_size = 10;
            let max_index = self.perf_top_filtered_symbols.len().saturating_sub(1);

            if self.selected_symbol_index + page_size <= max_index {
                self.selected_symbol_index += page_size;
            } else {
                self.selected_symbol_index = max_index;
            }
            self.perf_top_table_state
                .select(Some(self.selected_symbol_index));
        } else {
            let mut filtered_state = self.filtered_state.lock().unwrap();
            if (self.state == AppState::PerfEvent
                || self.state == AppState::KprobeEvent
                || self.state == AppState::Default
                || self.state == AppState::Llc
                || self.state == AppState::Node
                || self.state == AppState::Process)
                && filtered_state.scroll <= filtered_state.count - self.events_list_size
            {
                filtered_state.scroll += self.events_list_size - 1;
                filtered_state.selected += (self.events_list_size - 1) as usize;
            }
        }
    }
    /// Updates app state when page up or mapped key is pressed.
    fn on_pg_up(&mut self) {
        if self.state == AppState::BpfPrograms {
            // Handle page up for BPF programs view
            let page_size = 10;
            let programs_to_display: Vec<(u32, crate::bpf_prog_data::BpfProgData)> =
                if self.filtering {
                    self.filtered_bpf_programs.clone()
                } else {
                    let mut programs: Vec<(u32, crate::bpf_prog_data::BpfProgData)> = self
                        .bpf_program_stats
                        .programs
                        .iter()
                        .map(|(id, data)| (*id, data.clone()))
                        .collect();
                    programs.sort_by(|a, b| {
                        b.1.avg_runtime_ns()
                            .partial_cmp(&a.1.avg_runtime_ns())
                            .unwrap_or(std::cmp::Ordering::Equal)
                    });
                    programs
                };

            if !programs_to_display.is_empty() {
                let current_selected = self.bpf_program_table_state.selected().unwrap_or(0);

                let new_selected = current_selected.saturating_sub(page_size);

                self.bpf_program_table_state.select(Some(new_selected));

                // Update selected program ID to preserve selection across refreshes
                if let Some((prog_id, _)) = programs_to_display.get(new_selected) {
                    self.selected_bpf_program_id = Some(*prog_id);
                }
            }
        } else if self.state == AppState::PerfTop {
            // Handle page up for PerfTop view
            let page_size = 10;

            if self.selected_symbol_index >= page_size {
                self.selected_symbol_index -= page_size;
            } else {
                self.selected_symbol_index = 0;
            }
            self.perf_top_table_state
                .select(Some(self.selected_symbol_index));
        } else {
            let mut filtered_state = self.filtered_state.lock().unwrap();
            if (self.state == AppState::PerfEvent
                || self.state == AppState::KprobeEvent
                || self.state == AppState::Default
                || self.state == AppState::Llc
                || self.state == AppState::Node
                || self.state == AppState::Process)
                && filtered_state.scroll > 0
            {
                if filtered_state.scroll >= (self.events_list_size - 1) {
                    filtered_state.scroll -= self.events_list_size - 1;
                    filtered_state.selected -= (self.events_list_size - 1) as usize;
                } else {
                    filtered_state.selected -= filtered_state.scroll as usize;
                    filtered_state.scroll = 0;
                }
            }
        }
    }

    /// Updates app state when the enter key is pressed.
    fn on_enter(&mut self) -> Result<()> {
        match self.state {
            AppState::PerfEvent | AppState::KprobeEvent => {
                self.event_input_buffer.clear();
                let selected = {
                    let mut filtered_state = self.filtered_state.lock().unwrap();
                    if filtered_state.list.is_empty() {
                        return Ok(());
                    }
                    let selected = filtered_state.list[filtered_state.selected].clone();
                    filtered_state.reset();
                    selected.as_string()
                };

                let event = match self.state {
                    AppState::PerfEvent => selected.split_once(":").map(|(subsystem, event)| {
                        ProfilingEvent::Perf(PerfEvent::new(
                            subsystem.to_string(),
                            event.to_string(),
                            0,
                        ))
                    }),
                    AppState::KprobeEvent => Some(ProfilingEvent::Kprobe(KprobeEvent::new(
                        selected.to_string(),
                        0,
                    ))),
                    _ => None,
                };

                if let Some(prof_event) = event {
                    if let ProfilingEvent::Kprobe(ref k) = prof_event {
                        let already_exists = self.available_events.iter().any(
                        |e| matches!(e, ProfilingEvent::Kprobe(x) if x.event_name == k.event_name),
                    );

                        if !already_exists {
                            self.kprobe_links.push(
                                self.skel
                                    .as_mut()
                                    .unwrap()
                                    .progs
                                    .generic_kprobe
                                    .attach_kprobe(false, &k.event_name)?,
                            );
                        };
                    };

                    self.active_prof_events.clear();
                    self.active_event = prof_event.clone();
                    let _ = self.activate_prof_event(&prof_event);
                    let prev_state = self.prev_state.clone();
                    self.prev_state = self.state.clone();
                    self.state = prev_state;
                    self.available_events.push(prof_event);
                }
            }
            AppState::PerfTop => {
                self.filtering = false;
                self.filter_symbols();
            }
            AppState::BpfPrograms => {
                // Enter BPF program detail view for the selected program
                if let Some(selected_index) = self.bpf_program_table_state.selected() {
                    // Use filtered programs if filtering is active, otherwise use all programs
                    let programs_list: Vec<(u32, BpfProgData)> = if self.filtering {
                        self.filtered_bpf_programs.clone()
                    } else {
                        // Get sorted list of BPF programs to match table order
                        let mut programs: Vec<(u32, BpfProgData)> = self
                            .bpf_program_stats
                            .programs
                            .iter()
                            .map(|(id, data)| (*id, data.clone()))
                            .collect();

                        // Sort by average runtime descending (must match display sort order!)
                        programs.sort_by(|a, b| {
                            b.1.avg_runtime_ns()
                                .partial_cmp(&a.1.avg_runtime_ns())
                                .unwrap_or(std::cmp::Ordering::Equal)
                        });
                        programs
                    };

                    // Get the selected program ID
                    if let Some((prog_id, _)) = programs_list.get(selected_index) {
                        self.selected_bpf_program_id = Some(*prog_id);

                        // Cache the BPF symbol info for this program (expensive operation)
                        self.cached_bpf_symbol_info =
                            BpfProgStats::get_real_symbol_info(*prog_id).ok().flatten();

                        if let Some(ref symbol_info) = self.cached_bpf_symbol_info {
                            log::info!(
                                "Cached BPF symbol info for prog {}: {} ksyms, {} func_lens, {} line_info",
                                prog_id,
                                symbol_info.jited_ksyms.len(),
                                symbol_info.jited_func_lens.len(),
                                symbol_info.jited_line_info.len()
                            );
                        } else {
                            log::warn!("Failed to get BPF symbol info for prog {}", prog_id);
                        }

                        self.prev_state = self.state.clone();
                        self.state = AppState::BpfProgramDetail;
                    }
                }
            }
            AppState::Default | AppState::Node | AppState::Llc | AppState::Process => {
                // Reset process view
                self.filtering = false;
                self.event_input_buffer.clear();

                if let Some(proc_data) = self.selected_proc_data() {
                    proc_data.init_threads()?;

                    // Kick off thread view
                    self.in_thread_view = true;
                }

                self.filter_events();
            }
            _ => {
                // Handle other states (Help, MangoApp, Memory, Pause, Scheduler, etc.)
                // For these states, do nothing on Enter
            }
        }

        Ok(())
    }

    fn on_escape(&mut self) -> Result<()> {
        match self.state() {
            AppState::BpfPrograms => {
                if self.filtering {
                    // Clear filter and exit filtering mode
                    self.filtering = false;
                    self.event_input_buffer.clear();
                    self.filter_bpf_programs();
                }
            }
            AppState::BpfProgramDetail => {
                // Go back to BPF programs list view
                self.selected_bpf_program_id = None;
                self.cached_bpf_symbol_info = None;
                self.state = AppState::BpfPrograms;
                self.filtering = false;
                self.event_input_buffer.clear();
                self.filter_bpf_programs();
            }
            AppState::PerfEvent | AppState::KprobeEvent => {
                self.event_input_buffer.clear();
                self.filter_events();
                self.handle_action(&Action::SetState(self.prev_state.clone()))?;
            }
            AppState::Default | AppState::Llc | AppState::Node | AppState::Process => {
                if !self.filtering && !self.in_thread_view {
                    self.handle_action(&Action::Quit)?;
                } else if !self.filtering {
                    if let Some(proc_data) = self.selected_proc_data() {
                        proc_data.clear_threads();
                    }
                    self.in_thread_view = false;
                    self.filter_events();
                } else {
                    self.filtering = false;
                    self.event_input_buffer.clear();
                    self.filter_events();
                }
            }
            AppState::PerfTop => {
                if self.filtering {
                    self.filtering = false;
                    self.event_input_buffer.clear();
                    self.filter_symbols();
                } else {
                    self.handle_action(&Action::Quit)?;
                }
            }
            _ => self.handle_action(&Action::Quit)?,
        }

        Ok(())
    }

    /// Attaches any BPF programs required for perfetto traces.
    fn attach_trace_progs(&mut self) -> Result<()> {
        if let Some(ref mut skel) = self.skel {
            self.trace_links = vec![
                skel.progs.on_softirq_entry.attach()?,
                skel.progs.on_softirq_exit.attach()?,
                skel.progs.on_ipi_send_cpu.attach()?,
                skel.progs.on_sched_fork.attach()?,
                skel.progs.on_sched_exec.attach()?,
                skel.progs.on_sched_exit.attach()?,
            ];
        }

        Ok(())
    }

    /// Records the trace to perfetto output.
    fn stop_recording_trace(&mut self, ts: u64) -> Result<()> {
        if let Some(ref mut skel) = self.skel {
            skel.maps.data_data.as_mut().unwrap().sample_rate = self.prev_bpf_sample_rate;
        }
        self.state = self.prev_state.clone();
        self.trace_manager.stop(None, Some(ts))?;
        self.trace_links.clear();

        Ok(())
    }

    /// Request the BPF side start a trace.
    fn request_start_trace(&mut self) -> Result<()> {
        if self.state == AppState::Tracing || self.skel.is_none() {
            return Ok(());
        };

        if let Some(ref mut skel) = self.skel {
            skel.maps.data_data.as_mut().unwrap().trace_duration_ns =
                self.config.trace_duration_ns();
            skel.maps.data_data.as_mut().unwrap().trace_warmup_ns = self.config.trace_warmup_ns();

            if self.trace_links.is_empty() {
                self.attach_trace_progs()?;
            }
        }

        let ret = self
            .skel
            .as_mut()
            .unwrap()
            .progs
            .start_trace
            .test_run(ProgramInput::default())?
            .return_value;
        if ret != 0 {
            Err(anyhow::anyhow!(
                "start_trace failed with exit code: {}",
                ret
            ))
        } else {
            Ok(())
        }
    }

    /// Starts recording a trace.
    fn start_recording_trace(
        &mut self,
        immediate: bool,
        start_time: u64,
        stop_scheduled: bool,
    ) -> Result<()> {
        if self.skel.is_none() {
            return Ok(());
        }
        self.prev_state = self.state.clone();
        self.state = AppState::Tracing;
        self.trace_start = if immediate {
            start_time
        } else {
            start_time + self.config.trace_warmup_ns()
        };
        self.trace_manager.start()?;

        if !stop_scheduled {
            let mut args = bpf_intf::schedule_stop_trace_args {
                stop_timestamp: self.trace_start + self.config.trace_duration_ns(),
            };
            let input = ProgramInput {
                context_in: Some(unsafe {
                    std::slice::from_raw_parts_mut(
                        &mut args as *mut _ as *mut u8,
                        std::mem::size_of_val(&args),
                    )
                }),
                ..Default::default()
            };

            let ret = self
                .skel
                .as_mut()
                .unwrap()
                .progs
                .schedule_stop_trace
                .test_run(input)?
                .return_value;
            if ret != 0 {
                return Err(anyhow::anyhow!(
                    "schedule_stop_trace failed with exit code: {}",
                    ret
                ));
            }
        }

        if self.trace_links.is_empty() {
            self.attach_trace_progs()?;
        }

        Ok(())
    }

    /// Updates the app when a scheduler is unloaded.
    fn on_scheduler_unload(&mut self) {
        self.scheduler = "".to_string();
        self.sched_stats_raw = "".to_string();
        self.dsq_data.clear();
        let _ = self
            .cpu_data
            .values_mut()
            .map(|cpu_data| cpu_data.data.clear_event("perf"));
    }

    /// Updates the app when a scheduler is loaded.
    fn on_scheduler_load(&mut self) -> Result<()> {
        self.dsq_data.clear();
        self.sched_stats_raw = "".to_string();
        self.scheduler = read_file_string(SCHED_NAME_PATH)?;
        Ok(())
    }

    /// Updates the app when a CPUs performance is changed by the scheduler.
    fn on_cpu_perf(&mut self, cpu: u32, perf: u32) {
        let cpu_data = self
            .cpu_data
            .get_mut(&(cpu as usize))
            .expect("CpuData should have been present");
        cpu_data.add_event_data("perf", perf as u64);
    }

    fn on_exec(&mut self, action: &ExecAction) {
        let ExecAction {
            old_pid,
            pid,
            layer_id,
            ..
        } = action;

        // In case pid != old_pid
        let old_pid: i32 = u32_to_i32(*old_pid);
        self.proc_data.remove(&old_pid);

        let pid = u32_to_i32(*pid);
        if let Ok(mut new_proc_data) = ProcData::from_tgid(pid, self.max_cpu_events) {
            new_proc_data.layer_id = Some(*layer_id);
            self.proc_data.insert(pid, new_proc_data);
        }

        if self.state == AppState::Tracing && action.ts > self.trace_start {
            self.trace_manager.on_exec(action);
        }
    }

    fn on_exit(&mut self, action: &ExitAction) {
        let ExitAction { pid, tgid, .. } = action;

        let pid: i32 = u32_to_i32(*pid);
        let tgid: i32 = u32_to_i32(*tgid);

        if pid == tgid {
            self.proc_data.remove(&pid);
        } else if let Entry::Occupied(entry) = self.proc_data.entry(tgid) {
            if self.in_thread_view {
                entry.into_mut().remove_thread(pid);
            }
        }

        if self.state == AppState::Tracing && action.ts > self.trace_start {
            self.trace_manager.on_exit(action);
        }
    }

    fn on_fork(&mut self, action: &ForkAction) {
        let ForkAction {
            parent_tgid,
            child_pid,
            child_tgid,
            parent_layer_id,
            child_layer_id,
            ..
        } = action;

        let parent_tgid: i32 = u32_to_i32(*parent_tgid);
        let child_tgid: i32 = u32_to_i32(*child_tgid);
        let child_pid: i32 = u32_to_i32(*child_pid);

        if parent_tgid == child_tgid {
            // Fork created a new thread for an existing process
            match self.proc_data.entry(parent_tgid) {
                Entry::Vacant(entry) => {
                    if let Ok(mut proc_data) = ProcData::from_tgid(parent_tgid, self.max_cpu_events)
                    {
                        proc_data.layer_id = Some(*parent_layer_id);
                        entry.insert(proc_data);
                    }
                }
                Entry::Occupied(entry) => {
                    let proc_data = entry.into_mut();
                    proc_data.layer_id = Some(*parent_layer_id);
                    if self.in_thread_view {
                        if let Some(selected_tgid) = self.selected_process {
                            if selected_tgid == parent_tgid {
                                proc_data.add_thread(child_pid);
                            }
                        }
                    }
                }
            }
        } else {
            // Fork created a fully new process
            if let Ok(mut new_proc_data) = ProcData::from_tgid(child_pid, self.max_cpu_events) {
                new_proc_data.layer_id = Some(*child_layer_id);
                self.proc_data.insert(child_pid, new_proc_data);
            }
        }

        if self.state == AppState::Tracing && action.ts > self.trace_start {
            self.trace_manager.on_fork(action);
        }
    }

    fn on_wait(&mut self, action: &WaitAction) {
        if self.state == AppState::Tracing && action.ts > self.trace_start {
            self.trace_manager.on_wait(action);
        }
    }

    /// Updates the app when a task wakes.
    fn on_sched_wakeup(&mut self, action: &SchedWakeupAction) {
        let SchedWakeupAction {
            pid,
            tgid,
            waker_pid,
            waker_comm,
            ..
        } = action;

        let tid = u32_to_i32(*pid);
        let tgid = u32_to_i32(*tgid);

        // Update waker information for the thread
        if let Some(proc_data) = self.proc_data.get_mut(&tgid) {
            if self.in_thread_view {
                if let Some(thread_data) = proc_data.threads.get_mut(&tid) {
                    if *waker_pid != 0 {
                        thread_data.last_waker_pid = Some(*waker_pid);
                        thread_data.last_waker_comm = Some(waker_comm.to_string());
                    }
                }
            }
        }

        if self.state == AppState::Tracing && action.ts > self.trace_start {
            self.trace_manager.on_sched_wakeup(action);
        }
    }

    /// Updates the app when a task is about to wake.
    fn on_sched_waking(&mut self, action: &SchedWakingAction) {
        let SchedWakingAction {
            pid,
            tgid,
            waker_pid,
            waker_comm,
            ..
        } = action;

        let tid = u32_to_i32(*pid);
        let tgid = u32_to_i32(*tgid);

        // Update waker information for the thread
        if let Some(proc_data) = self.proc_data.get_mut(&tgid) {
            if self.in_thread_view {
                if let Some(thread_data) = proc_data.threads.get_mut(&tid) {
                    if *waker_pid != 0 {
                        thread_data.last_waker_pid = Some(*waker_pid);
                        thread_data.last_waker_comm = Some(waker_comm.to_string());
                    }
                }
            }
        }

        if self.state == AppState::Tracing && action.ts > self.trace_start {
            self.trace_manager.on_sched_waking(action);
        }
    }

    /// Updates the app when a task is scheduled.
    fn on_sched_switch(&mut self, action: &SchedSwitchAction) {
        let SchedSwitchAction {
            cpu,
            next_dsq_id,
            next_dsq_nr_queued,
            next_dsq_lat_us,
            next_dsq_vtime,
            next_tgid,
            next_pid,
            next_layer_id,
            prev_dsq_id,
            prev_used_slice_ns,
            prev_tgid,
            prev_pid,
            prev_layer_id,
            ..
        } = action;

        let topo_cpu = self
            .topo
            .all_cpus
            .get(&(*cpu as usize))
            .expect("Cpu should exist in topology");
        let cpu_i32 = u32_to_i32(*cpu);
        let llc = Some(topo_cpu.llc_id as u32);
        let node = Some(topo_cpu.node_id as u32);
        let max_cpu_events = self.max_cpu_events;

        macro_rules! update_fields {
            ($data:expr, $cpu:expr, $llc:expr, $node:expr, $dsq:expr, $layer:expr) => {{
                $data.cpu = $cpu;
                $data.llc = $llc;
                $data.node = $node;
                $data.dsq = $dsq;
                $data.layer_id = $layer;
            }};
        }

        let insert_or_update_thread =
            |proc_data: &mut ProcData, tid: i32, dsq: Option<u64>, layer: Option<i32>| {
                match proc_data.threads.entry(tid) {
                    Entry::Vacant(entry) => {
                        if let Ok(mut thread_data) =
                            ThreadData::from_tgid_tid(proc_data.tgid, tid, max_cpu_events)
                        {
                            update_fields!(thread_data, cpu_i32, llc, node, dsq, layer);
                            entry.insert(thread_data);
                        }
                    }
                    Entry::Occupied(mut entry) => {
                        let thread_data = entry.get_mut();
                        update_fields!(thread_data, cpu_i32, llc, node, dsq, layer);
                    }
                };
            };

        let mut insert_or_update_proc =
            |tgid: i32, tid: i32, dsq: Option<u64>, layer: Option<i32>| {
                match self.proc_data.entry(tgid) {
                    Entry::Vacant(entry) => {
                        if let Ok(mut proc_data) = ProcData::from_tgid(tgid, max_cpu_events) {
                            update_fields!(proc_data, cpu_i32, llc, node, dsq, layer);
                            entry.insert(proc_data);
                        }
                    }
                    Entry::Occupied(mut entry) => {
                        let proc_data = entry.get_mut();
                        update_fields!(proc_data, cpu_i32, llc, node, dsq, layer);
                    }
                };

                if self.in_thread_view {
                    if let Some(proc_data) = self.selected_proc_data() {
                        if proc_data.tgid == tgid {
                            insert_or_update_thread(proc_data, tid, dsq, layer);
                        }
                    }
                }
            };

        let next_tgid = u32_to_i32(*next_tgid);
        let prev_tgid = u32_to_i32(*prev_tgid);
        let next_tid = u32_to_i32(*next_pid);
        let prev_tid = u32_to_i32(*prev_pid);

        insert_or_update_proc(
            next_tgid,
            next_tid,
            Some(*next_dsq_id),
            Some(*next_layer_id),
        );
        insert_or_update_proc(
            prev_tgid,
            prev_tid,
            Some(*prev_dsq_id),
            Some(*prev_layer_id),
        );

        if let Some(proc_data) = self.proc_data.get_mut(&prev_tgid) {
            proc_data.add_event_data("slice_consumed", *prev_used_slice_ns);
            if self.in_thread_view {
                if let Some(thread_data) = proc_data.threads.get_mut(&prev_tid) {
                    thread_data.add_event_data("slice_consumed", *prev_used_slice_ns);
                }
            }
        }

        if let Some(proc_data) = self.proc_data.get_mut(&next_tgid) {
            proc_data.add_event_data("lat_us", *next_dsq_lat_us);
            if self.in_thread_view {
                if let Some(thread_data) = proc_data.threads.get_mut(&next_tid) {
                    thread_data.add_event_data("lat_us", *next_dsq_lat_us);
                }
            }
        }

        if self.state == AppState::Tracing {
            if action.ts > self.trace_start {
                self.trace_manager.on_sched_switch(action);
            }
            return;
        }

        if self.scheduler.is_empty() {
            return;
        }

        let cpu_data = self
            .cpu_data
            .get_mut(&(*cpu as usize))
            .expect("CpuData should have been present");

        let next_dsq_id = App::classify_dsq(*next_dsq_id);
        let prev_dsq_id = App::classify_dsq(*prev_dsq_id);

        if next_dsq_id != scx_enums.SCX_DSQ_INVALID && *next_dsq_lat_us > 0 {
            let next_dsq_data = self
                .dsq_data
                .entry(next_dsq_id)
                .or_insert(EventData::new(self.max_cpu_events));

            if self.state == AppState::MangoApp {
                if self.process_id > 0 && action.next_tgid == self.process_id as u32 {
                    cpu_data.add_event_data("dsq_lat_us", *next_dsq_lat_us);
                    next_dsq_data.add_event_data("dsq_lat_us", *next_dsq_lat_us);
                    next_dsq_data.add_event_data("dsq_nr_queued", *next_dsq_nr_queued as u64);
                }
            } else {
                cpu_data.add_event_data("dsq_lat_us", *next_dsq_lat_us);
                next_dsq_data.add_event_data("dsq_lat_us", *next_dsq_lat_us);
                next_dsq_data.add_event_data("dsq_nr_queued", *next_dsq_nr_queued as u64);
            }

            if *next_dsq_vtime > 0 {
                next_dsq_data.add_event_data("dsq_vtime", *next_dsq_vtime);
            }
        }

        if prev_dsq_id != scx_enums.SCX_DSQ_INVALID && *prev_used_slice_ns > 0 {
            let prev_dsq_data = self
                .dsq_data
                .entry(prev_dsq_id)
                .or_insert(EventData::new(self.max_cpu_events));
            if self.state == AppState::MangoApp {
                if self.process_id > 0 && action.prev_tgid == self.process_id as u32 {
                    prev_dsq_data.add_event_data("dsq_slice_consumed", *prev_used_slice_ns);
                }
            } else {
                prev_dsq_data.add_event_data("dsq_slice_consumed", *prev_used_slice_ns);
            }
        }
    }

    fn on_sched_migrate(&mut self, action: &SchedMigrateTaskAction) {
        if self.state == AppState::Tracing && action.ts > self.trace_start {
            self.trace_manager.on_sched_migrate(action);
        }
    }

    fn on_sched_hang(&mut self, action: &SchedHangAction) {
        if self.state == AppState::Tracing && action.ts > self.trace_start {
            self.trace_manager.on_sched_hang(action);
        }
    }

    // Groups built-in dsq's (GLOBAL, LOCAL, and LOCAL-ON)
    fn classify_dsq(dsq_id: u64) -> u64 {
        if dsq_id & scx_enums.SCX_DSQ_FLAG_BUILTIN == 0 {
            dsq_id
        } else if (dsq_id & scx_enums.SCX_DSQ_LOCAL_ON) == scx_enums.SCX_DSQ_LOCAL_ON {
            scx_enums.SCX_DSQ_LOCAL_ON
        } else {
            // Catches both GLOBAL and LOCAL bits (1 or 2)
            dsq_id & (scx_enums.SCX_DSQ_FLAG_BUILTIN | 3)
        }
    }

    /// Handles softirq events.
    pub fn on_softirq(&mut self, action: &SoftIRQAction) {
        if self.state == AppState::Tracing && action.exit_ts > self.trace_start {
            self.trace_manager.on_softirq(action);
        }
    }

    /// Handles IPI events.
    pub fn on_ipi(&mut self, action: &IPIAction) {
        if self.state == AppState::Tracing && action.ts > self.trace_start {
            self.trace_manager.on_ipi(action);
        }
    }

    pub fn on_gpu_mem(&mut self, action: &GpuMemAction) {
        if self.state == AppState::Tracing && action.ts > self.trace_start {
            self.trace_manager.on_gpu_mem(action);
        }
    }

    /// Handles cpu hotplug events.
    pub fn on_cpu_hp_enter(&mut self, action: &CpuhpEnterAction) {
        if self.state == AppState::Tracing && action.ts > self.trace_start {
            self.trace_manager.on_cpu_hp_enter(action);
        }
    }

    pub fn on_cpu_hp_exit(&mut self, action: &CpuhpExitAction) {
        if self.state == AppState::Tracing && action.ts > self.trace_start {
            self.trace_manager.on_cpu_hp_exit(action);
        }
    }

    /// Handles hardware pressure events.
    pub fn on_hw_pressure(&mut self, action: &HwPressureAction) {
        let HwPressureAction { cpu, hw_pressure } = action;

        let cpu_data = self
            .cpu_data
            .get_mut(&(*cpu as usize))
            .expect("CpuData should have been present");
        cpu_data.add_event_data("hw_pressure", *hw_pressure);
    }

    /// Handles kprobe events.
    pub fn on_kprobe(&mut self, action: &KprobeAction) {
        let cpu = action.cpu as usize;
        // can't happen
        if self.skel.is_none() {
            return;
        }
        let sample_rate = self
            .skel
            .as_ref()
            .unwrap()
            .maps
            .data_data
            .as_ref()
            .unwrap()
            .sample_rate as u64;

        if let Some(ProfilingEvent::Kprobe(kprobe)) = self.active_prof_events.get_mut(&cpu) {
            if kprobe.instruction_pointer == Some(action.instruction_pointer) {
                kprobe.increment_by(sample_rate);
            }
        }
    }

    /// Gets the currently selected symbol in the perf top view.
    fn get_selected_symbol(&self) -> Option<&crate::symbol_data::SymbolSample> {
        if self.perf_top_filtered_symbols.is_empty() {
            None
        } else {
            self.perf_top_table_state
                .selected()
                .and_then(|index| self.perf_top_filtered_symbols.get(index))
                .map(|(_, symbol)| symbol)
        }
    }

    /// Handles perf sample events for the perf top view.
    pub fn on_perf_sample(&mut self, action: &crate::PerfSampleAction) {
        // Check if we're profiling a specific BPF program
        if self.state == AppState::BpfProgramDetail && self.bpf_perf_sampling_active {
            if let Some(prog_id) = self.selected_bpf_program_id {
                // For BPF program profiling, we need to check if this sample is from the BPF program
                // BPF programs execute as JIT-compiled kernel code
                if action.is_kernel {
                    // Use cached BPF symbol info to check if instruction pointer is in this BPF program
                    let is_bpf_program_sample =
                        if let Some(ref bpf_symbol_info) = self.cached_bpf_symbol_info {
                            // Use the contains_address method to check if IP falls within BPF program
                            bpf_symbol_info.contains_address(action.instruction_pointer)
                        } else {
                            // No cached symbol info - don't accept samples without address info
                            false
                        };

                    if is_bpf_program_sample {
                        // This is a sample from our BPF program or kernel code it calls
                        self.bpf_program_symbol_data
                            .add_sample_with_stacks_and_layer(
                                action.instruction_pointer,
                                prog_id, // Use prog_id as pid for BPF programs
                                action.cpu_id,
                                true, // BPF programs are kernel code
                                &action.kernel_stack,
                                &action.user_stack,
                                None, // No layer ID for BPF programs
                            );

                        // Update filtered BPF symbols
                        self.filter_bpf_symbols();
                    }
                }
            }
        } else if self.state == AppState::PerfTop {
            // Original PerfTop behavior
            // Get layer ID from BPF sample (negative if not present)
            let layer_id = if action.layer_id >= 0 {
                Some(action.layer_id)
            } else {
                None
            };

            // Add the sample with full stack trace information
            self.symbol_data.add_sample_with_stacks_and_layer(
                action.instruction_pointer,
                action.pid,
                action.cpu_id,
                action.is_kernel,
                &action.kernel_stack,
                &action.user_stack,
                layer_id,
            );

            // Update filtered symbols with new data
            self.filter_symbols();

            // Only store detailed stack trace if this matches the highlighted instruction pointer
            if let Some(selected_symbol) = self.get_selected_symbol() {
                if selected_symbol.symbol_info.address == action.instruction_pointer {
                    // Store the latest symbolized data for the selected symbol
                    self.symbol_data.update_selected_symbol_details(
                        action.instruction_pointer,
                        &action.kernel_stack,
                        &action.user_stack,
                        action.pid,
                    );
                }
            }
        }
    }

    /// Filters BPF program symbols based on the current filter text
    fn filter_bpf_symbols(&mut self) {
        let top_symbols = self.bpf_program_symbol_data.get_top_symbols(1000);

        // Enhance symbols with BPF line information if available
        let enhanced_symbols: Vec<crate::symbol_data::SymbolSample> = top_symbols
            .into_iter()
            .map(|sample| {
                let mut enhanced = sample.clone();

                // If we have cached BPF symbol info, try to get source location
                if let Some(ref bpf_symbol_info) = self.cached_bpf_symbol_info {
                    if let Some((line, _col)) =
                        bpf_symbol_info.get_source_location(sample.symbol_info.address)
                    {
                        // Update the symbol name to include line number
                        let base_name = &sample.symbol_info.symbol_name;
                        enhanced.symbol_info.symbol_name = format!("{} (line {})", base_name, line);
                        enhanced.symbol_info.line_number = Some(line);
                    }
                }

                enhanced
            })
            .collect();

        if !self.event_input_buffer.is_empty() {
            let filter_text = self.event_input_buffer.to_lowercase();
            self.bpf_program_filtered_symbols = enhanced_symbols
                .into_iter()
                .filter(|sample| {
                    sample
                        .symbol_info
                        .symbol_name
                        .to_lowercase()
                        .contains(&filter_text)
                        || sample
                            .symbol_info
                            .module_name
                            .to_lowercase()
                            .contains(&filter_text)
                        || sample
                            .symbol_info
                            .file_name
                            .as_ref()
                            .is_some_and(|f| f.to_lowercase().contains(&filter_text))
                })
                .collect();
        } else {
            self.bpf_program_filtered_symbols = enhanced_symbols;
        }

        // Reset selection if out of bounds
        if self.bpf_program_symbol_table_state.selected().unwrap_or(0)
            >= self.bpf_program_filtered_symbols.len()
            && !self.bpf_program_filtered_symbols.is_empty()
        {
            self.bpf_program_symbol_table_state.select(Some(0));
        }
    }

    /// Filters symbols based on the current filter text
    fn filter_symbols(&mut self) {
        let top_symbols = self.symbol_data.get_top_symbols(1000); // Get more symbols for filtering

        if !self.event_input_buffer.is_empty() {
            let filter_text = self.event_input_buffer.to_lowercase();
            self.perf_top_filtered_symbols = top_symbols
                .into_iter()
                .filter(|sample| {
                    sample
                        .symbol_info
                        .symbol_name
                        .to_lowercase()
                        .contains(&filter_text)
                        || sample
                            .symbol_info
                            .module_name
                            .to_lowercase()
                            .contains(&filter_text)
                })
                .map(|sample| (sample.symbol_info.symbol_name.clone(), sample.clone()))
                .collect();
        } else {
            self.perf_top_filtered_symbols = top_symbols
                .into_iter()
                .map(|sample| (sample.symbol_info.symbol_name.clone(), sample.clone()))
                .collect();
        }

        // Reset selection if it's out of bounds
        if self.selected_symbol_index >= self.perf_top_filtered_symbols.len()
            && !self.perf_top_filtered_symbols.is_empty()
        {
            self.selected_symbol_index = 0;
        }

        // Update table state selection
        if !self.perf_top_filtered_symbols.is_empty() {
            self.perf_top_table_state
                .select(Some(self.selected_symbol_index));
        } else {
            self.perf_top_table_state.select(None);
        }
    }

    /// Attaches perf event sampling for perf top view
    #[allow(clippy::unnecessary_cast)]
    fn attach_perf_sampling(&mut self) -> Result<()> {
        if !self.has_perf_cap {
            return Ok(());
        }
        // Clear any existing links
        self.detach_perf_sampling();

        // Determine which perf event to use for sampling
        let sampling_event = if let ProfilingEvent::Perf(_) = &self.active_event {
            // Use the currently active event if it's a perf event
            self.active_event.clone()
        } else {
            // Find the first available perf event or default to CPU cycles
            self.available_events
                .iter()
                .find(|event| matches!(event, ProfilingEvent::Perf(_)))
                .cloned()
                .unwrap_or_else(|| {
                    ProfilingEvent::Perf(PerfEvent::new("hw".to_string(), "cycles".to_string(), 0))
                })
        };

        let all_cpus = self.topo.all_cpus.clone();
        let total_cpus = all_cpus.len();
        let mut attached_count = 0;

        for (cpu_id, _cpu_info) in all_cpus {
            // Get the base perf event and configure it for sampling
            let base_perf_event = match &sampling_event {
                ProfilingEvent::Perf(p) => p,
                _ => unreachable!("sampling_event should always be Perf"),
            };

            // Create custom perf event attributes for sampling with IP collection
            let mut attr: perf::bindings::perf_event_attr = unsafe { std::mem::zeroed() };
            attr.size = std::mem::size_of::<perf::bindings::perf_event_attr>() as u32;

            // Set the event type and config based on the existing perf event
            match base_perf_event.subsystem.to_lowercase().as_str() {
                "hw" | "hardware" => {
                    attr.type_ = perf::bindings::PERF_TYPE_HARDWARE;
                    match base_perf_event.event.to_lowercase().as_str() {
                        "cycles" | "cpu-cycles" | "cpu_cycles" => {
                            attr.config = perf::bindings::PERF_COUNT_HW_CPU_CYCLES as u64;
                        }
                        "instructions" | "instr" => {
                            attr.config = perf::bindings::PERF_COUNT_HW_INSTRUCTIONS as u64;
                        }
                        "branches" | "branch-instructions" => {
                            attr.config = perf::bindings::PERF_COUNT_HW_BRANCH_INSTRUCTIONS as u64;
                        }
                        "cache-misses" => {
                            attr.config = perf::bindings::PERF_COUNT_HW_CACHE_MISSES as u64;
                        }
                        _ => {
                            // Default to CPU cycles if unknown hardware event
                            attr.config = perf::bindings::PERF_COUNT_HW_CPU_CYCLES as u64;
                        }
                    }
                }
                "sw" | "software" => {
                    attr.type_ = perf::bindings::PERF_TYPE_SOFTWARE;
                    match base_perf_event.event.to_lowercase().as_str() {
                        "cpu-clock" => {
                            attr.config = perf::bindings::PERF_COUNT_SW_CPU_CLOCK as u64;
                        }
                        "task-clock" => {
                            attr.config = perf::bindings::PERF_COUNT_SW_TASK_CLOCK as u64;
                        }
                        _ => {
                            // Default to task clock for software events
                            attr.config = perf::bindings::PERF_COUNT_SW_TASK_CLOCK as u64;
                        }
                    }
                }
                _ => {
                    // For tracepoint events, default to hardware CPU cycles for sampling
                    attr.type_ = perf::bindings::PERF_TYPE_HARDWARE;
                    attr.config = perf::bindings::PERF_COUNT_HW_CPU_CYCLES as u64;
                }
            }

            // Configure for sampling with instruction pointer collection
            attr.sample_type = perf::bindings::PERF_SAMPLE_IP as u64;
            attr.__bindgen_anon_1.sample_period = self.perf_sample_rate as u64;
            attr.set_freq(0);
            attr.set_disabled(0);
            attr.set_exclude_kernel(0);
            attr.set_exclude_hv(0);
            attr.set_inherit(1); // inherit to all processes
            attr.set_pinned(1);

            // Use scx_utils perf event helper to open the perf event
            let perf_fd = unsafe {
                perf::perf_event_open(
                    &mut attr as *mut perf::bindings::perf_event_attr,
                    -1,            // pid (-1 for all processes)
                    cpu_id as i32, // cpu
                    -1,            // group_fd
                    0,             // flags
                )
            };

            if perf_fd <= 0 {
                let err = std::io::Error::last_os_error();
                eprintln!("Failed to open perf event for CPU {cpu_id}: {err}");
                continue;
            }

            // Attach BPF program to the perf event
            if let Some(ref mut skel) = self.skel {
                match skel.progs.perf_sample_handler.attach_perf_event(perf_fd) {
                    Ok(link) => {
                        // Enable the perf event using scx_utils ioctl helper
                        if unsafe { perf::ioctls::enable(perf_fd, 0) } < 0 {
                            let err = std::io::Error::last_os_error();
                            eprintln!("Failed to enable perf event for CPU {cpu_id}: {err}");
                            unsafe {
                                libc::close(perf_fd);
                            }
                            continue;
                        }

                        self.perf_links.push(link);
                        attached_count += 1;
                    }
                    Err(_e) => unsafe {
                        libc::close(perf_fd);
                    },
                }
            }
        }

        if attached_count == 0 {
            return Err(anyhow::anyhow!("Failed to attach perf events to any CPU"));
        }

        log::info!(
            "Attached perf sampling to {} CPUs (out of {} total)",
            attached_count,
            total_cpus
        );

        // Store the current sampling event for display in UI
        self.current_sampling_event = Some(sampling_event);

        Ok(())
    }

    /// Detaches perf event sampling
    fn detach_perf_sampling(&mut self) {
        self.perf_links.clear();
    }

    /// Updates the filtered events list based on the current input buffer
    fn filter_events(&mut self) {
        let filtered_events_list = match self.state {
            AppState::PerfEvent => {
                search::fuzzy_search(&self.perf_events, &self.event_input_buffer)
                    .into_iter()
                    .map(FilterItem::String)
                    .collect()
            }
            AppState::KprobeEvent => {
                search::fuzzy_search(&self.kprobe_events, &self.event_input_buffer)
                    .into_iter()
                    .map(FilterItem::String)
                    .collect()
            }
            AppState::PerfTop => {
                // For PerfTop, call the specialized filter_symbols method
                self.filter_symbols();
                return; // Early return since filter_symbols handles everything
            }
            AppState::Default
            | AppState::Llc
            | AppState::Node
            | AppState::Memory
            | AppState::Process => {
                if self.in_thread_view {
                    if let Some(proc_data) = self.selected_proc_data_immut() {
                        proc_data
                            .threads
                            .iter()
                            .filter(|(_, thread_data)| {
                                // When event_input_buffer is empty, include all threads
                                if self.event_input_buffer.is_empty() {
                                    true
                                } else {
                                    search::contains_spread(
                                        &thread_data.thread_name,
                                        &self.event_input_buffer,
                                    )
                                    .is_some()
                                        || search::contains_spread(
                                            &thread_data.tid.to_string(),
                                            &self.event_input_buffer,
                                        )
                                        .is_some()
                                }
                            })
                            .map(|(tid, _)| FilterItem::Int(*tid))
                            .collect()
                    } else {
                        vec![]
                    }
                } else {
                    // When event_input_buffer is empty, include all processes
                    if self.event_input_buffer.is_empty() {
                        self.proc_data
                            .keys()
                            .map(|tgid| FilterItem::Int(*tgid))
                            .collect()
                    } else {
                        self.proc_data
                            .iter()
                            .filter(|(_, proc_data)| {
                                search::contains_spread(
                                    &proc_data.process_name,
                                    &self.event_input_buffer,
                                )
                                .is_some()
                                    || search::contains_spread(
                                        &proc_data.tgid.to_string(),
                                        &self.event_input_buffer,
                                    )
                                    .is_some()
                            })
                            .map(|(tgid, _)| FilterItem::Int(*tgid))
                            .collect()
                    }
                }
            }
            _ => vec![],
        };

        let mut filtered_state = self.filtered_state.lock().unwrap();

        filtered_state.list = filtered_events_list;
        filtered_state.count = filtered_state.list.len() as u16;

        if (filtered_state.count as usize) <= filtered_state.selected {
            filtered_state.selected = (filtered_state.count as usize).saturating_sub(1);
        }

        if filtered_state.count <= filtered_state.scroll {
            filtered_state.scroll = filtered_state.count.saturating_sub(1);
        }
    }

    /// Updates a column's visibility
    pub fn update_col_visibility(&mut self, action: &UpdateColVisibilityAction) -> Result<()> {
        let UpdateColVisibilityAction {
            table,
            col,
            visible,
        } = action;

        match table.as_str() {
            "Process" => self.process_columns.update_visibility(col, *visible),
            "Thread" => self.thread_columns.update_visibility(col, *visible),
            _ => bail!("Invalid table name"),
        };

        // Track layered state based on Layer ID column visibility
        if col == "Layer ID" {
            if *visible {
                self.layered_enabled = true;
            } else {
                // Check if any Layer ID column is still visible
                let process_layer_visible = self
                    .process_columns
                    .all_columns()
                    .iter()
                    .find(|c| c.header == "Layer ID")
                    .map(|c| c.visible)
                    .unwrap_or(false);

                let thread_layer_visible = self
                    .thread_columns
                    .all_columns()
                    .iter()
                    .find(|c| c.header == "Layer ID")
                    .map(|c| c.visible)
                    .unwrap_or(false);

                self.layered_enabled = process_layer_visible || thread_layer_visible;
            }
        }

        Ok(())
    }

    /// Updates the bpf bpf sampling rate.
    pub fn update_bpf_sample_rate(&mut self, sample_rate: u32) {
        if let Some(ref mut skel) = self.skel {
            skel.maps.data_data.as_mut().unwrap().sample_rate = sample_rate;
        }
    }

    /// Handles the action and updates application states.
    pub fn handle_action(&mut self, action: &Action) -> Result<()> {
        match action {
            Action::Tick => {
                self.on_tick()?;
            }
            Action::Down => self.on_down(),
            Action::Up => self.on_up(),
            Action::PageUp => self.on_pg_up(),
            Action::PageDown => self.on_pg_down(),
            Action::Enter => {
                self.on_enter()?;
            }
            Action::SetState(state) => {
                if *state == AppState::Memory {
                    self.memory_view_state = self.memory_view_state.next();
                    // Handle memory view tristate cycling based on current state
                    match self.memory_view_state {
                        ComponentViewState::Detail => {
                            // Show detailed memory view
                            self.set_state(AppState::Memory);
                        }
                        ComponentViewState::Hidden | ComponentViewState::Default => {
                            // Stay in default view, memory summary will update automatically
                            if self.state == AppState::Memory {
                                self.set_state(self.prev_state.clone());
                            }
                        }
                    }
                } else if *state == AppState::Network {
                    // Handle network view tristate cycling (original working logic)
                    self.network_view_state = self.network_view_state.next();
                    match self.network_view_state {
                        ComponentViewState::Detail => {
                            self.set_state(AppState::Network);
                        }
                        ComponentViewState::Hidden | ComponentViewState::Default => {
                            // If we're in the Network view, switch back to default view
                            if self.state == AppState::Network {
                                self.set_state(self.prev_state.clone());
                            }
                            // If we're already in default view, the summary state will update automatically
                        }
                    }
                } else if *state == self.state {
                    self.set_state(self.prev_state.clone());
                } else {
                    self.set_state(state.clone());
                }
            }
            Action::NextEvent => {
                if self.next_event().is_err() {
                    // XXX handle error
                }
            }
            Action::PrevEvent => {
                if self.prev_event().is_err() {
                    // XXX handle error
                }
            }
            Action::NextViewState => self.next_view_state(),
            Action::SchedReg => {
                self.on_scheduler_load()?;
            }
            Action::SchedUnreg => {
                self.on_scheduler_unload();
            }
            Action::SchedStats(raw) => {
                self.on_sched_stats(raw.clone());
            }
            Action::SchedCpuPerfSet(SchedCpuPerfSetAction { cpu, perf }) => {
                self.on_cpu_perf(*cpu, *perf);
            }
            Action::RequestTrace => {
                self.request_start_trace()?;
            }
            Action::TraceStarted(TraceStartedAction {
                start_immediately,
                ts,
                stop_scheduled,
            }) => {
                self.start_recording_trace(*start_immediately, *ts, *stop_scheduled)?;
            }
            Action::TraceStopped(TraceStoppedAction { ts }) => {
                self.stop_recording_trace(*ts)?;
            }
            Action::ReloadStatsClient => {
                tokio::task::block_in_place(|| {
                    let _ = self.reload_stats_client();
                });
            }
            Action::SaveConfig => {
                self.on_save_config()?;
            }
            Action::SchedSwitch(a) => {
                self.on_sched_switch(a);
            }
            Action::SchedWakeup(a) => {
                self.on_sched_wakeup(a);
            }
            Action::SchedWaking(a) => {
                self.on_sched_waking(a);
            }
            Action::SchedMigrateTask(a) => {
                self.on_sched_migrate(a);
            }
            Action::SchedHang(a) => {
                self.on_sched_hang(a);
            }
            Action::SoftIRQ(a) => {
                self.on_softirq(a);
            }
            Action::Exec(a) => {
                self.on_exec(a);
            }
            Action::Exit(a) => {
                self.on_exit(a);
            }
            Action::Fork(a) => {
                self.on_fork(a);
            }
            Action::Wait(a) => {
                self.on_wait(a);
            }
            Action::IPI(a) => {
                self.on_ipi(a);
            }
            Action::MangoApp(a) => {
                self.on_mangoapp(a)?;
            }
            Action::GpuMem(a) => {
                self.on_gpu_mem(a);
            }
            Action::CpuhpEnter(a) => {
                self.on_cpu_hp_enter(a);
            }
            Action::CpuhpExit(a) => {
                self.on_cpu_hp_exit(a);
            }
            Action::HwPressure(a) => {
                self.on_hw_pressure(a);
            }
            Action::Kprobe(a) => {
                self.on_kprobe(a);
            }
            Action::PerfSample(a) => {
                self.on_perf_sample(a);
            }
            Action::ClearEvent => {
                match self.state {
                    AppState::PerfTop => {
                        self.symbol_data.clear();
                        self.selected_symbol_index = 0;
                        self.filter_symbols(); // Update filtered symbols after clearing
                    }
                    _ => {
                        self.reset_prof_events()?;
                    }
                }
            }
            Action::UpdateColVisibility(a) => {
                self.update_col_visibility(a)?;
            }
            Action::ChangeTheme => {
                self.set_theme(self.theme().next());
            }
            Action::TickRateChange(dur) => {
                let new_tick_rate_ms: u64 = dur.as_millis().try_into().unwrap();
                self.config.set_tick_rate_ms(new_tick_rate_ms as usize);
                // Update the CPU frequency refresh interval for the background thread
                self.cpu_freq_refresh_interval_ms
                    .store(new_tick_rate_ms, Ordering::Relaxed);
            }
            Action::ToggleBpfPerfSampling => {
                self.toggle_bpf_perf_sampling()?;
            }
            Action::ToggleCpuFreq => self.collect_cpu_freq = !self.collect_cpu_freq,
            Action::ToggleUncoreFreq => self.collect_uncore_freq = !self.collect_uncore_freq,
            Action::ToggleLocalization => self.localize = !self.localize,
            Action::ToggleHwPressure => self.hw_pressure = !self.hw_pressure,
            Action::IncBpfSampleRate => {
                if self.state == AppState::PerfTop {
                    // In PerfTop view, control perf sample rate
                    self.perf_sample_rate = (self.perf_sample_rate << 1).max(1);
                    // Restart perf sampling with new rate if active
                    if self.current_sampling_event.is_some() {
                        self.detach_perf_sampling();
                        let _ = self.attach_perf_sampling();
                    }
                } else if self.state == AppState::BpfProgramDetail && self.bpf_perf_sampling_active
                {
                    // In BPF program detail view with perf sampling active, control global perf sample rate
                    self.perf_sample_rate = (self.perf_sample_rate << 1).max(1);
                    // Restart perf sampling with new rate
                    self.detach_perf_sampling();
                    let _ = self.attach_perf_sampling();
                    log::info!(
                        "Increased perf sample rate to {} samples/sec per CPU",
                        self.perf_sample_rate
                    );
                } else if let Some(ref skel) = self.skel {
                    // Normal BPF sample rate control
                    let sample_rate = skel.maps.data_data.as_ref().unwrap().sample_rate;
                    if sample_rate == 0 {
                        self.update_bpf_sample_rate(8_u32);
                    } else {
                        self.update_bpf_sample_rate(sample_rate << 2);
                    }
                }
            }
            Action::DecBpfSampleRate => {
                if self.state == AppState::PerfTop {
                    // In PerfTop view, control perf sample rate
                    self.perf_sample_rate = (self.perf_sample_rate >> 1).max(1);
                    // Restart perf sampling with new rate if active
                    if self.current_sampling_event.is_some() {
                        self.detach_perf_sampling();
                        let _ = self.attach_perf_sampling();
                    }
                } else if self.state == AppState::BpfProgramDetail && self.bpf_perf_sampling_active
                {
                    // In BPF program detail view with perf sampling active, control global perf sample rate
                    self.perf_sample_rate = (self.perf_sample_rate >> 1).max(1);
                    // Restart perf sampling with new rate
                    self.detach_perf_sampling();
                    let _ = self.attach_perf_sampling();
                    log::info!(
                        "Decreased perf sample rate to {} samples/sec per CPU",
                        self.perf_sample_rate
                    );
                } else if let Some(ref skel) = self.skel {
                    // Normal BPF sample rate control
                    let sample_rate = skel.maps.data_data.as_ref().unwrap().sample_rate;
                    if sample_rate > 0 {
                        // prevent overly aggressive bpf sampling, but allow disabling sampling
                        let new_rate = sample_rate >> 2;
                        self.update_bpf_sample_rate(if new_rate >= 8 { new_rate } else { 0 });
                    }
                }
            }
            Action::Quit => match self.state {
                AppState::Help => {
                    self.handle_action(&Action::SetState(AppState::Help))?;
                }
                AppState::Default | AppState::Llc | AppState::Node | AppState::Process => {
                    if self.in_thread_view {
                        self.in_thread_view = false;
                    } else {
                        self.should_quit.store(true, Ordering::Relaxed);
                    }
                }
                _ => {
                    self.should_quit.store(true, Ordering::Relaxed);
                }
            },
            Action::Filter => match self.state {
                AppState::Default
                | AppState::Llc
                | AppState::Node
                | AppState::Process
                | AppState::Memory => {
                    self.filtering = true;
                    self.filter_events();
                }
                AppState::BpfPrograms => {
                    self.filtering = true;
                    self.filter_bpf_programs();
                }
                AppState::PerfTop => {
                    self.filtering = true;
                    self.filter_symbols();
                }
                _ => {}
            },
            Action::InputEntry(input) => {
                self.event_input_buffer.push_str(input);
                match self.state {
                    AppState::BpfPrograms => {
                        self.filter_bpf_programs();
                    }
                    AppState::PerfTop => {
                        self.filter_symbols();
                    }
                    _ => {
                        self.filter_events();
                    }
                }
            }
            Action::Backspace => {
                self.event_input_buffer.pop();
                match self.state {
                    AppState::BpfPrograms => {
                        self.filter_bpf_programs();
                    }
                    AppState::PerfTop => {
                        self.filter_symbols();
                    }
                    _ => {
                        self.filter_events();
                    }
                }
            }
            Action::Esc => {
                self.on_escape()?;
            }
            _ => {}
        };
        Ok(())
    }

    /// Updates power monitoring data
    pub fn update_power_data(&mut self) -> Result<()> {
        if let Ok(power_data) = self.power_collector.collect() {
            self.power_snapshot.update(power_data);
        }
        Ok(())
    }

    /// Renders the power monitoring view
    fn render_power(&mut self, frame: &mut Frame) -> Result<()> {
        if self.has_capability_warnings() {
            self.render_capability_warnings(frame, frame.area())?;
            return Ok(());
        }
        let power_data = self.power_snapshot.current.clone();

        // Main layout: vertical split into three sections
        let main_chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints(
                [
                    Constraint::Percentage(50), // Core power details and package summary at top
                    Constraint::Percentage(30), // Power charts in middle
                    Constraint::Percentage(20), // C-states and battery at bottom
                ]
                .as_ref(),
            )
            .split(frame.area());

        // Top section: Split vertically for core table and package summary
        let top_chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints(
                [
                    Constraint::Percentage(75), // Core power table
                    Constraint::Percentage(25), // Package watts summary
                ]
                .as_ref(),
            )
            .split(main_chunks[0]);

        // Top: Core power table
        self.render_core_power_table(frame, top_chunks[0], &power_data)?;

        // Below core table: Split horizontally for package and RAM/uncore summaries
        let summary_chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(50), Constraint::Percentage(50)].as_ref())
            .split(top_chunks[1]);

        // Left: Package watts summary
        self.render_package_power_summary(frame, summary_chunks[0], &power_data)?;

        // Right: RAM watts and uncore frequencies summary
        self.render_ram_uncore_summary(frame, summary_chunks[1], &power_data)?;

        // Middle: Power charts (full width)
        self.render_power_summary(frame, main_chunks[1], &power_data)?;

        // Bottom: Split into two columns for C-states and battery
        let bottom_chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(50), Constraint::Percentage(50)].as_ref())
            .split(main_chunks[2]);

        self.render_c_states_summary(frame, bottom_chunks[0], &power_data)?;
        self.render_battery_info(frame, bottom_chunks[1], &power_data)?;

        Ok(())
    }

    fn render_core_power_table(
        &mut self,
        frame: &mut Frame,
        area: Rect,
        power_data: &crate::SystemPowerData,
    ) -> Result<()> {
        let core_count = power_data.cores.len();

        // Calculate number of columns based on CPU count
        let num_columns = if core_count >= 128 {
            8
        } else if core_count >= 64 {
            4
        } else if core_count >= 32 {
            2
        } else {
            1
        };

        // If only one column, use the original single-table approach
        if num_columns == 1 {
            self.render_single_core_power_table(frame, area, power_data)
        } else {
            self.render_multi_column_core_power_table(frame, area, power_data, num_columns)
        }
    }

    fn render_single_core_power_table(
        &mut self,
        frame: &mut Frame,
        area: Rect,
        power_data: &crate::SystemPowerData,
    ) -> Result<()> {
        // Determine available C-states across all cores
        let available_cstates = self.get_available_cstates(power_data);

        // Check if temperature data is available
        let has_temp_data = self.has_temperature_data(power_data);

        // Get columns configuration
        let power_columns = crate::columns::get_power_columns(has_temp_data, &available_cstates);
        let columns = crate::columns::Columns::new(power_columns);
        let visible_columns: Vec<_> = columns.visible_columns().collect();

        // Build header from visible columns
        let header_cells: Vec<Cell> = visible_columns
            .iter()
            .map(|col| Cell::from(col.header))
            .collect();

        let header = Row::new(header_cells)
            .style(Style::default().fg(self.config.theme().text_color()))
            .height(1);

        // Get constraints from visible columns
        let constraints: Vec<Constraint> =
            visible_columns.iter().map(|col| col.constraint).collect();

        let mut rows: Vec<Row> = Vec::new();
        let mut cores: Vec<_> = power_data.cores.iter().collect();
        cores.sort_by_key(|(core_id, _)| *core_id);

        for (core_id, core_data) in cores {
            let row_cells: Vec<Cell> = visible_columns
                .iter()
                .map(|col| {
                    let value = if available_cstates.contains(&col.header.to_string()) {
                        // This is a C-state column, get percentage from snapshot
                        format!(
                            "{:.1}%",
                            self.power_snapshot
                                .get_cstate_percentage(*core_id, col.header)
                        )
                    } else {
                        // Regular column, use the value function
                        (col.value_fn)(*core_id, core_data)
                    };

                    // Apply conditional styling based on column type
                    let cell = Cell::from(value);

                    // Apply color styling based on column header using theme gradients
                    match col.header {
                        "Watt" => {
                            let theme = self.config.theme();
                            let (low_threshold, high_threshold) =
                                self.power_snapshot.get_power_thresholds();
                            let color = theme.gradient_3(
                                core_data.power_watts,
                                low_threshold,
                                high_threshold,
                                false,
                            );
                            cell.style(Style::default().fg(color))
                        }
                        "Temp" => {
                            let theme = self.config.theme();
                            let (low_threshold, high_threshold) =
                                self.power_snapshot.get_temperature_thresholds();
                            let color = theme.gradient_3(
                                core_data.temperature_celsius,
                                low_threshold,
                                high_threshold,
                                false,
                            );
                            cell.style(Style::default().fg(color))
                        }
                        "Freq" => {
                            let theme = self.config.theme();
                            let (low_threshold, high_threshold) =
                                self.power_snapshot.get_frequency_thresholds();
                            let color = theme.gradient_3(
                                core_data.frequency_mhz,
                                low_threshold,
                                high_threshold,
                                false,
                            );
                            cell.style(Style::default().fg(color))
                        }
                        header if available_cstates.contains(&header.to_string()) => {
                            // C-state percentages: higher C-states generally mean lower power
                            let percentage =
                                self.power_snapshot.get_cstate_percentage(*core_id, header);
                            let theme = self.config.theme();

                            // For deeper C-states (C3, C6, C7, etc.), higher percentages are better
                            // For shallow C-states (POLL, C1), lower percentages are better
                            let reverse = match header {
                                "POLL" => false,                   // Lower POLL percentage is better
                                "C1" | "C1_ACPI" | "C1E" => false, // Lower C1 percentage is better
                                _ => true, // Higher deep C-state percentage is better
                            };

                            let color = theme.gradient_3(
                                percentage, 20.0, // Low threshold
                                80.0, // High threshold
                                reverse,
                            );
                            cell.style(Style::default().fg(color))
                        }
                        "Pkg" => {
                            let theme = self.config.theme();
                            let color = theme.gradient_3(
                                core_data.package_id as f64,
                                0.0,   // First package
                                3.0,   // Higher package numbers
                                false, // Lower package numbers might be better (first package)
                            );
                            cell.style(Style::default().fg(color))
                        }
                        _ => cell,
                    }
                })
                .collect();

            rows.push(Row::new(row_cells));
        }

        let table = Table::new(rows, constraints)
            .header(header)
            .block(
                Block::default()
                    .title("Core Power Details")
                    .title_top(
                        Line::from(format!("{}ms", self.config.tick_rate_ms()))
                            .style(self.config.theme().text_important_color())
                            .right_aligned(),
                    )
                    .borders(Borders::ALL)
                    .border_style(self.config.theme().border_style()),
            )
            .row_highlight_style(Style::default().bg(Color::DarkGray));

        frame.render_widget(table, area);
        Ok(())
    }

    fn render_multi_column_core_power_table(
        &mut self,
        frame: &mut Frame,
        area: Rect,
        power_data: &crate::SystemPowerData,
        num_columns: usize,
    ) -> Result<()> {
        // Create a single border around the entire core power details area
        let block = Block::default()
            .title("Core Power Details")
            .title_top(
                Line::from(format!("{}ms", self.config.tick_rate_ms()))
                    .style(self.config.theme().text_important_color())
                    .right_aligned(),
            )
            .borders(Borders::ALL)
            .border_style(self.config.theme().border_style());

        // Get the inner area (excluding the border)
        let inner_area = block.inner(area);

        // Render the border
        frame.render_widget(block, area);

        // Split the inner area horizontally into columns
        let column_constraints: Vec<Constraint> = (0..num_columns)
            .map(|_| Constraint::Percentage(100 / num_columns as u16))
            .collect();

        let column_areas = Layout::default()
            .direction(Direction::Horizontal)
            .constraints(column_constraints)
            .split(inner_area);

        // Sort cores by ID
        let mut cores: Vec<_> = power_data.cores.iter().collect();
        cores.sort_by_key(|(core_id, _)| *core_id);

        // Calculate cores per column
        let cores_per_column = cores.len().div_ceil(num_columns);

        // Split cores into chunks for each column
        for (col_idx, column_area) in column_areas.iter().enumerate() {
            let start_idx = col_idx * cores_per_column;
            let end_idx = std::cmp::min(start_idx + cores_per_column, cores.len());

            if start_idx < cores.len() {
                let column_cores = &cores[start_idx..end_idx];
                self.render_core_power_column(
                    frame,
                    *column_area,
                    column_cores,
                    col_idx,
                    num_columns,
                )?;
            }
        }

        Ok(())
    }

    fn render_core_power_column(
        &mut self,
        frame: &mut Frame,
        area: Rect,
        cores: &[(&u32, &crate::CorePowerData)],
        _col_idx: usize,
        total_columns: usize,
    ) -> Result<()> {
        // Check if temperature data is available for these cores
        let has_temp_data = cores
            .iter()
            .any(|(_, core_data)| core_data.temperature_celsius > 0.0);

        // Get available C-states from these cores
        let mut cstate_names = std::collections::HashSet::new();
        for (_, core_data) in cores {
            for cstate_name in core_data.c_states.keys() {
                cstate_names.insert(cstate_name.clone());
            }
        }

        let mut available_cstates: Vec<String> = cstate_names.into_iter().collect();
        available_cstates.sort_by(|a, b| {
            // Custom sorting to put common C-states first
            let order_a = match a.as_str() {
                "POLL" => 0,
                "C1" | "C1_ACPI" => 1,
                "C1E" => 2,
                "C2" => 3,
                "C3" => 4,
                "C6" => 5,
                "C7" => 6,
                "C8" => 7,
                "C9" => 8,
                "C10" => 9,
                _ => 100,
            };
            let order_b = match b.as_str() {
                "POLL" => 0,
                "C1" | "C1_ACPI" => 1,
                "C1E" => 2,
                "C2" => 3,
                "C3" => 4,
                "C6" => 5,
                "C7" => 6,
                "C8" => 7,
                "C9" => 8,
                "C10" => 9,
                _ => 100,
            };
            order_a.cmp(&order_b).then_with(|| a.cmp(b))
        });

        // Get power columns with or without C-states based on space
        let mut power_columns = vec![
            crate::columns::Column {
                header: "Cpu",
                constraint: if total_columns <= 2 {
                    Constraint::Length(4)
                } else {
                    Constraint::Length(3)
                },
                visible: true,
                value_fn: Box::new(|core_id: u32, _: &crate::CorePowerData| core_id.to_string()),
            },
            crate::columns::Column {
                header: "Freq",
                constraint: Constraint::Length(9),
                visible: true,
                value_fn: Box::new(|_: u32, data: &crate::CorePowerData| {
                    crate::util::format_hz((data.frequency_mhz * 1_000.0) as u64)
                }),
            },
            crate::columns::Column {
                header: "Temp",
                constraint: if total_columns <= 2 {
                    Constraint::Length(5)
                } else {
                    Constraint::Length(4)
                },
                visible: has_temp_data,
                value_fn: Box::new(|_: u32, data: &crate::CorePowerData| {
                    if data.temperature_celsius > 0.0 {
                        format!("{:.0}", data.temperature_celsius)
                    } else {
                        "-".to_string()
                    }
                }),
            },
            crate::columns::Column {
                header: "Power",
                constraint: if total_columns <= 2 {
                    Constraint::Length(6)
                } else {
                    Constraint::Length(5)
                },
                visible: true,
                value_fn: Box::new(|_: u32, data: &crate::CorePowerData| {
                    format!("{:.1}", data.power_watts)
                }),
            },
            crate::columns::Column {
                header: "Pkg",
                constraint: Constraint::Length(3),
                visible: true,
                value_fn: Box::new(|_: u32, data: &crate::CorePowerData| {
                    data.package_id.to_string()
                }),
            },
        ];

        // Add C-state columns if we have space
        for cstate in &available_cstates {
            let cstate_name = cstate.clone();
            power_columns.push(crate::columns::Column {
                header: Box::leak(cstate.clone().into_boxed_str()),
                constraint: Constraint::Length(6),
                visible: true,
                value_fn: Box::new(move |_: u32, data: &crate::CorePowerData| {
                    if let Some(cstate_info) = data.c_states.get(&cstate_name) {
                        // Calculate residency percentage
                        let total_residency: u64 =
                            data.c_states.values().map(|cs| cs.residency).sum();
                        if total_residency > 0 {
                            let percentage =
                                (cstate_info.residency as f64 / total_residency as f64) * 100.0;
                            format!("{percentage:.1}%")
                        } else {
                            "0.0%".to_string()
                        }
                    } else {
                        "-".to_string()
                    }
                }),
            });
        }

        let columns = crate::columns::Columns::new(power_columns);
        let visible_columns: Vec<_> = columns.visible_columns().collect();

        // Build header from visible columns
        let header_cells: Vec<Cell> = visible_columns
            .iter()
            .map(|col| Cell::from(col.header))
            .collect();

        let header = Row::new(header_cells)
            .style(Style::default().fg(self.config.theme().text_color()))
            .height(1);

        // Get constraints from visible columns
        let constraints: Vec<Constraint> =
            visible_columns.iter().map(|col| col.constraint).collect();

        let mut rows: Vec<Row> = Vec::new();

        for (core_id, core_data) in cores {
            let row_cells: Vec<Cell> = visible_columns
                .iter()
                .map(|col| {
                    let value = if available_cstates.contains(&col.header.to_string()) {
                        // This is a C-state column, get percentage from snapshot
                        format!(
                            "{:.1}%",
                            self.power_snapshot
                                .get_cstate_percentage(**core_id, col.header)
                        )
                    } else {
                        // Regular column, use the value function
                        (col.value_fn)(**core_id, core_data)
                    };

                    let cell = Cell::from(value);

                    // Apply color styling based on column header using theme gradients
                    match col.header {
                        "Power" => {
                            let theme = self.config.theme();
                            let (low_threshold, high_threshold) =
                                self.power_snapshot.get_power_thresholds();
                            let color = theme.gradient_3(
                                core_data.power_watts,
                                low_threshold,
                                high_threshold,
                                false,
                            );
                            cell.style(Style::default().fg(color))
                        }
                        "Temp" => {
                            let theme = self.config.theme();
                            let (low_threshold, high_threshold) =
                                self.power_snapshot.get_temperature_thresholds();
                            let color = theme.gradient_3(
                                core_data.temperature_celsius,
                                low_threshold,
                                high_threshold,
                                false,
                            );
                            cell.style(Style::default().fg(color))
                        }
                        "Freq" => {
                            let theme = self.config.theme();
                            let (low_threshold, high_threshold) =
                                self.power_snapshot.get_frequency_thresholds();
                            let color = theme.gradient_3(
                                core_data.frequency_mhz,
                                low_threshold,
                                high_threshold,
                                false,
                            );
                            cell.style(Style::default().fg(color))
                        }
                        header if available_cstates.contains(&header.to_string()) => {
                            // C-state percentages: higher C-states generally mean lower power
                            let percentage =
                                self.power_snapshot.get_cstate_percentage(**core_id, header);
                            let theme = self.config.theme();

                            // For deeper C-states (C3, C6, C7, etc.), higher percentages are better
                            // For shallow C-states (POLL, C1), lower percentages are better
                            let reverse = match header {
                                "POLL" => false,                   // Lower POLL percentage is better
                                "C1" | "C1_ACPI" | "C1E" => false, // Lower C1 percentage is better
                                _ => true, // Higher deep C-state percentage is better
                            };

                            let color = theme.gradient_3(
                                percentage, 20.0, // Low threshold
                                80.0, // High threshold
                                reverse,
                            );
                            cell.style(Style::default().fg(color))
                        }
                        "Pkg" => {
                            let theme = self.config.theme();
                            let color = theme.gradient_3(
                                core_data.package_id as f64,
                                0.0,   // First package
                                3.0,   // Higher package numbers
                                false, // Lower package numbers might be better (first package)
                            );
                            cell.style(Style::default().fg(color))
                        }
                        _ => cell,
                    }
                })
                .collect();

            rows.push(Row::new(row_cells));
        }

        let table = Table::new(rows, constraints)
            .header(header)
            .row_highlight_style(Style::default().bg(Color::DarkGray));

        // No borders or block - just render the table directly
        frame.render_widget(table, area);
        Ok(())
    }

    /// Get available C-states across all cores
    fn get_available_cstates(&self, power_data: &crate::SystemPowerData) -> Vec<String> {
        let mut cstate_names = std::collections::HashSet::new();

        // Collect all unique C-state names
        for core_data in power_data.cores.values() {
            for cstate_name in core_data.c_states.keys() {
                cstate_names.insert(cstate_name.clone());
            }
        }

        // Convert to sorted vector, prioritizing common C-states
        let mut cstates: Vec<String> = cstate_names.into_iter().collect();
        cstates.sort_by(|a, b| {
            // Custom sorting to put common C-states first
            let order_a = match a.as_str() {
                "POLL" => 0,
                "C1" | "C1_ACPI" => 1,
                "C1E" => 2,
                "C2" => 3,
                "C3" => 4,
                "C6" => 5,
                "C7" => 6,
                "C8" => 7,
                "C9" => 8,
                "C10" => 9,
                _ => 100,
            };
            let order_b = match b.as_str() {
                "POLL" => 0,
                "C1" | "C1_ACPI" => 1,
                "C1E" => 2,
                "C2" => 3,
                "C3" => 4,
                "C6" => 5,
                "C7" => 6,
                "C8" => 7,
                "C9" => 8,
                "C10" => 9,
                _ => 100,
            };
            order_a.cmp(&order_b).then_with(|| a.cmp(b))
        });

        // Limit to first 4 C-states to avoid table being too wide
        cstates.truncate(4);
        cstates
    }

    /// Check if temperature data is available (non-zero temperatures)
    fn has_temperature_data(&self, power_data: &crate::SystemPowerData) -> bool {
        power_data
            .cores
            .values()
            .any(|core| core.temperature_celsius > 0.0)
    }

    /// Renders C-states summary
    fn render_c_states_summary(
        &mut self,
        frame: &mut Frame,
        area: Rect,
        power_data: &crate::SystemPowerData,
    ) -> Result<()> {
        let mut c_state_summary = std::collections::HashMap::<String, (u64, u64, usize)>::new();

        // Aggregate C-state data across all cores
        for core_data in power_data.cores.values() {
            for (state_name, state_info) in &core_data.c_states {
                let entry = c_state_summary
                    .entry(state_name.clone())
                    .or_insert((0, 0, 0));
                entry.0 += state_info.usage;
                entry.1 += state_info.residency;
                entry.2 += 1;
            }
        }

        // Calculate total residency time for percentage calculation
        let total_residency_all_states: u64 = c_state_summary
            .values()
            .map(|(_, residency, _)| residency)
            .sum();

        let header = Row::new(vec![
            Cell::from("C-State"),
            Cell::from("Avg Usage"),
            Cell::from("Avg Residency(μs)"),
            Cell::from("Percentage"),
        ])
        .style(Style::default().fg(self.config.theme().text_color()))
        .height(1);

        let mut rows: Vec<Row> = Vec::new();
        let mut states: Vec<_> = c_state_summary.iter().collect();
        states.sort_by_key(|(name, _)| name.as_str());

        for (state_name, (total_usage, total_residency, core_count)) in states {
            let avg_usage = if *core_count > 0 {
                total_usage / *core_count as u64
            } else {
                0
            };
            let avg_residency = if *core_count > 0 {
                total_residency / *core_count as u64
            } else {
                0
            };

            // Calculate percentage of time spent in this C-state
            let percentage = if total_residency_all_states > 0 {
                (*total_residency as f64 / total_residency_all_states as f64) * 100.0
            } else {
                0.0
            };

            let percentage_style = if percentage > 50.0 {
                Style::default().fg(Color::Red)
            } else if percentage > 25.0 {
                Style::default().fg(Color::Yellow)
            } else {
                Style::default().fg(Color::Green)
            };

            rows.push(Row::new(vec![
                Cell::from(state_name.clone()),
                Cell::from(format!("{avg_usage}")),
                Cell::from(format!("{avg_residency}")),
                Cell::from(format!("{percentage:.1}%")).style(percentage_style),
            ]));
        }

        let table = Table::new(
            rows,
            [
                Constraint::Length(10),
                Constraint::Length(12),
                Constraint::Length(18),
                Constraint::Length(12),
            ],
        )
        .header(header)
        .block(
            Block::default()
                .title("C-States Summary")
                .borders(Borders::ALL)
                .border_style(self.config.theme().border_style()),
        );

        frame.render_widget(table, area);
        Ok(())
    }

    /// Renders power summary
    fn render_power_summary(
        &mut self,
        frame: &mut Frame,
        area: Rect,
        _power_data: &crate::SystemPowerData,
    ) -> Result<()> {
        // Split area horizontally for two charts
        let chart_chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
            .split(area);

        // Render total power chart
        self.render_total_power_chart(frame, chart_chunks[0])?;

        // Render average power per core chart
        self.render_avg_power_chart(frame, chart_chunks[1])?;

        Ok(())
    }

    fn render_total_power_chart(&mut self, frame: &mut Frame, area: Rect) -> Result<()> {
        // Get current tick interval from TUI state
        let tick_interval_ms = self.config.tick_rate_ms() as u64;

        // Get high-density chart data based on chart width and tick interval
        let chart_width = area.width.saturating_sub(2); // Account for borders
        let adaptive_data = self
            .power_snapshot
            .get_adaptive_chart_data(tick_interval_ms, chart_width);

        if adaptive_data.is_empty() {
            // Show placeholder when no data
            let placeholder = Paragraph::new("No data available")
                .block(
                    Block::default()
                        .title("Total Power (W)")
                        .borders(Borders::ALL)
                        .border_style(self.config.theme().border_style()),
                )
                .alignment(Alignment::Center);
            frame.render_widget(placeholder, area);
            return Ok(());
        }

        // Convert adaptive data to chart data points
        let data_points: Vec<(f64, f64)> = adaptive_data
            .iter()
            .map(|point| (point.timestamp as f64, point.total_power_watts))
            .collect();

        // Get current total power value for the legend
        let current_total_power = self.power_snapshot.current.total_power_watts;
        let data_count = adaptive_data.len();

        let dataset = Dataset::default()
            .name(format!(
                "Total Power: {current_total_power:.2}W ({data_count} pts)"
            ))
            .marker(ratatui::symbols::Marker::Braille)
            .style(Style::default().fg(self.config.theme().text_enabled_color()))
            .data(&data_points);

        // Calculate time bounds from adaptive data
        let time_min = adaptive_data.first().unwrap().timestamp as f64;
        let time_max = adaptive_data.last().unwrap().timestamp as f64;
        let time_range = time_max - time_min;
        let time_buffer = time_range * 0.05; // 5% buffer

        // Calculate power bounds from adaptive data
        let actual_min = adaptive_data
            .iter()
            .map(|point| point.total_power_watts)
            .fold(f64::INFINITY, f64::min);
        let actual_max = adaptive_data
            .iter()
            .map(|point| point.total_power_watts)
            .fold(f64::NEG_INFINITY, f64::max);

        let power_range = actual_max - actual_min;
        let power_buffer = (power_range * 0.1).max(1.0); // 10% buffer, min 1W
        let power_min = (actual_min - power_buffer).max(0.0);
        let power_max = actual_max + power_buffer;

        // Format power labels with min/max indicators and time window info
        let time_window_sec = (data_count as u64 * tick_interval_ms) / 1000;
        let power_labels = vec![
            Span::styled(
                format!("Min: {actual_min:.1}W"),
                Style::default().fg(self.theme().negative_value_color()),
            ),
            Span::styled(
                format!(
                    "{:.1}W ({}s)",
                    (power_min + power_max) / 2.0,
                    time_window_sec
                ),
                self.theme().text_color(),
            ),
            Span::styled(
                format!("Max: {actual_max:.1}W"),
                Style::default().fg(self.theme().positive_value_color()),
            ),
        ];

        let chart = Chart::new(vec![dataset])
            .block(
                Block::default()
                    .title("Total Power (W)")
                    .borders(Borders::ALL)
                    .border_style(self.config.theme().border_style()),
            )
            .x_axis(
                Axis::default()
                    .title("Time")
                    .style(Style::default().fg(self.config.theme().text_color()))
                    .bounds([time_min - time_buffer, time_max + time_buffer]),
            )
            .y_axis(
                Axis::default()
                    .title("Watts")
                    .style(Style::default().fg(self.config.theme().text_color()))
                    .labels(power_labels)
                    .bounds([power_min, power_max]),
            );

        frame.render_widget(chart, area);
        Ok(())
    }

    fn render_avg_power_chart(&mut self, frame: &mut Frame, area: Rect) -> Result<()> {
        // Get current tick interval from TUI state
        let tick_interval_ms = self.config.tick_rate_ms() as u64;

        // Get adaptive chart data based on chart width and tick interval
        let chart_width = area.width.saturating_sub(2); // Account for borders
        let adaptive_data = self
            .power_snapshot
            .get_adaptive_chart_data(tick_interval_ms, chart_width);

        if adaptive_data.is_empty() {
            // Show placeholder when no data
            let placeholder = Paragraph::new("No data available")
                .block(
                    Block::default()
                        .title("Avg Power/Core (W)")
                        .borders(Borders::ALL)
                        .border_style(self.config.theme().border_style()),
                )
                .alignment(Alignment::Center);
            frame.render_widget(placeholder, area);
            return Ok(());
        }

        // Convert adaptive data to chart data points
        let data_points: Vec<(f64, f64)> = adaptive_data
            .iter()
            .map(|point| (point.timestamp as f64, point.avg_power_per_core))
            .collect();

        // Calculate current average power per core for the legend
        let current_avg_power = if !self.power_snapshot.current.cores.is_empty() {
            self.power_snapshot.current.total_power_watts
                / self.power_snapshot.current.cores.len() as f64
        } else {
            0.0
        };
        let data_count = adaptive_data.len();

        let dataset = Dataset::default()
            .name(format!(
                "Avg Power/Core: {current_avg_power:.2}W ({data_count} pts)"
            ))
            .marker(ratatui::symbols::Marker::Braille)
            .style(Style::default().fg(self.config.theme().text_disabled_color()))
            .data(&data_points);

        // Calculate time bounds from adaptive data
        let time_min = adaptive_data.first().unwrap().timestamp as f64;
        let time_max = adaptive_data.last().unwrap().timestamp as f64;
        let time_range = time_max - time_min;
        let time_buffer = time_range * 0.05; // 5% buffer

        // Calculate power bounds from adaptive data
        let actual_min = adaptive_data
            .iter()
            .map(|point| point.avg_power_per_core)
            .fold(f64::INFINITY, f64::min);
        let actual_max = adaptive_data
            .iter()
            .map(|point| point.avg_power_per_core)
            .fold(f64::NEG_INFINITY, f64::max);

        let power_range = actual_max - actual_min;
        let power_buffer = (power_range * 0.1).max(0.1); // 10% buffer, min 0.1W
        let power_min = (actual_min - power_buffer).max(0.0);
        let power_max = actual_max + power_buffer;

        // Format power labels with min/max indicators and time window info
        let time_window_sec = (data_count as u64 * tick_interval_ms) / 1000;
        let power_labels = vec![
            Span::styled(
                format!("Min: {actual_min:.2}W"),
                Style::default().fg(self.theme().negative_value_color()),
            ),
            Span::styled(
                format!(
                    "{:.2}W ({}s)",
                    (power_min + power_max) / 2.0,
                    time_window_sec
                ),
                self.theme().text_color(),
            ),
            Span::styled(
                format!("Max: {actual_max:.2}W"),
                Style::default().fg(self.theme().positive_value_color()),
            ),
        ];

        let chart = Chart::new(vec![dataset])
            .block(
                Block::default()
                    .title("Avg Power/Core (W)")
                    .borders(Borders::ALL)
                    .border_style(self.config.theme().border_style()),
            )
            .x_axis(
                Axis::default()
                    .title("Time")
                    .style(Style::default().fg(self.config.theme().text_color()))
                    .bounds([time_min - time_buffer, time_max + time_buffer]),
            )
            .y_axis(
                Axis::default()
                    .title("Watts")
                    .style(Style::default().fg(self.config.theme().text_color()))
                    .labels(power_labels)
                    .bounds([power_min, power_max]),
            );

        frame.render_widget(chart, area);
        Ok(())
    }

    /// Renders battery information
    fn render_battery_info(
        &mut self,
        frame: &mut Frame,
        area: Rect,
        power_data: &crate::SystemPowerData,
    ) -> Result<()> {
        let battery_text = if let Some(battery_level) = power_data.battery_level_percent {
            vec![
                Line::from(vec![
                    Span::styled(
                        "Battery: ",
                        Style::default().fg(self.config.theme().text_color()),
                    ),
                    Span::styled(
                        format!("{battery_level:.1}%"),
                        Style::default().fg(if battery_level < 20.0 {
                            self.config.theme().gradient_3_low(true)
                        } else if battery_level < 50.0 {
                            self.config.theme().gradient_3_mid()
                        } else {
                            self.config.theme().gradient_3_high(true)
                        }),
                    ),
                ]),
                Line::from(vec![
                    Span::styled(
                        "Status: ",
                        Style::default().fg(self.config.theme().text_color()),
                    ),
                    Span::styled(
                        if power_data.battery_charging.unwrap_or(false) {
                            "Charging"
                        } else {
                            "Discharging"
                        },
                        Style::default().fg(if power_data.battery_charging.unwrap_or(false) {
                            self.config.theme().positive_value_color()
                        } else {
                            self.config.theme().negative_value_color()
                        }),
                    ),
                ]),
                Line::from(vec![
                    Span::styled(
                        "Remaining: ",
                        Style::default().fg(self.config.theme().text_color()),
                    ),
                    Span::styled(
                        power_data
                            .battery_remaining_time_minutes
                            .map(|t| format!("{t}m"))
                            .unwrap_or_else(|| "Unknown".to_string()),
                        Style::default().fg(self.config.theme().text_enabled_color()),
                    ),
                ]),
            ]
        } else {
            vec![Line::from(vec![
                Span::styled(
                    "Battery: ",
                    Style::default().fg(self.config.theme().text_color()),
                ),
                Span::styled("Not Available", Style::default().fg(Color::Gray)),
            ])]
        };

        let paragraph = Paragraph::new(battery_text)
            .block(
                Block::default()
                    .title("Battery Info")
                    .borders(Borders::ALL)
                    .border_style(self.config.theme().border_style()),
            )
            .wrap(Wrap { trim: true });

        frame.render_widget(paragraph, area);
        Ok(())
    }

    /// Renders package power summary with comprehensive RAPL data
    fn render_package_power_summary(
        &mut self,
        frame: &mut Frame,
        area: Rect,
        power_data: &crate::SystemPowerData,
    ) -> Result<()> {
        use ratatui::widgets::{Cell, Row, Table};

        if power_data.package_power.is_empty() {
            let placeholder = Paragraph::new("Package power data not available")
                .block(
                    Block::default()
                        .title("Package Power Summary")
                        .borders(Borders::ALL)
                        .border_style(self.config.theme().border_style()),
                )
                .alignment(Alignment::Center);
            frame.render_widget(placeholder, area);
            return Ok(());
        }

        // Create table rows for each package
        let mut rows = Vec::new();
        let mut total_package_power = 0.0;

        // Sort packages by ID for consistent display
        let mut sorted_packages: Vec<_> = power_data.package_power.iter().collect();
        sorted_packages.sort_by_key(|(package_id, _)| *package_id);

        let package_count = sorted_packages.len();

        for (package_id, package_power) in &sorted_packages {
            total_package_power += *package_power;

            // Get comprehensive data from first core in this package for RAPL info
            let package_rapl_data = power_data
                .cores
                .values()
                .find(|core| core.package_id == **package_id);

            let (tdp_str, limit_str, throttle_str) = if let Some(core_data) = package_rapl_data {
                (
                    if core_data.tdp > 0.0 {
                        format!("{:.1}W", core_data.tdp)
                    } else {
                        "-".to_string()
                    },
                    if core_data.power_limit > 0.0 {
                        format!("{:.1}W", core_data.power_limit)
                    } else {
                        "-".to_string()
                    },
                    if core_data.throttle_percent > 0.0 {
                        format!("{:.1}%", core_data.throttle_percent)
                    } else {
                        "-".to_string()
                    },
                )
            } else {
                ("-".to_string(), "-".to_string(), "-".to_string())
            };

            // Calculate percentage of total system power
            let percentage = if power_data.total_power_watts > 0.0 {
                (*package_power / power_data.total_power_watts) * 100.0
            } else {
                0.0
            };

            // Color coding based on power level
            let power_style = if **package_power > 50.0 {
                Style::default().fg(Color::Red)
            } else if **package_power > 25.0 {
                Style::default().fg(Color::Yellow)
            } else {
                Style::default().fg(Color::Green)
            };

            let throttle_style = if package_rapl_data
                .map(|d| d.throttle_percent > 10.0)
                .unwrap_or(false)
            {
                Style::default().fg(Color::Red)
            } else if package_rapl_data
                .map(|d| d.throttle_percent > 1.0)
                .unwrap_or(false)
            {
                Style::default().fg(Color::Yellow)
            } else {
                Style::default().fg(self.config.theme().text_color())
            };

            rows.push(Row::new(vec![
                Cell::from(format!("PKG{package_id}")),
                Cell::from(format!("{:.2}", *package_power)).style(power_style),
                Cell::from(format!("{percentage:.1}%")),
                Cell::from(tdp_str),
                Cell::from(limit_str),
                Cell::from(throttle_str).style(throttle_style),
            ]));
        }

        // Add total row
        if package_count > 1 {
            rows.push(Row::new(vec![
                Cell::from("TOTAL"),
                Cell::from(format!("{total_package_power:.2}"))
                    .style(Style::default().fg(self.config.theme().text_enabled_color())),
                Cell::from("100.0%"),
                Cell::from("-"),
                Cell::from("-"),
                Cell::from("-"),
            ]));
        }

        let header = Row::new(vec![
            Cell::from("Package"),
            Cell::from("Power(W)"),
            Cell::from("% Total"),
            Cell::from("TDP(W)"),
            Cell::from("Limit(W)"),
            Cell::from("Throttle"),
        ])
        .style(Style::default().fg(self.config.theme().text_color()))
        .height(1);

        let table = Table::new(
            rows,
            [
                Constraint::Length(8),  // Package
                Constraint::Length(10), // Power(W)
                Constraint::Length(8),  // % Total
                Constraint::Length(8),  // TDP(W)
                Constraint::Length(10), // Limit(W)
                Constraint::Length(8),  // Throttle
            ],
        )
        .header(header)
        .block(
            Block::default()
                .title(format!(
                    "Package Power Summary (Total: {total_package_power:.2}W)"
                ))
                .borders(Borders::ALL)
                .border_style(self.config.theme().border_style()),
        );

        frame.render_widget(table, area);
        Ok(())
    }

    /// Renders RAM power and uncore frequency summary per node
    fn render_ram_uncore_summary(
        &mut self,
        frame: &mut Frame,
        area: Rect,
        power_data: &crate::SystemPowerData,
    ) -> Result<()> {
        use ratatui::widgets::{Cell, Row, Table};
        use std::collections::HashMap;

        // Organize data by node/package for NUMA systems
        let mut node_data: HashMap<u32, (f64, f64, f64, u32)> = HashMap::new(); // package_id -> (dram_power, uncore_freq, total_dram_energy, core_count)

        if power_data.cores.is_empty() {
            let placeholder = Paragraph::new("No core data available")
                .block(
                    Block::default()
                        .title("RAM & Uncore Summary")
                        .borders(Borders::ALL)
                        .border_style(self.config.theme().border_style()),
                )
                .alignment(Alignment::Center);
            frame.render_widget(placeholder, area);
            return Ok(());
        }

        // Collect data per package/node using enhanced RAPL data
        for core_data in power_data.cores.values() {
            let package_id = core_data.package_id;
            let entry = node_data.entry(package_id).or_insert((0.0, 0.0, 0.0, 0));

            // Use DRAM energy from RAPL readings (only count once per package)
            if core_data.dram_energy_uj > 0 && entry.3 == 0 {
                entry.2 = core_data.dram_energy_uj as f64;
            }

            // Better uncore frequency estimation based on package
            let uncore_freq = if core_data.frequency_mhz > 0.0 {
                // More realistic uncore frequency estimation:
                // - Base uncore frequency is typically 800-1200 MHz
                // - Scales with core frequency but has different ratios per architecture
                let base_uncore = 1000.0; // Base uncore frequency
                let scaling_factor = (core_data.frequency_mhz / 2000.0).min(2.0); // Scale factor based on core freq
                (base_uncore * (1.0 + scaling_factor)).min(3500.0) // Cap at realistic maximum
            } else {
                1000.0 // Default uncore frequency
            };

            if uncore_freq > entry.1 {
                entry.1 = uncore_freq;
            }

            entry.3 += 1; // Core count per package
        }

        // Calculate DRAM power using package power proportional estimation
        // This gives a more realistic DRAM power estimate based on package power
        let package_ids: Vec<u32> = node_data.keys().cloned().collect();

        for package_id in package_ids {
            if let Some((dram_power, _, _, core_count)) = node_data.get_mut(&package_id) {
                if let Some(package_power_watts) = power_data.package_power.get(&package_id) {
                    // DRAM typically consumes 15-25% of package power in modern systems
                    *dram_power = package_power_watts * 0.20; // 20% estimation
                } else {
                    // Fallback: estimate based on core count and typical DRAM power per core
                    *dram_power = (*core_count as f64) * 2.0; // ~2W per core for DRAM
                }
            }
        }

        // Create table rows
        let mut rows = Vec::new();
        let mut total_dram_power = 0.0;

        // Sort by package ID for consistent display
        let mut sorted_nodes: Vec<_> = node_data.iter().collect();
        sorted_nodes.sort_by_key(|(package_id, _)| *package_id);

        let node_count = sorted_nodes.len();

        for (package_id, (dram_power, uncore_freq, _, core_count)) in &sorted_nodes {
            total_dram_power += *dram_power;

            // Color coding for DRAM power
            let dram_power_style = if *dram_power > 10.0 {
                Style::default().fg(Color::Red)
            } else if *dram_power > 5.0 {
                Style::default().fg(Color::Yellow)
            } else {
                Style::default().fg(Color::Green)
            };

            // Color coding for uncore frequency
            let uncore_freq_style = if *uncore_freq > 3000.0 {
                Style::default().fg(Color::Red)
            } else if *uncore_freq > 2000.0 {
                Style::default().fg(Color::Yellow)
            } else {
                Style::default().fg(self.config.theme().text_color())
            };

            rows.push(Row::new(vec![
                Cell::from(format!("N{package_id}")),
                Cell::from(format!("{:.2}", *dram_power)).style(dram_power_style),
                Cell::from(format!("{:.0}", *uncore_freq)).style(uncore_freq_style),
                Cell::from(format!("{}", *core_count)),
            ]));
        }

        // Add total row if multiple nodes
        if node_count > 1 {
            let total_cores: u32 = node_data.values().map(|(_, _, _, count)| *count).sum();
            rows.push(Row::new(vec![
                Cell::from("TOTAL"),
                Cell::from(format!("{total_dram_power:.2}"))
                    .style(Style::default().fg(self.config.theme().text_enabled_color())),
                Cell::from("-"),
                Cell::from(format!("{total_cores}")),
            ]));
        }

        let header = Row::new(vec![
            Cell::from("Node"),
            Cell::from("DRAM(W)"),
            Cell::from("Uncore(MHz)"),
            Cell::from("Cores"),
        ])
        .style(Style::default().fg(self.config.theme().text_color()))
        .height(1);

        let table = Table::new(
            rows,
            [
                Constraint::Length(6),  // Node
                Constraint::Length(9),  // DRAM(W)
                Constraint::Length(12), // Uncore(MHz)
                Constraint::Length(6),  // Cores
            ],
        )
        .header(header)
        .block(
            Block::default()
                .title(format!(
                    "RAM & Uncore Summary (DRAM: {total_dram_power:.2}W)"
                ))
                .borders(Borders::ALL)
                .border_style(self.config.theme().border_style()),
        );

        frame.render_widget(table, area);
        Ok(())
    }

    /// Discovers new processes that have started since initialization
    fn discover_new_processes(&mut self) -> Result<()> {
        // Get all current processes
        let all_procs = procfs::process::all_processes()?;

        // Add any new processes that aren't already in our proc_data
        for proc in all_procs.flatten() {
            let tgid = proc.pid();
            if let std::collections::btree_map::Entry::Vacant(entry) = self.proc_data.entry(tgid) {
                if let Ok(proc_data) = ProcData::from_tgid(tgid, 10) {
                    entry.insert(proc_data);
                }
            }
        }

        Ok(())
    }

    /// Updates all process data for detailed process view
    fn update_all_process_data(&mut self) -> Result<()> {
        // First discover any new processes
        self.discover_new_processes()?;

        let system_util = self.cpu_stat_tracker.read().unwrap().system_total_util();
        let num_cpus = self.topo.all_cpus.len();
        let mut to_remove = vec![];

        for (&i, proc_data) in self.proc_data.iter_mut() {
            if proc_data.update(system_util, num_cpus).is_err() {
                to_remove.push(i);
            }
        }

        for key in to_remove {
            self.proc_data.remove(&key);
        }

        Ok(())
    }

    /// Updates CPU stats - common helper for views that need it
    fn update_cpu_stats(&mut self) -> Result<()> {
        let mut system_guard = self.sys.lock().unwrap();
        self.cpu_stat_tracker
            .write()
            .unwrap()
            .update(&mut system_guard)?;
        Ok(())
    }

    /// Default view: basic system overview
    fn on_tick_default(&mut self) -> Result<()> {
        self.update_cpu_stats()?;
        if let Some(ref mut skel) = self.skel {
            self.bpf_stats = BpfStats::get_from_skel(skel)?;
        }

        match self.memory_view_state {
            ComponentViewState::Default | ComponentViewState::Detail => self.mem_info.update()?,
            _ => {}
        }

        match self.network_view_state {
            ComponentViewState::Default | ComponentViewState::Detail => {
                self.network_stats.update()?;
            }
            _ => {}
        }

        self.update_all_process_data()?;
        let system_util = self.cpu_stat_tracker.read().unwrap().system_total_util();
        let num_cpus = self.topo.all_cpus.len();
        if let Some(proc_data) = self.selected_proc_data() {
            proc_data.update_threads(system_util, num_cpus);
        }

        for node in self.topo.nodes.keys() {
            let node_data = self
                .node_data
                .get_mut(node)
                .expect("NodeData should have been present");
            node_data.add_event_data(self.active_event.event_name(), 0);
        }

        for llc in self.topo.all_llcs.keys() {
            let llc_data = self
                .llc_data
                .get_mut(llc)
                .expect("LlcData should have been present");
            llc_data.add_event_data(self.active_event.event_name(), 0);
        }

        for (cpu, event) in &mut self.active_prof_events {
            let val = event.value(true)?;
            let cpu_data = self
                .cpu_data
                .get_mut(cpu)
                .expect("CpuData should have been present");
            cpu_data.add_event_data(event.event_name(), val);
            let llc_data = self
                .llc_data
                .get_mut(&cpu_data.llc)
                .expect("LlcData should have been present");
            llc_data.add_cpu_event_data(event.event_name(), val);
            let node_data = self
                .node_data
                .get_mut(&cpu_data.node)
                .expect("NodeData should have been present");
            node_data.add_cpu_event_data(event.event_name(), val);
        }

        if self.collect_cpu_freq {
            self.record_cpu_freq()?;
        }
        if self.collect_uncore_freq {
            self.record_uncore_freq()?;
        }

        // Always call filter_events to update the filtered state with all processes
        // even when not actively filtering (when filtering is false, it includes all processes)
        // But skip this for BpfPrograms state as it has its own filtering logic
        if self.state != AppState::BpfPrograms {
            self.filter_events();
        }

        Ok(())
    }

    /// Process view: focus on process/thread data
    fn on_tick_process(&mut self) -> Result<()> {
        if let Some(ref mut skel) = self.skel {
            self.bpf_stats = BpfStats::get_from_skel(skel)?;
        }
        self.update_all_process_data()?;

        if self.in_thread_view {
            let system_util = self.cpu_stat_tracker.read().unwrap().system_total_util();
            let num_cpus = self.topo.all_cpus.len();
            if let Some(proc_data) = self.selected_proc_data() {
                proc_data.update_threads(system_util, num_cpus);
            }
        }

        if self.filtering() {
            self.filter_events();
        }

        Ok(())
    }

    /// Memory view: focus on memory stats
    fn on_tick_memory(&mut self) -> Result<()> {
        self.mem_info.update()?;
        Ok(())
    }

    /// Network view: focus on network stats
    fn on_tick_network(&mut self) -> Result<()> {
        self.network_stats.update()?;
        Ok(())
    }

    /// LLC view: topology and LLC-specific data
    fn on_tick_llc(&mut self) -> Result<()> {
        self.update_cpu_stats()?;
        self.update_all_process_data()?;
        let system_util = self.cpu_stat_tracker.read().unwrap().system_total_util();
        let num_cpus = self.topo.all_cpus.len();
        if let Some(proc_data) = self.selected_proc_data() {
            proc_data.update_threads(system_util, num_cpus);
        }
        if let Some(ref mut skel) = self.skel {
            self.bpf_stats = BpfStats::get_from_skel(skel)?;
        }

        for llc in self.topo.all_llcs.keys() {
            let llc_data = self
                .llc_data
                .get_mut(llc)
                .expect("LlcData should have been present");
            llc_data.add_event_data(self.active_event.event_name(), 0);
        }

        for (cpu, event) in &mut self.active_prof_events {
            let val = event.value(true)?;
            let cpu_data = self
                .cpu_data
                .get_mut(cpu)
                .expect("CpuData should have been present");
            cpu_data.add_event_data(event.event_name(), val);
            let llc_data = self
                .llc_data
                .get_mut(&cpu_data.llc)
                .expect("LlcData should have been present");
            llc_data.add_cpu_event_data(event.event_name(), val);
        }

        if self.collect_cpu_freq {
            self.record_cpu_freq()?;
        }
        if self.collect_uncore_freq {
            self.record_uncore_freq()?;
        }
        if self.filtering() {
            self.filter_events();
        }

        Ok(())
    }

    /// Node view: NUMA topology and node-specific data
    fn on_tick_node(&mut self) -> Result<()> {
        self.update_cpu_stats()?;
        self.update_all_process_data()?;
        let system_util = self.cpu_stat_tracker.read().unwrap().system_total_util();
        let num_cpus = self.topo.all_cpus.len();
        if let Some(proc_data) = self.selected_proc_data() {
            proc_data.update_threads(system_util, num_cpus);
        }
        if let Some(ref mut skel) = self.skel {
            self.bpf_stats = BpfStats::get_from_skel(skel)?;
        }

        for node in self.topo.nodes.keys() {
            let node_data = self
                .node_data
                .get_mut(node)
                .expect("NodeData should have been present");
            node_data.add_event_data(self.active_event.event_name(), 0);
        }

        for (cpu, event) in &mut self.active_prof_events {
            let val = event.value(true)?;
            let cpu_data = self
                .cpu_data
                .get_mut(cpu)
                .expect("CpuData should have been present");
            cpu_data.add_event_data(event.event_name(), val);
            let node_data = self
                .node_data
                .get_mut(&cpu_data.node)
                .expect("NodeData should have been present");
            node_data.add_cpu_event_data(event.event_name(), val);
        }

        if self.collect_cpu_freq {
            self.record_cpu_freq()?;
        }
        if self.collect_uncore_freq {
            self.record_uncore_freq()?;
        }
        if self.filtering() {
            self.filter_events();
        }

        Ok(())
    }

    /// Power view: power-specific data collection
    fn on_tick_power(&mut self) -> Result<()> {
        if self.has_capability_warnings() {
            return Ok(());
        }
        self.update_power_data()?;

        if self.collect_cpu_freq {
            self.record_cpu_freq()?;
        }
        if self.collect_uncore_freq {
            self.record_uncore_freq()?;
        }

        Ok(())
    }

    /// Scheduler view: scheduler stats and basic system data
    fn on_tick_scheduler(&mut self) -> Result<()> {
        if self.has_capability_warnings() {
            return Ok(());
        }
        if let Some(ref mut skel) = self.skel {
            self.bpf_stats = BpfStats::get_from_skel(skel)?;
        }

        // libbpf_rs doesn't generate defaults
        let mut args = default_scxtop_sched_ext_stats();
        let input = ProgramInput {
            context_in: Some(unsafe {
                std::slice::from_raw_parts_mut(
                    &mut args as *mut _ as *mut u8,
                    std::mem::size_of_val(&args),
                )
            }),
            ..Default::default()
        };
        let ret = self
            .skel
            .as_mut()
            .unwrap()
            .progs
            .collect_scx_stats
            .test_run(input)?
            .return_value;
        if ret != 0 {
            return Err(anyhow::anyhow!(
                "collect_scx_stats failed with exit code: {}",
                ret
            ));
        }
        self.scx_stats = args;

        if self.scheduler.is_empty() {
            self.sched_stats_raw.clear();
        } else if let Some(stats_client_read) = self.stats_client.clone() {
            let tx = self.action_tx.clone();
            tokio::spawn(async move {
                let mut client = stats_client_read.lock().await;

                let result = client.request::<JsonValue>("stats", vec![]);
                let action = match result {
                    Ok(stats) => Action::SchedStats(
                        serde_json::to_string_pretty(&stats)
                            .expect("Unable to parse scheduler stats JSON."),
                    ),
                    Err(_) => Action::ReloadStatsClient,
                };
                tx.send(action)?;
                Ok::<(), anyhow::Error>(())
            });
        };

        Ok(())
    }

    /// Event list views: only update event filtering
    fn on_tick_events(&mut self) -> Result<()> {
        if self.filtering() {
            self.filter_events();
        }
        Ok(())
    }

    /// PerfTop view: profiling events and symbol data
    fn on_tick_perf_top(&mut self) -> Result<()> {
        if !self.has_perf_cap {
            return Ok(());
        }
        if let Some(ref mut skel) = self.skel {
            self.bpf_stats = BpfStats::get_from_skel(skel)?;
        }

        for (cpu, event) in &mut self.active_prof_events {
            let val = event.value(true)?;
            let cpu_data = self
                .cpu_data
                .get_mut(cpu)
                .expect("CpuData should have been present");
            cpu_data.add_event_data(event.event_name(), val);
        }

        if self.filtering() {
            self.filter_events();
        }

        Ok(())
    }

    /// MangoApp view: minimal system data
    fn on_tick_mango_app(&mut self) -> Result<()> {
        if let Some(ref mut skel) = self.skel {
            self.bpf_stats = BpfStats::get_from_skel(skel)?;
        }
        Ok(())
    }

    /// Static views: minimal or no updates needed
    fn on_tick_static(&mut self) -> Result<()> {
        Ok(())
    }

    /// Ensures BPF stats tracking is enabled by opening the BPF stats FD if needed
    fn ensure_bpf_stats_enabled(&mut self) -> Result<()> {
        if self.bpf_stats_fd.is_none() {
            match self.enable_bpf_stats() {
                Ok(fd) => {
                    self.bpf_stats_fd = Some(fd);
                    log::debug!("BPF stats tracking enabled with FD: {}", fd);
                }
                Err(e) => {
                    log::warn!("Failed to enable BPF stats tracking: {}", e);
                    return Err(e);
                }
            }
        }
        Ok(())
    }

    /// Disables BPF stats tracking by closing the BPF stats FD
    fn disable_bpf_stats(&mut self) {
        if let Some(fd) = self.bpf_stats_fd.take() {
            unsafe {
                libc::close(fd);
            }
            log::debug!("BPF stats tracking disabled, closed FD: {}", fd);
        }
    }

    /// Enable BPF runtime statistics using BPF_ENABLE_STATS
    fn enable_bpf_stats(&self) -> Result<i32> {
        use libbpf_rs::libbpf_sys::bpf_enable_stats;
        let fd = unsafe { bpf_enable_stats(libbpf_rs::libbpf_sys::BPF_STATS_RUN_TIME) };
        if fd < 0 {
            return Err(anyhow::anyhow!(
                "Failed to enable BPF stats: {}",
                std::io::Error::last_os_error()
            ));
        }
        Ok(fd as i32)
    }

    /// Toggle perf sampling for the selected BPF program
    fn toggle_bpf_perf_sampling(&mut self) -> Result<()> {
        // Only allow toggling in BPF program detail view
        if self.state != AppState::BpfProgramDetail {
            log::debug!("Perf sampling toggle only available in BPF program detail view");
            return Ok(());
        }

        if self.selected_bpf_program_id.is_none() {
            log::warn!("No BPF program selected for perf sampling");
            return Ok(());
        }

        let prog_id = self.selected_bpf_program_id.unwrap();

        if self.bpf_perf_sampling_active {
            // Stop sampling
            self.bpf_perf_sampling_active = false;
            self.detach_perf_sampling();
            log::info!("Stopped perf sampling for BPF program {}", prog_id);
        } else {
            // Start sampling - attach perf events to all CPUs
            self.attach_perf_sampling()?;
            self.bpf_perf_sampling_active = true;
            log::info!(
                "Started perf sampling for BPF program {} (global sample rate: {} samples/sec per CPU)",
                prog_id,
                self.perf_sample_rate
            );
        }

        Ok(())
    }

    /// Update total CPU time from /proc/stat
    fn update_total_cpu_time(&mut self) -> Result<()> {
        use std::fs::File;
        use std::io::{BufRead, BufReader};

        let file = File::open("/proc/stat")?;
        let reader = BufReader::new(file);

        for line in reader.lines() {
            let line = line?;
            if line.starts_with("cpu ") {
                let fields: Vec<&str> = line.split_whitespace().collect();
                if fields.len() > 7 {
                    // Sum all CPU time fields (user, nice, system, idle, iowait, irq, softirq, etc.)
                    // Fields are in jiffies, need to convert to nanoseconds
                    let jiffies_sum: u64 = fields[1..]
                        .iter()
                        .filter_map(|s| s.parse::<u64>().ok())
                        .sum();

                    // Convert jiffies to nanoseconds (assuming 100 HZ, 1 jiffy = 10ms)
                    let clock_ticks_per_sec = 100; // sysconf(_SC_CLK_TCK), typically 100
                    let ns_per_tick = 1_000_000_000 / clock_ticks_per_sec;

                    self.prev_total_cpu_time_ns = self.total_cpu_time_ns;
                    self.total_cpu_time_ns = jiffies_sum * ns_per_tick;
                }
                break;
            }
        }

        Ok(())
    }

    /// Calculate BPF overhead as percentage of CPU time
    fn calculate_bpf_overhead(&mut self) {
        if self.prev_total_cpu_time_ns == 0 {
            return; // First sample, no delta to calculate
        }

        let cpu_time_delta = self
            .total_cpu_time_ns
            .saturating_sub(self.prev_total_cpu_time_ns);
        let bpf_time_delta = self
            .bpf_program_stats
            .total_runtime_ns
            .saturating_sub(self.prev_bpf_total_runtime_ns);

        if cpu_time_delta > 0 {
            let overhead_pct = (bpf_time_delta as f64 / cpu_time_delta as f64) * 100.0;

            // Add to history for trending
            self.bpf_overhead_history.push_back(overhead_pct);

            // Limit history size to terminal width (accounting for borders)
            // This ensures we keep exactly the right amount of data for display
            let max_history = self.terminal_width.saturating_sub(2).max(10) as usize;
            while self.bpf_overhead_history.len() > max_history {
                self.bpf_overhead_history.pop_front();
            }
        }

        // Update previous BPF runtime for next delta calculation
        self.prev_bpf_total_runtime_ns = self.bpf_program_stats.total_runtime_ns;
    }

    /// Runs callbacks to update BPF programs statistics on tick.
    fn on_tick_bpf_programs(&mut self) -> Result<()> {
        // Enable BPF stats tracking if not already enabled
        self.ensure_bpf_stats_enabled()?;

        // Update total CPU time from /proc/stat
        self.update_total_cpu_time()?;

        // Collect BPF program statistics (update existing to maintain history)
        if let Err(e) = self.bpf_program_stats.collect_and_update() {
            log::warn!("Failed to collect BPF program stats: {e}");
        }

        // Calculate BPF overhead percentage
        self.calculate_bpf_overhead();

        // Always refresh filtered programs list (filtering logic is inside the method)
        self.filter_bpf_programs();

        // Get the current display list (filtered or unfiltered, sorted)
        let programs_to_display: Vec<(u32, crate::bpf_prog_data::BpfProgData)> = if self.filtering {
            self.filtered_bpf_programs.clone()
        } else {
            let mut programs: Vec<(u32, crate::bpf_prog_data::BpfProgData)> = self
                .bpf_program_stats
                .programs
                .iter()
                .map(|(id, data)| (*id, data.clone()))
                .collect();
            programs.sort_by(|a, b| {
                b.1.avg_runtime_ns()
                    .partial_cmp(&a.1.avg_runtime_ns())
                    .unwrap_or(std::cmp::Ordering::Equal)
            });
            programs
        };

        // Try to preserve the selection across refreshes
        if let Some(selected_id) = self.selected_bpf_program_id {
            // Find the selected program in the new list
            if let Some(new_index) = programs_to_display
                .iter()
                .position(|(id, _)| *id == selected_id)
            {
                // The selected program is still in the list, update table state to point to its new position
                self.bpf_program_table_state.select(Some(new_index));
            } else {
                // The selected program is no longer in the list (e.g., unloaded or filtered out)
                // Clear the selection and let the initialization logic below handle it
                self.selected_bpf_program_id = None;
                self.bpf_program_table_state.select(None);
            }
        }

        // Initialize table selection if no item is selected and we have programs
        if !programs_to_display.is_empty() && self.bpf_program_table_state.selected().is_none() {
            self.bpf_program_table_state.select(Some(0));
            // Update selected program ID to match the first item
            if let Some((prog_id, _)) = programs_to_display.first() {
                self.selected_bpf_program_id = Some(*prog_id);
            }
        }

        Ok(())
    }

    /// Runs callbacks to update BPF program detail view on tick.
    fn on_tick_bpf_program_detail(&mut self) -> Result<()> {
        // Enable BPF stats tracking if not already enabled
        self.ensure_bpf_stats_enabled()?;

        // Collect BPF program statistics to keep the detailed view up to date (update existing to maintain history)
        if let Err(e) = self.bpf_program_stats.collect_and_update() {
            log::warn!("Failed to collect BPF program stats: {e}");
        }

        // Clear BPF symbols when not sampling
        // (Samples are collected in on_perf_sample when sampling is active)
        if !self.bpf_perf_sampling_active {
            self.bpf_program_filtered_symbols.clear();
            self.bpf_program_symbol_data = SymbolData::new();
        }

        Ok(())
    }
}

impl Drop for App<'_> {
    fn drop(&mut self) {
        // Ensure BPF stats file descriptor is closed when App is dropped
        self.disable_bpf_stats();
    }
}
