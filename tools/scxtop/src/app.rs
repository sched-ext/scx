// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use crate::available_kprobe_events;
use crate::available_perf_events;
use crate::bpf_intf;
use crate::bpf_skel::BpfSkel;
use crate::bpf_stats::BpfStats;
use crate::columns::{
    get_memory_detail_columns, get_memory_detail_metrics, get_memory_rates_columns,
    get_memory_summary_columns, get_pagefault_summary_columns, get_perf_top_columns,
    get_process_columns, get_slab_columns, get_swap_summary_columns, get_thread_columns, Column,
    Columns,
};
use crate::config::get_config_path;
use crate::config::Config;
use crate::get_default_events;
use crate::network_stats::InterfaceStats;
use crate::search;
use crate::util::{
    format_bits, format_bytes, format_hz, read_file_string, sanitize_nbsp, u32_to_i32,
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
    layout::{Alignment, Layout, Margin, Rect},
    prelude::{Direction, Stylize},
    style::{Color, Modifier, Style},
    symbols::bar::{NINE_LEVELS, THREE_LEVELS},
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

use std::collections::{btree_map::Entry, BTreeMap};
use std::os::fd::{AsFd, AsRawFd};
use std::path::Path;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
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
    pub skel: BpfSkel<'a>,
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

    // power monitoring
    power_snapshot: crate::PowerSnapshot,
    power_collector: crate::PowerDataCollector,

    // layout releated
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
}

impl<'a> App<'a> {
    /// Creates a new appliation.
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
        stats_client = stats_client.connect().unwrap_or_else(|_| {
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

        let mut app = Self {
            config,
            localize: true,
            hw_pressure,
            locale: SystemLocale::default()?,
            stats_client,
            cpu_stat_tracker,
            sched_stats_raw: "".to_string(),
            sys: Arc::new(StdMutex::new(System::new_all())),
            mem_info,
            memory_view_state: ComponentViewState::Default,
            network_view_state: ComponentViewState::Default,
            scheduler,
            max_cpu_events,
            max_sched_events: max_cpu_events,
            state: AppState::Default,
            view_state: ViewState::BarChart,
            prev_state: AppState::Default,
            should_quit: Arc::new(AtomicBool::new(false)),
            action_tx,
            skel,
            large_core_count: topo.all_cpus.len() >= 128,
            topo,
            collect_cpu_freq: true,
            collect_uncore_freq: true,
            layered_enabled,
            process_columns: Columns::new(get_process_columns()),
            thread_columns: Columns::new(get_thread_columns()),
            perf_top_columns: Columns::new(get_perf_top_columns(layered_enabled)),
            selected_process: None,
            in_thread_view: false,
            cpu_data,
            llc_data,
            node_data,
            dsq_data: BTreeMap::new(),
            proc_data,
            network_stats: NetworkStatSnapshot::new(100),
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
                // Entering PerfTop view - attach perf sampling and reset selection
                self.selected_symbol_index = 0;
                if let Err(e) = self.attach_perf_sampling() {
                    eprintln!("Failed to attach perf sampling: {e}");
                }
            }
            (AppState::PerfTop, new) if new != AppState::PerfTop => {
                // Leaving PerfTop view - detach perf sampling
                self.detach_perf_sampling();
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
            let prof_event = &self.available_events[self.active_hw_event_id].clone();
            let _ = self.activate_prof_event(prof_event);
            self.max_fps = 1;
            self.frames_since_update = 0;
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
    fn resize_sched_events(&mut self, max_events: usize) {
        for events in self.dsq_data.values_mut() {
            events.set_max_size(max_events);
        }
    }

    /// resizes existing events based on new max value.
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
        new_client = new_client.connect()?;
        if let Some(client_ref) = &self.stats_client {
            let mut client = client_ref.blocking_lock();
            *client = new_client;
        }
        Ok(())
    }

    /// Runs callbacks to update application state on tick.
    fn on_tick(&mut self) -> Result<()> {
        // always grab updated stats
        self.bpf_stats = BpfStats::get_from_skel(&self.skel)?;
        {
            let mut system_guard = self.sys.lock().unwrap();
            self.cpu_stat_tracker
                .write()
                .unwrap()
                .update(&mut system_guard)?;
        }

        // Update memory information
        match self.memory_view_state {
            ComponentViewState::Default | ComponentViewState::Detail => self.mem_info.update()?,
            _ => {}
        }

        // Update network information
        match self.network_view_state {
            ComponentViewState::Default | ComponentViewState::Detail => {
                self.network_stats.update()?;
            }
            _ => {}
        }

        // Update power information - collect power data regularly to keep data fresh
        self.update_power_data()?;

        let system_util = self.cpu_stat_tracker.read().unwrap().system_total_util();
        let mut to_remove = vec![];

        for (&i, proc_data) in self.proc_data.iter_mut() {
            if proc_data.update(system_util).is_err() {
                to_remove.push(i);
            }
        }

        // If we weren't able to update the stats, it is because the process is no longer alive
        for key in to_remove {
            self.proc_data.remove(&key);
        }

        if self.in_thread_view {
            if let Some(proc_data) = self.selected_proc_data() {
                proc_data.update_threads(system_util);
            }
        }

        // Update network stats
        if let Err(e) = self.network_stats.update() {
            eprintln!("Failed to update network stats: {e}");
        }

        // Now that we updated the process data, we need to also update the filtered data
        self.filter_events();

        if self.state == AppState::Scheduler {
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
        };
        // Add entry for nodes
        for node in self.topo.nodes.keys() {
            let node_data = self
                .node_data
                .get_mut(node)
                .expect("NodeData should have been present");
            node_data.add_event_data(self.active_event.event_name(), 0);
        }
        // Add entry for llcs
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
        Ok(())
    }

    /// Generates a CPU bar chart.
    fn cpu_bar(&self, cpu: usize, event: &str) -> Bar {
        let cpu_data = self
            .cpu_data
            .get(&cpu)
            .expect("CpuData should have been present");
        let value = cpu_data
            .event_data_immut(event)
            .last()
            .copied()
            .unwrap_or(0_u64);
        let hw_pressure = cpu_data
            .event_data_immut("hw_pressure")
            .last()
            .copied()
            .unwrap_or(0);
        Bar::default()
            .value(value)
            .label(Line::from(format!(
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
                if self.hw_pressure && hw_pressure > 0 {
                    format!("{hw_pressure}")
                } else {
                    "".to_string()
                }
            )))
            .text_value(if self.localize {
                sanitize_nbsp(value.to_formatted_string(&self.locale))
            } else {
                format!("{value}")
            })
    }

    /// Creates a sparkline for a cpu.
    fn cpu_sparkline(&self, cpu: usize, max: u64, borders: Borders, small: bool) -> Sparkline {
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
        Sparkline::default()
            .data(&data)
            .max(max)
            .direction(RenderDirection::RightToLeft)
            .style(self.theme().sparkline_style())
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
    fn llc_sparkline(&self, llc: usize, max: u64, bottom_border: bool) -> Sparkline {
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
    fn node_sparkline(&self, node: usize, max: u64, bottom_border: bool) -> Sparkline {
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
                    .bar_style(self.theme().sparkline_style())
                    .bar_gap(0)
                    .bar_width(1);

                frame.render_widget(barchart, right);
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
                    .bar_style(self.theme().sparkline_style())
                    .bar_gap(0)
                    .bar_width(1);

                frame.render_widget(barchart, right);
            }
        }

        self.render_table(frame, left, false)
    }

    /// Creates a sparkline for a dsq.
    fn dsq_sparkline(
        &self,
        event: &str,
        dsq_id: u64,
        borders: Borders,
        render_title: bool,
        render_sample_rate: bool,
    ) -> Sparkline {
        let data = if self.dsq_data.contains_key(&dsq_id) {
            let dsq_data = self.dsq_data.get(&dsq_id).unwrap();
            dsq_data.event_data_immut(event)
        } else {
            Vec::new()
        };
        // XXX: this should be max across all CPUs
        let stats = VecStats::new(&data, None);
        Sparkline::default()
            .data(&data)
            .max(stats.max)
            .direction(RenderDirection::RightToLeft)
            .style(self.theme().sparkline_style())
            .block(
                Block::new()
                    .borders(borders)
                    .border_type(BorderType::Rounded)
                    .style(self.theme().border_style())
                    .title_top(if render_sample_rate {
                        Line::from(format!(
                            "sample rate {}",
                            self.skel.maps.data_data.as_ref().unwrap().sample_rate
                        ))
                        .style(self.theme().text_important_color())
                        .right_aligned()
                    } else {
                        Line::from("".to_string())
                    })
                    .title_top(if render_title {
                        Line::from(format!("{event} "))
                            .style(self.theme().title_style())
                            .left_aligned()
                    } else {
                        Line::from("".to_string())
                    })
                    .title_top(
                        Line::from(if self.localize {
                            format!(
                                "dsq {:#X} avg {} max {} min {}",
                                dsq_id,
                                sanitize_nbsp(stats.avg.to_formatted_string(&self.locale)),
                                sanitize_nbsp(stats.max.to_formatted_string(&self.locale)),
                                sanitize_nbsp(stats.min.to_formatted_string(&self.locale))
                            )
                        } else {
                            format!(
                                "dsq {:#X} avg {} max {} min {}",
                                dsq_id, stats.avg, stats.max, stats.min,
                            )
                        })
                        .style(self.theme().title_style())
                        .centered(),
                    ),
            )
    }

    /// Generates dsq sparklines.
    fn dsq_sparklines(
        &self,
        event: &str,
        render_title: bool,
        render_sample_rate: bool,
    ) -> Vec<Sparkline> {
        self.dsq_data
            .iter()
            .filter(|(_dsq_id, dsq_data)| dsq_data.data.contains_key(event))
            .enumerate()
            .map(|(j, (dsq_id, _data))| {
                self.dsq_sparkline(
                    event,
                    *dsq_id,
                    Borders::ALL,
                    j == 0 && render_title,
                    j == 0 && render_sample_rate,
                )
            })
            .collect()
    }

    /// Generates a DSQ bar chart.
    fn dsq_bar(&self, dsq: u64, value: u64, avg: u64, max: u64, min: u64) -> Bar {
        Bar::default()
            .value(value)
            .label(Line::from(if self.localize {
                format!(
                    "{:#X} avg {} max {} min {}",
                    dsq,
                    sanitize_nbsp(avg.to_formatted_string(&self.locale)),
                    sanitize_nbsp(max.to_formatted_string(&self.locale)),
                    sanitize_nbsp(min.to_formatted_string(&self.locale))
                )
            } else {
                format!("{dsq:#X} avg {avg} max {max} min {min}",)
            }))
            .text_value(if self.localize {
                sanitize_nbsp(value.to_formatted_string(&self.locale))
            } else {
                format!("{value}")
            })
    }

    /// Generates DSQ bar charts.
    fn dsq_bars(&self, event: &str) -> Vec<Bar> {
        self.dsq_data
            .iter()
            .filter(|(_dsq_id, dsq_data)| dsq_data.data.contains_key(event))
            .map(|(dsq_id, dsq_data)| {
                let values = dsq_data.event_data_immut(event);
                let value = values.last().copied().unwrap_or(0_u64);
                let stats = VecStats::new(&values, None);
                self.dsq_bar(*dsq_id, value, stats.avg, stats.max, stats.min)
            })
            .collect()
    }

    /// Generates a LLC bar chart.
    fn event_bar(&self, id: usize, value: u64, avg: u64, max: u64, min: u64) -> Bar {
        Bar::default()
            .value(value)
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
    fn llc_bars(&self, event: &str) -> Vec<Bar> {
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
    fn node_bars(&self, event: &str) -> Vec<Bar> {
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
    fn render_scheduler_stats(&mut self, frame: &mut Frame, area: Rect) -> Result<()> {
        let paragraph = Paragraph::new(self.sched_stats_raw.clone());
        let block = Block::bordered()
            .title_top(
                Line::from(self.scheduler.clone())
                    .style(self.theme().title_style())
                    .centered(),
            )
            .title_top(
                Line::from(format!("{}ms", self.config.tick_rate_ms()))
                    .style(self.theme().text_important_color())
                    .right_aligned(),
            )
            .style(self.theme().border_style())
            .border_type(BorderType::Rounded);

        frame.render_widget(paragraph.block(block), area);

        Ok(())
    }

    /// Renders the scheduler state as sparklines.
    fn render_scheduler_sparklines(
        &mut self,
        event: &str,
        frame: &mut Frame,
        area: Rect,
        render_title: bool,
        render_sample_rate: bool,
    ) -> Result<()> {
        let num_dsqs = self
            .dsq_data
            .iter()
            .filter(|(_dsq_id, dsq_data)| dsq_data.data.contains_key(event))
            .count();

        let mut dsq_constraints = Vec::new();

        let area_width = area.width as usize;
        if area_width != self.max_sched_events {
            self.resize_sched_events(area_width);
        }

        if num_dsqs == 0 {
            let block = Block::default()
                .title_top(
                    Line::from(self.scheduler.clone())
                        .style(self.theme().title_style())
                        .centered(),
                )
                .style(self.theme().border_style())
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded);
            frame.render_widget(block, area);
            return Ok(());
        }

        for _ in 0..num_dsqs {
            dsq_constraints.push(Constraint::Ratio(1, num_dsqs as u32));
        }
        let dsqs_verticle = Layout::vertical(dsq_constraints).split(area);

        self.dsq_sparklines(event, render_title, render_sample_rate)
            .iter()
            .enumerate()
            .for_each(|(j, dsq_sparkline)| {
                frame.render_widget(dsq_sparkline, dsqs_verticle[j]);
            });

        Ok(())
    }

    /// Renders the scheduler state as barcharts.
    fn render_scheduler_barchart(
        &mut self,
        event: &str,
        frame: &mut Frame,
        area: Rect,
        render_sample_rate: bool,
    ) -> Result<()> {
        let num_dsqs = self.dsq_data.len();
        if num_dsqs == 0 {
            let block = Block::default()
                .title_top(
                    Line::from(self.scheduler.clone())
                        .style(self.theme().title_style())
                        .centered(),
                )
                .style(self.theme().border_style())
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded);
            frame.render_widget(block, area);
            return Ok(());
        }
        let sample_rate = self.skel.maps.data_data.as_ref().unwrap().sample_rate;

        let dsq_global_iter = self
            .dsq_data
            .values()
            .flat_map(|dsq_data| dsq_data.event_data_immut(event))
            .collect::<Vec<u64>>();
        let stats = VecStats::new(&dsq_global_iter, None);

        let bar_block = Block::default()
            .title_top(
                Line::from(if self.localize {
                    format!(
                        "{} {} avg {} max {} min {}",
                        self.scheduler,
                        event,
                        sanitize_nbsp(stats.avg.to_formatted_string(&self.locale)),
                        sanitize_nbsp(stats.max.to_formatted_string(&self.locale)),
                        sanitize_nbsp(stats.min.to_formatted_string(&self.locale))
                    )
                } else {
                    format!(
                        "{} {} avg {} max {} min {}",
                        self.scheduler, event, stats.avg, stats.max, stats.min,
                    )
                })
                .style(self.theme().title_style())
                .centered(),
            )
            .title_top(if render_sample_rate {
                Line::from(format!("sample rate {sample_rate}"))
                    .style(self.theme().text_important_color())
                    .right_aligned()
            } else {
                Line::from("")
            })
            .style(self.theme().border_style())
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded);

        let dsq_bars: Vec<Bar> = self.dsq_bars(event);

        let barchart = BarChart::default()
            .data(BarGroup::default().bars(&dsq_bars))
            .block(bar_block)
            .max(stats.max)
            .direction(Direction::Horizontal)
            .bar_style(self.theme().sparkline_style())
            .bar_gap(0)
            .bar_width(1);

        frame.render_widget(barchart, area);
        Ok(())
    }

    /// Draw an error message.
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

    /// Renders the scheduler application state.
    fn render_scheduler(
        &mut self,
        event: &str,
        frame: &mut Frame,
        area: Rect,
        render_title: bool,
        render_sample_rate: bool,
    ) -> Result<()> {
        // If no scheduler is attached, display a message and return early.
        if self.scheduler.is_empty() {
            self.render_error_msg(frame, area, "Missing Scheduler");
            return Ok(());
        }

        match self.view_state {
            ViewState::Sparkline => self.render_scheduler_sparklines(
                event,
                frame,
                area,
                render_title,
                render_sample_rate,
            )?,
            ViewState::BarChart => {
                self.render_scheduler_barchart(event, frame, area, render_sample_rate)?
            }
        }

        Ok(())
    }

    /// Renders the event state.
    fn render_event(&mut self, frame: &mut Frame, area: Rect) -> Result<()> {
        match self.view_state {
            ViewState::Sparkline => {
                let num_nodes = self.topo.nodes.len();
                let constraints =
                    vec![Constraint::Ratio(1, num_nodes.try_into().unwrap()); num_nodes];
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
                    let node_constraints =
                        vec![Constraint::Percentage(2), Constraint::Percentage(98)];
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
                        let spark_constraints =
                            vec![Constraint::Ratio(1, col_scale as u32); col_scale];
                        spark_areas
                            .push(Layout::horizontal(spark_constraints).split(cpus_areas[j]));
                    }

                    let node_iter = self
                        .cpu_data
                        .values()
                        .filter(|cpu_data| cpu_data.node == node.id)
                        .flat_map(|cpu_data| {
                            cpu_data.event_data_immut(self.active_event.event_name())
                        })
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
                            self.cpu_sparkline(
                                cpu.id,
                                stats.max,
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
            }
            ViewState::BarChart => {
                let num_nodes = self.topo.nodes.len();
                let constraints =
                    vec![Constraint::Ratio(1, num_nodes.try_into().unwrap()); num_nodes];
                let node_areas = Layout::vertical(constraints).split(area);

                for (i, node) in self.topo.nodes.values().enumerate() {
                    let node_iter = self
                        .cpu_data
                        .values()
                        .filter(|cpu_data| cpu_data.node == node.id)
                        .flat_map(|cpu_data| {
                            cpu_data.event_data_immut(self.active_event.event_name())
                        })
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
                            let cpu_bar = self.cpu_bar(*cpu, self.active_event.event_name());
                            bar_col_data[j % col_scale as usize].push(cpu_bar);
                        })
                        .collect();

                    for (j, col_data) in bar_col_data.iter().enumerate() {
                        let bar_chart = BarChart::default()
                            .data(BarGroup::default().bars(col_data))
                            .max(stats.max)
                            .direction(Direction::Horizontal)
                            .bar_style(self.theme().sparkline_style())
                            .bar_gap(0)
                            .bar_width(1);
                        frame.render_widget(bar_chart, cpus_areas[j % col_scale as usize]);
                    }
                    frame.render_widget(node_block, node_area);
                }
            }
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

        let memory_key = self
            .config
            .active_keymap
            .action_keys_string(Action::SetState(AppState::Memory));

        // Check if the memory key is bound
        if memory_key.is_empty() {
            panic!("Memory key is not bound");
        }

        // Create a single block for all memory tables with keybinding in title
        let title = if memory_key == "m" || memory_key == "M" {
            Line::from(vec![
                Span::styled(
                    &memory_key,
                    self.theme().title_style().add_modifier(Modifier::BOLD),
                ),
                Span::styled("emory Statistics", self.theme().text_color()),
            ])
        } else {
            Line::from(vec![
                Span::styled("Memory Statistics (", self.theme().text_color()),
                Span::styled(&memory_key, self.theme().title_style()),
                Span::styled(")", self.theme().text_color()),
            ])
        };

        let block = Block::bordered()
            .title(title)
            .title_alignment(Alignment::Center)
            .border_type(BorderType::Rounded)
            .style(self.theme().border_style());

        // Get the inner area of the block
        let inner_area = block.inner(area);

        // Split the inner area into three sections for different memory tables
        // Use proportional heights based on content - memory needs more space than swap and page faults
        let [memory_area, swap_area, pagefault_area] = Layout::vertical([
            Constraint::Length(3), // Memory table (header + 1 row + padding)
            Constraint::Length(3), // Swap table (header + 1 row + padding)
            Constraint::Length(3), // Page faults table (header + 1 row + padding)
        ])
        .margin(0) // Remove margin between tables
        .areas(inner_area);

        // Get the columns for memory, swap, and pagefault stats
        let memory_columns = get_memory_summary_columns();
        let swap_columns = get_swap_summary_columns();
        let pagefault_columns = get_pagefault_summary_columns();

        // Render the block first
        frame.render_widget(block, area);

        // Render memory statistics table (without border)
        self.render_memory_table(frame, memory_area, None, &memory_columns, false)?;

        // Render swap statistics table (without border)
        self.render_memory_table(frame, swap_area, None, &swap_columns, false)?;

        // Render page fault statistics table (without border)
        self.render_memory_table(frame, pagefault_area, None, &pagefault_columns, false)?;

        Ok(())
    }

    /// Renders a memory table with the given columns
    fn render_memory_table(
        &mut self,
        frame: &mut Frame,
        area: Rect,
        title: Option<&str>,
        columns: &[Column<(), MemStatSnapshot>],
        with_border: bool,
    ) -> Result<()> {
        let mem_stats = &self.mem_info;

        // Create header cells from column headers
        let header_cells: Vec<Cell> = columns
            .iter()
            .filter(|col| col.visible)
            .map(|col| Cell::from(col.header).style(self.theme().title_style()))
            .collect();

        // Create row data
        let row_cells: Vec<Cell> = columns
            .iter()
            .filter(|col| col.visible)
            .map(|col| {
                let value = (col.value_fn)((), mem_stats);
                Cell::from(value).style(self.theme().text_color())
            })
            .collect();

        // Get constraints for visible columns
        let constraints: Vec<Constraint> = columns
            .iter()
            .filter(|col| col.visible)
            .map(|col| col.constraint)
            .collect();

        // Create the table with rows and constraints
        let mut table = Table::new(vec![Row::new(row_cells)], constraints)
            .header(Row::new(header_cells))
            .column_spacing(1);

        // Add border and title if requested
        if with_border {
            if let Some(table_title) = title {
                table = table.block(
                    Block::bordered()
                        .title(table_title)
                        .title_alignment(Alignment::Center)
                        .border_type(BorderType::Rounded)
                        .style(self.theme().border_style()),
                );
            } else {
                table = table.block(
                    Block::bordered()
                        .border_type(BorderType::Rounded)
                        .style(self.theme().border_style()),
                );
            }
        }

        frame.render_widget(table, area);

        Ok(())
    }

    /// Renders a simplified network summary for the default view.
    fn render_network_summary(&mut self, frame: &mut Frame, area: Rect) -> Result<()> {
        // Create a table for the network interfaces
        let header = Row::new(vec![
            Cell::from("Interface"),
            Cell::from("RX Bytes"),
            Cell::from("TX Bytes"),
            Cell::from("RX Packets"),
            Cell::from("TX Packets"),
        ])
        .height(1)
        .style(self.theme().text_color())
        .bold()
        .underlined();

        let constraints = vec![
            Constraint::Percentage(20),
            Constraint::Percentage(20),
            Constraint::Percentage(20),
            Constraint::Percentage(20),
            Constraint::Percentage(20),
        ];

        let mut interfaces: Vec<(&String, &InterfaceStats)> =
            self.network_stats.interfaces.iter().collect();
        interfaces.sort_by(|a, b| b.1.recv_bytes.cmp(&a.1.recv_bytes));

        // Limit to top 5 interfaces by received bytes
        let top_interfaces = interfaces.into_iter().take(5);

        let rows = top_interfaces.map(|(interface, _)| {
            let delta_recv_bytes = self.network_stats.get_delta_recv_bytes(interface);
            let delta_sent_bytes = self.network_stats.get_delta_sent_bytes(interface);
            let delta_recv_packets = self.network_stats.get_delta_recv_packets(interface);
            let delta_sent_packets = self.network_stats.get_delta_sent_packets(interface);

            Row::new(vec![
                Cell::from(interface.to_string()),
                Cell::from(format_bytes(delta_recv_bytes) + "/s"),
                Cell::from(format_bytes(delta_sent_bytes) + "/s"),
                Cell::from(if self.localize {
                    sanitize_nbsp(delta_recv_packets.to_formatted_string(&self.locale)) + "/s"
                } else {
                    format!("{delta_recv_packets}/s")
                }),
                Cell::from(if self.localize {
                    sanitize_nbsp(delta_sent_packets.to_formatted_string(&self.locale)) + "/s"
                } else {
                    format!("{delta_sent_packets}/s")
                }),
            ])
            .height(1)
            .style(self.theme().text_color())
        });

        let block = Block::bordered()
            .title_top({
                let network_key = self
                    .config
                    .active_keymap
                    .action_keys_string(Action::SetState(AppState::Network));

                if network_key == "N" || network_key == "n" {
                    let key_char = network_key.clone();
                    Line::from(vec![
                        Span::styled(
                            key_char,
                            self.theme().title_style().add_modifier(Modifier::BOLD),
                        ),
                        Span::styled("etwork", self.theme().text_color()),
                    ])
                    .style(self.theme().title_style())
                    .centered()
                } else {
                    Line::from(format!("Network (press {network_key} for full view)"))
                        .style(self.theme().title_style())
                        .centered()
                }
            })
            .border_type(BorderType::Rounded)
            .style(self.theme().border_style());

        let table = Table::new(rows, constraints).header(header).block(block);

        frame.render_widget(table, area);

        Ok(())
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
                    self.skel.maps.data_data.as_ref().unwrap().sample_rate
                ),
                Style::default(),
            )),
            Line::from(Span::styled(
                format!(
                    "{}: increase bpf sample rate ({})",
                    self.config
                        .active_keymap
                        .action_keys_string(Action::IncBpfSampleRate),
                    self.skel.maps.data_data.as_ref().unwrap().sample_rate
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
            let prof_event = &self.available_events[self.active_hw_event_id].clone();
            let _ = self.activate_prof_event(prof_event);
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
        self.render_scheduler("dsq_lat_us", frame, left_areas[1], true, true)?;
        self.render_scheduler("dsq_slice_consumed", frame, left_areas[2], true, false)?;

        Ok(())
    }

    /// Common helper to create table header and constraints from visible columns
    fn create_table_header_and_constraints<T, D>(
        &self,
        visible_columns: &[&crate::columns::Column<T, D>],
    ) -> (Row, Vec<Constraint>) {
        let header = visible_columns
            .iter()
            .map(|col| Cell::from(col.header))
            .collect::<Row>()
            .height(1)
            .style(self.theme().text_color())
            .bold()
            .underlined();

        let constraints = visible_columns
            .iter()
            .map(|col| col.constraint)
            .collect::<Vec<_>>();

        (header, constraints)
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
        let [scroll_area, data_area] =
            Layout::horizontal(vec![Constraint::Min(1), Constraint::Percentage(100)]).areas(area);
        self.update_events_list_size(data_area);

        let visible_columns: Vec<_> = self.process_columns.visible_columns().collect();
        let (header, constraints) = self.create_table_header_and_constraints(&visible_columns);

        let block = Block::bordered()
            .border_type(BorderType::Rounded)
            .border_style(self.theme().border_style())
            .title_top(
                Line::from(format!("Processes (total: {})", self.proc_data.len()))
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
            .title_top(
                Line::from(format!(
                    "sample rate {}{}",
                    self.skel.maps.data_data.as_ref().unwrap().sample_rate,
                    if render_tick_rate {
                        format!(" --- tick rate {}", self.config.tick_rate_ms())
                    } else {
                        "".to_string()
                    }
                ))
                .style(self.theme().text_important_color())
                .right_aligned(),
            );

        // We want to hold the lock for as short as possible
        let (mut filtered_processes, selected): (Vec<_>, usize) = {
            let filtered_state = self.filtered_state.lock().unwrap();
            let processes = filtered_state
                .list
                .iter()
                .filter_map(|item| {
                    item.as_int()
                        .and_then(|pid| self.proc_data.get(&pid).map(|data| (pid, data)))
                })
                .collect();
            (processes, filtered_state.selected)
        };

        filtered_processes.sort_unstable_by(|a, b| {
            b.1.cpu_util_perc
                .partial_cmp(&a.1.cpu_util_perc)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| b.1.num_threads.cmp(&a.1.num_threads))
        });

        let rows = filtered_processes
            .iter()
            .enumerate()
            .map(|(i, (tgid, data))| {
                visible_columns
                    .iter()
                    .map(|col| Cell::from((col.value_fn)(*tgid, data)))
                    .collect::<Row>()
                    .height(1)
                    .style(if i == selected {
                        self.theme().text_important_color()
                    } else {
                        self.theme().text_color()
                    })
            });

        let table = Table::new(rows, constraints).header(header).block(block);

        frame.render_stateful_widget(
            table,
            data_area,
            &mut TableState::new().with_offset(selected),
        );

        frame.render_stateful_widget(
            Scrollbar::new(ScrollbarOrientation::VerticalLeft)
                .begin_symbol(Some("↑"))
                .end_symbol(Some("↓")),
            scroll_area,
            &mut ScrollbarState::new(filtered_processes.len()).position(selected),
        );

        if let Some((tgid, _)) = filtered_processes.get(selected) {
            self.selected_process = Some(*tgid);
        }

        Ok(())
    }

    fn render_thread_table(
        &mut self,
        frame: &mut Frame,
        area: Rect,
        render_tick_rate: bool,
    ) -> Result<()> {
        let [scroll_area, data_area] =
            Layout::horizontal(vec![Constraint::Min(1), Constraint::Percentage(100)]).areas(area);
        self.update_events_list_size(data_area);

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
        let (header, constraints) = self.create_table_header_and_constraints(&visible_columns);

        let block = Block::bordered()
            .border_type(BorderType::Rounded)
            .border_style(self.theme().border_style())
            .title_top(
                Line::from(format!(
                    "Process: {:.15} [{}] (total threads: {})",
                    proc_data.process_name, proc_data.tgid, proc_data.num_threads,
                ))
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
            .title_top(
                Line::from(format!(
                    "sample rate {}{}",
                    self.skel.maps.data_data.as_ref().unwrap().sample_rate,
                    if render_tick_rate {
                        format!(" --- tick rate {}", self.config.tick_rate_ms())
                    } else {
                        "".to_string()
                    }
                ))
                .style(self.theme().text_important_color())
                .right_aligned(),
            );

        let (mut filtered_threads, selected): (Vec<_>, usize) = {
            let filtered_state = self.filtered_state.lock().unwrap();
            let threads = filtered_state
                .list
                .iter()
                .filter_map(|item| {
                    item.as_int()
                        .and_then(|tid| proc_data.threads.get(&tid).map(|data| (tid, data)))
                })
                .collect();
            (threads, filtered_state.selected)
        };

        filtered_threads.sort_unstable_by(|a, b| {
            b.1.cpu_util_perc
                .partial_cmp(&a.1.cpu_util_perc)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        let rows = filtered_threads.iter().enumerate().map(|(i, (tid, data))| {
            visible_columns
                .iter()
                .map(|col| Cell::from((col.value_fn)(*tid, data)))
                .collect::<Row>()
                .height(1)
                .style(if i == selected {
                    self.theme().text_important_color()
                } else {
                    self.theme().text_color()
                })
        });

        let table = Table::new(rows, constraints).header(header).block(block);

        frame.render_stateful_widget(
            table,
            data_area,
            &mut TableState::new().with_offset(selected),
        );

        frame.render_stateful_widget(
            Scrollbar::new(ScrollbarOrientation::VerticalLeft)
                .begin_symbol(Some("↑"))
                .end_symbol(Some("↓")),
            scroll_area,
            &mut ScrollbarState::new(filtered_threads.len()).position(selected),
        );

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
                    Span::styled("Userspace", Style::default().fg(self.theme().text_color())),
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
                        "{clear_key} clear • {dec_key}/{inc_key} adjust rate • {up_key}/{down_key} navigate"
                    )
                })
                .style(self.theme().text_color())
                .centered(),
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
        let area = frame.area();
        let [left, right] = Layout::horizontal([Constraint::Fill(1); 2]).areas(area);

        let mem_stats = &self.mem_info;

        // Get the columns and metrics for the detailed memory view
        let memory_columns = get_memory_detail_columns();
        let memory_metrics = get_memory_detail_metrics();

        // Create header cells from column headers
        let header_cells: Vec<Cell> = memory_columns
            .iter()
            .map(|col| Cell::from(col.header).style(self.theme().title_style()))
            .collect();

        // Create constraints from column constraints
        let constraints: Vec<Constraint> =
            memory_columns.iter().map(|col| col.constraint).collect();

        // Create rows for memory metrics
        let rows = memory_metrics
            .iter()
            .map(|metric| {
                let cells = memory_columns
                    .iter()
                    .map(|col| {
                        Cell::from((col.value_fn)(metric, mem_stats))
                            .style(self.theme().text_important_color())
                    })
                    .collect::<Vec<Cell>>();
                Row::new(cells)
            })
            .collect::<Vec<Row>>();

        let block = Block::bordered()
            .title_top(
                Line::from("Memory Statistics")
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

        let table = Table::new(rows, constraints)
            .header(Row::new(header_cells).style(self.theme().title_style()))
            .block(block);

        frame.render_widget(table, left);

        // Create memory usage gauges and additional stats for the right side
        let [right_top, right_middle, right_bottom] = Layout::vertical([
            Constraint::Min(3),
            Constraint::Percentage(50),
            Constraint::Percentage(50),
        ])
        .areas(right);

        // Split the top section into two columns for memory and swap gauges
        let [gauge_left, gauge_right] =
            Layout::horizontal([Constraint::Fill(1); 2]).areas(right_top);

        // Memory usage gauge
        let mem_used_percent =
            100.0 - (mem_stats.available_kb as f64 / mem_stats.total_kb as f64) * 100.0;
        let mem_used_kb = mem_stats.total_kb - mem_stats.available_kb;
        let mem_gauge = LineGauge::default()
            .block(
                Block::bordered()
                    .title_top(
                        Line::from("Memory Usage")
                            .style(self.theme().title_style())
                            .centered(),
                    )
                    .border_type(BorderType::Rounded)
                    .style(self.theme().border_style()),
            )
            .filled_style(self.theme().text_important_color())
            .ratio(mem_used_percent / 100.0)
            .label(format!(
                "{}/{}",
                format_bytes(mem_used_kb),
                format_bytes(mem_stats.total_kb),
            ));

        frame.render_widget(mem_gauge, gauge_left);

        // Swap usage gauge
        let swap_used_percent = if mem_stats.swap_total_kb > 0 {
            100.0 - (mem_stats.swap_free_kb as f64 / mem_stats.swap_total_kb as f64) * 100.0
        } else {
            0.0
        };
        let swap_used_kb = mem_stats.swap_total_kb - mem_stats.swap_free_kb;
        let swap_gauge = LineGauge::default()
            .block(
                Block::bordered()
                    .title_top(
                        Line::from("Swap Usage")
                            .style(self.theme().title_style())
                            .centered(),
                    )
                    .border_type(BorderType::Rounded)
                    .style(self.theme().border_style()),
            )
            .filled_style(self.theme().text_important_color())
            .ratio(swap_used_percent / 100.0)
            .label(format!(
                "{}/{}",
                format_bytes(swap_used_kb),
                format_bytes(mem_stats.swap_total_kb),
            ));

        frame.render_widget(swap_gauge, gauge_right);

        // Memory rates (pagefaults, swap I/O)
        let memory_rates_columns = get_memory_rates_columns();
        self.render_memory_table(
            frame,
            right_middle,
            Some("Memory Activity Rates"),
            &memory_rates_columns,
            true,
        )?;

        // Slab information section
        let slab_columns = get_slab_columns();
        self.render_memory_table(
            frame,
            right_bottom,
            Some("Slab Information"),
            &slab_columns,
            true,
        )?;

        Ok(())
    }

    /// Renders the network application state.
    fn render_network(&mut self, frame: &mut Frame) -> Result<()> {
        let area = frame.area();
        let [left, right] = Layout::horizontal([Constraint::Fill(1); 2]).areas(area);

        // Create a table for the network interfaces
        let header = Row::new(vec![
            Cell::from("Interface"),
            Cell::from("RX Bits"),
            Cell::from("TX Bits"),
            Cell::from("RX Packets"),
            Cell::from("TX Packets"),
            Cell::from("RX Errors"),
            Cell::from("TX Errors"),
        ])
        .height(1)
        .style(self.theme().text_color())
        .bold()
        .underlined();

        let constraints = vec![
            Constraint::Percentage(20),
            Constraint::Percentage(15),
            Constraint::Percentage(15),
            Constraint::Percentage(15),
            Constraint::Percentage(15),
            Constraint::Percentage(10),
            Constraint::Percentage(10),
        ];

        let mut interfaces: Vec<(&String, &InterfaceStats)> =
            self.network_stats.interfaces.iter().collect();
        interfaces.sort_by(|a, b| a.0.cmp(b.0));

        // Get totals for summary row
        let total_delta_recv_bytes = self.network_stats.get_total_delta_recv_bytes();
        let total_delta_sent_bytes = self.network_stats.get_total_delta_sent_bytes();
        let total_delta_recv_packets = self.network_stats.get_total_delta_recv_packets();
        let total_delta_sent_packets = self.network_stats.get_total_delta_sent_packets();
        let total_delta_recv_errs = self.network_stats.get_total_delta_recv_errs();
        let total_delta_sent_errs = self.network_stats.get_total_delta_sent_errs();

        let mut rows: Vec<Row> = interfaces
            .iter()
            .map(|(interface, _)| {
                let delta_recv_bytes = self.network_stats.get_delta_recv_bytes(interface);
                let delta_sent_bytes = self.network_stats.get_delta_sent_bytes(interface);
                let delta_recv_packets = self.network_stats.get_delta_recv_packets(interface);
                let delta_sent_packets = self.network_stats.get_delta_sent_packets(interface);
                let delta_recv_errs = self.network_stats.get_delta_recv_errs(interface);
                let delta_sent_errs = self.network_stats.get_delta_sent_errs(interface);

                Row::new(vec![
                    Cell::from(interface.to_string()),
                    Cell::from(format_bits(delta_recv_bytes) + "/s"),
                    Cell::from(format_bits(delta_sent_bytes) + "/s"),
                    Cell::from(if self.localize {
                        sanitize_nbsp(delta_recv_packets.to_formatted_string(&self.locale)) + "/s"
                    } else {
                        format!("{delta_recv_packets}/s")
                    }),
                    Cell::from(if self.localize {
                        sanitize_nbsp(delta_sent_packets.to_formatted_string(&self.locale)) + "/s"
                    } else {
                        format!("{delta_sent_packets}/s")
                    }),
                    Cell::from(if self.localize {
                        sanitize_nbsp(delta_recv_errs.to_formatted_string(&self.locale)) + "/s"
                    } else {
                        format!("{delta_recv_errs}/s")
                    }),
                    Cell::from(if self.localize {
                        sanitize_nbsp(delta_sent_errs.to_formatted_string(&self.locale)) + "/s"
                    } else {
                        format!("{delta_sent_errs}/s")
                    }),
                ])
                .height(1)
                .style(self.theme().text_color())
            })
            .collect();

        // Add summary row at the bottom
        rows.push(
            Row::new(vec![
                Cell::from("TOTAL").style(
                    Style::default()
                        .fg(self.theme().text_important_color())
                        .bold(),
                ),
                Cell::from(format_bits(total_delta_recv_bytes) + "/s")
                    .style(Style::default().fg(self.theme().text_important_color())),
                Cell::from(format_bits(total_delta_sent_bytes) + "/s")
                    .style(Style::default().fg(self.theme().text_important_color())),
                Cell::from(if self.localize {
                    sanitize_nbsp(total_delta_recv_packets.to_formatted_string(&self.locale)) + "/s"
                } else {
                    format!("{total_delta_recv_packets}/s")
                })
                .style(Style::default().fg(self.theme().text_important_color())),
                Cell::from(if self.localize {
                    sanitize_nbsp(total_delta_sent_packets.to_formatted_string(&self.locale)) + "/s"
                } else {
                    format!("{total_delta_sent_packets}/s")
                })
                .style(Style::default().fg(self.theme().text_important_color())),
                Cell::from(if self.localize {
                    sanitize_nbsp(total_delta_recv_errs.to_formatted_string(&self.locale)) + "/s"
                } else {
                    format!("{total_delta_recv_errs}/s")
                })
                .style(Style::default().fg(if total_delta_recv_errs > 0 {
                    Color::Red
                } else {
                    self.theme().text_important_color()
                })),
                Cell::from(if self.localize {
                    sanitize_nbsp(total_delta_sent_errs.to_formatted_string(&self.locale)) + "/s"
                } else {
                    format!("{total_delta_sent_errs}/s")
                })
                .style(Style::default().fg(if total_delta_sent_errs > 0 {
                    Color::Red
                } else {
                    self.theme().text_important_color()
                })),
            ])
            .height(1),
        );

        let block = Block::bordered()
            .title_top(
                Line::from("Network Interfaces")
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

        let table = Table::new(rows, constraints).header(header).block(block);

        // Render the network interfaces table with integrated summary
        frame.render_widget(table, left);

        // Render network traffic charts on the right side
        self.render_network_charts(frame, right)?;

        Ok(())
    }

    /// Renders network traffic charts showing historical data per interface.
    fn render_network_charts(&mut self, frame: &mut Frame, area: Rect) -> Result<()> {
        // Get the top 3 most active interfaces by total bytes
        let mut interface_activity: Vec<(String, u64)> = self
            .network_stats
            .interfaces
            .iter()
            .map(|(name, stats)| (name.clone(), stats.recv_bytes + stats.sent_bytes))
            .collect();
        interface_activity.sort_by(|a, b| b.1.cmp(&a.1));
        let top_interfaces: Vec<String> = interface_activity
            .into_iter()
            .take(3)
            .map(|(name, _)| name)
            .collect();

        if top_interfaces.is_empty() {
            let block = Block::bordered()
                .title_top(
                    Line::from("Network Traffic History")
                        .style(self.theme().title_style())
                        .centered(),
                )
                .border_type(BorderType::Rounded)
                .style(self.theme().border_style());

            let paragraph = Paragraph::new("No network interfaces detected")
                .block(block)
                .alignment(Alignment::Center);

            frame.render_widget(paragraph, area);
            return Ok(());
        }

        // Create vertical layout for each interface (each interface gets 2 charts: bytes + packets)
        let interface_count = top_interfaces.len();
        let constraints: Vec<Constraint> = (0..interface_count)
            .map(|_| Constraint::Ratio(1, interface_count as u32))
            .collect();

        let interface_areas = Layout::vertical(constraints).split(area);

        // Render charts for each interface
        for (i, interface) in top_interfaces.iter().enumerate() {
            if i < interface_areas.len() {
                self.render_interface_charts(frame, interface_areas[i], interface)?;
            }
        }

        Ok(())
    }

    /// Renders charts for a single interface (bytes and packets stacked vertically).
    fn render_interface_charts(
        &mut self,
        frame: &mut Frame,
        area: Rect,
        interface: &str,
    ) -> Result<()> {
        // Split area vertically: bytes chart on top, packets chart on bottom
        let [bytes_area, packets_area] =
            Layout::vertical([Constraint::Percentage(50), Constraint::Percentage(50)]).areas(area);

        // Render bytes chart for this interface
        self.render_interface_bytes_chart(frame, bytes_area, interface)?;

        // Render packets chart for this interface
        self.render_interface_packets_chart(frame, packets_area, interface)?;

        Ok(())
    }

    /// Renders the bytes chart for a single interface.
    fn render_interface_bytes_chart(
        &mut self,
        frame: &mut Frame,
        area: Rect,
        interface: &str,
    ) -> Result<()> {
        // Split area to make room for summary statistics at the bottom
        let [chart_area, stats_area] =
            Layout::vertical([Constraint::Fill(1), Constraint::Length(3)]).areas(area);

        let rx_history = self
            .network_stats
            .get_historical_data(interface, "recv_bytes");
        let tx_history = self
            .network_stats
            .get_historical_data(interface, "sent_bytes");

        // Convert to (x, y) coordinates with RX as negative, TX as positive
        let rx_data: Vec<(f64, f64)> = rx_history
            .iter()
            .enumerate()
            .map(|(x, &y)| (x as f64, -(y as f64)))
            .collect();

        let tx_data: Vec<(f64, f64)> = tx_history
            .iter()
            .enumerate()
            .map(|(x, &y)| (x as f64, y as f64))
            .collect();

        // Collect all values for scaling
        let mut all_values = Vec::new();
        all_values.extend(rx_history.iter().map(|&v| v as f64));
        all_values.extend(tx_history.iter().map(|&v| v as f64));

        let marker = self.theme().plot_marker();
        let tx_color = self.theme().positive_value_color();
        let rx_color = self.theme().negative_value_color();

        // Create datasets
        let datasets = vec![
            Dataset::default()
                .name(format!("{interface} RX"))
                .marker(marker)
                .style(Style::default().fg(rx_color))
                .data(&rx_data),
            Dataset::default()
                .name(format!("{interface} TX"))
                .marker(marker)
                .style(Style::default().fg(tx_color))
                .data(&tx_data),
        ];

        let max_value = all_values.iter().fold(0.0f64, |a, &b| a.max(b)).max(1000.0); // Minimum 1000 bytes/s for reasonable scaling
        let history_len = self.network_stats.max_history_size as f64;

        let chart = Chart::new(datasets)
            .block(
                Block::bordered()
                    .title_top(
                        Line::from(format!("{interface} - Bits/s"))
                            .style(self.theme().title_style())
                            .centered(),
                    )
                    .border_type(BorderType::Rounded)
                    .style(self.theme().border_style()),
            )
            .x_axis(
                Axis::default()
                    .title("Time")
                    .style(self.theme().text_color())
                    .bounds([0.0, history_len]),
            )
            .y_axis(
                Axis::default()
                    .title("Bits/s")
                    .style(self.theme().text_color())
                    .bounds([-max_value, max_value])
                    .labels(vec![
                        Span::styled(
                            format!("RX {}", format_bits(max_value as u64)),
                            Style::default().fg(self.theme().negative_value_color()),
                        ),
                        Span::styled("0", self.theme().text_color()),
                        Span::styled(
                            format!("TX {}", format_bits(max_value as u64)),
                            Style::default().fg(self.theme().positive_value_color()),
                        ),
                    ]),
            );

        frame.render_widget(chart, chart_area);

        // Calculate and render summary statistics
        self.render_bytes_summary_stats(frame, stats_area, &rx_history, &tx_history)?;

        Ok(())
    }

    /// Renders summary statistics for bytes data.
    fn render_bytes_summary_stats(
        &mut self,
        frame: &mut Frame,
        area: Rect,
        rx_history: &[u64],
        tx_history: &[u64],
    ) -> Result<()> {
        if rx_history.is_empty() && tx_history.is_empty() {
            return Ok(());
        }

        // Calculate RX statistics
        let (rx_min, rx_max, rx_avg) = if rx_history.is_empty() {
            (0, 0, 0)
        } else {
            let min = *rx_history.iter().min().unwrap_or(&0);
            let max = *rx_history.iter().max().unwrap_or(&0);
            let avg = rx_history.iter().sum::<u64>() / rx_history.len() as u64;
            (min, max, avg)
        };

        // Calculate TX statistics
        let (tx_min, tx_max, tx_avg) = if tx_history.is_empty() {
            (0, 0, 0)
        } else {
            let min = *tx_history.iter().min().unwrap_or(&0);
            let max = *tx_history.iter().max().unwrap_or(&0);
            let avg = tx_history.iter().sum::<u64>() / tx_history.len() as u64;
            (min, max, avg)
        };

        let stats_text = vec![Line::from(vec![
            Span::raw("Min: "),
            Span::styled(
                format_bits(rx_min),
                Style::default().fg(self.theme().negative_value_color()),
            ),
            Span::raw("/"),
            Span::styled(
                format_bits(tx_min),
                Style::default().fg(self.theme().positive_value_color()),
            ),
            Span::raw(" Max: "),
            Span::styled(
                format_bits(rx_max),
                Style::default().fg(self.theme().negative_value_color()),
            ),
            Span::raw("/"),
            Span::styled(
                format_bits(tx_max),
                Style::default().fg(self.theme().positive_value_color()),
            ),
            Span::raw(" Avg: "),
            Span::styled(
                format_bits(rx_avg),
                Style::default().fg(self.theme().negative_value_color()),
            ),
            Span::raw("/"),
            Span::styled(
                format_bits(tx_avg),
                Style::default().fg(self.theme().positive_value_color()),
            ),
        ])];

        let stats_paragraph = Paragraph::new(stats_text).style(self.theme().text_color());

        frame.render_widget(stats_paragraph, area);
        Ok(())
    }

    /// Renders the packets chart for a single interface.
    fn render_interface_packets_chart(
        &mut self,
        frame: &mut Frame,
        area: Rect,
        interface: &str,
    ) -> Result<()> {
        // Split area to make room for summary statistics at the bottom
        let [chart_area, stats_area] =
            Layout::vertical([Constraint::Fill(1), Constraint::Length(3)]).areas(area);

        let rx_history = self
            .network_stats
            .get_historical_data(interface, "recv_packets");
        let tx_history = self
            .network_stats
            .get_historical_data(interface, "sent_packets");

        // Convert to (x, y) coordinates with RX as negative, TX as positive
        let rx_data: Vec<(f64, f64)> = rx_history
            .iter()
            .enumerate()
            .map(|(x, &y)| (x as f64, -(y as f64)))
            .collect();

        let tx_data: Vec<(f64, f64)> = tx_history
            .iter()
            .enumerate()
            .map(|(x, &y)| (x as f64, y as f64))
            .collect();

        // Collect all values for scaling
        let mut all_values = Vec::new();
        all_values.extend(rx_history.iter().map(|&v| v as f64));
        all_values.extend(tx_history.iter().map(|&v| v as f64));

        let marker = self.theme().plot_marker();
        let tx_color = self.theme().positive_value_color();
        let rx_color = self.theme().negative_value_color();

        // Create datasets
        let datasets = vec![
            Dataset::default()
                .name(format!("{interface} RX"))
                .marker(marker)
                .style(Style::default().fg(rx_color))
                .data(&rx_data),
            Dataset::default()
                .name(format!("{interface} TX"))
                .marker(marker)
                .style(Style::default().fg(tx_color))
                .data(&tx_data),
        ];

        let max_value = all_values.iter().fold(0.0f64, |a, &b| a.max(b)).max(100.0); // Minimum 100 packets/s for reasonable scaling
        let history_len = self.network_stats.max_history_size as f64;

        let chart = Chart::new(datasets)
            .block(
                Block::bordered()
                    .title_top(
                        Line::from(format!("{interface} - Packets/s"))
                            .style(self.theme().title_style())
                            .centered(),
                    )
                    .border_type(BorderType::Rounded)
                    .style(self.theme().border_style()),
            )
            .x_axis(
                Axis::default()
                    .title("Time")
                    .style(self.theme().text_color())
                    .bounds([0.0, history_len]),
            )
            .y_axis(
                Axis::default()
                    .title("Packets/s")
                    .style(self.theme().text_color())
                    .bounds([-max_value, max_value])
                    .labels(vec![
                        Span::styled(
                            if self.localize {
                                format!(
                                    "RX {}",
                                    sanitize_nbsp(
                                        (max_value as u64).to_formatted_string(&self.locale)
                                    )
                                )
                            } else {
                                format!("RX {}", max_value as u64)
                            },
                            Style::default().fg(self.theme().negative_value_color()),
                        ),
                        Span::styled("0", self.theme().text_color()),
                        Span::styled(
                            if self.localize {
                                format!(
                                    "TX {}",
                                    sanitize_nbsp(
                                        (max_value as u64).to_formatted_string(&self.locale)
                                    )
                                )
                            } else {
                                format!("TX {}", max_value as u64)
                            },
                            Style::default().fg(self.theme().positive_value_color()),
                        ),
                    ]),
            );

        frame.render_widget(chart, chart_area);

        // Calculate and render summary statistics
        self.render_packets_summary_stats(frame, stats_area, &rx_history, &tx_history)?;

        Ok(())
    }

    /// Renders summary statistics for packets data.
    fn render_packets_summary_stats(
        &mut self,
        frame: &mut Frame,
        area: Rect,
        rx_history: &[u64],
        tx_history: &[u64],
    ) -> Result<()> {
        if rx_history.is_empty() && tx_history.is_empty() {
            return Ok(());
        }

        // Calculate RX statistics
        let (rx_min, rx_max, rx_avg) = if rx_history.is_empty() {
            (0, 0, 0)
        } else {
            let min = *rx_history.iter().min().unwrap_or(&0);
            let max = *rx_history.iter().max().unwrap_or(&0);
            let avg = rx_history.iter().sum::<u64>() / rx_history.len() as u64;
            (min, max, avg)
        };

        // Calculate TX statistics
        let (tx_min, tx_max, tx_avg) = if tx_history.is_empty() {
            (0, 0, 0)
        } else {
            let min = *tx_history.iter().min().unwrap_or(&0);
            let max = *tx_history.iter().max().unwrap_or(&0);
            let avg = tx_history.iter().sum::<u64>() / tx_history.len() as u64;
            (min, max, avg)
        };

        let rx_min_str = if self.localize {
            sanitize_nbsp(rx_min.to_formatted_string(&self.locale))
        } else {
            rx_min.to_string()
        };
        let rx_max_str = if self.localize {
            sanitize_nbsp(rx_max.to_formatted_string(&self.locale))
        } else {
            rx_max.to_string()
        };
        let rx_avg_str = if self.localize {
            sanitize_nbsp(rx_avg.to_formatted_string(&self.locale))
        } else {
            rx_avg.to_string()
        };
        let tx_min_str = if self.localize {
            sanitize_nbsp(tx_min.to_formatted_string(&self.locale))
        } else {
            tx_min.to_string()
        };
        let tx_max_str = if self.localize {
            sanitize_nbsp(tx_max.to_formatted_string(&self.locale))
        } else {
            tx_max.to_string()
        };
        let tx_avg_str = if self.localize {
            sanitize_nbsp(tx_avg.to_formatted_string(&self.locale))
        } else {
            tx_avg.to_string()
        };

        let stats_text = vec![Line::from(vec![
            Span::raw("Min: "),
            Span::styled(
                rx_min_str,
                Style::default().fg(self.theme().negative_value_color()),
            ),
            Span::raw("/"),
            Span::styled(
                tx_min_str,
                Style::default().fg(self.theme().positive_value_color()),
            ),
            Span::raw(" Max: "),
            Span::styled(
                rx_max_str,
                Style::default().fg(self.theme().negative_value_color()),
            ),
            Span::raw("/"),
            Span::styled(
                tx_max_str,
                Style::default().fg(self.theme().positive_value_color()),
            ),
            Span::raw(" Avg: "),
            Span::styled(
                rx_avg_str,
                Style::default().fg(self.theme().negative_value_color()),
            ),
            Span::raw("/"),
            Span::styled(
                tx_avg_str,
                Style::default().fg(self.theme().positive_value_color()),
            ),
        ])];

        let stats_paragraph = Paragraph::new(stats_text).style(self.theme().text_color());

        frame.render_widget(stats_paragraph, area);
        Ok(())
    }

    /// Renders the application to the frame.
    pub fn render(&mut self, frame: &mut Frame) -> Result<()> {
        match self.state {
            AppState::Help => self.render_help(frame),
            AppState::PerfEvent | AppState::KprobeEvent => self.render_event_list(frame),
            AppState::Process => self.render_table(frame, frame.area(), true),
            AppState::MangoApp => self.render_mangoapp(frame),
            AppState::Memory => self.render_memory(frame),
            AppState::Network => self.render_network(frame),
            AppState::Node => self.render_node(frame),
            AppState::Llc => self.render_llc(frame),
            AppState::PerfTop => self.render_perf_top(frame),
            AppState::Power => self.render_power(frame),
            AppState::Scheduler => {
                let [left, right] =
                    Layout::horizontal([Constraint::Fill(1); 2]).areas(frame.area());
                let [left_top, left_center, left_bottom] = Layout::vertical([
                    Constraint::Ratio(1, 3),
                    Constraint::Ratio(1, 3),
                    Constraint::Ratio(1, 3),
                ])
                .areas(left);
                let [right_top, right_bottom] =
                    Layout::vertical(vec![Constraint::Ratio(2, 3), Constraint::Ratio(1, 3)])
                        .areas(right);
                self.render_scheduler("dsq_lat_us", frame, left_top, true, true)?;
                self.render_scheduler("dsq_slice_consumed", frame, left_center, true, false)?;
                self.render_scheduler("dsq_vtime", frame, left_bottom, true, false)?;
                self.render_scheduler("dsq_nr_queued", frame, right_bottom, true, false)?;
                self.render_scheduler_stats(frame, right_top)
            }
            AppState::Tracing => self.render_tracing(frame),
            _ => self.render_default(frame),
        }
    }

    /// Updates app state when the down arrow or mapped key is pressed.
    fn on_down(&mut self) {
        if self.state == AppState::PerfTop {
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
        if self.state == AppState::PerfTop {
            // Handle PerfTop navigation separately
            if self.selected_symbol_index > 0 {
                self.selected_symbol_index -= 1;
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
                && filtered_state.selected > 0
            {
                filtered_state.scroll -= 1;
                filtered_state.selected -= 1;
            }
        }
    }

    /// Updates app state when page down or mapped key is pressed.
    fn on_pg_down(&mut self) {
        if self.state == AppState::PerfTop {
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
        if self.state == AppState::PerfTop {
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
        self.trace_links = vec![
            self.skel.progs.on_softirq_entry.attach()?,
            self.skel.progs.on_softirq_exit.attach()?,
            self.skel.progs.on_ipi_send_cpu.attach()?,
            self.skel.progs.on_sched_fork.attach()?,
            self.skel.progs.on_sched_exec.attach()?,
            self.skel.progs.on_sched_exit.attach()?,
            self.skel.progs.on_sched_wait.attach()?,
        ];

        Ok(())
    }

    /// Records the trace to perfetto output.
    fn stop_recording_trace(&mut self, ts: u64) -> Result<()> {
        self.skel.maps.data_data.as_mut().unwrap().sample_rate = self.prev_bpf_sample_rate;
        self.state = self.prev_state.clone();
        self.trace_manager.stop(None, Some(ts))?;
        self.trace_links.clear();

        Ok(())
    }

    /// Request the BPF side start a trace.
    fn request_start_trace(&mut self) -> Result<()> {
        if self.state == AppState::Tracing {
            return Ok(());
        };

        self.skel.maps.data_data.as_mut().unwrap().trace_duration_ns =
            self.config.trace_duration_ns();
        self.skel.maps.data_data.as_mut().unwrap().trace_warmup_ns = self.config.trace_warmup_ns();

        if self.trace_links.is_empty() {
            self.attach_trace_progs()?;
        }

        let ret = self
            .skel
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
        let sample_rate = self.skel.maps.data_data.as_ref().unwrap().sample_rate as u64;

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
        // Only process perf samples when in PerfTop state
        if self.state == AppState::PerfTop {
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
            match self
                .skel
                .progs
                .perf_sample_handler
                .attach_perf_event(perf_fd)
            {
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

        if attached_count == 0 {
            return Err(anyhow::anyhow!("Failed to attach perf events to any CPU"));
        }

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
                            })
                            .map(|(tid, _)| FilterItem::Int(*tid))
                            .collect()
                    } else {
                        vec![]
                    }
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
        self.skel.maps.data_data.as_mut().unwrap().sample_rate = sample_rate;
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
                    self.reload_stats_client()
                        .expect("Failed to reload stats client");
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
                self.config
                    .set_tick_rate_ms(dur.as_millis().try_into().unwrap());
            }
            Action::ToggleCpuFreq => self.collect_cpu_freq = !self.collect_cpu_freq,
            Action::ToggleUncoreFreq => self.collect_uncore_freq = !self.collect_uncore_freq,
            Action::ToggleLocalization => self.localize = !self.localize,
            Action::ToggleHwPressure => self.hw_pressure = !self.hw_pressure,
            Action::IncBpfSampleRate => {
                if self.state == AppState::PerfTop {
                    // In PerfTop view, control perf sample rate
                    self.perf_sample_rate = (self.perf_sample_rate << 1).max(1);
                } else {
                    // Normal BPF sample rate control
                    let sample_rate = self.skel.maps.data_data.as_ref().unwrap().sample_rate;
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
                } else {
                    // Normal BPF sample rate control
                    let sample_rate = self.skel.maps.data_data.as_ref().unwrap().sample_rate;
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
                AppState::Default | AppState::Llc | AppState::Node | AppState::Memory => {
                    self.filtering = true;
                    self.filter_events();
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
}
