// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use crate::available_kprobe_events;
use crate::available_perf_events;
use crate::bpf_intf;
use crate::bpf_skel::BpfSkel;
use crate::bpf_stats::BpfStats;
use crate::columns::{get_process_columns, get_thread_columns};
use crate::config::get_config_path;
use crate::config::Config;
use crate::get_default_events;
use crate::search;
use crate::util::{format_hz, read_file_string, sanitize_nbsp, u32_to_i32};
use crate::AppState;
use crate::AppTheme;
use crate::Columns;
use crate::CpuData;
use crate::CpuStatTracker;
use crate::EventData;
use crate::FilterItem;
use crate::FilteredState;
use crate::KprobeEvent;
use crate::LlcData;
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

use anyhow::{bail, Result};
use glob::glob;
use libbpf_rs::Link;
use libbpf_rs::ProgramInput;
use num_format::{SystemLocale, ToFormattedString};
use procfs::process::all_processes;
use ratatui::prelude::Constraint;
use ratatui::{
    layout::{Alignment, Direction, Layout, Rect},
    style::{Color, Modifier, Style, Stylize},
    symbols::bar::{NINE_LEVELS, THREE_LEVELS},
    text::{Line, Span},
    widgets::{
        Bar, BarChart, BarGroup, Block, BorderType, Borders, Cell, Clear, Gauge, Paragraph,
        RenderDirection, Row, Scrollbar, ScrollbarOrientation, ScrollbarState, Sparkline, Table,
        TableState,
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

    process_columns: Columns<i32, ProcData>,
    thread_columns: Columns<i32, ThreadData>,
    selected_process: Option<i32>,
    in_thread_view: bool,

    cpu_data: BTreeMap<usize, CpuData>,
    llc_data: BTreeMap<usize, LlcData>,
    node_data: BTreeMap<usize, NodeData>,
    dsq_data: BTreeMap<u64, EventData>,
    proc_data: BTreeMap<i32, ProcData>,

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
}

impl<'a> App<'a> {
    /// Creates a new appliation.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        config: Config,
        scheduler: String,
        max_cpu_events: usize,
        process_id: i32,
        action_tx: UnboundedSender<Action>,
        skel: BpfSkel<'a>,
    ) -> Result<Self> {
        let topo = Topology::new()?;
        let mut cpu_data = BTreeMap::new();
        let mut llc_data = BTreeMap::new();
        let mut node_data = BTreeMap::new();
        let mut proc_data = BTreeMap::new();
        let cpu_stat_tracker = Arc::new(RwLock::new(CpuStatTracker::default()));
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

        let process_columns = Columns::new(get_process_columns());
        let thread_columns = Columns::new(get_thread_columns());

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
            process_columns,
            thread_columns,
            selected_process: None,
            in_thread_view: false,
            cpu_data,
            llc_data,
            node_data,
            dsq_data: BTreeMap::new(),
            proc_data,
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
            process_id,
            prev_process_id: -1,
            trace_links: vec![],
            last_mangoapp_action: None,
            frames_since_update: 0,
            max_fps: 1,
        };

        // Set the initial filter state
        app.filter_events();

        Ok(app)
    }

    /// Returns the state of the application.
    pub fn state(&self) -> AppState {
        self.state.clone()
    }

    /// Sets the state of the application.
    pub fn set_state(&mut self, state: AppState) {
        if self.state == AppState::Tracing {
            return;
        }

        if self.state != AppState::Help
            && self.state != AppState::PerfEvent
            && self.state != AppState::KprobeEvent
            && self.state != AppState::Pause
        {
            self.prev_state = self.state.clone();
        }
        self.state = state;

        if self.state == AppState::PerfEvent
            || self.state == AppState::KprobeEvent
            || self.state == AppState::Default
            || self.state == AppState::Llc
            || self.state == AppState::Node
        {
            self.filtered_state.lock().unwrap().reset();
            self.filter_events();
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

    fn selected_proc_data(&mut self) -> Option<&mut ProcData> {
        self.selected_process
            .and_then(|tgid| self.proc_data.get_mut(&tgid))
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
        let data = llc_data
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
        let data = node_data
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

        self.render_table(frame, left)
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

        self.render_table(frame, left)
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
        self.render_table(frame, left)
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
            Line::from(Span::styled("Key Bindings:", Style::default())),
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
                    "{}: record perfetto trace",
                    self.config
                        .active_keymap
                        .action_keys_string(Action::RequestTrace),
                ),
                Style::default(),
            )),
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
            Line::from(Span::styled(
                format!(
                    "{}: profiling event list scroll up",
                    self.config.active_keymap.action_keys_string(Action::PageUp)
                ),
                Style::default(),
            )),
            Line::from(Span::styled(
                format!(
                    "{}: profiling event list scroll down",
                    self.config
                        .active_keymap
                        .action_keys_string(Action::PageDown)
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
                format!("{pause}: press to pause/unpause"),
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
                    "{}: display scheduler view",
                    self.config
                        .active_keymap
                        .action_keys_string(Action::SetState(AppState::Scheduler))
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
            Line::from(""),
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
    fn render_process_table(&mut self, frame: &mut Frame, area: Rect) -> Result<()> {
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
            );

        // We want to hold the lock for as short as possible
        let (mut filtered_processes, selected): (Vec<(i32, &ProcData)>, usize) = {
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

    fn render_thread_table(&mut self, frame: &mut Frame, area: Rect) -> Result<()> {
        self.update_events_list_size(area);

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
                Line::from(format!(
                    "sample rate {}",
                    self.skel.maps.data_data.as_ref().unwrap().sample_rate
                ))
                .style(self.theme().text_important_color())
                .right_aligned(),
            );

        let mut threads = proc_data.threads.iter().collect::<Vec<_>>();

        threads.sort_unstable_by(|a, b| {
            b.1.cpu_util_perc
                .partial_cmp(&a.1.cpu_util_perc)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        let rows = threads.into_iter().map(|(tid, data)| {
            visible_columns
                .iter()
                .map(|col| Cell::from((col.value_fn)(*tid, data)))
                .collect::<Row>()
                .height(1)
                .style(self.theme().text_color())
        });

        let table = Table::new(rows, constraints).header(header).block(block);

        frame.render_widget(table, area);

        Ok(())
    }

    fn render_table(&mut self, frame: &mut Frame, area: Rect) -> Result<()> {
        if self.in_thread_view {
            self.render_thread_table(frame, area)
        } else {
            self.render_process_table(frame, area)
        }
    }

    /// Renders the application to the frame.
    pub fn render(&mut self, frame: &mut Frame) -> Result<()> {
        match self.state {
            AppState::Help => self.render_help(frame),
            AppState::PerfEvent | AppState::KprobeEvent => self.render_event_list(frame),
            AppState::MangoApp => self.render_mangoapp(frame),
            AppState::Node => self.render_node(frame),
            AppState::Llc => self.render_llc(frame),
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
        let mut filtered_state = self.filtered_state.lock().unwrap();
        if (self.state == AppState::PerfEvent
            || self.state == AppState::KprobeEvent
            || self.state == AppState::Default
            || self.state == AppState::Llc
            || self.state == AppState::Node)
            && filtered_state.scroll < filtered_state.count - 1
        {
            filtered_state.scroll += 1;
            filtered_state.selected += 1;
        }
    }

    /// Updates app state when the up arrow or mapped key is pressed.
    fn on_up(&mut self) {
        let mut filtered_state = self.filtered_state.lock().unwrap();
        if (self.state == AppState::PerfEvent
            || self.state == AppState::KprobeEvent
            || self.state == AppState::Default
            || self.state == AppState::Llc
            || self.state == AppState::Node)
            && filtered_state.scroll > 0
        {
            filtered_state.scroll -= 1;
            filtered_state.selected -= 1;
        }
    }

    /// Updates app state when page down or mapped key is pressed.
    fn on_pg_down(&mut self) {
        let mut filtered_state = self.filtered_state.lock().unwrap();
        if (self.state == AppState::PerfEvent
            || self.state == AppState::KprobeEvent
            || self.state == AppState::Default
            || self.state == AppState::Llc
            || self.state == AppState::Node)
            && filtered_state.scroll <= filtered_state.count - self.events_list_size
        {
            filtered_state.scroll += self.events_list_size - 1;
            filtered_state.selected += (self.events_list_size - 1) as usize;
        }
    }

    /// Updates app state when page up or mapped key is pressed.
    fn on_pg_up(&mut self) {
        let mut filtered_state = self.filtered_state.lock().unwrap();
        if self.state == AppState::PerfEvent
            || self.state == AppState::KprobeEvent
            || self.state == AppState::Default
            || self.state == AppState::Llc
            || self.state == AppState::Node
        {
            if filtered_state.scroll > self.events_list_size {
                filtered_state.scroll -= self.events_list_size - 1;
                filtered_state.selected -= (self.events_list_size - 1) as usize;
            } else {
                filtered_state.scroll = 0;
                filtered_state.selected = 0;
            }
        }
    }

    /// Updates app state when the enter key is pressed.
    fn on_enter(&mut self) -> Result<()> {
        if self.state == AppState::PerfEvent || self.state == AppState::KprobeEvent {
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
        } else if self.state == AppState::Default
            || self.state == AppState::Node
            || self.state == AppState::Llc
        {
            // Reset process view
            self.filtering = false;
            self.event_input_buffer.clear();
            self.filter_events();

            if let Some(proc_data) = self.selected_proc_data() {
                proc_data.init_threads()?;

                // Kick off thread view
                self.in_thread_view = true;
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
            AppState::Default | AppState::Llc | AppState::Node => {
                if self.filtering {
                    self.filtering = false;
                    self.event_input_buffer.clear();
                    self.filter_events();
                } else if self.in_thread_view {
                    if let Some(proc_data) = self.selected_proc_data() {
                        proc_data.clear_threads();
                    }
                    self.in_thread_view = false;
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
        if self.state == AppState::Tracing && action.ts > self.trace_start {
            self.trace_manager.on_sched_wakeup(action);
        }
    }

    fn on_sched_waking(&mut self, action: &SchedWakingAction) {
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

        let next_dsq_id = Self::classify_dsq(*next_dsq_id);
        let prev_dsq_id = Self::classify_dsq(*prev_dsq_id);

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

    pub fn filter_events(&mut self) {
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
            AppState::Default | AppState::Llc | AppState::Node => self
                .proc_data
                .iter()
                .filter(|(_, proc_data)| {
                    search::contains_spread(&proc_data.process_name, &self.event_input_buffer)
                        .is_some()
                        || search::contains_spread(
                            &proc_data.tgid.to_string(),
                            &self.event_input_buffer,
                        )
                        .is_some()
                })
                .map(|(tgid, _)| FilterItem::Int(*tgid))
                .collect(),
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
            _ => bail!("Invalid table name"),
        };

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
                if *state == self.state {
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
            Action::ClearEvent => self.reset_prof_events()?,
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
                let sample_rate = self.skel.maps.data_data.as_ref().unwrap().sample_rate;
                if sample_rate == 0 {
                    self.update_bpf_sample_rate(8_u32);
                } else {
                    self.update_bpf_sample_rate(sample_rate << 2);
                }
            }
            Action::DecBpfSampleRate => {
                let sample_rate = self.skel.maps.data_data.as_ref().unwrap().sample_rate;
                if sample_rate > 0 {
                    // prevent overly aggressive bpf sampling, but allow disabling sampling
                    let new_rate = sample_rate >> 2;
                    self.update_bpf_sample_rate(if new_rate >= 8 { new_rate } else { 0 });
                }
            }
            Action::Quit => match self.state {
                AppState::Help => {
                    self.handle_action(&Action::SetState(AppState::Help))?;
                }
                AppState::Default | AppState::Llc | AppState::Node => {
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
                AppState::Default | AppState::Llc | AppState::Node => {
                    self.filtering = true;
                    self.filter_events();
                }
                _ => {}
            },
            Action::InputEntry(input) => {
                self.event_input_buffer.push_str(input);
                self.filter_events();
            }
            Action::Backspace => {
                self.event_input_buffer.pop();
                self.filter_events();
            }
            Action::Esc => {
                self.on_escape()?;
            }
            _ => {}
        };
        Ok(())
    }
}
