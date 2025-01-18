// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use crate::available_perf_events;
use crate::bpf_skel::BpfSkel;
use crate::format_hz;
use crate::read_file_string;
use crate::Action;
use crate::AppState;
use crate::AppTheme;
use crate::CpuData;
use crate::EventData;
use crate::KeyMap;
use crate::LlcData;
use crate::NodeData;
use crate::PerfEvent;
use crate::VecStats;
use crate::ViewState;
use crate::APP;
use crate::LICENSE;
use crate::SCHED_NAME_PATH;
use anyhow::Result;
use glob::glob;
use ratatui::prelude::Constraint;
use ratatui::{
    layout::{Alignment, Direction, Layout, Rect},
    style::{Modifier, Style, Stylize},
    symbols::bar::{NINE_LEVELS, THREE_LEVELS},
    text::{Line, Span},
    widgets::{
        Bar, BarChart, BarGroup, Block, BorderType, Borders, Paragraph, RenderDirection, Scrollbar,
        ScrollbarOrientation, ScrollbarState, Sparkline,
    },
    Frame,
};
use regex::Regex;
use scx_utils::misc::read_file_usize;
use scx_utils::Topology;
use std::collections::{BTreeMap, HashSet};
use std::path::Path;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use tokio::sync::mpsc::UnboundedSender;

const DSQ_VTIME_CUTOFF: u64 = 1_000_000_000_000_000;

/// App is the struct for scxtop application state.
pub struct App<'a> {
    keymap: KeyMap,
    scheduler: String,
    max_cpu_events: usize,
    state: AppState,
    prev_state: AppState,
    theme: AppTheme,
    view_state: ViewState,
    pub counter: i64,
    pub tick_rate_ms: usize,
    pub should_quit: Arc<AtomicBool>,
    pub action_tx: UnboundedSender<Action>,
    pub skel: BpfSkel<'a>,
    topo: Topology,
    collect_cpu_freq: bool,
    collect_uncore_freq: bool,
    event_scroll_state: ScrollbarState,
    event_scroll: u16,

    active_hw_event: PerfEvent,
    active_hw_event_id: usize,
    active_perf_events: BTreeMap<usize, PerfEvent>,
    available_events: Vec<PerfEvent>,

    available_perf_events: BTreeMap<String, HashSet<String>>,
    cpu_data: BTreeMap<usize, CpuData>,
    llc_data: BTreeMap<usize, LlcData>,
    node_data: BTreeMap<usize, NodeData>,
    dsq_data: BTreeMap<u64, EventData>,
}

impl<'a> App<'a> {
    /// Creates a new appliation.
    pub fn new(
        scheduler: String,
        keymap: KeyMap,
        max_cpu_events: usize,
        tick_rate_ms: usize,
        action_tx: UnboundedSender<Action>,
        skel: BpfSkel<'a>,
    ) -> Result<Self> {
        let topo = Topology::new()?;
        let mut cpu_data = BTreeMap::new();
        let mut llc_data = BTreeMap::new();
        let mut node_data = BTreeMap::new();
        let mut active_perf_events = BTreeMap::new();
        let active_hw_event = PerfEvent::new("hw".to_string(), "cycles".to_string(), 0);
        let available_perf_events = available_perf_events()?;
        let default_events = PerfEvent::default_events();
        let default_events_str = default_events
            .iter()
            .map(|event| event.event.clone())
            .collect::<Vec<String>>();
        for cpu in topo.all_cpus.values() {
            let mut event = PerfEvent::new("hw".to_string(), "cycles".to_string(), cpu.id);
            event.attach()?;
            active_perf_events.insert(cpu.id, event);
            let mut data =
                CpuData::new(cpu.id, cpu.core_id, cpu.llc_id, cpu.node_id, max_cpu_events);
            data.initialize_events(&default_events_str);
            cpu_data.insert(cpu.id, data);
        }
        for llc in topo.all_llcs.values() {
            let mut data = LlcData::new(llc.id, llc.node_id, max_cpu_events);
            data.initialize_events(&default_events_str);
            llc_data.insert(llc.id, data);
        }
        for node in topo.nodes.values() {
            let mut data = NodeData::new(node.id, max_cpu_events);
            data.initialize_events(&default_events_str);
            node_data.insert(node.id, data);
        }

        let app = Self {
            scheduler,
            max_cpu_events,
            keymap,
            theme: AppTheme::Default,
            state: AppState::Default,
            view_state: ViewState::BarChart,
            prev_state: AppState::Default,
            counter: 0,
            tick_rate_ms,
            should_quit: Arc::new(AtomicBool::new(false)),
            action_tx,
            skel,
            topo,
            collect_cpu_freq: true,
            collect_uncore_freq: true,
            cpu_data,
            llc_data,
            node_data,
            dsq_data: BTreeMap::new(),
            event_scroll_state: ScrollbarState::new(available_perf_events.len()).position(0),
            event_scroll: 0,
            active_hw_event_id: 0,
            active_hw_event,
            available_perf_events,
            active_perf_events,
            available_events: default_events,
        };

        Ok(app)
    }

    /// Returns the state of the application.
    pub fn state(&self) -> AppState {
        self.state.clone()
    }

    /// Sets the state of the application.
    pub fn set_state(&mut self, state: AppState) {
        self.prev_state = self.state.clone();
        self.state = state;
    }

    /// Returns the current theme of the application
    pub fn theme(&self) -> AppTheme {
        self.theme.clone()
    }

    /// Sets the theme of the application.
    pub fn set_theme(&mut self, theme: AppTheme) {
        self.theme = theme
    }

    /// Stop all active perf events.
    fn stop_perf_events(&mut self) {
        for cpu_data in self.cpu_data.values_mut() {
            cpu_data.data.clear();
        }
        self.active_perf_events.clear();
    }

    /// Activates the next event.
    fn next_event(&mut self) -> Result<()> {
        self.active_perf_events.clear();
        if self.active_hw_event_id == self.available_events.len() - 1 {
            self.active_hw_event_id = 0;
        } else {
            self.active_hw_event_id += 1;
        }
        let perf_event = &self.available_events[self.active_hw_event_id].clone();

        self.active_hw_event = perf_event.clone();
        self.activate_perf_event(perf_event)
    }

    /// Activates the previous event.
    fn prev_event(&mut self) -> Result<()> {
        self.active_perf_events.clear();
        if self.active_hw_event_id == 0 {
            self.active_hw_event_id = self.available_events.len() - 1;
        } else {
            self.active_hw_event_id -= 1;
        }
        let perf_event = &self.available_events[self.active_hw_event_id].clone();

        self.active_hw_event = perf_event.clone();
        self.activate_perf_event(perf_event)
    }

    /// Activates the next view state.
    fn next_view_state(&mut self) {
        self.view_state = self.view_state.next();
    }

    /// Activates a perf event, stopping any active perf events.
    fn activate_perf_event(&mut self, perf_event: &PerfEvent) -> Result<()> {
        if !self.active_perf_events.is_empty() {
            self.stop_perf_events();
        }
        for cpu_id in self.topo.all_cpus.keys() {
            let mut event = PerfEvent::new(
                perf_event.subsystem.clone(),
                perf_event.event.clone(),
                *cpu_id,
            );
            event.attach()?;
            self.active_perf_events.insert(*cpu_id, event);
        }
        Ok(())
    }

    fn record_cpu_freq(&mut self) -> Result<()> {
        for cpu_id in self.topo.all_cpus.keys() {
            let file = format!(
                "/sys/devices/system/cpu/cpu{}/cpufreq/scaling_cur_freq",
                *cpu_id
            );
            let path = Path::new(&file);
            let freq = read_file_usize(path).unwrap_or(0);
            let cpu_data = self.cpu_data.entry(*cpu_id).or_insert(CpuData::new(
                *cpu_id,
                0,
                0,
                0,
                self.max_cpu_events,
            ));

            cpu_data.add_event_data("cpu_freq".to_string(), freq as u64);
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
                    let uncore_freq = read_file_usize(path).unwrap_or(0);
                    for cpu in self.topo.all_cpus.values() {
                        if cpu.package_id != package_id {
                            continue;
                        }
                        let node_data = self
                            .node_data
                            .entry(cpu.node_id)
                            .or_insert(NodeData::new(cpu.node_id, self.max_cpu_events));
                        node_data.add_event_data("uncore_freq".to_string(), uncore_freq as u64);
                    }
                }
            }
        }
        Ok(())
    }

    /// Runs callbacks to update application state on tick.
    fn on_tick(&mut self) -> Result<()> {
        // Add entry for nodes
        for node in self.topo.nodes.keys() {
            let node_data = self
                .node_data
                .entry(*node)
                .or_insert(NodeData::new(*node, self.max_cpu_events));
            node_data.add_event_data(self.active_hw_event.event.clone(), 0);
        }
        // Add entry for llcs
        for llc in self.topo.all_llcs.keys() {
            let llc_data =
                self.llc_data
                    .entry(*llc)
                    .or_insert(LlcData::new(*llc, 0, self.max_cpu_events));
            llc_data.add_event_data(self.active_hw_event.event.clone(), 0);
        }

        for (cpu, event) in &mut self.active_perf_events {
            let val = event.value(true)?;
            let cpu_data = self
                .cpu_data
                .entry(*cpu)
                // XXX: fixme
                .or_insert(CpuData::new(*cpu, 0, 0, 0, self.max_cpu_events));
            cpu_data.add_event_data(event.event.clone(), val);
            let llc_data = self.llc_data.entry(cpu_data.llc).or_insert(LlcData::new(
                cpu_data.llc,
                0,
                self.max_cpu_events,
            ));
            llc_data.add_cpu_event_data(event.event.clone(), val);
            let node_data = self
                .node_data
                .entry(cpu_data.node)
                .or_insert(NodeData::new(cpu_data.node, self.max_cpu_events));
            node_data.add_cpu_event_data(event.event.clone(), val);
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
    fn cpu_bar(&self, cpu: usize, event: String) -> Bar {
        let value = self
            .cpu_data
            .get(&cpu)
            .unwrap()
            .event_data_immut(event.clone())
            .last()
            .copied()
            .unwrap_or(0_u64);
        Bar::default()
            .value(value)
            .label(Line::from(format!(
                "{}{}",
                cpu,
                if self.collect_cpu_freq {
                    let cpu_data = self.cpu_data.get(&cpu).unwrap();
                    format!(
                        " {}",
                        format_hz(
                            cpu_data
                                .event_data_immut("cpu_freq".to_string())
                                .last()
                                .copied()
                                .unwrap_or(0)
                        )
                    )
                } else {
                    "".to_string()
                }
            )))
            .text_value(format!("{}", value))
    }

    /// Creates a sparkline for a cpu.
    fn cpu_sparkline(&self, cpu: usize, max: u64, borders: Borders, small: bool) -> Sparkline {
        let mut perf: u64 = 0;
        let mut cpu_freq: u64 = 0;
        let data = if self.cpu_data.contains_key(&cpu) {
            let cpu_data = self.cpu_data.get(&cpu).unwrap();
            perf = cpu_data
                .event_data_immut("perf".to_string())
                .last()
                .copied()
                .unwrap_or(0);
            if self.collect_cpu_freq {
                cpu_freq = cpu_data
                    .event_data_immut("cpu_freq".to_string())
                    .last()
                    .copied()
                    .unwrap_or(0);
            }
            cpu_data.event_data_immut(self.active_hw_event.event.clone())
        } else {
            Vec::new()
        };
        Sparkline::default()
            .data(&data)
            .max(max)
            .direction(RenderDirection::RightToLeft)
            .style(self.theme.sparkline_style())
            .bar_set(if small { THREE_LEVELS } else { NINE_LEVELS })
            .block(
                Block::new()
                    .title(format!(
                        "{} perf({}){}",
                        cpu,
                        if perf == 0 {
                            "".to_string()
                        } else {
                            format!("{}", perf)
                        },
                        if self.collect_cpu_freq {
                            format!(" {}", format_hz(cpu_freq))
                        } else {
                            "".to_string()
                        }
                    ))
                    .borders(borders)
                    .border_type(BorderType::Rounded)
                    .style(self.theme.border_style()),
            )
    }

    /// creates as sparkline for a llc.
    fn llc_sparkline(&self, llc: usize, bottom_border: bool) -> Sparkline {
        let data = if self.llc_data.contains_key(&llc) {
            let llc_data = self.llc_data.get(&llc).unwrap();
            llc_data.event_data_immut(self.active_hw_event.event.clone())
        } else {
            Vec::new()
        };
        let stats = VecStats::new(&data, true, true, true, None);

        Sparkline::default()
            .data(&data)
            .direction(RenderDirection::RightToLeft)
            .style(self.theme.sparkline_style())
            .block(
                Block::new()
                    .borders(if bottom_border {
                        Borders::LEFT | Borders::RIGHT | Borders::BOTTOM
                    } else {
                        Borders::LEFT | Borders::RIGHT
                    })
                    .style(self.theme.border_style())
                    .border_type(BorderType::Rounded)
                    .title_top(
                        Line::from(format!(
                            "LLC {} avg {} max {} min {}",
                            llc, stats.avg, stats.max, stats.min
                        ))
                        .style(self.theme.title_style())
                        .left_aligned(),
                    ),
            )
    }

    /// creates as sparkline for a node.
    fn node_sparkline(&self, node: usize, bottom_border: bool) -> Sparkline {
        let data = if self.llc_data.contains_key(&node) {
            let node_data = self.node_data.get(&node).unwrap();
            node_data.event_data_immut(self.active_hw_event.event.clone())
        } else {
            Vec::new()
        };
        let stats = VecStats::new(&data, true, true, true, None);

        Sparkline::default()
            .data(&data)
            .direction(RenderDirection::RightToLeft)
            .style(self.theme.sparkline_style())
            .block(
                Block::new()
                    .borders(if bottom_border {
                        Borders::LEFT | Borders::RIGHT | Borders::BOTTOM
                    } else {
                        Borders::LEFT | Borders::RIGHT
                    })
                    .border_type(BorderType::Rounded)
                    .style(self.theme.border_style())
                    .title_top(
                        Line::from(format!(
                            "{}",
                            if self.collect_uncore_freq {
                                "uncore ".to_string()
                                    + &format_hz(
                                        self.node_data
                                            .get(&node)
                                            .unwrap()
                                            .event_data_immut("uncore_freq".to_string())
                                            .last()
                                            .copied()
                                            .unwrap_or(0_u64),
                                    )
                            } else {
                                "".to_string()
                            }
                        ))
                        .style(self.theme.text_important_color())
                        .right_aligned(),
                    )
                    .title_top(
                        Line::from(format!(
                            "Node {} avg {} max {} min {}",
                            node, stats.avg, stats.max, stats.min
                        ))
                        .style(self.theme.title_style())
                        .left_aligned(),
                    ),
            )
    }

    /// Renders the llc application state.
    fn render_llc(&mut self, frame: &mut Frame) -> Result<()> {
        let [left, right] = Layout::horizontal([Constraint::Fill(1); 2]).areas(frame.area());
        let [top_left, bottom_left] = Layout::vertical([Constraint::Fill(1); 2]).areas(left);
        let num_llcs = self.topo.all_llcs.len();

        let llc_iter = self
            .llc_data
            .values()
            .map(|llc_data| llc_data.event_data_immut(self.active_hw_event.event.clone()))
            .flatten()
            .collect::<Vec<u64>>();
        let stats = VecStats::new(&llc_iter, true, true, true, None);

        match self.view_state {
            ViewState::Sparkline => {
                let mut llcs_constraints = vec![Constraint::Length(1)];
                for _ in 0..num_llcs {
                    llcs_constraints.push(Constraint::Ratio(1, num_llcs as u32));
                }
                let llcs_verticle = Layout::vertical(llcs_constraints).split(right);

                let llc_block = Block::bordered()
                    .title_top(
                        Line::from(format!(
                            "LLCs ({}) avg {} max {} min {}",
                            self.active_hw_event.event, stats.avg, stats.max, stats.min
                        ))
                        .style(self.theme.title_style())
                        .centered(),
                    )
                    .border_type(BorderType::Rounded)
                    .title_top(
                        Line::from(format!("{}ms", self.tick_rate_ms))
                            .style(self.theme.text_important_color())
                            .right_aligned(),
                    )
                    .style(self.theme.border_style());

                frame.render_widget(llc_block, llcs_verticle[0]);

                let llc_sparklines: Vec<Sparkline> = self
                    .topo
                    .all_llcs
                    .keys()
                    .map(|llc_id| self.llc_sparkline(llc_id.clone(), *llc_id == num_llcs - 1))
                    .collect();

                let _ = llc_sparklines
                    .iter()
                    .enumerate()
                    .for_each(|(i, llc_sparkline)| {
                        frame.render_widget(llc_sparkline, llcs_verticle[i + 1]);
                    });
            }
            ViewState::BarChart => {
                let llc_block = Block::default()
                    .title_top(
                        Line::from(format!(
                            "LLCs ({}) avg {} max {} min {}",
                            self.active_hw_event.event, stats.avg, stats.max, stats.min,
                        ))
                        .style(self.theme.title_style())
                        .centered(),
                    )
                    .title_top(
                        Line::from(format!("{}ms", self.tick_rate_ms))
                            .style(self.theme.text_important_color())
                            .right_aligned(),
                    )
                    .style(self.theme.border_style())
                    .borders(Borders::TOP | Borders::BOTTOM | Borders::LEFT | Borders::RIGHT)
                    .border_type(BorderType::Rounded);

                let llc_bars: Vec<Bar> = self.llc_bars(self.active_hw_event.event.clone());

                let barchart = BarChart::default()
                    .data(BarGroup::default().bars(&llc_bars))
                    .block(llc_block)
                    .max(stats.max)
                    .direction(Direction::Horizontal)
                    .bar_style(self.theme.sparkline_style())
                    .bar_gap(0)
                    .bar_width(1);

                frame.render_widget(barchart, right);
            }
        }

        self.render_scheduler("dsq_lat_us".to_string(), frame, top_left, true)?;
        self.render_dsq_vtime(frame, bottom_left, false)?;

        Ok(())
    }

    /// Renders the node application state.
    fn render_node(&mut self, frame: &mut Frame) -> Result<()> {
        let [left, right] = Layout::horizontal([Constraint::Fill(1); 2]).areas(frame.area());
        let [top_left, bottom_left] = Layout::vertical([Constraint::Fill(1); 2]).areas(left);
        let num_nodes = self.topo.nodes.len();

        let node_iter = self
            .node_data
            .values()
            .map(|node_data| node_data.event_data_immut(self.active_hw_event.event.clone()))
            .flatten()
            .collect::<Vec<u64>>();
        let stats = VecStats::new(&node_iter, true, true, true, None);

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
                    .map(|node_id| self.node_sparkline(node_id.clone(), *node_id == num_nodes - 1))
                    .collect();

                let node_block = Block::bordered()
                    .title_top(
                        Line::from(format!(
                            "Node ({}) avg {} max {} min {}",
                            self.active_hw_event.event, stats.avg, stats.max, stats.min
                        ))
                        .style(self.theme.title_style())
                        .centered(),
                    )
                    .title_top(
                        Line::from(format!("{}ms", self.tick_rate_ms))
                            .style(self.theme.text_important_color())
                            .right_aligned(),
                    )
                    .border_type(BorderType::Rounded)
                    .style(self.theme.border_style());

                frame.render_widget(node_block, nodes_verticle[0]);
                let _ = node_sparklines
                    .iter()
                    .enumerate()
                    .for_each(|(i, node_sparkline)| {
                        frame.render_widget(node_sparkline, nodes_verticle[i + 1]);
                    });
            }
            ViewState::BarChart => {
                let node_block = Block::default()
                    .title_top(
                        Line::from(format!(
                            "NUMA Nodes ({}) avg {} max {} min {}",
                            self.active_hw_event.event, stats.avg, stats.max, stats.min,
                        ))
                        .style(self.theme.title_style())
                        .centered(),
                    )
                    .title_top(
                        Line::from(format!("{}ms", self.tick_rate_ms))
                            .style(self.theme.text_important_color())
                            .right_aligned(),
                    )
                    .style(self.theme.border_style())
                    .borders(Borders::TOP | Borders::BOTTOM | Borders::LEFT | Borders::RIGHT)
                    .border_type(BorderType::Rounded);

                let node_bars: Vec<Bar> = self.node_bars(self.active_hw_event.event.clone());

                let barchart = BarChart::default()
                    .data(BarGroup::default().bars(&node_bars))
                    .block(node_block)
                    .max(stats.max)
                    .direction(Direction::Horizontal)
                    .bar_style(self.theme.sparkline_style())
                    .bar_gap(0)
                    .bar_width(1);

                frame.render_widget(barchart, right);
            }
        }

        self.render_scheduler("dsq_lat_us".to_string(), frame, top_left, true)?;
        self.render_dsq_vtime(frame, bottom_left, false)?;
        Ok(())
    }

    /// Creates a sparkline for a dsq.
    fn dsq_sparkline(&self, event: String, dsq_id: u64, borders: Borders) -> Sparkline {
        let data = if self.dsq_data.contains_key(&dsq_id) {
            let dsq_data = self.dsq_data.get(&dsq_id).unwrap();
            dsq_data.event_data_immut(event.clone())
        } else {
            Vec::new()
        };
        // XXX: this should be max across all CPUs
        let stats = VecStats::new(&data, true, true, true, None);
        Sparkline::default()
            .data(&data)
            .max(stats.max)
            .direction(RenderDirection::RightToLeft)
            .style(self.theme.sparkline_style())
            .block(
                Block::new()
                    .borders(borders)
                    .border_type(BorderType::Rounded)
                    .style(self.theme.border_style())
                    .title_alignment(Alignment::Left)
                    .title(format!(
                        "dsq {:#X} avg {} max {} min {}",
                        dsq_id, stats.avg, stats.max, stats.min
                    )),
            )
    }

    /// Generates dsq sparklines.
    fn dsq_sparklines(&self, event: String) -> Vec<Sparkline> {
        self.dsq_data
            .iter()
            .filter(|(_dsq_id, dsq_data)| dsq_data.data.contains_key(&event.clone()))
            .enumerate()
            .map(|(j, (dsq_id, _data))| {
                self.dsq_sparkline(
                    event.clone(),
                    dsq_id.clone(),
                    if j < 1 {
                        Borders::LEFT | Borders::RIGHT | Borders::BOTTOM
                    } else {
                        Borders::TOP | Borders::LEFT | Borders::RIGHT | Borders::BOTTOM
                    },
                )
            })
            .collect()
    }

    /// Generates a DSQ bar chart.
    fn dsq_bar(&self, dsq: u64, value: u64, avg: u64, max: u64, min: u64) -> Bar {
        Bar::default()
            .value(value)
            .label(Line::from(format!(
                "{:#X} avg {} max {} min {}",
                dsq, avg, max, min
            )))
            .text_value(format!("{}", value))
    }

    /// Generates DSQ bar charts.
    fn dsq_bars(&self, event: String) -> Vec<Bar> {
        self.dsq_data
            .iter()
            .filter(|(_dsq_id, dsq_data)| dsq_data.data.contains_key(&event.clone()))
            .map(|(dsq_id, dsq_data)| {
                let values = dsq_data.event_data_immut(event.clone());
                let value = values.last().copied().unwrap_or(0_u64);
                let stats = VecStats::new(&values, true, true, true, None);
                self.dsq_bar(*dsq_id, value, stats.avg, stats.max, stats.min)
            })
            .collect()
    }

    /// Generates a LLC bar chart.
    fn event_bar(&self, id: usize, value: u64, avg: u64, max: u64, min: u64) -> Bar {
        Bar::default()
            .value(value)
            .label(Line::from(format!(
                "{} avg {} max {} min {}",
                id, avg, max, min
            )))
            .text_value(format!("{}", value))
    }

    /// Generates LLC bar charts.
    fn llc_bars(&self, event: String) -> Vec<Bar> {
        self.llc_data
            .iter()
            .filter(|(_llc_id, llc_data)| llc_data.data.data.contains_key(&event.clone()))
            .map(|(llc_id, llc_data)| {
                let values = llc_data.event_data_immut(event.clone());
                let value = values.last().copied().unwrap_or(0_u64);
                let stats = VecStats::new(&values, true, true, true, None);
                self.event_bar(*llc_id, value, stats.avg, stats.max, stats.min)
            })
            .collect()
    }

    /// Generates Node bar charts.
    fn node_bars(&self, event: String) -> Vec<Bar> {
        self.node_data
            .iter()
            .filter(|(_node_id, node_data)| node_data.data.data.contains_key(&event.clone()))
            .map(|(node_id, node_data)| {
                let values = node_data.event_data_immut(event.clone());
                let value = values.last().copied().unwrap_or(0_u64);
                let stats = VecStats::new(&values, true, true, true, None);
                self.event_bar(*node_id, value, stats.avg, stats.max, stats.min)
            })
            .collect()
    }

    /// Renders the scheduler state as sparklines.
    fn render_scheduler_sparklines(
        &mut self,
        event: String,
        frame: &mut Frame,
        area: Rect,
        render_sample_rate: bool,
    ) -> Result<()> {
        let num_dsqs = self.dsq_data.len();
        let mut dsq_constraints = Vec::new();
        if num_dsqs == 0 {
            let block = Block::default()
                .title_top(
                    Line::from(self.scheduler.clone())
                        .style(self.theme.title_style())
                        .centered(),
                )
                .style(self.theme.border_style())
                .borders(Borders::TOP | Borders::BOTTOM | Borders::LEFT | Borders::RIGHT)
                .border_type(BorderType::Rounded);
            frame.render_widget(block, area);
            return Ok(());
        } else {
            dsq_constraints.push(Constraint::Percentage(2));
        }
        for _ in 0..num_dsqs {
            dsq_constraints.push(Constraint::Ratio(1, num_dsqs as u32));
        }
        let dsqs_verticle = Layout::vertical(dsq_constraints).split(area);

        let dsq_global_iter = self
            .dsq_data
            .values()
            .map(|dsq_data| dsq_data.event_data_immut(event.clone()))
            .flatten()
            .collect::<Vec<u64>>();
        let stats = VecStats::new(&dsq_global_iter, true, true, true, None);
        let sample_rate = self.skel.maps.data_data.sample_rate;

        let block = Block::default()
            .title_top(
                Line::from(format!(
                    "{} {} avg {} max {} min {}",
                    self.scheduler, event, stats.avg, stats.max, stats.min,
                ))
                .style(self.theme.title_style())
                .centered(),
            )
            .title_top(if render_sample_rate {
                Line::from(format!("sample rate {}", sample_rate))
                    .style(self.theme.text_important_color())
                    .right_aligned()
            } else {
                Line::from("")
            })
            .style(self.theme.border_style())
            .borders(Borders::TOP | Borders::BOTTOM | Borders::LEFT | Borders::RIGHT)
            .border_type(BorderType::Rounded);
        frame.render_widget(block, dsqs_verticle[0]);

        let _ = self
            .dsq_sparklines(event.clone())
            .iter()
            .enumerate()
            .for_each(|(j, dsq_sparkline)| {
                frame.render_widget(dsq_sparkline, dsqs_verticle[j + 1]);
            });

        Ok(())
    }

    /// Returns the dsq vtime chart.
    fn render_dsq_vtime_sparklines(
        &self,
        event: String,
        frame: &mut Frame,
        area: Rect,
        render_sample_rate: bool,
    ) -> Result<()> {
        let num_dsqs = self
            .dsq_data
            .iter()
            .filter(|(_dsq_id, dsq_data)| dsq_data.data.contains_key(&event.clone()))
            .count();
        if num_dsqs == 0 {
            let block = Block::default()
                .title_top(
                    Line::from(self.scheduler.clone())
                        .style(self.theme.title_style())
                        .centered(),
                )
                .style(self.theme.border_style())
                .borders(Borders::TOP | Borders::BOTTOM | Borders::LEFT | Borders::RIGHT)
                .border_type(BorderType::Rounded);
            frame.render_widget(block, area);
            return Ok(());
        }
        let mut dsq_constraints = Vec::with_capacity(num_dsqs + 1);
        dsq_constraints.push(Constraint::Percentage(2));

        for _ in 0..num_dsqs {
            dsq_constraints.push(Constraint::Ratio(1, num_dsqs as u32));
        }
        let dsqs_verticle = Layout::vertical(dsq_constraints).split(area);

        let dsq_global_iter = self
            .dsq_data
            .values()
            .map(|dsq_data| dsq_data.event_data_immut(event.clone()))
            .flatten()
            .collect::<Vec<u64>>();
        let stats = VecStats::new(&dsq_global_iter, true, true, true, None);
        let sample_rate = self.skel.maps.data_data.sample_rate;

        let block = Block::default()
            .title_top(
                Line::from(format!(
                    "{} DSQ vtime delta avg {} max {} min {}",
                    self.scheduler, stats.avg, stats.max, stats.min,
                ))
                .style(self.theme.title_style())
                .centered(),
            )
            .title_top(if render_sample_rate {
                Line::from(format!("sample rate {}", sample_rate))
                    .style(self.theme.text_important_color())
                    .right_aligned()
            } else {
                Line::from("")
            })
            .style(self.theme.border_style())
            .borders(Borders::TOP | Borders::BOTTOM | Borders::LEFT | Borders::RIGHT)
            .border_type(BorderType::Rounded);
        frame.render_widget(block, dsqs_verticle[0]);

        let _ = self
            .dsq_sparklines(event.clone())
            .iter()
            .enumerate()
            .for_each(|(j, dsq_sparkline)| {
                frame.render_widget(dsq_sparkline, dsqs_verticle[j + 1]);
            });

        Ok(())
    }

    /// Returns the dsq vtime chart.
    fn render_dsq_vtime_barchart(
        &self,
        event: String,
        frame: &mut Frame,
        area: Rect,
        render_sample_rate: bool,
    ) -> Result<()> {
        let num_dsqs = self
            .dsq_data
            .iter()
            .filter(|(_dsq_id, dsq_data)| dsq_data.data.contains_key(&event.clone()))
            .count();
        if num_dsqs == 0 {
            let block = Block::default()
                .title_top(
                    Line::from(self.scheduler.clone())
                        .style(self.theme.title_style())
                        .centered(),
                )
                .style(self.theme.border_style())
                .borders(Borders::TOP | Borders::BOTTOM | Borders::LEFT | Borders::RIGHT)
                .border_type(BorderType::Rounded);
            frame.render_widget(block, area);
            return Ok(());
        }

        let dsq_constraints = vec![Constraint::Percentage(1), Constraint::Percentage(99)];
        let dsqs_verticle = Layout::vertical(dsq_constraints).split(area);
        let sample_rate = self.skel.maps.data_data.sample_rate;

        let vtime_global_iter: Vec<u64> = self
            .dsq_data
            .iter()
            .filter(|(_dsq_id, event_data)| event_data.data.contains_key(&event.clone()))
            .map(|(_dsq_id, event_data)| event_data.event_data_immut(event.clone()))
            .flatten()
            .collect::<Vec<u64>>();

        let stats = VecStats::new(&vtime_global_iter, true, true, true, None);

        let bar_block = Block::default()
            .title_top(
                Line::from(format!(
                    "{} {} avg {} max {} min {}",
                    self.scheduler, event, stats.avg, stats.max, stats.min,
                ))
                .style(self.theme.title_style())
                .centered(),
            )
            .title_top(if render_sample_rate {
                Line::from(format!("sample rate {}", sample_rate))
                    .style(self.theme.text_important_color())
                    .right_aligned()
            } else {
                Line::from("")
            })
            .style(self.theme.border_style())
            .borders(Borders::TOP | Borders::BOTTOM | Borders::LEFT | Borders::RIGHT)
            .border_type(BorderType::Rounded);

        let dsq_bars: Vec<Bar> = self.dsq_bars(event.clone());

        let barchart = BarChart::default()
            .data(BarGroup::default().bars(&dsq_bars))
            .block(bar_block)
            .max(stats.max)
            .direction(Direction::Horizontal)
            .bar_style(self.theme.sparkline_style())
            .bar_gap(0)
            .bar_width(1);

        frame.render_widget(barchart, dsqs_verticle[1]);
        Ok(())
    }

    /// Renders the scheduler state as barcharts.
    fn render_scheduler_barchart(
        &mut self,
        event: String,
        frame: &mut Frame,
        area: Rect,
        render_sample_rate: bool,
    ) -> Result<()> {
        let num_dsqs = self.dsq_data.len();
        if num_dsqs == 0 {
            let block = Block::default()
                .title_top(
                    Line::from(self.scheduler.clone())
                        .style(self.theme.title_style())
                        .centered(),
                )
                .style(self.theme.border_style())
                .borders(Borders::TOP | Borders::BOTTOM | Borders::LEFT | Borders::RIGHT)
                .border_type(BorderType::Rounded);
            frame.render_widget(block, area);
            return Ok(());
        }
        let dsq_constraints = vec![Constraint::Percentage(1), Constraint::Percentage(99)];
        let dsqs_verticle = Layout::vertical(dsq_constraints).split(area);
        let sample_rate = self.skel.maps.data_data.sample_rate;

        let dsq_global_iter = self
            .dsq_data
            .values()
            .map(|dsq_data| dsq_data.event_data_immut(event.clone()))
            .flatten()
            .collect::<Vec<u64>>();
        let stats = VecStats::new(&dsq_global_iter, true, true, true, None);

        let bar_block = Block::default()
            .title_top(
                Line::from(format!(
                    "{} {} avg {} max {} min {}",
                    self.scheduler, event, stats.avg, stats.max, stats.min,
                ))
                .style(self.theme.title_style())
                .centered(),
            )
            .title_top(if render_sample_rate {
                Line::from(format!("sample rate {}", sample_rate))
                    .style(self.theme.text_important_color())
                    .right_aligned()
            } else {
                Line::from("")
            })
            .style(self.theme.border_style())
            .borders(Borders::TOP | Borders::BOTTOM | Borders::LEFT | Borders::RIGHT)
            .border_type(BorderType::Rounded);

        let dsq_bars: Vec<Bar> = self.dsq_bars(event.clone());

        let barchart = BarChart::default()
            .data(BarGroup::default().bars(&dsq_bars))
            .block(bar_block)
            .max(stats.max)
            .direction(Direction::Horizontal)
            .bar_style(self.theme.sparkline_style())
            .bar_gap(0)
            .bar_width(1);

        frame.render_widget(barchart, dsqs_verticle[1]);
        Ok(())
    }

    /// Renders the scheduler application state.
    fn render_scheduler(
        &mut self,
        event: String,
        frame: &mut Frame,
        area: Rect,
        render_sample_rate: bool,
    ) -> Result<()> {
        match self.view_state {
            ViewState::Sparkline => {
                self.render_scheduler_sparklines(event, frame, area, render_sample_rate)
            }
            ViewState::BarChart => {
                self.render_scheduler_barchart(event, frame, area, render_sample_rate)
            }
        }
    }

    /// Renders the scheduler application state.
    fn render_dsq_vtime(
        &mut self,
        frame: &mut Frame,
        area: Rect,
        render_sample_rate: bool,
    ) -> Result<()> {
        match self.view_state {
            ViewState::Sparkline => self.render_dsq_vtime_sparklines(
                "dsq_vtime_delta".to_string(),
                frame,
                area,
                render_sample_rate,
            ),
            ViewState::BarChart => self.render_dsq_vtime_barchart(
                "dsq_vtime_delta".to_string(),
                frame,
                area,
                render_sample_rate,
            ),
        }
    }

    /// Renders the event state.
    fn render_event(&mut self, frame: &mut Frame, area: Rect) -> Result<()> {
        match self.view_state {
            ViewState::Sparkline => {
                let num_nodes = self.topo.nodes.len();
                let constraints =
                    vec![Constraint::Ratio(1, num_nodes.try_into().unwrap()); num_nodes];
                let node_areas = Layout::vertical(constraints).split(area);

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
                        .map(|cpu_data| {
                            cpu_data.event_data_immut(self.active_hw_event.event.clone())
                        })
                        .flatten()
                        .collect::<Vec<u64>>();
                    let stats = VecStats::new(&node_iter, true, true, true, None);

                    let node_block = Block::bordered()
                        .title_top(
                            Line::from(format!(
                                "Node{} ({}) avg {} max {} min {}",
                                node.id,
                                self.active_hw_event.event,
                                stats.avg,
                                stats.max,
                                stats.min
                            ))
                            .style(self.theme.title_style())
                            .centered(),
                        )
                        .title_top(if i == 0 {
                            Line::from(format!("{}ms", self.tick_rate_ms))
                                .style(self.theme.text_important_color())
                                .right_aligned()
                        } else {
                            Line::from("")
                        })
                        .title_top(
                            Line::from(format!(
                                "{}",
                                if self.collect_uncore_freq {
                                    "uncore ".to_string()
                                        + &format_hz(
                                            self.node_data
                                                .get(&node.id)
                                                .unwrap()
                                                .event_data_immut("uncore_freq".to_string())
                                                .last()
                                                .copied()
                                                .unwrap_or(0_u64),
                                        )
                                } else {
                                    "".to_string()
                                }
                            ))
                            .style(self.theme.text_important_color())
                            .left_aligned(),
                        )
                        .border_type(BorderType::Rounded)
                        .style(self.theme.border_style());

                    frame.render_widget(node_block, top);

                    let cpu_sparklines: Vec<Sparkline> = self
                        .topo
                        .all_cpus
                        .values()
                        .filter(|cpu| cpu.node_id == node.id)
                        .enumerate()
                        .map(|(j, cpu)| {
                            self.cpu_sparkline(
                                cpu.id.clone(),
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

                    let _ = cpu_sparklines
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
                    let node_constraints =
                        vec![Constraint::Percentage(2), Constraint::Percentage(98)];
                    let [top, bottom] = Layout::vertical(node_constraints).areas(node_areas[i]);

                    let node_cpus = node.all_cpus.len();
                    let col_scale = if node_cpus <= 128 { 2 } else { 4 };

                    let cpus_constraints =
                        vec![Constraint::Ratio(1, col_scale); col_scale.try_into().unwrap()];
                    let cpus_areas = Layout::horizontal(cpus_constraints).split(bottom);

                    let node_iter = self
                        .cpu_data
                        .values()
                        .filter(|cpu_data| cpu_data.node == node.id)
                        .map(|cpu_data| {
                            cpu_data.event_data_immut(self.active_hw_event.event.clone())
                        })
                        .flatten()
                        .collect::<Vec<u64>>();
                    let stats = VecStats::new(&node_iter, true, true, true, None);

                    let node_block = Block::bordered()
                        .title_top(
                            Line::from(format!(
                                "Node{} ({}) avg {} max {} min {}",
                                node.id,
                                self.active_hw_event.event,
                                stats.avg,
                                stats.max,
                                stats.min
                            ))
                            .style(self.theme.title_style())
                            .centered(),
                        )
                        .title_top(if i == 0 {
                            Line::from(format!("{}ms", self.tick_rate_ms))
                                .style(self.theme.text_important_color())
                                .right_aligned()
                        } else {
                            Line::from("")
                        })
                        .title_top(
                            Line::from(format!(
                                "{}",
                                if self.collect_uncore_freq {
                                    "uncore ".to_string()
                                        + &format_hz(
                                            self.node_data
                                                .get(&node.id)
                                                .unwrap()
                                                .event_data_immut("uncore_freq".to_string())
                                                .last()
                                                .copied()
                                                .unwrap_or(0_u64),
                                        )
                                } else {
                                    "".to_string()
                                }
                            ))
                            .style(self.theme.text_important_color())
                            .left_aligned(),
                        )
                        .border_type(BorderType::Rounded)
                        .style(self.theme.border_style());

                    let mut bar_col_data: Vec<Vec<Bar>> = vec![Vec::new(); 4];
                    let _: Vec<_> = node
                        .all_cpus
                        .keys()
                        .enumerate()
                        .map(|(j, cpu)| {
                            let cpu_bar = self.cpu_bar(*cpu, self.active_hw_event.event.clone());
                            bar_col_data[j % col_scale as usize].push(cpu_bar);
                        })
                        .collect();
                    frame.render_widget(node_block, top);
                    for (j, col_data) in bar_col_data.iter().enumerate() {
                        let cpu_block = Block::new()
                            .borders(
                                if j == col_scale as usize - 1
                                    || j % col_scale as usize == col_scale as usize - 1
                                {
                                    Borders::RIGHT | Borders::BOTTOM
                                } else if j == 0 || j % col_scale as usize == 0 {
                                    Borders::LEFT | Borders::BOTTOM
                                } else {
                                    Borders::BOTTOM
                                },
                            )
                            .border_type(BorderType::Rounded)
                            .style(self.theme.border_style());
                        let bar_chart = BarChart::default()
                            .block(cpu_block)
                            .data(BarGroup::default().bars(&col_data))
                            .max(stats.max)
                            .direction(Direction::Horizontal)
                            .bar_style(self.theme.sparkline_style())
                            .bar_gap(0)
                            .bar_width(1);
                        frame.render_widget(bar_chart, cpus_areas[j % col_scale as usize]);
                    }
                }
            }
        }
        Ok(())
    }

    /// Renders the default application state.
    fn render_default(&mut self, frame: &mut Frame) -> Result<()> {
        let [left, right] = Layout::horizontal([Constraint::Fill(1); 2]).areas(frame.area());
        let [top_left, bottom_left] = Layout::vertical([Constraint::Fill(1); 2]).areas(left);

        self.render_event(frame, right)?;
        self.render_scheduler("dsq_lat_us".to_string(), frame, top_left, true)?;
        self.render_dsq_vtime(frame, bottom_left, false)?;
        Ok(())
    }

    /// Renders the help TUI.
    fn render_help(&mut self, frame: &mut Frame) -> Result<()> {
        let area = frame.area();
        let theme = self.theme();
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
                    self.keymap.action_keys_string(Action::SetState {
                        state: AppState::Help,
                    })
                ),
                Style::default(),
            )),
            Line::from(Span::styled(
                format!(
                    "{}: change theme ({})",
                    self.keymap.action_keys_string(Action::ChangeTheme),
                    serde_json::to_string_pretty(&theme)?
                ),
                Style::default(),
            )),
            Line::from(Span::styled(
                format!(
                    "{}: decrease tick rate ({}ms)",
                    self.keymap.action_keys_string(Action::DecTickRate),
                    self.tick_rate_ms
                ),
                Style::default(),
            )),
            Line::from(Span::styled(
                format!(
                    "{}: increase tick rate ({}ms)",
                    self.keymap.action_keys_string(Action::IncTickRate),
                    self.tick_rate_ms
                ),
                Style::default(),
            )),
            Line::from(Span::styled(
                format!(
                    "{}: decrease bpf sample rate ({})",
                    self.keymap.action_keys_string(Action::DecBpfSampleRate),
                    self.skel.maps.data_data.sample_rate
                ),
                Style::default(),
            )),
            Line::from(Span::styled(
                format!(
                    "{}: increase bpf sample rate ({})",
                    self.keymap.action_keys_string(Action::IncBpfSampleRate),
                    self.skel.maps.data_data.sample_rate
                ),
                Style::default(),
            )),
            Line::from(Span::styled(
                format!(
                    "{}: Enable CPU frequency ({})",
                    self.keymap.action_keys_string(Action::ToggleCpuFreq),
                    self.collect_cpu_freq
                ),
                Style::default(),
            )),
            Line::from(Span::styled(
                format!(
                    "{}: Enable uncore frequency ({})",
                    self.keymap.action_keys_string(Action::ToggleUncoreFreq),
                    self.collect_uncore_freq
                ),
                Style::default(),
            )),
            Line::from(Span::styled(
                format!(
                    "{}: show CPU event menu ({})",
                    self.keymap.action_keys_string(Action::SetState {
                        state: AppState::Event
                    }),
                    self.active_hw_event.event
                ),
                Style::default(),
            )),
            Line::from(Span::styled(
                format!(
                    "{}: clear active perf event",
                    self.keymap.action_keys_string(Action::ClearEvent),
                ),
                Style::default(),
            )),
            Line::from(Span::styled(
                format!(
                    "{}: next perf event",
                    self.keymap.action_keys_string(Action::NextEvent),
                ),
                Style::default(),
            )),
            Line::from(Span::styled(
                format!(
                    "{}: previous perf event",
                    self.keymap.action_keys_string(Action::PrevEvent)
                ),
                Style::default(),
            )),
            Line::from(Span::styled(
                format!("{}: quit", self.keymap.action_keys_string(Action::Quit),),
                Style::default(),
            )),
            Line::from(Span::styled(
                format!(
                    "{}: display LLC view",
                    self.keymap.action_keys_string(Action::SetState {
                        state: AppState::Llc,
                    })
                ),
                Style::default(),
            )),
            Line::from(Span::styled(
                format!(
                    "{}: display NUMA Node view",
                    self.keymap.action_keys_string(Action::SetState {
                        state: AppState::Node,
                    })
                ),
                Style::default(),
            )),
            Line::from(Span::styled(
                format!(
                    "{}: display scheduler view",
                    self.keymap.action_keys_string(Action::SetState {
                        state: AppState::Scheduler,
                    })
                ),
                Style::default(),
            )),
            Line::from(Span::styled(
                format!(
                    "{}: change view state ({})",
                    self.keymap.action_keys_string(Action::NextViewState),
                    self.view_state
                ),
                Style::default(),
            )),
        ];
        frame.render_widget(
            Paragraph::new(text)
                .block(
                    Block::default()
                        .title_top(Line::from(APP).style(self.theme.title_style()).centered())
                        .borders(Borders::ALL)
                        .border_type(BorderType::Rounded),
                )
                .style(self.theme.border_style())
                .alignment(Alignment::Left),
            area,
        );
        Ok(())
    }

    /// Renders the event list TUI.
    fn render_event_list(&mut self, frame: &mut Frame) -> Result<()> {
        let area = frame.area();
        let default_style = Style::default().fg(self.theme.text_color());
        let chunks = Layout::vertical([Constraint::Min(1), Constraint::Percentage(99)]).split(area);

        let events: Vec<Line> = self
            .available_perf_events
            .iter()
            .flat_map(|(subsystem, events)| {
                events
                    .iter()
                    .map(|event| Line::from(format!("{}:{}", subsystem.clone(), event)))
            })
            .collect();

        let title = Block::new()
            .style(default_style)
            .title_alignment(Alignment::Center)
            .title("Use ▲ ▼ to scroll ".bold());
        frame.render_widget(title, chunks[0]);

        let paragraph = Paragraph::new(events.clone())
            .style(default_style)
            .scroll((self.event_scroll, 0));
        frame.render_widget(paragraph, chunks[1]);

        frame.render_stateful_widget(
            Scrollbar::new(ScrollbarOrientation::VerticalRight)
                .begin_symbol(Some("↑"))
                .end_symbol(Some("↓")),
            chunks[1],
            &mut self.event_scroll_state,
        );

        Ok(())
    }

    /// Renders the application to the frame.
    pub fn render(&mut self, frame: &mut Frame) -> Result<()> {
        match self.state {
            AppState::Help => self.render_help(frame),
            AppState::Event => self.render_event_list(frame),
            AppState::Node => self.render_node(frame),
            AppState::Llc => self.render_llc(frame),
            AppState::Scheduler => {
                let [top, center, bottom] =
                    Layout::vertical([Constraint::Fill(1); 3]).areas(frame.area());
                self.render_scheduler("dsq_lat_us".to_string(), frame, top, true)?;
                self.render_scheduler("dsq_slice_consumed".to_string(), frame, center, false)?;
                self.render_scheduler("dsq_vtime_delta".to_string(), frame, bottom, false)
            }
            _ => self.render_default(frame),
        }
    }

    /// Updates app state when the down arrow or mapped key is pressed.
    fn on_down(&mut self) {
        match self.state {
            AppState::Event => {
                self.event_scroll += 1;
            }
            _ => {}
        }
    }

    /// Updates app state when the up arrow or mapped key is pressed.
    fn on_up(&mut self) {
        match self.state {
            AppState::Event => {
                if self.event_scroll > 1 {
                    self.event_scroll -= 1;
                }
            }
            _ => {}
        }
    }

    /// Updates the app when a scheduler is unloaded.
    fn on_scheduler_unload(&mut self) {
        self.scheduler = "none".to_string();
        self.dsq_data.clear();
        let _ = self
            .cpu_data
            .values_mut()
            .map(|cpu_data| cpu_data.data.clear_event("perf".to_string()));
    }

    /// Updates the app when a scheduler is loaded.
    fn on_scheduler_load(&mut self) -> Result<()> {
        self.dsq_data.clear();
        self.scheduler = read_file_string(SCHED_NAME_PATH)?;
        Ok(())
    }

    /// Updates the app when a CPUs performance is changed by the scheduler.
    fn on_cpu_perf(&mut self, cpu: u32, perf: u32) {
        // XXX fixme
        let cpu_data = self.cpu_data.entry(cpu as usize).or_insert(CpuData::new(
            cpu as usize,
            0,
            0,
            0,
            self.max_cpu_events,
        ));
        cpu_data.add_event_data("perf".to_string(), perf as u64);
    }

    /// Updates the app when a task is scheduled.
    fn on_sched_switch(
        &mut self,
        cpu: u32,
        next_dsq_id: u64,
        next_dsq_lat_us: u64,
        next_dsq_vtime: u64,
        _next_slice_ns: u64,
        prev_dsq_id: u64,
        prev_used_slice_ns: u64,
        _prev_slice_ns: u64,
    ) {
        if self.scheduler == "none" {
            return;
        }
        // XXX fixme
        let cpu_data = self.cpu_data.entry(cpu as usize).or_insert(CpuData::new(
            cpu as usize,
            0,
            0,
            0,
            self.max_cpu_events,
        ));
        cpu_data.add_event_data("dsq_lat_us".to_string(), next_dsq_lat_us);
        let next_dsq_data = self
            .dsq_data
            .entry(next_dsq_id)
            .or_insert(EventData::new(self.max_cpu_events * 2));
        next_dsq_data.add_event_data("dsq_lat_us".to_string(), next_dsq_lat_us);
        if next_dsq_vtime > 0 {
            // vtime is special because we want the delta
            let last = next_dsq_data
                .event_data_immut("dsq_vtime_delta".to_string())
                .last()
                .copied()
                .unwrap_or(0_u64);
            if next_dsq_vtime - last < DSQ_VTIME_CUTOFF {
                next_dsq_data.add_event_data(
                    "dsq_vtime_delta".to_string(),
                    if last > 0 { next_dsq_vtime - last } else { 0 },
                );
            }
        }

        let prev_dsq_data = self
            .dsq_data
            .entry(prev_dsq_id)
            .or_insert(EventData::new(self.max_cpu_events * 2));
        prev_dsq_data.add_event_data("dsq_slice_consumed".to_string(), prev_used_slice_ns);
    }

    /// Updates the bpf bpf sampling rate.
    pub fn update_bpf_sample_rate(&mut self, sample_rate: u32) {
        self.skel.maps.data_data.sample_rate = sample_rate;
    }

    /// Handles the action and updates application states.
    pub fn handle_action(&mut self, action: Action) -> Result<()> {
        match action {
            Action::Tick => {
                self.on_tick()?;
            }
            Action::Increment => {
                self.counter += 1;
            }
            Action::Decrement => {
                self.counter -= 1;
            }
            Action::Down => self.on_down(),
            Action::Up => self.on_up(),
            Action::SetState { state } => {
                if state == self.state {
                    self.set_state(self.prev_state.clone());
                } else {
                    self.set_state(state);
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
            Action::SchedCpuPerfSet { cpu, perf } => {
                self.on_cpu_perf(cpu, perf);
            }
            Action::SchedSwitch {
                cpu,
                next_dsq_id,
                next_dsq_lat_us,
                next_dsq_vtime,
                next_slice_ns,
                prev_dsq_id,
                prev_used_slice_ns,
                prev_slice_ns,
            } => {
                self.on_sched_switch(
                    cpu,
                    next_dsq_id,
                    next_dsq_lat_us,
                    next_dsq_vtime,
                    next_slice_ns,
                    prev_dsq_id,
                    prev_used_slice_ns,
                    prev_slice_ns,
                );
            }
            Action::ClearEvent => self.stop_perf_events(),
            Action::ChangeTheme => {
                self.set_theme(self.theme().next());
            }
            Action::TickRateChange { tick_rate_ms } => {
                self.tick_rate_ms = tick_rate_ms as usize;
            }
            Action::ToggleCpuFreq => self.collect_cpu_freq = !self.collect_cpu_freq,
            Action::ToggleUncoreFreq => self.collect_uncore_freq = !self.collect_uncore_freq,
            Action::IncBpfSampleRate => {
                let sample_rate = self.skel.maps.data_data.sample_rate;
                if sample_rate == 0 {
                    self.update_bpf_sample_rate(8_u32);
                } else {
                    self.update_bpf_sample_rate(sample_rate << 2);
                }
            }
            Action::DecBpfSampleRate => {
                let sample_rate = self.skel.maps.data_data.sample_rate;
                if sample_rate > 0 {
                    // prevent overly aggressive bpf sampling, but allow disabling sampling
                    let new_rate = sample_rate >> 2;
                    self.update_bpf_sample_rate(if new_rate >= 8 { new_rate } else { 0 });
                }
            }
            Action::Quit => {
                self.should_quit.store(true, Ordering::Relaxed);
            }
            _ => {}
        };
        Ok(())
    }
}
