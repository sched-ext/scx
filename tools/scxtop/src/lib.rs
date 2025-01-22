// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

mod app;
pub mod bpf_intf;
pub mod bpf_skel;
mod cpu_data;
mod event_data;
mod keymap;
mod llc_data;
mod node_data;
mod perf_event;
mod perfetto_trace;
pub mod protos;
mod stats;
mod theme;
mod tui;
mod util;

pub use app::App;
pub use bpf_skel::*;
pub use cpu_data::CpuData;
pub use event_data::EventData;
pub use keymap::Key;
pub use keymap::KeyMap;
pub use llc_data::LlcData;
pub use node_data::NodeData;
pub use perf_event::available_perf_events;
pub use perf_event::PerfEvent;
pub use perfetto_trace::PerfettoTraceManager;
pub use protos::*;
pub use stats::StatAggregation;
pub use stats::VecStats;
pub use theme::AppTheme;
pub use tui::Event;
pub use tui::Tui;
pub use util::format_hz;
pub use util::read_file_string;

pub use plain::Plain;
// Generate serialization types for handling events from the bpf ring buffer.
unsafe impl Plain for crate::bpf_skel::types::bpf_event {}

pub const STATS_SOCKET_PATH: &'static str = "/var/run/scx/root/stats";
pub const APP: &'static str = "scxtop";
pub const LICENSE: &'static str = "Copyright (c) Meta Platforms, Inc. and affiliates. 

This software may be used and distributed according to the terms of the 
GNU General Public License version 2.";
pub const SCHED_NAME_PATH: &'static str = "/sys/kernel/sched_ext/root/ops";

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum AppState {
    /// Application is in the default state.
    Default,
    /// Application is in the event state.
    Event,
    /// Application is in the help state.
    Help,
    /// Application is in the Llc state.
    Llc,
    /// Application is in the NUMA node state.
    Node,
    /// Application is in the scheduler state.
    Scheduler,
    /// Application is in the tracing  state.
    Tracing,
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ViewState {
    Sparkline,
    BarChart,
}

impl ViewState {
    /// Returns the next ViewState.
    pub fn next(&self) -> Self {
        match self {
            ViewState::Sparkline => ViewState::BarChart,
            ViewState::BarChart => ViewState::Sparkline,
        }
    }
}

impl std::fmt::Display for ViewState {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            ViewState::Sparkline => write!(f, "sparkline"),
            ViewState::BarChart => write!(f, "barchart"),
        }
    }
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Action {
    Tick,
    Increment,
    Decrement,
    Quit,
    Help,
    Event,
    ClearEvent,
    NextEvent,
    PrevEvent,
    ChangeTheme,
    Up,
    Down,
    PageUp,
    PageDown,
    Enter,
    Render,
    SchedReg,
    SchedUnreg,
    SchedCpuPerfSet {
        cpu: u32,
        perf: u32,
    },
    SchedStats {
        raw: String,
    },
    SchedSwitch {
        ts: u64,
        cpu: u32,
        preempt: bool,
        next_dsq_id: u64,
        next_dsq_lat_us: u64,
        next_dsq_nr_queued: u32,
        next_dsq_vtime: u64,
        next_slice_ns: u64,
        next_pid: u32,
        next_tgid: u32,
        next_prio: i32,
        next_comm: String,
        prev_dsq_id: u64,
        prev_used_slice_ns: u64,
        prev_slice_ns: u64,
        prev_pid: u32,
        prev_tgid: u32,
        prev_prio: i32,
        prev_comm: String,
        prev_state: u64,
    },
    SchedWakeup {
        ts: u64,
        cpu: u32,
        pid: u32,
        prio: i32,
        comm: String,
    },
    SchedWakeupNew {
        ts: u64,
        cpu: u32,
        pid: u32,
        prio: i32,
        comm: String,
    },
    SetState {
        state: AppState,
    },
    NextViewState,
    RecordTrace,
    ToggleCpuFreq,
    ToggleUncoreFreq,
    TickRateChange {
        tick_rate_ms: u64,
    },
    IncTickRate,
    DecTickRate,
    IncBpfSampleRate,
    DecBpfSampleRate,
    None,
}
