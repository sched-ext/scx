// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

mod app;
pub mod bpf_intf;
pub mod bpf_skel;
mod bpf_stats;
pub mod cli;
pub mod config;
mod cpu_data;
pub mod edm;
mod event_data;
mod keymap;
mod llc_data;
mod node_data;
mod perf_event;
mod perfetto_trace;
pub mod protos;
mod stats;
mod theme;
pub mod tracer;
mod tui;
mod util;

pub use crate::bpf_skel::types::bpf_event;
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

use smartstring::alias::String as SsoString;

pub const APP: &str = "scxtop";
pub const TRACE_FILE_PREFIX: &str = "scxtop_trace";
pub const STATS_SOCKET_PATH: &str = "/var/run/scx/root/stats";
pub const LICENSE: &str = "Copyright (c) Meta Platforms, Inc. and affiliates.

This software may be used and distributed according to the terms of the 
GNU General Public License version 2.";
pub const SCHED_NAME_PATH: &str = "/sys/kernel/sched_ext/root/ops";

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
pub struct SchedCpuPerfSetAction {
    pub cpu: u32,
    pub perf: u32,
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SchedSwitchAction {
    pub ts: u64,
    pub cpu: u32,
    pub preempt: bool,
    pub next_dsq_id: u64,
    pub next_dsq_lat_us: u64,
    pub next_dsq_nr_queued: u32,
    pub next_dsq_vtime: u64,
    pub next_slice_ns: u64,
    pub next_pid: u32,
    pub next_tgid: u32,
    pub next_prio: i32,
    pub next_comm: SsoString,
    pub prev_dsq_id: u64,
    pub prev_used_slice_ns: u64,
    pub prev_slice_ns: u64,
    pub prev_pid: u32,
    pub prev_tgid: u32,
    pub prev_prio: i32,
    pub prev_comm: SsoString,
    pub prev_state: u64,
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SchedWakeActionCtx {
    pub ts: u64,
    pub cpu: u32,
    pub pid: u32,
    pub prio: i32,
    pub comm: SsoString,
}

pub type SchedWakeupNewAction = SchedWakeActionCtx;
pub type SchedWakingAction = SchedWakeActionCtx;
pub type SchedWakeupAction = SchedWakeActionCtx;

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SoftIRQAction {
    pub cpu: u32,
    pub pid: u32,
    pub entry_ts: u64,
    pub exit_ts: u64,
    pub softirq_nr: usize,
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct TraceStartedAction {
    pub start_immediately: bool,
    pub ts: u64,
    pub stop_scheduled: bool,
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct TraceStoppedAction {
    pub ts: u64,
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct IPIAction {
    pub ts: u64,
    pub cpu: u32,
    pub target_cpu: u32,
    pub pid: u32,
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct GpuMemAction {
    pub ts: u64,
    pub size: u64,
    pub cpu: u32,
    pub gpu: u32,
    pub pid: u32,
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CpuhpAction {
    pub ts: u64,
    pub cpu: u32,
    pub target: i32,
    pub state: i32,
    pub pid: u32,
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Action {
    ChangeTheme,
    ClearEvent,
    Cpuhp(CpuhpAction),
    DecBpfSampleRate,
    DecTickRate,
    Down,
    Enter,
    Event,
    GpuMem(GpuMemAction),
    Help,
    IncBpfSampleRate,
    IncTickRate,
    IPI(IPIAction),
    NextEvent,
    NextViewState,
    PageDown,
    PageUp,
    PrevEvent,
    Quit,
    RequestTrace,
    TraceStarted(TraceStartedAction),
    TraceStopped(TraceStoppedAction),
    ReloadStatsClient,
    SaveConfig,
    SchedCpuPerfSet(SchedCpuPerfSetAction),
    SchedReg,
    SchedStats(String),
    SchedSwitch(SchedSwitchAction),
    SchedUnreg,
    SchedWakeupNew(SchedWakeupNewAction),
    SchedWakeup(SchedWakeupAction),
    SchedWaking(SchedWakingAction),
    SetState(AppState),
    SoftIRQ(SoftIRQAction),
    Tick,
    TickRateChange(std::time::Duration),
    ToggleCpuFreq,
    ToggleLocalization,
    ToggleUncoreFreq,
    Up,
    None,
}

impl TryFrom<bpf_event> for Action {
    type Error = ();

    fn try_from(event: bpf_event) -> Result<Action, Self::Error> {
        Self::try_from(&event)
    }
}

impl TryFrom<&bpf_event> for Action {
    type Error = ();

    fn try_from(event: &bpf_event) -> Result<Action, Self::Error> {
        let ty = event.r#type as u32;
        match ty {
            #[allow(non_upper_case_globals)]
            bpf_intf::event_type_SCHED_REG => Ok(Action::SchedReg),
            #[allow(non_upper_case_globals)]
            bpf_intf::event_type_SCHED_UNREG => Ok(Action::SchedUnreg),
            #[allow(non_upper_case_globals)]
            bpf_intf::event_type_CPU_PERF_SET => {
                Ok(Action::SchedCpuPerfSet(SchedCpuPerfSetAction {
                    cpu: event.cpu,
                    perf: unsafe { event.event.perf.perf },
                }))
            }
            #[allow(non_upper_case_globals)]
            bpf_intf::event_type_IPI => Ok(Action::IPI(IPIAction {
                ts: event.ts,
                cpu: event.cpu,
                pid: unsafe { event.event.ipi.pid },
                target_cpu: unsafe { event.event.ipi.target_cpu },
            })),
            #[allow(non_upper_case_globals)]
            bpf_intf::event_type_GPU_MEM => Ok(Action::GpuMem(GpuMemAction {
                ts: event.ts,
                cpu: event.cpu,
                pid: unsafe { event.event.gm.pid },
                gpu: unsafe { event.event.gm.gpu },
                size: unsafe { event.event.gm.size },
            })),
            #[allow(non_upper_case_globals)]
            bpf_intf::event_type_CPU_HP => Ok(Action::Cpuhp(CpuhpAction {
                ts: event.ts,
                pid: unsafe { event.event.chp.pid },
                cpu: unsafe { event.event.chp.cpu },
                state: unsafe { event.event.chp.state },
                target: unsafe { event.event.chp.target },
            })),
            #[allow(non_upper_case_globals)]
            bpf_intf::event_type_SOFTIRQ => {
                let softirq = unsafe { event.event.softirq };
                Ok(Action::SoftIRQ(SoftIRQAction {
                    cpu: event.cpu,
                    pid: softirq.pid,
                    entry_ts: softirq.entry_ts,
                    exit_ts: softirq.exit_ts,
                    softirq_nr: softirq.softirq_nr as usize,
                }))
            }
            #[allow(non_upper_case_globals)]
            bpf_intf::event_type_SCHED_WAKEUP => {
                let wakeup = unsafe { event.event.wakeup };
                let comm = unsafe {
                    std::str::from_utf8(std::slice::from_raw_parts(
                        event.event.wakeup.comm.as_ptr() as *const u8,
                        16,
                    ))
                    .unwrap()
                };
                Ok(Action::SchedWakeup(SchedWakeupAction {
                    ts: event.ts,
                    cpu: event.cpu,
                    pid: wakeup.pid,
                    prio: wakeup.prio,
                    comm: comm.into(),
                }))
            }
            #[allow(non_upper_case_globals)]
            bpf_intf::event_type_SCHED_WAKING => {
                let waking = unsafe { &event.event.waking };
                let comm = std::str::from_utf8(unsafe {
                    std::slice::from_raw_parts(waking.comm.as_ptr() as *const u8, 16)
                })
                .unwrap();
                Ok(Action::SchedWaking(SchedWakingAction {
                    ts: event.ts,
                    cpu: event.cpu,
                    pid: waking.pid,
                    prio: waking.prio,
                    comm: comm.into(),
                }))
            }
            #[allow(non_upper_case_globals)]
            bpf_intf::event_type_SCHED_SWITCH => {
                let sched_switch = unsafe { &event.event.sched_switch };
                let prev_comm = unsafe {
                    std::str::from_utf8(std::slice::from_raw_parts(
                        sched_switch.prev_comm.as_ptr() as *const u8,
                        sched_switch.prev_comm.len(),
                    ))
                    .unwrap()
                };
                let next_comm = unsafe {
                    std::str::from_utf8(std::slice::from_raw_parts(
                        sched_switch.next_comm.as_ptr() as *const u8,
                        sched_switch.next_comm.len(),
                    ))
                    .unwrap()
                };

                Ok(Action::SchedSwitch(SchedSwitchAction {
                    ts: event.ts,
                    cpu: event.cpu,
                    preempt: unsafe { sched_switch.preempt.assume_init() },
                    next_dsq_id: sched_switch.next_dsq_id,
                    next_dsq_lat_us: sched_switch.next_dsq_lat_us,
                    next_dsq_nr_queued: sched_switch.next_dsq_nr,
                    next_dsq_vtime: sched_switch.next_dsq_vtime,
                    next_slice_ns: sched_switch.next_slice_ns,
                    next_pid: sched_switch.next_pid,
                    next_tgid: sched_switch.next_tgid,
                    next_prio: sched_switch.next_prio,
                    next_comm: next_comm.into(),
                    prev_dsq_id: sched_switch.prev_dsq_id,
                    prev_used_slice_ns: sched_switch.prev_slice_ns,
                    prev_slice_ns: sched_switch.prev_slice_ns,
                    prev_pid: sched_switch.prev_pid,
                    prev_tgid: sched_switch.prev_tgid,
                    prev_comm: prev_comm.into(),
                    prev_prio: sched_switch.prev_prio,
                    prev_state: sched_switch.prev_state,
                }))
            }
            #[allow(non_upper_case_globals)]
            bpf_intf::event_type_TRACE_STARTED => {
                let trace = unsafe { &event.event.trace };
                Ok(Action::TraceStarted(TraceStartedAction {
                    start_immediately: unsafe { trace.start_immediately.assume_init() },
                    ts: event.ts,
                    stop_scheduled: unsafe { trace.stop_scheduled.assume_init() },
                }))
            }
            #[allow(non_upper_case_globals)]
            bpf_intf::event_type_TRACE_STOPPED => {
                let action = Action::TraceStopped(TraceStoppedAction { ts: event.ts });
                Ok(action)
            }
            _ => Err(()),
        }
    }
}

impl std::fmt::Display for Action {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Action::SetState(AppState::Default) => write!(f, "AppStateDefault"),
            Action::SetState(AppState::Event) => write!(f, "AppStateEvent"),
            Action::ToggleCpuFreq => write!(f, "ToggleCpuFreq"),
            Action::ToggleUncoreFreq => write!(f, "ToggleUncoreFreq"),
            Action::ToggleLocalization => write!(f, "ToggleLocalization"),
            Action::SetState(AppState::Help) => write!(f, "AppStateHelp"),
            Action::SetState(AppState::Llc) => write!(f, "AppStateLlc"),
            Action::SetState(AppState::Node) => write!(f, "AppStateNode"),
            Action::SetState(AppState::Scheduler) => write!(f, "AppStateScheduler"),
            Action::SaveConfig => write!(f, "SaveConfig"),
            Action::RequestTrace => write!(f, "RequestTrace"),
            Action::TraceStarted(_) => write!(f, "TraceStarted"),
            Action::TraceStopped(_) => write!(f, "TraceStopped"),
            Action::ClearEvent => write!(f, "ClearEvent"),
            Action::PrevEvent => write!(f, "PrevEvent"),
            Action::NextEvent => write!(f, "NextEvent"),
            Action::Quit => write!(f, "Quit"),
            Action::ChangeTheme => write!(f, "ChangeTheme"),
            Action::DecTickRate => write!(f, "DecTickRate"),
            Action::IncTickRate => write!(f, "IncTickRate"),
            Action::DecBpfSampleRate => write!(f, "DecBpfSampleRate"),
            Action::IncBpfSampleRate => write!(f, "IncBpfSampleRate"),
            Action::NextViewState => write!(f, "NextViewState"),
            Action::Down => write!(f, "Down"),
            Action::Up => write!(f, "Up"),
            Action::PageDown => write!(f, "PageDown"),
            Action::PageUp => write!(f, "PageUp"),
            Action::Enter => write!(f, "Enter"),
            _ => write!(f, "{:?}", self),
        }
    }
}
