// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

mod app;
pub mod bpf_intf;
mod bpf_prog_data;
pub mod bpf_skel;
mod bpf_stats;
pub mod cli;
mod columns;
pub mod config;
mod cpu_data;
mod cpu_stats;
pub mod edm;
mod event_data;
mod keymap;
pub mod layered_util;
mod llc_data;
pub mod mangoapp;
pub mod mcp;
mod mem_stats;
pub mod network_stats;
mod node_data;
mod perfetto_trace;
mod power_data;
mod proc_data;
pub mod profiling_events;
pub mod render;
pub mod search;
mod stats;
mod symbol_data;
mod theme;
mod thread_data;
pub mod tracer;
mod tui;
pub mod util;

pub use crate::bpf_skel::types::bpf_event;
pub use app::App;
pub use bpf_prog_data::{BpfProgData, BpfProgStats};
pub use bpf_skel::*;
pub use columns::{Column, Columns};
pub use cpu_data::CpuData;
pub use cpu_stats::{CpuStatSnapshot, CpuStatTracker};
pub use event_data::EventData;
pub use keymap::Key;
pub use keymap::KeyMap;
pub use llc_data::LlcData;
pub use mem_stats::MemStatSnapshot;
pub use network_stats::NetworkStatSnapshot;
pub use node_data::NodeData;
pub use perfetto_trace::PerfettoTraceManager;
pub use power_data::{
    CStateInfo, CorePowerData, PowerDataCollector, PowerSnapshot, SystemPowerData,
};
pub use proc_data::ProcData;
pub use profiling_events::{
    available_kprobe_events, available_perf_events, get_default_events, KprobeEvent, PerfEvent,
    ProfilingEvent,
};
pub use stats::StatAggregation;
pub use stats::VecStats;
pub use theme::AppTheme;
pub use thread_data::ThreadData;
pub use tui::Event;
pub use tui::Tui;

pub use plain::Plain;
// Generate serialization types for handling events from the bpf ring buffer.
unsafe impl Plain for crate::bpf_skel::types::bpf_event {}

use smartstring::alias::String as SsoString;
use std::collections::BTreeMap;

pub const APP: &str = "scxtop";
pub const TRACE_FILE_PREFIX: &str = "scxtop_trace";
pub const STATS_SOCKET_PATH: &str = "/var/run/scx/root/stats";
pub const LICENSE: &str = concat!(
    "Copyright (c) Meta Platforms, Inc. and affiliates.\n",
    "\n",
    "This software may be used and distributed according to the terms of the \n",
    "GNU General Public License version 2."
);
pub const SCHED_NAME_PATH: &str = "/sys/kernel/sched_ext/root/ops";

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum AppState {
    /// Application is in the BPF programs state.
    BpfPrograms,
    /// Application is in the BPF program detail state.
    BpfProgramDetail,
    /// Application is in the default state.
    Default,
    /// Application is in the help state.
    Help,
    /// Application is in the KprobeEvent list state.
    KprobeEvent,
    /// Application is in the Llc state.
    Llc,
    /// Application is in the mangoapp state.
    MangoApp,
    /// Application is in the Memory state.
    Memory,
    /// Application is in the network state.
    Network,
    /// Application is in the NUMA node state.
    Node,
    /// Application is in the paused state.
    Pause,
    /// Application is in the PerfEvent list state.
    PerfEvent,
    /// Application is in the perf top view state.
    PerfTop,
    /// Application is in the Power state.
    Power,
    /// Application is in the Process state.
    Process,
    /// Application is in the scheduler state.
    Scheduler,
    /// Application is in the tracing  state.
    Tracing,
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ViewState {
    Sparkline,
    BarChart,
    LineGauge,
}

impl ViewState {
    /// Returns the next ViewState.
    pub fn next(&self) -> Self {
        match self {
            ViewState::Sparkline => ViewState::BarChart,
            ViewState::BarChart => ViewState::LineGauge,
            ViewState::LineGauge => ViewState::Sparkline,
        }
    }
}

impl std::fmt::Display for ViewState {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            ViewState::Sparkline => write!(f, "sparkline"),
            ViewState::BarChart => write!(f, "barchart"),
            ViewState::LineGauge => write!(f, "linegauge"),
        }
    }
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ComponentViewState {
    /// Component view is hidden in the default view
    Hidden,
    /// Component view is shown in the default view (current behavior)
    Default,
    /// Switch to detailed component view
    Detail,
}

impl ComponentViewState {
    /// Returns the next ComponentViewState, cycling through the values.
    pub fn next(&self) -> Self {
        match self {
            ComponentViewState::Hidden => ComponentViewState::Default,
            ComponentViewState::Default => ComponentViewState::Detail,
            ComponentViewState::Detail => ComponentViewState::Hidden,
        }
    }
}

impl std::fmt::Display for ComponentViewState {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            ComponentViewState::Hidden => write!(f, "hidden"),
            ComponentViewState::Default => write!(f, "default"),
            ComponentViewState::Detail => write!(f, "detail"),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum FilterItem {
    String(String),
    Int(i32),
}
impl FilterItem {
    pub fn as_string(&self) -> String {
        match self {
            FilterItem::String(s) => s.clone(),
            FilterItem::Int(int) => int.to_string(),
        }
    }

    pub fn as_int(&self) -> Option<i32> {
        match self {
            FilterItem::Int(int) => Some(*int),
            FilterItem::String(_) => None,
        }
    }
}

#[derive(Default, Debug, Clone)]
pub struct FilteredState {
    pub list: Vec<FilterItem>,
    pub count: u16,
    pub scroll: u16,
    pub selected: usize,
}

impl FilteredState {
    pub fn reset(&mut self) {
        self.list.clear();
        self.count = 0;
        self.scroll = 0;
        self.selected = 0;
    }
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SchedCpuPerfSetAction {
    pub cpu: u32,
    pub perf: u32,
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ExitAction {
    pub ts: u64,
    pub cpu: u32,
    pub pid: u32,
    pub tgid: u32,
    pub prio: u32,
    pub comm: SsoString,
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ForkAction {
    pub ts: u64,
    pub cpu: u32,
    pub parent_pid: u32,
    pub parent_tgid: u32,
    pub child_pid: u32,
    pub child_tgid: u32,
    pub parent_comm: SsoString,
    pub child_comm: SsoString,
    pub parent_layer_id: i32,
    pub child_layer_id: i32,
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ExecAction {
    pub ts: u64,
    pub cpu: u32,
    pub old_pid: u32,
    pub pid: u32,
    pub layer_id: i32,
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct WaitAction {
    pub ts: u64,
    pub cpu: u32,
    pub comm: SsoString,
    pub pid: u32,
    pub prio: i32,
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
    pub next_layer_id: i32,
    pub next_comm: SsoString,
    pub prev_dsq_id: u64,
    pub prev_used_slice_ns: u64,
    pub prev_slice_ns: u64,
    pub prev_pid: u32,
    pub prev_tgid: u32,
    pub prev_prio: i32,
    pub prev_comm: SsoString,
    pub prev_state: u64,
    pub prev_layer_id: i32,
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SchedWakeActionCtx {
    pub ts: u64,
    pub cpu: u32,
    pub pid: u32,
    pub tgid: u32,
    pub prio: i32,
    pub comm: SsoString,
    pub waker_pid: u32,
    pub waker_comm: SsoString,
}

pub type SchedWakeupNewAction = SchedWakeActionCtx;
pub type SchedWakingAction = SchedWakeActionCtx;
pub type SchedWakeupAction = SchedWakeActionCtx;

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SchedMigrateTaskAction {
    pub ts: u64,
    pub cpu: u32,
    pub dest_cpu: u32,
    pub pid: u32,
    pub prio: i32,
    pub comm: SsoString,
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SchedHangAction {
    pub ts: u64,
    pub cpu: u32,
    pub comm: SsoString,
    pub pid: u32,
}

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
pub struct CpuhpEnterAction {
    pub ts: u64,
    pub cpu: u32,
    pub target: i32,
    pub state: i32,
    pub pid: u32,
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CpuhpExitAction {
    pub ts: u64,
    pub cpu: u32,
    pub state: i32,
    pub idx: i32,
    pub ret: i32,
    pub pid: u32,
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct HwPressureAction {
    pub hw_pressure: u64,
    pub cpu: u32,
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct KprobeAction {
    pub ts: u64,
    pub cpu: u32,
    pub pid: u32,
    pub instruction_pointer: u64,
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SystemStatAction {
    pub ts: u64,
    pub cpu_data_prev: BTreeMap<usize, CpuStatSnapshot>,
    pub cpu_data_current: BTreeMap<usize, CpuStatSnapshot>,
    pub mem_info: MemStatSnapshot,
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct UpdateColVisibilityAction {
    pub table: String,
    pub col: String,
    pub visible: bool,
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct MangoAppAction {
    pub pid: u32,
    pub vis_frametime: u64,
    pub app_frametime: u64,
    pub fsr_upscale: u8,
    pub fsr_sharpness: u8,
    pub latency_ns: u64,
    pub output_width: u32,
    pub output_height: u32,
    pub display_refresh: u16,
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PerfSampleAction {
    pub ts: u64,
    pub cpu: u32,
    pub pid: u32,
    pub instruction_pointer: u64,
    pub cpu_id: u32,
    pub is_kernel: bool,
    pub kernel_stack: Vec<u64>,
    pub user_stack: Vec<u64>,
    pub layer_id: i32,
}

#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Action {
    Backspace,
    ChangeTheme,
    ClearEvent,
    CpuhpEnter(CpuhpEnterAction),
    CpuhpExit(CpuhpExitAction),
    SystemStat(SystemStatAction),
    DecBpfSampleRate,
    DecTickRate,
    Down,
    Enter,
    Event,
    Esc,
    Exec(ExecAction),
    Exit(ExitAction),
    Filter,
    Fork(ForkAction),
    Kprobe(KprobeAction),
    GpuMem(GpuMemAction),
    Help,
    HwPressure(HwPressureAction),
    IncBpfSampleRate,
    IncTickRate,
    InputEntry(String),
    IPI(IPIAction),
    MangoApp(MangoAppAction),
    NextEvent,
    NextViewState,
    PageDown,
    PageUp,
    PerfSample(PerfSampleAction),
    PerfSampleRateIncrease,
    PerfSampleRateDecrease,
    PrevEvent,
    Quit,
    RequestTrace,
    TraceStarted(TraceStartedAction),
    TraceStopped(TraceStoppedAction),
    ReloadStatsClient,
    SaveConfig,
    SchedCpuPerfSet(SchedCpuPerfSetAction),
    SchedHang(SchedHangAction),
    SchedMigrateTask(SchedMigrateTaskAction),
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
    ToggleBpfPerfSampling,
    ToggleCpuFreq,
    ToggleLocalization,
    ToggleHwPressure,
    ToggleUncoreFreq,
    Up,
    UpdateColVisibility(UpdateColVisibilityAction),
    Wait(WaitAction),
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
            bpf_intf::event_type_CPU_HP_ENTER => Ok(Action::CpuhpEnter(CpuhpEnterAction {
                ts: event.ts,
                pid: unsafe { event.event.chp.pid },
                cpu: unsafe { event.event.chp.cpu },
                state: unsafe { event.event.chp.state },
                target: unsafe { event.event.chp.target },
            })),
            #[allow(non_upper_case_globals)]
            bpf_intf::event_type_CPU_HP_EXIT => Ok(Action::CpuhpExit(CpuhpExitAction {
                ts: event.ts,
                pid: unsafe { event.event.cxp.pid },
                cpu: unsafe { event.event.cxp.cpu },
                state: unsafe { event.event.cxp.state },
                idx: unsafe { event.event.cxp.idx },
                ret: unsafe { event.event.cxp.ret },
            })),
            #[allow(non_upper_case_globals)]
            bpf_intf::event_type_HW_PRESSURE => Ok(Action::HwPressure(HwPressureAction {
                cpu: event.cpu,
                hw_pressure: unsafe { event.event.hwp.hw_pressure },
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

                let comm = String::from_utf8_lossy(&wakeup.comm);
                let waker_comm = String::from_utf8_lossy(&wakeup.waker_comm);

                Ok(Action::SchedWakeup(SchedWakeupAction {
                    ts: event.ts,
                    cpu: event.cpu,
                    pid: wakeup.pid,
                    tgid: wakeup.tgid,
                    prio: wakeup.prio,
                    comm: comm.into(),
                    waker_pid: wakeup.waker_pid,
                    waker_comm: waker_comm.into(),
                }))
            }
            #[allow(non_upper_case_globals)]
            bpf_intf::event_type_SCHED_WAKING => {
                let waking = unsafe { &event.event.waking };

                let comm = String::from_utf8_lossy(&waking.comm);
                let waker_comm = String::from_utf8_lossy(&waking.waker_comm);

                Ok(Action::SchedWaking(SchedWakingAction {
                    ts: event.ts,
                    cpu: event.cpu,
                    pid: waking.pid,
                    tgid: waking.tgid,
                    prio: waking.prio,
                    comm: comm.into(),
                    waker_pid: waking.waker_pid,
                    waker_comm: waker_comm.into(),
                }))
            }
            #[allow(non_upper_case_globals)]
            bpf_intf::event_type_SCHED_MIGRATE => {
                let migrate = unsafe { &event.event.migrate };

                let comm = String::from_utf8_lossy(&migrate.comm);

                Ok(Action::SchedMigrateTask(SchedMigrateTaskAction {
                    ts: event.ts,
                    cpu: event.cpu,
                    dest_cpu: migrate.dest_cpu,
                    pid: migrate.pid,
                    prio: migrate.prio,
                    comm: comm.into(),
                }))
            }
            #[allow(non_upper_case_globals)]
            bpf_intf::event_type_SCHED_HANG => {
                let hang = unsafe { &event.event.hang };

                let comm = String::from_utf8_lossy(&hang.comm);

                Ok(Action::SchedHang(SchedHangAction {
                    ts: event.ts,
                    cpu: event.cpu,
                    comm: comm.into(),
                    pid: hang.pid,
                }))
            }
            bpf_intf::event_type_EXEC => {
                let exec = unsafe { &event.event.exec };

                Ok(Action::Exec(ExecAction {
                    ts: event.ts,
                    cpu: event.cpu,
                    old_pid: exec.old_pid,
                    pid: exec.pid,
                    layer_id: exec.layer_id,
                }))
            }
            bpf_intf::event_type_EXIT => {
                let exit = unsafe { &event.event.exit };
                let comm = String::from_utf8_lossy(&exit.comm);

                Ok(Action::Exit(ExitAction {
                    ts: event.ts,
                    cpu: event.cpu,
                    pid: exit.pid,
                    tgid: exit.tgid,
                    prio: exit.prio,
                    comm: comm.into(),
                }))
            }
            #[allow(non_upper_case_globals)]
            bpf_intf::event_type_FORK => {
                let fork = unsafe { &event.event.fork };
                let parent_comm = String::from_utf8_lossy(&fork.parent_comm);
                let child_comm = String::from_utf8_lossy(&fork.child_comm);

                Ok(Action::Fork(ForkAction {
                    ts: event.ts,
                    cpu: event.cpu,
                    parent_pid: fork.parent_pid,
                    parent_tgid: fork.parent_tgid,
                    child_pid: fork.child_pid,
                    child_tgid: fork.child_tgid,
                    parent_comm: parent_comm.into(),
                    child_comm: child_comm.into(),
                    parent_layer_id: fork.parent_layer_id,
                    child_layer_id: fork.child_layer_id,
                }))
            }
            #[allow(non_upper_case_globals)]
            bpf_intf::event_type_KPROBE => {
                let kprobe = unsafe { &event.event.kprobe };

                Ok(Action::Kprobe(KprobeAction {
                    ts: event.ts,
                    cpu: event.cpu,
                    pid: kprobe.pid,
                    instruction_pointer: kprobe.instruction_pointer,
                }))
            }
            #[allow(non_upper_case_globals)]
            bpf_intf::event_type_PERF_SAMPLE => {
                let perf_sample = unsafe { &event.event.perf_sample };

                // Extract kernel stack trace
                let kernel_stack: Vec<u64> = if perf_sample.kernel_stack_size > 0 {
                    perf_sample.kernel_stack[0..perf_sample.kernel_stack_size as usize].to_vec()
                } else {
                    Vec::new()
                };

                // Extract user stack trace
                let user_stack: Vec<u64> = if perf_sample.user_stack_size > 0 {
                    perf_sample.user_stack[0..perf_sample.user_stack_size as usize].to_vec()
                } else {
                    Vec::new()
                };

                Ok(Action::PerfSample(PerfSampleAction {
                    ts: event.ts,
                    cpu: event.cpu,
                    pid: perf_sample.pid,
                    instruction_pointer: perf_sample.instruction_pointer,
                    cpu_id: perf_sample.cpu_id,
                    is_kernel: unsafe { perf_sample.is_kernel.assume_init() },
                    kernel_stack,
                    user_stack,
                    layer_id: perf_sample.layer_id,
                }))
            }
            #[allow(non_upper_case_globals)]
            bpf_intf::event_type_SCHED_SWITCH => {
                let sched_switch = unsafe { &event.event.sched_switch };
                let prev_comm = String::from_utf8_lossy(&sched_switch.prev_comm);
                let next_comm = String::from_utf8_lossy(&sched_switch.next_comm);

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
                    next_layer_id: sched_switch.next_layer_id,
                    next_comm: next_comm.into(),
                    prev_dsq_id: sched_switch.prev_dsq_id,
                    prev_used_slice_ns: sched_switch.prev_used_slice_ns,
                    prev_slice_ns: sched_switch.prev_slice_ns,
                    prev_pid: sched_switch.prev_pid,
                    prev_tgid: sched_switch.prev_tgid,
                    prev_comm: prev_comm.into(),
                    prev_prio: sched_switch.prev_prio,
                    prev_state: sched_switch.prev_state,
                    prev_layer_id: sched_switch.prev_layer_id,
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
            bpf_intf::event_type_WAIT => {
                let wait = unsafe { &event.event.wait };
                let comm = String::from_utf8_lossy(&wait.comm);

                Ok(Action::Wait(WaitAction {
                    ts: event.ts,
                    cpu: event.cpu,
                    comm: comm.into(),
                    pid: wait.pid,
                    prio: wait.prio,
                }))
            }
            _ => Err(()),
        }
    }
}

impl std::fmt::Display for Action {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Action::SetState(AppState::Default) => write!(f, "AppStateDefault"),
            Action::SetState(AppState::Pause) => write!(f, "AppStatePause"),
            Action::SetState(AppState::PerfEvent) => write!(f, "AppStatePerfEvent"),
            Action::SetState(AppState::Process) => write!(f, "AppStateProcess"),
            Action::SetState(AppState::KprobeEvent) => write!(f, "AppStateKprobeEvent"),
            Action::SetState(AppState::MangoApp) => write!(f, "AppStateMangoApp"),
            Action::Filter => write!(f, "Filter"),
            Action::UpdateColVisibility(_) => write!(f, "UpdateColVisibility"),
            Action::ToggleCpuFreq => write!(f, "ToggleCpuFreq"),
            Action::ToggleUncoreFreq => write!(f, "ToggleUncoreFreq"),
            Action::ToggleLocalization => write!(f, "ToggleLocalization"),
            Action::ToggleHwPressure => write!(f, "ToggleHwPressure"),
            Action::SetState(AppState::Help) => write!(f, "AppStateHelp"),
            Action::SetState(AppState::Llc) => write!(f, "AppStateLlc"),
            Action::SetState(AppState::Network) => write!(f, "AppStateNetwork"),
            Action::SetState(AppState::Node) => write!(f, "AppStateNode"),
            Action::SetState(AppState::Scheduler) => write!(f, "AppStateScheduler"),
            Action::SaveConfig => write!(f, "SaveConfig"),
            Action::RequestTrace => write!(f, "RequestTrace"),
            Action::TraceStarted(_) => write!(f, "TraceStarted"),
            Action::PerfSampleRateIncrease => write!(f, "PerfSampleRateIncrease"),
            Action::PerfSampleRateDecrease => write!(f, "PerfSampleRateDecrease"),
            Action::PageUp => write!(f, "PageUp"),
            Action::PageDown => write!(f, "PageDown"),
            Action::PrevEvent => write!(f, "PrevEvent"),
            Action::Quit => write!(f, "Quit"),
            Action::ChangeTheme => write!(f, "ChangeTheme"),
            Action::DecTickRate => write!(f, "DecTickRate"),
            Action::IncTickRate => write!(f, "IncTickRate"),
            Action::DecBpfSampleRate => write!(f, "DecBpfSampleRate"),
            Action::IncBpfSampleRate => write!(f, "IncBpfSampleRate"),
            Action::NextViewState => write!(f, "NextViewState"),
            Action::Down => write!(f, "Down"),
            Action::Up => write!(f, "Up"),
            Action::Enter => write!(f, "Enter"),
            _ => write!(f, "{self:?}"),
        }
    }
}
