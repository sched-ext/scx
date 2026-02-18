//! Trace event recording for the simulator.
//!
//! Every scheduling action (task scheduled, preempted, slept, woke, CPU idle)
//! is recorded as a `TraceEvent` with a simulated timestamp and CPU ID.

use crate::fmt::FmtTs;
use crate::task::TaskDef;
use crate::types::{CpuId, DsqId, Pid, TimeNs, Vtime};

/// A single trace event produced by the simulator.
#[derive(Debug, Clone)]
pub struct TraceEvent {
    /// Simulated time in nanoseconds when this event occurred.
    pub time_ns: TimeNs,
    /// The CPU on which this event occurred.
    pub cpu: CpuId,
    /// The kind of event.
    pub kind: TraceKind,
}

/// The type of scheduling event recorded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TraceKind {
    /// A task was scheduled to run on this CPU.
    TaskScheduled { pid: Pid },
    /// A task was preempted (slice expired) on this CPU.
    TaskPreempted { pid: Pid },
    /// A task yielded (phase complete but still runnable) on this CPU.
    TaskYielded { pid: Pid },
    /// A task voluntarily slept on this CPU.
    TaskSlept { pid: Pid },
    /// A task woke up.
    TaskWoke { pid: Pid },
    /// A task completed all its phases.
    TaskCompleted { pid: Pid },
    /// The CPU became idle (no tasks to run).
    CpuIdle,
    /// Simulation ended while this task was still running on a CPU.
    /// Emitted for each CPU with a current task when the event loop exits.
    SimulationEnd { pid: Pid },

    // ----- Ops-level events (kernel context-switch path) -----
    /// A task was stopped on this CPU (put_prev_task → stopping()).
    PutPrevTask { pid: Pid, still_runnable: bool },
    /// A CPU was selected for a waking task (select_task_rq → select_cpu()).
    SelectTaskRq {
        pid: Pid,
        prev_cpu: CpuId,
        selected_cpu: CpuId,
    },
    /// A task was enqueued into the scheduler (enqueue_task → enqueue()).
    EnqueueTask { pid: Pid, enq_flags: u64 },
    /// The scheduler's dispatch() callback was invoked to fill the local DSQ.
    Balance { prev_pid: Option<Pid> },
    /// A task was popped from the local DSQ (pick_task).
    PickTask { pid: Pid },
    /// A task was handed to the CPU to run (set_next_task → running()).
    SetNextTask { pid: Pid },

    // ----- Kfunc-level events (BPF helper calls) -----
    /// scx_bpf_dsq_insert: FIFO insert into a DSQ.
    DsqInsert {
        pid: Pid,
        dsq_id: DsqId,
        slice: TimeNs,
    },
    /// scx_bpf_dsq_insert_vtime: vtime-ordered insert into a DSQ.
    DsqInsertVtime {
        pid: Pid,
        dsq_id: DsqId,
        slice: TimeNs,
        vtime: Vtime,
    },
    /// scx_bpf_dsq_move_to_local: move head of DSQ to the current CPU's local DSQ.
    DsqMoveToLocal { dsq_id: DsqId, success: bool },
    /// scx_bpf_kick_cpu: send scheduling IPI to a CPU.
    KickCpu { target_cpu: CpuId },
    /// A periodic scheduler tick fired on this CPU.
    Tick { pid: Pid },
}

/// A complete simulation trace, containing all events in chronological order.
#[derive(Debug, Clone)]
pub struct Trace {
    events: Vec<TraceEvent>,
    pub(crate) nr_cpus: u32,
    task_names: Vec<(Pid, String)>,
}

impl Trace {
    pub(crate) fn new(nr_cpus: u32, tasks: &[TaskDef]) -> Self {
        let task_names = tasks.iter().map(|t| (t.pid, t.name.clone())).collect();
        Self {
            events: Vec::new(),
            nr_cpus,
            task_names,
        }
    }

    /// Resolve a PID to a task name, or `"???"` if unknown.
    pub(crate) fn task_name(&self, pid: Pid) -> &str {
        self.task_names
            .iter()
            .find(|(p, _)| *p == pid)
            .map(|(_, n)| n.as_str())
            .unwrap_or("???")
    }

    pub(crate) fn record(&mut self, time_ns: TimeNs, cpu: CpuId, kind: TraceKind) {
        self.events.push(TraceEvent { time_ns, cpu, kind });
    }

    /// Get all events in chronological order.
    pub fn events(&self) -> &[TraceEvent] {
        &self.events
    }

    /// Calculate the total runtime (nanoseconds) for a given task PID.
    ///
    /// This sums up the intervals between `TaskScheduled` and the next
    /// `TaskPreempted`/`TaskSlept`/`TaskCompleted` for that PID. Open
    /// intervals (task still running at simulation end) are not counted;
    /// use longer durations or shorter phases to ensure tasks complete
    /// at least one cycle.
    pub fn total_runtime(&self, pid: Pid) -> TimeNs {
        let mut total: TimeNs = 0;
        let mut running_since: Option<TimeNs> = None;

        for event in &self.events {
            match &event.kind {
                TraceKind::TaskScheduled { pid: p } if *p == pid => {
                    running_since = Some(event.time_ns);
                }
                TraceKind::TaskPreempted { pid: p }
                | TraceKind::TaskYielded { pid: p }
                | TraceKind::TaskSlept { pid: p }
                | TraceKind::TaskCompleted { pid: p }
                    if *p == pid =>
                {
                    if let Some(start) = running_since.take() {
                        total += event.time_ns - start;
                    }
                }
                _ => {}
            }
        }

        total
    }

    /// Count the number of times a task was scheduled.
    pub fn schedule_count(&self, pid: Pid) -> usize {
        self.events
            .iter()
            .filter(|e| matches!(e.kind, TraceKind::TaskScheduled { pid: p } if p == pid))
            .count()
    }

    /// Count the number of times a CPU went idle.
    pub fn idle_count(&self, cpu: CpuId) -> usize {
        self.events
            .iter()
            .filter(|e| e.cpu == cpu && matches!(e.kind, TraceKind::CpuIdle))
            .count()
    }

    /// Count the number of `Balance` events on a CPU.
    pub fn balance_count(&self, cpu: CpuId) -> usize {
        self.events
            .iter()
            .filter(|e| e.cpu == cpu && matches!(e.kind, TraceKind::Balance { .. }))
            .count()
    }

    /// Count the number of `DsqInsert` or `DsqInsertVtime` events for a task.
    pub fn dsq_insert_count(&self, pid: Pid) -> usize {
        self.events
            .iter()
            .filter(|e| {
                matches!(
                    e.kind,
                    TraceKind::DsqInsert { pid: p, .. }
                    | TraceKind::DsqInsertVtime { pid: p, .. }
                    if p == pid
                )
            })
            .count()
    }

    /// Count the number of tick events on a CPU.
    pub fn tick_count(&self, cpu: CpuId) -> usize {
        self.events
            .iter()
            .filter(|e| e.cpu == cpu && matches!(e.kind, TraceKind::Tick { .. }))
            .count()
    }

    /// Write the trace in Chrome Trace Event Format JSON, loadable in
    /// [ui.perfetto.dev](https://ui.perfetto.dev).
    pub fn write_perfetto_json(&self, writer: &mut impl std::io::Write) -> std::io::Result<()> {
        crate::perfetto::write_json(self, writer)
    }

    /// Pretty-print the trace for debugging.
    pub fn dump(&self) {
        for event in &self.events {
            let desc = match &event.kind {
                TraceKind::TaskScheduled { pid } => format!("SCHED    pid={}", pid.0),
                TraceKind::TaskPreempted { pid } => format!("PREEMPT  pid={}", pid.0),
                TraceKind::TaskYielded { pid } => format!("YIELD    pid={}", pid.0),
                TraceKind::TaskSlept { pid } => format!("SLEEP    pid={}", pid.0),
                TraceKind::TaskWoke { pid } => format!("WAKE     pid={}", pid.0),
                TraceKind::TaskCompleted { pid } => format!("COMPLETE pid={}", pid.0),
                TraceKind::CpuIdle => "IDLE".to_string(),
                TraceKind::SimulationEnd { pid } => format!("SIM_END  pid={}", pid.0),
                TraceKind::PutPrevTask {
                    pid,
                    still_runnable,
                } => {
                    format!("PUT_PREV pid={} runnable={}", pid.0, still_runnable)
                }
                TraceKind::SelectTaskRq {
                    pid,
                    prev_cpu,
                    selected_cpu,
                } => {
                    format!(
                        "SELECT_CPU pid={} prev={} sel={}",
                        pid.0, prev_cpu.0, selected_cpu.0
                    )
                }
                TraceKind::EnqueueTask { pid, enq_flags } => {
                    format!("ENQUEUE  pid={} flags={:#x}", pid.0, enq_flags)
                }
                TraceKind::Balance { prev_pid } => {
                    let p = prev_pid.map_or(-1, |p| p.0);
                    format!("BALANCE  prev_pid={}", p)
                }
                TraceKind::PickTask { pid } => format!("PICK     pid={}", pid.0),
                TraceKind::SetNextTask { pid } => format!("SET_NEXT pid={}", pid.0),
                TraceKind::DsqInsert { pid, dsq_id, slice } => {
                    format!("DSQ_INS  pid={} dsq={:#x} slice={}", pid.0, dsq_id.0, slice)
                }
                TraceKind::DsqInsertVtime {
                    pid,
                    dsq_id,
                    slice,
                    vtime,
                } => {
                    format!(
                        "DSQ_INS_V pid={} dsq={:#x} slice={} vtime={}",
                        pid.0, dsq_id.0, slice, vtime.0
                    )
                }
                TraceKind::DsqMoveToLocal { dsq_id, success } => {
                    format!("DSQ_MOVE dsq={:#x} ok={}", dsq_id.0, success)
                }
                TraceKind::KickCpu { target_cpu } => {
                    format!("KICK     cpu={}", target_cpu.0)
                }
                TraceKind::Tick { pid } => format!("TICK     pid={}", pid.0),
            };
            eprintln!(
                "[{}] cpu={:<3} {}",
                FmtTs::local(event.time_ns),
                event.cpu.0,
                desc
            );
        }
    }
}
