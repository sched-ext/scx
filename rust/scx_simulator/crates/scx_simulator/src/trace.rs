//! Trace event recording for the simulator.
//!
//! Every scheduling action (task scheduled, preempted, slept, woke, CPU idle)
//! is recorded as a `TraceEvent` with a simulated timestamp and CPU ID.

use crate::engine::ExitKind;
use crate::fmt::FmtTs;
use crate::task::TaskDef;
use crate::types::{CpuId, DsqId, Pid, TimeNs, Vtime};

/// Summary statistics from a trace, useful for realism comparison.
///
/// This struct captures high-level metrics that can be compared between
/// simulated and real kernel traces to identify realism gaps.
#[derive(Debug, Clone, Default)]
pub struct TraceSummary {
    /// Total number of trace events recorded.
    pub total_events: usize,
    /// Total number of scheduler tick events across all CPUs.
    pub total_ticks: usize,
    /// Total number of task yield events (voluntary phase boundary).
    pub total_yields: usize,
    /// Total number of task preemption events (slice expiration).
    pub total_preempts: usize,
    /// Total number of task sleep events.
    pub total_sleeps: usize,
    /// Total number of task wake events.
    pub total_wakes: usize,
    /// Total number of CPU idle periods.
    pub total_idle_periods: usize,
    /// Count of dispatches to global DSQs.
    pub global_dsq_dispatches: usize,
    /// Count of dispatches to local (per-CPU) DSQs.
    pub local_dsq_dispatches: usize,
}

impl std::fmt::Display for TraceSummary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Trace Summary:")?;
        writeln!(f, "  total_events:          {}", self.total_events)?;
        writeln!(f, "  total_ticks:           {}", self.total_ticks)?;
        writeln!(f, "  total_yields:          {}", self.total_yields)?;
        writeln!(f, "  total_preempts:        {}", self.total_preempts)?;
        writeln!(f, "  total_sleeps:          {}", self.total_sleeps)?;
        writeln!(f, "  total_wakes:           {}", self.total_wakes)?;
        writeln!(f, "  total_idle_periods:    {}", self.total_idle_periods)?;
        writeln!(f, "  global_dsq_dispatches: {}", self.global_dsq_dispatches)?;
        writeln!(f, "  local_dsq_dispatches:  {}", self.local_dsq_dispatches)
    }
}

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
    /// Dispatch to local DSQ rejected (cpumask violation).
    ///
    /// Emitted when a scheduler dispatches to `SCX_DSQ_LOCAL_ON | cpu` but
    /// the task cannot run on that CPU (cpumask or migration-disabled).
    DispatchRejected {
        pid: Pid,
        target_cpu: CpuId,
        reason: DispatchRejectReason,
    },
}

/// Reason why a dispatch to a local DSQ was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DispatchRejectReason {
    /// Target CPU is not in the task's cpumask.
    CpumaskViolation,
    /// Task is migration-disabled and cannot move to a different CPU.
    MigrationDisabled,
}

/// A complete simulation trace, containing all events in chronological order.
#[derive(Debug, Clone)]
pub struct Trace {
    events: Vec<TraceEvent>,
    pub(crate) nr_cpus: u32,
    task_names: Vec<(Pid, String)>,
    /// How the simulation terminated.
    exit_kind: ExitKind,
}

impl Trace {
    pub(crate) fn new(nr_cpus: u32, tasks: &[TaskDef]) -> Self {
        let task_names = tasks.iter().map(|t| (t.pid, t.name.clone())).collect();
        Self {
            events: Vec::new(),
            nr_cpus,
            task_names,
            exit_kind: ExitKind::Normal,
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

    /// Set the exit kind for this trace.
    pub(crate) fn set_exit_kind(&mut self, kind: ExitKind) {
        self.exit_kind = kind;
    }

    /// Get the exit kind for this simulation.
    pub fn exit_kind(&self) -> &ExitKind {
        &self.exit_kind
    }

    /// Returns true if the simulation exited with an error.
    pub fn has_error(&self) -> bool {
        self.exit_kind.is_error()
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

    /// Count the number of yield events for a task.
    ///
    /// Yields occur when a task voluntarily gives up the CPU (phase boundary)
    /// but remains runnable. High yield counts for CPU-bound tasks may indicate
    /// a realism gap in the simulation model.
    pub fn yield_count(&self, pid: Pid) -> usize {
        self.events
            .iter()
            .filter(|e| matches!(e.kind, TraceKind::TaskYielded { pid: p } if p == pid))
            .count()
    }

    /// Count the number of preemption events for a task.
    pub fn preempt_count(&self, pid: Pid) -> usize {
        self.events
            .iter()
            .filter(|e| matches!(e.kind, TraceKind::TaskPreempted { pid: p } if p == pid))
            .count()
    }

    /// Compute run duration statistics for a task.
    ///
    /// Returns a tuple of (min, max, mean, count) for run durations in nanoseconds.
    /// This is useful for comparing simulated vs real traces where real systems
    /// show more variance due to system noise.
    pub fn run_duration_stats(&self, pid: Pid) -> Option<(TimeNs, TimeNs, TimeNs, usize)> {
        let mut durations: Vec<TimeNs> = Vec::new();
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
                        durations.push(event.time_ns - start);
                    }
                }
                _ => {}
            }
        }

        if durations.is_empty() {
            return None;
        }

        let min = *durations.iter().min().unwrap();
        let max = *durations.iter().max().unwrap();
        let sum: TimeNs = durations.iter().sum();
        let mean = sum / durations.len() as TimeNs;
        Some((min, max, mean, durations.len()))
    }

    /// Count dispatches through the global DSQ vs local DSQ.
    ///
    /// Returns (global_dsq_dispatches, local_dsq_dispatches).
    /// In real execution, CPU-bound tasks mostly use direct dispatch via
    /// SCX_DSQ_LOCAL from select_cpu, while simulated tasks may show more
    /// global DSQ usage due to yield cycles.
    pub fn dsq_dispatch_counts(&self) -> (usize, usize) {
        let mut global = 0usize;
        let mut local = 0usize;

        // DSQ ID 0x8000_0000_0000_0000 | cpu is local DSQ
        // Other IDs are global DSQs (e.g., 4096 for LAVD)
        const LOCAL_DSQ_MASK: u64 = 0xC000_0000_0000_0000;

        for event in &self.events {
            match &event.kind {
                TraceKind::DsqInsert { dsq_id, .. } | TraceKind::DsqInsertVtime { dsq_id, .. } => {
                    if dsq_id.0 & LOCAL_DSQ_MASK != 0 {
                        local += 1;
                    } else {
                        global += 1;
                    }
                }
                _ => {}
            }
        }

        (global, local)
    }

    /// Get a summary of trace statistics useful for realism comparison.
    ///
    /// Returns a struct with key metrics for comparing simulated vs real traces.
    pub fn summary(&self) -> TraceSummary {
        let mut total_ticks = 0usize;
        let mut total_yields = 0usize;
        let mut total_preempts = 0usize;
        let mut total_sleeps = 0usize;
        let mut total_wakes = 0usize;
        let mut total_idle_periods = 0usize;

        for event in &self.events {
            match &event.kind {
                TraceKind::Tick { .. } => total_ticks += 1,
                TraceKind::TaskYielded { .. } => total_yields += 1,
                TraceKind::TaskPreempted { .. } => total_preempts += 1,
                TraceKind::TaskSlept { .. } => total_sleeps += 1,
                TraceKind::TaskWoke { .. } => total_wakes += 1,
                TraceKind::CpuIdle => total_idle_periods += 1,
                _ => {}
            }
        }

        let (global_dsq, local_dsq) = self.dsq_dispatch_counts();

        TraceSummary {
            total_events: self.events.len(),
            total_ticks,
            total_yields,
            total_preempts,
            total_sleeps,
            total_wakes,
            total_idle_periods,
            global_dsq_dispatches: global_dsq,
            local_dsq_dispatches: local_dsq,
        }
    }

    /// Write the trace in Chrome Trace Event Format JSON, loadable in
    /// [ui.perfetto.dev](https://ui.perfetto.dev).
    pub fn write_perfetto_json(&self, writer: &mut impl std::io::Write) -> std::io::Result<()> {
        crate::perfetto::write_json(self, writer)
    }

    /// Pretty-print the trace for debugging.
    pub fn dump(&self) {
        let cpu_width = if self.nr_cpus == 0 {
            1u8
        } else {
            ((self.nr_cpus as f64).log10().floor() as u8) + 1
        };
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
                TraceKind::DispatchRejected {
                    pid,
                    target_cpu,
                    reason,
                } => {
                    let reason_str = match reason {
                        DispatchRejectReason::CpumaskViolation => "cpumask",
                        DispatchRejectReason::MigrationDisabled => "migration_disabled",
                    };
                    format!(
                        "DISPATCH_REJECT pid={} target_cpu={} reason={}",
                        pid.0, target_cpu.0, reason_str
                    )
                }
            };
            eprintln!(
                "[{}] cpu={:<3} {}",
                FmtTs::local(event.time_ns, Some(event.cpu), cpu_width),
                event.cpu.0,
                desc
            );
        }
    }
}
