//! Trace event recording for the simulator.
//!
//! Every scheduling action (task scheduled, preempted, slept, woke, CPU idle)
//! is recorded as a `TraceEvent` with a simulated timestamp and CPU ID.

/// A single trace event produced by the simulator.
#[derive(Debug, Clone)]
pub struct TraceEvent {
    /// Simulated time in nanoseconds when this event occurred.
    pub time_ns: u64,
    /// The CPU on which this event occurred.
    pub cpu: u32,
    /// The kind of event.
    pub kind: TraceKind,
}

/// The type of scheduling event recorded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TraceKind {
    /// A task was scheduled to run on this CPU.
    TaskScheduled { pid: i32 },
    /// A task was preempted (slice expired) on this CPU.
    TaskPreempted { pid: i32 },
    /// A task voluntarily slept on this CPU.
    TaskSlept { pid: i32 },
    /// A task woke up.
    TaskWoke { pid: i32 },
    /// A task completed all its phases.
    TaskCompleted { pid: i32 },
    /// The CPU became idle (no tasks to run).
    CpuIdle,
}

/// A complete simulation trace, containing all events in chronological order.
#[derive(Debug, Clone)]
pub struct Trace {
    events: Vec<TraceEvent>,
}

impl Trace {
    pub(crate) fn new() -> Self {
        Self { events: Vec::new() }
    }

    pub(crate) fn record(&mut self, time_ns: u64, cpu: u32, kind: TraceKind) {
        self.events.push(TraceEvent { time_ns, cpu, kind });
    }

    /// Get all events in chronological order.
    pub fn events(&self) -> &[TraceEvent] {
        &self.events
    }

    /// Calculate the total runtime (nanoseconds) for a given task PID.
    ///
    /// This sums up the intervals between `TaskScheduled` and the next
    /// `TaskPreempted`/`TaskSlept`/`TaskCompleted` for that PID.
    pub fn total_runtime(&self, pid: i32) -> u64 {
        let mut total: u64 = 0;
        let mut running_since: Option<u64> = None;

        for event in &self.events {
            match &event.kind {
                TraceKind::TaskScheduled { pid: p } if *p == pid => {
                    running_since = Some(event.time_ns);
                }
                TraceKind::TaskPreempted { pid: p }
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
    pub fn schedule_count(&self, pid: i32) -> usize {
        self.events
            .iter()
            .filter(|e| matches!(e.kind, TraceKind::TaskScheduled { pid: p } if p == pid))
            .count()
    }

    /// Count the number of times a CPU went idle.
    pub fn idle_count(&self, cpu: u32) -> usize {
        self.events
            .iter()
            .filter(|e| e.cpu == cpu && matches!(e.kind, TraceKind::CpuIdle))
            .count()
    }

    /// Pretty-print the trace for debugging.
    pub fn dump(&self) {
        for event in &self.events {
            let desc = match &event.kind {
                TraceKind::TaskScheduled { pid } => format!("SCHED    pid={pid}"),
                TraceKind::TaskPreempted { pid } => format!("PREEMPT  pid={pid}"),
                TraceKind::TaskSlept { pid } => format!("SLEEP    pid={pid}"),
                TraceKind::TaskWoke { pid } => format!("WAKE     pid={pid}"),
                TraceKind::TaskCompleted { pid } => format!("COMPLETE pid={pid}"),
                TraceKind::CpuIdle => "IDLE".to_string(),
            };
            eprintln!(
                "[{:>12} ns] cpu={:<3} {}",
                event.time_ns, event.cpu, desc
            );
        }
    }
}
