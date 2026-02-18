//! Monitor trait for mid-simulation state sampling.
//!
//! Monitors are called by the engine at scheduling events, enabling
//! scheduler-specific probes to sample internal state into a time series.

use std::ffi::c_void;

use crate::trace::Trace;
use crate::types::{CpuId, Pid, TimeNs};

/// Scheduling events where monitors are invoked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbePoint {
    /// After `ops.running()` — task just started executing.
    Running,
    /// After `ops.stopping()` — task just stopped executing.
    Stopping,
    /// After `ops.quiescent()` — task went to sleep.
    Quiescent,
    /// After `ops.dispatch()` completed on a CPU.
    Dispatched,
}

/// Context passed to monitors at each probe point.
pub struct ProbeContext<'a> {
    /// Which scheduling event triggered this sample.
    pub point: ProbePoint,
    /// PID of the task involved (for task-scoped events).
    pub pid: Pid,
    /// CPU where the event occurred.
    pub cpu: CpuId,
    /// Simulation time at the probe point.
    pub time_ns: TimeNs,
    /// Raw C `task_struct` pointer for the task involved.
    /// Use this with scheduler probe functions (e.g., `LavdProbes`).
    pub task_raw: *mut c_void,
    /// Read-only access to the trace accumulated so far.
    pub trace: &'a Trace,
}

/// Trait for mid-simulation state sampling.
///
/// Implement this to read scheduler-internal state at each scheduling
/// event and accumulate it for post-simulation assertions.
pub trait Monitor {
    /// Called at each probe point during simulation.
    fn sample(&mut self, ctx: &ProbeContext);
}
