//! Simulated CPU state.

use std::collections::VecDeque;

use crate::types::{CpuId, Pid, TimeNs};

/// How the previous task on this CPU stopped running.
/// Used to determine context switch overhead (voluntary vs involuntary).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LastStopReason {
    /// Task yielded, slept, or completed (voluntary).
    Voluntary,
    /// Task was preempted by tick or higher-priority task (involuntary).
    Involuntary,
}

/// A simulated CPU.
#[derive(Debug)]
pub struct SimCpu {
    /// CPU ID.
    pub id: CpuId,
    /// PID of the currently running task, or None if idle.
    pub current_task: Option<Pid>,
    /// PID of the previously running task (for dispatch `prev` argument).
    /// Set when a task stops running; cleared when a new task starts.
    pub prev_task: Option<Pid>,
    /// The CPU's local dispatch queue (FIFO).
    pub local_dsq: VecDeque<Pid>,
    /// Per-CPU logical clock (nanoseconds).
    ///
    /// Advances when this CPU processes events. With no scheduler overhead,
    /// equals the event queue time. When overhead is modeled, local clocks
    /// diverge across CPUs.
    pub local_clock: TimeNs,
    /// SMT sibling CPUs (including self). Empty if SMT is not configured.
    pub siblings: Vec<CpuId>,
    /// CPU performance level set by `scx_bpf_cpuperf_set`.
    /// Range: `[0, SCX_CPUPERF_ONE]` where `SCX_CPUPERF_ONE = 1024`.
    pub perf_lvl: u32,
    /// Timestamp when the current task started running on this CPU.
    /// Used by `preempt_current()` to compute how much of the slice was consumed.
    pub task_started_at: Option<TimeNs>,
    /// The slice value when the current task started running.
    /// Used by `preempt_current()` to set the remaining slice on the raw task.
    pub task_original_slice: Option<TimeNs>,
    /// Whether this CPU is online. Offline CPUs don't receive ticks or dispatch.
    pub is_online: bool,
}

impl SimCpu {
    pub fn new(id: CpuId) -> Self {
        SimCpu {
            id,
            current_task: None,
            prev_task: None,
            local_dsq: VecDeque::new(),
            local_clock: 0,
            siblings: Vec::new(),
            perf_lvl: 0,
            task_started_at: None,
            task_original_slice: None,
            is_online: true,
        }
    }

    pub fn is_idle(&self) -> bool {
        self.current_task.is_none()
    }
}
