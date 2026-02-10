//! Simulated CPU state.

use std::collections::VecDeque;

use crate::types::{CpuId, Pid};

/// A simulated CPU.
#[derive(Debug)]
pub struct SimCpu {
    /// CPU ID.
    pub id: CpuId,
    /// PID of the currently running task, or None if idle.
    pub current_task: Option<Pid>,
    /// The CPU's local dispatch queue (FIFO).
    pub local_dsq: VecDeque<Pid>,
}

impl SimCpu {
    pub fn new(id: CpuId) -> Self {
        SimCpu {
            id,
            current_task: None,
            local_dsq: VecDeque::new(),
        }
    }

    pub fn is_idle(&self) -> bool {
        self.current_task.is_none()
    }
}
