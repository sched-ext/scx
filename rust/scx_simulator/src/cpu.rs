//! Simulated CPU state.

use std::collections::VecDeque;

/// A simulated CPU.
#[derive(Debug)]
pub struct SimCpu {
    /// CPU ID.
    pub id: u32,
    /// PID of the currently running task, or None if idle.
    pub current_task: Option<i32>,
    /// The CPU's local dispatch queue (FIFO).
    pub local_dsq: VecDeque<i32>,
}

impl SimCpu {
    pub fn new(id: u32) -> Self {
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
