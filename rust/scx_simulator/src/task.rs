//! Task model for the simulator.
//!
//! Each simulated task has a scripted behavior (sequence of phases) and
//! carries a raw pointer to a heap-allocated C `task_struct`.

use std::ffi::c_void;

use crate::ffi;
use crate::types::{CpuId, Pid, TimeNs, Weight};

/// The state a simulated task can be in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskState {
    /// Task is sleeping (not runnable).
    Sleeping,
    /// Task is runnable but not currently executing on any CPU.
    Runnable,
    /// Task is currently executing on the given CPU.
    Running { cpu: CpuId },
    /// Task has completed all its phases and exited.
    Exited,
}

/// A phase in a task's scripted behavior.
#[derive(Debug, Clone)]
pub enum Phase {
    /// Run (consume CPU) for the given number of nanoseconds.
    Run(TimeNs),
    /// Sleep (block) for the given number of nanoseconds.
    Sleep(TimeNs),
    /// Wake another task by PID (instantaneous).
    Wake(Pid),
}

/// The scripted behavior for a task: a sequence of phases, optionally repeating.
#[derive(Debug, Clone)]
pub struct TaskBehavior {
    pub phases: Vec<Phase>,
    pub repeat: bool,
}

/// Definition of a task for scenario creation.
#[derive(Debug, Clone)]
pub struct TaskDef {
    pub name: String,
    pub pid: Pid,
    pub weight: Weight,
    pub behavior: TaskBehavior,
    /// When the task first becomes runnable (simulated ns).
    pub start_time_ns: TimeNs,
}

/// A simulated task at runtime.
pub struct SimTask {
    /// Raw pointer to the heap-allocated C task_struct.
    raw: *mut c_void,
    /// Task PID (also stored in the raw task_struct).
    pub pid: Pid,
    /// The task's name.
    pub name: String,
    /// Scripted behavior phases.
    pub behavior: TaskBehavior,
    /// Current phase index.
    pub phase_idx: usize,
    /// Remaining nanoseconds in the current Run phase (only meaningful
    /// when the current phase is `Phase::Run`).
    pub run_remaining_ns: TimeNs,
    /// Current task state.
    pub state: TaskState,
    /// Whether `enable` has been called for this task.
    pub enabled: bool,
    /// The last CPU the task ran on (for select_cpu prev_cpu).
    pub prev_cpu: CpuId,
}

impl SimTask {
    /// Create a new simulated task from a definition.
    pub fn new(def: &TaskDef, nr_cpus: u32) -> Self {
        let raw = unsafe { ffi::sim_task_alloc() };
        assert!(!raw.is_null(), "sim_task_alloc returned null");

        unsafe {
            ffi::sim_task_set_pid(raw, def.pid.0);
            ffi::sim_task_set_weight(raw, def.weight);
            ffi::sim_task_set_scx_weight(raw, def.weight);
            // Default: task can run on all CPUs
            ffi::sim_task_set_nr_cpus_allowed(raw, nr_cpus as i32);
            // Default nice 0 = static_prio 120
            ffi::sim_task_set_static_prio(raw, 120);
        }

        // Initialize run_remaining from the first phase if it's a Run
        let run_remaining_ns = match def.behavior.phases.first() {
            Some(Phase::Run(ns)) => *ns,
            _ => 0,
        };

        SimTask {
            raw,
            pid: def.pid,
            name: def.name.clone(),
            behavior: def.behavior.clone(),
            phase_idx: 0,
            run_remaining_ns,
            state: TaskState::Sleeping,
            enabled: false,
            prev_cpu: CpuId(0),
        }
    }

    /// Get the raw C task_struct pointer (for passing to scheduler ops).
    pub fn raw(&self) -> *mut c_void {
        self.raw
    }

    /// Get the current phase, or None if the task has completed all phases.
    pub fn current_phase(&self) -> Option<&Phase> {
        self.behavior.phases.get(self.phase_idx)
    }

    /// Advance to the next phase. Returns true if there is a next phase.
    pub fn advance_phase(&mut self) -> bool {
        self.phase_idx += 1;
        if self.phase_idx >= self.behavior.phases.len() {
            if self.behavior.repeat {
                self.phase_idx = 0;
            } else {
                return false;
            }
        }
        // Reset run_remaining for the new phase
        if let Some(Phase::Run(ns)) = self.current_phase() {
            self.run_remaining_ns = *ns;
        }
        true
    }

    /// Read the task's current slice from the C task_struct.
    pub fn get_slice(&self) -> u64 {
        unsafe { ffi::sim_task_get_slice(self.raw) }
    }

    /// Read the task's dsq_vtime from the C task_struct.
    pub fn get_dsq_vtime(&self) -> u64 {
        unsafe { ffi::sim_task_get_dsq_vtime(self.raw) }
    }
}

impl Drop for SimTask {
    fn drop(&mut self) {
        unsafe {
            ffi::sim_task_free(self.raw);
        }
    }
}
