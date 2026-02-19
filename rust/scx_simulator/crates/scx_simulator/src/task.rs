//! Task model for the simulator.
//!
//! Each simulated task has a scripted behavior (sequence of phases) and
//! carries a raw pointer to a heap-allocated C `task_struct`.

use std::ffi::c_void;

use crate::ffi;
use crate::types::{CpuId, MmId, Pid, TimeNs, Vtime};

/// Kernel sched_prio_to_weight table from kernel/sched/core.c.
/// Maps nice levels -20..19 (indices 0..39) to scheduler weights.
const SCHED_PRIO_TO_WEIGHT: [u32; 40] = [
    /* -20 */ 88761, 71755, 56483, 46273, 36291, /* -15 */ 29154, 23254, 18705, 14949,
    11916, /* -10 */ 9548, 7620, 6100, 4904, 3906, /*  -5 */ 3121, 2501, 1991, 1586,
    1277, /*   0 */ 1024, 820, 655, 526, 423, /*   5 */ 335, 272, 215, 172, 137,
    /*  10 */ 110, 87, 70, 56, 45, /*  15 */ 36, 29, 23, 18, 15,
];

/// Convert a nice value (-20..=19) to a kernel scheduler weight.
pub fn nice_to_weight(nice: i8) -> u32 {
    assert!(
        (-20..=19).contains(&nice),
        "nice value {nice} out of range -20..=19"
    );
    SCHED_PRIO_TO_WEIGHT[(nice + 20) as usize]
}

/// Cgroup weight constants from include/linux/cgroup.h.
const CGROUP_WEIGHT_MIN: u32 = 1;
const CGROUP_WEIGHT_DFL: u32 = 100;
const CGROUP_WEIGHT_MAX: u32 = 10000;

/// Convert a raw kernel scheduler weight to cgroup-weight space [1..10000].
///
/// Mirrors the kernel's `sched_weight_to_cgroup()` from kernel/sched/sched.h:
///   clamp(weight * CGROUP_WEIGHT_DFL / 1024, 1, 10000)
///
/// The kernel stores this converted value in `p->scx.weight`, not the raw
/// sched_prio_to_weight value. BPF schedulers (e.g. scx_simple's stopping
/// callback) assume cgroup-weight space when they divide by `p->scx.weight`.
pub fn sched_weight_to_cgroup(weight: u32) -> u32 {
    let cg = ((weight as u64 * CGROUP_WEIGHT_DFL as u64) + 512) / 1024;
    (cg as u32).clamp(CGROUP_WEIGHT_MIN, CGROUP_WEIGHT_MAX)
}

/// Per-task SCX ops_state, modeling the kernel's `SCX_OPSS_*` state machine.
///
/// In the kernel, `ops.dequeue()` is only called when a task is in
/// `SCX_OPSS_QUEUED` — i.e., it was handed to the BPF scheduler via
/// `enqueue()` but has not yet been dispatched to a DSQ. Once dispatched
/// (or picked to run), the task transitions to `NONE` and `dequeue()` is
/// no longer valid.
///
/// We only need two states: the kernel's `DISPATCHING` is transient and
/// resolved immediately by `resolve_pending_dispatch()`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OpsTaskState {
    /// Task is not queued in the BPF scheduler (default / after dispatch).
    #[default]
    None,
    /// Task has been enqueued to the BPF scheduler but not yet dispatched.
    Queued,
}

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

/// How a task's phase sequence repeats.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RepeatMode {
    /// Run the phase sequence exactly once and exit.
    Once,
    /// Repeat the phase sequence a fixed number of times, then exit.
    Count(u32),
    /// Repeat the phase sequence indefinitely (until simulation ends).
    Forever,
}

/// The scripted behavior for a task: a sequence of phases with a repeat mode.
#[derive(Debug, Clone)]
pub struct TaskBehavior {
    pub phases: Vec<Phase>,
    pub repeat: RepeatMode,
}

/// Definition of a task for scenario creation.
#[derive(Debug, Clone)]
pub struct TaskDef {
    pub name: String,
    pub pid: Pid,
    pub nice: i8,
    pub behavior: TaskBehavior,
    /// When the task first becomes runnable (simulated ns).
    pub start_time_ns: TimeNs,
    /// Address-space group. Tasks with the same `MmId` share an address
    /// space (like threads) and are eligible for wake-affine scheduling.
    pub mm_id: Option<MmId>,
    /// CPU affinity mask. `None` means all CPUs are allowed.
    /// When `Some(cpus)`, the task may only run on the listed CPUs.
    pub allowed_cpus: Option<Vec<CpuId>>,
    /// Parent task PID. When set, `real_parent` on the C `task_struct`
    /// will point to the specified parent's struct, enabling scheduler
    /// features that track parent-child relationships (e.g. LAVD's
    /// waker-wakee latency criticality propagation).
    pub parent_pid: Option<Pid>,
    /// Cgroup name. When set, the task belongs to the named cgroup.
    /// The cgroup must be defined in the scenario via `.cgroup()`.
    /// If `None`, the task belongs to the root cgroup.
    pub cgroup_name: Option<String>,
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
    /// Current repeat iteration (0-based). Incremented each time the phase
    /// sequence wraps back to the beginning.
    pub repeat_iteration: u32,
    /// Remaining nanoseconds in the current Run phase (only meaningful
    /// when the current phase is `Phase::Run`).
    pub run_remaining_ns: TimeNs,
    /// Current task state.
    pub state: TaskState,
    /// Whether `enable` has been called for this task.
    pub enabled: bool,
    /// The last CPU the task ran on (for select_cpu prev_cpu).
    pub prev_cpu: CpuId,
    /// Timestamp (simulated ns) when the task became Runnable.
    ///
    /// Used by the watchdog to detect stalled tasks. Set when the task
    /// transitions to Runnable, cleared (set to None) when the task starts
    /// Running or goes to Sleeping. Matches kernel semantics: only reset
    /// when the task actually runs, not when dequeued and re-enqueued.
    pub runnable_at_ns: Option<TimeNs>,
    /// Snapshot of `sum_exec_runtime` when the task last started running.
    ///
    /// The kernel's `update_curr()` increments `p->se.sum_exec_runtime`
    /// by CPU time consumed. The simulator mirrors this by saving the
    /// base value at `running()` and computing `base + elapsed` before
    /// `tick()` and `stopping()` callbacks.
    pub sum_exec_base: TimeNs,
}

impl SimTask {
    /// Create a new simulated task from a definition.
    pub fn new(def: &TaskDef, nr_cpus: u32) -> Self {
        let raw = unsafe { ffi::sim_task_alloc() };
        assert!(!raw.is_null(), "sim_task_alloc returned null");

        let scx_weight = sched_weight_to_cgroup(nice_to_weight(def.nice));

        unsafe {
            ffi::sim_task_set_pid(raw, def.pid.0);
            // The kernel stores cgroup-weight-space [1..10000] in p->scx.weight,
            // not the raw sched_prio_to_weight value.
            ffi::sim_task_set_weight(raw, scx_weight);
            // Default: task can run on all CPUs
            ffi::sim_task_set_nr_cpus_allowed(raw, nr_cpus as i32);
            // static_prio = nice + 120
            ffi::sim_task_set_static_prio(raw, def.nice as i32 + 120);
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
            repeat_iteration: 0,
            run_remaining_ns,
            state: TaskState::Sleeping,
            enabled: false,
            prev_cpu: CpuId(0),
            runnable_at_ns: None,
            sum_exec_base: 0,
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
            match self.behavior.repeat {
                RepeatMode::Once => return false,
                RepeatMode::Forever => {
                    self.phase_idx = 0;
                    self.repeat_iteration += 1;
                }
                RepeatMode::Count(n) => {
                    self.repeat_iteration += 1;
                    if self.repeat_iteration >= n {
                        return false;
                    }
                    self.phase_idx = 0;
                }
            }
        }
        // Reset run_remaining for the new phase
        match self.current_phase() {
            Some(Phase::Run(ns)) => self.run_remaining_ns = *ns,
            _ => self.run_remaining_ns = 0,
        }
        true
    }

    /// Read the task's current slice from the C task_struct.
    pub fn get_slice(&self) -> u64 {
        unsafe { ffi::sim_task_get_slice(self.raw) }
    }

    /// Read the task's dsq_vtime from the C task_struct.
    pub fn get_dsq_vtime(&self) -> Vtime {
        Vtime(unsafe { ffi::sim_task_get_dsq_vtime(self.raw) })
    }
}

impl Drop for SimTask {
    fn drop(&mut self) {
        unsafe {
            ffi::sim_task_free(self.raw);
        }
    }
}
