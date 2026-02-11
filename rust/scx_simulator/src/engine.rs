//! Event-driven simulation engine.
//!
//! This is the core of the simulator. It maintains the event queue, simulated
//! clock, CPU/task state, and drives the scheduler through its ops callbacks.

use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap};

use tracing::{debug, info};

use crate::cpu::SimCpu;
use crate::dsq::DsqManager;
use crate::ffi::Scheduler;
use crate::fmt::FmtN;
use crate::kfuncs::{self, OpsContext, SimulatorState};
use crate::scenario::Scenario;
use crate::task::{Phase, SimTask, TaskState};
use crate::trace::{Trace, TraceKind};
use crate::types::{CpuId, Pid, TimeNs};

/// SCX wake flags.
const SCX_ENQ_WAKEUP: u64 = 0x1;

/// A simulation event, ordered by timestamp.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Event {
    time_ns: TimeNs,
    /// Tiebreaker for events at the same time (lower = higher priority).
    seq: u64,
    kind: EventKind,
}

impl Ord for Event {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.time_ns
            .cmp(&other.time_ns)
            .then_with(|| self.seq.cmp(&other.seq))
    }
}

impl PartialOrd for Event {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum EventKind {
    /// A task becomes runnable (wakes up).
    TaskWake { pid: Pid },
    /// A task's time slice expires on the given CPU.
    SliceExpired { cpu: CpuId },
    /// A task finishes its current Run phase on the given CPU.
    TaskPhaseComplete { cpu: CpuId },
}

/// The main simulator.
pub struct Simulator<S: Scheduler> {
    scheduler: S,
}

impl<S: Scheduler> Simulator<S> {
    pub fn new(scheduler: S) -> Self {
        Simulator { scheduler }
    }

    /// Run a scenario and return the trace.
    pub fn run(&self, scenario: Scenario) -> Trace {
        let nr_cpus = scenario.nr_cpus;

        // Build CPUs
        let cpus: Vec<SimCpu> = (0..nr_cpus).map(|i| SimCpu::new(CpuId(i))).collect();

        // Build tasks
        let mut tasks: HashMap<Pid, SimTask> = HashMap::new();
        let mut task_raw_to_pid: HashMap<usize, Pid> = HashMap::new();

        for def in &scenario.tasks {
            let task = SimTask::new(def, nr_cpus);
            task_raw_to_pid.insert(task.raw() as usize, task.pid);
            tasks.insert(task.pid, task);
        }

        // Build simulator state (shared with kfuncs via thread-local)
        let mut state = SimulatorState {
            cpus,
            dsqs: DsqManager::new(),
            current_cpu: CpuId(0),
            trace: Trace::new(),
            clock: 0,
            task_raw_to_pid,
            prng_state: 0xDEAD_BEEF, // deterministic seed
            ops_context: OpsContext::None,
            pending_dispatch: None,
        };

        // Initialize scheduler
        unsafe {
            kfuncs::enter_sim(&mut state);
            let rc = self.scheduler.init();
            kfuncs::exit_sim();
            assert!(rc == 0, "scheduler init failed with rc={rc}");
        }

        // Build event queue
        let mut events: BinaryHeap<Reverse<Event>> = BinaryHeap::new();
        let mut seq: u64 = 0;

        // Schedule initial TaskWake events for all tasks
        for def in &scenario.tasks {
            events.push(Reverse(Event {
                time_ns: def.start_time_ns,
                seq,
                kind: EventKind::TaskWake { pid: def.pid },
            }));
            seq += 1;
        }

        // Main event loop
        while let Some(Reverse(event)) = events.pop() {
            if event.time_ns > scenario.duration_ns {
                break;
            }

            state.clock = event.time_ns;

            // Advance per-CPU clock for CPU-specific events
            match &event.kind {
                EventKind::SliceExpired { cpu } | EventKind::TaskPhaseComplete { cpu } => {
                    state.advance_cpu_clock(*cpu);
                    kfuncs::set_sim_clock(state.cpus[cpu.0 as usize].local_clock);
                }
                EventKind::TaskWake { .. } => {
                    // No specific CPU yet; use event queue time for tracing
                    kfuncs::set_sim_clock(state.clock);
                }
            }

            match event.kind {
                EventKind::TaskWake { pid } => {
                    self.handle_task_wake(pid, &mut state, &mut tasks, &mut events, &mut seq);
                }
                EventKind::SliceExpired { cpu } => {
                    self.handle_slice_expired(cpu, &mut state, &mut tasks, &mut events, &mut seq);
                }
                EventKind::TaskPhaseComplete { cpu } => {
                    self.handle_task_phase_complete(
                        cpu,
                        &mut state,
                        &mut tasks,
                        &mut events,
                        &mut seq,
                        scenario.duration_ns,
                    );
                }
            }
        }

        state.trace
    }

    /// Handle a task waking up.
    fn handle_task_wake(
        &self,
        pid: Pid,
        state: &mut SimulatorState,
        tasks: &mut HashMap<Pid, SimTask>,
        events: &mut BinaryHeap<Reverse<Event>>,
        seq: &mut u64,
    ) {
        let task = match tasks.get_mut(&pid) {
            Some(t) => t,
            None => return,
        };

        // Skip if task is already runnable or running
        if matches!(task.state, TaskState::Runnable | TaskState::Running { .. }) {
            return;
        }

        if matches!(task.state, TaskState::Exited) {
            return;
        }

        task.state = TaskState::Runnable;

        // Make sure the current phase is a Run phase
        // (skip over Wake phases, handle Sleep->Run transitions)
        self.advance_to_run_phase(task, state, events, seq);

        if matches!(task.state, TaskState::Exited | TaskState::Sleeping) {
            return;
        }

        state
            .trace
            .record(state.clock, CpuId(0), TraceKind::TaskWoke { pid });

        // Call select_cpu
        let prev_cpu = task.prev_cpu;
        let raw = task.raw();

        unsafe {
            kfuncs::enter_sim(state);
            state.pending_dispatch = None;
            state.ops_context = OpsContext::SelectCpu;
            state.current_cpu = prev_cpu;

            let selected_cpu_raw =
                self.scheduler
                    .select_cpu(raw, prev_cpu.0 as i32, SCX_ENQ_WAKEUP);
            let selected_cpu = CpuId(selected_cpu_raw as u32);
            state.ops_context = OpsContext::None;
            debug!(
                pid = pid.0,
                prev_cpu = prev_cpu.0,
                selected_cpu = selected_cpu.0,
                "select_cpu"
            );

            // Resolve deferred dispatch: SCX_DSQ_LOCAL -> selected_cpu
            // (kernel semantics: LOCAL resolves to the CPU select_cpu returned)
            let direct_dispatched = state.resolve_pending_dispatch(selected_cpu);
            kfuncs::exit_sim();

            let task = tasks.get_mut(&pid).unwrap();
            task.prev_cpu = selected_cpu;

            if let Some(dd_cpu) = direct_dispatched {
                // Task was directly dispatched — skip enqueue (kernel semantics)
                self.try_dispatch_and_run(dd_cpu, state, tasks, events, seq);
            } else {
                // Task was not directly dispatched; call enqueue
                kfuncs::enter_sim(state);
                state.ops_context = OpsContext::Enqueue;
                state.current_cpu = selected_cpu;
                debug!(pid = pid.0, enq_flags = SCX_ENQ_WAKEUP, "enqueue");
                self.scheduler.enqueue(raw, SCX_ENQ_WAKEUP);
                state.ops_context = OpsContext::None;
                // Resolve any deferred dispatch from enqueue
                // (SCX_DSQ_LOCAL resolves to the task's assigned CPU)
                state.resolve_pending_dispatch(selected_cpu);
                kfuncs::exit_sim();

                // Try to dispatch on idle CPUs
                let idle_cpus: Vec<CpuId> = state
                    .cpus
                    .iter()
                    .filter(|c| c.is_idle())
                    .map(|c| c.id)
                    .collect();

                for cpu in idle_cpus {
                    self.try_dispatch_and_run(cpu, state, tasks, events, seq);
                }
            }
        }
    }

    /// Handle a task's time slice expiring.
    fn handle_slice_expired(
        &self,
        cpu: CpuId,
        state: &mut SimulatorState,
        tasks: &mut HashMap<Pid, SimTask>,
        events: &mut BinaryHeap<Reverse<Event>>,
        seq: &mut u64,
    ) {
        let pid = match state.cpus[cpu.0 as usize].current_task {
            Some(pid) => pid,
            None => return,
        };

        let task = match tasks.get_mut(&pid) {
            Some(t) => t,
            None => return,
        };

        // Deduct the slice from remaining work
        let slice = task.get_slice();
        task.run_remaining_ns = task.run_remaining_ns.saturating_sub(slice);

        state.trace.record(
            state.cpus[cpu.0 as usize].local_clock,
            cpu,
            TraceKind::TaskPreempted { pid },
        );

        let task_name = task.name.as_str();
        info!(
            cpu = cpu.0,
            task = task_name,
            pid = pid.0,
            ran_ns = %FmtN(slice),
            "PREEMPTED"
        );

        // Stop the task - entire slice was consumed
        let raw = task.raw();
        task.state = TaskState::Runnable;

        state.cpus[cpu.0 as usize].current_task = None;

        // Set slice to 0: the full slice was consumed (used by stopping() for vtime)
        unsafe { crate::ffi::sim_task_set_slice(raw, 0) };

        unsafe {
            kfuncs::enter_sim(state);
            state.current_cpu = cpu;
            debug!(pid = pid.0, cpu = cpu.0, runnable = true, "stopping");
            self.scheduler.stopping(raw, true); // true = still runnable
                                                // Re-enqueue the preempted task
            state.ops_context = OpsContext::Enqueue;
            debug!(pid = pid.0, "enqueue (re-enqueue)");
            self.scheduler.enqueue(raw, 0);
            state.ops_context = OpsContext::None;
            state.resolve_pending_dispatch(cpu);
            kfuncs::exit_sim();
        }

        // Dispatch next task on this CPU
        self.try_dispatch_and_run(cpu, state, tasks, events, seq);
    }

    /// Handle a task completing its current Run phase.
    fn handle_task_phase_complete(
        &self,
        cpu: CpuId,
        state: &mut SimulatorState,
        tasks: &mut HashMap<Pid, SimTask>,
        events: &mut BinaryHeap<Reverse<Event>>,
        seq: &mut u64,
        duration_ns: TimeNs,
    ) {
        let pid = match state.cpus[cpu.0 as usize].current_task {
            Some(pid) => pid,
            None => return,
        };

        let task = match tasks.get_mut(&pid) {
            Some(t) => t,
            None => return,
        };

        let raw = task.raw();

        // Save the time consumed before advance_phase resets run_remaining_ns
        let time_consumed = task.run_remaining_ns;
        let original_slice = task.get_slice();

        // Advance to the next phase
        let has_next = task.advance_phase();
        let next_phase = task.current_phase().cloned();

        // Stop the running task
        let still_runnable = has_next && matches!(next_phase, Some(Phase::Run(_)));

        state.cpus[cpu.0 as usize].current_task = None;

        // Set slice to reflect consumed time (used by stopping() for vtime)
        let remaining_slice = original_slice.saturating_sub(time_consumed);
        unsafe { crate::ffi::sim_task_set_slice(raw, remaining_slice) };

        unsafe {
            kfuncs::enter_sim(state);
            state.current_cpu = cpu;
            debug!(pid = pid.0, cpu = cpu.0, still_runnable, "stopping");
            self.scheduler.stopping(raw, still_runnable);
            kfuncs::exit_sim();
        }

        if !has_next {
            // Task has completed all phases
            let task = tasks.get_mut(&pid).unwrap();
            task.state = TaskState::Exited;
            state.trace.record(
                state.cpus[cpu.0 as usize].local_clock,
                cpu,
                TraceKind::TaskCompleted { pid },
            );
            info!(
                cpu = cpu.0,
                task = task.name.as_str(),
                pid = pid.0,
                "COMPLETED"
            );
        } else {
            match next_phase {
                Some(Phase::Sleep(sleep_ns)) => {
                    let task = tasks.get_mut(&pid).unwrap();
                    task.state = TaskState::Sleeping;
                    let local_t = state.cpus[cpu.0 as usize].local_clock;
                    state
                        .trace
                        .record(local_t, cpu, TraceKind::TaskSlept { pid });
                    info!(
                        cpu = cpu.0,
                        task = task.name.as_str(),
                        pid = pid.0,
                        "SLEEPING"
                    );

                    // Schedule wake event
                    let wake_time = local_t + sleep_ns;
                    if wake_time <= duration_ns {
                        events.push(Reverse(Event {
                            time_ns: wake_time,
                            seq: *seq,
                            kind: EventKind::TaskWake { pid },
                        }));
                        *seq += 1;
                    }
                }
                Some(Phase::Run(_)) => {
                    // Task goes directly to the next Run phase (still runnable)
                    let task = tasks.get_mut(&pid).unwrap();
                    task.state = TaskState::Runnable;

                    state.trace.record(
                        state.cpus[cpu.0 as usize].local_clock,
                        cpu,
                        TraceKind::TaskYielded { pid },
                    );
                    info!(
                        cpu = cpu.0,
                        task = task.name.as_str(),
                        pid = pid.0,
                        "YIELDED"
                    );

                    // Re-enqueue
                    let raw = task.raw();
                    unsafe {
                        kfuncs::enter_sim(state);
                        state.ops_context = OpsContext::Enqueue;
                        state.current_cpu = cpu;
                        self.scheduler.enqueue(raw, 0);
                        state.ops_context = OpsContext::None;
                        state.resolve_pending_dispatch(cpu);
                        kfuncs::exit_sim();
                    }
                }
                Some(Phase::Wake(target_pid)) => {
                    let local_t = state.cpus[cpu.0 as usize].local_clock;
                    let task = tasks.get_mut(&pid).unwrap();
                    task.state = TaskState::Sleeping;
                    state
                        .trace
                        .record(local_t, cpu, TraceKind::TaskSlept { pid });

                    // Immediately wake the target
                    events.push(Reverse(Event {
                        time_ns: local_t,
                        seq: *seq,
                        kind: EventKind::TaskWake { pid: target_pid },
                    }));
                    *seq += 1;

                    // And schedule our own re-wake after the Wake phase
                    // by advancing to the next phase
                    let task = tasks.get_mut(&pid).unwrap();
                    if task.advance_phase() {
                        match task.current_phase() {
                            Some(Phase::Sleep(ns)) => {
                                let ns = *ns;
                                task.state = TaskState::Sleeping;
                                let wake_time = local_t + ns;
                                if wake_time <= duration_ns {
                                    events.push(Reverse(Event {
                                        time_ns: wake_time,
                                        seq: *seq,
                                        kind: EventKind::TaskWake { pid },
                                    }));
                                    *seq += 1;
                                }
                            }
                            Some(Phase::Run(_)) => {
                                task.state = TaskState::Runnable;
                                events.push(Reverse(Event {
                                    time_ns: local_t,
                                    seq: *seq,
                                    kind: EventKind::TaskWake { pid },
                                }));
                                *seq += 1;
                            }
                            Some(Phase::Wake(_)) => {
                                // Chain of wakes - schedule immediate re-processing
                                events.push(Reverse(Event {
                                    time_ns: local_t,
                                    seq: *seq,
                                    kind: EventKind::TaskWake { pid },
                                }));
                                *seq += 1;
                            }
                            None => {
                                task.state = TaskState::Exited;
                            }
                        }
                    } else {
                        task.state = TaskState::Exited;
                    }
                }
                None => {
                    let task = tasks.get_mut(&pid).unwrap();
                    task.state = TaskState::Exited;
                    state.trace.record(
                        state.cpus[cpu.0 as usize].local_clock,
                        cpu,
                        TraceKind::TaskCompleted { pid },
                    );
                }
            }
        }

        // Dispatch next task on this CPU
        self.try_dispatch_and_run(cpu, state, tasks, events, seq);
    }

    /// Try to dispatch and run a task on the given CPU.
    fn try_dispatch_and_run(
        &self,
        cpu: CpuId,
        state: &mut SimulatorState,
        tasks: &mut HashMap<Pid, SimTask>,
        events: &mut BinaryHeap<Reverse<Event>>,
        seq: &mut u64,
    ) {
        // If CPU is already running something, nothing to do
        if state.cpus[cpu.0 as usize].current_task.is_some() {
            return;
        }

        // Advance this CPU's clock to at least the event queue time
        state.advance_cpu_clock(cpu);

        // Check if local DSQ has tasks
        if state.cpus[cpu.0 as usize].local_dsq.is_empty() {
            // Call scheduler dispatch to try to fill the local DSQ
            unsafe {
                kfuncs::enter_sim(state);
                state.ops_context = OpsContext::Dispatch;
                state.current_cpu = cpu;
                debug!(cpu = cpu.0, "dispatch");
                self.scheduler.dispatch(cpu.0 as i32, std::ptr::null_mut());
                state.ops_context = OpsContext::None;
                // Flush any deferred dispatch from dispatch() callback
                // (SCX_DSQ_LOCAL resolves to the dispatching CPU)
                state.resolve_pending_dispatch(cpu);
                kfuncs::exit_sim();
            }
        }

        // Try to pull a task from the local DSQ
        if let Some(pid) = state.cpus[cpu.0 as usize].local_dsq.pop_front() {
            self.start_running(cpu, pid, state, tasks, events, seq);
        } else {
            // CPU is idle
            let local_t = state.cpus[cpu.0 as usize].local_clock;
            kfuncs::set_sim_clock(local_t);
            state.trace.record(local_t, cpu, TraceKind::CpuIdle);
            info!(cpu = cpu.0, "IDLE");
        }
    }

    /// Start running a task on a CPU.
    fn start_running(
        &self,
        cpu: CpuId,
        pid: Pid,
        state: &mut SimulatorState,
        tasks: &mut HashMap<Pid, SimTask>,
        events: &mut BinaryHeap<Reverse<Event>>,
        seq: &mut u64,
    ) {
        let task = match tasks.get_mut(&pid) {
            Some(t) => t,
            None => return,
        };

        // Skip exited tasks that are still lingering in DSQs
        if matches!(task.state, TaskState::Exited) {
            self.try_dispatch_and_run(cpu, state, tasks, events, seq);
            return;
        }

        task.state = TaskState::Running { cpu };
        task.prev_cpu = cpu;
        state.cpus[cpu.0 as usize].current_task = Some(pid);

        let raw = task.raw();

        // Call enable on first schedule
        if !task.enabled {
            task.enabled = true;
            unsafe {
                kfuncs::enter_sim(state);
                state.current_cpu = cpu;
                debug!(pid = pid.0, cpu = cpu.0, "enable");
                self.scheduler.enable(raw);
                kfuncs::exit_sim();
            }
        }

        // Call running
        unsafe {
            kfuncs::enter_sim(state);
            state.current_cpu = cpu;
            debug!(pid = pid.0, cpu = cpu.0, "running");
            self.scheduler.running(raw);
            kfuncs::exit_sim();
        }

        let local_t = state.cpus[cpu.0 as usize].local_clock;
        kfuncs::set_sim_clock(local_t);

        state
            .trace
            .record(local_t, cpu, TraceKind::TaskScheduled { pid });

        // Determine how long this task will run
        let task = tasks.get(&pid).unwrap();
        let slice = task.get_slice();
        let remaining = task.run_remaining_ns;

        info!(
            cpu = cpu.0,
            task = task.name.as_str(),
            pid = pid.0,
            slice_ns = %FmtN(slice),
            "STARTED"
        );

        if remaining == 0 {
            // Task has no remaining work -- complete immediately
            events.push(Reverse(Event {
                time_ns: local_t,
                seq: *seq,
                kind: EventKind::TaskPhaseComplete { cpu },
            }));
            *seq += 1;
        } else if slice > 0 && slice <= remaining {
            // Slice expires before the phase completes
            events.push(Reverse(Event {
                time_ns: local_t + slice,
                seq: *seq,
                kind: EventKind::SliceExpired { cpu },
            }));
            *seq += 1;
        } else {
            // Phase completes before the slice
            events.push(Reverse(Event {
                time_ns: local_t + remaining,
                seq: *seq,
                kind: EventKind::TaskPhaseComplete { cpu },
            }));
            *seq += 1;
        }
    }

    /// Advance a task past any Wake phases to the next Run or Sleep phase.
    fn advance_to_run_phase(
        &self,
        task: &mut SimTask,
        state: &mut SimulatorState,
        events: &mut BinaryHeap<Reverse<Event>>,
        seq: &mut u64,
    ) {
        loop {
            match task.current_phase() {
                Some(Phase::Run(_)) => break,
                Some(Phase::Wake(target_pid)) => {
                    let target = *target_pid;
                    events.push(Reverse(Event {
                        time_ns: state.clock,
                        seq: *seq,
                        kind: EventKind::TaskWake { pid: target },
                    }));
                    *seq += 1;
                    if !task.advance_phase() {
                        task.state = TaskState::Exited;
                        return;
                    }
                }
                Some(Phase::Sleep(_)) | None => {
                    // Task shouldn't wake into a Sleep phase normally,
                    // but if behavior is unusual, just mark sleeping/exited
                    if task.current_phase().is_none() {
                        task.state = TaskState::Exited;
                    }
                    return;
                }
            }
        }
    }
}
