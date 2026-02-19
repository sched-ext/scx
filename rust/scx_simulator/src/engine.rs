//! Event-driven simulation engine.
//!
//! This is the core of the simulator. It maintains the event queue, simulated
//! clock, CPU/task state, and drives the scheduler through its ops callbacks.

use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap};
use std::ffi::c_void;

use tracing::{debug, info, trace};

use crate::cpu::{LastStopReason, SimCpu};
use crate::dsq::DsqManager;
use crate::ffi::{self, Scheduler};
use crate::fmt::FmtN;
use crate::kfuncs::{self, OpsContext, SimulatorState};
use crate::monitor::{Monitor, ProbeContext, ProbePoint};
use crate::perf;
use crate::scenario::Scenario;
use crate::task::{OpsTaskState, Phase, SimTask, TaskState};
use crate::trace::{Trace, TraceKind};
use crate::types::{CpuId, DsqId, KickFlags, Pid, TimeNs};

/// SCX wake flags.
const SCX_ENQ_WAKEUP: u64 = 0x1;

/// SCX dequeue flags: task is going to sleep.
const SCX_DEQ_SLEEP: u64 = 1;

/// Tick interval in nanoseconds (4ms, matching HZ=250).
const TICK_INTERVAL_NS: TimeNs = 4_000_000;

/// A simulation event, ordered by timestamp then tiebreaker.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Event {
    time_ns: TimeNs,
    /// Tiebreaker for events at the same time (lower = higher priority).
    /// In fixed-priority mode, this is a monotonic counter (insertion order).
    /// In randomized mode, this combines a PRNG-derived priority with a
    /// monotonic counter to explore different orderings while remaining
    /// deterministic for a given seed.
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

/// Priority-queue wrapper that assigns tiebreakers to events.
///
/// In **fixed-priority** mode, events at the same timestamp are processed in
/// insertion order (monotonic `seq`). In **randomized** mode, each event gets
/// a PRNG-derived priority in the upper 32 bits of `seq` with the monotonic
/// counter in the lower 32 bits. This explores different orderings for
/// same-timestamp events while remaining deterministic for a given seed.
///
/// The event PRNG is separate from `SimulatorState::prng_state` so that
/// adding/removing events does not perturb the scheduler's PRNG sequence.
struct EventQueue {
    heap: BinaryHeap<Reverse<Event>>,
    /// Monotonic counter for unique event identity / fixed-priority ordering.
    seq: u64,
    /// Separate xorshift32 PRNG for randomized tiebreaking.
    event_prng: u32,
    /// When true, use insertion-order tiebreaking (monotonic seq).
    fixed_priority: bool,
}

impl EventQueue {
    fn new(seed: u32, fixed_priority: bool) -> Self {
        // Derive event PRNG seed from scenario seed but offset it so it's
        // independent of the main simulation PRNG.
        let event_seed = seed.wrapping_mul(0x9e3779b9).wrapping_add(0xdeadbeef);
        let event_seed = if event_seed == 0 { 1 } else { event_seed };
        EventQueue {
            heap: BinaryHeap::new(),
            seq: 0,
            event_prng: event_seed,
            fixed_priority,
        }
    }

    /// Advance the event PRNG (xorshift32) and return the next value.
    fn next_prng(&mut self) -> u32 {
        let mut x = self.event_prng;
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        self.event_prng = x;
        x
    }

    /// Compute the `seq` tiebreaker for a new event.
    fn next_seq(&mut self) -> u64 {
        let s = self.seq;
        self.seq += 1;
        if self.fixed_priority {
            s
        } else {
            // Upper 32 bits: random priority; lower 32 bits: monotonic
            // counter for deterministic uniqueness.
            let random_priority = self.next_prng() as u64;
            (random_priority << 32) | (s & 0xFFFF_FFFF)
        }
    }

    /// Push a new event, automatically assigning a tiebreaker.
    fn push(&mut self, time_ns: TimeNs, kind: EventKind) {
        let seq = self.next_seq();
        self.heap.push(Reverse(Event { time_ns, seq, kind }));
    }

    /// Pop the next event (earliest timestamp, then lowest tiebreaker).
    fn pop(&mut self) -> Option<Event> {
        self.heap.pop().map(|Reverse(e)| e)
    }
}

/// Context about the task that triggered a wakeup.
///
/// In the kernel, `select_cpu` runs in the waker's context: both
/// `bpf_get_current_task_btf()` and `bpf_get_smp_processor_id()` return
/// the waker's state. The engine uses this to set up the same context.
#[derive(Debug, Clone, PartialEq, Eq)]
struct WakerInfo {
    pid: Pid,
    cpu: CpuId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum EventKind {
    /// A task becomes runnable (wakes up).
    /// `waker` identifies the task that triggered the wake (if any),
    /// enabling wake-affine scheduling (e.g., COSMOS mm_affinity).
    TaskWake { pid: Pid, waker: Option<WakerInfo> },
    /// A task's time slice expires on the given CPU.
    SliceExpired { cpu: CpuId },
    /// A task finishes its current Run phase on the given CPU.
    TaskPhaseComplete { cpu: CpuId },
    /// A BPF timer fires (e.g., deferred wakeup timer).
    TimerFired,
    /// Periodic scheduler tick on a CPU.
    Tick { cpu: CpuId },
}

/// The main simulator.
pub struct Simulator<S: Scheduler> {
    scheduler: S,
}

/// Result of a simulation, keeping task storage alive for post-simulation
/// probing of scheduler-internal state.
pub struct SimulationResult {
    /// The event trace.
    pub trace: Trace,
    /// Kept alive so raw task pointers remain valid until dropped.
    tasks: HashMap<Pid, SimTask>,
}

impl SimulationResult {
    /// Get the raw `task_struct` pointer for a task.
    ///
    /// Valid until this `SimulationResult` is dropped.
    pub fn task_raw(&self, pid: Pid) -> Option<*mut c_void> {
        self.tasks.get(&pid).map(|t| t.raw())
    }
}

/// A no-op monitor (zero overhead when no monitor is needed).
struct NoopMonitor;
impl Monitor for NoopMonitor {
    fn sample(&mut self, _ctx: &ProbeContext) {}
}

/// Reset and enable the RBC counter before an ops call.
fn start_rbc(state: &mut SimulatorState) {
    if let Some(ref rbc) = state.rbc_counter {
        state.rbc_kfunc_calls = 0;
        state.rbc_kfunc_ns = 0;
        let _ = rbc.reset();
        let _ = rbc.enable();
    }
}

/// Disable the RBC counter, read the count, and charge RBC-derived time to `cpu`.
fn charge_sched_time(state: &mut SimulatorState, cpu: CpuId, ops: &str) {
    if let Some(ref rbc) = state.rbc_counter {
        let _ = rbc.disable();
        let count = rbc.read().unwrap_or(0);
        if let Some(ns_per_rbc) = state.sched_overhead_rbc_ns {
            let rbc_ns = count * ns_per_rbc;
            let kfunc_ns = state.rbc_kfunc_ns;
            let total_ns = rbc_ns + kfunc_ns;
            state.cpus[cpu.0 as usize].local_clock += total_ns;
            trace!(
                ops,
                rbc = count,
                kfuncs = state.rbc_kfunc_calls,
                kfunc_ns,
                total_ns,
                "sched overhead"
            );
        }
    }
}

impl<S: Scheduler> Simulator<S> {
    pub fn new(scheduler: S) -> Self {
        Simulator { scheduler }
    }

    /// Run a scenario and return the trace.
    pub fn run(&self, scenario: Scenario) -> Trace {
        let result = self.run_internal(scenario, &mut NoopMonitor);
        result.trace
    }

    /// Run a scenario with a monitor, returning the full result.
    ///
    /// The monitor is called at each scheduling event (Running, Stopping,
    /// Quiescent, Dispatched) with a [`ProbeContext`] that includes the
    /// raw task pointer for scheduler-internal inspection.
    pub fn run_monitored(&self, scenario: Scenario, monitor: &mut dyn Monitor) -> SimulationResult {
        self.run_internal(scenario, monitor)
    }

    /// Internal simulation loop shared by `run()` and `run_monitored()`.
    fn run_internal(&self, scenario: Scenario, monitor: &mut dyn Monitor) -> SimulationResult {
        let nr_cpus = scenario.nr_cpus;
        let smt = scenario.smt_threads_per_core;

        // Build CPUs with SMT sibling groups
        let mut cpus: Vec<SimCpu> = (0..nr_cpus).map(|i| SimCpu::new(CpuId(i))).collect();
        if smt > 1 {
            for core_base in (0..nr_cpus).step_by(smt as usize) {
                let siblings: Vec<CpuId> = (core_base..core_base + smt).map(CpuId).collect();
                for &sib in &siblings {
                    cpus[sib.0 as usize].siblings = siblings.clone();
                }
            }
        }

        // Initialize all CPUs as idle in the C cpumasks
        for i in 0..nr_cpus {
            unsafe {
                ffi::scx_test_set_all_cpumask(i as i32);
                ffi::scx_test_set_idle_cpumask(i as i32);
                // All CPUs idle => all cores fully idle
                ffi::scx_test_set_idle_smtmask(i as i32);
            };
        }

        // Build tasks
        let mut tasks: HashMap<Pid, SimTask> = HashMap::new();
        let mut task_raw_to_pid: HashMap<usize, Pid> = HashMap::new();
        let mut task_pid_to_raw: HashMap<Pid, usize> = HashMap::new();

        // Allocate a synthetic idle task for bpf_get_current_task_btf() fallback.
        // In the kernel, there's always a task running (idle task on idle CPUs).
        // PF_IDLE = 0x2, mm = NULL (calloc-zeroed).
        let idle_task_raw = unsafe {
            let p = ffi::sim_task_alloc();
            ffi::sim_task_set_flags(p, 0x2); // PF_IDLE
            p
        };

        for def in &scenario.tasks {
            let task = SimTask::new(def, nr_cpus);
            let raw_addr = task.raw() as usize;
            task_raw_to_pid.insert(raw_addr, task.pid);
            task_pid_to_raw.insert(task.pid, raw_addr);
            // Set up cpus_ptr — restricted to allowed_cpus if specified
            unsafe {
                ffi::sim_task_setup_cpus_ptr(task.raw());
                if let Some(ref cpus) = def.allowed_cpus {
                    ffi::sim_task_clear_cpumask(task.raw());
                    for cpu in cpus {
                        ffi::sim_task_set_cpumask_cpu(task.raw(), cpu.0 as i32);
                    }
                    ffi::sim_task_set_nr_cpus_allowed(task.raw(), cpus.len() as i32);
                }
            }
            // Set mm pointer for address-space grouping (wake-affine scheduling)
            if let Some(mm_id) = def.mm_id {
                // Synthetic non-NULL pointer: never dereferenced, only compared.
                // Each unique MmId maps to a distinct non-NULL value.
                let mm_ptr = ((mm_id.0 as usize) + 1) * 0x1000;
                unsafe { ffi::sim_task_set_mm(task.raw(), mm_ptr as *mut c_void) };
            }
            tasks.insert(task.pid, task);
        }

        // Build simulator state (shared with kfuncs via thread-local)
        let rbc_ns = scenario.sched_overhead_rbc_ns.filter(|&ns| ns > 0);
        let rbc_counter = if rbc_ns.is_some() {
            perf::try_create_rbc_counter()
        } else {
            None
        };

        let mut state = SimulatorState {
            cpus,
            dsqs: DsqManager::new(),
            current_cpu: CpuId(0),
            trace: Trace::new(scenario.nr_cpus, &scenario.tasks),
            clock: 0,
            task_raw_to_pid,
            task_pid_to_raw,
            prng_state: scenario.seed,
            ops_context: OpsContext::None,
            pending_dispatch: None,
            dsq_iter: None,
            kicked_cpus: HashMap::new(),
            task_last_cpu: HashMap::new(),
            task_ops_state: HashMap::new(),
            reenqueue_local_requested: false,
            pending_timer_ns: None,
            waker_task_raw: None,
            idle_task_raw,
            noise: scenario.noise.clone(),
            overhead: scenario.overhead.clone(),
            rbc_counter,
            sched_overhead_rbc_ns: rbc_ns,
            rbc_kfunc_calls: 0,
            rbc_kfunc_ns: 0,
        };

        // Set CPU ID width for log formatting
        kfuncs::set_sim_cpu_width(nr_cpus);

        // Initialize scheduler
        unsafe {
            let cpu = state.current_cpu;
            kfuncs::enter_sim(&mut state, cpu);
            start_rbc(&mut state);
            let rc = self.scheduler.init();
            charge_sched_time(&mut state, CpuId(0), "init");
            kfuncs::exit_sim();
            assert!(rc == 0, "scheduler init failed with rc={rc}");
        }

        // Call init_task for each task (after scheduler init)
        unsafe {
            let cpu = state.current_cpu;
            kfuncs::enter_sim(&mut state, cpu);
            for task in tasks.values() {
                start_rbc(&mut state);
                let rc = self.scheduler.init_task(task.raw());
                charge_sched_time(&mut state, CpuId(0), "init_task");
                assert!(rc == 0, "init_task failed for pid={} rc={rc}", task.pid.0);
                // Notify scheduler of initial cpumask (mirrors kernel enumeration)
                let cpus_ptr = ffi::sim_task_get_cpus_ptr(task.raw());
                start_rbc(&mut state);
                self.scheduler.set_cpumask(task.raw(), cpus_ptr);
                charge_sched_time(&mut state, CpuId(0), "set_cpumask");
            }
            kfuncs::exit_sim();
        }

        // Build event queue
        let mut events = EventQueue::new(scenario.seed, scenario.fixed_priority);

        // Drain any pending timer from scheduler init (e.g., deferred wakeup timer)
        if let Some(fire_at) = state.pending_timer_ns.take() {
            events.push(fire_at, EventKind::TimerFired);
        }

        // Schedule initial TaskWake events for all tasks
        for def in &scenario.tasks {
            events.push(
                def.start_time_ns,
                EventKind::TaskWake {
                    pid: def.pid,
                    waker: None,
                },
            );
        }

        // Seed per-CPU tick streams. Each CPU gets a single perpetual tick
        // chain: tick fires → handle_tick → schedule next tick. This matches
        // the kernel's periodic timer interrupt (HZ=250 → 4ms).
        for cpu_id in 0..nr_cpus {
            events.push(TICK_INTERVAL_NS, EventKind::Tick { cpu: CpuId(cpu_id) });
        }

        // Main event loop
        while let Some(event) = events.pop() {
            if event.time_ns > scenario.duration_ns {
                break;
            }

            state.clock = event.time_ns;

            // Advance per-CPU clock for CPU-specific events
            match &event.kind {
                EventKind::SliceExpired { cpu }
                | EventKind::TaskPhaseComplete { cpu }
                | EventKind::Tick { cpu } => {
                    state.advance_cpu_clock(*cpu);
                    kfuncs::set_sim_clock(state.cpus[cpu.0 as usize].local_clock, Some(*cpu));
                }
                EventKind::TaskWake { .. } | EventKind::TimerFired => {
                    // No specific CPU yet; use event queue time for tracing
                    kfuncs::set_sim_clock(state.clock, None);
                }
            }

            match event.kind {
                EventKind::TaskWake { pid, waker } => {
                    self.handle_task_wake(pid, waker, &mut state, &mut tasks, &mut events, monitor);
                }
                EventKind::SliceExpired { cpu } => {
                    self.handle_slice_expired(cpu, &mut state, &mut tasks, &mut events, monitor);
                }
                EventKind::TaskPhaseComplete { cpu } => {
                    self.handle_task_phase_complete(
                        cpu,
                        &mut state,
                        &mut tasks,
                        &mut events,
                        scenario.duration_ns,
                        monitor,
                    );
                }
                EventKind::TimerFired => {
                    self.handle_timer_fired(&mut state, &mut tasks, &mut events, monitor);
                }
                EventKind::Tick { cpu } => {
                    self.handle_tick(cpu, &mut state, &mut tasks, &mut events, monitor);
                }
            }
        }

        // Flush running tasks: emit SimulationEnd for any task still on-CPU
        // so that total_runtime() can close its open interval. We use
        // duration_ns as the end time because the simulation conceptually
        // ends at the configured boundary regardless of per-CPU clock drift.
        for cpu_idx in 0..state.cpus.len() {
            if let Some(pid) = state.cpus[cpu_idx].current_task {
                state.trace.record(
                    scenario.duration_ns,
                    CpuId(cpu_idx as u32),
                    TraceKind::SimulationEnd { pid },
                );
            }
        }

        // Call scheduler dump before exit (mirrors kernel dump on scheduler unload)
        unsafe {
            let cpu = state.current_cpu;
            kfuncs::enter_sim(&mut state, cpu);
            start_rbc(&mut state);
            self.scheduler.dump(std::ptr::null_mut());
            charge_sched_time(&mut state, CpuId(0), "dump");

            for task in tasks.values() {
                start_rbc(&mut state);
                self.scheduler.dump_task(std::ptr::null_mut(), task.raw());
                charge_sched_time(&mut state, CpuId(0), "dump_task");
            }
            kfuncs::exit_sim();
        }

        // Call scheduler exit
        unsafe {
            let cpu = state.current_cpu;
            kfuncs::enter_sim(&mut state, cpu);
            start_rbc(&mut state);
            self.scheduler.exit();
            charge_sched_time(&mut state, CpuId(0), "exit");
            kfuncs::exit_sim();
        }

        // Free the synthetic idle task
        unsafe { ffi::sim_task_free(idle_task_raw) };

        SimulationResult {
            trace: state.trace,
            tasks,
        }
    }

    /// Handle a BPF timer firing.
    ///
    /// Calls the scheduler's `fire_timer()` callback, which invokes the
    /// stored BPF timer callback (e.g., `wakeup_timerfn` in COSMOS).
    /// The callback may kick CPUs and re-arm the timer via `bpf_timer_start`.
    fn handle_timer_fired(
        &self,
        state: &mut SimulatorState,
        tasks: &mut HashMap<Pid, SimTask>,
        events: &mut EventQueue,
        monitor: &mut dyn Monitor,
    ) {
        unsafe {
            let cpu = state.current_cpu;
            kfuncs::enter_sim(state, cpu);
            start_rbc(state);
            self.scheduler.fire_timer();
            charge_sched_time(state, CpuId(0), "fire_timer");
            kfuncs::exit_sim();
        }

        // Drain re-armed timer
        if let Some(fire_at) = state.pending_timer_ns.take() {
            events.push(fire_at, EventKind::TimerFired);
        }

        // Process CPUs kicked by the timer callback
        self.process_kicked_cpus(None, state, tasks, events, monitor);
    }

    /// Handle a periodic scheduler tick on a CPU.
    ///
    /// Ticks are per-CPU periodic timer interrupts, independent of which task
    /// is running. Each tick unconditionally schedules the next tick at
    /// `now + TICK_INTERVAL_NS`, maintaining a single perpetual chain per CPU.
    ///
    /// If a task is running, calls `ops.tick(p)` and detects self-preemption
    /// via two patterns:
    /// 1. Scheduler called `scx_bpf_kick_cpu(cpu, SCX_KICK_PREEMPT)` on self
    /// 2. Scheduler zeroed `p->scx.slice` (slice changed to 0 during tick)
    fn handle_tick(
        &self,
        cpu: CpuId,
        state: &mut SimulatorState,
        tasks: &mut HashMap<Pid, SimTask>,
        events: &mut EventQueue,
        monitor: &mut dyn Monitor,
    ) {
        // Always schedule the next tick — ticks are unconditional per-CPU timers
        let jitter = state.tick_jitter();
        let interval = (TICK_INTERVAL_NS as i64 + jitter).max(1) as TimeNs;
        let next_tick = state.cpus[cpu.0 as usize].local_clock + interval;
        events.push(next_tick, EventKind::Tick { cpu });

        let pid = match state.cpus[cpu.0 as usize].current_task {
            Some(pid) => pid,
            None => return, // No task running — nothing to tick
        };

        let raw = match tasks.get(&pid) {
            Some(task) => task.raw(),
            None => return,
        };

        // Record tick in trace
        state.trace.record(
            state.cpus[cpu.0 as usize].local_clock,
            cpu,
            TraceKind::Tick { pid },
        );

        // Save pre-tick slice to detect if scheduler zeroed it
        let pre_tick_slice = unsafe { ffi::sim_task_get_slice(raw) };

        unsafe {
            kfuncs::enter_sim(state, cpu);
            start_rbc(state);
            debug!(pid = pid.0, "tick");
            self.scheduler.tick(raw);
            charge_sched_time(state, cpu, "tick");
            kfuncs::exit_sim();
        }

        // Check for self-preemption
        let self_kick_preempt = state
            .kicked_cpus
            .get(&cpu)
            .is_some_and(|flags| flags.contains(KickFlags::PREEMPT));
        let post_tick_slice = unsafe { ffi::sim_task_get_slice(raw) };
        let slice_zeroed = pre_tick_slice > 0 && post_tick_slice == 0;
        let should_preempt = self_kick_preempt || slice_zeroed;

        // Remove self from kicked set before processing others
        state.kicked_cpus.remove(&cpu);

        // Process other kicked CPUs
        self.process_kicked_cpus(Some(cpu), state, tasks, events, monitor);

        if should_preempt && state.cpus[cpu.0 as usize].current_task.is_some() {
            self.preempt_current(cpu, state, tasks, events, monitor);
        }
    }

    /// Handle a task waking up.
    ///
    /// If `waker` is provided (from a `Phase::Wake`), the waker's context is
    /// set so that `bpf_get_current_task_btf()` and `bpf_get_smp_processor_id()`
    /// return the waker's state during `select_cpu` (kernel semantics).
    fn handle_task_wake(
        &self,
        pid: Pid,
        waker: Option<WakerInfo>,
        state: &mut SimulatorState,
        tasks: &mut HashMap<Pid, SimTask>,
        events: &mut EventQueue,
        monitor: &mut dyn Monitor,
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
        self.advance_to_run_phase(task, state, events);

        if matches!(task.state, TaskState::Exited | TaskState::Sleeping) {
            return;
        }

        // Set waker context: in the kernel, runnable/select_cpu/enqueue all
        // run in the waker's context, so bpf_get_current_task_btf() and
        // bpf_get_smp_processor_id() return the waker's state.
        let waker_raw = waker
            .as_ref()
            .and_then(|w| state.task_pid_to_raw.get(&w.pid).copied());

        // CPU where the wakeup originates (waker's CPU or prev_cpu as fallback)
        let prev_cpu = task.prev_cpu;
        let wake_cpu = waker.as_ref().map_or(prev_cpu, |w| w.cpu);

        state
            .trace
            .record(state.clock, wake_cpu, TraceKind::TaskWoke { pid });

        // Call runnable callback
        let raw = task.raw();
        unsafe {
            kfuncs::enter_sim(state, wake_cpu);
            state.waker_task_raw = waker_raw;
            start_rbc(state);
            debug!(pid = pid.0, "runnable");
            self.scheduler.runnable(raw, SCX_ENQ_WAKEUP);
            charge_sched_time(state, wake_cpu, "runnable");
            kfuncs::exit_sim();
        }

        // Call select_cpu
        // Set ops_state to Queued before select_cpu — kernel sets QUEUED in
        // do_enqueue_task before either select_cpu or enqueue.
        state.task_ops_state.insert(pid, OpsTaskState::Queued);

        unsafe {
            kfuncs::enter_sim(state, wake_cpu);
            state.pending_dispatch = None;
            state.ops_context = OpsContext::SelectCpu;
            state.waker_task_raw = waker_raw;
            start_rbc(state);

            let selected_cpu_raw =
                self.scheduler
                    .select_cpu(raw, prev_cpu.0 as i32, SCX_ENQ_WAKEUP);
            let selected_cpu = CpuId(selected_cpu_raw as u32);
            charge_sched_time(state, selected_cpu, "select_cpu");
            state.ops_context = OpsContext::None;
            state.waker_task_raw = None;
            state.current_cpu = selected_cpu;
            kfuncs::set_sim_clock(
                state.cpus[selected_cpu.0 as usize].local_clock,
                Some(selected_cpu),
            );
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

            state.trace.record(
                state.clock,
                wake_cpu,
                TraceKind::SelectTaskRq {
                    pid,
                    prev_cpu,
                    selected_cpu,
                },
            );

            let task = tasks.get_mut(&pid).unwrap();
            task.prev_cpu = selected_cpu;

            if let Some(dd_cpu) = direct_dispatched {
                // Task was directly dispatched — skip enqueue (kernel semantics)
                state.current_cpu = dd_cpu;
                kfuncs::set_sim_clock(state.cpus[dd_cpu.0 as usize].local_clock, Some(dd_cpu));
                debug!(pid = pid.0, target_cpu = dd_cpu.0, "direct dispatch");
                self.try_dispatch_and_run(dd_cpu, state, tasks, events, monitor);
            } else {
                // Task was not directly dispatched; call enqueue
                kfuncs::enter_sim(state, selected_cpu);
                state.ops_context = OpsContext::Enqueue;
                start_rbc(state);
                debug!(pid = pid.0, enq_flags = SCX_ENQ_WAKEUP, "enqueue");
                self.scheduler.enqueue(raw, SCX_ENQ_WAKEUP);
                charge_sched_time(state, selected_cpu, "enqueue");
                state.ops_context = OpsContext::None;
                // Resolve any deferred dispatch from enqueue
                // (SCX_DSQ_LOCAL resolves to the task's assigned CPU)
                state.resolve_pending_dispatch(selected_cpu);
                kfuncs::exit_sim();

                state.trace.record(
                    state.clock,
                    selected_cpu,
                    TraceKind::EnqueueTask {
                        pid,
                        enq_flags: SCX_ENQ_WAKEUP,
                    },
                );

                // Try to dispatch on idle CPUs
                let idle_cpus: Vec<CpuId> = state
                    .cpus
                    .iter()
                    .filter(|c| c.is_idle())
                    .map(|c| c.id)
                    .collect();

                for cpu in idle_cpus {
                    self.try_dispatch_and_run(cpu, state, tasks, events, monitor);
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
        events: &mut EventQueue,
        monitor: &mut dyn Monitor,
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

        let task_name = task.name.as_str();
        info!(
            task = task_name,
            pid = pid.0,
            ran_ns = %FmtN(slice),
            "PREEMPTED"
        );

        // Stop the task - entire slice was consumed
        let raw = task.raw();
        task.state = TaskState::Runnable;

        state.cpus[cpu.0 as usize].current_task = None;
        state.cpus[cpu.0 as usize].prev_task = Some(pid);
        state.cpus[cpu.0 as usize].task_started_at = None;
        state.cpus[cpu.0 as usize].task_original_slice = None;

        // Apply CSW overhead directly to local_clock (see #NOTE TIMING_MODEL)
        let overhead = state.csw_overhead(LastStopReason::Involuntary);
        state.cpus[cpu.0 as usize].local_clock += overhead;

        // Set slice to 0: the full slice was consumed (used by stopping() for vtime)
        unsafe { crate::ffi::sim_task_set_slice(raw, 0) };

        unsafe {
            kfuncs::enter_sim(state, cpu);
            start_rbc(state);
            debug!(pid = pid.0, runnable = true, "stopping");
            self.scheduler.stopping(raw, true); // true = still runnable
            charge_sched_time(state, cpu, "stopping");
            kfuncs::exit_sim();
        }

        // Monitor: Stopping probe
        monitor.sample(&ProbeContext {
            point: ProbePoint::Stopping,
            pid,
            cpu,
            time_ns: state.cpus[cpu.0 as usize].local_clock,
            task_raw: raw,
            trace: &state.trace,
        });

        unsafe {
            kfuncs::enter_sim(state, cpu);

            state.trace.record(
                state.cpus[cpu.0 as usize].local_clock,
                cpu,
                TraceKind::PutPrevTask {
                    pid,
                    still_runnable: true,
                },
            );

            // Re-enqueue the preempted task
            state.ops_context = OpsContext::Enqueue;
            state.task_ops_state.insert(pid, OpsTaskState::Queued);
            start_rbc(state);
            debug!(pid = pid.0, "enqueue (re-enqueue)");
            self.scheduler.enqueue(raw, 0);
            charge_sched_time(state, cpu, "enqueue");
            state.ops_context = OpsContext::None;
            state.resolve_pending_dispatch(cpu);
            kfuncs::exit_sim();

            state.trace.record(
                state.cpus[cpu.0 as usize].local_clock,
                cpu,
                TraceKind::EnqueueTask { pid, enq_flags: 0 },
            );
        }

        // High-level event: task is now fully off-CPU and re-enqueued
        state.trace.record(
            state.cpus[cpu.0 as usize].local_clock,
            cpu,
            TraceKind::TaskPreempted { pid },
        );

        // Process CPUs kicked during enqueue (e.g. SCX_DSQ_LOCAL_ON | cpu)
        self.process_kicked_cpus(Some(cpu), state, tasks, events, monitor);

        // Dispatch next task on this CPU
        self.try_dispatch_and_run(cpu, state, tasks, events, monitor);
    }

    /// Handle a task completing its current Run phase.
    fn handle_task_phase_complete(
        &self,
        cpu: CpuId,
        state: &mut SimulatorState,
        tasks: &mut HashMap<Pid, SimTask>,
        events: &mut EventQueue,
        duration_ns: TimeNs,
        monitor: &mut dyn Monitor,
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

        // Determine stop reason: Run→Run is a voluntary yield, Sleep/Wake/Complete are voluntary
        let stop_reason = LastStopReason::Voluntary;

        state.cpus[cpu.0 as usize].current_task = None;
        state.cpus[cpu.0 as usize].prev_task = Some(pid);
        state.cpus[cpu.0 as usize].task_started_at = None;
        state.cpus[cpu.0 as usize].task_original_slice = None;

        // Apply CSW overhead directly to local_clock (see #NOTE TIMING_MODEL)
        let overhead = state.csw_overhead(stop_reason);
        state.cpus[cpu.0 as usize].local_clock += overhead;

        // Set slice to reflect consumed time (used by stopping() for vtime)
        let remaining_slice = original_slice.saturating_sub(time_consumed);
        unsafe { crate::ffi::sim_task_set_slice(raw, remaining_slice) };

        unsafe {
            kfuncs::enter_sim(state, cpu);
            start_rbc(state);
            debug!(pid = pid.0, still_runnable, "stopping");
            self.scheduler.stopping(raw, still_runnable);
            charge_sched_time(state, cpu, "stopping");
            kfuncs::exit_sim();
        }

        // Monitor: Stopping probe
        monitor.sample(&ProbeContext {
            point: ProbePoint::Stopping,
            pid,
            cpu,
            time_ns: state.cpus[cpu.0 as usize].local_clock,
            task_raw: raw,
            trace: &state.trace,
        });

        if !still_runnable {
            unsafe {
                kfuncs::enter_sim(state, cpu);
                let ops_state = state.task_ops_state.get(&pid).copied().unwrap_or_default();
                if ops_state == OpsTaskState::Queued {
                    start_rbc(state);
                    debug!(pid = pid.0, "dequeue");
                    self.scheduler.dequeue(raw, SCX_DEQ_SLEEP);
                    charge_sched_time(state, cpu, "dequeue");
                    state.task_ops_state.insert(pid, OpsTaskState::None);
                }
                start_rbc(state);
                debug!(pid = pid.0, "quiescent");
                self.scheduler.quiescent(raw, SCX_DEQ_SLEEP);
                charge_sched_time(state, cpu, "quiescent");
                kfuncs::exit_sim();
            }

            // Monitor: Quiescent probe
            monitor.sample(&ProbeContext {
                point: ProbePoint::Quiescent,
                pid,
                cpu,
                time_ns: state.cpus[cpu.0 as usize].local_clock,
                task_raw: raw,
                trace: &state.trace,
            });
        }

        state.trace.record(
            state.cpus[cpu.0 as usize].local_clock,
            cpu,
            TraceKind::PutPrevTask {
                pid,
                still_runnable,
            },
        );

        if !has_next {
            // Task has completed all phases
            let task = tasks.get_mut(&pid).unwrap();
            task.state = TaskState::Exited;
            state.trace.record(
                state.cpus[cpu.0 as usize].local_clock,
                cpu,
                TraceKind::TaskCompleted { pid },
            );
            info!(task = task.name.as_str(), pid = pid.0, "COMPLETED");
        } else {
            match next_phase {
                Some(Phase::Sleep(sleep_ns)) => {
                    let task = tasks.get_mut(&pid).unwrap();
                    task.state = TaskState::Sleeping;
                    let local_t = state.cpus[cpu.0 as usize].local_clock;
                    state
                        .trace
                        .record(local_t, cpu, TraceKind::TaskSlept { pid });
                    info!(task = task.name.as_str(), pid = pid.0, "SLEEPING");

                    // Schedule wake event
                    let wake_time = local_t.saturating_add(sleep_ns);
                    if wake_time <= duration_ns {
                        events.push(wake_time, EventKind::TaskWake { pid, waker: None });
                    }
                }
                Some(Phase::Run(_)) => {
                    // Task goes directly to the next Run phase (still runnable)
                    let task = tasks.get_mut(&pid).unwrap();
                    task.state = TaskState::Runnable;

                    // Re-enqueue (part of put_prev_task for runnable tasks)
                    let raw = task.raw();
                    unsafe {
                        kfuncs::enter_sim(state, cpu);
                        state.ops_context = OpsContext::Enqueue;
                        start_rbc(state);
                        debug!(pid = pid.0, "enqueue (yield re-enqueue)");
                        state.task_ops_state.insert(pid, OpsTaskState::Queued);
                        self.scheduler.enqueue(raw, 0);
                        charge_sched_time(state, cpu, "enqueue");
                        state.ops_context = OpsContext::None;
                        state.resolve_pending_dispatch(cpu);
                        kfuncs::exit_sim();
                    }

                    state.trace.record(
                        state.cpus[cpu.0 as usize].local_clock,
                        cpu,
                        TraceKind::EnqueueTask { pid, enq_flags: 0 },
                    );

                    // High-level event: task is now fully off-CPU and re-enqueued
                    state.trace.record(
                        state.cpus[cpu.0 as usize].local_clock,
                        cpu,
                        TraceKind::TaskYielded { pid },
                    );
                    info!(task = task.name.as_str(), pid = pid.0, "YIELDED");
                }
                Some(Phase::Wake(target_pid)) => {
                    let local_t = state.cpus[cpu.0 as usize].local_clock;

                    // Queue the wake for the target task (with waker context)
                    events.push(
                        local_t,
                        EventKind::TaskWake {
                            pid: target_pid,
                            waker: Some(WakerInfo { pid, cpu }),
                        },
                    );

                    // Phase::Wake is instantaneous — advance to the next phase
                    // and handle it inline. The waker does NOT sleep during a wake.
                    let task = tasks.get_mut(&pid).unwrap();
                    if !task.advance_phase() {
                        task.state = TaskState::Exited;
                        state
                            .trace
                            .record(local_t, cpu, TraceKind::TaskCompleted { pid });
                    } else {
                        // Process chained Wake phases (e.g. wake A, wake B, run)
                        loop {
                            match task.current_phase() {
                                Some(Phase::Wake(next_target)) => {
                                    let next_target = *next_target;
                                    events.push(
                                        local_t,
                                        EventKind::TaskWake {
                                            pid: next_target,
                                            waker: Some(WakerInfo { pid, cpu }),
                                        },
                                    );
                                    if !task.advance_phase() {
                                        task.state = TaskState::Exited;
                                        state.trace.record(
                                            local_t,
                                            cpu,
                                            TraceKind::TaskCompleted { pid },
                                        );
                                        break;
                                    }
                                }
                                Some(Phase::Run(_)) => {
                                    // Still runnable — re-enqueue (same as yield)
                                    task.state = TaskState::Runnable;
                                    let raw = task.raw();
                                    unsafe {
                                        kfuncs::enter_sim(state, cpu);
                                        state.ops_context = OpsContext::Enqueue;
                                        start_rbc(state);
                                        state.task_ops_state.insert(pid, OpsTaskState::Queued);
                                        self.scheduler.enqueue(raw, 0);
                                        charge_sched_time(state, cpu, "enqueue");
                                        state.ops_context = OpsContext::None;
                                        state.resolve_pending_dispatch(cpu);
                                        kfuncs::exit_sim();
                                    }
                                    state.trace.record(
                                        state.cpus[cpu.0 as usize].local_clock,
                                        cpu,
                                        TraceKind::EnqueueTask { pid, enq_flags: 0 },
                                    );
                                    state.trace.record(
                                        state.cpus[cpu.0 as usize].local_clock,
                                        cpu,
                                        TraceKind::TaskYielded { pid },
                                    );
                                    info!(
                                        task = task.name.as_str(),
                                        pid = pid.0,
                                        "YIELDED (after wake)"
                                    );
                                    break;
                                }
                                Some(Phase::Sleep(ns)) => {
                                    let ns = *ns;
                                    task.state = TaskState::Sleeping;
                                    state
                                        .trace
                                        .record(local_t, cpu, TraceKind::TaskSlept { pid });
                                    info!(
                                        task = task.name.as_str(),
                                        pid = pid.0,
                                        "SLEEPING (after wake)"
                                    );
                                    let wake_time = local_t.saturating_add(ns);
                                    if wake_time <= duration_ns {
                                        events.push(
                                            wake_time,
                                            EventKind::TaskWake { pid, waker: None },
                                        );
                                    }
                                    break;
                                }
                                None => {
                                    task.state = TaskState::Exited;
                                    state.trace.record(
                                        local_t,
                                        cpu,
                                        TraceKind::TaskCompleted { pid },
                                    );
                                    break;
                                }
                            }
                        }
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

        // Process CPUs kicked during enqueue (e.g. SCX_DSQ_LOCAL_ON | cpu)
        self.process_kicked_cpus(Some(cpu), state, tasks, events, monitor);

        // Dispatch next task on this CPU
        self.try_dispatch_and_run(cpu, state, tasks, events, monitor);
    }

    /// Try to dispatch and run a task on the given CPU.
    fn try_dispatch_and_run(
        &self,
        cpu: CpuId,
        state: &mut SimulatorState,
        tasks: &mut HashMap<Pid, SimTask>,
        events: &mut EventQueue,
        monitor: &mut dyn Monitor,
    ) {
        // If CPU is already running something, nothing to do
        if state.cpus[cpu.0 as usize].current_task.is_some() {
            return;
        }

        // Advance this CPU's clock to at least the event queue time
        state.advance_cpu_clock(cpu);

        // Check if local DSQ has tasks
        if state.cpus[cpu.0 as usize].local_dsq.is_empty() {
            // Look up the previously-running task's raw pointer for dispatch
            let prev_pid = state.cpus[cpu.0 as usize].prev_task;
            let prev_raw = prev_pid
                .and_then(|pid| state.task_pid_to_raw.get(&pid).copied())
                .map_or(std::ptr::null_mut(), |raw| raw as *mut c_void);

            // Call scheduler dispatch to try to fill the local DSQ
            unsafe {
                kfuncs::enter_sim(state, cpu);
                state.ops_context = OpsContext::Dispatch;
                state.kicked_cpus.clear();
                start_rbc(state);
                debug!("dispatch");
                self.scheduler.dispatch(cpu.0 as i32, prev_raw);
                charge_sched_time(state, cpu, "dispatch");
                state.ops_context = OpsContext::None;
                // Flush any deferred dispatch from dispatch() callback
                // (SCX_DSQ_LOCAL resolves to the dispatching CPU)
                state.resolve_pending_dispatch(cpu);
                kfuncs::exit_sim();
            }

            state.trace.record(
                state.cpus[cpu.0 as usize].local_clock,
                cpu,
                TraceKind::Balance { prev_pid },
            );

            // Monitor: Dispatched probe (after ops.dispatch() completed)
            if let Some(ppid) = prev_pid {
                if let Some(task) = tasks.get(&ppid) {
                    monitor.sample(&ProbeContext {
                        point: ProbePoint::Dispatched,
                        pid: ppid,
                        cpu,
                        time_ns: state.cpus[cpu.0 as usize].local_clock,
                        task_raw: task.raw(),
                        trace: &state.trace,
                    });
                }
            }

            // Process CPUs kicked during dispatch().
            // The scheduler may have dispatched tasks to other CPUs'
            // local DSQs via scx_bpf_dsq_move(SCX_DSQ_LOCAL_ON | cpu).
            self.process_kicked_cpus(Some(cpu), state, tasks, events, monitor);
        }

        // Kernel fallback: if local DSQ is still empty after dispatch(),
        // automatically consume from the global DSQ (SCX_DSQ_GLOBAL).
        // This matches pick_next_task_scx() which tries the global DSQ
        // before going idle.
        if state.cpus[cpu.0 as usize].local_dsq.is_empty() {
            let cpu_idx = cpu.0 as usize;
            let cpus_ptr = state.cpus.as_mut_ptr();
            let sim_cpu = unsafe { &mut *cpus_ptr.add(cpu_idx) };
            let consumed = state.dsqs.move_to_local(DsqId::GLOBAL, sim_cpu);
            if consumed {
                state.trace.record(
                    state.cpus[cpu_idx].local_clock,
                    cpu,
                    TraceKind::DsqMoveToLocal {
                        dsq_id: DsqId::GLOBAL,
                        success: true,
                    },
                );
            }
        }

        // Try to pull a task from the local DSQ
        if let Some(pid) = state.cpus[cpu.0 as usize].local_dsq.pop_front() {
            state.trace.record(
                state.cpus[cpu.0 as usize].local_clock,
                cpu,
                TraceKind::PickTask { pid },
            );
            self.start_running(cpu, pid, state, tasks, events, monitor);
        } else {
            // CPU is idle — update the C idle cpumask so
            // scx_bpf_test_and_clear_cpu_idle works correctly
            unsafe { ffi::scx_test_set_idle_cpumask(cpu.0 as i32) };
            // Check if all siblings are idle too (full-idle core)
            state.update_smt_mask_idle(cpu);
            let local_t = state.cpus[cpu.0 as usize].local_clock;
            kfuncs::set_sim_clock(local_t, Some(cpu));
            state.trace.record(local_t, cpu, TraceKind::CpuIdle);
            info!("IDLE");
        }
    }

    /// Process CPUs kicked via `scx_bpf_kick_cpu` during a callback.
    ///
    /// Drains the kicked_cpus map and handles each entry based on its flags:
    /// - `PREEMPT` + task running → `preempt_current(cpu)`
    /// - `IDLE` → only dispatch if CPU is idle
    /// - Plain kick → `try_dispatch_and_run(cpu)`
    ///
    /// `exclude_cpu` is skipped (caller handles it separately, e.g. tick's own CPU).
    fn process_kicked_cpus(
        &self,
        exclude_cpu: Option<CpuId>,
        state: &mut SimulatorState,
        tasks: &mut HashMap<Pid, SimTask>,
        events: &mut EventQueue,
        monitor: &mut dyn Monitor,
    ) {
        let kicked: Vec<(CpuId, KickFlags)> = state.kicked_cpus.drain().collect();
        for (kicked_cpu, flags) in kicked {
            if Some(kicked_cpu) == exclude_cpu {
                continue;
            }
            if flags.contains(KickFlags::PREEMPT)
                && state.cpus[kicked_cpu.0 as usize].current_task.is_some()
            {
                self.preempt_current(kicked_cpu, state, tasks, events, monitor);
            } else if flags.contains(KickFlags::IDLE) {
                if state.cpus[kicked_cpu.0 as usize].current_task.is_none() {
                    self.try_dispatch_and_run(kicked_cpu, state, tasks, events, monitor);
                }
            } else {
                self.try_dispatch_and_run(kicked_cpu, state, tasks, events, monitor);
            }
        }
    }

    /// Preempt the currently running task on `cpu` mid-slice.
    ///
    /// Computes how much of the slice was consumed, deducts it from
    /// `run_remaining_ns`, calls `stopping()` + `enqueue()`, then
    /// dispatches the next task via `try_dispatch_and_run()`.
    fn preempt_current(
        &self,
        cpu: CpuId,
        state: &mut SimulatorState,
        tasks: &mut HashMap<Pid, SimTask>,
        events: &mut EventQueue,
        monitor: &mut dyn Monitor,
    ) {
        let pid = match state.cpus[cpu.0 as usize].current_task {
            Some(pid) => pid,
            None => return,
        };

        let task = match tasks.get_mut(&pid) {
            Some(t) => t,
            None => return,
        };

        let local_clock = state.cpus[cpu.0 as usize].local_clock;
        let started_at = state.cpus[cpu.0 as usize]
            .task_started_at
            .unwrap_or(local_clock);
        let original_slice = state.cpus[cpu.0 as usize].task_original_slice.unwrap_or(0);
        let consumed = local_clock.saturating_sub(started_at);

        task.run_remaining_ns = task.run_remaining_ns.saturating_sub(consumed);

        state
            .trace
            .record(local_clock, cpu, TraceKind::TaskPreempted { pid });

        let task_name = task.name.as_str();
        info!(
            task = task_name,
            pid = pid.0,
            ran_ns = %FmtN(consumed),
            "PREEMPTED (tick)"
        );

        let raw = task.raw();
        task.state = TaskState::Runnable;

        state.cpus[cpu.0 as usize].current_task = None;
        state.cpus[cpu.0 as usize].prev_task = Some(pid);
        state.cpus[cpu.0 as usize].task_started_at = None;
        state.cpus[cpu.0 as usize].task_original_slice = None;

        // Apply CSW overhead directly to local_clock (see #NOTE TIMING_MODEL)
        let overhead = state.csw_overhead(LastStopReason::Involuntary);
        state.cpus[cpu.0 as usize].local_clock += overhead;

        // Set remaining slice on raw task (used by stopping() for vtime accounting)
        let remaining_slice = original_slice.saturating_sub(consumed);
        unsafe { crate::ffi::sim_task_set_slice(raw, remaining_slice) };

        unsafe {
            kfuncs::enter_sim(state, cpu);
            start_rbc(state);
            debug!(pid = pid.0, runnable = true, "stopping (tick preempt)");
            self.scheduler.stopping(raw, true);
            charge_sched_time(state, cpu, "stopping");
            kfuncs::exit_sim();
        }

        // Monitor: Stopping probe
        monitor.sample(&ProbeContext {
            point: ProbePoint::Stopping,
            pid,
            cpu,
            time_ns: state.cpus[cpu.0 as usize].local_clock,
            task_raw: raw,
            trace: &state.trace,
        });

        unsafe {
            kfuncs::enter_sim(state, cpu);
            state.ops_context = OpsContext::Enqueue;
            state.task_ops_state.insert(pid, OpsTaskState::Queued);
            start_rbc(state);
            debug!(pid = pid.0, "enqueue (re-enqueue after tick preempt)");
            self.scheduler.enqueue(raw, 0);
            charge_sched_time(state, cpu, "enqueue");
            state.ops_context = OpsContext::None;
            state.resolve_pending_dispatch(cpu);
            kfuncs::exit_sim();
        }

        // Process any CPUs kicked during stopping/enqueue
        self.process_kicked_cpus(Some(cpu), state, tasks, events, monitor);

        // Dispatch next task on this CPU (will also schedule a new tick)
        self.try_dispatch_and_run(cpu, state, tasks, events, monitor);
    }

    /// Start running a task on a CPU.
    fn start_running(
        &self,
        cpu: CpuId,
        pid: Pid,
        state: &mut SimulatorState,
        tasks: &mut HashMap<Pid, SimTask>,
        events: &mut EventQueue,
        monitor: &mut dyn Monitor,
    ) {
        let task = match tasks.get_mut(&pid) {
            Some(t) => t,
            None => return,
        };

        // Skip exited tasks that are still lingering in DSQs
        if matches!(task.state, TaskState::Exited) {
            self.try_dispatch_and_run(cpu, state, tasks, events, monitor);
            return;
        }

        task.state = TaskState::Running { cpu };
        task.prev_cpu = cpu;
        state.cpus[cpu.0 as usize].current_task = Some(pid);
        state.cpus[cpu.0 as usize].prev_task = None;
        state.task_last_cpu.insert(pid, cpu);
        // Clear idle bit in the C cpumask (in case scheduler didn't call
        // scx_bpf_test_and_clear_cpu_idle for this CPU)
        unsafe { ffi::scx_bpf_test_and_clear_cpu_idle(cpu.0 as i32) };
        // CPU is now busy — core is no longer fully idle
        state.update_smt_mask_busy(cpu);

        let raw = task.raw();

        // Call enable on first schedule
        if !task.enabled {
            task.enabled = true;
            unsafe {
                kfuncs::enter_sim(state, cpu);
                start_rbc(state);
                debug!(pid = pid.0, "enable");
                self.scheduler.enable(raw);
                charge_sched_time(state, cpu, "enable");
                kfuncs::exit_sim();
            }
        }

        // Call running
        unsafe {
            kfuncs::enter_sim(state, cpu);
            start_rbc(state);
            debug!(pid = pid.0, "running");
            self.scheduler.running(raw);
            charge_sched_time(state, cpu, "running");
            kfuncs::exit_sim();
        }

        // Monitor: Running probe
        monitor.sample(&ProbeContext {
            point: ProbePoint::Running,
            pid,
            cpu,
            time_ns: state.cpus[cpu.0 as usize].local_clock,
            task_raw: raw,
            trace: &state.trace,
        });

        state.trace.record(
            state.cpus[cpu.0 as usize].local_clock,
            cpu,
            TraceKind::SetNextTask { pid },
        );

        let local_t = state.cpus[cpu.0 as usize].local_clock;
        kfuncs::set_sim_clock(local_t, Some(cpu));

        state
            .trace
            .record(local_t, cpu, TraceKind::TaskScheduled { pid });

        // Determine how long this task will run
        let task = tasks.get(&pid).unwrap();
        let slice = task.get_slice();
        let remaining = task.run_remaining_ns;

        // Track when task started for mid-slice preemption accounting
        state.cpus[cpu.0 as usize].task_started_at = Some(local_t);
        state.cpus[cpu.0 as usize].task_original_slice = Some(slice);

        info!(
            task = task.name.as_str(),
            pid = pid.0,
            slice_ns = %FmtN(slice),
            "STARTED"
        );

        if remaining == 0 {
            // Task has no remaining work -- complete immediately
            events.push(local_t, EventKind::TaskPhaseComplete { cpu });
        } else if slice > 0 && slice <= remaining {
            // Slice expires before the phase completes
            events.push(local_t + slice, EventKind::SliceExpired { cpu });
        } else {
            // Phase completes before the slice
            events.push(local_t + remaining, EventKind::TaskPhaseComplete { cpu });
        }
    }

    /// Advance a task past any Wake phases to the next Run or Sleep phase.
    fn advance_to_run_phase(
        &self,
        task: &mut SimTask,
        state: &mut SimulatorState,
        events: &mut EventQueue,
    ) {
        loop {
            match task.current_phase() {
                Some(Phase::Run(_)) => break,
                Some(Phase::Wake(target_pid)) => {
                    let target = *target_pid;
                    events.push(
                        state.clock,
                        EventKind::TaskWake {
                            pid: target,
                            waker: None,
                        },
                    );
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
