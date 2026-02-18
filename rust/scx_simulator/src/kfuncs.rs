//! Kfunc implementations for the simulator.
//!
//! These are `#[no_mangle] extern "C"` functions that the compiled scheduler
//! C code calls. They access the simulator state via a thread-local pointer.
//!
//! The pattern is:
//! 1. Before calling any scheduler ops, the simulator installs a pointer
//!    to its state via `enter_sim()`.
//! 2. When the scheduler calls a kfunc, the kfunc accesses the simulator
//!    state via `with_sim()`.
//! 3. After the ops call returns, the simulator calls `exit_sim()`.

// These are extern "C" FFI entry points called from C code — the C caller
// is responsible for passing valid pointers, so marking them `unsafe` in Rust
// would be meaningless.
#![allow(clippy::not_unsafe_ptr_arg_deref)]

use std::cell::RefCell;
use std::collections::HashMap;
use std::ffi::c_void;
use std::ptr;

use tracing::debug;

use crate::cpu::{LastStopReason, SimCpu};
use crate::dsq::DsqManager;
use crate::ffi;
use crate::fmt::FmtN;
use crate::scenario::{NoiseConfig, OverheadConfig};
use crate::task::OpsTaskState;
use crate::trace::{Trace, TraceKind};
use crate::types::{CpuId, DsqId, KickFlags, Pid, TimeNs, Vtime};

/// Which scheduler callback is currently executing.
///
/// The kernel defers `scx_bpf_dsq_insert` — it never inserts immediately.
/// During `select_cpu`/`enqueue` the intent is recorded on the task and
/// executed after the callback returns. During `dispatch` inserts are
/// buffered and flushed after the callback. We track the context so
/// the engine can resolve `SCX_DSQ_LOCAL` correctly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpsContext {
    None,
    SelectCpu,
    Enqueue,
    Dispatch,
}

/// A deferred dispatch request recorded by `scx_bpf_dsq_insert[_vtime]`.
///
/// Mirrors the kernel's `p->scx.ddsp_dsq_id` / `ddsp_enq_flags` fields.
#[derive(Debug, Clone)]
pub struct PendingDispatch {
    pub pid: Pid,
    pub dsq_id: DsqId,
    pub enq_flags: u64,
    pub vtime: Option<Vtime>,
}

/// Active DSQ iterator state for `bpf_for_each(scx_dsq, ...)`.
///
/// Holds a snapshot of the DSQ contents at iteration start, plus the
/// current cursor position. This lets C loop code iterate a Rust-owned
/// DSQ via `sim_dsq_iter_begin` / `sim_dsq_iter_next` kfuncs.
#[derive(Debug)]
pub struct DsqIterState {
    pub dsq_id: DsqId,
    pub pids: Vec<Pid>,
    pub pos: usize,
}

/// The subset of simulator state that kfuncs need access to.
pub struct SimulatorState {
    pub cpus: Vec<SimCpu>,
    pub dsqs: DsqManager,
    pub current_cpu: CpuId,
    pub trace: Trace,
    pub clock: TimeNs,
    /// Maps raw task_struct pointers to PIDs for reverse lookup.
    pub task_raw_to_pid: HashMap<usize, Pid>,
    /// Maps PIDs to raw task_struct pointers (reverse of task_raw_to_pid).
    pub task_pid_to_raw: HashMap<Pid, usize>,
    /// Deterministic PRNG state (xorshift32).
    pub prng_state: u32,
    /// Which ops callback we are currently inside.
    pub ops_context: OpsContext,
    /// Deferred dispatch recorded during `select_cpu` or `enqueue`.
    /// The engine resolves `SCX_DSQ_LOCAL` and executes after the callback.
    pub pending_dispatch: Option<PendingDispatch>,
    /// Active DSQ iterator for `bpf_for_each(scx_dsq, ...)`.
    pub dsq_iter: Option<DsqIterState>,
    /// CPUs kicked via `scx_bpf_kick_cpu` during a callback.
    /// The engine processes these after the callback returns.
    pub kicked_cpus: HashMap<CpuId, KickFlags>,
    /// Per-task last CPU (set when a task starts running).
    /// Used by `scx_bpf_task_cpu` to return the correct value.
    pub task_last_cpu: HashMap<Pid, CpuId>,
    /// Per-task SCX ops_state (mirrors kernel's `SCX_OPSS_*`).
    /// Tracks whether the task is `Queued` (in the BPF scheduler) or `None`
    /// (dispatched / not queued). Used to gate `ops.dequeue()`.
    pub task_ops_state: HashMap<Pid, OpsTaskState>,
    /// Flag set by `scx_bpf_reenqueue_local` during `cpu_release`.
    /// The engine drains the local DSQ and re-enqueues tasks after the
    /// callback returns.
    pub reenqueue_local_requested: bool,
    /// Pending BPF timer: fire at this time (set by `sim_timer_start`).
    pub pending_timer_ns: Option<TimeNs>,
    /// Raw pointer to the waker task during a wake-induced `select_cpu` call.
    ///
    /// In the kernel, `select_cpu` runs in the waker's context, so
    /// `bpf_get_current_task_btf()` returns the waker's task_struct.
    /// The engine sets this when processing a `Phase::Wake`-induced event.
    pub waker_task_raw: Option<usize>,
    /// Raw pointer to a synthetic idle task_struct (PF_IDLE, mm=NULL).
    ///
    /// In the real kernel, `bpf_get_current_task_btf()` never returns NULL —
    /// the idle task is always running when no real task is. The engine
    /// allocates this once at startup so kfuncs can return it as a fallback.
    pub idle_task_raw: *mut c_void,
    /// Timing noise configuration (tick jitter).
    pub noise: NoiseConfig,
    /// Context switch overhead configuration.
    pub overhead: OverheadConfig,
}

impl SimulatorState {
    pub fn cpu_is_idle(&self, cpu: CpuId) -> bool {
        self.cpus
            .get(cpu.0 as usize)
            .is_some_and(|c| c.is_idle() && c.local_dsq.is_empty())
    }

    pub fn find_any_idle_cpu(&self) -> Option<CpuId> {
        self.cpus
            .iter()
            .find(|c| c.is_idle() && c.local_dsq.is_empty())
            .map(|c| c.id)
    }

    /// Update the idle SMT mask when a CPU transitions busy→idle.
    ///
    /// If all SMT siblings of `cpu` are idle, sets all of them in the
    /// idle SMT mask (the core is fully idle). Called by the engine when
    /// a CPU becomes idle.
    pub fn update_smt_mask_idle(&self, cpu: CpuId) {
        let siblings = &self.cpus[cpu.0 as usize].siblings;
        if siblings.is_empty() {
            return;
        }
        // Check if all siblings (including self) are idle
        let all_idle = siblings
            .iter()
            .all(|&sib| self.cpus[sib.0 as usize].is_idle());
        if all_idle {
            for &sib in siblings {
                unsafe { crate::ffi::scx_test_set_idle_smtmask(sib.0 as i32) };
            }
        }
    }

    /// Update the idle SMT mask when a CPU transitions idle→busy.
    ///
    /// Clears all SMT siblings from the idle SMT mask (the core is no
    /// longer fully idle). Called by the engine when a task starts
    /// running on a CPU.
    pub fn update_smt_mask_busy(&self, cpu: CpuId) {
        let siblings = &self.cpus[cpu.0 as usize].siblings;
        if siblings.is_empty() {
            return;
        }
        for &sib in siblings {
            unsafe { crate::ffi::scx_test_clear_idle_smtmask(sib.0 as i32) };
        }
    }

    pub fn task_pid_from_raw(&self, p: *mut c_void) -> Pid {
        *self
            .task_raw_to_pid
            .get(&(p as usize))
            .unwrap_or_else(|| panic!("unknown task_struct pointer {:?}", p))
    }

    /// Deterministic PRNG (xorshift32).
    pub fn next_prng(&mut self) -> u32 {
        let mut x = self.prng_state;
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        self.prng_state = x;
        x
    }

    /// Advance a CPU's local clock to at least the event queue time.
    ///
    /// # NOTE TIMING_MODEL
    ///
    /// This simulator is **not** cycle-accurate. Real CPU cores share a
    /// clock and run in lockstep, but our discrete-event loop jumps between
    /// unrelated concurrent events. Each CPU maintains a `local_clock` that
    /// tracks how far that CPU has progressed in simulated time.
    ///
    /// The essential correctness invariant: it is safe for CPU A's local
    /// clock to run ahead of CPU B's, **as long as the interval does not
    /// involve interaction between A and B**. When an event does require
    /// cross-CPU coordination (wake, kick, etc.), the event queue timestamp
    /// establishes a lower bound, and this function synchronizes:
    ///
    /// ```text
    /// local_clock = max(local_clock, event_queue_time)
    /// ```
    ///
    /// - If `local_clock > event_queue_time`: the CPU was busy and has
    ///   already advanced past the event. The local clock is preserved.
    ///   This is the common case for back-to-back task execution.
    ///
    /// - If `local_clock < event_queue_time`: the CPU was idle or behind.
    ///   We pull its clock forward to the event time. Any per-CPU overhead
    ///   (e.g. context switch cost) that was applied to `local_clock`
    ///   before the idle period is correctly absorbed — it represents real
    ///   time consumed on that CPU, which elapsed during the idle gap.
    ///
    /// Corollary: per-CPU timing adjustments (CSW overhead, tick jitter)
    /// should be applied directly to `local_clock` at the point they
    /// occur. They affect only subsequent events on that CPU and cannot
    /// influence other CPUs' clocks.
    pub fn advance_cpu_clock(&mut self, cpu: CpuId) {
        let idx = cpu.0 as usize;
        self.cpus[idx].local_clock = self.cpus[idx].local_clock.max(self.clock);
    }

    /// Sample approximately-normal noise using Irwin-Hall (sum of 4 uniforms).
    /// Returns a value centered around 0 with the given stddev.
    pub fn sample_normal_ns(&mut self, stddev: TimeNs) -> i64 {
        if stddev == 0 {
            return 0;
        }
        // Sum of 4 uniform [0,1000) values → mean=2000, σ ≈ 577 (in milli-units)
        let sum: u64 = (0..4).map(|_| (self.next_prng() as u64) % 1000).sum();
        let centered = sum as i64 - 2000;
        // Scale: centered/577 * stddev
        (centered * stddev as i64) / 577
    }

    /// Compute tick jitter (added to next tick interval).
    pub fn tick_jitter(&mut self) -> i64 {
        if !self.noise.enabled || !self.noise.tick_jitter {
            return 0;
        }
        self.sample_normal_ns(self.noise.tick_jitter_stddev_ns)
    }

    /// Compute context switch overhead for the given stop reason.
    pub fn csw_overhead(&mut self, reason: LastStopReason) -> TimeNs {
        if !self.overhead.enabled {
            return 0;
        }
        let (enabled, base) = match reason {
            LastStopReason::Voluntary => {
                (self.overhead.voluntary_csw, self.overhead.voluntary_csw_ns)
            }
            LastStopReason::Involuntary => (
                self.overhead.involuntary_csw,
                self.overhead.involuntary_csw_ns,
            ),
        };
        if !enabled {
            return 0;
        }
        let jitter = if self.overhead.csw_jitter {
            self.sample_normal_ns(self.overhead.csw_jitter_stddev_ns)
        } else {
            0
        };
        // Clamp to [0, 2*base] to avoid negative overhead
        (base as i64 + jitter).clamp(0, 2 * base as i64) as TimeNs
    }

    /// Execute a pending deferred dispatch, resolving `SCX_DSQ_LOCAL` to
    /// the given `local_cpu`.
    ///
    /// This mirrors the kernel's post-callback dispatch resolution:
    /// after `select_cpu`, `local_cpu` is the CPU that `select_cpu` returned;
    /// after `enqueue`, it is the task's assigned CPU.
    ///
    /// Returns the CPU if a local DSQ dispatch was resolved (the engine
    /// should try to run on that CPU), or None.
    pub fn resolve_pending_dispatch(&mut self, local_cpu: CpuId) -> Option<CpuId> {
        let pd = self.pending_dispatch.take()?;

        // Task has been dispatched — no longer in BPF scheduler's queue.
        self.task_ops_state.insert(pd.pid, OpsTaskState::None);

        let dsq = pd.dsq_id;
        if dsq.is_local() {
            self.cpus[local_cpu.0 as usize].local_dsq.push_back(pd.pid);
            debug!(pid = pd.pid.0, cpu = local_cpu.0, "resolved SCX_DSQ_LOCAL");
            Some(local_cpu)
        } else if dsq.is_local_on() {
            let cpu = dsq.local_on_cpu();
            if (cpu.0 as usize) < self.cpus.len() {
                self.cpus[cpu.0 as usize].local_dsq.push_back(pd.pid);
            }
            Some(cpu)
        } else if let Some(vtime) = pd.vtime {
            self.dsqs.insert_vtime(dsq, pd.pid, vtime);
            None
        } else {
            self.dsqs.insert_fifo(dsq, pd.pid);
            None
        }
    }
}

// ---------------------------------------------------------------------------
// Thread-local simulator state access
// ---------------------------------------------------------------------------

thread_local! {
    static SIM_STATE: RefCell<Option<*mut SimulatorState>> = const { RefCell::new(None) };
    static SIM_LOCAL_CLOCK: std::cell::Cell<TimeNs> = const { std::cell::Cell::new(0) };
}

/// Install a simulator state pointer for the duration of ops callbacks.
///
/// # Safety
/// The caller must ensure `state` remains valid and unaliased for the
/// duration between `enter_sim` and `exit_sim`.
pub unsafe fn enter_sim(state: &mut SimulatorState) {
    SIM_STATE.with(|cell| {
        *cell.borrow_mut() = Some(state as *mut SimulatorState);
    });
}

/// Remove the simulator state pointer after ops callbacks complete.
pub fn exit_sim() {
    SIM_STATE.with(|cell| {
        *cell.borrow_mut() = None;
    });
}

/// Read the current CPU's local clock from the thread-local.
///
/// Returns the local clock set by the engine for the current event's CPU.
/// Used by the custom trace formatter to show simulated time.
pub fn sim_clock() -> TimeNs {
    SIM_LOCAL_CLOCK.with(|c| c.get())
}

/// Update the local clock thread-local. Called by the engine before
/// `info!`/`debug!` calls so the trace formatter has access.
pub fn set_sim_clock(local: TimeNs) {
    SIM_LOCAL_CLOCK.with(|c| c.set(local));
}

/// Access the simulator state from within a kfunc.
///
/// # Panics
/// Panics if called outside of an `enter_sim`/`exit_sim` scope.
fn with_sim<F, R>(f: F) -> R
where
    F: FnOnce(&mut SimulatorState) -> R,
{
    SIM_STATE.with(|cell| {
        let ptr = cell
            .borrow()
            .expect("kfunc called outside of simulator context");
        // SAFETY: We hold a valid pointer installed by enter_sim, and
        // the simulation is single-threaded.
        let sim = unsafe { &mut *ptr };
        f(sim)
    })
}

// ---------------------------------------------------------------------------
// SCX kfunc implementations
// ---------------------------------------------------------------------------

/// Create a dispatch queue.
#[no_mangle]
pub extern "C" fn scx_bpf_create_dsq(dsq_id: u64, _node: i32) -> i32 {
    with_sim(|sim| {
        let result = if sim.dsqs.create(DsqId(dsq_id)) {
            0
        } else {
            -1
        };
        debug!(dsq_id, result, "kfunc create_dsq");
        result
    })
}

/// Default CPU selection: find an idle CPU, preferring prev_cpu.
///
/// Respects the task's cpumask (`p->cpus_ptr`): only CPUs allowed by the
/// task's affinity mask are considered, matching the kernel's
/// `scx_select_cpu_dfl` behavior.
#[no_mangle]
pub extern "C" fn scx_bpf_select_cpu_dfl(
    p: *mut c_void,
    prev_cpu: i32,
    _wake_flags: u64,
    is_idle: *mut bool,
) -> i32 {
    with_sim(|sim| {
        let cpus_ptr = unsafe { ffi::sim_task_get_cpus_ptr(p) };
        let allowed = |cpu: u32| -> bool {
            cpus_ptr.is_null() || unsafe { ffi::bpf_cpumask_test_cpu(cpu, cpus_ptr) }
        };

        let prev = CpuId(prev_cpu as u32);
        // Prefer prev_cpu if it's idle and allowed
        if (prev.0 as usize) < sim.cpus.len() && sim.cpu_is_idle(prev) && allowed(prev.0) {
            unsafe { *is_idle = true };
            debug!(
                prev_cpu,
                cpu = prev_cpu,
                idle = true,
                "kfunc select_cpu_dfl"
            );
            return prev_cpu;
        }
        // Find any idle CPU that is allowed
        if let Some(cpu) = sim
            .cpus
            .iter()
            .find(|c| c.is_idle() && c.local_dsq.is_empty() && allowed(c.id.0))
        {
            let cpu_id = cpu.id;
            unsafe { *is_idle = true };
            debug!(
                prev_cpu,
                cpu = cpu_id.0,
                idle = true,
                "kfunc select_cpu_dfl"
            );
            return cpu_id.0 as i32;
        }
        unsafe { *is_idle = false };
        // Fall back to prev_cpu if allowed, otherwise first allowed CPU
        let fallback = if allowed(prev.0) {
            prev_cpu
        } else {
            (0..sim.cpus.len() as u32)
                .find(|&c| allowed(c))
                .map_or(prev_cpu, |c| c as i32)
        };
        debug!(
            prev_cpu,
            cpu = fallback,
            idle = false,
            "kfunc select_cpu_dfl"
        );
        fallback
    })
}

/// Extended CPU selection with cpumask constraint and SCX_PICK_IDLE_CORE.
///
/// Returns an idle CPU (>= 0) matching both the task's cpus_ptr and
/// `cpus_allowed`, or negative on failure.
#[no_mangle]
pub extern "C" fn scx_bpf_select_cpu_and(
    p: *mut c_void,
    prev_cpu: i32,
    _wake_flags: u64,
    cpus_allowed: *const c_void,
    flags: u64,
) -> i32 {
    const SCX_PICK_IDLE_CORE: u64 = 1;

    with_sim(|sim| {
        let nr_cpus = sim.cpus.len();
        let prev = CpuId(prev_cpu as u32);
        let want_idle_core = flags & SCX_PICK_IDLE_CORE != 0;
        let cpus_ptr = unsafe { ffi::sim_task_get_cpus_ptr(p) };

        let in_mask = |cpu: u32| -> bool {
            let task_ok = cpus_ptr.is_null() || unsafe { ffi::bpf_cpumask_test_cpu(cpu, cpus_ptr) };
            let caller_ok =
                cpus_allowed.is_null() || unsafe { ffi::bpf_cpumask_test_cpu(cpu, cpus_allowed) };
            task_ok && caller_ok
        };

        let has_idle_core = |cpu: CpuId| -> bool {
            let siblings = &sim.cpus[cpu.0 as usize].siblings;
            if siblings.is_empty() {
                return true; // no SMT — single-thread core
            }
            siblings.iter().all(|&sib| sim.cpu_is_idle(sib))
        };

        // Prefer prev_cpu if it meets all constraints
        if (prev.0 as usize) < nr_cpus
            && sim.cpu_is_idle(prev)
            && in_mask(prev.0)
            && (!want_idle_core || has_idle_core(prev))
        {
            debug!(prev_cpu, cpu = prev_cpu, "kfunc select_cpu_and (prev idle)");
            return prev_cpu;
        }

        // Scan for any idle CPU matching constraints
        for i in 0..nr_cpus {
            let cpu = CpuId(i as u32);
            if cpu == prev {
                continue;
            }
            if sim.cpu_is_idle(cpu) && in_mask(i as u32) && (!want_idle_core || has_idle_core(cpu))
            {
                debug!(prev_cpu, cpu = i, "kfunc select_cpu_and (found idle)");
                return i as i32;
            }
        }

        debug!(prev_cpu, "kfunc select_cpu_and (no idle)");
        -1 // EBUSY
    })
}

/// Insert a task into a DSQ (FIFO ordering).
///
/// Like the kernel, this records intent but does NOT insert immediately.
/// The engine resolves the pending dispatch after the callback returns,
/// at which point `SCX_DSQ_LOCAL` is mapped to the correct CPU.
#[no_mangle]
pub extern "C" fn scx_bpf_dsq_insert(p: *mut c_void, dsq_id: u64, slice: u64, enq_flags: u64) {
    with_sim(|sim| {
        let pid = sim.task_pid_from_raw(p);
        unsafe { ffi::sim_task_set_slice(p, slice) };
        debug!(pid = pid.0, dsq_id, slice = %FmtN(slice), "kfunc dsq_insert");

        sim.pending_dispatch = Some(PendingDispatch {
            pid,
            dsq_id: DsqId(dsq_id),
            enq_flags,
            vtime: None,
        });

        let cpu = sim.current_cpu;
        let local_t = sim.cpus[cpu.0 as usize].local_clock;
        sim.trace.record(
            local_t,
            cpu,
            TraceKind::DsqInsert {
                pid,
                dsq_id: DsqId(dsq_id),
                slice,
            },
        );
    })
}

/// Insert a task into a DSQ with vtime ordering.
///
/// Deferred like `scx_bpf_dsq_insert` — see its doc comment.
///
/// # Panics
/// Panics if `dsq_id` is a built-in DSQ (LOCAL, GLOBAL), matching the
/// kernel's `dispatch_enqueue` which calls `scx_error()` for this case.
#[no_mangle]
pub extern "C" fn scx_bpf_dsq_insert_vtime(
    p: *mut c_void,
    dsq_id: u64,
    slice: u64,
    vtime: u64,
    enq_flags: u64,
) {
    let dsq = DsqId(dsq_id);
    assert!(
        !dsq.is_builtin(),
        "cannot use vtime ordering for built-in DSQ {:#x}",
        dsq_id
    );
    with_sim(|sim| {
        let pid = sim.task_pid_from_raw(p);
        unsafe { ffi::sim_task_set_slice(p, slice) };
        debug!(pid = pid.0, dsq_id, slice = %FmtN(slice), vtime = %Vtime(vtime), "kfunc dsq_insert_vtime");

        sim.pending_dispatch = Some(PendingDispatch {
            pid,
            dsq_id: DsqId(dsq_id),
            enq_flags,
            vtime: Some(Vtime(vtime)),
        });

        let cpu = sim.current_cpu;
        let local_t = sim.cpus[cpu.0 as usize].local_clock;
        sim.trace.record(
            local_t,
            cpu,
            TraceKind::DsqInsertVtime {
                pid,
                dsq_id: DsqId(dsq_id),
                slice,
                vtime: Vtime(vtime),
            },
        );
    })
}

/// Move the head of a DSQ to the current CPU's local DSQ.
#[no_mangle]
pub extern "C" fn scx_bpf_dsq_move_to_local(dsq_id: u64) -> bool {
    with_sim(|sim| {
        let cpu_idx = sim.current_cpu.0 as usize;
        // Need to split borrow: extract cpu mutably, pass dsqs mutably
        let cpus_ptr = sim.cpus.as_mut_ptr();
        let cpu = unsafe { &mut *cpus_ptr.add(cpu_idx) };
        let result = sim.dsqs.move_to_local(DsqId(dsq_id), cpu);
        debug!(dsq_id, result, "kfunc dsq_move_to_local");

        let local_t = sim.cpus[cpu_idx].local_clock;
        sim.trace.record(
            local_t,
            sim.current_cpu,
            TraceKind::DsqMoveToLocal {
                dsq_id: DsqId(dsq_id),
                success: result,
            },
        );

        result
    })
}

/// Query the number of tasks queued in a DSQ.
#[no_mangle]
pub extern "C" fn scx_bpf_dsq_nr_queued(dsq_id: u64) -> i32 {
    with_sim(|sim| {
        let dsq = DsqId(dsq_id);
        if dsq.is_local() {
            let cpu = sim.current_cpu.0 as usize;
            let n = sim.cpus[cpu].local_dsq.len() as i32;
            debug!(dsq_id, cpu, n, "kfunc dsq_nr_queued LOCAL");
            return n;
        }
        if dsq.is_local_on() {
            let cpu = dsq.local_on_cpu();
            if (cpu.0 as usize) < sim.cpus.len() {
                let n = sim.cpus[cpu.0 as usize].local_dsq.len() as i32;
                debug!(dsq_id, cpu = cpu.0, n, "kfunc dsq_nr_queued LOCAL_ON");
                return n;
            }
            return 0;
        }
        let n = sim.dsqs.nr_queued(dsq) as i32;
        debug!(dsq_id, n, "kfunc dsq_nr_queued");
        n
    })
}

/// Get the current simulated time (per-CPU local clock).
#[no_mangle]
pub extern "C" fn scx_bpf_now() -> u64 {
    with_sim(|sim| {
        let cpu = sim.current_cpu.0 as usize;
        sim.cpus[cpu].local_clock
    })
}

/// Get the current CPU ID.
#[no_mangle]
pub extern "C" fn bpf_get_smp_processor_id() -> u32 {
    with_sim(|sim| sim.current_cpu.0)
}

/// Alias for sim_wrapper.h macro override (avoids conflict with the
/// static function pointer in bpf_helper_defs.h).
#[no_mangle]
pub extern "C" fn sim_bpf_get_smp_processor_id() -> u32 {
    with_sim(|sim| sim.current_cpu.0)
}

/// Deterministic PRNG replacement for bpf_get_prandom_u32.
#[no_mangle]
pub extern "C" fn sim_bpf_get_prandom_u32() -> u32 {
    with_sim(|sim| sim.next_prng())
}

/// Get the CPU a task is assigned to.
///
/// Returns the CPU the task was last scheduled on, matching the kernel's
/// `task_cpu(p)` semantics. Falls back to CPU 0 for tasks that haven't
/// run yet.
#[no_mangle]
pub extern "C" fn scx_bpf_task_cpu(p: *const c_void) -> i32 {
    with_sim(|sim| {
        let pid = sim.task_pid_from_raw(p as *mut c_void);
        let cpu = sim.task_last_cpu.get(&pid).copied().unwrap_or(CpuId(0));
        cpu.0 as i32
    })
}

/// Report a scheduler error. In the simulator, we panic.
#[no_mangle]
pub extern "C" fn scx_bpf_error_bstr(fmt: *const i8, _data: *const u64, _data_sz: u32) {
    let msg = if fmt.is_null() {
        "scheduler error (null fmt)".to_string()
    } else {
        let cstr = unsafe { std::ffi::CStr::from_ptr(fmt) };
        format!("scheduler error: {}", cstr.to_string_lossy())
    };
    eprintln!("scx_bpf_error: {msg}");
}

/// Request re-enqueue of all tasks on the current CPU's local DSQ.
///
/// Called by `cpu_release` handlers (e.g. COSMOS). Sets a flag that
/// the engine checks after the callback returns. The engine then
/// drains the local DSQ and calls `enqueue(p, SCX_ENQ_REENQ)` for
/// each task.
#[no_mangle]
pub extern "C" fn scx_bpf_reenqueue_local() -> u32 {
    with_sim(|sim| {
        debug!(cpu = sim.current_cpu.0, "kfunc reenqueue_local");
        sim.reenqueue_local_requested = true;
        0
    })
}

/// No-op stubs for cpumask ref counting in simulator.
#[no_mangle]
pub extern "C" fn scx_bpf_put_cpumask(_cpumask: *const c_void) {}

#[no_mangle]
pub extern "C" fn scx_bpf_put_idle_cpumask(_cpumask: *const c_void) {}

/// Destroy a DSQ. No-op in simulator.
#[no_mangle]
pub extern "C" fn scx_bpf_destroy_dsq(_dsq_id: u64) {}

/// No-op for bpf_ktime_get_ns -- use per-CPU local clock.
#[no_mangle]
pub extern "C" fn bpf_ktime_get_ns() -> u64 {
    with_sim(|sim| {
        let cpu = sim.current_cpu.0 as usize;
        sim.cpus[cpu].local_clock
    })
}

// RCU stubs -- no-op in simulator
#[no_mangle]
pub extern "C" fn bpf_rcu_read_lock() {}

#[no_mangle]
pub extern "C" fn bpf_rcu_read_unlock() {}

// Task reference stubs
#[no_mangle]
pub extern "C" fn bpf_task_release(_p: *mut c_void) {}

/// Get the current task's task_struct pointer (for the CPU we're running on).
///
/// During a wake path with a known waker (Phase::Wake), returns the waker's
/// task_struct so that `is_wake_affine()` can compare address spaces.
/// Otherwise returns the task running on `current_cpu`, or a synthetic idle
/// task if no task is running (matching kernel behavior where the idle task
/// is always "current" on idle CPUs).
#[no_mangle]
pub extern "C" fn bpf_get_current_task_btf() -> *mut c_void {
    with_sim(|sim| {
        // Waker override: during select_cpu for a waker-induced wake,
        // return the waker's task_struct (kernel semantics).
        if let Some(raw) = sim.waker_task_raw {
            return raw as *mut c_void;
        }
        let cpu = sim.current_cpu;
        if let Some(pid) = sim.cpus[cpu.0 as usize].current_task {
            if let Some(&raw) = sim.task_pid_to_raw.get(&pid) {
                return raw as *mut c_void;
            }
        }
        // Idle task fallback — never return NULL (kernel never does).
        sim.idle_task_raw
    })
}

/// Alias for sim_wrapper.h macro override (avoids conflict with the
/// static function pointer in bpf_helper_defs.h).
#[no_mangle]
pub extern "C" fn sim_bpf_get_current_task_btf() -> *mut c_void {
    bpf_get_current_task_btf()
}

/// Get the task running on a given CPU.
///
/// Needed as a linkable symbol for compat paths, even though
/// `__COMPAT_scx_bpf_cpu_curr` is overridden to a macro returning NULL.
#[no_mangle]
pub extern "C" fn scx_bpf_cpu_curr(cpu: i32) -> *mut c_void {
    with_sim(|sim| {
        let idx = cpu as usize;
        if idx >= sim.cpus.len() {
            return ptr::null_mut();
        }
        if let Some(pid) = sim.cpus[idx].current_task {
            if let Some(&raw) = sim.task_pid_to_raw.get(&pid) {
                return raw as *mut c_void;
            }
        }
        ptr::null_mut()
    })
}

// ---------------------------------------------------------------------------
// DSQ iterator kfuncs for bpf_for_each(scx_dsq, ...)
// ---------------------------------------------------------------------------

/// Begin iterating a DSQ. Returns the first task_struct* or NULL.
///
/// Called by the `bpf_for_each(scx_dsq, p, dsq_id, flags)` macro override.
/// Snapshots the DSQ contents in priority order and stores the iterator
/// state in SimulatorState.
#[no_mangle]
pub extern "C" fn sim_dsq_iter_begin(dsq_id: u64, _flags: u64) -> *mut c_void {
    with_sim(|sim| {
        let pids = sim.dsqs.ordered_pids(DsqId(dsq_id));
        debug!(dsq_id, count = pids.len(), "dsq_iter_begin");

        if pids.is_empty() {
            sim.dsq_iter = None;
            return ptr::null_mut();
        }

        let first_pid = pids[0];
        sim.dsq_iter = Some(DsqIterState {
            dsq_id: DsqId(dsq_id),
            pids,
            pos: 0,
        });

        sim.task_pid_to_raw
            .get(&first_pid)
            .map_or(ptr::null_mut(), |&raw| raw as *mut c_void)
    })
}

/// Advance the DSQ iterator. Returns the next task_struct* or NULL.
#[no_mangle]
pub extern "C" fn sim_dsq_iter_next() -> *mut c_void {
    with_sim(|sim| {
        let iter = match sim.dsq_iter.as_mut() {
            Some(it) => it,
            None => return ptr::null_mut(),
        };

        iter.pos += 1;

        // Skip PIDs that were removed from the DSQ (by dsq_move)
        while iter.pos < iter.pids.len() {
            let pid = iter.pids[iter.pos];
            // Check if this PID is still in the DSQ
            if sim.dsqs.ordered_pids(iter.dsq_id).contains(&pid) {
                return sim
                    .task_pid_to_raw
                    .get(&pid)
                    .map_or(ptr::null_mut(), |&raw| raw as *mut c_void);
            }
            iter.pos += 1;
        }

        sim.dsq_iter = None;
        ptr::null_mut()
    })
}

/// Move a task from the currently-iterated DSQ to a destination DSQ.
///
/// Called by `__COMPAT_scx_bpf_dsq_move` macro override. The source DSQ
/// is determined from the active DSQ iterator state.
#[no_mangle]
pub extern "C" fn sim_scx_bpf_dsq_move(p: *mut c_void, dst_dsq_id: u64, _enq_flags: u64) -> bool {
    with_sim(|sim| {
        let pid = sim.task_pid_from_raw(p);
        let src_dsq_id = match &sim.dsq_iter {
            Some(iter) => iter.dsq_id,
            None => {
                debug!(pid = pid.0, "dsq_move: no active iterator");
                return false;
            }
        };

        // Remove from source DSQ
        if !sim.dsqs.remove_pid(src_dsq_id, pid) {
            debug!(
                pid = pid.0,
                src = src_dsq_id.0,
                "dsq_move: pid not in source DSQ"
            );
            return false;
        }

        let dst = DsqId(dst_dsq_id);
        if dst.is_local() {
            let cpu_idx = sim.current_cpu.0 as usize;
            sim.cpus[cpu_idx].local_dsq.push_back(pid);
            debug!(pid = pid.0, cpu = sim.current_cpu.0, "dsq_move → LOCAL");
        } else if dst.is_local_on() {
            let cpu = dst.local_on_cpu();
            if (cpu.0 as usize) < sim.cpus.len() {
                sim.cpus[cpu.0 as usize].local_dsq.push_back(pid);
            }
            debug!(pid = pid.0, cpu = cpu.0, "dsq_move → LOCAL_ON");
        } else {
            // Move to another named DSQ (FIFO)
            sim.dsqs.insert_fifo(dst, pid);
            debug!(pid = pid.0, dst = dst.0, "dsq_move → DSQ");
        }

        true
    })
}

// ---------------------------------------------------------------------------
// Updated bpf_task_from_pid — return real task_struct*
// ---------------------------------------------------------------------------

/// Look up a task by PID and return its task_struct pointer.
///
/// In BPF this is a verifier workaround; in the simulator we use it
/// to get the raw pointer from our PID→pointer map.
#[no_mangle]
pub extern "C" fn bpf_task_from_pid(pid: i32) -> *mut c_void {
    with_sim(|sim| {
        sim.task_pid_to_raw
            .get(&Pid(pid))
            .map_or(ptr::null_mut(), |&raw| raw as *mut c_void)
    })
}

// ---------------------------------------------------------------------------
// scx_bpf_kick_cpu — record kicked CPUs for the engine
// ---------------------------------------------------------------------------

/// Kick a CPU (send scheduling IPI).
///
/// Records the CPU and flags in the kicked map. The engine processes kicked
/// CPUs after the current scheduler callback returns, triggering dispatch
/// on those CPUs. Flags are OR'd so multiple kicks accumulate.
#[no_mangle]
pub extern "C" fn scx_bpf_kick_cpu(cpu: i32, flags: u64) {
    with_sim(|sim| {
        let cpu_id = CpuId(cpu as u32);
        if (cpu_id.0 as usize) < sim.cpus.len() {
            let new_flags = KickFlags::from_raw(flags);
            sim.kicked_cpus
                .entry(cpu_id)
                .and_modify(|existing| existing.insert(new_flags))
                .or_insert(new_flags);
            debug!(cpu, flags, "kick_cpu");

            let current = sim.current_cpu;
            let local_t = sim.cpus[current.0 as usize].local_clock;
            sim.trace
                .record(local_t, current, TraceKind::KickCpu { target_cpu: cpu_id });
        }
    })
}

// ---------------------------------------------------------------------------
// Dump kfuncs — no-op stubs for scheduler debug output
// ---------------------------------------------------------------------------

/// Dump debug text. No-op in the simulator (debug output is not modeled).
#[no_mangle]
pub extern "C" fn scx_bpf_dump_bstr(_fmt: *const i8, _data: *const u64, _data_sz: u32) {}

// ---------------------------------------------------------------------------
// Cgroup kfuncs — stub implementations
// ---------------------------------------------------------------------------

/// Get a task's cgroup. Returns NULL in the simulator (cgroups not yet modeled).
#[no_mangle]
pub extern "C" fn scx_bpf_task_cgroup(_p: *mut c_void, _subsys_id: i32) -> *mut c_void {
    ptr::null_mut()
}

/// Look up a cgroup by ID. Returns NULL (cgroups not yet modeled).
#[no_mangle]
pub extern "C" fn bpf_cgroup_from_id(_id: u64) -> *mut c_void {
    ptr::null_mut()
}

/// Get ancestor cgroup at a given level. Returns NULL (cgroups not yet modeled).
#[no_mangle]
pub extern "C" fn bpf_cgroup_ancestor(_cgrp: *mut c_void, _level: i32) -> *mut c_void {
    ptr::null_mut()
}

/// Acquire a reference on a cgroup. No-op in the simulator.
#[no_mangle]
pub extern "C" fn bpf_cgroup_acquire(_cgrp: *mut c_void) -> *mut c_void {
    _cgrp
}

/// Release a cgroup reference. No-op in the simulator.
#[no_mangle]
pub extern "C" fn bpf_cgroup_release(_cgrp: *mut c_void) {}

/// Get per-cgroup BPF local storage. Returns NULL (not yet modeled).
#[no_mangle]
pub extern "C" fn bpf_cgrp_storage_get(
    _map: *mut c_void,
    _cgrp: *mut c_void,
    _value: *mut c_void,
    _flags: u64,
) -> *mut c_void {
    ptr::null_mut()
}

/// Get per-task BPF local storage. Returns NULL (not yet modeled).
#[no_mangle]
pub extern "C" fn bpf_task_storage_get(
    _map: *mut c_void,
    _task: *mut c_void,
    _value: *mut c_void,
    _flags: u64,
) -> *mut c_void {
    ptr::null_mut()
}

/// Look up per-CPU array element. Returns NULL (not yet modeled).
#[no_mangle]
pub extern "C" fn bpf_map_lookup_percpu_elem(
    _map: *mut c_void,
    _key: *const c_void,
    _cpu: u32,
) -> *mut c_void {
    ptr::null_mut()
}

/// Check if a task is currently running on any CPU.
#[no_mangle]
pub extern "C" fn scx_bpf_task_running(p: *const c_void) -> bool {
    with_sim(|sim| {
        let pid = sim.task_pid_from_raw(p as *mut c_void);
        let running = sim.cpus.iter().any(|cpu| cpu.current_task == Some(pid));
        debug!(pid = pid.0, running, "kfunc task_running");
        running
    })
}

/// Return the number of possible CPUs.
#[no_mangle]
pub extern "C" fn scx_bpf_nr_cpu_ids() -> u32 {
    with_sim(|sim| {
        let n = sim.cpus.len() as u32;
        debug!(n, "kfunc nr_cpu_ids");
        n
    })
}

/// Set CPU performance level. Stores in SimCpu for observability.
#[no_mangle]
pub extern "C" fn scx_bpf_cpuperf_set(cpu: i32, perf: u32) {
    with_sim(|sim| {
        if let Some(c) = sim.cpus.get_mut(cpu as usize) {
            c.perf_lvl = perf;
        }
    });
}

/// Get current CPU performance level. Returns the level set by cpuperf_set,
/// or SCX_CPUPERF_ONE (1024) if never set.
#[no_mangle]
pub extern "C" fn scx_bpf_cpuperf_cur(cpu: i32) -> u32 {
    with_sim(|sim| {
        sim.cpus
            .get(cpu as usize)
            .map_or(0, |c| if c.perf_lvl > 0 { c.perf_lvl } else { 1024 })
    })
}

/// Get CPU performance capacity. Returns SCX_CPUPERF_ONE (1024) for all
/// CPUs in the simulator (all CPUs have equal max capacity).
#[no_mangle]
pub extern "C" fn scx_bpf_cpuperf_cap(_cpu: i32) -> u32 {
    1024
}

/// Schedule a BPF timer to fire after `nsecs` nanoseconds.
///
/// Called from C scheduler code when `bpf_timer_start(timer, nsecs, flags)`
/// is invoked. The engine drains `pending_timer_ns` after each callback
/// and inserts a `TimerFired` event into the event queue.
#[no_mangle]
pub extern "C" fn sim_timer_start(nsecs: u64) {
    with_sim(|sim| {
        sim.pending_timer_ns = Some(sim.clock + nsecs);
        debug!(nsecs, fire_at = sim.clock + nsecs, "timer_start");
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cpu::SimCpu;
    use crate::dsq::DsqManager;
    use crate::scenario::{NoiseConfig, OverheadConfig};
    use crate::trace::Trace;
    use crate::types::{CpuId, DsqId, KickFlags, Pid};
    use crate::SIM_LOCK;

    /// Create a minimal SimulatorState for unit testing.
    fn test_state(nr_cpus: u32) -> SimulatorState {
        SimulatorState {
            cpus: (0..nr_cpus).map(|i| SimCpu::new(CpuId(i))).collect(),
            dsqs: DsqManager::new(),
            current_cpu: CpuId(0),
            trace: Trace::new(nr_cpus, &[]),
            clock: 0,
            task_raw_to_pid: HashMap::new(),
            task_pid_to_raw: HashMap::new(),
            task_last_cpu: HashMap::new(),
            task_ops_state: HashMap::new(),
            prng_state: 0xDEAD_BEEF,
            ops_context: OpsContext::None,
            pending_dispatch: None,
            dsq_iter: None,
            kicked_cpus: HashMap::new(),
            reenqueue_local_requested: false,
            pending_timer_ns: None,
            waker_task_raw: None,
            idle_task_raw: ptr::null_mut(),
            noise: NoiseConfig {
                enabled: false,
                ..Default::default()
            },
            overhead: OverheadConfig {
                enabled: false,
                ..Default::default()
            },
        }
    }

    /// Allocate a C task_struct and register it in the state's pointer maps.
    ///
    /// Returns the raw pointer. Caller must call `ffi::sim_task_free` when done.
    fn register_task(state: &mut SimulatorState, pid: Pid) -> *mut c_void {
        let raw = unsafe { ffi::sim_task_alloc() };
        assert!(!raw.is_null());
        unsafe { ffi::sim_task_set_pid(raw, pid.0) };
        state.task_raw_to_pid.insert(raw as usize, pid);
        state.task_pid_to_raw.insert(pid, raw as usize);
        raw
    }

    /// Free a previously registered task.
    fn free_task(state: &mut SimulatorState, pid: Pid) {
        if let Some(raw) = state.task_pid_to_raw.remove(&pid) {
            state.task_raw_to_pid.remove(&raw);
            unsafe { ffi::sim_task_free(raw as *mut c_void) };
        }
    }

    /// Run a closure with SimulatorState installed in the thread-local.
    #[allow(dead_code)]
    fn with_state<F, R>(state: &mut SimulatorState, f: F) -> R
    where
        F: FnOnce(&mut SimulatorState) -> R,
    {
        unsafe { enter_sim(state) };
        let result = f(state);
        exit_sim();
        result
    }

    // -----------------------------------------------------------------------
    // DSQ creation and querying
    // -----------------------------------------------------------------------

    #[test]
    fn test_create_dsq() {
        let _lock = SIM_LOCK.lock().unwrap();
        let mut state = test_state(1);

        unsafe { enter_sim(&mut state) };
        assert_eq!(scx_bpf_create_dsq(42, -1), 0);
        // Creating the same DSQ again should fail
        assert_eq!(scx_bpf_create_dsq(42, -1), -1);
        exit_sim();

        assert_eq!(state.dsqs.nr_queued(DsqId(42)), 0);
    }

    #[test]
    fn test_dsq_nr_queued_empty() {
        let _lock = SIM_LOCK.lock().unwrap();
        let mut state = test_state(1);
        state.dsqs.create(DsqId(100));

        unsafe { enter_sim(&mut state) };
        assert_eq!(scx_bpf_dsq_nr_queued(100), 0);
        exit_sim();
    }

    #[test]
    fn test_dsq_nr_queued_with_tasks() {
        let _lock = SIM_LOCK.lock().unwrap();
        let mut state = test_state(1);
        state.dsqs.create(DsqId(100));
        state.dsqs.insert_fifo(DsqId(100), Pid(1));
        state.dsqs.insert_fifo(DsqId(100), Pid(2));

        unsafe { enter_sim(&mut state) };
        assert_eq!(scx_bpf_dsq_nr_queued(100), 2);
        exit_sim();
    }

    // -----------------------------------------------------------------------
    // DSQ insert (deferred dispatch)
    // -----------------------------------------------------------------------

    #[test]
    fn test_dsq_insert_deferred() {
        let _lock = SIM_LOCK.lock().unwrap();
        let mut state = test_state(1);
        let p = register_task(&mut state, Pid(1));

        unsafe { enter_sim(&mut state) };
        scx_bpf_dsq_insert(p, DsqId::GLOBAL.0, 5_000_000, 0);
        exit_sim();

        // Insert is deferred, not immediate
        assert!(state.pending_dispatch.is_some());
        let pd = state.pending_dispatch.as_ref().unwrap();
        assert_eq!(pd.pid, Pid(1));
        assert_eq!(pd.dsq_id, DsqId::GLOBAL);
        assert!(pd.vtime.is_none());
        // DSQ should still be empty until resolved
        assert_eq!(state.dsqs.nr_queued(DsqId::GLOBAL), 0);

        free_task(&mut state, Pid(1));
    }

    #[test]
    fn test_dsq_insert_vtime_deferred() {
        let _lock = SIM_LOCK.lock().unwrap();
        let mut state = test_state(1);
        state.dsqs.create(DsqId(50));
        let p = register_task(&mut state, Pid(3));

        unsafe { enter_sim(&mut state) };
        scx_bpf_dsq_insert_vtime(p, 50, 5_000_000, 1000, 0);
        exit_sim();

        let pd = state.pending_dispatch.as_ref().unwrap();
        assert_eq!(pd.pid, Pid(3));
        assert_eq!(pd.dsq_id, DsqId(50));
        assert_eq!(pd.vtime, Some(Vtime(1000)));

        free_task(&mut state, Pid(3));
    }

    #[test]
    fn test_resolve_pending_dispatch_global() {
        let _lock = SIM_LOCK.lock().unwrap();
        let mut state = test_state(2);
        let p = register_task(&mut state, Pid(1));

        unsafe { enter_sim(&mut state) };
        scx_bpf_dsq_insert(p, DsqId::GLOBAL.0, 5_000_000, 0);
        exit_sim();

        let result = state.resolve_pending_dispatch(CpuId(0));
        // Global DSQ dispatch returns None (not a local dispatch)
        assert!(result.is_none());
        assert_eq!(state.dsqs.nr_queued(DsqId::GLOBAL), 1);

        free_task(&mut state, Pid(1));
    }

    #[test]
    fn test_resolve_pending_dispatch_local() {
        let _lock = SIM_LOCK.lock().unwrap();
        let mut state = test_state(2);
        let p = register_task(&mut state, Pid(1));

        unsafe { enter_sim(&mut state) };
        scx_bpf_dsq_insert(p, DsqId::LOCAL.0, 5_000_000, 0);
        exit_sim();

        let result = state.resolve_pending_dispatch(CpuId(1));
        // Local dispatch resolves to the specified CPU
        assert_eq!(result, Some(CpuId(1)));
        assert_eq!(state.cpus[1].local_dsq.len(), 1);
        assert_eq!(state.cpus[1].local_dsq[0], Pid(1));

        free_task(&mut state, Pid(1));
    }

    // -----------------------------------------------------------------------
    // DSQ move_to_local
    // -----------------------------------------------------------------------

    #[test]
    fn test_dsq_move_to_local() {
        let _lock = SIM_LOCK.lock().unwrap();
        let mut state = test_state(2);
        state.dsqs.create(DsqId(77));
        state.dsqs.insert_fifo(DsqId(77), Pid(10));
        state.dsqs.insert_fifo(DsqId(77), Pid(11));
        state.current_cpu = CpuId(1);

        unsafe { enter_sim(&mut state) };
        let moved = scx_bpf_dsq_move_to_local(77);
        exit_sim();

        assert!(moved);
        assert_eq!(state.cpus[1].local_dsq.len(), 1);
        assert_eq!(state.cpus[1].local_dsq[0], Pid(10));
        assert_eq!(state.dsqs.nr_queued(DsqId(77)), 1);
    }

    #[test]
    fn test_dsq_move_to_local_empty() {
        let _lock = SIM_LOCK.lock().unwrap();
        let mut state = test_state(1);
        state.dsqs.create(DsqId(77));

        unsafe { enter_sim(&mut state) };
        let moved = scx_bpf_dsq_move_to_local(77);
        exit_sim();

        assert!(!moved);
        assert!(state.cpus[0].local_dsq.is_empty());
    }

    // -----------------------------------------------------------------------
    // CPU selection
    // -----------------------------------------------------------------------

    #[test]
    fn test_select_cpu_dfl_prefers_prev_if_idle() {
        let _lock = SIM_LOCK.lock().unwrap();
        let mut state = test_state(4);
        // All CPUs idle, prev_cpu=2 should be returned
        let p = register_task(&mut state, Pid(1));

        unsafe { enter_sim(&mut state) };
        let mut is_idle = false;
        let cpu = scx_bpf_select_cpu_dfl(p, 2, 0, &mut is_idle);
        exit_sim();

        assert_eq!(cpu, 2);
        assert!(is_idle);

        free_task(&mut state, Pid(1));
    }

    #[test]
    fn test_select_cpu_dfl_finds_other_idle() {
        let _lock = SIM_LOCK.lock().unwrap();
        let mut state = test_state(3);
        // Make prev_cpu busy, leave others idle
        state.cpus[1].current_task = Some(Pid(99));
        let p = register_task(&mut state, Pid(1));

        unsafe { enter_sim(&mut state) };
        let mut is_idle = false;
        let cpu = scx_bpf_select_cpu_dfl(p, 1, 0, &mut is_idle);
        exit_sim();

        assert!(is_idle);
        assert_ne!(cpu, 1); // Should pick a different idle CPU

        free_task(&mut state, Pid(1));
    }

    #[test]
    fn test_select_cpu_dfl_no_idle() {
        let _lock = SIM_LOCK.lock().unwrap();
        let mut state = test_state(2);
        // All CPUs busy
        state.cpus[0].current_task = Some(Pid(10));
        state.cpus[1].current_task = Some(Pid(11));
        let p = register_task(&mut state, Pid(1));

        unsafe { enter_sim(&mut state) };
        let mut is_idle = false;
        let cpu = scx_bpf_select_cpu_dfl(p, 0, 0, &mut is_idle);
        exit_sim();

        assert!(!is_idle);
        assert_eq!(cpu, 0); // Falls back to prev_cpu

        free_task(&mut state, Pid(1));
    }

    // -----------------------------------------------------------------------
    // Clock and timing
    // -----------------------------------------------------------------------

    #[test]
    fn test_scx_bpf_now() {
        let _lock = SIM_LOCK.lock().unwrap();
        let mut state = test_state(2);
        state.current_cpu = CpuId(1);
        state.cpus[1].local_clock = 42_000_000;

        unsafe { enter_sim(&mut state) };
        let now = scx_bpf_now();
        exit_sim();

        assert_eq!(now, 42_000_000);
    }

    #[test]
    fn test_bpf_ktime_get_ns() {
        let _lock = SIM_LOCK.lock().unwrap();
        let mut state = test_state(1);
        state.cpus[0].local_clock = 99_000;

        unsafe { enter_sim(&mut state) };
        let t = bpf_ktime_get_ns();
        exit_sim();

        assert_eq!(t, 99_000);
    }

    // -----------------------------------------------------------------------
    // CPU ID helpers
    // -----------------------------------------------------------------------

    #[test]
    fn test_get_smp_processor_id() {
        let _lock = SIM_LOCK.lock().unwrap();
        let mut state = test_state(4);
        state.current_cpu = CpuId(3);

        unsafe { enter_sim(&mut state) };
        assert_eq!(bpf_get_smp_processor_id(), 3);
        assert_eq!(sim_bpf_get_smp_processor_id(), 3);
        exit_sim();
    }

    #[test]
    fn test_nr_cpu_ids() {
        let _lock = SIM_LOCK.lock().unwrap();
        let mut state = test_state(8);

        unsafe { enter_sim(&mut state) };
        assert_eq!(scx_bpf_nr_cpu_ids(), 8);
        exit_sim();
    }

    // -----------------------------------------------------------------------
    // PRNG
    // -----------------------------------------------------------------------

    #[test]
    fn test_prng_deterministic() {
        let _lock = SIM_LOCK.lock().unwrap();
        let mut state = test_state(1);
        state.prng_state = 12345;

        unsafe { enter_sim(&mut state) };
        let a = sim_bpf_get_prandom_u32();
        let b = sim_bpf_get_prandom_u32();
        exit_sim();

        // Replay with same seed
        state.prng_state = 12345;
        unsafe { enter_sim(&mut state) };
        let a2 = sim_bpf_get_prandom_u32();
        let b2 = sim_bpf_get_prandom_u32();
        exit_sim();

        assert_eq!(a, a2);
        assert_eq!(b, b2);
        assert_ne!(a, b); // Successive values should differ
    }

    // -----------------------------------------------------------------------
    // Task lookup
    // -----------------------------------------------------------------------

    #[test]
    fn test_bpf_task_from_pid() {
        let _lock = SIM_LOCK.lock().unwrap();
        let mut state = test_state(1);
        let raw = register_task(&mut state, Pid(42));

        unsafe { enter_sim(&mut state) };
        let found = bpf_task_from_pid(42);
        let not_found = bpf_task_from_pid(999);
        exit_sim();

        assert_eq!(found, raw);
        assert!(not_found.is_null());

        free_task(&mut state, Pid(42));
    }

    #[test]
    fn test_get_current_task_btf() {
        let _lock = SIM_LOCK.lock().unwrap();
        let mut state = test_state(2);
        let raw = register_task(&mut state, Pid(7));
        state.cpus[0].current_task = Some(Pid(7));
        state.current_cpu = CpuId(0);

        unsafe { enter_sim(&mut state) };
        let current = bpf_get_current_task_btf();
        exit_sim();

        assert_eq!(current, raw);

        free_task(&mut state, Pid(7));
    }

    #[test]
    fn test_get_current_task_btf_idle() {
        let _lock = SIM_LOCK.lock().unwrap();
        let mut state = test_state(1);
        // No task running on CPU 0

        unsafe { enter_sim(&mut state) };
        let current = bpf_get_current_task_btf();
        exit_sim();

        assert!(current.is_null());
    }

    // -----------------------------------------------------------------------
    // scx_bpf_cpu_curr
    // -----------------------------------------------------------------------

    #[test]
    fn test_cpu_curr() {
        let _lock = SIM_LOCK.lock().unwrap();
        let mut state = test_state(2);
        let raw = register_task(&mut state, Pid(5));
        state.cpus[1].current_task = Some(Pid(5));

        unsafe { enter_sim(&mut state) };
        let p = scx_bpf_cpu_curr(1);
        let idle = scx_bpf_cpu_curr(0);
        let oob = scx_bpf_cpu_curr(99);
        exit_sim();

        assert_eq!(p, raw);
        assert!(idle.is_null());
        assert!(oob.is_null());

        free_task(&mut state, Pid(5));
    }

    // -----------------------------------------------------------------------
    // Kick CPU
    // -----------------------------------------------------------------------

    #[test]
    fn test_kick_cpu() {
        let _lock = SIM_LOCK.lock().unwrap();
        let mut state = test_state(4);

        unsafe { enter_sim(&mut state) };
        scx_bpf_kick_cpu(1, 0);
        scx_bpf_kick_cpu(3, 2); // SCX_KICK_PREEMPT
        scx_bpf_kick_cpu(1, 2); // OR flags: 0 | 2 = PREEMPT
        exit_sim();

        assert_eq!(state.kicked_cpus.len(), 2);
        assert!(state.kicked_cpus.contains_key(&CpuId(1)));
        assert!(state.kicked_cpus.contains_key(&CpuId(3)));
        // CPU 1 was kicked with 0 then 2, should have PREEMPT
        assert!(state.kicked_cpus[&CpuId(1)].contains(KickFlags::PREEMPT));
        // CPU 3 was kicked with PREEMPT
        assert!(state.kicked_cpus[&CpuId(3)].contains(KickFlags::PREEMPT));
    }

    #[test]
    fn test_kick_cpu_out_of_range() {
        let _lock = SIM_LOCK.lock().unwrap();
        let mut state = test_state(2);

        unsafe { enter_sim(&mut state) };
        scx_bpf_kick_cpu(99, 0);
        exit_sim();

        assert!(state.kicked_cpus.is_empty());
    }

    // -----------------------------------------------------------------------
    // DSQ iterator
    // -----------------------------------------------------------------------

    #[test]
    fn test_dsq_iter_empty() {
        let _lock = SIM_LOCK.lock().unwrap();
        let mut state = test_state(1);
        state.dsqs.create(DsqId(200));

        unsafe { enter_sim(&mut state) };
        let first = sim_dsq_iter_begin(200, 0);
        exit_sim();

        assert!(first.is_null());
        assert!(state.dsq_iter.is_none());
    }

    #[test]
    fn test_dsq_iter_traversal() {
        let _lock = SIM_LOCK.lock().unwrap();
        let mut state = test_state(1);
        state.dsqs.create(DsqId(200));
        state.dsqs.insert_fifo(DsqId(200), Pid(1));
        state.dsqs.insert_fifo(DsqId(200), Pid(2));
        state.dsqs.insert_fifo(DsqId(200), Pid(3));

        let raw1 = register_task(&mut state, Pid(1));
        let raw2 = register_task(&mut state, Pid(2));
        let raw3 = register_task(&mut state, Pid(3));

        unsafe { enter_sim(&mut state) };

        let p1 = sim_dsq_iter_begin(200, 0);
        assert_eq!(p1, raw1);

        let p2 = sim_dsq_iter_next();
        assert_eq!(p2, raw2);

        let p3 = sim_dsq_iter_next();
        assert_eq!(p3, raw3);

        let end = sim_dsq_iter_next();
        assert!(end.is_null());

        exit_sim();

        free_task(&mut state, Pid(1));
        free_task(&mut state, Pid(2));
        free_task(&mut state, Pid(3));
    }

    // -----------------------------------------------------------------------
    // DSQ move during iteration
    // -----------------------------------------------------------------------

    #[test]
    fn test_dsq_move() {
        let _lock = SIM_LOCK.lock().unwrap();
        let mut state = test_state(1);
        state.dsqs.create(DsqId(300));
        state.dsqs.create(DsqId(301));
        state.dsqs.insert_fifo(DsqId(300), Pid(1));
        state.dsqs.insert_fifo(DsqId(300), Pid(2));

        let raw1 = register_task(&mut state, Pid(1));
        let _raw2 = register_task(&mut state, Pid(2));

        unsafe { enter_sim(&mut state) };

        // Start iterating DSQ 300
        let p = sim_dsq_iter_begin(300, 0);
        assert_eq!(p, raw1);

        // Move pid 1 from DSQ 300 to DSQ 301
        let moved = sim_scx_bpf_dsq_move(raw1, 301, 0);
        assert!(moved);

        exit_sim();

        assert_eq!(state.dsqs.nr_queued(DsqId(300)), 1); // pid 2 remains
        assert_eq!(state.dsqs.nr_queued(DsqId(301)), 1); // pid 1 moved here

        free_task(&mut state, Pid(1));
        free_task(&mut state, Pid(2));
    }

    // -----------------------------------------------------------------------
    // scx_bpf_task_running
    // -----------------------------------------------------------------------

    #[test]
    fn test_task_running() {
        let _lock = SIM_LOCK.lock().unwrap();
        let mut state = test_state(2);
        let raw_running = register_task(&mut state, Pid(1));
        let raw_idle = register_task(&mut state, Pid(2));
        state.cpus[0].current_task = Some(Pid(1));

        unsafe { enter_sim(&mut state) };
        assert!(scx_bpf_task_running(raw_running));
        assert!(!scx_bpf_task_running(raw_idle));
        exit_sim();

        free_task(&mut state, Pid(1));
        free_task(&mut state, Pid(2));
    }

    // -----------------------------------------------------------------------
    // Advance CPU clock
    // -----------------------------------------------------------------------

    #[test]
    fn test_advance_cpu_clock() {
        let _lock = SIM_LOCK.lock().unwrap();
        let mut state = test_state(2);
        state.clock = 100_000;
        state.cpus[0].local_clock = 50_000;
        state.cpus[1].local_clock = 200_000;

        state.advance_cpu_clock(CpuId(0));
        state.advance_cpu_clock(CpuId(1));

        // CPU 0 should advance to event clock (100k > 50k)
        assert_eq!(state.cpus[0].local_clock, 100_000);
        // CPU 1 stays at its higher local clock (200k > 100k)
        assert_eq!(state.cpus[1].local_clock, 200_000);
    }

    // -----------------------------------------------------------------------
    // RCU / ref-counting stubs (just verify they don't panic)
    // -----------------------------------------------------------------------

    #[test]
    fn test_rcu_stubs_no_panic() {
        bpf_rcu_read_lock();
        bpf_rcu_read_unlock();
    }

    #[test]
    fn test_task_release_no_panic() {
        bpf_task_release(ptr::null_mut());
    }

    #[test]
    fn test_put_cpumask_no_panic() {
        scx_bpf_put_cpumask(ptr::null());
        scx_bpf_put_idle_cpumask(ptr::null());
    }

    // -----------------------------------------------------------------------
    // Cgroup stubs return NULL
    // -----------------------------------------------------------------------

    #[test]
    fn test_cgroup_stubs_return_null() {
        let _lock = SIM_LOCK.lock().unwrap();
        let mut state = test_state(1);

        unsafe { enter_sim(&mut state) };

        assert!(scx_bpf_task_cgroup(ptr::null_mut(), 0).is_null());
        assert!(bpf_cgroup_from_id(123).is_null());
        assert!(bpf_cgroup_ancestor(ptr::null_mut(), 0).is_null());
        assert!(
            bpf_cgrp_storage_get(ptr::null_mut(), ptr::null_mut(), ptr::null_mut(), 0).is_null()
        );
        assert!(
            bpf_task_storage_get(ptr::null_mut(), ptr::null_mut(), ptr::null_mut(), 0).is_null()
        );
        assert!(bpf_map_lookup_percpu_elem(ptr::null_mut(), ptr::null(), 0).is_null());

        exit_sim();
    }

    #[test]
    fn test_cgroup_acquire_release_passthrough() {
        let sentinel = 0x1234usize as *mut c_void;
        let acquired = bpf_cgroup_acquire(sentinel);
        assert_eq!(acquired, sentinel);
        bpf_cgroup_release(sentinel); // should not panic
    }

    // -----------------------------------------------------------------------
    // SDT / arena per-task storage
    // -----------------------------------------------------------------------

    #[test]
    fn test_sdt_task_alloc_data_free() {
        let _lock = SIM_LOCK.lock().unwrap();
        let mut state = test_state(1);
        let p = register_task(&mut state, Pid(100));

        // Initialize the allocator with 256 bytes per task
        let ret = unsafe { ffi::scx_task_init(256) };
        assert_eq!(ret, 0);

        // Allocate per-task data
        let data = unsafe { ffi::scx_task_alloc(p) };
        assert!(!data.is_null(), "scx_task_alloc must return non-null");

        // Retrieve the same data
        let data2 = unsafe { ffi::scx_task_data(p) };
        assert_eq!(data, data2, "scx_task_data must return same pointer");

        // Write to the allocated memory to verify it's valid
        unsafe { *(data as *mut u64) = 0xDEADBEEF };
        let read_back = unsafe { *(data2 as *mut u64) };
        assert_eq!(read_back, 0xDEADBEEF);

        // Free the data
        unsafe { ffi::scx_task_free(p) };

        // After free, data should be gone
        let data3 = unsafe { ffi::scx_task_data(p) };
        assert!(data3.is_null(), "scx_task_data must return null after free");

        free_task(&mut state, Pid(100));
    }

    #[test]
    fn test_sdt_task_multiple_tasks() {
        let _lock = SIM_LOCK.lock().unwrap();
        let mut state = test_state(2);
        let p1 = register_task(&mut state, Pid(10));
        let p2 = register_task(&mut state, Pid(20));

        let ret = unsafe { ffi::scx_task_init(64) };
        assert_eq!(ret, 0);

        let d1 = unsafe { ffi::scx_task_alloc(p1) };
        let d2 = unsafe { ffi::scx_task_alloc(p2) };
        assert!(!d1.is_null());
        assert!(!d2.is_null());
        assert_ne!(d1, d2, "different tasks must get different allocations");

        // Each task retrieves its own data
        assert_eq!(unsafe { ffi::scx_task_data(p1) }, d1);
        assert_eq!(unsafe { ffi::scx_task_data(p2) }, d2);

        // Free one, other remains
        unsafe { ffi::scx_task_free(p1) };
        assert!(unsafe { ffi::scx_task_data(p1) }.is_null());
        assert_eq!(unsafe { ffi::scx_task_data(p2) }, d2);

        unsafe { ffi::scx_task_free(p2) };
        free_task(&mut state, Pid(10));
        free_task(&mut state, Pid(20));
    }

    #[test]
    fn test_sdt_task_data_null_before_alloc() {
        let _lock = SIM_LOCK.lock().unwrap();
        let mut state = test_state(1);
        let p = register_task(&mut state, Pid(50));

        let ret = unsafe { ffi::scx_task_init(32) };
        assert_eq!(ret, 0);

        // Before alloc, data should be null
        let data = unsafe { ffi::scx_task_data(p) };
        assert!(data.is_null(), "scx_task_data before alloc must be null");

        free_task(&mut state, Pid(50));
    }
}
