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

use crate::cpu::SimCpu;
use crate::dsq::DsqManager;
use crate::ffi;
use crate::fmt::FmtN;
use crate::trace::Trace;
use crate::types::{CpuId, DsqId, Pid, TimeNs, Vtime};

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
    /// Uses Lamport-style max: `local_clock = max(local_clock, clock)`.
    /// When there's no scheduler overhead, this keeps local clocks in sync
    /// with the event queue. With overhead, local clocks advance further.
    pub fn advance_cpu_clock(&mut self, cpu: CpuId) {
        let idx = cpu.0 as usize;
        self.cpus[idx].local_clock = self.cpus[idx].local_clock.max(self.clock);
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
#[no_mangle]
pub extern "C" fn scx_bpf_select_cpu_dfl(
    _p: *mut c_void,
    prev_cpu: i32,
    _wake_flags: u64,
    is_idle: *mut bool,
) -> i32 {
    with_sim(|sim| {
        let prev = CpuId(prev_cpu as u32);
        // Prefer prev_cpu if it's idle
        if (prev.0 as usize) < sim.cpus.len() && sim.cpu_is_idle(prev) {
            unsafe { *is_idle = true };
            debug!(
                prev_cpu,
                cpu = prev_cpu,
                idle = true,
                "kfunc select_cpu_dfl"
            );
            return prev_cpu;
        }
        // Find any idle CPU
        if let Some(cpu) = sim.find_any_idle_cpu() {
            unsafe { *is_idle = true };
            debug!(prev_cpu, cpu = cpu.0, idle = true, "kfunc select_cpu_dfl");
            return cpu.0 as i32;
        }
        unsafe { *is_idle = false };
        debug!(
            prev_cpu,
            cpu = prev_cpu,
            idle = false,
            "kfunc select_cpu_dfl"
        );
        prev_cpu
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
    })
}

/// Insert a task into a DSQ with vtime ordering.
///
/// Deferred like `scx_bpf_dsq_insert` — see its doc comment.
#[no_mangle]
pub extern "C" fn scx_bpf_dsq_insert_vtime(
    p: *mut c_void,
    dsq_id: u64,
    slice: u64,
    vtime: u64,
    enq_flags: u64,
) {
    with_sim(|sim| {
        let pid = sim.task_pid_from_raw(p);
        unsafe { ffi::sim_task_set_slice(p, slice) };
        debug!(pid = pid.0, dsq_id, slice = %FmtN(slice), vtime, "kfunc dsq_insert_vtime");

        sim.pending_dispatch = Some(PendingDispatch {
            pid,
            dsq_id: DsqId(dsq_id),
            enq_flags,
            vtime: Some(Vtime(vtime)),
        });
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
        result
    })
}

/// Query the number of tasks queued in a DSQ.
#[no_mangle]
pub extern "C" fn scx_bpf_dsq_nr_queued(dsq_id: u64) -> i32 {
    with_sim(|sim| {
        let n = sim.dsqs.nr_queued(DsqId(dsq_id)) as i32;
        debug!(dsq_id, n, "kfunc dsq_nr_queued");
        n
    })
}

/// Kick a CPU (send scheduling IPI). In the simulator, this is mostly a no-op
/// for now. The simulation engine handles idle CPU dispatch separately.
#[no_mangle]
pub extern "C" fn scx_bpf_kick_cpu(_cpu: i32, _flags: u64) {
    // Phase 2: generate dispatch events for kicked CPUs
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
#[no_mangle]
pub extern "C" fn scx_bpf_task_cpu(_p: *const c_void) -> i32 {
    with_sim(|sim| sim.current_cpu.0 as i32)
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

/// Reenqueue all tasks from the local DSQ. No-op for now.
#[no_mangle]
pub extern "C" fn scx_bpf_reenqueue_local() -> u32 {
    0
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

#[no_mangle]
pub extern "C" fn bpf_task_from_pid(_pid: i32) -> *mut c_void {
    ptr::null_mut()
}

/// Get the current task's task_struct pointer (for the CPU we're running on).
///
/// Used by tickless in `is_wake_sync()` to check the waker's flags.
#[no_mangle]
pub extern "C" fn bpf_get_current_task_btf() -> *mut c_void {
    with_sim(|sim| {
        let cpu = sim.current_cpu;
        if let Some(pid) = sim.cpus[cpu.0 as usize].current_task {
            if let Some(&raw) = sim.task_pid_to_raw.get(&pid) {
                return raw as *mut c_void;
            }
        }
        ptr::null_mut()
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
