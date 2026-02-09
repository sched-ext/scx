//! FFI declarations for scheduler ops and task_struct accessors.

use std::ffi::c_void;

// ---------------------------------------------------------------------------
// task_struct accessors (implemented in csrc/sim_task.c)
// ---------------------------------------------------------------------------
extern "C" {
    pub fn sim_task_alloc() -> *mut c_void;
    pub fn sim_task_free(p: *mut c_void);
    pub fn sim_task_struct_size() -> usize;

    pub fn sim_task_set_pid(p: *mut c_void, pid: i32);
    pub fn sim_task_get_pid(p: *mut c_void) -> i32;
    pub fn sim_task_set_comm(p: *mut c_void, comm: *const i8);

    pub fn sim_task_set_weight(p: *mut c_void, weight: u32);
    pub fn sim_task_get_weight(p: *mut c_void) -> u32;
    pub fn sim_task_set_static_prio(p: *mut c_void, prio: i32);
    pub fn sim_task_set_flags(p: *mut c_void, flags: u32);
    pub fn sim_task_set_nr_cpus_allowed(p: *mut c_void, nr: i32);

    pub fn sim_task_get_dsq_vtime(p: *mut c_void) -> u64;
    pub fn sim_task_set_dsq_vtime(p: *mut c_void, vtime: u64);
    pub fn sim_task_get_slice(p: *mut c_void) -> u64;
    pub fn sim_task_set_slice(p: *mut c_void, slice: u64);
    pub fn sim_task_get_scx_weight(p: *mut c_void) -> u32;
    pub fn sim_task_set_scx_weight(p: *mut c_void, weight: u32);
}

// ---------------------------------------------------------------------------
// Scheduler trait
// ---------------------------------------------------------------------------

/// Trait that wraps a compiled scheduler's ops functions.
///
/// Each method corresponds to one of the sched_ext_ops callbacks.
/// Default implementations are no-ops for optional callbacks.
pub trait Scheduler {
    /// Initialize the scheduler (ops.init). Called once before simulation.
    /// # Safety
    /// Calls into C code.
    unsafe fn init(&self) -> i32;

    /// Select a CPU for a waking task (ops.select_cpu).
    /// # Safety
    /// Calls into C code. `p` must be a valid task_struct pointer.
    unsafe fn select_cpu(&self, p: *mut c_void, prev_cpu: i32, wake_flags: u64) -> i32;

    /// Enqueue a task (ops.enqueue).
    /// # Safety
    /// Calls into C code. `p` must be a valid task_struct pointer.
    unsafe fn enqueue(&self, p: *mut c_void, enq_flags: u64);

    /// Dispatch: CPU is looking for work (ops.dispatch).
    /// # Safety
    /// Calls into C code. `prev` may be null.
    unsafe fn dispatch(&self, cpu: i32, prev: *mut c_void);

    /// A task started running (ops.running).
    /// # Safety
    /// Calls into C code. `p` must be a valid task_struct pointer.
    unsafe fn running(&self, p: *mut c_void);

    /// A task stopped running (ops.stopping).
    /// # Safety
    /// Calls into C code. `p` must be a valid task_struct pointer.
    unsafe fn stopping(&self, p: *mut c_void, runnable: bool);

    /// Enable a task for scheduling (ops.enable). Called once per task.
    /// # Safety
    /// Calls into C code. `p` must be a valid task_struct pointer.
    unsafe fn enable(&self, p: *mut c_void);

    /// A task went to sleep (ops.quiescent). Optional.
    /// # Safety
    /// Calls into C code. `p` must be a valid task_struct pointer.
    unsafe fn quiescent(&self, _p: *mut c_void, _deq_flags: u64) {}

    /// A task became runnable (ops.runnable). Optional.
    /// # Safety
    /// Calls into C code. `p` must be a valid task_struct pointer.
    unsafe fn runnable(&self, _p: *mut c_void, _enq_flags: u64) {}
}

// ---------------------------------------------------------------------------
// scx_simple scheduler FFI
// ---------------------------------------------------------------------------

extern "C" {
    fn simple_init() -> i32;
    fn simple_select_cpu(p: *mut c_void, prev_cpu: i32, wake_flags: u64) -> i32;
    fn simple_enqueue(p: *mut c_void, enq_flags: u64);
    fn simple_dispatch(cpu: i32, prev: *mut c_void);
    fn simple_running(p: *mut c_void);
    fn simple_stopping(p: *mut c_void, runnable: bool);
    fn simple_enable(p: *mut c_void);
}

/// The scx_simple scheduler compiled as userspace C.
pub struct ScxSimple;

impl Scheduler for ScxSimple {
    unsafe fn init(&self) -> i32 {
        simple_init()
    }

    unsafe fn select_cpu(&self, p: *mut c_void, prev_cpu: i32, wake_flags: u64) -> i32 {
        simple_select_cpu(p, prev_cpu, wake_flags)
    }

    unsafe fn enqueue(&self, p: *mut c_void, enq_flags: u64) {
        simple_enqueue(p, enq_flags)
    }

    unsafe fn dispatch(&self, cpu: i32, prev: *mut c_void) {
        simple_dispatch(cpu, prev)
    }

    unsafe fn running(&self, p: *mut c_void) {
        simple_running(p)
    }

    unsafe fn stopping(&self, p: *mut c_void, runnable: bool) {
        simple_stopping(p, runnable)
    }

    unsafe fn enable(&self, p: *mut c_void) {
        simple_enable(p)
    }
}
