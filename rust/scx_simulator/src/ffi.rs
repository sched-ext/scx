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

    pub fn sim_task_setup_cpus_ptr(p: *mut c_void);
    pub fn sim_task_get_scx_flags(p: *mut c_void) -> u32;
    pub fn sim_task_set_scx_flags(p: *mut c_void, flags: u32);
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

    /// Initialize a task (ops.init_task). Called once per task at creation.
    /// # Safety
    /// Calls into C code. `p` must be a valid task_struct pointer.
    unsafe fn init_task(&self, _p: *mut c_void) -> i32 {
        0
    }
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

// ---------------------------------------------------------------------------
// scx_tickless scheduler FFI
// ---------------------------------------------------------------------------

extern "C" {
    fn tickless_init() -> i32;
    fn tickless_select_cpu(p: *mut c_void, prev_cpu: i32, wake_flags: u64) -> i32;
    fn tickless_enqueue(p: *mut c_void, enq_flags: u64);
    fn tickless_dispatch(cpu: i32, prev: *mut c_void);
    fn tickless_running(p: *mut c_void);
    fn tickless_stopping(p: *mut c_void, runnable: bool);
    fn tickless_enable(p: *mut c_void);
    fn tickless_runnable(p: *mut c_void, enq_flags: u64);
    fn tickless_init_task(p: *mut c_void, args: *mut c_void) -> i32;

    // Tickless global variables
    static mut nr_cpu_ids: u32;
    static mut smt_enabled: bool;
    static mut slice_ns: u64;
    static mut tick_freq: u64;
    static mut preferred_cpus: [u64; 1024];

    // Primary CPU setup (takes struct cpu_arg *)
    fn enable_primary_cpu(input: *mut c_void) -> i32;

    // Map registration
    fn tickless_register_maps();
}

/// Matches the C `struct cpu_arg` from tickless intf.h.
#[repr(C)]
struct CpuArg {
    cpu_id: i32,
}

/// The scx_tickless scheduler compiled as userspace C.
pub struct ScxTickless;

impl ScxTickless {
    /// Set up tickless global state (nr_cpu_ids, slice, preferred_cpus)
    /// and enable CPU 0 as the primary scheduling CPU.
    ///
    /// # Safety
    /// Must be called before `init()` and before any scheduler ops.
    pub unsafe fn setup(&self, num_cpus: u32) {
        nr_cpu_ids = num_cpus;
        smt_enabled = false;
        // 20ms default slice
        slice_ns = 20_000_000;
        // Use simulated time, set tick_freq to avoid CONFIG_HZ dependency
        tick_freq = 250;

        // Set preferred CPU ordering (identity mapping)
        for i in 0..num_cpus.min(1024) {
            preferred_cpus[i as usize] = i as u64;
        }

        // Register BPF maps with test infrastructure
        tickless_register_maps();

        // Enable CPU 0 as primary
        let mut arg = CpuArg { cpu_id: 0 };
        enable_primary_cpu(&mut arg as *mut CpuArg as *mut c_void);
    }
}

impl Scheduler for ScxTickless {
    unsafe fn init(&self) -> i32 {
        tickless_init()
    }

    unsafe fn select_cpu(&self, p: *mut c_void, prev_cpu: i32, wake_flags: u64) -> i32 {
        tickless_select_cpu(p, prev_cpu, wake_flags)
    }

    unsafe fn enqueue(&self, p: *mut c_void, enq_flags: u64) {
        tickless_enqueue(p, enq_flags)
    }

    unsafe fn dispatch(&self, cpu: i32, prev: *mut c_void) {
        tickless_dispatch(cpu, prev)
    }

    unsafe fn running(&self, p: *mut c_void) {
        tickless_running(p)
    }

    unsafe fn stopping(&self, p: *mut c_void, runnable: bool) {
        tickless_stopping(p, runnable)
    }

    unsafe fn enable(&self, p: *mut c_void) {
        tickless_enable(p)
    }

    unsafe fn runnable(&self, p: *mut c_void, enq_flags: u64) {
        tickless_runnable(p, enq_flags)
    }

    unsafe fn init_task(&self, p: *mut c_void) -> i32 {
        tickless_init_task(p, std::ptr::null_mut())
    }
}
