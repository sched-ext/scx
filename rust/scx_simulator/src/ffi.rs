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

    // Idle cpumask management (implemented in scx_test_cpumask.c)
    pub fn scx_test_set_idle_cpumask(cpu: i32);
    pub fn scx_bpf_test_and_clear_cpu_idle(cpu: i32) -> bool;
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
// DynamicScheduler — loads scheduler .so via libloading
// ---------------------------------------------------------------------------

/// Function pointer types for scheduler ops.
type InitFn = unsafe extern "C" fn() -> i32;
type SelectCpuFn = unsafe extern "C" fn(*mut c_void, i32, u64) -> i32;
type EnqueueFn = unsafe extern "C" fn(*mut c_void, u64);
type DispatchFn = unsafe extern "C" fn(i32, *mut c_void);
type RunningFn = unsafe extern "C" fn(*mut c_void);
type StoppingFn = unsafe extern "C" fn(*mut c_void, bool);
type EnableFn = unsafe extern "C" fn(*mut c_void);
type RunnableFn = unsafe extern "C" fn(*mut c_void, u64);
type InitTaskFn = unsafe extern "C" fn(*mut c_void, *mut c_void) -> i32;
type SetupFn = unsafe extern "C" fn(u32);

/// Resolved function pointers for a scheduler's ops.
struct SchedOps {
    init: InitFn,
    select_cpu: SelectCpuFn,
    enqueue: EnqueueFn,
    dispatch: DispatchFn,
    running: RunningFn,
    stopping: StoppingFn,
    enable: EnableFn,
    runnable: Option<RunnableFn>,
    init_task: Option<InitTaskFn>,
}

/// A scheduler loaded dynamically from a `.so` shared library.
///
/// Each instance owns a `libloading::Library` handle. When the
/// `DynamicScheduler` is dropped, the library is unloaded via `dlclose`,
/// resetting all global state in the scheduler C code.
pub struct DynamicScheduler {
    /// Keep the library alive so function pointers remain valid.
    _lib: libloading::Library,
    ops: SchedOps,
}

impl DynamicScheduler {
    /// Load the scx_simple scheduler.
    pub fn simple() -> Self {
        let path = env!("LIB_SCX_SIMPLE_SO");
        // SAFETY: The .so is built by our build.rs from known-safe C source.
        // We use RTLD_NOW for eager binding and the default RTLD_LOCAL for
        // symbol isolation.
        let lib = unsafe { libloading::Library::new(path) }
            .unwrap_or_else(|e| panic!("failed to load {path}: {e}"));

        let ops = unsafe { Self::load_ops(&lib, "simple", false) };
        Self { _lib: lib, ops }
    }

    /// Load the scx_tickless scheduler, configured for `nr_cpus` CPUs.
    ///
    /// Calls the C-side `tickless_setup()` to initialize globals, register
    /// maps, and enable CPU 0 before returning.
    pub fn tickless(nr_cpus: u32) -> Self {
        let path = env!("LIB_SCX_TICKLESS_SO");
        let lib = unsafe { libloading::Library::new(path) }
            .unwrap_or_else(|e| panic!("failed to load {path}: {e}"));

        // Call tickless_setup() to initialize globals before any ops
        unsafe {
            let setup: libloading::Symbol<SetupFn> = lib
                .get(b"tickless_setup")
                .expect("tickless_setup not found in .so");
            let setup_fn: SetupFn = *setup;
            setup_fn(nr_cpus);
        }

        let ops = unsafe { Self::load_ops(&lib, "tickless", true) };
        Self { _lib: lib, ops }
    }

    /// Look up scheduler ops function pointers from the loaded library.
    ///
    /// # Safety
    /// The library must contain the expected symbols with correct signatures.
    unsafe fn load_ops(lib: &libloading::Library, prefix: &str, has_extras: bool) -> SchedOps {
        macro_rules! get {
            ($name:expr) => {{
                let sym_name = format!("{}_{}", prefix, $name);
                let sym: libloading::Symbol<*const ()> = lib
                    .get(sym_name.as_bytes())
                    .unwrap_or_else(|e| panic!("{sym_name} not found: {e}"));
                // Copy the raw pointer out — it's valid as long as _lib lives.
                *sym
            }};
        }

        let ops = SchedOps {
            init: std::mem::transmute(get!("init")),
            select_cpu: std::mem::transmute(get!("select_cpu")),
            enqueue: std::mem::transmute(get!("enqueue")),
            dispatch: std::mem::transmute(get!("dispatch")),
            running: std::mem::transmute(get!("running")),
            stopping: std::mem::transmute(get!("stopping")),
            enable: std::mem::transmute(get!("enable")),
            runnable: if has_extras {
                Some(std::mem::transmute(get!("runnable")))
            } else {
                None
            },
            init_task: if has_extras {
                Some(std::mem::transmute(get!("init_task")))
            } else {
                None
            },
        };

        ops
    }
}

impl Scheduler for DynamicScheduler {
    unsafe fn init(&self) -> i32 {
        (self.ops.init)()
    }

    unsafe fn select_cpu(&self, p: *mut c_void, prev_cpu: i32, wake_flags: u64) -> i32 {
        (self.ops.select_cpu)(p, prev_cpu, wake_flags)
    }

    unsafe fn enqueue(&self, p: *mut c_void, enq_flags: u64) {
        (self.ops.enqueue)(p, enq_flags)
    }

    unsafe fn dispatch(&self, cpu: i32, prev: *mut c_void) {
        (self.ops.dispatch)(cpu, prev)
    }

    unsafe fn running(&self, p: *mut c_void) {
        (self.ops.running)(p)
    }

    unsafe fn stopping(&self, p: *mut c_void, runnable: bool) {
        (self.ops.stopping)(p, runnable)
    }

    unsafe fn enable(&self, p: *mut c_void) {
        (self.ops.enable)(p)
    }

    unsafe fn runnable(&self, p: *mut c_void, enq_flags: u64) {
        if let Some(f) = self.ops.runnable {
            f(p, enq_flags);
        }
    }

    unsafe fn init_task(&self, p: *mut c_void) -> i32 {
        if let Some(f) = self.ops.init_task {
            f(p, std::ptr::null_mut())
        } else {
            0
        }
    }
}
