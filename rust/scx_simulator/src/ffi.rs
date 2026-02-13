//! FFI declarations for scheduler ops and task_struct accessors.

use std::ffi::c_void;
use std::path::Path;

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

    // Address space (mm_struct pointer)
    pub fn sim_task_set_mm(p: *mut c_void, mm: *mut c_void);
    pub fn sim_task_get_mm(p: *mut c_void) -> *mut c_void;

    // Idle cpumask management (implemented in scx_test_cpumask.c)
    pub fn scx_test_set_idle_cpumask(cpu: i32);
    pub fn scx_test_clear_idle_cpumask(cpu: i32);
    pub fn scx_test_set_idle_smtmask(cpu: i32);
    pub fn scx_test_clear_idle_smtmask(cpu: i32);
    pub fn scx_bpf_test_and_clear_cpu_idle(cpu: i32) -> bool;
    pub fn bpf_cpumask_test_cpu(cpu: u32, cpumask: *const c_void) -> bool;

    // Exit info for the exit callback (implemented in sim_task.c)
    pub fn sim_get_exit_info() -> *mut c_void;

    // SDT / arena per-task storage (implemented in sim_sdt_stubs.c)
    pub fn scx_task_init(data_size: u64) -> i32;
    pub fn scx_task_alloc(p: *mut c_void) -> *mut c_void;
    pub fn scx_task_data(p: *mut c_void) -> *mut c_void;
    pub fn scx_task_free(p: *mut c_void);
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

    /// A CPU was released by a higher scheduling class (ops.cpu_release).
    /// # Safety
    /// Calls into C code.
    unsafe fn cpu_release(&self, _cpu: i32, _args: *mut c_void) {}

    /// Scheduler is being unloaded (ops.exit). Called once during shutdown.
    /// # Safety
    /// Calls into C code.
    unsafe fn exit(&self) {}

    /// Fire a pending BPF timer callback. Optional.
    /// # Safety
    /// Calls into C code.
    unsafe fn fire_timer(&self) {}
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
type CpuReleaseFn = unsafe extern "C" fn(i32, *mut c_void);
type ExitFn = unsafe extern "C" fn(*mut c_void);
type SetupFn = unsafe extern "C" fn(u32);
type FireTimerFn = unsafe extern "C" fn();

/// Resolved function pointers for a scheduler's ops.
struct SchedOps {
    init: InitFn,
    select_cpu: SelectCpuFn,
    enqueue: EnqueueFn,
    dispatch: DispatchFn,
    running: RunningFn,
    stopping: StoppingFn,
    enable: Option<EnableFn>,
    runnable: Option<RunnableFn>,
    init_task: Option<InitTaskFn>,
    cpu_release: Option<CpuReleaseFn>,
    exit: Option<ExitFn>,
    fire_timer: Option<FireTimerFn>,
}

/// Metadata about a discovered scheduler .so file.
pub struct SchedulerInfo {
    /// Scheduler name derived from the filename (e.g., "simple").
    pub name: String,
    /// Full path to the .so file.
    pub path: std::path::PathBuf,
}

/// Scan a directory for `libscx_*.so` files and return metadata for each.
///
/// Does NOT load the .so files — just discovers them. Loading happens
/// on demand via `DynamicScheduler::load`.
pub fn discover_schedulers(dir: &Path) -> Vec<SchedulerInfo> {
    let mut schedulers = Vec::new();
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return schedulers,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = match path.file_name().and_then(|n| n.to_str()) {
            Some(n) => n,
            None => continue,
        };
        if let Some(sched_name) = name
            .strip_prefix("libscx_")
            .and_then(|s| s.strip_suffix(".so"))
        {
            schedulers.push(SchedulerInfo {
                name: sched_name.to_owned(),
                path,
            });
        }
    }
    schedulers.sort_by(|a, b| a.name.cmp(&b.name));
    schedulers
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
    /// Load a scheduler from a `.so` file.
    ///
    /// - `path`: path to the `.so` file
    /// - `prefix`: symbol prefix (e.g., "simple" or "tickless")
    /// - `nr_cpus`: passed to `{prefix}_setup()` if the symbol exists
    ///
    /// Mandatory ops (`init`, `select_cpu`, etc.) panic if missing.
    /// Optional ops (`runnable`, `init_task`) become `None` if missing.
    pub fn load(path: &str, prefix: &str, nr_cpus: u32) -> Self {
        // SAFETY: The .so is built by our build system from known-safe C source.
        // We use RTLD_NOW for eager binding and the default RTLD_LOCAL for
        // symbol isolation.
        let lib = unsafe { libloading::Library::new(path) }
            .unwrap_or_else(|e| panic!("failed to load {path}: {e}"));

        // Probe for {prefix}_setup — call it if present
        unsafe {
            let setup_sym = format!("{prefix}_setup");
            if let Ok(sym) = lib.get::<SetupFn>(setup_sym.as_bytes()) {
                let setup_fn: SetupFn = *sym;
                setup_fn(nr_cpus);
            }
        }

        let ops = unsafe { Self::load_ops(&lib, prefix) };
        Self { _lib: lib, ops }
    }

    /// Load the scx_simple scheduler.
    pub fn simple() -> Self {
        let dir = env!("SCHEDULER_SO_DIR");
        Self::load(&format!("{dir}/libscx_simple.so"), "simple", 1)
    }

    /// Load the scx_tickless scheduler, configured for `nr_cpus` CPUs.
    pub fn tickless(nr_cpus: u32) -> Self {
        let dir = env!("SCHEDULER_SO_DIR");
        Self::load(&format!("{dir}/libscx_tickless.so"), "tickless", nr_cpus)
    }

    /// Load the scx_cosmos scheduler, configured for `nr_cpus` CPUs.
    pub fn cosmos(nr_cpus: u32) -> Self {
        let dir = env!("SCHEDULER_SO_DIR");
        Self::load(&format!("{dir}/libscx_cosmos.so"), "cosmos", nr_cpus)
    }

    /// Load the scx_mitosis scheduler, configured for `nr_cpus` CPUs.
    ///
    /// Mitosis is a dynamic affinity scheduler that assigns cgroups to
    /// cells with discrete CPU sets. In the simulator, all tasks belong
    /// to the root cgroup (cell 0).
    pub fn mitosis(nr_cpus: u32) -> Self {
        let dir = env!("SCHEDULER_SO_DIR");
        Self::load(&format!("{dir}/libscx_mitosis.so"), "mitosis", nr_cpus)
    }

    /// Load the scx_cosmos scheduler with NUMA topology.
    ///
    /// CPUs are grouped sequentially into `nr_nodes` NUMA nodes.
    /// `nr_cpus` must be divisible by `nr_nodes`.
    pub fn cosmos_with_numa(nr_cpus: u32, nr_nodes: u32) -> Self {
        assert!(nr_nodes > 0);
        assert!(nr_cpus >= nr_nodes);
        assert!(
            nr_cpus.is_multiple_of(nr_nodes),
            "nr_cpus ({nr_cpus}) must be divisible by nr_nodes ({nr_nodes})"
        );
        let sched = Self::cosmos(nr_cpus);
        // Call cosmos_configure_numa in the loaded .so
        type ConfigureNumaFn = unsafe extern "C" fn(u32, u32);
        unsafe {
            let sym: libloading::Symbol<ConfigureNumaFn> = sched
                ._lib
                .get(b"cosmos_configure_numa")
                .expect("cosmos_configure_numa not found");
            (sym)(nr_cpus, nr_nodes);
        }
        sched
    }

    /// Look up scheduler ops function pointers from the loaded library.
    ///
    /// Mandatory symbols panic if missing. Optional symbols become `None`.
    ///
    /// # Safety
    /// The library must contain the expected symbols with correct signatures.
    unsafe fn load_ops(lib: &libloading::Library, prefix: &str) -> SchedOps {
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

        macro_rules! try_get {
            ($name:expr) => {{
                let sym_name = format!("{}_{}", prefix, $name);
                lib.get::<*const ()>(sym_name.as_bytes())
                    .ok()
                    .map(|sym| *sym)
            }};
        }

        SchedOps {
            init: std::mem::transmute::<*const (), InitFn>(get!("init")),
            select_cpu: std::mem::transmute::<*const (), SelectCpuFn>(get!("select_cpu")),
            enqueue: std::mem::transmute::<*const (), EnqueueFn>(get!("enqueue")),
            dispatch: std::mem::transmute::<*const (), DispatchFn>(get!("dispatch")),
            running: std::mem::transmute::<*const (), RunningFn>(get!("running")),
            stopping: std::mem::transmute::<*const (), StoppingFn>(get!("stopping")),
            enable: try_get!("enable").map(|p| std::mem::transmute::<*const (), EnableFn>(p)),
            runnable: try_get!("runnable").map(|p| std::mem::transmute::<*const (), RunnableFn>(p)),
            init_task: try_get!("init_task")
                .map(|p| std::mem::transmute::<*const (), InitTaskFn>(p)),
            cpu_release: try_get!("cpu_release")
                .map(|p| std::mem::transmute::<*const (), CpuReleaseFn>(p)),
            exit: try_get!("exit").map(|p| std::mem::transmute::<*const (), ExitFn>(p)),
            fire_timer: try_get!("fire_timer")
                .map(|p| std::mem::transmute::<*const (), FireTimerFn>(p)),
        }
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
        if let Some(f) = self.ops.enable {
            f(p);
        }
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

    unsafe fn cpu_release(&self, cpu: i32, args: *mut c_void) {
        if let Some(f) = self.ops.cpu_release {
            f(cpu, args);
        }
    }

    unsafe fn exit(&self) {
        if let Some(f) = self.ops.exit {
            f(sim_get_exit_info());
        }
    }

    unsafe fn fire_timer(&self) {
        if let Some(f) = self.ops.fire_timer {
            f();
        }
    }
}
