//! Scheduler-specific probe accessors and LAVD monitor.
//!
//! [`LavdProbes`] resolves function pointers from the loaded LAVD `.so`
//! and wraps them for safe(r) access. [`LavdMonitor`] implements the
//! [`Monitor`](crate::monitor::Monitor) trait to sample LAVD state at
//! each scheduling event.

use std::ffi::c_void;

use crate::ffi::DynamicScheduler;
use crate::monitor::{Monitor, ProbeContext, ProbePoint};
use crate::types::{Pid, TimeNs};

// C function pointer types for LAVD probe functions.
type TaskProbeU16 = unsafe extern "C" fn(*mut c_void) -> u16;
type TaskProbeU64 = unsafe extern "C" fn(*mut c_void) -> u64;
type SysProbeU32 = unsafe extern "C" fn() -> u32;
type SysProbeU64 = unsafe extern "C" fn() -> u64;

/// Resolved LAVD probe function pointers.
///
/// Created from a loaded [`DynamicScheduler`] via [`LavdProbes::new`].
/// All function pointers are valid for the lifetime of the scheduler.
// Additional C function pointer types for slice boost probes.
type SysProbeU8 = unsafe extern "C" fn() -> u8;

pub struct LavdProbes {
    lat_cri_fn: TaskProbeU16,
    wait_freq_fn: TaskProbeU64,
    wake_freq_fn: TaskProbeU64,
    avg_runtime_fn: TaskProbeU64,
    lat_cri_waker_fn: TaskProbeU16,
    lat_cri_wakee_fn: TaskProbeU16,
    sys_avg_lat_cri_fn: SysProbeU32,
    sys_thr_lat_cri_fn: SysProbeU32,
    sys_nr_sched_fn: SysProbeU64,
    sys_nr_lat_cri_fn: SysProbeU64,
    // Slice boost debug probes
    sys_slice_wall_fn: SysProbeU64,
    sys_nr_queued_task_fn: SysProbeU32,
    can_boost_slice_fn: SysProbeU8,
    task_slice_wall_fn: TaskProbeU64,
}

impl LavdProbes {
    /// Resolve all LAVD probe symbols from the loaded scheduler.
    ///
    /// # Panics
    /// Panics if any required probe symbol is missing (indicates the
    /// scheduler was built without probe exports).
    pub fn new(sched: &DynamicScheduler) -> Self {
        unsafe {
            macro_rules! resolve {
                ($name:expr, $ty:ty) => {
                    *sched.get_symbol::<$ty>($name).unwrap_or_else(|| {
                        panic!(
                            "probe symbol {:?} not found",
                            std::str::from_utf8($name).unwrap_or("<invalid>")
                        )
                    })
                };
            }

            LavdProbes {
                lat_cri_fn: resolve!(b"lavd_probe_lat_cri", TaskProbeU16),
                wait_freq_fn: resolve!(b"lavd_probe_wait_freq", TaskProbeU64),
                wake_freq_fn: resolve!(b"lavd_probe_wake_freq", TaskProbeU64),
                avg_runtime_fn: resolve!(b"lavd_probe_avg_runtime", TaskProbeU64),
                lat_cri_waker_fn: resolve!(b"lavd_probe_lat_cri_waker", TaskProbeU16),
                lat_cri_wakee_fn: resolve!(b"lavd_probe_lat_cri_wakee", TaskProbeU16),
                sys_avg_lat_cri_fn: resolve!(b"lavd_probe_sys_avg_lat_cri", SysProbeU32),
                sys_thr_lat_cri_fn: resolve!(b"lavd_probe_sys_thr_lat_cri", SysProbeU32),
                sys_nr_sched_fn: resolve!(b"lavd_probe_sys_nr_sched", SysProbeU64),
                sys_nr_lat_cri_fn: resolve!(b"lavd_probe_sys_nr_lat_cri", SysProbeU64),
                // Slice boost debug probes
                sys_slice_wall_fn: resolve!(b"lavd_probe_sys_slice_wall", SysProbeU64),
                sys_nr_queued_task_fn: resolve!(b"lavd_probe_sys_nr_queued_task", SysProbeU32),
                can_boost_slice_fn: resolve!(b"lavd_probe_can_boost_slice", SysProbeU8),
                task_slice_wall_fn: resolve!(b"lavd_probe_task_slice_wall", TaskProbeU64),
            }
        }
    }

    // -- Per-task probes --

    /// Read `task_ctx.lat_cri` (final latency criticality score).
    /// # Safety
    /// `task_raw` must be a valid `task_struct` pointer with allocated
    /// per-task storage (via `scx_task_alloc`).
    pub unsafe fn lat_cri(&self, task_raw: *mut c_void) -> u16 {
        (self.lat_cri_fn)(task_raw)
    }

    /// Read `task_ctx.wait_freq` (sleep frequency EWMA).
    /// # Safety
    /// `task_raw` must be a valid `task_struct` pointer.
    pub unsafe fn wait_freq(&self, task_raw: *mut c_void) -> u64 {
        (self.wait_freq_fn)(task_raw)
    }

    /// Read `task_ctx.wake_freq` (wakeup frequency EWMA).
    /// # Safety
    /// `task_raw` must be a valid `task_struct` pointer.
    pub unsafe fn wake_freq(&self, task_raw: *mut c_void) -> u64 {
        (self.wake_freq_fn)(task_raw)
    }

    /// Read `task_ctx.avg_runtime` (average runtime per schedule).
    /// # Safety
    /// `task_raw` must be a valid `task_struct` pointer.
    pub unsafe fn avg_runtime(&self, task_raw: *mut c_void) -> u64 {
        (self.avg_runtime_fn)(task_raw)
    }

    /// Read `task_ctx.lat_cri_waker` (inherited waker latency criticality).
    /// # Safety
    /// `task_raw` must be a valid `task_struct` pointer.
    pub unsafe fn lat_cri_waker(&self, task_raw: *mut c_void) -> u16 {
        (self.lat_cri_waker_fn)(task_raw)
    }

    /// Read `task_ctx.lat_cri_wakee` (inherited wakee latency criticality).
    /// # Safety
    /// `task_raw` must be a valid `task_struct` pointer.
    pub unsafe fn lat_cri_wakee(&self, task_raw: *mut c_void) -> u16 {
        (self.lat_cri_wakee_fn)(task_raw)
    }

    // -- System-wide probes --

    /// Read `sys_stat.avg_lat_cri` (system average latency criticality).
    pub fn sys_avg_lat_cri(&self) -> u32 {
        unsafe { (self.sys_avg_lat_cri_fn)() }
    }

    /// Read `sys_stat.thr_lat_cri` (latency criticality kick threshold).
    pub fn sys_thr_lat_cri(&self) -> u32 {
        unsafe { (self.sys_thr_lat_cri_fn)() }
    }

    /// Read `sys_stat.nr_sched` (total scheduling decisions).
    pub fn sys_nr_sched(&self) -> u64 {
        unsafe { (self.sys_nr_sched_fn)() }
    }

    /// Read `sys_stat.nr_lat_cri` (number of latency-critical scheduling decisions).
    pub fn sys_nr_lat_cri(&self) -> u64 {
        unsafe { (self.sys_nr_lat_cri_fn)() }
    }

    // -- Slice boost debug probes --

    /// Read `sys_stat.slice_wall` (current target slice for the system).
    pub fn sys_slice_wall(&self) -> u64 {
        unsafe { (self.sys_slice_wall_fn)() }
    }

    /// Read `sys_stat.nr_queued_task` (number of queued tasks).
    pub fn sys_nr_queued_task(&self) -> u32 {
        unsafe { (self.sys_nr_queued_task_fn)() }
    }

    /// Check if `can_boost_slice()` returns true.
    pub fn can_boost_slice(&self) -> bool {
        unsafe { (self.can_boost_slice_fn)() != 0 }
    }

    /// Read `task_ctx.slice_wall` (task's assigned slice).
    /// # Safety
    /// `task_raw` must be a valid `task_struct` pointer.
    pub unsafe fn task_slice_wall(&self, task_raw: *mut c_void) -> u64 {
        (self.task_slice_wall_fn)(task_raw)
    }
}

/// A snapshot of LAVD state at a single probe point.
#[derive(Debug, Clone)]
pub struct LavdSnapshot {
    pub time_ns: TimeNs,
    pub pid: Pid,
    pub point: ProbePoint,
    pub lat_cri: u16,
    pub wait_freq: u64,
    pub wake_freq: u64,
    pub avg_runtime: u64,
    pub lat_cri_waker: u16,
    pub lat_cri_wakee: u16,
    pub sys_avg_lat_cri: u32,
    pub sys_thr_lat_cri: u32,
    // Slice boost debug fields
    pub sys_slice_wall: u64,
    pub sys_nr_queued_task: u32,
    pub can_boost_slice: bool,
    pub task_slice_wall: u64,
}

/// Accumulates per-task LAVD probe snapshots at each scheduling event.
///
/// After simulation, use [`final_snapshot`](LavdMonitor::final_snapshot)
/// and [`task_history`](LavdMonitor::task_history) to inspect the
/// trajectory of LAVD state.
pub struct LavdMonitor {
    probes: LavdProbes,
    /// Time series of snapshots across all tasks and events.
    pub snapshots: Vec<LavdSnapshot>,
}

impl LavdMonitor {
    /// Create a new LAVD monitor with the given probe accessors.
    pub fn new(probes: LavdProbes) -> Self {
        LavdMonitor {
            probes,
            snapshots: Vec::new(),
        }
    }

    /// Get the final (most recent) snapshot for a task.
    pub fn final_snapshot(&self, pid: Pid) -> Option<&LavdSnapshot> {
        self.snapshots.iter().rev().find(|s| s.pid == pid)
    }

    /// Get all snapshots for a task, ordered by time.
    pub fn task_history(&self, pid: Pid) -> Vec<&LavdSnapshot> {
        self.snapshots.iter().filter(|s| s.pid == pid).collect()
    }
}

impl Monitor for LavdMonitor {
    fn sample(&mut self, ctx: &ProbeContext) {
        // SAFETY: task_raw is a valid task_struct pointer from the engine,
        // with per-task storage allocated by scx_task_alloc during init_task.
        unsafe {
            self.snapshots.push(LavdSnapshot {
                time_ns: ctx.time_ns,
                pid: ctx.pid,
                point: ctx.point,
                lat_cri: self.probes.lat_cri(ctx.task_raw),
                wait_freq: self.probes.wait_freq(ctx.task_raw),
                wake_freq: self.probes.wake_freq(ctx.task_raw),
                avg_runtime: self.probes.avg_runtime(ctx.task_raw),
                lat_cri_waker: self.probes.lat_cri_waker(ctx.task_raw),
                lat_cri_wakee: self.probes.lat_cri_wakee(ctx.task_raw),
                sys_avg_lat_cri: self.probes.sys_avg_lat_cri(),
                sys_thr_lat_cri: self.probes.sys_thr_lat_cri(),
                // Slice boost debug probes
                sys_slice_wall: self.probes.sys_slice_wall(),
                sys_nr_queued_task: self.probes.sys_nr_queued_task(),
                can_boost_slice: self.probes.can_boost_slice(),
                task_slice_wall: self.probes.task_slice_wall(ctx.task_raw),
            });
        }
    }
}
