//! scx_cosmos — a deadline + vruntime scheduler, ported from C to pure Rust.
//!
//! This is an incremental port of scx_cosmos. It implements:
//!
//! - `select_cpu`: uses `scx_bpf_select_cpu_dfl` with busy-aware dispatch
//! - `enqueue`: dual-mode — local DSQ when idle, vtime-ordered shared DSQ when busy
//! - `dispatch`: `dsq_move_to_local` + slice extension for prev task
//! - `running`: updates vtime_now + records per-task last_run_at via task storage
//! - `stopping`: charges actual used time (via scx_bpf_now delta) to dsq_vtime,
//!   accumulates exec_runtime in per-task storage
//! - `runnable`: resets exec_runtime, updates wakeup_freq via per-task storage
//! - `enable`: initializes task dsq_vtime to current vtime_now
//! - `init_task`: creates per-task context via BPF_MAP_TYPE_TASK_STORAGE
//!
//! BPF map usage:
//! - `TASK_CTX`: per-task storage for exec_runtime, wakeup_freq, last_run_at
//! - `CPU_CTX`: per-CPU array for load tracking (last_update timestamp)
//!
//! Gaps vs the full C implementation (see PORT_TODO comments throughout):
//! - No cpufreq scaling, no PMU tracking
//! - No NUMA per-node DSQs
//! - No flat/preferred idle scan, no mm_affinity
//! - No deferred wakeup timer

#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]
#![allow(non_camel_case_types, non_upper_case_globals, dead_code)]

use scx_ebpf::prelude::*;
use scx_ebpf::core_read;
use scx_ebpf::maps::{TaskStorage, PerCpuArray};

scx_ebpf::scx_ebpf_boilerplate!();

/// Generated vmlinux struct definitions with real field layouts.
mod vmlinux {
    include!(concat!(env!("OUT_DIR"), "/vmlinux.rs"));
}

// ── Per-task context ────────────────────────────────────────────────────

/// Per-task context stored in BPF_MAP_TYPE_TASK_STORAGE.
///
/// Mirrors the C cosmos `struct task_ctx`:
/// - `exec_runtime`: accumulated CPU time since last sleep (for deadline calc)
/// - `wakeup_freq`: exponentially-smoothed wakeup frequency (for slice_lag scaling)
/// - `last_run_at`: timestamp when this task last started running
/// - `last_woke_at`: timestamp of last wakeup (for wakeup_freq calculation)
#[repr(C)]
#[derive(Copy, Clone)]
struct TaskCtx {
    exec_runtime: u64,
    wakeup_freq: u64,
    last_run_at: u64,
    last_woke_at: u64,
}

/// Per-CPU context stored in BPF_MAP_TYPE_PERCPU_ARRAY.
///
/// Tracks the last scheduling update timestamp for this CPU, used for
/// load tracking and cpufreq scaling.
#[repr(C)]
#[derive(Copy, Clone)]
struct CpuCtx {
    last_update: u64,
}

// ── BPF map declarations ────────────────────────────────────────────────

/// Per-task storage map. Automatically freed when a task exits.
#[unsafe(link_section = ".maps")]
#[unsafe(no_mangle)]
static TASK_CTX: TaskStorage<TaskCtx> = TaskStorage::new();

/// Per-CPU context array (1 entry, each CPU gets its own copy).
#[unsafe(link_section = ".maps")]
#[unsafe(no_mangle)]
static CPU_CTX: PerCpuArray<CpuCtx, 1> = PerCpuArray::new();

// ── Constants ───────────────────────────────────────────────────────────

/// Shared DSQ used for deadline-mode scheduling when the system is saturated.
const SHARED_DSQ: u64 = 0;

/// Default time slice: 10us (matches C cosmos `slice_ns = 10000`).
const SLICE_NS: u64 = 10_000;

/// Maximum runtime charged to a task (bounds vruntime jumps).
const SLICE_LAG: u64 = 20_000_000;

/// SCX_TASK_QUEUED flag in scx entity flags.
const SCX_TASK_QUEUED: u32 = 1;

/// SCX_KICK_IDLE flag for kick_cpu.
const SCX_KICK_IDLE: u64 = 1;

// PORT_TODO: cpufreq performance scaling thresholds
// C reference: CPUFREQ_LOW_THRESH and CPUFREQ_HIGH_THRESH control hysteresis
// for CPU frequency scaling. update_cpu_load() / update_cpufreq() use these.

// PORT_TODO: primary_cpumask and primary_all for preferred CPU domain
// C reference: `private(COSMOS) struct bpf_cpumask __kptr *primary_cpumask`
// and `const volatile bool primary_all = true` control a subset of CPUs
// to prioritize. enable_primary_cpu() is a syscall program that sets bits.
// Requires BPF kptr support in the Rust framework.

// PORT_TODO: flat_idle_scan and preferred_idle_scan modes
// C reference: When flat_idle_scan or preferred_idle_scan is true, cosmos
// uses pick_idle_cpu_flat() which iterates CPUs in preferred order or
// round-robin to find idle cores. Requires preferred_cpus[] array and
// cpu_capacity[] array from userspace.

// PORT_TODO: NUMA support with per-node DSQs
// C reference: When numa_enabled is true, cosmos creates per-node DSQs
// (one per NUMA node) and routes tasks to their node's DSQ via
// shared_dsq(cpu) = cpu_node(cpu). Requires cpu_node_map BPF hash map.

// PORT_TODO: deferred wakeup timer
// C reference: A BPF timer (wakeup_timerfn) fires every slice_ns to kick
// idle CPUs that have pending tasks. This reduces overhead in the enqueue
// hot path by deferring wakeups. Requires BPF_MAP_TYPE_ARRAY + bpf_timer.

// PORT_TODO: PMU / perf event integration
// C reference: perf_config selects a hardware counter. scx_pmu_event_start/stop
// track per-task events. is_event_heavy() checks if a task exceeds
// perf_threshold. pick_least_busy_event_cpu() distributes event-heavy tasks.
// Requires BPF perf event support.

// PORT_TODO: mm_affinity (address space affinity)
// C reference: When mm_affinity is true and waker/wakee share the same mm,
// is_wake_affine() returns true. select_cpu uses this to keep wakee on the
// waker's CPU for cache locality.

// ── Global state ────────────────────────────────────────────────────────

/// Current global vruntime — tracks the most recent dsq_vtime seen.
static mut VTIME_NOW: u64 = 0;

/// Number of CPUs on this system, set in init().
static mut NR_CPU_IDS: u32 = 0;

// PORT_TODO: Global cpu_util and busy_threshold for is_system_busy()
// C reference: `volatile u64 cpu_util` is the current CPU utilization
// (range [0..1024]) set by userspace. `const volatile u64 busy_threshold`
// is the threshold. is_system_busy() returns cpu_util >= busy_threshold.
// For now we approximate: system is busy when the shared DSQ has queued tasks.

// PORT_TODO: smt_enabled and avoid_smt for SMT-aware idle scanning
// C reference: When smt_enabled is true, cosmos uses scx_bpf_get_idle_smtmask()
// and is_smt_contended() to prefer full-idle SMT cores. avoid_smt controls
// whether to pass SCX_PICK_IDLE_CORE to scx_bpf_select_cpu_and().

// PORT_TODO: no_wake_sync for disabling synchronous wakeup hints
// C reference: `const volatile bool no_wake_sync` — when true, the
// SCX_WAKE_SYNC bit is cleared from wake_flags before pick_idle_cpu().

// PORT_TODO: cpufreq_enabled for CPU frequency scaling
// C reference: `const volatile bool cpufreq_enabled = true` — controls
// whether update_cpu_load() and update_cpufreq() are called in running/stopping.

// ── Helpers ─────────────────────────────────────────────────────────────

/// Write a u64 field in a kernel struct at a known compile-time offset.
#[inline(always)]
unsafe fn write_field_u64(base: *mut task_struct, offset: usize, val: u64) {
    let ptr = (base as *mut u8).add(offset) as *mut u64;
    core::ptr::write_volatile(ptr, val);
}

/// Compute a weight-scaled time slice: slice_ns * weight / 100.
/// This matches C cosmos `task_slice()` = `scale_by_task_weight(p, slice_ns)`.
#[inline(always)]
fn task_slice(weight: u64) -> u64 {
    if weight > 0 { (SLICE_NS * weight) / 100 } else { SLICE_NS }
}

/// Read the task's scx.weight, defaulting to 100 (NICE 0).
#[inline(always)]
fn read_weight(p: *mut task_struct) -> u64 {
    if let Ok(w) = core_read!(vmlinux::task_struct, p, scx.weight) {
        w as u64
    } else {
        100
    }
}

/// Approximate check for system saturation.
///
/// Returns true if there are tasks queued in the shared DSQ, indicating
/// the system has more runnable tasks than idle CPUs.
// PORT_TODO: Real is_system_busy() using cpu_util from userspace
// C reference: `is_system_busy()` returns `cpu_util >= busy_threshold`
// where cpu_util is set by the userspace daemon based on /proc/stat.
// Our approximation checks if the shared DSQ has tasks queued.
#[inline(always)]
fn is_system_busy() -> bool {
    kfuncs::dsq_nr_queued(SHARED_DSQ) > 0
}

/// Exponential moving average update for wakeup frequency tracking.
///
/// Computes `update_freq(old_freq, delta_t)` matching the C cosmos logic:
///   new_freq = (1024 * NSEC_PER_MSEC) / delta_t
///   smoothed = (old_freq + new_freq) / 2
///
/// Capped at 1024 to prevent overflow.
#[inline(always)]
fn update_freq(old_freq: u64, delta_ns: u64) -> u64 {
    // Avoid division by zero; if delta is tiny, cap at max frequency.
    if delta_ns == 0 {
        return 1024;
    }
    // 1024 * 1_000_000 = 1024 * NSEC_PER_MSEC
    let new_freq = (1024 * 1_000_000) / delta_ns;
    let smoothed = (old_freq + new_freq) / 2;
    if smoothed > 1024 { 1024 } else { smoothed }
}

// ── Scheduler callbacks ─────────────────────────────────────────────────

/// select_cpu: find an idle CPU for the task.
///
/// Uses `scx_bpf_select_cpu_dfl` for idle CPU selection.
/// - If idle CPU found: dispatch directly to local DSQ (any saturation level)
/// - If no idle CPU and not busy: dispatch to local DSQ (round-robin)
/// - If no idle CPU and busy: do NOT dispatch, let enqueue() handle
///   deadline-mode dispatch to the shared DSQ
///
/// This matches the C cosmos behavior:
///   `if (cpu >= 0 || !is_busy) dsq_insert(LOCAL, ...);`
// PORT_TODO: Enhanced select_cpu with pick_idle_cpu() strategies
// C reference: cosmos_select_cpu() calls pick_idle_cpu() which tries multiple
// strategies: (1) flat/preferred scan when enabled, (2) wake-affine optimization
// for hybrid cores, (3) scx_bpf_select_cpu_and() with primary cpumask and
// avoid_smt flag, (4) fallback scx_bpf_select_cpu_dfl(). It also handles
// mm_affinity (same address space) and perf_config (event-heavy tasks).
#[inline(always)]
pub fn on_select_cpu(p: *mut task_struct, prev_cpu: i32, wake_flags: u64) -> i32 {
    let mut is_idle: bool = false;
    let cpu = kfuncs::select_cpu_dfl(p, prev_cpu, wake_flags, &mut is_idle);

    // Dispatch to local DSQ when:
    // 1. An idle CPU was found (always dispatch, regardless of busy state), or
    // 2. No idle CPU but system is not busy (round-robin mode)
    //
    // When busy and no idle CPU, don't dispatch — let enqueue() handle
    // deadline-mode dispatch to the shared DSQ for fairness.
    // C: if (cpu >= 0 || !is_busy) dsq_insert(LOCAL, ...);
    if is_idle || !is_system_busy() {
        let weight = read_weight(p);
        let slice = task_slice(weight);
        kfuncs::dsq_insert(p, kfuncs::SCX_DSQ_LOCAL, slice, 0);
    }

    // Return the idle CPU if found, otherwise prev_cpu.
    // C: return cpu >= 0 ? cpu : prev_cpu;
    if is_idle { cpu } else { prev_cpu }
}

/// enqueue: dual-mode dispatch — local round-robin or shared DSQ deadline.
///
/// When the system is NOT busy (no tasks queued in shared DSQ), dispatch
/// directly to the local DSQ in round-robin mode for low latency.
///
/// When the system IS busy, dispatch to the shared DSQ with vtime-based
/// ordering (deadline mode) for fairness under contention.
///
/// If select_cpu already dispatched the task (via SCX_DSQ_LOCAL), this
/// callback is not invoked by the kernel.
// PORT_TODO: Migration attempt in enqueue when task should migrate
// C reference: cosmos_enqueue() calls task_should_migrate() to check if
// ops.select_cpu() was NOT called and task is not running. If so, it calls
// pick_idle_cpu() to find an idle CPU and dispatches via SCX_DSQ_LOCAL_ON.
// Then calls wakeup_cpu() to kick the target CPU.
// BPF verifier constraint: kfunc calls (task_cpu, task_running) consume
// the trusted_ptr to p, preventing subsequent kfunc calls with the same
// pointer. This makes the migration pattern difficult without RCU read lock.
#[inline(always)]
pub fn on_enqueue(p: *mut task_struct, enq_flags: u64) {
    // Read ALL fields we need BEFORE any kfunc calls.
    // The BPF verifier invalidates the trusted pointer after kfunc calls
    // that consume it (dsq_insert, task_cpu, task_running, etc.).
    let vtime = if let Ok(v) = core_read!(vmlinux::task_struct, p, scx.dsq_vtime) {
        v
    } else {
        unsafe { VTIME_NOW }
    };

    let weight = read_weight(p);
    let slice = task_slice(weight);

    // When system is not saturated, use round-robin local dispatch.
    // This avoids shared DSQ contention and gives lower latency.
    // C: if (!is_system_busy()) { dsq_insert(LOCAL, ...); return; }
    if !is_system_busy() {
        kfuncs::dsq_insert(p, kfuncs::SCX_DSQ_LOCAL, slice, enq_flags);
        return;
    }

    // Compute deadline using exec_runtime from per-task storage.
    // C: task_dl() = dsq_vtime + scale_inverse(exec_runtime)
    // Tasks with more accumulated runtime get higher (later) deadlines,
    // prioritizing interactive tasks that sleep frequently.
    //
    // Read both exec_runtime and wakeup_freq in a single lookup to avoid
    // the LLVM BPF backend register clobber bug (see helpers.rs docs).
    let (exec_runtime, wakeup_freq) = if let Some(tctx) = TASK_CTX.get(p as *mut u8) {
        let tctx = unsafe { tctx.as_ref() };
        (tctx.exec_runtime, tctx.wakeup_freq)
    } else {
        (0, 0)
    };
    let deadline = if weight > 0 {
        vtime.wrapping_add(exec_runtime * 100 / weight)
    } else {
        vtime.wrapping_add(exec_runtime)
    };

    // No idle CPU found — use deadline-mode dispatch to the shared DSQ.
    // Clamp vtime so tasks don't accumulate too much credit from sleeping.
    // C: vtime_min = vtime_now - scale_by_task_weight(p, slice_lag)
    let vtime_now = unsafe { VTIME_NOW };

    // Scale slice_lag by wakeup frequency: tasks that wake up often get
    // more vtime credit (larger effective slice_lag).
    // C: wakeup_freq_lag = slice_lag + slice_lag * tctx->wakeup_freq / 1024
    let effective_lag = SLICE_LAG + SLICE_LAG * wakeup_freq / 1024;

    let vsleep_max = if weight > 0 { (effective_lag * weight) / 100 } else { effective_lag };
    let vtime_min = vtime_now.wrapping_sub(vsleep_max);
    let clamped_deadline = if deadline < vtime_min { vtime_min } else { deadline };

    // Write clamped vtime back if it changed (after all reads are done).
    if clamped_deadline != vtime {
        let offset = core::mem::offset_of!(vmlinux::task_struct, scx.dsq_vtime);
        unsafe { write_field_u64(p, offset, clamped_deadline); }
    }

    kfuncs::dsq_insert_vtime(p, SHARED_DSQ, slice, clamped_deadline, enq_flags);
}

/// dispatch: consume from the shared DSQ.
///
/// If the shared DSQ has a task, move it to the local CPU. Otherwise,
/// if the previous task is still queued (expired its slice but no
/// contention), extend its slice to avoid unnecessary context switches.
#[inline(always)]
pub fn on_dispatch(_cpu: i32, prev: *mut task_struct) {
    if kfuncs::dsq_move_to_local(SHARED_DSQ) {
        return;
    }

    // If the previous task's time slice expired but no other task is
    // waiting, let it continue with a fresh slice.
    // C: if (prev && (prev->scx.flags & SCX_TASK_QUEUED))
    //        prev->scx.slice = task_slice(prev);
    if !prev.is_null() {
        // Read flags and weight together as a u64 to avoid the LLVM BPF
        // backend bug where consecutive bpf_probe_read_kernel calls with
        // the same size arg skip re-materializing r2.
        // scx.flags is at offset 816 (u32), scx.weight is at offset 820 (u32).
        // Reading 8 bytes at offset 816 gets both in one call.
        let base = prev as *const u8;
        let flags_offset = core::mem::offset_of!(vmlinux::task_struct, scx.flags);
        let src = unsafe { base.add(flags_offset) as *const u64 };
        if let Ok(flags_and_weight) = unsafe { scx_ebpf::helpers::probe_read_kernel(src) } {
            let flags = flags_and_weight as u32;
            let weight = (flags_and_weight >> 32) as u64;
            if flags & SCX_TASK_QUEUED != 0 {
                let slice = task_slice(weight);
                let offset = core::mem::offset_of!(vmlinux::task_struct, scx.slice);
                unsafe { write_field_u64(prev, offset, slice); }
            }
        }
    }
}

/// runnable: called when a task becomes runnable (wakeup or new fork).
///
/// Resets exec_runtime and updates wakeup frequency in per-task storage.
/// C reference: cosmos_runnable() does:
///   tctx->exec_runtime = 0;
///   delta_t = now - tctx->last_woke_at;
///   tctx->wakeup_freq = update_freq(tctx->wakeup_freq, delta_t);
///   tctx->wakeup_freq = MIN(tctx->wakeup_freq, 1024);
///   tctx->last_woke_at = now;
#[inline(always)]
pub fn on_runnable(p: *mut task_struct, _enq_flags: u64) {
    let now = kfuncs::now();
    if let Some(mut tctx) = TASK_CTX.get(p as *mut u8) {
        let tctx = unsafe { tctx.as_mut() };
        // Reset accumulated runtime — task just woke up.
        tctx.exec_runtime = 0;
        // Update wakeup frequency using time since last wakeup.
        let delta = now.wrapping_sub(tctx.last_woke_at);
        tctx.wakeup_freq = update_freq(tctx.wakeup_freq, delta);
        tctx.last_woke_at = now;
    }
}

/// running: update vtime_now and record run start time in per-task storage.
///
/// Advances the global vruntime to track the most recent task's vtime.
/// Records the timestamp in per-task storage for accurate time-slice
/// charging in stopping().
// PORT_TODO: cpufreq update on running
// C reference: cosmos_running() calls update_cpufreq(scx_bpf_task_cpu(p))
// which reads per-CPU perf_lvl and applies it via scx_bpf_cpuperf_set().
// Also calls scx_pmu_event_start() when perf_config is set.
#[inline(always)]
pub fn on_running(p: *mut task_struct) {
    // Record run start time in per-task storage.
    // C: tctx->last_run_at = scx_bpf_now();
    let now = kfuncs::now();
    if let Some(mut tctx) = TASK_CTX.get(p as *mut u8) {
        unsafe { tctx.as_mut().last_run_at = now; }
    }

    // Update per-CPU context timestamp.
    let cctx = CPU_CTX.get_ptr_mut(0);
    if !cctx.is_null() {
        unsafe { (*cctx).last_update = now; }
    }

    // Update current system's vruntime.
    // C: if (time_before(vtime_now, p->scx.dsq_vtime))
    //        vtime_now = p->scx.dsq_vtime;
    if let Ok(dsq_vtime) = core_read!(vmlinux::task_struct, p, scx.dsq_vtime) {
        unsafe {
            if VTIME_NOW < dsq_vtime {
                VTIME_NOW = dsq_vtime;
            }
        }
    }
}

/// stopping: charge the actual used time slice and update dsq_vtime.
///
/// Uses the per-task last_run_at timestamp to compute the real time delta,
/// capped at slice_ns. Advances dsq_vtime inversely proportional to
/// weight (higher weight = slower vtime advancement = more CPU time).
/// Also accumulates exec_runtime in per-task storage for deadline calculation.
// PORT_TODO: Update per-CPU load for cpufreq scaling
// C reference: update_cpu_load(p, slice) computes perf_lvl as
// MIN(slice * SCX_CPUPERF_ONE / delta_t, SCX_CPUPERF_ONE) and
// smooths it with EWMA. Requires per-CPU context map.
// PORT_TODO: PMU counter update in stopping
// C reference: scx_pmu_event_stop(p) + update_counters(p, tctx, cpu)
// reads perf event delta and stores in per-task and per-CPU contexts.
#[inline(always)]
pub fn on_stopping(p: *mut task_struct, _runnable: bool) {
    // Read ALL fields before writing.
    let old_vtime = if let Ok(v) = core_read!(vmlinux::task_struct, p, scx.dsq_vtime) {
        v
    } else {
        return;
    };

    let weight = read_weight(p);

    // Compute actual time slice used from per-task last_run_at, and
    // update exec_runtime, all in a single TASK_CTX lookup to avoid
    // the LLVM BPF backend register clobber bug (see helpers.rs docs).
    // C: slice = MIN(scx_bpf_now() - tctx->last_run_at, slice_ns);
    // C: tctx->exec_runtime = MIN(tctx->exec_runtime + slice, slice_lag)
    let now = kfuncs::now();
    let slice = if let Some(mut tctx) = TASK_CTX.get(p as *mut u8) {
        let tctx = unsafe { tctx.as_mut() };
        let delta = now.wrapping_sub(tctx.last_run_at);
        let s = if delta < SLICE_NS { delta } else { SLICE_NS };
        // Update exec_runtime while we have the pointer.
        let new_runtime = tctx.exec_runtime + s;
        tctx.exec_runtime = if new_runtime > SLICE_LAG { SLICE_LAG } else { new_runtime };
        s
    } else {
        SLICE_NS
    };

    // C: p->scx.dsq_vtime += scale_by_task_weight_inverse(p, slice);
    // scale_by_task_weight_inverse(p, v) = v * 100 / weight
    let vtime_delta = if weight > 0 { slice * 100 / weight } else { slice };
    let new_vtime = old_vtime.wrapping_add(vtime_delta);

    let offset = core::mem::offset_of!(vmlinux::task_struct, scx.dsq_vtime);
    unsafe { write_field_u64(p, offset, new_vtime); }
}

/// enable: initialize a task's dsq_vtime to the current global vruntime.
///
/// Direct port of the C cosmos_enable callback.
#[inline(always)]
pub fn on_enable(p: *mut task_struct) {
    let vtime_now = unsafe { VTIME_NOW };
    let offset = core::mem::offset_of!(vmlinux::task_struct, scx.dsq_vtime);
    unsafe { write_field_u64(p, offset, vtime_now); }
}

/// init_task: create per-task context via BPF task storage.
///
/// C reference: cosmos_init_task creates per-task storage via
/// bpf_task_storage_get(&task_ctx_stor, ..., BPF_LOCAL_STORAGE_GET_F_CREATE).
#[inline(always)]
pub fn on_init_task(p: *mut task_struct, _args: *mut core::ffi::c_void) -> i32 {
    // Create per-task storage (zero-initialized by the kernel).
    if TASK_CTX.get_or_create(p as *mut u8).is_none() {
        return -12; // ENOMEM
    }
    0
}

/// init: create the shared DSQ and record nr_cpu_ids.
// PORT_TODO: Per-node DSQ creation for NUMA
// C reference: When numa_enabled is true, cosmos_init creates one DSQ per
// NUMA node via `bpf_for(node, 0, nr_node_ids) { create_dsq(node, node); }`.
// Each CPU dispatches to its node's DSQ via shared_dsq(cpu) = cpu_node(cpu).
// PORT_TODO: Deferred wakeup timer initialization
// C reference: When deferred_wakeups is true, cosmos_init creates a BPF timer
// that fires every slice_ns and kicks idle CPUs with pending local DSQ tasks.
// PORT_TODO: PMU installation
// C reference: When perf_config is set, cosmos_init calls scx_pmu_install().
#[inline(always)]
pub fn on_init() -> i32 {
    // Record the number of CPUs for bounds checking.
    unsafe { NR_CPU_IDS = kfuncs::nr_cpu_ids(); }

    let err = kfuncs::create_dsq(SHARED_DSQ, -1);
    if err != 0 {
        scx_ebpf::scx_bpf_error!("cosmos: failed to create shared DSQ");
        return err;
    }
    0
}

/// exit: no-op for now.
// PORT_TODO: PMU cleanup and UEI_RECORD
// C reference: cosmos_exit() calls scx_pmu_uninstall() when perf_config
// is set, and UEI_RECORD(uei, ei) to save exit info for userspace.
#[inline(always)]
pub fn on_exit(_ei: *mut scx_exit_info) {}

// ── Registration ────────────────────────────────────────────────────────

scx_ebpf::scx_ops_define! {
    name: "cosmos",
    timeout_ms: 5000,
    select_cpu: on_select_cpu,
    enqueue: on_enqueue,
    dispatch: on_dispatch,
    runnable: on_runnable,
    running: on_running,
    stopping: on_stopping,
    enable: on_enable,
    init_task: on_init_task,
    init: on_init,
    exit: on_exit,
}
