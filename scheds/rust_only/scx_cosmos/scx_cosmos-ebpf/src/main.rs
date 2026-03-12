//! scx_cosmos — a deadline + vruntime scheduler, ported from C to pure Rust.
//!
//! This is a work-in-progress incremental port of scx_cosmos. Currently
//! implements the simpler callbacks (init, exit, running, stopping, enable)
//! with stub/simplified versions of the complex ones (select_cpu, enqueue,
//! dispatch, runnable).

#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]
#![allow(non_camel_case_types, non_upper_case_globals, dead_code)]

use scx_ebpf::prelude::*;
use scx_ebpf::core_read;

scx_ebpf::scx_ebpf_boilerplate!();

/// Generated vmlinux struct definitions with real field layouts.
mod vmlinux {
    include!(concat!(env!("OUT_DIR"), "/vmlinux.rs"));
}

// ── Constants ───────────────────────────────────────────────────────────

/// Shared DSQ used when system is saturated (deadline mode).
const SHARED_DSQ: u64 = 0;

/// Default time slice: 10us (matches C cosmos `slice_ns = 10000`).
/// Note: the C code value is 10000 ns = 10us; the C global `slice_ns`
/// is the per-task base slice that gets scaled by weight.
const SLICE_NS: u64 = 10_000;

/// Maximum runtime charged to a task (bounds exec_runtime accumulation).
const SLICE_LAG: u64 = 20_000_000;

/// SCX_CPUPERF_ONE: full performance level.
const SCX_CPUPERF_ONE: u64 = 1024;

/// PF_IDLE flag from kernel task_struct.flags.
const PF_IDLE: u32 = 0x0000_0002;

/// SCX_TASK_QUEUED flag in scx entity flags.
const SCX_TASK_QUEUED: u32 = 1;

// ── Global state ────────────────────────────────────────────────────────

/// Current global vruntime — tracks the most recent dsq_vtime seen.
static mut VTIME_NOW: u64 = 0;

// ── Helper: min of two u64 ──────────────────────────────────────────────

#[inline(always)]
fn min_u64(a: u64, b: u64) -> u64 {
    if a < b { a } else { b }
}

// ── Scheduler callbacks ─────────────────────────────────────────────────

/// select_cpu: simplified — just return prev_cpu.
///
/// TODO: Port the full idle-CPU selection logic from C cosmos (pick_idle_cpu,
/// flat scan, preferred scan, mm affinity, perf-event CPU selection).
#[inline(always)]
pub fn on_select_cpu(p: *mut task_struct, prev_cpu: i32, _wake_flags: u64) -> i32 {
    prev_cpu
}

/// enqueue: simplified — insert all tasks into the shared DSQ with FIFO ordering.
///
/// TODO: Port the full enqueue logic with:
///  - vtime-based insertion (dsq_insert_vtime) for busy systems
///  - per-CPU local DSQ dispatch for non-busy systems
///  - perf-event-heavy task migration
///  - idle CPU selection and direct dispatch
#[inline(always)]
pub fn on_enqueue(p: *mut task_struct, enq_flags: u64) {
    kfuncs::dsq_insert(p, SHARED_DSQ, SLICE_NS, enq_flags);
}

/// dispatch: consume from the shared DSQ.
///
/// TODO: Port the full dispatch logic which also checks prev->scx.flags
/// for SCX_TASK_QUEUED and extends the slice when no other task wants the CPU.
#[inline(always)]
pub fn on_dispatch(_cpu: i32, _prev: *mut task_struct) {
    kfuncs::dsq_move_to_local(SHARED_DSQ);
}

/// runnable: stub — resets exec_runtime and updates wakeup frequency in full cosmos.
///
/// TODO: Port once per-task BPF map storage is available. The full implementation
/// tracks wakeup frequency via EWMA.
#[inline(always)]
pub fn on_runnable(_p: *mut task_struct, _enq_flags: u64) {
    // In the full port, this would:
    //  1. Look up task_ctx from BPF_MAP_TYPE_TASK_STORAGE
    //  2. Reset tctx.exec_runtime = 0
    //  3. Compute wakeup frequency from time since last wake
}

/// running: record the timestamp when a task starts running and update vtime_now.
///
/// Simplified version that updates vtime_now from the task's dsq_vtime
/// but skips cpufreq and PMU logic (which need per-CPU map storage).
#[inline(always)]
pub fn on_running(p: *mut task_struct) {
    // Update the global vruntime to track the most recent task's vtime.
    // In the C code: if (time_before(vtime_now, p->scx.dsq_vtime))
    //                    vtime_now = p->scx.dsq_vtime;
    if let Ok(dsq_vtime) = core_read!(vmlinux::task_struct, p, scx.dsq_vtime) {
        unsafe {
            if VTIME_NOW < dsq_vtime {
                VTIME_NOW = dsq_vtime;
            }
        }
    }

    // TODO: Save tctx->last_run_at = kfuncs::now() (needs task storage map)
    // TODO: Call update_cpufreq(kfuncs::task_cpu(p)) (needs per-CPU map)
    // TODO: Start PMU event capture if perf_config is set
}

/// stopping: called when a task is being descheduled.
///
/// Simplified version that only updates the task's dsq_vtime.
/// Skips PMU counters, cpufreq load tracking, and exec_runtime
/// (which need BPF map storage).
#[inline(always)]
pub fn on_stopping(p: *mut task_struct, _runnable: bool) {
    // In the full port, this would:
    //  1. Look up task_ctx
    //  2. Compute slice = min(now() - tctx.last_run_at, SLICE_NS)
    //  3. Update p->scx.dsq_vtime += scale_by_task_weight_inverse(p, slice)
    //  4. Cap tctx.exec_runtime
    //  5. Update per-CPU load statistics
    //
    // For now, we do nothing — tasks in the shared DSQ use FIFO anyway.
}

/// enable: initialize a task's dsq_vtime to the current global vruntime.
///
/// This is a direct port of the C cosmos_enable callback.
#[inline(always)]
pub fn on_enable(p: *mut task_struct) {
    // p->scx.dsq_vtime = vtime_now;
    //
    // Note: Writing to kernel structs via core_read! is read-only.
    // Direct pointer writes require computing the field offset and
    // using a raw pointer store. For now this is a best-effort approach.
    let vtime_now = unsafe { VTIME_NOW };
    let base = p as *const u8;
    let offset = core::mem::offset_of!(vmlinux::task_struct, scx.dsq_vtime);
    let field_ptr = unsafe { base.add(offset) as *mut u64 };
    unsafe {
        core::ptr::write_volatile(field_ptr, vtime_now);
    }
}

/// init: create the shared DSQ. Simplified — no NUMA DSQs, no timer, no PMU.
///
/// TODO: Port NUMA-aware DSQ creation (per-node DSQs when numa_enabled).
/// TODO: Port deferred wakeup timer setup (BPF timer map).
/// TODO: Port per-CPU context initialization.
/// TODO: Port PMU installation.
#[inline(always)]
pub fn on_init() -> i32 {
    let err = kfuncs::create_dsq(SHARED_DSQ, -1);
    if err != 0 {
        kfuncs::error_msg(b"cosmos: failed to create shared DSQ\0");
        return err;
    }
    0
}

/// exit: no-op for now.
///
/// TODO: Port UEI_RECORD and PMU uninstall when those subsystems are ported.
#[inline(always)]
pub fn on_exit(_ei: *mut scx_exit_info) {}

// ── Registration ────────────────────────────────────────────────────────

scx_ebpf::scx_ops_define! {
    name: "cosmos",
    select_cpu: on_select_cpu,
    enqueue: on_enqueue,
    dispatch: on_dispatch,
    runnable: on_runnable,
    running: on_running,
    stopping: on_stopping,
    enable: on_enable,
    init: on_init,
    exit: on_exit,
}
