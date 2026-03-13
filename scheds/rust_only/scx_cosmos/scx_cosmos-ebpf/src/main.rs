//! scx_cosmos — a deadline + vruntime scheduler, ported from C to pure Rust.
//!
//! This is an incremental port of scx_cosmos. It implements:
//!
//! - `select_cpu`: uses `scx_bpf_select_cpu_dfl` for idle CPU selection
//! - `enqueue`: vtime-based dispatch to shared DSQ (deadline mode)
//! - `dispatch`: `dsq_move_to_local` + slice extension for prev task
//! - `running`: updates vtime_now
//! - `stopping`: updates dsq_vtime based on used time slice (weight-inverse)
//! - `enable`: initializes task dsq_vtime to current vtime_now
//!
//! Simplified vs the full C implementation:
//! - No per-task BPF map storage (task_ctx), so no exec_runtime/wakeup_freq
//! - No cpufreq scaling, no PMU tracking, no NUMA awareness
//! - No flat/preferred idle scan, no mm_affinity
//! - No deferred wakeup timer

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

/// Shared DSQ used for deadline-mode scheduling.
const SHARED_DSQ: u64 = 0;

/// Default time slice: 10us (matches C cosmos `slice_ns = 10000`).
const SLICE_NS: u64 = 10_000;

/// Maximum runtime charged to a task (bounds vruntime jumps).
const SLICE_LAG: u64 = 20_000_000;

/// SCX_TASK_QUEUED flag in scx entity flags.
const SCX_TASK_QUEUED: u32 = 1;

// ── Global state ────────────────────────────────────────────────────────

/// Current global vruntime — tracks the most recent dsq_vtime seen.
static mut VTIME_NOW: u64 = 0;

// ── Helpers ─────────────────────────────────────────────────────────────

/// Write a u64 field in a kernel struct at a known compile-time offset.
#[inline(always)]
unsafe fn write_field_u64(base: *mut task_struct, offset: usize, val: u64) {
    let ptr = (base as *mut u8).add(offset) as *mut u64;
    core::ptr::write_volatile(ptr, val);
}

// ── Scheduler callbacks ─────────────────────────────────────────────────

/// select_cpu: use the kernel's default idle CPU selection.
///
/// Calls `scx_bpf_select_cpu_dfl` which picks the best idle CPU
/// considering cache topology and wake_flags. If an idle CPU is found,
/// dispatch the task directly to the local DSQ to skip the enqueue path.
#[inline(always)]
pub fn on_select_cpu(p: *mut task_struct, prev_cpu: i32, wake_flags: u64) -> i32 {
    let mut is_idle: bool = false;
    let cpu = kfuncs::select_cpu_dfl(p, prev_cpu, wake_flags, &mut is_idle);
    if is_idle {
        // Idle CPU found — dispatch directly to local DSQ.
        // Read weight before any potential side effects.
        let weight = if let Ok(w) = core_read!(vmlinux::task_struct, p, scx.weight) {
            w as u64
        } else {
            100
        };
        let slice = if weight > 0 { (SLICE_NS * weight) / 100 } else { SLICE_NS };
        kfuncs::dsq_insert(p, kfuncs::SCX_DSQ_LOCAL, slice, 0);
    }
    cpu
}

/// enqueue: dispatch to the shared DSQ with vtime-based ordering.
///
/// This uses the task's dsq_vtime as the virtual deadline, providing
/// fair scheduling weighted by task priority. Tasks with lower vruntime
/// (i.e., those that have consumed less CPU) are scheduled first.
///
/// If select_cpu already dispatched the task (via SCX_DSQ_LOCAL), this
/// callback is not invoked by the kernel.
#[inline(always)]
pub fn on_enqueue(p: *mut task_struct, enq_flags: u64) {
    // Read ALL fields we need BEFORE any writes to the task struct.
    // The BPF verifier invalidates the pointer's trusted_ptr status
    // after writes, so subsequent reads would fail verification.
    let vtime = if let Ok(v) = core_read!(vmlinux::task_struct, p, scx.dsq_vtime) {
        v
    } else {
        unsafe { VTIME_NOW }
    };

    let weight = if let Ok(w) = core_read!(vmlinux::task_struct, p, scx.weight) {
        w as u64
    } else {
        100 // default weight
    };

    // Compute the time slice scaled by weight.
    let slice = if weight > 0 { (SLICE_NS * weight) / 100 } else { SLICE_NS };

    // Clamp vtime so tasks don't accumulate too much credit from sleeping.
    // C: vtime_min = vtime_now - scale_by_task_weight(p, slice_lag)
    let vtime_now = unsafe { VTIME_NOW };
    let vsleep_max = if weight > 0 { (SLICE_LAG * weight) / 100 } else { SLICE_LAG };
    let vtime_min = vtime_now.wrapping_sub(vsleep_max);
    let clamped_vtime = if vtime < vtime_min { vtime_min } else { vtime };

    // Now do writes (after all reads are done).
    if clamped_vtime != vtime {
        let offset = core::mem::offset_of!(vmlinux::task_struct, scx.dsq_vtime);
        unsafe { write_field_u64(p, offset, clamped_vtime); }
    }

    kfuncs::dsq_insert_vtime(p, SHARED_DSQ, slice, clamped_vtime, enq_flags);
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
                let slice = if weight > 0 { (SLICE_NS * weight) / 100 } else { SLICE_NS };
                let offset = core::mem::offset_of!(vmlinux::task_struct, scx.slice);
                unsafe { write_field_u64(prev, offset, slice); }
            }
        }
    }
}

/// runnable: stub — needs per-task BPF map storage for full implementation.
///
/// The full C implementation resets exec_runtime and updates wakeup
/// frequency via EWMA. This requires BPF_MAP_TYPE_TASK_STORAGE which
/// is not yet supported in the pure-Rust eBPF framework.
#[inline(always)]
pub fn on_runnable(_p: *mut task_struct, _enq_flags: u64) {
}

/// running: update vtime_now when a task starts executing.
///
/// Advances the global vruntime to track the most recent task's vtime.
/// This ensures newly-enabled tasks start with a fair baseline.
#[inline(always)]
pub fn on_running(p: *mut task_struct) {
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

/// stopping: charge the used time slice and update dsq_vtime.
///
/// Computes the actual time the task ran (capped at SLICE_NS) and
/// advances the task's dsq_vtime proportionally, scaled inversely by
/// the task's weight (higher weight = slower vtime advancement = more
/// CPU time).
///
/// Without per-task storage, we use SLICE_NS as the default time
/// charged (since we can't track last_run_at without task_ctx).
#[inline(always)]
pub fn on_stopping(p: *mut task_struct, _runnable: bool) {
    // Read ALL fields before writing.
    let old_vtime = if let Ok(v) = core_read!(vmlinux::task_struct, p, scx.dsq_vtime) {
        v
    } else {
        return;
    };

    let weight = if let Ok(w) = core_read!(vmlinux::task_struct, p, scx.weight) {
        w as u64
    } else {
        100
    };

    // C: p->scx.dsq_vtime += scale_by_task_weight_inverse(p, slice);
    // scale_by_task_weight_inverse(p, v) = v * 100 / weight
    let slice = SLICE_NS;
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

/// init: create the shared DSQ.
///
/// Simplified — no NUMA DSQs, no deferred wakeup timer, no PMU.
#[inline(always)]
pub fn on_init() -> i32 {
    let err = kfuncs::create_dsq(SHARED_DSQ, -1);
    if err != 0 {
        scx_ebpf::scx_bpf_error!("cosmos: failed to create shared DSQ");
        return err;
    }
    0
}

/// exit: no-op for now.
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
