//! A simple sched_ext scheduler in pure Rust.
//!
//! Equivalent to `scx_simple.bpf.c` from the Linux kernel, operating in
//! FIFO scheduling mode. All tasks are dispatched to a shared DSQ and
//! consumed by any CPU in FIFO order.
//!
//! Callbacks that need kernel struct field access (running, stopping,
//! enable) are stubbed — the vtime scheduling mode requires reading
//! `p->scx.dsq_vtime` etc., which needs CO-RE support not yet available
//! in the Rust BPF toolchain.

#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]

mod compat;

use compat::kfuncs as scx;
use compat::vmlinux::{scx_exit_info, task_struct};

/// User-created shared dispatch queue. Unlike the built-in SCX_DSQ_GLOBAL,
/// user DSQs work with both `dsq_insert` and `dsq_move_to_local`.
const SHARED_DSQ: u64 = 0;

// ── Scheduler callbacks ────────────────────────────────────────────────
//
// These implement the scheduling policy. Each is called by a trampoline
// in compat::struct_ops that handles the BPF struct_ops calling
// convention (extracting arguments from the context pointer).

/// Select a CPU for a waking task.
///
/// Returns the previous CPU as a simple default. A full implementation
/// would call `scx_bpf_select_cpu_dfl` to find an idle CPU and fast-path
/// the task directly to its local DSQ.
#[inline(always)]
pub fn on_select_cpu(_p: *mut task_struct, prev_cpu: i32, _wake_flags: u64) -> i32 {
    prev_cpu
}

/// Enqueue: insert the task into the shared DSQ with the default slice.
#[inline(always)]
pub fn on_enqueue(p: *mut task_struct, enq_flags: u64) {
    scx::dsq_insert(p, SHARED_DSQ, scx::SLICE_DFL, enq_flags);
}

/// Dispatch: move one task from the shared DSQ to the local CPU's DSQ.
#[inline(always)]
pub fn on_dispatch(_cpu: i32, _prev: *mut task_struct) {
    scx::dsq_move_to_local(SHARED_DSQ);
}

/// Running: called when a task starts executing on a CPU.
#[inline(always)]
pub fn on_running(_p: *mut task_struct) {
    // vtime tracking: p->scx.dsq_vtime (needs CO-RE field access)
}

/// Stopping: called when a task stops executing.
#[inline(always)]
pub fn on_stopping(_p: *mut task_struct, _runnable: bool) {
    // vtime charging: p->scx.slice, p->scx.weight (needs CO-RE field access)
}

/// Enable: called when a task joins the ext scheduler class.
#[inline(always)]
pub fn on_enable(_p: *mut task_struct) {
    // vtime init: p->scx.dsq_vtime = vtime_now (needs CO-RE field access)
}

/// Init: create the shared dispatch queue.
#[inline(always)]
pub fn on_init() -> i32 {
    scx::create_dsq(SHARED_DSQ, -1)
}

/// Exit: scheduler teardown notification.
#[inline(always)]
pub fn on_exit(_ei: *mut scx_exit_info) {}
