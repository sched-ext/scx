//! A simple sched_ext FIFO scheduler in pure Rust.
//!
//! All tasks are dispatched to a shared DSQ and consumed by any CPU
//! in FIFO order. Equivalent to `scx_simple.bpf.c` from the kernel.

#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]

use core::ffi::c_void;
use scx_ebpf::prelude::*;

scx_ebpf::scx_ebpf_boilerplate!();

/// User-created shared dispatch queue.
const SHARED_DSQ: u64 = 0;

// ── Scheduler callbacks ────────────────────────────────────────────────

#[inline(always)]
pub fn on_select_cpu(_p: *mut c_void, prev_cpu: i32, _wake_flags: u64) -> i32 {
    prev_cpu
}

#[inline(always)]
pub fn on_enqueue(p: *mut c_void, enq_flags: u64) {
    kfuncs::dsq_insert(p as *mut task_struct, SHARED_DSQ, kfuncs::SLICE_DFL, enq_flags);
}

#[inline(always)]
pub fn on_dispatch(_cpu: i32, _prev: *mut c_void) {
    kfuncs::dsq_move_to_local(SHARED_DSQ);
}

#[inline(always)]
pub fn on_running(_p: *mut c_void) {}

#[inline(always)]
pub fn on_stopping(_p: *mut c_void, _runnable: bool) {}

#[inline(always)]
pub fn on_enable(_p: *mut c_void) {}

#[inline(always)]
pub fn on_init() -> i32 {
    kfuncs::create_dsq(SHARED_DSQ, -1)
}

#[inline(always)]
pub fn on_exit(_ei: *mut c_void) {}

// ── Registration ───────────────────────────────────────────────────────

scx_ebpf::scx_ops_define! {
    name: "simple",
    select_cpu: on_select_cpu,
    enqueue: on_enqueue,
    dispatch: on_dispatch,
    running: on_running,
    stopping: on_stopping,
    enable: on_enable,
    init: on_init,
    exit: on_exit,
}
