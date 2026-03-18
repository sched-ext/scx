//! A simple sched_ext FIFO scheduler in pure Rust.
//!
//! All tasks are dispatched to a shared DSQ and consumed by any CPU
//! in FIFO order. Equivalent to `scx_simple.bpf.c` from the kernel.

#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]
#![allow(non_camel_case_types, non_upper_case_globals, dead_code)]

use scx_ebpf::prelude::*;
use scx_ebpf::core_read;

scx_ebpf::scx_ebpf_boilerplate!();

/// Generated vmlinux struct definitions with real field layouts.
#[allow(non_snake_case, improper_ctypes_definitions, unnecessary_transmutes)]
mod vmlinux {
    include!(concat!(env!("OUT_DIR"), "/vmlinux.rs"));
}

/// User-created shared dispatch queue.
const SHARED_DSQ: u64 = 0;

// ── Scheduler callbacks ────────────────────────────────────────────────

#[inline(always)]
pub fn on_select_cpu(p: *mut task_struct, prev_cpu: i32, _wake_flags: u64) -> i32 {
    // Demonstrate CO-RE field access via core_read!
    // Read nr_cpus_allowed from the real kernel task_struct layout
    if let Ok(nr_cpus) = core_read!(vmlinux::task_struct, p, nr_cpus_allowed) {
        if nr_cpus == 1 {
            // Pinned task — must use prev_cpu
            return prev_cpu;
        }
    }
    prev_cpu
}

#[inline(always)]
pub fn on_enqueue(p: *mut task_struct, enq_flags: u64) {
    kfuncs::dsq_insert(p, SHARED_DSQ, kfuncs::SLICE_DFL, enq_flags);
}

#[inline(always)]
pub fn on_dispatch(_cpu: i32, _prev: *mut task_struct) {
    kfuncs::dsq_move_to_local(SHARED_DSQ);
}

#[inline(always)]
pub fn on_running(_p: *mut task_struct) {}

#[inline(always)]
pub fn on_stopping(_p: *mut task_struct, _runnable: bool) {}

#[inline(always)]
pub fn on_enable(_p: *mut task_struct) {}

#[inline(always)]
pub fn on_init() -> i32 {
    kfuncs::create_dsq(SHARED_DSQ, -1)
}

#[inline(always)]
pub fn on_exit(_ei: *mut scx_exit_info) {}

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
