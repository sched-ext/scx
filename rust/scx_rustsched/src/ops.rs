// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.

//! The sched_ext side of the program: the kernel types the callbacks take,
//! the enqueue, dequeue, kick and ops flags, and the struct_ops map the
//! scheduler registers with, which `#[scheduler]` declares with `ops_map!`
//! from the callbacks the scheduler implements.
//!
//! The struct declares only the `sched_ext_ops_cid` members the scheduler
//! uses. libbpf maps them by name into the running kernel's structure
//! using BTF, so the local structure deliberately matches neither the
//! kernel's size nor its layout. Each entry point receives a pointer to an
//! array of 64-bit argument slots; the initializer casts its address to the
//! kernel callback type so that its BTF describes a function pointer, which
//! libbpf and the kernel consume and nothing calls through the cast type.

use core::panic::PanicInfo;

#[repr(C)]
pub struct task_struct {
    _opaque: [u8; 0],
}

#[repr(C)]
pub struct cpumask {
    _opaque: [u8; 0],
}

#[repr(C)]
pub struct scx_cmask {
    _opaque: [u8; 0],
}

#[repr(C)]
pub struct scx_dump_ctx {
    _opaque: [u8; 0],
}

#[repr(C)]
pub struct scx_exit_info {
    _opaque: [u8; 0],
}

#[repr(C)]
pub struct scx_init_task_args {
    _opaque: [u8; 0],
}

#[repr(C)]
pub struct scx_exit_task_args {
    _opaque: [u8; 0],
}

#[repr(C)]
pub struct cgroup {
    _opaque: [u8; 0],
}

#[repr(C)]
pub struct scx_cgroup_init_args {
    _opaque: [u8; 0],
}

/// Where a CID sits in the topology, as scx_bpf_cid_topo() fills it in.
#[repr(C)]
pub struct scx_cid_topo {
    pub(crate) core_cid: i32,
    pub(crate) core_idx: i32,
    pub(crate) llc_cid: i32,
    pub(crate) llc_idx: i32,
    pub(crate) node_cid: i32,
    pub(crate) node_idx: i32,
    pub(crate) shard_cid: i32,
    pub(crate) shard_idx: i32,
    #[cfg(feature = "topo_size")]
    pub(crate) cluster_cid: i32,
    #[cfg(feature = "topo_size")]
    pub(crate) cluster_idx: i32,
}

pub const SCX_DSQ_LOCAL: u64 = (1 << 63) | 2;
pub const SCX_DSQ_LOCAL_ON: u64 = (1 << 63) | (1 << 62);
pub const SCX_TASK_QUEUED: u32 = 1;
pub const SCX_ENQ_WAKEUP: u64 = 1;
pub const SCX_ENQ_PREEMPT: u64 = 1 << 32;
pub const SCX_DEQ_SLEEP: u64 = 1;
pub const SCX_DEQ_SCHED_CHANGE: u64 = 1 << 33;
pub const SCX_WAKE_TTWU: u64 = 8;
pub const SCX_KICK_IDLE: u64 = 1;
pub const SCX_KICK_PREEMPT: u64 = 2;
/// Hands the last runnable task of a CPU to ops.enqueue() when its slice
/// ends with nothing else dispatched. Without it the kernel refills the
/// slice and keeps the task running.
pub const SCX_OPS_ENQ_LAST: u64 = 2;
/// Exiting and migration-disabled tasks go through ops.enqueue() too,
/// rather than straight to their CPU's local DSQ behind the scheduler's
/// back.
pub const SCX_OPS_ENQ_EXITING: u64 = 4;
pub const SCX_OPS_ENQ_MIGRATION_DISABLED: u64 = 16;
/// Lets a wakeup be queued to the target CPU's wake list, ttwu_queue(), so
/// that ops.enqueue() runs there rather than on the waker under the remote
/// runqueue lock.
pub const SCX_OPS_ALLOW_QUEUED_WAKEUP: u64 = 32;
/// Lets dispatch resolve a queued task from its tid, scx_bpf_tid_to_task().
pub const SCX_OPS_TID_TO_TASK: u64 = 256;
/// Proxy execution: a task that blocks on a mutex stays runnable as a
/// donor, handed to ops.enqueue() with SCX_ENQ_BLOCKED, and when it is
/// picked its scheduling context runs the mutex owner. A kernel without it
/// refuses the flag: user space adds it where the kernel has it, see
/// `Task::is_blocked()`.
pub const SCX_OPS_ENQ_BLOCKED: u64 = 1 << 10;

/// The ops flags under the names `#[scheduler(flags = ...)]` takes.
pub mod flags {
    pub const ENQ_LAST: u64 = super::SCX_OPS_ENQ_LAST;
    pub const ENQ_EXITING: u64 = super::SCX_OPS_ENQ_EXITING;
    pub const ENQ_MIGRATION_DISABLED: u64 = super::SCX_OPS_ENQ_MIGRATION_DISABLED;
    pub const ALLOW_QUEUED_WAKEUP: u64 = super::SCX_OPS_ALLOW_QUEUED_WAKEUP;
    pub const TID_TO_TASK: u64 = super::SCX_OPS_TID_TO_TASK;
    pub const ENQ_BLOCKED: u64 = super::SCX_OPS_ENQ_BLOCKED;
}

/// Was the scheduler loaded with all of the ops `flags`, as `#[scheduler]`
/// declares them and its user space changed them?
#[inline(always)]
pub fn enabled(flags: u64) -> bool {
    crate::config::get(crate::config::OPS_FLAGS) & flags == flags
}

/// The kernel's prototype of each callback, by member name. The cgroup
/// callbacks appear under both their cpuctl_* and cgroup_* names.
#[macro_export]
macro_rules! ops_signature {
    (init_task) => { unsafe extern "C" fn(*mut $crate::ops::task_struct, *mut $crate::ops::scx_init_task_args) -> i32 };
    (exit_task) => { unsafe extern "C" fn(*mut $crate::ops::task_struct, *mut $crate::ops::scx_exit_task_args) };
    (select_cid) => { unsafe extern "C" fn(*mut $crate::ops::task_struct, i32, u64) -> i32 };
    (update_idle) => { unsafe extern "C" fn(i32, bool) };
    (enqueue) => { unsafe extern "C" fn(*mut $crate::ops::task_struct, u64) };
    (dequeue) => { unsafe extern "C" fn(*mut $crate::ops::task_struct, u64) };
    (dispatch) => { unsafe extern "C" fn(i32, *mut $crate::ops::task_struct) };
    (tick) => { unsafe extern "C" fn(*mut $crate::ops::task_struct) };
    (running) => { unsafe extern "C" fn(*mut $crate::ops::task_struct) };
    (stopping) => { unsafe extern "C" fn(*mut $crate::ops::task_struct, bool) };
    (runnable) => { unsafe extern "C" fn(*mut $crate::ops::task_struct, u64) };
    (quiescent) => { unsafe extern "C" fn(*mut $crate::ops::task_struct, u64) };
    (r#yield) => { unsafe extern "C" fn(*mut $crate::ops::task_struct, *mut $crate::ops::task_struct) -> bool };
    (core_sched_before) => { unsafe extern "C" fn(*mut $crate::ops::task_struct, *mut $crate::ops::task_struct) -> bool };
    (set_weight) => { unsafe extern "C" fn(*mut $crate::ops::task_struct, u32) };
    (set_cmask) => { unsafe extern "C" fn(*mut $crate::ops::task_struct, *const $crate::ops::scx_cmask) };
    (enable) => { unsafe extern "C" fn(*mut $crate::ops::task_struct) };
    (disable) => { unsafe extern "C" fn(*mut $crate::ops::task_struct) };
    (cid_online) => { unsafe extern "C" fn(i32) };
    (cid_offline) => { unsafe extern "C" fn(i32) };
    (init) => { unsafe extern "C" fn() -> i32 };
    (exit) => { unsafe extern "C" fn(*mut $crate::ops::scx_exit_info) };
    (dump) => { unsafe extern "C" fn(*mut $crate::ops::scx_dump_ctx) };
    (dump_cid) => { unsafe extern "C" fn(*mut $crate::ops::scx_dump_ctx, i32, bool) };
    (dump_task) => { unsafe extern "C" fn(*mut $crate::ops::scx_dump_ctx, *mut $crate::ops::task_struct) };
    (cpuctl_init) => { unsafe extern "C" fn(*mut $crate::ops::cgroup, *mut $crate::ops::scx_cgroup_init_args) -> i32 };
    (cpuctl_exit) => { unsafe extern "C" fn(*mut $crate::ops::cgroup) };
    (cpuctl_prep_move) => { unsafe extern "C" fn(*mut $crate::ops::task_struct, *mut $crate::ops::cgroup, *mut $crate::ops::cgroup) -> i32 };
    (cpuctl_cancel_move) => { unsafe extern "C" fn(*mut $crate::ops::task_struct, *mut $crate::ops::cgroup, *mut $crate::ops::cgroup) };
    (cpuctl_move) => { unsafe extern "C" fn(*mut $crate::ops::task_struct, *mut $crate::ops::cgroup, *mut $crate::ops::cgroup) };
    (cpuctl_set_weight) => { unsafe extern "C" fn(*mut $crate::ops::cgroup, u32) };
    (cpuctl_set_idle) => { unsafe extern "C" fn(*mut $crate::ops::cgroup, bool) };
    (cpuctl_set_bandwidth) => { unsafe extern "C" fn(*mut $crate::ops::cgroup, u64, u64, u64) };
    (cgroup_init) => { unsafe extern "C" fn(*mut $crate::ops::cgroup, *mut $crate::ops::scx_cgroup_init_args) -> i32 };
    (cgroup_exit) => { unsafe extern "C" fn(*mut $crate::ops::cgroup) };
    (cgroup_prep_move) => { unsafe extern "C" fn(*mut $crate::ops::task_struct, *mut $crate::ops::cgroup, *mut $crate::ops::cgroup) -> i32 };
    (cgroup_cancel_move) => { unsafe extern "C" fn(*mut $crate::ops::task_struct, *mut $crate::ops::cgroup, *mut $crate::ops::cgroup) };
    (cgroup_move) => { unsafe extern "C" fn(*mut $crate::ops::task_struct, *mut $crate::ops::cgroup, *mut $crate::ops::cgroup) };
    (cgroup_set_weight) => { unsafe extern "C" fn(*mut $crate::ops::cgroup, u32) };
    (cgroup_set_idle) => { unsafe extern "C" fn(*mut $crate::ops::cgroup, bool) };
    (cgroup_set_bandwidth) => { unsafe extern "C" fn(*mut $crate::ops::cgroup, u64, u64, u64) };
}

/// An entry point as the struct_ops map holds it: cast to the kernel's
/// prototype, never called through it.
#[macro_export]
macro_rules! callback {
    ($function:path, $member:ident) => {
        unsafe {
            core::mem::transmute::<
                unsafe extern "C" fn(*const u64) -> u64,
                $crate::ops_signature!($member),
            >($function)
        }
    };
}

/// The watchdog timeout of a scheduler whose `#[scheduler]` names none:
/// how long a runnable task may wait before the kernel ejects the
/// scheduler. Shorter than the kernel's 30 s default, so that a stall
/// shows up as one. The loader's --timeout-ms replaces it at run time.
pub const TIMEOUT_MS: u32 = 5000;

/// One struct_ops type and map: `$type` declares the members listed, and
/// `$map` in `$section` is its instance.
#[macro_export]
macro_rules! ops_map {
    ($map:ident: $type:ident in $section:literal,
     name: $name:expr, flags: $flags:expr, timeout_ms: $timeout:expr, dump_len: $dump_len:expr,
     { $($member:ident: $function:path,)* }) => {
        #[repr(C)]
        pub struct $type {
            $($member: $crate::ops_signature!($member),)*
            flags: u64,
            timeout_ms: u32,
            exit_dump_len: u32,
            name: [u8; 128],
        }

        #[used]
        #[unsafe(no_mangle)]
        #[unsafe(link_section = $section)]
        pub static mut $map: $type = $type {
            $($member: $crate::callback!($function, $member),)*
            flags: $flags,
            timeout_ms: $timeout,
            exit_dump_len: $dump_len,
            name: $crate::ops::name($name),
        };
    };
}

/// The scheduler's name as the map holds it.
pub const fn name(bytes: &[u8]) -> [u8; 128] {
    let mut name = [0; 128];
    let mut index = 0;
    while index < bytes.len() && index < 127 {
        name[index] = bytes[index];
        index += 1;
    }
    name
}

#[used]
#[unsafe(no_mangle)]
#[unsafe(link_section = "license")]
pub static LICENSE: [u8; 4] = *b"GPL\0";

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}
