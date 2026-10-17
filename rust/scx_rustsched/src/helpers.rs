// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.

//! The BPF helpers, called by number as the kernel's bpf_func_id lists
//! them. Rust has no declaration for a helper, so each one here is its
//! number cast to the prototype the kernel gives it, in one place.
//!
//! Pointer parameters are generic or untyped where the helper takes more
//! than one type, a map or a kernel address: the cast is the caller's.

use core::ffi::c_void;

use crate::ops::{cgroup, task_struct};

const MAP_LOOKUP_ELEM: usize = 1;
const KTIME_GET_NS: usize = 5;
const GET_PRANDOM_U32: usize = 7;
const PROBE_READ_KERNEL: usize = 113;
const PROBE_READ_KERNEL_STR: usize = 115;
const PER_CPU_PTR: usize = 153;
const TASK_STORAGE_GET: usize = 156;
const TASK_STORAGE_DELETE: usize = 157;
const GET_CURRENT_TASK_BTF: usize = 158;
const TIMER_INIT: usize = 169;
const TIMER_SET_CALLBACK: usize = 170;
const TIMER_START: usize = 171;
const CGRP_STORAGE_GET: usize = 210;

/// bpf_map_lookup_elem(): the value of `key` in `map`, or null.
#[inline(always)]
pub unsafe fn map_lookup_elem<M, K, V>(map: *mut M, key: *const K) -> *mut V {
    let helper: unsafe extern "C" fn(*mut M, *const K) -> *mut V =
        unsafe { core::mem::transmute(MAP_LOOKUP_ELEM) };
    unsafe { helper(map, key) }
}

/// bpf_ktime_get_ns().
#[inline(always)]
pub fn ktime_get_ns() -> u64 {
    let helper: unsafe extern "C" fn() -> u64 = unsafe { core::mem::transmute(KTIME_GET_NS) };
    unsafe { helper() }
}

/// bpf_get_prandom_u32().
#[inline(always)]
pub fn get_prandom_u32() -> u32 {
    let helper: unsafe extern "C" fn() -> u32 = unsafe { core::mem::transmute(GET_PRANDOM_U32) };
    unsafe { helper() }
}

/// bpf_probe_read_kernel(): copy `size` bytes at the kernel address
/// `source` to `destination`. 0 on success.
#[inline(always)]
pub unsafe fn probe_read_kernel(destination: *mut c_void, size: u32, source: u64) -> i64 {
    let helper: unsafe extern "C" fn(*mut c_void, u32, u64) -> i64 =
        unsafe { core::mem::transmute(PROBE_READ_KERNEL) };
    unsafe { helper(destination, size, source) }
}

/// bpf_probe_read_kernel() of a kernel value at `address`, its default if
/// unreadable.
#[inline(always)]
pub unsafe fn read_kernel<T: Copy + Default>(address: u64) -> T {
    let mut value = T::default();
    if unsafe { probe_read_kernel((&raw mut value).cast(), size_of::<T>() as u32, address) } != 0 {
        return T::default();
    }
    value
}

/// bpf_probe_read_kernel_str(): copy the string at the kernel address
/// `source` into `size` bytes at `destination`.
#[inline(always)]
pub unsafe fn probe_read_kernel_str(destination: *mut c_void, size: u32, source: u64) -> i64 {
    let helper: unsafe extern "C" fn(*mut c_void, u32, u64) -> i64 =
        unsafe { core::mem::transmute(PROBE_READ_KERNEL_STR) };
    unsafe { helper(destination, size, source) }
}

/// bpf_per_cpu_ptr(): `cpu`'s instance of the per-CPU ksym `variable`, or
/// null.
#[inline(always)]
pub unsafe fn per_cpu_ptr<T>(variable: *const c_void, cpu: u32) -> *const T {
    let helper: unsafe extern "C" fn(*const c_void, u32) -> *const T =
        unsafe { core::mem::transmute(PER_CPU_PTR) };
    unsafe { helper(variable, cpu) }
}

/// bpf_task_storage_get(): `task`'s value in the task-storage `map`,
/// created from `value` with BPF_LOCAL_STORAGE_GET_F_CREATE in `flags`.
#[inline(always)]
pub unsafe fn task_storage_get<M, V>(
    map: *mut M,
    task: *mut task_struct,
    value: *mut c_void,
    flags: u64,
) -> *mut V {
    let helper: unsafe extern "C" fn(*mut M, *mut task_struct, *mut c_void, u64) -> *mut V =
        unsafe { core::mem::transmute(TASK_STORAGE_GET) };
    unsafe { helper(map, task, value, flags) }
}

/// bpf_task_storage_delete().
#[inline(always)]
pub unsafe fn task_storage_delete<M>(map: *mut M, task: *mut task_struct) -> i64 {
    let helper: unsafe extern "C" fn(*mut M, *mut task_struct) -> i64 =
        unsafe { core::mem::transmute(TASK_STORAGE_DELETE) };
    unsafe { helper(map, task) }
}

/// bpf_get_current_task_btf().
#[inline(always)]
pub unsafe fn get_current_task() -> *mut task_struct {
    let helper: unsafe extern "C" fn() -> *mut task_struct =
        unsafe { core::mem::transmute(GET_CURRENT_TASK_BTF) };
    unsafe { helper() }
}

/// bpf_timer_init().
#[inline(always)]
pub unsafe fn timer_init<M>(timer: *mut c_void, map: *mut M, flags: u64) -> i64 {
    let helper: unsafe extern "C" fn(*mut c_void, *mut M, u64) -> i64 =
        unsafe { core::mem::transmute(TIMER_INIT) };
    unsafe { helper(timer, map, flags) }
}

/// bpf_timer_set_callback().
#[inline(always)]
pub unsafe fn timer_set_callback(timer: *mut c_void, callback: *const c_void) -> i64 {
    let helper: unsafe extern "C" fn(*mut c_void, *const c_void) -> i64 =
        unsafe { core::mem::transmute(TIMER_SET_CALLBACK) };
    unsafe { helper(timer, callback) }
}

/// bpf_timer_start().
#[inline(always)]
pub unsafe fn timer_start(timer: *mut c_void, nsecs: u64, flags: u64) -> i64 {
    let helper: unsafe extern "C" fn(*mut c_void, u64, u64) -> i64 =
        unsafe { core::mem::transmute(TIMER_START) };
    unsafe { helper(timer, nsecs, flags) }
}

/// bpf_cgrp_storage_get(): `cgroup`'s value in the cgroup-storage `map`,
/// as bpf_task_storage_get() for a task.
#[inline(always)]
pub unsafe fn cgrp_storage_get<M, V>(
    map: *mut M,
    cgroup: *mut cgroup,
    value: *mut c_void,
    flags: u64,
) -> *mut V {
    let helper: unsafe extern "C" fn(*mut M, *mut cgroup, *mut c_void, u64) -> *mut V =
        unsafe { core::mem::transmute(CGRP_STORAGE_GET) };
    unsafe { helper(map, cgroup, value, flags) }
}
