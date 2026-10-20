// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.

//! What the loader cannot learn from user space about a CPU's place in the
//! kernel's asymmetric packing: arch_asym_cpu_priority() and whether its
//! scheduling domains carry SD_ASYM_PACKING, down to the SMT domain. Neither
//! has a user-space ABI, so a syscall program reads them from the kernel's
//! per-CPU sched_core_priority and sd_asym_packing. Both are weak ksyms,
//! and a kernel without ITMT has no sched_core_priority.

use core::{ffi::c_void, hint::black_box, ptr::write_volatile};

use crate::helpers::{self, read_kernel};

/// sched_domain walk depth, enough for any topology.
const MAX_DEPTH: u32 = 16;

/// What the loader passes in and reads back.
#[repr(C)]
pub struct PriorityArgs {
    cpu: u64,
    /// struct sched_domain's flags and child offsets, and the
    /// SD_ASYM_PACKING and SD_SHARE_CPUCAPACITY bits, from kernel BTF.
    flags_offset: u64,
    child_offset: u64,
    asym_packing_flag: u64,
    share_capacity_flag: u64,
    /// Out: the priority, whether the CPU's domains pack asymmetrically,
    /// and whether that reaches its SMT domain.
    priority: i64,
    asym_packing: u64,
    smt_asym_packing: u64,
}

unsafe extern "C" {
    static sched_core_priority: i32;
    static sd_asym_packing: u64;
}

#[inline(always)]
unsafe fn per_cpu(address: *const c_void, cpu: u32) -> *const c_void {
    unsafe { helpers::per_cpu_ptr(address, cpu) }
}

#[unsafe(no_mangle)]
#[unsafe(link_section = "syscall")]
pub unsafe extern "C" fn rust_cpu_priority(args: *mut PriorityArgs) -> i32 {
    unsafe {
        let args = &mut *args;
        // One by one: three adjacent zero stores become a memset, which
        // BPF has no call for.
        write_volatile(&raw mut args.priority, 0);
        write_volatile(&raw mut args.asym_packing, 0);
        write_volatile(&raw mut args.smt_asym_packing, 0);
        // Missing weak ksyms resolve to null; keep the test from being
        // folded away on the assumption that a static has an address.
        let priority = black_box(&raw const sched_core_priority).cast::<c_void>();
        let domain = black_box(&raw const sd_asym_packing).cast::<c_void>();
        if args.cpu > i32::MAX as u64 || priority.is_null() || domain.is_null() {
            return 0;
        }
        let priority = per_cpu(priority, args.cpu as u32).cast::<i32>();
        let domain = per_cpu(domain, args.cpu as u32).cast::<u64>();
        if priority.is_null() || domain.is_null() {
            return 0;
        }
        let mut domain = *domain;
        if domain == 0 {
            return 0;
        }
        args.priority = i64::from(*priority);
        args.asym_packing = 1;
        let both = args.asym_packing_flag | args.share_capacity_flag;
        for _ in 0..MAX_DEPTH {
            if domain == 0 {
                break;
            }
            let flags: i32 = read_kernel(domain + args.flags_offset);
            if flags as u64 & both == both {
                args.smt_asym_packing = 1;
                break;
            }
            domain = read_kernel(domain + args.child_offset);
        }
    }
    0
}
