// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.

//! Cgroups as the cgroup callbacks of `#[scheduler]` take them: the cpu
//! controller reports each cgroup it puts under the scheduler, the tasks
//! that move between them and what is written to cpu.weight, cpu.idle and
//! cpu.max.
//!
//! The field offsets come from the configuration table, which the loader
//! fills from kernel BTF. A kernel built without group scheduling never
//! calls these callbacks.

use core::ptr::read_volatile;

use crate::{
    config, helpers,
    ops::{cgroup, scx_cgroup_init_args},
};

/// A cgroup, valid for the callback it was passed to.
#[repr(transparent)]
pub struct Cgroup(cgroup);

impl Cgroup {
    /// # Safety
    /// `cgroup` must be a cgroup the kernel passed to the running callback.
    #[inline(always)]
    pub unsafe fn from_ptr<'cgroup>(cgroup: *mut cgroup) -> &'cgroup Cgroup {
        unsafe { &*cgroup.cast::<Cgroup>() }
    }

    /// The cgroup as the kfuncs take it.
    #[inline(always)]
    pub fn as_ptr(&self) -> *mut cgroup {
        (self as *const Cgroup).cast_mut().cast()
    }

    /// How deep the cgroup is in the hierarchy: 0 for the root.
    #[inline(always)]
    pub fn level(&self) -> u32 {
        let offset = config::get(config::TG_LEVEL) as usize;
        unsafe { read_volatile(self.as_ptr().cast::<u8>().add(offset).cast::<i32>()) as u32 }
    }

    /// The cgroup's id, which stays the same for as long as it exists, or
    /// 0 where the kernel's layout does not give it.
    #[inline(always)]
    pub fn id(&self) -> u64 {
        let node = config::get(config::TG_KN) as usize;
        if node == 0 {
            return 0;
        }
        // The node is reached through a pointer, so both are probe reads.
        unsafe {
            let node: u64 = helpers::read_kernel(self.as_ptr().cast::<u8>().add(node) as u64);
            if node == 0 {
                return 0;
            }
            helpers::read_kernel(node.wrapping_add(config::get(config::KN_ID)))
        }
    }
}

/// What a cgroup starts with, ops.cgroup_init()'s second argument: the
/// settings it already has when the scheduler first sees it, which no
/// later callback reports.
#[repr(transparent)]
pub struct CgroupArgs(scx_cgroup_init_args);

/// The quota of a cgroup whose cpu.max is "max".
pub const QUOTA_UNLIMITED: u64 = u64::MAX;

impl CgroupArgs {
    /// # Safety
    /// `args` must be the arguments the kernel passed to ops.cgroup_init().
    #[inline(always)]
    pub unsafe fn from_ptr<'args>(args: *mut scx_cgroup_init_args) -> &'args CgroupArgs {
        unsafe { &*args.cast::<CgroupArgs>() }
    }

    #[inline(always)]
    unsafe fn field<T: Copy>(&self, offset: usize) -> T {
        unsafe {
            read_volatile(
                (self as *const CgroupArgs)
                    .cast::<u8>()
                    .add(offset)
                    .cast::<T>(),
            )
        }
    }

    /// cpu.weight: 100 by default, from 1 to 10000.
    #[inline(always)]
    pub fn weight(&self) -> u32 {
        unsafe { self.field(config::get(config::TG_WEIGHT) as usize) }
    }

    /// cpu.max as (period, quota, burst) in microseconds, the quota
    /// `QUOTA_UNLIMITED` for "max". None on a kernel that does not report
    /// it.
    #[inline(always)]
    pub fn bandwidth(&self) -> Option<(u64, u64, u64)> {
        let quota = config::get(config::BW_QUOTA) as usize;
        if quota == 0 {
            return None;
        }
        unsafe {
            Some((
                self.field(config::get(config::BW_PERIOD) as usize),
                self.field(quota),
                self.field(config::get(config::BW_BURST) as usize),
            ))
        }
    }
}
