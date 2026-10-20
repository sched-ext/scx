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
//!
//! What the scheduler keeps per cgroup goes in cgroup storage, which the
//! kernel frees with the cgroup:
//!
//! ```ignore
//! #[derive(Default)]
//! struct GroupCtx {
//!     weight: Var<u64>,
//! }
//! scx::cgroup_state!(GroupCtx, group_ctx);
//!
//! fn cgroup_init(cgroup: &Cgroup, args: &CgroupArgs) -> Result<(), Error> {
//!     let ctx = cgroup.state_or_create::<GroupCtx>().ok_or(Error::ENOMEM)?;
//!     ctx.weight.set(u64::from(args.weight()));
//!     Ok(())
//! }
//! ```
//!
//! A cgroup the kernel did not pass to the callback, a task's, an
//! ancestor or one found by its id, is a `CgroupGuard`: a reference that
//! is given back when the guard goes out of scope.

use core::{ffi::c_void, ops::Deref, ptr::read_volatile};

use crate::{
    config, helpers,
    kfuncs::{bpf_cgroup_ancestor, bpf_cgroup_from_id, bpf_cgroup_release, scx_bpf_cgroup_nr_cpus},
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

    /// Is the cgroup online: created and not yet removed?
    #[inline(always)]
    pub fn is_online(&self) -> bool {
        let offset = config::get(config::TG_FLAGS) as usize;
        let flags = unsafe { read_volatile(self.as_ptr().cast::<u8>().add(offset).cast::<u32>()) };
        u64::from(flags) & config::get(config::TG_ONLINE) != 0
    }

    /// Is the cgroup set cpu.idle? ops.cgroup_set_idle() only reports
    /// changes and the init arguments have no idle state, so this is for a
    /// cgroup made idle before the scheduler saw it. False where the
    /// kernel's layout does not give it.
    #[inline(always)]
    pub fn is_idle(&self) -> bool {
        let css = config::get(config::CPU_CSS) as usize;
        let idle = config::get(config::TG_IDLE) as usize;
        if css == 0 || idle == 0 {
            return false;
        }
        // The cpu controller's css is reached through a pointer the
        // verifier will not follow, so both are probe reads.
        unsafe {
            let group: u64 = helpers::read_kernel(self.as_ptr().cast::<u8>().add(css) as u64);
            if group == 0 {
                return false;
            }
            helpers::read_kernel::<i32>(group.wrapping_add(idle as u64)) > 0
        }
    }

    /// Whether the kernel can tell how many CPUs a cgroup has.
    #[inline(always)]
    pub fn has_nr_cpus() -> bool {
        // A weak kfunc: its address is zero where the kernel lacks it.
        !core::hint::black_box(scx_bpf_cgroup_nr_cpus as *const c_void).is_null()
    }

    /// How many CPUs the cgroup's effective cpuset has, or None on a
    /// kernel that cannot tell.
    #[inline(always)]
    pub fn nr_cpus(&self) -> Option<u32> {
        if !Self::has_nr_cpus() {
            return None;
        }
        Some(unsafe { scx_bpf_cgroup_nr_cpus(self.as_ptr()) })
    }

    /// The cgroup's ancestor at `level`, 0 being the root.
    #[inline(always)]
    pub fn ancestor(&self, level: u32) -> Option<CgroupGuard> {
        CgroupGuard::new(unsafe { bpf_cgroup_ancestor(self.as_ptr(), level as i32) })
    }

    /// The cgroup with the id `id()` returned, if it still exists.
    #[inline(always)]
    pub fn from_id(id: u64) -> Option<CgroupGuard> {
        CgroupGuard::new(unsafe { bpf_cgroup_from_id(id) })
    }

    /// The scheduler's state of the cgroup, of a type declared with
    /// `cgroup_state!`, if it has any.
    #[inline(always)]
    pub fn state<T: CgroupState>(&self) -> Option<&T> {
        unsafe { T::lookup(self.as_ptr(), false).as_ref() }
    }

    /// The scheduler's state of the cgroup, created as zeroes if it has
    /// none. None if there is no memory for it.
    #[inline(always)]
    pub fn state_or_create<T: CgroupState>(&self) -> Option<&T> {
        unsafe { T::lookup(self.as_ptr(), true).as_ref() }
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

/// A cgroup the scheduler holds a reference to, which it gives back when
/// the guard is dropped. The verifier refuses a program that leaves with
/// one, so there is no way to keep it past the callback.
pub struct CgroupGuard(*mut cgroup);

impl CgroupGuard {
    #[inline(always)]
    pub(crate) fn new(cgroup: *mut cgroup) -> Option<CgroupGuard> {
        if cgroup.is_null() {
            None
        } else {
            Some(CgroupGuard(cgroup))
        }
    }
}

impl Deref for CgroupGuard {
    type Target = Cgroup;

    #[inline(always)]
    fn deref(&self) -> &Cgroup {
        unsafe { Cgroup::from_ptr(self.0) }
    }
}

impl Drop for CgroupGuard {
    #[inline(always)]
    fn drop(&mut self) {
        unsafe { bpf_cgroup_release(self.0) };
    }
}

/// The BTF-defined map of a cgroup storage whose value is `T`.
#[repr(C)]
pub struct CgroupStorage<T> {
    r#type: *const [u32; 32],
    map_flags: *const [u32; 1],
    key: *const i32,
    value: *const T,
}

impl<T> CgroupStorage<T> {
    #[allow(clippy::new_without_default)]
    pub const fn new() -> Self {
        Self {
            r#type: core::ptr::null(),
            map_flags: core::ptr::null(),
            key: core::ptr::null(),
            value: core::ptr::null(),
        }
    }
}

/// A type the scheduler keeps per cgroup, see `cgroup_state!`. Its fields
/// are `Var`s, since `Cgroup::state()` hands it out as a shared reference.
pub trait CgroupState: Sized + 'static {
    fn map() -> *mut CgroupStorage<Self>;

    /// # Safety
    /// `cgroup` must be a cgroup the program holds or was passed.
    #[inline(always)]
    unsafe fn lookup(cgroup: *mut cgroup, create: bool) -> *mut Self {
        unsafe {
            helpers::cgrp_storage_get(
                Self::map(),
                cgroup,
                core::ptr::null_mut(),
                u64::from(create),
            )
        }
    }
}

/// Declare the cgroup storage map `$map` for the type `$type`, see the
/// module.
#[macro_export]
macro_rules! cgroup_state {
    ($type:ty, $map:ident) => {
        #[unsafe(no_mangle)]
        #[unsafe(link_section = ".maps")]
        #[allow(non_upper_case_globals)]
        pub static mut $map: $crate::cgroup::CgroupStorage<$type> =
            $crate::cgroup::CgroupStorage::new();

        impl $crate::cgroup::CgroupState for $type {
            #[inline(always)]
            fn map() -> *mut $crate::cgroup::CgroupStorage<$type> {
                &raw mut $map
            }
        }
    };
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

    /// Does the kernel report the cgroup's cpu.max here?
    #[inline(always)]
    pub fn has_bandwidth(&self) -> bool {
        config::get(config::BW_QUOTA) != 0
    }

    /// cpu.max's quota in microseconds, `QUOTA_UNLIMITED` for "max". Only
    /// if `has_bandwidth()`.
    #[inline(always)]
    pub fn quota_us(&self) -> u64 {
        unsafe { self.field(config::get(config::BW_QUOTA) as usize) }
    }

    /// cpu.max's period in microseconds. Only if `has_bandwidth()`.
    #[inline(always)]
    pub fn period_us(&self) -> u64 {
        unsafe { self.field(config::get(config::BW_PERIOD) as usize) }
    }

    /// cpu.max.burst in microseconds. Only if `has_bandwidth()`.
    #[inline(always)]
    pub fn burst_us(&self) -> u64 {
        unsafe { self.field(config::get(config::BW_BURST) as usize) }
    }
}
