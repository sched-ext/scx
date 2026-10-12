// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.

//! The kfuncs, declared from the catalog in ../kfuncs.rs, which the build
//! reads too for their BTF prototypes and the linker's export list.

use core::ffi::c_void;

use crate::ops::{cgroup, cpumask, scx_cid_topo, task_struct};

/// The parameter types the catalog names.
pub type I32 = i32;
pub type U32 = u32;
pub type U64 = u64;
pub type Bool = bool;
pub type TaskPtr = *mut task_struct;
pub type VoidPtr = *mut c_void;
pub type CpumaskPtr = *const cpumask;
pub type TopoPtr = *mut scx_cid_topo;
pub type CgroupPtr = *mut cgroup;
pub type BytePtr = *mut u8;
pub type U64Ptr = *const u64;

macro_rules! kfunc_decl {
    (#[sized] fn $name:ident ( $($param:ident : $type:ident),* ) $(-> $ret:ident)? ;) => {
        #[cfg(feature = "topo_size")]
        unsafe extern "C" {
            pub fn $name($($param: $type,)* size: U64) $(-> $ret)?;
        }
        #[cfg(not(feature = "topo_size"))]
        unsafe extern "C" {
            pub fn $name($($param: $type),*) $(-> $ret)?;
        }
    };
    (#[weak] #[safe] fn $name:ident ( $($param:ident : $type:ident),* ) $(-> $ret:ident)? ;) => {
        unsafe extern "C" {
            pub safe fn $name($($param: $type),*) $(-> $ret)?;
        }
    };
    (#[safe] fn $name:ident ( $($param:ident : $type:ident),* ) $(-> $ret:ident)? ;) => {
        unsafe extern "C" {
            pub safe fn $name($($param: $type),*) $(-> $ret)?;
        }
    };
    (#[weak] fn $name:ident ( $($param:ident : $type:ident),* ) $(-> $ret:ident)? ;) => {
        unsafe extern "C" {
            pub fn $name($($param: $type),*) $(-> $ret)?;
        }
    };
    (fn $name:ident ( $($param:ident : $type:ident),* ) $(-> $ret:ident)? ;) => {
        unsafe extern "C" {
            pub fn $name($($param: $type),*) $(-> $ret)?;
        }
    };
}

macro_rules! kfuncs {
    ($( $(#[$attr:ident])* fn $name:ident ( $($param:ident : $type:ident),* ) $(-> $ret:ident)? ; )*) => {
        $( kfunc_decl!($(#[$attr])* fn $name ( $($param : $type),* ) $(-> $ret)? ;); )*
    };
}

include!("../kfuncs.rs");
