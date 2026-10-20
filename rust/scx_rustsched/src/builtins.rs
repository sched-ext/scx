// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.

//! memset() and memcpy(), which the compiler calls for a value it fills
//! or copies as a block, such as an array built on the stack. BPF has no library to take them from, so they are here, as
//! static functions the verifier checks at each call with the size the
//! caller passes.
//!
//! The loops address each byte through an integer. Written over the
//! pointer, the compiler recognizes them as a memset() and a memcpy() and
//! replaces each body with a call to itself.
//!
//! Both return null where C returns the destination. The compiler emits
//! these calls for block fills and copies, whose result it never uses, and
//! the verifier refuses a function that returns a pointer to its caller's
//! stack.

use core::ffi::c_void;

#[unsafe(no_mangle)]
pub unsafe extern "C" fn memset(destination: *mut c_void, value: i32, count: usize) -> *mut c_void {
    let base = destination as usize;
    for index in 0..count {
        unsafe { *((base + index) as *mut u8) = value as u8 };
    }
    core::ptr::null_mut()
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn memcpy(
    destination: *mut c_void,
    source: *const c_void,
    count: usize,
) -> *mut c_void {
    let (to, from) = (destination as usize, source as usize);
    for index in 0..count {
        unsafe { *((to + index) as *mut u8) = *((from + index) as *const u8) };
    }
    core::ptr::null_mut()
}
