// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.

//! BPF timers. A bpf_timer lives in a map value, and its callback takes
//! the map, the key and the value. `timer_map!` declares an array map of
//! them, and the functions here set one up and arm it.
//!
//! Every op runs with interrupts off, so bpf_timer_start() cannot touch
//! the hrtimer from there: it queues an irq_work, a self-IPI per arming.
//! From the callback itself, with interrupts on, it arms directly.

use core::ffi::c_void;

use crate::helpers;

const CLOCK_MONOTONIC: u64 = 1;

/// struct bpf_timer.
#[repr(C)]
pub struct bpf_timer {
    opaque: [u64; 2],
}

/// A timer map's value.
#[repr(C)]
pub struct Timer {
    timer: bpf_timer,
}

/// What a timer's callback is: `fn(map, key, value) -> u64`, the key an
/// integer of the map's key size.
pub type Callback<K> = unsafe extern "C" fn(*mut c_void, *mut K, *mut Timer) -> u64;

/// An array map of `$entries` timers named `$map`, of the type `$type`
/// this declares. A map of one entry per CID is declared with one entry
/// and sized by the loader.
#[macro_export]
macro_rules! timer_map {
    ($vis:vis $map:ident: $type:ident, entries: $entries:literal) => {
        #[repr(C)]
        $vis struct $type {
            r#type: *const [u32; 2],
            key: *const u32,
            value: *const $crate::timer::Timer,
            max_entries: *const [u32; $entries],
        }

        #[unsafe(no_mangle)]
        #[unsafe(link_section = ".maps")]
        $vis static mut $map: $type = $type {
            r#type: core::ptr::null(),
            key: core::ptr::null(),
            value: core::ptr::null(),
            max_entries: core::ptr::null(),
        };
    };
}

/// The timer at `key` of the timer map `map`, or null.
#[inline(always)]
pub unsafe fn lookup<M>(map: *mut M, key: u32) -> *mut Timer {
    unsafe { helpers::map_lookup_elem(map, &key) }
}

/// Set `timer`, of the timer map `map`, up to call `callback`, on
/// CLOCK_MONOTONIC. 0 or a negative errno.
#[inline(always)]
pub unsafe fn init<M, K>(timer: *mut Timer, map: *mut M, callback: Callback<K>) -> i32 {
    unsafe {
        let result = helpers::timer_init(timer.cast(), map, CLOCK_MONOTONIC);
        if result != 0 {
            return result as i32;
        }
        helpers::timer_set_callback(timer.cast(), callback as *const c_void) as i32
    }
}

/// Arm `timer` to fire `delta` ns from now, moving it if it is armed.
#[inline(always)]
pub unsafe fn start(timer: *mut Timer, delta: u64) {
    unsafe { helpers::timer_start(timer.cast(), delta, 0) };
}
