// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.

//! BPF timers. A bpf_timer lives in a map value, and its callback takes
//! the map, the key and the value. `timer_map!` declares an array map of
//! them, and with a callback it declares how they fire too:
//!
//! ```ignore
//! scx::timer_map!(pub hrticks: Hrticks, entries: 1, callback: fire);
//!
//! fn fire(key: u32, timer: &Timer) {
//!     // The timer at `key` went off. It can be armed again from here.
//!     timer.start(1_000_000);
//! }
//!
//! Hrticks::init(key)?;               // once, from ops.init()
//! Hrticks::start(key, delta_ns);     // from any callback
//! ```
//!
//! The lower functions take the map and the timer by raw pointer.
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

impl Timer {
    /// Arm the timer to fire `delta` ns from now, moving it if it is
    /// armed. A timer that was never set up stays as it is.
    #[inline(always)]
    pub fn start(&self, delta: u64) {
        unsafe { start((self as *const Timer).cast_mut(), delta) };
    }
}

/// A map of timers declared with `timer_map!` and a callback.
pub trait TimerMap: Sized + 'static {
    fn map() -> *mut Self;
    fn callback() -> Callback<u32>;

    /// The timer at `key`, or None past the end of the map.
    #[inline(always)]
    fn get<'timer>(key: u32) -> Option<&'timer Timer> {
        unsafe { lookup(Self::map(), key).as_ref() }
    }

    /// Set the timer at `key` up to call the map's callback, once, from
    /// ops.init(). 0 or a negative errno.
    #[inline(always)]
    fn init(key: u32) -> i32 {
        unsafe {
            let timer = lookup(Self::map(), key);
            if timer.is_null() {
                return -2;
            }
            init(timer, Self::map(), Self::callback())
        }
    }

    /// Arm the timer at `key` to fire `delta` ns from now. False for a key
    /// past the end of the map.
    #[inline(always)]
    fn start(key: u32, delta: u64) -> bool {
        match Self::get(key) {
            Some(timer) => {
                timer.start(delta);
                true
            }
            None => false,
        }
    }
}

/// What a timer's callback is: `fn(map, key, value) -> u64`, the key an
/// integer of the map's key size.
pub type Callback<K> = unsafe extern "C" fn(*mut c_void, *mut K, *mut Timer) -> u64;

/// An array map of `$entries` timers named `$map`, of the type `$type`
/// this declares. A map of one entry per CID is declared with one entry
/// and sized by the loader.
#[macro_export]
macro_rules! timer_map {
    ($vis:vis $map:ident: $type:ident, entries: $entries:literal, callback: $callback:path) => {
        $crate::timer_map!($vis $map: $type, entries: $entries);

        impl $crate::timer::TimerMap for $type {
            #[inline(always)]
            fn map() -> *mut $type {
                &raw mut $map
            }

            #[inline(always)]
            fn callback() -> $crate::timer::Callback<u32> {
                // What the kernel calls: it hands the callback the key and
                // the timer, which stay valid until it returns.
                unsafe extern "C" fn scx_timer_fired(
                    _map: *mut core::ffi::c_void,
                    key: *mut u32,
                    timer: *mut $crate::timer::Timer,
                ) -> u64 {
                    unsafe { $callback(*key, &*timer) };
                    0
                }
                scx_timer_fired
            }
        }
    };
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
