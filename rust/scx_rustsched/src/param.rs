// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.

//! The scheduler's tunables: constants the loader can set by name before
//! the scheduler starts.
//!
//! ```ignore
//! scx::params! {
//!     /// The time slice, in nanoseconds.
//!     SLICE_NS: u64 = 5_000_000;
//!     /// Give a waking task an idle CPU.
//!     WAKE_IDLE: bool = true;
//! }
//!
//! dsq::insert(task, Dsq::Global, SLICE_NS.get(), flags);
//! ```
//!
//! A tunable may also be an array, `MASK: [u64; 4] = [0; 4];`, read one
//! element at a time with `MASK.at(index)`.
//!
//! Each is a read-only value with the default written here, in a section
//! named after it and its type, which the loader finds in the object. The
//! loader sets each from the option of the same name, such as `--slice-ns
//! 1000000`, or from the one that gives a time in microseconds,
//! `--slice-us 1000`.
//!
//! `opts!()` declares the tunables from those options instead, so that
//! each is written once, in the loader: see `scx_rustsched_macros`. `params!` is
//! then for what no option gives as it stands, such as an array the
//! loader fills from a list.
//! The values are frozen when the object is loaded, so the verifier sees
//! them as constants and drops the branches a `bool` rules out.

use core::ptr::read_volatile;

/// A tunable, see `params!`.
#[repr(transparent)]
pub struct Param<T>(T);

impl<T: Copy> Param<T> {
    pub const fn new(value: T) -> Self {
        Self(value)
    }

    /// The value the loader set, or the default. A volatile read: the
    /// compiler must not take the default for the value.
    #[inline(always)]
    pub fn get(&self) -> T {
        unsafe { read_volatile(&raw const self.0) }
    }
}

impl<T: Copy, const N: usize> Param<[T; N]> {
    /// How many elements the array has.
    pub const fn len(&self) -> usize {
        N
    }

    /// Element `index` as the loader set it, None past the end.
    #[inline(always)]
    pub fn at(&self, index: usize) -> Option<T> {
        if index < N {
            Some(unsafe { read_volatile((&raw const self.0).cast::<T>().add(index)) })
        } else {
            None
        }
    }
}

/// Declare the scheduler's tunables: `NAME: type = default;` for each, of
/// an integer type or `bool`, or an array of one.
#[macro_export]
macro_rules! params {
    () => {};
    ($(#[$doc:meta])* $vis:vis $name:ident: [$type:ty; $len:expr] = $value:expr; $($rest:tt)*) => {
        $(#[$doc])*
        #[used]
        #[unsafe(no_mangle)]
        #[unsafe(link_section = concat!(
            ".rodata.param.",
            stringify!($name),
            ".[",
            stringify!($type),
            "]"
        ))]
        $vis static $name: $crate::param::Param<[$type; $len]> = $crate::param::Param::new($value);
        $crate::params! { $($rest)* }
    };
    ($(#[$doc:meta])* $vis:vis $name:ident: $type:ty = $value:expr; $($rest:tt)*) => {
        $(#[$doc])*
        #[used]
        #[unsafe(no_mangle)]
        #[unsafe(link_section = concat!(
            ".rodata.param.",
            stringify!($name),
            ".",
            stringify!($type)
        ))]
        $vis static $name: $crate::param::Param<$type> = $crate::param::Param::new($value);
        $crate::params! { $($rest)* }
    };
}
