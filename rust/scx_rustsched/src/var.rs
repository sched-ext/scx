// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.

//! A value the callbacks share: a global.
//!
//! Callbacks run on every CPU at once, so nothing they share can be handed
//! out as `&mut`. A `Var` is read and written whole through a shared
//! reference instead, each access one load or one store, as READ_ONCE()
//! and WRITE_ONCE() are in C. Two CPUs that update the same `Var` race as
//! they would there: the last store wins. `fetch_add()` is the atomic
//! update for a counter that must not lose one.
//!
//! ```ignore
//! static VTIME_NOW: Var<u64> = Var::new(0);
//!
//! #[derive(Default)]
//! struct TaskCtx {
//!     vtime: Var<u64>,
//! }
//! ```

use core::{
    cell::UnsafeCell,
    intrinsics::{AtomicOrdering, atomic_cxchg, atomic_xadd},
    ptr::{read_volatile, write_volatile},
};

/// Declare a static in a section of its own, which libbpf makes a map of
/// that name: a loader finds the value by it, and nothing else shares its
/// cache lines. The section is a `.data.` or `.bss.` name no other static
/// uses.
///
/// ```ignore
/// scx_rustsched::shared! {
///     /// Tasks queued, for the loader's statistics.
///     pub static NR_QUEUED in ".data.queued": Var<u64> = Var::new(0);
/// }
/// ```
#[macro_export]
macro_rules! shared {
    ($(#[$attr:meta])* $vis:vis static $name:ident in $section:literal : $type:ty = $init:expr;) => {
        $(#[$attr])*
        #[used]
        #[unsafe(no_mangle)]
        #[unsafe(link_section = $section)]
        $vis static $name: $type = $init;
    };
}

#[repr(transparent)]
pub struct Var<T>(UnsafeCell<T>);

// Every access is a whole volatile load or store of a `Copy` value.
unsafe impl<T: Copy> Sync for Var<T> {}

impl<T: Copy> Var<T> {
    pub const fn new(value: T) -> Self {
        Self(UnsafeCell::new(value))
    }

    #[inline(always)]
    pub fn get(&self) -> T {
        unsafe { read_volatile(self.0.get()) }
    }

    #[inline(always)]
    pub fn set(&self, value: T) {
        unsafe { write_volatile(self.0.get(), value) }
    }

    /// Store what `update` makes of the current value, and return it. Not
    /// atomic: a concurrent store between the load and the store is lost.
    #[inline(always)]
    pub fn update(&self, update: impl FnOnce(T) -> T) -> T {
        let value = update(self.get());
        self.set(value);
        value
    }
}

impl<T: Copy + Default> Default for Var<T> {
    fn default() -> Self {
        Self::new(T::default())
    }
}

impl Var<u64> {
    /// Add `value` atomically, and return the value before.
    #[inline(always)]
    pub fn fetch_add(&self, value: u64) -> u64 {
        // Not Relaxed: LLVM's BPF backend lowers a relaxed atomicrmw add to
        // the non-fetching `lock +=`, whose result register is `value`
        // itself, even when the result is used, and on BPF v3 it says
        // nothing. Any stronger ordering emits atomic_fetch_add, which on
        // BPF is the same instruction whatever the ordering.
        unsafe { atomic_xadd::<u64, u64, { AtomicOrdering::SeqCst }>(self.0.get(), value) }
    }

    /// Store `new` if the value is `old`, atomically, and return what it
    /// was: `old` if the store happened.
    #[inline(always)]
    pub fn compare_exchange(&self, old: u64, new: u64) -> u64 {
        unsafe {
            atomic_cxchg::<u64, { AtomicOrdering::SeqCst }, { AtomicOrdering::SeqCst }>(
                self.0.get(),
                old,
                new,
            )
            .0
        }
    }
}

/// `N` words the callbacks share, by index: a table of a fixed size, such
/// as one slot per registered object. An index past the end wraps, so
/// that no access can leave the table.
#[repr(transparent)]
pub struct VarArray<const N: usize>(UnsafeCell<[u64; N]>);

unsafe impl<const N: usize> Sync for VarArray<N> {}

impl<const N: usize> VarArray<N> {
    pub const fn new() -> Self {
        Self(UnsafeCell::new([0; N]))
    }

    #[inline(always)]
    fn word(&self, index: u64) -> *mut u64 {
        unsafe { self.0.get().cast::<u64>().add((index % N as u64) as usize) }
    }

    #[inline(always)]
    pub fn get(&self, index: u64) -> u64 {
        unsafe { read_volatile(self.word(index)) }
    }

    #[inline(always)]
    pub fn set(&self, index: u64, value: u64) {
        unsafe { write_volatile(self.word(index), value) }
    }

    /// Store `new` in word `index` if it holds `old`, atomically, and
    /// return what it held.
    #[inline(always)]
    pub fn compare_exchange(&self, index: u64, old: u64, new: u64) -> u64 {
        unsafe {
            atomic_cxchg::<u64, { AtomicOrdering::SeqCst }, { AtomicOrdering::SeqCst }>(
                self.word(index),
                old,
                new,
            )
            .0
        }
    }
}
