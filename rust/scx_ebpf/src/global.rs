//! Safe wrappers for BPF global variables.
//!
//! BPF programs execute in a single-threaded, per-CPU context with
//! preemption disabled.  This means mutable static access is data-race
//! free, but Rust's safety rules still require `unsafe` for every
//! `static mut` read/write.
//!
//! [`BpfGlobal<T>`] and [`BpfGlobalArray<T, N>`] encapsulate the
//! `UnsafeCell` + `Sync` pattern so that scheduler code can read and
//! write globals through safe `.get()` / `.set()` methods.
//!
//! Both types are `#[repr(transparent)]`, so the in-memory layout is
//! identical to the bare `T` / `[T; N]`.  The aya loader's
//! `override_global` can still locate and overwrite the value at the
//! symbol address.
//!
//! # Example
//!
//! ```ignore
//! use scx_ebpf::global::BpfGlobal;
//!
//! #[unsafe(no_mangle)]
//! static SLICE_NS: BpfGlobal<u64> = BpfGlobal::new(10_000);
//!
//! fn get_slice() -> u64 {
//!     SLICE_NS.get()   // no unsafe needed
//! }
//! ```

use core::cell::UnsafeCell;

/// Safe wrapper for a single BPF global variable.
///
/// `#[repr(transparent)]` guarantees the same layout as `T`, so the
/// loader can find and overwrite the value at the symbol address.
#[repr(transparent)]
pub struct BpfGlobal<T> {
    inner: UnsafeCell<T>,
}

// SAFETY: BPF execution is single-threaded per CPU with preemption
// disabled, so concurrent mutable access cannot occur.
unsafe impl<T> Sync for BpfGlobal<T> {}

impl<T: Copy> BpfGlobal<T> {
    /// Create a new global with the given initial value.
    pub const fn new(val: T) -> Self {
        Self {
            inner: UnsafeCell::new(val),
        }
    }

    /// Read the current value.
    #[inline(always)]
    pub fn get(&self) -> T {
        // SAFETY: BPF is single-threaded per CPU; no data race.
        unsafe { *self.inner.get() }
    }

    /// Overwrite the current value.
    #[inline(always)]
    pub fn set(&self, val: T) {
        // SAFETY: BPF is single-threaded per CPU; no data race.
        unsafe { *self.inner.get() = val }
    }

    /// Return a raw mutable pointer to the inner value.
    ///
    /// This is useful when you need to pass the address to inline asm
    /// or `bpf_kptr_xchg`.
    #[inline(always)]
    pub const fn as_ptr(&self) -> *mut T {
        self.inner.get()
    }
}

/// Safe wrapper for a fixed-size BPF global array.
///
/// Provides bounds-checked access via `get()` / `set()` that return
/// `Option`, and an unchecked variant for hot paths where the caller
/// has already validated the index.
#[repr(transparent)]
pub struct BpfGlobalArray<T, const N: usize> {
    inner: UnsafeCell<[T; N]>,
}

// SAFETY: same as BpfGlobal — single-threaded per-CPU execution.
unsafe impl<T, const N: usize> Sync for BpfGlobalArray<T, N> {}

impl<T: Copy, const N: usize> BpfGlobalArray<T, N> {
    /// Create a new global array with the given initial contents.
    pub const fn new(val: [T; N]) -> Self {
        Self {
            inner: UnsafeCell::new(val),
        }
    }

    /// Read element at `idx`, returning `None` if out of bounds.
    #[inline(always)]
    pub fn get(&self, idx: usize) -> Option<T> {
        if idx < N {
            // SAFETY: bounds checked above; single-threaded per CPU.
            Some(unsafe { (*self.inner.get())[idx] })
        } else {
            None
        }
    }

    /// Write element at `idx`, returning `false` if out of bounds.
    #[inline(always)]
    pub fn set(&self, idx: usize, val: T) -> bool {
        if idx < N {
            // SAFETY: bounds checked above; single-threaded per CPU.
            unsafe { (*self.inner.get())[idx] = val };
            true
        } else {
            false
        }
    }

    /// Read element at `idx` without bounds checking.
    ///
    /// # Safety
    ///
    /// Caller must ensure `idx < N`.
    #[inline(always)]
    pub unsafe fn get_unchecked(&self, idx: usize) -> T {
        (*self.inner.get())[idx]
    }

    /// Return a raw pointer to the underlying array.
    #[inline(always)]
    pub const fn as_ptr(&self) -> *mut [T; N] {
        self.inner.get()
    }
}
