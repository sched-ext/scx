// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2026 Galih Tama <galpt@v.recipes>

#![allow(dead_code, unused_imports)]

use std::sync::atomic::{AtomicUsize, Ordering};

#[cfg(feature = "count_alloc")]
use std::alloc::{GlobalAlloc, Layout, System};

/// Counters for the optional allocation tracker. Only active when the
/// `count_alloc` feature is enabled. The global allocator below bumps
/// these on every heap allocation, so a hot-path iteration that stays at
/// zero proves the zero-allocation guarantee.
pub static ALLOC_COUNT: AtomicUsize = AtomicUsize::new(0);
pub static ALLOC_BYTES: AtomicUsize = AtomicUsize::new(0);

/// Reset the counters to zero. Call before a measurement window.
pub fn reset_counters() {
    ALLOC_COUNT.store(0, Ordering::Relaxed);
    ALLOC_BYTES.store(0, Ordering::Relaxed);
}

/// Read the current counters.
pub fn counters() -> (usize, usize) {
    (
        ALLOC_COUNT.load(Ordering::Relaxed),
        ALLOC_BYTES.load(Ordering::Relaxed),
    )
}

#[cfg(feature = "count_alloc")]
pub struct TrackingAllocator;

#[cfg(feature = "count_alloc")]
unsafe impl GlobalAlloc for TrackingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOC_COUNT.fetch_add(1, Ordering::Relaxed);
        ALLOC_BYTES.fetch_add(layout.size(), Ordering::Relaxed);
        System.alloc(layout)
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        System.dealloc(ptr, layout)
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        ALLOC_COUNT.fetch_add(1, Ordering::Relaxed);
        ALLOC_BYTES.fetch_add(layout.size(), Ordering::Relaxed);
        System.alloc_zeroed(layout)
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        ALLOC_COUNT.fetch_add(1, Ordering::Relaxed);
        ALLOC_BYTES.fetch_add(new_size, Ordering::Relaxed);
        System.realloc(ptr, layout, new_size)
    }
}
