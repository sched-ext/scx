// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.

//! The arena: its map, the view of it the EDQ and the slab work through,
//! and the statistics the loader reads back. `slots` hands out per-task
//! slots in it.

use core::{
    arch::asm,
    intrinsics::{AtomicOrdering, atomic_xadd},
    ptr::null,
};

use crate::{
    edq::{Memory, View},
    mem,
};

#[repr(C)]
pub struct ArenaMap {
    r#type: *const [u32; 33],
    map_flags: *const [u32; 1024],
    max_entries: *const [u32; 4096],
}

#[unsafe(no_mangle)]
#[unsafe(link_section = ".maps")]
pub static mut arena: ArenaMap = ArenaMap {
    r#type: null(),
    map_flags: null(),
    max_entries: null(),
};

/// Slots taken, slots released, validation errors, failed page
/// allocations, pages allocated, and idle-mask updates that ran out of
/// retries. The loader reads them back at exit. Nothing on a hot path is
/// counted: the words are shared by every CPU.
#[used]
#[unsafe(no_mangle)]
#[unsafe(link_section = ".data.astats")]
pub static mut ARENA_STATS: [u64; 6] = [0; 6];

/// Reference the arena map, so that the verifier associates the program
/// with it, which every program that casts arena addresses needs once.
/// Each callback does this at its entry, and the accessors do not: they
/// loaded the map's address into a register on every access.
#[inline(always)]
pub fn touch() {
    unsafe { asm!("", in("r0") &raw mut arena, options(nostack)) };
}

/// Count a validation error, which makes the loader fail on detach.
pub fn count_error() {
    count(2);
}

/// Count an idle-state update that ran out of compare-and-swap retries,
/// which makes the loader fail on detach. It lives beside the arena
/// errors because, like them, it should never happen: events on the hot
/// paths are not counted.
pub fn count_cas_failure() {
    count(5);
}

#[inline(always)]
pub(crate) fn count(index: usize) {
    add(index, 1);
}

#[inline(always)]
pub(crate) fn add(index: usize, value: u64) {
    unsafe {
        atomic_xadd::<u64, u64, { AtomicOrdering::Relaxed }>(
            (&raw mut ARENA_STATS).cast::<u64>().add(index),
            value,
        );
    }
}

/// The arena, as the EDQ and the slab see it.
#[derive(Clone, Copy)]
pub struct Arena;

/// Allocate `pages` pages of the arena, zeroed, and return their address,
/// or 0 if there is no memory or the allocation was contended.
#[inline(always)]
pub fn alloc_pages(pages: u32) -> u64 {
    unsafe {
        crate::kfuncs::bpf_arena_alloc_pages(
            (&raw mut arena).cast(),
            core::ptr::null_mut(),
            pages,
            -1,
            0,
        ) as u64
    }
}

/// Give back `pages` pages at `address`, which alloc_pages() returned.
/// Nothing may use them afterwards: they read as zero, or as what their
/// next owner stores.
#[inline(always)]
pub fn free_pages(address: u64, pages: u32) {
    unsafe {
        crate::kfuncs::bpf_arena_free_pages(
            (&raw mut arena).cast(),
            address as *mut core::ffi::c_void,
            pages,
        )
    };
}

impl View for Arena {
    #[inline(always)]
    fn load_word(&self, base: u64, word: u64) -> u64 {
        mem::load(base, word * 8)
    }

    #[inline(always)]
    fn load(&self, address: u64) -> u64 {
        mem::load(address, 0)
    }
}

impl Memory for Arena {
    #[inline(always)]
    fn store_word(&self, base: u64, word: u64, value: u64) {
        mem::store(base, word * 8, value)
    }

    #[inline(always)]
    fn store(&self, address: u64, value: u64) {
        mem::store(address, 0, value)
    }

    /// An exchange, so that the store is ordered on weakly ordered CPUs too.
    #[inline(always)]
    fn release(&self, address: u64, value: u64) {
        mem::release(address, value)
    }

    /// The previous value, to be compared with `old`.
    #[inline(always)]
    fn cas(&self, address: u64, old: u64, new: u64) -> u64 {
        mem::cas(address, old, new)
    }

    #[inline(always)]
    fn add(&self, address: u64, value: u64) {
        mem::add(address, value)
    }

    #[inline(always)]
    fn repeat(&self, limit: u32, mut body: impl FnMut() -> bool) -> bool {
        crate::loops::arena_for(0, limit, |_| body())
    }

    fn corrupt(&self) {
        count_error();
    }
}
