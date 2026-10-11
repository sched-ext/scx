// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.

//! Tables in the arena with one entry per CID: what a scheduler keeps per
//! CPU, where any CPU can read it.
//!
//! `cid_table!` declares a table: its header, a few words in a `.data`
//! section of its own that hold the table's arena address and the number
//! of CIDs it covers, and a type that implements [`CidTable`] for it. The
//! table itself is allocated at init, for the CIDs present, zeroed.
//!
//! An entry is a number of 64-bit words, read and written through `mem`
//! by the entry's arena address and the word's offset.

use core::ptr::{null_mut, read_volatile, write_volatile};

use crate::{kfuncs::bpf_arena_alloc_pages, mem, pool};

/// A per-CID table, see `cid_table!`.
pub trait CidTable {
    /// Bytes per entry, a multiple of 8.
    const BYTES: u64;

    /// The header: the table's arena address, the number of CIDs, and the
    /// extra words the declaration asked for.
    fn header() -> *mut u64;

    /// Allocate the table for `count` CIDs, from init. 0 or -ENOMEM.
    #[inline(always)]
    unsafe fn init(count: u32) -> i32 {
        let pages = (u64::from(count) * Self::BYTES).div_ceil(4096) as u32;
        let table = unsafe {
            bpf_arena_alloc_pages((&raw mut pool::arena).cast(), null_mut(), pages, -1, 0)
        };
        if table.is_null() {
            return -12;
        }
        unsafe {
            write_volatile(Self::header(), table as u64);
            write_volatile(Self::header().add(1), u64::from(count));
        }
        0
    }

    /// The table's arena address, 0 before init.
    #[inline(always)]
    fn base() -> u64 {
        unsafe { read_volatile(Self::header()) }
    }

    /// The number of CIDs the table covers.
    #[inline(always)]
    fn count() -> u32 {
        unsafe { read_volatile(Self::header().add(1)) as u32 }
    }

    /// Is `cid` within the table?
    #[inline(always)]
    fn valid(cid: i32) -> bool {
        cid >= 0 && (cid as u64) < unsafe { read_volatile(Self::header().add(1)) }
    }

    /// The arena address of word `index` of `cid`'s entry, for the atomic
    /// accessors of `mem`.
    #[inline(always)]
    fn address(cid: i32, index: u64) -> u64 {
        Self::base() + cid as u32 as u64 * Self::BYTES + index * 8
    }

    /// The arena address of `cid`'s entry. The caller checks `cid`.
    #[inline(always)]
    fn entry(cid: i32) -> u64 {
        Self::base() + cid as u32 as u64 * Self::BYTES
    }

    /// Word `index` of `cid`'s entry. The caller checks `cid`.
    #[inline(always)]
    unsafe fn get(cid: i32, index: u64) -> u64 {
        unsafe { mem::load(Self::entry(cid), index * 8) }
    }

    #[inline(always)]
    unsafe fn set(cid: i32, index: u64, value: u64) {
        unsafe { mem::store(Self::entry(cid), index * 8, value) }
    }

    /// Extra header word `index`.
    #[inline(always)]
    fn extra(index: usize) -> u64 {
        unsafe { read_volatile(Self::header().add(2 + index)) }
    }

    #[inline(always)]
    unsafe fn set_extra(index: usize, value: u64) {
        unsafe { write_volatile(Self::header().add(2 + index), value) }
    }
}

/// Declare the per-CID table `$type`, of `$bytes` bytes per entry, with
/// its header `$header` in `$section`, which the loader can read by that
/// name. `extra` adds words to the header for the declaring module's own
/// use.
#[macro_export]
macro_rules! cid_table {
    ($vis:vis $type:ident, $header:ident in $section:literal, bytes: $bytes:expr) => {
        $crate::cid_table!($vis $type, $header in $section, bytes: $bytes, extra: 0);
    };
    ($vis:vis $type:ident, $header:ident in $section:literal, bytes: $bytes:expr, extra: $extra:literal) => {
        #[used]
        #[unsafe(no_mangle)]
        #[unsafe(link_section = $section)]
        static mut $header: [u64; 2 + $extra] = [0; 2 + $extra];

        $vis struct $type;

        impl $crate::cid_table::CidTable for $type {
            const BYTES: u64 = $bytes;

            #[inline(always)]
            fn header() -> *mut u64 {
                (&raw mut $header).cast()
            }
        }
    };
}
