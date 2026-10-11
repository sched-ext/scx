// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.

//! The runtime's per-CID words, in a table of their own in the arena: the
//! idle scans' budgets and the task clock's offset, and a few flags the
//! policy sets once. Two words per CID. The header also keeps the
//! kernel's nr_cpu_ids, which does not change once loaded.

use core::ptr::{read_volatile, write_volatile};

use crate::cid_table::CidTable;

/// The SIS_UTIL budgets, see cid_idle.rs.
pub const BUDGETS: u64 = 0;
/// The rq clock less the task clock at the last owned read, see clock.rs.
pub const CLOCK_OFF: u64 = 1;

/// Flags: whether the idle scan is bounded by SIS_UTIL.
pub const SCAN_BOUNDED: u64 = 1;

// The table, with the flags and nr_cpu_ids in its header's extra words.
crate::cid_table!(Cids, CIDS in ".data.cids", bytes: 16, extra: 2);

/// The extra header word that holds nr_cpu_ids.
const NR_CPU_IDS: usize = 1;

/// Allocate the table for `count` CIDs, from init.
pub unsafe fn init(count: u32) -> i32 {
    let result = unsafe { Cids::init(count) };
    if result == 0 {
        unsafe { Cids::set_extra(NR_CPU_IDS, u64::from(crate::kfuncs::scx_bpf_nr_cpu_ids())) };
    }
    result
}

/// nr_cpu_ids, as init read it.
#[inline(always)]
pub fn nr_cpu_ids() -> u32 {
    Cids::extra(NR_CPU_IDS) as u32
}

/// The number of CIDs.
#[inline(always)]
pub fn count() -> u32 {
    Cids::count()
}

/// Is `cid` within the table?
#[inline(always)]
pub fn valid(cid: i32) -> bool {
    Cids::valid(cid)
}

/// The arena address of `cid`'s entry.
#[inline(always)]
pub fn entry(cid: i32) -> u64 {
    Cids::entry(cid)
}

#[inline(always)]
pub fn get(cid: i32, index: u64) -> u64 {
    unsafe { Cids::get(cid, index) }
}

#[inline(always)]
pub unsafe fn set(cid: i32, index: u64, value: u64) {
    unsafe { Cids::set(cid, index, value) }
}

#[inline(always)]
pub fn flag(bit: u64) -> bool {
    Cids::extra(0) & bit != 0
}

#[inline(always)]
pub unsafe fn set_flag(bit: u64, set: bool) {
    unsafe {
        let flags = Cids::header().add(2);
        let value = read_volatile(flags);
        write_volatile(flags, if set { value | bit } else { value & !bit });
    }
}
