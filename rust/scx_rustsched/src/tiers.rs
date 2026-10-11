// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.

//! CPU capacity and asymmetric packing, per CID: what the loader reads
//! from the topology and the kernel arrives
//! per CPU before attach, and init translates it to CIDs.
//!
//! Capacity is normalized to 1024 for the fastest CPU. Both kinds of tier
//! count from 0, the most preferred. A CID's LLC also records the best
//! packing tier among its CIDs: fair.c compares an asymmetric scheduling
//! group by its preferred CPU, and the LLC is the child group of the
//! package-level packing domain. One mask of CIDs per packing tier lets a
//! scan restrict itself to a tier.

use core::ptr::{null_mut, read_volatile};

use crate::kfuncs::{bpf_arena_alloc_pages, scx_bpf_cid_to_cpu};
use crate::{
    cid_idle,
    edq::{Memory, View},
    pool::arena,
    queue::Arena,
};

const MAX_CPUS: usize = 8192;
const VALID: u64 = 1 << 63;
const ASYM_CAPACITY: u64 = 1;
const SCHED_ASYM_CAPACITY: u64 = 2;
const ASYM_PACKING: u64 = 4;
const FORCED: u64 = 8;
const ANY_SMT_ASYM_PACKING: u64 = 16;
/// A CID's entry: capacity, capacity tier, packing tier and its LLC's
/// best packing tier, 16 bits each, then whether the SMT domain packs and,
/// from bit 32, the width of its asymmetric capacity domain.
const ENTRY_BYTES: u64 = 16;

/// Written by the loader between load and attach: the capacity and packing
/// tier counts, the policy bits, and per CPU the valid bit, capacity,
/// capacity tier << 16, packing tier << 32 and SMT packing << 48.
#[used]
#[unsafe(no_mangle)]
#[unsafe(link_section = ".data.tiers")]
static mut TIERS: [u64; 4 + MAX_CPUS] = [0; 4 + MAX_CPUS];

/// The CID table, the packing tier masks, an unused slot, and the words per
/// mask.
#[used]
#[unsafe(no_mangle)]
#[unsafe(link_section = ".data.tiertab")]
static mut TABLE: [u64; 4] = [0; 4];

#[inline(always)]
fn header(index: usize) -> u64 {
    unsafe { read_volatile((&raw const TIERS).cast::<u64>().add(index)) }
}

#[inline(always)]
fn table(index: usize) -> u64 {
    unsafe { read_volatile((&raw const TABLE).cast::<u64>().add(index)) }
}

pub fn nr_capacity_tiers() -> u32 {
    header(0).max(1) as u32
}

pub fn nr_place_tiers() -> u32 {
    header(1).max(1) as u32
}

/// Placement and balance follow capacity.
pub fn asym_capacity() -> bool {
    header(2) & ASYM_CAPACITY != 0
}

/// The kernel has an SD_ASYM_CPUCAPACITY domain.
pub fn sched_asym_capacity() -> bool {
    header(2) & SCHED_ASYM_CAPACITY != 0
}

/// --asym-capacity forced placement to follow capacity.
pub fn forced_asym_capacity() -> bool {
    header(2) & FORCED != 0
}

/// Does any CPU's SMT domain pack, so that its threads rank?
pub fn any_smt_asym_packing() -> bool {
    header(2) & ANY_SMT_ASYM_PACKING != 0
}

pub fn asym_packing() -> bool {
    header(2) & ASYM_PACKING != 0
}

#[inline(always)]
fn entry(cid: i32) -> u64 {
    let base = table(0);
    if base == 0 || cid < 0 || cid as u32 >= crate::queue::cid_count() {
        return 0;
    }
    unsafe { Arena.load(base + cid as u32 as u64 * ENTRY_BYTES) }
}

/// The capacity of `cid`, 1024 for the fastest.
pub fn capacity(cid: i32) -> u64 {
    match entry(cid) & 0xffff {
        0 => 1024,
        capacity => capacity,
    }
}

/// capacity(), as a global function: its result is unknown to the
/// verifier, so a loop summing capacities converges instead of tracking a
/// bounded sum that changes each iteration.
#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn rust_cid_capacity(cid: i32) -> u64 {
    capacity(cid)
}

pub fn capacity_tier(cid: i32) -> u32 {
    (entry(cid) >> 16 & 0xffff) as u32
}

pub fn place_tier(cid: i32) -> u32 {
    (entry(cid) >> 32 & 0xffff) as u32
}

/// The best packing tier of the LLC of `cid`.
pub fn llc_place_tier(cid: i32) -> u32 {
    (entry(cid) >> 48) as u32
}

/// The SMT domain of `cid` packs: its core's threads rank too.
pub fn smt_asym_packing(cid: i32) -> bool {
    let base = table(0);
    if base == 0 || cid < 0 || cid as u32 >= crate::queue::cid_count() {
        return false;
    }
    unsafe { Arena.load(base + cid as u32 as u64 * ENTRY_BYTES + 8) & 1 != 0 }
}

/// The width of `cid`'s asymmetric capacity domain, SD_ASYM_CPUCAPACITY_FULL,
/// in CPUs, 0 for none.
pub fn asym_span(cid: i32) -> u32 {
    let base = table(0);
    if base == 0 || cid < 0 || cid as u32 >= crate::queue::cid_count() {
        return 0;
    }
    unsafe { (Arena.load(base + cid as u32 as u64 * ENTRY_BYTES + 8) >> 32 & 0x3fff) as u32 }
}

/// Word `index` of the mask of the CIDs in packing tier `tier`.
pub fn place_word(tier: u32, index: u32) -> u64 {
    mask_word(1, tier, index)
}

#[inline(always)]
fn mask_word(which: usize, tier: u32, index: u32) -> u64 {
    let (base, words) = (table(which), table(3));
    if base == 0 || u64::from(index) >= words {
        return 0;
    }
    unsafe { Arena.load(base + (u64::from(tier) * words + u64::from(index)) * 8) }
}

#[inline(always)]
unsafe fn alloc(bytes: u64) -> u64 {
    let pages = bytes.div_ceil(4096).max(1) as u32;
    unsafe { bpf_arena_alloc_pages((&raw mut arena).cast(), null_mut(), pages, -1, 0) as u64 }
}

/// Run `body` for each of `count` CIDs.
#[inline(always)]
fn for_each(count: u32, mut body: impl FnMut(i32)) {
    for value in crate::loops::range(0, count) {
        body(value as i32);
    }
}

/// Translate the loader's per-CPU table to the `count` CIDs. A CPU the
/// loader did not describe counts as full capacity in the last tiers.
pub unsafe fn init(count: u32) -> i32 {
    let words = u64::from(count).div_ceil(64);
    let (place_tiers, capacity_tiers) =
        (u64::from(nr_place_tiers()), u64::from(nr_capacity_tiers()));
    unsafe {
        let base = alloc(u64::from(count) * ENTRY_BYTES);
        let place = alloc(place_tiers * words * 8);
        if base == 0 || place == 0 {
            return -12;
        }
        TABLE[0] = base;
        TABLE[1] = place;
        TABLE[3] = words;
        // Each CID's entry, and each LLC's best packing tier at its first
        // CID, in the second word of the entry until the second pass.
        for_each(count, |cid| {
            let cpu = scx_bpf_cid_to_cpu(cid);
            let raw = if cpu >= 0 && (cpu as usize) < MAX_CPUS {
                header(4 + cpu as usize)
            } else {
                0
            };
            let (cap, cap_tier, place_tier, smt) = if raw & VALID != 0 {
                (
                    raw & 0xffff,
                    (raw >> 16 & 0xffff).min(capacity_tiers - 1),
                    (raw >> 32 & 0xffff).min(place_tiers - 1),
                    raw >> 48 & 1 | (raw >> 49 & 0x3fff) << 32,
                )
            } else {
                (1024, capacity_tiers - 1, place_tiers - 1, 0)
            };
            let address = base + cid as u32 as u64 * ENTRY_BYTES;
            Arena.store(address, cap | cap_tier << 16 | place_tier << 32);
            // The second word: the SMT bit, the asymmetric capacity span from
            // bit 32 and, on an LLC's first CID until the second pass, the
            // LLC's best packing tier in bits 16 to 31.
            let (_, llc) = cid_idle::llc_span(cid);
            let first = base + u64::from(llc) * ENTRY_BYTES;
            if llc == cid as u32 {
                Arena.store(address + 8, smt | place_tier << 16);
            } else {
                Arena.store(address + 8, smt);
                let held = Arena.load(first + 8);
                let best = (held >> 16 & 0xffff).min(place_tier);
                Arena.store(first + 8, held & !(0xffff << 16) | best << 16);
            }
            let word = place + (place_tier * words + u64::from(cid as u32 / 64)) * 8;
            Arena.store(word, Arena.load(word) | 1 << (cid as u32 % 64));
        });
        for_each(count, |cid| {
            let address = base + cid as u32 as u64 * ENTRY_BYTES;
            let (_, llc) = cid_idle::llc_span(cid);
            let best = Arena.load(base + u64::from(llc) * ENTRY_BYTES + 8) >> 16 & 0xffff;
            Arena.store(address, Arena.load(address) & 0xffff_ffff_ffff | best << 48);
        });
        // The LLC's best tier has been copied out; keep the SMT bit and the
        // asymmetric capacity span.
        for_each(count, |cid| {
            let address = base + cid as u32 as u64 * ENTRY_BYTES + 8;
            Arena.store(address, Arena.load(address) & (1 | 0x3fff << 32));
        });
    }
    0
}
