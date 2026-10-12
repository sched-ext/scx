// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.

//! A set of CIDs as the kernel hands one over, struct scx_cmask: the
//! affinity ops.set_cmask() reports.
//!
//! The kernel builds the mask in the scheduler's arena, in scratch memory
//! of the CPU the callback runs on, and reuses it once the callback
//! returns. `Cmask` is therefore neither `Copy` nor `Clone`: what a
//! scheduler wants to keep, it reads out. The mask is read with the arena
//! loads of `mem`, which need no bounds the verifier can see.

use crate::{mem, sched::Cid};

/// Offsets in struct scx_cmask: base, nr_cids and alloc_words are u32, and
/// bits[] follows them at the next 64-bit boundary.
const BASE: u64 = 0;
const NR_CIDS: u64 = 4;
const BITS: u64 = 16;

/// A mask of CIDs in the arena, valid for the callback it was passed to.
pub struct Cmask(u64);

impl Cmask {
    /// # Safety
    /// `address` must be the arena address of a struct scx_cmask the
    /// kernel passed to the running callback.
    #[inline(always)]
    pub unsafe fn from_raw(address: u64) -> Cmask {
        Cmask(address)
    }

    /// The first CID the mask covers.
    #[inline(always)]
    pub fn base(&self) -> u32 {
        unsafe { mem::load32(self.0, BASE) }
    }

    /// How many CIDs the mask covers, from `base()` on.
    #[inline(always)]
    pub fn nr_cids(&self) -> u32 {
        unsafe { mem::load32(self.0, NR_CIDS) }
    }

    /// How many words of bits the covered range spans. The first holds
    /// `base()`, which need not be the word's first bit.
    #[inline(always)]
    pub fn nr_words(&self) -> u32 {
        let (base, nr_cids) = (self.base(), self.nr_cids());
        if nr_cids == 0 {
            return 0;
        }
        (base + nr_cids - 1) / 64 - base / 64 + 1
    }

    /// Word `index` of the mask, counted from the word `base()` is in: bit
    /// `n` is CID `(base() / 64 + index) * 64 + n`. Zero past the end.
    #[inline(always)]
    pub fn word(&self, index: u32) -> u64 {
        if index >= self.nr_words() {
            return 0;
        }
        unsafe { mem::load(self.0, BITS + u64::from(index) * 8) }
    }

    /// Is `cid` in the mask?
    #[inline(always)]
    pub fn test(&self, cid: Cid) -> bool {
        let (base, nr_cids) = (self.base(), self.nr_cids());
        let cid = cid.raw() as u32;
        if cid < base || cid - base >= nr_cids {
            return false;
        }
        let word = unsafe { mem::load(self.0, BITS + u64::from(cid / 64 - base / 64) * 8) };
        word & (1 << (cid & 63)) != 0
    }
}
