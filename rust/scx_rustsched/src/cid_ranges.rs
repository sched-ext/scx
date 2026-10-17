// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RangeEnds {
    pub core_base: u32,
    pub core: u32,
    pub cluster_base: u32,
    pub cluster: u32,
    pub shard_base: u32,
    pub shard: u32,
    pub llc: u32,
    pub node: u32,
    pub segment_word: u32,
}

pub struct RangeBuilder {
    last_core: i32,
    last_cluster: i32,
    last_shard: i32,
    last_llc: i32,
    last_node: i32,
    ends: RangeEnds,
}

impl RangeBuilder {
    pub const fn new() -> Self {
        Self {
            last_core: -1,
            last_cluster: -1,
            last_shard: -1,
            last_llc: -1,
            last_node: -1,
            ends: RangeEnds {
                core_base: 0,
                core: 0,
                cluster_base: 0,
                cluster: 0,
                shard_base: 0,
                shard: 0,
                llc: 0,
                node: 0,
                segment_word: 0,
            },
        }
    }

    #[inline(always)]
    pub fn add(
        &mut self,
        cid: u32,
        core: i32,
        cluster: i32,
        shard: i32,
        llc: i32,
        node: i32,
    ) -> RangeEnds {
        if core < 0
            || cluster < 0
            || shard < 0
            || llc < 0
            || node < 0
            || core as u32 > cid
            || cluster as u32 > cid
            || shard as u32 > cid
            || llc as u32 > cid
            || node as u32 > cid
        {
            return RangeEnds {
                core_base: cid,
                core: cid + 1,
                cluster_base: cid,
                cluster: cid + 1,
                shard_base: cid,
                shard: cid + 1,
                llc: cid + 1,
                node: cid + 1,
                segment_word: 0,
            };
        }
        if core != self.last_core {
            self.last_core = core;
            self.ends.core = cid + 1;
        }
        self.ends.core_base = core as u32;
        if cluster != self.last_cluster {
            self.last_cluster = cluster;
            self.ends.cluster = cid + 1;
        }
        self.ends.cluster_base = cluster as u32;
        if shard != self.last_shard {
            self.last_shard = shard;
            self.ends.shard = cid + 1;
        }
        self.ends.shard_base = shard as u32;
        if llc != self.last_llc {
            self.last_llc = llc;
            self.ends.llc = cid + 1;
        }
        if node != self.last_node {
            self.last_node = node;
            self.ends.node = cid + 1;
        }
        self.ends
    }
}

/// 64-bit words in a cache line.
pub const WORDS_PER_LINE: u32 = 8;

pub struct SegmentBuilder {
    base: u32,
    end: u32,
    word: u32,
    next_word: u32,
}

impl SegmentBuilder {
    pub const fn new() -> Self {
        Self {
            base: 0,
            end: 0,
            word: 0,
            next_word: 0,
        }
    }

    pub fn add(&mut self, cid: u32, base: u32, end: u32) -> Option<u32> {
        if base > cid || cid >= end {
            return None;
        }
        if cid == base {
            if cid != self.end {
                return None;
            }
            self.base = base;
            self.end = end;
            self.word = self.next_word;
            // Each segment on cache lines of its own, so that idle
            // transitions in one do not contend with those of another.
            self.next_word += (end - base).div_ceil(64).next_multiple_of(WORDS_PER_LINE);
        } else if base != self.base || end != self.end {
            return None;
        }
        Some(self.word)
    }

    pub const fn words(&self) -> u32 {
        self.next_word
    }
}

#[inline(always)]
pub fn word_mask(base: u32, end: u32, word_base: u32) -> u64 {
    if end <= word_base || base >= word_base + 64 {
        return 0;
    }
    let start = base.max(word_base) - word_base;
    let end = end.min(word_base + 64) - word_base;
    if start >= end {
        return 0;
    }
    (u64::MAX << start) & (u64::MAX >> (64 - end))
}
