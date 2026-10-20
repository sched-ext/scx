// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.

#[path = "../../scx_rustsched/src/cid_ranges.rs"]
mod cid_ranges;

use cid_ranges::{RangeBuilder, RangeEnds, SegmentBuilder, word_mask};

#[test]
fn builds_nested_ranges_in_reverse_cid_order() {
    let mut builder = RangeBuilder::new();
    for cid in (0..32).rev() {
        let core = cid / 2 * 2;
        let cluster = cid / 4 * 4;
        let shard = cid / 8 * 8;
        let llc = cid / 8 * 8;
        let node = cid / 16 * 16;
        assert_eq!(
            builder.add(
                cid,
                core as i32,
                cluster as i32,
                shard as i32,
                llc as i32,
                node as i32
            ),
            RangeEnds {
                core_base: core,
                core: core + 2,
                cluster_base: cluster,
                cluster: cluster + 4,
                shard_base: shard,
                shard: shard + 8,
                llc: llc + 8,
                node: node + 16,
                segment_word: 0,
            }
        );
    }
}

#[test]
fn legacy_cluster_follows_llc() {
    let mut builder = RangeBuilder::new();
    for cid in (0..8).rev() {
        let llc = cid / 4 * 4;
        let ends = builder.add(cid, cid as i32, llc as i32, llc as i32, llc as i32, 0);
        assert_eq!(ends.cluster_base, llc);
        assert_eq!(ends.cluster, ends.llc);
        assert_eq!(ends.llc, llc + 4);
    }
}

#[test]
fn invalid_topology_is_singleton_without_resetting_builder() {
    let mut builder = RangeBuilder::new();
    assert_eq!(
        builder.add(3, 0, 0, 0, 0, 0),
        RangeEnds {
            core_base: 0,
            core: 4,
            cluster_base: 0,
            cluster: 4,
            shard_base: 0,
            shard: 4,
            llc: 4,
            node: 4,
            segment_word: 0,
        }
    );
    assert_eq!(
        builder.add(2, -1, -1, -1, -1, -1),
        RangeEnds {
            core_base: 2,
            core: 3,
            cluster_base: 2,
            cluster: 3,
            shard_base: 2,
            shard: 3,
            llc: 3,
            node: 3,
            segment_word: 0,
        }
    );
    assert_eq!(
        builder.add(1, 0, 0, 0, 0, 0),
        RangeEnds {
            core_base: 0,
            core: 4,
            cluster_base: 0,
            cluster: 4,
            shard_base: 0,
            shard: 4,
            llc: 4,
            node: 4,
            segment_word: 0,
        }
    );
    assert_eq!(builder.add(0, 1, 0, 0, 0, 0).core_base, 0);
}

#[test]
fn masks_full_cores_across_bitmap_words() {
    assert_eq!(word_mask(62, 66, 0), 0xc000_0000_0000_0000);
    assert_eq!(word_mask(62, 66, 64), 0x3);
    assert_eq!(word_mask(62, 66, 128), 0);
    assert_eq!(word_mask(0, 64, 0), u64::MAX);
    assert_eq!(word_mask(64, 65, 64), 1);
    assert_eq!(word_mask(67, 70, 66), 0xe);
    assert_eq!(word_mask(70, 71, 70), 1);
}

#[test]
fn packs_shard_words_without_overlapping_adjacent_segments() {
    let mut builder = SegmentBuilder::new();
    for cid in 0..66 {
        assert_eq!(builder.add(cid, 0, 66), Some(0));
    }
    for cid in 66..70 {
        assert_eq!(builder.add(cid, 66, 70), Some(8));
    }
    assert_eq!(builder.words(), 16);
    assert_eq!(builder.add(70, 66, 70), None);
}

#[test]
fn rejects_noncontiguous_shard_ranges() {
    let mut builder = SegmentBuilder::new();
    assert_eq!(builder.add(0, 0, 2), Some(0));
    assert_eq!(builder.add(1, 1, 2), None);
    assert_eq!(builder.add(1, 0, 2), Some(0));
    assert_eq!(builder.add(2, 1, 4), None);
}
