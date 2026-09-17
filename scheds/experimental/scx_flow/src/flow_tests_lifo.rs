// SPDX-License-Identifier: GPL-2.0
/*
 * LIFO unit tests
 *
 * Covers the bounded LIFO helpers with period, index, wrap, starvation, and
 * mirror checks. Run with cargo test -p scx_flow flow_tests_lifo.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
use crate::flow_slot::*;

/*
 * Period holds 8 heads with one tail at K 8 plus one forced tail at MAX.
 * Seq 8, 17, and 26 stay tail, all others stay head except MAX stays tail.
 * Forced tails at period plus MAX keep max gap 9 with 8 heads everywhere
 * with wrap, so the bound stays exact with no drift.
 */
#[test]
fn lifo_period_holds_k_8_with_wrap() {
    for seq in 0..27u32 {
        let want = seq % 9 != 8;
        assert_eq!(lifo_take_head(seq), want);
    }
    assert!(!lifo_take_head(8));
    assert!(!lifo_take_head(17));
    assert!(!lifo_take_head(26));
    assert!(lifo_take_head(0));
    assert!(lifo_take_head(7));
    assert!(lifo_take_head(9));
    assert!(lifo_take_head(16));
    assert!(lifo_take_head(18));
    let max = u32::MAX;
    assert_eq!(max % 9, 3);
    assert!(!lifo_take_head(max));
    assert!(lifo_take_head(max.wrapping_sub(1)));
    assert!(!lifo_take_head(max.wrapping_sub(4)));
    let wrapped = max.wrapping_add(1);
    assert_eq!(wrapped, 0);
    assert!(lifo_take_head(wrapped));
    let wrap_tail = 8u32.wrapping_sub(9).wrapping_add(9);
    assert_eq!(wrap_tail, 8);
    assert!(!lifo_take_head(wrap_tail));
    assert_eq!((1u64 << 32) % 9, 4);
    for off in 0..18u32 {
        let seq = max.wrapping_add(off);
        let want = seq != u32::MAX && seq % 9 != 8;
        assert_eq!(lifo_take_head(seq), want);
    }
}

/*
 * Bound holds one tail per 9 with no more than 8 heads in a row. Nine
 * straight takes hold 8 heads and one tail, so the bound keeps one slot
 * tail per period with no starve. Forced tails at period plus MAX keep max
 * gap 9 with 8 heads everywhere with wrap.
 */
#[test]
fn lifo_bound_breach_hits_once_per_period() {
    for base in [0u32, 1, 9, 100, 1000, u32::MAX - 20] {
        let mut heads = 0u32;
        let mut tails = 0u32;
        for off in 0..9u32 {
            let seq = base.wrapping_add(off);
            if lifo_take_head(seq) {
                heads += 1;
            } else {
                tails += 1;
            }
        }
        assert_eq!(heads, 8);
        assert_eq!(tails, 1);
    }
    for base in [0u32, 7, 8, 9] {
        let mut run = 0u32;
        let mut worst = 0u32;
        for off in 0..27u32 {
            let seq = base.wrapping_add(off);
            if lifo_take_head(seq) {
                run += 1;
                if run > worst {
                    worst = run;
                }
            } else {
                run = 0;
            }
        }
        assert!(worst <= 8);
    }
    for off in 0..27u32 {
        let base = u32::MAX.wrapping_sub(26).wrapping_add(off);
        let mut run = 0u32;
        let mut worst = 0u32;
        for k in 0..27u32 {
            let seq = base.wrapping_add(k);
            if lifo_take_head(seq) {
                run += 1;
                if run > worst {
                    worst = run;
                }
            } else {
                run = 0;
            }
        }
        assert!(worst <= 8);
    }
}

/*
 * Index maps per CPU plus overflow at 2050 with no share. Per CPU holds CPU
 * times 2 plus group, overflow holds 2048 plus group, so total matches slot
 * max. Bad group falls to light with no trap.
 */
#[test]
fn lifo_idx_maps_per_cpu_plus_overflow() {
    use crate::flow_group::GROUP_HOG;
    use crate::flow_group::GROUP_LIGHT;
    assert_eq!(lifo_idx(false, 0, GROUP_LIGHT), 0);
    assert_eq!(lifo_idx(false, 0, GROUP_HOG), 1);
    assert_eq!(lifo_idx(false, 1, GROUP_LIGHT), 2);
    assert_eq!(lifo_idx(false, 1, GROUP_HOG), 3);
    assert_eq!(lifo_idx(false, 1023, GROUP_LIGHT), 2046);
    assert_eq!(lifo_idx(false, 1023, GROUP_HOG), 2047);
    assert_eq!(lifo_idx(true, 0, GROUP_LIGHT), 2048);
    assert_eq!(lifo_idx(true, 0, GROUP_HOG), 2049);
    assert_eq!(lifo_idx(true, 999, GROUP_LIGHT), 2048);
    assert_eq!(lifo_idx(false, 7, 9), lifo_idx(false, 7, GROUP_LIGHT));
    assert_eq!(lifo_idx(true, 7, 9), lifo_idx(true, 7, GROUP_LIGHT));
    assert_eq!(LIFO_NSEQ, 2050);
    assert_eq!(SLOT_MAX_DSQS, 2050);
    assert_eq!(LIFO_NSEQ, SLOT_MAX_DSQS);
    assert_eq!(
        LIFO_NSEQ,
        crate::bpf_intf::flow_consts_FLOW_SLOT_MAX_DSQS as u64
    );
}

/*
 * Victim drains within K plus ceil depth over D with bounded LIFO. Victim
 * sits at the tail behind depth, inserts run before drains with head to
 * front and tail past the victim, so at most 8 heads delay the victim.
 * Drains move at most D per pass, so the bound holds for all depths with
 * no starve.
 */
#[test]
fn lifo_starvation_bound_holds() {
    use std::collections::VecDeque;
    for depth in [0usize, 1, 4, 8, 9, 16, 32] {
        let bound = 8 + depth.div_ceil(4);
        let mut q: VecDeque<u32> = VecDeque::new();
        for i in 0..depth as u32 {
            q.push_back(i);
        }
        q.push_back(9999);
        let mut seq = 0u32;
        let mut steps = 0u32;
        let mut victim_done = false;
        let mut guard = 0u32;
        while !victim_done && guard < 100 {
            guard += 1;
            for _ in 0..2 {
                let head = lifo_take_head(seq);
                seq = seq.wrapping_add(1);
                if head {
                    q.push_front(5000 + seq);
                } else {
                    q.push_back(6000 + seq);
                }
            }
            let mut moved = 0u32;
            while moved < 4 && !q.is_empty() {
                let v = q.pop_front().unwrap();
                moved += 1;
                if v == 9999 {
                    victim_done = true;
                    break;
                }
            }
            if victim_done {
                break;
            }
            steps += 1;
            if steps > bound as u32 + 10 {
                break;
            }
        }
        assert!(victim_done);
        assert!(steps <= bound as u32);
    }
}

/*
 * Mirrors hold K, period, 2050, slice 1M, stats 272, and config 1000us. BPF
 * and Rust share the same period with no drift, so the bound stays exact on
 * both sides of the boundary.
 */
#[test]
fn lifo_mirrors_hold() {
    assert_eq!(LIFO_K, 8);
    assert_eq!(LIFO_PERIOD, 9);
    assert_eq!(LIFO_K, crate::bpf_intf::flow_consts_FLOW_LIFO_K as u64);
    assert_eq!(
        LIFO_PERIOD,
        crate::bpf_intf::flow_consts_FLOW_LIFO_PERIOD as u64
    );
    assert_eq!(LIFO_NSEQ, 2050);
    assert_eq!(
        LIFO_NSEQ,
        crate::bpf_intf::flow_consts_FLOW_SLOT_MAX_DSQS as u64
    );
    assert_eq!(crate::flow_slice::SLICE_NS, 1_000_000);
    assert_eq!(
        crate::flow_slice::SLICE_NS,
        crate::bpf_intf::flow_consts_FLOW_SLICE_NS as u64
    );
    assert_eq!(
        std::mem::size_of::<crate::bpf_intf::flow_sched_stats>(),
        272
    );
    assert_eq!(crate::flow_slice::SLICE_NS, 1_000_000);
    let cfg = crate::config::Config::default();
    assert_eq!(cfg.slice_ns, 1_000_000);
    assert!(cfg.describe().contains("slice=1000us"));
}
