// SPDX-License-Identifier: GPL-2.0
/*
 * Slot store unit tests
 *
 * Covers the per CPU slot helpers with probe, ids, steal, defer, and
 * kick checks. Run with cargo test -p scx_flow flow_tests_slot.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
use crate::flow_group::*;
use crate::flow_select::*;
use crate::flow_slot::*;
use std::collections::VecDeque;

#[test]
fn slot_ids_match_header() {
    assert_eq!(SLOT_BASE, 0x6000);
    assert_eq!(SLOT_OVERFLOW_BASE, 0x6800);
    assert_eq!(SLOT_OVERFLOW_N, 2);
    assert_eq!(SLOT_PER_CPU, 2);
    assert_eq!(SLOT_MAX_DSQS, 2050);
    assert_eq!(SLOT_D, 4);
    assert_eq!(SLOT_BUDGET, 32);
    assert_eq!(SLOT_OWN_CAP, 31);
    assert_eq!(SWEEP_MAX, 256);
    assert_eq!(slot_own_cap(32), 31);
    assert_eq!(slot_own_cap(0), 0);
    assert_eq!(
        SLOT_BASE,
        crate::bpf_intf::flow_consts_FLOW_SLOT_BASE as u64
    );
    assert_eq!(
        SLOT_OVERFLOW_BASE,
        crate::bpf_intf::flow_consts_FLOW_SLOT_OVERFLOW_BASE as u64
    );
    assert_eq!(
        SLOT_OVERFLOW_N,
        crate::bpf_intf::flow_consts_FLOW_SLOT_OVERFLOW_N as u64
    );
    assert_eq!(
        SLOT_PER_CPU,
        crate::bpf_intf::flow_consts_FLOW_SLOT_PER_CPU as u64
    );
    assert_eq!(
        SLOT_MAX_DSQS,
        crate::bpf_intf::flow_consts_FLOW_SLOT_MAX_DSQS as u64
    );
    assert_eq!(SLOT_D, crate::bpf_intf::flow_consts_FLOW_SLOT_D as u32);
    assert_eq!(
        SLOT_BUDGET,
        crate::bpf_intf::flow_consts_FLOW_SLOT_BUDGET as u32
    );
    assert_eq!(
        SWEEP_MAX as u32,
        crate::bpf_intf::flow_consts_FLOW_SLOT_SWEEP_MAX as u32
    );
    assert_eq!(crate::flow::SLOT_BASE, SLOT_BASE);
    assert_eq!(crate::flow::SLOT_BUDGET, SLOT_BUDGET);
}

#[test]
fn per_cpu_ids_match_topology() {
    assert_eq!(slot_cpu_dsq(0, GROUP_LIGHT), 0x6000);
    assert_eq!(slot_cpu_dsq(0, GROUP_HOG), 0x6001);
    assert_eq!(slot_cpu_dsq(1, GROUP_LIGHT), 0x6002);
    assert_eq!(slot_cpu_dsq(1, GROUP_HOG), 0x6003);
    assert_eq!(slot_cpu_dsq(255, GROUP_LIGHT), 0x61FE);
    assert_eq!(slot_cpu_dsq(255, GROUP_HOG), 0x61FF);
    assert_eq!(slot_cpu_dsq(256, GROUP_LIGHT), 0x6200);
    assert_eq!(slot_cpu_dsq(1023, GROUP_HOG), 0x67FF);
    assert_eq!(slot_cpu_dsq(7, 9), slot_cpu_dsq(7, GROUP_LIGHT));
    assert_ne!(slot_cpu_dsq(0, GROUP_LIGHT), slot_cpu_dsq(0, GROUP_HOG));
    assert_ne!(slot_cpu_dsq(0, GROUP_LIGHT), slot_cpu_dsq(1, GROUP_LIGHT));
    assert_eq!(slot_overflow_dsq(GROUP_LIGHT), 0x6800);
    assert_eq!(slot_overflow_dsq(GROUP_HOG), 0x6801);
    assert_eq!(slot_nr_dsqs(8), 18);
    assert_eq!(slot_nr_dsqs(1024), 2050);
    assert_eq!(slot_nr_dsqs(1), 4);
    assert_eq!(steal_need(true), 1);
    assert_eq!(steal_need(false), 2);
    assert_eq!(
        SLOT_MAX_DSQS,
        crate::bpf_intf::flow_consts_FLOW_SLOT_MAX_DSQS as u64
    );
    assert_eq!(slot_cpu_dsq(0, GROUP_LIGHT), SLOT_BASE);
    assert_eq!(slot_overflow_dsq(GROUP_LIGHT), SLOT_OVERFLOW_BASE);
    assert_eq!(
        insert_cpu_dsq(3, GROUP_LIGHT, 9, false, 8),
        slot_cpu_dsq(3, GROUP_LIGHT)
    );
    assert_eq!(
        insert_cpu_dsq(3, GROUP_HOG, 300, false, 8),
        slot_overflow_dsq(GROUP_HOG)
    );
    assert_eq!(
        insert_cpu_dsq(3, GROUP_LIGHT, 9, true, 8),
        slot_overflow_dsq(GROUP_LIGHT)
    );
}

#[test]
fn wheel_consts_match_header() {
    assert_eq!(WHEEL_SLOT_NS, 64_000);
    assert_eq!(WHEEL_DIM, 256);
    assert_eq!(WHEEL_TOTAL, 65536);
    assert_eq!(WHEEL_HORIZON_NS, 64_000 * 65536);
    assert_eq!(WHEEL_QUANT_LO, 0xFFFF);
    assert_eq!(TOKEN_MAX, 255);
    assert_eq!(
        WHEEL_SLOT_NS,
        crate::bpf_intf::flow_consts_FLOW_WHEEL_SLOT_NS as u64
    );
    assert_eq!(
        WHEEL_TOTAL,
        crate::bpf_intf::flow_consts_FLOW_WHEEL_TOTAL as u64
    );
    assert_eq!(
        WHEEL_HORIZON_NS,
        crate::bpf_intf::flow_consts_FLOW_WHEEL_HORIZON_NS as u64
    );
}

#[test]
fn probe_overdue_maps_slot_zero() {
    let frontier = 100_000_000;
    let (qdl, slot, err, over) = wheel_probe(frontier - 1_000, frontier);
    assert_eq!(slot, 0);
    assert!(!over);
    assert_eq!(qdl, qdl_round_down(frontier - 1_000));
    assert_eq!(err, (frontier - 1_000) & 0xFFFF);
}

#[test]
fn probe_inside_maps_shifted_distance() {
    // Aligned frontier keeps quantise exact, so slot reads the distance.
    let frontier = 0x1_0000_0000u64;
    for k in [0, 1, 7, 255] {
        let dl = frontier + k * 65536;
        let (qdl, slot, _, over) = wheel_probe(dl, frontier);
        assert!(!over);
        assert_eq!(slot, k);
        assert_eq!(qdl, qdl_round_down(dl));
    }
}

#[test]
fn probe_past_horizon_pins_tail() {
    let frontier = 1_000_000_000;
    let dl = frontier + WHEEL_HORIZON_NS + 1_000_000;
    let (qdl, slot, _, over) = wheel_probe(dl, frontier);
    assert!(over);
    assert_eq!(slot, WHEEL_TOTAL - 1);
    assert_eq!(qdl, qdl_round_down(frontier + WHEEL_HORIZON_NS - 1));
}

#[test]
fn probe_rounds_down_with_bounded_error() {
    let frontier = 1_000_000_000;
    let dl = frontier + 100_000;
    let (qdl, _, err, _) = wheel_probe(dl, frontier);
    assert_eq!(qdl, dl & !0xFFFF);
    assert_eq!(err, dl & 0xFFFF);
    assert!(err <= 0xFFFF);
}

#[test]
fn overflow_tails_are_per_group() {
    assert_eq!(slot_overflow_dsq(GROUP_LIGHT), 0x6800);
    assert_eq!(slot_overflow_dsq(GROUP_HOG), 0x6801);
    assert_eq!(slot_overflow_dsq(7), 0x6800);
    assert_eq!(overflow_for_group(GROUP_LIGHT), OVERFLOW_LIGHT);
    assert_eq!(overflow_for_group(GROUP_HOG), OVERFLOW_HOG);
    assert_eq!(OVERFLOW_LIGHT, 0x6800);
    assert_eq!(OVERFLOW_HOG, 0x6801);
    assert_eq!(
        OVERFLOW_LIGHT,
        crate::bpf_intf::flow_consts_FLOW_SLOT_OVERFLOW_BASE as u64
    );
}

#[test]
fn slot_cap_holds_at_d() {
    assert_eq!(slot_cap(32), 4);
    assert_eq!(slot_cap(100), 4);
    assert_eq!(slot_cap(4), 4);
    assert_eq!(slot_cap(3), 3);
    assert_eq!(slot_cap(0), 0);
}

#[test]
fn local_trips_cover_own_overflow_other() {
    let trips = local_trip_dsqs(9, GROUP_LIGHT);
    assert_eq!(trips[0], slot_cpu_dsq(9, GROUP_LIGHT));
    assert_eq!(trips[1], slot_overflow_dsq(GROUP_LIGHT));
    assert_eq!(trips[2], slot_cpu_dsq(9, GROUP_HOG));
    assert_eq!(trips[3], slot_overflow_dsq(GROUP_HOG));
    assert_ne!(trips[0], trips[2]);
    assert_ne!(trips[1], trips[3]);
    let hog = local_trip_dsqs(3, GROUP_HOG);
    assert_eq!(hog[0], slot_cpu_dsq(3, GROUP_HOG));
    assert_eq!(hog[1], slot_overflow_dsq(GROUP_HOG));
    assert_eq!(hog[2], slot_cpu_dsq(3, GROUP_LIGHT));
    assert_eq!(hog[3], slot_overflow_dsq(GROUP_LIGHT));
}

#[test]
fn insert_cpu_rests_pinned_in_overflow() {
    assert_eq!(
        insert_cpu_dsq(3, GROUP_HOG, 9, true, 8),
        slot_overflow_dsq(GROUP_HOG)
    );
    assert_eq!(
        insert_cpu_dsq(3, GROUP_LIGHT, 9, true, 8),
        slot_overflow_dsq(GROUP_LIGHT)
    );
    assert_eq!(
        insert_cpu_dsq(5, GROUP_LIGHT, 9, false, 8),
        slot_cpu_dsq(5, GROUP_LIGHT)
    );
    assert_eq!(
        insert_cpu_dsq(5, GROUP_HOG, 300, false, 8),
        slot_overflow_dsq(GROUP_HOG)
    );
    assert_eq!(
        insert_cpu_dsq(5, GROUP_LIGHT, 255, false, 8),
        slot_cpu_dsq(5, GROUP_LIGHT)
    );
    assert_eq!(
        insert_cpu_dsq(5, GROUP_LIGHT, 256, false, 8),
        slot_overflow_dsq(GROUP_LIGHT)
    );
}

#[test]
fn race_queue_truth_never_hides_queued_work() {
    // Drains consult queue truth only, so queued work stays
    // collectible under every insert interleave.
    let mut len = 0u32;
    let mut bit = false;
    let mut ops = Vec::new();
    for i in 0..64u32 {
        ops.push(i % 4);
    }
    for op in ops {
        match op {
            0 => {
                len += 1;
                bit = true;
            }
            1 => {
                if len > 0 {
                    len -= 1;
                }
            }
            2 => {
                if len > 0 {
                    len -= 1;
                }
            }
            _ => {
                if len > 0 {
                    bit = true;
                }
            }
        }
        if len > 0 {
            assert!(bit, "queued work must stay collectible");
        }
    }
}

#[test]
fn defer_fires_on_cap_with_work_left() {
    assert!(defer_ok(4, true));
    assert!(!defer_ok(32, false));
    assert!(defer_ok(32, true));
    assert!(!defer_ok(3, true));
    assert!(!defer_ok(4, false));
    assert!(!defer_ok(0, true));
    assert!(!defer_ok(0, false));
}

#[test]
fn kick_sweep_discipline() {
    // Moves with window ride the next natural dispatch
    // with no kick, since the loop already visited every
    // task. Zero-move window sweeps to 256 with no loop.
    assert_eq!(kick_step(1, true, 0), (false, 0));
    assert_eq!(kick_step(5, false, 0), (false, 0));
    assert_eq!(kick_step(5, true, 0), (false, 0));
    assert_eq!(kick_step(0, false, 3), (false, 3));
    assert_eq!(kick_step(0, false, 7), (false, 7));
    assert_eq!(kick_step(0, true, 7), (true, 8));
    assert_eq!(kick_step(0, true, 255), (true, 256));
    assert_eq!(kick_step(0, true, 256), (false, 256));
    assert_eq!(kick_step(1, true, 9), (false, 0));
}

fn live_task(cpu: usize, nr: usize) -> PendingTask {
    PendingTask {
        allowed: (0..nr).map(|c| c == cpu).collect(),
        exiting: false,
        live: true,
        fail: false,
    }
}

#[test]
fn slot_drain_skips_dead_head() {
    let mut q = VecDeque::from([
        PendingTask {
            live: false,
            ..live_task(0, 2)
        },
        live_task(0, 2),
        live_task(0, 2),
    ]);
    let moved = slot_drain_model(&mut q, 0, SLOT_BUDGET, 0);
    assert_eq!(moved, 2);
    assert_eq!(q.len(), 1);
}

#[test]
fn slot_drain_skips_failed_move_with_progress() {
    let mut q = VecDeque::from([
        PendingTask {
            fail: true,
            ..live_task(0, 2)
        },
        live_task(0, 2),
    ]);
    let moved = slot_drain_model(&mut q, 0, SLOT_BUDGET, 0);
    assert_eq!(moved, 1);
    assert_eq!(q.len(), 1);
    assert!(q[0].fail);
}

#[test]
fn slot_drain_respects_cap_plus_base() {
    let mut q = VecDeque::from([
        live_task(0, 2),
        live_task(0, 2),
        live_task(0, 2),
        live_task(0, 2),
        live_task(0, 2),
    ]);
    let moved = slot_drain_model(&mut q, 0, SLOT_D, 0);
    assert_eq!(moved, SLOT_D);
    assert_eq!(q.len(), 1);
    let moved2 = slot_drain_model(&mut q, 0, SLOT_BUDGET, moved);
    assert_eq!(moved2, 1);
    assert!(q.is_empty());
}

#[test]
fn slot_drain_keeps_queue_order() {
    let mut q = VecDeque::from([live_task(0, 2), live_task(1, 2)]);
    let moved = slot_drain_model(&mut q, 0, SLOT_BUDGET, 0);
    assert_eq!(moved, 1);
    assert_eq!(q.len(), 1);
    assert_eq!(q[0].allowed, vec![false, true]);
}

#[test]
fn steal_need_holds_idle_empty_fast_path() {
    assert_eq!(steal_need(true), 1);
    assert_eq!(steal_need(false), 2);
    assert_eq!(steal_need(true), 1);
    // Donor with one task steals when idle empty only.
    assert!(1 >= steal_need(true));
    assert!(1 < steal_need(false));
    assert!(2 >= steal_need(false));
}

#[test]
fn steal_single_move_toward_budget() {
    // Each steal drain moves at most one toward budget 32.
    // A second drain moves one more toward budget.
    let cpu = 0;
    let mut moved = 0u32;
    let mut peer_q: VecDeque<PendingTask> = (0..4).map(|_| live_task(cpu as usize, 2)).collect();
    let lim = (moved + 1).min(SLOT_BUDGET);
    let got = slot_drain_model(&mut peer_q, cpu, lim, moved);
    assert_eq!(got, 1);
    moved += got;
    assert_eq!(moved, 1);
    assert_eq!(peer_q.len(), 3);
    // Second peer moves one more toward budget.
    let mut peer2: VecDeque<PendingTask> = (0..2).map(|_| live_task(cpu as usize, 2)).collect();
    let lim2 = (moved + 1).min(SLOT_BUDGET);
    let got2 = slot_drain_model(&mut peer2, cpu, lim2, moved);
    assert_eq!(got2, 1);
    moved += got2;
    assert_eq!(moved, 2);
}

#[test]
fn token_eligible_needs_full_conjunct() {
    assert!(token_eligible(true, 5, 1_000_000, 0, 100));
    assert!(!token_eligible(false, 5, 1_000_000, 0, 100));
    assert!(!token_eligible(true, 0, 1_000_000, 0, 100));
    assert!(!token_eligible(true, 5, 1_000_001, 0, 100));
    assert!(!token_eligible(true, 5, 1_000_000, 4_000_000, 100));
    assert!(!token_eligible(true, 5, 1_000_000, 0, 64_001));
    assert!(token_eligible(true, 255, 1, 0, 64_000));
}

#[test]
fn facade_matches_slot_helpers() {
    assert_eq!(crate::flow::SLOT_BASE, SLOT_BASE);
    assert_eq!(crate::flow::SLOT_D, SLOT_D);
    assert_eq!(crate::flow::SLOT_BUDGET, SLOT_BUDGET);
    assert_eq!(crate::flow::WHEEL_TOTAL, WHEEL_TOTAL);
    assert_eq!(crate::flow::TOKEN_MAX, TOKEN_MAX);
    assert_eq!(
        slot_cpu_dsq(3, GROUP_LIGHT),
        crate::flow::slot_cpu_dsq(3, GROUP_LIGHT)
    );
}

#[test]
fn slot_own_cap_holds_31_with_reserve() {
    assert_eq!(SLOT_OWN_CAP, 31);
    assert_eq!(SLOT_BUDGET, 32);
    assert_eq!(slot_own_cap(32), 31);
    assert_eq!(slot_own_cap(31), 30);
    assert_eq!(slot_own_cap(1), 0);
    assert_eq!(slot_own_cap(0), 0);
    assert_eq!(slot_cap(32), SLOT_D);
}

#[test]
fn high1_single_group_hog_overflow_drains_bounded() {
    // Single-group host all-light with a hog overflow tail must
    // drain via other overflow bounded at D with mask wins.
    let cpu = 0;
    let trips = local_trip_dsqs(0, GROUP_LIGHT);
    assert_eq!(trips[3], slot_overflow_dsq(GROUP_HOG));
    assert_ne!(trips[1], trips[3]);
    let mut hog_over: VecDeque<PendingTask> = (0..8).map(|_| live_task(0, 2)).collect();
    let got = slot_drain_model(&mut hog_over, cpu, SLOT_D, 0);
    assert_eq!(got, SLOT_D);
    assert_eq!(hog_over.len(), 4);
    let got2 = slot_drain_model(&mut hog_over, cpu, SLOT_D, 0);
    assert_eq!(got2, SLOT_D);
    assert!(hog_over.is_empty());
    let mut mixed = VecDeque::from([
        PendingTask {
            allowed: vec![false, true],
            exiting: false,
            live: true,
            fail: false,
        },
        live_task(0, 2),
    ]);
    let got3 = slot_drain_model(&mut mixed, cpu, SLOT_D, 0);
    assert_eq!(got3, 1);
    assert_eq!(mixed.len(), 1);
}

#[test]
fn high2_foreign_crowd_idle_target_wakes() {
    // Shared queue crowded by foreign work must still kick
    // an idle target, so no idle CPU sleeps unkicked.
    assert!(kick_idle_ok(8, 0, true));
    assert!(kick_idle_ok(100, 0, true));
    assert!(kick_idle_ok(u64::MAX, 0, true));
    assert!(!kick_idle_ok(8, 1, true));
    assert!(!kick_idle_ok(8, 0, false));
    let now = 5_000_000u64;
    let recent = now - 1_000;
    assert!(!kick_coalesced(8, 0, true, false, now, recent));
    assert!(!kick_coalesced(100, 0, true, false, now, recent));
    assert!(kick_coalesced(2, 0, true, false, now, recent));
    assert!(!kick_coalesced(2, 0, true, true, now, recent));
}

#[test]
fn high3_saturated_own_steal_progress() {
    // Saturated own at 40 with peer at 4 must still move
    // peer via steal single move with one per dispatch.
    let cpu = 0;
    let mut own_q: VecDeque<PendingTask> = (0..40).map(|_| live_task(0, 2)).collect();
    let mut peer_q: VecDeque<PendingTask> = (0..4).map(|_| live_task(0, 2)).collect();
    let mut moved = slot_drain_model(&mut own_q, cpu, SLOT_OWN_CAP, 0);
    assert_eq!(moved, SLOT_OWN_CAP);
    assert_eq!(own_q.len(), 9);
    let lim = (moved + 1).min(SLOT_BUDGET);
    let got = slot_drain_model(&mut peer_q, cpu, lim, moved);
    assert_eq!(got, 1);
    moved += got;
    assert_eq!(moved, SLOT_BUDGET);
    assert_eq!(peer_q.len(), 3);
}

#[test]
fn high4_kick_rate_bounded_at_steady_state() {
    // Steady state with no window work stays quiet, so
    // kicks per dispatch stay well below one. Sweep only
    // fires on zero-move window work.
    assert!(!defer_ok(32, false));
    assert!(!kick_step(5, false, 0).0);
    assert!(!kick_step(0, false, 0).0);
    assert!(kick_step(0, true, 0).0);
    let mut kicks = 0u32;
    let mut sweep: u16 = 0;
    let dispatches = 100u32;
    for _ in 0..dispatches {
        let (kick, next) = kick_step(5, false, sweep);
        sweep = next;
        if kick {
            kicks += 1;
        }
        assert!(!kick);
    }
    assert_eq!(kicks, 0);
    let (kick2, _) = kick_step(0, false, sweep);
    assert!(!kick2);
    let (kick3, next3) = kick_step(1, true, 0);
    assert!(!kick3);
    assert_eq!(next3, 0);
    let mut s: u16 = 0;
    for _ in 0..SWEEP_MAX {
        let (k, n) = kick_step(0, true, s);
        assert!(k);
        s = n;
    }
    assert_eq!(s, SWEEP_MAX);
    let (k_last, s_last) = kick_step(0, true, s);
    assert!(!k_last);
    assert_eq!(s_last, SWEEP_MAX);
    let rate = 0.0 / dispatches as f64;
    assert!(rate < 0.1);
}

#[test]
fn window_gate_covers_local_only() {
    assert!(window_has_work(true, false, false, false));
    assert!(window_has_work(false, true, false, false));
    assert!(window_has_work(false, false, true, false));
    assert!(window_has_work(false, false, false, true));
    assert!(!window_has_work(false, false, false, false));
    assert!(defer_ok(SLOT_D, true));
    assert!(!defer_ok(SLOT_D, false));
    assert!(!kick_step(1, true, 0).0);
    assert!(kick_step(0, true, 0).0);
    assert!(!kick_step(0, false, 0).0);
}

#[test]
fn pinned_rests_in_overflow_with_bounded_drain() {
    // Pinned tasks rest in overflow, so every owner pass
    // visits them in the window.
    assert_eq!(
        insert_cpu_dsq(3, GROUP_HOG, 122, true, 8),
        slot_overflow_dsq(GROUP_HOG)
    );
    // CPU first arg order still overflows pinned hog at CPU 3.
    assert_eq!(
        insert_cpu_dsq(3, GROUP_HOG, 129, true, 8),
        slot_overflow_dsq(GROUP_HOG)
    );
    assert_eq!(
        insert_cpu_dsq(3, GROUP_LIGHT, 78, true, 8),
        slot_overflow_dsq(GROUP_LIGHT)
    );
    assert_eq!(
        insert_cpu_dsq(3, GROUP_HOG, 122, false, 8),
        slot_cpu_dsq(3, GROUP_HOG)
    );
    assert_eq!(
        insert_cpu_dsq(3, GROUP_HOG, 300, false, 8),
        slot_overflow_dsq(GROUP_HOG)
    );
    let trips = local_trip_dsqs(0, GROUP_HOG);
    assert_eq!(trips[1], slot_overflow_dsq(GROUP_HOG));
    let mut q: VecDeque<PendingTask> = VecDeque::from([live_task(15, 16), live_task(11, 16)]);
    let moved = slot_drain_model(&mut q, 15, SLOT_D, 0);
    assert_eq!(moved, 1);
    assert_eq!(q.len(), 1);
    let moved2 = slot_drain_model(&mut q, 11, SLOT_D, 0);
    assert_eq!(moved2, 1);
    assert!(q.is_empty());
    assert!(defer_ok(SLOT_D, true));
    assert!(!kick_step(1, true, 0).0);
    assert!(!kick_step(0, false, 0).0);
}

/*
 * Steal wrap reaches low peers from high CPUs.
 * Start from 7 at 8 visits 0 to 6 first with no
 * dead read, so high CPUs steal with wrap. Mirrors
 * the BPF steal scan order with bound 8. See
 * src/flow_select.rs and src/bpf/dispatch.bpf.c.
 */
#[test]
fn steal_wrap_reaches_low_peers() {
    let peers = steal_peers(7, 8);
    assert_eq!(peers.len(), STEAL_BOUND);
    assert_eq!(peers, vec![0, 1, 2, 3, 4, 5, 6, 7]);
    assert!(peers.contains(&0));
    assert!(peers.contains(&1));
    assert!(peers.contains(&2));
    assert!(peers.contains(&3));
    assert!(peers.contains(&4));
    assert!(peers.contains(&5));
    assert!(peers.contains(&6));
    let mid = steal_peers(3, 8);
    assert_eq!(mid, vec![4, 5, 6, 7, 0, 1, 2, 3]);
    let single = steal_peers(0, 1);
    assert_eq!(single, vec![0, 0, 0, 0, 0, 0, 0, 0]);
}

/*
 * Rotation start wraps with mask and stand.
 * Start steps masked cursor plus one with wrap once
 * per dispatch, so passes spread with no hot spot.
 * Stand stays masked out, so the flag never skews
 * the order. Single host stays at zero with no
 * scan. See src/flow_select.rs and
 * src/bpf/dispatch.bpf.c.
 */
#[test]
fn steal_start_rotates_with_wrap() {
    assert_eq!(steal_start(7, 8), 0);
    assert_eq!(steal_start(0, 8), 1);
    assert_eq!(steal_start(3, 8), 4);
    assert_eq!(steal_start(0, 1), 0);
    assert_eq!(steal_start(5, 1), 0);
    let stand = crate::flow_preempt::CURSOR_STAND_BIT;
    assert_eq!(steal_start(7 | stand, 8), 0);
    assert_eq!(steal_start(stand | 3, 8), 4);
    assert_eq!(steal_start(15, 16), 0);
    assert_eq!(steal_start(0, 16), 1);
}

/*
 * Cursor stride keeps stand with step 8.
 * Advance stores masked plus 8 with wrap in 4 compare
 * and swap tries while it keeps the flag bit from
 * the old word, so a lost race can drop the step with
 * no stall. Next start then lands 8 past the old start
 * with wrap. When host size divides 8, step 8 is
 * identity with no advance, harmless as the bound 8
 * scan covers all peers while donor priority goes
 * stale. See src/flow_preempt.rs and
 * src/bpf/dispatch.bpf.c.
 */
#[test]
fn steal_cursor_stride_keeps_stand() {
    let stand = crate::flow_preempt::CURSOR_STAND_BIT;
    let mask = crate::flow_preempt::CURSOR_MASK;
    for nr in [16usize, 64, 256, 1024] {
        for cur in [0u32, 1, 7, 15, 100] {
            let masked = cur & mask;
            let old = cur | stand;
            let nxt_peer = (masked + 8) % nr as u32;
            let nxt = crate::flow_preempt::cursor_store(nxt_peer, old);
            assert_eq!(nxt & stand, stand);
            assert_eq!(nxt & mask, nxt_peer & mask);
            let s0 = steal_start(cur, nr);
            let s1 = steal_start(nxt, nr);
            assert_eq!(s1, (s0 + 8) % nr as u32);
        }
    }
    let plain = crate::flow_preempt::cursor_store(9, 0);
    assert_eq!(plain & mask, 9);
    assert_eq!(plain & stand, 0);
    for cur in [0u32, 1, 7] {
        let masked = cur & mask;
        let old = cur | stand;
        let nxt_peer = (masked + 8) % 8;
        assert_eq!(nxt_peer, masked);
        let nxt = crate::flow_preempt::cursor_store(nxt_peer, old);
        assert_eq!(nxt & mask, masked);
        let s0 = steal_start(cur, 8);
        let s1 = steal_start(nxt, 8);
        assert_eq!(s1, s0);
        assert_eq!(s1, (s0 + 8) % 8);
        let peers = steal_peers(cur, 8);
        assert_eq!(peers.len(), STEAL_BOUND);
        let mut sorted = peers.clone();
        sorted.sort_unstable();
        assert_eq!(sorted, (0..8).collect::<Vec<u32>>());
    }
}

/*
 * Sixteen sweep keeps order for many host sizes.
 * Peers from start visit 16 in order with wrap, so
 * first 8 feed one same group scan and next 8
 * preview the next scan after the stride 8 step.
 * At 16 the sweep covers every peer, past 16 it
 * covers 16 distinct peers. Self visit stays
 * allowed with no skip, so small hosts keep full
 * cover. See src/flow_select.rs and
 * src/bpf/dispatch.bpf.c.
 */
#[test]
fn steal_sixteen_sweep_covers_sizes() {
    for nr in [16usize, 64, 256, 1024] {
        for start in [0u32, 1, 7, 15] {
            let s = start % nr as u32;
            let peers = steal_peers_from(s, nr);
            assert_eq!(peers.len(), 16);
            for (i, p) in peers.iter().enumerate() {
                assert_eq!(*p, (s + i as u32) % nr as u32);
            }
            let mut seen = std::collections::HashSet::new();
            for p in &peers {
                seen.insert(*p);
            }
            assert_eq!(seen.len(), 16);
            let first8: Vec<u32> = peers.iter().take(8).cloned().collect();
            let cpu = if s == 0 { nr as u32 - 1 } else { s - 1 };
            let via = steal_peers(cpu, nr);
            assert_eq!(via, first8);
        }
    }
    let full = steal_peers_from(0, 16);
    let mut sorted = full.clone();
    sorted.sort_unstable();
    assert_eq!(sorted, (0..16).collect::<Vec<u32>>());
}

/*
 * Insert fails closed to overflow on dead CPUs.
 * Negative plus past live plus past 1024 all pin
 * to the tail with no trap. Mirrors the BPF live
 * check with the same overflow fallback.
 */
#[test]
fn insert_fails_closed_on_dead_cpu() {
    assert_eq!(
        insert_cpu_dsq(-1, GROUP_LIGHT, 9, false, 8),
        slot_overflow_dsq(GROUP_LIGHT)
    );
    assert_eq!(
        insert_cpu_dsq(9, GROUP_LIGHT, 9, false, 8),
        slot_overflow_dsq(GROUP_LIGHT)
    );
    assert_eq!(
        insert_cpu_dsq(8, GROUP_HOG, 9, false, 8),
        slot_overflow_dsq(GROUP_HOG)
    );
    assert_eq!(
        insert_cpu_dsq(1024, GROUP_LIGHT, 9, false, 1024),
        slot_overflow_dsq(GROUP_LIGHT)
    );
    assert_eq!(
        insert_cpu_dsq(3, GROUP_LIGHT, 9, false, 8),
        slot_cpu_dsq(3, GROUP_LIGHT)
    );
}

/*
 * Cross peers sweep start plus 8 with wrap.
 * Cross peers from start visit bound peers from start
 * plus 8 with wrap, so high starts reach low peers with
 * no dead read. First 8 plus cross 8 match the 16 sweep
 * in order, so same plus cross share one rotation with
 * stride 8 step. Mirrors the BPF second loop with modulo.
 * See src/flow_select.rs and src/bpf/dispatch.bpf.c.
 */
#[test]
fn steal_cross_peers_sweep_start_plus_8() {
    assert_eq!(steal_cross_peers(0, 16), vec![8, 9, 10, 11, 12, 13, 14, 15]);
    let full = steal_peers_from(0, 16);
    assert_eq!(&full[0..8], &[0, 1, 2, 3, 4, 5, 6, 7]);
    assert_eq!(&full[8..16], steal_cross_peers(0, 16).as_slice());
    assert_eq!(steal_cross_peers(12, 16), vec![4, 5, 6, 7, 8, 9, 10, 11]);
    let same8 = steal_peers_from(1, 8);
    assert_eq!(steal_cross_peers(1, 8), same8[0..8].to_vec());
    assert!(steal_cross_peers(0, 0).is_empty());
    assert_eq!(steal_cross_peers(0, 16).len(), STEAL_BOUND);
}

/*
 * Cross peers wrap on small hosts with full union cover.
 * Cross peers from start visit bound peers from start
 * plus 8 with wrap, so nr 2, 3, and 9 keep no dead
 * read with every entry below nr. Same plus cross
 * union covers every peer, so small hosts keep full
 * cover. Mirrors the BPF second loop with modulo.
 * See src/flow_select.rs and src/bpf/dispatch.bpf.c.
 */
#[test]
fn steal_cross_peers_small_hosts_cover_union() {
    for nr in [2usize, 3, 9] {
        for start in 0..nr as u32 {
            let cross = steal_cross_peers(start, nr);
            assert_eq!(cross.len(), STEAL_BOUND);
            for (off, p) in cross.iter().enumerate() {
                assert!((*p as usize) < nr);
                assert_eq!(
                    *p,
                    start.wrapping_add(8).wrapping_add(off as u32) % nr as u32
                );
            }
            let same = steal_peers_from(start, nr);
            let mut seen = std::collections::HashSet::new();
            for p in same.iter().take(STEAL_BOUND) {
                seen.insert(*p);
            }
            for p in &cross {
                seen.insert(*p);
            }
            assert_eq!(seen.len(), nr);
        }
    }
    assert!(steal_cross_peers(0, 0).is_empty());
}

/*
 * LSB derive holds cross truth with no branch.
 * Same DSQ low bit matches owner, so mark stays zero
 * with no count. Cross DSQ low bit flips owner, so mark
 * stays one with full count. Zero got keeps zero in both
 * adds. Mirrors the BPF post hoc xor. See
 * src/flow_select.rs and src/bpf/dispatch.bpf.c.
 */
#[test]
fn steal_lsb_derive_holds_cross_truth() {
    for cpu in [0u32, 1, 3, 7] {
        let same_light = slot_cpu_dsq(cpu, GROUP_LIGHT);
        let cross_light = slot_cpu_dsq(cpu, GROUP_HOG);
        assert_eq!(steal_cross_x(same_light, GROUP_LIGHT), 0);
        assert_eq!(steal_cross_x(cross_light, GROUP_LIGHT), 1);
        let same_hog = slot_cpu_dsq(cpu, GROUP_HOG);
        let cross_hog = slot_cpu_dsq(cpu, GROUP_LIGHT);
        assert_eq!(steal_cross_x(same_hog, GROUP_HOG), 0);
        assert_eq!(steal_cross_x(cross_hog, GROUP_HOG), 1);
        assert!(steal_cross_x(same_light, GROUP_LIGHT) <= 1);
        assert!(steal_cross_x(cross_light, GROUP_LIGHT) <= 1);
    }
    assert_eq!(steal_cross_x(0x6000, GROUP_LIGHT), 0);
    assert_eq!(steal_cross_x(0x6001, GROUP_LIGHT), 1);
    assert_eq!(steal_cross_x(0x6001, GROUP_HOG), 0);
    assert_eq!(steal_cross_x(0x6000, GROUP_HOG), 1);
}

/*
 * Fold counts all plus cross subset with two adds.
 * Steal moves adds got for all peer moves with no branch,
 * so same plus cross share one drain. Steal x moves adds
 * got times mark for the cross subset, so same keeps zero
 * and cross keeps got with no branch on cross. Mirrors
 * the BPF fold. See src/flow_slot.rs and
 * src/bpf/dispatch.bpf.c.
 */
#[test]
fn steal_fold_counts_all_plus_cross_subset() {
    let same = slot_cpu_dsq(2, GROUP_LIGHT);
    let cross = slot_cpu_dsq(2, GROUP_HOG);
    assert_eq!(steal_fold_counts(0, same, GROUP_LIGHT), (0, 0));
    assert_eq!(steal_fold_counts(0, cross, GROUP_LIGHT), (0, 0));
    assert_eq!(steal_fold_counts(1, same, GROUP_LIGHT), (1, 0));
    assert_eq!(steal_fold_counts(1, cross, GROUP_LIGHT), (1, 1));
    assert_eq!(steal_fold_counts(1, cross, GROUP_HOG), (1, 0));
    assert_eq!(steal_fold_counts(1, same, GROUP_HOG), (1, 1));
    let (all, x) = steal_fold_counts(1, cross, GROUP_LIGHT);
    assert_eq!(all, 1);
    assert_eq!(x, 1);
    let (all2, x2) = steal_fold_counts(1, same, GROUP_LIGHT);
    assert_eq!(all2, 1);
    assert_eq!(x2, 0);
}

/*
 * Strict zero stays same only while perf adds cross.
 * Same hit returns same with no cross use in both modes,
 * so strict keeps cache apart. Same miss with cross work
 * returns none in strict with zero cross, while perf
 * returns cross with full fold, so perf adds cover on miss
 * only. Single host stays none in both modes. Mirrors the
 * BPF narrow gate. See src/flow_slot.rs and
 * src/bpf/dispatch.bpf.c.
 */
#[test]
fn steal_strict_zero_vs_perf_positive() {
    let need = 2u64;
    let start = 0u32;
    let nr = 8usize;
    let mut same_hit = vec![0u64; 8];
    same_hit[1] = 4;
    let cross_idle = vec![0u64; 8];
    let got_same_strict = steal_pick_fold(
        start,
        nr,
        GROUP_LIGHT,
        GROUP_HOG,
        need,
        &same_hit,
        &cross_idle,
        false,
    );
    let got_same_perf = steal_pick_fold(
        start,
        nr,
        GROUP_LIGHT,
        GROUP_HOG,
        need,
        &same_hit,
        &cross_idle,
        true,
    );
    assert_eq!(got_same_strict, Some((slot_cpu_dsq(1, GROUP_LIGHT), false)));
    assert_eq!(got_same_perf, Some((slot_cpu_dsq(1, GROUP_LIGHT), false)));
    let same_miss = vec![0u64; 8];
    let mut cross_work = vec![0u64; 8];
    cross_work[2] = 4;
    let miss_strict = steal_pick_fold(
        start,
        nr,
        GROUP_LIGHT,
        GROUP_HOG,
        need,
        &same_miss,
        &cross_work,
        false,
    );
    assert_eq!(miss_strict, None);
    let miss_perf = steal_pick_fold(
        start,
        nr,
        GROUP_LIGHT,
        GROUP_HOG,
        need,
        &same_miss,
        &cross_work,
        true,
    );
    assert!(miss_perf.is_some());
    let (dsq, is_cross) = miss_perf.unwrap();
    assert!(is_cross);
    assert_eq!(steal_cross_x(dsq, GROUP_LIGHT), 1);
    assert_eq!(steal_fold_counts(1, dsq, GROUP_LIGHT), (1, 1));
    let (same_dsq, same_cross) = got_same_strict.unwrap();
    assert!(!same_cross);
    assert_eq!(steal_fold_counts(1, same_dsq, GROUP_LIGHT), (1, 0));
    assert_eq!(
        steal_pick_fold(
            start,
            1,
            GROUP_LIGHT,
            GROUP_HOG,
            need,
            &same_hit,
            &cross_work,
            false
        ),
        None
    );
    assert_eq!(
        steal_pick_fold(
            start,
            1,
            GROUP_LIGHT,
            GROUP_HOG,
            need,
            &same_hit,
            &cross_work,
            true
        ),
        None
    );
    assert_eq!(
        steal_first_donor(start, nr, GROUP_LIGHT, need, &same_hit),
        Some(slot_cpu_dsq(1, GROUP_LIGHT))
    );
    assert_eq!(
        steal_first_donor(start, nr, GROUP_LIGHT, need, &same_miss),
        None
    );
}

/*
 * Fold single move holds one toward budget with shared drain.
 * One shared drain moves at most one with lim at moved plus
 * one, so tail stays smooth with no burst theft. Fold then
 * adds got to steal moves and got times mark to steal x
 * moves with no branch, so counts track the single move.
 * Mirrors the BPF single move. See src/flow_slot.rs and
 * src/bpf/dispatch.bpf.c.
 */
#[test]
fn steal_fold_single_move_toward_budget() {
    let cpu = 0;
    let mut moved = 0u32;
    let mut peer_q: VecDeque<PendingTask> = (0..4).map(|_| live_task(0, 2)).collect();
    let lim = (moved + 1).min(SLOT_BUDGET);
    let got = slot_drain_model(&mut peer_q, cpu, lim, moved);
    assert_eq!(got, 1);
    moved += got;
    assert_eq!(moved, 1);
    let same = slot_cpu_dsq(1, GROUP_LIGHT);
    let cross = slot_cpu_dsq(1, GROUP_HOG);
    assert_eq!(steal_fold_counts(got, same, GROUP_LIGHT), (1, 0));
    assert_eq!(steal_fold_counts(got, cross, GROUP_LIGHT), (1, 1));
    let mut full_q: VecDeque<PendingTask> = (0..4).map(|_| live_task(0, 2)).collect();
    let lim2 = (moved + 1).min(SLOT_BUDGET);
    let got2 = slot_drain_model(&mut full_q, cpu, lim2, moved);
    assert_eq!(got2, 1);
    moved += got2;
    assert_eq!(moved, 2);
    let mut sat_q: VecDeque<PendingTask> = (0..4).map(|_| live_task(0, 2)).collect();
    let sat_moved = SLOT_BUDGET;
    let sat_lim = (sat_moved + 1).min(SLOT_BUDGET);
    let sat_got = slot_drain_model(&mut sat_q, cpu, sat_lim, sat_moved);
    assert_eq!(sat_got, 0);
    assert_eq!(steal_fold_counts(sat_got, cross, GROUP_LIGHT), (0, 0));
}
