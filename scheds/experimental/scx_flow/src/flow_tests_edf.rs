/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 *
 * EDF unit tests for the flow scheduler.
 * The tests mirror the BPF header so behavior
 * stays the same on both sides of the boundary.
 * The slice is fixed at 1ms with no knob.
 * Frequency plus LLC plus CPU cards stay display only
 * and never shape placement.
 */
use crate::flow_edf::*;
use crate::flow_select::*;
use crate::flow_slice::*;
use std::collections::VecDeque;

#[test]
fn est_clamp_caps_at_one_second() {
    assert_eq!(clamp_est(0), EST_MIN_NS);
    assert_eq!(clamp_est(1), EST_MIN_NS);
    assert_eq!(clamp_est(EST_MAX_NS), EST_MAX_NS);
    assert_eq!(clamp_est(EST_MAX_NS + 1), EST_MAX_NS);
    assert_eq!(clamp_est(u64::MAX), EST_MAX_NS);
    assert_eq!(clamp_est(8_000_000), 8_000_000);
    assert_ne!(clamp_est(1_000_000), clamp_est(8_000_000));
}

#[test]
fn slice_is_fixed_at_1ms() {
    assert_eq!(SLICE_NS, 1_000_000);
    assert_eq!(crate::flow::SLICE_NS, SLICE_NS);
    assert_eq!(crate::bpf_intf::flow_consts_FLOW_SLICE_NS as u64, SLICE_NS);
}

#[test]
fn edf_weight_matches_fixed() {
    assert_eq!(WEIGHT, 1024);
    assert_eq!(scale_by_weight(1_000_000, 1024), 1_000_000);
    assert_eq!(scale_by_weight(8_000_000, 1024), 8_000_000);
    assert_eq!(scale_by_weight(1_000_000, 0), 1_000_000);
    assert_eq!(scale_by_weight(1_000_000, 512), 2_000_000);
    assert_eq!(scale_by_weight(2_000_000, 2048), 1_000_000);
}

#[test]
fn edf_clamp_bounds_match_slice() {
    assert_eq!(clamp_vruntime(0, 100_000_000, SLICE_NS), 99_000_000);
    assert!(was_clamped(0, 100_000_000, SLICE_NS));
    assert_eq!(
        clamp_vruntime(99_000_000, 100_000_000, SLICE_NS),
        99_000_000
    );
    assert!(!was_clamped(99_000_000, 100_000_000, SLICE_NS));
    assert_eq!(
        clamp_vruntime(99_500_000, 100_000_000, SLICE_NS),
        99_500_000
    );
    assert!(!was_clamped(99_500_000, 100_000_000, SLICE_NS));
    assert_eq!(
        clamp_vruntime(110_000_000, 100_000_000, SLICE_NS),
        110_000_000
    );
    assert!(!was_clamped(110_000_000, 100_000_000, SLICE_NS));
}

#[test]
fn edf_deadline_wraps_safe() {
    assert_eq!(deadline(100, 50), 150);
    assert_eq!(deadline(u64::MAX - 10, 20), 9);
    assert!(time_before(u64::MAX - 10, 9));
    assert!(!time_before(9, u64::MAX - 10));
    assert!(!time_before(100, 100));
    assert_eq!(vruntime_add(100, 50), 150);
    assert_eq!(vruntime_add(u64::MAX, 1), 0);
}

#[test]
fn s1_bounded_lag_holds_across_trials() {
    for trial in 0..16u64 {
        let slice = SLICE_NS;
        let frontier = 100_000_000 + trial * 1_000_000;
        let lags = [0, 1, slice - 1, slice, slice + 1, 50_000_000];
        for lag in lags {
            let v = frontier.wrapping_sub(lag);
            let clamped = clamp_vruntime(v, frontier, slice);
            if time_before(v, frontier) {
                let held = frontier.wrapping_sub(clamped);
                assert!(held <= slice);
            } else {
                assert_eq!(clamped, v);
            }
            let (c2, dl, flag) = edf_insert(v, frontier, slice, 1_000_000, 1024);
            assert_eq!(c2, clamped);
            assert_eq!(flag, was_clamped(v, frontier, slice));
            assert_eq!(dl, deadline(c2, 1_000_000));
        }
    }
}

#[test]
fn s2_sleeper_cap_one_slice_holds() {
    for trial in 0..8u64 {
        let slice = SLICE_NS;
        let frontier = 200_000_000 + trial * 1_000_000;
        let est = 500_000 + trial * 50_000;
        let (clamped, dl, flag) = edf_insert(0, frontier, slice, est, 1024);
        assert_eq!(clamped, frontier.wrapping_sub(slice));
        assert!(flag);
        assert_eq!(dl, clamped.wrapping_add(clamp_est(est)));
        if clamp_est(est) <= slice {
            assert!(!time_before(frontier, dl));
            let early = frontier.wrapping_sub(dl);
            assert!(early <= slice);
        }
        let near = frontier.wrapping_sub(100_000);
        let (_, _, flag2) = edf_insert(near, frontier, slice, est, 1024);
        assert!(!flag2);
    }
}

#[test]
fn s3_frontier_monotonic_with_wrap_holds() {
    for trial in 0..8u64 {
        let old = 1_000_000 + trial * 1_000_000;
        let next = old.wrapping_add(500_000);
        assert_eq!(frontier_max(old, next), next);
        assert_eq!(frontier_max(next, old), next);
        assert_eq!(frontier_step(old, next, true, 0), next);
        assert_eq!(frontier_step(old, next, false, 1), next);
        assert_eq!(frontier_step(old, next, false, 0), next);
        assert_eq!(frontier_idle(next), next);
    }
    let old = u64::MAX - 100;
    let next = 50u64;
    assert!(time_before(old, next));
    assert_eq!(frontier_max(old, next), next);
    assert_eq!(frontier_step(old, next, true, 1), next);
    assert_eq!(frontier_step(old, next, false, 0), next);
    let lag = u64::MAX - 2_000_000;
    let top = u64::MAX - 1_000_000;
    assert_eq!(
        clamp_vruntime(lag, top, SLICE_NS),
        top.wrapping_sub(SLICE_NS)
    );
    assert_eq!(clamp_vruntime(0, top, SLICE_NS), 0);
    assert_eq!(clamp_vruntime(0, 500_000, SLICE_NS), 0);
}

#[test]
fn edf_insert_counts_clamp_and_order() {
    let slice = SLICE_NS;
    let frontier = 100_000_000;
    let (c1, dl1, f1) = edf_insert(0, frontier, slice, 800_000, 1024);
    assert!(f1);
    assert_eq!(c1, frontier.wrapping_sub(slice));
    assert_eq!(dl1, c1.wrapping_add(800_000));
    let (c2, dl2, f2) = edf_insert(frontier, frontier, slice, 500_000, 1024);
    assert!(!f2);
    assert_eq!(c2, frontier);
    let mut q = Vec::new();
    ordered_insert(
        &mut q,
        OrderedEntry {
            deadline: dl1,
            seq: 0,
            id: 1,
        },
    );
    ordered_insert(
        &mut q,
        OrderedEntry {
            deadline: dl2,
            seq: 1,
            id: 2,
        },
    );
    assert_eq!(q.len(), 2);
    assert!(!q[1].before(&q[0]));
}

#[test]
fn edf_frontier_step_idle_bounded() {
    let waking = 50_000_000;
    assert_eq!(frontier_step(100_000_000, waking, false, 0), waking);
    assert_ne!(frontier_step(100_000_000, waking, false, 0), 0);
    assert_eq!(frontier_step(100_000_000, waking, false, 1), 100_000_000);
    assert_eq!(frontier_step(100_000_000, waking, true, 0), 100_000_000);
    assert_eq!(frontier_step(10, 20, true, 5), 20);
    assert_eq!(frontier_step(10, 20, false, 3), 20);
    assert_eq!(frontier_step(100_000_000, 0, false, 0), 100_000_000);
    assert_eq!(frontier_idle_guarded(100_000_000, 0), 100_000_000);
    assert_eq!(frontier_idle_guarded(100_000_000, waking), waking);
}

#[test]
fn edf_insert_and_step_matches_composition() {
    for trial in 0..8u64 {
        let frontier = 100_000_000 + trial * 1_000_000;
        let slice = SLICE_NS;
        let est = 500_000 + trial * 50_000;
        let v = frontier.wrapping_sub(trial * 200_000);
        for (runnable, queued) in [(true, 0), (false, 0), (false, 1)] {
            let (c1, dl1, flag1) = edf_insert(v, frontier, slice, est, 1024);
            let scaled = scale_by_weight(clamp_est(est), 1024);
            let next_v = vruntime_add(c1, scaled);
            let want = frontier_step(frontier, next_v, runnable, queued);
            let (c2, dl2, got, flag2) =
                edf_insert_and_step(v, frontier, slice, est, 1024, runnable, queued);
            assert_eq!(c2, c1);
            assert_eq!(dl2, dl1);
            assert_eq!(flag2, flag1);
            assert_eq!(got, want);
            assert_eq!(dl2, deadline(c2, scaled));
        }
    }
}

#[test]
fn dsq_ids_match_spec() {
    assert_eq!(DSQ_BASE, 0x4000);
    assert_eq!(DSQ_PARK, 0x5000);
    assert_ne!(DSQ_BASE, DSQ_PARK);
    assert_eq!(dsq_for_cpu(0, 8), Some(0x4000));
    assert_eq!(dsq_for_cpu(7, 8), Some(0x4007));
    assert_eq!(dsq_for_cpu(8, 8), None);
    assert_eq!(dsq_for_cpu(1023, 1024), Some(0x43ff));
    assert_eq!(dsq_for_cpu(1024, 2048), None);
}

#[test]
fn ordered_insert_sorts_by_deadline() {
    let mut q = Vec::new();
    for (dl, seq, id) in [(8_000_000, 0, 1), (1_000_000, 1, 2)] {
        ordered_insert(
            &mut q,
            OrderedEntry {
                deadline: dl,
                seq,
                id,
            },
        );
    }
    ordered_insert(
        &mut q,
        OrderedEntry {
            deadline: 4_000_000,
            seq: 2,
            id: 3,
        },
    );
    assert_eq!(q[0].id, 2);
    assert_eq!(q[1].id, 3);
    assert_eq!(q[2].id, 1);
}

#[test]
fn ordered_insert_keeps_arrival_order_on_ties() {
    let mut q = Vec::new();
    for i in 0..4 {
        let e = OrderedEntry {
            deadline: 2_000_000,
            seq: i,
            id: i,
        };
        ordered_insert(&mut q, e);
    }
    assert_eq!(q[0].id, 0);
    assert_eq!(q[1].id, 1);
    assert_eq!(q[2].id, 2);
    assert_eq!(q[3].id, 3);
}

#[test]
fn kick_idle_rescues_stale_queue() {
    assert!(kick_idle_ok(0, 0, true));
    assert!(kick_idle_ok(1, 0, true));
    assert!(kick_idle_ok(2, 0, true));
    assert!(!kick_idle_ok(3, 0, true));
    assert!(!kick_idle_ok(8, 0, true));
    assert!(!kick_idle_ok(u64::MAX, 0, true));
    assert!(!kick_idle_ok(0, 7, true));
    assert!(!kick_idle_ok(1, 1, true));
    assert!(!kick_idle_ok(2, 7, true));
    assert!(!kick_idle_ok(0, 0, false));
    assert!(!kick_idle_ok(2, 0, false));
    assert!(!park_kick_ok());
}

/*
 * Coalesce const matches the header at 50us with no
 * space. Zero init keeps the first kick with wrap.
 */
#[test]
fn kick_coalesce_const_matches_header() {
    assert_eq!(
        KICK_COALESCE_NS,
        crate::bpf_intf::flow_consts_FLOW_KICK_COALESCE_NS as u64
    );
    assert_eq!(KICK_COALESCE_NS, 50_000);
}

/*
 * Recent needs 50us with zero open plus wrap. Zero
 * last never counts, 49999 counts, 50000 plus stays
 * open. Wrap diff holds across the wrap with no check.
 */
#[test]
fn kick_recent_needs_50us_with_zero_open() {
    assert!(!kick_recent(1_000_000, 0));
    assert!(!kick_recent(0, 0));
    assert!(kick_recent(1_000_000, 999_999));
    assert!(kick_recent(1_000_000, 950_001));
    assert!(!kick_recent(1_000_000, 950_000));
    assert!(!kick_recent(1_000_000, 949_999));
    assert!(!kick_recent(1_000_000, 900_000));
    assert!(kick_recent(5, u64::MAX - 10));
    assert!(!kick_recent(60_000, u64::MAX - 10));
    assert!(!kick_recent(100, 200));
    assert!(!kick_recent(0, 1));
}

/*
 * Coalesce needs q2 plus idle plus recent plus not
 * pinned. Q1 plus busy plus missing plus pinned stay
 * open with a kick. Park stays out with no kick use,
 * see park helper. Exiting uses its own idle kick with
 * no coalesce, see exiting helpers.
 */
#[test]
fn kick_coalesce_needs_q2_idle_recent_unpinned() {
    let now = 1_000_000u64;
    let recent = now - 10_000;
    let stale = now - 60_000;
    assert!(kick_coalesced(2, 0, true, false, now, recent));
    assert!(!kick_coalesced(2, 0, true, false, now, stale));
    assert!(!kick_coalesced(2, 0, true, false, now, 0));
    assert!(!kick_coalesced(1, 0, true, false, now, recent));
    assert!(!kick_coalesced(0, 0, true, false, now, recent));
    assert!(!kick_coalesced(3, 0, true, false, now, recent));
    assert!(!kick_coalesced(2, 7, true, false, now, recent));
    assert!(!kick_coalesced(2, 0, false, false, now, recent));
    assert!(!kick_coalesced(2, 0, true, true, now, recent));
    assert!(!kick_coalesced(2, 0, true, true, now, stale));
    assert!(!park_kick_ok());
}

/*
 * Q1 always kicks with no coalesce even when recent.
 * Deep stays quiet with no coalesce count. Q0 stays
 * open with a kick. Busy stays quiet with no coalesce.
 */
#[test]
fn kick_q1_always_kicks_deep_stays_quiet() {
    let now = 5_000_000u64;
    let recent = now - 1_000;
    assert!(kick_idle_ok(1, 0, true));
    assert!(!kick_coalesced(1, 0, true, false, now, recent));
    assert!(!kick_coalesced(1, 0, true, true, now, recent));
    assert!(!kick_idle_ok(3, 0, true));
    assert!(!kick_coalesced(3, 0, true, false, now, recent));
    assert!(!kick_coalesced(8, 0, true, false, now, recent));
    assert!(!kick_coalesced(u64::MAX, 0, true, false, now, recent));
    assert!(kick_idle_ok(0, 0, true));
    assert!(!kick_coalesced(0, 0, true, false, now, recent));
    assert!(!kick_idle_ok(2, 9, true));
    assert!(!kick_coalesced(2, 9, true, false, now, recent));
}

/*
 * Pinned never skips with no coalesce even when recent.
 * Skip keeps the old last with no slide, kick slides
 * to now. Models the BPF last update with plain values.
 */
#[test]
fn kick_pinned_never_skips_no_slide() {
    let mut last = 1_000_000u64;
    let now = last + 10_000;
    assert!(!kick_coalesced(2, 0, true, true, now, last));
    let kept = last;
    let skip = kick_coalesced(2, 0, true, false, now, last);
    assert!(skip);
    if skip {
    } else {
        last = now;
    }
    assert_eq!(last, kept);
    let stale = last + 60_000;
    let kick = !kick_coalesced(2, 0, true, false, stale, last);
    assert!(kick);
    if kick {
        last = stale;
    }
    assert_eq!(last, stale);
    assert!(!kick_recent(last, kept));
    assert!(!kick_recent(last + 60_000, last));
    assert!(kick_recent(kept + 10_000, kept));
}

/*
 * Exiting fast path follows the task CPU with an idle
 * kick. The task CPU wins over the enqueuer, so an exit
 * enqueued elsewhere still runs where the task lives.
 * Fallback runs the normal path exactly once with no
 * double enqueue. Non-exiting tasks never take this path.
 */
#[test]
fn exiting_runs_at_once_on_allowed_tgt() {
    assert!(exiting_local_ok(true, true));
    assert!(!exiting_local_ok(true, false));
    assert!(!exiting_local_ok(false, true));
    assert!(!exiting_local_ok(false, false));
}

/*
 * Enqueuer differs from the task CPU. The decision follows
 * the task CPU mask only, so an allowed task CPU wins even
 * when the enqueuer is foreign, and a foreign task CPU
 * falls back even when the enqueuer is allowed. Mirrors the
 * BPF fix from here equals smp id to tgt equals task cpu.
 */
#[test]
fn exiting_uses_task_cpu_not_enqueuer() {
    let allowed = [false, true, true, false];
    let enqueuer = 0;
    let tgt = 1;
    assert!(!may_run_on(enqueuer, &allowed));
    assert!(may_run_on(tgt, &allowed));
    assert!(exiting_local_ok(true, may_run_on(tgt, &allowed)));
    let allowed2 = [true, false, false, false];
    let enqueuer2 = 0;
    let tgt2 = 1;
    assert!(may_run_on(enqueuer2, &allowed2));
    assert!(!may_run_on(tgt2, &allowed2));
    assert!(!exiting_local_ok(true, may_run_on(tgt2, &allowed2)));
    assert_eq!(stay_target(tgt, 4, &allowed), Some(1));
    assert_eq!(stay_target(enqueuer, 4, &allowed), None);
}

/*
 * Kick on idle with no depth plus no coalesce plus no rate.
 * Any queue state kicks when the task CPU is idle with a
 * live state, so q0 plus q1 plus q2 all wake at once.
 */
#[test]
fn exiting_kick_on_idle() {
    assert!(exiting_kick_ok(0, true));
    assert!(exiting_local_ok(true, true) && exiting_kick_ok(0, true));
}

/*
 * No kick when busy or when the target state is missing.
 * Busy task CPUs stay quiet with no preempt, and a missing
 * state fails closed with no kick. Mirrors the BPF tst plus
 * running pid check with no kick at plus no coalesce.
 */
#[test]
fn exiting_no_kick_when_busy_or_missing() {
    assert!(!exiting_kick_ok(7, true));
    assert!(!exiting_kick_ok(1, true));
    assert!(!exiting_kick_ok(0, false));
    assert!(!exiting_kick_ok(99, false));
    assert!(!kick_idle_ok(3, 0, true));
    assert!(exiting_local_ok(true, true));
    assert!(!exiting_kick_ok(9, true));
}

/*
 * Fallback runs the normal path exactly once with no double
 * enqueue. An exiting task with a foreign task CPU skips the
 * fast insert plus the fast kick, then the normal path
 * inserts once. Counts model single insert plus no double.
 */
#[test]
fn exiting_fallback_single_insert_no_double() {
    let fast = exiting_local_ok(true, false);
    assert!(!fast);
    let fast_inserts = if fast { 1 } else { 0 };
    let fast_kicks = if fast && exiting_kick_ok(0, true) {
        1
    } else {
        0
    };
    let normal_inserts = if !fast { 1 } else { 0 };
    assert_eq!(fast_inserts, 0);
    assert_eq!(fast_kicks, 0);
    assert_eq!(normal_inserts, 1);
    assert_eq!(fast_inserts + normal_inserts, 1);
    let fast_hit = exiting_local_ok(true, true);
    assert!(fast_hit);
    let hit_fast = if fast_hit { 1 } else { 0 };
    let hit_normal = if !fast_hit { 1 } else { 0 };
    assert_eq!(hit_fast, 1);
    assert_eq!(hit_normal, 0);
    assert_eq!(hit_fast + hit_normal, 1);
}

/*
 * Non-exiting tasks never take the fast path and keep the
 * normal kick rules. The fast gate stays closed for any tgt
 * mask, park stays kickless, and the normal idle plus
 * coalesce helpers stay unchanged.
 */
#[test]
fn exiting_non_exiting_unchanged() {
    assert!(!exiting_local_ok(false, true));
    assert!(!exiting_local_ok(false, false));
    assert!(kick_idle_ok(0, 0, true));
    assert!(kick_idle_ok(1, 0, true));
    assert!(!kick_idle_ok(3, 0, true));
    assert!(!park_kick_ok());
    let now = 1_000_000u64;
    let recent = now - 10_000;
    assert!(kick_coalesced(2, 0, true, false, now, recent));
    assert!(!kick_coalesced(1, 0, true, false, now, recent));
}

#[test]
fn target_prefers_selected_when_allowed() {
    assert_eq!(pick_target_cpu(2, &[true, true, true]), Some(2));
    assert_eq!(pick_target_cpu(0, &[true, false]), Some(0));
    assert_eq!(pick_target_cpu(1, &[false, true]), Some(1));
    assert_eq!(pick_target_cpu(-1, &[false, true, true]), Some(1));
    assert_eq!(pick_target_cpu(5, &[true, false]), Some(0));
    assert_eq!(pick_target_cpu(-1, &[]), None);
}

#[test]
fn target_pinned_resolves_to_single() {
    assert_eq!(pick_target_cpu(2, &[false, false, true]), Some(2));
    assert_eq!(pick_target_cpu(0, &[false, false, true]), Some(2));
    assert_eq!(pick_target_cpu(-1, &[false, true, false]), Some(1));
    assert_eq!(pick_target_cpu(0, &[false, false]), None);
    assert_eq!(pick_target_cpu(-1, &[false]), None);
}

#[test]
fn narrow_mask_keeps_within_mask() {
    let narrow = [false, false, true, true, false];
    assert_eq!(pick_target_cpu(3, &narrow), Some(3));
    assert_eq!(pick_target_cpu(2, &narrow), Some(2));
    assert_eq!(pick_target_cpu(0, &narrow), Some(2));
    assert_eq!(pick_target_cpu(4, &narrow), Some(2));
    assert_eq!(pick_target_cpu(-1, &narrow), Some(2));
    assert!(may_run_on(2, &narrow));
    assert!(may_run_on(3, &narrow));
    assert!(!may_run_on(0, &narrow));
    assert!(!may_run_on(4, &narrow));
    assert!(!may_run_on(0, &[false, false, true]));
    assert!(may_run_on(2, &[false, false, true]));
}

#[test]
fn stay_local_keeps_task_cpu() {
    let all = [true; 8];
    assert_eq!(stay_target(2, 8, &all), Some(2));
    assert_eq!(stay_target(0, 8, &all), Some(0));
    assert_eq!(stay_target(-1, 8, &all), None);
    assert_eq!(stay_target(99, 8, &all), None);
    assert_eq!(stay_target(7, 8, &all), Some(7));
    assert_eq!(stay_target(8, 8, &all), None);
    let narrow = [false, false, true];
    assert_eq!(stay_target(0, 3, &narrow), None);
    assert_eq!(stay_target(2, 3, &narrow), Some(2));
    assert_eq!(stay_target(0, 3, &[false, false, false]), None);
    assert_eq!(stay_target(3, 3, &[true, true, true]), None);
}

#[test]
fn empty_mask_parks() {
    let empty = [false, false, false];
    assert_eq!(pick_target_cpu(0, &empty), None);
    assert_eq!(pick_target_cpu(2, &empty), None);
    assert_eq!(pick_target_cpu(-1, &empty), None);
    assert!(!may_run_on(0, &empty));
    assert!(!may_run_on(2, &empty));
    assert_eq!(pick_target_cpu(-1, &[]), None);
    assert!(!may_run_on(0, &[]));
}

#[test]
fn zero_freq_is_unknown_with_fallback() {
    assert!(!freq_known(0));
    assert!(freq_known(1));
    assert!(freq_known(3_800_000));
    assert!(freq_known(u64::MAX));
}

#[test]
fn single_cpu_has_no_peers() {
    assert_eq!(next_peer(0, 1), None);
    assert_eq!(next_peer(0, 0), None);
    assert_eq!(next_peer(0, 2), Some(1));
    assert_eq!(next_peer(1, 2), Some(0));
    assert_eq!(next_peer(2, 2), None);
    assert_eq!(scan_bound(0), 0);
    assert_eq!(scan_bound(1), 0);
    assert_eq!(scan_bound(2), 1);
    assert_eq!(scan_bound(8), 7);
    assert_eq!(scan_bound(64), STEAL_BOUND);
    assert_eq!(stay_target(0, 1, &[true]), Some(0));
    assert_eq!(stay_target(0, 1, &[false]), None);
    assert_eq!(stay_target(1, 1, &[true]), None);
    assert_eq!(pick_target_cpu(0, &[true]), Some(0));
    assert_eq!(pick_target_cpu(-1, &[true]), Some(0));
    assert_eq!(pick_target_cpu(0, &[false]), None);
}

#[test]
fn steal_cursor_rotates_across_peers() {
    assert_eq!(steal_next(0, 4), 1);
    assert_eq!(steal_next(3, 4), 0);
    assert_eq!(steal_next(0, 1), 0);
    assert_eq!(steal_next(5, 0), 0);
    let mut cur = 0;
    for want in [1, 2, 3, 0, 1] {
        cur = steal_next(cur, 4);
        assert_eq!(cur, want);
    }
}

/*
 * Tier 0 model only for donor plus rescue. BPF ships
 * thief idle only by construction due to verifier jump
 * at 1000001 on asleep check, with donor asleep handled
 * by idle kick.
 */
#[test]
fn donor_keeps_last_task() {
    assert!(!donor_ok(0, false, false));
    assert!(!donor_ok(1, false, false));
    assert!(!donor_ok(0, true, true));
    assert!(donor_ok(1, true, false));
    assert!(donor_ok(1, false, true));
    assert!(donor_ok(1, true, true));
    for depth in [2, 3, 8, 32] {
        assert!(donor_ok(depth, false, false));
        assert!(donor_ok(depth, true, false));
        assert!(donor_ok(depth, false, true));
    }
    assert_eq!(scan_bound(2), 1);
    assert_eq!(scan_bound(9), 8);
    assert_eq!(scan_bound(16), 8);
    assert_eq!(scan_bound(1024), 8);
}

#[test]
fn select_prefers_idle_then_prior() {
    let allowed = [true, true, true, true];
    let idle = [false, true, false, false];
    assert_eq!(pick_any_idle(&allowed, &idle), Some(1));
    assert_eq!(select_cpu_model(0, 2, &allowed, &idle), Some(1));
    let busy = [false, false, false, false];
    assert_eq!(pick_any_idle(&allowed, &busy), None);
    assert_eq!(select_cpu_model(2, 1, &allowed, &busy), Some(2));
    let empty = [false, false, false, false];
    assert_eq!(select_cpu_model(1, 0, &empty, &idle), None);
}

#[test]
fn lestat_pinned_subset_stays_in_mask() {
    let mut allowed = vec![false; 32];
    for cpu in 0..8 {
        allowed[cpu] = true;
    }
    for cpu in 16..24 {
        allowed[cpu] = true;
    }
    assert_eq!(allowed.iter().filter(|v| **v).count(), 16);
    for sel in [0, 7, 16, 23, -1, 8, 24, 99] {
        let got = pick_target_cpu(sel, &allowed);
        assert!(got.is_some());
        let cpu = got.unwrap() as usize;
        assert!(allowed[cpu]);
        assert!(may_run_on(cpu as i32, &allowed));
    }
    assert!(!may_run_on(8, &allowed));
    assert!(!may_run_on(15, &allowed));
    assert!(!may_run_on(24, &allowed));
    assert!(!may_run_on(31, &allowed));
    assert!(may_run_on(0, &allowed));
    assert!(may_run_on(23, &allowed));
    assert_eq!(stay_target(8, 32, &allowed), None);
    assert_eq!(stay_target(0, 32, &allowed), Some(0));
    assert_eq!(stay_target(16, 32, &allowed), Some(16));
}

#[test]
fn konaka_single_cpu_never_leaves() {
    let allowed = [true];
    assert_eq!(pick_target_cpu(0, &allowed), Some(0));
    assert_eq!(pick_target_cpu(-1, &allowed), Some(0));
    assert_eq!(pick_target_cpu(5, &allowed), Some(0));
    assert_eq!(pick_target_cpu(0, &[false]), None);
    assert!(may_run_on(0, &allowed));
    assert!(!may_run_on(1, &allowed));
    assert_eq!(stay_target(0, 1, &allowed), Some(0));
    assert_eq!(stay_target(1, 1, &allowed), None);
    assert_eq!(next_peer(0, 1), None);
    assert_eq!(scan_bound(1), 0);
}

#[test]
fn pinned_single_cpu_never_leaves() {
    let pinned = [false, false, true, false];
    for sel in [-1, 0, 1, 2, 3, 5, 99] {
        assert_eq!(pick_target_cpu(sel, &pinned), Some(2));
    }
    assert!(may_run_on(2, &pinned));
    assert!(!may_run_on(0, &pinned));
    assert!(!may_run_on(-1, &pinned));
    assert!(!may_run_on(99, &pinned));
}

#[test]
fn dispatch_skips_dead_head() {
    let dead = PendingTask {
        allowed: vec![true, true],
        exiting: false,
        live: false,
        fail: false,
    };
    let good = PendingTask {
        allowed: vec![true, true],
        exiting: false,
        live: true,
        fail: false,
    };
    let mut q = VecDeque::from([dead.clone(), good.clone()]);
    for _ in 0..2 {
        q.push_back(good.clone());
    }
    let moved = drain_model(&mut q, 0, DISPATCH_BATCH);
    assert_eq!(moved, 3);
    assert_eq!(q.len(), 1);
    assert_eq!(q[0], dead);
}

#[test]
fn dispatch_skips_failed_move_with_progress() {
    let failed = PendingTask {
        allowed: vec![true, true],
        exiting: false,
        live: true,
        fail: true,
    };
    let good = PendingTask {
        allowed: vec![true, true],
        exiting: false,
        live: true,
        fail: false,
    };
    let mut q = VecDeque::from([failed.clone(), good.clone(), good.clone()]);
    let moved = drain_model(&mut q, 0, DISPATCH_BATCH);
    assert!(moved > 0);
    assert_eq!(moved, 2);
    assert_eq!(q.len(), 1);
    assert_eq!(q[0], failed);
}

#[test]
fn dispatch_batch_drains_within_passes() {
    let good = PendingTask {
        allowed: vec![true; 16],
        exiting: false,
        live: true,
        fail: false,
    };
    let mut q = VecDeque::new();
    for _ in 0..64 {
        q.push_back(good.clone());
    }
    let first = drain_model(&mut q, 0, DISPATCH_BATCH);
    assert_eq!(first, 32);
    assert_eq!(q.len(), 32);
    let second = drain_model(&mut q, 0, DISPATCH_BATCH);
    assert_eq!(second, 32);
    assert!(q.is_empty());
}

#[test]
fn dispatch_park_moves_exiting_head() {
    let exiting = PendingTask {
        allowed: vec![true, true],
        exiting: true,
        live: true,
        fail: false,
    };
    let foreign = PendingTask {
        allowed: vec![false, true],
        exiting: false,
        live: true,
        fail: false,
    };
    let good = PendingTask {
        allowed: vec![true, true],
        exiting: false,
        live: true,
        fail: false,
    };
    let mut q = VecDeque::from([exiting.clone(), foreign.clone(), good.clone(), good.clone()]);
    let moved = drain_model(&mut q, 0, DISPATCH_BATCH);
    assert!(moved > 0);
    assert_eq!(moved, 3);
    assert_eq!(q.len(), 1);
    assert_eq!(q[0], foreign);
}

#[test]
fn progress_guarantee_zero_means_no_movable_work() {
    let dead = PendingTask {
        allowed: vec![true, true],
        exiting: false,
        live: false,
        fail: false,
    };
    let foreign = PendingTask {
        allowed: vec![false, false],
        exiting: false,
        live: true,
        fail: false,
    };
    let mut q = VecDeque::from([dead.clone(), foreign.clone()]);
    let moved = drain_model(&mut q, 0, DISPATCH_BATCH);
    assert_eq!(moved, 0);
    assert_eq!(q.len(), 2);
    q.push_back(PendingTask {
        allowed: vec![true, true],
        exiting: false,
        live: true,
        fail: false,
    });
    let moved2 = drain_model(&mut q, 0, DISPATCH_BATCH);
    assert_eq!(moved2, 1);
}

#[test]
fn dispatch_own_park_respects_budget() {
    let good = PendingTask {
        allowed: vec![true, true],
        exiting: false,
        live: true,
        fail: false,
    };
    let mut own = VecDeque::new();
    let mut park = VecDeque::new();
    for _ in 0..64 {
        own.push_back(good.clone());
    }
    for _ in 0..4 {
        park.push_back(good.clone());
    }
    let (a, b) = dispatch_own_park_model(&mut own, &mut park, 0, 32);
    assert_eq!(a, 32);
    assert_eq!(b, 0);
    assert_eq!(a + b, 32);
    let mut small_own = VecDeque::new();
    let mut small_park = VecDeque::new();
    for _ in 0..10 {
        small_own.push_back(good.clone());
    }
    for _ in 0..4 {
        small_park.push_back(good.clone());
    }
    let (c, d) = dispatch_own_park_model(&mut small_own, &mut small_park, 0, 32);
    assert_eq!(c, 10);
    assert_eq!(d, 4);
}

#[test]
fn steal_only_when_idle_and_bounded() {
    let good = PendingTask {
        allowed: vec![true, true],
        exiting: false,
        live: true,
        fail: false,
    };
    let mut peers: Vec<VecDeque<PendingTask>> = vec![
        VecDeque::new(),
        VecDeque::from([good.clone(), good.clone()]),
    ];
    let (busy, _) = steal_model(&mut peers.clone(), 0, 0, 8, false, false, &[]);
    assert_eq!(busy, 0);
    let (idle, next) = steal_model(&mut peers, 0, 0, 8, true, false, &[false, false]);
    assert_eq!(idle, 1);
    assert_eq!(next, 1);
    let mut wide: Vec<VecDeque<PendingTask>> = vec![VecDeque::new(); 16];
    for q in wide.iter_mut().skip(1) {
        q.push_back(good.clone());
        q.push_back(good.clone());
    }
    let (capped, _) = steal_model(&mut wide, 0, 0, 32, true, false, &[]);
    assert!(capped > 0);
    assert!(capped <= 8);
}

#[test]
fn steal_checks_mask_and_skips_bad_heads() {
    let foreign = PendingTask {
        allowed: vec![false, false],
        exiting: false,
        live: true,
        fail: false,
    };
    let exiting = PendingTask {
        allowed: vec![true, true],
        exiting: true,
        live: true,
        fail: false,
    };
    let good = PendingTask {
        allowed: vec![true, true],
        exiting: false,
        live: true,
        fail: false,
    };
    let mut peers: Vec<VecDeque<PendingTask>> = vec![
        VecDeque::new(),
        VecDeque::from([foreign.clone(), exiting.clone(), good.clone()]),
        VecDeque::from([good.clone()]),
    ];
    let (moved, _) = steal_model(&mut peers, 0, 0, 8, true, false, &[false, false, false]);
    assert_eq!(moved, 1);
    assert_eq!(peers[1].len(), 2);
    assert_eq!(peers[2].len(), 1);
}

#[test]
fn idle_rescues_singleton() {
    let good = PendingTask {
        allowed: vec![true, true],
        exiting: false,
        live: true,
        fail: false,
    };
    let mut peers: Vec<VecDeque<PendingTask>> =
        vec![VecDeque::new(), VecDeque::from([good.clone()])];
    let (moved, _) = steal_model(&mut peers, 0, 0, 8, true, true, &[false, false]);
    assert_eq!(moved, 1);
    assert!(peers[1].is_empty());
}

#[test]
fn busy_refuses_singleton() {
    let good = PendingTask {
        allowed: vec![true, true],
        exiting: false,
        live: true,
        fail: false,
    };
    let mut peers: Vec<VecDeque<PendingTask>> =
        vec![VecDeque::new(), VecDeque::from([good.clone()])];
    let (moved, _) = steal_model(&mut peers, 0, 0, 8, true, false, &[false, false]);
    assert_eq!(moved, 0);
    assert_eq!(peers[1].len(), 1);
    let (busy, _) = steal_model(&mut peers.clone(), 0, 0, 8, false, false, &[false, false]);
    assert_eq!(busy, 0);
}

#[test]
fn rescue_ignores_unmovable_park_leftovers() {
    assert!(rescue_single_ok(0, 0));
    assert!(!rescue_single_ok(1, 0));
    assert!(!rescue_single_ok(0, 1));
    assert!(!rescue_single_ok(1, 1));
    assert!(!rescue_single_ok(0, 2));
}

/*
 * Tier 0 model only for donor asleep rescue. BPF ships
 * thief idle only by construction due to verifier jump
 * at 1000001 on asleep check, with donor asleep handled
 * by idle kick.
 */
#[test]
fn donor_asleep_rescues_singleton() {
    let good = PendingTask {
        allowed: vec![true, true],
        exiting: false,
        live: true,
        fail: false,
    };
    let mut peers: Vec<VecDeque<PendingTask>> =
        vec![VecDeque::new(), VecDeque::from([good.clone()])];
    let (moved, _) = steal_model(&mut peers, 0, 0, 8, true, false, &[false, true]);
    assert_eq!(moved, 1);
    assert!(peers[1].is_empty());
}

#[test]
fn exiting_task_eventually_runs() {
    let exiting = PendingTask {
        allowed: vec![true, true],
        exiting: true,
        live: true,
        fail: false,
    };
    let good = PendingTask {
        allowed: vec![true, true],
        exiting: false,
        live: true,
        fail: false,
    };
    let mut q = VecDeque::from([exiting.clone(), good.clone()]);
    let moved = drain_model(&mut q, 0, DISPATCH_BATCH);
    assert_eq!(moved, 2);
    assert!(q.is_empty());
    assert!(peer_head_ok(0, Some(&exiting)));
    let mut peers: Vec<VecDeque<PendingTask>> = vec![
        VecDeque::new(),
        VecDeque::from([exiting.clone(), good.clone()]),
        VecDeque::new(),
    ];
    let (stolen, _) = steal_model(&mut peers, 0, 0, 8, true, false, &[false, false, false]);
    assert_eq!(stolen, 1);
    let far = PendingTask {
        allowed: vec![false, true],
        exiting: true,
        live: true,
        fail: false,
    };
    assert!(!peer_head_ok(0, Some(&far)));
    assert!(peer_head_ok(1, Some(&far)));
}

#[test]
fn idle_steals_past_unmovable_leftovers() {
    assert!(may_steal(2, 0, 0));
    assert!(may_steal(0, 1, 0));
    assert!(may_steal(0, 0, 0));
    assert!(!may_steal(1, 0, 1));
    assert!(!may_steal(0, 1, 1));
    assert!(may_steal(0, 0, 1));
    let foreign = PendingTask {
        allowed: vec![false, true],
        exiting: false,
        live: true,
        fail: false,
    };
    let mut own = VecDeque::from([foreign.clone(), foreign.clone()]);
    let moved = drain_model(&mut own, 0, DISPATCH_BATCH);
    assert_eq!(moved, 0);
    assert!(may_steal(own.len() as u64, 0, moved));
}

#[test]
fn cleared_running_view_reads_idle() {
    let mut view = RunningView {
        est: 100,
        pid: 7,
        nice: -5,
        weight: 1218,
    };
    assert!(!view.is_idle());
    view.clear();
    assert_eq!(view, RunningView::idle());
    assert!(view.is_idle());
}

#[test]
fn disable_exit_clears_only_owner() {
    let mut view = RunningView {
        est: 100,
        pid: 7,
        nice: -5,
        weight: 1218,
    };
    view.clear_if_owner(7);
    assert_eq!(view, RunningView::idle());
    assert!(view.is_idle());
    let mut busy = RunningView {
        est: 100,
        pid: 9,
        nice: 10,
        weight: 494,
    };
    busy.clear_if_owner(7);
    assert_eq!(busy.pid, 9);
    assert_eq!(busy.est, 100);
    assert_eq!(busy.nice, 10);
    assert_eq!(busy.weight, 494);
    assert!(!busy.is_idle());
    let mut idle = RunningView::idle();
    idle.clear_if_owner(7);
    assert_eq!(idle, RunningView::idle());
    assert!(kick_idle_ok(2, idle.pid, true));
    assert!(!kick_idle_ok(2, busy.pid, true));
}

#[test]
fn completion_counts_once_per_grant() {
    let mut deadline = COMPLETED_SENTINEL;
    assert!(!completion_take(&mut deadline));
    completion_grant(&mut deadline, 1_000_000);
    assert!(completion_take(&mut deadline));
    assert!(!completion_take(&mut deadline));
    assert!(!completion_take(&mut deadline));
    completion_grant(&mut deadline, u64::MAX);
    assert_ne!(deadline, COMPLETED_SENTINEL);
    assert!(completion_take(&mut deadline));
    assert!(!completion_take(&mut deadline));
}

#[test]
fn dispatch_own_park_then_steal_gate() {
    let good = PendingTask {
        allowed: vec![true, true, true],
        exiting: false,
        live: true,
        fail: false,
    };
    let foreign = PendingTask {
        allowed: vec![false, false, false],
        exiting: false,
        live: true,
        fail: false,
    };
    let mut own = VecDeque::from([foreign.clone(), foreign.clone()]);
    let mut park = VecDeque::new();
    let mut peers: Vec<VecDeque<PendingTask>> = vec![
        VecDeque::new(),
        VecDeque::from([good.clone(), good.clone()]),
        VecDeque::new(),
    ];
    let (a, b) = dispatch_own_park_model(&mut own, &mut park, 0, 32);
    assert_eq!(a + b, 0);
    assert_eq!(own.len(), 2);
    let moved = a + b;
    assert!(may_steal(own.len() as u64, park.len() as u64, moved));
    let (stolen, _) = steal_model(&mut peers, 0, 0, 32 - moved, true, false, &[]);
    assert_eq!(stolen, 1);
    assert_eq!(a + b + stolen, 1);
    let mut own2 = VecDeque::from([good.clone(), good.clone()]);
    let mut park2 = VecDeque::new();
    let mut peers2: Vec<VecDeque<PendingTask>> = vec![
        VecDeque::new(),
        VecDeque::from([good.clone(), good.clone()]),
        VecDeque::new(),
    ];
    let (c, d) = dispatch_own_park_model(&mut own2, &mut park2, 0, 32);
    assert_eq!(c, 2);
    assert_eq!(d, 0);
    assert!(own2.is_empty());
    let moved2 = c + d;
    assert!(may_steal(own2.len() as u64, park2.len() as u64, moved2));
    let (stolen2, _) = steal_model(&mut peers2, 0, 0, 32 - moved2, true, false, &[]);
    assert_eq!(stolen2, 1);
    assert!(c + d + stolen2 <= 32);
    let mut own3 = VecDeque::from([good.clone(), foreign.clone()]);
    let mut park3 = VecDeque::new();
    let (e, f) = dispatch_own_park_model(&mut own3, &mut park3, 0, 32);
    assert_eq!(e, 1);
    assert_eq!(own3.len(), 1);
    let moved3 = e + f;
    assert!(!may_steal(own3.len() as u64, park3.len() as u64, moved3));
    assert!(e + f <= 32);
}

#[test]
fn mask_range_and_live_fail_closed() {
    assert!(!may_run_on(-1, &[true, true]));
    assert!(!cpu_live(-1, 2));
    assert!(!may_run_on_live(-1, &[true, true], 2));
    assert!(!may_run_on(1024, &[true; 2048]));
    assert!(!cpu_live(1024, 2048));
    assert!(cpu_live(0, 2));
    assert!(cpu_live(1, 2));
    assert!(!cpu_live(2, 2));
    assert!(!cpu_live(0, 0));
    assert!(may_run_on_live(0, &[true, true], 2));
    assert!(!may_run_on_live(0, &[false, true], 2));
    assert!(!may_run_on_live(1, &[true, true], 1));
    assert!(may_run_on(0, &[true, false]));
    assert!(!may_run_on(1, &[true, false]));
    assert!(!may_run_on(2, &[true, false]));
}

#[test]
fn facade_matches_helpers() {
    assert_eq!(crate::flow::DISPATCH_BATCH, crate::flow_edf::DISPATCH_BATCH);
    assert_eq!(crate::flow::DSQ_BASE, crate::flow_edf::DSQ_BASE);
    assert_eq!(crate::flow::DSQ_PARK, crate::flow_edf::DSQ_PARK);
    assert_eq!(crate::flow::EST_MIN_NS, crate::flow_slice::EST_MIN_NS);
    assert_eq!(crate::flow::EST_MAX_NS, crate::flow_slice::EST_MAX_NS);
    assert_eq!(crate::flow::SLICE_NS, crate::flow_slice::SLICE_NS);
    assert_eq!(crate::flow::WEIGHT, crate::flow_slice::WEIGHT);
    assert_eq!(crate::flow::MAX_CPUS, crate::flow_select::MAX_CPUS);
    assert_eq!(
        crate::flow::STEAL_MIN_DEPTH,
        crate::flow_select::STEAL_MIN_DEPTH
    );
    assert_eq!(crate::flow::STEAL_BOUND, crate::flow_select::STEAL_BOUND);
    assert_eq!(
        crate::flow::KICK_COALESCE_NS,
        crate::flow_select::KICK_COALESCE_NS
    );
}

/*
 * Free core needs no sibling running. Singletons with
 * 0xffff read as free. Out of range fails closed. Busy
 * siblings read as held. Follows the partner table for
 * up to 8 steps with no trap. Mirrors the BPF walk.
 */
#[test]
fn free_core_needs_no_sibling_running() {
    use crate::flow_group::SIBLING_EMPTY;
    let partner = vec![1, 0, SIBLING_EMPTY, SIBLING_EMPTY];
    let free = vec![false, false, false, false];
    assert!(core_free(0, &partner, &free, 4));
    assert!(core_free(2, &partner, &free, 4));
    let busy = vec![false, true, false, false];
    assert!(!core_free(0, &partner, &busy, 4));
    assert!(core_free(2, &partner, &busy, 4));
    assert!(!core_free(-1, &partner, &free, 4));
    assert!(!core_free(99, &partner, &free, 4));
    assert!(!core_free(1024, &partner, &free, 4));
    let tri = vec![1, 2, 0];
    let busy_tri = vec![false, false, true];
    assert!(!core_free(0, &tri, &busy_tri, 3));
    assert!(!core_free(1, &tri, &busy_tri, 3));
    assert!(!core_free(2, &tri, &busy_tri, 3));
}

/*
 * Tier A scans for a free core in the group with no
 * claim. Tier B prefers any idle in the group. The
 * scan stays in id order with group plus mask plus
 * running pid. Strict iff ready is zero, best effort
 * iff ready is one with live table in placement.
 */
#[test]
fn tier_prefers_free_core_in_group() {
    use crate::flow_group::GROUP_HOG;
    use crate::flow_group::GROUP_LIGHT;
    use crate::flow_group::GROUP_TABLE_LEN;
    let nr = 4;
    let mut table = [GROUP_LIGHT; GROUP_TABLE_LEN];
    table[0] = GROUP_LIGHT;
    table[1] = GROUP_LIGHT;
    table[2] = GROUP_HOG;
    table[3] = GROUP_HOG;
    let partner = vec![1, 0, 3, 2];
    let allowed = vec![true; 4];
    let running = vec![false, true, false, false];
    let free = pick_free_idle(&allowed, GROUP_LIGHT, nr, &table, 1, &partner, &running);
    assert_eq!(free, None);
    let running2 = vec![false, false, false, false];
    let free2 = pick_free_idle(&allowed, GROUP_LIGHT, nr, &table, 1, &partner, &running2);
    assert_eq!(free2, Some(0));
    let idle = vec![true; 4];
    let any = pick_idle_in_group(&allowed, &idle, GROUP_LIGHT, nr, &table, 1);
    assert_eq!(any, Some(0));
    let hog = pick_idle_in_group(&allowed, &idle, GROUP_HOG, nr, &table, 1);
    assert_eq!(hog, Some(2));
    let tier = select_cpu_tiered(
        3,
        3,
        &allowed,
        &idle,
        GROUP_LIGHT,
        nr,
        &table,
        1,
        &partner,
        &running2,
    );
    assert_eq!(tier, Some(0));
}

/*
 * Tier A needs no scx idle claim. Running free wins
 * even when no CPU is marked idle, so a miss wastes
 * no idle claim. Tier B needs idle and stays none.
 */
#[test]
fn tier_a_needs_no_idle_claim() {
    use crate::flow_group::GROUP_LIGHT;
    use crate::flow_group::GROUP_TABLE_LEN;
    use crate::flow_group::SIBLING_EMPTY;
    let nr = 4;
    let table = [GROUP_LIGHT; GROUP_TABLE_LEN];
    let partner = vec![SIBLING_EMPTY; 4];
    let running = vec![false; 4];
    let allowed = vec![true; 4];
    let idle = vec![false; 4];
    let free = pick_free_idle(&allowed, GROUP_LIGHT, nr, &table, 0, &partner, &running);
    assert_eq!(free, Some(0));
    let any = pick_idle_in_group(&allowed, &idle, GROUP_LIGHT, nr, &table, 0);
    assert_eq!(any, None);
    let tier = select_cpu_tiered(
        -1,
        -1,
        &allowed,
        &idle,
        GROUP_LIGHT,
        nr,
        &table,
        0,
        &partner,
        &running,
    );
    assert_eq!(tier, Some(0));
}

/*
 * Singletons treat all running free as free. The core
 * check is a no-op, so Tier A is the first running
 * free in the group with no trap. Tier B stays first
 * idle, so the two may differ with no stall. Waker CPU
 * is busy, so the tiers below run with no keep.
 */
#[test]
fn singleton_tier_is_noop_with_prior_order() {
    use crate::flow_group::GROUP_LIGHT;
    use crate::flow_group::GROUP_TABLE_LEN;
    use crate::flow_group::SIBLING_EMPTY;
    let nr = 4;
    let table = [GROUP_LIGHT; GROUP_TABLE_LEN];
    let partner = vec![SIBLING_EMPTY; 4];
    let running = vec![false, false, true, false];
    let allowed = vec![true; 4];
    let idle = vec![false, true, false, false];
    let free = pick_free_idle(&allowed, GROUP_LIGHT, nr, &table, 0, &partner, &running);
    assert_eq!(free, Some(0));
    let any = pick_idle_in_group(&allowed, &idle, GROUP_LIGHT, nr, &table, 0);
    assert_eq!(any, Some(1));
    assert!(core_free(0, &partner, &running, nr));
    assert!(core_free(1, &partner, &running, nr));
    let tier = select_cpu_tiered(
        0,
        2,
        &allowed,
        &idle,
        GROUP_LIGHT,
        nr,
        &table,
        0,
        &partner,
        &running,
    );
    assert_eq!(tier, Some(0));
    let busy = vec![false, true, false, false];
    let idle2 = vec![false, false, false, false];
    let tier2 = select_cpu_tiered(
        2,
        1,
        &allowed,
        &idle2,
        GROUP_LIGHT,
        nr,
        &table,
        0,
        &partner,
        &busy,
    );
    assert_eq!(tier2, Some(0));
}

/*
 * Tiered keeps mask plus group. Cross group running
 * stays out. Empty masks park with none. Pinned single
 * keeps the single CPU with no scan. Strict iff ready
 * is zero, best effort iff ready is one.
 */
#[test]
fn tiered_keeps_mask_plus_group() {
    use crate::flow_group::GROUP_HOG;
    use crate::flow_group::GROUP_LIGHT;
    use crate::flow_group::GROUP_TABLE_LEN;
    use crate::flow_group::SIBLING_EMPTY;
    let nr = 4;
    let mut table = [GROUP_LIGHT; GROUP_TABLE_LEN];
    table[0] = GROUP_LIGHT;
    table[1] = GROUP_LIGHT;
    table[2] = GROUP_HOG;
    table[3] = GROUP_HOG;
    let partner = vec![SIBLING_EMPTY; 4];
    let running = vec![false; 4];
    let narrow = vec![false, false, true, true];
    let idle = vec![true, true, true, true];
    let got = select_cpu_tiered(
        -1,
        -1,
        &narrow,
        &idle,
        GROUP_LIGHT,
        nr,
        &table,
        1,
        &partner,
        &running,
    );
    assert_eq!(got, Some(2));
    let hog_idle = vec![false, false, true, false];
    let got2 = select_cpu_tiered(
        -1, -1, &narrow, &hog_idle, GROUP_HOG, nr, &table, 1, &partner, &running,
    );
    assert_eq!(got2, Some(2));
    let empty = vec![false; 4];
    let got3 = select_cpu_tiered(
        1,
        0,
        &empty,
        &idle,
        GROUP_LIGHT,
        nr,
        &table,
        1,
        &partner,
        &running,
    );
    assert_eq!(got3, None);
    let pinned = vec![false, false, true, false];
    let got4 = select_cpu_tiered(
        -1, -1, &pinned, &idle, GROUP_HOG, nr, &table, 1, &partner, &running,
    );
    assert_eq!(got4, Some(2));
}

/*
 * Waker CPU idle in group keeps the waker. Needs idle
 * with no running task plus allowed plus in group.
 * An idle core cannot stack, so locality is free.
 * Beats Tier A even when CPU 0 is free with no idle.
 */
#[test]
fn waker_idle_keeps_waker() {
    use crate::flow_group::GROUP_LIGHT;
    use crate::flow_group::GROUP_TABLE_LEN;
    use crate::flow_group::SIBLING_EMPTY;
    let nr = 4;
    let table = [GROUP_LIGHT; GROUP_TABLE_LEN];
    let partner = vec![SIBLING_EMPTY; 4];
    let running = vec![false; 4];
    let allowed = vec![true; 4];
    let idle = vec![false; 4];
    assert!(waker_first_ok(
        2,
        &allowed,
        GROUP_LIGHT,
        nr,
        &table,
        1,
        &running
    ));
    let got = select_cpu_tiered(
        0,
        2,
        &allowed,
        &idle,
        GROUP_LIGHT,
        nr,
        &table,
        1,
        &partner,
        &running,
    );
    assert_eq!(got, Some(2));
}

/*
 * Waker CPU busy falls through to the tiers. Needs no
 * running task, so a busy waker keeps Tier A order
 * with no keep. Every other case keeps current
 * behavior with no change.
 */
#[test]
fn waker_busy_falls_to_tiers() {
    use crate::flow_group::GROUP_LIGHT;
    use crate::flow_group::GROUP_TABLE_LEN;
    use crate::flow_group::SIBLING_EMPTY;
    let nr = 4;
    let table = [GROUP_LIGHT; GROUP_TABLE_LEN];
    let partner = vec![SIBLING_EMPTY; 4];
    let running = vec![false, false, true, false];
    let allowed = vec![true; 4];
    let idle = vec![false; 4];
    assert!(!waker_first_ok(
        2,
        &allowed,
        GROUP_LIGHT,
        nr,
        &table,
        1,
        &running
    ));
    let got = select_cpu_tiered(
        0,
        2,
        &allowed,
        &idle,
        GROUP_LIGHT,
        nr,
        &table,
        1,
        &partner,
        &running,
    );
    assert_eq!(got, Some(0));
}

/*
 * Waker CPU cross group falls through to the tiers.
 * Needs the same group, so a hog waker keeps light
 * Tier A order with no keep. Every other case keeps
 * current behavior with no change.
 */
#[test]
fn waker_cross_group_falls_to_tiers() {
    use crate::flow_group::GROUP_HOG;
    use crate::flow_group::GROUP_LIGHT;
    use crate::flow_group::GROUP_TABLE_LEN;
    use crate::flow_group::SIBLING_EMPTY;
    let nr = 4;
    let mut table = [GROUP_LIGHT; GROUP_TABLE_LEN];
    table[0] = GROUP_LIGHT;
    table[1] = GROUP_LIGHT;
    table[2] = GROUP_HOG;
    table[3] = GROUP_HOG;
    let partner = vec![SIBLING_EMPTY; 4];
    let running = vec![false; 4];
    let allowed = vec![true; 4];
    let idle = vec![true; 4];
    assert!(!waker_first_ok(
        2,
        &allowed,
        GROUP_LIGHT,
        nr,
        &table,
        1,
        &running
    ));
    assert!(waker_first_ok(
        2, &allowed, GROUP_HOG, nr, &table, 1, &running
    ));
    let got = select_cpu_tiered(
        0,
        2,
        &allowed,
        &idle,
        GROUP_LIGHT,
        nr,
        &table,
        1,
        &partner,
        &running,
    );
    assert_eq!(got, Some(0));
}

/*
 * Waker CPU mask fail falls through to the tiers. Needs
 * the mask set, so a foreign waker keeps Tier A order
 * with no keep. Every other case keeps current
 * behavior with no change.
 */
#[test]
fn waker_mask_fail_falls_to_tiers() {
    use crate::flow_group::GROUP_LIGHT;
    use crate::flow_group::GROUP_TABLE_LEN;
    use crate::flow_group::SIBLING_EMPTY;
    let nr = 4;
    let table = [GROUP_LIGHT; GROUP_TABLE_LEN];
    let partner = vec![SIBLING_EMPTY; 4];
    let running = vec![false; 4];
    let allowed = vec![true, false, false, true];
    let idle = vec![false; 4];
    assert!(!waker_first_ok(
        1,
        &allowed,
        GROUP_LIGHT,
        nr,
        &table,
        0,
        &running
    ));
    assert!(!waker_first_ok(
        9,
        &allowed,
        GROUP_LIGHT,
        nr,
        &table,
        0,
        &running
    ));
    let got = select_cpu_tiered(
        0,
        1,
        &allowed,
        &idle,
        GROUP_LIGHT,
        nr,
        &table,
        0,
        &partner,
        &running,
    );
    assert_eq!(got, Some(0));
}

/*
 * SMT off placement keeps the core check as a no-op.
 * All singleton cores read as free, so Tier A is the
 * first running free in the group with no trap. Table
 * equals halves with ready cleared, so no stall.
 * Waker CPU is busy, so the tiers below run with no keep.
 * Strict iff ready is zero with live table in use.
 */
#[test]
fn smt_off_placement_matches_prior() {
    use crate::flow_group::GROUP_LIGHT;
    use crate::flow_group::GROUP_TABLE_LEN;
    use crate::flow_group::SIBLING_EMPTY;
    let nr = 8;
    let table = [GROUP_LIGHT; GROUP_TABLE_LEN];
    let partner = vec![SIBLING_EMPTY; 8];
    let running = vec![false, false, false, false, false, false, false, true];
    let allowed = vec![true; 8];
    for idle in [
        vec![true; 8],
        vec![false, true, false, true, false, true, false, true],
        vec![false; 8],
    ] {
        let free = pick_free_idle(&allowed, GROUP_LIGHT, nr, &table, 0, &partner, &running);
        assert_eq!(free, Some(0));
        let any = pick_idle_in_group(&allowed, &idle, GROUP_LIGHT, nr, &table, 0);
        let tier = select_cpu_tiered(
            0,
            7,
            &allowed,
            &idle,
            GROUP_LIGHT,
            nr,
            &table,
            0,
            &partner,
            &running,
        );
        assert_eq!(tier, Some(0));
        if any.is_some() {
            assert!(tier.is_some());
        }
    }
    let single_partner = vec![SIBLING_EMPTY];
    let single_run = vec![false];
    let single_allow = vec![true];
    let single_idle = vec![true];
    let single_table = [GROUP_LIGHT; GROUP_TABLE_LEN];
    let t = select_cpu_tiered(
        0,
        0,
        &single_allow,
        &single_idle,
        GROUP_LIGHT,
        1,
        &single_table,
        0,
        &single_partner,
        &single_run,
    );
    assert_eq!(t, Some(0));
    for nr in [3, 5] {
        let table = [GROUP_LIGHT; GROUP_TABLE_LEN];
        let partner = vec![SIBLING_EMPTY; nr];
        let running = vec![false; nr];
        let allowed = vec![true; nr];
        let idle = vec![true; nr];
        let free = pick_free_idle(&allowed, GROUP_LIGHT, nr, &table, 0, &partner, &running);
        let any = pick_idle_in_group(&allowed, &idle, GROUP_LIGHT, nr, &table, 0);
        assert_eq!(free, Some(0));
        assert_eq!(any, Some(0));
    }
}

/*
 * Empty plus zero plus missing stay safe. Zero CPUs
 * give none with no table use. Missing partner reads
 * as free with no trap. No division runs here.
 */
#[test]
fn empty_plus_zero_stay_safe_with_no_trap() {
    use crate::flow_group::GROUP_LIGHT;
    use crate::flow_group::GROUP_TABLE_LEN;
    use crate::flow_group::SIBLING_EMPTY;
    let table = [GROUP_LIGHT; GROUP_TABLE_LEN];
    let partner: Vec<u16> = vec![];
    let running: Vec<bool> = vec![];
    assert!(!core_free(0, &partner, &running, 0));
    assert!(!core_free(-1, &partner, &running, 0));
    assert_eq!(
        pick_free_idle(&[], GROUP_LIGHT, 0, &table, 0, &partner, &running),
        None
    );
    assert_eq!(
        pick_idle_in_group(&[], &[], GROUP_LIGHT, 0, &table, 0),
        None
    );
    let tier = select_cpu_tiered(
        -1,
        -1,
        &[],
        &[],
        GROUP_LIGHT,
        0,
        &table,
        0,
        &partner,
        &running,
    );
    assert_eq!(tier, None);
    let short_partner = vec![SIBLING_EMPTY];
    assert!(core_free(0, &short_partner, &[], 1));
    assert!(!core_free(1, &short_partner, &[], 1));
}

/*
 * Weight table holds 40 levels with strict fall plus
 * center 1024 at nice 0. Ends are 2048 at minus 20
 * and 256 at 19, so total spread K is 8 with boost
 * 2x and penalty 4x. All values fit in u16 with no zero.
 */
#[test]
fn weight_table_is_monotonic_with_center_1024() {
    assert_eq!(WEIGHT_TABLE.len(), 40);
    assert_eq!(WEIGHT_TABLE[20], 1024);
    assert_eq!(WEIGHT, 1024);
    assert_eq!(WEIGHT_TABLE[0], 2048);
    assert_eq!(WEIGHT_TABLE[9], 1499);
    assert_eq!(WEIGHT_TABLE[39], 256);
    for w in WEIGHT_TABLE {
        assert!(w > 0);
    }
    for i in 0..39 {
        assert!(WEIGHT_TABLE[i] > WEIGHT_TABLE[i + 1]);
    }
    assert_eq!(weight_of(0), 1024);
    assert_eq!(weight_of(-20), 2048);
    assert_eq!(weight_of(19), 256);
    assert_eq!(NICE_MIN, -20);
    assert_eq!(NICE_MAX, 19);
    assert_eq!(WEIGHT_K, 8);
}

/*
 * Nice maps from static prio minus 120 with no clamp.
 * Weight falls back to 1024 past the table ends, so
 * unknown tasks stay neutral with no trap.
 */
#[test]
fn nice_maps_prio_minus_120_with_fallback() {
    assert_eq!(nice_of(120), 0);
    assert_eq!(nice_of(100), -20);
    assert_eq!(nice_of(139), 19);
    assert_eq!(nice_of(0), -120);
    assert_eq!(weight_of(nice_of(120)), 1024);
    assert_eq!(weight_of(nice_of(100)), 2048);
    assert_eq!(weight_of(nice_of(139)), 256);
    assert_eq!(weight_of(nice_of(0)), 1024);
    assert_eq!(weight_of(-21), 1024);
    assert_eq!(weight_of(20), 1024);
    assert_eq!(weight_of_prio(120), 1024);
    assert_eq!(weight_of_prio(0), 1024);
}

/*
 * Cap holds base in slice over 8 to slice times 8.
 * Center stays at one slice. Heavy keeps a short cap,
 * light keeps a long cap. Zero weight plus zero slice
 * stay safe with no divide fault.
 */
#[test]
fn cap_holds_in_k_bounds() {
    let slice = SLICE_NS;
    assert_eq!(cap_for_weight(1024, slice), slice);
    assert_eq!(cap_for_weight(0, slice), slice);
    assert_eq!(cap_for_weight(1024, 0), 0);
    assert_eq!(cap_for_weight(0, 0), 0);
    let heavy = cap_for_weight(2048, slice);
    let light = cap_for_weight(256, slice);
    assert!(heavy < slice);
    assert!(light > slice);
    assert!(heavy >= slice / 8);
    assert!(light <= slice * 8);
    assert_eq!(cap_for_weight(1, slice), slice * 8);
    assert_eq!(cap_for_weight(u32::MAX, slice), slice / 8);
    assert_eq!(heavy, (slice * 1024) / 2048);
    assert_eq!(light, (slice * 1024) / 256);
}

/*
 * Weight scaled clamp matches the fixed clamp at 1024.
 * Heavy keeps a short lag, light keeps a long lag. Wrap
 * stays safe with the same before check.
 */
#[test]
fn clamp_w_matches_fixed_at_center() {
    let slice = SLICE_NS;
    let frontier = 100_000_000;
    assert_eq!(
        clamp_vruntime_w(0, frontier, slice, 1024),
        clamp_vruntime(0, frontier, slice)
    );
    assert!(!was_clamped_w(frontier, frontier, slice, 1024));
    assert!(was_clamped_w(0, frontier, slice, 1024));
    let heavy = clamp_vruntime_w(0, frontier, slice, 2048);
    let light = clamp_vruntime_w(0, frontier, slice, 256);
    assert!(time_before(light, heavy));
    assert_eq!(heavy, frontier - cap_for_weight(2048, slice));
    assert_eq!(light, frontier - cap_for_weight(256, slice));
}

/*
 * Heavy tasks keep earlier deadlines with the same
 * start. Scale plus clamp plus deadline all move with
 * weight, so low nice gains service with no starve as
 * the cap holds extremes in 8x.
 */
#[test]
fn heavy_keeps_earlier_deadline() {
    let slice = SLICE_NS;
    let frontier = 100_000_000;
    let v = frontier;
    let est = 1_000_000;
    let (_, dl_heavy, _) = edf_insert(v, frontier, slice, est, 2048);
    let (_, dl_base, _) = edf_insert(v, frontier, slice, est, 1024);
    let (_, dl_light, _) = edf_insert(v, frontier, slice, est, 256);
    assert!(time_before(dl_heavy, dl_base));
    assert!(time_before(dl_base, dl_light));
    assert!(scale_by_weight(est, 2048) < est);
    assert!(scale_by_weight(est, 256) > est);
}

/*
 * Insert matches weighted clamp plus scale plus
 * deadline. BPF clamps with the weight cap in both
 * enqueue paths, so the model composes the weighted
 * clamp with the scaled estimate at every weight.
 */
#[test]
fn edf_insert_matches_weighted_clamp_and_scale() {
    let slice = SLICE_NS;
    let frontier: u64 = 100_000_000;
    let weights = [256u32, 1024, 2048];
    let vs = [
        frontier,
        frontier.wrapping_sub(500_000),
        0,
        frontier.wrapping_add(1_000_000),
    ];
    let ests = [500_000u64, 1_000_000u64];
    for weight in weights {
        for v in vs {
            for est in ests {
                let want_c = clamp_vruntime_w(v, frontier, slice, weight);
                let want_flag = was_clamped_w(v, frontier, slice, weight);
                let want_scaled = scale_by_weight(clamp_est(est), weight);
                let want_dl = deadline(want_c, want_scaled);
                let (got_c, got_dl, got_flag) = edf_insert(v, frontier, slice, est, weight);
                assert_eq!(got_c, want_c);
                assert_eq!(got_flag, want_flag);
                assert_eq!(got_dl, want_dl);
            }
        }
    }
    assert_eq!(
        edf_insert(0, frontier, slice, 500_000, 1024).0,
        clamp_vruntime(0, frontier, slice)
    );
}

/*
 * Weight stays out of routing with no group plus steal
 * plus kick change. Placement plus drain plus kick read
 * the same with any weight, so only deadline plus
 * vruntime move with nice.
 */
#[test]
fn weight_keeps_routing_unchanged() {
    let allowed = [true, true, true, true];
    assert_eq!(pick_target_cpu(1, &allowed), Some(1));
    assert!(may_run_on(1, &allowed));
    assert!(donor_ok(2, false, false));
    assert!(!donor_ok(1, false, false));
    assert!(kick_idle_ok(2, 0, true));
    assert!(!park_kick_ok());
    let idle = RunningView::idle();
    assert!(idle.is_idle());
    assert_eq!(idle.nice, 0);
    assert_eq!(idle.weight, 1024);
    let mut view = RunningView {
        est: 100,
        pid: 7,
        nice: -20,
        weight: 2048,
    };
    assert!(!view.is_idle());
    view.clear();
    assert_eq!(view, RunningView::idle());
}

/*
 * Per CPU nice plus weight decode with defaults plus
 * alias. Old JSON with no new fields stays valid. Old
 * tq_ns still maps to slice with no loss.
 */
#[test]
fn per_cpu_nice_plus_weight_decode_with_alias() {
    let txt = "{\"id\":0}";
    let m: crate::stats::PerCpuMetrics = serde_json::from_str(txt).unwrap();
    assert_eq!(m.id, 0);
    assert_eq!(m.running_nice, 0);
    assert_eq!(m.running_weight, 0);
    assert_eq!(m.slice_ns, 0);
    assert_eq!(m.delay_win, 0);
    assert!(!m.delay_armed);
    let txt2 = "{\"id\":1,\"running_nice\":-5,\"running_weight\":1218,\"tq_ns\":1000000}";
    let m2: crate::stats::PerCpuMetrics = serde_json::from_str(txt2).unwrap();
    assert_eq!(m2.running_nice, -5);
    assert_eq!(m2.running_weight, 1218);
    assert_eq!(m2.slice_ns, 1_000_000);
    assert_eq!(m2.delay_win, 0);
    assert!(!m2.delay_armed);
    let txt3 = "{\"id\":2,\"running_nice\":10,\"running_weight\":494,\"slice_ns\":1000000}";
    let m3: crate::stats::PerCpuMetrics = serde_json::from_str(txt3).unwrap();
    assert_eq!(m3.slice_ns, 1_000_000);
    assert_eq!(m3.running_nice, 10);
    assert_eq!(m3.running_weight, 494);
    let txt4 = "{\"id\":3,\"delay_win\":16,\"delay_armed\":true}";
    let m4: crate::stats::PerCpuMetrics = serde_json::from_str(txt4).unwrap();
    assert_eq!(m4.delay_win, 16);
    assert!(m4.delay_armed);
}

/*
 * Facade reexports the weight helpers with no drift.
 * Table plus nice plus weight plus cap plus clamp all
 * match the helper modules at once.
 */
#[test]
fn facade_matches_weight_helpers() {
    assert_eq!(crate::flow::WEIGHT_TABLE, crate::flow_slice::WEIGHT_TABLE);
    assert_eq!(crate::flow::NICE_MIN, crate::flow_slice::NICE_MIN);
    assert_eq!(crate::flow::NICE_MAX, crate::flow_slice::NICE_MAX);
    assert_eq!(crate::flow::WEIGHT_K, crate::flow_slice::WEIGHT_K);
    assert_eq!(crate::flow::weight_of(0), crate::flow_slice::weight_of(0));
    assert_eq!(
        crate::flow::cap_for_weight(256, crate::flow::SLICE_NS),
        crate::flow_slice::cap_for_weight(256, crate::flow_slice::SLICE_NS)
    );
    assert_eq!(
        crate::flow::clamp_vruntime_w(0, 100, crate::flow::SLICE_NS, 1024),
        crate::flow_edf::clamp_vruntime_w(0, 100, crate::flow_slice::SLICE_NS, 1024)
    );
}

/*
 * Tiered least fallback picks the smallest queued
 * depth with lowest id on ties. Earlier tiers still
 * win when they hit, so the least step only covers
 * the old first fallback. Placement keeps live with
 * strict iff ready is zero. Mirrors BPF select at
 * 4.2.19 with halves untouched in dispatch.
 */
#[test]
fn tiered_least_fallback_picks_least() {
    use crate::flow_group::GROUP_LIGHT;
    use crate::flow_group::GROUP_TABLE_LEN;
    use crate::flow_group::SIBLING_EMPTY;
    let nr = 4;
    let table = [GROUP_LIGHT; GROUP_TABLE_LEN];
    let partner = vec![SIBLING_EMPTY; 4];
    let running = vec![true; 4];
    let allowed = vec![true; 4];
    let idle = vec![false; 4];
    let queued = vec![5, 1, 3, 9];
    let got = select_cpu_tiered_least(
        9,
        9,
        &allowed,
        &idle,
        GROUP_LIGHT,
        nr,
        &table,
        0,
        &partner,
        &running,
        &queued,
    );
    assert_eq!(got, Some(1));
    let tie = vec![2, 2, 2, 2];
    let got2 = select_cpu_tiered_least(
        9,
        9,
        &allowed,
        &idle,
        GROUP_LIGHT,
        nr,
        &table,
        0,
        &partner,
        &running,
        &tie,
    );
    assert_eq!(got2, Some(0));
    let empty: Vec<u64> = vec![];
    let got3 = select_cpu_tiered_least(
        9,
        9,
        &allowed,
        &idle,
        GROUP_LIGHT,
        nr,
        &table,
        0,
        &partner,
        &running,
        &empty,
    );
    assert_eq!(got3, Some(0));
    let narrow = vec![false, true, false, false];
    let got4 = select_cpu_tiered_least(
        9,
        9,
        &narrow,
        &idle,
        GROUP_LIGHT,
        nr,
        &table,
        0,
        &partner,
        &running,
        &queued,
    );
    assert_eq!(got4, Some(1));
}

/*
 * Pick in group least prefers the selected CPU when
 * allowed plus in group, else the least queued in the
 * group with lowest id on ties. No allowed CPU in the
 * group yields none for park use. Mirrors BPF enqueue
 * pick at 4.2.19 with live view plus frozen bounds.
 */
#[test]
fn pick_in_group_least_prefers_selected_else_least() {
    use crate::flow_group::GROUP_LIGHT;
    use crate::flow_group::GROUP_TABLE_LEN;
    let nr = 4;
    let table = [GROUP_LIGHT; GROUP_TABLE_LEN];
    let allowed = vec![true; 4];
    let queued = vec![5, 1, 3, 9];
    assert_eq!(
        pick_in_group_least(0, &allowed, GROUP_LIGHT, nr, &table, 0, &queued),
        Some(0)
    );
    assert_eq!(
        pick_in_group_least(9, &allowed, GROUP_LIGHT, nr, &table, 0, &queued),
        Some(1)
    );
    assert_eq!(
        pick_in_group_least(-1, &allowed, GROUP_LIGHT, nr, &table, 0, &queued),
        Some(1)
    );
    assert_eq!(
        pick_in_group_least(2, &allowed, GROUP_LIGHT, nr, &table, 0, &queued),
        Some(1)
    );
    let narrow = vec![false, false, true, true];
    assert_eq!(
        pick_in_group_least(0, &narrow, GROUP_LIGHT, nr, &table, 0, &queued),
        None
    );
    let empty = vec![false; 4];
    assert_eq!(
        pick_in_group_least(0, &empty, GROUP_LIGHT, nr, &table, 0, &queued),
        None
    );
}

/*
 * Corrected frontier takes the max with wrap. Ref
 * past target wins, target past ref wins, equal
 * stays, zero follows max, wrap follows before.
 * Mirrors the BPF normal path max of ref plus
 * target with no park plus no tctx use.
 */
#[test]
fn corrected_frontier_takes_max_with_wrap() {
    assert_eq!(corrected_frontier(100, 90), 100);
    assert_eq!(corrected_frontier(90, 100), 100);
    assert_eq!(corrected_frontier(100, 100), 100);
    assert_eq!(corrected_frontier(0, 0), 0);
    assert_eq!(corrected_frontier(100_000_000, 0), 100_000_000);
    assert_eq!(corrected_frontier(0, 100_000_000), 100_000_000);
    assert_eq!(corrected_frontier(90_000_000, 100_000_000), 100_000_000);
    assert_eq!(corrected_frontier(100_000_000, 90_000_000), 100_000_000);
    let old = u64::MAX - 100;
    let next = 50u64;
    assert!(time_before(old, next));
    assert_eq!(corrected_frontier(old, next), next);
    assert_eq!(corrected_frontier(next, old), next);
    assert_eq!(corrected_frontier(old, next), frontier_max(old, next));
    assert_eq!(corrected_frontier(next, old), frontier_max(next, old));
    assert_eq!(
        crate::flow::corrected_frontier(100, 90),
        corrected_frontier(100, 90)
    );
}

/*
 * Corrected frontier feeds clamp plus deserved with
 * one floor. A ref past target lifts the clamp and
 * widens deserved at once, so both see the same
 * max with no split view. Park plus no tctx keep
 * ref only with no use here.
 */
#[test]
fn corrected_frontier_feeds_clamp_and_deserved() {
    let slice = SLICE_NS;
    let target = 90_000_000u64;
    let reference = 100_000_000u64;
    let corrected = corrected_frontier(reference, target);
    assert_eq!(corrected, reference);
    let v = 0u64;
    let weight = 1024u32;
    let est = 500_000u64;
    let clamped_corrected = clamp_vruntime_w(v, corrected, slice, weight);
    let clamped_target = clamp_vruntime_w(v, target, slice, weight);
    assert_eq!(clamped_corrected, corrected.wrapping_sub(slice));
    assert_eq!(clamped_target, target.wrapping_sub(slice));
    assert!(time_before(clamped_target, clamped_corrected));
    let (_, dl_corrected, _) = edf_insert(v, corrected, slice, est, weight);
    let (_, dl_target, _) = edf_insert(v, target, slice, est, weight);
    assert!(time_before(dl_target, dl_corrected));
    let gran = crate::flow_preempt::granule_for_weight(weight, slice);
    let woken_dl = 95_000_000u64;
    let deserved_target = crate::flow_preempt::deserved(woken_dl, target, gran);
    let deserved_corrected = crate::flow_preempt::deserved(woken_dl, corrected, gran);
    assert!(!deserved_target);
    assert!(deserved_corrected);
    let deserved_raw = crate::flow_preempt::deserved(woken_dl, corrected, gran);
    assert_eq!(deserved_corrected, deserved_raw);
}

/*
 * S0 strict keeps group isolation with mask win.
 * Perf widens to any allowed on in group miss with
 * same tier order. Least keeps lowest depth plus
 * lowest id over the widened set. Mask always wins.
 */
#[test]
fn s0_strict_keeps_isolation_perf_widens_on_miss() {
    use crate::flow_group::GROUP_LIGHT;
    use crate::flow_group::GROUP_TABLE_LEN;
    let nr = 4;
    let table = [GROUP_LIGHT; GROUP_TABLE_LEN];
    // Halves at 4: 0,1 light plus 2,3 hog.
    let allowed = vec![true; 4];
    let queued = vec![5, 1, 3, 0];
    // Strict least in light is 1, perf same when hit.
    assert_eq!(
        pick_in_group_widened(9, &allowed, GROUP_LIGHT, nr, &table, 0, &queued, false),
        Some(1)
    );
    assert_eq!(
        pick_in_group_widened(9, &allowed, GROUP_LIGHT, nr, &table, 0, &queued, true),
        Some(1)
    );
    // Narrow to hog only: strict light misses, perf widens.
    let narrow = vec![false, false, true, true];
    assert_eq!(
        pick_in_group_widened(-1, &narrow, GROUP_LIGHT, nr, &table, 0, &queued, false),
        None
    );
    assert_eq!(
        pick_in_group_widened(-1, &narrow, GROUP_LIGHT, nr, &table, 0, &queued, true),
        Some(3)
    );
    // Selected cross group: strict skips to least, perf keeps it.
    assert_eq!(
        pick_in_group_widened(2, &allowed, GROUP_LIGHT, nr, &table, 0, &queued, false),
        Some(1)
    );
    assert_eq!(
        pick_in_group_widened(2, &allowed, GROUP_LIGHT, nr, &table, 0, &queued, true),
        Some(2)
    );
    // Mask wins in both modes with no allowed.
    let empty = vec![false; 4];
    assert_eq!(
        pick_in_group_widened(0, &empty, GROUP_LIGHT, nr, &table, 0, &queued, false),
        None
    );
    assert_eq!(
        pick_in_group_widened(0, &empty, GROUP_LIGHT, nr, &table, 0, &queued, true),
        None
    );
    // Least any keeps lowest depth plus lowest id.
    let tie = vec![2, 2, 1, 1];
    assert_eq!(least_any(&allowed, nr, &tie), Some(2));
    assert_eq!(least_any(&narrow, nr, &tie), Some(2));
    assert_eq!(least_any(&empty, nr, &tie), None);
}

/*
 * S0 tiered perf keeps order with wider any allowed.
 * Strict free plus idle plus prev plus least stay in
 * group, perf falls to any on each miss. Mask wins.
 */
#[test]
fn s0_tiered_perf_keeps_order_with_wider_set() {
    use crate::flow_group::GROUP_LIGHT;
    use crate::flow_group::GROUP_TABLE_LEN;
    use crate::flow_group::SIBLING_EMPTY;
    let nr = 4;
    let table = [GROUP_LIGHT; GROUP_TABLE_LEN];
    let partner = vec![SIBLING_EMPTY; 4];
    // All idle plus free: strict and perf both take 0.
    let allowed = vec![true; 4];
    let idle = vec![true; 4];
    let running = vec![false; 4];
    let queued = vec![0; 4];
    assert_eq!(
        select_cpu_tiered_perf(
            -1,
            0,
            &allowed,
            &idle,
            GROUP_LIGHT,
            nr,
            &table,
            0,
            &partner,
            &running,
            &queued,
            false
        ),
        Some(0)
    );
    assert_eq!(
        select_cpu_tiered_perf(
            -1,
            0,
            &allowed,
            &idle,
            GROUP_LIGHT,
            nr,
            &table,
            0,
            &partner,
            &running,
            &queued,
            true
        ),
        Some(0)
    );
    // Light masked out: strict falls to first hog, perf widens least.
    let hog_only = vec![false, false, true, true];
    let idle_hog = vec![false, false, true, true];
    let strict = select_cpu_tiered_perf(
        -1,
        0,
        &hog_only,
        &idle_hog,
        GROUP_LIGHT,
        nr,
        &table,
        0,
        &partner,
        &running,
        &queued,
        false,
    );
    let perf = select_cpu_tiered_perf(
        -1,
        0,
        &hog_only,
        &idle_hog,
        GROUP_LIGHT,
        nr,
        &table,
        0,
        &partner,
        &running,
        &queued,
        true,
    );
    assert_eq!(strict, Some(2));
    assert_eq!(perf, Some(2));
    // Waker cross group: strict skips, perf keeps waker.
    let running_busy = vec![true, true, true, false];
    let idle_none = vec![false; 4];
    let queued_busy = vec![5, 5, 5, 0];
    // Waker 3 is hog with idle core, group light.
    let s = select_cpu_tiered_perf(
        0,
        3,
        &allowed,
        &idle_none,
        GROUP_LIGHT,
        nr,
        &table,
        0,
        &partner,
        &running_busy,
        &queued_busy,
        false,
    );
    let p = select_cpu_tiered_perf(
        0,
        3,
        &allowed,
        &idle_none,
        GROUP_LIGHT,
        nr,
        &table,
        0,
        &partner,
        &running_busy,
        &queued_busy,
        true,
    );
    assert_ne!(s, p);
    assert_eq!(p, Some(3));
    // Mask wins: no allowed yields none in both modes.
    let empty = vec![false; 4];
    assert_eq!(
        select_cpu_tiered_perf(
            -1,
            0,
            &empty,
            &idle,
            GROUP_LIGHT,
            nr,
            &table,
            0,
            &partner,
            &running,
            &queued,
            false
        ),
        None
    );
    assert_eq!(
        select_cpu_tiered_perf(
            -1,
            0,
            &empty,
            &idle,
            GROUP_LIGHT,
            nr,
            &table,
            0,
            &partner,
            &running,
            &queued,
            true
        ),
        None
    );
}
