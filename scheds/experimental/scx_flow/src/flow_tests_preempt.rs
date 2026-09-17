// SPDX-License-Identifier: GPL-2.0
/*
 * Preempt unit tests
 *
 * Covers the delay, granule, slack, and rate helpers with header match and math
 * checks. Run with cargo test -p scx_flow flow_tests_preempt.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
use crate::flow_preempt::*;
use crate::flow_select::*;

#[test]
fn delay_consts_match_header() {
    assert_eq!(
        DELAY_UNIT_NS,
        crate::bpf_intf::flow_consts_FLOW_DELAY_UNIT_NS as u64
    );
    assert_eq!(
        DELAY_MAX,
        crate::bpf_intf::flow_consts_FLOW_DELAY_MAX as u64
    );
    assert_eq!(
        DELAY_ARM,
        crate::bpf_intf::flow_consts_FLOW_DELAY_ARM as u64
    );
    assert_eq!(
        DELAY_STAND,
        crate::bpf_intf::flow_consts_FLOW_DELAY_STAND as u64
    );
    assert_eq!(
        DELAY_WIN_LEN,
        crate::bpf_intf::flow_consts_FLOW_DELAY_WIN_LEN as u64
    );
    assert_eq!(
        GRANULE_FLOOR_NS,
        crate::bpf_intf::flow_consts_FLOW_GRANULE_FLOOR_NS as u64
    );
    assert_eq!(
        DESERVED_SLACK_NS,
        crate::bpf_intf::flow_consts_FLOW_DESERVED_SLACK_NS as u64
    );
    assert_eq!(
        crate::flow_preempt::CURSOR_STAND_BIT,
        crate::bpf_intf::flow_consts_FLOW_CURSOR_STAND_BIT as u32
    );
    assert_eq!(
        CURSOR_MASK,
        crate::bpf_intf::flow_consts_FLOW_CURSOR_MASK as u32
    );
    assert_eq!(DELAY_UNIT_NS, 32_000);
    assert_eq!(DELAY_MAX, 250);
    assert_eq!(DELAY_ARM, 16);
    assert_eq!(DELAY_STAND, 8);
    assert_eq!(DELAY_WIN_LEN, 8);
    assert_eq!(GRANULE_FLOOR_NS, 64_000);
    assert_eq!(DESERVED_SLACK_NS, 32_000);
    assert_eq!(DESERVED_SLACK_NS * 2, GRANULE_FLOOR_NS);
    assert_eq!(crate::flow_preempt::CURSOR_STAND_BIT, 0x400);
    assert_eq!(CURSOR_MASK, 0x7fff_fbff);
}

#[test]
fn delay_sample_maps_queued_to_units() {
    assert_eq!(delay_from_queued(0), 0);
    assert_eq!(delay_from_queued(1), 31);
    assert_eq!(delay_from_queued(2), 62);
    assert_eq!(delay_from_queued(3), 93);
    assert_eq!(delay_from_queued(4), 125);
    assert_eq!(delay_from_queued(7), 218);
    assert_eq!(delay_from_queued(8), 250);
    assert_eq!(delay_from_queued(9), 250);
    assert_eq!(delay_from_queued(100), 250);
    assert_eq!(delay_from_queued(u64::MAX), 250);
}

#[test]
fn delay_armed_needs_16() {
    assert!(!delay_armed(0));
    assert!(!delay_armed(8));
    assert!(!delay_armed(15));
    assert!(delay_armed(16));
    assert!(delay_armed(17));
    assert!(delay_armed(250));
}

#[test]
fn stand_holds_16_to_14_until_8() {
    assert!(delay_armed_latched(16, false));
    assert!(delay_armed_latched(14, true));
    assert!(!delay_armed(14));
    assert!(delay_armed_latched(8, true));
    assert!(!delay_armed_latched(7, true));
    assert!(!delay_armed_latched(14, false));
    assert!(!delay_armed_latched(8, false));
    assert!(!delay_armed_latched(0, true));
    assert!(!stand_held(0));
    assert!(stand_held(crate::flow_preempt::CURSOR_STAND_BIT));
    let win = delay_close(16, 0);
    assert_eq!(win, 14);
    assert!(delay_armed_latched(win, true));
    assert!(!delay_armed(win));
    let mut w = 16u8;
    let mut held = false;
    held = delay_armed_latched(w, held);
    assert!(held);
    w = delay_close(w, 0);
    held = delay_armed_latched(w, held);
    assert!(held);
    for _ in 0..16 {
        w = delay_close(w, 0);
        held = delay_armed_latched(w, held);
        if !held {
            break;
        }
    }
    assert!(!held);
    assert!((w as u64) < DELAY_STAND);
}

#[test]
fn delay_decay_holds_peaks_for_hysteresis() {
    assert_eq!(delay_decay(0), 0);
    assert_eq!(delay_decay(250), 219);
    assert_eq!(delay_decay(16), 14);
    assert_eq!(delay_decay(8), 7);
    assert_eq!(delay_decay(62), 55);
    let mut win = 250u8;
    for _ in 0..3 {
        win = delay_close(win, 0);
    }
    assert!(delay_armed(win));
    for _ in 0..24 {
        win = delay_close(win, 0);
    }
    assert!(!delay_armed(win));
    let mut w2 = 16u8;
    w2 = delay_close(w2, 0);
    assert!(!delay_armed(w2));
    let w3 = delay_close(16, 16);
    assert!(delay_armed(w3));
}

#[test]
fn delay_window_push_fast_arm_slow_fall() {
    let (w, c, n) = delay_push(0, 0, 0, 16);
    assert_eq!(w, 16);
    assert!(delay_armed(w));
    assert_eq!(c, 16);
    assert_eq!(n, 1);
    let mut win = 0u8;
    let mut cur = 0u8;
    let mut cnt = 0u16;
    for _ in 0..7 {
        let (a, b, d) = delay_push(win, cur, cnt, 10);
        win = a;
        cur = b;
        cnt = d;
    }
    assert!(!delay_armed(win));
    let (w2, _, _) = delay_push(win, cur, cnt, 250);
    assert!(delay_armed(w2));
    let mut w3 = w2;
    let mut c3 = 0u8;
    let mut n3 = 0u16;
    for _ in 0..240 {
        let (a, b, d) = delay_push(w3, c3, n3, 0);
        w3 = a;
        c3 = b;
        n3 = d;
        if !delay_armed(w3) {
            break;
        }
    }
    assert!(!delay_armed(w3));
}

#[test]
fn granule_is_weight_aware_with_64us_floor() {
    let slice = 1_000_000u64;
    assert_eq!(granule_for_weight(1024, slice), 250_000);
    assert_eq!(granule_for_weight(2048, slice), 125_000);
    assert_eq!(granule_for_weight(256, slice), 1_000_000);
    assert_eq!(granule_for_weight(1024, 0), 64_000);
    assert_eq!(granule_for_weight(0, slice), 250_000);
    assert_eq!(granule_for_weight(0, 0), 64_000);
    assert_eq!(granule_for_weight(0, 10_000), 64_000);
    assert_eq!(granule_for_weight(u32::MAX, slice), 64_000);
    assert!(granule_for_weight(2048, slice) < slice);
    assert_eq!(granule_for_weight(256, slice), slice);
    assert!(granule_for_weight(128, slice) > slice);
}

#[test]
fn frontier_deserved_beats_floor_by_granule() {
    let slice = 1_000_000u64;
    let gran = granule_for_weight(1024, slice);
    assert_eq!(gran, 250_000);
    assert_eq!(DESERVED_SLACK_NS, 32_000);
    let frontier = 100_000_000u64;
    let bound = frontier.wrapping_add(gran).wrapping_add(DESERVED_SLACK_NS);
    assert!(deserved(frontier, frontier, gran));
    assert!(deserved(frontier + 100_000, frontier, gran));
    assert!(deserved(frontier + gran, frontier, gran));
    assert!(deserved(bound.wrapping_sub(1), frontier, gran));
    assert!(!deserved(bound, frontier, gran));
    assert!(!deserved(bound.wrapping_add(1), frontier, gran));
    assert!(!deserved(frontier + 1_000_000, frontier, gran));
    let old = u64::MAX - 10;
    let wrap_gran = 20u64;
    let wrap_sum = old.wrapping_add(wrap_gran);
    assert_eq!(wrap_sum, 9);
    let wrap_bound = old.wrapping_add(wrap_gran).wrapping_add(DESERVED_SLACK_NS);
    assert_eq!(wrap_bound, 32_009);
    assert!(deserved(5, old, wrap_gran));
    assert!(deserved(wrap_bound.wrapping_sub(1), old, wrap_gran));
    assert!(!deserved(wrap_bound, old, wrap_gran));
    assert!(!deserved(wrap_bound.wrapping_add(1), old, wrap_gran));
}

/*
 * Slack eases the deserved bound by 32us with a strict miss by one pass and
 * exact boundary fail. Zero slack collapses to the old granule only compare
 * with no behavior change.
 */
#[test]
fn deserved_slack_eases_by_32us() {
    let slice = 1_000_000u64;
    let gran = granule_for_weight(1024, slice);
    assert_eq!(gran, 250_000);
    assert_eq!(DESERVED_SLACK_NS, 32_000);
    assert_eq!(DESERVED_SLACK_NS * 2, GRANULE_FLOOR_NS);
    let frontier = 100_000_000u64;
    let bound = frontier.wrapping_add(gran).wrapping_add(DESERVED_SLACK_NS);
    assert_eq!(bound, frontier + gran + 32_000);
    assert!(deserved(frontier + gran, frontier, gran));
    assert!(deserved(bound.wrapping_sub(1), frontier, gran));
    assert!(!deserved(bound, frontier, gran));
    assert!(!deserved(bound.wrapping_add(1), frontier, gran));
    let old = |woken_dl: u64| (woken_dl.wrapping_sub(frontier.wrapping_add(gran)) as i64) < 0;
    assert!(!old(frontier + gran));
    assert!(old(frontier + gran - 1));
    assert!(!old(frontier + gran + 1));
    let zero_slack = |woken_dl: u64| {
        (woken_dl.wrapping_sub(frontier.wrapping_add(gran).wrapping_add(0)) as i64) < 0
    };
    assert_eq!(zero_slack(frontier + gran - 1), old(frontier + gran - 1));
    assert_eq!(zero_slack(frontier + gran), old(frontier + gran));
    assert_eq!(zero_slack(frontier + gran + 1), old(frontier + gran + 1));
    assert!(deserved(frontier + gran, frontier, gran) != old(frontier + gran));
    assert!(deserved(bound.wrapping_sub(1), frontier, gran));
    assert!(!old(bound.wrapping_sub(1)));
}

#[test]
fn delay_stamp_has_no_count() {
    let (w, c) = delay_stamp(0, 0, 62);
    assert_eq!(w, 62);
    assert_eq!(c, 62);
    assert!(delay_armed(w));
    let (w2, c2) = delay_stamp(100, 20, 10);
    assert_eq!(w2, 100);
    assert_eq!(c2, 20);
    let (w3, c3) = delay_stamp(10, 10, 250);
    assert_eq!(w3, 250);
    assert_eq!(c3, 250);
    let mut win = 0u8;
    let mut cur = 0u8;
    let mut cnt = 0u16;
    for _ in 0..7 {
        let (a, b, d) = delay_push(win, cur, cnt, 0);
        win = a;
        cur = b;
        cnt = d;
    }
    assert_eq!(cnt, 7);
    let (sw, sc) = delay_stamp(win, cur, 62);
    assert_eq!(sw, 62);
    assert_eq!(sc, 62);
    assert_eq!(cnt, 7);
    let (cw, cc, cn) = delay_push(sw, sc, cnt, 0);
    assert_eq!(cn, 0);
    assert_eq!(cc, 0);
    assert!(delay_armed(cw));
}

#[test]
fn cursor_store_keeps_stand() {
    use crate::flow_preempt::CURSOR_STAND_BIT;
    let old = CURSOR_STAND_BIT | 7;
    assert_eq!(cursor_store(2, old), CURSOR_STAND_BIT | 2);
    assert_eq!(cursor_store(2, 0), 2);
    assert_eq!(cursor_store(2, CURSOR_STAND_BIT | 7), CURSOR_STAND_BIT | 2);
    assert_eq!(stand_set(5), CURSOR_STAND_BIT | 5);
    assert!(stand_held(stand_set(5)));
    assert!(!stand_held(stand_clear(stand_set(5))));
    assert_eq!(cursor_val(cursor_store(2, old)), 2);
    assert_eq!(
        steal_next(cursor_val(cursor_store(9, old)), 16),
        steal_next(9, 16)
    );
}

#[test]
fn preempt_bound_gate_needs_all_checks() {
    assert!(preempt_ok(false, true, true, true, true, true));
    assert!(!preempt_ok(true, true, true, true, true, true));
    assert!(!preempt_ok(false, false, true, true, true, true));
    assert!(!preempt_ok(false, true, false, true, true, true));
    assert!(!preempt_ok(false, true, true, false, true, true));
    assert!(!preempt_ok(false, true, true, true, false, true));
    assert!(!preempt_ok(false, true, true, true, true, false));
    assert!(!preempt_ok(true, false, false, false, false, false));
    assert!(!preempt_ok(false, empty_ok(2), true, true, true, true));
    assert!(preempt_ok(false, empty_ok(1), true, true, true, true));
    let hog_pass = deserved_or_hog(false, true);
    assert!(hog_pass);
    assert!(preempt_ok(false, true, hog_pass, true, true, true));
    let hog_fail = deserved_or_hog(false, false);
    assert!(!hog_fail);
    assert!(!preempt_ok(false, true, hog_fail, true, true, true));
    assert!(delay_armed(16));
    assert!(!delay_armed(15));
    assert!(preempt_ok(false, true, true, true, true, true));
}

#[test]
fn armed_display_only_no_gate() {
    for win in [0u8, 8, 15] {
        assert!(!delay_armed(win));
        assert!(preempt_ok(false, true, true, true, true, true));
    }
    for win in [16u8, 100, 250] {
        assert!(delay_armed(win));
        assert!(preempt_ok(false, true, true, true, true, true));
        assert!(!preempt_ok(false, true, false, true, true, true));
        assert!(!preempt_ok(false, false, true, true, true, true));
    }
    assert!(delay_armed_latched(14, true));
    assert!(!delay_armed(14));
    assert!(preempt_ok(false, true, true, true, true, true));
}

#[test]
fn facade_matches_preempt_helpers() {
    assert_eq!(
        crate::flow::DELAY_UNIT_NS,
        crate::flow_preempt::DELAY_UNIT_NS
    );
    assert_eq!(crate::flow::DELAY_MAX, crate::flow_preempt::DELAY_MAX);
    assert_eq!(crate::flow::DELAY_ARM, crate::flow_preempt::DELAY_ARM);
    assert_eq!(crate::flow::DELAY_STAND, crate::flow_preempt::DELAY_STAND);
    assert_eq!(
        crate::flow::CURSOR_STAND_BIT,
        crate::flow_preempt::CURSOR_STAND_BIT
    );
    assert_eq!(
        crate::flow::GRANULE_FLOOR_NS,
        crate::flow_preempt::GRANULE_FLOOR_NS
    );
    assert_eq!(
        crate::flow::delay_from_queued(2),
        crate::flow_preempt::delay_from_queued(2)
    );
    assert_eq!(
        crate::flow::granule_for_weight(1024, 1_000_000),
        crate::flow_preempt::granule_for_weight(1024, 1_000_000)
    );
    assert_eq!(
        crate::flow::delay_armed_latched(14, true),
        crate::flow_preempt::delay_armed_latched(14, true)
    );
    assert_eq!(
        crate::flow::stand_held(0x400),
        crate::flow_preempt::stand_held(0x400)
    );
}

/*
 * Dual max is idempotent with bounded loss. Commutes, assoc, and idem, racy
 * keeps old to true max. Count stays running only, decay stays intact.
 */
#[test]
fn delay_max_concurrent_keeps_bound() {
    for (a, b) in [(0u8, 0u8), (10, 62), (62, 100), (100, 62), (250, 250)] {
        assert_eq!(delay_max(a, b), delay_max(b, a));
        assert_eq!(delay_max(a, a), delay_max(a, a));
    }
    assert_eq!(delay_max(10, 10), 10);
    assert_eq!(delay_max(250, 255), 250);
    for (a, b, c) in [(10u8, 62u8, 100u8), (0, 31, 62), (62, 62, 62)] {
        assert_eq!(delay_max(delay_max(a, b), c), delay_max(a, delay_max(b, c)));
    }
    let old = 10u8;
    let s1 = 62u8;
    let s2 = 100u8;
    let seq = delay_max(delay_max(old, s1), s2);
    assert_eq!(seq, 100);
    let r1 = delay_max(old, s1);
    let r2 = delay_max(old, s2);
    assert_eq!(r1, 62);
    assert_eq!(r2, 100);
    for r in [r1, r2] {
        assert!(r >= old);
        assert!(r <= seq);
    }
    assert_eq!(r1.max(r2), seq);
    assert!(delay_close(100, 0) >= delay_close(62, 0));
    assert_eq!(delay_close(62, 0), 55);
}

/*
 * Cursor store keeps the stand flag, so CAS avoids
 * the stale overwrite. Sequential model matches BPF
 * CAS with no race, timing only, see dispatch.
 */
#[test]
fn cursor_cas_keeps_fresh_flags() {
    use crate::flow_preempt::CURSOR_STAND_BIT;
    let old = 7u32;
    let fresh = CURSOR_STAND_BIT | 7;
    let peer = 2u32;
    let stale = cursor_store(peer, old);
    let kept = cursor_store(peer, fresh);
    assert_eq!(stale, 2);
    assert_eq!(kept, CURSOR_STAND_BIT | 2);
    assert!(stand_held(kept));
    assert!(!stand_held(stale));
    assert_eq!(cursor_store(peer, old), cursor_store(peer, old));
    assert_eq!(cursor_val(kept), peer);
}

/*
 * Split reasons follow bound order pinned, empty,
 * deserved or hog, same, mask, and rate. First fail
 * wins, rate last as the window check. Pinned plus
 * empty count total only at 272B with no reason, so
 * total covers reasons plus total only. Deserved is
 * 2, group is 3, mask is 4, rate is 5 with armed 1
 * retired frozen.
 */
#[test]
fn skip_reason_follows_branch_order() {
    assert_eq!(skip_reason(false, true, true, true, true, true), None);
    assert_eq!(skip_reason(true, true, true, true, true, true), Some(6));
    assert_eq!(skip_reason(false, false, true, true, true, true), Some(6));
    assert_eq!(skip_reason(false, true, false, true, true, true), Some(2));
    assert_eq!(skip_reason(false, true, true, false, true, true), Some(3));
    assert_eq!(skip_reason(false, true, true, true, false, true), Some(4));
    assert_eq!(skip_reason(false, true, true, true, true, false), Some(5));
    assert_eq!(
        skip_reason(true, false, false, false, false, false),
        Some(6)
    );
    assert_eq!(
        skip_reason(false, false, false, false, false, false),
        Some(6)
    );
    assert_eq!(
        skip_reason(false, true, false, false, false, false),
        Some(2)
    );
    assert_eq!(skip_reason(false, true, true, false, false, false), Some(3));
    assert_eq!(skip_reason(false, true, true, true, false, false), Some(4));
    assert_eq!(skip_reason_name(0), "kick");
    assert_eq!(skip_reason_name(1), "armed");
    assert_eq!(skip_reason_name(2), "deserved");
    assert_eq!(skip_reason_name(3), "group");
    assert_eq!(skip_reason_name(4), "mask");
    assert_eq!(skip_reason_name(5), "rate");
    assert_eq!(skip_reason_name(6), "total-only");
}

/*
 * Skip reason matches the bound gate check. None means
 * all pass with kick, some means first fail wins in
 * pinned, empty, deserved or hog, same, mask, and
 * rate order at 272B.
 */
#[test]
fn skip_reason_matches_preempt_ok() {
    for bits in 0..64u8 {
        let pinned = bits & 1 != 0;
        let empty = bits & 2 != 0;
        let hog = bits & 4 != 0;
        let same = bits & 8 != 0;
        let mask = bits & 16 != 0;
        let rate_ok = bits & 32 != 0;
        let ok = preempt_ok(pinned, empty, hog, same, mask, rate_ok);
        let reason = skip_reason(pinned, empty, hog, same, mask, rate_ok);
        assert_eq!(reason.is_none(), ok);
        if !ok {
            assert!(reason.is_some());
        }
    }
    assert!(preempt_ok(false, true, true, true, true, true));
    assert_eq!(skip_reason(false, true, true, true, true, true), None);
    assert_eq!(skip_reason(false, true, false, true, true, true), Some(2));
    assert_eq!(skip_reason(false, true, true, false, true, true), Some(3));
    assert_eq!(skip_reason(false, true, true, true, false, true), Some(4));
    assert_eq!(skip_reason(false, true, true, true, true, false), Some(5));
    assert_eq!(skip_reason(true, true, true, true, true, true), Some(6));
    assert_eq!(skip_reason(false, false, true, true, true, true), Some(6));
}

/*
 * Deep queues stay quiet past one queued with no
 * storm. Delay dots stay display only with no gate,
 * so armed never gates. Rate holds one kick per
 * slice in the bound gate order.
 */
#[test]
fn storm_line_needs_two_queued() {
    assert_eq!(delay_from_queued(1), 31);
    assert_eq!(delay_from_queued(2), 62);
    assert!(delay_armed(62));
    assert!(delay_armed(16));
    assert!(!delay_armed(15));
    assert!(empty_ok(1));
    assert!(!empty_ok(2));
    assert_eq!(skip_reason(false, false, true, true, true, true), Some(6));
    assert_eq!(skip_reason(false, true, true, true, true, false), Some(5));
    assert!(preempt_ok(false, true, true, true, true, true));
}

/*
 * S1 perf bypasses the group gate with no recount. Strict keeps the live check,
 * so cross group fails with reason 3. Perf forces same true before the branch
 * checks, so the same cross group wake kicks with no group count. Other gates
 * stay live, so pinned plus empty total only and deserved or hog, mask, and
 * rate still fail in perf with the same bound order. Armed stays display only
 * with no gate use. Mirrors the BPF if flow_perf_enabled same true in enqueue.
 */
#[test]
fn same_override_bypasses_group_without_recount() {
    assert!(!same_override(false, false));
    assert!(same_override(true, false));
    assert!(same_override(false, true));
    assert!(same_override(true, true));
    assert_eq!(skip_reason(false, true, true, false, true, true), Some(3));
    assert!(!preempt_ok(false, true, true, false, true, true));
    let eff = same_override(false, true);
    assert!(eff);
    assert_eq!(skip_reason(false, true, true, eff, true, true), None);
    assert!(preempt_ok(false, true, true, eff, true, true));
    assert_ne!(skip_reason(false, true, true, eff, true, true), Some(3));
    assert_eq!(skip_reason(true, true, true, eff, true, true), Some(6));
    assert_eq!(skip_reason(false, false, true, eff, true, true), Some(6));
    assert_eq!(skip_reason(false, true, false, eff, true, true), Some(2));
    assert_eq!(skip_reason(false, true, true, eff, false, true), Some(4));
    assert_eq!(skip_reason(false, true, true, eff, true, false), Some(5));
    assert!(!preempt_ok(true, true, true, eff, true, true));
    assert!(!preempt_ok(false, false, true, eff, true, true));
    assert!(!preempt_ok(false, true, false, eff, true, true));
    assert!(!preempt_ok(false, true, true, eff, false, true));
    assert!(!preempt_ok(false, true, true, eff, true, false));
    let strict = same_override(false, false);
    assert!(!strict);
    assert_eq!(skip_reason(false, true, true, strict, true, true), Some(3));
}

/*
 * Empty first holds at most one queued task. Zero and
 * one pass, two and more fail, so deep queues stay
 * quiet with no storm. Mirrors the BPF empty check
 * with no wrap and no new constant.
 */
#[test]
fn empty_first_bounds_shallow_only() {
    assert!(empty_ok(0));
    assert!(empty_ok(1));
    assert!(!empty_ok(2));
    assert!(!empty_ok(3));
    assert!(!empty_ok(8));
    assert!(!empty_ok(100));
    assert!(!empty_ok(u64::MAX));
    assert_eq!(empty_ok(0), true);
    assert_eq!(empty_ok(1), true);
    assert_eq!(empty_ok(2), false);
}

/*
 * Deserved edge holds minus one only with exact bound
 * fail. Bound is frontier plus granule plus slack, so
 * minus one passes and bound plus one fails with wrap
 * safety intact. Uses the floor granule for cover.
 */
#[test]
fn deserved_edge_holds_minus_one_only() {
    let frontier = 50_000_000u64;
    let gran = GRANULE_FLOOR_NS;
    assert_eq!(gran, 64_000);
    let bound = frontier.wrapping_add(gran).wrapping_add(DESERVED_SLACK_NS);
    assert_eq!(bound, frontier + 96_000);
    assert!(deserved(bound.wrapping_sub(1), frontier, gran));
    assert!(!deserved(bound, frontier, gran));
    assert!(!deserved(bound.wrapping_add(1), frontier, gran));
    assert!(deserved(frontier, frontier, gran));
    assert!(!deserved(frontier + 1_000_000, frontier, gran));
}

/*
 * Hog OR needs no time cap past empty first. False
 * plus false fails, all other pairs pass, so hog
 * occupants preempt even when far past the deserved
 * bound with no extra check. Minimal OR only.
 */
#[test]
fn hog_or_truth_needs_no_time_cap() {
    assert!(!deserved_or_hog(false, false));
    assert!(deserved_or_hog(false, true));
    assert!(deserved_or_hog(true, false));
    assert!(deserved_or_hog(true, true));
    let frontier = 50_000_000u64;
    let gran = GRANULE_FLOOR_NS;
    let far = frontier + gran + DESERVED_SLACK_NS + 1_000_000;
    assert!(!deserved(far, frontier, gran));
    assert!(deserved_or_hog(false, true));
    assert!(!deserved_or_hog(false, false));
    let near = frontier;
    assert!(deserved(near, frontier, gran));
    assert!(deserved_or_hog(true, false));
}

/*
 * Skip reason holds bound gate order stable with total
 * only intact. None means all pass with kick, some means
 * first fail wins in pinned, empty, deserved or hog,
 * same, mask, and rate order at 272B. Deserved stays
 * 2, group stays 3, mask stays 4, rate stays 5 with
 * armed 1 retired frozen and total only 6 for pinned
 * plus deep. Empty boundary plus hog OR stay live with
 * no armed gate.
 */
#[test]
fn skip_reason_holds_bound_gate_stable() {
    assert_eq!(skip_reason(false, true, true, true, true, true), None);
    assert!(preempt_ok(false, true, true, true, true, true));
    assert_eq!(skip_reason(true, true, true, true, true, true), Some(6));
    assert_eq!(skip_reason(false, false, true, true, true, true), Some(6));
    assert_eq!(skip_reason(false, true, false, true, true, true), Some(2));
    assert_eq!(skip_reason(false, true, true, false, true, true), Some(3));
    assert_eq!(skip_reason(false, true, true, true, false, true), Some(4));
    assert_eq!(skip_reason(false, true, true, true, true, false), Some(5));
    assert!(!preempt_ok(true, true, true, true, true, true));
    assert!(!preempt_ok(false, false, true, true, true, true));
    assert!(!preempt_ok(false, true, false, true, true, true));
    assert!(!preempt_ok(false, true, true, false, true, true));
    assert!(!preempt_ok(false, true, true, true, false, true));
    assert!(!preempt_ok(false, true, true, true, true, false));
    assert!(empty_ok(1));
    assert!(!empty_ok(2));
    assert!(deserved_or_hog(true, false));
    assert!(deserved_or_hog(false, true));
    assert!(!deserved_or_hog(false, false));
    assert_eq!(skip_reason_name(0), "kick");
    assert_eq!(skip_reason_name(1), "armed");
    assert_eq!(skip_reason_name(2), "deserved");
    assert_eq!(skip_reason_name(5), "rate");
    assert_eq!(skip_reason_name(6), "total-only");
}
