// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.

/// The runtime's nice-0 weight, which accounting.rs takes from crate::task.
mod task {
    pub const NICE_0_WEIGHT: u64 = 1024;
}

#[path = "../bpf/src/accounting.rs"]
mod accounting;

use accounting::{
    ForkGroup, GROUP_MIN_SHARES, GROUP_WEIGHT_SHIFT, MIN_DL_WEIGHT, NEWIDLE_DECAY_NS,
    NICE_0_WEIGHT, Request, UTIL_HALF_LIFE_NS, advance, avg_idle_update, cgroup_load_weight,
    charge, delay_debt, fork_group_wins, group_shares, join_delta, lag, lag_limit, leave_delta,
    newidle_cost_update, newidle_sample, newidle_stats_fold, place, prop_weight, reference_at,
    reference_before_join, round_weight, runnable_update, task_load, time_before, util_est_update,
    wake_affine_weight, wake_wide,
};

#[test]
fn weighted_deadline() {
    let mut request = Request::default();
    request.prepare(1000, 200, 2048, false);
    assert_eq!(request.deadline, 1100);
    assert_eq!(request.slice, 200);
    assert_eq!(request.weight, 2048);
}

#[test]
fn preemption_preserves_unfinished_request() {
    let mut request = Request::default();
    request.prepare(1000, 200, 1024, false);
    request.prepare(1050, 200, 1024, false);
    assert_eq!(request.deadline, 1200);
}

#[test]
fn completion_and_yield_charge_renew_request() {
    let mut request = Request::default();
    request.prepare(1000, 200, 1024, false);
    request.prepare(1200, 200, 1024, false);
    assert_eq!(request.deadline, 1400);
    request.prepare(1450, 200, 1024, false);
    assert_eq!(request.deadline, 1650);
}

#[test]
fn sleep_discards_remaining_deadline() {
    let mut request = Request::default();
    request.prepare(1000, 200, 1024, false);
    request.sleep();
    request.prepare(1050, 200, 1024, false);
    assert_eq!(request.deadline, 1250);
}

#[test]
fn placement_carries_remaining_request() {
    let mut request = Request::default();
    request.prepare(1000, 200, 1024, false);
    request.rebase(1050, 5000);
    request.prepare(5000, 200, 1024, false);
    assert_eq!(request.deadline, 5150);
    request.rebase(5150, 6000);
    request.prepare(6000, 200, 1024, false);
    assert_eq!(request.deadline, 6200);
}

#[test]
fn reweight_rescales_remaining_service() {
    let mut request = Request::default();
    request.prepare(1000, 200, 1024, false);
    request.prepare(1050, 200, 2048, false);
    assert_eq!(request.deadline, 1125);
    request.prepare(1050, 400, 2048, false);
    assert_eq!(request.deadline, 1250);
}

#[test]
fn wrapped_zero_deadline_remains_valid() {
    let mut request = Request::default();
    request.prepare(u64::MAX - 99, 100, 1024, false);
    assert_eq!(request.deadline, 0);
    request.prepare(u64::MAX - 49, 100, 1024, false);
    assert_eq!(request.deadline, 0);
    request.prepare(0, 100, 1024, false);
    assert_eq!(request.deadline, 100);
}

#[test]
fn zero_weight_is_guarded() {
    let mut request = Request::default();
    request.prepare(0, 200, 0, false);
    assert_eq!(request.deadline, 800);
}

#[test]
fn joins_track_the_weighted_average() {
    let base = u64::MAX - 500;
    let members = [
        (base, 100),
        (base.wrapping_add(900), 300),
        (base.wrapping_add(300), 200),
    ];
    let (mut reference, mut sum) = (0_u64, 0_u64);
    for (vtime, weight) in members {
        reference = reference.wrapping_add(join_delta(reference, sum, vtime, weight));
        sum += weight;
    }
    // (0 * 100 + 900 * 300 + 300 * 200) / 600 = 550
    assert_eq!(reference, base.wrapping_add(550));
    reference = reference.wrapping_add(leave_delta(reference, sum, members[1].0, 300));
    sum -= 300;
    // (0 * 100 + 300 * 200) / 300 = 200
    assert_eq!(reference, base.wrapping_add(200));
    reference = reference.wrapping_add(leave_delta(reference, sum, members[2].0, 200));
    assert_eq!(reference, base);
    assert_eq!(leave_delta(reference, 100, base, 100), 0);
}

#[test]
fn placement_preserves_lag_after_join() {
    for (sum, weight, owed) in [(300, 100, 600), (300, 100, -600), (100, 400, 1000)] {
        let reference = 10_000_u64;
        let vtime = place(reference, sum, owed, weight);
        let joined = reference.wrapping_add(join_delta(reference, sum, vtime, weight));
        assert_eq!(lag(joined, vtime, i64::MAX), owed);
    }
    // The only member of a pack is its average.
    let vtime = place(10_000, 0, 50, 100);
    assert_eq!(
        10_000_u64.wrapping_add(join_delta(10_000, 0, vtime, 100)),
        vtime
    );
}

#[test]
fn lag_is_clamped() {
    let limit = lag_limit(400, NICE_0_WEIGHT);
    assert_eq!(limit, 400);
    assert_eq!(lag_limit(400, 1), 1600);
    assert_eq!(lag(1000, 0, limit), 400);
    assert_eq!(lag(0, 1000, limit), -400);
    assert_eq!(lag(1000, 900, limit), 100);
}

#[test]
fn charge_carries_the_remainder() {
    let (mut reference, mut remainder) = (0, 0);
    for _ in 0..3 {
        let (advance, rest) = charge(1, 1, 3, remainder);
        reference += advance;
        remainder = rest;
    }
    assert_eq!((reference, remainder), (1, 0));
    assert_eq!(charge(200, 30, 600, 0), (10, 0));
}

#[test]
fn projection_matches_a_charge() {
    // A lone runner stays exactly at the reference.
    assert_eq!(
        reference_at(1000, NICE_0_WEIGHT, NICE_0_WEIGHT, 500, 20_000),
        advance(1000, 500, NICE_0_WEIGHT)
    );
    // dV = w * dv / W: a nice 0 task in a pack of three running 600 ns
    // moves V by 200.
    let (one, three) = (NICE_0_WEIGHT, 3 * NICE_0_WEIGHT);
    assert_eq!(reference_at(1000, three, one, 600, 20_000), 1200);
    // Past a whole request, or with nothing running, nothing is projected.
    assert_eq!(reference_at(1000, three, one, 20_000, 20_000), 1000);
    assert_eq!(reference_at(1000, three, 0, 600, 20_000), 1000);
    assert_eq!(advance(1000, 600, three), 1200);
}

#[test]
fn first_request_asks_for_half() {
    let mut request = Request::default();
    assert!(request.prepare(1000, 200, 1024, true));
    assert_eq!(request.deadline, 1100);
    // Unfinished: kept, and not halved again.
    assert!(!request.prepare(1050, 200, 1024, false));
    assert_eq!(request.deadline, 1100);
    assert!(request.prepare(1100, 200, 1024, false));
    assert_eq!(request.deadline, 1300);
}

#[test]
fn deadlines_floor_the_weight() {
    let mut request = Request::default();
    request.prepare(0, 200, 1, false);
    assert_eq!(request.deadline, 200 * NICE_0_WEIGHT / MIN_DL_WEIGHT);
    // A changed request issues a new deadline at once.
    request.prepare(10, 100, 1024, false);
    assert_eq!(request.deadline, 110);
}

#[test]
fn time_before_wraps() {
    assert!(time_before(u64::MAX - 5, 3));
    assert!(!time_before(3, u64::MAX - 5));
    assert!(!time_before(7, 7));
}

#[test]
fn delayed_debt_is_paid_by_the_pack() {
    // A pack of 100 without the task, which weighs 100, moved by 400: the
    // task would have seen half of that.
    assert_eq!(delay_debt(-300, 400, 100, 100), -100);
    // Paid in full and never turned into credit.
    assert_eq!(delay_debt(-300, 1000, 100, 100), 0);
    // A pack that has not moved collects nothing; credit is not a debt.
    assert_eq!(delay_debt(-300, 0, 100, 100), -300);
    assert_eq!(delay_debt(50, 400, 100, 100), 0);
}

#[test]
fn zero_lag_joiner_stays_eligible() {
    // A pack of weight 300 whose running task of weight 100 has run 7 ns
    // uncharged, joined by a task of weight 100 with no lag.
    let (reference, sum, weight, delta, request, join) = (1_000_u64, 300, 100, 7, 1_000, 100);
    let after = |vtime: u64| {
        let joined = reference.wrapping_add(join_delta(reference, sum, vtime, join));
        reference_at(joined, sum + join, weight, delta, request)
    };
    // Placed at the pre-join projection, truncation leaves it ineligible.
    let naive = reference_at(reference, sum, weight, delta, request);
    assert!(time_before(after(naive), naive));
    // Placed as pack_vref_before_join() does, it is not.
    let placed = reference_before_join(reference, sum, weight, delta, request, join);
    assert!(!time_before(after(placed), placed));
}

#[test]
fn util_estimate_rises_at_once_and_falls_slowly() {
    assert_eq!(util_est_update(100, 800), 800);
    assert_eq!(util_est_update(800, 0), 600);
    assert_eq!(util_est_update(600, 200), 500);
}

#[test]
fn runnable_fraction_is_averaged_over_cycles() {
    assert_eq!(runnable_update(0, 1000, 1000), 128);
    assert_eq!(runnable_update(1024, 1000, 500), (1024 * 7 + 512) / 8);
    assert_eq!(runnable_update(300, 0, 10), 300);
    assert_eq!(runnable_update(0, 1000, 5000), 128);
}

#[test]
fn task_load_decays_while_asleep() {
    let half = u64::from(UTIL_HALF_LIFE_NS);
    assert_eq!(task_load(100, 512, 256, 0), 50);
    assert_eq!(task_load(100, 256, 1024, 0), 100);
    assert_eq!(task_load(100, 1024, 0, half), 50);
    assert_eq!(task_load(100, 1024, 0, 100 * half), 0);
}

#[test]
fn wake_wide_needs_both_to_flip_often() {
    assert!(!wake_wide(100, 3, 4));
    assert!(wake_wide(100, 4, 4));
    assert!(!wake_wide(15, 4, 4));
    assert!(wake_wide(4, 16, 4));
}

#[test]
fn wake_affine_weight_balances_the_two_cids() {
    // A heavy waking CID keeps the wakee on its idle-ish previous one.
    assert!(!wake_affine_weight(300, 100, None, 50, false));
    // A light waking CID takes it.
    assert!(wake_affine_weight(100, 300, None, 50, false));
    // WA_BIAS weighs the previous CID's load up: equal loads move to the
    // waking CID, and it takes a margin to stay.
    assert!(wake_affine_weight(200, 200, None, 0, false));
    assert!(!wake_affine_weight(220, 200, None, 0, false));
    // A sync waker about to leave makes its CID lighter by its own load.
    assert!(wake_affine_weight(300, 260, Some(200), 50, false));
    // A sync waker heavier than its whole CID takes the wakee at once.
    assert!(wake_affine_weight(100, 1000, Some(150), 50, false));
}

fn group(idle: u32, load: u64, local: bool) -> ForkGroup {
    ForkGroup {
        nr: 2,
        idle,
        load,
        cap: 2048,
        allowed: 2,
        local,
        ..ForkGroup::default()
    }
}

/// Does `candidate` beat `best` among cores (`core`) or wider groups, for an
/// unrestricted task unless `restricted`?
fn wins(candidate: ForkGroup, best: Option<ForkGroup>, restricted: bool, core: bool) -> bool {
    fork_group_wins(&candidate, best.as_ref(), restricted, core)
}

#[test]
fn fork_groups_order_by_idle_then_load() {
    assert!(wins(group(0, 900, false), None, false, false));
    // More idle CPUs win whatever the load.
    assert!(wins(
        group(2, 900, false),
        Some(group(1, 0, false)),
        false,
        false
    ));
    assert!(!wins(
        group(0, 0, false),
        Some(group(1, 900, false)),
        false,
        false
    ));
    // Equally idle: lower load per capacity wins.
    assert!(wins(
        group(0, 100, false),
        Some(group(0, 200, false)),
        false,
        false
    ));
    assert!(!wins(
        group(0, 300, false),
        Some(group(0, 200, false)),
        false,
        false
    ));
    // A tie keeps the local group.
    assert!(!wins(
        group(0, 200, false),
        Some(group(0, 200, true)),
        false,
        false
    ));
    assert!(wins(
        group(0, 200, true),
        Some(group(0, 200, false)),
        false,
        false
    ));
    // Between cores, the core a fork went to longer ago wins a load tie.
    let recent = ForkGroup {
        recent: 50,
        ..group(0, 200, false)
    };
    let older = ForkGroup {
        recent: 10,
        ..group(0, 200, false)
    };
    assert!(wins(older, Some(recent), false, true));
    assert!(!wins(recent, Some(older), false, true));
    // A group with no CPU allowed never wins.
    let barred = ForkGroup {
        allowed: 0,
        ..group(2, 0, false)
    };
    assert!(!wins(barred, None, true, false));
}

#[test]
fn restricted_forks_prefer_spare_capacity_and_the_local_group() {
    let full = ForkGroup {
        runnable: 2,
        ..group(0, 100, false)
    };
    let spare = ForkGroup {
        runnable: 1,
        ..group(0, 900, false)
    };
    assert!(wins(spare, Some(full), true, false));
    assert!(!wins(full, Some(spare), true, false));
    // Busy groups: the local one is kept within 125% of the other's load.
    let mut local = ForkGroup {
        runnable: 2,
        ..group(0, 120, true)
    };
    let remote = ForkGroup {
        runnable: 2,
        ..group(0, 100, false)
    };
    assert!(!wins(remote, Some(local), true, false));
    local.load = 130;
    assert!(wins(remote, Some(local), true, false));
}

#[test]
fn avg_idle_moves_an_eighth_and_is_capped() {
    assert_eq!(avg_idle_update(800, 1600, 1_000_000), 900);
    assert_eq!(avg_idle_update(800, 0, 1_000_000), 700);
    assert_eq!(avg_idle_update(800, 100_000, 300), 600);
}

#[test]
fn newidle_cost_rises_at_once_and_decays_per_second() {
    assert_eq!(newidle_cost_update(100, 0, 500, 7), (500, 7));
    assert_eq!(newidle_cost_update(256, 0, 10, 5), (256, 0));
    assert_eq!(
        newidle_cost_update(256, 0, 10, NEWIDLE_DECAY_NS + 1),
        (253, NEWIDLE_DECAY_NS + 1)
    );
}

#[test]
fn newidle_sampling_folds_and_weighs() {
    // Below 1024 calls nothing folds.
    assert_eq!(
        newidle_stats_fold(1000, 9, 0, 512, 1 << 30),
        (1000, 9, 0, 512)
    );
    // 100 successes and 2^22 * 10 ns between folds give a ratio of 110.
    assert_eq!(
        newidle_stats_fold(1024, 100, 0, 512, 10 << 22),
        (512, 50, 10 << 22, 110)
    );
    assert_eq!(newidle_stats_fold(2048, 5000, 0, 512, 0).3, 1024);
    // A saturated ratio always scans; otherwise the draw decides, and a
    // success counts with the inverse of the probability.
    assert_eq!(newidle_sample(1024, 1023), Some(1));
    assert_eq!(newidle_sample(511, 100), Some(2));
    assert_eq!(newidle_sample(511, 700), None);
    assert_eq!(newidle_sample(0, 0), Some(1024));
}

#[test]
fn cgroup_weights_follow_the_kernel() {
    assert_eq!(cgroup_load_weight(100), NICE_0_WEIGHT);
    assert_eq!(cgroup_load_weight(1), 10);
    assert_eq!(cgroup_load_weight(10000), 100 * NICE_0_WEIGHT);
}

#[test]
fn hierarchy_weight_is_rounded_once() {
    // A nice 0 task alone in a group that has the default weight keeps it.
    let fixed = NICE_0_WEIGHT << GROUP_WEIGHT_SHIFT;
    assert_eq!(
        round_weight(prop_weight(fixed, NICE_0_WEIGHT, NICE_0_WEIGHT)),
        NICE_0_WEIGHT
    );
    // Three levels of a third each, truncated per level, would lose a unit.
    let mut fixed = 100 << GROUP_WEIGHT_SHIFT;
    for _ in 0..3 {
        fixed = prop_weight(fixed, 1, 3);
    }
    assert_eq!(round_weight(fixed), 4);
    assert_eq!(round_weight(0), 1);
}

#[test]
fn concur_shares_scale_with_the_cids_in_use() {
    let weight = NICE_0_WEIGHT;
    // One task: the group's weight on the CID it runs on.
    assert_eq!(group_shares(weight, 1, 8, 1024, 1024, 1024, 1024), weight);
    // Four CIDs equally loaded with four tasks: the weight on each.
    assert_eq!(group_shares(weight, 4, 8, 1024, 1024, 4096, 1024), weight);
    // More tasks than CIDs count as every CID.
    assert_eq!(group_shares(weight, 64, 8, 1024, 1024, 8192, 1024), weight);
    // More tasks than the cpuset has CPUs count as every one of them.
    assert_eq!(group_shares(weight, 8, 2, 1024, 1024, 2048, 1024), weight);
    // A queue gone quiet keeps the floor.
    assert_eq!(group_shares(weight, 4, 8, 0, 0, 4096, 0), GROUP_MIN_SHARES);
}
