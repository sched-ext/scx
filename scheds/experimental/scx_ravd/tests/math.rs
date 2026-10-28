// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Piotr Gorski <lucjan.lucjanov@gmail.com>

//! LAVD's arithmetic, bpf/src/math.rs, built for the host. The expected
//! values are worked out by hand from scx_lavd's C.

#[path = "../bpf/src/lavd.rs"]
#[allow(dead_code)]
mod lavd;

#[path = "../bpf/src/math.rs"]
#[allow(dead_code)]
mod math;

use lavd::*;
use math::*;

#[test]
fn constants_match_lavd() {
    assert_eq!(LAVD_DL_COMPETE_WINDOW, 4577);
    assert_eq!(LAVD_SLICE_BOOST_UTIL_WALL, 972);
    assert_eq!(LAVD_CPU_UTIL_MAX_FOR_CPUPERF, 870);
    assert_eq!(LAVD_SYS_STAT_DECAY_TIMES, 200);
    assert_eq!(LAVD_CPDOM_MIG_PROB_FT, 2);
}

#[test]
fn moving_averages() {
    // 0.875 * 800 + 0.125 * 1600.
    assert_eq!(calc_avg(800, 1600), 900);
    // Below 2^decay the average moves by halves, and 1 decays to 0.
    assert_eq!(calc_avg(4, 6), 5);
    assert_eq!(calc_avg(1, 0), 0);
    // Rising takes a quarter of the step at once, falling an eighth.
    assert_eq!(calc_asym_avg(100, 900), 700);
    assert_eq!(calc_asym_avg(900, 100), 800);
}

#[test]
fn frequency_per_second() {
    // A first interval of 1 ms is 1000 per second, halved in.
    assert_eq!(calc_avg_freq(0, 1_000_000), 500);
    // No interval is no frequency.
    assert_eq!(calc_avg_freq(0, 0), 0);
    // A steady 1 kHz stays.
    assert_eq!(calc_avg_freq(1000, 1_000_000), 1000);
}

#[test]
fn logarithm_is_log2_u64() {
    assert_eq!(log2x(0), 1);
    assert_eq!(log2x(1), 1);
    assert_eq!(log2x(2), 2);
    assert_eq!(log2x(3), 2);
    assert_eq!(log2x(4), 3);
    assert_eq!(log2x(101), 7);
    assert_eq!(log2x(1 << 32), 33);
    assert_eq!(log2x(u64::MAX), 64);
}

#[test]
fn sched_ext_weight() {
    assert_eq!(scx_weight_of(1024), 100);
    assert_eq!(scx_weight_of(88761), 8668);
    assert_eq!(scx_weight_of(15), 1);
}

#[test]
fn latency_criticality() {
    // No waits, no wakes, a long runtime and nice 0 with no boost:
    // (log2x(1) + log2x(1 * 101))^2 = (1 + 7)^2.
    assert_eq!(lat_cri_of(1, 1, 1, 101, 0), (64, 1));
    // A giver well above twice the task's own hands over 1/8 of the
    // excess, capped at a quarter of the task's own.
    assert_eq!(lat_cri_of(1, 1, 1, 101, 1000).0, 80);
    assert_eq!(lat_cri_of(1, 1, 1, 101, 200).0, 64 + ((200 - 128) >> 3));
    // A chained task that waits and wakes 1000 times a second and runs
    // briefly is far more critical.
    let (chained, _) = lat_cri_of(1001, 1001, reverse_runtime_factor(100_000), 101, 0);
    assert!(chained > 64 * 4, "{chained}");
}

#[test]
fn reverse_runtime() {
    assert_eq!(reverse_runtime_factor(LAVD_LC_RUNTIME_MAX), 1);
    assert_eq!(
        reverse_runtime_factor(0),
        LAVD_LC_RUNTIME_MAX / LAVD_SLICE_MIN_NS_DFL + 1
    );
}

#[test]
fn greedy_penalty_spans_one_to_two() {
    let lag_max = 1_000_000;
    // Exactly its share: 150%.
    let fair = greedy_penalty(5_000_000, 5_000_000, lag_max);
    assert_eq!((fair.penalty, fair.greedy), (1536, false));
    // Owed the most: no penalty.
    let owed = greedy_penalty(5_000_000, 4_000_000, lag_max);
    assert_eq!((owed.penalty, owed.greedy), (1024, false));
    // A long sleeper is brought up to lag_max behind the average.
    let sleeper = greedy_penalty(5_000_000, 1_000_000, lag_max);
    assert_eq!(sleeper.penalty, 1024);
    assert_eq!(sleeper.svc_time_iwgt, 4_000_000);
    // Ahead by lag_max or more: twice the deadline.
    let greedy = greedy_penalty(5_000_000, 9_000_000, lag_max);
    assert_eq!((greedy.penalty, greedy.greedy), (2048, true));
    assert_eq!(greedy.svc_time_iwgt, 9_000_000);
}

#[test]
fn virtual_deadline() {
    // (5 ms + 0) * 1536 / 64 >> 10.
    assert_eq!(deadline_delta(0, 1536, 64), 117_187);
    // A task that ran its whole bound since waking gets twice as far.
    assert_eq!(deadline_delta(10_000_000, 1536, 64), 234_375);
    // More criticality, a nearer deadline.
    assert!(deadline_delta(0, 1536, 1024) < deadline_delta(0, 1536, 64));
}

#[test]
fn compete_window_shrinks_when_oversubscribed() {
    assert_eq!(compete_window(4, 8), LAVD_DL_COMPETE_WINDOW);
    assert_eq!(compete_window(16, 8), LAVD_DL_COMPETE_WINDOW / 2);
}

#[test]
fn logical_clock_moves_forward_only() {
    assert_eq!(advance_clock(100, 200, 4), 125);
    assert_eq!(advance_clock(100, 200, 0), 200);
    assert_eq!(advance_clock(200, 100, 1), 200);
    // Across the wrap, by the signed difference.
    assert_eq!(advance_clock(u64::MAX - 9, 10, 1), 10);
}

#[test]
fn time_slice_fits_the_targeted_latency() {
    let (min, max) = (500_000, 5_000_000);
    assert_eq!(sys_time_slice(0, 8, min, max), max);
    assert_eq!(sys_time_slice(16, 8, min, max), 5_000_000);
    assert_eq!(sys_time_slice(32, 8, min, max), 2_500_000);
    assert_eq!(sys_time_slice(1000, 8, min, max), min);
}

#[test]
fn thresholds() {
    assert_eq!(thr_lat_cri(1000, 200, 6), 988);
    assert_eq!(thr_lat_cri(1000, 200, 0), 200);
    // Big cores with no capacity, all of it, a half and three quarters.
    assert_eq!(thr_perf_cri(0, 10, 20, 40), 40);
    assert_eq!(thr_perf_cri(1024, 10, 20, 40), 0);
    assert_eq!(thr_perf_cri(512, 10, 20, 40), 20);
    assert_eq!(thr_perf_cri(768, 10, 20, 40), 15);
}
