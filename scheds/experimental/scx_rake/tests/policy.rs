// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Piotr Gorski <lucjan.lucjanov@gmail.com>

//! The policy's arithmetic, bpf/src/policy.rs, checked on the host against
//! the definitions scx_cake documents and the tables it carries.

#[path = "../bpf/src/policy.rs"]
#[allow(dead_code)]
mod policy;

use policy::*;

/// scx_cake's recip_weight[]: (1024 << 20) / sched_prio_to_weight[i] for
/// nice -20 to 19, and SCHED_IDLE's weight 3 at index 40.
const CAKE_RECIP: [u64; 41] = [
    12097, 14964, 19009, 23204, 29587, 36830, 46174, 57404, 71827, 90109, 112457, 140911, 176023,
    218952, 274895, 344037, 429324, 539297, 677012, 840831, 1048576, 1309441, 1639300, 2041334,
    2538396, 3205199, 3947580, 4994148, 6242685, 7837531, 9761289, 12341860, 15339168, 19173961,
    23860929, 29826161, 37025580, 46684427, 59652323, 71582788, 357913941,
];

/// The kernel's sched_prio_to_weight[] and WEIGHT_IDLEPRIO.
const WEIGHTS: [u64; 41] = [
    88761, 71755, 56483, 46273, 36291, 29154, 23254, 18705, 14949, 11916, 9548, 7620, 6100, 4904,
    3906, 3121, 2501, 1991, 1586, 1277, 1024, 820, 655, 526, 423, 335, 272, 215, 172, 137, 110, 87,
    70, 56, 45, 36, 29, 23, 18, 15, 3,
];

/// A small deterministic generator, so that the sweeps need no crate.
struct Lcg(u64);

impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0 ^ (self.0 >> 29)
    }
}

/// The adaptive slice as DESIGN.md states it, with two divisions, in
/// arithmetic wide enough not to wrap.
fn slice_reference(runtime: u64, age: u64, n: u64) -> u64 {
    let (runtime, age, n) = (u128::from(runtime), u128::from(age), u128::from(n));
    let a = 2 * (runtime / n);
    let b = age / (2 * n);
    a.min(b).min(1_500_000).max(1464) as u64
}

#[test]
fn reciprocals_match_cake_table() {
    for (weight, expected) in WEIGHTS.iter().zip(CAKE_RECIP) {
        assert_eq!(reciprocal(*weight), expected, "weight {weight}");
    }
    assert_eq!(reciprocal(0), 1 << RECIP_SHIFT);
    assert_eq!(MAX_RECIP_WEIGHT, reciprocal(3));
}

#[test]
fn slice_matches_design_formula_on_a_grid() {
    let values = [
        0u64,
        1,
        2,
        3,
        7,
        1463,
        1464,
        1465,
        2928,
        5000,
        64_000,
        999_999,
        1_000_000,
        1_500_000,
        2_999_999,
        3_000_000,
        3_000_001,
        12_000_000,
        1 << 32,
        1 << 40,
    ];
    for &runtime in &values {
        for &age in &values {
            for nvcsw in [0u64, 1, 2, 3, 4, 10, 100, 1000, 1 << 20] {
                let n = switches(nvcsw);
                let (slice, _) = slice_from_service(runtime, age, n);
                assert_eq!(
                    slice,
                    slice_reference(runtime, age, n),
                    "runtime {runtime} age {age} n {n}"
                );
            }
        }
    }
}

#[test]
fn slice_matches_design_formula_at_random() {
    let mut rng = Lcg(0x5eed);
    for _ in 0..200_000 {
        let runtime = rng.next() >> (rng.next() % 64);
        let age = rng.next() >> (rng.next() % 64);
        let n = switches(rng.next() >> (rng.next() % 64));
        assert_eq!(
            slice_from_service(runtime, age, n).0,
            slice_reference(runtime, age, n),
            "runtime {runtime} age {age} n {n}"
        );
    }
}

#[test]
fn quotient_is_mean_burst_when_runtime_term_wins() {
    let (_, q) = slice_from_service(10_000, 1_000_000_000, 9);
    assert_eq!(q, 10_000 / 9);
}

#[test]
fn task_slice_floor_cap_and_young_tasks() {
    // Nothing run yet: the handoff floor.
    assert_eq!(task_slice(0, 0, 0), HANDOFF_MAX_NS);
    // A long compute task: the cap, half the fixed slice.
    assert_eq!(task_slice(1 << 40, 1 << 41, 0), SLICE_NS >> 1);
    // A task younger than a slice is priced as a slice old.
    assert_eq!(task_slice(1 << 30, 10, 0), task_slice(1 << 30, SLICE_NS, 0));
}

#[test]
fn stage_and_subhandoff_boundaries() {
    assert!(stage(SEAT_BURST_MIN_NS, 1));
    assert!(!stage(SEAT_BURST_MIN_NS - 1, 1));
    // nvcsw 2 counts as 3 switches.
    assert!(stage(3 * SEAT_BURST_MIN_NS, 2));
    assert!(!stage(3 * SEAT_BURST_MIN_NS - 1, 2));
    assert!(!stage(u64::MAX, u64::MAX));

    assert!(subhandoff(HANDOFF_MAX_NS - 1, 0));
    assert!(!subhandoff(HANDOFF_MAX_NS, 0));
    assert!(!subhandoff(0, 1 << 32));
}

#[test]
fn starvation_compares_mean_wait_with_mean_burst() {
    let unit = 1u64 << RATIO_SHIFT;
    // Waits 2 units per run, runs 1 unit per switch.
    assert!(starved(10 * unit, 9, 20 * unit, 9, false));
    // Twice its burst is not more than twice its burst.
    assert!(!starved(10 * unit, 9, 20 * unit, 9, true));
    assert!(starved(10 * unit, 9, 21 * unit, 9, true));
    // No runtime yet: never starved.
    assert!(!starved(unit - 1, 0, u64::MAX, 0, false));
}

#[test]
fn continuation_key_clamps_sleepers_to_one_slice() {
    let frontier = 100 * SLICE_NS;
    assert_eq!(continuation_key(frontier, 0), frontier - SLICE_NS);
    assert_eq!(continuation_key(frontier, frontier + 5), frontier + 5);
    // Across the wrap of the virtual clock.
    let frontier = 10;
    assert_eq!(
        continuation_key(frontier, frontier.wrapping_sub(5)),
        frontier.wrapping_sub(5)
    );
    assert_eq!(
        continuation_key(frontier, frontier.wrapping_sub(2 * SLICE_NS)),
        frontier.wrapping_sub(SLICE_NS)
    );
}

#[test]
fn starved_sleepers_come_back_deeper() {
    let frontier = 1000 * SLICE_NS;
    let age = 1 << 34;
    let (slice, plain) = admit(4 * SLICE_NS, age, 1000, false, frontier, 0);
    let (_, deep) = admit(4 * SLICE_NS, age, 1000, true, frontier, 0);
    assert_eq!(plain, frontier - SLICE_NS);
    // A mean burst of 12 us leaves most of the slice unused.
    let burst = 4 * SLICE_NS / 1001;
    assert_eq!(deep, frontier - SLICE_NS - sleeper_dose(SLICE_NS - burst));
    assert_eq!(slice, task_slice(4 * SLICE_NS, age, 1000));
    // A task ahead of the floor keeps its own key either way.
    let (_, ahead) = admit(4 * SLICE_NS, age, 1000, true, frontier, frontier + 7);
    assert_eq!(ahead, frontier + 7);
}

#[test]
fn scaled_vtime_is_exact() {
    let mut rng = Lcg(42);
    for _ in 0..100_000 {
        let base = rng.next();
        let runtime = rng.next() >> (rng.next() % 64);
        let recip = CAKE_RECIP[(rng.next() % 41) as usize];
        let exact = (u128::from(runtime) * u128::from(recip)) >> RECIP_SHIFT;
        let got = scale_vtime_add(base, runtime, recip).wrapping_sub(base);
        // The split product drops at most the carry of the low half.
        let diff = (exact as u64).wrapping_sub(got);
        assert!(
            diff <= 1,
            "runtime {runtime} recip {recip}: {got} vs {exact}"
        );
    }
    assert_eq!(scale_vtime_add(5, 1000, 1 << RECIP_SHIFT), 1005);
}

#[test]
fn handoff_paths_agree() {
    let mut rng = Lcg(7);
    for _ in 0..100_000 {
        let ran = rng.next() >> (rng.next() % 64);
        let runtime = rng.next() >> (rng.next() % 64);
        let nvcsw = rng.next() >> (rng.next() % 64);
        let n = u128::from(switches(nvcsw));
        let limit = u128::from(ran) + u128::from(HANDOFF_MAX_NS);
        let got = handoff_yields(ran, runtime, nvcsw);
        if (limit | n) >> 32 == 0 {
            assert_eq!(got, u128::from(runtime) < limit * n);
        } else {
            let burst = u128::from(runtime) / n;
            assert_eq!(
                got,
                burst <= u128::from(ran) || burst - u128::from(ran) < 1464
            );
        }
    }
}

#[test]
fn pinned_wakeups_preempt_by_sleep_depth() {
    let frontier = 100 * SLICE_NS;
    let floor = frontier - SLICE_NS;
    // A deep sleeper is keyed two slices behind the frontier.
    let depth = 0u64.wrapping_sub(10 * SLICE_NS);
    assert!(pinned_preempts(frontier, depth, 1464, floor));
    assert!(!pinned_preempts(frontier, depth, 1464, 0));
    // A task a slice ahead of the floor is keyed at the floor.
    assert!(!pinned_preempts(frontier, SLICE_NS, SLICE_NS, floor));
}

#[test]
fn hint_counts_quick_handoffs_and_saturates() {
    let mut hint = 0;
    for expected in [1, 2, 3, 3] {
        hint = hint_after(hint | HINT_WOKE, false, 10);
        assert_eq!(hint >> HINT_CONF_SHIFT, expected);
    }
    assert!(hint_serial(hint));
    // A preemption keeps the count, a slow block clears it.
    assert_eq!(hint_after(hint, true, 1 << 30), hint);
    assert_eq!(hint_after(hint | HINT_WOKE, false, HANDOFF_MAX_NS), 0);
    // A block without a wake clears it too.
    assert_eq!(hint_after(hint, false, 1), 0);
}

#[test]
fn time_helpers_wrap() {
    assert!(time_before(u64::MAX, 0));
    assert!(!time_before(0, u64::MAX));
    assert_eq!(time_delta(5, u64::MAX), 6);
    assert_eq!(time_delta(5, 6), 0);
    assert_eq!(grant_left(10, 3), 0);
    assert_eq!(grant_left(3, 10), 7);
    assert!(system_serial(3, 4));
    assert!(!system_serial(2, 4));
    assert_eq!(
        wake_protect(PREEMPT_PROTECT_SHIFT, 1_000_000),
        SLICE_NS >> 4
    );
    assert_eq!(wake_protect(PREEMPT_PROTECT_SHIFT, 2000), 2000);
}

/// An LLC's CIDs as the census sees them, driven by ops.update_idle()
/// reports, against a scan of the runtime's idle bits.
struct Llc {
    /// ops.update_idle()'s last report per CID: the census's flag.
    idle: Vec<bool>,
    /// The runtime's idle bit per CID, which a claim clears at once.
    claimable: Vec<bool>,
    count: u64,
}

impl Llc {
    /// The LLC as init() seeds it: every idle CID counted once.
    fn seeded(idle: &[bool]) -> Llc {
        Llc {
            idle: idle.to_vec(),
            claimable: idle.to_vec(),
            count: idle.iter().filter(|idle| **idle).count() as u64,
        }
    }

    fn report(&mut self, cid: usize, idle: bool) {
        let delta = census_delta(self.idle[cid], idle);
        self.idle[cid] = idle;
        self.claimable[cid] = idle;
        self.count = self.count.wrapping_add(delta);
    }

    /// A wakeup claims an idle CID: the runtime's bit goes, the census
    /// waits for the CID to leave idle.
    fn claim(&mut self, cid: usize) {
        self.claimable[cid] = false;
    }

    fn scan(&self) -> u64 {
        self.claimable.iter().filter(|bit| **bit).count() as u64
    }

    fn claimed(&self) -> u64 {
        self.idle
            .iter()
            .zip(&self.claimable)
            .filter(|(idle, bit)| **idle && !**bit)
            .count() as u64
    }
}

#[test]
fn census_follows_reports_including_repeated_ones() {
    let mut rng = Lcg(0xce45);
    for _ in 0..2000 {
        let size = 1 + (rng.next() % 16) as usize;
        let seed: Vec<bool> = (0..size).map(|_| rng.next() & 1 == 0).collect();
        let mut llc = Llc::seeded(&seed);
        for _ in 0..200 {
            let cid = (rng.next() % size as u64) as usize;
            match rng.next() % 3 {
                0 => llc.report(cid, true),
                1 => llc.report(cid, false),
                _ => {
                    if llc.claimable[cid] {
                        llc.claim(cid)
                    }
                }
            }
            let idle = llc.idle.iter().filter(|idle| **idle).count() as u64;
            assert_eq!(llc.count, idle);
            assert!(census_serial(llc.count, size as u32).is_some());
            // The only difference from a scan: claimed CIDs not yet out of
            // idle.
            assert_eq!(llc.count - llc.scan(), llc.claimed());
        }
    }
}

#[test]
fn a_broken_census_is_reported_not_read_as_idle() {
    // A decrement at zero wraps: past the size, never "all idle".
    assert_eq!(
        census_serial(0u64.wrapping_add(census_delta(true, false)), 8),
        None
    );
    assert_eq!(census_serial(9, 8), None);
    assert_eq!(census_serial(8, 8), Some(true));
    assert_eq!(census_serial(6, 8), Some(true));
    assert_eq!(census_serial(5, 8), Some(false));
}

#[test]
fn claims_make_the_census_read_serial_before_a_scan_would() {
    // Six of eight idle: serial. Two wakeups claim two of them: a scan
    // sees four, not serial, while the census still sees six.
    let mut llc = Llc::seeded(&[true, true, true, true, true, true, false, false]);
    llc.claim(0);
    llc.claim(1);
    assert_eq!(census_serial(llc.count, 8), Some(true));
    assert!(!system_serial(llc.scan() as u32, 8));
    // Once the claimed CIDs run, the two agree again.
    llc.report(0, false);
    llc.report(1, false);
    assert_eq!(llc.count, llc.scan());
}
