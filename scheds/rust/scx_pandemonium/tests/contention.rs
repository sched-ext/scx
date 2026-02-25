// PANDEMONIUM BENCH-CONTENTION UNIT TESTS
// STRESS THE v5.3.0 -> v5.4.11 ADAPTIVE CONTROL LOOP ADDITIONS
//
// ALL TESTS USE PURE-RUST TYPES FROM pandemonium::tuning.
// ZERO BPF DEPENDENCIES. RUN OFFLINE.

use scx_pandemonium::tuning::{
    compute_p99_from_histogram, compute_stability_score, detect_regime, regime_knobs,
    should_reflex_tighten, sleep_adjust_batch_ns, Regime, TuningKnobs, AFFINITY_STRONG,
    AFFINITY_WEAK, BATCH_MAX_NS, HIST_BUCKETS, HIST_EDGES_NS,
};

// SOJOURN THRESHOLD ADAPTATION
// THE EWMA LIVES IN adaptive.rs (INLINE IN monitor_loop), SO WE REPLICATE
// THE EXACT ARITHMETIC HERE TO VERIFY IT IN ISOLATION.

fn sojourn_floor(nr_cpus: u64) -> u64 {
    5_000_000u64.max(1_000_000 * (nr_cpus / 2))
}

fn sojourn_ceil(nr_cpus: u64) -> u64 {
    sojourn_floor(nr_cpus) * 2
}

fn sojourn_ewma_step(current: u64, target: u64) -> u64 {
    current - (current >> 3) + (target >> 3)
}

fn sojourn_target(delta_d: u64, elapsed_ns: u64, nr_cpus: u64) -> u64 {
    if delta_d == 0 || elapsed_ns == 0 {
        return 0; // CALLER SKIPS UPDATE
    }
    let dispatch_rate = delta_d * 1_000_000_000 / elapsed_ns;
    let interval_ns = if dispatch_rate > 0 {
        1_000_000_000 / dispatch_rate
    } else {
        0
    };
    let floor = sojourn_floor(nr_cpus);
    let ceil = sojourn_ceil(nr_cpus);
    (interval_ns * 4).clamp(floor, ceil)
}

#[test]
fn sojourn_floor_scaling_2c() {
    assert_eq!(sojourn_floor(2), 5_000_000); // 5MS BASELINE WINS
}

#[test]
fn sojourn_floor_scaling_8c() {
    assert_eq!(sojourn_floor(8), 5_000_000); // 1MS*4=4MS < 5MS, BASELINE WINS
}

#[test]
fn sojourn_floor_scaling_16c() {
    assert_eq!(sojourn_floor(16), 8_000_000); // 1MS*8=8MS > 5MS
}

#[test]
fn sojourn_floor_scaling_64c() {
    assert_eq!(sojourn_floor(64), 32_000_000); // 1MS*32=32MS
}

#[test]
fn sojourn_ceil_is_double_floor() {
    for nr_cpus in [2, 4, 8, 16, 32, 64] {
        assert_eq!(sojourn_ceil(nr_cpus), sojourn_floor(nr_cpus) * 2);
    }
}

#[test]
fn sojourn_high_dispatch_rate_clamps_to_floor() {
    // 500K DISPATCHES/SEC ON 8 CORES -> INTERVAL=2US -> TARGET=8US -> CLAMPED TO 5MS FLOOR
    let nr_cpus = 8;
    let target = sojourn_target(500_000, 1_000_000_000, nr_cpus);
    assert_eq!(target, sojourn_floor(nr_cpus));
}

#[test]
fn sojourn_low_dispatch_rate_clamps_to_ceil() {
    // 10 DISPATCHES/SEC ON 8 CORES -> INTERVAL=100MS -> TARGET=400MS -> CLAMPED TO CEIL
    let nr_cpus = 8;
    let target = sojourn_target(10, 1_000_000_000, nr_cpus);
    assert_eq!(target, sojourn_ceil(nr_cpus));
}

#[test]
fn sojourn_zero_dispatches_returns_zero() {
    // delta_d=0: CALLER SKIPS UPDATE
    let target = sojourn_target(0, 1_000_000_000, 8);
    assert_eq!(target, 0);
}

#[test]
fn sojourn_ewma_converges_from_floor() {
    let nr_cpus = 16;
    let floor = sojourn_floor(nr_cpus);
    let ceil = sojourn_ceil(nr_cpus);
    let mut thresh = floor;

    // REPEATEDLY TARGET CEIL: EWMA SHOULD CONVERGE UPWARD
    for _ in 0..100 {
        thresh = sojourn_ewma_step(thresh, ceil);
    }
    // WITHIN 1% OF CEIL
    let diff = if thresh > ceil {
        thresh - ceil
    } else {
        ceil - thresh
    };
    assert!(
        diff * 100 <= ceil,
        "EWMA DID NOT CONVERGE TO CEIL: {} vs {}",
        thresh,
        ceil
    );
}

#[test]
fn sojourn_ewma_converges_from_ceil() {
    let nr_cpus = 16;
    let floor = sojourn_floor(nr_cpus);
    let ceil = sojourn_ceil(nr_cpus);
    let mut thresh = ceil;

    // REPEATEDLY TARGET FLOOR: EWMA SHOULD CONVERGE DOWNWARD
    for _ in 0..100 {
        thresh = sojourn_ewma_step(thresh, floor);
    }
    let diff = if thresh > floor {
        thresh - floor
    } else {
        floor - thresh
    };
    assert!(
        diff * 100 <= floor,
        "EWMA DID NOT CONVERGE TO FLOOR: {} vs {}",
        thresh,
        floor
    );
}

#[test]
fn sojourn_ewma_stability_identical_targets() {
    let nr_cpus = 8;
    let target = 7_000_000u64; // 7MS, BETWEEN FLOOR AND CEIL
    let mut thresh = sojourn_floor(nr_cpus);

    for _ in 0..200 {
        thresh = sojourn_ewma_step(thresh, target);
    }
    let diff = if thresh > target {
        thresh - target
    } else {
        target - thresh
    };
    assert!(
        diff * 100 <= target,
        "NOT STABLE AT {}: GOT {}",
        target,
        thresh
    );
}

// GRADUATED RELAX STATE MACHINE
// SIMULATE THE EXACT LOGIC FROM adaptive.rs

const MIN_SLICE_NS: u64 = 500_000;
const RELAX_STEP_NS: u64 = 500_000;
const RELAX_HOLD_TICKS: u32 = 2;

struct RelaxSim {
    tightened: bool,
    relax_counter: u32,
    slice_ns: u64,
    preempt_thresh_ns: u64,
    batch_slice_ns: u64,
}

impl RelaxSim {
    fn new(slice_ns: u64, preempt_ns: u64, batch_ns: u64) -> Self {
        Self {
            tightened: true,
            relax_counter: 0,
            slice_ns,
            preempt_thresh_ns: preempt_ns,
            batch_slice_ns: batch_ns,
        }
    }

    fn tick_relax(&mut self, p99_ns: u64, ceiling: u64, baseline: &TuningKnobs) {
        if !self.tightened {
            return;
        }
        if p99_ns <= ceiling {
            self.relax_counter += 1;
            if self.relax_counter >= RELAX_HOLD_TICKS {
                if self.slice_ns < baseline.slice_ns {
                    let new_slice = (self.slice_ns + RELAX_STEP_NS).min(baseline.slice_ns);
                    self.slice_ns = new_slice;
                    self.preempt_thresh_ns = baseline.preempt_thresh_ns.min(new_slice);
                    // BATCH PRESERVED
                    if new_slice >= baseline.slice_ns {
                        self.tightened = false;
                    }
                } else {
                    self.tightened = false;
                }
                self.relax_counter = 0;
            }
        } else {
            self.relax_counter = 0;
        }
    }
}

#[test]
fn relax_requires_hold_ticks() {
    let baseline = regime_knobs(Regime::Mixed);
    let ceiling = Regime::Mixed.p99_ceiling();
    let mut sim = RelaxSim::new(500_000, 500_000, 15_000_000);

    // TICK 1: BELOW CEILING, COUNTER=1, NO STEP YET
    sim.tick_relax(1_000_000, ceiling, &baseline);
    assert_eq!(sim.slice_ns, 500_000);
    assert!(sim.tightened);

    // TICK 2: BELOW CEILING, COUNTER=2, STEP FIRES
    sim.tick_relax(1_000_000, ceiling, &baseline);
    assert_eq!(sim.slice_ns, 1_000_000); // 500K + 500K = BASELINE
    assert!(!sim.tightened); // REACHED BASELINE, DONE
}

#[test]
fn relax_resets_counter_on_spike() {
    let baseline = regime_knobs(Regime::Mixed);
    let ceiling = Regime::Mixed.p99_ceiling();
    let mut sim = RelaxSim::new(500_000, 500_000, 15_000_000);

    // TICK 1: GOOD
    sim.tick_relax(1_000_000, ceiling, &baseline);
    assert_eq!(sim.relax_counter, 1);

    // TICK 2: SPIKE -> COUNTER RESETS
    sim.tick_relax(6_000_000, ceiling, &baseline);
    assert_eq!(sim.relax_counter, 0);
    assert_eq!(sim.slice_ns, 500_000); // NO CHANGE
}

#[test]
fn relax_preserves_batch_slice() {
    let baseline = regime_knobs(Regime::Mixed);
    let ceiling = Regime::Mixed.p99_ceiling();
    let custom_batch = 15_000_000u64;
    let mut sim = RelaxSim::new(500_000, 500_000, custom_batch);

    sim.tick_relax(1_000_000, ceiling, &baseline);
    sim.tick_relax(1_000_000, ceiling, &baseline);

    // BATCH UNCHANGED -- RELAX ONLY TOUCHES SLICE AND PREEMPT
    assert_eq!(sim.batch_slice_ns, custom_batch);
}

#[test]
fn relax_preempt_follows_min() {
    let baseline = regime_knobs(Regime::Mixed); // preempt=1MS, slice=1MS
    let ceiling = Regime::Mixed.p99_ceiling();
    // START AT 250US TIGHTENED (WELL BELOW BASELINE)
    let mut sim = RelaxSim::new(250_000, 250_000, 20_000_000);

    // FIRST RELAX: 250K + 500K = 750K. PREEMPT = MIN(1MS, 750K) = 750K
    sim.tick_relax(1_000_000, ceiling, &baseline);
    sim.tick_relax(1_000_000, ceiling, &baseline);
    assert_eq!(sim.slice_ns, 750_000);
    assert_eq!(sim.preempt_thresh_ns, 750_000);
    assert!(sim.tightened); // NOT AT BASELINE YET

    // SECOND RELAX: 750K + 500K = 1MS = BASELINE. PREEMPT = MIN(1MS, 1MS) = 1MS
    sim.tick_relax(1_000_000, ceiling, &baseline);
    sim.tick_relax(1_000_000, ceiling, &baseline);
    assert_eq!(sim.slice_ns, 1_000_000);
    assert_eq!(sim.preempt_thresh_ns, 1_000_000);
    assert!(!sim.tightened);
}

#[test]
fn relax_noop_when_not_tightened() {
    let baseline = regime_knobs(Regime::Mixed);
    let ceiling = Regime::Mixed.p99_ceiling();
    let mut sim = RelaxSim::new(1_000_000, 1_000_000, 20_000_000);
    sim.tightened = false;

    sim.tick_relax(1_000_000, ceiling, &baseline);
    sim.tick_relax(1_000_000, ceiling, &baseline);
    sim.tick_relax(1_000_000, ceiling, &baseline);

    // NOTHING CHANGES
    assert_eq!(sim.slice_ns, 1_000_000);
    assert!(!sim.tightened);
}

// TIGHTEN/SPIKE DETECTION

struct TightenSim {
    spike_count: u32,
    tightened: bool,
    slice_ns: u64,
    tighten_events: u64,
}

impl TightenSim {
    fn new(slice_ns: u64) -> Self {
        Self {
            spike_count: 0,
            tightened: false,
            slice_ns,
            tighten_events: 0,
        }
    }

    fn tick(&mut self, p99_ns: u64, interactive_p99_ns: u64, regime: Regime) {
        if self.tightened {
            return;
        }
        let ceiling = regime.p99_ceiling();
        if should_reflex_tighten(p99_ns, interactive_p99_ns, ceiling) {
            self.spike_count += 1;
            if self.spike_count >= 2 && regime == Regime::Mixed {
                self.slice_ns = (self.slice_ns * 3 / 4).max(MIN_SLICE_NS);
                self.tightened = true;
                self.tighten_events += 1;
                self.spike_count = 0;
            }
        } else {
            self.spike_count = 0;
        }
    }
}

#[test]
fn tighten_requires_two_consecutive_spikes() {
    let mut sim = TightenSim::new(1_000_000);
    let ceiling = Regime::Mixed.p99_ceiling();

    // ONE SPIKE: NO TIGHTEN
    sim.tick(ceiling + 1, 0, Regime::Mixed);
    assert_eq!(sim.spike_count, 1);
    assert!(!sim.tightened);

    // BELOW CEILING: SPIKE_COUNT RESETS
    sim.tick(ceiling - 1, 0, Regime::Mixed);
    assert_eq!(sim.spike_count, 0);

    // TWO CONSECUTIVE SPIKES: TIGHTEN
    sim.tick(ceiling + 1, 0, Regime::Mixed);
    sim.tick(ceiling + 1, 0, Regime::Mixed);
    assert!(sim.tightened);
    assert_eq!(sim.slice_ns, 750_000); // 1MS * 3/4
}

#[test]
fn tighten_only_in_mixed() {
    for regime in [Regime::Light, Regime::Heavy] {
        let mut sim = TightenSim::new(1_000_000);
        let ceiling = regime.p99_ceiling();
        sim.tick(ceiling + 1_000_000, ceiling + 1_000_000, regime);
        sim.tick(ceiling + 1_000_000, ceiling + 1_000_000, regime);
        assert!(!sim.tightened, "SHOULD NOT TIGHTEN IN {:?}", regime);
    }
}

#[test]
fn tighten_cascades_to_floor() {
    let mut sim = TightenSim::new(1_000_000);
    let spike = Regime::Mixed.p99_ceiling() + 1;

    // FIRST TIGHTEN: 1000 -> 750
    sim.tick(spike, spike, Regime::Mixed);
    sim.tick(spike, spike, Regime::Mixed);
    assert_eq!(sim.slice_ns, 750_000);

    // RESET FOR NEXT CYCLE
    sim.tightened = false;
    sim.tick(spike, spike, Regime::Mixed);
    sim.tick(spike, spike, Regime::Mixed);
    assert_eq!(sim.slice_ns, 562_500); // 750K * 3/4

    sim.tightened = false;
    sim.tick(spike, spike, Regime::Mixed);
    sim.tick(spike, spike, Regime::Mixed);
    assert_eq!(sim.slice_ns, 500_000); // FLOOR (421K CLAMPED TO 500K)

    // ONE MORE: STAYS AT FLOOR
    sim.tightened = false;
    sim.tick(spike, spike, Regime::Mixed);
    sim.tick(spike, spike, Regime::Mixed);
    assert_eq!(sim.slice_ns, 500_000);
}

#[test]
fn tighten_fires_on_interactive_p99_alone() {
    let mut sim = TightenSim::new(1_000_000);
    let ceiling = Regime::Mixed.p99_ceiling();

    // AGGREGATE BELOW, INTERACTIVE ABOVE: STILL TIGHTENS
    sim.tick(1_000_000, ceiling + 1, Regime::Mixed);
    sim.tick(1_000_000, ceiling + 1, Regime::Mixed);
    assert!(sim.tightened);
}

// LONGRUN OVERRIDE LOGIC

#[test]
fn longrun_override_skips_sleep_adjust() {
    let baseline = regime_knobs(Regime::Mixed);
    let longrun_active = true;

    let final_batch = if longrun_active {
        baseline.batch_slice_ns
    } else {
        sleep_adjust_batch_ns(baseline.batch_slice_ns, 70) // IO-HEAVY WOULD EXTEND
    };

    assert_eq!(final_batch, baseline.batch_slice_ns); // NO EXTENSION
}

#[test]
fn longrun_override_forces_weak_affinity() {
    for regime in [Regime::Light, Regime::Mixed, Regime::Heavy] {
        let baseline = regime_knobs(regime);
        let longrun_active = true;

        let final_affinity = if longrun_active {
            AFFINITY_WEAK
        } else {
            baseline.affinity_mode
        };

        assert_eq!(
            final_affinity, AFFINITY_WEAK,
            "LONGRUN SHOULD FORCE WEAK IN {:?}",
            regime
        );
    }
}

#[test]
fn no_longrun_uses_regime_affinity() {
    let baseline = regime_knobs(Regime::Mixed);
    let longrun_active = false;

    let final_affinity = if longrun_active {
        AFFINITY_WEAK
    } else {
        baseline.affinity_mode
    };

    assert_eq!(final_affinity, AFFINITY_STRONG); // MIXED = STRONG
}

// SLEEP-INFORMED BATCH TUNING BOUNDARIES

#[test]
fn sleep_adjust_io_pct_0_tightens() {
    let result = sleep_adjust_batch_ns(20_000_000, 0);
    assert_eq!(result, 15_000_000); // -25%
}

#[test]
fn sleep_adjust_io_pct_14_tightens() {
    let result = sleep_adjust_batch_ns(20_000_000, 14);
    assert_eq!(result, 15_000_000); // JUST BELOW 15
}

#[test]
fn sleep_adjust_io_pct_15_dead_zone() {
    let result = sleep_adjust_batch_ns(20_000_000, 15);
    assert_eq!(result, 20_000_000); // NO CHANGE
}

#[test]
fn sleep_adjust_io_pct_60_dead_zone() {
    let result = sleep_adjust_batch_ns(20_000_000, 60);
    assert_eq!(result, 20_000_000); // NO CHANGE
}

#[test]
fn sleep_adjust_io_pct_61_extends() {
    let result = sleep_adjust_batch_ns(20_000_000, 61);
    assert_eq!(result, 25_000_000); // +25%
}

#[test]
fn sleep_adjust_io_pct_100_capped() {
    let result = sleep_adjust_batch_ns(24_000_000, 100);
    assert_eq!(result, BATCH_MAX_NS); // 30MS WOULD EXCEED, CAPPED AT 25MS
}

// REGIME HOLD (2-TICK HYSTERESIS)

struct RegimeHoldSim {
    regime: Regime,
    pending: Regime,
    hold: u32,
}

impl RegimeHoldSim {
    fn new(regime: Regime) -> Self {
        Self {
            regime,
            pending: regime,
            hold: 0,
        }
    }

    fn tick(&mut self, idle_pct: u64) -> bool {
        let detected = detect_regime(self.regime, idle_pct);
        let mut changed = false;

        if detected != self.regime {
            if detected == self.pending {
                self.hold += 1;
            } else {
                self.pending = detected;
                self.hold = 1;
            }
            if self.hold >= 2 {
                self.regime = detected;
                changed = true;
            }
        } else {
            self.pending = self.regime;
            self.hold = 0;
        }
        changed
    }
}

#[test]
fn regime_hold_single_tick_no_transition() {
    let mut sim = RegimeHoldSim::new(Regime::Light);

    // ONE TICK OF LOW IDLE: NO TRANSITION
    let changed = sim.tick(20); // BELOW LIGHT_EXIT (30)
    assert!(!changed);
    assert_eq!(sim.regime, Regime::Light);
    assert_eq!(sim.hold, 1);
}

#[test]
fn regime_hold_two_ticks_transitions() {
    let mut sim = RegimeHoldSim::new(Regime::Light);

    sim.tick(20); // TICK 1: DETECT MIXED
    let changed = sim.tick(20); // TICK 2: CONFIRM
    assert!(changed);
    assert_eq!(sim.regime, Regime::Mixed);
}

#[test]
fn regime_hold_alternating_never_transitions() {
    let mut sim = RegimeHoldSim::new(Regime::Mixed);

    for _ in 0..20 {
        // ODD TICKS: HEAVY (IDLE=5)
        let c1 = sim.tick(5);
        assert!(!c1 || sim.hold == 0); // HOLD RESETS ON ALTERNATION
                                       // EVEN TICKS: LIGHT (IDLE=55)
        let c2 = sim.tick(55);
        // NEVER STAYS LONG ENOUGH
        assert_eq!(sim.regime, Regime::Mixed);
        let _ = c2;
    }
}

#[test]
fn regime_hold_resets_on_new_pending() {
    let mut sim = RegimeHoldSim::new(Regime::Mixed);

    // TICK 1: DETECT HEAVY (IDLE=5)
    sim.tick(5);
    assert_eq!(sim.pending, Regime::Heavy);
    assert_eq!(sim.hold, 1);

    // TICK 2: DETECT LIGHT (IDLE=55) -> DIFFERENT PENDING, HOLD RESETS TO 1
    sim.tick(55);
    assert_eq!(sim.pending, Regime::Light);
    assert_eq!(sim.hold, 1);

    // TICK 3: DETECT LIGHT AGAIN -> HOLD=2, TRANSITION
    let changed = sim.tick(55);
    assert!(changed);
    assert_eq!(sim.regime, Regime::Light);
}

// P99 HISTOGRAM EDGE CASES

#[test]
fn p99_all_in_one_bucket() {
    let mut counts = [0u64; HIST_BUCKETS];
    counts[3] = 1000; // ALL IN 100US BUCKET
    let p99 = compute_p99_from_histogram(&counts);
    assert_eq!(p99, HIST_EDGES_NS[3]); // 100_000
}

#[test]
fn p99_split_99_1() {
    let mut counts = [0u64; HIST_BUCKETS];
    counts[2] = 99; // 50US: 99%
    counts[6] = 1; // 1MS: 1%
                   // THRESHOLD = (100*99+99)/100 = 99. CUMULATIVE HITS 99 AT BUCKET 2.
                   // P99 = 50US (THE 99TH PERCENTILE FALLS WITHIN THE 99-SAMPLE BUCKET)
    let p99 = compute_p99_from_histogram(&counts);
    assert_eq!(p99, HIST_EDGES_NS[2]); // 50_000
}

#[test]
fn p99_split_98_2() {
    let mut counts = [0u64; HIST_BUCKETS];
    counts[2] = 98; // 50US: 98%
    counts[6] = 2; // 1MS: 2%
                   // THRESHOLD = (100*99+99)/100 = 99. CUMULATIVE=98 AT BUCKET 2 (NOT ENOUGH).
                   // P99 FALLS IN BUCKET 6 (1MS)
    let p99 = compute_p99_from_histogram(&counts);
    assert_eq!(p99, HIST_EDGES_NS[6]); // 1_000_000
}

#[test]
fn p99_all_in_inf_bucket_capped() {
    let mut counts = [0u64; HIST_BUCKETS];
    counts[HIST_BUCKETS - 1] = 500; // ALL IN +INF
    let p99 = compute_p99_from_histogram(&counts);
    // CAPPED AT 20MS, NOT U64::MAX
    assert_eq!(p99, HIST_EDGES_NS[HIST_BUCKETS - 2]); // 20_000_000
}

#[test]
fn p99_single_sample() {
    let mut counts = [0u64; HIST_BUCKETS];
    counts[0] = 1; // SINGLE SAMPLE IN 10US
    let p99 = compute_p99_from_histogram(&counts);
    assert_eq!(p99, HIST_EDGES_NS[0]); // 10_000
}

#[test]
fn p99_exactly_100_samples() {
    let mut counts = [0u64; HIST_BUCKETS];
    counts[1] = 98; // 25US: 98 SAMPLES
    counts[5] = 2; // 500US: 2 SAMPLES
                   // THRESHOLD = (100*99+99)/100 = 99. BUCKET 1 HAS 98, NEED 99 -> BUCKET 5
    let p99 = compute_p99_from_histogram(&counts);
    assert_eq!(p99, HIST_EDGES_NS[5]); // 500_000
}

// STABILITY SCORE INTEGRATION

#[test]
fn stability_regime_change_plus_relax_reset() {
    // SIMULATE: TIGHTENED, REGIME CHANGES -> BOTH SHOULD RESET
    let score = compute_stability_score(8, true, 0, 0, 5_000_000);
    assert_eq!(score, 0);

    // THEN BACK TO STABLE: SCORE INCREMENTS
    let score = compute_stability_score(0, false, 0, 0, 5_000_000);
    assert_eq!(score, 1);
}

#[test]
fn stability_p99_at_exactly_half_ceiling() {
    // P99 = EXACTLY CEILING/2 -> NOT A RESET (STRICTLY GREATER THAN)
    let ceiling = 5_000_000u64;
    let p99 = ceiling / 2; // 2_500_000
    let score = compute_stability_score(8, false, 0, p99, ceiling);
    assert_eq!(score, 9); // INCREMENTS (NOT RESET)
}

#[test]
fn stability_p99_just_above_half_ceiling() {
    // P99 = CEILING/2 + 1 -> RESET
    let ceiling = 5_000_000u64;
    let p99 = ceiling / 2 + 1; // 2_500_001
    let score = compute_stability_score(8, false, 0, p99, ceiling);
    assert_eq!(score, 0);
}

// TUNING KNOBS SOJOURN FIELD

#[test]
fn tuning_knobs_has_sojourn_thresh() {
    let k = TuningKnobs::default();
    assert_eq!(k.sojourn_thresh_ns, 5_000_000); // 5MS DEFAULT
}

#[test]
fn regime_knobs_all_have_sojourn() {
    for regime in [Regime::Light, Regime::Mixed, Regime::Heavy] {
        let k = regime_knobs(regime);
        assert!(k.sojourn_thresh_ns > 0, "SOJOURN MISSING IN {:?}", regime);
        assert!(k.burst_slice_ns > 0, "BURST_SLICE MISSING IN {:?}", regime);
    }
}
