// PANDEMONIUM ADAPTIVE CONTROL TESTS
// REGIME DETECTION, KNOB COMPUTATION, DEMOTION THRESHOLDS, ABI LAYOUT
//
// ALL TESTS USE PURE-RUST TYPES FROM pandemonium::tuning.
// ZERO BPF DEPENDENCIES. RUN OFFLINE.

use pandemonium::tuning::{
    Regime, TuningKnobs, detect_regime, regime_knobs,
    samples_per_check_for_regime,
    compute_stability_score, hibernate_samples_per_check,
    should_print_telemetry,
    compute_p99_from_histogram, should_reflex_tighten,
    HEAVY_ENTER_PCT, HEAVY_EXIT_PCT, LIGHT_ENTER_PCT, LIGHT_EXIT_PCT,
    LIGHT_DEMOTION_NS, MIXED_DEMOTION_NS, HEAVY_DEMOTION_NS,
    LIGHT_SAMPLES_PER_CHECK, MIXED_SAMPLES_PER_CHECK, HEAVY_SAMPLES_PER_CHECK,
    STABILITY_THRESHOLD, HIBERNATE_MULTIPLIER,
    DEFAULT_LAT_CRI_THRESH_HIGH, DEFAULT_LAT_CRI_THRESH_LOW,
    HIST_BUCKETS,
};

// REGIME DETECTION (SCHMITT TRIGGER)

#[test]
fn detect_regime_light_to_mixed() {
    // IDLE DROPS BELOW LIGHT_EXIT_PCT -> TRANSITION TO MIXED
    let result = detect_regime(Regime::Light, LIGHT_EXIT_PCT - 1);
    assert_eq!(result, Regime::Mixed);
}

#[test]
fn detect_regime_mixed_to_heavy() {
    // IDLE DROPS BELOW HEAVY_ENTER_PCT -> TRANSITION TO HEAVY
    let result = detect_regime(Regime::Mixed, HEAVY_ENTER_PCT - 1);
    assert_eq!(result, Regime::Heavy);
}

#[test]
fn detect_regime_heavy_to_mixed() {
    // IDLE RISES ABOVE HEAVY_EXIT_PCT -> TRANSITION TO MIXED
    let result = detect_regime(Regime::Heavy, HEAVY_EXIT_PCT + 1);
    assert_eq!(result, Regime::Mixed);
}

#[test]
fn detect_regime_mixed_to_light() {
    // IDLE RISES ABOVE LIGHT_ENTER_PCT -> TRANSITION TO LIGHT
    let result = detect_regime(Regime::Mixed, LIGHT_ENTER_PCT + 1);
    assert_eq!(result, Regime::Light);
}

#[test]
fn detect_regime_light_stays_in_dead_zone() {
    // IDLE=35%: ABOVE LIGHT_EXIT (30%) BUT BELOW LIGHT_ENTER (50%) -> STAYS LIGHT
    let result = detect_regime(Regime::Light, 35);
    assert_eq!(result, Regime::Light);
}

#[test]
fn detect_regime_heavy_stays_in_dead_zone() {
    // IDLE=15%: ABOVE HEAVY_ENTER (10%) BUT BELOW HEAVY_EXIT (25%) -> STAYS HEAVY
    let result = detect_regime(Regime::Heavy, 15);
    assert_eq!(result, Regime::Heavy);
}

// KNOB COMPUTATION

#[test]
fn regime_knobs_light_values() {
    let k = regime_knobs(Regime::Light);
    assert_eq!(k.slice_ns, 2_000_000);
    assert_eq!(k.preempt_thresh_ns, 1_000_000);
    assert_eq!(k.lag_scale, 6);
    assert_eq!(k.batch_slice_ns, 20_000_000);
    assert_eq!(k.cpu_bound_thresh_ns, LIGHT_DEMOTION_NS);
    assert_eq!(k.lat_cri_thresh_high, DEFAULT_LAT_CRI_THRESH_HIGH);
    assert_eq!(k.lat_cri_thresh_low, DEFAULT_LAT_CRI_THRESH_LOW);
}

#[test]
fn regime_knobs_mixed_values() {
    let k = regime_knobs(Regime::Mixed);
    assert_eq!(k.slice_ns, 1_000_000);
    assert_eq!(k.preempt_thresh_ns, 1_000_000);
    assert_eq!(k.lag_scale, 4);
    assert_eq!(k.batch_slice_ns, 20_000_000);
    assert_eq!(k.cpu_bound_thresh_ns, MIXED_DEMOTION_NS);
    assert_eq!(k.lat_cri_thresh_high, DEFAULT_LAT_CRI_THRESH_HIGH);
    assert_eq!(k.lat_cri_thresh_low, DEFAULT_LAT_CRI_THRESH_LOW);
}

#[test]
fn regime_knobs_heavy_values() {
    let k = regime_knobs(Regime::Heavy);
    assert_eq!(k.slice_ns, 4_000_000);
    assert_eq!(k.preempt_thresh_ns, 2_000_000);
    assert_eq!(k.lag_scale, 2);
    assert_eq!(k.batch_slice_ns, 20_000_000);
    assert_eq!(k.cpu_bound_thresh_ns, HEAVY_DEMOTION_NS);
    assert_eq!(k.lat_cri_thresh_high, DEFAULT_LAT_CRI_THRESH_HIGH);
    assert_eq!(k.lat_cri_thresh_low, DEFAULT_LAT_CRI_THRESH_LOW);
}

// DEMOTION THRESHOLD (FEATURE 5)

#[test]
fn demotion_threshold_per_regime() {
    assert_eq!(LIGHT_DEMOTION_NS, 3_500_000);  // 3.5MS: LENIENT
    assert_eq!(MIXED_DEMOTION_NS, 2_500_000);  // 2.5MS: CURRENT DEFAULT
    assert_eq!(HEAVY_DEMOTION_NS, 2_000_000);  // 2.0MS: AGGRESSIVE
}

#[test]
fn demotion_threshold_in_knobs() {
    // VERIFY cpu_bound_thresh_ns IS SET CORRECTLY PER REGIME
    assert_eq!(regime_knobs(Regime::Light).cpu_bound_thresh_ns, 3_500_000);
    assert_eq!(regime_knobs(Regime::Mixed).cpu_bound_thresh_ns, 2_500_000);
    assert_eq!(regime_knobs(Regime::Heavy).cpu_bound_thresh_ns, 2_000_000);
}

// ADAPTIVE BATCH SIZE (FEATURE 4)

#[test]
fn samples_per_check_per_regime() {
    assert_eq!(samples_per_check_for_regime(Regime::Light), LIGHT_SAMPLES_PER_CHECK);
    assert_eq!(samples_per_check_for_regime(Regime::Mixed), MIXED_SAMPLES_PER_CHECK);
    assert_eq!(samples_per_check_for_regime(Regime::Heavy), HEAVY_SAMPLES_PER_CHECK);
    assert_eq!(LIGHT_SAMPLES_PER_CHECK, 16);
    assert_eq!(MIXED_SAMPLES_PER_CHECK, 32);
    assert_eq!(HEAVY_SAMPLES_PER_CHECK, 64);
}

// TUNING KNOBS ABI

#[test]
fn tuning_knobs_size_is_7_u64() {
    // MUST MATCH struct tuning_knobs IN intf.h (7 x u64 = 56 BYTES)
    assert_eq!(std::mem::size_of::<TuningKnobs>(), 56);
}

#[test]
fn tuning_knobs_default() {
    let k = TuningKnobs::default();
    assert_eq!(k.slice_ns, 1_000_000);
    assert_eq!(k.preempt_thresh_ns, 1_000_000);
    assert_eq!(k.lag_scale, 4);
    assert_eq!(k.batch_slice_ns, 20_000_000);
    assert_eq!(k.cpu_bound_thresh_ns, MIXED_DEMOTION_NS);
    assert_eq!(k.lat_cri_thresh_high, DEFAULT_LAT_CRI_THRESH_HIGH);
    assert_eq!(k.lat_cri_thresh_low, DEFAULT_LAT_CRI_THRESH_LOW);
}

// STABILITY MODE

#[test]
fn stability_score_increments_when_stable() {
    let score = compute_stability_score(5, false, 0, 0, 0, 5_000_000);
    assert_eq!(score, 6);
}

#[test]
fn stability_score_caps_at_threshold() {
    let score = compute_stability_score(STABILITY_THRESHOLD, false, 0, 0, 0, 5_000_000);
    assert_eq!(score, STABILITY_THRESHOLD);
}

#[test]
fn stability_score_resets_on_regime_change() {
    let score = compute_stability_score(8, true, 0, 0, 0, 5_000_000);
    assert_eq!(score, 0);
}

#[test]
fn stability_score_resets_on_guard_clamps() {
    let score = compute_stability_score(8, false, 1, 0, 0, 5_000_000);
    assert_eq!(score, 0);
}

#[test]
fn stability_score_resets_on_reflex_event() {
    let score = compute_stability_score(8, false, 0, 1, 0, 5_000_000);
    assert_eq!(score, 0);
}

#[test]
fn stability_score_resets_on_p99_above_half_ceiling() {
    // CEILING=5MS, P99=2.6MS > 2.5MS (HALF CEILING) -> RESET
    let score = compute_stability_score(8, false, 0, 0, 2_600_000, 5_000_000);
    assert_eq!(score, 0);
}

// HIBERNATE SAMPLES PER CHECK

#[test]
fn hibernate_samples_per_check_base_when_unstable() {
    let spc = hibernate_samples_per_check(Regime::Mixed, 5);
    assert_eq!(spc, MIXED_SAMPLES_PER_CHECK);
}

#[test]
fn hibernate_samples_per_check_4x_when_stable() {
    let spc = hibernate_samples_per_check(Regime::Mixed, STABILITY_THRESHOLD);
    assert_eq!(spc, MIXED_SAMPLES_PER_CHECK * HIBERNATE_MULTIPLIER);
}

// TELEMETRY GATING

#[test]
fn should_print_telemetry_always_when_unstable() {
    for tick in 0..10 {
        assert!(should_print_telemetry(tick, STABILITY_THRESHOLD - 1));
    }
}

#[test]
fn should_print_telemetry_alternates_when_stable() {
    assert!(should_print_telemetry(0, STABILITY_THRESHOLD));
    assert!(!should_print_telemetry(1, STABILITY_THRESHOLD));
    assert!(should_print_telemetry(2, STABILITY_THRESHOLD));
    assert!(!should_print_telemetry(3, STABILITY_THRESHOLD));
}

// PER-TIER P99

#[test]
fn per_tier_p99_isolates_tiers() {
    // BATCH SAMPLES AT 50US DON'T AFFECT INTERACTIVE P99
    let mut batch_counts = [0u64; HIST_BUCKETS];
    batch_counts[2] = 100; // 50US BUCKET

    let mut interactive_counts = [0u64; HIST_BUCKETS];
    interactive_counts[6] = 100; // 1MS BUCKET

    let batch_p99 = compute_p99_from_histogram(&batch_counts);
    let interactive_p99 = compute_p99_from_histogram(&interactive_counts);

    assert_eq!(batch_p99, 50_000);       // 50US
    assert_eq!(interactive_p99, 1_000_000); // 1MS
}

#[test]
fn per_tier_p99_reset_clears_all() {
    // AFTER DRAINING A HISTOGRAM, EMPTY COUNTS PRODUCE ZERO P99
    let mut counts = [0u64; HIST_BUCKETS];
    counts[4] = 50; // 250US BUCKET

    let p99 = compute_p99_from_histogram(&counts);
    assert_eq!(p99, 250_000);

    // EMPTY HISTOGRAM: P99 = 0 (SIMULATES POST-DRAIN STATE)
    let empty = [0u64; HIST_BUCKETS];
    assert_eq!(compute_p99_from_histogram(&empty), 0);
}

#[test]
fn reflex_tightens_on_interactive_p99() {
    let ceiling = Regime::Mixed.p99_ceiling(); // 5MS

    // AGGREGATE BELOW CEILING, INTERACTIVE ABOVE: TIGHTEN
    assert!(should_reflex_tighten(500_000, 6_000_000, ceiling));

    // BOTH BELOW CEILING: NO TIGHTEN
    assert!(!should_reflex_tighten(500_000, 500_000, ceiling));

    // AGGREGATE ABOVE, INTERACTIVE BELOW: STILL TIGHTENS
    assert!(should_reflex_tighten(6_000_000, 500_000, ceiling));

    // BOTH ABOVE: TIGHTENS
    assert!(should_reflex_tighten(6_000_000, 6_000_000, ceiling));
}

// CLASSIFIER THRESHOLDS

#[test]
fn classifier_threshold_constants() {
    assert_eq!(DEFAULT_LAT_CRI_THRESH_HIGH, 32);
    assert_eq!(DEFAULT_LAT_CRI_THRESH_LOW, 8);
}

#[test]
fn classifier_thresholds_in_all_regimes() {
    // ALL REGIMES USE THE SAME CLASSIFIER THRESHOLDS (FOR NOW)
    for regime in [Regime::Light, Regime::Mixed, Regime::Heavy] {
        let k = regime_knobs(regime);
        assert_eq!(k.lat_cri_thresh_high, 32, "high threshold mismatch in {:?}", regime);
        assert_eq!(k.lat_cri_thresh_low, 8, "low threshold mismatch in {:?}", regime);
    }
}

