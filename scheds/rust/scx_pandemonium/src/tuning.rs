// PANDEMONIUM TUNING TYPES
// PURE-RUST MODULE: ZERO BPF DEPENDENCIES
// SHARED BETWEEN BINARY CRATE (scheduler.rs, adaptive.rs) AND LIB CRATE (tests)

// REGIME THRESHOLDS (SCHMITT TRIGGER)
// DIRECTIONAL HYSTERESIS PREVENTS OSCILLATION AT REGIME BOUNDARIES.
// WIDE DEAD ZONES: MUST CLEARLY ENTER A REGIME AND CLEARLY LEAVE IT.

pub const HEAVY_ENTER_PCT: u64 = 10;   // ENTER HEAVY: IDLE < 10%
pub const HEAVY_EXIT_PCT: u64  = 25;   // LEAVE HEAVY: IDLE > 25%
pub const LIGHT_ENTER_PCT: u64 = 50;   // ENTER LIGHT: IDLE > 50%
pub const LIGHT_EXIT_PCT: u64  = 30;   // LEAVE LIGHT: IDLE < 30%

// REGIME PROFILES
// PREEMPT_THRESH CONTROLS WHEN TICK PREEMPTS BATCH TASKS (IF INTERACTIVE WAITING).
// BATCH_SLICE_NS CONTROLS MAX UNINTERRUPTED BATCH RUN WHEN NO INTERACTIVE WAITING.
// CPU_BOUND_THRESH_NS CONTROLS DEMOTION THRESHOLD PER REGIME (FEATURE 5).

const LIGHT_SLICE_NS: u64     = 2_000_000;   // 2MS
const LIGHT_PREEMPT_NS: u64   = 1_000_000;   // 1MS: AGGRESSIVE
const LIGHT_LAG_SCALE: u64    = 6;
const LIGHT_BATCH_NS: u64     = 20_000_000;  // 20MS: NO CONTENTION, LET BATCH RIP

const MIXED_SLICE_NS: u64     = 1_000_000;   // 1MS: TIGHT INTERACTIVE CONTROL
const MIXED_PREEMPT_NS: u64   = 1_000_000;   // 1MS: MATCH FOR CLEAN ENFORCEMENT
const MIXED_LAG_SCALE: u64    = 4;
const MIXED_BATCH_NS: u64     = 20_000_000;  // 20MS: MATCHES LIGHT/HEAVY/BPF DEFAULT

const HEAVY_SLICE_NS: u64     = 4_000_000;   // 4MS: WIDER FOR THROUGHPUT
const HEAVY_PREEMPT_NS: u64   = 2_000_000;   // 2MS: SLIGHTLY RELAXED
const HEAVY_LAG_SCALE: u64    = 2;
const HEAVY_BATCH_NS: u64     = 20_000_000;  // 20MS: LET BATCH RIP

// P99 CEILINGS

const LIGHT_P99_CEIL_NS: u64  = 3_000_000;   // 3MS
const MIXED_P99_CEIL_NS: u64  = 5_000_000;   // 5MS: BELOW 16MS FRAME BUDGET
const HEAVY_P99_CEIL_NS: u64  = 10_000_000;  // 10MS: HEAVY LOAD, REALISTIC

// CPU-BOUND DEMOTION THRESHOLDS
// PER-REGIME: LENIENT IN LIGHT, AGGRESSIVE IN HEAVY

pub const LIGHT_DEMOTION_NS: u64 = 3_500_000;  // 3.5MS: LENIENT, FEW CONTEND
pub const MIXED_DEMOTION_NS: u64 = 2_500_000;  // 2.5MS: CURRENT CPU_BOUND_THRESH_NS
pub const HEAVY_DEMOTION_NS: u64 = 2_000_000;  // 2.0MS: AGGRESSIVE

// ADAPTIVE SAMPLES_PER_CHECK

pub const LIGHT_SAMPLES_PER_CHECK: u32 = 16;
pub const MIXED_SAMPLES_PER_CHECK: u32 = 32;
pub const HEAVY_SAMPLES_PER_CHECK: u32 = 64;

// CLASSIFIER THRESHOLDS
// LAT_CRI SCORE BOUNDARIES FOR TIER CLASSIFICATION
// EXPOSED AS TUNING KNOBS FOR RUNTIME ADJUSTMENT

pub const DEFAULT_LAT_CRI_THRESH_HIGH: u64 = 32;  // >= THIS: LAT_CRITICAL
pub const DEFAULT_LAT_CRI_THRESH_LOW: u64  = 8;   // >= THIS: INTERACTIVE, BELOW: BATCH

// TUNING KNOBS
// MATCHES struct tuning_knobs IN BPF (intf.h)

#[repr(C)]
#[derive(Clone, Copy)]
pub struct TuningKnobs {
    pub slice_ns: u64,
    pub preempt_thresh_ns: u64,
    pub lag_scale: u64,
    pub batch_slice_ns: u64,
    pub cpu_bound_thresh_ns: u64,
    pub lat_cri_thresh_high: u64,
    pub lat_cri_thresh_low: u64,
}

impl Default for TuningKnobs {
    fn default() -> Self {
        Self {
            slice_ns: 1_000_000,
            preempt_thresh_ns: 1_000_000,
            lag_scale: 4,
            batch_slice_ns: 20_000_000,
            cpu_bound_thresh_ns: MIXED_DEMOTION_NS,
            lat_cri_thresh_high: DEFAULT_LAT_CRI_THRESH_HIGH,
            lat_cri_thresh_low: DEFAULT_LAT_CRI_THRESH_LOW,
        }
    }
}

// REGIME

#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Regime {
    Light = 0,
    Mixed = 1,
    Heavy = 2,
}

impl Regime {
    pub fn from_u8(v: u8) -> Self {
        match v {
            0 => Self::Light,
            1 => Self::Mixed,
            _ => Self::Heavy,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Light => "LIGHT",
            Self::Mixed => "MIXED",
            Self::Heavy => "HEAVY",
        }
    }

    pub fn p99_ceiling(self) -> u64 {
        match self {
            Self::Light => LIGHT_P99_CEIL_NS,
            Self::Mixed => MIXED_P99_CEIL_NS,
            Self::Heavy => HEAVY_P99_CEIL_NS,
        }
    }
}

// REGIME KNOBS

pub fn regime_knobs(r: Regime) -> TuningKnobs {
    match r {
        Regime::Light => TuningKnobs {
            slice_ns: LIGHT_SLICE_NS,
            preempt_thresh_ns: LIGHT_PREEMPT_NS,
            lag_scale: LIGHT_LAG_SCALE,
            batch_slice_ns: LIGHT_BATCH_NS,
            cpu_bound_thresh_ns: LIGHT_DEMOTION_NS,
            lat_cri_thresh_high: DEFAULT_LAT_CRI_THRESH_HIGH,
            lat_cri_thresh_low: DEFAULT_LAT_CRI_THRESH_LOW,
        },
        Regime::Mixed => TuningKnobs {
            slice_ns: MIXED_SLICE_NS,
            preempt_thresh_ns: MIXED_PREEMPT_NS,
            lag_scale: MIXED_LAG_SCALE,
            batch_slice_ns: MIXED_BATCH_NS,
            cpu_bound_thresh_ns: MIXED_DEMOTION_NS,
            lat_cri_thresh_high: DEFAULT_LAT_CRI_THRESH_HIGH,
            lat_cri_thresh_low: DEFAULT_LAT_CRI_THRESH_LOW,
        },
        Regime::Heavy => TuningKnobs {
            slice_ns: HEAVY_SLICE_NS,
            preempt_thresh_ns: HEAVY_PREEMPT_NS,
            lag_scale: HEAVY_LAG_SCALE,
            batch_slice_ns: HEAVY_BATCH_NS,
            cpu_bound_thresh_ns: HEAVY_DEMOTION_NS,
            lat_cri_thresh_high: DEFAULT_LAT_CRI_THRESH_HIGH,
            lat_cri_thresh_low: DEFAULT_LAT_CRI_THRESH_LOW,
        },
    }
}

// REGIME DETECTION (SCHMITT TRIGGER)
// DIRECTION-AWARE: CURRENT REGIME DETERMINES WHICH THRESHOLDS APPLY.
// DEAD ZONES PREVENT OSCILLATION THAT SINGLE-BOUNDARY DETECTION CAUSED.

pub fn detect_regime(current: Regime, idle_pct: u64) -> Regime {
    match current {
        Regime::Light => {
            if idle_pct < LIGHT_EXIT_PCT {
                Regime::Mixed
            } else {
                Regime::Light
            }
        }
        Regime::Mixed => {
            if idle_pct > LIGHT_ENTER_PCT {
                Regime::Light
            } else if idle_pct < HEAVY_ENTER_PCT {
                Regime::Heavy
            } else {
                Regime::Mixed
            }
        }
        Regime::Heavy => {
            if idle_pct > HEAVY_EXIT_PCT {
                Regime::Mixed
            } else {
                Regime::Heavy
            }
        }
    }
}

// ADAPTIVE SAMPLES PER CHECK

pub fn samples_per_check_for_regime(r: Regime) -> u32 {
    match r {
        Regime::Light => LIGHT_SAMPLES_PER_CHECK,
        Regime::Mixed => MIXED_SAMPLES_PER_CHECK,
        Regime::Heavy => HEAVY_SAMPLES_PER_CHECK,
    }
}

// STABILITY MODE
// REFLEX THREAD HIBERNATION WHEN SYSTEM IS STABLE.
// REDUCES P99 COMPUTATION FROM ~1250/SEC TO ~312/SEC DURING STABLE GAMING.

pub const STABILITY_THRESHOLD: u32 = 10;    // CONSECUTIVE STABLE TICKS BEFORE HIBERNATE
pub const HIBERNATE_MULTIPLIER: u32 = 4;    // 4X SAMPLES_PER_CHECK WHEN STABLE

pub fn compute_stability_score(
    prev_score: u32,
    regime_changed: bool,
    guard_clamps: u64,
    reflex_events_delta: u64,
    p99_ns: u64,
    p99_ceiling_ns: u64,
) -> u32 {
    if regime_changed
        || guard_clamps > 0
        || reflex_events_delta > 0
        || p99_ns > p99_ceiling_ns / 2
    {
        return 0;
    }
    (prev_score + 1).min(STABILITY_THRESHOLD)
}

pub fn hibernate_samples_per_check(regime: Regime, stability_score: u32) -> u32 {
    let base = samples_per_check_for_regime(regime);
    if stability_score >= STABILITY_THRESHOLD {
        base * HIBERNATE_MULTIPLIER
    } else {
        base
    }
}

// TELEMETRY GATING

pub fn should_print_telemetry(tick_counter: u64, stability_score: u32) -> bool {
    if stability_score >= STABILITY_THRESHOLD {
        tick_counter % 2 == 0
    } else {
        true
    }
}

// P99 HISTOGRAM

pub const HIST_BUCKETS: usize = 12;
pub const HIST_EDGES_NS: [u64; HIST_BUCKETS] = [
    10_000,      // 10us
    25_000,      // 25us
    50_000,      // 50us
    100_000,     // 100us
    250_000,     // 250us
    500_000,     // 500us
    1_000_000,   // 1ms
    2_000_000,   // 2ms
    5_000_000,   // 5ms
    10_000_000,  // 10ms
    20_000_000,  // 20ms
    u64::MAX,    // +inf
];

// COMPUTE P99 FROM DRAINED HISTOGRAM COUNTS. PURE FUNCTION.
// CAP AT 20MS (LAST REAL BUCKET) -- +INF WOULD POISON EVERY COMPARISON.
pub fn compute_p99_from_histogram(counts: &[u64; HIST_BUCKETS]) -> u64 {
    let total: u64 = counts.iter().sum();
    if total == 0 {
        return 0;
    }
    let threshold = (total * 99 + 99) / 100;
    let mut cumulative = 0u64;
    for i in 0..HIST_BUCKETS {
        cumulative += counts[i];
        if cumulative >= threshold {
            return HIST_EDGES_NS[i].min(HIST_EDGES_NS[HIST_BUCKETS - 2]);
        }
    }
    HIST_EDGES_NS[HIST_BUCKETS - 2]
}

// REFLEX TIGHTEN DECISION: USES BOTH AGGREGATE AND INTERACTIVE P99.
// TIGHTEN IF EITHER EXCEEDS CEILING (INTERACTIVE STARVATION HIDDEN IN AGGREGATE).
pub fn should_reflex_tighten(aggregate_p99: u64, interactive_p99: u64, ceiling: u64) -> bool {
    aggregate_p99 > ceiling || interactive_p99 > ceiling
}

