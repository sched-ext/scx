// PANDEMONIUM TUNING TYPES
// PURE-RUST MODULE: ZERO BPF DEPENDENCIES
// SHARED BETWEEN BINARY CRATE (scheduler.rs, adaptive.rs) AND LIB CRATE (tests)

// REGIME THRESHOLDS (SCHMITT TRIGGER)
// DIRECTIONAL HYSTERESIS PREVENTS OSCILLATION AT REGIME BOUNDARIES.
// WIDE DEAD ZONES: MUST CLEARLY ENTER A REGIME AND CLEARLY LEAVE IT.

pub const HEAVY_ENTER_PCT: u64 = 10; // ENTER HEAVY: IDLE < 10%
pub const HEAVY_EXIT_PCT: u64 = 25; // LEAVE HEAVY: IDLE > 25%
pub const LIGHT_ENTER_PCT: u64 = 50; // ENTER LIGHT: IDLE > 50%
pub const LIGHT_EXIT_PCT: u64 = 30; // LEAVE LIGHT: IDLE < 30%

// REGIME PROFILES
// PREEMPT_THRESH CONTROLS WHEN TICK PREEMPTS BATCH TASKS (IF INTERACTIVE WAITING).
// BATCH_SLICE_NS CONTROLS MAX UNINTERRUPTED BATCH RUN WHEN NO INTERACTIVE WAITING.
// CPU_BOUND_THRESH_NS CONTROLS DEMOTION THRESHOLD PER REGIME (FEATURE 5).

const LIGHT_SLICE_NS: u64 = 2_000_000; // 2MS
const LIGHT_PREEMPT_NS: u64 = 1_000_000; // 1MS: AGGRESSIVE
const LIGHT_LAG_SCALE: u64 = 6;
const LIGHT_BATCH_NS: u64 = 20_000_000; // 20MS: NO CONTENTION, LET BATCH RIP

const MIXED_SLICE_NS: u64 = 1_000_000; // 1MS: TIGHT INTERACTIVE CONTROL
const MIXED_PREEMPT_NS: u64 = 1_000_000; // 1MS: MATCH FOR CLEAN ENFORCEMENT
const MIXED_LAG_SCALE: u64 = 4;
const MIXED_BATCH_NS: u64 = 20_000_000; // 20MS: MATCHES LIGHT/HEAVY/BPF DEFAULT

const HEAVY_SLICE_NS: u64 = 4_000_000; // 4MS: WIDER FOR THROUGHPUT
const HEAVY_PREEMPT_NS: u64 = 2_000_000; // 2MS: SLIGHTLY RELAXED
const HEAVY_LAG_SCALE: u64 = 2;
const HEAVY_BATCH_NS: u64 = 20_000_000; // 20MS: LET BATCH RIP

// P99 CEILINGS

const LIGHT_P99_CEIL_NS: u64 = 3_000_000; // 3MS
const MIXED_P99_CEIL_NS: u64 = 5_000_000; // 5MS: BELOW 16MS FRAME BUDGET
const HEAVY_P99_CEIL_NS: u64 = 10_000_000; // 10MS: HEAVY LOAD, REALISTIC

// CPU-BOUND DEMOTION THRESHOLDS
// PER-REGIME: LENIENT IN LIGHT, AGGRESSIVE IN HEAVY

pub const LIGHT_DEMOTION_NS: u64 = 3_500_000; // 3.5MS: LENIENT, FEW CONTEND
pub const MIXED_DEMOTION_NS: u64 = 2_500_000; // 2.5MS: CURRENT CPU_BOUND_THRESH_NS
pub const HEAVY_DEMOTION_NS: u64 = 2_000_000; // 2.0MS: AGGRESSIVE

// CLASSIFIER THRESHOLDS
// LAT_CRI SCORE BOUNDARIES FOR TIER CLASSIFICATION
// EXPOSED AS TUNING KNOBS FOR RUNTIME ADJUSTMENT

pub const DEFAULT_LAT_CRI_THRESH_HIGH: u64 = 32; // >= THIS: LAT_CRITICAL
pub const DEFAULT_LAT_CRI_THRESH_LOW: u64 = 8; // >= THIS: INTERACTIVE, BELOW: BATCH

// TUNING KNOBS
// MATCHES struct tuning_knobs IN BPF (intf.h)

// AFFINITY MODE: L2 PLACEMENT STRENGTH
pub const AFFINITY_OFF: u64 = 0;
pub const AFFINITY_WEAK: u64 = 1;
pub const AFFINITY_STRONG: u64 = 2;

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
    pub affinity_mode: u64,
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
            affinity_mode: AFFINITY_OFF,
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
            affinity_mode: AFFINITY_WEAK,
        },
        Regime::Mixed => TuningKnobs {
            slice_ns: MIXED_SLICE_NS,
            preempt_thresh_ns: MIXED_PREEMPT_NS,
            lag_scale: MIXED_LAG_SCALE,
            batch_slice_ns: MIXED_BATCH_NS,
            cpu_bound_thresh_ns: MIXED_DEMOTION_NS,
            lat_cri_thresh_high: DEFAULT_LAT_CRI_THRESH_HIGH,
            lat_cri_thresh_low: DEFAULT_LAT_CRI_THRESH_LOW,
            affinity_mode: AFFINITY_STRONG,
        },
        Regime::Heavy => TuningKnobs {
            slice_ns: HEAVY_SLICE_NS,
            preempt_thresh_ns: HEAVY_PREEMPT_NS,
            lag_scale: HEAVY_LAG_SCALE,
            batch_slice_ns: HEAVY_BATCH_NS,
            cpu_bound_thresh_ns: HEAVY_DEMOTION_NS,
            lat_cri_thresh_high: DEFAULT_LAT_CRI_THRESH_HIGH,
            lat_cri_thresh_low: DEFAULT_LAT_CRI_THRESH_LOW,
            affinity_mode: AFFINITY_WEAK,
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

// STABILITY MODE

pub const STABILITY_THRESHOLD: u32 = 10; // CONSECUTIVE STABLE TICKS BEFORE HIBERNATE

pub fn compute_stability_score(
    prev_score: u32,
    regime_changed: bool,
    guard_clamps: u64,
    reflex_events_delta: u64,
    p99_ns: u64,
    p99_ceiling_ns: u64,
) -> u32 {
    if regime_changed || guard_clamps > 0 || reflex_events_delta > 0 || p99_ns > p99_ceiling_ns / 2
    {
        return 0;
    }
    (prev_score + 1).min(STABILITY_THRESHOLD)
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
    10_000,     // 10us
    25_000,     // 25us
    50_000,     // 50us
    100_000,    // 100us
    250_000,    // 250us
    500_000,    // 500us
    1_000_000,  // 1ms
    2_000_000,  // 2ms
    5_000_000,  // 5ms
    10_000_000, // 10ms
    20_000_000, // 20ms
    u64::MAX,   // +inf
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

// SLEEP-INFORMED BATCH TUNING
// IO-HEAVY: EXTEND BATCH SLICES (+25%) -- IO-BOUND TASKS BATCH BETWEEN FREQUENT SHORT SLEEPS
// IDLE-HEAVY: TIGHTEN BATCH SLICES (-25%) -- SPORADIC USER INPUT NEEDS FASTER PREEMPTION

pub const BATCH_MAX_NS: u64 = 25_000_000; // 25MS CEILING

pub fn sleep_adjust_batch_ns(base_batch_ns: u64, io_pct: u64) -> u64 {
    if io_pct > 60 {
        // IO-HEAVY: EXTEND BATCH SLICES (+25%)
        (base_batch_ns * 5 / 4).min(BATCH_MAX_NS)
    } else if io_pct < 15 {
        // IDLE-HEAVY: TIGHTEN BATCH SLICES (-25%)
        (base_batch_ns * 3 / 4).max(base_batch_ns / 2)
    } else {
        base_batch_ns
    }
}

// CONTENTION RESPONSE
// DETECTS INTERACTIVE STARVATION FROM GUARD CLAMPS, KICK RATIOS, AND DSQ DEPTH.
// CUTS BATCH SLICE TO REDUCE QUEUE PRESSURE WHEN CONTENTION PERSISTS.

pub const GUARD_CLAMP_THRESH: u64 = 10;
pub const KICK_RATIO_THRESH: u64 = 30;
pub const DSQ_DEPTH_THRESH: u64 = 4;
pub const CONTENTION_HOLD_TICKS: u32 = 3;
pub const CONTENTION_BATCH_CUT_PCT: u64 = 75;

pub fn detect_contention(
    guard_clamps: u64,
    hard_kicks: u64,
    dispatches: u64,
    avg_dsq_depth: u64,
) -> bool {
    let kick_pct = if dispatches > 0 {
        hard_kicks * 100 / dispatches
    } else {
        0
    };
    guard_clamps > GUARD_CLAMP_THRESH
        || kick_pct > KICK_RATIO_THRESH
        || avg_dsq_depth > DSQ_DEPTH_THRESH
}

pub fn contention_adjust_batch_ns(
    current_batch_ns: u64,
    baseline_batch_ns: u64,
    contention_ticks: u32,
) -> (u64, u32) {
    if contention_ticks >= CONTENTION_HOLD_TICKS {
        let cut = current_batch_ns * CONTENTION_BATCH_CUT_PCT / 100;
        let floor = baseline_batch_ns / 2;
        (cut.max(floor), 0)
    } else {
        (current_batch_ns, contention_ticks)
    }
}
