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
    pub sojourn_thresh_ns: u64,
    pub burst_slice_ns: u64,
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
            sojourn_thresh_ns: 5_000_000,
            burst_slice_ns: 1_000_000,
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
            sojourn_thresh_ns: 5_000_000,
            burst_slice_ns: 1_000_000,
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
            sojourn_thresh_ns: 5_000_000,
            burst_slice_ns: 1_000_000,
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
            sojourn_thresh_ns: 5_000_000,
            burst_slice_ns: 1_000_000,
        },
    }
}

// CORE-COUNT-AWARE REGIME KNOBS
// AT LOW CORE COUNTS, TIME SLICES MUST BE SHORTER TO MAINTAIN ADEQUATE
// DISPATCH FREQUENCY. HEAVY AT 2C WITH 4MS SLICES = 250 DISPATCHES/S/CORE,
// TOO COARSE FOR DEADLINE AND IPC WORKLOADS.
// SCALE: slice = min(BASE, nr_cpus * 500US), preempt = min(BASE, nr_cpus * 250US).
// MIXED ALSO SCALES: BATCH_SLICE CAPS AT nr_cpus * 5MS (2C: 10MS VS 20MS BASE).

pub fn scaled_regime_knobs(r: Regime, nr_cpus: u64) -> TuningKnobs {
    let mut knobs = regime_knobs(r);
    match r {
        Regime::Heavy | Regime::Light => {
            let slice_cap = nr_cpus * 500_000;
            let preempt_cap = (nr_cpus * 250_000).max(1_000_000);
            knobs.slice_ns = knobs.slice_ns.min(slice_cap);
            knobs.preempt_thresh_ns = knobs.preempt_thresh_ns.min(preempt_cap);
        }
        Regime::Mixed => {
            let slice_cap = nr_cpus * 500_000;
            let preempt_cap = nr_cpus * 500_000;
            knobs.slice_ns = knobs.slice_ns.min(slice_cap);
            knobs.preempt_thresh_ns = knobs.preempt_thresh_ns.min(preempt_cap);
            let batch_cap = nr_cpus * 5_000_000;
            knobs.batch_slice_ns = knobs.batch_slice_ns.min(batch_cap);
        }
    }
    // SOJOURN FLOOR: CPU-SCALED, SAME FORMULA THE OLD EWMA USED AS ITS FLOOR
    knobs.sojourn_thresh_ns = (nr_cpus * 1_000_000).clamp(2_000_000, 6_000_000);
    knobs
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
    reflex_events_delta: u64,
    p99_ns: u64,
    p99_ceiling_ns: u64,
) -> u32 {
    if regime_changed || reflex_events_delta > 0 || p99_ns > p99_ceiling_ns / 2 {
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
#[allow(dead_code)]
pub fn should_reflex_tighten(aggregate_p99: u64, interactive_p99: u64, ceiling: u64) -> bool {
    aggregate_p99 > ceiling || interactive_p99 > ceiling
}

// SLEEP-INFORMED BATCH TUNING
// IO-HEAVY: EXTEND BATCH SLICES (+25%) -- IO-BOUND TASKS BATCH BETWEEN FREQUENT SHORT SLEEPS
// IDLE-HEAVY: TIGHTEN BATCH SLICES (-25%) -- SPORADIC USER INPUT NEEDS FASTER PREEMPTION

#[allow(dead_code)]
pub const BATCH_MAX_NS: u64 = 25_000_000; // 25MS CEILING

#[allow(dead_code)]
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

// MWU ORCHESTRATOR
// SCHMITT-GATED MULTIPLICATIVE WEIGHT UPDATES ACROSS ALL 11 TUNING KNOBS.
// 6 EXPERT PROFILES, EACH A SCALE FACTOR ON THE REGIME BASELINE.
// CORRECTED SCALE FACTORS: sum(EQ[i] * SCALE[i]) = 1.0 FOR EACH CONTINUOUS KNOB.
// DISCRETE KNOBS (LAG, AFFINITY, DEPTH) USE MAJORITY VOTE, NOT WEIGHTED AVERAGE.
// 4 LOSS PATHWAYS: P99 SPIKE, RESCUE DELTA, IO DELTA, FORK STORM.
// 1e-6 WEIGHT FLOOR PREVENTS UNDERFLOW (DEAD WEIGHTS CAN'T RECOVER).

const N_EXPERTS: usize = 6;
const ETA: f64 = 8.0;
const RELAX_RATE: f64 = 0.80;
const SPIKE_CONFIRM: u32 = 2;
const RELAX_HOLD: u32 = 2;
const RELAX_CEIL_PCT: f64 = 0.70;
const EQUILIBRIUM: [f64; N_EXPERTS] = [0.08, 0.44, 0.12, 0.12, 0.12, 0.12];
const WEIGHT_FLOOR: f64 = 1e-6;

const EX_LATENCY: usize = 0;
const EX_BALANCED: usize = 1;
const EX_THROUGHPUT: usize = 2;
const EX_IO_HEAVY: usize = 3;
const EX_FORK_STORM: usize = 4;
const EX_SATURATED: usize = 5;

// CORRECTED CONTINUOUS SCALE FACTORS
// PROPORTIONALLY ADJUSTED SO sum(EQ[i] * SCALE[i]) = 1.0 AT EQUILIBRIUM.
// [LATENCY, BALANCED, THROUGHPUT, IO_HEAVY, FORK_STORM, SATURATED]
const SC_SLICE: [f64; 6] = [0.74, 1.00, 1.23, 0.98, 0.49, 1.47];
const SC_PREEMPT: [f64; 6] = [0.74, 1.00, 1.23, 0.98, 0.49, 1.47];
const SC_BATCH: [f64; 6] = [0.78, 1.00, 1.30, 1.30, 0.52, 1.04];
const SC_DEMOTE: [f64; 6] = [0.86, 1.00, 1.29, 1.08, 0.86, 0.86];
const SC_LCRI_HI: [f64; 6] = [0.74, 1.00, 1.23, 0.98, 0.98, 0.98];
const SC_LCRI_LO: [f64; 6] = [0.70, 1.00, 1.40, 0.93, 0.93, 0.93];
const SC_SOJOURN: [f64; 6] = [0.80, 1.00, 1.60, 0.93, 0.53, 1.07];
const SC_BURST: [f64; 6] = [0.74, 1.00, 1.47, 0.98, 0.49, 1.23];

// DISCRETE KNOB VALUES (ABSOLUTE, NOT SCALE FACTORS)
const DV_LAG: [u64; 6] = [6, 4, 3, 4, 4, 3];
const DV_AFFINITY: [u64; 6] = [
    AFFINITY_STRONG,
    AFFINITY_STRONG,
    AFFINITY_WEAK,
    AFFINITY_WEAK,
    AFFINITY_OFF,
    AFFINITY_WEAK,
];
fn blend_continuous(base: u64, scales: &[f64; 6], w: &[f64; N_EXPERTS]) -> u64 {
    let v: f64 = (0..N_EXPERTS).map(|i| w[i] * base as f64 * scales[i]).sum();
    (v.round() as u64).max(1)
}

fn majority_discrete(values: &[u64; 6], w: &[f64; N_EXPERTS]) -> u64 {
    // GROUP BY VALUE, SUM WEIGHTS, PICK HIGHEST GROUP
    let mut best_val = values[0];
    let mut best_w = 0.0f64;
    for &v in values.iter() {
        let total: f64 = (0..N_EXPERTS)
            .filter(|&i| values[i] == v)
            .map(|i| w[i])
            .sum();
        if total > best_w {
            best_w = total;
            best_val = v;
        }
    }
    best_val
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum IoBucket {
    Low,
    Mid,
    High,
}

pub fn io_bucket(io_pct: u64) -> IoBucket {
    if io_pct > 60 {
        IoBucket::High
    } else if io_pct < 15 {
        IoBucket::Low
    } else {
        IoBucket::Mid
    }
}

pub struct MwuSignals {
    pub p99_ns: u64,
    pub interactive_p99_ns: u64,
    pub io_pct: u64,
    pub rescue_count: u64,
    pub wakeup_rate: u64,
}

pub struct MwuController {
    weights: [f64; N_EXPERTS],
    baseline: TuningKnobs,
    spike_streak: u32,
    healthy_streak: u32,
    fork_streak: u32,
    prev_io_bucket: IoBucket,
    prev_rescuing: bool,
    losses_applied: bool,
}

impl MwuController {
    pub fn new(baseline: TuningKnobs) -> Self {
        Self {
            weights: EQUILIBRIUM,
            baseline,
            spike_streak: 0,
            healthy_streak: 0,
            fork_streak: 0,
            prev_io_bucket: IoBucket::Mid,
            prev_rescuing: false,
            losses_applied: false,
        }
    }

    pub fn reset(&mut self) {
        self.weights = EQUILIBRIUM;
        self.spike_streak = 0;
        self.healthy_streak = 0;
        self.fork_streak = 0;
        self.prev_io_bucket = IoBucket::Mid;
        self.prev_rescuing = false;
        self.losses_applied = false;
    }

    pub fn set_baseline(&mut self, baseline: TuningKnobs) {
        self.baseline = baseline;
    }

    pub fn update(&mut self, sig: &MwuSignals, ceiling: u64, nr_cpus: u64) -> TuningKnobs {
        let worst = sig.p99_ns.max(sig.interactive_p99_ns);
        let above = worst > ceiling;
        let below_relax = (worst as f64) < (ceiling as f64 * RELAX_CEIL_PCT);

        let mut losses = [0.0f64; N_EXPERTS];
        let mut has_loss = false;

        // PATHWAY 1: P99 SPIKE (SCHMITT-GATED)
        if above {
            self.healthy_streak = 0;
            self.spike_streak += 1;
            if self.spike_streak >= SPIKE_CONFIRM {
                let v = ((worst - ceiling) as f64 / ceiling as f64).min(3.0);
                losses[EX_BALANCED] += v * 0.5;
                losses[EX_THROUGHPUT] += v * 1.0;
                losses[EX_IO_HEAVY] += v * 0.6;
                losses[EX_FORK_STORM] += v * 0.3;
                losses[EX_SATURATED] += v * 0.9;
                has_loss = true;
            }
        } else {
            self.spike_streak = 0;
        }

        // PATHWAY 2: RESCUE DELTA (0 -> NONZERO TRANSITION)
        // PATHWAY 2: RESCUE DELTA (0 -> NONZERO TRANSITION)
        // PENALIZE ALL EXPERTS EQUALLY: THE DAMPED OSCILLATION IN BPF
        // HANDLES TIGHTENING VIA THE CODEL TARGET. MWU SHOULD HOLD STEADY,
        // NOT COMPOUND BY ALSO TIGHTENING SLICES VIA LATENCY EXPERT.
        let rescuing = sig.rescue_count > 0;
        if rescuing && !self.prev_rescuing {
            let v = (sig.rescue_count as f64 * 1.5).min(3.0);
            losses[EX_LATENCY] += v * 0.4;
            losses[EX_THROUGHPUT] += v * 0.6;
            losses[EX_SATURATED] += v * 0.6;
            losses[EX_IO_HEAVY] += v * 0.4;
            losses[EX_BALANCED] += v * 0.2;
            has_loss = true;
        }
        self.prev_rescuing = rescuing;

        // PATHWAY 3: IO DELTA (BUCKET TRANSITION)
        let cur_io = io_bucket(sig.io_pct);
        if cur_io != self.prev_io_bucket {
            match cur_io {
                IoBucket::High => {
                    let v = ((sig.io_pct as f64 - 60.0) / 40.0).min(1.0);
                    for i in 0..N_EXPERTS {
                        if i != EX_IO_HEAVY {
                            losses[i] += v * 0.8;
                        }
                    }
                    has_loss = true;
                }
                IoBucket::Low => {
                    let v = ((15.0 - sig.io_pct as f64) / 15.0).clamp(0.0, 1.0);
                    losses[EX_IO_HEAVY] += v * 1.0;
                    has_loss = true;
                }
                IoBucket::Mid => {}
            }
        }
        self.prev_io_bucket = cur_io;

        // PATHWAY 4: FORK STORM (SCHMITT-GATED)
        let fork_storm = sig.wakeup_rate > nr_cpus * 2;
        if fork_storm {
            self.fork_streak += 1;
            if self.fork_streak >= SPIKE_CONFIRM {
                losses[EX_LATENCY] += 0.05;
                losses[EX_BALANCED] += 0.15;
                losses[EX_THROUGHPUT] += 0.30;
                losses[EX_IO_HEAVY] += 0.25;
                losses[EX_SATURATED] += 0.20;
                has_loss = true;
            }
        } else {
            self.fork_streak = 0;
        }

        // APPLY LOSSES WITH WEIGHT FLOOR
        if has_loss {
            for i in 0..N_EXPERTS {
                if losses[i] > 0.0 {
                    self.weights[i] *= (-ETA * losses[i]).exp();
                }
                if self.weights[i] < WEIGHT_FLOOR {
                    self.weights[i] = WEIGHT_FLOOR;
                }
            }
            let sum: f64 = self.weights.iter().sum();
            for w in self.weights.iter_mut() {
                *w /= sum;
            }
        }

        // RELAXATION
        if !has_loss && below_relax {
            self.healthy_streak += 1;
            if self.healthy_streak >= RELAX_HOLD {
                for i in 0..N_EXPERTS {
                    self.weights[i] =
                        (1.0 - RELAX_RATE) * self.weights[i] + RELAX_RATE * EQUILIBRIUM[i];
                }
            }
        } else if !has_loss {
            self.healthy_streak = 0;
        }

        self.losses_applied = has_loss;

        // BLEND: CONTINUOUS KNOBS VIA CORRECTED SCALE FACTORS, DISCRETE VIA MAJORITY
        let b = &self.baseline;
        TuningKnobs {
            slice_ns: blend_continuous(b.slice_ns, &SC_SLICE, &self.weights),
            preempt_thresh_ns: blend_continuous(b.preempt_thresh_ns, &SC_PREEMPT, &self.weights),
            lag_scale: majority_discrete(&DV_LAG, &self.weights),
            batch_slice_ns: blend_continuous(b.batch_slice_ns, &SC_BATCH, &self.weights),
            cpu_bound_thresh_ns: blend_continuous(b.cpu_bound_thresh_ns, &SC_DEMOTE, &self.weights),
            lat_cri_thresh_high: blend_continuous(
                b.lat_cri_thresh_high,
                &SC_LCRI_HI,
                &self.weights,
            ),
            lat_cri_thresh_low: blend_continuous(b.lat_cri_thresh_low, &SC_LCRI_LO, &self.weights),
            affinity_mode: majority_discrete(&DV_AFFINITY, &self.weights),
            sojourn_thresh_ns: blend_continuous(b.sojourn_thresh_ns, &SC_SOJOURN, &self.weights),
            burst_slice_ns: blend_continuous(b.burst_slice_ns, &SC_BURST, &self.weights),
        }
    }

    pub fn had_losses(&self) -> bool {
        self.losses_applied
    }

    pub fn scale(&self) -> f64 {
        let s: f64 = (0..N_EXPERTS).map(|i| self.weights[i] * SC_SLICE[i]).sum();
        s
    }
}
