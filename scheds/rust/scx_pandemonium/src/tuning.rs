// PANDEMONIUM TUNING TYPES
// PURE-RUST MODULE: ZERO BPF DEPENDENCIES
// SHARED BETWEEN BINARY CRATE (scheduler.rs, adaptive.rs) AND LIB CRATE (tests)

// REGIME THRESHOLDS (CHAOS-DRIVEN BANDS)
// THE SCHMITT-TRIGGER ENTER/EXIT PAIR IS GONE. THESE TWO THRESHOLDS
// DEFINE THE HIGH/LOW BANDS OF mean_idle_pct USED BY THE CHAOS-DRIVEN
// REGIME DETECTOR: BOTH ENTRY AND EXIT GO THROUGH THE SAME WINDOWED
// MEAN, AND THE HVG/BP PRIMITIVES DECIDE WHEN ORDER IS SUFFICIENT TO
// LATCH LIGHT OR HEAVY (OTHERWISE MIXED).

pub const HEAVY_ENTER_PCT: u64 = 10; // mean_idle <= THIS BAND -> CANDIDATE HEAVY
pub const LIGHT_ENTER_PCT: u64 = 50; // mean_idle >= THIS BAND -> CANDIDATE LIGHT

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
    pub lat_cri_thresh_high: u64,
    pub lat_cri_thresh_low: u64,
    pub affinity_mode: u64,
    pub sojourn_thresh_ns: u64,
    pub burst_slice_ns: u64,
    // FIEDLER-DERIVED TOPOLOGY TIME CONSTANT (TAU_SCALE_NS / lambda_2).
    // ZERO MEANS RUST HAS NOT YET WRITTEN tau; BPF USES THE PRE-FIRST-TICK
    // FALLBACK CONSTANTS UNTIL A NONZERO VALUE LANDS. WRITTEN BY RUST AT
    // TOPOLOGY DETECT AND ON HOTPLUG; READ BY BPF AT THE FIRST CPU-0 TICK.
    pub topology_tau_ns: u64,
    // R_eff-DERIVED CODEL EQUILIBRIUM TARGET (<R_eff> * 2m * tau).
    // CO-LOCATED WITH topology_tau_ns; SAME ZERO/WRITE/CLAMP SEMANTICS.
    pub codel_eq_ns: u64,
}

impl Default for TuningKnobs {
    fn default() -> Self {
        Self {
            slice_ns: 1_000_000,
            preempt_thresh_ns: 1_000_000,
            lag_scale: 4,
            batch_slice_ns: 20_000_000,
            lat_cri_thresh_high: DEFAULT_LAT_CRI_THRESH_HIGH,
            lat_cri_thresh_low: DEFAULT_LAT_CRI_THRESH_LOW,
            affinity_mode: AFFINITY_OFF,
            sojourn_thresh_ns: 5_000_000,
            burst_slice_ns: 1_000_000,
            topology_tau_ns: 0,
            codel_eq_ns: 0,
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
            lat_cri_thresh_high: DEFAULT_LAT_CRI_THRESH_HIGH,
            lat_cri_thresh_low: DEFAULT_LAT_CRI_THRESH_LOW,
            affinity_mode: AFFINITY_WEAK,
            sojourn_thresh_ns: 5_000_000,
            burst_slice_ns: 1_000_000,
            topology_tau_ns: 0,
            codel_eq_ns: 0,
        },
        Regime::Mixed => TuningKnobs {
            slice_ns: MIXED_SLICE_NS,
            preempt_thresh_ns: MIXED_PREEMPT_NS,
            lag_scale: MIXED_LAG_SCALE,
            batch_slice_ns: MIXED_BATCH_NS,
            lat_cri_thresh_high: DEFAULT_LAT_CRI_THRESH_HIGH,
            lat_cri_thresh_low: DEFAULT_LAT_CRI_THRESH_LOW,
            affinity_mode: AFFINITY_STRONG,
            sojourn_thresh_ns: 5_000_000,
            burst_slice_ns: 1_000_000,
            topology_tau_ns: 0,
            codel_eq_ns: 0,
        },
        Regime::Heavy => TuningKnobs {
            slice_ns: HEAVY_SLICE_NS,
            preempt_thresh_ns: HEAVY_PREEMPT_NS,
            lag_scale: HEAVY_LAG_SCALE,
            batch_slice_ns: HEAVY_BATCH_NS,
            lat_cri_thresh_high: DEFAULT_LAT_CRI_THRESH_HIGH,
            lat_cri_thresh_low: DEFAULT_LAT_CRI_THRESH_LOW,
            affinity_mode: AFFINITY_WEAK,
            sojourn_thresh_ns: 5_000_000,
            burst_slice_ns: 1_000_000,
            topology_tau_ns: 0,
            codel_eq_ns: 0,
        },
    }
}

// TAU-SCALED REGIME KNOBS
// CAPS DIMENSIONED AS Q16 FIXED-POINT MULTIPLIERS OF tau_ns. k_i CALIBRATED
// AGAINST THE 12C REFERENCE TOPOLOGY (tau ~= 40MS):
//   SLICE_CAP:   0.15 -> 6MS  AT tau=40MS
//   PREEMPT_CAP: 0.075 -> 3MS AT tau=40MS
//   BATCH_CAP:   1.5 -> 60MS  AT tau=40MS (Mixed ONLY)
//   SOJOURN:     0.15 -> 6MS  AT tau=40MS
// PER-CAP CLAMPS ARE SAFETY RAILS.
const K_SLICE_CAP_Q16: u64 = 9830; // 0.15
const K_PREEMPT_CAP_Q16: u64 = 4915; // 0.075
const K_BATCH_CAP_Q16: u64 = 98304; // 1.5
const K_SOJOURN_Q16: u64 = 9830; // 0.15

// FORK-STORM RAW-WAKE-RATE THRESHOLD. Q16 RATIO INTERPRETED AS
// "WAKES/SEC PER MS-OF-tau", SO scale_tau_u64(tau, K) PRODUCES
// THE TOTAL-WAKE THRESHOLD (NOT PER-CPU). AT THE 12C REFERENCE
// (tau=40MS) THE GATE FIRES AT ~8000 WAKE/S, TIGHTENING LINEARLY
// AT LOWER tau (1200/S AT 4C, 400/S AT THE 2C FLOOR).
const K_FORK_STORM_RATE_Q16: u64 = 13107; // 0.20
const FORK_STORM_RATE_FLOOR: u64 = 200; // HZ; CLAMPS BELOW tau=1MS

#[inline]
fn scale_tau_u64(tau_ns: u64, k_q16: u64) -> u64 {
    (tau_ns as u128 * k_q16 as u128 >> 16) as u64
}

pub fn scaled_regime_knobs(r: Regime, _nr_cpus: u64, tau_ns: u64) -> TuningKnobs {
    let mut knobs = regime_knobs(r);

    let slice_cap_tau = scale_tau_u64(tau_ns, K_SLICE_CAP_Q16).clamp(500_000, 8_000_000);
    let preempt_cap_tau = scale_tau_u64(tau_ns, K_PREEMPT_CAP_Q16).clamp(250_000, 4_000_000);
    let sojourn_tau = scale_tau_u64(tau_ns, K_SOJOURN_Q16).clamp(2_000_000, 6_000_000);

    knobs.slice_ns = knobs.slice_ns.min(slice_cap_tau);
    knobs.preempt_thresh_ns = knobs.preempt_thresh_ns.min(preempt_cap_tau);
    if matches!(r, Regime::Mixed) {
        let batch_cap_tau = scale_tau_u64(tau_ns, K_BATCH_CAP_Q16).clamp(10_000_000, 80_000_000);
        knobs.batch_slice_ns = knobs.batch_slice_ns.min(batch_cap_tau);
    }
    knobs.sojourn_thresh_ns = sojourn_tau;

    knobs
}

// REGIME DETECTION (CHAOS-DRIVEN)
// THE SCHMITT TRIGGER IS GONE. REGIME IS A FUNCTION OF:
//   - mean_idle_pct: WINDOWED MEAN OVER THE LAST N TICKS
//   - hvg_lambda:    HVG MEAN DEGREE OF THE idle_pct WINDOW
//   - bp_h:          BANDT-POMPE D=3 PERMUTATION ENTROPY OF THE WINDOW
// HYSTERESIS IS BUILT INTO THE WINDOW: SAMPLES MUST FLOW IN BEFORE THE
// MEAN MOVES. THE 2-TICK HOLD IN THE MONITOR LOOP STAYS AS ADDITIONAL
// SMOOTHING.
//
// LIGHT  := mean_idle HIGH  AND CHAOS-LOW (PERIODIC / IDLE-DOMINATED)
// HEAVY  := mean_idle LOW   AND CHAOS-LOW (PERIODIC / SATURATED)
// MIXED  := ANYTHING ELSE (REGIME IS UNSTABLE OR IN MID-BAND)
//
// THE chaos_low PREDICATE IS lambda < CHAOTIC_MIN OR bp_h < BP_H_HIGH.
// EITHER PRIMITIVE INDICATING ORDER IS ENOUGH; THEY MEASURE DIFFERENT
// THINGS (AMPLITUDE-AWARE VS AMPLITUDE-INVARIANT) AND THE FIRST TO
// FIRE LATCHES THE REGIME TO LIGHT/HEAVY INSTEAD OF MIXED.

pub fn detect_regime(mean_idle_pct: f64, hvg_lambda: f64, bp_h: f64) -> Regime {
    let chaos_low =
        hvg_lambda < crate::chaos::HVG_LAMBDA_CHAOTIC_MIN || bp_h < crate::chaos::BP_H_HIGH;

    if chaos_low && mean_idle_pct >= LIGHT_ENTER_PCT as f64 {
        Regime::Light
    } else if chaos_low && mean_idle_pct <= HEAVY_ENTER_PCT as f64 {
        Regime::Heavy
    } else {
        Regime::Mixed
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

// MWU ORCHESTRATOR
// MULTIPLICATIVE WEIGHT UPDATES ACROSS ALL 11 TUNING KNOBS.
// 6 EXPERT PROFILES, EACH A SCALE FACTOR ON THE REGIME BASELINE.
// CORRECTED SCALE FACTORS: sum(EQ[i] * SCALE[i]) = 1.0 FOR EACH CONTINUOUS KNOB.
// DISCRETE KNOBS (LAG, AFFINITY, DEPTH) USE MAJORITY VOTE, NOT WEIGHTED AVERAGE.
// 5 LOSS PATHWAYS: P99 SPIKE, RESCUE DELTA, IO DELTA, FORK STORM, CHAOS TRANSITION.
// 1e-6 WEIGHT FLOOR PREVENTS UNDERFLOW (DEAD WEIGHTS CAN'T RECOVER).
// PATHWAYS FIRE IMMEDIATELY -- NO SCHMITT-STYLE STREAK CONFIRMATION.

const N_EXPERTS: usize = 6;
const ETA: f64 = 8.0;
const RELAX_RATE: f64 = 0.80;
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
    // CHAOS PRIMITIVES (RAW-WINDOW DERIVED, NO EWMA, NO SCHMITT).
    // hvg_lambda     := HVG MEAN DEGREE OF THE idle_pct WINDOW
    // bp_h_delta     := bp_h(THIS TICK) - bp_h(PREVIOUS TICK), WHERE
    //                   bp_h IS BANDT-POMPE D=3 PERMUTATION ENTROPY ON
    //                   THE wakeup_rate WINDOW, NORMALIZED TO [0, 1].
    //                   POSITIVE = WORKLOAD ENTERED A MORE-DISORDERED
    //                   ORDINAL REGIME WITHIN THE LAST SECOND.
    pub hvg_lambda: f64,
    pub bp_h_delta: f64,
}

// SNAPSHOT OF THE BPF DAMPED-HARMONIC OSCILLATOR'S ADAPTIVE STATE.
// MWU READS THIS BEFORE COMPUTING PATHWAY LOSSES SO IT CAN AVOID
// DOUBLE-CORRECTING ON RESCUE PRESSURE: WHEN THE OSCILLATOR HAS
// ALREADY TIGHTENED codel_target_ns TOWARD THE FLOOR, BPF HAS
// RESPONDED -- MWU STAYS OUT. WHEN THE OSCILLATOR IS NEAR THE
// CEILING, NO RESCUE PRESSURE EXISTS FOR MWU TO AMPLIFY.
//
// ALL FIELDS ZERO = SENTINEL ("READBACK UNAVAILABLE / INIT") -> NO GATING.
#[derive(Clone, Copy, Debug, Default)]
pub struct OscillatorState {
    pub codel_target_ns: u64,
    pub codel_target_floor_ns: u64,
    pub codel_target_max_ns: u64,
}

impl OscillatorState {
    // 0.0 = AT FLOOR (TIGHTENED), 1.0 = AT MAX (RELAXED).
    // SENTINEL OR DEGENERATE RANGE -> 0.5 (CENTER, NEUTRAL).
    pub fn position(&self) -> f64 {
        if self.codel_target_max_ns == 0 || self.codel_target_floor_ns >= self.codel_target_max_ns {
            return 0.5;
        }
        let range = (self.codel_target_max_ns - self.codel_target_floor_ns) as f64;
        let pos = self
            .codel_target_ns
            .saturating_sub(self.codel_target_floor_ns) as f64;
        (pos / range).clamp(0.0, 1.0)
    }
}

pub struct MwuController {
    weights: [f64; N_EXPERTS],
    baseline: TuningKnobs,
    healthy_streak: u32,
    prev_io_bucket: IoBucket,
    prev_rescuing: bool,
    prev_lambda_chaotic: bool,
    losses_applied: bool,
}

impl MwuController {
    pub fn new(baseline: TuningKnobs) -> Self {
        Self {
            weights: EQUILIBRIUM,
            baseline,
            healthy_streak: 0,
            prev_io_bucket: IoBucket::Mid,
            prev_rescuing: false,
            prev_lambda_chaotic: false,
            losses_applied: false,
        }
    }

    pub fn reset(&mut self) {
        self.weights = EQUILIBRIUM;
        self.healthy_streak = 0;
        self.prev_io_bucket = IoBucket::Mid;
        self.prev_rescuing = false;
        self.prev_lambda_chaotic = false;
        self.losses_applied = false;
    }

    pub fn set_baseline(&mut self, baseline: TuningKnobs) {
        self.baseline = baseline;
    }

    pub fn update(
        &mut self,
        sig: &MwuSignals,
        ceiling: u64,
        _nr_cpus: u64,
        tau_ns: u64,
        osc: &OscillatorState,
    ) -> TuningKnobs {
        let worst = sig.p99_ns.max(sig.interactive_p99_ns);
        let above = worst > ceiling;
        let below_relax = (worst as f64) < (ceiling as f64 * RELAX_CEIL_PCT);

        // OSCILLATOR-AWARE GATING. THE BPF DAMPED OSCILLATOR ALREADY
        // CONSUMES global_rescue_count AND ADAPTS codel_target_ns ON
        // EVERY TICK. PATHWAYS THAT TRIGGER ON THE SAME RESCUE SIGNAL
        // (PATHWAY 2 RESCUE-DELTA, PATHWAY 4 FORK-STORM) SHOULD DEFER
        // TO IT WHEN THE OSCILLATOR HAS ALREADY MOVED -- OTHERWISE BOTH
        // CONTROLLERS PUSH IN THE SAME DIRECTION AND OVERSHOOT.
        //
        // POSITION 0.0 = TIGHTENED (FLOOR), 1.0 = RELAXED (MAX).
        // < 0.40 -> BPF HAS RESPONDED HEAVILY; SKIP RESCUE-DRIVEN LOSSES.
        // > 0.90 -> BPF SAYS QUIET; RESCUE BURSTS ARE STALE NOISE; SKIP.
        let osc_pos = osc.position();
        let osc_already_tight = osc_pos < 0.40;
        let osc_already_loose = osc_pos > 0.90;
        let defer_to_oscillator = osc_already_tight || osc_already_loose;

        let mut losses = [0.0f64; N_EXPERTS];
        let mut has_loss = false;

        // PATHWAY 1: P99 SPIKE (FIRES IMMEDIATELY)
        if above {
            self.healthy_streak = 0;
            let v = ((worst - ceiling) as f64 / ceiling as f64).min(3.0);
            losses[EX_BALANCED] += v * 0.5;
            losses[EX_THROUGHPUT] += v * 1.0;
            losses[EX_IO_HEAVY] += v * 0.6;
            losses[EX_FORK_STORM] += v * 0.3;
            losses[EX_SATURATED] += v * 0.9;
            has_loss = true;
        }

        // PATHWAY 2: RESCUE DELTA (0 -> NONZERO TRANSITION)
        // PATHWAY 2: RESCUE DELTA (0 -> NONZERO TRANSITION)
        // PENALIZE ALL EXPERTS EQUALLY: THE DAMPED OSCILLATION IN BPF
        // HANDLES TIGHTENING VIA THE CODEL TARGET. MWU SHOULD HOLD STEADY,
        // NOT COMPOUND BY ALSO TIGHTENING SLICES VIA LATENCY EXPERT.
        let rescuing = sig.rescue_count > 0;
        if rescuing && !self.prev_rescuing && !defer_to_oscillator {
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

        // PATHWAY 4: FORK STORM (PRESSURE-CONFIRMED, FIRES IMMEDIATELY).
        // GATE THRESHOLD IS TAU-DERIVED. sig.wakeup_rate IS THE RAW TOTAL
        // WAKES/SEC; scale_tau_u64(tau, K_FORK_STORM_RATE_Q16) PRODUCES
        // THE COMPARISON THRESHOLD. AT THE 12C REFERENCE (tau=40MS) THE
        // THRESHOLD IS ~8000/SEC; AT 4C IT TIGHTENS TO ~1200/SEC. A FORK
        // STORM ALSO REQUIRES ACTIVE RESCUES (rescue_count > 0) AS GROUND-
        // TRUTH PRESSURE -- THE PRESSURE PREDICATE IS THE CONFIRMATION;
        // NO ADDITIONAL STREAK COUNTER.
        //
        // FORK_STORM EXPERT (SC_SLICE=0.49, SC_PREEMPT=0.49, SC_BATCH=0.52,
        // SC_SOJOURN=0.53, SC_BURST=0.49) DOMINATES THE BLEND DURING A REAL
        // STORM, DRIVING burst_slice_ns / preempt_thresh_ns / sojourn_thresh_ns
        // / batch_slice_ns DOWN END-TO-END.
        let fork_thresh = scale_tau_u64(tau_ns, K_FORK_STORM_RATE_Q16).max(FORK_STORM_RATE_FLOOR);
        let fork_storm = sig.wakeup_rate > fork_thresh && sig.rescue_count > 0;
        if fork_storm && !defer_to_oscillator {
            let denom = fork_thresh.max(1) as f64;
            let v = ((sig.wakeup_rate as f64 / denom) - 1.0).clamp(0.0, 3.0);
            losses[EX_BALANCED] += v * 0.30;
            losses[EX_THROUGHPUT] += v * 1.00;
            losses[EX_IO_HEAVY] += v * 0.50;
            losses[EX_SATURATED] += v * 0.80;
            has_loss = true;
        }

        // PATHWAY 5: CHAOS TRANSITION (RAW-WINDOW, NO EWMA, NO SCHMITT)
        // FIRES WHEN THE WORKLOAD'S ORDINAL OR AMPLITUDE-DEGREE STRUCTURE
        // SHIFTS WITHIN THE LAST WINDOW. THE FAILED-PREDICTION INTERPRETATION
        // IS: WHICHEVER EXPERT IS CURRENTLY DOMINANT WAS PRICED FOR THE
        // PREVIOUS WINDOW; PENALIZE IT PROPORTIONAL TO THE TRANSITION SIZE
        // SO THE BLEND RAPIDLY RE-WEIGHTS TOWARD BALANCED / SATURATED.
        // EX_BALANCED IS EXEMPT (IT IS THE REGIME-AGNOSTIC BASELINE).
        //
        // GATE CONDITIONS (EITHER FIRES):
        //   - bp_h_delta > 0.10   (>10% NORMALIZED PERMUTATION-ENTROPY JUMP)
        //   - hvg_lambda CROSSED CHAOTIC_MIN UPWARD
        let bp_jump = sig.bp_h_delta > 0.10;
        let lambda_cross =
            sig.hvg_lambda >= crate::chaos::HVG_LAMBDA_CHAOTIC_MIN && !self.prev_lambda_chaotic;
        let chaos_transition = bp_jump || lambda_cross;
        if chaos_transition {
            // SIZE OF THE LOSS: SCALES WITH WHICHEVER GATE TRIGGERED HARDER.
            let v_bp = (sig.bp_h_delta / 0.10).clamp(0.0, 3.0);
            let v_l = if lambda_cross {
                ((sig.hvg_lambda - crate::chaos::HVG_LAMBDA_CHAOTIC_MIN)
                    / (4.0 - crate::chaos::HVG_LAMBDA_CHAOTIC_MIN))
                    .clamp(0.0, 1.5)
            } else {
                0.0
            };
            let v = v_bp.max(v_l);
            // FIND THE DOMINANT EXPERT (HIGHEST WEIGHT) AND PENALIZE IT.
            // EX_BALANCED IS EXEMPT.
            let mut dom_idx = EX_BALANCED;
            let mut dom_w = 0.0f64;
            for i in 0..N_EXPERTS {
                if i == EX_BALANCED {
                    continue;
                }
                if self.weights[i] > dom_w {
                    dom_w = self.weights[i];
                    dom_idx = i;
                }
            }
            if dom_idx != EX_BALANCED && dom_w > 0.0 {
                losses[dom_idx] += v * 0.8;
                has_loss = true;
            }
        }
        self.prev_lambda_chaotic = sig.hvg_lambda >= crate::chaos::HVG_LAMBDA_CHAOTIC_MIN;

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
        let blended_slice = blend_continuous(b.slice_ns, &SC_SLICE, &self.weights);
        let blended_burst = blend_continuous(b.burst_slice_ns, &SC_BURST, &self.weights);
        let mut blended_sojourn = blend_continuous(b.sojourn_thresh_ns, &SC_SOJOURN, &self.weights);

        // SOJOURN FLOOR: dispatch waterfall services aged overflow at
        // overflow_sojourn_rescue_ns (BPF-side, tau-clamped to [4ms, 10ms]).
        // tick() also kicks per-CPU DSQs whose oldest task has aged past
        // sojourn_thresh_ns. If MWU drives sojourn_thresh_ns below the
        // dispatch service window + one slice, every tick generates kicks
        // on per-CPU DSQs that the dispatcher will service on the next
        // dispatch anyway -- a kick storm. Floor against the worst-case
        // dispatch service window to prevent it.
        let sojourn_floor = 4_000_000u64.saturating_add(blended_slice);
        if blended_sojourn < sojourn_floor {
            blended_sojourn = sojourn_floor;
        }

        TuningKnobs {
            slice_ns: blended_slice,
            preempt_thresh_ns: blend_continuous(b.preempt_thresh_ns, &SC_PREEMPT, &self.weights),
            lag_scale: majority_discrete(&DV_LAG, &self.weights),
            batch_slice_ns: blend_continuous(b.batch_slice_ns, &SC_BATCH, &self.weights),
            lat_cri_thresh_high: blend_continuous(
                b.lat_cri_thresh_high,
                &SC_LCRI_HI,
                &self.weights,
            ),
            lat_cri_thresh_low: blend_continuous(b.lat_cri_thresh_low, &SC_LCRI_LO, &self.weights),
            affinity_mode: majority_discrete(&DV_AFFINITY, &self.weights),
            sojourn_thresh_ns: blended_sojourn,
            burst_slice_ns: blended_burst,
            // topology_tau_ns AND codel_eq_ns ARE OWNED BY THE TOPOLOGY LAYER;
            // MWU DOESN'T TOUCH THEM. THE MONITOR LOOP OVERLAYS THE LIVE BPF
            // VALUES BACK ONTO MWU'S OUTPUT BEFORE WRITING -- PASSTHROUGH.
            topology_tau_ns: 0,
            codel_eq_ns: 0,
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
