// PANDEMONIUM TUNING TYPES
// PURE-RUST MODULE: ZERO BPF DEPENDENCIES
// SHARED BETWEEN BINARY CRATE (scheduler.rs, adaptive.rs) AND LIB CRATE (tests)

// REGIME THRESHOLDS (CHAOS-DRIVEN BANDS)
// THESE TWO THRESHOLDS DEFINE THE HIGH/LOW BANDS OF mean_idle_pct USED BY THE CHAOS-DRIVEN
// REGIME DETECTOR: BOTH ENTRY AND EXIT GO THROUGH THE SAME WINDOWED
// MEAN, AND THE HVG/BP PRIMITIVES DECIDE WHEN ORDER IS SUFFICIENT TO
// LATCH LIGHT OR HEAVY (OTHERWISE MIXED).

pub const HEAVY_ENTER_PCT: u64 = 10; // mean_idle <= THIS BAND -> CANDIDATE HEAVY
pub const LIGHT_ENTER_PCT: u64 = 50; // mean_idle >= THIS BAND -> CANDIDATE LIGHT

// REGIME PROFILES
// PREEMPT_THRESH CONTROLS WHEN TICK PREEMPTS BATCH TASKS (IF INTERACTIVE WAITING).
// BATCH_SLICE_NS CONTROLS MAX UNINTERRUPTED BATCH RUN WHEN NO INTERACTIVE WAITING.
// CPU_BOUND_THRESH_NS CONTROLS DEMOTION THRESHOLD PER REGIME (FEATURE 5).

const MIXED_SLICE_NS: u64 = 1_000_000; // 1MS: TIGHT INTERACTIVE CONTROL
const MIXED_PREEMPT_NS: u64 = 1_000_000; // 1MS: MATCH FOR CLEAN ENFORCEMENT
const MIXED_BATCH_NS: u64 = 20_000_000; // 20MS: MATCHES LIGHT/HEAVY/BPF DEFAULT

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
// Unused since the coupling->affinity derivation was withdrawn 2026-08-05.
// Kept: it is half of a two-value ABI the BPF side still reads, and a knob that
// can only ever hold one of its values is a defect waiting to be re-found.
#[allow(dead_code)]
pub const AFFINITY_STRONG: u64 = 2;

// SPILL TEMPERATURE (SPILL-Phi). T = T_base*(1 + kappa*H), H THE Bandt-Pompe
// PERMUTATION ENTROPY IN [0,1]; Q16 FIXED-POINT (65536 = T_base = 1.0).
// COMPUTED EACH ADAPTIVE TICK FROM THE CHAOS LAYER, SHIPPED AS A NON-MWU KNOB
// OVERLAID LIKE topology_tau_ns. INERT UNTIL THE SPILL PRICE CONSUMES IT.
pub const SPILL_TEMP_BASE_Q16: u64 = 65536;
pub const SPILL_TEMP_KAPPA: f64 = 1.0;

pub fn spill_temp_q16(h: f64) -> u64 {
    let h = h.clamp(0.0, 1.0);
    ((SPILL_TEMP_BASE_Q16 as f64) * (1.0 + SPILL_TEMP_KAPPA * h)) as u64
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct TuningKnobs {
    pub slice_ns: u64,
    pub preempt_thresh_ns: u64,
    pub batch_slice_ns: u64,
    pub lat_cri_thresh_high: u64,
    pub lat_cri_thresh_low: u64,
    pub affinity_mode: u64,
    pub codel_thresh_ns: u64,
    pub burst_slice_ns: u64,
    // FIEDLER-DERIVED TOPOLOGY TIME CONSTANT (TAU_SCALE_NS / lambda_2).
    // ZERO MEANS RUST HAS NOT YET WRITTEN tau; BPF USES THE PRE-FIRST-TICK
    // FALLBACK CONSTANTS UNTIL A NONZERO VALUE LANDS. WRITTEN BY RUST AT
    // TOPOLOGY DETECT AND ON HOTPLUG; READ BY BPF AT THE FIRST CPU-0 TICK.
    pub topology_tau_ns: u64,
    // R_eff-DERIVED CODEL EQUILIBRIUM TARGET (<R_eff> * 2m * tau).
    // CO-LOCATED WITH topology_tau_ns; SAME ZERO/WRITE/CLAMP SEMANTICS.
    pub codel_eq_ns: u64,
    pub spill_temp_q16: u64,
}

impl Default for TuningKnobs {
    fn default() -> Self {
        Self {
            slice_ns: 1_000_000,
            preempt_thresh_ns: 1_000_000,
            batch_slice_ns: 20_000_000,
            lat_cri_thresh_high: DEFAULT_LAT_CRI_THRESH_HIGH,
            lat_cri_thresh_low: DEFAULT_LAT_CRI_THRESH_LOW,
            affinity_mode: AFFINITY_OFF,
            codel_thresh_ns: 5_000_000,
            burst_slice_ns: 1_000_000,
            topology_tau_ns: 0,
            codel_eq_ns: 0,
            spill_temp_q16: SPILL_TEMP_BASE_Q16,
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

pub fn base_knobs() -> TuningKnobs {
    TuningKnobs {
        slice_ns: MIXED_SLICE_NS,
        preempt_thresh_ns: MIXED_PREEMPT_NS,
        batch_slice_ns: MIXED_BATCH_NS,
        lat_cri_thresh_high: DEFAULT_LAT_CRI_THRESH_HIGH,
        lat_cri_thresh_low: DEFAULT_LAT_CRI_THRESH_LOW,
        affinity_mode: AFFINITY_WEAK,
        codel_thresh_ns: 5_000_000,
        burst_slice_ns: 1_000_000,
        topology_tau_ns: 0,
        codel_eq_ns: 0,
        spill_temp_q16: SPILL_TEMP_BASE_Q16,
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

#[inline]
fn scale_tau_u64(tau_ns: u64, k_q16: u64) -> u64 {
    (tau_ns as u128 * k_q16 as u128 >> 16) as u64
}

pub fn scaled_regime_knobs(r: Regime, nr_cpus: u64, tau_ns: u64) -> TuningKnobs {
    let mut knobs = base_knobs();

    let slice_cap_tau = scale_tau_u64(tau_ns, K_SLICE_CAP_Q16).clamp(500_000, 8_000_000);
    let preempt_cap_tau = scale_tau_u64(tau_ns, K_PREEMPT_CAP_Q16).clamp(250_000, 4_000_000);
    let sojourn_tau = scale_tau_u64(tau_ns, K_SOJOURN_Q16).clamp(2_000_000, 6_000_000);

    knobs.slice_ns = knobs.slice_ns.min(slice_cap_tau);
    knobs.preempt_thresh_ns = knobs.preempt_thresh_ns.min(preempt_cap_tau);

    // LOW-CORE SLICE CAP. tau IS LARGEST AT LOW CORE COUNT (lambda_2 SHRINKS
    // AS CORES DROP), SO THE tau SLICE CAP ABOVE IS LOOSEST EXACTLY WHERE A
    // WIDE BATCH SLICE DOES THE MOST DAMAGE: ON 2-4 CORES THE HEAVY PROFILE'S
    // 4ms SLICE DENIES A LATENCY-SENSITIVE PROBE ACROSS MANY CONSECUTIVE
    // SLICES, PRODUCING THE 50-200ms LONG-RUN/MIXED P99 TAIL AT LOW CORE.
    // idle_pct READS LOW AT LOW CORE COUNT -- BECAUSE THE
    // BPF WARM-STAY/PER-CPU LANDING DELIBERATELY BYPASSES THE IDLE FAST PATH
    // -- SO THE REGIME FALSELY LATCHES HEAVY AND INHERITS ITS 4ms SLICE. THE
    // BPF BASELINE RUNS 1ms HERE WITH NO SUCH TAIL, AND THE LONG-RUN WORK
    // NUMBERS SHOW THE WIDE SLICE BUYS NO THROUGHPUT ON SO FEW CORES. CAP THE
    // SLICE TO THE MIXED VALUE AT <=4 CORES; 8C/12C (WHERE ADAPTIVE WINS AND
    // THE WIDER SLICE EARNS THROUGHPUT) ARE UNTOUCHED.
    if nr_cpus <= 4 {
        knobs.slice_ns = knobs.slice_ns.min(MIXED_SLICE_NS);
    }
    if matches!(r, Regime::Mixed) {
        let batch_cap_tau = scale_tau_u64(tau_ns, K_BATCH_CAP_Q16).clamp(10_000_000, 80_000_000);
        knobs.batch_slice_ns = knobs.batch_slice_ns.min(batch_cap_tau);
    }
    knobs.codel_thresh_ns = sojourn_tau;

    knobs
}

// REGIME DETECTION (CHAOS-DRIVEN)
// REGIME IS A FUNCTION OF:
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

// OSCILLATOR STATE, READ FROM BPF
// The BPF damped-harmonic oscillator owns codel_target_ns. The adaptive layer
// reads its position so nothing upstream re-derives a target the oscillator is
// already moving.
#[allow(dead_code)]
#[derive(Default, Clone, Copy, Debug)]
pub struct OscillatorState {
    pub codel_target_ns: u64,
    pub codel_target_floor_ns: u64,
    pub codel_target_max_ns: u64,
    // HOME NEAREST-PEER PHI HOLD (reff_value SLOT 0, ns). THE BPF WARM-STAY
    // AND STEP-1 R_eff STEAL RELEASE AT codel_target_ns + THIS, NOT AT THE
    // BARE CODEL WINDOW. position() MEASURES THE BARE WINDOW; THE ABSOLUTE
    // CHECKS BELOW ADD THIS TERM SO THE DEFER DECISION IS TAKEN AGAINST THE
    // EFFECTIVE PHI RELEASE POINT THE BPF ACTUALLY USES. 0 = READBACK
    // UNAVAILABLE -> TREATED AS NO EXTRA HOLD (NEUTRAL).
    pub home_dist_extra_ns: u64,
}

impl OscillatorState {
    // 0.0 = AT FLOOR (TIGHTENED), 1.0 = AT MAX (RELAXED).
    // SENTINEL OR DEGENERATE RANGE -> 0.5 (CENTER, NEUTRAL).
    #[allow(dead_code)]
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

    // EFFECTIVE PHI RELEASE POINT: WHERE WARM-STAY / STEP-1 STEAL ACTUALLY LET
    // A TASK LEAVE HOME (codel_target + NEAREST-PEER HOLD). THE DEFER GATE
    // COMPARES THIS AGAINST codel_eq TO DECIDE WHETHER THE BPF HAS GENUINELY
    // RESPONDED, RATHER THAN TRUSTING THE BARE-WINDOW position() ALONE.
    #[allow(dead_code)]
    pub fn effective_release_ns(&self) -> u64 {
        self.codel_target_ns.saturating_add(self.home_dist_extra_ns)
    }
}

// QUIESCENCE GATE
// Latches a "frozen" flag telling the monitor loop the machine is steady. The
// loop still ticks at 1 Hz; the chaos sensors are the exit condition.
//
// The third term used to be MWU weight-vector convergence. With no learner
// there is nothing to converge, so the gate is the chaos band alone -- which
// makes the saturation hole (a flat idle_pct window reads lambda ~2 and DET
// 1.0, both in band) the only thing standing between a pegged box and a frozen
// loop. Replacing this with an occupancy predicate over per-CPU queue depth is
// the open item; the graph now supplies the depth series it needs.
pub const QUIESCE_ENTER_TICKS: u32 = 4;

pub struct QuiescenceState {
    in_band_streak: u32,
    frozen: bool,
}

impl Default for QuiescenceState {
    fn default() -> Self {
        Self::new()
    }
}

impl QuiescenceState {
    pub const fn new() -> Self {
        Self {
            in_band_streak: 0,
            frozen: false,
        }
    }

    // ADVANCE THE GATE ONE TICK. RETURNS THE LATCHED `frozen` FLAG.
    // rqa_det IS None WHEN THE WINDOW IS NOT YET FULL -- THAT NEVER
    // COUNTS AS IN-BAND (NEVER FREEZE ON INSUFFICIENT DATA).
    pub fn update(&mut self, hvg_lambda: f64, rqa_det: Option<f64>, mwu_converged: bool) -> bool {
        let in_band = hvg_lambda <= crate::chaos::HVG_LAMBDA_PERIODIC_MAX
            && rqa_det.map_or(false, |d| d >= crate::chaos::RQA_DET_STEADY_MIN)
            && mwu_converged;

        if in_band {
            self.in_band_streak = self.in_band_streak.saturating_add(1);
            if self.in_band_streak >= QUIESCE_ENTER_TICKS {
                self.frozen = true;
            }
        } else {
            self.in_band_streak = 0;
            self.frozen = false;
        }
        self.frozen
    }
}

// ADAPTIVE-RARITY RETUNE INTERVAL
// WHEN THE ORCHESTRATOR IS NOT FROZEN BUT A RETUNE PRODUCES ONLY A
// SUB-THRESHOLD KNOB DELTA, STRETCH THE INTERVAL BETWEEN RETUNES x1.5
// (UP TO A FORCED CEILING) SO THE LOOP CONVERGES TOWARD QUIESCENCE.
// ANY DISTURBANCE SNAPS IT BACK TO THE BASE INTERVAL.

pub const RETUNE_INTERVAL_BASE: u32 = 1;
pub const RETUNE_INTERVAL_MAX: u32 = 8;

pub fn next_retune_interval(cur: u32, sub_threshold: bool, disturbed: bool) -> u32 {
    if disturbed {
        RETUNE_INTERVAL_BASE
    } else if sub_threshold {
        // x1.5 STRETCH, BUT ALWAYS GROW BY AT LEAST 1 -- INTEGER x1.5
        // OF THE BASE INTERVAL (1) WOULD OTHERWISE STALL AT 1.
        let stretched = (cur.saturating_mul(3) / 2).max(cur + 1);
        stretched.clamp(RETUNE_INTERVAL_BASE, RETUNE_INTERVAL_MAX)
    } else {
        cur
    }
}

// COMMIT-ON-CHANGE: TRUE IFF THE TWO KNOB SETS DIFFER ON ANY
// MWU-OWNED FIELD. topology_tau_ns / codel_eq_ns ARE EXCLUDED -- THEY
// ARE OWNED BY THE TOPOLOGY LAYER AND WRITTEN INDEPENDENTLY VIA
// write_topology_fields(); INCLUDING THEM WOULD SPURIOUSLY TRIP THE
// DIFF EVERY TICK THE LOOP OVERLAYS THEM.
pub fn knobs_differ(a: &TuningKnobs, b: &TuningKnobs) -> bool {
    a.slice_ns != b.slice_ns
        || a.preempt_thresh_ns != b.preempt_thresh_ns
        || a.batch_slice_ns != b.batch_slice_ns
        || a.lat_cri_thresh_high != b.lat_cri_thresh_high
        || a.lat_cri_thresh_low != b.lat_cri_thresh_low
        || a.affinity_mode != b.affinity_mode
        || a.codel_thresh_ns != b.codel_thresh_ns
        || a.burst_slice_ns != b.burst_slice_ns
}
