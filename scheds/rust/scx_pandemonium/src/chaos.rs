// PANDEMONIUM CHAOS PRIMITIVES
// PURE-RUST RAW-WINDOW STATISTICS USED BY THE ADAPTIVE LAYER.
//
// EVERY PUBLIC ITEM IN THIS MODULE IS PART OF THE CHAOS API SURFACE:
// SOME ARE CONSUMED BY THE BINARY (adaptive.rs), SOME BY TESTS, AND
// SOME ARE EXPORTED CONSTANTS FOR DIAGNOSTICS / FUTURE EXPANSION.
// CARGO'S DEAD-CODE LINT FIRES PER COMPILATION TARGET; SILENCE IT.
#![allow(dead_code)]

// EVERY MEASURE IS COMPUTED FROM THE RAW SAMPLE WINDOW EACH CALL. NO
// ACCUMULATOR CARRIES STATE BETWEEN TICKS.

// HVG MEAN DEGREE / HVG ENTROPY (LUQUE-LACASA 2009): TWO STATISTICS OF
// THE HORIZONTAL VISIBILITY GRAPH'S DEGREE DISTRIBUTION.
//   - MEAN DEGREE LAMBDA = <k>. IID RANDOM SEQUENCES SATURATE AT 4 - 2/N
//     (-> 4 IN THE LIMIT). PURELY PERIODIC SEQUENCES STAY NEAR 2.
//   - SHANNON ENTROPY S OVER THE DEGREE DISTRIBUTION. IID HAS THE EXACT
//     CLOSED FORM P(k) = (1/3)*(2/3)^(k-2), k >= 2, GIVING
//     S_IID = LN(3) + 2*LN(3/2) ~= 1.910.
// LN(3/2) IS THE CHARACTERISTIC EXPONENT OF THAT DISTRIBUTION, NOT AN
// ENTROPY THRESHOLD. LAMBDA IS THE PRIMARY REGIME DISCRIMINATOR AND
// ENTROPY THE CORROBORATOR.
//
// BANDT-POMPE PERMUTATION ENTROPY, D=3 (BANDT-POMPE 2002): SHANNON
// ENTROPY OF THE ORDINAL-PATTERN DISTRIBUTION OF LENGTH-3 SUB-WINDOWS,
// NORMALIZED TO [0, 1] BY LN(6). 0 IS MONOTONIC OR PERIODIC, 1 IS
// MAXIMALLY DISORDERED.
//
// THE TWO ARE COMPLEMENTARY. HVG ENTROPY IS AMPLITUDE-SENSITIVE;
// BANDT-POMPE IS AMPLITUDE-INVARIANT AND CAPTURES ORDINAL DYNAMICS.

use std::sync::atomic::{AtomicU64, Ordering};

// CRITICAL VALUES

// LN(3/2). IID HVG DEGREE-DISTRIBUTION CHARACTERISTIC EXPONENT.
// EXPOSED FOR DIAGNOSTICS / FUTURE USE; NOT USED AS A DIRECT THRESHOLD.
pub const HVG_LN_3_2: f64 = 0.405_465_108_108_164_4;

// HVG MEAN-DEGREE THRESHOLDS. IID RANDOM SATURATES AT 4 - 2/N; PURELY
// PERIODIC SEQUENCES STAY NEAR 2. THE TWO THRESHOLDS BELOW DEFINE A
// DEAD ZONE FOR THE MIXED REGIME. THE BAND ITSELF IS THE HYSTERESIS:
// A WINDOW MUST CROSS IT ENTIRELY TO CHANGE THE VERDICT.
pub const HVG_LAMBDA_PERIODIC_MAX: f64 = 2.6;
pub const HVG_LAMBDA_CHAOTIC_MIN: f64 = 3.4;

// IID-ASYMPTOTE HVG ENTROPY: LN(3) + 2*LN(3/2) ~= 1.910.
pub const HVG_S_IID: f64 = 1.910_543_686_807_036;

// BANDT-POMPE D=3 PATTERN COUNT.
pub const BP_D3_PATTERNS: usize = 6;

// LN(6): NORMALIZATION FACTOR FOR BP D=3 PERMUTATION ENTROPY.
const LN_BP_D3: f64 = 1.791_759_469_228_055;

// HIGH PERMUTATION-ENTROPY THRESHOLD. ABOVE THIS THE ORDINAL DYNAMICS
// LOOK MAXIMALLY DISORDERED ON THE WINDOW; THE ADAPTIVE LAYER USES IT
// AS A "WORKLOAD IS UNPREDICTABLE THIS WINDOW" SIGNAL.
pub const BP_H_HIGH: f64 = 0.85;

// RQA (RECURRENCE QUANTIFICATION ANALYSIS) DETERMINISM.
// DET IS THE FRACTION OF RECURRENCE POINTS THAT LIE ON DIAGONAL LINE
// SEGMENTS. A DETERMINISTIC / STEADY SIGNAL REVISITS PHASE-SPACE
// NEIGHBORHOODS ALONG DIAGONALS (DET -> 1); AN IID SIGNAL SCATTERS
// RECURRENCE POINTS WITH NO DIAGONAL STRUCTURE (DET -> 0).
// THE ADAPTIVE QUIESCENCE GATE PAIRS HIGH DET WITH HVG LAMBDA IN THE
// PERIODIC BAND TO DETECT "STOP RETUNING" STEADY STATE.

// DELAY-EMBEDDING DIMENSION. 3-D VECTORS WITH UNIT DELAY -- MATCHES
// THE D=3 ORDINAL SCALE USED BY BANDT-POMPE.
pub const RQA_EMBED_DIM: usize = 3;

// RECURRENCE THRESHOLD AS A FRACTION OF THE WINDOW STANDARD DEVIATION:
// eps = RQA_THRESH_STD_FRAC * sigma. 0.20 IS THE STANDARD RQA DEFAULT
// BAND FOR SHORT SERIES.
pub const RQA_THRESH_STD_FRAC: f64 = 0.20;

// MINIMUM DIAGONAL-LINE LENGTH COUNTED AS DETERMINISM (RQA l_min).
pub const RQA_LMIN: usize = 2;

// DET AT OR ABOVE THIS = DETERMINISTIC / STEADY. CONSUMED BY THE
// ADAPTIVE QUIESCENCE GATE.
pub const RQA_DET_STEADY_MIN: f64 = 0.90;

// BELOW THIS WINDOW FILL, rqa_det RETURNS None (INSUFFICIENT DATA --
// NEVER LET THE GATE FREEZE ON A HALF-FILLED WINDOW).
pub const RQA_MIN_SAMPLES: usize = 8;

// RAW WINDOW
// FIXED-SIZE RING BUFFER OF f64 SAMPLES. NO HEAP ALLOC AT STEADY STATE.
// SEMANTICS:
//   - PUSH IS O(1)
//   - SAMPLES ARE READ IN INSERTION ORDER (OLDEST FIRST)
//   - UNFILLED SLOTS ARE NOT YIELDED
//   - len() == 0 UNTIL FIRST PUSH; AT MOST N AFTER N PUSHES

#[derive(Clone, Debug)]
pub struct RawWindow<const N: usize> {
    buf: [f64; N],
    head: usize,
    filled: usize,
}

impl<const N: usize> Default for RawWindow<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> RawWindow<N> {
    pub const fn new() -> Self {
        Self {
            buf: [0.0; N],
            head: 0,
            filled: 0,
        }
    }

    pub fn push(&mut self, x: f64) {
        self.buf[self.head] = x;
        self.head = (self.head + 1) % N;
        if self.filled < N {
            self.filled += 1;
        }
    }

    pub fn len(&self) -> usize {
        self.filled
    }

    pub fn is_empty(&self) -> bool {
        self.filled == 0
    }

    pub fn capacity(&self) -> usize {
        N
    }

    // YIELD SAMPLES IN INSERTION ORDER (OLDEST -> NEWEST).
    pub fn iter(&self) -> RawWindowIter<'_, N> {
        let start = if self.filled < N { 0 } else { self.head };
        RawWindowIter {
            win: self,
            pos: 0,
            start,
        }
    }

    pub fn last(&self) -> Option<f64> {
        if self.filled == 0 {
            None
        } else {
            let i = (self.head + N - 1) % N;
            Some(self.buf[i])
        }
    }
}

pub struct RawWindowIter<'a, const N: usize> {
    win: &'a RawWindow<N>,
    pos: usize,
    start: usize,
}

impl<'a, const N: usize> Iterator for RawWindowIter<'a, N> {
    type Item = f64;
    fn next(&mut self) -> Option<f64> {
        if self.pos >= self.win.filled {
            return None;
        }
        let idx = (self.start + self.pos) % N;
        self.pos += 1;
        Some(self.win.buf[idx])
    }
}

// MEAN / MIN / MAX HELPERS

#[allow(dead_code)]
pub fn mean<const N: usize>(w: &RawWindow<N>) -> f64 {
    if w.filled == 0 {
        return 0.0;
    }
    let mut s = 0.0;
    for x in w.iter() {
        s += x;
    }
    s / w.filled as f64
}

// HORIZONTAL VISIBILITY GRAPH
//
// FOR A SEQUENCE x_1..x_N, NODES i AND j (i < j) ARE HVG-CONNECTED IFF
// x_k < min(x_i, x_j) FOR ALL i < k < j. ADJACENT NODES (j = i+1) ARE
// ALWAYS CONNECTED.
//
// hvg_degrees BUILDS THE DEGREE VECTOR ONCE; hvg_stats DERIVES BOTH
// LAMBDA AND ENTROPY FROM IT IN A SINGLE O(N^2) PASS.
//
// BRUTE-FORCE O(N^2). AT N <= 128 (>1-MINUTE WINDOW AT 1HZ) THIS IS
// UNDER 16K COMPARISONS, DONE ONCE PER SECOND.

fn hvg_degrees<const N: usize>(w: &RawWindow<N>) -> Option<([u32; N], usize)> {
    let n = w.filled;
    if n < 3 {
        return None;
    }

    let mut s: [f64; N] = [0.0; N];
    let mut k = 0;
    for x in w.iter() {
        s[k] = x;
        k += 1;
    }

    let mut deg: [u32; N] = [0; N];
    for i in 0..n {
        let mut blocker = f64::NEG_INFINITY;
        for j in (i + 1)..n {
            let limit = s[i].min(s[j]);
            if j == i + 1 || blocker < limit {
                deg[i] += 1;
                deg[j] += 1;
            }
            if s[j] > blocker {
                blocker = s[j];
            }
        }
    }
    Some((deg, n))
}

// AMORTIZED LAMBDA + ENTROPY. ONE O(N^2) PASS BUILDS THE DEGREE VECTOR;
// BOTH STATISTICS DERIVE FROM IT.
pub fn hvg_stats<const N: usize>(w: &RawWindow<N>) -> (f64, f64) {
    let (deg, n) = match hvg_degrees(w) {
        Some(v) => v,
        None => return (0.0, 0.0),
    };

    let mut sum: u64 = 0;
    let mut hist: [u32; N] = [0; N];
    for d in deg.iter().take(n) {
        sum += *d as u64;
        let bucket = (*d as usize).min(n - 1);
        hist[bucket] += 1;
    }
    let lambda = sum as f64 / n as f64;

    let total = n as f64;
    let mut entropy = 0.0;
    for c in hist.iter().take(n) {
        if *c == 0 {
            continue;
        }
        let p = *c as f64 / total;
        entropy -= p * p.ln();
    }
    (lambda, entropy)
}

// BANDT-POMPE PERMUTATION ENTROPY (D=3)
//
// SLIDE A LENGTH-3 WINDOW. FOR EACH (a, b, c) MAP TO ONE OF SIX ORDINAL
// PATTERNS BY THE RANK ORDER. BUILD THE EMPIRICAL DISTRIBUTION AND
// RETURN H / LN(6) IN [0, 1].
//
// TIES ARE BROKEN BY POSITION (b > a IFF b STRICTLY GREATER, ELSE a > b).
// IID RANDOM SAMPLES YIELD H ~= 1; PERIODIC OR MONOTONIC YIELD H << 1.
pub fn bandt_pompe_d3<const N: usize>(w: &RawWindow<N>) -> f64 {
    let n = w.filled;
    if n < 3 {
        return 0.0;
    }

    // INLINED RING WALK: WE NEED THREE CONSECUTIVE SAMPLES.
    let mut counts = [0u32; BP_D3_PATTERNS];
    let mut total = 0u32;

    // COLLECT INTO LINEAR BUFFER ONCE; SAFE FOR N <= 128.
    let mut s: [f64; N] = [0.0; N];
    let mut k = 0;
    for x in w.iter() {
        s[k] = x;
        k += 1;
    }

    for i in 0..(n - 2) {
        let a = s[i];
        let b = s[i + 1];
        let c = s[i + 2];
        // BREAK TIES BY POSITION (POSITIONAL ORDER WHEN VALUES EQUAL).
        let pattern = match (a < b, b < c, a < c) {
            (true, true, true) => 0,    // a < b < c
            (true, false, true) => 1,   // a < c <= b
            (true, false, false) => 2,  // c <= a < b
            (false, true, true) => 3,   // b <= a < c
            (false, true, false) => 4,  // b < c <= a
            (false, false, false) => 5, // c <= b <= a
            (true, true, false) => 1,   // DEGENERATE TIE: TREAT AS PATTERN 1
            (false, false, true) => 4,  // DEGENERATE TIE: TREAT AS PATTERN 4
        };
        counts[pattern] += 1;
        total += 1;
    }

    if total == 0 {
        return 0.0;
    }

    let denom = total as f64;
    let mut h = 0.0;
    for c in counts.iter() {
        if *c == 0 {
            continue;
        }
        let p = *c as f64 / denom;
        h -= p * p.ln();
    }
    h / LN_BP_D3
}

// RQA DETERMINISM (DET)
//
// DELAY-EMBED THE WINDOW INTO RQA_EMBED_DIM-D VECTORS WITH UNIT DELAY,
// BUILD THE RECURRENCE MATRIX UNDER A CHEBYSHEV (L-INFINITY) BALL OF
// RADIUS eps = RQA_THRESH_STD_FRAC * sigma, AND RETURN THE FRACTION OF
// OFF-DIAGONAL RECURRENCE POINTS THAT LIE ON DIAGONAL RUNS OF LENGTH
// >= RQA_LMIN.
//
// RETURNS Some(DET) IN [0, 1], OR None WHEN THE WINDOW HAS FEWER THAN
// RQA_MIN_SAMPLES FILLED SLOTS -- THE QUIESCENCE GATE MUST NOT FREEZE
// ON A HALF-FILLED WINDOW.
//
// BRUTE-FORCE O(N^2), SAME COST CLASS AS hvg_degrees. AT N <= 64 THIS
// IS UNDER 4K COMPARISONS, DONE ONCE PER SECOND.

// CHEBYSHEV (L-INFINITY) DISTANCE BETWEEN TWO 3-D EMBEDDED POINTS.
fn chebyshev3(a: &[f64; RQA_EMBED_DIM], b: &[f64; RQA_EMBED_DIM]) -> f64 {
    let mut m = 0.0;
    for k in 0..RQA_EMBED_DIM {
        let d = (a[k] - b[k]).abs();
        if d > m {
            m = d;
        }
    }
    m
}

pub fn rqa_det<const N: usize>(w: &RawWindow<N>) -> Option<f64> {
    let n = w.filled;
    if n < RQA_MIN_SAMPLES {
        return None;
    }

    // COPY WINDOW INTO ORDER-PRESERVING SLICE FOR INDEXED ACCESS.
    let mut s: [f64; N] = [0.0; N];
    let mut k = 0;
    for x in w.iter() {
        s[k] = x;
        k += 1;
    }

    // MEAN AND STANDARD DEVIATION OVER THE n FILLED SAMPLES.
    let nf = n as f64;
    let mut sum = 0.0;
    for v in s.iter().take(n) {
        sum += *v;
    }
    let mean = sum / nf;
    let mut var = 0.0;
    for v in s.iter().take(n) {
        let d = *v - mean;
        var += d * d;
    }
    let sigma = (var / nf).sqrt();

    // FLAT-WINDOW SPECIAL CASE. A PERFECTLY STEADY SIGNAL HAS sigma = 0;
    // EVERY EMBEDDED POINT RECURS WITH EVERY OTHER. THAT IS FULLY
    // DETERMINISTIC -- RETURN 1.0 DIRECTLY (AND AVOID eps = 0 / A
    // DEGENERATE RECURRENCE MATRIX). idle_pct IS INTEGER-PERCENT CAST
    // TO f64, SO A STEADY COMPUTE WORKLOAD PRODUCES AN EXACTLY-FLAT
    // WINDOW AND MUST READ AS QUIESCENT.
    if sigma < 1e-9 {
        return Some(1.0);
    }

    let eps = RQA_THRESH_STD_FRAC * sigma;

    // DELAY-EMBED: m = n - (RQA_EMBED_DIM - 1) VECTORS.
    let m = n - (RQA_EMBED_DIM - 1);
    if m < 2 {
        return None;
    }
    let mut emb: [[f64; RQA_EMBED_DIM]; N] = [[0.0; RQA_EMBED_DIM]; N];
    for i in 0..m {
        for d in 0..RQA_EMBED_DIM {
            emb[i][d] = s[i + d];
        }
    }

    // RECURRENCE MATRIX OVER THE m EMBEDDED POINTS.
    let mut rec: [[bool; N]; N] = [[false; N]; N];
    for i in 0..m {
        for j in 0..m {
            rec[i][j] = chebyshev3(&emb[i], &emb[j]) <= eps;
        }
    }

    // WALK EVERY OFF-MAIN DIAGONAL. COUNT TOTAL RECURRENCE POINTS AND
    // THE POINTS THAT BELONG TO DIAGONAL RUNS OF LENGTH >= RQA_LMIN.
    let mut total_rec: u64 = 0;
    let mut diag_rec: u64 = 0;
    // OFFSET o > 0: PAIRS (i, i + o). OFFSET o < 0 IS THE SYMMETRIC
    // MIRROR; THE RECURRENCE MATRIX IS SYMMETRIC SO WE WALK o IN
    // [1, m) AND DOUBLE-COUNT NOTHING BY COUNTING BOTH (i,j) AND (j,i)
    // VIA THE 2x FACTOR -- INSTEAD WE JUST WALK BOTH UPPER AND LOWER
    // EXPLICITLY TO KEEP total_rec CONSISTENT WITH diag_rec.
    for o in 1..m {
        // UPPER DIAGONAL: (i, i + o).
        let mut run: usize = 0;
        for i in 0..(m - o) {
            if rec[i][i + o] {
                total_rec += 1;
                run += 1;
            } else {
                if run >= RQA_LMIN {
                    diag_rec += run as u64;
                }
                run = 0;
            }
        }
        if run >= RQA_LMIN {
            diag_rec += run as u64;
        }
        // LOWER DIAGONAL: (i + o, i).
        run = 0;
        for i in 0..(m - o) {
            if rec[i + o][i] {
                total_rec += 1;
                run += 1;
            } else {
                if run >= RQA_LMIN {
                    diag_rec += run as u64;
                }
                run = 0;
            }
        }
        if run >= RQA_LMIN {
            diag_rec += run as u64;
        }
    }

    if total_rec == 0 {
        return Some(0.0);
    }
    Some(diag_rec as f64 / total_rec as f64)
}

// A PRICED READING: A VALUE AND HOW MUCH IT IS WORTH TRUSTING.
// EACH ESTIMATOR ANSWERS WHEREVER ITS ARITHMETIC IS DEFINED AND REPORTS
// CONFIDENCE SEPARATELY, RATHER THAN REFUSING UNDER A SAMPLE FLOOR. A WINDOW AT
// 7 SAMPLES IS NOT UNKNOWABLE, IT IS WEAKLY KNOWN -- PRICE IT, NEVER BAIL.
// CONFIDENCE RAMPS FROM THE MATHEMATICAL MINIMUM TO THE STATISTICAL FLOOR, AND
// THE CONSUMER MULTIPLIES ITS EFFECT BY IT, SO DATA FLOWS FROM THE FIRST SAMPLE
// THE MATH ALLOWS AND ITS INFLUENCE GROWS WITH THE EVIDENCE.
// THE Option-RETURNING FORMS REMAIN, ANSWERING WHETHER A READING IS COMPUTABLE
// AT ALL, WHICH IS A DIFFERENT QUESTION FROM WHAT IT IS WORTH.
#[derive(Clone, Copy, Debug)]
pub struct Priced {
    pub value: f64,
    // [0, 1]. 0 means computable but on the thinnest possible evidence; 1 means
    // the window carries at least what the old gate demanded.
    pub confidence: f64,
}

impl Priced {
    // Effect scaled by trust: a full-confidence reading moves the knob the whole
    // way, a thin one moves it proportionally. Never a step.
    pub fn weighted(&self, neutral: f64) -> f64 {
        neutral + (self.value - neutral) * self.confidence
    }
}

// Confidence for a window of `filled` samples against the floor that used to
// gate it. Linear: at the mathematical minimum it is near zero, at the old gate
// it is 1. Beyond the gate it stays 1 -- more samples do not make a statistic
// more true than its own definition allows.
fn confidence(filled: usize, math_min: usize, stat_floor: usize) -> f64 {
    if filled <= math_min {
        return 0.0;
    }
    if filled >= stat_floor {
        return 1.0;
    }
    (filled - math_min) as f64 / (stat_floor - math_min) as f64
}

// LAG-1 AUTOCORRELATION (CRITICAL SLOWING DOWN)
//
// EVERY OTHER PRIMITIVE IN THIS MODULE DESCRIBES THE WINDOW THAT
// ALREADY HAPPENED. THIS ONE LEADS. AS A SYSTEM APPROACHES A CRITICAL
// TRANSITION ITS RECOVERY FROM SMALL PERTURBATIONS SLOWS, AND THE
// SLOWING SHOWS UP AS RISING LAG-1 AUTOCORRELATION BEFORE THE
// TRANSITION ITSELF (SCHEFFER 2009; DETECTION LIMITS IN BOETTIGER AND
// HASTINGS 2012). ON A RUNQUEUE-LENGTH SERIES THAT IS THE DIFFERENCE
// BETWEEN SEEING A BURST FORM AND SEEING THAT ONE HAPPENED.
//
// r1 = SUM (x_i - mean)(x_{i+1} - mean) / SUM (x_i - mean)^2, THE
// STANDARD BIASED ESTIMATOR. BIASED IS THE LOWER-VARIANCE CHOICE, AND
// VARIANCE IS WHAT MAKES A SHORT-WINDOW ESTIMATE USELESS.
//   r1 NEAR 0      MEMORYLESS, EACH SAMPLE INDEPENDENT OF THE LAST
//   r1 TOWARD 1    CRITICAL SLOWING, PERTURBATIONS PERSISTING
//   r1 NEGATIVE    OSCILLATION, EACH SAMPLE OVERSHOOTING THE LAST
// ONE MULTIPLY-ACCUMULATE PER SAMPLE. NOT WIRED TO A DECISION.

// LAG-1 NEEDS ENOUGH PAIRS THAT ONE OUTLIER CANNOT SET THE ANSWER.
pub const ACF1_MIN_SAMPLES: usize = 8;

pub fn lag1_autocorr<const N: usize>(w: &RawWindow<N>) -> Option<f64> {
    if w.filled < ACF1_MIN_SAMPLES {
        return None;
    }
    lag1_autocorr_raw(w)
}

// Unfloored body -- the priced form supplies its own minimum.
fn lag1_autocorr_raw<const N: usize>(w: &RawWindow<N>) -> Option<f64> {
    let n = w.filled;
    let mut s: [f64; N] = [0.0; N];
    let mut k = 0;
    for x in w.iter() {
        s[k] = x;
        k += 1;
    }
    let nf = n as f64;
    let mut sum = 0.0;
    for v in s.iter().take(n) {
        sum += *v;
    }
    let mean = sum / nf;

    let mut denom = 0.0;
    for v in s.iter().take(n) {
        let d = *v - mean;
        denom += d * d;
    }
    // A FLAT WINDOW HAS NO PERTURBATION TO RECOVER FROM, SO IT CARRIES
    // NO CRITICAL-SLOWING INFORMATION. None, NOT 1.0 -- AN IDLE CPU MUST
    // NOT READ AS MAXIMALLY AUTOCORRELATED AND THEREFORE ABOUT TO TIP.
    if denom < 1e-12 {
        return None;
    }
    let mut numer = 0.0;
    for i in 0..(n - 1) {
        numer += (s[i] - mean) * (s[i + 1] - mean);
    }
    Some((numer / denom).clamp(-1.0, 1.0))
}

// KIM-JO FINITE-SIZE-CORRECTED BURSTINESS.
// THE CLASSICAL B = (sigma - mu) / (sigma + mu) (GOH-BARABASI 2008) DRIFTS
// TOWARD -1 AS n FALLS, SO A SHORT WINDOW READS AS REGULAR WHATEVER IT
// CONTAINS -- DISQUALIFYING HERE, WHERE EVERY WINDOW IS SHORT.
// KIM AND JO (2016) CORRECT FOR FINITE SIZE:
//
//   A_n(r) = (sqrt(n+1) r - sqrt(n-1)) /
//            ((sqrt(n+1) - 2) r + sqrt(n-1))
//
// WITH r = sigma / mu. -1 IS PERFECTLY REGULAR, 0 IS POISSON, +1 IS
// MAXIMALLY BURSTY, AT EVERY n -- WHICH IS WHAT MAKES IT COMPARABLE
// ACROSS WINDOW SIZES. ONE SCALAR SEPARATING BURST-STARVATION (POSITIVE),
// LONGRUN (NEAR ZERO) AND DEADLINE-PACED (NEGATIVE).
// NOT WIRED TO A DECISION.

pub const BURSTINESS_MIN_SAMPLES: usize = 4;

pub fn kim_jo_burstiness<const N: usize>(w: &RawWindow<N>) -> Option<f64> {
    if w.filled < BURSTINESS_MIN_SAMPLES {
        return None;
    }
    kim_jo_burstiness_raw(w)
}

// Unfloored body -- the priced form supplies its own minimum.
fn kim_jo_burstiness_raw<const N: usize>(w: &RawWindow<N>) -> Option<f64> {
    let n = w.filled;
    let mut s: [f64; N] = [0.0; N];
    let mut k = 0;
    for x in w.iter() {
        s[k] = x;
        k += 1;
    }
    let nf = n as f64;
    let mut sum = 0.0;
    for v in s.iter().take(n) {
        sum += *v;
    }
    let mu = sum / nf;
    // BURSTINESS IS DEFINED ON A POSITIVE INTERVAL SERIES (WAITING
    // TIMES, QUEUE LENGTHS). A NON-POSITIVE MEAN MEANS THE CALLER HANDED
    // OVER SOMETHING THAT IS NOT ONE, AND sigma/mu WOULD BE MEANINGLESS.
    if mu <= 1e-12 {
        return None;
    }
    let mut var = 0.0;
    for v in s.iter().take(n) {
        let d = *v - mu;
        var += d * d;
    }
    // SAMPLE (n-1) STANDARD DEVIATION: THE KIM-JO CORRECTION IS DERIVED
    // AGAINST THE UNBIASED VARIANCE.
    let sigma = (var / (nf - 1.0)).sqrt();
    let r = sigma / mu;

    let sp = (nf + 1.0).sqrt();
    let sm = (nf - 1.0).sqrt();
    let denom = (sp - 2.0) * r + sm;
    if denom.abs() < 1e-12 {
        return None;
    }
    Some(((sp * r - sm) / denom).clamp(-1.0, 1.0))
}

// VEITCH-ABRY HURST (WAVELET-VARIANCE / LOGSCALE-DIAGRAM ESTIMATOR)
//
// H IS THE LONG-RANGE-DEPENDENCE EXPONENT. FOR FRACTIONAL GAUSSIAN
// NOISE THE VARIANCE OF THE DETAIL COEFFICIENTS AT OCTAVE j SCALES AS
//   E[d_j^2] ~ 2^(j*(2H - 1)),
// SO A LEAST-SQUARES FIT OF log2(E[d_j^2]) AGAINST j HAS SLOPE 2H - 1
// AND H = (SLOPE + 1) / 2. THIS IS THE VEITCH-ABRY (1999) ESTIMATOR
// WITH A HAAR FILTER, WHICH IS THE CHEAPEST MULTIRESOLUTION ANALYSIS
// AND NEEDS NO FILTER STATE.
//
// READING IT: H = 0.5 IS AN UNCORRELATED SEQUENCE -- THIS WINDOW SAYS
// NOTHING ABOUT THE NEXT. H > 0.5 IS PERSISTENT: WHAT IS HAPPENING
// TENDS TO KEEP HAPPENING, WHICH IS EXACTLY THE "THE SAME TASK IS
// STATISTICALLY LIKELY TO RETURN" PROPERTY THAT MAKES CACHE
// AMORTIZATION PAY. H < 0.5 IS ANTI-PERSISTENT / MEAN-REVERTING, WHERE
// A BUSY WINDOW PREDICTS AN IDLE ONE.
//
// NOT WIRED TO ANY DECISION. PORTED AND MEASURED FIRST; ITS BEHAVIOR ON
// THIS SCHEDULER'S OWN SIGNALS IS NOT YET KNOWN, AND A LONG-RANGE-
// DEPENDENCE READ ON A 16-SAMPLE WINDOW IS THIN BY CONSTRUCTION.

// MINIMUM SAMPLES: 16 GIVES THREE USABLE OCTAVES (8, 4 AND 2 DETAIL
// COEFFICIENTS), WHICH IS THE FLOOR FOR A SLOPE THAT IS A FIT RATHER
// THAN A LINE THROUGH TWO POINTS.
pub const HURST_MIN_SAMPLES: usize = 16;

// AN OCTAVE CONTRIBUTES TO THE FIT ONLY WITH AT LEAST THIS MANY DETAIL
// COEFFICIENTS. THE COARSEST OCTAVES CARRY THE FEWEST AND THE NOISIEST
// VARIANCE ESTIMATES; INCLUDING A ONE-COEFFICIENT OCTAVE LETS A SINGLE
// SAMPLE SET THE SLOPE.
const HURST_MIN_COEFFS: usize = 2;

pub fn veitch_abry_hurst<const N: usize>(w: &RawWindow<N>) -> Option<f64> {
    let n = w.filled;
    if n < HURST_MIN_SAMPLES {
        return None;
    }

    let mut a: [f64; N] = [0.0; N];
    let mut k = 0;
    for x in w.iter() {
        a[k] = x;
        k += 1;
    }

    // HAAR CASCADE. AT EACH OCTAVE THE APPROXIMATION HALVES IN LENGTH
    // AND THE DETAIL VARIANCE IS ACCUMULATED. THE 1/sqrt(2) KEEPS THE
    // TRANSFORM ORTHONORMAL, SO A WHITE SEQUENCE HOLDS ITS VARIANCE
    // ACROSS OCTAVES AND LANDS ON SLOPE 0 -> H = 0.5.
    const INV_SQRT2: f64 = std::f64::consts::FRAC_1_SQRT_2;
    let mut len = n;
    let mut octave = 0usize;
    // (j, log2(mean d^2)) PAIRS, AT MOST log2(N) OF THEM.
    let mut xs: [f64; 64] = [0.0; 64];
    let mut ys: [f64; 64] = [0.0; 64];
    let mut pts = 0usize;

    while len >= 2 && pts < xs.len() {
        let half = len / 2;
        octave += 1;
        let mut sq = 0.0;
        for i in 0..half {
            let lo = a[2 * i];
            let hi = a[2 * i + 1];
            let d = (lo - hi) * INV_SQRT2;
            sq += d * d;
            a[i] = (lo + hi) * INV_SQRT2;
        }
        if half >= HURST_MIN_COEFFS {
            let mean_sq = sq / half as f64;
            // A PERFECTLY FLAT OCTAVE HAS NO SCALING INFORMATION AND ITS
            // log2 IS -inf; SKIP IT RATHER THAN POISON THE FIT.
            if mean_sq > 1e-300 {
                xs[pts] = octave as f64;
                ys[pts] = mean_sq.log2();
                pts += 1;
            }
        }
        len = half;
    }

    if pts < 3 {
        return None;
    }

    // ORDINARY LEAST SQUARES ON (j, log2 E[d_j^2]).
    let m = pts as f64;
    let mut sx = 0.0;
    let mut sy = 0.0;
    for i in 0..pts {
        sx += xs[i];
        sy += ys[i];
    }
    let mx = sx / m;
    let my = sy / m;
    let mut num = 0.0;
    let mut den = 0.0;
    for i in 0..pts {
        let dx = xs[i] - mx;
        num += dx * (ys[i] - my);
        den += dx * dx;
    }
    if den < 1e-12 {
        return None;
    }
    let slope = num / den;
    let h = (slope + 1.0) / 2.0;
    // H IS DEFINED ON [0, 1]. A SHORT WINDOW CAN PRODUCE A SLOPE OUTSIDE
    // THAT; CLAMP RATHER THAN REPORT AN IMPOSSIBLE EXPONENT.
    Some(h.clamp(0.0, 1.0))
}

// PECORA-CARROLL COUPLING
//
// ASKS WHETHER ONE SERIES IS A FUNCTION OF ANOTHER: IF x_i AND x_j ARE
// NEIGHBORS, ARE y_i AND y_j ALSO NEIGHBORS? WHEN y IS DRIVEN BY x THE
// ANSWER IS YES AND THE CROSS-PREDICTION ERROR COLLAPSES; WHEN THE TWO
// ARE INDEPENDENT AN x-NEIGHBOR SAYS NOTHING ABOUT y AND THE ERROR
// RISES TO THE SERIES' OWN MEAN PAIRWISE SPREAD.
//
// BOTH SERIES ARE STANDARDIZED FIRST, SO THIS MEASURES SHARED DYNAMICS
// AND NOT SHARED UNITS -- TWO CPUS' QUEUE LENGTHS COUPLE OR DO NOT
// REGARDLESS OF WHICH ONE CARRIES MORE WORK.
//
// RETURNS [0, 1]: 1 IS FULLY SLAVED, 0 IS INDEPENDENT. THIS IS THE
// PRIMITIVE BEHIND "ARE THESE TWO RUNQUEUES CONVERGING OR DIVERGING",
// WHICH IS THE SHAPE OF BOTH THE SEAT-TOPOLOGY AND THE THRASHING
// QUESTION.
//
// NOT WIRED TO ANY DECISION -- SAME REASON AS THE HURST ESTIMATOR.

pub const PC_MIN_SAMPLES: usize = 8;

fn standardize<const N: usize>(w: &RawWindow<N>, out: &mut [f64; N]) -> Option<usize> {
    let n = w.filled;
    if n == 0 {
        return None;
    }
    let mut k = 0;
    for x in w.iter() {
        out[k] = x;
        k += 1;
    }
    let nf = n as f64;
    let mut sum = 0.0;
    for v in out.iter().take(n) {
        sum += *v;
    }
    let mean = sum / nf;
    let mut var = 0.0;
    for v in out.iter().take(n) {
        let d = *v - mean;
        var += d * d;
    }
    let sigma = (var / nf).sqrt();
    // A FLAT SERIES HAS NO DYNAMICS TO COUPLE. REPORT IT AS SUCH RATHER
    // THAN DIVIDING BY ZERO AND CALLING THE RESULT SYNCHRONY.
    if sigma < 1e-9 {
        return None;
    }
    for v in out.iter_mut().take(n) {
        *v = (*v - mean) / sigma;
    }
    Some(n)
}

pub fn pecora_carroll<const N: usize>(x: &RawWindow<N>, y: &RawWindow<N>) -> Option<f64> {
    if x.filled.min(y.filled) < PC_MIN_SAMPLES {
        return None;
    }
    pecora_carroll_raw(x, y)
}

// Unfloored body -- the priced form supplies its own minimum.
fn pecora_carroll_raw<const N: usize>(x: &RawWindow<N>, y: &RawWindow<N>) -> Option<f64> {
    let n = x.filled.min(y.filled);
    let mut xs: [f64; N] = [0.0; N];
    let mut ys: [f64; N] = [0.0; N];
    let nx = standardize(x, &mut xs)?;
    let ny = standardize(y, &mut ys)?;
    let n = n.min(nx).min(ny);
    if n < PC_MIN_SAMPLES {
        return None;
    }

    // CROSS-PREDICTION ERROR: FOR EACH i, THE NEAREST OTHER POINT IN x,
    // SCORED BY HOW FAR APART THE MATCHING y VALUES ARE.
    let mut err = 0.0;
    for i in 0..n {
        let mut best = f64::INFINITY;
        let mut best_j = usize::MAX;
        for j in 0..n {
            if j == i {
                continue;
            }
            let d = (xs[i] - xs[j]).abs();
            if d < best {
                best = d;
                best_j = j;
            }
        }
        if best_j == usize::MAX {
            return None;
        }
        err += (ys[i] - ys[best_j]).abs();
    }
    err /= n as f64;

    // BASELINE: THE MEAN PAIRWISE SPREAD OF y ITSELF, WHICH IS WHAT THE
    // ERROR APPROACHES WHEN x CARRIES NO INFORMATION ABOUT y. TAKING THE
    // SERIES' OWN SPREAD RATHER THAN A GAUSSIAN CONSTANT KEEPS THIS
    // HONEST ON THE SHORT, NON-NORMAL WINDOWS THIS SCHEDULER ACTUALLY
    // SEES.
    let mut base = 0.0;
    let mut pairs = 0u64;
    for i in 0..n {
        for j in (i + 1)..n {
            base += (ys[i] - ys[j]).abs();
            pairs += 1;
        }
    }
    if pairs == 0 {
        return None;
    }
    base /= pairs as f64;
    if base < 1e-12 {
        return None;
    }

    Some((1.0 - err / base).clamp(0.0, 1.0))
}

// PRICED ESTIMATOR FORMS
//
// Each pairs the existing computation with a confidence, and lowers the hard
// refusal to the point where the ARITHMETIC breaks rather than where the
// STATISTICS get thin. The old floors survive as the confidence ceiling: at the
// old gate the reading is worth its full weight, below it a proportional share.
//
// Hurst is the exception and stays gated at 16. Its floor is not statistical --
// the wavelet fit needs three octaves with two coefficients each, and a window
// of 8 yields two usable octaves, which is a line through two points rather
// than a regression. There is no weakly-known answer there; there is no answer.

// A single pair is enough to define lag-1; eight is where it stops being noise.
const ACF1_MATH_MIN: usize = 3;
pub fn lag1_autocorr_priced<const N: usize>(w: &RawWindow<N>) -> Option<Priced> {
    let n = w.filled;
    if n < ACF1_MATH_MIN {
        return None;
    }
    let v = lag1_autocorr_raw(w)?;
    Some(Priced {
        value: v,
        confidence: confidence(n, ACF1_MATH_MIN, ACF1_MIN_SAMPLES),
    })
}

// Burstiness needs a sample stdev, so n >= 2. The Kim-Jo correction is defined
// from there; four was a comfort floor, not a requirement.
const BURSTINESS_MATH_MIN: usize = 2;
pub fn kim_jo_burstiness_priced<const N: usize>(w: &RawWindow<N>) -> Option<Priced> {
    let n = w.filled;
    if n < BURSTINESS_MATH_MIN {
        return None;
    }
    let v = kim_jo_burstiness_raw(w)?;
    Some(Priced {
        value: v,
        confidence: confidence(n, BURSTINESS_MATH_MIN, BURSTINESS_MIN_SAMPLES),
    })
}

// Coupling needs a nearest neighbour that is not the point itself, so n >= 3.
const PC_MATH_MIN: usize = 3;
pub fn pecora_carroll_priced<const N: usize>(x: &RawWindow<N>, y: &RawWindow<N>) -> Option<Priced> {
    let n = x.filled.min(y.filled);
    if n < PC_MATH_MIN {
        return None;
    }
    let v = pecora_carroll_raw(x, y)?;
    Some(Priced {
        value: v,
        confidence: confidence(n, PC_MATH_MIN, PC_MIN_SAMPLES),
    })
}

// Hurst: gated, not priced. See above.
pub fn veitch_abry_hurst_priced<const N: usize>(w: &RawWindow<N>) -> Option<Priced> {
    veitch_abry_hurst(w).map(|v| Priced {
        value: v,
        confidence: 1.0,
    })
}

// CHAOS COUNTER (DIAGNOSTIC)
//
// MONOTONIC COUNTER OF "WINDOW IS CHAOTIC" CROSSINGS. INCREMENT WHEN
// HVG ENTROPY CROSSES LN(3/2) UPWARD OR WHEN PERMUTATION ENTROPY
// CROSSES BP_H_HIGH UPWARD. EXPOSED FOR THE TELEMETRY LINE AND
// FOR THE COMMITTED MWU PATHWAY THAT GATES OFF CROSSINGS.
#[derive(Default, Debug)]
pub struct ChaosCounter(AtomicU64);

impl ChaosCounter {
    pub const fn new() -> Self {
        Self(AtomicU64::new(0))
    }

    pub fn bump(&self) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }

    pub fn load(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }
}
