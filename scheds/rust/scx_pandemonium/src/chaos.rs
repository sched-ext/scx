// PANDEMONIUM CHAOS PRIMITIVES
// PURE-RUST RAW-WINDOW STATISTICS USED BY THE ADAPTIVE LAYER.
//
// EVERY PUBLIC ITEM IN THIS MODULE IS PART OF THE CHAOS API SURFACE:
// SOME ARE CONSUMED BY THE BINARY (adaptive.rs), SOME BY TESTS, AND
// SOME ARE EXPORTED CONSTANTS FOR DIAGNOSTICS / FUTURE EXPANSION.
// CARGO'S DEAD-CODE LINT FIRES PER COMPILATION TARGET; SILENCE IT.
#![allow(dead_code)]

// NO EWMA, NO SCHMITT, NO CUSUM. EVERY MEASURE IS COMPUTED FROM
// THE RAW SAMPLE WINDOW EACH CALL.
//
// HVG MEAN DEGREE / HVG ENTROPY (LUQUE-LACASA 2009): TWO STATISTICS OF
// THE HORIZONTAL VISIBILITY GRAPH'S DEGREE DISTRIBUTION.
//   - MEAN DEGREE LAMBDA = <k>. IID RANDOM SEQUENCES SATURATE AT 4 - 2/N
//     (-> 4 IN THE LIMIT). PURELY PERIODIC SEQUENCES STAY NEAR 2.
//   - SHANNON ENTROPY S OVER THE DEGREE DISTRIBUTION. IID HAS THE EXACT
//     CLOSED FORM P(k) = (1/3)*(2/3)^(k-2), k >= 2, GIVING
//     S_IID = LN(3) + 2*LN(3/2) ~= 1.910.
// LN(3/2) IS THE CHARACTERISTIC EXPONENT OF THE IID DEGREE DISTRIBUTION,
// NOT THE ENTROPY THRESHOLD. WE EXPOSE LAMBDA AS THE PRIMARY REGIME
// DISCRIMINATOR (DIRECTLY INTERPRETABLE) AND ENTROPY AS A CORROBORATOR.
//
// BANDT-POMPE PERMUTATION ENTROPY (D=3) (BANDT-POMPE 2002): SHANNON
// ENTROPY OF THE ORDINAL-PATTERN DISTRIBUTION OF LENGTH-3 SUB-WINDOWS,
// NORMALIZED TO [0, 1] BY LN(6). 0 = PERFECTLY MONOTONIC / PERIODIC,
// 1 = MAXIMALLY DISORDERED.
//
// THESE TWO PRIMITIVES ARE COMPLEMENTARY: HVG ENTROPY IS AMPLITUDE-
// SENSITIVE (TWO SEQUENCES WITH IDENTICAL ORDINAL STRUCTURE BUT
// DIFFERENT VALUES CAN DIFFER IN HVG-S), BANDT-POMPE IS AMPLITUDE-
// INVARIANT (CAPTURES PURE ORDINAL DYNAMICS).

use std::sync::atomic::{AtomicU64, Ordering};

// CRITICAL VALUES

// LN(3/2). IID HVG DEGREE-DISTRIBUTION CHARACTERISTIC EXPONENT.
// EXPOSED FOR DIAGNOSTICS / FUTURE USE; NOT USED AS A DIRECT THRESHOLD.
pub const HVG_LN_3_2: f64 = 0.405_465_108_108_164_4;

// HVG MEAN-DEGREE THRESHOLDS. IID RANDOM SATURATES AT 4 - 2/N; PURELY
// PERIODIC SEQUENCES STAY NEAR 2. THE TWO THRESHOLDS BELOW DEFINE A
// DEAD ZONE FOR THE MIXED REGIME WITHOUT HYSTERESIS SCHMITT LOGIC.
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

#[allow(dead_code)]
pub fn min<const N: usize>(w: &RawWindow<N>) -> f64 {
    let mut it = w.iter();
    let mut m = match it.next() {
        Some(x) => x,
        None => return 0.0,
    };
    for x in it {
        if x < m {
            m = x;
        }
    }
    m
}

#[allow(dead_code)]
pub fn max<const N: usize>(w: &RawWindow<N>) -> f64 {
    let mut it = w.iter();
    let mut m = match it.next() {
        Some(x) => x,
        None => return 0.0,
    };
    for x in it {
        if x > m {
            m = x;
        }
    }
    m
}

// HORIZONTAL VISIBILITY GRAPH
//
// FOR A SEQUENCE x_1..x_N, NODES i AND j (i < j) ARE HVG-CONNECTED IFF
// x_k < min(x_i, x_j) FOR ALL i < k < j. ADJACENT NODES (j = i+1) ARE
// ALWAYS CONNECTED.
//
// hvg_degrees BUILDS THE DEGREE VECTOR ONCE; hvg_mean_degree AND
// hvg_entropy ARE THIN WRAPPERS OVER IT. WHEN BOTH ARE NEEDED IN THE
// SAME TICK, USE hvg_stats TO AMORTIZE THE O(N^2) CONSTRUCTION.
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

// HVG MEAN DEGREE (LAMBDA). PRIMARY DISCRIMINATOR FOR REGIME DETECTION.
//   - PERIODIC: ~2
//   - CHAOTIC / IID RANDOM: -> 4
#[allow(dead_code)]
pub fn hvg_mean_degree<const N: usize>(w: &RawWindow<N>) -> f64 {
    let (deg, n) = match hvg_degrees(w) {
        Some(v) => v,
        None => return 0.0,
    };
    let mut sum: u64 = 0;
    for d in deg.iter().take(n) {
        sum += *d as u64;
    }
    sum as f64 / n as f64
}

// HVG SHANNON ENTROPY (S). CORROBORATING DISCRIMINATOR.
// 0 = SHARP DEGREE DISTRIBUTION (PERIODIC). HVG_S_IID ~= 1.91 = IID
// ASYMPTOTE. INTERMEDIATE VALUES = MIXED OR CHAOTIC DYNAMICS.
#[allow(dead_code)]
pub fn hvg_entropy<const N: usize>(w: &RawWindow<N>) -> f64 {
    let (deg, n) = match hvg_degrees(w) {
        Some(v) => v,
        None => return 0.0,
    };

    let mut hist: [u32; N] = [0; N];
    for d in deg.iter().take(n) {
        let bucket = (*d as usize).min(n - 1);
        hist[bucket] += 1;
    }

    let total = n as f64;
    let mut s_hvg = 0.0;
    for c in hist.iter().take(n) {
        if *c == 0 {
            continue;
        }
        let p = *c as f64 / total;
        s_hvg -= p * p.ln();
    }
    s_hvg
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
