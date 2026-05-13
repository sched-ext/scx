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

#[cfg(test)]
mod tests {
    use super::*;

    fn fill_window<const N: usize>(w: &mut RawWindow<N>, samples: &[f64]) {
        for s in samples {
            w.push(*s);
        }
    }

    #[test]
    fn raw_window_basic_push_and_iter() {
        let mut w: RawWindow<4> = RawWindow::new();
        assert!(w.is_empty());
        w.push(1.0);
        w.push(2.0);
        w.push(3.0);
        let got: Vec<f64> = w.iter().collect();
        assert_eq!(got, vec![1.0, 2.0, 3.0]);
        assert_eq!(w.len(), 3);
        w.push(4.0);
        w.push(5.0);
        let got: Vec<f64> = w.iter().collect();
        assert_eq!(got, vec![2.0, 3.0, 4.0, 5.0]);
        assert_eq!(w.len(), 4);
    }

    #[test]
    fn mean_min_max() {
        let mut w: RawWindow<8> = RawWindow::new();
        fill_window(&mut w, &[1.0, 2.0, 3.0, 4.0, 5.0]);
        assert!((mean(&w) - 3.0).abs() < 1e-9);
        assert_eq!(min(&w), 1.0);
        assert_eq!(max(&w), 5.0);
    }

    #[test]
    fn hvg_monotonic_low_mean_degree() {
        let mut w: RawWindow<32> = RawWindow::new();
        // STRICTLY INCREASING RAMP: NO PEAK CAN SEE PAST AN INTERIOR PEAK,
        // SO EVERY NODE ONLY SEES ITS NEIGHBORS. LAMBDA -> 2.
        for i in 0..32 {
            w.push(i as f64);
        }
        let lambda = hvg_mean_degree(&w);
        assert!(
            lambda <= HVG_LAMBDA_PERIODIC_MAX,
            "monotonic ramp lambda should be in periodic band; got {} > {}",
            lambda,
            HVG_LAMBDA_PERIODIC_MAX
        );
    }

    #[test]
    fn hvg_period_2_in_mixed_band() {
        // PERIOD-2 [1,0,1,0,...] IS A KNOWN HVG DEGENERATE CASE: PEAKS
        // SEE EACH OTHER THROUGH TROUGHS, INFLATING LAMBDA TOWARD ~3.
        // NOT PERIODIC BY LAMBDA, NOT CHAOTIC EITHER -- THE MIXED BAND
        // IS THE CORRECT BUCKET FOR THIS SHAPE.
        let mut w: RawWindow<32> = RawWindow::new();
        for i in 0..32 {
            w.push(if i % 2 == 0 { 1.0 } else { 0.0 });
        }
        let lambda = hvg_mean_degree(&w);
        assert!(
            lambda > HVG_LAMBDA_PERIODIC_MAX && lambda < HVG_LAMBDA_CHAOTIC_MIN,
            "period-2 lambda should sit in mixed band; got {}",
            lambda
        );
    }

    #[test]
    fn hvg_random_mean_degree_in_chaotic_band() {
        let mut w: RawWindow<64> = RawWindow::new();
        let mut state: u64 = 0xdeadbeefcafebabe;
        for _ in 0..64 {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            let v = ((state >> 33) as u32) as f64 / u32::MAX as f64;
            w.push(v);
        }
        let lambda = hvg_mean_degree(&w);
        assert!(
            lambda >= HVG_LAMBDA_CHAOTIC_MIN,
            "iid random lambda should be in chaotic band; got {} < {}",
            lambda,
            HVG_LAMBDA_CHAOTIC_MIN
        );
    }

    #[test]
    fn hvg_stats_agrees_with_individual_functions() {
        let mut w: RawWindow<32> = RawWindow::new();
        let mut state: u64 = 0xfeedface12345678;
        for _ in 0..32 {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            let v = ((state >> 33) as u32) as f64 / u32::MAX as f64;
            w.push(v);
        }
        let lambda_solo = hvg_mean_degree(&w);
        let entropy_solo = hvg_entropy(&w);
        let (lambda_pair, entropy_pair) = hvg_stats(&w);
        assert!((lambda_solo - lambda_pair).abs() < 1e-9);
        assert!((entropy_solo - entropy_pair).abs() < 1e-9);
    }

    #[test]
    fn bandt_pompe_monotonic_zero() {
        let mut w: RawWindow<16> = RawWindow::new();
        for i in 0..16 {
            w.push(i as f64);
        }
        let h = bandt_pompe_d3(&w);
        assert!(h < 0.1, "monotonic should have H ~= 0; got {}", h);
    }

    #[test]
    fn bandt_pompe_random_near_one() {
        let mut w: RawWindow<64> = RawWindow::new();
        let mut state: u64 = 0x1234567890abcdef;
        for _ in 0..64 {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            let v = ((state >> 33) as u32) as f64 / u32::MAX as f64;
            w.push(v);
        }
        let h = bandt_pompe_d3(&w);
        assert!(h > 0.85, "random should have H ~> 0.85; got {}", h);
    }
}
