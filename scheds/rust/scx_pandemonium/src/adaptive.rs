// PANDEMONIUM ADAPTIVE CONTROL LOOP
// SINGLE-THREAD CLOSED-LOOP TUNING SYSTEM
//
// ONE THREAD: MONITOR LOOP (1-SECOND CONTROL LOOP)
//   READS THE PER-CPU STATS ARRAY, UNCOLLAPSED, AND BUILDS THE LIVE LOAD
//   GRAPH: NODES ARE CPUs WEIGHTED BY THEIR QUEUE CLOCK, TRAFFIC SHAPE,
//   CRITICAL SLOWING AND PERSISTENCE; EDGES ARE CPU PAIRS WEIGHTED BY
//   COUPLING. EVERY MEASURE IS RECOMPUTED FROM THE RAW WINDOW EACH TICK.
//
//   EVERY KNOB IS DERIVED, NONE ARE LEARNED. Domain depth -> slice, its
//   burstiness -> batch/burst ceilings, its Hurst -> rescue threshold, R_eff ->
//   CoDel equilibrium. Lag-1 and Bandt-Pompe H are read and actuate nothing.
//   Coupling is MEASURED and not actuated: deriving affinity from it cost 16x on IPC pipe
//   p50 in the first PRISM pass and was withdrawn. There is no expert set, no loss pathway and no convergence
//   window: a derived knob is correct this tick, where a learned one was
//   correct several convergence windows later if the regime held still.
//
// BPF PRODUCES HISTOGRAMS, RUST READS AND REACTS. RUST WRITES KNOBS,
// BPF READS THEM ON THE VERY NEXT SCHEDULING DECISION.

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::Result;

use crate::bpf_intf::{PHI_BASE_MAX_NS, PHI_BASE_MIN_NS};
use crate::chaos::{self, Priced, RawWindow};
use crate::scheduler::{
    DEPTH_RING_SLOTS, FlowRow, PandemoniumStats, REFILL_RING_SLOTS, RefillRing, Scheduler,
};
use crate::topology::CpuTopology;
use crate::tuning::{self, HIST_BUCKETS, Regime, detect_regime, scaled_regime_knobs};

// THE REGIME WINDOWS READ THE RING, ONE MACHINE-WIDE SAMPLE PER BUCKET: THE
// IDLE-HIT SHARE OF THE BUCKET'S RUNS (PERCENT) AND ITS WAKES, OVER THE SAME
// WINDOW_SPAN_S AS EVERY GRAPH SERIES, 64-256 SAMPLES. THE REGIME'S MEMORY IS
// 1.6S INSTEAD OF 16 ONE-SECOND SAMPLES, AND HVG AND BANDT-POMPE READ A SERIES
// LONG ENOUGH TO TELL ORDER FROM NOISE (t07). HVG IS O(N^2), 65,536
// COMPARISONS AT 256; BP D=3 GETS 254 LENGTH-3 PATTERNS OVER 6 BUCKETS.

// RQA WINDOW. rqa_det REPORTS FROM RQA_MIN_SAMPLES, SO RQA-DET READS THE NEWEST
// RQA_MIN_SAMPLES BUCKETS OF THE SAME IDLE-HIT SHARE ON A WINDOW OF ITS OWN.
const RQA_WIN: usize = chaos::RQA_MIN_SAMPLES;

// DEPTH WINDOW SIZE. The depth series are fed from the BPF depth ring, one
// sample per bucket (a quarter of the oscillator's damped period, 6.28ms at the
// 12C reference), not one per second. 256 is where every lens in sublimation's
// battery reports, and it fills in 1.6s at the 12C reference. It is the most a
// window holds; the windows span time (WINDOW_SPAN_S).
const DEPTH_WIN: usize = 256;

// THE DEPTH WINDOWS SPAN TIME, NOT BUCKETS: 256 buckets of the 12C reference's
// 6.28ms, 1.608s, at every width, never under WINDOW_MIN samples. 256 buckets
// of 2C's 100.5ms spanned 25.7s and held a storm's reading long after it ended
// (research t22).
const WINDOW_SPAN_S: f64 = 1.608;
const WINDOW_MIN: usize = 64;

// THE EVIDENCE BAND. A derived field writes only when it moved from the value
// last written by more than EVIDENCE_K times its own spread over its last
// EVIDENCE_TICKS derivations. The derivation's sensors move every tick with
// their own sampling noise, and exact-equality writes wrote on 127-129 of 129
// ticks (research t22).
const EVIDENCE_TICKS: usize = 16;
const EVIDENCE_K: f64 = 2.0;

// THE REFILL READING (research t14). stopping() APPENDS EVERY RUN THAT ENDED A
// CLASSED WAKE TO THAT CPU's RING: THE TASK, WHETHER THE WAKER RAN ACROSS THE
// L3, AND THE SERVICE IT RENDERED. A TASK POOLS ITS STINTS PER CLASS, AT MOST
// REFILL_TICK_STINTS OF A TICK's EVENLY THINNED, SO A POOL SPANS THE LAST
// REFILL_SPAN_TICKS OF A BUSY TASK AND ALL OF A QUIET ONE. A TASK WITH
// REFILL_MIN_STINTS IN BOTH IS ITS OWN CONTROL: ITS MEDIAN STINT AFTER A
// CROSS-L3 WAKE LESS ITS MEDIAN AFTER A SAME-L3 ONE. THE READING IS THE MEDIAN
// OF THOSE OVER THE PAIRED TASKS, SO A LONG-STINT TASK COUNTS ONCE, NOT ONCE PER
// STOP, AND NO TAIL SETS THE LEVEL; UNDER REFILL_MIN_TASKS NOTHING IS READ. A
// DRAIN TAKES EACH RING's NEWEST SLOTS LESS REFILL_RING_MARGIN, SO A CPU THAT
// LOGS MORE THAN THAT A SECOND IS SAMPLED, NOT READ WHOLE. A TASK QUIET FOR A
// SPAN LEAVES THE TABLE.
const REFILL_TASKS: usize = 1024;
const REFILL_PROBE: usize = 16;
const REFILL_SPAN_TICKS: u64 = EVIDENCE_TICKS as u64;
const REFILL_TICK_STINTS: usize = 16;
const REFILL_TASK_SLOTS: usize = EVIDENCE_TICKS * REFILL_TICK_STINTS;
const REFILL_MIN_STINTS: usize = 20;
const REFILL_MIN_TASKS: usize = 3;
const REFILL_MIN_TICKS: usize = 4;
// AN APPEND RACING THE COPY OVERWRITES A RING's OLDEST SLOTS; A DRAIN STOPS THIS
// SHORT OF THEM.
const REFILL_RING_MARGIN: usize = 64;
// A TASK's PROBE RUN STARTS AT THE TOP 10 BITS OF ITS PID's FIBONACCI HASH.
const _: () = assert!(REFILL_TASKS == 1 << 10);

// THE LIVE BASE COST STAYS AT tau's UNTIL THE PAIRED READING IS SCORED AGAINST
// t14 ON THIS TREE AND THE COST BINDS ONLY ON THE RUNG IT WAS MEASURED ON: THE
// STOP-WEIGHTED SUM BEFORE IT PINNED THE COST AT 42-100us AND STOPPED THE STEALS
// THAT ROTATE AN IPC PAIR BETWEEN SMT SIBLINGS. THE CANDIDATE IS DERIVED AND
// REPORTED BESIDE WHAT IS WRITTEN AND APPLIED.
const LIVE_BASE_COST: bool = false;

// THE LEAVING-WAKER PARTNER SEAT. A WAKE THE WAKER RAN THROUGH IS JUDGED WHEN
// THE NEXT ONE ARRIVES, AND A FAN-OUT WAKE NEVER TAKES THE SEAT, SO FRAME'S MAIN,
// WHICH WAKES RENDER AND RUNS A 1.5ms SIM, NO LONGER READS AS LEAVING.
const WAKER_SEAT_LIVE: bool = true;

// THE STARVATION SHARE DOES NOT QUALIFY HURST'S LOWERING UNTIL IT IS SCORED. THE
// SHARE IS THE PART OF THE LOWERING IT KEEPS, AND IT READS 0 AT 2C, 0.02-0.05 AT
// 8C AND 0.11-0.16 AT 12C, WHICH RETURNS THE RESCUE THRESHOLD TO ITS BASE WHERE
// THE 8C DEADLINE WIN RIDES ON THE LOWERING. THE SHARE IS DERIVED AND REPORTED
// EITHER WAY.
const QUALIFIED_RESCUE_LIVE: bool = false;

// A PHASE CUT: SIGUSR1 (main.rs installs on_phase_cut for both arms) MARKS
// A BOUNDARY IN THE LOAD, A BENCH's SCENARIO ENDING, AND THE NEXT TICK PRINTS
// THE REGIME TICKS SINCE THE LAST CUT AS ONE [PHASE] LINE, SO EACH SCENARIO
// READS ITS OWN L/M/H WHERE [KNOBS] CARRIES THE WHOLE RUN's. THE BPF ARM's
// LOOP HAS NO REGIME AND PRINTS NONE.
pub static PHASE_CUT: AtomicBool = AtomicBool::new(false);

pub extern "C" fn on_phase_cut(_sig: libc::c_int) {
    PHASE_CUT.store(true, Ordering::Relaxed);
}

fn print_phase(n: &mut u64, ticks: &mut [u64; 3]) {
    *n += 1;
    println!(
        "[PHASE] n={} ticks=L:{}/M:{}/H:{}",
        n, ticks[0], ticks[1], ticks[2]
    );
    *ticks = [0; 3];
}

// THE PER-CPU KNOBS THE LAYER WRITES, AS THE GRAPH PROM NAMES THEM, EACH
// EMITTED WRITTEN AND APPLIED.
const KNOB_NAMES: [&str; 5] = [
    "slice_ns",
    "batch_ns",
    "rescue_ns",
    "standing_targets",
    "waker_leave_ns",
];

fn knob_fields(k: &tuning::TuningKnobs) -> [u64; KNOB_NAMES.len()] {
    [
        k.slice_ns,
        k.batch_slice_ns,
        k.codel_thresh_ns,
        k.standing_targets,
        k.waker_leave_ns,
    ]
}

// THE BASE COST TO WRITE: THE WINDOW's MEAN PAIRED REFILL ON BPF's RAIL, SO WHAT
// IS WRITTEN IS WHAT BPF APPLIES, ONCE IT LEAVES THE BAND AROUND WHAT IS
// WRITTEN; ELSE THE WRITTEN VALUE. THE BAND IS THE READINGS' OWN SPREAD,
// UNCLAMPED, SO A WORKLOAD UNDER THE FLOOR HOLDS THE FLOOR.
fn phi_base_candidate(win: &RawWindow<EVIDENCE_TICKS>, written: u64) -> u64 {
    if win.iter().count() < REFILL_MIN_TICKS {
        return written;
    }
    let v = (chaos::mean(win).round().max(0.0) as u64).clamp(PHI_BASE_MIN_NS, PHI_BASE_MAX_NS);
    let band = chaos::stdev(win).map_or(0.0, |s| EVIDENCE_K * s);
    if written == 0 || (v as f64 - written as f64).abs() > band {
        v
    } else {
        written
    }
}

#[derive(Clone, Copy)]
struct RefillTask {
    pid: u32,         // 0 = FREE
    seen: u64,        // TICK OF ITS NEWEST RECORD
    tick_n: [u32; 2], // THIS TICK's RECORDS PER CLASS
    tick_k: [u32; 2], // OF THOSE, HOW MANY THE POOLING PASS WALKED
    n: [u32; 2],      // STINTS POOLED, SAME-L3 [0], CROSS-L3 [1]
    stint: [[u32; REFILL_TASK_SLOTS]; 2],
}

impl RefillTask {
    const FREE: Self = Self {
        pid: 0,
        seen: 0,
        tick_n: [0; 2],
        tick_k: [0; 2],
        n: [0; 2],
        stint: [[0; REFILL_TASK_SLOTS]; 2],
    };

    fn lapsed(&self, tick: u64) -> bool {
        self.seen + REFILL_SPAN_TICKS < tick
    }
}

struct RefillReading {
    paired_ns: f64,
    medmed_ns: f64,
    tasks: usize,
}

// THE TASK TABLE, ALLOCATED ONCE (~2.1MB); THE SCRATCH VECTORS KEEP THEIR
// CAPACITY.
struct RefillPairs {
    task: Vec<RefillTask>,
    head: Vec<u32>,
    take: Vec<usize>,
    slot: Vec<u32>,
    diff: Vec<f64>,
    cross: Vec<f64>,
    same: Vec<f64>,
    records: u64,
    lost: u64,
    dropped: u64,
}

// THE TASK's SLOT: ITS OWN, ELSE THE FIRST FREE OR LAPSED ONE IN ITS PROBE RUN,
// CLEARED. None WHEN THE RUN HOLDS ONLY LIVE TASKS.
fn refill_seat(task: &mut [RefillTask], pid: u32, tick: u64) -> Option<usize> {
    if pid == 0 {
        return None;
    }
    let base = (pid.wrapping_mul(0x9E37_79B1) >> 22) as usize;
    let mut open = None;
    for j in 0..REFILL_PROBE {
        let i = (base + j) & (REFILL_TASKS - 1);
        if task[i].pid == pid {
            open = Some(i);
            break;
        }
        if open.is_none() && (task[i].pid == 0 || task[i].lapsed(tick)) {
            open = Some(i);
        }
    }
    let t = &mut task[open?];
    if t.pid != pid || t.lapsed(tick) {
        *t = RefillTask {
            pid,
            seen: tick,
            ..RefillTask::FREE
        };
    } else if t.seen != tick {
        t.seen = tick;
        t.tick_n = [0; 2];
        t.tick_k = [0; 2];
    }
    open
}

fn refill_rec(r: &RefillRing, age: usize) -> u64 {
    r.rec[r.head.wrapping_sub(1 + age as u32) as usize % REFILL_RING_SLOTS]
}

// t14's MEDIAN (sim::stats::quantile AT 0.5): THE MIDDLE RANK, OR THE MEAN OF THE
// TWO MIDDLE RANKS. CALLERS PASS AT LEAST ONE VALUE.
fn median_u32(xs: &[u32]) -> f64 {
    let mut buf = [0u32; REFILL_TASK_SLOTS];
    let v = &mut buf[..xs.len()];
    v.copy_from_slice(xs);
    let n = v.len();
    let (_, mid, above) = v.select_nth_unstable((n - 1) / 2);
    let lo = *mid as f64;
    if n % 2 == 1 {
        lo
    } else {
        (lo + above.iter().copied().min().unwrap_or(*mid) as f64) / 2.0
    }
}

fn median_f64(v: &mut [f64]) -> f64 {
    let n = v.len();
    let (_, mid, above) = v.select_nth_unstable_by((n - 1) / 2, f64::total_cmp);
    let lo = *mid;
    if n % 2 == 1 {
        lo
    } else {
        (lo + above.iter().copied().fold(f64::INFINITY, f64::min)) / 2.0
    }
}

impl RefillPairs {
    fn new() -> Self {
        Self {
            task: vec![RefillTask::FREE; REFILL_TASKS],
            head: Vec::new(),
            take: Vec::new(),
            slot: Vec::new(),
            diff: Vec::with_capacity(REFILL_TASKS),
            cross: Vec::with_capacity(REFILL_TASKS),
            same: Vec::with_capacity(REFILL_TASKS),
            records: 0,
            lost: 0,
            dropped: 0,
        }
    }

    // EACH CPU's RECORDS SINCE THE LAST DRAIN, AT MOST ITS RING LESS THE MARGIN,
    // NEWEST KEPT, WALKED OLDEST FIRST BY AGE ACROSS THE CPUs SO NO CPU's RECORDS
    // CROWD ANOTHER's OUT OF A TASK's THINNING. PASS ONE SEATS THE TASKS AND
    // COUNTS EACH CLASS THIS TICK; PASS TWO POOLS EVERY stride-TH. THE FIRST
    // DRAIN SEEDS THE HEADS.
    fn ingest(&mut self, rings: &[RefillRing], tick: u64) {
        if self.head.len() != rings.len() {
            self.head = rings.iter().map(|r| r.head).collect();
            return;
        }
        let cap = REFILL_RING_SLOTS - REFILL_RING_MARGIN;
        self.take.clear();
        for (h, r) in self.head.iter_mut().zip(rings) {
            let d = r.head.wrapping_sub(*h) as usize;
            let k = d.min(cap);
            self.lost += (d - k) as u64;
            self.records += k as u64;
            self.take.push(k);
            *h = r.head;
        }
        let deepest = self.take.iter().copied().max().unwrap_or(0);
        self.slot.clear();
        for age in (0..deepest).rev() {
            for (r, &k) in rings.iter().zip(&self.take) {
                if age < k {
                    let rec = refill_rec(r, age);
                    let s = refill_seat(&mut self.task, (rec >> 33) as u32, tick);
                    match s {
                        Some(i) => self.task[i].tick_n[(rec >> 32) as usize & 1] += 1,
                        None => self.dropped += 1,
                    }
                    self.slot.push(s.map_or(u32::MAX, |i| i as u32));
                }
            }
        }
        let mut j = 0;
        for age in (0..deepest).rev() {
            for (r, &k) in rings.iter().zip(&self.take) {
                if age < k {
                    let s = self.slot[j];
                    j += 1;
                    if s == u32::MAX {
                        continue;
                    }
                    let rec = refill_rec(r, age);
                    let c = (rec >> 32) as usize & 1;
                    let t = &mut self.task[s as usize];
                    if t.tick_k[c] % t.tick_n[c].div_ceil(REFILL_TICK_STINTS as u32) == 0 {
                        t.stint[c][t.n[c] as usize % REFILL_TASK_SLOTS] = rec as u32;
                        t.n[c] = t.n[c].wrapping_add(1);
                    }
                    t.tick_k[c] += 1;
                }
            }
        }
    }

    // THE PAIRED MEDIAN OVER THE TASKS SEEN WITHIN A SPAN, AND BESIDE IT THE
    // DIFFERENCE OF THE TWO CLASSES' MEDIANS OVER THE SAME TASKS, THE FORM THE
    // ROADMAP QUOTES t14 IN. None UNDER REFILL_MIN_TASKS.
    fn reading(&mut self, tick: u64) -> Option<RefillReading> {
        self.diff.clear();
        self.cross.clear();
        self.same.clear();
        for t in &self.task {
            if t.pid == 0 || t.lapsed(tick) {
                continue;
            }
            let held = t.n.map(|n| (n as usize).min(REFILL_TASK_SLOTS));
            if held.iter().any(|&h| h < REFILL_MIN_STINTS) {
                continue;
            }
            let same = median_u32(&t.stint[0][..held[0]]);
            let cross = median_u32(&t.stint[1][..held[1]]);
            if same > 0.0 {
                self.diff.push(cross - same);
                self.cross.push(cross);
                self.same.push(same);
            }
        }
        if self.diff.len() < REFILL_MIN_TASKS {
            return None;
        }
        Some(RefillReading {
            tasks: self.diff.len(),
            paired_ns: median_f64(&mut self.diff),
            medmed_ns: median_f64(&mut self.cross) - median_f64(&mut self.same),
        })
    }
}

// COUPLING WINDOW. Pecora-Carroll's nearest-neighbour search costs the window
// squared per CPU pair, so it reads the newest 64 samples, where sublimation's
// rqa and spectral lenses first report, instead of all 256: 16x cheaper, and
// coupling actuates nothing.
const COUPLING_WIN: usize = 64;

// REGIME THRESHOLDS, PROFILES, AND KNOB COMPUTATION LIVE IN tuning.rs
// (ZERO BPF DEPENDENCIES, TESTABLE OFFLINE)

// THE LIVE LOAD GRAPH
//
// Nodes are CPUs weighted by their queue clock, the wait of the tasks they
// ran; edges are CPU pairs weighted by Pecora-Carroll coupling between those
// series. The chip's electrical graph is a constant and R_eff already prices
// against it; this is the graph the WORKLOAD forms, which moves every second
// and which nothing measured.
//
// THE KNOBS READ THE DOMAIN'S LANE DEPTH; THE QUEUE CLOCK RIDES BESIDE IT.
// Per-CPU seat depth reads empty under load (the hand-off seats tasks on local
// DSQs the depth sample never saw), so the nodes read the queue clock and the
// arrivals, which are alive whenever the CPU runs anything. The domain
// derivation reads the domain's requeues waiting on its CPUs' lanes, the
// population the domain overflow held before it; fed the arrivals' Fano lenses
// instead it lowered the rescue threshold everywhere and lost the 8C deadline
// win the depth lenses hold. The domain queue clock is carried for the levers
// that read a wait.
//
// BPF cannot build this. Relating CPU i to CPU j means reading another CPU's
// state, which per-CPU maps exist to avoid, and the spectral work that follows
// needs f64 and unbounded loops. This is the half of the boundary that
// justifies a userspace loop existing at all.
//
// EDGES ARE THE MEASUREMENT THAT DECIDES THE HORIZON. If every pair couples
// identically the graph is complete-and-uniform, there is no structure to
// exploit, and pricing against it can only reproduce the static case. That is
// falsifiable from the summary below and is the point of emitting it before
// anything consumes it.
pub struct LoadGraph {
    // Mean queue clock per CPU over the last window, in microseconds. NaN
    // where a CPU has no usable series yet -- absent, not empty.
    pub node_wait: Vec<f64>,
    // TRAFFIC SHAPE per CPU (Fano burstiness of its arrivals, [-1, 1]).
    // -1 perfectly regular / deadline-paced, 0 Poisson / longrun, +1 maximally
    // bursty / starvation-shaped. This is the continuous form of the property
    // the three-valued regime enum was approximating for the whole machine.
    pub node_burst: Vec<Option<chaos::Priced>>,
    // CRITICAL SLOWING per CPU (lag-1 autocorrelation of its queue clock,
    // [-1, 1]). Rises BEFORE saturation rather than at window close, which is
    // the one thing no other signal in this loop does.
    pub node_slowing: Vec<Option<chaos::Priced>>,
    // PERSISTENCE per CPU (Fano-slope Hurst of its arrivals, [0, 1]). > 0.5
    // says this CPU's load pattern tends to continue, which is precisely the
    // "the same task is likely to return" premise the warm-stay price already
    // assumes.
    pub node_persist: Vec<Option<chaos::Priced>>,
    // Upper-triangular coupling, index pair_index(i, j), priced like the node
    // attributes. None where either series is too short or flat to couple.
    pub edge: Vec<Option<chaos::Priced>>,
    pub n: usize,
    // THE DOMAIN SERIES, WHERE THE LOAD IS. The hand-off seats wakes on local
    // DSQs, so the seats read near-empty under load while the lanes hold the
    // waiting requeues, summed over the domain's CPUs. The knob derivations
    // read these, each CPU its own domain's, indexed by the domain id its ring
    // reports. NaN / None where a domain has no series yet.
    pub dom_depth: Vec<f64>,
    // The domain's queue clock (its CPUs' waits pooled by run), in us.
    pub dom_wait: Vec<f64>,
    // ITS TAIL: the largest pooled bucket wait over the last second, in us, the
    // best predictor of the next second's tail of fifteen measured (t28). Set
    // by the loop, which knows how many buckets a second holds.
    pub dom_tail: Vec<f64>,
    // ITS QUEUED WAIT: the mean wait of the runs that queued, idle-seated wakes
    // left out, in us. Set by the loop. The standing hold reads it.
    pub dom_qwait: Vec<f64>,
    // THE CoDel EQUILIBRIUM BPF APPLIES, IN us, THAT THE QUEUED WAIT AND THE
    // STARVATION SHARE ARE JUDGED AGAINST. Set by the loop; NaN until it is.
    pub eq_us: f64,
    // ITS STARVATION SHARE: over the last second, the share of its CPUs' buckets
    // whose shortest wait stayed above the CoDel equilibrium, a task held behind
    // a resident rather than a backlog draining (CoDel's standing-queue test,
    // research t35). Set by the loop; NaN with no reading.
    pub dom_starve: Vec<f64>,
    pub dom_burst: Vec<Option<chaos::Priced>>,
    // CRITICAL SLOWING per domain: lag-1 of the queue clock on ranks, the
    // samples it read, and its rise since the previous built tick (set by the
    // loop).
    pub dom_lag1: Vec<f64>,
    pub dom_lag1_n: Vec<usize>,
    pub dom_rise: Vec<f64>,
    pub dom_persist: Vec<Option<chaos::Priced>>,
    pub cpu_dom: Vec<Option<usize>>,
}

// CRITICAL SLOWING ON RANKS. The lag-1 autocorrelation of a window's ranks,
// ties broken by a fixed hash of position: A tie carries no order, and on ranks
// the IID null is N(-1/W, 1/W) whatever the series' marginal (research t32).
// NaN under 64 samples.
fn ranked_lag1<const N: usize>(w: &RawWindow<N>) -> f64 {
    let xs: Vec<f64> = w.iter().collect();
    if xs.len() < 64 {
        return f64::NAN;
    }
    let key = |i: usize| {
        let mut z = (i as u64).wrapping_add(0x9E37_79B9_7F4A_7C15);
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    };
    let mut idx: Vec<usize> = (0..xs.len()).collect();
    idx.sort_by(|&a, &b| {
        xs[a]
            .partial_cmp(&xs[b])
            .unwrap_or(std::cmp::Ordering::Equal)
            .then(key(a).cmp(&key(b)))
    });
    let mut ranks = vec![0.0; xs.len()];
    for (k, &i) in idx.iter().enumerate() {
        ranks[i] = k as f64;
    }
    let mut r = RawWindow::<N>::new();
    for x in ranks {
        r.push(x);
    }
    chaos::lag1_autocorr_priced(&r)
        .map(|p| p.value)
        .unwrap_or(f64::NAN)
}

fn pair_index(n: usize, i: usize, j: usize) -> usize {
    // i < j; row-major over the strict upper triangle.
    debug_assert!(i < j && j < n);
    i * n - (i * (i + 1)) / 2 + (j - i - 1)
}

impl LoadGraph {
    // wait_win / cnt_win: the queue clock and the arrivals per bucket, per
    // CPU. dom_win: the domain's lane depth per bucket; dom_wait_win: its
    // queue clock; dom_cnt_win: its CPUs' arrivals pooled.
    pub fn build<const N: usize>(
        wait_win: &[RawWindow<N>],
        cnt_win: &[RawWindow<N>],
        dom_win: &[RawWindow<N>],
        dom_wait_win: &[RawWindow<N>],
        dom_cnt_win: &[RawWindow<N>],
        cpu_dom: &[Option<usize>],
        edge_cache: &mut Vec<Option<chaos::Priced>>,
        edge_cursor: &mut (usize, usize),
    ) -> LoadGraph {
        let n = wait_win.len();
        let mean_or_nan = |w: &RawWindow<N>| {
            if w.is_empty() {
                f64::NAN
            } else {
                chaos::mean(w)
            }
        };
        let node_wait = wait_win.iter().map(mean_or_nan).collect();
        let dom_depth = dom_win.iter().map(mean_or_nan).collect();
        let dom_wait = dom_wait_win.iter().map(mean_or_nan).collect();
        // Burstiness is a statistic of an arrival process, so it reads the
        // domain's pooled arrivals. Persistence reads the lane depth, as the
        // slice does: Whether a deep queue stays deep is the rescue's question,
        // and the arrivals' Hurst holds 0.49-0.52 at every width, which leaves
        // the threshold at its base.
        let dom_burst = dom_cnt_win
            .iter()
            .map(chaos::kim_jo_counts_priced)
            .collect();
        let dom_persist = dom_win
            .iter()
            .map(chaos::veitch_abry_hurst_priced)
            .collect();
        let dom_lag1 = dom_wait_win.iter().map(ranked_lag1).collect();
        let dom_lag1_n = dom_wait_win.iter().map(|w| w.iter().count()).collect();
        // NODE ATTRIBUTES. Each answers a different question about the CPU:
        // burstiness is SHAPE, lag-1 is DIRECTION, Hurst is DURATION.
        // Shape and duration derive knobs; direction is read and actuates
        // nothing until a knob BPF reads takes it. A learner searching one
        // loss signal could not separate them; measured, they do not need to be.
        // PRICED, NOT GATED. Each answers wherever its arithmetic is defined and
        // carries how much the window is worth; the derivations below scale their
        // effect by that confidence. A knob moves a little on thin evidence and
        // fully on a complete window, instead of not at all and then all at once.
        let node_burst = cnt_win.iter().map(chaos::fano_burstiness_priced).collect();
        let node_slowing = wait_win.iter().map(chaos::lag1_autocorr_priced).collect();
        let node_persist = cnt_win.iter().map(chaos::fano_hurst_priced).collect();

        // Coupling reads the newest COUPLING_WIN samples of each series: its
        // nearest-neighbour search is quadratic in the window, over every pair.
        // COUPLING IN ROTATION. Every pair a tick was the tick's whole cost
        // (0.48ms at 12C, 229ms at 256 CPUs); n pairs a tick, the rest carried
        // from their last computation, keep the summary within the estimator's
        // own noise (research t03, t09).
        let tails: Vec<RawWindow<COUPLING_WIN>> = wait_win.iter().map(|w| w.newest()).collect();
        let pairs = n * n.saturating_sub(1) / 2;
        if edge_cache.len() != pairs {
            edge_cache.clear();
            edge_cache.resize(pairs, None);
            *edge_cursor = (0, 1);
        }
        for _ in 0..n.min(pairs) {
            let (i, j) = *edge_cursor;
            edge_cache[pair_index(n, i, j)] = chaos::pecora_carroll_priced(&tails[i], &tails[j]);
            *edge_cursor = if j + 1 < n {
                (i, j + 1)
            } else if i + 2 < n {
                (i + 1, i + 2)
            } else {
                (0, 1)
            };
        }
        let edge = edge_cache.clone();
        LoadGraph {
            node_wait,
            node_burst,
            node_slowing,
            node_persist,
            edge,
            n,
            dom_lag1,
            dom_lag1_n,
            dom_rise: Vec::new(),
            dom_depth,
            dom_wait,
            dom_tail: Vec::new(),
            dom_qwait: Vec::new(),
            eq_us: f64::NAN,
            dom_starve: Vec::new(),
            dom_burst,
            dom_persist,
            cpu_dom: cpu_dom.to_vec(),
        }
    }

    // DERIVE PER-CPU SLICE PRESSURE FROM THE GRAPH.
    //
    // This is what the graph is FOR. A CPU carrying a deep queue needs a
    // shorter slice so the queue drains. A CPU near-empty keeps the base: its
    // running task is not contending, and dispatch's keep-prev already lets it
    // run on without a context switch, so a longer slice there only lengthens
    // the hold a wakee meets when one does arrive. One slice for the whole
    // machine would solve the average of a distribution it cannot see -- the
    // average being wrong for every CPU that is not at the mean.
    //
    // DERIVED, NOT LEARNED. There is no loss signal, no convergence window and
    // no weight vector: depth is measured and the slice follows from it this
    // tick, the way codel_eq_ns is computed from R_eff.
    //
    // EACH CPU READS ITS DOMAIN. Every CPU in an L3 shares the domain queue, so
    // the CPUs of one domain derive the same knobs: the derivation is
    // per-domain, written per CPU. A CPU whose domain is not yet known, or whose
    // domain has no series, keeps the base.
    //
    // Returns one knob set per CPU, seeded from `base` so every field the graph
    // does not own is carried through untouched.
    pub fn derive_percpu_knobs(
        &self,
        base: &crate::tuning::TuningKnobs,
    ) -> Vec<crate::tuning::TuningKnobs> {
        // Reference depth: the mean over domains that actually reported. A
        // domain at the reference keeps the base slice exactly, so a uniformly
        // loaded machine, and any machine with a single domain, keeps the base
        // slice and moves on shape and persistence alone.
        let present: Vec<f64> = self
            .dom_depth
            .iter()
            .copied()
            .filter(|d| d.is_finite())
            .collect();
        let refd = if present.is_empty() {
            0.0
        } else {
            present.iter().sum::<f64>() / present.len() as f64
        };
        (0..self.n)
            .map(|i| {
                let mut k = *base;
                // THE WAKER'S SEAT. When WAKER_SEAT_LIVE, the layer turns on the
                // BPF's leaving-waker partner seat at the measured departure
                // bound, on every CPU and before any series gates the rest; the
                // BPF arm leaves it off.
                if WAKER_SEAT_LIVE {
                    k.waker_leave_ns = tuning::WAKER_LEAVE_NS;
                }
                let Some(dom) = self.cpu_dom.get(i).copied().flatten() else {
                    return k;
                };
                let d = self.dom_depth.get(dom).copied().unwrap_or(f64::NAN);
                // Absent series or a flat machine: the slice carries the base.
                // Every reading below prices itself, so only the slice is gated;
                // a domain with no lane depth still prices its batch and rescue.
                if d.is_finite() && refd > f64::EPSILON {
                    // Deeper than reference -> shorter slice, down to 1/2. A
                    // CPU at or under the reference keeps the base slice, never
                    // more: Shorten-only is the form proven on frame contended
                    // at N = 5 (v5.24.0, 1% lows +7.5 over the BPF arm), and the
                    // 2x a shallow domain once took gave frame contended's
                    // hogs the longer hold (1% lows avg 224 against 264).
                    let ratio = (refd / (d + refd).max(f64::EPSILON) * 2.0).clamp(0.5, 1.0);
                    k.slice_ns = ((base.slice_ns as f64) * ratio) as u64;
                }

                // BURSTINESS -> BATCH CEILING.
                // Paced traffic (B < 0) means steady arrivals, so a long
                // ceiling holds the CPU against work that is genuinely queued:
                // shortened by up to 50% across [-1, 0]. Bursty traffic
                // (B > 0) arrives in clumps, so a longer ceiling lets a clump
                // drain in fewer cuts: lengthened by up to 50% across [0, 1].
                if let Some(b) = self.dom_burst.get(dom).and_then(|v| *v) {
                    // weighted() collapses toward the neutral factor 1.0 as
                    // confidence falls, so a thin window nudges rather than swings.
                    let f = Priced {
                        value: 1.0 + 0.5 * b.value.clamp(-1.0, 1.0),
                        confidence: b.confidence,
                    }
                    .weighted(1.0);
                    k.batch_slice_ns = ((base.batch_slice_ns as f64) * f) as u64;
                }

                // PERSISTENCE -> CoDel RESCUE THRESHOLD.
                // H > 0.5 says this domain's load pattern tends to continue, so a
                // queue that is deep now will likely still be deep: rescue
                // sooner. H < 0.5 is mean-reverting, where a deep queue is
                // likely transient and rescuing early only scatters a task that
                // was about to be served anyway. Centered on H = 0.5 so an
                // uncorrelated domain keeps the base exactly.
                if let Some(h) = self.dom_persist.get(dom).and_then(|v| *v) {
                    let mut f = Priced {
                        value: (1.0f64 - (h.value.clamp(0.0, 1.0) - 0.5)).clamp(0.5, 1.5),
                        confidence: h.confidence,
                    }
                    .weighted(1.0);
                    // QUALIFIED. Persistence says how far to lower; the
                    // domain's starvation share says whether. A held task is
                    // starvation, which an earlier rescue answers; a draining
                    // backlog is overload, which it does not. No reading, no
                    // qualification.
                    if QUALIFIED_RESCUE_LIVE && f < 1.0 {
                        if let Some(s) = self.dom_starve.get(dom).copied().filter(|s| s.is_finite())
                        {
                            f = 1.0 - (1.0 - f) * s;
                        }
                    }
                    k.codel_thresh_ns = ((base.codel_thresh_ns as f64) * f) as u64;
                }

                // THE TAIL -> RESCUE SOONER. Where the domain's last-second
                // tail wait reaches past the base threshold, rescue sooner in
                // proportion, down to half at a tail of twice the base; under
                // it, the readings above decide. Lowers, never raises.
                let tail = self.dom_tail.get(dom).copied().unwrap_or(f64::NAN);
                if tail.is_finite() && tail > 0.0 {
                    let base_us = base.codel_thresh_ns as f64 / 1000.0;
                    let f = (base_us / tail).clamp(0.5, 1.0);
                    k.codel_thresh_ns = k
                        .codel_thresh_ns
                        .min(((base.codel_thresh_ns as f64) * f) as u64);
                }

                // QUEUE CLOCK -> STANDING HOLD. A standing task may hold the
                // CPU for standing_targets CoDel targets. A domain whose queued
                // runs (idle-seated wakes left out, which wait ~0us) wait longer
                // than the equilibrium target pays for those holds: shorter,
                // down to half. A domain at or under the equilibrium keeps the
                // base, never more, as task_slice reads the knob and as the
                // slice above: A hold lengthened under a shallow queue is the
                // hold a frame thread waits out behind a hog (frame contended).
                let eq_us = self.eq_us;
                let dw = self.dom_qwait.get(dom).copied().unwrap_or(f64::NAN);
                if eq_us > 0.0 && dw.is_finite() && dw > 0.0 {
                    let f = (eq_us / dw).clamp(0.5, 1.0);
                    k.standing_targets =
                        ((base.standing_targets as f64) * f).round().max(1.0) as u64;
                }

                // CRITICAL SLOWING -> RESCUE SOONER. A domain whose queue clock
                // recovers from each perturbation more slowly than a tick ago
                // is nearing a tail. Priced by the rise's null spread at this
                // window, sqrt(2/W): Silent while the rise is noise, toward half
                // as it reaches twice the one-sided 5% point (research t34: AUC
                // 0.84-0.90 ahead of fork-thread's tail events). Lowers, never
                // raises.
                let rise = self.dom_rise.get(dom).copied().unwrap_or(f64::NAN);
                let win = self.dom_lag1_n.get(dom).copied().unwrap_or(0) as f64;
                if rise.is_finite() && win >= 64.0 {
                    let z = rise / (2.0 / win).sqrt();
                    let s = ((z - 1.645) / 1.645).clamp(0.0, 1.0);
                    if s > 0.0 {
                        let f = 1.0 - 0.5 * s;
                        k.codel_thresh_ns = k
                            .codel_thresh_ns
                            .min(((base.codel_thresh_ns as f64) * f) as u64);
                    }
                }

                // COUPLING DRIVES NO PLACEMENT, AND THE REASON IS MEASURED.
                //
                // This briefly read coupling and bound strongly above a
                // midpoint, on the argument that runqueues moving together mean
                // tasks sharing data. That argument was reasoning, not
                // measurement, and the first full PRISM pass on v5.18.0 put a
                // number against it: baseline_gate reported every IPC primitive
                // regressed on every arm, worst pipe p50 20 -> 336us at drift
                // 1.04x, which is 16x with the environment ruled out.
                //
                // IPC is precisely a two-task ping-pong with tightly coupled
                // queue depths, so the derivation fired hardest exactly where
                // the damage landed. Whether coupling should raise affinity,
                // lower it, or not touch it is now an open question with
                // evidence on one side only, so coupling actuates nothing until
                // something measures the direction. mean_coupling() stays
                // as telemetry -- the reading is still wanted, the actuation is
                // not.
                k
            })
            .collect()
    }

    // Is there structure worth pricing against? Returns (available_edges,
    // mean, min, max) over the edges that computed. A spread near zero means
    // the coupling matrix is flat and the live graph adds nothing over the
    // static one.
    pub fn edge_summary(&self) -> (usize, f64, f64, f64) {
        let vals: Vec<f64> = self
            .edge
            .iter()
            .filter_map(|e| e.map(|p| p.value))
            .collect();
        if vals.is_empty() {
            return (0, 0.0, 0.0, 0.0);
        }
        let sum: f64 = vals.iter().sum();
        let mut lo = f64::INFINITY;
        let mut hi = f64::NEG_INFINITY;
        for v in &vals {
            if *v < lo {
                lo = *v;
            }
            if *v > hi {
                hi = *v;
            }
        }
        (vals.len(), sum / vals.len() as f64, lo, hi)
    }
}

// THE FLOW GRAPH. Each tick, the wakes and the migrations every CPU received
// from every other, the deltas of the BPF flow rows: the traffic between CPUs,
// observed, where coupling infers a relation from two CPUs' series. Directed
// counts at src * n + dst; a CPU's flow to itself is not an edge.
pub struct FlowGraph {
    pub wake: Vec<f64>,
    pub mig: Vec<f64>,
}

// ONE FLOW KIND ON ONE TICK.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct FlowReading {
    pub total: f64,
    // THE SHARE WHOSE SOURCE AND DESTINATION SIT IN DIFFERENT DOMAINS.
    pub cross_dom: f64,
    // HOW CLOSELY THE FLOW'S OWN FIEDLER CUT FOLLOWS THE DOMAINS: PER DOMAIN, ITS
    // CPUs ON THE SIDE MOST OF THEM TAKE, OVER EVERY CPU THE CUT READ. 1 WHEN
    // THE CUT IS THE DOMAIN BOUNDARY. None UNDER 4 CPUs WITH FLOW OR 2 DOMAINS.
    pub cut_purity: Option<f64>,
    // THE SHARE THE BUSIEST 10% OF DIRECTED PAIRS CARRY.
    pub top10: f64,
}

// POWER ITERATIONS AT MOST, AND THE STEP UNDER WHICH THE VECTOR HAS SETTLED.
const FIEDLER_ITERS: usize = 500;
const FIEDLER_EPS: f64 = 1e-9;

impl FlowGraph {
    pub fn from_rows(cur: &[FlowRow], prev: &[FlowRow], n: usize) -> Self {
        let mut wake = vec![0.0; n * n];
        let mut mig = vec![0.0; n * n];
        for (d, (c, p)) in cur.iter().zip(prev).enumerate().take(n) {
            for s in 0..n.min(c.wake.len()) {
                if s != d {
                    wake[s * n + d] = c.wake[s].wrapping_sub(p.wake[s]) as f64;
                    mig[s * n + d] = c.mig[s].wrapping_sub(p.mig[s]) as f64;
                }
            }
        }
        Self { wake, mig }
    }

    // ONE KIND'S READING. warm CARRIES THE LAST FIEDLER VECTOR BETWEEN TICKS SO
    // A FLOW THAT MOVED LITTLE SETTLES IN A FEW STEPS.
    pub fn reading(
        flow: &[f64],
        n: usize,
        cpu_dom: &[Option<usize>],
        warm: &mut Vec<f64>,
    ) -> Option<FlowReading> {
        let total: f64 = flow.iter().sum();
        if total <= 0.0 {
            return None;
        }
        let dom = |c: usize| cpu_dom.get(c).copied().flatten();
        let mut cross = 0.0;
        for s in 0..n {
            for d in 0..n {
                let x = flow[s * n + d];
                if x > 0.0 && dom(s).is_some() && dom(s) != dom(d) {
                    cross += x;
                }
            }
        }
        let mut dir: Vec<f64> = flow.iter().copied().filter(|&x| x > 0.0).collect();
        dir.sort_by(|a, b| b.total_cmp(a));
        let top10 = dir.iter().take((dir.len() / 10).max(1)).sum::<f64>() / total;

        let active: Vec<usize> = (0..n)
            .filter(|&c| {
                dom(c).is_some() && (0..n).any(|o| flow[c * n + o] > 0.0 || flow[o * n + c] > 0.0)
            })
            .collect();
        let mut doms: Vec<usize> = active.iter().filter_map(|&c| dom(c)).collect();
        doms.sort_unstable();
        doms.dedup();
        let cut_purity = (active.len() >= 4 && doms.len() >= 2).then(|| {
            let sym: Vec<f64> = (0..n * n)
                .map(|x| flow[x] + flow[(x % n) * n + x / n])
                .collect();
            let v = fiedler(&sym, &active, n, warm);
            let mut sides = vec![(0usize, 0usize); doms.last().map_or(0, |d| d + 1)];
            for (&c, &x) in active.iter().zip(&v) {
                if let Some(d) = dom(c) {
                    if x >= 0.0 {
                        sides[d].0 += 1;
                    } else {
                        sides[d].1 += 1;
                    }
                }
            }
            sides.iter().map(|&(a, b)| a.max(b)).sum::<usize>() as f64 / active.len() as f64
        });
        Some(FlowReading {
            total,
            cross_dom: cross / total,
            cut_purity,
            top10,
        })
    }
}

// THE FIEDLER VECTOR OF A SYMMETRIC WEIGHT MATRIX OVER THE CPUs IN idx, BY POWER
// ITERATION ON (c I - L) WITH THE CONSTANT VECTOR DEFLATED (research t13). A warm
// VECTOR OF THE RIGHT LENGTH SEEDS IT; THE RESULT IS LEFT IN warm.
fn fiedler(w: &[f64], idx: &[usize], n: usize, warm: &mut Vec<f64>) -> Vec<f64> {
    let m = idx.len();
    let mut l = vec![0.0; m * m];
    for a in 0..m {
        for b in 0..m {
            if a != b {
                let x = w[idx[a] * n + idx[b]];
                l[a * m + b] = -x;
                l[a * m + a] += x;
            }
        }
    }
    let c = (0..m).map(|a| l[a * m + a]).fold(0.0, f64::max) * 2.0 + 1e-9;
    let mut v: Vec<f64> = if warm.len() == m {
        warm.clone()
    } else {
        (0..m).map(|i| ((i * 7919) % 13) as f64 - 6.0).collect()
    };
    for _ in 0..FIEDLER_ITERS {
        let mu = v.iter().sum::<f64>() / m as f64;
        v.iter_mut().for_each(|x| *x -= mu);
        let mut nv = vec![0.0; m];
        for a in 0..m {
            let mut s = c * v[a];
            for b in 0..m {
                s -= l[a * m + b] * v[b];
            }
            nv[a] = s;
        }
        let nrm = nv.iter().map(|x| x * x).sum::<f64>().sqrt().max(1e-300);
        nv.iter_mut().for_each(|x| *x /= nrm);
        let step: f64 = nv
            .iter()
            .zip(&v)
            .map(|(a, b)| (a - b) * (a - b))
            .sum::<f64>()
            .sqrt();
        v = nv;
        if step < FIEDLER_EPS {
            break;
        }
    }
    *warm = v.clone();
    v
}

// ONE FLOW KIND'S READINGS OVER A RUN, FOR THE GRAPH PROM.
#[derive(Default)]
struct FlowAcc {
    ticks: u64,
    total: f64,
    cross: f64,
    top10: f64,
    purity: f64,
    purity_n: u64,
    churn: f64,
    churn_n: u64,
}

impl FlowAcc {
    fn prom(&self, kind: &str) -> String {
        let t = self.ticks.max(1) as f64;
        format!(
            "pandemonium_flow_{kind}_per_s {:.1}\n\
             pandemonium_flow_{kind}_cross_dom_share {:.4}\n\
             pandemonium_flow_{kind}_top10_share {:.4}\n\
             pandemonium_flow_{kind}_cut_purity {:.4}\n\
             pandemonium_flow_{kind}_cut_ticks {}\n\
             pandemonium_flow_{kind}_churn {:.4}\n",
            self.total / t,
            self.cross / t,
            self.top10 / t,
            self.purity / self.purity_n.max(1) as f64,
            self.purity_n,
            self.churn / self.churn_n.max(1) as f64
        )
    }
}

// HOW FAR A FLOW MOVED SINCE THE LAST TICK: HALF THE L1 DISTANCE BETWEEN THE
// TWO TICKS' FLOWS, EACH NORMALIZED TO ITS TOTAL. 0 UNCHANGED, 1 DISJOINT.
fn flow_churn(prev: &[f64], cur: &[f64]) -> Option<f64> {
    let (ps, cs): (f64, f64) = (prev.iter().sum(), cur.iter().sum());
    (ps > 0.0 && cs > 0.0 && prev.len() == cur.len()).then(|| {
        prev.iter()
            .zip(cur)
            .map(|(a, b)| (a / ps - b / cs).abs())
            .sum::<f64>()
            / 2.0
    })
}

// SLEEP PATTERN BUCKETS: CLASSIFY IO-WAIT VS IDLE WORKLOADS
const SLEEP_BUCKETS: usize = 4;

// MONITOR LOOP

// 1-SECOND CONTROL LOOP. READS BPF HISTOGRAMS, COMPUTES P99,
// DETECTS WORKLOAD REGIME, TIGHTENS/RELAXES KNOBS.
// RUNS ON THE MAIN THREAD.
pub fn monitor_loop(
    sched: &mut Scheduler,
    shutdown: &'static AtomicBool,
    verbose: bool,
    nr_cpus: u64,
) -> Result<bool> {
    // HOTPLUG POLL STATE: the online count as last observed. The poll below
    // re-derives topology on change AND refreshes the Rust-local tau_ns --
    // without that refresh, a hotplug that changes tau without flipping the
    // regime leaves every knob derived off pre-hotplug tau until a regime
    // change happens to land.
    let mut last_online = CpuTopology::online_cpu_count();
    let mut prev = PandemoniumStats::default();
    let mut prev_hist = [[0u64; HIST_BUCKETS]; 3];
    let mut prev_sleep = [0u64; SLEEP_BUCKETS];
    let mut regime = Regime::Mixed;

    // CHAOS RAW WINDOWS, ONE SAMPLE PER RING BUCKET. THE IDLE-HIT SHARE DRIVES
    // REGIME DETECTION; THE WAKES' BANDT-POMPE ENTROPY FEEDS IT TOO AND FLAGS
    // CHAOS CROSSINGS (BANDT-POMPE IS ORDINAL, SO ABSOLUTE RATE SCALE DOES NOT
    // MATTER -- THE PATTERN DOES).
    let mut idle_win: RawWindow<DEPTH_WIN> = RawWindow::new();
    let mut wake_win: RawWindow<DEPTH_WIN> = RawWindow::new();
    let mut rqa_win: RawWindow<RQA_WIN> = RawWindow::new();
    // PER-CPU RUNQUEUE-DEPTH WINDOWS: THE NODES OF THE LIVE LOAD GRAPH.
    // One series per CPU, each sample the mean depth on that CPU over one
    // bucket of the BPF depth ring. Until v5.18.0 there was exactly ONE series
    // in this whole loop -- a system-wide integer percentage -- which is why a
    // coupling measure had nothing to couple.
    let mut depth_win: Vec<RawWindow<DEPTH_WIN>> =
        (0..nr_cpus as usize).map(|_| RawWindow::new()).collect();
    // DOMAIN LANE DEPTH WINDOWS, ONE PER DOMAIN, indexed by the domain id the
    // ring reports. Each sample sums the lane depth of the domain's CPUs that
    // ticked in the bucket, the requeues waiting there, where a saturated
    // population sits; the per-CPU seat series cannot see it.
    let mut dom_win: Vec<RawWindow<DEPTH_WIN>> = Vec::new();
    let mut dom_acc: Vec<(f64, u32)> = Vec::new();
    // THE GRAPH'S SERIES. Per CPU: the queue clock (mean wait of the runs in a
    // bucket, us) and arrivals (runs that ended a wake). Per domain: its CPUs'
    // waits pooled by run. A CPU that neither ticked nor ran in a bucket was
    // idle: no wait sample, zero arrivals.
    let mut wait_win: Vec<RawWindow<DEPTH_WIN>> =
        (0..nr_cpus as usize).map(|_| RawWindow::new()).collect();
    let mut cnt_win: Vec<RawWindow<DEPTH_WIN>> =
        (0..nr_cpus as usize).map(|_| RawWindow::new()).collect();
    let mut dom_wait_win: Vec<RawWindow<DEPTH_WIN>> = Vec::new();
    // EACH DOMAIN'S LAG-1 ON RANKS AS OF THE PREVIOUS BUILT TICK, FOR ITS RISE.
    let mut prev_dom_lag1: Vec<f64> = Vec::new();
    let mut dom_qacc: Vec<(f64, f64)> = Vec::new();
    // Per domain, the waits of the runs that queued, idle-seated wakes left
    // out: the bucket's (wait sum, runs less idle hits), and its window.
    let mut dom_qqacc: Vec<(f64, f64)> = Vec::new();
    let mut dom_qwait_win: Vec<RawWindow<DEPTH_WIN>> = Vec::new();
    // Per domain, its CPUs' arrivals pooled, an idle CPU counting zero: the
    // stream the domain's burstiness and persistence lenses are built for.
    let mut dom_cnt_win: Vec<RawWindow<DEPTH_WIN>> = Vec::new();
    let mut dom_cacc: Vec<(f64, u32)> = Vec::new();
    // Per domain, per bucket, the share of its CPUs that ran whose shortest wait
    // stayed above the CoDel equilibrium, and the bucket's (above, ran) counts.
    let mut dom_starve_win: Vec<RawWindow<DEPTH_WIN>> = Vec::new();
    let mut dom_sacc: Vec<(u32, u32)> = Vec::new();
    // EACH CPU'S DOMAIN, AS ITS OWN RING LAST REPORTED IT. None UNTIL IT TICKS.
    let mut cpu_dom: Vec<Option<usize>> = vec![None; nr_cpus as usize];
    // LAST RING EPOCH DRAINED. 0 BEFORE THE FIRST DRAIN.
    let mut depth_cursor: u64 = 0;
    // THE BUCKET RATE, MEASURED. The ring's epoch advances once per bucket, so
    // the epochs between two drains over the time between them sets how many
    // samples WINDOW_SPAN_S holds.
    let mut span_epoch: u64 = 0;
    let mut span_at = std::time::Instant::now();
    let mut window_span: usize = DEPTH_WIN;
    let mut bucket_rate: f64 = 0.0;
    // EACH CPU'S RECENT DERIVED slice, batch AND rescue, FOR THE EVIDENCE BAND.
    let mut evidence: Vec<[RawWindow<EVIDENCE_TICKS>; 4]> = Vec::new();
    // THE COUPLING EDGES, CARRIED BETWEEN TICKS, AND THE NEXT PAIR TO RECOMPUTE.
    let mut edge_cache: Vec<Option<Priced>> = Vec::new();
    let mut edge_cursor: (usize, usize) = (0, 1);
    let mut prev_bp_h: f64 = 0.0;
    let chaos_count = chaos::ChaosCounter::new();
    let mut prev_lambda_above: bool = false;
    // READ CURRENT tau SNAPSHOT FROM THE BPF-SIDE KNOB MAP. main.rs WROTE IT
    // ONCE AT TOPOLOGY DETECT; THE ADAPTIVE LOOP RE-READS SO TAU-SCALED REGIME
    // KNOBS AGREE WITH TAU-SCALED BPF INIT AT FIRST TICK AND EVERY REGIME CHANGE.
    let mut tau_ns = sched.read_tuning_knobs().topology_tau_ns;
    let mut pending_regime = regime;
    let mut regime_hold: u32 = 0;
    let mut light_ticks: u64 = 0;
    let mut mixed_ticks: u64 = 0;
    let mut heavy_ticks: u64 = 0;
    // THE SAME TICKS SINCE THE LAST PHASE CUT, AND THE CUTS PRINTED.
    let mut phase_ticks = [0u64; 3];
    let mut phase_n: u64 = 0;
    // STABILITY SCORE IS A WEAK PRE-CHAOS STEADY-STATE PROXY, KEPT FOR
    // TELEMETRY GATING ONLY -- THE REAL STEADY-STATE GATE
    // IS `quiesce.frozen` BELOW. DO NOT WIRE stability_score INTO THE
    // FREEZE DECISION (TWO COMPETING "AM I STEADY" SIGNALS = A BUG).
    let mut stability_score: u32 = 0;
    let mut tick_counter: u64 = 0;

    // QUIESCENCE GATE + ADAPTIVE-RARITY RETUNE STATE. The gate latches
    // a "frozen" flag from occupancy, corroborated by HVG-lambda and RQA-DET,
    // and the loop then skips the knob retune and write. When
    // not frozen, the retune interval stretches on sub-threshold deltas.
    let mut quiesce = tuning::QuiescenceState::new();
    let mut retune_interval: u32 = tuning::RETUNE_INTERVAL_BASE;
    let mut ticks_since_retune: u32 = 0;
    let mut frozen_ticks: u64 = 0;
    let mut occupied_ticks: u64 = 0;
    // GRAPH SUMMARY ACCUMULATORS. The scheduler writes its own telemetry file
    // at shutdown rather than relying on a bench to capture stdout: three
    // separate benches discarded it three different ways (no recording dir, a
    // path that bypassed the marker writer, and stdout sent to DEVNULL), and
    // the coupling reading went unread each time. A producer that owns its own
    // artifact cannot be defeated by a consumer's plumbing.
    let mut g_tick: u64 = 0;
    let mut g_edge_ticks: u64 = 0;
    let mut g_edges_total: u64 = 0;
    let mut g_mean_sum: f64 = 0.0;
    let mut g_spread_sum: f64 = 0.0;
    let mut g_spread_max: f64 = 0.0;
    // LENS AND DEPTH-SERIES ACCUMULATORS. A lens counts as available on a node
    // only at full confidence, the weight its derivation is written for; the
    // edge lens counts any coupling value. Own-queue and domain-queue
    // variability sit side by side so a saturated run shows which series moves.
    let mut g_depth_samples: u64 = 0;
    let mut g_node_ticks: u64 = 0;
    let mut g_burst_full: u64 = 0;
    let mut g_slowing_full: u64 = 0;
    let mut g_persist_full: u64 = 0;
    let mut g_pair_ticks: u64 = 0;
    let mut g_pair_some: u64 = 0;
    let (mut g_own_sd_sum, mut g_own_sd_n) = (0.0f64, 0u64);
    let (mut g_dom_sd_sum, mut g_dom_sd_n) = (0.0f64, 0u64);
    let (mut g_dom_mean_sum, mut g_dom_mean_n) = (0.0f64, 0u64);
    let (mut g_dom_wait_sum, mut g_dom_wait_n) = (0.0f64, 0u64);
    // The domain lenses on arrivals, which actuate, beside the same lenses on
    // lane depth, the reading they replaced, so one run shows both.
    let (mut g_dom_burst_sum, mut g_dom_burst_n) = (0.0f64, 0u64);
    let (mut g_dom_persist_sum, mut g_dom_persist_n) = (0.0f64, 0u64);
    let (mut g_depth_burst_sum, mut g_depth_burst_n) = (0.0f64, 0u64);
    let (mut g_depth_persist_sum, mut g_depth_persist_n) = (0.0f64, 0u64);
    // DOMAIN-TICKS WITH A SLOWING READING, AND THOSE WHERE IT LOWERED THE RESCUE.
    let (mut g_slowing_dom_ticks, mut g_slowing_fired) = (0u64, 0u64);
    // DOMAIN-TICKS WITH A TAIL READING, AND THOSE WHERE IT PASSED THE BASE.
    let (mut g_tail_dom_ticks, mut g_tail_fired) = (0u64, 0u64);
    // THE DOMAINS' STARVATION SHARES, SUMMED OVER DOMAIN-TICKS.
    let (mut g_starve_sum, mut g_starve_n) = (0.0f64, 0u64);
    // EVERY CPU'S WRITTEN KNOBS AND WHAT BPF APPLIES FOR THEM, EVERY TICK, IN
    // KNOB_NAMES ORDER.
    let mut g_knob_written = [0.0f64; KNOB_NAMES.len()];
    let mut g_knob_applied = [0.0f64; KNOB_NAMES.len()];
    let mut g_knob_n: u64 = 0;
    // THE CoDel EQUILIBRIUM, WRITTEN AND APPLIED, EVERY TICK.
    let (mut g_eq_written, mut g_eq_applied, mut g_eq_n) = (0.0f64, 0.0f64, 0u64);
    // THE FLOW GRAPH: THE ROWS AS LAST READ, AND PER KIND (WAKE, MIGRATION) THE
    // LAST TICK'S FLOW, ITS FIEDLER VECTOR AND THE RUN'S READINGS.
    let mut prev_flow: Vec<FlowRow> = Vec::new();
    let mut flow_last: [Vec<f64>; 2] = [Vec::new(), Vec::new()];
    let mut flow_warm: [Vec<f64>; 2] = [Vec::new(), Vec::new()];
    let mut flow_acc: [FlowAcc; 2] = Default::default();
    // THE REFILL TABLE, THE READINGS THE BASE COST WRITES FROM, THE TICK OF THE
    // LAST ONE AND THE RUN's MEANS.
    let mut refill = RefillPairs::new();
    let mut refill_win: RawWindow<EVIDENCE_TICKS> = RawWindow::new();
    let mut refill_last: u64 = 0;
    let mut phi_candidate: u64 = 0;
    let (mut g_refill_sum, mut g_refill_medmed_sum) = (0.0f64, 0.0f64);
    let (mut g_refill_tasks, mut g_refill_ticks) = (0u64, 0u64);

    // APPLY INITIAL REGIME. scaled_regime_knobs RETURNS topology_tau_ns/codel_eq_ns=0;
    // OVERLAY THE LIVE BPF VALUES SO THE FIRST WRITE DOESN'T CLOBBER WHAT
    // write_topology_fields() PUT IN THE MAP. Mirrors the regime-change path at line 230.
    let live = sched.read_tuning_knobs();
    let mut rk = scaled_regime_knobs(regime, nr_cpus, tau_ns);
    rk.topology_tau_ns = tau_ns;
    rk.codel_eq_ns = live.codel_eq_ns;
    sched.write_tuning_knobs(&rk)?;
    // COMMIT-ON-CHANGE BASELINE: the per-CPU knob set last written to the BPF
    // map. Updated here at init, on every regime-change write and on every
    // conditional write; the per-CPU fields drive the diff.
    let mut last_written: Vec<tuning::TuningKnobs> = vec![rk; depth_win.len()];
    // IN-REGIME WRITES: how often a moving derivation reached BPF between regime
    // changes, and how far apart the CPUs' slices sat when it did.
    let mut knob_writes: u64 = 0;
    let mut knob_writes_deferred: u64 = 0;
    let mut slice_spread_sum_us: f64 = 0.0;

    while !shutdown.load(Ordering::Relaxed) && !sched.exited() {
        crate::watchdog::LOOP_HEARTBEAT.fetch_add(1, Ordering::Relaxed);
        std::thread::sleep(Duration::from_secs(1));

        if CpuTopology::poll_hotplug(sched, nr_cpus as usize, &mut last_online) {
            tau_ns = sched.read_tuning_knobs().topology_tau_ns;
            // THE TOPOLOGY WRITE RESET EVERY LIVE FIELD TO THE NEW BASE AND
            // phi_base_ns TO 0, SO WHAT IS WRITTEN IS NOW THAT: THE NEXT RETUNE,
            // PULLED TO THIS TICK, RE-ASSERTS WHAT THE LAYER DERIVES. THE REFILL
            // POOLS WERE CLASSED ON THE OLD DOMAIN MAP AND RE-MEASURE FROM HERE.
            for (lw, k) in last_written
                .iter_mut()
                .zip(sched.read_tuning_knobs_percpu())
            {
                *lw = k;
            }
            retune_interval = tuning::RETUNE_INTERVAL_BASE;
            refill = RefillPairs::new();
            refill_win = RawWindow::new();
            phi_candidate = 0;
        }

        // THE ARRAY, UNCOLLAPSED. `stats` below is the same fold this loop
        // always consumed; `percpu` is the spatial dimension that used to be
        // discarded at the boundary. Both come from ONE syscall.
        let percpu = sched.read_stats_percpu();
        let stats = Scheduler::fold_stats(&percpu);
        let cur_hist = sched.read_wake_lat_hist();
        let cur_sleep = sched.read_sleep_hist();

        // WRAP GUARD: BPF RELOAD, UEI RECOVERY, OR HOTPLUG CAN RESET KERNEL-SIDE
        // CUMULATIVE COUNTERS WHILE RUST'S PREV STILL HOLDS OLD VALUES. WITHOUT
        // THIS CHECK, WRAPPING_SUB PRODUCES A GARBAGE POSITIVE DELTA THAT POISONS
        // P99 AND EVERY RATE THE LOOP DERIVES. RESET BASELINE AND SKIP THE TICK.
        let mut wrapped = stats.nr_dispatches < prev.nr_dispatches;
        if !wrapped {
            'wrap: for tier in 0..3 {
                for b in 0..HIST_BUCKETS {
                    if cur_hist[tier][b] < prev_hist[tier][b] {
                        wrapped = true;
                        break 'wrap;
                    }
                }
            }
        }
        if !wrapped {
            for i in 0..SLEEP_BUCKETS {
                if cur_sleep[i] < prev_sleep[i] {
                    wrapped = true;
                    break;
                }
            }
        }
        if wrapped {
            log_warn!("WRAP DETECTED: BASELINE RESET, SKIPPING ADAPTIVE UPDATE");
            prev = stats;
            prev_hist = cur_hist;
            prev_sleep = cur_sleep;
            continue;
        }

        // THE REFILL READING: THE RINGS' NEW RECORDS INTO THE TASKS' POOLS, THEN
        // THE PAIRED MEDIAN. A SPAN WITH NO READING RETIRES THE WINDOW AND THE
        // CANDIDATE, AND THE 0 WRITTEN NEXT RESTORES tau's COST.
        refill.ingest(&sched.read_refill_rings(), tick_counter);
        if let Some(r) = refill.reading(tick_counter) {
            refill_win.push(r.paired_ns);
            refill_last = tick_counter;
            g_refill_sum += r.paired_ns;
            g_refill_medmed_sum += r.medmed_ns;
            g_refill_tasks += r.tasks as u64;
            g_refill_ticks += 1;
        } else if tick_counter.saturating_sub(refill_last) >= REFILL_SPAN_TICKS
            && !refill_win.is_empty()
        {
            refill_win = RawWindow::new();
            phi_candidate = 0;
        }

        // COMPUTE DELTAS
        let delta_d = stats.nr_dispatches.wrapping_sub(prev.nr_dispatches);
        let delta_idle = stats.nr_idle_hits.wrapping_sub(prev.nr_idle_hits);
        let delta_shared = stats.nr_shared.wrapping_sub(prev.nr_shared);
        let delta_preempt = stats.nr_preempt.wrapping_sub(prev.nr_preempt);
        let delta_keep = stats.nr_keep_running.wrapping_sub(prev.nr_keep_running);
        let delta_parks = stats.nr_osc_park.wrapping_sub(prev.nr_osc_park);
        let delta_wake_sum = stats.wake_lat_sum.wrapping_sub(prev.wake_lat_sum);
        let delta_wake_samples = stats.wake_lat_samples.wrapping_sub(prev.wake_lat_samples);
        let delta_hard = stats.nr_hard_kicks.wrapping_sub(prev.nr_hard_kicks);
        let delta_soft = stats.nr_soft_kicks.wrapping_sub(prev.nr_soft_kicks);
        let delta_steal = stats.nr_steal.wrapping_sub(prev.nr_steal);
        let delta_enq_wake = stats.nr_enq_wakeup.wrapping_sub(prev.nr_enq_wakeup);
        let delta_enq_requeue = stats.nr_enq_requeue.wrapping_sub(prev.nr_enq_requeue);
        let delta_rescue = stats.nr_rescue.wrapping_sub(prev.nr_rescue);
        let wake_avg_us = if delta_wake_samples > 0 {
            delta_wake_sum / delta_wake_samples / 1000
        } else {
            0
        };

        // PER-PATH LATENCY
        let d_idle_sum = stats.wake_lat_idle_sum.wrapping_sub(prev.wake_lat_idle_sum);
        let d_idle_cnt = stats.wake_lat_idle_cnt.wrapping_sub(prev.wake_lat_idle_cnt);
        let d_kick_sum = stats.wake_lat_kick_sum.wrapping_sub(prev.wake_lat_kick_sum);
        let d_kick_cnt = stats.wake_lat_kick_cnt.wrapping_sub(prev.wake_lat_kick_cnt);
        let lat_idle_us = if d_idle_cnt > 0 {
            d_idle_sum / d_idle_cnt / 1000
        } else {
            0
        };
        let lat_kick_us = if d_kick_cnt > 0 {
            d_kick_sum / d_kick_cnt / 1000
        } else {
            0
        };
        let delta_reenq = stats.nr_reenqueue.wrapping_sub(prev.nr_reenqueue);

        // L2 CACHE AFFINITY DELTAS
        let dl2_hb = stats.nr_l2_hit_batch.wrapping_sub(prev.nr_l2_hit_batch);
        let dl2_mb = stats.nr_l2_miss_batch.wrapping_sub(prev.nr_l2_miss_batch);
        let dl2_hi = stats
            .nr_l2_hit_interactive
            .wrapping_sub(prev.nr_l2_hit_interactive);
        let dl2_mi = stats
            .nr_l2_miss_interactive
            .wrapping_sub(prev.nr_l2_miss_interactive);
        let l2_pct_b = if dl2_hb + dl2_mb > 0 {
            dl2_hb * 100 / (dl2_hb + dl2_mb)
        } else {
            0
        };
        let l2_pct_i = if dl2_hi + dl2_mi > 0 {
            dl2_hi * 100 / (dl2_hi + dl2_mi)
        } else {
            0
        };

        let idle_pct = if delta_d > 0 {
            delta_idle * 100 / delta_d
        } else {
            0
        };

        // COMPUTE HISTOGRAM DELTAS (cur_hist READ AT TOP FOR WRAP GUARD)
        let mut delta_hist = [[0u64; HIST_BUCKETS]; 3];
        for tier in 0..3 {
            for b in 0..HIST_BUCKETS {
                delta_hist[tier][b] = cur_hist[tier][b] - prev_hist[tier][b];
            }
        }

        // COMPUTE P99 PER TIER
        let tp99_b_ns = tuning::compute_p99_from_histogram(&delta_hist[0]);
        let tp99_i_ns = tuning::compute_p99_from_histogram(&delta_hist[1]);
        let tp99_l_ns = tuning::compute_p99_from_histogram(&delta_hist[2]);

        // AGGREGATE P99
        let mut agg = [0u64; HIST_BUCKETS];
        for t in 0..3 {
            for b in 0..HIST_BUCKETS {
                agg[b] += delta_hist[t][b];
            }
        }
        let p99_ns = tuning::compute_p99_from_histogram(&agg);

        // SLEEP HISTOGRAM DELTAS (cur_sleep READ AT TOP FOR WRAP GUARD)
        let mut delta_sleep = [0u64; SLEEP_BUCKETS];
        for i in 0..SLEEP_BUCKETS {
            delta_sleep[i] = cur_sleep[i] - prev_sleep[i];
        }
        let sleep_total: u64 = delta_sleep.iter().sum();
        let io_pct = if sleep_total > 0 {
            (delta_sleep[0] + delta_sleep[1]) * 100 / sleep_total
        } else {
            0
        };

        // NODE WEIGHTS: EVERY RING SAMPLE SINCE THE LAST TICK, FROM THE BPF
        // RING, oldest first. The newest epoch any CPU has written is the
        // bucket still filling, so the drain stops short of it. A slot counts
        // for an epoch only when its epoch matches. A CPU that did not tick in a
        // bucket gives no depth sample and one that ran nothing gives no wait
        // sample, rather than a zero, since no samples is not an empty queue;
        // its arrivals are zero, which is exactly what an idle CPU received. A
        // domain's depth sample is the sum of its CPUs' lane depths over those
        // that ticked in the bucket. A cursor ahead of the ring
        // (first drain, a stalled loop, a hotplug that changed the bucket
        // width) restarts from the oldest slot the ring still holds.
        let rings = sched.read_depth_rings();
        // THE EQUILIBRIUM A BUCKET'S SHORTEST WAIT IS JUDGED AGAINST, IN US: THE
        // ONE BPF APPLIES, BESIDE THE ONE WRITTEN.
        let eq_written = sched.read_tuning_knobs().codel_eq_ns;
        let eq_applied = sched.read_oscillator_state().applied_eq(eq_written);
        let eq_us_now = eq_applied as f64 / 1000.0;
        g_eq_written += eq_written as f64;
        g_eq_applied += eq_applied as f64;
        g_eq_n += 1;
        let mut depth_pushed: u64 = 0;
        let mut depth_occupied = false;
        if let Some(newest) = rings
            .iter()
            .flat_map(|r| r.slot.iter())
            .filter(|s| s.ticks > 0 || s.runs > 0)
            .map(|s| s.epoch)
            .max()
        {
            let span = DEPTH_RING_SLOTS as u64;
            let mut e =
                if depth_cursor == 0 || newest <= depth_cursor || newest - depth_cursor > span {
                    newest.saturating_sub(span - 1)
                } else {
                    depth_cursor + 1
                };
            while e < newest {
                let idx = (e % span) as usize;
                dom_acc.iter_mut().for_each(|a| *a = (0.0, 0));
                dom_qacc.iter_mut().for_each(|a| *a = (0.0, 0.0));
                dom_qqacc.iter_mut().for_each(|a| *a = (0.0, 0.0));
                dom_cacc.iter_mut().for_each(|a| *a = (0.0, 0));
                dom_sacc.iter_mut().for_each(|a| *a = (0, 0));
                // THE MACHINE'S RUNS, IDLE HITS AND WAKES IN THIS BUCKET.
                let (mut b_runs, mut b_idle, mut b_wakes) = (0u64, 0u64, 0u64);
                for (i, r) in rings.iter().enumerate().take(depth_win.len()) {
                    let s = &r.slot[idx];
                    if s.epoch == e {
                        b_runs += s.runs as u64;
                        b_idle += s.idle as u64;
                        b_wakes += s.wakes as u64;
                    }
                    if s.epoch != e || (s.ticks == 0 && s.runs == 0) {
                        if let Some(d) = cpu_dom[i] {
                            cnt_win[i].push(0.0);
                            if let Some(c) = dom_cacc.get_mut(d) {
                                c.1 += 1;
                            }
                        }
                        continue;
                    }
                    let d = r.domain as usize;
                    cpu_dom[i] = Some(d);
                    if d >= dom_acc.len() {
                        dom_acc.resize(d + 1, (0.0, 0));
                        dom_qacc.resize(d + 1, (0.0, 0.0));
                        dom_qqacc.resize(d + 1, (0.0, 0.0));
                    }
                    if d >= dom_cacc.len() {
                        dom_cacc.resize(d + 1, (0.0, 0));
                    }
                    dom_cacc[d].0 += s.wakes as f64;
                    dom_cacc[d].1 += 1;
                    if s.ticks > 0 {
                        let t = s.ticks as f64;
                        depth_win[i].push(s.own as f64 / t);
                        depth_pushed += 1;
                        dom_acc[d].0 += s.lane as f64 / t;
                        dom_acc[d].1 += 1;
                    }
                    // The local DSQ counts: hand-offs and cuts wait there, and
                    // a waiter is a waiter whichever queue holds it.
                    depth_occupied |= s.own > 0 || s.lane > 0 || s.loc > 0;
                    if s.runs > 0 {
                        wait_win[i].push(s.wait_us as f64 / s.runs as f64);
                        if d >= dom_sacc.len() {
                            dom_sacc.resize(d + 1, (0, 0));
                        }
                        dom_sacc[d].1 += 1;
                        if eq_us_now > 0.0 && s.min_wait_us as f64 > eq_us_now {
                            dom_sacc[d].0 += 1;
                        }
                    }
                    cnt_win[i].push(s.wakes as f64);
                    dom_qacc[d].0 += s.wait_us as f64;
                    dom_qacc[d].1 += s.runs as f64;
                    dom_qqacc[d].0 += s.wait_us as f64;
                    dom_qqacc[d].1 += s.runs.saturating_sub(s.idle) as f64;
                }
                if dom_win.len() < dom_acc.len() {
                    dom_win.resize_with(dom_acc.len(), RawWindow::new);
                    dom_wait_win.resize_with(dom_acc.len(), RawWindow::new);
                }
                for (d, &(sum, n)) in dom_acc.iter().enumerate() {
                    if n > 0 {
                        dom_win[d].push(sum);
                    }
                }
                for (d, &(wsum, runs)) in dom_qacc.iter().enumerate() {
                    if runs > 0.0 {
                        dom_wait_win[d].push(wsum / runs);
                    }
                }
                if dom_qwait_win.len() < dom_qqacc.len() {
                    dom_qwait_win.resize_with(dom_qqacc.len(), RawWindow::new);
                }
                for (d, &(wsum, queued)) in dom_qqacc.iter().enumerate() {
                    if queued > 0.0 {
                        dom_qwait_win[d].push(wsum / queued);
                    }
                }
                if dom_cnt_win.len() < dom_cacc.len() {
                    dom_cnt_win.resize_with(dom_cacc.len(), RawWindow::new);
                }
                for (d, &(arrivals, cpus)) in dom_cacc.iter().enumerate() {
                    if cpus > 0 {
                        dom_cnt_win[d].push(arrivals);
                    }
                }
                if dom_starve_win.len() < dom_sacc.len() {
                    dom_starve_win.resize_with(dom_sacc.len(), RawWindow::new);
                }
                for (d, &(above, ran)) in dom_sacc.iter().enumerate() {
                    if ran > 0 {
                        dom_starve_win[d].push(above as f64 / ran as f64);
                    }
                }
                // A BUCKET NO CPU RAN IN GIVES NO IDLE SHARE, AND ITS WAKES ARE
                // ZERO, WHICH IS WHAT THE MACHINE RECEIVED.
                if b_runs > 0 {
                    let share = b_idle as f64 * 100.0 / b_runs as f64;
                    idle_win.push(share);
                    rqa_win.push(share);
                }
                wake_win.push(b_wakes as f64);
                e += 1;
            }
            depth_cursor = newest - 1;
            let now = std::time::Instant::now();
            let dt = now.duration_since(span_at).as_secs_f64();
            if span_epoch > 0 && newest > span_epoch && dt >= 0.5 {
                bucket_rate = (newest - span_epoch) as f64 / dt;
                window_span =
                    ((WINDOW_SPAN_S * bucket_rate).ceil() as usize).clamp(WINDOW_MIN, DEPTH_WIN);
            }
            span_epoch = newest;
            span_at = now;
        }
        // THE FLOW GRAPH, FROM THE FLOW ROWS' DELTAS SINCE THE LAST TICK. THE
        // FIRST READ SEEDS THE BASE.
        let rows = sched.read_flow_rows();
        if !rows.is_empty() && prev_flow.len() == rows.len() {
            let n = depth_win.len().min(rows.len());
            let fg = FlowGraph::from_rows(&rows, &prev_flow, n);
            for (k, flow) in [&fg.wake, &fg.mig].into_iter().enumerate() {
                if let Some(r) = FlowGraph::reading(flow, n, &cpu_dom, &mut flow_warm[k]) {
                    let a = &mut flow_acc[k];
                    a.ticks += 1;
                    a.total += r.total;
                    a.cross += r.cross_dom;
                    a.top10 += r.top10;
                    if let Some(p) = r.cut_purity {
                        a.purity += p;
                        a.purity_n += 1;
                    }
                }
                if let Some(c) = flow_churn(&flow_last[k], flow) {
                    flow_acc[k].churn += c;
                    flow_acc[k].churn_n += 1;
                }
                flow_last[k] = flow.clone();
            }
        }
        prev_flow = rows;

        idle_win.set_span(window_span);
        wake_win.set_span(window_span);
        for w in depth_win
            .iter_mut()
            .chain(dom_win.iter_mut())
            .chain(wait_win.iter_mut())
            .chain(cnt_win.iter_mut())
            .chain(dom_wait_win.iter_mut())
            .chain(dom_cnt_win.iter_mut())
            .chain(dom_starve_win.iter_mut())
            .chain(dom_qwait_win.iter_mut())
        {
            w.set_span(window_span);
        }

        // CHAOS PRIMITIVES. ONE O(N^2) HVG PASS + ONE O(N^2) RQA PASS
        // PER WINDOW; BP IS O(N). RQA-DET READS THE SAME IDLE-HIT SHARE
        // AS HVG ON ITS OWN RQA_WIN WINDOW, AND rqa IS None UNTIL
        // RQA_MIN_SAMPLES BUCKETS HAVE FILLED IT.
        let (idle_lambda, _idle_hvg_s) = chaos::hvg_stats(&idle_win);
        let wake_bp_h = chaos::bandt_pompe_d3(&wake_win);
        let rqa = chaos::rqa_det(&rqa_win);

        // QUIESCENCE GATE. No queued work in any depth sample this tick, and
        // the pattern lenses that have a reading in band -> latch `frozen` and
        // skip the retune + knob write. The loop still ticks at 1 Hz; any
        // queued work or a lambda leaving the steady band thaws it on the
        // same tick, so a regime change and the gate compose without conflict.
        // Decided ahead of the graph, which it does not read, so a frozen tick
        // does not pay for a graph it will not use.
        let frozen = quiesce.update(idle_lambda, rqa, depth_occupied);
        if depth_occupied {
            occupied_ticks += 1;
        }
        if frozen {
            frozen_ticks += 1;
        }

        // BUILD THE LIVE LOAD GRAPH. Measured and reported before anything
        // prices against it: if the coupling spread is ~0 the graph is
        // complete-and-uniform and carries no structure the static topology
        // does not already have. The knob derivation reads its domain series;
        // the coupling it measures stays telemetry. Built on a tick that uses
        // it: an unfrozen one, or a regime change below.
        let mut graph: Option<LoadGraph> = (!frozen).then(|| {
            LoadGraph::build(
                &wait_win,
                &cnt_win,
                &dom_win,
                &dom_wait_win,
                &dom_cnt_win,
                &cpu_dom,
                &mut edge_cache,
                &mut edge_cursor,
            )
        });
        if let Some(g) = graph.as_mut() {
            if prev_dom_lag1.len() < g.dom_lag1.len() {
                prev_dom_lag1.resize(g.dom_lag1.len(), f64::NAN);
            }
            g.dom_rise = g
                .dom_lag1
                .iter()
                .zip(&prev_dom_lag1)
                .map(|(a, b)| a - b)
                .collect();
            prev_dom_lag1 = g.dom_lag1.clone();
            for (rise, &w) in g.dom_rise.iter().zip(&g.dom_lag1_n) {
                if rise.is_finite() && w >= 64 {
                    g_slowing_dom_ticks += 1;
                    g_slowing_fired += (rise / (2.0 / w as f64).sqrt() > 1.645) as u64;
                }
            }
            // EACH DOMAIN'S LAST SECOND OF QUEUE CLOCK, IN BUCKETS AT THE MEASURED
            // RATE, AND ITS LARGEST WAIT.
            let last_s = (bucket_rate.ceil() as usize).max(1);
            g.dom_tail = dom_wait_win
                .iter()
                .map(|w| {
                    let n = w.iter().count();
                    if n == 0 {
                        f64::NAN
                    } else {
                        w.iter().skip(n.saturating_sub(last_s)).fold(0.0, f64::max)
                    }
                })
                .collect();
            g.dom_qwait = dom_qwait_win
                .iter()
                .map(|w| {
                    if w.is_empty() {
                        f64::NAN
                    } else {
                        chaos::mean(w)
                    }
                })
                .collect();
            g.eq_us = eq_us_now;
            g.dom_starve = dom_starve_win
                .iter()
                .map(|w| {
                    let n = w.iter().count();
                    let k = n.min(last_s);
                    if k == 0 {
                        f64::NAN
                    } else {
                        w.iter().skip(n - k).sum::<f64>() / k as f64
                    }
                })
                .collect();
            for &s in g.dom_starve.iter().filter(|s| s.is_finite()) {
                g_starve_sum += s;
                g_starve_n += 1;
            }
            let base_us =
                scaled_regime_knobs(regime, nr_cpus, tau_ns).codel_thresh_ns as f64 / 1000.0;
            for &t in g.dom_tail.iter().filter(|t| t.is_finite()) {
                g_tail_dom_ticks += 1;
                g_tail_fired += (t > base_us) as u64;
            }
        }
        let (g_edges, g_mean, g_min, g_max) = graph
            .as_ref()
            .map_or((0, 0.0, 0.0, 0.0), |g| g.edge_summary());
        // OSCILLATOR POSITION, READ NOT RE-DERIVED. The BPF damped oscillator owns
        // codel_target_ns; this reads where it currently sits (0.0 floor/tightened,
        // 1.0 max/relaxed) so the layer can SEE the target it must not fight. The
        // reader existed with no consumer, which meant the one piece of state that
        // says whether the BPF has already responded was unobservable from up here.
        // The retune below defers to it (OscillatorState::responding).
        let osc = sched.read_oscillator_state();
        let osc_pos = osc.position();
        // The Phi release point the warm-stay and STEP-1 steal actually let a task
        // leave home at: codel_target plus the nearest-peer hold. Reported beside
        // the raw position because position() alone cannot say whether the BPF has
        // genuinely responded; responding() compares release points.
        let osc_rel_us = osc.effective_release_ns() / 1000;
        g_tick += 1;
        g_depth_samples += depth_pushed;
        let full = |p: &Option<Priced>| p.is_some_and(|v| v.confidence >= 1.0);
        if let Some(graph) = graph.as_ref() {
            for i in 0..graph.n {
                if !graph.node_wait[i].is_finite() {
                    continue;
                }
                g_node_ticks += 1;
                g_burst_full += full(&graph.node_burst[i]) as u64;
                g_slowing_full += full(&graph.node_slowing[i]) as u64;
                g_persist_full += full(&graph.node_persist[i]) as u64;
            }
            g_pair_ticks += graph.edge.len() as u64;
            g_pair_some += graph.edge.iter().filter(|e| e.is_some()).count() as u64;
            for b in graph.dom_burst.iter().flatten() {
                g_dom_burst_sum += b.value;
                g_dom_burst_n += 1;
            }
            // THE ARRIVALS' HURST, REPORTED BESIDE THE DEPTH's THE KNOB READS.
            for h in dom_cnt_win
                .iter()
                .filter_map(chaos::veitch_abry_hurst_priced)
            {
                g_dom_persist_sum += h.value;
                g_dom_persist_n += 1;
            }
            for w in &graph.dom_wait {
                if w.is_finite() {
                    g_dom_wait_sum += w;
                    g_dom_wait_n += 1;
                }
            }
        }
        for sd in depth_win.iter().filter_map(chaos::stdev) {
            g_own_sd_sum += sd;
            g_own_sd_n += 1;
        }
        for w in dom_win.iter().filter(|w| !w.is_empty()) {
            g_dom_mean_sum += chaos::mean(w);
            g_dom_mean_n += 1;
            if let Some(sd) = chaos::stdev(w) {
                g_dom_sd_sum += sd;
                g_dom_sd_n += 1;
            }
            if let Some(b) = chaos::kim_jo_burstiness_priced(w) {
                g_depth_burst_sum += b.value;
                g_depth_burst_n += 1;
            }
            if let Some(h) = chaos::veitch_abry_hurst_priced(w) {
                g_depth_persist_sum += h.value;
                g_depth_persist_n += 1;
            }
        }
        if g_edges > 0 {
            g_edge_ticks += 1;
            g_edges_total += g_edges as u64;
            g_mean_sum += g_mean;
            let spread = g_max - g_min;
            g_spread_sum += spread;
            if spread > g_spread_max {
                g_spread_max = spread;
            }
        }
        // BANDT-POMPE'S RISE THIS TICK, ONE HALF OF THE CHAOS CROSSING BELOW.
        let bp_delta = wake_bp_h - prev_bp_h;
        let mean_idle = chaos::mean(&idle_win);

        // CHAOS CROSSING DIAGNOSTIC: BUMP COUNTER ON EITHER GATE FIRING.
        // chaos_crossing IS ALSO REUSED BELOW AS THE ADAPTIVE-RARITY
        // "disturbed" SIGNAL -- CAPTURE IT BEFORE prev_lambda_above IS
        // OVERWRITTEN.
        let lambda_above = idle_lambda >= chaos::HVG_LAMBDA_CHAOTIC_MIN;
        let chaos_crossing = (lambda_above && !prev_lambda_above) || bp_delta > 0.10;
        if chaos_crossing {
            chaos_count.bump();
        }
        prev_lambda_above = lambda_above;

        // DETECT REGIME (CHAOS-DRIVEN + 2-TICK HOLD)
        let detected = detect_regime(mean_idle, idle_lambda, wake_bp_h);

        let mut regime_changed_this_tick = false;
        if detected != regime {
            if detected == pending_regime {
                regime_hold += 1;
            } else {
                pending_regime = detected;
                regime_hold = 1;
            }
            if regime_hold >= 2 {
                regime = detected;
                // REFRESH tau IN CASE HOTPLUG/TOPOLOGY CHANGED.
                // scaled_regime_knobs RETURNS topology_tau_ns/codel_eq_ns=0;
                // OVERLAY THE LIVE BPF VALUES (BOTH OWNED BY TOPOLOGY LAYER).
                let live = sched.read_tuning_knobs();
                tau_ns = live.topology_tau_ns;
                let mut rk = scaled_regime_knobs(regime, nr_cpus, tau_ns);
                rk.topology_tau_ns = tau_ns;
                rk.codel_eq_ns = live.codel_eq_ns;
                // Regime baseline, spread per CPU by the graph on the same
                // terms as the retune path below.
                let mut set = graph
                    .get_or_insert_with(|| {
                        LoadGraph::build(
                            &wait_win,
                            &cnt_win,
                            &dom_win,
                            &dom_wait_win,
                            &dom_cnt_win,
                            &cpu_dom,
                            &mut edge_cache,
                            &mut edge_cursor,
                        )
                    })
                    .derive_percpu_knobs(&rk);
                // THE MEASURED BASE COST IS NOT THE REGIME'S; IT CARRIES OVER.
                let phi = last_written.first().map_or(0, |k| k.phi_base_ns);
                set.iter_mut().for_each(|k| k.phi_base_ns = phi);
                sched.write_tuning_knobs_percpu(&set)?;
                last_written = set;
                regime_changed_this_tick = true;
                // SNAP THE ADAPTIVE-RARITY INTERVAL BACK TO BASE.
                retune_interval = tuning::RETUNE_INTERVAL_BASE;
                ticks_since_retune = 0;
            }
        } else {
            pending_regime = regime;
            regime_hold = 0;
        }

        // KNOB RETUNE: UNIFIED KNOB CONTROL
        // GATED BY !regime_changed_this_tick (a fresh regime already
        // wrote its baseline) AND !frozen (steady state -- stop the
        // machinery). When neither gate is set, the adaptive-rarity
        // counter throttles how often the retune actually fires.
        if !regime_changed_this_tick && !frozen {
            ticks_since_retune += 1;
            if ticks_since_retune >= retune_interval {
                ticks_since_retune = 0;
                // KNOBS COME FROM THE REGIME BASELINE, SPREAD BY THE GRAPH.
                // No expert weights, no loss pathways, no convergence window:
                // the baseline is a function of regime and tau, and per-CPU
                // slice pressure is a function of measured queue depth. Both
                // are computed this tick from this tick's data.
                let live = sched.read_tuning_knobs();
                let mut knobs = scaled_regime_knobs(regime, nr_cpus, tau_ns);
                knobs.topology_tau_ns = live.topology_tau_ns;
                knobs.codel_eq_ns = live.codel_eq_ns;
                // COMMIT-ON-CHANGE: only push when a field actually moved. The
                // BPF side reads the map unsynchronized, so skipping redundant
                // writes strictly reduces torn-read exposure. The diff runs on
                // the per-CPU set derived this tick against the per-CPU set last
                // written: compared on the base set, a function of regime and
                // tau alone, nothing moved inside a regime and the derivation
                // reached BPF only when the regime changed.
                //
                // EVIDENCE. Each derived field writes only when it moved from
                // what was last written by more than EVIDENCE_K times its own
                // spread over its recent derivations; a field inside its band
                // keeps the written value.
                //
                // DEFER THE RESCUE TO THE OSCILLATOR. While the BPF oscillator
                // is pulled below rest by rescues it is already correcting this
                // pressure on the rescue path; a rescue-threshold write now
                // would be a second controller on the same error, so that one
                // field holds its written value. Slice and batch are not the
                // oscillator's and write through.
                // An unfrozen tick built the graph; without one nothing moves.
                let set = match graph.as_ref() {
                    Some(g) => g.derive_percpu_knobs(&knobs),
                    None => last_written.clone(),
                };
                let deferring = osc.responding(live.codel_eq_ns);
                let mut rescue_held = false;
                let mut cand: Vec<tuning::TuningKnobs> = if set.len() != last_written.len() {
                    evidence.clear();
                    set
                } else {
                    evidence.resize_with(set.len(), || std::array::from_fn(|_| RawWindow::new()));
                    set.iter()
                        .zip(&last_written)
                        .zip(evidence.iter_mut())
                        .map(|((d, lw), ev)| {
                            ev[0].push(d.slice_ns as f64);
                            ev[1].push(d.batch_slice_ns as f64);
                            ev[2].push(d.codel_thresh_ns as f64);
                            ev[3].push(d.standing_targets as f64);
                            let moved = |w: &RawWindow<EVIDENCE_TICKS>, dv: u64, lv: u64| {
                                let band = chaos::stdev(w).map_or(0.0, |s| EVIDENCE_K * s);
                                (dv as f64 - lv as f64).abs() > band
                            };
                            let mut c = *d;
                            if !moved(&ev[0], d.slice_ns, lw.slice_ns) {
                                c.slice_ns = lw.slice_ns;
                            }
                            if !moved(&ev[1], d.batch_slice_ns, lw.batch_slice_ns) {
                                c.batch_slice_ns = lw.batch_slice_ns;
                            }
                            if !moved(&ev[2], d.codel_thresh_ns, lw.codel_thresh_ns) {
                                c.codel_thresh_ns = lw.codel_thresh_ns;
                            }
                            if !moved(&ev[3], d.standing_targets, lw.standing_targets) {
                                c.standing_targets = lw.standing_targets;
                            }
                            if deferring && c.codel_thresh_ns != lw.codel_thresh_ns {
                                c.codel_thresh_ns = lw.codel_thresh_ns;
                                rescue_held = true;
                            }
                            c
                        })
                        .collect()
                };
                // THE BASE COST, ONE VALUE FOR EVERY CPU, ON BPF's RAIL AND THE
                // SAME EVIDENCE; WRITTEN ONLY WHILE LIVE_BASE_COST.
                phi_candidate = phi_base_candidate(&refill_win, phi_candidate);
                let phi = if LIVE_BASE_COST { phi_candidate } else { 0 };
                cand.iter_mut().for_each(|k| k.phi_base_ns = phi);
                let changed = cand.len() != last_written.len()
                    || cand
                        .iter()
                        .zip(&last_written)
                        .any(|(a, b)| tuning::knobs_differ(a, b));
                if rescue_held {
                    knob_writes_deferred += 1;
                }
                if changed {
                    sched.write_tuning_knobs_percpu(&cand)?;
                    knob_writes += 1;
                    let lo = cand.iter().map(|k| k.slice_ns).min().unwrap_or(0);
                    let hi = cand.iter().map(|k| k.slice_ns).max().unwrap_or(0);
                    slice_spread_sum_us += (hi - lo) as f64 / 1000.0;
                    last_written = cand;
                }
                let disturbed = chaos_crossing;
                retune_interval =
                    tuning::next_retune_interval(retune_interval, !changed, disturbed);
            }
        }

        for k in &last_written {
            let (w, a) = (knob_fields(k), knob_fields(&k.applied()));
            for i in 0..KNOB_NAMES.len() {
                g_knob_written[i] += w[i] as f64;
                g_knob_applied[i] += a[i] as f64;
            }
            g_knob_n += 1;
        }

        // STABILITY TRACKING
        let tighten_delta = if chaos_crossing { 1u64 } else { 0u64 };
        stability_score = tuning::compute_stability_score(
            stability_score,
            regime_changed_this_tick,
            tighten_delta,
            p99_ns,
            regime.p99_ceiling(),
        );

        let p99_us = p99_ns / 1000;
        let tp99_b = tp99_b_ns / 1000;
        let tp99_i = tp99_i_ns / 1000;
        let tp99_l = tp99_l_ns / 1000;
        let knobs = sched.read_tuning_knobs();

        let sojourn_thresh_ms = knobs.codel_thresh_ns / 1_000_000;

        if verbose && tuning::should_print_telemetry(tick_counter, stability_score) {
            let rqa_disp = rqa.unwrap_or(-1.0);
            let frozen_disp = if frozen { 1 } else { 0 };
            println!(
                "d/s: {:<8} idle: {}% shared: {:<6} preempt: {:<4} keep: {:<4} kick: H={:<4} S={:<4} enq: W={:<4} R={:<4} wake: {}us p99: {}us [B:{} I:{} L:{}] lat_idle: {}us lat_kick: {}us sleep: io={}% slice: {}us batch: {}us reenq: {} sjrn: {}ms rescue: {} l2: B={}% I={}% chaos: lam={:.2} H={:.2} det={:.2} x={} frozen: {} (n={}) retune_iv: {} [{}] graph: n={} e={} cpl={:.2}/{:.2}/{:.2} osc: {:.2}/{}us",
                delta_d,
                idle_pct,
                delta_shared,
                delta_preempt,
                delta_keep,
                delta_hard,
                delta_soft,
                delta_enq_wake,
                delta_enq_requeue,
                wake_avg_us,
                p99_us,
                tp99_b,
                tp99_i,
                tp99_l,
                lat_idle_us,
                lat_kick_us,
                io_pct,
                knobs.slice_ns / 1000,
                knobs.batch_slice_ns / 1000,
                delta_reenq,
                sojourn_thresh_ms,
                delta_rescue,
                l2_pct_b,
                l2_pct_i,
                idle_lambda,
                wake_bp_h,
                rqa_disp,
                chaos_count.load(),
                frozen_disp,
                frozen_ticks,
                retune_interval,
                regime.label(),
                graph.as_ref().map_or(depth_win.len(), |g| g.n),
                g_edges,
                g_mean,
                g_min,
                g_max,
                osc_pos,
                osc_rel_us,
            );
        }

        sched.log.snapshot(
            delta_d,
            delta_idle,
            delta_shared,
            delta_preempt,
            delta_keep,
            delta_parks,
            wake_avg_us,
            delta_hard,
            delta_soft,
            lat_idle_us,
            lat_kick_us,
            delta_steal,
        );

        match regime {
            Regime::Light => light_ticks += 1,
            Regime::Mixed => mixed_ticks += 1,
            Regime::Heavy => heavy_ticks += 1,
        }
        phase_ticks[regime as usize] += 1;
        if PHASE_CUT.swap(false, Ordering::Relaxed) {
            print_phase(&mut phase_n, &mut phase_ticks);
        }

        tick_counter += 1;
        prev_hist = cur_hist;
        prev_sleep = cur_sleep;
        prev = stats;
        prev_bp_h = wake_bp_h;
    }
    // A CUT ASKED FOR JUST BEFORE THE STOP CLOSES THE LAST PHASE.
    if PHASE_CUT.swap(false, Ordering::Relaxed) {
        print_phase(&mut phase_n, &mut phase_ticks);
    }

    // KNOBS SUMMARY: CAPTURED BY TEST HARNESS FOR ARCHIVE
    let final_knobs = sched.read_tuning_knobs();
    let final_stats = sched.read_stats();
    let l2_total_b = final_stats.nr_l2_hit_batch + final_stats.nr_l2_miss_batch;
    let l2_total_i = final_stats.nr_l2_hit_interactive + final_stats.nr_l2_miss_interactive;
    let l2_cum_b = if l2_total_b > 0 {
        final_stats.nr_l2_hit_batch * 100 / l2_total_b
    } else {
        0
    };
    let l2_cum_i = if l2_total_i > 0 {
        final_stats.nr_l2_hit_interactive * 100 / l2_total_i
    } else {
        0
    };
    // CROSS-DOMAIN SCATTER ATTRIBUTION (PER XDOM_* PATH). scatter_pct IS THE
    // PLACEMENT-SIDE FRACTION (idx 0..6); THE PER-PATH COUNTS
    // ARE THE PERMANENT ATTRIBUTION SURFACED TO THE BENCH SUITE EVERY RUN.
    let x = &final_stats.nr_cross_domain;
    let x_scatter: u64 = x[0..6].iter().sum();
    let x_scatter_pct = if final_stats.nr_dispatches > 0 {
        x_scatter * 100 / final_stats.nr_dispatches
    } else {
        0
    };
    // osc_park IS THE OSCILLATOR ENVELOPE'S OWN COLLAPSE DETECTOR: ZERO PARKS
    // AFTER AN IDLE-HEAVY RUN MEANS THE ENVELOPE NEVER WENT QUIET, WHICH IS THE
    // MINIMUM-ATTENTION-COLLAPSE FAILURE MODE. IT WAS IN THE STATS STRUCT AND ON
    // THE TERMINAL, BUT NOT ON THIS LINE, SO IT NEVER REACHED THE BENCH ARCHIVE
    // OR THE PRISM .prom -- THE IDLE POWER QUESTION HAD NO COUNTER BEHIND IT.
    // THE COUPLING READING, WRITTEN WHERE A BENCH CANNOT LOSE IT.
    // edge_ticks == 0 is the falsification: no CPU pair ever produced a usable
    // coupling value, so the live graph has nodes and no edges and there is
    // nothing for a spectral price to solve over. That is a real answer and it
    // must survive to disk to count as one.
    {
        let dir = std::path::Path::new("/tmp/pandemonium");
        let _ = std::fs::create_dir_all(dir);
        let denom = g_edge_ticks.max(1) as f64;
        let body = format!(
            "pandemonium_graph_ticks {}\n\
             pandemonium_graph_edge_ticks {}\n\
             pandemonium_graph_edges_mean {:.2}\n\
             pandemonium_graph_coupling_mean {:.4}\n\
             pandemonium_graph_coupling_spread_mean {:.4}\n\
             pandemonium_graph_coupling_spread_max {:.4}\n\
             pandemonium_chaos_frozen_ticks {}\n\
             pandemonium_chaos_frozen_fraction {:.4}\n\
             pandemonium_chaos_occupied_fraction {:.4}\n\
             pandemonium_chaos_knob_writes_in_regime {}\n\
             pandemonium_chaos_knob_writes_deferred {}\n\
             pandemonium_chaos_slice_spread_mean_us {:.2}\n\
             pandemonium_graph_depth_samples_per_cpu_s {:.2}\n\
             pandemonium_graph_lens_burst_full {:.4}\n\
             pandemonium_graph_lens_slowing_full {:.4}\n\
             pandemonium_graph_lens_persist_full {:.4}\n\
             pandemonium_graph_lens_edge_available {:.4}\n\
             pandemonium_graph_own_depth_sd_mean {:.4}\n\
             pandemonium_graph_dom_depth_mean {:.4}\n\
             pandemonium_graph_dom_depth_sd_mean {:.4}\n\
             pandemonium_graph_dom_wait_mean_us {:.2}\n\
             pandemonium_graph_dom_burst_mean {:.4}\n\
             pandemonium_graph_dom_persist_mean {:.4}\n\
             pandemonium_graph_dom_depth_burst_mean {:.4}\n\
             pandemonium_graph_dom_depth_persist_mean {:.4}\n\
             pandemonium_graph_dom_slowing_fired_fraction {:.4}\n",
            g_tick,
            g_edge_ticks,
            g_edges_total as f64 / denom,
            g_mean_sum / denom,
            g_spread_sum / denom,
            g_spread_max,
            frozen_ticks,
            frozen_ticks as f64 / g_tick.max(1) as f64,
            occupied_ticks as f64 / g_tick.max(1) as f64,
            knob_writes,
            knob_writes_deferred,
            slice_spread_sum_us / knob_writes.max(1) as f64,
            g_depth_samples as f64 / (g_tick.max(1) * depth_win.len().max(1) as u64) as f64,
            g_burst_full as f64 / g_node_ticks.max(1) as f64,
            g_slowing_full as f64 / g_node_ticks.max(1) as f64,
            g_persist_full as f64 / g_node_ticks.max(1) as f64,
            g_pair_some as f64 / g_pair_ticks.max(1) as f64,
            g_own_sd_sum / g_own_sd_n.max(1) as f64,
            g_dom_mean_sum / g_dom_mean_n.max(1) as f64,
            g_dom_sd_sum / g_dom_sd_n.max(1) as f64,
            g_dom_wait_sum / g_dom_wait_n.max(1) as f64,
            g_dom_burst_sum / g_dom_burst_n.max(1) as f64,
            g_dom_persist_sum / g_dom_persist_n.max(1) as f64,
            g_depth_burst_sum / g_depth_burst_n.max(1) as f64,
            g_depth_persist_sum / g_depth_persist_n.max(1) as f64,
            g_slowing_fired as f64 / g_slowing_dom_ticks.max(1) as f64
        );
        let body = body
            + &flow_acc[0].prom("wake")
            + &flow_acc[1].prom("mig")
            + &format!(
                "pandemonium_refill_paired_ns_mean {:.1}\n\
                 pandemonium_refill_medmed_ns_mean {:.1}\n\
                 pandemonium_refill_tasks_mean {:.2}\n\
                 pandemonium_refill_ticks {}\n\
                 pandemonium_refill_records {}\n\
                 pandemonium_refill_lost {}\n\
                 pandemonium_refill_dropped {}\n\
                 pandemonium_phi_base_written_ns {}\n\
                 pandemonium_phi_base_applied_ns {}\n\
                 pandemonium_phi_base_candidate_ns {}\n\
                 pandemonium_graph_dom_tail_fired_fraction {:.4}\n\
                 pandemonium_graph_dom_starve_mean {:.4}\n",
                g_refill_sum / g_refill_ticks.max(1) as f64,
                g_refill_medmed_sum / g_refill_ticks.max(1) as f64,
                g_refill_tasks as f64 / g_refill_ticks.max(1) as f64,
                g_refill_ticks,
                refill.records,
                refill.lost,
                refill.dropped,
                last_written.first().map_or(0, |k| k.phi_base_ns),
                sched.read_phi_base_applied(),
                phi_candidate,
                g_tail_fired as f64 / g_tail_dom_ticks.max(1) as f64,
                g_starve_sum / g_starve_n.max(1) as f64
            );
        let body = KNOB_NAMES.iter().enumerate().fold(body, |b, (i, name)| {
            let n = g_knob_n.max(1) as f64;
            b + &format!(
                "pandemonium_knob_{name}_written_mean {:.1}\n\
                 pandemonium_knob_{name}_applied_mean {:.1}\n",
                g_knob_written[i] / n,
                g_knob_applied[i] / n
            )
        }) + &format!(
            "pandemonium_knob_codel_eq_ns_written_mean {:.1}\n\
             pandemonium_knob_codel_eq_ns_applied_mean {:.1}\n",
            g_eq_written / g_eq_n.max(1) as f64,
            g_eq_applied / g_eq_n.max(1) as f64
        );
        let path = dir.join(format!("graph-{}.prom", std::process::id()));
        let _ = std::fs::write(&path, body);
        println!("[GRAPH] {}", path.display());
    }

    println!(
        "[KNOBS] regime={} slice_ns={} batch_ns={} ticks=L:{}/M:{}/H:{} frozen={} l2_hit=B:{}%/I:{}% cross_domain_scatter_pct={} cross_domain_sel_tight={} cross_domain_sel_sync={} cross_domain_sel_normal={} cross_domain_sel_dfl={} cross_domain_enq_t1={} cross_domain_enq_t2={} cross_domain_steal={} cross_domain_step5={} osc_park={} steal={} steal_lost={} steal_base_held={} spill={} kick_declined={} sleepless_cut={} sleepless_miss={} dispatches={}",
        regime.label(),
        final_knobs.slice_ns,
        final_knobs.batch_slice_ns,
        light_ticks,
        mixed_ticks,
        heavy_ticks,
        frozen_ticks,
        l2_cum_b,
        l2_cum_i,
        x_scatter_pct,
        x[0],
        x[1],
        x[2],
        x[3],
        x[4],
        x[5],
        x[6],
        x[7],
        final_stats.nr_osc_park,
        final_stats.nr_steal,
        final_stats.nr_steal_lost,
        final_stats.nr_steal_base_held,
        final_stats.nr_spill_kick_preempt,
        final_stats.nr_kick_declined,
        final_stats.nr_sleepless_cut,
        final_stats.nr_sleepless_miss,
        final_stats.nr_dispatches,
    );

    // READ UEI EXIT REASON
    let should_restart = sched.read_exit_info();
    Ok(should_restart)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn zero_row() -> FlowRow {
        FlowRow {
            wake: [0; crate::scheduler::FLOW_ROW_CPUS],
            mig: [0; crate::scheduler::FLOW_ROW_CPUS],
        }
    }

    fn refill_append(r: &mut RefillRing, pid: u32, cross: bool, ns: u32, n: usize) {
        for _ in 0..n {
            let key = ((pid << 1) | cross as u32) as u64;
            r.rec[r.head as usize % REFILL_RING_SLOTS] = key << 32 | ns as u64;
            r.head = r.head.wrapping_add(1);
        }
    }

    // THREE TASKS, EACH ITS OWN CONTROL: THE READING IS THE MEDIAN OF THEIR OWN
    // DIFFERENCES, 6us, WHERE THE CLASS MEDIANS' DIFFERENCE READS 10us; A TASK
    // SHORT OF REFILL_MIN_STINTS IN A CLASS IS NOT PAIRED.
    #[test]
    fn refill_reads_the_paired_median_over_tasks() {
        let mut r = RefillRing {
            head: 0,
            _pad: 0,
            rec: [0; REFILL_RING_SLOTS],
        };
        let mut p = RefillPairs::new();
        p.ingest(std::slice::from_ref(&r), 0);
        for tick in 1..=2 {
            for (pid, same, cross) in [
                (10, 10_000, 30_000),
                (11, 100_000, 104_000),
                (12, 20_000, 26_000),
            ] {
                refill_append(&mut r, pid, false, same, REFILL_TICK_STINTS);
                refill_append(&mut r, pid, true, cross, REFILL_TICK_STINTS);
            }
            refill_append(&mut r, 13, false, 1_000, REFILL_TICK_STINTS);
            refill_append(&mut r, 13, true, 900_000, REFILL_MIN_STINTS / 2 - 1);
            p.ingest(std::slice::from_ref(&r), tick);
        }
        let x = p.reading(2).unwrap();
        assert_eq!((x.tasks, x.paired_ns, x.medmed_ns), (3, 6_000.0, 10_000.0));
    }

    // THE EQUILIBRIUM BPF APPLIES: THE WRITTEN ONE INSIDE THE OSCILLATOR's
    // WINDOW, THE WINDOW's EDGE OUTSIDE IT, AND THE WRITTEN ONE WHEN NOTHING IS
    // WRITTEN OR NO WINDOW WAS READ BACK.
    #[test]
    fn applied_eq_is_apply_tau_scaling_clamp() {
        let osc = tuning::OscillatorState {
            codel_target_floor_ns: 200_000,
            codel_target_max_ns: 665_000,
            ..Default::default()
        };
        assert_eq!(osc.applied_eq(547_000), 547_000);
        assert_eq!(osc.applied_eq(17_500), 200_000);
        assert_eq!(osc.applied_eq(2_000_000), 665_000);
        assert_eq!(osc.applied_eq(0), 0);
        assert_eq!(
            tuning::OscillatorState::default().applied_eq(17_500),
            17_500
        );
    }

    // A DRAIN READS THE NEWEST RING-LESS-MARGIN AND COUNTS THE REST LOST, ACROSS
    // THE HEAD's WRAP; A CLASS KEEPS AT MOST REFILL_TICK_STINTS OF A TICK's.
    #[test]
    fn refill_drain_thins_wraps_and_counts_what_it_lost() {
        let mut r = RefillRing {
            head: u32::MAX - 10,
            _pad: 0,
            rec: [0; REFILL_RING_SLOTS],
        };
        let mut p = RefillPairs::new();
        p.ingest(std::slice::from_ref(&r), 0);
        refill_append(&mut r, 7, false, 5_000, REFILL_RING_SLOTS);
        p.ingest(std::slice::from_ref(&r), 1);
        assert_eq!(
            (p.records, p.lost),
            (
                (REFILL_RING_SLOTS - REFILL_RING_MARGIN) as u64,
                REFILL_RING_MARGIN as u64
            )
        );
        assert_eq!(
            p.task.iter().find(|t| t.pid == 7).unwrap().n,
            [REFILL_TICK_STINTS as u32, 0]
        );
    }

    // A TASK QUIET FOR A SPAN LEAVES THE READING.
    #[test]
    fn refill_task_lapses_after_a_span() {
        let mut r = RefillRing {
            head: 0,
            _pad: 0,
            rec: [0; REFILL_RING_SLOTS],
        };
        let mut p = RefillPairs::new();
        p.ingest(std::slice::from_ref(&r), 0);
        for tick in 1..=2 {
            for pid in 20..23 {
                refill_append(&mut r, pid, false, 10_000, REFILL_TICK_STINTS);
                refill_append(&mut r, pid, true, 12_000, REFILL_TICK_STINTS);
            }
            p.ingest(std::slice::from_ref(&r), tick);
        }
        assert_eq!(p.reading(2).map(|x| x.paired_ns), Some(2_000.0));
        assert!(p.reading(2 + REFILL_SPAN_TICKS + 1).is_none());
    }

    // THE BASE COST WAITS FOR REFILL_MIN_TICKS READINGS, WRITES THE FIRST, HOLDS
    // INSIDE ITS BAND AND CLAMPS AS BPF CLAMPS: ipc's 2.5us AND A NEGATIVE READING
    // WRITE THE FLOOR, NOTHING WRITES PAST THE CEILING.
    #[test]
    fn phi_base_waits_writes_holds_and_clamps() {
        let mut w = RawWindow::<EVIDENCE_TICKS>::new();
        for x in [20_000.0, 21_000.0, 19_000.0] {
            w.push(x);
        }
        assert_eq!(phi_base_candidate(&w, 0), 0);
        w.push(20_000.0);
        assert_eq!(phi_base_candidate(&w, 0), 20_000);
        assert_eq!(phi_base_candidate(&w, 20_400), 20_400);
        assert_eq!(phi_base_candidate(&w, 40_000), 20_000);
        let at = |x: f64| {
            let mut w = RawWindow::<EVIDENCE_TICKS>::new();
            for _ in 0..REFILL_MIN_TICKS {
                w.push(x);
            }
            phi_base_candidate(&w, 0)
        };
        assert_eq!(at(2_500.0), PHI_BASE_MIN_NS);
        assert_eq!(at(-3_000.0), PHI_BASE_MIN_NS);
        assert_eq!(at(250_000.0), PHI_BASE_MAX_NS);
    }

    // DELTAS WRAP WITH THE u32 COUNTERS, AND A CPU'S FLOW TO ITSELF IS NO EDGE.
    #[test]
    fn flow_rows_take_wrapping_deltas_and_drop_self() {
        let (mut p, mut c) = (vec![zero_row(); 2], vec![zero_row(); 2]);
        p[1].wake[0] = u32::MAX - 1;
        c[1].wake[0] = 2;
        p[0].mig[1] = 5;
        c[0].mig[1] = 9;
        c[0].wake[0] = 7;
        let fg = FlowGraph::from_rows(&c, &p, 2);
        assert_eq!(fg.wake[0 * 2 + 1], 4.0);
        assert_eq!(fg.mig[1 * 2 + 0], 4.0);
        assert_eq!(fg.wake[0], 0.0);
    }

    // TWO DOMAINS OF THREE, HEAVY FLOW INSIDE EACH AND A TRICKLE ACROSS: THE CUT
    // IS THE DOMAIN BOUNDARY, AND THE CROSS SHARE IS THE TRICKLE'S.
    #[test]
    fn flow_cut_follows_the_domains_its_traffic_draws() {
        let n = 6;
        let dom: Vec<Option<usize>> = (0..n).map(|c| Some(c / 3)).collect();
        let mut f = vec![0.0; n * n];
        for s in 0..n {
            for d in 0..n {
                if s != d {
                    f[s * n + d] = if s / 3 == d / 3 { 100.0 } else { 1.0 };
                }
            }
        }
        let mut warm = Vec::new();
        let r = FlowGraph::reading(&f, n, &dom, &mut warm).unwrap();
        assert_eq!(r.cut_purity, Some(1.0));
        assert!((r.cross_dom - 18.0 / 1218.0).abs() < 1e-12);
        let again = FlowGraph::reading(&f, n, &dom, &mut warm).unwrap();
        assert_eq!(again.cut_purity, Some(1.0));
        assert_eq!(flow_churn(&f, &f), Some(0.0));
    }

    // ORDER, NOT SCALE: A RAMP AND ITS SQUARE SHARE RANKS AND SO A READING; A
    // FLAT SERIES TAKES ITS RANKS FROM THE TIE HASH AND READS NO ORDER; UNDER 64
    // SAMPLES THERE IS NO READING.
    #[test]
    fn ranked_lag1_reads_order_not_scale() {
        let mut short = RawWindow::<256>::new();
        for k in 0..63 {
            short.push(k as f64);
        }
        assert!(ranked_lag1(&short).is_nan());
        let (mut a, mut b, mut c) = (
            RawWindow::<256>::new(),
            RawWindow::<256>::new(),
            RawWindow::<256>::new(),
        );
        for k in 0..128 {
            a.push(k as f64);
            b.push((k * k) as f64);
            c.push(5.0);
        }
        let (ra, rb) = (ranked_lag1(&a), ranked_lag1(&b));
        assert!(ra > 0.9 && (ra - rb).abs() < 1e-12);
        assert!(ranked_lag1(&c).abs() < 0.3);
    }

    // n PAIRS A TICK, IN ROW-MAJOR ORDER, BACK TO (0, 1) ONCE EVERY PAIR HAS
    // BEEN RECOMPUTED.
    #[test]
    fn coupling_rotation_walks_every_pair_once_a_cycle() {
        const W: usize = 64;
        let n = 5;
        let mut wait: Vec<RawWindow<W>> = (0..n).map(|_| RawWindow::new()).collect();
        for (c, w) in wait.iter_mut().enumerate() {
            for k in 0..W {
                w.push(((k * (c + 2)) % 17) as f64 + c as f64);
            }
        }
        let none: Vec<RawWindow<W>> = Vec::new();
        let cpu_dom = vec![None; n];
        let mut cache = Vec::new();
        let mut cursor = (0, 1);
        let build = |cache: &mut Vec<Option<Priced>>, cursor: &mut (usize, usize)| {
            LoadGraph::build(&wait, &wait, &none, &none, &none, &cpu_dom, cache, cursor)
        };
        let g = build(&mut cache, &mut cursor);
        assert_eq!(g.edge.len(), n * (n - 1) / 2);
        assert_eq!(cursor, (1, 3));
        build(&mut cache, &mut cursor);
        assert_eq!(cursor, (0, 1));
    }
}
