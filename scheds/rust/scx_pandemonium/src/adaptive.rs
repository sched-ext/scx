// PANDEMONIUM ADAPTIVE CONTROL LOOP
// SINGLE-THREAD CLOSED-LOOP TUNING SYSTEM
//
// ONE THREAD: MONITOR LOOP (1-SECOND CONTROL LOOP)
//   READS THE PER-CPU STATS ARRAY, UNCOLLAPSED, AND BUILDS THE LIVE LOAD
//   GRAPH: NODES ARE CPUs WEIGHTED BY RUNQUEUE DEPTH, TRAFFIC SHAPE,
//   CRITICAL SLOWING AND PERSISTENCE; EDGES ARE CPU PAIRS WEIGHTED BY
//   COUPLING. EVERY MEASURE IS RECOMPUTED FROM THE RAW WINDOW EACH TICK.
//
//   EVERY KNOB IS DERIVED, NONE ARE LEARNED. depth -> slice, depth+lag-1 ->
//   preempt, burstiness -> batch/burst ceilings, Hurst -> rescue threshold,
//   Bandt-Pompe H -> spill temperature, R_eff -> CoDel equilibrium. Coupling is
//   MEASURED and not actuated: deriving affinity from it cost 16x on IPC pipe
//   p50 in the first PRISM pass and was withdrawn. There is no expert set, no loss pathway and no convergence
//   window: a derived knob is correct this tick, where a learned one was
//   correct several convergence windows later if the regime held still.
//
// BPF PRODUCES HISTOGRAMS, RUST READS AND REACTS. RUST WRITES KNOBS,
// BPF READS THEM ON THE VERY NEXT SCHEDULING DECISION.

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::Result;

use crate::chaos::{self, Priced, RawWindow};
use crate::scheduler::{DEPTH_RING_SLOTS, PandemoniumStats, Scheduler};
use crate::topology::CpuTopology;
use crate::tuning::{self, HIST_BUCKETS, Regime, detect_regime, scaled_regime_knobs};

// CHAOS WINDOW SIZE. 16 SAMPLES AT 1HZ = 16-SECOND REGIME MEMORY.
// SIZED FOR BENCH-SCALE RESPONSIVENESS (16-30s iterations) RATHER THAN
// MINUTE-SCALE DESKTOP STEADY STATE. HVG IS O(N^2) = 256 COMPARISONS
// PER TICK; BP D=3 GETS 14 LENGTH-3 PATTERNS OVER 6 BUCKETS -- LIMITED
// RESOLUTION BUT ENOUGH TO DISTINGUISH PERIODIC FROM RANDOM IN ONE
// BENCH ITERATION.
const CHAOS_WIN: usize = 16;

// RQA WINDOW. rqa_det REPORTS FROM RQA_MIN_SAMPLES, SO RQA-DET READS idle_pct
// ON A WINDOW OF ITS OWN AT THAT LENGTH; ON CHAOS_WIN IT WOULD NEVER VOTE.
const RQA_WIN: usize = chaos::RQA_MIN_SAMPLES;

// DEPTH WINDOW SIZE. The depth series are fed from the BPF depth ring, one
// sample per bucket (a quarter of the oscillator's damped period, 6.28ms at the
// 12C reference), not one per second. 256 is where every lens in sublimation's
// battery reports, and it fills in 1.6s at the 12C reference and 26s at 2C.
const DEPTH_WIN: usize = 256;

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
// THE KNOBS READ THE DOMAIN'S OVERFLOW DEPTH; THE QUEUE CLOCK RIDES BESIDE IT.
// Per-CPU depth reads empty under load (the hand-off seats tasks on local DSQs
// the depth sample never saw), so the nodes read the queue clock and the
// arrivals, which are alive whenever the CPU runs anything. The domain
// derivation keeps the overflow-depth lenses it was measured on: fed the
// arrivals' Fano lenses instead it lowered the rescue threshold everywhere and
// lost the 8C deadline win the depth lenses hold (prism-scale-20261103-032430
// against the e93de7d42 archive). The domain queue clock is carried for the
// levers that read a wait.
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
    // DSQs, so the per-CPU queues read near-empty under load while the
    // domain overflow queue holds the waiting population. The knob derivations
    // read these, each CPU its own domain's, indexed by the domain id its ring
    // reports. NaN / None where a domain has no series yet.
    pub dom_depth: Vec<f64>,
    // The domain's queue clock (its CPUs' waits pooled by run), in us.
    pub dom_wait: Vec<f64>,
    pub dom_burst: Vec<Option<chaos::Priced>>,
    pub dom_persist: Vec<Option<chaos::Priced>>,
    pub cpu_dom: Vec<Option<usize>>,
}

fn pair_index(n: usize, i: usize, j: usize) -> usize {
    // i < j; row-major over the strict upper triangle.
    debug_assert!(i < j && j < n);
    i * n - (i * (i + 1)) / 2 + (j - i - 1)
}

impl LoadGraph {
    // wait_win / cnt_win: the queue clock and the arrivals per bucket, per
    // CPU. dom_win: the domain's overflow depth per bucket; dom_wait_win: its
    // queue clock.
    pub fn build<const N: usize>(
        wait_win: &[RawWindow<N>],
        cnt_win: &[RawWindow<N>],
        dom_win: &[RawWindow<N>],
        dom_wait_win: &[RawWindow<N>],
        cpu_dom: &[Option<usize>],
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
        let dom_burst = dom_win
            .iter()
            .map(chaos::kim_jo_burstiness_priced)
            .collect();
        let dom_persist = dom_win
            .iter()
            .map(chaos::veitch_abry_hurst_priced)
            .collect();
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
        let tails: Vec<RawWindow<COUPLING_WIN>> = wait_win.iter().map(|w| w.newest()).collect();
        let mut edge = vec![None; n * (n.saturating_sub(1)) / 2];
        for i in 0..n {
            for j in (i + 1)..n {
                edge[pair_index(n, i, j)] = chaos::pecora_carroll_priced(&tails[i], &tails[j]);
            }
        }
        LoadGraph {
            node_wait,
            node_burst,
            node_slowing,
            node_persist,
            edge,
            n,
            dom_depth,
            dom_wait,
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
                let Some(dom) = self.cpu_dom.get(i).copied().flatten() else {
                    return k;
                };
                let d = self.dom_depth.get(dom).copied().unwrap_or(f64::NAN);
                // Absent series or a flat machine: carry the base through.
                if !d.is_finite() || refd <= f64::EPSILON {
                    return k;
                }
                // Deeper than reference -> shorter slice, down to 1/2. A CPU
                // at or under the reference keeps the base slice, never more.
                let ratio = (refd / (d + refd).max(f64::EPSILON) * 2.0).clamp(0.5, 1.0);
                k.slice_ns = ((base.slice_ns as f64) * ratio) as u64;

                // BURSTINESS -> BATCH AND BURST CEILINGS.
                // Paced traffic (B < 0) means steady arrivals, so a long
                // ceiling holds the CPU against work that is genuinely queued:
                // shortened by up to 50% across [-1, 0]. Bursty traffic
                // (B > 0) keeps the base. The quiet between its clumps is
                // keep-prev's to cover, not a longer ceiling's.
                if let Some(b) = self.dom_burst.get(dom).and_then(|v| *v) {
                    // weighted() collapses toward the neutral factor 1.0 as
                    // confidence falls, so a thin window nudges rather than swings.
                    let f = Priced {
                        value: 1.0 + 0.5 * b.value.clamp(-1.0, 0.0),
                        confidence: b.confidence,
                    }
                    .weighted(1.0);
                    k.batch_slice_ns = ((base.batch_slice_ns as f64) * f) as u64;
                    k.burst_slice_ns = ((base.burst_slice_ns as f64) * f) as u64;
                }

                // PERSISTENCE -> CoDel RESCUE THRESHOLD.
                // H > 0.5 says this domain's load pattern tends to continue, so a
                // queue that is deep now will likely still be deep: rescue
                // sooner. H < 0.5 is mean-reverting, where a deep queue is
                // likely transient and rescuing early only scatters a task that
                // was about to be served anyway. Centered on H = 0.5 so an
                // uncorrelated domain keeps the base exactly.
                if let Some(h) = self.dom_persist.get(dom).and_then(|v| *v) {
                    let f = Priced {
                        value: (1.0f64 - (h.value.clamp(0.0, 1.0) - 0.5)).clamp(0.5, 1.5),
                        confidence: h.confidence,
                    }
                    .weighted(1.0);
                    k.codel_thresh_ns = ((base.codel_thresh_ns as f64) * f) as u64;
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

    // CHAOS RAW WINDOWS. idle_pct DRIVES REGIME DETECTION; wakeup_rate's
    // BANDT-POMPE ENTROPY FEEDS IT TOO AND FLAGS CHAOS CROSSINGS (BANDT-POMPE
    // IS ORDINAL, SO ABSOLUTE RATE SCALE DOES NOT MATTER -- THE PATTERN DOES).
    let mut idle_win: RawWindow<CHAOS_WIN> = RawWindow::new();
    let mut wake_win: RawWindow<CHAOS_WIN> = RawWindow::new();
    let mut rqa_win: RawWindow<RQA_WIN> = RawWindow::new();
    // PER-CPU RUNQUEUE-DEPTH WINDOWS: THE NODES OF THE LIVE LOAD GRAPH.
    // One series per CPU, each sample the mean depth on that CPU over one
    // bucket of the BPF depth ring. Until v5.18.0 there was exactly ONE series
    // in this whole loop -- a system-wide integer percentage -- which is why a
    // coupling measure had nothing to couple.
    let mut depth_win: Vec<RawWindow<DEPTH_WIN>> =
        (0..nr_cpus as usize).map(|_| RawWindow::new()).collect();
    // DOMAIN QUEUE DEPTH WINDOWS, ONE PER OVERFLOW DOMAIN, indexed by the domain
    // id the ring reports. The per-CPU series cannot see the domain queue, where
    // a saturated population sits, so it enters as its own series and is never
    // summed into a CPU's sample.
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
    let mut dom_qacc: Vec<(f64, f64)> = Vec::new();
    // EACH CPU'S DOMAIN, AS ITS OWN RING LAST REPORTED IT. None UNTIL IT TICKS.
    let mut cpu_dom: Vec<Option<usize>> = vec![None; nr_cpus as usize];
    // LAST RING EPOCH DRAINED. 0 BEFORE THE FIRST DRAIN.
    let mut depth_cursor: u64 = 0;
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
        let delta_rescue = stats
            .nr_overflow_rescue
            .wrapping_sub(prev.nr_overflow_rescue);
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

        // CHAOS UPDATE: PUSH RAW SAMPLES INTO WINDOWS BEFORE COMPUTING
        // ANY DERIVED FEATURES. WAKE WINDOW USES THE PER-SECOND DELTA
        // (delta_enq_wake) RATHER THAN AN INSTANTANEOUS RATE.
        idle_win.push(idle_pct as f64);
        rqa_win.push(idle_pct as f64);
        wake_win.push(delta_enq_wake as f64);

        // NODE WEIGHTS: EVERY RING SAMPLE SINCE THE LAST TICK, FROM THE BPF
        // RING, oldest first. The newest epoch any CPU has written is the
        // bucket still filling, so the drain stops short of it. A slot counts
        // for an epoch only when its epoch matches. A CPU that did not tick in a
        // bucket gives no depth sample and one that ran nothing gives no wait
        // sample, rather than a zero, since no samples is not an empty queue;
        // its arrivals are zero, which is exactly what an idle CPU received. A
        // domain's depth sample is the mean over its CPUs that ticked in the
        // bucket: they all read the same queue. A cursor ahead of the ring
        // (first drain, a stalled loop, a hotplug that changed the bucket
        // width) restarts from the oldest slot the ring still holds.
        let rings = sched.read_depth_rings();
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
                for (i, r) in rings.iter().enumerate().take(depth_win.len()) {
                    let s = &r.slot[idx];
                    if s.epoch != e || (s.ticks == 0 && s.runs == 0) {
                        if cpu_dom[i].is_some() {
                            cnt_win[i].push(0.0);
                        }
                        continue;
                    }
                    let d = r.domain as usize;
                    cpu_dom[i] = Some(d);
                    if d >= dom_acc.len() {
                        dom_acc.resize(d + 1, (0.0, 0));
                        dom_qacc.resize(d + 1, (0.0, 0.0));
                    }
                    if s.ticks > 0 {
                        let t = s.ticks as f64;
                        depth_win[i].push(s.own as f64 / t);
                        depth_pushed += 1;
                        dom_acc[d].0 += s.dom as f64 / t;
                        dom_acc[d].1 += 1;
                    }
                    depth_occupied |= s.own > 0 || s.dom > 0;
                    if s.runs > 0 {
                        wait_win[i].push(s.wait_us as f64 / s.runs as f64);
                    }
                    cnt_win[i].push(s.wakes as f64);
                    dom_qacc[d].0 += s.wait_us as f64;
                    dom_qacc[d].1 += s.runs as f64;
                }
                if dom_win.len() < dom_acc.len() {
                    dom_win.resize_with(dom_acc.len(), RawWindow::new);
                    dom_wait_win.resize_with(dom_acc.len(), RawWindow::new);
                }
                for (d, &(sum, n)) in dom_acc.iter().enumerate() {
                    if n > 0 {
                        dom_win[d].push(sum / n as f64);
                    }
                }
                for (d, &(wsum, runs)) in dom_qacc.iter().enumerate() {
                    if runs > 0.0 {
                        dom_wait_win[d].push(wsum / runs);
                    }
                }
                e += 1;
            }
            depth_cursor = newest - 1;
        }

        // CHAOS PRIMITIVES. ONE O(N^2) HVG PASS + ONE O(N^2) RQA PASS
        // PER WINDOW; BP IS O(N). RQA-DET READS THE SAME idle_pct SAMPLES
        // AS HVG ON ITS OWN RQA_WIN WINDOW, AND rqa IS None FOR THE FIRST
        // RQA_MIN_SAMPLES TICKS.
        let (idle_lambda, _idle_hvg_s) = chaos::hvg_stats(&idle_win);
        let wake_bp_h = chaos::bandt_pompe_d3(&wake_win);

        // BUILD THE LIVE LOAD GRAPH. Measured and reported before anything
        // prices against it: if the coupling spread is ~0 the graph is
        // complete-and-uniform and carries no structure the static topology
        // does not already have. The knob derivation reads its domain series;
        // the coupling it measures stays telemetry.
        let graph = LoadGraph::build(&wait_win, &cnt_win, &dom_win, &dom_wait_win, &cpu_dom);
        let (g_edges, g_mean, g_min, g_max) = graph.edge_summary();
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
        }
        for w in &graph.dom_wait {
            if w.is_finite() {
                g_dom_wait_sum += w;
                g_dom_wait_n += 1;
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
        // SPILL-Phi CHAOS->TEMPERATURE BRIDGE: OVERLAID ONTO EVERY KNOB
        // WRITE BELOW LIKE topology_tau_ns; INERT IN BPF UNTIL THE SPILL
        // PRICE CONSUMES IT.
        let bp_delta = wake_bp_h - prev_bp_h;
        let mean_idle = chaos::mean(&idle_win);
        let rqa = chaos::rqa_det(&rqa_win);

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
                let set = graph.derive_percpu_knobs(&rk);
                sched.write_tuning_knobs_percpu(&set)?;
                last_written = set;
                regime_changed_this_tick = true;
                // RESET ONLY THE NEW REGIME'S WEIGHT VECTOR + EDGE STATE
                // (THE OTHER REGIMES KEEP THEIR LEARNED VECTORS), AND
                // SNAP THE ADAPTIVE-RARITY INTERVAL BACK TO BASE.
                retune_interval = tuning::RETUNE_INTERVAL_BASE;
                ticks_since_retune = 0;
            }
        } else {
            pending_regime = regime;
            regime_hold = 0;
        }

        // QUIESCENCE GATE. No queued work in any depth sample this tick, and
        // the pattern lenses that have a reading in band -> latch `frozen` and
        // skip the retune + knob write. The loop still ticks at 1 Hz; any
        // queued work or a lambda leaving the steady band thaws it on the
        // same tick, so a regime change and the gate compose without conflict.
        let frozen = quiesce.update(idle_lambda, rqa, depth_occupied);
        if depth_occupied {
            occupied_ticks += 1;
        }
        if frozen {
            frozen_ticks += 1;
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
                // DEFER TO THE OSCILLATOR. While the BPF oscillator is pulled
                // below rest by rescues it is already correcting this pressure;
                // a knob write now would be a second controller on the same
                // error. The write holds, last_written stays, and the next
                // retune after the oscillator returns to rest commits it.
                let set = graph.derive_percpu_knobs(&knobs);
                let changed = set.len() != last_written.len()
                    || set
                        .iter()
                        .zip(&last_written)
                        .any(|(a, b)| tuning::knobs_differ(a, b));
                let deferring = osc.responding(live.codel_eq_ns);
                if changed && deferring {
                    knob_writes_deferred += 1;
                }
                if changed && !deferring {
                    sched.write_tuning_knobs_percpu(&set)?;
                    knob_writes += 1;
                    let lo = set.iter().map(|k| k.slice_ns).min().unwrap_or(0);
                    let hi = set.iter().map(|k| k.slice_ns).max().unwrap_or(0);
                    slice_spread_sum_us += (hi - lo) as f64 / 1000.0;
                    last_written = set;
                }
                let disturbed = chaos_crossing;
                retune_interval =
                    tuning::next_retune_interval(retune_interval, !changed, disturbed);
            }
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

        let sojourn_ms = stats.batch_sojourn_ns / 1_000_000;
        let sojourn_thresh_ms = knobs.codel_thresh_ns / 1_000_000;
        let longrun_label = if stats.longrun_mode_active > 0 {
            " LONGRUN"
        } else {
            ""
        };

        if verbose && tuning::should_print_telemetry(tick_counter, stability_score) {
            let rqa_disp = rqa.unwrap_or(-1.0);
            let frozen_disp = if frozen { 1 } else { 0 };
            println!(
                "d/s: {:<8} idle: {}% shared: {:<6} preempt: {:<4} keep: {:<4} kick: H={:<4} S={:<4} enq: W={:<4} R={:<4} wake: {}us p99: {}us [B:{} I:{} L:{}] lat_idle: {}us lat_kick: {}us sleep: io={}% slice: {}us batch: {}us reenq: {} sjrn: {}ms/{}ms rescue: {} l2: B={}% I={}% chaos: lam={:.2} H={:.2} det={:.2} x={} frozen: {} (n={}) retune_iv: {} [{}{}] graph: n={} e={} cpl={:.2}/{:.2}/{:.2} osc: {:.2}/{}us",
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
                sojourn_ms,
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
                graph.n,
                g_edges,
                g_mean,
                g_min,
                g_max,
                osc_pos,
                osc_rel_us,
                regime.label(),
                longrun_label,
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

        tick_counter += 1;
        prev_hist = cur_hist;
        prev_sleep = cur_sleep;
        prev = stats;
        prev_bp_h = wake_bp_h;
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
             pandemonium_graph_dom_wait_mean_us {:.2}\n",
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
            g_dom_wait_sum / g_dom_wait_n.max(1) as f64
        );
        let path = dir.join(format!("graph-{}.prom", std::process::id()));
        let _ = std::fs::write(&path, body);
        println!("[GRAPH] {}", path.display());
    }

    println!(
        "[KNOBS] regime={} slice_ns={} batch_ns={} ticks=L:{}/M:{}/H:{} frozen={} l2_hit=B:{}%/I:{}% cross_domain_scatter_pct={} cross_domain_sel_tight={} cross_domain_sel_sync={} cross_domain_sel_normal={} cross_domain_sel_dfl={} cross_domain_enq_t1={} cross_domain_enq_t2={} cross_domain_steal={} cross_domain_step5={} osc_park={} steal={} spill={} kick_declined={} dispatches={}",
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
        final_stats.nr_spill_kick_preempt,
        final_stats.nr_kick_declined,
        final_stats.nr_dispatches,
    );

    // READ UEI EXIT REASON
    let should_restart = sched.read_exit_info();
    Ok(should_restart)
}
