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
use crate::scheduler::{PandemoniumStats, Scheduler};
use crate::topology::CpuTopology;
use crate::tuning::{self, detect_regime, scaled_regime_knobs, Regime, HIST_BUCKETS};

// CHAOS WINDOW SIZE. 16 SAMPLES AT 1HZ = 16-SECOND REGIME MEMORY.
// SIZED FOR BENCH-SCALE RESPONSIVENESS (16-30s iterations) RATHER THAN
// MINUTE-SCALE DESKTOP STEADY STATE. HVG IS O(N^2) = 256 COMPARISONS
// PER TICK; BP D=3 GETS 14 LENGTH-3 PATTERNS OVER 6 BUCKETS -- LIMITED
// RESOLUTION BUT ENOUGH TO DISTINGUISH PERIODIC FROM RANDOM IN ONE
// BENCH ITERATION.
const CHAOS_WIN: usize = 16;

// REGIME THRESHOLDS, PROFILES, AND KNOB COMPUTATION LIVE IN tuning.rs
// (ZERO BPF DEPENDENCIES, TESTABLE OFFLINE)

// THE LIVE LOAD GRAPH
//
// Nodes are CPUs weighted by mean runqueue depth; edges are CPU pairs weighted
// by Pecora-Carroll coupling between their depth series. The chip's electrical
// graph is a constant and R_eff already prices against it; this is the graph
// the WORKLOAD forms, which moves every second and which nothing measured.
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
    // Mean runqueue depth per CPU over the last window. NaN where a CPU has
    // no usable series yet -- absent, not empty.
    pub node_depth: Vec<f64>,
    // TRAFFIC SHAPE per CPU (Kim-Jo finite-size-corrected burstiness, [-1, 1]).
    // -1 perfectly regular / deadline-paced, 0 Poisson / longrun, +1 maximally
    // bursty / starvation-shaped. This is the continuous form of the property
    // the three-valued regime enum was approximating for the whole machine.
    pub node_burst: Vec<Option<chaos::Priced>>,
    // CRITICAL SLOWING per CPU (lag-1 autocorrelation, [-1, 1]). Rises BEFORE
    // saturation rather than at window close, which is the one thing no other
    // signal in this loop does.
    pub node_slowing: Vec<Option<chaos::Priced>>,
    // PERSISTENCE per CPU (Veitch-Abry Hurst, [0, 1]). > 0.5 says this CPU's
    // load pattern tends to continue, which is precisely the "the same task is
    // likely to return" premise the warm-stay price already assumes.
    pub node_persist: Vec<Option<chaos::Priced>>,
    // Upper-triangular coupling, index pair_index(i, j). None where either
    // series is too short or flat to couple.
    pub edge: Vec<Option<f64>>,
    pub n: usize,
}

fn pair_index(n: usize, i: usize, j: usize) -> usize {
    // i < j; row-major over the strict upper triangle.
    debug_assert!(i < j && j < n);
    i * n - (i * (i + 1)) / 2 + (j - i - 1)
}

impl LoadGraph {
    pub fn build<const N: usize>(depth_win: &[RawWindow<N>]) -> LoadGraph {
        let n = depth_win.len();
        let node_depth = depth_win
            .iter()
            .map(|w| {
                if w.is_empty() {
                    f64::NAN
                } else {
                    chaos::mean(w)
                }
            })
            .collect();
        // NODE ATTRIBUTES. Each answers a different question about the same
        // series, which is why they derive different knobs: burstiness is
        // SHAPE, lag-1 is DIRECTION, Hurst is DURATION. A learner searching one
        // loss signal could not separate them; measured, they do not need to be.
        // PRICED, NOT GATED. Each answers wherever its arithmetic is defined and
        // carries how much the window is worth; the derivations below scale their
        // effect by that confidence. A knob moves a little on thin evidence and
        // fully on a complete window, instead of not at all and then all at once.
        let node_burst = depth_win
            .iter()
            .map(chaos::kim_jo_burstiness_priced)
            .collect();
        let node_slowing = depth_win.iter().map(chaos::lag1_autocorr_priced).collect();
        let node_persist = depth_win
            .iter()
            .map(chaos::veitch_abry_hurst_priced)
            .collect();

        let mut edge = vec![None; n * (n.saturating_sub(1)) / 2];
        for i in 0..n {
            for j in (i + 1)..n {
                edge[pair_index(n, i, j)] = chaos::pecora_carroll(&depth_win[i], &depth_win[j]);
            }
        }
        LoadGraph {
            node_depth,
            node_burst,
            node_slowing,
            node_persist,
            edge,
            n,
        }
    }

    // DERIVE PER-CPU SLICE PRESSURE FROM THE GRAPH.
    //
    // This is what the graph is FOR. A CPU carrying a deep queue needs a
    // shorter slice so the queue drains; a CPU near-empty needs a longer one so
    // it stops paying context-switch cost for work that is not contending. MWU
    // could only ever search for one slice for the whole machine, so it was
    // solving the average of a distribution it could not see -- the average
    // being wrong for every CPU that is not at the mean.
    //
    // DERIVED, NOT LEARNED. There is no loss signal, no convergence window and
    // no weight vector: depth is measured and the slice follows from it this
    // tick. codel_eq_ns has worked this way since v5.16.0 (computed from R_eff,
    // explicitly excluded from MWU); this extends that pattern to the knobs a
    // learner was guessing at.
    //
    // Returns one knob set per CPU, seeded from `base` so every field the graph
    // does not own is carried through untouched.
    pub fn derive_percpu_knobs(
        &self,
        base: &crate::tuning::TuningKnobs,
    ) -> Vec<crate::tuning::TuningKnobs> {
        // Reference depth: the mean over CPUs that actually reported. A CPU at
        // the reference keeps the base slice exactly, so a uniformly-loaded
        // machine is bit-identical to the pre-graph behavior.
        let present: Vec<f64> = self
            .node_depth
            .iter()
            .copied()
            .filter(|d| d.is_finite())
            .collect();
        let refd = if present.is_empty() {
            0.0
        } else {
            present.iter().sum::<f64>() / present.len() as f64
        };
        self.node_depth
            .iter()
            .enumerate()
            .map(|(i, d)| {
                let mut k = *base;
                // Absent series or a flat machine: carry the base through.
                if !d.is_finite() || refd <= f64::EPSILON {
                    return k;
                }
                // Deeper than reference -> shorter slice, and inversely.
                // Clamped to [1/2, 2x] so one anomalous tick cannot hand a CPU
                // a slice far outside anything the regime profile intended.
                let ratio = (refd / (d + refd).max(f64::EPSILON) * 2.0).clamp(0.5, 2.0);
                k.slice_ns = ((base.slice_ns as f64) * ratio) as u64;
                k.preempt_thresh_ns = ((base.preempt_thresh_ns as f64) * ratio) as u64;

                // BURSTINESS -> BATCH AND BURST CEILINGS.
                // Bursty traffic (B > 0) arrives in clumps with quiet between,
                // so a batch task wants a LONGER ceiling: it will not be
                // contending most of the time, and cutting it short pays
                // context-switch cost for contention that is not there. Paced
                // traffic (B < 0) is the opposite -- steady arrivals mean a
                // long ceiling holds the CPU against work that is genuinely
                // queued. Scaled +/-50% across the full [-1, 1] range.
                if let Some(b) = self.node_burst.get(i).and_then(|v| *v) {
                    // weighted() collapses toward the neutral factor 1.0 as
                    // confidence falls, so a thin window nudges rather than swings.
                    let f = Priced {
                        value: 1.0 + 0.5 * b.value.clamp(-1.0, 1.0),
                        confidence: b.confidence,
                    }
                    .weighted(1.0);
                    k.batch_slice_ns = ((base.batch_slice_ns as f64) * f) as u64;
                    k.burst_slice_ns = ((base.burst_slice_ns as f64) * f) as u64;
                }

                // CRITICAL SLOWING -> PREEMPT WINDOW, AHEAD OF THE BURST.
                // r1 rising toward 1 means perturbations on this CPU are
                // persisting instead of damping: it is approaching saturation
                // and has not got there yet. Tightening the preempt window now
                // is the only place in this loop that acts on a prediction
                // rather than on a completed loss. Only the positive half
                // matters -- an oscillating CPU (r1 < 0) is already recovering.
                if let Some(r1) = self.node_slowing.get(i).and_then(|v| *v) {
                    if r1.value > 0.0 {
                        let tighten = Priced {
                            value: 1.0 - 0.4 * r1.value.clamp(0.0, 1.0),
                            confidence: r1.confidence,
                        }
                        .weighted(1.0);
                        k.preempt_thresh_ns = ((k.preempt_thresh_ns as f64) * tighten) as u64;
                    }
                }

                // PERSISTENCE -> CoDel RESCUE THRESHOLD.
                // H > 0.5 says this CPU's load pattern tends to continue, so a
                // queue that is deep now will likely still be deep: rescue
                // sooner. H < 0.5 is mean-reverting, where a deep queue is
                // likely transient and rescuing early only scatters a task that
                // was about to be served anyway. Centered on H = 0.5 so an
                // uncorrelated CPU keeps the base exactly.
                if let Some(h) = self.node_persist.get(i).and_then(|v| *v) {
                    let f = Priced {
                        value: (1.0f64 - (h.value.clamp(0.0, 1.0) - 0.5)).clamp(0.5, 1.5),
                        confidence: h.confidence,
                    }
                    .weighted(1.0);
                    k.codel_thresh_ns = ((base.codel_thresh_ns as f64) * f) as u64;
                }

                // AFFINITY IS NOT DERIVED, AND THE REASON IS MEASURED.
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
                // evidence on one side only, so the knob keeps the base value
                // until something measures the direction. mean_coupling() stays
                // as telemetry -- the reading is still wanted, the actuation is
                // not.
                k
            })
            .collect()
    }

    // TELEMETRY ONLY since the affinity derivation was withdrawn. This is the
    // number that says whether the coupling graph carries structure at all, and
    // it is still wanted -- the reading was never the problem.
    #[allow(dead_code)]
    // Mean coupling over the edges that computed. None when the machine is too
    // quiet or too new to have any -- affinity then keeps whatever the caller
    // set rather than defaulting to a guess.
    pub fn mean_coupling(&self) -> Option<f64> {
        let (n, mean, _, _) = self.edge_summary();
        if n == 0 {
            None
        } else {
            Some(mean)
        }
    }

    // Is there structure worth pricing against? Returns (available_edges,
    // mean, min, max) over the edges that computed. A spread near zero means
    // the coupling matrix is flat and the live graph adds nothing over the
    // static one.
    pub fn edge_summary(&self) -> (usize, f64, f64, f64) {
        let vals: Vec<f64> = self.edge.iter().filter_map(|e| *e).collect();
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
    phi_scale: Option<u64>,
) -> Result<bool> {
    // HOTPLUG POLL STATE: the online count as last observed. The poll below
    // re-derives topology on change AND refreshes the Rust-local tau_ns --
    // without that refresh, a hotplug that changes tau without flipping the
    // regime left MWU computing every knob off pre-hotplug tau until a regime
    // change happened to land (the stale-MWU-tau gap).
    let mut last_online = CpuTopology::online_cpu_count();
    let mut prev = PandemoniumStats::default();
    let mut prev_hist = [[0u64; HIST_BUCKETS]; 3];
    let mut prev_sleep = [0u64; SLEEP_BUCKETS];
    let mut regime = Regime::Mixed;

    // CHAOS RAW WINDOWS. idle_pct DRIVES REGIME DETECTION; wakeup_rate
    // DRIVES THE MWU CHAOS-TRANSITION PATHWAY (BANDT-POMPE IS ORDINAL,
    // SO ABSOLUTE RATE SCALE DOES NOT MATTER -- THE PATTERN DOES).
    let mut idle_win: RawWindow<CHAOS_WIN> = RawWindow::new();
    let mut wake_win: RawWindow<CHAOS_WIN> = RawWindow::new();
    // PER-CPU RUNQUEUE-DEPTH WINDOWS: THE NODES OF THE LIVE LOAD GRAPH.
    // One series per CPU, each the interval-mean depth on that CPU, which is
    // what rq_depth_sum/rq_depth_samples differenced gives. Until v5.18.0
    // there was exactly ONE series in this whole loop -- a system-wide integer
    // percentage -- which is why a coupling measure had nothing to couple.
    let mut depth_win: Vec<RawWindow<CHAOS_WIN>> =
        (0..nr_cpus as usize).map(|_| RawWindow::new()).collect();
    let mut prev_percpu: Vec<PandemoniumStats> = Vec::new();
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
    // a "frozen" flag from HVG-lambda + RQA-DET + MWU convergence and
    // the loop then skips the expensive MWU retune + knob write. When
    // not frozen, the retune interval stretches on sub-threshold deltas.
    let mut quiesce = tuning::QuiescenceState::new();
    let mut retune_interval: u32 = tuning::RETUNE_INTERVAL_BASE;
    let mut ticks_since_retune: u32 = 0;
    let mut frozen_ticks: u64 = 0;
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

    // APPLY INITIAL REGIME. scaled_regime_knobs RETURNS topology_tau_ns/codel_eq_ns=0;
    // OVERLAY THE LIVE BPF VALUES SO THE FIRST WRITE DOESN'T CLOBBER WHAT
    // write_topology_fields() PUT IN THE MAP. Mirrors the regime-change path at line 230.
    let live = sched.read_tuning_knobs();
    let mut rk = scaled_regime_knobs(regime, nr_cpus, tau_ns);
    rk.topology_tau_ns = tau_ns;
    rk.codel_eq_ns = live.codel_eq_ns;
    sched.write_tuning_knobs(&rk)?;
    // SEED THE MWU BASELINE WITH THE LIVE PHI EQUILIBRIUM AT TICK 0. new()
    // BUILT mwu FROM scaled_regime_knobs (codel_eq_ns=0); set_baseline IS
    // OTHERWISE ONLY CALLED ON A REGIME CHANGE. WITHOUT THIS SEED THE SOJOURN
    // FLOOR (tuning.rs) FALLS BACK TO THE DEAD 4ms CONSTANT FOR ANY RUN WHOSE
    // REGIME NEVER CHANGES (E.G. A STEADY MIXED BENCH), SO THE PHI-COHERENT
    // FLOOR WOULD NEVER ENGAGE.
    // COMMIT-ON-CHANGE BASELINE: the last knob set actually written to
    // the BPF map. Updated here at init, on every regime-change write,
    // and on every conditional write. MWU-owned fields drive the diff.
    let mut last_written_knobs = rk;

    while !shutdown.load(Ordering::Relaxed) && !sched.exited() {
        crate::watchdog::LOOP_HEARTBEAT.fetch_add(1, Ordering::Relaxed);
        std::thread::sleep(Duration::from_secs(1));

        if CpuTopology::poll_hotplug(sched, nr_cpus as usize, phi_scale, &mut last_online) {
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
        // P99 AND FEEDS NONSENSE TO MWU. RESET BASELINE AND SKIP THE TICK.
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
        let delta_enq_wake = stats.nr_enq_wakeup.wrapping_sub(prev.nr_enq_wakeup);
        let delta_enq_requeue = stats.nr_enq_requeue.wrapping_sub(prev.nr_enq_requeue);
        let delta_rescue = stats
            .nr_overflow_rescue
            .wrapping_sub(prev.nr_overflow_rescue);
        // CROSS-DOMAIN SCATTER (PATHWAY 6 INPUT). PLACEMENT-SIDE PATHS ONLY:
        // XDOM_SEL_* + XDOM_ENQ_T1/T2 (INDICES 0..6). THE PHI-CORRECT WORK-
        // CONSERVATION PATHS XDOM_STEAL (6) AND XDOM_STEP5 (7) ARE EXCLUDED --
        // PENALIZING THEM WOULD MAKE MWU FIGHT THE BPF'S DELIBERATE REBALANCING.
        // saturating_sub ABSORBS A COUNTER RESET (BPF RELOAD) AS 0, NO GARBAGE.
        let scatter_now: u64 = stats.nr_cross_domain[0..6].iter().sum();
        let scatter_prev: u64 = prev.nr_cross_domain[0..6].iter().sum();
        let delta_scatter = scatter_now.saturating_sub(scatter_prev);
        // Cross-domain scatter: measured and reported. Its consumer was MWU's
        // scatter loss pathway; placement now prices against the graph instead.
        let _scatter_pct = if delta_d > 0 {
            delta_scatter * 100 / delta_d
        } else {
            0
        };
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
        let dl2_hl = stats
            .nr_l2_hit_lat_crit
            .wrapping_sub(prev.nr_l2_hit_lat_crit);
        let dl2_ml = stats
            .nr_l2_miss_lat_crit
            .wrapping_sub(prev.nr_l2_miss_lat_crit);
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
        let l2_pct_l = if dl2_hl + dl2_ml > 0 {
            dl2_hl * 100 / (dl2_hl + dl2_ml)
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
        wake_win.push(delta_enq_wake as f64);

        // NODE WEIGHTS: MEAN RUNQUEUE DEPTH PER CPU OVER THIS INTERVAL.
        // Both fields are monotonic, so the interval mean is the ratio of the
        // two deltas -- the same shape wake_lat_sum/wake_lat_samples is already
        // consumed with. A CPU whose sample count did not advance contributes
        // nothing rather than a zero: no samples is not an empty queue.
        if prev_percpu.len() == percpu.len() {
            for (i, w) in depth_win.iter_mut().enumerate() {
                if i >= percpu.len() {
                    break;
                }
                let ds = percpu[i]
                    .rq_depth_samples
                    .wrapping_sub(prev_percpu[i].rq_depth_samples);
                if ds > 0 {
                    let dd = percpu[i]
                        .rq_depth_sum
                        .wrapping_sub(prev_percpu[i].rq_depth_sum);
                    w.push(dd as f64 / ds as f64);
                }
            }
        }
        prev_percpu = percpu.clone();

        // CHAOS PRIMITIVES. ONE O(N^2) HVG PASS + ONE O(N^2) RQA PASS
        // PER WINDOW; BP IS O(N). RQA-DET RUNS ON THE SAME idle_win AS
        // HVG SO THE QUIESCENCE GATE SEES IDENTICAL SAMPLES. rqa IS
        // None UNTIL THE WINDOW HAS RQA_MIN_SAMPLES FILLED.
        let (idle_lambda, _idle_hvg_s) = chaos::hvg_stats(&idle_win);
        let wake_bp_h = chaos::bandt_pompe_d3(&wake_win);

        // BUILD THE LIVE LOAD GRAPH. Measured and reported before anything
        // prices against it: if the coupling spread is ~0 the graph is
        // complete-and-uniform and carries no structure the static topology
        // does not already have. Nothing downstream consumes it yet -- this
        // tick is the falsification, not the feature.
        let graph = LoadGraph::build(&depth_win);
        let (g_edges, g_mean, g_min, g_max) = graph.edge_summary();
        g_tick += 1;
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
        let spill_temp_q16 = tuning::spill_temp_q16(wake_bp_h);
        let bp_delta = wake_bp_h - prev_bp_h;
        let mean_idle = chaos::mean(&idle_win);
        let rqa = chaos::rqa_det(&idle_win);

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
                rk.spill_temp_q16 = spill_temp_q16;
                // Regime baseline, spread per CPU by the graph on the same
                // terms as the retune path below.
                sched.write_tuning_knobs_percpu(&graph.derive_percpu_knobs(&rk))?;
                last_written_knobs = rk;
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

        // QUIESCENCE GATE. HVG-lambda in the periodic band + RQA-DET
        // steady + the active-regime MWU vector converged -> latch
        // `frozen` and skip the expensive MWU retune + knob write. The
        // loop still ticks at 1 Hz; the chaos sensors above are the
        // exit condition for frozen mode. A regime change moves lambda
        // out of the steady band, so the gate thaws on the same/next
        // tick -- the two gates compose without conflict.
        // The freeze gate's third term was MWU convergence. With no learner
        // there is nothing to converge, so the gate is the chaos band alone.
        let frozen = quiesce.update(idle_lambda, rqa, true);
        if frozen {
            frozen_ticks += 1;
        }

        // MWU ORCHESTRATOR: UNIFIED KNOB CONTROL
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
                knobs.spill_temp_q16 = spill_temp_q16;
                // COMMIT-ON-CHANGE: only push when a field actually moved. The
                // BPF side reads the map unsynchronized, so skipping redundant
                // writes strictly reduces torn-read exposure.
                let changed = tuning::knobs_differ(&knobs, &last_written_knobs);
                if changed {
                    sched.write_tuning_knobs_percpu(&graph.derive_percpu_knobs(&knobs))?;
                    last_written_knobs = knobs;
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
                "d/s: {:<8} idle: {}% shared: {:<6} preempt: {:<4} keep: {:<4} kick: H={:<4} S={:<4} enq: W={:<4} R={:<4} wake: {}us p99: {}us [B:{} I:{} L:{}] lat_idle: {}us lat_kick: {}us sleep: io={}% slice: {}us batch: {}us reenq: {} sjrn: {}ms/{}ms rescue: {} l2: B={}% I={}% L={}% chaos: lam={:.2} H={:.2} det={:.2} x={} frozen: {} (n={}) retune_iv: {} [{}{}] graph: n={} e={} cpl={:.2}/{:.2}/{:.2}",
                delta_d, idle_pct, delta_shared, delta_preempt, delta_keep,
                delta_hard, delta_soft, delta_enq_wake, delta_enq_requeue,
                wake_avg_us, p99_us, tp99_b, tp99_i, tp99_l,
                lat_idle_us, lat_kick_us,
                io_pct, knobs.slice_ns / 1000, knobs.batch_slice_ns / 1000,
                delta_reenq, sojourn_ms, sojourn_thresh_ms,
                delta_rescue,
                l2_pct_b, l2_pct_i, l2_pct_l,
                idle_lambda, wake_bp_h, rqa_disp, chaos_count.load(),
                frozen_disp, frozen_ticks, retune_interval,
                graph.n, g_edges, g_mean, g_min, g_max,
                regime.label(), longrun_label,
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
    let l2_total_l = final_stats.nr_l2_hit_lat_crit + final_stats.nr_l2_miss_lat_crit;
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
    let l2_cum_l = if l2_total_l > 0 {
        final_stats.nr_l2_hit_lat_crit * 100 / l2_total_l
    } else {
        0
    };
    // CROSS-DOMAIN SCATTER ATTRIBUTION (PER XDOM_* PATH). scatter_pct IS THE
    // PLACEMENT-SIDE FRACTION (idx 0..6) PATHWAY 6 ACTS ON; THE PER-PATH COUNTS
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
             pandemonium_chaos_frozen_fraction {:.4}\n",
            g_tick,
            g_edge_ticks,
            g_edges_total as f64 / denom,
            g_mean_sum / denom,
            g_spread_sum / denom,
            g_spread_max,
            frozen_ticks,
            frozen_ticks as f64 / g_tick.max(1) as f64
        );
        let path = dir.join(format!("graph-{}.prom", std::process::id()));
        let _ = std::fs::write(&path, body);
        println!("[GRAPH] {}", path.display());
    }

    println!(
        "[KNOBS] regime={} slice_ns={} batch_ns={} preempt_ns={} mwu={:.3} ticks=L:{}/M:{}/H:{} frozen={} l2_hit=B:{}%/I:{}%/L:{}% cross_domain_scatter_pct={} cross_domain_sel_tight={} cross_domain_sel_sync={} cross_domain_sel_normal={} cross_domain_sel_dfl={} cross_domain_enq_t1={} cross_domain_enq_t2={} cross_domain_steal={} cross_domain_step5={} osc_park={}",
        regime.label(), final_knobs.slice_ns, final_knobs.batch_slice_ns,
        final_knobs.preempt_thresh_ns,
        0.0f64,
        light_ticks, mixed_ticks, heavy_ticks, frozen_ticks,
        l2_cum_b, l2_cum_i, l2_cum_l,
        x_scatter_pct, x[0], x[1], x[2], x[3], x[4], x[5], x[6], x[7],
        final_stats.nr_osc_park,
    );

    // READ UEI EXIT REASON
    let should_restart = sched.read_exit_info();
    Ok(should_restart)
}

// THE LIVE LOAD GRAPH SEES STRUCTURE THAT THE STATIC TOPOLOGY CANNOT
//
// The static chip graph is a constant: two CPUs in the same cache domain are
// always "close", whatever the workload does. These build a graph from
// synthetic per-CPU depth series where the COUPLING is known by construction
// and the wiring is irrelevant, and require the graph to report it. A build
// that returned a flat matrix would still produce a plausible telemetry line,
// which is exactly why the discriminating case is asserted rather than eyeballed.
#[cfg(test)]
mod load_graph_tests {
    use super::*;

    fn lcg(s: &mut u64) -> f64 {
        *s = s
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        ((*s >> 33) as f64 / (1u64 << 31) as f64) - 0.5
    }

    fn win(vals: &[f64]) -> RawWindow<CHAOS_WIN> {
        let mut w = RawWindow::new();
        for v in vals {
            w.push(*v);
        }
        w
    }

    #[test]
    fn pair_index_is_a_bijection_over_the_upper_triangle() {
        for n in 2..12usize {
            let mut seen = vec![false; n * (n - 1) / 2];
            for i in 0..n {
                for j in (i + 1)..n {
                    let k = pair_index(n, i, j);
                    assert!(!seen[k], "n={n} collision at ({i},{j})");
                    seen[k] = true;
                }
            }
            assert!(seen.iter().all(|s| *s), "n={n} left a hole");
        }
    }

    #[test]
    fn coupled_cpus_read_higher_than_independent_ones() {
        // CPUs 0 and 1 share a driving signal; CPU 2 runs its own. No cache
        // topology is involved -- this is structure the static graph cannot
        // express, which is the entire claim.
        let mut s = 4242u64;
        let drive: Vec<f64> = (0..CHAOS_WIN).map(|_| 2.0 + lcg(&mut s)).collect();
        let mut s2 = 99u64;
        let indep: Vec<f64> = (0..CHAOS_WIN).map(|_| 2.0 + lcg(&mut s2)).collect();
        let scaled: Vec<f64> = drive.iter().map(|v| 3.0 * v + 1.0).collect();

        let g = LoadGraph::build(&[win(&drive), win(&scaled), win(&indep)]);
        let c01 = g.edge[pair_index(3, 0, 1)].expect("0-1 must couple");
        let c02 = g.edge[pair_index(3, 0, 2)].expect("0-2 must compute");
        assert!(
            c01 > c02,
            "coupled pair {c01} must exceed independent pair {c02}"
        );
        assert!(c01 > 0.9, "an affine copy should read as slaved, got {c01}");
    }

    #[test]
    fn a_flat_machine_produces_no_edges_not_fake_ones() {
        // Every CPU pinned at the same depth: no dynamics, nothing to couple.
        // Reporting perfect synchrony here would make an idle box look maximally
        // structured, which is the most common state a desktop is in.
        let g = LoadGraph::build(&[win(&[4.0; CHAOS_WIN]), win(&[4.0; CHAOS_WIN])]);
        assert_eq!(g.edge_summary().0, 0, "a flat machine must yield no edges");
    }

    #[test]
    fn edge_summary_spread_is_the_falsification() {
        // A uniform-coupling machine has ~zero spread and the live graph adds
        // nothing over the static one. A mixed machine must not.
        let mut s = 7u64;
        let a: Vec<f64> = (0..CHAOS_WIN).map(|_| 2.0 + lcg(&mut s)).collect();
        let b: Vec<f64> = a.iter().map(|v| 2.0 * v).collect();
        let mut s2 = 8u64;
        let c: Vec<f64> = (0..CHAOS_WIN).map(|_| 2.0 + lcg(&mut s2)).collect();
        let g = LoadGraph::build(&[win(&a), win(&b), win(&c)]);
        let (n, _mean, lo, hi) = g.edge_summary();
        assert_eq!(n, 3);
        assert!(
            hi - lo > 0.3,
            "mixed machine should show spread, got {}",
            hi - lo
        );
    }

    #[test]
    fn nodes_absent_where_a_cpu_has_no_series() {
        // An offline or never-sampled CPU is ABSENT, not depth zero. Zero would
        // read as a permanently idle CPU and drag every mean toward it.
        let g = LoadGraph::build(&[win(&[1.0, 2.0, 3.0]), win(&[])]);
        assert!(g.node_depth[0].is_finite());
        assert!(
            g.node_depth[1].is_nan(),
            "an unsampled CPU must not read as 0"
        );
    }
}

// THE GRAPH ACTUALLY DRIVES THE KNOBS
//
// derive_percpu_knobs is the consumer LoadGraph exists for. These pin the two
// properties that decide whether it is safe to have MWU stop owning the slice:
// a machine with no structure must come out exactly where it went in, and a
// machine WITH structure must come out different in the right direction.
#[cfg(test)]
mod derive_tests {
    use super::*;
    use crate::tuning::TuningKnobs;

    fn base() -> TuningKnobs {
        let mut k = TuningKnobs::default();
        k.slice_ns = 1_000_000;
        k.preempt_thresh_ns = 1_000_000;
        k.codel_thresh_ns = 5_000_000;
        k
    }

    fn win(vals: &[f64]) -> RawWindow<CHAOS_WIN> {
        let mut w = RawWindow::new();
        for v in vals {
            w.push(*v);
        }
        w
    }

    #[test]
    fn a_uniform_machine_is_a_no_op() {
        // The safety property. Every CPU at the same depth must derive the base
        // slice exactly -- otherwise turning this on changes behavior on
        // machines that have no structure to exploit, which is most of them.
        let g = LoadGraph::build(&[win(&[3.0; 8]), win(&[3.0; 8]), win(&[3.0; 8])]);
        let b = base();
        for k in g.derive_percpu_knobs(&b) {
            assert_eq!(
                k.slice_ns, b.slice_ns,
                "uniform depth must not move the slice"
            );
            assert_eq!(k.preempt_thresh_ns, b.preempt_thresh_ns);
        }
    }

    #[test]
    fn a_deep_queue_gets_a_shorter_slice_than_a_shallow_one() {
        // The whole point: one machine-wide slice is the average of a
        // distribution MWU could not see. CPU 0 is buried, CPU 2 is nearly idle.
        let g = LoadGraph::build(&[win(&[12.0; 8]), win(&[3.0; 8]), win(&[0.2; 8])]);
        let k = g.derive_percpu_knobs(&base());
        assert!(
            k[0].slice_ns < k[1].slice_ns,
            "deep queue {} must slice shorter than mid {}",
            k[0].slice_ns,
            k[1].slice_ns
        );
        assert!(
            k[1].slice_ns < k[2].slice_ns,
            "mid {} must slice shorter than shallow {}",
            k[1].slice_ns,
            k[2].slice_ns
        );
    }

    #[test]
    fn derived_slices_stay_inside_the_clamp() {
        // One anomalous tick must not hand a CPU a slice far outside what the
        // regime profile intended. 2x either way, no further.
        let g = LoadGraph::build(&[win(&[1e9; 8]), win(&[0.0001; 8])]);
        let b = base();
        for k in g.derive_percpu_knobs(&b) {
            assert!(k.slice_ns >= b.slice_ns / 2, "under-clamp: {}", k.slice_ns);
            assert!(k.slice_ns <= b.slice_ns * 2, "over-clamp: {}", k.slice_ns);
        }
    }

    #[test]
    fn fields_the_graph_does_not_own_are_carried_through() {
        let g = LoadGraph::build(&[win(&[9.0; 8]), win(&[1.0; 8])]);
        let b = base();
        for k in g.derive_percpu_knobs(&b) {
            assert_eq!(
                k.codel_thresh_ns, b.codel_thresh_ns,
                "the graph must not touch knobs it does not own"
            );
        }
    }

    #[test]
    fn an_unsampled_cpu_keeps_the_base() {
        // NaN node -> no derivation. A CPU we have not measured must not be
        // handed a slice computed from a number we do not have.
        let g = LoadGraph::build(&[win(&[9.0; 8]), win(&[])]);
        let b = base();
        let k = g.derive_percpu_knobs(&b);
        assert_eq!(k[1].slice_ns, b.slice_ns);
    }
}

// EACH SENSOR DERIVES ITS OWN KNOB
//
// The claim these defend is that the four node attributes are not redundant:
// burstiness is SHAPE, lag-1 is DIRECTION, Hurst is DURATION, depth is
// MAGNITUDE. If any two moved the same knob the same way, one of them would be
// a second name for the other and MWU's single loss signal would have been
// adequate after all. Each test isolates one sensor and requires the others to
// stay out of the way.
#[cfg(test)]
mod derivation_tests {
    use super::*;
    use crate::tuning::TuningKnobs;

    fn base() -> TuningKnobs {
        let mut k = TuningKnobs::default();
        k.slice_ns = 1_000_000;
        k.preempt_thresh_ns = 1_000_000;
        k.batch_slice_ns = 20_000_000;
        k.burst_slice_ns = 1_000_000;
        k.codel_thresh_ns = 5_000_000;
        k
    }

    fn win(vals: &[f64]) -> RawWindow<CHAOS_WIN> {
        let mut w = RawWindow::new();
        for v in vals {
            w.push(*v);
        }
        w
    }

    fn lcg(s: &mut u64) -> f64 {
        *s = s
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        ((*s >> 33) as f64 / (1u64 << 31) as f64) - 0.5
    }

    // Spiky: long quiet punctuated by clumps. Burstiness positive.
    fn bursty() -> Vec<f64> {
        let mut v = vec![0.05f64; CHAOS_WIN];
        v[3] = 30.0;
        v[11] = 40.0;
        v
    }

    // Steady arrivals with tiny jitter. Burstiness negative.
    fn paced() -> Vec<f64> {
        let mut s = 3u64;
        (0..CHAOS_WIN).map(|_| 5.0 + 0.01 * lcg(&mut s)).collect()
    }

    #[test]
    fn bursty_traffic_lengthens_the_batch_ceiling_paced_shortens_it() {
        let g = LoadGraph::build(&[win(&bursty()), win(&paced())]);
        let b = base();
        let k = g.derive_percpu_knobs(&b);
        assert!(
            k[0].batch_slice_ns > b.batch_slice_ns,
            "bursty CPU should widen the batch ceiling: {} vs {}",
            k[0].batch_slice_ns,
            b.batch_slice_ns
        );
        assert!(
            k[1].batch_slice_ns < b.batch_slice_ns,
            "paced CPU should tighten it: {} vs {}",
            k[1].batch_slice_ns,
            b.batch_slice_ns
        );
    }

    #[test]
    fn critical_slowing_tightens_the_preempt_window() {
        // A ramp is maximally autocorrelated: r1 -> 1, the approach to
        // saturation. Compare against an oscillating CPU at the same mean
        // depth, where r1 < 0 and no tightening should apply.
        let ramp: Vec<f64> = (0..CHAOS_WIN).map(|i| 4.0 + i as f64 * 0.1).collect();
        let osc: Vec<f64> = (0..CHAOS_WIN)
            .map(|i| if i % 2 == 0 { 4.7 } else { 4.0 })
            .collect();
        let g = LoadGraph::build(&[win(&ramp), win(&osc)]);
        let k = g.derive_percpu_knobs(&base());
        assert!(
            k[0].preempt_thresh_ns < k[1].preempt_thresh_ns,
            "a CPU that is slowing critically must preempt sooner: {} vs {}",
            k[0].preempt_thresh_ns,
            k[1].preempt_thresh_ns
        );
    }

    #[test]
    fn persistence_rescues_sooner_than_mean_reversion() {
        // Random walk: H -> 1, a deep queue will stay deep, rescue sooner.
        // Differenced noise: H -> 0, transient, do not scatter the task.
        let mut s = 7u64;
        let mut acc = 5.0;
        let walk: Vec<f64> = (0..CHAOS_WIN)
            .map(|_| {
                acc += lcg(&mut s);
                acc.abs() + 1.0
            })
            .collect();
        let mut s2 = 11u64;
        let noise: Vec<f64> = (0..CHAOS_WIN + 1).map(|_| lcg(&mut s2)).collect();
        let diff: Vec<f64> = (1..=CHAOS_WIN)
            .map(|i| 5.0 + (noise[i] - noise[i - 1]))
            .collect();
        let g = LoadGraph::build(&[win(&walk), win(&diff)]);
        let k = g.derive_percpu_knobs(&base());
        assert!(
            k[0].codel_thresh_ns < k[1].codel_thresh_ns,
            "persistent load should rescue sooner than mean-reverting: {} vs {}",
            k[0].codel_thresh_ns,
            k[1].codel_thresh_ns
        );
    }

    #[test]
    fn the_sensors_move_different_knobs() {
        // The non-redundancy claim, asserted directly. Two CPUs with the SAME
        // mean depth but different shape must differ on the burst-derived
        // knobs and agree on the depth-derived slice.
        let mut s = 5u64;
        let a: Vec<f64> = {
            let mut v = vec![0.2f64; CHAOS_WIN];
            v[4] = 20.0;
            v
        };
        let mean_a: f64 = a.iter().sum::<f64>() / a.len() as f64;
        let b: Vec<f64> = (0..CHAOS_WIN)
            .map(|_| mean_a + 0.001 * lcg(&mut s))
            .collect();
        let g = LoadGraph::build(&[win(&a), win(&b)]);
        let k = g.derive_percpu_knobs(&base());
        // Within rounding: the ratio is a float and the two means differ in
        // the last bits. What matters is that SHAPE did not leak into the
        // depth-derived knob.
        let d = k[0].slice_ns.abs_diff(k[1].slice_ns);
        assert!(
            d * 10_000 < k[0].slice_ns,
            "equal mean depth must derive the same slice, got {} vs {}",
            k[0].slice_ns,
            k[1].slice_ns
        );
        assert_ne!(
            k[0].batch_slice_ns, k[1].batch_slice_ns,
            "different traffic shape must derive a different batch ceiling"
        );
    }

    #[test]
    fn data_flows_below_the_old_gate() {
        // THE POINT OF PRICING. Three samples is below the old burstiness floor
        // of four. Under the gate the knob did not move at all -- the reading
        // was discarded. Now it lands, weighted by what the window is worth.
        let g = LoadGraph::build(&[win(&[0.1, 9.0, 0.1])]);
        let b = base();
        assert_ne!(
            g.derive_percpu_knobs(&b)[0].batch_slice_ns,
            b.batch_slice_ns,
            "a sub-floor window must still reach the knob"
        );
    }

    #[test]
    fn hurst_stays_gated_because_its_floor_is_arithmetic() {
        // The one estimator that is NOT priced. Its floor is not statistical
        // thinness -- the wavelet fit needs three octaves, and a short window
        // yields two, which is a line through two points rather than a
        // regression. There is no weakly-known answer, so codel_thresh_ns holds.
        let g = LoadGraph::build(&[win(&[2.0, 3.0, 2.5])]);
        let b = base();
        assert_eq!(
            g.derive_percpu_knobs(&b)[0].codel_thresh_ns,
            b.codel_thresh_ns
        );
    }

    #[test]
    fn a_uniform_machine_derives_uniformly_but_not_necessarily_the_base() {
        // THE SAFETY PROPERTY, CORRECTED. With only the depth derivation an
        // unstructured machine came out exactly where it went in. With four
        // sensors that is no longer true and should not be: a machine with no
        // SPATIAL structure can still have TEMPORAL structure -- every CPU
        // slowing critically at once is a real state, and deriving from it is
        // the entire point.
        //
        // What must still hold is that identical CPUs get identical knobs.
        // Divergence without structure would mean a sensor is reading noise.
        let p = paced();
        let g = LoadGraph::build(&[win(&p), win(&p), win(&p)]);
        let k = g.derive_percpu_knobs(&base());
        for w in k.windows(2) {
            assert_eq!(
                w[0].slice_ns, w[1].slice_ns,
                "identical CPUs diverged on slice"
            );
            assert_eq!(
                w[0].preempt_thresh_ns, w[1].preempt_thresh_ns,
                "identical CPUs diverged on preempt"
            );
            assert_eq!(
                w[0].batch_slice_ns, w[1].batch_slice_ns,
                "identical CPUs diverged on batch ceiling"
            );
            assert_eq!(
                w[0].codel_thresh_ns, w[1].codel_thresh_ns,
                "identical CPUs diverged on rescue threshold"
            );
        }
    }
}

// AFFINITY IS NOT DERIVED FROM COUPLING
//
// It was, for one release candidate, and the first PRISM pass measured the
// cost. These pin the retreat: coupling is still READ, and it no longer moves
// the knob.
#[cfg(test)]
mod affinity_tests {
    use super::*;
    use crate::tuning::{TuningKnobs, AFFINITY_STRONG};

    fn win(vals: &[f64]) -> RawWindow<CHAOS_WIN> {
        let mut w = RawWindow::new();
        for v in vals {
            w.push(*v);
        }
        w
    }
    fn lcg(s: &mut u64) -> f64 {
        *s = s
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        ((*s >> 33) as f64 / (1u64 << 31) as f64) - 0.5
    }

    #[test]
    fn coupling_no_longer_moves_affinity() {
        // Two tightly coupled runqueues -- the IPC ping-pong shape that
        // regressed 16x when this derived. The knob must keep the base.
        let mut s = 21u64;
        let a: Vec<f64> = (0..CHAOS_WIN).map(|_| 4.0 + lcg(&mut s)).collect();
        let b: Vec<f64> = a.iter().map(|v| 2.0 * v + 1.0).collect();
        let g = LoadGraph::build(&[win(&a), win(&b)]);
        assert!(
            g.mean_coupling().unwrap() > 0.9,
            "the pair must still READ as coupled"
        );
        let mut base = TuningKnobs::default();
        base.affinity_mode = AFFINITY_STRONG;
        for k in g.derive_percpu_knobs(&base) {
            assert_eq!(
                k.affinity_mode, AFFINITY_STRONG,
                "affinity must carry the base through, not be derived"
            );
        }
    }
}
