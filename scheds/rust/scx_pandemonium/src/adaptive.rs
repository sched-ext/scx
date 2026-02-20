// PANDEMONIUM ADAPTIVE CONTROL LOOP
// EVENT-DRIVEN CLOSED-LOOP TUNING SYSTEM
//
// TWO THREADS, ZERO MUTEXES:
//   REFLEX THREAD: RING BUFFER CONSUMER. REACTS TO EVERY WAKE LATENCY SAMPLE.
//                  TIGHTENS TUNING KNOBS ON P99 SPIKES. SUB-MILLISECOND RESPONSE.
//   MONITOR THREAD: 1-SECOND CONTROL LOOP. DETECTS WORKLOAD REGIME.
//                   SETS BASELINE KNOBS. RELAXES GRADUALLY AFTER P99 NORMALIZES.
//
// BPF PRODUCES EVENTS, RUST REACTS. RUST WRITES KNOBS, BPF READS THEM
// ON THE VERY NEXT SCHEDULING DECISION. ONE SYSTEM, NOT TWO.

use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicU8, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use libbpf_rs::MapCore;

use crate::procdb::ProcessDb;
use crate::scheduler::{PandemoniumStats, Scheduler};
use crate::tuning::{self, Regime, TuningKnobs, regime_knobs, detect_regime, HIST_BUCKETS, HIST_EDGES_NS};

// REGIME THRESHOLDS, PROFILES, AND KNOB COMPUTATION LIVE IN tuning.rs
// (ZERO BPF DEPENDENCIES, TESTABLE OFFLINE)

// REFLEX PARAMETERS

const COOLDOWN_CHECKS: u32   = 2;
const MIN_SLICE_NS: u64      = 500_000;   // 500US FLOOR -- ALLOWS 5 TIGHTEN STEPS FROM 2MS BASELINE

// GRADUATED RELAX: STEP TOWARD BASELINE AFTER P99 NORMALIZES
const RELAX_STEP_NS: u64    = 500_000;   // RELAX BY 500US PER TICK
const RELAX_HOLD_TICKS: u32 = 2;         // WAIT 2S OF GOOD P99 BEFORE STEPPING

// LOCK-FREE LATENCY HISTOGRAM

// SLEEP PATTERN BUCKETS: CLASSIFY IO-WAIT VS IDLE WORKLOADS
const SLEEP_BUCKETS: usize = 4;
const SLEEP_EDGES_NS: [u64; SLEEP_BUCKETS] = [
    1_000_000,      // 1ms: IO-WAIT (FAST DISK/NETWORK/PIPE)
    10_000_000,     // 10ms: SHORT IO (TYPICAL DISK READ)
    100_000_000,    // 100ms: MODERATE (NETWORK, USER INPUT)
    u64::MAX,       // +INF: IDLE (LONG SLEEP, TIMER, POLLING)
];

// TYPES

#[repr(C)]
struct WakeLatSample {
    lat_ns:   u64,
    sleep_ns: u64,    // HOW LONG TASK SLEPT BEFORE THIS WAKEUP
    pid:      u32,
    path:     u8,     // 0=IDLE, 1=HARD_KICK, 2=SOFT_KICK
    tier:     u8,     // TASK TIER AT WAKEUP TIME
    _pad:     [u8; 2],
}

// SHARED STATE (ATOMICS ONLY, NO MUTEX)

const ATOMIC_ZERO: AtomicU64 = AtomicU64::new(0);

pub struct SharedState {
    pub p99_ns: AtomicU64,
    regime: AtomicU8,
    sample_count: AtomicU64,
    histogram: [AtomicU64; HIST_BUCKETS],
    tier_histogram: [[AtomicU64; HIST_BUCKETS]; 3],
    pub tier_p99_ns: [AtomicU64; 3],
    sleep_histogram: [AtomicU64; SLEEP_BUCKETS],
    sleep_count: AtomicU64,
    pub reflex_events: AtomicU64,
    pub samples_per_check: AtomicU32,
}

impl SharedState {
    pub fn new() -> Self {
        Self {
            p99_ns: AtomicU64::new(0),
            regime: AtomicU8::new(Regime::Mixed as u8),
            sample_count: AtomicU64::new(0),
            histogram: [ATOMIC_ZERO; HIST_BUCKETS],
            tier_histogram: [
                [ATOMIC_ZERO; HIST_BUCKETS],
                [ATOMIC_ZERO; HIST_BUCKETS],
                [ATOMIC_ZERO; HIST_BUCKETS],
            ],
            tier_p99_ns: [ATOMIC_ZERO; 3],
            sleep_histogram: [ATOMIC_ZERO; SLEEP_BUCKETS],
            sleep_count: AtomicU64::new(0),
            reflex_events: AtomicU64::new(0),
            samples_per_check: AtomicU32::new(tuning::MIXED_SAMPLES_PER_CHECK),
        }
    }

    fn record_sample(&self, lat_ns: u64, tier: u8) {
        let bucket = HIST_EDGES_NS.iter()
            .position(|&edge| lat_ns <= edge)
            .unwrap_or(HIST_BUCKETS - 1);
        self.histogram[bucket].fetch_add(1, Ordering::Relaxed);
        self.sample_count.fetch_add(1, Ordering::Relaxed);
        let tier_idx = (tier as usize).min(2);
        self.tier_histogram[tier_idx][bucket].fetch_add(1, Ordering::Relaxed);
    }

    // DRAIN HISTOGRAM, COMPUTE P99, STORE IN ATOMIC. RETURNS P99 IN NANOSECONDS.
    fn compute_and_reset_p99(&self) -> u64 {
        let mut counts = [0u64; HIST_BUCKETS];
        for i in 0..HIST_BUCKETS {
            counts[i] = self.histogram[i].swap(0, Ordering::Relaxed);
        }
        self.sample_count.store(0, Ordering::Relaxed);
        let p99 = tuning::compute_p99_from_histogram(&counts);
        self.p99_ns.store(p99, Ordering::Relaxed);
        p99
    }

    // DRAIN PER-TIER HISTOGRAMS, COMPUTE P99 FOR EACH TIER.
    // [0]=BATCH, [1]=INTERACTIVE, [2]=LAT_CRITICAL
    fn compute_and_reset_tier_p99(&self) -> [u64; 3] {
        let mut result = [0u64; 3];
        for tier in 0..3 {
            let mut counts = [0u64; HIST_BUCKETS];
            for i in 0..HIST_BUCKETS {
                counts[i] = self.tier_histogram[tier][i].swap(0, Ordering::Relaxed);
            }
            let p99 = tuning::compute_p99_from_histogram(&counts);
            self.tier_p99_ns[tier].store(p99, Ordering::Relaxed);
            result[tier] = p99;
        }
        result
    }

    fn record_sleep(&self, sleep_ns: u64) {
        let bucket = SLEEP_EDGES_NS.iter()
            .position(|&edge| sleep_ns <= edge)
            .unwrap_or(SLEEP_BUCKETS - 1);
        self.sleep_histogram[bucket].fetch_add(1, Ordering::Relaxed);
        self.sleep_count.fetch_add(1, Ordering::Relaxed);
    }

    // DRAIN SLEEP HISTOGRAM. RETURNS (IO_WAIT_PCT, IDLE_PCT).
    // IO_WAIT = SLEEPS < 10MS, IDLE = SLEEPS > 100MS.
    fn compute_and_reset_sleep(&self) -> (u64, u64) {
        let mut counts = [0u64; SLEEP_BUCKETS];
        let mut total = 0u64;
        for i in 0..SLEEP_BUCKETS {
            counts[i] = self.sleep_histogram[i].swap(0, Ordering::Relaxed);
            total += counts[i];
        }
        self.sleep_count.store(0, Ordering::Relaxed);

        if total == 0 {
            return (0, 0);
        }

        let io_count = counts[0] + counts[1]; // <10MS
        let idle_count = counts[3]; // >100MS
        (io_count * 100 / total, idle_count * 100 / total)
    }

    fn current_regime(&self) -> Regime {
        Regime::from_u8(self.regime.load(Ordering::Relaxed))
    }

    fn set_regime(&self, r: Regime) {
        self.regime.store(r as u8, Ordering::Relaxed);
    }
}

// RING BUFFER BUILDER

// BUILD A RingBuffer FROM THE BPF WAKE LATENCY MAP.
// THE CALLBACK RECORDS EVERY SAMPLE INTO THE SHARED HISTOGRAM.
// THE RETURNED RingBuffer OWNS THE FD INTERNALLY -- SAFE TO MOVE TO THREAD.
pub fn build_ring_buffer(
    sched: &Scheduler,
    shared: Arc<SharedState>,
) -> Result<libbpf_rs::RingBuffer<'static>> {
    sched.build_wake_lat_ring_buffer(move |data: &[u8]| -> i32 {
        if data.len() >= std::mem::size_of::<WakeLatSample>() {
            let sample: WakeLatSample = unsafe {
                std::ptr::read_unaligned(data.as_ptr() as *const WakeLatSample)
            };
            shared.record_sample(sample.lat_ns, sample.tier);
            if sample.sleep_ns > 0 {
                shared.record_sleep(sample.sleep_ns);
            }
        }
        0
    })
}

// REFLEX THREAD

// RING BUFFER CONSUMER. BLOCKS ON poll(), RECORDS SAMPLES, TIGHTENS KNOBS
// WHEN P99 EXCEEDS THE CURRENT REGIME'S CEILING.
// FIXED 25% CUT PER TRIGGER -- SIMPLE AND STABLE.
pub fn reflex_thread(
    ring_buf: libbpf_rs::RingBuffer<'static>,
    shared: Arc<SharedState>,
    knobs_handle: libbpf_rs::MapHandle,
    shutdown: &'static AtomicBool,
) {
    let mut cooldown: u32 = 0;
    let mut spike_count: u32 = 0;

    while !shutdown.load(Ordering::Relaxed) {
        // BLOCK FOR UP TO 100MS (SO WE CHECK SHUTDOWN PERIODICALLY)
        let _ = ring_buf.poll(Duration::from_millis(100));

        // CHECK IF ENOUGH SAMPLES ACCUMULATED FOR A P99 COMPUTATION
        let count = shared.sample_count.load(Ordering::Relaxed);
        let threshold = shared.samples_per_check.load(Ordering::Relaxed) as u64;
        if count < threshold {
            continue;
        }

        let p99 = shared.compute_and_reset_p99();
        let tier_p99 = shared.compute_and_reset_tier_p99();

        if cooldown > 0 {
            cooldown -= 1;
            continue;
        }

        let current_regime = shared.current_regime();
        let ceiling = current_regime.p99_ceiling();
        let interactive_p99 = tier_p99[1];
        if tuning::should_reflex_tighten(p99, interactive_p99, ceiling) {
            spike_count += 1;
            // REQUIRE 2 CONSECUTIVE ABOVE-CEILING CHECKS BEFORE TIGHTENING.
            // FILTERS TRANSIENT NOISE THAT CAUSES FALSE TRIGGERS AT LOW CORE COUNTS.
            if spike_count >= 2 {
                // ONLY TIGHTEN IN MIXED. LIGHT HAS NO CONTENTION
                // (POINTLESS). HEAVY IS FULLY SATURATED (MORE PREEMPTION
                // JUST ADDS OVERHEAD). MIXED IS THE ONLY REGIME WHERE
                // SHORTER SLICES COULD PLAUSIBLY HELP INTERACTIVE TASKS.
                if current_regime == Regime::Mixed {
                    tighten_knobs(&knobs_handle);
                    shared.reflex_events.fetch_add(1, Ordering::Relaxed);
                }
                cooldown = COOLDOWN_CHECKS;
                spike_count = 0;
            }
        } else {
            spike_count = 0;
        }
    }
}

fn tighten_knobs(handle: &libbpf_rs::MapHandle) {
    let key = 0u32.to_ne_bytes();
    let current = match handle.lookup(&key, libbpf_rs::MapFlags::ANY) {
        Ok(Some(v)) if v.len() >= std::mem::size_of::<TuningKnobs>() => unsafe {
            std::ptr::read_unaligned(v.as_ptr() as *const TuningKnobs)
        },
        _ => return,
    };

    let new_slice = (current.slice_ns * 3 / 4).max(MIN_SLICE_NS);
    // ONLY TIGHTEN SLICE + PREEMPT. ALL OTHER KNOBS PRESERVED.
    let knobs = TuningKnobs {
        slice_ns: new_slice,
        preempt_thresh_ns: new_slice,
        ..current
    };

    let value = unsafe {
        std::slice::from_raw_parts(
            &knobs as *const TuningKnobs as *const u8,
            std::mem::size_of::<TuningKnobs>(),
        )
    };
    let _ = handle.update(&key, value, libbpf_rs::MapFlags::ANY);
}

// MONITOR LOOP

// 1-SECOND CONTROL LOOP. READS STATS, DETECTS WORKLOAD REGIME,
// SETS BASELINE KNOBS, RELAXES GRADUALLY AFTER P99 NORMALIZES.
// RUNS ON THE MAIN THREAD. REPLACES THE OLD Scheduler::run().
pub fn monitor_loop(
    sched: &mut Scheduler,
    shared: &Arc<SharedState>,
    shutdown: &'static AtomicBool,
    verbose: bool,
) -> Result<bool> {
    let mut prev = PandemoniumStats::default();
    let mut regime = Regime::Mixed;
    let mut relax_counter: u32 = 0;
    let mut tightened = false;
    let mut pending_regime = regime;
    let mut regime_hold: u32 = 0;
    let mut light_ticks: u64 = 0;
    let mut mixed_ticks: u64 = 0;
    let mut heavy_ticks: u64 = 0;
    let mut stability_score: u32 = 0;
    let mut prev_reflex_events: u64 = 0;
    let mut tick_counter: u64 = 0;

    let mut procdb = match ProcessDb::new() {
        Ok(db) => Some(db),
        Err(e) => {
            log_warn!("PROCDB INIT FAILED: {}", e);
            None
        }
    };

    // APPLY INITIAL REGIME
    shared.set_regime(regime);
    sched.write_tuning_knobs(&regime_knobs(regime))?;

    while !shutdown.load(Ordering::Relaxed) && !sched.exited() {
        std::thread::sleep(Duration::from_secs(1));

        let stats = sched.read_stats();

        // COMPUTE DELTAS
        let delta_d = stats.nr_dispatches.wrapping_sub(prev.nr_dispatches);
        let delta_idle = stats.nr_idle_hits.wrapping_sub(prev.nr_idle_hits);
        let delta_shared = stats.nr_shared.wrapping_sub(prev.nr_shared);
        let delta_preempt = stats.nr_preempt.wrapping_sub(prev.nr_preempt);
        let delta_keep = stats.nr_keep_running.wrapping_sub(prev.nr_keep_running);
        let delta_wake_sum = stats.wake_lat_sum.wrapping_sub(prev.wake_lat_sum);
        let delta_wake_samples = stats.wake_lat_samples.wrapping_sub(prev.wake_lat_samples);
        let delta_hard = stats.nr_hard_kicks.wrapping_sub(prev.nr_hard_kicks);
        let delta_soft = stats.nr_soft_kicks.wrapping_sub(prev.nr_soft_kicks);
        let delta_enq_wake = stats.nr_enq_wakeup.wrapping_sub(prev.nr_enq_wakeup);
        let delta_enq_requeue = stats.nr_enq_requeue.wrapping_sub(prev.nr_enq_requeue);
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
        let lat_idle_us = if d_idle_cnt > 0 { d_idle_sum / d_idle_cnt / 1000 } else { 0 };
        let lat_kick_us = if d_kick_cnt > 0 { d_kick_sum / d_kick_cnt / 1000 } else { 0 };
        let delta_guard = stats.nr_guard_clamps.wrapping_sub(prev.nr_guard_clamps);

        // L2 CACHE AFFINITY DELTAS
        let dl2_hb = stats.nr_l2_hit_batch.wrapping_sub(prev.nr_l2_hit_batch);
        let dl2_mb = stats.nr_l2_miss_batch.wrapping_sub(prev.nr_l2_miss_batch);
        let dl2_hi = stats.nr_l2_hit_interactive.wrapping_sub(prev.nr_l2_hit_interactive);
        let dl2_mi = stats.nr_l2_miss_interactive.wrapping_sub(prev.nr_l2_miss_interactive);
        let dl2_hl = stats.nr_l2_hit_lat_crit.wrapping_sub(prev.nr_l2_hit_lat_crit);
        let dl2_ml = stats.nr_l2_miss_lat_crit.wrapping_sub(prev.nr_l2_miss_lat_crit);
        let l2_pct_b = if dl2_hb + dl2_mb > 0 { dl2_hb * 100 / (dl2_hb + dl2_mb) } else { 0 };
        let l2_pct_i = if dl2_hi + dl2_mi > 0 { dl2_hi * 100 / (dl2_hi + dl2_mi) } else { 0 };
        let l2_pct_l = if dl2_hl + dl2_ml > 0 { dl2_hl * 100 / (dl2_hl + dl2_ml) } else { 0 };

        let idle_pct = if delta_d > 0 {
            delta_idle * 100 / delta_d
        } else {
            0
        };

        // DETECT REGIME (SCHMITT TRIGGER + 2-TICK HOLD)
        let detected = detect_regime(regime, idle_pct);

        let p99_ns = shared.p99_ns.load(Ordering::Relaxed);

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
                shared.set_regime(regime);
                sched.write_tuning_knobs(&regime_knobs(regime))?;
                regime_changed_this_tick = true;
                tightened = false;
                relax_counter = 0;
            }
        } else {
            pending_regime = regime;
            regime_hold = 0;
        }

        if tightened {
            // GRADUATED RELAX: STEP SLICE TOWARD BASELINE (BATCH UNTOUCHED)
            let ceiling = regime.p99_ceiling();
            let baseline = regime_knobs(regime);
            if p99_ns <= ceiling {
                relax_counter += 1;
                if relax_counter >= RELAX_HOLD_TICKS {
                    let current = sched.read_tuning_knobs();
                    if current.slice_ns < baseline.slice_ns {
                        let new_slice = (current.slice_ns + RELAX_STEP_NS)
                            .min(baseline.slice_ns);
                        let knobs = TuningKnobs {
                            slice_ns: new_slice,
                            preempt_thresh_ns: baseline.preempt_thresh_ns
                                .min(new_slice),
                            batch_slice_ns: current.batch_slice_ns,
                            ..baseline
                        };
                        sched.write_tuning_knobs(&knobs)?;
                        if new_slice >= baseline.slice_ns {
                            tightened = false;
                        }
                    } else {
                        tightened = false;
                    }
                    relax_counter = 0;
                }
            } else {
                relax_counter = 0;
            }
        }

        // DETECT IF REFLEX THREAD TIGHTENED KNOBS
        if !tightened {
            let current = sched.read_tuning_knobs();
            let baseline = regime_knobs(regime);
            if current.slice_ns < baseline.slice_ns {
                tightened = true;
                relax_counter = 0;
            }
        }

        // SLEEP PATTERN ANALYSIS: IO-WAIT VS IDLE CLASSIFICATION
        let (io_pct, _idle_sleep_pct) = shared.compute_and_reset_sleep();

        // STABILITY TRACKING: HIBERNATE REFLEX THREAD WHEN STABLE
        let reflex_now = shared.reflex_events.load(Ordering::Relaxed);
        let reflex_delta = reflex_now.wrapping_sub(prev_reflex_events);
        prev_reflex_events = reflex_now;
        stability_score = tuning::compute_stability_score(
            stability_score,
            regime_changed_this_tick,
            delta_guard,
            reflex_delta,
            p99_ns,
            regime.p99_ceiling(),
        );
        let new_spc = tuning::hibernate_samples_per_check(regime, stability_score);
        shared.samples_per_check.store(new_spc, Ordering::Relaxed);

        // PROCESS CLASSIFICATION DATABASE: INGEST, PREDICT, EVICT
        let (db_total, db_confident) = if let Some(ref mut db) = procdb {
            db.ingest();
            db.flush_predictions();
            db.tick();
            db.summary()
        } else {
            (0, 0)
        };

        let p99_us = p99_ns / 1000;
        let tp99_b = shared.tier_p99_ns[0].load(Ordering::Relaxed) / 1000;
        let tp99_i = shared.tier_p99_ns[1].load(Ordering::Relaxed) / 1000;
        let tp99_l = shared.tier_p99_ns[2].load(Ordering::Relaxed) / 1000;
        let knobs = sched.read_tuning_knobs();

        if verbose && tuning::should_print_telemetry(tick_counter, stability_score) {
            println!(
                "d/s: {:<8} idle: {}% shared: {:<6} preempt: {:<4} keep: {:<4} kick: H={:<4} S={:<4} enq: W={:<4} R={:<4} wake: {}us p99: {}us [B:{} I:{} L:{}] lat_idle: {}us lat_kick: {}us procdb: {}/{} sleep: io={}% slice: {}us batch: {}us guard: {} l2: B={}% I={}% L={}% [{}]",
                delta_d, idle_pct, delta_shared, delta_preempt, delta_keep,
                delta_hard, delta_soft, delta_enq_wake, delta_enq_requeue,
                wake_avg_us, p99_us, tp99_b, tp99_i, tp99_l,
                lat_idle_us, lat_kick_us,
                db_total, db_confident,
                io_pct, knobs.slice_ns / 1000, knobs.batch_slice_ns / 1000,
                delta_guard,
                l2_pct_b, l2_pct_i, l2_pct_l, regime.label(),
            );
        }

        sched.log.snapshot(
            delta_d, delta_idle, delta_shared,
            delta_preempt, delta_keep, wake_avg_us,
            delta_hard, delta_soft, lat_idle_us, lat_kick_us,
        );

        match regime {
            Regime::Light => light_ticks += 1,
            Regime::Mixed => mixed_ticks += 1,
            Regime::Heavy => heavy_ticks += 1,
        }

        tick_counter += 1;
        prev = stats;
    }

    // PROCDB: SAVE LEARNED CLASSIFICATIONS TO DISK
    if let Some(ref db) = procdb {
        let path = ProcessDb::default_path();
        match db.save(&path) {
            Ok(()) => {
                let (total, confident) = db.summary();
                log_info!("PROCDB: SAVED {}/{} PROFILES TO {}", confident, total, path.display());
            }
            Err(e) => log_warn!("PROCDB SAVE FAILED: {}", e),
        }
    }

    // KNOBS SUMMARY: CAPTURED BY TEST HARNESS FOR ARCHIVE
    let final_knobs = sched.read_tuning_knobs();
    let reflex_count = shared.reflex_events.load(Ordering::Relaxed);
    let final_stats = sched.read_stats();
    let l2_total_b = final_stats.nr_l2_hit_batch + final_stats.nr_l2_miss_batch;
    let l2_total_i = final_stats.nr_l2_hit_interactive + final_stats.nr_l2_miss_interactive;
    let l2_total_l = final_stats.nr_l2_hit_lat_crit + final_stats.nr_l2_miss_lat_crit;
    let l2_cum_b = if l2_total_b > 0 { final_stats.nr_l2_hit_batch * 100 / l2_total_b } else { 0 };
    let l2_cum_i = if l2_total_i > 0 { final_stats.nr_l2_hit_interactive * 100 / l2_total_i } else { 0 };
    let l2_cum_l = if l2_total_l > 0 { final_stats.nr_l2_hit_lat_crit * 100 / l2_total_l } else { 0 };
    println!(
        "[KNOBS] regime={} slice_ns={} batch_ns={} preempt_ns={} demotion_ns={} lag={} tightened={} reflex={} ticks=L:{}/M:{}/H:{} l2_hit=B:{}%/I:{}%/L:{}%",
        regime.label(), final_knobs.slice_ns, final_knobs.batch_slice_ns,
        final_knobs.preempt_thresh_ns, final_knobs.cpu_bound_thresh_ns,
        final_knobs.lag_scale, tightened, reflex_count,
        light_ticks, mixed_ticks, heavy_ticks,
        l2_cum_b, l2_cum_i, l2_cum_l,
    );

    // READ UEI EXIT REASON
    let should_restart = sched.read_exit_info();
    Ok(should_restart)
}
