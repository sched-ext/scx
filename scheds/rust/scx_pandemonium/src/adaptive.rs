// PANDEMONIUM ADAPTIVE CONTROL LOOP
// SINGLE-THREAD CLOSED-LOOP TUNING SYSTEM
//
// ONE THREAD: MONITOR LOOP (1-SECOND CONTROL LOOP)
//   READS BPF PER-CPU HISTOGRAMS FOR P99 COMPUTATION.
//   DETECTS WORKLOAD REGIME. SETS BASELINE KNOBS.
//   TIGHTENS ON P99 SPIKES. RELAXES GRADUALLY AFTER P99 NORMALIZES.
//
// BPF PRODUCES HISTOGRAMS, RUST READS AND REACTS. RUST WRITES KNOBS,
// BPF READS THEM ON THE VERY NEXT SCHEDULING DECISION.

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::Result;

use crate::procdb::ProcessDb;
use crate::scheduler::{PandemoniumStats, Scheduler};
use crate::tuning::{self, detect_regime, regime_knobs, Regime, TuningKnobs, HIST_BUCKETS};

// REGIME THRESHOLDS, PROFILES, AND KNOB COMPUTATION LIVE IN tuning.rs
// (ZERO BPF DEPENDENCIES, TESTABLE OFFLINE)

// TIGHTEN PARAMETERS

const MIN_SLICE_NS: u64 = 500_000; // 500US FLOOR

// GRADUATED RELAX: STEP TOWARD BASELINE AFTER P99 NORMALIZES
const RELAX_STEP_NS: u64 = 500_000; // RELAX BY 500US PER TICK
const RELAX_HOLD_TICKS: u32 = 2; // WAIT 2S OF GOOD P99 BEFORE STEPPING

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
) -> Result<bool> {
    let mut prev = PandemoniumStats::default();
    let mut prev_hist = [[0u64; HIST_BUCKETS]; 3];
    let mut prev_sleep = [0u64; SLEEP_BUCKETS];
    let mut regime = Regime::Mixed;
    let mut relax_counter: u32 = 0;
    let mut tightened = false;
    let mut pending_regime = regime;
    let mut regime_hold: u32 = 0;
    let mut light_ticks: u64 = 0;
    let mut mixed_ticks: u64 = 0;
    let mut heavy_ticks: u64 = 0;
    let mut stability_score: u32 = 0;
    let mut spike_count: u32 = 0;
    let mut tick_counter: u64 = 0;
    let mut tighten_events: u64 = 0;
    let mut prev_tighten_events: u64 = 0;
    let mut contention_ticks: u32 = 0;

    let mut procdb = match ProcessDb::new() {
        Ok(db) => Some(db),
        Err(e) => {
            log_warn!("PROCDB INIT FAILED: {}", e);
            None
        }
    };

    // APPLY INITIAL REGIME
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
        let delta_guard = stats.nr_guard_clamps.wrapping_sub(prev.nr_guard_clamps);
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

        // READ HISTOGRAMS (CUMULATIVE, COMPUTE DELTAS)
        let cur_hist = sched.read_wake_lat_hist();
        let mut delta_hist = [[0u64; HIST_BUCKETS]; 3];
        for tier in 0..3 {
            for b in 0..HIST_BUCKETS {
                delta_hist[tier][b] = cur_hist[tier][b].wrapping_sub(prev_hist[tier][b]);
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

        // SLEEP HISTOGRAM
        let cur_sleep = sched.read_sleep_hist();
        let mut delta_sleep = [0u64; SLEEP_BUCKETS];
        for i in 0..SLEEP_BUCKETS {
            delta_sleep[i] = cur_sleep[i].wrapping_sub(prev_sleep[i]);
        }
        let sleep_total: u64 = delta_sleep.iter().sum();
        let io_pct = if sleep_total > 0 {
            (delta_sleep[0] + delta_sleep[1]) * 100 / sleep_total
        } else {
            0
        };

        // DETECT REGIME (SCHMITT TRIGGER + 2-TICK HOLD)
        let detected = detect_regime(regime, idle_pct);

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
                sched.write_tuning_knobs(&regime_knobs(regime))?;
                regime_changed_this_tick = true;
                tightened = false;
                relax_counter = 0;
                spike_count = 0;
            }
        } else {
            pending_regime = regime;
            regime_hold = 0;
        }

        // TIGHTEN CHECK: P99 SPIKE DETECTION
        // REQUIRE 2 CONSECUTIVE ABOVE-CEILING TICKS BEFORE TIGHTENING.
        // ONLY TIGHTEN IN MIXED: LIGHT HAS NO CONTENTION (POINTLESS),
        // HEAVY IS FULLY SATURATED (MORE PREEMPTION JUST ADDS OVERHEAD).
        if !tightened && !regime_changed_this_tick {
            let ceiling = regime.p99_ceiling();
            if tuning::should_reflex_tighten(p99_ns, tp99_i_ns, ceiling) {
                spike_count += 1;
                if spike_count >= 2 && regime == Regime::Mixed {
                    let current = sched.read_tuning_knobs();
                    let new_slice = (current.slice_ns * 3 / 4).max(MIN_SLICE_NS);
                    let knobs = TuningKnobs {
                        slice_ns: new_slice,
                        preempt_thresh_ns: new_slice,
                        ..current
                    };
                    sched.write_tuning_knobs(&knobs)?;
                    tightened = true;
                    tighten_events += 1;
                    spike_count = 0;
                }
            } else {
                spike_count = 0;
            }
        }

        // GRADUATED RELAX: STEP SLICE TOWARD BASELINE (BATCH UNTOUCHED)
        if tightened && !regime_changed_this_tick {
            let ceiling = regime.p99_ceiling();
            let baseline = regime_knobs(regime);
            if p99_ns <= ceiling {
                relax_counter += 1;
                if relax_counter >= RELAX_HOLD_TICKS {
                    let current = sched.read_tuning_knobs();
                    if current.slice_ns < baseline.slice_ns {
                        let new_slice = (current.slice_ns + RELAX_STEP_NS).min(baseline.slice_ns);
                        let knobs = TuningKnobs {
                            slice_ns: new_slice,
                            preempt_thresh_ns: baseline.preempt_thresh_ns.min(new_slice),
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

        // SLEEP-INFORMED BATCH TUNING (EVERY TICK)
        let baseline = regime_knobs(regime);
        let sleep_batch = tuning::sleep_adjust_batch_ns(baseline.batch_slice_ns, io_pct);

        // CONTENTION RESPONSE: DETECT AND CUT BATCH WHEN QUEUES ARE DEEP
        let delta_dsq_sum = stats.dsq_depth_sum.wrapping_sub(prev.dsq_depth_sum);
        let delta_dsq_samples = stats.dsq_depth_samples.wrapping_sub(prev.dsq_depth_samples);
        let avg_dsq = if delta_dsq_samples > 0 {
            delta_dsq_sum / delta_dsq_samples
        } else {
            0
        };

        if tuning::detect_contention(delta_guard, delta_hard, delta_d, avg_dsq) {
            contention_ticks += 1;
        } else {
            contention_ticks = 0;
        }

        let (final_batch, new_ct) = tuning::contention_adjust_batch_ns(
            sleep_batch,
            baseline.batch_slice_ns,
            contention_ticks,
        );
        contention_ticks = new_ct;

        {
            let current = sched.read_tuning_knobs();
            if current.batch_slice_ns != final_batch {
                sched.write_tuning_knobs(&TuningKnobs {
                    batch_slice_ns: final_batch,
                    ..current
                })?;
            }
        }

        // STABILITY TRACKING
        let tighten_delta = tighten_events.wrapping_sub(prev_tighten_events);
        prev_tighten_events = tighten_events;
        stability_score = tuning::compute_stability_score(
            stability_score,
            regime_changed_this_tick,
            delta_guard,
            tighten_delta,
            p99_ns,
            regime.p99_ceiling(),
        );

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
        let tp99_b = tp99_b_ns / 1000;
        let tp99_i = tp99_i_ns / 1000;
        let tp99_l = tp99_l_ns / 1000;
        let knobs = sched.read_tuning_knobs();

        if verbose && tuning::should_print_telemetry(tick_counter, stability_score) {
            println!(
                "d/s: {:<8} idle: {}% shared: {:<6} preempt: {:<4} keep: {:<4} kick: H={:<4} S={:<4} enq: W={:<4} R={:<4} wake: {}us p99: {}us [B:{} I:{} L:{}] lat_idle: {}us lat_kick: {}us procdb: {}/{} sleep: io={}% slice: {}us batch: {}us guard: {} reenq: {} l2: B={}% I={}% L={}% [{}]",
                delta_d, idle_pct, delta_shared, delta_preempt, delta_keep,
                delta_hard, delta_soft, delta_enq_wake, delta_enq_requeue,
                wake_avg_us, p99_us, tp99_b, tp99_i, tp99_l,
                lat_idle_us, lat_kick_us,
                db_total, db_confident,
                io_pct, knobs.slice_ns / 1000, knobs.batch_slice_ns / 1000,
                delta_guard, delta_reenq,
                l2_pct_b, l2_pct_i, l2_pct_l, regime.label(),
            );
        }

        sched.log.snapshot(
            delta_d,
            delta_idle,
            delta_shared,
            delta_preempt,
            delta_keep,
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
    }

    // PROCDB: SAVE LEARNED CLASSIFICATIONS TO DISK
    if let Some(ref db) = procdb {
        let path = ProcessDb::default_path();
        match db.save(&path) {
            Ok(()) => {
                let (total, confident) = db.summary();
                log_info!(
                    "PROCDB: SAVED {}/{} PROFILES TO {}",
                    confident,
                    total,
                    path.display()
                );
            }
            Err(e) => log_warn!("PROCDB SAVE FAILED: {}", e),
        }
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
    println!(
        "[KNOBS] regime={} slice_ns={} batch_ns={} preempt_ns={} demotion_ns={} lag={} tightened={} tighten_events={} ticks=L:{}/M:{}/H:{} l2_hit=B:{}%/I:{}%/L:{}%",
        regime.label(), final_knobs.slice_ns, final_knobs.batch_slice_ns,
        final_knobs.preempt_thresh_ns, final_knobs.cpu_bound_thresh_ns,
        final_knobs.lag_scale, tightened, tighten_events,
        light_ticks, mixed_ticks, heavy_ticks,
        l2_cum_b, l2_cum_i, l2_cum_l,
    );

    // READ UEI EXIT REASON
    let should_restart = sched.read_exit_info();
    Ok(should_restart)
}
