// PANDEMONIUM ADAPTIVE CONTROL LOOP
// SINGLE-THREAD CLOSED-LOOP TUNING SYSTEM
//
// ONE THREAD: MONITOR LOOP (1-SECOND CONTROL LOOP)
//   READS BPF PER-CPU HISTOGRAMS FOR P99 COMPUTATION.
//   DETECTS WORKLOAD REGIME VIA SCHMITT TRIGGER.
//   MWU ORCHESTRATOR TUNES ALL 11 KNOBS WITHIN REGIME.
//
// BPF PRODUCES HISTOGRAMS, RUST READS AND REACTS. RUST WRITES KNOBS,
// BPF READS THEM ON THE VERY NEXT SCHEDULING DECISION.

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::Result;

use crate::procdb::ProcessDb;
use crate::scheduler::{PandemoniumStats, Scheduler};
use crate::tuning::{
    self, detect_regime, scaled_regime_knobs, MwuController, MwuSignals, Regime, HIST_BUCKETS,
};

// REGIME THRESHOLDS, PROFILES, AND KNOB COMPUTATION LIVE IN tuning.rs
// (ZERO BPF DEPENDENCIES, TESTABLE OFFLINE)

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
    let mut prev = PandemoniumStats::default();
    let mut prev_hist = [[0u64; HIST_BUCKETS]; 3];
    let mut prev_sleep = [0u64; SLEEP_BUCKETS];
    let mut regime = Regime::Mixed;
    // READ CURRENT tau SNAPSHOT FROM THE BPF-SIDE KNOB MAP. main.rs WROTE IT
    // ONCE AT TOPOLOGY DETECT; THE ADAPTIVE LOOP RE-READS SO TAU-SCALED REGIME
    // KNOBS AGREE WITH TAU-SCALED BPF INIT AT FIRST TICK AND EVERY REGIME CHANGE.
    let mut tau_ns = sched.read_tuning_knobs().topology_tau_ns;
    let mut mwu = MwuController::new(scaled_regime_knobs(regime, nr_cpus, tau_ns));
    let mut pending_regime = regime;
    let mut regime_hold: u32 = 0;
    let mut light_ticks: u64 = 0;
    let mut mixed_ticks: u64 = 0;
    let mut heavy_ticks: u64 = 0;
    let mut stability_score: u32 = 0;
    let mut tick_counter: u64 = 0;

    let mut procdb = match ProcessDb::new() {
        Ok(db) => Some(db),
        Err(e) => {
            log_warn!("PROCDB INIT FAILED: {}", e);
            None
        }
    };

    // APPLY INITIAL REGIME. scaled_regime_knobs RETURNS topology_tau_ns/codel_eq_ns=0;
    // OVERLAY THE LIVE BPF VALUES SO THE FIRST WRITE DOESN'T CLOBBER WHAT
    // write_topology_fields() PUT IN THE MAP. Mirrors the regime-change path at line 230.
    let live = sched.read_tuning_knobs();
    let mut rk = scaled_regime_knobs(regime, nr_cpus, tau_ns);
    rk.topology_tau_ns = tau_ns;
    rk.codel_eq_ns = live.codel_eq_ns;
    sched.write_tuning_knobs(&rk)?;

    while !shutdown.load(Ordering::Relaxed) && !sched.exited() {
        crate::watchdog::LOOP_HEARTBEAT.fetch_add(1, Ordering::Relaxed);
        std::thread::sleep(Duration::from_secs(1));

        let stats = sched.read_stats();
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
        let delta_wake_sum = stats.wake_lat_sum.wrapping_sub(prev.wake_lat_sum);
        let delta_wake_samples = stats.wake_lat_samples.wrapping_sub(prev.wake_lat_samples);
        let delta_hard = stats.nr_hard_kicks.wrapping_sub(prev.nr_hard_kicks);
        let delta_soft = stats.nr_soft_kicks.wrapping_sub(prev.nr_soft_kicks);
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
                // REFRESH tau IN CASE HOTPLUG/TOPOLOGY CHANGED.
                // scaled_regime_knobs RETURNS topology_tau_ns/codel_eq_ns=0;
                // OVERLAY THE LIVE BPF VALUES (BOTH OWNED BY TOPOLOGY LAYER).
                let live = sched.read_tuning_knobs();
                tau_ns = live.topology_tau_ns;
                let mut rk = scaled_regime_knobs(regime, nr_cpus, tau_ns);
                rk.topology_tau_ns = tau_ns;
                rk.codel_eq_ns = live.codel_eq_ns;
                sched.write_tuning_knobs(&rk)?;
                regime_changed_this_tick = true;
                mwu.set_baseline(rk);
                mwu.reset();
            }
        } else {
            pending_regime = regime;
            regime_hold = 0;
        }

        // MWU ORCHESTRATOR: UNIFIED KNOB CONTROL
        // REPLACES: TIGHTEN/RELAX, SLEEP-INFORMED BATCH, SOJOURN EWMA, LONGRUN OVERRIDE
        if !regime_changed_this_tick {
            let signals = MwuSignals {
                p99_ns,
                interactive_p99_ns: tp99_i_ns,
                io_pct,
                rescue_count: delta_rescue,
                // RAW total wakes/sec; the MWU fork-storm gate compares against
                // a tau-derived total threshold (scale_tau_u64 * K_FORK_STORM_RATE).
                // Per-CPU normalization here re-introduced an nr_cpus^2 effective
                // threshold and latched on quiet 2-4C systems.
                wakeup_rate: delta_enq_wake,
            };
            // OSCILLATOR-AWARE GATING: READ THE BPF DAMPED-HARMONIC
            // OSCILLATOR'S CURRENT STATE BEFORE MWU DECIDES. PATHWAYS
            // 2 AND 4 (RESCUE-DRIVEN) DEFER WHEN THE OSCILLATOR HAS
            // ALREADY MOVED. WITHOUT THIS, MWU AND THE OSCILLATOR
            // INDEPENDENTLY ADAPT ON global_rescue_count AND THE TWO
            // CONTROLLERS DOUBLE-CORRECT.
            let osc_state = sched.read_oscillator_state();
            let mut knobs = mwu.update(&signals, regime.p99_ceiling(), nr_cpus, tau_ns, &osc_state);
            // PRESERVE TOPOLOGY-OWNED FIELDS (tau_ns, codel_eq_ns) -- MWU
            // DOESN'T TOUCH THEM. WITHOUT THIS, THE ADAPTIVE LOOP'S 1HZ
            // WRITES WOULD CLOBBER VALUES main.rs SET AT TOPOLOGY DETECT.
            let live = sched.read_tuning_knobs();
            knobs.topology_tau_ns = live.topology_tau_ns;
            knobs.codel_eq_ns = live.codel_eq_ns;
            sched.write_tuning_knobs(&knobs)?;
        }

        // STABILITY TRACKING
        let tighten_delta = if mwu.had_losses() { 1u64 } else { 0u64 };
        stability_score = tuning::compute_stability_score(
            stability_score,
            regime_changed_this_tick,
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

        let sojourn_ms = stats.batch_sojourn_ns / 1_000_000;
        let sojourn_thresh_ms = knobs.sojourn_thresh_ns / 1_000_000;
        let longrun_label = if stats.longrun_mode_active > 0 {
            " LONGRUN"
        } else {
            ""
        };

        if verbose && tuning::should_print_telemetry(tick_counter, stability_score) {
            println!(
                "d/s: {:<8} idle: {}% shared: {:<6} preempt: {:<4} keep: {:<4} kick: H={:<4} S={:<4} enq: W={:<4} R={:<4} wake: {}us p99: {}us [B:{} I:{} L:{}] lat_idle: {}us lat_kick: {}us procdb: {}/{} sleep: io={}% slice: {}us batch: {}us reenq: {} sjrn: {}ms/{}ms rescue: {} l2: B={}% I={}% L={}% [{}{}]",
                delta_d, idle_pct, delta_shared, delta_preempt, delta_keep,
                delta_hard, delta_soft, delta_enq_wake, delta_enq_requeue,
                wake_avg_us, p99_us, tp99_b, tp99_i, tp99_l,
                lat_idle_us, lat_kick_us,
                db_total, db_confident,
                io_pct, knobs.slice_ns / 1000, knobs.batch_slice_ns / 1000,
                delta_reenq, sojourn_ms, sojourn_thresh_ms,
                delta_rescue,
                l2_pct_b, l2_pct_i, l2_pct_l, regime.label(), longrun_label,
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
        "[KNOBS] regime={} slice_ns={} batch_ns={} preempt_ns={} lag={} mwu={:.3} ticks=L:{}/M:{}/H:{} l2_hit=B:{}%/I:{}%/L:{}%",
        regime.label(), final_knobs.slice_ns, final_knobs.batch_slice_ns,
        final_knobs.preempt_thresh_ns,
        final_knobs.lag_scale, mwu.scale(),
        light_ticks, mixed_ticks, heavy_ticks,
        l2_cum_b, l2_cum_i, l2_cum_l,
    );

    // READ UEI EXIT REASON
    let should_restart = sched.read_exit_info();
    Ok(should_restart)
}
