// SPDX-License-Identifier: GPL-2.0
// ETD for scx_cake - measures inter-core latency via CAS ping-pong (adapted from nviennot/core-to-core-latency)

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Barrier};

use log::{debug, info};
use quanta::Clock;

/// Cache-line padded atomic to avoid false sharing
#[repr(align(64))]
struct PaddedAtomicBool {
    val: AtomicBool,
    _pad: [u8; 63],
}

impl PaddedAtomicBool {
    fn new(v: bool) -> Self {
        Self {
            val: AtomicBool::new(v),
            _pad: [0u8; 63],
        }
    }
}

/// Shared state for two-buffer ping-pong (avoids SMT contention)
struct SharedState {
    barrier: Barrier,
    flag: PaddedAtomicBool,
}

const PING: bool = false;
const PONG: bool = true;

/// Configuration for ETD calibration
pub struct EtdConfig {
    /// Number of round-trips per sample
    pub iterations: u32,
    /// Number of samples to collect
    pub samples: u32,
    /// Warmup iterations to stabilize boost clocks (discarded)
    pub warmup: u32,
    /// Maximum acceptable standard deviation (ns) - samples exceeding this trigger retry
    pub max_stddev: f64,
}

impl Default for EtdConfig {
    fn default() -> Self {
        Self {
            // Display-grade: 500 iterations @ 50 samples (sufficient for heatmap accuracy)
            iterations: 500,
            samples: 50,
            // 200 warmup iters to stabilize boost clocks
            warmup: 200,
            // Discard samples with σ > 15ns (relaxed for faster calibration)
            max_stddev: 15.0,
        }
    }
}

/// Measure round-trip latency between two CPUs using CAS ping-pong. Returns per-sample latencies (ns).
fn measure_pair(cpu_a: usize, cpu_b: usize, config: &EtdConfig) -> Option<Vec<f64>> {
    let state = Arc::new(SharedState {
        barrier: Barrier::new(2),
        flag: PaddedAtomicBool::new(PING),
    });

    let clock = Arc::new(Clock::new());
    let num_round_trips = config.iterations as usize;
    let num_samples = config.samples as usize;
    let warmup_trips = config.warmup as usize;

    let state_pong = Arc::clone(&state);
    let state_ping = Arc::clone(&state);
    let clock_ping = Arc::clone(&clock);

    crossbeam_utils::thread::scope(|s| {
        // PONG thread: waits for PING, sets to PONG
        let pong = s.spawn(move |_| {
            let core_id = core_affinity::CoreId { id: cpu_b };
            if !core_affinity::set_for_current(core_id) {
                return;
            }

            // Set real-time priority to minimize preemption jitter
            unsafe {
                let param = libc::sched_param { sched_priority: 99 };
                libc::sched_setscheduler(0, libc::SCHED_FIFO, &param);
            }

            state_pong.barrier.wait();

            // Warmup phase (not timed, stabilizes boost clocks)
            for _ in 0..warmup_trips {
                while state_pong
                    .flag
                    .val
                    .compare_exchange(PING, PONG, Ordering::AcqRel, Ordering::Relaxed)
                    .is_err()
                {
                    std::hint::spin_loop();
                }
            }

            // Measurement phase
            for _ in 0..(num_round_trips * num_samples) {
                while state_pong
                    .flag
                    .val
                    .compare_exchange(PING, PONG, Ordering::AcqRel, Ordering::Relaxed)
                    .is_err()
                {
                    std::hint::spin_loop();
                }
            }

            // Reset to normal priority before thread exit
            unsafe {
                let param = libc::sched_param { sched_priority: 0 };
                libc::sched_setscheduler(0, libc::SCHED_OTHER, &param);
            }
        });

        // PING thread: sets to PING, waits for PONG, measures time
        let ping = s.spawn(move |_| {
            let core_id = core_affinity::CoreId { id: cpu_a };
            if !core_affinity::set_for_current(core_id) {
                return None;
            }

            // Set real-time priority to minimize preemption jitter
            unsafe {
                let param = libc::sched_param { sched_priority: 99 };
                libc::sched_setscheduler(0, libc::SCHED_FIFO, &param);
            }

            let mut results = Vec::with_capacity(num_samples);

            state_ping.barrier.wait();

            // Warmup phase (not timed, stabilizes boost clocks)
            for _ in 0..warmup_trips {
                while state_ping
                    .flag
                    .val
                    .compare_exchange(PONG, PING, Ordering::AcqRel, Ordering::Relaxed)
                    .is_err()
                {
                    std::hint::spin_loop();
                }
            }

            // Measurement phase
            for _ in 0..num_samples {
                let start = clock_ping.raw();

                for _ in 0..num_round_trips {
                    while state_ping
                        .flag
                        .val
                        .compare_exchange(PONG, PING, Ordering::AcqRel, Ordering::Relaxed)
                        .is_err()
                    {
                        std::hint::spin_loop();
                    }
                }

                let end = clock_ping.raw();
                let duration_ns = clock_ping.delta(start, end).as_nanos() as f64;
                // One-way latency = total time / (round_trips * 2 hops)
                results.push(duration_ns / (num_round_trips as f64 * 2.0));
            }

            // Reset to normal priority before thread exit
            unsafe {
                let param = libc::sched_param { sched_priority: 0 };
                libc::sched_setscheduler(0, libc::SCHED_OTHER, &param);
            }

            Some(results)
        });

        pong.join().unwrap();
        ping.join().unwrap()
    })
    .ok()?
}

/// Perform full topology calibration. Returns matrix[i][j] = latency from CPU i to CPU j.
pub fn calibrate_full_matrix<F>(
    nr_cpus: usize,
    config: &EtdConfig,
    mut progress_callback: F,
) -> Vec<Vec<f64>>
where
    F: FnMut(usize, usize, bool),
{
    let mut matrix = vec![vec![0.0; nr_cpus]; nr_cpus];

    info!(
        "ETD: Starting calibration for {} CPUs ({} iterations × {} samples)",
        nr_cpus, config.iterations, config.samples
    );

    let start = std::time::Instant::now();

    // Calculate total pairs to measure
    let total_pairs = (nr_cpus * (nr_cpus - 1)) / 2;
    let mut current_pair = 0;

    #[allow(clippy::needless_range_loop)]
    for cpu_a in 0..nr_cpus {
        for cpu_b in (cpu_a + 1)..nr_cpus {
            current_pair += 1;
            let mut retry_count = 0;
            const MAX_RETRIES: u32 = 3;

            while let Some(samples) = measure_pair(cpu_a, cpu_b, config) {
                if !samples.is_empty() {
                    // Calculate mean and standard deviation
                    let n = samples.len() as f64;
                    let mean = samples.iter().sum::<f64>() / n;
                    let variance = samples.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / n;
                    let stddev = variance.sqrt();

                    // Check if variance is acceptable (no IRQ interference)
                    if stddev <= config.max_stddev || retry_count >= MAX_RETRIES {
                        // Use median for final value (more robust than mean)
                        let mut sorted = samples;
                        sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());
                        let median = sorted[sorted.len() / 2];

                        matrix[cpu_a][cpu_b] = median;
                        matrix[cpu_b][cpu_a] = median;

                        if stddev > config.max_stddev {
                            debug!(
                                "ETD: CPU {}<->{} stddev={:.1}ns (exceeded threshold after {} retries)",
                                cpu_a, cpu_b, stddev, retry_count
                            );
                        }

                        // Report progress (not complete yet)
                        progress_callback(current_pair, total_pairs, false);
                        break;
                    } else {
                        retry_count += 1;
                        debug!(
                            "ETD: CPU {}<->{} stddev={:.1}ns > {:.1}ns, retrying ({}/{})",
                            cpu_a, cpu_b, stddev, config.max_stddev, retry_count, MAX_RETRIES
                        );
                    }
                } else {
                    break; // Empty samples, skip
                }
            }
        }
    }

    // Final progress update to signal completion
    progress_callback(total_pairs, total_pairs, true);

    let elapsed = start.elapsed();
    info!("ETD: Calibration complete in {:.2}s", elapsed.as_secs_f64());

    // Log the matrix for debugging
    debug!("ETD: Latency matrix (ns):");
    for (i, row) in matrix.iter().enumerate() {
        debug!(
            "  CPU {:2}: {:?}",
            i,
            row.iter().map(|v| format!("{:.1}", v)).collect::<Vec<_>>()
        );
    }

    matrix
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_measure_pair_smoke() {
        // Just verify it doesn't panic on a 2-CPU system
        let config = EtdConfig {
            iterations: 100,
            samples: 2,
            warmup: 10,
            max_stddev: 100.0,
        };
        let result = measure_pair(0, 1, &config);
        // Result might be None if pinning fails, that's OK in tests
        if let Some(latencies) = result {
            for latency in &latencies {
                assert!(*latency > 0.0, "Latency should be positive");
                assert!(
                    *latency < 1_000_000.0,
                    "Latency should be reasonable (<1ms)"
                );
            }
        }
    }
}
