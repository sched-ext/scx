// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use super::perfetto_parser::PerfettoTrace;
use perfetto_protos::ftrace_event::ftrace_event;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;

// ============================================================================
// LLC Locality Analyzer
// ============================================================================

/// Analyzes cache locality of scheduling decisions using topology data.
/// Tracks whether wakeups and migrations stay within the same LLC or cross LLC/NUMA boundaries.
pub struct LlcLocalityAnalyzer {
    trace: Arc<PerfettoTrace>,
}

impl LlcLocalityAnalyzer {
    pub fn new(trace: Arc<PerfettoTrace>) -> Self {
        Self { trace }
    }

    /// Analyze LLC locality of migrations.
    /// Returns None if no topology data is available in the trace.
    pub fn analyze(&self) -> Option<LlcLocalityStats> {
        let topology = self.trace.get_topology()?;

        let mut stats = LlcLocalityStats {
            nr_cpus: topology.nr_cpus,
            nr_llcs: topology.nr_llcs,
            nr_numa_nodes: topology.nr_numa_nodes,
            total_migrations: 0,
            same_llc_migrations: 0,
            cross_llc_same_numa_migrations: 0,
            cross_numa_migrations: 0,
            per_llc_stats: HashMap::new(),
            top_cross_llc_processes: Vec::new(),
        };

        // Initialize per-LLC stats
        for llc_id in topology.cpu_to_llc.values() {
            stats.per_llc_stats.entry(*llc_id).or_insert(LlcStats {
                llc_id: *llc_id,
                inbound_migrations: 0,
                outbound_migrations: 0,
                internal_migrations: 0,
            });
        }

        // Track per-process cross-LLC migration counts
        let mut process_cross_llc: HashMap<i32, usize> = HashMap::new();

        // Analyze sched_migrate events
        let migrate_events = self.trace.get_events_by_type("sched_migrate");
        for event in &migrate_events {
            if let Some(ftrace_event::Event::SchedMigrateTask(migrate)) = &event.event {
                let orig_cpu = migrate.orig_cpu.unwrap_or(0) as u32;
                let dest_cpu = migrate.dest_cpu.unwrap_or(0) as u32;
                let pid = migrate.pid.unwrap_or(0);

                stats.total_migrations += 1;

                let orig_llc = topology.cpu_to_llc.get(&orig_cpu).copied();
                let dest_llc = topology.cpu_to_llc.get(&dest_cpu).copied();
                let orig_numa = topology.cpu_to_numa.get(&orig_cpu).copied();
                let dest_numa = topology.cpu_to_numa.get(&dest_cpu).copied();

                match (orig_llc, dest_llc, orig_numa, dest_numa) {
                    (Some(ol), Some(dl), Some(on), Some(dn)) => {
                        if ol == dl {
                            stats.same_llc_migrations += 1;
                            if let Some(llc_stats) = stats.per_llc_stats.get_mut(&ol) {
                                llc_stats.internal_migrations += 1;
                            }
                        } else if on == dn {
                            stats.cross_llc_same_numa_migrations += 1;
                            *process_cross_llc.entry(pid).or_insert(0) += 1;
                            if let Some(llc_stats) = stats.per_llc_stats.get_mut(&ol) {
                                llc_stats.outbound_migrations += 1;
                            }
                            if let Some(llc_stats) = stats.per_llc_stats.get_mut(&dl) {
                                llc_stats.inbound_migrations += 1;
                            }
                        } else {
                            stats.cross_numa_migrations += 1;
                            *process_cross_llc.entry(pid).or_insert(0) += 1;
                            if let Some(llc_stats) = stats.per_llc_stats.get_mut(&ol) {
                                llc_stats.outbound_migrations += 1;
                            }
                            if let Some(llc_stats) = stats.per_llc_stats.get_mut(&dl) {
                                llc_stats.inbound_migrations += 1;
                            }
                        }
                    }
                    _ => {
                        // CPU not in topology map, count as cross-LLC to be safe
                        stats.cross_llc_same_numa_migrations += 1;
                    }
                }
            }
        }

        // Build top cross-LLC processes
        let mut cross_llc_sorted: Vec<_> = process_cross_llc.into_iter().collect();
        cross_llc_sorted.sort_by_key(|b| std::cmp::Reverse(b.1));
        let processes = self.trace.get_processes();
        stats.top_cross_llc_processes = cross_llc_sorted
            .into_iter()
            .take(20)
            .map(|(pid, count)| {
                let comm = processes
                    .get(&pid)
                    .and_then(|p| p.name.clone())
                    .unwrap_or_default();
                ProcessCrossLlcStats {
                    pid,
                    comm,
                    cross_llc_count: count,
                }
            })
            .collect();

        Some(stats)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LlcLocalityStats {
    pub nr_cpus: u32,
    pub nr_llcs: u32,
    pub nr_numa_nodes: u32,
    pub total_migrations: usize,
    pub same_llc_migrations: usize,
    pub cross_llc_same_numa_migrations: usize,
    pub cross_numa_migrations: usize,
    pub per_llc_stats: HashMap<u32, LlcStats>,
    pub top_cross_llc_processes: Vec<ProcessCrossLlcStats>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LlcStats {
    pub llc_id: u32,
    pub inbound_migrations: usize,
    pub outbound_migrations: usize,
    pub internal_migrations: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessCrossLlcStats {
    pub pid: i32,
    pub comm: String,
    pub cross_llc_count: usize,
}

// ============================================================================
// Runqueue Depth Analyzer
// ============================================================================

/// Analyzes runqueue depth over time per CPU.
/// Tracks how many runnable tasks are waiting on each CPU by correlating
/// sched_wakeup (task becomes runnable) and sched_switch (task starts/stops running) events.
pub struct RunqueueDepthAnalyzer {
    trace: Arc<PerfettoTrace>,
}

impl RunqueueDepthAnalyzer {
    pub fn new(trace: Arc<PerfettoTrace>) -> Self {
        Self { trace }
    }

    /// Analyze runqueue depth for all CPUs.
    /// Returns per-CPU statistics about queue depth over the trace duration.
    pub fn analyze(&self, cpu_filter: Option<u32>) -> RunqueueDepthStats {
        let num_cpus = self.trace.num_cpus();
        let mut per_cpu: HashMap<u32, CpuRunqueueStats> = HashMap::new();
        let (trace_start, trace_end) = self.trace.time_range();
        let trace_duration_ns = trace_end.saturating_sub(trace_start);

        // For each CPU, process events chronologically to track runqueue depth
        for cpu in 0..num_cpus {
            let cpu_id = cpu as u32;
            if let Some(filter) = cpu_filter {
                if cpu_id != filter {
                    continue;
                }
            }

            let events = self.trace.get_events_by_cpu(cpu_id);
            if events.is_empty() {
                continue;
            }

            let mut depth: i64 = 0;
            let mut max_depth: i64 = 0;
            let mut depth_samples: Vec<(u64, i64)> = Vec::new(); // (timestamp, depth)
            let mut total_depth_time: f64 = 0.0; // weighted sum for average
            let mut last_ts = trace_start;

            for event_with_idx in events {
                let ts = event_with_idx.event.timestamp.unwrap_or(0);

                match &event_with_idx.event.event {
                    Some(ftrace_event::Event::SchedWakeup(wakeup))
                        // Task placed on this CPU's runqueue
                        if wakeup.target_cpu == Some(cpu_id as i32) => {
                            // Accumulate weighted depth before changing it
                            if ts > last_ts {
                                total_depth_time += depth as f64 * (ts - last_ts) as f64;
                                last_ts = ts;
                            }
                            depth += 1;
                            if depth > max_depth {
                                max_depth = depth;
                            }
                            depth_samples.push((ts, depth));
                        }
                    Some(ftrace_event::Event::SchedSwitch(switch)) => {
                        // Accumulate weighted depth before changing it
                        if ts > last_ts {
                            total_depth_time += depth as f64 * (ts - last_ts) as f64;
                            last_ts = ts;
                        }

                        // If prev task is still runnable (preempted), it goes to runqueue
                        if let Some(prev_state) = switch.prev_state {
                            // State 0 = TASK_RUNNING (still runnable, was preempted)
                            if prev_state == 0 && switch.prev_pid.unwrap_or(0) != 0 {
                                depth += 1;
                            }
                        }

                        // If next task is a real task (not idle), it leaves runqueue
                        if switch.next_pid.unwrap_or(0) != 0 {
                            depth -= 1;
                            if depth < 0 {
                                depth = 0; // Clamp due to trace start boundary
                            }
                        }

                        if depth > max_depth {
                            max_depth = depth;
                        }
                        depth_samples.push((ts, depth));
                    }
                    _ => {}
                }
            }

            // Final accumulation
            if trace_end > last_ts {
                total_depth_time += depth as f64 * (trace_end - last_ts) as f64;
            }

            let avg_depth = if trace_duration_ns > 0 {
                total_depth_time / trace_duration_ns as f64
            } else {
                0.0
            };

            // Calculate p99 depth from samples
            let p99_depth = if !depth_samples.is_empty() {
                let mut depths: Vec<i64> = depth_samples.iter().map(|(_, d)| *d).collect();
                depths.sort_unstable();
                let idx = (depths.len() as f64 * 0.99).ceil() as usize;
                depths[idx.min(depths.len() - 1)]
            } else {
                0
            };

            per_cpu.insert(
                cpu_id,
                CpuRunqueueStats {
                    cpu_id,
                    avg_depth,
                    max_depth,
                    p99_depth,
                    sample_count: depth_samples.len(),
                },
            );
        }

        // Build summary
        let total_cpus = per_cpu.len();
        let global_avg = if total_cpus > 0 {
            per_cpu.values().map(|s| s.avg_depth).sum::<f64>() / total_cpus as f64
        } else {
            0.0
        };
        let global_max = per_cpu.values().map(|s| s.max_depth).max().unwrap_or(0);
        let cpus_with_high_depth = per_cpu.values().filter(|s| s.max_depth > 10).count();

        RunqueueDepthStats {
            total_cpus,
            global_avg_depth: global_avg,
            global_max_depth: global_max,
            cpus_with_high_depth,
            per_cpu,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunqueueDepthStats {
    pub total_cpus: usize,
    pub global_avg_depth: f64,
    pub global_max_depth: i64,
    pub cpus_with_high_depth: usize,
    pub per_cpu: HashMap<u32, CpuRunqueueStats>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CpuRunqueueStats {
    pub cpu_id: u32,
    pub avg_depth: f64,
    pub max_depth: i64,
    pub p99_depth: i64,
    pub sample_count: usize,
}

// ============================================================================
// DSQ Latency Analyzer (Full Implementation)
// ============================================================================

/// Analyzes DSQ (dispatch queue) latency and queue depth from sched_ext traces.
/// Uses the properly-parsed DSQ events with UUID-matched latency and nr_queued data.
pub struct DsqLatencyAnalyzer {
    trace: Arc<PerfettoTrace>,
}

impl DsqLatencyAnalyzer {
    pub fn new(trace: Arc<PerfettoTrace>) -> Self {
        Self { trace }
    }

    /// Analyze DSQ latency for all dispatch queues in the trace.
    pub fn analyze(&self) -> Option<DsqLatencyStats> {
        if !self.trace.is_scx_trace() {
            return None;
        }

        let scx_meta = self.trace.get_scx_metadata()?;
        let (trace_start, trace_end) = self.trace.time_range();
        let trace_duration_ns = trace_end.saturating_sub(trace_start);

        let mut per_dsq: Vec<PerDsqStats> = Vec::new();
        let mut total_events = 0usize;

        for &dsq_id in &scx_meta.dsq_ids {
            let events = self.trace.get_dsq_events(dsq_id);
            if events.is_empty() {
                per_dsq.push(PerDsqStats {
                    dsq_id,
                    event_count: 0,
                    latency_avg_us: 0.0,
                    latency_p50_us: 0.0,
                    latency_p95_us: 0.0,
                    latency_p99_us: 0.0,
                    latency_max_us: 0.0,
                    avg_queue_depth: 0.0,
                    max_queue_depth: 0,
                    dispatches_per_sec: 0.0,
                });
                continue;
            }

            total_events += events.len();

            // Collect latency values (in microseconds)
            let mut latencies: Vec<f64> = events
                .iter()
                .filter_map(|e| e.latency_us.map(|v| v as f64))
                .collect();
            latencies.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

            // Collect queue depth values
            let mut queue_depths: Vec<i64> = events.iter().filter_map(|e| e.nr_queued).collect();

            let lat_count = latencies.len();
            let (lat_avg, lat_p50, lat_p95, lat_p99, lat_max) = if lat_count > 0 {
                let avg = latencies.iter().sum::<f64>() / lat_count as f64;
                let p50 = latencies[lat_count / 2];
                let p95 = latencies[(lat_count as f64 * 0.95) as usize];
                let p99 = latencies[(lat_count as f64 * 0.99).min(lat_count as f64 - 1.0) as usize];
                let max = latencies[lat_count - 1];
                (avg, p50, p95, p99, max)
            } else {
                (0.0, 0.0, 0.0, 0.0, 0.0)
            };

            let (avg_qd, max_qd) = if !queue_depths.is_empty() {
                queue_depths.sort_unstable();
                let avg = queue_depths.iter().sum::<i64>() as f64 / queue_depths.len() as f64;
                let max = *queue_depths.last().unwrap();
                (avg, max)
            } else {
                (0.0, 0)
            };

            let dispatches_per_sec = if trace_duration_ns > 0 {
                events.len() as f64 / (trace_duration_ns as f64 / 1_000_000_000.0)
            } else {
                0.0
            };

            per_dsq.push(PerDsqStats {
                dsq_id,
                event_count: events.len(),
                latency_avg_us: lat_avg,
                latency_p50_us: lat_p50,
                latency_p95_us: lat_p95,
                latency_p99_us: lat_p99,
                latency_max_us: lat_max,
                avg_queue_depth: avg_qd,
                max_queue_depth: max_qd,
                dispatches_per_sec,
            });
        }

        Some(DsqLatencyStats {
            scheduler_name: scx_meta.scheduler_name.clone(),
            total_dsqs: scx_meta.dsq_ids.len(),
            total_events,
            per_dsq,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DsqLatencyStats {
    pub scheduler_name: Option<String>,
    pub total_dsqs: usize,
    pub total_events: usize,
    pub per_dsq: Vec<PerDsqStats>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerDsqStats {
    pub dsq_id: u64,
    pub event_count: usize,
    pub latency_avg_us: f64,
    pub latency_p50_us: f64,
    pub latency_p95_us: f64,
    pub latency_p99_us: f64,
    pub latency_max_us: f64,
    pub avg_queue_depth: f64,
    pub max_queue_depth: i64,
    pub dispatches_per_sec: f64,
}

// ============================================================================
// Fairness / Starvation Analyzer
// ============================================================================

/// Detects scheduling fairness issues by comparing actual CPU time distribution
/// against expected fair share. Identifies starved and hogging processes.
pub struct FairnessAnalyzer {
    trace: Arc<PerfettoTrace>,
}

impl FairnessAnalyzer {
    pub fn new(trace: Arc<PerfettoTrace>) -> Self {
        Self { trace }
    }

    /// Analyze scheduling fairness across all processes.
    pub fn analyze(&self) -> FairnessStats {
        let num_cpus = self.trace.num_cpus();

        // Calculate per-process runtime from sched_switch events
        let mut process_runtime: HashMap<i32, u64> = HashMap::new();
        let mut process_names: HashMap<i32, String> = HashMap::new();

        // Track when each process last started running on each CPU
        let mut last_switch_in: HashMap<(u32, i32), u64> = HashMap::new();

        for cpu in 0..num_cpus {
            let cpu_id = cpu as u32;
            let events = self.trace.get_events_by_cpu(cpu_id);

            for event_with_idx in events {
                if let Some(ftrace_event::Event::SchedSwitch(switch)) = &event_with_idx.event.event
                {
                    let ts = event_with_idx.event.timestamp.unwrap_or(0);
                    let prev_pid = switch.prev_pid.unwrap_or(0);
                    let next_pid = switch.next_pid.unwrap_or(0);

                    // Account runtime for prev_pid
                    if prev_pid != 0 {
                        if let Some(start_ts) = last_switch_in.remove(&(cpu_id, prev_pid)) {
                            let runtime = ts.saturating_sub(start_ts);
                            *process_runtime.entry(prev_pid).or_insert(0) += runtime;
                        }
                        if let Some(comm) = &switch.prev_comm {
                            process_names
                                .entry(prev_pid)
                                .or_insert_with(|| comm.clone());
                        }
                    }

                    // Mark next_pid as running on this CPU
                    if next_pid != 0 {
                        last_switch_in.insert((cpu_id, next_pid), ts);
                        if let Some(comm) = &switch.next_comm {
                            process_names
                                .entry(next_pid)
                                .or_insert_with(|| comm.clone());
                        }
                    }
                }
            }
        }

        if process_runtime.is_empty() {
            return FairnessStats {
                total_processes: 0,
                total_cpu_time_ns: 0,
                fair_share_ns: 0,
                gini_coefficient: 0.0,
                max_min_ratio: 0.0,
                starved_processes: Vec::new(),
                hogging_processes: Vec::new(),
            };
        }

        // Total CPU time across all processes
        let total_cpu_time: u64 = process_runtime.values().sum();
        let num_processes = process_runtime.len();

        // Fair share = total CPU time / number of processes
        let fair_share = total_cpu_time / num_processes as u64;

        // Calculate Gini coefficient
        let mut runtimes: Vec<u64> = process_runtime.values().copied().collect();
        runtimes.sort_unstable();
        let gini = calculate_gini(&runtimes);

        // Max/min ratio (excluding zeros)
        let non_zero_runtimes: Vec<u64> = runtimes.iter().copied().filter(|&r| r > 0).collect();
        let max_min_ratio = if non_zero_runtimes.len() >= 2 {
            let max = *non_zero_runtimes.last().unwrap();
            let min = *non_zero_runtimes.first().unwrap();
            if min > 0 {
                max as f64 / min as f64
            } else {
                f64::INFINITY
            }
        } else {
            1.0
        };

        // Identify starved processes (< 10% of fair share)
        let starvation_threshold = fair_share / 10;
        let mut starved: Vec<_> = process_runtime
            .iter()
            .filter(|(_, &runtime)| runtime < starvation_threshold && runtime > 0)
            .map(|(&pid, &runtime)| {
                let comm = process_names.get(&pid).cloned().unwrap_or_default();
                let share_pct = if fair_share > 0 {
                    runtime as f64 / fair_share as f64 * 100.0
                } else {
                    0.0
                };
                FairnessProcess {
                    pid,
                    comm,
                    runtime_ns: runtime,
                    fair_share_pct: share_pct,
                }
            })
            .collect();
        starved.sort_by_key(|a| a.runtime_ns);

        // Identify hogging processes (> 10x fair share)
        let hogging_threshold = fair_share.saturating_mul(10);
        let mut hogging: Vec<_> = process_runtime
            .iter()
            .filter(|(_, &runtime)| runtime > hogging_threshold)
            .map(|(&pid, &runtime)| {
                let comm = process_names.get(&pid).cloned().unwrap_or_default();
                let share_pct = if fair_share > 0 {
                    runtime as f64 / fair_share as f64 * 100.0
                } else {
                    0.0
                };
                FairnessProcess {
                    pid,
                    comm,
                    runtime_ns: runtime,
                    fair_share_pct: share_pct,
                }
            })
            .collect();
        hogging.sort_by_key(|b| std::cmp::Reverse(b.runtime_ns));

        FairnessStats {
            total_processes: num_processes,
            total_cpu_time_ns: total_cpu_time,
            fair_share_ns: fair_share,
            gini_coefficient: gini,
            max_min_ratio,
            starved_processes: starved,
            hogging_processes: hogging,
        }
    }
}

/// Calculate the Gini coefficient from a sorted list of values.
/// Returns 0.0 for perfect equality, 1.0 for maximum inequality.
fn calculate_gini(sorted_values: &[u64]) -> f64 {
    let n = sorted_values.len();
    if n <= 1 {
        return 0.0;
    }

    let sum: f64 = sorted_values.iter().map(|&v| v as f64).sum();
    if sum == 0.0 {
        return 0.0;
    }

    let mut numerator = 0.0;
    for (i, &val) in sorted_values.iter().enumerate() {
        numerator += (2.0 * (i + 1) as f64 - n as f64 - 1.0) * val as f64;
    }

    numerator / (n as f64 * sum)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FairnessStats {
    pub total_processes: usize,
    pub total_cpu_time_ns: u64,
    pub fair_share_ns: u64,
    pub gini_coefficient: f64,
    pub max_min_ratio: f64,
    pub starved_processes: Vec<FairnessProcess>,
    pub hogging_processes: Vec<FairnessProcess>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FairnessProcess {
    pub pid: i32,
    pub comm: String,
    pub runtime_ns: u64,
    /// Percentage of fair share received (100% = exactly fair)
    pub fair_share_pct: f64,
}
