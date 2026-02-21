//! Trace statistics for comparing real vs simulated scheduler behavior.
//!
//! This module provides statistical analysis of simulation traces to help
//! identify realism gaps. Compare metrics from simulated traces against
//! equivalent metrics from bpftrace captures of real kernel behavior.
//!
//! # Metrics Computed
//!
//! - **Run duration distribution**: Min/max/mean/stddev of task run times
//! - **Inter-arrival times**: Time between consecutive schedules of a task
//! - **Dispatch path frequency**: Direct dispatch vs enqueue path ratio
//! - **Tick frequency**: Actual tick interval vs expected
//! - **Yield/re-enqueue cycles**: Number of spurious yield patterns
//!
//! These metrics help identify the realism gaps documented in sim-6b003.

use std::collections::HashMap;

use crate::trace::{Trace, TraceKind};
use crate::types::{CpuId, Pid, TimeNs};

/// Summary statistics for a distribution of values.
#[derive(Debug, Clone, Default)]
pub struct DistributionStats {
    /// Number of samples.
    pub count: usize,
    /// Minimum value (or 0 if empty).
    pub min: TimeNs,
    /// Maximum value (or 0 if empty).
    pub max: TimeNs,
    /// Sum of all values.
    pub sum: TimeNs,
    /// Sum of squares (for variance calculation).
    sum_sq: u128,
}

impl DistributionStats {
    /// Create new empty statistics.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a sample value.
    pub fn add(&mut self, value: TimeNs) {
        if self.count == 0 {
            self.min = value;
            self.max = value;
        } else {
            self.min = self.min.min(value);
            self.max = self.max.max(value);
        }
        self.count += 1;
        self.sum += value;
        self.sum_sq += (value as u128) * (value as u128);
    }

    /// Mean value (or 0 if empty).
    pub fn mean(&self) -> f64 {
        if self.count == 0 {
            0.0
        } else {
            self.sum as f64 / self.count as f64
        }
    }

    /// Standard deviation (or 0 if empty or single sample).
    pub fn stddev(&self) -> f64 {
        if self.count < 2 {
            0.0
        } else {
            let mean = self.mean();
            let variance = (self.sum_sq as f64 / self.count as f64) - (mean * mean);
            variance.max(0.0).sqrt()
        }
    }

    /// Coefficient of variation (stddev / mean), as a percentage.
    /// Returns 0 if mean is 0.
    pub fn cv_percent(&self) -> f64 {
        let mean = self.mean();
        if mean == 0.0 {
            0.0
        } else {
            100.0 * self.stddev() / mean
        }
    }
}

/// Per-task statistics computed from a trace.
#[derive(Debug, Clone, Default)]
pub struct TaskStats {
    /// PID of the task.
    pub pid: Pid,
    /// Number of times the task was scheduled.
    pub schedule_count: usize,
    /// Distribution of run durations (time between scheduled and stopped).
    pub run_duration: DistributionStats,
    /// Distribution of inter-arrival times (time between consecutive schedules).
    pub inter_arrival: DistributionStats,
    /// Number of times the task was dispatched directly (via SCX_DSQ_LOCAL in select_cpu).
    pub direct_dispatch_count: usize,
    /// Number of times the task went through the enqueue path.
    pub enqueue_count: usize,
    /// Number of yield events (task yielded but remained runnable).
    pub yield_count: usize,
    /// Number of preemption events (slice expired).
    pub preempt_count: usize,
    /// Number of sleep events (voluntary block).
    pub sleep_count: usize,
}

/// Per-CPU statistics computed from a trace.
#[derive(Debug, Clone, Default)]
pub struct CpuStats {
    /// CPU ID.
    pub cpu: CpuId,
    /// Number of tick events on this CPU.
    pub tick_count: usize,
    /// Distribution of tick intervals.
    pub tick_interval: DistributionStats,
    /// Number of times this CPU went idle.
    pub idle_count: usize,
    /// Number of dispatch (balance) calls on this CPU.
    pub balance_count: usize,
}

/// Global trace statistics.
#[derive(Debug, Clone, Default)]
pub struct TraceStats {
    /// Per-task statistics.
    pub tasks: HashMap<Pid, TaskStats>,
    /// Per-CPU statistics.
    pub cpus: HashMap<CpuId, CpuStats>,
    /// Total simulation duration.
    pub duration_ns: TimeNs,
    /// Number of DsqInsert events (FIFO).
    pub dsq_insert_count: usize,
    /// Number of DsqInsertVtime events (vtime-ordered).
    pub dsq_insert_vtime_count: usize,
    /// Number of DsqMoveToLocal events.
    pub dsq_move_to_local_count: usize,
    /// Number of kick_cpu calls.
    pub kick_cpu_count: usize,
}

impl TraceStats {
    /// Compute statistics from a simulation trace.
    pub fn from_trace(trace: &Trace) -> Self {
        let mut stats = TraceStats::default();

        // Track last events for interval computation
        let mut task_last_scheduled: HashMap<Pid, TimeNs> = HashMap::new();
        let mut task_running_since: HashMap<Pid, TimeNs> = HashMap::new();
        let mut cpu_last_tick: HashMap<CpuId, TimeNs> = HashMap::new();
        let mut last_event_time: TimeNs = 0;

        // Track if the last select_cpu did a direct dispatch (by checking
        // if DsqInsert with LOCAL DSQ happened between SelectTaskRq and EnqueueTask)
        let mut pending_select_cpu: HashMap<Pid, TimeNs> = HashMap::new();
        let mut pending_direct_dispatch: HashMap<Pid, bool> = HashMap::new();

        for event in trace.events() {
            last_event_time = last_event_time.max(event.time_ns);

            // Ensure task and CPU entries exist
            stats.tasks.entry(Pid(0)).or_default(); // placeholder
            stats.cpus.entry(event.cpu).or_insert_with(|| CpuStats {
                cpu: event.cpu,
                ..Default::default()
            });

            match &event.kind {
                TraceKind::TaskScheduled { pid } => {
                    let task_stats = stats.tasks.entry(*pid).or_insert_with(|| TaskStats {
                        pid: *pid,
                        ..Default::default()
                    });
                    task_stats.schedule_count += 1;
                    task_running_since.insert(*pid, event.time_ns);

                    // Compute inter-arrival time
                    if let Some(last_time) = task_last_scheduled.get(pid) {
                        let interval = event.time_ns.saturating_sub(*last_time);
                        task_stats.inter_arrival.add(interval);
                    }
                    task_last_scheduled.insert(*pid, event.time_ns);
                }

                TraceKind::TaskPreempted { pid }
                | TraceKind::TaskYielded { pid }
                | TraceKind::TaskSlept { pid }
                | TraceKind::TaskCompleted { pid } => {
                    let task_stats = stats.tasks.entry(*pid).or_insert_with(|| TaskStats {
                        pid: *pid,
                        ..Default::default()
                    });

                    // Compute run duration
                    if let Some(start_time) = task_running_since.remove(pid) {
                        let duration = event.time_ns.saturating_sub(start_time);
                        task_stats.run_duration.add(duration);
                    }

                    match &event.kind {
                        TraceKind::TaskPreempted { .. } => task_stats.preempt_count += 1,
                        TraceKind::TaskYielded { .. } => task_stats.yield_count += 1,
                        TraceKind::TaskSlept { .. } => task_stats.sleep_count += 1,
                        _ => {}
                    }
                }

                TraceKind::SelectTaskRq { pid, .. } => {
                    pending_select_cpu.insert(*pid, event.time_ns);
                    pending_direct_dispatch.insert(*pid, false);
                }

                TraceKind::DsqInsert { pid, dsq_id, .. } => {
                    stats.dsq_insert_count += 1;

                    // Check if this is a direct dispatch (LOCAL DSQ during select_cpu)
                    if (dsq_id.is_local() || dsq_id.is_local_on())
                        && pending_select_cpu.contains_key(pid)
                    {
                        pending_direct_dispatch.insert(*pid, true);
                    }
                }

                TraceKind::DsqInsertVtime { .. } => {
                    stats.dsq_insert_vtime_count += 1;
                }

                TraceKind::EnqueueTask { pid, .. } => {
                    let task_stats = stats.tasks.entry(*pid).or_insert_with(|| TaskStats {
                        pid: *pid,
                        ..Default::default()
                    });

                    // Check if this followed a direct dispatch in select_cpu
                    let was_direct = pending_direct_dispatch.remove(pid).unwrap_or(false);
                    pending_select_cpu.remove(pid);

                    if was_direct {
                        task_stats.direct_dispatch_count += 1;
                    } else {
                        task_stats.enqueue_count += 1;
                    }
                }

                TraceKind::Balance { .. } => {
                    let cpu_stats = stats.cpus.get_mut(&event.cpu).unwrap();
                    cpu_stats.balance_count += 1;
                }

                TraceKind::CpuIdle => {
                    let cpu_stats = stats.cpus.get_mut(&event.cpu).unwrap();
                    cpu_stats.idle_count += 1;
                }

                TraceKind::Tick { .. } => {
                    let cpu_stats = stats.cpus.get_mut(&event.cpu).unwrap();
                    cpu_stats.tick_count += 1;

                    // Compute tick interval
                    if let Some(last_tick) = cpu_last_tick.get(&event.cpu) {
                        let interval = event.time_ns.saturating_sub(*last_tick);
                        cpu_stats.tick_interval.add(interval);
                    }
                    cpu_last_tick.insert(event.cpu, event.time_ns);
                }

                TraceKind::DsqMoveToLocal { .. } => {
                    stats.dsq_move_to_local_count += 1;
                }

                TraceKind::KickCpu { .. } => {
                    stats.kick_cpu_count += 1;
                }

                _ => {}
            }
        }

        // Remove placeholder task entry
        stats.tasks.remove(&Pid(0));
        stats.duration_ns = last_event_time;
        stats
    }

    /// Print a summary report to stderr.
    pub fn print_summary(&self) {
        eprintln!("\n=== Trace Statistics ===\n");
        eprintln!("Duration: {:.3}ms", self.duration_ns as f64 / 1_000_000.0);
        eprintln!();

        eprintln!("--- Per-Task Statistics ---");
        let mut task_pids: Vec<_> = self.tasks.keys().copied().collect();
        task_pids.sort_by_key(|p| p.0);

        for pid in task_pids {
            let ts = &self.tasks[&pid];
            eprintln!("  Task PID={}:", pid.0);
            eprintln!("    Schedules:       {}", ts.schedule_count);
            eprintln!(
                "    Run duration:    {:.3}ms mean, {:.3}ms stddev, CV={:.1}%",
                ts.run_duration.mean() / 1_000_000.0,
                ts.run_duration.stddev() / 1_000_000.0,
                ts.run_duration.cv_percent()
            );
            eprintln!(
                "    Inter-arrival:   {:.3}ms mean, {:.3}ms stddev",
                ts.inter_arrival.mean() / 1_000_000.0,
                ts.inter_arrival.stddev() / 1_000_000.0
            );
            eprintln!("    Direct dispatch: {}", ts.direct_dispatch_count);
            eprintln!("    Enqueue calls:   {}", ts.enqueue_count);
            eprintln!("    Yields:          {}", ts.yield_count);
            eprintln!("    Preemptions:     {}", ts.preempt_count);
            eprintln!("    Sleeps:          {}", ts.sleep_count);
        }
        eprintln!();

        eprintln!("--- Per-CPU Statistics ---");
        let mut cpu_ids: Vec<_> = self.cpus.keys().copied().collect();
        cpu_ids.sort_by_key(|c| c.0);

        for cpu in cpu_ids {
            let cs = &self.cpus[&cpu];
            eprintln!("  CPU {}:", cpu.0);
            eprintln!("    Ticks:         {}", cs.tick_count);
            eprintln!(
                "    Tick interval: {:.3}ms mean, {:.3}ms stddev",
                cs.tick_interval.mean() / 1_000_000.0,
                cs.tick_interval.stddev() / 1_000_000.0
            );
            eprintln!("    Balance calls: {}", cs.balance_count);
            eprintln!("    Idle events:   {}", cs.idle_count);
        }
        eprintln!();

        eprintln!("--- Global Statistics ---");
        eprintln!("  DSQ inserts (FIFO):    {}", self.dsq_insert_count);
        eprintln!("  DSQ inserts (vtime):   {}", self.dsq_insert_vtime_count);
        eprintln!("  DSQ move_to_local:     {}", self.dsq_move_to_local_count);
        eprintln!("  Kick CPU calls:        {}", self.kick_cpu_count);
        eprintln!();
    }

    /// Compute a realism score based on known gap indicators.
    ///
    /// Returns a score from 0-100 where 100 means most realistic.
    /// Deductions are made for:
    /// - High yield counts (Gap 1: spurious yield/re-enqueue)
    /// - Low tick variance (Gap 2: tick frequency mismatch)
    /// - Zero run duration variance (Gap 6: no timing jitter)
    pub fn realism_score(&self) -> f64 {
        let mut score = 100.0;

        // Gap 1: Spurious yield/re-enqueue cycles
        // Real CPU-bound tasks rarely yield; they get preempted.
        for ts in self.tasks.values() {
            if ts.schedule_count > 0 {
                let yield_ratio = ts.yield_count as f64 / ts.schedule_count as f64;
                // Deduct up to 20 points for high yield ratio (>50%)
                if yield_ratio > 0.5 {
                    score -= 20.0 * (yield_ratio - 0.5).min(0.5) / 0.5;
                }
            }
        }

        // Gap 2: Tick frequency mismatch
        // Expected 4ms ticks (HZ=250). Real kernel has some jitter.
        for cs in self.cpus.values() {
            let tick_cv = cs.tick_interval.cv_percent();
            // Very low CV (<1%) suggests unrealistic uniformity
            if tick_cv < 1.0 && cs.tick_count > 5 {
                score -= 10.0;
            }
        }

        // Gap 6: Run duration variance
        // Real tasks have variance from interrupts, overhead, etc.
        for ts in self.tasks.values() {
            let run_cv = ts.run_duration.cv_percent();
            // Zero CV suggests unrealistic determinism
            if run_cv == 0.0 && ts.run_duration.count > 2 {
                score -= 10.0;
            }
        }

        score.max(0.0)
    }
}

/// Comparison between two traces (real vs simulated).
#[derive(Debug)]
pub struct TraceComparison {
    /// Statistics from the baseline trace (typically real).
    pub baseline: TraceStats,
    /// Statistics from the comparison trace (typically simulated).
    pub comparison: TraceStats,
}

impl TraceComparison {
    /// Create a comparison between two traces.
    pub fn new(baseline: &Trace, comparison: &Trace) -> Self {
        Self {
            baseline: TraceStats::from_trace(baseline),
            comparison: TraceStats::from_trace(comparison),
        }
    }

    /// Print a comparison report to stderr.
    pub fn print_comparison(&self) {
        eprintln!("\n=== Trace Comparison ===\n");

        eprintln!("--- Duration ---");
        eprintln!(
            "  Baseline:   {:.3}ms",
            self.baseline.duration_ns as f64 / 1_000_000.0
        );
        eprintln!(
            "  Comparison: {:.3}ms",
            self.comparison.duration_ns as f64 / 1_000_000.0
        );
        eprintln!();

        eprintln!("--- DSQ Operations ---");
        eprintln!(
            "  DSQ inserts:  {} vs {} ({:+})",
            self.baseline.dsq_insert_count,
            self.comparison.dsq_insert_count,
            self.comparison.dsq_insert_count as i64 - self.baseline.dsq_insert_count as i64
        );
        eprintln!(
            "  Kick CPU:     {} vs {} ({:+})",
            self.baseline.kick_cpu_count,
            self.comparison.kick_cpu_count,
            self.comparison.kick_cpu_count as i64 - self.baseline.kick_cpu_count as i64
        );
        eprintln!();

        eprintln!("--- Realism Scores ---");
        eprintln!("  Baseline:   {:.1}/100", self.baseline.realism_score());
        eprintln!("  Comparison: {:.1}/100", self.comparison.realism_score());
        eprintln!();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_distribution_stats_empty() {
        let stats = DistributionStats::new();
        assert_eq!(stats.count, 0);
        assert_eq!(stats.mean(), 0.0);
        assert_eq!(stats.stddev(), 0.0);
    }

    #[test]
    fn test_distribution_stats_single() {
        let mut stats = DistributionStats::new();
        stats.add(1000);
        assert_eq!(stats.count, 1);
        assert_eq!(stats.min, 1000);
        assert_eq!(stats.max, 1000);
        assert_eq!(stats.mean(), 1000.0);
        assert_eq!(stats.stddev(), 0.0);
    }

    #[test]
    fn test_distribution_stats_multiple() {
        let mut stats = DistributionStats::new();
        stats.add(100);
        stats.add(200);
        stats.add(300);
        assert_eq!(stats.count, 3);
        assert_eq!(stats.min, 100);
        assert_eq!(stats.max, 300);
        assert_eq!(stats.mean(), 200.0);
        // stddev of [100,200,300] is ~81.65
        assert!(stats.stddev() > 80.0 && stats.stddev() < 83.0);
    }

    #[test]
    fn test_cv_percent() {
        let mut stats = DistributionStats::new();
        stats.add(100);
        stats.add(100);
        stats.add(100);
        // Zero variance -> 0% CV
        assert_eq!(stats.cv_percent(), 0.0);

        let mut stats2 = DistributionStats::new();
        stats2.add(100);
        stats2.add(200);
        // CV = stddev/mean * 100
        assert!(stats2.cv_percent() > 30.0);
    }
}
