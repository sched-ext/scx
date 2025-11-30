// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use super::perfetto_parser::{Percentiles, PerfettoTrace};
use perfetto_protos::ftrace_event::ftrace_event;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;

/// Analyzes context switches and CPU utilization from trace
pub struct ContextSwitchAnalyzer {
    trace: Arc<PerfettoTrace>,
}

impl ContextSwitchAnalyzer {
    pub fn new(trace: Arc<PerfettoTrace>) -> Self {
        Self { trace }
    }

    /// Analyze CPU utilization for all CPUs
    pub fn analyze_cpu_utilization(&self) -> HashMap<u32, CpuUtilStats> {
        let mut stats = HashMap::new();

        for cpu in 0..self.trace.num_cpus() {
            if let Some(cpu_stats) = self.analyze_cpu(cpu as u32) {
                stats.insert(cpu as u32, cpu_stats);
            }
        }

        stats
    }

    /// Analyze CPU utilization in parallel (multi-threaded)
    pub fn analyze_cpu_utilization_parallel(&self) -> HashMap<u32, CpuUtilStats> {
        (0..self.trace.num_cpus())
            .into_par_iter()
            .filter_map(|cpu| {
                let cpu_u32 = cpu as u32;
                self.analyze_cpu(cpu_u32).map(|stats| (cpu_u32, stats))
            })
            .collect()
    }

    /// Analyze a single CPU
    fn analyze_cpu(&self, cpu: u32) -> Option<CpuUtilStats> {
        let events = self.trace.get_events_by_cpu(cpu);
        if events.is_empty() {
            return None;
        }

        let mut active_time_ns = 0u64;
        let mut total_switches = 0usize;
        let mut timeslices: Vec<u64> = Vec::new();
        let mut last_switch_ts = None;
        let mut last_was_idle = false;

        for event_with_idx in events {
            if let Some(ftrace_event::Event::SchedSwitch(switch)) = &event_with_idx.event.event {
                if let Some(ts) = event_with_idx.event.timestamp {
                    total_switches += 1;

                    // Calculate timeslice if we have a previous switch
                    if let Some(prev_ts) = last_switch_ts {
                        let timeslice = ts.saturating_sub(prev_ts);
                        timeslices.push(timeslice);

                        // Add to active time if previous task was not idle
                        if !last_was_idle {
                            active_time_ns += timeslice;
                        }
                    }

                    // Check if next task is idle (PID 0 or swapper)
                    last_was_idle = switch.next_pid.unwrap_or(0) == 0;
                    last_switch_ts = Some(ts);
                }
            }
        }

        let (start_ts, end_ts) = self.trace.time_range();
        let total_time_ns = end_ts.saturating_sub(start_ts);
        let idle_time_ns = total_time_ns.saturating_sub(active_time_ns);
        let utilization_percent = if total_time_ns > 0 {
            (active_time_ns as f64 / total_time_ns as f64) * 100.0
        } else {
            0.0
        };

        // Calculate timeslice percentiles
        let timeslice_percentiles = if !timeslices.is_empty() {
            PerfettoTrace::calculate_percentiles(&timeslices)
        } else {
            Percentiles {
                count: 0,
                min: 0,
                max: 0,
                mean: 0.0,
                median: 0,
                p95: 0,
                p99: 0,
                p999: 0,
            }
        };

        Some(CpuUtilStats {
            cpu_id: cpu,
            active_time_ns,
            idle_time_ns,
            utilization_percent,
            total_switches,
            min_timeslice_ns: timeslice_percentiles.min,
            max_timeslice_ns: timeslice_percentiles.max,
            avg_timeslice_ns: timeslice_percentiles.mean as u64,
            p50_timeslice_ns: timeslice_percentiles.median,
            p95_timeslice_ns: timeslice_percentiles.p95,
            p99_timeslice_ns: timeslice_percentiles.p99,
        })
    }

    /// Analyze process runtime statistics
    pub fn analyze_process_runtime(&self, pid: Option<i32>) -> Vec<ProcessRuntimeStats> {
        let mut process_data: HashMap<i32, ProcessRuntimeData> = HashMap::new();

        // Collect data from all CPUs
        for cpu in 0..self.trace.num_cpus() {
            let events = self.trace.get_events_by_cpu(cpu as u32);

            for event_with_idx in events {
                if let Some(ftrace_event::Event::SchedSwitch(switch)) = &event_with_idx.event.event
                {
                    if let (Some(ts), Some(prev_pid), Some(next_pid)) = (
                        event_with_idx.event.timestamp,
                        switch.prev_pid,
                        switch.next_pid,
                    ) {
                        // Track when processes are scheduled off
                        if prev_pid > 0 {
                            let data = process_data.entry(prev_pid).or_insert_with(|| {
                                ProcessRuntimeData {
                                    pid: prev_pid,
                                    comm: switch
                                        .prev_comm
                                        .clone()
                                        .unwrap_or_else(|| "unknown".to_string()),
                                    last_scheduled_on: None,
                                    total_runtime_ns: 0,
                                    num_switches: 0,
                                    timeslices: Vec::new(),
                                }
                            });

                            // If we have a previous schedule-on time, calculate runtime
                            if let Some(scheduled_on) = data.last_scheduled_on {
                                let runtime = ts.saturating_sub(scheduled_on);
                                data.total_runtime_ns += runtime;
                                data.timeslices.push(runtime);
                            }
                            data.last_scheduled_on = None;
                            data.num_switches += 1;
                        }

                        // Track when processes are scheduled on
                        if next_pid > 0 {
                            let data = process_data.entry(next_pid).or_insert_with(|| {
                                ProcessRuntimeData {
                                    pid: next_pid,
                                    comm: switch
                                        .next_comm
                                        .clone()
                                        .unwrap_or_else(|| "unknown".to_string()),
                                    last_scheduled_on: None,
                                    total_runtime_ns: 0,
                                    num_switches: 0,
                                    timeslices: Vec::new(),
                                }
                            });
                            data.last_scheduled_on = Some(ts);
                        }
                    }
                }
            }
        }

        // Convert to stats and filter by PID if requested
        let (start_ts, end_ts) = self.trace.time_range();
        let total_trace_time_ns = end_ts.saturating_sub(start_ts);

        let mut stats: Vec<ProcessRuntimeStats> = process_data
            .into_iter()
            .filter(|(p, _)| pid.is_none_or(|filter_pid| *p == filter_pid))
            .map(|(_, data)| {
                let cpu_time_percent = if total_trace_time_ns > 0 {
                    (data.total_runtime_ns as f64 / total_trace_time_ns as f64) * 100.0
                } else {
                    0.0
                };

                let timeslice_percentiles = if !data.timeslices.is_empty() {
                    PerfettoTrace::calculate_percentiles(&data.timeslices)
                } else {
                    Percentiles::default()
                };

                ProcessRuntimeStats {
                    pid: data.pid,
                    comm: data.comm,
                    total_runtime_ns: data.total_runtime_ns,
                    cpu_time_percent,
                    num_switches: data.num_switches,
                    min_timeslice_ns: timeslice_percentiles.min,
                    max_timeslice_ns: timeslice_percentiles.max,
                    avg_timeslice_ns: timeslice_percentiles.mean as u64,
                    p50_timeslice_ns: timeslice_percentiles.median,
                    p95_timeslice_ns: timeslice_percentiles.p95,
                    p99_timeslice_ns: timeslice_percentiles.p99,
                }
            })
            .collect();

        // Sort by total runtime (descending)
        stats.sort_by(|a, b| b.total_runtime_ns.cmp(&a.total_runtime_ns));

        stats
    }

    /// Analyze process runtime in parallel (multi-threaded)
    pub fn analyze_process_runtime_parallel(&self, pid: Option<i32>) -> Vec<ProcessRuntimeStats> {
        // For parallel processing, we split by CPU and then merge
        let process_data_vec: Vec<HashMap<i32, ProcessRuntimeData>> = (0..self.trace.num_cpus())
            .into_par_iter()
            .map(|cpu| {
                let mut cpu_process_data = HashMap::new();
                let events = self.trace.get_events_by_cpu(cpu as u32);

                for event_with_idx in events {
                    if let Some(ftrace_event::Event::SchedSwitch(switch)) =
                        &event_with_idx.event.event
                    {
                        if let (Some(ts), Some(prev_pid), Some(next_pid)) = (
                            event_with_idx.event.timestamp,
                            switch.prev_pid,
                            switch.next_pid,
                        ) {
                            // Track prev_pid being scheduled off
                            if prev_pid > 0 {
                                let data = cpu_process_data.entry(prev_pid).or_insert_with(|| {
                                    ProcessRuntimeData {
                                        pid: prev_pid,
                                        comm: switch
                                            .prev_comm
                                            .clone()
                                            .unwrap_or_else(|| "unknown".to_string()),
                                        last_scheduled_on: None,
                                        total_runtime_ns: 0,
                                        num_switches: 0,
                                        timeslices: Vec::new(),
                                    }
                                });

                                if let Some(scheduled_on) = data.last_scheduled_on {
                                    let runtime = ts.saturating_sub(scheduled_on);
                                    data.total_runtime_ns += runtime;
                                    data.timeslices.push(runtime);
                                }
                                data.last_scheduled_on = None;
                                data.num_switches += 1;
                            }

                            // Track next_pid being scheduled on
                            if next_pid > 0 {
                                let data = cpu_process_data.entry(next_pid).or_insert_with(|| {
                                    ProcessRuntimeData {
                                        pid: next_pid,
                                        comm: switch
                                            .next_comm
                                            .clone()
                                            .unwrap_or_else(|| "unknown".to_string()),
                                        last_scheduled_on: None,
                                        total_runtime_ns: 0,
                                        num_switches: 0,
                                        timeslices: Vec::new(),
                                    }
                                });
                                data.last_scheduled_on = Some(ts);
                            }
                        }
                    }
                }

                cpu_process_data
            })
            .collect();

        // Merge results from all CPUs
        let mut merged_data: HashMap<i32, ProcessRuntimeData> = HashMap::new();
        for cpu_data in process_data_vec {
            for (pid, data) in cpu_data {
                let entry = merged_data
                    .entry(pid)
                    .or_insert_with(|| ProcessRuntimeData {
                        pid: data.pid,
                        comm: data.comm.clone(),
                        last_scheduled_on: None,
                        total_runtime_ns: 0,
                        num_switches: 0,
                        timeslices: Vec::new(),
                    });

                entry.total_runtime_ns += data.total_runtime_ns;
                entry.num_switches += data.num_switches;
                entry.timeslices.extend(data.timeslices);
            }
        }

        // Convert to stats (same as non-parallel version)
        let (start_ts, end_ts) = self.trace.time_range();
        let total_trace_time_ns = end_ts.saturating_sub(start_ts);

        let mut stats: Vec<ProcessRuntimeStats> = merged_data
            .into_iter()
            .filter(|(p, _)| pid.is_none_or(|filter_pid| *p == filter_pid))
            .map(|(_, data)| {
                let cpu_time_percent = if total_trace_time_ns > 0 {
                    (data.total_runtime_ns as f64 / total_trace_time_ns as f64) * 100.0
                } else {
                    0.0
                };

                let timeslice_percentiles = if !data.timeslices.is_empty() {
                    PerfettoTrace::calculate_percentiles(&data.timeslices)
                } else {
                    Percentiles::default()
                };

                ProcessRuntimeStats {
                    pid: data.pid,
                    comm: data.comm,
                    total_runtime_ns: data.total_runtime_ns,
                    cpu_time_percent,
                    num_switches: data.num_switches,
                    min_timeslice_ns: timeslice_percentiles.min,
                    max_timeslice_ns: timeslice_percentiles.max,
                    avg_timeslice_ns: timeslice_percentiles.mean as u64,
                    p50_timeslice_ns: timeslice_percentiles.median,
                    p95_timeslice_ns: timeslice_percentiles.p95,
                    p99_timeslice_ns: timeslice_percentiles.p99,
                }
            })
            .collect();

        stats.sort_by(|a, b| b.total_runtime_ns.cmp(&a.total_runtime_ns));
        stats
    }
}

/// Internal data structure for tracking process runtime
struct ProcessRuntimeData {
    pid: i32,
    comm: String,
    last_scheduled_on: Option<u64>,
    total_runtime_ns: u64,
    num_switches: usize,
    timeslices: Vec<u64>,
}

/// CPU utilization statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CpuUtilStats {
    pub cpu_id: u32,
    pub active_time_ns: u64,
    pub idle_time_ns: u64,
    pub utilization_percent: f64,
    pub total_switches: usize,
    // Timeslice statistics
    pub min_timeslice_ns: u64,
    pub max_timeslice_ns: u64,
    pub avg_timeslice_ns: u64,
    pub p50_timeslice_ns: u64,
    pub p95_timeslice_ns: u64,
    pub p99_timeslice_ns: u64,
}

/// Process runtime statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessRuntimeStats {
    pub pid: i32,
    pub comm: String,
    pub total_runtime_ns: u64,
    pub cpu_time_percent: f64,
    pub num_switches: usize,
    // Timeslice statistics
    pub min_timeslice_ns: u64,
    pub max_timeslice_ns: u64,
    pub avg_timeslice_ns: u64,
    pub p50_timeslice_ns: u64,
    pub p95_timeslice_ns: u64,
    pub p99_timeslice_ns: u64,
}

impl Default for Percentiles {
    fn default() -> Self {
        Self {
            count: 0,
            min: 0,
            max: 0,
            mean: 0.0,
            median: 0,
            p95: 0,
            p99: 0,
            p999: 0,
        }
    }
}

/// Analyzes wakeup chains and latencies
pub struct WakeupChainAnalyzer {
    trace: Arc<PerfettoTrace>,
}

impl WakeupChainAnalyzer {
    pub fn new(trace: Arc<PerfettoTrace>) -> Self {
        Self { trace }
    }

    /// Analyze wakeup latency across all wakeup events
    pub fn analyze_wakeup_latency(&self) -> WakeupLatencyStats {
        let mut latencies: Vec<u64> = Vec::new();
        let mut per_cpu_latencies: HashMap<u32, Vec<u64>> = HashMap::new();
        let mut wakeup_times: HashMap<i32, u64> = HashMap::new(); // pid -> wakeup_ts

        // Collect wakeup and schedule events
        for cpu in 0..self.trace.num_cpus() {
            let events = self.trace.get_events_by_cpu(cpu as u32);

            for event_with_idx in events {
                match &event_with_idx.event.event {
                    Some(ftrace_event::Event::SchedWakeup(wakeup)) => {
                        // Record wakeup time
                        if let (Some(ts), Some(pid)) = (event_with_idx.event.timestamp, wakeup.pid)
                        {
                            wakeup_times.insert(pid, ts);
                        }
                    }
                    Some(ftrace_event::Event::SchedSwitch(switch)) => {
                        // Calculate latency if task was previously woken
                        if let (Some(ts), Some(next_pid)) =
                            (event_with_idx.event.timestamp, switch.next_pid)
                        {
                            if let Some(wakeup_ts) = wakeup_times.remove(&next_pid) {
                                let latency = ts.saturating_sub(wakeup_ts);
                                latencies.push(latency);
                                per_cpu_latencies
                                    .entry(cpu as u32)
                                    .or_default()
                                    .push(latency);
                            }
                        }
                    }
                    _ => {}
                }
            }
        }

        let overall_percentiles = if !latencies.is_empty() {
            PerfettoTrace::calculate_percentiles(&latencies)
        } else {
            Percentiles::default()
        };

        // Calculate per-CPU stats
        let per_cpu_stats = per_cpu_latencies
            .into_iter()
            .map(|(cpu, lats)| {
                let percentiles = PerfettoTrace::calculate_percentiles(&lats);
                (
                    cpu,
                    LatencyStatsPerCpu {
                        cpu_id: cpu,
                        count: percentiles.count,
                        avg_latency_ns: percentiles.mean as u64,
                        p99_latency_ns: percentiles.p99,
                    },
                )
            })
            .collect();

        WakeupLatencyStats {
            total_wakeups: overall_percentiles.count,
            min_latency_ns: overall_percentiles.min,
            max_latency_ns: overall_percentiles.max,
            avg_latency_ns: overall_percentiles.mean as u64,
            p50_latency_ns: overall_percentiles.median,
            p95_latency_ns: overall_percentiles.p95,
            p99_latency_ns: overall_percentiles.p99,
            p999_latency_ns: overall_percentiles.p999,
            per_cpu_stats,
        }
    }
}

/// Wakeup latency statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WakeupLatencyStats {
    pub total_wakeups: usize,
    pub min_latency_ns: u64,
    pub max_latency_ns: u64,
    pub avg_latency_ns: u64,
    pub p50_latency_ns: u64,
    pub p95_latency_ns: u64,
    pub p99_latency_ns: u64,
    pub p999_latency_ns: u64,
    pub per_cpu_stats: HashMap<u32, LatencyStatsPerCpu>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LatencyStatsPerCpu {
    pub cpu_id: u32,
    pub count: usize,
    pub avg_latency_ns: u64,
    pub p99_latency_ns: u64,
}

/// Analyzes process migration patterns from perfetto trace
pub struct PerfettoMigrationAnalyzer {
    trace: Arc<PerfettoTrace>,
}

impl PerfettoMigrationAnalyzer {
    pub fn new(trace: Arc<PerfettoTrace>) -> Self {
        Self { trace }
    }

    /// Analyze migration patterns across the trace
    ///
    /// Returns migration statistics including per-process counts and latencies.
    /// Note: Migration latency calculation requires tracking task state across events.
    /// Cross-NUMA/LLC detection requires topology information at parse time.
    pub fn analyze_migration_patterns(&self) -> PerfettoMigrationStats {
        let migrate_events = self.trace.get_events_by_type("sched_migrate");
        let mut migrations_by_process: HashMap<i32, usize> = HashMap::new();

        // Cross-NUMA and cross-LLC detection would require:
        // 1. Topology information (CPU to NUMA/LLC mapping)
        // 2. Tracking source and destination CPU
        // These are set to 0 for now; topology integration is future work
        let cross_numa_migrations = 0usize;
        let cross_llc_migrations = 0usize;

        for event in &migrate_events {
            if let Some(ftrace_event::Event::SchedMigrateTask(migrate)) = &event.event {
                if let Some(pid) = migrate.pid {
                    *migrations_by_process.entry(pid).or_insert(0) += 1;
                }
            }
        }

        // Migration latency would be calculated as:
        // (time task is scheduled on new CPU) - (time task was descheduled on old CPU)
        // This requires tracking task state across CPUs, which is complex.
        // For now, latency stats are zero/default; this is future enhancement.
        let percentiles = Percentiles::default();

        PerfettoMigrationStats {
            total_migrations: migrate_events.len(),
            migrations_by_process,
            cross_numa_migrations,
            cross_llc_migrations,
            min_latency_ns: percentiles.min,
            max_latency_ns: percentiles.max,
            avg_latency_ns: percentiles.mean as u64,
            p50_latency_ns: percentiles.median,
            p95_latency_ns: percentiles.p95,
            p99_latency_ns: percentiles.p99,
        }
    }
}

/// Migration statistics from perfetto trace
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerfettoMigrationStats {
    pub total_migrations: usize,
    pub migrations_by_process: HashMap<i32, usize>,
    pub cross_numa_migrations: usize,
    pub cross_llc_migrations: usize,
    // Migration latency statistics
    pub min_latency_ns: u64,
    pub max_latency_ns: u64,
    pub avg_latency_ns: u64,
    pub p50_latency_ns: u64,
    pub p95_latency_ns: u64,
    pub p99_latency_ns: u64,
}

/// Analyzes DSQ (dispatch queue) metrics for sched_ext schedulers
pub struct DsqAnalyzer {
    trace: Arc<PerfettoTrace>,
}

impl DsqAnalyzer {
    pub fn new(trace: Arc<PerfettoTrace>) -> Self {
        Self { trace }
    }

    /// Check if trace has sched_ext data
    pub fn has_scx_data(&self) -> bool {
        self.trace.is_scx_trace()
    }

    /// Get summary of DSQ analysis
    pub fn get_summary(&self) -> Option<DsqAnalysisSummary> {
        let scx_meta = self.trace.get_scx_metadata()?;

        Some(DsqAnalysisSummary {
            scheduler_name: scx_meta.scheduler_name.clone(),
            total_dsqs: scx_meta.dsq_ids.len(),
            dsq_ids: scx_meta.dsq_ids.clone(),
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DsqAnalysisSummary {
    pub scheduler_name: Option<String>,
    pub total_dsqs: usize,
    pub dsq_ids: Vec<u64>,
}

/// Analyzes correlations between events (wakeup→schedule, migration→performance)
pub struct CorrelationAnalyzer {
    trace: Arc<PerfettoTrace>,
}

impl CorrelationAnalyzer {
    pub fn new(trace: Arc<PerfettoTrace>) -> Self {
        Self { trace }
    }

    /// Correlate wakeup events to schedule events to measure wakeup latency
    pub fn correlate_wakeup_to_schedule(
        &self,
        pid_filter: Option<i32>,
    ) -> Vec<WakeupScheduleCorrelation> {
        let mut correlations = Vec::new();
        let mut wakeup_times: HashMap<i32, Vec<WakeupRecord>> = HashMap::new();

        // First pass: collect all wakeup events
        for cpu in 0..self.trace.num_cpus() {
            let events = self.trace.get_events_by_cpu(cpu as u32);

            for event_with_idx in events {
                match &event_with_idx.event.event {
                    Some(ftrace_event::Event::SchedWakeup(wakeup)) => {
                        if let (Some(ts), Some(pid)) = (event_with_idx.event.timestamp, wakeup.pid)
                        {
                            if pid_filter.is_none_or(|filter| pid == filter) {
                                wakeup_times.entry(pid).or_default().push(WakeupRecord {
                                    timestamp: ts,
                                    waker_pid: event_with_idx.event.pid.unwrap_or(0),
                                });
                            }
                        }
                    }
                    Some(ftrace_event::Event::SchedWaking(waking)) => {
                        if let (Some(ts), Some(pid)) = (event_with_idx.event.timestamp, waking.pid)
                        {
                            if pid_filter.is_none_or(|filter| pid == filter) {
                                wakeup_times.entry(pid).or_default().push(WakeupRecord {
                                    timestamp: ts,
                                    waker_pid: event_with_idx.event.pid.unwrap_or(0),
                                });
                            }
                        }
                    }
                    _ => {}
                }
            }
        }

        // Second pass: find schedule events and correlate
        for cpu in 0..self.trace.num_cpus() {
            let events = self.trace.get_events_by_cpu(cpu as u32);

            for event_with_idx in events {
                if let Some(ftrace_event::Event::SchedSwitch(switch)) = &event_with_idx.event.event
                {
                    if let (Some(ts), Some(next_pid)) =
                        (event_with_idx.event.timestamp, switch.next_pid)
                    {
                        if pid_filter.is_none_or(|filter| next_pid == filter) {
                            // Find most recent wakeup for this PID
                            if let Some(wakeups) = wakeup_times.get_mut(&next_pid) {
                                // Find the most recent wakeup before this schedule
                                if let Some(pos) = wakeups.iter().rposition(|w| w.timestamp <= ts) {
                                    let wakeup = wakeups.remove(pos);
                                    let latency = ts.saturating_sub(wakeup.timestamp);

                                    correlations.push(WakeupScheduleCorrelation {
                                        pid: next_pid,
                                        wakeup_timestamp: wakeup.timestamp,
                                        schedule_timestamp: ts,
                                        wakeup_latency_ns: latency,
                                        waker_pid: wakeup.waker_pid,
                                        cpu: cpu as u32,
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }

        // Sort by latency (descending)
        correlations.sort_by(|a, b| b.wakeup_latency_ns.cmp(&a.wakeup_latency_ns));

        correlations
    }

    /// Find scheduling bottlenecks in the trace
    pub fn find_scheduling_bottlenecks(&self, limit: usize) -> Vec<SchedulingBottleneck> {
        let mut bottlenecks = Vec::new();

        // Bottleneck 1: High context switch rate per CPU
        let ctx_analyzer = ContextSwitchAnalyzer::new(self.trace.clone());
        let cpu_stats = ctx_analyzer.analyze_cpu_utilization();

        for (cpu, stats) in &cpu_stats {
            let (start_ts, end_ts) = self.trace.time_range();
            let duration_secs = (end_ts - start_ts) as f64 / 1_000_000_000.0;
            let switch_rate = stats.total_switches as f64 / duration_secs;

            if switch_rate > 1000.0 {
                // More than 1000 switches/sec
                bottlenecks.push(SchedulingBottleneck {
                    description: format!(
                        "High context switch rate on CPU {}: {:.0} Hz",
                        cpu, switch_rate
                    ),
                    severity: (switch_rate / 1000.0).min(10.0),
                    affected_pids: Vec::new(),
                    time_range: (start_ts, end_ts),
                    bottleneck_type: BottleneckType::HighContextSwitchRate {
                        cpu: *cpu,
                        rate_hz: switch_rate,
                    },
                });
            }
        }

        // Bottleneck 2: Long wakeup latencies
        let wakeup_analyzer = WakeupChainAnalyzer::new(self.trace.clone());
        let wakeup_stats = wakeup_analyzer.analyze_wakeup_latency();

        if wakeup_stats.p99_latency_ns > 100_000_000 {
            // p99 > 100ms
            let (start_ts, end_ts) = self.trace.time_range();
            bottlenecks.push(SchedulingBottleneck {
                description: format!(
                    "High wakeup latency: p99={:.2}ms, p999={:.2}ms",
                    wakeup_stats.p99_latency_ns as f64 / 1_000_000.0,
                    wakeup_stats.p999_latency_ns as f64 / 1_000_000.0
                ),
                severity: (wakeup_stats.p99_latency_ns as f64 / 100_000_000.0).min(10.0),
                affected_pids: Vec::new(),
                time_range: (start_ts, end_ts),
                bottleneck_type: BottleneckType::LongWakeupLatency {
                    avg_latency_ns: wakeup_stats.avg_latency_ns,
                },
            });
        }

        // Bottleneck 3: Excessive migration
        let migration_analyzer = PerfettoMigrationAnalyzer::new(self.trace.clone());
        let migration_stats = migration_analyzer.analyze_migration_patterns();

        let (start_ts, end_ts) = self.trace.time_range();
        let duration_secs = (end_ts - start_ts) as f64 / 1_000_000_000.0;
        let migration_rate = migration_stats.total_migrations as f64 / duration_secs;

        if migration_rate > 100.0 {
            // More than 100 migrations/sec
            bottlenecks.push(SchedulingBottleneck {
                description: format!("High migration rate: {:.0} migrations/sec", migration_rate),
                severity: (migration_rate / 100.0).min(10.0),
                affected_pids: Vec::new(),
                time_range: (start_ts, end_ts),
                bottleneck_type: BottleneckType::ExcessiveMigration { migration_rate },
            });
        }

        // Sort by severity (descending)
        bottlenecks.sort_by(|a, b| b.severity.partial_cmp(&a.severity).unwrap());

        bottlenecks.into_iter().take(limit).collect()
    }
}

struct WakeupRecord {
    timestamp: u64,
    waker_pid: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WakeupScheduleCorrelation {
    pub pid: i32,
    pub wakeup_timestamp: u64,
    pub schedule_timestamp: u64,
    pub wakeup_latency_ns: u64,
    pub waker_pid: u32,
    pub cpu: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchedulingBottleneck {
    pub description: String,
    pub severity: f64,
    pub affected_pids: Vec<i32>,
    pub time_range: (u64, u64),
    pub bottleneck_type: BottleneckType,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BottleneckType {
    HighContextSwitchRate { cpu: u32, rate_hz: f64 },
    LongWakeupLatency { avg_latency_ns: u64 },
    ExcessiveMigration { migration_rate: f64 },
}
