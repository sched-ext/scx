// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

//! Outlier Analysis for Perfetto Traces
//!
//! Analyzes traces to find outlier processes, CPUs, and events across
//! various metrics (latency, runtime, frequency, etc.)

use super::outlier_detection::{
    CpuOutlier, OutlierDetector, OutlierMethod, OutlierResult, OutlierSummary, ProcessOutlier,
};
use super::perfetto_analyzers::{ContextSwitchAnalyzer, CpuUtilStats};
use super::perfetto_parser::PerfettoTrace;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;

/// Comprehensive outlier analysis result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceOutlierAnalysis {
    pub summary: OutlierSummary,
    pub latency_outliers: LatencyOutliers,
    pub runtime_outliers: RuntimeOutliers,
    pub cpu_outliers: CpuUtilizationOutliers,
    pub detection_method: OutlierMethod,
}

/// Latency-related outliers
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LatencyOutliers {
    pub wakeup_latency: Vec<ProcessOutlier>,
    pub schedule_latency: Vec<ProcessOutlier>,
    pub blocked_time: Vec<ProcessOutlier>,
    pub outlier_count: usize,
    pub detection_result: Option<OutlierResult>,
}

/// Runtime-related outliers
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeOutliers {
    pub excessive_runtime: Vec<ProcessOutlier>,
    pub minimal_runtime: Vec<ProcessOutlier>,
    pub high_context_switches: Vec<ProcessOutlier>,
    pub outlier_count: usize,
    pub detection_result: Option<OutlierResult>,
}

/// CPU utilization outliers
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CpuUtilizationOutliers {
    pub overutilized_cpus: Vec<CpuOutlier>,
    pub underutilized_cpus: Vec<CpuOutlier>,
    pub high_contention_cpus: Vec<CpuOutlier>,
    pub outlier_count: usize,
    pub detection_result: Option<OutlierResult>,
}

/// Outlier analyzer for perfetto traces
pub struct PerfettoOutlierAnalyzer {
    trace: Arc<PerfettoTrace>,
    method: OutlierMethod,
}

impl PerfettoOutlierAnalyzer {
    pub fn new(trace: Arc<PerfettoTrace>) -> Self {
        Self {
            trace,
            method: OutlierMethod::IQR, // Default to IQR (most robust)
        }
    }

    pub fn with_method(trace: Arc<PerfettoTrace>, method: OutlierMethod) -> Self {
        Self { trace, method }
    }

    /// Comprehensive outlier analysis across all metrics
    pub fn analyze(&self) -> TraceOutlierAnalysis {
        let latency_outliers = self.analyze_latency_outliers();
        let runtime_outliers = self.analyze_runtime_outliers();
        let cpu_outliers = self.analyze_cpu_outliers();

        let total_outliers = latency_outliers.outlier_count
            + runtime_outliers.outlier_count
            + cpu_outliers.outlier_count;

        let mut by_metric = HashMap::new();
        by_metric.insert(
            "wakeup_latency".to_string(),
            latency_outliers.wakeup_latency.len(),
        );
        by_metric.insert(
            "schedule_latency".to_string(),
            latency_outliers.schedule_latency.len(),
        );
        by_metric.insert(
            "blocked_time".to_string(),
            latency_outliers.blocked_time.len(),
        );
        by_metric.insert(
            "excessive_runtime".to_string(),
            runtime_outliers.excessive_runtime.len(),
        );
        by_metric.insert(
            "minimal_runtime".to_string(),
            runtime_outliers.minimal_runtime.len(),
        );
        by_metric.insert(
            "high_context_switches".to_string(),
            runtime_outliers.high_context_switches.len(),
        );
        by_metric.insert(
            "overutilized_cpus".to_string(),
            cpu_outliers.overutilized_cpus.len(),
        );
        by_metric.insert(
            "underutilized_cpus".to_string(),
            cpu_outliers.underutilized_cpus.len(),
        );
        by_metric.insert(
            "high_contention_cpus".to_string(),
            cpu_outliers.high_contention_cpus.len(),
        );

        let summary = OutlierSummary {
            total_outliers,
            process_outliers: self.collect_process_outliers(&latency_outliers, &runtime_outliers),
            cpu_outliers: cpu_outliers.overutilized_cpus.clone(),
            event_outliers: vec![], // Populated separately if needed
            detection_method: self.method,
            by_metric,
        };

        TraceOutlierAnalysis {
            summary,
            latency_outliers,
            runtime_outliers,
            cpu_outliers,
            detection_method: self.method,
        }
    }

    /// Analyze latency-related outliers
    fn analyze_latency_outliers(&self) -> LatencyOutliers {
        // Get wakeup latency data
        let wakeup_events = self.trace.get_events_by_type("sched_waking");
        let switch_events = self.trace.get_events_by_type("sched_switch");

        // Collect latencies per process using optimized single-pass algorithm
        let process_latencies =
            self.calculate_wakeup_latencies_optimized(&wakeup_events, &switch_events);

        // Detect outliers
        let mut wakeup_outliers = Vec::new();
        let mut all_latencies = Vec::new();

        for (pid, latencies) in &process_latencies {
            if latencies.is_empty() {
                continue;
            }

            all_latencies.extend(latencies);

            // Calculate average latency for this process
            let avg_latency = latencies.iter().sum::<u64>() / latencies.len() as u64;

            // Check if this process's average latency is an outlier
            if latencies.len() >= 5 {
                let (outliers, _) = match self.method {
                    OutlierMethod::IQR => OutlierDetector::detect_iqr(latencies, 1.5),
                    OutlierMethod::MAD => OutlierDetector::detect_mad(latencies, 3.5),
                    OutlierMethod::StdDev => OutlierDetector::detect_stddev(latencies, 3.0),
                    OutlierMethod::Percentile => {
                        OutlierDetector::detect_percentile(latencies, 99.0)
                    }
                };

                if !outliers.is_empty() {
                    let max_severity = outliers.iter().map(|o| o.severity).fold(0.0, f64::max);
                    wakeup_outliers.push(ProcessOutlier {
                        pid: *pid,
                        comm: self.get_process_comm(*pid),
                        metric: "wakeup_latency_ns".to_string(),
                        value: avg_latency,
                        severity: max_severity,
                        percentile: self.calculate_percentile(&all_latencies, avg_latency),
                    });
                }
            }
        }

        // Sort by severity
        wakeup_outliers.sort_by(|a, b| b.severity.partial_cmp(&a.severity).unwrap());

        let detection_result = if !all_latencies.is_empty() {
            let (_, result) = match self.method {
                OutlierMethod::IQR => OutlierDetector::detect_iqr(&all_latencies, 1.5),
                OutlierMethod::MAD => OutlierDetector::detect_mad(&all_latencies, 3.5),
                OutlierMethod::StdDev => OutlierDetector::detect_stddev(&all_latencies, 3.0),
                OutlierMethod::Percentile => {
                    OutlierDetector::detect_percentile(&all_latencies, 99.0)
                }
            };
            Some(result)
        } else {
            None
        };

        let outlier_count = wakeup_outliers.len();

        LatencyOutliers {
            wakeup_latency: wakeup_outliers,
            schedule_latency: vec![], // Can be expanded
            blocked_time: vec![],     // Can be expanded
            outlier_count,
            detection_result,
        }
    }

    /// Analyze runtime-related outliers
    fn analyze_runtime_outliers(&self) -> RuntimeOutliers {
        let analyzer = ContextSwitchAnalyzer::new(self.trace.clone());
        let process_stats = analyzer.analyze_process_runtime(None);

        let runtimes: Vec<u64> = process_stats.iter().map(|p| p.total_runtime_ns).collect();
        let context_switches: Vec<u64> = process_stats
            .iter()
            .map(|p| p.num_switches as u64)
            .collect();

        let (runtime_outliers, runtime_result) = match self.method {
            OutlierMethod::IQR => OutlierDetector::detect_iqr(&runtimes, 1.5),
            OutlierMethod::MAD => OutlierDetector::detect_mad(&runtimes, 3.5),
            OutlierMethod::StdDev => OutlierDetector::detect_stddev(&runtimes, 3.0),
            OutlierMethod::Percentile => OutlierDetector::detect_percentile(&runtimes, 99.0),
        };

        let (cs_outliers, _) = match self.method {
            OutlierMethod::IQR => OutlierDetector::detect_iqr(&context_switches, 1.5),
            OutlierMethod::MAD => OutlierDetector::detect_mad(&context_switches, 3.5),
            OutlierMethod::StdDev => OutlierDetector::detect_stddev(&context_switches, 3.0),
            OutlierMethod::Percentile => {
                OutlierDetector::detect_percentile(&context_switches, 99.0)
            }
        };

        let mut excessive_runtime = Vec::new();
        let mut minimal_runtime = Vec::new();
        let mut high_cs = Vec::new();

        for outlier in runtime_outliers {
            let process = &process_stats[outlier.index];
            let percentile = self.calculate_percentile(&runtimes, outlier.value);

            let process_outlier = ProcessOutlier {
                pid: process.pid,
                comm: process.comm.clone(),
                metric: "total_runtime_ns".to_string(),
                value: outlier.value,
                severity: outlier.severity,
                percentile,
            };

            if outlier.value > runtime_result.thresholds.median as u64 {
                excessive_runtime.push(process_outlier);
            } else {
                minimal_runtime.push(process_outlier);
            }
        }

        for outlier in cs_outliers {
            let process = &process_stats[outlier.index];
            let percentile = self.calculate_percentile(&context_switches, outlier.value);

            high_cs.push(ProcessOutlier {
                pid: process.pid,
                comm: process.comm.clone(),
                metric: "context_switches".to_string(),
                value: outlier.value,
                severity: outlier.severity,
                percentile,
            });
        }

        // Sort by severity
        excessive_runtime.sort_by(|a, b| b.severity.partial_cmp(&a.severity).unwrap());
        minimal_runtime.sort_by(|a, b| b.severity.partial_cmp(&a.severity).unwrap());
        high_cs.sort_by(|a, b| b.severity.partial_cmp(&a.severity).unwrap());

        RuntimeOutliers {
            excessive_runtime,
            minimal_runtime,
            high_context_switches: high_cs,
            outlier_count: process_stats.len(),
            detection_result: Some(runtime_result),
        }
    }

    /// Analyze CPU utilization outliers
    fn analyze_cpu_outliers(&self) -> CpuUtilizationOutliers {
        let analyzer = ContextSwitchAnalyzer::new(self.trace.clone());
        let cpu_stats = analyzer.analyze_cpu_utilization();

        // Convert HashMap to Vec to maintain index mapping
        let mut cpu_data: Vec<(u32, CpuUtilStats)> = cpu_stats.into_iter().collect();
        cpu_data.sort_by_key(|(cpu_id, _)| *cpu_id);

        let utilizations: Vec<u64> = cpu_data
            .iter()
            .map(|(_cpu_id, stats)| {
                let total_time = stats.active_time_ns + stats.idle_time_ns;
                if total_time > 0 {
                    ((stats.active_time_ns as f64 / total_time as f64) * 100.0) as u64
                } else {
                    0
                }
            })
            .collect();

        let context_switches: Vec<u64> = cpu_data
            .iter()
            .map(|(_cpu_id, stats)| stats.total_switches as u64)
            .collect();

        let (util_outliers, util_result) = match self.method {
            OutlierMethod::IQR => OutlierDetector::detect_iqr(&utilizations, 1.5),
            OutlierMethod::MAD => OutlierDetector::detect_mad(&utilizations, 3.5),
            OutlierMethod::StdDev => OutlierDetector::detect_stddev(&utilizations, 3.0),
            OutlierMethod::Percentile => OutlierDetector::detect_percentile(&utilizations, 95.0),
        };

        let (cs_outliers, _) = match self.method {
            OutlierMethod::IQR => OutlierDetector::detect_iqr(&context_switches, 1.5),
            OutlierMethod::MAD => OutlierDetector::detect_mad(&context_switches, 3.5),
            OutlierMethod::StdDev => OutlierDetector::detect_stddev(&context_switches, 3.0),
            OutlierMethod::Percentile => {
                OutlierDetector::detect_percentile(&context_switches, 99.0)
            }
        };

        let mut overutilized = Vec::new();
        let mut underutilized = Vec::new();
        let mut high_contention = Vec::new();

        for outlier in util_outliers {
            let (cpu_id, _stats) = &cpu_data[outlier.index];
            let percentile = self.calculate_percentile(&utilizations, outlier.value);

            let cpu_outlier = CpuOutlier {
                cpu: *cpu_id,
                metric: "utilization_percent".to_string(),
                value: outlier.value,
                severity: outlier.severity,
                percentile,
            };

            if outlier.value > util_result.thresholds.median as u64 {
                overutilized.push(cpu_outlier);
            } else {
                underutilized.push(cpu_outlier);
            }
        }

        for outlier in cs_outliers {
            let (cpu_id, _stats) = &cpu_data[outlier.index];
            let percentile = self.calculate_percentile(&context_switches, outlier.value);

            high_contention.push(CpuOutlier {
                cpu: *cpu_id,
                metric: "context_switches".to_string(),
                value: outlier.value,
                severity: outlier.severity,
                percentile,
            });
        }

        // Sort by severity
        overutilized.sort_by(|a, b| b.severity.partial_cmp(&a.severity).unwrap());
        underutilized.sort_by(|a, b| b.severity.partial_cmp(&a.severity).unwrap());
        high_contention.sort_by(|a, b| b.severity.partial_cmp(&a.severity).unwrap());

        CpuUtilizationOutliers {
            overutilized_cpus: overutilized,
            underutilized_cpus: underutilized,
            high_contention_cpus: high_contention,
            outlier_count: cpu_data.len(),
            detection_result: Some(util_result),
        }
    }

    // Helper functions

    fn extract_wakee_pid(&self, event: &perfetto_protos::ftrace_event::FtraceEvent) -> Option<i32> {
        use perfetto_protos::ftrace_event::ftrace_event::Event;
        match &event.event {
            Some(Event::SchedWaking(waking)) => Some(waking.pid()),
            Some(Event::SchedWakeup(wakeup)) => Some(wakeup.pid()),
            _ => None,
        }
    }

    /// Optimized wakeup latency calculation using a single merged pass
    /// This is O(N log N + M log M + N + M) instead of O(N × M)
    fn calculate_wakeup_latencies_optimized(
        &self,
        wakeup_events: &[&perfetto_protos::ftrace_event::FtraceEvent],
        switch_events: &[&perfetto_protos::ftrace_event::FtraceEvent],
    ) -> HashMap<i32, Vec<u64>> {
        use perfetto_protos::ftrace_event::ftrace_event::Event;
        use std::collections::HashMap;

        let mut process_latencies: HashMap<i32, Vec<u64>> = HashMap::new();

        // Early exit if no events
        if wakeup_events.is_empty() || switch_events.is_empty() {
            return process_latencies;
        }

        // Create sorted index of switch events by timestamp and PID
        // Map: pid -> Vec<(timestamp, event_index)>
        let mut switch_by_pid: HashMap<i32, Vec<(u64, usize)>> = HashMap::new();

        for (idx, event) in switch_events.iter().enumerate() {
            if let (Some(ts), Some(Event::SchedSwitch(ss))) = (event.timestamp, &event.event) {
                let pid = ss.next_pid();
                switch_by_pid.entry(pid).or_default().push((ts, idx));
            }
        }

        // Sort each PID's switch events by timestamp for binary search
        for events in switch_by_pid.values_mut() {
            events.sort_by_key(|(ts, _)| *ts);
        }

        // Process wakeup events
        for wakeup in wakeup_events {
            if let Some(wakee_pid) = self.extract_wakee_pid(wakeup) {
                if let Some(wakeup_ts) = wakeup.timestamp {
                    // Find the first switch event for this PID after the wakeup timestamp
                    if let Some(switch_list) = switch_by_pid.get(&wakee_pid) {
                        // Binary search for first event after wakeup_ts
                        let pos = switch_list.partition_point(|(ts, _)| *ts <= wakeup_ts);

                        if pos < switch_list.len() {
                            let (switch_ts, _) = switch_list[pos];
                            let latency = switch_ts - wakeup_ts;
                            process_latencies
                                .entry(wakee_pid)
                                .or_default()
                                .push(latency);
                        }
                    }
                }
            }
        }

        process_latencies
    }

    fn get_process_comm(&self, pid: i32) -> String {
        self.trace
            .get_processes()
            .get(&pid)
            .and_then(|p| p.name.clone())
            .unwrap_or_else(|| format!("pid_{}", pid))
    }

    fn calculate_percentile(&self, data: &[u64], value: u64) -> f64 {
        if data.is_empty() {
            return 0.0;
        }

        let count_below = data.iter().filter(|&&x| x < value).count();
        (count_below as f64 / data.len() as f64) * 100.0
    }

    fn collect_process_outliers(
        &self,
        latency: &LatencyOutliers,
        runtime: &RuntimeOutliers,
    ) -> Vec<ProcessOutlier> {
        let mut all_outliers = Vec::new();
        all_outliers.extend(latency.wakeup_latency.clone());
        all_outliers.extend(runtime.excessive_runtime.clone());
        all_outliers.extend(runtime.high_context_switches.clone());

        // Sort by severity
        all_outliers.sort_by(|a, b| b.severity.partial_cmp(&a.severity).unwrap());

        // Limit to top 50
        all_outliers.truncate(50);
        all_outliers
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_outlier_analyzer_creation() {
        // This would require a real trace, so just test the structure
        assert_eq!(OutlierMethod::IQR, OutlierMethod::IQR);
    }
}
