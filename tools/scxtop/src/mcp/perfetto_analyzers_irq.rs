// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

//! Phase 2: IRQ and Synchronization Analyzers
//!
//! Analyzers for interrupt handling, lock contention, and synchronization events

use super::perfetto_parser::{Percentiles, PerfettoTrace};
use perfetto_protos::ftrace_event::ftrace_event;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// IRQ Handler Analyzer - analyzes hardware interrupt handling
pub struct IrqHandlerAnalyzer;

impl IrqHandlerAnalyzer {
    /// Analyze IRQ handler entry/exit events
    pub fn analyze(trace: &PerfettoTrace) -> IrqAnalysisResult {
        let mut irq_stats: HashMap<u32, IrqStats> = HashMap::new();
        let mut per_cpu_irq: HashMap<u32, Vec<IrqEvent>> = HashMap::new();

        // Track IRQ entry/exit pairs
        let mut pending_entry: HashMap<(u32, u32), IrqEvent> = HashMap::new(); // (cpu, irq) -> entry event

        // Scan all CPUs
        for cpu in 0..trace.num_cpus() {
            let events = trace.get_events_by_cpu(cpu as u32);

            for event_with_idx in events {
                match &event_with_idx.event.event {
                    Some(ftrace_event::Event::IrqHandlerEntry(entry)) => {
                        if let (Some(irq), Some(ts)) = (entry.irq, event_with_idx.event.timestamp) {
                            let irq_event = IrqEvent {
                                irq: irq as u32,
                                cpu: cpu as u32,
                                entry_ts: ts,
                                exit_ts: None,
                                duration_ns: None,
                            };
                            pending_entry.insert((cpu as u32, irq as u32), irq_event);
                        }
                    }
                    Some(ftrace_event::Event::IrqHandlerExit(exit)) => {
                        if let (Some(irq), Some(exit_ts)) =
                            (exit.irq, event_with_idx.event.timestamp)
                        {
                            if let Some(mut entry_event) =
                                pending_entry.remove(&(cpu as u32, irq as u32))
                            {
                                let duration = exit_ts - entry_event.entry_ts;
                                entry_event.exit_ts = Some(exit_ts);
                                entry_event.duration_ns = Some(duration);

                                // Update stats
                                let stats =
                                    irq_stats.entry(irq as u32).or_insert_with(|| IrqStats {
                                        irq: irq as u32,
                                        count: 0,
                                        total_duration_ns: 0,
                                        durations: Vec::new(),
                                    });
                                stats.count += 1;
                                stats.total_duration_ns += duration;
                                stats.durations.push(duration);

                                // Track per-CPU
                                per_cpu_irq.entry(cpu as u32).or_default().push(entry_event);
                            }
                        }
                    }
                    _ => {}
                }
            }
        }

        // Calculate percentiles for each IRQ
        let mut irq_summary: Vec<IrqSummary> = irq_stats
            .into_iter()
            .map(|(irq, stats)| {
                let percentiles = PerfettoTrace::calculate_percentiles(&stats.durations);
                IrqSummary {
                    irq,
                    count: stats.count,
                    total_duration_ns: stats.total_duration_ns,
                    percentiles,
                }
            })
            .collect();

        // Sort by total time spent
        irq_summary.sort_by_key(|s| std::cmp::Reverse(s.total_duration_ns));

        IrqAnalysisResult {
            irq_summary,
            per_cpu_irq,
        }
    }
}

/// IPI Analyzer - analyzes Inter-Processor Interrupts
pub struct IpiAnalyzer;

impl IpiAnalyzer {
    /// Analyze IPI entry/exit/raise events
    pub fn analyze(trace: &PerfettoTrace) -> IpiAnalysisResult {
        let mut ipi_events: Vec<IpiEvent> = Vec::new();
        let mut per_cpu_ipi: HashMap<u32, Vec<IpiEvent>> = HashMap::new();

        // Track IPI entry/exit pairs
        let mut pending_entry: HashMap<u32, IpiEvent> = HashMap::new(); // cpu -> entry event

        // Scan all CPUs
        for cpu in 0..trace.num_cpus() {
            let events = trace.get_events_by_cpu(cpu as u32);

            for event_with_idx in events {
                match &event_with_idx.event.event {
                    Some(ftrace_event::Event::IpiEntry(entry)) => {
                        if let Some(ts) = event_with_idx.event.timestamp {
                            let ipi_event = IpiEvent {
                                cpu: cpu as u32,
                                reason: entry.reason.clone().unwrap_or_default(),
                                entry_ts: ts,
                                exit_ts: None,
                                duration_ns: None,
                            };
                            pending_entry.insert(cpu as u32, ipi_event);
                        }
                    }
                    Some(ftrace_event::Event::IpiExit(exit)) => {
                        if let Some(exit_ts) = event_with_idx.event.timestamp {
                            if let Some(mut entry_event) = pending_entry.remove(&(cpu as u32)) {
                                let duration = exit_ts - entry_event.entry_ts;
                                entry_event.exit_ts = Some(exit_ts);
                                entry_event.duration_ns = Some(duration);
                                entry_event.reason = exit.reason.clone().unwrap_or_default();

                                per_cpu_ipi
                                    .entry(cpu as u32)
                                    .or_default()
                                    .push(entry_event.clone());
                                ipi_events.push(entry_event);
                            }
                        }
                    }
                    _ => {}
                }
            }
        }

        // Calculate stats per IPI reason
        let mut reason_stats: HashMap<String, IpiReasonStats> = HashMap::new();
        for event in &ipi_events {
            if let Some(duration) = event.duration_ns {
                let stats =
                    reason_stats
                        .entry(event.reason.clone())
                        .or_insert_with(|| IpiReasonStats {
                            reason: event.reason.clone(),
                            count: 0,
                            durations: Vec::new(),
                        });
                stats.count += 1;
                stats.durations.push(duration);
            }
        }

        let reason_summary: Vec<IpiReasonSummary> = reason_stats
            .into_iter()
            .map(|(reason, stats)| {
                let percentiles = PerfettoTrace::calculate_percentiles(&stats.durations);
                IpiReasonSummary {
                    reason,
                    count: stats.count,
                    percentiles,
                }
            })
            .collect();

        IpiAnalysisResult {
            ipi_events,
            per_cpu_ipi,
            reason_summary,
        }
    }
}

// ============================================================================
// Data Structures
// ============================================================================

/// IRQ event with entry/exit timing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IrqEvent {
    pub irq: u32,
    pub cpu: u32,
    pub entry_ts: u64,
    pub exit_ts: Option<u64>,
    pub duration_ns: Option<u64>,
}

/// IRQ statistics (internal)
struct IrqStats {
    #[allow(dead_code)]
    irq: u32,
    count: usize,
    total_duration_ns: u64,
    durations: Vec<u64>,
}

/// IRQ summary with percentiles
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IrqSummary {
    pub irq: u32,
    pub count: usize,
    pub total_duration_ns: u64,
    pub percentiles: Percentiles,
}

/// IRQ analysis result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IrqAnalysisResult {
    pub irq_summary: Vec<IrqSummary>,
    pub per_cpu_irq: HashMap<u32, Vec<IrqEvent>>,
}

/// IPI event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpiEvent {
    pub cpu: u32,
    pub reason: String,
    pub entry_ts: u64,
    pub exit_ts: Option<u64>,
    pub duration_ns: Option<u64>,
}

/// IPI reason statistics (internal)
struct IpiReasonStats {
    #[allow(dead_code)]
    reason: String,
    count: usize,
    durations: Vec<u64>,
}

/// IPI reason summary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpiReasonSummary {
    pub reason: String,
    pub count: usize,
    pub percentiles: Percentiles,
}

/// IPI analysis result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpiAnalysisResult {
    pub ipi_events: Vec<IpiEvent>,
    pub per_cpu_ipi: HashMap<u32, Vec<IpiEvent>>,
    pub reason_summary: Vec<IpiReasonSummary>,
}

#[cfg(test)]
mod tests {

    #[test]
    fn test_irq_analyzer_empty_trace() {
        // Test with mock empty trace would go here
        // For now, this is a placeholder
    }

    #[test]
    fn test_ipi_analyzer_empty_trace() {
        // Test with mock empty trace would go here
    }
}
