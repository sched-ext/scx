// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

//! Phase 4: Power and Performance Analyzers
//!
//! Analyzers for CPU frequency scaling, idle states, and power management

use super::perfetto_parser::PerfettoTrace;
use perfetto_protos::ftrace_event::ftrace_event;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// CPU Frequency Analyzer - analyzes CPU frequency scaling behavior
pub struct CpuFrequencyAnalyzer;

impl CpuFrequencyAnalyzer {
    /// Analyze CPU frequency changes across all CPUs
    pub fn analyze(trace: &PerfettoTrace) -> CpuFrequencyResult {
        let mut per_cpu_freq: HashMap<u32, Vec<FrequencyEvent>> = HashMap::new();
        let mut per_cpu_current_freq: HashMap<u32, u32> = HashMap::new();

        // Scan all CPUs
        for cpu in 0..trace.num_cpus() {
            let events = trace.get_events_by_cpu(cpu as u32);

            for event_with_idx in events {
                if let Some(ftrace_event::Event::CpuFrequency(freq)) = &event_with_idx.event.event {
                    if let (Some(state), Some(ts)) = (freq.state, event_with_idx.event.timestamp) {
                        let freq_khz = state;

                        let event = FrequencyEvent {
                            cpu: cpu as u32,
                            frequency_khz: freq_khz,
                            timestamp: ts,
                        };

                        per_cpu_freq.entry(cpu as u32).or_default().push(event);
                        per_cpu_current_freq.insert(cpu as u32, freq_khz);
                    }
                }
            }
        }

        // Calculate statistics per CPU
        let mut cpu_stats: Vec<CpuFrequencyStats> = Vec::new();

        for (cpu, events) in &per_cpu_freq {
            if events.is_empty() {
                continue;
            }

            // Calculate time spent at each frequency
            let mut freq_durations: HashMap<u32, u64> = HashMap::new();
            let mut frequencies: Vec<u32> = Vec::new();

            for i in 0..events.len() {
                let current = &events[i];
                frequencies.push(current.frequency_khz);

                if i + 1 < events.len() {
                    let next = &events[i + 1];
                    let duration = next.timestamp - current.timestamp;
                    *freq_durations.entry(current.frequency_khz).or_insert(0) += duration;
                }
            }

            // Calculate statistics
            let min_freq = frequencies.iter().min().copied().unwrap_or(0);
            let max_freq = frequencies.iter().max().copied().unwrap_or(0);
            let avg_freq = if !frequencies.is_empty() {
                frequencies.iter().sum::<u32>() as f64 / frequencies.len() as f64
            } else {
                0.0
            };

            // Find most common frequency
            let most_common_freq = freq_durations
                .iter()
                .max_by_key(|(_, duration)| *duration)
                .map(|(freq, _)| *freq)
                .unwrap_or(0);

            cpu_stats.push(CpuFrequencyStats {
                cpu: *cpu,
                transition_count: events.len(),
                min_frequency_khz: min_freq,
                max_frequency_khz: max_freq,
                avg_frequency_khz: avg_freq,
                most_common_frequency_khz: most_common_freq,
                freq_durations,
            });
        }

        // Sort by CPU number
        cpu_stats.sort_by_key(|s| s.cpu);

        CpuFrequencyResult {
            total_transitions: per_cpu_freq.values().map(|v| v.len()).sum(),
            cpu_stats,
        }
    }
}

/// CPU Idle State Analyzer - analyzes CPU idle state transitions
pub struct CpuIdleStateAnalyzer;

impl CpuIdleStateAnalyzer {
    /// Analyze CPU idle state behavior
    pub fn analyze(trace: &PerfettoTrace) -> CpuIdleResult {
        let mut per_cpu_idle: HashMap<u32, Vec<IdleEvent>> = HashMap::new();

        // Scan all CPUs
        for cpu in 0..trace.num_cpus() {
            let events = trace.get_events_by_cpu(cpu as u32);

            for event_with_idx in events {
                if let Some(ftrace_event::Event::CpuIdle(idle)) = &event_with_idx.event.event {
                    if let (Some(state), Some(ts)) = (idle.state, event_with_idx.event.timestamp) {
                        let event = IdleEvent {
                            cpu: cpu as u32,
                            state: state as i32,
                            timestamp: ts,
                        };

                        per_cpu_idle.entry(cpu as u32).or_default().push(event);
                    }
                }
            }
        }

        // Calculate statistics per CPU
        let mut cpu_stats: Vec<CpuIdleStats> = Vec::new();

        for (cpu, events) in &per_cpu_idle {
            if events.is_empty() {
                continue;
            }

            // Calculate time in each idle state
            let mut state_durations: HashMap<i32, u64> = HashMap::new();
            let mut active_time = 0u64;
            let mut idle_time = 0u64;

            for i in 0..events.len() {
                let current = &events[i];

                if i + 1 < events.len() {
                    let next = &events[i + 1];
                    let duration = next.timestamp - current.timestamp;

                    if current.state == -1 || current.state == 4294967295u32 as i32 {
                        // State -1 or 0xFFFFFFFF means active (exiting idle)
                        active_time += duration;
                    } else {
                        // Positive state means idle
                        idle_time += duration;
                        *state_durations.entry(current.state).or_insert(0) += duration;
                    }
                }
            }

            let total_time = active_time + idle_time;
            let idle_percentage = if total_time > 0 {
                (idle_time as f64 / total_time as f64) * 100.0
            } else {
                0.0
            };

            cpu_stats.push(CpuIdleStats {
                cpu: *cpu,
                transition_count: events.len(),
                active_time_ns: active_time,
                idle_time_ns: idle_time,
                idle_percentage,
                state_durations,
            });
        }

        // Sort by CPU number
        cpu_stats.sort_by_key(|s| s.cpu);

        CpuIdleResult {
            total_transitions: per_cpu_idle.values().map(|v| v.len()).sum(),
            cpu_stats,
        }
    }
}

/// Power State Analyzer - analyzes system suspend/resume events
pub struct PowerStateAnalyzer;

impl PowerStateAnalyzer {
    /// Analyze system power state transitions
    pub fn analyze(trace: &PerfettoTrace) -> PowerStateResult {
        let mut suspend_resume_events: Vec<SuspendResumeEvent> = Vec::new();

        // Scan all CPUs for suspend/resume events
        for cpu in 0..trace.num_cpus() {
            let events = trace.get_events_by_cpu(cpu as u32);

            for event_with_idx in events {
                if let Some(ftrace_event::Event::SuspendResume(sr)) = &event_with_idx.event.event {
                    if let Some(ts) = event_with_idx.event.timestamp {
                        let event = SuspendResumeEvent {
                            action: sr.action.clone().unwrap_or_default(),
                            timestamp: ts,
                        };
                        suspend_resume_events.push(event);
                    }
                }
            }
        }

        // Sort by timestamp
        suspend_resume_events.sort_by_key(|e| e.timestamp);

        PowerStateResult {
            suspend_resume_count: suspend_resume_events.len(),
            suspend_resume_events,
        }
    }
}

// ============================================================================
// Data Structures
// ============================================================================

/// CPU frequency event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FrequencyEvent {
    pub cpu: u32,
    pub frequency_khz: u32,
    pub timestamp: u64,
}

/// CPU frequency statistics per CPU
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CpuFrequencyStats {
    pub cpu: u32,
    pub transition_count: usize,
    pub min_frequency_khz: u32,
    pub max_frequency_khz: u32,
    pub avg_frequency_khz: f64,
    pub most_common_frequency_khz: u32,
    /// Frequency (kHz) -> total duration (ns)
    pub freq_durations: HashMap<u32, u64>,
}

/// CPU frequency analysis result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CpuFrequencyResult {
    pub total_transitions: usize,
    pub cpu_stats: Vec<CpuFrequencyStats>,
}

/// CPU idle state event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdleEvent {
    pub cpu: u32,
    pub state: i32, // -1 = active, 0+ = idle state depth
    pub timestamp: u64,
}

/// CPU idle statistics per CPU
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CpuIdleStats {
    pub cpu: u32,
    pub transition_count: usize,
    pub active_time_ns: u64,
    pub idle_time_ns: u64,
    pub idle_percentage: f64,
    /// Idle state -> total duration (ns)
    pub state_durations: HashMap<i32, u64>,
}

/// CPU idle analysis result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CpuIdleResult {
    pub total_transitions: usize,
    pub cpu_stats: Vec<CpuIdleStats>,
}

/// System suspend/resume event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuspendResumeEvent {
    pub action: String,
    pub timestamp: u64,
}

/// Power state analysis result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PowerStateResult {
    pub suspend_resume_count: usize,
    pub suspend_resume_events: Vec<SuspendResumeEvent>,
}

#[cfg(test)]
mod tests {

    #[test]
    fn test_cpu_frequency_analyzer_empty() {
        // Placeholder for mock tests
    }

    #[test]
    fn test_cpu_idle_analyzer_empty() {
        // Placeholder for mock tests
    }

    #[test]
    fn test_power_state_analyzer_empty() {
        // Placeholder for mock tests
    }
}
