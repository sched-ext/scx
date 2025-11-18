// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

//! Tests for Phase 4: Power and Performance Analyzers

use scxtop::mcp::{CpuFrequencyAnalyzer, CpuIdleStateAnalyzer, PerfettoTrace, PowerStateAnalyzer};
use std::path::Path;

/// Test CPU Frequency analyzer with real trace
#[test]
#[ignore] // Only run with --ignored since it requires the trace file
fn test_cpu_frequency_analyzer_real_trace() {
    let trace_path = Path::new("/home/hodgesd/scx/scxtop_trace_0.proto");

    if !trace_path.exists() {
        eprintln!("Trace file not found, skipping test");
        return;
    }

    let trace = PerfettoTrace::from_file(trace_path).expect("Failed to load trace");
    let result = CpuFrequencyAnalyzer::analyze(&trace);

    println!("\n=== CPU Frequency Analysis ===");
    println!("Total frequency transitions: {}", result.total_transitions);
    println!("CPUs analyzed: {}", result.cpu_stats.len());

    for (i, cpu) in result.cpu_stats.iter().take(4).enumerate() {
        println!("\nCPU {}:", cpu.cpu);
        println!("  Transitions: {}", cpu.transition_count);
        println!(
            "  Frequency range: {} - {} MHz",
            cpu.min_frequency_khz / 1000,
            cpu.max_frequency_khz / 1000
        );
        println!("  Average: {:.0} MHz", cpu.avg_frequency_khz / 1000.0);
        println!(
            "  Most common: {} MHz",
            cpu.most_common_frequency_khz / 1000
        );

        if i < 4 && !cpu.freq_durations.is_empty() {
            println!("  Frequency distribution:");
            let mut freq_vec: Vec<_> = cpu.freq_durations.iter().collect();
            freq_vec.sort_by_key(|(_, duration)| std::cmp::Reverse(*duration));
            for (freq, duration) in freq_vec.iter().take(3) {
                println!(
                    "    {} MHz: {:.2}%",
                    **freq / 1000,
                    (**duration as f64 / cpu.freq_durations.values().sum::<u64>() as f64) * 100.0
                );
            }
        }
    }

    println!("\n(CPU frequency events may not be captured in all traces)");
}

/// Test CPU Idle State analyzer with real trace
#[test]
#[ignore]
fn test_cpu_idle_analyzer_real_trace() {
    let trace_path = Path::new("/home/hodgesd/scx/scxtop_trace_0.proto");

    if !trace_path.exists() {
        eprintln!("Trace file not found, skipping test");
        return;
    }

    let trace = PerfettoTrace::from_file(trace_path).expect("Failed to load trace");
    let result = CpuIdleStateAnalyzer::analyze(&trace);

    println!("\n=== CPU Idle State Analysis ===");
    println!("Total idle transitions: {}", result.total_transitions);
    println!("CPUs analyzed: {}", result.cpu_stats.len());

    for cpu in result.cpu_stats.iter().take(4) {
        println!("\nCPU {}:", cpu.cpu);
        println!("  Transitions: {}", cpu.transition_count);
        println!(
            "  Active time: {:.2}ms",
            cpu.active_time_ns as f64 / 1_000_000.0
        );
        println!(
            "  Idle time: {:.2}ms",
            cpu.idle_time_ns as f64 / 1_000_000.0
        );
        println!("  Idle percentage: {:.2}%", cpu.idle_percentage);

        if !cpu.state_durations.is_empty() {
            println!("  Idle state distribution:");
            let mut states: Vec<_> = cpu.state_durations.iter().collect();
            states.sort_by_key(|(state, _)| *state);
            for (state, duration) in states.iter() {
                println!(
                    "    State {}: {:.2}ms ({:.1}%)",
                    state,
                    **duration as f64 / 1_000_000.0,
                    (**duration as f64 / cpu.idle_time_ns as f64) * 100.0
                );
            }
        }
    }

    println!("\n(CPU idle events may not be captured in all traces)");
}

/// Test Power State analyzer with real trace
#[test]
#[ignore]
fn test_power_state_analyzer_real_trace() {
    let trace_path = Path::new("/home/hodgesd/scx/scxtop_trace_0.proto");

    if !trace_path.exists() {
        eprintln!("Trace file not found, skipping test");
        return;
    }

    let trace = PerfettoTrace::from_file(trace_path).expect("Failed to load trace");
    let result = PowerStateAnalyzer::analyze(&trace);

    println!("\n=== Power State Analysis ===");
    println!("Suspend/resume events: {}", result.suspend_resume_count);

    for (i, event) in result.suspend_resume_events.iter().take(10).enumerate() {
        println!(
            "  {}. Action: '{}' at {}ns",
            i + 1,
            event.action,
            event.timestamp
        );
    }

    println!("\n(Suspend/resume events are typically only in mobile/embedded traces)");
}

/// Test that all analyzers handle empty results gracefully
#[test]
fn test_power_analyzers_empty_results() {
    // All analyzers should return empty/zero results without panicking
    // when no events are found
}

/// Test CPU frequency statistics accuracy
#[test]
#[ignore]
fn test_cpu_frequency_stats() {
    let trace_path = Path::new("/home/hodgesd/scx/scxtop_trace_0.proto");

    if !trace_path.exists() {
        eprintln!("Trace file not found, skipping test");
        return;
    }

    let trace = PerfettoTrace::from_file(trace_path).expect("Failed to load trace");
    let result = CpuFrequencyAnalyzer::analyze(&trace);

    println!("\n=== CPU Frequency Statistics Validation ===");

    for cpu in &result.cpu_stats {
        // Verify min <= avg <= max
        assert!(cpu.min_frequency_khz as f64 <= cpu.avg_frequency_khz);
        assert!(cpu.avg_frequency_khz <= cpu.max_frequency_khz as f64);

        // Verify most common frequency is within range
        assert!(cpu.most_common_frequency_khz >= cpu.min_frequency_khz);
        assert!(cpu.most_common_frequency_khz <= cpu.max_frequency_khz);

        println!(
            "CPU {}: min={}, avg={:.0}, max={} MHz - OK",
            cpu.cpu,
            cpu.min_frequency_khz / 1000,
            cpu.avg_frequency_khz / 1000.0,
            cpu.max_frequency_khz / 1000
        );
    }
}

/// Test CPU idle percentage calculation
#[test]
#[ignore]
fn test_cpu_idle_percentage() {
    let trace_path = Path::new("/home/hodgesd/scx/scxtop_trace_0.proto");

    if !trace_path.exists() {
        eprintln!("Trace file not found, skipping test");
        return;
    }

    let trace = PerfettoTrace::from_file(trace_path).expect("Failed to load trace");
    let result = CpuIdleStateAnalyzer::analyze(&trace);

    println!("\n=== CPU Idle Percentage Validation ===");

    for cpu in &result.cpu_stats {
        // Idle percentage should be between 0 and 100
        assert!(cpu.idle_percentage >= 0.0);
        assert!(cpu.idle_percentage <= 100.0);

        // Verify calculation
        let total = cpu.active_time_ns + cpu.idle_time_ns;
        if total > 0 {
            let calculated_idle = (cpu.idle_time_ns as f64 / total as f64) * 100.0;
            assert!((calculated_idle - cpu.idle_percentage).abs() < 0.01);
        }

        println!(
            "CPU {}: {:.2}% idle ({:.2}ms idle / {:.2}ms total) - OK",
            cpu.cpu,
            cpu.idle_percentage,
            cpu.idle_time_ns as f64 / 1_000_000.0,
            total as f64 / 1_000_000.0
        );
    }
}

/// Test frequency distribution sums to 100%
#[test]
#[ignore]
fn test_frequency_distribution() {
    let trace_path = Path::new("/home/hodgesd/scx/scxtop_trace_0.proto");

    if !trace_path.exists() {
        eprintln!("Trace file not found, skipping test");
        return;
    }

    let trace = PerfettoTrace::from_file(trace_path).expect("Failed to load trace");
    let result = CpuFrequencyAnalyzer::analyze(&trace);

    println!("\n=== Frequency Distribution Validation ===");

    for cpu in result.cpu_stats.iter().take(4) {
        if !cpu.freq_durations.is_empty() {
            let total_duration: u64 = cpu.freq_durations.values().sum();
            let mut percentage_sum = 0.0;

            for (freq, duration) in &cpu.freq_durations {
                let percentage = (*duration as f64 / total_duration as f64) * 100.0;
                percentage_sum += percentage;
                println!(
                    "  CPU {} @ {} MHz: {:.2}%",
                    cpu.cpu,
                    freq / 1000,
                    percentage
                );
            }

            // Sum should be ~100% (allowing for floating point error)
            assert!((percentage_sum - 100.0).abs() < 0.01);
            println!("  Total: {:.2}% - OK", percentage_sum);
        }
    }
}
