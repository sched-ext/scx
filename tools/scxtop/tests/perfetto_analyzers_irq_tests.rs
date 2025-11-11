// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

//! Tests for Phase 2: IRQ and IPI Analyzers

use scxtop::mcp::{IpiAnalyzer, IrqHandlerAnalyzer, PerfettoTrace};
use std::path::Path;

/// Test IRQ analyzer with real trace
#[test]
#[ignore] // Only run with --ignored since it requires the trace file
fn test_irq_analyzer_real_trace() {
    let trace_path = Path::new("/home/hodgesd/scx/scxtop_trace_0.proto");

    if !trace_path.exists() {
        eprintln!("Trace file not found, skipping test");
        return;
    }

    let trace = PerfettoTrace::from_file(trace_path).expect("Failed to load trace");
    let result = IrqHandlerAnalyzer::analyze(&trace);

    println!("\n=== IRQ Handler Analysis ===");
    println!("Total IRQ types: {}", result.irq_summary.len());

    for (i, irq) in result.irq_summary.iter().take(10).enumerate() {
        println!(
            "  {}. IRQ {}: count={}, total_time={}ns, mean={:.2}ns",
            i + 1,
            irq.irq,
            irq.count,
            irq.total_duration_ns,
            irq.percentiles.mean
        );
    }

    // Verify we got some IRQ data (if IRQs are present in trace)
    if !result.irq_summary.is_empty() {
        assert!(result.irq_summary[0].count > 0);
        assert!(result.irq_summary[0].total_duration_ns > 0);
    }
}

/// Test IPI analyzer with real trace
#[test]
#[ignore] // Only run with --ignored since it requires the trace file
fn test_ipi_analyzer_real_trace() {
    let trace_path = Path::new("/home/hodgesd/scx/scxtop_trace_0.proto");

    if !trace_path.exists() {
        eprintln!("Trace file not found, skipping test");
        return;
    }

    let trace = PerfettoTrace::from_file(trace_path).expect("Failed to load trace");
    let result = IpiAnalyzer::analyze(&trace);

    println!("\n=== IPI Analysis ===");
    println!("Total IPI events: {}", result.ipi_events.len());
    println!("IPI reasons: {}", result.reason_summary.len());

    for (i, reason) in result.reason_summary.iter().take(5).enumerate() {
        println!(
            "  {}. Reason '{}': count={}, mean={:.2}ns",
            i + 1,
            reason.reason,
            reason.count,
            reason.percentiles.mean
        );
    }

    // IPIs may not be present in all traces, so we don't assert on counts
    println!("  (IPIs may not be captured in all traces)");
}

/// Test IRQ analyzer per-CPU breakdown
#[test]
#[ignore]
fn test_irq_analyzer_per_cpu() {
    let trace_path = Path::new("/home/hodgesd/scx/scxtop_trace_0.proto");

    if !trace_path.exists() {
        eprintln!("Trace file not found, skipping test");
        return;
    }

    let trace = PerfettoTrace::from_file(trace_path).expect("Failed to load trace");
    let result = IrqHandlerAnalyzer::analyze(&trace);

    println!("\n=== IRQ Per-CPU Breakdown ===");

    // Show IRQ distribution across CPUs
    for (cpu, events) in result.per_cpu_irq.iter().take(4) {
        println!("  CPU {}: {} IRQ events", cpu, events.len());
    }

    if !result.per_cpu_irq.is_empty() {
        let total_events: usize = result.per_cpu_irq.values().map(|v| v.len()).sum();
        println!("  Total IRQ events across all CPUs: {}", total_events);
    }
}

/// Test IPI analyzer per-CPU breakdown
#[test]
#[ignore]
fn test_ipi_analyzer_per_cpu() {
    let trace_path = Path::new("/home/hodgesd/scx/scxtop_trace_0.proto");

    if !trace_path.exists() {
        eprintln!("Trace file not found, skipping test");
        return;
    }

    let trace = PerfettoTrace::from_file(trace_path).expect("Failed to load trace");
    let result = IpiAnalyzer::analyze(&trace);

    println!("\n=== IPI Per-CPU Breakdown ===");

    for (cpu, events) in result.per_cpu_ipi.iter().take(4) {
        println!("  CPU {}: {} IPI events", cpu, events.len());
    }

    if !result.per_cpu_ipi.is_empty() {
        let total_events: usize = result.per_cpu_ipi.values().map(|v| v.len()).sum();
        println!("  Total IPI events across all CPUs: {}", total_events);
    }
}

/// Test that analyzers handle traces without IRQ/IPI events gracefully
#[test]
fn test_analyzers_empty_results() {
    // This test would need a mock trace with no IRQ/IPI events
    // For now, it's a placeholder to ensure we handle empty results gracefully

    // The analyzers should return empty results without panicking
    // when no events are found
}
