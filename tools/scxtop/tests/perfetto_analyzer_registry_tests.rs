// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

//! Tests for Phase 6: Analyzer Registry and Auto-Discovery

use scxtop::mcp::{AnalyzerCategory, AnalyzerRegistry, PerfettoTrace};
use std::path::Path;

/// Test registry creation with built-ins
#[test]
fn test_registry_with_builtins() {
    let registry = AnalyzerRegistry::with_builtins();
    let analyzers = registry.list_analyzers();

    println!("\n=== Registered Analyzers ===");
    println!("Total: {}", analyzers.len());

    assert!(analyzers.len() >= 15); // Should have many analyzers
}

/// Test category filtering
#[test]
fn test_category_filtering() {
    let registry = AnalyzerRegistry::with_builtins();

    let scheduling = registry.list_by_category(AnalyzerCategory::Scheduling);
    let interrupt = registry.list_by_category(AnalyzerCategory::Interrupt);
    let io = registry.list_by_category(AnalyzerCategory::IO);
    let power = registry.list_by_category(AnalyzerCategory::Power);
    let extended = registry.list_by_category(AnalyzerCategory::Extended);

    println!("\n=== Analyzers by Category ===");
    println!("Scheduling: {}", scheduling.len());
    println!("Interrupt: {}", interrupt.len());
    println!("I/O: {}", io.len());
    println!("Power: {}", power.len());
    println!("Extended: {}", extended.len());

    assert!(!scheduling.is_empty());
    assert!(!interrupt.is_empty());
    assert!(!io.is_empty());
    assert!(!power.is_empty());
    assert!(!extended.is_empty());
}

/// Test analyzer metadata
#[test]
fn test_analyzer_metadata() {
    let registry = AnalyzerRegistry::with_builtins();
    let analyzers = registry.list_analyzers();

    println!("\n=== Analyzer Metadata ===");
    for analyzer in analyzers.iter().take(5) {
        println!("\n{}:", analyzer.name);
        println!("  ID: {}", analyzer.id);
        println!("  Category: {:?}", analyzer.category);
        println!("  Description: {}", analyzer.description);
        println!("  Required events: {:?}", analyzer.required_events);
        println!("  Performance cost: {}/5", analyzer.performance_cost);
        println!("  Requires scx: {}", analyzer.requires_scx);

        // Validate metadata
        assert!(!analyzer.id.is_empty());
        assert!(!analyzer.name.is_empty());
        assert!(!analyzer.description.is_empty());
        assert!(analyzer.performance_cost >= 1 && analyzer.performance_cost <= 5);
    }
}

/// Test analyzer discovery with real trace
#[test]
#[ignore]
fn test_discover_analyzers_real_trace() {
    let trace_path = Path::new("/home/hodgesd/scx/scxtop_trace_0.proto");

    if !trace_path.exists() {
        eprintln!("Trace file not found, skipping test");
        return;
    }

    let trace = PerfettoTrace::from_file(trace_path).expect("Failed to load trace");
    let registry = AnalyzerRegistry::with_builtins();

    let applicable = registry.discover_analyzers(&trace);

    println!("\n=== Applicable Analyzers for Trace ===");
    println!("Total applicable: {}", applicable.len());

    for analyzer in &applicable {
        println!("\n{}:", analyzer.name);
        println!("  Category: {:?}", analyzer.category);
        println!("  Required events: {:?}", analyzer.required_events);
    }

    assert!(!applicable.is_empty());
}

/// Test trace summary
#[test]
#[ignore]
fn test_trace_summary() {
    let trace_path = Path::new("/home/hodgesd/scx/scxtop_trace_0.proto");

    if !trace_path.exists() {
        eprintln!("Trace file not found, skipping test");
        return;
    }

    let trace = PerfettoTrace::from_file(trace_path).expect("Failed to load trace");
    let registry = AnalyzerRegistry::with_builtins();

    let summary = registry.get_trace_summary(&trace);

    println!("\n=== Trace Summary ===");
    println!("Duration: {}ms", summary.trace_duration_ms);
    println!("CPUs: {}", summary.num_cpus);
    println!("Processes: {}", summary.num_processes);
    println!("Total events: {}", summary.total_events);
    println!("Is sched_ext trace: {}", summary.is_scx_trace);
    println!("Applicable analyzers: {}", summary.applicable_analyzers);

    println!("\nAnalyzers by category:");
    for (category, analyzers) in &summary.analyzers_by_category {
        println!("  {}: {} analyzer(s)", category, analyzers.len());
        for analyzer in analyzers {
            println!("    - {}", analyzer);
        }
    }

    assert!(summary.trace_duration_ms > 0);
    assert!(summary.num_cpus > 0);
    assert!(summary.total_events > 0);
    assert!(summary.applicable_analyzers > 0);
}

/// Test running specific analyzer by ID
#[test]
#[ignore]
fn test_run_analyzer_by_id() {
    let trace_path = Path::new("/home/hodgesd/scx/scxtop_trace_0.proto");

    if !trace_path.exists() {
        eprintln!("Trace file not found, skipping test");
        return;
    }

    let trace = PerfettoTrace::from_file(trace_path).expect("Failed to load trace");
    let registry = AnalyzerRegistry::with_builtins();

    // Run CPU utilization analyzer
    if let Some(result) = registry.analyze_by_id("cpu_utilization", std::sync::Arc::new(trace)) {
        println!("\n=== CPU Utilization Analysis ===");
        println!("Analyzer: {}", result.analyzer_id);
        println!("Success: {}", result.success);
        println!("Duration: {}ms", result.duration_ms);

        if let Some(error) = &result.error {
            println!("Error: {}", error);
        }

        assert!(result.success);
        assert!(result.duration_ms > 0);
    } else {
        panic!("Analyzer 'cpu_utilization' not found");
    }
}

/// Test running all analyzers
#[test]
#[ignore]
fn test_run_all_analyzers() {
    let trace_path = Path::new("/home/hodgesd/scx/scxtop_trace_0.proto");

    if !trace_path.exists() {
        eprintln!("Trace file not found, skipping test");
        return;
    }

    let trace = PerfettoTrace::from_file(trace_path).expect("Failed to load trace");
    let registry = AnalyzerRegistry::with_builtins();

    let results = registry.analyze_all(std::sync::Arc::new(trace));

    println!("\n=== Batch Analysis Results ===");
    println!("Total analyzers run: {}", results.len());

    let successful = results.iter().filter(|r| r.success).count();
    let failed = results.iter().filter(|r| !r.success).count();
    let total_time: u64 = results.iter().map(|r| r.duration_ms).sum();

    println!("Successful: {}", successful);
    println!("Failed: {}", failed);
    println!("Total analysis time: {}ms", total_time);

    println!("\nIndividual results:");
    for result in &results {
        let status = if result.success { "✓" } else { "✗" };
        println!(
            "  {} {} ({}ms)",
            status, result.analyzer_id, result.duration_ms
        );
        if let Some(error) = &result.error {
            println!("      Error: {}", error);
        }
    }

    assert!(!results.is_empty());
    assert!(successful > 0);
}

/// Test category-based analysis
#[test]
#[ignore]
fn test_category_analysis() {
    let trace_path = Path::new("/home/hodgesd/scx/scxtop_trace_0.proto");

    if !trace_path.exists() {
        eprintln!("Trace file not found, skipping test");
        return;
    }

    let trace = PerfettoTrace::from_file(trace_path).expect("Failed to load trace");
    let registry = AnalyzerRegistry::with_builtins();

    // Test scheduling analyzers only
    let scheduling_analyzers = registry
        .discover_analyzers(&trace)
        .into_iter()
        .filter(|a| a.category == AnalyzerCategory::Scheduling)
        .collect::<Vec<_>>();

    println!("\n=== Scheduling Analyzers ===");
    println!("Count: {}", scheduling_analyzers.len());

    let results: Vec<_> = scheduling_analyzers
        .iter()
        .filter_map(|metadata| {
            registry.analyze_by_id(&metadata.id, std::sync::Arc::new(trace.clone()))
        })
        .collect();

    println!("Results: {}", results.len());
    for result in &results {
        println!("  {} - {}ms", result.analyzer_id, result.duration_ms);
    }

    assert!(!results.is_empty());
}

/// Test performance cost ordering
#[test]
fn test_performance_cost_ordering() {
    let registry = AnalyzerRegistry::with_builtins();
    let mut analyzers = registry.list_analyzers();

    // Sort by performance cost (ascending)
    analyzers.sort_by_key(|a| a.performance_cost);

    println!("\n=== Analyzers by Performance Cost ===");
    for analyzer in &analyzers {
        println!(
            "  Cost {}/5: {} ({})",
            analyzer.performance_cost, analyzer.name, analyzer.id
        );
    }

    // Verify all costs are valid
    for analyzer in analyzers {
        assert!(analyzer.performance_cost >= 1);
        assert!(analyzer.performance_cost <= 5);
    }
}

/// Test required events validation
#[test]
fn test_required_events() {
    let registry = AnalyzerRegistry::with_builtins();
    let analyzers = registry.list_analyzers();

    println!("\n=== Required Events per Analyzer ===");
    for analyzer in &analyzers {
        println!("{}: {:?}", analyzer.name, analyzer.required_events);

        // Most analyzers should have required events (except query/generic ones)
        if analyzer.category != AnalyzerCategory::Query {
            // DSQ analyzer is special - requires scx trace
            if analyzer.id != "dsq_summary" {
                assert!(
                    !analyzer.required_events.is_empty(),
                    "{} has no required events",
                    analyzer.id
                );
            }
        }
    }
}
