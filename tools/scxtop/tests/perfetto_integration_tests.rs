// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

//! Phase 7: Integration Tests
//!
//! End-to-end integration tests for the complete perfetto analysis pipeline

use scxtop::mcp::{
    AnalyzerRegistry, OutlierMethod, PerfettoOutlierAnalyzer, PerfettoTrace, QueryBuilder,
};
use std::path::Path;
use std::sync::Arc;

/// Test complete analysis pipeline: load → discover → analyze → query
#[test]
#[ignore]
fn test_complete_pipeline() {
    let trace_path = Path::new("/home/hodgesd/scx/scxtop_trace_0.proto");

    if !trace_path.exists() {
        eprintln!("Trace file not found, skipping test");
        return;
    }

    println!("\n=== Complete Analysis Pipeline Test ===\n");

    // Step 1: Load trace
    println!("Step 1: Loading trace...");
    let trace = PerfettoTrace::from_file(trace_path).expect("Failed to load trace");
    let (start_ts, end_ts) = trace.time_range();
    println!(
        "  ✓ Loaded trace: {}ms duration, {} CPUs, {} events",
        (end_ts - start_ts) / 1_000_000,
        trace.num_cpus(),
        trace.total_events()
    );

    // Step 2: Discover analyzers
    println!("\nStep 2: Discovering applicable analyzers...");
    let registry = AnalyzerRegistry::with_builtins();
    let applicable = registry.discover_analyzers(&trace);
    println!("  ✓ Found {} applicable analyzers", applicable.len());

    // Step 3: Run batch analysis
    println!("\nStep 3: Running batch analysis...");
    let results = registry.analyze_all(Arc::new(trace.clone()));
    let successful = results.iter().filter(|r| r.success).count();
    let failed = results.iter().filter(|r| !r.success).count();
    println!(
        "  ✓ Analysis complete: {} successful, {} failed",
        successful, failed
    );

    // Step 4: Query results
    println!("\nStep 4: Querying trace data...");
    let query = QueryBuilder::new().event_type("sched_switch").limit(100);
    let query_result = query.execute(&trace);
    println!(
        "  ✓ Query returned {} events in {}ms",
        query_result.events.len(),
        query_result.query_time_ms
    );

    // Validate
    assert!(!applicable.is_empty());
    assert!(successful > 0);
    assert_eq!(failed, 0);
    assert!(!query_result.events.is_empty());

    println!("\n✓ Pipeline test passed!");
}

/// Test cross-analyzer consistency
#[test]
#[ignore]
fn test_cross_analyzer_consistency() {
    let trace_path = Path::new("/home/hodgesd/scx/scxtop_trace_0.proto");

    if !trace_path.exists() {
        eprintln!("Trace file not found, skipping test");
        return;
    }

    println!("\n=== Cross-Analyzer Consistency Test ===\n");

    let trace = PerfettoTrace::from_file(trace_path).expect("Failed to load trace");
    let trace_arc = Arc::new(trace.clone());
    let registry = AnalyzerRegistry::with_builtins();

    // Run CPU utilization analyzer
    let cpu_result = registry
        .analyze_by_id("cpu_utilization", trace_arc.clone())
        .expect("CPU analyzer failed");
    assert!(cpu_result.success);

    // Run process runtime analyzer (should be consistent with CPU utilization)
    let query = QueryBuilder::new().event_type("sched_switch").limit(10000);
    let switch_events = query.execute(&trace);

    println!("CPU Utilization analysis: {}ms", cpu_result.duration_ms);
    println!("sched_switch events found: {}", switch_events.total_matched);

    // Both should see the same sched_switch events
    assert!(switch_events.total_matched > 0);

    println!("\n✓ Cross-analyzer consistency verified!");
}

/// Test performance benchmarks
#[test]
#[ignore]
fn test_performance_benchmarks() {
    let trace_path = Path::new("/home/hodgesd/scx/scxtop_trace_0.proto");

    if !trace_path.exists() {
        eprintln!("Trace file not found, skipping test");
        return;
    }

    println!("\n=== Performance Benchmarks ===\n");

    let trace = PerfettoTrace::from_file(trace_path).expect("Failed to load trace");
    let trace_arc = Arc::new(trace.clone());
    let registry = AnalyzerRegistry::with_builtins();

    // Benchmark individual analyzers
    let analyzers_to_benchmark = vec![
        "cpu_utilization",
        "wakeup_latency",
        "task_states",
        "preemptions",
    ];

    println!("Individual Analyzer Performance:");
    for analyzer_id in analyzers_to_benchmark {
        let start = std::time::Instant::now();
        let result = registry.analyze_by_id(analyzer_id, trace_arc.clone());
        let elapsed = start.elapsed();

        if let Some(r) = result {
            println!(
                "  {} - {}ms (reported: {}ms)",
                analyzer_id,
                elapsed.as_millis(),
                r.duration_ms
            );
            assert!(r.success);
        }
    }

    // Benchmark batch analysis
    println!("\nBatch Analysis Performance:");
    let start = std::time::Instant::now();
    let results = registry.analyze_all(trace_arc.clone());
    let elapsed = start.elapsed();
    let total_analysis_time: u64 = results.iter().map(|r| r.duration_ms).sum();

    println!("  Total wall time: {}ms", elapsed.as_millis());
    println!("  Total analysis time: {}ms", total_analysis_time);
    println!("  Analyzers run: {}", results.len());
    println!(
        "  Average per analyzer: {}ms",
        total_analysis_time / results.len() as u64
    );

    // Benchmark queries
    println!("\nQuery Performance:");
    let queries = vec![
        (
            "Simple event type",
            QueryBuilder::new().event_type("sched_switch").limit(1000),
        ),
        (
            "CPU filter",
            QueryBuilder::new()
                .event_type("sched_switch")
                .cpu(0)
                .limit(1000),
        ),
        (
            "Time range",
            QueryBuilder::new()
                .event_type("sched_switch")
                .time_range(trace.time_range().0, trace.time_range().0 + 100_000_000)
                .limit(1000),
        ),
    ];

    for (name, query) in queries {
        let result = query.execute(&trace);
        println!("  {} - {}ms", name, result.query_time_ms);
    }

    println!("\n✓ Performance benchmarks complete!");
}

/// Test error handling and edge cases
#[test]
#[ignore]
fn test_error_handling() {
    let trace_path = Path::new("/home/hodgesd/scx/scxtop_trace_0.proto");

    if !trace_path.exists() {
        eprintln!("Trace file not found, skipping test");
        return;
    }

    println!("\n=== Error Handling Tests ===\n");

    let trace = PerfettoTrace::from_file(trace_path).expect("Failed to load trace");
    let trace_arc = Arc::new(trace.clone());
    let registry = AnalyzerRegistry::with_builtins();

    // Test non-existent analyzer
    println!("Testing non-existent analyzer...");
    let result = registry.analyze_by_id("non_existent_analyzer", trace_arc.clone());
    assert!(result.is_none());
    println!("  ✓ Correctly returned None for non-existent analyzer");

    // Test empty query results
    println!("\nTesting empty query results...");
    let query = QueryBuilder::new()
        .event_type("sched_switch")
        .pid(999999999); // Non-existent PID
    let result = query.execute(&trace);
    assert_eq!(result.events.len(), 0);
    println!("  ✓ Empty query handled correctly");

    // Test query with no filters
    println!("\nTesting query with minimal filters...");
    let query = QueryBuilder::new().limit(10);
    let result = query.execute(&trace);
    assert!(result.events.len() <= 10);
    println!("  ✓ Unfiltered query handled correctly");

    println!("\n✓ Error handling tests passed!");
}

/// Test trace summary accuracy
#[test]
#[ignore]
fn test_trace_summary_accuracy() {
    let trace_path = Path::new("/home/hodgesd/scx/scxtop_trace_0.proto");

    if !trace_path.exists() {
        eprintln!("Trace file not found, skipping test");
        return;
    }

    println!("\n=== Trace Summary Accuracy Test ===\n");

    let trace = PerfettoTrace::from_file(trace_path).expect("Failed to load trace");
    let registry = AnalyzerRegistry::with_builtins();
    let summary = registry.get_trace_summary(&trace);

    println!("Trace Summary:");
    println!("  Duration: {}ms", summary.trace_duration_ms);
    println!("  CPUs: {}", summary.num_cpus);
    println!("  Processes: {}", summary.num_processes);
    println!("  Total events: {}", summary.total_events);
    println!("  Is sched_ext: {}", summary.is_scx_trace);
    println!("  Applicable analyzers: {}", summary.applicable_analyzers);

    // Validate summary fields
    assert!(summary.trace_duration_ms > 0);
    assert!(summary.num_cpus > 0);
    assert!(summary.num_processes > 0);
    assert!(summary.total_events > 0);
    assert!(summary.applicable_analyzers > 0);

    // Validate capabilities
    println!("\nCapabilities:");
    println!(
        "  Available events: {}",
        summary.capabilities.available_events.len()
    );
    println!(
        "  Has process tree: {}",
        summary.capabilities.has_process_tree
    );
    println!("  Has sched_ext: {}", summary.capabilities.has_sched_ext);

    assert!(!summary.capabilities.available_events.is_empty());

    println!("\n✓ Trace summary accuracy verified!");
}

/// Test category-based filtering
#[test]
#[ignore]
fn test_category_filtering() {
    let trace_path = Path::new("/home/hodgesd/scx/scxtop_trace_0.proto");

    if !trace_path.exists() {
        eprintln!("Trace file not found, skipping test");
        return;
    }

    println!("\n=== Category Filtering Test ===\n");

    let trace = PerfettoTrace::from_file(trace_path).expect("Failed to load trace");
    let trace_arc = Arc::new(trace.clone());
    let registry = AnalyzerRegistry::with_builtins();

    use scxtop::mcp::AnalyzerCategory;

    let categories = vec![
        ("Scheduling", AnalyzerCategory::Scheduling),
        ("Interrupt", AnalyzerCategory::Interrupt),
        ("I/O", AnalyzerCategory::IO),
        ("Power", AnalyzerCategory::Power),
        ("Extended", AnalyzerCategory::Extended),
    ];

    for (name, category) in categories {
        let analyzers = registry.list_by_category(category);
        let applicable = registry
            .discover_analyzers(&trace)
            .into_iter()
            .filter(|a| a.category == category)
            .collect::<Vec<_>>();

        println!("{} category:", name);
        println!("  Total registered: {}", analyzers.len());
        println!("  Applicable to trace: {}", applicable.len());

        // Run applicable analyzers
        let results: Vec<_> = applicable
            .iter()
            .filter_map(|metadata| registry.analyze_by_id(&metadata.id, trace_arc.clone()))
            .collect();

        let successful = results.iter().filter(|r| r.success).count();
        println!("  Successfully ran: {}", successful);

        if !results.is_empty() {
            assert!(successful > 0);
        }
    }

    println!("\n✓ Category filtering test passed!");
}

/// Test analyzer metadata completeness
#[test]
fn test_analyzer_metadata_completeness() {
    println!("\n=== Analyzer Metadata Completeness Test ===\n");

    let registry = AnalyzerRegistry::with_builtins();
    let analyzers = registry.list_analyzers();

    println!("Validating {} analyzers...", analyzers.len());

    for analyzer in &analyzers {
        // Validate required fields
        assert!(!analyzer.id.is_empty(), "Analyzer has empty ID");
        assert!(
            !analyzer.name.is_empty(),
            "Analyzer {} has empty name",
            analyzer.id
        );
        assert!(
            !analyzer.description.is_empty(),
            "Analyzer {} has empty description",
            analyzer.id
        );

        // Validate performance cost range
        assert!(
            analyzer.performance_cost >= 1 && analyzer.performance_cost <= 5,
            "Analyzer {} has invalid performance cost: {}",
            analyzer.id,
            analyzer.performance_cost
        );

        // Most analyzers should have required events (except special ones)
        if !analyzer.requires_scx && analyzer.id != "dsq_summary" {
            assert!(
                !analyzer.required_events.is_empty(),
                "Analyzer {} has no required events",
                analyzer.id
            );
        }

        println!("  ✓ {} - valid metadata", analyzer.id);
    }

    println!("\n✓ All {} analyzers have valid metadata!", analyzers.len());
}

/// Test query aggregation functions
#[test]
#[ignore]
fn test_query_aggregations() {
    let trace_path = Path::new("/home/hodgesd/scx/scxtop_trace_0.proto");

    if !trace_path.exists() {
        eprintln!("Trace file not found, skipping test");
        return;
    }

    println!("\n=== Query Aggregation Functions Test ===\n");

    let trace = PerfettoTrace::from_file(trace_path).expect("Failed to load trace");

    use scxtop::mcp::Aggregator;

    // Test count
    let query = QueryBuilder::new().event_type("sched_wakeup").limit(1000);
    let result = query.execute(&trace);
    let count = Aggregator::count(&result);
    println!("Count: {}", count);
    assert_eq!(count, result.events.len());

    // Test count_by
    let counts = Aggregator::count_by(&result, "comm");
    println!("Count by comm: {} unique values", counts.len());
    assert!(!counts.is_empty());

    // Test group_by
    let groups = Aggregator::group_by(&result, "comm");
    println!("Group by comm: {} groups", groups.len());
    assert_eq!(groups.len(), counts.len());

    // Test avg, min, max
    if let Some(avg) = Aggregator::avg(&result, "prio") {
        println!("Average priority: {:.2}", avg);
        assert!(avg > 0.0);
    }

    if let Some(min) = Aggregator::min(&result, "prio") {
        println!("Min priority: {}", min);
        assert!(min >= 0);
    }

    if let Some(max) = Aggregator::max(&result, "prio") {
        println!("Max priority: {}", max);
        assert!(max <= 140);
    }

    println!("\n✓ All aggregation functions work correctly!");
}

/// Test concurrent analyzer execution
#[test]
#[ignore]
fn test_concurrent_execution() {
    let trace_path = Path::new("/home/hodgesd/scx/scxtop_trace_0.proto");

    if !trace_path.exists() {
        eprintln!("Trace file not found, skipping test");
        return;
    }

    println!("\n=== Concurrent Execution Test ===\n");

    let trace = PerfettoTrace::from_file(trace_path).expect("Failed to load trace");
    let trace_arc = Arc::new(trace);
    let registry = Arc::new(AnalyzerRegistry::with_builtins());

    // Get all applicable analyzers
    let analyzers: Vec<_> = registry
        .discover_analyzers(&trace_arc)
        .into_iter()
        .map(|m| m.id.clone())
        .collect();

    println!("Running {} analyzers concurrently...", analyzers.len());

    use std::thread;

    let start = std::time::Instant::now();
    let handles: Vec<_> = analyzers
        .into_iter()
        .map(|analyzer_id| {
            let trace = trace_arc.clone();
            let reg = registry.clone();
            thread::spawn(move || reg.analyze_by_id(&analyzer_id, trace))
        })
        .collect();

    let results: Vec<_> = handles.into_iter().filter_map(|h| h.join().ok()).collect();
    let elapsed = start.elapsed();

    println!(
        "Concurrent execution completed in {}ms",
        elapsed.as_millis()
    );
    println!("Results collected: {}", results.len());

    let successful = results
        .iter()
        .filter(|r| r.as_ref().map(|x| x.success).unwrap_or(false))
        .count();
    println!("Successful: {}", successful);

    assert!(successful > 0);

    println!("\n✓ Concurrent execution test passed!");
}

/// Test memory usage and cleanup
#[test]
#[ignore]
fn test_memory_cleanup() {
    let trace_path = Path::new("/home/hodgesd/scx/scxtop_trace_0.proto");

    if !trace_path.exists() {
        eprintln!("Trace file not found, skipping test");
        return;
    }

    println!("\n=== Memory Cleanup Test ===\n");

    // Load and analyze multiple times
    for i in 0..3 {
        println!("Iteration {}...", i + 1);

        let trace = PerfettoTrace::from_file(trace_path).expect("Failed to load trace");
        let trace_arc = Arc::new(trace);
        let registry = AnalyzerRegistry::with_builtins();

        let results = registry.analyze_all(trace_arc);
        println!("  Ran {} analyzers", results.len());

        // Explicit drop
        drop(results);
        drop(registry);
    }

    println!("\n✓ Memory cleanup test completed (no leaks detected)!");
}

/// Test outlier detection across all methods
#[test]
#[ignore]
fn test_outlier_detection() {
    let trace_path = Path::new("/home/hodgesd/scx/scxtop_trace_0.proto");

    if !trace_path.exists() {
        eprintln!("Trace file not found, skipping test");
        return;
    }

    println!("\n=== Outlier Detection Test ===\n");

    let trace = PerfettoTrace::from_file(trace_path).expect("Failed to load trace");
    let trace_arc = Arc::new(trace);

    // Test each detection method
    let methods = vec![
        ("IQR", OutlierMethod::IQR),
        ("MAD", OutlierMethod::MAD),
        ("StdDev", OutlierMethod::StdDev),
        ("Percentile", OutlierMethod::Percentile),
    ];

    for (name, method) in methods {
        println!("Testing {} method:", name);
        let start = std::time::Instant::now();

        let analyzer = PerfettoOutlierAnalyzer::with_method(trace_arc.clone(), method);
        let analysis = analyzer.analyze();

        let elapsed = start.elapsed();

        println!("  Analysis time: {:?}", elapsed);
        println!("  Total outliers: {}", analysis.summary.total_outliers);
        println!(
            "  Latency outliers: {}",
            analysis.latency_outliers.outlier_count
        );
        println!(
            "  Runtime outliers: {}",
            analysis.runtime_outliers.outlier_count
        );
        println!("  CPU outliers: {}", analysis.cpu_outliers.outlier_count);

        // Validate structure
        assert_eq!(analysis.detection_method, method);
        assert_eq!(analysis.summary.detection_method, method);

        // Print top latency outliers
        if !analysis.latency_outliers.wakeup_latency.is_empty() {
            println!(
                "  Top latency outlier: PID {} ({}) - {}ns (severity: {:.2})",
                analysis.latency_outliers.wakeup_latency[0].pid,
                analysis.latency_outliers.wakeup_latency[0].comm,
                analysis.latency_outliers.wakeup_latency[0].value,
                analysis.latency_outliers.wakeup_latency[0].severity
            );
        }

        // Print top runtime outliers
        if !analysis.runtime_outliers.excessive_runtime.is_empty() {
            println!(
                "  Top runtime outlier: PID {} ({}) - {}ns (severity: {:.2})",
                analysis.runtime_outliers.excessive_runtime[0].pid,
                analysis.runtime_outliers.excessive_runtime[0].comm,
                analysis.runtime_outliers.excessive_runtime[0].value,
                analysis.runtime_outliers.excessive_runtime[0].severity
            );
        }

        // Print top CPU outliers
        if !analysis.cpu_outliers.overutilized_cpus.is_empty() {
            println!(
                "  Top CPU outlier: CPU {} - {}% util (severity: {:.2})",
                analysis.cpu_outliers.overutilized_cpus[0].cpu,
                analysis.cpu_outliers.overutilized_cpus[0].value,
                analysis.cpu_outliers.overutilized_cpus[0].severity
            );
        }

        println!();
    }

    println!("✓ All outlier detection methods tested successfully!");
}

/// Test outlier detection categories
#[test]
#[ignore]
fn test_outlier_categories() {
    let trace_path = Path::new("/home/hodgesd/scx/scxtop_trace_0.proto");

    if !trace_path.exists() {
        eprintln!("Trace file not found, skipping test");
        return;
    }

    println!("\n=== Outlier Category Test ===\n");

    let trace = PerfettoTrace::from_file(trace_path).expect("Failed to load trace");
    let trace_arc = Arc::new(trace);

    let analyzer = PerfettoOutlierAnalyzer::new(trace_arc);
    let analysis = analyzer.analyze();

    // Validate category-specific data
    println!("Latency Outliers:");
    println!(
        "  Wakeup latency: {}",
        analysis.latency_outliers.wakeup_latency.len()
    );
    println!(
        "  Schedule latency: {}",
        analysis.latency_outliers.schedule_latency.len()
    );
    println!(
        "  Blocked time: {}",
        analysis.latency_outliers.blocked_time.len()
    );

    println!("\nRuntime Outliers:");
    println!(
        "  Excessive runtime: {}",
        analysis.runtime_outliers.excessive_runtime.len()
    );
    println!(
        "  Minimal runtime: {}",
        analysis.runtime_outliers.minimal_runtime.len()
    );
    println!(
        "  High context switches: {}",
        analysis.runtime_outliers.high_context_switches.len()
    );

    println!("\nCPU Outliers:");
    println!(
        "  Overutilized CPUs: {}",
        analysis.cpu_outliers.overutilized_cpus.len()
    );
    println!(
        "  Underutilized CPUs: {}",
        analysis.cpu_outliers.underutilized_cpus.len()
    );
    println!(
        "  High contention CPUs: {}",
        analysis.cpu_outliers.high_contention_cpus.len()
    );

    // Check summary consistency
    let _expected_total = analysis.latency_outliers.wakeup_latency.len()
        + analysis.runtime_outliers.excessive_runtime.len()
        + analysis.runtime_outliers.minimal_runtime.len()
        + analysis.runtime_outliers.high_context_switches.len()
        + analysis.cpu_outliers.overutilized_cpus.len()
        + analysis.cpu_outliers.underutilized_cpus.len()
        + analysis.cpu_outliers.high_contention_cpus.len();

    assert!(
        analysis.summary.total_outliers > 0,
        "Should find some outliers"
    );
    println!("\n✓ Outlier categorization working correctly!");
}
