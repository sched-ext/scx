// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use scxtop::mcp::perfetto_analyzers::*;
use scxtop::mcp::perfetto_parser::*;
use std::path::Path;
use std::sync::Arc;

#[test]
#[ignore]
fn test_process_timeline() {
    let trace_path = Path::new("/home/hodgesd/scx/scxtop_trace_0.proto");

    if !trace_path.exists() {
        eprintln!("Trace file not found, skipping test");
        return;
    }

    let trace = Arc::new(PerfettoTrace::from_file(trace_path).unwrap());

    // Get timeline for a process (PID from test trace)
    let (start, end) = trace.time_range();
    let timeline = trace.get_timeline_for_process(2952187, start, end); // schbench from earlier tests

    println!("\n=== Process Timeline Test ===");
    println!("PID: {} ({})", timeline.pid, timeline.comm);
    println!("Total events: {}", timeline.events.len());

    // Show first 20 events
    println!("\nFirst 20 events:");
    for event in timeline.events.iter().take(20) {
        println!("  {:?}", event);
    }

    assert!(!timeline.events.is_empty(), "Expected timeline events");
}

#[test]
#[ignore]
fn test_cpu_timeline() {
    let trace_path = Path::new("/home/hodgesd/scx/scxtop_trace_0.proto");

    if !trace_path.exists() {
        eprintln!("Trace file not found, skipping test");
        return;
    }

    let trace = Arc::new(PerfettoTrace::from_file(trace_path).unwrap());

    // Get timeline for CPU 0
    let (start, end) = trace.time_range();
    let timeline = trace.get_cpu_timeline(0, start, end);

    println!("\n=== CPU Timeline Test ===");
    println!("CPU: {}", timeline.cpu);
    println!("Total events: {}", timeline.events.len());

    // Show first 10 events
    println!("\nFirst 10 events:");
    for event in timeline.events.iter().take(10) {
        match &event.event_type {
            CpuEventType::ContextSwitch {
                prev_pid,
                next_pid,
                prev_comm,
                next_comm,
            } => {
                println!(
                    "  [{}] Switch: {} ({}) -> {} ({})",
                    event.timestamp, prev_pid, prev_comm, next_pid, next_comm
                );
            }
            CpuEventType::Softirq { vec, entry } => {
                println!(
                    "  [{}] Softirq {}: vec={}",
                    event.timestamp,
                    if *entry { "entry" } else { "exit" },
                    vec
                );
            }
        }
    }

    assert!(!timeline.events.is_empty(), "Expected timeline events");
}

#[test]
#[ignore]
fn test_wakeup_schedule_correlation() {
    let trace_path = Path::new("/home/hodgesd/scx/scxtop_trace_0.proto");

    if !trace_path.exists() {
        eprintln!("Trace file not found, skipping test");
        return;
    }

    let trace = Arc::new(PerfettoTrace::from_file(trace_path).unwrap());
    let analyzer = CorrelationAnalyzer::new(trace);

    let start = std::time::Instant::now();
    let correlations = analyzer.correlate_wakeup_to_schedule(None);
    let duration = start.elapsed();

    println!("\n=== Wakeup→Schedule Correlation Test ===");
    println!("Time taken: {:?}", duration);
    println!("Total correlations: {}", correlations.len());

    // Show top 10 by latency
    println!("\nTop 10 highest latencies:");
    for (i, corr) in correlations.iter().take(10).enumerate() {
        println!(
            "  {}. PID {} woken by PID {}, latency: {} ns ({:.2} ms), CPU: {}",
            i + 1,
            corr.pid,
            corr.waker_pid,
            corr.wakeup_latency_ns,
            corr.wakeup_latency_ns as f64 / 1_000_000.0,
            corr.cpu
        );
    }

    // Calculate percentiles
    let latencies: Vec<u64> = correlations.iter().map(|c| c.wakeup_latency_ns).collect();
    let percentiles = PerfettoTrace::calculate_percentiles(&latencies);

    println!("\nLatency percentiles:");
    println!("  min:  {} ns", percentiles.min);
    println!("  p50:  {} ns", percentiles.median);
    println!("  p95:  {} ns", percentiles.p95);
    println!("  p99:  {} ns", percentiles.p99);
    println!("  p999: {} ns", percentiles.p999);
    println!("  max:  {} ns", percentiles.max);

    assert!(!correlations.is_empty(), "Expected correlations");
}

#[test]
#[ignore]
fn test_scheduling_bottleneck_detection() {
    let trace_path = Path::new("/home/hodgesd/scx/scxtop_trace_0.proto");

    if !trace_path.exists() {
        eprintln!("Trace file not found, skipping test");
        return;
    }

    let trace = Arc::new(PerfettoTrace::from_file(trace_path).unwrap());
    let analyzer = CorrelationAnalyzer::new(trace);

    let start = std::time::Instant::now();
    let bottlenecks = analyzer.find_scheduling_bottlenecks(10);
    let duration = start.elapsed();

    println!("\n=== Bottleneck Detection Test ===");
    println!("Time taken: {:?}", duration);
    println!("Bottlenecks found: {}", bottlenecks.len());

    for (i, bottleneck) in bottlenecks.iter().enumerate() {
        println!(
            "\n{}. {} (severity: {:.2})",
            i + 1,
            bottleneck.description,
            bottleneck.severity
        );
        println!("   Type: {:?}", bottleneck.bottleneck_type);
        println!(
            "   Time range: {} - {} ns",
            bottleneck.time_range.0, bottleneck.time_range.1
        );
    }

    // Verify ordering by severity
    for i in 1..bottlenecks.len() {
        assert!(
            bottlenecks[i - 1].severity >= bottlenecks[i].severity,
            "Bottlenecks should be sorted by severity descending"
        );
    }
}

#[test]
#[ignore]
fn test_export_comprehensive_analysis() {
    let trace_path = Path::new("/home/hodgesd/scx/scxtop_trace_0.proto");

    if !trace_path.exists() {
        eprintln!("Trace file not found, skipping test");
        return;
    }

    let trace = Arc::new(PerfettoTrace::from_file(trace_path).unwrap());

    // Create export data structure
    let mut export_data = serde_json::json!({
        "time_range": trace.time_range(),
        "num_cpus": trace.num_cpus(),
        "num_processes": trace.get_processes().len(),
        "total_events": trace.total_events(),
    });

    println!("\n=== Comprehensive Export Test ===");

    // CPU utilization
    let ctx_analyzer = ContextSwitchAnalyzer::new(trace.clone());
    let start = std::time::Instant::now();
    let cpu_stats = ctx_analyzer.analyze_cpu_utilization_parallel();
    println!("CPU utilization: {:?}", start.elapsed());
    export_data["cpu_utilization"] = serde_json::json!(cpu_stats);

    // Process runtime
    let start = std::time::Instant::now();
    let process_stats = ctx_analyzer.analyze_process_runtime_parallel(None);
    println!("Process runtime: {:?}", start.elapsed());
    let top_20: Vec<_> = process_stats.into_iter().take(20).collect();
    export_data["process_runtime"] = serde_json::json!(top_20);

    // Wakeup latency
    let wakeup_analyzer = WakeupChainAnalyzer::new(trace.clone());
    let start = std::time::Instant::now();
    let wakeup_stats = wakeup_analyzer.analyze_wakeup_latency();
    println!("Wakeup latency: {:?}", start.elapsed());
    export_data["wakeup_latency"] = serde_json::json!(wakeup_stats);

    // Migration
    let migration_analyzer = PerfettoMigrationAnalyzer::new(trace.clone());
    let start = std::time::Instant::now();
    let migration_stats = migration_analyzer.analyze_migration_patterns();
    println!("Migration patterns: {:?}", start.elapsed());
    export_data["migration"] = serde_json::json!(migration_stats);

    // Bottlenecks
    let corr_analyzer = CorrelationAnalyzer::new(trace.clone());
    let start = std::time::Instant::now();
    let bottlenecks = corr_analyzer.find_scheduling_bottlenecks(10);
    println!("Bottleneck detection: {:?}", start.elapsed());
    export_data["bottlenecks"] = serde_json::json!(bottlenecks);

    // DSQ (if available)
    let dsq_analyzer = DsqAnalyzer::new(trace);
    if dsq_analyzer.has_scx_data() {
        export_data["dsq"] = serde_json::json!(dsq_analyzer.get_summary());
    }

    // Write to temp file
    let output_path = "/tmp/scxtop_test_export.json";
    let json_str = serde_json::to_string_pretty(&export_data).unwrap();
    std::fs::write(output_path, &json_str).unwrap();

    println!("\nExported to: {}", output_path);
    println!("File size: {} bytes", json_str.len());

    // Verify we can read it back
    let read_back = std::fs::read_to_string(output_path).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&read_back).unwrap();

    assert!(parsed["cpu_utilization"].is_object());
    assert!(parsed["process_runtime"].is_array());
    assert!(parsed["wakeup_latency"].is_object());
    assert!(parsed["bottlenecks"].is_array());

    println!("✓ Export and re-import successful");
}
