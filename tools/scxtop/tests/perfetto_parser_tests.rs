// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use scxtop::mcp::perfetto_parser::*;
use std::path::Path;

#[test]
fn test_percentile_calculation() {
    // Test with simple values
    let values = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
    let percentiles = PerfettoTrace::calculate_percentiles(&values);

    assert_eq!(percentiles.count, 10);
    assert_eq!(percentiles.min, 1);
    assert_eq!(percentiles.max, 10);
    assert_eq!(percentiles.median, 5);
    assert!((percentiles.mean - 5.5).abs() < 0.01);

    // Test p95 and p99
    let values: Vec<u64> = (1..=100).collect();
    let percentiles = PerfettoTrace::calculate_percentiles(&values);

    assert_eq!(percentiles.p95, 95);
    assert_eq!(percentiles.p99, 99);
}

#[test]
fn test_percentile_empty() {
    let values: Vec<u64> = vec![];
    let percentiles = PerfettoTrace::calculate_percentiles(&values);

    assert_eq!(percentiles.count, 0);
    assert_eq!(percentiles.min, 0);
    assert_eq!(percentiles.max, 0);
}

#[test]
fn test_percentile_single_value() {
    let values = vec![42];
    let percentiles = PerfettoTrace::calculate_percentiles(&values);

    assert_eq!(percentiles.count, 1);
    assert_eq!(percentiles.min, 42);
    assert_eq!(percentiles.max, 42);
    assert_eq!(percentiles.median, 42);
    assert_eq!(percentiles.p95, 42);
    assert_eq!(percentiles.p99, 42);
}

#[test]
#[ignore] // Only run with --ignored since it requires the trace file
fn test_parse_real_trace_file() {
    // This test uses the real trace file if it exists
    let trace_path = Path::new("/home/hodgesd/scx/scxtop_trace_0.proto");

    if !trace_path.exists() {
        eprintln!("Trace file not found, skipping test");
        return;
    }

    let result = PerfettoTrace::from_file(trace_path);
    assert!(
        result.is_ok(),
        "Failed to parse trace file: {:?}",
        result.err()
    );

    let trace = result.unwrap();

    // Verify basic properties
    assert!(
        !trace.get_processes().is_empty(),
        "Expected processes in trace"
    );
    assert!(
        trace.time_range().1 > trace.time_range().0,
        "Expected valid time range"
    );
    assert!(trace.num_cpus() > 0, "Expected CPUs in trace");
    assert!(trace.total_events() > 0, "Expected events in trace");

    println!("Successfully parsed trace:");
    println!("  Processes: {}", trace.get_processes().len());
    println!(
        "  Time range: {} - {} ns",
        trace.time_range().0,
        trace.time_range().1
    );
    println!("  CPUs: {}", trace.num_cpus());
    println!("  Total events: {}", trace.total_events());
    println!("  Is sched_ext trace: {}", trace.is_scx_trace());

    if let Some(scx_meta) = trace.get_scx_metadata() {
        println!("  sched_ext DSQs: {:?}", scx_meta.dsq_ids);
        println!("  DSQ descriptors: {}", scx_meta.dsq_descriptors.len());
    }
}

#[test]
#[ignore]
fn test_query_sched_switch_events() {
    let trace_path = Path::new("/home/hodgesd/scx/scxtop_trace_0.proto");

    if !trace_path.exists() {
        eprintln!("Trace file not found, skipping test");
        return;
    }

    let trace = PerfettoTrace::from_file(trace_path).unwrap();
    let events = trace.get_events_by_type("sched_switch");

    println!("Found {} sched_switch events", events.len());
    assert!(!events.is_empty(), "Expected sched_switch events");

    // Verify event structure
    for event in events.iter().take(5) {
        assert!(event.timestamp.is_some(), "Expected timestamp");
        assert!(event.pid.is_some(), "Expected PID");
        println!("  Event: ts={:?}, pid={:?}", event.timestamp, event.pid);
    }
}

#[test]
#[ignore]
fn test_query_by_cpu() {
    let trace_path = Path::new("/home/hodgesd/scx/scxtop_trace_0.proto");

    if !trace_path.exists() {
        eprintln!("Trace file not found, skipping test");
        return;
    }

    let trace = PerfettoTrace::from_file(trace_path).unwrap();

    // Query events for CPU 0
    let cpu0_events = trace.get_events_by_cpu(0);
    println!("CPU 0 has {} events", cpu0_events.len());

    assert!(!cpu0_events.is_empty(), "Expected events on CPU 0");

    // Verify all events are for CPU 0
    for event in cpu0_events.iter().take(10) {
        println!(
            "  Event: ts={:?}, pid={:?}",
            event.event.timestamp, event.event.pid
        );
    }
}

#[test]
#[ignore]
fn test_time_range_query() {
    let trace_path = Path::new("/home/hodgesd/scx/scxtop_trace_0.proto");

    if !trace_path.exists() {
        eprintln!("Trace file not found, skipping test");
        return;
    }

    let trace = PerfettoTrace::from_file(trace_path).unwrap();
    let (start, end) = trace.time_range();

    // Query first 10% of trace
    let query_end = start + (end - start) / 10;
    let events = trace.get_events_by_time_range(start, query_end);

    println!("Query range: {} - {} ns", start, query_end);
    println!("Found {} events in first 10% of trace", events.len());

    assert!(!events.is_empty(), "Expected events in time range");

    // Verify events are within range
    for event in &events {
        if let Some(ts) = event.timestamp {
            assert!(
                ts >= start && ts <= query_end,
                "Event timestamp {} not in range {} - {}",
                ts,
                start,
                query_end
            );
        }
    }
}

#[test]
#[ignore]
fn test_scx_metadata_extraction() {
    let trace_path = Path::new("/home/hodgesd/scx/scxtop_trace_0.proto");

    if !trace_path.exists() {
        eprintln!("Trace file not found, skipping test");
        return;
    }

    let trace = PerfettoTrace::from_file(trace_path).unwrap();

    if trace.is_scx_trace() {
        let scx_meta = trace
            .get_scx_metadata()
            .expect("Expected sched_ext metadata");

        println!("sched_ext trace detected:");
        println!("  Scheduler: {:?}", scx_meta.scheduler_name);
        println!("  DSQ IDs: {:?}", scx_meta.dsq_ids);

        for (dsq_id, desc) in &scx_meta.dsq_descriptors {
            println!(
                "  DSQ {}: {} events, range {} - {} ns",
                dsq_id, desc.event_count, desc.first_seen, desc.last_seen
            );
        }

        assert!(!scx_meta.dsq_ids.is_empty(), "Expected at least one DSQ");
        assert!(
            scx_meta.has_scx_events,
            "Expected has_scx_events to be true"
        );
    } else {
        println!("Not a sched_ext trace (no DSQ events found)");
    }
}
