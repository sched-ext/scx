// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

//! Tests for Phase 5: Generic Query Framework

use scxtop::mcp::{
    Aggregator, FieldFilter, FilterOperator, FilterValue, PerfettoTrace, QueryBuilder,
};
use std::path::Path;

/// Test basic query builder functionality
#[test]
fn test_query_builder_basic() {
    let query = QueryBuilder::new()
        .event_type("sched_switch")
        .limit(100)
        .offset(10);

    // Just test that it builds
    let _ = query;
}

/// Test field filter creation
#[test]
fn test_field_filter_creation() {
    let filter = FieldFilter::new("prev_pid", FilterOperator::Equal, FilterValue::Int(1234));

    assert_eq!(filter.field, "prev_pid");
}

/// Test filter operators
#[test]
fn test_filter_operators() {
    let int_10 = FilterValue::Int(10);
    let int_5 = FilterValue::Int(5);
    let int_10_again = FilterValue::Int(10);

    assert!(FilterOperator::Equal.compare(&int_10, &int_10_again));
    assert!(!FilterOperator::Equal.compare(&int_10, &int_5));
    assert!(FilterOperator::NotEqual.compare(&int_10, &int_5));
    assert!(FilterOperator::GreaterThan.compare(&int_10, &int_5));
    assert!(!FilterOperator::GreaterThan.compare(&int_5, &int_10));
    assert!(FilterOperator::LessThan.compare(&int_5, &int_10));
    assert!(FilterOperator::GreaterOrEqual.compare(&int_10, &int_10_again));
    assert!(FilterOperator::LessOrEqual.compare(&int_10, &int_10_again));

    let str_hello = FilterValue::String("hello world".to_string());
    let str_hello_again = FilterValue::String("hello world".to_string());
    let str_world = FilterValue::String("world".to_string());

    assert!(FilterOperator::Equal.compare(&str_hello, &str_hello_again));
    assert!(!FilterOperator::Equal.compare(&str_hello, &str_world));
    assert!(FilterOperator::Contains.compare(&str_hello, &str_world));
}

/// Test query execution with real trace
#[test]
#[ignore]
fn test_query_execution_real_trace() {
    let trace_path = Path::new("/home/hodgesd/scx/scxtop_trace_0.proto");

    if !trace_path.exists() {
        eprintln!("Trace file not found, skipping test");
        return;
    }

    let trace = PerfettoTrace::from_file(trace_path).expect("Failed to load trace");

    // Basic query - all sched_switch events
    let query = QueryBuilder::new().event_type("sched_switch").limit(100);

    let result = query.execute(&trace);

    println!("\n=== Query: All sched_switch events (limit 100) ===");
    println!("Query time: {}ms", result.query_time_ms);
    println!("Total matched: {}", result.total_matched);
    println!("Returned: {}", result.events.len());
    assert!(result.events.len() <= 100);
    assert!(result.events.len() > 0);
}

/// Test query with CPU filter
#[test]
#[ignore]
fn test_query_cpu_filter() {
    let trace_path = Path::new("/home/hodgesd/scx/scxtop_trace_0.proto");

    if !trace_path.exists() {
        eprintln!("Trace file not found, skipping test");
        return;
    }

    let trace = PerfettoTrace::from_file(trace_path).expect("Failed to load trace");

    // Query CPU 0 events
    let query = QueryBuilder::new()
        .event_type("sched_switch")
        .cpu(0)
        .limit(50);

    let result = query.execute(&trace);

    println!("\n=== Query: sched_switch on CPU 0 ===");
    println!("Query time: {}ms", result.query_time_ms);
    println!("Total matched: {}", result.total_matched);
    println!("Returned: {}", result.events.len());

    // All events should be on CPU 0 (implicit from query)
    assert!(result.events.len() > 0);
}

/// Test query with field filter
#[test]
#[ignore]
fn test_query_field_filter() {
    let trace_path = Path::new("/home/hodgesd/scx/scxtop_trace_0.proto");

    if !trace_path.exists() {
        eprintln!("Trace file not found, skipping test");
        return;
    }

    let trace = PerfettoTrace::from_file(trace_path).expect("Failed to load trace");

    // Query for processes switching to swapper/0 (idle)
    let query = QueryBuilder::new()
        .event_type("sched_switch")
        .where_field(FieldFilter::new(
            "next_comm",
            FilterOperator::Contains,
            FilterValue::String("swapper".to_string()),
        ))
        .limit(20);

    let result = query.execute(&trace);

    println!("\n=== Query: sched_switch to swapper (idle) ===");
    println!("Query time: {}ms", result.query_time_ms);
    println!("Total matched: {}", result.total_matched);
    println!("Returned: {}", result.events.len());

    // Show sample events
    for (i, event) in result.events.iter().take(5).enumerate() {
        println!(
            "  {}. {} @ {}ns: {:?}",
            i + 1,
            event.event_type,
            event.timestamp.unwrap_or(0),
            event.fields
        );
    }
}

/// Test aggregation - count
#[test]
#[ignore]
fn test_aggregation_count() {
    let trace_path = Path::new("/home/hodgesd/scx/scxtop_trace_0.proto");

    if !trace_path.exists() {
        eprintln!("Trace file not found, skipping test");
        return;
    }

    let trace = PerfettoTrace::from_file(trace_path).expect("Failed to load trace");

    let query = QueryBuilder::new().event_type("sched_wakeup");
    let result = query.execute(&trace);

    let count = Aggregator::count(&result);

    println!("\n=== Aggregation: Count sched_wakeup events ===");
    println!("Count: {}", count);
    assert_eq!(count, result.events.len());
}

/// Test aggregation - count_by
#[test]
#[ignore]
fn test_aggregation_count_by() {
    let trace_path = Path::new("/home/hodgesd/scx/scxtop_trace_0.proto");

    if !trace_path.exists() {
        eprintln!("Trace file not found, skipping test");
        return;
    }

    let trace = PerfettoTrace::from_file(trace_path).expect("Failed to load trace");

    let query = QueryBuilder::new().event_type("sched_switch").limit(1000);
    let result = query.execute(&trace);

    let counts = Aggregator::count_by(&result, "next_comm");

    println!("\n=== Aggregation: Count by next_comm (top 10) ===");
    let mut sorted_counts: Vec<_> = counts.iter().collect();
    sorted_counts.sort_by_key(|(_, count)| std::cmp::Reverse(*count));

    for (comm, count) in sorted_counts.iter().take(10) {
        println!("  {}: {} switches", comm, count);
    }

    assert!(!counts.is_empty());
}

/// Test aggregation - group_by
#[test]
#[ignore]
fn test_aggregation_group_by() {
    let trace_path = Path::new("/home/hodgesd/scx/scxtop_trace_0.proto");

    if !trace_path.exists() {
        eprintln!("Trace file not found, skipping test");
        return;
    }

    let trace = PerfettoTrace::from_file(trace_path).expect("Failed to load trace");

    let query = QueryBuilder::new().event_type("sched_wakeup").limit(500);
    let result = query.execute(&trace);

    let groups = Aggregator::group_by(&result, "comm");

    println!("\n=== Aggregation: Group by comm (top 5) ===");
    let mut sorted_groups: Vec<_> = groups.iter().collect();
    sorted_groups.sort_by_key(|(_, events)| std::cmp::Reverse(events.len()));

    for (comm, events) in sorted_groups.iter().take(5) {
        println!("  {}: {} wakeup events", comm, events.len());
    }

    assert!(!groups.is_empty());
}

/// Test aggregation - avg
#[test]
#[ignore]
fn test_aggregation_avg() {
    let trace_path = Path::new("/home/hodgesd/scx/scxtop_trace_0.proto");

    if !trace_path.exists() {
        eprintln!("Trace file not found, skipping test");
        return;
    }

    let trace = PerfettoTrace::from_file(trace_path).expect("Failed to load trace");

    let query = QueryBuilder::new().event_type("sched_wakeup").limit(1000);
    let result = query.execute(&trace);

    if let Some(avg_prio) = Aggregator::avg(&result, "prio") {
        println!("\n=== Aggregation: Average priority ===");
        println!("Average prio: {:.2}", avg_prio);
        assert!(avg_prio >= 0.0);
        assert!(avg_prio <= 140.0); // Linux priority range
    }
}

/// Test aggregation - min/max
#[test]
#[ignore]
fn test_aggregation_min_max() {
    let trace_path = Path::new("/home/hodgesd/scx/scxtop_trace_0.proto");

    if !trace_path.exists() {
        eprintln!("Trace file not found, skipping test");
        return;
    }

    let trace = PerfettoTrace::from_file(trace_path).expect("Failed to load trace");

    let query = QueryBuilder::new().event_type("sched_wakeup").limit(1000);
    let result = query.execute(&trace);

    println!("\n=== Aggregation: Min/Max priority ===");

    if let Some(min_prio) = Aggregator::min(&result, "prio") {
        println!("Min prio: {}", min_prio);
        assert!(min_prio >= 0);
    }

    if let Some(max_prio) = Aggregator::max(&result, "prio") {
        println!("Max prio: {}", max_prio);
        assert!(max_prio <= 140);
    }
}

/// Test time range query
#[test]
#[ignore]
fn test_query_time_range() {
    let trace_path = Path::new("/home/hodgesd/scx/scxtop_trace_0.proto");

    if !trace_path.exists() {
        eprintln!("Trace file not found, skipping test");
        return;
    }

    let trace = PerfettoTrace::from_file(trace_path).expect("Failed to load trace");

    let (start, end) = trace.time_range();
    let mid = start + (end - start) / 2;

    // Query first half
    let query = QueryBuilder::new()
        .event_type("sched_switch")
        .time_range(start, mid)
        .limit(1000);

    let result = query.execute(&trace);

    println!("\n=== Query: Time range (first half) ===");
    println!("Time range: {} - {}", start, mid);
    println!("Events: {}", result.events.len());

    // All events should be in range
    for event in &result.events {
        if let Some(ts) = event.timestamp {
            assert!(ts >= start && ts <= mid);
        }
    }
}

/// Test complex query with multiple filters
#[test]
#[ignore]
fn test_query_complex() {
    let trace_path = Path::new("/home/hodgesd/scx/scxtop_trace_0.proto");

    if !trace_path.exists() {
        eprintln!("Trace file not found, skipping test");
        return;
    }

    let trace = PerfettoTrace::from_file(trace_path).expect("Failed to load trace");

    // Find high-priority wakeups
    let query = QueryBuilder::new()
        .event_type("sched_wakeup")
        .where_field(FieldFilter::new(
            "prio",
            FilterOperator::LessThan,
            FilterValue::Int(100),
        ))
        .limit(50);

    let result = query.execute(&trace);

    println!("\n=== Query: High priority wakeups (prio < 100) ===");
    println!("Query time: {}ms", result.query_time_ms);
    println!("Matched: {}", result.events.len());

    // Show sample events
    for (i, event) in result.events.iter().take(5).enumerate() {
        println!(
            "  {}. {} @ {}ns - prio: {}",
            i + 1,
            event.event_type,
            event.timestamp.unwrap_or(0),
            event.fields.get("prio").unwrap_or(&"N/A".to_string())
        );
    }
}

/// Test pagination with offset
#[test]
#[ignore]
fn test_query_pagination() {
    let trace_path = Path::new("/home/hodgesd/scx/scxtop_trace_0.proto");

    if !trace_path.exists() {
        eprintln!("Trace file not found, skipping test");
        return;
    }

    let trace = PerfettoTrace::from_file(trace_path).expect("Failed to load trace");

    // Page 1
    let query1 = QueryBuilder::new()
        .event_type("sched_switch")
        .limit(10)
        .offset(0);
    let result1 = query1.execute(&trace);

    // Page 2
    let query2 = QueryBuilder::new()
        .event_type("sched_switch")
        .limit(10)
        .offset(10);
    let result2 = query2.execute(&trace);

    println!("\n=== Query: Pagination test ===");
    println!("Page 1 events: {}", result1.events.len());
    println!("Page 2 events: {}", result2.events.len());

    assert_eq!(result1.events.len(), 10);
    assert_eq!(result2.events.len(), 10);

    // First events should be different
    if let (Some(e1), Some(e2)) = (result1.events.first(), result2.events.first()) {
        assert_ne!(e1.timestamp, e2.timestamp);
    }
}

/// Test empty result handling
#[test]
#[ignore]
fn test_query_empty_result() {
    let trace_path = Path::new("/home/hodgesd/scx/scxtop_trace_0.proto");

    if !trace_path.exists() {
        eprintln!("Trace file not found, skipping test");
        return;
    }

    let trace = PerfettoTrace::from_file(trace_path).expect("Failed to load trace");

    // Query for non-existent PID
    let query = QueryBuilder::new()
        .event_type("sched_switch")
        .pid(999999999);

    let result = query.execute(&trace);

    println!("\n=== Query: Empty result (PID 999999999) ===");
    println!("Matched: {}", result.events.len());

    assert_eq!(result.events.len(), 0);
    assert_eq!(Aggregator::count(&result), 0);
}
