// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

//! Tests for Phase 1: Enhanced Parser Infrastructure

use scxtop::mcp::{
    event_category, event_type_name, CompatibilityDetector, EventCategory, PerfettoTrace,
    TraceCapabilities, TraceSource,
};
use std::path::Path;

/// Test event type categorization
#[test]
fn test_event_categorization() {
    assert_eq!(event_category("sched_switch"), EventCategory::Scheduler);
    assert_eq!(
        event_category("irq_handler_entry"),
        EventCategory::Interrupt
    );
    assert_eq!(event_category("block_rq_issue"), EventCategory::BlockIO);
    assert_eq!(event_category("net_dev_xmit"), EventCategory::Network);
    assert_eq!(event_category("mm_page_alloc"), EventCategory::Memory);
    assert_eq!(event_category("cpu_frequency"), EventCategory::Power);
    assert_eq!(
        event_category("ext4_sync_file_enter"),
        EventCategory::FileSystem
    );
    assert_eq!(
        event_category("contention_begin"),
        EventCategory::Synchronization
    );
    assert_eq!(
        event_category("workqueue_execute_start"),
        EventCategory::Workqueue
    );
    assert_eq!(event_category("unknown_event"), EventCategory::Unknown);
}

/// Test human-readable event names
#[test]
fn test_event_type_names() {
    assert_eq!(event_type_name("sched_switch"), "Context Switch");
    assert_eq!(event_type_name("sched_wakeup"), "Task Wakeup");
    assert_eq!(event_type_name("irq_handler_entry"), "IRQ Handler Entry");
    assert_eq!(event_type_name("block_rq_issue"), "Block Request Issue");
    assert_eq!(event_type_name("unknown_event"), "unknown_event");
}

/// Test trace capabilities detection with real trace
#[test]
#[ignore] // Only run with --ignored since it requires the trace file
fn test_trace_capabilities_from_real_trace() {
    let trace_path = Path::new("/home/hodgesd/scx/scxtop_trace_0.proto");

    if !trace_path.exists() {
        eprintln!("Trace file not found, skipping test");
        return;
    }

    let trace = PerfettoTrace::from_file(trace_path).expect("Failed to load trace");
    let caps = trace.build_capabilities();

    // Verify basic properties
    assert!(
        caps.is_analyzable(),
        "Trace should have minimum data for analysis"
    );
    assert!(caps.total_events > 0, "Should have at least some events");
    assert!(caps.num_cpus > 0, "Should have at least one CPU");

    // Verify sched events are present
    assert!(
        caps.available_events.contains("sched_switch"),
        "Should have sched_switch events"
    );

    // Print capabilities for inspection
    println!("\n=== Trace Capabilities ===");
    println!("Source: {:?}", caps.trace_source);
    println!("Total events: {}", caps.total_events);
    println!("CPUs: {}", caps.num_cpus);
    println!("Processes: {}", caps.num_processes);
    println!("Has sched_ext: {}", caps.has_sched_ext);
    println!("\nAvailable event types ({}):", caps.available_events.len());
    for event_type in caps.list_event_types() {
        let count = caps.get_event_count(&event_type);
        let category = event_category(&event_type);
        println!("  {} ({}): {} events", event_type, category.as_str(), count);
    }

    println!("\nEvents by category:");
    for (category, events) in caps.events_by_category() {
        println!("  {}: {} event types", category.as_str(), events.len());
    }
}

/// Test TraceCapabilities supports_analyzer
#[test]
fn test_capabilities_supports_analyzer() {
    // Create mock capabilities
    let mut caps = TraceCapabilities {
        available_events: std::collections::HashSet::new(),
        event_counts: std::collections::HashMap::new(),
        track_event_categories: std::collections::HashSet::new(),
        track_event_counts: std::collections::HashMap::new(),
        clock_sources: std::collections::HashSet::new(),
        has_process_tree: true,
        has_system_info: false,
        has_process_stats: false,
        has_perf_samples: false,
        has_sched_ext: false,
        time_range: (0, 1000000),
        num_cpus: 4,
        num_processes: 10,
        total_events: 1000,
        trace_source: TraceSource::GenericFtrace,
    };

    caps.available_events.insert("sched_switch".to_string());
    caps.available_events.insert("sched_wakeup".to_string());
    caps.available_events
        .insert("irq_handler_entry".to_string());

    // Test single requirement
    assert!(caps.supports_analyzer(&["sched_switch"]));

    // Test multiple requirements (all present)
    assert!(caps.supports_analyzer(&["sched_switch", "sched_wakeup"]));

    // Test multiple requirements (some missing)
    assert!(!caps.supports_analyzer(&["sched_switch", "block_rq_issue"]));

    // Test all missing
    assert!(!caps.supports_analyzer(&["net_dev_xmit", "mm_page_alloc"]));
}

/// Test CompatibilityDetector missing events detection
#[test]
fn test_missing_events_detection() {
    let mut caps = TraceCapabilities {
        available_events: std::collections::HashSet::new(),
        event_counts: std::collections::HashMap::new(),
        track_event_categories: std::collections::HashSet::new(),
        track_event_counts: std::collections::HashMap::new(),
        clock_sources: std::collections::HashSet::new(),
        has_process_tree: true,
        has_system_info: false,
        has_process_stats: false,
        has_perf_samples: false,
        has_sched_ext: false,
        time_range: (0, 1000000),
        num_cpus: 4,
        num_processes: 10,
        total_events: 1000,
        trace_source: TraceSource::GenericFtrace,
    };

    caps.available_events.insert("sched_switch".to_string());
    caps.available_events.insert("sched_wakeup".to_string());

    let missing = CompatibilityDetector::get_missing_events(
        &caps,
        &[
            "sched_switch",
            "sched_wakeup",
            "irq_handler_entry",
            "block_rq_issue",
        ],
    );

    assert_eq!(missing.len(), 2);
    assert!(missing.contains(&"irq_handler_entry".to_string()));
    assert!(missing.contains(&"block_rq_issue".to_string()));
    assert!(!missing.contains(&"sched_switch".to_string()));
}

/// Test EventTypeIndex building and queries
#[test]
#[ignore] // Only run with --ignored since it requires the trace file
fn test_event_type_index_from_real_trace() {
    let trace_path = Path::new("/home/hodgesd/scx/scxtop_trace_0.proto");

    if !trace_path.exists() {
        eprintln!("Trace file not found, skipping test");
        return;
    }

    let trace = PerfettoTrace::from_file(trace_path).expect("Failed to load trace");
    let index = trace.build_event_index();

    // Test event type listing
    let event_types = index.list_event_types();
    println!("\n=== Event Type Index ===");
    println!("Indexed event types: {}", event_types.len());
    for event_type in &event_types {
        let count = index.get_event_count(event_type);
        println!("  {}: {} events", event_type, count);
    }

    // Test by-type queries
    if event_types.contains(&"sched_switch".to_string()) {
        let sched_switch_events = index.get_events_by_type("sched_switch");
        println!("\nTotal sched_switch events: {}", sched_switch_events.len());
        assert!(
            sched_switch_events.len() > 0,
            "Should have sched_switch events"
        );
    }

    // Test by-CPU queries
    if event_types.contains(&"sched_switch".to_string()) {
        let cpu0_events = index.get_events_by_type_and_cpu("sched_switch", 0);
        println!("CPU 0 sched_switch events: {}", cpu0_events.len());
    }
}

/// Test trace source detection
#[test]
#[ignore] // Only run with --ignored since it requires the trace file
fn test_trace_source_detection() {
    let trace_path = Path::new("/home/hodgesd/scx/scxtop_trace_0.proto");

    if !trace_path.exists() {
        eprintln!("Trace file not found, skipping test");
        return;
    }

    let trace = PerfettoTrace::from_file(trace_path).expect("Failed to load trace");
    let caps = trace.build_capabilities();

    println!("\n=== Trace Source Detection ===");
    println!(
        "Detected source: {:?} ({})",
        caps.trace_source,
        caps.trace_source.as_str()
    );
    println!("Has sched_ext: {}", caps.has_sched_ext);

    // scxtop traces should be detected as Scxtop source if they have DSQ data
    if caps.has_sched_ext {
        assert_eq!(caps.trace_source, TraceSource::Scxtop);
    }
}

/// Test PerfettoTrace supports_analysis method
#[test]
#[ignore] // Only run with --ignored since it requires the trace file
fn test_supports_analysis_method() {
    let trace_path = Path::new("/home/hodgesd/scx/scxtop_trace_0.proto");

    if !trace_path.exists() {
        eprintln!("Trace file not found, skipping test");
        return;
    }

    let trace = PerfettoTrace::from_file(trace_path).expect("Failed to load trace");

    // Should support basic scheduler analysis
    assert!(
        trace.supports_analysis(&["sched_switch"]),
        "Should support basic scheduler analysis"
    );

    // May not support IRQ analysis (depends on trace)
    let supports_irq = trace.supports_analysis(&["irq_handler_entry", "irq_handler_exit"]);
    println!("\n=== Analysis Support ===");
    println!("Supports IRQ analysis: {}", supports_irq);

    // May not support block I/O analysis
    let supports_block_io = trace.supports_analysis(&["block_rq_insert", "block_rq_complete"]);
    println!("Supports Block I/O analysis: {}", supports_block_io);
}

/// Test list_event_types method
#[test]
#[ignore] // Only run with --ignored since it requires the trace file
fn test_list_event_types_method() {
    let trace_path = Path::new("/home/hodgesd/scx/scxtop_trace_0.proto");

    if !trace_path.exists() {
        eprintln!("Trace file not found, skipping test");
        return;
    }

    let trace = PerfettoTrace::from_file(trace_path).expect("Failed to load trace");
    let event_types = trace.list_event_types();

    println!("\n=== Available Event Types ===");
    println!("Total: {}", event_types.len());
    for (i, event_type) in event_types.iter().enumerate() {
        println!("  {}: {}", i + 1, event_type);
    }

    assert!(
        !event_types.is_empty(),
        "Should have at least some event types"
    );
    assert!(
        event_types.contains(&"sched_switch".to_string()),
        "Should have sched_switch"
    );
}
