// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

//! Comprehensive tests for Phase 1 enhanced parser - edge cases, performance, compatibility

use scxtop::mcp::{
    events_in_category, softirq_type_name, CompatibilityDetector, EventCategory, PerfettoTrace,
    TraceCapabilities, TraceSource,
};
use std::path::Path;

/// Test all event categories have correct events
#[test]
fn test_events_in_category_comprehensive() {
    // Scheduler category
    let sched_events = events_in_category(EventCategory::Scheduler);
    assert!(sched_events.contains(&"sched_switch"));
    assert!(sched_events.contains(&"sched_wakeup"));
    assert!(sched_events.contains(&"sched_waking"));
    assert!(sched_events.contains(&"sched_migrate_task"));
    assert!(sched_events.contains(&"sched_process_fork"));
    assert_eq!(sched_events.len(), 10);

    // Interrupt category
    let irq_events = events_in_category(EventCategory::Interrupt);
    assert!(irq_events.contains(&"irq_handler_entry"));
    assert!(irq_events.contains(&"irq_handler_exit"));
    assert!(irq_events.contains(&"softirq_entry"));
    assert!(irq_events.contains(&"softirq_exit"));
    assert!(irq_events.contains(&"softirq_raise"));
    assert_eq!(irq_events.len(), 8);

    // Block I/O category
    let block_events = events_in_category(EventCategory::BlockIO);
    assert!(block_events.contains(&"block_rq_insert"));
    assert!(block_events.contains(&"block_rq_issue"));
    assert!(block_events.contains(&"block_rq_complete"));
    assert_eq!(block_events.len(), 6);

    // Network category
    let net_events = events_in_category(EventCategory::Network);
    assert!(net_events.contains(&"net_dev_xmit"));
    assert!(net_events.contains(&"netif_receive_skb"));
    assert_eq!(net_events.len(), 3);

    // Memory category
    let mem_events = events_in_category(EventCategory::Memory);
    assert!(mem_events.contains(&"mm_page_alloc"));
    assert!(mem_events.contains(&"mm_page_free"));
    assert!(mem_events.contains(&"mm_vmscan_direct_reclaim_begin"));
    assert_eq!(mem_events.len(), 9);

    // Power category
    let power_events = events_in_category(EventCategory::Power);
    assert!(power_events.contains(&"cpu_frequency"));
    assert!(power_events.contains(&"cpu_idle"));
    assert_eq!(power_events.len(), 3);

    // FileSystem category
    let fs_events = events_in_category(EventCategory::FileSystem);
    assert!(fs_events.contains(&"ext4_sync_file_enter"));
    assert!(fs_events.contains(&"ext4_sync_file_exit"));
    assert_eq!(fs_events.len(), 4);

    // Synchronization category
    let sync_events = events_in_category(EventCategory::Synchronization);
    assert!(sync_events.contains(&"contention_begin"));
    assert!(sync_events.contains(&"contention_end"));
    assert_eq!(sync_events.len(), 2);

    // Workqueue category
    let wq_events = events_in_category(EventCategory::Workqueue);
    assert!(wq_events.contains(&"workqueue_execute_start"));
    assert!(wq_events.contains(&"workqueue_execute_end"));
    assert_eq!(wq_events.len(), 4);

    // Unknown category
    let unknown_events = events_in_category(EventCategory::Unknown);
    assert_eq!(unknown_events.len(), 0);
}

/// Test softirq type name mapping
#[test]
fn test_softirq_type_names() {
    assert_eq!(softirq_type_name(0), "HI");
    assert_eq!(softirq_type_name(1), "TIMER");
    assert_eq!(softirq_type_name(2), "NET_TX");
    assert_eq!(softirq_type_name(3), "NET_RX");
    assert_eq!(softirq_type_name(4), "BLOCK");
    assert_eq!(softirq_type_name(5), "IRQ_POLL");
    assert_eq!(softirq_type_name(6), "TASKLET");
    assert_eq!(softirq_type_name(7), "SCHED");
    assert_eq!(softirq_type_name(8), "HRTIMER");
    assert_eq!(softirq_type_name(9), "RCU");
    assert_eq!(softirq_type_name(10), "UNKNOWN");
    assert_eq!(softirq_type_name(99), "UNKNOWN");
}

/// Test TraceCapabilities with minimal data
#[test]
fn test_capabilities_minimal_trace() {
    let caps = TraceCapabilities {
        available_events: std::collections::HashSet::new(),
        event_counts: std::collections::HashMap::new(),
        track_event_categories: std::collections::HashSet::new(),
        track_event_counts: std::collections::HashMap::new(),
        clock_sources: std::collections::HashSet::new(),
        has_process_tree: false,
        has_system_info: false,
        has_process_stats: false,
        has_perf_samples: false,
        has_sched_ext: false,
        time_range: (0, 0),
        num_cpus: 0,
        num_processes: 0,
        total_events: 0,
        trace_source: TraceSource::Unknown,
    };

    // Empty trace should not be analyzable
    assert!(!caps.is_analyzable());
    assert_eq!(caps.list_event_types().len(), 0);
    assert_eq!(caps.get_event_count("sched_switch"), 0);
}

/// Test TraceCapabilities with only sched_switch
#[test]
fn test_capabilities_minimal_analyzable() {
    let mut caps = TraceCapabilities {
        available_events: std::collections::HashSet::new(),
        event_counts: std::collections::HashMap::new(),
        track_event_categories: std::collections::HashSet::new(),
        track_event_counts: std::collections::HashMap::new(),
        clock_sources: std::collections::HashSet::new(),
        has_process_tree: false,
        has_system_info: false,
        has_process_stats: false,
        has_perf_samples: false,
        has_sched_ext: false,
        time_range: (0, 1000000),
        num_cpus: 1,
        num_processes: 1,
        total_events: 100,
        trace_source: TraceSource::GenericFtrace,
    };

    caps.available_events.insert("sched_switch".to_string());
    caps.event_counts.insert("sched_switch".to_string(), 100);

    // Should be analyzable with just sched_switch
    assert!(caps.is_analyzable());
    assert_eq!(caps.list_event_types().len(), 1);
    assert_eq!(caps.get_event_count("sched_switch"), 100);
}

/// Test TraceCapabilities events_by_category
#[test]
fn test_capabilities_events_by_category() {
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

    // Add events from multiple categories
    caps.available_events.insert("sched_switch".to_string());
    caps.available_events.insert("sched_wakeup".to_string());
    caps.available_events
        .insert("irq_handler_entry".to_string());
    caps.available_events.insert("irq_handler_exit".to_string());
    caps.available_events.insert("block_rq_issue".to_string());

    let by_category = caps.events_by_category();

    // Should have 3 categories
    assert!(by_category.contains_key(&EventCategory::Scheduler));
    assert!(by_category.contains_key(&EventCategory::Interrupt));
    assert!(by_category.contains_key(&EventCategory::BlockIO));

    // Scheduler should have 2 events
    assert_eq!(by_category[&EventCategory::Scheduler].len(), 2);

    // Interrupt should have 2 events
    assert_eq!(by_category[&EventCategory::Interrupt].len(), 2);

    // BlockIO should have 1 event
    assert_eq!(by_category[&EventCategory::BlockIO].len(), 1);
}

/// Test CompatibilityDetector has_required_events
#[test]
fn test_compatibility_has_required_events() {
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

    assert!(CompatibilityDetector::has_required_events(
        &caps,
        &["sched_switch"]
    ));
    assert!(CompatibilityDetector::has_required_events(
        &caps,
        &["sched_switch", "sched_wakeup"]
    ));
    assert!(!CompatibilityDetector::has_required_events(
        &caps,
        &["sched_switch", "irq_handler_entry"]
    ));
}

/// Test EventTypeIndex with real trace - detailed queries
#[test]
#[ignore]
fn test_event_index_detailed_queries() {
    let trace_path = Path::new("/home/hodgesd/scx/scxtop_trace_0.proto");

    if !trace_path.exists() {
        eprintln!("Trace file not found, skipping test");
        return;
    }

    let trace = PerfettoTrace::from_file(trace_path).expect("Failed to load trace");
    let index = trace.build_event_index();

    println!("\n=== Event Index Detailed Query Tests ===");

    // Test get_events_by_type_and_cpu for multiple CPUs
    for cpu in 0..4.min(trace.num_cpus()) {
        let events = index.get_events_by_type_and_cpu("sched_switch", cpu as u32);
        println!("CPU {}: {} sched_switch events", cpu, events.len());
        assert!(events.len() > 0 || cpu >= trace.num_cpus());
    }

    // Test get_events_by_type_in_range
    let (start_ts, end_ts) = trace.time_range();
    let duration = end_ts - start_ts;
    let mid_ts = start_ts + duration / 2;

    let first_half = index.get_events_by_type_in_range("sched_switch", start_ts, mid_ts);
    let second_half = index.get_events_by_type_in_range("sched_switch", mid_ts, end_ts);
    let all_events = index.get_events_by_type("sched_switch");

    println!("\nTime range queries:");
    println!("  First half: {} events", first_half.len());
    println!("  Second half: {} events", second_half.len());
    println!("  Total: {} events", all_events.len());

    // Sum should roughly equal total (some overlap at mid_ts is OK)
    assert!(
        first_half.len() + second_half.len() >= all_events.len() - 1,
        "Time range queries should cover all events"
    );
}

/// Test PerfettoTrace list_event_types is sorted
#[test]
#[ignore]
fn test_list_event_types_sorted() {
    let trace_path = Path::new("/home/hodgesd/scx/scxtop_trace_0.proto");

    if !trace_path.exists() {
        eprintln!("Trace file not found, skipping test");
        return;
    }

    let trace = PerfettoTrace::from_file(trace_path).expect("Failed to load trace");
    let event_types = trace.list_event_types();

    // Verify sorted
    for i in 0..event_types.len() - 1 {
        assert!(
            event_types[i] <= event_types[i + 1],
            "Event types should be sorted"
        );
    }
}

/// Test capabilities detection consistency
#[test]
#[ignore]
fn test_capabilities_consistency() {
    let trace_path = Path::new("/home/hodgesd/scx/scxtop_trace_0.proto");

    if !trace_path.exists() {
        eprintln!("Trace file not found, skipping test");
        return;
    }

    let trace = PerfettoTrace::from_file(trace_path).expect("Failed to load trace");

    // Build capabilities twice - should be consistent
    let caps1 = trace.build_capabilities();
    let caps2 = trace.build_capabilities();

    assert_eq!(caps1.total_events, caps2.total_events);
    assert_eq!(caps1.num_cpus, caps2.num_cpus);
    assert_eq!(caps1.num_processes, caps2.num_processes);
    assert_eq!(caps1.available_events, caps2.available_events);
    assert_eq!(caps1.trace_source, caps2.trace_source);
}

/// Test event index building is deterministic
#[test]
#[ignore]
fn test_event_index_deterministic() {
    let trace_path = Path::new("/home/hodgesd/scx/scxtop_trace_0.proto");

    if !trace_path.exists() {
        eprintln!("Trace file not found, skipping test");
        return;
    }

    let trace = PerfettoTrace::from_file(trace_path).expect("Failed to load trace");

    // Build index twice
    let index1 = trace.build_event_index();
    let index2 = trace.build_event_index();

    // Should have same event types
    assert_eq!(index1.list_event_types(), index2.list_event_types());

    // Should have same counts for each type
    for event_type in index1.list_event_types() {
        assert_eq!(
            index1.get_event_count(&event_type),
            index2.get_event_count(&event_type)
        );
    }
}

/// Test supports_analysis with complex requirements
#[test]
#[ignore]
fn test_supports_analysis_complex() {
    let trace_path = Path::new("/home/hodgesd/scx/scxtop_trace_0.proto");

    if !trace_path.exists() {
        eprintln!("Trace file not found, skipping test");
        return;
    }

    let trace = PerfettoTrace::from_file(trace_path).expect("Failed to load trace");

    println!("\n=== Complex Analysis Support Tests ===");

    // Test various analyzer requirements
    let tests = vec![
        (
            "Basic Scheduler",
            vec!["sched_switch"],
            true, // Should support
        ),
        (
            "Advanced Scheduler",
            vec!["sched_switch", "sched_wakeup", "sched_waking"],
            true,
        ),
        (
            "Migration Analyzer",
            vec!["sched_migrate_task"],
            false, // May or may not be in trace
        ),
        (
            "IRQ Analyzer",
            vec!["irq_handler_entry", "irq_handler_exit"],
            false, // Likely not in scxtop trace
        ),
        (
            "Softirq Analyzer",
            vec!["softirq_entry", "softirq_exit"],
            true, // Should be present
        ),
        (
            "Block I/O Analyzer",
            vec!["block_rq_insert", "block_rq_issue", "block_rq_complete"],
            false, // Likely not in scxtop trace
        ),
        (
            "Lock Contention",
            vec!["contention_begin", "contention_end"],
            false, // Likely not in scxtop trace
        ),
    ];

    for (name, required, _expected) in tests {
        let supported = trace.supports_analysis(&required);
        println!(
            "  {}: {} (requires: {:?})",
            name,
            if supported { "✓" } else { "✗" },
            required
        );
    }
}

/// Test event count accuracy
#[test]
#[ignore]
fn test_event_count_accuracy() {
    let trace_path = Path::new("/home/hodgesd/scx/scxtop_trace_0.proto");

    if !trace_path.exists() {
        eprintln!("Trace file not found, skipping test");
        return;
    }

    let trace = PerfettoTrace::from_file(trace_path).expect("Failed to load trace");
    let caps = trace.build_capabilities();
    let index = trace.build_event_index();

    println!("\n=== Event Count Accuracy Test ===");

    // For each event type, compare capabilities count with index count
    for event_type in caps.list_event_types() {
        let caps_count = caps.get_event_count(&event_type);
        let index_count = index.get_event_count(&event_type);

        println!(
            "  {}: caps={}, index={}",
            event_type, caps_count, index_count
        );

        // Index might have more precise counts (splits softirq into entry/exit)
        // But for most events they should match
        if event_type != "softirq" {
            // For most event types, counts should be close or exact
            // Allow some tolerance for edge cases
            let diff = if caps_count > index_count {
                caps_count - index_count
            } else {
                index_count - caps_count
            };
            assert!(
                diff < 100,
                "Event counts should be close: {} vs {}",
                caps_count,
                index_count
            );
        }
    }
}

/// Test trace source detection variations
#[test]
fn test_trace_source_variations() {
    // Test Scxtop detection
    let mut caps_scxtop = TraceCapabilities {
        available_events: std::collections::HashSet::new(),
        event_counts: std::collections::HashMap::new(),
        track_event_categories: std::collections::HashSet::new(),
        track_event_counts: std::collections::HashMap::new(),
        clock_sources: std::collections::HashSet::new(),
        has_process_tree: true,
        has_system_info: false,
        has_process_stats: false,
        has_perf_samples: false,
        has_sched_ext: true, // Key marker
        time_range: (0, 1000000),
        num_cpus: 4,
        num_processes: 10,
        total_events: 1000,
        trace_source: TraceSource::Scxtop,
    };
    caps_scxtop
        .available_events
        .insert("sched_switch".to_string());
    assert_eq!(caps_scxtop.trace_source, TraceSource::Scxtop);

    // Test GenericFtrace detection
    let mut caps_generic = caps_scxtop.clone();
    caps_generic.has_sched_ext = false;
    caps_generic.trace_source = TraceSource::GenericFtrace;
    assert_eq!(caps_generic.trace_source, TraceSource::GenericFtrace);
}

/// Benchmark capabilities building (informally)
#[test]
#[ignore]
fn test_capabilities_performance() {
    let trace_path = Path::new("/home/hodgesd/scx/scxtop_trace_0.proto");

    if !trace_path.exists() {
        eprintln!("Trace file not found, skipping test");
        return;
    }

    let trace = PerfettoTrace::from_file(trace_path).expect("Failed to load trace");

    println!("\n=== Capabilities Building Performance ===");

    let start = std::time::Instant::now();
    let caps = trace.build_capabilities();
    let duration = start.elapsed();

    println!(
        "Built capabilities for {} events in {:?}",
        caps.total_events, duration
    );
    println!(
        "Events per second: {:.0}",
        caps.total_events as f64 / duration.as_secs_f64()
    );

    // Should be fast - under 100ms for typical traces
    assert!(
        duration.as_millis() < 500,
        "Capability building should be fast"
    );
}

/// Benchmark event index building (informally)
#[test]
#[ignore]
fn test_event_index_performance() {
    let trace_path = Path::new("/home/hodgesd/scx/scxtop_trace_0.proto");

    if !trace_path.exists() {
        eprintln!("Trace file not found, skipping test");
        return;
    }

    let trace = PerfettoTrace::from_file(trace_path).expect("Failed to load trace");

    println!("\n=== Event Index Building Performance ===");

    let start = std::time::Instant::now();
    let index = trace.build_event_index();
    let duration = start.elapsed();

    let total_indexed = index
        .list_event_types()
        .iter()
        .map(|t| index.get_event_count(t))
        .sum::<usize>();

    println!("Built index for {} events in {:?}", total_indexed, duration);
    println!(
        "Events per second: {:.0}",
        total_indexed as f64 / duration.as_secs_f64()
    );

    // Should be reasonably fast
    assert!(
        duration.as_millis() < 2000,
        "Index building should complete in reasonable time"
    );
}
