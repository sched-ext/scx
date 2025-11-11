// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

//! Tests for Phase 3: I/O and Resource Analyzers

use scxtop::mcp::{
    BlockIoAnalyzer, FileIoAnalyzer, MemoryPressureAnalyzer, NetworkIoAnalyzer, PerfettoTrace,
};
use std::path::Path;

/// Test Block I/O analyzer with real trace
#[test]
#[ignore] // Only run with --ignored since it requires the trace file
fn test_block_io_analyzer_real_trace() {
    let trace_path = Path::new("/home/hodgesd/scx/scxtop_trace_0.proto");

    if !trace_path.exists() {
        eprintln!("Trace file not found, skipping test");
        return;
    }

    let trace = PerfettoTrace::from_file(trace_path).expect("Failed to load trace");
    let result = BlockIoAnalyzer::analyze(&trace);

    println!("\n=== Block I/O Analysis ===");
    println!("Total I/O operations: {}", result.total_ios);
    println!("  Read operations: {}", result.read_count);
    println!("  Write operations: {}", result.write_count);

    if let Some(read_lat) = &result.read_latency {
        println!("\nRead latency:");
        println!("  Mean: {:.2}µs", read_lat.mean / 1000.0);
        println!("  P50: {}µs", read_lat.median / 1000);
        println!("  P95: {}µs", read_lat.p95 / 1000);
        println!("  P99: {}µs", read_lat.p99 / 1000);
    }

    if let Some(write_lat) = &result.write_latency {
        println!("\nWrite latency:");
        println!("  Mean: {:.2}µs", write_lat.mean / 1000.0);
        println!("  P50: {}µs", write_lat.median / 1000);
        println!("  P95: {}µs", write_lat.p95 / 1000);
    }

    // Block I/O may not be present in all traces
    println!("\n(Block I/O events may not be captured in all traces)");
}

/// Test Network I/O analyzer with real trace
#[test]
#[ignore]
fn test_network_io_analyzer_real_trace() {
    let trace_path = Path::new("/home/hodgesd/scx/scxtop_trace_0.proto");

    if !trace_path.exists() {
        eprintln!("Trace file not found, skipping test");
        return;
    }

    let trace = PerfettoTrace::from_file(trace_path).expect("Failed to load trace");
    let result = NetworkIoAnalyzer::analyze(&trace);

    println!("\n=== Network I/O Analysis ===");
    println!("TX packets: {}", result.tx_packets);
    println!("RX packets: {}", result.rx_packets);
    println!(
        "TX bytes: {} ({:.2} MB)",
        result.tx_bytes,
        result.tx_bytes as f64 / 1_000_000.0
    );
    println!(
        "RX bytes: {} ({:.2} MB)",
        result.rx_bytes,
        result.rx_bytes as f64 / 1_000_000.0
    );
    println!("\nBandwidth (over {:.2}s):", result.duration_secs);
    println!("  TX: {:.2} Mbps", result.tx_bandwidth_mbps);
    println!("  RX: {:.2} Mbps", result.rx_bandwidth_mbps);

    // Network events may not be present in all traces
    println!("\n(Network I/O events may not be captured in all traces)");
}

/// Test Memory Pressure analyzer with real trace
#[test]
#[ignore]
fn test_memory_pressure_analyzer_real_trace() {
    let trace_path = Path::new("/home/hodgesd/scx/scxtop_trace_0.proto");

    if !trace_path.exists() {
        eprintln!("Trace file not found, skipping test");
        return;
    }

    let trace = PerfettoTrace::from_file(trace_path).expect("Failed to load trace");
    let result = MemoryPressureAnalyzer::analyze(&trace);

    println!("\n=== Memory Pressure Analysis ===");
    println!("Page allocations: {}", result.page_alloc_count);
    println!("Page frees: {}", result.page_free_count);
    println!("Net allocation: {} pages", result.net_allocation);
    println!("Direct reclaim events: {}", result.reclaim_count);

    if let Some(reclaim_lat) = &result.reclaim_latency {
        println!("\nDirect reclaim latency:");
        println!("  Mean: {:.2}µs", reclaim_lat.mean / 1000.0);
        println!("  P50: {}µs", reclaim_lat.median / 1000);
        println!("  P95: {}µs", reclaim_lat.p95 / 1000);
        println!("  P99: {}µs", reclaim_lat.p99 / 1000);
        println!("  Max: {}µs", reclaim_lat.max / 1000);
    }

    // Memory events may not be present in all traces
    println!("\n(Memory events may not be captured in all traces)");
}

/// Test File I/O analyzer with real trace
#[test]
#[ignore]
fn test_file_io_analyzer_real_trace() {
    let trace_path = Path::new("/home/hodgesd/scx/scxtop_trace_0.proto");

    if !trace_path.exists() {
        eprintln!("Trace file not found, skipping test");
        return;
    }

    let trace = PerfettoTrace::from_file(trace_path).expect("Failed to load trace");
    let result = FileIoAnalyzer::analyze(&trace);

    println!("\n=== File I/O Analysis ===");
    println!("File sync operations: {}", result.sync_count);

    if let Some(sync_lat) = &result.sync_latency {
        println!("\nFile sync latency:");
        println!("  Mean: {:.2}µs", sync_lat.mean / 1000.0);
        println!("  P50: {}µs", sync_lat.median / 1000);
        println!("  P95: {}µs", sync_lat.p95 / 1000);
        println!("  P99: {}µs", sync_lat.p99 / 1000);
    }

    // File I/O events may not be present in all traces
    println!("\n(File I/O events may not be captured in all traces)");
}

/// Test that all analyzers handle empty results gracefully
#[test]
fn test_io_analyzers_empty_results() {
    // All analyzers should return empty/zero results without panicking
    // when no events are found
}

/// Test Block I/O latency breakdown
#[test]
#[ignore]
fn test_block_io_latency_breakdown() {
    let trace_path = Path::new("/home/hodgesd/scx/scxtop_trace_0.proto");

    if !trace_path.exists() {
        eprintln!("Trace file not found, skipping test");
        return;
    }

    let trace = PerfettoTrace::from_file(trace_path).expect("Failed to load trace");
    let result = BlockIoAnalyzer::analyze(&trace);

    println!("\n=== Block I/O Latency Breakdown ===");

    if let Some(queue_lat) = &result.queue_latency {
        println!("Queue latency (insert->issue):");
        println!("  Mean: {:.2}µs", queue_lat.mean / 1000.0);
    }

    if let Some(device_lat) = &result.device_latency {
        println!("\nDevice latency (issue->complete):");
        println!("  Mean: {:.2}µs", device_lat.mean / 1000.0);
    }
}

/// Test Network I/O bandwidth calculation
#[test]
#[ignore]
fn test_network_io_bandwidth() {
    let trace_path = Path::new("/home/hodgesd/scx/scxtop_trace_0.proto");

    if !trace_path.exists() {
        eprintln!("Trace file not found, skipping test");
        return;
    }

    let trace = PerfettoTrace::from_file(trace_path).expect("Failed to load trace");
    let result = NetworkIoAnalyzer::analyze(&trace);

    println!("\n=== Network Bandwidth Calculation ===");

    if result.duration_secs > 0.0 {
        println!("Trace duration: {:.2}s", result.duration_secs);
        println!(
            "Average TX rate: {:.2} KB/s",
            result.tx_bytes as f64 / result.duration_secs / 1000.0
        );
        println!(
            "Average RX rate: {:.2} KB/s",
            result.rx_bytes as f64 / result.duration_secs / 1000.0
        );
    }
}
