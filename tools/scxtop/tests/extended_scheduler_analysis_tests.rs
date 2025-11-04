// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

//! Tests for extended scheduler analyses: task states, preemption, wakeup chains, latency breakdown

use scxtop::mcp::perfetto_analyzers_extended::*;
use scxtop::mcp::perfetto_parser::*;
use std::path::Path;
use std::sync::Arc;

#[test]
#[ignore]
fn test_task_state_analysis() {
    let trace_path = Path::new("/home/hodgesd/scx/scxtop_trace_0.proto");

    if !trace_path.exists() {
        eprintln!("Trace file not found, skipping test");
        return;
    }

    let trace = Arc::new(PerfettoTrace::from_file(trace_path).unwrap());
    let analyzer = TaskStateAnalyzer::new(trace);

    let start = std::time::Instant::now();
    let stats = analyzer.analyze_task_states(None);
    let duration = start.elapsed();

    println!("\n=== Task State Analysis Test ===");
    println!("Time taken: {:?}", duration);
    println!("Total processes: {}", stats.len());

    // Show top 10 by total time
    println!("\nTop 10 processes by total time:");
    for (i, stat) in stats.iter().take(10).enumerate() {
        println!("\n{}. {} (PID {})", i + 1, stat.comm, stat.pid);
        println!("   Total time: {} ns", stat.total_time_ns);
        println!("   State breakdown:");
        println!(
            "     Running:  {:.2}% ({} ns)",
            stat.running_percent, stat.running_time_ns
        );
        println!(
            "     Runnable: {:.2}% ({} ns)",
            stat.runnable_percent, stat.runnable_time_ns
        );
        println!(
            "     Sleeping: {:.2}% ({} ns)",
            stat.sleeping_percent, stat.sleeping_time_ns
        );
        println!(
            "     Blocked:  {:.2}% ({} ns)",
            stat.blocked_percent, stat.blocked_time_ns
        );
        println!("   Context switches:");
        println!("     Voluntary:   {}", stat.voluntary_switches);
        println!("     Involuntary: {}", stat.involuntary_switches);
        println!("   Scheduler latency (runnable→running):");
        println!("     avg: {} ns", stat.avg_scheduler_latency_ns);
        println!("     p50: {} ns", stat.p50_scheduler_latency_ns);
        println!("     p95: {} ns", stat.p95_scheduler_latency_ns);
        println!("     p99: {} ns", stat.p99_scheduler_latency_ns);
    }

    assert!(!stats.is_empty(), "Expected task state stats");

    // Verify percentages add up to ~100%
    for stat in stats.iter().take(10) {
        let total_percent = stat.running_percent
            + stat.runnable_percent
            + stat.sleeping_percent
            + stat.blocked_percent;
        assert!(
            (total_percent - 100.0).abs() < 1.0,
            "State percentages should add to 100%, got {}",
            total_percent
        );
    }
}

#[test]
#[ignore]
fn test_preemption_analysis() {
    let trace_path = Path::new("/home/hodgesd/scx/scxtop_trace_0.proto");

    if !trace_path.exists() {
        eprintln!("Trace file not found, skipping test");
        return;
    }

    let trace = Arc::new(PerfettoTrace::from_file(trace_path).unwrap());
    let analyzer = PreemptionAnalyzer::new(trace);

    let start = std::time::Instant::now();
    let stats = analyzer.analyze_preemptions(None);
    let duration = start.elapsed();

    println!("\n=== Preemption Analysis Test ===");
    println!("Time taken: {:?}", duration);
    println!("Total processes with preemptions: {}", stats.len());

    // Show top 10 most preempted
    println!("\nTop 10 most preempted processes:");
    for (i, stat) in stats.iter().take(10).enumerate() {
        println!("\n{}. {} (PID {})", i + 1, stat.comm, stat.pid);
        println!("   Total preemptions: {}", stat.preempted_count);
        println!("   Preempted by (top 5):");
        for (j, preemptor) in stat.preempted_by.iter().take(5).enumerate() {
            println!(
                "     {}. {} (PID {}): {} times",
                j + 1,
                preemptor.comm,
                preemptor.pid,
                preemptor.count
            );
        }
    }

    assert!(!stats.is_empty(), "Expected preemption stats");

    // Verify ordering
    for i in 1..stats.len().min(10) {
        assert!(
            stats[i - 1].preempted_count >= stats[i].preempted_count,
            "Stats should be sorted by preemption count"
        );
    }
}

#[test]
#[ignore]
fn test_wakeup_chain_detection() {
    let trace_path = Path::new("/home/hodgesd/scx/scxtop_trace_0.proto");

    if !trace_path.exists() {
        eprintln!("Trace file not found, skipping test");
        return;
    }

    let trace = Arc::new(PerfettoTrace::from_file(trace_path).unwrap());
    let analyzer = WakeupChainDetector::new(trace);

    let start = std::time::Instant::now();
    let chains = analyzer.find_wakeup_chains(20);
    let duration = start.elapsed();

    println!("\n=== Wakeup Chain Detection Test ===");
    println!("Time taken: {:?}", duration);
    println!("Critical chains found: {}", chains.len());

    // Show top 5 chains
    println!("\nTop 5 critical wakeup chains:");
    for (i, chain) in chains.iter().take(5).enumerate() {
        println!(
            "\n{}. Chain length: {}, Total latency: {:.2}ms, Criticality: {:.2}",
            i + 1,
            chain.chain_length,
            chain.total_latency_ns as f64 / 1_000_000.0,
            chain.criticality_score
        );
        println!("   Chain:");
        for (j, event) in chain.chain.iter().enumerate() {
            let latency = event
                .schedule_ts
                .map(|s| s.saturating_sub(event.wakeup_ts))
                .unwrap_or(0);
            println!(
                "     {}. PID {} ({}) woken by PID {}, latency: {:.2}ms",
                j + 1,
                event.wakee_pid,
                event.wakee_comm,
                event.waker_pid,
                latency as f64 / 1_000_000.0
            );
        }
    }

    assert!(!chains.is_empty(), "Expected wakeup chains");

    // Verify ordering by criticality
    for i in 1..chains.len().min(5) {
        assert!(
            chains[i - 1].criticality_score >= chains[i].criticality_score,
            "Chains should be sorted by criticality score"
        );
    }
}

#[test]
#[ignore]
fn test_scheduling_latency_breakdown() {
    let trace_path = Path::new("/home/hodgesd/scx/scxtop_trace_0.proto");

    if !trace_path.exists() {
        eprintln!("Trace file not found, skipping test");
        return;
    }

    let trace = Arc::new(PerfettoTrace::from_file(trace_path).unwrap());
    let analyzer = SchedulingLatencyBreakdown::new(trace);

    let start = std::time::Instant::now();
    let stats = analyzer.analyze_latency_stages();
    let duration = start.elapsed();

    println!("\n=== Scheduling Latency Breakdown Test ===");
    println!("Time taken: {:?}", duration);
    println!("Total average latency: {} ns", stats.total_avg_latency_ns);

    println!("\nWaking→Wakeup stage (wakeup path):");
    println!("   Count: {}", stats.waking_to_wakeup.count);
    println!("   Average: {} ns", stats.waking_to_wakeup.avg_ns);
    println!("   p50: {} ns", stats.waking_to_wakeup.p50_ns);
    println!("   p95: {} ns", stats.waking_to_wakeup.p95_ns);
    println!("   p99: {} ns", stats.waking_to_wakeup.p99_ns);
    println!(
        "   Percent of total: {:.2}%",
        stats.waking_to_wakeup.percent_of_total
    );

    println!("\nWakeup→Schedule stage (runqueue wait):");
    println!("   Count: {}", stats.wakeup_to_schedule.count);
    println!("   Average: {} ns", stats.wakeup_to_schedule.avg_ns);
    println!("   p50: {} ns", stats.wakeup_to_schedule.p50_ns);
    println!("   p95: {} ns", stats.wakeup_to_schedule.p95_ns);
    println!("   p99: {} ns", stats.wakeup_to_schedule.p99_ns);
    println!(
        "   Percent of total: {:.2}%",
        stats.wakeup_to_schedule.percent_of_total
    );

    assert!(stats.waking_to_wakeup.count > 0 || stats.wakeup_to_schedule.count > 0);

    // Verify percentages add up to 100%
    let total_percent =
        stats.waking_to_wakeup.percent_of_total + stats.wakeup_to_schedule.percent_of_total;
    assert!(
        (total_percent - 100.0).abs() < 0.1,
        "Percentages should add to 100%, got {}",
        total_percent
    );
}

#[test]
#[ignore]
fn test_all_extended_analyses() {
    let trace_path = Path::new("/home/hodgesd/scx/scxtop_trace_0.proto");

    if !trace_path.exists() {
        eprintln!("Trace file not found, skipping test");
        return;
    }

    println!("\n=== Complete Extended Analysis Suite ===\n");

    let load_start = std::time::Instant::now();
    let trace = Arc::new(PerfettoTrace::from_file(trace_path).unwrap());
    let load_time = load_start.elapsed();
    println!("Trace loaded in {:?}", load_time);

    // Task state analysis
    let start = std::time::Instant::now();
    let task_analyzer = TaskStateAnalyzer::new(trace.clone());
    let task_stats = task_analyzer.analyze_task_states(None);
    println!(
        "✓ Task state analysis: {} processes in {:?}",
        task_stats.len(),
        start.elapsed()
    );

    // Preemption analysis
    let start = std::time::Instant::now();
    let preempt_analyzer = PreemptionAnalyzer::new(trace.clone());
    let preempt_stats = preempt_analyzer.analyze_preemptions(None);
    println!(
        "✓ Preemption analysis: {} processes in {:?}",
        preempt_stats.len(),
        start.elapsed()
    );

    // Wakeup chain detection
    let start = std::time::Instant::now();
    let chain_detector = WakeupChainDetector::new(trace.clone());
    let chains = chain_detector.find_wakeup_chains(20);
    println!(
        "✓ Wakeup chain detection: {} chains in {:?}",
        chains.len(),
        start.elapsed()
    );

    // Latency breakdown
    let start = std::time::Instant::now();
    let latency_analyzer = SchedulingLatencyBreakdown::new(trace);
    let latency_stats = latency_analyzer.analyze_latency_stages();
    println!("✓ Latency breakdown: analyzed in {:?}", start.elapsed());
    println!(
        "   - Waking→Wakeup: {:.2}%",
        latency_stats.waking_to_wakeup.percent_of_total
    );
    println!(
        "   - Wakeup→Schedule: {:.2}%",
        latency_stats.wakeup_to_schedule.percent_of_total
    );

    println!("\n✅ All extended analyses completed successfully!");
}
