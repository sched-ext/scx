// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use scxtop::mcp::perfetto_analyzers::{
    ContextSwitchAnalyzer, DsqAnalyzer, PerfettoMigrationAnalyzer, WakeupChainAnalyzer,
};
use scxtop::mcp::perfetto_parser::*;
use std::path::Path;
use std::sync::Arc;

#[test]
#[ignore] // Requires real trace file
fn test_cpu_utilization_analysis() {
    let trace_path = Path::new("/home/hodgesd/scx/scxtop_trace_0.proto");

    if !trace_path.exists() {
        eprintln!("Trace file not found, skipping test");
        return;
    }

    let trace = Arc::new(PerfettoTrace::from_file(trace_path).unwrap());
    let analyzer = ContextSwitchAnalyzer::new(trace);

    // Test single-threaded version
    let stats = analyzer.analyze_cpu_utilization();

    println!("\n=== CPU Utilization Analysis (Single-threaded) ===");
    println!("Analyzed {} CPUs", stats.len());

    // Show first 5 CPUs
    for cpu_id in 0..5.min(stats.len()) {
        if let Some(cpu_stats) = stats.get(&(cpu_id as u32)) {
            println!("\nCPU {}:", cpu_id);
            println!("  Utilization: {:.2}%", cpu_stats.utilization_percent);
            println!("  Total switches: {}", cpu_stats.total_switches);
            println!("  Timeslice stats (ns):");
            println!("    min:    {}", cpu_stats.min_timeslice_ns);
            println!("    avg:    {}", cpu_stats.avg_timeslice_ns);
            println!("    p50:    {}", cpu_stats.p50_timeslice_ns);
            println!("    p95:    {}", cpu_stats.p95_timeslice_ns);
            println!("    p99:    {}", cpu_stats.p99_timeslice_ns);
            println!("    max:    {}", cpu_stats.max_timeslice_ns);
        }
    }

    assert!(!stats.is_empty(), "Expected CPU statistics");

    // Verify percentiles are ordered
    for cpu_stats in stats.values() {
        assert!(cpu_stats.min_timeslice_ns <= cpu_stats.avg_timeslice_ns);
        assert!(cpu_stats.p50_timeslice_ns <= cpu_stats.p95_timeslice_ns);
        assert!(cpu_stats.p95_timeslice_ns <= cpu_stats.p99_timeslice_ns);
        assert!(cpu_stats.p99_timeslice_ns <= cpu_stats.max_timeslice_ns);
    }
}

#[test]
#[ignore]
fn test_cpu_utilization_parallel() {
    let trace_path = Path::new("/home/hodgesd/scx/scxtop_trace_0.proto");

    if !trace_path.exists() {
        eprintln!("Trace file not found, skipping test");
        return;
    }

    let trace = Arc::new(PerfettoTrace::from_file(trace_path).unwrap());
    let analyzer = ContextSwitchAnalyzer::new(trace);

    // Test parallel version
    let start = std::time::Instant::now();
    let stats_parallel = analyzer.analyze_cpu_utilization_parallel();
    let parallel_time = start.elapsed();

    println!("\n=== CPU Utilization Analysis (Parallel) ===");
    println!("Time taken: {:?}", parallel_time);
    println!("Analyzed {} CPUs", stats_parallel.len());

    assert!(!stats_parallel.is_empty(), "Expected CPU statistics");

    // Verify results match single-threaded (basic sanity check)
    let stats_single = analyzer.analyze_cpu_utilization();
    assert_eq!(
        stats_parallel.len(),
        stats_single.len(),
        "Parallel and single-threaded should analyze same number of CPUs"
    );
}

#[test]
#[ignore]
fn test_process_runtime_analysis() {
    let trace_path = Path::new("/home/hodgesd/scx/scxtop_trace_0.proto");

    if !trace_path.exists() {
        eprintln!("Trace file not found, skipping test");
        return;
    }

    let trace = Arc::new(PerfettoTrace::from_file(trace_path).unwrap());
    let analyzer = ContextSwitchAnalyzer::new(trace);

    let stats = analyzer.analyze_process_runtime(None);

    println!("\n=== Process Runtime Analysis ===");
    println!("Total processes: {}", stats.len());

    // Show top 10 processes by runtime
    println!("\nTop 10 processes by runtime:");
    for (i, proc) in stats.iter().take(10).enumerate() {
        println!("\n{}. {} (PID {})", i + 1, proc.comm, proc.pid);
        println!("   Total runtime: {} ns", proc.total_runtime_ns);
        println!("   CPU time: {:.2}%", proc.cpu_time_percent);
        println!("   Switches: {}", proc.num_switches);
        println!("   Timeslice percentiles (ns):");
        println!("     min: {}", proc.min_timeslice_ns);
        println!("     p50: {}", proc.p50_timeslice_ns);
        println!("     p95: {}", proc.p95_timeslice_ns);
        println!("     p99: {}", proc.p99_timeslice_ns);
        println!("     max: {}", proc.max_timeslice_ns);
    }

    assert!(!stats.is_empty(), "Expected process statistics");

    // Verify ordering (should be sorted by runtime descending)
    for i in 1..stats.len().min(10) {
        assert!(
            stats[i - 1].total_runtime_ns >= stats[i].total_runtime_ns,
            "Process stats should be sorted by runtime"
        );
    }
}

#[test]
#[ignore]
fn test_process_runtime_parallel() {
    let trace_path = Path::new("/home/hodgesd/scx/scxtop_trace_0.proto");

    if !trace_path.exists() {
        eprintln!("Trace file not found, skipping test");
        return;
    }

    let trace = Arc::new(PerfettoTrace::from_file(trace_path).unwrap());
    let analyzer = ContextSwitchAnalyzer::new(trace);

    let start = std::time::Instant::now();
    let stats_parallel = analyzer.analyze_process_runtime_parallel(None);
    let parallel_time = start.elapsed();

    println!("\n=== Process Runtime Analysis (Parallel) ===");
    println!("Time taken: {:?}", parallel_time);
    println!("Total processes: {}", stats_parallel.len());

    assert!(!stats_parallel.is_empty(), "Expected process statistics");

    // Compare with single-threaded
    let start = std::time::Instant::now();
    let stats_single = analyzer.analyze_process_runtime(None);
    let single_time = start.elapsed();

    println!("Single-threaded time: {:?}", single_time);
    println!(
        "Speedup: {:.2}x",
        single_time.as_secs_f64() / parallel_time.as_secs_f64()
    );

    // Should analyze same number of processes
    assert_eq!(stats_parallel.len(), stats_single.len());
}

#[test]
#[ignore]
fn test_wakeup_latency_analysis() {
    let trace_path = Path::new("/home/hodgesd/scx/scxtop_trace_0.proto");

    if !trace_path.exists() {
        eprintln!("Trace file not found, skipping test");
        return;
    }

    let trace = Arc::new(PerfettoTrace::from_file(trace_path).unwrap());
    let analyzer = WakeupChainAnalyzer::new(trace);

    let stats = analyzer.analyze_wakeup_latency();

    println!("\n=== Wakeup Latency Analysis ===");
    println!("Total wakeups: {}", stats.total_wakeups);
    println!("Latency statistics (ns):");
    println!("  min:  {}", stats.min_latency_ns);
    println!("  avg:  {}", stats.avg_latency_ns);
    println!("  p50:  {}", stats.p50_latency_ns);
    println!("  p95:  {}", stats.p95_latency_ns);
    println!("  p99:  {}", stats.p99_latency_ns);
    println!("  p999: {}", stats.p999_latency_ns);
    println!("  max:  {}", stats.max_latency_ns);

    println!("\nPer-CPU statistics:");
    for (cpu, cpu_stats) in stats.per_cpu_stats.iter().take(5) {
        println!(
            "  CPU {}: {} wakeups, avg={} ns, p99={} ns",
            cpu, cpu_stats.count, cpu_stats.avg_latency_ns, cpu_stats.p99_latency_ns
        );
    }

    assert!(stats.total_wakeups > 0, "Expected wakeup events");

    // Verify percentile ordering
    assert!(stats.min_latency_ns <= stats.p50_latency_ns);
    assert!(stats.p50_latency_ns <= stats.p95_latency_ns);
    assert!(stats.p95_latency_ns <= stats.p99_latency_ns);
    assert!(stats.p99_latency_ns <= stats.p999_latency_ns);
    assert!(stats.p999_latency_ns <= stats.max_latency_ns);
}

#[test]
#[ignore]
fn test_migration_analysis() {
    let trace_path = Path::new("/home/hodgesd/scx/scxtop_trace_0.proto");

    if !trace_path.exists() {
        eprintln!("Trace file not found, skipping test");
        return;
    }

    let trace = Arc::new(PerfettoTrace::from_file(trace_path).unwrap());
    let analyzer = PerfettoMigrationAnalyzer::new(trace);

    let stats = analyzer.analyze_migration_patterns();

    println!("\n=== Migration Analysis ===");
    println!("Total migrations: {}", stats.total_migrations);
    println!("Cross-NUMA migrations: {}", stats.cross_numa_migrations);
    println!("Cross-LLC migrations: {}", stats.cross_llc_migrations);

    println!("\nTop 10 processes by migration count:");
    let mut process_migrations: Vec<_> = stats.migrations_by_process.iter().collect();
    process_migrations.sort_by(|a, b| b.1.cmp(a.1));

    for (i, (pid, count)) in process_migrations.iter().take(10).enumerate() {
        println!("  {}. PID {}: {} migrations", i + 1, pid, count);
    }

    // Note: Migration latency stats will be 0 until implemented
    println!("\nMigration latency statistics (ns):");
    println!("  min: {}", stats.min_latency_ns);
    println!("  avg: {}", stats.avg_latency_ns);
    println!("  p50: {}", stats.p50_latency_ns);
    println!("  p95: {}", stats.p95_latency_ns);
    println!("  p99: {}", stats.p99_latency_ns);
    println!("  max: {}", stats.max_latency_ns);
}

#[test]
#[ignore]
fn test_dsq_analysis() {
    let trace_path = Path::new("/home/hodgesd/scx/scxtop_trace_0.proto");

    if !trace_path.exists() {
        eprintln!("Trace file not found, skipping test");
        return;
    }

    let trace = Arc::new(PerfettoTrace::from_file(trace_path).unwrap());
    let analyzer = DsqAnalyzer::new(trace);

    println!("\n=== DSQ Analysis ===");

    if !analyzer.has_scx_data() {
        println!("Not a sched_ext trace, skipping DSQ analysis");
        return;
    }

    let summary = analyzer.get_summary().expect("Expected DSQ summary");

    println!("Scheduler: {:?}", summary.scheduler_name);
    println!("Total DSQs: {}", summary.total_dsqs);
    println!(
        "DSQ IDs: {:?}",
        &summary.dsq_ids[..summary.dsq_ids.len().min(10)]
    );

    assert!(summary.total_dsqs > 0, "Expected DSQs in sched_ext trace");
}

#[test]
#[ignore]
fn test_full_analysis_workflow() {
    let trace_path = Path::new("/home/hodgesd/scx/scxtop_trace_0.proto");

    if !trace_path.exists() {
        eprintln!("Trace file not found, skipping test");
        return;
    }

    println!("\n=== Full Analysis Workflow ===");

    // Load trace
    let load_start = std::time::Instant::now();
    let trace = Arc::new(PerfettoTrace::from_file(trace_path).unwrap());
    let load_time = load_start.elapsed();
    println!("Trace loaded in {:?}", load_time);

    // Run all analyzers
    let analysis_start = std::time::Instant::now();

    let ctx_analyzer = ContextSwitchAnalyzer::new(trace.clone());
    let cpu_stats = ctx_analyzer.analyze_cpu_utilization_parallel();
    println!("✓ CPU utilization analyzed: {} CPUs", cpu_stats.len());

    let process_stats = ctx_analyzer.analyze_process_runtime_parallel(None);
    println!(
        "✓ Process runtime analyzed: {} processes",
        process_stats.len()
    );

    let wakeup_analyzer = WakeupChainAnalyzer::new(trace.clone());
    let wakeup_stats = wakeup_analyzer.analyze_wakeup_latency();
    println!(
        "✓ Wakeup latency analyzed: {} wakeups",
        wakeup_stats.total_wakeups
    );

    let migration_analyzer = PerfettoMigrationAnalyzer::new(trace.clone());
    let migration_stats = migration_analyzer.analyze_migration_patterns();
    println!(
        "✓ Migration patterns analyzed: {} migrations",
        migration_stats.total_migrations
    );

    let dsq_analyzer = DsqAnalyzer::new(trace.clone());
    if dsq_analyzer.has_scx_data() {
        let dsq_summary = dsq_analyzer.get_summary().unwrap();
        println!("✓ DSQ analysis: {} queues", dsq_summary.total_dsqs);
    }

    let analysis_time = analysis_start.elapsed();
    println!("\nTotal analysis time: {:?}", analysis_time);
    println!("Analysis completed successfully!");
}
