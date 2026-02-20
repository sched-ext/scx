use std::path::Path;

use scx_simulator::*;

mod common;

/// Run two_runners.json through mitosis and dump the full trace.
///
/// This test exists for real-vs-simulated comparison. Run it with:
///   RUST_LOG=debug cargo test test_compare_two_runners_mitosis --test compare -- --nocapture
///
/// The debug-level output shows ops callbacks (select_cpu, enqueue, dispatch,
/// running, stopping) interleaved with info-level lifecycle events (STARTED,
/// PREEMPTED, SLEEPING, IDLE). Compare this against bpftrace output from
/// scripts/run_real.sh to identify simulator realism gaps.
#[test]
fn test_compare_two_runners_mitosis() {
    let _lock = common::setup_test();
    let json = include_str!("../workloads/two_runners.json");
    let scenario = load_rtapp(json, 2).unwrap();

    let trace = Simulator::new(DynamicScheduler::mitosis(2)).run(scenario);
    trace.dump();

    // Sanity: both tasks should run
    let heavy_rt = trace.total_runtime(Pid(1));
    let light_rt = trace.total_runtime(Pid(2));
    eprintln!("\n--- Summary ---");
    eprintln!(
        "heavy(pid=1): runtime={}ms, schedules={}",
        heavy_rt / 1_000_000,
        trace.schedule_count(Pid(1))
    );
    eprintln!(
        "light(pid=2): runtime={}ms, schedules={}",
        light_rt / 1_000_000,
        trace.schedule_count(Pid(2))
    );

    assert!(heavy_rt > 0, "heavy task got no runtime");
    assert!(light_rt > 0, "light task got no runtime");
}

/// Run two_runners.json through mitosis and compute detailed statistics.
///
/// This test demonstrates the TraceStats module for quantifying realism gaps.
/// Run with:
///   cargo test test_mitosis_trace_stats --test compare -- --nocapture
///
/// The output includes:
/// - Per-task run duration statistics (mean, stddev, CV%)
/// - Per-CPU tick interval statistics
/// - Yield/enqueue/preemption counts (for Gap 1 detection)
/// - Realism score
#[test]
fn test_mitosis_trace_stats() {
    let _lock = common::setup_test();
    let json = include_str!("../workloads/two_runners.json");
    let scenario = load_rtapp(json, 2).unwrap();

    let trace = Simulator::new(DynamicScheduler::mitosis(2)).run(scenario);

    // Compute and print statistics
    let stats = TraceStats::from_trace(&trace);
    stats.print_summary();

    // Check for Gap 1: spurious yield/re-enqueue cycles
    // In the current simulator, CPU-bound tasks have high yield counts
    // because Phase::Run boundaries trigger yield behavior.
    let task1 = stats.tasks.get(&Pid(1));
    if let Some(ts) = task1 {
        eprintln!("--- Gap 1 Analysis (Task 1) ---");
        eprintln!(
            "  Yield ratio: {:.1}% ({} yields / {} schedules)",
            if ts.schedule_count > 0 {
                100.0 * ts.yield_count as f64 / ts.schedule_count as f64
            } else {
                0.0
            },
            ts.yield_count,
            ts.schedule_count
        );
        eprintln!(
            "  Direct dispatch ratio: {:.1}%",
            if ts.schedule_count > 0 {
                100.0 * ts.direct_dispatch_count as f64 / ts.schedule_count as f64
            } else {
                0.0
            }
        );
    }

    // Check for Gap 2: tick frequency
    for (cpu, cs) in &stats.cpus {
        eprintln!("--- Gap 2 Analysis (CPU {}) ---", cpu.0);
        eprintln!(
            "  Tick interval: {:.3}ms mean (expected ~4ms for HZ=250)",
            cs.tick_interval.mean() / 1_000_000.0
        );
        eprintln!(
            "  Tick jitter CV: {:.1}% (low = unrealistic)",
            cs.tick_interval.cv_percent()
        );
    }

    eprintln!("\n--- Realism Score ---");
    eprintln!("  Score: {:.1}/100", stats.realism_score());

    // Sanity checks
    assert!(
        stats.tasks.len() >= 2,
        "expected at least 2 tasks in trace stats"
    );
}

/// Run two_runners.json through LAVD and produce detailed statistics
/// for comparison with real kernel traces.
///
/// This test outputs TraceSummary data and per-task metrics that can be
/// compared against bpftrace output from `--real-run --bpf-trace`.
///
/// Run with: cargo test test_compare_lavd_trace_stats --test compare -- --nocapture
#[test]
fn test_compare_lavd_trace_stats() {
    let _lock = common::setup_test();
    let json = include_str!("../workloads/two_runners.json");
    let scenario = load_rtapp(json, 2).unwrap();

    let trace = Simulator::new(DynamicScheduler::lavd(2)).run(scenario);

    // Print high-level summary
    let summary = trace.summary();
    eprintln!("\n=== LAVD Trace Statistics (for real-vs-sim comparison) ===\n");
    eprintln!("{}", summary);

    // Per-task statistics
    for pid in [Pid(1), Pid(2)] {
        let name = if pid == Pid(1) { "heavy" } else { "light" };
        let runtime_ms = trace.total_runtime(pid) / 1_000_000;
        let schedules = trace.schedule_count(pid);
        let yields = trace.yield_count(pid);
        let preempts = trace.preempt_count(pid);
        let dsq_inserts = trace.dsq_insert_count(pid);

        eprintln!("Task {name} (pid={}):", pid.0);
        eprintln!("  total_runtime:  {}ms", runtime_ms);
        eprintln!("  schedule_count: {}", schedules);
        eprintln!("  yield_count:    {}", yields);
        eprintln!("  preempt_count:  {}", preempts);
        eprintln!("  dsq_inserts:    {}", dsq_inserts);

        if let Some((min, max, mean, count)) = trace.run_duration_stats(pid) {
            eprintln!(
                "  run_durations:  min={}us max={}us mean={}us count={}",
                min / 1000,
                max / 1000,
                mean / 1000,
                count
            );
        }
        eprintln!();
    }

    // Realism gap indicators
    eprintln!("=== Realism Gap Indicators ===\n");

    let yield_ratio = if summary.total_preempts + summary.total_yields > 0 {
        summary.total_yields as f64 / (summary.total_preempts + summary.total_yields) as f64
    } else {
        0.0
    };
    eprintln!(
        "Yield ratio: {:.1}% (high values for CPU-bound tasks indicate spurious yields)",
        yield_ratio * 100.0
    );

    let dsq_ratio = if summary.global_dsq_dispatches + summary.local_dsq_dispatches > 0 {
        summary.global_dsq_dispatches as f64
            / (summary.global_dsq_dispatches + summary.local_dsq_dispatches) as f64
    } else {
        0.0
    };
    eprintln!(
        "Global DSQ ratio: {:.1}% (real CPU-bound tasks mostly use direct local dispatch)",
        dsq_ratio * 100.0
    );

    // Verify basic correctness
    assert!(trace.total_runtime(Pid(1)) > 0, "heavy task got no runtime");
    assert!(trace.total_runtime(Pid(2)) > 0, "light task got no runtime");
}

/// Parse a BPF trace file and compute statistics from it.
///
/// This test verifies the BPF trace parser works with synthetic trace data.
/// It demonstrates how to compute TraceStats from real kernel traces.
///
/// Run with: cargo test test_bpf_trace_parsing --test compare -- --nocapture
#[test]
fn test_bpf_trace_parsing() {
    // Synthetic BPF trace data matching trace_scx_ops.bt output format
    let trace_data = r#"
Attached 24 probes
Tracing sched_ext ops + kfuncs on CPUs 0-3. Ctrl-C to stop.

1000000 cpu=0 == sched_wakeup pid=100 comm=worker-0 target_cpu=0
1100000 cpu=0 >> select_task_rq
1101000 cpu=0 .. select_cpu_dfl pid=100 prev_cpu=0 ret=0
1102000 cpu=0 >> enqueue_task
1200000 cpu=0 >> balance
1201000 cpu=0 .. dispatch pid=100 dsq=9223372036854775810 slice=5000000 enq_flags=0
1202000 cpu=0 .. consume dsq=9223372036854775810 ret=1
1300000 cpu=0 >> set_next_task
1400000 cpu=0 == sched_switch prev_pid=0 prev_comm=swapper/0 prev_state=0 next_pid=100 next_comm=worker-0
5000000 cpu=0 >> task_tick
5400000 cpu=0 == sched_switch prev_pid=100 prev_comm=worker-0 prev_state=0 next_pid=0 next_comm=swapper/0
5500000 cpu=0 == sched_wakeup pid=100 comm=worker-0 target_cpu=0
5600000 cpu=0 == sched_switch prev_pid=0 prev_comm=swapper/0 prev_state=0 next_pid=100 next_comm=worker-0
9000000 cpu=0 >> task_tick
10000000 cpu=0 == sched_switch prev_pid=100 prev_comm=worker-0 prev_state=1 next_pid=0 next_comm=swapper/0

Done. Captured ops + kfunc trace.
"#;

    let bpf_trace = BpfTrace::parse(trace_data.as_bytes()).unwrap();

    // Basic parsing validation
    assert!(!bpf_trace.is_empty(), "trace should have events");
    assert_eq!(bpf_trace.task_name(Pid(100)), Some("worker-0"));
    assert_eq!(bpf_trace.duration_ns(), 9_000_000); // 10M - 1M ns

    // Compute stats
    let stats = bpf_trace.compute_stats();

    eprintln!("\n=== BPF Trace Statistics ===\n");
    stats.print_summary();

    // Verify task stats
    let task = stats.tasks.get(&Pid(100)).expect("task 100 should exist");
    assert_eq!(task.schedule_count, 2, "worker-0 scheduled twice");
    assert_eq!(task.preempt_count, 1, "one preemption (prev_state=0)");
    assert_eq!(task.sleep_count, 1, "one sleep (prev_state=1)");

    // Verify CPU stats
    let cpu0 = stats.cpus.get(&CpuId(0)).expect("CPU 0 should exist");
    assert_eq!(cpu0.tick_count, 2, "two tick events on CPU 0");
    assert_eq!(cpu0.balance_count, 1, "one balance call on CPU 0");

    // Verify global stats
    assert_eq!(stats.dsq_insert_count, 1, "one dispatch event");
    assert_eq!(stats.dsq_move_to_local_count, 1, "one consume success");
}

/// Compare BPF trace statistics with simulated trace statistics.
///
/// This test demonstrates the full comparison workflow:
/// 1. Parse a real BPF trace (synthetic data in this test)
/// 2. Run a simulated trace with the same workload pattern
/// 3. Compare the two using TraceComparisonResult
///
/// Run with: cargo test test_bpf_vs_simulated_comparison --test compare -- --nocapture
#[test]
fn test_bpf_vs_simulated_comparison() {
    let _lock = common::setup_test();

    // Synthetic BPF trace representing a simple CPU-bound task
    let bpf_data = r#"
Tracing sched_ext ops + kfuncs on CPUs 0-1. Ctrl-C to stop.

0 cpu=0 == sched_switch prev_pid=0 prev_comm=swapper/0 prev_state=0 next_pid=100 next_comm=worker
4000000 cpu=0 >> task_tick
5000000 cpu=0 == sched_switch prev_pid=100 prev_comm=worker prev_state=0 next_pid=0 next_comm=swapper/0
5100000 cpu=0 == sched_switch prev_pid=0 prev_comm=swapper/0 prev_state=0 next_pid=100 next_comm=worker
9000000 cpu=0 >> task_tick
10000000 cpu=0 == sched_switch prev_pid=100 prev_comm=worker prev_state=0 next_pid=0 next_comm=swapper/0
10100000 cpu=0 == sched_switch prev_pid=0 prev_comm=swapper/0 prev_state=0 next_pid=100 next_comm=worker
14000000 cpu=0 >> task_tick
15000000 cpu=0 == sched_switch prev_pid=100 prev_comm=worker prev_state=0 next_pid=0 next_comm=swapper/0

Done.
"#;

    let bpf_trace = BpfTrace::parse(bpf_data.as_bytes()).unwrap();

    // Create a simulated scenario with similar characteristics
    // 3 run phases of ~5ms each, matching the BPF trace pattern
    let scenario = Scenario::builder()
        .cpus(2)
        .add_task(
            "worker",
            0,
            TaskBehavior {
                phases: vec![Phase::Run(5_000_000)], // 5ms run phases
                repeat: RepeatMode::Count(3),
            },
        )
        .duration_ms(20)
        .build();

    let sim_trace = Simulator::new(DynamicScheduler::simple()).run(scenario);
    let sim_stats = TraceStats::from_trace(&sim_trace);

    // Compare
    let comparison = TraceComparisonResult::compare_bpf_vs_sim(&bpf_trace, &sim_stats);
    comparison.print_report();

    // Validate the comparison works
    assert!(
        comparison.baseline.tasks.contains_key(&Pid(100)),
        "baseline should have task 100"
    );
    assert!(
        !comparison.comparison.tasks.is_empty(),
        "comparison should have tasks"
    );

    eprintln!("\n=== Differences Summary ===");
    eprintln!(
        "  Schedule count diff: {:+}",
        comparison.differences.schedule_count_diff
    );
    eprintln!(
        "  Run duration variance ratio: {:.2}",
        comparison.differences.run_duration_variance_ratio
    );
}

/// Test loading a real BPF trace file if one exists.
///
/// This test looks for a bpf_trace.log file in the project root
/// (produced by `--real-run --bpf-trace`) and parses it if found.
///
/// Run with: cargo test test_load_real_bpf_trace --test compare -- --nocapture
///
/// # Manual Testing Steps
///
/// To generate a real trace file:
/// 1. Build the scheduler: `cargo build -p scx_lavd --release`
/// 2. Run with BPF tracing: `cargo run -p scxsim -- --real-run --bpf-trace -w workloads/two_runners.json`
/// 3. This creates bpf_trace.log in the current directory
/// 4. Re-run this test to parse and analyze the real trace
#[test]
fn test_load_real_bpf_trace() {
    // Look for a real trace file in the project root
    let trace_path = Path::new("bpf_trace.log");

    if !trace_path.exists() {
        eprintln!("\n=== Skipping real BPF trace test ===");
        eprintln!("No bpf_trace.log found in current directory.");
        eprintln!();
        eprintln!("To generate a real trace file:");
        eprintln!("  1. Build the scheduler: cargo build -p scx_lavd --release");
        eprintln!(
            "  2. Run: cargo run -p scxsim -- --real-run --bpf-trace -w workloads/two_runners.json"
        );
        eprintln!("  3. Re-run this test to parse the trace.");
        return;
    }

    eprintln!(
        "\n=== Loading real BPF trace from {} ===\n",
        trace_path.display()
    );

    let bpf_trace = BpfTrace::from_file(trace_path).expect("failed to parse bpf_trace.log");

    eprintln!("Parsed {} events", bpf_trace.len());
    eprintln!(
        "Duration: {:.3}ms",
        bpf_trace.duration_ns() as f64 / 1_000_000.0
    );
    eprintln!();

    // List discovered tasks
    eprintln!("Tasks discovered:");
    let stats = bpf_trace.compute_stats();
    for (pid, task_stats) in &stats.tasks {
        let name = bpf_trace.task_name(*pid).unwrap_or("???");
        eprintln!(
            "  PID={} ({}): {} schedules, {} preempts, {} sleeps",
            pid.0,
            name,
            task_stats.schedule_count,
            task_stats.preempt_count,
            task_stats.sleep_count
        );
    }
    eprintln!();

    // Print full stats
    stats.print_summary();

    // Basic sanity checks
    assert!(!bpf_trace.is_empty(), "trace should not be empty");
    assert!(bpf_trace.duration_ns() > 0, "trace should have duration");
}

/// Compare a real BPF trace with a simulated trace using the same workload.
///
/// This test demonstrates the full real-vs-simulated comparison workflow:
/// 1. Load a real BPF trace from bpf_trace.log
/// 2. Run the same workload (two_runners.json) in simulation
/// 3. Compare statistics and identify realism gaps
///
/// Run with: cargo test test_full_real_vs_sim_comparison --test compare -- --nocapture
///
/// Prerequisites:
/// - Generate bpf_trace.log using: cargo run -p scxsim -- --real-run --bpf-trace -s lavd -w workloads/two_runners.json
#[test]
fn test_full_real_vs_sim_comparison() {
    let _lock = common::setup_test();

    let trace_path = Path::new("bpf_trace.log");

    if !trace_path.exists() {
        eprintln!("\n=== Skipping full comparison test ===");
        eprintln!("No bpf_trace.log found. Run with --real-run --bpf-trace first.");
        return;
    }

    eprintln!("\n=== Full Real vs Simulated Comparison ===\n");

    // Load real trace
    let bpf_trace = BpfTrace::from_file(trace_path).expect("failed to parse bpf_trace.log");
    eprintln!(
        "Real trace: {} events, {:.3}ms duration",
        bpf_trace.len(),
        bpf_trace.duration_ns() as f64 / 1_000_000.0
    );

    // Run simulation with same workload
    let json = include_str!("../workloads/two_runners.json");
    let scenario = load_rtapp(json, 2).unwrap();
    let sim_trace = Simulator::new(DynamicScheduler::lavd(2)).run(scenario);
    let sim_stats = TraceStats::from_trace(&sim_trace);
    eprintln!(
        "Simulated trace: {} events, {:.3}ms duration\n",
        sim_trace.events().len(),
        sim_stats.duration_ns as f64 / 1_000_000.0
    );

    // Compare
    let comparison = TraceComparisonResult::compare_bpf_vs_sim(&bpf_trace, &sim_stats);
    comparison.print_report();

    // Identify specific realism gaps
    eprintln!("=== Realism Gap Detection ===\n");

    // Gap 1: Spurious yields (simulated tasks yield more than real ones)
    let sim_total_yields: usize = sim_stats.tasks.values().map(|t| t.yield_count).sum();
    let real_total_preempts: usize = comparison
        .baseline
        .tasks
        .values()
        .map(|t| t.preempt_count)
        .sum();
    eprintln!(
        "Gap 1 (Spurious Yields): sim yields={}, real preempts={}",
        sim_total_yields, real_total_preempts
    );

    // Gap 2: Tick interval variance
    let sim_tick_cv: f64 = sim_stats
        .cpus
        .values()
        .filter(|c| c.tick_interval.count > 1)
        .map(|c| c.tick_interval.cv_percent())
        .sum::<f64>()
        / sim_stats.cpus.len().max(1) as f64;
    let real_tick_cv: f64 = comparison
        .baseline
        .cpus
        .values()
        .filter(|c| c.tick_interval.count > 1)
        .map(|c| c.tick_interval.cv_percent())
        .sum::<f64>()
        / comparison.baseline.cpus.len().max(1) as f64;
    eprintln!(
        "Gap 2 (Tick Jitter): sim CV={:.1}%, real CV={:.1}%",
        sim_tick_cv, real_tick_cv
    );

    // Gap 6: Run duration variance
    eprintln!(
        "Gap 6 (Timing Variance): ratio={:.2} (1.0 = matched, <0.1 = sim too deterministic)",
        comparison.differences.run_duration_variance_ratio
    );

    eprintln!();
}
