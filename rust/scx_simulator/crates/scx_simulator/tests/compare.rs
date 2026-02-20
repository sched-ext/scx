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
