//! Debug test to investigate slice boost behavior in LAVD.
//!
//! Run with: cargo test test_slice_boost_debug --test slice_boost_debug -- --nocapture

use scx_simulator::probes::{LavdMonitor, LavdProbes};
use scx_simulator::ProbePoint;
use scx_simulator::*;

mod common;

/// Debug test that prints slice boost diagnostic information during simulation.
///
/// This test checks:
/// - sys_stat.slice_wall (target slice for the system)
/// - sys_stat.nr_queued_task (number of queued tasks)
/// - can_boost_slice() result
/// - task's avg_runtime_wall
/// - task's slice_wall from task_ctx
#[test]
fn test_slice_boost_debug() {
    let _lock = common::setup_test();

    let json = include_str!("../workloads/two_runners.json");
    let scenario = load_rtapp(json, 4).unwrap();

    // Create LAVD scheduler and monitor
    let sched = DynamicScheduler::lavd(4);
    let probes = LavdProbes::new(&sched);
    let mut monitor = LavdMonitor::new(probes);

    // Run with monitor to capture LAVD state at each event
    let sim = Simulator::new(sched);
    let trace = sim.run_monitored(scenario, &mut monitor);

    eprintln!("\n=== Slice Boost Debug ===\n");

    // Print summary
    let summary = trace.trace.summary();
    eprintln!("{}", summary);

    // Look at the first few snapshots to see slice boost state
    eprintln!("\n=== First 10 LAVD Snapshots ===\n");
    for (i, snap) in monitor.snapshots.iter().take(10).enumerate() {
        eprintln!(
            "[{}] time={:>12}ns pid={} point={:?}",
            i, snap.time_ns, snap.pid.0, snap.point
        );
        eprintln!(
            "      avg_runtime={:>10}ns task_slice_wall={:>10}ns",
            snap.avg_runtime, snap.task_slice_wall
        );
        eprintln!(
            "      sys_slice_wall={:>10}ns nr_queued={} can_boost={}",
            snap.sys_slice_wall, snap.sys_nr_queued_task, snap.can_boost_slice
        );
        eprintln!();
    }

    // Check state after simulation has been running for a while
    eprintln!("=== Snapshots at t > 100ms (task should have learned avg_runtime) ===\n");
    let late_snaps: Vec<_> = monitor
        .snapshots
        .iter()
        .filter(|s| s.time_ns > 100_000_000 && s.pid.0 == 1)
        .take(5)
        .collect();

    for snap in late_snaps {
        eprintln!(
            "time={:>12}ns pid={} point={:?}",
            snap.time_ns, snap.pid.0, snap.point
        );
        eprintln!(
            "      avg_runtime={:>10}ns (should be ~10ms for heavy task)",
            snap.avg_runtime
        );
        eprintln!("      task_slice_wall={:>10}ns", snap.task_slice_wall);
        eprintln!(
            "      sys_slice_wall={:>10}ns nr_queued={} can_boost={}",
            snap.sys_slice_wall, snap.sys_nr_queued_task, snap.can_boost_slice
        );
        eprintln!();
    }

    // Analyze the last snapshot for heavy task
    if let Some(final_snap) = monitor.final_snapshot(Pid(1)) {
        eprintln!("=== Final State for Heavy Task ===\n");
        eprintln!("  avg_runtime_wall:    {:>10}ns", final_snap.avg_runtime);
        eprintln!(
            "  task_slice_wall:     {:>10}ns",
            final_snap.task_slice_wall
        );
        eprintln!("  sys_slice_wall:      {:>10}ns", final_snap.sys_slice_wall);
        eprintln!("  sys_nr_queued_task:  {}", final_snap.sys_nr_queued_task);
        eprintln!("  can_boost_slice:     {}", final_snap.can_boost_slice);
        eprintln!();

        // Check slice boost conditions
        eprintln!("=== Slice Boost Condition Check ===\n");
        let should_boost =
            final_snap.avg_runtime >= final_snap.sys_slice_wall && final_snap.can_boost_slice;
        eprintln!(
            "  avg_runtime ({}) >= sys_slice_wall ({})? {}",
            final_snap.avg_runtime,
            final_snap.sys_slice_wall,
            final_snap.avg_runtime >= final_snap.sys_slice_wall
        );
        eprintln!("  can_boost_slice()? {}", final_snap.can_boost_slice);
        eprintln!("  => Should get boosted slice? {}", should_boost);

        if should_boost {
            let expected_slice = final_snap.avg_runtime + 500_000; // + 500μs bonus
            eprintln!(
                "  => Expected boosted slice: {}ns ({}ms)",
                expected_slice,
                expected_slice / 1_000_000
            );
        }
    }

    // Analyze preemption pattern for heavy task
    eprintln!("=== Heavy Task Slice Evolution ===\n");
    let heavy_snaps: Vec<_> = monitor.snapshots.iter().filter(|s| s.pid.0 == 1).collect();

    // Find when slice first exceeds 10ms (can complete work without preemption)
    let mut preempt_count = 0;
    let mut voluntary_sleep_count = 0;
    let mut first_adequate_slice_time: Option<u64> = None;

    for (i, snap) in heavy_snaps.iter().enumerate() {
        if snap.task_slice_wall >= 10_000_000 && first_adequate_slice_time.is_none() {
            first_adequate_slice_time = Some(snap.time_ns);
            eprintln!(
                "  First adequate slice (>=10ms) at t={}ms: slice={}ms, avg_runtime={}ms",
                snap.time_ns / 1_000_000,
                snap.task_slice_wall / 1_000_000,
                snap.avg_runtime / 1_000_000
            );
        }

        // Count Stopping events (check if followed by Quiescent = voluntary or Running = preempt)
        if matches!(snap.point, ProbePoint::Stopping) {
            if let Some(next) = heavy_snaps.get(i + 1) {
                if matches!(next.point, ProbePoint::Quiescent) {
                    voluntary_sleep_count += 1;
                } else if matches!(next.point, ProbePoint::Running) {
                    preempt_count += 1;
                }
            }
        }
    }

    eprintln!(
        "\n  Heavy task preemptions: {} (task didn't complete, continued running)",
        preempt_count
    );
    eprintln!(
        "  Heavy task voluntary sleeps: {} (task completed work, went to sleep)",
        voluntary_sleep_count
    );
    eprintln!(
        "  First adequate slice at: {:?}ms into simulation",
        first_adequate_slice_time.map(|t| t / 1_000_000)
    );

    // Verify basic correctness
    assert!(
        trace.trace.total_runtime(Pid(1)) > 0,
        "heavy task got no runtime"
    );
    assert!(
        trace.trace.total_runtime(Pid(2)) > 0,
        "light task got no runtime"
    );
}
