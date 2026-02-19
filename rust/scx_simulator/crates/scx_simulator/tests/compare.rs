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
