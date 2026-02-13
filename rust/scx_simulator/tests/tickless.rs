use scx_simulator::*;

#[macro_use]
mod common;

// Generic test suite applied to scx_tickless
scheduler_tests!(|nr_cpus| DynamicScheduler::tickless(nr_cpus));

// ---------------------------------------------------------------------------
// scx_tickless-specific tests (depend on SCX_SLICE_INF behavior)
// ---------------------------------------------------------------------------

/// Weighted fairness with SCX_SLICE_INF: weight affects scheduling order
/// rather than runtime proportionally. Both tasks should still get
/// significant runtime.
#[test]
fn test_weighted_fairness() {
    let _lock = common::setup_test();
    let scenario = Scenario::builder()
        .cpus(1)
        .task(TaskDef {
            name: "heavy".into(),
            pid: Pid(1),
            nice: -3,
            behavior: TaskBehavior {
                phases: vec![Phase::Run(50_000_000)], // 50ms
                repeat: true,
            },
            start_time_ns: 0,
        })
        .task(TaskDef {
            name: "light".into(),
            pid: Pid(2),
            nice: 0,
            behavior: TaskBehavior {
                phases: vec![Phase::Run(50_000_000)], // 50ms
                repeat: true,
            },
            start_time_ns: 0,
        })
        .duration_ms(200)
        .build();

    let trace = Simulator::new(DynamicScheduler::tickless(1)).run(scenario);
    trace.dump();

    let rt_heavy = trace.total_runtime(Pid(1));
    let rt_light = trace.total_runtime(Pid(2));

    assert!(rt_heavy > 0, "heavy task got no runtime");
    assert!(rt_light > 0, "light task got no runtime");

    // With SCX_SLICE_INF and equal-length phases, both tasks get equal
    // runtime on a single CPU. Verify both ran with significant time.
    let total = rt_heavy + rt_light;
    assert!(
        rt_heavy >= total / 4 && rt_light >= total / 4,
        "expected both tasks to get at least 25% runtime: heavy={rt_heavy}ns, light={rt_light}ns"
    );
}
