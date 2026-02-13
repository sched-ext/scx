use scx_simulator::*;

#[macro_use]
mod common;

// Generic test suite applied to scx_cosmos
scheduler_tests!(|nr_cpus| DynamicScheduler::cosmos(nr_cpus));

/// SMT topology: 4 CPUs with 2 threads per core.
/// Tasks should spread across cores and the scheduler should
/// exercise the idle-core preference path.
#[test]
fn test_smt_topology() {
    let _lock = common::setup_test();
    let scenario = Scenario::builder()
        .cpus(4)
        .smt(2) // 2 cores, 2 threads each
        .task(TaskDef {
            name: "t1".into(),
            pid: Pid(1),
            nice: 0,
            behavior: TaskBehavior {
                phases: vec![Phase::Run(50_000_000)],
                repeat: true,
            },
            start_time_ns: 0,
        })
        .task(TaskDef {
            name: "t2".into(),
            pid: Pid(2),
            nice: 0,
            behavior: TaskBehavior {
                phases: vec![Phase::Run(50_000_000)],
                repeat: true,
            },
            start_time_ns: 0,
        })
        .duration_ms(200)
        .build();

    let trace = Simulator::new(DynamicScheduler::cosmos(4)).run(scenario);

    assert!(trace.total_runtime(Pid(1)) > 0, "task 1 got no runtime");
    assert!(trace.total_runtime(Pid(2)) > 0, "task 2 got no runtime");

    // Both tasks should get significant runtime (at least 25% each)
    let total = trace.total_runtime(Pid(1)) + trace.total_runtime(Pid(2));
    assert!(
        trace.total_runtime(Pid(1)) >= total / 4,
        "task 1 didn't get fair share"
    );
}

/// NUMA topology: 4 CPUs across 2 NUMA nodes.
/// With NUMA enabled, each node has its own shared DSQ.
/// Tasks on different nodes should still get fair runtime.
#[test]
fn test_numa_topology() {
    let _lock = common::setup_test();
    let scenario = Scenario::builder()
        .cpus(4)
        .add_task("node0_task", 0, TaskBehavior {
            phases: vec![Phase::Run(50_000_000)],
            repeat: true,
        })
        .add_task("node1_task", 0, TaskBehavior {
            phases: vec![Phase::Run(50_000_000)],
            repeat: true,
        })
        .duration_ms(200)
        .build();

    let trace = Simulator::new(DynamicScheduler::cosmos_with_numa(4, 2)).run(scenario);

    assert!(trace.total_runtime(Pid(1)) > 0, "task 1 got no runtime");
    assert!(trace.total_runtime(Pid(2)) > 0, "task 2 got no runtime");

    // Both tasks should get significant runtime
    let total = trace.total_runtime(Pid(1)) + trace.total_runtime(Pid(2));
    assert!(
        trace.total_runtime(Pid(1)) >= total / 4,
        "task 1 didn't get fair share"
    );
}
