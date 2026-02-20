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
                repeat: RepeatMode::Forever,
            },
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: None,
            parent_pid: None,
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
        })
        .task(TaskDef {
            name: "t2".into(),
            pid: Pid(2),
            nice: 0,
            behavior: TaskBehavior {
                phases: vec![Phase::Run(50_000_000)],
                repeat: RepeatMode::Forever,
            },
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: None,
            parent_pid: None,
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
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

/// Address-space affinity (mm_affinity): threads sharing an address space
/// should be co-located via wake-affine scheduling.
///
/// Task A (waker) runs, sleeps, then wakes task B (wakee). Both share
/// MmId(1). COSMOS's is_wake_affine() should return true and dispatch B
/// directly to A's previous CPU when conditions align.
#[test]
fn test_mm_affinity() {
    let _lock = common::setup_test();
    let scenario = Scenario::builder()
        .cpus(2)
        .add_task_with_mm(
            "waker",
            0,
            TaskBehavior {
                // Run 5ms → wake peer → sleep 5ms → repeat
                phases: vec![
                    Phase::Run(5_000_000),
                    Phase::Wake(Pid(2)),
                    Phase::Sleep(5_000_000),
                ],
                repeat: RepeatMode::Forever,
            },
            MmId(1),
        )
        .add_task_with_mm(
            "wakee",
            0,
            TaskBehavior {
                // Run 5ms → sleep 20ms (will be woken by waker before timer)
                phases: vec![Phase::Run(5_000_000), Phase::Sleep(20_000_000)],
                repeat: RepeatMode::Forever,
            },
            MmId(1),
        )
        .duration_ms(200)
        .build();

    let trace = Simulator::new(DynamicScheduler::cosmos(2)).run(scenario);

    assert!(trace.total_runtime(Pid(1)) > 0, "waker got no runtime");
    assert!(trace.total_runtime(Pid(2)) > 0, "wakee got no runtime");

    // Both tasks should be scheduled multiple times (wake/sleep cycling)
    assert!(
        trace.schedule_count(Pid(1)) >= 3,
        "waker scheduled only {} times",
        trace.schedule_count(Pid(1))
    );
    assert!(
        trace.schedule_count(Pid(2)) >= 3,
        "wakee scheduled only {} times",
        trace.schedule_count(Pid(2))
    );
}

/// With NUMA enabled, each node has its own shared DSQ.
/// Tasks on different nodes should still get fair runtime.
#[test]
fn test_numa_topology() {
    let _lock = common::setup_test();
    let scenario = Scenario::builder()
        .cpus(4)
        .add_task(
            "node0_task",
            0,
            TaskBehavior {
                phases: vec![Phase::Run(50_000_000)],
                repeat: RepeatMode::Forever,
            },
        )
        .add_task(
            "node1_task",
            0,
            TaskBehavior {
                phases: vec![Phase::Run(50_000_000)],
                repeat: RepeatMode::Forever,
            },
        )
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
