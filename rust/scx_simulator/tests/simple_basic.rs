use std::collections::HashSet;

use scx_simulator::*;

mod common;

/// Smoke test: single task on single CPU runs to completion.
#[test]
fn test_single_task_single_cpu() {
    let _lock = common::setup_test();
    let scenario = Scenario::builder()
        .cpus(1)
        .task(TaskDef {
            name: "worker".into(),
            pid: Pid(1),
            weight: 100,
            behavior: TaskBehavior {
                phases: vec![Phase::Run(5_000_000)], // 5ms
                repeat: false,
            },
            start_time_ns: 0,
        })
        .duration_ms(100)
        .build();

    let trace = Simulator::new(ScxSimple).run(scenario);
    trace.dump();

    // Task should have been scheduled at least once
    assert!(trace.schedule_count(Pid(1)) > 0, "task was never scheduled");

    // Task should have completed
    assert!(
        trace.events().iter().any(|e| matches!(
            e.kind,
            TraceKind::TaskCompleted { pid } if pid == Pid(1)
        )),
        "task did not complete"
    );

    // Runtime should be approximately 5ms
    let runtime = trace.total_runtime(Pid(1));
    assert!(
        runtime == 5_000_000,
        "expected 5ms runtime, got {runtime}ns"
    );
}

/// Multiple tasks on a single CPU should all get scheduled.
#[test]
fn test_multiple_tasks_single_cpu() {
    let _lock = common::setup_test();
    let scenario = Scenario::builder()
        .cpus(1)
        .task(TaskDef {
            name: "t1".into(),
            pid: Pid(1),
            weight: 100,
            behavior: TaskBehavior {
                phases: vec![Phase::Run(20_000_000)], // 20ms
                repeat: true,
            },
            start_time_ns: 0,
        })
        .task(TaskDef {
            name: "t2".into(),
            pid: Pid(2),
            weight: 100,
            behavior: TaskBehavior {
                phases: vec![Phase::Run(20_000_000)], // 20ms
                repeat: true,
            },
            start_time_ns: 0,
        })
        .duration_ms(100)
        .build();

    let trace = Simulator::new(ScxSimple).run(scenario);
    trace.dump();

    // Both tasks should have been scheduled
    assert!(
        trace.schedule_count(Pid(1)) > 0,
        "task 1 was never scheduled"
    );
    assert!(
        trace.schedule_count(Pid(2)) > 0,
        "task 2 was never scheduled"
    );

    // Both should get significant runtime
    let rt1 = trace.total_runtime(Pid(1));
    let rt2 = trace.total_runtime(Pid(2));
    assert!(rt1 > 0, "task 1 got no runtime");
    assert!(rt2 > 0, "task 2 got no runtime");
}

/// Tasks on multiple CPUs should spread across CPUs.
#[test]
fn test_multiple_cpus() {
    let _lock = common::setup_test();
    let scenario = Scenario::builder()
        .cpus(4)
        .task(TaskDef {
            name: "t1".into(),
            pid: Pid(1),
            weight: 100,
            behavior: TaskBehavior {
                phases: vec![Phase::Run(50_000_000)], // 50ms
                repeat: true,
            },
            start_time_ns: 0,
        })
        .task(TaskDef {
            name: "t2".into(),
            pid: Pid(2),
            weight: 100,
            behavior: TaskBehavior {
                phases: vec![Phase::Run(50_000_000)], // 50ms
                repeat: true,
            },
            start_time_ns: 0,
        })
        .duration_ms(100)
        .build();

    let trace = Simulator::new(ScxSimple).run(scenario);

    // Both tasks should get runtime
    assert!(trace.total_runtime(Pid(1)) > 0);
    assert!(trace.total_runtime(Pid(2)) > 0);

    // Tasks should actually run on different CPUs
    let cpus_used: HashSet<CpuId> = trace
        .events()
        .iter()
        .filter_map(|e| match e.kind {
            TraceKind::TaskScheduled { .. } => Some(e.cpu),
            _ => None,
        })
        .collect();

    assert!(
        cpus_used.len() >= 2,
        "expected tasks to spread across CPUs, but only used {:?}",
        cpus_used
    );
}

/// Determinism: same scenario should produce identical traces.
#[test]
fn test_determinism() {
    let _lock = common::setup_test();
    let make_scenario = || {
        Scenario::builder()
            .cpus(2)
            .task(TaskDef {
                name: "t1".into(),
                pid: Pid(1),
                weight: 100,
                behavior: TaskBehavior {
                    phases: vec![Phase::Run(10_000_000)],
                    repeat: true,
                },
                start_time_ns: 0,
            })
            .task(TaskDef {
                name: "t2".into(),
                pid: Pid(2),
                weight: 200,
                behavior: TaskBehavior {
                    phases: vec![Phase::Run(10_000_000)],
                    repeat: true,
                },
                start_time_ns: 0,
            })
            .duration_ms(50)
            .build()
    };

    let trace1 = Simulator::new(ScxSimple).run(make_scenario());
    let trace2 = Simulator::new(ScxSimple).run(make_scenario());

    assert_eq!(
        trace1.events().len(),
        trace2.events().len(),
        "traces have different lengths"
    );

    for (i, (e1, e2)) in trace1
        .events()
        .iter()
        .zip(trace2.events().iter())
        .enumerate()
    {
        assert_eq!(
            e1.time_ns, e2.time_ns,
            "event {i}: timestamps differ: {} vs {}",
            e1.time_ns, e2.time_ns
        );
        assert_eq!(
            e1.cpu, e2.cpu,
            "event {i}: CPUs differ: {:?} vs {:?}",
            e1.cpu, e2.cpu
        );
        assert_eq!(
            e1.kind, e2.kind,
            "event {i}: kinds differ: {:?} vs {:?}",
            e1.kind, e2.kind
        );
    }
}
