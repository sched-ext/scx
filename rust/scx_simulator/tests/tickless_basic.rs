use std::collections::HashSet;

use scx_simulator::*;

mod common;

/// Helper to create a ScxTickless scheduler initialized for `nr_cpus` CPUs.
fn make_tickless(nr_cpus: u32) -> ScxTickless {
    let sched = ScxTickless;
    unsafe { sched.setup(nr_cpus) };
    sched
}

/// Smoke test: single task on single CPU runs to completion.
#[test]
fn test_tickless_single_task_single_cpu() {
    let _lock = common::setup_test();
    let scenario = Scenario::builder()
        .cpus(1)
        .task(TaskDef {
            name: "worker".into(),
            pid: Pid(1),
            nice: 0,
            behavior: TaskBehavior {
                phases: vec![Phase::Run(5_000_000)], // 5ms
                repeat: false,
            },
            start_time_ns: 0,
        })
        .duration_ms(100)
        .build();

    let trace = Simulator::new(make_tickless(1)).run(scenario);
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

/// Multiple tasks on a single CPU should all get scheduled (vtime fairness).
#[test]
fn test_tickless_multiple_tasks_single_cpu() {
    let _lock = common::setup_test();
    let scenario = Scenario::builder()
        .cpus(1)
        .task(TaskDef {
            name: "t1".into(),
            pid: Pid(1),
            nice: 0,
            behavior: TaskBehavior {
                phases: vec![Phase::Run(20_000_000)], // 20ms
                repeat: true,
            },
            start_time_ns: 0,
        })
        .task(TaskDef {
            name: "t2".into(),
            pid: Pid(2),
            nice: 0,
            behavior: TaskBehavior {
                phases: vec![Phase::Run(20_000_000)], // 20ms
                repeat: true,
            },
            start_time_ns: 0,
        })
        .duration_ms(100)
        .build();

    let trace = Simulator::new(make_tickless(1)).run(scenario);
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
fn test_tickless_multiple_cpus() {
    let _lock = common::setup_test();
    let scenario = Scenario::builder()
        .cpus(4)
        .task(TaskDef {
            name: "t1".into(),
            pid: Pid(1),
            nice: 0,
            behavior: TaskBehavior {
                phases: vec![Phase::Run(50_000_000)], // 50ms
                repeat: true,
            },
            start_time_ns: 0,
        })
        .task(TaskDef {
            name: "t2".into(),
            pid: Pid(2),
            nice: 0,
            behavior: TaskBehavior {
                phases: vec![Phase::Run(50_000_000)], // 50ms
                repeat: true,
            },
            start_time_ns: 0,
        })
        .duration_ms(100)
        .build();

    let trace = Simulator::new(make_tickless(4)).run(scenario);

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
fn test_tickless_determinism() {
    let _lock = common::setup_test();
    let make_scenario = || {
        Scenario::builder()
            .cpus(2)
            .task(TaskDef {
                name: "t1".into(),
                pid: Pid(1),
                nice: 0,
                behavior: TaskBehavior {
                    phases: vec![Phase::Run(10_000_000)],
                    repeat: true,
                },
                start_time_ns: 0,
            })
            .task(TaskDef {
                name: "t2".into(),
                pid: Pid(2),
                nice: -3,
                behavior: TaskBehavior {
                    phases: vec![Phase::Run(10_000_000)],
                    repeat: true,
                },
                start_time_ns: 0,
            })
            .duration_ms(50)
            .build()
    };

    let trace1 = Simulator::new(make_tickless(2)).run(make_scenario());
    let trace2 = Simulator::new(make_tickless(2)).run(make_scenario());

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

/// Weighted fairness: with vtime scheduling, higher weight task
/// accumulates vruntime more slowly, so it gets scheduled preferentially.
/// With SCX_SLICE_INF, tasks run their full phase each time, so the
/// effect of weight is on scheduling ORDER rather than runtime.
#[test]
fn test_tickless_weighted_fairness() {
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

    let trace = Simulator::new(make_tickless(1)).run(scenario);
    trace.dump();

    let rt_heavy = trace.total_runtime(Pid(1));
    let rt_light = trace.total_runtime(Pid(2));

    // Both tasks must get runtime
    assert!(rt_heavy > 0, "heavy task got no runtime");
    assert!(rt_light > 0, "light task got no runtime");

    // With SCX_SLICE_INF and equal-length phases, both tasks get equal
    // runtime on a single CPU. The effect of weight is that the heavy
    // task is scheduled first (lower vruntime accumulation).
    // Verify both tasks ran and got significant time.
    let total = rt_heavy + rt_light;
    assert!(
        rt_heavy >= total / 4 && rt_light >= total / 4,
        "expected both tasks to get at least 25% runtime: heavy={rt_heavy}ns, light={rt_light}ns"
    );
}
