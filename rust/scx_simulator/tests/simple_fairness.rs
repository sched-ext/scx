use scx_simulator::*;

mod common;

/// Two tasks with equal weight on 1 CPU should get roughly equal runtime.
#[test]
fn test_equal_weight_fairness() {
    let _lock = common::setup_test();
    let scenario = Scenario::builder()
        .cpus(1)
        .task(TaskDef {
            name: "t1".into(),
            pid: Pid(1),
            nice: 0,
            behavior: TaskBehavior {
                phases: vec![Phase::Run(100_000_000)], // 100ms - always has work
                repeat: true,
            },
            start_time_ns: 0,
        })
        .task(TaskDef {
            name: "t2".into(),
            pid: Pid(2),
            nice: 0,
            behavior: TaskBehavior {
                phases: vec![Phase::Run(100_000_000)],
                repeat: true,
            },
            start_time_ns: 0,
        })
        .duration_ms(200)
        .build();

    let trace = Simulator::new(DynamicScheduler::simple()).run(scenario);
    trace.dump();

    let rt1 = trace.total_runtime(Pid(1));
    let rt2 = trace.total_runtime(Pid(2));

    eprintln!("t1 runtime: {rt1}ns, t2 runtime: {rt2}ns");

    // Both should get significant runtime
    assert!(rt1 > 0, "task 1 got no runtime");
    assert!(rt2 > 0, "task 2 got no runtime");

    // The ratio should be close to 1:1
    let ratio = rt1 as f64 / rt2 as f64;
    assert!(
        (0.8..=1.2).contains(&ratio),
        "expected ~equal runtime ratio, got {ratio:.3} (rt1={rt1}, rt2={rt2})"
    );
}

/// A task with lower nice should get more runtime (nice -3 ≈ 1.94x weight of nice 0).
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
                phases: vec![Phase::Run(100_000_000)],
                repeat: true,
            },
            start_time_ns: 0,
        })
        .task(TaskDef {
            name: "light".into(),
            pid: Pid(2),
            nice: 0,
            behavior: TaskBehavior {
                phases: vec![Phase::Run(100_000_000)],
                repeat: true,
            },
            start_time_ns: 0,
        })
        .duration_ms(200)
        .build();

    let trace = Simulator::new(DynamicScheduler::simple()).run(scenario);
    trace.dump();

    let rt1 = trace.total_runtime(Pid(1)); // nice -3 (weight 1991)
    let rt2 = trace.total_runtime(Pid(2)); // nice  0 (weight 1024)

    eprintln!("heavy(nice=-3) runtime: {rt1}ns, light(nice=0) runtime: {rt2}ns");

    // The heavy task should get roughly 2x the runtime
    let ratio = rt1 as f64 / rt2 as f64;
    assert!(
        (1.5..=2.5).contains(&ratio),
        "expected ~2:1 ratio, got {ratio:.3} (heavy={rt1}, light={rt2})"
    );
}

/// Three tasks with nice 5, 2, 0 should get proportional runtime (~1:2:3).
#[test]
fn test_three_way_weighted_fairness() {
    let _lock = common::setup_test();
    let scenario = Scenario::builder()
        .cpus(1)
        .task(TaskDef {
            name: "n5".into(),
            pid: Pid(1),
            nice: 5, // weight 335
            behavior: TaskBehavior {
                phases: vec![Phase::Run(100_000_000)],
                repeat: true,
            },
            start_time_ns: 0,
        })
        .task(TaskDef {
            name: "n2".into(),
            pid: Pid(2),
            nice: 2, // weight 655
            behavior: TaskBehavior {
                phases: vec![Phase::Run(100_000_000)],
                repeat: true,
            },
            start_time_ns: 0,
        })
        .task(TaskDef {
            name: "n0".into(),
            pid: Pid(3),
            nice: 0, // weight 1024
            behavior: TaskBehavior {
                phases: vec![Phase::Run(100_000_000)],
                repeat: true,
            },
            start_time_ns: 0,
        })
        .duration_ms(600) // longer to allow convergence
        .build();

    let trace = Simulator::new(DynamicScheduler::simple()).run(scenario);

    let rt1 = trace.total_runtime(Pid(1)); // nice 5 (lightest)
    let rt2 = trace.total_runtime(Pid(2)); // nice 2
    let rt3 = trace.total_runtime(Pid(3)); // nice 0 (heaviest)

    eprintln!("n5={rt1}ns, n2={rt2}ns, n0={rt3}ns");

    // rt2/rt1 should be ~2.0 (655/335 = 1.96), rt3/rt1 should be ~3.0 (1024/335 = 3.06)
    let ratio_21 = rt2 as f64 / rt1 as f64;
    let ratio_31 = rt3 as f64 / rt1 as f64;

    assert!(
        (1.5..=2.5).contains(&ratio_21),
        "expected n2/n5 ~2.0, got {ratio_21:.3}"
    );
    assert!(
        (2.5..=3.5).contains(&ratio_31),
        "expected n0/n5 ~3.0, got {ratio_31:.3}"
    );
}
