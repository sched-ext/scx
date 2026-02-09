use scx_simulator::*;

/// Two tasks with equal weight on 1 CPU should get roughly equal runtime.
#[test]
fn test_equal_weight_fairness() {
    let scenario = Scenario::builder()
        .cpus(1)
        .task(TaskDef {
            name: "t1".into(),
            pid: 1,
            weight: 100,
            behavior: TaskBehavior {
                phases: vec![Phase::Run(100_000_000)], // 100ms - always has work
                repeat: true,
            },
            start_time_ns: 0,
        })
        .task(TaskDef {
            name: "t2".into(),
            pid: 2,
            weight: 100,
            behavior: TaskBehavior {
                phases: vec![Phase::Run(100_000_000)],
                repeat: true,
            },
            start_time_ns: 0,
        })
        .duration_ms(200)
        .build();

    let trace = Simulator::new(ScxSimple).run(scenario);
    trace.dump();

    let rt1 = trace.total_runtime(1);
    let rt2 = trace.total_runtime(2);

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

/// A task with 2x weight should get ~2x the runtime of a task with 1x weight.
#[test]
fn test_weighted_fairness() {
    let scenario = Scenario::builder()
        .cpus(1)
        .task(TaskDef {
            name: "heavy".into(),
            pid: 1,
            weight: 200,
            behavior: TaskBehavior {
                phases: vec![Phase::Run(100_000_000)],
                repeat: true,
            },
            start_time_ns: 0,
        })
        .task(TaskDef {
            name: "light".into(),
            pid: 2,
            weight: 100,
            behavior: TaskBehavior {
                phases: vec![Phase::Run(100_000_000)],
                repeat: true,
            },
            start_time_ns: 0,
        })
        .duration_ms(200)
        .build();

    let trace = Simulator::new(ScxSimple).run(scenario);
    trace.dump();

    let rt1 = trace.total_runtime(1); // weight 200
    let rt2 = trace.total_runtime(2); // weight 100

    eprintln!("heavy(w=200) runtime: {rt1}ns, light(w=100) runtime: {rt2}ns");

    // The heavy task should get roughly 2x the runtime
    let ratio = rt1 as f64 / rt2 as f64;
    assert!(
        (1.5..=2.5).contains(&ratio),
        "expected ~2:1 ratio, got {ratio:.3} (heavy={rt1}, light={rt2})"
    );
}

/// Three tasks with weights 100, 200, 300 should get proportional runtime.
#[test]
fn test_three_way_weighted_fairness() {
    let scenario = Scenario::builder()
        .cpus(1)
        .task(TaskDef {
            name: "w100".into(),
            pid: 1,
            weight: 100,
            behavior: TaskBehavior {
                phases: vec![Phase::Run(100_000_000)],
                repeat: true,
            },
            start_time_ns: 0,
        })
        .task(TaskDef {
            name: "w200".into(),
            pid: 2,
            weight: 200,
            behavior: TaskBehavior {
                phases: vec![Phase::Run(100_000_000)],
                repeat: true,
            },
            start_time_ns: 0,
        })
        .task(TaskDef {
            name: "w300".into(),
            pid: 3,
            weight: 300,
            behavior: TaskBehavior {
                phases: vec![Phase::Run(100_000_000)],
                repeat: true,
            },
            start_time_ns: 0,
        })
        .duration_ms(600) // longer to allow convergence
        .build();

    let trace = Simulator::new(ScxSimple).run(scenario);

    let rt1 = trace.total_runtime(1);
    let rt2 = trace.total_runtime(2);
    let rt3 = trace.total_runtime(3);

    eprintln!("w100={rt1}ns, w200={rt2}ns, w300={rt3}ns");

    // rt2/rt1 should be ~2.0, rt3/rt1 should be ~3.0
    let ratio_21 = rt2 as f64 / rt1 as f64;
    let ratio_31 = rt3 as f64 / rt1 as f64;

    assert!(
        (1.5..=2.5).contains(&ratio_21),
        "expected w200/w100 ~2.0, got {ratio_21:.3}"
    );
    assert!(
        (2.5..=3.5).contains(&ratio_31),
        "expected w300/w100 ~3.0, got {ratio_31:.3}"
    );
}
