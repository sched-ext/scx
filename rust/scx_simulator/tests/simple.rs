use scx_simulator::*;

#[macro_use]
mod common;

// Generic test suite applied to scx_simple
scheduler_tests!(|_nr_cpus| DynamicScheduler::simple());

// ---------------------------------------------------------------------------
// scx_simple-specific tests (depend on SCX_SLICE_DFL = 20ms behavior)
// ---------------------------------------------------------------------------

/// A task with lower nice should get more runtime (nice -3 ~ 1.94x weight of nice 0).
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
            mm_id: None,
            allowed_cpus: None,
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
            mm_id: None,
            allowed_cpus: None,
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
            mm_id: None,
            allowed_cpus: None,
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
            mm_id: None,
            allowed_cpus: None,
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
            mm_id: None,
            allowed_cpus: None,
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

/// Slice expiry: task with long Run phase should be preempted by slice.
#[test]
fn test_slice_preemption() {
    let _lock = common::setup_test();
    let scenario = Scenario::builder()
        .cpus(1)
        .instant_timing()
        .task(TaskDef {
            name: "long_runner".into(),
            pid: Pid(1),
            nice: 0,
            behavior: TaskBehavior {
                phases: vec![Phase::Run(100_000_000)], // 100ms
                repeat: false,
            },
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: None,
        })
        .duration_ms(200)
        .build();

    let trace = Simulator::new(DynamicScheduler::simple()).run(scenario);
    trace.dump();

    // With a single task, it should be rescheduled after each slice expiry
    // 100ms run / 20ms slice = 5 scheduling events
    let count = trace.schedule_count(Pid(1));
    assert!(
        count >= 3,
        "expected multiple schedule events due to slice expiry, got {count}"
    );

    // Total runtime should be 100ms (it completes its phase)
    let runtime = trace.total_runtime(Pid(1));
    assert_eq!(
        runtime, 100_000_000,
        "expected exactly 100ms runtime, got {runtime}ns"
    );
}

/// Two CPU-hungry tasks contending on 1 CPU: preemption interleaving.
#[test]
fn test_preemption_interleaving() {
    let _lock = common::setup_test();
    let scenario = Scenario::builder()
        .cpus(1)
        .task(TaskDef {
            name: "t1".into(),
            pid: Pid(1),
            nice: 0,
            behavior: TaskBehavior {
                phases: vec![Phase::Run(100_000_000)],
                repeat: true,
            },
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: None,
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
            mm_id: None,
            allowed_cpus: None,
        })
        .duration_ms(100)
        .build();

    let trace = Simulator::new(DynamicScheduler::simple()).run(scenario);

    // Both tasks should be scheduled multiple times (interleaving)
    let count1 = trace.schedule_count(Pid(1));
    let count2 = trace.schedule_count(Pid(2));

    assert!(
        count1 >= 2 && count2 >= 2,
        "expected interleaving, got count1={count1}, count2={count2}"
    );

    // Check that tasks alternate: look for interleaving in the trace
    let sched_events: Vec<Pid> = trace
        .events()
        .iter()
        .filter_map(|e| match e.kind {
            TraceKind::TaskScheduled { pid } => Some(pid),
            _ => None,
        })
        .collect();

    // There should be at least one transition between tasks
    let transitions = sched_events.windows(2).filter(|w| w[0] != w[1]).count();

    assert!(
        transitions >= 2,
        "expected task interleaving, but saw only {transitions} transitions in {:?}",
        sched_events
    );
}
