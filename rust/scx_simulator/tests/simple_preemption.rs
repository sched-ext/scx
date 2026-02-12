use scx_simulator::*;

mod common;

/// Task that sleeps and wakes should produce correct timing.
#[test]
fn test_sleep_wake_cycle() {
    let _lock = common::setup_test();
    let scenario = Scenario::builder()
        .cpus(1)
        .task(TaskDef {
            name: "sleeper".into(),
            pid: Pid(1),
            nice: 0,
            behavior: TaskBehavior {
                phases: vec![
                    Phase::Run(5_000_000),    // run 5ms
                    Phase::Sleep(10_000_000), // sleep 10ms
                ],
                repeat: true,
            },
            start_time_ns: 0,
        })
        .duration_ms(100)
        .build();

    let trace = Simulator::new(ScxSimple).run(scenario);
    trace.dump();

    // Should have been scheduled multiple times
    let count = trace.schedule_count(Pid(1));
    assert!(count > 1, "expected multiple schedules, got {count}");

    // Runtime should be about 5ms per cycle, ~6-7 cycles in 100ms
    // (15ms per cycle = ~6.6 cycles, each contributing 5ms = ~33ms)
    let runtime = trace.total_runtime(Pid(1));
    eprintln!("sleeper runtime: {runtime}ns, schedule_count: {count}");
    assert!(
        runtime > 20_000_000 && runtime < 40_000_000,
        "expected ~33ms runtime, got {runtime}ns"
    );
}

/// Slice expiry: task with long Run phase should be preempted by slice.
#[test]
fn test_slice_preemption() {
    let _lock = common::setup_test();
    let scenario = Scenario::builder()
        .cpus(1)
        .task(TaskDef {
            name: "long_runner".into(),
            pid: Pid(1),
            nice: 0,
            behavior: TaskBehavior {
                // Run much longer than a single slice (SCX_SLICE_DFL = 20ms)
                phases: vec![Phase::Run(100_000_000)], // 100ms
                repeat: false,
            },
            start_time_ns: 0,
        })
        .duration_ms(200)
        .build();

    let trace = Simulator::new(ScxSimple).run(scenario);
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
        .duration_ms(100)
        .build();

    let trace = Simulator::new(ScxSimple).run(scenario);

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
