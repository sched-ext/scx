use scx_simulator::*;

#[macro_use]
mod common;

/// Tick events should be recorded in the trace for running tasks.
#[test]
fn test_tick_events_recorded() {
    let _lock = common::setup_test();
    let scenario = Scenario::builder()
        .cpus(2)
        .task(TaskDef {
            name: "runner1".into(),
            pid: Pid(1),
            nice: 0,
            behavior: TaskBehavior {
                phases: vec![Phase::Run(100_000_000)], // 100ms
                repeat: RepeatMode::Forever,
            },
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: None,
            parent_pid: None,
        })
        .task(TaskDef {
            name: "runner2".into(),
            pid: Pid(2),
            nice: 0,
            behavior: TaskBehavior {
                phases: vec![Phase::Run(100_000_000)], // 100ms
                repeat: RepeatMode::Forever,
            },
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: None,
            parent_pid: None,
        })
        .duration_ms(100)
        .build();

    let trace = Simulator::new(DynamicScheduler::lavd(2)).run(scenario);
    trace.dump();

    // With 100ms duration and 4ms tick interval, each CPU should see ticks
    let ticks_cpu0 = trace.tick_count(CpuId(0));
    let ticks_cpu1 = trace.tick_count(CpuId(1));
    eprintln!("ticks: cpu0={ticks_cpu0}, cpu1={ticks_cpu1}");

    assert!(
        ticks_cpu0 > 0 || ticks_cpu1 > 0,
        "expected tick events to be recorded, got cpu0={ticks_cpu0}, cpu1={ticks_cpu1}"
    );
}

/// LAVD tick preemption: with many competing tasks, tick-triggered
/// preemption should produce TaskPreempted events.
#[test]
fn test_lavd_tick_preemption() {
    let _lock = common::setup_test();
    let scenario = Scenario::builder()
        .cpus(2)
        .task(TaskDef {
            name: "t1".into(),
            pid: Pid(1),
            nice: 0,
            behavior: TaskBehavior {
                phases: vec![Phase::Run(100_000_000)],
                repeat: RepeatMode::Forever,
            },
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: None,
            parent_pid: None,
        })
        .task(TaskDef {
            name: "t2".into(),
            pid: Pid(2),
            nice: 0,
            behavior: TaskBehavior {
                phases: vec![Phase::Run(100_000_000)],
                repeat: RepeatMode::Forever,
            },
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: None,
            parent_pid: None,
        })
        .task(TaskDef {
            name: "t3".into(),
            pid: Pid(3),
            nice: 0,
            behavior: TaskBehavior {
                phases: vec![Phase::Run(100_000_000)],
                repeat: RepeatMode::Forever,
            },
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: None,
            parent_pid: None,
        })
        .task(TaskDef {
            name: "t4".into(),
            pid: Pid(4),
            nice: 0,
            behavior: TaskBehavior {
                phases: vec![Phase::Run(100_000_000)],
                repeat: RepeatMode::Forever,
            },
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: None,
            parent_pid: None,
        })
        .duration_ms(200)
        .build();

    let trace = Simulator::new(DynamicScheduler::lavd(2)).run(scenario);
    trace.dump();

    // Count preemption events
    let preempt_count = trace
        .events()
        .iter()
        .filter(|e| matches!(e.kind, TraceKind::TaskPreempted { .. }))
        .count();

    eprintln!("preemption events: {preempt_count}");

    // With 4 tasks competing on 2 CPUs over 200ms, there should be preemptions
    assert!(
        preempt_count > 0,
        "expected preemption events from tick-triggered preemption"
    );

    // All tasks should get scheduled
    for pid_val in 1..=4 {
        let count = trace.schedule_count(Pid(pid_val));
        assert!(count > 0, "task pid={pid_val} was never scheduled");
    }
}
