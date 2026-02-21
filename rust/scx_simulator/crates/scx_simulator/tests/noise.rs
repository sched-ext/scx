use scx_simulator::*;

mod common;

/// Noise disabled: instant timing preserved.
#[test]
fn test_noise_disabled_instant_timing() {
    let _lock = common::setup_test();
    let scenario = Scenario::builder()
        .cpus(1)
        .instant_timing()
        .task(TaskDef {
            name: "worker".into(),
            pid: Pid(1),
            nice: 0,
            behavior: TaskBehavior {
                phases: vec![Phase::Run(5_000_000)],
                repeat: RepeatMode::Once,
            },
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: None,
            parent_pid: None,
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
        })
        .duration_ms(100)
        .build();

    let trace = Simulator::new(DynamicScheduler::simple()).run(scenario);
    let runtime = trace.total_runtime(Pid(1));
    assert_eq!(
        runtime, 5_000_000,
        "expected exact 5ms runtime, got {runtime}ns"
    );
}

/// Noise enabled: tick jitter varies timing.
#[test]
fn test_tick_jitter_varies_intervals() {
    let _lock = common::setup_test();
    let scenario = Scenario::builder()
        .cpus(1)
        .noise(true)
        .overhead(false)
        .task(TaskDef {
            name: "runner".into(),
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
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
        })
        .duration_ms(50)
        .build();

    let trace = Simulator::new(DynamicScheduler::simple()).run(scenario);

    // Collect tick event timestamps
    let tick_times: Vec<TimeNs> = trace
        .events()
        .iter()
        .filter(|e| matches!(e.kind, TraceKind::Tick { .. }))
        .map(|e| e.time_ns)
        .collect();

    // Need at least a few ticks to check intervals
    assert!(
        tick_times.len() >= 3,
        "expected at least 3 tick events, got {}",
        tick_times.len()
    );

    // Compute intervals between consecutive ticks on the same CPU
    let intervals: Vec<i64> = tick_times
        .windows(2)
        .map(|w| w[1] as i64 - w[0] as i64)
        .collect();

    // Assert that not all intervals are exactly TICK_INTERVAL_NS (4ms)
    let all_exact = intervals.iter().all(|&i| i == 4_000_000);
    assert!(
        !all_exact,
        "expected jittered tick intervals, but all were exactly 4ms"
    );

    // Assert intervals are clustered around TICK_INTERVAL_NS (within 50%)
    for &interval in &intervals {
        assert!(
            interval > 2_000_000 && interval < 6_000_000,
            "tick interval {interval}ns is too far from 4ms"
        );
    }
}

/// Context switch overhead consumes time.
#[test]
fn test_csw_overhead_consumed() {
    let _lock = common::setup_test();

    // Use short run phases that complete quickly, causing many voluntary context
    // switches (sleep/wake cycles). With large CSW overhead, this eats into
    // available CPU time measurably.
    let make_tasks = || {
        vec![
            TaskDef {
                name: "t1".into(),
                pid: Pid(1),
                nice: 0,
                behavior: TaskBehavior {
                    phases: vec![Phase::Run(1_000_000), Phase::Sleep(1_000_000)],
                    repeat: RepeatMode::Forever,
                },
                start_time_ns: 0,
                mm_id: None,
                allowed_cpus: None,
                parent_pid: None,
                cgroup_name: None,
                task_flags: 0,
                migration_disabled: 0,
            },
            TaskDef {
                name: "t2".into(),
                pid: Pid(2),
                nice: 0,
                behavior: TaskBehavior {
                    phases: vec![Phase::Run(1_000_000), Phase::Sleep(1_000_000)],
                    repeat: RepeatMode::Forever,
                },
                start_time_ns: 0,
                mm_id: None,
                allowed_cpus: None,
                parent_pid: None,
                cgroup_name: None,
                task_flags: 0,
                migration_disabled: 0,
            },
        ]
    };

    // Run with exact timing — get baseline runtime
    let scenario_exact = Scenario::builder()
        .cpus(1)
        .instant_timing()
        .task(make_tasks()[0].clone())
        .task(make_tasks()[1].clone())
        .duration_ms(100)
        .build();

    let trace_exact = Simulator::new(DynamicScheduler::simple()).run(scenario_exact);
    let total_exact = trace_exact.total_runtime(Pid(1)) + trace_exact.total_runtime(Pid(2));

    // Run with overhead only (no tick jitter, to isolate CSW effect)
    let scenario_overhead = Scenario::builder()
        .cpus(1)
        .noise(false)
        .overhead_config(OverheadConfig {
            enabled: true,
            voluntary_csw: true,
            involuntary_csw: true,
            voluntary_csw_ns: 500_000,   // 500μs per voluntary CSW
            involuntary_csw_ns: 500_000, // 500μs per involuntary CSW
            csw_jitter: false,
            csw_jitter_stddev_ns: 0,
        })
        .task(make_tasks()[0].clone())
        .task(make_tasks()[1].clone())
        .duration_ms(100)
        .build();

    let trace_overhead = Simulator::new(DynamicScheduler::simple()).run(scenario_overhead);
    let total_overhead =
        trace_overhead.total_runtime(Pid(1)) + trace_overhead.total_runtime(Pid(2));

    let schedules_exact = trace_exact.schedule_count(Pid(1)) + trace_exact.schedule_count(Pid(2));
    let schedules_overhead =
        trace_overhead.schedule_count(Pid(1)) + trace_overhead.schedule_count(Pid(2));

    eprintln!("exact total runtime: {total_exact}ns, overhead total runtime: {total_overhead}ns");
    eprintln!("exact schedules: {schedules_exact}, overhead schedules: {schedules_overhead}");

    // CSW overhead consumes time, reducing the number of schedule cycles
    // that fit within the fixed simulation duration.
    assert!(
        schedules_overhead < schedules_exact,
        "expected overhead schedules ({schedules_overhead}) < exact schedules ({schedules_exact}) due to CSW overhead"
    );
}

/// Noise and overhead are deterministic (same PRNG seed → same trace).
#[test]
fn test_noise_determinism() {
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
                nice: -3,
                behavior: TaskBehavior {
                    phases: vec![Phase::Run(10_000_000)],
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
            .duration_ms(50)
            .build()
    };

    let trace1 = Simulator::new(DynamicScheduler::simple()).run(make_scenario());
    let trace2 = Simulator::new(DynamicScheduler::simple()).run(make_scenario());

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
