use scx_simulator::*;

#[macro_use]
mod common;

// Generic test suite applied to scx_mitosis
scheduler_tests!(|nr_cpus| DynamicScheduler::mitosis(nr_cpus));

// ---------------------------------------------------------------------------
// Helpers for configuring mitosis globals via get_symbol()
// ---------------------------------------------------------------------------

/// Write a bool global variable in the loaded mitosis .so.
///
/// # Safety
/// Caller must hold SIM_LOCK and ensure the symbol name is valid.
unsafe fn set_mitosis_bool(sched: &DynamicScheduler, name: &[u8], value: bool) {
    let sym: libloading::Symbol<'_, *mut bool> = sched
        .get_symbol::<*mut bool>(name)
        .unwrap_or_else(|| panic!("symbol {:?} not found", std::str::from_utf8(name)));
    std::ptr::write_volatile(*sym, value);
}

// ---------------------------------------------------------------------------
// scx_mitosis-specific tests
// ---------------------------------------------------------------------------

/// Multiple CPU-pinned tasks on different CPUs exercise the per-CPU DSQ
/// path (all_cell_cpus_allowed=false) through select_cpu, enqueue, and
/// dispatch.
#[test]
fn test_pinned_tasks_percpu_dsq() {
    let _lock = common::setup_test();
    let scenario = Scenario::builder()
        .cpus(4)
        .task(TaskDef {
            name: "pin0".into(),
            pid: Pid(1),
            nice: 0,
            behavior: TaskBehavior {
                phases: vec![Phase::Run(5_000_000), Phase::Sleep(5_000_000)],
                repeat: RepeatMode::Forever,
            },
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: Some(vec![CpuId(0)]),
        })
        .task(TaskDef {
            name: "pin1".into(),
            pid: Pid(2),
            nice: 0,
            behavior: TaskBehavior {
                phases: vec![Phase::Run(5_000_000), Phase::Sleep(5_000_000)],
                repeat: RepeatMode::Forever,
            },
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: Some(vec![CpuId(1)]),
        })
        .task(TaskDef {
            name: "free".into(),
            pid: Pid(3),
            nice: 0,
            behavior: TaskBehavior {
                phases: vec![Phase::Run(20_000_000)],
                repeat: RepeatMode::Forever,
            },
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: None,
        })
        .duration_ms(100)
        .build();

    let trace = Simulator::new(DynamicScheduler::mitosis(4)).run(scenario);
    trace.dump();

    // Pinned tasks must only run on their assigned CPU
    for event in trace.events() {
        if let TraceKind::TaskScheduled { pid } = &event.kind {
            if *pid == Pid(1) {
                assert_eq!(event.cpu, CpuId(0), "pin0 scheduled on wrong CPU");
            }
            if *pid == Pid(2) {
                assert_eq!(event.cpu, CpuId(1), "pin1 scheduled on wrong CPU");
            }
        }
    }

    // All tasks should run
    assert!(trace.schedule_count(Pid(1)) > 0, "pin0 never scheduled");
    assert!(trace.schedule_count(Pid(2)) > 0, "pin1 never scheduled");
    assert!(
        trace.schedule_count(Pid(3)) > 0,
        "free task never scheduled"
    );

    // Verify per-CPU DSQ inserts occurred (DsqInsertVtime with PCPU_BASE DSQ)
    let pcpu_inserts = trace
        .events()
        .iter()
        .filter(|e| matches!(e.kind, TraceKind::DsqInsertVtime { .. }))
        .count();
    assert!(pcpu_inserts > 0, "expected vtime DSQ inserts");
}

/// A pinned task competing with a free task on the same CPU exercises the
/// dispatch path where both cell DSQ and cpu DSQ have tasks.
#[test]
fn test_pinned_and_free_competing_on_same_cpu() {
    let _lock = common::setup_test();
    let scenario = Scenario::builder()
        .cpus(2)
        .task(TaskDef {
            name: "pinned".into(),
            pid: Pid(1),
            nice: 0,
            behavior: TaskBehavior {
                phases: vec![Phase::Run(10_000_000)],
                repeat: RepeatMode::Forever,
            },
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: Some(vec![CpuId(0)]),
        })
        .task(TaskDef {
            name: "free1".into(),
            pid: Pid(2),
            nice: 0,
            behavior: TaskBehavior {
                phases: vec![Phase::Run(10_000_000)],
                repeat: RepeatMode::Forever,
            },
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: None,
        })
        .task(TaskDef {
            name: "free2".into(),
            pid: Pid(3),
            nice: 0,
            behavior: TaskBehavior {
                phases: vec![Phase::Run(10_000_000)],
                repeat: RepeatMode::Forever,
            },
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: None,
        })
        .duration_ms(200)
        .build();

    let trace = Simulator::new(DynamicScheduler::mitosis(2)).run(scenario);
    trace.dump();

    // All tasks should get runtime
    assert!(trace.total_runtime(Pid(1)) > 0);
    assert!(trace.total_runtime(Pid(2)) > 0);
    assert!(trace.total_runtime(Pid(3)) > 0);

    // Pinned task must stay on CPU 0
    for event in trace.events() {
        if let TraceKind::TaskScheduled { pid } = &event.kind {
            if *pid == Pid(1) {
                assert_eq!(event.cpu, CpuId(0));
            }
        }
    }
}

/// Heavy load on all CPUs forces dispatch to look at both cell and per-CPU
/// DSQs and exercise the fallback path in select_cpu where no idle CPU is
/// found.
#[test]
fn test_overloaded_cpus_no_idle() {
    let _lock = common::setup_test();
    let nr_cpus = 2u32;
    // More tasks than CPUs forces select_cpu to fail to find idle
    let scenario = Scenario::builder()
        .cpus(nr_cpus)
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
        })
        .task(TaskDef {
            name: "t3".into(),
            pid: Pid(3),
            nice: 0,
            behavior: TaskBehavior {
                phases: vec![Phase::Run(50_000_000)],
                repeat: RepeatMode::Forever,
            },
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: None,
        })
        .task(TaskDef {
            name: "t4".into(),
            pid: Pid(4),
            nice: 0,
            behavior: TaskBehavior {
                phases: vec![Phase::Run(50_000_000)],
                repeat: RepeatMode::Forever,
            },
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: None,
        })
        .duration_ms(200)
        .build();

    let trace = Simulator::new(DynamicScheduler::mitosis(nr_cpus)).run(scenario);
    trace.dump();

    // All tasks should eventually run
    for pid in 1..=4 {
        assert!(
            trace.total_runtime(Pid(pid)) > 0,
            "task {pid} got no runtime"
        );
    }

    // Both CPUs should be used
    let cpus_used: std::collections::HashSet<CpuId> = trace
        .events()
        .iter()
        .filter_map(|e| match e.kind {
            TraceKind::TaskScheduled { .. } => Some(e.cpu),
            _ => None,
        })
        .collect();
    assert!(
        cpus_used.len() >= 2,
        "expected both CPUs used, got {:?}",
        cpus_used
    );
}

/// Enable SMT in the scheduler and run with hyperthreading topology.
/// This exercises the SMT idle CPU selection path (SCX_PICK_IDLE_CORE).
#[test]
fn test_smt_enabled_idle_core_selection() {
    let _lock = common::setup_test();
    let nr_cpus = 4u32;
    let sched = DynamicScheduler::mitosis(nr_cpus);

    // Enable SMT in the C scheduler
    unsafe {
        set_mitosis_bool(&sched, b"smt_enabled\0", true);
    }

    let scenario = Scenario::builder()
        .cpus(nr_cpus)
        .smt(2) // 4 CPUs, 2 per core = 2 cores
        .task(TaskDef {
            name: "t1".into(),
            pid: Pid(1),
            nice: 0,
            behavior: TaskBehavior {
                phases: vec![Phase::Run(5_000_000), Phase::Sleep(10_000_000)],
                repeat: RepeatMode::Forever,
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
                phases: vec![Phase::Run(5_000_000), Phase::Sleep(10_000_000)],
                repeat: RepeatMode::Forever,
            },
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: None,
        })
        .duration_ms(100)
        .build();

    let trace = Simulator::new(sched).run(scenario);
    trace.dump();

    // Both tasks should run
    assert!(trace.total_runtime(Pid(1)) > 0);
    assert!(trace.total_runtime(Pid(2)) > 0);
}

/// SMT with overloaded CPUs: more tasks than cores to exercise all branches
/// of pick_idle_cpu_from with SMT enabled.
#[test]
fn test_smt_overloaded() {
    let _lock = common::setup_test();
    let nr_cpus = 4u32;
    let sched = DynamicScheduler::mitosis(nr_cpus);

    unsafe {
        set_mitosis_bool(&sched, b"smt_enabled\0", true);
    }

    let scenario = Scenario::builder()
        .cpus(nr_cpus)
        .smt(2)
        .task(TaskDef {
            name: "t1".into(),
            pid: Pid(1),
            nice: 0,
            behavior: TaskBehavior {
                phases: vec![Phase::Run(20_000_000)],
                repeat: RepeatMode::Forever,
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
                phases: vec![Phase::Run(20_000_000)],
                repeat: RepeatMode::Forever,
            },
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: None,
        })
        .task(TaskDef {
            name: "t3".into(),
            pid: Pid(3),
            nice: 0,
            behavior: TaskBehavior {
                phases: vec![Phase::Run(20_000_000)],
                repeat: RepeatMode::Forever,
            },
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: None,
        })
        .task(TaskDef {
            name: "t4".into(),
            pid: Pid(4),
            nice: 0,
            behavior: TaskBehavior {
                phases: vec![Phase::Run(20_000_000)],
                repeat: RepeatMode::Forever,
            },
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: None,
        })
        .task(TaskDef {
            name: "t5".into(),
            pid: Pid(5),
            nice: 0,
            behavior: TaskBehavior {
                phases: vec![Phase::Run(20_000_000)],
                repeat: RepeatMode::Forever,
            },
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: None,
        })
        .duration_ms(200)
        .build();

    let trace = Simulator::new(sched).run(scenario);
    trace.dump();

    // All tasks should get runtime
    for pid in 1..=5 {
        assert!(
            trace.total_runtime(Pid(pid)) > 0,
            "task {pid} got no runtime"
        );
    }
}

/// SMT with pinned tasks exercises the SMT idle mask path for pinned tasks.
#[test]
fn test_smt_pinned_tasks() {
    let _lock = common::setup_test();
    let nr_cpus = 4u32;
    let sched = DynamicScheduler::mitosis(nr_cpus);

    unsafe {
        set_mitosis_bool(&sched, b"smt_enabled\0", true);
    }

    let scenario = Scenario::builder()
        .cpus(nr_cpus)
        .smt(2)
        .task(TaskDef {
            name: "pin0".into(),
            pid: Pid(1),
            nice: 0,
            behavior: TaskBehavior {
                phases: vec![Phase::Run(5_000_000), Phase::Sleep(10_000_000)],
                repeat: RepeatMode::Forever,
            },
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: Some(vec![CpuId(0)]),
        })
        .task(TaskDef {
            name: "free".into(),
            pid: Pid(2),
            nice: 0,
            behavior: TaskBehavior {
                phases: vec![Phase::Run(10_000_000)],
                repeat: RepeatMode::Forever,
            },
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: None,
        })
        .duration_ms(100)
        .build();

    let trace = Simulator::new(sched).run(scenario);
    trace.dump();

    assert!(trace.total_runtime(Pid(1)) > 0);
    assert!(trace.total_runtime(Pid(2)) > 0);

    // Pinned task stays on CPU 0
    for event in trace.events() {
        if let TraceKind::TaskScheduled { pid } = &event.kind {
            if *pid == Pid(1) {
                assert_eq!(event.cpu, CpuId(0));
            }
        }
    }
}

/// Enable split_vtime_updates to exercise the alternative vtime update
/// path in running() and stopping().
#[test]
fn test_split_vtime_updates() {
    let _lock = common::setup_test();
    let nr_cpus = 2u32;
    let sched = DynamicScheduler::mitosis(nr_cpus);

    unsafe {
        set_mitosis_bool(&sched, b"split_vtime_updates\0", true);
    }

    let scenario = Scenario::builder()
        .cpus(nr_cpus)
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
        })
        .task(TaskDef {
            name: "t2".into(),
            pid: Pid(2),
            nice: 0,
            behavior: TaskBehavior {
                phases: vec![Phase::Run(10_000_000)],
                repeat: RepeatMode::Forever,
            },
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: None,
        })
        .duration_ms(200)
        .build();

    let trace = Simulator::new(sched).run(scenario);
    trace.dump();

    // Both tasks should still get fair runtime with split vtime updates
    let rt1 = trace.total_runtime(Pid(1));
    let rt2 = trace.total_runtime(Pid(2));
    assert!(rt1 > 0 && rt2 > 0, "both tasks must run");

    let total = rt1 + rt2;
    assert!(
        rt1 >= total / 4 && rt2 >= total / 4,
        "expected roughly fair scheduling: t1={rt1}ns, t2={rt2}ns"
    );
}

/// split_vtime_updates with pinned tasks exercises both the running()
/// and stopping() vtime paths for per-CPU DSQ tasks.
#[test]
fn test_split_vtime_with_pinned() {
    let _lock = common::setup_test();
    let nr_cpus = 2u32;
    let sched = DynamicScheduler::mitosis(nr_cpus);

    unsafe {
        set_mitosis_bool(&sched, b"split_vtime_updates\0", true);
    }

    let scenario = Scenario::builder()
        .cpus(nr_cpus)
        .task(TaskDef {
            name: "pinned".into(),
            pid: Pid(1),
            nice: 0,
            behavior: TaskBehavior {
                phases: vec![Phase::Run(5_000_000), Phase::Sleep(5_000_000)],
                repeat: RepeatMode::Forever,
            },
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: Some(vec![CpuId(0)]),
        })
        .task(TaskDef {
            name: "free".into(),
            pid: Pid(2),
            nice: 0,
            behavior: TaskBehavior {
                phases: vec![Phase::Run(20_000_000)],
                repeat: RepeatMode::Forever,
            },
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: None,
        })
        .duration_ms(100)
        .build();

    let trace = Simulator::new(sched).run(scenario);
    trace.dump();

    assert!(trace.total_runtime(Pid(1)) > 0);
    assert!(trace.total_runtime(Pid(2)) > 0);
}

/// Test weighted scheduling with different nice values.
/// Higher priority (lower nice) tasks should get more runtime.
#[test]
fn test_weighted_scheduling() {
    let _lock = common::setup_test();
    let scenario = Scenario::builder()
        .cpus(1)
        .task(TaskDef {
            name: "heavy".into(),
            pid: Pid(1),
            nice: -5,
            behavior: TaskBehavior {
                phases: vec![Phase::Run(50_000_000)],
                repeat: RepeatMode::Forever,
            },
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: None,
        })
        .task(TaskDef {
            name: "light".into(),
            pid: Pid(2),
            nice: 5,
            behavior: TaskBehavior {
                phases: vec![Phase::Run(50_000_000)],
                repeat: RepeatMode::Forever,
            },
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: None,
        })
        .duration_ms(500)
        .build();

    let trace = Simulator::new(DynamicScheduler::mitosis(1)).run(scenario);
    trace.dump();

    let rt_heavy = trace.total_runtime(Pid(1));
    let rt_light = trace.total_runtime(Pid(2));

    assert!(rt_heavy > 0, "heavy task got no runtime");
    assert!(rt_light > 0, "light task got no runtime");

    // Higher priority task should get more runtime
    assert!(
        rt_heavy > rt_light,
        "expected heavy task (nice=-5) to get more runtime than light (nice=5): heavy={rt_heavy}ns, light={rt_light}ns"
    );
}

/// Test vtime clamping: tasks that sleep a long time should not accumulate
/// excessive negative vtime credit. The scheduler clamps to basis - slice_ns.
#[test]
fn test_vtime_clamping_after_sleep() {
    let _lock = common::setup_test();
    let scenario = Scenario::builder()
        .cpus(1)
        .task(TaskDef {
            name: "sleeper".into(),
            pid: Pid(1),
            nice: 0,
            behavior: TaskBehavior {
                phases: vec![
                    Phase::Run(1_000_000),    // 1ms
                    Phase::Sleep(50_000_000), // 50ms - long sleep
                ],
                repeat: RepeatMode::Forever,
            },
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: None,
        })
        .task(TaskDef {
            name: "busy".into(),
            pid: Pid(2),
            nice: 0,
            behavior: TaskBehavior {
                phases: vec![Phase::Run(50_000_000)],
                repeat: RepeatMode::Forever,
            },
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: None,
        })
        .duration_ms(300)
        .build();

    let trace = Simulator::new(DynamicScheduler::mitosis(1)).run(scenario);
    trace.dump();

    // Both tasks should run without the scheduler erroring
    assert!(trace.total_runtime(Pid(1)) > 0);
    assert!(trace.total_runtime(Pid(2)) > 0);

    // The sleeper should wake and run multiple times
    assert!(
        trace.schedule_count(Pid(1)) > 2,
        "sleeper should be scheduled multiple times"
    );
}

/// Test with many tasks doing short run phases to exercise the dispatch
/// path heavily - looking for both cell DSQ and cpu DSQ tasks in dispatch.
#[test]
fn test_many_short_tasks_dispatch_pressure() {
    let _lock = common::setup_test();
    let nr_cpus = 2u32;

    let mut builder = Scenario::builder().cpus(nr_cpus).duration_ms(200);

    // Create many short-lived tasks
    for i in 1..=8 {
        builder = builder.task(TaskDef {
            name: format!("t{i}"),
            pid: Pid(i),
            nice: 0,
            behavior: TaskBehavior {
                phases: vec![Phase::Run(2_000_000), Phase::Sleep(3_000_000)],
                repeat: RepeatMode::Forever,
            },
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: None,
        });
    }

    let scenario = builder.build();
    let trace = Simulator::new(DynamicScheduler::mitosis(nr_cpus)).run(scenario);
    trace.dump();

    // All tasks should run
    for i in 1..=8 {
        assert!(trace.total_runtime(Pid(i)) > 0, "task {i} got no runtime");
    }
}

/// Mix of pinned and free tasks with sleep/wake patterns exercises many
/// dispatch and enqueue branches simultaneously.
#[test]
fn test_mixed_pinned_free_sleepwake() {
    let _lock = common::setup_test();
    let nr_cpus = 4u32;

    let scenario = Scenario::builder()
        .cpus(nr_cpus)
        .task(TaskDef {
            name: "pin0".into(),
            pid: Pid(1),
            nice: -3,
            behavior: TaskBehavior {
                phases: vec![Phase::Run(3_000_000), Phase::Sleep(7_000_000)],
                repeat: RepeatMode::Forever,
            },
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: Some(vec![CpuId(0)]),
        })
        .task(TaskDef {
            name: "pin2".into(),
            pid: Pid(2),
            nice: 3,
            behavior: TaskBehavior {
                phases: vec![Phase::Run(8_000_000), Phase::Sleep(2_000_000)],
                repeat: RepeatMode::Forever,
            },
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: Some(vec![CpuId(2)]),
        })
        .task(TaskDef {
            name: "free1".into(),
            pid: Pid(3),
            nice: 0,
            behavior: TaskBehavior {
                phases: vec![Phase::Run(15_000_000)],
                repeat: RepeatMode::Forever,
            },
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: None,
        })
        .task(TaskDef {
            name: "free2".into(),
            pid: Pid(4),
            nice: 0,
            behavior: TaskBehavior {
                phases: vec![Phase::Run(5_000_000), Phase::Sleep(5_000_000)],
                repeat: RepeatMode::Forever,
            },
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: None,
        })
        .duration_ms(200)
        .build();

    let trace = Simulator::new(DynamicScheduler::mitosis(nr_cpus)).run(scenario);
    trace.dump();

    for pid in 1..=4 {
        assert!(
            trace.total_runtime(Pid(pid)) > 0,
            "task {pid} got no runtime"
        );
    }
}

/// Delayed task start: tasks starting at different times exercise the
/// timer and wake-up paths.
#[test]
fn test_delayed_task_start() {
    let _lock = common::setup_test();
    let scenario = Scenario::builder()
        .cpus(2)
        .task(TaskDef {
            name: "early".into(),
            pid: Pid(1),
            nice: 0,
            behavior: TaskBehavior {
                phases: vec![Phase::Run(20_000_000)],
                repeat: RepeatMode::Forever,
            },
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: None,
        })
        .task(TaskDef {
            name: "late".into(),
            pid: Pid(2),
            nice: 0,
            behavior: TaskBehavior {
                phases: vec![Phase::Run(20_000_000)],
                repeat: RepeatMode::Forever,
            },
            start_time_ns: 50_000_000, // Start 50ms into simulation
            mm_id: None,
            allowed_cpus: None,
        })
        .duration_ms(200)
        .build();

    let trace = Simulator::new(DynamicScheduler::mitosis(2)).run(scenario);
    trace.dump();

    // Both should run
    assert!(trace.total_runtime(Pid(1)) > 0);
    assert!(trace.total_runtime(Pid(2)) > 0);

    // The late task should have started later
    let first_late_schedule = trace
        .events()
        .iter()
        .find(|e| matches!(e.kind, TraceKind::TaskScheduled { pid } if pid == Pid(2)));
    assert!(
        first_late_schedule.is_some(),
        "late task was never scheduled"
    );
    assert!(
        first_late_schedule.unwrap().time_ns >= 50_000_000,
        "late task started too early"
    );
}

/// Exercise the timer callback path. The mitosis init sets up a BPF timer
/// that fires update_timer_cb periodically. With the default configuration
/// (no cpuset changes), it should fire and be a no-op since
/// configuration_seq == applied_configuration_seq.
#[test]
fn test_timer_fires_during_simulation() {
    let _lock = common::setup_test();
    let scenario = Scenario::builder()
        .cpus(2)
        .task(TaskDef {
            name: "worker".into(),
            pid: Pid(1),
            nice: 0,
            behavior: TaskBehavior {
                phases: vec![Phase::Run(10_000_000)],
                repeat: RepeatMode::Forever,
            },
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: None,
        })
        .duration_ms(500) // Long enough for multiple timer fires
        .build();

    let trace = Simulator::new(DynamicScheduler::mitosis(2)).run(scenario);
    trace.dump();

    assert!(trace.total_runtime(Pid(1)) > 0);

    // The tick events should fire (these are separate from the BPF timer)
    let tick_count = trace
        .events()
        .iter()
        .filter(|e| matches!(e.kind, TraceKind::Tick { .. }))
        .count();
    assert!(tick_count > 0, "expected tick events during simulation");
}

/// Test with wake chains to exercise wake-up and enqueue paths with
/// different tasks waking each other.
#[test]
fn test_wake_chain_pattern() {
    let _lock = common::setup_test();
    let pids = [Pid(1), Pid(2), Pid(3)];
    let behaviors = workloads::wake_chain(&pids, 2_000_000, 5_000_000);

    let scenario = Scenario::builder()
        .cpus(2)
        .task(TaskDef {
            name: "head".into(),
            pid: pids[0],
            nice: 0,
            behavior: behaviors[0].clone(),
            start_time_ns: 0,
            mm_id: Some(MmId(1)),
            allowed_cpus: None,
        })
        .task(TaskDef {
            name: "mid".into(),
            pid: pids[1],
            nice: 0,
            behavior: behaviors[1].clone(),
            start_time_ns: 0,
            mm_id: Some(MmId(1)),
            allowed_cpus: None,
        })
        .task(TaskDef {
            name: "tail".into(),
            pid: pids[2],
            nice: 0,
            behavior: behaviors[2].clone(),
            start_time_ns: 0,
            mm_id: Some(MmId(1)),
            allowed_cpus: None,
        })
        .duration_ms(100)
        .build();

    let trace = Simulator::new(DynamicScheduler::mitosis(2)).run(scenario);
    trace.dump();

    // All tasks in the chain should run
    for pid in &pids {
        assert!(
            trace.total_runtime(*pid) > 0,
            "task {} got no runtime",
            pid.0
        );
    }
}

/// Ping-pong workload exercises rapid wake/sleep transitions between
/// two cooperating tasks.
#[test]
fn test_ping_pong_pattern() {
    let _lock = common::setup_test();
    let (a_behavior, b_behavior) = workloads::ping_pong(Pid(1), Pid(2), 1_000_000);

    let scenario = Scenario::builder()
        .cpus(2)
        .task(TaskDef {
            name: "pong_a".into(),
            pid: Pid(1),
            nice: 0,
            behavior: a_behavior,
            start_time_ns: 0,
            mm_id: Some(MmId(1)),
            allowed_cpus: None,
        })
        .task(TaskDef {
            name: "pong_b".into(),
            pid: Pid(2),
            nice: 0,
            behavior: b_behavior,
            start_time_ns: 0,
            mm_id: Some(MmId(1)),
            allowed_cpus: None,
        })
        .duration_ms(50)
        .build();

    let trace = Simulator::new(DynamicScheduler::mitosis(2)).run(scenario);
    trace.dump();

    // Both tasks should run multiple times
    assert!(trace.schedule_count(Pid(1)) > 1);
    assert!(trace.schedule_count(Pid(2)) > 1);
}

/// Stress test with many CPUs and many tasks to maximize dispatch coverage.
#[test]
fn test_many_cpus_stress() {
    let _lock = common::setup_test();
    let nr_cpus = 8u32;
    let mut builder = Scenario::builder().cpus(nr_cpus).duration_ms(100);

    for i in 1..=16 {
        builder = builder.task(TaskDef {
            name: format!("t{i}"),
            pid: Pid(i),
            nice: (i as i8 % 7) - 3, // Mix of nice values
            behavior: TaskBehavior {
                phases: vec![
                    Phase::Run(3_000_000 + (i as u64) * 500_000),
                    Phase::Sleep(2_000_000),
                ],
                repeat: RepeatMode::Forever,
            },
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: None,
        });
    }

    let scenario = builder.build();
    let trace = Simulator::new(DynamicScheduler::mitosis(nr_cpus)).run(scenario);
    trace.dump();

    // At least half the tasks should have run
    let running_count = (1..=16)
        .filter(|&i| trace.total_runtime(Pid(i)) > 0)
        .count();
    assert!(
        running_count >= 8,
        "expected at least 8 of 16 tasks to run, got {running_count}"
    );
}

/// Single task completing quickly to exercise TaskCompleted path in mitosis.
#[test]
fn test_single_task_completes() {
    let _lock = common::setup_test();
    let scenario = Scenario::builder()
        .cpus(2)
        .instant_timing()
        .task(TaskDef {
            name: "quick".into(),
            pid: Pid(1),
            nice: 0,
            behavior: TaskBehavior {
                phases: vec![Phase::Run(1_000_000)], // 1ms
                repeat: RepeatMode::Once,
            },
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: None,
        })
        .duration_ms(50)
        .build();

    let trace = Simulator::new(DynamicScheduler::mitosis(2)).run(scenario);
    trace.dump();

    // Task should complete
    assert!(
        trace.events().iter().any(|e| matches!(
            e.kind,
            TraceKind::TaskCompleted { pid } if pid == Pid(1)
        )),
        "task did not complete"
    );
}

/// Exercise with count-based repeat mode.
#[test]
fn test_repeat_count_mode() {
    let _lock = common::setup_test();
    let scenario = Scenario::builder()
        .cpus(1)
        .task(TaskDef {
            name: "counted".into(),
            pid: Pid(1),
            nice: 0,
            behavior: TaskBehavior {
                phases: vec![Phase::Run(2_000_000), Phase::Sleep(3_000_000)],
                repeat: RepeatMode::Count(3),
            },
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: None,
        })
        .task(TaskDef {
            name: "forever".into(),
            pid: Pid(2),
            nice: 0,
            behavior: TaskBehavior {
                phases: vec![Phase::Run(10_000_000)],
                repeat: RepeatMode::Forever,
            },
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: None,
        })
        .duration_ms(100)
        .build();

    let trace = Simulator::new(DynamicScheduler::mitosis(1)).run(scenario);
    trace.dump();

    // Counted task should complete
    assert!(trace
        .events()
        .iter()
        .any(|e| matches!(e.kind, TraceKind::TaskCompleted { pid } if pid == Pid(1))));

    // Background task keeps running
    assert!(trace.total_runtime(Pid(2)) > 0);
}

/// SMT + split_vtime_updates together to exercise both features
/// interacting.
#[test]
fn test_smt_with_split_vtime() {
    let _lock = common::setup_test();
    let nr_cpus = 4u32;
    let sched = DynamicScheduler::mitosis(nr_cpus);

    unsafe {
        set_mitosis_bool(&sched, b"smt_enabled\0", true);
        set_mitosis_bool(&sched, b"split_vtime_updates\0", true);
    }

    let scenario = Scenario::builder()
        .cpus(nr_cpus)
        .smt(2)
        .task(TaskDef {
            name: "t1".into(),
            pid: Pid(1),
            nice: -2,
            behavior: TaskBehavior {
                phases: vec![Phase::Run(10_000_000)],
                repeat: RepeatMode::Forever,
            },
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: None,
        })
        .task(TaskDef {
            name: "t2".into(),
            pid: Pid(2),
            nice: 2,
            behavior: TaskBehavior {
                phases: vec![Phase::Run(10_000_000), Phase::Sleep(5_000_000)],
                repeat: RepeatMode::Forever,
            },
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: None,
        })
        .task(TaskDef {
            name: "t3".into(),
            pid: Pid(3),
            nice: 0,
            behavior: TaskBehavior {
                phases: vec![Phase::Run(15_000_000)],
                repeat: RepeatMode::Forever,
            },
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: None,
        })
        .duration_ms(200)
        .build();

    let trace = Simulator::new(sched).run(scenario);
    trace.dump();

    for pid in 1..=3 {
        assert!(
            trace.total_runtime(Pid(pid)) > 0,
            "task {pid} got no runtime"
        );
    }
}

/// Test with io_bound workload pattern (short run, long sleep).
#[test]
fn test_io_bound_workload() {
    let _lock = common::setup_test();
    let scenario = Scenario::builder()
        .cpus(2)
        .add_task("io1", 0, workloads::io_bound(1_000_000, 10_000_000))
        .add_task("io2", 0, workloads::io_bound(1_000_000, 10_000_000))
        .add_task("cpu", 0, workloads::cpu_bound(20_000_000))
        .duration_ms(200)
        .build();

    let trace = Simulator::new(DynamicScheduler::mitosis(2)).run(scenario);
    trace.dump();

    // All tasks should run
    assert!(trace.total_runtime(Pid(1)) > 0);
    assert!(trace.total_runtime(Pid(2)) > 0);
    assert!(trace.total_runtime(Pid(3)) > 0);
}

/// Test with periodic workload pattern.
#[test]
fn test_periodic_workload() {
    let _lock = common::setup_test();
    let scenario = Scenario::builder()
        .cpus(2)
        .add_task("periodic", 0, workloads::periodic(2_000_000, 10_000_000))
        .add_task("bg", 0, workloads::cpu_bound(20_000_000))
        .duration_ms(100)
        .build();

    let trace = Simulator::new(DynamicScheduler::mitosis(2)).run(scenario);
    trace.dump();

    assert!(trace.total_runtime(Pid(1)) > 0);
    assert!(trace.total_runtime(Pid(2)) > 0);
}
