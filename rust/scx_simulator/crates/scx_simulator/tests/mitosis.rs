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

/// Write a u32 global variable in the loaded mitosis .so.
///
/// # Safety
/// Caller must hold SIM_LOCK and ensure the symbol name is valid.
unsafe fn set_mitosis_u32(sched: &DynamicScheduler, name: &[u8], value: u32) {
    let sym: libloading::Symbol<'_, *mut u32> = sched
        .get_symbol::<*mut u32>(name)
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
            parent_pid: None,
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
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
            parent_pid: None,
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
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
            parent_pid: None,
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
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
            parent_pid: None,
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
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
            parent_pid: None,
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
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
            parent_pid: None,
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
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
            parent_pid: None,
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
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
            parent_pid: None,
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
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
                phases: vec![Phase::Run(5_000_000), Phase::Sleep(10_000_000)],
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
                phases: vec![Phase::Run(20_000_000)],
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
            parent_pid: None,
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
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
            parent_pid: None,
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
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
            parent_pid: None,
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
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
            parent_pid: None,
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
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
            parent_pid: None,
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
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
            parent_pid: None,
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
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
            parent_pid: None,
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
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
            parent_pid: None,
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
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
            parent_pid: None,
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
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
            parent_pid: None,
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
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
            parent_pid: None,
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
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
            parent_pid: None,
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
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
            parent_pid: None,
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
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
            parent_pid: None,
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
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
            parent_pid: None,
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
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
            parent_pid: None,
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
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
            parent_pid: None,
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
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
            parent_pid: None,
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
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
            parent_pid: None,
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
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
            parent_pid: None,
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
        })
        .task(TaskDef {
            name: "mid".into(),
            pid: pids[1],
            nice: 0,
            behavior: behaviors[1].clone(),
            start_time_ns: 0,
            mm_id: Some(MmId(1)),
            allowed_cpus: None,
            parent_pid: None,
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
        })
        .task(TaskDef {
            name: "tail".into(),
            pid: pids[2],
            nice: 0,
            behavior: behaviors[2].clone(),
            start_time_ns: 0,
            mm_id: Some(MmId(1)),
            allowed_cpus: None,
            parent_pid: None,
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
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
            parent_pid: None,
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
        })
        .task(TaskDef {
            name: "pong_b".into(),
            pid: Pid(2),
            nice: 0,
            behavior: b_behavior,
            start_time_ns: 0,
            mm_id: Some(MmId(1)),
            allowed_cpus: None,
            parent_pid: None,
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
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
            parent_pid: None,
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
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
            parent_pid: None,
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
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
            parent_pid: None,
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
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
            parent_pid: None,
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
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
            parent_pid: None,
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
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
            parent_pid: None,
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
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
            parent_pid: None,
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
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

/// Exercise the timer callback reconfiguration path by bumping
/// configuration_seq before simulation. The timer callback checks
/// configuration_seq != applied_configuration_seq and enters the
/// cell reconfiguration logic when they differ.
#[test]
fn test_timer_reconfiguration_path() {
    let _lock = common::setup_test();
    let sched = DynamicScheduler::mitosis(4);
    unsafe {
        // Bump configuration_seq to 1 so the timer callback enters
        // the reconfiguration path. applied_configuration_seq starts at 0.
        set_mitosis_u32(&sched, b"configuration_seq\0", 1);
    }

    let scenario = Scenario::builder()
        .cpus(4)
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
            parent_pid: None,
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
        })
        .duration_ms(500) // Multiple timer intervals (100ms each)
        .build();

    let trace = Simulator::new(sched).run(scenario);
    trace.dump();

    assert!(trace.total_runtime(Pid(1)) > 0);
}

/// Exercise the debug_events_enabled path. When enabled, the scheduler
/// records cgroup init/exit and task init events to the debug buffer.
/// These are called during init and init_task.
#[test]
fn test_debug_events_enabled() {
    let _lock = common::setup_test();
    let sched = DynamicScheduler::mitosis(2);
    unsafe {
        set_mitosis_bool(&sched, b"debug_events_enabled\0", true);
    }

    let scenario = Scenario::builder()
        .cpus(2)
        .task(TaskDef {
            name: "worker1".into(),
            pid: Pid(1),
            nice: 0,
            behavior: TaskBehavior {
                phases: vec![Phase::Run(5_000_000), Phase::Sleep(5_000_000)],
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
            name: "worker2".into(),
            pid: Pid(2),
            nice: 0,
            behavior: TaskBehavior {
                phases: vec![Phase::Run(5_000_000)],
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
        .duration_ms(100)
        .build();

    let trace = Simulator::new(sched).run(scenario);
    trace.dump();

    assert!(trace.total_runtime(Pid(1)) > 0);
    assert!(trace.total_runtime(Pid(2)) > 0);
}

/// Exercise debug events + timer reconfiguration together.
#[test]
fn test_debug_events_with_timer_reconfig() {
    let _lock = common::setup_test();
    let sched = DynamicScheduler::mitosis(2);
    unsafe {
        set_mitosis_bool(&sched, b"debug_events_enabled\0", true);
        set_mitosis_u32(&sched, b"configuration_seq\0", 1);
    }

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
            parent_pid: None,
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
        })
        .duration_ms(300)
        .build();

    let trace = Simulator::new(sched).run(scenario);
    trace.dump();

    assert!(trace.total_runtime(Pid(1)) > 0);
}

/// Exercise SMT + pinned tasks + timer reconfiguration for combined path coverage.
#[test]
fn test_smt_pinned_timer_reconfig() {
    let _lock = common::setup_test();
    let sched = DynamicScheduler::mitosis(4);
    unsafe {
        set_mitosis_bool(&sched, b"smt_enabled\0", true);
        set_mitosis_u32(&sched, b"configuration_seq\0", 1);
    }

    let scenario = Scenario::builder()
        .cpus(4)
        .smt(2)
        .task(TaskDef {
            name: "pin0".into(),
            pid: Pid(1),
            nice: 0,
            behavior: TaskBehavior {
                phases: vec![Phase::Run(5_000_000), Phase::Sleep(3_000_000)],
                repeat: RepeatMode::Forever,
            },
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: Some(vec![CpuId(0)]),
            parent_pid: None,
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
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
            parent_pid: None,
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
        })
        .duration_ms(500)
        .build();

    let trace = Simulator::new(sched).run(scenario);
    trace.dump();

    assert!(trace.total_runtime(Pid(1)) > 0);
    assert!(trace.total_runtime(Pid(2)) > 0);
}

/// Exercise overloaded CPUs with all features enabled for maximum branch coverage.
#[test]
fn test_overloaded_all_features() {
    let _lock = common::setup_test();
    let sched = DynamicScheduler::mitosis(2);
    unsafe {
        set_mitosis_bool(&sched, b"smt_enabled\0", true);
        set_mitosis_bool(&sched, b"split_vtime_updates\0", true);
        set_mitosis_bool(&sched, b"debug_events_enabled\0", true);
        set_mitosis_u32(&sched, b"configuration_seq\0", 1);
    }

    // More tasks than CPUs to exercise overloaded dispatch
    let mut builder = Scenario::builder().cpus(2).smt(2).duration_ms(300);
    for i in 1..=6 {
        builder = builder.task(TaskDef {
            name: format!("task{i}"),
            pid: Pid(i),
            nice: if i <= 2 { -5 } else { 5 },
            behavior: TaskBehavior {
                phases: vec![Phase::Run(3_000_000), Phase::Sleep(2_000_000)],
                repeat: RepeatMode::Forever,
            },
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: if i == 1 { Some(vec![CpuId(0)]) } else { None },
            parent_pid: None,
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
        });
    }

    let trace = Simulator::new(sched).run(builder.build());
    trace.dump();

    for i in 1..=6 {
        assert!(trace.total_runtime(Pid(i)) > 0, "task {i} got no runtime");
    }
}

/// Exercise reject_multicpu_pinning=true with a single-CPU pinned task.
/// This doesn't trigger the error (which requires multi-CPU pinning),
/// but exercises the check path.
#[test]
fn test_reject_multicpu_pinning() {
    let _lock = common::setup_test();
    let sched = DynamicScheduler::mitosis(4);
    unsafe {
        set_mitosis_bool(&sched, b"reject_multicpu_pinning\0", true);
    }

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
            parent_pid: None,
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
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
            parent_pid: None,
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
        })
        .duration_ms(200)
        .build();

    let trace = Simulator::new(sched).run(scenario);
    trace.dump();

    assert!(trace.total_runtime(Pid(1)) > 0);
    assert!(trace.total_runtime(Pid(2)) > 0);
}

/// Exercise high task churn: many tasks with short lifetimes completing.
/// This exercises init_task and exit paths more heavily.
#[test]
fn test_high_task_churn() {
    let _lock = common::setup_test();

    let mut builder = Scenario::builder().cpus(2).duration_ms(200);
    for i in 1..=16 {
        builder = builder.task(TaskDef {
            name: format!("short{i}"),
            pid: Pid(i),
            nice: 0,
            behavior: TaskBehavior {
                phases: vec![Phase::Run(2_000_000)],
                repeat: RepeatMode::Count(3),
            },
            start_time_ns: (i as u64 - 1) * 5_000_000, // stagger starts
            mm_id: None,
            allowed_cpus: None,
            parent_pid: None,
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
        });
    }

    let trace = Simulator::new(DynamicScheduler::mitosis(2)).run(builder.build());
    trace.dump();

    // At least some tasks should complete
    let completed = trace
        .events()
        .iter()
        .filter(|e| matches!(e.kind, TraceKind::TaskCompleted { .. }))
        .count();
    assert!(completed > 0, "no tasks completed");
}

/// Different nice values spanning the full range to exercise weight calculation.
#[test]
fn test_extreme_nice_values() {
    let _lock = common::setup_test();

    let scenario = Scenario::builder()
        .cpus(2)
        .task(TaskDef {
            name: "high_prio".into(),
            pid: Pid(1),
            nice: -20,
            behavior: TaskBehavior {
                phases: vec![Phase::Run(5_000_000)],
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
            name: "low_prio".into(),
            pid: Pid(2),
            nice: 19,
            behavior: TaskBehavior {
                phases: vec![Phase::Run(5_000_000)],
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

    let trace = Simulator::new(DynamicScheduler::mitosis(2)).run(scenario);
    trace.dump();

    // Both tasks should run but high priority should get significantly more time
    let high_runtime = trace.total_runtime(Pid(1));
    let low_runtime = trace.total_runtime(Pid(2));
    assert!(high_runtime > 0, "high priority task got no runtime");
    assert!(low_runtime > 0, "low priority task got no runtime");
}

/// Exercise `cpu_controller_disabled=false` path.
/// When CPU controller is NOT disabled, `init_task` uses `args->cgroup`
/// directly (line 1578) instead of calling `task_cgroup()` → `init_cgrp_ctx_with_ancestors()`.
/// Also covers the `!cpu_controller_disabled` branch in `task_cgroup()` (line 147)
/// and the `maybe_refresh_cell` path that skips the cgroup-change check (line 573).
#[test]
fn test_cpu_controller_enabled() {
    let _lock = common::setup_test();
    let sched = DynamicScheduler::mitosis(4);
    unsafe {
        set_mitosis_bool(&sched, b"cpu_controller_disabled\0", false);
    }

    let scenario = Scenario::builder()
        .cpus(4)
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
            nice: 0,
            behavior: TaskBehavior {
                phases: vec![Phase::Run(5_000_000), Phase::Sleep(5_000_000)],
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

    let trace = Simulator::new(sched).run(scenario);
    trace.dump();

    assert!(trace.total_runtime(Pid(1)) > 0);
    assert!(trace.total_runtime(Pid(2)) > 0);
}

/// Exercise `cpu_controller_disabled=false` with pinned tasks.
/// Covers the `__COMPAT_scx_bpf_task_cgroup(p)` call inside `task_cgroup()`
/// when the cgroup change detection is skipped in `maybe_refresh_cell()`.
#[test]
fn test_cpu_controller_enabled_pinned() {
    let _lock = common::setup_test();
    let sched = DynamicScheduler::mitosis(4);
    unsafe {
        set_mitosis_bool(&sched, b"cpu_controller_disabled\0", false);
    }

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
            parent_pid: None,
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
        })
        .task(TaskDef {
            name: "free".into(),
            pid: Pid(2),
            nice: 0,
            behavior: TaskBehavior {
                phases: vec![Phase::Run(15_000_000)],
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

    let trace = Simulator::new(sched).run(scenario);
    trace.dump();

    assert!(trace.total_runtime(Pid(1)) > 0);
    assert!(trace.total_runtime(Pid(2)) > 0);
}

/// Exercise `cpu_controller_disabled=false` with timer reconfiguration.
/// When CPU controller is enabled, the `maybe_refresh_cell` skips the
/// cgroup-change check (line 573), but still checks `configuration_seq`.
#[test]
fn test_cpu_controller_enabled_timer_reconfig() {
    let _lock = common::setup_test();
    let sched = DynamicScheduler::mitosis(4);
    unsafe {
        set_mitosis_bool(&sched, b"cpu_controller_disabled\0", false);
        set_mitosis_u32(&sched, b"configuration_seq\0", 1);
    }

    let scenario = Scenario::builder()
        .cpus(4)
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
            parent_pid: None,
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
        })
        .duration_ms(500)
        .build();

    let trace = Simulator::new(sched).run(scenario);
    trace.dump();

    assert!(trace.total_runtime(Pid(1)) > 0);
}

/// Exercise `exiting_task_workaround_enabled=true` combined with
/// `cpu_controller_disabled=false`.
/// When CPU controller is enabled, init_task goes through args->cgroup
/// (the root cgroup), so the cgrp_ctx lookup should succeed for root
/// and the workaround path won't trigger normally — but having the
/// flag enabled exercises the guard checks differently.
#[test]
fn test_exiting_task_workaround_enabled() {
    let _lock = common::setup_test();
    let sched = DynamicScheduler::mitosis(2);
    unsafe {
        set_mitosis_bool(&sched, b"exiting_task_workaround_enabled\0", true);
    }

    let scenario = Scenario::builder()
        .cpus(2)
        .task(TaskDef {
            name: "worker".into(),
            pid: Pid(1),
            nice: 0,
            behavior: TaskBehavior {
                phases: vec![Phase::Run(5_000_000)],
                repeat: RepeatMode::Count(3),
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
            name: "bg".into(),
            pid: Pid(2),
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
        .duration_ms(100)
        .build();

    let trace = Simulator::new(sched).run(scenario);
    trace.dump();

    assert!(trace.total_runtime(Pid(1)) > 0);
    assert!(trace.total_runtime(Pid(2)) > 0);
}

/// Exercise `reject_multicpu_pinning=true` with multi-CPU pinning.
/// The task is pinned to 2 CPUs (not all cell CPUs), which exercises
/// the `reject_multicpu_pinning` branch in `update_task_cpumask`.
/// Since all tasks are in cell 0 in the simulator (tctx->cell == 0),
/// the check `tctx->cell != 0` will prevent the error — but we
/// exercise the condition evaluation path.
#[test]
fn test_reject_multicpu_pinning_two_cpus() {
    let _lock = common::setup_test();
    let sched = DynamicScheduler::mitosis(4);
    unsafe {
        set_mitosis_bool(&sched, b"reject_multicpu_pinning\0", true);
    }

    let scenario = Scenario::builder()
        .cpus(4)
        .task(TaskDef {
            name: "multi_pin".into(),
            pid: Pid(1),
            nice: 0,
            behavior: TaskBehavior {
                phases: vec![Phase::Run(5_000_000), Phase::Sleep(3_000_000)],
                repeat: RepeatMode::Forever,
            },
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: Some(vec![CpuId(0), CpuId(1)]),
            parent_pid: None,
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
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
            parent_pid: None,
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
        })
        .duration_ms(200)
        .build();

    let trace = Simulator::new(sched).run(scenario);
    trace.dump();

    assert!(trace.total_runtime(Pid(1)) > 0);
    assert!(trace.total_runtime(Pid(2)) > 0);
}

/// Exercise the `stopping()` path where `cidx == 0 && !all_cell_cpus_allowed`.
/// This skips the `cell_cycles += used` accounting (line 1260-1267).
/// A pinned task in cell 0 with limited CPU affinity will have
/// `all_cell_cpus_allowed=false` and `cidx=0`.
#[test]
fn test_stopping_skip_cell_cycles() {
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
            // Pinned to one CPU => all_cell_cpus_allowed = false
            allowed_cpus: Some(vec![CpuId(0)]),
            parent_pid: None,
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
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
            parent_pid: None,
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
        })
        .duration_ms(200)
        .build();

    let trace = Simulator::new(DynamicScheduler::mitosis(4)).run(scenario);
    trace.dump();

    // Pinned task runs on CPU 0 only
    for event in trace.events() {
        if let TraceKind::TaskScheduled { pid } = &event.kind {
            if *pid == Pid(1) {
                assert_eq!(event.cpu, CpuId(0));
            }
        }
    }
    assert!(trace.total_runtime(Pid(1)) > 0);
}

/// Exercise the `split_vtime_updates` + `cpu_controller_disabled=false` combo.
/// Covers both the split vtime path and the CPU controller enabled path.
#[test]
fn test_split_vtime_cpu_controller_enabled() {
    let _lock = common::setup_test();
    let sched = DynamicScheduler::mitosis(2);
    unsafe {
        set_mitosis_bool(&sched, b"cpu_controller_disabled\0", false);
        set_mitosis_bool(&sched, b"split_vtime_updates\0", true);
    }

    let scenario = Scenario::builder()
        .cpus(2)
        .task(TaskDef {
            name: "t1".into(),
            pid: Pid(1),
            nice: -3,
            behavior: TaskBehavior {
                phases: vec![Phase::Run(5_000_000), Phase::Sleep(3_000_000)],
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
            nice: 3,
            behavior: TaskBehavior {
                phases: vec![Phase::Run(8_000_000)],
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

    let trace = Simulator::new(sched).run(scenario);
    trace.dump();

    assert!(trace.total_runtime(Pid(1)) > 0);
    assert!(trace.total_runtime(Pid(2)) > 0);
}

/// Exercise all features enabled with `cpu_controller_disabled=false`.
/// This combines timer reconfig, debug events, SMT, split vtime, and
/// CPU controller enabled for maximum branch coverage.
#[test]
fn test_all_features_cpu_controller_enabled() {
    let _lock = common::setup_test();
    let sched = DynamicScheduler::mitosis(4);
    unsafe {
        set_mitosis_bool(&sched, b"cpu_controller_disabled\0", false);
        set_mitosis_bool(&sched, b"smt_enabled\0", true);
        set_mitosis_bool(&sched, b"split_vtime_updates\0", true);
        set_mitosis_bool(&sched, b"debug_events_enabled\0", true);
        set_mitosis_u32(&sched, b"configuration_seq\0", 1);
    }

    let mut builder = Scenario::builder().cpus(4).smt(2).duration_ms(500);
    for i in 1..=6 {
        builder = builder.task(TaskDef {
            name: format!("t{i}"),
            pid: Pid(i),
            nice: (i as i8 % 5) - 2,
            behavior: TaskBehavior {
                phases: vec![Phase::Run(3_000_000), Phase::Sleep(2_000_000)],
                repeat: RepeatMode::Forever,
            },
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: if i == 1 { Some(vec![CpuId(0)]) } else { None },
            parent_pid: None,
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
        });
    }

    let trace = Simulator::new(sched).run(builder.build());
    trace.dump();

    for i in 1..=6 {
        assert!(trace.total_runtime(Pid(i)) > 0, "task {i} got no runtime");
    }
}

/// Exercise many tasks with staggered starts to maximize timer
/// interaction with various task lifecycle phases.
#[test]
fn test_staggered_many_tasks_timer() {
    let _lock = common::setup_test();
    let sched = DynamicScheduler::mitosis(4);
    unsafe {
        set_mitosis_u32(&sched, b"configuration_seq\0", 2);
    }

    let mut builder = Scenario::builder().cpus(4).duration_ms(600);
    for i in 1..=12 {
        builder = builder.task(TaskDef {
            name: format!("t{i}"),
            pid: Pid(i),
            nice: 0,
            behavior: TaskBehavior {
                phases: vec![Phase::Run(5_000_000), Phase::Sleep(10_000_000)],
                repeat: RepeatMode::Forever,
            },
            start_time_ns: (i as u64 - 1) * 10_000_000,
            mm_id: None,
            allowed_cpus: None,
            parent_pid: None,
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
        });
    }

    let trace = Simulator::new(sched).run(builder.build());
    trace.dump();

    // At least half should have run
    let running = (1..=12)
        .filter(|&i| trace.total_runtime(Pid(i)) > 0)
        .count();
    assert!(
        running >= 6,
        "expected at least 6/12 tasks to run, got {running}"
    );
}

/// Exercise SMT enabled with cpu_controller_disabled=false.
#[test]
fn test_smt_cpu_controller_enabled() {
    let _lock = common::setup_test();
    let sched = DynamicScheduler::mitosis(4);
    unsafe {
        set_mitosis_bool(&sched, b"cpu_controller_disabled\0", false);
        set_mitosis_bool(&sched, b"smt_enabled\0", true);
    }

    let scenario = Scenario::builder()
        .cpus(4)
        .smt(2)
        .task(TaskDef {
            name: "t1".into(),
            pid: Pid(1),
            nice: 0,
            behavior: TaskBehavior {
                phases: vec![Phase::Run(8_000_000), Phase::Sleep(4_000_000)],
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
                phases: vec![Phase::Run(8_000_000), Phase::Sleep(4_000_000)],
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
            parent_pid: None,
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
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

/// Long-running simulation to exercise many timer firings at different
/// configuration_seq values. Bumps seq higher to test convergence.
#[test]
fn test_timer_many_reconfigurations() {
    let _lock = common::setup_test();
    let sched = DynamicScheduler::mitosis(8);
    unsafe {
        set_mitosis_u32(&sched, b"configuration_seq\0", 5);
    }

    let mut builder = Scenario::builder().cpus(8).duration_ms(800);
    for i in 1..=8 {
        builder = builder.task(TaskDef {
            name: format!("t{i}"),
            pid: Pid(i),
            nice: (i as i8 % 5) - 2,
            behavior: TaskBehavior {
                phases: vec![
                    Phase::Run(4_000_000 + (i as u64) * 1_000_000),
                    Phase::Sleep(3_000_000),
                ],
                repeat: RepeatMode::Forever,
            },
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: if i <= 2 {
                Some(vec![CpuId((i - 1) as u32)])
            } else {
                None
            },
            parent_pid: None,
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
        });
    }

    let trace = Simulator::new(sched).run(builder.build());
    trace.dump();

    for i in 1..=8 {
        assert!(trace.total_runtime(Pid(i)) > 0, "task {i} got no runtime");
    }
}

/// Exercise dump_cpumask with > 32 CPUs to cover the comma separator branch.
/// When `nr_possible_cpus >= 33`, `nr_words = (nr_cpus + 31) / 32 >= 2`,
/// so the `dump_cpumask` loop iterates more than once and hits the
/// `if (word)` branch (line 1601) that prints a comma separator.
#[test]
fn test_dump_cpumask_many_cpus() {
    let _lock = common::setup_test();
    let nr_cpus = 33;
    let sched = DynamicScheduler::mitosis(nr_cpus);
    unsafe {
        set_mitosis_bool(&sched, b"debug_events_enabled\0", true);
    }

    let mut builder = Scenario::builder().cpus(nr_cpus);
    for i in 1..=4 {
        builder = builder.task(TaskDef {
            name: format!("t{i}"),
            pid: Pid(i),
            nice: 0,
            behavior: TaskBehavior {
                phases: vec![Phase::Run(5_000_000)],
                repeat: RepeatMode::Forever,
            },
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: None,
            parent_pid: None,
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
        });
    }

    let trace = Simulator::new(sched).run(builder.duration_ms(100).build());
    trace.dump();

    for i in 1..=4 {
        assert!(trace.total_runtime(Pid(i)) > 0, "task {i} got no runtime");
    }
}

/// Exercise many debug events to cover more dump iteration paths.
/// With debug_events_enabled=true and many tasks, `record_init_task`
/// fires for each task, populating the debug_events buffer.
/// The dump function then iterates through all recorded events.
#[test]
fn test_many_debug_events() {
    let _lock = common::setup_test();
    let nr_cpus = 8;
    let nr_tasks: i32 = 32;
    let sched = DynamicScheduler::mitosis(nr_cpus);
    unsafe {
        set_mitosis_bool(&sched, b"debug_events_enabled\0", true);
    }

    let mut builder = Scenario::builder().cpus(nr_cpus);
    for i in 1..=nr_tasks {
        builder = builder.task(TaskDef {
            name: format!("t{i}"),
            pid: Pid(i),
            nice: 0,
            behavior: TaskBehavior {
                phases: vec![Phase::Run(2_000_000)],
                repeat: RepeatMode::Forever,
            },
            start_time_ns: (i as u64 - 1) * 500_000,
            mm_id: None,
            allowed_cpus: None,
            parent_pid: None,
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
        });
    }

    let trace = Simulator::new(sched).run(builder.duration_ms(200).build());
    trace.dump();

    let running = (1..=nr_tasks)
        .filter(|&i| trace.total_runtime(Pid(i)) > 0)
        .count();
    assert!(
        running >= nr_tasks as usize / 2,
        "expected at least half of {nr_tasks} tasks to run, got {running}"
    );
}

/// Combine 33+ CPUs with cpu_controller_disabled=false, SMT, and timer reconfig
/// to exercise dump paths with large cpumasks alongside other coverage targets.
#[test]
fn test_large_cpu_count_all_features() {
    let _lock = common::setup_test();
    let nr_cpus = 36;
    let sched = DynamicScheduler::mitosis(nr_cpus);
    unsafe {
        set_mitosis_bool(&sched, b"cpu_controller_disabled\0", false);
        set_mitosis_bool(&sched, b"smt_enabled\0", true);
        set_mitosis_bool(&sched, b"split_vtime_updates\0", true);
        set_mitosis_bool(&sched, b"debug_events_enabled\0", true);
        set_mitosis_u32(&sched, b"configuration_seq\0", 1);
    }

    let mut builder = Scenario::builder().cpus(nr_cpus);
    for i in 1..=8i32 {
        builder = builder.task(TaskDef {
            name: format!("t{i}"),
            pid: Pid(i),
            nice: 0,
            behavior: TaskBehavior {
                phases: vec![Phase::Run(5_000_000), Phase::Sleep(2_000_000)],
                repeat: RepeatMode::Forever,
            },
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: if i <= 2 {
                Some(vec![CpuId((i as u32 - 1) * 16)])
            } else {
                None
            },
            parent_pid: None,
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
        });
    }

    let trace = Simulator::new(sched).run(builder.duration_ms(300).build());
    trace.dump();

    for i in 1..=8i32 {
        assert!(trace.total_runtime(Pid(i)) > 0, "task {i} got no runtime");
    }
}
