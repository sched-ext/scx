use std::sync::MutexGuard;

use scx_simulator::{SimFormat, SIM_LOCK};

/// Acquire the simulator lock and initialize tracing from `RUST_LOG`.
///
/// Returns the lock guard — hold it for the duration of the test.
/// `try_init()` is idempotent: first call in the process succeeds,
/// subsequent calls are silently ignored.
///
/// This function handles poisoned locks (from panicked tests) by clearing
/// the poison and recovering the lock. This is safe because each test
/// starts with fresh simulator state.
pub fn setup_test() -> MutexGuard<'static, ()> {
    let guard = SIM_LOCK.lock().unwrap_or_else(|poisoned| {
        // A previous test panicked while holding the lock. This is fine
        // because the simulator state is reset between tests anyway.
        // Clear the poison and recover.
        poisoned.into_inner()
    });
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .event_format(SimFormat)
        .try_init();
    guard
}

/// Generate a suite of scheduler-generic tests.
///
/// `$make_sched` is a closure `|nr_cpus: u32| -> DynamicScheduler` that
/// constructs the scheduler under test. Tests that need multiple CPUs
/// pass the appropriate count; single-CPU tests pass 1.
///
/// Usage:
/// ```ignore
/// mod common;
/// common::scheduler_tests!(|n| DynamicScheduler::tickless(n));
/// ```
#[macro_export]
macro_rules! scheduler_tests {
    ($make_sched:expr) => {
        use std::collections::HashSet;
        use scx_simulator::ExitKind;

        /// Smoke test: single task on single CPU runs to completion.
        #[test]
        fn test_single_task_single_cpu() {
            let _lock = common::setup_test();
            let sched_factory = $make_sched;
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

            let trace = Simulator::new(sched_factory(1)).run(scenario);
            trace.dump();

            assert_eq!(trace.exit_kind(), &ExitKind::Normal, "simulation should complete normally");
            assert!(trace.schedule_count(Pid(1)) > 0, "task was never scheduled");
            assert!(
                trace.events().iter().any(|e| matches!(
                    e.kind,
                    TraceKind::TaskCompleted { pid } if pid == Pid(1)
                )),
                "task did not complete"
            );
            let runtime = trace.total_runtime(Pid(1));
            assert!(runtime == 5_000_000, "expected 5ms runtime, got {runtime}ns");
        }

        /// Multiple tasks on a single CPU should all get scheduled.
        #[test]
        fn test_multiple_tasks_single_cpu() {
            let _lock = common::setup_test();
            let sched_factory = $make_sched;
            let scenario = Scenario::builder()
                .cpus(1)
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
                .duration_ms(100)
                .build();

            let trace = Simulator::new(sched_factory(1)).run(scenario);
            trace.dump();

            assert_eq!(trace.exit_kind(), &ExitKind::Normal, "simulation should complete normally");
            assert!(trace.schedule_count(Pid(1)) > 0, "task 1 was never scheduled");
            assert!(trace.schedule_count(Pid(2)) > 0, "task 2 was never scheduled");
            let rt1 = trace.total_runtime(Pid(1));
            let rt2 = trace.total_runtime(Pid(2));
            assert!(rt1 > 0, "task 1 got no runtime");
            assert!(rt2 > 0, "task 2 got no runtime");
        }

        /// Tasks on multiple CPUs should spread across CPUs.
        #[test]
        fn test_multiple_cpus() {
            let _lock = common::setup_test();
            let sched_factory = $make_sched;
            let scenario = Scenario::builder()
                .cpus(4)
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
                .duration_ms(100)
                .build();

            let trace = Simulator::new(sched_factory(4)).run(scenario);

            assert_eq!(trace.exit_kind(), &ExitKind::Normal, "simulation should complete normally");
            assert!(trace.total_runtime(Pid(1)) > 0);
            assert!(trace.total_runtime(Pid(2)) > 0);

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
            let sched_factory = $make_sched;
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

            let trace1 = Simulator::new(sched_factory(2)).run(make_scenario());
            let trace2 = Simulator::new(sched_factory(2)).run(make_scenario());

            assert_eq!(trace1.exit_kind(), &ExitKind::Normal, "trace1 should complete normally");
            assert_eq!(trace2.exit_kind(), &ExitKind::Normal, "trace2 should complete normally");
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

        /// Equal-weight tasks on 1 CPU should get roughly equal runtime.
        #[test]
        fn test_equal_weight_fairness() {
            let _lock = common::setup_test();
            let sched_factory = $make_sched;
            let scenario = Scenario::builder()
                .cpus(1)
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
            cgroup_name: None,
            task_flags: 0,
                    migration_disabled: 0,
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
            cgroup_name: None,
            task_flags: 0,
                    migration_disabled: 0,
                })
                .duration_ms(500)
                .build();

            let trace = Simulator::new(sched_factory(1)).run(scenario);
            trace.dump();

            assert_eq!(trace.exit_kind(), &ExitKind::Normal, "simulation should complete normally");
            let rt1 = trace.total_runtime(Pid(1));
            let rt2 = trace.total_runtime(Pid(2));

            assert!(rt1 > 0, "task 1 got no runtime");
            assert!(rt2 > 0, "task 2 got no runtime");

            // Both should get at least 25% of total runtime
            let total = rt1 + rt2;
            assert!(
                rt1 >= total / 4 && rt2 >= total / 4,
                "expected both tasks to get at least 25% runtime: t1={rt1}ns, t2={rt2}ns"
            );
        }

        /// Sleep/wake cycle: task should run multiple times and accumulate
        /// the expected runtime across cycles.
        #[test]
        fn test_sleep_wake_cycle() {
            let _lock = common::setup_test();
            let sched_factory = $make_sched;
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

            let trace = Simulator::new(sched_factory(1)).run(scenario);
            trace.dump();

            assert_eq!(trace.exit_kind(), &ExitKind::Normal, "simulation should complete normally");
            let count = trace.schedule_count(Pid(1));
            assert!(count > 1, "expected multiple schedules, got {count}");

            // Runtime should be about 5ms per cycle, ~6-7 cycles in 100ms
            // (15ms per cycle => ~33ms total runtime)
            // Allow wider range for schedulers with different slice/preemption behavior.
            let runtime = trace.total_runtime(Pid(1));
            assert!(
                runtime > 20_000_000 && runtime < 55_000_000,
                "expected ~33ms runtime, got {runtime}ns"
            );
        }

        /// Trace ops events: verify that the fine-grained kernel-level trace
        /// events (PutPrevTask, PickTask, SetNextTask, Balance, DsqInsert, etc.)
        /// are emitted consistently alongside the high-level events.
        #[test]
        fn test_trace_ops_events() {
            let _lock = common::setup_test();
            let sched_factory = $make_sched;
            let scenario = Scenario::builder()
                .cpus(2)
                .task(TaskDef {
                    name: "t1".into(),
                    pid: Pid(1),
                    nice: 0,
                    behavior: TaskBehavior {
                        phases: vec![
                            Phase::Run(5_000_000),
                            Phase::Sleep(5_000_000),
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
                .duration_ms(100)
                .build();

            let trace = Simulator::new(sched_factory(2)).run(scenario);
            trace.dump();

            assert_eq!(trace.exit_kind(), &ExitKind::Normal, "simulation should complete normally");
            let events = trace.events();

            // Every TaskScheduled must be preceded by PickTask and SetNextTask
            // for the same pid (within the last few events on the same CPU).
            for (i, e) in events.iter().enumerate() {
                if let TraceKind::TaskScheduled { pid } = &e.kind {
                    // Search backwards for SetNextTask and PickTask
                    let mut found_set_next = false;
                    let mut found_pick = false;
                    for j in (0..i).rev() {
                        match &events[j].kind {
                            TraceKind::SetNextTask { pid: p } if *p == *pid => {
                                found_set_next = true;
                            }
                            TraceKind::PickTask { pid: p } if *p == *pid => {
                                found_pick = true;
                                break; // PickTask comes before SetNextTask
                            }
                            // Stop searching if we hit another high-level event
                            TraceKind::TaskScheduled { .. }
                            | TraceKind::TaskPreempted { .. }
                            | TraceKind::TaskSlept { .. }
                            | TraceKind::TaskCompleted { .. }
                            | TraceKind::CpuIdle => break,
                            _ => {}
                        }
                    }
                    assert!(
                        found_set_next,
                        "TaskScheduled(pid={}) at index {i} not preceded by SetNextTask",
                        pid.0
                    );
                    assert!(
                        found_pick,
                        "TaskScheduled(pid={}) at index {i} not preceded by PickTask",
                        pid.0
                    );
                }
            }

            // Every TaskPreempted must be preceded by PutPrevTask
            // (kernel: put_prev_task runs before the task is considered off-CPU)
            for (i, e) in events.iter().enumerate() {
                if let TraceKind::TaskPreempted { pid } = &e.kind {
                    let found = events[..i].iter().rev().take(10).any(|ev| {
                        matches!(
                            &ev.kind,
                            TraceKind::PutPrevTask { pid: p, .. } if *p == *pid
                        )
                    });
                    assert!(
                        found,
                        "TaskPreempted(pid={}) at index {i} not preceded by PutPrevTask",
                        pid.0
                    );
                }
            }

            // At least one Balance event must exist
            let balance_count = events
                .iter()
                .filter(|e| matches!(e.kind, TraceKind::Balance { .. }))
                .count();
            assert!(
                balance_count > 0,
                "expected at least one Balance event"
            );

            // DsqInsert or DsqInsertVtime events must appear
            let dsq_insert_count = events
                .iter()
                .filter(|e| {
                    matches!(
                        e.kind,
                        TraceKind::DsqInsert { .. } | TraceKind::DsqInsertVtime { .. }
                    )
                })
                .count();
            assert!(
                dsq_insert_count > 0,
                "expected at least one DsqInsert or DsqInsertVtime event"
            );
        }

        /// CPU affinity: a task pinned to CPU 0 on a 4-CPU system must only
        /// be scheduled on CPU 0.
        #[test]
        fn test_cpu_affinity() {
            let _lock = common::setup_test();
            let sched_factory = $make_sched;
            let scenario = Scenario::builder()
                .cpus(4)
                .task(TaskDef {
                    name: "pinned".into(),
                    pid: Pid(1),
                    nice: 0,
                    behavior: TaskBehavior {
                        phases: vec![
                            Phase::Run(5_000_000),
                            Phase::Sleep(5_000_000),
                        ],
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
                // Add an unpinned task to occupy other CPUs
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

            let trace = Simulator::new(sched_factory(4)).run(scenario);
            trace.dump();

            assert_eq!(trace.exit_kind(), &ExitKind::Normal, "simulation should complete normally");
            // Pinned task must have been scheduled
            let pinned_schedules = trace.schedule_count(Pid(1));
            assert!(
                pinned_schedules > 0,
                "pinned task was never scheduled"
            );

            // Every TaskScheduled event for the pinned task must be on CPU 0
            for event in trace.events() {
                if let TraceKind::TaskScheduled { pid } = &event.kind {
                    if *pid == Pid(1) {
                        assert_eq!(
                            event.cpu,
                            CpuId(0),
                            "pinned task scheduled on {:?} instead of CPU 0",
                            event.cpu
                        );
                    }
                }
            }
        }
    };
}
