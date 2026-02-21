//! Integration tests for concurrent callback interleaving.
//!
//! These tests verify that `--interleave` mode works correctly:
//! deterministic for a given seed, no panics, and different seeds
//! can produce different dispatch winners.

use scx_simulator::*;

#[macro_use]
mod common;

// ---------------------------------------------------------------------------
// Smoke test: interleave mode runs to completion on scx_simple
// ---------------------------------------------------------------------------

#[test]
fn test_interleave_smoke() {
    let _lock = common::setup_test();
    let scenario = Scenario::builder()
        .cpus(4)
        .interleave(true)
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
        .duration_ms(50)
        .build();

    let trace = Simulator::new(DynamicScheduler::simple()).run(scenario);
    trace.dump();

    assert!(
        trace.schedule_count(Pid(1)) > 0,
        "task 1 was never scheduled"
    );
    assert!(
        trace.schedule_count(Pid(2)) > 0,
        "task 2 was never scheduled"
    );
}

// ---------------------------------------------------------------------------
// Determinism: same seed + scenario gives identical traces
// ---------------------------------------------------------------------------

#[test]
fn test_interleave_determinism() {
    let _lock = common::setup_test();
    let make_scenario = || {
        Scenario::builder()
            .cpus(4)
            .seed(42)
            .interleave(true)
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
            .duration_ms(50)
            .build()
    };

    let trace1 = Simulator::new(DynamicScheduler::simple()).run(make_scenario());
    let trace2 = Simulator::new(DynamicScheduler::simple()).run(make_scenario());

    assert_eq!(
        trace1.events().len(),
        trace2.events().len(),
        "interleave traces have different lengths"
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

// ---------------------------------------------------------------------------
// Interleave with sleep/wake cycles
// ---------------------------------------------------------------------------

#[test]
fn test_interleave_sleep_wake() {
    let _lock = common::setup_test();
    let scenario = Scenario::builder()
        .cpus(4)
        .interleave(true)
        .task(TaskDef {
            name: "sleeper".into(),
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
            name: "worker".into(),
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

    let trace = Simulator::new(DynamicScheduler::simple()).run(scenario);
    trace.dump();

    let count = trace.schedule_count(Pid(1));
    assert!(count > 1, "expected multiple schedules, got {count}");

    let runtime = trace.total_runtime(Pid(1));
    assert!(
        runtime > 20_000_000 && runtime < 55_000_000,
        "expected ~33ms runtime, got {runtime}ns"
    );
}

// ---------------------------------------------------------------------------
// Interleave mode matches sequential mode for single CPU
// ---------------------------------------------------------------------------

#[test]
fn test_interleave_single_cpu_noop() {
    let _lock = common::setup_test();
    let make_scenario = |interleave: bool| {
        Scenario::builder()
            .cpus(1)
            .seed(42)
            .fixed_priority(true)
            .interleave(interleave)
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
            .duration_ms(50)
            .build()
    };

    let trace_seq = Simulator::new(DynamicScheduler::simple()).run(make_scenario(false));
    let trace_ilv = Simulator::new(DynamicScheduler::simple()).run(make_scenario(true));

    // With a single CPU, interleave mode should be a no-op (never
    // hits the 2+ CPU threshold), so traces should be identical.
    assert_eq!(
        trace_seq.events().len(),
        trace_ilv.events().len(),
        "single-CPU: interleave and sequential traces differ in length"
    );

    for (i, (e1, e2)) in trace_seq
        .events()
        .iter()
        .zip(trace_ilv.events().iter())
        .enumerate()
    {
        assert_eq!(
            e1.kind, e2.kind,
            "single-CPU event {i}: kinds differ: {:?} vs {:?}",
            e1.kind, e2.kind
        );
    }
}

// ---------------------------------------------------------------------------
// Multiple seeds: interleave mode doesn't crash for various seeds
// ---------------------------------------------------------------------------

#[test]
fn test_interleave_multiple_seeds() {
    let _lock = common::setup_test();
    for seed in [1, 42, 100, 999, 65535] {
        let scenario = Scenario::builder()
            .cpus(4)
            .seed(seed)
            .interleave(true)
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
            .task(TaskDef {
                name: "t3".into(),
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
            .duration_ms(50)
            .build();

        let trace = Simulator::new(DynamicScheduler::simple()).run(scenario);
        assert!(
            trace.schedule_count(Pid(1)) > 0,
            "seed {seed}: task 1 never scheduled"
        );
        assert!(
            trace.schedule_count(Pid(2)) > 0,
            "seed {seed}: task 2 never scheduled"
        );
    }
}

// ===========================================================================
// Preemptive interleaving tests
// ===========================================================================

/// Helper: build a simple N-task scenario with preemptive interleaving.
fn preemptive_scenario(nr_cpus: u32, nr_tasks: u32, seed: u32, duration_ms: u64) -> Scenario {
    let mut builder = Scenario::builder()
        .cpus(nr_cpus)
        .seed(seed)
        .preemptive(PreemptiveConfig::default());

    for i in 1..=nr_tasks {
        builder = builder.task(TaskDef {
            name: format!("t{i}"),
            pid: Pid(i as i32),
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
        });
    }

    builder.duration_ms(duration_ms).build()
}

// ---------------------------------------------------------------------------
// Smoke test: preemptive mode runs to completion
// ---------------------------------------------------------------------------

#[test]
fn test_preemptive_smoke() {
    let _lock = common::setup_test();
    let scenario = preemptive_scenario(4, 2, 42, 50);

    let trace = Simulator::new(DynamicScheduler::simple()).run(scenario);
    trace.dump();

    assert!(
        trace.schedule_count(Pid(1)) > 0,
        "task 1 was never scheduled"
    );
    assert!(
        trace.schedule_count(Pid(2)) > 0,
        "task 2 was never scheduled"
    );
}

// ---------------------------------------------------------------------------
// Determinism: same seed gives identical traces (preemptive mode)
// ---------------------------------------------------------------------------

#[test]
fn test_preemptive_determinism() {
    let _lock = common::setup_test();
    let make = || preemptive_scenario(4, 2, 42, 50);

    let trace1 = Simulator::new(DynamicScheduler::simple()).run(make());
    let trace2 = Simulator::new(DynamicScheduler::simple()).run(make());

    assert_eq!(
        trace1.events().len(),
        trace2.events().len(),
        "preemptive traces have different lengths"
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

// ---------------------------------------------------------------------------
// Sleep/wake interaction with preemptive interleaving
// ---------------------------------------------------------------------------

#[test]
fn test_preemptive_sleep_wake() {
    let _lock = common::setup_test();
    let scenario = Scenario::builder()
        .cpus(4)
        .preemptive(PreemptiveConfig::default())
        .task(TaskDef {
            name: "sleeper".into(),
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
            name: "worker".into(),
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

    let trace = Simulator::new(DynamicScheduler::simple()).run(scenario);
    trace.dump();

    let count = trace.schedule_count(Pid(1));
    assert!(count > 1, "expected multiple schedules, got {count}");

    let runtime = trace.total_runtime(Pid(1));
    assert!(
        runtime > 20_000_000 && runtime < 55_000_000,
        "expected ~33ms runtime, got {runtime}ns"
    );
}

// ---------------------------------------------------------------------------
// Multiple seeds: preemptive mode doesn't crash for various seeds
// ---------------------------------------------------------------------------

#[test]
fn test_preemptive_multiple_seeds() {
    let _lock = common::setup_test();
    for seed in [1, 42, 100, 999, 65535] {
        let scenario = preemptive_scenario(4, 3, seed, 50);
        let trace = Simulator::new(DynamicScheduler::simple()).run(scenario);
        assert!(
            trace.schedule_count(Pid(1)) > 0,
            "seed {seed}: task 1 never scheduled"
        );
        assert!(
            trace.schedule_count(Pid(2)) > 0,
            "seed {seed}: task 2 never scheduled"
        );
    }
}

// ===========================================================================
// Batch-concurrent tests: same-timestamp per-CPU event interleaving
// ===========================================================================

// ---------------------------------------------------------------------------
// Smoke test: batch-concurrent tick interleaving completes
// ---------------------------------------------------------------------------

#[test]
fn test_batch_concurrent_smoke() {
    let _lock = common::setup_test();
    // 4 CPUs, 4 tasks, 50ms: ticks on all CPUs fire at TICK_INTERVAL_NS
    // boundaries and should be processed concurrently.
    let scenario = Scenario::builder()
        .cpus(4)
        .seed(42)
        .interleave(true)
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
        .task(TaskDef {
            name: "t3".into(),
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
        .task(TaskDef {
            name: "t4".into(),
            pid: Pid(4),
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
        .duration_ms(50)
        .build();

    let trace = Simulator::new(DynamicScheduler::simple()).run(scenario);
    trace.dump();

    // All 4 tasks must be scheduled
    for pid_val in 1..=4 {
        assert!(
            trace.schedule_count(Pid(pid_val)) > 0,
            "task {pid_val} was never scheduled"
        );
    }

    // Tick events must appear for all CPUs
    let tick_cpus: std::collections::HashSet<CpuId> = trace
        .events()
        .iter()
        .filter_map(|e| match e.kind {
            TraceKind::Tick { pid: _ } => Some(e.cpu),
            _ => None,
        })
        .collect();
    assert!(
        tick_cpus.len() >= 4,
        "expected ticks on 4 CPUs, got {:?}",
        tick_cpus
    );
}

// ---------------------------------------------------------------------------
// Determinism: batch-concurrent produces identical traces for same seed
// ---------------------------------------------------------------------------

#[test]
fn test_batch_concurrent_determinism() {
    let _lock = common::setup_test();
    let make_scenario = || {
        Scenario::builder()
            .cpus(4)
            .seed(42)
            .interleave(true)
            .task(TaskDef {
                name: "t1".into(),
                pid: Pid(1),
                nice: 0,
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
                nice: 0,
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
                name: "t3".into(),
                pid: Pid(3),
                nice: 0,
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
                name: "t4".into(),
                pid: Pid(4),
                nice: 0,
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
            .duration_ms(50)
            .build()
    };

    let trace1 = Simulator::new(DynamicScheduler::simple()).run(make_scenario());
    let trace2 = Simulator::new(DynamicScheduler::simple()).run(make_scenario());

    assert_eq!(
        trace1.events().len(),
        trace2.events().len(),
        "batch-concurrent traces have different lengths"
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

// ---------------------------------------------------------------------------
// DSQ contention: 8 tasks on 4 CPUs with short sleep/wake cycles
// ---------------------------------------------------------------------------

#[test]
fn test_batch_concurrent_with_dsq_contention() {
    let _lock = common::setup_test();
    // 8 tasks on 4 CPUs, 2ms run / 1ms sleep: frequent dispatch and shared
    // DSQ contention. This exercises the global DSQ path that scx_simple
    // uses when tasks aren't directly dispatched during select_cpu.
    let mut builder = Scenario::builder().cpus(4).seed(42).interleave(true);

    for i in 1..=8 {
        builder = builder.task(TaskDef {
            name: format!("w{i}"),
            pid: Pid(i),
            nice: 0,
            behavior: TaskBehavior {
                phases: vec![Phase::Run(2_000_000), Phase::Sleep(1_000_000)],
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

    let scenario = builder.duration_ms(50).build();
    let trace = Simulator::new(DynamicScheduler::simple()).run(scenario);
    trace.dump();

    // All 8 tasks must be scheduled
    for pid_val in 1..=8 {
        assert!(
            trace.schedule_count(Pid(pid_val)) > 0,
            "task {pid_val} was never scheduled"
        );
    }
}

// ---------------------------------------------------------------------------
// Batch-concurrent with preemptive interleaving
// ---------------------------------------------------------------------------

#[test]
fn test_batch_concurrent_preemptive_smoke() {
    let _lock = common::setup_test();
    let scenario = Scenario::builder()
        .cpus(4)
        .seed(42)
        .preemptive(PreemptiveConfig::default())
        .task(TaskDef {
            name: "t1".into(),
            pid: Pid(1),
            nice: 0,
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
            nice: 0,
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
            name: "t3".into(),
            pid: Pid(3),
            nice: 0,
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
            name: "t4".into(),
            pid: Pid(4),
            nice: 0,
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
        .duration_ms(50)
        .build();

    let trace = Simulator::new(DynamicScheduler::simple()).run(scenario);
    trace.dump();

    for pid_val in 1..=4 {
        assert!(
            trace.schedule_count(Pid(pid_val)) > 0,
            "task {pid_val} was never scheduled"
        );
    }
}

// ---------------------------------------------------------------------------
// Custom timeslice range
// ---------------------------------------------------------------------------

#[test]
fn test_preemptive_custom_timeslice() {
    let _lock = common::setup_test();
    let scenario = Scenario::builder()
        .cpus(4)
        .preemptive(PreemptiveConfig {
            timeslice_min: 50,
            timeslice_max: 200,
        })
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
        .duration_ms(50)
        .build();

    let trace = Simulator::new(DynamicScheduler::simple()).run(scenario);
    assert!(
        trace.schedule_count(Pid(1)) > 0,
        "task 1 was never scheduled"
    );
    assert!(
        trace.schedule_count(Pid(2)) > 0,
        "task 2 was never scheduled"
    );
}
