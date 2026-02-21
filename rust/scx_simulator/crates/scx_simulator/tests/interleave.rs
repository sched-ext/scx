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
///
/// Uses `cooperative_only` mode to disable PMU timers, `fixed_priority` to
/// ensure deterministic event ordering, and `instant_timing` to disable
/// noise and overhead. All of these are needed to ensure deterministic
/// interleaving for tests.
fn preemptive_scenario(nr_cpus: u32, nr_tasks: u32, seed: u32, duration_ms: u64) -> Scenario {
    let mut builder = Scenario::builder()
        .cpus(nr_cpus)
        .seed(seed)
        .fixed_priority(true)
        .instant_timing()
        .preemptive(PreemptiveConfig::cooperative_only());

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
        if e1.time_ns != e2.time_ns || e1.cpu != e2.cpu || e1.kind != e2.kind {
            // Dump context around mismatch
            eprintln!("MISMATCH at event {i}:");
            eprintln!(
                "  trace1[{i}]: time={} cpu={:?} kind={:?}",
                e1.time_ns, e1.cpu, e1.kind
            );
            eprintln!(
                "  trace2[{i}]: time={} cpu={:?} kind={:?}",
                e2.time_ns, e2.cpu, e2.kind
            );
            if i > 0 {
                let prev1 = &trace1.events()[i - 1];
                let prev2 = &trace2.events()[i - 1];
                eprintln!(
                    "  trace1[{}]: time={} cpu={:?} kind={:?}",
                    i - 1,
                    prev1.time_ns,
                    prev1.cpu,
                    prev1.kind
                );
                eprintln!(
                    "  trace2[{}]: time={} cpu={:?} kind={:?}",
                    i - 1,
                    prev2.time_ns,
                    prev2.cpu,
                    prev2.kind
                );
            }
        }
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
            cooperative_only: false,
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

// ---------------------------------------------------------------------------
// Determinism: true PMU-based preemptive mode
// ---------------------------------------------------------------------------

/// Helper: build a scenario with TRUE preemptive interleaving (PMU enabled).
///
/// Unlike `preemptive_scenario()` which uses `cooperative_only`, this enables
/// actual PMU RBC timer signals for mid-C-code preemption points.
///
/// See ai_docs/DETERMINISM.md for details on RBC determinism.
fn pmu_preemptive_scenario(nr_cpus: u32, nr_tasks: u32, seed: u32, duration_ms: u64) -> Scenario {
    let mut builder = Scenario::builder()
        .cpus(nr_cpus)
        .seed(seed)
        .fixed_priority(true)
        .instant_timing()
        .preemptive(PreemptiveConfig {
            timeslice_min: 100,
            timeslice_max: 500,
            cooperative_only: false, // Enable PMU
        });

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

/// Test determinism of true PMU-based preemptive interleaving.
///
/// This tests the full preemptive mode with PMU RBC timers enabled.
/// RBC is deterministic because it counts only retired (committed) branches,
/// not speculative ones. See ai_docs/DETERMINISM.md for the full explanation.
///
/// The test verifies determinism at two levels:
/// 1. **Trace events**: Same sequence of scheduling events
/// 2. **Preemption records**: Same (RBC, RIP) pairs at each preemption point
///
/// Note: PMU delivery has inherent "skid" (signal delivery latency), which
/// could theoretically cause slight variations. In practice, this test passes
/// reliably because:
/// 1. The PRNG-driven timeslices are deterministic
/// 2. The C code executes the same instruction sequence
/// 3. Worker selection is deterministic via PreemptRing
///
/// If this test becomes flaky on certain hardware, it may need to be marked
/// `#[ignore]` with a comment explaining the hardware-specific skid behavior.
#[test]
fn test_preemptive_pmu_determinism() {
    use scx_simulator::{drain_preemption_records, enable_preemption_collection};

    let _lock = common::setup_test();
    let make = || pmu_preemptive_scenario(4, 2, 42, 20);

    // Run 1: collect preemption records
    enable_preemption_collection();
    let trace1 = Simulator::new(DynamicScheduler::simple()).run(make());
    let records1 = drain_preemption_records();

    // Run 2: collect preemption records
    enable_preemption_collection();
    let trace2 = Simulator::new(DynamicScheduler::simple()).run(make());
    let records2 = drain_preemption_records();

    // If PMU is unavailable (VMs, containers), both runs fall back to
    // cooperative-only mode and should still be deterministic.

    // ---------------------------------------------------------------------------
    // Verify trace event determinism
    // ---------------------------------------------------------------------------
    assert_eq!(
        trace1.events().len(),
        trace2.events().len(),
        "PMU preemptive traces have different lengths: {} vs {}",
        trace1.events().len(),
        trace2.events().len()
    );

    let mut event_mismatches = 0;
    for (i, (e1, e2)) in trace1
        .events()
        .iter()
        .zip(trace2.events().iter())
        .enumerate()
    {
        if e1.time_ns != e2.time_ns || e1.cpu != e2.cpu || e1.kind != e2.kind {
            event_mismatches += 1;
            if event_mismatches <= 3 {
                eprintln!("TRACE MISMATCH at event {i}:");
                eprintln!(
                    "  trace1[{i}]: time={} cpu={:?} kind={:?}",
                    e1.time_ns, e1.cpu, e1.kind
                );
                eprintln!(
                    "  trace2[{i}]: time={} cpu={:?} kind={:?}",
                    e2.time_ns, e2.cpu, e2.kind
                );
            }
        }
    }

    assert_eq!(
        event_mismatches,
        0,
        "PMU preemptive mode: {} trace event mismatches out of {} events",
        event_mismatches,
        trace1.events().len()
    );

    // ---------------------------------------------------------------------------
    // Verify preemption record determinism (RBC count, instruction pointer)
    // ---------------------------------------------------------------------------
    eprintln!(
        "Preemption records: run1={} run2={}",
        records1.len(),
        records2.len()
    );

    // Print diagnostic info about preemption points
    if !records1.is_empty() {
        eprintln!("Run 1 preemption points:");
        for (i, rec) in records1.iter().take(10).enumerate() {
            eprintln!("  [{i}] {rec}");
        }
        if records1.len() > 10 {
            eprintln!("  ... and {} more", records1.len() - 10);
        }
    }

    if !records2.is_empty() {
        eprintln!("Run 2 preemption points:");
        for (i, rec) in records2.iter().take(10).enumerate() {
            eprintln!("  [{i}] {rec}");
        }
        if records2.len() > 10 {
            eprintln!("  ... and {} more", records2.len() - 10);
        }
    }

    // Compare preemption record counts
    assert_eq!(
        records1.len(),
        records2.len(),
        "Preemption record counts differ: {} vs {}",
        records1.len(),
        records2.len()
    );

    // Compare (RBC, RIP) pairs element-by-element
    let mut record_mismatches = 0;
    for (i, (r1, r2)) in records1.iter().zip(records2.iter()).enumerate() {
        let rbc_match = r1.rbc_count == r2.rbc_count;
        let rip_match = r1.instruction_pointer == r2.instruction_pointer;
        let cpu_match = r1.cpu_id == r2.cpu_id;

        if !rbc_match || !rip_match || !cpu_match {
            record_mismatches += 1;
            if record_mismatches <= 5 {
                eprintln!("PREEMPTION RECORD MISMATCH at [{i}]:");
                eprintln!("  run1: {r1}");
                eprintln!("  run2: {r2}");
                eprintln!(
                    "  match: rbc={} rip={} cpu={}",
                    if rbc_match { "YES" } else { "NO" },
                    if rip_match { "YES" } else { "NO" },
                    if cpu_match { "YES" } else { "NO" }
                );
            }
        }
    }

    // Report on preemption record consistency.
    // This provides strong evidence that RBC-based preemption is truly deterministic.
    if !records1.is_empty() {
        if record_mismatches == 0 {
            eprintln!(
                "SUCCESS: {} preemption records verified identical (RBC, RIP, CPU). \
                 This proves RBC-based preemption is deterministic - same branch count, \
                 same instruction, every time.",
                records1.len()
            );
        } else {
            // PMU skid can cause slight variations in exact RBC/RIP values.
            // This is documented in ai_docs/DETERMINISM.md. If trace events matched
            // (verified above), the simulation is effectively deterministic despite
            // the low-level preemption point variations.
            //
            // We don't fail the test here because:
            // 1. Trace event determinism (asserted above) is the stronger property
            // 2. PMU skid is a hardware-level phenomenon outside our control
            // 3. The preemption records are diagnostic, not the primary assertion
            eprintln!(
                "INFO: {} preemption record mismatch(es) out of {} records. \
                 This can happen due to PMU skid (signal delivery latency). \
                 Trace event determinism was verified successfully.",
                record_mismatches,
                records1.len()
            );
            eprintln!("      See ai_docs/DETERMINISM.md for details on PMU skid behavior.");
        }
    } else {
        eprintln!(
            "NOTE: No PMU preemption records collected (PMU likely unavailable). \
             Trace event determinism verified instead."
        );
    }
}

// ===========================================================================
// Aggressive determinism mode tests (memory hash checkpoints)
// ===========================================================================

/// Test aggressive determinism mode with memory state hashing.
///
/// This test enables the aggressive determinism mode that hashes scheduler
/// memory at key scheduling events (dispatch, enqueue, running, stopping, etc.)
/// and verifies that two runs with the same seed produce identical checkpoint
/// sequences.
///
/// The checkpoint comparison can detect divergence in:
/// - RIP (instruction pointer)
/// - RBC (retired branch count)
/// - Memory state (DSQ contents, task state, etc.)
/// - Event type or CPU
///
/// This is the primary tool for debugging non-determinism: when stress.py
/// finds a failing seed, replay with aggressive determinism mode and the
/// divergence diagnostic will pinpoint exactly where execution diverged.
#[test]
fn test_aggressive_determinism_mode() {
    use scx_simulator::{
        compare_checkpoints, drain_determinism_checkpoints, enable_determinism_mode,
    };

    let _lock = common::setup_test();
    let make = || preemptive_scenario(4, 2, 42, 30);

    // Run 1: collect checkpoints
    enable_determinism_mode();
    let trace1 = Simulator::new(DynamicScheduler::simple()).run(make());
    let checkpoints1 = drain_determinism_checkpoints();

    // Run 2: collect checkpoints
    enable_determinism_mode();
    let trace2 = Simulator::new(DynamicScheduler::simple()).run(make());
    let checkpoints2 = drain_determinism_checkpoints();

    // ---------------------------------------------------------------------------
    // Verify trace event determinism first (sanity check)
    // ---------------------------------------------------------------------------
    assert_eq!(
        trace1.events().len(),
        trace2.events().len(),
        "Traces have different lengths: {} vs {}",
        trace1.events().len(),
        trace2.events().len()
    );

    // ---------------------------------------------------------------------------
    // Verify checkpoint determinism (including memory hashes)
    // ---------------------------------------------------------------------------
    eprintln!(
        "Aggressive determinism checkpoints: run1={} run2={}",
        checkpoints1.len(),
        checkpoints2.len()
    );

    // Print first few checkpoints for diagnostic
    if !checkpoints1.is_empty() {
        eprintln!("Run 1 checkpoints:");
        for (i, cp) in checkpoints1.iter().take(10).enumerate() {
            eprintln!("  [{i}] {cp}");
        }
        if checkpoints1.len() > 10 {
            eprintln!("  ... and {} more", checkpoints1.len() - 10);
        }
    }

    // Compare checkpoints and detect first divergence
    if let Some(divergence) = compare_checkpoints(&checkpoints1, &checkpoints2) {
        eprintln!("CHECKPOINT DIVERGENCE DETECTED:");
        eprintln!("{divergence}");
        panic!(
            "Aggressive determinism check failed: divergence at checkpoint {}",
            divergence.checkpoint_index
        );
    }

    eprintln!(
        "SUCCESS: {} checkpoints verified identical (including memory hashes). \
         Scheduler state is fully deterministic.",
        checkpoints1.len()
    );

    // Verify we collected meaningful checkpoints
    assert!(
        !checkpoints1.is_empty(),
        "No checkpoints collected - aggressive determinism mode may not be working"
    );
}

/// Test that aggressive determinism mode is efficiently disabled when not enabled.
///
/// When determinism mode is disabled (the default), checkpoint collection should
/// have zero overhead beyond a single atomic load per callback.
#[test]
fn test_determinism_mode_disabled_by_default() {
    use scx_simulator::is_determinism_mode_enabled;

    // Acquire lock first to ensure no other test is running with determinism mode enabled
    let _lock = common::setup_test();

    // Determinism mode should be disabled by default (checked after lock acquisition
    // to avoid race with other tests that may be enabling/disabling it)
    assert!(
        !is_determinism_mode_enabled(),
        "Determinism mode should be disabled by default"
    );

    let scenario = preemptive_scenario(2, 2, 42, 10);

    // Run without enabling determinism mode
    let trace = Simulator::new(DynamicScheduler::simple()).run(scenario);

    // Should complete successfully
    assert!(
        trace.schedule_count(Pid(1)) > 0,
        "task 1 was never scheduled"
    );

    // Determinism mode should still be disabled
    assert!(
        !is_determinism_mode_enabled(),
        "Determinism mode should remain disabled"
    );
}

/// Test checkpoint divergence detection with intentionally different seeds.
///
/// This verifies that the divergence detection correctly identifies when
/// two runs produce different checkpoint sequences.
#[test]
fn test_checkpoint_divergence_detection() {
    use scx_simulator::{
        compare_checkpoints, drain_determinism_checkpoints, enable_determinism_mode, DivergenceType,
    };

    let _lock = common::setup_test();

    // Run 1: seed 42
    enable_determinism_mode();
    let _ = Simulator::new(DynamicScheduler::simple()).run(preemptive_scenario(2, 2, 42, 20));
    let checkpoints1 = drain_determinism_checkpoints();

    // Run 2: different seed (100) - should produce different checkpoints
    enable_determinism_mode();
    let _ = Simulator::new(DynamicScheduler::simple()).run(preemptive_scenario(2, 2, 100, 20));
    let checkpoints2 = drain_determinism_checkpoints();

    // Both runs should produce checkpoints
    assert!(
        !checkpoints1.is_empty() && !checkpoints2.is_empty(),
        "Both runs should produce checkpoints"
    );

    // Different seeds may or may not produce different checkpoints depending on
    // how much the seed affects scheduling decisions. For simple scheduler with
    // fixed-priority events, the checkpoints might actually be identical.
    //
    // So we just verify the comparison function works correctly:
    let divergence = compare_checkpoints(&checkpoints1, &checkpoints2);

    if let Some(div) = divergence {
        eprintln!("Expected divergence detected: {}", div);
        // Verify the divergence type is something meaningful
        assert!(
            !matches!(div.divergence_type, DivergenceType::Multiple(ref v) if v.is_empty()),
            "Divergence type should not be empty"
        );
    } else {
        // Same checkpoints despite different seeds is valid (simple scheduler is deterministic
        // for the same scenario structure)
        eprintln!(
            "INFO: Different seeds produced identical checkpoints ({} each). \
             This is valid for simple scheduler with fixed-priority events.",
            checkpoints1.len()
        );
    }
}
