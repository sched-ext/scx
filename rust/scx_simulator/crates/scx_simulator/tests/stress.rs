//! Stress test scenarios for bug finding.
//!
//! These tests use randomized parameters to explore the scheduler state space
//! and find bugs (stalls, crashes, BPF errors). They are designed to be run
//! repeatedly with different seeds via the `bug_finding/stress.sh` script.
//!
//! Configuration via environment variables:
//! - `STRESS_SEED`: Random seed (default: 42)
//! - `STRESS_SCHEDULER`: Which scheduler to test (lavd, mitosis, simple)
//!
//! Each test:
//! - Uses `.detect_bpf_errors()` to catch scx_bpf_error() calls
//! - Uses `.watchdog_timeout_ns(Some(2_000_000_000))` for 2s watchdog
//! - Uses `.duration_ms(4000)` for 4s simulation
//! - Randomizes task counts, CPU counts, behaviors

use rand::rngs::SmallRng;
use rand::{RngCore, SeedableRng};
use scx_simulator::*;

mod common;

/// Deterministic PRNG wrapper for stress tests.
struct Rng {
    inner: SmallRng,
}

impl Rng {
    fn new(seed: u32) -> Self {
        Self {
            inner: SmallRng::seed_from_u64(seed as u64),
        }
    }

    fn next_u32(&mut self) -> u32 {
        self.inner.next_u32()
    }

    fn range(&mut self, min: u32, max: u32) -> u32 {
        min + (self.next_u32() % (max - min + 1))
    }

    fn range_i8(&mut self, min: i8, max: i8) -> i8 {
        let range = (max - min + 1) as u32;
        (min as i32 + (self.next_u32() % range) as i32) as i8
    }

    fn bool(&mut self) -> bool {
        self.next_u32() % 2 == 0
    }
}

/// Get seed from environment or use default.
fn get_seed() -> u32 {
    std::env::var("STRESS_SEED")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(42)
}

/// Generate a random task behavior.
fn random_behavior(rng: &mut Rng) -> TaskBehavior {
    let pattern = rng.range(0, 4);
    match pattern {
        0 => {
            // CPU-bound: long runs
            let run_ns = rng.range(10_000_000, 100_000_000) as u64;
            workloads::cpu_bound(run_ns)
        }
        1 => {
            // I/O-bound: short runs, long sleeps
            let run_ns = rng.range(100_000, 2_000_000) as u64;
            let sleep_ns = rng.range(5_000_000, 50_000_000) as u64;
            workloads::io_bound(run_ns, sleep_ns)
        }
        2 => {
            // Periodic: run/sleep cycle
            let run_ns = rng.range(1_000_000, 10_000_000) as u64;
            let period_ns = run_ns + rng.range(5_000_000, 20_000_000) as u64;
            workloads::periodic(run_ns, period_ns)
        }
        3 => {
            // Short burst
            let run_ns = rng.range(500_000, 5_000_000) as u64;
            TaskBehavior {
                phases: vec![
                    Phase::Run(run_ns),
                    Phase::Sleep(rng.range(1_000_000, 10_000_000) as u64),
                ],
                repeat: RepeatMode::Forever,
            }
        }
        _ => {
            // Mixed: run, sleep, run
            let run1 = rng.range(1_000_000, 5_000_000) as u64;
            let sleep = rng.range(2_000_000, 10_000_000) as u64;
            let run2 = rng.range(1_000_000, 5_000_000) as u64;
            TaskBehavior {
                phases: vec![Phase::Run(run1), Phase::Sleep(sleep), Phase::Run(run2)],
                repeat: RepeatMode::Forever,
            }
        }
    }
}

/// Build a random stress scenario.
fn random_scenario(rng: &mut Rng, nr_cpus: u32) -> Scenario {
    let nr_tasks = rng.range(2, 16);

    let mut builder = Scenario::builder()
        .cpus(nr_cpus)
        .seed(rng.next_u32())
        .detect_bpf_errors()
        .watchdog_timeout_ns(Some(2_000_000_000)) // 2 second watchdog
        .duration_ms(4000); // 4 second simulation

    for i in 0..nr_tasks {
        let pid = Pid((i + 1) as i32);
        let nice = rng.range_i8(-20, 19);
        let behavior = random_behavior(rng);

        // Random CPU affinity (10% chance)
        let allowed_cpus = if rng.range(0, 9) == 0 && nr_cpus > 1 {
            let cpu = CpuId(rng.range(0, nr_cpus - 1));
            Some(vec![cpu])
        } else {
            None
        };

        // Random mm_id for thread groups (30% chance)
        let mm_id = if rng.range(0, 9) < 3 {
            Some(MmId(rng.range(1, 4)))
        } else {
            None
        };

        builder = builder.task(TaskDef {
            name: format!("t{i}"),
            pid,
            nice,
            behavior,
            start_time_ns: 0,
            mm_id,
            allowed_cpus,
            parent_pid: None,
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
        });
    }

    builder.build()
}

/// Build a ping-pong stress scenario.
fn ping_pong_scenario(rng: &mut Rng, nr_cpus: u32) -> Scenario {
    let nr_pairs = rng.range(1, 4);
    let work_ns = rng.range(100_000, 2_000_000) as u64;

    let mut builder = Scenario::builder()
        .cpus(nr_cpus)
        .seed(rng.next_u32())
        .detect_bpf_errors()
        .watchdog_timeout_ns(Some(2_000_000_000))
        .duration_ms(4000);

    for pair in 0..nr_pairs {
        let pid_a = Pid((pair * 2 + 1) as i32);
        let pid_b = Pid((pair * 2 + 2) as i32);
        let mm_id = MmId(pair + 1);

        let (behavior_a, behavior_b) = workloads::ping_pong(pid_a, pid_b, work_ns);

        builder = builder
            .task(TaskDef {
                name: format!("ping{pair}"),
                pid: pid_a,
                nice: 0,
                behavior: behavior_a,
                start_time_ns: 0,
                mm_id: Some(mm_id),
                allowed_cpus: None,
                parent_pid: None,
                cgroup_name: None,
                task_flags: 0,
                migration_disabled: 0,
            })
            .task(TaskDef {
                name: format!("pong{pair}"),
                pid: pid_b,
                nice: 0,
                behavior: behavior_b,
                start_time_ns: 0,
                mm_id: Some(mm_id),
                allowed_cpus: None,
                parent_pid: None,
                cgroup_name: None,
                task_flags: 0,
                migration_disabled: 0,
            });
    }

    // Add some CPU hogs for contention
    let nr_hogs = rng.range(0, 3);
    for i in 0..nr_hogs {
        let pid = Pid((nr_pairs * 2 + i + 1) as i32);
        builder = builder.task(TaskDef {
            name: format!("hog{i}"),
            pid,
            nice: rng.range_i8(0, 19), // Lower priority
            behavior: workloads::cpu_bound(50_000_000),
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: None,
            parent_pid: None,
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
        });
    }

    builder.build()
}

/// Build a wake-chain stress scenario.
fn wake_chain_scenario(rng: &mut Rng, nr_cpus: u32) -> Scenario {
    let chain_len = rng.range(3, 8);
    let work_ns = rng.range(100_000, 1_000_000) as u64;
    let head_sleep_ns = rng.range(1_000_000, 5_000_000) as u64;

    let pids: Vec<Pid> = (1..=chain_len).map(|i| Pid(i as i32)).collect();
    let behaviors = workloads::wake_chain(&pids, work_ns, head_sleep_ns);

    let mut builder = Scenario::builder()
        .cpus(nr_cpus)
        .seed(rng.next_u32())
        .detect_bpf_errors()
        .watchdog_timeout_ns(Some(2_000_000_000))
        .duration_ms(4000);

    let mm_id = MmId(1);
    for (i, behavior) in behaviors.into_iter().enumerate() {
        builder = builder.task(TaskDef {
            name: format!("chain{i}"),
            pid: pids[i],
            nice: 0,
            behavior,
            start_time_ns: 0,
            mm_id: Some(mm_id),
            allowed_cpus: None,
            parent_pid: None,
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
        });
    }

    // Add background load
    let nr_bg = rng.range(1, 4);
    for i in 0..nr_bg {
        let pid = Pid((chain_len + i + 1) as i32);
        builder = builder.task(TaskDef {
            name: format!("bg{i}"),
            pid,
            nice: rng.range_i8(5, 19),
            behavior: random_behavior(rng),
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: None,
            parent_pid: None,
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
        });
    }

    builder.build()
}

/// Build a high-contention scenario with many tasks on few CPUs.
fn contention_scenario(rng: &mut Rng, nr_cpus: u32) -> Scenario {
    // More tasks than CPUs
    let nr_tasks = nr_cpus * rng.range(2, 5);

    let mut builder = Scenario::builder()
        .cpus(nr_cpus)
        .seed(rng.next_u32())
        .detect_bpf_errors()
        .watchdog_timeout_ns(Some(2_000_000_000))
        .duration_ms(4000);

    for i in 0..nr_tasks {
        let pid = Pid((i + 1) as i32);
        let nice = rng.range_i8(-10, 10);

        // Mix of short and long runners
        let behavior = if rng.bool() {
            workloads::cpu_bound(rng.range(5_000_000, 20_000_000) as u64)
        } else {
            workloads::io_bound(
                rng.range(200_000, 2_000_000) as u64,
                rng.range(1_000_000, 5_000_000) as u64,
            )
        };

        builder = builder.task(TaskDef {
            name: format!("t{i}"),
            pid,
            nice,
            behavior,
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: None,
            parent_pid: None,
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
        });
    }

    builder.build()
}

// ---------------------------------------------------------------------------
// LAVD stress tests
// ---------------------------------------------------------------------------

/// Stress test for LAVD scheduler with random scenarios.
///
/// This test is ignored by default - run with `cargo test -- --ignored` or
/// via `./bug_finding/stress.sh`.
#[test]
#[ignore]
fn stress_random_lavd() {
    let _lock = common::setup_test();
    let seed = get_seed();
    let mut rng = Rng::new(seed);

    // Random CPU count: 1-8
    let nr_cpus = rng.range(1, 8);

    // Pick random scenario type
    let scenario_type = rng.range(0, 3);
    let scenario = match scenario_type {
        0 => random_scenario(&mut rng, nr_cpus),
        1 => ping_pong_scenario(&mut rng, nr_cpus),
        2 => wake_chain_scenario(&mut rng, nr_cpus),
        _ => contention_scenario(&mut rng, nr_cpus),
    };

    eprintln!(
        "LAVD stress test: seed={}, cpus={}, tasks={}, scenario_type={}",
        seed,
        nr_cpus,
        scenario.tasks.len(),
        scenario_type
    );

    let sched = DynamicScheduler::lavd(nr_cpus);
    let trace = Simulator::new(sched).run(scenario);

    if trace.has_error() {
        eprintln!("FOUND: seed={}, exit={:?}", seed, trace.exit_kind());
        trace.dump();
    }

    assert!(
        !trace.has_error(),
        "LAVD stress test failed: seed={}, exit={:?}",
        seed,
        trace.exit_kind()
    );
}

// ---------------------------------------------------------------------------
// Mitosis stress tests
// ---------------------------------------------------------------------------

/// Stress test for Mitosis scheduler with random scenarios.
///
/// This test is ignored by default - run with `cargo test -- --ignored` or
/// via `./bug_finding/stress.sh`.
#[test]
#[ignore]
fn stress_random_mitosis() {
    let _lock = common::setup_test();
    let seed = get_seed();
    let mut rng = Rng::new(seed);

    let nr_cpus = rng.range(1, 8);

    let scenario_type = rng.range(0, 3);
    let scenario = match scenario_type {
        0 => random_scenario(&mut rng, nr_cpus),
        1 => ping_pong_scenario(&mut rng, nr_cpus),
        2 => wake_chain_scenario(&mut rng, nr_cpus),
        _ => contention_scenario(&mut rng, nr_cpus),
    };

    eprintln!(
        "Mitosis stress test: seed={}, cpus={}, tasks={}, scenario_type={}",
        seed,
        nr_cpus,
        scenario.tasks.len(),
        scenario_type
    );

    let sched = DynamicScheduler::mitosis(nr_cpus);
    let trace = Simulator::new(sched).run(scenario);

    if trace.has_error() {
        eprintln!("FOUND: seed={}, exit={:?}", seed, trace.exit_kind());
        trace.dump();
    }

    assert!(
        !trace.has_error(),
        "Mitosis stress test failed: seed={}, exit={:?}",
        seed,
        trace.exit_kind()
    );
}

// ---------------------------------------------------------------------------
// Simple scheduler stress tests
// ---------------------------------------------------------------------------

/// Stress test for Simple scheduler with random scenarios.
///
/// This test is ignored by default - run with `cargo test -- --ignored` or
/// via `./bug_finding/stress.sh`.
#[test]
#[ignore]
fn stress_random_simple() {
    let _lock = common::setup_test();
    let seed = get_seed();
    let mut rng = Rng::new(seed);

    let nr_cpus = rng.range(1, 8);

    let scenario_type = rng.range(0, 3);
    let scenario = match scenario_type {
        0 => random_scenario(&mut rng, nr_cpus),
        1 => ping_pong_scenario(&mut rng, nr_cpus),
        2 => wake_chain_scenario(&mut rng, nr_cpus),
        _ => contention_scenario(&mut rng, nr_cpus),
    };

    eprintln!(
        "Simple stress test: seed={}, cpus={}, tasks={}, scenario_type={}",
        seed,
        nr_cpus,
        scenario.tasks.len(),
        scenario_type
    );

    let sched = DynamicScheduler::simple();
    let trace = Simulator::new(sched).run(scenario);

    if trace.has_error() {
        eprintln!("FOUND: seed={}, exit={:?}", seed, trace.exit_kind());
        trace.dump();
    }

    assert!(
        !trace.has_error(),
        "Simple stress test failed: seed={}, exit={:?}",
        seed,
        trace.exit_kind()
    );
}

// ---------------------------------------------------------------------------
// Determinism validation
// ---------------------------------------------------------------------------

/// Verify that stress tests are deterministic: same seed gives same result.
#[test]
fn stress_determinism_check() {
    let _lock = common::setup_test();
    let seed = 12345u32;

    // Run twice with same seed
    let mut rng1 = Rng::new(seed);
    let scenario1 = random_scenario(&mut rng1, 4);

    let mut rng2 = Rng::new(seed);
    let scenario2 = random_scenario(&mut rng2, 4);

    // Scenarios should be identical
    assert_eq!(scenario1.tasks.len(), scenario2.tasks.len());
    for (t1, t2) in scenario1.tasks.iter().zip(scenario2.tasks.iter()) {
        assert_eq!(t1.pid, t2.pid);
        assert_eq!(t1.nice, t2.nice);
    }

    // Run both
    let trace1 = Simulator::new(DynamicScheduler::simple()).run(scenario1);
    let trace2 = Simulator::new(DynamicScheduler::simple()).run(scenario2);

    assert_eq!(
        trace1.events().len(),
        trace2.events().len(),
        "determinism check failed: different event counts"
    );
}

// ---------------------------------------------------------------------------
// Cgroup lifecycle stress tests
// ---------------------------------------------------------------------------

/// Test cgroup creation at runtime.
#[test]
fn stress_cgroup_create_runtime() {
    let _lock = common::setup_test();

    // Create initial scenario with a simple task
    let scenario = Scenario::builder()
        .cpus(2)
        .seed(42)
        .add_task(
            "worker",
            0,
            TaskBehavior {
                phases: vec![Phase::Run(1_000_000), Phase::Sleep(1_000_000)],
                repeat: RepeatMode::Forever,
            },
        )
        // Create cgroups at runtime
        .cgroup_create_at("cg1", None, None, 10_000_000)
        .cgroup_create_at("cg2", None, None, 20_000_000)
        .cgroup_create_at("cg3", None, None, 30_000_000)
        // Destroy one
        .cgroup_destroy_at("cg2", 40_000_000)
        // Create another
        .cgroup_create_at("cg4", None, None, 50_000_000)
        .duration_ms(100)
        .build();

    let sched = DynamicScheduler::lavd(2);
    let trace = Simulator::new(sched).run(scenario);

    assert!(
        !trace.has_error(),
        "cgroup create test failed: exit={:?}",
        trace.exit_kind()
    );
}

/// Test cgroup exhaustion with a low limit.
#[test]
fn stress_cgroup_exhaustion_lavd() {
    let _lock = common::setup_test();

    // Configure a low cgroup limit to trigger exhaustion
    let max_cgroups = 5; // Root + 4 cgroups = exhaustion at 5th create

    let mut builder = Scenario::builder()
        .cpus(2)
        .seed(42)
        .max_cgroups(max_cgroups)
        .add_task(
            "worker",
            0,
            TaskBehavior {
                phases: vec![Phase::Run(1_000_000), Phase::Sleep(1_000_000)],
                repeat: RepeatMode::Forever,
            },
        )
        .duration_ms(500);

    // Schedule creation of more cgroups than the limit allows
    // Root counts as 1, so we can create max_cgroups - 1 more
    for i in 0..10 {
        let at_ns = (i + 1) * 10_000_000;
        builder = builder.cgroup_create_at(&format!("cg{i}"), None, None, at_ns);
    }

    let scenario = builder.build();

    let sched = DynamicScheduler::lavd(2);
    let trace = Simulator::new(sched).run(scenario);

    // Should have hit the cgroup limit
    match trace.exit_kind() {
        ExitKind::ErrorCgroupExhausted {
            cgroup_name,
            active_count,
            max_cgroups: max,
        } => {
            eprintln!(
                "Got expected cgroup exhaustion: name={}, active={}, max={}",
                cgroup_name, active_count, max
            );
            assert_eq!(*max, max_cgroups);
        }
        other => {
            panic!("Expected ErrorCgroupExhausted but got {:?}", other);
        }
    }
}

/// Test rapid cgroup create/destroy cycles.
#[test]
fn stress_cgroup_rapid_lifecycle() {
    let _lock = common::setup_test();

    let mut builder = Scenario::builder()
        .cpus(4)
        .seed(12345)
        .max_cgroups(20)
        .detect_bpf_errors()
        .watchdog_timeout_ns(Some(2_000_000_000))
        .add_task(
            "worker",
            0,
            TaskBehavior {
                phases: vec![Phase::Run(500_000), Phase::Sleep(500_000)],
                repeat: RepeatMode::Forever,
            },
        )
        .duration_ms(200);

    // Create and destroy cgroups in rapid succession
    // This stays under the limit because we destroy before creating new ones
    let interval_ns = 1_000_000; // 1ms between operations
    for cycle in 0..10 {
        let base = cycle * 10_000_000;
        // Create 5 cgroups
        for i in 0..5 {
            let name = format!("cycle{}_{}", cycle, i);
            builder = builder.cgroup_create_at(&name, None, None, base + i * interval_ns);
        }
        // Destroy them
        for i in 0..5 {
            let name = format!("cycle{}_{}", cycle, i);
            builder = builder.cgroup_destroy_at(&name, base + 5_000_000 + i * interval_ns);
        }
    }

    let scenario = builder.build();

    let sched = DynamicScheduler::lavd(4);
    let trace = Simulator::new(sched).run(scenario);

    // Should complete without hitting the limit
    assert!(
        !trace.has_error(),
        "rapid cgroup lifecycle test failed: exit={:?}",
        trace.exit_kind()
    );
}

/// Test cgroup lifecycle with simple scheduler (basic functionality).
#[test]
fn stress_cgroup_lifecycle_simple() {
    let _lock = common::setup_test();

    let scenario = Scenario::builder()
        .cpus(2)
        .seed(42)
        .add_task(
            "worker",
            0,
            TaskBehavior {
                phases: vec![Phase::Run(2_000_000)],
                repeat: RepeatMode::Forever,
            },
        )
        .cgroup_create_at("test_cg", None, None, 5_000_000)
        .cgroup_destroy_at("test_cg", 50_000_000)
        .duration_ms(100)
        .build();

    let sched = DynamicScheduler::simple();
    let trace = Simulator::new(sched).run(scenario);

    assert!(
        !trace.has_error(),
        "simple scheduler cgroup lifecycle failed: exit={:?}",
        trace.exit_kind()
    );
}

/// Test cgroup_bw tracking in LAVD wrapper.
#[test]
fn stress_cgroup_bw_tracking() {
    let _lock = common::setup_test();

    // Build a simple scenario
    let scenario = Scenario::builder()
        .cpus(2)
        .seed(42)
        .add_task(
            "worker",
            0,
            TaskBehavior {
                phases: vec![Phase::Run(1_000_000)],
                repeat: RepeatMode::Forever,
            },
        )
        // Create several cgroups
        .cgroup("cg1", &[CpuId(0), CpuId(1)])
        .cgroup("cg2", &[CpuId(0), CpuId(1)])
        .cgroup("cg3", &[CpuId(0), CpuId(1)])
        .duration_ms(50)
        .build();

    let sched = DynamicScheduler::lavd(2);

    // Set a cgroup_bw limit higher than our cgroup count
    sched.lavd_set_cgroup_bw_max(10);

    let trace = Simulator::new(sched).run(scenario);

    assert!(
        !trace.has_error(),
        "cgroup_bw tracking test failed: exit={:?}",
        trace.exit_kind()
    );
}
