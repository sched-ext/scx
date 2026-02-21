//! Criterion benchmarks for the scx_simulator.
//!
//! Measures end-to-end simulation throughput for representative workloads
//! across different schedulers and CPU counts. Run with:
//!
//!     cargo bench -p scx_simulator
//!
//! The `SIM_LOCK` mutex is held for each iteration so benchmarks are
//! compatible with the C scheduler's global state.

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};

use scx_simulator::*;

/// Acquire the simulator lock (C schedulers have global mutable state).
fn lock() -> std::sync::MutexGuard<'static, ()> {
    SIM_LOCK.lock().unwrap()
}

// ---------------------------------------------------------------------------
// Scenario builders
// ---------------------------------------------------------------------------

/// LAVD mixed classification: ping-pong pair + CPU hog on 4 CPUs, 500ms.
///
/// This is the most sophisticated standard test — exercises wake chains,
/// DSQ iteration, vtime ordering, idle CPU selection, and tick preemption.
fn lavd_mixed_scenario() -> Scenario {
    let (ping_b, pong_b) = workloads::ping_pong(Pid(1), Pid(2), 500_000);
    Scenario::builder()
        .cpus(4)
        .seed(42)
        .instant_timing()
        .task(TaskDef {
            name: "ping".into(),
            pid: Pid(1),
            nice: 0,
            behavior: ping_b,
            start_time_ns: 0,
            mm_id: Some(MmId(1)),
            allowed_cpus: None,
            parent_pid: None,
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
        })
        .task(TaskDef {
            name: "pong".into(),
            pid: Pid(2),
            nice: 0,
            behavior: pong_b,
            start_time_ns: 0,
            mm_id: Some(MmId(1)),
            allowed_cpus: None,
            parent_pid: None,
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
        })
        .task(TaskDef {
            name: "cpu_hog".into(),
            pid: Pid(3),
            nice: 0,
            behavior: workloads::cpu_bound(100_000_000),
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: None,
            parent_pid: None,
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
        })
        .duration_ms(500)
        .build()
}

/// Simple contention: N equal-weight CPU-bound tasks on M CPUs, 200ms.
fn contention_scenario(nr_cpus: u32, nr_tasks: i32) -> Scenario {
    let mut builder = Scenario::builder().cpus(nr_cpus).seed(42).instant_timing();

    for i in 1..=nr_tasks {
        builder = builder.task(TaskDef {
            name: format!("t{i}"),
            pid: Pid(i),
            nice: 0,
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

    builder.duration_ms(200).build()
}

/// Sleep/wake workload: tasks with periodic sleep/run cycles.
fn sleep_wake_scenario(nr_cpus: u32) -> Scenario {
    Scenario::builder()
        .cpus(nr_cpus)
        .seed(42)
        .instant_timing()
        .task(TaskDef {
            name: "sleeper1".into(),
            pid: Pid(1),
            nice: 0,
            behavior: workloads::io_bound(200_000, 5_000_000),
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: None,
            parent_pid: None,
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
        })
        .task(TaskDef {
            name: "sleeper2".into(),
            pid: Pid(2),
            nice: 0,
            behavior: workloads::io_bound(500_000, 3_000_000),
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: None,
            parent_pid: None,
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
        })
        .task(TaskDef {
            name: "hog".into(),
            pid: Pid(3),
            nice: 0,
            behavior: workloads::cpu_bound(100_000_000),
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: None,
            parent_pid: None,
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
        })
        .duration_ms(200)
        .build()
}

// ---------------------------------------------------------------------------
// Benchmarks
// ---------------------------------------------------------------------------

fn bench_lavd_mixed(c: &mut Criterion) {
    let _lock = lock();
    c.bench_function("lavd_mixed_4cpu_500ms", |b| {
        b.iter(|| {
            let scenario = lavd_mixed_scenario();
            Simulator::new(DynamicScheduler::lavd(4)).run(scenario);
        });
    });
}

fn bench_simple_contention(c: &mut Criterion) {
    let _lock = lock();
    let mut group = c.benchmark_group("simple_contention");
    for &(cpus, tasks) in &[(1, 4), (2, 4), (4, 8)] {
        group.bench_with_input(
            BenchmarkId::new(format!("{cpus}cpu"), tasks),
            &(cpus, tasks),
            |b, &(cpus, tasks)| {
                b.iter(|| {
                    let scenario = contention_scenario(cpus, tasks);
                    Simulator::new(DynamicScheduler::simple()).run(scenario);
                });
            },
        );
    }
    group.finish();
}

fn bench_lavd_contention(c: &mut Criterion) {
    let _lock = lock();
    let mut group = c.benchmark_group("lavd_contention");
    for &(cpus, tasks) in &[(1, 4), (4, 8)] {
        group.bench_with_input(
            BenchmarkId::new(format!("{cpus}cpu"), tasks),
            &(cpus, tasks),
            |b, &(cpus, tasks)| {
                b.iter(|| {
                    let scenario = contention_scenario(cpus, tasks);
                    Simulator::new(DynamicScheduler::lavd(cpus)).run(scenario);
                });
            },
        );
    }
    group.finish();
}

fn bench_sleep_wake(c: &mut Criterion) {
    let _lock = lock();
    let mut group = c.benchmark_group("sleep_wake");
    for &cpus in &[1, 4] {
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{cpus}cpu")),
            &cpus,
            |b, &cpus| {
                b.iter(|| {
                    let scenario = sleep_wake_scenario(cpus);
                    Simulator::new(DynamicScheduler::simple()).run(scenario);
                });
            },
        );
    }
    group.finish();
}

/// Contention scenario with configurable interleaving mode.
fn interleave_contention_scenario(interleave: bool, preemptive: bool) -> Scenario {
    let mut builder = Scenario::builder()
        .cpus(4)
        .seed(42)
        .instant_timing()
        .interleave(interleave);

    if preemptive {
        builder = builder.preemptive(PreemptiveConfig {
            timeslice_min: 100,
            timeslice_max: 1000,
        });
    }

    for i in 1..=8 {
        builder = builder.task(TaskDef {
            name: format!("t{i}"),
            pid: Pid(i),
            nice: 0,
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

    builder.duration_ms(200).build()
}

/// Sleep/wake scenario with configurable interleaving mode.
fn interleave_sleep_wake_scenario(interleave: bool, preemptive: bool) -> Scenario {
    let mut builder = Scenario::builder()
        .cpus(4)
        .seed(42)
        .instant_timing()
        .interleave(interleave);

    if preemptive {
        builder = builder.preemptive(PreemptiveConfig {
            timeslice_min: 100,
            timeslice_max: 1000,
        });
    }

    builder
        .task(TaskDef {
            name: "sleeper1".into(),
            pid: Pid(1),
            nice: 0,
            behavior: workloads::io_bound(200_000, 5_000_000),
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: None,
            parent_pid: None,
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
        })
        .task(TaskDef {
            name: "sleeper2".into(),
            pid: Pid(2),
            nice: 0,
            behavior: workloads::io_bound(500_000, 3_000_000),
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: None,
            parent_pid: None,
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
        })
        .task(TaskDef {
            name: "hog".into(),
            pid: Pid(3),
            nice: 0,
            behavior: workloads::cpu_bound(100_000_000),
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: None,
            parent_pid: None,
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
        })
        .duration_ms(200)
        .build()
}

fn bench_interleave_overhead(c: &mut Criterion) {
    let _lock = lock();
    let mut group = c.benchmark_group("interleave_overhead");

    // Compare sequential vs cooperative interleaved dispatch.
    // 4 CPUs, 8 tasks — lots of idle-CPU dispatch opportunities.
    for &interleave in &[false, true] {
        let label = if interleave { "on" } else { "off" };
        group.bench_function(BenchmarkId::new("simple_4cpu_8t", label), |b| {
            b.iter(|| {
                let scenario = interleave_contention_scenario(interleave, false);
                Simulator::new(DynamicScheduler::simple()).run(scenario);
            });
        });
    }

    // Sleep/wake with interleaving — frequent idle CPU dispatch.
    for &interleave in &[false, true] {
        let label = if interleave { "on" } else { "off" };
        group.bench_function(BenchmarkId::new("sleep_wake_4cpu", label), |b| {
            b.iter(|| {
                let scenario = interleave_sleep_wake_scenario(interleave, false);
                Simulator::new(DynamicScheduler::simple()).run(scenario);
            });
        });
    }

    group.finish();
}

/// Benchmark preemptive interleaving overhead.
///
/// Compares three modes: sequential (off), cooperative (interleave), and
/// preemptive (PMU timer signals). The preemptive mode adds thread spawning,
/// PMU timer setup, and signal delivery overhead on top of cooperative.
fn bench_preemptive_overhead(c: &mut Criterion) {
    let _lock = lock();
    let mut group = c.benchmark_group("preemptive_overhead");

    let modes: &[(&str, bool, bool)] = &[
        ("off", false, false),
        ("cooperative", true, false),
        ("preemptive", true, true),
    ];

    // CPU-bound contention: 4 CPUs, 8 tasks
    for &(label, interleave, preemptive) in modes {
        group.bench_function(BenchmarkId::new("contention_4cpu_8t", label), |b| {
            b.iter(|| {
                let scenario = interleave_contention_scenario(interleave, preemptive);
                Simulator::new(DynamicScheduler::simple()).run(scenario);
            });
        });
    }

    // Sleep/wake: I/O-bound + hog on 4 CPUs
    for &(label, interleave, preemptive) in modes {
        group.bench_function(BenchmarkId::new("sleep_wake_4cpu", label), |b| {
            b.iter(|| {
                let scenario = interleave_sleep_wake_scenario(interleave, preemptive);
                Simulator::new(DynamicScheduler::simple()).run(scenario);
            });
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_lavd_mixed,
    bench_simple_contention,
    bench_lavd_contention,
    bench_sleep_wake,
    bench_interleave_overhead,
    bench_preemptive_overhead,
);
criterion_main!(benches);
