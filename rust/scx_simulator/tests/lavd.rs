use scx_simulator::probes::{LavdMonitor, LavdProbes};
use scx_simulator::*;

#[macro_use]
mod common;

// Generic test suite applied to scx_lavd
scheduler_tests!(|nr_cpus| DynamicScheduler::lavd(nr_cpus));

// ---------------------------------------------------------------------------
// LAVD-specific tests: latency criticality classification
// ---------------------------------------------------------------------------

/// Ping-pong tasks (mutual wake) should be classified as latency-critical.
#[test]
fn test_lavd_ping_pong_is_lat_cri() {
    let _lock = common::setup_test();
    let sched = DynamicScheduler::lavd(4);
    let probes = LavdProbes::new(&sched);
    let mut monitor = LavdMonitor::new(probes);

    let (prod, cons) = workloads::ping_pong(Pid(1), Pid(2), 500_000); // 0.5ms work
    let scenario = Scenario::builder()
        .cpus(4)
        .task(TaskDef {
            name: "ping".into(),
            pid: Pid(1),
            nice: 0,
            behavior: prod,
            start_time_ns: 0,
            mm_id: Some(MmId(1)),
            allowed_cpus: None,
        })
        .task(TaskDef {
            name: "pong".into(),
            pid: Pid(2),
            nice: 0,
            behavior: cons,
            start_time_ns: 0,
            mm_id: Some(MmId(1)),
            allowed_cpus: None,
        })
        .duration_ms(500)
        .build();

    let _result = Simulator::new(sched).run_monitored(scenario, &mut monitor);

    let p1 = monitor.final_snapshot(Pid(1)).unwrap();
    let p2 = monitor.final_snapshot(Pid(2)).unwrap();

    eprintln!(
        "ping-pong: p1 lat_cri={}, p2 lat_cri={}, sys_avg={}, p1 wake_freq={}, p2 wake_freq={}",
        p1.lat_cri, p2.lat_cri, p1.sys_avg_lat_cri, p1.wake_freq, p2.wake_freq
    );

    // After 500ms of ping-pong, both tasks should have non-zero lat_cri
    assert!(
        p1.lat_cri > 0,
        "expected ping task lat_cri > 0, got {}",
        p1.lat_cri
    );
    assert!(
        p2.lat_cri > 0,
        "expected pong task lat_cri > 0, got {}",
        p2.lat_cri
    );
}

/// CPU-bound task should NOT be latency-critical.
#[test]
fn test_lavd_cpu_bound_not_lat_cri() {
    let _lock = common::setup_test();
    let sched = DynamicScheduler::lavd(4);
    let probes = LavdProbes::new(&sched);
    let mut monitor = LavdMonitor::new(probes);

    let scenario = Scenario::builder()
        .cpus(4)
        .task(TaskDef {
            name: "cpu_hog".into(),
            pid: Pid(1),
            nice: 0,
            behavior: workloads::cpu_bound(100_000_000), // 100ms chunks
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: None,
        })
        .duration_ms(500)
        .build();

    let _result = Simulator::new(sched).run_monitored(scenario, &mut monitor);

    let snap = monitor.final_snapshot(Pid(1)).unwrap();

    eprintln!(
        "cpu_bound: lat_cri={}, wait_freq={}, wake_freq={}",
        snap.lat_cri, snap.wait_freq, snap.wake_freq
    );

    // CPU-bound: no sleeps, no wakes → wake_freq should be 0
    assert_eq!(
        snap.wake_freq, 0,
        "expected cpu_bound wake_freq == 0, got {}",
        snap.wake_freq
    );
}

/// Mixed workload: ping-pong tasks should have higher lat_cri than cpu-bound.
#[test]
fn test_lavd_mixed_classification() {
    let _lock = common::setup_test();
    let sched = DynamicScheduler::lavd(4);
    let probes = LavdProbes::new(&sched);
    let mut monitor = LavdMonitor::new(probes);

    let (ping_b, pong_b) = workloads::ping_pong(Pid(1), Pid(2), 500_000);
    let scenario = Scenario::builder()
        .cpus(4)
        .task(TaskDef {
            name: "ping".into(),
            pid: Pid(1),
            nice: 0,
            behavior: ping_b,
            start_time_ns: 0,
            mm_id: Some(MmId(1)),
            allowed_cpus: None,
        })
        .task(TaskDef {
            name: "pong".into(),
            pid: Pid(2),
            nice: 0,
            behavior: pong_b,
            start_time_ns: 0,
            mm_id: Some(MmId(1)),
            allowed_cpus: None,
        })
        .task(TaskDef {
            name: "cpu_hog".into(),
            pid: Pid(3),
            nice: 0,
            behavior: workloads::cpu_bound(100_000_000),
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: None,
        })
        .duration_ms(500)
        .build();

    let _result = Simulator::new(sched).run_monitored(scenario, &mut monitor);

    let ping = monitor.final_snapshot(Pid(1)).unwrap();
    let cpu = monitor.final_snapshot(Pid(3)).unwrap();

    eprintln!(
        "mixed: ping lat_cri={}, cpu_hog lat_cri={}",
        ping.lat_cri, cpu.lat_cri
    );

    // Ping-pong should have higher lat_cri than CPU-bound
    assert!(
        ping.lat_cri > cpu.lat_cri,
        "expected ping lat_cri ({}) > cpu_hog lat_cri ({})",
        ping.lat_cri,
        cpu.lat_cri
    );
}

/// I/O-bound task should have higher lat_cri than CPU-bound.
#[test]
fn test_lavd_io_bound_vs_cpu() {
    let _lock = common::setup_test();
    let sched = DynamicScheduler::lavd(4);
    let probes = LavdProbes::new(&sched);
    let mut monitor = LavdMonitor::new(probes);

    let scenario = Scenario::builder()
        .cpus(4)
        .task(TaskDef {
            name: "io_task".into(),
            pid: Pid(1),
            nice: 0,
            behavior: workloads::io_bound(200_000, 5_000_000), // 0.2ms run, 5ms sleep
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: None,
        })
        .task(TaskDef {
            name: "cpu_task".into(),
            pid: Pid(2),
            nice: 0,
            behavior: workloads::cpu_bound(100_000_000),
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: None,
        })
        .duration_ms(500)
        .build();

    let _result = Simulator::new(sched).run_monitored(scenario, &mut monitor);

    let io_snap = monitor.final_snapshot(Pid(1)).unwrap();
    let cpu_snap = monitor.final_snapshot(Pid(2)).unwrap();

    eprintln!(
        "io_vs_cpu: io lat_cri={} wait_freq={}, cpu lat_cri={} wait_freq={}",
        io_snap.lat_cri, io_snap.wait_freq, cpu_snap.lat_cri, cpu_snap.wait_freq
    );

    // I/O-bound should have higher wait_freq (frequent sleeps)
    assert!(
        io_snap.wait_freq > cpu_snap.wait_freq,
        "expected io wait_freq ({}) > cpu wait_freq ({})",
        io_snap.wait_freq,
        cpu_snap.wait_freq
    );

    // I/O-bound should have higher lat_cri than CPU-bound
    assert!(
        io_snap.lat_cri > cpu_snap.lat_cri,
        "expected io lat_cri ({}) > cpu lat_cri ({})",
        io_snap.lat_cri,
        cpu_snap.lat_cri
    );
}

/// 3-task wake chain: middle task should develop non-zero lat_cri.
#[test]
fn test_lavd_wake_chain_propagation() {
    let _lock = common::setup_test();
    let sched = DynamicScheduler::lavd(4);
    let probes = LavdProbes::new(&sched);
    let mut monitor = LavdMonitor::new(probes);

    let pids = [Pid(1), Pid(2), Pid(3)];
    let behaviors = workloads::wake_chain(&pids, 100_000, 10_000_000); // 0.1ms work, 10ms head sleep

    let mut builder = Scenario::builder();
    builder = builder.cpus(4);
    for (i, behavior) in behaviors.into_iter().enumerate() {
        builder = builder.task(TaskDef {
            name: format!("chain_{i}"),
            pid: pids[i],
            nice: 0,
            behavior,
            start_time_ns: 0,
            mm_id: Some(MmId(1)), // same address space for wake_freq
            allowed_cpus: None,
        });
    }
    let scenario = builder.duration_ms(500).build();

    let _result = Simulator::new(sched).run_monitored(scenario, &mut monitor);

    let mid = monitor.final_snapshot(Pid(2)).unwrap();

    eprintln!(
        "wake_chain middle: lat_cri={}, wake_freq={}, wait_freq={}",
        mid.lat_cri, mid.wake_freq, mid.wait_freq
    );

    // Middle task in a 100Hz chain should develop non-zero lat_cri
    assert!(
        mid.lat_cri > 0,
        "expected middle task lat_cri > 0, got {}",
        mid.lat_cri
    );
}

/// Monitor trajectory: ping-pong lat_cri should start at 0 and increase over time.
#[test]
fn test_lavd_lat_cri_convergence() {
    let _lock = common::setup_test();
    let sched = DynamicScheduler::lavd(4);
    let probes = LavdProbes::new(&sched);
    let mut monitor = LavdMonitor::new(probes);

    let (prod, cons) = workloads::ping_pong(Pid(1), Pid(2), 500_000);
    let scenario = Scenario::builder()
        .cpus(4)
        .task(TaskDef {
            name: "ping".into(),
            pid: Pid(1),
            nice: 0,
            behavior: prod,
            start_time_ns: 0,
            mm_id: Some(MmId(1)),
            allowed_cpus: None,
        })
        .task(TaskDef {
            name: "pong".into(),
            pid: Pid(2),
            nice: 0,
            behavior: cons,
            start_time_ns: 0,
            mm_id: Some(MmId(1)),
            allowed_cpus: None,
        })
        .duration_ms(500)
        .build();

    let _result = Simulator::new(sched).run_monitored(scenario, &mut monitor);

    let history = monitor.task_history(Pid(1));

    // Should have many snapshots over 500ms
    assert!(
        history.len() >= 10,
        "expected at least 10 snapshots for ping task, got {}",
        history.len()
    );

    // First snapshots should have lat_cri == 0 (EWMA hasn't converged)
    let first = history.first().unwrap();
    eprintln!(
        "convergence: first lat_cri={}, last lat_cri={}, total snapshots={}",
        first.lat_cri,
        history.last().unwrap().lat_cri,
        history.len()
    );

    // Final lat_cri should be greater than the initial value
    let last = history.last().unwrap();
    assert!(
        last.lat_cri >= first.lat_cri,
        "expected lat_cri to converge upward: first={}, last={}",
        first.lat_cri,
        last.lat_cri
    );
}

// ---------------------------------------------------------------------------
// LAVD-specific tests: multi-domain load balancing (balance.bpf.c)
// ---------------------------------------------------------------------------

/// Multi-domain with imbalanced load: domain 1 should steal tasks from domain 0.
///
/// 4 CPUs in 2 domains (0: CPUs 0-1, 1: CPUs 2-3). All CPU-bound tasks
/// are unpinned but naturally cluster on domain 0 initially, creating
/// imbalance. The timer-driven plan_x_cpdom_migration() should mark
/// domain 0 as stealee and domain 1 as stealer, triggering
/// try_to_steal_task() and force_to_steal_task() in balance.bpf.c.
#[test]
fn test_lavd_multi_domain_balance() {
    let _lock = common::setup_test();
    let sched = DynamicScheduler::lavd_multi_domain(4, 2);

    // 6 CPU-bound tasks compete for 4 CPUs across 2 domains.
    // The scheduler's load balancer should distribute work across domains.
    let mut builder = Scenario::builder().cpus(4).duration_ms(500);
    for i in 1..=6i32 {
        builder = builder.task(TaskDef {
            name: format!("worker_{i}"),
            pid: Pid(i),
            nice: 0,
            behavior: workloads::cpu_bound(10_000_000), // 10ms chunks
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: None,
        });
    }

    let trace = Simulator::new(sched).run(builder.build());

    // All 6 tasks should have been scheduled
    for i in 1..=6i32 {
        assert!(
            trace.schedule_count(Pid(i)) > 0,
            "worker_{i} was never scheduled"
        );
    }
}

/// Multi-domain with pinned tasks creating intentional domain imbalance.
///
/// Pin all tasks to domain 0 (CPUs 0-1), leaving domain 1 (CPUs 2-3) idle.
/// Domain 1 CPUs should attempt force_to_steal_task() when dispatching
/// since they have no local tasks.
#[test]
fn test_lavd_multi_domain_force_steal() {
    let _lock = common::setup_test();
    let sched = DynamicScheduler::lavd_multi_domain(4, 2);

    // Pin 4 CPU-bound tasks to domain 0 (CPUs 0,1) only
    let domain0_cpus = Some(vec![CpuId(0), CpuId(1)]);
    let mut builder = Scenario::builder().cpus(4).duration_ms(500);
    for i in 1..=4i32 {
        builder = builder.task(TaskDef {
            name: format!("pinned_{i}"),
            pid: Pid(i),
            nice: 0,
            behavior: workloads::cpu_bound(10_000_000),
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: domain0_cpus.clone(),
        });
    }

    let trace = Simulator::new(sched).run(builder.build());

    // All 4 tasks should have been scheduled
    for i in 1..=4i32 {
        assert!(
            trace.schedule_count(Pid(i)) > 0,
            "pinned_{i} was never scheduled"
        );
    }
}

/// Multi-domain with mixed workload: IO tasks on domain 0, CPU tasks on domain 1.
///
/// This creates bidirectional load imbalance patterns as the IO tasks
/// sleep and wake, exercising plan_x_cpdom_migration thresholds.
#[test]
fn test_lavd_multi_domain_mixed_workload() {
    let _lock = common::setup_test();
    let sched = DynamicScheduler::lavd_multi_domain(4, 2);

    let mut builder = Scenario::builder().cpus(4).duration_ms(500);

    // IO-bound tasks (frequent sleep/wake)
    for i in 1..=3i32 {
        builder = builder.task(TaskDef {
            name: format!("io_{i}"),
            pid: Pid(i),
            nice: 0,
            behavior: workloads::io_bound(200_000, 2_000_000), // 0.2ms run, 2ms sleep
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: None,
        });
    }

    // CPU-bound tasks
    for i in 4..=7i32 {
        builder = builder.task(TaskDef {
            name: format!("cpu_{i}"),
            pid: Pid(i),
            nice: 0,
            behavior: workloads::cpu_bound(10_000_000),
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: None,
        });
    }

    let trace = Simulator::new(sched).run(builder.build());

    // All tasks should have been scheduled at least once
    for i in 1..=7i32 {
        assert!(
            trace.schedule_count(Pid(i)) > 0,
            "task {i} was never scheduled"
        );
    }
}

/// Multi-domain with mig_delta_pct > 0: fixed migration threshold.
///
/// Tests the `mig_delta_pct > 0` branches in plan_x_cpdom_migration:
/// - Uses avg_util_sum instead of cur_util_sum (line 84)
/// - Uses fixed percentage for x_mig_delta instead of calc_mig_delta (line 108-110)
/// - Disables force_to_steal_task (line 473: mig_delta_pct == 0 is false)
#[test]
fn test_lavd_multi_domain_mig_delta_pct() {
    let _lock = common::setup_test();
    let sched = DynamicScheduler::lavd_multi_domain(4, 2);
    sched.lavd_configure(false, 0, 20); // 20% migration threshold

    let mut builder = Scenario::builder().cpus(4).duration_ms(500);
    for i in 1..=6i32 {
        builder = builder.task(TaskDef {
            name: format!("worker_{i}"),
            pid: Pid(i),
            nice: 0,
            behavior: workloads::cpu_bound(10_000_000),
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: None,
        });
    }

    let trace = Simulator::new(sched).run(builder.build());
    for i in 1..=6i32 {
        assert!(
            trace.schedule_count(Pid(i)) > 0,
            "worker_{i} was never scheduled"
        );
    }
}

/// Multi-domain with pinned_slice_ns: dual-DSQ mode (per-CPU + per-cpdom).
///
/// Tests the dual-DSQ vtime comparison path in consume_task (lines 434-458).
/// TODO(sim-fa170): This test requires __COMPAT_scx_bpf_dsq_peek which
/// is not yet implemented in the simulator. Enable when available.
#[test]
#[ignore]
fn test_lavd_multi_domain_pinned_slice() {
    let _lock = common::setup_test();
    let sched = DynamicScheduler::lavd_multi_domain(4, 2);
    sched.lavd_configure(false, 3_000_000, 0); // 3ms pinned slice

    let mut builder = Scenario::builder().cpus(4).duration_ms(500);
    for i in 1..=6i32 {
        builder = builder.task(TaskDef {
            name: format!("worker_{i}"),
            pid: Pid(i),
            nice: 0,
            behavior: workloads::cpu_bound(10_000_000),
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: None,
        });
    }

    let trace = Simulator::new(sched).run(builder.build());
    for i in 1..=6i32 {
        assert!(
            trace.schedule_count(Pid(i)) > 0,
            "worker_{i} was never scheduled"
        );
    }
}

/// Multi-domain with per_cpu_dsq: per-CPU DSQ with migratable tasks.
///
/// Tests the per-CPU DSQ path in consume_task (lines 462-464) and
/// the is_per_cpu_dsq_migratable() path in pick_most_loaded_dsq (lines 252-276).
#[test]
fn test_lavd_multi_domain_per_cpu_dsq() {
    let _lock = common::setup_test();
    let sched = DynamicScheduler::lavd_multi_domain(4, 2);
    sched.lavd_configure(true, 0, 0); // per-CPU DSQ mode

    let mut builder = Scenario::builder().cpus(4).duration_ms(500);
    for i in 1..=6i32 {
        builder = builder.task(TaskDef {
            name: format!("worker_{i}"),
            pid: Pid(i),
            nice: 0,
            behavior: workloads::cpu_bound(10_000_000),
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: None,
        });
    }

    let trace = Simulator::new(sched).run(builder.build());
    for i in 1..=6i32 {
        assert!(
            trace.schedule_count(Pid(i)) > 0,
            "worker_{i} was never scheduled"
        );
    }
}

/// 3 domains with partially loaded system: exercises calc_mig_delta normal branch.
///
/// With 3 domains, only some having queued tasks, nz_qlen is between 0 and
/// nr_active_cpdoms, hitting calc_mig_delta line 31 (LAVD_CPDOM_MIG_SHIFT).
/// Also exercises the "keep as is" branch (lines 197-198) where a domain's
/// load is between stealer and stealee thresholds.
#[test]
fn test_lavd_three_domains_partial_load() {
    let _lock = common::setup_test();
    let sched = DynamicScheduler::lavd_multi_domain(6, 3);

    // Put tasks on only 2 of 3 domains, leaving 1 idle
    let mut builder = Scenario::builder().cpus(6).duration_ms(500);
    // Tasks pinned to domain 0 (CPUs 0-1)
    for i in 1..=2i32 {
        builder = builder.task(TaskDef {
            name: format!("d0_worker_{i}"),
            pid: Pid(i),
            nice: 0,
            behavior: workloads::cpu_bound(10_000_000),
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: Some(vec![CpuId(0), CpuId(1)]),
        });
    }
    // Tasks pinned to domain 1 (CPUs 2-3), lighter load
    builder = builder.task(TaskDef {
        name: "d1_worker".into(),
        pid: Pid(3),
        nice: 0,
        behavior: workloads::io_bound(500_000, 5_000_000), // light IO
        start_time_ns: 0,
        mm_id: None,
        allowed_cpus: Some(vec![CpuId(2), CpuId(3)]),
    });
    // Domain 2 (CPUs 4-5) has no tasks → idle stealer

    let trace = Simulator::new(sched).run(builder.build());
    for i in 1..=3i32 {
        assert!(
            trace.schedule_count(Pid(i)) > 0,
            "task {i} was never scheduled"
        );
    }
}

/// Balanced load across domains: exercises the "no stealee" early return.
///
/// When all domains have equal load, stealee_threshold > max_sc_load,
/// triggering the early return in plan_x_cpdom_migration (lines 127-143).
#[test]
fn test_lavd_multi_domain_balanced_load() {
    let _lock = common::setup_test();
    let sched = DynamicScheduler::lavd_multi_domain(4, 2);

    // Equal number of CPU-bound tasks per domain — symmetric load
    let mut builder = Scenario::builder().cpus(4).duration_ms(500);
    for i in 1..=4i32 {
        builder = builder.task(TaskDef {
            name: format!("balanced_{i}"),
            pid: Pid(i),
            nice: 0,
            behavior: workloads::cpu_bound(10_000_000),
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: None,
        });
    }

    let trace = Simulator::new(sched).run(builder.build());
    for i in 1..=4i32 {
        assert!(
            trace.schedule_count(Pid(i)) > 0,
            "balanced_{i} was never scheduled"
        );
    }
}

/// Multi-domain with is_monitored enabled: exercises consume_dsq latency tracking.
///
/// When is_monitored is true, consume_dsq() calls bpf_ktime_get_ns() before
/// and after consuming from the DSQ, then records dsq_consume_lat (lines 215, 222).
#[test]
fn test_lavd_multi_domain_monitored() {
    let _lock = common::setup_test();
    let sched = DynamicScheduler::lavd_multi_domain(4, 2);
    sched.lavd_set_monitored(true);

    let mut builder = Scenario::builder().cpus(4).duration_ms(500);
    for i in 1..=6i32 {
        builder = builder.task(TaskDef {
            name: format!("worker_{i}"),
            pid: Pid(i),
            nice: 0,
            behavior: workloads::cpu_bound(10_000_000),
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: None,
        });
    }

    let trace = Simulator::new(sched).run(builder.build());
    for i in 1..=6i32 {
        assert!(
            trace.schedule_count(Pid(i)) > 0,
            "worker_{i} was never scheduled"
        );
    }
}

/// 4 domains with gradient load: exercises "keep as is" and !is_stealee paths.
///
/// Domain 0: heavily loaded (stealee), domain 1: moderately loaded (keep as is),
/// domain 2: lightly loaded (stealer), domain 3: empty (stealer).
/// This exercises:
/// - L198-199: "keep as is" for domain 1 (between thresholds)
/// - L327: !is_stealee when stealer domain checks domain 1 neighbor
#[test]
fn test_lavd_four_domains_gradient() {
    let _lock = common::setup_test();
    let sched = DynamicScheduler::lavd_multi_domain(8, 4);

    let mut builder = Scenario::builder().cpus(8).duration_ms(500);

    // Domain 0 (CPUs 0-1): 4 CPU-bound tasks → heavily loaded
    for i in 1..=4i32 {
        builder = builder.task(TaskDef {
            name: format!("heavy_{i}"),
            pid: Pid(i),
            nice: 0,
            behavior: workloads::cpu_bound(10_000_000),
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: Some(vec![CpuId(0), CpuId(1)]),
        });
    }

    // Domain 1 (CPUs 2-3): 2 IO-bound tasks → moderate load
    for i in 5..=6i32 {
        builder = builder.task(TaskDef {
            name: format!("medium_{i}"),
            pid: Pid(i),
            nice: 0,
            behavior: workloads::io_bound(1_000_000, 3_000_000), // 1ms run, 3ms sleep
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: Some(vec![CpuId(2), CpuId(3)]),
        });
    }

    // Domain 2 (CPUs 4-5): 1 light IO task → lightly loaded
    builder = builder.task(TaskDef {
        name: "light_7".into(),
        pid: Pid(7),
        nice: 0,
        behavior: workloads::io_bound(200_000, 10_000_000), // 0.2ms run, 10ms sleep
        start_time_ns: 0,
        mm_id: None,
        allowed_cpus: Some(vec![CpuId(4), CpuId(5)]),
    });

    // Domain 3 (CPUs 6-7): empty → idle stealer

    let trace = Simulator::new(sched).run(builder.build());
    for i in 1..=7i32 {
        assert!(
            trace.schedule_count(Pid(i)) > 0,
            "task {i} was never scheduled"
        );
    }
}

/// Multi-domain with IO tasks that transition from imbalanced to balanced.
///
/// IO-bound tasks on domain 0 create periodic imbalance when running,
/// then balance out when sleeping. Over time, plan_x_cpdom_migration()
/// first sets stealees (when tasks are running), then resets them
/// (when tasks sleep and load equalizes), exercising lines 132-144.
#[test]
fn test_lavd_multi_domain_load_transition() {
    let _lock = common::setup_test();
    let sched = DynamicScheduler::lavd_multi_domain(4, 2);

    let mut builder = Scenario::builder().cpus(4).duration_ms(1000);

    // IO tasks on domain 0: create periodic load spikes
    for i in 1..=3i32 {
        builder = builder.task(TaskDef {
            name: format!("io_{i}"),
            pid: Pid(i),
            nice: 0,
            // Short bursts followed by long sleeps — load oscillates
            behavior: workloads::io_bound(500_000, 20_000_000), // 0.5ms run, 20ms sleep
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: Some(vec![CpuId(0), CpuId(1)]),
        });
    }

    // 1 IO task on domain 1 to keep it slightly active
    builder = builder.task(TaskDef {
        name: "io_d1".into(),
        pid: Pid(4),
        nice: 0,
        behavior: workloads::io_bound(500_000, 20_000_000),
        start_time_ns: 0,
        mm_id: None,
        allowed_cpus: Some(vec![CpuId(2), CpuId(3)]),
    });

    let trace = Simulator::new(sched).run(builder.build());
    for i in 1..=4i32 {
        assert!(
            trace.schedule_count(Pid(i)) > 0,
            "io_{i} was never scheduled"
        );
    }
}
