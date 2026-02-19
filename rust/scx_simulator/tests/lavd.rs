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
            parent_pid: None,
        })
        .task(TaskDef {
            name: "pong".into(),
            pid: Pid(2),
            nice: 0,
            behavior: cons,
            start_time_ns: 0,
            mm_id: Some(MmId(1)),
            allowed_cpus: None,
            parent_pid: None,
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
            parent_pid: None,
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
            parent_pid: None,
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
            parent_pid: None,
        })
        .task(TaskDef {
            name: "cpu_task".into(),
            pid: Pid(2),
            nice: 0,
            behavior: workloads::cpu_bound(100_000_000),
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: None,
            parent_pid: None,
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
            parent_pid: None,
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
            parent_pid: None,
        })
        .task(TaskDef {
            name: "pong".into(),
            pid: Pid(2),
            nice: 0,
            behavior: cons,
            start_time_ns: 0,
            mm_id: Some(MmId(1)),
            allowed_cpus: None,
            parent_pid: None,
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
            parent_pid: None,
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
            parent_pid: None,
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
            parent_pid: None,
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
            parent_pid: None,
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
            parent_pid: None,
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
            parent_pid: None,
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
            parent_pid: None,
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
            parent_pid: None,
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
        parent_pid: None,
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
            parent_pid: None,
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
            parent_pid: None,
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
///
/// Core compaction is disabled so all domains keep their active CPUs,
/// preventing overflow_running from masking the gradient load distribution.
///
/// This exercises:
/// - L198-199: "keep as is" for domain 1 (between thresholds)
/// - L327: !is_stealee when stealer domain checks domain 1 neighbor
#[test]
fn test_lavd_four_domains_gradient() {
    let _lock = common::setup_test();
    let sched = DynamicScheduler::lavd_multi_domain(8, 4);
    // Disable core compaction so all domains keep active CPUs.
    // Without this, do_core_compaction() deactivates domains, creating
    // overflow_running=true which prevents the "keep as is" path.
    sched.lavd_set_no_core_compaction(true);

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
            parent_pid: None,
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
            parent_pid: None,
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
        parent_pid: None,
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
///
/// Core compaction is disabled to prevent overflow domains from masking
/// the balanced load condition.
#[test]
fn test_lavd_multi_domain_load_transition() {
    let _lock = common::setup_test();
    let sched = DynamicScheduler::lavd_multi_domain(4, 2);
    sched.lavd_set_no_core_compaction(true);

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
            parent_pid: None,
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
        parent_pid: None,
    });

    let trace = Simulator::new(sched).run(builder.build());
    for i in 1..=4i32 {
        assert!(
            trace.schedule_count(Pid(i)) > 0,
            "io_{i} was never scheduled"
        );
    }
}

/// Multi-domain balanced load without core compaction: exercises stealee reset.
///
/// With no_core_compaction=true and symmetric load, all domains stay active.
/// On each timer tick, stealee_threshold > max_sc_load (balanced) triggers
/// the stealee reset path (L127-144) whenever nr_stealee > 0 from a
/// previous round. After lavd_init() runs, early timer ticks may see
/// transient imbalance that sets nr_stealee, followed by balanced ticks
/// that trigger the reset.
#[test]
fn test_lavd_multi_domain_no_compact_balanced() {
    let _lock = common::setup_test();
    let sched = DynamicScheduler::lavd_multi_domain(4, 2);
    sched.lavd_set_no_core_compaction(true);

    // Symmetric load: exactly 1 CPU-bound task per CPU
    let mut builder = Scenario::builder().cpus(4).duration_ms(500);
    for i in 1..=4i32 {
        builder = builder.task(TaskDef {
            name: format!("symmetric_{i}"),
            pid: Pid(i),
            nice: 0,
            behavior: workloads::cpu_bound(10_000_000),
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: None,
            parent_pid: None,
        });
    }

    let trace = Simulator::new(sched).run(builder.build());
    for i in 1..=4i32 {
        assert!(
            trace.schedule_count(Pid(i)) > 0,
            "symmetric_{i} was never scheduled"
        );
    }
}

/// 3 domains without core compaction: exercises "keep as is" and stealee reset.
///
/// With no_core_compaction=true, all domains keep active CPUs. With 3 domains
/// and carefully tuned load, the system transitions between imbalanced and
/// balanced states across timer ticks, exercising:
/// - L132-144: stealee reset when load becomes balanced after imbalance
/// - L197-199: "keep as is" when domain load is between thresholds
///
/// Load: Domain 0 overloaded (4 tasks), Domain 1 moderate (2 tasks),
/// Domain 2 light (1 IO task). The similar utilization between domains 0
/// and 1 creates fluctuating stealer/stealee assignments that eventually
/// produce balanced rounds (triggering stealee reset).
#[test]
fn test_lavd_three_domains_no_compact() {
    let _lock = common::setup_test();
    let sched = DynamicScheduler::lavd_multi_domain(6, 3);
    sched.lavd_set_no_core_compaction(true);

    let mut builder = Scenario::builder().cpus(6).duration_ms(1000);

    // Domain 0 (CPUs 0-1): overloaded with 4 CPU-bound tasks
    for i in 1..=4i32 {
        builder = builder.task(TaskDef {
            name: format!("heavy_{i}"),
            pid: Pid(i),
            nice: 0,
            behavior: workloads::cpu_bound(10_000_000),
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: Some(vec![CpuId(0), CpuId(1)]),
            parent_pid: None,
        });
    }

    // Domain 1 (CPUs 2-3): moderate load with 2 CPU-bound tasks
    for i in 5..=6i32 {
        builder = builder.task(TaskDef {
            name: format!("medium_{i}"),
            pid: Pid(i),
            nice: 0,
            behavior: workloads::cpu_bound(10_000_000),
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: Some(vec![CpuId(2), CpuId(3)]),
            parent_pid: None,
        });
    }

    // Domain 2 (CPUs 4-5): lightly loaded with 1 IO task
    builder = builder.task(TaskDef {
        name: "light_7".into(),
        pid: Pid(7),
        nice: 0,
        behavior: workloads::io_bound(500_000, 5_000_000),
        start_time_ns: 0,
        mm_id: None,
        allowed_cpus: Some(vec![CpuId(4), CpuId(5)]),
        parent_pid: None,
    });

    let trace = Simulator::new(sched).run(builder.build());
    for i in 1..=7i32 {
        assert!(
            trace.schedule_count(Pid(i)) > 0,
            "task {i} was never scheduled"
        );
    }
}

/// 3 domains with narrow migration threshold: targeted at "keep as is" path.
///
/// Uses mig_delta_pct=5 for a narrow 5% migration threshold to increase
/// the chance of a domain landing in the middle band between stealer
/// and stealee thresholds, exercising L197-199.
///
/// - Domain 0: very heavy (4 tasks on 2 CPUs -> stealee)
/// - Domain 1: moderate (1 task on 2 CPUs -> "keep as is")
/// - Domain 2: idle (0 tasks -> stealer)
#[test]
fn test_lavd_gradient_narrow_threshold() {
    let _lock = common::setup_test();
    let sched = DynamicScheduler::lavd_multi_domain(6, 3);
    sched.lavd_set_no_core_compaction(true);
    sched.lavd_configure(false, 0, 5); // very narrow 5% migration threshold

    let mut builder = Scenario::builder().cpus(6).duration_ms(1000);

    // Domain 0 (CPUs 0-1): very heavy
    for i in 1..=4i32 {
        builder = builder.task(TaskDef {
            name: format!("heavy_{i}"),
            pid: Pid(i),
            nice: 0,
            behavior: workloads::cpu_bound(10_000_000),
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: Some(vec![CpuId(0), CpuId(1)]),
            parent_pid: None,
        });
    }

    // Domain 1 (CPUs 2-3): moderate (1 CPU-bound task)
    builder = builder.task(TaskDef {
        name: "medium_5".into(),
        pid: Pid(5),
        nice: 0,
        behavior: workloads::cpu_bound(10_000_000),
        start_time_ns: 0,
        mm_id: None,
        allowed_cpus: Some(vec![CpuId(2), CpuId(3)]),
        parent_pid: None,
    });

    // Domain 2 (CPUs 4-5): empty -> stealer

    let trace = Simulator::new(sched).run(builder.build());
    for i in 1..=5i32 {
        assert!(
            trace.schedule_count(Pid(i)) > 0,
            "task {i} was never scheduled"
        );
    }
}

// ---------------------------------------------------------------------------
// LAVD-specific tests: waker-wakee latency criticality propagation
// ---------------------------------------------------------------------------

/// Ping-pong tasks with shared parent: exercises lavd_runnable waker-wakee
/// latency criticality propagation path (main.bpf.c L1198-1260).
///
/// The key gate at L1198 is `p->real_parent != waker->real_parent` — when
/// both tasks share the same parent_pid, this check passes and the function
/// continues to:
/// - Update waker's wake_freq (L1227-1233)
/// - Propagate latency criticality forward/backward (L1248-1250)
/// - Record waker_pid when is_monitored (L1255-1259)
#[test]
fn test_lavd_waker_wakee_with_parent() {
    let _lock = common::setup_test();
    let sched = DynamicScheduler::lavd(4);
    let probes = LavdProbes::new(&sched);
    let mut monitor = LavdMonitor::new(probes);

    // Create a "parent" task (Pid(1)) and two children (Pid(2), Pid(3))
    // that ping-pong with each other. The parent just runs CPU-bound.
    let (ping_b, pong_b) = workloads::ping_pong(Pid(2), Pid(3), 500_000);
    let scenario = Scenario::builder()
        .cpus(4)
        // Parent task
        .task(TaskDef {
            name: "parent".into(),
            pid: Pid(1),
            nice: 0,
            behavior: workloads::cpu_bound(50_000_000),
            start_time_ns: 0,
            mm_id: Some(MmId(1)),
            allowed_cpus: None,
            parent_pid: None,
        })
        // Child ping — shares parent with pong
        .task(TaskDef {
            name: "child_ping".into(),
            pid: Pid(2),
            nice: 0,
            behavior: ping_b,
            start_time_ns: 0,
            mm_id: Some(MmId(1)),
            allowed_cpus: None,
            parent_pid: Some(Pid(1)),
        })
        // Child pong — shares parent with ping
        .task(TaskDef {
            name: "child_pong".into(),
            pid: Pid(3),
            nice: 0,
            behavior: pong_b,
            start_time_ns: 0,
            mm_id: Some(MmId(1)),
            allowed_cpus: None,
            parent_pid: Some(Pid(1)),
        })
        .duration_ms(500)
        .build();

    let _result = Simulator::new(sched).run_monitored(scenario, &mut monitor);

    let p2 = monitor.final_snapshot(Pid(2)).unwrap();
    let p3 = monitor.final_snapshot(Pid(3)).unwrap();

    eprintln!(
        "waker-wakee: p2 lat_cri={}, wake_freq={}, p3 lat_cri={}, wake_freq={}",
        p2.lat_cri, p2.wake_freq, p3.lat_cri, p3.wake_freq
    );

    // With shared parent, waker-wakee tracking should produce non-zero
    // wake_freq on both tasks (propagated through lavd_runnable L1227-1233)
    assert!(
        p2.wake_freq > 0,
        "expected child_ping wake_freq > 0 (waker-wakee path), got {}",
        p2.wake_freq
    );
    assert!(
        p3.wake_freq > 0,
        "expected child_pong wake_freq > 0 (waker-wakee path), got {}",
        p3.wake_freq
    );
}

/// Wake chain with shared parent and is_monitored: exercises waker_pid
/// and waker_comm recording in lavd_runnable (main.bpf.c L1255-1259).
#[test]
fn test_lavd_waker_wakee_monitored() {
    let _lock = common::setup_test();
    let sched = DynamicScheduler::lavd(4);
    sched.lavd_set_monitored(true);

    let pids = [Pid(2), Pid(3), Pid(4)];
    let behaviors = workloads::wake_chain(&pids, 100_000, 10_000_000);

    let mut builder = Scenario::builder().cpus(4);
    // Parent task
    builder = builder.task(TaskDef {
        name: "parent".into(),
        pid: Pid(1),
        nice: 0,
        behavior: workloads::cpu_bound(50_000_000),
        start_time_ns: 0,
        mm_id: Some(MmId(1)),
        allowed_cpus: None,
        parent_pid: None,
    });
    // Chain tasks all share parent Pid(1)
    for (i, behavior) in behaviors.into_iter().enumerate() {
        builder = builder.task(TaskDef {
            name: format!("chain_{i}"),
            pid: pids[i],
            nice: 0,
            behavior,
            start_time_ns: 0,
            mm_id: Some(MmId(1)),
            allowed_cpus: None,
            parent_pid: Some(Pid(1)),
        });
    }
    let scenario = builder.duration_ms(500).build();

    let trace = Simulator::new(sched).run(scenario);

    // All tasks should have been scheduled
    for pid in &pids {
        assert!(
            trace.schedule_count(*pid) > 0,
            "chain task {:?} was never scheduled",
            pid
        );
    }
}

// ---------------------------------------------------------------------------
// LAVD-specific tests: under-loaded system (core compaction dispatch path)
// ---------------------------------------------------------------------------

/// Under-loaded system: exercises lavd_dispatch core compaction path
/// (main.bpf.c L964-1134).
///
/// When `use_full_cpus()` returns false (nr_active < nr_cpus_onln),
/// lavd_dispatch enters the core compaction path instead of going directly
/// to consume_out. This exercises cpumask checking, overflow set extension,
/// and per-domain DSQ iteration.
#[test]
fn test_lavd_underloaded_dispatch() {
    let _lock = common::setup_test();
    // Use multi-domain to have cpdom DSQs
    let sched = DynamicScheduler::lavd_multi_domain(4, 2);

    let scenario = Scenario::builder()
        .cpus(4)
        // Only 1 task for 4 CPUs — system is heavily under-loaded
        .task(TaskDef {
            name: "lonely".into(),
            pid: Pid(1),
            nice: 0,
            behavior: workloads::io_bound(500_000, 5_000_000), // 0.5ms run, 5ms sleep
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: None,
            parent_pid: None,
        })
        .duration_ms(500)
        .build();

    let trace = Simulator::new(sched).run(scenario);
    assert!(
        trace.schedule_count(Pid(1)) > 0,
        "lonely task was never scheduled"
    );
}

/// Under-loaded system with pinned tasks: exercises overflow set extension
/// paths in lavd_dispatch (main.bpf.c L1006-1034).
///
/// When a CPU's prev task is pinned but the CPU is not in the active set,
/// the dispatch code extends the overflow set (L1011-1014). Similarly,
/// when prev can run on this CPU but not on active/overflow sets, the
/// overflow set is extended (L1024-1033).
#[test]
fn test_lavd_underloaded_pinned_overflow() {
    let _lock = common::setup_test();
    let sched = DynamicScheduler::lavd_multi_domain(4, 2);

    let scenario = Scenario::builder()
        .cpus(4)
        // One task pinned to CPU 3 only — with under-loaded system,
        // CPU 3 may not be in the active set
        .task(TaskDef {
            name: "pinned_3".into(),
            pid: Pid(1),
            nice: 0,
            behavior: workloads::cpu_bound(10_000_000),
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: Some(vec![CpuId(3)]),
            parent_pid: None,
        })
        // One IO task on any CPU
        .task(TaskDef {
            name: "io_free".into(),
            pid: Pid(2),
            nice: 0,
            behavior: workloads::io_bound(200_000, 5_000_000),
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: None,
            parent_pid: None,
        })
        .duration_ms(500)
        .build();

    let trace = Simulator::new(sched).run(scenario);
    assert!(
        trace.schedule_count(Pid(1)) > 0,
        "pinned task was never scheduled"
    );
    assert!(
        trace.schedule_count(Pid(2)) > 0,
        "io task was never scheduled"
    );
}

/// Lightly loaded system with per-CPU DSQ: exercises the per-CPU DSQ
/// fast path in core compaction (main.bpf.c L1000-1004).
#[test]
fn test_lavd_underloaded_per_cpu_dsq() {
    let _lock = common::setup_test();
    let sched = DynamicScheduler::lavd_multi_domain(4, 2);
    sched.lavd_configure(true, 0, 0); // per-CPU DSQ mode

    let scenario = Scenario::builder()
        .cpus(4)
        // 2 tasks for 4 CPUs — under-loaded
        .task(TaskDef {
            name: "worker_1".into(),
            pid: Pid(1),
            nice: 0,
            behavior: workloads::cpu_bound(10_000_000),
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: None,
            parent_pid: None,
        })
        .task(TaskDef {
            name: "worker_2".into(),
            pid: Pid(2),
            nice: 0,
            behavior: workloads::io_bound(500_000, 5_000_000),
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: None,
            parent_pid: None,
        })
        .duration_ms(500)
        .build();

    let trace = Simulator::new(sched).run(scenario);
    assert!(
        trace.schedule_count(Pid(1)) > 0,
        "worker_1 was never scheduled"
    );
    assert!(
        trace.schedule_count(Pid(2)) > 0,
        "worker_2 was never scheduled"
    );
}

// ---------------------------------------------------------------------------
// LAVD-specific tests: init_task parent inheritance
// ---------------------------------------------------------------------------

/// Tasks with parent_pid: exercises lavd_init_task parent context inheritance
/// path (main.bpf.c L1726-1729).
#[test]
fn test_lavd_init_task_parent_inheritance() {
    let _lock = common::setup_test();
    let sched = DynamicScheduler::lavd(4);

    let (ping_b, pong_b) = workloads::ping_pong(Pid(1), Pid(2), 500_000);
    let scenario = Scenario::builder()
        .cpus(4)
        .task(TaskDef {
            name: "parent_task".into(),
            pid: Pid(1),
            nice: 0,
            behavior: ping_b,
            start_time_ns: 0,
            mm_id: Some(MmId(1)),
            allowed_cpus: None,
            parent_pid: None,
        })
        .task(TaskDef {
            name: "child_a".into(),
            pid: Pid(2),
            nice: 0,
            behavior: pong_b,
            start_time_ns: 0,
            mm_id: Some(MmId(1)),
            allowed_cpus: None,
            parent_pid: Some(Pid(1)),
        })
        .task(TaskDef {
            name: "child_b".into(),
            pid: Pid(3),
            nice: 0,
            behavior: workloads::cpu_bound(10_000_000),
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: None,
            parent_pid: Some(Pid(1)),
        })
        .duration_ms(500)
        .build();

    let trace = Simulator::new(sched).run(scenario);
    for i in 1..=3i32 {
        assert!(
            trace.schedule_count(Pid(i)) > 0,
            "task {i} was never scheduled"
        );
    }
}

// ---------------------------------------------------------------------------
// LAVD-specific tests: consume_prev with SCX_TASK_QUEUED
// ---------------------------------------------------------------------------

/// Overloaded system with many IO tasks: exercises consume_prev body
/// (main.bpf.c L884-920).
#[test]
fn test_lavd_consume_prev_queued() {
    let _lock = common::setup_test();
    let sched = DynamicScheduler::lavd(2);

    let mut builder = Scenario::builder().cpus(2).duration_ms(500);
    for i in 1..=8i32 {
        builder = builder.task(TaskDef {
            name: format!("io_{i}"),
            pid: Pid(i),
            nice: 0,
            behavior: workloads::io_bound(200_000, 2_000_000),
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: None,
            parent_pid: None,
        });
    }

    let trace = Simulator::new(sched).run(builder.build());
    for i in 1..=8i32 {
        assert!(
            trace.schedule_count(Pid(i)) > 0,
            "io_{i} was never scheduled"
        );
    }
}

// ---------------------------------------------------------------------------
// LAVD-specific tests: slice boost paths in calc_time_slice
// ---------------------------------------------------------------------------

/// Under-loaded system with long-running tasks: exercises can_boost_slice()
/// path in calc_time_slice (main.bpf.c L315-325).
#[test]
fn test_lavd_slice_boost_underloaded() {
    let _lock = common::setup_test();
    let sched = DynamicScheduler::lavd(4);

    let scenario = Scenario::builder()
        .cpus(4)
        .task(TaskDef {
            name: "long_1".into(),
            pid: Pid(1),
            nice: 0,
            behavior: workloads::cpu_bound(500_000_000), // 500ms chunks
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: None,
            parent_pid: None,
        })
        .task(TaskDef {
            name: "long_2".into(),
            pid: Pid(2),
            nice: 0,
            behavior: workloads::cpu_bound(500_000_000),
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: None,
            parent_pid: None,
        })
        .duration_ms(1000)
        .build();

    let trace = Simulator::new(sched).run(scenario);
    assert!(
        trace.schedule_count(Pid(1)) > 0,
        "long_1 was never scheduled"
    );
    assert!(
        trace.schedule_count(Pid(2)) > 0,
        "long_2 was never scheduled"
    );
}

/// Overloaded system with high-lat_cri tasks: exercises the
/// lat_cri > avg_lat_cri slice boost path (main.bpf.c L334-344).
#[test]
fn test_lavd_slice_boost_lat_cri() {
    let _lock = common::setup_test();
    let sched = DynamicScheduler::lavd(2);

    let (ping_b, pong_b) = workloads::ping_pong(Pid(1), Pid(2), 2_000_000);
    let mut builder = Scenario::builder().cpus(2);

    builder = builder
        .task(TaskDef {
            name: "parent".into(),
            pid: Pid(10),
            nice: 0,
            behavior: workloads::cpu_bound(50_000_000),
            start_time_ns: 0,
            mm_id: Some(MmId(1)),
            allowed_cpus: None,
            parent_pid: None,
        })
        .task(TaskDef {
            name: "ping".into(),
            pid: Pid(1),
            nice: 0,
            behavior: ping_b,
            start_time_ns: 0,
            mm_id: Some(MmId(1)),
            allowed_cpus: None,
            parent_pid: Some(Pid(10)),
        })
        .task(TaskDef {
            name: "pong".into(),
            pid: Pid(2),
            nice: 0,
            behavior: pong_b,
            start_time_ns: 0,
            mm_id: Some(MmId(1)),
            allowed_cpus: None,
            parent_pid: Some(Pid(10)),
        });

    for i in 3..=4i32 {
        builder = builder.task(TaskDef {
            name: format!("cpu_{i}"),
            pid: Pid(i),
            nice: 0,
            behavior: workloads::cpu_bound(10_000_000),
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: None,
            parent_pid: None,
        });
    }

    let trace = Simulator::new(sched).run(builder.duration_ms(1000).build());
    for i in 1..=4i32 {
        assert!(
            trace.schedule_count(Pid(i)) > 0,
            "task {i} was never scheduled"
        );
    }
}

// ---------------------------------------------------------------------------
// LAVD-specific tests: misc coverage paths
// ---------------------------------------------------------------------------

/// Under-loaded system with single domain: exercises the early return
/// at L1040-1042 in lavd_dispatch when use_cpdom_dsq() is false.
#[test]
fn test_lavd_underloaded_no_dsq_early_return() {
    let _lock = common::setup_test();
    let sched = DynamicScheduler::lavd(4);

    let scenario = Scenario::builder()
        .cpus(4)
        .task(TaskDef {
            name: "sparse".into(),
            pid: Pid(1),
            nice: 0,
            behavior: workloads::io_bound(100_000, 10_000_000),
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: None,
            parent_pid: None,
        })
        .duration_ms(500)
        .build();

    let trace = Simulator::new(sched).run(scenario);
    assert!(
        trace.schedule_count(Pid(1)) > 0,
        "sparse task was never scheduled"
    );
}

/// Multi-domain under-loaded with affinitized task: exercises per-domain
/// DSQ iteration for affinitized tasks (main.bpf.c L1055-1126).
#[test]
fn test_lavd_underloaded_cpdom_dsq_affinity() {
    let _lock = common::setup_test();
    let sched = DynamicScheduler::lavd_multi_domain(4, 2);

    let scenario = Scenario::builder()
        .cpus(4)
        .task(TaskDef {
            name: "affine_3".into(),
            pid: Pid(1),
            nice: 0,
            behavior: workloads::io_bound(500_000, 5_000_000),
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: Some(vec![CpuId(3)]),
            parent_pid: None,
        })
        .task(TaskDef {
            name: "free".into(),
            pid: Pid(2),
            nice: 0,
            behavior: workloads::io_bound(200_000, 5_000_000),
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: None,
            parent_pid: None,
        })
        .duration_ms(500)
        .build();

    let trace = Simulator::new(sched).run(scenario);
    assert!(
        trace.schedule_count(Pid(1)) > 0,
        "affinitized task was never scheduled"
    );
    assert!(
        trace.schedule_count(Pid(2)) > 0,
        "free task was never scheduled"
    );
}
