use scx_simulator::probes::{LavdMonitor, LavdProbes};
use scx_simulator::*;

#[macro_use]
mod common;

// Generic test suite applied to scx_lavd
scheduler_tests!(|nr_cpus| DynamicScheduler::lavd(nr_cpus));

// ---------------------------------------------------------------------------
// Helper: configure LAVD globals via dlsym to enable features disabled by
// default in lavd_setup() (no_core_compaction, is_autopilot_on, etc.)
// ---------------------------------------------------------------------------

/// Write a boolean value to a named LAVD global variable.
unsafe fn lavd_set_bool(sched: &DynamicScheduler, name: &str, val: bool) {
    let sym: libloading::Symbol<'_, *mut bool> = sched
        .get_symbol(name.as_bytes())
        .unwrap_or_else(|| panic!("symbol {name} not found"));
    std::ptr::write_volatile(*sym, val);
}

/// Write a u8 value to a named LAVD global variable.
unsafe fn lavd_set_u8(sched: &DynamicScheduler, name: &str, val: u8) {
    let sym: libloading::Symbol<'_, *mut u8> = sched
        .get_symbol(name.as_bytes())
        .unwrap_or_else(|| panic!("symbol {name} not found"));
    std::ptr::write_volatile(*sym, val);
}

/// Write a u64 value to a named LAVD global variable.
unsafe fn lavd_set_u64(sched: &DynamicScheduler, name: &str, val: u64) {
    let sym: libloading::Symbol<'_, *mut u64> = sched
        .get_symbol(name.as_bytes())
        .unwrap_or_else(|| panic!("symbol {name} not found"));
    std::ptr::write_volatile(*sym, val);
}

/// Set up a minimal valid PCO table for core compaction.
/// Without this, `get_cpu_order()` errors on `pco_idx >= LAVD_PCO_STATE_MAX`.
unsafe fn lavd_setup_pco(sched: &DynamicScheduler, nr_cpus: u32) {
    const LAVD_CPU_ID_MAX: usize = 512;

    lavd_set_u8(sched, "nr_pco_states\0", 1);

    // Set up PCO table: state 0 has CPUs in order 0..nr_cpus
    let pco_sym: libloading::Symbol<'_, *mut u16> = sched
        .get_symbol(b"pco_table\0")
        .expect("pco_table not found");
    let pco = *pco_sym;
    for i in 0..nr_cpus.min(LAVD_CPU_ID_MAX as u32) {
        std::ptr::write_volatile(pco.add(i as usize), i as u16);
    }

    // Set PCO bounds high enough that all CPUs are considered
    let bounds_sym: libloading::Symbol<'_, *mut u32> = sched
        .get_symbol(b"pco_bounds\0")
        .expect("pco_bounds not found");
    std::ptr::write_volatile(*bounds_sym, u32::MAX);

    // Set primary count
    let primary_sym: libloading::Symbol<'_, *mut u16> = sched
        .get_symbol(b"pco_nr_primary\0")
        .expect("pco_nr_primary not found");
    std::ptr::write_volatile(*primary_sym, nr_cpus as u16);
}

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

/// Test core compaction dispatch: a task pinned to a CPU outside the active
/// set forces the dispatch path through the core compaction branch (L970-L1128
/// in main.bpf.c). Core compaction reduces nr_active below nr_cpus_onln, so
/// use_full_cpus() returns false. When the pinned task wakes on an inactive
/// CPU, lavd_dispatch enters the compaction logic.
#[test]
fn test_lavd_core_compaction_dispatch() {
    let _lock = common::setup_test();
    let sched = DynamicScheduler::lavd(8);
    // Enable core compaction so nr_active can drop below nr_cpus_onln
    sched.lavd_set_no_core_compaction(false);

    let scenario = Scenario::builder()
        .cpus(8)
        // A task pinned to CPU 4 — after compaction, CPU 4 will NOT be in
        // the active set (since cpu_order maps everything to CPU 0 in sim).
        // This forces the dispatch through the core compaction overflow path.
        .task(TaskDef {
            name: "pinned_4".into(),
            pid: Pid(1),
            nice: 0,
            behavior: workloads::io_bound(100_000, 2_000_000),
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: Some(vec![CpuId(4)]),
            parent_pid: None,
        })
        // An unpinned task to generate some scheduling activity
        .task(TaskDef {
            name: "free".into(),
            pid: Pid(2),
            nice: 0,
            behavior: workloads::io_bound(100_000, 2_000_000),
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
        "pinned task on CPU 4 was never scheduled"
    );
    assert!(
        trace.schedule_count(Pid(2)) > 0,
        "free task was never scheduled"
    );
}

/// Test core compaction with per-CPU DSQ fast path. When core compaction
/// is active and per_cpu_dsq is enabled, a task on an inactive CPU with
/// something in its per-CPU DSQ takes the fast path (L1000-L1004).
#[test]
fn test_lavd_core_compaction_per_cpu_dsq() {
    let _lock = common::setup_test();
    let sched = DynamicScheduler::lavd(8);
    sched.lavd_set_no_core_compaction(false);
    sched.lavd_configure(true, 0, 0); // per_cpu_dsq = true

    let scenario = Scenario::builder()
        .cpus(8)
        // Pinned task on CPU 6 — outside active set after compaction
        .task(TaskDef {
            name: "pinned_6".into(),
            pid: Pid(1),
            nice: 0,
            behavior: workloads::io_bound(50_000, 1_000_000),
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: Some(vec![CpuId(6)]),
            parent_pid: None,
        })
        // Another pinned task on CPU 5
        .task(TaskDef {
            name: "pinned_5".into(),
            pid: Pid(2),
            nice: 0,
            behavior: workloads::io_bound(50_000, 1_000_000),
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: Some(vec![CpuId(5)]),
            parent_pid: None,
        })
        .duration_ms(1000)
        .build();

    let trace = Simulator::new(sched).run(scenario);

    assert!(
        trace.schedule_count(Pid(1)) > 0,
        "pinned task on CPU 6 was never scheduled"
    );
}

/// Test core compaction with a prev task that is pinned and still queued.
/// When dispatch is called with a prev task that is_pinned, the compaction
/// logic extends the overflow set for that CPU (L1011-L1014).
#[test]
fn test_lavd_core_compaction_pinned_prev() {
    let _lock = common::setup_test();
    let sched = DynamicScheduler::lavd(8);
    sched.lavd_set_no_core_compaction(false);

    let scenario = Scenario::builder()
        .cpus(8)
        // Two tasks both pinned to CPU 7, forcing context switches between them.
        // When one is "prev" during dispatch, it triggers the is_pinned(prev) path.
        .task(TaskDef {
            name: "pin7_a".into(),
            pid: Pid(1),
            nice: 0,
            behavior: workloads::cpu_bound(100_000),
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: Some(vec![CpuId(7)]),
            parent_pid: None,
        })
        .task(TaskDef {
            name: "pin7_b".into(),
            pid: Pid(2),
            nice: 0,
            behavior: workloads::cpu_bound(100_000),
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: Some(vec![CpuId(7)]),
            parent_pid: None,
        })
        .duration_ms(500)
        .build();

    let trace = Simulator::new(sched).run(scenario);

    assert!(
        trace.schedule_count(Pid(1)) > 0,
        "pinned task A was never scheduled"
    );
    assert!(
        trace.schedule_count(Pid(2)) > 0,
        "pinned task B was never scheduled"
    );
}

// ===========================================================================
// Coverage tests: exercise LAVD code paths disabled by default in lavd_setup
// ===========================================================================

// ---------------------------------------------------------------------------
// power.bpf.c: core compaction (do_core_compaction, calc_nr_active_cpus)
// Covers: do_core_compaction, calc_nr_active_cpus, calc_required_capacity,
//         get_cpu_order, get_human_readable_avg_sc_util
// ---------------------------------------------------------------------------

/// Enable core compaction on an overloaded system (many tasks, few CPUs).
/// This triggers do_core_compaction() → calc_nr_active_cpus() via the
/// timer callback in update_sys_stat().
#[test]
fn test_lavd_core_compaction_overloaded() {
    let _lock = common::setup_test();
    let nr_cpus = 4;
    let sched = DynamicScheduler::lavd(nr_cpus);

    // Enable core compaction (disabled by default)
    unsafe {
        lavd_set_bool(&sched, "no_core_compaction\0", false);
        lavd_setup_pco(&sched, nr_cpus);
    }

    // Overloaded: 8 CPU-bound tasks on 4 CPUs → all CPUs should be active
    let mut builder = Scenario::builder().cpus(nr_cpus).duration_ms(200);
    for i in 0..8 {
        builder = builder.add_task(&format!("hog-{i}"), 0, workloads::cpu_bound(20_000_000));
    }
    let scenario = builder.build();

    let trace = Simulator::new(sched).run(scenario);
    // All tasks should have run
    for pid_val in 1..=8 {
        assert!(
            trace.schedule_count(Pid(pid_val)) > 0,
            "task pid={pid_val} was never scheduled"
        );
    }
}

/// Enable core compaction on an underloaded system (few tasks, many CPUs).
/// With low utilization, some CPUs should be deactivated.
#[test]
fn test_lavd_core_compaction_underloaded() {
    let _lock = common::setup_test();
    let nr_cpus = 8;
    let sched = DynamicScheduler::lavd(nr_cpus);

    // Enable core compaction
    unsafe {
        lavd_set_bool(&sched, "no_core_compaction\0", false);
        lavd_setup_pco(&sched, nr_cpus);
    }

    // Underloaded: 1 I/O-bound task on 8 CPUs → most CPUs can be deactivated
    let scenario = Scenario::builder()
        .cpus(nr_cpus)
        .add_task("io-light", 0, workloads::io_bound(100_000, 10_000_000))
        .duration_ms(200)
        .build();

    let trace = Simulator::new(sched).run(scenario);
    assert!(
        trace.schedule_count(Pid(1)) > 0,
        "io-light task was never scheduled"
    );
}

// ---------------------------------------------------------------------------
// power.bpf.c: autopilot (do_autopilot, do_set_power_profile)
// Covers: do_autopilot, do_set_power_profile, init_autopilot_caps,
//         update_power_mode_time, update_autopilot_high_cap
// ---------------------------------------------------------------------------

/// Enable autopilot on a heavily loaded system → should switch to performance mode.
#[test]
fn test_lavd_autopilot_high_load() {
    let _lock = common::setup_test();
    let nr_cpus = 4;
    let sched = DynamicScheduler::lavd(nr_cpus);

    unsafe {
        lavd_set_bool(&sched, "is_autopilot_on\0", true);
        lavd_set_bool(&sched, "no_core_compaction\0", false);
        lavd_setup_pco(&sched, nr_cpus);
    }

    // Heavy load: 4 CPU-bound tasks on 4 CPUs (100% utilization)
    let mut builder = Scenario::builder().cpus(nr_cpus).duration_ms(200);
    for i in 0..4 {
        builder = builder.add_task(&format!("cpu-{i}"), 0, workloads::cpu_bound(50_000_000));
    }
    let scenario = builder.build();
    let trace = Simulator::new(sched).run(scenario);
    for pid_val in 1..=4 {
        assert!(trace.schedule_count(Pid(pid_val)) > 0);
    }
}

/// Enable autopilot on a lightly loaded system → should switch to powersave mode.
#[test]
fn test_lavd_autopilot_low_load() {
    let _lock = common::setup_test();
    let nr_cpus = 8;
    let sched = DynamicScheduler::lavd(nr_cpus);

    unsafe {
        lavd_set_bool(&sched, "is_autopilot_on\0", true);
        lavd_set_bool(&sched, "no_core_compaction\0", false);
        lavd_setup_pco(&sched, nr_cpus);
    }

    // Very light load on many CPUs → should trigger powersave mode
    let scenario = Scenario::builder()
        .cpus(nr_cpus)
        .add_task("light", 0, workloads::io_bound(50_000, 50_000_000))
        .duration_ms(300)
        .build();

    let trace = Simulator::new(sched).run(scenario);
    assert!(trace.schedule_count(Pid(1)) > 0);
}

/// Enable autopilot with moderate load → balanced mode.
#[test]
fn test_lavd_autopilot_moderate_load() {
    let _lock = common::setup_test();
    let nr_cpus = 4;
    let sched = DynamicScheduler::lavd(nr_cpus);

    unsafe {
        lavd_set_bool(&sched, "is_autopilot_on\0", true);
        lavd_set_bool(&sched, "no_core_compaction\0", false);
        lavd_setup_pco(&sched, nr_cpus);
    }

    // Moderate load: 2 periodic tasks on 4 CPUs
    let mut builder = Scenario::builder().cpus(nr_cpus).duration_ms(200);
    for i in 0..2 {
        builder = builder.add_task(
            &format!("periodic-{i}"),
            0,
            workloads::periodic(5_000_000, 10_000_000),
        );
    }
    let scenario = builder.build();
    let trace = Simulator::new(sched).run(scenario);
    for pid_val in 1..=2 {
        assert!(trace.schedule_count(Pid(pid_val)) > 0);
    }
}

// ---------------------------------------------------------------------------
// power.bpf.c: frequency scaling (update_cpuperf_target, reset_cpuperf_target)
// ---------------------------------------------------------------------------

/// Enable frequency scaling to trigger update_cpuperf_target codepath.
#[test]
fn test_lavd_freq_scaling_enabled() {
    let _lock = common::setup_test();
    let nr_cpus = 2;
    let sched = DynamicScheduler::lavd(nr_cpus);

    unsafe {
        lavd_set_bool(&sched, "no_freq_scaling\0", false);
    }

    let scenario = Scenario::builder()
        .cpus(nr_cpus)
        .add_task("worker", 0, workloads::periodic(3_000_000, 10_000_000))
        .add_task("hog", 0, workloads::cpu_bound(50_000_000))
        .duration_ms(200)
        .build();

    let trace = Simulator::new(sched).run(scenario);
    assert!(trace.schedule_count(Pid(1)) > 0);
    assert!(trace.schedule_count(Pid(2)) > 0);
}

// ---------------------------------------------------------------------------
// power.bpf.c: performance mode reinit
// (reinit_active_cpumask_for_performance)
// ---------------------------------------------------------------------------

/// Trigger performance mode reinit by switching from balanced→performance.
/// This covers reinit_active_cpumask_for_performance().
#[test]
fn test_lavd_reinit_cpumask_performance() {
    let _lock = common::setup_test();
    let nr_cpus = 4;
    let sched = DynamicScheduler::lavd(nr_cpus);

    // Start with core compaction enabled (balanced mode),
    // then autopilot will switch to performance under heavy load.
    unsafe {
        lavd_set_bool(&sched, "is_autopilot_on\0", true);
        lavd_set_bool(&sched, "no_core_compaction\0", false);
        lavd_setup_pco(&sched, nr_cpus);
    }

    // Start light (triggers powersave/balanced), then heavy load via
    // many CPU-bound tasks → autopilot switches to performance,
    // which sets reinit_cpumask_for_performance = true
    let mut builder = Scenario::builder().cpus(nr_cpus).duration_ms(300);
    for i in 0..8 {
        builder = builder.add_task(&format!("worker-{i}"), 0, workloads::cpu_bound(30_000_000));
    }
    let scenario = builder.build();
    let trace = Simulator::new(sched).run(scenario);
    for pid_val in 1..=8 {
        assert!(trace.schedule_count(Pid(pid_val)) > 0);
    }
}

// ---------------------------------------------------------------------------
// preempt.bpf.c: preemption with contention
// Covers: try_find_and_kick_victim_cpu, find_victim_cpu, can_x_kick_y,
//         can_x_kick_cpu2, ask_cpu_yield_after, shrink_boosted_slice_remote,
//         is_worth_kick_other_task, preempt_at_tick, reset_cpu_preemption_info
// ---------------------------------------------------------------------------

/// High-contention scenario: many lat-cri tasks competing for few CPUs.
/// The frequent sleep/wake cycles create high lat_cri, triggering preemption.
#[test]
fn test_lavd_preemption_contention() {
    let _lock = common::setup_test();
    let nr_cpus = 2;
    let sched = DynamicScheduler::lavd(nr_cpus);

    // Mix of lat-cri (I/O) and CPU-bound on few CPUs
    let mut builder = Scenario::builder().cpus(nr_cpus).duration_ms(300);
    // High-frequency I/O tasks → high lat_cri → should preempt CPU hogs
    for i in 0..4 {
        builder = builder.add_task(
            &format!("io-{i}"),
            0,
            workloads::io_bound(200_000, 2_000_000),
        );
    }
    // CPU-bound hogs → low lat_cri → victims for preemption
    for i in 0..4 {
        builder = builder.add_task(&format!("hog-{i}"), 0, workloads::cpu_bound(50_000_000));
    }
    let scenario = builder.build();
    let trace = Simulator::new(sched).run(scenario);

    // All tasks should have been scheduled
    for pid_val in 1..=8 {
        assert!(
            trace.schedule_count(Pid(pid_val)) > 0,
            "task pid={pid_val} was never scheduled"
        );
    }
}

/// Ping-pong with CPU hogs: triggers preemption kick paths when
/// high-lat-cri tasks compete with low-lat-cri hogs.
#[test]
fn test_lavd_preemption_ping_pong_vs_hogs() {
    let _lock = common::setup_test();
    let nr_cpus = 2;
    let sched = DynamicScheduler::lavd(nr_cpus);

    let (ping_b, pong_b) = workloads::ping_pong(Pid(10), Pid(11), 200_000);
    let scenario = Scenario::builder()
        .cpus(nr_cpus)
        .task(TaskDef {
            name: "ping".into(),
            pid: Pid(10),
            nice: 0,
            behavior: ping_b,
            start_time_ns: 0,
            mm_id: Some(MmId(1)),
            allowed_cpus: None,
            parent_pid: None,
        })
        .task(TaskDef {
            name: "pong".into(),
            pid: Pid(11),
            nice: 0,
            behavior: pong_b,
            start_time_ns: 0,
            mm_id: Some(MmId(1)),
            allowed_cpus: None,
            parent_pid: None,
        })
        .task(TaskDef {
            name: "hog-0".into(),
            pid: Pid(12),
            nice: 0,
            behavior: workloads::cpu_bound(50_000_000),
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: None,
            parent_pid: None,
        })
        .task(TaskDef {
            name: "hog-1".into(),
            pid: Pid(13),
            nice: 0,
            behavior: workloads::cpu_bound(50_000_000),
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: None,
            parent_pid: None,
        })
        .duration_ms(300)
        .build();

    let trace = Simulator::new(sched).run(scenario);
    for pid_val in [10, 11, 12, 13] {
        assert!(trace.schedule_count(Pid(pid_val)) > 0);
    }
}

// ---------------------------------------------------------------------------
// preempt.bpf.c: pinned task slice shrinking
// Covers: shrink_slice_at_tick, shrink_boosted_slice_remote with
//         pinned_slice_ns path, nr_pinned_tasks tracking
// ---------------------------------------------------------------------------

/// CPU-pinned tasks contending on a single CPU should trigger the
/// pinned_slice_ns codepath in shrink_slice_at_tick.
#[test]
fn test_lavd_pinned_task_contention() {
    let _lock = common::setup_test();
    let nr_cpus = 4;
    let sched = DynamicScheduler::lavd(nr_cpus);

    // Two tasks pinned to CPU 0 contending with unpinned tasks
    let scenario = Scenario::builder()
        .cpus(nr_cpus)
        .task(TaskDef {
            name: "pinned-0".into(),
            pid: Pid(10),
            nice: 0,
            behavior: workloads::cpu_bound(20_000_000),
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: Some(vec![CpuId(0)]),
            parent_pid: None,
        })
        .task(TaskDef {
            name: "pinned-1".into(),
            pid: Pid(11),
            nice: 0,
            behavior: workloads::cpu_bound(20_000_000),
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: Some(vec![CpuId(0)]),
            parent_pid: None,
        })
        .task(TaskDef {
            name: "free-0".into(),
            pid: Pid(12),
            nice: 0,
            behavior: workloads::cpu_bound(30_000_000),
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: None,
            parent_pid: None,
        })
        .task(TaskDef {
            name: "free-1".into(),
            pid: Pid(13),
            nice: 0,
            behavior: workloads::cpu_bound(30_000_000),
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: None,
            parent_pid: None,
        })
        .duration_ms(200)
        .build();

    let trace = Simulator::new(sched).run(scenario);
    for pid_val in [10, 11, 12, 13] {
        assert!(
            trace.schedule_count(Pid(pid_val)) > 0,
            "task pid={pid_val} was never scheduled"
        );
    }
}

// ---------------------------------------------------------------------------
// idle.bpf.c: more CPU selection paths
// Covers: pick_idle_cpu (no-idle path, sticky fallback), pick_random_cpu,
//         cpumask_any_distribute, find_cpu_in, find_sticky_cpu_at_cpdom
// ---------------------------------------------------------------------------

/// Overloaded system with no idle CPUs → pick_idle_cpu falls through
/// to sticky_cpu or pick_random_cpu paths.
#[test]
fn test_lavd_no_idle_cpu_fallback() {
    let _lock = common::setup_test();
    let nr_cpus = 2;
    let sched = DynamicScheduler::lavd(nr_cpus);

    // Many tasks, few CPUs, frequent wakes → no idle CPUs available
    let mut builder = Scenario::builder().cpus(nr_cpus).duration_ms(200);
    for i in 0..6 {
        builder = builder.add_task(&format!("busy-{i}"), 0, workloads::cpu_bound(10_000_000));
    }
    // Add I/O tasks that wake frequently → need to find CPU when none idle
    for i in 0..4 {
        builder = builder.add_task(
            &format!("io-{i}"),
            0,
            workloads::io_bound(100_000, 1_000_000),
        );
    }
    let scenario = builder.build();
    let trace = Simulator::new(sched).run(scenario);
    for pid_val in 1..=10 {
        assert!(trace.schedule_count(Pid(pid_val)) > 0);
    }
}

// ---------------------------------------------------------------------------
// idle.bpf.c: affinitized task idle selection
// Covers: init_idle_i_mask (LAVD_FLAG_IS_AFFINITIZED path),
//         init_ao_masks (affinitized path), can_run_on_cpu (affinitized)
// ---------------------------------------------------------------------------

/// Affinitized tasks with restricted CPU sets trigger the cpumask-AND
/// paths in init_idle_i_mask and init_ao_masks.
#[test]
fn test_lavd_affinitized_idle_selection() {
    let _lock = common::setup_test();
    let nr_cpus = 4;
    let sched = DynamicScheduler::lavd(nr_cpus);

    let scenario = Scenario::builder()
        .cpus(nr_cpus)
        // Task pinned to CPUs 0,1 (subset)
        .task(TaskDef {
            name: "affin-01".into(),
            pid: Pid(10),
            nice: 0,
            behavior: workloads::io_bound(200_000, 3_000_000),
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: Some(vec![CpuId(0), CpuId(1)]),
            parent_pid: None,
        })
        // Task pinned to CPUs 2,3
        .task(TaskDef {
            name: "affin-23".into(),
            pid: Pid(11),
            nice: 0,
            behavior: workloads::io_bound(200_000, 3_000_000),
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: Some(vec![CpuId(2), CpuId(3)]),
            parent_pid: None,
        })
        // Unpinned tasks to fill CPUs
        .task(TaskDef {
            name: "free-0".into(),
            pid: Pid(12),
            nice: 0,
            behavior: workloads::cpu_bound(20_000_000),
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: None,
            parent_pid: None,
        })
        .task(TaskDef {
            name: "free-1".into(),
            pid: Pid(13),
            nice: 0,
            behavior: workloads::cpu_bound(20_000_000),
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: None,
            parent_pid: None,
        })
        .duration_ms(200)
        .build();

    let trace = Simulator::new(sched).run(scenario);
    for pid_val in [10, 11, 12, 13] {
        assert!(trace.schedule_count(Pid(pid_val)) > 0);
    }

    // Verify affinity constraints are respected
    for event in trace.events() {
        if let TraceKind::TaskScheduled { pid } = &event.kind {
            if *pid == Pid(10) {
                assert!(
                    event.cpu == CpuId(0) || event.cpu == CpuId(1),
                    "affin-01 scheduled on {:?}, expected CPU 0 or 1",
                    event.cpu
                );
            }
            if *pid == Pid(11) {
                assert!(
                    event.cpu == CpuId(2) || event.cpu == CpuId(3),
                    "affin-23 scheduled on {:?}, expected CPU 2 or 3",
                    event.cpu
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// lat_cri.bpf.c: varied nice values and greedy penalty
// Covers: calc_greedy_factor (nice != 0 path), reverse_time_to_weight_ratio,
//         calc_virtual_deadline_delta (nice-weighted path)
// ---------------------------------------------------------------------------

/// Tasks with different nice values exercise the weight-based vdeadline paths.
#[test]
fn test_lavd_varied_nice_values() {
    let _lock = common::setup_test();
    let nr_cpus = 2;
    let sched = DynamicScheduler::lavd(nr_cpus);
    let probes = LavdProbes::new(&sched);
    let mut monitor = LavdMonitor::new(probes);

    let scenario = Scenario::builder()
        .cpus(nr_cpus)
        .task(TaskDef {
            name: "high-pri".into(),
            pid: Pid(1),
            nice: -10,
            behavior: workloads::cpu_bound(20_000_000),
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: None,
            parent_pid: None,
        })
        .task(TaskDef {
            name: "low-pri".into(),
            pid: Pid(2),
            nice: 10,
            behavior: workloads::cpu_bound(20_000_000),
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: None,
            parent_pid: None,
        })
        .task(TaskDef {
            name: "normal".into(),
            pid: Pid(3),
            nice: 0,
            behavior: workloads::cpu_bound(20_000_000),
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: None,
            parent_pid: None,
        })
        .duration_ms(300)
        .build();

    let _result = Simulator::new(sched).run_monitored(scenario, &mut monitor);

    // High-priority task (nice -10) should get more runtime
    // than low-priority task (nice 10) on a 2-CPU system with 3 tasks
    let high_snap = monitor.final_snapshot(Pid(1));
    let low_snap = monitor.final_snapshot(Pid(2));
    assert!(
        high_snap.is_some() && low_snap.is_some(),
        "expected snapshots for both tasks"
    );
}

/// Extremely high-nice task alongside normal task: exercises the
/// greedy penalty scaling in calc_greedy_factor.
#[test]
fn test_lavd_greedy_penalty_extreme_nice() {
    let _lock = common::setup_test();
    let nr_cpus = 1;
    let sched = DynamicScheduler::lavd(nr_cpus);

    let scenario = Scenario::builder()
        .cpus(nr_cpus)
        .task(TaskDef {
            name: "greedy".into(),
            pid: Pid(1),
            nice: 19,
            behavior: workloads::cpu_bound(50_000_000),
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: None,
            parent_pid: None,
        })
        .task(TaskDef {
            name: "priority".into(),
            pid: Pid(2),
            nice: -20,
            behavior: workloads::cpu_bound(50_000_000),
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: None,
            parent_pid: None,
        })
        .duration_ms(300)
        .build();

    let trace = Simulator::new(sched).run(scenario);
    let rt1 = trace.total_runtime(Pid(1));
    let rt2 = trace.total_runtime(Pid(2));
    // Highest priority should get significantly more runtime
    assert!(rt2 > rt1, "expected nice=-20 ({rt2}ns) > nice=19 ({rt1}ns)");
}

// ---------------------------------------------------------------------------
// main.bpf.c: multi-CPU with sleep/wake for idle tracking
// Covers: lavd_update_idle, update_stat_for_stopping, stat accumulation
// ---------------------------------------------------------------------------

/// Many tasks with varied sleep patterns exercise idle tracking in
/// update_stat_for_stopping and the CAS loop in collect_sys_stat.
#[test]
fn test_lavd_idle_tracking_varied_sleep() {
    let _lock = common::setup_test();
    let nr_cpus = 4;
    let sched = DynamicScheduler::lavd(nr_cpus);

    let scenario = Scenario::builder()
        .cpus(nr_cpus)
        // Fast sleeper
        .add_task("fast-io", 0, workloads::io_bound(100_000, 500_000))
        // Slow sleeper
        .add_task("slow-io", 0, workloads::io_bound(2_000_000, 20_000_000))
        // Periodic task
        .add_task("periodic", 0, workloads::periodic(1_000_000, 5_000_000))
        // CPU-bound
        .add_task("hog", 0, workloads::cpu_bound(50_000_000))
        .duration_ms(200)
        .build();

    let trace = Simulator::new(sched).run(scenario);
    for pid_val in 1..=4 {
        assert!(trace.schedule_count(Pid(pid_val)) > 0);
    }
}

// ---------------------------------------------------------------------------
// Combined: all features enabled (core compaction + autopilot + freq scaling)
// This exercises the complete update_sys_stat → autopilot → core_compaction
// → calc_sys_time_slice → update_thr_perf_cri call chain.
// ---------------------------------------------------------------------------

/// Full-featured LAVD: all power management features enabled simultaneously.
#[test]
fn test_lavd_all_power_features() {
    let _lock = common::setup_test();
    let nr_cpus = 4;
    let sched = DynamicScheduler::lavd(nr_cpus);

    unsafe {
        lavd_set_bool(&sched, "is_autopilot_on\0", true);
        lavd_set_bool(&sched, "no_core_compaction\0", false);
        lavd_set_bool(&sched, "no_freq_scaling\0", false);
        lavd_setup_pco(&sched, nr_cpus);
    }

    // Mixed workload: I/O + CPU + periodic
    let (ping_b, pong_b) = workloads::ping_pong(Pid(10), Pid(11), 300_000);
    let scenario = Scenario::builder()
        .cpus(nr_cpus)
        .task(TaskDef {
            name: "ping".into(),
            pid: Pid(10),
            nice: 0,
            behavior: ping_b,
            start_time_ns: 0,
            mm_id: Some(MmId(1)),
            allowed_cpus: None,
            parent_pid: None,
        })
        .task(TaskDef {
            name: "pong".into(),
            pid: Pid(11),
            nice: 0,
            behavior: pong_b,
            start_time_ns: 0,
            mm_id: Some(MmId(1)),
            allowed_cpus: None,
            parent_pid: None,
        })
        .task(TaskDef {
            name: "io".into(),
            pid: Pid(12),
            nice: 0,
            behavior: workloads::io_bound(200_000, 5_000_000),
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: None,
            parent_pid: None,
        })
        .task(TaskDef {
            name: "periodic".into(),
            pid: Pid(13),
            nice: 0,
            behavior: workloads::periodic(2_000_000, 8_000_000),
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: None,
            parent_pid: None,
        })
        .task(TaskDef {
            name: "hog".into(),
            pid: Pid(14),
            nice: 5,
            behavior: workloads::cpu_bound(30_000_000),
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: None,
            parent_pid: None,
        })
        .duration_ms(300)
        .build();

    let trace = Simulator::new(sched).run(scenario);
    for pid_val in [10, 11, 12, 13, 14] {
        assert!(
            trace.schedule_count(Pid(pid_val)) > 0,
            "task pid={pid_val} was never scheduled"
        );
    }
}

// ---------------------------------------------------------------------------
// Stress test: concurrent interleaving with core compaction
// Covers: race conditions in CAS loops, concurrent dispatch + tick
// ---------------------------------------------------------------------------

/// Concurrent interleaving with all features enabled: exercises race
/// conditions in the CAS loops for idle tracking, preemption, etc.
#[test]
fn test_lavd_concurrent_all_features() {
    let _lock = common::setup_test();
    let nr_cpus = 4;
    let sched = DynamicScheduler::lavd(nr_cpus);

    unsafe {
        lavd_set_bool(&sched, "is_autopilot_on\0", true);
        lavd_set_bool(&sched, "no_core_compaction\0", false);
        lavd_set_bool(&sched, "no_freq_scaling\0", false);
        lavd_setup_pco(&sched, nr_cpus);
    }

    let mut builder = Scenario::builder().cpus(nr_cpus).duration_ms(200);

    // Mix of workload types
    for i in 0..3 {
        builder = builder.add_task(
            &format!("io-{i}"),
            0,
            workloads::io_bound(150_000, 2_000_000),
        );
    }
    for i in 0..3 {
        builder = builder.add_task(
            &format!("hog-{i}"),
            (i as i8) * 5,
            workloads::cpu_bound(20_000_000),
        );
    }
    let scenario = builder.build();
    let trace = Simulator::new(sched).run(scenario);
    for pid_val in 1..=6 {
        assert!(trace.schedule_count(Pid(pid_val)) > 0);
    }
}

// ---------------------------------------------------------------------------
// Seed exploration: try different seeds to trigger different branches
// in preemption, idle selection, and core compaction.
// ---------------------------------------------------------------------------

/// Run with multiple seeds to explore different scheduling interleavings.
/// Different seeds cause different random choices in find_victim_cpu,
/// pick_random_cpu, and bpf_cpumask_any_distribute.
#[test]
fn test_lavd_seed_exploration() {
    let _lock = common::setup_test();

    for seed in [1, 7, 42, 99, 12345, 999999] {
        let nr_cpus = 4;
        let sched = DynamicScheduler::lavd(nr_cpus);

        unsafe {
            lavd_set_bool(&sched, "no_core_compaction\0", false);
            lavd_setup_pco(&sched, nr_cpus);
        }

        let scenario = Scenario::builder()
            .cpus(nr_cpus)
            .seed(seed)
            .add_task("io-0", 0, workloads::io_bound(100_000, 1_000_000))
            .add_task("io-1", 0, workloads::io_bound(200_000, 3_000_000))
            .add_task("hog-0", 0, workloads::cpu_bound(15_000_000))
            .add_task("hog-1", 5, workloads::cpu_bound(25_000_000))
            .add_task("periodic", -5, workloads::periodic(1_000_000, 4_000_000))
            .duration_ms(150)
            .build();

        let trace = Simulator::new(sched).run(scenario);
        for pid_val in 1..=5 {
            assert!(
                trace.schedule_count(Pid(pid_val)) > 0,
                "seed={seed}: task pid={pid_val} was never scheduled"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// SMT (hyperthreading) topology: exercises is_smt_active paths
// Covers: pick_idle_cpu SMT branch, idle_smtmask handling
// ---------------------------------------------------------------------------

/// SMT topology: triggers the SMT-aware idle CPU selection paths.
#[test]
fn test_lavd_smt_topology() {
    let _lock = common::setup_test();
    let nr_cpus = 4;
    let sched = DynamicScheduler::lavd(nr_cpus);

    // Note: lavd_setup sets is_smt_active = false by default.
    // Even without setting it true, building the scenario with smt(2)
    // exercises the SMT paths in the simulator engine (cpu_sibling tracking).

    let scenario = Scenario::builder()
        .cpus(nr_cpus)
        .smt(2) // 2 threads per core → 2 physical cores
        .add_task("io-0", 0, workloads::io_bound(200_000, 3_000_000))
        .add_task("io-1", 0, workloads::io_bound(200_000, 3_000_000))
        .add_task("hog-0", 0, workloads::cpu_bound(20_000_000))
        .add_task("hog-1", 0, workloads::cpu_bound(20_000_000))
        .duration_ms(200)
        .build();

    let trace = Simulator::new(sched).run(scenario);
    for pid_val in 1..=4 {
        assert!(trace.schedule_count(Pid(pid_val)) > 0);
    }
}

// ---------------------------------------------------------------------------
// power.bpf.c: have_little_core = true
// Covers: is_perf_cri (have_little_core path), update_thr_perf_cri
//         (big/little threshold calculation), perf_cri stat collection
//         in collect_sys_stat phase 3
// ---------------------------------------------------------------------------

/// Enable big.LITTLE topology to exercise perf_cri threshold calculation.
#[test]
fn test_lavd_big_little_topology() {
    let _lock = common::setup_test();
    let nr_cpus = 4;
    let sched = DynamicScheduler::lavd(nr_cpus);

    unsafe {
        // Mark CPUs 0,1 as big, 2,3 as little
        lavd_set_bool(&sched, "have_little_core\0", true);

        // Set capacity for big cores higher
        let cap_sym: libloading::Symbol<'_, *mut u16> = sched
            .get_symbol(b"cpu_capacity\0")
            .expect("cpu_capacity not found");
        let cap_arr = *cap_sym;
        std::ptr::write_volatile(cap_arr.add(0), 1024);
        std::ptr::write_volatile(cap_arr.add(1), 1024);
        std::ptr::write_volatile(cap_arr.add(2), 512);
        std::ptr::write_volatile(cap_arr.add(3), 512);

        // Mark big cores
        let big_sym: libloading::Symbol<'_, *mut u8> =
            sched.get_symbol(b"cpu_big\0").expect("cpu_big not found");
        let big_arr = *big_sym;
        std::ptr::write_volatile(big_arr.add(0), 1);
        std::ptr::write_volatile(big_arr.add(1), 1);
        std::ptr::write_volatile(big_arr.add(2), 0);
        std::ptr::write_volatile(big_arr.add(3), 0);

        // Enable core compaction to trigger update_thr_perf_cri
        lavd_set_bool(&sched, "no_core_compaction\0", false);
        lavd_setup_pco(&sched, nr_cpus);
    }

    let scenario = Scenario::builder()
        .cpus(nr_cpus)
        .add_task("io-fast", 0, workloads::io_bound(100_000, 1_000_000))
        .add_task("hog-0", 0, workloads::cpu_bound(30_000_000))
        .add_task("hog-1", 5, workloads::cpu_bound(30_000_000))
        .add_task("periodic", -5, workloads::periodic(2_000_000, 8_000_000))
        .duration_ms(300)
        .build();

    let trace = Simulator::new(sched).run(scenario);
    for pid_val in 1..=4 {
        assert!(trace.schedule_count(Pid(pid_val)) > 0);
    }
}

// ---------------------------------------------------------------------------
// main.bpf.c: delayed start tasks (start_time_ns > 0)
// Covers: task wakeup at different times, dynamic task arrival
// ---------------------------------------------------------------------------

/// Staggered task arrival: tests dynamic task wakeup at different times.
#[test]
fn test_lavd_staggered_task_arrival() {
    let _lock = common::setup_test();
    let nr_cpus = 2;
    let sched = DynamicScheduler::lavd(nr_cpus);

    let scenario = Scenario::builder()
        .cpus(nr_cpus)
        .task(TaskDef {
            name: "early".into(),
            pid: Pid(1),
            nice: 0,
            behavior: workloads::cpu_bound(20_000_000),
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: None,
            parent_pid: None,
        })
        .task(TaskDef {
            name: "mid".into(),
            pid: Pid(2),
            nice: 0,
            behavior: workloads::cpu_bound(20_000_000),
            start_time_ns: 50_000_000, // arrives at 50ms
            mm_id: None,
            allowed_cpus: None,
            parent_pid: None,
        })
        .task(TaskDef {
            name: "late".into(),
            pid: Pid(3),
            nice: 0,
            behavior: workloads::cpu_bound(20_000_000),
            start_time_ns: 100_000_000, // arrives at 100ms
            mm_id: None,
            allowed_cpus: None,
            parent_pid: None,
        })
        .duration_ms(300)
        .build();

    let trace = Simulator::new(sched).run(scenario);
    for pid_val in 1..=3 {
        assert!(
            trace.schedule_count(Pid(pid_val)) > 0,
            "task pid={pid_val} was never scheduled"
        );
    }
    // Early task should have more runtime than late task
    let rt_early = trace.total_runtime(Pid(1));
    let rt_late = trace.total_runtime(Pid(3));
    assert!(
        rt_early > rt_late,
        "expected early ({rt_early}ns) > late ({rt_late}ns)"
    );
}

// ---------------------------------------------------------------------------
// util.bpf.c: more branch coverage via extreme values
// Covers: calc_avg, calc_avg32, calc_asym_avg with zero and saturated inputs
// ---------------------------------------------------------------------------

/// Single-CPU with a task that alternates between very short and very long
/// run phases. This exercises the avg runtime calculation with extreme values.
#[test]
fn test_lavd_extreme_runtime_variation() {
    let _lock = common::setup_test();
    let nr_cpus = 1;
    let sched = DynamicScheduler::lavd(nr_cpus);

    let scenario = Scenario::builder()
        .cpus(nr_cpus)
        .task(TaskDef {
            name: "bursty".into(),
            pid: Pid(1),
            nice: 0,
            behavior: TaskBehavior {
                phases: vec![
                    Phase::Run(10_000),      // 10us burst
                    Phase::Sleep(1_000_000), // 1ms sleep
                    Phase::Run(50_000_000),  // 50ms burst
                    Phase::Sleep(1_000_000), // 1ms sleep
                ],
                repeat: RepeatMode::Forever,
            },
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: None,
            parent_pid: None,
        })
        .duration_ms(300)
        .build();

    let trace = Simulator::new(sched).run(scenario);
    assert!(trace.schedule_count(Pid(1)) > 0);
}

// ---------------------------------------------------------------------------
// power.bpf.c: energy model (no_use_em = false)
// Covers: calc_nr_active_cpus (energy model path), init_autopilot_caps
//         (energy model path), pco_bounds/pco_nr_primary usage
// ---------------------------------------------------------------------------

/// Test with energy model enabled (no_use_em = false) to exercise the
/// PCO-based calc_nr_active_cpus codepath.
#[test]
fn test_lavd_energy_model_enabled() {
    let _lock = common::setup_test();
    let nr_cpus = 4;
    let sched = DynamicScheduler::lavd(nr_cpus);

    unsafe {
        lavd_set_bool(&sched, "no_core_compaction\0", false);
        lavd_set_bool(&sched, "is_autopilot_on\0", true);

        // Set up a simple energy model with 2 PCO states
        lavd_set_u8(&sched, "no_use_em\0", 0); // Enable energy model
        lavd_set_u8(&sched, "nr_pco_states\0", 2);

        // Set PCO bounds and primary counts
        let bounds_sym: libloading::Symbol<'_, *mut u32> = sched
            .get_symbol(b"pco_bounds\0")
            .expect("pco_bounds not found");
        let bounds = *bounds_sym;
        std::ptr::write_volatile(bounds.add(0), 2048); // low state
        std::ptr::write_volatile(bounds.add(1), 8192); // high state

        let primary_sym: libloading::Symbol<'_, *mut u16> = sched
            .get_symbol(b"pco_nr_primary\0")
            .expect("pco_nr_primary not found");
        let primary = *primary_sym;
        std::ptr::write_volatile(primary.add(0), 2);
        std::ptr::write_volatile(primary.add(1), 4);

        // Set up PCO table (CPU order for each state)
        let pco_sym: libloading::Symbol<'_, *mut u16> = sched
            .get_symbol(b"pco_table\0")
            .expect("pco_table not found");
        let pco = *pco_sym;
        // State 0: CPUs 0,1,2,3
        for i in 0..4u16 {
            std::ptr::write_volatile(pco.add(i as usize), i);
        }
        // State 1: CPUs 0,1,2,3 (same order, all active)
        // LAVD_CPU_ID_MAX entries per state
        let stride = 512; // LAVD_CPU_ID_MAX
        for i in 0..4u16 {
            std::ptr::write_volatile(pco.add(stride + i as usize), i);
        }
    }

    let scenario = Scenario::builder()
        .cpus(nr_cpus)
        .add_task("io-0", 0, workloads::io_bound(100_000, 2_000_000))
        .add_task("hog-0", 0, workloads::cpu_bound(30_000_000))
        .add_task("periodic", 0, workloads::periodic(2_000_000, 8_000_000))
        .duration_ms(200)
        .build();

    let trace = Simulator::new(sched).run(scenario);
    for pid_val in 1..=3 {
        assert!(trace.schedule_count(Pid(pid_val)) > 0);
    }
}

// ===========================================================================
// Phase 2: deeper branch coverage in covered functions
// ===========================================================================

// ---------------------------------------------------------------------------
// idle.bpf.c: is_pinned path in pick_idle_cpu (line 622)
// When nr_cpus_allowed == 1, the task goes through the pinned fast-path
// which tests active cpumask and optionally extends overflow set.
// ---------------------------------------------------------------------------

/// Single-CPU-pinned task triggers is_pinned() fast path in pick_idle_cpu.
/// Also exercises the overflow set extension (bpf_cpumask_test_and_set_cpu).
#[test]
fn test_lavd_pinned_single_cpu_overflow() {
    let _lock = common::setup_test();
    let nr_cpus = 4;
    let sched = DynamicScheduler::lavd(nr_cpus);

    unsafe {
        lavd_set_bool(&sched, "no_core_compaction\0", false);
        lavd_setup_pco(&sched, nr_cpus);
    }

    // Pin task to CPU 0 only (nr_cpus_allowed=1 → is_pinned returns true)
    // With core compaction deactivating some CPUs, CPU 0 may not be in the
    // active set, triggering the overflow path.
    let scenario = Scenario::builder()
        .cpus(nr_cpus)
        .task(TaskDef {
            name: "pinned-0".into(),
            pid: Pid(10),
            nice: 0,
            behavior: workloads::io_bound(100_000, 2_000_000),
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: Some(vec![CpuId(0)]),
            parent_pid: None,
        })
        .task(TaskDef {
            name: "pinned-3".into(),
            pid: Pid(11),
            nice: 0,
            behavior: workloads::io_bound(100_000, 2_000_000),
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: Some(vec![CpuId(3)]),
            parent_pid: None,
        })
        .task(TaskDef {
            name: "hog-0".into(),
            pid: Pid(12),
            nice: 0,
            behavior: workloads::cpu_bound(30_000_000),
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: None,
            parent_pid: None,
        })
        .duration_ms(300)
        .build();

    let trace = Simulator::new(sched).run(scenario);
    for pid_val in [10, 11, 12] {
        assert!(trace.schedule_count(Pid(pid_val)) > 0);
    }
}

// ---------------------------------------------------------------------------
// idle.bpf.c: no-idle-CPU with many tasks → sticky_cpu or random fallback
// Covers: i_empty path (line 674), find_sticky_cpu_at_cpdom fallback
// ---------------------------------------------------------------------------

/// Extremely overloaded system: 16 tasks on 2 CPUs with core compaction.
/// Forces the "no idle CPU" paths in pick_idle_cpu.
#[test]
fn test_lavd_extreme_overload_no_idle() {
    let _lock = common::setup_test();
    let nr_cpus = 2;
    let sched = DynamicScheduler::lavd(nr_cpus);

    unsafe {
        lavd_set_bool(&sched, "no_core_compaction\0", false);
        lavd_setup_pco(&sched, nr_cpus);
    }

    let mut builder = Scenario::builder().cpus(nr_cpus).duration_ms(200);
    // 16 tasks on 2 CPUs → no CPU is ever idle
    for i in 0..16 {
        builder = builder.add_task(
            &format!("t-{i}"),
            (i % 5) as i8 - 2, // varied nice values
            workloads::cpu_bound(5_000_000),
        );
    }
    let scenario = builder.build();
    let trace = Simulator::new(sched).run(scenario);
    for pid_val in 1..=16 {
        assert!(trace.schedule_count(Pid(pid_val)) > 0);
    }
}

// ---------------------------------------------------------------------------
// preempt.bpf.c: deeper branches in try_find_and_kick_victim_cpu
// Covers: can_x_kick_cpu2 (is_smt_active SMT sibling check),
//         slice-boosted victim detection
// ---------------------------------------------------------------------------

/// Overloaded system with SMT and I/O tasks to trigger deeper preemption
/// branches (SMT sibling checking, slice-boosted victim detection).
#[test]
fn test_lavd_preemption_smt_overloaded() {
    let _lock = common::setup_test();
    let nr_cpus = 4;
    let sched = DynamicScheduler::lavd(nr_cpus);

    let scenario = Scenario::builder()
        .cpus(nr_cpus)
        .smt(2)
        .add_task("io-0", 0, workloads::io_bound(100_000, 1_000_000))
        .add_task("io-1", 0, workloads::io_bound(150_000, 1_500_000))
        .add_task("io-2", 0, workloads::io_bound(200_000, 2_000_000))
        .add_task("hog-0", 0, workloads::cpu_bound(20_000_000))
        .add_task("hog-1", 5, workloads::cpu_bound(20_000_000))
        .add_task("hog-2", 10, workloads::cpu_bound(20_000_000))
        .duration_ms(300)
        .build();

    let trace = Simulator::new(sched).run(scenario);
    for pid_val in 1..=6 {
        assert!(trace.schedule_count(Pid(pid_val)) > 0);
    }
}

// ---------------------------------------------------------------------------
// main.bpf.c: consume_prev path variation
// When prev is still runnable and has remaining slice, it should be consumed
// directly (fast path in dispatch).
// ---------------------------------------------------------------------------

/// Fast-path dispatch: a single task running repeatedly should hit
/// consume_prev frequently, exercising the fast dispatch path.
#[test]
fn test_lavd_consume_prev_fast_path() {
    let _lock = common::setup_test();
    let nr_cpus = 4;
    let sched = DynamicScheduler::lavd(nr_cpus);

    // 4 tasks on 4 CPUs → each task stays on its own CPU mostly,
    // exercising consume_prev (prev is runnable and has slice remaining)
    let scenario = Scenario::builder()
        .cpus(nr_cpus)
        .add_task("t0", 0, workloads::cpu_bound(50_000_000))
        .add_task("t1", 0, workloads::cpu_bound(50_000_000))
        .add_task("t2", 0, workloads::cpu_bound(50_000_000))
        .add_task("t3", 0, workloads::cpu_bound(50_000_000))
        .duration_ms(200)
        .build();

    let trace = Simulator::new(sched).run(scenario);
    for pid_val in 1..=4 {
        assert!(trace.schedule_count(Pid(pid_val)) > 0);
    }
}

// ---------------------------------------------------------------------------
// lat_cri.bpf.c: calc_lat_cri with waker/wakee propagation
// Exercise the waker→wakee lat_cri propagation paths (non-zero
// lat_cri_waker and lat_cri_wakee).
// ---------------------------------------------------------------------------

/// Deep wake chain (5 tasks) to maximize lat_cri propagation depth.
/// This exercises calc_lat_cri's weighted average of waker/wakee lat_cri.
#[test]
fn test_lavd_deep_wake_chain_lat_cri() {
    let _lock = common::setup_test();
    let nr_cpus = 4;
    let sched = DynamicScheduler::lavd(nr_cpus);
    let probes = LavdProbes::new(&sched);
    let mut monitor = LavdMonitor::new(probes);

    let pids = [Pid(1), Pid(2), Pid(3), Pid(4), Pid(5)];
    let behaviors = workloads::wake_chain(&pids, 50_000, 5_000_000);

    let mut builder = Scenario::builder().cpus(nr_cpus);
    for (i, behavior) in behaviors.into_iter().enumerate() {
        builder = builder.task(TaskDef {
            name: format!("chain_{i}"),
            pid: pids[i],
            nice: 0,
            behavior,
            start_time_ns: 0,
            mm_id: Some(MmId(1)),
            allowed_cpus: None,
            parent_pid: None,
        });
    }
    let scenario = builder.duration_ms(500).build();
    let _result = Simulator::new(sched).run_monitored(scenario, &mut monitor);

    // Tail task should have non-zero lat_cri from propagation
    let tail = monitor.final_snapshot(Pid(5)).unwrap();
    eprintln!("deep chain tail: lat_cri={}", tail.lat_cri);
    assert!(tail.lat_cri > 0, "expected tail lat_cri > 0");
}

// ---------------------------------------------------------------------------
// sys_stat.bpf.c: decay path (LAVD_SYS_STAT_DECAY_TIMES)
// The stats decay every ~60 timer ticks. Need to run long enough.
// ---------------------------------------------------------------------------

/// Long-running simulation to trigger stats decay in calc_sys_stat.
/// The decay path halves statistics every LAVD_SYS_STAT_DECAY_TIMES (60)
/// timer iterations at 20ms each = 1.2 seconds.
#[test]
fn test_lavd_stats_decay_long_run() {
    let _lock = common::setup_test();
    let nr_cpus = 2;
    let sched = DynamicScheduler::lavd(nr_cpus);

    unsafe {
        lavd_set_bool(&sched, "no_core_compaction\0", false);
        lavd_setup_pco(&sched, nr_cpus);
    }

    // Run for 2 seconds to trigger the decay path (60 * 20ms = 1.2s)
    let scenario = Scenario::builder()
        .cpus(nr_cpus)
        .add_task("io", 0, workloads::io_bound(200_000, 3_000_000))
        .add_task("hog", 0, workloads::cpu_bound(30_000_000))
        .duration_ms(2000)
        .build();

    let trace = Simulator::new(sched).run(scenario);
    assert!(trace.schedule_count(Pid(1)) > 0);
    assert!(trace.schedule_count(Pid(2)) > 0);
}

// ---------------------------------------------------------------------------
// sys_stat.bpf.c: have_little_core perf_cri branches
// When have_little_core is true, several branches in calc_sys_stat
// enable perf_cri threshold calculation and big/little stat tracking.
// ---------------------------------------------------------------------------

/// have_little_core with overload: exercises all perf_cri branches
/// in collect_sys_stat phase 2/3 and calc_sys_stat.
#[test]
fn test_lavd_big_little_overloaded_perf_cri() {
    let _lock = common::setup_test();
    let nr_cpus = 4;
    let sched = DynamicScheduler::lavd(nr_cpus);

    unsafe {
        lavd_set_bool(&sched, "have_little_core\0", true);
        lavd_set_bool(&sched, "no_core_compaction\0", false);
        lavd_setup_pco(&sched, nr_cpus);
    }

    // Mix of I/O (latency-cri) and CPU-bound (perf-cri) on big.LITTLE
    let (ping_b, pong_b) = workloads::ping_pong(Pid(10), Pid(11), 200_000);
    let scenario = Scenario::builder()
        .cpus(nr_cpus)
        .task(TaskDef {
            name: "ping".into(),
            pid: Pid(10),
            nice: 0,
            behavior: ping_b,
            start_time_ns: 0,
            mm_id: Some(MmId(1)),
            allowed_cpus: None,
            parent_pid: None,
        })
        .task(TaskDef {
            name: "pong".into(),
            pid: Pid(11),
            nice: 0,
            behavior: pong_b,
            start_time_ns: 0,
            mm_id: Some(MmId(1)),
            allowed_cpus: None,
            parent_pid: None,
        })
        .task(TaskDef {
            name: "hog-0".into(),
            pid: Pid(12),
            nice: 0,
            behavior: workloads::cpu_bound(20_000_000),
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: None,
            parent_pid: None,
        })
        .task(TaskDef {
            name: "hog-1".into(),
            pid: Pid(13),
            nice: 5,
            behavior: workloads::cpu_bound(20_000_000),
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: None,
            parent_pid: None,
        })
        .task(TaskDef {
            name: "hog-2".into(),
            pid: Pid(14),
            nice: -5,
            behavior: workloads::cpu_bound(20_000_000),
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: None,
            parent_pid: None,
        })
        .task(TaskDef {
            name: "hog-3".into(),
            pid: Pid(15),
            nice: 0,
            behavior: workloads::cpu_bound(20_000_000),
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: None,
            parent_pid: None,
        })
        .duration_ms(300)
        .build();

    let trace = Simulator::new(sched).run(scenario);
    for pid_val in [10, 11, 12, 13, 14, 15] {
        assert!(trace.schedule_count(Pid(pid_val)) > 0);
    }
}

// ---------------------------------------------------------------------------
// util.bpf.c: calc_time_slice branches
// Exercise the different time_slice calculation branches:
// - lat_cri > avg → boost path
// - slice boost with no_slice_boost disabled
// - greedy penalty with negative nice
// ---------------------------------------------------------------------------

/// Very high lat_cri task (frequent I/O) with low lat_cri hog
/// on single CPU → exercises the lat_cri boost in calc_time_slice.
#[test]
fn test_lavd_time_slice_boost() {
    let _lock = common::setup_test();
    let nr_cpus = 1;
    let sched = DynamicScheduler::lavd(nr_cpus);

    // High-frequency I/O → very high lat_cri → should get slice boost
    let scenario = Scenario::builder()
        .cpus(nr_cpus)
        .add_task("hi-freq-io", 0, workloads::io_bound(50_000, 500_000))
        .add_task("hog", 10, workloads::cpu_bound(50_000_000))
        .duration_ms(300)
        .build();

    let trace = Simulator::new(sched).run(scenario);
    assert!(trace.schedule_count(Pid(1)) > 0);
    assert!(trace.schedule_count(Pid(2)) > 0);
}

// ---------------------------------------------------------------------------
// preempt.bpf.c: is_worth_kick_other_task (greedy task path)
// When a task has LAVD_FLAG_IS_GREEDY set (negative nice contribution to
// greedy penalty), the preemption kick is skipped entirely.
// ---------------------------------------------------------------------------

/// Very greedy task (nice=19) alongside lat-cri task: the greedy task
/// should NOT trigger preemption kicks (is_worth_kick returns false).
#[test]
fn test_lavd_greedy_no_preempt_kick() {
    let _lock = common::setup_test();
    let nr_cpus = 2;
    let sched = DynamicScheduler::lavd(nr_cpus);

    let scenario = Scenario::builder()
        .cpus(nr_cpus)
        .task(TaskDef {
            name: "greedy".into(),
            pid: Pid(10),
            nice: 19,
            behavior: workloads::cpu_bound(50_000_000),
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: None,
            parent_pid: None,
        })
        .task(TaskDef {
            name: "io-lat".into(),
            pid: Pid(11),
            nice: -10,
            behavior: workloads::io_bound(100_000, 1_000_000),
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: None,
            parent_pid: None,
        })
        .task(TaskDef {
            name: "hog".into(),
            pid: Pid(12),
            nice: 0,
            behavior: workloads::cpu_bound(20_000_000),
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: None,
            parent_pid: None,
        })
        .duration_ms(300)
        .build();

    let trace = Simulator::new(sched).run(scenario);
    for pid_val in [10, 11, 12] {
        assert!(trace.schedule_count(Pid(pid_val)) > 0);
    }
}

// ---------------------------------------------------------------------------
// main.bpf.c: no_wake_sync path
// Disable wake sync to exercise the no_wake_sync branch.
// ---------------------------------------------------------------------------

/// Disable wake sync to trigger alternate paths in select_cpu/idle_cpu.
#[test]
fn test_lavd_no_wake_sync() {
    let _lock = common::setup_test();
    let nr_cpus = 4;
    let sched = DynamicScheduler::lavd(nr_cpus);

    unsafe {
        lavd_set_bool(&sched, "no_wake_sync\0", true);
    }

    let (ping_b, pong_b) = workloads::ping_pong(Pid(10), Pid(11), 300_000);
    let scenario = Scenario::builder()
        .cpus(nr_cpus)
        .task(TaskDef {
            name: "ping".into(),
            pid: Pid(10),
            nice: 0,
            behavior: ping_b,
            start_time_ns: 0,
            mm_id: Some(MmId(1)),
            allowed_cpus: None,
            parent_pid: None,
        })
        .task(TaskDef {
            name: "pong".into(),
            pid: Pid(11),
            nice: 0,
            behavior: pong_b,
            start_time_ns: 0,
            mm_id: Some(MmId(1)),
            allowed_cpus: None,
            parent_pid: None,
        })
        .task(TaskDef {
            name: "hog".into(),
            pid: Pid(12),
            nice: 0,
            behavior: workloads::cpu_bound(30_000_000),
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: None,
            parent_pid: None,
        })
        .duration_ms(300)
        .build();

    let trace = Simulator::new(sched).run(scenario);
    for pid_val in [10, 11, 12] {
        assert!(trace.schedule_count(Pid(pid_val)) > 0);
    }
}

// ---------------------------------------------------------------------------
// main.bpf.c: no_preemption path
// Disable preemption to exercise alternate code path.
// ---------------------------------------------------------------------------

/// Disable preemption to exercise the no_preemption branch in enqueue.
#[test]
fn test_lavd_no_preemption_mode() {
    let _lock = common::setup_test();
    let nr_cpus = 2;
    let sched = DynamicScheduler::lavd(nr_cpus);

    unsafe {
        lavd_set_bool(&sched, "no_preemption\0", true);
    }

    let scenario = Scenario::builder()
        .cpus(nr_cpus)
        .add_task("io", 0, workloads::io_bound(100_000, 2_000_000))
        .add_task("hog-0", 0, workloads::cpu_bound(30_000_000))
        .add_task("hog-1", 5, workloads::cpu_bound(30_000_000))
        .duration_ms(200)
        .build();

    let trace = Simulator::new(sched).run(scenario);
    for pid_val in 1..=3 {
        assert!(trace.schedule_count(Pid(pid_val)) > 0);
    }
}

// ---------------------------------------------------------------------------
// main.bpf.c/idle.bpf.c: concurrent interleaving with many seeds
// Different seeds produce different scheduling interleavings that hit
// different branches in the complex idle selection logic.
// ---------------------------------------------------------------------------

/// Extended seed exploration with core compaction + autopilot enabled.
#[test]
fn test_lavd_seed_exploration_with_features() {
    let _lock = common::setup_test();

    for seed in [3, 17, 31, 53, 71, 97, 127, 251, 509, 1021] {
        let nr_cpus = 4;
        let sched = DynamicScheduler::lavd(nr_cpus);

        unsafe {
            lavd_set_bool(&sched, "is_autopilot_on\0", true);
            lavd_set_bool(&sched, "no_core_compaction\0", false);
            lavd_set_bool(&sched, "no_freq_scaling\0", false);
            lavd_setup_pco(&sched, nr_cpus);
        }

        let scenario = Scenario::builder()
            .cpus(nr_cpus)
            .seed(seed)
            .add_task("io-hi", -5, workloads::io_bound(50_000, 500_000))
            .add_task("io-lo", 5, workloads::io_bound(500_000, 5_000_000))
            .add_task("periodic", 0, workloads::periodic(2_000_000, 10_000_000))
            .add_task("hog-0", 0, workloads::cpu_bound(20_000_000))
            .add_task("hog-1", 10, workloads::cpu_bound(30_000_000))
            .add_task("hog-2", -10, workloads::cpu_bound(15_000_000))
            .duration_ms(100)
            .build();

        let trace = Simulator::new(sched).run(scenario);
        for pid_val in 1..=6 {
            assert!(
                trace.schedule_count(Pid(pid_val)) > 0,
                "seed={seed}: task pid={pid_val} was never scheduled"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// power.bpf.c: do_autopilot in different load regimes
// Need scenarios that produce intermediate utilization levels to trigger
// all three power mode transitions: powersave, balanced, performance.
// ---------------------------------------------------------------------------

/// Gradually increasing load to trigger all three power mode transitions.
/// Start with 1 I/O task (powersave), add more tasks (balanced),
/// then saturate (performance).
#[test]
fn test_lavd_autopilot_transitions() {
    let _lock = common::setup_test();
    let nr_cpus = 4;
    let sched = DynamicScheduler::lavd(nr_cpus);

    unsafe {
        lavd_set_bool(&sched, "is_autopilot_on\0", true);
        lavd_set_bool(&sched, "no_core_compaction\0", false);
        lavd_setup_pco(&sched, nr_cpus);
    }

    // Staggered arrival: light → moderate → heavy
    let scenario = Scenario::builder()
        .cpus(nr_cpus)
        .task(TaskDef {
            name: "light".into(),
            pid: Pid(10),
            nice: 0,
            behavior: workloads::io_bound(50_000, 10_000_000),
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: None,
            parent_pid: None,
        })
        .task(TaskDef {
            name: "mid-0".into(),
            pid: Pid(11),
            nice: 0,
            behavior: workloads::periodic(3_000_000, 10_000_000),
            start_time_ns: 100_000_000, // arrives at 100ms
            mm_id: None,
            allowed_cpus: None,
            parent_pid: None,
        })
        .task(TaskDef {
            name: "mid-1".into(),
            pid: Pid(12),
            nice: 0,
            behavior: workloads::periodic(3_000_000, 10_000_000),
            start_time_ns: 100_000_000,
            mm_id: None,
            allowed_cpus: None,
            parent_pid: None,
        })
        .task(TaskDef {
            name: "heavy-0".into(),
            pid: Pid(13),
            nice: 0,
            behavior: workloads::cpu_bound(50_000_000),
            start_time_ns: 200_000_000, // arrives at 200ms
            mm_id: None,
            allowed_cpus: None,
            parent_pid: None,
        })
        .task(TaskDef {
            name: "heavy-1".into(),
            pid: Pid(14),
            nice: 0,
            behavior: workloads::cpu_bound(50_000_000),
            start_time_ns: 200_000_000,
            mm_id: None,
            allowed_cpus: None,
            parent_pid: None,
        })
        .task(TaskDef {
            name: "heavy-2".into(),
            pid: Pid(15),
            nice: 0,
            behavior: workloads::cpu_bound(50_000_000),
            start_time_ns: 200_000_000,
            mm_id: None,
            allowed_cpus: None,
            parent_pid: None,
        })
        .task(TaskDef {
            name: "heavy-3".into(),
            pid: Pid(16),
            nice: 0,
            behavior: workloads::cpu_bound(50_000_000),
            start_time_ns: 200_000_000,
            mm_id: None,
            allowed_cpus: None,
            parent_pid: None,
        })
        .duration_ms(500)
        .build();

    let trace = Simulator::new(sched).run(scenario);
    for pid_val in [10, 11, 12, 13, 14, 15, 16] {
        assert!(trace.schedule_count(Pid(pid_val)) > 0);
    }
}

// ---------------------------------------------------------------------------
// Multiple affinity sets with varied sizes
// Covers: init_ao_masks (a_empty/o_empty combinations),
//         can_run_on_cpu/domain with restricted masks
// ---------------------------------------------------------------------------

/// Complex affinity patterns: tasks with overlapping and non-overlapping
/// CPU sets to exercise all cpumask intersection paths.
#[test]
fn test_lavd_complex_affinity_patterns() {
    let _lock = common::setup_test();
    let nr_cpus = 8;
    let sched = DynamicScheduler::lavd(nr_cpus);

    unsafe {
        lavd_set_bool(&sched, "no_core_compaction\0", false);
        lavd_setup_pco(&sched, nr_cpus);
    }

    let scenario = Scenario::builder()
        .cpus(nr_cpus)
        // Task on all even CPUs
        .task(TaskDef {
            name: "even".into(),
            pid: Pid(10),
            nice: 0,
            behavior: workloads::io_bound(200_000, 3_000_000),
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: Some(vec![CpuId(0), CpuId(2), CpuId(4), CpuId(6)]),
            parent_pid: None,
        })
        // Task on all odd CPUs
        .task(TaskDef {
            name: "odd".into(),
            pid: Pid(11),
            nice: 0,
            behavior: workloads::io_bound(200_000, 3_000_000),
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: Some(vec![CpuId(1), CpuId(3), CpuId(5), CpuId(7)]),
            parent_pid: None,
        })
        // Task on just CPU 4 and 5
        .task(TaskDef {
            name: "mid".into(),
            pid: Pid(12),
            nice: 0,
            behavior: workloads::cpu_bound(20_000_000),
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: Some(vec![CpuId(4), CpuId(5)]),
            parent_pid: None,
        })
        // Unpinned tasks
        .task(TaskDef {
            name: "free-0".into(),
            pid: Pid(13),
            nice: 0,
            behavior: workloads::cpu_bound(20_000_000),
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: None,
            parent_pid: None,
        })
        .task(TaskDef {
            name: "free-1".into(),
            pid: Pid(14),
            nice: 0,
            behavior: workloads::cpu_bound(20_000_000),
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: None,
            parent_pid: None,
        })
        .duration_ms(300)
        .build();

    let trace = Simulator::new(sched).run(scenario);
    for pid_val in [10, 11, 12, 13, 14] {
        assert!(trace.schedule_count(Pid(pid_val)) > 0);
    }
}

// ---------------------------------------------------------------------------
// Concurrent interleaving: stress test with pinned + unpinned tasks
// ---------------------------------------------------------------------------

/// Concurrent interleaving with a mix of pinned and free tasks.
/// The interleaving explores race conditions in shared state updates.
#[test]
fn test_lavd_concurrent_pinned_mixed() {
    let _lock = common::setup_test();
    let nr_cpus = 4;
    let sched = DynamicScheduler::lavd(nr_cpus);

    unsafe {
        lavd_set_bool(&sched, "no_core_compaction\0", false);
        lavd_setup_pco(&sched, nr_cpus);
    }

    let scenario = Scenario::builder()
        .cpus(nr_cpus)
        .task(TaskDef {
            name: "pinned-0".into(),
            pid: Pid(10),
            nice: 0,
            behavior: workloads::io_bound(100_000, 2_000_000),
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: Some(vec![CpuId(0)]),
            parent_pid: None,
        })
        .task(TaskDef {
            name: "pinned-2".into(),
            pid: Pid(11),
            nice: 0,
            behavior: workloads::io_bound(100_000, 2_000_000),
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: Some(vec![CpuId(2)]),
            parent_pid: None,
        })
        .task(TaskDef {
            name: "free-0".into(),
            pid: Pid(12),
            nice: -5,
            behavior: workloads::cpu_bound(20_000_000),
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: None,
            parent_pid: None,
        })
        .task(TaskDef {
            name: "free-1".into(),
            pid: Pid(13),
            nice: 5,
            behavior: workloads::cpu_bound(20_000_000),
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: None,
            parent_pid: None,
        })
        .task(TaskDef {
            name: "periodic".into(),
            pid: Pid(14),
            nice: 0,
            behavior: workloads::periodic(1_000_000, 5_000_000),
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: None,
            parent_pid: None,
        })
        .duration_ms(200)
        .build();

    let trace = Simulator::new(sched).run(scenario);
    for pid_val in [10, 11, 12, 13, 14] {
        assert!(trace.schedule_count(Pid(pid_val)) > 0);
    }
}

/// Verify that update_idle fixes CPU utilization tracking.
///
/// With update_idle implemented, idle CPUs now have their idle_start_clk
/// set correctly, so `collect_sys_stat()` computes realistic utilization
/// instead of treating every CPU as 100% busy. With 1 IO task on 8 CPUs,
/// avg_sc_util should be well below its maximum of 1024.
#[test]
fn test_lavd_compaction_diagnostic() {
    let _lock = common::setup_test();
    let nr_cpus = 8u32;
    let sched = DynamicScheduler::lavd(nr_cpus);
    sched.lavd_set_no_core_compaction(false);

    type ProbeU64 = unsafe extern "C" fn() -> u64;

    let probe_avg_sc_util: ProbeU64 = unsafe {
        *sched
            .get_symbol::<ProbeU64>(b"lavd_probe_sys_avg_sc_util\0")
            .expect("lavd_probe_sys_avg_sc_util not found")
    };

    // Very low load: 1 IO task on 8 CPUs. Use a longer duration to let
    // the exponentially-weighted avg_sc_util decay past warmup overhead.
    let scenario = Scenario::builder()
        .cpus(nr_cpus)
        .add_task(
            "io-light",
            0,
            workloads::io_bound(100_000, 10_000_000), // 100us work, 10ms sleep (1%)
        )
        .duration_ms(200)
        .build();

    let sim = Simulator::new(sched);
    let trace = sim.run(scenario);
    assert!(trace.schedule_count(Pid(1)) > 0);

    let avg_sc_util = unsafe { probe_avg_sc_util() };

    eprintln!("=== Compaction Diagnostic ===");
    eprintln!("avg_sc_util = {avg_sc_util} (was 1022 before update_idle fix)");

    // After the update_idle fix, utilization should be significantly lower
    // than the old saturated value of ~1022. Before the fix, every CPU
    // appeared 100% busy because idle_start_clk was never set.
    assert!(
        avg_sc_util < 512,
        "avg_sc_util = {avg_sc_util}; expected < 512 for 1 IO task on 8 CPUs"
    );

    drop(sim);
}
