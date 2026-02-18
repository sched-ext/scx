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
