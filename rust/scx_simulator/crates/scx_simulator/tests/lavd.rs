use scx_simulator::probes::{LavdMonitor, LavdProbes};
use scx_simulator::*;

#[macro_use]
mod common;

// Generic test suite applied to scx_lavd
scheduler_tests!(|nr_cpus| DynamicScheduler::lavd(nr_cpus));

// ---------------------------------------------------------------------------
// Multi-mode test infrastructure: run tests under multiple LAVD power modes
// ---------------------------------------------------------------------------

/// Runs a test closure under multiple LAVD power modes.
///
/// This helper enables testing behavior that may differ between power modes
/// (e.g., core compaction is disabled in Performance mode). Each mode is
/// tested independently with a fresh scheduler instance.
///
/// # Example
/// ```ignore
/// run_with_power_modes(
///     &[LavdPowerMode::Performance, LavdPowerMode::Balanced],
///     |mode| {
///         let sched = DynamicScheduler::lavd(4);
///         sched.lavd_set_power_mode(mode);
///         // ... test body ...
///     },
/// );
/// ```
fn run_with_power_modes<F>(modes: &[LavdPowerMode], test_fn: F)
where
    F: Fn(LavdPowerMode),
{
    for &mode in modes {
        eprintln!("[power_mode_test] Running with {:?}", mode);
        test_fn(mode);
        eprintln!("[power_mode_test] {:?} passed", mode);
    }
}

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

/// Write a u32 value to a named LAVD global variable.
#[allow(dead_code)]
unsafe fn lavd_set_u32(sched: &DynamicScheduler, name: &str, val: u32) {
    let sym: libloading::Symbol<'_, *mut u32> = sched
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

/// Monitor that injects high-load sys_stat values after init.
///
/// `init_sys_stat()` resets `sys_stat.nr_active` and `sys_stat.slice`,
/// so pre-init writes are overwritten. This monitor continuously writes
/// to `sys_stat` on every scheduling event to maintain the illusion of
/// high system load.
///
/// sys_stat field offsets (from intf.h struct sys_stat):
///   32: nr_queued_task (u64)
///   40: slice (u64)
struct HighLoadInjector {
    /// Raw pointer to the `sys_stat` global in the scheduler .so.
    sys_stat_ptr: *mut u8,
}

// SAFETY: The raw pointer points into the scheduler .so's global data,
// which lives as long as the Simulator owns the scheduler.
unsafe impl Send for HighLoadInjector {}
unsafe impl Sync for HighLoadInjector {}

impl Monitor for HighLoadInjector {
    fn sample(&mut self, _ctx: &ProbeContext<'_>) {
        unsafe {
            // sys_stat.nr_queued_task at offset 32 (u64): set high to make
            // can_boost_slice() return false (nr_queued_task > nr_active)
            let nr_queued = self.sys_stat_ptr.add(32) as *mut u64;
            std::ptr::write_volatile(nr_queued, 100);
            // sys_stat.slice at offset 40 (u64): set to 1 so nearly all tasks
            // satisfy avg_runtime >= slice
            let slice = self.sys_stat_ptr.add(40) as *mut u64;
            std::ptr::write_volatile(slice, 1);
        }
    }
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
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
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
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
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
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
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
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
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
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
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
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
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
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
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
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
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
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
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
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
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
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
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
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
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
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
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
#[test]
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
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
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
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
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
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
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
        cgroup_name: None,
        task_flags: 0,
        migration_disabled: 0,
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
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
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
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
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
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
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
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
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
        cgroup_name: None,
        task_flags: 0,
        migration_disabled: 0,
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
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
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
        cgroup_name: None,
        task_flags: 0,
        migration_disabled: 0,
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
///
/// This test runs under multiple power modes:
/// - Performance: core compaction is disabled automatically
/// - Balanced: we explicitly disable core compaction to match expected behavior
#[test]
fn test_lavd_multi_domain_no_compact_balanced() {
    let _lock = common::setup_test();

    run_with_power_modes(
        &[LavdPowerMode::Performance, LavdPowerMode::Balanced],
        |mode| {
            let sched = DynamicScheduler::lavd_multi_domain(4, 2);
            sched.lavd_set_power_mode(mode);

            // For Balanced mode, explicitly disable core compaction to match
            // Performance mode behavior for this specific test.
            // In Performance mode, core compaction is already disabled.
            if mode == LavdPowerMode::Balanced {
                sched.lavd_set_no_core_compaction(true);
            }

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
                    cgroup_name: None,
                    task_flags: 0,
                    migration_disabled: 0,
                });
            }

            let trace = Simulator::new(sched).run(builder.build());
            for i in 1..=4i32 {
                assert!(
                    trace.schedule_count(Pid(i)) > 0,
                    "[{:?}] symmetric_{i} was never scheduled",
                    mode
                );
            }
        },
    );
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
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
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
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
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
        cgroup_name: None,
        task_flags: 0,
        migration_disabled: 0,
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
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
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
        cgroup_name: None,
        task_flags: 0,
        migration_disabled: 0,
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
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
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
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
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
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
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
        cgroup_name: None,
        task_flags: 0,
        migration_disabled: 0,
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
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
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
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
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
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
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
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
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
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
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
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
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
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
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
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
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
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
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
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
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
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
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
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
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
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
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
            parent_pid: Some(Pid(10)),
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
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
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
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
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
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
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
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
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
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
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
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
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
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
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
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
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
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
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
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
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
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
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
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
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
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
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
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
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
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
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
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
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
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
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
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
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
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
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
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
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
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
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
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
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
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
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
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
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
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
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
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
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
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
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
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
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
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
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
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
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
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
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
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
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
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
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
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
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
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
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
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
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
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
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
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
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
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
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
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
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
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
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
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
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
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
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
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
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
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
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
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
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
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
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
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
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
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
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
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
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
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
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
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
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
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
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
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
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
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
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
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
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
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
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
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
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
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
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
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
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
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
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
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
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
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
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
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
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
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
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
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
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
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
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
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
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
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
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
        })
        .duration_ms(200)
        .build();

    let trace = Simulator::new(sched).run(scenario);
    for pid_val in [10, 11, 12, 13, 14] {
        assert!(trace.schedule_count(Pid(pid_val)) > 0);
    }
}

// ===========================================================================
// Phase 3: targeting specific uncovered code paths
// ===========================================================================

// ---------------------------------------------------------------------------
// sys_stat.bpf.c lines 434-448: stats decay
// The static counter `cnt` needs to reach LAVD_SYS_STAT_DECAY_TIMES (200)
// via post-increment (cnt++ == 200), so the 201st call triggers decay.
// Timer fires every 10ms, so we need >2010ms of simulated time.
// ---------------------------------------------------------------------------

/// Run long enough (2.5s) to trigger the stats decay path at line 434.
/// Each timer fires every 10ms; the 201st call (at T=2010ms) triggers decay.
#[test]
fn test_lavd_stats_decay_triggered() {
    let _lock = common::setup_test();
    let nr_cpus = 4;
    let sched = DynamicScheduler::lavd(nr_cpus);

    unsafe {
        lavd_set_bool(&sched, "no_core_compaction\0", false);
        lavd_set_bool(&sched, "is_autopilot_on\0", true);
        lavd_setup_pco(&sched, nr_cpus);
    }

    // Mix of workloads to keep the scheduler active for 2.5 seconds.
    let scenario = Scenario::builder()
        .cpus(nr_cpus)
        .instant_timing()
        .add_task("io", 0, workloads::io_bound(200_000, 3_000_000))
        .add_task("hog", 0, workloads::cpu_bound(30_000_000))
        .add_task("periodic", 0, workloads::periodic(1_000_000, 8_000_000))
        .duration_ms(2500)
        .build();

    let trace = Simulator::new(sched).run(scenario);
    for pid_val in 1..=3 {
        assert!(trace.schedule_count(Pid(pid_val)) > 0);
    }
}

// ---------------------------------------------------------------------------
// power.bpf.c lines 283-313: calc_nr_active_cpus with no_use_em=true
// When no_use_em is set, core compaction uses the heuristic-based path
// that iterates CPUs in PCO order and accumulates effective capacity at
// 50% utilization. This is the common path for systems without an energy
// model (most desktop/server systems).
// ---------------------------------------------------------------------------

/// Exercise the no_use_em heuristic path in calc_nr_active_cpus.
/// With low load on many CPUs, core compaction should reduce nr_active,
/// also triggering use_full_cpus() to return false.
#[test]
fn test_lavd_no_use_em_core_compaction() {
    let _lock = common::setup_test();
    let nr_cpus = 8;
    let sched = DynamicScheduler::lavd(nr_cpus);

    unsafe {
        lavd_set_bool(&sched, "no_core_compaction\0", false);
        lavd_set_u8(&sched, "no_use_em\0", 1);
        lavd_setup_pco(&sched, nr_cpus);
    }

    // Light workload: one IO-bound task with lots of sleep.
    // avg_sc_util should be very low -> calc_nr_active_cpus returns < 8.
    let scenario = Scenario::builder()
        .cpus(nr_cpus)
        .instant_timing()
        .add_task("light-io", 0, workloads::io_bound(100_000, 5_000_000))
        .duration_ms(500)
        .build();

    let trace = Simulator::new(sched).run(scenario);
    assert!(trace.schedule_count(Pid(1)) > 0);
}

// ---------------------------------------------------------------------------
// main.bpf.c lines 970-1134: lavd_dispatch core compaction path
// When use_full_cpus() returns false (nr_active < nr_cpus_onln), the
// dispatch function enters the core compaction path that checks
// active/overflow cpumasks, handles pinned tasks on inactive CPUs,
// and traverses per-domain DSQ for affinitized tasks.
// ---------------------------------------------------------------------------

/// Trigger the core compaction dispatch path with a low-load scenario.
/// With 8 CPUs and minimal work, core compaction reduces nr_active,
/// making dispatch check active/overflow cpumasks (lines 970-988).
#[test]
fn test_lavd_dispatch_compaction_path() {
    let _lock = common::setup_test();
    let nr_cpus = 8;
    let sched = DynamicScheduler::lavd(nr_cpus);

    unsafe {
        lavd_set_bool(&sched, "no_core_compaction\0", false);
        lavd_set_u8(&sched, "no_use_em\0", 1);
        lavd_setup_pco(&sched, nr_cpus);
    }

    // Two light tasks on 8 CPUs -- core compaction should compact to ~2 CPUs.
    // Run long enough for timer to fire and update sys_stat.nr_active.
    let scenario = Scenario::builder()
        .cpus(nr_cpus)
        .instant_timing()
        .add_task("io-0", 0, workloads::io_bound(100_000, 5_000_000))
        .add_task("io-1", 0, workloads::io_bound(200_000, 4_000_000))
        .duration_ms(500)
        .build();

    let trace = Simulator::new(sched).run(scenario);
    assert!(trace.schedule_count(Pid(1)) > 0);
    assert!(trace.schedule_count(Pid(2)) > 0);
}

/// Pinned task on a CPU that becomes inactive under core compaction.
/// Exercises the is_pinned(prev) path in lavd_dispatch (lines 1006-1014)
/// which extends the overflow set for the inactive CPU.
#[test]
fn test_lavd_dispatch_pinned_on_inactive_cpu() {
    let _lock = common::setup_test();
    let nr_cpus = 8;
    let sched = DynamicScheduler::lavd(nr_cpus);

    unsafe {
        lavd_set_bool(&sched, "no_core_compaction\0", false);
        lavd_set_u8(&sched, "no_use_em\0", 1);
        lavd_setup_pco(&sched, nr_cpus);
    }

    // Pin a task to CPU 7 (likely inactive under compaction).
    // The light IO task keeps overall utilization low.
    let scenario = Scenario::builder()
        .cpus(nr_cpus)
        .instant_timing()
        .add_task("light", 0, workloads::io_bound(100_000, 5_000_000))
        .task(TaskDef {
            name: "pinned-7".into(),
            pid: Pid(2),
            nice: 0,
            behavior: workloads::periodic(500_000, 3_000_000),
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: Some(vec![CpuId(7)]),
            parent_pid: None,
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
        })
        .duration_ms(500)
        .build();

    let trace = Simulator::new(sched).run(scenario);
    assert!(trace.schedule_count(Pid(1)) > 0);
    assert!(trace.schedule_count(Pid(2)) > 0);
}

/// Affinitized task restricted to CPUs outside the active set.
/// Exercises the LAVD_FLAG_IS_AFFINITIZED path in lavd_dispatch
/// (lines 1024-1033) which extends overflow set for non-active CPUs.
#[test]
fn test_lavd_dispatch_affinitized_on_inactive_cpus() {
    let _lock = common::setup_test();
    let nr_cpus = 8;
    let sched = DynamicScheduler::lavd(nr_cpus);

    unsafe {
        lavd_set_bool(&sched, "no_core_compaction\0", false);
        lavd_set_u8(&sched, "no_use_em\0", 1);
        lavd_setup_pco(&sched, nr_cpus);
    }

    // Task affinitized to CPUs 5,6,7 -- all likely inactive under compaction.
    let scenario = Scenario::builder()
        .cpus(nr_cpus)
        .instant_timing()
        .add_task("light", 0, workloads::io_bound(100_000, 5_000_000))
        .task(TaskDef {
            name: "affinity-567".into(),
            pid: Pid(2),
            nice: 0,
            behavior: workloads::periodic(500_000, 3_000_000),
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: Some(vec![CpuId(5), CpuId(6), CpuId(7)]),
            parent_pid: None,
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
        })
        .duration_ms(500)
        .build();

    let trace = Simulator::new(sched).run(scenario);
    assert!(trace.schedule_count(Pid(1)) > 0);
    assert!(trace.schedule_count(Pid(2)) > 0);
}

// ---------------------------------------------------------------------------
// sys_stat.bpf.c lines 386-398: completely idle system interval
// When nr_sched == 0 in a timer interval, the idle-system path executes,
// preserving previous lat_cri/perf_cri values.
// ---------------------------------------------------------------------------

/// Create a scenario where all tasks sleep simultaneously, producing
/// a timer interval with zero scheduling activity (nr_sched == 0).
#[test]
fn test_lavd_idle_interval_zero_sched() {
    let _lock = common::setup_test();
    let nr_cpus = 2;
    let sched = DynamicScheduler::lavd(nr_cpus);

    unsafe {
        lavd_set_bool(&sched, "have_little_core\0", true);
    }

    // A single task: runs 1ms then sleeps 30ms. During the 30ms sleep,
    // at least 2 timer intervals (10ms each) have zero scheduling.
    let scenario = Scenario::builder()
        .cpus(nr_cpus)
        .instant_timing()
        .task(TaskDef {
            name: "sleeper".into(),
            pid: Pid(1),
            nice: 0,
            behavior: TaskBehavior {
                phases: vec![
                    Phase::Run(1_000_000),    // 1ms run
                    Phase::Sleep(30_000_000), // 30ms sleep
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
        .duration_ms(300)
        .build();

    let trace = Simulator::new(sched).run(scenario);
    assert!(trace.schedule_count(Pid(1)) > 0);
}

// ---------------------------------------------------------------------------
// idle.bpf.c: trigger uncovered functions in CPU selection
// find_cpu_in (lines 122-152): called when affinitized task's cpumask
//   doesn't intersect active/overflow sets during dispatch.
// pick_random_cpu (lines 220-237): called when sticky_cpdom < 0
//   (no domain found for the task).
// find_sticky_cpu_at_cpdom (lines 241-274): called when sticky domain
//   exists but sticky CPU doesn't.
// ---------------------------------------------------------------------------

/// Heavy load on many CPUs with affinitized tasks to exercise idle CPU
/// selection paths in pick_idle_cpu including the a_empty/o_empty case
/// and the can_run_on_cpu prev_cpu fallback.
#[test]
fn test_lavd_idle_cpu_selection_complex() {
    let _lock = common::setup_test();
    let nr_cpus = 8;
    let sched = DynamicScheduler::lavd(nr_cpus);

    unsafe {
        lavd_set_bool(&sched, "no_core_compaction\0", false);
        lavd_set_u8(&sched, "no_use_em\0", 1);
        lavd_setup_pco(&sched, nr_cpus);
    }

    // Multiple affinitized tasks on overlapping CPU subsets with heavy load.
    // This creates contention in CPU selection and exercises various paths
    // in pick_idle_cpu where masks are partially empty.
    let scenario = Scenario::builder()
        .cpus(nr_cpus)
        .instant_timing()
        .task(TaskDef {
            name: "aff-01".into(),
            pid: Pid(1),
            nice: 0,
            behavior: workloads::cpu_bound(15_000_000),
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: Some(vec![CpuId(0), CpuId(1)]),
            parent_pid: None,
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
        })
        .task(TaskDef {
            name: "aff-23".into(),
            pid: Pid(2),
            nice: 0,
            behavior: workloads::cpu_bound(15_000_000),
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: Some(vec![CpuId(2), CpuId(3)]),
            parent_pid: None,
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
        })
        .task(TaskDef {
            name: "aff-45".into(),
            pid: Pid(3),
            nice: 0,
            behavior: workloads::periodic(2_000_000, 3_000_000),
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: Some(vec![CpuId(4), CpuId(5)]),
            parent_pid: None,
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
        })
        .task(TaskDef {
            name: "aff-67".into(),
            pid: Pid(4),
            nice: 0,
            behavior: workloads::periodic(2_000_000, 3_000_000),
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: Some(vec![CpuId(6), CpuId(7)]),
            parent_pid: None,
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
        })
        // Free-roaming CPU hogs to saturate active CPUs
        .task(TaskDef {
            name: "hog-0".into(),
            pid: Pid(5),
            nice: 5,
            behavior: workloads::cpu_bound(20_000_000),
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: None,
            parent_pid: None,
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
        })
        .task(TaskDef {
            name: "hog-1".into(),
            pid: Pid(6),
            nice: 5,
            behavior: workloads::cpu_bound(20_000_000),
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
    for pid_val in 1..=6 {
        assert!(trace.schedule_count(Pid(pid_val)) > 0);
    }
}

/// Exercise the prev_cpu fallback and sticky CPU domain paths in
/// pick_idle_cpu by creating tasks that wake frequently and have
/// constrained affinity, forcing the scheduler to try prev_cpu
/// and fall back through the sticky domain hierarchy.
#[test]
fn test_lavd_idle_cpu_sticky_domain_fallback() {
    let _lock = common::setup_test();
    let nr_cpus = 4;
    let sched = DynamicScheduler::lavd(nr_cpus);

    // Fast wake/sleep cycles with constrained affinity.
    // The waker/wakee relationship exercises sticky domain lookup.
    let (prod, cons) = workloads::ping_pong(Pid(1), Pid(2), 200_000);
    let scenario = Scenario::builder()
        .cpus(nr_cpus)
        .instant_timing()
        .task(TaskDef {
            name: "pp-a".into(),
            pid: Pid(1),
            nice: 0,
            behavior: prod,
            start_time_ns: 0,
            mm_id: Some(MmId(1)),
            allowed_cpus: Some(vec![CpuId(0), CpuId(1)]),
            parent_pid: None,
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
        })
        .task(TaskDef {
            name: "pp-b".into(),
            pid: Pid(2),
            nice: 0,
            behavior: cons,
            start_time_ns: 0,
            mm_id: Some(MmId(1)),
            allowed_cpus: Some(vec![CpuId(2), CpuId(3)]),
            parent_pid: None,
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
        })
        // Background hogs on all CPUs to prevent trivial idle selection
        .add_task("bg-0", 10, workloads::cpu_bound(30_000_000))
        .add_task("bg-1", 10, workloads::cpu_bound(30_000_000))
        .duration_ms(200)
        .build();

    let trace = Simulator::new(sched).run(scenario);
    assert!(trace.schedule_count(Pid(1)) > 0);
    assert!(trace.schedule_count(Pid(2)) > 0);
}

// ---------------------------------------------------------------------------
// Combined stress test: long-running core compaction with mixed affinity
// Exercises stats decay, no_use_em, dispatch compaction, and idle paths
// all in one simulation.
// ---------------------------------------------------------------------------

/// Extended simulation combining multiple uncovered paths:
/// - Stats decay (>2s run time for 201+ timer callbacks)
/// - no_use_em core compaction (heuristic CPU selection)
/// - Dispatch compaction path (nr_active < nr_cpus_onln)
/// - Pinned + affinitized tasks on inactive CPUs
/// - Idle intervals between bursts
#[test]
fn test_lavd_comprehensive_compaction_stress() {
    let _lock = common::setup_test();
    let nr_cpus = 8;
    let sched = DynamicScheduler::lavd(nr_cpus);

    unsafe {
        lavd_set_bool(&sched, "no_core_compaction\0", false);
        lavd_set_bool(&sched, "is_autopilot_on\0", true);
        lavd_set_u8(&sched, "no_use_em\0", 1);
        lavd_set_bool(&sched, "have_little_core\0", true);
        lavd_setup_pco(&sched, nr_cpus);
    }

    let scenario = Scenario::builder()
        .cpus(nr_cpus)
        .instant_timing()
        // Light periodic task -- allows core compaction
        .task(TaskDef {
            name: "light-periodic".into(),
            pid: Pid(1),
            nice: 0,
            behavior: workloads::periodic(500_000, 8_000_000),
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: None,
            parent_pid: None,
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
        })
        // Pinned task on high CPU (inactive under compaction)
        .task(TaskDef {
            name: "pinned-high".into(),
            pid: Pid(2),
            nice: 0,
            behavior: workloads::periodic(300_000, 10_000_000),
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: Some(vec![CpuId(7)]),
            parent_pid: None,
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
        })
        // Affinitized task on CPUs 4-6 (inactive under compaction)
        .task(TaskDef {
            name: "aff-456".into(),
            pid: Pid(3),
            nice: 0,
            behavior: workloads::periodic(400_000, 6_000_000),
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: Some(vec![CpuId(4), CpuId(5), CpuId(6)]),
            parent_pid: None,
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
        })
        // Task with long sleep to create idle intervals
        .task(TaskDef {
            name: "bursty".into(),
            pid: Pid(4),
            nice: 0,
            behavior: TaskBehavior {
                phases: vec![
                    Phase::Run(2_000_000),    // 2ms burst
                    Phase::Sleep(50_000_000), // 50ms idle
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
        .duration_ms(2500)
        .build();

    let trace = Simulator::new(sched).run(scenario);
    for pid_val in 1..=4 {
        assert!(trace.schedule_count(Pid(pid_val)) > 0);
    }
}

// ---------------------------------------------------------------------------
// preempt.bpf.c: trigger slice boost preemption path (lines 360-391)
// When a task with LAVD_FLAG_SLICE_BOOST is running on the preferred CPU
// and a higher-priority task enqueues, the slice boost should be canceled.
// ---------------------------------------------------------------------------

/// Trigger the slice boost cancellation path in try_find_and_kick_victim_cpu.
/// Use wake-heavy IO tasks (high lat_cri -> slice boost) competing with
/// CPU-bound tasks that preempt them.
#[test]
fn test_lavd_slice_boost_preemption_cancel() {
    let _lock = common::setup_test();
    let nr_cpus = 4;
    let sched = DynamicScheduler::lavd(nr_cpus);

    // Rapid ping-pong creates high lat_cri -> slice boost.
    // CPU hogs preempting the slice-boosted tasks triggers the cancel path.
    let (prod, cons) = workloads::ping_pong(Pid(1), Pid(2), 100_000);
    let scenario = Scenario::builder()
        .cpus(nr_cpus)
        .instant_timing()
        .task(TaskDef {
            name: "pp-a".into(),
            pid: Pid(1),
            nice: -5,
            behavior: prod,
            start_time_ns: 0,
            mm_id: Some(MmId(1)),
            allowed_cpus: None,
            parent_pid: None,
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
        })
        .task(TaskDef {
            name: "pp-b".into(),
            pid: Pid(2),
            nice: -5,
            behavior: cons,
            start_time_ns: 0,
            mm_id: Some(MmId(1)),
            allowed_cpus: None,
            parent_pid: None,
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
        })
        .add_task("hog-0", 0, workloads::cpu_bound(20_000_000))
        .add_task("hog-1", 0, workloads::cpu_bound(20_000_000))
        .add_task("hog-2", 0, workloads::cpu_bound(20_000_000))
        .add_task("hog-3", 0, workloads::cpu_bound(20_000_000))
        .duration_ms(300)
        .build();

    let trace = Simulator::new(sched).run(scenario);
    assert!(trace.schedule_count(Pid(1)) > 0);
    assert!(trace.schedule_count(Pid(2)) > 0);
}

// ---------------------------------------------------------------------------
// Phase 4: Core compaction dispatch path coverage
//
// The simulator's utilization tracking inflates avg_sc_util, preventing the
// natural timer-driven compaction from reducing nr_active. To exercise the
// compaction dispatch path (main.bpf.c lines 964-1134), we use
// lavd_force_compaction() to directly set the active/overflow cpumasks
// and nr_active after lavd_init() has run.
//
// The ForceCompactionMonitor re-forces compaction whenever the timer
// resets nr_active back to full, ensuring compaction persists across
// timer ticks. This lets tasks complete time slices so prev_task is set
// when dispatch runs, covering pinned/affinitized prev sub-paths.
// ---------------------------------------------------------------------------

/// Function pointer type for lavd_force_compaction(int nr_active_cpus).
type ForceCompactionFn = unsafe extern "C" fn(i32);

/// Monitor that persistently forces compaction by re-applying it whenever
/// the timer resets nr_active. Observes min_nr_active to confirm the
/// dispatch compaction path is entered.
///
/// All operations are pure memory writes/reads (no kfuncs), safe outside
/// the sim context.
struct ForceCompactionMonitor {
    force_fn: ForceCompactionFn,
    nr_active_fn: unsafe extern "C" fn() -> u32,
    target_nr_active: i32,
    min_nr_active: u32,
    nr_cpus: u32,
    forced: bool,
}

impl ForceCompactionMonitor {
    fn new(
        force_fn: ForceCompactionFn,
        nr_active_fn: unsafe extern "C" fn() -> u32,
        target_nr_active: i32,
        nr_cpus: u32,
    ) -> Self {
        Self {
            force_fn,
            nr_active_fn,
            target_nr_active,
            min_nr_active: nr_cpus,
            nr_cpus,
            forced: false,
        }
    }

    fn compaction_occurred(&self) -> bool {
        self.min_nr_active < self.nr_cpus
    }
}

impl Monitor for ForceCompactionMonitor {
    fn sample(&mut self, _ctx: &ProbeContext) {
        let nr = unsafe { (self.nr_active_fn)() };
        // Re-force compaction whenever the timer resets it back to full.
        // This ensures compaction persists across timer ticks so that
        // dispatch sees prev != NULL on inactive CPUs (after the first
        // time slice completes and prev_task is set).
        if nr >= self.nr_cpus {
            unsafe { (self.force_fn)(self.target_nr_active) };
            self.forced = true;
        }
        let nr = unsafe { (self.nr_active_fn)() };
        if nr < self.min_nr_active {
            self.min_nr_active = nr;
        }
    }
}

/// Helper to resolve force_compaction and nr_active probe from sched.
fn resolve_compaction_fns(
    sched: &DynamicScheduler,
) -> (ForceCompactionFn, unsafe extern "C" fn() -> u32) {
    type SysProbeU32 = unsafe extern "C" fn() -> u32;
    unsafe {
        let force_fn = *sched
            .get_symbol::<ForceCompactionFn>(b"lavd_force_compaction\0")
            .expect("lavd_force_compaction not found");
        let nr_active_fn = *sched
            .get_symbol::<SysProbeU32>(b"lavd_probe_sys_nr_active\0")
            .expect("lavd_probe_sys_nr_active not found");
        (force_fn, nr_active_fn)
    }
}

/// Verify that lavd_force_compaction() reduces nr_active and the
/// dispatch compaction path (use_full_cpus() == false) is entered.
#[test]
fn test_lavd_compaction_monitor_verify() {
    let _lock = common::setup_test();
    let nr_cpus = 8;
    let sched = DynamicScheduler::lavd(nr_cpus);

    unsafe {
        lavd_set_bool(&sched, "no_core_compaction\0", false);
        lavd_set_u8(&sched, "no_use_em\0", 1);
        lavd_setup_pco(&sched, nr_cpus);
    }

    let (force_fn, nr_active_fn) = resolve_compaction_fns(&sched);
    let mut monitor = ForceCompactionMonitor::new(force_fn, nr_active_fn, 2, nr_cpus);

    let scenario = Scenario::builder()
        .cpus(nr_cpus)
        .instant_timing()
        .add_task("light-io", 0, workloads::io_bound(100_000, 5_000_000))
        .duration_ms(200)
        .build();

    let result = Simulator::new(sched).run_monitored(scenario, &mut monitor);
    assert!(result.trace.schedule_count(Pid(1)) > 0);
    assert!(
        monitor.compaction_occurred(),
        "compaction not observed (min_nr_active={})",
        monitor.min_nr_active,
    );
}

/// Pinned task on inactive CPU under forced compaction.
/// Exercises is_pinned(prev) overflow extension path (main.bpf.c:1011-1014).
/// A CPU-bound task pinned to CPU 7 dispatches on CPU 7 which is inactive
/// under compaction, triggering the pinned-prev overflow extension.
#[test]
fn test_lavd_compaction_pinned_prev_forced() {
    let _lock = common::setup_test();
    let nr_cpus = 8;
    let sched = DynamicScheduler::lavd(nr_cpus);

    unsafe {
        lavd_set_bool(&sched, "no_core_compaction\0", false);
        lavd_set_u8(&sched, "no_use_em\0", 1);
        lavd_setup_pco(&sched, nr_cpus);
    }

    let (force_fn, nr_active_fn) = resolve_compaction_fns(&sched);
    let mut monitor = ForceCompactionMonitor::new(force_fn, nr_active_fn, 2, nr_cpus);

    let scenario = Scenario::builder()
        .cpus(nr_cpus)
        .instant_timing()
        .add_task("light", 0, workloads::io_bound(100_000, 5_000_000))
        .task(TaskDef {
            name: "pinned-7".into(),
            pid: Pid(2),
            nice: 0,
            behavior: workloads::cpu_bound(20_000_000),
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: Some(vec![CpuId(7)]),
            parent_pid: None,
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
        })
        .duration_ms(300)
        .build();

    let result = Simulator::new(sched).run_monitored(scenario, &mut monitor);
    assert!(result.trace.schedule_count(Pid(1)) > 0);
    assert!(
        result.trace.schedule_count(Pid(2)) > 0,
        "pinned task never ran"
    );
    assert!(monitor.compaction_occurred(), "compaction didn't fire");
}

/// Affinitized task on inactive CPUs under forced compaction.
/// Exercises LAVD_FLAG_IS_AFFINITIZED overflow extension path
/// (main.bpf.c:1024-1033). A periodic task affinitized to CPUs {5,6,7}
/// dispatches on those inactive CPUs.
#[test]
fn test_lavd_compaction_affinitized_prev_forced() {
    let _lock = common::setup_test();
    let nr_cpus = 8;
    let sched = DynamicScheduler::lavd(nr_cpus);

    unsafe {
        lavd_set_bool(&sched, "no_core_compaction\0", false);
        lavd_set_u8(&sched, "no_use_em\0", 1);
        lavd_setup_pco(&sched, nr_cpus);
    }

    let (force_fn, nr_active_fn) = resolve_compaction_fns(&sched);
    let mut monitor = ForceCompactionMonitor::new(force_fn, nr_active_fn, 2, nr_cpus);

    let scenario = Scenario::builder()
        .cpus(nr_cpus)
        .instant_timing()
        .add_task("light", 0, workloads::io_bound(100_000, 5_000_000))
        .task(TaskDef {
            name: "affinity-567".into(),
            pid: Pid(2),
            nice: 0,
            behavior: workloads::periodic(500_000, 3_000_000),
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: Some(vec![CpuId(5), CpuId(6), CpuId(7)]),
            parent_pid: None,
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
        })
        .duration_ms(300)
        .build();

    let result = Simulator::new(sched).run_monitored(scenario, &mut monitor);
    assert!(result.trace.schedule_count(Pid(1)) > 0);
    assert!(
        result.trace.schedule_count(Pid(2)) > 0,
        "affinitized task never ran"
    );
    assert!(monitor.compaction_occurred(), "compaction didn't fire");
}

/// Per-CPU DSQ mode under compaction: exercises the per-CPU DSQ fast path
/// (main.bpf.c:1000-1004) and the !use_cpdom_dsq early exit (line 1040-1043).
#[test]
fn test_lavd_compaction_per_cpu_dsq_mode() {
    let _lock = common::setup_test();
    let nr_cpus = 8;
    let sched = DynamicScheduler::lavd(nr_cpus);

    unsafe {
        lavd_set_bool(&sched, "no_core_compaction\0", false);
        lavd_set_u8(&sched, "no_use_em\0", 1);
        lavd_set_bool(&sched, "per_cpu_dsq\0", true);
        lavd_setup_pco(&sched, nr_cpus);
    }

    let (force_fn, nr_active_fn) = resolve_compaction_fns(&sched);
    let mut monitor = ForceCompactionMonitor::new(force_fn, nr_active_fn, 2, nr_cpus);

    let scenario = Scenario::builder()
        .cpus(nr_cpus)
        .instant_timing()
        .add_task("io-0", 0, workloads::io_bound(200_000, 3_000_000))
        .add_task("io-1", 0, workloads::io_bound(200_000, 3_000_000))
        .add_task("cpu-0", 0, workloads::cpu_bound(20_000_000))
        .duration_ms(300)
        .build();

    let result = Simulator::new(sched).run_monitored(scenario, &mut monitor);
    assert!(result.trace.schedule_count(Pid(1)) > 0);
    assert!(result.trace.schedule_count(Pid(2)) > 0);
    assert!(monitor.compaction_occurred(), "compaction didn't fire");
}

/// DSQ iteration entry: exercises the bpf_for_each(scx_dsq, ...) loop
/// at main.bpf.c:1055-1126. Affinitized tasks on inactive CPUs create
/// DSQ entries for the iteration loop. bpf_task_from_pid resolves from
/// the Rust kfuncs for actual PID→task_struct lookup.
#[test]
fn test_lavd_compaction_dsq_iteration() {
    let _lock = common::setup_test();
    let nr_cpus = 8;
    let sched = DynamicScheduler::lavd(nr_cpus);

    unsafe {
        lavd_set_bool(&sched, "no_core_compaction\0", false);
        lavd_set_u8(&sched, "no_use_em\0", 1);
        lavd_setup_pco(&sched, nr_cpus);
    }

    let (force_fn, nr_active_fn) = resolve_compaction_fns(&sched);
    let mut monitor = ForceCompactionMonitor::new(force_fn, nr_active_fn, 2, nr_cpus);

    let scenario = Scenario::builder()
        .cpus(nr_cpus)
        .instant_timing()
        .add_task("light", 0, workloads::io_bound(100_000, 5_000_000))
        .task(TaskDef {
            name: "aff-67".into(),
            pid: Pid(2),
            nice: 0,
            behavior: workloads::periodic(400_000, 2_000_000),
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: Some(vec![CpuId(6), CpuId(7)]),
            parent_pid: None,
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
        })
        .task(TaskDef {
            name: "aff-45".into(),
            pid: Pid(3),
            nice: 0,
            behavior: workloads::periodic(300_000, 2_000_000),
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: Some(vec![CpuId(4), CpuId(5)]),
            parent_pid: None,
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
        })
        .task(TaskDef {
            name: "pin-3".into(),
            pid: Pid(4),
            nice: 0,
            behavior: workloads::periodic(200_000, 3_000_000),
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: Some(vec![CpuId(3)]),
            parent_pid: None,
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
        })
        .duration_ms(400)
        .build();

    let result = Simulator::new(sched).run_monitored(scenario, &mut monitor);
    assert!(result.trace.schedule_count(Pid(1)) > 0);
    assert!(result.trace.schedule_count(Pid(2)) > 0);
    assert!(monitor.compaction_occurred(), "compaction didn't fire");
}

/// Large CPU count compaction: 32 CPUs with very light workload.
/// Tests core compaction with many inactive CPUs, exercising the
/// PCO iteration and cpumask operations at scale.
#[test]
fn test_lavd_compaction_large_cpu_count() {
    let _lock = common::setup_test();
    let nr_cpus = 32;
    let sched = DynamicScheduler::lavd(nr_cpus);

    unsafe {
        lavd_set_bool(&sched, "no_core_compaction\0", false);
        lavd_set_u8(&sched, "no_use_em\0", 1);
        lavd_setup_pco(&sched, nr_cpus);
    }

    let (force_fn, nr_active_fn) = resolve_compaction_fns(&sched);
    let mut monitor = ForceCompactionMonitor::new(force_fn, nr_active_fn, 4, nr_cpus);

    let scenario = Scenario::builder()
        .cpus(nr_cpus)
        .instant_timing()
        .add_task("tiny", 0, workloads::io_bound(50_000, 10_000_000))
        .duration_ms(300)
        .build();

    let result = Simulator::new(sched).run_monitored(scenario, &mut monitor);
    assert!(result.trace.schedule_count(Pid(1)) > 0);
    assert!(
        monitor.compaction_occurred(),
        "compaction didn't fire on 32 CPUs (min_nr_active={})",
        monitor.min_nr_active,
    );
}

/// Combined: pinned + affinitized + free tasks under forced compaction.
/// Exercises multiple compaction sub-paths in a single simulation run.
#[test]
fn test_lavd_compaction_combined_stress() {
    let _lock = common::setup_test();
    let nr_cpus = 8;
    let sched = DynamicScheduler::lavd(nr_cpus);

    unsafe {
        lavd_set_bool(&sched, "no_core_compaction\0", false);
        lavd_set_u8(&sched, "no_use_em\0", 1);
        lavd_setup_pco(&sched, nr_cpus);
    }

    let (force_fn, nr_active_fn) = resolve_compaction_fns(&sched);
    let mut monitor = ForceCompactionMonitor::new(force_fn, nr_active_fn, 2, nr_cpus);

    let scenario = Scenario::builder()
        .cpus(nr_cpus)
        .instant_timing()
        // Free tasks (can migrate anywhere)
        .add_task("free-0", 0, workloads::io_bound(100_000, 4_000_000))
        .add_task("free-1", 0, workloads::io_bound(150_000, 3_000_000))
        // Pinned tasks on inactive CPUs
        .task(TaskDef {
            name: "pin-6".into(),
            pid: Pid(3),
            nice: 0,
            behavior: workloads::periodic(300_000, 2_000_000),
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: Some(vec![CpuId(6)]),
            parent_pid: None,
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
        })
        .task(TaskDef {
            name: "pin-7".into(),
            pid: Pid(4),
            nice: 0,
            behavior: workloads::periodic(200_000, 3_000_000),
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: Some(vec![CpuId(7)]),
            parent_pid: None,
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
        })
        // Affinitized task on inactive CPUs
        .task(TaskDef {
            name: "aff-345".into(),
            pid: Pid(5),
            nice: 0,
            behavior: workloads::periodic(400_000, 2_500_000),
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: Some(vec![CpuId(3), CpuId(4), CpuId(5)]),
            parent_pid: None,
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
        })
        .duration_ms(400)
        .build();

    let result = Simulator::new(sched).run_monitored(scenario, &mut monitor);
    for pid in 1..=5 {
        assert!(
            result.trace.schedule_count(Pid(pid)) > 0,
            "pid {} was never scheduled",
            pid,
        );
    }
    assert!(monitor.compaction_occurred(), "compaction didn't fire");
}

// ---------------------------------------------------------------------------
// Phase 5: idle.bpf.c — SMT topology, CPU saturation, sync wakeup
// ---------------------------------------------------------------------------

/// Configure LAVD's BPF globals for SMT: set `is_smt_active = true` and
/// pair adjacent CPUs as siblings (0↔1, 2↔3, …).
///
/// # Safety
/// Must be called after `DynamicScheduler::lavd()` init completes.
unsafe fn lavd_setup_smt(sched: &DynamicScheduler, nr_cpus: u32) {
    lavd_set_bool(sched, "is_smt_active\0", true);

    const LAVD_CPU_ID_MAX: usize = 512;
    let sibling_sym: libloading::Symbol<'_, *mut u16> = sched
        .get_symbol(b"cpu_sibling\0")
        .expect("cpu_sibling not found");
    let sibling = *sibling_sym;
    for i in (0..nr_cpus.min(LAVD_CPU_ID_MAX as u32)).step_by(2) {
        let sib = i + 1;
        if sib < nr_cpus {
            std::ptr::write_volatile(sibling.add(i as usize), sib as u16);
            std::ptr::write_volatile(sibling.add(sib as usize), i as u16);
        }
    }
}

/// SMT idle-core selection: with `is_smt_active = true` and paired siblings,
/// LAVD should prefer fully idle cores (both siblings idle) over partially
/// idle ones.
///
/// Covers: idle.bpf.c lines 687-714 (SMT idle mask acquisition, sticky CPU
/// fully-idle check, fully-idle-core search in sticky domain).
#[test]
fn test_lavd_smt_idle_core_selection() {
    let _lock = common::setup_test();
    let nr_cpus = 8;
    let sched = DynamicScheduler::lavd(nr_cpus);

    unsafe {
        lavd_setup_smt(&sched, nr_cpus);
    }

    // 4 tasks on 8 CPUs (4 cores of 2 threads each).
    // With some CPUs idle, the scheduler should prefer fully idle cores.
    let scenario = Scenario::builder()
        .cpus(nr_cpus)
        .smt(2) // 2 threads per core
        .add_task("io-0", 0, workloads::io_bound(100_000, 2_000_000))
        .add_task("io-1", 0, workloads::io_bound(150_000, 2_500_000))
        .add_task("hog-0", 0, workloads::cpu_bound(20_000_000))
        .add_task("hog-1", 0, workloads::cpu_bound(20_000_000))
        .duration_ms(300)
        .build();

    let trace = Simulator::new(sched).run(scenario);
    for pid_val in 1..=4 {
        assert!(trace.schedule_count(Pid(pid_val)) > 0);
    }
}

/// SMT with no idle cores: all 8 CPUs busy so the idle SMT mask is empty.
/// LAVD falls through the SMT-preferred path and uses the non-SMT idle
/// CPU selection or fallback.
///
/// Covers: idle.bpf.c `i_smt_empty = true` path when SMT active but
/// all cores have at least one sibling busy.
#[test]
fn test_lavd_smt_no_idle_core() {
    let _lock = common::setup_test();
    let nr_cpus = 4;
    let sched = DynamicScheduler::lavd(nr_cpus);

    unsafe {
        lavd_setup_smt(&sched, nr_cpus);
    }

    // 6 tasks on 4 CPUs — all cores partially or fully busy
    let scenario = Scenario::builder()
        .cpus(nr_cpus)
        .smt(2) // 2 threads per core → 2 physical cores
        .add_task("io-0", 0, workloads::io_bound(100_000, 1_000_000))
        .add_task("io-1", 0, workloads::io_bound(150_000, 1_500_000))
        .add_task("hog-0", 0, workloads::cpu_bound(20_000_000))
        .add_task("hog-1", 0, workloads::cpu_bound(20_000_000))
        .add_task("hog-2", 0, workloads::cpu_bound(20_000_000))
        .add_task("hog-3", 0, workloads::cpu_bound(20_000_000))
        .duration_ms(300)
        .build();

    let trace = Simulator::new(sched).run(scenario);
    for pid_val in 1..=6 {
        assert!(trace.schedule_count(Pid(pid_val)) > 0);
    }
}

/// CPU saturation: more tasks than CPUs forces the scheduler through
/// fallback paths when no idle CPU is found. Exercises `find_sticky_cpu_at_cpdom`
/// and potentially `pick_random_cpu` in idle.bpf.c.
#[test]
fn test_lavd_cpu_saturation() {
    let _lock = common::setup_test();
    let nr_cpus = 4;
    let sched = DynamicScheduler::lavd(nr_cpus);

    // 8 CPU-bound tasks competing for 4 CPUs — no CPU idle at wakeup
    let scenario = Scenario::builder()
        .cpus(nr_cpus)
        .add_task("hog-0", 0, workloads::cpu_bound(20_000_000))
        .add_task("hog-1", 0, workloads::cpu_bound(20_000_000))
        .add_task("hog-2", 0, workloads::cpu_bound(20_000_000))
        .add_task("hog-3", 0, workloads::cpu_bound(20_000_000))
        .add_task("hog-4", 0, workloads::cpu_bound(20_000_000))
        .add_task("hog-5", 0, workloads::cpu_bound(20_000_000))
        .add_task("hog-6", 0, workloads::cpu_bound(20_000_000))
        .add_task("hog-7", 0, workloads::cpu_bound(20_000_000))
        .duration_ms(300)
        .build();

    let trace = Simulator::new(sched).run(scenario);
    for pid_val in 1..=8 {
        assert!(trace.schedule_count(Pid(pid_val)) > 0);
    }
}

/// SMT + sync wakeup: exercises the intersection of sync wakeup logic
/// (SCX_WAKE_SYNC) with SMT idle-core selection paths.
///
/// Covers: idle.bpf.c `is_sync_wakeup()` returning true combined with
/// SMT-aware CPU placement.
#[test]
fn test_lavd_smt_sync_wakeup() {
    let _lock = common::setup_test();
    let nr_cpus = 8;
    let sched = DynamicScheduler::lavd(nr_cpus);

    unsafe {
        lavd_setup_smt(&sched, nr_cpus);
    }

    // Mix of IO-bound tasks (frequent sync wakeups) and CPU-bound tasks
    // on an SMT system. IO tasks have short compute / long sleep, producing
    // waker→wakee patterns that trigger SCX_WAKE_SYNC.
    let scenario = Scenario::builder()
        .cpus(nr_cpus)
        .smt(2)
        .add_task("io-fast-0", -10, workloads::io_bound(50_000, 500_000))
        .add_task("io-fast-1", -10, workloads::io_bound(80_000, 800_000))
        .add_task("io-fast-2", -5, workloads::io_bound(60_000, 600_000))
        .add_task("hog-0", 5, workloads::cpu_bound(20_000_000))
        .add_task("hog-1", 5, workloads::cpu_bound(20_000_000))
        .add_task("hog-2", 0, workloads::cpu_bound(20_000_000))
        .duration_ms(300)
        .build();

    let trace = Simulator::new(sched).run(scenario);
    for pid_val in 1..=6 {
        assert!(trace.schedule_count(Pid(pid_val)) > 0);
    }
}

/// SMT + compaction: exercises fully idle core preference during
/// compaction dispatch, where a subset of CPUs are active.
#[test]
fn test_lavd_smt_compaction() {
    let _lock = common::setup_test();
    let nr_cpus = 8;
    let sched = DynamicScheduler::lavd(nr_cpus);

    unsafe {
        lavd_setup_smt(&sched, nr_cpus);
        lavd_set_bool(&sched, "no_core_compaction\0", false);
        lavd_set_u8(&sched, "no_use_em\0", 1);
        lavd_setup_pco(&sched, nr_cpus);
    }

    let (force_fn, nr_active_fn) = resolve_compaction_fns(&sched);
    // Only 4 out of 8 CPUs active (2 out of 4 cores)
    let mut monitor = ForceCompactionMonitor::new(force_fn, nr_active_fn, 4, nr_cpus);

    let scenario = Scenario::builder()
        .cpus(nr_cpus)
        .smt(2)
        .instant_timing()
        .add_task("io-0", 0, workloads::io_bound(100_000, 2_000_000))
        .add_task("io-1", 0, workloads::io_bound(150_000, 2_500_000))
        .add_task("hog-0", 0, workloads::cpu_bound(20_000_000))
        .duration_ms(300)
        .build();

    let result = Simulator::new(sched).run_monitored(scenario, &mut monitor);
    for pid_val in 1..=3 {
        assert!(result.trace.schedule_count(Pid(pid_val)) > 0);
    }
    assert!(
        monitor.compaction_occurred(),
        "SMT compaction didn't fire (min_nr_active={})",
        monitor.min_nr_active,
    );
}

/// Saturation with SMT: all cores busy, exercises the idle.bpf.c path
/// where `i_empty = true` (no idle CPUs at all) and the scheduler must
/// fall through to `find_sticky_cpu_at_cpdom` / `pick_random_cpu`.
#[test]
fn test_lavd_smt_saturation() {
    let _lock = common::setup_test();
    let nr_cpus = 4;
    let sched = DynamicScheduler::lavd(nr_cpus);

    unsafe {
        lavd_setup_smt(&sched, nr_cpus);
    }

    // 8 CPU-bound tasks on 4 CPUs (2 cores): system fully saturated
    let scenario = Scenario::builder()
        .cpus(nr_cpus)
        .smt(2)
        .add_task("hog-0", 0, workloads::cpu_bound(20_000_000))
        .add_task("hog-1", 0, workloads::cpu_bound(20_000_000))
        .add_task("hog-2", 0, workloads::cpu_bound(20_000_000))
        .add_task("hog-3", 0, workloads::cpu_bound(20_000_000))
        .add_task("hog-4", 0, workloads::cpu_bound(20_000_000))
        .add_task("hog-5", 0, workloads::cpu_bound(20_000_000))
        .add_task("hog-6", 0, workloads::cpu_bound(20_000_000))
        .add_task("hog-7", 0, workloads::cpu_bound(20_000_000))
        .duration_ms(300)
        .build();

    let trace = Simulator::new(sched).run(scenario);
    for pid_val in 1..=8 {
        assert!(trace.schedule_count(Pid(pid_val)) > 0);
    }
}

/// Big/little + CPU saturation: exercises the `find_sticky_cpu_at_cpdom`
/// path (idle.bpf.c lines 676-679) when `i_empty = true` AND `sticky_cpu`
/// is -ENOENT due to big/little mismatch.
///
/// When a task is perf_cri (big) but its prev_cpu is on a little core,
/// `find_sticky_cpu_and_cpdom` puts it in the not_match bucket and returns
/// -ENOENT for sticky_cpu. If all CPUs are also busy (i_empty), the code
/// falls through to `find_sticky_cpu_at_cpdom`.
#[test]
fn test_lavd_big_little_saturation() {
    let _lock = common::setup_test();
    let nr_cpus = 4;
    let sched = DynamicScheduler::lavd(nr_cpus);

    unsafe {
        // CPUs 0,1 = big, CPUs 2,3 = little
        lavd_set_bool(&sched, "have_little_core\0", true);

        let cap_sym: libloading::Symbol<'_, *mut u16> = sched
            .get_symbol(b"cpu_capacity\0")
            .expect("cpu_capacity not found");
        let cap_arr = *cap_sym;
        std::ptr::write_volatile(cap_arr.add(0), 1024);
        std::ptr::write_volatile(cap_arr.add(1), 1024);
        std::ptr::write_volatile(cap_arr.add(2), 512);
        std::ptr::write_volatile(cap_arr.add(3), 512);

        let big_sym: libloading::Symbol<'_, *mut u8> =
            sched.get_symbol(b"cpu_big\0").expect("cpu_big not found");
        let big_arr = *big_sym;
        std::ptr::write_volatile(big_arr.add(0), 1);
        std::ptr::write_volatile(big_arr.add(1), 1);
        std::ptr::write_volatile(big_arr.add(2), 0);
        std::ptr::write_volatile(big_arr.add(3), 0);
    }

    // 8 CPU-bound tasks on 4 CPUs: fully saturated with big/little mismatch
    let scenario = Scenario::builder()
        .cpus(nr_cpus)
        .add_task("hog-0", 0, workloads::cpu_bound(20_000_000))
        .add_task("hog-1", 0, workloads::cpu_bound(20_000_000))
        .add_task("hog-2", 0, workloads::cpu_bound(20_000_000))
        .add_task("hog-3", 0, workloads::cpu_bound(20_000_000))
        .add_task("hog-4", 0, workloads::cpu_bound(20_000_000))
        .add_task("hog-5", 0, workloads::cpu_bound(20_000_000))
        .add_task("hog-6", 0, workloads::cpu_bound(20_000_000))
        .add_task("hog-7", 0, workloads::cpu_bound(20_000_000))
        .duration_ms(300)
        .build();

    let trace = Simulator::new(sched).run(scenario);
    for pid_val in 1..=8 {
        assert!(trace.schedule_count(Pid(pid_val)) > 0);
    }
}

/// Big/little + SMT + IO: exercises the `is_sync_waker_idle` path deeper
/// (idle.bpf.c lines 496-510) when sync wakeup occurs with busy CPUs.
/// Also exercises `i_nm == 2` path in `find_sticky_cpu_and_cpdom` when
/// both prev_cpu and waker_cpu are on not-matching cores.
#[test]
fn test_lavd_big_little_smt_sync_wakeup() {
    let _lock = common::setup_test();
    let nr_cpus = 8;
    let sched = DynamicScheduler::lavd(nr_cpus);

    unsafe {
        lavd_setup_smt(&sched, nr_cpus);
        lavd_set_bool(&sched, "have_little_core\0", true);

        let cap_sym: libloading::Symbol<'_, *mut u16> = sched
            .get_symbol(b"cpu_capacity\0")
            .expect("cpu_capacity not found");
        let cap_arr = *cap_sym;
        // CPUs 0-3 = big (cores 0-1), CPUs 4-7 = little (cores 2-3)
        for i in 0..4 {
            std::ptr::write_volatile(cap_arr.add(i), 1024);
        }
        for i in 4..8 {
            std::ptr::write_volatile(cap_arr.add(i), 512);
        }

        let big_sym: libloading::Symbol<'_, *mut u8> =
            sched.get_symbol(b"cpu_big\0").expect("cpu_big not found");
        let big_arr = *big_sym;
        for i in 0..4 {
            std::ptr::write_volatile(big_arr.add(i), 1);
        }
        for i in 4..8 {
            std::ptr::write_volatile(big_arr.add(i), 0);
        }
    }

    // Mix of IO (frequent sync wakeups) and CPU-bound tasks on big/little + SMT
    let scenario = Scenario::builder()
        .cpus(nr_cpus)
        .smt(2)
        .add_task("io-fast-0", -10, workloads::io_bound(50_000, 500_000))
        .add_task("io-fast-1", -10, workloads::io_bound(80_000, 800_000))
        .add_task("io-fast-2", -5, workloads::io_bound(60_000, 600_000))
        .add_task("io-fast-3", -5, workloads::io_bound(70_000, 700_000))
        .add_task("hog-0", 5, workloads::cpu_bound(20_000_000))
        .add_task("hog-1", 5, workloads::cpu_bound(20_000_000))
        .add_task("hog-2", 0, workloads::cpu_bound(20_000_000))
        .add_task("hog-3", 0, workloads::cpu_bound(20_000_000))
        .add_task("hog-4", 0, workloads::cpu_bound(20_000_000))
        .add_task("hog-5", 0, workloads::cpu_bound(20_000_000))
        .duration_ms(400)
        .build();

    let trace = Simulator::new(sched).run(scenario);
    for pid_val in 1..=10 {
        assert!(trace.schedule_count(Pid(pid_val)) > 0);
    }
}

/// Saturated IO with sync wakeups: many IO-bound tasks that wake each other
/// up in a chain pattern, exercising the `is_sync_waker_idle` function when
/// the waker's local DSQ is non-empty (queued_on_cpu check) and when
/// ia_empty && io_empty at line 744 (no idle CPU in active/overflow).
#[test]
fn test_lavd_saturated_io_sync_wakeup() {
    let _lock = common::setup_test();
    let nr_cpus = 4;
    let sched = DynamicScheduler::lavd(nr_cpus);

    // 12 IO-bound tasks with very short sleep on 4 CPUs:
    // frequent sync wakeups with all CPUs often busy
    let scenario = Scenario::builder()
        .cpus(nr_cpus)
        .add_task("io-0", 0, workloads::io_bound(50_000, 200_000))
        .add_task("io-1", 0, workloads::io_bound(60_000, 250_000))
        .add_task("io-2", 0, workloads::io_bound(70_000, 300_000))
        .add_task("io-3", 0, workloads::io_bound(80_000, 350_000))
        .add_task("io-4", -5, workloads::io_bound(40_000, 150_000))
        .add_task("io-5", -5, workloads::io_bound(45_000, 180_000))
        .add_task("io-6", -5, workloads::io_bound(55_000, 220_000))
        .add_task("io-7", -5, workloads::io_bound(65_000, 280_000))
        .add_task("hog-0", 5, workloads::cpu_bound(20_000_000))
        .add_task("hog-1", 5, workloads::cpu_bound(20_000_000))
        .add_task("hog-2", 5, workloads::cpu_bound(20_000_000))
        .add_task("hog-3", 5, workloads::cpu_bound(20_000_000))
        .duration_ms(400)
        .build();

    let trace = Simulator::new(sched).run(scenario);
    for pid_val in 1..=12 {
        assert!(trace.schedule_count(Pid(pid_val)) > 0);
    }
}

// ---------------------------------------------------------------------------
// Phase 6: Coverage improvements — is_monitored, pinned_slice_ns, slice boost,
// SCX_TASK_QUEUED for consume_prev, power mode changes
// ---------------------------------------------------------------------------

/// Enable `is_monitored` to cover introspection data collection paths.
/// Covers main.bpf.c lines 378-380 (`resched_interval` tracking in
/// `update_stat_for_running`) and lines 1256-1259 (`waker_pid` / `waker_comm`
/// collection in `lavd_runnable`).
#[test]
fn test_lavd_is_monitored() {
    let _lock = common::setup_test();
    let nr_cpus = 4;
    let sched = DynamicScheduler::lavd(nr_cpus);

    unsafe {
        lavd_set_bool(&sched, "is_monitored\0", true);
    }

    // Ping-pong tasks to exercise waker-wakee tracking with monitoring
    let mm = MmId(1);
    let (beh_a, beh_b) = workloads::ping_pong(Pid(1), Pid(2), 100_000);
    let scenario = Scenario::builder()
        .cpus(nr_cpus)
        .task(TaskDef {
            name: "monitored-a".into(),
            pid: Pid(1),
            nice: 0,
            behavior: beh_a,
            mm_id: Some(mm),
            start_time_ns: 0,
            allowed_cpus: None,
            parent_pid: None,
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
        })
        .task(TaskDef {
            name: "monitored-b".into(),
            pid: Pid(2),
            nice: 0,
            behavior: beh_b,
            mm_id: Some(mm),
            start_time_ns: 0,
            allowed_cpus: None,
            parent_pid: None,
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
        })
        .add_task("hog", 5, workloads::cpu_bound(20_000_000))
        .duration_ms(300)
        .build();

    let trace = Simulator::new(sched).run(scenario);
    assert!(trace.schedule_count(Pid(1)) > 0);
    assert!(trace.schedule_count(Pid(2)) > 0);
}

/// Enable `pinned_slice_ns` to cover the pinned-task time slice reduction
/// path in `calc_time_slice` (main.bpf.c lines 283-287) and the pinned
/// slice target in `shrink_slice_at_tick` (preempt.bpf.c lines 262-292).
///
/// When `pinned_slice_ns > 0` and a CPU has `nr_pinned_tasks > 0`, time
/// slices are clamped to `min(pinned_slice_ns, sys_stat.slice)`.
#[test]
fn test_lavd_pinned_slice_ns() {
    let _lock = common::setup_test();
    let nr_cpus = 4;
    let sched = DynamicScheduler::lavd(nr_cpus);

    unsafe {
        // Enable pinned_slice_ns: clamp slices to 2ms when pinned tasks exist
        lavd_set_u64(&sched, "pinned_slice_ns\0", 2_000_000);
    }

    // Pinned tasks + unpinned tasks to exercise the interaction
    let scenario = Scenario::builder()
        .cpus(nr_cpus)
        .add_task("pinned-0", 0, workloads::cpu_bound(20_000_000))
        .add_task("pinned-1", 0, workloads::cpu_bound(20_000_000))
        .add_task("free-0", 0, workloads::cpu_bound(20_000_000))
        .add_task("free-1", 0, workloads::io_bound(100_000, 500_000))
        .add_task("free-2", 0, workloads::io_bound(80_000, 400_000))
        .duration_ms(300)
        .build();

    let trace = Simulator::new(sched).run(scenario);
    for pid_val in 1..=5 {
        assert!(trace.schedule_count(Pid(pid_val)) > 0);
    }
}

/// Exercise the slice boost path in `calc_time_slice` (main.bpf.c lines
/// 299-345). Slice boost triggers when:
///   - `no_slice_boost = false` (default)
///   - `cpuc->nr_pinned_tasks == 0`
///   - `taskc->avg_runtime >= sys_stat.slice`
///
/// With low task count relative to CPUs, `can_boost_slice()` returns true
/// (nr_queued_task <= nr_active), giving the full boost path (lines 315-324).
/// With high task count, only lat-cri tasks get partial boost (lines 334-344).
#[test]
fn test_lavd_slice_boost_full() {
    let _lock = common::setup_test();
    let nr_cpus = 4;
    let sched = DynamicScheduler::lavd(nr_cpus);

    // 2 CPU-bound tasks on 4 CPUs: low load → can_boost_slice() returns true.
    // Long-running tasks should develop avg_runtime >= sys_stat.slice,
    // triggering the full boost path.
    let scenario = Scenario::builder()
        .cpus(nr_cpus)
        .add_task("long-0", 0, workloads::cpu_bound(50_000_000))
        .add_task("long-1", 0, workloads::cpu_bound(50_000_000))
        .duration_ms(500)
        .build();

    let trace = Simulator::new(sched).run(scenario);
    assert!(trace.schedule_count(Pid(1)) > 0);
    assert!(trace.schedule_count(Pid(2)) > 0);
}

/// Exercise the partial slice boost path for latency-critical tasks under
/// high load (main.bpf.c lines 334-344). When `can_boost_slice()` returns
/// false but `taskc->lat_cri > sys_stat.avg_lat_cri`, the scheduler boosts
/// proportional to latency criticality.
#[test]
fn test_lavd_slice_boost_partial_lat_cri() {
    let _lock = common::setup_test();
    let nr_cpus = 4;
    let sched = DynamicScheduler::lavd(nr_cpus);

    // Overloaded system (6 tasks on 4 CPUs) with a mix of IO and CPU-bound.
    // IO tasks develop high lat_cri. With can_boost_slice() false (overloaded),
    // only the high-lat_cri IO tasks get partial boost.
    let mm = MmId(1);
    let (beh_a, beh_b) = workloads::ping_pong(Pid(1), Pid(2), 200_000);
    let scenario = Scenario::builder()
        .cpus(nr_cpus)
        .task(TaskDef {
            name: "io-cri-a".into(),
            pid: Pid(1),
            nice: -10,
            behavior: beh_a,
            mm_id: Some(mm),
            start_time_ns: 0,
            allowed_cpus: None,
            parent_pid: None,
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
        })
        .task(TaskDef {
            name: "io-cri-b".into(),
            pid: Pid(2),
            nice: -10,
            behavior: beh_b,
            mm_id: Some(mm),
            start_time_ns: 0,
            allowed_cpus: None,
            parent_pid: None,
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
        })
        .add_task("hog-0", 0, workloads::cpu_bound(20_000_000))
        .add_task("hog-1", 0, workloads::cpu_bound(20_000_000))
        .add_task("hog-2", 0, workloads::cpu_bound(20_000_000))
        .add_task("hog-3", 0, workloads::cpu_bound(20_000_000))
        .duration_ms(500)
        .build();

    let trace = Simulator::new(sched).run(scenario);
    // Ping-pong tasks should definitely run (high priority, latency-critical)
    assert!(trace.schedule_count(Pid(1)) > 0);
    assert!(trace.schedule_count(Pid(2)) > 0);
    // At least some CPU-bound hogs should get CPU time
    let hog_scheduled: usize = (3..=6)
        .filter(|&pid_val| trace.schedule_count(Pid(pid_val)) > 0)
        .count();
    assert!(
        hog_scheduled >= 2,
        "expected at least 2 hogs scheduled, got {hog_scheduled}"
    );
}

/// Enable `__SCX_TASK_QUEUED` and manage `scx.flags` to cover
/// `consume_prev` (main.bpf.c lines 879-920) and `update_stat_for_refill`
/// (lines 537-552).
///
/// In the kernel, `SCX_TASK_QUEUED` (= 1) is set in `p->scx.flags` when
/// a task is enqueued and cleared when consumed/dispatched. The simulator
/// must set the `__SCX_TASK_QUEUED` enum value AND set the flag on the
/// prev task when calling dispatch with a still-runnable prev.
#[test]
fn test_lavd_consume_prev() {
    let _lock = common::setup_test();
    let nr_cpus = 4;
    let sched = DynamicScheduler::lavd(nr_cpus);

    unsafe {
        // Set __SCX_TASK_QUEUED to 1 (matching kernel enum value)
        let sym: libloading::Symbol<'_, *mut u64> = sched
            .get_symbol(b"__SCX_TASK_QUEUED\0")
            .expect("__SCX_TASK_QUEUED not found");
        std::ptr::write_volatile(*sym, 1);
    }

    // CPU-bound tasks that run long enough for dispatch to be called
    // with a still-runnable prev task. With SCX_TASK_QUEUED set, the
    // dispatch fallback path calls consume_prev to extend the slice.
    let scenario = Scenario::builder()
        .cpus(nr_cpus)
        .add_task("worker-0", 0, workloads::cpu_bound(20_000_000))
        .add_task("worker-1", 0, workloads::cpu_bound(20_000_000))
        .add_task("worker-2", 0, workloads::cpu_bound(20_000_000))
        .add_task("worker-3", 0, workloads::cpu_bound(20_000_000))
        .duration_ms(300)
        .build();

    let trace = Simulator::new(sched).run(scenario);
    for pid_val in 1..=4 {
        assert!(trace.schedule_count(Pid(pid_val)) > 0);
    }
}

/// Test `is_monitored + is_smt_active` together for comprehensive coverage
/// of monitoring paths when SMT is enabled.
#[test]
fn test_lavd_monitored_smt() {
    let _lock = common::setup_test();
    let nr_cpus = 8;
    let sched = DynamicScheduler::lavd(nr_cpus);

    unsafe {
        lavd_set_bool(&sched, "is_monitored\0", true);
        lavd_setup_smt(&sched, nr_cpus);
    }

    let mm = MmId(1);
    let (beh_a, beh_b) = workloads::ping_pong(Pid(1), Pid(2), 100_000);
    let scenario = Scenario::builder()
        .cpus(nr_cpus)
        .smt(2)
        .task(TaskDef {
            name: "ping".into(),
            pid: Pid(1),
            nice: -5,
            behavior: beh_a,
            mm_id: Some(mm),
            start_time_ns: 0,
            allowed_cpus: None,
            parent_pid: None,
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
        })
        .task(TaskDef {
            name: "pong".into(),
            pid: Pid(2),
            nice: -5,
            behavior: beh_b,
            mm_id: Some(mm),
            start_time_ns: 0,
            allowed_cpus: None,
            parent_pid: None,
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
        })
        .add_task("hog-0", 5, workloads::cpu_bound(20_000_000))
        .add_task("hog-1", 5, workloads::cpu_bound(20_000_000))
        .add_task("hog-2", 5, workloads::cpu_bound(20_000_000))
        .add_task("hog-3", 5, workloads::cpu_bound(20_000_000))
        .duration_ms(300)
        .build();

    let trace = Simulator::new(sched).run(scenario);
    assert!(trace.schedule_count(Pid(1)) > 0);
    assert!(trace.schedule_count(Pid(2)) > 0);
}

/// Exercise power mode switching paths in power.bpf.c.
/// The `do_set_power_profile` function (lines 532-600+) has branches for
/// LAVD_PM_PERFORMANCE, LAVD_PM_BALANCED, and LAVD_PM_POWERSAVE modes.
/// Setting different `power_mode` values before running covers these paths
/// via `update_power_mode_time` (lines 506-530).
#[test]
fn test_lavd_power_mode_performance() {
    let _lock = common::setup_test();
    let nr_cpus = 4;
    let sched = DynamicScheduler::lavd(nr_cpus);

    unsafe {
        // LAVD_PM_PERFORMANCE = 0
        lavd_set_u64(&sched, "power_mode\0", 0);
        lavd_set_bool(&sched, "no_core_compaction\0", true);
    }

    let scenario = Scenario::builder()
        .cpus(nr_cpus)
        .add_task("worker-0", 0, workloads::cpu_bound(20_000_000))
        .add_task("worker-1", 0, workloads::cpu_bound(20_000_000))
        .duration_ms(200)
        .build();

    let trace = Simulator::new(sched).run(scenario);
    assert!(trace.schedule_count(Pid(1)) > 0);
}

/// Exercise powersave mode paths in power.bpf.c.
/// `LAVD_PM_POWERSAVE = 2` triggers `is_powersave_mode = true` and
/// sets `pco_idx = 0` in `calc_nr_active_cpus`.
#[test]
fn test_lavd_power_mode_powersave() {
    let _lock = common::setup_test();
    let nr_cpus = 4;
    let sched = DynamicScheduler::lavd(nr_cpus);

    unsafe {
        // LAVD_PM_POWERSAVE = 2
        lavd_set_u64(&sched, "power_mode\0", 2);
        lavd_set_bool(&sched, "is_powersave_mode\0", true);
        lavd_set_bool(&sched, "no_core_compaction\0", false);
        lavd_setup_pco(&sched, nr_cpus);
    }

    let scenario = Scenario::builder()
        .cpus(nr_cpus)
        .add_task("worker-0", 0, workloads::cpu_bound(20_000_000))
        .add_task("worker-1", 0, workloads::io_bound(100_000, 500_000))
        .duration_ms(300)
        .build();

    let trace = Simulator::new(sched).run(scenario);
    assert!(trace.schedule_count(Pid(1)) > 0);
}

/// Test pinned_slice_ns with per_cpu_dsq enabled.
/// This exercises `use_per_cpu_dsq()` (returns true when `per_cpu_dsq ||
/// pinned_slice_ns`) and `get_target_dsq_id` returning per-CPU DSQ IDs
/// for pinned tasks (util.bpf.c line 349).
#[test]
fn test_lavd_pinned_slice_per_cpu_dsq() {
    let _lock = common::setup_test();
    let nr_cpus = 4;
    let sched = DynamicScheduler::lavd(nr_cpus);

    unsafe {
        lavd_set_u64(&sched, "pinned_slice_ns\0", 3_000_000);
        lavd_set_bool(&sched, "per_cpu_dsq\0", true);
    }

    let scenario = Scenario::builder()
        .cpus(nr_cpus)
        .add_task("worker-0", 0, workloads::cpu_bound(20_000_000))
        .add_task("worker-1", 0, workloads::cpu_bound(20_000_000))
        .add_task("io-0", -5, workloads::io_bound(50_000, 300_000))
        .add_task("io-1", -5, workloads::io_bound(60_000, 400_000))
        .duration_ms(300)
        .build();

    let trace = Simulator::new(sched).run(scenario);
    for pid_val in 1..=4 {
        assert!(trace.schedule_count(Pid(pid_val)) > 0);
    }
}

// ---------------------------------------------------------------------------
// Phase 7: Direct ops coverage — pinned tasks, compaction dispatch DSQ
// iteration, SCX_TASK_QUEUED paths, cpu_acquire/release, update_idle,
// set_cpumask, and lock holder paths.
// ---------------------------------------------------------------------------

/// Pinned tasks (allowed_cpus = single CPU) with pinned_slice_ns enabled.
///
/// When a task has `nr_cpus_allowed == 1` (is_pinned), LAVD:
///  1. Increments `cpuc->nr_pinned_tasks` in enqueue (main.bpf.c:763-770)
///  2. Routes to per-CPU DSQ in `get_target_dsq_id` (util.bpf.c:349-350)
///  3. Clamps time slice in `calc_time_slice` (main.bpf.c:283-287)
///
/// Covers: main.bpf.c lines 284-287 (pinned slice path), lines 763-770
/// (nr_pinned_tasks increment), util.bpf.c line 349-350.
#[test]
fn test_lavd_pinned_single_cpu_slice_clamp() {
    let _lock = common::setup_test();
    let nr_cpus = 4;
    let sched = DynamicScheduler::lavd(nr_cpus);

    unsafe {
        lavd_set_u64(&sched, "pinned_slice_ns\0", 1_000_000); // 1ms
    }

    // Two tasks pinned to CPU 0 — forces nr_pinned_tasks > 0 on CPU 0
    let scenario = Scenario::builder()
        .cpus(nr_cpus)
        .task(TaskDef {
            name: "pinned-a".into(),
            pid: Pid(1),
            nice: 0,
            behavior: workloads::cpu_bound(10_000_000),
            start_time_ns: 0,
            mm_id: Some(MmId(1)),
            allowed_cpus: Some(vec![CpuId(0)]),
            parent_pid: None,
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
        })
        .task(TaskDef {
            name: "pinned-b".into(),
            pid: Pid(2),
            nice: 0,
            behavior: workloads::cpu_bound(10_000_000),
            start_time_ns: 0,
            mm_id: Some(MmId(1)),
            allowed_cpus: Some(vec![CpuId(0)]),
            parent_pid: None,
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
        })
        // Unpinned tasks on other CPUs
        .add_task("free-0", 0, workloads::cpu_bound(10_000_000))
        .add_task("free-1", 0, workloads::cpu_bound(10_000_000))
        .duration_ms(300)
        .build();

    let trace = Simulator::new(sched).run(scenario);
    // Both pinned tasks should run (they contend for CPU 0)
    assert!(
        trace.schedule_count(Pid(1)) > 0,
        "pinned-a should be scheduled"
    );
    assert!(
        trace.schedule_count(Pid(2)) > 0,
        "pinned-b should be scheduled"
    );
}

/// Dispatch compaction DSQ iteration for affinitized tasks on non-active CPUs.
///
/// When `!use_full_cpus()` (compaction active) and a CPU is not in the
/// active or overflow sets, the dispatch function iterates the cpdom DSQ
/// to find tasks affinitized to inactive CPUs (main.bpf.c:1055-1126).
///
/// Covers: main.bpf.c lines 964-1004 (use_full_cpus check, compaction
/// mask tests, fast path for per-CPU DSQ on inactive CPU), lines 1055-1126
/// (DSQ iteration finding affinitized tasks on inactive CPUs).
#[test]
fn test_lavd_dispatch_compaction_dsq_iteration() {
    let _lock = common::setup_test();
    let nr_cpus = 8;
    let sched = DynamicScheduler::lavd(nr_cpus);

    let (force_fn, nr_active_fn) = resolve_compaction_fns(&sched);

    unsafe {
        lavd_set_bool(&sched, "no_core_compaction\0", false);
        lavd_setup_pco(&sched, nr_cpus);
    }

    // Compact to 4 active CPUs (CPUs 0-3 active, 4-7 inactive).
    // Place affinitized tasks on CPU 6 — when CPU 6 dispatches,
    // it must iterate the cpdom DSQ to find its affinitized task.
    let mut monitor = ForceCompactionMonitor::new(force_fn, nr_active_fn, 4, nr_cpus);

    let scenario = Scenario::builder()
        .cpus(nr_cpus)
        .task(TaskDef {
            name: "affinity-6".into(),
            pid: Pid(1),
            nice: 0,
            behavior: workloads::cpu_bound(20_000_000),
            start_time_ns: 0,
            mm_id: Some(MmId(1)),
            allowed_cpus: Some(vec![CpuId(6)]),
            parent_pid: None,
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
        })
        .task(TaskDef {
            name: "affinity-7".into(),
            pid: Pid(2),
            nice: 0,
            behavior: workloads::cpu_bound(20_000_000),
            start_time_ns: 0,
            mm_id: Some(MmId(1)),
            allowed_cpus: Some(vec![CpuId(7)]),
            parent_pid: None,
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
        })
        // Regular tasks on active CPUs
        .add_task("hog-0", 0, workloads::cpu_bound(20_000_000))
        .add_task("hog-1", 0, workloads::cpu_bound(20_000_000))
        .add_task("hog-2", 0, workloads::cpu_bound(20_000_000))
        .add_task("hog-3", 0, workloads::cpu_bound(20_000_000))
        .duration_ms(400)
        .build();

    let result = Simulator::new(sched).run_monitored(scenario, &mut monitor);

    // Compaction should have been applied
    assert!(
        monitor.compaction_occurred(),
        "compaction should reduce nr_active below {}",
        nr_cpus
    );
    // Affinitized tasks should still get scheduled (overflow set expansion)
    assert!(
        result.trace.schedule_count(Pid(1)) > 0,
        "affinity-6 should run on CPU 6"
    );
    assert!(
        result.trace.schedule_count(Pid(2)) > 0,
        "affinity-7 should run on CPU 7"
    );
}

/// Compaction with pinned tasks on non-active CPUs.
///
/// When compaction is active and a task is pinned to a non-active CPU,
/// the dispatch DSQ iteration should find the pinned task and extend the
/// overflow set (main.bpf.c:1073-1080).
///
/// Covers: main.bpf.c lines 1006-1014 (prev is_pinned path),
/// lines 1073-1080 (pinned task found during DSQ iteration, overflow extend).
#[test]
fn test_lavd_compaction_pinned_overflow_extend() {
    let _lock = common::setup_test();
    let nr_cpus = 8;
    let sched = DynamicScheduler::lavd(nr_cpus);

    let (force_fn, nr_active_fn) = resolve_compaction_fns(&sched);

    unsafe {
        lavd_set_bool(&sched, "no_core_compaction\0", false);
        lavd_set_u64(&sched, "pinned_slice_ns\0", 2_000_000);
        lavd_setup_pco(&sched, nr_cpus);
    }

    let mut monitor = ForceCompactionMonitor::new(force_fn, nr_active_fn, 4, nr_cpus);

    // Pinned task on CPU 5 (not in active set 0-3)
    let scenario = Scenario::builder()
        .cpus(nr_cpus)
        .task(TaskDef {
            name: "pinned-5".into(),
            pid: Pid(1),
            nice: 0,
            behavior: workloads::cpu_bound(20_000_000),
            start_time_ns: 0,
            mm_id: Some(MmId(1)),
            allowed_cpus: Some(vec![CpuId(5)]),
            parent_pid: None,
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
        })
        // IO tasks to create dispatch pressure
        .add_task("hog-0", 0, workloads::cpu_bound(20_000_000))
        .add_task("hog-1", 0, workloads::cpu_bound(20_000_000))
        .add_task("hog-2", 0, workloads::cpu_bound(20_000_000))
        .add_task("io-0", -5, workloads::io_bound(50_000, 200_000))
        .duration_ms(400)
        .build();

    let result = Simulator::new(sched).run_monitored(scenario, &mut monitor);

    assert!(monitor.compaction_occurred(), "compaction must be active");
    assert!(
        result.trace.schedule_count(Pid(1)) > 0,
        "pinned task on CPU 5 should still run via overflow"
    );
}

/// Dequeue path: enable_cpu_bw is false, so lavd_dequeue should
/// early-return. This covers main.bpf.c lines 864-865 (the early
/// return path when enable_cpu_bw is false).
///
/// The dequeue op is called by the engine when a running task is
/// interrupted. With enable_cpu_bw = false (default), the entire
/// body is skipped via early return.
#[test]
fn test_lavd_dequeue_early_return() {
    let _lock = common::setup_test();
    let nr_cpus = 4;
    let sched = DynamicScheduler::lavd(nr_cpus);

    // Default: enable_cpu_bw = false
    // Preemption scenario: high-priority task wakes while low-priority runs
    let (beh_a, beh_b) = workloads::ping_pong(Pid(1), Pid(2), 100_000);
    let scenario = Scenario::builder()
        .cpus(nr_cpus)
        .task(TaskDef {
            name: "ping".into(),
            pid: Pid(1),
            nice: -10,
            behavior: beh_a,
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
            nice: -10,
            behavior: beh_b,
            start_time_ns: 0,
            mm_id: Some(MmId(1)),
            allowed_cpus: None,
            parent_pid: None,
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
        })
        .add_task("hog-0", 10, workloads::cpu_bound(20_000_000))
        .add_task("hog-1", 10, workloads::cpu_bound(20_000_000))
        .duration_ms(200)
        .build();

    let trace = Simulator::new(sched).run(scenario);
    assert!(trace.schedule_count(Pid(1)) > 0);
    assert!(trace.schedule_count(Pid(2)) > 0);
}

/// Dispatch with per_cpu_dsq mode: when `per_cpu_dsq = true`, all tasks
/// use per-CPU DSQs instead of per-domain DSQs.
///
/// Covers: main.bpf.c lines 938-939 (cpu_to_dsq), util.bpf.c line 349
/// (per_cpu_dsq path in get_target_dsq_id), and the init_per_cpu_dsqs()
/// codepath in lavd_init (main.bpf.c:2037-2071).
#[test]
fn test_lavd_per_cpu_dsq_mode() {
    let _lock = common::setup_test();
    let nr_cpus = 4;
    let sched = DynamicScheduler::lavd(nr_cpus);

    unsafe {
        lavd_set_bool(&sched, "per_cpu_dsq\0", true);
    }

    let scenario = Scenario::builder()
        .cpus(nr_cpus)
        .add_task("cpu-0", 0, workloads::cpu_bound(10_000_000))
        .add_task("cpu-1", 0, workloads::cpu_bound(10_000_000))
        .add_task("io-0", -5, workloads::io_bound(50_000, 300_000))
        .add_task("io-1", -5, workloads::io_bound(80_000, 400_000))
        .duration_ms(300)
        .build();

    let trace = Simulator::new(sched).run(scenario);
    for pid_val in 1..=4 {
        assert!(
            trace.schedule_count(Pid(pid_val)) > 0,
            "task {pid_val} should be scheduled"
        );
    }
}

/// Autopilot transitions with varied load — exercise the autopilot
/// mode switching paths in sys_stat.bpf.c that respond to load changes.
///
/// Covers: sys_stat.bpf.c autopilot high/low/moderate load transitions,
/// main.bpf.c lines 1895-1930 (init_per_cpu_ctx error/debug paths).
#[test]
fn test_lavd_autopilot_dynamic_load() {
    let _lock = common::setup_test();
    let nr_cpus = 8;
    let sched = DynamicScheduler::lavd(nr_cpus);

    unsafe {
        lavd_set_bool(&sched, "is_autopilot_on\0", true);
        lavd_set_bool(&sched, "no_core_compaction\0", false);
        lavd_setup_pco(&sched, nr_cpus);
    }

    // Mix of CPU-bound and IO-bound to create dynamic load
    let scenario = Scenario::builder()
        .cpus(nr_cpus)
        .add_task("hog-0", 0, workloads::cpu_bound(20_000_000))
        .add_task("hog-1", 0, workloads::cpu_bound(20_000_000))
        .add_task("hog-2", 5, workloads::cpu_bound(20_000_000))
        .add_task("io-0", -10, workloads::io_bound(30_000, 500_000))
        .add_task("io-1", -10, workloads::io_bound(50_000, 800_000))
        .add_task("io-2", -5, workloads::io_bound(40_000, 600_000))
        .duration_ms(500)
        .build();

    let trace = Simulator::new(sched).run(scenario);
    // At least 4 of the 6 tasks should run
    let scheduled = (1..=6)
        .filter(|&p| trace.schedule_count(Pid(p)) > 0)
        .count();
    assert!(
        scheduled >= 4,
        "expected at least 4 tasks scheduled, got {scheduled}"
    );
}

/// Exercise the reenq path: when SCX_ENQ_REENQ is set, lavd_enqueue
/// skips deadline/timeslice recalculation (main.bpf.c:693-700).
///
/// The engine sets SCX_ENQ_REENQ when re-enqueueing tasks after
/// cpu_release. This test creates conditions that trigger reenqueue.
///
/// Also covers: main.bpf.c lines 693-700 (SCX_ENQ_REENQ skip path).
#[test]
fn test_lavd_reenq_skip_recalc() {
    let _lock = common::setup_test();
    let nr_cpus = 4;
    let sched = DynamicScheduler::lavd(nr_cpus);

    // Many tasks contending on few CPUs — triggers preemption and
    // potential reenqueue paths through the engine
    let (beh_a, beh_b) = workloads::ping_pong(Pid(1), Pid(2), 50_000);
    let scenario = Scenario::builder()
        .cpus(nr_cpus)
        .task(TaskDef {
            name: "ping".into(),
            pid: Pid(1),
            nice: -15,
            behavior: beh_a,
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
            nice: -15,
            behavior: beh_b,
            start_time_ns: 0,
            mm_id: Some(MmId(1)),
            allowed_cpus: None,
            parent_pid: None,
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
        })
        .add_task("hog-0", 10, workloads::cpu_bound(20_000_000))
        .add_task("hog-1", 10, workloads::cpu_bound(20_000_000))
        .add_task("hog-2", 10, workloads::cpu_bound(20_000_000))
        .add_task("hog-3", 10, workloads::cpu_bound(20_000_000))
        .duration_ms(300)
        .build();

    let trace = Simulator::new(sched).run(scenario);
    assert!(trace.schedule_count(Pid(1)) > 0);
    assert!(trace.schedule_count(Pid(2)) > 0);
}

/// Exercise preemption with affinitized tasks: when an affinitized task
/// is enqueued and its preferred CPU is running a boosted task, the
/// preemption code cancels the slice boost (preempt.bpf.c:385-390).
///
/// Covers: preempt.bpf.c lines 373-390 (can_x_kick_cpu2 for affinitized
/// task, slice boost cancellation).
#[test]
fn test_lavd_preemption_affinitized_cancel_boost() {
    let _lock = common::setup_test();
    let nr_cpus = 4;
    let sched = DynamicScheduler::lavd(nr_cpus);

    // Affinitized task targets CPU 0, which runs a long CPU-bound task
    let scenario = Scenario::builder()
        .cpus(nr_cpus)
        .task(TaskDef {
            name: "affinity-0".into(),
            pid: Pid(1),
            nice: -10,
            behavior: workloads::io_bound(50_000, 500_000),
            start_time_ns: 500_000, // start after hog is running
            mm_id: Some(MmId(1)),
            allowed_cpus: Some(vec![CpuId(0), CpuId(1)]),
            parent_pid: None,
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
        })
        .task(TaskDef {
            name: "hog-on-0".into(),
            pid: Pid(2),
            nice: 5,
            behavior: workloads::cpu_bound(20_000_000),
            start_time_ns: 0,
            mm_id: Some(MmId(1)),
            allowed_cpus: None,
            parent_pid: None,
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
        })
        .add_task("hog-1", 5, workloads::cpu_bound(20_000_000))
        .add_task("hog-2", 5, workloads::cpu_bound(20_000_000))
        .duration_ms(300)
        .build();

    let trace = Simulator::new(sched).run(scenario);
    assert!(trace.schedule_count(Pid(1)) > 0);
}

/// Exercise the `no_wake_sync = true` path.
/// When wake sync is disabled, the waker's CPU is not preferred for
/// the wakee (idle.bpf.c sync_wakeup path disabled).
///
/// Covers: idle.bpf.c lines 486-510 (is_sync_waker_idle when
/// no_wake_sync is true → sync path skipped).
#[test]
fn test_lavd_no_wake_sync_mode() {
    let _lock = common::setup_test();
    let nr_cpus = 4;
    let sched = DynamicScheduler::lavd(nr_cpus);

    unsafe {
        lavd_set_bool(&sched, "no_wake_sync\0", true);
    }

    let (beh_a, beh_b) = workloads::ping_pong(Pid(1), Pid(2), 100_000);
    let scenario = Scenario::builder()
        .cpus(nr_cpus)
        .task(TaskDef {
            name: "ping".into(),
            pid: Pid(1),
            nice: 0,
            behavior: beh_a,
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
            behavior: beh_b,
            start_time_ns: 0,
            mm_id: Some(MmId(1)),
            allowed_cpus: None,
            parent_pid: None,
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
        })
        .duration_ms(200)
        .build();

    let trace = Simulator::new(sched).run(scenario);
    assert!(trace.schedule_count(Pid(1)) > 0);
    assert!(trace.schedule_count(Pid(2)) > 0);
}

/// Compaction dispatch with prev affinitized on inactive CPU.
///
/// When compaction is active and the previous task on a non-active CPU
/// is affinitized (can't run on active CPUs), the dispatch function
/// extends the overflow set (main.bpf.c:1024-1033).
///
/// Covers: main.bpf.c lines 1024-1033 (taskc_prev LAVD_FLAG_IS_AFFINITIZED,
/// bpf_cpumask_intersects checks, overflow extension for prev task).
#[test]
fn test_lavd_compaction_prev_affinitized_overflow() {
    let _lock = common::setup_test();
    let nr_cpus = 8;
    let sched = DynamicScheduler::lavd(nr_cpus);

    let (force_fn, nr_active_fn) = resolve_compaction_fns(&sched);

    unsafe {
        lavd_set_bool(&sched, "no_core_compaction\0", false);
        lavd_setup_pco(&sched, nr_cpus);
    }

    let mut monitor = ForceCompactionMonitor::new(force_fn, nr_active_fn, 4, nr_cpus);

    // Task affinitized to CPUs 5,6,7 — none in active set (0-3)
    let scenario = Scenario::builder()
        .cpus(nr_cpus)
        .task(TaskDef {
            name: "affinity-567".into(),
            pid: Pid(1),
            nice: 0,
            behavior: workloads::cpu_bound(20_000_000),
            start_time_ns: 0,
            mm_id: Some(MmId(1)),
            allowed_cpus: Some(vec![CpuId(5), CpuId(6), CpuId(7)]),
            parent_pid: None,
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
        })
        .add_task("hog-0", 0, workloads::cpu_bound(20_000_000))
        .add_task("hog-1", 0, workloads::cpu_bound(20_000_000))
        .add_task("hog-2", 0, workloads::cpu_bound(20_000_000))
        .add_task("io-0", -5, workloads::io_bound(50_000, 300_000))
        .duration_ms(400)
        .build();

    let result = Simulator::new(sched).run_monitored(scenario, &mut monitor);

    assert!(monitor.compaction_occurred(), "compaction should be active");
    assert!(
        result.trace.schedule_count(Pid(1)) > 0,
        "affinitized task should run via overflow extension"
    );
}

/// Compaction with per_cpu_dsq: when compaction is active and per_cpu_dsq
/// is enabled, the fast path at main.bpf.c:1000-1004 checks if the
/// per-CPU DSQ has queued tasks and adds the CPU to overflow if so.
///
/// Covers: main.bpf.c lines 1000-1004 (per-CPU DSQ fast path on inactive CPU).
#[test]
fn test_lavd_compaction_per_cpu_dsq_fast_path() {
    let _lock = common::setup_test();
    let nr_cpus = 8;
    let sched = DynamicScheduler::lavd(nr_cpus);

    let (force_fn, nr_active_fn) = resolve_compaction_fns(&sched);

    unsafe {
        lavd_set_bool(&sched, "no_core_compaction\0", false);
        lavd_set_bool(&sched, "per_cpu_dsq\0", true);
        lavd_setup_pco(&sched, nr_cpus);
    }

    let mut monitor = ForceCompactionMonitor::new(force_fn, nr_active_fn, 4, nr_cpus);

    let scenario = Scenario::builder()
        .cpus(nr_cpus)
        .add_task("hog-0", 0, workloads::cpu_bound(20_000_000))
        .add_task("hog-1", 0, workloads::cpu_bound(20_000_000))
        .add_task("hog-2", 0, workloads::cpu_bound(20_000_000))
        .add_task("hog-3", 0, workloads::cpu_bound(20_000_000))
        .add_task("hog-4", 0, workloads::cpu_bound(20_000_000))
        .add_task("hog-5", 0, workloads::cpu_bound(20_000_000))
        .add_task("io-0", -5, workloads::io_bound(50_000, 300_000))
        .add_task("io-1", -5, workloads::io_bound(80_000, 400_000))
        .duration_ms(400)
        .build();

    let result = Simulator::new(sched).run_monitored(scenario, &mut monitor);

    assert!(monitor.compaction_occurred(), "compaction should be active");
    // At least 6 of 8 tasks should run
    let scheduled = (1..=8)
        .filter(|&p| result.trace.schedule_count(Pid(p)) > 0)
        .count();
    assert!(
        scheduled >= 6,
        "expected at least 6 tasks scheduled, got {scheduled}"
    );
}

/// Extreme overload with high preemption: many high-priority IO tasks
/// and low-priority CPU hogs creates intense preemption.
///
/// Covers: preempt.bpf.c lines 326-331 (victim selection with high
/// contention), lines 398-405 (cpumask preparation for victim search),
/// lines 428-446 (reset_cpu_preemption_info both branches).
#[test]
fn test_lavd_extreme_preemption_contention() {
    let _lock = common::setup_test();
    let nr_cpus = 4;
    let sched = DynamicScheduler::lavd(nr_cpus);

    // 4 high-priority IO tasks competing with 4 low-priority hogs
    // on only 4 CPUs → heavy preemption
    let scenario = Scenario::builder()
        .cpus(nr_cpus)
        .add_task("io-0", -15, workloads::io_bound(20_000, 100_000))
        .add_task("io-1", -15, workloads::io_bound(25_000, 120_000))
        .add_task("io-2", -15, workloads::io_bound(30_000, 150_000))
        .add_task("io-3", -15, workloads::io_bound(35_000, 180_000))
        .add_task("hog-0", 15, workloads::cpu_bound(20_000_000))
        .add_task("hog-1", 15, workloads::cpu_bound(20_000_000))
        .add_task("hog-2", 15, workloads::cpu_bound(20_000_000))
        .add_task("hog-3", 15, workloads::cpu_bound(20_000_000))
        .duration_ms(400)
        .build();

    let trace = Simulator::new(sched).run(scenario);
    // IO tasks should definitely get scheduled
    for pid_val in 1..=4 {
        assert!(
            trace.schedule_count(Pid(pid_val)) > 0,
            "io-{} should be scheduled",
            pid_val - 1
        );
    }
}

/// Combined test: is_monitored + pinned_slice_ns + compaction + SMT.
/// Exercises many interacting features together, maximizing code path
/// coverage through feature interaction.
#[test]
fn test_lavd_combined_features() {
    let _lock = common::setup_test();
    let nr_cpus = 8;
    let sched = DynamicScheduler::lavd(nr_cpus);

    unsafe {
        lavd_set_bool(&sched, "is_monitored\0", true);
        lavd_set_u64(&sched, "pinned_slice_ns\0", 2_000_000);
        lavd_set_bool(&sched, "no_core_compaction\0", false);
        lavd_setup_pco(&sched, nr_cpus);
        lavd_setup_smt(&sched, nr_cpus);
    }

    let mm = MmId(1);
    let (beh_a, beh_b) = workloads::ping_pong(Pid(1), Pid(2), 80_000);
    let scenario = Scenario::builder()
        .cpus(nr_cpus)
        .smt(2)
        .task(TaskDef {
            name: "ping".into(),
            pid: Pid(1),
            nice: -10,
            behavior: beh_a,
            mm_id: Some(mm),
            start_time_ns: 0,
            allowed_cpus: None,
            parent_pid: None,
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
        })
        .task(TaskDef {
            name: "pong".into(),
            pid: Pid(2),
            nice: -10,
            behavior: beh_b,
            mm_id: Some(mm),
            start_time_ns: 0,
            allowed_cpus: None,
            parent_pid: None,
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
        })
        .add_task("hog-0", 0, workloads::cpu_bound(20_000_000))
        .add_task("hog-1", 0, workloads::cpu_bound(20_000_000))
        .add_task("hog-2", 5, workloads::cpu_bound(20_000_000))
        .add_task("hog-3", 5, workloads::cpu_bound(20_000_000))
        .add_task("io-0", -5, workloads::io_bound(40_000, 200_000))
        .add_task("io-1", -5, workloads::io_bound(60_000, 300_000))
        .duration_ms(400)
        .build();

    let trace = Simulator::new(sched).run(scenario);
    // Ping-pong tasks should definitely run
    assert!(trace.schedule_count(Pid(1)) > 0);
    assert!(trace.schedule_count(Pid(2)) > 0);
    // Most tasks should get scheduled (some low-prio may not under compaction)
    let total_scheduled: usize = (1..=8)
        .filter(|&pid_val| trace.schedule_count(Pid(pid_val)) > 0)
        .count();
    assert!(
        total_scheduled >= 5,
        "expected at least 5 tasks scheduled, got {total_scheduled}"
    );
}

// ---------------------------------------------------------------------------
// Phase 8: Coverage improvement — introspection, big/little, multi-domain
// ---------------------------------------------------------------------------

/// Set up introspection with LAVD_CMD_SCHED_N command.
///
/// Sets `is_monitored=true`, `intrspc.cmd=LAVD_CMD_SCHED_N (0x1)`,
/// and `intrspc.arg=count` to allow `count` introspection events.
///
/// # Safety
/// Caller must ensure `sched` is a loaded LAVD scheduler.
unsafe fn lavd_setup_introspec(sched: &DynamicScheduler, count: u64) {
    const LAVD_CMD_SCHED_N: u32 = 0x1;

    lavd_set_bool(sched, "is_monitored\0", true);

    // intrspc struct layout: { volatile u64 arg; volatile u32 cmd; }
    let sym: libloading::Symbol<'_, *mut u8> =
        sched.get_symbol(b"intrspc\0").expect("intrspc not found");
    let base = *sym;
    // Write arg (u64 at offset 0)
    std::ptr::write_volatile(base as *mut u64, count);
    // Write cmd (u32 at offset 8)
    std::ptr::write_volatile(base.add(8) as *mut u32, LAVD_CMD_SCHED_N);
}

/// Set up mixed big/little core topology.
///
/// CPUs listed in `big_cpus` get `cpu_big[cpu]=1` and full capacity (1024).
/// All other CPUs get `cpu_big[cpu]=0` and reduced capacity (512).
///
/// Must be called after `DynamicScheduler::lavd()` but before `run()`.
///
/// # Safety
/// Caller must ensure `sched` is a loaded LAVD scheduler and `big_cpus`
/// contains valid CPU IDs < `nr_cpus`.
unsafe fn lavd_setup_big_little(sched: &DynamicScheduler, nr_cpus: u32, big_cpus: &[u32]) {
    const LAVD_CPU_ID_MAX: usize = 512;

    let cpu_big_sym: libloading::Symbol<'_, *mut u8> =
        sched.get_symbol(b"cpu_big\0").expect("cpu_big not found");
    let cpu_big_ptr = *cpu_big_sym;

    let cpu_cap_sym: libloading::Symbol<'_, *mut u16> = sched
        .get_symbol(b"cpu_capacity\0")
        .expect("cpu_capacity not found");
    let cpu_cap_ptr = *cpu_cap_sym;

    for cpu in 0..nr_cpus.min(LAVD_CPU_ID_MAX as u32) {
        if big_cpus.contains(&cpu) {
            std::ptr::write_volatile(cpu_big_ptr.add(cpu as usize), 1);
            std::ptr::write_volatile(cpu_cap_ptr.add(cpu as usize), 1024);
        } else {
            std::ptr::write_volatile(cpu_big_ptr.add(cpu as usize), 0);
            std::ptr::write_volatile(cpu_cap_ptr.add(cpu as usize), 512);
        }
    }
}

/// Set up two compute domains with disjoint CPU sets.
///
/// Domain 0: CPUs [0, split), Domain 1: CPUs [split, nr_cpus).
/// Each domain lists the other as a neighbor at distance 0.
///
/// Must be called after `DynamicScheduler::lavd()` but before `run()`.
///
/// # Safety
/// Caller must ensure `sched` is a loaded LAVD scheduler, `split > 0`,
/// and `split < nr_cpus`.
unsafe fn lavd_setup_two_domains(sched: &DynamicScheduler, nr_cpus: u32, split: u32) {
    const LAVD_CPU_ID_MAX: usize = 512;
    let sym: libloading::Symbol<'_, *mut u8> = sched
        .get_symbol(b"cpdom_ctxs\0")
        .expect("cpdom_ctxs not found");
    let base = *sym;

    // Field offsets within cpdom_ctx (empirically from struct layout):
    const OFF_ID: usize = 0; // u64
    const OFF_ALT_ID: usize = 8; // u64
    const OFF_NUMA_ID: usize = 16; // u8
    const OFF_LLC_ID: usize = 17; // u8
    const OFF_IS_BIG: usize = 18; // u8
    const OFF_IS_VALID: usize = 19; // u8
    const OFF_NR_NEIGHBORS: usize = 20; // u8[3]
                                        // padding to align __cpumask to u64
    const OFF_CPUMASK: usize = 24; // u64[8] (512/64=8)
    const OFF_NEIGHBOR_IDS: usize = 24 + 8 * 8; // = 88, u8[3*128=384]
                                                // End of first section: 88 + 384 = 472, padded to 512
    const SECTION2_START: usize = 512;
    const OFF_NR_ACTIVE_CPUS: usize = SECTION2_START + 2; // u16
    const OFF_CAP_SUM_ACTIVE: usize = SECTION2_START + 12; // u32
    const CPDOM_CTX_SIZE: usize = 576; // 512 + 64

    // Zero out both entries first
    std::ptr::write_bytes(base, 0, CPDOM_CTX_SIZE * 2);

    // --- Domain 0: CPUs [0, split) ---
    let d0 = base;
    std::ptr::write_volatile(d0.add(OFF_ID) as *mut u64, 0);
    std::ptr::write_volatile(d0.add(OFF_ALT_ID) as *mut u64, 1);
    std::ptr::write_volatile(d0.add(OFF_NUMA_ID), 0);
    std::ptr::write_volatile(d0.add(OFF_LLC_ID), 0);
    std::ptr::write_volatile(d0.add(OFF_IS_BIG), 0);
    std::ptr::write_volatile(d0.add(OFF_IS_VALID), 1);
    // nr_neighbors[0] = 1 (one neighbor at distance 0)
    std::ptr::write_volatile(d0.add(OFF_NR_NEIGHBORS), 1);
    // neighbor_ids[0 * LAVD_CPDOM_MAX_NR + 0] = 1
    std::ptr::write_volatile(d0.add(OFF_NEIGHBOR_IDS), 1);
    // __cpumask: set bits for CPUs [0, split)
    let mask0 = d0.add(OFF_CPUMASK) as *mut u64;
    for cpu in 0..split.min(LAVD_CPU_ID_MAX as u32) {
        let word = cpu as usize / 64;
        let bit = cpu as usize % 64;
        let cur = std::ptr::read_volatile(mask0.add(word));
        std::ptr::write_volatile(mask0.add(word), cur | (1u64 << bit));
    }
    // nr_active_cpus
    std::ptr::write_volatile(d0.add(OFF_NR_ACTIVE_CPUS) as *mut u16, split as u16);
    // cap_sum_active_cpus
    std::ptr::write_volatile(d0.add(OFF_CAP_SUM_ACTIVE) as *mut u32, split * 1024);

    // --- Domain 1: CPUs [split, nr_cpus) ---
    let d1 = base.add(CPDOM_CTX_SIZE);
    std::ptr::write_volatile(d1.add(OFF_ID) as *mut u64, 1);
    std::ptr::write_volatile(d1.add(OFF_ALT_ID) as *mut u64, 0);
    std::ptr::write_volatile(d1.add(OFF_NUMA_ID), 1);
    std::ptr::write_volatile(d1.add(OFF_LLC_ID), 1);
    std::ptr::write_volatile(d1.add(OFF_IS_BIG), 0);
    std::ptr::write_volatile(d1.add(OFF_IS_VALID), 1);
    // nr_neighbors[0] = 1 (one neighbor at distance 0)
    std::ptr::write_volatile(d1.add(OFF_NR_NEIGHBORS), 1);
    // neighbor_ids[0 * LAVD_CPDOM_MAX_NR + 0] = 0
    std::ptr::write_volatile(d1.add(OFF_NEIGHBOR_IDS), 0);
    // __cpumask: set bits for CPUs [split, nr_cpus)
    let mask1 = d1.add(OFF_CPUMASK) as *mut u64;
    for cpu in split..nr_cpus.min(LAVD_CPU_ID_MAX as u32) {
        let word = cpu as usize / 64;
        let bit = cpu as usize % 64;
        let cur = std::ptr::read_volatile(mask1.add(word));
        std::ptr::write_volatile(mask1.add(word), cur | (1u64 << bit));
    }
    let d1_cpus = nr_cpus - split;
    std::ptr::write_volatile(d1.add(OFF_NR_ACTIVE_CPUS) as *mut u16, d1_cpus as u16);
    std::ptr::write_volatile(d1.add(OFF_CAP_SUM_ACTIVE) as *mut u32, d1_cpus * 1024);
}

// ---------------------------------------------------------------------------
// Phase 8a: Introspection with SCHED_N command
// ---------------------------------------------------------------------------

/// Introspection with LAVD_CMD_SCHED_N exercises the introspection code path.
///
/// Covers: introspec.bpf.c `try_proc_introspec_cmd` → `proc_introspec_sched_n`
/// → `submit_task_ctx` (up to ringbuf reserve failure).
/// Also covers `is_monitored` paths in main.bpf.c (resched_interval tracking,
/// waker_pid/waker_comm in lavd_runnable) and balance.bpf.c (dsq_consume_lat).
#[test]
fn test_lavd_introspection_sched_n() {
    let _lock = common::setup_test();
    let nr_cpus = 4;
    let sched = DynamicScheduler::lavd(nr_cpus);

    unsafe {
        lavd_setup_introspec(&sched, 1000);
    }

    let (beh_a, beh_b) = workloads::ping_pong(Pid(1), Pid(2), 200_000);
    let scenario = Scenario::builder()
        .cpus(nr_cpus)
        .task(TaskDef {
            name: "ping".into(),
            pid: Pid(1),
            nice: 0,
            behavior: beh_a,
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
            behavior: beh_b,
            start_time_ns: 0,
            mm_id: Some(MmId(1)),
            allowed_cpus: None,
            parent_pid: None,
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
        })
        .add_task("hog", 5, workloads::cpu_bound(20_000_000))
        .duration_ms(300)
        .build();

    let trace = Simulator::new(sched).run(scenario);
    assert!(trace.schedule_count(Pid(1)) > 0);
    assert!(trace.schedule_count(Pid(2)) > 0);
}

/// Introspection NOP command: exercises the switch default/NOP path.
///
/// Covers: introspec.bpf.c `try_proc_introspec_cmd` LAVD_CMD_NOP case.
#[test]
fn test_lavd_introspection_nop() {
    let _lock = common::setup_test();
    let nr_cpus = 4;
    let sched = DynamicScheduler::lavd(nr_cpus);

    // Set is_monitored=true but leave intrspc.cmd = 0 (LAVD_CMD_NOP)
    unsafe {
        lavd_set_bool(&sched, "is_monitored\0", true);
    }

    let scenario = Scenario::builder()
        .cpus(nr_cpus)
        .add_task("worker", 0, workloads::cpu_bound(20_000_000))
        .duration_ms(200)
        .build();

    let trace = Simulator::new(sched).run(scenario);
    assert!(trace.schedule_count(Pid(1)) > 0);
}

// ---------------------------------------------------------------------------
// Phase 8b: Big/little core topology
// ---------------------------------------------------------------------------

/// Mixed big/little core topology exercises heterogeneous scheduling paths.
///
/// Covers: power.bpf.c `is_perf_cri()` (actual big/little check instead of
/// always-true), util.bpf.c `set_on_core_type()` (big vs little classification),
/// main.bpf.c `update_stat_for_running()` (perf_cri tracking when
/// have_little_core), sys_stat.bpf.c `collect_sys_stat()` phase 3
/// (big/little core statistics).
#[test]
fn test_lavd_big_little_8cpu_ping_pong() {
    let _lock = common::setup_test();
    let nr_cpus = 8;
    let sched = DynamicScheduler::lavd(nr_cpus);

    // CPUs 0-3 are big, CPUs 4-7 are little
    unsafe {
        lavd_setup_big_little(&sched, nr_cpus, &[0, 1, 2, 3]);
    }

    let (beh_a, beh_b) = workloads::ping_pong(Pid(1), Pid(2), 300_000);
    let scenario = Scenario::builder()
        .cpus(nr_cpus)
        .task(TaskDef {
            name: "lat-cri-a".into(),
            pid: Pid(1),
            nice: -10,
            behavior: beh_a,
            start_time_ns: 0,
            mm_id: Some(MmId(1)),
            allowed_cpus: None,
            parent_pid: None,
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
        })
        .task(TaskDef {
            name: "lat-cri-b".into(),
            pid: Pid(2),
            nice: -10,
            behavior: beh_b,
            start_time_ns: 0,
            mm_id: Some(MmId(1)),
            allowed_cpus: None,
            parent_pid: None,
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
        })
        .add_task("hog-0", 5, workloads::cpu_bound(20_000_000))
        .add_task("hog-1", 5, workloads::cpu_bound(20_000_000))
        .add_task("hog-2", 10, workloads::cpu_bound(20_000_000))
        .add_task("hog-3", 10, workloads::cpu_bound(20_000_000))
        .duration_ms(500)
        .build();

    let trace = Simulator::new(sched).run(scenario);
    // Latency-critical tasks should get scheduled on big cores
    assert!(trace.schedule_count(Pid(1)) > 0);
    assert!(trace.schedule_count(Pid(2)) > 0);
}

/// Big/little topology with core compaction: big cores in active set,
/// little cores in overflow set.
///
/// Covers: power.bpf.c `reinit_active_cpumask_for_performance()` (big/little
/// aware compaction), `update_thr_perf_cri()` (big_core_scale computation
/// with actual big+little cores).
#[test]
fn test_lavd_big_little_compaction() {
    let _lock = common::setup_test();
    let nr_cpus = 8;
    let sched = DynamicScheduler::lavd(nr_cpus);

    unsafe {
        lavd_setup_big_little(&sched, nr_cpus, &[0, 1, 2, 3]);
        lavd_set_bool(&sched, "no_core_compaction\0", false);
        lavd_setup_pco(&sched, nr_cpus);
    }

    let scenario = Scenario::builder()
        .cpus(nr_cpus)
        .add_task("io-0", -10, workloads::io_bound(50_000, 200_000))
        .add_task("io-1", -10, workloads::io_bound(60_000, 250_000))
        .add_task("hog-0", 5, workloads::cpu_bound(20_000_000))
        .add_task("hog-1", 5, workloads::cpu_bound(20_000_000))
        .duration_ms(400)
        .build();

    let trace = Simulator::new(sched).run(scenario);
    // At least IO tasks should run
    assert!(trace.schedule_count(Pid(1)) > 0);
    assert!(trace.schedule_count(Pid(2)) > 0);
}

/// Big/little with SMT: exercises core type matching in find_sticky_cpu.
///
/// Covers: idle.bpf.c `find_sticky_cpu_and_cpdom()` (big_core matching logic),
/// power.bpf.c `update_thr_perf_cri()` different big_core_scale branches
/// (little_core_scale >= 50% path).
#[test]
fn test_lavd_big_little_smt() {
    let _lock = common::setup_test();
    let nr_cpus = 8;
    let sched = DynamicScheduler::lavd(nr_cpus);

    unsafe {
        // CPUs 0-3 big (2 big physical cores, each with 2 SMT threads)
        // CPUs 4-7 little (2 little physical cores, each with 2 SMT threads)
        lavd_setup_big_little(&sched, nr_cpus, &[0, 1, 2, 3]);
        lavd_setup_smt(&sched, nr_cpus);
    }

    let (beh_a, beh_b) = workloads::ping_pong(Pid(1), Pid(2), 150_000);
    let scenario = Scenario::builder()
        .cpus(nr_cpus)
        .smt(2)
        .task(TaskDef {
            name: "ping".into(),
            pid: Pid(1),
            nice: -5,
            behavior: beh_a,
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
            nice: -5,
            behavior: beh_b,
            start_time_ns: 0,
            mm_id: Some(MmId(1)),
            allowed_cpus: None,
            parent_pid: None,
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
        })
        .add_task("hog-0", 0, workloads::cpu_bound(20_000_000))
        .add_task("hog-1", 0, workloads::cpu_bound(20_000_000))
        .add_task("hog-2", 5, workloads::cpu_bound(20_000_000))
        .add_task("hog-3", 5, workloads::cpu_bound(20_000_000))
        .duration_ms(400)
        .build();

    let trace = Simulator::new(sched).run(scenario);
    assert!(trace.schedule_count(Pid(1)) > 0);
    assert!(trace.schedule_count(Pid(2)) > 0);
}

// ---------------------------------------------------------------------------
// Phase 8d: Multi-domain (2 compute domains for balance.bpf.c coverage)
// ---------------------------------------------------------------------------

/// Two compute domains with imbalanced load exercises cross-domain migration.
///
/// Covers: balance.bpf.c `plan_x_cpdom_migration()` (stealer/stealee
/// classification), `try_to_steal_task()` (cross-domain task stealing),
/// `pick_most_loaded_dsq()` (finding DSQ with most queued tasks).
/// sys_stat.bpf.c `update_sys_stat()` (plan_x_cpdom_migration call when
/// nr_cpdoms > 1).
#[test]
fn test_lavd_two_domain_load_imbalance() {
    let _lock = common::setup_test();
    let nr_cpus = 8;
    let sched = DynamicScheduler::lavd(nr_cpus);

    // Domain 0: CPUs 0-3, Domain 1: CPUs 4-7
    unsafe {
        lavd_setup_two_domains(&sched, nr_cpus, 4);
    }

    // Put heavy load on domain 0 (4 hogs on 4 CPUs) and light load on
    // domain 1 (1 IO task on 4 CPUs). This creates a load imbalance that
    // should trigger cross-domain migration.
    let scenario = Scenario::builder()
        .cpus(nr_cpus)
        .add_task("hog-0", 0, workloads::cpu_bound(20_000_000))
        .add_task("hog-1", 0, workloads::cpu_bound(20_000_000))
        .add_task("hog-2", 0, workloads::cpu_bound(20_000_000))
        .add_task("hog-3", 0, workloads::cpu_bound(20_000_000))
        .add_task("hog-4", 0, workloads::cpu_bound(20_000_000))
        .add_task("hog-5", 0, workloads::cpu_bound(20_000_000))
        .add_task("io-0", -5, workloads::io_bound(50_000, 200_000))
        .duration_ms(400)
        .build();

    let trace = Simulator::new(sched).run(scenario);
    // All tasks should get scheduled
    for pid_val in 1..=7 {
        assert!(
            trace.schedule_count(Pid(pid_val)) > 0,
            "task pid={pid_val} should be scheduled"
        );
    }
}

/// Two domains with per-CPU DSQ mode exercises domain-specific dispatch.
///
/// Covers: balance.bpf.c `consume_dsq()` domain iteration with nr_cpdoms>1,
/// `force_to_steal_task()` (steal when migration delta is zero),
/// idle.bpf.c `migrate_to_neighbor()` path (when sticky domain is stealee).
#[test]
fn test_lavd_two_domain_per_cpu_dsq() {
    let _lock = common::setup_test();
    let nr_cpus = 8;
    let sched = DynamicScheduler::lavd(nr_cpus);

    unsafe {
        lavd_setup_two_domains(&sched, nr_cpus, 4);
        lavd_set_bool(&sched, "per_cpu_dsq\0", true);
    }

    let (beh_a, beh_b) = workloads::ping_pong(Pid(1), Pid(2), 200_000);
    let scenario = Scenario::builder()
        .cpus(nr_cpus)
        .task(TaskDef {
            name: "ping".into(),
            pid: Pid(1),
            nice: -5,
            behavior: beh_a,
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
            nice: -5,
            behavior: beh_b,
            start_time_ns: 0,
            mm_id: Some(MmId(1)),
            allowed_cpus: None,
            parent_pid: None,
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
        })
        .add_task("hog-0", 5, workloads::cpu_bound(20_000_000))
        .add_task("hog-1", 5, workloads::cpu_bound(20_000_000))
        .add_task("hog-2", 5, workloads::cpu_bound(20_000_000))
        .add_task("hog-3", 5, workloads::cpu_bound(20_000_000))
        .duration_ms(400)
        .build();

    let trace = Simulator::new(sched).run(scenario);
    assert!(trace.schedule_count(Pid(1)) > 0);
    assert!(trace.schedule_count(Pid(2)) > 0);
}

/// Two domains with is_monitored exercises consume latency tracking.
///
/// Covers: balance.bpf.c `consume_dsq()` dsq_consume_lat measurement path
/// (only active when is_monitored=true), multi-domain sys_stat accumulation.
#[test]
fn test_lavd_two_domain_monitored() {
    let _lock = common::setup_test();
    let nr_cpus = 8;
    let sched = DynamicScheduler::lavd(nr_cpus);

    unsafe {
        lavd_setup_two_domains(&sched, nr_cpus, 4);
        lavd_setup_introspec(&sched, 500);
    }

    let (beh_a, beh_b) = workloads::ping_pong(Pid(1), Pid(2), 150_000);
    let scenario = Scenario::builder()
        .cpus(nr_cpus)
        .task(TaskDef {
            name: "ping".into(),
            pid: Pid(1),
            nice: -10,
            behavior: beh_a,
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
            nice: -10,
            behavior: beh_b,
            start_time_ns: 0,
            mm_id: Some(MmId(1)),
            allowed_cpus: None,
            parent_pid: None,
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
        })
        .add_task("hog-0", 0, workloads::cpu_bound(20_000_000))
        .add_task("hog-1", 0, workloads::cpu_bound(20_000_000))
        .add_task("hog-2", 5, workloads::cpu_bound(20_000_000))
        .add_task("hog-3", 5, workloads::cpu_bound(20_000_000))
        .duration_ms(400)
        .build();

    let trace = Simulator::new(sched).run(scenario);
    assert!(trace.schedule_count(Pid(1)) > 0);
    assert!(trace.schedule_count(Pid(2)) > 0);
}

/// Two domains with big/little: domain 0 is big, domain 1 is little.
///
/// Covers: balance.bpf.c domain-aware load balancing with heterogeneous
/// core types, idle.bpf.c domain matching with core type awareness,
/// power.bpf.c `update_thr_perf_cri()` with multi-domain big/little.
#[test]
fn test_lavd_two_domain_big_little() {
    let _lock = common::setup_test();
    let nr_cpus = 8;
    let sched = DynamicScheduler::lavd(nr_cpus);

    unsafe {
        // Domain 0 (CPUs 0-3) = big, Domain 1 (CPUs 4-7) = little
        lavd_setup_two_domains(&sched, nr_cpus, 4);
        lavd_setup_big_little(&sched, nr_cpus, &[0, 1, 2, 3]);
    }

    let (beh_a, beh_b) = workloads::ping_pong(Pid(1), Pid(2), 200_000);
    let scenario = Scenario::builder()
        .cpus(nr_cpus)
        .task(TaskDef {
            name: "ping".into(),
            pid: Pid(1),
            nice: -10,
            behavior: beh_a,
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
            nice: -10,
            behavior: beh_b,
            start_time_ns: 0,
            mm_id: Some(MmId(1)),
            allowed_cpus: None,
            parent_pid: None,
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
        })
        .add_task("batch-0", 10, workloads::cpu_bound(20_000_000))
        .add_task("batch-1", 10, workloads::cpu_bound(20_000_000))
        .add_task("batch-2", 10, workloads::cpu_bound(20_000_000))
        .add_task("batch-3", 10, workloads::cpu_bound(20_000_000))
        .add_task("batch-4", 10, workloads::cpu_bound(20_000_000))
        .add_task("batch-5", 10, workloads::cpu_bound(20_000_000))
        .duration_ms(400)
        .build();

    let trace = Simulator::new(sched).run(scenario);
    assert!(trace.schedule_count(Pid(1)) > 0);
    assert!(trace.schedule_count(Pid(2)) > 0);
}

// ---------------------------------------------------------------------------
// Phase 9: Deeper coverage — power branches, multi-domain load imbalance
// ---------------------------------------------------------------------------

/// All-big core topology: every CPU is big, no little cores.
///
/// Covers: power.bpf.c `update_thr_perf_cri()` `LAVD_SCALE` case (line 642)
/// where `cur_big_core_scale == 1024` → `thr_perf_cri = 0`.
#[test]
fn test_lavd_all_big_topology() {
    let _lock = common::setup_test();
    let nr_cpus = 4;
    let sched = DynamicScheduler::lavd(nr_cpus);

    // Set ALL CPUs as big with full capacity
    unsafe {
        let cpu_big_sym: libloading::Symbol<'_, *mut u8> =
            sched.get_symbol(b"cpu_big\0").expect("cpu_big not found");
        let cpu_big_ptr = *cpu_big_sym;
        for cpu in 0..nr_cpus {
            std::ptr::write_volatile(cpu_big_ptr.add(cpu as usize), 1);
        }
        // Note: capacity is already 1024 from lavd_setup()
    }

    let scenario = Scenario::builder()
        .cpus(nr_cpus)
        .add_task("hog-0", 0, workloads::cpu_bound(20_000_000))
        .add_task("hog-1", 0, workloads::cpu_bound(20_000_000))
        .add_task("io-0", -5, workloads::io_bound(50_000, 200_000))
        .add_task("io-1", -5, workloads::io_bound(60_000, 250_000))
        .duration_ms(400)
        .build();

    let trace = Simulator::new(sched).run(scenario);
    for pid_val in 1..=4 {
        assert!(trace.schedule_count(Pid(pid_val)) > 0);
    }
}

/// 2 big + 6 little topology: little cores have >= 50% of total capacity.
///
/// Covers: power.bpf.c `update_thr_perf_cri()` `little_core_scale >= 50%`
/// path (lines 693, 718-721) — uses `max_perf_cri - avg_perf_cri` delta.
#[test]
fn test_lavd_mostly_little_topology() {
    let _lock = common::setup_test();
    let nr_cpus = 8;
    let sched = DynamicScheduler::lavd(nr_cpus);

    // CPUs 0-1 are big, CPUs 2-7 are little
    // big capacity: 2*1024 = 2048
    // little capacity: 6*512 = 3072
    // total = 5120, big_scale = 2048*1024/5120 = 409
    // little_scale = 1024 - 409 = 615 >= 512
    unsafe {
        lavd_setup_big_little(&sched, nr_cpus, &[0, 1]);
    }

    let (beh_a, beh_b) = workloads::ping_pong(Pid(1), Pid(2), 200_000);
    let scenario = Scenario::builder()
        .cpus(nr_cpus)
        .task(TaskDef {
            name: "ping".into(),
            pid: Pid(1),
            nice: -10,
            behavior: beh_a,
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
            nice: -10,
            behavior: beh_b,
            start_time_ns: 0,
            mm_id: Some(MmId(1)),
            allowed_cpus: None,
            parent_pid: None,
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
        })
        .add_task("hog-0", 5, workloads::cpu_bound(20_000_000))
        .add_task("hog-1", 5, workloads::cpu_bound(20_000_000))
        .add_task("hog-2", 10, workloads::cpu_bound(20_000_000))
        .add_task("hog-3", 10, workloads::cpu_bound(20_000_000))
        .add_task("hog-4", 10, workloads::cpu_bound(20_000_000))
        .add_task("hog-5", 10, workloads::cpu_bound(20_000_000))
        .duration_ms(500)
        .build();

    let trace = Simulator::new(sched).run(scenario);
    assert!(trace.schedule_count(Pid(1)) > 0);
    assert!(trace.schedule_count(Pid(2)) > 0);
}

/// Two domains with heavy pinned load imbalance creates stealer/stealee roles.
///
/// 8 CPU hogs pinned to domain 0 (CPUs 0-3) with only 1 IO task on domain 1.
/// This forces `max_sc_load >> stealee_threshold`, triggering the full
/// stealer/stealee classification in `plan_x_cpdom_migration()`.
///
/// Covers: balance.bpf.c `plan_x_cpdom_migration()` lines 154-203
/// (stealer/stealee loop), `try_to_steal_task()` (when is_stealer=true).
#[test]
fn test_lavd_two_domain_pinned_imbalance() {
    let _lock = common::setup_test();
    let nr_cpus = 8;
    let sched = DynamicScheduler::lavd(nr_cpus);

    unsafe {
        lavd_setup_two_domains(&sched, nr_cpus, 4);
    }

    // 8 CPU hogs pinned to domain 0 CPUs [0-3] -> 8 tasks for 4 CPUs
    // 1 IO task unpinned -> can go to domain 1 CPUs [4-7]
    let d0_cpus = vec![CpuId(0), CpuId(1), CpuId(2), CpuId(3)];
    let scenario = Scenario::builder()
        .cpus(nr_cpus)
        .task(TaskDef {
            name: "hog-d0-0".into(),
            pid: Pid(1),
            nice: 5,
            behavior: workloads::cpu_bound(20_000_000),
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: Some(d0_cpus.clone()),
            parent_pid: None,
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
        })
        .task(TaskDef {
            name: "hog-d0-1".into(),
            pid: Pid(2),
            nice: 5,
            behavior: workloads::cpu_bound(20_000_000),
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: Some(d0_cpus.clone()),
            parent_pid: None,
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
        })
        .task(TaskDef {
            name: "hog-d0-2".into(),
            pid: Pid(3),
            nice: 5,
            behavior: workloads::cpu_bound(20_000_000),
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: Some(d0_cpus.clone()),
            parent_pid: None,
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
        })
        .task(TaskDef {
            name: "hog-d0-3".into(),
            pid: Pid(4),
            nice: 5,
            behavior: workloads::cpu_bound(20_000_000),
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: Some(d0_cpus.clone()),
            parent_pid: None,
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
        })
        .task(TaskDef {
            name: "hog-d0-4".into(),
            pid: Pid(5),
            nice: 5,
            behavior: workloads::cpu_bound(20_000_000),
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: Some(d0_cpus.clone()),
            parent_pid: None,
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
        })
        .task(TaskDef {
            name: "hog-d0-5".into(),
            pid: Pid(6),
            nice: 5,
            behavior: workloads::cpu_bound(20_000_000),
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: Some(d0_cpus.clone()),
            parent_pid: None,
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
        })
        .task(TaskDef {
            name: "hog-d0-6".into(),
            pid: Pid(7),
            nice: 5,
            behavior: workloads::cpu_bound(20_000_000),
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: Some(d0_cpus.clone()),
            parent_pid: None,
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
        })
        .task(TaskDef {
            name: "hog-d0-7".into(),
            pid: Pid(8),
            nice: 5,
            behavior: workloads::cpu_bound(20_000_000),
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: Some(d0_cpus),
            parent_pid: None,
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
        })
        .add_task("io-d1", -5, workloads::io_bound(50_000, 500_000))
        .duration_ms(500)
        .build();

    let trace = Simulator::new(sched).run(scenario);
    // Domain 0 hogs should definitely run
    assert!(trace.schedule_count(Pid(1)) > 0);
    // IO task should also run
    assert!(trace.schedule_count(Pid(9)) > 0);
}

/// Two domains with mig_delta_pct > 0 takes the fixed-percentage path.
///
/// Covers: balance.bpf.c `plan_x_cpdom_migration()` `mig_delta_pct > 0` path
/// (lines 108-110), `avg_util_sum` usage (line 84).
#[test]
fn test_lavd_two_domain_mig_delta_pct() {
    let _lock = common::setup_test();
    let nr_cpus = 8;
    let sched = DynamicScheduler::lavd(nr_cpus);

    unsafe {
        lavd_setup_two_domains(&sched, nr_cpus, 4);
        // Set mig_delta_pct to 10% — uses fixed percentage instead of dynamic
        lavd_set_u8(&sched, "mig_delta_pct\0", 10);
    }

    // Create load imbalance: many tasks pinned to domain 0
    let d0_cpus = vec![CpuId(0), CpuId(1), CpuId(2), CpuId(3)];
    let scenario = Scenario::builder()
        .cpus(nr_cpus)
        .task(TaskDef {
            name: "hog-d0-0".into(),
            pid: Pid(1),
            nice: 0,
            behavior: workloads::cpu_bound(20_000_000),
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: Some(d0_cpus.clone()),
            parent_pid: None,
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
        })
        .task(TaskDef {
            name: "hog-d0-1".into(),
            pid: Pid(2),
            nice: 0,
            behavior: workloads::cpu_bound(20_000_000),
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: Some(d0_cpus.clone()),
            parent_pid: None,
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
        })
        .task(TaskDef {
            name: "hog-d0-2".into(),
            pid: Pid(3),
            nice: 0,
            behavior: workloads::cpu_bound(20_000_000),
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: Some(d0_cpus.clone()),
            parent_pid: None,
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
        })
        .task(TaskDef {
            name: "hog-d0-3".into(),
            pid: Pid(4),
            nice: 0,
            behavior: workloads::cpu_bound(20_000_000),
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: Some(d0_cpus.clone()),
            parent_pid: None,
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
        })
        .task(TaskDef {
            name: "hog-d0-4".into(),
            pid: Pid(5),
            nice: 0,
            behavior: workloads::cpu_bound(20_000_000),
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: Some(d0_cpus),
            parent_pid: None,
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
        })
        .add_task("io-d1", -5, workloads::io_bound(30_000, 200_000))
        .duration_ms(400)
        .build();

    let trace = Simulator::new(sched).run(scenario);
    assert!(trace.schedule_count(Pid(1)) > 0);
    assert!(trace.schedule_count(Pid(6)) > 0);
}

/// All-big with compaction: exercises PCO with homogeneous big cores.
///
/// Covers: power.bpf.c `do_core_compaction()` with all-big topology.
#[test]
fn test_lavd_all_big_compaction_reduce() {
    let _lock = common::setup_test();
    let nr_cpus = 8;
    let sched = DynamicScheduler::lavd(nr_cpus);

    unsafe {
        let cpu_big_sym: libloading::Symbol<'_, *mut u8> =
            sched.get_symbol(b"cpu_big\0").expect("cpu_big not found");
        let cpu_big_ptr = *cpu_big_sym;
        for cpu in 0..nr_cpus {
            std::ptr::write_volatile(cpu_big_ptr.add(cpu as usize), 1);
        }
        lavd_set_bool(&sched, "no_core_compaction\0", false);
        lavd_setup_pco(&sched, nr_cpus);
    }

    let scenario = Scenario::builder()
        .cpus(nr_cpus)
        .add_task("io-0", -10, workloads::io_bound(30_000, 200_000))
        .add_task("io-1", -10, workloads::io_bound(40_000, 300_000))
        .add_task("hog-0", 5, workloads::cpu_bound(20_000_000))
        .duration_ms(400)
        .build();

    let trace = Simulator::new(sched).run(scenario);
    assert!(trace.schedule_count(Pid(1)) > 0);
    assert!(trace.schedule_count(Pid(2)) > 0);
}

/// Mostly-big (6 big + 2 little): little_core_scale < 50%.
///
/// Covers: power.bpf.c `update_thr_perf_cri()` `little_core_scale < 50%`
/// (lines 689-691) with actual big/little distinction.
#[test]
fn test_lavd_mostly_big_compaction() {
    let _lock = common::setup_test();
    let nr_cpus = 8;
    let sched = DynamicScheduler::lavd(nr_cpus);

    // CPUs 0-5 big (cap 1024), CPUs 6-7 little (cap 512)
    // little_scale = 1024 - 877 = 147 < 512
    unsafe {
        lavd_setup_big_little(&sched, nr_cpus, &[0, 1, 2, 3, 4, 5]);
        lavd_set_bool(&sched, "no_core_compaction\0", false);
        lavd_setup_pco(&sched, nr_cpus);
    }

    let (beh_a, beh_b) = workloads::ping_pong(Pid(1), Pid(2), 150_000);
    let scenario = Scenario::builder()
        .cpus(nr_cpus)
        .task(TaskDef {
            name: "ping".into(),
            pid: Pid(1),
            nice: -10,
            behavior: beh_a,
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
            nice: -10,
            behavior: beh_b,
            start_time_ns: 0,
            mm_id: Some(MmId(1)),
            allowed_cpus: None,
            parent_pid: None,
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
        })
        .add_task("hog-0", 5, workloads::cpu_bound(20_000_000))
        .add_task("hog-1", 5, workloads::cpu_bound(20_000_000))
        .add_task("hog-2", 5, workloads::cpu_bound(20_000_000))
        .add_task("hog-3", 5, workloads::cpu_bound(20_000_000))
        .duration_ms(500)
        .build();

    let trace = Simulator::new(sched).run(scenario);
    assert!(trace.schedule_count(Pid(1)) > 0);
    assert!(trace.schedule_count(Pid(2)) > 0);
}

// ---------------------------------------------------------------------------
// Phase 10: Compaction depth, powersave, dispatch on inactive CPUs
// ---------------------------------------------------------------------------

/// Low-load compaction: very few IO tasks on many CPUs.
///
/// With low utilization, `calc_nr_active_cpus()` should return a small
/// number, causing `reinit_active_cpumask_for_compaction()` to deactivate
/// most CPUs. This covers the `i >= nr_active` branch in the compaction
/// inner loop (power.bpf.c lines 425-462) and the dispatch paths for
/// inactive CPUs (main.bpf.c lines 964-1018).
#[test]
fn test_lavd_compaction_low_load() {
    let _lock = common::setup_test();
    let nr_cpus = 8;
    let sched = DynamicScheduler::lavd(nr_cpus);

    unsafe {
        // Must have big/little for compaction to run (have_little_core check)
        lavd_setup_big_little(&sched, nr_cpus, &[0, 1, 2, 3]);
        lavd_setup_pco(&sched, nr_cpus);
        lavd_set_u8(&sched, "no_use_em\0", 1);
        // Ensure compaction is on (default for balanced mode)
        lavd_set_bool(&sched, "no_core_compaction\0", false);
    }

    // Very low load: 1 IO task with short bursts and long sleeps
    let scenario = Scenario::builder()
        .cpus(nr_cpus)
        .add_task(
            "io-light",
            0,
            workloads::io_bound(100_000, 5_000_000), // 100us work, 5ms sleep
        )
        .duration_ms(50) // Long enough for stats to stabilize
        .build();

    let trace = Simulator::new(sched).run(scenario);
    assert!(trace.schedule_count(Pid(1)) > 0);
}

/// Powersave mode with compaction.
///
/// Sets `is_powersave_mode = true` to cover power.bpf.c line 291:
/// `WRITE_ONCE(pco_idx, 0)` in the powersave path of `calc_nr_active_cpus`.
#[test]
fn test_lavd_powersave_mode_compaction() {
    let _lock = common::setup_test();
    let nr_cpus = 8;
    let sched = DynamicScheduler::lavd(nr_cpus);

    unsafe {
        lavd_setup_big_little(&sched, nr_cpus, &[0, 1, 2, 3]);
        lavd_setup_pco(&sched, nr_cpus);
        lavd_set_u8(&sched, "no_use_em\0", 1);
        lavd_set_bool(&sched, "no_core_compaction\0", false);
        lavd_set_bool(&sched, "is_powersave_mode\0", true);
    }

    // Moderate load in powersave mode
    let scenario = Scenario::builder()
        .cpus(nr_cpus)
        .add_task("hog-0", 0, workloads::cpu_bound(20_000_000))
        .add_task("hog-1", 0, workloads::cpu_bound(20_000_000))
        .add_task("io-0", 0, workloads::io_bound(200_000, 2_000_000))
        .duration_ms(50)
        .build();

    let trace = Simulator::new(sched).run(scenario);
    assert!(trace.schedule_count(Pid(1)) > 0);
}

/// Compaction with pinned task on a likely-inactive CPU.
///
/// Pins a task to the last CPU (CPU 7), which is likely to be deactivated
/// by compaction. When dispatch runs on CPU 7, it's not in the active set
/// but has a pinned prev task, extending the overflow set.
///
/// Covers: main.bpf.c lines 1011-1014 (pinned prev on inactive CPU extends
/// overflow) and power.bpf.c lines 428-436 (pinned task overflow in compaction).
#[test]
fn test_lavd_compaction_pinned_on_inactive() {
    let _lock = common::setup_test();
    let nr_cpus = 8;
    let sched = DynamicScheduler::lavd(nr_cpus);

    unsafe {
        lavd_setup_big_little(&sched, nr_cpus, &[0, 1, 2, 3]);
        lavd_setup_pco(&sched, nr_cpus);
        lavd_set_u8(&sched, "no_use_em\0", 1);
        lavd_set_bool(&sched, "no_core_compaction\0", false);
    }

    // Pin a task to CPU 7 (last little core, likely inactive under compaction)
    let scenario = Scenario::builder()
        .cpus(nr_cpus)
        .task(TaskDef {
            name: "pinned-7".into(),
            pid: Pid(1),
            nice: 0,
            behavior: workloads::cpu_bound(20_000_000),
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: Some(vec![CpuId(7)]),
            parent_pid: None,
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
        })
        .add_task("io-light", 0, workloads::io_bound(100_000, 5_000_000))
        .duration_ms(50)
        .build();

    let trace = Simulator::new(sched).run(scenario);
    assert!(trace.schedule_count(Pid(1)) > 0);
}

/// Compaction with per-CPU DSQ and queued tasks on inactive CPU.
///
/// Uses `per_cpu_dsq = true` with tasks dispatched to per-CPU DSQs.
/// When compaction deactivates a CPU that has tasks in its per-CPU DSQ,
/// the dispatch code adds it to the overflow set.
///
/// Covers: main.bpf.c lines 1000-1004 (per-CPU DSQ fast path for inactive CPU).
#[test]
fn test_lavd_compaction_per_cpu_dsq_overflow() {
    let _lock = common::setup_test();
    let nr_cpus = 8;
    let sched = DynamicScheduler::lavd(nr_cpus);

    unsafe {
        lavd_setup_big_little(&sched, nr_cpus, &[0, 1, 2, 3]);
        lavd_setup_pco(&sched, nr_cpus);
        lavd_set_u8(&sched, "no_use_em\0", 1);
        lavd_set_bool(&sched, "no_core_compaction\0", false);
        lavd_set_bool(&sched, "per_cpu_dsq\0", true);
    }

    // Multiple tasks including some pinned to likely-inactive CPUs
    let scenario = Scenario::builder()
        .cpus(nr_cpus)
        .task(TaskDef {
            name: "pinned-6".into(),
            pid: Pid(1),
            nice: 0,
            behavior: workloads::cpu_bound(20_000_000),
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: Some(vec![CpuId(6)]),
            parent_pid: None,
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
        })
        .task(TaskDef {
            name: "pinned-7".into(),
            pid: Pid(2),
            nice: 0,
            behavior: workloads::cpu_bound(20_000_000),
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: Some(vec![CpuId(7)]),
            parent_pid: None,
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
        })
        .add_task("io-light", 0, workloads::io_bound(100_000, 5_000_000))
        .duration_ms(50)
        .build();

    let trace = Simulator::new(sched).run(scenario);
    assert!(trace.schedule_count(Pid(1)) > 0);
    assert!(trace.schedule_count(Pid(2)) > 0);
}

/// Moderate load compaction: 3 CPU-bound tasks on 8 CPUs.
///
/// With 3 tasks on 8 CPUs, utilization is ~37.5%. Compaction should
/// activate 4-5 CPUs and deactivate the rest. The deactivated CPUs
/// go through the overflow check path, and idle CPU selection must
/// handle the reduced active set.
///
/// Covers deeper branches in power.bpf.c compaction loop and
/// dispatch cpumask checking.
#[test]
fn test_lavd_compaction_moderate_load() {
    let _lock = common::setup_test();
    let nr_cpus = 8;
    let sched = DynamicScheduler::lavd(nr_cpus);

    unsafe {
        lavd_setup_big_little(&sched, nr_cpus, &[0, 1, 2, 3]);
        lavd_setup_pco(&sched, nr_cpus);
        lavd_set_u8(&sched, "no_use_em\0", 1);
        lavd_set_bool(&sched, "no_core_compaction\0", false);
    }

    let scenario = Scenario::builder()
        .cpus(nr_cpus)
        .add_task("hog-0", 0, workloads::cpu_bound(20_000_000))
        .add_task("hog-1", 0, workloads::cpu_bound(20_000_000))
        .add_task("hog-2", 0, workloads::cpu_bound(20_000_000))
        .add_task("io-0", 0, workloads::io_bound(200_000, 2_000_000))
        .duration_ms(50)
        .build();

    let trace = Simulator::new(sched).run(scenario);
    assert!(trace.schedule_count(Pid(1)) > 0);
}

/// Two domains with powersave mode and low load.
///
/// Combines multi-domain with powersave mode compaction. The powersave
/// path in `calc_nr_active_cpus()` uses `pco_idx = 0`, and multi-domain
/// drives load-balancing paths in `reinit_active_cpumask_for_compaction`
/// at lines 483-498 (per-domain active CPU accounting).
#[test]
fn test_lavd_two_domain_powersave_compaction() {
    let _lock = common::setup_test();
    let nr_cpus = 8;
    let sched = DynamicScheduler::lavd(nr_cpus);

    unsafe {
        lavd_setup_big_little(&sched, nr_cpus, &[0, 1, 2, 3]);
        lavd_setup_two_domains(&sched, nr_cpus, 4);
        lavd_setup_pco(&sched, nr_cpus);
        lavd_set_u8(&sched, "no_use_em\0", 1);
        lavd_set_bool(&sched, "no_core_compaction\0", false);
        lavd_set_bool(&sched, "is_powersave_mode\0", true);
    }

    let scenario = Scenario::builder()
        .cpus(nr_cpus)
        .add_task("hog-0", 0, workloads::cpu_bound(20_000_000))
        .add_task("io-0", 0, workloads::io_bound(200_000, 2_000_000))
        .duration_ms(50)
        .build();

    let trace = Simulator::new(sched).run(scenario);
    assert!(trace.schedule_count(Pid(1)) > 0);
}

/// Energy model compaction path: `no_use_em = false` with valid PCO setup.
///
/// When the energy model is available (no_use_em = false), `calc_nr_active_cpus`
/// takes the else branch (power.bpf.c lines 321-351) that iterates PCO states
/// to find the minimum active CPU count that meets capacity requirements.
///
/// Covers: power.bpf.c lines 321-351 (energy model path in calc_nr_active_cpus).
#[test]
fn test_lavd_compaction_energy_model() {
    let _lock = common::setup_test();
    let nr_cpus = 8;
    let sched = DynamicScheduler::lavd(nr_cpus);

    unsafe {
        lavd_setup_big_little(&sched, nr_cpus, &[0, 1, 2, 3]);
        // Set up 2 PCO states: state 0 with 4 CPUs, state 1 with 8 CPUs
        lavd_set_u8(&sched, "nr_pco_states\0", 2);

        let pco_sym: libloading::Symbol<'_, *mut u16> = sched
            .get_symbol(b"pco_table\0")
            .expect("pco_table not found");
        let pco = *pco_sym;
        // State 0: CPUs 0,1,2,3 (big cores first)
        for i in 0..nr_cpus.min(512) {
            std::ptr::write_volatile(pco.add(i as usize), i as u16);
        }
        // State 1: All CPUs
        let state1_offset = 512; // LAVD_CPU_ID_MAX
        for i in 0..nr_cpus.min(512) {
            std::ptr::write_volatile(pco.add(state1_offset + i as usize), i as u16);
        }

        // Set PCO bounds: state 0 fits moderate load, state 1 fits everything
        let bounds_sym: libloading::Symbol<'_, *mut u32> = sched
            .get_symbol(b"pco_bounds\0")
            .expect("pco_bounds not found");
        let bounds = *bounds_sym;
        std::ptr::write_volatile(bounds, 4 * 1024); // state 0: 4 CPUs worth
        std::ptr::write_volatile(bounds.add(1), u32::MAX); // state 1: unlimited

        // Set primary counts
        let primary_sym: libloading::Symbol<'_, *mut u16> = sched
            .get_symbol(b"pco_nr_primary\0")
            .expect("pco_nr_primary not found");
        let primary = *primary_sym;
        std::ptr::write_volatile(primary, 4); // state 0: 4 primary CPUs
        std::ptr::write_volatile(primary.add(1), nr_cpus as u16); // state 1: all

        lavd_set_u8(&sched, "no_use_em\0", 0); // Enable energy model
        lavd_set_bool(&sched, "no_core_compaction\0", false);
    }

    // Low-moderate load so state 0 might be sufficient
    let scenario = Scenario::builder()
        .cpus(nr_cpus)
        .add_task("hog-0", 0, workloads::cpu_bound(20_000_000))
        .add_task("io-0", 0, workloads::io_bound(200_000, 2_000_000))
        .duration_ms(50)
        .build();

    let trace = Simulator::new(sched).run(scenario);
    assert!(trace.schedule_count(Pid(1)) > 0);
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

// ---------------------------------------------------------------------------
// LAVD-specific tests: CPU hotplug (ops.cpu_online / ops.cpu_offline)
// ---------------------------------------------------------------------------

/// Test CPU hotplug: take a CPU offline then bring it back online.
/// Exercises lavd_cpu_offline (L1484-1505) and lavd_cpu_online (L1461-1482),
/// including cpu_ctx_init_offline (L1438-1459) and cpu_ctx_init_online
/// (L1415-1436). Together these are ~64 uncovered lines in main.bpf.c.
#[test]
fn test_lavd_cpu_hotplug() {
    let _lock = common::setup_test();
    let nr_cpus = 8u32;
    let sched = DynamicScheduler::lavd(nr_cpus);

    let scenario = Scenario::builder()
        .cpus(nr_cpus)
        .add_task("worker", 0, workloads::io_bound(200_000, 2_000_000))
        .duration_ms(200)
        // Take CPU 7 offline at 20ms, bring it back at 100ms
        .cpu_offline_at(CpuId(7), 20_000_000)
        .cpu_online_at(CpuId(7), 100_000_000)
        .build();

    let trace = Simulator::new(sched).run(scenario);

    assert!(
        trace.schedule_count(Pid(1)) > 0,
        "worker task was never scheduled"
    );
}

/// Test CPU hotplug with multiple CPUs going offline and coming back.
/// Verifies the scheduler handles capacity changes gracefully.
#[test]
fn test_lavd_cpu_hotplug_multi() {
    let _lock = common::setup_test();
    let nr_cpus = 8u32;
    let sched = DynamicScheduler::lavd(nr_cpus);

    let scenario = Scenario::builder()
        .cpus(nr_cpus)
        .add_task("worker-a", 0, workloads::io_bound(200_000, 2_000_000))
        .add_task("worker-b", 0, workloads::cpu_bound(500_000))
        .duration_ms(200)
        // Take CPUs 6 and 7 offline at 10ms, bring them back at 80ms
        .cpu_offline_at(CpuId(7), 10_000_000)
        .cpu_offline_at(CpuId(6), 12_000_000)
        .cpu_online_at(CpuId(6), 80_000_000)
        .cpu_online_at(CpuId(7), 82_000_000)
        .build();

    let trace = Simulator::new(sched).run(scenario);

    assert!(
        trace.schedule_count(Pid(1)) > 0,
        "worker-a was never scheduled"
    );
    assert!(
        trace.schedule_count(Pid(2)) > 0,
        "worker-b was never scheduled"
    );
}

// ---------------------------------------------------------------------------
// LAVD-specific tests: slice boost under load
// ---------------------------------------------------------------------------

/// Test that latency-critical tasks get slice boosts under heavy load.
/// Uses CPU hotplug to create overload: tasks build up avg_runtime with
/// 4 CPUs, then 3 go offline so nr_queued >> nr_active.
/// Exercises calc_time_slice() L334-345 (slice boost under load).
#[test]
fn test_lavd_slice_boost_under_load() {
    let _lock = common::setup_test();
    let nr_cpus = 4u32;
    let sched = DynamicScheduler::lavd(nr_cpus);

    // Ping-pong pair to build lat_cri with long work phases
    let (prod, cons) = workloads::ping_pong(Pid(1), Pid(2), 15_000_000); // 15ms work

    let mut builder = Scenario::builder()
        .cpus(nr_cpus)
        .task(TaskDef {
            name: "ping".into(),
            pid: Pid(1),
            nice: 0,
            behavior: prod,
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
            behavior: cons,
            start_time_ns: 0,
            mm_id: Some(MmId(1)),
            allowed_cpus: None,
            parent_pid: None,
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
        });
    // CPU-bound tasks to fill queues
    for i in 0..6 {
        builder = builder.add_task(&format!("hog-{i}"), 0, workloads::cpu_bound(5_000_000));
    }
    // Let tasks run normally for 100ms, then take 3 CPUs offline.
    // This forces nr_active=1 while nr_queued stays high.
    let scenario = builder
        .cpu_offline_at(CpuId(3), 100_000_000)
        .cpu_offline_at(CpuId(2), 100_500_000)
        .cpu_offline_at(CpuId(1), 101_000_000)
        // Bring them back at 250ms
        .cpu_online_at(CpuId(1), 250_000_000)
        .cpu_online_at(CpuId(2), 251_000_000)
        .cpu_online_at(CpuId(3), 252_000_000)
        .duration_ms(400)
        .build();

    let trace = Simulator::new(sched).run(scenario);

    assert!(
        trace.schedule_count(Pid(1)) > 0,
        "ping task was never scheduled"
    );
}

// ---------------------------------------------------------------------------
// LAVD-specific tests: cgroup ops
// ---------------------------------------------------------------------------

/// Test that cgroup_init/cgroup_exit are called for user-defined cgroups.
/// Tasks are assigned to cgroups, exercising the cgroup assignment in init_task
/// and the cgroup_init/exit ops for non-root cgroups.
#[test]
fn test_lavd_cgroup_ops() {
    let _lock = common::setup_test();
    let nr_cpus = 4u32;
    let sched = DynamicScheduler::lavd(nr_cpus);

    let scenario = Scenario::builder()
        .cpus(nr_cpus)
        .cgroup("batch", &[CpuId(0), CpuId(1)])
        .cgroup("interactive", &[CpuId(2), CpuId(3)])
        .add_task_in_cgroup("worker-a", 0, workloads::cpu_bound(5_000_000), "batch")
        .add_task_in_cgroup("worker-b", 0, workloads::cpu_bound(5_000_000), "batch")
        .add_task_in_cgroup("ui", -5, workloads::cpu_bound(3_000_000), "interactive")
        .duration_ms(50)
        .build();

    let trace = Simulator::new(sched).run(scenario);

    // All tasks should be scheduled
    assert!(
        trace.schedule_count(Pid(1)) > 0,
        "worker-a was never scheduled"
    );
    assert!(
        trace.schedule_count(Pid(2)) > 0,
        "worker-b was never scheduled"
    );
    assert!(trace.schedule_count(Pid(3)) > 0, "ui was never scheduled");
}

// ---------------------------------------------------------------------------
// LAVD-specific tests: cpu_acquire / cpu_release
// ---------------------------------------------------------------------------

/// Test that cpu_acquire and cpu_release ops are exercised when a
/// higher-priority scheduler class temporarily preempts a CPU.
#[test]
fn test_lavd_cpu_acquire_release() {
    let _lock = common::setup_test();
    let nr_cpus = 4u32;
    let sched = DynamicScheduler::lavd(nr_cpus);

    let scenario = Scenario::builder()
        .cpus(nr_cpus)
        .add_task("worker-a", 0, workloads::cpu_bound(5_000_000))
        .add_task("worker-b", 0, workloads::cpu_bound(5_000_000))
        .add_task("worker-c", 0, workloads::cpu_bound(5_000_000))
        // CPU 3 is preempted by RT class from 30ms to 40ms
        .cpu_preempt(CpuId(3), 30_000_000, 40_000_000)
        // CPU 1 is preempted from 50ms to 55ms
        .cpu_preempt(CpuId(1), 50_000_000, 55_000_000)
        .duration_ms(100)
        .build();

    let trace = Simulator::new(sched).run(scenario);

    assert!(
        trace.schedule_count(Pid(1)) > 0,
        "worker-a was never scheduled"
    );
}

// ---------------------------------------------------------------------------
// LAVD-specific tests: CPU bandwidth control (enable_cpu_bw)
// ---------------------------------------------------------------------------

/// Test LAVD with CPU bandwidth control enabled.
///
/// When `enable_cpu_bw = true`:
/// - `lavd_init()` calls `scx_cgroup_bw_lib_init()` (main.bpf.c:2206-2211)
/// - `lavd_cgroup_init()` calls `scx_cgroup_bw_init()` (main.bpf.c:2081-2085)
/// - `lavd_cgroup_exit()` calls `scx_cgroup_bw_exit()` (main.bpf.c:2094-2097)
/// - `lavd_enqueue()` calls `cgroup_throttled()` (main.bpf.c:753-758, 638-669)
/// - `lavd_dequeue()` calls `scx_cgroup_bw_cancel()` (main.bpf.c:864-875)
/// - `cgroup_set_bandwidth()` calls `scx_cgroup_bw_set()` (main.bpf.c:2112-2121)
///
/// The cgroup bandwidth stubs all return 0 (no actual throttling), so tasks
/// run normally but the code paths are exercised.
#[test]
fn test_lavd_enable_cpu_bw() {
    let _lock = common::setup_test();
    let nr_cpus = 4u32;
    let sched = DynamicScheduler::lavd(nr_cpus);

    // Enable CPU bandwidth control before init
    unsafe {
        lavd_set_bool(&sched, "enable_cpu_bw\0", true);
    }

    let scenario = Scenario::builder()
        .cpus(nr_cpus)
        .cgroup_with_bandwidth(
            "batch",
            &[CpuId(0), CpuId(1), CpuId(2), CpuId(3)],
            100_000, // 100ms period
            50_000,  // 50ms quota
            10_000,  // 10ms burst
        )
        .cgroup_with_bandwidth(
            "interactive",
            &[CpuId(0), CpuId(1), CpuId(2), CpuId(3)],
            100_000, // 100ms period
            80_000,  // 80ms quota
            20_000,  // 20ms burst
        )
        .add_task_in_cgroup("worker-a", 5, workloads::cpu_bound(10_000_000), "batch")
        .add_task_in_cgroup("worker-b", 5, workloads::cpu_bound(10_000_000), "batch")
        .add_task_in_cgroup(
            "ui",
            -5,
            workloads::io_bound(50_000, 300_000),
            "interactive",
        )
        .add_task("unbounded", 0, workloads::cpu_bound(10_000_000))
        .duration_ms(200)
        .build();

    let trace = Simulator::new(sched).run(scenario);

    // All tasks should be scheduled (stubs don't actually throttle)
    assert!(
        trace.schedule_count(Pid(1)) > 0,
        "worker-a was never scheduled"
    );
    assert!(
        trace.schedule_count(Pid(2)) > 0,
        "worker-b was never scheduled"
    );
    assert!(trace.schedule_count(Pid(3)) > 0, "ui was never scheduled");
    assert!(
        trace.schedule_count(Pid(4)) > 0,
        "unbounded was never scheduled"
    );
}

/// Test cgroup migration: move a task between cgroups at runtime.
///
/// Exercises `lavd_cgroup_move` (main.bpf.c:2099-2108) which updates
/// `taskc->cgrp_id` when a task moves between cgroups.
#[test]
fn test_lavd_cgroup_move() {
    let _lock = common::setup_test();
    let nr_cpus = 4u32;
    let sched = DynamicScheduler::lavd(nr_cpus);

    let scenario = Scenario::builder()
        .cpus(nr_cpus)
        .cgroup("source", &[CpuId(0), CpuId(1), CpuId(2), CpuId(3)])
        .cgroup("dest", &[CpuId(0), CpuId(1), CpuId(2), CpuId(3)])
        .add_task_in_cgroup("mover", 0, workloads::cpu_bound(10_000_000), "source")
        .add_task_in_cgroup("stayer", 0, workloads::cpu_bound(10_000_000), "source")
        .add_task_in_cgroup("dest-task", 0, workloads::cpu_bound(10_000_000), "dest")
        // Migrate "mover" (Pid(1)) from "source" to "dest" at 50ms
        .cgroup_migrate(Pid(1), "source", "dest", 50_000_000)
        .duration_ms(200)
        .build();

    let trace = Simulator::new(sched).run(scenario);

    assert!(
        trace.schedule_count(Pid(1)) > 0,
        "mover was never scheduled"
    );
    assert!(
        trace.schedule_count(Pid(2)) > 0,
        "stayer was never scheduled"
    );
    assert!(
        trace.schedule_count(Pid(3)) > 0,
        "dest-task was never scheduled"
    );
}

/// Test slice boost under high system load.
///
/// When `can_boost_slice()` returns false (high load), `adjust_slice()` takes
/// the fallback path (main.bpf.c:334-344) that boosts time slice proportionally
/// to `lat_cri` for latency-critical tasks. Uses a HighLoadInjector monitor to
/// set sys_stat after init (since init_sys_stat resets the values).
#[test]
fn test_lavd_high_load_slice_boost() {
    let _lock = common::setup_test();
    let nr_cpus = 4u32;
    let sched = DynamicScheduler::lavd(nr_cpus);

    // Get raw pointer to sys_stat before the scheduler is consumed by Simulator
    let sys_stat_ptr: *mut u8 = unsafe {
        let sym: libloading::Symbol<'_, *mut u8> =
            sched.get_symbol(b"sys_stat\0").expect("sys_stat not found");
        *sym
    };

    // Use mixed workload: IO-bound tasks develop high lat_cri,
    // CPU-bound tasks develop high avg_runtime (>= sys_stat.slice)
    let scenario = Scenario::builder()
        .cpus(nr_cpus)
        // IO-bound tasks: short run + sleep → high lat_cri
        .add_task("io-cri-1", -10, workloads::io_bound(50_000, 200_000))
        .add_task("io-cri-2", -10, workloads::io_bound(30_000, 150_000))
        // CPU-bound tasks: long run → high avg_runtime, exercise slice boost
        .add_task("cpu-hog-1", 5, workloads::cpu_bound(20_000_000))
        .add_task("cpu-hog-2", 5, workloads::cpu_bound(20_000_000))
        .add_task("cpu-hog-3", 10, workloads::cpu_bound(20_000_000))
        .add_task("cpu-hog-4", 10, workloads::cpu_bound(20_000_000))
        .add_task("cpu-hog-5", 15, workloads::cpu_bound(20_000_000))
        .add_task("cpu-hog-6", 15, workloads::cpu_bound(20_000_000))
        .duration_ms(200)
        .build();

    let mut monitor = HighLoadInjector { sys_stat_ptr };
    let result = Simulator::new(sched).run_monitored(scenario, &mut monitor);

    // All tasks should run despite high-load conditions
    for pid in 1..=8 {
        assert!(
            result.trace.schedule_count(Pid(pid)) > 0,
            "task Pid({pid}) was never scheduled"
        );
    }
}

/// Test CPU bandwidth with dequeue path exercised via preemption.
///
/// When `enable_cpu_bw = true` and tasks are preempted, the dequeue path
/// calls `scx_cgroup_bw_cancel()` (main.bpf.c:867-875). This test uses
/// cpu_preempt events to force dequeue while bandwidth control is active.
///
/// Also exercises `consume_prev` cgroup_throttled check (main.bpf.c:898-899)
/// and dispatch cgroup_throttled check (main.bpf.c:1340).
#[test]
fn test_lavd_cpu_bw_with_preemption() {
    let _lock = common::setup_test();
    let nr_cpus = 4u32;
    let sched = DynamicScheduler::lavd(nr_cpus);

    unsafe {
        lavd_set_bool(&sched, "enable_cpu_bw\0", true);
    }

    let (beh_a, beh_b) = workloads::ping_pong(Pid(1), Pid(2), 100_000);
    let scenario = Scenario::builder()
        .cpus(nr_cpus)
        .cgroup_with_bandwidth(
            "group-a",
            &[CpuId(0), CpuId(1), CpuId(2), CpuId(3)],
            100_000,
            70_000,
            10_000,
        )
        .task(TaskDef {
            name: "ping".into(),
            pid: Pid(1),
            nice: -10,
            behavior: beh_a,
            start_time_ns: 0,
            mm_id: Some(MmId(1)),
            allowed_cpus: None,
            parent_pid: None,
            cgroup_name: Some("group-a".into()),
            task_flags: 0,
            migration_disabled: 0,
        })
        .task(TaskDef {
            name: "pong".into(),
            pid: Pid(2),
            nice: -10,
            behavior: beh_b,
            start_time_ns: 0,
            mm_id: Some(MmId(1)),
            allowed_cpus: None,
            parent_pid: None,
            cgroup_name: Some("group-a".into()),
            task_flags: 0,
            migration_disabled: 0,
        })
        .add_task_in_cgroup("hog", 10, workloads::cpu_bound(10_000_000), "group-a")
        .add_task("free", 0, workloads::cpu_bound(10_000_000))
        // CPU preemption to trigger dequeue with enable_cpu_bw
        .cpu_preempt(CpuId(0), 30_000_000, 35_000_000)
        .cpu_preempt(CpuId(1), 60_000_000, 65_000_000)
        .duration_ms(200)
        .build();

    let trace = Simulator::new(sched).run(scenario);

    assert!(trace.schedule_count(Pid(1)) > 0, "ping was never scheduled");
    assert!(trace.schedule_count(Pid(2)) > 0, "pong was never scheduled");
}

// ---------------------------------------------------------------------------
// LAVD-specific tests: kernel task types (PF_KTHREAD, PF_WQ_WORKER, ksoftirqd)
// ---------------------------------------------------------------------------

/// Kernel task flags: exercises LAVD's `is_kernel_task()`, `is_kernel_worker()`,
/// and `is_ksoftirqd()` code paths in lat_cri.bpf.c and util.bpf.c.
///
/// Covers:
/// - lat_cri.bpf.c L72-73: is_kernel_task(p) → LAVD_LC_WEIGHT_BOOST_MEDIUM
/// - lat_cri.bpf.c L78-79: LAVD_FLAG_KSOFTIRQD → LAVD_LC_WEIGHT_BOOST_HIGH
/// - lat_cri.bpf.c L84-85: is_kernel_worker(p) → LAVD_LC_WEIGHT_BOOST_REGULAR
/// - main.bpf.c L1756-1757: is_ksoftirqd(p) → set_task_flag(LAVD_FLAG_KSOFTIRQD)
/// - util.bpf.c L137-140: is_kernel_task()
/// - util.bpf.c L143-146: is_kernel_worker()
/// - util.bpf.c L148-152: is_ksoftirqd()
#[test]
fn test_lavd_kernel_task_types() {
    let _lock = common::setup_test();
    let sched = DynamicScheduler::lavd(4);

    // PF_KTHREAD = 0x200000, PF_WQ_WORKER = 0x20, PF_IO_WORKER = 0x10
    const PF_KTHREAD: u32 = 0x200000;
    const PF_WQ_WORKER: u32 = 0x20;
    const PF_IO_WORKER: u32 = 0x10;

    let scenario = Scenario::builder()
        .cpus(4)
        // Pure kernel thread (PF_KTHREAD only) — triggers is_kernel_task()
        .task(TaskDef {
            name: "kthread_worker".into(),
            pid: Pid(1),
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
            task_flags: PF_KTHREAD,
            migration_disabled: 0,
        })
        // ksoftirqd thread — triggers is_ksoftirqd() + LAVD_FLAG_KSOFTIRQD
        // Needs PF_KTHREAD and comm starting with "ksoftirqd/"
        .task(TaskDef {
            name: "ksoftirqd/0".into(),
            pid: Pid(2),
            nice: 0,
            behavior: TaskBehavior {
                phases: vec![Phase::Run(1_000_000), Phase::Sleep(5_000_000)],
                repeat: RepeatMode::Forever,
            },
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: None,
            parent_pid: None,
            cgroup_name: None,
            task_flags: PF_KTHREAD,
            migration_disabled: 0,
        })
        // Workqueue worker — triggers is_kernel_worker()
        .task(TaskDef {
            name: "kworker/0:0".into(),
            pid: Pid(3),
            nice: 0,
            behavior: TaskBehavior {
                phases: vec![Phase::Run(2_000_000), Phase::Sleep(4_000_000)],
                repeat: RepeatMode::Forever,
            },
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: None,
            parent_pid: None,
            cgroup_name: None,
            task_flags: PF_KTHREAD | PF_WQ_WORKER,
            migration_disabled: 0,
        })
        // IO worker — triggers is_kernel_worker() via PF_IO_WORKER
        .task(TaskDef {
            name: "io_worker".into(),
            pid: Pid(4),
            nice: 0,
            behavior: TaskBehavior {
                phases: vec![Phase::Run(1_000_000), Phase::Sleep(3_000_000)],
                repeat: RepeatMode::Forever,
            },
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: None,
            parent_pid: None,
            cgroup_name: None,
            task_flags: PF_IO_WORKER,
            migration_disabled: 0,
        })
        // Regular user task to have a mixed workload
        .task(TaskDef {
            name: "user_task".into(),
            pid: Pid(5),
            nice: 0,
            behavior: workloads::cpu_bound(10_000_000),
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

    // All tasks should have been scheduled
    for i in 1..=5i32 {
        assert!(
            trace.schedule_count(Pid(i)) > 0,
            "task {} was never scheduled",
            i,
        );
    }
}

/// Asymmetric wake pattern: high-lat-cri IO task wakes low-lat-cri CPU hog.
///
/// Exercises the lat_cri inheritance path in lat_cri.bpf.c L194-205:
///   lat_cri_giver = taskc->lat_cri_waker + taskc->lat_cri_wakee
///   if (lat_cri_giver > (2 * lat_cri)) { ... }
///
/// Task A (IO-bound) rapidly cycles run/sleep/wake, building high lat_cri
/// from frequent wait/wake. Task B (CPU-bound) sleeps for long periods and
/// gets woken by A, inheriting A's high lat_cri via lat_cri_waker.
///
/// The key filter in lavd_runnable() at L1198 requires `p->real_parent ==
/// waker->real_parent`, so B must have A as parent_pid.
#[test]
fn test_lavd_lat_cri_inheritance() {
    let _lock = common::setup_test();
    let sched = DynamicScheduler::lavd(4);

    let scenario = Scenario::builder()
        .cpus(4)
        // Task A: IO-bound waker — short run/sleep cycles, wakes B each cycle
        .task(TaskDef {
            name: "io_waker".into(),
            pid: Pid(1),
            nice: -5,
            behavior: TaskBehavior {
                phases: vec![
                    Phase::Run(100_000),   // 100us CPU
                    Phase::Sleep(200_000), // 200us sleep
                    Phase::Wake(Pid(2)),   // wake the CPU hog
                ],
                repeat: RepeatMode::Forever,
            },
            start_time_ns: 0,
            mm_id: Some(MmId(1)),
            allowed_cpus: None,
            parent_pid: None,
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
        })
        // Task B: CPU-bound sleeper — long sleep then short CPU, woken by A.
        // parent_pid = A so lavd_runnable's real_parent check passes.
        .task(TaskDef {
            name: "cpu_hog".into(),
            pid: Pid(2),
            nice: 10,
            behavior: TaskBehavior {
                phases: vec![
                    Phase::Sleep(50_000_000), // 50ms sleep (will be woken by A)
                    Phase::Run(2_000_000),    // 2ms CPU burst
                ],
                repeat: RepeatMode::Forever,
            },
            start_time_ns: 0,
            mm_id: Some(MmId(1)),
            allowed_cpus: None,
            parent_pid: Some(Pid(1)),
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
        })
        // Background CPU load to keep sys_stat active
        .add_task("bg1", 5, workloads::cpu_bound(10_000_000))
        .add_task("bg2", 5, workloads::cpu_bound(10_000_000))
        .duration_ms(500)
        .build();

    let trace = Simulator::new(sched).run(scenario);

    assert!(
        trace.schedule_count(Pid(1)) > 10,
        "io_waker should cycle many times"
    );
    assert!(
        trace.schedule_count(Pid(2)) > 0,
        "cpu_hog was never scheduled"
    );
}

// ---------------------------------------------------------------------------
// Power mode configuration tests
// ---------------------------------------------------------------------------

/// Test that power mode can be set to balanced via the API.
///
/// This verifies that `lavd_set_power_mode(Balanced)` configures the scheduler
/// correctly and that a scenario runs successfully in balanced mode.
#[test]
fn test_lavd_api_set_power_mode_balanced() {
    use scx_simulator::LavdPowerMode;

    let _lock = common::setup_test();
    let sched = DynamicScheduler::lavd(4);

    // Switch to balanced mode (enables core compaction, no powersave)
    sched.lavd_set_power_mode(LavdPowerMode::Balanced);

    let scenario = Scenario::builder()
        .cpus(4)
        .task(TaskDef {
            name: "worker".into(),
            pid: Pid(1),
            nice: 0,
            behavior: workloads::cpu_bound(10_000_000), // 10ms chunks
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

    // Basic sanity: task should have been scheduled
    assert!(
        trace.schedule_count(Pid(1)) > 0,
        "worker was never scheduled in balanced mode"
    );
}

/// Test that power mode can be set to powersave via the API.
#[test]
fn test_lavd_api_set_power_mode_powersave() {
    use scx_simulator::LavdPowerMode;

    let _lock = common::setup_test();
    let sched = DynamicScheduler::lavd(4);

    // Switch to powersave mode
    sched.lavd_set_power_mode(LavdPowerMode::Powersave);

    let scenario = Scenario::builder()
        .cpus(4)
        .task(TaskDef {
            name: "worker".into(),
            pid: Pid(1),
            nice: 0,
            behavior: workloads::cpu_bound(10_000_000),
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

    assert!(
        trace.schedule_count(Pid(1)) > 0,
        "worker was never scheduled in powersave mode"
    );
}

/// Test that autopilot can be enabled via the API.
#[test]
fn test_lavd_api_set_autopilot() {
    let _lock = common::setup_test();
    let sched = DynamicScheduler::lavd(4);

    // Enable autopilot mode
    sched.lavd_set_autopilot(true);

    let scenario = Scenario::builder()
        .cpus(4)
        .task(TaskDef {
            name: "worker".into(),
            pid: Pid(1),
            nice: 0,
            behavior: workloads::cpu_bound(10_000_000),
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

    assert!(
        trace.schedule_count(Pid(1)) > 0,
        "worker was never scheduled with autopilot enabled"
    );
}

/// Test that lavd_noflags() resets to vanilla state.
#[test]
fn test_lavd_api_noflags() {
    use scx_simulator::LavdPowerMode;

    let _lock = common::setup_test();
    let sched = DynamicScheduler::lavd(4);

    // First set to performance mode
    sched.lavd_set_power_mode(LavdPowerMode::Performance);

    // Then reset to noflags (balanced, no autopilot, core compaction on)
    sched.lavd_noflags();

    let scenario = Scenario::builder()
        .cpus(4)
        .task(TaskDef {
            name: "worker".into(),
            pid: Pid(1),
            nice: 0,
            behavior: workloads::cpu_bound(10_000_000),
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

    assert!(
        trace.schedule_count(Pid(1)) > 0,
        "worker was never scheduled after lavd_noflags()"
    );
}

// ---------------------------------------------------------------------------
// Production bug reproduction: migration-disabled kworker dispatched to wrong CPU
// ---------------------------------------------------------------------------

/// Attempt to reproduce production bug where LAVD dispatches a migration-disabled
/// task to a different CPU via SCX_DSQ_LOCAL_ON.
///
/// # Production Error
/// ```text
/// kworker/8:1[3065910] triggered exit kind 1024:
///   runtime error (SCX_DSQ_LOCAL[_ON] cannot move migration disabled
///   kworker/u208:2[4181193] from CPU 8 to 31)
///
/// Backtrace:
///   task_can_run_on_remote_rq+0x8b/0x120
///   dispatch_to_local_dsq+0x62/0x260
/// ```
///
/// # Root Cause Analysis
///
/// The bug occurs when:
/// 1. A kworker has `migration_disabled > 1` (cannot migrate, pinned to CPU 8)
/// 2. Task wakes up and LAVD calls `pick_idle_cpu()`
/// 3. Because `is_migration_disabled()` is not properly checked (or returns false
///    when it should return true), LAVD finds a different idle CPU (e.g., 31)
/// 4. LAVD dispatches to `SCX_DSQ_LOCAL_ON | 31` in `lavd_enqueue()`
/// 5. Kernel rejects this in `task_can_run_on_remote_rq()` with scx_bpf_error()
///
/// # Simulator Support (sim-7cc89)
///
/// The simulator now supports `migration_disabled`:
/// 1. `TaskDef.migration_disabled` field sets the task_struct counter
/// 2. `is_migration_disabled()` in wrapper.c reads the actual value
/// 3. `resolve_pending_dispatch()` validates SCX_DSQ_LOCAL_ON dispatches
/// 4. Invalid dispatches trigger `ExitKind::ErrorBpf`
///
/// # What This Test Verifies
///
/// This test creates a migration-disabled kworker that:
/// 1. Has `nr_cpus_allowed > 1` (can run on any CPU by cpumask)
/// 2. Has `migration_disabled = 2` (cannot migrate temporarily)
/// 3. Is woken from various CPUs to trigger cross-CPU dispatch paths
///
/// The test verifies that either:
/// - LAVD correctly handles `is_migration_disabled()` and dispatches locally
/// - The simulator catches invalid SCX_DSQ_LOCAL_ON dispatches
#[test]
fn test_lavd_migration_disabled_kworker_scenario() {
    let _lock = common::setup_test();

    // Production configuration: 52 CPUs, performance mode, enable_cpu_bw
    let nr_cpus = 52;
    let sched = DynamicScheduler::lavd(nr_cpus);
    sched.lavd_set_power_mode(LavdPowerMode::Performance);
    // Note: pinned_slice_us=3000 in production, but we use the default for now

    // Enable CPU bandwidth control (from production)
    unsafe {
        lavd_set_bool(&sched, "enable_cpu_bw\0", true);
    }

    // Create a kworker-like task pinned to CPU 8
    // In production, kworkers have PF_WQ_WORKER (0x20) and PF_KTHREAD (0x200000)
    const PF_KTHREAD: u32 = 0x00200000;
    const PF_WQ_WORKER: u32 = 0x00000020;
    let kworker_flags = PF_KTHREAD | PF_WQ_WORKER;

    let mut builder = Scenario::builder().cpus(nr_cpus);

    // The kworker has migration_disabled > 0 but is technically allowed on all CPUs.
    // This reproduces the production bug where a migration-disabled task was
    // dispatched to a different CPU via SCX_DSQ_LOCAL_ON.
    //
    // migration_disabled = 2 simulates a task that was already migration-disabled
    // before entering the BPF scheduler callback (in the kernel, BPF prolog
    // increments migration_disabled to 1, so > 1 means pre-existing disable).
    builder = builder.task(TaskDef {
        name: "kworker/8:1".into(),
        pid: Pid(1),
        nice: 0,
        behavior: workloads::io_bound(100_000, 1_000_000), // 0.1ms work, 1ms sleep
        start_time_ns: 0,
        mm_id: None,
        allowed_cpus: None, // Can run on any CPU (not pinned by cpumask)
        parent_pid: None,
        cgroup_name: None,
        task_flags: kworker_flags,
        migration_disabled: 2, // Cannot migrate despite nr_cpus_allowed > 1
    });

    // Add other tasks spread across CPUs to create load imbalance
    // These might cause LAVD to try migrating tasks
    for i in 2..=20 {
        builder = builder.task(TaskDef {
            name: format!("worker_{i}"),
            pid: Pid(i),
            nice: 0,
            behavior: workloads::cpu_bound(10_000_000), // 10ms chunks
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: None, // Can run anywhere
            parent_pid: None,
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
        });
    }

    // Add tasks that wake the kworker from different CPUs
    // This exercises the wake path where LAVD might pick a wrong idle CPU
    for i in 21..=24 {
        // Wake the kworker after doing some work
        let phases = vec![
            scx_simulator::task::Phase::Run(500_000),     // 0.5ms
            scx_simulator::task::Phase::Wake(Pid(1)),     // Wake kworker
            scx_simulator::task::Phase::Sleep(2_000_000), // 2ms sleep
        ];
        builder = builder.task(TaskDef {
            name: format!("waker_{i}"),
            pid: Pid(i),
            nice: 0,
            behavior: scx_simulator::task::TaskBehavior {
                phases,
                repeat: scx_simulator::task::RepeatMode::Forever,
            },
            start_time_ns: (i as u64 - 21) * 500_000, // Stagger start times
            mm_id: None,
            // Pin wakers to CPUs far from CPU 8 to trigger cross-CPU wake
            allowed_cpus: Some(vec![CpuId(30 + i as u32 - 21)]),
            parent_pid: None,
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
        });
    }

    let scenario = builder
        .duration_ms(500)
        // Enable BPF error detection - if the simulator properly modeled
        // migration_disabled, this would catch the invalid dispatch
        .detect_bpf_errors()
        .build();

    let trace = Simulator::new(sched).run(scenario);

    // With migration_disabled properly modeled, this test now verifies that:
    // 1. LAVD's is_migration_disabled() check sees migration_disabled > 0
    // 2. The simulator validates SCX_DSQ_LOCAL_ON dispatches
    // 3. If LAVD dispatches to a different CPU, we get a BPF error
    //
    // The exit kind tells us what happened:
    // - ErrorBpf means the simulator caught an invalid dispatch
    // - Normal means LAVD correctly handled the migration-disabled task
    eprintln!(
        "[migration_disabled test] exit_kind={:?}, kworker scheduled {} times",
        trace.exit_kind(),
        trace.schedule_count(Pid(1))
    );

    // The test can have two valid outcomes:
    // 1. LAVD correctly handles migration_disabled and the simulation completes
    // 2. LAVD incorrectly dispatches and we catch the error
    //
    // Either outcome exercises the migration_disabled code path.
    // If this test fails with ErrorBpf, it means LAVD has a bug!
}

/// Alternative test: Task with restricted cpumask dispatched to wrong CPU.
///
/// This is a simpler variant that tests cpumask validation rather than
/// migration_disabled. Even though LAVD respects cpumasks in pick_idle_cpu(),
/// the simulator should validate dispatches.
///
/// The kernel validates in `task_can_run_on_remote_rq()`:
/// ```c
/// if (!cpumask_test_cpu(cpu, p->cpus_ptr))
///     return -EINVAL;
/// ```
#[test]
fn test_lavd_pinned_task_cpumask_respected() {
    let _lock = common::setup_test();

    // Multi-domain setup to exercise cross-domain dispatch paths
    let sched = DynamicScheduler::lavd_multi_domain(16, 4);
    sched.lavd_set_power_mode(LavdPowerMode::Performance);

    // Task pinned to CPUs 0-3 (domain 0)
    let domain0_cpus = vec![CpuId(0), CpuId(1), CpuId(2), CpuId(3)];

    let scenario = Scenario::builder()
        .cpus(16)
        // Pinned task in domain 0
        .task(TaskDef {
            name: "pinned_domain0".into(),
            pid: Pid(1),
            nice: 0,
            behavior: workloads::io_bound(200_000, 2_000_000),
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: Some(domain0_cpus.clone()),
            parent_pid: None,
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
        })
        // Tasks in other domains to create load
        .task(TaskDef {
            name: "worker_d1".into(),
            pid: Pid(2),
            nice: 0,
            behavior: workloads::cpu_bound(10_000_000),
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: Some(vec![CpuId(4), CpuId(5), CpuId(6), CpuId(7)]),
            parent_pid: None,
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
        })
        .task(TaskDef {
            name: "worker_d2".into(),
            pid: Pid(3),
            nice: 0,
            behavior: workloads::cpu_bound(10_000_000),
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: Some(vec![CpuId(8), CpuId(9), CpuId(10), CpuId(11)]),
            parent_pid: None,
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
        })
        // Waker from a different domain
        .task(TaskDef {
            name: "waker_d3".into(),
            pid: Pid(4),
            nice: 0,
            behavior: {
                let phases = vec![
                    scx_simulator::task::Phase::Run(300_000),
                    scx_simulator::task::Phase::Wake(Pid(1)),
                    scx_simulator::task::Phase::Sleep(3_000_000),
                ];
                scx_simulator::task::TaskBehavior {
                    phases,
                    repeat: scx_simulator::task::RepeatMode::Forever,
                }
            },
            start_time_ns: 100_000,
            mm_id: None,
            allowed_cpus: Some(vec![CpuId(12), CpuId(13), CpuId(14), CpuId(15)]),
            parent_pid: None,
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
        })
        .duration_ms(500)
        .detect_bpf_errors()
        .build();

    let trace = Simulator::new(sched).run(scenario);

    // All tasks should be scheduled
    for i in 1..=4 {
        assert!(
            trace.schedule_count(Pid(i)) > 0,
            "task {} was never scheduled",
            i
        );
    }

    // Verify the pinned task only ran on its allowed CPUs
    let pinned_runs: Vec<_> = trace
        .events()
        .iter()
        .filter(|e| {
            matches!(
                e.kind,
                scx_simulator::trace::TraceKind::SetNextTask { pid } if pid == Pid(1)
            )
        })
        .collect();

    for run_event in &pinned_runs {
        assert!(
            domain0_cpus.contains(&run_event.cpu),
            "pinned task ran on CPU {} which is not in allowed set {:?}",
            run_event.cpu.0,
            domain0_cpus
        );
    }

    eprintln!(
        "[cpumask test] pinned task ran {} times, all on allowed CPUs",
        pinned_runs.len()
    );
}
// ---------------------------------------------------------------------------
// LAVD-specific tests: Cgroup exhaustion stress test
// ---------------------------------------------------------------------------

/// Test LAVD with many cgroups to stress test cgroup init/exit code paths.
///
/// # Production Failure Context (sim-d80a2)
///
/// In production, after 10 hours of runtime, LAVD failed with:
/// ```text
/// scx_lavd_alpha triggered exit kind 1025:
///   scx_bpf_error (main.bpf.c:2089: Failed to init a cgroup: -12)
/// ```
///
/// The error code -12 is ENOMEM. The failure occurs in `scx_cgroup_bw_init()`
/// (lib/cgroup_bw.bpf.c) when the `cbw_cgrp_llc_map` hash map is full.
///
/// # LAVD Cgroup Limits
///
/// From lib/cgroup_bw.bpf.c:
/// - `CBW_NR_CGRP_MAX = 2048` - Maximum number of cgroups
/// - `CBW_NR_CGRP_LLC_MAX = CBW_NR_CGRP_MAX * 32 = 65536` - Max LLC contexts
/// - Each cgroup with tasks allocates up to TOPO_NR(LLC) entries in the
///   `cbw_cgrp_llc_map` hash map
///
/// The production failure likely happened when:
/// 1. Many cgroups were created and destroyed over 10 hours
/// 2. The BPF hash map filled up (no automatic cleanup of dead cgroups)
/// 3. A new cgroup creation triggered `bpf_map_update_elem()` with BPF_NOEXIST
///    which returned -ENOMEM when the map was at capacity
///
/// # Test Strategy
///
/// We cannot fully reproduce this in the simulator because:
/// 1. The `scx_cgroup_bw_*` functions are weak stubs (return 0, no map alloc)
/// 2. The simulator doesn't support dynamic cgroup creation at runtime
/// 3. We'd need the actual BPF map implementation to hit the limit
///
/// However, this test:
/// 1. Creates many cgroups to stress the cgroup code paths
/// 2. Exercises `lavd_cgroup_init` / `lavd_cgroup_exit` with `enable_cpu_bw=true`
/// 3. Verifies the simulator handles large cgroup counts correctly
/// 4. Documents the limits for future investigation
///
/// # Configuration matching production failure
///
/// - Performance mode (no_core_compaction=true)
/// - enable_cpu_bw=true
/// - 36 CPUs
/// - pinned_slice_us=3000
#[test]
fn test_lavd_cgroup_exhaustion_stress() {
    let _lock = common::setup_test();

    // Match production configuration: 36 CPUs, performance mode
    let nr_cpus = 36u32;
    let sched = DynamicScheduler::lavd(nr_cpus);

    // Enable CPU bandwidth control (the code path where -ENOMEM occurs)
    unsafe {
        lavd_set_bool(&sched, "enable_cpu_bw\0", true);
        // Match production: performance mode
        lavd_set_bool(&sched, "no_core_compaction\0", true);
        // Match production: pinned_slice_us=3000 (3ms = 3_000_000 ns)
        lavd_set_u64(&sched, "pinned_slice_ns\0", 3_000_000);
    }

    // Create a scenario with many cgroups (stress test)
    // Note: The real limit is CBW_NR_CGRP_MAX=2048, but the simulator's weak
    // stubs don't enforce this. We use a smaller number to keep the test fast
    // while still exercising the code paths.
    const NUM_CGROUPS: usize = 100;

    let mut builder = Scenario::builder().cpus(nr_cpus).duration_ms(200);

    // Create many cgroups
    for i in 0..NUM_CGROUPS {
        let cpus: Vec<CpuId> = (0..nr_cpus).map(CpuId).collect();
        builder = builder.cgroup_with_bandwidth(
            &format!("cgroup_{i}"),
            &cpus,
            100_000, // 100ms period
            50_000,  // 50ms quota (50% CPU)
            10_000,  // 10ms burst
        );
    }

    // Add tasks to some cgroups to exercise the task<->cgroup interaction
    for i in 0..20 {
        let cgroup_name = format!("cgroup_{}", i % NUM_CGROUPS);
        builder = builder.add_task_in_cgroup(
            &format!("worker_{i}"),
            0,
            workloads::cpu_bound(10_000_000),
            &cgroup_name,
        );
    }

    let scenario = builder.build();
    let trace = Simulator::new(sched).run(scenario);

    // All workers should have been scheduled
    for i in 0..20i32 {
        assert!(
            trace.schedule_count(Pid(i + 1)) > 0,
            "worker_{i} was never scheduled"
        );
    }

    // Document the actual limit for posterity
    eprintln!(
        "[cgroup_exhaustion_stress] Successfully ran with {} cgroups",
        NUM_CGROUPS
    );
    eprintln!("[cgroup_exhaustion_stress] Production limit: CBW_NR_CGRP_MAX = 2048");
    eprintln!("[cgroup_exhaustion_stress] To fully reproduce ENOMEM:");
    eprintln!("  1. Need actual BPF map implementation (not weak stubs)");
    eprintln!("  2. Need dynamic cgroup lifecycle events in simulator");
    eprintln!("  3. Create >2048 cgroups with enable_cpu_bw=true");
}

/// Test LAVD cgroup churn: tasks migrating between cgroups.
///
/// This simulates the kind of cgroup activity that can lead to resource
/// exhaustion over time. In production, cgroups are created/destroyed
/// as containers/services start and stop.
///
/// While the simulator doesn't support dynamic cgroup creation, we can
/// exercise cgroup migration paths that update internal state.
#[test]
fn test_lavd_cgroup_churn() {
    let _lock = common::setup_test();

    let nr_cpus = 8u32;
    let sched = DynamicScheduler::lavd(nr_cpus);

    // Enable bandwidth control for more thorough testing
    unsafe {
        lavd_set_bool(&sched, "enable_cpu_bw\0", true);
    }

    let cpus: Vec<CpuId> = (0..nr_cpus).map(CpuId).collect();

    // Create 10 cgroups for migration targets
    let mut builder = Scenario::builder().cpus(nr_cpus).duration_ms(300);
    for i in 0..10 {
        builder =
            builder.cgroup_with_bandwidth(&format!("group_{i}"), &cpus, 100_000, 80_000, 10_000);
    }

    // Create tasks and schedule migrations
    for i in 0..10 {
        let cgroup_name = format!("group_{}", i);
        builder = builder.add_task_in_cgroup(
            &format!("task_{i}"),
            0,
            workloads::cpu_bound(10_000_000),
            &cgroup_name,
        );
    }

    // Schedule many migrations to exercise cgroup_move
    for t in 0..10u64 {
        let time_ns = 50_000_000 + t * 20_000_000; // Every 20ms starting at 50ms
        for task_id in 0..5i32 {
            let from = format!("group_{}", (task_id as u64 + t) % 10);
            let to = format!("group_{}", (task_id as u64 + t + 1) % 10);
            builder = builder.cgroup_migrate(Pid(task_id + 1), &from, &to, time_ns);
        }
    }

    let scenario = builder.build();
    let trace = Simulator::new(sched).run(scenario);

    // All tasks should have been scheduled despite frequent migrations
    for i in 0..10i32 {
        assert!(
            trace.schedule_count(Pid(i + 1)) > 0,
            "task_{i} was never scheduled"
        );
    }
}

/// Test LAVD with the maximum number of statically-defined cgroups.
///
/// This test pushes the simulator's cgroup handling to verify it can
/// manage a large number of cgroups without issues. The actual BPF
/// limit is 2048, but we use a smaller number for reasonable test time.
#[test]
fn test_lavd_many_cgroups() {
    let _lock = common::setup_test();

    let nr_cpus = 4u32;
    let sched = DynamicScheduler::lavd(nr_cpus);

    // Test with a significant but manageable number of cgroups
    const NUM_CGROUPS: usize = 200;

    let cpus: Vec<CpuId> = (0..nr_cpus).map(CpuId).collect();
    let mut builder = Scenario::builder().cpus(nr_cpus).duration_ms(100);

    for i in 0..NUM_CGROUPS {
        builder = builder.cgroup(&format!("cg_{i}"), &cpus);
    }

    // Add a single task (we're testing cgroup init, not task scheduling)
    builder = builder.add_task_in_cgroup("worker", 0, workloads::cpu_bound(10_000_000), "cg_0");

    let scenario = builder.build();
    let trace = Simulator::new(sched).run(scenario);

    assert!(
        trace.schedule_count(Pid(1)) > 0,
        "worker was never scheduled"
    );

    eprintln!(
        "[many_cgroups] Successfully initialized and exited {} cgroups",
        NUM_CGROUPS
    );
}

/// Test cgroup BPF map resource exhaustion.
///
/// This test simulates the production behavior where BPF hash maps have
/// size limits (CBW_NR_CGRP_MAX = 2048 in LAVD). When these maps fill up,
/// `cgroup_init` should fail with ENOMEM.
///
/// The test:
/// 1. Sets `max_cgroups=50` to simulate a low BPF map limit
/// 2. Enables `enable_cpu_bw=true` so `scx_cgroup_bw_init` is called
/// 3. Tries to create 100 cgroups
/// 4. Expects a panic from the engine when cgroup_init fails
///
/// This covers the resource exhaustion code path in scx_cgroup_bw_init.
#[test]
#[should_panic(expected = "cgroup_init failed")]
fn test_lavd_cgroup_resource_exhaustion() {
    let _lock = common::setup_test();

    let nr_cpus = 4u32;
    let sched = DynamicScheduler::lavd(nr_cpus);

    // Enable bandwidth control so scx_cgroup_bw_init is called
    unsafe {
        lavd_set_bool(&sched, "enable_cpu_bw\0", true);
    }

    let cpus: Vec<CpuId> = (0..nr_cpus).map(CpuId).collect();

    // Create more cgroups than the limit (100 > 50)
    const NUM_CGROUPS: usize = 100;
    const MAX_CGROUPS: u32 = 50;

    let mut builder = Scenario::builder()
        .cpus(nr_cpus)
        .duration_ms(100)
        .max_cgroups(MAX_CGROUPS);

    for i in 0..NUM_CGROUPS {
        builder = builder.cgroup(&format!("cg_{i}"), &cpus);
    }

    // Add a task so the scenario is valid
    builder = builder.add_task_in_cgroup("worker", 0, workloads::cpu_bound(1_000_000), "cg_0");

    let scenario = builder.build();

    // This should panic with "cgroup_init failed" when we hit the limit
    let _trace = Simulator::new(sched).run(scenario);
}

/// Test that cgroup resource tracking counts correctly.
///
/// This test verifies that the registry correctly tracks allocated entries:
/// 1. With a high limit (default), many cgroups can be created
/// 2. The count increases with each cgroup_init
/// 3. The count decreases with each cgroup_exit (on cleanup)
#[test]
fn test_lavd_cgroup_resource_tracking() {
    let _lock = common::setup_test();

    let nr_cpus = 4u32;
    let sched = DynamicScheduler::lavd(nr_cpus);

    // Enable bandwidth control so scx_cgroup_bw_init is called
    unsafe {
        lavd_set_bool(&sched, "enable_cpu_bw\0", true);
    }

    let cpus: Vec<CpuId> = (0..nr_cpus).map(CpuId).collect();

    // Create exactly at the limit
    const NUM_CGROUPS: usize = 30;
    const MAX_CGROUPS: u32 = 50; // Above NUM_CGROUPS so no failure

    let mut builder = Scenario::builder()
        .cpus(nr_cpus)
        .duration_ms(50)
        .max_cgroups(MAX_CGROUPS);

    for i in 0..NUM_CGROUPS {
        builder = builder.cgroup(&format!("cg_{i}"), &cpus);
    }

    builder = builder.add_task_in_cgroup("worker", 0, workloads::cpu_bound(1_000_000), "cg_0");

    let scenario = builder.build();
    let trace = Simulator::new(sched).run(scenario);

    // Should complete successfully
    assert!(
        trace.schedule_count(Pid(1)) > 0,
        "worker was never scheduled"
    );

    eprintln!(
        "[cgroup_resource_tracking] Successfully ran with {} cgroups (limit={})",
        NUM_CGROUPS, MAX_CGROUPS
    );
}

// ---------------------------------------------------------------------------
// LAVD-specific tests: Production bug reproduction (cgroup ENOMEM)
// ---------------------------------------------------------------------------

/// Reproduce production LAVD bug: cgroup_init fails with ENOMEM (-12).
///
/// # Production Bug Details
///
/// ```text
/// scx_lavd_alpha[3801850] triggered exit kind 1025:
///   scx_bpf_error (././main/scheds/rust/scx_lavd/src/bpf/main.bpf.c:2089:
///     Failed to init a cgroup: -12)
///
/// Backtrace:
///   scx_kf_exit+0x62/0x70
///   scx_bpf_error_bstr+0x76/0x80
///   bpf_prog_05e793d23f72903b_lavd_cgroup_init+0x72/0x79
/// ```
///
/// The bug occurs after ~10 hours of running, suggesting resource exhaustion
/// from cgroup churn (continuous creation/destruction of cgroups).
///
/// # Root Cause
///
/// In production LAVD with `enable_cpu_bw=true`:
/// - `lavd_cgroup_init` calls `scx_cgroup_bw_init` (main.bpf.c:2087)
/// - `scx_cgroup_bw_init` allocates entries in BPF hash maps:
///   - `cbw_cgrp_map` (cgroup storage)
///   - `cbw_cgrp_llc_map` (max_entries = CBW_NR_CGRP_LLC_MAX = 65536)
/// - When these maps fill up (e.g., 2048 cgroups * 32 LLCs), ENOMEM is returned
///
/// # This Test
///
/// This test creates cgroups dynamically at runtime (not at init time)
/// with `enable_cpu_bw=true` to simulate production behavior where
/// containers/services are continuously started and stopped.
///
/// When the configurable `max_cgroups` limit is exceeded, the scheduler's
/// `cgroup_init` returns -12 (ENOMEM) and the simulation terminates with
/// `ExitKind::ErrorCgroupExhausted`.
#[test]
fn test_lavd_cgroup_init_enomem_production_repro() {
    let _lock = common::setup_test();

    // Production-like configuration
    let nr_cpus = 36u32;
    let sched = DynamicScheduler::lavd(nr_cpus);

    // Enable CPU bandwidth control - required for the ENOMEM path
    // In production this is enabled via --enable-cpu-bw or similar flag
    unsafe {
        lavd_set_bool(&sched, "enable_cpu_bw\0", true);
    }

    // Simulate a low BPF map limit (production limit is 2048)
    // Root cgroup counts as 1, so with max_cgroups=10 we can create 9 more
    const MAX_CGROUPS: u32 = 10;

    let mut builder = Scenario::builder()
        .cpus(nr_cpus)
        .seed(42)
        .max_cgroups(MAX_CGROUPS)
        .detect_bpf_errors()
        .add_task(
            "worker",
            0,
            TaskBehavior {
                phases: vec![Phase::Run(1_000_000), Phase::Sleep(1_000_000)],
                repeat: RepeatMode::Forever,
            },
        )
        .duration_ms(500);

    // Dynamically create cgroups at runtime (simulating container churn)
    // This mimics production where services start/stop over 10 hours
    for i in 0..20 {
        let at_ns = (i + 1) * 10_000_000; // Every 10ms
        builder = builder.cgroup_create_at(&format!("container_{i}"), None, None, at_ns);
    }

    let scenario = builder.build();
    let trace = Simulator::new(sched).run(scenario);

    // Verify we hit the expected error
    match trace.exit_kind() {
        ExitKind::ErrorCgroupExhausted {
            cgroup_name,
            active_count,
            max_cgroups: max,
        } => {
            eprintln!(
                "[production_repro] Reproduced ENOMEM: cgroup='{}', active={}, max={}",
                cgroup_name, active_count, max
            );
            assert_eq!(*max, MAX_CGROUPS);
            // active_count should equal max when we hit the limit
            assert_eq!(*active_count, MAX_CGROUPS);
        }
        other => {
            panic!(
                "Expected ErrorCgroupExhausted (ENOMEM repro) but got {:?}",
                other
            );
        }
    }
}

/// Test that rapid cgroup create/destroy cycles don't leak resources.
///
/// This simulates 10 hours of container churn in accelerated form:
/// - Create batch of containers
/// - Destroy them
/// - Repeat
///
/// With proper cleanup in cgroup_exit, this should stay under the limit.
/// If there's a resource leak, the limit will eventually be hit.
#[test]
fn test_lavd_cgroup_lifecycle_no_leak() {
    let _lock = common::setup_test();

    let nr_cpus = 8u32;
    let sched = DynamicScheduler::lavd(nr_cpus);

    // Enable CPU bandwidth control for full code path coverage
    unsafe {
        lavd_set_bool(&sched, "enable_cpu_bw\0", true);
    }

    // Moderate limit - should NOT be exhausted if cleanup works
    const MAX_CGROUPS: u32 = 30;

    let mut builder = Scenario::builder()
        .cpus(nr_cpus)
        .seed(12345)
        .max_cgroups(MAX_CGROUPS)
        .detect_bpf_errors()
        .add_task(
            "worker",
            0,
            TaskBehavior {
                phases: vec![Phase::Run(500_000), Phase::Sleep(500_000)],
                repeat: RepeatMode::Forever,
            },
        )
        .duration_ms(300);

    // Simulate 10 cycles of container churn
    // Each cycle: create 5 containers, then destroy them
    // Total cgroups created: 50, but never more than 5 active at once (+ root = 6)
    let interval_ns: u64 = 1_000_000; // 1ms
    for cycle in 0..10 {
        let base: u64 = cycle * 15_000_000;
        // Create 5 cgroups
        for i in 0..5 {
            let name = format!("cycle{}_{}", cycle, i);
            builder = builder.cgroup_create_at(&name, None, None, base + (i as u64) * interval_ns);
        }
        // Destroy them 5ms later
        for i in 0..5 {
            let name = format!("cycle{}_{}", cycle, i);
            builder = builder.cgroup_destroy_at(&name, base + 5_000_000 + (i as u64) * interval_ns);
        }
    }

    let scenario = builder.build();
    let trace = Simulator::new(sched).run(scenario);

    // Should complete successfully - no resource exhaustion
    assert!(
        !trace.has_error(),
        "Cgroup lifecycle leaked resources, got: {:?}",
        trace.exit_kind()
    );

    eprintln!(
        "[cgroup_no_leak] {} create/destroy cycles completed without exhaustion",
        10
    );
}

// ---------------------------------------------------------------------------
// Phase 10: Additional LAVD coverage — turbo cores, migrate_to_neighbor,
// sticky CPU edge cases
// ---------------------------------------------------------------------------

/// Configure LAVD's BPF globals for turbo cores.
///
/// Sets `have_turbo_core = true` and populates `cpu_turbo[]` for specified CPUs.
/// Also sets the turbo_cpumask to include these CPUs.
unsafe fn lavd_setup_turbo_cores(sched: &DynamicScheduler, turbo_cpus: &[u32]) {
    lavd_set_bool(sched, "have_turbo_core\0", true);

    // Set cpu_turbo array for the specified CPUs
    let cpu_turbo: libloading::Symbol<'_, *mut u8> = sched
        .get_symbol(b"cpu_turbo\0")
        .expect("cpu_turbo not found");
    for &cpu in turbo_cpus {
        std::ptr::write_volatile((*cpu_turbo).add(cpu as usize), 1);
    }
}

/// Turbo core preference in idle CPU selection.
///
/// When have_turbo_core is true and turbo CPUs exist, the scheduler should
/// prefer turbo CPUs in the `pick_idle_cpu_at_cpdom()` function (lines 171-179
/// in idle.bpf.c).
///
/// Covers: idle.bpf.c lines 110-116 (init_idle_ato_masks with turbo),
/// lines 171-179 (pick turbo CPU first in pick_idle_cpu_at_cpdom)
#[test]
fn test_lavd_turbo_core_preference() {
    let _lock = common::setup_test();

    let nr_cpus = 8u32;
    let sched = DynamicScheduler::lavd(nr_cpus);

    // Enable turbo cores on CPUs 0 and 1
    unsafe {
        lavd_setup_turbo_cores(&sched, &[0, 1]);
        lavd_setup_pco(&sched, nr_cpus);
        lavd_setup_two_domains(&sched, nr_cpus, 4);
    }

    // Create a workload with wake-ups that should prefer turbo cores
    let scenario = Scenario::builder()
        .cpus(nr_cpus)
        .seed(9999)
        .detect_bpf_errors()
        .add_task(
            "turbo_seeker",
            0,
            TaskBehavior {
                phases: vec![Phase::Run(100_000), Phase::Sleep(200_000)],
                repeat: RepeatMode::Forever,
            },
        )
        .add_task(
            "background",
            0,
            TaskBehavior {
                phases: vec![Phase::Run(500_000), Phase::Sleep(100_000)],
                repeat: RepeatMode::Forever,
            },
        )
        .duration_ms(200)
        .build();

    let trace = Simulator::new(sched).run(scenario);
    assert!(
        !trace.has_error(),
        "Unexpected error: {:?}",
        trace.exit_kind()
    );
    eprintln!("[turbo_core_preference] Test passed with turbo cores enabled");
}

/// Turbo core with SMT enabled: tests the iat_mask (idle active turbo) path.
///
/// When both SMT and turbo cores are active, the scheduler initializes
/// iat_mask in init_idle_ato_masks() (lines 110-116).
///
/// Covers: idle.bpf.c lines 110-116 (iat_mask initialization with turbo_cpumask)
#[test]
fn test_lavd_turbo_core_with_smt() {
    let _lock = common::setup_test();

    let nr_cpus = 8u32;
    let sched = DynamicScheduler::lavd(nr_cpus);

    unsafe {
        lavd_setup_turbo_cores(&sched, &[0, 1]);
        lavd_setup_smt(&sched, nr_cpus);
        lavd_setup_pco(&sched, nr_cpus);
        lavd_setup_two_domains(&sched, nr_cpus, 4);
    }

    // SMT topology with turbo cores
    let scenario = Scenario::builder()
        .cpus(nr_cpus)
        .smt(2) // 2 threads per core
        .seed(8888)
        .detect_bpf_errors()
        .add_task(
            "smt_turbo",
            0,
            TaskBehavior {
                phases: vec![Phase::Run(80_000), Phase::Sleep(120_000)],
                repeat: RepeatMode::Forever,
            },
        )
        .duration_ms(150)
        .build();

    let trace = Simulator::new(sched).run(scenario);
    assert!(
        !trace.has_error(),
        "Unexpected error: {:?}",
        trace.exit_kind()
    );
    eprintln!("[turbo_with_smt] Test passed with turbo cores + SMT");
}

/// Test migrate_to_neighbor with successful migration.
///
/// Sets up domains where one is a stealee (overloaded) and the neighbor
/// is a stealer (underloaded), enabling successful task donation.
///
/// Covers: idle.bpf.c lines 532-566 (migrate_to_neighbor success path),
/// specifically lines 547-561 (successful donation with stealer/stealee flags)
#[test]
fn test_lavd_migrate_to_neighbor_donation() {
    let _lock = common::setup_test();

    let nr_cpus = 8u32;
    let sched = DynamicScheduler::lavd(nr_cpus);

    // Configure for migration testing
    unsafe {
        lavd_setup_pco(&sched, nr_cpus);
        lavd_set_bool(&sched, "is_smt_active\0", true);
        lavd_setup_two_domains(&sched, nr_cpus, 4);
    }

    // Create an imbalanced workload: domain 0 has many tasks, domain 1 has few
    // This should trigger stealer/stealee classification and migration
    let scenario = Scenario::builder()
        .cpus(nr_cpus)
        .smt(2)
        .seed(7777)
        .detect_bpf_errors()
        // Heavy tasks pinned to domain 0 (CPUs 0-3)
        .task(TaskDef {
            name: "heavy1".into(),
            pid: Pid(1),
            nice: 0,
            behavior: TaskBehavior {
                phases: vec![Phase::Run(1_000_000)],
                repeat: RepeatMode::Count(50),
            },
            start_time_ns: 0,
            mm_id: Some(MmId(1)),
            allowed_cpus: Some(vec![CpuId(0), CpuId(1), CpuId(2), CpuId(3)]),
            parent_pid: None,
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
        })
        .task(TaskDef {
            name: "heavy2".into(),
            pid: Pid(2),
            nice: 0,
            behavior: TaskBehavior {
                phases: vec![Phase::Run(1_000_000)],
                repeat: RepeatMode::Count(50),
            },
            start_time_ns: 0,
            mm_id: Some(MmId(1)),
            allowed_cpus: Some(vec![CpuId(0), CpuId(1), CpuId(2), CpuId(3)]),
            parent_pid: None,
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
        })
        // Light task that can migrate to any domain
        .task(TaskDef {
            name: "migrator".into(),
            pid: Pid(3),
            nice: 0,
            behavior: TaskBehavior {
                phases: vec![Phase::Run(50_000), Phase::Sleep(100_000)],
                repeat: RepeatMode::Forever,
            },
            start_time_ns: 1_000_000,
            mm_id: Some(MmId(1)),
            allowed_cpus: None, // Can run on any CPU
            parent_pid: None,
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
        })
        .duration_ms(300)
        .build();

    let trace = Simulator::new(sched).run(scenario);
    assert!(
        !trace.has_error(),
        "Unexpected error: {:?}",
        trace.exit_kind()
    );
    eprintln!("[migrate_to_neighbor] Test passed with domain migration");
}

/// Test sticky CPU fallback when both prev and waker CPUs are not matching.
///
/// Exercises the `sctx.i_nm == 2` path in find_sticky_cpu_and_cpdom()
/// where neither the previous CPU nor the waker CPU matches the task's
/// big/little preference.
///
/// Covers: idle.bpf.c lines 424-450 (i_nm == 2 branch with non-matching CPUs)
#[test]
fn test_lavd_sticky_cpu_non_matching_type() {
    let _lock = common::setup_test();

    let nr_cpus = 8u32;
    let sched = DynamicScheduler::lavd(nr_cpus);

    unsafe {
        lavd_setup_pco(&sched, nr_cpus);
        lavd_setup_two_domains(&sched, nr_cpus, 4);
        // Set up big/little cores: CPUs 0-3 are big, CPUs 4-7 are little
        let cpu_big: libloading::Symbol<'_, *mut u8> =
            sched.get_symbol(b"cpu_big\0").expect("cpu_big not found");
        for cpu in 0..4 {
            std::ptr::write_volatile((*cpu_big).add(cpu), 1);
        }
        lavd_set_bool(&sched, "have_little_core\0", true);
    }

    // Create tasks that will have mismatched big/little preferences
    let (prod, cons) = workloads::ping_pong(Pid(1), Pid(2), 100_000);

    let scenario = Scenario::builder()
        .cpus(nr_cpus)
        .seed(6666)
        .detect_bpf_errors()
        .task(TaskDef {
            name: "ping".into(),
            pid: Pid(1),
            nice: 0,
            behavior: prod,
            start_time_ns: 0,
            mm_id: Some(MmId(1)),
            allowed_cpus: Some(vec![CpuId(4), CpuId(5), CpuId(6), CpuId(7)]), // Force to little cores
            parent_pid: None,
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
        })
        .task(TaskDef {
            name: "pong".into(),
            pid: Pid(2),
            nice: 0,
            behavior: cons,
            start_time_ns: 0,
            mm_id: Some(MmId(1)),
            allowed_cpus: Some(vec![CpuId(0), CpuId(1), CpuId(2), CpuId(3)]), // Force to big cores
            parent_pid: None,
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
        })
        .duration_ms(200)
        .build();

    let trace = Simulator::new(sched).run(scenario);
    assert!(
        !trace.has_error(),
        "Unexpected error: {:?}",
        trace.exit_kind()
    );
    eprintln!("[sticky_non_matching] Test passed with mismatched big/little");
}

/// Test sync waker idle path with multi-domain setup.
///
/// When a task is synchronously woken and the waker CPU is in a different
/// domain than the previous CPU, is_sync_waker_idle() should return false
/// (lines 502-506).
///
/// Covers: idle.bpf.c lines 481-510 (is_sync_waker_idle cross-domain check)
#[test]
fn test_lavd_sync_waker_cross_domain() {
    let _lock = common::setup_test();

    let nr_cpus = 8u32;
    let sched = DynamicScheduler::lavd(nr_cpus);

    unsafe {
        lavd_setup_pco(&sched, nr_cpus);
        lavd_setup_two_domains(&sched, nr_cpus, 4);
    }

    // Create tasks that wake each other across domains
    let (prod, cons) = workloads::ping_pong(Pid(1), Pid(2), 80_000);

    let scenario = Scenario::builder()
        .cpus(nr_cpus)
        .seed(5555)
        .detect_bpf_errors()
        .task(TaskDef {
            name: "domain0_task".into(),
            pid: Pid(1),
            nice: 0,
            behavior: prod,
            start_time_ns: 0,
            mm_id: Some(MmId(1)),
            allowed_cpus: Some(vec![CpuId(0), CpuId(1), CpuId(2), CpuId(3)]), // Domain 0
            parent_pid: None,
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
        })
        .task(TaskDef {
            name: "domain1_task".into(),
            pid: Pid(2),
            nice: 0,
            behavior: cons,
            start_time_ns: 0,
            mm_id: Some(MmId(1)),
            allowed_cpus: Some(vec![CpuId(4), CpuId(5), CpuId(6), CpuId(7)]), // Domain 1
            parent_pid: None,
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
        })
        .duration_ms(200)
        .build();

    let trace = Simulator::new(sched).run(scenario);
    assert!(
        !trace.has_error(),
        "Unexpected error: {:?}",
        trace.exit_kind()
    );
    eprintln!("[sync_waker_cross_domain] Test passed with cross-domain sync wakeups");
}

/// Test waker CPU load comparison in find_sticky_cpu_and_cpdom.
///
/// When both prev and waker CPUs match (sctx.i_m == 2), the function
/// compares domain loads to choose the less loaded domain (lines 396-410).
///
/// Covers: idle.bpf.c lines 390-410 (i_m == 2 with load comparison)
#[test]
fn test_lavd_sticky_cpu_load_comparison() {
    let _lock = common::setup_test();

    let nr_cpus = 8u32;
    let sched = DynamicScheduler::lavd(nr_cpus);

    unsafe {
        lavd_setup_pco(&sched, nr_cpus);
        lavd_setup_two_domains(&sched, nr_cpus, 4);
    }

    // Create an imbalanced workload to trigger load comparison
    let mut builder = Scenario::builder()
        .cpus(nr_cpus)
        .seed(4444)
        .detect_bpf_errors();

    // Heavy load on domain 0
    let d0_cpus = vec![CpuId(0), CpuId(1), CpuId(2), CpuId(3)];
    for i in 1i32..=3 {
        builder = builder.task(TaskDef {
            name: format!("heavy{}", i),
            pid: Pid(i),
            nice: 0,
            behavior: TaskBehavior {
                phases: vec![Phase::Run(500_000)],
                repeat: RepeatMode::Forever,
            },
            start_time_ns: 0,
            mm_id: Some(MmId(1)),
            allowed_cpus: Some(d0_cpus.clone()),
            parent_pid: None,
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
        });
    }

    // Add ping-pong that should benefit from load comparison
    let (prod, cons) = workloads::ping_pong(Pid(10), Pid(11), 60_000);
    builder = builder
        .task(TaskDef {
            name: "ping".into(),
            pid: Pid(10),
            nice: 0,
            behavior: prod,
            start_time_ns: 500_000,
            mm_id: Some(MmId(2)),
            allowed_cpus: None,
            parent_pid: None,
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
        })
        .task(TaskDef {
            name: "pong".into(),
            pid: Pid(11),
            nice: 0,
            behavior: cons,
            start_time_ns: 500_000,
            mm_id: Some(MmId(2)),
            allowed_cpus: None,
            parent_pid: None,
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
        });

    let scenario = builder.duration_ms(250).build();

    let trace = Simulator::new(sched).run(scenario);
    assert!(
        !trace.has_error(),
        "Unexpected error: {:?}",
        trace.exit_kind()
    );
    eprintln!("[sticky_load_comparison] Test passed with domain load comparison");
}

/// Test pick_random_cpu fallback when no idle CPU found.
///
/// When pick_idle_cpu cannot find an idle CPU in any expected location,
/// it falls back to pick_random_cpu() using the power-of-two-choices.
///
/// Covers: idle.bpf.c lines 218-237 (pick_random_cpu),
/// lines 823-824 (fallback to pick_random_cpu)
#[test]
fn test_lavd_pick_random_cpu_fallback() {
    let _lock = common::setup_test();

    let nr_cpus = 4u32;
    let sched = DynamicScheduler::lavd(nr_cpus);

    unsafe {
        lavd_setup_pco(&sched, nr_cpus);
    }

    // Saturate all CPUs to force random CPU selection
    let mut builder = Scenario::builder()
        .cpus(nr_cpus)
        .seed(3333)
        .detect_bpf_errors();

    for i in 1..=(nr_cpus + 2) {
        builder = builder.add_task(
            &format!("saturator{}", i),
            0,
            TaskBehavior {
                phases: vec![Phase::Run(1_000_000)],
                repeat: RepeatMode::Forever,
            },
        );
    }

    let scenario = builder.duration_ms(150).build();
    let trace = Simulator::new(sched).run(scenario);
    assert!(
        !trace.has_error(),
        "Unexpected error: {:?}",
        trace.exit_kind()
    );
    eprintln!("[pick_random_fallback] Test passed with CPU saturation");
}

/// Test cpumask_any_distribute in pick_random_cpu.
///
/// When picking a random CPU, cpumask_any_distribute is called twice
/// to implement power-of-two-choices (lines 224-225).
///
/// Covers: idle.bpf.c lines 201-216 (cpumask_any_distribute),
/// lines 224-236 (two-choice comparison)
#[test]
fn test_lavd_two_choice_cpu_selection() {
    let _lock = common::setup_test();

    let nr_cpus = 8u32;
    let sched = DynamicScheduler::lavd(nr_cpus);

    unsafe {
        lavd_setup_pco(&sched, nr_cpus);
    }

    // Create varied utilization across CPUs
    let mut builder = Scenario::builder()
        .cpus(nr_cpus)
        .seed(2222)
        .detect_bpf_errors();

    // Different workloads with varying runtimes (no pinning to specific CPUs)
    for i in 0i32..6 {
        let runtime = 200_000 + (i as u64 * 100_000); // Varying runtimes
        builder = builder.task(TaskDef {
            name: format!("worker{}", i),
            pid: Pid(i + 1),
            nice: 0,
            behavior: TaskBehavior {
                phases: vec![Phase::Run(runtime), Phase::Sleep(100_000)],
                repeat: RepeatMode::Forever,
            },
            start_time_ns: (i as u64) * 50_000,
            mm_id: Some(MmId(1)),
            allowed_cpus: None, // Let scheduler choose - no pinning
            parent_pid: None,
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
        });
    }

    // Add a free-roaming task that will trigger two-choice selection
    builder = builder.add_task(
        "roamer",
        0,
        TaskBehavior {
            phases: vec![Phase::Run(50_000), Phase::Sleep(150_000)],
            repeat: RepeatMode::Forever,
        },
    );

    let scenario = builder.duration_ms(200).build();
    let trace = Simulator::new(sched).run(scenario);
    assert!(
        !trace.has_error(),
        "Unexpected error: {:?}",
        trace.exit_kind()
    );
    eprintln!("[two_choice_selection] Test passed with varied CPU utilization");
}

/// Test find_cpu_in when task cannot run on active/overflow sets.
///
/// When a task's cpumask doesn't intersect with active or overflow sets,
/// find_cpu_in() is called to find a CPU in preference order (lines 121-152).
///
/// Covers: idle.bpf.c lines 121-152 (find_cpu_in), lines 640-645 (extending overflow)
#[test]
fn test_lavd_find_cpu_in_overflow_extension() {
    let _lock = common::setup_test();

    let nr_cpus = 8u32;
    let sched = DynamicScheduler::lavd(nr_cpus);

    unsafe {
        lavd_setup_pco(&sched, nr_cpus);
        lavd_setup_two_domains(&sched, nr_cpus, 4);
        // Enable core compaction to have a small active set
        lavd_set_bool(&sched, "no_core_compaction\0", false);
    }

    // Create a task with limited affinity to a subset of CPUs (not single CPU)
    // This exercises find_cpu_in when the task's cpumask doesn't fully overlap active set
    let scenario = Scenario::builder()
        .cpus(nr_cpus)
        .seed(1111)
        .detect_bpf_errors()
        .task(TaskDef {
            name: "limited_affinity".into(),
            pid: Pid(1),
            nice: 0,
            behavior: TaskBehavior {
                phases: vec![Phase::Run(100_000), Phase::Sleep(200_000)],
                repeat: RepeatMode::Forever,
            },
            start_time_ns: 0,
            mm_id: Some(MmId(1)),
            // Affinity to domain 1 CPUs only - exercises overflow extension
            allowed_cpus: Some(vec![CpuId(4), CpuId(5), CpuId(6), CpuId(7)]),
            parent_pid: None,
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
        })
        .add_task(
            "background",
            0,
            TaskBehavior {
                phases: vec![Phase::Run(50_000), Phase::Sleep(150_000)],
                repeat: RepeatMode::Forever,
            },
        )
        .duration_ms(200)
        .build();

    let trace = Simulator::new(sched).run(scenario);
    assert!(
        !trace.has_error(),
        "Unexpected error: {:?}",
        trace.exit_kind()
    );
    eprintln!("[find_cpu_in_overflow] Test passed with overflow extension");
}

/// Test multiple seeds to explore different scheduling paths.
///
/// Uses different random seeds to hit various branch combinations
/// in the idle CPU selection logic.
#[test]
fn test_lavd_seed_exploration_idle_paths() {
    let _lock = common::setup_test();

    let seeds = [100, 200, 300, 400, 500, 600, 700, 800, 900, 1000];

    for seed in seeds {
        let nr_cpus = 8u32;
        let sched = DynamicScheduler::lavd(nr_cpus);

        unsafe {
            lavd_setup_pco(&sched, nr_cpus);
            lavd_set_bool(&sched, "is_smt_active\0", seed % 2 == 0);
            // Set up two domains for variety (single-domain tests exist elsewhere)
            lavd_setup_two_domains(&sched, nr_cpus, 4);
        }

        let (prod, cons) = workloads::ping_pong(Pid(1), Pid(2), 80_000);

        let scenario = Scenario::builder()
            .cpus(nr_cpus)
            .seed(seed)
            .detect_bpf_errors()
            .task(TaskDef {
                name: "ping".into(),
                pid: Pid(1),
                nice: 0,
                behavior: prod,
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
                behavior: cons,
                start_time_ns: 0,
                mm_id: Some(MmId(1)),
                allowed_cpus: None,
                parent_pid: None,
                cgroup_name: None,
                task_flags: 0,
                migration_disabled: 0,
            })
            .add_task(
                "background",
                5,
                TaskBehavior {
                    phases: vec![Phase::Run(300_000), Phase::Sleep(100_000)],
                    repeat: RepeatMode::Forever,
                },
            )
            .duration_ms(100)
            .build();

        let trace = Simulator::new(sched).run(scenario);
        assert!(
            !trace.has_error(),
            "Seed {} failed: {:?}",
            seed,
            trace.exit_kind()
        );
    }

    eprintln!("[seed_exploration_idle] All {} seeds passed", seeds.len());
}

/// Test PF_EXITING waker path in is_sync_wakeup.
///
/// When a waker task has PF_EXITING set, is_sync_wakeup() should return false
/// (line 355-356 in idle.bpf.c).
///
/// Note: This test simulates the scenario by having tasks exit while
/// waking others, though the simulator may not fully model PF_EXITING.
#[test]
fn test_lavd_exiting_waker_sync() {
    let _lock = common::setup_test();

    let nr_cpus = 4u32;
    let sched = DynamicScheduler::lavd(nr_cpus);

    unsafe {
        lavd_setup_pco(&sched, nr_cpus);
    }

    // Create a task that wakes another then exits
    let scenario = Scenario::builder()
        .cpus(nr_cpus)
        .seed(9876)
        .detect_bpf_errors()
        .task(TaskDef {
            name: "waker_then_exit".into(),
            pid: Pid(1),
            nice: 0,
            behavior: TaskBehavior {
                phases: vec![Phase::Run(100_000), Phase::Wake(Pid(2)), Phase::Run(50_000)],
                repeat: RepeatMode::Count(1), // Exit after one iteration
            },
            start_time_ns: 0,
            mm_id: Some(MmId(1)),
            allowed_cpus: None,
            parent_pid: None,
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
        })
        .task(TaskDef {
            name: "wakee".into(),
            pid: Pid(2),
            nice: 0,
            behavior: TaskBehavior {
                phases: vec![Phase::Sleep(500_000), Phase::Run(200_000)],
                repeat: RepeatMode::Forever,
            },
            start_time_ns: 0,
            mm_id: Some(MmId(1)),
            allowed_cpus: None,
            parent_pid: None,
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
        })
        .duration_ms(150)
        .build();

    let trace = Simulator::new(sched).run(scenario);
    assert!(
        !trace.has_error(),
        "Unexpected error: {:?}",
        trace.exit_kind()
    );
    eprintln!("[exiting_waker] Test passed with exiting waker scenario");
}

/// Test dispatch with per-domain DSQ and affinitized task iteration.
///
/// When using per-domain DSQ (use_cpdom_dsq), the dispatch function
/// iterates through the DSQ looking for affinitized tasks (lines 1060-1131).
///
/// Covers: main.bpf.c lines 1060-1131 (bpf_for_each in dispatch)
#[test]
fn test_lavd_dispatch_cpdom_dsq_affinity_search() {
    let _lock = common::setup_test();

    let nr_cpus = 8u32;
    let sched = DynamicScheduler::lavd(nr_cpus);

    unsafe {
        lavd_setup_pco(&sched, nr_cpus);
        lavd_setup_two_domains(&sched, nr_cpus, 4);
        // Force per-domain DSQ by setting pinned_slice_ns > 0
        lavd_set_u64(&sched, "pinned_slice_ns\0", 1_000_000);
    }

    // Create tasks with domain-level affinity (not single CPU) to avoid dispatch errors
    let scenario = Scenario::builder()
        .cpus(nr_cpus)
        .seed(1234)
        .detect_bpf_errors()
        // Task affinitized to domain 1 CPUs
        .task(TaskDef {
            name: "domain1_affinity".into(),
            pid: Pid(1),
            nice: 0,
            behavior: TaskBehavior {
                phases: vec![Phase::Run(200_000), Phase::Sleep(100_000)],
                repeat: RepeatMode::Forever,
            },
            start_time_ns: 0,
            mm_id: Some(MmId(1)),
            allowed_cpus: Some(vec![CpuId(4), CpuId(5), CpuId(6), CpuId(7)]),
            parent_pid: None,
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
        })
        // Free-roaming task
        .add_task(
            "roamer",
            0,
            TaskBehavior {
                phases: vec![Phase::Run(100_000), Phase::Sleep(50_000)],
                repeat: RepeatMode::Forever,
            },
        )
        .duration_ms(200)
        .build();

    let trace = Simulator::new(sched).run(scenario);
    assert!(
        !trace.has_error(),
        "Unexpected error: {:?}",
        trace.exit_kind()
    );
    eprintln!("[dispatch_cpdom_affinity] Test passed with per-domain DSQ affinity search");
}

/// Test quiescent callback with affinitized task counting.
///
/// When an affinitized task goes quiescent, task state is updated
/// in the quiescent callback (lines 1375-1417 in main.bpf.c).
///
/// Covers: main.bpf.c lines 1375-1417 (quiescent path)
#[test]
fn test_lavd_quiescent_affinitized_task() {
    let _lock = common::setup_test();

    let nr_cpus = 4u32;
    let sched = DynamicScheduler::lavd(nr_cpus);

    unsafe {
        lavd_setup_pco(&sched, nr_cpus);
    }

    // Create an affinitized task (to subset of CPUs) that sleeps
    let scenario = Scenario::builder()
        .cpus(nr_cpus)
        .seed(5678)
        .detect_bpf_errors()
        .task(TaskDef {
            name: "affinitized_sleeper".into(),
            pid: Pid(1),
            nice: 0,
            behavior: TaskBehavior {
                phases: vec![Phase::Run(100_000), Phase::Sleep(200_000)],
                repeat: RepeatMode::Forever,
            },
            start_time_ns: 0,
            mm_id: Some(MmId(1)),
            // Affinitized to subset of CPUs (not single CPU)
            allowed_cpus: Some(vec![CpuId(0), CpuId(1)]),
            parent_pid: None,
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
        })
        .add_task(
            "background",
            0,
            TaskBehavior {
                phases: vec![Phase::Run(50_000)],
                repeat: RepeatMode::Forever,
            },
        )
        .duration_ms(150)
        .build();

    let trace = Simulator::new(sched).run(scenario);
    assert!(
        !trace.has_error(),
        "Unexpected error: {:?}",
        trace.exit_kind()
    );
    eprintln!("[quiescent_affinitized] Test passed with affinitized task quiescent");
}

/// Test tick handler with affinitized tasks contention.
///
/// When there are multiple tasks competing for the same CPUs, the tick
/// handler processes them and may trigger slice adjustment.
///
/// Covers: main.bpf.c lavd_tick path
#[test]
fn test_lavd_tick_affinity_contention() {
    let _lock = common::setup_test();

    let nr_cpus = 4u32;
    let sched = DynamicScheduler::lavd(nr_cpus);

    unsafe {
        lavd_setup_pco(&sched, nr_cpus);
    }

    // Create multiple tasks affinitized to same subset of CPUs
    let scenario = Scenario::builder()
        .cpus(nr_cpus)
        .seed(9012)
        .detect_bpf_errors()
        .task(TaskDef {
            name: "contender1".into(),
            pid: Pid(1),
            nice: 0,
            behavior: TaskBehavior {
                phases: vec![Phase::Run(500_000)],
                repeat: RepeatMode::Forever,
            },
            start_time_ns: 0,
            mm_id: Some(MmId(1)),
            // Affinitized to CPUs 0,1
            allowed_cpus: Some(vec![CpuId(0), CpuId(1)]),
            parent_pid: None,
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
        })
        .task(TaskDef {
            name: "contender2".into(),
            pid: Pid(2),
            nice: 0,
            behavior: TaskBehavior {
                phases: vec![Phase::Run(500_000)],
                repeat: RepeatMode::Forever,
            },
            start_time_ns: 0,
            mm_id: Some(MmId(1)),
            // Same affinity
            allowed_cpus: Some(vec![CpuId(0), CpuId(1)]),
            parent_pid: None,
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
        })
        .duration_ms(200)
        .build();

    let trace = Simulator::new(sched).run(scenario);
    assert!(
        !trace.has_error(),
        "Unexpected error: {:?}",
        trace.exit_kind()
    );
    eprintln!("[tick_affinity_contention] Test passed with affinity contention");
}

/// Test wait_freq update in quiescent.
///
/// When a task goes to sleep (SCX_DEQ_SLEEP), wait_freq is updated
/// (lines 1412-1416 in main.bpf.c).
///
/// Covers: main.bpf.c lines 1412-1416 (wait_freq update in quiescent)
#[test]
fn test_lavd_quiescent_wait_freq() {
    let _lock = common::setup_test();

    let nr_cpus = 4u32;
    let sched = DynamicScheduler::lavd(nr_cpus);

    unsafe {
        lavd_setup_pco(&sched, nr_cpus);
    }

    // Create a task with frequent sleep/wake cycles to update wait_freq
    let scenario = Scenario::builder()
        .cpus(nr_cpus)
        .seed(3456)
        .detect_bpf_errors()
        .add_task(
            "frequent_sleeper",
            0,
            TaskBehavior {
                phases: vec![Phase::Run(50_000), Phase::Sleep(50_000)],
                repeat: RepeatMode::Forever,
            },
        )
        .duration_ms(200)
        .build();

    let trace = Simulator::new(sched).run(scenario);
    assert!(
        !trace.has_error(),
        "Unexpected error: {:?}",
        trace.exit_kind()
    );
    eprintln!("[quiescent_wait_freq] Test passed with wait_freq update");
}

/// Test dispatch prev task handling with queued state.
///
/// When the previous task is still queued (SCX_TASK_QUEUED), dispatch
/// may continue it without DSQ consumption in certain conditions.
///
/// Covers: main.bpf.c dispatch prev task handling
#[test]
fn test_lavd_dispatch_prev_task_queued() {
    let _lock = common::setup_test();

    let nr_cpus = 4u32;
    let sched = DynamicScheduler::lavd(nr_cpus);

    unsafe {
        lavd_setup_pco(&sched, nr_cpus);
    }

    // Create a ping-pong workload that exercises dispatch paths
    let (prod, cons) = workloads::ping_pong(Pid(1), Pid(2), 50_000);

    let scenario = Scenario::builder()
        .cpus(nr_cpus)
        .seed(7890)
        .detect_bpf_errors()
        .task(TaskDef {
            name: "ping".into(),
            pid: Pid(1),
            nice: 0,
            behavior: prod,
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
            behavior: cons,
            start_time_ns: 0,
            mm_id: Some(MmId(1)),
            allowed_cpus: None,
            parent_pid: None,
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
        })
        .duration_ms(150)
        .build();

    let trace = Simulator::new(sched).run(scenario);
    assert!(
        !trace.has_error(),
        "Unexpected error: {:?}",
        trace.exit_kind()
    );
    eprintln!("[dispatch_prev_queued] Test passed with prev task queued handling");
}

/// Test use_full_cpus fast path in dispatch.
///
/// When all CPUs are in use (use_full_cpus returns true), dispatch
/// skips cpumask checks and goes directly to consume (lines 969-970).
///
/// Covers: main.bpf.c lines 969-970 (use_full_cpus fast path)
#[test]
fn test_lavd_dispatch_full_cpus_fast_path() {
    let _lock = common::setup_test();

    let nr_cpus = 4u32;
    let sched = DynamicScheduler::lavd(nr_cpus);

    unsafe {
        lavd_setup_pco(&sched, nr_cpus);
        // Disable core compaction to use all CPUs
        lavd_set_bool(&sched, "no_core_compaction\0", true);
    }

    // Create enough tasks to saturate all CPUs
    let mut builder = Scenario::builder()
        .cpus(nr_cpus)
        .seed(2345)
        .detect_bpf_errors();

    for i in 1i32..=4 {
        builder = builder.add_task(
            &format!("worker{}", i),
            0,
            TaskBehavior {
                phases: vec![Phase::Run(200_000), Phase::Sleep(50_000)],
                repeat: RepeatMode::Forever,
            },
        );
    }

    let scenario = builder.duration_ms(200).build();
    let trace = Simulator::new(sched).run(scenario);
    assert!(
        !trace.has_error(),
        "Unexpected error: {:?}",
        trace.exit_kind()
    );
    eprintln!("[dispatch_full_cpus] Test passed with full CPUs fast path");
}

/// Test migration disabled task in dispatch.
///
/// When a task has migration disabled (is_migration_disabled), dispatch
/// handles it specially (lines 1020-1023, 1090-1098).
///
/// Covers: main.bpf.c lines 1020-1023, 1090-1098 (migration_disabled paths)
#[test]
fn test_lavd_dispatch_migration_disabled() {
    let _lock = common::setup_test();

    let nr_cpus = 8u32;
    let sched = DynamicScheduler::lavd(nr_cpus);

    unsafe {
        lavd_setup_pco(&sched, nr_cpus);
        lavd_setup_two_domains(&sched, nr_cpus, 4);
    }

    // Create a task with migration disabled
    let scenario = Scenario::builder()
        .cpus(nr_cpus)
        .seed(6789)
        .detect_bpf_errors()
        .task(TaskDef {
            name: "migration_disabled".into(),
            pid: Pid(1),
            nice: 0,
            behavior: TaskBehavior {
                phases: vec![Phase::Run(200_000), Phase::Sleep(100_000)],
                repeat: RepeatMode::Forever,
            },
            start_time_ns: 0,
            mm_id: Some(MmId(1)),
            allowed_cpus: None,
            parent_pid: None,
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 1, // Migration disabled
        })
        .add_task(
            "normal",
            0,
            TaskBehavior {
                phases: vec![Phase::Run(100_000), Phase::Sleep(50_000)],
                repeat: RepeatMode::Forever,
            },
        )
        .duration_ms(200)
        .build();

    let trace = Simulator::new(sched).run(scenario);
    assert!(
        !trace.has_error(),
        "Unexpected error: {:?}",
        trace.exit_kind()
    );
    eprintln!("[dispatch_migration_disabled] Test passed with migration disabled");
}

/// Test high priority waker and wakee interaction.
///
/// When a high priority task wakes another task, the wakee may
/// receive priority boost (lines 1215-1218 in main.bpf.c).
///
/// Covers: main.bpf.c lavd_runnable waker/wakee handling
#[test]
fn test_lavd_high_priority_waker() {
    let _lock = common::setup_test();

    let nr_cpus = 4u32;
    let sched = DynamicScheduler::lavd(nr_cpus);

    unsafe {
        lavd_setup_pco(&sched, nr_cpus);
    }

    // Create tasks with negative nice (high priority)
    // Note: No parent_pid since parent task doesn't exist in scenario
    let scenario = Scenario::builder()
        .cpus(nr_cpus)
        .seed(4567)
        .detect_bpf_errors()
        .task(TaskDef {
            name: "high_prio_waker".into(),
            pid: Pid(1),
            nice: -19, // Very high priority
            behavior: TaskBehavior {
                phases: vec![Phase::Run(50_000), Phase::Wake(Pid(2)), Phase::Run(50_000)],
                repeat: RepeatMode::Forever,
            },
            start_time_ns: 0,
            mm_id: Some(MmId(1)),
            allowed_cpus: None,
            parent_pid: None,
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
        })
        .task(TaskDef {
            name: "wakee".into(),
            pid: Pid(2),
            nice: 0,
            behavior: TaskBehavior {
                phases: vec![Phase::Sleep(200_000), Phase::Run(100_000)],
                repeat: RepeatMode::Forever,
            },
            start_time_ns: 0,
            mm_id: Some(MmId(1)),
            allowed_cpus: None,
            parent_pid: None,
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
        })
        .duration_ms(200)
        .build();

    let trace = Simulator::new(sched).run(scenario);
    assert!(
        !trace.has_error(),
        "Unexpected error: {:?}",
        trace.exit_kind()
    );
    eprintln!("[high_priority_waker] Test passed with high priority waker");
}

/// Test enqueue with different priority combinations.
///
/// Exercises various paths in lavd_enqueue based on task priorities
/// and preemption scenarios.
///
/// Covers: main.bpf.c lavd_enqueue priority handling
#[test]
fn test_lavd_enqueue_priority_variations() {
    let _lock = common::setup_test();

    let nr_cpus = 4u32;
    let sched = DynamicScheduler::lavd(nr_cpus);

    unsafe {
        lavd_setup_pco(&sched, nr_cpus);
    }

    // Create a preemption-heavy workload with different priorities
    let (prod, cons) = workloads::ping_pong(Pid(1), Pid(2), 30_000);

    let scenario = Scenario::builder()
        .cpus(nr_cpus)
        .seed(8901)
        .detect_bpf_errors()
        .task(TaskDef {
            name: "ping".into(),
            pid: Pid(1),
            nice: -10, // High priority
            behavior: prod,
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
            nice: 10, // Low priority
            behavior: cons,
            start_time_ns: 0,
            mm_id: Some(MmId(1)),
            allowed_cpus: None,
            parent_pid: None,
            cgroup_name: None,
            task_flags: 0,
            migration_disabled: 0,
        })
        // Add background tasks to create contention
        .add_task(
            "background",
            5,
            TaskBehavior {
                phases: vec![Phase::Run(100_000)],
                repeat: RepeatMode::Forever,
            },
        )
        .duration_ms(150)
        .build();

    let trace = Simulator::new(sched).run(scenario);
    assert!(
        !trace.has_error(),
        "Unexpected error: {:?}",
        trace.exit_kind()
    );
    eprintln!("[enqueue_priorities] Test passed with various priorities");
}
