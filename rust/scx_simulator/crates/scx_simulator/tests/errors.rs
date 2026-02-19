//! Tests for error detection infrastructure.
//!
//! Tests for ExitKind, watchdog configuration, and error reporting.
//! Note: Full integration tests for ErrorBpf and ErrorStall would require
//! special scheduler variants that call scx_bpf_error() or fail to dispatch.

use scx_simulator::*;

mod common;

/// Test that normal simulations complete with ExitKind::Normal.
///
/// This is a sanity check to ensure the error detection infrastructure
/// doesn't interfere with normal operation.
#[test]
fn test_normal_exit() {
    let _lock = common::setup_test();

    let scenario = Scenario::builder()
        .cpus(1)
        .instant_timing()
        .task(TaskDef {
            name: "worker".into(),
            pid: Pid(1),
            nice: 0,
            behavior: TaskBehavior {
                phases: vec![Phase::Run(5_000_000)], // 5ms
                repeat: RepeatMode::Once,
            },
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: None,
            parent_pid: None,
            cgroup_name: None,
        })
        .duration_ms(100)
        .build();

    let trace = Simulator::new(DynamicScheduler::simple()).run(scenario);
    trace.dump();

    // Verify the simulation completed normally
    assert!(
        !trace.has_error(),
        "simulation should complete without error"
    );
    assert_eq!(
        trace.exit_kind(),
        &ExitKind::Normal,
        "exit_kind should be Normal"
    );

    // Task should have run and completed
    assert!(
        trace.schedule_count(Pid(1)) > 0,
        "task should have been scheduled"
    );
}

/// Test that watchdog can be disabled via no_watchdog().
#[test]
fn test_watchdog_disabled() {
    let _lock = common::setup_test();

    let scenario = Scenario::builder()
        .cpus(1)
        .no_watchdog() // Disable watchdog
        .instant_timing()
        .task(TaskDef {
            name: "worker".into(),
            pid: Pid(1),
            nice: 0,
            behavior: TaskBehavior {
                phases: vec![Phase::Run(10_000_000)], // 10ms
                repeat: RepeatMode::Forever,
            },
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: None,
            parent_pid: None,
            cgroup_name: None,
        })
        .duration_ms(50)
        .build();

    // Verify watchdog is disabled in the scenario
    assert_eq!(
        scenario.watchdog_timeout_ns, None,
        "watchdog should be disabled"
    );

    // Run the simulation
    let trace = Simulator::new(DynamicScheduler::simple()).run(scenario);
    trace.dump();

    // With watchdog disabled, simulation should complete normally
    assert_eq!(
        trace.exit_kind(),
        &ExitKind::Normal,
        "simulation should complete normally"
    );
}

/// Test that watchdog_timeout_ns can be configured.
#[test]
fn test_watchdog_timeout_configured() {
    let _lock = common::setup_test();

    // Test with custom timeout
    let custom_timeout = 5_000_000_000u64; // 5 seconds
    let scenario = Scenario::builder()
        .cpus(1)
        .watchdog_timeout_ns(Some(custom_timeout))
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
        })
        .duration_ms(50)
        .build();

    assert_eq!(
        scenario.watchdog_timeout_ns,
        Some(custom_timeout),
        "watchdog timeout should be configured"
    );

    // Run simulation - should complete normally with a working scheduler
    let trace = Simulator::new(DynamicScheduler::simple()).run(scenario);
    assert_eq!(trace.exit_kind(), &ExitKind::Normal);
}

/// Test ExitKind helper methods.
#[test]
fn test_exit_kind_helpers() {
    // Normal is not an error
    let normal = ExitKind::Normal;
    assert!(!normal.is_error());

    // All error variants are errors
    let bpf_error = ExitKind::ErrorBpf("test".to_string());
    assert!(bpf_error.is_error());

    let stall_error = ExitKind::ErrorStall {
        pid: Pid(1),
        runnable_for_ns: 1_000_000,
    };
    assert!(stall_error.is_error());

    let dispatch_error = ExitKind::ErrorDispatchLoopExhausted { cpu: CpuId(0) };
    assert!(dispatch_error.is_error());
}

/// Test ExitKind equality and cloning.
#[test]
fn test_exit_kind_traits() {
    let kind1 = ExitKind::Normal;
    let kind2 = ExitKind::Normal;
    assert_eq!(kind1, kind2);

    let kind3 = ExitKind::ErrorBpf("error".to_string());
    let kind4 = kind3.clone();
    assert_eq!(kind3, kind4);

    let kind5 = ExitKind::ErrorStall {
        pid: Pid(42),
        runnable_for_ns: 1_000_000_000,
    };
    let kind6 = kind5.clone();
    assert_eq!(kind5, kind6);

    // Different variants are not equal
    assert_ne!(kind1, kind3);
}

/// Test Trace has_error() and exit_kind() methods work correctly.
#[test]
fn test_trace_error_methods() {
    let _lock = common::setup_test();

    let scenario = Scenario::builder()
        .cpus(1)
        .instant_timing()
        .task(TaskDef {
            name: "worker".into(),
            pid: Pid(1),
            nice: 0,
            behavior: TaskBehavior {
                phases: vec![Phase::Run(1_000_000)],
                repeat: RepeatMode::Once,
            },
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: None,
            parent_pid: None,
            cgroup_name: None,
        })
        .duration_ms(10)
        .build();

    let trace = Simulator::new(DynamicScheduler::simple()).run(scenario);

    // Test both methods
    assert!(
        !trace.has_error(),
        "has_error() should return false for normal exit"
    );
    assert_eq!(
        trace.exit_kind(),
        &ExitKind::Normal,
        "exit_kind() should return Normal"
    );
}

/// Test default watchdog timeout is 30 seconds.
#[test]
fn test_default_watchdog_timeout() {
    let scenario = Scenario::builder()
        .cpus(1)
        .task(TaskDef {
            name: "worker".into(),
            pid: Pid(1),
            nice: 0,
            behavior: TaskBehavior {
                phases: vec![Phase::Run(1_000_000)],
                repeat: RepeatMode::Once,
            },
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: None,
            parent_pid: None,
            cgroup_name: None,
        })
        .duration_ms(10)
        .build();

    // Default should be 30 seconds (30_000_000_000 ns)
    assert_eq!(
        scenario.watchdog_timeout_ns,
        Some(30_000_000_000),
        "default watchdog timeout should be 30 seconds"
    );
}
