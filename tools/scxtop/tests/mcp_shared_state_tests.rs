// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use scx_utils::Topology;
use scxtop::bpf_intf;
use scxtop::bpf_skel::types::bpf_event;
use scxtop::mcp::{create_shared_stats, SharedStats};
use std::mem::MaybeUninit;
use std::sync::Arc;

/// Helper function to get system topology for testing
/// Returns None if topology cannot be loaded
fn try_create_test_topology() -> Option<Topology> {
    Topology::new().ok()
}

/// Helper function to create a sched_switch event
fn create_sched_switch_event(
    cpu: u32,
    timestamp_ns: u64,
    prev_pid: u32,
    next_pid: u32,
    next_comm: &str,
    next_dsq_id: u64,
    prev_dsq_id: u64,
) -> bpf_event {
    let mut event: bpf_event = unsafe { MaybeUninit::zeroed().assume_init() };
    event.r#type = bpf_intf::event_type_SCHED_SWITCH as i32;
    event.cpu = cpu;
    event.ts = timestamp_ns;

    unsafe {
        event.event.sched_switch.prev_pid = prev_pid;
        event.event.sched_switch.next_pid = next_pid;
        event.event.sched_switch.next_dsq_id = next_dsq_id;
        event.event.sched_switch.prev_dsq_id = prev_dsq_id;

        // Copy command name
        let comm_bytes = next_comm.as_bytes();
        let len = std::cmp::min(comm_bytes.len(), event.event.sched_switch.next_comm.len());
        event.event.sched_switch.next_comm[..len].copy_from_slice(&comm_bytes[..len]);
    }

    event
}

/// Helper function to create a sched_wakeup event
fn create_sched_wakeup_event(cpu: u32, timestamp_ns: u64, pid: u32, comm: &str) -> bpf_event {
    let mut event: bpf_event = unsafe { MaybeUninit::zeroed().assume_init() };
    event.r#type = bpf_intf::event_type_SCHED_WAKEUP as i32;
    event.cpu = cpu;
    event.ts = timestamp_ns;

    unsafe {
        event.event.wakeup.pid = pid;

        // Copy command name
        let comm_bytes = comm.as_bytes();
        let len = std::cmp::min(comm_bytes.len(), event.event.wakeup.comm.len());
        event.event.wakeup.comm[..len].copy_from_slice(&comm_bytes[..len]);
    }

    event
}

/// Helper function to create a sched_migrate event
fn create_sched_migrate_event(cpu: u32, timestamp_ns: u64) -> bpf_event {
    let mut event: bpf_event = unsafe { MaybeUninit::zeroed().assume_init() };
    event.r#type = bpf_intf::event_type_SCHED_MIGRATE as i32;
    event.cpu = cpu;
    event.ts = timestamp_ns;

    event
}

#[test]
fn test_shared_stats_new() {
    let stats = SharedStats::new();
    assert_eq!(stats.cpu_stats.len(), 0);
    assert_eq!(stats.process_stats.len(), 0);
    assert_eq!(stats.dsq_stats.len(), 0);
    assert!(stats.start_time_ns > 0);
}

#[test]
fn test_create_shared_stats() {
    let stats_handle = create_shared_stats();
    let stats = stats_handle.read().unwrap();
    assert_eq!(stats.cpu_stats.len(), 0);
    assert_eq!(stats.process_stats.len(), 0);
}

#[test]
fn test_sched_switch_updates_cpu_stats() {
    let mut stats = SharedStats::new();
    stats.enable_tracking();
    let event = create_sched_switch_event(0, 1000000, 100, 200, "test_proc", u64::MAX, u64::MAX);

    stats.update_from_event(&event);

    assert_eq!(stats.cpu_stats.len(), 1);
    let cpu_stats = stats.cpu_stats.get(&0).unwrap();
    assert_eq!(cpu_stats.cpu_id, 0);
    assert_eq!(cpu_stats.nr_switches, 1);
    assert_eq!(cpu_stats.nr_wakeups, 0);
}

#[test]
fn test_sched_switch_updates_process_stats() {
    let mut stats = SharedStats::new();
    stats.enable_tracking();
    let event = create_sched_switch_event(0, 1000000, 100, 200, "test_proc", u64::MAX, u64::MAX);

    stats.update_from_event(&event);

    assert_eq!(stats.process_stats.len(), 1);
    let proc_stats = stats.process_stats.get(&200).unwrap();
    assert_eq!(proc_stats.pid, 200);
    assert_eq!(proc_stats.comm, "test_proc");
    assert_eq!(proc_stats.nr_switches, 1);
}

#[test]
fn test_multiple_sched_switches() {
    let mut stats = SharedStats::new();
    stats.enable_tracking();

    // First switch on CPU 0
    let event1 = create_sched_switch_event(0, 1000000, 100, 200, "proc1", u64::MAX, u64::MAX);
    stats.update_from_event(&event1);

    // Second switch on CPU 0
    let event2 = create_sched_switch_event(0, 2000000, 200, 300, "proc2", u64::MAX, u64::MAX);
    stats.update_from_event(&event2);

    // Switch on CPU 1
    let event3 = create_sched_switch_event(1, 1500000, 400, 500, "proc3", u64::MAX, u64::MAX);
    stats.update_from_event(&event3);

    // Verify CPU stats
    assert_eq!(stats.cpu_stats.len(), 2);
    assert_eq!(stats.cpu_stats.get(&0).unwrap().nr_switches, 2);
    assert_eq!(stats.cpu_stats.get(&1).unwrap().nr_switches, 1);

    // Verify process stats
    assert_eq!(stats.process_stats.len(), 3);
    assert_eq!(stats.process_stats.get(&200).unwrap().nr_switches, 1);
    assert_eq!(stats.process_stats.get(&300).unwrap().nr_switches, 1);
    assert_eq!(stats.process_stats.get(&500).unwrap().nr_switches, 1);
}

#[test]
fn test_sched_wakeup_updates_stats() {
    let mut stats = SharedStats::new();
    stats.enable_tracking();
    let event = create_sched_wakeup_event(0, 1000000, 200, "test_proc");

    stats.update_from_event(&event);

    // Verify CPU stats
    assert_eq!(stats.cpu_stats.len(), 1);
    let cpu_stats = stats.cpu_stats.get(&0).unwrap();
    assert_eq!(cpu_stats.nr_wakeups, 1);
    assert!(stats.pending_wakeups.contains_key(&200));

    // Verify process stats
    assert_eq!(stats.process_stats.len(), 1);
    let proc_stats = stats.process_stats.get(&200).unwrap();
    assert_eq!(proc_stats.nr_wakeups, 1);
    assert_eq!(proc_stats.comm, "test_proc");
}

#[test]
fn test_wakeup_latency_calculation() {
    let mut stats = SharedStats::new();
    stats.enable_tracking();

    // Wakeup at t=1000000
    let wakeup = create_sched_wakeup_event(0, 1000000, 200, "test_proc");
    stats.update_from_event(&wakeup);

    // Switch at t=1500000 (latency = 500000)
    let switch = create_sched_switch_event(0, 1500000, 100, 200, "test_proc", u64::MAX, u64::MAX);
    stats.update_from_event(&switch);

    // Verify CPU latency stats
    let cpu_stats = stats.cpu_stats.get(&0).unwrap();
    assert_eq!(cpu_stats.total_latency_ns, 500000);
    assert_eq!(cpu_stats.min_latency_ns, 500000);
    assert_eq!(cpu_stats.max_latency_ns, 500000);
    assert_eq!(cpu_stats.latency_samples, 1);

    // Verify process latency stats
    let proc_stats = stats.process_stats.get(&200).unwrap();
    assert_eq!(proc_stats.total_latency_ns, 500000);
    assert_eq!(proc_stats.min_latency_ns, 500000);
    assert_eq!(proc_stats.max_latency_ns, 500000);
    assert_eq!(proc_stats.latency_samples, 1);

    // Pending wakeup should be removed
    assert!(!stats.pending_wakeups.contains_key(&200));
}

#[test]
fn test_multiple_latency_samples() {
    let mut stats = SharedStats::new();
    stats.enable_tracking();

    // First wakeup/switch pair (latency = 500000)
    let wakeup1 = create_sched_wakeup_event(0, 1000000, 200, "test_proc");
    stats.update_from_event(&wakeup1);
    let switch1 = create_sched_switch_event(0, 1500000, 100, 200, "test_proc", u64::MAX, u64::MAX);
    stats.update_from_event(&switch1);

    // Second wakeup/switch pair (latency = 300000)
    let wakeup2 = create_sched_wakeup_event(0, 2000000, 200, "test_proc");
    stats.update_from_event(&wakeup2);
    let switch2 = create_sched_switch_event(0, 2300000, 100, 200, "test_proc", u64::MAX, u64::MAX);
    stats.update_from_event(&switch2);

    // Third wakeup/switch pair (latency = 700000)
    let wakeup3 = create_sched_wakeup_event(0, 3000000, 200, "test_proc");
    stats.update_from_event(&wakeup3);
    let switch3 = create_sched_switch_event(0, 3700000, 100, 200, "test_proc", u64::MAX, u64::MAX);
    stats.update_from_event(&switch3);

    let proc_stats = stats.process_stats.get(&200).unwrap();
    assert_eq!(proc_stats.latency_samples, 3);
    assert_eq!(proc_stats.total_latency_ns, 1500000); // 500000 + 300000 + 700000
    assert_eq!(proc_stats.min_latency_ns, 300000);
    assert_eq!(proc_stats.max_latency_ns, 700000);
}

#[test]
fn test_sched_migrate_updates_stats() {
    let mut stats = SharedStats::new();
    stats.enable_tracking();
    let event = create_sched_migrate_event(0, 1000000);

    stats.update_from_event(&event);

    assert_eq!(stats.cpu_stats.len(), 1);
    let cpu_stats = stats.cpu_stats.get(&0).unwrap();
    assert_eq!(cpu_stats.nr_migrations, 1);
}

#[test]
fn test_multiple_migrations() {
    let mut stats = SharedStats::new();
    stats.enable_tracking();

    let event1 = create_sched_migrate_event(0, 1000000);
    stats.update_from_event(&event1);

    let event2 = create_sched_migrate_event(0, 2000000);
    stats.update_from_event(&event2);

    let event3 = create_sched_migrate_event(1, 1500000);
    stats.update_from_event(&event3);

    assert_eq!(stats.cpu_stats.get(&0).unwrap().nr_migrations, 2);
    assert_eq!(stats.cpu_stats.get(&1).unwrap().nr_migrations, 1);
}

#[test]
fn test_dsq_stats_tracking() {
    let mut stats = SharedStats::new();
    stats.enable_tracking();

    // Switch with DSQ IDs
    let event = create_sched_switch_event(0, 1000000, 100, 200, "proc", 42, 43);
    stats.update_from_event(&event);

    assert_eq!(stats.dsq_stats.len(), 2);
    assert_eq!(stats.dsq_stats.get(&42).unwrap().nr_dispatches, 1);
    assert_eq!(stats.dsq_stats.get(&43).unwrap().nr_enqueues, 1);
}

#[test]
fn test_dsq_stats_ignores_max_value() {
    let mut stats = SharedStats::new();
    stats.enable_tracking();

    // Switch with MAX DSQ IDs (should be ignored)
    let event = create_sched_switch_event(0, 1000000, 100, 200, "proc", u64::MAX, u64::MAX);
    stats.update_from_event(&event);

    assert_eq!(stats.dsq_stats.len(), 0);
}

#[test]
fn test_get_cpu_stats_json() {
    let mut stats = SharedStats::new();
    stats.enable_tracking();

    // Add some events
    let wakeup = create_sched_wakeup_event(0, 1000000, 200, "test");
    stats.update_from_event(&wakeup);

    let switch = create_sched_switch_event(0, 1500000, 100, 200, "test", u64::MAX, u64::MAX);
    stats.update_from_event(&switch);

    let json = stats.get_cpu_stats_json();

    assert!(json["cpus"].is_array());
    assert_eq!(json["total_cpus"], 1);

    let cpu0 = &json["cpus"][0];
    assert_eq!(cpu0["cpu_id"], 0);
    assert_eq!(cpu0["nr_switches"], 1);
    assert_eq!(cpu0["nr_wakeups"], 1);
    assert_eq!(cpu0["latency"]["avg_ns"], 500000);
}

#[test]
fn test_get_process_stats_json() {
    let mut stats = SharedStats::new();
    stats.enable_tracking();

    // Add events for multiple processes
    for pid in 100..105 {
        let event = create_sched_switch_event(0, 1000000, pid - 1, pid, "proc", u64::MAX, u64::MAX);
        stats.update_from_event(&event);
    }

    let json = stats.get_process_stats_json(Some(3));

    assert!(json["processes"].is_array());
    assert_eq!(json["total_processes"], 5);
    assert_eq!(json["shown"], 3); // Limited to 3
}

#[test]
fn test_get_dsq_stats_json() {
    let mut stats = SharedStats::new();
    stats.enable_tracking();

    // Add DSQ events
    let event1 = create_sched_switch_event(0, 1000000, 100, 200, "proc", 10, 20);
    stats.update_from_event(&event1);

    let event2 = create_sched_switch_event(0, 2000000, 200, 300, "proc", 10, 20);
    stats.update_from_event(&event2);

    let json = stats.get_dsq_stats_json();

    assert!(json["dsqs"].is_array());
    assert_eq!(json["total_dsqs"], 2);
}

#[test]
fn test_get_llc_stats_json() {
    let Some(topology) = try_create_test_topology() else {
        // Skip test if topology is unavailable
        return;
    };

    let mut stats = SharedStats::new();
    stats.enable_tracking();

    // Add events on first two CPUs
    if let Some(cpu1) = topology.all_cpus.keys().next().copied() {
        let event1 =
            create_sched_switch_event(cpu1 as u32, 1000000, 100, 200, "proc", u64::MAX, u64::MAX);
        stats.update_from_event(&event1);
    }

    if let Some(cpu2) = topology.all_cpus.keys().nth(1).copied() {
        let event2 =
            create_sched_switch_event(cpu2 as u32, 2000000, 200, 300, "proc", u64::MAX, u64::MAX);
        stats.update_from_event(&event2);
    }

    let json = stats.get_llc_stats_json(&topology);

    assert!(json["llcs"].is_array());
    assert!(json["total_llcs"].as_u64().unwrap() > 0);
}

#[test]
fn test_get_node_stats_json() {
    let Some(topology) = try_create_test_topology() else {
        // Skip test if topology is unavailable
        return;
    };

    let mut stats = SharedStats::new();
    stats.enable_tracking();

    // Add events on first two CPUs
    if let Some(cpu1) = topology.all_cpus.keys().next().copied() {
        let event1 =
            create_sched_switch_event(cpu1 as u32, 1000000, 100, 200, "proc", u64::MAX, u64::MAX);
        stats.update_from_event(&event1);
    }

    if let Some(cpu2) = topology.all_cpus.keys().nth(1).copied() {
        let event2 =
            create_sched_switch_event(cpu2 as u32, 2000000, 200, 300, "proc", u64::MAX, u64::MAX);
        stats.update_from_event(&event2);
    }

    let json = stats.get_node_stats_json(&topology);

    assert!(json["nodes"].is_array());
    assert!(json["total_nodes"].as_u64().unwrap() > 0);
}

#[test]
fn test_thread_safe_shared_stats() {
    use std::thread;

    let stats_handle = create_shared_stats();
    let stats_handle_clone = Arc::clone(&stats_handle);

    // Spawn a thread that updates stats
    let handle = thread::spawn(move || {
        let mut stats = stats_handle_clone.write().unwrap();
        stats.enable_tracking();
        let event = create_sched_switch_event(0, 1000000, 100, 200, "test", u64::MAX, u64::MAX);
        stats.update_from_event(&event);
    });

    handle.join().unwrap();

    // Read stats from main thread
    let stats = stats_handle.read().unwrap();
    assert_eq!(stats.cpu_stats.len(), 1);
    assert_eq!(stats.process_stats.len(), 1);
}
