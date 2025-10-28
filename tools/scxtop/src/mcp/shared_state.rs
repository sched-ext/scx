// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use crate::bpf_skel::types::bpf_event;
use serde_json::Value as JsonValue;
use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};

/// Per-CPU scheduling statistics
#[derive(Debug, Clone, Default)]
pub struct CpuStats {
    pub cpu_id: usize,
    pub nr_switches: u64,
    pub nr_wakeups: u64,
    pub nr_migrations: u64,

    // Latency tracking
    pub total_latency_ns: u64,
    pub min_latency_ns: u64,
    pub max_latency_ns: u64,
    pub latency_samples: u64,
}

/// Per-thread scheduling statistics
/// Note: Despite the field name "pid", this tracks per-thread (TID) in Linux kernel terms.
/// This allows tracking individual threads within multi-threaded processes separately,
/// which is crucial for accurate latency measurements in applications like claude.
#[derive(Debug, Clone, Default)]
pub struct ProcessStats {
    pub pid: i32,  // Actually stores TID (Thread ID)
    pub tgid: i32, // Thread Group ID (actual process ID)
    pub comm: String,
    pub nr_switches: u64,
    pub nr_wakeups: u64,
    pub runtime_ns: u64,

    // Latency tracking (per-thread)
    pub total_latency_ns: u64,
    pub min_latency_ns: u64,
    pub max_latency_ns: u64,
    pub latency_samples: u64,
}

/// Dispatch queue statistics
#[derive(Debug, Clone, Default)]
pub struct DsqStats {
    pub dsq_id: u64,
    pub nr_enqueues: u64,
    pub nr_dispatches: u64,
}

/// Aggregated statistics for LLC or NUMA node groupings
#[derive(Debug, Clone, Default)]
struct AggregateStats {
    nr_switches: u64,
    nr_wakeups: u64,
    nr_migrations: u64,
    total_latency_ns: u64,
    min_latency_ns: u64,
    max_latency_ns: u64,
    latency_samples: u64,
    cpu_count: usize,
}

/// Shared statistics state for MCP server
pub struct SharedStats {
    pub cpu_stats: BTreeMap<usize, CpuStats>,
    pub process_stats: BTreeMap<i32, ProcessStats>,
    pub dsq_stats: BTreeMap<u64, DsqStats>,
    /// Track pending wakeups per-thread (TID) to avoid overwriting when multiple
    /// threads from the same process wake up before being scheduled.
    /// Note: In Linux kernel scheduling events, the "pid" field is actually the TID.
    pub pending_wakeups: BTreeMap<i32, u64>, // tid -> wakeup_timestamp_ns
    pub start_time_ns: u64,
    /// Flag to control whether stat tracking is enabled. When false, update_from_event
    /// does no work, providing significant performance improvement when stats aren't needed.
    tracking_enabled: bool,
}

impl Default for SharedStats {
    fn default() -> Self {
        Self {
            cpu_stats: BTreeMap::new(),
            process_stats: BTreeMap::new(),
            dsq_stats: BTreeMap::new(),
            pending_wakeups: BTreeMap::new(),
            start_time_ns: crate::util::get_clock_value(libc::CLOCK_BOOTTIME),
            tracking_enabled: false, // Disabled by default for performance
        }
    }
}

impl SharedStats {
    pub fn new() -> Self {
        Self::default()
    }

    /// Enable stat tracking. Once enabled, update_from_event will process events.
    /// This is called when process/thread stats resources are first accessed.
    pub fn enable_tracking(&mut self) {
        self.tracking_enabled = true;
    }

    /// Check if stat tracking is enabled
    pub fn is_tracking_enabled(&self) -> bool {
        self.tracking_enabled
    }

    /// Update statistics from a BPF event
    /// Returns immediately if tracking is not enabled, providing significant performance
    /// improvement when stats aren't being used.
    pub fn update_from_event(&mut self, event: &bpf_event) {
        // Early return if tracking is disabled
        if !self.tracking_enabled {
            return;
        }
        use crate::bpf_intf;

        let event_type = event.r#type as u32;
        match event_type {
            bpf_intf::event_type_SCHED_SWITCH => self.handle_sched_switch(event),
            bpf_intf::event_type_SCHED_WAKEUP | bpf_intf::event_type_SCHED_WAKING => {
                self.handle_sched_wakeup(event)
            }
            bpf_intf::event_type_SCHED_MIGRATE => self.handle_sched_migrate(event),
            bpf_intf::event_type_EXIT => self.handle_exit(event),
            bpf_intf::event_type_EXEC => self.handle_exec(event),
            _ => {}
        }
    }

    fn handle_sched_switch(&mut self, event: &bpf_event) {
        let sched_switch = unsafe { &event.event.sched_switch };
        let cpu_id = event.cpu as usize;
        // Note: next_pid is actually the TID (Thread ID) in kernel scheduling events
        let next_tid = sched_switch.next_pid as i32;
        let next_tgid = sched_switch.next_tgid as i32; // Actual process ID
        let timestamp_ns = event.ts;

        // Update CPU stats
        let cpu_stats = self.cpu_stats.entry(cpu_id).or_default();
        cpu_stats.cpu_id = cpu_id;
        cpu_stats.nr_switches += 1;

        // Check if this thread was previously woken up (tracks per-TID to avoid
        // losing wakeup events when multiple threads in same process wake up)
        if let Some(wakeup_ts) = self.pending_wakeups.remove(&next_tid) {
            let latency_ns = timestamp_ns.saturating_sub(wakeup_ts);

            // Update CPU latency stats
            cpu_stats.total_latency_ns = cpu_stats.total_latency_ns.saturating_add(latency_ns);
            cpu_stats.latency_samples += 1;

            if cpu_stats.min_latency_ns == 0 || latency_ns < cpu_stats.min_latency_ns {
                cpu_stats.min_latency_ns = latency_ns;
            }
            if latency_ns > cpu_stats.max_latency_ns {
                cpu_stats.max_latency_ns = latency_ns;
            }

            // Update thread/process latency stats (keyed by TID for per-thread tracking)
            let proc_stats = self.process_stats.entry(next_tid).or_default();
            proc_stats.pid = next_tid;
            proc_stats.tgid = next_tgid;
            proc_stats.total_latency_ns = proc_stats.total_latency_ns.saturating_add(latency_ns);
            proc_stats.latency_samples += 1;

            if proc_stats.min_latency_ns == 0 || latency_ns < proc_stats.min_latency_ns {
                proc_stats.min_latency_ns = latency_ns;
            }
            if latency_ns > proc_stats.max_latency_ns {
                proc_stats.max_latency_ns = latency_ns;
            }
        }

        // Update thread/process switch count and comm (per-TID tracking)
        let proc_stats = self.process_stats.entry(next_tid).or_default();
        proc_stats.pid = next_tid;
        proc_stats.tgid = next_tgid;
        proc_stats.nr_switches += 1;
        if !sched_switch.next_comm.is_empty() {
            proc_stats.comm = String::from_utf8_lossy(&sched_switch.next_comm)
                .trim_end_matches('\0')
                .to_string();
        }

        // Update DSQ stats from dispatch queue info
        let next_dsq_id = sched_switch.next_dsq_id;
        if next_dsq_id != u64::MAX {
            // u64::MAX typically indicates no DSQ
            let dsq_stats = self.dsq_stats.entry(next_dsq_id).or_default();
            dsq_stats.dsq_id = next_dsq_id;
            dsq_stats.nr_dispatches += 1;
        }

        let prev_dsq_id = sched_switch.prev_dsq_id;
        if prev_dsq_id != u64::MAX {
            let dsq_stats = self.dsq_stats.entry(prev_dsq_id).or_default();
            dsq_stats.dsq_id = prev_dsq_id;
            dsq_stats.nr_enqueues += 1;
        }
    }

    fn handle_sched_wakeup(&mut self, event: &bpf_event) {
        let wakeup = unsafe { &event.event.wakeup };
        let cpu_id = event.cpu as usize;
        // Note: wakeup.pid is actually the TID (Thread ID) in kernel scheduling events
        let tid = wakeup.pid as i32;
        let tgid = wakeup.tgid as i32; // Actual process ID
        let timestamp_ns = event.ts;

        // Store wakeup timestamp per-thread (TID) for accurate latency calculation
        // This prevents losing wakeup events when multiple threads wake up before scheduling
        self.pending_wakeups.insert(tid, timestamp_ns);

        // Update CPU wakeup count
        let cpu_stats = self.cpu_stats.entry(cpu_id).or_default();
        cpu_stats.cpu_id = cpu_id;
        cpu_stats.nr_wakeups += 1;

        // Update thread/process wakeup count (per-TID tracking)
        let proc_stats = self.process_stats.entry(tid).or_default();
        proc_stats.pid = tid;
        proc_stats.tgid = tgid;
        proc_stats.nr_wakeups += 1;

        // Update comm if available
        if !wakeup.comm.is_empty() {
            proc_stats.comm = String::from_utf8_lossy(&wakeup.comm)
                .trim_end_matches('\0')
                .to_string();
        }
    }

    fn handle_sched_migrate(&mut self, event: &bpf_event) {
        let cpu_id = event.cpu as usize;
        let cpu_stats = self.cpu_stats.entry(cpu_id).or_default();
        cpu_stats.cpu_id = cpu_id;
        cpu_stats.nr_migrations += 1;
    }

    fn handle_exit(&mut self, event: &bpf_event) {
        let exit = unsafe { &event.event.exit };
        let tid = exit.pid as i32;

        // Clean up stale wakeup timestamp to prevent TID reuse from causing
        // inflated latency measurements
        self.pending_wakeups.remove(&tid);
    }

    fn handle_exec(&mut self, event: &bpf_event) {
        let exec = unsafe { &event.event.exec };
        let tid = exec.pid as i32;

        // Clean up wakeup timestamp on exec since the thread identity has changed
        // Latency measurements from before exec() are not meaningful for the new program
        self.pending_wakeups.remove(&tid);
    }

    /// Get CPU stats as JSON
    pub fn get_cpu_stats_json(&self) -> JsonValue {
        let cpus: Vec<JsonValue> = self
            .cpu_stats
            .values()
            .map(|stats| {
                let avg_latency_ns = if stats.latency_samples > 0 {
                    stats.total_latency_ns / stats.latency_samples
                } else {
                    0
                };

                serde_json::json!({
                    "cpu_id": stats.cpu_id,
                    "nr_switches": stats.nr_switches,
                    "nr_wakeups": stats.nr_wakeups,
                    "nr_migrations": stats.nr_migrations,
                    "latency": {
                        "avg_ns": avg_latency_ns,
                        "min_ns": stats.min_latency_ns,
                        "max_ns": stats.max_latency_ns,
                        "total_ns": stats.total_latency_ns,
                        "samples": stats.latency_samples,
                    },
                })
            })
            .collect();

        serde_json::json!({
            "cpus": cpus,
            "total_cpus": self.cpu_stats.len(),
        })
    }

    /// Get process stats as JSON
    pub fn get_process_stats_json(&self, limit: Option<usize>) -> JsonValue {
        let mut processes: Vec<_> = self.process_stats.values().collect();

        // Sort by total runtime or latency
        processes.sort_by(|a, b| b.nr_switches.cmp(&a.nr_switches));

        let processes: Vec<JsonValue> = processes
            .iter()
            .take(limit.unwrap_or(100))
            .map(|stats| {
                let avg_latency_ns = if stats.latency_samples > 0 {
                    stats.total_latency_ns / stats.latency_samples
                } else {
                    0
                };

                serde_json::json!({
                    "tid": stats.pid,  // This is actually TID
                    "pid": stats.tgid, // This is the actual process ID (TGID)
                    "comm": stats.comm,
                    "nr_switches": stats.nr_switches,
                    "nr_wakeups": stats.nr_wakeups,
                    "runtime_ns": stats.runtime_ns,
                    "latency": {
                        "avg_ns": avg_latency_ns,
                        "min_ns": stats.min_latency_ns,
                        "max_ns": stats.max_latency_ns,
                        "total_ns": stats.total_latency_ns,
                        "samples": stats.latency_samples,
                    },
                })
            })
            .collect();

        serde_json::json!({
            "processes": processes,
            "total_processes": self.process_stats.len(),
            "shown": processes.len(),
        })
    }

    /// Get process-level aggregated stats (aggregates all threads by TGID)
    pub fn get_aggregated_process_stats_json(&self, limit: Option<usize>) -> JsonValue {
        use std::collections::HashMap;

        // Aggregate thread stats by TGID (process ID)
        let mut process_aggregates: HashMap<i32, AggregateStats> = HashMap::new();
        let mut process_comms: HashMap<i32, String> = HashMap::new();

        for thread_stats in self.process_stats.values() {
            if thread_stats.tgid == 0 {
                continue; // Skip if TGID not set
            }

            let entry = process_aggregates.entry(thread_stats.tgid).or_default();

            entry.nr_switches += thread_stats.nr_switches;
            entry.nr_wakeups += thread_stats.nr_wakeups;
            entry.total_latency_ns += thread_stats.total_latency_ns;
            entry.latency_samples += thread_stats.latency_samples;

            // Track min/max across all threads
            if entry.min_latency_ns == 0
                || (thread_stats.min_latency_ns < entry.min_latency_ns
                    && thread_stats.min_latency_ns > 0)
            {
                entry.min_latency_ns = thread_stats.min_latency_ns;
            }
            entry.max_latency_ns = entry.max_latency_ns.max(thread_stats.max_latency_ns);

            // Use comm from main thread (TID == TGID) or any thread's comm
            if thread_stats.pid == thread_stats.tgid
                || !process_comms.contains_key(&thread_stats.tgid)
            {
                process_comms.insert(thread_stats.tgid, thread_stats.comm.clone());
            }
        }

        let mut processes: Vec<_> = process_aggregates.iter().collect();
        processes.sort_by(|(_, a), (_, b)| b.nr_switches.cmp(&a.nr_switches));

        let processes: Vec<JsonValue> = processes
            .iter()
            .take(limit.unwrap_or(100))
            .map(|(tgid, stats)| {
                let avg_latency_ns = if stats.latency_samples > 0 {
                    stats.total_latency_ns / stats.latency_samples
                } else {
                    0
                };

                serde_json::json!({
                    "pid": tgid,
                    "comm": process_comms.get(tgid).cloned().unwrap_or_default(),
                    "nr_switches": stats.nr_switches,
                    "nr_wakeups": stats.nr_wakeups,
                    "latency": {
                        "avg_ns": avg_latency_ns,
                        "min_ns": stats.min_latency_ns,
                        "max_ns": stats.max_latency_ns,
                        "total_ns": stats.total_latency_ns,
                        "samples": stats.latency_samples,
                    },
                })
            })
            .collect();

        serde_json::json!({
            "processes": processes,
            "total_processes": process_aggregates.len(),
            "shown": processes.len(),
        })
    }

    /// Get DSQ stats as JSON
    pub fn get_dsq_stats_json(&self) -> JsonValue {
        let dsqs: Vec<JsonValue> = self
            .dsq_stats
            .values()
            .map(|stats| {
                serde_json::json!({
                    "dsq_id": stats.dsq_id,
                    "nr_enqueues": stats.nr_enqueues,
                    "nr_dispatches": stats.nr_dispatches,
                    "queue_depth": stats.nr_enqueues.saturating_sub(stats.nr_dispatches),
                })
            })
            .collect();

        serde_json::json!({
            "dsqs": dsqs,
            "total_dsqs": self.dsq_stats.len(),
        })
    }

    /// Get LLC (Last Level Cache) aggregated stats as JSON
    /// Requires topology to map CPUs to LLCs
    pub fn get_llc_stats_json(&self, topology: &scx_utils::Topology) -> JsonValue {
        use std::collections::HashMap;

        // Aggregate stats by LLC ID
        let mut llc_aggregates: HashMap<usize, AggregateStats> = HashMap::new();

        for cpu_stats in self.cpu_stats.values() {
            if let Some(cpu_info) = topology.all_cpus.get(&cpu_stats.cpu_id) {
                let llc_id = cpu_info.llc_id;
                let entry = llc_aggregates.entry(llc_id).or_default();

                entry.nr_switches += cpu_stats.nr_switches;
                entry.nr_wakeups += cpu_stats.nr_wakeups;
                entry.nr_migrations += cpu_stats.nr_migrations;
                entry.total_latency_ns += cpu_stats.total_latency_ns;
                entry.min_latency_ns = if entry.min_latency_ns == 0
                    || cpu_stats.min_latency_ns < entry.min_latency_ns
                        && cpu_stats.min_latency_ns > 0
                {
                    cpu_stats.min_latency_ns
                } else {
                    entry.min_latency_ns
                };
                entry.max_latency_ns = entry.max_latency_ns.max(cpu_stats.max_latency_ns);
                entry.latency_samples += cpu_stats.latency_samples;
                entry.cpu_count += 1;
            }
        }

        let llcs: Vec<JsonValue> = llc_aggregates
            .iter()
            .map(|(llc_id, stats)| {
                let avg_latency_ns = if stats.latency_samples > 0 {
                    stats.total_latency_ns / stats.latency_samples
                } else {
                    0
                };

                serde_json::json!({
                    "llc_id": llc_id,
                    "nr_cpus": stats.cpu_count,
                    "nr_switches": stats.nr_switches,
                    "nr_wakeups": stats.nr_wakeups,
                    "nr_migrations": stats.nr_migrations,
                    "latency": {
                        "avg_ns": avg_latency_ns,
                        "min_ns": stats.min_latency_ns,
                        "max_ns": stats.max_latency_ns,
                        "total_ns": stats.total_latency_ns,
                        "samples": stats.latency_samples,
                    },
                })
            })
            .collect();

        serde_json::json!({
            "llcs": llcs,
            "total_llcs": llc_aggregates.len(),
        })
    }

    /// Get NUMA node aggregated stats as JSON
    /// Requires topology to map CPUs to NUMA nodes
    pub fn get_node_stats_json(&self, topology: &scx_utils::Topology) -> JsonValue {
        use std::collections::HashMap;

        // Aggregate stats by NUMA node ID
        let mut node_aggregates: HashMap<usize, AggregateStats> = HashMap::new();

        for cpu_stats in self.cpu_stats.values() {
            if let Some(cpu_info) = topology.all_cpus.get(&cpu_stats.cpu_id) {
                let node_id = cpu_info.node_id;
                let entry = node_aggregates.entry(node_id).or_default();

                entry.nr_switches += cpu_stats.nr_switches;
                entry.nr_wakeups += cpu_stats.nr_wakeups;
                entry.nr_migrations += cpu_stats.nr_migrations;
                entry.total_latency_ns += cpu_stats.total_latency_ns;
                entry.min_latency_ns = if entry.min_latency_ns == 0
                    || cpu_stats.min_latency_ns < entry.min_latency_ns
                        && cpu_stats.min_latency_ns > 0
                {
                    cpu_stats.min_latency_ns
                } else {
                    entry.min_latency_ns
                };
                entry.max_latency_ns = entry.max_latency_ns.max(cpu_stats.max_latency_ns);
                entry.latency_samples += cpu_stats.latency_samples;
                entry.cpu_count += 1;
            }
        }

        let nodes: Vec<JsonValue> = node_aggregates
            .iter()
            .map(|(node_id, stats)| {
                let avg_latency_ns = if stats.latency_samples > 0 {
                    stats.total_latency_ns / stats.latency_samples
                } else {
                    0
                };

                serde_json::json!({
                    "node_id": node_id,
                    "nr_cpus": stats.cpu_count,
                    "nr_switches": stats.nr_switches,
                    "nr_wakeups": stats.nr_wakeups,
                    "nr_migrations": stats.nr_migrations,
                    "latency": {
                        "avg_ns": avg_latency_ns,
                        "min_ns": stats.min_latency_ns,
                        "max_ns": stats.max_latency_ns,
                        "total_ns": stats.total_latency_ns,
                        "samples": stats.latency_samples,
                    },
                })
            })
            .collect();

        serde_json::json!({
            "nodes": nodes,
            "total_nodes": node_aggregates.len(),
        })
    }
}

/// Thread-safe wrapper for SharedStats
pub type SharedStatsHandle = Arc<RwLock<SharedStats>>;

pub fn create_shared_stats() -> SharedStatsHandle {
    Arc::new(RwLock::new(SharedStats::new()))
}
