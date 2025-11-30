// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

//! Phase 3: I/O and Resource Analyzers
//!
//! Analyzers for Block I/O, Network I/O, Memory pressure, and File I/O

use super::perfetto_parser::{Percentiles, PerfettoTrace};
use perfetto_protos::ftrace_event::ftrace_event;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Block I/O Analyzer - analyzes block device I/O patterns
pub struct BlockIoAnalyzer;

impl BlockIoAnalyzer {
    /// Analyze block I/O request lifecycle
    pub fn analyze(trace: &PerfettoTrace) -> BlockIoResult {
        let mut pending_insert: HashMap<u64, BlockIoEvent> = HashMap::new(); // sector -> insert event
        let mut pending_issue: HashMap<u64, BlockIoEvent> = HashMap::new(); // sector -> issue event
        let mut completed_ios: Vec<BlockIoEvent> = Vec::new();

        // Scan all CPUs
        for cpu in 0..trace.num_cpus() {
            let events = trace.get_events_by_cpu(cpu as u32);

            for event_with_idx in events {
                match &event_with_idx.event.event {
                    Some(ftrace_event::Event::BlockRqInsert(insert)) => {
                        if let (Some(sector), Some(ts)) =
                            (insert.sector, event_with_idx.event.timestamp)
                        {
                            let io_event = BlockIoEvent {
                                sector,
                                nr_sector: insert.nr_sector.unwrap_or(0),
                                rwbs: insert.rwbs.clone().unwrap_or_default(),
                                insert_ts: Some(ts),
                                issue_ts: None,
                                complete_ts: None,
                                queue_latency_ns: None,
                                device_latency_ns: None,
                                total_latency_ns: None,
                            };
                            pending_insert.insert(sector, io_event);
                        }
                    }
                    Some(ftrace_event::Event::BlockRqIssue(issue)) => {
                        if let (Some(sector), Some(ts)) =
                            (issue.sector, event_with_idx.event.timestamp)
                        {
                            if let Some(mut io_event) = pending_insert.remove(&sector) {
                                io_event.issue_ts = Some(ts);
                                if let Some(insert_ts) = io_event.insert_ts {
                                    io_event.queue_latency_ns = Some(ts - insert_ts);
                                }
                                pending_issue.insert(sector, io_event);
                            } else {
                                // Issue without insert (started before trace)
                                let io_event = BlockIoEvent {
                                    sector,
                                    nr_sector: issue.nr_sector.unwrap_or(0),
                                    rwbs: issue.rwbs.clone().unwrap_or_default(),
                                    insert_ts: None,
                                    issue_ts: Some(ts),
                                    complete_ts: None,
                                    queue_latency_ns: None,
                                    device_latency_ns: None,
                                    total_latency_ns: None,
                                };
                                pending_issue.insert(sector, io_event);
                            }
                        }
                    }
                    Some(ftrace_event::Event::BlockRqComplete(complete)) => {
                        if let (Some(sector), Some(ts)) =
                            (complete.sector, event_with_idx.event.timestamp)
                        {
                            if let Some(mut io_event) = pending_issue.remove(&sector) {
                                io_event.complete_ts = Some(ts);
                                if let Some(issue_ts) = io_event.issue_ts {
                                    io_event.device_latency_ns = Some(ts - issue_ts);
                                }
                                if let Some(insert_ts) = io_event.insert_ts {
                                    io_event.total_latency_ns = Some(ts - insert_ts);
                                }
                                completed_ios.push(io_event);
                            }
                        }
                    }
                    _ => {}
                }
            }
        }

        // Calculate statistics
        let mut read_latencies = Vec::new();
        let mut write_latencies = Vec::new();
        let mut queue_latencies = Vec::new();
        let mut device_latencies = Vec::new();

        for io in &completed_ios {
            if let Some(total_lat) = io.total_latency_ns {
                if io.rwbs.contains('R') {
                    read_latencies.push(total_lat);
                } else if io.rwbs.contains('W') {
                    write_latencies.push(total_lat);
                }
            }
            if let Some(queue_lat) = io.queue_latency_ns {
                queue_latencies.push(queue_lat);
            }
            if let Some(device_lat) = io.device_latency_ns {
                device_latencies.push(device_lat);
            }
        }

        BlockIoResult {
            total_ios: completed_ios.len(),
            read_count: read_latencies.len(),
            write_count: write_latencies.len(),
            read_latency: if !read_latencies.is_empty() {
                Some(PerfettoTrace::calculate_percentiles(&read_latencies))
            } else {
                None
            },
            write_latency: if !write_latencies.is_empty() {
                Some(PerfettoTrace::calculate_percentiles(&write_latencies))
            } else {
                None
            },
            queue_latency: if !queue_latencies.is_empty() {
                Some(PerfettoTrace::calculate_percentiles(&queue_latencies))
            } else {
                None
            },
            device_latency: if !device_latencies.is_empty() {
                Some(PerfettoTrace::calculate_percentiles(&device_latencies))
            } else {
                None
            },
        }
    }
}

/// Network I/O Analyzer - analyzes network transmit/receive patterns
pub struct NetworkIoAnalyzer;

impl NetworkIoAnalyzer {
    /// Analyze network I/O patterns
    pub fn analyze(trace: &PerfettoTrace) -> NetworkIoResult {
        let mut tx_events: Vec<NetworkEvent> = Vec::new();
        let mut rx_events: Vec<NetworkEvent> = Vec::new();

        // Scan all CPUs
        for cpu in 0..trace.num_cpus() {
            let events = trace.get_events_by_cpu(cpu as u32);

            for event_with_idx in events {
                match &event_with_idx.event.event {
                    Some(ftrace_event::Event::NetDevXmit(xmit)) => {
                        if let Some(ts) = event_with_idx.event.timestamp {
                            tx_events.push(NetworkEvent {
                                timestamp: ts,
                                len: xmit.len.unwrap_or(0),
                                name: xmit.name.clone().unwrap_or_default(),
                            });
                        }
                    }
                    Some(ftrace_event::Event::NetifReceiveSkb(rx)) => {
                        if let Some(ts) = event_with_idx.event.timestamp {
                            rx_events.push(NetworkEvent {
                                timestamp: ts,
                                len: rx.len.unwrap_or(0),
                                name: rx.name.clone().unwrap_or_default(),
                            });
                        }
                    }
                    _ => {}
                }
            }
        }

        // Calculate total bytes
        let tx_bytes: u64 = tx_events.iter().map(|e| e.len as u64).sum();
        let rx_bytes: u64 = rx_events.iter().map(|e| e.len as u64).sum();

        // Calculate bandwidth (bytes/second) if we have time range
        let (start_ts, end_ts) = trace.time_range();
        let duration_secs = if end_ts > start_ts {
            (end_ts - start_ts) as f64 / 1_000_000_000.0
        } else {
            0.0
        };

        let tx_bandwidth_mbps = if duration_secs > 0.0 {
            (tx_bytes as f64 * 8.0) / (duration_secs * 1_000_000.0)
        } else {
            0.0
        };

        let rx_bandwidth_mbps = if duration_secs > 0.0 {
            (rx_bytes as f64 * 8.0) / (duration_secs * 1_000_000.0)
        } else {
            0.0
        };

        NetworkIoResult {
            tx_packets: tx_events.len(),
            rx_packets: rx_events.len(),
            tx_bytes,
            rx_bytes,
            tx_bandwidth_mbps,
            rx_bandwidth_mbps,
            duration_secs,
        }
    }
}

/// Memory Pressure Analyzer - analyzes memory allocation and reclaim
pub struct MemoryPressureAnalyzer;

impl MemoryPressureAnalyzer {
    /// Analyze memory pressure events
    pub fn analyze(trace: &PerfettoTrace) -> MemoryPressureResult {
        let mut alloc_count = 0;
        let mut free_count = 0;
        let mut reclaim_events: Vec<ReclaimEvent> = Vec::new();
        let mut pending_reclaim: HashMap<u32, ReclaimEvent> = HashMap::new(); // cpu -> begin event

        // Scan all CPUs
        for cpu in 0..trace.num_cpus() {
            let events = trace.get_events_by_cpu(cpu as u32);

            for event_with_idx in events {
                match &event_with_idx.event.event {
                    Some(ftrace_event::Event::MmPageAlloc(_)) => {
                        alloc_count += 1;
                    }
                    Some(ftrace_event::Event::MmPageFree(_)) => {
                        free_count += 1;
                    }
                    Some(ftrace_event::Event::MmVmscanDirectReclaimBegin(_begin)) => {
                        if let Some(ts) = event_with_idx.event.timestamp {
                            let reclaim = ReclaimEvent {
                                begin_ts: ts,
                                end_ts: None,
                                duration_ns: None,
                            };
                            pending_reclaim.insert(cpu as u32, reclaim);
                        }
                    }
                    Some(ftrace_event::Event::MmVmscanDirectReclaimEnd(_end)) => {
                        if let Some(ts) = event_with_idx.event.timestamp {
                            if let Some(mut reclaim) = pending_reclaim.remove(&(cpu as u32)) {
                                reclaim.end_ts = Some(ts);
                                reclaim.duration_ns = Some(ts - reclaim.begin_ts);
                                reclaim_events.push(reclaim);
                            }
                        }
                    }
                    _ => {}
                }
            }
        }

        // Calculate reclaim statistics
        let reclaim_durations: Vec<u64> = reclaim_events
            .iter()
            .filter_map(|e| e.duration_ns)
            .collect();

        MemoryPressureResult {
            page_alloc_count: alloc_count,
            page_free_count: free_count,
            net_allocation: alloc_count as i64 - free_count as i64,
            reclaim_count: reclaim_events.len(),
            reclaim_latency: if !reclaim_durations.is_empty() {
                Some(PerfettoTrace::calculate_percentiles(&reclaim_durations))
            } else {
                None
            },
        }
    }
}

/// File I/O Analyzer - analyzes filesystem operations
pub struct FileIoAnalyzer;

impl FileIoAnalyzer {
    /// Analyze file I/O operations (ext4 sync as example)
    pub fn analyze(trace: &PerfettoTrace) -> FileIoResult {
        let mut sync_events: Vec<FileSyncEvent> = Vec::new();
        let mut pending_sync: HashMap<u32, FileSyncEvent> = HashMap::new(); // cpu -> enter event

        // Scan all CPUs
        for cpu in 0..trace.num_cpus() {
            let events = trace.get_events_by_cpu(cpu as u32);

            for event_with_idx in events {
                match &event_with_idx.event.event {
                    Some(ftrace_event::Event::Ext4SyncFileEnter(_enter)) => {
                        if let Some(ts) = event_with_idx.event.timestamp {
                            let sync = FileSyncEvent {
                                enter_ts: ts,
                                exit_ts: None,
                                duration_ns: None,
                            };
                            pending_sync.insert(cpu as u32, sync);
                        }
                    }
                    Some(ftrace_event::Event::Ext4SyncFileExit(_exit)) => {
                        if let Some(ts) = event_with_idx.event.timestamp {
                            if let Some(mut sync) = pending_sync.remove(&(cpu as u32)) {
                                sync.exit_ts = Some(ts);
                                sync.duration_ns = Some(ts - sync.enter_ts);
                                sync_events.push(sync);
                            }
                        }
                    }
                    _ => {}
                }
            }
        }

        // Calculate statistics
        let sync_durations: Vec<u64> = sync_events.iter().filter_map(|e| e.duration_ns).collect();

        FileIoResult {
            sync_count: sync_events.len(),
            sync_latency: if !sync_durations.is_empty() {
                Some(PerfettoTrace::calculate_percentiles(&sync_durations))
            } else {
                None
            },
        }
    }
}

// ============================================================================
// Data Structures
// ============================================================================

/// Block I/O event tracking lifecycle
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockIoEvent {
    pub sector: u64,
    pub nr_sector: u32,
    pub rwbs: String,
    pub insert_ts: Option<u64>,
    pub issue_ts: Option<u64>,
    pub complete_ts: Option<u64>,
    pub queue_latency_ns: Option<u64>,
    pub device_latency_ns: Option<u64>,
    pub total_latency_ns: Option<u64>,
}

/// Block I/O analysis result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockIoResult {
    pub total_ios: usize,
    pub read_count: usize,
    pub write_count: usize,
    pub read_latency: Option<Percentiles>,
    pub write_latency: Option<Percentiles>,
    pub queue_latency: Option<Percentiles>,
    pub device_latency: Option<Percentiles>,
}

/// Network event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkEvent {
    pub timestamp: u64,
    pub len: u32,
    pub name: String,
}

/// Network I/O analysis result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkIoResult {
    pub tx_packets: usize,
    pub rx_packets: usize,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    pub tx_bandwidth_mbps: f64,
    pub rx_bandwidth_mbps: f64,
    pub duration_secs: f64,
}

/// Memory reclaim event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReclaimEvent {
    pub begin_ts: u64,
    pub end_ts: Option<u64>,
    pub duration_ns: Option<u64>,
}

/// Memory pressure analysis result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryPressureResult {
    pub page_alloc_count: usize,
    pub page_free_count: usize,
    pub net_allocation: i64,
    pub reclaim_count: usize,
    pub reclaim_latency: Option<Percentiles>,
}

/// File sync event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileSyncEvent {
    pub enter_ts: u64,
    pub exit_ts: Option<u64>,
    pub duration_ns: Option<u64>,
}

/// File I/O analysis result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileIoResult {
    pub sync_count: usize,
    pub sync_latency: Option<Percentiles>,
}

#[cfg(test)]
mod tests {

    #[test]
    fn test_block_io_analyzer_empty() {
        // Placeholder for mock tests
    }

    #[test]
    fn test_network_io_analyzer_empty() {
        // Placeholder for mock tests
    }

    #[test]
    fn test_memory_pressure_analyzer_empty() {
        // Placeholder for mock tests
    }

    #[test]
    fn test_file_io_analyzer_empty() {
        // Placeholder for mock tests
    }
}
