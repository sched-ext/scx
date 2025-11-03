// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use serde::Serialize;
use serde_json::Value;
use std::collections::{HashMap, VecDeque};

/// Process event history tracker
pub struct ProcessEventHistory {
    events: HashMap<u32, VecDeque<ProcessEvent>>,
    max_events_per_process: usize,
    enabled: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct ProcessEvent {
    pub timestamp: u64,
    pub event_type: String,
    pub cpu: Option<u32>,
    pub data: Value,
}

impl ProcessEventHistory {
    pub fn new(max_events_per_process: usize) -> Self {
        Self {
            events: HashMap::new(),
            max_events_per_process,
            enabled: false, // Disabled by default
        }
    }

    /// Enable event history tracking
    pub fn start(&mut self) {
        self.enabled = true;
    }

    /// Disable event history tracking
    pub fn stop(&mut self) {
        self.enabled = false;
    }

    /// Check if tracker is actively collecting
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Clear all tracked events
    pub fn reset(&mut self) {
        self.events.clear();
    }

    pub fn record_event(
        &mut self,
        pid: u32,
        event_type: String,
        cpu: Option<u32>,
        data: Value,
        timestamp: u64,
    ) {
        if !self.enabled {
            return;
        }
        let event = ProcessEvent {
            timestamp,
            event_type,
            cpu,
            data,
        };

        let events = self.events.entry(pid).or_default();
        if events.len() >= self.max_events_per_process {
            events.pop_front();
        }
        events.push_back(event);
    }

    pub fn get_events(&self, pid: u32, limit: Option<usize>) -> Vec<ProcessEvent> {
        self.events
            .get(&pid)
            .map(|events| {
                let mut result: Vec<_> = events.iter().cloned().rev().collect();
                if let Some(limit) = limit {
                    result.truncate(limit);
                }
                result
            })
            .unwrap_or_default()
    }

    pub fn get_stats(&self, pid: u32) -> Option<ProcessEventStats> {
        let events = self.events.get(&pid)?;

        let mut event_counts: HashMap<String, u64> = HashMap::new();
        for event in events {
            *event_counts.entry(event.event_type.clone()).or_insert(0) += 1;
        }

        Some(ProcessEventStats {
            pid,
            total_events: events.len() as u64,
            event_counts,
            oldest_timestamp: events.front().map(|e| e.timestamp),
            newest_timestamp: events.back().map(|e| e.timestamp),
        })
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct ProcessEventStats {
    pub pid: u32,
    pub total_events: u64,
    pub event_counts: HashMap<String, u64>,
    pub oldest_timestamp: Option<u64>,
    pub newest_timestamp: Option<u64>,
}

/// DSQ (Dispatch Queue) Monitor
pub struct DsqMonitor {
    dsq_stats: HashMap<u64, DsqStats>,
    window_start: u64,
    enabled: bool,
}

#[derive(Clone, Debug)]
struct DsqStats {
    enqueue_count: u64,
    dequeue_count: u64,
    total_latency_us: u64,
    latency_samples: Vec<u64>,
    max_queue_length: u64,
    current_queue_length: u64,
}

impl DsqMonitor {
    pub fn new() -> Self {
        Self {
            dsq_stats: HashMap::new(),
            window_start: now_ms(),
            enabled: false, // Disabled by default
        }
    }

    /// Enable DSQ monitoring
    pub fn start(&mut self) {
        self.enabled = true;
        self.window_start = now_ms();
    }

    /// Disable DSQ monitoring
    pub fn stop(&mut self) {
        self.enabled = false;
    }

    /// Check if monitor is actively collecting
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Clear all tracked data
    pub fn reset(&mut self) {
        self.dsq_stats.clear();
        self.window_start = now_ms();
    }

    pub fn record_event(&mut self, json: &Value) {
        if !self.enabled {
            return;
        }
        if let Some(event_type) = json.get("type").and_then(|v| v.as_str()) {
            if event_type == "sched_switch" {
                // Extract DSQ info
                if let Some(dsq_id) = json.get("next_dsq_id").and_then(|v| v.as_u64()) {
                    let stats = self.dsq_stats.entry(dsq_id).or_insert_with(|| DsqStats {
                        enqueue_count: 0,
                        dequeue_count: 0,
                        total_latency_us: 0,
                        latency_samples: Vec::new(),
                        max_queue_length: 0,
                        current_queue_length: 0,
                    });

                    stats.dequeue_count += 1;

                    if let Some(lat) = json.get("next_dsq_lat_us").and_then(|v| v.as_u64()) {
                        stats.total_latency_us += lat;
                        stats.latency_samples.push(lat);
                    }

                    if let Some(queue_len) = json.get("next_dsq_nr_queued").and_then(|v| v.as_u64())
                    {
                        stats.current_queue_length = queue_len;
                        stats.max_queue_length = stats.max_queue_length.max(queue_len);
                    }
                }
            }
        }
    }

    pub fn get_stats(&self, dsq_ids: Option<&[u64]>) -> Vec<DsqMonitorStats> {
        let ids: Vec<u64> = if let Some(ids) = dsq_ids {
            ids.to_vec()
        } else {
            self.dsq_stats.keys().copied().collect()
        };

        ids.iter()
            .filter_map(|dsq_id| {
                let stats = self.dsq_stats.get(dsq_id)?;

                let avg_latency = if stats.dequeue_count > 0 {
                    stats.total_latency_us as f64 / stats.dequeue_count as f64
                } else {
                    0.0
                };

                Some(DsqMonitorStats {
                    dsq_id: *dsq_id,
                    enqueue_count: stats.enqueue_count,
                    dequeue_count: stats.dequeue_count,
                    avg_latency_us: avg_latency,
                    max_queue_length: stats.max_queue_length,
                    current_queue_length: stats.current_queue_length,
                })
            })
            .collect()
    }
}

impl Default for DsqMonitor {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct DsqMonitorStats {
    pub dsq_id: u64,
    pub enqueue_count: u64,
    pub dequeue_count: u64,
    pub avg_latency_us: f64,
    pub max_queue_length: u64,
    pub current_queue_length: u64,
}

/// Event rate monitor with anomaly detection
pub struct EventRateMonitor {
    event_counts: HashMap<String, VecDeque<u64>>,
    window_size_ms: u64,
    baseline_windows: usize,
    window_timestamps: VecDeque<u64>,
    enabled: bool,
}

impl EventRateMonitor {
    pub fn new(window_size_ms: u64, baseline_windows: usize) -> Self {
        Self {
            event_counts: HashMap::new(),
            window_size_ms,
            baseline_windows,
            window_timestamps: VecDeque::new(),
            enabled: false, // Disabled by default
        }
    }

    /// Enable rate monitoring
    pub fn start(&mut self) {
        self.enabled = true;
    }

    /// Disable rate monitoring
    pub fn stop(&mut self) {
        self.enabled = false;
    }

    /// Check if monitor is actively collecting
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Clear all tracked data
    pub fn reset(&mut self) {
        self.event_counts.clear();
        self.window_timestamps.clear();
    }

    pub fn record_event(&mut self, event_type: String, timestamp: u64) {
        if !self.enabled {
            return;
        }
        // Find or create window
        let window_idx = timestamp / (self.window_size_ms * 1_000_000);

        // Check if we need a new window
        let need_new_window = if let Some(&last_window) = self.window_timestamps.back() {
            window_idx > last_window
        } else {
            true
        };

        // Add new window if needed
        if need_new_window {
            self.window_timestamps.push_back(window_idx);
            for counts in self.event_counts.values_mut() {
                counts.push_back(0);
            }
        }

        // Initialize event type if needed and increment count
        let counts = self.event_counts.entry(event_type).or_insert_with(|| {
            let mut v = VecDeque::new();
            // Fill with zeros for existing windows
            for _ in 0..self.window_timestamps.len() {
                v.push_back(0);
            }
            v
        });

        // Increment count for current window
        if let Some(last_count) = counts.back_mut() {
            *last_count += 1;
        }

        // Trim old windows
        let max_windows = self.baseline_windows + 1;
        while self.window_timestamps.len() > max_windows {
            self.window_timestamps.pop_front();
            for counts in self.event_counts.values_mut() {
                counts.pop_front();
            }
        }
    }

    pub fn detect_anomalies(&self, threshold_multiplier: f64) -> Vec<RateAnomaly> {
        let mut anomalies = Vec::new();

        for (event_type, counts) in &self.event_counts {
            if counts.len() < 2 {
                continue;
            }

            let current_rate = *counts.back().unwrap() as f64;

            // Calculate baseline (all but last window)
            let baseline_counts: Vec<_> = counts
                .iter()
                .rev()
                .skip(1)
                .take(self.baseline_windows)
                .copied()
                .collect();
            if baseline_counts.is_empty() {
                continue;
            }

            let baseline_avg =
                baseline_counts.iter().sum::<u64>() as f64 / baseline_counts.len() as f64;

            if baseline_avg > 0.0 && current_rate > baseline_avg * threshold_multiplier {
                anomalies.push(RateAnomaly {
                    event_type: event_type.clone(),
                    current_rate,
                    baseline_avg,
                    spike_factor: current_rate / baseline_avg,
                });
            }
        }

        anomalies.sort_by(|a, b| b.spike_factor.partial_cmp(&a.spike_factor).unwrap());
        anomalies
    }

    pub fn get_rates(&self) -> HashMap<String, f64> {
        self.event_counts
            .iter()
            .filter_map(|(event_type, counts)| {
                counts.back().map(|&count| {
                    let rate = count as f64 / (self.window_size_ms as f64 / 1000.0);
                    (event_type.clone(), rate)
                })
            })
            .collect()
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct RateAnomaly {
    pub event_type: String,
    pub current_rate: f64,
    pub baseline_avg: f64,
    pub spike_factor: f64,
}

/// Wakeup chain tracker
pub struct WakeupChainTracker {
    wakeups: HashMap<u32, Vec<WakeupEvent>>,
    #[allow(dead_code)]
    max_chain_length: usize,
    enabled: bool,
}

#[derive(Clone, Debug)]
struct WakeupEvent {
    #[allow(dead_code)]
    timestamp: u64,
    waker_pid: u32,
    #[allow(dead_code)]
    waker_comm: String,
    target_pid: u32,
    target_comm: String,
    #[allow(dead_code)]
    cpu: u32,
}

impl WakeupChainTracker {
    pub fn new(max_chain_length: usize) -> Self {
        Self {
            wakeups: HashMap::new(),
            max_chain_length,
            enabled: false, // Disabled by default
        }
    }

    /// Enable wakeup chain tracking
    pub fn start(&mut self) {
        self.enabled = true;
    }

    /// Disable wakeup chain tracking
    pub fn stop(&mut self) {
        self.enabled = false;
    }

    /// Check if tracker is actively collecting
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Clear all tracked data
    pub fn reset(&mut self) {
        self.wakeups.clear();
    }

    pub fn record_wakeup(&mut self, json: &Value, timestamp: u64) {
        if !self.enabled {
            return;
        }
        if let Some(event_type) = json.get("type").and_then(|v| v.as_str()) {
            if event_type == "sched_wakeup" || event_type == "sched_wakeup_new" {
                let waker_pid = json
                    .get("waker_pid")
                    .and_then(|v| v.as_u64())
                    .map(|v| v as u32);
                let target_pid = json.get("pid").and_then(|v| v.as_u64()).map(|v| v as u32);

                if let (Some(waker_pid), Some(target_pid)) = (waker_pid, target_pid) {
                    let event = WakeupEvent {
                        timestamp,
                        waker_pid,
                        waker_comm: json
                            .get("waker_comm")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string(),
                        target_pid,
                        target_comm: json
                            .get("comm")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string(),
                        cpu: json.get("cpu").and_then(|v| v.as_u64()).unwrap_or(0) as u32,
                    };

                    self.wakeups.entry(target_pid).or_default().push(event);
                }
            }
        }
    }

    pub fn trace_chain(&self, pid: u32, max_depth: usize) -> Vec<WakeupChain> {
        let mut chains = Vec::new();

        if let Some(wakeups) = self.wakeups.get(&pid) {
            for wakeup in wakeups {
                let chain = self.build_chain(wakeup.waker_pid, max_depth, 0);
                if !chain.is_empty() {
                    chains.push(WakeupChain {
                        root_pid: pid,
                        root_comm: wakeup.target_comm.clone(),
                        chain,
                        total_latency_us: 0, // Would need to calculate from timestamps
                        chain_length: 1,
                    });
                }
            }
        }

        chains
    }

    fn build_chain(&self, pid: u32, max_depth: usize, depth: usize) -> Vec<WakeupLink> {
        if depth >= max_depth {
            return Vec::new();
        }

        let mut links = Vec::new();

        if let Some(wakeups) = self.wakeups.get(&pid) {
            for wakeup in wakeups.iter().take(1) {
                // Take most recent
                links.push(WakeupLink {
                    pid: wakeup.waker_pid,
                    wakes: wakeup.target_pid,
                    latency_us: 0, // Would calculate from timestamps
                });

                // Recurse
                let next_links = self.build_chain(wakeup.waker_pid, max_depth, depth + 1);
                links.extend(next_links);
            }
        }

        links
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct WakeupChain {
    pub root_pid: u32,
    pub root_comm: String,
    pub chain: Vec<WakeupLink>,
    pub total_latency_us: u64,
    pub chain_length: usize,
}

#[derive(Clone, Debug, Serialize)]
pub struct WakeupLink {
    pub pid: u32,
    pub wakes: u32,
    pub latency_us: u64,
}

/// System snapshot capturer
#[derive(Clone, Debug, Serialize)]
pub struct SystemSnapshot {
    pub snapshot_id: String,
    pub timestamp: u64,
    pub processes: Vec<ProcessSnapshot>,
    pub cpu_states: Vec<CpuSnapshot>,
    pub recent_events: Vec<Value>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ProcessSnapshot {
    pub pid: u32,
    pub comm: String,
    pub cpu: Option<u32>,
    pub state: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct CpuSnapshot {
    pub cpu: u32,
    pub utilization: f64,
    pub frequency: Option<u64>,
}

// Helper function
fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}
