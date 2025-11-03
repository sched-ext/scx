// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

//! Waker/Wakee Relationship Analyzer
//!
//! Tracks and analyzes wakeup relationships between processes to understand:
//! - Critical process dependencies
//! - Wakeup latencies and patterns
//! - CPU affinity and migration behavior
//! - Scheduler effectiveness at handling dependent tasks

use serde::Serialize;
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

/// Maximum number of relationships to track
const DEFAULT_MAX_RELATIONSHIPS: usize = 10_000;

/// Minimum wakeup count to keep tracking a relationship
const DEFAULT_MIN_WAKEUP_COUNT: u32 = 10;

/// Maximum latency samples to keep per relationship
const MAX_LATENCY_SAMPLES: usize = 100;

/// Waker/Wakee relationship analyzer
pub struct WakerWakeeAnalyzer {
    /// Map of (waker_pid, wakee_pid) → relationship stats
    relationships: HashMap<(u32, u32), RelationshipStats>,

    /// Pending wakeup events (waiting for corresponding sched_switch)
    pending_wakeups: HashMap<u32, PendingWakeup>,

    /// Topology info for LLC/NUMA analysis
    topology: Option<Arc<scx_utils::Topology>>,

    /// Track only top N relationships to limit memory
    max_relationships: usize,

    /// Minimum wakeup count to track (filter noise)
    min_wakeup_count: u32,

    /// Control flag for start/stop
    enabled: bool,
}

/// Statistics for a waker/wakee relationship
#[derive(Clone, Debug, Serialize)]
pub struct RelationshipStats {
    /// Waker process
    pub waker_pid: u32,
    pub waker_comm: String,

    /// Wakee process
    pub wakee_pid: u32,
    pub wakee_comm: String,

    /// Frequency metrics
    pub wakeup_count: u64,
    pub first_seen_ns: u64,
    pub last_seen_ns: u64,

    /// Latency metrics (microseconds)
    #[serde(skip)]
    latency_samples: Vec<u64>,
    pub min_latency_us: u64,
    pub max_latency_us: u64,
    pub total_latency_us: u64,
    pub sample_count: u64,

    /// CPU affinity metrics
    pub same_cpu_count: u64,
    pub cross_cpu_count: u64,
    #[serde(skip)]
    pub cpu_pairs: HashMap<(u32, u32), u64>,

    /// LLC affinity (if topology available)
    pub same_llc_count: u64,
    pub cross_llc_count: u64,

    /// NUMA affinity (if topology available)
    pub same_node_count: u64,
    pub cross_node_count: u64,
}

/// Pending wakeup event
#[derive(Clone)]
struct PendingWakeup {
    waker_pid: u32,
    waker_comm: String,
    waker_cpu: u32,
    timestamp_ns: u64,
}

/// Relationships grouped by PID
#[derive(Clone, Debug, Serialize)]
pub struct RelationshipsByPid {
    pub pid: u32,
    pub as_waker: Vec<RelationshipStats>,
    pub as_wakee: Vec<RelationshipStats>,
}

/// Bidirectional relationship pair
#[derive(Clone, Debug, Serialize)]
pub struct BidirectionalRelationship {
    pub pid_a: u32,
    pub comm_a: String,
    pub pid_b: u32,
    pub comm_b: String,
    pub a_wakes_b_count: u64,
    pub a_wakes_b_avg_latency_us: u64,
    pub b_wakes_a_count: u64,
    pub b_wakes_a_avg_latency_us: u64,
    pub pattern_description: String,
}

impl WakerWakeeAnalyzer {
    pub fn new() -> Self {
        Self {
            relationships: HashMap::new(),
            pending_wakeups: HashMap::new(),
            topology: None,
            max_relationships: DEFAULT_MAX_RELATIONSHIPS,
            min_wakeup_count: DEFAULT_MIN_WAKEUP_COUNT,
            enabled: false,
        }
    }

    /// Create with custom limits
    pub fn with_limits(max_relationships: usize, min_wakeup_count: u32) -> Self {
        Self {
            relationships: HashMap::new(),
            pending_wakeups: HashMap::new(),
            topology: None,
            max_relationships,
            min_wakeup_count,
            enabled: false,
        }
    }

    /// Set topology for LLC/NUMA analysis
    pub fn set_topology(&mut self, topology: Arc<scx_utils::Topology>) {
        self.topology = Some(topology);
    }

    /// Enable waker/wakee tracking
    pub fn start(&mut self) {
        self.enabled = true;
    }

    /// Disable waker/wakee tracking
    pub fn stop(&mut self) {
        self.enabled = false;
    }

    /// Check if tracker is actively collecting
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Clear all tracked data
    pub fn reset(&mut self) {
        self.relationships.clear();
        self.pending_wakeups.clear();
    }

    /// Record a wakeup event (from sched_wakeup/sched_wakeup_new)
    pub fn record_wakeup(
        &mut self,
        wakee_pid: u32,
        waker_pid: u32,
        waker_comm: &str,
        waker_cpu: u32,
        timestamp_ns: u64,
    ) {
        if !self.enabled {
            return;
        }

        // Store pending wakeup for later matching with sched_switch
        self.pending_wakeups.insert(
            wakee_pid,
            PendingWakeup {
                waker_pid,
                waker_comm: waker_comm.to_string(),
                waker_cpu,
                timestamp_ns,
            },
        );
    }

    /// Record when wakee actually runs (from sched_switch)
    pub fn record_wakee_run(
        &mut self,
        wakee_pid: u32,
        wakee_comm: &str,
        wakee_cpu: u32,
        timestamp_ns: u64,
    ) {
        if !self.enabled {
            return;
        }

        // Find matching pending wakeup
        if let Some(wakeup) = self.pending_wakeups.remove(&wakee_pid) {
            let latency_ns = timestamp_ns.saturating_sub(wakeup.timestamp_ns);
            let latency_us = latency_ns / 1000;

            // Update or create relationship stats
            let key = (wakeup.waker_pid, wakee_pid);
            let stats = self.relationships.entry(key).or_insert_with(|| {
                RelationshipStats::new(
                    wakeup.waker_pid,
                    wakeup.waker_comm.clone(),
                    wakee_pid,
                    wakee_comm.to_string(),
                    timestamp_ns,
                )
            });

            // Update frequency
            stats.wakeup_count += 1;
            stats.last_seen_ns = timestamp_ns;

            // Update latency stats
            stats.record_latency(latency_us);

            // Update CPU affinity
            let same_cpu = wakeup.waker_cpu == wakee_cpu;
            if same_cpu {
                stats.same_cpu_count += 1;
            } else {
                stats.cross_cpu_count += 1;
            }

            *stats
                .cpu_pairs
                .entry((wakeup.waker_cpu, wakee_cpu))
                .or_insert(0) += 1;

            // Update LLC/NUMA affinity if topology available
            if let Some(ref topo) = self.topology {
                if let (Some(waker_cpu_info), Some(wakee_cpu_info)) = (
                    topo.all_cpus.get(&(wakeup.waker_cpu as usize)),
                    topo.all_cpus.get(&(wakee_cpu as usize)),
                ) {
                    if waker_cpu_info.llc_id == wakee_cpu_info.llc_id {
                        stats.same_llc_count += 1;
                    } else {
                        stats.cross_llc_count += 1;
                    }

                    if waker_cpu_info.node_id == wakee_cpu_info.node_id {
                        stats.same_node_count += 1;
                    } else {
                        stats.cross_node_count += 1;
                    }
                }
            }

            // Enforce max relationships limit
            self.enforce_relationship_limit();
        }
    }

    /// Keep only the most active/important relationships
    fn enforce_relationship_limit(&mut self) {
        if self.relationships.len() <= self.max_relationships {
            return;
        }

        // Remove relationships below minimum wakeup count
        self.relationships
            .retain(|_, stats| stats.wakeup_count >= self.min_wakeup_count.into());

        // If still over limit, remove least recent/active
        if self.relationships.len() > self.max_relationships {
            let mut items: Vec<_> = self
                .relationships
                .iter()
                .map(|(k, v)| (*k, v.wakeup_count, v.last_seen_ns))
                .collect();

            // Sort by wakeup count (descending) then recency
            items.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| b.2.cmp(&a.2)));

            // Keep only top N
            let to_keep: HashSet<_> = items
                .iter()
                .take(self.max_relationships)
                .map(|(k, _, _)| *k)
                .collect();

            self.relationships.retain(|k, _| to_keep.contains(k));
        }
    }

    /// Get top N relationships by frequency
    pub fn get_top_by_frequency(&self, limit: usize) -> Vec<RelationshipStats> {
        let mut items: Vec<_> = self.relationships.values().cloned().collect();
        items.sort_by_key(|s| std::cmp::Reverse(s.wakeup_count));
        items.truncate(limit);
        items
    }

    /// Get top N relationships by average latency
    pub fn get_top_by_latency(&self, limit: usize) -> Vec<RelationshipStats> {
        let mut items: Vec<_> = self.relationships.values().cloned().collect();
        items.sort_by_key(|s| std::cmp::Reverse(s.avg_latency_us()));
        items.truncate(limit);
        items
    }

    /// Get relationships by criticality score (frequency * latency)
    pub fn get_critical_relationships(&self, limit: usize) -> Vec<RelationshipStats> {
        let mut items: Vec<_> = self
            .relationships
            .values()
            .map(|s| (s.clone(), s.criticality_score()))
            .collect();
        items.sort_by_key(|(_, score)| std::cmp::Reverse(*score));
        items.truncate(limit);
        items.into_iter().map(|(s, _)| s).collect()
    }

    /// Find bidirectional relationships (A↔B)
    pub fn get_bidirectional_relationships(&self) -> Vec<BidirectionalRelationship> {
        let mut results = Vec::new();

        for ((waker, wakee), stats1) in &self.relationships {
            // Check if reverse relationship exists
            if let Some(stats2) = self.relationships.get(&(*wakee, *waker)) {
                // Only add once (smaller PID first)
                if waker < wakee {
                    let pattern = classify_bidirectional_pattern(stats1, stats2);

                    results.push(BidirectionalRelationship {
                        pid_a: *waker,
                        comm_a: stats1.waker_comm.clone(),
                        pid_b: *wakee,
                        comm_b: stats1.wakee_comm.clone(),
                        a_wakes_b_count: stats1.wakeup_count,
                        a_wakes_b_avg_latency_us: stats1.avg_latency_us(),
                        b_wakes_a_count: stats2.wakeup_count,
                        b_wakes_a_avg_latency_us: stats2.avg_latency_us(),
                        pattern_description: pattern,
                    });
                }
            }
        }

        results
    }

    /// Get all relationships for a specific PID (as waker or wakee)
    pub fn get_relationships_for_pid(&self, pid: u32) -> RelationshipsByPid {
        let as_waker: Vec<_> = self
            .relationships
            .iter()
            .filter(|((waker, _), _)| *waker == pid)
            .map(|(_, stats)| stats.clone())
            .collect();

        let as_wakee: Vec<_> = self
            .relationships
            .iter()
            .filter(|((_, wakee), _)| *wakee == pid)
            .map(|(_, stats)| stats.clone())
            .collect();

        RelationshipsByPid {
            pid,
            as_waker,
            as_wakee,
        }
    }

    /// Get summary statistics
    pub fn get_summary(&self) -> WakerWakeeSummary {
        let total_relationships = self.relationships.len();
        let total_wakeups: u64 = self.relationships.values().map(|s| s.wakeup_count).sum();

        let bidirectional_count = self.get_bidirectional_relationships().len();

        WakerWakeeSummary {
            enabled: self.enabled,
            total_relationships,
            total_wakeups,
            bidirectional_count,
            pending_wakeups: self.pending_wakeups.len(),
        }
    }
}

impl Default for WakerWakeeAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl RelationshipStats {
    fn new(
        waker_pid: u32,
        waker_comm: String,
        wakee_pid: u32,
        wakee_comm: String,
        timestamp_ns: u64,
    ) -> Self {
        Self {
            waker_pid,
            waker_comm,
            wakee_pid,
            wakee_comm,
            wakeup_count: 0,
            first_seen_ns: timestamp_ns,
            last_seen_ns: timestamp_ns,
            latency_samples: Vec::new(),
            min_latency_us: u64::MAX,
            max_latency_us: 0,
            total_latency_us: 0,
            sample_count: 0,
            same_cpu_count: 0,
            cross_cpu_count: 0,
            cpu_pairs: HashMap::new(),
            same_llc_count: 0,
            cross_llc_count: 0,
            same_node_count: 0,
            cross_node_count: 0,
        }
    }

    fn record_latency(&mut self, latency_us: u64) {
        self.total_latency_us += latency_us;
        self.sample_count += 1;
        self.min_latency_us = self.min_latency_us.min(latency_us);
        self.max_latency_us = self.max_latency_us.max(latency_us);

        // Keep limited number of samples for percentile calculation
        self.latency_samples.push(latency_us);
        if self.latency_samples.len() > MAX_LATENCY_SAMPLES {
            self.latency_samples.remove(0);
        }
    }

    pub fn avg_latency_us(&self) -> u64 {
        if self.sample_count > 0 {
            self.total_latency_us / self.sample_count
        } else {
            0
        }
    }

    pub fn criticality_score(&self) -> u64 {
        // Combined metric: frequency * average latency
        self.wakeup_count * self.avg_latency_us()
    }

    pub fn same_cpu_percentage(&self) -> f64 {
        let total = self.same_cpu_count + self.cross_cpu_count;
        if total > 0 {
            (self.same_cpu_count as f64 / total as f64) * 100.0
        } else {
            0.0
        }
    }

    pub fn same_llc_percentage(&self) -> f64 {
        let total = self.same_llc_count + self.cross_llc_count;
        if total > 0 {
            (self.same_llc_count as f64 / total as f64) * 100.0
        } else {
            0.0
        }
    }

    /// Get latency percentiles
    pub fn get_percentiles(&self) -> LatencyPercentiles {
        let mut samples = self.latency_samples.clone();
        samples.sort_unstable();

        let p50 = percentile(&samples, 50);
        let p95 = percentile(&samples, 95);
        let p99 = percentile(&samples, 99);

        LatencyPercentiles { p50, p95, p99 }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct LatencyPercentiles {
    pub p50: u64,
    pub p95: u64,
    pub p99: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct WakerWakeeSummary {
    pub enabled: bool,
    pub total_relationships: usize,
    pub total_wakeups: u64,
    pub bidirectional_count: usize,
    pub pending_wakeups: usize,
}

/// Calculate percentile from sorted samples
fn percentile(sorted_samples: &[u64], p: usize) -> u64 {
    if sorted_samples.is_empty() {
        return 0;
    }
    let index = (sorted_samples.len() * p) / 100;
    sorted_samples[index.min(sorted_samples.len() - 1)]
}

/// Classify bidirectional pattern
fn classify_bidirectional_pattern(
    stats1: &RelationshipStats,
    stats2: &RelationshipStats,
) -> String {
    let ratio = if stats1.wakeup_count > stats2.wakeup_count {
        stats1.wakeup_count as f64 / stats2.wakeup_count as f64
    } else {
        stats2.wakeup_count as f64 / stats1.wakeup_count as f64
    };

    if ratio < 1.2 {
        "Balanced ping-pong (likely mutex/condvar)".to_string()
    } else if ratio < 2.0 {
        "Slightly imbalanced bidirectional wakeups".to_string()
    } else {
        format!("Asymmetric bidirectional ({:.1}:1 ratio)", ratio)
    }
}

/// Helper to extract waker/wakee info from sched_wakeup event
pub fn extract_wakeup_info(json: &Value) -> Option<(u32, u32, String, u32, u64)> {
    let event_type = json.get("type")?.as_str()?;
    if event_type != "sched_wakeup" && event_type != "sched_wakeup_new" {
        return None;
    }

    let wakee_pid = json.get("pid")?.as_u64()? as u32;
    let waker_pid = json.get("waker_pid")?.as_u64()? as u32;
    let waker_comm = json.get("waker_comm")?.as_str()?.to_string();
    let waker_cpu = json.get("cpu")?.as_u64()? as u32;
    let timestamp_ns = json.get("timestamp")?.as_u64()?;

    Some((wakee_pid, waker_pid, waker_comm, waker_cpu, timestamp_ns))
}

/// Helper to extract wakee run info from sched_switch event
pub fn extract_wakee_run_info(json: &Value) -> Option<(u32, String, u32, u64)> {
    let event_type = json.get("type")?.as_str()?;
    if event_type != "sched_switch" {
        return None;
    }

    let wakee_pid = json.get("next_pid")?.as_u64()? as u32;
    let wakee_comm = json.get("next_comm")?.as_str()?.to_string();
    let wakee_cpu = json.get("cpu")?.as_u64()? as u32;
    let timestamp_ns = json.get("timestamp")?.as_u64()?;

    Some((wakee_pid, wakee_comm, wakee_cpu, timestamp_ns))
}
