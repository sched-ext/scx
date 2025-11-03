// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;

/// Aggregation configuration
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AggregationConfig {
    pub event_type: String,
    pub time_window_ms: u64,
    pub group_by: Vec<String>, // e.g., ["cpu", "prev_comm"]
    pub metrics: Vec<String>,  // e.g., ["count", "avg_slice_ns", "p50_latency"]
    pub top_n: Option<usize>,
}

/// Aggregated statistics for a group
#[derive(Clone, Debug, Serialize)]
pub struct AggregatedStats {
    pub group_key: HashMap<String, Value>,
    pub count: u64,
    pub metrics: HashMap<String, f64>,
}

/// Event aggregator
pub struct EventAggregator {
    config: AggregationConfig,
    window_start: u64,
    window_end: u64,
    groups: HashMap<String, GroupStats>,
}

impl EventAggregator {
    pub fn new(config: AggregationConfig, start_ts: u64) -> Self {
        let window_end = start_ts + config.time_window_ms * 1_000_000; // Convert to nanoseconds
        Self {
            config,
            window_start: start_ts,
            window_end,
            groups: HashMap::new(),
        }
    }

    /// Add an event to the aggregation
    pub fn add_event(&mut self, json: &Value, timestamp: u64) -> bool {
        // Check if event is in window
        if timestamp < self.window_start || timestamp > self.window_end {
            return false;
        }

        // Check event type
        if let Some(event_type) = json.get("type").and_then(|v| v.as_str()) {
            if event_type != self.config.event_type {
                return false;
            }
        } else {
            return false;
        }

        // Extract group key
        let group_key = self.extract_group_key(json);
        let group_key_str = format!("{:?}", group_key);

        // Get or create group stats
        let group_stats = self
            .groups
            .entry(group_key_str)
            .or_insert_with(|| GroupStats::new(group_key));

        // Update statistics
        group_stats.count += 1;

        // Update metric values
        let metrics = self.config.metrics.clone();
        for metric in &metrics {
            Self::update_metric_static(group_stats, json, metric);
        }

        true
    }

    fn extract_group_key(&self, json: &Value) -> HashMap<String, Value> {
        let mut key = HashMap::new();
        for field in &self.config.group_by {
            if let Some(value) = json.get(field) {
                key.insert(field.clone(), value.clone());
            }
        }
        key
    }

    fn update_metric_static(stats: &mut GroupStats, json: &Value, metric: &str) {
        match metric {
            "count" => {
                // Already tracked
            }
            "avg_slice_ns" => {
                if let Some(slice) = json.get("prev_slice_ns").and_then(|v| v.as_u64()) {
                    stats.sum_slice_ns += slice;
                }
            }
            "avg_used_slice_ns" => {
                if let Some(used) = json.get("prev_used_slice_ns").and_then(|v| v.as_u64()) {
                    stats.sum_used_slice_ns += used;
                }
            }
            "avg_latency_us" | "p50_latency" | "p99_latency" => {
                if let Some(lat) = json.get("next_dsq_lat_us").and_then(|v| v.as_u64()) {
                    stats.latencies.push(lat);
                }
            }
            "avg_queue_depth" => {
                if let Some(depth) = json.get("next_dsq_nr_queued").and_then(|v| v.as_u64()) {
                    stats.sum_queue_depth += depth;
                }
            }
            _ => {
                // Unknown metric, try to extract numeric value directly
                if let Some(val) = json.get(metric).and_then(|v| v.as_f64()) {
                    stats
                        .custom_metrics
                        .entry(metric.to_string())
                        .or_default()
                        .push(val);
                }
            }
        }
    }

    /// Compute final aggregated results
    pub fn compute_results(&self) -> Vec<AggregatedStats> {
        let mut results: Vec<AggregatedStats> = self
            .groups
            .values()
            .map(|stats| {
                let mut metrics = HashMap::new();

                // Compute requested metrics
                for metric in &self.config.metrics {
                    let value = match metric.as_str() {
                        "count" => stats.count as f64,
                        "avg_slice_ns" => {
                            if stats.count > 0 {
                                stats.sum_slice_ns as f64 / stats.count as f64
                            } else {
                                0.0
                            }
                        }
                        "avg_used_slice_ns" => {
                            if stats.count > 0 {
                                stats.sum_used_slice_ns as f64 / stats.count as f64
                            } else {
                                0.0
                            }
                        }
                        "avg_latency_us" => {
                            if !stats.latencies.is_empty() {
                                stats.latencies.iter().sum::<u64>() as f64
                                    / stats.latencies.len() as f64
                            } else {
                                0.0
                            }
                        }
                        "p50_latency" => percentile(&stats.latencies, 50.0),
                        "p95_latency" => percentile(&stats.latencies, 95.0),
                        "p99_latency" => percentile(&stats.latencies, 99.0),
                        "max_latency" => stats.latencies.iter().max().copied().unwrap_or(0) as f64,
                        "avg_queue_depth" => {
                            if stats.count > 0 {
                                stats.sum_queue_depth as f64 / stats.count as f64
                            } else {
                                0.0
                            }
                        }
                        _ => {
                            // Check custom metrics
                            if let Some(values) = stats.custom_metrics.get(metric) {
                                if !values.is_empty() {
                                    values.iter().sum::<f64>() / values.len() as f64
                                } else {
                                    0.0
                                }
                            } else {
                                0.0
                            }
                        }
                    };
                    metrics.insert(metric.clone(), value);
                }

                AggregatedStats {
                    group_key: stats.group_key.clone(),
                    count: stats.count,
                    metrics,
                }
            })
            .collect();

        // Sort by count descending
        results.sort_by(|a, b| b.count.cmp(&a.count));

        // Apply top_n limit
        if let Some(n) = self.config.top_n {
            results.truncate(n);
        }

        results
    }

    pub fn window_info(&self) -> (u64, u64, u64) {
        (self.window_start, self.window_end, self.groups.len() as u64)
    }
}

/// Statistics for a single group
#[derive(Clone, Debug)]
struct GroupStats {
    group_key: HashMap<String, Value>,
    count: u64,
    sum_slice_ns: u64,
    sum_used_slice_ns: u64,
    sum_queue_depth: u64,
    latencies: Vec<u64>,
    custom_metrics: HashMap<String, Vec<f64>>,
}

impl GroupStats {
    fn new(group_key: HashMap<String, Value>) -> Self {
        Self {
            group_key,
            count: 0,
            sum_slice_ns: 0,
            sum_used_slice_ns: 0,
            sum_queue_depth: 0,
            latencies: Vec::new(),
            custom_metrics: HashMap::new(),
        }
    }
}

/// Calculate percentile from sorted or unsorted data
fn percentile(values: &[u64], p: f64) -> f64 {
    if values.is_empty() {
        return 0.0;
    }

    let mut sorted = values.to_vec();
    sorted.sort_unstable();

    // Use floor to get the lower bound index for the percentile
    let idx = (p / 100.0 * (sorted.len() - 1) as f64).floor() as usize;
    sorted[idx] as f64
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_aggregation() {
        let config = AggregationConfig {
            event_type: "sched_switch".to_string(),
            time_window_ms: 1000,
            group_by: vec!["cpu".to_string()],
            metrics: vec!["count".to_string()],
            top_n: None,
        };

        let mut aggregator = EventAggregator::new(config, 1_000_000_000);

        // Add events
        let event1 = json!({"type": "sched_switch", "cpu": 0, "ts": 1_000_000_000});
        let event2 = json!({"type": "sched_switch", "cpu": 0, "ts": 1_000_000_100});
        let event3 = json!({"type": "sched_switch", "cpu": 1, "ts": 1_000_000_200});

        aggregator.add_event(&event1, 1_000_000_000);
        aggregator.add_event(&event2, 1_000_000_100);
        aggregator.add_event(&event3, 1_000_000_200);

        let results = aggregator.compute_results();
        assert_eq!(results.len(), 2); // Two CPUs
    }

    #[test]
    fn test_percentile() {
        let values = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        assert_eq!(percentile(&values, 50.0), 5.0);
        assert_eq!(percentile(&values, 90.0), 9.0);
    }
}
