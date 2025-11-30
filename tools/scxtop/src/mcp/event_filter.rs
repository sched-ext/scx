// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use crate::Action;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Event filter configuration
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EventFilter {
    /// Event types to include (if empty, include all)
    #[serde(default)]
    pub event_types: Vec<String>,

    /// CPU filter
    #[serde(default)]
    pub cpus: Vec<u32>,

    /// Process ID filter
    #[serde(default)]
    pub pids: Vec<u32>,

    /// Thread group ID filter
    #[serde(default)]
    pub tgids: Vec<u32>,

    /// Command name regex filter
    #[serde(default)]
    pub comm_regex: Option<String>,

    /// Minimum latency filter (microseconds)
    #[serde(default)]
    pub min_latency_us: Option<u64>,

    /// Sample rate (0.0-1.0, 1.0 means all events)
    #[serde(default = "default_sample_rate")]
    pub sample_rate: f64,
}

fn default_sample_rate() -> f64 {
    1.0
}

impl Default for EventFilter {
    fn default() -> Self {
        Self {
            event_types: Vec::new(),
            cpus: Vec::new(),
            pids: Vec::new(),
            tgids: Vec::new(),
            comm_regex: None,
            min_latency_us: None,
            sample_rate: 1.0,
        }
    }
}

impl EventFilter {
    /// Check if an action matches the filter
    pub fn matches(&self, action: &Action, json: &Value) -> bool {
        // Check event type
        if !self.event_types.is_empty() {
            let event_type = json.get("type").and_then(|v| v.as_str()).unwrap_or("");
            if !self.event_types.iter().any(|t| t == event_type) {
                return false;
            }
        }

        // Check CPU
        if !self.cpus.is_empty() {
            let cpu = json.get("cpu").and_then(|v| v.as_u64()).map(|v| v as u32);
            if cpu.is_none() || !self.cpus.contains(&cpu.unwrap()) {
                return false;
            }
        }

        // Check PID
        if !self.pids.is_empty() {
            let pid = self.extract_pid(json);
            if pid.is_none() || !self.pids.contains(&pid.unwrap()) {
                return false;
            }
        }

        // Check TGID
        if !self.tgids.is_empty() {
            let tgid = self.extract_tgid(json);
            if tgid.is_none() || !self.tgids.contains(&tgid.unwrap()) {
                return false;
            }
        }

        // Check comm regex
        if let Some(ref pattern) = self.comm_regex {
            if let Ok(regex) = Regex::new(pattern) {
                let comm = self.extract_comm(json);
                if !regex.is_match(&comm) {
                    return false;
                }
            }
        }

        // Check minimum latency
        if let Some(min_lat) = self.min_latency_us {
            let latency = self.extract_latency_us(json);
            if latency.is_none() || latency.unwrap() < min_lat {
                return false;
            }
        }

        // Check sample rate
        if self.sample_rate < 1.0 {
            use std::collections::hash_map::DefaultHasher;
            use std::hash::{Hash, Hasher};

            let mut hasher = DefaultHasher::new();
            format!("{:?}", action).hash(&mut hasher);
            let hash = hasher.finish();
            let sample = (hash as f64 / u64::MAX as f64) <= self.sample_rate;
            if !sample {
                return false;
            }
        }

        true
    }

    fn extract_pid(&self, json: &Value) -> Option<u32> {
        json.get("pid")
            .and_then(|v| v.as_u64())
            .map(|v| v as u32)
            .or_else(|| {
                json.get("next_pid")
                    .and_then(|v| v.as_u64())
                    .map(|v| v as u32)
            })
            .or_else(|| {
                json.get("prev_pid")
                    .and_then(|v| v.as_u64())
                    .map(|v| v as u32)
            })
    }

    fn extract_tgid(&self, json: &Value) -> Option<u32> {
        json.get("tgid")
            .and_then(|v| v.as_u64())
            .map(|v| v as u32)
            .or_else(|| {
                json.get("next_tgid")
                    .and_then(|v| v.as_u64())
                    .map(|v| v as u32)
            })
    }

    fn extract_comm(&self, json: &Value) -> String {
        json.get("comm")
            .and_then(|v| v.as_str())
            .or_else(|| json.get("next_comm").and_then(|v| v.as_str()))
            .or_else(|| json.get("prev_comm").and_then(|v| v.as_str()))
            .unwrap_or("")
            .to_string()
    }

    fn extract_latency_us(&self, json: &Value) -> Option<u64> {
        json.get("next_dsq_lat_us")
            .and_then(|v| v.as_u64())
            .or_else(|| json.get("latency_us").and_then(|v| v.as_u64()))
    }

    /// Validate the filter
    pub fn validate(&self) -> Result<(), String> {
        if self.sample_rate < 0.0 || self.sample_rate > 1.0 {
            return Err("sample_rate must be between 0.0 and 1.0".to_string());
        }

        if let Some(ref pattern) = self.comm_regex {
            Regex::new(pattern).map_err(|e| format!("Invalid regex: {}", e))?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_cpu_filter() {
        let filter = EventFilter {
            cpus: vec![0, 1],
            ..Default::default()
        };

        let json1 = json!({"type": "sched_switch", "cpu": 0});
        let json2 = json!({"type": "sched_switch", "cpu": 2});

        assert!(filter.matches(&crate::Action::None, &json1));
        assert!(!filter.matches(&crate::Action::None, &json2));
    }

    #[test]
    fn test_event_type_filter() {
        let filter = EventFilter {
            event_types: vec!["sched_switch".to_string()],
            ..Default::default()
        };

        let json1 = json!({"type": "sched_switch", "cpu": 0});
        let json2 = json!({"type": "sched_wakeup", "cpu": 0});

        assert!(filter.matches(&crate::Action::None, &json1));
        assert!(!filter.matches(&crate::Action::None, &json2));
    }

    #[test]
    fn test_sample_rate() {
        let filter = EventFilter {
            sample_rate: 0.0, // Should reject all
            ..Default::default()
        };

        let json = json!({"type": "sched_switch", "cpu": 0});
        // With 0.0 sample rate, should always be false
        assert!(!filter.matches(&crate::Action::None, &json));
    }
}
