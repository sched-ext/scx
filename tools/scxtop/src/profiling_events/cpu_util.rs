// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use crate::CpuStatTracker;
use anyhow::{bail, Result};
use std::sync::{Arc, RwLock};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CpuUtilMetric {
    Total,
    User,
    System,
    Frequency,
}

impl CpuUtilMetric {
    pub fn as_str(&self) -> &'static str {
        match self {
            CpuUtilMetric::Total => "cpu_total_util_percent",
            CpuUtilMetric::User => "cpu_user_util_percent",
            CpuUtilMetric::System => "cpu_system_util_percent",
            CpuUtilMetric::Frequency => "cpu_frequency",
        }
    }
}

#[derive(Debug, Clone)]
pub struct CpuUtilEvent {
    pub cpu: usize,
    pub metric: CpuUtilMetric,
    pub tracker: Arc<RwLock<CpuStatTracker>>,
}

impl CpuUtilEvent {
    pub fn new(cpu: usize, metric: CpuUtilMetric, tracker: Arc<RwLock<CpuStatTracker>>) -> Self {
        Self {
            cpu,
            metric,
            tracker: tracker.clone(),
        }
    }

    /// Returns the set of default cpu metric events.
    pub fn default_events(tracker: Arc<RwLock<CpuStatTracker>>) -> Vec<CpuUtilEvent> {
        vec![
            CpuUtilEvent::new(0, CpuUtilMetric::Total, tracker.clone()),
            CpuUtilEvent::new(0, CpuUtilMetric::User, tracker.clone()),
            CpuUtilEvent::new(0, CpuUtilMetric::System, tracker.clone()),
            CpuUtilEvent::new(0, CpuUtilMetric::Frequency, tracker.clone()),
        ]
    }

    pub fn event_name(&self) -> &str {
        self.metric.as_str()
    }

    pub fn value(&self) -> Result<u64> {
        let tracker = self.tracker.read().unwrap();
        let prev = tracker.prev.get(&self.cpu).unwrap();
        let current = tracker.current.get(&self.cpu).unwrap();

        if self.metric == CpuUtilMetric::Frequency {
            return Ok(current.freq);
        }

        let total = current.cpu_util_data.total_util() - prev.cpu_util_data.total_util();
        if total == 0 {
            return Ok(0);
        }

        let value = match self.metric {
            CpuUtilMetric::Total => {
                current.cpu_util_data.active_util() - prev.cpu_util_data.active_util()
            }
            CpuUtilMetric::User => current.cpu_util_data.user - prev.cpu_util_data.user,
            CpuUtilMetric::System => current.cpu_util_data.system - prev.cpu_util_data.system,
            CpuUtilMetric::Frequency => bail!("CpuUtilFrequency should have returned early"),
        };

        Ok((value * 100) / total)
    }
}

#[cfg(test)]
mod tests {
    use crate::cpu_stats::CpuStatSnapshot;
    use crate::cpu_stats::CpuUtilData;

    use super::*;
    use std::sync::{Arc, RwLock};

    fn create_snapshot(user: u64, system: u64, idle: u64, freq: u64) -> CpuStatSnapshot {
        CpuStatSnapshot {
            cpu_util_data: CpuUtilData {
                user,
                nice: 0,
                system,
                idle,
                iowait: 0,
                irq: 0,
                softirq: 0,
                steal: 0,
                guest: 0,
                guest_nice: 0,
            },
            freq,
        }
    }

    #[test]
    fn test_cpu_util_event_total_full() {
        let mut tracker = CpuStatTracker::default();

        tracker.prev.insert(0, create_snapshot(15, 5, 50, 0));
        tracker.current.insert(0, create_snapshot(30, 10, 50, 0));

        let tracker = Arc::new(RwLock::new(tracker));
        let event = CpuUtilEvent::new(0, CpuUtilMetric::Total, tracker);

        assert_eq!(event.value().unwrap(), 100);
    }

    #[test]
    fn test_cpu_util_event_total_partial() {
        let mut tracker = CpuStatTracker::default();

        tracker.prev.insert(0, create_snapshot(15, 5, 50, 0));
        tracker.current.insert(0, create_snapshot(30, 10, 70, 0));

        let tracker = Arc::new(RwLock::new(tracker));
        let event = CpuUtilEvent::new(0, CpuUtilMetric::Total, tracker);

        assert_eq!(event.value().unwrap(), 50);
    }

    #[test]
    fn test_cpu_util_event_user() {
        let mut tracker = CpuStatTracker::default();

        tracker.prev.insert(0, create_snapshot(10, 5, 100, 0));
        tracker.current.insert(0, create_snapshot(90, 45, 140, 0));

        let tracker = Arc::new(RwLock::new(tracker));
        let event = CpuUtilEvent::new(0, CpuUtilMetric::User, tracker);

        assert_eq!(event.value().unwrap(), 50);
    }

    #[test]
    fn test_cpu_util_event_system() {
        let mut tracker = CpuStatTracker::default();

        tracker.prev.insert(0, create_snapshot(10, 5, 100, 0));
        tracker.current.insert(0, create_snapshot(20, 25, 150, 0));

        let tracker = Arc::new(RwLock::new(tracker));
        let event = CpuUtilEvent::new(0, CpuUtilMetric::System, tracker);

        assert_eq!(event.value().unwrap(), 25);
    }

    #[test]
    fn test_cpu_util_zero_total() {
        let mut tracker = CpuStatTracker::default();

        tracker.prev.insert(0, create_snapshot(100, 50, 850, 0));
        tracker.current.insert(0, create_snapshot(100, 50, 850, 0));

        let tracker = Arc::new(RwLock::new(tracker));
        let event = CpuUtilEvent::new(0, CpuUtilMetric::Total, tracker);

        assert_eq!(event.value().unwrap(), 0);
    }

    #[test]
    fn test_cpu_frequency_basic() {
        let mut tracker = CpuStatTracker::default();

        tracker.prev.insert(0, create_snapshot(100, 50, 850, 50));
        tracker.current.insert(0, create_snapshot(100, 50, 850, 75));

        let tracker = Arc::new(RwLock::new(tracker));
        let event = CpuUtilEvent::new(0, CpuUtilMetric::Frequency, tracker);
        println!("{:?}", event);
        println!("{:?}", event.value());

        assert_eq!(event.value().unwrap(), 75);
    }
}
