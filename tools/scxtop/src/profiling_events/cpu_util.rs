// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use crate::CpuStatTracker;
use anyhow::Result;
use std::sync::{Arc, RwLock};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CpuUtilMetric {
    Total,
    User,
    System,
}

impl CpuUtilMetric {
    pub fn as_str(&self) -> &'static str {
        match self {
            CpuUtilMetric::Total => "cpu_util_percent",
            CpuUtilMetric::User => "cpu_user_util_percent",
            CpuUtilMetric::System => "cpu_system_util_percent",
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
        ]
    }

    pub fn event_name(&self) -> &str {
        self.metric.as_str()
    }

    pub fn value(&self) -> Result<u64> {
        let tracker = self.tracker.read().unwrap();
        let prev = tracker.prev.get(&self.cpu).unwrap();
        let current = tracker.current.get(&self.cpu).unwrap();
        let total = current.total() - prev.total();
        if total == 0 {
            return Ok(0);
        }

        let value = match self.metric {
            CpuUtilMetric::Total => current.active() - prev.active(),
            CpuUtilMetric::User => current.user - prev.user,
            CpuUtilMetric::System => current.system - prev.system,
        };

        Ok((value * 100) / total)
    }
}
