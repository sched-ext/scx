// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

pub mod cpu_util;
pub mod kprobe;
pub mod perf;

use anyhow::Result;
use std::str::FromStr;
use std::sync::{Arc, RwLock};

pub use cpu_util::CpuUtilEvent;
pub use kprobe::{available_kprobe_events, KprobeEvent};
pub use perf::{available_perf_events, PerfEvent};

use crate::profiling_events::cpu_util::CpuUtilMetric;
use crate::CpuStatTracker;

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ProfilingEvent {
    CpuUtil(CpuUtilEvent),
    Perf(PerfEvent),
    Kprobe(KprobeEvent),
}

impl ProfilingEvent {
    pub fn event_name(&self) -> &str {
        match self {
            ProfilingEvent::CpuUtil(c) => c.event_name(),
            ProfilingEvent::Perf(p) => p.event_name(),
            ProfilingEvent::Kprobe(k) => &k.event_name,
        }
    }

    pub fn initialize_for_cpu(&self, cpu: usize, process: i32) -> Result<ProfilingEvent> {
        match self {
            ProfilingEvent::Perf(p) => {
                let mut p = p.clone();
                p.cpu = cpu;
                p.attach(process)?;
                Ok(ProfilingEvent::Perf(p))
            }
            ProfilingEvent::Kprobe(k) => {
                let mut k = k.clone();
                k.cpu = cpu;
                Ok(ProfilingEvent::Kprobe(k))
            }
            ProfilingEvent::CpuUtil(c) => {
                let mut c = c.clone();
                c.cpu = cpu;
                Ok(ProfilingEvent::CpuUtil(c))
            }
        }
    }

    pub fn value(&mut self, reset: bool) -> Result<u64> {
        match self {
            ProfilingEvent::CpuUtil(c) => c.value(),
            ProfilingEvent::Perf(p) => p.value(reset),
            ProfilingEvent::Kprobe(k) => k.value(reset),
        }
    }

    pub fn from_str_args(s: &str, tracker: Option<Arc<RwLock<CpuStatTracker>>>) -> Result<Self> {
        let (source, event) = s
            .split_once(':')
            .ok_or(anyhow::anyhow!("Invalid profiling event: {}", s))?;
        match source {
            "cpu" => Ok(ProfilingEvent::CpuUtil(CpuUtilEvent::new(
                0,
                CpuUtilMetric::from_str(event)?,
                tracker.expect("CpuStatTracker not provided"),
            ))),
            "perf" => Ok(ProfilingEvent::Perf(PerfEvent::from_str_args(event, 0)?)),
            "kprobe" => Ok(ProfilingEvent::Kprobe(KprobeEvent::new(
                event.to_string(),
                0,
            ))),
            _ => Err(anyhow::anyhow!("Invalid profiling event: {}", s)),
        }
    }
}

pub fn get_default_events(tracker: Arc<RwLock<CpuStatTracker>>) -> Vec<ProfilingEvent> {
    let default_perf_events = PerfEvent::default_events()
        .into_iter()
        .map(ProfilingEvent::Perf);

    let default_cpu_util_events = CpuUtilEvent::default_events(tracker)
        .into_iter()
        .map(ProfilingEvent::CpuUtil);

    default_perf_events
        .chain(default_cpu_util_events)
        .collect::<Vec<ProfilingEvent>>()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_tracker() -> Arc<RwLock<CpuStatTracker>> {
        Arc::new(RwLock::new(CpuStatTracker::default()))
    }

    #[test]
    fn test_cpu_event_parsing() {
        let tracker = dummy_tracker();
        let result =
            ProfilingEvent::from_str_args("cpu:cpu_total_util_percent", Some(tracker.clone()))
                .unwrap();

        let expected = ProfilingEvent::CpuUtil(CpuUtilEvent::new(0, CpuUtilMetric::Total, tracker));

        assert_eq!(result, expected);
    }

    #[test]
    fn test_perf_event_parsing() {
        let result = ProfilingEvent::from_str_args("perf:hw:cycles", None).unwrap();

        let expected =
            ProfilingEvent::Perf(PerfEvent::new("hw".to_string(), "cycles".to_string(), 0));

        assert_eq!(result, expected);
    }

    #[test]
    fn test_kprobe_event_parsing() {
        let result = ProfilingEvent::from_str_args("kprobe:vfs_read", None).unwrap();

        let expected = ProfilingEvent::Kprobe(KprobeEvent::new("vfs_read".to_string(), 0));

        assert_eq!(result, expected);
    }

    #[test]
    fn test_invalid_format_missing_colon() {
        let tracker = dummy_tracker();
        let err = ProfilingEvent::from_str_args("invalid_format", None);
        assert!(err.is_err());

        let err = ProfilingEvent::from_str_args("invalid_format", Some(tracker));
        assert!(err.is_err());
    }

    #[test]
    fn test_invalid_source_type() {
        let tracker = dummy_tracker();
        let err = ProfilingEvent::from_str_args("foo:bar", None);
        assert!(err.is_err());

        let err = ProfilingEvent::from_str_args("foo:bar", Some(tracker));
        assert!(err.is_err());
    }

    #[test]
    fn test_invalid_cpu_metric() {
        let tracker = dummy_tracker();
        let result = ProfilingEvent::from_str_args("cpu:not_a_real_metric", Some(tracker));
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_perf_event() {
        let result = ProfilingEvent::from_str_args("perf:", None);
        assert!(result.is_err());
    }
}
