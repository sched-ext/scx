// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

pub mod cpu_util;
pub mod kprobe;
pub mod perf;

use std::sync::{Arc, RwLock};

pub use cpu_util::CpuUtilEvent;
pub use kprobe::{available_kprobe_events, KprobeEvent};
pub use perf::{available_perf_events, PerfEvent};

use crate::profiling_events::cpu_util::CpuUtilMetric;
use crate::CpuStatTracker;

#[derive(Clone, Debug)]
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

    pub fn start(&self, cpu: usize, process: i32) -> ProfilingEvent {
        match self {
            ProfilingEvent::Perf(p) => {
                let mut p = p.clone();
                p.cpu = cpu;
                p.attach(process)
                    .expect("Failed to attach perf event to process");
                ProfilingEvent::Perf(p)
            }
            ProfilingEvent::Kprobe(k) => {
                let mut k = k.clone();
                k.cpu = cpu;
                ProfilingEvent::Kprobe(k)
            }
            ProfilingEvent::CpuUtil(c) => {
                let mut c = c.clone();
                c.cpu = cpu;
                ProfilingEvent::CpuUtil(c)
            }
        }
    }

    pub fn value(&mut self, reset: bool) -> anyhow::Result<u64> {
        match self {
            ProfilingEvent::CpuUtil(c) => c.value(),
            ProfilingEvent::Perf(p) => p.value(reset),
            ProfilingEvent::Kprobe(k) => k.value(reset),
        }
    }

    pub fn from_str(s: &str, tracker: Arc<RwLock<CpuStatTracker>>) -> anyhow::Result<Self> {
        let (source, event) = s.split_once(':').expect("Invalid profiling event");
        match source {
            "cpu" => Ok(ProfilingEvent::CpuUtil(CpuUtilEvent::new(
                0,
                CpuUtilMetric::from_str(event)?,
                tracker,
            ))),
            "perf" => Ok(ProfilingEvent::Perf(PerfEvent::from_str(event)?)),
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
            ProfilingEvent::from_str("cpu:cpu_total_util_percent", tracker.clone()).unwrap();

        let expected = ProfilingEvent::CpuUtil(CpuUtilEvent::new(
            0,
            CpuUtilMetric::from_str("cpu_total_util_percent").unwrap(),
            tracker,
        ));

        assert_eq!(result, expected);
    }

    #[test]
    fn test_perf_event_parsing() {
        let tracker = dummy_tracker();
        let result = ProfilingEvent::from_str("perf:hw:cycles", tracker).unwrap();

        let expected = ProfilingEvent::Perf(PerfEvent::from_str("hw:cycles").unwrap());

        assert_eq!(result, expected);
    }

    #[test]
    fn test_kprobe_event_parsing() {
        let tracker = dummy_tracker();
        let result = ProfilingEvent::from_str("kprobe:vfs_read", tracker).unwrap();

        let expected = ProfilingEvent::Kprobe(KprobeEvent::new("vfs_read", 0).unwrap());

        assert_eq!(result, expected);
    }

    #[test]
    fn test_invalid_format_missing_colon() {
        let tracker = dummy_tracker();
        let err = ProfilingEvent::from_str("invalid_format", tracker);
        assert!(err.is_err(),);
    }

    #[test]
    fn test_invalid_source_type() {
        let tracker = dummy_tracker();
        let err = ProfilingEvent::from_str("foo:bar", tracker);
        assert!(err.is_err(),);
    }

    #[test]
    fn test_invalid_cpu_metric() {
        let tracker = dummy_tracker();
        let result = ProfilingEvent::from_str("cpu:not_a_real_metric", tracker);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_perf_event() {
        let tracker = dummy_tracker();
        let result = ProfilingEvent::from_str("perf:", tracker);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_kprobe_event() {
        let tracker = dummy_tracker();
        let result = ProfilingEvent::from_str("kprobe:", tracker);
        assert!(result.is_err());
    }
}
