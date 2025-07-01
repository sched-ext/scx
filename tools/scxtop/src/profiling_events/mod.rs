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

    pub fn value(&mut self, reset: bool) -> anyhow::Result<u64> {
        match self {
            ProfilingEvent::CpuUtil(c) => c.value(),
            ProfilingEvent::Perf(p) => p.value(reset),
            ProfilingEvent::Kprobe(k) => k.value(reset),
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
