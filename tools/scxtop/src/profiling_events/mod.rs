// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

pub mod kprobe;
pub mod perf;

pub use kprobe::{available_kprobe_events, KprobeEvent};
pub use perf::{available_perf_events, PerfEvent};

#[derive(Clone, Debug)]
pub enum ProfilingEvent {
    Perf(PerfEvent),
    Kprobe(KprobeEvent),
}

impl ProfilingEvent {
    pub fn event_name(&self) -> &str {
        match self {
            ProfilingEvent::Perf(p) => p.event_name(),
            ProfilingEvent::Kprobe(k) => &k.event_name,
        }
    }

    pub fn value(&mut self, reset: bool) -> anyhow::Result<u64> {
        match self {
            ProfilingEvent::Perf(p) => p.value(reset),
            ProfilingEvent::Kprobe(k) => k.value(reset),
        }
    }
}
