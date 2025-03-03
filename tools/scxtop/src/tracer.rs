// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use crate::bpf_skel::BpfSkel;
use crate::bpf_stats::BpfStats;

use anyhow::Result;
use libbpf_rs::Link;
use log::debug;

pub struct Tracer<'a> {
    pub skel: BpfSkel<'a>,
    trace_links: Vec<Link>,
}

impl<'a> Tracer<'a> {
    /// Creates a new appliation.
    pub fn new(skel: BpfSkel<'a>) -> Self {
        let trace_links = vec![];
        Self { skel, trace_links }
    }

    /// Returns the BPF stats for the tracer.
    pub fn stats(&self) -> Result<BpfStats> {
        BpfStats::get_from_skel(&self.skel)
    }

    /// Attaches any BPF programs required for perfetto traces.
    fn attach_trace_progs(&mut self) -> Result<()> {
        self.trace_links = vec![
            self.skel.progs.on_softirq_entry.attach()?,
            self.skel.progs.on_softirq_exit.attach()?,
            self.skel.progs.on_ipi_send_cpu.attach()?,
        ];

        Ok(())
    }

    /// Starts the collection of a trace, does not stop the trace.
    pub async fn trace_async(&mut self, dur: std::time::Duration) -> Result<()> {
        self.skel.maps.data_data.sample_rate = 1;
        self.skel.maps.data_data.enable_bpf_events = true;
        self.attach_trace_progs()?;
        debug!(
            "attached {} trace progs, sample_rate: {}",
            self.trace_links.len(),
            self.skel.maps.data_data.sample_rate
        );
        tokio::time::sleep(dur).await;
        self.trace_links.clear();
        Ok(())
    }
}
