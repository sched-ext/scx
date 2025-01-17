// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use crate::EventData;
use crate::PerfEvent;

/// Container for per CPU data.
#[derive(Clone, Debug)]
pub struct CpuData {
    pub llc: usize,
    pub node: usize,
    pub core: usize,
    pub cpu: usize,
    pub data: EventData,
    pub max_data_size: usize,
}

impl CpuData {
    /// Creates a new CpuData.
    pub fn new(cpu: usize, core: usize, llc: usize, node: usize, max_data_size: usize) -> CpuData {
        let mut data = EventData::new(max_data_size);
        for event in PerfEvent::default_events() {
            data.event_data(event.event.clone());
        }
        Self {
            llc,
            node,
            core,
            cpu,
            data,
            max_data_size,
        }
    }

    /// Initializes events with default values.
    pub fn initialize_events(&mut self, events: &Vec<String>) {
        for event in events {
            self.data.event_data(event.to_string());
        }
    }

    /// Returns the data for an event and updates if no entry is present.
    pub fn event_data(&mut self, event: String) -> &Vec<u64> {
        self.data.event_data(event)
    }

    /// Returns the data for an event and updates if no entry is present.
    pub fn event_data_immut(&self, event: String) -> Vec<u64> {
        self.data.event_data_immut(event)
    }

    /// Adds data for an event.
    pub fn add_event_data(&mut self, event: String, val: u64) {
        self.data.add_event_data(event, val)
    }
}
