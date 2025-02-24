// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use crate::EventData;
use crate::PerfEvent;

use std::collections::VecDeque;

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
            data.event_data(&event.event);
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
    pub fn initialize_events(&mut self, events: &[&str]) {
        self.data.initialize_events(events);
    }

    /// Returns the data for an event and updates if no entry is present.
    pub fn event_data(&mut self, event: &str) -> &VecDeque<u64> {
        self.data.event_data(event)
    }

    /// Returns the data for an event and updates if no entry is present.
    pub fn event_data_immut(&self, event: &str) -> Vec<u64> {
        self.data.event_data_immut(event)
    }

    /// Adds data for an event.
    pub fn add_event_data(&mut self, event: &str, val: u64) {
        self.data.add_event_data(event, val)
    }
}
