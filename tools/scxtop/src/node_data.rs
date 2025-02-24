// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use crate::EventData;
use crate::PerfEvent;

use std::collections::VecDeque;

/// Container for per NUMA node data.
#[derive(Clone, Debug)]
pub struct NodeData {
    pub node: usize,
    pub data: EventData,
    pub max_data_size: usize,
}

impl NodeData {
    /// Creates a new NodeData.
    pub fn new(node: usize, max_data_size: usize) -> NodeData {
        let mut data = EventData::new(max_data_size);
        for event in PerfEvent::default_events() {
            data.event_data(&event.event);
        }
        Self {
            node,
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

    /// Adds data for a cpu by updating the first value.
    pub fn add_cpu_event_data(&mut self, event: &str, val: u64) {
        let data = self.data.event_data_mut(event);
        let len = data.len();
        data[len - 1] += val;
    }
}
