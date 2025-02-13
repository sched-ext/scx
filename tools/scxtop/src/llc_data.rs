// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use crate::EventData;
use crate::PerfEvent;

/// Container for per LLC data.
#[derive(Clone, Debug)]
pub struct LlcData {
    pub node: usize,
    pub llc: usize,
    pub data: EventData,
    pub max_data_size: usize,
}

impl LlcData {
    /// Creates a new NodeData.
    pub fn new(llc: usize, node: usize, max_data_size: usize) -> LlcData {
        let mut data = EventData::new(max_data_size);
        for event in PerfEvent::default_events() {
            data.event_data(event.event.clone());
        }

        Self {
            llc,
            node,
            data,
            max_data_size,
        }
    }

    /// Initializes events with default values.
    pub fn initialize_events(&mut self, events: &Vec<String>) {
        self.data.initialize_events(events);
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
        self.data.add_event_data(event, val);
    }

    /// Adds data for a cpu by updating the first value.
    pub fn add_cpu_event_data(&mut self, event: String, val: u64) {
        let size = self.max_data_size - 1;
        self.data
            .data
            .entry(event.clone())
            .and_modify(|x| {
                let len = x.len();
                x[len - 1] += val
            })
            .or_insert(vec![0, size.try_into().unwrap()]);
    }
}
