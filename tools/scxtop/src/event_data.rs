// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use std::collections::BTreeMap;

/// Container for event data.
#[derive(Clone, Debug)]
pub struct EventData {
    pub data: BTreeMap<String, Vec<u64>>,
    pub max_data_size: usize,
}

impl EventData {
    /// Creates a new EventData.
    pub fn new(max_data_size: usize) -> EventData {
        Self {
            data: BTreeMap::new(),
            max_data_size: max_data_size,
        }
    }

    /// Initializes events with default values.
    pub fn initialize_events(&mut self, events: &Vec<String>) {
        for event in events {
            self.event_data(event.to_string());
        }
    }

    /// Returns the data for an event and updates if no entry is present.
    pub fn event_data(&mut self, event: String) -> &Vec<u64> {
        self.data.entry(event).or_insert(vec![
            0,
            self.max_data_size
                .try_into()
                .expect("invalid max data size"),
        ])
    }

    /// Zeros out values for an event.
    pub fn zero_event(&mut self, event: String) {
        for ref mut val in self.event_data(event) {
            *val = &0;
        }
    }

    /// Clears an event.
    pub fn clear_event(&mut self, event: String) {
        self.data.remove(&event);
    }

    /// Clears out all values
    pub fn clear(&mut self) {
        self.data.clear();
    }

    /// Returns the data for an event and updates if no entry is present.
    pub fn event_data_immut(&self, event: String) -> Vec<u64> {
        if self.data.contains_key(&event.clone()) {
            self.data
                .get(&event.clone())
                .expect("failed to get vec")
                .to_vec()
        } else {
            vec![
                0,
                self.max_data_size
                    .try_into()
                    .expect("invalid max data size"),
            ]
        }
    }

    /// Adds data for an event.
    pub fn add_event_data(&mut self, event: String, val: u64) {
        let size = self.max_data_size - 1;
        self.data
            .entry(event.clone())
            .or_insert(vec![0, size.try_into().expect("invalid max data size")])
            .push(val);
        // XXX: make this efficient
        if let Some(values) = self.data.get_mut(&event.clone()) {
            if values.len() >= self.max_data_size {
                values.remove(0);
            }
        }
    }
}
