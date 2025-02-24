// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

// This crate provides basically the same map as `std::collections::HashMap`. However, the raw
// entry API isn't gated behind an unstable flag that requires a nightly compiler. When (if) the
// raw entry API stabilises, this should be switched to the standard map.
use hashbrown::HashMap;

use std::collections::VecDeque;

/// Container for event data.
#[derive(Clone, Debug)]
pub struct EventData {
    pub data: HashMap<String, VecDeque<u64>>,
    pub max_data_size: usize,
}

fn vec_deque_truncate_extend_with_zeros(vd: &mut VecDeque<u64>, len: usize) {
    vd.truncate(len);
    vd.reserve(len);
    while vd.len() < len {
        vd.push_front(0);
    }
}

impl EventData {
    /// Creates a new EventData.
    pub fn new(max_data_size: usize) -> EventData {
        Self {
            data: HashMap::new(),
            max_data_size,
        }
    }

    /// Initializes events with default values.
    pub fn initialize_events(&mut self, events: &[&str]) {
        for event in events {
            self.event_data(event);
        }
    }

    /// Returns the data for an event and updates if no entry is present.
    pub fn event_data_mut(&mut self, event: &str) -> &mut VecDeque<u64> {
        self.data
            .raw_entry_mut()
            .from_key(event)
            .or_insert_with(|| {
                (event.to_string(), {
                    let mut vd = VecDeque::new();
                    vec_deque_truncate_extend_with_zeros(&mut vd, self.max_data_size);
                    vd
                })
            })
            .1
    }

    /// Returns the data for an event and updates if no entry is present.
    pub fn event_data(&mut self, event: &str) -> &VecDeque<u64> {
        self.event_data_mut(event)
    }

    /// Zeros out values for an event.
    pub fn zero_event(&mut self, event: &str) {
        for val in self.event_data_mut(event) {
            *val = 0;
        }
    }

    /// Sets the max size and truncates events greater than the max.
    pub fn set_max_size(&mut self, max_data_size: usize) {
        self.max_data_size = max_data_size;
        for event_data in self.data.values_mut() {
            vec_deque_truncate_extend_with_zeros(event_data, self.max_data_size);
        }
    }

    /// Clears an event.
    pub fn clear_event(&mut self, event: &str) {
        self.data.remove(event);
    }

    /// Clears out all values
    pub fn clear(&mut self) {
        self.data.clear();
    }

    /// Returns the data for an event and updates if no entry is present.
    pub fn event_data_immut(&self, event: &str) -> Vec<u64> {
        if let Some(vs) = self.data.get(event) {
            vs.iter().copied().collect()
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
    pub fn add_event_data(&mut self, event: &str, val: u64) {
        let size = self.max_data_size;
        let data = self.event_data_mut(event);
        if data.len() == size {
            data.pop_front();
        }
        data.push_back(val);
    }
}
