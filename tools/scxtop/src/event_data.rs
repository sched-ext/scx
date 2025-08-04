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

    /// Returns the data for an event. Returns empty Vec if event doesn't exist.
    pub fn event_data_immut(&self, event: &str) -> Vec<u64> {
        if let Some(vs) = self.data.get(event) {
            vs.iter().copied().collect()
        } else {
            Vec::new()
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new() {
        let event_data = EventData::new(10);
        assert_eq!(event_data.max_data_size, 10);
        assert!(event_data.data.is_empty());
    }

    #[test]
    fn test_initialize_events() {
        let mut event_data = EventData::new(5);
        let events = vec!["event1", "event2", "event3"];

        event_data.initialize_events(&events);

        assert_eq!(event_data.data.len(), 3);
        for event in &events {
            assert!(event_data.data.contains_key(*event));
            let data = event_data.data.get(*event).unwrap();
            assert_eq!(data.len(), 5);
            // All values should be initialized to 0
            for &val in data {
                assert_eq!(val, 0);
            }
        }
    }

    #[test]
    fn test_event_data_mut_creates_new_entry() {
        let mut event_data = EventData::new(3);

        let data = event_data.event_data_mut("new_event");
        assert_eq!(data.len(), 3);
        for &val in data.iter() {
            assert_eq!(val, 0);
        }

        assert!(event_data.data.contains_key("new_event"));
    }

    #[test]
    fn test_event_data_mut_returns_existing_entry() {
        let mut event_data = EventData::new(3);

        // Create initial entry
        let data1 = event_data.event_data_mut("existing_event");
        data1[0] = 42;

        // Get the same entry again
        let data2 = event_data.event_data_mut("existing_event");
        assert_eq!(data2[0], 42);
    }

    #[test]
    fn test_event_data() {
        let mut event_data = EventData::new(3);

        let data = event_data.event_data("test_event");
        assert_eq!(data.len(), 3);
        for &val in data {
            assert_eq!(val, 0);
        }
    }

    #[test]
    fn test_zero_event() {
        let mut event_data = EventData::new(3);

        // Add some data
        event_data.add_event_data("test_event", 10);
        event_data.add_event_data("test_event", 20);
        event_data.add_event_data("test_event", 30);

        // Verify data is not zero
        let data = event_data.event_data("test_event");
        assert!(data.iter().any(|&x| x != 0));

        // Zero out the event
        event_data.zero_event("test_event");

        // Verify all values are zero
        let data = event_data.event_data("test_event");
        for &val in data {
            assert_eq!(val, 0);
        }
    }

    #[test]
    fn test_set_max_size_increase() {
        let mut event_data = EventData::new(3);
        event_data.add_event_data("test_event", 10);
        event_data.add_event_data("test_event", 20);
        event_data.add_event_data("test_event", 30);

        // Increase max size
        event_data.set_max_size(5);

        assert_eq!(event_data.max_data_size, 5);
        let data = event_data.event_data("test_event");
        assert_eq!(data.len(), 5);

        // The original data should be preserved, with zeros added at the front
        let vec_data: Vec<u64> = data.iter().copied().collect();
        assert_eq!(vec_data[vec_data.len() - 3..], [10, 20, 30]);
    }

    #[test]
    fn test_set_max_size_decrease() {
        let mut event_data = EventData::new(5);
        for i in 1..=5 {
            event_data.add_event_data("test_event", i * 10);
        }

        // Decrease max size
        event_data.set_max_size(3);

        assert_eq!(event_data.max_data_size, 3);
        let data = event_data.event_data("test_event");
        assert_eq!(data.len(), 3);
    }

    #[test]
    fn test_clear_event() {
        let mut event_data = EventData::new(3);
        event_data.add_event_data("event1", 10);
        event_data.add_event_data("event2", 20);

        assert!(event_data.data.contains_key("event1"));
        assert!(event_data.data.contains_key("event2"));

        event_data.clear_event("event1");

        assert!(!event_data.data.contains_key("event1"));
        assert!(event_data.data.contains_key("event2"));
    }

    #[test]
    fn test_clear() {
        let mut event_data = EventData::new(3);
        event_data.add_event_data("event1", 10);
        event_data.add_event_data("event2", 20);

        assert_eq!(event_data.data.len(), 2);

        event_data.clear();

        assert!(event_data.data.is_empty());
    }

    #[test]
    fn test_event_data_immut_existing_event() {
        let mut event_data = EventData::new(3);
        event_data.add_event_data("test_event", 10);
        event_data.add_event_data("test_event", 20);
        event_data.add_event_data("test_event", 30);

        let data = event_data.event_data_immut("test_event");
        assert_eq!(data.len(), 3);
        assert_eq!(data[data.len() - 3..], [10, 20, 30]);
    }

    #[test]
    fn test_event_data_immut_nonexistent_event() {
        let event_data = EventData::new(5);

        let data = event_data.event_data_immut("nonexistent");
        // Returns empty Vec for non-existent events
        assert_eq!(data, Vec::<u64>::new());
    }

    #[test]
    fn test_add_event_data_basic() {
        let mut event_data = EventData::new(3);

        event_data.add_event_data("test_event", 10);
        let data = event_data.event_data("test_event");
        assert_eq!(data.back(), Some(&10));

        event_data.add_event_data("test_event", 20);
        let data = event_data.event_data("test_event");
        assert_eq!(data.back(), Some(&20));
    }

    #[test]
    fn test_add_event_data_overflow() {
        let mut event_data = EventData::new(3);

        // Fill up the deque
        for i in 1..=3 {
            event_data.add_event_data("test_event", i * 10);
        }

        let data = event_data.event_data("test_event");
        assert_eq!(data.len(), 3);

        // Add one more item, should cause the first item to be removed
        event_data.add_event_data("test_event", 40);

        let data = event_data.event_data("test_event");
        assert_eq!(data.len(), 3);
        let vec_data: Vec<u64> = data.iter().copied().collect();
        assert_eq!(vec_data[vec_data.len() - 3..], [20, 30, 40]);
    }

    #[test]
    fn test_add_event_data_multiple_events() {
        let mut event_data = EventData::new(2);

        event_data.add_event_data("event1", 10);
        event_data.add_event_data("event2", 20);
        event_data.add_event_data("event1", 30);

        let data1 = event_data.event_data_immut("event1");
        let data2 = event_data.event_data_immut("event2");

        assert_eq!(data1[data1.len() - 2..], [10, 30]);
        assert_eq!(data2[data2.len() - 1..], [20]);
    }

    #[test]
    fn test_complex_workflow() {
        let mut event_data = EventData::new(4);

        // Initialize multiple events
        event_data.initialize_events(&["cpu_usage", "memory_usage", "disk_io"]);

        // Add data to different events
        for i in 1..=5 {
            event_data.add_event_data("cpu_usage", i * 10);
            event_data.add_event_data("memory_usage", i * 20);
        }

        // Verify cpu_usage data (should have overflow behavior)
        let cpu_data = event_data.event_data_immut("cpu_usage");
        assert_eq!(cpu_data.len(), 4);
        // First value (10) should be dropped due to overflow, remaining: [20, 30, 40, 50]
        assert_eq!(cpu_data[cpu_data.len() - 4..], [20, 30, 40, 50]);

        // Verify memory_usage data
        let mem_data = event_data.event_data_immut("memory_usage");
        assert_eq!(mem_data.len(), 4);
        // First value (20) should be dropped due to overflow, remaining: [40, 60, 80, 100]
        assert_eq!(mem_data[mem_data.len() - 4..], [40, 60, 80, 100]);

        // Verify disk_io has only zeros (no data added)
        let disk_data = event_data.event_data_immut("disk_io");
        assert_eq!(disk_data.len(), 4);
        assert_eq!(disk_data, vec![0, 0, 0, 0]);

        // Clear one event and verify
        event_data.clear_event("memory_usage");
        let cleared_data = event_data.event_data_immut("memory_usage");
        assert_eq!(cleared_data, Vec::<u64>::new()); // Returns empty Vec for cleared event
    }
}
