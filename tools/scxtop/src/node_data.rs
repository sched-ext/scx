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
    pub num_cpus: usize,
    pub data: EventData,
    pub max_data_size: usize,
}

impl NodeData {
    /// Creates a new NodeData.
    pub fn new(node: usize, num_cpus: usize, max_data_size: usize) -> NodeData {
        let mut data = EventData::new(max_data_size);
        for event in PerfEvent::default_events() {
            data.event_data(&event.event);
        }
        Self {
            node,
            num_cpus,
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

    /// Returns the data for an event. Returns empty Vec if event doesn't exist.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_node_data() {
        let node_id = 1;
        let num_cpus = 4;
        let max_data_size = 10;

        let node_data = NodeData::new(node_id, num_cpus, max_data_size);

        // Verify basic properties
        assert_eq!(node_data.node, node_id);
        assert_eq!(node_data.num_cpus, num_cpus);
        assert_eq!(node_data.max_data_size, max_data_size);

        // Verify that default events are initialized
        for event in PerfEvent::default_events() {
            let event_data = node_data.data.event_data_immut(&event.event);
            assert_eq!(event_data.len(), max_data_size);
            // All values should be initialized to 0
            for val in event_data {
                assert_eq!(val, 0);
            }
        }
    }

    #[test]
    fn test_initialize_events() {
        let node_data = NodeData::new(0, 2, 5);
        let mut node_data_clone = node_data.clone();

        // Define custom events
        let custom_events = ["custom_event1", "custom_event2", "custom_event3"];

        // Initialize events
        node_data_clone.initialize_events(&custom_events);

        // Verify that events were initialized
        for event in &custom_events {
            let event_data = node_data_clone.data.event_data_immut(event);
            assert_eq!(event_data.len(), 5);
            // All values should be initialized to 0
            for val in event_data {
                assert_eq!(val, 0);
            }
        }
    }

    #[test]
    fn test_event_data() {
        let mut node_data = NodeData::new(0, 2, 5);

        // Get event data for a new event
        let event_name = "test_event";
        let event_data = node_data.event_data(event_name);

        // Verify that the event was created with the correct size
        assert_eq!(event_data.len(), 5);
        for &val in event_data {
            assert_eq!(val, 0);
        }
    }

    #[test]
    fn test_event_data_immut() {
        let mut node_data = NodeData::new(0, 2, 5);

        // Add data to an event
        let event_name = "test_event";
        node_data.add_event_data(event_name, 42);

        // Get immutable event data
        let event_data = node_data.event_data_immut(event_name);

        // Verify that the data contains the value we added
        assert!(!event_data.is_empty());
        assert!(event_data.contains(&42));

        // Test with non-existent event
        let empty_data = node_data.event_data_immut("nonexistent_event");
        assert!(empty_data.is_empty());
    }

    #[test]
    fn test_add_event_data() {
        let mut node_data = NodeData::new(0, 2, 5);

        // Add data to an event
        let event_name = "test_event";
        node_data.add_event_data(event_name, 10);
        node_data.add_event_data(event_name, 20);
        node_data.add_event_data(event_name, 30);

        // Verify that the data was added correctly
        let event_data = node_data.event_data_immut(event_name);
        assert!(!event_data.is_empty());
        assert!(event_data.contains(&10));
        assert!(event_data.contains(&20));
        assert!(event_data.contains(&30));
    }

    #[test]
    fn test_add_cpu_event_data() {
        let mut node_data = NodeData::new(0, 2, 5);

        // Add initial data to an event
        let event_name = "test_event";
        node_data.add_event_data(event_name, 10);

        // Add CPU event data (should update the last value)
        node_data.add_cpu_event_data(event_name, 5);

        // Verify that the data contains the expected values
        let event_data = node_data.event_data_immut(event_name);
        assert!(!event_data.is_empty());

        // Add more data and test again
        node_data.add_event_data(event_name, 20);
        node_data.add_cpu_event_data(event_name, 7);

        // Verify that the data was updated
        let event_data = node_data.event_data_immut(event_name);
        assert!(!event_data.is_empty());
    }
}
