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

    /// Returns the data for an event. Returns empty Vec if event doesn't exist.
    pub fn event_data_immut(&self, event: &str) -> Vec<u64> {
        self.data.event_data_immut(event)
    }

    /// Adds data for an event.
    pub fn add_event_data(&mut self, event: &str, val: u64) {
        self.data.add_event_data(event, val)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_cpu_data() {
        let cpu_id = 1;
        let core_id = 2;
        let llc_id = 3;
        let node_id = 4;
        let max_data_size = 10;

        let cpu_data = CpuData::new(cpu_id, core_id, llc_id, node_id, max_data_size);

        // Verify basic properties
        assert_eq!(cpu_data.cpu, cpu_id);
        assert_eq!(cpu_data.core, core_id);
        assert_eq!(cpu_data.llc, llc_id);
        assert_eq!(cpu_data.node, node_id);
        assert_eq!(cpu_data.max_data_size, max_data_size);

        // Verify that default events are initialized
        for event in PerfEvent::default_events() {
            let event_data = cpu_data.event_data_immut(&event.event);
            assert_eq!(event_data.len(), max_data_size);
            // All values should be initialized to 0
            for val in event_data {
                assert_eq!(val, 0);
            }
        }
    }

    #[test]
    fn test_initialize_events() {
        let cpu_data = CpuData::new(0, 0, 0, 0, 5);
        let mut cpu_data_clone = cpu_data.clone();

        // Define custom events
        let custom_events = ["custom_event1", "custom_event2", "custom_event3"];

        // Initialize events
        cpu_data_clone.initialize_events(&custom_events);

        // Verify that events were initialized
        for event in &custom_events {
            let event_data = cpu_data_clone.event_data_immut(event);
            assert_eq!(event_data.len(), 5);
            // All values should be initialized to 0
            for val in event_data {
                assert_eq!(val, 0);
            }
        }
    }

    #[test]
    fn test_event_data() {
        let mut cpu_data = CpuData::new(0, 0, 0, 0, 5);

        // Get event data for a new event
        let event_name = "test_event";
        let event_data = cpu_data.event_data(event_name);

        // Verify that the event was created with the correct size
        assert_eq!(event_data.len(), 5);
        for &val in event_data {
            assert_eq!(val, 0);
        }
    }

    #[test]
    fn test_event_data_immut() {
        let mut cpu_data = CpuData::new(0, 0, 0, 0, 5);

        // Add data to an event
        let event_name = "test_event";
        cpu_data.add_event_data(event_name, 42);

        // Get immutable event data
        let event_data = cpu_data.event_data_immut(event_name);

        // Verify that the data contains the value we added
        assert!(!event_data.is_empty());
        assert!(event_data.contains(&42));

        // Test with non-existent event
        let empty_data = cpu_data.event_data_immut("nonexistent_event");
        assert!(empty_data.is_empty());
    }

    #[test]
    fn test_add_event_data() {
        let mut cpu_data = CpuData::new(0, 0, 0, 0, 5);

        // Add data to an event
        let event_name = "test_event";
        cpu_data.add_event_data(event_name, 10);
        cpu_data.add_event_data(event_name, 20);
        cpu_data.add_event_data(event_name, 30);

        // Verify that the data was added correctly
        let event_data = cpu_data.event_data_immut(event_name);
        assert!(!event_data.is_empty());
        assert!(event_data.contains(&10));
        assert!(event_data.contains(&20));
        assert!(event_data.contains(&30));
    }

    #[test]
    fn test_max_data_size_handling() {
        // Create CPU data with small max size
        let mut cpu_data = CpuData::new(0, 0, 0, 0, 3);

        // Add more data than the max size
        let event_name = "test_event";
        cpu_data.add_event_data(event_name, 10);
        cpu_data.add_event_data(event_name, 20);
        cpu_data.add_event_data(event_name, 30);
        cpu_data.add_event_data(event_name, 40);
        cpu_data.add_event_data(event_name, 50);

        // Verify that data was added
        let event_data = cpu_data.event_data_immut(event_name);
        assert_eq!(event_data.len(), 3);
        // The implementation might handle overflow differently, so we just check
        // that the most recent value (50) is present
        assert!(event_data.contains(&50));
    }
}
