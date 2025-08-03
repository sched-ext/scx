// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use crate::EventData;
use anyhow::Result;
use procfs::net::DeviceStatus;
use std::collections::BTreeMap;

#[derive(Clone, Debug)]
pub struct NetworkStatSnapshot {
    pub interfaces: BTreeMap<String, InterfaceStats>,
    pub prev_interfaces: BTreeMap<String, InterfaceStats>,
    pub last_update_time: std::time::Instant,
    pub historical_data: BTreeMap<String, EventData>,
    pub max_history_size: usize,
}

impl Default for NetworkStatSnapshot {
    fn default() -> Self {
        Self::new(100) // Default to 100 data points of history
    }
}

#[derive(Clone, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct InterfaceStats {
    pub recv_bytes: u64,
    pub recv_packets: u64,
    pub recv_errs: u64,
    pub recv_drop: u64,
    pub sent_bytes: u64,
    pub sent_packets: u64,
    pub sent_errs: u64,
    pub sent_drop: u64,
}

impl NetworkStatSnapshot {
    pub fn new(max_history_size: usize) -> Self {
        Self {
            interfaces: BTreeMap::default(),
            prev_interfaces: BTreeMap::default(),
            last_update_time: std::time::Instant::now(),
            historical_data: BTreeMap::default(),
            max_history_size,
        }
    }

    pub fn update(&mut self) -> Result<()> {
        // Save current interfaces as previous
        std::mem::swap(&mut self.interfaces, &mut self.prev_interfaces);

        // Calculate elapsed time since last update
        let now = std::time::Instant::now();
        self.last_update_time = now;

        // Get new interface stats
        let dev_status = procfs::net::dev_status()?;
        self.interfaces.clear();

        for (interface, stats) in dev_status {
            self.interfaces.insert(
                interface.clone(),
                InterfaceStats {
                    recv_bytes: stats.recv_bytes,
                    recv_packets: stats.recv_packets,
                    recv_errs: stats.recv_errs,
                    recv_drop: stats.recv_drop,
                    sent_bytes: stats.sent_bytes,
                    sent_packets: stats.sent_packets,
                    sent_errs: stats.sent_errs,
                    sent_drop: stats.sent_drop,
                },
            );

            // Update historical data for this interface
            self.update_historical_data(&interface);
        }

        Ok(())
    }

    fn update_historical_data(&mut self, interface: &str) {
        // Skip historical data update if this is the first update (no previous data)
        if !self.prev_interfaces.contains_key(interface) {
            // Initialize historical data but don't add any values yet
            self.historical_data
                .entry(interface.to_string())
                .or_insert_with(|| EventData::new(self.max_history_size));
            return;
        }

        // Calculate delta values first to avoid borrowing conflicts
        let delta_recv_bytes = self.get_delta_recv_bytes(interface);
        let delta_sent_bytes = self.get_delta_sent_bytes(interface);
        let delta_recv_packets = self.get_delta_recv_packets(interface);
        let delta_sent_packets = self.get_delta_sent_packets(interface);

        // Get or create historical data for this interface
        let historical = self
            .historical_data
            .entry(interface.to_string())
            .or_insert_with(|| EventData::new(self.max_history_size));

        // Add current delta values to historical data
        historical.add_event_data("recv_bytes", delta_recv_bytes);
        historical.add_event_data("sent_bytes", delta_sent_bytes);
        historical.add_event_data("recv_packets", delta_recv_packets);
        historical.add_event_data("sent_packets", delta_sent_packets);
    }

    pub fn get_historical_data(&self, interface: &str, metric: &str) -> Vec<u64> {
        self.historical_data
            .get(interface)
            .map(|data| data.event_data_immut(metric))
            .unwrap_or_default()
    }

    pub fn set_max_history_size(&mut self, max_size: usize) {
        self.max_history_size = max_size;
        for historical in self.historical_data.values_mut() {
            historical.set_max_size(max_size);
        }
    }

    fn get_delta<F>(&self, interface: &str, field_accessor: F) -> u64
    where
        F: Fn(&InterfaceStats) -> u64,
    {
        let current = self.interfaces.get(interface).map_or(0, &field_accessor);
        let previous = self
            .prev_interfaces
            .get(interface)
            .map_or(0, &field_accessor);
        if current >= previous {
            current - previous
        } else {
            // Handle counter reset/overflow
            current
        }
    }

    fn get_total_delta<F>(&self, field_accessor: F) -> u64
    where
        F: Fn(&InterfaceStats) -> u64,
    {
        self.interfaces
            .keys()
            .map(|iface| self.get_delta(iface, &field_accessor))
            .sum()
    }

    pub fn get_delta_recv_bytes(&self, interface: &str) -> u64 {
        self.get_delta(interface, |s| s.recv_bytes)
    }

    pub fn get_delta_sent_bytes(&self, interface: &str) -> u64 {
        self.get_delta(interface, |s| s.sent_bytes)
    }

    pub fn get_delta_recv_packets(&self, interface: &str) -> u64 {
        self.get_delta(interface, |s| s.recv_packets)
    }

    pub fn get_delta_sent_packets(&self, interface: &str) -> u64 {
        self.get_delta(interface, |s| s.sent_packets)
    }

    pub fn get_delta_recv_errs(&self, interface: &str) -> u64 {
        self.get_delta(interface, |s| s.recv_errs)
    }

    pub fn get_delta_sent_errs(&self, interface: &str) -> u64 {
        self.get_delta(interface, |s| s.sent_errs)
    }

    pub fn get_total_delta_recv_bytes(&self) -> u64 {
        self.get_total_delta(|s| s.recv_bytes)
    }

    pub fn get_total_delta_sent_bytes(&self) -> u64 {
        self.get_total_delta(|s| s.sent_bytes)
    }

    pub fn get_total_delta_recv_packets(&self) -> u64 {
        self.get_total_delta(|s| s.recv_packets)
    }

    pub fn get_total_delta_sent_packets(&self) -> u64 {
        self.get_total_delta(|s| s.sent_packets)
    }

    pub fn get_total_delta_recv_errs(&self) -> u64 {
        self.get_total_delta(|s| s.recv_errs)
    }

    pub fn get_total_delta_sent_errs(&self) -> u64 {
        self.get_total_delta(|s| s.sent_errs)
    }

    pub fn get_interface_stats(&self, interface: &str) -> Option<&InterfaceStats> {
        self.interfaces.get(interface)
    }

    pub fn get_total_recv_bytes(&self) -> u64 {
        self.interfaces.values().map(|stats| stats.recv_bytes).sum()
    }

    pub fn get_total_sent_bytes(&self) -> u64 {
        self.interfaces.values().map(|stats| stats.sent_bytes).sum()
    }

    pub fn get_total_recv_packets(&self) -> u64 {
        self.interfaces
            .values()
            .map(|stats| stats.recv_packets)
            .sum()
    }

    pub fn get_total_sent_packets(&self) -> u64 {
        self.interfaces
            .values()
            .map(|stats| stats.sent_packets)
            .sum()
    }

    pub fn get_total_recv_errs(&self) -> u64 {
        self.interfaces.values().map(|stats| stats.recv_errs).sum()
    }

    pub fn get_total_sent_errs(&self) -> u64 {
        self.interfaces.values().map(|stats| stats.sent_errs).sum()
    }
}

impl From<&DeviceStatus> for InterfaceStats {
    fn from(stats: &DeviceStatus) -> Self {
        Self {
            recv_bytes: stats.recv_bytes,
            recv_packets: stats.recv_packets,
            recv_errs: stats.recv_errs,
            recv_drop: stats.recv_drop,
            sent_bytes: stats.sent_bytes,
            sent_packets: stats.sent_packets,
            sent_errs: stats.sent_errs,
            sent_drop: stats.sent_drop,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_update_network_stats() -> Result<()> {
        let mut snapshot = NetworkStatSnapshot::default();
        snapshot.update()?;

        // Just verify that we have at least one interface
        assert!(!snapshot.interfaces.is_empty());

        Ok(())
    }

    #[test]
    fn test_get_total_stats() -> Result<()> {
        let mut snapshot = NetworkStatSnapshot::default();

        // Add some mock interfaces
        snapshot.interfaces.insert(
            "eth0".to_string(),
            InterfaceStats {
                recv_bytes: 1000,
                recv_packets: 10,
                recv_errs: 1,
                recv_drop: 0,
                sent_bytes: 2000,
                sent_packets: 20,
                sent_errs: 2,
                sent_drop: 0,
            },
        );

        snapshot.interfaces.insert(
            "eth1".to_string(),
            InterfaceStats {
                recv_bytes: 3000,
                recv_packets: 30,
                recv_errs: 3,
                recv_drop: 0,
                sent_bytes: 4000,
                sent_packets: 40,
                sent_errs: 4,
                sent_drop: 0,
            },
        );

        assert_eq!(snapshot.get_total_recv_bytes(), 4000);
        assert_eq!(snapshot.get_total_sent_bytes(), 6000);
        assert_eq!(snapshot.get_total_recv_packets(), 40);
        assert_eq!(snapshot.get_total_sent_packets(), 60);
        assert_eq!(snapshot.get_total_recv_errs(), 4);
        assert_eq!(snapshot.get_total_sent_errs(), 6);

        Ok(())
    }
}
