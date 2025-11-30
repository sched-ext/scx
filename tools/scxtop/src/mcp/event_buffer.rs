// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use crate::Action;
use serde_json::Value;
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

/// Maximum number of events to buffer
const MAX_BUFFER_SIZE: usize = 100_000;

/// Event with timestamp and metadata
#[derive(Clone, Debug)]
pub struct BufferedEvent {
    pub timestamp: u64,
    pub action: Action,
    pub json: Value,
}

/// Ring buffer for storing recent events
pub struct EventBuffer {
    events: VecDeque<BufferedEvent>,
    max_size: usize,
    total_received: u64,
    total_dropped: u64,
    enabled: bool,
}

impl EventBuffer {
    pub fn new() -> Self {
        Self::with_capacity(MAX_BUFFER_SIZE)
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            events: VecDeque::with_capacity(capacity),
            max_size: capacity,
            total_received: 0,
            total_dropped: 0,
            enabled: false, // Disabled by default to prevent overhead
        }
    }

    /// Enable event collection
    pub fn start(&mut self) {
        self.enabled = true;
    }

    /// Disable event collection
    pub fn stop(&mut self) {
        self.enabled = false;
    }

    /// Check if buffer is actively collecting
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Clear all buffered events and reset statistics
    pub fn reset(&mut self) {
        self.events.clear();
        self.total_received = 0;
        self.total_dropped = 0;
    }

    /// Push a new event, dropping oldest if buffer is full
    /// Returns true if event was recorded, false if buffer is disabled
    pub fn push(&mut self, action: Action, json: Value) -> bool {
        if !self.enabled {
            return false;
        }

        self.total_received += 1;

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;

        let event = BufferedEvent {
            timestamp,
            action,
            json,
        };

        if self.events.len() >= self.max_size {
            self.events.pop_front();
            self.total_dropped += 1;
        }

        self.events.push_back(event);
        true
    }

    /// Get events in time range
    pub fn get_events_in_range(&self, start_ts: u64, end_ts: u64) -> Vec<&BufferedEvent> {
        self.events
            .iter()
            .filter(|e| e.timestamp >= start_ts && e.timestamp <= end_ts)
            .collect()
    }

    /// Get last N events
    pub fn get_last_n(&self, n: usize) -> Vec<&BufferedEvent> {
        self.events.iter().rev().take(n).collect()
    }

    /// Get statistics about the buffer
    pub fn stats(&self) -> EventBufferStats {
        EventBufferStats {
            enabled: self.enabled,
            current_size: self.events.len(),
            max_size: self.max_size,
            total_received: self.total_received,
            total_dropped: self.total_dropped,
            oldest_timestamp: self.events.front().map(|e| e.timestamp),
            newest_timestamp: self.events.back().map(|e| e.timestamp),
        }
    }

    /// Clear all events
    pub fn clear(&mut self) {
        self.events.clear();
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct EventBufferStats {
    pub enabled: bool,
    pub current_size: usize,
    pub max_size: usize,
    pub total_received: u64,
    pub total_dropped: u64,
    pub oldest_timestamp: Option<u64>,
    pub newest_timestamp: Option<u64>,
}

/// Shared event buffer
pub type SharedEventBuffer = Arc<Mutex<EventBuffer>>;

impl Default for EventBuffer {
    fn default() -> Self {
        Self::new()
    }
}
