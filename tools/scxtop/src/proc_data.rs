// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use crate::EventData;
use crate::ThreadData;

use fb_procfs::PidState;
use std::collections::BTreeMap;
use std::collections::VecDeque;

/// Container for per CPU data.
#[derive(Clone, Debug)]
pub struct ProcData {
    pub tgid: i32,
    pub process_name: String,
    pub cpu: i32,
    pub dsq: Option<usize>,
    pub state: PidState,
    pub cmdline: Vec<String>,
    pub running_secs: u64,
    pub threads: BTreeMap<i32, ThreadData>,
    pub data: EventData,
    pub max_data_size: usize,
}

impl ProcData {
    /// Creates a new CpuData.
    pub fn new(
        tgid: i32,
        process_name: String,
        cpu: i32,
        dsq: Option<usize>,
        state: PidState,
        cmdline: Vec<String>,
        running_secs: u64,
        max_data_size: usize,
    ) -> ProcData {
        Self {
            tgid,
            process_name,
            cpu,
            dsq,
            state,
            cmdline,
            running_secs,
            threads: BTreeMap::new(),
            data: EventData::new(max_data_size),
            max_data_size,
        }
    }

    pub fn get_default_events(&self) -> Vec<String> {
        vec!["cpu-utilization".to_string()]
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
