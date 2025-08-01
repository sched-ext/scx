// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use crate::EventData;

use anyhow::Result;
use procfs::process::{ProcState, Process, Task};

/// Container for Thread data.
#[derive(Clone, Debug)]
pub struct ThreadData {
    pub tid: i32,
    pub tgid: i32,
    pub thread_name: String,
    pub cpu: i32,
    pub llc: Option<u32>,
    pub node: Option<u32>,
    pub dsq: Option<u64>,
    pub layer_id: Option<i32>,
    pub prev_cpu_time: u64,
    pub current_cpu_time: u64,
    pub cpu_util_perc: f64,
    pub state: ProcState,
    pub data: EventData,
    pub max_data_size: usize,
}

impl ThreadData {
    /// Creates a new ThreadData.
    pub fn new(thread: Task, max_data_size: usize) -> Result<Self> {
        let mut thread_stats = thread.stat()?;
        let cpu = thread_stats
            .processor
            .expect("thread_stats should have processor");

        let current_cpu_time = thread_stats.stime + thread_stats.utime;

        let thread_data = Self {
            tid: thread.tid,
            tgid: thread.pid,
            thread_name: std::mem::take(&mut thread_stats.comm),
            cpu,
            llc: None,
            node: None,
            dsq: None,
            layer_id: None,
            prev_cpu_time: 0,
            current_cpu_time,
            cpu_util_perc: 0.0,
            state: thread_stats.state()?,
            data: EventData::new(max_data_size),
            max_data_size,
        };

        Ok(thread_data)
    }

    pub fn from_tgid_tid(tgid: i32, tid: i32, max_data_size: usize) -> Result<Self> {
        let process = Process::new(tgid)?;
        let thread = process.task_from_tid(tid)?;
        Self::new(thread, max_data_size)
    }

    pub fn update(&mut self, system_util: u64) -> Result<()> {
        let process = Process::new(self.tgid)?;
        let thread = process.task_from_tid(self.tid)?;
        let stats = thread.stat()?;

        self.prev_cpu_time = std::mem::take(&mut self.current_cpu_time);
        self.current_cpu_time = stats.stime + stats.utime;
        self.set_cpu_util(system_util);
        self.cpu = stats.processor.expect("thread_stats should have processor");
        self.state = stats.state()?;

        Ok(())
    }

    fn set_cpu_util(&mut self, system_util: u64) {
        self.cpu_util_perc = if system_util == 0 {
            0.0
        } else {
            let delta = self.current_cpu_time.saturating_sub(self.prev_cpu_time);
            (delta as f64 / system_util as f64) * 100.0
        };
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
