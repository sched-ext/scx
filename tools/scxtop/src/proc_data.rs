// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use crate::EventData;
use crate::ThreadData;

use anyhow::Result;
use procfs::process::{ProcState, Process};
use std::collections::BTreeMap;

/// Container for Process data.
#[derive(Clone, Debug)]
pub struct ProcData {
    pub tgid: i32,
    pub process_name: String,
    pub cpu: i32,
    pub llc: Option<u32>,
    pub node: Option<u32>,
    pub dsq: Option<u64>,
    pub layer_id: Option<i32>,
    pub prev_cpu_time: u64,
    pub current_cpu_time: u64,
    pub cpu_util_perc: f64,
    pub state: ProcState,
    pub cmdline: Vec<String>,
    pub threads: BTreeMap<i32, ThreadData>,
    pub data: EventData,
    pub max_data_size: usize,
}

impl ProcData {
    /// Creates a new ProcData.
    pub fn new(process: &Process, max_data_size: usize) -> Result<ProcData> {
        let mut proc_stats = process.stat()?;
        let cpu = proc_stats
            .processor
            .expect("proc_stats should have processor");
        let cmdline = process.cmdline().unwrap_or_default();

        let mut threads = BTreeMap::new();
        for thread in process.tasks()?.flatten() {
            let thread_data = ThreadData::new(thread, max_data_size)?;
            threads.insert(thread_data.pid, thread_data);
        }

        let current_cpu_time = proc_stats.stime + proc_stats.utime;

        let proc_data = Self {
            tgid: process.pid,
            process_name: std::mem::take(&mut proc_stats.comm),
            cpu,
            llc: None,
            node: None,
            dsq: None,
            layer_id: None,
            state: proc_stats.state()?,
            prev_cpu_time: 0,
            current_cpu_time,
            cpu_util_perc: 0.0,
            cmdline,
            threads,
            data: EventData::new(max_data_size),
            max_data_size,
        };

        Ok(proc_data)
    }

    /// Creates a new ProcData from a given tgid.
    pub fn from_tgid(tgid: i32, max_data_size: usize) -> Result<ProcData> {
        let process = Process::new(tgid)?;
        Self::new(&process, max_data_size)
    }

    pub fn add_thread(&mut self, pid: i32) {
        let process = Process::new(self.tgid);
        if let Ok(process) = process {
            let thread = process.task_from_tid(pid);
            if let Ok(thread) = thread {
                let thread_data = ThreadData::new(thread, self.max_data_size);
                if let Ok(thread_data) = thread_data {
                    self.threads.insert(pid, thread_data);
                }
            }
        }
    }

    pub fn remove_thread(&mut self, pid: i32) -> Option<ThreadData> {
        self.threads.remove(&pid)
    }

    pub fn update_cpu_usage(&mut self) -> Result<()> {
        let process = Process::new(self.tgid)?;
        let stats = process.stat()?;

        self.prev_cpu_time = std::mem::take(&mut self.current_cpu_time);
        self.current_cpu_time = stats.stime + stats.utime;

        Ok(())
    }

    pub fn set_cpu_util(&mut self, system_util: u64) {
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
