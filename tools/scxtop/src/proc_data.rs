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
    pub num_threads: i64,
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
            threads: BTreeMap::new(),
            num_threads: proc_stats.num_threads,
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

    pub fn update(&mut self, system_util: u64) -> Result<()> {
        let process = Process::new(self.tgid)?;
        let stats = process.stat()?;

        self.prev_cpu_time = std::mem::take(&mut self.current_cpu_time);
        self.current_cpu_time = stats.stime + stats.utime;
        self.set_cpu_util(system_util);
        self.num_threads = stats.num_threads;
        self.cpu = stats.processor.expect("proc_stats should have processor");
        self.state = stats.state()?;

        Ok(())
    }

    pub fn add_thread(&mut self, pid: i32) -> Option<ThreadData> {
        let process = Process::new(self.tgid);
        if let Ok(process) = process {
            let thread = process.task_from_tid(pid);
            if let Ok(thread) = thread {
                let thread_data = ThreadData::new(thread, self.max_data_size);
                if let Ok(thread_data) = thread_data {
                    return self.threads.insert(pid, thread_data);
                }
            }
        }
        None
    }

    pub fn remove_thread(&mut self, pid: i32) -> Option<ThreadData> {
        self.threads.remove(&pid)
    }

    pub fn init_threads(&mut self) -> Result<()> {
        let process = Process::new(self.tgid)?;

        for thread in process.tasks()?.flatten() {
            let thread_data = ThreadData::new(thread, self.max_data_size)?;
            self.threads.insert(thread_data.tid, thread_data);
        }

        Ok(())
    }

    pub fn update_threads(&mut self, system_active_util: u64) {
        let mut to_remove = Vec::new();

        for (&i, thread_data) in self.threads.iter_mut() {
            if thread_data.update(system_active_util).is_err() {
                to_remove.push(i);
            }
        }

        for key in to_remove {
            self.threads.remove(&key);
        }
    }

    fn set_cpu_util(&mut self, system_util: u64) {
        self.cpu_util_perc = if system_util == 0 {
            0.0
        } else {
            let delta = self.current_cpu_time.saturating_sub(self.prev_cpu_time);
            (delta as f64 / system_util as f64) * 100.0
        };
    }

    pub fn clear_threads(&mut self) {
        self.threads.clear();
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
