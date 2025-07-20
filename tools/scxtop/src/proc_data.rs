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
        let cmdline = process.cmdline().unwrap_or(vec![]);

        let mut threads = BTreeMap::new();
        for thread in process.tasks()? {
            if let Ok(thread) = thread {
                let thread_data = ThreadData::new(thread, max_data_size)?;
                threads.insert(thread_data.pid, thread_data);
            }
        }

        let proc_data = Self {
            tgid: process.pid,
            process_name: std::mem::take(&mut proc_stats.comm),
            cpu,
            llc: None,
            node: None,
            dsq: None,
            state: proc_stats.state()?,
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
}
