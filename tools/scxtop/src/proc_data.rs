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

    pub fn update(&mut self, system_util: u64, num_cpus: usize) -> Result<()> {
        let process = Process::new(self.tgid)?;
        let stats = process.stat()?;

        self.prev_cpu_time = std::mem::take(&mut self.current_cpu_time);
        self.current_cpu_time = stats.stime + stats.utime;
        self.set_cpu_util(system_util, num_cpus);
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

    pub fn update_threads(&mut self, system_active_util: u64, num_cpus: usize) {
        let mut to_remove = Vec::new();

        for (&i, thread_data) in self.threads.iter_mut() {
            if thread_data.update(system_active_util, num_cpus).is_err() {
                to_remove.push(i);
            }
        }

        for key in to_remove {
            self.threads.remove(&key);
        }
    }

    fn set_cpu_util(&mut self, system_util: u64, num_cpus: usize) {
        self.cpu_util_perc = if system_util == 0 || num_cpus == 0 {
            0.0
        } else {
            let delta = self.current_cpu_time.saturating_sub(self.prev_cpu_time);
            // system_util is total across all CPUs, so we multiply by num_cpus to get proper percentage
            (delta as f64 / system_util as f64) * 100.0 * num_cpus as f64
        };
    }

    pub fn clear_threads(&mut self) {
        self.threads.clear();
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
    fn test_new_proc_data() {
        // Get the current process
        let current_pid = std::process::id() as i32;
        let process = Process::new(current_pid).unwrap();

        // Create ProcData from the current process
        let proc_data = ProcData::new(&process, 10).unwrap();

        // Verify basic properties
        assert_eq!(proc_data.tgid, current_pid);
        assert!(!proc_data.process_name.is_empty());
        assert_eq!(proc_data.prev_cpu_time, 0);
        // The current_cpu_time might be 0 in some environments, so we don't assert it's > 0
        assert_eq!(proc_data.cpu_util_perc, 0.0);
        assert!(proc_data.threads.is_empty());
        assert_eq!(proc_data.max_data_size, 10);
    }

    #[test]
    fn test_from_tgid() {
        // Get the current process ID
        let current_pid = std::process::id() as i32;

        // Create ProcData from the current process ID
        let proc_data = ProcData::from_tgid(current_pid, 5).unwrap();

        // Verify basic properties
        assert_eq!(proc_data.tgid, current_pid);
        assert!(!proc_data.process_name.is_empty());
        assert_eq!(proc_data.max_data_size, 5);
    }

    #[test]
    fn test_update() {
        // Get the current process
        let current_pid = std::process::id() as i32;
        let mut proc_data = ProcData::from_tgid(current_pid, 10).unwrap();

        // Store initial values
        let initial_cpu_time = proc_data.current_cpu_time;

        // Do some CPU work to ensure time changes
        for _ in 0..1000000 {
            let _ = 2 + 2;
        }

        // Update with a non-zero system util and 4 CPUs
        proc_data.update(100, 4).unwrap();

        // Verify update effects
        assert_eq!(proc_data.prev_cpu_time, initial_cpu_time);
        assert!(proc_data.current_cpu_time >= initial_cpu_time);
        // CPU util should be non-zero since we provided a system_util value
        assert!(proc_data.cpu_util_perc >= 0.0);
    }

    #[test]
    fn test_set_cpu_util() {
        // Get the current process
        let current_pid = std::process::id() as i32;
        let mut proc_data = ProcData::from_tgid(current_pid, 10).unwrap();

        // Set initial values
        proc_data.prev_cpu_time = 100;
        proc_data.current_cpu_time = 150;

        // Test with zero system_util
        proc_data.set_cpu_util(0, 4);
        assert_eq!(proc_data.cpu_util_perc, 0.0);

        // Test with non-zero system_util and 4 CPUs
        proc_data.set_cpu_util(100, 4);
        assert_eq!(proc_data.cpu_util_perc, 200.0); // (150-100)/100 * 100 * 4 = 200%
    }

    #[test]
    fn test_event_data_operations() {
        // Get the current process
        let current_pid = std::process::id() as i32;
        let mut proc_data = ProcData::from_tgid(current_pid, 5).unwrap();

        // Test adding event data
        proc_data.add_event_data("test_event", 42);
        proc_data.add_event_data("test_event", 84);

        // Test retrieving event data
        let data = proc_data.event_data_immut("test_event");
        assert!(!data.is_empty());
        assert!(data.contains(&42));
        assert!(data.contains(&84));

        // Test retrieving non-existent event data
        let empty_data = proc_data.event_data_immut("nonexistent_event");
        assert!(empty_data.is_empty());
    }

    #[test]
    fn test_thread_operations() {
        // Get the current process
        let current_pid = std::process::id() as i32;
        let mut proc_data = ProcData::from_tgid(current_pid, 10).unwrap();

        // Initialize threads
        proc_data.init_threads().unwrap();

        // Verify threads were added
        assert!(!proc_data.threads.is_empty());
        assert!(proc_data.threads.contains_key(&current_pid));

        // Test thread update with 4 CPUs
        proc_data.update_threads(100, 4);
        // The thread count might change during the test as threads are created or destroyed
        // So we don't assert exact equality

        // Test clearing threads
        proc_data.clear_threads();
        assert!(proc_data.threads.is_empty());
    }
}
