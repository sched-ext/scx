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
    pub last_waker_pid: Option<u32>,
    pub last_waker_comm: Option<String>,
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
            last_waker_pid: None,
            last_waker_comm: None,
        };

        Ok(thread_data)
    }

    pub fn from_tgid_tid(tgid: i32, tid: i32, max_data_size: usize) -> Result<Self> {
        let process = Process::new(tgid)?;
        let thread = process.task_from_tid(tid)?;
        Self::new(thread, max_data_size)
    }

    pub fn update(&mut self, system_util: u64, num_cpus: usize) -> Result<()> {
        let process = Process::new(self.tgid)?;
        let thread = process.task_from_tid(self.tid)?;
        let stats = thread.stat()?;

        self.prev_cpu_time = std::mem::take(&mut self.current_cpu_time);
        self.current_cpu_time = stats.stime + stats.utime;
        self.set_cpu_util(system_util, num_cpus);
        self.cpu = stats.processor.expect("thread_stats should have processor");
        self.state = stats.state()?;

        Ok(())
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
    use procfs::process::Process;

    #[test]
    fn test_new_thread_data() {
        // Get the current process and its main thread
        let current_pid = std::process::id() as i32;
        let process = Process::new(current_pid).unwrap();
        let tasks = process.tasks().unwrap();
        let main_thread = tasks.flatten().next().unwrap();

        // Create ThreadData from the main thread
        let thread_data = ThreadData::new(main_thread, 10).unwrap();

        // Verify basic properties
        assert_eq!(thread_data.tgid, current_pid);
        assert_eq!(thread_data.tid, current_pid); // Main thread has same TID as PID
        assert!(!thread_data.thread_name.is_empty());
        assert_eq!(thread_data.prev_cpu_time, 0);
        // The current_cpu_time might be 0 in some environments, so we don't assert it's > 0
        assert_eq!(thread_data.cpu_util_perc, 0.0);
        assert_eq!(thread_data.max_data_size, 10);
        assert!(thread_data.llc.is_none());
        assert!(thread_data.node.is_none());
        assert!(thread_data.dsq.is_none());
        assert!(thread_data.layer_id.is_none());
    }

    #[test]
    fn test_from_tgid_tid() {
        // Get the current process ID (which is also the main thread ID)
        let current_pid = std::process::id() as i32;

        // Create ThreadData from the current process and thread ID
        let thread_data = ThreadData::from_tgid_tid(current_pid, current_pid, 5).unwrap();

        // Verify basic properties
        assert_eq!(thread_data.tgid, current_pid);
        assert_eq!(thread_data.tid, current_pid);
        assert!(!thread_data.thread_name.is_empty());
        assert_eq!(thread_data.max_data_size, 5);
    }

    #[test]
    fn test_from_tgid_tid_invalid() {
        // Test with invalid PID
        let result = ThreadData::from_tgid_tid(-1, -1, 10);
        assert!(result.is_err());

        // Test with valid PID but invalid TID
        let current_pid = std::process::id() as i32;
        let result = ThreadData::from_tgid_tid(current_pid, -1, 10);
        assert!(result.is_err());
    }

    #[test]
    fn test_update() {
        // Get the current process ID
        let current_pid = std::process::id() as i32;
        let mut thread_data = ThreadData::from_tgid_tid(current_pid, current_pid, 10).unwrap();

        // Store initial values
        let initial_cpu_time = thread_data.current_cpu_time;

        // Do some CPU work to ensure time changes
        for _ in 0..1000000 {
            let _ = 2 + 2;
        }

        // Update with a non-zero system util and 4 CPUs
        thread_data.update(100, 4).unwrap();

        // Verify update effects
        assert_eq!(thread_data.prev_cpu_time, initial_cpu_time);
        assert!(thread_data.current_cpu_time >= initial_cpu_time);
        // CPU util should be non-negative
        assert!(thread_data.cpu_util_perc >= 0.0);
    }

    #[test]
    fn test_update_invalid_thread() {
        // Create a thread data with valid initial values
        let current_pid = std::process::id() as i32;
        let mut thread_data = ThreadData::from_tgid_tid(current_pid, current_pid, 10).unwrap();

        // Change the TID to an invalid one
        thread_data.tid = -1;

        // Update should fail
        let result = thread_data.update(100, 4);
        assert!(result.is_err());
    }

    #[test]
    fn test_set_cpu_util() {
        // Get the current process ID
        let current_pid = std::process::id() as i32;
        let mut thread_data = ThreadData::from_tgid_tid(current_pid, current_pid, 10).unwrap();

        // Set initial values for testing
        thread_data.prev_cpu_time = 100;
        thread_data.current_cpu_time = 150;

        // Test with zero system_util
        thread_data.set_cpu_util(0, 4);
        assert_eq!(thread_data.cpu_util_perc, 0.0);

        // Test with non-zero system_util and 4 CPUs
        thread_data.set_cpu_util(100, 4);
        assert_eq!(thread_data.cpu_util_perc, 200.0); // (150-100)/100 * 100 * 4 = 200%

        // Test with system_util smaller than delta (should not panic)
        thread_data.prev_cpu_time = 200;
        thread_data.current_cpu_time = 150; // Less than prev (edge case)
        thread_data.set_cpu_util(50, 4);
        assert_eq!(thread_data.cpu_util_perc, 0.0); // saturating_sub should make delta 0
    }

    #[test]
    fn test_event_data_operations() {
        // Get the current process ID
        let current_pid = std::process::id() as i32;
        let mut thread_data = ThreadData::from_tgid_tid(current_pid, current_pid, 5).unwrap();

        // Test adding event data
        thread_data.add_event_data("test_event", 42);
        thread_data.add_event_data("test_event", 84);

        // Test retrieving event data
        let data = thread_data.event_data_immut("test_event");
        assert!(!data.is_empty());
        assert!(data.contains(&42));
        assert!(data.contains(&84));

        // Test retrieving non-existent event data
        let empty_data = thread_data.event_data_immut("nonexistent_event");
        assert!(empty_data.is_empty());
    }

    #[test]
    fn test_event_data_max_size_respected() {
        // Get the current process ID
        let current_pid = std::process::id() as i32;
        let mut thread_data = ThreadData::from_tgid_tid(current_pid, current_pid, 3).unwrap();

        // Add more data than max_data_size
        for i in 1..=5 {
            thread_data.add_event_data("overflow_test", i * 10);
        }

        let data = thread_data.event_data_immut("overflow_test");
        assert_eq!(data.len(), 3); // Should respect max_data_size
                                   // Should contain the last 3 values: 30, 40, 50
        assert!(data.contains(&30));
        assert!(data.contains(&40));
        assert!(data.contains(&50));
        assert!(!data.contains(&10)); // First value should be dropped
        assert!(!data.contains(&20)); // Second value should be dropped
    }

    #[test]
    fn test_thread_data_clone() {
        // Get the current process ID
        let current_pid = std::process::id() as i32;
        let mut original = ThreadData::from_tgid_tid(current_pid, current_pid, 5).unwrap();

        // Add some event data
        original.add_event_data("clone_test", 123);

        // Clone the thread data
        let cloned = original.clone();

        // Verify the clone has the same data
        assert_eq!(cloned.tid, original.tid);
        assert_eq!(cloned.tgid, original.tgid);
        assert_eq!(cloned.thread_name, original.thread_name);
        assert_eq!(cloned.cpu, original.cpu);
        assert_eq!(cloned.max_data_size, original.max_data_size);

        // Verify event data is cloned
        let original_data = original.event_data_immut("clone_test");
        let cloned_data = cloned.event_data_immut("clone_test");
        assert_eq!(original_data, cloned_data);
    }

    #[test]
    fn test_thread_data_debug() {
        // Get the current process ID
        let current_pid = std::process::id() as i32;
        let thread_data = ThreadData::from_tgid_tid(current_pid, current_pid, 5).unwrap();

        // Verify Debug trait is implemented and doesn't panic
        let debug_string = format!("{:?}", thread_data);
        assert!(!debug_string.is_empty());
        assert!(debug_string.contains("ThreadData"));
    }

    #[test]
    fn test_multiple_events() {
        // Get the current process ID
        let current_pid = std::process::id() as i32;
        let mut thread_data = ThreadData::from_tgid_tid(current_pid, current_pid, 4).unwrap();

        // Add data to multiple events
        thread_data.add_event_data("cpu_usage", 10);
        thread_data.add_event_data("memory_usage", 20);
        thread_data.add_event_data("cpu_usage", 15);
        thread_data.add_event_data("io_usage", 30);

        // Verify each event has correct data
        let cpu_data = thread_data.event_data_immut("cpu_usage");
        assert!(cpu_data.contains(&10));
        assert!(cpu_data.contains(&15));

        let memory_data = thread_data.event_data_immut("memory_usage");
        assert!(memory_data.contains(&20));

        let io_data = thread_data.event_data_immut("io_usage");
        assert!(io_data.contains(&30));

        // Verify non-existent event returns empty
        let nonexistent_data = thread_data.event_data_immut("nonexistent");
        assert!(nonexistent_data.is_empty());
    }

    #[test]
    fn test_cpu_util_edge_cases() {
        // Get the current process ID
        let current_pid = std::process::id() as i32;
        let mut thread_data = ThreadData::from_tgid_tid(current_pid, current_pid, 5).unwrap();

        // Test with same prev and current times
        thread_data.prev_cpu_time = 100;
        thread_data.current_cpu_time = 100;
        thread_data.set_cpu_util(50, 4);
        assert_eq!(thread_data.cpu_util_perc, 0.0);

        // Test with very large numbers
        thread_data.prev_cpu_time = u64::MAX - 100;
        thread_data.current_cpu_time = u64::MAX;
        thread_data.set_cpu_util(200, 4);
        assert_eq!(thread_data.cpu_util_perc, 200.0); // 100/200 * 100 * 4 = 200%

        // Test with current time less than previous (overflow scenario)
        thread_data.prev_cpu_time = 200;
        thread_data.current_cpu_time = 100;
        thread_data.set_cpu_util(100, 4);
        assert_eq!(thread_data.cpu_util_perc, 0.0); // saturating_sub should handle this
    }
}
