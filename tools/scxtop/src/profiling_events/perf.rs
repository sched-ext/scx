// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use crate::config::Config;

use anyhow::anyhow;
use anyhow::Context;
use anyhow::Result;
use libc::{close, read};
use scx_utils::compat::tracefs_mount;
use scx_utils::perf;

use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::mem;
use std::path::Path;
use std::str::FromStr;

#[allow(dead_code)]
const PERF_SAMPLE_ID: u64 = 1 << 16;
#[allow(dead_code)]
const PERF_FORMAT_TOTAL_TIME_ENABLED: u64 = 1 << 0;
#[allow(dead_code)]
const PERF_FORMAT_TOTAL_TIME_RUNNING: u64 = 1 << 1;

/// Reads a file and returns the u64 value from a file.
pub fn read_file_u64<P: AsRef<Path>>(path: P) -> Result<u64> {
    let path = path.as_ref();
    let contents = fs::read_to_string(path)
        .with_context(|| format!("Failed to read file: {}", path.display()))?;

    let trimmed_contents = contents.trim();

    u64::from_str(trimmed_contents)
        .with_context(|| format!("Failed to parse u64 from '{}'", contents))
}

/// Returns the config value for the perf event.
pub fn perf_event_config(subsystem: &str, event: &str) -> Result<u64> {
    let path = tracefs_mount()?;
    let event_path = path.join("events").join(subsystem).join(event).join("id");
    read_file_u64(event_path)
}

#[derive(Debug, Clone)]
pub struct PerfEvent {
    pub subsystem: String,
    pub event: String,
    pub cpu: usize,
    pub alias: String,
    pub use_config: bool,
    pub event_type: u32,
    config: u64,
    fd: usize,
    freq: usize,
}

impl Drop for PerfEvent {
    /// Closes the perf event context if running.
    fn drop(&mut self) {
        if self.fd > 0 {
            unsafe {
                close(self.fd as i32);
            }
        }
    }
}

impl PerfEvent {
    /// Creates a PerfEvent.
    pub fn new(subsystem: String, event: String, cpu: usize) -> Self {
        Self {
            subsystem,
            event,
            cpu,
            alias: "".to_string(),
            config: 0,
            event_type: 0,
            use_config: false,
            fd: 0,
            freq: 0,
        }
    }

    /// Returns a set of PerfEvents from a Config.
    pub fn from_config(config: &Config) -> Result<Vec<PerfEvent>> {
        let mut events = vec![];
        for event_config in &config.perf_events {
            let split: Vec<&str> = event_config.split(":").collect();
            if split.len() != 3 {
                return Err(anyhow!("Invalid event config: {}", event_config));
            }
            let alias = split.first().expect("can't happen").to_string();
            let config = u64::from_str_radix(split[1].to_string().trim_start_matches("0x"), 16)?;
            let event_type = u32::from_str(split[2])?;
            events.push(PerfEvent {
                subsystem: "".to_string(),
                event: "".to_string(),
                cpu: 0,
                alias,
                config,
                use_config: true,
                event_type,
                fd: 0,
                freq: 0,
            });
        }

        Ok(events)
    }

    /// Returns the set of default hardware events.
    pub fn default_hw_events() -> Vec<PerfEvent> {
        vec![
            PerfEvent::new("hw".to_string(), "cycles".to_string(), 0),
            PerfEvent::new("hw".to_string(), "branches".to_string(), 0),
            PerfEvent::new("hw".to_string(), "branch-misses".to_string(), 0),
            PerfEvent::new("hw".to_string(), "cache-misses".to_string(), 0),
            PerfEvent::new("hw".to_string(), "cache-references".to_string(), 0),
            PerfEvent::new("hw".to_string(), "instructions".to_string(), 0),
            PerfEvent::new("hw".to_string(), "ref-cycles".to_string(), 0),
            PerfEvent::new("hw".to_string(), "stalled-cycles-backend".to_string(), 0),
            PerfEvent::new("hw".to_string(), "stalled-cycles-frontend".to_string(), 0),
            PerfEvent::new("hw".to_string(), "bus-cycles".to_string(), 0),
            PerfEvent::new("hw".to_string(), "L1-dcache-load-misses".to_string(), 0),
        ]
    }

    /// Returns the set of default software events.
    pub fn default_sw_events() -> Vec<PerfEvent> {
        vec![
            PerfEvent::new("sw".to_string(), "cpu-clock".to_string(), 0),
            PerfEvent::new("sw".to_string(), "task-clock".to_string(), 0),
            PerfEvent::new("sw".to_string(), "context-switches".to_string(), 0),
            PerfEvent::new("sw".to_string(), "page-faults".to_string(), 0),
            PerfEvent::new("sw".to_string(), "minor-faults".to_string(), 0),
            PerfEvent::new("sw".to_string(), "major-faults".to_string(), 0),
            PerfEvent::new("sw".to_string(), "migrations".to_string(), 0),
        ]
    }

    /// Returns the set of default hardware and software events.
    pub fn default_events() -> Vec<PerfEvent> {
        let mut avail_events = PerfEvent::default_hw_events();
        avail_events.append(&mut PerfEvent::default_sw_events());

        avail_events
    }

    /// Returns the event name.
    pub fn event_name(&self) -> &str {
        if self.use_config {
            &self.alias
        } else {
            &self.event
        }
    }

    /// Attaches a PerfEvent struct.
    pub fn attach(&mut self, process_id: i32) -> Result<()> {
        let mut attrs = scx_utils::perf::bindings::perf_event_attr {
            size: std::mem::size_of::<perf::bindings::perf_event_attr>() as u32,
            ..Default::default()
        };

        match self.subsystem.to_lowercase().as_str() {
            "hw" | "hardware" => {
                attrs.type_ = perf::bindings::PERF_TYPE_HARDWARE;
                match self.event.to_lowercase().as_str() {
                    "branches" | "branch-instructions" => {
                        attrs.config = perf::bindings::PERF_COUNT_HW_BRANCH_INSTRUCTIONS as u64;
                    }
                    "branch-misses" => {
                        attrs.config = perf::bindings::PERF_COUNT_HW_BRANCH_MISSES as u64;
                    }
                    "cache-misses" => {
                        attrs.config = perf::bindings::PERF_COUNT_HW_CACHE_MISSES as u64;
                    }
                    "cache-references" => {
                        attrs.config = perf::bindings::PERF_COUNT_HW_CACHE_REFERENCES as u64;
                    }
                    "cycles" | "cpu-cycles" | "cpu_cycles" => {
                        attrs.config = perf::bindings::PERF_COUNT_HW_CPU_CYCLES as u64;
                    }
                    "instructions" | "instr" => {
                        attrs.config = perf::bindings::PERF_COUNT_HW_INSTRUCTIONS as u64;
                    }
                    "ref-cycles" => {
                        attrs.config = perf::bindings::PERF_COUNT_HW_REF_CPU_CYCLES as u64;
                    }
                    "stalled-cycles-backend" => {
                        attrs.config = perf::bindings::PERF_COUNT_HW_STALLED_CYCLES_BACKEND as u64;
                    }
                    "stalled-cycles-frontend" => {
                        attrs.config = perf::bindings::PERF_COUNT_HW_STALLED_CYCLES_FRONTEND as u64;
                    }
                    "bus-cycles" | "bus_cycles" => {
                        attrs.config = perf::bindings::PERF_COUNT_HW_BUS_CYCLES as u64;
                    }
                    "l1-dcache-load-misses" => {
                        attrs.config = perf::bindings::PERF_COUNT_HW_CACHE_RESULT_MISS as u64;
                    }
                    _ => {
                        return Err(anyhow!("unknown event"));
                    }
                }
            }
            "sw" | "software" => {
                attrs.type_ = perf::bindings::PERF_TYPE_SOFTWARE;
                match self.event.to_lowercase().as_str() {
                    "cs" | "context-switches" => {
                        attrs.config = perf::bindings::PERF_COUNT_SW_CONTEXT_SWITCHES as u64;
                    }
                    "cpu-clock" => {
                        attrs.config = perf::bindings::PERF_COUNT_SW_CPU_CLOCK as u64;
                    }
                    "task-clock" => {
                        attrs.config = perf::bindings::PERF_COUNT_SW_TASK_CLOCK as u64;
                    }
                    "page-faults" | "faults" => {
                        attrs.config = perf::bindings::PERF_COUNT_SW_PAGE_FAULTS as u64;
                    }
                    "minor-faults" => {
                        attrs.config = perf::bindings::PERF_COUNT_SW_PAGE_FAULTS_MIN as u64;
                    }
                    "major-faults" => {
                        attrs.config = perf::bindings::PERF_COUNT_SW_PAGE_FAULTS_MAJ as u64;
                    }
                    "migrations" | "cpu-migrations" => {
                        attrs.config = perf::bindings::PERF_COUNT_SW_CPU_MIGRATIONS as u64;
                    }
                    _ => {
                        return Err(anyhow!("unknown event"));
                    }
                }
            }
            _ => {
                if self.use_config {
                    attrs.type_ = self.event_type;
                    attrs.config = self.config
                } else {
                    // Not a hardware or software event so get the event type.
                    let config = perf_event_config(&self.subsystem, &self.event)?;
                    attrs.type_ = perf::bindings::PERF_TYPE_TRACEPOINT;
                    attrs.config = config as u64;
                }
            }
        }

        attrs.set_freq(
            self.freq
                .try_into()
                .expect("Failed to set freq on perf_event_attr"),
        );
        attrs.set_disabled(0);
        attrs.set_exclude_kernel(0);
        attrs.set_exclude_hv(0);
        attrs.set_inherit(if process_id == -1 { 1 } else { 0 });
        attrs.set_pinned(1);

        let result =
            unsafe { perf::perf_event_open(&mut attrs, process_id, self.cpu as i32, -1, 0) };

        if result < 0 {
            return Err(anyhow!("failed to open perf event: {}", result));
        }

        unsafe {
            if perf::ioctls::enable(result, 0) < 0 {
                return Err(anyhow!("failed to enable perf event: {}", self.event));
            }
        }

        self.fd = result as usize;
        Ok(())
    }

    /// Returns the value of the perf event.
    pub fn value(&mut self, reset: bool) -> Result<u64> {
        let mut count: u64 = 0;
        let size = mem::size_of::<u64>();
        unsafe {
            if read(
                self.fd as i32,
                &mut count as *mut _ as *mut libc::c_void,
                size,
            ) != size as isize
            {
                return Err(anyhow!("failed to read perf event {:?}", self));
            }
            if reset && perf::ioctls::reset(self.fd as i32, 0) < 0 {
                return Err(anyhow!("failed to reset perf event: {}", self.event));
            }
        }
        Ok(count)
    }
}

/// Returns the available perf events on the system from tracefs.
pub fn available_perf_events() -> Result<BTreeMap<String, HashSet<String>>> {
    let path = tracefs_mount()?;
    let file = File::open(path.join("available_events"))?;
    let reader = BufReader::new(file);

    let mut events = BTreeMap::new();

    for line in reader.lines() {
        let line = line?;

        // perf events are formatted in <subsystem>:<event> format
        let mut words = line.split(":");
        let subsystem = words
            .next()
            .context("failed to parse perf event subsystem")?;
        let event = words.next().context("failed to parse perf event")?;
        events
            .entry(subsystem.to_string())
            .or_insert(HashSet::new())
            .insert(event.to_string());
    }

    Ok(events)
}
