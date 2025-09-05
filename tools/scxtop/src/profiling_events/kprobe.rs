// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use anyhow::Result;
use scx_utils::compat::tracefs_mount;
use std::fs::File;
use std::io::{BufRead, BufReader};

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct KprobeEvent {
    pub cpu: usize,
    pub event_name: String,
    pub count: u64,
    pub instruction_pointer: Option<u64>,
}

impl KprobeEvent {
    pub fn new(event_name: String, cpu: usize) -> Self {
        let instruction_pointer = resolve_kfunc_address(&event_name);
        Self {
            event_name,
            cpu,
            count: 0,
            instruction_pointer,
        }
    }

    pub fn increment_by(&mut self, stride: u64) {
        self.count += stride;
    }

    pub fn value(&mut self, reset: bool) -> Result<u64> {
        let count = self.count;
        if reset {
            self.count = 0;
        }
        Ok(count)
    }
}

fn resolve_kfunc_address(name: &str) -> Option<u64> {
    let file = File::open("/proc/kallsyms")
        .expect("Failed to open /proc/kallsyms. Make sure CONFIG_KALLSYMS is enabled.");
    let reader = BufReader::new(file);
    for line in reader.lines().map_while(std::io::Result::ok) {
        if line.ends_with(&format!(" {name}")) {
            if let Some(addr_str) = line.split_whitespace().next() {
                if let Ok(addr) = u64::from_str_radix(addr_str, 16) {
                    return Some(addr);
                }
            }
        }
    }
    None
}

/// Returns the available kprobe events on the system from tracefs.
/// For non-root users, returns an empty list to allow graceful degradation.
pub fn available_kprobe_events() -> Result<Vec<String>> {
    match tracefs_mount() {
        Ok(path) => {
            match File::open(path.join("available_filter_functions")) {
                Ok(file) => {
                    let reader = BufReader::new(file);
                    let mut events = Vec::new();

                    for line in reader.lines() {
                        let line = line?;
                        if let Some(func) = line.split_whitespace().next() {
                            events.push(func.to_string());
                        }
                    }

                    Ok(events)
                }
                Err(_) => {
                    // Permission denied or file not accessible - return empty list for graceful degradation
                    Ok(Vec::new())
                }
            }
        }
        Err(_) => {
            // Cannot access tracefs - return empty list for graceful degradation
            Ok(Vec::new())
        }
    }
}
