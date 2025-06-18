// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use anyhow::Result;
use std::fs::File;
use std::io::{BufRead, BufReader};
use scx_utils::compat::tracefs_mount;

use crate::Search;

pub struct AllKprobeEvents {
    entries: Search,
}

impl AllKprobeEvents {
    pub fn new() -> Result<Self> {
        let kprobe_events = available_kprobe_events()?;
        Ok(Self { entries: Search::new(kprobe_events) })
    }

    pub fn is_valid_kprobe_event(&self, event: &str) -> bool {
        self.entries.binary_search(&event.to_string()).is_some()
    }

    pub fn are_valid_kprobe_events(&self, events: &[String]) -> bool {
        events.iter().all(|e| self.is_valid_kprobe_event(e))
    }
}

/// Returns the available kprobe events on the system from tracefs.
pub fn available_kprobe_events() -> Result<Vec<String>> {
    let path = tracefs_mount()?;
    let file = File::open(path.join("available_filter_functions"))?;
    let reader = BufReader::new(file);

    let mut events = Vec::new();

    for line in reader.lines() {
        let line = line?;
        events.push(line);
    }

    Ok(events)
}
