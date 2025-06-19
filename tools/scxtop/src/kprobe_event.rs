// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use anyhow::Result;
use scx_utils::compat::tracefs_mount;
use std::fs::File;
use std::io::{BufRead, BufReader};

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
