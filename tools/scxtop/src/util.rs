// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use anyhow::Result;
use nix::time::{clock_gettime, ClockId};
use std::fs;
use std::io::Read;

/// Returns the file content as a String.
pub fn read_file_string(path: &str) -> Result<String> {
    let mut file = fs::File::open(path)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    Ok(contents)
}

/// Formats a value in hz to human readable.
pub fn format_hz(hz: u64) -> String {
    match hz {
        0..=999 => format!("{hz}Hz"),
        1_000..=999_999 => format!("{:.0}MHz", hz as f64 / 1_000.0),
        1_000_000..=999_999_999 => format!("{:.3}GHz", hz as f64 / 1_000_000.0),
        _ => format!("{:.3}THz", hz as f64 / 1_000_000_000.0),
    }
}

/// Returns the current clock_id time in nanoseconds.
pub fn get_clock_value(clock_id: libc::c_int) -> u64 {
    let ts = clock_gettime(ClockId::from_raw(clock_id)).expect("Failed to get clock time");
    (ts.tv_sec() as u64 * 1_000_000_000) + ts.tv_nsec() as u64
}

/// Replaces non-breaking spaces with regular spaces. [TEMPORARY]
pub fn sanitize_nbsp(s: String) -> String {
    s.replace('\u{202F}', " ")
}
