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

/// Formats bytes to human readable format (B, KB, MB, GB, TB).
pub fn format_bytes(bytes: u64) -> String {
    const KB: f64 = 1024.0;
    const MB: f64 = KB * 1024.0;
    const GB: f64 = MB * 1024.0;
    const TB: f64 = GB * 1024.0;

    let bytes_f64 = bytes as f64;

    match bytes_f64 {
        b if b < KB => format!("{} B", bytes),
        b if b < MB => format!("{:.2} KB", b / KB),
        b if b < GB => format!("{:.2} MB", b / MB),
        b if b < TB => format!("{:.2} GB", b / GB),
        b => format!("{:.2} TB", b / TB),
    }
}

/// Formats bytes to human readable bits format (bps, Kbps, Mbps, Gbps, Tbps).
/// Converts bytes to bits (multiply by 8) and uses decimal units (1000) for network standards.
pub fn format_bits(bytes: u64) -> String {
    const KBPS: f64 = 1000.0;
    const MBPS: f64 = KBPS * 1000.0;
    const GBPS: f64 = MBPS * 1000.0;
    const TBPS: f64 = GBPS * 1000.0;

    let bits = (bytes as f64) * 8.0; // Convert bytes to bits

    match bits {
        b if b < KBPS => format!("{:.0} bps", b),
        b if b < MBPS => format!("{:.2} Kbps", b / KBPS),
        b if b < GBPS => format!("{:.2} Mbps", b / MBPS),
        b if b < TBPS => format!("{:.2} Gbps", b / GBPS),
        b => format!("{:.2} Tbps", b / TBPS),
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

/// Converts a u32 to a i32, panics on failure
pub fn u32_to_i32(x: u32) -> i32 {
    i32::try_from(x).expect("u32 to i32 conversion failed")
}
