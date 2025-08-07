// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use anyhow::Result;
use nix::time::{clock_gettime, ClockId};
use std::fs;
use std::io::Read;

/// Formats a byte value to human readable.
/// The input value must be in bytes, not KB or other units.
pub fn format_bytes(bytes: u64) -> String {
    const KB: f64 = 1024.0;
    const MB: f64 = KB * 1024.0;
    const GB: f64 = MB * 1024.0;
    const TB: f64 = GB * 1024.0;

    let bytes_f64 = bytes as f64;

    if bytes_f64 < KB {
        format!("{bytes}B")
    } else if bytes_f64 < MB {
        format!("{:.2}KB", bytes_f64 / KB)
    } else if bytes_f64 < GB {
        format!("{:.2}MB", bytes_f64 / MB)
    } else if bytes_f64 < TB {
        format!("{:.2}GB", bytes_f64 / GB)
    } else {
        format!("{:.2}TB", bytes_f64 / TB)
    }
}

/// Formats a KB value to human readable.
/// The input value must be in KB (kilobytes).
pub fn format_kb(kb: u64) -> String {
    // Convert KB to bytes and use the existing format_bytes function
    format_bytes(kb * 1024)
}

/// Formats a bytes per second value to human readable.
/// The input value must be in bytes per second, not KB/s or other units.
pub fn format_bytes_per_sec(bytes: u64) -> String {
    format!("{}/s", format_bytes(bytes))
}

/// Formats a number to be more readable with K, M, B suffixes.
pub fn format_number(num: u64) -> String {
    match num {
        0..=999 => format!("{num}"),
        1_000..=999_999 => format!("{:.1}K", num as f64 / 1_000.0),
        1_000_000..=999_999_999 => format!("{:.1}M", num as f64 / 1_000_000.0),
        _ => format!("{:.1}B", num as f64 / 1_000_000_000.0),
    }
}

/// Formats pagefaults in terms of memory size (assuming 4KB page size)
pub fn format_pages(pages: u64) -> String {
    // Standard page size is 4KB on most Linux systems
    const PAGE_SIZE: u64 = 4 * 1024;
    format_bytes(pages * PAGE_SIZE)
}

/// Formats a frequency value in Hz to a human-readable format
pub fn format_hz(hz: u64) -> String {
    match hz {
        0..=999 => format!("{hz}Hz"),
        1_000..=999_999 => format!("{:.0}MHz", hz as f64 / 1_000.0),
        1_000_000..=999_999_999 => format!("{:.3}GHz", hz as f64 / 1_000_000.0),
        _ => format!("{:.3}THz", hz as f64 / 1_000_000_000.0),
    }
}

/// Reads a file and returns its contents as a string
pub fn read_file_string(path: &str) -> Result<String> {
    let mut file = fs::File::open(path)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    Ok(contents)
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

/// Formats a percentage value (0.0 to 1.0) to a string with % suffix
pub fn format_percentage(value: f64) -> String {
    format!("{:.1}%", value * 100.0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_read_file_string_success() {
        let mut temp_file = NamedTempFile::new().expect("Failed to create temp file");
        let test_content = "Hello, World!\nThis is a test file.";
        temp_file
            .write_all(test_content.as_bytes())
            .expect("Failed to write to temp file");

        let result = read_file_string(temp_file.path().to_str().unwrap());
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), test_content);
    }

    #[test]
    fn test_read_file_string_nonexistent_file() {
        let result = read_file_string("/nonexistent/file/path");
        assert!(result.is_err());
    }

    #[test]
    fn test_read_file_string_empty_file() {
        let temp_file = NamedTempFile::new().expect("Failed to create temp file");

        let result = read_file_string(temp_file.path().to_str().unwrap());
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "");
    }

    #[test]
    fn test_format_hz_hz_range() {
        assert_eq!(format_hz(0), "0Hz");
        assert_eq!(format_hz(1), "1Hz");
        assert_eq!(format_hz(999), "999Hz");
    }

    #[test]
    fn test_format_hz_mhz_range() {
        assert_eq!(format_hz(1_000), "1MHz");
        assert_eq!(format_hz(1_500), "2MHz");
        assert_eq!(format_hz(999_999), "1000MHz");
    }

    #[test]
    fn test_format_hz_ghz_range() {
        assert_eq!(format_hz(1_000_000), "1.000GHz");
        assert_eq!(format_hz(1_500_000), "1.500GHz");
        assert_eq!(format_hz(2_400_000), "2.400GHz");
        assert_eq!(format_hz(999_999_999), "1000.000GHz");
    }

    #[test]
    fn test_format_hz_thz_range() {
        assert_eq!(format_hz(1_000_000_000), "1.000THz");
        assert_eq!(format_hz(1_500_000_000), "1.500THz");
        assert_eq!(
            format_hz(u64::MAX),
            format!("{:.3}THz", u64::MAX as f64 / 1_000_000_000.0)
        );
    }

    #[test]
    fn test_get_clock_value() {
        // Test with CLOCK_MONOTONIC (should always be available on Linux)
        let time1 = get_clock_value(libc::CLOCK_MONOTONIC);
        let time2 = get_clock_value(libc::CLOCK_MONOTONIC);

        // Time should be positive and monotonically increasing
        assert!(time1 > 0);
        assert!(time2 >= time1);
    }

    #[test]
    fn test_sanitize_nbsp_with_nbsp() {
        let input = "Hello\u{202F}World\u{202F}Test".to_string();
        let expected = "Hello World Test".to_string();
        assert_eq!(sanitize_nbsp(input), expected);
    }

    #[test]
    fn test_sanitize_nbsp_without_nbsp() {
        let input = "Hello World Test".to_string();
        let expected = "Hello World Test".to_string();
        assert_eq!(sanitize_nbsp(input), expected);
    }

    #[test]
    fn test_sanitize_nbsp_empty_string() {
        let input = "".to_string();
        let expected = "".to_string();
        assert_eq!(sanitize_nbsp(input), expected);
    }

    #[test]
    fn test_sanitize_nbsp_only_nbsp() {
        let input = "\u{202F}\u{202F}\u{202F}".to_string();
        let expected = "   ".to_string();
        assert_eq!(sanitize_nbsp(input), expected);
    }

    #[test]
    fn test_u32_to_i32_valid_conversion() {
        assert_eq!(u32_to_i32(0), 0);
        assert_eq!(u32_to_i32(1), 1);
        assert_eq!(u32_to_i32(i32::MAX as u32), i32::MAX);
    }

    #[test]
    #[should_panic(expected = "u32 to i32 conversion failed")]
    fn test_u32_to_i32_overflow() {
        u32_to_i32(u32::MAX);
    }

    #[test]
    #[should_panic(expected = "u32 to i32 conversion failed")]
    fn test_u32_to_i32_just_over_max() {
        u32_to_i32((i32::MAX as u32) + 1);
    }
}
