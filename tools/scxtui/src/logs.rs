// SPDX-License-Identifier: GPL-2.0

//! Journal access for the log view.
//!
//! Spawns `journalctl` as a one-shot subprocess with `--output=json` rather
//! than linking sd-journal bindings: no libsystemd build dependency, and the
//! JSON output carries `PRIORITY` reliably, which drives the coloring.
//! Multi-line messages (scheduler `Opts { ... }` dumps and the like) are
//! flattened into display lines here, with continuations marked so the UI
//! can indent or fold them.

use anyhow::{Context, Result, bail};
use chrono::TimeZone;

use crate::backend::service::system_command;

/// The unit the log view inspects: the scheduler runs as its main process,
/// so its stdout/stderr land in the unit's journal.
pub const UNIT: &str = crate::backend::service::UNIT;

/// One display line of the log view.
pub struct LogLine {
    /// Local wall-clock time, `HH:MM:SS`. Empty for continuation lines.
    pub time: String,
    /// syslog priority (0-7); 6 (info) when the entry carries none.
    pub priority: u8,
    pub text: String,
    /// Second and further lines of a multi-line journal entry.
    pub continuation: bool,
}

/// Tail limit for a single journal fetch. Without it, a chatty scheduler
/// on a long-running boot can hand back tens of megabytes of JSON, all
/// parsed synchronously while the UI is frozen. The newest entries are
/// what the view opens on anyway; anything older is `journalctl`'s job.
const MAX_ENTRIES: usize = 5000;

/// Result of one journal fetch: flattened display lines plus whether the
/// tail limit cut the beginning off, so the UI can say so.
pub struct LogFetch {
    pub lines: Vec<LogLine>,
    pub truncated: bool,
}

/// Fetches the journal tail for `unit` (up to [`MAX_ENTRIES`] entries),
/// current boot or the previous one, and flattens it into display lines
/// (oldest first).
pub fn fetch(unit: &str, previous_boot: bool) -> Result<LogFetch> {
    let boot = if previous_boot { "-1" } else { "0" };
    let limit = MAX_ENTRIES.to_string();
    let output = system_command("journalctl")?
        .args([
            "--unit",
            unit,
            "--boot",
            boot,
            "--lines",
            &limit,
            "--output=json",
            "--no-pager",
            "--quiet",
        ])
        .output()
        .context("failed to run journalctl — is this a systemd system?")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stderr = stderr.trim();
        // journalctl exits non-zero e.g. when boot -1 is absent (volatile
        // journal) — surface its own wording, it is usually clear enough.
        bail!(
            "journalctl failed{}{}",
            if stderr.is_empty() { "" } else { ": " },
            stderr
        );
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    // `--lines` limits journal *entries*; display lines can be more after
    // multi-line flattening. Hitting the entry count exactly means the
    // tail almost certainly cut something off.
    let entries = stdout.lines().filter(|line| !line.is_empty()).count();
    Ok(LogFetch {
        lines: parse_entries(&stdout),
        truncated: entries >= MAX_ENTRIES,
    })
}

/// Pure parsing core: one `journalctl --output=json` line per entry in,
/// flattened display lines out. Malformed entries are skipped rather than
/// failing the whole view.
fn parse_entries(stdout: &str) -> Vec<LogLine> {
    let mut lines = Vec::new();
    for raw in stdout.lines() {
        if raw.is_empty() {
            continue;
        }
        let Ok(entry) = serde_json::from_str::<serde_json::Value>(raw) else {
            continue;
        };

        let priority = entry
            .get("PRIORITY")
            .and_then(|p| p.as_str())
            .and_then(|p| p.parse().ok())
            .unwrap_or(6);
        let time = entry
            .get("__REALTIME_TIMESTAMP")
            .and_then(|t| t.as_str())
            .and_then(|t| t.parse::<i64>().ok())
            .map(format_local_time)
            .unwrap_or_default();
        // MESSAGE is a JSON string for UTF-8 payloads and a byte array
        // otherwise (journald convention); handle both.
        let message = match entry.get("MESSAGE") {
            Some(serde_json::Value::String(s)) => s.clone(),
            Some(serde_json::Value::Array(bytes)) => {
                let raw: Vec<u8> = bytes
                    .iter()
                    .filter_map(|b| b.as_u64().and_then(|b| u8::try_from(b).ok()))
                    .collect();
                String::from_utf8_lossy(&raw).into_owned()
            }
            _ => continue,
        };

        for (i, text) in message.lines().enumerate() {
            lines.push(LogLine {
                time: if i == 0 { time.clone() } else { String::new() },
                priority,
                text: text.to_owned(),
                continuation: i > 0,
            });
        }
    }
    lines
}

fn format_local_time(usec: i64) -> String {
    chrono::Local
        .timestamp_opt(usec / 1_000_000, 0)
        .single()
        .map(|dt| dt.format("%H:%M:%S").to_string())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_priority_with_info_default() {
        let entries = parse_entries(concat!(
            r#"{"PRIORITY":"3","MESSAGE":"boom"}"#,
            "\n",
            r#"{"MESSAGE":"plain"}"#,
        ));
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].priority, 3);
        assert_eq!(entries[1].priority, 6);
    }

    #[test]
    fn flattens_multiline_messages() {
        let entries = parse_entries(
            r#"{"PRIORITY":"6","MESSAGE":"Opts {\n  verbose: 0,\n}","__REALTIME_TIMESTAMP":"1753000000000000"}"#,
        );
        assert_eq!(entries.len(), 3);
        assert!(!entries[0].continuation);
        assert!(entries[1].continuation && entries[2].continuation);
        assert_eq!(entries[1].time, "");
        assert_eq!(entries[1].text, "  verbose: 0,");
        // Continuation lines inherit the entry's priority.
        assert_eq!(entries[2].priority, 6);
    }

    #[test]
    fn decodes_byte_array_messages() {
        let entries = parse_entries(r#"{"MESSAGE":[104,105]}"#);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].text, "hi");
    }

    #[test]
    fn skips_malformed_and_empty_lines() {
        let entries = parse_entries("not json\n\n{\"MESSAGE\":\"ok\"}\n{\"NO_MESSAGE\":true}");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].text, "ok");
    }
}
