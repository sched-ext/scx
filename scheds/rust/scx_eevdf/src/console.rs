// SPDX-License-Identifier: GPL-2.0
//
// Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.

// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

//! The console style shared by the startup report, the stats blocks and the
//! status lines: a header line of `|`-separated fields, then aligned rows.
//! Every line goes through the logger at info level, so it carries the same
//! time stamp and prefix as any other message, in plain ASCII, appended and
//! never redrawn.

use log::info;

/// One line of output, through the logger.
pub fn emit(line: &str) {
    info!("{line}");
}

/// The header line: the scheduler name and version, then the caller's
/// fields.
pub fn header(fields: &[String]) -> String {
    let mut parts = vec![format!(
        "{} {}",
        crate::SCHEDULER_NAME,
        env!("CARGO_PKG_VERSION")
    )];
    parts.extend(fields.iter().cloned());
    parts.join(" | ")
}

/// The running kernel's release string, what uname -r prints.
pub fn kernel_release() -> String {
    let mut uts: libc::utsname = unsafe { std::mem::zeroed() };
    if unsafe { libc::uname(&mut uts) } != 0 {
        return "unknown".to_string();
    }
    unsafe { std::ffi::CStr::from_ptr(uts.release.as_ptr()) }
        .to_string_lossy()
        .into_owned()
}

/// One status line: the scheduler is attached and running, or it has
/// stopped and why.
pub fn status(msg: &str) {
    emit(&format!("{} {}", crate::SCHEDULER_NAME, msg));
}

/// A block of aligned `key  value` rows under a header, printed once.
pub struct Report {
    fields: Vec<String>,
    rows: Vec<(String, String)>,
}

impl Report {
    pub fn new() -> Self {
        Self {
            fields: Vec::new(),
            rows: Vec::new(),
        }
    }

    /// A header field, after the name and version.
    pub fn field(&mut self, s: impl Into<String>) {
        self.fields.push(s.into());
    }

    pub fn row(&mut self, key: impl Into<String>, value: impl std::fmt::Display) {
        self.rows.push((key.into(), value.to_string()));
    }

    pub fn print(&self) {
        emit(&header(&self.fields));
        let width = self.rows.iter().map(|(k, _)| k.len()).max().unwrap_or(0);
        for (key, value) in &self.rows {
            emit(&format!("{key:<width$}  {value}"));
        }
    }
}
