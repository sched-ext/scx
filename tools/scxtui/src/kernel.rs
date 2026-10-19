// SPDX-License-Identifier: GPL-2.0

//! The kernel's own view of `sched_ext`, read straight from sysfs.
//!
//! `scx.service` only knows whether its unit is active; the kernel knows
//! what is actually attached. Reading `/sys/kernel/sched_ext` lets the UI
//! show ground truth and flag disagreements — a scheduler launched by hand
//! next to the service, a scheduler that got kicked out by the watchdog
//! while the unit is still active, and so on. Everything here is plain
//! world-readable sysfs, so no privileges are needed.

use std::fs;
use std::path::Path;

use anyhow::{Context, Result};

const SYSFS_DIR: &str = "/sys/kernel/sched_ext";

pub struct KernelState {
    /// Contents of `state`: "enabled", "disabled", or a transitional value
    /// ("enabling"/"disabling") if we catch a switch mid-flight.
    pub state: String,
    /// BPF ops name from `root/ops` when a scheduler is attached — the name
    /// the scheduler registered with, typically without the `scx_` prefix
    /// (e.g. "lavd" for `scx_lavd`).
    pub ops: Option<String>,
}

impl KernelState {
    pub fn enabled(&self) -> bool {
        self.state == "enabled"
    }

    /// Whether `sched_name` (full name, e.g. `scx_lavd`) plausibly matches
    /// the ops the kernel reports. Ops names are chosen by each scheduler
    /// and some embed extra detail, with or without the `scx_` prefix —
    /// bpfland registers e.g. `bpfland_1.1.2_x86_64_unknown_linux_gnu`,
    /// flow registers `scx_flow_3.1.1_x86_64_unknown_linux_gnu` — so
    /// beyond an exact match (with or without the prefix) an ops name
    /// that *starts with* either form of the scheduler name followed by
    /// `_` also counts. Used for a soft warning only, so a rare false
    /// negative is acceptable.
    pub fn matches(&self, sched_name: &str) -> bool {
        let stripped = sched_name.strip_prefix("scx_").unwrap_or(sched_name);
        self.ops.as_deref().is_some_and(|ops| {
            ops == sched_name
                || ops == stripped
                || ops
                    .strip_prefix(sched_name)
                    .is_some_and(|rest| rest.starts_with('_'))
                || ops
                    .strip_prefix(stripped)
                    .is_some_and(|rest| rest.starts_with('_'))
        })
    }
}

/// Reads the kernel's `sched_ext` state. `Ok(None)` means the sysfs
/// directory is absent, i.e. the running kernel was built without
/// `sched_ext`; `Err` means it is there but `state` could not be read,
/// which is a different fact and must not be reported as the former.
/// `root/ops` is absent while nothing is attached, so NotFound on it is
/// not an error; any other failure on it is.
pub fn read() -> Result<Option<KernelState>> {
    let dir = Path::new(SYSFS_DIR);
    if !dir.is_dir() {
        return Ok(None);
    }
    let state = fs::read_to_string(dir.join("state"))
        .with_context(|| format!("cannot read {}/state", dir.display()))?
        .trim()
        .to_owned();
    // `root/ops` exists only while a scheduler is attached, so NotFound
    // is the normal "nothing attached" answer; any other failure is a
    // broken observation and must not pass for one.
    let ops = match fs::read_to_string(dir.join("root/ops")) {
        Ok(s) => Some(s.trim().to_owned()).filter(|s| !s.is_empty()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => None,
        Err(err) => {
            return Err(err).with_context(|| format!("cannot read {}/root/ops", dir.display()));
        }
    };
    Ok(Some(KernelState { state, ops }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn enabled_with(ops: Option<&str>) -> KernelState {
        KernelState {
            state: "enabled".to_owned(),
            ops: ops.map(str::to_owned),
        }
    }

    #[test]
    fn matches_stripped_ops_name() {
        assert!(enabled_with(Some("lavd")).matches("scx_lavd"));
    }

    #[test]
    fn matches_full_ops_name() {
        assert!(enabled_with(Some("scx_lavd")).matches("scx_lavd"));
    }

    #[test]
    fn matches_versioned_ops_suffix() {
        // bpfland registers e.g. "bpfland_1.1.2_x86_64_unknown_linux_gnu".
        assert!(
            enabled_with(Some("bpfland_1.1.2_x86_64_unknown_linux_gnu")).matches("scx_bpfland")
        );
    }

    #[test]
    fn matches_versioned_ops_suffix_with_prefix() {
        // flow keeps the scx_ prefix in its versioned ops name.
        assert!(enabled_with(Some("scx_flow_3.1.1_x86_64_unknown_linux_gnu")).matches("scx_flow"));
    }

    #[test]
    fn rejects_full_name_prefix_without_separator() {
        assert!(!enabled_with(Some("scx_flowmatic_1.0")).matches("scx_flow"));
    }

    #[test]
    fn rejects_a_different_scheduler() {
        assert!(!enabled_with(Some("flow_1.0")).matches("scx_flash"));
    }

    #[test]
    fn rejects_prefix_without_separator() {
        assert!(!enabled_with(Some("bpflandish")).matches("scx_bpfland"));
    }

    #[test]
    fn no_ops_never_matches() {
        assert!(!enabled_with(None).matches("scx_lavd"));
    }
}
