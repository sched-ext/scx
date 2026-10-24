// SPDX-License-Identifier: GPL-2.0

//! The kernel's own view of `sched_ext`, from sysfs. The unit only knows
//! whether it is active; the kernel knows what is attached. Plain
//! world-readable files, no privileges needed.

use std::fs;
use std::io::ErrorKind;
use std::path::Path;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

const SYSFS_DIR: &str = "/sys/kernel/sched_ext";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KernelState {
    /// `state`: "enabled", "disabled", or a transitional value.
    pub state: String,
    /// `root/ops` while a scheduler is attached: the name it registered
    /// with, typically without the `scx_` prefix.
    pub ops: Option<String>,
}

impl KernelState {
    pub fn enabled(&self) -> bool {
        self.state == "enabled"
    }

    /// Whether `sched` (full name, e.g. `scx_lavd`) plausibly matches the
    /// ops the kernel reports. Ops names are chosen by each scheduler and
    /// some embed a version, with or without the prefix (bpfland registers
    /// `bpfland_1.1.2_x86_64_unknown_linux_gnu`, flow
    /// `scx_flow_3.1.1_...`), so beyond an exact match an ops name that
    /// starts with either form of the name followed by `_` counts.
    pub fn matches(&self, sched: &str) -> bool {
        let stripped = sched.strip_prefix("scx_").unwrap_or(sched);
        self.ops.as_deref().is_some_and(|ops| {
            ops == sched
                || ops == stripped
                || ops
                    .strip_prefix(sched)
                    .is_some_and(|rest| rest.starts_with('_'))
                || ops
                    .strip_prefix(stripped)
                    .is_some_and(|rest| rest.starts_with('_'))
        })
    }
}

/// `Ok(None)` means the kernel has no `sched_ext`; `Err` means it does
/// but the state could not be read. `root/ops` is absent while nothing
/// is attached, so NotFound on it is the normal answer.
pub fn read() -> Result<Option<KernelState>> {
    read_at(Path::new(SYSFS_DIR))
}

pub fn read_at(dir: &Path) -> Result<Option<KernelState>> {
    if !dir.is_dir() {
        return Ok(None);
    }
    let state = fs::read_to_string(dir.join("state"))
        .with_context(|| format!("cannot read {}/state", dir.display()))?
        .trim()
        .to_owned();
    let ops = match fs::read_to_string(dir.join("root/ops")) {
        Ok(s) => Some(s.trim().to_owned()).filter(|s| !s.is_empty()),
        Err(err) if err.kind() == ErrorKind::NotFound => None,
        Err(err) => {
            return Err(err).with_context(|| format!("cannot read {}/root/ops", dir.display()));
        }
    };
    Ok(Some(KernelState { state, ops }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn with(ops: Option<&str>) -> KernelState {
        KernelState {
            state: "enabled".into(),
            ops: ops.map(str::to_owned),
        }
    }

    #[test]
    fn ops_names_match_with_or_without_prefix_and_version() {
        assert!(with(Some("lavd")).matches("scx_lavd"));
        assert!(with(Some("scx_lavd")).matches("scx_lavd"));
        assert!(with(Some("bpfland_1.1.2_x86_64_unknown_linux_gnu")).matches("scx_bpfland"));
        assert!(with(Some("scx_flow_3.1.1_x86_64")).matches("scx_flow"));
        assert!(!with(Some("scx_flowmatic_1.0")).matches("scx_flow"));
        assert!(!with(Some("flow_1.0")).matches("scx_flash"));
        assert!(!with(Some("bpflandish")).matches("scx_bpfland"));
        assert!(!with(None).matches("scx_lavd"));
    }

    #[test]
    fn sysfs_is_read_as_the_kernel_writes_it() {
        let dir = std::env::temp_dir().join(format!("scx_profiles-sysfs-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        assert_eq!(read_at(&dir).unwrap(), None);
        fs::create_dir_all(dir.join("root")).unwrap();
        fs::write(dir.join("state"), "disabled\n").unwrap();
        assert_eq!(
            read_at(&dir).unwrap(),
            Some(KernelState {
                state: "disabled".into(),
                ops: None
            })
        );
        fs::write(dir.join("state"), "enabled\n").unwrap();
        fs::write(dir.join("root/ops"), "lavd\n").unwrap();
        let state = read_at(&dir).unwrap().unwrap();
        assert!(state.enabled());
        assert_eq!(state.ops.as_deref(), Some("lavd"));
        let _ = fs::remove_dir_all(&dir);
    }
}
