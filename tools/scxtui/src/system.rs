// SPDX-License-Identifier: GPL-2.0

//! Programs scxtui starts (`scxcli`, `pkexec`, `journalctl`, `scxtop`),
//! resolved in systemd's default search path rather than scxtui's PATH.
//! scxtui may run as root, and a user-writable directory ahead of
//! `/usr/bin` in root's PATH would let anyone substitute one of them.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};

/// Where `systemd-path` lives. Called by absolute path with a cleared
/// environment, so the directory list scxtui trusts cannot itself come
/// from the caller's PATH.
const SYSTEMD_PATH: &str = "/usr/bin/systemd-path";

pub fn system_command(name: &str) -> Result<Command> {
    Ok(Command::new(system_executable(name)?))
}

/// The absolute path a program resolves to in systemd's default search
/// path.
pub fn system_executable(name: &str) -> Result<PathBuf> {
    let dirs = system_binary_dirs()?;
    dirs.iter()
        .map(|dir| dir.join(name))
        .find(|candidate| is_executable_file(candidate))
        .with_context(|| format!("{name} is not an executable in systemd's default search path"))
}

fn system_binary_dirs() -> Result<Vec<PathBuf>> {
    let out = Command::new(SYSTEMD_PATH)
        .arg("search-binaries-default")
        .env_clear()
        .output()
        .with_context(|| format!("cannot run {SYSTEMD_PATH}"))?;
    if !out.status.success() {
        bail!(
            "{SYSTEMD_PATH} search-binaries-default failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    let text = std::str::from_utf8(&out.stdout).context("systemd-path printed non-UTF-8")?;
    let dirs: Vec<PathBuf> = std::env::split_paths(text.trim()).collect();
    if dirs.is_empty() || dirs.iter().any(|dir| !dir.is_absolute()) {
        bail!(
            "systemd-path returned an invalid search path: {:?}",
            text.trim()
        );
    }
    Ok(dirs)
}

fn is_executable_file(path: &Path) -> bool {
    std::fs::metadata(path)
        .is_ok_and(|meta| meta.is_file() && meta.permissions().mode() & 0o111 != 0)
}
