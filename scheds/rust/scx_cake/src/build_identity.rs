// SPDX-License-Identifier: GPL-2.0

use std::fs::File;
use std::process::{Command, Stdio};

use anyhow::{Context, Result, ensure};

/// Identify the running executable, including local changes and its embedded BPF.
/// Open before spawning: /proc/self/exe in the child would identify sha256sum.
/// The open inode also remains correct if a rebuild replaces the binary on disk.
pub fn binary_sha256() -> Result<String> {
    let executable = File::open("/proc/self/exe").context("opening running executable")?;
    let output = Command::new("sha256sum")
        .stdin(Stdio::from(executable))
        .stderr(Stdio::null())
        .output()
        .context("running sha256sum (coreutils)")?;
    ensure!(output.status.success(), "sha256sum failed");
    let stdout = std::str::from_utf8(&output.stdout).context("reading SHA-256 output")?;
    let hash = stdout.split_whitespace().next().unwrap_or_default();
    ensure!(
        hash.len() == 64 && hash.bytes().all(|b| b.is_ascii_hexdigit()),
        "invalid SHA-256 output"
    );
    Ok(hash.to_ascii_lowercase())
}
