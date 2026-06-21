// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: GPL-2.0-only
//! Resolve how the harness gains root to load the scheduler, and build the
//! privileged commands. Ported from the Python harness's `setup_sudo`.
//!
//! Precedence:
//!   1. already root            -> run directly, no sudo
//!   2. `$SUDO_ASKPASS` set      -> `sudo -A` (use the caller's askpass)
//!   3. `$SCX_SUDO_PASSWORD_FILE` -> generate an askpass shim that prints the
//!      file's contents and use `sudo -A`; the password stays in the file and
//!      never appears in argv or the process table
//!   4. otherwise               -> `sudo -n` (passwordless / cached credentials)

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::Command;

use anyhow::{Context, Result};

/// A generated askpass shim, removed from disk when dropped (replaces atexit).
struct TempShim {
    path: PathBuf,
}

impl Drop for TempShim {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Resolved sudo strategy: the argv prefix plus any owned askpass shim.
pub struct Sudo {
    /// e.g. `[]` (root), `["sudo", "-A"]`, or `["sudo", "-n"]`.
    prefix: Vec<String>,
    _shim: Option<TempShim>,
}

/// Single-quote a path for safe embedding in a /bin/sh script.
fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

impl Sudo {
    /// Decide the sudo strategy from euid and the environment.
    pub fn resolve() -> Result<Sudo> {
        if unsafe { libc::geteuid() } == 0 {
            return Ok(Sudo {
                prefix: Vec::new(),
                _shim: None,
            });
        }
        if std::env::var_os("SUDO_ASKPASS").is_some() {
            return Ok(Sudo {
                prefix: vec!["sudo".into(), "-A".into()],
                _shim: None,
            });
        }
        if let Some(pass_file) = std::env::var_os("SCX_SUDO_PASSWORD_FILE") {
            let pf = PathBuf::from(&pass_file);
            if !pf.is_file() {
                anyhow::bail!("SCX_SUDO_PASSWORD_FILE not found: {}", pf.display());
            }
            let pf_abs = std::fs::canonicalize(&pf)
                .with_context(|| format!("canonicalize {}", pf.display()))?;
            // askpass helper: sudo runs this and reads the password from stdout.
            let shim = std::env::temp_dir().join(format!("scx-askpass-{}.sh", std::process::id()));
            std::fs::write(
                &shim,
                format!(
                    "#!/bin/sh\nexec cat {}\n",
                    shell_quote(&pf_abs.to_string_lossy())
                ),
            )
            .with_context(|| format!("write askpass shim {}", shim.display()))?;
            std::fs::set_permissions(&shim, std::fs::Permissions::from_mode(0o700))
                .with_context(|| format!("chmod askpass shim {}", shim.display()))?;
            std::env::set_var("SUDO_ASKPASS", &shim);
            return Ok(Sudo {
                prefix: vec!["sudo".into(), "-A".into()],
                _shim: Some(TempShim { path: shim }),
            });
        }
        Ok(Sudo {
            prefix: vec!["sudo".into(), "-n".into()],
            _shim: None,
        })
    }

    /// Build a `Command` running `program` (with `args`) as root.
    pub fn command(&self, program: &str, args: &[String]) -> Command {
        if self.prefix.is_empty() {
            let mut c = Command::new(program);
            c.args(args);
            c
        } else {
            let mut c = Command::new(&self.prefix[0]);
            c.args(&self.prefix[1..]);
            c.arg(program);
            c.args(args);
            c
        }
    }

    /// Validate that sudo authenticates now (`sudo <prefix> -v`). No-op as root.
    /// Returns Err with sudo's stderr on failure.
    pub fn authenticate(&self) -> Result<()> {
        if self.prefix.is_empty() {
            return Ok(());
        }
        let out = Command::new(&self.prefix[0])
            .args(&self.prefix[1..])
            .arg("-v")
            .output()
            .context("spawn sudo -v")?;
        if out.status.success() {
            Ok(())
        } else {
            let err = String::from_utf8_lossy(&out.stderr);
            anyhow::bail!("{}", err.trim());
        }
    }
}
