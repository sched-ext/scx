// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: GPL-2.0-only
//! Resolve how the harness gains root to load the scheduler, and build the
//! privileged commands. Ported from the Python harness's `setup_sudo`.
//!
//! Precedence:
//!   1. already root            -> run directly, no sudo
//!   2. `$SUDO_ASKPASS` set      -> `sudo -A` (use the caller's askpass)
//!   3. password file (from the spec via `resolve()`, or from
//!      `$SCX_SUDO_PASSWORD_FILE`) -> generate an askpass shim that prints the
//!      file's contents and use `sudo -A`; the password stays in the file and
//!      never appears in argv or the process table. The shim path is exported
//!      to spawned sudo commands only (via `Command::env`), never to the
//!      agent's own environment.
//!   4. otherwise               -> `sudo -n` (passwordless / cached credentials)

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
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
    /// Askpass shim exported to spawned sudo commands via `SUDO_ASKPASS`.
    /// `None` when sudo is not used, or when the caller's own `SUDO_ASKPASS`
    /// is inherited from the environment.
    askpass: Option<PathBuf>,
    _shim: Option<TempShim>,
}

/// Single-quote a path for safe embedding in a /bin/sh script.
fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

impl Sudo {
    /// Decide the sudo strategy from euid, the environment, and an optional
    /// password file resolved from the spec (takes precedence over
    /// `$SCX_SUDO_PASSWORD_FILE`).
    pub fn resolve(password_file: Option<&Path>) -> Result<Sudo> {
        if unsafe { libc::geteuid() } == 0 {
            return Ok(Sudo {
                prefix: Vec::new(),
                askpass: None,
                _shim: None,
            });
        }
        if std::env::var_os("SUDO_ASKPASS").is_some() {
            return Ok(Sudo {
                prefix: vec!["sudo".into(), "-A".into()],
                askpass: None,
                _shim: None,
            });
        }
        let pass_file = password_file
            .map(Path::to_path_buf)
            .or_else(|| std::env::var_os("SCX_SUDO_PASSWORD_FILE").map(PathBuf::from));
        if let Some(pass_file) = pass_file {
            let pf = pass_file;
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
            return Ok(Sudo {
                prefix: vec!["sudo".into(), "-A".into()],
                askpass: Some(shim.clone()),
                _shim: Some(TempShim { path: shim }),
            });
        }
        Ok(Sudo {
            prefix: vec!["sudo".into(), "-n".into()],
            askpass: None,
            _shim: None,
        })
    }

    /// Export the askpass shim (if any) to a spawned sudo command.
    fn apply_env(&self, c: &mut Command) {
        if let Some(askpass) = &self.askpass {
            c.env("SUDO_ASKPASS", askpass);
        }
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
            self.apply_env(&mut c);
            c
        }
    }

    /// Validate that sudo authenticates now (`sudo <prefix> -v`). No-op as root.
    /// Returns Err with sudo's stderr on failure.
    pub fn authenticate(&self) -> Result<()> {
        if self.prefix.is_empty() {
            return Ok(());
        }
        let mut c = Command::new(&self.prefix[0]);
        c.args(&self.prefix[1..]).arg("-v");
        self.apply_env(&mut c);
        let out = c.output().context("spawn sudo -v")?;
        if out.status.success() {
            Ok(())
        } else {
            let err = String::from_utf8_lossy(&out.stderr);
            anyhow::bail!("{}", err.trim());
        }
    }
}
