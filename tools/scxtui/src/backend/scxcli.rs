// SPDX-License-Identifier: GPL-2.0

//! `scxcli` as a child process.
//!
//! Reads are `scxcli list --json`, parsed into the types of the published
//! contract (`model`). Writes are `scxcli apply|run|profiles` run
//! directly when scxtui is root, and through `pkexec` otherwise, so
//! scxtui itself never needs root and never touches the configuration.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::model::{Listing, OUTPUT_VERSION, ProfilesFile};
use crate::system::{system_command, system_executable};
use anyhow::{Context, Result, bail};

use super::{ProfileBackend, Report};

/// Where the shipped polkit policy expects scxcli. A scxcli found
/// elsewhere still runs, but polkit then matches no action and pkexec
/// falls back to asking for an administrator's password for everything.
const POLICY_PATH: &str = "/usr/bin/scxcli";

pub struct ScxcliBackend {
    root: bool,
    /// The absolute path scxcli resolved to, passed as such to pkexec:
    /// polkit matches the action on the program's path, so the name is
    /// resolved here, once, in the trusted search path, not by pkexec
    /// against whatever PATH it has.
    scxcli: PathBuf,
}

impl ScxcliBackend {
    /// Checks that scxcli is installed, so startup fails fast with a
    /// plain message instead of the first key press.
    pub fn connect() -> Result<Self> {
        let scxcli = system_executable("scxcli")
            .context("scxcli is not installed in systemd's default search path")?;
        let out = Command::new(&scxcli)
            .arg("--version")
            .output()
            .context("cannot run scxcli")?;
        if !out.status.success() {
            bail!("scxcli --version failed: {}", stderr(&out));
        }
        Ok(Self {
            root: is_root(),
            scxcli,
        })
    }

    /// A warning for startup when scxcli is not where the policy
    /// expects it, since every privileged action then prompts.
    pub fn policy_mismatch(&self) -> Option<String> {
        (!self.root && self.scxcli != Path::new(POLICY_PATH)).then(|| {
            format!(
                "scxcli is {} but the polkit policy names {POLICY_PATH}; every change will ask \
for a password",
                self.scxcli.display()
            )
        })
    }

    /// A privileged scxcli command: direct as root, else via pkexec.
    /// Both are resolved in systemd's default search path, not scxtui's
    /// PATH.
    fn privileged(&self, args: &[&str]) -> Result<Command> {
        let mut command = if self.root {
            Command::new(&self.scxcli)
        } else {
            let mut pkexec = system_command("pkexec")
                .context("pkexec is not installed; run scxtui as root to change schedulers")?;
            pkexec.arg(&self.scxcli);
            pkexec
        };
        command.args(args);
        Ok(command)
    }

    fn write(&self, args: &[&str], stdin: Option<&str>) -> Result<Report> {
        let mut command = self.privileged(args)?;
        if stdin.is_some() {
            command.stdin(Stdio::piped());
        }
        command.stdout(Stdio::piped()).stderr(Stdio::piped());
        let mut child = command.spawn().context("cannot run scxcli")?;
        if let (Some(text), Some(mut pipe)) = (stdin, child.stdin.take()) {
            pipe.write_all(text.as_bytes())
                .context("cannot write to scxcli")?;
        }
        let out = child.wait_with_output().context("scxcli did not finish")?;
        if !out.status.success() {
            bail!("scxcli {} failed: {}", args.join(" "), stderr(&out));
        }
        Ok(String::from_utf8_lossy(&out.stdout).trim().to_owned())
    }
}

fn is_root() -> bool {
    std::fs::metadata("/proc/self")
        .map(|m| std::os::unix::fs::MetadataExt::uid(&m) == 0)
        .unwrap_or(false)
}

fn stderr(out: &std::process::Output) -> String {
    let text = String::from_utf8_lossy(&out.stderr).trim().to_owned();
    if text.is_empty() {
        format!("exit status {}", out.status)
    } else {
        text
    }
}

impl ProfileBackend for ScxcliBackend {
    fn label(&self) -> String {
        if self.root {
            "scxcli (root)".to_owned()
        } else {
            "scxcli via pkexec".to_owned()
        }
    }

    fn list(&self) -> Result<Listing> {
        let out = Command::new(&self.scxcli)
            .args(["list", "--json"])
            .output()
            .context("cannot run scxcli list")?;
        if !out.status.success() {
            bail!("scxcli list failed: {}", stderr(&out));
        }
        let listing: Listing =
            serde_json::from_slice(&out.stdout).context("scxcli list printed unexpected JSON")?;
        if listing.version != OUTPUT_VERSION {
            bail!(
                "scxcli prints output version {}, this scxtui reads {}",
                listing.version,
                OUTPUT_VERSION
            );
        }
        Ok(listing)
    }

    fn apply(&self, id: &str) -> Result<Report> {
        self.write(&["apply", id], None)
    }

    fn run(&self, sched: &str, args: &[String]) -> Result<Report> {
        let mut argv = vec!["run", sched];
        argv.extend(args.iter().map(String::as_str));
        self.write(&argv, None)
    }

    fn save(&self, profiles: &ProfilesFile) -> Result<Report> {
        self.write(&["profiles", "save"], Some(&profiles.render()?))
    }

    fn reset(&self) -> Result<Report> {
        self.write(&["profiles", "reset"], None)
    }

    fn escalates(&self) -> bool {
        !self.root
    }
}
