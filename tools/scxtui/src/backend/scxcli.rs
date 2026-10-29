// SPDX-License-Identifier: GPL-2.0

//! `scxcli` as a child process.
//!
//! Reads are `scxcli list --json`, parsed into the types of the published
//! contract (`model`). Writes are `scxcli start|stop|run` run directly
//! when scxtui is root, and through `pkexec` otherwise, so scxtui itself
//! never needs root and never touches the configuration.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::model::{Listing, OUTPUT_VERSION};
use crate::system::{system_command, system_executable};
use anyhow::{Context, Result, bail};

use super::{Backend, Report};

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
    /// A catalog file to list with instead of the installed one
    /// (`scxtui --catalog PATH`). Reads only: `start` goes through
    /// scxcli without it, so what runs without a password is still
    /// decided by the installed catalog and the policy that covers it.
    catalog: Option<PathBuf>,
}

impl ScxcliBackend {
    /// Checks that scxcli is installed, so startup fails fast with a
    /// plain message instead of the first key press.
    pub fn connect(catalog: Option<PathBuf>) -> Result<Self> {
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
            catalog,
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

    /// The argument list of `scxcli list`, the one command the catalog
    /// override reaches.
    fn list_args(&self) -> Vec<OsString> {
        let mut args: Vec<OsString> = vec!["list".into(), "--json".into()];
        if let Some(catalog) = &self.catalog {
            args.push("--catalog".into());
            args.push(catalog.clone().into_os_string());
        }
        args
    }

    /// The argument lists of the privileged commands: what the user
    /// asked for and nothing else. `self` is taken so that a catalog
    /// override has every chance to leak in and the test can show it
    /// does not: `start` with one is the same `start` as without.
    fn start_args(&self, id: &str) -> Vec<OsString> {
        vec!["start".into(), id.into()]
    }

    fn run_args(&self, sched: &str, args: &[String]) -> Vec<OsString> {
        let mut argv: Vec<OsString> = vec!["run".into(), sched.into()];
        argv.extend(args.iter().map(OsString::from));
        argv
    }

    fn stop_args(&self) -> Vec<OsString> {
        vec!["stop".into()]
    }

    /// A privileged scxcli command: direct as root, else via pkexec.
    /// Both are resolved in systemd's default search path, not scxtui's
    /// PATH.
    fn privileged(&self, args: &[OsString]) -> Result<Command> {
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

    fn write(&self, args: &[OsString]) -> Result<Report> {
        let mut command = self.privileged(args)?;
        command.stdout(Stdio::piped()).stderr(Stdio::piped());
        let out = command.output().context("cannot run scxcli")?;
        if !out.status.success() {
            let shown: Vec<String> = args
                .iter()
                .map(|a| a.to_string_lossy().into_owned())
                .collect();
            bail!("scxcli {} failed: {}", shown.join(" "), stderr(&out));
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

impl Backend for ScxcliBackend {
    fn label(&self) -> String {
        if self.root {
            "scxcli (root)".to_owned()
        } else {
            "scxcli via pkexec".to_owned()
        }
    }

    fn list(&self) -> Result<Listing> {
        let mut command = Command::new(&self.scxcli);
        command.args(self.list_args());
        let out = command.output().context("cannot run scxcli list")?;
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

    fn start(&self, id: &str) -> Result<Report> {
        self.write(&self.start_args(id))
    }

    fn run(&self, sched: &str, args: &[String]) -> Result<Report> {
        self.write(&self.run_args(sched, args))
    }

    fn stop(&self) -> Result<Report> {
        self.write(&self.stop_args())
    }

    fn escalates(&self) -> bool {
        !self.root
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn backend(catalog: Option<&str>) -> ScxcliBackend {
        ScxcliBackend {
            root: true,
            scxcli: PathBuf::from(POLICY_PATH),
            catalog: catalog.map(PathBuf::from),
        }
    }

    fn words(args: &[OsString]) -> Vec<String> {
        args.iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect()
    }

    /// The line between looking and running: a catalog file reaches
    /// `list --json` and nothing else. The privileged commands, which
    /// the policy covers and the installed catalog governs, are built
    /// the same with an override as without one.
    #[test]
    fn the_catalog_reaches_list_and_no_privileged_command() {
        let plain = backend(None);
        let with = backend(Some("/tmp/try.json"));
        assert_eq!(words(&plain.list_args()), ["list", "--json"]);
        assert_eq!(
            words(&with.list_args()),
            ["list", "--json", "--catalog", "/tmp/try.json"]
        );

        let opts = vec!["--slice-us".to_owned(), "2000".to_owned()];
        assert_eq!(
            words(&with.start_args("scx_cosmos")),
            ["start", "scx_cosmos"]
        );
        assert_eq!(
            words(&with.run_args("scx_layered", &opts)),
            ["run", "scx_layered", "--slice-us", "2000"]
        );
        assert_eq!(words(&with.stop_args()), ["stop"]);
        assert_eq!(
            with.start_args("scx_cosmos"),
            plain.start_args("scx_cosmos")
        );
        assert_eq!(
            with.run_args("scx_layered", &opts),
            plain.run_args("scx_layered", &opts)
        );
        assert_eq!(with.stop_args(), plain.stop_args());
    }
}
