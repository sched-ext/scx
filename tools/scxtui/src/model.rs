// SPDX-License-Identifier: GPL-2.0

//! scxcli's public JSON, as scxtui reads and writes it: the `list --json`
//! output (version 1) and the profile file (version 2) that `profiles
//! save` takes on stdin. Defined here, against `services/PROFILES.md`,
//! rather than borrowed from the `scx_profiles` crate: scxtui is a
//! client of scxcli like any other and depends on the published
//! contract, not on the crate's API. The fixture test at the bottom
//! reads the shared fixtures to keep the two in step.
//!
//! The validators mirror the contract so that the TUI can refuse a bad
//! id or option before spawning anything; scxcli's own validation stays
//! the authoritative one.

use std::path::PathBuf;

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};

/// `list --json` and `get --json` version this scxtui reads.
pub const OUTPUT_VERSION: u32 = 1;
/// Profile file version this scxtui writes.
pub const FORMAT_VERSION: u32 = 2;
pub const DEFAULT_ID: &str = "default";
pub const ADMIN_PATH: &str = "/etc/scx/profiles.json";
pub const SHIPPED_PATH: &str = "/usr/share/scx/profiles.json";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Stop,
}

/// One profile in the file `profiles save` takes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Profile {
    pub id: String,
    pub label: String,
    #[serde(default)]
    pub description: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action: Option<Action>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sched: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub args: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfilesFile {
    pub version: u32,
    pub profiles: Vec<Profile>,
}

impl ProfilesFile {
    pub fn render(&self) -> Result<String> {
        let mut text = serde_json::to_string_pretty(self)?;
        text.push('\n');
        Ok(text)
    }
}

/// One profile as `list --json` prints it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    pub id: String,
    pub label: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub action: Option<Action>,
    #[serde(default)]
    pub sched: Option<String>,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub args: Vec<String>,
    pub available: bool,
}

impl Entry {
    /// The entry as a line of the profile file, for an edit.
    pub fn to_profile(&self) -> Profile {
        Profile {
            id: self.id.clone(),
            label: self.label.clone(),
            description: self.description.clone(),
            action: self.action,
            sched: self.sched.clone(),
            args: self.args.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Unit {
    pub active: bool,
    pub enabled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Running {
    pub sched: String,
    pub args: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Next {
    pub sched: String,
    pub args: Vec<String>,
    #[serde(rename = "override")]
    pub overridden: bool,
}

impl Next {
    /// The scheduler by name; the file may hold a path.
    pub fn name(&self) -> &str {
        self.sched.rsplit('/').next().unwrap_or(&self.sched)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Kernel {
    pub state: String,
    pub ops: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Failure {
    pub message: String,
    pub status: String,
}

/// `get --json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Current {
    pub version: u32,
    pub profile: Option<String>,
    pub applied: Option<String>,
    pub custom: bool,
    pub unit: Unit,
    pub running: Option<Running>,
    pub next: Option<Next>,
    pub kernel: Option<Kernel>,
    pub failure: Option<Failure>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config_error: Option<String>,
}

/// `list --json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Listing {
    pub version: u32,
    pub source: PathBuf,
    pub customized: bool,
    pub profiles: Vec<Entry>,
    #[serde(default)]
    pub installed: Vec<String>,
    #[serde(default)]
    pub config: Option<PathBuf>,
    pub current: Current,
}

/// 1 to 64 characters of lowercase ASCII letters, digits and `-`,
/// starting with a letter; `custom` is reserved.
pub fn validate_id(id: &str) -> Result<()> {
    let ok = (1..=64).contains(&id.len())
        && id.starts_with(|c: char| c.is_ascii_lowercase())
        && id
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-');
    if !ok {
        bail!(
            "invalid profile id {id:?}: lowercase ASCII letters, digits and '-', starting with a letter"
        );
    }
    if id == "custom" {
        bail!("profile id {id:?} is reserved");
    }
    Ok(())
}

/// 1 to 256 characters of ASCII letters, digits and `-_=.,:/+`.
pub fn validate_arg(arg: &str) -> Result<()> {
    let ok = (1..=256).contains(&arg.len())
        && arg
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "-_=.,:/+".contains(c));
    if !ok {
        bail!("invalid option {arg:?}: ASCII letters, digits and -_=.,:/+ only");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;

    use super::*;

    fn fixtures() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../rust/scx_profiles/fixtures")
    }

    /// The shared fixtures are the contract. Every expected `get` output
    /// and every valid profile file must parse into these types and
    /// serialise back to the same JSON, so scxtui reads what scxcli
    /// prints.
    #[test]
    fn the_shared_fixtures_round_trip_through_these_types() {
        let mut seen = 0;
        for dir in fs::read_dir(fixtures().join("detection")).unwrap() {
            let path = dir.unwrap().path().join("expected.json");
            let text = fs::read_to_string(&path).unwrap();
            let value: serde_json::Value = serde_json::from_str(&text).unwrap();
            let current: Current = serde_json::from_value(value.clone())
                .unwrap_or_else(|err| panic!("{}: {err}", path.display()));
            assert_eq!(current.version, OUTPUT_VERSION);
            assert_eq!(
                serde_json::to_value(&current).unwrap(),
                value,
                "{}",
                path.display()
            );
            seen += 1;
        }
        assert!(seen >= 10);
        for file in fs::read_dir(fixtures().join("profiles/valid")).unwrap() {
            let path = file.unwrap().path();
            let text = fs::read_to_string(&path).unwrap();
            let profiles: ProfilesFile = serde_json::from_str(&text).unwrap();
            assert_eq!(profiles.version, FORMAT_VERSION);
            let again: ProfilesFile = serde_json::from_str(&profiles.render().unwrap()).unwrap();
            assert_eq!(again, profiles);
        }
    }

    #[test]
    fn validators_mirror_the_contract() {
        validate_id("low-latency2").unwrap();
        for bad in ["", "Gaming", "1a", "a b", "custom"] {
            assert!(validate_id(bad).is_err(), "{bad:?}");
        }
        validate_arg("--pinned-slice-us=500").unwrap();
        for bad in ["", "-s 5", "$HOME", "'x'", "a;b"] {
            assert!(validate_arg(bad).is_err(), "{bad:?}");
        }
        assert_eq!(
            Next {
                sched: "/usr/bin/scx_lavd".into(),
                args: Vec::new(),
                overridden: false
            }
            .name(),
            "scx_lavd"
        );
    }
}
