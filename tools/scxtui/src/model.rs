// SPDX-License-Identifier: GPL-2.0

//! scxcli's public JSON, as scxtui reads it: the `list --json` output
//! (version 2). Defined here, against `services/CATALOG.md`, rather
//! than borrowed from the `scx_catalog` crate: scxtui is a client of
//! scxcli like any other and depends on the published contract, not on
//! the crate's API. The fixture test at the bottom reads the shared
//! fixtures to keep the two in step.
//!
//! The option validator mirrors the contract so that the TUI can refuse
//! a bad option before spawning anything; scxcli's own validation stays
//! the authoritative one.

use std::path::PathBuf;

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};

/// `list --json` and `get --json` version this scxtui reads.
pub const OUTPUT_VERSION: u32 = 2;
pub const DEFAULT_ID: &str = "default";
pub const ADMIN_PATH: &str = "/etc/scx/catalog.json";
pub const SHIPPED_PATH: &str = "/usr/share/scx/catalog.json";

/// One profile as `list --json` prints it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Pick {
    pub id: String,
    pub label: String,
    #[serde(default)]
    pub description: String,
    /// A custom profile's scheduler, by name; absent on a plain
    /// profile, whose id is the scheduler, and on `default`.
    #[serde(default)]
    pub sched: Option<String>,
    /// The options the profile starts its scheduler with; none on a
    /// plain profile.
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default)]
    pub path: Option<String>,
    pub available: bool,
}

impl Pick {
    /// The scheduler the profile starts, by name, or `None` for
    /// `default`.
    pub fn sched_name(&self) -> Option<&str> {
        match &self.sched {
            Some(sched) => Some(sched),
            None => (self.id != DEFAULT_ID).then_some(self.id.as_str()),
        }
    }

    /// A custom profile: a scheduler with options under an id of its
    /// own, whose command the installed catalog decides.
    pub fn is_custom(&self) -> bool {
        self.sched.is_some()
    }

    /// Whether `sched` (by name) with `args` is exactly this profile's
    /// command. The unit's file holds a command and not a profile id,
    /// so this is how the running or selected profile is found; a
    /// plain profile matches its scheduler with no options.
    pub fn is_command(&self, sched: &str, args: &[String]) -> bool {
        self.sched_name() == Some(sched) && self.args == args
    }
}

/// One installed scheduler the catalog does not hide.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Installed {
    pub name: String,
    pub path: String,
    /// A plain profile names it.
    pub recommended: bool,
    /// The catalog features it: the maintainers' pick, shown first.
    /// Absent in older output reads as not featured.
    #[serde(default)]
    pub featured: bool,
    /// What the catalog says: `stable`, `experimental`, or `unknown`
    /// when it names the scheduler nowhere. Absent in older output
    /// reads as unknown, since that output made no such statement.
    #[serde(default)]
    pub tier: Tier,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Tier {
    Stable,
    Experimental,
    #[default]
    Unknown,
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
    /// The running scheduler by name, `default` while the kernel's own
    /// runs, null while the unit and the kernel disagree.
    pub scheduler: Option<String>,
    pub unit: Unit,
    pub running: Option<Running>,
    pub next: Option<Next>,
    pub kernel: Option<Kernel>,
    pub failure: Option<Failure>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config_error: Option<String>,
}

impl Current {
    pub fn attached(&self) -> bool {
        self.kernel.as_ref().is_some_and(|k| k.ops.is_some())
    }
}

/// `list --json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Listing {
    pub version: u32,
    pub source: PathBuf,
    pub customized: bool,
    pub recommended: Vec<Pick>,
    #[serde(default)]
    pub all: Vec<Installed>,
    #[serde(default)]
    pub config: Option<PathBuf>,
    pub current: Current,
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
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../rust/scx_catalog/fixtures")
    }

    /// The shared fixtures are the contract. Every expected `get` output
    /// must parse into these types and serialise back to the same JSON,
    /// so scxtui reads what scxcli prints.
    #[test]
    fn the_shared_fixtures_round_trip_through_these_types() {
        let mut seen = 0;
        for entry in fs::read_dir(fixtures().join("detection")).unwrap() {
            let path = entry.unwrap().path();
            if path.extension().is_none_or(|e| e != "json") {
                continue;
            }
            let text = fs::read_to_string(&path).unwrap();
            let case: serde_json::Value = serde_json::from_str(&text).unwrap();
            let value = case["expected"].clone();
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
    }

    #[test]
    fn an_installed_entry_without_a_tier_is_unknown_and_round_trips_its_tier() {
        let old: Installed = serde_json::from_str(
            r#"{"name":"scx_cosmos","path":"/usr/bin/scx_cosmos","recommended":true}"#,
        )
        .unwrap();
        assert_eq!(
            old.tier,
            Tier::Unknown,
            "no statement is not a stable statement"
        );
        let exp: Installed = serde_json::from_str(
            r#"{"name":"scx_flow","path":"/usr/bin/scx_flow","recommended":false,"tier":"experimental"}"#,
        )
        .unwrap();
        assert_eq!(exp.tier, Tier::Experimental);
        assert!(
            serde_json::to_string(&exp)
                .unwrap()
                .contains("\"tier\":\"experimental\"")
        );
    }

    #[test]
    fn the_validator_mirrors_the_contract() {
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
