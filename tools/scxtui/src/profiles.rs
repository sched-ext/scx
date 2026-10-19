// SPDX-License-Identifier: GPL-2.0

//! Scheduler profiles ("modes"): named flag sets per scheduler, applied by
//! writing them to `SCX_FLAGS` next to `SCX_SCHEDULER`.
//!
//! The schema and the built-in tables are scx_loader's, so an existing
//! `/etc/scx_loader.toml` keeps working, and the loader's defaults apply
//! where the file says nothing. The mechanism is deliberately stateless:
//! nothing records which profile was started. The running profile is
//! recognised by comparing the process' arguments with the table, and
//! anything that matches no row is shown as custom flags.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::Deserialize;

/// Where the profile file is looked for, first hit wins. scxtui's own
/// paths come first, then scx_loader's, so a system migrating off the
/// loader needs no edits.
const CONFIG_CANDIDATES: [&str; 8] = [
    "/etc/scxtui/config.toml",
    "/etc/scxtui.toml",
    "/etc/scx_loader/config.toml",
    "/etc/scx_loader.toml",
    "/usr/share/scxtui/config.toml",
    "/usr/share/scxtui.toml",
    "/usr/share/scx_loader/config.toml",
    "/usr/share/scx_loader.toml",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize)]
pub enum Mode {
    #[serde(alias = "auto")]
    Auto,
    #[serde(alias = "gaming")]
    Gaming,
    #[serde(alias = "powersave")]
    PowerSave,
    #[serde(alias = "lowlatency")]
    LowLatency,
    #[serde(alias = "server")]
    Server,
}

/// All modes, in the cycling order used by the mode selector.
pub const MODES: [Mode; 5] = [
    Mode::Auto,
    Mode::Gaming,
    Mode::PowerSave,
    Mode::LowLatency,
    Mode::Server,
];

impl Mode {
    /// Lower-case name, matching scxctl's CLI.
    pub fn label(self) -> &'static str {
        match self {
            Mode::Auto => "auto",
            Mode::Gaming => "gaming",
            Mode::PowerSave => "powersave",
            Mode::LowLatency => "lowlatency",
            Mode::Server => "server",
        }
    }
}

/// One scheduler's table. A `None` row falls back to the built-in default
/// for that scheduler and mode; an explicit empty list means "no flags".
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
struct Sched {
    auto_mode: Option<Vec<String>>,
    gaming_mode: Option<Vec<String>>,
    lowlatency_mode: Option<Vec<String>>,
    powersave_mode: Option<Vec<String>>,
    server_mode: Option<Vec<String>>,
}

impl Sched {
    fn row(&self, mode: Mode) -> Option<&[String]> {
        match mode {
            Mode::Auto => &self.auto_mode,
            Mode::Gaming => &self.gaming_mode,
            Mode::PowerSave => &self.powersave_mode,
            Mode::LowLatency => &self.lowlatency_mode,
            Mode::Server => &self.server_mode,
        }
        .as_deref()
    }
}

#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(default)]
struct Config {
    default_sched: Option<String>,
    default_mode: Option<Mode>,
    scheds: HashMap<String, Sched>,
}

/// The loaded profile set: file contents over built-in defaults.
#[derive(Debug, Clone, Default)]
pub struct Profiles {
    config: Config,
    /// Where the table came from; `None` = built-in defaults only.
    pub source: Option<PathBuf>,
}

impl Profiles {
    /// Loads the first existing candidate, or the built-in defaults when
    /// none exists. A file that exists but does not parse is an error:
    /// silently running the defaults instead would start schedulers with
    /// flags the admin did not configure.
    pub fn load() -> Result<Self> {
        match CONFIG_CANDIDATES.iter().map(Path::new).find(|p| p.exists()) {
            Some(path) => Self::from_path(path),
            None => Ok(Self::default()),
        }
    }

    fn from_path(path: &Path) -> Result<Self> {
        let text = fs::read_to_string(path)
            .with_context(|| format!("cannot read profiles from {}", path.display()))?;
        let config = Self::parse(&text)
            .with_context(|| format!("invalid profiles file {}", path.display()))?;
        Ok(Self {
            config,
            source: Some(path.to_path_buf()),
        })
    }

    fn parse(text: &str) -> Result<Config> {
        Ok(toml::from_str(text)?)
    }

    /// Flags for `sched` in `mode`: the file's row when present, else the
    /// built-in default, else nothing. Mirrors scx_loader's resolution.
    pub fn flags(&self, sched: &str, mode: Mode) -> Vec<String> {
        self.config
            .scheds
            .get(sched)
            .and_then(|table| table.row(mode))
            .map(<[String]>::to_vec)
            .unwrap_or_else(|| {
                builtin_flags(sched, mode)
                    .iter()
                    .map(|s| (*s).to_owned())
                    .collect()
            })
    }

    /// Which mode `flags` correspond to for `sched`, if any. First match
    /// in [`MODES`] order wins when two modes share a flag set (common:
    /// `auto` and `server` both empty).
    pub fn mode_for(&self, sched: &str, flags: &[String]) -> Option<Mode> {
        MODES
            .iter()
            .copied()
            .find(|mode| self.flags(sched, *mode) == flags)
    }

    /// The configured default, if the file names a scheduler. The mode
    /// defaults to `Auto` like in scx_loader.
    pub fn default_launch(&self) -> Option<(&str, Mode)> {
        let sched = self.config.default_sched.as_deref()?;
        Some((sched, self.config.default_mode.unwrap_or(Mode::Auto)))
    }
}

impl Profiles {
    /// The resolved table as JSON: for every scheduler in `schedulers`
    /// (plus any the file names) the flags each profile resolves to, with
    /// file rows and built-in defaults already merged, so a consumer
    /// sees exactly what `Enter` would write. The shape is deliberately
    /// not the TOML schema: that one has holes (missing rows) this one
    /// fills in.
    pub fn export(&self, schedulers: &[String]) -> serde_json::Value {
        let mut names: Vec<&str> = schedulers.iter().map(String::as_str).collect();
        names.extend(self.config.scheds.keys().map(String::as_str));
        names.sort_unstable();
        names.dedup();
        let scheds: serde_json::Map<String, serde_json::Value> = names
            .into_iter()
            .map(|sched| {
                let modes: serde_json::Map<String, serde_json::Value> = MODES
                    .iter()
                    .map(|mode| {
                        (
                            mode.label().to_owned(),
                            serde_json::Value::from(self.flags(sched, *mode)),
                        )
                    })
                    .collect();
                (sched.to_owned(), serde_json::Value::Object(modes))
            })
            .collect();
        serde_json::json!({
            "source": self.source.as_ref().map(|p| p.display().to_string()),
            "default": self.default_launch().map(|(sched, mode)| {
                serde_json::json!({ "sched": sched, "mode": mode.label() })
            }),
            "schedulers": scheds,
        })
    }
}

/// scx_loader's built-in mode tables, keyed by scheduler name. Kept in
/// sync by hand; the loader is the reference.
fn builtin_flags(sched: &str, mode: Mode) -> &'static [&'static str] {
    match (sched, mode) {
        ("scx_bpfland", Mode::Auto) => &["-m", "auto"],
        ("scx_bpfland", Mode::Gaming) => &["-m", "all"],
        ("scx_bpfland", Mode::PowerSave) => {
            &["-s", "20000", "-m", "powersave", "-I", "100", "-t", "100"]
        }
        ("scx_bpfland", Mode::LowLatency) => &["-m", "performance", "-w"],
        ("scx_bpfland", Mode::Server) => &["-s", "20000", "-S"],

        ("scx_lavd", Mode::Auto) => &["--autopilot", "--pinned-slice-us", "500"],
        ("scx_lavd", Mode::Gaming | Mode::LowLatency) => {
            &["--performance", "--pinned-slice-us", "500"]
        }
        ("scx_lavd", Mode::PowerSave) => &["--powersave", "--pinned-slice-us", "500"],
        ("scx_lavd", Mode::Server) => &[
            "--performance",
            "--slice-min-us",
            "3000",
            "--slice-max-us",
            "10000",
            "--pinned-slice-us",
            "3000",
        ],

        ("scx_p2dq", Mode::Auto) => &["--sched-mode", "default"],
        ("scx_p2dq", Mode::Gaming) => {
            &["--task-slice", "true", "-f", "--sched-mode", "performance"]
        }
        ("scx_p2dq", Mode::PowerSave) => &["--sched-mode", "efficiency"],
        ("scx_p2dq", Mode::LowLatency) => &["-y", "-f", "--task-slice", "true"],
        ("scx_p2dq", Mode::Server) => &["--keep-running"],

        ("scx_tickless", Mode::Gaming) => &["-f", "5000", "-s", "5000"],
        ("scx_tickless", Mode::PowerSave) => &["-f", "50"],
        ("scx_tickless", Mode::LowLatency) => &["-f", "5000", "-s", "1000"],
        ("scx_tickless", Mode::Server) => &["-f", "100"],

        ("scx_cosmos", Mode::Gaming) => &["-s", "700"],
        ("scx_cosmos", Mode::PowerSave) => &["-m", "powersave"],
        ("scx_cosmos", Mode::LowLatency) => &["-s", "700", "-m", "performance", "-w"],

        _ => &[],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strs(flags: &[&str]) -> Vec<String> {
        flags.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn builtin_defaults_apply_without_a_file() {
        let profiles = Profiles::default();
        assert_eq!(
            profiles.flags("scx_bpfland", Mode::Gaming),
            strs(&["-m", "all"])
        );
        assert!(profiles.flags("scx_rusty", Mode::Gaming).is_empty());
        assert_eq!(profiles.default_launch(), None);
    }

    #[test]
    fn file_rows_override_defaults_per_mode() {
        let config = Profiles::parse(
            r#"
default_sched = "scx_lavd"
default_mode = "PowerSave"

[scheds.scx_bpfland]
gaming_mode = ["-m", "performance", "-k"]
auto_mode = []
"#,
        )
        .unwrap();
        let profiles = Profiles {
            config,
            source: None,
        };
        assert_eq!(
            profiles.flags("scx_bpfland", Mode::Gaming),
            strs(&["-m", "performance", "-k"])
        );
        // An explicit empty row means "no flags", not "use the default".
        assert!(profiles.flags("scx_bpfland", Mode::Auto).is_empty());
        // A missing row keeps the built-in default.
        assert_eq!(
            profiles.flags("scx_bpfland", Mode::Server),
            strs(&["-s", "20000", "-S"])
        );
        assert_eq!(
            profiles.default_launch(),
            Some(("scx_lavd", Mode::PowerSave))
        );
    }

    #[test]
    fn export_merges_file_rows_defaults_and_path_schedulers() {
        let config = Profiles::parse(
            "default_sched = \"scx_lavd\"\n[scheds.scx_bpfland]\ngaming_mode = [\"-k\"]\n",
        )
        .unwrap();
        let profiles = Profiles {
            config,
            source: Some(PathBuf::from("/etc/scxtui.toml")),
        };
        let out = profiles.export(&strs(&["scx_rusty", "scx_lavd"]));
        assert_eq!(out["source"], "/etc/scxtui.toml");
        assert_eq!(out["default"]["sched"], "scx_lavd");
        assert_eq!(out["default"]["mode"], "auto");
        // File row, built-in default, and a scheduler with no table at all.
        assert_eq!(
            out["schedulers"]["scx_bpfland"]["gaming"],
            serde_json::json!(["-k"])
        );
        assert_eq!(
            out["schedulers"]["scx_bpfland"]["server"],
            serde_json::json!(["-s", "20000", "-S"])
        );
        assert_eq!(
            out["schedulers"]["scx_lavd"]["auto"],
            serde_json::json!(["--autopilot", "--pinned-slice-us", "500"])
        );
        assert_eq!(
            out["schedulers"]["scx_rusty"]["gaming"],
            serde_json::json!([])
        );
        assert_eq!(out["schedulers"].as_object().unwrap().len(), 3);
    }

    #[test]
    fn mode_names_accept_both_spellings() {
        let config = Profiles::parse("default_mode = \"lowlatency\"\n").unwrap();
        assert_eq!(config.default_mode, Some(Mode::LowLatency));
        assert!(Profiles::parse("default_mode = \"turbo\"\n").is_err());
    }

    #[test]
    fn running_flags_map_back_to_a_mode() {
        let profiles = Profiles::default();
        assert_eq!(
            profiles.mode_for("scx_bpfland", &strs(&["-m", "all"])),
            Some(Mode::Gaming)
        );
        // Shared flag sets resolve to the first mode in selector order.
        assert_eq!(
            profiles.mode_for(
                "scx_lavd",
                &strs(&["--performance", "--pinned-slice-us", "500"])
            ),
            Some(Mode::Gaming)
        );
        assert_eq!(profiles.mode_for("scx_cosmos", &[]), Some(Mode::Auto));
        assert_eq!(profiles.mode_for("scx_bpfland", &strs(&["-k"])), None);
    }
}
