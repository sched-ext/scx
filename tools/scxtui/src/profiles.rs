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

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize, Serialize)]
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
    /// Parses scxctl's `--mode` spelling (lower-case), case-insensitively.
    pub fn parse(name: &str) -> Option<Self> {
        MODES
            .iter()
            .copied()
            .find(|mode| mode.label().eq_ignore_ascii_case(name))
    }

    /// The variant name, as scxctl prints it (`Gaming mode`).
    pub fn name(self) -> &'static str {
        match self {
            Mode::Auto => "Auto",
            Mode::Gaming => "Gaming",
            Mode::PowerSave => "PowerSave",
            Mode::LowLatency => "LowLatency",
            Mode::Server => "Server",
        }
    }

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
#[derive(Debug, Clone, Default, PartialEq, Deserialize, Serialize)]
struct Sched {
    #[serde(skip_serializing_if = "Option::is_none")]
    auto_mode: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    gaming_mode: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    lowlatency_mode: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    powersave_mode: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
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

    fn row_mut(&mut self, mode: Mode) -> &mut Option<Vec<String>> {
        match mode {
            Mode::Auto => &mut self.auto_mode,
            Mode::Gaming => &mut self.gaming_mode,
            Mode::PowerSave => &mut self.powersave_mode,
            Mode::LowLatency => &mut self.lowlatency_mode,
            Mode::Server => &mut self.server_mode,
        }
    }
}

/// The file's schema, scx_loader's. Schedulers are kept sorted so that
/// an export is deterministic.
#[derive(Debug, Clone, Default, PartialEq, Deserialize, Serialize)]
#[serde(default)]
struct Config {
    #[serde(skip_serializing_if = "Option::is_none")]
    default_sched: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    default_mode: Option<Mode>,
    scheds: BTreeMap<String, Sched>,
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

    /// Whether `mode` is configured for `sched`, by scx_loader's rule:
    /// `Auto` always is, since it means the scheduler's own defaults;
    /// any other mode only when it has flags. A mode without a row is
    /// not a profile, it is the absence of one, so it is neither listed
    /// by `modes` nor recognised in a running process.
    pub fn configured(&self, sched: &str, mode: Mode) -> bool {
        mode == Mode::Auto || !self.flags(sched, mode).is_empty()
    }

    /// Every configured mode whose flag set for `sched` is exactly
    /// `flags`, in [`MODES`] order. Several modes can share a flag set
    /// (lavd's gaming and lowlatency), and the process' argv cannot tell
    /// them apart; callers that need one answer take the first and
    /// callers that report state should show the whole list. A process
    /// without flags matches `Auto` alone: the unconfigured modes run
    /// the same way, but naming them would list every mode for a
    /// scheduler that has no profiles at all.
    pub fn modes_for(&self, sched: &str, flags: &[String]) -> Vec<Mode> {
        MODES
            .iter()
            .copied()
            .filter(|mode| self.configured(sched, *mode) && self.flags(sched, *mode) == flags)
            .collect()
    }

    /// The configured default, if the file names a scheduler. The mode
    /// defaults to `Auto` like in scx_loader.
    pub fn default_launch(&self) -> Option<(&str, Mode)> {
        let sched = self.config.default_sched.as_deref()?;
        Some((sched, self.config.default_mode.unwrap_or(Mode::Auto)))
    }
}

/// Output format of `--export-profiles`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportFormat {
    /// For scripts and other front ends: every row filled in.
    Json,
    /// The file's own schema, so the output loads back as a profiles
    /// file: a starting point to edit, or a record of what is in effect.
    Toml,
}

impl ExportFormat {
    pub fn parse(name: &str) -> Option<Self> {
        match name {
            "json" => Some(Self::Json),
            "toml" => Some(Self::Toml),
            _ => None,
        }
    }
}

impl Profiles {
    /// The schedulers an export covers: `installed` (what the TUI would
    /// list) and every one the file names, as a row or as the default,
    /// plus, when `builtin` is set, every one with a built-in row.
    /// Sorted and deduplicated. The JSON export keeps `builtin` off: its
    /// keys have meant "available here" since it appeared, and a front
    /// end may offer them as such. The TOML export sets it: a profiles
    /// file is configuration, not inventory, and a row for a scheduler
    /// that is not installed today must not drop out of it.
    fn export_names(&self, installed: &[String], builtin: bool) -> Vec<String> {
        let mut names: Vec<String> = installed.to_vec();
        names.extend(self.config.scheds.keys().cloned());
        names.extend(self.config.default_sched.iter().cloned());
        if builtin {
            names.extend(BUILTIN_SCHEDS.iter().map(|s| (*s).to_owned()));
        }
        names.sort_unstable();
        names.dedup();
        names
    }

    /// The resolved table in the file's own schema: every row filled in
    /// with what it resolves to, so loading the output gives the same
    /// flags for every scheduler and mode (an empty row stays empty,
    /// which reads back as "no flags" either way). The guarantee is
    /// that semantic round trip, not identical text: the header names
    /// the file the rows came from, since the merge leaves no other
    /// trace, and an export installed as a file is exported again under
    /// that file's name.
    pub fn export_toml(&self, installed: &[String]) -> Result<String> {
        let scheds: BTreeMap<String, Sched> = self
            .export_names(installed, true)
            .into_iter()
            .map(|sched| {
                let mut table = Sched::default();
                for mode in MODES {
                    *table.row_mut(mode) = Some(self.flags(&sched, mode));
                }
                (sched, table)
            })
            .collect();
        // The default is spelled out like the rows: a configured
        // scheduler gets its mode written even when the file left it to
        // the Auto fallback. Without one, the two keys go in as
        // comments, as a template to uncomment, so the output shows
        // where `restore` and the TUI's `d` key would take their target
        // from. The example is the first installed scheduler, so that
        // uncommenting it as is works on this system; only when nothing
        // is installed (--builtin, or no scheduler at all) the first of
        // the table stands in.
        let default = self.default_launch();
        let config = Config {
            default_sched: default.map(|(sched, _)| sched.to_owned()),
            default_mode: default.map(|(_, mode)| mode),
            scheds,
        };
        let body = toml::to_string(&config).context("cannot serialise the profiles")?;
        let mut installed: Vec<&String> = installed.iter().collect();
        installed.sort_unstable();
        let example = installed
            .first()
            .map(|s| s.as_str())
            .or_else(|| config.scheds.keys().next().map(String::as_str));
        // The example is escaped as a one-line TOML string rather than
        // quoted by hand: the discovered names are plain, but a file row
        // can be keyed by anything, and a name with a newline in it
        // would otherwise turn the comment into a live key. (toml's own
        // Display picks a multi-line literal for such a string, which
        // breaks out of the comment just the same.)
        let template = match (default, example) {
            (None, Some(example)) => format!(
                "\n# No default scheduler is configured. Uncomment to give `restore` and\n\
# the TUI's `d` key a target:\n\
#default_sched = {}\n\
#default_mode = \"Auto\"      # Auto | Gaming | PowerSave | LowLatency | Server\n",
                toml_basic_string(example)
            ),
            _ => String::new(),
        };
        let origin = match &self.source {
            Some(path) => format!("{} over the built-in defaults", path.display()),
            None => "the built-in defaults".to_owned(),
        };
        Ok(format!(
            "# scxtui profiles, resolved from {origin}.\n\
# Every row is spelled out; a row left out of a file keeps the\n\
# built-in default for that scheduler and mode.\n{template}\n{body}"
        ))
    }

    /// The resolved table as JSON: for every installed scheduler (plus
    /// any the file names) the flags each profile resolves to, with file
    /// rows and built-in defaults already merged, so a consumer sees
    /// exactly what `Enter` would write. The shape is deliberately not
    /// the TOML schema: that one has holes (missing rows) this one fills
    /// in. `builtin` stands in for the installed list when there is no
    /// system to ask.
    pub fn export(&self, installed: &[String], builtin: bool) -> serde_json::Value {
        let scheds: serde_json::Map<String, serde_json::Value> = self
            .export_names(installed, builtin)
            .into_iter()
            .map(|sched| {
                let modes: serde_json::Map<String, serde_json::Value> = MODES
                    .iter()
                    .map(|mode| {
                        (
                            mode.label().to_owned(),
                            serde_json::Value::from(self.flags(&sched, *mode)),
                        )
                    })
                    .collect();
                (sched, serde_json::Value::Object(modes))
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

/// `text` as a TOML basic string on one line: quoted, with the quote,
/// the backslash and every control character escaped.
fn toml_basic_string(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            '\r' => out.push_str("\\r"),
            c if c.is_control() => out.push_str(&format!("\\u{:04X}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// The schedulers [`builtin_flags`] has rows for, in table order. Kept
/// in step with the table by hand; the test below catches a name that
/// resolves to nothing.
const BUILTIN_SCHEDS: [&str; 7] = [
    "scx_bpfland",
    "scx_lavd",
    "scx_mavd",
    "scx_p2dq",
    "scx_chaos",
    "scx_tickless",
    "scx_cosmos",
];

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

        // scx_mavd is a fork of scx_lavd with the same command line.
        ("scx_lavd" | "scx_mavd", Mode::Auto) => &["--autopilot", "--pinned-slice-us", "500"],
        ("scx_lavd" | "scx_mavd", Mode::Gaming | Mode::LowLatency) => {
            &["--performance", "--pinned-slice-us", "500"]
        }
        ("scx_lavd" | "scx_mavd", Mode::PowerSave) => &["--powersave", "--pinned-slice-us", "500"],
        ("scx_lavd" | "scx_mavd", Mode::Server) => &[
            "--performance",
            "--slice-min-us",
            "3000",
            "--slice-max-us",
            "10000",
            "--pinned-slice-us",
            "3000",
        ],

        // scx_chaos is a fork of scx_p2dq with the same command line.
        ("scx_p2dq" | "scx_chaos", Mode::Auto) => &["--sched-mode", "default"],
        ("scx_p2dq" | "scx_chaos", Mode::Gaming) => {
            &["--task-slice", "true", "-f", "--sched-mode", "performance"]
        }
        ("scx_p2dq" | "scx_chaos", Mode::PowerSave) => &["--sched-mode", "efficiency"],
        ("scx_p2dq" | "scx_chaos", Mode::LowLatency) => &["-y", "-f", "--task-slice", "true"],
        ("scx_p2dq" | "scx_chaos", Mode::Server) => &["--keep-running"],

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
        let out = profiles.export(&strs(&["scx_rusty", "scx_lavd"]), false);
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
        // The installed ones and the file's, not the whole built-in
        // table: the keys have meant "available here" since the export
        // appeared. The default counts as named by the file.
        let names: Vec<&String> = out["schedulers"].as_object().unwrap().keys().collect();
        assert_eq!(names, ["scx_bpfland", "scx_lavd", "scx_rusty"]);
        let out = profiles.export(&strs(&["scx_rusty"]), false);
        assert!(out["schedulers"].get("scx_lavd").is_some(), "default_sched");
        assert!(out["schedulers"].get("scx_cosmos").is_none());
        // --builtin: the table's own schedulers, nothing installed.
        let out = Profiles::default().export(&[], true);
        let names: Vec<&String> = out["schedulers"].as_object().unwrap().keys().collect();
        assert_eq!(names.len(), BUILTIN_SCHEDS.len());
    }

    #[test]
    fn every_builtin_scheduler_has_a_row() {
        // The list is kept by hand; a name that resolves to nothing in
        // every mode is a typo or a scheduler dropped from the table.
        for sched in BUILTIN_SCHEDS {
            assert!(
                MODES
                    .iter()
                    .any(|mode| !builtin_flags(sched, *mode).is_empty()),
                "{sched} has no built-in rows"
            );
        }
    }

    #[test]
    fn toml_export_loads_back_to_the_same_flags() {
        // Built-in only, nothing installed: the output is a profiles
        // file that resolves every scheduler and mode as the table does.
        let builtin = Profiles::default();
        let text = builtin.export_toml(&[]).unwrap();
        assert!(text.starts_with("# scxtui profiles, resolved from the built-in defaults."));
        let reloaded = Profiles {
            config: Profiles::parse(&text).unwrap(),
            source: None,
        };
        for sched in BUILTIN_SCHEDS {
            for mode in MODES {
                assert_eq!(
                    reloaded.flags(sched, mode),
                    builtin.flags(sched, mode),
                    "{sched} {mode:?}"
                );
            }
        }
        assert_eq!(reloaded.default_launch(), None);
        // No default: the keys are there as a commented template, which
        // the reload ignores, and no live default_* key appears.
        assert!(
            text.contains("#default_sched = \"scx_bpfland\"\n"),
            "{text}"
        );
        // With schedulers installed, the example is one of them, so the
        // template works as is on this system.
        let with_installed = builtin
            .export_toml(&strs(&["scx_rusty", "scx_flash"]))
            .unwrap();
        assert!(
            with_installed.contains("#default_sched = \"scx_flash\"\n"),
            "{with_installed}"
        );
        assert!(text.contains("#default_mode = \"Auto\""), "{text}");
        assert!(!text.contains("\ndefault_sched"), "{text}");
        // A name that would break out of the comment is escaped, so the
        // template stays a comment and the reload still sees no default.
        let hostile = builtin
            .export_toml(&strs(&["scx_a\ndefault_sched = \"scx_evil\""]))
            .unwrap();
        assert!(!hostile.contains("\ndefault_sched"), "{hostile}");
        let hostile_reloaded = Profiles {
            config: Profiles::parse(&hostile).unwrap(),
            source: None,
        };
        assert_eq!(hostile_reloaded.default_launch(), None);
        // The escaped form is what TOML reads back as the same string.
        let quoted = toml_basic_string("a\"b\\c\nd\u{1}");
        assert_eq!(quoted, "\"a\\\"b\\\\c\\nd\\u0001\"");
        let parsed: toml::Table = toml::from_str(&format!("x = {quoted}")).unwrap();
        assert_eq!(parsed["x"].as_str(), Some("a\"b\\c\nd\u{1}"));
        // Same source on both sides, so here the text itself is a fixed
        // point. With a file the header names it, so only the flags are
        // promised to come back; see below.
        assert_eq!(reloaded.export_toml(&[]).unwrap(), text);

        // With a file: its rows, its default, a scheduler it names that
        // has no table, and one that is only installed, all survive the
        // round trip, for every scheduler the export covers and every
        // mode. The default scheduler is covered even without a row.
        let config = Profiles::parse(
            "default_sched = \"scx_flash\"\ndefault_mode = \"PowerSave\"\n\
[scheds.scx_bpfland]\ngaming_mode = [\"-k\"]\nauto_mode = []\n\
[scheds.scx_rusty]\nserver_mode = [\"-x\"]\n",
        )
        .unwrap();
        let profiles = Profiles {
            config,
            source: Some(PathBuf::from("/etc/scxtui.toml")),
        };
        let installed = strs(&["scx_rlfifo"]);
        let text = profiles.export_toml(&installed).unwrap();
        assert!(text.contains("/etc/scxtui.toml over the built-in defaults"));
        let reloaded = Profiles {
            config: Profiles::parse(&text).unwrap(),
            source: None,
        };
        assert_eq!(
            reloaded.default_launch(),
            Some(("scx_flash", Mode::PowerSave))
        );
        assert!(
            !text.contains("#default_sched"),
            "no template with a default set"
        );
        // A default scheduler without a mode is Auto; the export says so.
        let only_sched = Profiles {
            config: Profiles::parse("default_sched = \"scx_lavd\"\n").unwrap(),
            source: None,
        };
        let auto = only_sched.export_toml(&[]).unwrap();
        assert!(
            auto.contains("default_sched = \"scx_lavd\"\ndefault_mode = \"Auto\"\n"),
            "{auto}"
        );
        for sched in profiles.export_names(&installed, true) {
            for mode in MODES {
                assert_eq!(
                    reloaded.flags(&sched, mode),
                    profiles.flags(&sched, mode),
                    "{sched} {mode:?}"
                );
            }
        }
        for sched in ["scx_flash", "scx_rlfifo", "scx_rusty", "scx_lavd"] {
            assert!(text.contains(&format!("[scheds.{sched}]")), "{sched}");
        }
        // Spot checks on what the loop proves: file row, explicit empty
        // row, built-in fallback, a row for a scheduler with no table.
        assert_eq!(reloaded.flags("scx_bpfland", Mode::Gaming), strs(&["-k"]));
        assert!(reloaded.flags("scx_bpfland", Mode::Auto).is_empty());
        assert_eq!(
            reloaded.flags("scx_bpfland", Mode::Server),
            strs(&["-s", "20000", "-S"])
        );
        assert_eq!(reloaded.flags("scx_rusty", Mode::Server), strs(&["-x"]));
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
            profiles.modes_for("scx_bpfland", &strs(&["-m", "all"])),
            [Mode::Gaming]
        );
        // Shared flag sets: all matches are reported, the selector takes
        // the first.
        let shared = strs(&["--performance", "--pinned-slice-us", "500"]);
        assert_eq!(
            profiles.modes_for("scx_lavd", &shared),
            [Mode::Gaming, Mode::LowLatency]
        );

        // No flags: Auto alone, never the modes that merely lack a row.
        // cosmos has rows for three modes, rburst for none; both run
        // their own defaults in Auto, and the answer is the same.
        assert_eq!(profiles.modes_for("scx_cosmos", &[]), [Mode::Auto]);
        assert_eq!(profiles.modes_for("scx_rburst", &[]), [Mode::Auto]);
        assert!(profiles.modes_for("scx_bpfland", &strs(&["-k"])).is_empty());
        // A file row that is explicitly empty is still not a profile.
        let empty_row = Profiles::parse("[scheds.scx_rburst]\nserver_mode = []\n").unwrap();
        let profiles = Profiles {
            config: empty_row,
            ..Profiles::default()
        };
        assert_eq!(profiles.modes_for("scx_rburst", &[]), [Mode::Auto]);
    }
}
