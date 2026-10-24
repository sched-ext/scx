// SPDX-License-Identifier: GPL-2.0

//! The unit's `EnvironmentFile`: how it is read, the way systemd reads
//! it, and how the three managed keys are rewritten in place.

use std::collections::HashMap;

/// The keys applying a profile manages.
pub const PROFILE_KEY: &str = "SCX_PROFILE";
pub const SCHEDULER_KEY: &str = "SCX_SCHEDULER";
pub const FLAGS_KEY: &str = "SCX_FLAGS";
pub const MANAGED_KEYS: [&str; 3] = [PROFILE_KEY, SCHEDULER_KEY, FLAGS_KEY];

/// The marker `run` writes: a scheduler started on purpose outside any
/// profile. Reserved, never a profile id, so detection never matches it
/// against the list.
pub const CUSTOM_MARKER: &str = "custom";

/// Runtime overrides the unit's `ExecStart` prefers over the file.
pub const SCHEDULER_OVERRIDE_KEY: &str = "SCX_SCHEDULER_OVERRIDE";
pub const FLAGS_OVERRIDE_KEY: &str = "SCX_FLAGS_OVERRIDE";

/// Parses an `EnvironmentFile=` the way systemd does for what matters
/// here: `#` and `;` start comments, `KEY=VALUE` per line, values may be
/// single- or double-quoted, later assignments win. Line continuations
/// and escapes inside quotes are not interpreted.
pub fn parse(content: &str) -> Vec<(String, String)> {
    content
        .lines()
        .map(str::trim)
        .filter(|line| !line.starts_with('#') && !line.starts_with(';'))
        .filter_map(|line| {
            let (key, value) = line.split_once('=')?;
            let key = key.trim();
            let valid =
                !key.is_empty() && key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
            valid.then(|| (key.to_owned(), unquote(value).to_owned()))
        })
        .collect()
}

/// The last value of each key.
pub fn parse_map(content: &str) -> HashMap<String, String> {
    parse(content).into_iter().collect()
}

pub(crate) fn unquote(value: &str) -> &str {
    let value = value.trim();
    value
        .strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .or_else(|| value.strip_prefix('\'').and_then(|s| s.strip_suffix('\'')))
        .unwrap_or(value)
}

/// The unit expands the flags unquoted (`exec $SCHED $FLAGS`), so bash
/// splits them on whitespace without interpreting quotes. Mirror that.
pub fn split_flags(value: &str) -> Vec<String> {
    value.split_whitespace().map(str::to_owned).collect()
}

/// What a rewrite does to `SCX_SCHEDULER` and `SCX_FLAGS`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Launch {
    /// Leave both keys as they are.
    Keep,
    /// Write both keys. `SCX_FLAGS` is written even when empty, so a
    /// profile without options clears a stale set.
    Set(String, Vec<String>),
    /// Remove both keys.
    Remove,
}

/// What a rewrite does to the managed keys.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Written {
    /// `Some` writes the marker, `None` removes it.
    pub profile: Option<String>,
    pub launch: Launch,
}

impl Written {
    /// The values a key would hold after the write, for the override
    /// check.
    pub fn values(&self) -> Vec<(&'static str, String)> {
        let mut values = Vec::new();
        if let Some(id) = &self.profile {
            values.push((PROFILE_KEY, id.clone()));
        }
        if let Launch::Set(sched, flags) = &self.launch {
            values.push((SCHEDULER_KEY, sched.clone()));
            values.push((FLAGS_KEY, flags.join(" ")));
        }
        values
    }
}

/// Rewrites the managed keys in place, preserving every other line and
/// appending keys that were absent. A key being removed disappears from
/// the file, and a key that appears more than once collapses into one.
/// Matches on the parsed key, the way the reader does, so a line written
/// as `SCX_SCHEDULER = x` is replaced rather than kept next to the new
/// one. Always ends with a trailing newline.
pub fn render(content: &str, written: &Written) -> String {
    // What each managed key becomes: `None` leaves the line as it is,
    // `Some(None)` drops it, `Some(Some(line))` replaces it.
    let plan = |key: &str| -> Option<Option<String>> {
        match key {
            PROFILE_KEY => Some(
                written
                    .profile
                    .as_ref()
                    .map(|id| format!("{PROFILE_KEY}={id}")),
            ),
            SCHEDULER_KEY | FLAGS_KEY => match &written.launch {
                Launch::Keep => None,
                Launch::Remove => Some(None),
                Launch::Set(sched, flags) => Some(Some(if key == SCHEDULER_KEY {
                    format!("{SCHEDULER_KEY}={sched}")
                } else {
                    format!("{FLAGS_KEY}=\"{}\"", flags.join(" "))
                })),
            },
            _ => None,
        }
    };
    let mut seen: Vec<&str> = Vec::new();
    let mut lines: Vec<String> = Vec::new();
    for line in content.lines() {
        let key = line.split_once('=').map(|(key, _)| key.trim());
        match key.map(|k| (k, plan(k))) {
            Some((k, Some(action))) => {
                if !seen.contains(&k) {
                    seen.push(k);
                    if let Some(new) = action {
                        lines.push(new);
                    }
                }
            }
            _ => lines.push(line.to_owned()),
        }
    }
    for key in [SCHEDULER_KEY, FLAGS_KEY, PROFILE_KEY] {
        if !seen.contains(&key)
            && let Some(Some(new)) = plan(key)
        {
            lines.push(new);
        }
    }
    let mut text = lines.join("\n");
    text.push('\n');
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pairs(list: &[(&str, &str)]) -> Vec<(String, String)> {
        list.iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect()
    }

    fn strs(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn parses_like_systemd() {
        let content = "# comment\n\
                       SCX_SCHEDULER=scx_cosmos\n\
                       ; disabled\n\
                       SCX_FLAGS='-s 700 -S'\n\
                       not a key=1\n\
                       SCX_SCHEDULER = scx_lavd\n";
        assert_eq!(
            parse(content),
            pairs(&[
                ("SCX_SCHEDULER", "scx_cosmos"),
                ("SCX_FLAGS", "-s 700 -S"),
                ("SCX_SCHEDULER", "scx_lavd"),
            ])
        );
        assert_eq!(parse_map(content)["SCX_SCHEDULER"], "scx_lavd");
        assert_eq!(unquote("\"x\""), "x");
        assert_eq!(unquote("\"x"), "\"x");
        assert_eq!(split_flags("  -s   700 -S "), strs(&["-s", "700", "-S"]));
    }

    #[test]
    fn render_replaces_in_place_and_appends_what_is_missing() {
        let content = "# keep me\nSCX_SCHEDULER = scx_cosmos\nOTHER=1\nSCX_FLAGS=\"-v\"\n";
        let written = Written {
            profile: Some("gaming".into()),
            launch: Launch::Set("/usr/bin/scx_lavd".into(), strs(&["--performance"])),
        };
        assert_eq!(
            render(content, &written),
            "# keep me\nSCX_SCHEDULER=/usr/bin/scx_lavd\nOTHER=1\nSCX_FLAGS=\"--performance\"\n\
SCX_PROFILE=gaming\n"
        );
        let written = Written {
            profile: Some("desktop".into()),
            launch: Launch::Set("/usr/bin/scx_cosmos".into(), Vec::new()),
        };
        assert_eq!(
            render("", &written),
            "SCX_SCHEDULER=/usr/bin/scx_cosmos\nSCX_FLAGS=\"\"\nSCX_PROFILE=desktop\n"
        );
    }

    #[test]
    fn default_removes_every_managed_key_and_keeps_the_rest() {
        // gaming -> default: nothing of the profile is left for a later
        // `systemctl start` to pick up.
        let gaming = render(
            "# scx.service\nOTHER=1\n",
            &Written {
                profile: Some("gaming".into()),
                launch: Launch::Set("/usr/bin/scx_lavd".into(), strs(&["--performance"])),
            },
        );
        let default = render(
            &gaming,
            &Written {
                profile: None,
                launch: Launch::Remove,
            },
        );
        assert_eq!(default, "# scx.service\nOTHER=1\n");
        assert!(!parse_map(&default).contains_key(SCHEDULER_KEY));
    }

    #[test]
    fn run_marks_custom_and_keep_leaves_the_launch_alone() {
        let content = "SCX_PROFILE=gaming\nSCX_SCHEDULER=/usr/bin/scx_lavd\nSCX_FLAGS=\"-v\"\n";
        let written = Written {
            profile: Some(CUSTOM_MARKER.into()),
            launch: Launch::Set("/usr/bin/scx_rusty".into(), Vec::new()),
        };
        assert_eq!(
            render(content, &written),
            "SCX_PROFILE=custom\nSCX_SCHEDULER=/usr/bin/scx_rusty\nSCX_FLAGS=\"\"\n"
        );
        let written = Written {
            profile: None,
            launch: Launch::Keep,
        };
        assert_eq!(
            render(content, &written),
            "SCX_SCHEDULER=/usr/bin/scx_lavd\nSCX_FLAGS=\"-v\"\n"
        );
        assert_eq!(written.values(), Vec::<(&str, String)>::new());
    }

    #[test]
    fn render_folds_duplicate_keys_into_one() {
        let content = "SCX_PROFILE=a\nSCX_PROFILE=b\nSCX_FLAGS=x\nSCX_FLAGS=y\n";
        let written = Written {
            profile: Some("c".into()),
            launch: Launch::Set("scx_lavd".into(), Vec::new()),
        };
        assert_eq!(
            render(content, &written),
            "SCX_PROFILE=c\nSCX_FLAGS=\"\"\nSCX_SCHEDULER=scx_lavd\n"
        );
    }
}
