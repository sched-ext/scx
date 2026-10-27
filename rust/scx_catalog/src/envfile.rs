// SPDX-License-Identifier: GPL-2.0

//! The unit's `EnvironmentFile`: how it is read, the way systemd reads
//! it, and how the two managed keys are rewritten in place.

use std::collections::HashMap;

/// The keys starting a scheduler manages: the ones the unit's
/// `ExecStart` expands.
pub const SCHEDULER_KEY: &str = "SCX_SCHEDULER";
pub const FLAGS_KEY: &str = "SCX_FLAGS";
pub const MANAGED_KEYS: [&str; 2] = [SCHEDULER_KEY, FLAGS_KEY];

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

/// What a rewrite does to the managed keys.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Launch {
    /// Write both keys. `SCX_FLAGS` is written even when empty, so a
    /// start without options clears a stale set.
    Set(String, Vec<String>),
    /// Remove both keys.
    Remove,
}

impl Launch {
    /// The values a key would hold after the write, for the override
    /// check.
    pub fn values(&self) -> Vec<(&'static str, String)> {
        match self {
            Launch::Set(sched, flags) => {
                vec![(SCHEDULER_KEY, sched.clone()), (FLAGS_KEY, flags.join(" "))]
            }
            Launch::Remove => Vec::new(),
        }
    }
}

/// Rewrites the managed keys in place, preserving every other line and
/// appending keys that were absent. A key being removed disappears from
/// the file, and a key that appears more than once collapses into one.
/// Matches on the parsed key, the way the reader does, so a line written
/// as `SCX_SCHEDULER = x` is replaced rather than kept next to the new
/// one. Always ends with a trailing newline.
pub fn render(content: &str, launch: &Launch) -> String {
    // What a managed key becomes: `None` drops the line, `Some(line)`
    // replaces it.
    let plan = |key: &str| -> Option<String> {
        match launch {
            Launch::Remove => None,
            Launch::Set(sched, flags) => Some(if key == SCHEDULER_KEY {
                format!("{SCHEDULER_KEY}={sched}")
            } else {
                format!("{FLAGS_KEY}=\"{}\"", flags.join(" "))
            }),
        }
    };
    let mut seen: Vec<&str> = Vec::new();
    let mut lines: Vec<String> = Vec::new();
    for line in content.lines() {
        let key = line.split_once('=').map(|(key, _)| key.trim());
        match key.filter(|k| MANAGED_KEYS.contains(k)) {
            Some(k) => {
                if !seen.contains(&k) {
                    seen.push(k);
                    if let Some(new) = plan(k) {
                        lines.push(new);
                    }
                }
            }
            None => lines.push(line.to_owned()),
        }
    }
    for key in MANAGED_KEYS {
        if !seen.contains(&key)
            && let Some(new) = plan(key)
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
        let launch = Launch::Set("/usr/bin/scx_lavd".into(), strs(&["--performance"]));
        assert_eq!(
            render(content, &launch),
            "# keep me\nSCX_SCHEDULER=/usr/bin/scx_lavd\nOTHER=1\nSCX_FLAGS=\"--performance\"\n"
        );
        let launch = Launch::Set("/usr/bin/scx_cosmos".into(), Vec::new());
        assert_eq!(
            render("", &launch),
            "SCX_SCHEDULER=/usr/bin/scx_cosmos\nSCX_FLAGS=\"\"\n"
        );
        assert_eq!(
            launch.values(),
            vec![
                ("SCX_SCHEDULER", "/usr/bin/scx_cosmos".to_owned()),
                ("SCX_FLAGS", String::new())
            ]
        );
    }

    #[test]
    fn default_removes_both_managed_keys_and_keeps_the_rest() {
        // lavd with options -> default: nothing is left for a later
        // `systemctl start` to pick up.
        let lavd = render(
            "# scx.service\nOTHER=1\n",
            &Launch::Set("/usr/bin/scx_lavd".into(), strs(&["--performance"])),
        );
        let default = render(&lavd, &Launch::Remove);
        assert_eq!(default, "# scx.service\nOTHER=1\n");
        assert!(!parse_map(&default).contains_key(SCHEDULER_KEY));
        assert_eq!(Launch::Remove.values(), Vec::<(&str, String)>::new());
    }

    #[test]
    fn render_folds_duplicate_keys_into_one() {
        let content = "SCX_FLAGS=x\nSCX_FLAGS=y\nSCX_SCHEDULER=a\nSCX_SCHEDULER=b\n";
        let launch = Launch::Set("scx_lavd".into(), Vec::new());
        assert_eq!(
            render(content, &launch),
            "SCX_FLAGS=\"\"\nSCX_SCHEDULER=scx_lavd\n"
        );
    }
}
