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

/// Syntax systemd accepts in an `EnvironmentFile=` that the line-based
/// [`parse`] does not: a quoted value that continues past the end of
/// its line, and a line continued with a trailing backslash. Parsing
/// such a file line by line would read the inside of a multi-line
/// value as assignments of its own, so a file that uses either is
/// reported rather than guessed at. Returns what was found and where.
pub fn unsupported(content: &str) -> Option<String> {
    // systemd ends a line at `\n` or at `\r`; `str::lines` ends one at
    // `\n` only (stripping a `\r` before it). A bare `\r` would hide
    // an assignment inside what this reader takes for one line.
    if content.contains('\r') && content.replace("\r\n", "").contains('\r') {
        return Some(
            "a bare carriage return ends a line for systemd but not for this reader; use \
newlines (CRLF is fine)"
                .to_owned(),
        );
    }
    for (idx, raw) in content.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if line.ends_with('\\') {
            return Some(format!(
                "line {}: continued with a trailing backslash, which is not supported",
                idx + 1
            ));
        }
        let Some((_, value)) = line.split_once('=') else {
            continue;
        };
        let value = value.trim();
        if let Some(quote) = value.chars().next().filter(|c| matches!(c, '"' | '\''))
            && !closes_on_the_line(&value[1..], quote)
        {
            return Some(format!(
                "line {}: a quoted value continues past the end of the line; multi-line \
values are not supported",
                idx + 1
            ));
        }
    }
    None
}

/// Whether a quoted value, given from after its opening `quote`, is
/// closed by the last non-blank character of its line. That is the one
/// shape the line-based reader handles. systemd's reader does more: a
/// closed quote returns it to `PRE_VALUE`, from where another quoted or
/// bare segment may follow (`'a''b` is `a` and then an open `b` that
/// runs on to the next lines), so a value that goes on after its
/// closing quote is refused rather than read. A backslash escapes the
/// character after it inside double quotes only (`DOUBLE_QUOTE_VALUE_ESCAPE`);
/// inside single quotes it is an ordinary character, so `'a\'` is
/// closed.
fn closes_on_the_line(rest: &str, quote: char) -> bool {
    let mut escaped = false;
    for (idx, c) in rest.char_indices() {
        if quote == '"' {
            if escaped {
                escaped = false;
                continue;
            }
            if c == '\\' {
                escaped = true;
                continue;
            }
        }
        if c == quote {
            return rest[idx + c.len_utf8()..].trim().is_empty();
        }
    }
    false
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
    /// Write both keys empty. Not removed: an `EnvironmentFile=`
    /// assignment wins over `Environment=` in the unit file or a
    /// drop-in, so an empty value in the file masks a scheduler set
    /// there, where a missing key would let it through to the next
    /// `systemctl start`. Empty is unset to the unit's shell.
    Clear,
}

impl Launch {
    /// The values a key would hold after the write, for the override
    /// check.
    pub fn values(&self) -> Vec<(&'static str, String)> {
        match self {
            Launch::Set(sched, flags) => {
                vec![(SCHEDULER_KEY, sched.clone()), (FLAGS_KEY, flags.join(" "))]
            }
            // An UnsetEnvironment= of an empty key changes nothing: unset
            // and empty are the same to the shell.
            Launch::Clear => Vec::new(),
        }
    }
}

/// Rewrites the managed keys in place, preserving every other line and
/// appending keys that were absent. A key that appears more than once
/// collapses into one.
/// Matches on the parsed key, the way the reader does, so a line written
/// as `SCX_SCHEDULER = x` is replaced rather than kept next to the new
/// one. Always ends with a trailing newline.
pub fn render(content: &str, launch: &Launch) -> String {
    // What a managed key's line becomes.
    let plan = |key: &str| -> String {
        let (sched, flags): (&str, String) = match launch {
            Launch::Clear => ("", String::new()),
            Launch::Set(sched, flags) => (sched, flags.join(" ")),
        };
        if key == SCHEDULER_KEY {
            // A path is written bare, as the shipped file has it; an
            // empty value is quoted so that the line reads as a choice.
            match sched {
                "" => format!("{SCHEDULER_KEY}=\"\""),
                sched => format!("{SCHEDULER_KEY}={sched}"),
            }
        } else {
            format!("{FLAGS_KEY}=\"{flags}\"")
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
                    lines.push(plan(k));
                }
            }
            None => lines.push(line.to_owned()),
        }
    }
    for key in MANAGED_KEYS {
        if !seen.contains(&key) {
            lines.push(plan(key));
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
    fn default_clears_both_managed_keys_in_place_and_keeps_the_rest() {
        // lavd with options -> default: both keys stay, empty, so a
        // value from a lower layer (Environment= in a drop-in) is
        // masked rather than let through to a later `systemctl start`.
        let lavd = render(
            "# scx.service\nOTHER=1\n",
            &Launch::Set("/usr/bin/scx_lavd".into(), strs(&["--performance"])),
        );
        let default = render(&lavd, &Launch::Clear);
        assert_eq!(
            default,
            "# scx.service\nOTHER=1\nSCX_SCHEDULER=\"\"\nSCX_FLAGS=\"\"\n"
        );
        assert_eq!(parse_map(&default)[SCHEDULER_KEY], "");
        // A file that never had the keys gets them, empty.
        assert_eq!(
            render("# scx.service\n", &Launch::Clear),
            "# scx.service\nSCX_SCHEDULER=\"\"\nSCX_FLAGS=\"\"\n"
        );
        assert_eq!(Launch::Clear.values(), Vec::<(&str, String)>::new());
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

    #[test]
    fn multi_line_values_and_continuations_are_reported_not_parsed() {
        // A quoted value that spans lines: the line-based reader would
        // take the assignment inside it for a real one.
        let notes = "NOTES='Example configuration:\nSCX_SCHEDULER=scx_cosmos\n'\n\
                     SCX_SCHEDULER=/usr/bin/scx_cosmos\n";
        assert!(unsupported(notes).unwrap().starts_with("line 1:"));
        let cont = "SCX_FLAGS=-s \\\n  500\n";
        assert!(unsupported(cont).unwrap().contains("backslash"));
        let double = "X=\"open\n";
        assert!(unsupported(double).is_some());
        // A lone quote opens a value that never closes on its line.
        assert!(unsupported("ODD=\"\n").is_some());
        // The closing quote must be a real one: an escaped quote at the
        // end of the first line leaves the value open, and the next line
        // is part of it, not an assignment.
        let escaped_end = "NOTES=\"Example configuration:\\\"\nSCX_SCHEDULER=scx_cosmos\n\"\n";
        assert!(unsupported(escaped_end).unwrap().starts_with("line 1:"));
        // Inside single quotes a backslash is an ordinary character, so
        // this line is closed and the next one is an assignment.
        assert_eq!(
            unsupported("NOTES='Example:\\'\nSCX_SCHEDULER=scx_cosmos\n"),
            None
        );
        // Two backslashes are one literal backslash; the quote after
        // them closes.
        assert_eq!(unsupported("PATHS=\"C:\\\\\"\n"), None);
        assert_eq!(unsupported("X='a\\\\'\n"), None);
        // A closed quote may be reopened in systemd, and the reopened
        // segment may run on; anything after the closing quote is
        // refused, in either style, whether it reopens or not.
        let reopened = "NOTES='a''b\nSCX_SCHEDULER=scx_cosmos\n'\n";
        assert!(unsupported(reopened).unwrap().starts_with("line 1:"));
        let reopened = "NOTES=\"a\"\"b\nSCX_SCHEDULER=scx_cosmos\n\"\n";
        assert!(unsupported(reopened).unwrap().starts_with("line 1:"));
        assert!(unsupported("X='a' b\n").is_some());
        assert!(unsupported("X=\"a\" \"b\"\n").is_some());
        // Blanks after the closing quote are fine.
        assert_eq!(unsupported("X='a'   \n"), None);
        // A bare carriage return is a line end to systemd, so this is
        // two assignments there and one here: refused. CRLF reads the
        // same both ways and passes.
        assert!(
            unsupported("NOTES=ok\rSCX_SCHEDULER=/usr/bin/scx_flash\r")
                .unwrap()
                .contains("carriage return")
        );
        assert_eq!(unsupported("NOTES=ok\r\nSCX_SCHEDULER=x\r\n"), None);
        assert!(unsupported("A=1\r\nB=2\rC=3\n").is_some());
        // Single-line quoting, an escaped quote inside, comments and
        // blank lines are all fine.
        let ok = "# c\n\nSCX_SCHEDULER=\"/usr/bin/scx_cosmos\"\nSCX_FLAGS='-s 5'\n\
                  NAME=\"a\\\"b\"\n";
        assert_eq!(unsupported(ok), None);
        assert!(closes_on_the_line("ab\"", '"'));
        assert!(!closes_on_the_line("ab\\\"", '"'));
        assert!(closes_on_the_line("ab\\\\\"", '"'));
        assert!(closes_on_the_line("ab\\'", '\''));
        assert!(!closes_on_the_line("a'b'", '\''));
    }
}
