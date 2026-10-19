// SPDX-License-Identifier: GPL-2.0

//! `scx.service` backend: the systemd unit shipped in `services/`, driven
//! by its environment (`SCX_SCHEDULER` / `SCX_FLAGS`) and plain
//! `systemctl`.
//!
//! Two sources of truth, kept apart on purpose. What runs now comes from
//! the unit's main process (`MainPID`, then `/proc/<pid>/cmdline`): the
//! unit is `Type=simple` and its `ExecStart` execs the scheduler, so the
//! main process *is* the scheduler. What the next start would run comes
//! from the unit's environment, assembled the way systemd assembles it
//! (see [`unit_environment`]) and resolved like `ExecStart` does:
//! `${SCX_SCHEDULER_OVERRIDE:-$SCX_SCHEDULER}` and
//! `${SCX_FLAGS_OVERRIDE:-$SCX_FLAGS}`. The file is routinely edited under
//! a running unit (by this TUI, among others), so inferring the running
//! scheduler from it would be a guess.
//!
//! Privileges: reading the files, `/proc` and querying systemd work as any
//! user, but editing the file and starting/stopping the unit generally
//! require root. Both paths fail with messages that say so.

use std::collections::BTreeSet;
use std::collections::HashMap;
use std::fs;
use std::io::{ErrorKind, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};

use super::{Process, SchedulerBackend, Status};

pub const UNIT: &str = "scx.service";
/// `scx_`-prefixed executables that are not schedulers and must not be
/// offered as such. The prefix scan is the only scheduler source the
/// service has, so these are filtered by name.
const NOT_SCHEDULERS: [&str; 4] = [
    "scx_loader",
    "scx_characterize",
    "scx_forge_agent",
    "scx_rustland_core",
];

pub struct ServiceBackend {
    /// The unit's first `EnvironmentFile=` as seen at startup, for the
    /// header line. `None` when the unit declares none. Writes never
    /// trust it: they re-resolve the path from the live unit and refuse
    /// when it no longer matches what the header shows.
    config_path: Option<PathBuf>,
}

/// One `EnvironmentFile=` entry of the unit, in declaration order.
#[derive(Debug, Clone, PartialEq)]
struct EnvFile {
    path: PathBuf,
    /// The `-` prefix: a missing file is fine rather than a start failure.
    optional: bool,
}

/// What `systemctl show` reports about the unit, from one round-trip.
#[derive(Debug, Default, PartialEq)]
struct UnitInfo {
    active: bool,
    main_pid: Option<u32>,
    /// `Environment=` entries, unit file and drop-ins merged by systemd.
    environment: Vec<(String, String)>,
    env_files: Vec<EnvFile>,
    /// `UnsetEnvironment=` entries: `NAME` drops the variable, `NAME=VALUE`
    /// drops it only when it has exactly that value. Applied last.
    unset_environment: Vec<String>,
}

/// The environment the unit's `ExecStart` sees, assembled per
/// systemd.exec(5): the manager environment (`systemctl set-environment`,
/// `DefaultEnvironment=`) is the base, `Environment=` overrides it, each
/// `EnvironmentFile=` overrides both, later files winning, and
/// `UnsetEnvironment=` is applied to the result. Every layer may set the
/// `*_OVERRIDE` variables, not just the manager.
#[derive(Debug, Default)]
struct UnitEnvironment {
    vars: HashMap<String, String>,
    /// First reason the assembled environment may not be the one the
    /// unit sees: a layer that could not be read, a required file that
    /// is missing. A missing optional file, and a missing *first* file
    /// (the one the TUI creates on its first write), are not problems.
    /// While set, the next-start answer is incomplete and writes are
    /// refused, since their effect cannot be predicted.
    error: Option<String>,
}

impl UnitEnvironment {
    fn get(&self, key: &str) -> Option<&str> {
        self.vars.get(key).map(String::as_str)
    }

    /// `${key:-}`: unset and empty are the same thing to the shell.
    fn non_empty(&self, key: &str) -> Option<&str> {
        self.get(key).filter(|v| !v.is_empty())
    }
}

impl ServiceBackend {
    /// Verifies the unit exists (so startup fails fast on systems without
    /// the scx service) and resolves the environment file it edits.
    pub fn connect() -> Result<Self> {
        let out = Command::new("systemctl")
            .args(["cat", UNIT])
            .output()
            .context("failed to run systemctl — is this a systemd system?")?;
        if !out.status.success() {
            bail!("{UNIT} unit not found — is the scx service installed?");
        }
        let info = unit_info()?;
        Ok(Self {
            config_path: editable_config_path(&info),
        })
    }

    fn systemctl(verb: &str) -> Result<()> {
        let out = Command::new("systemctl")
            .args([verb, UNIT])
            .output()
            .context("failed to run systemctl")?;
        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr);
            bail!(
                "systemctl {verb} {UNIT} failed: {} (controlling the unit may require root)",
                stderr.trim()
            );
        }
        Ok(())
    }

    /// Rewrites `SCX_SCHEDULER=` and `SCX_FLAGS=` in place, preserving
    /// every other line, appending keys that were absent.
    ///
    /// Only a *missing* file is treated as empty. Any other read failure
    /// (permissions, I/O, invalid UTF-8) aborts: rewriting a file whose
    /// contents could not be read would silently drop everything in it.
    fn write_config(&self, sched: &str, flags: &[String]) -> Result<()> {
        validate_value("scheduler name", sched)?;
        for flag in flags {
            validate_value("flag", flag)?;
        }
        // The write goes to the first environment file. systemd reads the
        // later ones after it, so a managed key set in any of them (or
        // dropped by UnsetEnvironment=) would make the write a no-op
        // that `systemctl restart` then reports as success. Refuse in
        // that case rather than restart into the wrong scheduler.
        let info = unit_info()?;
        let env = unit_environment(&info, manager_environment()?);
        if let Some(err) = env.error {
            bail!("the unit's environment could not be resolved ({err}); not writing");
        }
        let path = write_target(&info, self.config_path.as_deref())?;
        check_write_effective(&info, sched, flags)?;
        write_env_file(&path, sched, flags)
    }
}

/// The file a write goes to, from the *live* unit: its first
/// `EnvironmentFile=`. A unit that declares none has no file a write
/// could reach, so there is nothing to guess at. A path that differs
/// from the one the header shows means the unit was redefined (drop-in
/// plus daemon-reload) under the TUI; the header would then be lying
/// about where the write went, so the write is refused until restart.
fn write_target(info: &UnitInfo, shown: Option<&Path>) -> Result<PathBuf> {
    let Some(current) = editable_config_path(info) else {
        bail!("{UNIT} declares no EnvironmentFile=; nothing scxtui writes would reach it");
    };
    match shown {
        Some(shown) if shown == current => Ok(current),
        _ => bail!(
            "{UNIT} now reads {} instead of {}; restart scxtui to pick up the new unit definition",
            current.display(),
            shown.map_or_else(|| "none".to_owned(), |p| p.display().to_string())
        ),
    }
}

/// The file rewrite itself, separated from the systemd checks so it can
/// be tested against scratch files.
fn write_env_file(config_path: &Path, sched: &str, flags: &[String]) -> Result<()> {
    {
        // Edit the file behind a symlink, not the link: renaming over the
        // link would replace it with a regular file.
        let path = match fs::canonicalize(config_path) {
            Ok(real) => real,
            Err(err) if err.kind() == ErrorKind::NotFound => config_path.to_path_buf(),
            Err(err) => {
                return Err(err)
                    .with_context(|| format!("cannot resolve {}", config_path.display()));
            }
        };
        let original = match fs::read_to_string(&path) {
            Ok(content) => Some(content),
            Err(err) if err.kind() == ErrorKind::NotFound => None,
            Err(err) => {
                return Err(err).with_context(|| {
                    format!(
                        "cannot read {} — refusing to rewrite a config that could not be read",
                        path.display()
                    )
                });
            }
        };
        let text = render_config(original.as_deref().unwrap_or(""), sched, flags);

        // Write to a unique temporary file in the same directory, then
        // rename: a crash or a full disk mid-write can never leave the
        // config truncated, two scxtui instances never share a scratch
        // file, and the rename is atomic within one filesystem.
        let dir = path.parent().unwrap_or_else(|| Path::new("/"));
        let mut tmp = tempfile::Builder::new()
            .prefix(".scxtui-")
            .tempfile_in(dir)
            .with_context(|| {
                format!(
                    "cannot create a temporary file in {} — editing the config requires root; \
run scxtui as root to control {UNIT}",
                    dir.display()
                )
            })?;
        tmp.write_all(text.as_bytes())
            .and_then(|()| tmp.as_file().sync_all())
            .with_context(|| format!("cannot write {}", tmp.path().display()))?;
        // The temp file is created 0600 and owned by this process; carry
        // the original's mode and owner over so the rename neither widens
        // nor tightens access to a file the admin set up. ACLs and xattrs
        // are not carried over. A missing config keeps the defaults.
        match fs::metadata(&path) {
            Ok(meta) => {
                fs::set_permissions(tmp.path(), meta.permissions()).with_context(|| {
                    format!("cannot preserve permissions from {}", path.display())
                })?;
                std::os::unix::fs::chown(tmp.path(), Some(meta.uid()), Some(meta.gid()))
                    .with_context(|| format!("cannot preserve ownership of {}", path.display()))?;
            }
            Err(err) if err.kind() == ErrorKind::NotFound => {}
            Err(err) => {
                return Err(err)
                    .with_context(|| format!("cannot read permissions from {}", path.display()));
            }
        }
        // Last look before the swap: if someone else changed the file
        // since it was read, their edit must not be overwritten with a
        // rendering of the old contents. Not airtight (nothing short of a
        // lock is), but it closes the window to the rename itself.
        let now = match fs::read_to_string(&path) {
            Ok(content) => Some(content),
            Err(err) if err.kind() == ErrorKind::NotFound => None,
            Err(err) => {
                return Err(err).with_context(|| format!("cannot re-read {}", path.display()));
            }
        };
        if now != original {
            bail!(
                "{} changed while scxtui was editing it — nothing written, refresh and retry",
                path.display()
            );
        }
        tmp.persist(&path)
            .map(drop)
            .with_context(|| format!("cannot move the new config into {}", path.display()))
    }
}

fn unit_info() -> Result<UnitInfo> {
    let out = Command::new("systemctl")
        .args([
            "show",
            UNIT,
            "--property=ActiveState,MainPID,Environment,EnvironmentFiles,UnsetEnvironment",
        ])
        .output()
        .context("failed to run systemctl show")?;
    if !out.status.success() {
        bail!(
            "systemctl show {UNIT} failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(parse_unit_info(&String::from_utf8_lossy(&out.stdout)))
}

/// Pure core of [`unit_info`]: `KEY=VALUE` lines. The unit counts as
/// active in every state where its process may be alive (`activating`
/// under `Type=simple` already has the process running). `MainPID=0`
/// means no process. `Environment=` and `UnsetEnvironment=` hold their
/// entries space-separated, each shell-quoted as needed.
/// `EnvironmentFiles=` prints one `PATH (ignore_errors=yes|no)` line per
/// file, in order; the `-` prefix of the unit file is not serialised,
/// the flag carries it.
fn parse_unit_info(output: &str) -> UnitInfo {
    let mut info = UnitInfo::default();
    for line in output.lines() {
        if let Some(value) = line.strip_prefix("ActiveState=") {
            info.active = matches!(value.trim(), "active" | "activating" | "reloading");
        } else if let Some(value) = line.strip_prefix("MainPID=") {
            info.main_pid = value.trim().parse().ok().filter(|pid| *pid != 0);
        } else if let Some(value) = line.strip_prefix("Environment=") {
            info.environment.extend(
                split_shell_words(value)
                    .into_iter()
                    .filter_map(split_assignment),
            );
        } else if let Some(value) = line.strip_prefix("UnsetEnvironment=") {
            info.unset_environment.extend(split_shell_words(value));
        } else if let Some(value) = line.strip_prefix("EnvironmentFiles=") {
            let value = value.trim();
            let (path, suffix) = value.rsplit_once(" (").unwrap_or((value, ""));
            let optional = suffix.trim_end_matches(')') == "ignore_errors=yes";
            if !path.is_empty() {
                info.env_files.push(EnvFile {
                    path: PathBuf::from(path),
                    optional,
                });
            }
        }
    }
    info
}

/// The file the TUI edits: the unit's first `EnvironmentFile=`. `None`
/// when the unit declares none; a conventional path is deliberately not
/// guessed, since a file the unit does not read changes nothing.
fn editable_config_path(info: &UnitInfo) -> Option<PathBuf> {
    info.env_files.first().map(|file| file.path.clone())
}

/// Reads the manager environment, the lowest layer. A failed query is an
/// error, not an empty layer: `systemctl set-environment` overrides live
/// here, and a next-start answer computed without them would be wrong.
fn manager_environment() -> Result<Vec<(String, String)>> {
    let out = Command::new("systemctl")
        .arg("show-environment")
        .output()
        .context("failed to run systemctl show-environment")?;
    if !out.status.success() {
        bail!(
            "systemctl show-environment failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(parse_manager_environment(&String::from_utf8_lossy(
        &out.stdout,
    )))
}

/// Pure core of [`manager_environment`]: one `KEY=VALUE` per line, the
/// value shell-quoted as needed.
fn parse_manager_environment(output: &str) -> Vec<(String, String)> {
    output
        .lines()
        .flat_map(split_shell_words)
        .filter_map(split_assignment)
        .collect()
}

/// Assembles the unit's environment from its layers; see
/// [`UnitEnvironment`]. Environment files are read here, not in the
/// layer parsers, so a read problem is reported instead of silently
/// reading as "nothing configured".
fn unit_environment(info: &UnitInfo, manager: Vec<(String, String)>) -> UnitEnvironment {
    let mut env = UnitEnvironment::default();
    env.vars.extend(manager);
    env.vars.extend(info.environment.iter().cloned());
    for (idx, file) in info.env_files.iter().enumerate() {
        match fs::read_to_string(&file.path) {
            Ok(content) => env.vars.extend(parse_env_file(&content)),
            Err(err) if err.kind() == ErrorKind::NotFound && (file.optional || idx == 0) => {}
            Err(err) => {
                let what = if err.kind() == ErrorKind::NotFound {
                    "missing, the unit cannot start"
                } else {
                    "unreadable"
                };
                env.error
                    .get_or_insert_with(|| format!("{} is {what}: {err}", file.path.display()));
            }
        }
    }
    for entry in &info.unset_environment {
        match entry.split_once('=') {
            Some((name, value)) => {
                if env.vars.get(name).is_some_and(|v| v == value) {
                    env.vars.remove(name);
                }
            }
            None => {
                env.vars.remove(entry.as_str());
            }
        }
    }
    env
}

/// The two keys a write manages.
const MANAGED_KEYS: [&str; 2] = ["SCX_SCHEDULER", "SCX_FLAGS"];

/// Whether writing `sched`/`flags` to the first environment file would
/// decide the unit's next start. Any later file setting a managed key
/// would override the write. So would `UnsetEnvironment=NAME`, and
/// `UnsetEnvironment=NAME=VALUE` exactly when VALUE is what would be
/// written (a conditional unset of some other value is harmless). Pure
/// over the file contents, which are read here, so a later file that
/// cannot be read counts as "cannot guarantee" as well.
fn check_write_effective(info: &UnitInfo, sched: &str, flags: &[String]) -> Result<()> {
    for file in info.env_files.iter().skip(1) {
        let content = match fs::read_to_string(&file.path) {
            Ok(content) => content,
            Err(err) if err.kind() == ErrorKind::NotFound && file.optional => continue,
            Err(err) => {
                bail!(
                    "{} is read by the unit after the file scxtui edits, but cannot be checked: {err}",
                    file.path.display()
                );
            }
        };
        if let Some((key, _)) = parse_env_file(&content)
            .into_iter()
            .find(|(key, _)| MANAGED_KEYS.contains(&key.as_str()))
        {
            bail!(
                "{key} is also set in {}, which the unit reads after {}; a write here \
would be overridden, edit that file instead",
                file.path.display(),
                info.env_files[0].path.display()
            );
        }
    }
    let written = [
        ("SCX_SCHEDULER", sched.to_owned()),
        ("SCX_FLAGS", flags.join(" ")),
    ];
    if let Some(entry) = info
        .unset_environment
        .iter()
        .find(|entry| match entry.split_once('=') {
            Some((name, value)) => written.iter().any(|(k, v)| *k == name && v == value),
            None => MANAGED_KEYS.contains(&entry.as_str()),
        })
    {
        bail!("UnsetEnvironment={entry} on the unit would drop the written value");
    }
    Ok(())
}

/// The unit's main process from `/proc`. `cmdline` is world-readable
/// (unlike `exe`, which needs ptrace access to a root process), and since
/// `ExecStart` execs the scheduler directly, `argv[0]` is the scheduler
/// as the shell resolved it: a bare name or a path.
fn read_process(pid: u32) -> Option<Process> {
    let raw = fs::read(format!("/proc/{pid}/cmdline")).ok()?;
    let mut argv = raw
        .split(|b| *b == 0)
        .filter(|part| !part.is_empty())
        .map(|part| String::from_utf8_lossy(part).into_owned());
    let argv0 = argv.next()?;
    let sched = Path::new(&argv0)
        .file_name()
        .map_or(argv0.clone(), |name| name.to_string_lossy().into_owned());
    Some(Process {
        sched,
        args: argv.collect(),
    })
}

/// Parses an `EnvironmentFile=` the way systemd does for what matters
/// here: `#` and `;` start comments, `KEY=VALUE` per line, values may be
/// single- or double-quoted, later assignments win. Line continuations
/// and escapes inside quotes are not interpreted.
fn parse_env_file(content: &str) -> Vec<(String, String)> {
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

fn split_assignment(word: String) -> Option<(String, String)> {
    let (key, value) = word.split_once('=')?;
    Some((key.to_owned(), value.to_owned()))
}

/// Splits a line the way a POSIX shell would read it into words, with the
/// two quotings systemd prints: `shell_maybe_quote` in its default mode
/// (`"…"`, backslash before `"`, `\`, `` ` ``, `$`) for `systemctl show`
/// values, and in POSIX mode (ANSI-C `$'…'`, backslash before `\` and
/// `'`) for `show-environment`. Control characters come as C escapes
/// (`\n`, `\t`, `\NNN` octal) in both, and plain `'…'` is accepted for
/// hand-written input. Unterminated quoting ends the word at end of line
/// rather than dropping it.
fn split_shell_words(line: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut chars = line.chars().peekable();
    while let Some(&c) = chars.peek() {
        if c.is_whitespace() {
            chars.next();
            continue;
        }
        let mut word = String::new();
        while let Some(&c) = chars.peek() {
            match c {
                c if c.is_whitespace() => break,
                '\'' => {
                    chars.next();
                    word.extend(chars.by_ref().take_while(|c| *c != '\''));
                }
                '"' => {
                    chars.next();
                    while let Some(c) = chars.next() {
                        match c {
                            '"' => break,
                            '\\' => push_c_escape(&mut word, &mut chars),
                            c => word.push(c),
                        }
                    }
                }
                '$' => {
                    chars.next();
                    if chars.peek() == Some(&'\'') {
                        chars.next();
                        while let Some(c) = chars.next() {
                            match c {
                                '\'' => break,
                                '\\' => push_c_escape(&mut word, &mut chars),
                                c => word.push(c),
                            }
                        }
                    } else {
                        word.push('$');
                    }
                }
                '\\' => {
                    chars.next();
                    if let Some(c) = chars.next() {
                        word.push(c);
                    }
                }
                c => {
                    chars.next();
                    word.push(c);
                }
            }
        }
        words.push(word);
    }
    words
}

/// Decodes the escape after a backslash inside a quoted word: the C
/// escapes systemd's `cescape_char` emits, octal `\NNN`, and the
/// character itself for everything else (`\\`, `\"`, `\'`, `` \` ``, `\$`).
fn push_c_escape(out: &mut String, chars: &mut std::iter::Peekable<std::str::Chars>) {
    match chars.next() {
        Some('a') => out.push('\u{07}'),
        Some('b') => out.push('\u{08}'),
        Some('f') => out.push('\u{0c}'),
        Some('n') => out.push('\n'),
        Some('r') => out.push('\r'),
        Some('t') => out.push('\t'),
        Some('v') => out.push('\u{0b}'),
        Some(d @ '0'..='7') => {
            let mut code = d.to_digit(8).unwrap_or(0);
            for _ in 0..2 {
                match chars.peek().and_then(|c| c.to_digit(8)) {
                    Some(digit) => {
                        code = code * 8 + digit;
                        chars.next();
                    }
                    None => break,
                }
            }
            out.push(char::from_u32(code).unwrap_or('\u{fffd}'));
        }
        Some(other) => out.push(other),
        None => out.push('\\'),
    }
}

/// The unit expands the flags unquoted (`exec $SCHED $FLAGS`), so bash
/// splits them on whitespace without interpreting quotes. Mirror that.
fn split_flags(value: &str) -> Vec<String> {
    value.split_whitespace().map(str::to_owned).collect()
}

/// A value is written into the environment file bare (scheduler) or
/// inside double quotes (flags), then word-split and pathname-expanded
/// by bash (the unit expands `$SCX_FLAGS` unquoted). Characters that any
/// of those steps would interpret cannot round-trip into `argv`, so they
/// are refused up front instead of producing a file that runs something
/// else: quotes and whitespace for the two parsers, `*`, `?` and `[` for
/// globbing (a lone `*` expands to the directory listing).
pub fn validate_value(what: &str, value: &str) -> Result<()> {
    if value.is_empty() {
        bail!("empty {what}");
    }
    if let Some(bad) = value.chars().find(|c| {
        c.is_whitespace()
            || c.is_control()
            || matches!(c, '"' | '\'' | '\\' | '*' | '?' | '[' | ']')
    }) {
        bail!("{what} {value:?} contains {bad:?}, which cannot be written to {UNIT}'s config");
    }
    Ok(())
}

fn unquote(value: &str) -> &str {
    let value = value.trim();
    value
        .strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .or_else(|| value.strip_prefix('\'').and_then(|s| s.strip_suffix('\'')))
        .unwrap_or(value)
}

/// Pure core of [`ServiceBackend::write_config`]: rewrites the two keys in
/// place, preserving every other line, appending keys that were absent.
/// `SCX_FLAGS` is always written, so a mode without flags clears a stale
/// set instead of inheriting it. Always ends with a trailing newline.
fn render_config(content: &str, sched: &str, flags: &[String]) -> String {
    let sched_line = format!("SCX_SCHEDULER={sched}");
    let flags_line = format!("SCX_FLAGS=\"{}\"", flags.join(" "));
    let (mut saw_sched, mut saw_flags) = (false, false);
    let mut lines: Vec<String> = content
        .lines()
        .map(|line| {
            let key = line.trim_start();
            if key.starts_with("SCX_SCHEDULER=") {
                saw_sched = true;
                sched_line.clone()
            } else if key.starts_with("SCX_FLAGS=") {
                saw_flags = true;
                flags_line.clone()
            } else {
                line.to_owned()
            }
        })
        .collect();
    if !saw_sched {
        lines.push(sched_line);
    }
    if !saw_flags {
        lines.push(flags_line);
    }
    let mut text = lines.join("\n");
    text.push('\n');
    text
}

/// The service has no advertised scheduler list, so the closest honest
/// source of truth is what is actually installed: every `scx_*` executable
/// in PATH, minus the known non-schedulers. Sorted and deduplicated.
fn scan_path_for_schedulers() -> Vec<String> {
    let dirs: Vec<PathBuf> = std::env::var_os("PATH")
        .map(|path| std::env::split_paths(&path).collect())
        .unwrap_or_default();
    scan_dirs(dirs)
}

fn scan_dirs(dirs: impl IntoIterator<Item = PathBuf>) -> Vec<String> {
    let mut found = BTreeSet::new();
    for dir in dirs {
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            // These names end up verbatim in the environment file, so
            // beyond the prefix filter, restrict them to a conservative
            // character set — a stray `scx_$(...)` in PATH must never
            // travel into `SCX_SCHEDULER=`.
            let clean = name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-');
            if clean
                && name.starts_with("scx_")
                && !NOT_SCHEDULERS.contains(&name.as_str())
                && is_executable_file(&entry.path())
            {
                found.insert(name);
            }
        }
    }
    found.into_iter().collect()
}

/// A regular file (through symlinks) with any execute bit set — what the
/// shell would actually run for a bare name.
fn is_executable_file(path: &Path) -> bool {
    fs::metadata(path).is_ok_and(|meta| meta.is_file() && meta.permissions().mode() & 0o111 != 0)
}

/// Pure core of [`SchedulerBackend::status`] for this backend, so the
/// resolution can be tested against assembled inputs.
fn build_status(info: &UnitInfo, env: &UnitEnvironment, process: Option<Process>) -> Status {
    let configured = env.non_empty("SCX_SCHEDULER").map(str::to_owned);
    let override_sched = env.non_empty("SCX_SCHEDULER_OVERRIDE").map(str::to_owned);
    let override_flags = env.non_empty("SCX_FLAGS_OVERRIDE").map(split_flags);
    Status {
        active: info.active,
        process: process.filter(|_| info.active),
        next_sched: override_sched.clone().or_else(|| configured.clone()),
        next_flags: override_flags
            .clone()
            .unwrap_or_else(|| env.get("SCX_FLAGS").map(split_flags).unwrap_or_default()),
        configured,
        override_sched,
        override_flags,
        config_error: env.error.clone(),
    }
}

impl SchedulerBackend for ServiceBackend {
    fn label(&self) -> String {
        match &self.config_path {
            Some(path) => format!("{UNIT} · {}", path.display()),
            None => format!("{UNIT} · no EnvironmentFile= (read-only)"),
        }
    }

    fn status(&self) -> Result<Status> {
        let info = unit_info()?;
        // The unit's state is known even when the manager environment is
        // not; report the gap in the panel instead of failing the whole
        // read, so the process and kernel lines stay informative.
        let env = match manager_environment() {
            Ok(manager) => unit_environment(&info, manager),
            Err(err) => {
                let mut env = unit_environment(&info, Vec::new());
                env.error.get_or_insert_with(|| format!("{err:#}"));
                env
            }
        };
        let process = info.main_pid.and_then(read_process);
        Ok(build_status(&info, &env, process))
    }

    fn supported_schedulers(&self) -> Result<Vec<String>> {
        let scheds = scan_path_for_schedulers();
        if scheds.is_empty() {
            bail!("no scx_* scheduler binaries found in PATH");
        }
        Ok(scheds)
    }

    fn start(&self, sched: &str, flags: &[String]) -> Result<()> {
        self.write_config(sched, flags)?;
        Self::systemctl("start")
    }

    fn switch(&self, sched: &str, flags: &[String]) -> Result<()> {
        self.write_config(sched, flags)?;
        Self::systemctl("restart")
    }

    fn stop(&self) -> Result<()> {
        Self::systemctl("stop")
    }

    fn restart(&self) -> Result<()> {
        Self::systemctl("restart")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strs(flags: &[&str]) -> Vec<String> {
        flags.iter().map(|s| (*s).to_owned()).collect()
    }

    fn pairs(list: &[(&str, &str)]) -> Vec<(String, String)> {
        list.iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect()
    }

    fn scratch_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("scxtui-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn active_info(env_files: Vec<EnvFile>) -> UnitInfo {
        UnitInfo {
            active: true,
            main_pid: Some(1),
            environment: Vec::new(),
            env_files,
            unset_environment: Vec::new(),
        }
    }

    fn required(path: &Path) -> EnvFile {
        EnvFile {
            path: path.to_path_buf(),
            optional: false,
        }
    }

    #[test]
    fn unquote_handles_quote_styles() {
        assert_eq!(unquote("\"scx_lavd\""), "scx_lavd");
        assert_eq!(unquote("'scx_lavd'"), "scx_lavd");
        assert_eq!(unquote("scx_lavd"), "scx_lavd");
        assert_eq!(unquote("  scx_lavd  "), "scx_lavd");
        // A lone opening quote is not a quoted value.
        assert_eq!(unquote("\"scx_lavd"), "\"scx_lavd");
    }

    #[test]
    fn env_file_parses_like_systemd() {
        let content = "# List of scx_schedulers: scx_lavd scx_rusty\n\
                       SCX_SCHEDULER=scx_cosmos\n\
                       ; disabled\n\
                       SCX_FLAGS='-s 700 -S'\n\
                       not a key=1\n\
                       SCX_SCHEDULER=scx_lavd\n";
        assert_eq!(
            parse_env_file(content),
            pairs(&[
                ("SCX_SCHEDULER", "scx_cosmos"),
                ("SCX_FLAGS", "-s 700 -S"),
                ("SCX_SCHEDULER", "scx_lavd"),
            ])
        );
    }

    #[test]
    fn shell_words_follow_both_systemd_quotings() {
        // `systemctl show -p Environment`: default shell_maybe_quote mode.
        assert_eq!(
            split_shell_words(r#"A=1 "SCX_FLAGS=-s 700 \"x\"" "B=\$y \\ z""#),
            strs(&["A=1", "SCX_FLAGS=-s 700 \"x\"", "B=$y \\ z"])
        );
        // `systemctl show-environment`: POSIX mode, ANSI-C quoting.
        assert_eq!(
            split_shell_words(r"SCX_FLAGS_OVERRIDE=$'-s 10000 --name it\'s'"),
            strs(&["SCX_FLAGS_OVERRIDE=-s 10000 --name it's"])
        );
        assert_eq!(
            split_shell_words(r"X=$'a\\b\tc\033[0m\101'"),
            strs(&["X=a\\b\tc\u{1b}[0mA"])
        );
        // Hand-written quoting, a bare `$`, and an unterminated quote.
        assert_eq!(
            split_shell_words("X='-s 10000' Y=$HOME Z=\"open"),
            strs(&["X=-s 10000", "Y=$HOME", "Z=open"])
        );
        assert!(split_shell_words("   ").is_empty());
    }

    #[test]
    fn unit_info_reads_state_environment_and_files() {
        let output = "ActiveState=active\n\
                      MainPID=4242\n\
                      Environment=LANG=C \"SCX_FLAGS_OVERRIDE=-s 1 -S\"\n\
                      EnvironmentFiles=/etc/default/scx (ignore_errors=no)\n\
                      EnvironmentFiles=/etc/scx.d/local (ignore_errors=yes)\n\
                      UnsetEnvironment=TMPDIR \"SCX_FLAGS=-s 1 -S\"\n";
        let info = parse_unit_info(output);
        assert!(info.active);
        assert_eq!(info.main_pid, Some(4242));
        assert_eq!(
            info.environment,
            pairs(&[("LANG", "C"), ("SCX_FLAGS_OVERRIDE", "-s 1 -S")])
        );
        assert_eq!(
            info.env_files,
            vec![
                required(Path::new("/etc/default/scx")),
                EnvFile {
                    path: PathBuf::from("/etc/scx.d/local"),
                    optional: true
                },
            ]
        );
        assert_eq!(
            editable_config_path(&info),
            Some(PathBuf::from("/etc/default/scx"))
        );

        let idle = parse_unit_info("MainPID=0\nActiveState=inactive\n");
        assert!(!idle.active);
        assert_eq!(idle.main_pid, None);
        assert!(parse_unit_info("ActiveState=activating\nMainPID=7\n").active);
        assert!(!parse_unit_info("ActiveState=failed\nMainPID=0\n").active);
    }

    #[test]
    fn manager_environment_parses_quoted_values() {
        assert_eq!(
            parse_manager_environment(
                "LANG=C.UTF-8\nSCX_SCHEDULER_OVERRIDE=scx_rustland\nSCX_FLAGS_OVERRIDE=$'-s 10000'\n"
            ),
            pairs(&[
                ("LANG", "C.UTF-8"),
                ("SCX_SCHEDULER_OVERRIDE", "scx_rustland"),
                ("SCX_FLAGS_OVERRIDE", "-s 10000"),
            ])
        );
    }

    #[test]
    fn layers_override_in_systemd_order() {
        // Manager env < Environment= < EnvironmentFile= (later file wins).
        let dir = scratch_dir("layers");
        let first = dir.join("first");
        let second = dir.join("second");
        fs::write(&first, "SCX_SCHEDULER=scx_lavd\nSCX_FLAGS=\"-v\"\n").unwrap();
        fs::write(&second, "SCX_FLAGS=\"-s 5\"\n").unwrap();
        let info = UnitInfo {
            environment: pairs(&[("SCX_SCHEDULER", "scx_from_unit"), ("UNIT_ONLY", "1")]),
            ..active_info(vec![required(&first), required(&second)])
        };
        let manager = pairs(&[
            ("SCX_SCHEDULER", "scx_from_manager"),
            ("SCX_FLAGS_OVERRIDE", "-m 1"),
            ("MANAGER_ONLY", "1"),
        ]);

        let env = unit_environment(&info, manager);
        assert_eq!(env.get("SCX_SCHEDULER"), Some("scx_lavd"));
        assert_eq!(env.get("SCX_FLAGS"), Some("-s 5"));
        assert_eq!(env.get("SCX_FLAGS_OVERRIDE"), Some("-m 1"));
        assert_eq!(env.get("UNIT_ONLY"), Some("1"));
        assert_eq!(env.get("MANAGER_ONLY"), Some("1"));
        assert_eq!(env.error, None);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn override_in_the_file_beats_the_configured_scheduler() {
        // The reviewer's case: both keys in the same file. The unit runs
        // the override, so "next start" must say so.
        let dir = scratch_dir("file-override");
        let file = dir.join("scx");
        fs::write(
            &file,
            "SCX_SCHEDULER=scx_lavd\nSCX_SCHEDULER_OVERRIDE=scx_rusty\nSCX_FLAGS=\"-v\"\n",
        )
        .unwrap();
        let info = active_info(vec![required(&file)]);
        let env = unit_environment(&info, Vec::new());
        let status = build_status(&info, &env, None);
        assert_eq!(status.next_sched.as_deref(), Some("scx_rusty"));
        assert_eq!(status.configured.as_deref(), Some("scx_lavd"));
        assert_eq!(status.override_sched.as_deref(), Some("scx_rusty"));
        assert_eq!(status.override_flags, None);
        assert_eq!(status.next_flags, strs(&["-v"]));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn empty_override_is_unset_like_the_shell_treats_it() {
        let info = UnitInfo {
            environment: pairs(&[
                ("SCX_SCHEDULER", "scx_lavd"),
                ("SCX_SCHEDULER_OVERRIDE", ""),
                ("SCX_FLAGS_OVERRIDE", ""),
            ]),
            ..active_info(Vec::new())
        };
        let env = unit_environment(&info, Vec::new());
        let status = build_status(&info, &env, None);
        assert_eq!(status.next_sched.as_deref(), Some("scx_lavd"));
        assert_eq!(status.override_sched, None);
        assert_eq!(status.override_flags, None);
    }

    #[test]
    fn unreadable_or_missing_required_file_is_reported_not_hidden() {
        let dir = scratch_dir("env-errors");
        let bad = dir.join("bad");
        fs::write(&bad, b"SCX_SCHEDULER=\xff\xfe\n").unwrap();
        let missing = dir.join("missing");

        let env = unit_environment(&active_info(vec![required(&bad)]), Vec::new());
        assert!(env.error.as_deref().unwrap().contains("unreadable"));

        // A required file after the first one: the unit would not start.
        let good = dir.join("good");
        fs::write(&good, "SCX_SCHEDULER=scx_lavd\n").unwrap();
        let env = unit_environment(
            &active_info(vec![required(&good), required(&missing)]),
            Vec::new(),
        );
        assert!(env.error.as_deref().unwrap().contains("cannot start"));

        let optional = EnvFile {
            path: missing,
            optional: true,
        };
        let env = unit_environment(&active_info(vec![required(&good), optional]), Vec::new());
        assert_eq!(env.error, None);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn first_file_may_be_missing_but_later_required_ones_may_not() {
        // The first file is the one the TUI creates on its first write,
        // so its absence is "nothing configured", not an error.
        let dir = scratch_dir("first-missing");
        let env = unit_environment(&active_info(vec![required(&dir.join("scx"))]), Vec::new());
        assert_eq!(env.error, None);
        assert_eq!(env.get("SCX_SCHEDULER"), None);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn unset_environment_is_applied_last() {
        let info = UnitInfo {
            environment: pairs(&[
                ("SCX_SCHEDULER", "scx_lavd"),
                ("SCX_FLAGS_OVERRIDE", "-s 1"),
                ("KEEP", "x"),
            ]),
            unset_environment: strs(&["SCX_SCHEDULER", "SCX_FLAGS_OVERRIDE=-s 2", "KEEP=x"]),
            ..active_info(Vec::new())
        };
        let env = unit_environment(&info, Vec::new());
        assert_eq!(env.get("SCX_SCHEDULER"), None, "bare name drops it");
        assert_eq!(
            env.get("SCX_FLAGS_OVERRIDE"),
            Some("-s 1"),
            "NAME=VALUE drops only an exact match"
        );
        assert_eq!(env.get("KEEP"), None);
    }

    #[test]
    fn write_is_refused_when_a_later_file_or_unset_would_override_it() {
        // The reviewer's case: the unit reads a second file after the one
        // scxtui edits, and that file sets SCX_SCHEDULER. A write to the
        // first file followed by a restart would bring back the second
        // file's scheduler while systemctl reports success.
        let dir = scratch_dir("effective");
        let first = dir.join("scx");
        let later = dir.join("local");
        fs::write(&first, "SCX_SCHEDULER=scx_cosmos\n").unwrap();
        fs::write(&later, "SCX_SCHEDULER=scx_lavd\n").unwrap();

        let info = active_info(vec![required(&first), required(&later)]);
        let err = check_write_effective(&info, "scx_rusty", &[]).expect_err("later file wins");
        assert!(format!("{err:#}").contains("SCX_SCHEDULER is also set in"));

        // A later file that sets only unrelated keys is fine.
        fs::write(&later, "OTHER=1\n").unwrap();
        check_write_effective(&info, "scx_rusty", &[]).unwrap();

        // A later optional file that is missing is fine; a required one
        // that cannot be checked is not.
        let missing = dir.join("missing");
        check_write_effective(
            &active_info(vec![
                required(&first),
                EnvFile {
                    path: missing.clone(),
                    optional: true,
                },
            ]),
            "scx_rusty",
            &[],
        )
        .unwrap();
        assert!(
            check_write_effective(
                &active_info(vec![required(&first), required(&missing)]),
                "scx_rusty",
                &[]
            )
            .is_err()
        );

        // UnsetEnvironment=NAME drops the write whatever the value;
        // NAME=VALUE only when VALUE is exactly what would be written.
        let unset = |entries: &[&str]| UnitInfo {
            unset_environment: strs(entries),
            ..active_info(vec![required(&first)])
        };
        let flags = strs(&["--verbose"]);
        assert!(check_write_effective(&unset(&["SCX_FLAGS"]), "scx_rusty", &flags).is_err());
        check_write_effective(&unset(&["SCX_FLAGS=--old-option"]), "scx_rusty", &flags).unwrap();
        assert!(
            check_write_effective(&unset(&["SCX_FLAGS=--verbose"]), "scx_rusty", &flags).is_err()
        );
        assert!(
            check_write_effective(&unset(&["SCX_SCHEDULER=scx_rusty"]), "scx_rusty", &flags)
                .is_err()
        );
        check_write_effective(&unset(&["SCX_SCHEDULER=scx_lavd"]), "scx_rusty", &flags).unwrap();
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn write_target_follows_the_live_unit_not_the_startup_snapshot() {
        // The unit was redefined under the TUI (drop-in + daemon-reload):
        // the header still shows the old path, so the write is refused
        // instead of going to a file the unit no longer reads.
        let old = Path::new("/etc/default/scx");
        let live = active_info(vec![required(Path::new("/etc/sysconfig/scx"))]);
        let err = write_target(&live, Some(old)).expect_err("stale path");
        assert!(format!("{err:#}").contains("restart scxtui"));

        // Unchanged unit: the live path is the one written.
        let same = active_info(vec![required(old)]);
        assert_eq!(write_target(&same, Some(old)).unwrap(), old);

        // No EnvironmentFile= at all: nothing to write to, no guessing.
        let none = active_info(Vec::new());
        assert!(
            format!("{:#}", write_target(&none, None).unwrap_err()).contains("no EnvironmentFile=")
        );
        assert!(write_target(&none, Some(old)).is_err());
    }

    #[test]
    fn render_config_replaces_both_keys_in_place() {
        let before = "# managed by hand\nSCX_SCHEDULER=scx_rusty\nSCX_FLAGS='-v'\nOTHER=1\n";
        assert_eq!(
            render_config(before, "scx_lavd", &strs(&["--performance", "-s", "5"])),
            "# managed by hand\nSCX_SCHEDULER=scx_lavd\nSCX_FLAGS=\"--performance -s 5\"\nOTHER=1\n"
        );
    }

    #[test]
    fn render_config_appends_missing_keys_and_clears_flags() {
        // The upstream default file has SCX_FLAGS only as a comment: the
        // comment stays, a real key is appended, and empty flags are
        // written out explicitly rather than inherited.
        let before = "SCX_SCHEDULER=scx_cosmos\n#SCX_FLAGS='-s 700 -S'\n";
        assert_eq!(
            render_config(before, "scx_lavd", &[]),
            "SCX_SCHEDULER=scx_lavd\n#SCX_FLAGS='-s 700 -S'\nSCX_FLAGS=\"\"\n"
        );
        assert_eq!(
            render_config("", "scx_lavd", &[]),
            "SCX_SCHEDULER=scx_lavd\nSCX_FLAGS=\"\"\n"
        );
    }

    #[test]
    fn values_that_cannot_round_trip_are_refused() {
        assert!(validate_value("flag", "--slice-us=500").is_ok());
        assert!(validate_value("flag", "-s 500").is_err());
        assert!(validate_value("flag", "a\"b").is_err());
        assert!(validate_value("flag", "a\\b").is_err());
        assert!(validate_value("flag", "").is_err());
        // Unquoted expansion in the unit's ExecStart globs: a lone `*`
        // becomes the working directory's listing.
        assert!(validate_value("flag", "*").is_err());
        assert!(validate_value("flag", "--path=/tmp/?").is_err());
        assert!(validate_value("flag", "[a-z]").is_err());
        assert!(
            validate_value("scheduler name", "scx_$(x)").is_ok(),
            "no shell expansion applies"
        );
    }

    #[test]
    fn write_config_refuses_an_unreadable_file() {
        // Invalid UTF-8 makes read_to_string fail while the file exists:
        // the write must abort and leave the bytes untouched.
        let dir = scratch_dir("unreadable");
        let path = dir.join("scx");
        let garbage = b"SCX_FLAGS=\"-v\"\nSCX_SCHEDULER=\xff\xfe\n".to_vec();
        fs::write(&path, &garbage).unwrap();
        let err = write_env_file(&path, "scx_lavd", &[])
            .expect_err("unreadable config must not be rewritten");
        assert!(format!("{err:#}").contains("could not be read"));
        assert_eq!(fs::read(&path).unwrap(), garbage);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn write_config_creates_edits_and_keeps_permissions() {
        let dir = scratch_dir("write");
        let path = dir.join("scx");
        // Missing file: created.
        write_env_file(&path, "scx_lavd", &strs(&["-v"])).unwrap();
        assert_eq!(
            fs::read_to_string(&path).unwrap(),
            "SCX_SCHEDULER=scx_lavd\nSCX_FLAGS=\"-v\"\n"
        );

        // Existing file with tightened permissions: edited in place, mode kept.
        fs::write(&path, "# note\nSCX_SCHEDULER=scx_lavd\nSCX_FLAGS=\"-v\"\n").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        write_env_file(&path, "scx_rusty", &[]).unwrap();
        assert_eq!(
            fs::read_to_string(&path).unwrap(),
            "# note\nSCX_SCHEDULER=scx_rusty\nSCX_FLAGS=\"\"\n"
        );
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        // No scratch file left behind.
        assert_eq!(fs::read_dir(&dir).unwrap().count(), 1);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn write_config_edits_the_target_of_a_symlink() {
        let dir = scratch_dir("symlink");
        let real = dir.join("real");
        let link = dir.join("scx");
        fs::write(&real, "SCX_SCHEDULER=scx_lavd\n").unwrap();
        std::os::unix::fs::symlink(&real, &link).unwrap();
        write_env_file(&link, "scx_rusty", &[]).unwrap();
        assert!(
            fs::symlink_metadata(&link).unwrap().is_symlink(),
            "link kept"
        );
        assert_eq!(
            fs::read_to_string(&real).unwrap(),
            "SCX_SCHEDULER=scx_rusty\nSCX_FLAGS=\"\"\n"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn own_process_is_readable_through_proc() {
        // The test binary itself: argv[0] basename, no guessing from any file.
        let me = read_process(std::process::id()).expect("own cmdline is readable");
        let exe = std::env::current_exe().unwrap();
        assert_eq!(
            me.sched,
            exe.file_name().unwrap().to_string_lossy().as_ref()
        );
        assert_eq!(read_process(0), None);
    }

    #[test]
    fn scan_dirs_wants_executables_and_filters_non_schedulers() {
        let dir = scratch_dir("scan");
        for name in [
            "scx_zeta",
            "scx_alpha",
            "scx_loader",
            "scx_characterize",
            "not_a_sched",
        ] {
            fs::File::create(dir.join(name)).unwrap();
            fs::set_permissions(dir.join(name), fs::Permissions::from_mode(0o755)).unwrap();
        }
        // Present but not executable: the shell would not run it.
        fs::File::create(dir.join("scx_data")).unwrap();
        fs::set_permissions(dir.join("scx_data"), fs::Permissions::from_mode(0o644)).unwrap();

        let found = scan_dirs([dir.clone()]);
        let _ = fs::remove_dir_all(&dir);
        assert_eq!(found, ["scx_alpha", "scx_zeta"]);
    }
}
