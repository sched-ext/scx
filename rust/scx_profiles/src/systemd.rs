// SPDX-License-Identifier: GPL-2.0

//! `scx.service` as systemd sees it: the unit's state and main process,
//! its environment assembled per systemd.exec(5), the file a write goes
//! to and whether the write would take effect, and the `systemctl` verbs
//! that drive the unit. Lifted from scxtui's service backend.
//!
//! Privileges: reading works as any user; writing the file and driving
//! the unit need root. Both fail with errors that say so, mapped to
//! [`crate::Error::Permission`] by the callers.

use std::collections::HashMap;
use std::fs;
use std::io::ErrorKind;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};

use crate::envfile::{self, FLAGS_OVERRIDE_KEY, MANAGED_KEYS, SCHEDULER_OVERRIDE_KEY, Written};
use crate::files::rewrite_file;

pub const UNIT: &str = "scx.service";

/// `scx_`-prefixed executables that are not schedulers.
const NOT_SCHEDULERS: [&str; 4] = [
    "scx_loader",
    "scx_characterize",
    "scx_forge_agent",
    "scx_rustland_core",
];

/// Where `systemd-path` lives. Called by absolute path with a cleared
/// environment, so that the directory list this crate trusts cannot
/// itself come from a directory in the caller's PATH.
const SYSTEMD_PATH: &str = "/usr/bin/systemd-path";

/// One `EnvironmentFile=` entry of the unit, in declaration order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvFile {
    pub path: PathBuf,
    /// The `-` prefix: a missing file is fine rather than a start failure.
    pub optional: bool,
}

/// What `systemctl show` reports about the unit, from one round-trip.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct UnitInfo {
    /// `LoadState=loaded`: the unit exists.
    pub loaded: bool,
    pub active: bool,
    pub enabled: bool,
    pub main_pid: Option<u32>,
    /// `Result=` of the last run: `success`, `exit-code`, `signal`,
    /// `start-limit-hit`, ...
    pub result: String,
    pub exec_main_status: Option<i32>,
    pub invocation_id: Option<String>,
    pub environment: Vec<(String, String)>,
    pub env_files: Vec<EnvFile>,
    pub unset_environment: Vec<String>,
}

/// The environment the unit's `ExecStart` sees.
#[derive(Debug, Default)]
pub struct UnitEnvironment {
    pub vars: HashMap<String, String>,
    /// First reason the assembled environment may not be the one the
    /// unit sees. While set, writes are refused.
    pub error: Option<String>,
}

impl UnitEnvironment {
    pub fn get(&self, key: &str) -> Option<&str> {
        self.vars.get(key).map(String::as_str)
    }

    /// `${key:-}`: unset and empty are the same thing to the shell.
    pub fn non_empty(&self, key: &str) -> Option<&str> {
        self.get(key).filter(|v| !v.is_empty())
    }
}

/// The unit's main process as observed through `/proc`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Process {
    /// `argv[0]` basename, e.g. `scx_lavd`.
    pub sched: String,
    /// `argv[1..]`.
    pub args: Vec<String>,
}

pub fn unit_info() -> Result<UnitInfo> {
    let out = system_command("systemctl")?
        .args([
            "show",
            UNIT,
            "--property=LoadState,ActiveState,UnitFileState,MainPID,Result,ExecMainStatus,\
InvocationID,Environment,EnvironmentFiles,UnsetEnvironment",
        ])
        .output()
        .context("failed to run systemctl show; is this a systemd system?")?;
    if !out.status.success() {
        bail!(
            "systemctl show {UNIT} failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    let info = parse_unit_info(&String::from_utf8_lossy(&out.stdout));
    // `systemctl show` succeeds for a unit that does not exist and
    // prints a stub with LoadState=not-found.
    if !info.loaded {
        bail!("{UNIT} is not installed");
    }
    Ok(info)
}

/// Pure core of [`unit_info`]: `KEY=VALUE` lines.
pub fn parse_unit_info(output: &str) -> UnitInfo {
    let mut info = UnitInfo::default();
    for line in output.lines() {
        if let Some(value) = line.strip_prefix("LoadState=") {
            info.loaded = value.trim() == "loaded";
        } else if let Some(value) = line.strip_prefix("ActiveState=") {
            info.active = matches!(value.trim(), "active" | "activating" | "reloading");
        } else if let Some(value) = line.strip_prefix("UnitFileState=") {
            info.enabled = matches!(value.trim(), "enabled" | "enabled-runtime");
        } else if let Some(value) = line.strip_prefix("MainPID=") {
            info.main_pid = value.trim().parse().ok().filter(|pid| *pid != 0);
        } else if let Some(value) = line.strip_prefix("Result=") {
            info.result = value.trim().to_owned();
        } else if let Some(value) = line.strip_prefix("ExecMainStatus=") {
            info.exec_main_status = value.trim().parse().ok();
        } else if let Some(value) = line.strip_prefix("InvocationID=") {
            info.invocation_id = Some(value.trim().to_owned()).filter(|s| !s.is_empty());
        } else if let Some(value) = line.strip_prefix("Environment=") {
            info.environment.extend(
                split_shell_words(value)
                    .into_iter()
                    .filter_map(split_assignment),
            );
        } else if let Some(value) = line.strip_prefix("UnsetEnvironment=") {
            info.unset_environment.extend(split_shell_words(value));
        } else if let Some(value) = line.strip_prefix("EnvironmentFiles=") {
            info.env_files.extend(parse_env_files(value));
        }
    }
    info
}

/// One `EnvironmentFiles=` value: `PATH (ignore_errors=yes|no)` entries.
/// systemctl prints one entry per line, but the entries are parsed as
/// a sequence so that several on one line (as some versions and
/// scripts produce) come out right instead of as one long path.
fn parse_env_files(value: &str) -> Vec<EnvFile> {
    let mut files = Vec::new();
    let mut rest = value.trim();
    while !rest.is_empty() {
        let Some(open) = rest.find(" (ignore_errors=") else {
            if !rest.is_empty() {
                files.push(EnvFile {
                    path: PathBuf::from(rest),
                    optional: false,
                });
            }
            break;
        };
        let path = &rest[..open];
        let after = &rest[open + " (ignore_errors=".len()..];
        let Some(close) = after.find(')') else {
            break;
        };
        let optional = &after[..close] == "yes";
        if !path.is_empty() {
            files.push(EnvFile {
                path: PathBuf::from(path),
                optional,
            });
        }
        rest = after[close + 1..].trim_start();
    }
    files
}

/// The file a write goes to: the unit's first `EnvironmentFile=`.
pub fn config_path(info: &UnitInfo) -> Result<PathBuf> {
    info.env_files
        .first()
        .map(|f| f.path.clone())
        .with_context(|| format!("{UNIT} declares no EnvironmentFile=; nothing to write to"))
}

/// The manager environment, the lowest layer. A failed query is an
/// error, not an empty layer: `systemctl set-environment` overrides
/// live here.
pub fn manager_environment() -> Result<Vec<(String, String)>> {
    let out = system_command("systemctl")?
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

pub fn parse_manager_environment(output: &str) -> Vec<(String, String)> {
    output
        .lines()
        .flat_map(split_shell_words)
        .filter_map(split_assignment)
        .collect()
}

/// Assembles the unit's environment: manager environment, then
/// `Environment=`, then each `EnvironmentFile=` in order (later wins),
/// then `UnsetEnvironment=`. A missing optional file, and a missing
/// first file (the one a write creates), are not problems.
pub fn unit_environment(info: &UnitInfo, manager: Vec<(String, String)>) -> UnitEnvironment {
    let mut env = UnitEnvironment::default();
    env.vars.extend(manager);
    env.vars.extend(info.environment.iter().cloned());
    for (idx, file) in info.env_files.iter().enumerate() {
        match fs::read_to_string(&file.path) {
            Ok(content) => env.vars.extend(envfile::parse(&content)),
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

/// The environment as the unit sees it now, with a manager-environment
/// failure folded into `error` rather than failing the read.
pub fn current_environment(info: &UnitInfo) -> UnitEnvironment {
    match manager_environment() {
        Ok(manager) => unit_environment(info, manager),
        Err(err) => {
            let mut env = unit_environment(info, Vec::new());
            env.error.get_or_insert_with(|| format!("{err:#}"));
            env
        }
    }
}

/// Whether writing the managed keys to the first environment file
/// decides the unit's next start. Any later file setting a managed key
/// overrides the write; so does `UnsetEnvironment=NAME`, and
/// `UnsetEnvironment=NAME=VALUE` exactly when VALUE is what would be
/// written. So does an `SCX_SCHEDULER_OVERRIDE` or `SCX_FLAGS_OVERRIDE`
/// that applying cannot clear: `clear_overrides` only reaches the
/// manager environment, while the unit's `ExecStart` also honours one
/// set in `Environment=` (the unit file or a drop-in) or in any
/// environment file. Those are the administrator's configuration and
/// are never edited here; the write is refused with their source.
pub fn check_write_effective(info: &UnitInfo, written: &Written) -> Result<()> {
    let first = config_path(info)?;
    if let Some((key, source)) = persistent_override(info) {
        bail!(
            "{key} is set in {source}, which {UNIT} prefers over the written selection and \
`systemctl unset-environment` cannot clear; remove it there first"
        );
    }
    for file in info.env_files.iter().skip(1) {
        let content = match fs::read_to_string(&file.path) {
            Ok(content) => content,
            Err(err) if err.kind() == ErrorKind::NotFound && file.optional => continue,
            Err(err) => bail!(
                "{} is read by the unit after {} but cannot be checked: {err}",
                file.path.display(),
                first.display()
            ),
        };
        if let Some((key, _)) = envfile::parse(&content)
            .into_iter()
            .find(|(key, _)| MANAGED_KEYS.contains(&key.as_str()))
        {
            bail!(
                "{key} is also set in {}, which the unit reads after {}; a write would be \
overridden, edit that file instead",
                file.path.display(),
                first.display()
            );
        }
    }
    // Only a key the write sets can be dropped by an unset; a key the
    // write removes or leaves alone is no concern of this check.
    let values = written.values();
    if let Some(entry) = info
        .unset_environment
        .iter()
        .find(|entry| match entry.split_once('=') {
            Some((name, value)) => values.iter().any(|(k, v)| *k == name && v == value),
            None => values.iter().any(|(k, _)| *k == entry.as_str()),
        })
    {
        bail!("UnsetEnvironment={entry} on {UNIT} would drop the written value");
    }
    Ok(())
}

/// An override that survives `clear_overrides`: in the unit's
/// `Environment=` or in one of its environment files, non-empty (an
/// empty one is unset to the shell). Returns the key and where it is.
fn persistent_override(info: &UnitInfo) -> Option<(&'static str, String)> {
    // The environment as the unit will see it once the manager layer is
    // cleared: later assignments win, an empty one unsets, and
    // UnsetEnvironment= applies last. Only what survives that counts.
    let after_clear = unit_environment(info, Vec::new());
    let key = [SCHEDULER_OVERRIDE_KEY, FLAGS_OVERRIDE_KEY]
        .into_iter()
        .find(|k| after_clear.non_empty(k).is_some())?;
    // The source is the last layer that assigned the surviving value:
    // Environment= first, then each environment file in order.
    let mut source = format!("Environment= of {UNIT} (unit file or drop-in)");
    for file in &info.env_files {
        let Ok(content) = fs::read_to_string(&file.path) else {
            continue;
        };
        if envfile::parse(&content).iter().any(|(k, _)| k == key) {
            source = file.path.display().to_string();
        }
    }
    Some((key, source))
}

/// Rewrites the managed keys in the unit's first environment file, after
/// the checks above. A missing file is created 0644 whatever the
/// umask: the three managed keys hold nothing secret, `get` and `list`
/// must read them as any user, and nobody but root may write what the
/// unit runs. An existing file keeps its mode, so a file an administrator
/// made private stays private, and unprivileged reads then report a
/// `config_error` instead of guessing.
pub fn write_config(info: &UnitInfo, written: &Written) -> Result<()> {
    let env = current_environment(info);
    if let Some(err) = env.error {
        bail!("the environment of {UNIT} could not be resolved ({err}); not writing");
    }
    let path = config_path(info)?;
    check_write_effective(info, written)?;
    rewrite_file(&path, |old| Ok(envfile::render(old, written)))
        .with_context(|| format!("cannot rewrite {}", path.display()))
}

/// Drops the runtime overrides from the manager environment, so the
/// written selection takes effect. An override that was never set is
/// no error.
pub fn clear_overrides() -> Result<()> {
    let out = system_command("systemctl")?
        .args([
            "unset-environment",
            SCHEDULER_OVERRIDE_KEY,
            FLAGS_OVERRIDE_KEY,
        ])
        .output()
        .context("failed to run systemctl unset-environment")?;
    if !out.status.success() {
        bail!(
            "systemctl unset-environment failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

/// Runs `systemctl VERB [ARGS] scx.service`.
pub fn systemctl(args: &[&str]) -> Result<()> {
    let out = system_command("systemctl")?
        .args(args)
        .arg(UNIT)
        .output()
        .context("failed to run systemctl")?;
    if !out.status.success() {
        bail!(
            "systemctl {} {UNIT} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

/// The shipped unit has StartLimitBurst=2 within 30 s, meant to stop a
/// crashing scheduler from being restarted in a loop. Switching
/// profiles twice in a row hits the same limit. Clear the counter
/// before an explicit start; a failed reset is not an error, the start
/// that follows reports the real problem.
pub fn reset_failed() {
    let _ = systemctl(&["reset-failed"]);
}

/// The unit's main process from `/proc`. `cmdline` is world-readable,
/// and since `ExecStart` execs the scheduler directly, `argv[0]` is the
/// scheduler as the shell resolved it: a bare name or a path.
pub fn read_process(pid: u32) -> Option<Process> {
    let raw = fs::read(format!("/proc/{pid}/cmdline")).ok()?;
    let mut argv = raw
        .split(|b| *b == 0)
        .filter(|part| !part.is_empty())
        .map(|part| String::from_utf8_lossy(part).into_owned());
    let argv0 = argv.next()?;
    Some(Process {
        sched: crate::profile::sched_name(&argv0),
        args: argv.collect(),
    })
}

fn split_assignment(word: String) -> Option<(String, String)> {
    let (key, value) = word.split_once('=')?;
    Some((key.to_owned(), value.to_owned()))
}

/// Splits a line the way a POSIX shell reads it into words, with the
/// two quotings systemd prints: default `shell_maybe_quote` for
/// `systemctl show` values and POSIX mode (ANSI-C `$'...'`) for
/// `show-environment`. Control characters come as C escapes in both.
pub fn split_shell_words(line: &str) -> Vec<String> {
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

/// A command for a system tool, resolved in systemd's default search
/// path rather than the caller's PATH. This crate's privileged callers
/// run as root, and a user-writable directory ahead of `/usr/bin` in
/// root's PATH would let anyone substitute a program.
pub fn system_command(name: &str) -> Result<Command> {
    let dirs = system_binary_dirs()?;
    let executable = resolve_in(name, &dirs)?;
    Ok(Command::new(executable))
}

/// The directories the unit's shell searches for a bare scheduler name:
/// systemd's compiled-in default search path.
pub fn system_binary_dirs() -> Result<Vec<PathBuf>> {
    let out = Command::new(SYSTEMD_PATH)
        .arg("search-binaries-default")
        .env_clear()
        .output()
        .with_context(|| format!("cannot run {SYSTEMD_PATH}"))?;
    if !out.status.success() {
        bail!(
            "{SYSTEMD_PATH} search-binaries-default failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    let text = std::str::from_utf8(&out.stdout).context("systemd-path printed non-UTF-8")?;
    parse_search_path(text)
}

/// Only absolute entries are acceptable: a relative one would resolve
/// against the working directory.
pub fn parse_search_path(text: &str) -> Result<Vec<PathBuf>> {
    let dirs: Vec<PathBuf> = std::env::split_paths(text.trim()).collect();
    if dirs.is_empty() || dirs.iter().any(|dir| !dir.is_absolute()) {
        bail!(
            "systemd-path returned an invalid search path: {:?}",
            text.trim()
        );
    }
    Ok(dirs)
}

/// Every `scx_*` executable in `dirs`, minus the known non-schedulers,
/// sorted and deduplicated. Names end up in the environment file, so
/// beyond the prefix they are restricted to a conservative character
/// set.
pub fn scan_dirs(dirs: impl IntoIterator<Item = PathBuf>) -> Vec<String> {
    scan_dirs_with_paths(dirs)
        .into_iter()
        .map(|(name, _)| name)
        .collect()
}

/// [`scan_dirs`] with the path each name resolves to: the first
/// directory in order that holds it, as the shell would pick. One scan
/// serves both the names and the paths, so the two never disagree.
pub fn scan_dirs_with_paths(dirs: impl IntoIterator<Item = PathBuf>) -> Vec<(String, PathBuf)> {
    let mut found: std::collections::BTreeMap<String, PathBuf> = Default::default();
    for dir in dirs {
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if crate::profile::validate_sched(&name).is_ok()
                && !NOT_SCHEDULERS.contains(&name.as_str())
                && is_executable_file(&entry.path())
            {
                found.entry(name).or_insert_with(|| entry.path());
            }
        }
    }
    found.into_iter().collect()
}

/// The installed schedulers.
pub fn installed_schedulers() -> Result<Vec<String>> {
    Ok(scan_dirs(system_binary_dirs()?))
}

/// The absolute path a scheduler is written with. A bare name is looked
/// up in `dirs`, first hit wins, as the shell would. An absolute path
/// must lie directly in one of `dirs` and be executable; anything else
/// is refused, so that a profile cannot point the unit at `/tmp`.
pub fn resolve_scheduler(sched: &str, dirs: &[PathBuf]) -> Result<PathBuf> {
    crate::profile::validate_sched(sched)?;
    let path = Path::new(sched);
    if path.is_absolute() {
        let dir = path.parent().unwrap_or(Path::new("/"));
        if !dirs.iter().any(|d| d == dir) {
            bail!(
                "{sched} is not in systemd's default search path ({})",
                dirs.iter()
                    .map(|d| d.display().to_string())
                    .collect::<Vec<_>>()
                    .join(":")
            );
        }
        if !is_executable_file(path) {
            bail!("{sched} is not an executable file");
        }
        return Ok(path.to_path_buf());
    }
    resolve_in(sched, dirs)
}

/// Resolves a bare scheduler name on the live system.
pub fn resolve(sched: &str) -> Result<PathBuf> {
    resolve_scheduler(sched, &system_binary_dirs()?)
}

fn resolve_in(name: &str, dirs: &[PathBuf]) -> Result<PathBuf> {
    dirs.iter()
        .map(|dir| dir.join(name))
        .find(|candidate| candidate.is_absolute() && is_executable_file(candidate))
        .with_context(|| format!("{name} is not an executable in systemd's default search path"))
}

fn is_executable_file(path: &Path) -> bool {
    fs::metadata(path).is_ok_and(|meta| meta.is_file() && meta.permissions().mode() & 0o111 != 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strs(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| (*s).to_owned()).collect()
    }

    fn pairs(list: &[(&str, &str)]) -> Vec<(String, String)> {
        list.iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect()
    }

    pub(crate) fn scratch_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("scx_profiles-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn required(path: &Path) -> EnvFile {
        EnvFile {
            path: path.to_path_buf(),
            optional: false,
        }
    }

    fn with_files(env_files: Vec<EnvFile>) -> UnitInfo {
        UnitInfo {
            env_files,
            ..UnitInfo::default()
        }
    }

    #[test]
    fn unit_info_parses_every_property() {
        let output = "LoadState=loaded\nActiveState=active\nUnitFileState=enabled\nMainPID=4242\nResult=success\n\
ExecMainStatus=0\nInvocationID=abc\n\
Environment=LANG=C \"SCX_FLAGS_OVERRIDE=-s 1 -S\"\n\
EnvironmentFiles=/etc/default/scx (ignore_errors=no)\n\
EnvironmentFiles=/etc/scx.d/local (ignore_errors=yes)\n\
UnsetEnvironment=TMPDIR \"SCX_FLAGS=-s 1 -S\"\n";
        let info = parse_unit_info(output);
        assert!(info.loaded && info.active && info.enabled);
        assert_eq!(info.main_pid, Some(4242));
        assert_eq!(info.result, "success");
        assert_eq!(info.exec_main_status, Some(0));
        assert_eq!(info.invocation_id.as_deref(), Some("abc"));
        assert_eq!(
            info.environment,
            pairs(&[("LANG", "C"), ("SCX_FLAGS_OVERRIDE", "-s 1 -S")])
        );
        assert_eq!(info.env_files.len(), 2);
        assert!(info.env_files[1].optional);
        // Several entries on one line parse as a sequence, not one path.
        let packed = parse_env_files(
            "/etc/default/scx (ignore_errors=yes) /etc/scx.local (ignore_errors=no) /etc/x (ignore_errors=no)",
        );
        assert_eq!(packed.len(), 3);
        assert_eq!(packed[0].path, PathBuf::from("/etc/default/scx"));
        assert!(packed[0].optional);
        assert_eq!(packed[1].path, PathBuf::from("/etc/scx.local"));
        assert!(!packed[1].optional);
        assert_eq!(packed[2].path, PathBuf::from("/etc/x"));
        assert_eq!(
            parse_env_files("/etc/plain"),
            vec![required(Path::new("/etc/plain"))]
        );
        assert!(parse_env_files("  ").is_empty());
        assert_eq!(
            config_path(&info).unwrap(),
            PathBuf::from("/etc/default/scx")
        );
        assert_eq!(
            info.unset_environment,
            strs(&["TMPDIR", "SCX_FLAGS=-s 1 -S"])
        );

        let idle = parse_unit_info(
            "MainPID=0\nActiveState=failed\nResult=exit-code\nExecMainStatus=1\nInvocationID=\n",
        );
        assert!(!idle.active && !idle.loaded);
        assert_eq!(idle.main_pid, None);
        assert_eq!(idle.invocation_id, None);
        assert!(config_path(&idle).is_err());
    }

    #[test]
    fn shell_words_follow_both_systemd_quotings() {
        assert_eq!(
            split_shell_words(r#"A=1 "SCX_FLAGS=-s 700 \"x\"" "B=\$y \\ z""#),
            strs(&["A=1", "SCX_FLAGS=-s 700 \"x\"", "B=$y \\ z"])
        );
        assert_eq!(
            split_shell_words(r"SCX_FLAGS_OVERRIDE=$'-s 10000 --name it\'s'"),
            strs(&["SCX_FLAGS_OVERRIDE=-s 10000 --name it's"])
        );
        assert_eq!(
            split_shell_words(r"X=$'a\\b\tc\033[0m\101'"),
            strs(&["X=a\\b\tc\u{1b}[0mA"])
        );
        assert_eq!(
            parse_manager_environment("LANG=C\nSCX_SCHEDULER_OVERRIDE=scx_rustland\n"),
            pairs(&[("LANG", "C"), ("SCX_SCHEDULER_OVERRIDE", "scx_rustland")])
        );
    }

    #[test]
    fn layers_override_in_systemd_order_and_unset_applies_last() {
        let dir = scratch_dir("layers");
        let first = dir.join("first");
        let second = dir.join("second");
        fs::write(
            &first,
            "SCX_SCHEDULER=scx_lavd\nSCX_FLAGS=\"-v\"\nSCX_PROFILE=gaming\n",
        )
        .unwrap();
        fs::write(&second, "SCX_FLAGS=\"-s 5\"\n").unwrap();
        let info = UnitInfo {
            environment: pairs(&[("SCX_SCHEDULER", "scx_from_unit"), ("GONE", "x")]),
            unset_environment: strs(&["GONE=x", "SCX_PROFILE"]),
            ..with_files(vec![required(&first), required(&second)])
        };
        let manager = pairs(&[
            ("SCX_SCHEDULER", "scx_from_manager"),
            ("SCX_FLAGS_OVERRIDE", "-m 1"),
        ]);
        let env = unit_environment(&info, manager);
        assert_eq!(env.get("SCX_SCHEDULER"), Some("scx_lavd"));
        assert_eq!(env.get("SCX_FLAGS"), Some("-s 5"));
        assert_eq!(env.get("SCX_FLAGS_OVERRIDE"), Some("-m 1"));
        assert_eq!(env.get("GONE"), None);
        assert_eq!(env.get("SCX_PROFILE"), None);
        assert_eq!(env.error, None);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn missing_and_unreadable_files_are_reported() {
        let dir = scratch_dir("env-errors");
        let bad = dir.join("bad");
        fs::write(&bad, b"SCX_SCHEDULER=\xff\xfe\n").unwrap();
        let env = unit_environment(&with_files(vec![required(&bad)]), Vec::new());
        assert!(env.error.as_deref().unwrap().contains("unreadable"));

        let good = dir.join("good");
        fs::write(&good, "SCX_SCHEDULER=scx_lavd\n").unwrap();
        let missing = dir.join("missing");
        let env = unit_environment(
            &with_files(vec![required(&good), required(&missing)]),
            Vec::new(),
        );
        assert!(env.error.as_deref().unwrap().contains("cannot start"));
        let env = unit_environment(
            &with_files(vec![
                required(&good),
                EnvFile {
                    path: missing.clone(),
                    optional: true,
                },
            ]),
            Vec::new(),
        );
        assert_eq!(env.error, None);
        // The first file may be missing: it is the one a write creates.
        let env = unit_environment(&with_files(vec![required(&missing)]), Vec::new());
        assert_eq!(env.error, None);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn write_is_refused_when_a_later_file_or_unset_would_override_it() {
        let dir = scratch_dir("effective");
        let first = dir.join("scx");
        let later = dir.join("local");
        fs::write(&first, "SCX_SCHEDULER=scx_cosmos\n").unwrap();
        fs::write(&later, "SCX_PROFILE=server\n").unwrap();
        let written = Written {
            profile: Some("gaming".into()),
            launch: envfile::Launch::Set("/usr/bin/scx_lavd".into(), strs(&["-v"])),
        };
        let info = with_files(vec![required(&first), required(&later)]);
        let err = check_write_effective(&info, &written).unwrap_err();
        assert!(format!("{err:#}").contains("SCX_PROFILE is also set in"));

        fs::write(&later, "OTHER=1\n").unwrap();
        check_write_effective(&info, &written).unwrap();

        let info = UnitInfo {
            unset_environment: strs(&["SCX_FLAGS=-v"]),
            ..with_files(vec![required(&first)])
        };
        assert!(check_write_effective(&info, &written).is_err());
        let info = UnitInfo {
            unset_environment: strs(&["SCX_FLAGS=-x", "SCX_PROFILE=other"]),
            ..with_files(vec![required(&first)])
        };
        check_write_effective(&info, &written).unwrap();
        let info = UnitInfo {
            unset_environment: strs(&["SCX_PROFILE"]),
            ..with_files(vec![required(&first)])
        };
        assert!(check_write_effective(&info, &written).is_err());
        // Default removes every key, so an unset of any of them cannot
        // drop what it writes.
        let removing = Written {
            profile: None,
            launch: envfile::Launch::Remove,
        };
        let info = UnitInfo {
            unset_environment: strs(&["SCX_PROFILE", "SCX_SCHEDULER", "SCX_FLAGS=x"]),
            ..with_files(vec![required(&first)])
        };
        check_write_effective(&info, &removing).unwrap();
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn write_is_refused_while_a_persistent_override_would_win() {
        // A drop-in's Environment= or a value in an environment file
        // outlives `systemctl unset-environment`, so the applied profile
        // would be written and then ignored by ExecStart.
        let dir = scratch_dir("persistent-override");
        let first = dir.join("scx");
        fs::write(&first, "SCX_SCHEDULER=scx_cosmos\n").unwrap();
        let written = Written {
            profile: Some("gaming".into()),
            launch: envfile::Launch::Set("/usr/bin/scx_lavd".into(), strs(&["-v"])),
        };
        let info = UnitInfo {
            environment: pairs(&[("SCX_SCHEDULER_OVERRIDE", "scx_rusty")]),
            ..with_files(vec![required(&first)])
        };
        let err = check_write_effective(&info, &written).unwrap_err();
        assert!(
            format!("{err:#}").contains("SCX_SCHEDULER_OVERRIDE is set in Environment="),
            "{err:#}"
        );

        // An empty override is unset to the shell and does not block.
        let info = UnitInfo {
            environment: pairs(&[("SCX_SCHEDULER_OVERRIDE", "")]),
            ..with_files(vec![required(&first)])
        };
        check_write_effective(&info, &written).unwrap();

        // One in an environment file, the first file included, is found
        // and named; a later empty reassignment lifts it.
        fs::write(
            &first,
            "SCX_SCHEDULER=scx_cosmos\nSCX_FLAGS_OVERRIDE=\"-s 1\"\n",
        )
        .unwrap();
        let info = with_files(vec![required(&first)]);
        let err = check_write_effective(&info, &written).unwrap_err();
        assert!(
            format!("{err:#}")
                .contains(&format!("SCX_FLAGS_OVERRIDE is set in {}", first.display()))
        );
        fs::write(&first, "SCX_FLAGS_OVERRIDE=\"-s 1\"\nSCX_FLAGS_OVERRIDE=\n").unwrap();
        check_write_effective(&info, &written).unwrap();

        // Layers compose the way systemd composes them: a drop-in's
        // override that a later environment file empties, or that
        // UnsetEnvironment= drops, is no override; one a later file
        // re-sets is reported with that file as its source.
        fs::write(
            &first,
            "SCX_SCHEDULER=scx_cosmos\nSCX_SCHEDULER_OVERRIDE=\n",
        )
        .unwrap();
        let info = UnitInfo {
            environment: pairs(&[("SCX_SCHEDULER_OVERRIDE", "scx_rusty")]),
            ..with_files(vec![required(&first)])
        };
        check_write_effective(&info, &written).unwrap();
        let info = UnitInfo {
            environment: pairs(&[("SCX_SCHEDULER_OVERRIDE", "scx_rusty")]),
            unset_environment: strs(&["SCX_SCHEDULER_OVERRIDE"]),
            ..with_files(vec![required(&dir.join("absent"))])
        };
        check_write_effective(&info, &written).unwrap();
        let later = dir.join("later");
        fs::write(&first, "SCX_SCHEDULER=scx_cosmos\n").unwrap();
        fs::write(&later, "SCX_SCHEDULER_OVERRIDE=scx_flash\n").unwrap();
        let info = UnitInfo {
            environment: pairs(&[("SCX_SCHEDULER_OVERRIDE", "")]),
            ..with_files(vec![required(&first), required(&later)])
        };
        let err = check_write_effective(&info, &written).unwrap_err();
        assert!(
            format!("{err:#}").contains(&format!("is set in {}", later.display())),
            "{err:#}"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn schedulers_resolve_only_inside_the_search_path() {
        let dir = scratch_dir("resolve");
        let bin = dir.join("bin");
        let other = dir.join("other");
        fs::create_dir_all(&bin).unwrap();
        fs::create_dir_all(&other).unwrap();
        for (d, name) in [
            (&bin, "scx_lavd"),
            (&bin, "scx_loader"),
            (&bin, "scx_x y"),
            (&other, "scx_rusty"),
        ] {
            let p = d.join(name);
            fs::write(&p, "#!/bin/sh\n").unwrap();
            fs::set_permissions(&p, fs::Permissions::from_mode(0o755)).unwrap();
        }
        fs::write(bin.join("scx_notexec"), "").unwrap();
        let dirs = vec![bin.clone()];
        assert_eq!(scan_dirs(dirs.clone()), strs(&["scx_lavd"]));
        assert_eq!(
            scan_dirs_with_paths(dirs.clone()),
            vec![("scx_lavd".to_owned(), bin.join("scx_lavd"))]
        );
        // The first directory in order wins for a name in two of them.
        let dup = other.join("scx_lavd");
        fs::write(&dup, "#!/bin/sh\n").unwrap();
        fs::set_permissions(&dup, fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(
            scan_dirs_with_paths(vec![other.clone(), bin.clone()])[0].1,
            dup
        );
        assert_eq!(
            resolve_scheduler("scx_lavd", &dirs).unwrap(),
            bin.join("scx_lavd")
        );
        // An absolute path outside /usr, /bin and /sbin never resolves,
        // even when its directory is on the search path.
        assert!(resolve_scheduler(bin.join("scx_lavd").to_str().unwrap(), &dirs).is_err());
        assert!(resolve_scheduler("scx_rusty", &dirs).is_err());
        assert!(resolve_scheduler(other.join("scx_rusty").to_str().unwrap(), &dirs).is_err());
        assert!(resolve_scheduler("scx_notexec", &dirs).is_err());
        assert!(resolve_scheduler("/tmp/scx_evil", &dirs).is_err());
        assert!(parse_search_path("/usr/local/bin:/usr/bin").is_ok());
        assert!(parse_search_path("bin:/usr/bin").is_err());
        assert!(parse_search_path("").is_err());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn write_config_rewrites_the_first_file_in_place() {
        let dir = scratch_dir("write");
        let first = dir.join("scx");
        fs::write(&first, "# keep\nSCX_SCHEDULER=scx_cosmos\n").unwrap();
        let info = with_files(vec![required(&first)]);
        let written = Written {
            profile: Some("gaming".into()),
            launch: envfile::Launch::Set("/usr/bin/scx_lavd".into(), strs(&["-v"])),
        };
        // The manager environment comes from the live systemd (or fails
        // without one); either way the file is what is checked here.
        match write_config(&info, &written) {
            Ok(()) => assert_eq!(
                fs::read_to_string(&first).unwrap(),
                "# keep\nSCX_SCHEDULER=/usr/bin/scx_lavd\nSCX_FLAGS=\"-v\"\nSCX_PROFILE=gaming\n"
            ),
            Err(err) => assert!(
                format!("{err:#}").contains("could not be resolved"),
                "{err:#}"
            ),
        }
        let _ = fs::remove_dir_all(&dir);
    }
}
