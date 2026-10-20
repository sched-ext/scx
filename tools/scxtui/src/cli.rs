// SPDX-License-Identifier: GPL-2.0

//! `scxtui --cli`: scxctl's command set over the scx.service backend.
//!
//! Same subcommands, flags, name spellings and stdout text as scxctl, so
//! a script changes the command name and nothing else: `-s lavd` and
//! `-s scx_lavd` both work, `get` prints `running Lavd in Gaming mode`,
//! `list` prints `["bpfland", "lavd"]`, and the error cases exit 1 with
//! scxctl's messages. What the loader could not have known (the next
//! start when the file disagrees with the process, overrides in effect,
//! profiles matching the running arguments) goes to stderr, so stdout
//! never carries a line scxctl would not have printed.
//!
//! What differs follows from the backend and is stated rather than
//! hidden. A start or switch is a config rewrite plus a unit (re)start,
//! so the verbs report what systemd accepted, exactly as scxctl reported
//! what the loader accepted. `get` reports the unit's process, never the
//! file. `restart` re-pins the running process'
//! scheduler and arguments before restarting, since a bare `systemctl
//! restart` would start whatever the file says now. `-a` arguments go to
//! `SCX_FLAGS`, which the unit expands unquoted, so a quoted value with a
//! space is refused instead of mangled.

use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};

use crate::backend::service::validate_value;
use crate::backend::{SchedulerBackend, Status};
use crate::kernel::{self, KernelState};
use crate::profiles::{MODES, Mode, Profiles};

/// `--wait` without a value.
const DEFAULT_WAIT: Duration = Duration::from_secs(5);
/// Largest `--wait` accepted. Far beyond any attach time, and small
/// enough that `Instant + Duration` cannot overflow, which would panic
/// after the configuration is already written and the unit started.
const MAX_WAIT_SECS: u64 = 3600;
/// How often the kernel is re-read while waiting.
const WAIT_POLL: Duration = Duration::from_millis(100);

const SCHED_PREFIX: &str = "scx_";

pub const USAGE: &str = "\
scxtui --cli <COMMAND>

Commands:
  get                 Get the info on the running scheduler
  list                List all supported schedulers
  modes -s <SCHED> [--show-args]
                      List the modes configured for a scheduler
  start -s <SCHED> [-m <MODE> | -a <ARGS>]
                      Start a scheduler in a mode or with arguments
  switch [-s <SCHED>] [-m <MODE> | -a <ARGS>]
                      Switch schedulers or modes, optionally with arguments
  stop                Stop the current scheduler
  restart             Restart the current scheduler with original configuration
  restore             Restore the default scheduler from configuration

Options for start, switch, restart and restore:
  --wait[=SECS]       After systemd accepts the operation, wait until the
                      unit runs the scheduler and the kernel reports it
                      attached (default 5 s, at most 3600). Exit 1 if it
                      has not by then, 2 if a scheduler is attached but
                      its ops name cannot be matched to the executable

Scheduler names with or without the scx_ prefix (lavd, scx_lavd).
Modes: auto, gaming, powersave, lowlatency, server
Arguments (-a): separated by commas or whitespace, e.g. \"--verbose,--slice-us 5000\"
";

/// One subcommand's name, usage line and which options it takes.
struct Command {
    name: &'static str,
    usage: &'static str,
    /// Options this command accepts; anything else is rejected, as
    /// clap rejects options foreign to a subcommand.
    allowed: &'static [&'static str],
}

/// `static`, not `const`: [`Request`] hands out `&'static Command` into
/// this table, which needs one fixed place in memory rather than a value
/// materialised at each use.
static COMMANDS: [Command; 8] = [
    Command {
        name: "get",
        usage: "scxtui --cli get",
        allowed: &[],
    },
    Command {
        name: "list",
        usage: "scxtui --cli list",
        allowed: &[],
    },
    Command {
        name: "modes",
        usage: "scxtui --cli modes -s <SCHED> [--show-args]",
        allowed: &["sched", "show-args"],
    },
    Command {
        name: "start",
        usage: "scxtui --cli start -s <SCHED> [-m <MODE> | -a <ARGS>] [--wait[=SECS]]",
        allowed: &["sched", "mode", "args", "wait"],
    },
    Command {
        name: "switch",
        usage: "scxtui --cli switch [-s <SCHED>] [-m <MODE> | -a <ARGS>] [--wait[=SECS]]",
        allowed: &["sched", "mode", "args", "wait"],
    },
    Command {
        name: "stop",
        usage: "scxtui --cli stop",
        allowed: &[],
    },
    Command {
        name: "restart",
        usage: "scxtui --cli restart [--wait[=SECS]]",
        allowed: &["wait"],
    },
    Command {
        name: "restore",
        usage: "scxtui --cli restore [--wait[=SECS]]",
        allowed: &["wait"],
    },
];

/// Parsed options; each command checks what it accepts via
/// [`Command::allowed`].
#[derive(Debug, Default, PartialEq)]
struct Opts {
    sched: Option<String>,
    mode: Option<Mode>,
    args: Option<Vec<String>>,
    show_args: bool,
    /// `--wait`: how long to wait for the kernel to report the scheduler
    /// attached before failing. `None` = report acceptance only, like
    /// scxctl.
    wait: Option<Duration>,
}

/// What a parsed command line asks for.
#[derive(Debug, PartialEq)]
enum Request {
    /// Help for `--cli` as a whole or for one command; needs no backend.
    Help(Option<&'static Command>),
    Run(&'static Command, Opts),
}

impl PartialEq for Command {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name
    }
}

impl std::fmt::Debug for Command {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name)
    }
}

/// Parses `<COMMAND> [OPTIONS]`. Options come as `-s X`, `--sched X` or
/// `--sched=X`; `-m` and `-a` exclude each other, as in scxctl.
fn parse(args: &[String]) -> Result<Request> {
    let Some((name, rest)) = args.split_first() else {
        bail!("missing command\n\n{USAGE}");
    };
    if matches!(name.as_str(), "-h" | "--help" | "help") {
        return Ok(Request::Help(None));
    }
    let Some(command) = COMMANDS.iter().find(|c| c.name == name) else {
        bail!("unknown command {name:?}\n\n{USAGE}");
    };
    let mut opts = Opts::default();
    let mut iter = rest.iter();
    while let Some(arg) = iter.next() {
        let (key, inline) = match arg.split_once('=') {
            Some((key, value)) if key.starts_with("--") => (key, Some(value.to_owned())),
            _ => (arg.as_str(), None),
        };
        let (field, takes_value) = match key {
            "-h" | "--help" => return Ok(Request::Help(Some(command))),
            "-s" | "--sched" => ("sched", true),
            "-m" | "--mode" => ("mode", true),
            "-a" | "--args" => ("args", true),
            "--show-args" => ("show-args", false),
            // The value is optional: `--wait` alone means the default.
            "--wait" => ("wait", false),
            other => bail!(
                "unexpected argument {other:?} for {}\n\nUsage: {}",
                command.name,
                command.usage
            ),
        };
        if !command.allowed.contains(&field) {
            bail!(
                "{key} is not an option of {}\n\nUsage: {}",
                command.name,
                command.usage
            );
        }
        let value = if takes_value {
            inline
                .or_else(|| iter.next().cloned())
                .with_context(|| format!("{key} requires a value"))?
        } else if field == "wait" {
            inline.unwrap_or_default()
        } else {
            if inline.is_some() {
                bail!("{key} takes no value");
            }
            String::new()
        };
        // Last-one-wins would let a mistyped command line start a
        // scheduler other than the one meant; clap rejects repeats too.
        let repeated = match field {
            "sched" => opts.sched.is_some(),
            "mode" => opts.mode.is_some(),
            "args" => opts.args.is_some(),
            "wait" => opts.wait.is_some(),
            _ => opts.show_args,
        };
        if repeated {
            bail!("{key} given more than once");
        }
        match field {
            "sched" => opts.sched = Some(ensure_scx_prefix(&value)),
            "mode" => {
                opts.mode = Some(Mode::parse(&value).with_context(|| {
                    format!("unknown mode {value:?} (auto, gaming, powersave, lowlatency, server)")
                })?);
            }
            "args" => opts.args = Some(expand_args(&value)?),
            "wait" => {
                opts.wait = Some(if value.is_empty() {
                    DEFAULT_WAIT
                } else {
                    let secs: u64 = value.parse().ok().filter(|s| *s > 0).with_context(|| {
                        format!("--wait wants a number of seconds, got {value:?}")
                    })?;
                    if secs > MAX_WAIT_SECS {
                        bail!("--wait={secs} is more than the {MAX_WAIT_SECS} s maximum");
                    }
                    Duration::from_secs(secs)
                });
            }
            _ => opts.show_args = true,
        }
    }
    if opts.mode.is_some() && opts.args.is_some() {
        bail!("--mode and --args cannot be combined");
    }
    if matches!(command.name, "modes" | "start") && opts.sched.is_none() {
        bail!(
            "{} requires --sched\n\nUsage: {}",
            command.name,
            command.usage
        );
    }
    Ok(Request::Run(command, opts))
}

/// scxctl accepts `lavd` and `scx_lavd` alike; the backend speaks full
/// names only, so the prefix is added at the CLI boundary.
fn ensure_scx_prefix(name: &str) -> String {
    if name.starts_with(SCHED_PREFIX) {
        name.to_owned()
    } else {
        format!("{SCHED_PREFIX}{name}")
    }
}

/// How scxctl shows a scheduler: the `SupportedSched` variant name, e.g.
/// `Lavd` or `P2DQ`. Names whose variant is not plain capitalisation are
/// listed; the first three are scx_loader's, the rest follow the same
/// convention for schedulers that have no variant upstream yet. Anything
/// else gets the prefix stripped and the first letter capitalised, which
/// is what a variant for it would be called.
fn display_name(sched: &str) -> String {
    let bare = sched.strip_prefix(SCHED_PREFIX).unwrap_or(sched);
    match bare {
        "p2dq" => "P2DQ".to_owned(),
        "eevdf" => "EEVDF".to_owned(),
        "mlfq" => "MLFQ".to_owned(),
        "rvtime" => "RVTime".to_owned(),
        "rlocal" => "RLocal".to_owned(),
        "rburst" => "RBurst".to_owned(),
        _ => {
            let mut chars = bare.chars();
            match chars.next() {
                Some(first) => first.to_uppercase().chain(chars).collect(),
                None => String::new(),
            }
        }
    }
}

/// scxctl's `--args` pipeline reduced to what `SCX_FLAGS` can carry:
/// comma split, then whitespace split, flattened. Every token must
/// survive the unit's unquoted expansion, which [`validate_value`]
/// checks; an empty result is refused like scxctl refuses it.
fn expand_args(raw: &str) -> Result<Vec<String>> {
    let args: Vec<String> = raw
        .split(',')
        .flat_map(str::split_whitespace)
        .map(str::to_owned)
        .collect();
    if args.is_empty() {
        bail!("--args expanded to nothing; omit it to use the scheduler's defaults");
    }
    for arg in &args {
        validate_value("argument", arg)?;
    }
    Ok(args)
}

fn format_args(args: &[String]) -> String {
    shell_words::join(args)
}

/// Whether a command needs the profiles file. `stop`, `list`, `restart`
/// and help must work when that file is broken.
fn needs_profiles(command: &Command) -> bool {
    matches!(
        command.name,
        "get" | "modes" | "start" | "switch" | "restore"
    )
}

/// Entry point: parses, then runs with lazily provided backend and
/// profiles, so help needs neither and `stop` needs no profiles. Output
/// goes to stdout in scxctl's wording; errors come back for `main`.
pub fn run<'a>(
    args: &[String],
    backend: impl FnOnce() -> Result<Box<dyn SchedulerBackend + 'a>>,
    profiles: impl FnOnce() -> Result<Profiles>,
) -> Result<()> {
    let request = parse(args)?;
    let (command, opts) = match request {
        Request::Help(None) => {
            print!("{USAGE}");
            return Ok(());
        }
        Request::Help(Some(command)) => {
            println!("Usage: {}", command.usage);
            return Ok(());
        }
        Request::Run(command, opts) => (command, opts),
    };
    let backend = backend()?;
    let backend = backend.as_ref();
    let profiles = if needs_profiles(command) {
        Some(profiles()?)
    } else {
        None
    };
    let profiles = profiles.as_ref();
    match command.name {
        "get" => cmd_get(backend, profiles.expect("loaded")),
        "list" => cmd_list(backend),
        "modes" => cmd_modes(backend, profiles.expect("loaded"), &opts),
        "start" => cmd_start(backend, profiles.expect("loaded"), &opts),
        "switch" => cmd_switch(backend, profiles.expect("loaded"), &opts),
        "stop" => {
            backend.stop()?;
            println!("stopped");
            Ok(())
        }
        "restart" => cmd_restart(backend, &opts),
        "restore" => cmd_restore(backend, profiles.expect("loaded"), &opts),
        _ => unreachable!("parse admits only COMMANDS"),
    }
}

fn status(backend: &dyn SchedulerBackend) -> Result<Status> {
    backend.status().context("cannot read the unit's state")
}

/// scxctl's precondition for switch and restart: a scheduler must be
/// running, with its name known. An active unit whose process cannot
/// be read is not "running X" for these purposes.
fn require_running(status: &Status, verb: &str) -> Result<String> {
    match status.running() {
        Some(sched) => Ok(sched.to_owned()),
        None if status.active => {
            bail!("scx.service is active, but its process could not be read; refusing to {verb}")
        }
        None => bail!("no scx scheduler running, use 'start' instead of '{verb}'"),
    }
}

fn cmd_get(backend: &dyn SchedulerBackend, profiles: &Profiles) -> Result<()> {
    let status = status(backend)?;
    match (status.active, &status.process) {
        (false, _) => println!("no scx scheduler running"),
        (true, None) => println!("scx.service is active, but its process could not be read"),
        (true, Some(process)) => {
            // scxctl's rule: with arguments, print the arguments and no
            // mode; without, the mode. The loader knew the mode it was
            // asked for; here it would be reconstructed from argv, so
            // the matching profiles go on a diagnostic line of their
            // own and the first line stays scxctl's.
            let name = display_name(&process.sched);
            let modes = profiles.modes_for(&process.sched, &process.args);
            if process.args.is_empty() {
                // No arguments: Auto, as scxctl would say, unless the
                // file gives Auto flags of its own and the process has
                // none, in which case it runs the plain defaults.
                if modes == [Mode::Auto] {
                    println!("running {name} in Auto mode");
                } else {
                    println!("running {name} with its own defaults");
                }
            } else {
                println!(
                    "running {name} with arguments \"{}\"",
                    format_args(&process.args)
                );
            }
            // Diagnostic, on stderr like the rest below.
            if !modes.is_empty() && (!process.args.is_empty() || modes.len() > 1) {
                let names: Vec<&str> = modes.iter().map(|m| m.name()).collect();
                eprintln!("matching modes: {}", names.join(", "));
            }
        }
    }
    // Everything below is what the loader could not have known, so
    // scxctl never printed it. It goes to stderr: stdout stays what a
    // script written against scxctl expects, byte for byte, and a
    // person at a terminal still sees both.
    //
    // The file can disagree with the process, in scheduler or in
    // arguments; say so instead of letting the next restart surprise.
    if let Some(err) = &status.config_error {
        eprintln!("next start: unknown ({err})");
    } else if let Some(next) = &status.next_sched {
        let same = status
            .process
            .as_ref()
            .filter(|_| status.active)
            .is_some_and(|p| p.sched == *next && p.args == status.next_flags);
        if !same {
            eprintln!(
                "next start: {}{}",
                display_name(next),
                if status.next_flags.is_empty() {
                    String::new()
                } else {
                    format!(" with arguments \"{}\"", format_args(&status.next_flags))
                }
            );
        }
    }
    for (name, value) in [
        ("SCX_SCHEDULER_OVERRIDE", status.override_sched.clone()),
        (
            "SCX_FLAGS_OVERRIDE",
            status.override_flags.as_deref().map(format_args),
        ),
    ] {
        if let Some(value) = value {
            eprintln!("override in effect: {name}={value}");
        }
    }
    Ok(())
}

fn cmd_list(backend: &dyn SchedulerBackend) -> Result<()> {
    // scxctl strips the prefix and prints the Vec<String> with Debug.
    let supported: Vec<String> = backend
        .supported_schedulers()?
        .iter()
        .map(|s| s.strip_prefix(SCHED_PREFIX).unwrap_or(s).to_owned())
        .collect();
    println!("supported schedulers: {supported:?}");
    Ok(())
}

fn cmd_modes(backend: &dyn SchedulerBackend, profiles: &Profiles, opts: &Opts) -> Result<()> {
    let sched = opts.sched.as_deref().expect("parse requires --sched");
    validate_sched(backend, sched)?;
    let name = display_name(sched);
    if opts.show_args {
        println!("configuration for {name}:");
        for mode in MODES {
            let flags = profiles.flags(sched, mode);
            if flags.is_empty() {
                if mode == Mode::Auto {
                    println!("  {}: (uses {name}'s own defaults)", mode.name());
                } else {
                    println!(
                        "  {}: (not configured, uses {name}'s own defaults)",
                        mode.name()
                    );
                }
            } else {
                println!("  {}: {}", mode.name(), flags.join(" "));
            }
        }
    } else {
        let configured: Vec<&str> = MODES
            .iter()
            .filter(|mode| profiles.configured(sched, **mode))
            .map(|mode| mode.name())
            .collect();
        println!("modes configured for {name}: [{}]", configured.join(", "));
        println!(
            "(unlisted modes run with {name}'s own defaults; use --show-args to see them all)"
        );
    }
    Ok(())
}

/// Refuses a scheduler the backend would not list, like scxctl refuses
/// one the daemon does not advertise, before any file is written.
fn validate_sched(backend: &dyn SchedulerBackend, sched: &str) -> Result<()> {
    let supported = backend.supported_schedulers()?;
    if supported.iter().any(|s| s == sched) {
        Ok(())
    } else {
        let names: Vec<&str> = supported
            .iter()
            .map(|s| s.strip_prefix(SCHED_PREFIX).unwrap_or(s))
            .collect();
        bail!(
            "unknown scheduler {:?}\nsupported schedulers: {names:?}",
            sched.strip_prefix(SCHED_PREFIX).unwrap_or(sched)
        )
    }
}

fn cmd_start(backend: &dyn SchedulerBackend, profiles: &Profiles, opts: &Opts) -> Result<()> {
    let sched = opts.sched.as_deref().expect("parse requires --sched");
    validate_sched(backend, sched)?;
    let status = status(backend)?;
    if status.active {
        bail!(
            "scx.service is already running {}; use 'switch' instead of 'start'",
            status
                .running()
                .map_or("a scheduler".to_owned(), display_name)
        );
    }
    launch(
        backend,
        profiles,
        Launch {
            verb: "started",
            sched,
            mode: opts.mode,
            args: opts.args.as_deref(),
            restart: false,
            wait: opts.wait,
        },
    )
}

/// Resolves the switch target the way scxctl does: refused when nothing
/// runs, even with `--sched`; no `--sched` means the running scheduler;
/// no `--mode` keeps the running mode for the same scheduler and uses
/// `auto` for another one.
fn cmd_switch(backend: &dyn SchedulerBackend, profiles: &Profiles, opts: &Opts) -> Result<()> {
    let status = status(backend)?;
    let running = require_running(&status, "switch")?;
    let sched = opts.sched.clone().unwrap_or_else(|| running.clone());
    validate_sched(backend, &sched)?;
    let same = running == sched;
    let mode = match opts.mode {
        Some(mode) => Some(mode),
        None if opts.args.is_some() => None,
        // Same scheduler, no --mode: scxctl keeps the running mode. The
        // mode is not recorded here, so it is kept only when the running
        // arguments match exactly one profile row. Otherwise (custom
        // arguments, or two rows sharing them) the running arguments
        // are kept as they are: picking a row could change the
        // scheduling policy behind the user's back.
        None if same => {
            let process = status.process.as_ref().expect("running implies a process");
            match profiles.modes_for(&process.sched, &process.args).as_slice() {
                [mode] => Some(*mode),
                _ => {
                    return launch(
                        backend,
                        profiles,
                        Launch {
                            verb: "switched to",
                            sched: &sched,
                            mode: None,
                            args: Some(&process.args),
                            restart: true,
                            wait: opts.wait,
                        },
                    );
                }
            }
        }
        None => Some(Mode::Auto),
    };
    launch(
        backend,
        profiles,
        Launch {
            verb: "switched to",
            sched: &sched,
            mode,
            args: opts.args.as_deref(),
            restart: true,
            wait: opts.wait,
        },
    )
}

/// scxctl's restart keeps the running scheduler and its configuration.
/// `systemctl restart` alone would start whatever the file says now,
/// which may be something else since the last start, so the running
/// process' scheduler and arguments are written back first. Not atomic:
/// another writer between the read and the restart wins, as with any
/// two clients editing the same file.
fn cmd_restart(backend: &dyn SchedulerBackend, opts: &Opts) -> Result<()> {
    let status = status(backend)?;
    require_running(&status, "restart")?;
    // An override set since the last start would make the restart run
    // something other than what runs now, which is the one thing this
    // command promises to keep.
    refuse_overrides(&status)?;
    let process = status.process.as_ref().expect("running implies a process");
    backend.switch(&process.sched, &process.args)?;
    if let Some(timeout) = opts.wait {
        wait_for_attach(
            backend,
            &process.sched,
            timeout,
            kernel::read,
            std::thread::sleep,
        )?;
    }
    println!("restarted");
    Ok(())
}

/// An override wins over whatever is written: `SCX_SCHEDULER_OVERRIDE`
/// over the scheduler, `SCX_FLAGS_OVERRIDE` over the flags. systemd would
/// accept the restart and run something else, and a script reading
/// "switched to Bpfland" would believe it. Every command that writes and
/// (re)starts checks this before touching the file; the override's own
/// layer is where to fix it.
fn refuse_overrides(status: &Status) -> Result<()> {
    let overrides: Vec<&str> = [
        status
            .override_sched
            .as_ref()
            .map(|_| "SCX_SCHEDULER_OVERRIDE"),
        status.override_flags.as_ref().map(|_| "SCX_FLAGS_OVERRIDE"),
    ]
    .into_iter()
    .flatten()
    .collect();
    if overrides.is_empty() {
        Ok(())
    } else {
        bail!(
            "{} in effect and would take precedence over this change; \
clear it (systemctl unset-environment, or the file that sets it) and retry",
            overrides.join(" and ")
        )
    }
}

fn cmd_restore(backend: &dyn SchedulerBackend, profiles: &Profiles, opts: &Opts) -> Result<()> {
    let Some((sched, mode)) = profiles.default_launch() else {
        bail!(
            "no default scheduler configured\nSet 'default_sched' in the profiles file to use this command"
        );
    };
    validate_sched(backend, sched)?;
    let active = status(backend)?.active;
    launch(
        backend,
        profiles,
        Launch {
            verb: "restored default scheduler",
            sched,
            mode: Some(mode),
            args: None,
            restart: active,
            wait: opts.wait,
        },
    )
}

/// Writes the config and starts or restarts the unit, then reports in
/// scxctl's words. `restart` says which systemd verb applies; the
/// callers decided that from the state they checked, so the file and
/// the unit action stay consistent with the message.
/// What a start, switch or restore asks `launch` to do.
struct Launch<'a> {
    /// scxctl's verb for the success line.
    verb: &'static str,
    sched: &'a str,
    mode: Option<Mode>,
    args: Option<&'a [String]>,
    /// Whether the unit is active, so the systemd verb is restart.
    restart: bool,
    wait: Option<Duration>,
}

fn launch(backend: &dyn SchedulerBackend, profiles: &Profiles, launch: Launch<'_>) -> Result<()> {
    let Launch {
        verb,
        sched,
        mode,
        args,
        restart,
        wait,
    } = launch;
    refuse_overrides(&status(backend)?)?;
    let (flags, how) = match (args, mode) {
        (Some(args), _) => (
            args.to_vec(),
            format!("with arguments \"{}\"", format_args(args)),
        ),
        (None, mode) => {
            let mode = mode.unwrap_or(Mode::Auto);
            let flags = profiles.flags(sched, mode);
            let how = if mode == Mode::Auto || !flags.is_empty() {
                format!("in {} mode", mode.name())
            } else {
                "with its own defaults".to_owned()
            };
            (flags, how)
        }
    };
    if restart {
        backend.switch(sched, &flags)?;
    } else {
        backend.start(sched, &flags)?;
    }
    if let Some(timeout) = wait {
        wait_for_attach(backend, sched, timeout, kernel::read, std::thread::sleep)?;
    }
    println!("{verb} {} {how}", display_name(sched));
    Ok(())
}

/// The one outcome of `--wait` that is neither success nor failure: the
/// unit runs the requested scheduler and the kernel has a scheduler
/// attached, but the ops name it registered cannot be matched to the
/// executable's name, so the identity is not confirmed. Exit status 2,
/// so a script can tell it from "did not attach" (1).
#[derive(Debug)]
pub struct Unconfirmed(String);

impl std::fmt::Display for Unconfirmed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Unconfirmed {}

/// Exit status for a CLI error: 2 for [`Unconfirmed`], 1 otherwise.
pub fn exit_status(err: &anyhow::Error) -> i32 {
    if err.downcast_ref::<Unconfirmed>().is_some() {
        2
    } else {
        1
    }
}

/// `--wait`: systemd accepting a start says nothing about the scheduler
/// attaching, so poll until two independent observers agree: systemd
/// (the unit is active and its main process is `sched`) and the kernel
/// (`sched_ext` enabled, and the registered ops name is `sched`'s). The
/// kernel alone is not enough: a scheduler started by hand, or one the
/// unit no longer owns, reads as attached too. The unit going inactive
/// meanwhile (the scheduler exited and Restart= gave up) fails at once
/// instead of waiting out the clock.
///
/// Every failure says that the operation itself went through: the file
/// is written and the unit (re)started, only the confirmation is
/// missing. When the deadline passes with systemd satisfied and a
/// scheduler attached whose ops name just does not match, the result is
/// [`Unconfirmed`] rather than a failure: the ops name is chosen by each
/// scheduler and [`KernelState::matches`] knows the common shapes, not
/// every one. `probe` and `sleep` are parameters so the loop is testable
/// without a kernel or a clock.
fn wait_for_attach(
    backend: &dyn SchedulerBackend,
    sched: &str,
    timeout: Duration,
    mut probe: impl FnMut() -> Result<Option<KernelState>>,
    sleep: impl Fn(Duration),
) -> Result<()> {
    const ACCEPTED: &str = "systemd accepted the operation, but";
    let deadline = Instant::now() + timeout;
    loop {
        let status = status(backend)
            .with_context(|| format!("{ACCEPTED} the unit's state could not be re-read"))?;
        if !status.active {
            bail!(
                "{ACCEPTED} scx.service is no longer active: {} exited before attaching \
(see journalctl -u scx.service)",
                display_name(sched)
            );
        }
        let unit_runs_it = status.running() == Some(sched);
        let state = match probe() {
            Ok(Some(state)) => state,
            Ok(None) => bail!(
                "{ACCEPTED} there is nothing to wait for: this kernel has no sched_ext \
(/sys/kernel/sched_ext is absent)"
            ),
            Err(err) => {
                return Err(err)
                    .with_context(|| format!("{ACCEPTED} the kernel state could not be read"));
            }
        };
        let now = Instant::now();
        // The deadline is checked before any success is granted, so a
        // probe that comes back late cannot turn into a pass.
        let expired = now >= deadline;
        if !expired && unit_runs_it && state.enabled() && state.matches(sched) {
            return Ok(());
        }
        if expired {
            let ops = state.ops.as_deref().unwrap_or("none");
            // Unconfirmed is for an ops name the heuristic cannot match.
            // A late probe that does match is a plain timeout: the names
            // agree, only the clock ran out.
            if unit_runs_it && state.enabled() && !state.matches(sched) {
                return Err(Unconfirmed(format!(
                    "{ACCEPTED} the identity of the attached scheduler could not be confirmed \
within {} s: scx.service runs {}, the kernel reports ops name {ops:?}, and the two could \
not be matched; check scxtop or the journal",
                    timeout.as_secs(),
                    display_name(sched)
                ))
                .into());
            }
            bail!(
                "{ACCEPTED} {} did not attach within {} s (unit runs {}, kernel: sched_ext {}, \
ops: {ops})",
                display_name(sched),
                timeout.as_secs(),
                status
                    .running()
                    .map_or("no readable process".to_owned(), display_name),
                state.state
            );
        }
        sleep(WAIT_POLL.min(deadline.saturating_duration_since(now)));
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use super::*;
    use crate::backend::Process;

    fn strs(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| (*s).to_owned()).collect()
    }

    #[derive(Debug, PartialEq)]
    enum Call {
        Start(String, Vec<String>),
        Switch(String, Vec<String>),
        Stop,
        Restart,
    }

    struct Stub {
        truth: Status,
        calls: RefCell<Vec<Call>>,
        status_broken: bool,
        status_reads: RefCell<usize>,
    }

    impl Stub {
        fn idle() -> Self {
            Self {
                truth: Status::default(),
                calls: RefCell::new(Vec::new()),
                status_broken: false,
                status_reads: RefCell::new(0),
            }
        }

        fn running(sched: &str, args: &[&str]) -> Self {
            Self {
                truth: Status {
                    active: true,
                    process: Some(Process {
                        sched: sched.into(),
                        args: strs(args),
                    }),
                    next_sched: Some(sched.into()),
                    next_flags: strs(args),
                    ..Status::default()
                },
                calls: RefCell::new(Vec::new()),
                status_broken: false,
                status_reads: RefCell::new(0),
            }
        }
    }

    impl SchedulerBackend for Stub {
        fn label(&self) -> String {
            "stub".into()
        }
        fn status(&self) -> Result<Status> {
            *self.status_reads.borrow_mut() += 1;
            if self.status_broken {
                bail!("cannot read the unit's state");
            }
            Ok(self.truth.clone())
        }
        fn supported_schedulers(&self) -> Result<Vec<String>> {
            Ok(strs(&["scx_bpfland", "scx_lavd"]))
        }
        fn start(&self, sched: &str, flags: &[String]) -> Result<()> {
            self.calls
                .borrow_mut()
                .push(Call::Start(sched.into(), flags.to_vec()));
            Ok(())
        }
        fn switch(&self, sched: &str, flags: &[String]) -> Result<()> {
            self.calls
                .borrow_mut()
                .push(Call::Switch(sched.into(), flags.to_vec()));
            Ok(())
        }
        fn stop(&self) -> Result<()> {
            self.calls.borrow_mut().push(Call::Stop);
            Ok(())
        }
        fn restart(&self) -> Result<()> {
            self.calls.borrow_mut().push(Call::Restart);
            Ok(())
        }
    }

    /// Runs against a stub that is handed out by reference; the profiles
    /// closure counts how often it was needed.
    fn run_with(stub: &Stub, args: &[&str]) -> Result<()> {
        run(
            &strs(args),
            || Ok(Box::new(StubRef(stub)) as Box<dyn SchedulerBackend + '_>),
            || Ok(Profiles::default()),
        )
    }

    /// `run` wants an owned box; forward to the shared stub.
    struct StubRef<'a>(&'a Stub);

    impl SchedulerBackend for StubRef<'_> {
        fn label(&self) -> String {
            self.0.label()
        }
        fn status(&self) -> Result<Status> {
            self.0.status()
        }
        fn supported_schedulers(&self) -> Result<Vec<String>> {
            self.0.supported_schedulers()
        }
        fn start(&self, sched: &str, flags: &[String]) -> Result<()> {
            self.0.start(sched, flags)
        }
        fn switch(&self, sched: &str, flags: &[String]) -> Result<()> {
            self.0.switch(sched, flags)
        }
        fn stop(&self) -> Result<()> {
            self.0.stop()
        }
        fn restart(&self) -> Result<()> {
            self.0.restart()
        }
    }

    #[test]
    fn names_accept_both_spellings_and_display_like_scxctl() {
        assert_eq!(ensure_scx_prefix("lavd"), "scx_lavd");
        assert_eq!(ensure_scx_prefix("scx_lavd"), "scx_lavd");
        assert_eq!(display_name("scx_lavd"), "Lavd");
        assert_eq!(display_name("scx_p2dq"), "P2DQ");
        assert_eq!(display_name("scx_rburst"), "RBurst");
        assert_eq!(display_name("scx_rvtime"), "RVTime");
        assert_eq!(display_name("scx_homebrew"), "Homebrew");
    }

    #[test]
    fn options_are_checked_per_command() {
        let Request::Run(command, opts) =
            parse(&strs(&["switch", "-s", "lavd", "--mode=gaming"])).unwrap()
        else {
            panic!("run expected");
        };
        assert_eq!(command.name, "switch");
        assert_eq!(opts.sched.as_deref(), Some("scx_lavd"));
        assert_eq!(opts.mode, Some(Mode::Gaming));

        let Request::Run(_, opts) = parse(&strs(&[
            "start",
            "--sched",
            "bpfland",
            "-a",
            "--verbose,--slice-us 5000",
        ]))
        .unwrap() else {
            panic!("run expected");
        };
        assert_eq!(opts.args, Some(strs(&["--verbose", "--slice-us", "5000"])));

        // Options foreign to a command are rejected, not ignored.
        assert!(parse(&strs(&["start", "-s", "lavd", "--show-args"])).is_err());
        assert!(parse(&strs(&["modes", "-s", "lavd", "-m", "gaming"])).is_err());
        assert!(parse(&strs(&["get", "-s", "lavd"])).is_err());
        assert!(parse(&strs(&["stop", "now"])).is_err());
        // Required and exclusive options, bad values.
        assert!(parse(&strs(&["start", "-m", "gaming"])).is_err());
        assert!(parse(&strs(&["modes"])).is_err());
        assert!(parse(&strs(&["start", "-s", "lavd", "-m", "auto", "-a", "-v"])).is_err());
        assert!(parse(&strs(&["start", "-s", "lavd", "-m", "turbo"])).is_err());
        assert!(parse(&strs(&["start", "-s"])).is_err());
        assert!(parse(&strs(&["modes", "-s", "lavd", "--show-args=whatever"])).is_err());
        // Repeats are errors, not last-one-wins.
        assert!(parse(&strs(&["start", "-s", "lavd", "-s", "bpfland"])).is_err());
        assert!(parse(&strs(&["switch", "-m", "auto", "--mode=gaming"])).is_err());
        assert!(
            parse(&strs(&[
                "modes",
                "-s",
                "lavd",
                "--show-args",
                "--show-args"
            ]))
            .is_err()
        );
        assert!(parse(&strs(&["frobnicate"])).is_err());
        assert!(parse(&[]).is_err());
        // Help needs nothing else to be valid.
        assert_eq!(parse(&strs(&["--help"])).unwrap(), Request::Help(None));
        assert!(matches!(
            parse(&strs(&["start", "--help"])).unwrap(),
            Request::Help(Some(c)) if c.name == "start"
        ));
    }

    #[test]
    fn args_follow_scxctl_splitting_within_what_scx_flags_can_carry() {
        assert_eq!(
            expand_args("-s 20000,-m powersave,-I 100").unwrap(),
            strs(&["-s", "20000", "-m", "powersave", "-I", "100"])
        );
        assert!(expand_args("   ").is_err(), "empty expansion refused");
        // A quoted value with a space cannot reach argv through the
        // unit's unquoted expansion; refused rather than mangled.
        assert!(expand_args("--name \"foo bar\"").is_err());
        assert!(expand_args("--glob=*").is_err());
    }

    #[test]
    fn switch_and_restart_need_a_running_scheduler_like_scxctl() {
        let idle = Stub::idle();
        let err = run_with(&idle, &["switch", "-s", "lavd"]).unwrap_err();
        assert!(format!("{err:#}").contains("use 'start' instead of 'switch'"));
        assert!(run_with(&idle, &["restart"]).is_err());
        assert!(
            idle.calls.borrow().is_empty(),
            "nothing started behind switch's back"
        );

        // Active unit, unreadable process: not "running X" either.
        let blind = Stub {
            truth: Status {
                active: true,
                ..Status::default()
            },
            calls: RefCell::new(Vec::new()),
            status_broken: false,
            status_reads: RefCell::new(0),
        };
        assert!(run_with(&blind, &["switch", "-s", "lavd"]).is_err());
        assert!(run_with(&blind, &["restart"]).is_err());
        assert!(blind.calls.borrow().is_empty());
    }

    #[test]
    fn switch_resolves_target_and_mode_like_scxctl() {
        let running = Stub::running("scx_lavd", &["--performance", "--pinned-slice-us", "500"]);
        // Same scheduler, no mode: keep the running profile (first match).
        run_with(&running, &["switch", "-m", "powersave"]).unwrap();
        run_with(&running, &["switch"]).unwrap();
        // Other scheduler by short name, no mode: auto.
        run_with(&running, &["switch", "-s", "bpfland"]).unwrap();
        // Arguments go to SCX_FLAGS as given.
        run_with(
            &running,
            &["switch", "-s", "scx_bpfland", "-a", "-k,-s 5000"],
        )
        .unwrap();
        assert_eq!(
            *running.calls.borrow(),
            [
                Call::Switch(
                    "scx_lavd".into(),
                    strs(&["--powersave", "--pinned-slice-us", "500"])
                ),
                Call::Switch(
                    "scx_lavd".into(),
                    strs(&["--performance", "--pinned-slice-us", "500"])
                ),
                Call::Switch("scx_bpfland".into(), strs(&["-m", "auto"])),
                Call::Switch("scx_bpfland".into(), strs(&["-k", "-s", "5000"])),
            ]
        );
        // start on an active unit is refused; an unlisted scheduler is
        // refused before any write.
        assert!(run_with(&running, &["start", "-s", "bpfland"]).is_err());
        assert!(run_with(&running, &["switch", "-s", "nope"]).is_err());
        assert_eq!(running.calls.borrow().len(), 4);
    }

    #[test]
    fn an_override_in_effect_refuses_start_switch_and_restore() {
        // The file would be rewritten, systemd would accept the restart,
        // and the override would make it run something else: the
        // command must fail before the file changes.
        let mut running = Stub::running("scx_lavd", &[]);
        running.truth.override_sched = Some("scx_lavd".into());
        let err = run_with(&running, &["switch", "-s", "bpfland", "-m", "gaming"]).unwrap_err();
        assert!(format!("{err:#}").contains("SCX_SCHEDULER_OVERRIDE"));
        assert!(running.calls.borrow().is_empty());

        let mut idle = Stub::idle();
        idle.truth.override_flags = Some(strs(&["-s", "1"]));
        let err = run_with(&idle, &["start", "-s", "lavd", "-m", "gaming"]).unwrap_err();
        assert!(format!("{err:#}").contains("SCX_FLAGS_OVERRIDE"));
        assert!(!format!("{err:#}").contains("SCX_SCHEDULER_OVERRIDE"));
        assert!(idle.calls.borrow().is_empty());

        // restart promises to keep what runs; an override set since the
        // last start would break that promise, so it is refused too.
        let mut running = Stub::running("scx_lavd", &["--performance"]);
        running.truth.override_sched = Some("scx_bpfland".into());
        assert!(run_with(&running, &["restart"]).is_err());
        assert!(running.calls.borrow().is_empty(), "no switch issued");
    }

    #[test]
    fn switch_without_mode_keeps_running_arguments_when_no_single_profile_matches() {
        // lavd's gaming and lowlatency share a flag set: keep the
        // arguments rather than pick a row. Custom arguments likewise.
        let shared = Stub::running("scx_lavd", &["--performance", "--pinned-slice-us", "500"]);
        run_with(&shared, &["switch"]).unwrap();
        let custom = Stub::running("scx_lavd", &["--custom"]);
        run_with(&custom, &["switch"]).unwrap();
        assert_eq!(
            shared.calls.borrow().last(),
            Some(&Call::Switch(
                "scx_lavd".into(),
                strs(&["--performance", "--pinned-slice-us", "500"])
            ))
        );
        assert_eq!(
            custom.calls.borrow().last(),
            Some(&Call::Switch("scx_lavd".into(), strs(&["--custom"])))
        );
        // A unique match is the mode, as before.
        let unique = Stub::running("scx_bpfland", &["-m", "all"]);
        run_with(&unique, &["switch"]).unwrap();
        assert_eq!(
            unique.calls.borrow().last(),
            Some(&Call::Switch("scx_bpfland".into(), strs(&["-m", "all"])))
        );
    }

    #[test]
    fn wait_option_parses_and_is_per_command() {
        let Request::Run(_, opts) = parse(&strs(&["start", "-s", "lavd", "--wait"])).unwrap()
        else {
            panic!("run expected");
        };
        assert_eq!(opts.wait, Some(DEFAULT_WAIT));
        let Request::Run(_, opts) = parse(&strs(&["restart", "--wait=30"])).unwrap() else {
            panic!("run expected");
        };
        assert_eq!(opts.wait, Some(Duration::from_secs(30)));
        assert!(parse(&strs(&["restart", "--wait=0"])).is_err());
        assert!(parse(&strs(&["restart", "--wait=3600"])).is_ok());
        assert!(parse(&strs(&["restart", "--wait=3601"])).is_err());
        assert!(parse(&strs(&["restart", "--wait=18446744073709551615"])).is_err());
        assert!(parse(&strs(&["restart", "--wait=soon"])).is_err());
        assert!(parse(&strs(&["restart", "--wait", "--wait"])).is_err());
        assert!(
            parse(&strs(&["stop", "--wait"])).is_err(),
            "stop has nothing to wait for"
        );
        assert!(parse(&strs(&["get", "--wait"])).is_err());
    }

    #[test]
    fn wait_for_attach_needs_systemd_and_the_kernel_to_agree() {
        let kernel = |state: &str, ops: Option<&str>| KernelState {
            state: state.into(),
            ops: ops.map(str::to_owned),
        };
        let no_sleep = |_: Duration| {};
        let long = Duration::from_secs(60);

        // Unit active with the expected process, kernel attaches on the
        // third probe: success.
        let running = Stub::running("scx_lavd", &[]);
        let mut probes = 0;
        wait_for_attach(
            &running,
            "scx_lavd",
            long,
            || {
                probes += 1;
                Ok(Some(if probes < 3 {
                    kernel("disabled", None)
                } else {
                    kernel("enabled", Some("lavd"))
                }))
            },
            no_sleep,
        )
        .unwrap();
        assert_eq!(probes, 3);

        // The kernel says lavd, but the unit is inactive (lavd was
        // started by hand): no confirmation, the unit's state wins.
        let idle = Stub::idle();
        let err = wait_for_attach(
            &idle,
            "scx_lavd",
            long,
            || Ok(Some(kernel("enabled", Some("lavd")))),
            no_sleep,
        )
        .unwrap_err();
        assert!(format!("{err:#}").contains("no longer active"));

        // The kernel says lavd, but the unit's process is bpfland: the
        // attached scheduler is not the unit's. Times out as "did not
        // attach", not as unconfirmed, since the unit does not run it.
        let other = Stub::running("scx_bpfland", &[]);
        let err = wait_for_attach(
            &other,
            "scx_lavd",
            Duration::ZERO,
            || Ok(Some(kernel("enabled", Some("lavd")))),
            no_sleep,
        )
        .unwrap_err();
        assert!(format!("{err:#}").contains("did not attach"));
        assert_eq!(exit_status(&err), 1);

        // Deadline passed, but the names match: the clock ran out, the
        // identity is not in doubt. Exit 1, never 2.
        let err = wait_for_attach(
            &running,
            "scx_lavd",
            Duration::ZERO,
            || Ok(Some(kernel("enabled", Some("lavd")))),
            no_sleep,
        )
        .unwrap_err();
        assert!(format!("{err:#}").contains("did not attach"));
        assert_eq!(exit_status(&err), 1);

        // Unit runs lavd, kernel enabled, ops name unrecognisable: the
        // identity is unconfirmed, exit 2, distinct from failure.
        let err = wait_for_attach(
            &running,
            "scx_lavd",
            Duration::ZERO,
            || Ok(Some(kernel("enabled", Some("fancy_ops_name")))),
            no_sleep,
        )
        .unwrap_err();
        assert!(format!("{err:#}").contains("could not be confirmed"));
        assert_eq!(exit_status(&err), 2);

        // Unit runs lavd, kernel never enables: plain timeout.
        let err = wait_for_attach(
            &running,
            "scx_lavd",
            Duration::ZERO,
            || Ok(Some(kernel("disabled", None))),
            no_sleep,
        )
        .unwrap_err();
        assert!(format!("{err:#}").contains("did not attach"));
        assert_eq!(exit_status(&err), 1);

        // sysfs present but unreadable is not "no sched_ext".
        let err = wait_for_attach(
            &running,
            "scx_lavd",
            long,
            || bail!("permission denied"),
            no_sleep,
        )
        .unwrap_err();
        let text = format!("{err:#}");
        assert!(text.contains("kernel state could not be read"));
        assert!(text.contains("permission denied"));
        assert!(!text.contains("no sched_ext"));
        assert!(
            format!(
                "{:#}",
                wait_for_attach(&running, "scx_lavd", long, || Ok(None), no_sleep).unwrap_err()
            )
            .contains("no sched_ext")
        );

        // A failed unit read after the operation still says it went through.
        let broken = Stub {
            truth: Status::default(),
            calls: RefCell::new(Vec::new()),
            status_broken: true,
            status_reads: RefCell::new(0),
        };
        let err = wait_for_attach(
            &broken,
            "scx_lavd",
            long,
            || Ok(Some(kernel("enabled", Some("lavd")))),
            no_sleep,
        )
        .unwrap_err();
        assert!(format!("{err:#}").contains("systemd accepted the operation"));
    }

    #[test]
    fn without_wait_nothing_is_polled() {
        // The stub counts status reads: start without --wait reads the
        // state for its preconditions only, never in a loop.
        let idle = Stub::idle();
        run_with(&idle, &["start", "-s", "lavd"]).unwrap();
        assert!(*idle.status_reads.borrow() <= 3, "preconditions only");
    }

    #[test]
    fn restart_repins_the_running_configuration_not_the_file() {
        // The file was edited to another scheduler under the running
        // one: restart must bring back what runs, not what the file says.
        let mut stub = Stub::running("scx_lavd", &["--performance", "--pinned-slice-us", "500"]);
        stub.truth.next_sched = Some("scx_bpfland".into());
        stub.truth.next_flags = Vec::new();
        run_with(&stub, &["restart"]).unwrap();
        assert_eq!(
            *stub.calls.borrow(),
            [Call::Switch(
                "scx_lavd".into(),
                strs(&["--performance", "--pinned-slice-us", "500"])
            )]
        );
    }

    #[test]
    fn start_stop_restore_and_read_only_commands() {
        let idle = Stub::idle();
        run_with(&idle, &["start", "-s", "lavd", "-m", "server"]).unwrap();
        run_with(&idle, &["stop"]).unwrap();
        assert_eq!(idle.calls.borrow().len(), 2);
        assert!(matches!(&idle.calls.borrow()[0], Call::Start(s, _) if s == "scx_lavd"));
        assert_eq!(idle.calls.borrow()[1], Call::Stop);
        // No default_sched in the built-in profiles: restore refuses.
        assert!(run_with(&idle, &["restore"]).is_err());
        // Read-only commands never touch the write path.
        run_with(&idle, &["get"]).unwrap();
        run_with(&idle, &["list"]).unwrap();
        run_with(&idle, &["modes", "-s", "lavd", "--show-args"]).unwrap();
        run_with(&idle, &["help"]).unwrap();
        assert_eq!(idle.calls.borrow().len(), 2);
    }

    #[test]
    fn profiles_are_loaded_only_when_a_command_needs_them() {
        let idle = Stub::idle();
        let broken = || -> Result<Profiles> { bail!("profiles file is invalid") };
        let backend = || Ok(Box::new(StubRef(&idle)) as Box<dyn SchedulerBackend + '_>);
        run(&strs(&["stop"]), backend, broken).unwrap();
        run(&strs(&["list"]), backend, broken).unwrap();
        run(&strs(&["help"]), || bail!("no backend either"), broken).unwrap();
        assert!(run(&strs(&["get"]), backend, broken).is_err());
    }
}
