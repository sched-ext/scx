// SPDX-License-Identifier: GPL-2.0

//! scxcli: the command-line front end of `scx_catalog`, and the one
//! program that changes what `scx.service` runs. Every other client
//! (scxtui, widgets, scripts) reads through `list` and `get` and writes
//! through `pkexec scxcli start|stop|run`.
//!
//! The argument parser is deliberately strict. `start` takes at most
//! one scheduler name, `stop` nothing, and nothing takes an option it
//! does not know, because pkexec tells the polkit actions apart by the
//! first argument alone and whatever follows runs as root.

#![deny(unsafe_code)]

use std::io::Write;
use std::process::ExitCode;

use anyhow::Result;
use scx_catalog::catalog::{DEFAULT_ID, validate_arg, validate_name, validate_sched};
use scx_catalog::{Current, Listing, Tier};

const USAGE: &str = "\
scxcli - sched_ext schedulers through scx.service

USAGE:
    scxcli list [--json]              The recommended schedulers and the
                                      current state
    scxcli list recommended [--json]  The same
    scxcli list all [--json]          Every installed scheduler
    scxcli get [--json]               Show which scheduler is running
    scxcli start SCHED                Start a scheduler from `list all` with
                                      its defaults, or `default` for the
                                      kernel's own (root, or pkexec)
    scxcli start                      Start the selected scheduler again
                                      after `stop` (root, or pkexec)
    scxcli stop                       Stop the scheduler, keep the selection
                                      for the next start (root, or pkexec)
    scxcli run SCHED [ARGS...]        Start a scheduler with these options
                                      (root, or pkexec)
    scxcli -h | --help | -V | --version

Exit codes: 0 success, 1 failure, 2 usage, 3 permission denied.
See services/CATALOG.md in the scx repository for the file format and
the JSON output.
";

/// Process exit codes, part of the contract.
const EXIT_FAILURE: u8 = 1;
const EXIT_USAGE: u8 = 2;
const EXIT_PERMISSION: u8 = 3;

#[derive(Debug, Clone, PartialEq, Eq)]
enum Command {
    List { what: ListWhat, json: bool },
    Get { json: bool },
    Start { id: Option<String> },
    Stop,
    Run { sched: String, args: Vec<String> },
    Help,
    Version,
}

/// What `list` shows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ListWhat {
    Recommended,
    All,
}

/// A usage error: wrong arguments, exit code 2.
#[derive(Debug)]
struct Usage(String);

impl std::fmt::Display for Usage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Usage {}

fn usage<T>(msg: impl Into<String>) -> Result<T> {
    Err(Usage(msg.into()).into())
}

/// Parses `argv[1..]`.
fn parse(args: &[String]) -> Result<Command> {
    let Some((command, rest)) = args.split_first() else {
        return usage("missing command");
    };
    let only_json = |rest: &[String]| -> Result<bool> {
        match rest {
            [] => Ok(false),
            [flag] if flag == "--json" => Ok(true),
            [other, ..] => usage(format!("unexpected argument {other:?}")),
        }
    };
    match command.as_str() {
        "list" => {
            let (what, rest) = match rest.split_first() {
                Some((word, tail)) if word == "recommended" => (ListWhat::Recommended, tail),
                Some((word, tail)) if word == "all" => (ListWhat::All, tail),
                _ => (ListWhat::Recommended, rest),
            };
            Ok(Command::List {
                what,
                json: only_json(rest)?,
            })
        }
        "get" => Ok(Command::Get {
            json: only_json(rest)?,
        }),
        "stop" => match rest {
            [] => Ok(Command::Stop),
            _ => usage("stop takes no arguments"),
        },
        "start" => match rest {
            [] => Ok(Command::Start { id: None }),
            [id] => {
                if id != DEFAULT_ID {
                    validate_name(id).map_err(|err| Usage(format!("{err:#}")))?;
                }
                Ok(Command::Start {
                    id: Some(id.clone()),
                })
            }
            _ => usage("start takes at most one scheduler name; options go through run"),
        },
        "run" => match rest {
            [] => usage("run takes a scheduler"),
            [sched, args @ ..] => {
                validate_sched(sched).map_err(|err| Usage(format!("{err:#}")))?;
                for arg in args {
                    validate_arg(arg).map_err(|err| Usage(format!("{err:#}")))?;
                }
                Ok(Command::Run {
                    sched: sched.clone(),
                    args: args.to_vec(),
                })
            }
        },
        "-h" | "--help" | "help" => Ok(Command::Help),
        "-V" | "--version" => Ok(Command::Version),
        other => usage(format!("unknown command {other:?}")),
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let command = match parse(&args) {
        Ok(command) => command,
        Err(err) => {
            eprintln!("scxcli: {err:#}\n\n{USAGE}");
            return ExitCode::from(EXIT_USAGE);
        }
    };
    match execute(command) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("scxcli: {err:#}");
            ExitCode::from(if scx_catalog::permission_denied(&err) {
                EXIT_PERMISSION
            } else {
                EXIT_FAILURE
            })
        }
    }
}

fn execute(command: Command) -> Result<()> {
    let mut out = std::io::stdout().lock();
    match command {
        Command::Help => write!(out, "{USAGE}")?,
        Command::Version => writeln!(out, "scxcli {}", env!("CARGO_PKG_VERSION"))?,
        Command::List { what, json } => {
            let listing = scx_catalog::list()?;
            if json {
                writeln!(out, "{}", serde_json::to_string_pretty(&listing)?)?;
            } else {
                match what {
                    ListWhat::Recommended => write!(out, "{}", render_recommended(&listing))?,
                    ListWhat::All => write!(out, "{}", render_all(&listing))?,
                }
                write!(out, "{}", render_current(&listing.current))?;
            }
        }
        Command::Get { json } => {
            let current = scx_catalog::current()?;
            if json {
                writeln!(out, "{}", serde_json::to_string_pretty(&current)?)?;
            } else {
                write!(out, "{}", render_current(&current))?;
            }
        }
        Command::Stop => {
            scx_catalog::stop()?;
            writeln!(
                out,
                "scx.service stopped; the selected scheduler is kept for the next start"
            )?;
        }
        Command::Start { id: None } => {
            let name = scx_catalog::resume()?;
            writeln!(out, "scx.service started with {name}")?;
        }
        Command::Start { id: Some(id) } => {
            let started = scx_catalog::start(&id)?;
            match started.launch {
                Some((path, _)) => writeln!(out, "started {}: {path}", started.id)?,
                None => writeln!(out, "default: scx.service stopped and disabled")?,
            }
        }
        Command::Run { sched, args } => {
            let started = scx_catalog::run(&sched, &args)?;
            let (path, args) = started.launch.expect("run always launches");
            writeln!(out, "running {path} {}", args.join(" "))?;
        }
    }
    Ok(())
}

fn render_current(current: &Current) -> String {
    let mut text = String::new();
    let state = match current.scheduler.as_deref() {
        Some(DEFAULT_ID) => "default (kernel scheduler)".to_owned(),
        Some(name) => format!("{name} running"),
        None if current.attached() => "a scheduler is attached outside scx.service".to_owned(),
        None => "scx.service is active, nothing attached yet".to_owned(),
    };
    text.push_str(&format!("state: {state}\n"));
    match &current.running {
        Some(r) => text.push_str(&format!("running: {} {}\n", r.sched, r.args.join(" "))),
        None => text.push_str("running: nothing\n"),
    }
    // What the configuration says the unit runs, and whether that is
    // what runs now: one line, since the file and the next start are
    // the same thing unless an override is in effect. An environment
    // that did not resolve is unknown, not "nothing": `next` may be
    // what a partial read found. The last failed start is reported on
    // its own line below and not pinned on this configuration, which
    // may not be the one that failed.
    match (&current.config_error, &current.next) {
        (Some(_), _) => text.push_str("configured: unknown\n"),
        (None, Some(next)) => {
            let what = format!("{} {}", next.sched, next.args.join(" "));
            let what = what.trim_end();
            let note = if next.overridden {
                "SCX_*_OVERRIDE in effect"
            } else if current.running.as_ref().is_some_and(|r| {
                scx_catalog::catalog::sched_name(&next.sched) == r.sched && r.args == next.args
            }) {
                "running"
            } else {
                "not running"
            };
            text.push_str(&format!("configured: {what} ({note})\n"));
        }
        (None, None) => text.push_str("configured: nothing\n"),
    }
    match &current.kernel {
        Some(k) => text.push_str(&format!(
            "kernel: {} {}\n",
            k.state,
            k.ops.as_deref().unwrap_or("(nothing attached)")
        )),
        None => text.push_str("kernel: no sched_ext\n"),
    }
    if let Some(f) = &current.failure {
        text.push_str(&format!(
            "last start failed ({}): {}\n",
            f.status, f.message
        ));
    }
    if let Some(err) = &current.config_error {
        text.push_str(&format!("warning: {err}\n"));
    }
    text
}

/// The name a running scheduler is marked by in the lists: the entry
/// whose scheduler runs, or `default` while the kernel's own does.
fn running_name(current: &Current) -> Option<&str> {
    current.scheduler.as_deref()
}

fn render_recommended(listing: &Listing) -> String {
    let mut text = String::new();
    let running = running_name(&listing.current);
    for pick in &listing.recommended {
        let mark = if Some(pick.id.as_str()) == running {
            '*'
        } else if pick.available {
            ' '
        } else {
            '-'
        };
        text.push_str(&format!(
            "{mark} {:<14} {:<10} {}\n",
            pick.id, pick.label, pick.description
        ));
    }
    text.push_str(&format!(
        "\n* running, - not installed; catalog from {}{}\n",
        listing.source.display(),
        if listing.customized {
            " (administrator's)"
        } else {
            ""
        }
    ));
    text
}

fn render_all(listing: &Listing) -> String {
    let mut text = String::new();
    let running = running_name(&listing.current);
    if listing.all.is_empty() {
        text.push_str("  no scheduler in systemd's default search path\n");
    }
    for sched in &listing.all {
        let mark = if Some(sched.name.as_str()) == running {
            '*'
        } else {
            ' '
        };
        text.push_str(&format!(
            "{mark} {:<20} {:<13} {:<12} {}\n",
            sched.name,
            match sched.tier {
                Tier::Stable => "stable",
                Tier::Experimental => "experimental",
                Tier::Unknown => "unknown",
            },
            if sched.recommended { "recommended" } else { "" },
            sched.path.display()
        ));
    }
    text.push_str(&format!(
        "\n* running; stable schedulers first, experimental ones after them, then those the \
catalog does not name; the catalog from {} hides schedulers that need a configuration of \
their own, which `run` starts\n",
        listing.source.display()
    ));
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(args: &[&str]) -> Result<Command> {
        parse(&args.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>())
    }

    fn is_usage(result: Result<Command>) -> bool {
        result.is_err_and(|err| err.downcast_ref::<Usage>().is_some())
    }

    #[test]
    fn reads_and_help_parse() {
        let list = |what, json| Command::List { what, json };
        assert_eq!(p(&["list"]).unwrap(), list(ListWhat::Recommended, false));
        assert_eq!(
            p(&["list", "--json"]).unwrap(),
            list(ListWhat::Recommended, true)
        );
        assert_eq!(
            p(&["list", "recommended"]).unwrap(),
            list(ListWhat::Recommended, false)
        );
        assert_eq!(
            p(&["list", "all", "--json"]).unwrap(),
            list(ListWhat::All, true)
        );
        assert!(is_usage(p(&["list", "profiles"])));
        assert!(is_usage(p(&["list", "all", "x"])));
        assert_eq!(p(&["get", "--json"]).unwrap(), Command::Get { json: true });
        assert_eq!(p(&["stop"]).unwrap(), Command::Stop);
        assert!(is_usage(p(&["stop", "now"])));
        assert_eq!(p(&["--help"]).unwrap(), Command::Help);
        assert_eq!(p(&["-V"]).unwrap(), Command::Version);
        assert!(is_usage(p(&[])));
        assert!(is_usage(p(&["list", "--jsonx"])));
        assert!(is_usage(p(&["get", "--json", "x"])));
        assert!(is_usage(p(&["status"])));
        assert!(is_usage(p(&["apply", "gaming"])));
    }

    #[test]
    fn start_takes_default_or_one_scheduler_name() {
        assert_eq!(p(&["start"]).unwrap(), Command::Start { id: None });
        assert_eq!(
            p(&["start", "scx_cosmos"]).unwrap(),
            Command::Start {
                id: Some("scx_cosmos".into())
            }
        );
        assert_eq!(
            p(&["start", "default"]).unwrap(),
            Command::Start {
                id: Some("default".into())
            }
        );
        assert!(is_usage(p(&["start", "scx_cosmos", "scx_lavd"])));
        assert!(is_usage(p(&["start", "scx_lavd", "--performance"])));
        assert!(is_usage(p(&["start", "--json"])));
        assert!(is_usage(p(&["start", "cosmos"])));
        assert!(is_usage(p(&["start", "/usr/bin/scx_cosmos"])));
        assert!(is_usage(p(&["start", "../etc"])));
        assert!(is_usage(p(&["start", "a b"])));
        assert!(is_usage(p(&["start", ""])));
    }

    #[test]
    fn run_validates_the_scheduler_and_every_option() {
        assert_eq!(
            p(&["run", "scx_lavd", "--performance", "-s", "500"]).unwrap(),
            Command::Run {
                sched: "scx_lavd".into(),
                args: vec!["--performance".into(), "-s".into(), "500".into()]
            }
        );
        assert_eq!(
            p(&["run", "/usr/bin/scx_lavd"]).unwrap(),
            Command::Run {
                sched: "/usr/bin/scx_lavd".into(),
                args: Vec::new()
            }
        );
        assert!(is_usage(p(&["run"])));
        assert!(is_usage(p(&["run", "lavd"])));
        assert!(is_usage(p(&["run", "/tmp/scx_lavd"])));
        assert!(is_usage(p(&["run", "scx_lavd", "-s 500"])));
        assert!(is_usage(p(&["run", "scx_lavd", "$(id)"])));
        assert!(is_usage(p(&["run", "scx_lavd", "--name=it's"])));
    }

    #[test]
    fn text_output_names_the_state() {
        let json = r#"{"version":2,"scheduler":"default",
            "unit":{"active":false,"enabled":true},"running":null,
            "next":{"sched":"/usr/bin/scx_cosmos","args":[],"override":false},
            "kernel":{"state":"disabled","ops":null},
            "failure":{"message":"boom","status":"exit-code/1"}}"#;
        let current: Current = serde_json::from_str(json).unwrap();
        let text = render_current(&current);
        assert!(text.contains("state: default (kernel scheduler)\n"));
        // The failure is the unit's last run, not necessarily this
        // configuration's: it gets its own line and no verdict here.
        assert!(text.contains("configured: /usr/bin/scx_cosmos (not running)\n"));
        assert!(!text.contains("failed to start"));
        assert!(text.contains("last start failed (exit-code/1): boom"));

        // An environment that did not resolve is unknown, even when a
        // partial read produced a `next`.
        let json = r#"{"version":2,"scheduler":"default",
            "unit":{"active":false,"enabled":true},"running":null,
            "next":{"sched":"/usr/bin/scx_cosmos","args":[],"override":false},
            "kernel":{"state":"disabled","ops":null},"failure":null,
            "config_error":"/etc/scx/local is unreadable"}"#;
        let current: Current = serde_json::from_str(json).unwrap();
        let text = render_current(&current);
        assert!(text.contains("configured: unknown\n"), "{text}");
        assert!(!text.contains("configured: /usr/bin"));
        assert!(text.contains("warning: /etc/scx/local is unreadable"));

        let json = r#"{"version":2,"scheduler":"scx_cosmos",
            "unit":{"active":true,"enabled":true},
            "running":{"sched":"scx_cosmos","args":[]},
            "next":{"sched":"/usr/bin/scx_cosmos","args":[],"override":false},
            "kernel":{"state":"enabled","ops":"cosmos"},"failure":null}"#;
        let current: Current = serde_json::from_str(json).unwrap();
        assert!(render_current(&current).contains("configured: /usr/bin/scx_cosmos (running)\n"));

        let json = r#"{"version":2,"scheduler":null,
            "unit":{"active":false,"enabled":false},"running":null,"next":null,
            "kernel":{"state":"enabled","ops":"rusty"},"failure":null}"#;
        let current: Current = serde_json::from_str(json).unwrap();
        assert!(render_current(&current).contains("outside scx.service"));
    }
}
