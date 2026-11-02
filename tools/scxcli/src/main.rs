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
use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::Result;
use scx_catalog::catalog::{DEFAULT_ID, validate_arg, validate_sched, validate_start_id};
use scx_catalog::{Current, Listing, Tier};

const USAGE: &str = "\
scxcli - sched_ext schedulers through scx.service

USAGE:
    scxcli list [--json]              The recommended schedulers and the
                                      current state
    scxcli list recommended [--json]  The same
    scxcli list all [--json]          Every installed scheduler
      --catalog PATH                  List with this catalog file instead
                                      of the installed one
    scxcli get [--json]               Show which scheduler is running
    scxcli start ID                   Start an entry of `list`: a profile
                                      by id, a scheduler from `list all`
                                      with its defaults, or `default` for
                                      the kernel's own (root, or pkexec)
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
    List {
        what: ListWhat,
        json: bool,
        catalog: Option<PathBuf>,
    },
    Get {
        json: bool,
    },
    Start {
        id: Option<String>,
    },
    Stop,
    Run {
        sched: String,
        args: Vec<String>,
    },
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
            // `--json` and `--catalog PATH`, each at most once, in any
            // order. `list` is the one command that takes a catalog of
            // the caller's choosing: it only reads.
            let mut json = false;
            let mut catalog = None;
            let mut rest = rest.iter();
            while let Some(arg) = rest.next() {
                match arg.as_str() {
                    "--json" if !json => json = true,
                    "--catalog" if catalog.is_none() => match rest.next() {
                        Some(path) if !path.is_empty() => catalog = Some(PathBuf::from(path)),
                        _ => return usage("--catalog takes a path"),
                    },
                    other => return usage(format!("unexpected argument {other:?}")),
                }
            }
            Ok(Command::List {
                what,
                json,
                catalog,
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
                validate_start_id(id).map_err(|err| Usage(format!("{err:#}")))?;
                Ok(Command::Start {
                    id: Some(id.clone()),
                })
            }
            _ => usage("start takes at most one id; options go through run or a profile"),
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
        Command::List {
            what,
            json,
            catalog,
        } => {
            let listing = scx_catalog::list_with(catalog.as_deref())?;
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
                Some((path, args)) => {
                    writeln!(out, "started {}", render_started(&started.id, &path, &args))?
                }
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

/// `scx_cosmos: /usr/bin/scx_cosmos`, or for a profile
/// `latency: /usr/bin/scx_eevdf --slice-us 1600`.
fn render_started(id: &str, path: &str, args: &[String]) -> String {
    let mut text = format!("{id}: {path}");
    for arg in args {
        text.push(' ');
        text.push_str(arg);
    }
    text
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
            // The kernel's word as well as the unit's: the process
            // exists before its scheduler is attached.
            let name = scx_catalog::catalog::sched_name(&next.sched);
            let running = current.scheduler.as_deref() == Some(name.as_str())
                && current
                    .running
                    .as_ref()
                    .is_some_and(|r| r.sched == name && r.args == next.args);
            let note = if next.overridden {
                "SCX_*_OVERRIDE in effect"
            } else if running {
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

/// Whether the profile's command is what runs: its scheduler, by the
/// kernel's word, with exactly its options. The unit's file holds the
/// command and not the id, so this is how a profile is told from the
/// others on the same scheduler; of two profiles with one command, both
/// are marked. `default` has no process to compare, it is the kernel's
/// scheduler running and nothing attached.
fn pick_running(pick: &scx_catalog::Pick, current: &Current) -> bool {
    if pick.id == DEFAULT_ID {
        return running_name(current) == Some(DEFAULT_ID);
    }
    let sched = pick.sched.as_deref().unwrap_or(&pick.id);
    running_name(current) == Some(sched)
        && current
            .running
            .as_ref()
            .is_some_and(|r| r.args == pick.args)
}

fn render_recommended(listing: &Listing) -> String {
    let mut text = String::new();
    for pick in &listing.recommended {
        let mark = if pick_running(pick, &listing.current) {
            '*'
        } else if pick.available {
            ' '
        } else {
            '-'
        };
        let command = match &pick.sched {
            Some(sched) => format!("{sched} {}", pick.args.join(" ")),
            None => String::new(),
        };
        text.push_str(&format!(
            "{mark} {:<14} {:<10} {}{}\n",
            pick.id,
            pick.label,
            pick.description,
            if command.is_empty() {
                command
            } else {
                format!(" [{}]", command.trim_end())
            }
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
            if sched.featured { "featured" } else { "" },
            sched.path.display()
        ));
    }
    text.push_str(&format!(
        "\n* running; featured schedulers first, then the other stable ones, experimental \
ones after them, then those the catalog does not name; the catalog from {} hides schedulers \
that need a configuration of their own, which `run` or a profile starts\n",
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
        let list = |what, json| Command::List {
            what,
            json,
            catalog: None,
        };
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
        assert_eq!(
            p(&[
                "list",
                "all",
                "--catalog",
                "./services/catalog.json",
                "--json"
            ])
            .unwrap(),
            Command::List {
                what: ListWhat::All,
                json: true,
                catalog: Some("./services/catalog.json".into()),
            }
        );
        assert_eq!(
            p(&["list", "--json", "--catalog", "c.json"]).unwrap(),
            Command::List {
                what: ListWhat::Recommended,
                json: true,
                catalog: Some("c.json".into()),
            }
        );
        assert!(is_usage(p(&["list", "--catalog"])));
        assert!(is_usage(p(&["list", "--catalog", ""])));
        assert!(is_usage(p(&["list", "--json", "--json"])));
        assert!(is_usage(p(&["list", "--catalog", "a", "--catalog", "b"])));
        // Only `list` takes a catalog: the privileged commands consult
        // the installed one, and the policy covers what that one lists.
        assert!(is_usage(p(&["get", "--catalog", "c.json"])));
        assert!(is_usage(p(&["start", "--catalog", "c.json"])));
        assert!(is_usage(p(&["start", "scx_cosmos", "--catalog", "c.json"])));
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
    fn start_takes_default_one_scheduler_name_or_one_profile_id() {
        // A profile id parses; whether the catalog has it is the
        // start's business, not the parser's.
        assert_eq!(
            p(&["start", "latency"]).unwrap(),
            Command::Start {
                id: Some("latency".into())
            }
        );
        assert_eq!(
            render_started(
                "latency",
                "/usr/bin/scx_eevdf",
                &["--slice-us".into(), "1600".into()]
            ),
            "latency: /usr/bin/scx_eevdf --slice-us 1600"
        );
        assert_eq!(
            render_started("scx_cosmos", "/usr/bin/scx_cosmos", &[]),
            "scx_cosmos: /usr/bin/scx_cosmos"
        );
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
        assert!(is_usage(p(&["start", "Cosmos"])));
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

    /// The running mark goes to the profile whose command runs, not
    /// to every profile on that scheduler, and a custom profile shows
    /// its command.
    #[test]
    fn the_recommended_list_marks_the_profile_whose_command_runs() {
        let json = r#"{"version":2,"source":"/etc/scx/catalog.json","customized":true,
            "recommended":[
                {"id":"default","label":"Default","available":true},
                {"id":"scx_eevdf","label":"EEVDF","path":"/usr/bin/scx_eevdf",
                 "available":true},
                {"id":"latency","label":"Low latency","sched":"scx_eevdf",
                 "args":["--slice-us","1600"],"path":"/usr/bin/scx_eevdf",
                 "available":true}
            ],
            "all":[{"name":"scx_eevdf","path":"/usr/bin/scx_eevdf",
                    "recommended":true,"featured":true,"tier":"stable"}],
            "current":{"version":2,"scheduler":"scx_eevdf",
              "unit":{"active":true,"enabled":true},
              "running":{"sched":"scx_eevdf","args":["--slice-us","1600"]},
              "next":{"sched":"/usr/bin/scx_eevdf","args":["--slice-us","1600"],
                      "override":false},
              "kernel":{"state":"enabled","ops":"eevdf"},"failure":null}}"#;
        let listing: Listing = serde_json::from_str(json).unwrap();
        let text = render_recommended(&listing);
        assert!(text.contains("* latency"), "{text}");
        assert!(text.contains("  scx_eevdf"), "{text}");
        assert!(text.contains("  default"), "{text}");
        assert!(text.contains("[scx_eevdf --slice-us 1600]"), "{text}");
        let all = render_all(&listing);
        assert!(all.contains("featured"), "{all}");

        // `default` runs with no process to compare: the kernel's own
        // scheduler, `running` null. It keeps its mark, and no profile
        // has one.
        let mut stopped = listing.clone();
        stopped.current.scheduler = Some(DEFAULT_ID.into());
        stopped.current.running = None;
        stopped.current.unit.active = false;
        let text = render_recommended(&stopped);
        assert!(text.contains("* default"), "{text}");
        assert!(
            !text.contains("* latency") && !text.contains("* scx_eevdf"),
            "{text}"
        );
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
        // The unit's process is up but the kernel has nothing attached
        // yet: not running, whatever the process says.
        let json = r#"{"version":2,"scheduler":null,
            "unit":{"active":true,"enabled":true},
            "running":{"sched":"scx_cosmos","args":[]},
            "next":{"sched":"/usr/bin/scx_cosmos","args":[],"override":false},
            "kernel":{"state":"disabled","ops":null},"failure":null}"#;
        let current: Current = serde_json::from_str(json).unwrap();
        assert!(
            render_current(&current).contains("configured: /usr/bin/scx_cosmos (not running)\n")
        );

        let json = r#"{"version":2,"scheduler":null,
            "unit":{"active":false,"enabled":false},"running":null,"next":null,
            "kernel":{"state":"enabled","ops":"rusty"},"failure":null}"#;
        let current: Current = serde_json::from_str(json).unwrap();
        assert!(render_current(&current).contains("outside scx.service"));
    }
}
