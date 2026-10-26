// SPDX-License-Identifier: GPL-2.0

//! scxcli: the command-line front end of `scx_profiles`, and the one
//! program that changes what `scx.service` runs. Every other client
//! (scxtui, widgets, scripts) reads through `list` and `get` and writes
//! through `pkexec scxcli apply|profiles|run`.
//!
//! The argument parser is deliberately strict. `apply` takes exactly one
//! valid profile id, `profiles` exactly `save` or `reset`, and nothing
//! takes an option it does not know, because pkexec tells the polkit
//! actions apart by the first argument alone and whatever follows runs
//! as root.

#![deny(unsafe_code)]

use std::io::{IsTerminal, Read, Write};
use std::process::ExitCode;

use anyhow::{Context, Result, bail};
use scx_profiles::profile::{validate_arg, validate_id, validate_sched};
use scx_profiles::{Current, Listing, Profiles};

const USAGE: &str = "\
scxcli - sched_ext scheduling profiles through scx.service

USAGE:
    scxcli list [--json]           List the profiles, the installed
                                   schedulers and the current state
    scxcli list profiles [--json]  The profiles and the current state only
    scxcli list scheds [--json]    The installed schedulers only
    scxcli get [--json]            Show which profile is running
    scxcli apply ID                Apply a profile (root, or pkexec)
    scxcli stop                    Stop the scheduler, keep the applied
                                   profile for the next start (root, or pkexec)
    scxcli start                   Start the applied profile again (root,
                                   or pkexec)
    scxcli profiles save           Replace the profile list with the JSON
                                   on stdin (root, or pkexec)
    scxcli profiles reset          Remove the administrator's list, so the
                                   shipped one is used (root, or pkexec)
    scxcli run SCHED [ARGS...]     Start a scheduler with these options,
                                   outside any profile (root, or pkexec)
    scxcli -h | --help | -V | --version

Exit codes: 0 success, 1 failure, 2 usage, 3 permission denied.
See services/PROFILES.md in the scx repository for the file format and
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
    Apply { id: String },
    Stop,
    Start,
    ProfilesSave,
    ProfilesReset,
    Run { sched: String, args: Vec<String> },
    Help,
    Version,
}

/// What `list` shows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ListWhat {
    All,
    Profiles,
    Scheds,
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
                Some((word, tail)) if word == "profiles" => (ListWhat::Profiles, tail),
                Some((word, tail)) if word == "scheds" => (ListWhat::Scheds, tail),
                _ => (ListWhat::All, rest),
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
            [] => Ok(Command::Start),
            _ => usage("start takes no arguments"),
        },
        "apply" => match rest {
            [id] => {
                validate_id(id).map_err(|err| Usage(format!("{err:#}")))?;
                Ok(Command::Apply { id: id.clone() })
            }
            [] => usage("apply takes a profile id"),
            _ => usage("apply takes exactly one profile id"),
        },
        "profiles" => match rest {
            [verb] if verb == "save" => Ok(Command::ProfilesSave),
            [verb] if verb == "reset" => Ok(Command::ProfilesReset),
            _ => usage("profiles takes exactly one of: save, reset"),
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
            ExitCode::from(if scx_profiles::permission_denied(&err) {
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
        Command::List { what, json } => match what {
            ListWhat::Scheds => {
                let scheds = scx_profiles::installed()?;
                if json {
                    let value: Vec<serde_json::Value> = scheds
                        .iter()
                        .map(|(name, path)| serde_json::json!({ "name": name, "path": path }))
                        .collect();
                    writeln!(
                        out,
                        "{}",
                        serde_json::to_string_pretty(&serde_json::json!({
                            "version": scx_profiles::OUTPUT_VERSION,
                            "schedulers": value,
                        }))?
                    )?;
                } else {
                    write!(out, "{}", render_scheds(&scheds))?;
                }
            }
            ListWhat::All | ListWhat::Profiles => {
                let (listing, scheds) = scx_profiles::list_with_paths()?;
                if json {
                    writeln!(out, "{}", serde_json::to_string_pretty(&listing)?)?;
                } else {
                    write!(out, "{}", render_list(&listing))?;
                    if what == ListWhat::All {
                        write!(out, "\ninstalled schedulers:\n{}", render_scheds(&scheds))?;
                    }
                }
            }
        },
        Command::Get { json } => {
            let current = scx_profiles::current()?;
            if json {
                writeln!(out, "{}", serde_json::to_string_pretty(&current)?)?;
            } else {
                write!(out, "{}", render_current(&current))?;
            }
        }
        Command::Stop => {
            scx_profiles::stop()?;
            writeln!(
                out,
                "scx.service stopped; the applied profile is kept for the next start"
            )?;
        }
        Command::Start => {
            let id = scx_profiles::start()?;
            writeln!(out, "scx.service started with the applied profile {id}")?;
        }
        Command::Apply { id } => {
            let applied = scx_profiles::apply(&id)?;
            match applied.launch {
                Some((sched, args)) => {
                    writeln!(out, "applied {}: {} {}", applied.id, sched, args.join(" "))?
                }
                None => writeln!(out, "applied {}: scx.service stopped", applied.id)?,
            }
        }
        Command::ProfilesSave => {
            let mut text = String::new();
            if std::io::stdin().is_terminal() {
                bail!("profiles save reads a profiles file on stdin");
            }
            std::io::stdin()
                .read_to_string(&mut text)
                .context("cannot read stdin")?;
            let profiles = Profiles::parse(&text)?;
            scx_profiles::save(&profiles)?;
            writeln!(
                out,
                "saved {} profiles to {}",
                profiles.profiles.len(),
                scx_profiles::profile::ADMIN_PATH
            )?;
        }
        Command::ProfilesReset => {
            scx_profiles::reset()?;
            writeln!(
                out,
                "removed {}; the shipped list is in use",
                scx_profiles::profile::ADMIN_PATH
            )?;
        }
        Command::Run { sched, args } => {
            let applied = scx_profiles::run(&sched, &args)?;
            let (path, args) = applied.launch.expect("run always launches");
            writeln!(out, "running {path} {}", args.join(" "))?;
        }
    }
    Ok(())
}

fn render_current(current: &Current) -> String {
    let mut text = String::new();
    let state = match (&current.profile, current.custom) {
        (Some(id), _) => format!("profile {id}"),
        (None, true) => "custom".to_owned(),
        (None, false) => match &current.applied {
            Some(id) => format!("profile {id} applied but not running"),
            None => "nothing applied".to_owned(),
        },
    };
    text.push_str(&format!("state: {state}\n"));
    match &current.running {
        Some(r) => text.push_str(&format!("running: {} {}\n", r.sched, r.args.join(" "))),
        None => text.push_str("running: nothing\n"),
    }
    if let Some(next) = &current.next {
        text.push_str(&format!(
            "next start: {} {}{}\n",
            next.sched,
            next.args.join(" "),
            if next.overridden {
                " (from an SCX_*_OVERRIDE)"
            } else {
                ""
            }
        ));
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

fn render_scheds(scheds: &[(String, std::path::PathBuf)]) -> String {
    if scheds.is_empty() {
        return "  none in systemd's default search path\n".to_owned();
    }
    scheds
        .iter()
        .map(|(name, path)| format!("  {name:<20} {}\n", path.display()))
        .collect()
}

fn render_list(listing: &Listing) -> String {
    let mut text = String::new();
    let running = listing.current.profile.as_deref();
    for entry in &listing.profiles {
        let mark = if Some(entry.id.as_str()) == running {
            '*'
        } else if entry.available {
            ' '
        } else {
            '-'
        };
        let backing = match (&entry.action, &entry.sched) {
            (Some(_), _) => "stop scx.service".to_owned(),
            (None, Some(sched)) => format!("{sched} {}", entry.args.join(" ")),
            _ => String::new(),
        };
        text.push_str(&format!(
            "{mark} {:<12} {:<16} {}\n",
            entry.id,
            entry.label,
            backing.trim_end()
        ));
    }
    text.push_str(&format!(
        "\n* running, - not installed; list from {}{}\n",
        listing.source.display(),
        if listing.customized {
            " (administrator's)"
        } else {
            ""
        }
    ));
    text.push_str(&render_current(&listing.current));
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
        assert_eq!(p(&["list"]).unwrap(), list(ListWhat::All, false));
        assert_eq!(p(&["list", "--json"]).unwrap(), list(ListWhat::All, true));
        assert_eq!(
            p(&["list", "profiles"]).unwrap(),
            list(ListWhat::Profiles, false)
        );
        assert_eq!(
            p(&["list", "scheds", "--json"]).unwrap(),
            list(ListWhat::Scheds, true)
        );
        assert!(is_usage(p(&["list", "modes"])));
        assert!(is_usage(p(&["list", "scheds", "x"])));
        assert_eq!(p(&["get", "--json"]).unwrap(), Command::Get { json: true });
        assert_eq!(p(&["stop"]).unwrap(), Command::Stop);
        assert_eq!(p(&["start"]).unwrap(), Command::Start);
        assert!(is_usage(p(&["stop", "now"])));
        assert!(is_usage(p(&["start", "gaming"])));
        assert_eq!(p(&["--help"]).unwrap(), Command::Help);
        assert_eq!(p(&["-V"]).unwrap(), Command::Version);
        assert!(is_usage(p(&[])));
        assert!(is_usage(p(&["list", "--jsonx"])));
        assert!(is_usage(p(&["get", "--json", "x"])));
        assert!(is_usage(p(&["status"])));
    }

    #[test]
    fn apply_takes_exactly_one_valid_id() {
        assert_eq!(
            p(&["apply", "gaming"]).unwrap(),
            Command::Apply {
                id: "gaming".into()
            }
        );
        assert!(is_usage(p(&["apply"])));
        assert!(is_usage(p(&["apply", "gaming", "server"])));
        assert!(is_usage(p(&["apply", "--json"])));
        assert!(is_usage(p(&["apply", "Gaming"])));
        assert!(is_usage(p(&["apply", "../etc"])));
        assert!(is_usage(p(&["apply", "a b"])));
        assert!(is_usage(p(&["apply", ""])));
    }

    #[test]
    fn profiles_takes_save_or_reset_only() {
        assert_eq!(p(&["profiles", "save"]).unwrap(), Command::ProfilesSave);
        assert_eq!(p(&["profiles", "reset"]).unwrap(), Command::ProfilesReset);
        assert!(is_usage(p(&["profiles"])));
        assert!(is_usage(p(&["profiles", "edit"])));
        assert!(is_usage(p(&["profiles", "save", "file.json"])));
        assert!(is_usage(p(&["profiles", "reset", "--force"])));
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
        let json = r#"{"version":1,"profile":null,"applied":"gaming","custom":false,
            "unit":{"active":false,"enabled":true},"running":null,
            "next":{"sched":"/usr/bin/scx_lavd","args":["--performance"],"override":false},
            "kernel":{"state":"disabled","ops":null},
            "failure":{"message":"boom","status":"exit-code/1"}}"#;
        let current: Current = serde_json::from_str(json).unwrap();
        let text = render_current(&current);
        assert!(text.contains("profile gaming applied but not running"));
        assert!(text.contains("last start failed (exit-code/1): boom"));
        assert!(text.contains("next start: /usr/bin/scx_lavd --performance\n"));
    }
}
