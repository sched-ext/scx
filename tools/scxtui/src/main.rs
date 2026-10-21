// SPDX-License-Identifier: GPL-2.0

#![deny(unsafe_code)]

mod app;
mod backend;
mod cli;
mod kernel;
mod logs;
mod profiles;
mod ui;

use std::path::Path;

use anyhow::{Context, Result, bail};

use app::App;
use backend::SchedulerBackend;
use backend::service::{ServiceBackend, replace_file};
use profiles::{ExportFormat, Profiles};

const USAGE: &str = "\
scxtui — TUI for managing sched_ext schedulers through scx.service

USAGE:
    scxtui
    scxtui --cli <COMMAND> [OPTIONS]
    scxtui --export-profiles [FILE|-] [--format <json|toml>] [--builtin]

OPTIONS:
    --cli <COMMAND>             Run one scxctl-style command and exit
                                (get, list, modes, start, switch, stop,
                                restart, restore; --cli help for details)
    --export-profiles [FILE|-]  Write the resolved profile table and exit:
                                the profiles file's rows over the built-in
                                defaults, for every scheduler either names
                                or systemd can start (default: stdout)
        --format <json|toml>    json (default): every row filled in, for
                                scripts; toml: the profiles file's own
                                schema, loadable as one
        --builtin               The built-in table alone: ignore any
                                profiles file and do not consult systemd
    -h, --help                  Show this help
    -V, --version               Show the version
";

/// What the command line asked for besides the TUI.
enum Invocation {
    Tui,
    Cli(Vec<String>),
    ExportProfiles(Export),
}

/// `--export-profiles` and its options.
struct Export {
    /// Output path, `-` for stdout.
    target: String,
    format: ExportFormat,
    /// Built-in table only: no profiles file, no backend.
    builtin: bool,
}

fn main() -> Result<()> {
    let invocation = parse_args()?;

    if let Invocation::Cli(args) = invocation {
        // The CLI connects and loads profiles only as the command needs
        // them (help needs neither, stop needs no profiles), and a CLI
        // error is a one-line diagnostic, as scxctl prints it, not
        // anyhow's report with a backtrace.
        let backend = || Ok(Box::new(ServiceBackend::connect()?) as Box<dyn SchedulerBackend>);
        if let Err(err) = cli::run(&args, backend, Profiles::load) {
            eprintln!("error: {err:#}");
            std::process::exit(cli::exit_status(&err));
        }
        return Ok(());
    }

    if let Invocation::ExportProfiles(export) = invocation {
        return export_profiles(&export);
    }

    // Backend resolution happens *before* entering raw mode, so failures
    // print as normal error messages instead of garbling the terminal.
    let backend = ServiceBackend::connect()?;
    let profiles = Profiles::load()?;
    let mut app = App::new(Box::new(backend), profiles)?;

    let terminal = ratatui::init();
    let result = app.run(terminal);
    ratatui::restore();
    result
}

/// The informational flags end the process here; everything else is
/// handed back for dispatch after the backend is up.
fn parse_args() -> Result<Invocation> {
    let mut args = std::env::args().skip(1);
    let Some(arg) = args.next() else {
        return Ok(Invocation::Tui);
    };
    match arg.as_str() {
        "-h" | "--help" => print!("{USAGE}"),
        "-V" | "--version" => println!("scxtui {}", env!("CARGO_PKG_VERSION")),
        "--cli" => return Ok(Invocation::Cli(args.collect())),
        "--export-profiles" => return parse_export(None, args),
        other => match other.strip_prefix("--export-profiles=") {
            Some(target) => return parse_export(Some(target.to_owned()), args),
            None => bail!("unknown argument: {other}\n\n{USAGE}"),
        },
    }
    std::process::exit(0)
}

/// The options after `--export-profiles`. The target is the first
/// argument that is not an option, so `--export-profiles --builtin`
/// writes to stdout and `--export-profiles out.toml --format toml` to
/// the file; `-` is stdout explicitly.
fn parse_export(target: Option<String>, args: impl Iterator<Item = String>) -> Result<Invocation> {
    let mut export = Export {
        target: target.unwrap_or_default(),
        format: ExportFormat::Json,
        builtin: false,
    };
    let mut format_given = false;
    let mut args = args;
    while let Some(arg) = args.next() {
        let (key, inline) = match arg.split_once('=') {
            Some((key, value)) if key.starts_with("--") => (key, Some(value.to_owned())),
            _ => (arg.as_str(), None),
        };
        match key {
            "--format" => {
                if format_given {
                    bail!("--format given more than once");
                }
                format_given = true;
                let value = match inline {
                    Some(value) => value,
                    None => args.next().context("--format requires json or toml")?,
                };
                export.format = ExportFormat::parse(&value)
                    .with_context(|| format!("unknown export format {value:?} (json, toml)"))?;
            }
            "--builtin" => {
                if inline.is_some() {
                    bail!("--builtin takes no value");
                }
                if export.builtin {
                    bail!("--builtin given more than once");
                }
                export.builtin = true;
            }
            _ if key.starts_with("--") => {
                bail!("unknown argument: {key}\n\n{USAGE}");
            }
            _ if export.target.is_empty() => export.target = arg,
            _ => bail!(
                "--export-profiles takes one output path, got {arg:?} after {:?}",
                export.target
            ),
        }
    }
    if export.target.is_empty() {
        export.target = "-".to_owned();
    }
    Ok(Invocation::ExportProfiles(export))
}

/// `--export-profiles`: the resolved table, as JSON or TOML, to a file
/// or stdout. `--builtin` needs neither a profiles file nor systemd, so
/// it works on a machine without scx.service; the full export also
/// covers the installed schedulers, which takes the backend.
fn export_profiles(export: &Export) -> Result<()> {
    let (profiles, installed) = if export.builtin {
        (Profiles::default(), Vec::new())
    } else {
        let backend = ServiceBackend::connect()?;
        (Profiles::load()?, backend.supported_schedulers()?)
    };
    let text = match export.format {
        ExportFormat::Json => {
            format!(
                "{}\n",
                serde_json::to_string_pretty(&profiles.export(&installed, export.builtin))?
            )
        }
        ExportFormat::Toml => profiles.export_toml(&installed)?,
    };
    if export.target == "-" {
        print!("{text}");
    } else {
        replace_file(Path::new(&export.target), &text)
            .with_context(|| format!("cannot write {}", export.target))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn export(args: &[&str]) -> Result<Export> {
        let args = args.iter().map(|s| (*s).to_owned());
        match parse_export(None, args)? {
            Invocation::ExportProfiles(export) => Ok(export),
            _ => unreachable!("parse_export yields an export"),
        }
    }

    #[test]
    fn export_options_parse_in_any_order_and_default_to_stdout_json() {
        let e = export(&[]).unwrap();
        assert_eq!(
            (e.target.as_str(), e.format, e.builtin),
            ("-", ExportFormat::Json, false)
        );
        let e = export(&["out.toml", "--format", "toml"]).unwrap();
        assert_eq!(
            (e.target.as_str(), e.format),
            ("out.toml", ExportFormat::Toml)
        );
        let e = export(&["--builtin", "--format=toml", "out.toml"]).unwrap();
        assert_eq!(
            (e.target.as_str(), e.format, e.builtin),
            ("out.toml", ExportFormat::Toml, true)
        );
        // `--builtin` alone is not a path: stdout, as the usage says.
        let e = export(&["--builtin"]).unwrap();
        assert_eq!((e.target.as_str(), e.builtin), ("-", true));
        // An inline target from --export-profiles=FILE survives the rest.
        let Invocation::ExportProfiles(e) =
            parse_export(Some("p.json".into()), std::iter::empty()).unwrap()
        else {
            unreachable!()
        };
        assert_eq!(e.target, "p.json");
    }

    #[test]
    fn export_options_reject_what_they_cannot_mean() {
        assert!(export(&["--format", "yaml"]).is_err());
        assert!(export(&["--format"]).is_err());
        assert!(export(&["--format=toml", "--format=json"]).is_err());
        assert!(export(&["--builtin=yes"]).is_err());
        assert!(export(&["--builtin", "--builtin"]).is_err());
        assert!(export(&["a", "b"]).is_err(), "two output paths");
        assert!(export(&["--bogus"]).is_err());
    }
}
