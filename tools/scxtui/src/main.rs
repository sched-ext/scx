// SPDX-License-Identifier: GPL-2.0

#![deny(unsafe_code)]

mod app;
mod backend;
mod cli;
mod kernel;
mod logs;
mod profiles;
mod ui;

use anyhow::{Context, Result, bail};

use app::App;
use backend::SchedulerBackend;
use backend::service::ServiceBackend;
use profiles::Profiles;

const USAGE: &str = "\
scxtui — TUI for managing sched_ext schedulers through scx.service

USAGE:
    scxtui
    scxtui --cli <COMMAND> [OPTIONS]
    scxtui --export-profiles <FILE|->

OPTIONS:
    --cli <COMMAND>             Run one scxctl-style command and exit
                                (get, list, modes, start, switch, stop,
                                restart, restore; --cli help for details)
    --export-profiles <FILE|->  Write the resolved profile table (file rows
                                merged with built-in defaults, for every
                                scheduler systemd can start) as JSON and exit
    -h, --help                  Show this help
    -V, --version               Show the version
";

/// What the command line asked for besides the TUI.
enum Invocation {
    Tui,
    Cli(Vec<String>),
    ExportProfiles(String),
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

    // Backend resolution happens *before* entering raw mode, so failures
    // print as normal error messages instead of garbling the terminal.
    let backend = ServiceBackend::connect()?;
    let profiles = Profiles::load()?;
    if let Invocation::ExportProfiles(target) = invocation {
        return export_profiles(&backend, &profiles, &target);
    }
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
        "--export-profiles" => {
            let target = args
                .next()
                .context("--export-profiles requires a path or -")?;
            return Ok(Invocation::ExportProfiles(target));
        }
        other => match other.strip_prefix("--export-profiles=") {
            Some(target) => return Ok(Invocation::ExportProfiles(target.to_owned())),
            None => bail!("unknown argument: {other}\n\n{USAGE}"),
        },
    }
    std::process::exit(0)
}

/// `--export-profiles`: the resolved table for the schedulers the TUI
/// would list, as JSON, to a file or stdout.
fn export_profiles(backend: &ServiceBackend, profiles: &Profiles, target: &str) -> Result<()> {
    let schedulers = backend.supported_schedulers()?;
    let json = serde_json::to_string_pretty(&profiles.export(&schedulers))?;
    if target == "-" {
        println!("{json}");
    } else {
        std::fs::write(target, format!("{json}\n"))
            .with_context(|| format!("cannot write {target}"))?;
    }
    Ok(())
}
