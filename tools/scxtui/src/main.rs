// SPDX-License-Identifier: GPL-2.0

#![deny(unsafe_code)]

mod app;
mod backend;
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
    scxtui --export-profiles <FILE|->

OPTIONS:
    --export-profiles <FILE|->  Write the resolved profile table (file rows
                                merged with built-in defaults, for every
                                scheduler in PATH) as JSON and exit
    -h, --help                  Show this help
    -V, --version               Show the version
";

fn main() -> Result<()> {
    let export = parse_args()?;

    // Backend resolution happens *before* entering raw mode, so failures
    // print as normal error messages instead of garbling the terminal.
    let backend = ServiceBackend::connect()?;
    let profiles = Profiles::load()?;
    if let Some(target) = export {
        return export_profiles(&backend, &profiles, &target);
    }
    let mut app = App::new(Box::new(backend), profiles)?;

    let terminal = ratatui::init();
    let result = app.run(terminal);
    ratatui::restore();
    result
}

/// Returns the `--export-profiles` target when given. The informational
/// flags end the process here.
fn parse_args() -> Result<Option<String>> {
    let mut args = std::env::args().skip(1);
    let Some(arg) = args.next() else {
        return Ok(None);
    };
    match arg.as_str() {
        "-h" | "--help" => print!("{USAGE}"),
        "-V" | "--version" => println!("scxtui {}", env!("CARGO_PKG_VERSION")),
        "--export-profiles" => {
            let target = args
                .next()
                .context("--export-profiles requires a path or -")?;
            return Ok(Some(target));
        }
        other => match other.strip_prefix("--export-profiles=") {
            Some(target) => return Ok(Some(target.to_owned())),
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
