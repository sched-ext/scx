// SPDX-License-Identifier: GPL-2.0

#![deny(unsafe_code)]

mod app;
mod backend;
mod kernel;
mod logs;
mod model;
mod system;
mod ui;
mod watch;

use std::path::PathBuf;

use anyhow::{Result, bail};

use app::App;
use backend::scxcli::ScxcliBackend;

const USAGE: &str = "\
scxtui - TUI for sched_ext schedulers, through scxcli and scx.service

USAGE:
    scxtui [--catalog PATH]

OPTIONS:
    --catalog PATH   List with this catalog file instead of the installed
                     one (a checkout's services/catalog.json, say); starting
                     still goes by the installed catalog
    -h, --help       Show this help
    -V, --version    Show the version

scxtui runs as a normal user. Starting a scheduler goes through
`pkexec scxcli start`, which with the shipped policy needs no password;
starting one with options asks for an administrator's. For scripts, use
scxcli directly.
";

/// What the command line asks for.
#[derive(Debug, PartialEq, Eq)]
enum Invocation {
    Run { catalog: Option<PathBuf> },
    Help,
    Version,
}

fn parse(args: &[String]) -> Result<Invocation> {
    let mut catalog = None;
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-h" | "--help" => return Ok(Invocation::Help),
            "-V" | "--version" => return Ok(Invocation::Version),
            "--catalog" if catalog.is_none() => match args.next() {
                Some(path) if !path.is_empty() => catalog = Some(PathBuf::from(path)),
                _ => bail!("--catalog takes a path\n\n{USAGE}"),
            },
            other => bail!("unknown argument: {other}\n\n{USAGE}"),
        }
    }
    Ok(Invocation::Run { catalog })
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let catalog = match parse(&args)? {
        Invocation::Help => {
            print!("{USAGE}");
            return Ok(());
        }
        Invocation::Version => {
            println!("scxtui {}", env!("CARGO_PKG_VERSION"));
            return Ok(());
        }
        Invocation::Run { catalog } => catalog,
    };

    // Backend resolution happens before entering raw mode, so failures
    // print as normal error messages instead of garbling the terminal.
    let preview = catalog.is_some();
    let backend = ScxcliBackend::connect(catalog)?;
    let warning = backend.policy_mismatch();
    let mut app = App::new(Box::new(backend));
    app.preview_catalog = preview;
    if let Some(text) = warning {
        app.warn(&text);
    }

    let terminal = ratatui::init();
    let result = app.run(terminal);
    ratatui::restore();
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_command_line_takes_a_catalog_and_nothing_else() {
        let args = |list: &[&str]| list.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
        assert_eq!(
            parse(&args(&[])).unwrap(),
            Invocation::Run { catalog: None }
        );
        assert_eq!(
            parse(&args(&["--catalog", "./services/catalog.json"])).unwrap(),
            Invocation::Run {
                catalog: Some("./services/catalog.json".into())
            }
        );
        assert_eq!(parse(&args(&["--help"])).unwrap(), Invocation::Help);
        assert_eq!(parse(&args(&["-V"])).unwrap(), Invocation::Version);
        assert!(parse(&args(&["--catalog"])).is_err());
        assert!(parse(&args(&["--catalog", ""])).is_err());
        assert!(parse(&args(&["--catalog", "a", "--catalog", "b"])).is_err());
        assert!(parse(&args(&["--cli", "get"])).is_err());
    }
}
