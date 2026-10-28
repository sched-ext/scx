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

use anyhow::{Result, bail};

use app::App;
use backend::scxcli::ScxcliBackend;

const USAGE: &str = "\
scxtui - TUI for sched_ext schedulers, through scxcli and scx.service

USAGE:
    scxtui

OPTIONS:
    -h, --help       Show this help
    -V, --version    Show the version

scxtui runs as a normal user. Starting a scheduler goes through
`pkexec scxcli start`, which with the shipped policy needs no password;
starting one with options asks for an administrator's. For scripts, use
scxcli directly.
";

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        None => {}
        Some("-h" | "--help") => {
            print!("{USAGE}");
            return Ok(());
        }
        Some("-V" | "--version") => {
            println!("scxtui {}", env!("CARGO_PKG_VERSION"));
            return Ok(());
        }
        Some(other) => bail!("unknown argument: {other}\n\n{USAGE}"),
    }

    // Backend resolution happens before entering raw mode, so failures
    // print as normal error messages instead of garbling the terminal.
    let backend = ScxcliBackend::connect()?;
    let warning = backend.policy_mismatch();
    let mut app = App::new(Box::new(backend));
    if let Some(text) = warning {
        app.warn(&text);
    }

    let terminal = ratatui::init();
    let result = app.run(terminal);
    ratatui::restore();
    result
}
