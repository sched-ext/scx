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
scxtui - TUI for sched_ext scheduling profiles, through scxcli and scx.service

USAGE:
    scxtui

OPTIONS:
    -h, --help       Show this help
    -V, --version    Show the version

scxtui runs as a normal user. Applying a profile goes through
`pkexec scxcli apply`, which with the shipped policy needs no password;
editing the list or starting a scheduler outside a profile asks for an
administrator's. For scripts, use scxcli directly.
";

/// scxctl-style commands the removed `--cli` used to take, mapped to
/// the scxcli command that replaces each. Printed instead of acting, for
/// one release, so an old script fails with a pointer rather than a
/// parse error.
fn cli_pointer(args: &[String]) -> String {
    let command = args.first().map(String::as_str).unwrap_or("");
    let replacement = match command {
        "get" => "scxcli get [--json]",
        "list" | "modes" => "scxcli list [--json]",
        "start" | "switch" => {
            "scxcli apply ID, or scxcli run SCHED [ARGS...] for a scheduler outside a profile"
        }
        "stop" => "scxcli stop (keeps the applied profile), or scxcli apply default",
        "restart" => {
            "scxcli apply ID (applying restarts the unit), or systemctl restart scx.service"
        }
        "restore" => "scxcli apply ID",
        _ => "scxcli --help",
    };
    format!(
        "scxtui --cli was removed; profiles are managed by scxcli. For `{}` use: {replacement}",
        args.join(" ")
    )
}

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
        Some("--cli") => {
            eprintln!("{}", cli_pointer(&args[1..]));
            std::process::exit(2);
        }
        Some(other) if other.starts_with("--export-profiles") => {
            bail!(
                "--export-profiles was removed; the profile list is /usr/share/scx/profiles.json \
(or /etc/scx/profiles.json), and `scxcli list --json` prints it resolved"
            );
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_cli_pointer_names_the_replacement() {
        let args = |list: &[&str]| list.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
        assert!(cli_pointer(&args(&["get", "--json"])).contains("scxcli get"));
        assert!(cli_pointer(&args(&["switch", "-s", "lavd"])).contains("scxcli apply ID"));
        assert!(cli_pointer(&args(&["stop"])).contains("apply default"));
        assert!(cli_pointer(&args(&[])).contains("scxcli --help"));
    }
}
