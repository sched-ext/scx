mod cli;

use anyhow::Context;
use clap::Parser;
use cli::{Cli, Commands};
use colored::Colorize;
use scx_loader::{dbus::LoaderClientProxyBlocking, SchedMode, SupportedSched};
use std::process::exit;
use zbus::blocking::Connection;

fn cmd_get(scx_loader: LoaderClientProxyBlocking) -> anyhow::Result<()> {
    let current_scheduler: String = scx_loader.current_scheduler()?;

    match current_scheduler.as_str() {
        "unknown" => println!("no scx scheduler running"),
        _ => {
            let sched = SupportedSched::try_from(current_scheduler.as_str())?;
            let current_args: Vec<String> = scx_loader.current_scheduler_args()?;

            if current_args.is_empty() {
                let sched_mode: SchedMode = scx_loader.scheduler_mode()?;
                println!("running {sched:?} in {sched_mode:?} mode");
            } else {
                println!(
                    "running {sched:?} with arguments \"{}\"",
                    current_args.join(" ")
                );
            }
        }
    }
    Ok(())
}

fn cmd_list(scx_loader: LoaderClientProxyBlocking) -> anyhow::Result<()> {
    match scx_loader.supported_schedulers() {
        Ok(sl) => {
            let sched_names = sl
                .iter()
                .map(|s| remove_scx_prefix(s))
                .collect::<Vec<_>>()
                .join(", ");
            println!("supported schedulers: [{}]", sched_names);
            return Ok(());
        }
        Err(e) => {
            eprintln!("scheduler list failed: {e}");
            exit(1);
        }
    };
}

fn cmd_start(
    scx_loader: LoaderClientProxyBlocking,
    sched_name: String,
    mode_name: Option<SchedMode>,
    args: Option<Vec<String>>,
) -> anyhow::Result<()> {
    // Verify no scheduler is running
    check_scheduler_state(&scx_loader, false)?;

    let sched = validate_sched(scx_loader.clone(), sched_name)?;
    let mode = mode_name.unwrap_or(SchedMode::Auto);

    match &args {
        Some(args) => {
            scx_loader.start_scheduler_with_args(sched.clone(), args)?;
        }
        None => {
            scx_loader.start_scheduler(sched.clone(), mode.clone())?;
        }
    }

    println!("{}", format_scheduler_message("started", &sched, Some(&mode), args.as_ref()));
    Ok(())
}

fn cmd_switch(
    scx_loader: LoaderClientProxyBlocking,
    sched_name: Option<String>,
    mode_name: Option<SchedMode>,
    args: Option<Vec<String>>,
) -> anyhow::Result<()> {
    // Verify a scheduler is running
    let current_scheduler = check_scheduler_state(&scx_loader, true)?;

    let sched = match sched_name {
        Some(name) => validate_sched(scx_loader.clone(), name)?,
        None => SupportedSched::try_from(current_scheduler.as_str())
            .context("Failed to parse current scheduler")?,
    };

    let mode = match mode_name {
        Some(mode) => mode,
        None => scx_loader.scheduler_mode()
            .context("Failed to get current scheduler mode")?,
    };

    match &args {
        Some(args) => {
            scx_loader.switch_scheduler_with_args(sched.clone(), args)?;
        }
        None => {
            scx_loader.switch_scheduler(sched.clone(), mode.clone())?;
        }
    }

    println!("{}", format_scheduler_message("switched to", &sched, Some(&mode), args.as_ref()));
    Ok(())
}

fn cmd_stop(scx_loader: LoaderClientProxyBlocking) -> anyhow::Result<()> {
    scx_loader.stop_scheduler()?;
    println!("stopped");
    Ok(())
}

fn cmd_restart(scx_loader: LoaderClientProxyBlocking) -> anyhow::Result<()> {
    scx_loader.restart_scheduler()?;
    println!("restarted");
    Ok(())
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let conn = Connection::system()?;
    let scx_loader = LoaderClientProxyBlocking::new(&conn)?;

    match cli.command {
        Commands::Get => cmd_get(scx_loader)?,
        Commands::List => cmd_list(scx_loader)?,
        Commands::Start { args } => cmd_start(scx_loader, args.sched, args.mode, args.args)?,
        Commands::Switch { args } => cmd_switch(scx_loader, args.sched, args.mode, args.args)?,
        Commands::Stop => cmd_stop(scx_loader)?,
        Commands::Restart => cmd_restart(scx_loader)?,
    }

    Ok(())
}

/*
 * Utilities
 */

const SCHED_PREFIX: &str = "scx_";

fn check_scheduler_state(
    scx_loader: &LoaderClientProxyBlocking,
    expecting_running: bool
) -> anyhow::Result<String> {
    let current_scheduler = scx_loader.current_scheduler()
        .context("Failed to get current scheduler status")?;

    let is_running = current_scheduler != "unknown";

    if expecting_running && !is_running {
        println!(
            "{} no scx scheduler running, use '{}' instead of '{}'",
            "error:".red().bold(),
            "start".bold(),
            "switch".bold()
        );
        println!("\nFor more information, try '{}'", "--help".bold());
        exit(1);
    }

    if !expecting_running && is_running {
        println!(
            "{} scx scheduler already running, use '{}' instead of '{}'",
            "error:".red().bold(),
            "switch".bold(),
            "start".bold()
        );
        println!("\nFor more information, try '{}'", "--help".bold());
        exit(1);
    }

    Ok(current_scheduler)
}

fn format_scheduler_message(
    action: &str,
    sched: &SupportedSched,
    mode: Option<&SchedMode>,
    args: Option<&Vec<String>>
) -> String {
    match args {
        Some(args) => format!("{} {sched:?} with arguments \"{}\"", action, args.join(" ")),
        None => {
            let mode = mode.unwrap_or(&SchedMode::Auto);
            format!("{} {sched:?} in {mode:?} mode", action)
        }
    }
}

fn ensure_scx_prefix(input: &str) -> String {
    if !input.starts_with(SCHED_PREFIX) {
        return format!("{}{}", SCHED_PREFIX, input);
    }
    input.to_string()
}

fn remove_scx_prefix(input: &str) -> String {
    if let Some(strip_input) = input.strip_prefix(SCHED_PREFIX) {
        return strip_input.to_string();
    }
    input.to_string()
}

fn validate_sched(scx_loader: LoaderClientProxyBlocking, sched: String) -> anyhow::Result<SupportedSched> {
    let raw_supported_scheds = scx_loader.supported_schedulers()
        .context("Failed to get supported schedulers list")?;
    let supported_scheds: Vec<String> = raw_supported_scheds
        .iter()
        .map(|s| remove_scx_prefix(s))
        .collect();
    if !supported_scheds.contains(&sched) && !raw_supported_scheds.contains(&sched) {
        println!(
            "{} invalid value '{}' for '{}'",
            "error:".red().bold(),
            &sched.yellow(),
            "--sched <SCHED>".bold()
        );
        println!("supported schedulers: {:?}", supported_scheds);
        println!("\nFor more information, try '{}'", "--help".bold());
        exit(1);
    }

    SupportedSched::try_from(ensure_scx_prefix(&sched).as_str())
        .with_context(|| format!("Failed to parse scheduler '{}'", sched))
}
