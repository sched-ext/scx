mod cli;

use clap::Parser;
use cli::{Cli, Commands};
use colored::Colorize;
use scx_loader::{dbus::LoaderClientProxyBlocking, SchedMode, SupportedSched};
use std::process::exit;
use zbus::blocking::Connection;

fn cmd_get(scx_loader: LoaderClientProxyBlocking) -> Result<(), Box<dyn std::error::Error>> {
    let current_scheduler: String = scx_loader.current_scheduler().unwrap();
    let sched_mode: SchedMode = scx_loader.scheduler_mode().unwrap();
    match current_scheduler.as_str() {
        "unknown" => println!("no scx scheduler running"),
        _ => {
            let sched = SupportedSched::try_from(current_scheduler.as_str()).unwrap();
            println!("running {sched:?} in {sched_mode:?} mode");
        }
    }
    Ok(())
}

fn cmd_list(scx_loader: LoaderClientProxyBlocking) -> Result<(), Box<dyn std::error::Error>> {
    let supported_scheds: Vec<String> = scx_loader
        .supported_schedulers()
        .unwrap()
        .iter()
        .map(|s| remove_scx_prefix(&s.to_string()))
        .collect();
    println!("supported schedulers: {:?}", supported_scheds);
    Ok(())
}

fn cmd_start(
    scx_loader: LoaderClientProxyBlocking,
    sched_name: String,
    mode_name: Option<SchedMode>,
    args: Option<Vec<String>>,
) -> Result<(), Box<dyn std::error::Error>> {
    // Verify scx_loader is not running a scheduler
    if scx_loader.current_scheduler().unwrap() != "unknown" {
        println!(
            "{} scx scheduler already running, use '{}' instead of '{}'",
            "error:".red().bold(),
            "switch".bold(),
            "start".bold()
        );
        println!("\nFor more information, try '{}'", "--help".bold());
        exit(1);
    }

    let sched: SupportedSched = validate_sched(scx_loader.clone(), sched_name);
    let mode: SchedMode = mode_name.unwrap_or_else(|| SchedMode::Auto);
    match args {
        Some(args) => {
            scx_loader.start_scheduler_with_args(sched.clone(), &args.clone())?;
            println!("started {sched:?} with arguments \"{}\"", args.join(" "));
        }
        None => {
            scx_loader.start_scheduler(sched.clone(), mode.clone())?;
            println!("started {sched:?} in {mode:?} mode");
        }
    }
    Ok(())
}

fn cmd_switch(
    scx_loader: LoaderClientProxyBlocking,
    sched_name: Option<String>,
    mode_name: Option<SchedMode>,
    args: Option<Vec<String>>,
) -> Result<(), Box<dyn std::error::Error>> {
    // Verify scx_loader is running a scheduler
    if scx_loader.current_scheduler().unwrap() == "unknown" {
        println!(
            "{} no scx scheduler running, use '{}' instead of '{}'",
            "error:".red().bold(),
            "start".bold(),
            "switch".bold()
        );
        println!("\nFor more information, try '{}'", "--help".bold());
        exit(1);
    }

    let sched: SupportedSched = match sched_name {
        Some(sched_name) => validate_sched(scx_loader.clone(), sched_name),
        None => SupportedSched::try_from(scx_loader.current_scheduler().unwrap().as_str()).unwrap(),
    };
    let mode: SchedMode = match mode_name {
        Some(mode_name) => mode_name,
        None => scx_loader.scheduler_mode().unwrap(),
    };
    match args {
        Some(args) => {
            scx_loader.switch_scheduler_with_args(sched.clone(), &args.clone())?;
            println!(
                "switched to {sched:?} with arguments \"{}\"",
                args.join(" ")
            );
        }
        None => {
            scx_loader.switch_scheduler(sched.clone(), mode.clone())?;
            println!("switched to {sched:?} in {mode:?} mode");
        }
    }
    Ok(())
}

fn cmd_stop(scx_loader: LoaderClientProxyBlocking) -> Result<(), Box<dyn std::error::Error>> {
    scx_loader.stop_scheduler()?;
    println!("stopped");
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let conn = Connection::system()?;
    let scx_loader = LoaderClientProxyBlocking::new(&conn)?;

    match cli.command {
        Commands::Get => cmd_get(scx_loader)?,
        Commands::List => cmd_list(scx_loader)?,
        Commands::Start { args } => cmd_start(scx_loader, args.sched, args.mode, args.args)?,
        Commands::Switch { args } => cmd_switch(scx_loader, args.sched, args.mode, args.args)?,
        Commands::Stop => cmd_stop(scx_loader)?,
    }

    Ok(())
}

/*
 * Utilities
 */

const SCHED_PREFIX: &str = "scx_";

fn ensure_scx_prefix(input: String) -> String {
    if !input.starts_with(SCHED_PREFIX) {
        return format!("{}{}", SCHED_PREFIX, input);
    }
    input
}

fn remove_scx_prefix(input: &String) -> String {
    if input.starts_with(SCHED_PREFIX) {
        return input[SCHED_PREFIX.len()..].to_string();
    }
    input.to_string()
}

fn validate_sched(scx_loader: LoaderClientProxyBlocking, sched: String) -> SupportedSched {
    let raw_supported_scheds: Vec<String> = scx_loader.supported_schedulers().unwrap();
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

    SupportedSched::try_from(ensure_scx_prefix(sched).as_str()).unwrap()
}
