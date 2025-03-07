mod cli;
mod scx_loader;

use crate::scx_loader::{ScxLoaderMode, ScxLoaderProxyBlocking};
use clap::Parser;
use cli::{Cli, Commands};
use colored::Colorize;
use std::process::exit;
use zbus::blocking::Connection;

fn cmd_get(scx_loader: ScxLoaderProxyBlocking) -> Result<(), Box<dyn std::error::Error>> {
    let current_scheduler: String = remove_scx_prefix(&scx_loader.current_scheduler().unwrap());
    let sched_mode = ScxLoaderMode::from_u32(scx_loader.scheduler_mode().unwrap())
        .unwrap()
        .as_str();
    match current_scheduler.as_str() {
        "unknown" => println!("no scx scheduler running"),
        _ => println!("running {} in {} mode", current_scheduler, sched_mode),
    }
    Ok(())
}

fn cmd_list(scx_loader: ScxLoaderProxyBlocking) -> Result<(), Box<dyn std::error::Error>> {
    let supported_scheds: Vec<String> = scx_loader
        .supported_schedulers()
        .unwrap()
        .iter()
        .map(|s| remove_scx_prefix(s))
        .collect();
    println!("supported schedulers: {:?}", supported_scheds);
    Ok(())
}

fn cmd_start(
    scx_loader: ScxLoaderProxyBlocking,
    sched: String,
    mode: Option<ScxLoaderMode>,
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

    let sched = validate_sched(scx_loader.clone(), sched);
    let mode = mode.unwrap_or_else(|| ScxLoaderMode::Auto);
    match args {
        Some(args) => {
            scx_loader.start_scheduler_with_args(sched.clone(), args.clone())?;
            println!("started {} with arguments \"{}\"", sched, args.join(" "));
        }
        None => {
            scx_loader.start_scheduler(sched.clone(), mode.as_u32())?;
            println!("started {} in {} mode", sched, mode.as_str());
        }
    }
    Ok(())
}

fn cmd_switch(
    scx_loader: ScxLoaderProxyBlocking,
    sched: Option<String>,
    mode: Option<ScxLoaderMode>,
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

    let sched = match sched {
        Some(sched) => validate_sched(scx_loader.clone(), sched),
        None => scx_loader.current_scheduler().unwrap(),
    };
    let mode = match mode {
        Some(mode) => mode,
        None => ScxLoaderMode::from_u32(scx_loader.scheduler_mode().unwrap()).unwrap(),
    };
    match args {
        Some(args) => {
            scx_loader.switch_scheduler_with_args(sched.clone(), args.clone())?;
            println!(
                "switched to {} with arguments \"{}\"",
                sched,
                args.join(" ")
            );
        }
        None => {
            scx_loader.switch_scheduler(sched.clone(), mode.as_u32())?;
            println!("switched to {} in {} mode", sched, mode.as_str());
        }
    }
    Ok(())
}

fn cmd_stop(scx_loader: ScxLoaderProxyBlocking) -> Result<(), Box<dyn std::error::Error>> {
    scx_loader.stop_scheduler()?;
    println!("stopped");
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let conn = Connection::system()?;
    let scx_loader = ScxLoaderProxyBlocking::new(&conn)?;

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

fn validate_sched(scx_loader: ScxLoaderProxyBlocking, sched: String) -> String {
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

    ensure_scx_prefix(sched)
}
