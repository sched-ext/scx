mod cli;

use anyhow::Context;
use clap::Parser;
use cli::{Cli, Commands};
use scx_loader::{dbus::LoaderClientProxyBlocking, SchedMode, SupportedSched};
use zbus::blocking::Connection;

fn cmd_get(scx_loader: LoaderClientProxyBlocking) -> anyhow::Result<()> {
    let current_scheduler: String = scx_loader
        .current_scheduler()
        .context("Failed to get current scheduler status")?;

    match current_scheduler.as_str() {
        "unknown" => println!("no scx scheduler running"),
        _ => {
            let sched =
                SupportedSched::try_from(current_scheduler.as_str()).with_context(|| {
                    format!("Failed to parse current scheduler '{}'", current_scheduler)
                })?;
            let current_args: Vec<String> = scx_loader
                .current_scheduler_args()
                .context("Failed to get current scheduler arguments")?;

            if current_args.is_empty() {
                let sched_mode: SchedMode = scx_loader
                    .scheduler_mode()
                    .context("Failed to get current scheduler mode")?;
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
    let sl = scx_loader
        .supported_schedulers()
        .context("Failed to get supported schedulers list")?;
    let supported_scheds = sl
        .iter()
        .map(|s| remove_scx_prefix(&s.to_string()))
        .collect::<Vec<String>>();
    println!("supported schedulers: {:?}", supported_scheds);
    Ok(())
}

fn cmd_start(
    scx_loader: LoaderClientProxyBlocking,
    sched_name: String,
    mode_name: Option<SchedMode>,
    args: Option<Vec<String>>,
) -> anyhow::Result<()> {
    // Verify scx_loader is not running a scheduler
    let current_scheduler = scx_loader
        .current_scheduler()
        .context("Failed to get current scheduler status")?;
    if current_scheduler != "unknown" {
        return Err(anyhow::anyhow!(
            "Scx scheduler already running. Use 'switch' instead of 'start'"
        ));
    }

    let sched: SupportedSched = validate_sched(scx_loader.clone(), sched_name)?;
    let mode: SchedMode = mode_name.unwrap_or(SchedMode::Auto);
    match args {
        Some(args) => {
            scx_loader
                .start_scheduler_with_args(sched.clone(), &args.clone())
                .with_context(|| {
                    format!("Failed to start scheduler '{:?}' with arguments", sched)
                })?;
            println!("started {sched:?} with arguments \"{}\"", args.join(" "));
        }
        None => {
            scx_loader
                .start_scheduler(sched.clone(), mode.clone())
                .with_context(|| {
                    format!(
                        "Failed to start scheduler '{:?}' in '{:?}' mode",
                        sched, mode
                    )
                })?;
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
) -> anyhow::Result<()> {
    // Verify scx_loader is running a scheduler
    let current_scheduler = scx_loader
        .current_scheduler()
        .context("Failed to get current scheduler status")?;
    if current_scheduler == "unknown" {
        return Err(anyhow::anyhow!(
            "No scx scheduler running. Use 'start' instead of 'switch'"
        ));
    }

    let sched: SupportedSched = match sched_name {
        Some(sched_name) => validate_sched(scx_loader.clone(), sched_name)?,
        None => {
            let current_scheduler = scx_loader
                .current_scheduler()
                .context("Failed to get current scheduler status")?;
            SupportedSched::try_from(current_scheduler.as_str()).with_context(|| {
                format!("Failed to parse current scheduler '{}'", current_scheduler)
            })?
        }
    };
    let mode: SchedMode = match mode_name {
        Some(mode_name) => mode_name,
        None => scx_loader
            .scheduler_mode()
            .context("Failed to get current scheduler mode")?,
    };
    match args {
        Some(args) => {
            scx_loader
                .switch_scheduler_with_args(sched.clone(), &args.clone())
                .with_context(|| {
                    format!("Failed to switch to scheduler '{:?}' with arguments", sched)
                })?;
            println!(
                "switched to {sched:?} with arguments \"{}\"",
                args.join(" ")
            );
        }
        None => {
            scx_loader
                .switch_scheduler(sched.clone(), mode.clone())
                .with_context(|| {
                    format!(
                        "Failed to switch to scheduler '{:?}' in '{:?}' mode",
                        sched, mode
                    )
                })?;
            println!("switched to {sched:?} in {mode:?} mode");
        }
    }
    Ok(())
}

fn cmd_stop(scx_loader: LoaderClientProxyBlocking) -> anyhow::Result<()> {
    scx_loader
        .stop_scheduler()
        .context("Failed to stop scheduler")?;
    println!("stopped");
    Ok(())
}

fn cmd_restart(scx_loader: LoaderClientProxyBlocking) -> anyhow::Result<()> {
    scx_loader
        .restart_scheduler()
        .context("Failed to restart scheduler")?;
    println!("restarted");
    Ok(())
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let conn = Connection::system().context("Failed to connect to system DBUS")?;
    let scx_loader =
        LoaderClientProxyBlocking::new(&conn).context("Failed to create scx_loader DBUS client")?;

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

fn ensure_scx_prefix(input: String) -> String {
    if !input.starts_with(SCHED_PREFIX) {
        return format!("{}{}", SCHED_PREFIX, input);
    }
    input
}

fn remove_scx_prefix(input: &String) -> String {
    if let Some(strip_input) = input.strip_prefix(SCHED_PREFIX) {
        return strip_input.to_string();
    }
    input.to_string()
}

fn validate_sched(
    scx_loader: LoaderClientProxyBlocking,
    sched: String,
) -> anyhow::Result<SupportedSched> {
    let raw_supported_scheds: Vec<String> = scx_loader
        .supported_schedulers()
        .context("Failed to get supported schedulers list")?;
    let supported_scheds: Vec<String> = raw_supported_scheds
        .iter()
        .map(|s| remove_scx_prefix(s))
        .collect();
    if !supported_scheds.contains(&sched) && !raw_supported_scheds.contains(&sched) {
        return Err(anyhow::anyhow!(
            "Invalid scheduler '{}'. Supported schedulers: {:?}",
            sched,
            supported_scheds
        ));
    }

    SupportedSched::try_from(ensure_scx_prefix(sched.clone()).as_str())
        .with_context(|| format!("Failed to parse scheduler '{}'", sched))
}
