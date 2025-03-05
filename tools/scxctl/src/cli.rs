use crate::scx_loader::ScxLoaderMode;
use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Parser, Debug)]
#[group(required = true)]
pub struct StartArgs {
    #[arg(short, long, help = "Scheduler to start", required = true)]
    pub sched: String,
    #[arg(
        short,
        long,
        value_enum,
        default_value = "auto",
        conflicts_with = "args",
        help = "Mode to start in"
    )]
    pub mode: Option<ScxLoaderMode>,
    #[arg(
        short,
        long,
        value_delimiter(','),
        requires = "sched",
        conflicts_with = "mode",
        help = "Arguments to run scheduler with"
    )]
    pub args: Option<Vec<String>>,
}

#[derive(Parser, Debug)]
#[group(required = true)]
pub struct SwitchArgs {
    #[arg(short, long, help = "Scheduler to switch to")]
    pub sched: Option<String>,
    #[arg(
        short,
        long,
        value_enum,
        conflicts_with = "args",
        help = "Mode to switch to"
    )]
    pub mode: Option<ScxLoaderMode>,
    #[arg(
        short,
        long,
        value_delimiter(','),
        requires = "sched",
        conflicts_with = "mode",
        help = "Arguments to run scheduler with"
    )]
    pub args: Option<Vec<String>>,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    #[command(about = "Get the current scheduler and mode")]
    Get,
    #[command(about = "List all supported schedulers")]
    List,
    #[command(about = "Start a scheduler in a mode or with arguments")]
    Start {
        #[clap(flatten)]
        args: StartArgs,
    },
    #[command(about = "Switch schedulers or modes, optionally with arguments")]
    Switch {
        #[clap(flatten)]
        args: SwitchArgs,
    },
    #[command(about = "Stop the current scheduler")]
    Stop,
}
