// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use anyhow::Context;
use anyhow::Result;
use cargo_metadata::{Metadata, MetadataCommand, Package};
use clap::{Args, Parser, Subcommand};
use once_cell::sync::OnceCell;

mod bump_versions;
mod versions;

#[derive(Parser)]
#[command(name = "xtask")]
#[command(about = "Sched ext repository scripts and helpers")]
struct Cli {
    #[arg(short = 'v', long = "verbose", help = "Verbose logging")]
    verbose: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Args)]
#[group(required = true, multiple = false)]
struct BumpTarget {
    #[arg(short = 'p', long = "package", help = "Specific crates to bump")]
    packages: Vec<String>,
    #[arg(long, help = "Bump all workspace crates")]
    all: bool,
}

#[derive(Subcommand)]
enum Commands {
    Versions {
        #[arg(short = 'f', long = "format", default_value = "json")]
        format: versions::Format,
    },
    BumpVersions {
        #[command(flatten)]
        target: BumpTarget,
    },
}

fn main() {
    let cli = Cli::parse();

    let log_level = if cli.verbose {
        log::LevelFilter::Debug
    } else {
        log::LevelFilter::Warn
    };

    simplelog::TermLogger::init(
        log_level,
        simplelog::Config::default(),
        simplelog::TerminalMode::Stderr,
        simplelog::ColorChoice::Auto,
    )
    .unwrap();

    let res = match cli.command {
        Commands::Versions { format } => versions::version_command(format),
        Commands::BumpVersions { target } => {
            bump_versions::bump_versions_command(target.packages, target.all)
        }
    };

    if let Err(e) = res {
        eprintln!("Failed to run command: {e}");
        std::process::exit(1);
    }
}

fn get_cargo_metadata() -> Result<&'static Metadata> {
    static CARGO_METADATA: OnceCell<Metadata> = OnceCell::new();

    CARGO_METADATA.get_or_try_init(|| {
        MetadataCommand::new()
            .exec()
            .context("Failed to run cargo metadata")
    })
}

pub fn get_workspace_packages() -> Result<Vec<&'static Package>> {
    let metadata = get_cargo_metadata()?;

    // Filter to workspace member packages only
    let workspace_packages: Vec<&Package> = metadata
        .packages
        .iter()
        .filter(|package| metadata.workspace_members.contains(&package.id))
        .collect();

    Ok(workspace_packages)
}

pub fn get_rust_paths() -> Result<Vec<std::path::PathBuf>> {
    let packages = get_workspace_packages()?;
    Ok(packages
        .iter()
        .map(|pkg| pkg.manifest_path.as_std_path().to_path_buf())
        .collect())
}
