// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use anyhow::Context;
use anyhow::Result;
use clap::{Args, Parser, Subcommand};
use once_cell::sync::OnceCell;

use std::path::PathBuf;
use std::process::Command;

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

fn get_cargo_metadata() -> Result<&'static serde_json::Value> {
    static CARGO_METADATA: OnceCell<serde_json::Value> = OnceCell::new();

    CARGO_METADATA.get_or_try_init(|| {
        let output = Command::new("cargo")
            .args(["metadata", "--format-version", "1"])
            .output()?;

        if !output.status.success() {
            return Err(anyhow::anyhow!("Failed to run cargo metadata"));
        }

        Ok(serde_json::from_slice(&output.stdout)?)
    })
}

pub fn get_rust_paths() -> Result<Vec<PathBuf>> {
    let metadata = get_cargo_metadata()?;

    // Get workspace member paths only
    let workspace_members = metadata["workspace_members"]
        .as_array()
        .context("no workspace_members found in cargo metadata")?;

    let packages = metadata["packages"]
        .as_array()
        .context("no packages found in cargo metadata")?;

    let mut paths = Vec::new();

    // Only include packages that are workspace members
    for package in packages {
        if let Some(id) = package["id"].as_str() {
            if workspace_members
                .iter()
                .any(|member| member.as_str() == Some(id))
            {
                if let Some(manifest_path) = package["manifest_path"].as_str() {
                    paths.push(PathBuf::from(manifest_path));
                }
            }
        }
    }

    Ok(paths)
}
