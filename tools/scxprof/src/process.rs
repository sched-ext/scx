// Copyright (c) 2026 Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use anyhow::{bail, Context as _, Result};
use clap::Parser;
use std::path::PathBuf;
use std::process::Command;

#[derive(Debug, Parser)]
pub struct ProcessOpts {
    /// Path to profile file (tar.gz) or directory
    #[clap(short = 'f', long)]
    pub file: PathBuf,
}

pub fn cmd_process(opts: ProcessOpts) -> Result<()> {
    let profile_dir = prepare_profile_dir(&opts.file)?;
    print_profile_contents(&profile_dir)?;
    Ok(())
}

fn prepare_profile_dir(path: &PathBuf) -> Result<PathBuf> {
    if path.is_dir() {
        return Ok(path.clone());
    }

    let path_str = path.to_string_lossy();
    if !path_str.ends_with(".tar.gz") {
        bail!(
            "'{}' is not a directory or tar.gz archive",
            path.display()
        );
    }

    let dir_name = path_str.trim_end_matches(".tar.gz");
    let output_dir = PathBuf::from(dir_name);

    if output_dir.exists() {
        bail!(
            "output directory '{}' already exists",
            output_dir.display()
        );
    }

    let status = Command::new("tar")
        .args(["-xzf", &path_str, "-C", "."])
        .status()
        .context("failed to run tar")?;

    if !status.success() {
        bail!("tar extraction failed with status: {}", status);
    }

    if !output_dir.exists() {
        bail!(
            "expected directory '{}' not found after extraction",
            output_dir.display()
        );
    }

    Ok(output_dir)
}

fn print_profile_contents(profile_dir: &PathBuf) -> Result<()> {
    println!("Profile '{}':", profile_dir.display());

    let entries: Vec<_> = std::fs::read_dir(profile_dir)
        .context("failed to read profile directory")?
        .filter_map(|e| e.ok())
        .collect();

    if entries.is_empty() {
        println!("  (empty)");
        return Ok(());
    }

    for entry in entries {
        println!("  {}", entry.file_name().to_string_lossy());
    }

    Ok(())
}
