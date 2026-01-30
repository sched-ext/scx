// Copyright (c) 2026 Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::process::{Child, Command, ExitStatus};

#[derive(Debug, Parser)]
#[clap(name = "scxprof", about = "SCX Workload Profiler")]
struct Opts {
    #[clap(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Record workload profile using perf
    Record(RecordOpts),
}

#[derive(Debug, Parser)]
struct RecordOpts {
    /// Output directory for perf.data and other artifacts
    #[clap(short, long)]
    output: PathBuf,
}

struct SpawnedProcess {
    child: Child,
    name: String,
}

impl SpawnedProcess {
    fn spawn(name: &str, cmd: &mut Command) -> Result<Self> {
        let child = cmd
            .spawn()
            .with_context(|| format!("failed to spawn {}", name))?;
        Ok(Self {
            child,
            name: name.to_string(),
        })
    }

    fn wait(mut self) -> Result<ExitStatus> {
        let status = self
            .child
            .wait()
            .with_context(|| format!("failed to wait for {}", self.name))?;
        if !status.success() {
            bail!("{} exited with status: {}", self.name, status);
        }
        Ok(status)
    }
}

fn cmd_record(opts: RecordOpts) -> Result<()> {
    std::fs::create_dir_all(&opts.output)
        .with_context(|| format!("failed to create output directory {:?}", opts.output))?;

    let perf_data = opts.output.join("perf.data");

    let mut cmd = Command::new("perf");
    cmd.args([
        "record",
        "mem",
        "--all-cgroups",
        "-p",
        "--data-page-size",
        "-o",
    ])
    .arg(&perf_data);

    let proc = SpawnedProcess::spawn("perf", &mut cmd)?;
    proc.wait()?;

    Ok(())
}

fn main() -> Result<()> {
    let opts = Opts::parse();

    match opts.command {
        Commands::Record(record_opts) => cmd_record(record_opts),
    }
}
