// Copyright (c) 2026 Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use anyhow::Result;
use clap::Parser;

#[derive(Debug, Parser)]
#[clap(name = "scxprof", about = "SCX Workload Profiler")]
struct Opts {}

fn main() -> Result<()> {
    let _opts = Opts::parse();
    Ok(())
}
