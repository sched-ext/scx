// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use anyhow::Result;
use clap::Parser;

#[derive(Debug, Parser)]
#[command(
    name = "scx_characterize",
    about = "Workload characterization tool for sched_ext schedulers"
)]
struct Opts {}

fn main() -> Result<()> {
    let _opts = Opts::parse();

    Ok(())
}
