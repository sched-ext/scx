// Copyright (c) Meta Platforms, Inc. and affiliates.

// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.
use anyhow::bail;
use scx_chaos::run;
use scx_chaos::Args;

use clap::Parser;

fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    let llv = match &args.verbose {
        0 => simplelog::LevelFilter::Info,
        1 => simplelog::LevelFilter::Debug,
        _ => simplelog::LevelFilter::Trace,
    };

    simplelog::TermLogger::init(
        llv,
        simplelog::ConfigBuilder::new()
            .set_time_offset_to_local()
            .expect("Failed to set local time offset")
            .set_time_level(simplelog::LevelFilter::Error)
            .set_location_level(simplelog::LevelFilter::Off)
            .set_target_level(simplelog::LevelFilter::Off)
            .set_thread_level(simplelog::LevelFilter::Off)
            .build(),
        simplelog::TerminalMode::Stderr,
        simplelog::ColorChoice::Auto,
    )?;

    if args.p2dq.atq_enabled {
        bail!("ATQs not supported");
    }

    run(args)
}
