// Copyright (c) Meta Platforms, Inc. and affiliates.

// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.
pub mod bpf_skel;
pub use bpf_skel::*;
pub mod bpf_intf;
mod sched;
use sched::SchedulerBuilder;

use anyhow::Context;
use anyhow::Result;
use clap::Parser;

use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::time::Duration;

use scx_utils::LogRecorderBuilder;

/// scx_bolt: An interactive, battery-aware scheduler
#[derive(Debug, Parser)]
struct Opts {
    /// Enable verbose output including libbpf details. Specify multiple
    /// times to increase verbosity.
    #[clap(short = 'v', long, action = clap::ArgAction::Count)]
    verbose: u8,
}

fn main() -> Result<()> {
    let opts = Opts::parse();

    let llv = match opts.verbose {
        0 => simplelog::LevelFilter::Info,
        1 => simplelog::LevelFilter::Debug,
        _ => simplelog::LevelFilter::Trace,
    };
    let mut lcfg = simplelog::ConfigBuilder::new();
    lcfg.set_time_level(simplelog::LevelFilter::Error)
        .set_location_level(simplelog::LevelFilter::Off)
        .set_target_level(simplelog::LevelFilter::Off)
        .set_thread_level(simplelog::LevelFilter::Off);
    simplelog::TermLogger::init(
        llv,
        lcfg.build(),
        simplelog::TerminalMode::Stderr,
        simplelog::ColorChoice::Auto,
    )?;

    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_clone = shutdown.clone();
    ctrlc::set_handler(move || {
        shutdown_clone.store(true, Ordering::Relaxed);
    })
    .context("Error setting Ctrl-C handler")?;

    LogRecorderBuilder::new()
        .with_reporting_interval(Duration::from_secs(3))
        .install()
        .expect("failed to install log recorder");

    let mut builder = SchedulerBuilder::new();
    builder.verbosity(opts.verbose);
    builder.shutdown(shutdown.clone());
    loop {
        let mut sched = builder.build()?;
        let uei = sched.run()?;
        if !uei.should_restart() {
            break;
        }
    }
    Ok(())
}
