// Copyright (c) Meta Platforms, Inc. and affiliates.

// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.
pub mod bpf_skel;
pub use bpf_skel::*;
pub mod bpf_intf;
mod sched;
mod config;
use sched::SchedulerBuilder;

use anyhow::Context;
use anyhow::Result;
use clap::Parser;

use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;

/// scx_framesched: An interactive, battery-aware scheduler
///
/// scx_framesched is a deadline-based scheduler that uses QoS to inform how
/// virtual deadlines are calculated from thread and cgroup vruntimes.
/// scx_framesched allows users to classify tasks and cgroups into QoS
/// according to a variety of criteria.
#[derive(Debug, Parser)]
struct Opts {
    /// Enable verbose output including libbpf details. Specify multiple
    /// times to increase verbosity.
    #[clap(short = 'v', long, action = clap::ArgAction::Count)]
    verbose: u8,

    /// Specification for the scheduler. See the help message above.
    spec: Option<String>,
}

fn init_logger(verbose: u8) -> Result<()> {
    let llv = match verbose {
        0 => simplelog::LevelFilter::Info,
        1 => simplelog::LevelFilter::Debug,
        _ => simplelog::LevelFilter::Trace,
    };
    let mut lcfg = simplelog::ConfigBuilder::new();
    lcfg.set_time_level(simplelog::LevelFilter::Error)
        .set_location_level(simplelog::LevelFilter::Off)
        .set_target_level(simplelog::LevelFilter::Off)
        .set_thread_level(simplelog::LevelFilter::Off);

    Ok(simplelog::TermLogger::init(
        llv,
        lcfg.build(),
        simplelog::TerminalMode::Stderr,
        simplelog::ColorChoice::Auto,
    )?)
}

fn create_builder(opts: &Opts) -> Result<SchedulerBuilder> {
    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_clone = shutdown.clone();
    ctrlc::set_handler(move || {
        shutdown_clone.store(true, Ordering::Relaxed);
    })
    .context("Error setting Ctrl-C handler")?;

    let mut builder = SchedulerBuilder::new(opts.spec.clone());
    builder.verbosity(opts.verbose);
    builder.shutdown(shutdown.clone());

    Ok(builder)
}

fn main() -> Result<()> {
    let opts = Opts::parse();

    init_logger(opts.verbose)?;
    let mut builder = create_builder(&opts)?;

    loop {
        let mut sched = builder.build()?;
        let uei = sched.run()?;
        if !uei.should_restart() {
            break;
        }
    }
    Ok(())
}
