// SPDX-License-Identifier: GPL-2.0
//! Command line options for the flow scheduler.
//!
//! Copyright (c) 2026 Galih Tama <galpt@v.recipes>

//! Poll interval handling and scheduler flags.

use std::time::Duration;

use anyhow::Result;
use clap::Parser;
use clap_complete::Shell;
use scx_utils::libbpf_clap_opts::LibbpfOpts;

/* Binary name used in logs and stats. */
pub const SCHEDULER_NAME: &str = "scx_flow";

pub fn full_version() -> String {
    scx_utils::build_id::full_version(env!("CARGO_PKG_VERSION"))
}

/// Init stderr logging with local time offset.
/// Verbose selects debug output. Other levels stay fixed.
pub fn init_logging(verbose: bool) -> Result<()> {
    let loglevel = if verbose {
        simplelog::LevelFilter::Debug
    } else {
        simplelog::LevelFilter::Info
    };
    let mut lcfg = simplelog::ConfigBuilder::new();
    lcfg.set_time_offset_to_local()
        .expect("Failed to set local time offset")
        .set_time_level(simplelog::LevelFilter::Error)
        .set_location_level(simplelog::LevelFilter::Off)
        .set_target_level(simplelog::LevelFilter::Off)
        .set_thread_level(simplelog::LevelFilter::Off);
    simplelog::TermLogger::init(
        loglevel,
        lcfg.build(),
        simplelog::TerminalMode::Stderr,
        simplelog::ColorChoice::Auto,
    )?;
    Ok(())
}

/// Validated poll interval from float seconds.
/// Rejects NaN, infinite, non-positive, and values over one hour.
/// A bad value returns an error before any timer starts.
pub fn poll_interval_secs(v: f64) -> Result<Duration> {
    if !v.is_finite() || v <= 0.0 || v > 3600.0 {
        anyhow::bail!("interval bad {v}");
    }
    Ok(Duration::from_secs_f64(v))
}

#[derive(Debug, Parser)]
#[command(name = SCHEDULER_NAME, version, disable_version_flag = true)]
pub struct Opts {
    /* Poll interval for the stats printer. */
    #[clap(long)]
    pub stats: Option<f64>,
    /* Run the stats printer only. */
    #[clap(long)]
    pub monitor: Option<f64>,
    /* Verbose output with libbpf detail. */
    #[clap(short = 'v', long, action = clap::ArgAction::SetTrue)]
    pub verbose: bool,
    /* Exit dump buffer length in bytes. Zero keeps the default size. */
    /* Values pass to the kernel as given. The operator owns this path. */
    #[clap(long, default_value = "0")]
    pub exit_dump_len: u32,
    /* Print version and exit. */
    #[clap(short = 'V', long, action = clap::ArgAction::SetTrue)]
    pub version: bool,
    /* Show stat descriptions. */
    #[clap(long)]
    pub help_stats: bool,
    /* Generate shell completions and exit. */
    #[clap(long, value_name = "SHELL", hide = true)]
    pub completions: Option<Shell>,
    #[clap(flatten, next_help_heading = "Libbpf Options")]
    pub libbpf: LibbpfOpts,
}
