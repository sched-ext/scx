// SPDX-License-Identifier: GPL-2.0
//! Command line options of scx_flow.
//!
//! Copyright (c) 2026 Galih Tama <galpt@v.recipes>

use std::time::Duration;

use anyhow::Result;
use clap::Parser;
use clap_complete::Shell;
use scx_utils::libbpf_clap_opts::LibbpfOpts;

pub const SCHEDULER_NAME: &str = "scx_flow";

pub fn full_version() -> String {
    scx_utils::build_id::full_version(env!("CARGO_PKG_VERSION"))
}

/// Log to stderr with local timestamps, at debug level when @verbose.
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

/// Statistics interval in seconds, which must be above zero and at most
/// one hour.
pub fn poll_interval_secs(v: f64) -> Result<Duration> {
    if !v.is_finite() || v <= 0.0 || v > 3600.0 {
        anyhow::bail!("invalid statistics interval {v}");
    }
    Ok(Duration::from_secs_f64(v))
}

#[derive(Debug, Parser)]
#[command(name = SCHEDULER_NAME, version, disable_version_flag = true)]
pub struct Opts {
    /// Print statistics every this many seconds while scheduling.
    #[clap(long)]
    pub stats: Option<f64>,

    /// Print statistics of an already running instance every this many
    /// seconds, without starting the scheduler.
    #[clap(long)]
    pub monitor: Option<f64>,

    /// Enable debug output, including libbpf messages.
    #[clap(short = 'v', long, action = clap::ArgAction::SetTrue)]
    pub verbose: bool,

    /// Size of the debug dump buffer printed on exit, in bytes. Zero keeps
    /// the kernel default.
    #[clap(long, default_value = "0")]
    pub exit_dump_len: u32,

    /// Print the version and exit.
    #[clap(short = 'V', long, action = clap::ArgAction::SetTrue)]
    pub version: bool,

    /// Describe the statistics and exit.
    #[clap(long)]
    pub help_stats: bool,

    /// Generate shell completions and exit.
    #[clap(long, value_name = "SHELL", hide = true)]
    pub completions: Option<Shell>,

    #[clap(flatten, next_help_heading = "Libbpf Options")]
    pub libbpf: LibbpfOpts,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interval_bounds() {
        assert!(poll_interval_secs(0.5).is_ok());
        assert!(poll_interval_secs(3600.0).is_ok());
        for bad in [0.0, -1.0, 3600.5, f64::NAN, f64::INFINITY] {
            assert!(poll_interval_secs(bad).is_err());
        }
    }
}
