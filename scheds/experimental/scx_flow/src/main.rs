// SPDX-License-Identifier: GPL-2.0
//! Flow scheduler front end.
//! Copyright (c) 2026 Galih Tama <galpt@v.recipes>
mod bpf_skel;
pub use bpf_skel::*;
pub mod bpf_intf;
pub use bpf_intf::*;
pub mod cli;
pub mod metrics;
pub mod run;
#[path = "stats.rs"]
mod stats;
pub mod topology;
use anyhow::Result;
use clap::{CommandFactory, Parser};
use clap_complete::generate;
use log::info;
fn main() -> Result<()> {
    let opts = cli::Opts::parse();
    if let Some(shell) = opts.completions {
        generate(
            shell,
            &mut cli::Opts::command(),
            cli::SCHEDULER_NAME,
            &mut std::io::stdout(),
        );
        return Ok(());
    }
    if opts.version {
        println!("{} {}", cli::SCHEDULER_NAME, cli::full_version());
        return Ok(());
    }
    if opts.help_stats {
        stats::server_data().describe_meta(&mut std::io::stdout(), Some(&["Metrics"]))?;
        return Ok(());
    }
    cli::init_logging(opts.verbose)?;
    info!("{} {}", cli::SCHEDULER_NAME, cli::full_version());
    run::drive(&opts)
}
