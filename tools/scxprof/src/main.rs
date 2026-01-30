// Copyright (c) 2026 Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use anyhow::{bail, Context as _, Result};
use clap::{Parser, Subcommand};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

mod record;

pub mod bpf_intf;
pub mod bpf_skel;
pub use bpf_skel as bpf;

fn create_eventfd() -> Result<OwnedFd> {
    let fd = unsafe { libc::eventfd(0, libc::EFD_NONBLOCK | libc::EFD_CLOEXEC) };
    if fd < 0 {
        bail!("eventfd failed: {}", std::io::Error::last_os_error());
    }
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn signal_eventfd(fd: RawFd) {
    let val: u64 = 1;
    unsafe {
        libc::write(fd, &val as *const u64 as *const libc::c_void, 8);
    }
}

pub struct Context {
    shutdown_fd: OwnedFd,
}

impl Context {
    fn new() -> Result<Self> {
        let shutdown_fd = create_eventfd()?;
        let raw_fd = shutdown_fd.as_raw_fd();

        ctrlc::set_handler(move || {
            signal_eventfd(raw_fd);
        })
        .context("failed to set Ctrl+C handler")?;

        Ok(Self { shutdown_fd })
    }

    pub fn shutdown_fd(&self) -> RawFd {
        self.shutdown_fd.as_raw_fd()
    }
}

#[derive(Debug, Parser)]
#[clap(name = "scxprof", about = "SCX Workload Profiler")]
struct Opts {
    #[clap(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Record workload profile using perf
    Record(record::RecordOpts),
}

fn main() -> Result<()> {
    let ctx = Context::new()?;
    let opts = Opts::parse();

    match opts.command {
        Commands::Record(record_opts) => record::cmd_record(&ctx, record_opts),
    }
}
