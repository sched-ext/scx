// Copyright (c) Meta Platforms, Inc. and affiliates.

// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.
mod bpf_skel;
pub use bpf_skel::*;
pub mod bpf_intf;
use libbpf_rs::skel::OpenSkel;
use libbpf_rs::skel::Skel;
use libbpf_rs::skel::SkelBuilder;

use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use anyhow::Result;
use clap::Parser;
use log::info;

use scx_utils::build_id;
use scx_utils::init_libbpf_logging;
use scx_utils::scx_ops_attach;
use scx_utils::scx_ops_open;
use scx_utils::uei_exited;
use scx_utils::uei_report;
use scx_utils::LogRecorderBuilder;
use scx_utils::UserExitInfo;

/// scx_bolt: An interactive, battery-aware scheduler
#[derive(Debug, Parser)]
struct Opts {
    /// Enable verbose output including libbpf details. Specify multiple
    /// times to increase verbosity.
    #[clap(short = 'v', long, action = clap::ArgAction::Count)]
    verbose: u8,
}

struct Scheduler<'a> {
    skel: BpfSkel<'a>,
    struct_ops: Option<libbpf_rs::Link>,
}

impl<'a> Scheduler<'a> {
    fn init(opts: &Opts) -> Result<Self> {
        // Open the BPF prog first for verification.
        let mut skel_builder = BpfSkelBuilder::default();
        skel_builder.obj_builder.debug(opts.verbose > 0);
        init_libbpf_logging(None);
        info!("Running scx_bolt (build ID: {})", *build_id::SCX_FULL_VERSION);
        let mut skel = scx_ops_open!(skel_builder, bolt).unwrap();

        skel.rodata_mut().debug = opts.verbose;
        skel.struct_ops.bolt_mut().exit_dump_len = 0;

        // TODO: Once the libbpf bug is solved with user exit info, also
        // initialize that here.
        let mut skel = skel.load().context("Failed to load BPF program")?;

        // Attach.
        let struct_ops = Some(scx_ops_attach!(skel, bolt)?);
        info!("Bolt scheduler started!");

        Ok(Self {
            skel,
            struct_ops, // should be held to keep it attached
        })
    }

    fn run(&mut self, shutdown: Arc<AtomicBool>) -> Result<UserExitInfo> {
        let mut i = 0;
        while !shutdown.load(Ordering::Relaxed) && !uei_exited!(&self.skel, uei) {
            std::thread::sleep(Duration::from_secs(1));
            info!("{}", i);
            i += 1;
        }

        self.struct_ops.take();
        uei_report!(&self.skel, uei)
    }
}

impl<'a> Drop for Scheduler<'a> {
    fn drop(&mut self) {
        if let Some(struct_ops) = self.struct_ops.take() {
            drop(struct_ops);
        }
    }
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

    loop {
        let mut sched = Scheduler::init(&opts)?;
        if !sched.run(shutdown.clone())?.should_restart() {
            break;
        }
    }
    Ok(())
}
