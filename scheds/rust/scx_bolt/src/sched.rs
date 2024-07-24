// Copyright (c) Meta Platforms, Inc. and affiliates.

// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.
use crate::bpf_skel::*;
use libbpf_rs::skel::OpenSkel;
use libbpf_rs::skel::Skel;
use libbpf_rs::skel::SkelBuilder;

use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use anyhow::Result;
use log::info;

use scx_utils::build_id;
use scx_utils::init_libbpf_logging;
use scx_utils::scx_ops_attach;
use scx_utils::scx_ops_open;
use scx_utils::uei_exited;
use scx_utils::uei_report;
use scx_utils::Topology;
use scx_utils::UserExitInfo;

/// A builder for creating a new instance of a bolt `Scheduler`.
///
/// Example:
/// ```rust
/// SchedulerBuilder::new()
///     .verbosity(2)
///     .build()?;
/// ```
pub struct SchedulerBuilder {
    verbosity: u8,
    shutdown: Arc<AtomicBool>,
}

impl SchedulerBuilder {
    pub fn new() -> SchedulerBuilder {
        Self {
            verbosity: 0,
            shutdown: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn verbosity(&mut self, verbosity: u8) -> &mut Self {
        self.verbosity = verbosity;
        self
    }

    pub fn shutdown(&mut self, flag: Arc<AtomicBool>) -> &mut Self {
        self.shutdown = flag;
        self
    }

    pub fn build(&self) -> Result<Scheduler> {
        // Open the BPF prog first for verification.
        let mut skel_builder = BpfSkelBuilder::default();
        skel_builder.obj_builder.debug(self.verbosity > 0);
        init_libbpf_logging(None);

        let top = Arc::new(Topology::new()?);

        info!("Running scx_bolt (build ID: {})", *build_id::SCX_FULL_VERSION);
        let mut skel = scx_ops_open!(skel_builder, bolt).unwrap();

        skel.rodata_mut().debug = self.verbosity as u8;
        skel.struct_ops.bolt_mut().exit_dump_len = 0;

        // TODO: Once the libbpf bug is solved with user exit info, also
        // initialize that here.
        let mut skel = skel.load().context("Failed to load BPF program")?;

        // Attach.
        let struct_ops = Some(scx_ops_attach!(skel, bolt)?);
        info!("Bolt scheduler started!");

        Ok(Scheduler {
            skel,
            struct_ops,
            top,
            shutdown: self.shutdown.clone(),
        })
    }
}

pub struct Scheduler<'a> {
    /// Main libbpf-rs skeleton object.
    skel: BpfSkel<'a>,

    /// Link containing the attached scheduler. Drop to unload.
    struct_ops: Option<libbpf_rs::Link>,

    /// Read-only host Topology.
    #[allow(dead_code)]
    top: Arc<Topology>,

    /// Whether the scheduler should be shut down.
    shutdown: Arc<AtomicBool>,
}

impl<'a> Scheduler<'a> {
    pub fn run(&mut self) -> Result<UserExitInfo> {
        let mut i = 0;
        while !self.shutdown.load(Ordering::Relaxed) && !uei_exited!(&self.skel, uei) {
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
