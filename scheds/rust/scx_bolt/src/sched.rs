// Copyright (c) Meta Platforms, Inc. and affiliates.

// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.
use std::ffi::c_uint;
use std::ffi::c_ulonglong;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use anyhow::bail;
use anyhow::Context;
use anyhow::Result;
use libbpf_rs::ProgramInput;
use libbpf_rs::skel::OpenSkel;
use libbpf_rs::skel::Skel;
use libbpf_rs::skel::SkelBuilder;
use log::info;
use scx_utils::build_id;
use scx_utils::init_libbpf_logging;
use scx_utils::scx_ops_attach;
use scx_utils::scx_ops_open;
use scx_utils::uei_exited;
use scx_utils::uei_report;
use scx_utils::Topology;
use scx_utils::UserExitInfo;

use crate::bpf_skel::*;
use crate::bpf_intf;

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

    fn create_domains(top: Arc<Topology>, skel: &mut BpfSkel<'_>) -> Result<()> {
        if top.nr_cpu_ids() > bpf_intf::consts_MAX_CPUS as usize {
            bail!("Maximum CPUs {} exceeded: {}", bpf_intf::consts_MAX_CPUS, top.nr_cpu_ids());
        }
        let n_mask_indices = bpf_intf::consts_MAX_CPUS as usize / 64;
        let mut progs = skel.progs_mut();
        let prog = progs.create_dom_sys();
        for node in top.nodes().iter() {
            for (_, llc) in node.llcs().iter() {
                let raw_mask = llc.span().clone();
                let mut raw_mask = raw_mask.as_raw_slice().to_vec();
                if raw_mask.len() > n_mask_indices {
                    panic!("CPUs mask vector exceeded max expected size");
                }
                raw_mask.resize(n_mask_indices, 0);
                #[repr(C)]
                struct dom_init_ctx {
                    dom_id: c_uint,
                    mask: [c_ulonglong; 16],
                }
                let init_ctx = dom_init_ctx {
                    dom_id: llc.id() as u32,
                    mask: raw_mask.try_into().unwrap(),
                };
                let input = ProgramInput {
                    context_in: Some(unsafe { plain::as_bytes(&init_ctx)}),
                    ..Default::default()
                };
                let output = prog.test_run(input)?;
                if output.return_value != 0 {
                    bail!("Failed to create domain {}: {}", llc.id(), output.return_value);
                }
            }
        }
        Ok(())
    }

    pub fn build(&self) -> Result<Scheduler> {
        // Open the BPF prog first for verification.
        let mut skel_builder = BpfSkelBuilder::default();
        skel_builder.obj_builder.debug(self.verbosity > 0);
        init_libbpf_logging(None);

        let top = Arc::new(Topology::new()?);

        info!("Running scx_bolt (build ID: {})", *build_id::SCX_FULL_VERSION);
        let mut skel = scx_ops_open!(skel_builder, bolt).unwrap();

        let nr_cpu_ids = top.nr_cpu_ids() as u32;

        skel.rodata_mut().debug = self.verbosity as u8;
        skel.rodata_mut().nr_cpu_ids = nr_cpu_ids;
        skel.maps_mut().pcpu_data().set_max_entries(nr_cpu_ids)?;
        skel.struct_ops.bolt_mut().exit_dump_len = 0;

        let mut nr_dom_ids = 0;
        for node in top.nodes().iter() {
            for (_, _) in node.llcs().iter() {
                nr_dom_ids += 1;
            }
        }
        skel.rodata_mut().nr_dom_ids = nr_dom_ids as u32;
        skel.maps_mut().dom_data().set_max_entries(nr_dom_ids)?;

        for node in top.nodes().iter() {
            for (id, _) in node.llcs().iter() {
                skel.rodata_mut().numa_dom_id_map[*id] = node.id() as u32;
            }
        }

        // TODO: Once the libbpf bug is solved with user exit info, also
        // initialize that here.
        let mut skel = skel.load().context("Failed to load BPF program")?;
        Self::create_domains(top.clone(), &mut skel)?;

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
