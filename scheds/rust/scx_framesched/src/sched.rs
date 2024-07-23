// Copyright (c) Meta Platforms, Inc. and affiliates.

// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.
use std::cell::RefCell;
use std::collections::VecDeque;
use std::ffi::{c_uint, c_ulonglong};
use std::io;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;
use std::mem::MaybeUninit;

use anyhow::bail;
use anyhow::Context;
use anyhow::Result;
use libbpf_rs::OpenObject;
use libbpf_rs::ProgramInput;
use libbpf_rs::{RingBuffer, RingBufferBuilder};
use libbpf_rs::skel::OpenSkel;
use log::{debug, info};
use plain::Plain;
use scx_utils::build_id;
use scx_utils::init_libbpf_logging;
use scx_utils::scx_ops_attach;
use scx_utils::scx_ops_open;
use scx_utils::uei_exited;
use scx_utils::uei_report;
use scx_utils::Topology;
use scx_utils::UserExitInfo;
use scx_utils::NR_CPU_IDS;

use crate::bpf_skel::*;
use crate::bpf_intf;
use crate::config::*;

thread_local! {
    static TASK_NOTIFS_CELL: RefCell<VecDeque<bpf_intf::task_notif_msg>> = RefCell::new(VecDeque::with_capacity(8192));
}

unsafe impl Plain for bpf_intf::task_notif_msg {}

/// A builder for creating a new instance of a FrameSched `Scheduler`.
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
    open_object: MaybeUninit<OpenObject>,
    config: Option<String>,
}

impl SchedulerBuilder {
    pub fn new(config: Option<String>) -> SchedulerBuilder {
        Self {
            verbosity: 0,
            shutdown: Arc::new(AtomicBool::new(false)),
            open_object: MaybeUninit::uninit(),
            config,
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
        if *NR_CPU_IDS > bpf_intf::consts_MAX_CPUS as usize {
            bail!("Maximum CPUs {} exceeded: {}", bpf_intf::consts_MAX_CPUS, *NR_CPU_IDS);
        }
        let n_mask_indices = bpf_intf::consts_MAX_CPUS as usize / 64;
        let progs = &mut skel.progs;
        let prog = &mut progs.create_dom_sys;
        for (_, node) in top.nodes.iter() {
            for (_, llc) in node.llcs.iter() {
                let raw_mask = llc.span.clone();
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
                let mut init_ctx = dom_init_ctx {
                    dom_id: llc.id as u32,
                    mask: raw_mask.try_into().unwrap(),
                };

                let input = ProgramInput {
					context_in: Some(unsafe {
						std::slice::from_raw_parts_mut(
							&mut init_ctx as *mut _ as *mut u8,
							std::mem::size_of_val(&init_ctx),
						)
					}),
                    ..Default::default()
                };
                let output = prog.test_run(input)?;
                if output.return_value != 0 {
                    bail!("Failed to create domain {}: {}", llc.id, output.return_value);
                }
            }
        }
        Ok(())
    }

    pub fn build(&mut self) -> Result<Scheduler> {
        // Open the BPF prog first for verification.
        let mut skel_builder = BpfSkelBuilder::default();
        skel_builder.obj_builder.debug(self.verbosity > 0);
        init_libbpf_logging(None);

        let top = Arc::new(Topology::new()?);
        let specs = match &self.config {
            Some(config) => &FrameSchedSpec::parse(config)?,
            None => FrameSchedSpec::default(),
        };


        info!("Running scx_framesched (build ID: {})", *build_id::SCX_FULL_VERSION);
        let mut skel = scx_ops_open!(skel_builder, &mut self.open_object, framesched).unwrap();

        let nr_cpu_ids = *NR_CPU_IDS as u32;

        skel.maps.rodata_data.debug = self.verbosity;
        skel.maps.rodata_data.nr_cpu_ids = nr_cpu_ids;
        skel.maps.pcpu_data.set_max_entries(nr_cpu_ids)?;
        skel.struct_ops.framesched_mut().exit_dump_len = 0;

        let mut nr_dom_ids = 0;
        for (_, node) in top.nodes.iter() {
            for (_, _) in node.llcs.iter() {
                nr_dom_ids += 1;
            }
        }
        skel.maps.rodata_data.nr_dom_ids = nr_dom_ids;
        skel.maps.dom_data.set_max_entries(nr_dom_ids)?;

        for (_, node) in top.nodes.iter() {
            for (id, _) in node.llcs.iter() {
                skel.maps.rodata_data.numa_dom_id_map[*id] = node.id as u32;
            }
        }

        // TODO: Once the libbpf bug is solved with user exit info, also
        // initialize that here.
        let mut skel = skel.load().context("Failed to load BPF program")?;
        Self::create_domains(top.clone(), &mut skel)?;

        let maps = &skel.maps;
        let task_notif_rb = &maps.task_notifier;

        let mut builder = RingBufferBuilder::new();

        fn record_notif_cb(data: &[u8]) -> i32 {
            let record = plain::from_bytes::<bpf_intf::task_notif_msg>(data).expect("ringbuf data was invalid");
            TASK_NOTIFS_CELL.with(|cell| {
                let mut notifs = cell.borrow_mut();
                notifs.push_back(*record);
            });

            // 0 informs libbpf that it can invoke the callback again to provide
            // another sample.
            0
        }
        builder.add(task_notif_rb, record_notif_cb)?;
        let thread_notifier = builder.build()?;

        // Attach.
        let struct_ops = Some(scx_ops_attach!(skel, framesched)?);
        info!("FrameSched scheduler started!");

        Ok(Scheduler {
            skel,
            struct_ops,
            top,
            specs: specs.to_vec(),
            thread_notifier,
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

    /// The vector of matching specifications.
    specs: Vec<FrameSchedSpec>,

    /// Ringbuffer for receiving thread notification events.
    thread_notifier: RingBuffer<'a>,

    /// Whether the scheduler should be shut down.
    shutdown: Arc<AtomicBool>,
}

impl<'a> Scheduler<'a> {
    fn update_task_qos(&mut self, notif: &bpf_intf::task_notif_msg, spec: &FrameSchedSpec) -> Result<()> {
        #[repr(C)]
        struct task_notif_reply {
            pid: c_uint,
            token: c_ulonglong,
            qos: bpf_intf::fs_dl_qos,
        }

        let mut reply = task_notif_reply {
            pid: notif.pid.try_into().unwrap(),
            token: notif.token,
            qos: spec.qos.as_bpf_enum(),
        };

        let input = ProgramInput {
            context_in: Some(unsafe {
                std::slice::from_raw_parts_mut(
                    &mut reply as *mut _ as *mut u8,
                    std::mem::size_of_val(&reply),
                )
            }),
            ..Default::default()
        };
        let progs = &mut self.skel.progs;
        let prog = &mut progs.update_task_qos;
        let output = prog.test_run(input)?;
        if output.return_value != 0 {
            debug!("Failed to set task {} QoS: {}", notif.pid,
                   io::Error::from_raw_os_error(-(output.return_value as i32)));
        }

        Ok(())
    }

    fn drain_task_notifs(&mut self) -> Result<()> {
        self.thread_notifier.poll(Duration::from_secs(1))?;

        TASK_NOTIFS_CELL.with(|cell| {
            let mut notifs = cell.borrow_mut();
            for notif in notifs.drain(..) {
                let pid = &notif.pid;
                let matcher_result = ThreadMatcher::create(*pid);

                match matcher_result {
                    Ok(matcher) => {
                        let mut matched_spec = None;
                        for spec in &self.specs {
                            if spec.matches(&matcher) {
                                matched_spec = Some(spec.clone());
                                break;
                            }
                        }
                        if let Some(spec) = matched_spec {
                            self.update_task_qos(&notif, &spec).expect("Failed to call into bpf");
                        }
                    },
                    Err(e) => debug!("Failed to create matcher for {pid}: {e}"),
                }
            }
        });

        Ok(())
    }

    pub fn run(&mut self) -> Result<UserExitInfo> {
        let mut i = 0;
        while !self.shutdown.load(Ordering::Relaxed) && !uei_exited!(&self.skel, uei) {
            std::thread::sleep(Duration::from_secs(1));
            if let Err(e) = self.drain_task_notifs() {
                info!("Failed to drain notifs: {e}");
                break;
            }
            info!("{i}");
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
