// Copyright (c) Meta Platforms, Inc. and affiliates.

// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.
pub mod bpf_intf;

mod bpf_skel;
pub use bpf_skel::*;

pub use scx_utils::CoreType;
use scx_utils::Topology;
pub use scx_utils::NR_CPU_IDS;
use scx_utils::{Core, Llc};

use std::ffi::c_ulong;

use anyhow::{bail, Result};
use clap::Parser;
use libbpf_rs::ProgramInput;
use libbpf_rs::ProgramOutput;

use std::sync::Arc;

lazy_static::lazy_static! {
        pub static ref TOPO: Topology = Topology::new().unwrap();
}

fn get_default_greedy_disable() -> bool {
    TOPO.all_llcs.len() > 1
}

fn get_default_llc_runs() -> u64 {
    let n_llcs = TOPO.all_llcs.len() as f64;
    let llc_runs = n_llcs.log2();
    llc_runs as u64
}

#[derive(Debug, Parser)]
pub struct SchedulerOpts {
    /// Disables per-cpu kthreads directly dispatched into local dsqs.
    #[clap(short = 'k', long, action = clap::ArgAction::SetTrue)]
    pub disable_kthreads_local: bool,

    /// Enables autoslice tuning
    #[clap(short = 'a', long, action = clap::ArgAction::SetTrue)]
    pub autoslice: bool,

    /// Ratio of interactive tasks for autoslice tuning, percent value from 1-99.
    #[clap(short = 'r', long, default_value = "10")]
    pub interactive_ratio: usize,

    /// Disables eager pick2 load balancing.
    #[clap(short = 'e', long, action = clap::ArgAction::SetTrue)]
    pub eager_load_balance: bool,

    /// Enables CPU frequency control.
    #[clap(short = 'f', long, action = clap::ArgAction::SetTrue)]
    pub freq_control: bool,

    /// ***DEPRECATED*** Disables greedy idle CPU selection, may cause better load balancing on
    /// multi-LLC systems.
    #[clap(short = 'g', long, default_value_t = get_default_greedy_disable(), action = clap::ArgAction::Set)]
    pub greedy_idle_disable: bool,

    /// Interactive tasks stay sticky to their CPU if no idle CPU is found.
    #[clap(short = 'y', long, action = clap::ArgAction::SetTrue)]
    pub interactive_sticky: bool,

    /// Interactive tasks are FIFO scheduled
    #[clap(long, action = clap::ArgAction::SetTrue)]
    pub interactive_fifo: bool,

    /// Disables pick2 load balancing on the dispatch path.
    #[clap(short = 'd', long, action = clap::ArgAction::SetTrue)]
    pub dispatch_pick2_disable: bool,

    /// Enables pick2 load balancing on the dispatch path when LLC utilization is under the
    /// specified utilization.
    #[clap(long, default_value = "75", value_parser = clap::value_parser!(u64).range(0..100))]
    pub dispatch_lb_busy: u64,

    /// Enables pick2 load balancing on the dispatch path for interactive tasks.
    #[clap(long, action = clap::ArgAction::SetTrue)]
    pub dispatch_lb_interactive: bool,

    /// Enable tasks to run beyond their timeslice if the CPU is idle.
    #[clap(long, action = clap::ArgAction::SetTrue)]
    pub keep_running: bool,

    /// Minimum load for load balancing on the wakeup path, 0 to disable.
    #[clap(long, default_value = "0", value_parser = clap::value_parser!(u64).range(0..99))]
    pub wakeup_lb_busy: u64,

    /// Allow LLC migrations on the wakeup path.
    #[clap(long, action = clap::ArgAction::SetTrue)]
    pub wakeup_llc_migrations: bool,

    /// Allow selecting idle in enqueue path.
    #[clap(long, action = clap::ArgAction::SetTrue)]
    pub select_idle_in_enqueue: bool,

    /// Set idle QoS resume latency based in microseconds.
    #[clap(long)]
    pub idle_resume_us: Option<u32>,

    /// Only pick2 load balance from the max DSQ.
    #[clap(long, default_value="false", action = clap::ArgAction::Set)]
    pub max_dsq_pick2: bool,

    /// Scheduling min slice duration in microseconds.
    #[clap(short = 's', long, default_value = "100")]
    pub min_slice_us: u64,

    /// Slack factor for load balancing, load balancing is not performed if load is within slack
    /// factor percent.
    #[clap(long, default_value = "5", value_parser = clap::value_parser!(u64).range(0..99))]
    pub lb_slack_factor: u64,

    /// Number of runs on the LLC before a task becomes eligbile for pick2 migration on the wakeup
    /// path.
    #[clap(short = 'l', long, default_value_t = get_default_llc_runs())]
    pub min_llc_runs_pick2: u64,

    /// Manual definition of slice intervals in microseconds for DSQs, must be equal to number of
    /// dumb_queues.
    #[clap(short = 't', long, value_parser = clap::value_parser!(u64), default_values_t = [0;0])]
    pub dsq_time_slices: Vec<u64>,

    /// DSQ scaling shift, each queue min timeslice is shifted by the scaling shift.
    #[clap(short = 'x', long, default_value = "4")]
    pub dsq_shift: u64,

    /// Minimum number of queued tasks to use pick2 balancing, 0 to always enabled.
    #[clap(short = 'm', long, default_value = "0")]
    pub min_nr_queued_pick2: u32,

    /// Number of dumb DSQs.
    #[clap(short = 'q', long, default_value = "3")]
    pub dumb_queues: usize,

    /// Initial DSQ for tasks.
    #[clap(short = 'i', long, default_value = "0")]
    pub init_dsq_index: usize,
}

pub fn dsq_slice_ns(dsq_index: u64, min_slice_us: u64, dsq_shift: u64) -> u64 {
    let result = if dsq_index == 0 {
        1000 * min_slice_us
    } else {
        1000 * (min_slice_us << (dsq_index as u32) << dsq_shift)
    };
    result
}

/// Trait for interfacing with BPF arena programs
pub trait P2dqArenaProgs {
    /// Run the arena initialization program and return the result
    fn run_arena_init<'a>(&self, input: ProgramInput<'a>) -> Result<ProgramOutput<'a>>;

    /// Run the allocation mask program and return the result
    fn run_alloc_mask<'a>(&self, input: ProgramInput<'a>) -> Result<ProgramOutput<'a>>;

    /// Run the topology node initialization program and return the result
    fn run_topology_node_init<'a>(&self, input: ProgramInput<'a>) -> Result<ProgramOutput<'a>>;

    /// Access to the setup pointer in BSS data
    fn setup_ptr(&self) -> u64;
}

pub fn setup_arenas<T: P2dqArenaProgs>(skel: &T) -> Result<()> {
    // Allocate the arena memory from the BPF side so userspace initializes it before starting
    // the scheduler. Despite the function call's name this is neither a test nor a test run,
    // it's the recommended way of executing SEC("syscall") probes.

    let mut args = types::arena_init_args {
        static_pages: bpf_intf::consts_STATIC_ALLOC_PAGES_GRANULARITY as c_ulong,
        task_ctx_size: std::mem::size_of::<types::task_p2dq>() as c_ulong,
    };

    let input = ProgramInput {
        context_in: Some(unsafe {
            std::slice::from_raw_parts_mut(
                &mut args as *mut _ as *mut u8,
                std::mem::size_of_val(&args),
            )
        }),
        ..Default::default()
    };

    let output = skel.run_arena_init(input)?;
    if output.return_value != 0 {
        bail!(
            "Could not initialize arenas, p2dq_setup returned {}",
            output.return_value as i32
        );
    }

    Ok(())
}

fn setup_topology_node<T: P2dqArenaProgs>(skel: &T, mask: &[u64]) -> Result<()> {
    // Copy the address of ptr to the kernel to populate it from BPF with the arena pointer.
    let input = ProgramInput {
        ..Default::default()
    };

    let output = skel.run_alloc_mask(input)?;
    if output.return_value != 0 {
        bail!(
            "Could not initialize arenas, setup_topology_node returned {}",
            output.return_value as i32
        );
    }

    let ptr = unsafe { std::mem::transmute::<u64, &mut [u64; 10]>(skel.setup_ptr()) };

    let (valid_mask, _) = ptr.split_at_mut(mask.len());
    valid_mask.clone_from_slice(mask);

    let input = ProgramInput {
        ..Default::default()
    };
    let output = skel.run_topology_node_init(input)?;
    if output.return_value != 0 {
        bail!(
            "p2dq_topology_node_init returned {}",
            output.return_value as i32
        );
    }

    Ok(())
}

pub fn setup_topology<T: P2dqArenaProgs>(skel: &T) -> Result<()> {
    let topo = Topology::new().expect("Failed to build host topology");

    setup_topology_node(skel, topo.span.as_raw_slice())?;

    for (_, node) in topo.nodes {
        setup_topology_node(skel, node.span.as_raw_slice())?;
    }

    for (_, llc) in topo.all_llcs {
        setup_topology_node(
            skel,
            Arc::<Llc>::into_inner(llc)
                .expect("missing llc")
                .span
                .as_raw_slice(),
        )?;
    }

    for (_, core) in topo.all_cores {
        setup_topology_node(
            skel,
            Arc::<Core>::into_inner(core)
                .expect("missing core")
                .span
                .as_raw_slice(),
        )?;
    }
    for (_, cpu) in topo.all_cpus {
        let mut mask = [0; 9];
        mask[cpu.id.checked_shr(64).unwrap_or(0)] |= 1 << (cpu.id % 64);
        setup_topology_node(skel, &mask)?;
    }

    Ok(())
}

#[macro_export]
macro_rules! init_open_skel {
    ($skel: expr, $opts: expr, $verbose: expr) => {
        'block: {
            let opts: &$crate::SchedulerOpts = $opts;
            let verbose: u8 = $verbose;

            if opts.init_dsq_index > opts.dumb_queues - 1 {
                break 'block ::anyhow::Result::Err(::anyhow::anyhow!(
                    "Invalid init_dsq_index {}",
                    opts.init_dsq_index
                ));
            }
            if opts.dsq_time_slices.len() > 0 {
                if opts.dsq_time_slices.len() != opts.dumb_queues {
                    break 'block ::anyhow::Result::Err(::anyhow::anyhow!(
                        "Invalid number of dsq_time_slices, got {} need {}",
                        opts.dsq_time_slices.len(),
                        opts.dumb_queues,
                    ));
                }
                for vals in opts.dsq_time_slices.windows(2) {
                    if vals[0] >= vals[1] {
                        break 'block ::anyhow::Result::Err(::anyhow::anyhow!(
                            "DSQ time slices must be in increasing order"
                        ));
                    }
                }
                for (i, slice) in opts.dsq_time_slices.iter().enumerate() {
                    ::log::info!("DSQ[{}] slice_ns {}", i, slice * 1000);
                    $skel.maps.bss_data.dsq_time_slices[i] = slice * 1000;
                }
            } else {
                for i in 0..=opts.dumb_queues - 1 {
                    let slice_ns =
                        $crate::dsq_slice_ns(i as u64, opts.min_slice_us, opts.dsq_shift);
                    ::log::info!("DSQ[{}] slice_ns {}", i, slice_ns);
                    $skel.maps.bss_data.dsq_time_slices[i] = slice_ns;
                }
            }
            if opts.autoslice {
                if opts.interactive_ratio == 0 || opts.interactive_ratio > 99 {
                    break 'block ::anyhow::Result::Err(::anyhow::anyhow!(
                        "Invalid interactive_ratio {}, must be between 1-99",
                        opts.interactive_ratio
                    ));
                }
            }

            $skel.maps.rodata_data.interactive_ratio = opts.interactive_ratio as u32;
            $skel.maps.rodata_data.min_slice_us = opts.min_slice_us;
            $skel.maps.rodata_data.min_nr_queued_pick2 = opts.min_nr_queued_pick2;
            $skel.maps.rodata_data.min_llc_runs_pick2 = opts.min_llc_runs_pick2;
            $skel.maps.rodata_data.dsq_shift = opts.dsq_shift as u64;
            $skel.maps.rodata_data.kthreads_local = !opts.disable_kthreads_local;
            $skel.maps.rodata_data.nr_cpus = *$crate::NR_CPU_IDS as u32;
            $skel.maps.rodata_data.nr_dsqs_per_llc = opts.dumb_queues as u32;
            $skel.maps.rodata_data.init_dsq_index = opts.init_dsq_index as i32;
            $skel.maps.rodata_data.nr_llcs = $crate::TOPO.all_llcs.clone().keys().len() as u32;
            $skel.maps.rodata_data.nr_nodes = $crate::TOPO.nodes.clone().keys().len() as u32;
            $skel.maps.rodata_data.lb_slack_factor = opts.lb_slack_factor;

            $skel.maps.rodata_data.autoslice = opts.autoslice;
            $skel.maps.rodata_data.debug = verbose as u32;
            $skel.maps.rodata_data.dispatch_pick2_disable = opts.dispatch_pick2_disable;
            $skel.maps.rodata_data.dispatch_lb_busy = opts.dispatch_lb_busy;
            $skel.maps.rodata_data.dispatch_lb_interactive = opts.dispatch_lb_interactive;
            $skel.maps.rodata_data.eager_load_balance = !opts.eager_load_balance;
            $skel.maps.rodata_data.freq_control = opts.freq_control;
            $skel.maps.rodata_data.has_little_cores = $crate::TOPO.has_little_cores();
            $skel.maps.rodata_data.interactive_sticky = opts.interactive_sticky;
            $skel.maps.rodata_data.interactive_fifo = opts.interactive_fifo;
            $skel.maps.rodata_data.keep_running_enabled = opts.keep_running;
            $skel.maps.rodata_data.max_dsq_pick2 = opts.max_dsq_pick2;
            $skel.maps.rodata_data.smt_enabled = $crate::TOPO.smt_enabled;
            $skel.maps.rodata_data.select_idle_in_enqueue = opts.select_idle_in_enqueue;
            $skel.maps.rodata_data.wakeup_lb_busy = opts.wakeup_lb_busy;
            $skel.maps.rodata_data.wakeup_llc_migrations = opts.wakeup_llc_migrations;
            $skel.maps.rodata_data.max_exec_ns =
                2 * $skel.maps.bss_data.dsq_time_slices[opts.dumb_queues - 1];

            Ok(())
        }
    };
}

#[macro_export]
macro_rules! init_skel {
    ($skel: expr) => {
        for cpu in $crate::TOPO.all_cpus.values() {
            $skel.maps.bss_data.big_core_ids[cpu.id] =
                if cpu.core_type == ($crate::CoreType::Big { turbo: true }) {
                    1
                } else {
                    0
                };
            $skel.maps.bss_data.cpu_llc_ids[cpu.id] = cpu.llc_id as u64;
            $skel.maps.bss_data.cpu_node_ids[cpu.id] = cpu.node_id as u64;
        }

        $crate::setup_arenas($skel)?;
        $crate::setup_topology($skel)?;
    };
}

pub mod bpf_srcs {

    pub fn intf_h() -> &'static [u8] {
        const INTF_H: &'static [u8] =
            include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf/intf.h"));

        INTF_H
    }

    pub fn main_bpf_c() -> &'static [u8] {
        const MAIN_BPF_C: &'static [u8] =
            include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf/main.bpf.c"));

        MAIN_BPF_C
    }

    pub fn types_h() -> &'static [u8] {
        const TYPES_H: &'static [u8] =
            include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf/types.h"));

        TYPES_H
    }
}
