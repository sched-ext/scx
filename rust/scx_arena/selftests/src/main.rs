// Copyright (c) Meta Platforms, Inc. and affiliates.

// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.
mod bpf_skel;
pub use bpf_skel::*;

use std::mem::MaybeUninit;

use anyhow::bail;
use anyhow::Context;
use anyhow::Result;

use std::ffi::c_ulong;
use std::ffi::c_void;

use std::os::fd::AsFd;
use std::os::fd::AsRawFd;
use std::sync::Arc;

use scx_utils::init_libbpf_logging;
use scx_utils::Core;
use scx_utils::Llc;
use scx_utils::Topology;
use scx_utils::NR_CPU_IDS;

use simplelog::{ColorChoice, Config as SimplelogConfig, TermLogger, TerminalMode};

use libbpf_rs::libbpf_sys;

use libbpf_rs::skel::OpenSkel;
use libbpf_rs::skel::SkelBuilder;
use libbpf_rs::PrintLevel;
use libbpf_rs::ProgramInput;

const BPF_STDOUT: u32 = 1;
const BPF_STDERR: u32 = 2;

fn setup_arenas(skel: &mut BpfSkel<'_>) -> Result<()> {
    const STATIC_ALLOC_PAGES_GRANULARITY: c_ulong = 512;
    const TASK_SIZE: c_ulong = 42;

    // Allocate the arena memory from the BPF side so userspace initializes it before starting
    // the scheduler. Despite the function call's name this is neither a test nor a test run,
    // it's the recommended way of executing SEC("syscall") probes.
    let mut args = types::arena_init_args {
        static_pages: STATIC_ALLOC_PAGES_GRANULARITY,
        task_ctx_size: TASK_SIZE,
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

    let output = skel.progs.arena_init.test_run(input)?;
    if output.return_value != 0 {
        bail!(
            "Could not initialize arenas, arena_init returned {}",
            output.return_value as i32
        );
    }

    Ok(())
}

fn setup_topology_node(skel: &mut BpfSkel<'_>, mask: &[u64]) -> Result<()> {
    let mut args = types::arena_alloc_mask_args {
        bitmap: 0 as c_ulong,
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

    let output = skel.progs.arena_alloc_mask.test_run(input)?;
    if output.return_value != 0 {
        bail!(
            "Could not initialize arenas, setup_topology_node returned {}",
            output.return_value as i32
        );
    }

    let ptr = unsafe {
        &mut *std::ptr::with_exposed_provenance_mut::<[u64; 10]>(args.bitmap.try_into().unwrap())
    };

    let (valid_mask, _) = ptr.split_at_mut(mask.len());
    valid_mask.clone_from_slice(mask);

    let mut args = types::arena_topology_node_init_args {
        bitmap: args.bitmap as c_ulong,
        data_size: 0 as c_ulong,
        id: 0 as c_ulong,
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

    let output = skel.progs.arena_topology_node_init.test_run(input)?;
    if output.return_value != 0 {
        bail!(
            "arena_topology_node_init returned {}",
            output.return_value as i32
        );
    }

    Ok(())
}

fn setup_topology(skel: &mut BpfSkel<'_>) -> Result<()> {
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

fn print_stream(skel: &mut BpfSkel<'_>, stream_id: u32) -> () {
    let mut buf = vec![0u8; 4096];
    let name = if stream_id == 1 { "OUTPUT" } else { "ERROR" };
    let mut started = false;

    loop {
        let ret = unsafe {
            libbpf_sys::bpf_prog_stream_read(
                skel.progs.arena_selftest.as_fd().as_raw_fd(),
                stream_id,
                buf.as_mut_ptr() as *mut c_void,
                buf.len() as u32,
                std::ptr::null_mut(),
            )
        };
        if ret < 0 {
            eprintln!("STREAM {} UNAVAILABLE (REQUIRES >= v6.17)", name);
            return;
        }

        if !started {
            println!("===BEGIN STREAM {}===", name);
            started = true;
        }

        if ret == 0 {
            break;
        }

        print!("{}", String::from_utf8_lossy(&buf[..ret as usize]));
    }

    println!("\n====END STREAM  {}====", name);
}

fn main() {
    TermLogger::init(
        simplelog::LevelFilter::Info,
        SimplelogConfig::default(),
        TerminalMode::Mixed,
        ColorChoice::Auto,
    )
    .unwrap();

    let mut open_object = MaybeUninit::uninit();
    let mut builder = BpfSkelBuilder::default();

    builder.obj_builder.debug(true);
    init_libbpf_logging(Some(PrintLevel::Debug));

    let mut skel = builder
        .open(&mut open_object)
        .context("Failed to open BPF program")
        .unwrap();

    skel.maps.rodata_data.as_mut().unwrap().nr_cpu_ids = *NR_CPU_IDS as u32;

    let mut skel = skel.load().context("Failed to load BPF program").unwrap();

    setup_arenas(&mut skel).unwrap();
    setup_topology(&mut skel).unwrap();

    let input = ProgramInput {
        ..Default::default()
    };

    let output = skel.progs.arena_selftest.test_run(input).unwrap();
    if output.return_value != 0 {
        eprintln!(
            "Selftest returned {}, please check bpf tracelog for more details.",
            output.return_value as i32
        );
    } else {
        println!("Selftest successful.");
    }

    print_stream(&mut skel, BPF_STDOUT);
    print_stream(&mut skel, BPF_STDERR);
}
