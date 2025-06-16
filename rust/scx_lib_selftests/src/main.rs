// Copyright (c) Meta Platforms, Inc. and affiliates.

// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.
mod bpf_skel;
pub use bpf_skel::*;

use std::mem::MaybeUninit;

use anyhow::Context;
use anyhow::Result;
use anyhow::bail;

use std::ffi::c_ulong;

use scx_utils::NR_CPU_IDS;
use scx_utils::init_libbpf_logging;

use libbpf_rs::PrintLevel;
use libbpf_rs::skel::OpenSkel;
use libbpf_rs::skel::SkelBuilder;
use libbpf_rs::ProgramInput;

fn setup_arenas(skel: &mut BpfSkel<'_>) -> Result<()> {
    const STATIC_ALLOC_PAGES_GRANULARITY: c_ulong = 1;
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
            "Could not initialize arenas, p2dq_setup returned {}",
            output.return_value as i32
        );
    }

    Ok(())
}

fn main() {
    let mut open_object = MaybeUninit::uninit();
    let mut builder = BpfSkelBuilder::default();

    builder.obj_builder.debug(true);
    init_libbpf_logging(Some(PrintLevel::Debug));

    let skel = builder
        .open(&mut open_object)
        .context("Failed to open BPF program")
        .unwrap();

    skel.maps.rodata_data.nr_cpu_ids = *NR_CPU_IDS as u32;

    let mut skel = skel.load().context("Failed to load BPF program").unwrap();

    setup_arenas(&mut skel).unwrap();

    let input = ProgramInput {
        ..Default::default()
    };

    let output = skel.progs.arena_selftest.test_run(input).unwrap();
    if output.return_value != 0 {
        println!(
            "Selftest returned {}, please check bpf tracelog for more details.",
            output.return_value as i32
        );
    }
}
