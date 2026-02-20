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

use clap::Parser;

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

// Mirrors enum scx_selftest_id in lib/selftests/selftest.h.
// SCX_SELFTEST_ID_ALL (0) is reserved for "run all" and is not listed in
// TEST_CASES; only the named per-test IDs appear there.
#[repr(u32)]
#[allow(non_camel_case_types)]
enum SelfTestId {
    #[allow(dead_code)]
    SCX_SELFTEST_ID_ALL = 0,
    SCX_SELFTEST_ID_ARENA_TOPOLOGY_TIMER = 1,
    SCX_SELFTEST_ID_ATQ = 2,
    SCX_SELFTEST_ID_DHQ = 3,
    SCX_SELFTEST_ID_BTREE = 4,
    SCX_SELFTEST_ID_LVQUEUE = 5,
    SCX_SELFTEST_ID_MINHEAP = 6,
    SCX_SELFTEST_ID_RBTREE = 7,
    SCX_SELFTEST_ID_TOPOLOGY = 8,
    SCX_SELFTEST_ID_BITMAP = 9,
}

const TEST_CASES: &[(&str, u32)] = &[
    (
        "arena_topology_timer",
        SelfTestId::SCX_SELFTEST_ID_ARENA_TOPOLOGY_TIMER as u32,
    ),
    ("atq", SelfTestId::SCX_SELFTEST_ID_ATQ as u32),
    ("dhq", SelfTestId::SCX_SELFTEST_ID_DHQ as u32),
    ("btree", SelfTestId::SCX_SELFTEST_ID_BTREE as u32),
    ("lvqueue", SelfTestId::SCX_SELFTEST_ID_LVQUEUE as u32),
    ("minheap", SelfTestId::SCX_SELFTEST_ID_MINHEAP as u32),
    ("rbtree", SelfTestId::SCX_SELFTEST_ID_RBTREE as u32),
    ("topology", SelfTestId::SCX_SELFTEST_ID_TOPOLOGY as u32),
    ("bitmap", SelfTestId::SCX_SELFTEST_ID_BITMAP as u32),
];

#[derive(Debug, Parser)]
#[clap(about = "scx_arena library selftests")]
struct Opts {
    /// List all available test cases and exit.
    #[clap(long)]
    list: bool,

    /// Run one or more specific test cases. Multiple names can be given after a
    /// single --test flag (e.g. --test rbtree atq), or the flag can be repeated.
    /// If not specified, all tests are run.
    #[clap(long = "test", value_name = "NAME", num_args(1..))]
    tests: Vec<String>,
}

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
    let prog_fd = skel.progs.arena_selftest.as_fd().as_raw_fd();
    let mut buf = vec![0u8; 4096];
    let name = if stream_id == 1 { "OUTPUT" } else { "ERROR" };
    let mut started = false;

    loop {
        let ret = unsafe {
            libbpf_sys::bpf_prog_stream_read(
                prog_fd,
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

// Run the named test by setting selftest_run_id in the BPF bss and calling
// arena_selftest. The ID comes from enum scx_selftest_id in selftest.h.
fn run_test_by_name(skel: &mut BpfSkel<'_>, name: &str) -> Result<i32> {
    let id = TEST_CASES
        .iter()
        .find(|(n, _)| *n == name)
        .map(|(_, id)| *id)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "Unknown test: '{}'. Use --list to see available tests.",
                name
            )
        })?;

    skel.maps.bss_data.as_mut().unwrap().selftest_run_id = id;

    let input = ProgramInput {
        ..Default::default()
    };
    let output = skel.progs.arena_selftest.test_run(input)?;

    Ok(output.return_value as i32)
}

fn main() {
    TermLogger::init(
        simplelog::LevelFilter::Info,
        SimplelogConfig::default(),
        TerminalMode::Mixed,
        ColorChoice::Auto,
    )
    .unwrap();

    let opts = Opts::parse();

    if opts.list {
        println!("Available test cases:");
        for (name, _) in TEST_CASES {
            println!("  {}", name);
        }
        return;
    }

    // Validate test names before loading BPF.
    for name in &opts.tests {
        if !TEST_CASES.iter().any(|(n, _)| *n == name.as_str()) {
            eprintln!(
                "Unknown test: '{}'. Use --list to see available tests.",
                name
            );
            std::process::exit(1);
        }
    }

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

    let to_run: Vec<&str> = if opts.tests.is_empty() {
        TEST_CASES.iter().map(|(n, _)| *n).collect()
    } else {
        opts.tests.iter().map(String::as_str).collect()
    };

    let mut any_failed = false;
    for &name in &to_run {
        match run_test_by_name(&mut skel, name) {
            Ok(0) => println!("[ PASS ] {}", name),
            Ok(ret) => {
                eprintln!("[ FAIL ] {} (returned {})", name, ret);
                any_failed = true;
            }
            Err(e) => {
                eprintln!("[ FAIL ] {} (error: {})", name, e);
                any_failed = true;
            }
        }

        print_stream(&mut skel, BPF_STDOUT);
        print_stream(&mut skel, BPF_STDERR);
    }

    if any_failed {
        eprintln!("One or more selftests failed.");
        std::process::exit(1);
    } else {
        println!("All selftests passed.");
    }
}
