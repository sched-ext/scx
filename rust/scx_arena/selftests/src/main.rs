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
use std::ffi::c_void;
use std::io::IsTerminal;

use std::os::fd::AsFd;
use std::os::fd::AsRawFd;
use std::sync::Arc;

use clap::Parser;

use scx_utils::Core;
use scx_utils::Llc;
use scx_utils::NR_CPU_IDS;
use scx_utils::Topology;
use scx_utils::init_libbpf_logging;

use simplelog::{ColorChoice, Config as SimplelogConfig, TermLogger, TerminalMode};

use libbpf_rs::libbpf_sys;

use libbpf_rs::PrintLevel;
use libbpf_rs::ProgramInput;
use libbpf_rs::skel::OpenSkel;
use libbpf_rs::skel::SkelBuilder;

const BPF_STDOUT: u32 = 1;
const BPF_STDERR: u32 = 2;

const COLOR_BRIGHT_GREEN: &str = "\x1b[92m";
const COLOR_BRIGHT_RED: &str = "\x1b[91m";
const COLOR_RESET: &str = "\x1b[0m";

fn colorize(text: &str, color: &str, is_tty: bool) -> String {
    if is_tty {
        format!("{}{}{}", color, text, COLOR_RESET)
    } else {
        text.to_string()
    }
}

fn available_tests() -> String {
    SUITES
        .iter()
        .map(|name| format!("  {}", name))
        .collect::<Vec<_>>()
        .join("\n")
}

/*
 * Names of the per-suite BPF programs. Each suite is its own SEC("syscall")
 * program, arena_selftest_<name>, so that no call frame is spent on a
 * dispatcher: the arena allocator leaves very few of the verifier's eight.
 */
const SUITES: &[&str] = &["atq", "btree", "lvqueue", "minheap", "rbtree", "topology"];

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
    const TASK_SIZE: c_ulong = 42;

    // arena_init() allocates per-CPU bitmaps from the buddy allocator.
    let output = skel
        .progs
        .arena_buddy_reset
        .test_run(ProgramInput::default())?;
    if output.return_value != 0 {
        bail!(
            "Could not initialize libarena buddy allocator: {}",
            output.return_value as i32
        );
    }

    // Allocate the arena memory from the BPF side so userspace initializes it before starting
    // the scheduler. Despite the function call's name this is neither a test nor a test run,
    // it's the recommended way of executing SEC("syscall") probes.
    let mut args = types::arena_init_args {
        task_ctx_size: TASK_SIZE,
        task_ctx_align: 0,
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

/// Number of u64 words in a mask of `nr_cpus` bits. The BPF side allocates its
/// bitmaps to exactly this size, so userspace must not write past it.
fn nr_cpumask_words(nr_cpus: usize) -> usize {
    nr_cpus.div_ceil(64)
}

fn setup_topology_node(skel: &mut BpfSkel<'_>, nr_cpus: usize, mask: &[u64]) -> Result<()> {
    let nr_words = nr_cpumask_words(nr_cpus);
    if mask.len() < nr_words {
        bail!(
            "CPU mask has {} words, expected at least {}",
            mask.len(),
            nr_words
        );
    }
    let mask = &mask[..nr_words];

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

    let valid_mask = unsafe {
        std::slice::from_raw_parts_mut(
            std::ptr::with_exposed_provenance_mut::<u64>(args.bitmap.try_into().unwrap()),
            nr_words,
        )
    };
    valid_mask.copy_from_slice(mask);

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
    let nr_cpus = *NR_CPU_IDS;
    let topo = Topology::new().expect("Failed to build host topology");

    // Set per-level max children before registering any topology nodes.
    // NOTE: rust/scx_arena/scx_arena/src/arenalib.rs::setup_topology_max_children()
    // contains equivalent logic and must be kept in sync with this block.
    let max_children: [u32; 5] = [
        topo.nodes.len() as u32,
        topo.nodes.values().map(|n| n.llcs.len()).max().unwrap_or(0) as u32,
        topo.all_llcs
            .values()
            .map(|l| l.cores.len())
            .max()
            .unwrap_or(0) as u32,
        topo.all_cores
            .values()
            .map(|c| c.cpus.len())
            .max()
            .unwrap_or(0) as u32,
        0,
    ];
    let mut init_args = types::arena_topology_init_args { max_children };
    let init_input = ProgramInput {
        context_in: Some(unsafe {
            std::slice::from_raw_parts_mut(
                &mut init_args as *mut _ as *mut u8,
                std::mem::size_of_val(&init_args),
            )
        }),
        ..Default::default()
    };
    let output = skel.progs.arena_topology_init.test_run(init_input)?;
    if output.return_value != 0 {
        bail!(
            "arena_topology_init returned {}",
            output.return_value as i32
        );
    }

    setup_topology_node(skel, nr_cpus, topo.span.as_raw_slice())?;

    for (_, node) in topo.nodes {
        setup_topology_node(skel, nr_cpus, node.span.as_raw_slice())?;
    }

    for (_, llc) in topo.all_llcs {
        setup_topology_node(
            skel,
            nr_cpus,
            Arc::<Llc>::into_inner(llc)
                .expect("missing llc")
                .span
                .as_raw_slice(),
        )?;
    }

    for (_, core) in topo.all_cores {
        setup_topology_node(
            skel,
            nr_cpus,
            Arc::<Core>::into_inner(core)
                .expect("missing core")
                .span
                .as_raw_slice(),
        )?;
    }
    for (_, cpu) in topo.all_cpus {
        let mut mask = vec![0; nr_cpumask_words(nr_cpus)];
        mask[cpu.id / 64] |= 1 << (cpu.id % 64);
        setup_topology_node(skel, nr_cpus, &mask)?;
    }

    Ok(())
}

fn print_stream(skel: &BpfSkel<'_>, suite: &str, stream_id: u32) {
    let Ok(prog) = suite_prog(skel, suite) else {
        return;
    };
    let prog_fd = prog.as_fd().as_raw_fd();
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

/* Resolve a suite name to its per-suite BPF program. */
fn suite_prog<'a, 'obj>(
    skel: &'a BpfSkel<'obj>,
    name: &str,
) -> Result<&'a libbpf_rs::ProgramMut<'obj>> {
    Ok(match name {
        "atq" => &skel.progs.arena_selftest_atq,
        "btree" => &skel.progs.arena_selftest_btree,
        "lvqueue" => &skel.progs.arena_selftest_lvqueue,
        "minheap" => &skel.progs.arena_selftest_minheap,
        "rbtree" => &skel.progs.arena_selftest_rbtree,
        "topology" => &skel.progs.arena_selftest_topology,
        _ => bail!(
            "Unknown test: '{}'. Use --list to see available tests.",
            name
        ),
    })
}

/* Run one suite by invoking its own program. */
fn run_test_by_name(skel: &BpfSkel<'_>, name: &str) -> Result<i32> {
    let output = suite_prog(skel, name)?.test_run(ProgramInput::default())?;

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
        println!("Available test cases:\n{}", available_tests());
        return;
    }

    // Validate test names before loading BPF.
    for name in &opts.tests {
        if !SUITES.contains(&name.as_str()) {
            eprintln!(
                "Unknown test: '{}'.\nAvailable tests:\n{}",
                name,
                available_tests()
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
        SUITES.to_vec()
    } else {
        opts.tests.iter().map(String::as_str).collect()
    };

    let stdout_tty = std::io::stdout().is_terminal();
    let stderr_tty = std::io::stderr().is_terminal();
    let pass_label = colorize("[ PASS ]", COLOR_BRIGHT_GREEN, stdout_tty);
    let fail_label = colorize("[ FAIL ]", COLOR_BRIGHT_RED, stderr_tty);

    let mut any_failed = false;
    for &name in &to_run {
        match run_test_by_name(&skel, name) {
            Ok(0) => println!("{} {}", pass_label, name),
            Ok(ret) => {
                eprintln!("{} {} (returned {})", fail_label, name, ret);
                any_failed = true;
            }
            Err(e) => {
                eprintln!("{} {} (error: {})", fail_label, name, e);
                any_failed = true;
            }
        }

        print_stream(&skel, name, BPF_STDOUT);
        print_stream(&skel, name, BPF_STDERR);
    }

    if any_failed {
        eprintln!(
            "{}",
            colorize(
                "One or more selftests failed.",
                COLOR_BRIGHT_RED,
                stderr_tty
            )
        );
        std::process::exit(1);
    } else {
        println!(
            "{}",
            colorize("All selftests passed.", COLOR_BRIGHT_GREEN, stdout_tty)
        );
    }
}
