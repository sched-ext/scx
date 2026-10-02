// Copyright (c) Meta Platforms, Inc. and affiliates.

// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

mod bpf_skel;
use bpf_skel::*;

use std::io::IsTerminal;
use std::mem::MaybeUninit;

use anyhow::{Context, Result, bail};
use clap::Parser;
use libbpf_rs::ProgramInput;
use libbpf_rs::skel::{OpenSkel, Skel, SkelBuilder};
use scx_arena::ScxLibArena;
use scx_utils::{NR_CPU_IDS, init_libbpf_logging};
use simplelog::{ColorChoice, Config as SimplelogConfig, TermLogger, TerminalMode};

const COLOR_BRIGHT_GREEN: &str = "\x1b[92m";
const COLOR_BRIGHT_RED: &str = "\x1b[91m";
const COLOR_RESET: &str = "\x1b[0m";

const SUITES: &[&str] = &["atq", "btree", "lvqueue", "minheap", "rbtree", "topology"];

#[derive(Debug, Parser)]
#[clap(about = "scx_arena library selftests")]
struct Opts {
    #[clap(long)]
    list: bool,

    #[clap(long = "test", value_name = "NAME", num_args(1..))]
    tests: Vec<String>,
}

fn available_tests() -> String {
    SUITES
        .iter()
        .map(|name| format!("  {}", name))
        .collect::<Vec<_>>()
        .join("\n")
}

fn colorize(text: &str, color: &str, is_tty: bool) -> String {
    if is_tty {
        format!("{}{}{}", color, text, COLOR_RESET)
    } else {
        text.to_string()
    }
}

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
        _ => bail!("unknown test: {}", name),
    })
}

fn run_test(skel: &BpfSkel<'_>, name: &str) -> Result<i32> {
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
    init_libbpf_logging(Some(libbpf_rs::PrintLevel::Debug));

    let mut open = builder
        .open(&mut open_object)
        .context("Failed to open BPF program")
        .unwrap();
    open.maps.rodata_data.as_mut().unwrap().nr_cpu_ids = *NR_CPU_IDS as u32;
    let skel = open.load().context("Failed to load BPF program").unwrap();

    let _arena = ScxLibArena::setup(skel.object(), 42, 0, *NR_CPU_IDS)
        .context("Failed to set up arena")
        .unwrap();

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

    for name in to_run {
        match run_test(&skel, name) {
            Ok(0) => println!("{} {}", pass_label, name),
            Ok(ret) => {
                eprintln!("{} {} (returned {})", fail_label, name, ret);
                any_failed = true;
            }
            Err(err) => {
                eprintln!("{} {} ({})", fail_label, name, err);
                any_failed = true;
            }
        }
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
    }
    println!(
        "{}",
        colorize("All selftests passed.", COLOR_BRIGHT_GREEN, stdout_tty)
    );
}
