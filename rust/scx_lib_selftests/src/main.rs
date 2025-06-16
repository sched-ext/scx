// Copyright (c) Meta Platforms, Inc. and affiliates.

// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.
mod bpf_skel;
pub use bpf_skel::*;

use std::mem::MaybeUninit;

use anyhow::Context;

use scx_utils::init_libbpf_logging;

use libbpf_rs::ProgramInput;
use libbpf_rs::skel::OpenSkel;
use libbpf_rs::skel::SkelBuilder;

fn main() {
    let mut open_object = MaybeUninit::uninit();
    let mut builder = BpfSkelBuilder::default();

    builder.obj_builder.debug(true);
    init_libbpf_logging(None);

    let skel = builder
        .open(&mut open_object)
        .context("Failed to open BPF program")
        .unwrap();
    let skel = skel.load().context("Failed to load BPF program").unwrap();

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
