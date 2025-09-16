// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

fn main() {
    scx_cargo::BpfBuilder::new()
        .unwrap()
        .enable_intf("src/bpf/intf.h", "bpf_intf.rs")
        .enable_skel("src/bpf/main.bpf.c", "bpf")
        .add_source("src/bpf/timer.bpf.c")
        .add_source("src/bpf/util.bpf.c")
        .add_source("src/bpf/lib/pmu.bpf.c")
        .compile_link_gen()
        .unwrap();
}
