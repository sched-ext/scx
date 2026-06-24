// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

fn main() {
    scx_cargo::BpfBuilder::new()
        .expect("BpfBuilder creation returned error")
        .enable_intf("src/bpf/intf_rust.h", "bpf_intf.rs")
        .enable_skel("src/bpf/mitosis.bpf.c", "bpf")
        .build()
        .expect("BpfBuilder build returned error");
}
