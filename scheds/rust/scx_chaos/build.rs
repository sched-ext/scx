// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

fn main() {
    // TODO: The BpfBuilder appears to assume only files in the crate are relevant to building,
    // meaning chaos won't rebuild if p2dq sources change. This is fine for now as the CI should
    // catch anything obvious with a clean build.
    scx_utils::BpfBuilder::new()
        .unwrap()
        .enable_intf("src/bpf/intf.h", "bpf_intf.rs")
        .enable_skel("src/bpf/main.bpf.c", "bpf")
        .compile_link_gen()
        .unwrap();
}
