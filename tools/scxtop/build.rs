// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

fn main() {
    println!("cargo::rerun-if-changed=src/protos/perfetto_scx.proto");
    protobuf_codegen::Codegen::new()
        .pure()
        .cargo_out_dir("protos_gen/")
        .input("src/protos/perfetto_scx.proto")
        .include("src/protos")
        .run_from_script();
    scx_utils::BpfBuilder::new()
        .unwrap()
        .enable_intf("src/bpf/intf.h", "bpf_intf.rs")
        .enable_skel("src/bpf/main.bpf.c", "bpf")
        .compile_link_gen()
        .unwrap();
}
