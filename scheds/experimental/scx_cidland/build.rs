// Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

fn main() {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let libarena_include = std::path::Path::new(&manifest_dir).join("../../../libarena/include");

    scx_cargo::BpfBuilder::new()
        .unwrap()
        .add_include_path(libarena_include.to_str().unwrap())
        .add_cflag("-DENABLE_ATOMICS_TESTS")
        .enable_intf("src/bpf/intf.h", "bpf_intf.rs")
        .enable_skel("src/bpf/main.bpf.c", "bpf")
        .add_source("../../../libarena/src/buddy.bpf.c")
        .add_source("../../../libarena/src/common.bpf.c")
        .add_source("src/bpf/lib/sdt_task.bpf.c")
        .add_source("src/bpf/lib/urcu.bpf.c")
        .compile_link_gen()
        .unwrap();
}
