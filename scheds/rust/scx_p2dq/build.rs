// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

fn main() {
    scx_utils::BpfBuilder::new()
        .unwrap()
        .enable_intf("src/bpf/intf.h", "bpf_intf.rs")
        .enable_skel("src/bpf/main.bpf.c", "bpf")
        .add_source("src/bpf/lib/sdt_task.bpf.c")
        .add_source("src/bpf/lib/sdt_alloc.bpf.c")
        .add_source("src/bpf/lib/bitmap.bpf.c")
        .add_source("src/bpf/lib/cpumask.bpf.c")
        .add_source("src/bpf/lib/topology.bpf.c")
        .add_source("src/bpf/lib/arena.bpf.c")
        .compile_link_gen()
        .unwrap();
}
