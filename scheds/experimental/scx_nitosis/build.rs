// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

fn main() {
    scx_cargo::BpfBuilder::new()
        .expect("BpfBuilder creation returned error")
        .enable_intf("src/bpf/intf.h", "bpf_intf.rs")
        .enable_skel("src/bpf/mitosis.bpf.c", "bpf")
        // arena.bpf.c's arena_init() calls into rbtree and atq, so those two
        // ride along even though nothing here uses them directly yet.
        .add_source("src/bpf/lib/arena.bpf.c")
        .add_source("src/bpf/lib/atq.bpf.c")
        .add_source("src/bpf/lib/common.bpf.c")
        .add_source("src/bpf/lib/bitmap.bpf.c")
        .add_source("src/bpf/lib/cpumask.bpf.c")
        .add_source("src/bpf/lib/rbtree.bpf.c")
        .add_source("src/bpf/lib/sdt_alloc.bpf.c")
        .add_source("src/bpf/lib/sdt_cgroup.bpf.c")
        .add_source("src/bpf/lib/sdt_task.bpf.c")
        .add_source("src/bpf/lib/topology.bpf.c")
        .compile_link_gen()
        .expect("BpfBuilder build returned error");
}
