// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

fn main() {
    scx_cargo::BpfBuilder::new()
        .unwrap()
        .enable_intf("src/bpf/intf.h", "bpf_intf.rs")
        .enable_skel("src/bpf/main.bpf.c", "main")
        .add_source("src/bpf/lb_domain.bpf.c")
        .add_source("src/bpf/common.bpf.c")
        .add_source("src/bpf/deadline.bpf.c")
        .add_source("src/bpf/placement.bpf.c")
        .add_source("src/bpf/deadline.bpf.c")
        .add_source("../../../lib/arena.bpf.c")
        .add_source("../../../lib/bitmap.bpf.c")
        .add_source("../../../lib/cpumask.bpf.c")
        .add_source("../../../lib/minheap.bpf.c")
        .add_source("../../../lib/ravg.bpf.c")
        .add_source("../../../lib/sdt_task.bpf.c")
        .add_source("../../../lib/sdt_alloc.bpf.c")
        .add_source("../../../lib/topology.bpf.c")
        .compile_link_gen()
        .unwrap();
}
