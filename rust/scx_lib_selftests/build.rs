// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

fn main() {
    scx_utils::BpfBuilder::new()
        .unwrap()
        .enable_skel("src/bpf/main.bpf.c", "main")
        .add_source("../../lib/arena.bpf.c")
        .add_source("../../lib/atq.bpf.c")
        .add_source("../../lib/bitmap.bpf.c")
        .add_source("../../lib/minheap.bpf.c")
        .add_source("../../lib/sdt_alloc.bpf.c")
        .add_source("../../lib/sdt_task.bpf.c")
        .add_source("../../lib/topology.bpf.c")
        .add_source("../../lib/selftests/selftest.bpf.c")
        .add_source("../../lib/selftests/st_atq.bpf.c")
        .add_source("../../lib/selftests/st_bitmap.bpf.c")
        .add_source("../../lib/selftests/st_minheap.bpf.c")
        .add_source("../../lib/selftests/st_topology.bpf.c")
        .compile_link_gen()
        .unwrap();
}
