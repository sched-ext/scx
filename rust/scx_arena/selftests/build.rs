// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

fn main() {
    scx_utils::BpfBuilder::new()
        .unwrap()
        .enable_skel("src/bpf/main.bpf.c", "main")
        .add_source("src/bpf/lib/arena.bpf.c")
        .add_source("src/bpf/lib/atq.bpf.c")
        .add_source("src/bpf/lib/bitmap.bpf.c")
        .add_source("src/bpf/lib/btree.bpf.c")
        .add_source("src/bpf/lib/lvqueue.bpf.c")
        .add_source("src/bpf/lib/minheap.bpf.c")
        .add_source("src/bpf/lib/rbtree.bpf.c")
        .add_source("src/bpf/lib/sdt_alloc.bpf.c")
        .add_source("src/bpf/lib/sdt_task.bpf.c")
        .add_source("src/bpf/lib/topology.bpf.c")
        .add_source("src/bpf/lib/selftests/selftest.bpf.c")
        .add_source("src/bpf/lib/selftests/st_arena_topology_timer.bpf.c")
        .add_source("src/bpf/lib/selftests/st_atq.bpf.c")
        .add_source("src/bpf/lib/selftests/st_bitmap.bpf.c")
        .add_source("src/bpf/lib/selftests/st_btree.bpf.c")
        .add_source("src/bpf/lib/selftests/st_lvqueue.bpf.c")
        .add_source("src/bpf/lib/selftests/st_minheap.bpf.c")
        .add_source("src/bpf/lib/selftests/st_rbtree.bpf.c")
        .add_source("src/bpf/lib/selftests/st_topology.bpf.c")
        .compile_link_gen()
        .unwrap();
}
