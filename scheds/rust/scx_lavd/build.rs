// Copyright (c) Changwoo Min <changwoo@igalia.com>
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

fn main() {
    scx_cargo::BpfBuilder::new()
        .unwrap()
        .enable_intf("src/bpf/intf.h", "bpf_intf.rs")
        .enable_skel("src/bpf/main.bpf.c", "bpf")
        .add_source("src/bpf/introspec.bpf.c")
        .add_source("src/bpf/lock.bpf.c")
        .add_source("src/bpf/power.bpf.c")
        .add_source("src/bpf/preempt.bpf.c")
        .add_source("src/bpf/sys_stat.bpf.c")
        .add_source("src/bpf/lib/arena.bpf.c")
        .add_source("src/bpf/lib/atq.bpf.c")
        .add_source("src/bpf/lib/bitmap.bpf.c")
        .add_source("src/bpf/lib/cgroup_bw.bpf.c")
        .add_source("src/bpf/lib/cpumask.bpf.c")
        .add_source("src/bpf/lib/rbtree.bpf.c")
        .add_source("src/bpf/lib/minheap.bpf.c")
        .add_source("src/bpf/lib/sdt_alloc.bpf.c")
        .add_source("src/bpf/lib/sdt_task.bpf.c")
        .add_source("src/bpf/lib/topology.bpf.c")
        .compile_link_gen()
        .unwrap();
}
