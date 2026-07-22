// Copyright (c) Changwoo Min <changwoo@igalia.com>
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

fn main() {
    // libarena's headers (arena_malloc/arena_free and its arena primitives)
    // must be found before scx's bundled headers, so give its include/ dir
    // precedence over the built-in include paths.
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let libarena_include = std::path::Path::new(&manifest_dir).join("../../../libarena/include");

    scx_cargo::BpfBuilder::new()
        .unwrap()
        .add_include_path(libarena_include.to_str().unwrap())
        // libarena gates its arena spinlock (arena_spinlock_t / arena_spin_lock)
        // behind ENABLE_ATOMICS_TESTS; enable it so the lib headers resolve it.
        .add_cflag("-DENABLE_ATOMICS_TESTS")
        .enable_intf("src/bpf/intf.h", "bpf_intf.rs")
        .enable_skel("src/bpf/main.bpf.c", "bpf")
        .add_source("src/bpf/balance.bpf.c")
        .add_source("src/bpf/idle.bpf.c")
        .add_source("src/bpf/introspec.bpf.c")
        .add_source("src/bpf/lat_cri.bpf.c")
        .add_source("src/bpf/lock.bpf.c")
        .add_source("src/bpf/power.bpf.c")
        .add_source("src/bpf/preempt.bpf.c")
        .add_source("src/bpf/sys_stat.bpf.c")
        .add_source("src/bpf/util.bpf.c")
        .add_source("src/bpf/lib/arena.bpf.c")
        .add_source("src/bpf/libarena/src/buddy.bpf.c")
        .add_source("src/bpf/libarena/src/common.bpf.c")
        .add_source("src/bpf/lib/atq.bpf.c")
        .add_source("src/bpf/lib/bitmap.bpf.c")
        .add_source("src/bpf/lib/cgroup_bw.bpf.c")
        .add_source("src/bpf/lib/cpumask.bpf.c")
        .add_source("src/bpf/lib/rbtree.bpf.c")
        .add_source("src/bpf/lib/minheap.bpf.c")
        .add_source("src/bpf/lib/sdt_alloc.bpf.c")
        .add_source("src/bpf/lib/sdt_task.bpf.c")
        .add_source("src/bpf/lib/topology.bpf.c")
        .add_source("src/bpf/lib/ravg.bpf.c")
        .compile_link_gen()
        .unwrap();
}
