// Copyright (c) Changwoo Min <changwoo@igalia.com>
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

fn main() {
    let out_dir = std::env::var_os("OUT_DIR").unwrap();
    let assets = scx_arena::build_support::extract(out_dir).unwrap();
    let include_dir = assets.include_dir();
    let libarena_include_dir = assets.libarena_include_dir();
    let source = |name| assets.source(name).to_string_lossy().into_owned();
    let libarena_source = |name| assets.libarena_source(name).to_string_lossy().into_owned();
    let mut builder = scx_cargo::BpfBuilder::new().unwrap();

    builder
        .add_include_path(include_dir.to_str().unwrap())
        .add_include_path(libarena_include_dir.to_str().unwrap());
    for flag in assets.libarena_cflags() {
        builder.add_cflag(flag);
    }
    // v6.13-fb rejects a v4 atomic opcode emitted by the libarena sources.
    // LAVD still supports that kernel, so keep this object on the v3 ISA.
    builder.add_cflag("-mcpu=v3");

    builder
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
        .add_source(&source("arena.bpf.c"))
        .add_source(&libarena_source("bitmap.bpf.c"))
        .add_source(&libarena_source("buddy.bpf.c"))
        .add_source(&libarena_source("common.bpf.c"))
        .add_source(&libarena_source("rbtree.bpf.c"))
        .add_source(&source("atq.bpf.c"))
        .add_source(&source("cgroup_bw.bpf.c"))
        .add_source(&source("cpumask.bpf.c"))
        .add_source(&source("urcu.bpf.c"))
        .add_source(&source("sdt_task.bpf.c"))
        .add_source(&source("topology.bpf.c"))
        .add_source(&source("ravg.bpf.c"))
        .compile_link_gen()
        .unwrap();
}
