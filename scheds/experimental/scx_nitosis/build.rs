// Copyright (c) Meta Platforms, Inc. and affiliates.
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
    let mut builder = scx_cargo::BpfBuilder::new().expect("BpfBuilder creation returned error");

    builder
        .add_include_path(include_dir.to_str().unwrap())
        .add_include_path(libarena_include_dir.to_str().unwrap());
    for flag in assets.libarena_cflags() {
        builder.add_cflag(flag);
    }

    builder
        .enable_intf("src/bpf/intf.h", "bpf_intf.rs")
        .enable_skel("src/bpf/mitosis.bpf.c", "bpf")
        // arena.bpf.c's arena_init() calls into rbtree and atq, so those two
        // ride along even though nothing here uses them directly yet.
        .add_source(&libarena_source("buddy.bpf.c"))
        .add_source(&libarena_source("common.bpf.c"))
        .add_source(&libarena_source("bitmap.bpf.c"))
        .add_source(&source("arena.bpf.c"))
        .add_source(&source("atq.bpf.c"))
        .add_source(&source("cpumask.bpf.c"))
        .add_source(&libarena_source("rbtree.bpf.c"))
        .add_source(&source("sdt_cgroup.bpf.c"))
        .add_source(&source("urcu.bpf.c"))
        .add_source(&source("sdt_task.bpf.c"))
        .add_source(&source("topology.bpf.c"))
        .compile_link_gen()
        .expect("BpfBuilder build returned error");
}
