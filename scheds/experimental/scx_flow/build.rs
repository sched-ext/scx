// SPDX-License-Identifier: GPL-2.0
/*
 * Build script for scx_flow.
 *
 * Builds the BPF object and generates the userspace bindings. The double
 * helix queues of --performance come from the arena library of the scx
 * workspace, which is compiled and linked into the same object.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */

fn main() {
    scx_cargo::BpfBuilder::new()
        .unwrap()
        .enable_intf("src/bpf/intf.h", "bpf_intf.rs")
        .enable_skel("src/bpf/main.bpf.c", "bpf")
        .add_source("src/bpf/lib/common.bpf.c")
        .add_source("src/bpf/lib//dhq.bpf.c")
        .add_source("src/bpf/lib/minheap.bpf.c")
        .add_source("src/bpf/lib/sdt_alloc.bpf.c")
        .compile_link_gen()
        .unwrap();
}
