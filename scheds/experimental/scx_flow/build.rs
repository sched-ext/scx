// SPDX-License-Identifier: GPL-2.0
/*
 * Build helper
 *
 * Adds a warning suppression for the generated kernel header
 * and then builds the BPF object and the userspace bindings.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */

fn add_bpf_warning_suppression(flag: &str) {
    const KEY: &str = "BPF_EXTRA_CFLAGS_POST_INCL";
    let value = match std::env::var(KEY) {
        Ok(existing) => {
            if existing.split_whitespace().any(|entry| entry == flag) {
                return;
            }
            format!("{existing} {flag}")
        }
        Err(_) => flag.to_owned(),
    };
    /* SAFETY: build script runs single threaded. */
    unsafe {
        std::env::set_var(KEY, value);
    }
}

fn main() {
    /* The generated header may warn about declarations. */
    /* The warning is not actionable for this scheduler. */
    add_bpf_warning_suppression("-Wno-missing-declarations");
    scx_cargo::BpfBuilder::new()
        .unwrap()
        .enable_intf("src/bpf/intf.h", "bpf_intf.rs")
        .enable_skel("src/bpf/main.bpf.c", "bpf")
        .add_source("src/bpf/lib/arena.bpf.c")
        .add_source("src/bpf/lib/common.bpf.c")
        .add_source("src/bpf/lib/atq.bpf.c")
        .add_source("src/bpf/lib/edq.bpf.c")
        .add_source("src/bpf/lib/bitmap.bpf.c")
        .add_source("src/bpf/lib/cpumask.bpf.c")
        .add_source("src/bpf/lib/minheap.bpf.c")
        .add_source("src/bpf/lib/rbtree.bpf.c")
        .add_source("src/bpf/lib/sdt_alloc.bpf.c")
        .add_source("src/bpf/lib/sdt_task.bpf.c")
        .add_source("src/bpf/lib/topology.bpf.c")
        .compile_link_gen()
        .unwrap();
}
