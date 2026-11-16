// SPDX-License-Identifier: GPL-2.0
/*
 * Build script for scx_flow.
 *
 * Builds the BPF object and generates the userspace bindings.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */

fn main() {
    scx_cargo::BpfBuilder::new()
        .unwrap()
        .enable_intf("src/bpf/intf.h", "bpf_intf.rs")
        .enable_skel("src/bpf/main.bpf.c", "bpf")
        .build()
        .unwrap();
}
