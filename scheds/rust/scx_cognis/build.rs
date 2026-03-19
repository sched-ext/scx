// Copyright (c) scx_cognis contributors
// SPDX-License-Identifier: GPL-2.0-only
//
// Build our own BPF files (src/bpf/intf.h + src/bpf/main.bpf.c) without
// delegating to
// scx_rustland_core::RustLandBuilder.  RustLandBuilder::build() would
// overwrite src/bpf.rs, src/bpf/intf.h, and src/bpf/main.bpf.c with its own
// embedded
// templates on every fresh build, silently erasing our custom BPF code.
// Using scx_cargo::BpfBuilder directly compiles the committed files and
// generates the OUT_DIR skeleton / bindings without touching any source file.

fn main() {
    scx_cargo::BpfBuilder::new()
        .unwrap()
        .enable_intf("src/bpf/intf.h", "bpf_intf.rs")
        .enable_skel("src/bpf/main.bpf.c", "bpf")
        .build()
        .unwrap();
}
