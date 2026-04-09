// Copyright (c) 2026 Galih Tama <galpt@v.recipes>
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

fn add_bpf_warning_suppression(flag: &str) {
    const KEY: &str = "BPF_EXTRA_CFLAGS_POST_INCL";

    match std::env::var(KEY) {
        Ok(existing) => {
            if !existing.split_whitespace().any(|entry| entry == flag) {
                std::env::set_var(KEY, format!("{existing} {flag}"));
            }
        }
        Err(_) => std::env::set_var(KEY, flag),
    }
}

fn main() {
    // clang can warn about forward declarations inside generated vmlinux.h.
    // Those are not actionable for scx_flow and just add noise for builders.
    add_bpf_warning_suppression("-Wno-missing-declarations");

    scx_cargo::BpfBuilder::new()
        .unwrap()
        .enable_intf("src/bpf/intf.h", "bpf_intf.rs")
        .enable_skel("src/bpf/main.bpf.c", "bpf")
        .build()
        .unwrap();
}
