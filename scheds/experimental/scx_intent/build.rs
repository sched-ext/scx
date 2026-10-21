// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2026 Rahad Bhuiya <rahadbhuiya2021@gmail.com>

fn main() {
    scx_cargo::BpfBuilder::new()
        .unwrap()
        .enable_intf("src/bpf/intf.h", "bpf_intf.rs")
        .enable_skel("src/bpf/main.bpf.c", "bpf")
        .build()
        .unwrap();
}
