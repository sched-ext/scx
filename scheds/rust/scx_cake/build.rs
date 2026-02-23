// SPDX-License-Identifier: GPL-2.0
// Build script for scx_cake - compiles BPF code and generates bindings

fn main() {
    // Detect build profile: release builds pass CAKE_RELEASE=1 to BPF Clang,
    // which eliminates ALL stats/telemetry code at compile time (zero overhead).
    // Debug builds retain full --verbose/TUI support via volatile RODATA toggle.
    let profile = std::env::var("PROFILE").unwrap_or_default();
    let base_flags = "-O2 -mcpu=v4 -fno-stack-protector -fno-asynchronous-unwind-tables";
    let cflags = if profile == "release" {
        format!("{} -DCAKE_RELEASE=1", base_flags)
    } else {
        base_flags.to_string()
    };
    std::env::set_var("BPF_EXTRA_CFLAGS_PRE_INCL", &cflags);
    scx_cargo::BpfBuilder::new()
        .unwrap()
        .enable_intf("src/bpf/intf.h", "bpf_intf.rs")
        .enable_skel("src/bpf/cake.bpf.c", "bpf")
        .add_source("../../../lib/arena.bpf.c")
        .add_source("../../../lib/sdt_alloc.bpf.c")
        .add_source("../../../lib/sdt_task.bpf.c")
        .add_source("../../../lib/bitmap.bpf.c")
        .add_source("../../../lib/cpumask.bpf.c")
        .add_source("../../../lib/topology.bpf.c")
        .compile_link_gen()
        .unwrap();
}
