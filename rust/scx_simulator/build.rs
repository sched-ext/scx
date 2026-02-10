use std::env;
use std::path::PathBuf;

fn main() {
    let manifest_dir: PathBuf = env::var("CARGO_MANIFEST_DIR").unwrap().into();
    let root_dir = manifest_dir.join("../..");

    let include_paths: Vec<PathBuf> = vec![
        // Our own C source directory
        manifest_dir.join("csrc"),
        // Existing unit test infrastructure
        root_dir.join("lib/scxtest"),
        // Scheduler include paths
        root_dir.join("scheds/include"),
        root_dir.join("scheds/include/lib"),
        root_dir.join("scheds/vmlinux"),
        root_dir.join("scheds/vmlinux/arch/x86"),
        root_dir.join("scheds/include/bpf-compat"),
        // Scheduler C source (for #include "scx_simple.bpf.c")
        root_dir.join("scheds/c"),
        // libbpf headers
        env::var("DEP_BPF_INCLUDE")
            .expect("libbpf-sys include must be available")
            .into(),
    ];

    // Common compiler: BPF scheduler code compiled as userspace C has
    // inherently unused parameters (fixed BPF ops signatures) and unknown
    // attributes (preserve_access_index from vmlinux.h).
    let compiler = env::var("BPF_CLANG").unwrap_or_else(|_| "clang".into());

    // Build the scxtest support library (map emulation, cpumask, overrides)
    cc::Build::new()
        .compiler(&compiler)
        .files([
            root_dir.join("lib/scxtest/scx_test.c"),
            root_dir.join("lib/scxtest/overrides.c"),
            root_dir.join("lib/scxtest/scx_test_map.c"),
            root_dir.join("lib/scxtest/scx_test_cpumask.c"),
        ])
        .define("SCX_BPF_UNITTEST", None)
        .includes(&include_paths)
        .flag("-Wno-unused-parameter")
        .flag("-Wno-unknown-attributes")
        .compile("scxtest");

    // Build the task_struct accessor library
    cc::Build::new()
        .compiler(&compiler)
        .file(manifest_dir.join("csrc/sim_task.c"))
        .define("SCX_BPF_UNITTEST", None)
        .includes(&include_paths)
        .flag("-Wno-unused-parameter")
        .flag("-Wno-unknown-attributes")
        .compile("sim_task");

    // Build the scx_simple scheduler as userspace C
    cc::Build::new()
        .compiler(&compiler)
        .file(manifest_dir.join("csrc/simple_wrapper.c"))
        .define("SCX_BPF_UNITTEST", None)
        .includes(&include_paths)
        .flag("-Wno-unused-parameter")
        .flag("-Wno-unknown-attributes")
        .compile("scx_simple");

    // Rebuild triggers
    println!("cargo:rerun-if-changed=csrc/");
    println!("cargo:rerun-if-changed=../../lib/scxtest/");
    println!("cargo:rerun-if-changed=../../scheds/c/scx_simple.bpf.c");
}
