use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    let manifest_dir: PathBuf = env::var("CARGO_MANIFEST_DIR").unwrap().into();
    let root_dir = manifest_dir.join("../..");
    let out_dir: PathBuf = env::var("OUT_DIR").unwrap().into();

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
        // libbpf headers
        env::var("DEP_BPF_INCLUDE")
            .expect("libbpf-sys include must be available")
            .into(),
    ];

    // Common compiler: BPF scheduler code compiled as userspace C has
    // inherently unused parameters (fixed BPF ops signatures) and unknown
    // attributes (preserve_access_index from vmlinux.h).
    let compiler = env::var("BPF_CLANG").unwrap_or_else(|_| "clang".into());

    // ---------------------------------------------------------------
    // Static libraries (linked into the main binary)
    // ---------------------------------------------------------------

    // Build the scxtest support library (map emulation, cpumask, test assert).
    // NOTE: overrides.c is NOT included here — it goes into each .so instead,
    // so that the .so's weak stubs don't conflict with the main binary's
    // strong kfunc symbols exported via -rdynamic.
    cc::Build::new()
        .compiler(&compiler)
        .files([
            root_dir.join("lib/scxtest/scx_test.c"),
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

    // ---------------------------------------------------------------
    // Shared libraries (.so) for schedulers — built via Makefile
    // ---------------------------------------------------------------

    let scheduler_dir = out_dir.join("schedulers");
    let bpf_include = env::var("DEP_BPF_INCLUDE")
        .expect("libbpf-sys include must be available");

    let status = Command::new("make")
        .arg("-C")
        .arg(manifest_dir.join("schedulers"))
        .arg(format!("BUILD_DIR={}", scheduler_dir.display()))
        .arg(format!("SIMULATOR_DIR={}", manifest_dir.display()))
        .arg(format!("ROOT_DIR={}", root_dir.display()))
        .arg(format!("BPF_INCLUDE={bpf_include}"))
        .arg(format!("CC={compiler}"))
        .status()
        .expect("failed to run make");

    assert!(status.success(), "scheduler Makefile failed: exit {status}");

    // ---------------------------------------------------------------
    // Linker flags for the main binary
    // ---------------------------------------------------------------

    // Export all symbols so .so can resolve kfuncs and scxtest functions
    println!("cargo:rustc-link-arg=-rdynamic");

    // Force scxtest map functions into the binary even though Rust doesn't
    // reference them directly — the .so's scheduler code calls them via
    // the bpf_map_lookup_elem macro.
    println!("cargo:rustc-link-arg=-Wl,--undefined=scx_test_map_lookup_elem");

    // Expose scheduler .so directory to Rust code
    println!(
        "cargo:rustc-env=SCHEDULER_SO_DIR={}",
        scheduler_dir.display()
    );

    // Rebuild triggers
    println!("cargo:rerun-if-changed=schedulers/");
    println!("cargo:rerun-if-changed=csrc/");
    println!("cargo:rerun-if-changed=../../lib/scxtest/");
    println!("cargo:rerun-if-changed=../../scheds/rust/scx_tickless/src/bpf/");
}
