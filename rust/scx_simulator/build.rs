use std::env;
use std::path::{Path, PathBuf};
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
        // Tickless BPF source (for #include "intf.h" and "main.bpf.c")
        root_dir.join("scheds/rust/scx_tickless/src/bpf"),
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
    // Shared libraries (.so) for schedulers
    // ---------------------------------------------------------------

    let include_flags: Vec<String> = include_paths
        .iter()
        .map(|p| format!("-I{}", p.display()))
        .collect();

    // Common C flags for compiling .o files for .so
    let common_cflags: &[&str] = &[
        "-c",
        "-fPIC",
        "-DSCX_BPF_UNITTEST",
        "-Wno-unused-parameter",
        "-Wno-unknown-attributes",
    ];

    // Build libscx_simple.so
    let simple_so = build_scheduler_so(
        &compiler,
        &out_dir,
        "libscx_simple.so",
        &[
            manifest_dir.join("csrc/simple_wrapper.c"),
            manifest_dir.join("csrc/sim_bpf_stubs.c"),
            root_dir.join("lib/scxtest/overrides.c"),
        ],
        common_cflags,
        &include_flags,
        &[], // no extra defines
    );

    // Build libscx_tickless.so
    let tickless_so = build_scheduler_so(
        &compiler,
        &out_dir,
        "libscx_tickless.so",
        &[
            manifest_dir.join("csrc/tickless_wrapper.c"),
            manifest_dir.join("csrc/sim_bpf_stubs.c"),
            root_dir.join("lib/scxtest/overrides.c"),
        ],
        common_cflags,
        &include_flags,
        &["-Dconst="], // strip const for BPF "const volatile" globals
    );

    // ---------------------------------------------------------------
    // Linker flags for the main binary
    // ---------------------------------------------------------------

    // Export all symbols so .so can resolve kfuncs and scxtest functions
    println!("cargo:rustc-link-arg=-rdynamic");

    // Force scxtest map functions into the binary even though Rust doesn't
    // reference them directly — the .so's scheduler code calls them via
    // the bpf_map_lookup_elem macro.
    println!("cargo:rustc-link-arg=-Wl,--undefined=scx_test_map_lookup_elem");

    // Expose .so paths to Rust code via env vars
    println!(
        "cargo:rustc-env=LIB_SCX_SIMPLE_SO={}",
        simple_so.display()
    );
    println!(
        "cargo:rustc-env=LIB_SCX_TICKLESS_SO={}",
        tickless_so.display()
    );

    // Rebuild triggers
    println!("cargo:rerun-if-changed=csrc/");
    println!("cargo:rerun-if-changed=../../lib/scxtest/");
    println!("cargo:rerun-if-changed=../../scheds/rust/scx_tickless/src/bpf/");
}

/// Compile a set of C source files into a shared library (.so).
///
/// Each source file is compiled to a .o with -fPIC, then all .o files
/// are linked into a single .so with -shared.
fn build_scheduler_so(
    compiler: &str,
    out_dir: &Path,
    so_name: &str,
    sources: &[PathBuf],
    common_cflags: &[&str],
    include_flags: &[String],
    extra_defines: &[&str],
) -> PathBuf {
    let mut objects = Vec::new();

    for src in sources {
        let stem = src.file_stem().unwrap().to_str().unwrap();
        // Use so_name prefix to avoid collisions between simple and tickless
        // builds of the same source file (e.g. sim_bpf_stubs.c)
        let so_stem = so_name.trim_start_matches("lib").trim_end_matches(".so");
        let obj = out_dir.join(format!("{so_stem}_{stem}.o"));

        let mut cmd = Command::new(compiler);
        cmd.args(common_cflags);
        for flag in include_flags {
            cmd.arg(flag);
        }
        for def in extra_defines {
            cmd.arg(def);
        }
        cmd.arg("-o").arg(&obj).arg(src);

        let status = cmd
            .status()
            .unwrap_or_else(|e| panic!("failed to run {compiler}: {e}"));
        assert!(
            status.success(),
            "failed to compile {}: exit {}",
            src.display(),
            status
        );

        objects.push(obj);
    }

    // Link all .o files into a .so
    let so_path = out_dir.join(so_name);
    let mut cmd = Command::new(compiler);
    cmd.arg("-shared").arg("-o").arg(&so_path);
    for obj in &objects {
        cmd.arg(obj);
    }

    let status = cmd
        .status()
        .unwrap_or_else(|e| panic!("failed to run linker: {e}"));
    assert!(
        status.success(),
        "failed to link {so_name}: exit {status}"
    );

    so_path
}
