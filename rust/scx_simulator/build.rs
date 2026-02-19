use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    let manifest_dir: PathBuf = env::var("CARGO_MANIFEST_DIR").unwrap().into();
    let root_dir = manifest_dir.join("../..");
    let out_dir: PathBuf = env::var("OUT_DIR").unwrap().into();

    let coverage = env::var("SCX_SIM_COVERAGE").as_deref() == Ok("1");

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

    // DRY helper: apply common config to a cc::Build
    let configure_build = |build: &mut cc::Build| {
        build
            .compiler(&compiler)
            .define("SCX_BPF_UNITTEST", None)
            .includes(&include_paths)
            .flag("-Wno-unused-parameter")
            .flag("-Wno-unknown-attributes");
        if coverage {
            build
                .flag("-fprofile-instr-generate")
                .flag("-fcoverage-mapping");
        }
    };

    // ---------------------------------------------------------------
    // Static libraries (linked into the main binary)
    // ---------------------------------------------------------------

    // Build the scxtest support library (map emulation, cpumask, test assert).
    // NOTE: overrides.c is NOT included here — it goes into each .so instead,
    // so that the .so's weak stubs don't conflict with the main binary's
    // strong kfunc symbols exported via -rdynamic.
    let mut scxtest = cc::Build::new();
    scxtest.files([
        root_dir.join("lib/scxtest/scx_test.c"),
        root_dir.join("lib/scxtest/scx_test_map.c"),
        root_dir.join("lib/scxtest/scx_test_cpumask.c"),
    ]);
    configure_build(&mut scxtest);
    scxtest.compile("scxtest");

    // Build the task_struct accessor library
    let mut sim_task = cc::Build::new();
    sim_task.file(manifest_dir.join("csrc/sim_task.c"));
    configure_build(&mut sim_task);
    sim_task.compile("sim_task");

    // Build the SDT / arena per-task storage stubs.
    // Provides strong definitions of scx_task_alloc/data/free that override
    // the __weak stubs in overrides.c. Linked into the main binary for unit
    // tests and exported via -rdynamic for .so schedulers.
    let mut sim_sdt = cc::Build::new();
    sim_sdt.file(manifest_dir.join("csrc/sim_sdt_stubs.c"));
    configure_build(&mut sim_sdt);
    sim_sdt.compile("sim_sdt_stubs");

    // ---------------------------------------------------------------
    // Shared libraries (.so) for schedulers — built via Makefile
    // ---------------------------------------------------------------

    let scheduler_dir = if coverage {
        out_dir.join("schedulers_cov")
    } else {
        out_dir.join("schedulers")
    };
    let bpf_include = env::var("DEP_BPF_INCLUDE").expect("libbpf-sys include must be available");

    let mut make = Command::new("make");
    make.arg("-C")
        .arg(manifest_dir.join("schedulers"))
        .arg(format!("BUILD_DIR={}", scheduler_dir.display()))
        .arg(format!("SIMULATOR_DIR={}", manifest_dir.display()))
        .arg(format!("ROOT_DIR={}", root_dir.display()))
        .arg(format!("BPF_INCLUDE={bpf_include}"))
        .arg(format!("CC={compiler}"));
    if coverage {
        make.arg("SCX_SIM_COVERAGE=1");
    }
    let status = make.status().expect("failed to run make");

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

    // Link the clang profile runtime when coverage is enabled.
    // This provides __llvm_profile_* symbols for the instrumented .so files.
    if coverage {
        let rt_dir_output = Command::new(&compiler)
            .arg("--print-runtime-dir")
            .output()
            .expect("failed to run clang --print-runtime-dir");
        assert!(
            rt_dir_output.status.success(),
            "clang --print-runtime-dir failed"
        );
        let rt_dir = String::from_utf8(rt_dir_output.stdout)
            .expect("non-UTF8 runtime dir")
            .trim()
            .to_string();
        // Detect the actual library name (may or may not have arch suffix)
        let profile_lib =
            if std::path::Path::new(&format!("{rt_dir}/libclang_rt.profile.a")).exists() {
                "clang_rt.profile"
            } else {
                "clang_rt.profile-x86_64"
            };
        println!("cargo:rustc-link-search=native={rt_dir}");
        println!("cargo:rustc-link-lib=static={profile_lib}");
    }

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
    println!("cargo:rerun-if-changed=../../scheds/rust/scx_cosmos/src/bpf/");
    println!("cargo:rerun-if-env-changed=SCX_SIM_COVERAGE");
}
