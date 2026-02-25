// PANDEMONIUM BUILD SCRIPT (scx MONOREPO)
// USES BUNDLED vmlinux.h FROM scheds/vmlinux/ -- NO bpftool REQUIRED

use std::env;
use std::path::PathBuf;

use libbpf_cargo::SkeletonBuilder;

const BPF_SRC: &str = "src/bpf/main.bpf.c";

fn main() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());

    // MONOREPO LAYOUT: scheds/rust/scx_pandemonium/ -> scheds/vmlinux/
    let vmlinux_search = manifest_dir.join("../../vmlinux");
    let vmlinux_dir = vmlinux_search.canonicalize().unwrap_or_else(|_| {
        panic!(
            "vmlinux directory not found at {:?} -- is this an scx monorepo checkout?",
            vmlinux_search
        )
    });

    // ARCHITECTURE-SPECIFIC vmlinux.h (x86 -> arch/x86/vmlinux.h)
    let arch = if cfg!(target_arch = "x86_64") || cfg!(target_arch = "x86") {
        "x86"
    } else if cfg!(target_arch = "aarch64") {
        "arm64"
    } else if cfg!(target_arch = "arm") {
        "arm"
    } else if cfg!(target_arch = "riscv64") || cfg!(target_arch = "riscv32") {
        "riscv"
    } else if cfg!(target_arch = "s390x") {
        "s390"
    } else if cfg!(target_arch = "powerpc64") || cfg!(target_arch = "powerpc") {
        "powerpc"
    } else {
        panic!("unsupported architecture for vmlinux.h")
    };

    let arch_vmlinux = vmlinux_dir.join("arch").join(arch).join("vmlinux.h");
    if !arch_vmlinux.exists() {
        panic!("vmlinux.h not found at {:?}", arch_vmlinux);
    }

    // INCLUDE PATHS: arch-specific vmlinux.h dir + monorepo scx headers
    let scx_include = manifest_dir.join("include");
    let arch_include = arch_vmlinux.parent().unwrap();

    let skel_out = out_dir.join("bpf.skel.rs");

    SkeletonBuilder::new()
        .source(BPF_SRC)
        .clang_args([
            "-I",
            arch_include.to_str().unwrap(),
            "-I",
            scx_include.to_str().unwrap(),
            "-I",
            vmlinux_dir.to_str().unwrap(),
        ])
        .build_and_generate(&skel_out)
        .unwrap();

    println!("cargo:rerun-if-changed={BPF_SRC}");
    println!("cargo:rerun-if-changed=src/bpf/intf.h");
    println!("cargo:rerun-if-changed=include/scx");
}
