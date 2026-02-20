// PANDEMONIUM BUILD SCRIPT
// COMPILES src/bpf/main.bpf.c INTO BPF BYTECODE AND GENERATES RUST SKELETON
// vmlinux.h: CACHED AT /tmp/pandemonium-vmlinux.h. ON CACHE MISS, GENERATED
// FROM RUNNING KERNEL'S BTF VIA bpftool (ONLY NEEDED ONCE PER KERNEL).

use std::env;
use std::path::PathBuf;
use std::process::Command;

use libbpf_cargo::SkeletonBuilder;

const BPF_SRC: &str = "src/bpf/main.bpf.c";

fn main() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());

    // vmlinux.h: USE CACHE, GENERATE VIA bpftool ON MISS (ONLY NEEDED ONCE)
    // LAYOUT: $OUT_DIR/include/vmlinux/vmlinux.h
    // SCX HEADERS USE ../vmlinux.h RELATIVE TO include/scx/,
    // SO WE NEED include/vmlinux/vmlinux.h AT THE SAME LEVEL AS include/scx/
    let vmlinux_dir = out_dir.join("include").join("vmlinux");
    std::fs::create_dir_all(&vmlinux_dir).expect("failed to create vmlinux dir");

    let vmlinux_h = vmlinux_dir.join("vmlinux.h");
    let cache_path = PathBuf::from("/tmp/pandemonium-vmlinux.h");

    if cache_path.exists() && cache_path.metadata().map(|m| m.len() > 1000).unwrap_or(false) {
        let raw = std::fs::read_to_string(&cache_path).expect("cached vmlinux.h is not utf-8");
        let patched = patch_vmlinux_c23(&raw);
        std::fs::write(&vmlinux_h, patched.as_bytes()).expect("failed to write vmlinux.h");
    } else {
        let output = Command::new("bpftool")
            .args(["btf", "dump", "file", "/sys/kernel/btf/vmlinux", "format", "c"])
            .output()
            .expect("bpftool not found -- install once: pacman -S bpf (only needed for first build)");
        if !output.status.success() {
            panic!(
                "bpftool failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        std::fs::write(&cache_path, &output.stdout).expect("failed to cache vmlinux.h");
        let raw = String::from_utf8(output.stdout).expect("vmlinux.h is not utf-8");
        let patched = patch_vmlinux_c23(&raw);
        std::fs::write(&vmlinux_h, patched.as_bytes()).expect("failed to write vmlinux.h");
    }

    // SYMLINK: $OUT_DIR/include/vmlinux.h -> vmlinux/vmlinux.h
    // SO THAT #include "../vmlinux.h" FROM scx/ HEADERS RESOLVES
    let vmlinux_symlink = out_dir.join("include").join("vmlinux.h");
    let _ = std::fs::remove_file(&vmlinux_symlink);
    std::os::unix::fs::symlink(
        vmlinux_dir.join("vmlinux.h"),
        &vmlinux_symlink,
    )
    .expect("failed to symlink vmlinux.h");

    let gen_include = out_dir.join("include");
    let skel_out = out_dir.join("bpf.skel.rs");

    SkeletonBuilder::new()
        .source(BPF_SRC)
        .clang_args([
            "-std=gnu23",
            "-I",
            "include",
            "-I",
            gen_include.to_str().unwrap(),
            "-I",
            vmlinux_dir.to_str().unwrap(),
        ])
        .build_and_generate(&skel_out)
        .unwrap();

    println!("cargo:rerun-if-changed={BPF_SRC}");
    println!("cargo:rerun-if-changed=src/bpf/intf.h");
    println!("cargo:rerun-if-changed=include/scx");
}

// PATCH vmlinux.h FOR COMPATIBILITY.
// C23: true/false/bool ARE KEYWORDS, BUT vmlinux.h DEFINES THEM AS
// ENUM VALUES AND A TYPEDEF. RENAME THE CONFLICTS.
// ANONYMOUS FIELDS: KERNEL PATCHES (e.g. BORE) ADD STRUCT FIELDS NAMED `_`,
// WHICH IS VALID C BUT INVALID AS A RUST STRUCT FIELD. LIBBPF-CARGO GENERATES
// `pub _: u8` IN THE SKELETON, CAUSING RUSTFMT TO REJECT IT.
// FIX: RENAME `_` FIELDS TO `_anon_pad` IN THE C HEADER BEFORE SKELETON GEN.
fn patch_vmlinux_c23(raw: &str) -> String {
    let mut out = raw
        .replace("typedef _Bool bool;", "/* C23: bool is a keyword */")
        .replace("\tfalse = 0,", "\t/* C23: false */ _false = 0,")
        .replace("\ttrue = 1,", "\t/* C23: true */ _true = 1,");

    // RENAME ANONYMOUS STRUCT FIELDS: `type _;` -> `type _anon_pad;`
    // MATCHES ANY C TYPE FOLLOWED BY ` _;` AT A FIELD DECLARATION
    let mut count = 0u32;
    let mut result = String::with_capacity(out.len());
    for line in out.lines() {
        let trimmed = line.trim();
        if trimmed.ends_with(" _;") || trimmed.ends_with("\t_;") {
            let replaced = line.replacen(" _;", &format!(" _anon_pad_{};", count), 1);
            result.push_str(&replaced);
            count += 1;
        } else {
            result.push_str(line);
        }
        result.push('\n');
    }

    if count > 0 {
        result
    } else {
        out.push('\n');
        out
    }
}
