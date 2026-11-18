// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Will Clingan
use std::process::Command;

fn main() {
    // BUILD ID: GIT SHA, DIRTY FLAG, TARGET TRIPLE.
    let git_sha = Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default();

    let git_dirty = Command::new("git")
        .args(["status", "--porcelain", "--", "."])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| !o.stdout.is_empty())
        .unwrap_or(false);

    let build_id = if git_sha.is_empty() {
        String::new()
    } else if git_dirty {
        format!("-g{}-dirty", git_sha)
    } else {
        format!("-g{}", git_sha)
    };

    let target = std::env::var("TARGET").unwrap_or_default();

    println!("cargo:rustc-env=PANDA_BUILD_ID={}", build_id);
    println!("cargo:rustc-env=PANDA_TARGET={}", target);
    println!("cargo:rustc-env=PANDA_KERNEL=scx vmlinux.h");

    scx_cargo::BpfBuilder::new()
        .unwrap()
        .enable_intf("src/bpf/intf.h", "bpf_intf.rs")
        .enable_skel("src/bpf/main.bpf.c", "main")
        .build()
        .unwrap();
}
