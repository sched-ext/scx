// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use std::env;
use std::fs::File;
use std::path::{Path, PathBuf};

fn package_libarena_bpf(manifest_dir: &Path, out_dir: &Path) -> std::io::Result<()> {
    let source = manifest_dir.join("bpf");
    let archive = File::create(out_dir.join("scx-arena-libarena-bpf.tar"))?;
    let mut archive = tar::Builder::new(archive);

    archive.append_dir_all("include", source.join("include"))?;
    archive.append_dir_all("src", source.join("src"))?;
    archive.finish()?;

    println!(
        "cargo::rerun-if-changed={}",
        source.join("include").display()
    );
    println!("cargo::rerun-if-changed={}", source.join("src").display());
    Ok(())
}

fn main() {
    let manifest_dir = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let out_dir = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    package_libarena_bpf(&manifest_dir, &out_dir).unwrap();

    scx_cargo::BpfBuilder::new()
        .unwrap()
        .enable_skel("src/bpf/main.bpf.c", "bpf")
        .add_source("src/bpf/lib/arena.bpf.c")
        .add_source("src/bpf/lib/common.bpf.c")
        .add_source("src/bpf/lib/atq.bpf.c")
        .add_source("src/bpf/lib/bitmap.bpf.c")
        .add_source("src/bpf/lib/cpumask.bpf.c")
        .add_source("src/bpf/lib/minheap.bpf.c")
        .add_source("src/bpf/lib/rbtree.bpf.c")
        .add_source("src/bpf/lib/sdt_alloc.bpf.c")
        .add_source("src/bpf/lib/sdt_task.bpf.c")
        .add_source("src/bpf/lib/topology.bpf.c")
        .compile_link_gen()
        .unwrap();
}
