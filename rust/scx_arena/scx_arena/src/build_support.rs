// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

//! Materialization support for the packaged SCX libarena BPF inputs.

use std::fs;
use std::io;
use std::io::Cursor;
use std::path::{Path, PathBuf};

static BPF_ARCHIVE: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/scx-arena-libarena-bpf.tar"));

#[derive(Debug)]
pub struct BpfAssets {
    root: PathBuf,
    libarena: libarena_rs::build::BpfAssets,
}

impl BpfAssets {
    pub fn include_dir(&self) -> PathBuf {
        self.root.join("include")
    }

    pub fn source(&self, name: impl AsRef<Path>) -> PathBuf {
        self.root.join("src").join(name)
    }

    pub fn selftest_source(&self, name: impl AsRef<Path>) -> PathBuf {
        self.source(Path::new("selftests").join(name))
    }

    pub fn libarena_include_dir(&self) -> PathBuf {
        self.libarena.include_dir()
    }

    pub fn libarena_source(&self, name: impl AsRef<Path>) -> PathBuf {
        self.libarena.source(name)
    }

    pub fn libarena_cflags(&self) -> &'static [&'static str] {
        libarena_rs::build::CFLAGS
    }
}

pub fn extract(out_dir: impl AsRef<Path>) -> io::Result<BpfAssets> {
    let out_dir = out_dir.as_ref();
    let root = out_dir.join("scx-arena-libarena");
    match fs::remove_dir_all(&root) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    fs::create_dir_all(&root)?;
    tar::Archive::new(Cursor::new(BPF_ARCHIVE)).unpack(&root)?;

    let libarena = libarena_rs::build::extract(out_dir)?;
    inline_libarena_buddy_header(&libarena.source("buddy.bpf.c"))?;
    for name in [
        "common.bpf.c",
        "buddy.bpf.c",
        "bitmap.bpf.c",
        "rbtree.bpf.c",
    ] {
        let source = libarena.source(name);
        let contents = fs::read_to_string(&source)?;
        fs::write(
            source,
            format!("#include <lib/alloc/libarena_compat.h>\n{contents}"),
        )?;
    }

    Ok(BpfAssets { root, libarena })
}

fn inline_libarena_buddy_header(source: &Path) -> io::Result<()> {
    const OUT_OF_LINE: &str = "static struct buddy_header __arena *idx_to_header(";
    const INLINED: &str = "static __always_inline struct buddy_header __arena *idx_to_header(";

    // Leave room for callers of the buddy allocator in the BPF call stack.
    let contents = fs::read_to_string(source)?;
    if contents.matches(OUT_OF_LINE).count() != 1 {
        return Err(io::Error::other(format!(
            "{} does not contain the expected idx_to_header declaration",
            source.display()
        )));
    }
    fs::write(source, contents.replacen(OUT_OF_LINE, INLINED, 1))
}
