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

/// Extracted SCX and upstream libarena build inputs.
#[derive(Debug)]
pub struct BpfAssets {
    root: PathBuf,
    libarena: libarena_rs::build::BpfAssets,
}

impl BpfAssets {
    /// Directory containing the SCX arena headers backed by libarena.
    pub fn include_dir(&self) -> PathBuf {
        self.root.join("include")
    }

    /// Resolve a packaged SCX arena BPF source by name.
    pub fn source(&self, name: impl AsRef<Path>) -> PathBuf {
        self.root.join("src").join(name)
    }

    /// Resolve a packaged SCX libarena selftest source by name.
    pub fn selftest_source(&self, name: impl AsRef<Path>) -> PathBuf {
        self.source(Path::new("selftests").join(name))
    }

    /// Directory containing libarena's public headers.
    pub fn libarena_include_dir(&self) -> PathBuf {
        self.libarena.include_dir()
    }

    /// Resolve a packaged libarena BPF source by name.
    pub fn libarena_source(&self, name: impl AsRef<Path>) -> PathBuf {
        self.libarena.source(name)
    }

    /// Compiler flags required by libarena.
    pub fn libarena_cflags(&self) -> &'static [&'static str] {
        libarena_rs::build::CFLAGS
    }
}

/// Extract all BPF inputs needed by the libarena-backed implementation.
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

    Ok(BpfAssets {
        root,
        libarena: libarena_rs::build::extract(out_dir)?,
    })
}
