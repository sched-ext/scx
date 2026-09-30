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

fn patch_libarena_rbtree(source: &Path) -> io::Result<()> {
    const OLD_HELPER: &str = "__weak\nint rb_print_pop_up(";
    const NEW_HELPER: &str = "static __always_inline\nint rb_print_pop_up(";
    const OLD_PUSH: &str = "stack[depth++] = state;";
    const NEW_PUSH: &str = "volatile u8 stack_idx = depth & (RB_MAXLVL_PRINT - 1);\n\
                            \t\t\tif (stack_idx >= RB_MAXLVL_PRINT)\n\
                            \t\t\t\treturn 0;\n\
                            \t\t\tstack[stack_idx] = state;\n\
                            \t\t\tdepth++;";

    let contents = fs::read_to_string(source)?;
    if contents.matches(OLD_HELPER).count() != 1 || contents.matches(OLD_PUSH).count() != 2 {
        return Err(io::Error::other(format!(
            "{} does not contain the expected rb_print_pop_up implementation",
            source.display()
        )));
    }
    let patched = contents
        .replacen(OLD_HELPER, NEW_HELPER, 1)
        .replace(OLD_PUSH, NEW_PUSH);
    fs::write(source, patched)
}

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
    patch_libarena_rbtree(&libarena.source("rbtree.bpf.c"))?;

    Ok(BpfAssets { root, libarena })
}
