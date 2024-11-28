// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use std::{
    fs::File,
    path::{Path, PathBuf},
};

include!("clang_info.rs");

const BPF_H: &str = "bpf_h";

pub struct Builder;

impl Builder {
    pub fn new() -> Self {
        Builder
    }

    fn gen_bpf_h(&self) {
        let out_dir = env::var("OUT_DIR").unwrap();
        let file = File::create(PathBuf::from(&out_dir).join(format!("{}.tar", BPF_H))).unwrap();
        let mut ar = tar::Builder::new(file);

        ar.follow_symlinks(false);
        ar.append_dir_all(".", BPF_H).unwrap();
        ar.finish().unwrap();

        for ent in walkdir::WalkDir::new(BPF_H) {
            let ent = ent.unwrap();
            if !ent.file_type().is_dir() {
                println!("cargo:rerun-if-changed={}", ent.path().to_string_lossy());
            }
        }
    }

    fn gen_bindings(&self) {
        let out_dir = env::var("OUT_DIR").unwrap();
        let clang = ClangInfo::new().unwrap();
        let kernel_target = clang.kernel_target().unwrap();
        let vmlinux_h = Path::new(&BPF_H)
            .join("arch")
            .join(kernel_target)
            .join("vmlinux.h")
            .to_str()
            .unwrap()
            .to_string();

        let bindings = bindgen::Builder::default()
            .header(vmlinux_h)
            .allowlist_type("scx_exit_kind")
            .allowlist_type("scx_consts")
            .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
            .generate()
            .expect("Unable to generate bindings");

        bindings
            .write_to_file(PathBuf::from(&out_dir).join("bindings.rs"))
            .expect("Couldn't write bindings");
    }

    pub fn build(self) {
        self.gen_bpf_h();
        self.gen_bindings();
    }
}
