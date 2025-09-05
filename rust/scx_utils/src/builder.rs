// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use std::{
    fs::File,
    io::{Read, Seek},
    path::PathBuf,
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
        let file = File::create(PathBuf::from(&out_dir).join(format!("{BPF_H}.tar"))).unwrap();
        let mut ar = tar::Builder::new(file);

        ar.follow_symlinks(false);
        ar.append_dir_all(".", BPF_H).unwrap();

        let vmlinux_dir = tempfile::tempdir().unwrap();
        let mut vmlinux_tar_zst = File::open("vmlinux.tar.zst").unwrap();
        let vmlinux_tar = ruzstd::decoding::StreamingDecoder::new(&mut vmlinux_tar_zst).unwrap();
        tar::Archive::new(vmlinux_tar)
            .unpack(vmlinux_dir.path())
            .unwrap();
        ar.append_dir_all(".", vmlinux_dir.path().join("vmlinux"))
            .unwrap();

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

        let mut vmlinux_tar_zst = File::open("vmlinux.tar.zst").unwrap();

        let mut vmlinux_h = String::new();

        // vmlinux.h is a symlink. dereference it here.
        let search: PathBuf = format!("vmlinux/arch/{kernel_target}/vmlinux.h").into();

        let mut vmlinux_tar =
            ruzstd::decoding::StreamingDecoder::new(&mut vmlinux_tar_zst).unwrap();
        let mut archive = tar::Archive::new(&mut vmlinux_tar);
        let vmlinux_link_entry = archive
            .entries()
            .unwrap()
            .find(|x| x.as_ref().unwrap().path().unwrap() == search.as_path())
            .unwrap()
            .unwrap();

        let vmlinux_path = PathBuf::from(vmlinux_link_entry.path().unwrap())
            .parent()
            .unwrap()
            .join(vmlinux_link_entry.link_name().unwrap().unwrap());

        vmlinux_tar_zst.rewind().unwrap();
        let vmlinux_tar = ruzstd::decoding::StreamingDecoder::new(&mut vmlinux_tar_zst).unwrap();

        tar::Archive::new(vmlinux_tar)
            .entries()
            .unwrap()
            .find(|x| x.as_ref().unwrap().path().unwrap() == vmlinux_path.as_path())
            .unwrap()
            .unwrap()
            .read_to_string(&mut vmlinux_h)
            .unwrap();

        let bindings = bindgen::Builder::default()
            .header_contents(&search.to_string_lossy(), &vmlinux_h)
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
