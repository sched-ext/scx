// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use std::env;
use std::fs::File;
use std::path::PathBuf;

const BPF_H: &str = "bpf_h";

fn gen_bpf_h() {
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

fn main() {
    gen_bpf_h();
}
