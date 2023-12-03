// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use std::env;
use std::fs::File;
use std::path::PathBuf;

const BPF_H: &str = "bpf_h";

fn main() {
    let file =
        File::create(PathBuf::from(env::var("OUT_DIR").unwrap()).join(format!("{}.tar", BPF_H)))
            .unwrap();
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
