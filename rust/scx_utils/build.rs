// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use std::env;
use std::fs::File;
use std::io::{Read, Seek};
use std::path::PathBuf;

use scx_cargo::ClangInfo;
use vergen::EmitBuilder;

fn gen_bindings() {
    let out_dir = env::var("OUT_DIR").unwrap();
    let clang = ClangInfo::new().unwrap();
    let kernel_target = clang.kernel_target().unwrap();

    let mut vmlinux_tar_zst = File::open("vmlinux.tar.zst").unwrap();

    let mut vmlinux_h = String::new();

    // vmlinux.h is a symlink. dereference it here.
    let search: PathBuf = format!("vmlinux/arch/{kernel_target}/vmlinux.h").into();

    let mut vmlinux_tar = ruzstd::decoding::StreamingDecoder::new(&mut vmlinux_tar_zst).unwrap();
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

fn main() {
    gen_bindings();

    EmitBuilder::builder()
        .git_sha(true)
        .git_dirty(true)
        .cargo_target_triple()
        .emit()
        .unwrap();

    let bindings = bindgen::Builder::default()
        .header("perf_wrapper.h")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .prepend_enum_name(false)
        .derive_default(true)
        .generate()
        .expect("Unable to generate bindings");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("perf_bindings.rs"))
        .expect("Couldn't write bindings!");
}
