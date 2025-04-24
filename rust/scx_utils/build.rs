// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use vergen::EmitBuilder;
include!("src/builder.rs");

fn main() {
    Builder::new().build();
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
