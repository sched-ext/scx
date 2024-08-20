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
}
