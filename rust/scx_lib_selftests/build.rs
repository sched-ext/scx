// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

fn main() {
    scx_utils::BpfBuilder::new()
        .unwrap()
        .enable_skel("src/bpf/main.bpf.c", "main")
        .add_source("../../lib/selftests/selftest.bpf.c")
        .add_source("../../lib/selftests/st_bitmap.bpf.c")
        .compile_link_gen()
        .unwrap();
}
