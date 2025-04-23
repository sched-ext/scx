// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.
use std::io::Write;

fn main() {
    let include_path = std::env::var("OUT_DIR").unwrap() + "/include";

    std::fs::create_dir_all(include_path.clone() + "/scx_p2dq").unwrap();
    let mut file = std::fs::File::create(include_path.clone() + "/scx_p2dq/main.bpf.c").unwrap();
    file.write_all(scx_p2dq::bpf_srcs::main_bpf_c()).unwrap();
    let mut file = std::fs::File::create(include_path.clone() + "/scx_p2dq/intf.h").unwrap();
    file.write_all(scx_p2dq::bpf_srcs::intf_h()).unwrap();
    let mut file = std::fs::File::create(include_path.clone() + "/scx_p2dq/types.h").unwrap();
    file.write_all(scx_p2dq::bpf_srcs::types_h()).unwrap();

    // TODO: this is a massive hack. BpfBuilder should be rewritten to have an explicit change of
    // state between "builder" mode (where options are set) and "actualised" mode where they are
    // turned into the useful arguments. As it is cflags is generated too early, and refactoring it
    // is a pain and will require a change of interface.
    let mut extra_flags = vec!["-I".to_string() + &include_path];
    if let Ok(e) = std::env::var("BPF_EXTRA_CFLAGS_POST_INCL") {
        extra_flags.push(e);
    }
    std::env::set_var("BPF_EXTRA_CFLAGS_POST_INCL", extra_flags.join(" "));

    scx_utils::BpfBuilder::new()
        .unwrap()
        .enable_intf("src/bpf/intf.h", "bpf_intf.rs")
        .enable_skel("src/bpf/main.bpf.c", "bpf")
        .add_source("../../../lib/sdt_task.bpf.c")
        .add_source("../../../lib/sdt_alloc.bpf.c")
        .compile_link_gen()
        .unwrap();
}
