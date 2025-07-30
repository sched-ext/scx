// Copyright (c) Changwoo Min <changwoo@igalia.com>
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

fn main() {
    scx_utils::BpfBuilder::new()
        .unwrap()
        .enable_intf("src/bpf/intf.h", "bpf_intf.rs")
        .enable_skel("src/bpf/main.bpf.c", "bpf")
        .add_source("src/bpf/introspec.bpf.c")
        .add_source("src/bpf/lock.bpf.c")
        .add_source("src/bpf/power.bpf.c")
        .add_source("src/bpf/sys_stat.bpf.c")
        .compile_link_gen()
        .unwrap();
}
