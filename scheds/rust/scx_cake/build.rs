// SPDX-License-Identifier: GPL-2.0
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

// No build-host inputs: topology is measured by the loader into rodata at
// attach, so one binary fits any machine (STEAL_SPAN in intf.h bounds the
// steal matrix).

fn main() {
    scx_cargo::BpfBuilder::new()
        .unwrap()
        .enable_intf("src/bpf/intf.h", "bpf_intf.rs")
        .enable_skel("src/bpf/cake.bpf.c", "bpf")
        .build()
        .unwrap();
}
