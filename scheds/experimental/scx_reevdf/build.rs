// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.

use scx_rustsched_build::{KSYM_DOMAIN_POINTER, KSYM_INT, KSYM_RQ, Spec, build, kfuncs};

// The runtime's kfunc catalog, which the BPF crate declares from: here it
// lists the kfuncs for the build, kfuncs().
include!("../../../rust/scx_rustsched/kfuncs.rs");

/// The per-CPU kernel variables the scheduler reads, see Spec.
const KSYM_VARIABLES: [(&std::ffi::CStr, u8, u32); 6] = [
    (c"sched_core_priority", KSYM_INT, 4),
    (c"sd_asym_packing", KSYM_DOMAIN_POINTER, 8),
    (c"runqueues", KSYM_RQ, 0),
    (c"sd_llc", KSYM_DOMAIN_POINTER, 8),
    (c"sd_llc_id", KSYM_INT, 4),
    (c"sd_share_id", KSYM_INT, 4),
];

fn main() {
    build(&Spec {
        package: "scx_reevdf",
        manifest: "bpf/Cargo.toml",
        catalog: "../../../rust/scx_rustsched/kfuncs.rs",
        crate_name: "scx_reevdf_kernel",
        kfuncs: kfuncs(),
        ksyms: &KSYM_VARIABLES,
        variants: &[("legacy", false), ("sized", true)],
    });
}
