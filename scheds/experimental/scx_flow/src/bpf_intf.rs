// SPDX-License-Identifier: GPL-2.0
/*
 * Generated BPF bindings
 *
 * Holds the generated bindings for the shared BPF header. Naming follows the C header and
 * naming lints are allowed here so generated names do not warn.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(dead_code)]
#![allow(clippy::missing_safety_doc)]
include!(concat!(env!("OUT_DIR"), "/bpf_intf.rs"));
