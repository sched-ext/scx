// SPDX-License-Identifier: GPL-2.0
//
// Copyright (c) 2026 Galih Tama <galpt@v.recipes>
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

// Bindgen output from src/bpf/intf.h follows C naming and contains
// helpers without safety docs. Like fair.c's helpers, the naming is
// kept as-is from the header; allow those lints only for the
// generated file so an unused intf.h constant still warns.
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(dead_code)]
#![allow(clippy::missing_safety_doc)]

include!(concat!(env!("OUT_DIR"), "/bpf_intf.rs"));
