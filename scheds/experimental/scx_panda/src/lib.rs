// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Will Clingan
// scx_panda LIBRARY ROOT. THE LOADER, THE TOPOLOGY FILL AND THE SKELETON LIVE
// HERE SO THE BINARY AND THE SUITE UNDER tests/ SHARE ONE IMPLEMENTATION. NO
// TEST CODE LIVES UNDER src/: THE SUITE READS WHAT THIS LIBRARY MAKES PUBLIC.

#[macro_use]
pub mod log;

#[allow(non_upper_case_globals)]
#[allow(non_camel_case_types)]
#[allow(non_snake_case)]
#[allow(dead_code)]
pub mod bpf_skel;

pub mod bpf_intf;
pub mod events;
pub mod scheduler;
pub mod topology;
