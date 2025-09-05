// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

//! vmlinux.h for aarch64 architecture

pub const VMLINUX_H: &[u8] = include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/vmlinux.h"));