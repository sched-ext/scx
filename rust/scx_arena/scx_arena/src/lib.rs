// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

//! # SCX Arena library setup utilities
//!
//! Crate for setting up the BPF arena library for sched-ext schedulers.

mod bpf_skel;

mod arenalib;
pub use arenalib::ArenaLib;
