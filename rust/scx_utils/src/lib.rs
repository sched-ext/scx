// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

//! # Utility collection for sched_ext schedulers
//!
//! [sched_ext](https://github.com/sched-ext/scx) is a Linux kernel feature
//! which enables implementing kernel thread schedulers in BPF and dynamically
//! loading them.
//!
//! Thie crate is a collection of utilities for sched_ext scheduler
//! implementations which use Rust for userspace component. This enables
//! implementing hot paths in BPF while offloading colder and more complex
//! operations to userspace Rust code which can be significantly more convenient
//! and powerful.
//!
//! The utilities can be put into two broad categories.
//!
//! ## Build Utilities
//!
//! BPF being its own CPU architecture and independent runtime environment,
//! build environment and steps are already rather complex. The need to
//! interface between two different languages - C and Rust - adds further
//! complexities. This crate contains `struct BpfBuilder` which is to be
//! used from `build.rs` and automates most of the process.
//!
//! ## Utilities for Rust Userspace Component
//!
//! Utility modules which can be useful for userspace component of sched_ext
//! schedulers.

mod bindings;

mod bpf_builder;
pub use bpf_builder::BpfBuilder;

pub mod ravg;

mod libbpf_logger;
pub use libbpf_logger::init_libbpf_logging;

mod user_exit_info;
pub use user_exit_info::UserExitInfo;
pub use user_exit_info::ScxExitKind;

mod topology;
pub use topology::Domain;
pub use topology::Topology;
