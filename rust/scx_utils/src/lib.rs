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
//! This crate is a collection of utilities for sched_ext scheduler
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

pub use paste::paste;
pub use log::warn;

mod bindings;

mod bpf_builder;
pub use bpf_builder::BpfBuilder;

mod builder;
pub use builder::Builder;

mod user_exit_info;
pub use user_exit_info::ScxExitKind;
pub use user_exit_info::ScxConsts;
pub use user_exit_info::SCX_ECODE_RSN_HOTPLUG;
pub use user_exit_info::SCX_ECODE_ACT_RESTART;
pub use user_exit_info::UeiDumpPtr;
pub use user_exit_info::UserExitInfo;
pub use user_exit_info::UEI_DUMP_PTR_MUTEX;

pub mod compat;

mod libbpf_logger;
pub use libbpf_logger::init_libbpf_logging;

pub mod ravg;

mod topology;
pub use topology::Cache;
pub use topology::Core;
pub use topology::Cpu;
pub use topology::Node;
pub use topology::Topology;
pub use topology::TopologyMap;

mod cpumask;
pub use cpumask::Cpumask;

mod infeasible;
pub use infeasible::LoadAggregator;
pub use infeasible::LoadLedger;

mod log_recorder;
pub use log_recorder::LogRecorderBuilder;
