#![cfg(feature = "ktstr-tests")]
//! ktstr verifier declaration for scx_cosmos.
//!
//! `cargo ktstr verifier` boots scx_cosmos in a KVM VM and checks it verifies,
//! attaches, and dispatches. scx_cosmos attaches with defaults, so no
//! `sched_args` are required. Declaration only.

use ktstr::prelude::*;

declare_scheduler!(COSMOS, {
    name = "cosmos",
    binary = "scx_cosmos",
});
