#![cfg(feature = "ktstr-tests")]
//! ktstr verifier declaration for scx_lavd.
//!
//! `cargo ktstr verifier` boots scx_lavd in a KVM VM and checks it verifies,
//! attaches, and dispatches. scx_lavd attaches with defaults, so no
//! `sched_args` are required. Declaration only.

use ktstr::prelude::*;

declare_scheduler!(LAVD, {
    name = "lavd",
    binary = "scx_lavd",
});
