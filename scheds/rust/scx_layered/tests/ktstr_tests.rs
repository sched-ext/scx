#![cfg(feature = "ktstr-tests")]
//! ktstr verifier declaration for scx_layered.
//!
//! `cargo ktstr verifier` boots scx_layered in a KVM VM and checks it verifies,
//! attaches, and dispatches. scx_layered always needs a layer config, so
//! `--run-example` supplies the built-in example layers. Declaration only.

use ktstr::prelude::*;

declare_scheduler!(LAYERED, {
    name = "layered",
    binary = "scx_layered",
    sched_args = ["--run-example"],
});
