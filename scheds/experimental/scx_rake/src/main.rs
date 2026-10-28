// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Piotr Gorski <lucjan.lucjanov@gmail.com>

//! scx_rake: loads the scheduler in bpf/ and runs it until Ctrl-C.

/// The scheduler's tunables: `scx::opts!()` in bpf/src/main.rs declares
/// one for each option, named as the option in upper case.
///
/// scx_cake's policy has no tunables of its own: its slice, margins and
/// thresholds are constants of the policy, in bpf/src/policy.rs.
#[derive(clap::Args)]
struct Opts {
    /// Keep one wake pool for the whole machine instead of one per LLC,
    /// which also turns off the routing between LLCs. More than 16 LLCs
    /// always take one pool.
    #[clap(long)]
    single_pool: bool,
}

impl scx_rustsched_loader::Scheduler for Opts {}

scx_rustsched_loader::main!(
    "scx_cake's policy, with the BPF program written in Rust",
    Opts
);
