// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.

//! scx_rlocal: loads the scheduler in bpf/ and runs it until Ctrl-C.

/// The scheduler's tunables: `scx::opts!()` in bpf/src/main.rs declares
/// one for each option, named as the option in upper case. A time in
/// microseconds is a tunable in nanoseconds: `slice_us` is `SLICE_NS`.
#[derive(clap::Args)]
struct Opts {
    /// Scheduling slice duration in microseconds.
    #[clap(short = 's', long, default_value = "5000")]
    slice_us: u64,

    /// Do not let a CPU with an empty queue take from the other queues of
    /// its LLC.
    #[clap(long)]
    no_steal: bool,
}

impl scx_rustsched_loader::Scheduler for Opts {}

scx_rustsched_loader::main!(
    "A per-CPU queue sched_ext scheduler written in Rust BPF",
    Opts
);
