// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.

//! scx_rvtime: loads the scheduler in bpf/ and runs it until Ctrl-C.

/// The scheduler's tunables: `scx::opts!()` in bpf/src/main.rs declares
/// one for each option, named as the option in upper case. A time in
/// microseconds is a tunable in nanoseconds: `slice_us` is `SLICE_NS`.
#[derive(clap::Args)]
struct Opts {
    /// Scheduling slice duration in microseconds.
    #[clap(short = 's', long, default_value = "20000")]
    slice_us: u64,
}

impl scx_rustsched_loader::Scheduler for Opts {}

scx_rustsched_loader::main!(
    "A weighted vtime sched_ext scheduler written in Rust BPF",
    Opts
);
