// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.

//! scx_rburst: loads the scheduler in bpf/ and runs it until Ctrl-C.

mod stats;

use log::info;
use scx_rustsched_loader::{Attached, Params, Result, compat};

/// The scheduler's tunables: `scx::opts!()` in bpf/src/main.rs declares
/// one for each option, named as the option in upper case. A time in
/// microseconds is a tunable in nanoseconds: `slice_us` is `SLICE_NS`.
#[derive(clap::Args)]
struct Opts {
    /// Scheduling slice duration in microseconds.
    #[clap(short = 's', long, default_value = "1600")]
    slice_us: u64,

    /// Do not place tasks on the CPUs the kernel prefers, where it ranks
    /// them.
    #[clap(long)]
    no_asym_packing: bool,

    /// Do not let a waking task with a shorter request and an earlier
    /// deadline take the CPU from the running task.
    #[clap(long)]
    no_preempt: bool,

    /// Pick the earliest deadline whatever the virtual time, instead of
    /// among the eligible tasks, the ones not ahead of the clock.
    #[clap(long)]
    no_eligibility: bool,

    /// Do not keep a task's lag across a sleep, as EEVDF does: sleeping
    /// then earns service, up to the lag bound.
    #[clap(long)]
    no_vlag: bool,

    /// Maximum lag of a task when it is queued, behind the clock or ahead of
    /// it, in microseconds of service at nice 0.
    #[clap(short = 'l', long, default_value = "10000")]
    lag_bound_us: u64,

    /// Minimum time a task runs before a waking task can take the CPU from
    /// it, in microseconds.
    #[clap(short = 'g', long, default_value = "100")]
    min_granularity_us: u64,

    /// Do not let a waking task borrow virtual time. By default it is
    /// queued at least --vtime-borrowing-us behind the clock, ahead of the
    /// tasks that stayed runnable, and on a CPU where it preempts the one
    /// that runs.
    #[clap(long)]
    no_vtime_borrowing: bool,

    /// How much a waking task borrows, in microseconds of service at nice
    /// 0.
    #[clap(long, default_value = "20000")]
    vtime_borrowing_us: u64,

    /// Do not use proxy execution. By default a task that blocks on a
    /// mutex stays queued as a donor, and when it is picked its scheduling
    /// context runs the mutex owner, which gets the lock released sooner.
    /// This makes such a task block and leave the queue instead. Proxy
    /// execution is used only on kernels that support it for sched_ext.
    #[clap(long)]
    no_proxy_exec: bool,
}

impl scx_rustsched_loader::Scheduler for Opts {
    fn settings(&self, params: &mut Params) -> Result<()> {
        // SCX_OPS_ENQ_BLOCKED hands mutex-blocked donors to ops.enqueue()
        // with SCX_ENQ_BLOCKED. The flag reads as zero on a kernel without
        // it, which leaves proxy execution off.
        if !self.no_proxy_exec {
            params.add_flags(*compat::SCX_OPS_ENQ_BLOCKED);
        }
        Ok(())
    }

    fn attached(&self, attached: &Attached<'_>) {
        let proxy = if attached.ops_flags() & *compat::SCX_OPS_ENQ_BLOCKED != 0 {
            "on"
        } else if self.no_proxy_exec {
            "off (--no-proxy-exec)"
        } else {
            "off (not supported by the kernel)"
        };
        info!("{} attached, proxy execution {proxy}", attached.name());
    }

    fn stats(&self) -> Option<scx_rustsched_loader::Stats> {
        Some(stats::stats())
    }
}

scx_rustsched_loader::main!(
    "An EEVDF-style sched_ext scheduler with virtual-time borrowing and requests sized by the CPU burst, written in Rust BPF",
    Opts
);
