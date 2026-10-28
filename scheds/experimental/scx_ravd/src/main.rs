// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Piotr Gorski <lucjan.lucjanov@gmail.com>

//! scx_ravd: loads the scheduler in bpf/ and runs it until Ctrl-C.

use std::ffi::OsStr;

use libbpf_rs::{MapCore, MapFlags, Object};
use log::info;
use scx_rustsched_loader::{Attached, Scheduler};

/// The scheduler's options, named as scx_lavd's. `scx_rustsched::opts!()`
/// in bpf/src/main.rs declares a tunable for each, named as the option in
/// upper case, a time in microseconds as _NS.
#[derive(clap::Args)]
struct Opts {
    /// Maximum scheduling slice duration in microseconds.
    #[arg(long, default_value_t = 5000)]
    slice_max_us: u64,

    /// Minimum scheduling slice duration in microseconds.
    #[arg(long, default_value_t = 500)]
    slice_min_us: u64,

    /// Slice duration in microseconds for every task on a CPU where a
    /// pinned task waits. Pinned tasks then wait in a queue of their CPU,
    /// and get the CPU sooner. 0 turns it off.
    #[arg(long, default_value_t = 5000)]
    pinned_slice_us: u64,

    /// How latency-critical a task must be to preempt another: within the
    /// top 1/2^n of the spread between the average and the maximum latency
    /// criticality. Larger is stricter.
    #[arg(long, default_value_t = 6, value_parser = clap::value_parser!(u64).range(0..=10))]
    preempt_shift: u64,

    /// Dispatch straight to an idle CPU's local DSQ, past the deadline
    /// order, while the system's utilization is below this percentage.
    /// 0 turns it off.
    #[arg(long, default_value_t = 10, value_parser = clap::value_parser!(u64).range(0..=100))]
    lb_local_dsq_util_pct: u64,

    /// Never preempt a running task for an urgent one.
    #[arg(long)]
    no_preemption: bool,

    /// Do not take the waker's CPU on a synchronous wakeup.
    #[arg(long)]
    no_wake_sync: bool,

    /// Do not boost the time slice of tasks that run longer than it.
    #[arg(long)]
    no_slice_boost: bool,

    /// Run every CPU at its full frequency instead of scaling it with the
    /// CPU's utilization.
    #[arg(long)]
    no_freq_scaling: bool,

    /// Queue every task on a CPU of its own rather than on its compute
    /// domain.
    #[arg(long)]
    per_cpu_dsq: bool,
}

impl Scheduler for Opts {
    fn attached(&self, attached: &Attached<'_>) {
        let mut header = vec![format!("{} {}", attached.name(), attached.version())];
        if let Some(nr_cpus) = attached.nr_cpus() {
            header.push(format!("{nr_cpus} CPUs"));
        }
        header.push(format!(
            "{} compute domains",
            read_u64(attached.object(), ".data.nr_cpdoms")
        ));
        if let Some(smt) = attached.smt() {
            header.push(if smt { "SMT on" } else { "SMT off" }.to_string());
        }
        info!("{}", header.join(" | "));
        info!(
            "slice {}-{} us, pinned slice {} us, preemption {}, frequency scaling {}",
            self.slice_min_us,
            self.slice_max_us,
            self.pinned_slice_us,
            if self.no_preemption { "off" } else { "on" },
            if self.no_freq_scaling { "off" } else { "on" },
        );
        info!("{} scheduler attached and running", attached.name());
    }

    fn stopped(&self, name: &str, why: &str) {
        info!("{name} scheduler stopped: {why}");
    }
}

/// The first word of the map of `section`, 0 if there is none.
fn read_u64(object: &Object, section: &str) -> u64 {
    let mut bytes = [0_u8; 8];
    if let Some(map) = object.maps().find(|map| map.name() == OsStr::new(section)) {
        let _ = map.lookup_into(&0_u32.to_ne_bytes(), &mut bytes, MapFlags::ANY);
    }
    u64::from_ne_bytes(bytes)
}

scx_rustsched_loader::main!(
    "LAVD sched_ext scheduler completely written in Rust, after scx_lavd",
    Opts
);
