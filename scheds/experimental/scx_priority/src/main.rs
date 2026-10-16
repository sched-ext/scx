// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2026 Rahad Bhuiya <rahadbhuiya2021@gmail.com>

//! # Dual-Queue Priority Linux Kernel Scheduler using sched_ext
//!
//! ## Overview
//!
//! scx_priority is a dual-queue priority scheduler based on `scx_rustland_core`.
//! It classifies tasks into two priority categories:
//!
//! - **High-Priority / Interactive**: Tasks with weight > 100 (nice < 0) or latency-sensitive.
//!   These tasks are given boosted time slices (2x standard slice) and prioritized on dispatch.
//! - **Standard / Batch**: Tasks with standard weight (<= 100).
//!
//! High-priority tasks are dispatched first to available idle CPUs, ensuring responsive,
//! stutter-free interactive experience even under heavy background load.

mod bpf_skel;
pub use bpf_skel::*;
pub mod bpf_intf;

#[rustfmt::skip]
mod bpf;
use std::collections::VecDeque;
use std::mem::MaybeUninit;
use std::time::SystemTime;

use anyhow::Result;
use bpf::*;
use libbpf_rs::OpenObject;
use scx_utils::UserExitInfo;
use scx_utils::libbpf_clap_opts::LibbpfOpts;

// Base time slice (in nanoseconds)
const SLICE_NS: u64 = 5_000_000; // 5 ms
const BOOSTED_SLICE_NS: u64 = 10_000_000; // 10 ms for interactive tasks

struct Scheduler<'a> {
    bpf: BpfScheduler<'a>,
    high_prio_queue: VecDeque<QueuedTask>,
    low_prio_queue: VecDeque<QueuedTask>,
    nr_high_dispatched: u64,
    nr_low_dispatched: u64,
}

impl<'a> Scheduler<'a> {
    fn init(open_object: &'a mut MaybeUninit<OpenObject>) -> Result<Self> {
        let open_opts = LibbpfOpts::default();
        let bpf = BpfScheduler::init(
            open_object,
            open_opts.clone().into_bpf_open_opts(),
            0,            // exit_dump_len
            false,        // partial
            false,        // debug
            true,         // builtin_idle
            false,        // numa_local
            SLICE_NS,     // default slice
            "priority",   // name of scx ops
        )?;

        Ok(Self {
            bpf,
            high_prio_queue: VecDeque::new(),
            low_prio_queue: VecDeque::new(),
            nr_high_dispatched: 0,
            nr_low_dispatched: 0,
        })
    }

    fn dispatch_tasks(&mut self) {
        // Dequeue tasks from BPF into our internal priority queues
        while let Ok(Some(task)) = self.bpf.dequeue_task() {
            if task.weight > 100 {
                self.high_prio_queue.push_back(task);
            } else {
                self.low_prio_queue.push_back(task);
            }
        }

        // 1. Drain high-priority queue first
        while let Some(task) = self.high_prio_queue.pop_front() {
            let mut dispatched_task = DispatchedTask::new(&task);
            let cpu = self.bpf.select_cpu(task.pid, task.cpu, task.flags);
            dispatched_task.cpu = if cpu >= 0 { cpu } else { RL_CPU_ANY };
            dispatched_task.slice_ns = BOOSTED_SLICE_NS;

            self.bpf.dispatch_task(&dispatched_task).unwrap();
            self.nr_high_dispatched += 1;
        }

        // 2. Drain standard / batch queue
        while let Some(task) = self.low_prio_queue.pop_front() {
            let mut dispatched_task = DispatchedTask::new(&task);
            let cpu = self.bpf.select_cpu(task.pid, task.cpu, task.flags);
            dispatched_task.cpu = if cpu >= 0 { cpu } else { RL_CPU_ANY };
            dispatched_task.slice_ns = SLICE_NS;

            self.bpf.dispatch_task(&dispatched_task).unwrap();
            self.nr_low_dispatched += 1;
        }

        // Hand control back to the BPF scheduler
        let pending = (self.high_prio_queue.len() + self.low_prio_queue.len()) as u64;
        self.bpf.notify_complete(pending);
    }

    fn print_stats(&mut self) {
        let running = *self.bpf.nr_running_mut();
        let queued = *self.bpf.nr_queued_mut();

        println!(
            "high_prio_dispatched={} low_prio_dispatched={} running={} queued={}",
            self.nr_high_dispatched,
            self.nr_low_dispatched,
            running,
            queued,
        );
    }

    fn now() -> u64 {
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    fn run(&mut self) -> Result<UserExitInfo> {
        let mut prev_ts = Self::now();

        println!("scx_priority scheduler active. Prioritizing interactive tasks (weight > 100)...");
        println!("Press Ctrl-C to exit.");

        while !self.bpf.exited() {
            self.dispatch_tasks();

            let curr_ts = Self::now();
            if curr_ts > prev_ts {
                self.print_stats();
                prev_ts = curr_ts;
            }
        }

        self.bpf.shutdown_and_report()
    }
}

fn main() -> Result<()> {
    let mut open_object = MaybeUninit::uninit();
    loop {
        let mut sched = Scheduler::init(&mut open_object)?;
        if !sched.run()?.should_restart() {
            break;
        }
    }

    Ok(())
}
